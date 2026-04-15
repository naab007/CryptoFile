"""Regression tests for the CryptoFile 1.0.7 security / bug-hunt fixes.

Each test names the finding it covers:

* **H1** (SECURITY_AUDIT)    — header Argon2 parameter ceilings
* **H2** (SECURITY_AUDIT)    — coordinator auth-token handshake
* **M2** (SECURITY_AUDIT)    — NFC password normalisation
* **M3** (SECURITY_AUDIT)    — ``.partial`` created with O_EXCL + 0o600
* **M-new-3** (BUG_HUNT_10)  — ``.partial`` cleanup on ``os.replace`` failure
* **L-new-8** (BUG_HUNT_10)  — ``non_conflicting_name`` bounded
* **M-new-4** (BUG_HUNT_10)  — ``wait_for_collection`` primed idle clock
"""
from __future__ import annotations

import io
import json
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path

import pytest

from cryptofile import _atomic, batch, crypto, file_ops


# ── H1: Argon2 parameter ceilings in Header.from_bytes ────────────────────


def _build_header(
    memory_kib: int = crypto.ARGON2_MEMORY_KIB,
    time_cost: int = crypto.ARGON2_TIME_COST,
    parallelism: int = crypto.ARGON2_PARALLELISM,
    plaintext_size: int = 0,
) -> bytes:
    """Produce a valid-magic 52-byte header with arbitrary KDF parameters.

    Bypasses ``Header.to_bytes`` (which has no upper-bound check) so we
    can build the hostile headers this test is designed to exercise.
    """
    return (
        crypto.MAGIC
        + bytes([crypto.FILE_VERSION, crypto.KDF_ARGON2ID, crypto.CIPHER_AESGCM_1MIB, 0])
        + struct.pack("<II", memory_kib, time_cost)
        + bytes([parallelism, 0, 0, 0])
        + b"\x00" * crypto.SALT_SIZE
        + b"\x00" * crypto.NONCE_PREFIX_SIZE
        + struct.pack("<Q", plaintext_size)
    )


def test_h1_rejects_oversize_memory_kib():
    """u32 0xFFFFFFFF would request 4 TiB — must raise BadFormat."""
    data = _build_header(memory_kib=0xFFFFFFFF)
    with pytest.raises(crypto.BadFormat, match="memory_kib"):
        crypto.Header.from_bytes(data)


def test_h1_rejects_oversize_time_cost():
    data = _build_header(time_cost=0xFFFFFFFF)
    with pytest.raises(crypto.BadFormat, match="time_cost"):
        crypto.Header.from_bytes(data)


def test_h1_rejects_oversize_parallelism():
    data = _build_header(parallelism=255)
    with pytest.raises(crypto.BadFormat, match="parallelism"):
        crypto.Header.from_bytes(data)


def test_h1_rejects_zero_memory_kib():
    data = _build_header(memory_kib=0)
    with pytest.raises(crypto.BadFormat, match="memory_kib"):
        crypto.Header.from_bytes(data)


def test_h1_rejects_zero_time_cost():
    data = _build_header(time_cost=0)
    with pytest.raises(crypto.BadFormat, match="time_cost"):
        crypto.Header.from_bytes(data)


def test_h1_rejects_zero_parallelism():
    data = _build_header(parallelism=0)
    with pytest.raises(crypto.BadFormat, match="parallelism"):
        crypto.Header.from_bytes(data)


def test_h1_accepts_shipped_defaults():
    """Sanity: a file written with 1.0.0–1.0.6 defaults still decrypts."""
    data = _build_header(
        memory_kib=256 * 1024, time_cost=3, parallelism=4,
    )
    h = crypto.Header.from_bytes(data)
    assert h.memory_kib == 256 * 1024
    assert h.time_cost == 3
    assert h.parallelism == 4


def test_h1_accepts_boundary_max_memory():
    """The ceiling value itself must be allowed — off-by-one guard."""
    data = _build_header(memory_kib=crypto.ARGON2_MAX_MEMORY_KIB)
    h = crypto.Header.from_bytes(data)
    assert h.memory_kib == crypto.ARGON2_MAX_MEMORY_KIB


def test_h1_forward_compat_backup_roundtrip_old_params():
    """End-to-end: a file encrypted with the shipped defaults (and test
    values down-tuned for speed) decrypts cleanly — i.e. H1 doesn't
    inadvertently reject the params we actually write."""
    data = b"hello world" * 100
    out = io.BytesIO()
    crypto.encrypt_stream(
        io.BytesIO(data), out, "pw", len(data),
        memory_kib=8, time_cost=1, parallelism=1,
    )
    back = io.BytesIO()
    crypto.decrypt_stream(io.BytesIO(out.getvalue()), back, "pw")
    assert back.getvalue() == data


# ── M2: NFC password normalisation ────────────────────────────────────────


def test_m2_nfc_composed_and_decomposed_password_produce_same_key():
    """Composed and decomposed Unicode forms of the same password must
    derive the same AES key — otherwise users who type their password on
    a different IME get 'wrong password'."""
    composed = "caf\u00e9"            # café (5 bytes utf-8)
    decomposed = "cafe\u0301"         # café via combining acute (6 bytes utf-8)
    assert composed != decomposed     # sanity: different Python strings
    header = crypto.Header(
        memory_kib=8, time_cost=1, parallelism=1,
        salt=b"\x11" * 16, base_nonce=b"\x22" * 8, plaintext_size=0,
    )
    k1 = crypto.derive_key(composed, header)
    k2 = crypto.derive_key(decomposed, header)
    assert k1 == k2, "NFC normalization must make composed == decomposed"


def test_m2_nfc_roundtrip_encrypt_then_decrypt_with_different_form():
    """Encrypt with NFD form, decrypt with NFC form — must succeed."""
    data = b"secret contents"
    out = io.BytesIO()
    crypto.encrypt_stream(
        io.BytesIO(data), out, "cafe\u0301", len(data),
        memory_kib=8, time_cost=1, parallelism=1,
    )
    back = io.BytesIO()
    crypto.decrypt_stream(io.BytesIO(out.getvalue()), back, "caf\u00e9")
    assert back.getvalue() == data


# ── M3 / M-new-3: atomic_write — permissions + cleanup ────────────────────


def test_m3_partial_refuses_preexisting(tmp_path: Path):
    """Atomic-write opens with O_EXCL; a squatted .partial must fail fast
    rather than silently overwriting it (could be a concurrent run)."""
    final_out = tmp_path / "x.bin.lock"
    (tmp_path / "x.bin.lock.partial").write_bytes(b"squatter")
    with pytest.raises(FileExistsError):
        with _atomic.atomic_write(final_out) as (_fout, _tmp):
            pass


def test_mnew3_partial_cleaned_up_when_replace_fails(tmp_path: Path, monkeypatch):
    """If os.replace fails after the body ran, the .partial must NOT leak
    — the pre-1.0.7 code had the cleanup inside the ``with`` block, so a
    failure in the rename (AV lock, destination locked) left the partial
    behind."""
    final_out = tmp_path / "out.bin.lock"

    original_replace = os.replace

    def failing_replace(src, dst):
        raise PermissionError("simulated AV lock on destination")

    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(PermissionError):
        with _atomic.atomic_write(final_out) as (fout, tmp):
            fout.write(b"data")
    # The partial must be gone even though os.replace failed.
    leftovers = list(tmp_path.glob("*.partial"))
    assert leftovers == [], f"partial leaked after replace failure: {leftovers}"


def test_mnew3_partial_cleaned_up_on_body_exception(tmp_path: Path):
    """Reverification of existing behaviour — body raise also cleans up."""
    final_out = tmp_path / "out.bin.lock"
    with pytest.raises(RuntimeError):
        with _atomic.atomic_write(final_out) as (fout, _tmp):
            fout.write(b"partial")
            raise RuntimeError("boom")
    assert list(tmp_path.glob("*.partial")) == []
    assert not final_out.exists()


def test_mnew3_encrypt_file_cleans_up_on_simulated_replace_failure(
    tmp_path: Path, monkeypatch,
):
    """End-to-end: encrypt_file's .partial must be cleaned up even when
    os.replace fails (the full M-new-3 scenario)."""
    monkeypatch.setattr(crypto, "ARGON2_MEMORY_KIB", 8)
    monkeypatch.setattr(crypto, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(crypto, "ARGON2_PARALLELISM", 1)
    src = tmp_path / "doc.txt"
    src.write_bytes(b"some contents")
    # Patch os.replace in the _atomic module specifically (file_ops no
    # longer calls it directly — it's inside atomic_write now).
    original = os.replace
    calls = {"n": 0}

    def flaky(src_arg, dst_arg):
        calls["n"] += 1
        if calls["n"] == 1:
            raise PermissionError("simulated AV lock")
        return original(src_arg, dst_arg)

    monkeypatch.setattr(_atomic.os, "replace", flaky)
    with pytest.raises(PermissionError):
        file_ops.encrypt_file(src, "pw")
    # Source must remain (we didn't reach secure_delete).
    assert src.exists()
    # No partial leaked.
    assert list(tmp_path.glob("*.partial")) == []


# ── H2: coordinator auth-token handshake ──────────────────────────────────


@pytest.fixture
def _isolated_runtime(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(batch, "_runtime_dir", lambda: tmp_path)
    yield tmp_path


def _connect_and_send(port: int, payload: dict) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=2.0) as s:
        s.sendall(json.dumps(payload).encode("utf-8") + b"\n")


def test_h2_port_file_contains_token(_isolated_runtime: Path):
    c = batch.BatchCoordinator("encrypt")
    assert c.try_become_primary()
    try:
        c.start_server()
        content = c.port_path.read_text().strip()
        assert ":" in content, f"port file missing token: {content!r}"
        port_s, token = content.split(":", 1)
        assert int(port_s) > 0
        # 32 bytes → 64 hex chars
        assert len(token) == 64
        # Hex only
        int(token, 16)
    finally:
        c.close()


def test_h2_wrong_token_rejected(_isolated_runtime: Path, tmp_path: Path):
    """Same-box attacker who can't read the port file guesses a token —
    must NOT be able to inject a path."""
    target = tmp_path / "victim.bin"
    target.write_bytes(b"x")
    c = batch.BatchCoordinator("encrypt")
    assert c.try_become_primary()
    try:
        c.start_server()
        port = int(c.port_path.read_text().split(":")[0])
        _connect_and_send(port, {"path": str(target), "token": "00" * 32})
        time.sleep(0.2)
        paths = c.wait_for_collection(timeout_ms=200, idle_ms=100)
        assert paths == [], "wrong-token injection must not land"
    finally:
        c.close()


def test_h2_no_token_rejected(_isolated_runtime: Path, tmp_path: Path):
    target = tmp_path / "victim.bin"
    target.write_bytes(b"x")
    c = batch.BatchCoordinator("encrypt")
    assert c.try_become_primary()
    try:
        c.start_server()
        port = int(c.port_path.read_text().split(":")[0])
        _connect_and_send(port, {"path": str(target)})  # no token key
        time.sleep(0.2)
        paths = c.wait_for_collection(timeout_ms=200, idle_ms=100)
        assert paths == [], "tokenless injection must not land"
    finally:
        c.close()


def test_h2_correct_token_accepted(_isolated_runtime: Path, tmp_path: Path):
    target = tmp_path / "legit.bin"
    target.write_bytes(b"x")
    c = batch.BatchCoordinator("encrypt")
    assert c.try_become_primary()
    try:
        c.start_server()
        content = c.port_path.read_text().strip()
        port_s, token = content.split(":", 1)
        _connect_and_send(int(port_s), {"path": str(target), "token": token})
        time.sleep(0.2)
        paths = c.wait_for_collection(timeout_ms=400, idle_ms=100)
        names = {p.name for p in paths}
        assert target.name in names
    finally:
        c.close()


def test_h2_token_rotates_across_primary_sessions(_isolated_runtime: Path):
    """A stale token from a crashed primary must NOT authenticate a new
    primary — otherwise an attacker who observed a previous session could
    replay."""
    c1 = batch.BatchCoordinator("encrypt")
    assert c1.try_become_primary()
    c1.start_server()
    t1 = c1.port_path.read_text().split(":", 1)[1]
    c1.close()

    c2 = batch.BatchCoordinator("encrypt")
    assert c2.try_become_primary()
    try:
        c2.start_server()
        t2 = c2.port_path.read_text().split(":", 1)[1]
        assert t1 != t2, "token must rotate across primary sessions"
    finally:
        c2.close()


def test_h2_send_to_primary_still_works_end_to_end(_isolated_runtime: Path, tmp_path: Path):
    """Integration: the secondary uses the new payload format and reaches
    the primary successfully."""
    target = tmp_path / "f.bin"
    target.write_bytes(b"x")
    primary = batch.BatchCoordinator("encrypt")
    assert primary.try_become_primary()
    try:
        primary.start_server()
        sec = batch.BatchCoordinator("encrypt")
        assert sec.send_to_primary(target, timeout_s=2.0) is True
        time.sleep(0.1)
        paths = primary.wait_for_collection(timeout_ms=300, idle_ms=100)
        assert target.name in {p.name for p in paths}
    finally:
        primary.close()


# ── L-new-8: non_conflicting_name is bounded ──────────────────────────────


def test_lnew8_non_conflicting_name_returns_within_bounds(tmp_path: Path, monkeypatch):
    """Create a handful of conflicts; the function must still terminate."""
    (tmp_path / "a.lock").write_bytes(b"")
    (tmp_path / "a (2).lock").write_bytes(b"")
    (tmp_path / "a (3).lock").write_bytes(b"")
    out = file_ops.non_conflicting_name(tmp_path / "a.lock")
    assert out.name == "a (4).lock"


def test_lnew8_non_conflicting_name_caps_at_limit(tmp_path: Path, monkeypatch):
    """With a low cap, the function should raise FileOpError rather than
    spinning forever. We monkeypatch the cap to keep the test fast."""
    monkeypatch.setattr(file_ops, "_NON_CONFLICTING_MAX_ATTEMPTS", 3)
    (tmp_path / "a.lock").write_bytes(b"")
    for n in range(2, 6):
        (tmp_path / f"a ({n}).lock").write_bytes(b"")
    with pytest.raises(file_ops.FileOpError, match="non-conflicting"):
        file_ops.non_conflicting_name(tmp_path / "a.lock")


# ── M-new-4: wait_for_collection primed idle clock ────────────────────────


def test_mnew4_wait_for_collection_without_add_local_path(_isolated_runtime: Path):
    """Caller that forgets add_local_path() still gets a sane timeout —
    no infinite wait, no zero-second return. Must wait at least idle_ms."""
    c = batch.BatchCoordinator("encrypt")
    assert c.try_become_primary()
    try:
        c.start_server()
        t0 = time.monotonic()
        paths = c.wait_for_collection(timeout_ms=200, idle_ms=100)
        elapsed = time.monotonic() - t0
        assert paths == []
        # Post-fix: we initialise _last_arrival at start_server so the
        # idle window runs from server start — should take approximately
        # idle_ms (not return instantly, not hang forever).
        assert elapsed >= 0.09, f"returned too fast ({elapsed:.3f}s)"
        assert elapsed < 0.4, f"took too long ({elapsed:.3f}s)"
    finally:
        c.close()
