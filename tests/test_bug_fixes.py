"""Regression tests for the post-1.0.0 bug-hunt fixes.

Each test names the bug-hunt finding it covers (C1, C2, C3, M3) so if a
refactor breaks one of these, the failure points at the original finding.
"""
from __future__ import annotations

import io
import os
import sys
import threading
import time
from pathlib import Path

import pytest

from cryptofile import crypto, file_ops


# ── C1: silent truncation if source grows mid-encrypt ─────────────────────


class _ChunkAlignedGrowingReader(io.RawIOBase):
    """Reader that returns exactly `declared_size` then keeps producing
    bytes. Triggers the post-loop C1 guard (rather than the earlier
    size-mismatch check, which catches over-read within the loop)."""

    def __init__(self, declared_size: int, extra: int) -> None:
        self._declared = declared_size
        self._extra = extra
        self._returned = 0

    def readable(self) -> bool:
        return True

    def read(self, n: int = -1) -> bytes:
        remaining = self._declared + self._extra - self._returned
        if remaining <= 0:
            return b""
        # Chunk-align the first response to exactly `declared_size`.
        if self._returned < self._declared:
            take = min(n if n > 0 else remaining, self._declared - self._returned)
        else:
            take = min(n if n > 0 else remaining, remaining)
        self._returned += take
        return b"A" * take


def test_c1_source_grew_during_encrypt_raises():
    """Reader returns exactly `declared` (one full chunk) then has more bytes.
    The C1 guard's post-loop read(1) must detect the overflow."""
    declared = crypto.CHUNK_SIZE
    out = io.BytesIO()
    with pytest.raises(crypto.CryptoError, match="source file grew"):
        crypto.encrypt_stream(
            _ChunkAlignedGrowingReader(declared, 50),
            out,
            "pw",
            declared,
            memory_kib=8, time_cost=1, parallelism=1,
        )


def test_c1_oversized_read_caught_by_size_mismatch():
    """A non-chunk-aligned grow is caught by the pre-existing
    `bytes_done != plaintext_size` check. Document the behaviour."""
    declared = 100
    out = io.BytesIO()
    # A reader that blurts 150 bytes at once when declared=100 gets its
    # over-read encrypted as chunk 0, then bytes_done overshoots and the
    # size-mismatch check fires.
    class _Blob(io.RawIOBase):
        def __init__(self, total):
            self._data = b"A" * total
            self._offset = 0
        def readable(self): return True
        def read(self, n=-1):
            if n < 0:
                n = len(self._data) - self._offset
            chunk = self._data[self._offset:self._offset + n]
            self._offset += len(chunk)
            return chunk
    with pytest.raises(crypto.CryptoError, match="plaintext_size mismatch"):
        crypto.encrypt_stream(
            _Blob(150), out, "pw", declared,
            memory_kib=8, time_cost=1, parallelism=1,
        )


def test_c1_exact_size_still_succeeds():
    """Reader that produces exactly `declared` bytes still round-trips — the
    C1 guard must not false-positive on honest inputs."""
    data = b"Z" * 100
    out = io.BytesIO()
    crypto.encrypt_stream(
        io.BytesIO(data), out, "pw", 100,
        memory_kib=8, time_cost=1, parallelism=1,
    )
    back = io.BytesIO()
    crypto.decrypt_stream(io.BytesIO(out.getvalue()), back, "pw")
    assert back.getvalue() == data


# ── C2: walker must refuse to recurse into Windows reparse points ─────────


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only NTFS junctions")
def test_c2_walker_refuses_junction(tmp_path: Path):
    """Create an NTFS junction via `mklink /J`; the walker must NOT descend
    into it. Skipped when mklink isn't available (requires the user to have
    console access) but safe to call on CI runners."""
    import shutil
    import subprocess

    # Set up: safe_root contains one real file + a junction to outside_root.
    safe_root = tmp_path / "safe"
    safe_root.mkdir()
    (safe_root / "inside.txt").write_bytes(b"ok")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim.txt").write_bytes(b"would be encrypted by a buggy walker")

    junction = safe_root / "junction-to-outside"
    # /J is a directory junction — does NOT require admin on modern Windows.
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"mklink unavailable: {result.stderr!r}")

    try:
        exp = file_ops.expand_for_encrypt([safe_root])
        # Walker must find inside.txt but NOT outside/victim.txt.
        names = {p.name for p in exp.files}
        assert "inside.txt" in names
        assert "victim.txt" not in names, (
            "walker descended into a junction — would have encrypted a file "
            "outside the user's selected folder"
        )
    finally:
        # Clean up the junction specifically, not the target.
        subprocess.run(["cmd", "/c", "rmdir", str(junction)], capture_output=True)


def test_c2_is_reparse_point_is_false_on_regular_file(tmp_path: Path):
    """Sanity: the reparse-point helper doesn't false-positive on a plain file."""
    f = tmp_path / "plain.txt"
    f.write_bytes(b"x")
    assert file_ops._is_reparse_point(f) is False


# ── C3: mid-stream cancel raises Cancelled ────────────────────────────────


def test_c3_cancel_check_aborts_encrypt():
    """`cancel_check` returning True partway through encrypt must raise
    Cancelled — not complete the whole file before checking."""
    data = b"Q" * (crypto.CHUNK_SIZE * 3)
    out = io.BytesIO()
    calls = {"n": 0}

    def cancel_after_one():
        calls["n"] += 1
        return calls["n"] > 1

    with pytest.raises(crypto.Cancelled):
        crypto.encrypt_stream(
            io.BytesIO(data), out, "pw", len(data),
            cancel_check=cancel_after_one,
            memory_kib=8, time_cost=1, parallelism=1,
        )


def test_c3_cancel_check_aborts_decrypt():
    """Same for decrypt: cancel after the first chunk must raise rather than
    chugging through the rest of a large ciphertext."""
    data = b"R" * (crypto.CHUNK_SIZE * 3)
    out = io.BytesIO()
    crypto.encrypt_stream(
        io.BytesIO(data), out, "pw", len(data),
        memory_kib=8, time_cost=1, parallelism=1,
    )
    ct = out.getvalue()

    calls = {"n": 0}

    def cancel_after_one():
        calls["n"] += 1
        return calls["n"] > 1

    with pytest.raises(crypto.Cancelled):
        crypto.decrypt_stream(
            io.BytesIO(ct), io.BytesIO(), "pw",
            cancel_check=cancel_after_one,
        )


def test_c3_cancel_on_encrypt_file_cleans_up_partial(tmp_path: Path, monkeypatch):
    """Cancel during `file_ops.encrypt_file` must clean up the .partial file
    and leave the source intact (not secure-deleted)."""
    monkeypatch.setattr(crypto, "ARGON2_MEMORY_KIB", 8)
    monkeypatch.setattr(crypto, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(crypto, "ARGON2_PARALLELISM", 1)

    src = tmp_path / "victim.bin"
    src.write_bytes(b"X" * (crypto.CHUNK_SIZE * 2))

    calls = {"n": 0}

    def cancel_soon():
        calls["n"] += 1
        return calls["n"] > 1

    with pytest.raises(crypto.Cancelled):
        file_ops.encrypt_file(src, "pw", cancel_check=cancel_soon)

    assert src.exists(), "source must remain on disk after cancel"
    # No orphan .partial in the directory.
    partials = list(tmp_path.glob("*.partial"))
    assert partials == [], f"partial files leaked: {partials}"


# ── M3: coordinator survives a malformed path ─────────────────────────────


def test_m3_coordinator_rejects_path_with_null_byte(tmp_path: Path, monkeypatch):
    """A path containing a NUL byte raises ValueError from the stat call on
    some platforms. The coordinator's connection handler must swallow that
    as a rejected path, not crash the accept thread."""
    from cryptofile import batch

    monkeypatch.setattr(batch, "_runtime_dir", lambda: tmp_path)
    primary = batch.BatchCoordinator("encrypt")
    assert primary.try_become_primary()
    try:
        primary.start_server()

        # Connect manually and send a bogus path with a NUL byte — the
        # handler must not crash.
        import json
        import socket as _sock
        port = int(primary.port_path.read_text())
        with _sock.create_connection(("127.0.0.1", port)) as s:
            s.sendall(json.dumps({"path": "evil\x00path.txt"}).encode() + b"\n")
        # Give the handler a moment to process and (hopefully) not crash.
        time.sleep(0.1)
        paths = primary.wait_for_collection(timeout_ms=200, idle_ms=100)
        # Bogus path rejected → no paths collected.
        assert paths == []
    finally:
        primary.close()
