"""Round-trip + tamper-detection tests for the crypto module."""
from __future__ import annotations

import io
import os
import secrets

import pytest

from cryptofile import crypto


# ── Helpers ────────────────────────────────────────────────────────────────


FAST_KDF = {
    # Tests run under a deliberately-cheap KDF (~5 ms) instead of the
    # 1-second production default. We verify the cost params are stored
    # and respected; actual hardness is the production job.
    "memory_kib": 8,
    "time_cost": 1,
    "parallelism": 1,
}


def _enc(pt: bytes, pw: str = "correct horse battery staple") -> bytes:
    out = io.BytesIO()
    crypto.encrypt_stream(io.BytesIO(pt), out, pw, len(pt), **FAST_KDF)
    return out.getvalue()


def _dec(ct: bytes, pw: str = "correct horse battery staple") -> bytes:
    out = io.BytesIO()
    crypto.decrypt_stream(io.BytesIO(ct), out, pw)
    return out.getvalue()


# ── Round-trip ─────────────────────────────────────────────────────────────


def test_empty_file_roundtrip():
    assert _dec(_enc(b"")) == b""


def test_small_file_roundtrip():
    pt = b"hello world\n" * 10
    assert _dec(_enc(pt)) == pt


def test_single_chunk_boundary():
    pt = secrets.token_bytes(crypto.CHUNK_SIZE)
    assert _dec(_enc(pt)) == pt


def test_just_over_single_chunk():
    pt = secrets.token_bytes(crypto.CHUNK_SIZE + 1)
    assert _dec(_enc(pt)) == pt


def test_multi_chunk_roundtrip():
    pt = secrets.token_bytes(crypto.CHUNK_SIZE * 3 + 123)
    assert _dec(_enc(pt)) == pt


def test_unicode_password_roundtrip():
    pt = b"secret"
    pw = "pássw0rd-日本語-🔐"
    out = io.BytesIO()
    crypto.encrypt_stream(io.BytesIO(pt), out, pw, len(pt), **FAST_KDF)
    dec = io.BytesIO()
    crypto.decrypt_stream(io.BytesIO(out.getvalue()), dec, pw)
    assert dec.getvalue() == pt


# ── Authentication / tamper detection ─────────────────────────────────────


def test_wrong_password_raises_bad_password():
    ct = _enc(b"secret data")
    with pytest.raises(crypto.BadPassword):
        _dec(ct, pw="wrong password")


def test_bad_magic_raises_bad_format():
    with pytest.raises(crypto.BadFormat):
        _dec(b"NOPE" + b"\x00" * 200)


def test_truncated_header_raises_bad_format():
    with pytest.raises(crypto.BadFormat):
        _dec(b"CFIL")


def test_tampered_header_byte_fails_auth():
    ct = bytearray(_enc(b"data"))
    # Flip a byte in the salt — should break KDF + authentication.
    ct[25] ^= 0x01
    with pytest.raises(crypto.BadPassword):
        _dec(bytes(ct))


def test_tampered_ciphertext_byte_fails():
    ct = bytearray(_enc(b"A" * 1000))
    # Flip a byte in the chunk body (past the header).
    ct[crypto.HEADER_SIZE + 10] ^= 0x01
    with pytest.raises(crypto.BadPassword):
        _dec(bytes(ct))


def test_truncated_ciphertext_fails():
    ct = _enc(b"X" * (crypto.CHUNK_SIZE * 2 + 50))
    # Chop off the last chunk entirely.
    truncated = ct[: crypto.HEADER_SIZE + crypto.CHUNK_SIZE + crypto.GCM_TAG_SIZE]
    with pytest.raises(crypto.CryptoError):
        _dec(truncated)


def test_trailing_bytes_rejected():
    ct = _enc(b"data")
    with pytest.raises(crypto.CryptoError):
        _dec(ct + b"extra")


def test_chunk_swap_fails():
    """Swap chunk 0 with chunk 1 — per-chunk AAD binds the index, so this must fail."""
    pt = b"A" * crypto.CHUNK_SIZE + b"B" * crypto.CHUNK_SIZE
    ct = _enc(pt)
    chunk_size_on_disk = crypto.CHUNK_SIZE + crypto.GCM_TAG_SIZE
    header = ct[: crypto.HEADER_SIZE]
    c0_start = crypto.HEADER_SIZE
    c1_start = c0_start + chunk_size_on_disk
    c2_start = c1_start + chunk_size_on_disk
    swapped = (
        header
        + ct[c1_start:c2_start]
        + ct[c0_start:c1_start]
        + ct[c2_start:]
    )
    with pytest.raises(crypto.BadPassword):
        # chunk 0's tag verifies against the real chunk-0 AAD; swapped bytes fail.
        _dec(swapped)


# ── Header ─────────────────────────────────────────────────────────────────


def test_header_roundtrip_shape():
    h = crypto.Header(
        memory_kib=8, time_cost=1, parallelism=1,
        salt=b"\x00" * 16, base_nonce=b"\x01" * 8, plaintext_size=42,
    )
    b = h.to_bytes()
    assert len(b) == crypto.HEADER_SIZE
    parsed = crypto.Header.from_bytes(b)
    assert parsed == h


def test_header_stores_kdf_params_from_encryption():
    pt = b"x"
    out = io.BytesIO()
    crypto.encrypt_stream(io.BytesIO(pt), out, "pw", 1, memory_kib=32, time_cost=2, parallelism=2)
    header = crypto.Header.from_bytes(out.getvalue()[: crypto.HEADER_SIZE])
    assert header.memory_kib == 32
    assert header.time_cost == 2
    assert header.parallelism == 2
    assert header.plaintext_size == 1


def test_two_encryptions_have_different_salts():
    ct1 = _enc(b"same plaintext")
    ct2 = _enc(b"same plaintext")
    h1 = crypto.Header.from_bytes(ct1[: crypto.HEADER_SIZE])
    h2 = crypto.Header.from_bytes(ct2[: crypto.HEADER_SIZE])
    assert h1.salt != h2.salt
    assert h1.base_nonce != h2.base_nonce
    # Consequence: ciphertexts differ even with the same password + plaintext.
    assert ct1 != ct2
