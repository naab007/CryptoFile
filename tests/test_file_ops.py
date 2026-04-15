"""Tests for the file-level orchestration layer."""
from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from cryptofile import crypto, file_ops


# Fast KDF for tests — we patch this in via monkeypatch on encrypt_file.
@pytest.fixture(autouse=True)
def _fast_kdf(monkeypatch):
    monkeypatch.setattr(crypto, "ARGON2_MEMORY_KIB", 8)
    monkeypatch.setattr(crypto, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(crypto, "ARGON2_PARALLELISM", 1)


def test_encrypt_decrypt_roundtrip(tmp_path: Path):
    src = tmp_path / "hello.txt"
    src.write_bytes(b"hello, world\n")

    enc = file_ops.encrypt_file(src, "pw")
    # Source is gone, encrypted file exists with .lock suffix.
    assert not src.exists()
    assert enc == tmp_path / "hello.txt.lock"
    assert enc.exists()

    dec = file_ops.decrypt_file(enc, "pw")
    # Encrypted file is gone, plaintext restored.
    assert not enc.exists()
    assert dec == tmp_path / "hello.txt"
    assert dec.read_bytes() == b"hello, world\n"


def test_encrypt_wrong_password_leaves_source(tmp_path: Path):
    src = tmp_path / "data.bin"
    src.write_bytes(b"\x00" * 100)
    enc = file_ops.encrypt_file(src, "correct")
    # Source deleted after successful encrypt.
    assert not src.exists()

    # Now try decrypting with the wrong password — encrypted file must remain.
    with pytest.raises(crypto.BadPassword):
        file_ops.decrypt_file(enc, "wrong")
    assert enc.exists(), "failed decrypt must not delete the encrypted file"


def test_non_conflicting_name_picks_suffix(tmp_path: Path):
    (tmp_path / "x.txt").write_bytes(b"1")
    (tmp_path / "x (2).txt").write_bytes(b"2")
    (tmp_path / "x (3).txt").write_bytes(b"3")
    out = file_ops.non_conflicting_name(tmp_path / "x.txt")
    assert out == tmp_path / "x (4).txt"


def test_encrypt_does_not_overwrite_existing_lock_file(tmp_path: Path):
    src = tmp_path / "a.txt"
    src.write_bytes(b"original source")
    # Someone else's .lock file already at the target path.
    placeholder = tmp_path / "a.txt.lock"
    placeholder.write_bytes(b"sacred placeholder")
    # Encrypt — we must pick a non-conflicting name and leave the placeholder.
    out = file_ops.encrypt_file(src, "pw")
    assert placeholder.read_bytes() == b"sacred placeholder"
    assert out == tmp_path / "a.txt (2).lock"


def test_keep_source_flag(tmp_path: Path):
    src = tmp_path / "keep.txt"
    src.write_bytes(b"stay")
    file_ops.encrypt_file(src, "pw", delete_source=False)
    assert src.exists(), "delete_source=False must keep the plaintext"


def test_secure_delete_removes_file(tmp_path: Path):
    p = tmp_path / "s.bin"
    p.write_bytes(secrets.token_bytes(4096))
    file_ops.secure_delete(p)
    assert not p.exists()


def test_large_file_streaming(tmp_path: Path):
    # 5 MiB: forces a multi-chunk path through the streaming code.
    src = tmp_path / "big.bin"
    data = secrets.token_bytes(5 * 1024 * 1024)
    src.write_bytes(data)
    enc = file_ops.encrypt_file(src, "pw")
    dec = file_ops.decrypt_file(enc, "pw")
    assert dec.read_bytes() == data


def test_encryption_of_already_encrypted_file_works(tmp_path: Path):
    """Double-encryption is a supported workflow (user's call); the second
    layer still round-trips."""
    src = tmp_path / "doc.txt"
    src.write_bytes(b"inner")
    first = file_ops.encrypt_file(src, "outer-pw")
    second = file_ops.encrypt_file(first, "inner-pw")
    # Second layer decrypts with inner-pw; result is the first .lock file.
    first_dec = file_ops.decrypt_file(second, "inner-pw")
    # Then that decrypts with outer-pw back to the plaintext.
    orig = file_ops.decrypt_file(first_dec, "outer-pw")
    assert orig.read_bytes() == b"inner"
