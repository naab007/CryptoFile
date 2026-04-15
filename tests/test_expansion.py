"""Folder-expansion tests for `expand_for_encrypt` / `expand_for_decrypt`."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from cryptofile import file_ops


# ── expand_for_encrypt ─────────────────────────────────────────────────────


def test_single_file_goes_to_files(tmp_path: Path):
    f = tmp_path / "note.txt"; f.write_bytes(b"x")
    exp = file_ops.expand_for_encrypt([f])
    assert exp.files == [f]
    assert exp.skipped_already_encrypted == []


def test_lock_file_is_skipped_as_already_encrypted(tmp_path: Path):
    f = tmp_path / "n.txt.lock"; f.write_bytes(b"x")
    exp = file_ops.expand_for_encrypt([f])
    assert exp.files == []
    assert exp.skipped_already_encrypted == [f]


def test_folder_expands_recursively(tmp_path: Path):
    root = tmp_path / "docs"
    (root / "sub" / "deep").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"a")
    (root / "b.md").write_bytes(b"b")
    (root / "sub" / "c.txt").write_bytes(b"c")
    (root / "sub" / "deep" / "d.bin").write_bytes(b"d")
    exp = file_ops.expand_for_encrypt([root])
    names = {p.name for p in exp.files}
    assert names == {"a.txt", "b.md", "c.txt", "d.bin"}


def test_folder_skips_lock_files_mixed_in(tmp_path: Path):
    root = tmp_path / "mix"
    root.mkdir()
    (root / "plain.txt").write_bytes(b"p")
    (root / "already.txt.lock").write_bytes(b"q")
    exp = file_ops.expand_for_encrypt([root])
    assert [p.name for p in exp.files] == ["plain.txt"]
    assert [p.name for p in exp.skipped_already_encrypted] == ["already.txt.lock"]


def test_mixed_file_and_folder_inputs(tmp_path: Path):
    lone = tmp_path / "lone.txt"; lone.write_bytes(b"x")
    root = tmp_path / "dir"; root.mkdir()
    (root / "nested.txt").write_bytes(b"y")
    exp = file_ops.expand_for_encrypt([lone, root])
    assert {p.name for p in exp.files} == {"lone.txt", "nested.txt"}


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks; Win requires admin")
def test_symlinks_are_skipped(tmp_path: Path):
    target = tmp_path / "real.txt"; target.write_bytes(b"r")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    exp = file_ops.expand_for_encrypt([link])
    assert exp.files == []
    assert exp.skipped_symlinks == [link]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_symlink_inside_folder_is_skipped(tmp_path: Path):
    root = tmp_path / "d"; root.mkdir()
    target = tmp_path / "outside.txt"; target.write_bytes(b"z")
    real = root / "real.txt"; real.write_bytes(b"x")
    (root / "link.txt").symlink_to(target)
    exp = file_ops.expand_for_encrypt([root])
    names = {p.name for p in exp.files}
    assert names == {"real.txt"}
    assert [p.name for p in exp.skipped_symlinks] == ["link.txt"]


def test_empty_folder_yields_no_files(tmp_path: Path):
    root = tmp_path / "empty"; root.mkdir()
    exp = file_ops.expand_for_encrypt([root])
    assert exp.files == []
    assert exp.walk_errors == []


def test_duplicate_inputs_produce_duplicates(tmp_path: Path):
    """expand_for_encrypt is a pure transform — dedup is the caller's job.
    The batch coordinator already dedups by resolved path before we get here."""
    f = tmp_path / "x.txt"; f.write_bytes(b"x")
    exp = file_ops.expand_for_encrypt([f, f])
    assert exp.files == [f, f]


# ── expand_for_decrypt ─────────────────────────────────────────────────────


def test_decrypt_single_lock_file(tmp_path: Path):
    f = tmp_path / "x.txt.lock"; f.write_bytes(b"c")
    exp = file_ops.expand_for_decrypt([f])
    assert exp.files == [f]


def test_decrypt_non_lock_file_skipped(tmp_path: Path):
    f = tmp_path / "plain.txt"; f.write_bytes(b"c")
    exp = file_ops.expand_for_decrypt([f])
    assert exp.files == []
    assert exp.skipped_not_encrypted == [f]


def test_decrypt_folder_picks_only_lock_files(tmp_path: Path):
    root = tmp_path / "mix"
    (root / "inner").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"a")
    (root / "b.txt.lock").write_bytes(b"b")
    (root / "inner" / "c.txt").write_bytes(b"c")
    (root / "inner" / "d.bin.lock").write_bytes(b"d")
    exp = file_ops.expand_for_decrypt([root])
    names = {p.name for p in exp.files}
    assert names == {"b.txt.lock", "d.bin.lock"}
    skipped = {p.name for p in exp.skipped_not_encrypted}
    assert skipped == {"a.txt", "c.txt"}


def test_decrypt_mixed_file_and_folder(tmp_path: Path):
    lone = tmp_path / "lone.txt.lock"; lone.write_bytes(b"x")
    root = tmp_path / "dir"; root.mkdir()
    (root / "nested.md.lock").write_bytes(b"y")
    (root / "other.txt").write_bytes(b"z")
    exp = file_ops.expand_for_decrypt([lone, root])
    assert {p.name for p in exp.files} == {"lone.txt.lock", "nested.md.lock"}
    assert [p.name for p in exp.skipped_not_encrypted] == ["other.txt"]


# ── end-to-end roundtrip through the walker + crypto ──────────────────────


def test_folder_encrypt_then_decrypt_roundtrip(tmp_path: Path, monkeypatch):
    from cryptofile import crypto
    # Fast KDF for speed.
    monkeypatch.setattr(crypto, "ARGON2_MEMORY_KIB", 8)
    monkeypatch.setattr(crypto, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(crypto, "ARGON2_PARALLELISM", 1)

    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    payload = {
        root / "a.txt": b"alpha bytes",
        root / "b.bin": bytes(range(256)) * 10,
        root / "sub" / "c.md": b"# heading\nbody\n",
    }
    for p, data in payload.items():
        p.write_bytes(data)

    # Encrypt every file the walker finds.
    enc_paths = file_ops.expand_for_encrypt([root]).files
    for p in enc_paths:
        file_ops.encrypt_file(p, "pw")

    # Now the walker (decrypt variant) must find exactly the .lock files.
    dec_paths = file_ops.expand_for_decrypt([root]).files
    assert len(dec_paths) == len(payload)
    for p in dec_paths:
        file_ops.decrypt_file(p, "pw")

    # Original data is back on disk.
    for p, data in payload.items():
        assert p.read_bytes() == data, p
