"""File-level operations: atomic writes, secure-delete, name resolution."""
from __future__ import annotations

import os
import secrets
import stat as _stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from . import _logging, crypto
from ._atomic import atomic_write

_log = _logging.get("file_ops")

# Windows-only file attribute. Python's stdlib `stat` module exposes this
# on all platforms as of 3.12, but the attribute only appears on stat
# results produced by Windows. We gate use by sys.platform.
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(_stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

ENCRYPTED_SUFFIX = ".lock"


class FileOpError(Exception):
    pass


# ── Folder expansion ───────────────────────────────────────────────────────


@dataclass
class Expansion:
    """Result of expanding a list of user-picked paths (files and/or folders)
    into a flat list of files to process.

    Separate buckets for files that ARE the target, files that got skipped on
    purpose (already-encrypted during encrypt, non-.lock during decrypt), and
    paths we refused to follow (symlinks, permission errors)."""

    files: list[Path] = field(default_factory=list)
    skipped_already_encrypted: list[Path] = field(default_factory=list)
    skipped_not_encrypted: list[Path] = field(default_factory=list)
    skipped_symlinks: list[Path] = field(default_factory=list)
    walk_errors: list[tuple[Path, str]] = field(default_factory=list)


def _is_reparse_point(path: Path) -> bool:
    """Windows: True if ``path`` is a reparse point (junction, symlink, or
    any other NTFS link type). Other OSes: always False.

    Stronger than ``Path.is_symlink()``: ``os.walk(followlinks=False)``
    only suppresses symlinks, not other reparse classes. A junction at
    ``C:\\Users\\X\\Documents\\Link → C:\\Windows`` would be silently
    recursed into — and in an encryption tool that means overwriting
    system files. We refuse to enter reparse points of any kind.
    """
    if sys.platform != "win32":
        return False
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return bool(getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT)


def _walk_files(root: Path, errors: list[tuple[Path, str]]) -> Iterable[Path]:
    """Yield every non-reparse-point file under ``root``.

    Symlinks to files are NOT followed — the symlink itself shows up in
    ``Expansion.skipped_symlinks`` via the caller's per-file check.
    On Windows, junctions and other reparse-point directories are pruned
    from ``os.walk``'s descent.
    """
    def _on_error(e: OSError) -> None:
        errors.append((Path(getattr(e, "filename", "") or "?"), str(e)))

    for dirpath, dirnames, filenames in os.walk(
        root, followlinks=False, onerror=_on_error,
    ):
        if sys.platform == "win32":
            # Prune reparse-point subdirs before os.walk descends.
            # os.walk honours dirnames[:] mutations for this purpose.
            dirnames[:] = [
                d for d in dirnames
                if not _is_reparse_point(Path(dirpath) / d)
            ]
        for name in filenames:
            yield Path(dirpath) / name


def expand_for_encrypt(inputs: Iterable[Path]) -> Expansion:
    """Turn a list of user-picked paths into a list of files to encrypt.

    Rules:
    * File that isn't ``.lock`` → encrypt it.
    * File that IS ``.lock`` → skip as already-encrypted.
    * Folder → walk recursively, apply the same rules to each member.
    * Symlinks (at any level) → skip with an entry in ``skipped_symlinks``.
    """
    result = Expansion()
    for p in inputs:
        try:
            if p.is_symlink():
                result.skipped_symlinks.append(p)
                continue
            if p.is_file():
                if p.suffix.lower() == ENCRYPTED_SUFFIX:
                    result.skipped_already_encrypted.append(p)
                else:
                    result.files.append(p)
                continue
            if p.is_dir():
                for child in _walk_files(p, result.walk_errors):
                    try:
                        if child.is_symlink():
                            result.skipped_symlinks.append(child)
                            continue
                        if child.suffix.lower() == ENCRYPTED_SUFFIX:
                            result.skipped_already_encrypted.append(child)
                        else:
                            result.files.append(child)
                    except OSError as e:
                        result.walk_errors.append((child, str(e)))
                continue
            # Not a file, not a directory, not a symlink we can identify —
            # device node, pipe, etc. Skip silently; there's nothing sensible
            # to do with them.
        except OSError as e:
            result.walk_errors.append((p, str(e)))
    return result


def expand_for_decrypt(inputs: Iterable[Path]) -> Expansion:
    """Turn user-picked paths into a list of files to decrypt.

    Rules:
    * File that IS ``.lock`` → decrypt it.
    * File that isn't ``.lock`` → skip as not-encrypted.
    * Folder → walk recursively; only ``.lock`` files are selected.
    * Symlinks → skip.
    """
    result = Expansion()
    for p in inputs:
        try:
            if p.is_symlink():
                result.skipped_symlinks.append(p)
                continue
            if p.is_file():
                if p.suffix.lower() == ENCRYPTED_SUFFIX:
                    result.files.append(p)
                else:
                    result.skipped_not_encrypted.append(p)
                continue
            if p.is_dir():
                for child in _walk_files(p, result.walk_errors):
                    try:
                        if child.is_symlink():
                            result.skipped_symlinks.append(child)
                            continue
                        if child.suffix.lower() == ENCRYPTED_SUFFIX:
                            result.files.append(child)
                        else:
                            result.skipped_not_encrypted.append(child)
                    except OSError as e:
                        result.walk_errors.append((child, str(e)))
                continue
        except OSError as e:
            result.walk_errors.append((p, str(e)))
    return result


# ── Path helpers ───────────────────────────────────────────────────────────


def encrypted_name(src: Path) -> Path:
    """foo.txt → foo.txt.lock"""
    return src.with_suffix(src.suffix + ENCRYPTED_SUFFIX)


def decrypted_name(src: Path) -> Path:
    """foo.txt.lock → foo.txt. If the filename doesn't end in .lock we strip
    anyway (to cope with renamed inputs), appending '.decrypted' as a fallback
    so we never pick a name the user would overwrite silently."""
    if src.suffix == ENCRYPTED_SUFFIX:
        return src.with_suffix("")
    return src.with_suffix(src.suffix + ".decrypted")


# L-new-8 / SECURITY_AUDIT L3 — cap the conflict-resolution loop. An
# attacker (or unlucky filesystem) that pre-creates ``foo (2).lock`` ..
# ``foo (N).lock`` can force unbounded stat-spinning. 10_000 is already
# absurd for a normal user; beyond that we'd rather surface an error
# than hang the UI forever.
_NON_CONFLICTING_MAX_ATTEMPTS = 10_000


def non_conflicting_name(target: Path) -> Path:
    """If ``target`` exists, return ``target (2)``, ``target (3)``, … first
    name that doesn't exist. We never overwrite existing files — that's
    data loss waiting to happen.

    Raises :class:`FileOpError` after ``_NON_CONFLICTING_MAX_ATTEMPTS``
    tries so a pathological directory can't DoS the UI.
    """
    if not target.exists():
        return target
    stem = target.stem
    suffix = target.suffix
    parent = target.parent
    for n in range(2, _NON_CONFLICTING_MAX_ATTEMPTS + 2):
        candidate = parent / f"{stem} ({n}){suffix}"
        if not candidate.exists():
            return candidate
    raise FileOpError(
        f"could not find a non-conflicting name for {target.name!r} after "
        f"{_NON_CONFLICTING_MAX_ATTEMPTS} attempts"
    )


# ── Secure delete ─────────────────────────────────────────────────────────


def secure_delete(path: Path, passes: int = 1) -> None:
    """Overwrite the file's bytes with random data, truncate, unlink.

    Caveats (documented so the user knows what this guarantees):

    * **SSDs and modern flash**: wear leveling and TRIM mean the physical
      cells that held your plaintext are usually NOT the ones we just
      overwrote. Secure delete on SSD is best effort; the only real defence
      is full-disk encryption (BitLocker / VeraCrypt) so freed cells are
      already ciphertext before TRIM runs.
    * **HDDs**: one random pass is enough on modern drives. Multi-pass
      patterns (Gutmann, DoD 5220.22-M) are theatre on sub-100 GB/in² media.
    * **Copy-on-write filesystems** (ReFS, some network shares): the overwrite
      may allocate a new block and orphan the original. Again — FDE is the
      real answer.

    ``passes`` (L-new-3): values > 1 are effectively theatre on all
    modern media. Kept as a parameter for callers who want to request
    multiple HDD passes, but the default of 1 is the right answer on
    SSDs (wear levelling picks different cells) and HDDs alike.

    We still do the overwrite because it's cheap, it beats leaving plaintext
    in pagefile slack, and the cost-to-benefit ratio favours trying.
    """
    if not path.exists():
        return
    if not path.is_file():
        raise FileOpError(f"not a file: {path}")
    try:
        # Open read-write-binary so we can overwrite in place without
        # reallocating (on supported filesystems). Use fstat — taking size
        # from the open fd closes the TOCTOU between stat() and open().
        with open(path, "r+b") as f:
            size = os.fstat(f.fileno()).st_size
            for _ in range(max(1, passes)):
                f.seek(0)
                remaining = size
                while remaining > 0:
                    chunk = min(1024 * 1024, remaining)
                    f.write(secrets.token_bytes(chunk))
                    remaining -= chunk
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            # Truncate to zero so the directory entry still exists but the
            # size shrinks — some FS drivers clear old blocks on truncate.
            f.seek(0)
            f.truncate(0)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
    finally:
        # BUG_HUNT_10 M4 — on a locked file (AV mid-scan, a handle held
        # by another process) unlink may fail even after we've already
        # overwritten. The plaintext bytes are GONE from disk at this
        # point; the directory entry may linger for a few seconds but
        # it points at random bytes. Log and continue rather than
        # raising — raising here turns a secure-delete-succeeded into
        # a user-visible error.
        try:
            path.unlink()
        except OSError as e:
            _log.warning(
                "secure_delete: overwrite succeeded but unlink failed for %s: %s",
                _logging.safe_name(path), e,
            )
            # Re-raise as FileOpError only if the file still contains
            # bytes (we didn't even get to overwrite). Size == 0 means
            # the plaintext is already gone and the dentry will be
            # reaped by the OS.
            try:
                if path.exists() and path.stat().st_size > 0:
                    raise FileOpError(f"could not unlink {path}: {e}") from e
            except OSError:
                pass


# ── High-level encrypt / decrypt ──────────────────────────────────────────


ProgressCallback = Callable[[int, int], None]


def encrypt_file(
    src: Path,
    password: str,
    progress: ProgressCallback | None = None,
    cancel_check: Callable[[], bool] | None = None,
    *,
    delete_source: bool = True,
) -> Path:
    """Encrypt ``src`` to ``src.lock`` (with dedup suffix on conflict).

    On error, the partial output is deleted and the source is left untouched.
    On success, if ``delete_source`` is True, the source is securely deleted.
    Returns the final output path. Raises :class:`crypto.Cancelled` if
    ``cancel_check`` returned True mid-stream.
    """
    if not src.is_file():
        raise FileOpError(f"not a file: {src}")
    size = src.stat().st_size
    final_out = non_conflicting_name(encrypted_name(src))
    _log.info("encrypt_file start name=%s size=%d", _logging.safe_name(src), size)
    # Temp file in same directory so the final rename is atomic (same-volume).
    # ``atomic_write`` creates with O_EXCL + 0o600 (SECURITY_AUDIT M3) and
    # cleans up the .partial on ANY exception path, including os.replace
    # failures after the ``with`` block exits (BUG_HUNT_10 M-new-3).
    with open(src, "rb") as fin, atomic_write(final_out) as (fout, _tmp):
        crypto.encrypt_stream(fin, fout, password, size, progress, cancel_check)

    if delete_source:
        secure_delete(src)
    _log.info("encrypt_file done name=%s", _logging.safe_name(src))
    return final_out


def decrypt_file(
    src: Path,
    password: str,
    progress: ProgressCallback | None = None,
    cancel_check: Callable[[], bool] | None = None,
    *,
    delete_source: bool = True,
) -> Path:
    """Decrypt ``src.lock`` back to the original name (with dedup on conflict).

    On wrong password or corruption the partial output is removed and a
    :class:`cryptofile.crypto.BadPassword` (or other CryptoError) is raised
    — the source stays on disk. :class:`crypto.Cancelled` on user cancel.
    """
    if not src.is_file():
        raise FileOpError(f"not a file: {src}")
    final_out = non_conflicting_name(decrypted_name(src))
    _log.info("decrypt_file start name=%s", _logging.safe_name(src))
    # Same atomic-write pattern as encrypt_file; handles BUG_HUNT_10 M-new-3
    # and SECURITY_AUDIT M3 in one place.
    with open(src, "rb") as fin, atomic_write(final_out) as (fout, _tmp):
        crypto.decrypt_stream(fin, fout, password, progress, cancel_check)

    if delete_source:
        # SECURITY_AUDIT L5 — the encrypted file is already ciphertext, so
        # bit-recovery from free-space alone doesn't expose plaintext. But
        # a future attacker who later learns the password could combine
        # recovered ciphertext + password to reconstruct plaintext. One
        # random overwrite pass closes that window at the cost of a little
        # I/O. Full-disk encryption remains the real defense.
        try:
            secure_delete(src)
        except FileOpError as e:
            raise FileOpError(f"could not remove encrypted source: {e}") from e
    _log.info("decrypt_file done name=%s", _logging.safe_name(src))
    return final_out
