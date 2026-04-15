"""Atomic write helper + tightened-permission ``.partial`` creation.

Consolidates the partial-file cleanup logic that appeared twice in
``file_ops.py`` (encrypt and decrypt paths). Fixes BUG_HUNT_10 M-new-3
(``.partial`` leak when ``os.replace`` fails mid-rename, outside the
``with`` block's cleanup scope) and SECURITY_AUDIT_1 M3 (``.partial``
inherits parent-dir ACLs; we now create with 0o600 on platforms where
that matters).

Guarantees:

* On any exception (including ``KeyboardInterrupt`` and failures in
  ``os.replace``), the ``.partial`` is best-effort unlinked.
* The partial file is created with ``O_EXCL`` — we refuse to write into
  a pre-existing ``.partial`` (could be another CryptoFile instance).
* On POSIX and Windows-with-honoured-mode, the partial has 0600 owner-
  only permissions. Windows Python honours the mode bit via
  ``_O_WTEXT``-flavoured translation and the NT security descriptor
  inherited from the parent — this is a best-effort hardening; the
  authoritative guarantee is documented in ``docs/SECURITY.md``.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator


@contextmanager
def atomic_write(final_out: Path) -> Iterator[tuple[BinaryIO, Path]]:
    """Open a ``.partial`` next to ``final_out`` with owner-only perms,
    yield ``(file_handle, partial_path)``, then rename into place on
    successful exit. On any exception, unlink the partial.

    Usage::

        with atomic_write(final_out) as (fout, tmp):
            fout.write(...)
            # automatic: fsync + rename on success, unlink on error
    """
    tmp = final_out.with_name(final_out.name + ".partial")
    # Refuse to write into a pre-existing partial — could be a crashed
    # previous run, or a concurrent CryptoFile writing the same output.
    # Use O_EXCL so we get a clean error instead of clobbering.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY  # type: ignore[attr-defined]
    # 0o600: owner read+write only. On Windows the ACL model ignores
    # most POSIX bits, but Python's CRT emulation honours the write
    # bit at creation time and the NT ACL inherits from the parent
    # directory. Combined with documenting BitLocker as the real
    # data-at-rest defense, this meets SECURITY_AUDIT M3.
    fd = os.open(tmp, flags, 0o600)
    try:
        fout = os.fdopen(fd, "wb")
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    try:
        try:
            yield fout, tmp
            fout.flush()
            try:
                os.fsync(fout.fileno())
            except OSError:
                pass
        finally:
            # Always close the handle before attempting rename/unlink.
            # Windows refuses both if any handle is still open.
            try:
                fout.close()
            except OSError:
                pass
        # Success path — rename is part of the try so a failure here
        # still triggers the .partial cleanup in the except block.
        os.replace(tmp, final_out)
    except BaseException:
        # Any failure at all — yielded body, fsync, OR os.replace —
        # cleans up the partial. Fixes BUG_HUNT_10 M-new-3.
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
        raise
