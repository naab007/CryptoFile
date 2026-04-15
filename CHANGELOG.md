# Changelog

## 1.0.1 (2026-04-15)

Post-audit hardening + proper installer. No user-facing API changes; wire
format unchanged.

### Installer (new)

- **`CryptoFile-Setup-1.0.1.exe`** — Inno Setup-based installer (16.7 MB).
  Installs per-user (no admin) to `%LOCALAPPDATA%\Programs\CryptoFile\`,
  registers the right-click context-menu verbs automatically (both file
  and folder variants), creates a Start Menu entry, and writes an
  Add/Remove Programs entry for one-click uninstall from Windows
  Settings. Source: `installer.iss` at the repo root.
- **New `install-shell` / `uninstall-shell` CLI modes** on
  `CryptoFile.exe` — used by the installer's `[Run]` and `[UninstallRun]`
  sections to register/unregister shell verbs silently. Exit code 0 on
  success, 1 on failure.

### Fixed

- **C1** — `encrypt_stream` now raises `CryptoError("source file grew during
  encryption")` if the input produced exactly `plaintext_size` bytes in the
  read loop but has additional bytes afterwards. Prevents silent data loss
  when the source file is appended to between `stat()` and encryption.
- **C2** — `_walk_files` no longer recurses into NTFS reparse points
  (junctions, symlinked directories, other link classes). Previously
  `os.walk(followlinks=False)` only suppressed symlinks; a junction inside
  a selected folder could cause encryption of files outside the tree the
  user picked — including system directories. Checked via
  `stat.FILE_ATTRIBUTE_REPARSE_POINT` on Windows.
- **C3** — `encrypt_stream` / `decrypt_stream` accept a `cancel_check`
  callback that's polled per chunk; raises `crypto.Cancelled` if it
  returns True. Wired through `file_ops.encrypt_file` / `decrypt_file` and
  both the single-file and batch GUI paths. Cancelling a 10 GB encryption
  now aborts at the next chunk boundary instead of running to completion.
- **H5** — `shell_integration.is_installed()` now verifies the registered
  command's exe path still resolves to a real file. After moving the exe,
  Settings correctly shows "not installed" / "Reinstall" instead of
  falsely claiming it's installed.
- **M3** — `batch.BatchCoordinator._handle_connection` catches `ValueError`
  alongside `OSError` so a malformed path (NUL byte, Windows-invalid
  characters) no longer crashes the accept thread.
- **M5** — `secure_delete` now takes the file size from `os.fstat` on the
  open handle instead of a prior `path.stat()` call, closing a benign
  TOCTOU where a rapidly replaced file could leak tail bytes.

### Tests

- **56 passing** (up from 47). New regression tests: C1 chunk-aligned grow
  + oversized-read paths, C3 cancel-aborts-encrypt / -decrypt / cleans
  `.partial`, C2 is-reparse-point helper + Windows junction refusal (via
  `mklink /J`; skipped cleanly if `mklink` not available), M3 coordinator
  handles NUL-byte path.

## 1.0.0 (2026-04-15)

Initial release. Right-click file and folder encryption for Windows with a
strong default crypto suite and first-class multi-file support.

### Features

- **Shell integration** — `Encrypt with CryptoFile` on every file and folder;
  `Decrypt with CryptoFile` on `.lock` files and folders. Installs into the
  current-user hive (`HKCU\Software\Classes\*`, `Directory\shell`, `.lock\shell`,
  and the `CryptoFile.Locked` ProgID). No admin required.
- **Password-based encryption** using Argon2id (256 MiB, 3 iterations, 4 lanes)
  to derive a 32-byte key and AES-256-GCM for the cipher. KDF parameters are
  stored per file so future tightening never breaks old files.
- **Streaming cipher** in 1 MiB chunks. Each chunk carries its own GCM tag
  and is authenticated via AAD that binds the full header, the chunk index,
  and a final-flag byte — chunk swapping, truncation, and header tampering
  all fail authentication.
- **Secure delete** of the source after successful encrypt or decrypt:
  random-byte overwrite + `fsync` + truncate + unlink. Best-effort on SSDs
  (see `docs/SECURITY.md`).
- **Multi-file batch UI** — multi-select N files in Explorer, Windows spawns
  N exe invocations, a single-instance coordinator funnels them all into
  one primary process. User sees one password dialog (with scrollable file
  list + optional "different password per file" checkbox) and one
  two-level progress window (files N/total + current-file bytes).
- **Recursive folder support** — right-click a folder to walk it
  recursively. Encrypt walker skips already-`.lock` files and symlinks;
  decrypt walker picks only `.lock` files. Symlinked subdirectories are
  never followed (`os.walk(followlinks=False)`).
- **500-file confirm gate** — batches of 500+ files require an extra
  Yes/No confirmation before the password prompt so a stray right-click
  on a huge folder can't run away.
- **Non-overwriting output** — if `foo.txt.lock` already exists, the new
  output becomes `foo.txt (2).lock`. Existing files are never destroyed.

### Crypto decisions (locked in for v1; file-format version 0x01)

- KDF: Argon2id (RFC 9106).
- Cipher: AES-256-GCM with 12-byte nonces.
- Nonce construction: 8 random bytes per file || 4-byte big-endian chunk counter.
- AAD per chunk: full 52-byte header || chunk index (u32 BE) || is_final (u8).
- Chunk size: 1 MiB plaintext, 1 MiB + 16 B ciphertext+tag on disk.

### Known limitations (documented in `docs/SECURITY.md`)

- The file header reveals plaintext size (u64) and KDF cost parameters.
- Original filename + extension are preserved in the `.lock` filename.
- Secure delete does not defeat Volume Shadow Copies, pagefile, hibernation
  file, File History, cloud-sync history, or chip-off SSD forensics.
- No password-attempt rate-limiting; strength depends entirely on password.
- No key escrow — lost passwords mean lost files.

### Build

- Python 3.12, `cryptography>=42`, `argon2-cffi>=23.1`.
- PyInstaller `--onefile --windowed` produces `dist\CryptoFile.exe`, 14.3 MB.
- 47 tests passing (25 crypto + 10 batch coordinator + 12 expansion).
- 2 symlink tests skipped on Windows (creating symlinks requires admin).
