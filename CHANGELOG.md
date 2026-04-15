# Changelog

## 1.0.5 (2026-04-15)

### Bug fix
- **Progress window invisible — encryption creates `.partial` but no UI ever appears.** Same root cause as the 1.0.3 password-dialog bug, missed on that fix: `run_with_progress` and `ask_batch_password` still parented their Toplevels to a `withdraw()`-ed dummy `tk.Tk()`. On Windows, `Toplevel.transient(withdrawn_root)` produces a window that inherits the hidden parent's state and renders off-screen or behind Explorer. Worker thread started normally, created `<name>.partial`, ran Argon2id, began writing chunks — user saw nothing because the progress window was invisible. 1.0.3 fixed this for `PasswordDialog` only.

  Fix: `run_with_progress` and `ask_batch_password` now use the same 1x1 off-screen transparent dummy root as `ask_password`. `ProgressWindow` and `BatchProgressWindow` both gained the `_force_foreground` dance (topmost toggle + lift + focus_force for 150 ms) on construction, matching `PasswordDialog`.

No crypto / wire-format changes.

## 1.0.4 (2026-04-15)

### Bug fix
- **`RuntimeError: main thread is not in main loop`** when encrypting. Workers were calling `pw_win.after(0, pw_win.set_progress, …)` to marshal progress back to the main thread. While `.after()` is documented as thread-safe, in practice on Windows `--windowed` PyInstaller builds it can raise this error intermittently. Before 1.0.3, the error vanished silently; 1.0.3's new top-level try/except surfaced it as a messagebox.

  Fix: `ProgressWindow` and `BatchProgressWindow` now have thread-safe `report_progress()` / `report_file_start()` / `report_file_finish()` / `signal_batch_complete()` methods that write to locked state. The main thread runs a self-scheduled `_drain` loop every 80 ms that reads the state and updates the UI. Workers no longer call ANY tk method directly — eliminates the entire class of "main thread is not in main loop" failures for the common paths (single-file encrypt/decrypt, batch progress).

- The per-file-password batch path still uses `win.after(0, _ask)` to open a password dialog from the worker thread. That's the rare path (user ticks "Use a different password for each file" in the batch dialog). If the same issue hits there, the top-level error messagebox catches it rather than silent exit.

No wire-format / encryption changes.

## 1.0.3 (2026-04-15)

### Bug fix
- **Password dialog invisible when invoked from the right-click shell verb.** `PasswordDialog` is called transient to a withdrawn dummy root — a configuration that, on several Windows versions, causes the Toplevel to inherit the hidden parent's state and land either behind Explorer or off-screen entirely. Symptom from the user's point of view: click "Encrypt with CryptoFile", nothing happens.

  Fix: two layers.
  1. `ask_password` no longer uses `withdraw()` — it creates a 1x1 transparent, borderless, off-screen dummy root instead. `Toplevel.transient(parent)` now targets a real window and renders normally.
  2. `PasswordDialog` on construction runs `attributes("-topmost", True)` + `lift()` + `focus_force()`, then releases topmost 150 ms later. Forces the dialog to the foreground when the exe is launched from a shell verb that left focus with Explorer.

- **Silent crashes in the frozen `--windowed` exe now produce a visible error messagebox.** Previously an unhandled exception anywhere in dispatch vanished (stderr unreachable in --windowed mode). `main()` is now wrapped in a try/except that catches every exception, renders a messagebox with type + message + last 1200 chars of traceback, and falls back to stderr only if tkinter itself can't show a dialog.

No changes to encryption, file I/O, batch coordinator, or wire format.

## 1.0.2 (2026-04-15)

### Bug fix
- **Frozen exe crashed at startup with `ImportError: attempted relative import with no known parent package`.** PyInstaller was pointed at `cryptofile/__main__.py` directly; in that mode the entry script has no `__package__`, so every `from . import …` fails. The 1.0.1 smoke test caught this only when run via `python -m cryptofile` (which sets the package context) — the frozen exe path was never exercised end-to-end.

  Fix: added a top-level `run.py` shim that does `from cryptofile.__main__ import main`. `build_exe.py` now points at `run.py`; `cryptofile/` is imported as a proper package, and relative imports resolve correctly at runtime.

No code-level changes to the encryption, file handling, batch coordinator, or GUI — only the PyInstaller entry-point plumbing.

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
