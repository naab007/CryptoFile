# Changelog

## 1.0.7 (2026-04-15)

Security and bug-hunt hotfix. Addresses every in-scope finding from
`SECURITY_AUDIT_1.md` (2H / 6M / 7L) and `BUG_HUNT_10.md` (3H / 7M / 8L).
Wire format unchanged — files encrypted with 1.0.0–1.0.6 decrypt cleanly.

### Security — High

- **H1 — Argon2 header parameters were unbounded.** `Header.from_bytes`
  accepted any `memory_kib` / `time_cost` / `parallelism` the file
  declared. A hostile 52-byte header could request 4 TiB of RAM or
  2^32 passes and wedge the process before the password even
  mattered.
  Fix: `crypto.py` adds `ARGON2_{MIN,MAX}_{MEMORY_KIB,TIME_COST,PARALLELISM}`
  constants and `Header.from_bytes` raises `BadFormat` with the
  violating parameter named. Shipped defaults (256 MiB / 3 / 4) fit
  inside the window. (`cryptofile/crypto.py:Header.from_bytes`)

- **H2 — Batch coordinator had no auth.** Any process on the box that
  could open `127.0.0.1:<port>` could inject arbitrary paths into
  the primary's encrypt/decrypt queue — cross-user on shared Windows
  hosts.
  Fix: `batch.py` generates `secrets.token_hex(32)` per primary
  session, writes `"<port>:<token>"` to the port file (already 0o600
  on Windows because it's under the user profile), and every payload
  must include the token; `secrets.compare_digest` gates the handler.
  Tokens rotate across primary sessions so a stale token from a
  crashed primary can't replay. (`cryptofile/batch.py:start_server`,
  `_handle_connection`, `send_to_primary`)

### Security — Medium

- **M2 — Password not NFC-normalised.** Users who typed `café` on one
  IME (composed `U+00E9`) and on another (`e` + combining acute
  `U+0301`) got different AES keys from the same glyph. Lockout with
  no error feedback.
  Fix: `crypto.derive_key` calls `unicodedata.normalize("NFC", password)`
  before UTF-8 encoding. Backwards compatible because prior versions
  almost always saw the NFC form (Windows IMEs default to composed).
  (`cryptofile/crypto.py:derive_key`)

- **M3 — `.partial` inherited umask perms.** On POSIX the temp file
  sat at 0o644 until `os.replace`; on NTFS it inherited the parent
  directory's ACL. For a secret-bearing intermediate that's one roll
  of the dice too many.
  Fix: new `cryptofile/_atomic.py` opens `.partial` with
  `O_WRONLY|O_CREAT|O_EXCL|O_BINARY` at mode `0o600`. Also refuses to
  overwrite a pre-existing `.partial` (squatter defence).
  (`cryptofile/_atomic.py:atomic_write`, callers in
  `cryptofile/file_ops.py:encrypt_file,decrypt_file`)

- **M4 — Installer silently "succeeded" while the running exe was
  locked.** Windows queued the replacement for next reboot; ARP said
  1.0.7, the active process was still the vulnerable build.
  Fix: `installer.iss` adds `InitializeSetup()` that runs
  `tasklist /FI "IMAGENAME eq CryptoFile.exe"` and aborts with a
  messagebox if found. (`installer.iss:InitializeSetup`)

### Bug-hunt — High

- **H-new-3 — `shell_integration._write_verb` computed the icon path
  with `_shell_exe_path().split('"')[1]` plus a second call to
  `_shell_exe_path()`, both of which went wrong on unquoted paths
  containing a stray quote.**
  Fix: single call + explicit `_extract_exe_path()` helper that
  handles quoted and unquoted forms.
  (`cryptofile/shell_integration.py:_write_verb,_extract_exe_path`)

### Bug-hunt — Medium

- **M-new-3 — `.partial` leaked when `os.replace` failed.** The
  cleanup block lived inside the `with` context, so any exception
  from rename (AV lock on destination, concurrent run) left the
  temp file behind.
  Fix: cleanup moved to the outer `except` branch in
  `_atomic.atomic_write`. Regression test patches `os.replace` and
  asserts `list(tmp_path.glob("*.partial")) == []`.
  (`cryptofile/_atomic.py:atomic_write`)

- **M-new-4 — `wait_for_collection` idle clock started at zero.**
  A caller who forgot `add_local_path()` saw the idle window return
  immediately.
  Fix: `start_server` primes `self._last_arrival = time.monotonic()`.
  (`cryptofile/batch.py:start_server`)

- **M-new-1 — No persistent logs.** Silent-UI regressions like 1.0.3
  through 1.0.6 were diagnosed by guesswork because nothing survived
  the process.
  Fix: new `cryptofile/_logging.py` installs a `RotatingFileHandler`
  under `%LOCALAPPDATA%\CryptoFile\logs\cryptofile.log` (5 MiB x 3
  backups, lazy-created). No full paths written — only `safe_name()`
  basenames. Fails soft to `NullHandler` if the log dir can't be
  created. Wired from `__main__.main()`.

- **M-new-5 — Batch password dialog rendered behind Explorer.**
  Fix: `BatchPasswordDialog` calls `_force_window_foreground(self,
  self.e_pw)` 50 ms after construction — same dance used by
  `PasswordDialog` since 1.0.3. (`cryptofile/gui.py`)

- **M4 (bug-hunt) — `secure_delete` raised on transient unlink
  failures even when the file had already been zeroed.** Lost the
  secure-delete semantics for retryable errors.
  Fix: log the failure, only raise `FileOpError` if the file still
  has bytes on disk. (`cryptofile/file_ops.py:secure_delete`)

### Bug-hunt — Low

- **L-new-2 — Ambiguous `BadPassword` at chunk-0.** Added a clarifying
  comment so future readers don't "fix" it into leaking which chunk
  failed. (`cryptofile/crypto.py`)

- **L-new-4 — `shell_integration._delete_tree` caught only
  `FileNotFoundError`.** A DACL-restricted key aborted the whole
  uninstall and left stranded verbs.
  Fix: also catch bare `OSError` on `OpenKey` and `DeleteKey`.
  (`cryptofile/shell_integration.py:_delete_tree`)

- **L-new-6 — `BatchPasswordDialog` used `assert`.** Asserts compile
  out under `-O`, leaving the dialog to NPE on bad input.
  Fix: replace with explicit `ValueError` raises.
  (`cryptofile/gui.py:BatchPasswordDialog.__init__`)

- **L-new-7 — `ProgressWindow._drain` swallowed every exception
  including the progress-update itself.** Debugging blind.
  Fix: narrow the `except` to the set-progress call and log the
  exception via `logging.getLogger("cryptofile.gui")`.
  (`cryptofile/gui.py:ProgressWindow._drain`)

- **L-new-8 — `non_conflicting_name` looped unboundedly.** Hostile
  directory with N siblings made the function O(N).
  Fix: cap at `_NON_CONFLICTING_MAX_ATTEMPTS = 10_000`; raise
  `FileOpError` past the cap.
  (`cryptofile/file_ops.py:non_conflicting_name`)

### Observations (no code change)

- **I1 (SECURITY_AUDIT) — Argon2 working buffer may page to swap.**
  Noted in `docs/SECURITY.md`; documented as a known limitation of
  argon2-cffi under Windows.

### Tests

24 new regression tests in `tests/test_security_1_0_7.py` covering
H1 (six parameter-ceiling cases + defaults + boundary), H2 (token
presence, wrong-token rejection, tokenless rejection, accept on
correct token, rotation, end-to-end), M2 (NFC equivalence +
roundtrip across forms), M3 / M-new-3 (O_EXCL refusal, cleanup on
replace failure, cleanup on body exception, end-to-end
`encrypt_file` with flaky `os.replace`), L-new-8 (bounded +
capped), M-new-4 (primed idle clock). Total: 80 passing, 2
POSIX-only skips.

## 1.0.6 (2026-04-15)

### Bug fix
- **Frozen exe crashed at startup: `ModuleNotFoundError: No module named 'argon2'`.** The 1.0.5 build was done with system Python (via `python build_exe.py` in bash) instead of the venv Python. System Python had PyInstaller installed but not `argon2-cffi`, so PyInstaller's static analysis produced an exe with no `argon2` package bundled. 1.0.1–1.0.4 had worked because earlier builds happened to go through the venv.

  Fix (two layers):
  1. `build_exe.py` now uses `--collect-all argon2` instead of only `--hidden-import argon2.low_level`. `argon2-cffi` is a cffi package — `--collect-all` pulls the whole package tree plus the generated binary extension and data files, immune to which Python invocation runs the build.
  2. All future builds must go through `.venv/Scripts/python.exe build_exe.py`, not bare `python`.

No crypto / wire-format changes. The 1.0.5 release artifacts were broken at startup; 1.0.6 supersedes them.

- **Batch path (`__main__._run_batch`) still used `dummy_root.withdraw()`** for the per-batch dummy root after 1.0.5's fix. Result: multi-file right-click → batch progress window invisible (same bug as 1.0.5, just on the batch path). Now uses the same 1x1 off-screen transparent root.

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
