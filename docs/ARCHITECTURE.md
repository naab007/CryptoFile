# CryptoFile — Architecture

A bird's-eye view of every moving piece, the runtime dispatch, and the
threading model. Read this alongside [`PROTOCOL.md`](PROTOCOL.md) (wire
format) and [`SECURITY.md`](SECURITY.md) (threat model).

## Module layout

```
cryptofile/
├── __init__.py          version string
├── __main__.py          entry point + dispatch
├── crypto.py            KDF + streaming AEAD encrypt/decrypt
├── file_ops.py          atomic file writes, secure delete, walker
├── batch.py             single-instance coordinator for multi-file
├── gui.py               tk dialogs + progress windows
└── shell_integration.py HKCU registry install/uninstall
```

Every runtime-critical module is independently testable — the GUI is a
thin wrapper around the core, not the other way around. `crypto.py`
knows nothing about files; `file_ops.py` knows nothing about the GUI;
`batch.py` knows nothing about crypto.

### crypto.py

Only concerned with **bytes in, bytes out**. Two public functions:

- `encrypt_stream(plain_in, enc_out, password, plaintext_size, progress=None, **kdf_params)`
- `decrypt_stream(enc_in, plain_out, password, progress=None) -> Header`

The module owns the `Header` dataclass and the `BadPassword` / `BadFormat` /
`CryptoError` exception hierarchy. It doesn't touch the filesystem or
tkinter. See [`PROTOCOL.md`](PROTOCOL.md) for the exact on-disk layout.

### file_ops.py

Bridges `crypto.py` to the real filesystem:

- `encrypt_file(src, password, progress=None, delete_source=True) -> Path`
- `decrypt_file(src, password, progress=None, delete_source=True) -> Path`
- `secure_delete(path, passes=1)` — random overwrite + truncate + unlink
- `non_conflicting_name(target)` — returns `target (2)`, `(3)`, … if taken
- `expand_for_encrypt(inputs) -> Expansion` — turns file/folder inputs into
  a flat file list plus per-skip-category buckets
- `expand_for_decrypt(inputs) -> Expansion` — same shape; filters for
  `.lock` files when walking a folder

The `Expansion` dataclass is the hand-off between the dispatch layer and
the worker thread — it carries the files to process plus every kind of
path we decided to skip (already encrypted, not encrypted, symlinks,
walk errors). The summary modal reads all of those to show the user
where every input went.

### batch.py

Single-instance coordinator so N Explorer invocations become 1 UI.
See [`SECURITY.md`](SECURITY.md) §Multi-file for the threat analysis on
this surface. Implementation notes:

- Per-user lock at `%LOCALAPPDATA%\CryptoFile\<action>.lock`.
- Locking via `msvcrt.locking(LK_NBLCK, 1)` on Windows, `fcntl.flock` elsewhere.
- Primary binds `127.0.0.1:0`, writes the port atomically to
  `<action>.port`, starts a background accept thread.
- Secondaries read port file, connect, send `{"path": "..."}\n`, exit.
- Primary waits `timeout_ms=300` total with `idle_ms=150` reset after
  each arrival before moving on. Dedup by `Path.resolve()`.

### gui.py

Four self-contained widgets:

- `PasswordDialog` — single-file prompt (double-entry for encrypt, single
  for decrypt, optional show-password toggle, short-password warning).
- `ProgressWindow` — single-file progress bar + cancel.
- `BatchPasswordDialog` — multi-file prompt with scrollable file list and
  per-file-password checkbox.
- `BatchProgressWindow` — two bars (overall files done / total + current
  file bytes) + cancel.

Each widget exposes a constructor-plus-`.result`/`.cancelled()` pair so
the caller drives them via `wait_window` and reads the state after. No
module-global Tk root is kept — every helper creates an invisible root
when called without a parent, and destroys it on return. This keeps the
dispatcher composable: single-file flow and batch flow both set up and
tear down Tk cleanly.

The `run_with_progress(parent, title, subtitle, worker)` helper is the
canonical "run this long operation on a worker thread with a progress
window" idiom. Returns `(result, exception)` — exactly one is None.

### shell_integration.py

Purely registry I/O, no crypto awareness. Writes the following on
`install()`:

| Subkey (under `HKCU\Software\Classes\`) | Meaning |
|---|---|
| `*\shell\CryptoFile.Encrypt` | Encrypt verb on all files |
| `.lock\(default) = CryptoFile.Locked` | ProgID mapping for `.lock` files |
| `CryptoFile.Locked\(default) = "Encrypted CryptoFile"` | ProgID display name |
| `.lock\shell\CryptoFile.Decrypt` | Decrypt verb on `.lock` files |
| `CryptoFile.Locked\shell\CryptoFile.Decrypt` | Same verb under the ProgID |
| `Directory\shell\CryptoFile.Encrypt` | Encrypt verb on folders |
| `Directory\shell\CryptoFile.Decrypt` | Decrypt verb on folders |

The `Directory\shell` entries make the verbs appear on folder
right-click; identical labels to the file verbs mean Explorer shows one
consistent entry for mixed multi-select.

`uninstall()` removes all of the above. The `.lock` extension ProgID
mapping is deliberately left alone on uninstall in case another tool
started relying on the `CryptoFile.Locked` ProgID.

### __main__.py

The dispatch layer. Flow:

```
           ┌──────────────────────────┐
           │ cryptofile.exe <args>    │
           └───────────┬──────────────┘
                       │
        ┌──────────────┴──────────────────────────┐
        │                                         │
        ▼                                         ▼
   no-file args?                            cmd = encrypt|decrypt
        │                                         │
        ▼                                         ▼
   _run_settings()                   _coordinate_and_run(action, path)
                                             │
                                             ▼
                                    BatchCoordinator
                                             │
                             ┌───────────────┴───────────────┐
                             │                               │
                             ▼                               ▼
                   primary (first in)              secondary (later)
                   │                                │
                   ▼                                ▼
             start server              send path → primary → exit
             wait 300 ms
                   │
                   ▼
             collected paths
                   │
                   ▼
             _dispatch_paths(action, paths)
                   │
                   ├─ expand_for_{action}(paths) → Expansion
                   │
                   ├─ empty? → _show_empty_expansion + return
                   │
                   ├─ >= 500 files? → confirm gate
                   │
                   ├─ 1 file, no folder, no skips? → _run_single
                   │
                   └─ otherwise → _run_batch(Expansion)
```

## Threading model

Three thread roles:

1. **Tk main thread** — drives the UI. All widget operations go on this
   thread. Background work is dispatched via `win.after(0, callback)`.
2. **Coordinator accept thread** — runs in `BatchCoordinator.start_server`,
   lives only during the collection window (300 ms typical). Receives
   paths via socket, appends to the coordinator's list under a lock.
3. **Worker thread(s)** — one per long operation (`gui.run_with_progress`
   spawns this; `_run_batch` has its own similar pattern). Executes the
   actual crypto/IO. Progress is reported by calling
   `progress_window.after(0, ...)` to marshal back onto the Tk thread.

Every cross-thread communication is either (a) through an `after(0, …)`
marshal back to Tk, or (b) through a `threading.Event` + `list` pair for
"worker produced this result" style returns. There are no shared
mutable structures other than the coordinator's path list (explicitly
locked) and a few `Event`s.

## File-format versioning

The first byte after the magic is the format version (`0x01` as of v1.0.0).
Every decrypt call parses it and rejects unknown versions with a
`BadFormat`. Future tightening of KDF parameters or cipher swaps will
bump this byte and add branches in `crypto._header.from_bytes` — old
files continue to decrypt correctly because the header tells us which
branch to use.

## Testing surface

Three test modules, 47 tests total:

| Module | Covers |
|---|---|
| `tests/test_crypto.py` | 15 tests: round-trip at sizes 0 / 1 / chunk boundary / multi-chunk / unicode password / bad magic / tampered header / tampered ciphertext / truncation / trailing bytes / chunk swap / header round-trip / KDF param storage / distinct salts across encryptions. |
| `tests/test_file_ops.py` | 10 tests: roundtrip, wrong-password-keeps-source, non-conflicting-name, no-overwrite-existing-.lock, keep-source flag, secure-delete, 5 MiB streaming, double-encryption. |
| `tests/test_batch.py` | 10 tests: lock acquire/deny/release, independent encrypt+decrypt locks, real-file delivery, nonexistent-path rejection, 5 parallel secondaries, timeout when no primary, dedup, invalid action. |
| `tests/test_expansion.py` | 14 tests (2 skipped on Windows): single file, `.lock` skip, recursive walk, mixed plain/lock, mixed file+folder inputs, symlink skips, empty folder, dedup pass-through, decrypt variants, end-to-end folder roundtrip. |

GUI widgets are instantiated headlessly in smoke-test one-liners (not in
the pytest suite, which would need a display server), just to confirm
the tk layout builds without errors.

## Extension points

If CryptoFile gains features, these are the natural seams:

- **New cipher** (e.g. XChaCha20-Poly1305) → bump file-format version,
  add a branch in `crypto.encrypt_stream` selected by `cipher_algo`
  byte, keep old decrypt path intact.
- **New KDF** (e.g. Argon2id with increased defaults, or Balloon) →
  new `kdf_algo` byte, same branching approach.
- **Archive-style folder encryption** (one `.lock` per folder, contains
  a tar-like container) → new protocol version + new dispatch path;
  leave the per-file walker for the existing use case.
- **Hardware token / passkey auth** → new auth modes alongside the
  password path; the Argon2id-produced key continues to wrap
  per-file keys so the on-disk format doesn't need to change.
