# CryptoFile

Right-click a file or folder in Windows Explorer to encrypt it with a password.
Right-click the encrypted output to decrypt it.

## What you get

- **Encrypt with CryptoFile** on every file and folder in the right-click menu.
- **Decrypt with CryptoFile** on `.lock` files and on folders (walks and
  decrypts each `.lock` it finds).
- Strong password-based encryption with **Argon2id** + **AES-256-GCM**.
- Multi-file batches — select 50 files, enter one password, one progress
  window, one summary at the end.
- Recursive folders — select a folder, every file inside gets encrypted
  (symlinks are skipped; already-`.lock` files are left alone).
- Originals are securely overwritten after successful encrypt or decrypt
  (see the caveats in [`docs/SECURITY.md`](docs/SECURITY.md)).
- No admin required — everything registers under `HKCU`.

## How to install

**Recommended — installer**: download `CryptoFile-Setup-<version>.exe` from
the [Releases page](https://github.com/naab007/CryptoFile/releases) and
run it. No admin required (per-user install under
`%LOCALAPPDATA%\Programs\CryptoFile`). The installer registers the
right-click menu entries automatically and adds an Add/Remove Programs
entry so uninstallation is one click from Windows Settings.

**Portable** (advanced): download `CryptoFile.exe` directly, run it
once, click **Install** in the Settings window to register the
right-click entries.

## How to use

1. In Explorer, right-click a file or folder → **Encrypt with CryptoFile**
   → enter a password → done.
2. To decrypt: right-click the `.lock` file (or the folder containing them)
   → **Decrypt with CryptoFile**.

## Highlights

- **Argon2id KDF** (256 MiB memory, 3 iterations, 4 lanes) — per-file cost
  parameters stored in the header so they can be raised later without
  breaking old files.
- **AES-256-GCM** in 1 MiB chunks with per-chunk authentication. Each
  chunk's GCM tag is bound via AAD to the full header + chunk index +
  final-flag byte, so header tampering, chunk swapping, and truncation
  all fail authentication.
- **Per-file salt + nonce prefix** — two encryptions of the same plaintext
  with the same password produce different ciphertexts.
- **Single-instance coordinator** funnels N multi-select invocations into
  one primary process: one password dialog, one progress window, one
  summary. Uses a per-user file lock + localhost TCP handshake; no
  external dependencies.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module layout, runtime
  dispatch, threading model.
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — on-disk file format,
  AAD binding rules, nonce scheme, header layout.
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model, secure-delete
  caveats, disk-recovery discussion, known limitations.
- [`docs/BUILDING.md`](docs/BUILDING.md) — dev setup, running tests,
  producing the single-file exe.
- [`CHANGELOG.md`](CHANGELOG.md) — version history.

## Safety rails (one-page summary)

- **Forgotten passwords are unrecoverable.** There is no key escrow, no
  recovery phrase, no "forgot password" flow.
- **Never overwrites existing files.** If `foo.txt.lock` already exists,
  the new output becomes `foo.txt (2).lock`.
- **≥ 500-file batches** need a confirm click before the password prompt
  so a stray right-click on a huge folder doesn't run away from you.
- **Full-disk encryption (BitLocker) is strongly recommended** on top of
  CryptoFile. Secure-delete can't touch pagefile, hibernation file,
  Volume Shadow Copies, or cloud-sync history — BitLocker makes all of
  those already-encrypted at the block layer before any recovery tool
  gets a chance to see them.

## Current status

- Version **1.0.0** (2026-04-15)
- 47 tests passing on Windows / Python 3.12
- Single-file `dist\CryptoFile.exe`, 14.3 MB
