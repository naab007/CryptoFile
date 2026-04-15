# CryptoFile — Threat model & security notes

This document is the security-honest view of what CryptoFile defends against,
what it does not, and what artifacts of an "encrypted" file's existence can
survive on a typical Windows machine despite our best efforts.

Read this **before** you rely on CryptoFile to protect anything critical.

## Scope

CryptoFile is designed for the following scenarios:

- **"I want this file on my laptop to be unreadable if the laptop is stolen."**
  Secure against a casual attacker + filesystem-layer recovery tools on a
  modern Windows machine — provided you also enable BitLocker. Without
  BitLocker, see the Volume-Shadow-Copies / pagefile discussion below.
- **"I want to email this file and only my colleague should be able to open it."**
  Secure if you transmit the password out-of-band (Signal, phone call).
  The ciphertext file is useless without the password.
- **"I want to store this in OneDrive / Dropbox and be sure the cloud provider
  can't read it."** Secure; the cloud sees only ciphertext.

It is **not** designed for:

- High-assurance government / military requirements — get a proper KMS.
- Resistance to memory forensics on a running machine — Python strings
  aren't mlocked.
- Post-quantum security — AES-256 is believed post-quantum-secure for
  the next two decades, Argon2id doesn't move the needle either way, but
  formally this is not a PQC system.

## What it defends against

### Data-at-rest

Ciphertext is authenticated with AES-256-GCM, keyed by Argon2id(256 MiB,
3 iterations, 4 lanes). Breaking the file without the password requires
one of:

1. **Brute-forcing the password.** Argon2id caps how fast that goes.
   Rough numbers on a single GPU as of 2026:
   - 6-char lowercase wordlist → minutes
   - 8-char mixed-case alphanumeric → weeks on a $10k farm
   - 12-char mixed with symbols → centuries
   - 5-word diceware passphrase (~64 bits entropy) → centuries
2. **Key recovery without brute force** — would require breaking AES-256
   or Argon2id. Neither is plausible with publicly known cryptanalysis.

The strength is therefore **entirely dependent on your password**. Use a
12+ character mixed string, or better, a 5-word random passphrase.

### Tampering

Every GCM chunk tag is bound via AAD to the full header, the chunk index,
and a final-flag byte. Consequences:

- Flip any header byte → every chunk's tag fails → `BadPassword` (we
  can't distinguish header tampering from wrong password — by design).
- Swap two chunks → each tag verifies against the wrong chunk index →
  authentication fails.
- Splice a chunk from another CryptoFile → different base_nonce /
  different key → authentication fails.
- Truncate the last chunk → `is_final=1` flag is missing → we raise
  `CryptoError("encrypted file did not contain a final chunk")`.
- Append bytes after the last chunk → caught as `CryptoError("trailing
  bytes after final chunk — file tampered")`.

### Metadata

- Plaintext size is authenticated (stored in the header and bound into
  every chunk's AAD). An attacker can't quietly replace a small
  plaintext_size with a large one to trick the decrypt loop.

## What it does NOT defend against

### Brute force after the attacker has the ciphertext

We do not (and cannot) rate-limit password attempts on the ciphertext
file itself. An attacker with the `.lock` file can script
`cryptofile.exe decrypt` in a loop against offline copies. **Only
password strength saves you here.** See "What it defends against" above
for ballpark numbers.

### Compromised source machine

If the machine running CryptoFile is compromised (keylogger, memory
scraper, hostile kernel driver), the plaintext + password are both
available to the attacker before we ever touch them. Nothing a
userspace tool can do will fix this. Full-disk encryption + endpoint
security + not running as admin are the right defenses.

### Lost passwords

There is no key escrow, no recovery phrase, no backdoor. If you forget
the password, the file is gone.

## Disk recovery — can the plaintext be recovered after secure-delete?

The short answer depends on three things: (1) the storage medium,
(2) TRIM support, (3) whether BitLocker is on.

### Our secure-delete does

For each byte of the source file: overwrite in place with
`secrets.token_bytes(chunk)`, `fsync`, truncate to zero, `fsync`,
`unlink`.

### On a modern TRIM-enabled SSD (the typical 2020+ laptop)

Our overwrite **does not hit the physical NAND cells** that held the
plaintext. SSDs have a flash translation layer (FTL) that maps logical
block addresses (LBAs) to physical pages; `write(LBA)` allocates a
**new** page and marks the old one stale. The old plaintext remains in
flash until the block containing it is garbage-collected (minutes to
days).

**However** — when we `unlink` the file, Windows issues a **TRIM**
command for those LBAs. The SSD then marks the pages as officially
deallocated, and reads of those LBAs return zeros (on most consumer
drives — some return the original data until GC, which is still opaque
to filesystem-layer tools).

Filesystem-layer recovery tools (Recuva, PhotoRec, R-Studio, Windows
File Recovery) read through the OS block layer. **They cannot recover
the plaintext** after a successful TRIM, because all they see is the
post-TRIM zero response.

Chip-off forensics (desolder the NAND, read it directly, reconstruct
through the FTL yourself) can pull pre-GC data for hours-to-days. This
requires a Cellebrite-class lab. Not relevant to consumer-grade recovery
tools.

### On a HDD

Our overwrite **does** touch the same physical sectors. One random-byte
pass is enough on post-2001 drives; the old Peter Gutmann 35-pass
pattern is theater on modern media densities. Filesystem-layer tools
see random bytes in the old sectors — **unrecoverable at the block
level.**

### On external USB flash / SD cards / cheap SSDs without TRIM passthrough

No TRIM, limited wear leveling depending on the controller. Our
overwrite may or may not hit the same physical cells — varies by
device. **Assume recoverable for high-value targets.**

## What really survives — and why BitLocker is the real fix

Our secure-delete does **nothing** about the places plaintext actually
survives on Windows. In practice these are the paths used to recover
data after "secure delete":

1. **Volume Shadow Copies** — System Restore, File History, backup
   software, and Windows Server Shadow Copies keep snapshots of files
   including your pre-encrypt plaintext. `vssadmin list shadows` +
   ShadowExplorer pulls them back trivially.
2. **Previous Versions** tab in Explorer (same mechanism).
3. **Cloud sync** — OneDrive / Dropbox / Google Drive / iCloud retain
   deleted files in the provider's trash for 30+ days. The `.lock`
   file syncs up; the plaintext is still in the cloud recycle bin.
4. **File History** — Windows 10/11 continuous backup feature.
5. **Third-party backup** — Backblaze, CrashPlan, iDrive, etc.
6. **`pagefile.sys`** — if the plaintext was ever in RAM (it was, in our
   chunk buffers; it was also in whatever app created it), pagefile
   may hold fragments. Not cleared on shutdown by default.
7. **`hiberfil.sys`** — hibernation dumps all of RAM to disk.
8. **Windows Search indexer** — indexed content cached in
   `Windows.edb`.
9. **Thumbnail cache** (`thumbcache_*.db`) — cached previews for media.
10. **Application caches** — Office autosave, text-editor session
    restore, browser download cache, AV quarantine copies.
11. **NTFS `$LogFile` / `$UsnJrnl`** — for very small files the
    MFT-resident content can live in the journal briefly.

**The only defence against all of the above at once is full-disk
encryption with a TPM-protected volume key (BitLocker on the system
drive).** When BitLocker is on, every byte written anywhere on the
volume — pagefile, shadow copy, indexer cache, journal — is already
ciphertext before any recovery tool sees it. The machine's own
decryption key is released only on a trusted boot.

**Recommendation:** turn on BitLocker. CryptoFile is not a substitute
for FDE; it's an additional layer for specific files you want to ship
off the machine or into the cloud.

## Multi-file coordinator attack surface

The batch coordinator binds a localhost TCP socket for path delivery.
A local process running as the current user could connect to that
socket and inject paths. Mitigations:

- **Bound to 127.0.0.1 only** — not exposed on LAN or VPN interfaces.
- **Ephemeral port** (OS-picked, fresh per invocation) — no fixed port
  to target from malware already installed on the box.
- **Server-side `Path.is_file()` check** — we refuse to queue
  nonexistent paths, so at least the attacker can't cause us to
  encrypt a non-existent victim.
- **Confirmation in the batch password dialog** — the file list is
  rendered, the user must click Encrypt, so any injected path would
  be visible before the operation begins.
- **300 ms collection window** — closes automatically; the window
  during which a malicious process could race in is bounded.

**Threat model:** if a hostile process is already running as the user,
it can do anything the user can. The coordinator merely prevents
accidental cross-contamination with well-meaning local tools.

## Shell-integration attack surface

Our verbs are registered under `HKCU`. Any process running as the
current user can silently rewrite the command line:

```
HKCU\Software\Classes\*\shell\CryptoFile.Encrypt\command\(default) =
    "attacker.exe"  "%1"
```

Next right-click → user runs attacker code with their own privileges.
This is inherent to HKCU shell extensions — the alternative is HKLM
which requires admin and trades it for a slightly different machine-wide
threat. **Mitigation:** don't run as a compromised user. (Also: set the
exe path to a monitored location so you'd notice changes.)

## Header metadata leakage

The header is **not encrypted**. An attacker who has the `.lock` file
learns:

- Plaintext size (exactly, to the byte)
- Argon2id cost parameters — not sensitive
- That the file is specifically a CryptoFile and not some other `.lock`
  product

Filename preservation is also a leak:
`secret-payroll.xlsx.lock` tells the attacker what was inside to the
extension. **Rename before encrypting** if the filename itself is
sensitive (`cryptofile-1.lock` conveys almost nothing).

## Secure coding notes

- We treat every GCM tag failure on chunk 0 as a "wrong password or
  corrupted file" error and return one message to the user — we don't
  leak whether the password was wrong vs the ciphertext was tampered.
- On later chunks we do distinguish — but by that point the attacker
  necessarily has a decryptable key, so the distinction doesn't give
  them any new information.
- Python strings holding the password are not zeroed — `bytes` objects
  in CPython are immutable and the GC eventually collects them. Memory
  scrapers on a compromised machine can recover the password during
  the encryption window. We document this as accepted given the scope.
- The release exe is built with PyInstaller `--onefile --windowed`.
  The bootstrapping unpacks the embedded zip to `%TEMP%\_MEI…\` at
  launch; a race-condition swap of files in that directory by a
  concurrent attacker-run process is a theoretical attack. Code
  signing + AppLocker would mitigate; out of scope for v1.
- **Argon2id working buffer may page to the Windows pagefile**
  (SECURITY_AUDIT_1 I1). argon2-cffi's memory allocator on Windows
  uses `malloc`; 256 MiB of key material can be paged out while a
  derivation is in flight. `VirtualLock` would prevent this but is
  not exposed by the bindings. The salient mitigation is the same
  one that protects every other volatile artefact on the box:
  BitLocker. Documented rather than fixed because the fix requires a
  C shim below our dependency surface and the residual risk — an
  attacker with a forensic image of the pagefile — is already
  out-of-scope (they can also read unencrypted plaintext from the
  same image).
- **Intermediate `.partial` files are created with `O_EXCL` and mode
  `0o600`** (SECURITY_AUDIT_1 M3). This closes two gaps: (a) on
  POSIX the temp file no longer inherits the process umask (was
  typically `0o644`); (b) `O_EXCL` refuses to overwrite an existing
  `.partial`, so a concurrent primary or a prior crash's leftover
  can't be quietly written through. On NTFS the file still inherits
  the parent directory's ACL — we rely on the user profile
  directory being the usual destination and assume the user's
  profile ACL is already correctly restrictive.

## Summary

| Threat | Defence | Residual risk |
|---|---|---|
| Offline brute force of the ciphertext | Argon2id + 256 MiB memory cost | Password strength-dependent; weak passwords fall in hours |
| Chunk / header tampering | GCM AEAD with AAD binding header + index + final-flag | None; any tamper fails authentication |
| Truncation of final chunk | Authenticated `is_final` flag + check `remaining == 0` | None |
| Plaintext recovery via filesystem tools on HDD | Random overwrite before unlink | None (post-2001 drives) |
| Plaintext recovery via filesystem tools on SSD+TRIM | TRIM after unlink → LBAs read as zeros | Chip-off lab recovery of pre-GC data; not a consumer threat |
| Plaintext in Volume Shadow Copies / pagefile / etc. | **Not defended by CryptoFile** | **BitLocker required** |
| Compromised running machine | Out of scope | Password + plaintext both leak |
| Forgotten password | None (no escrow) | File is lost |
| Local malicious process injects paths into batch coordinator | 127.0.0.1 bind + ephemeral port + Path.is_file() + user confirmation | Low — local user has bigger concerns |
| HKCU shell-verb hijack | Documented limitation; HKLM needs admin | Low on a trusted machine |
