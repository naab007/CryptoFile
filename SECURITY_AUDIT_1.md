# CryptoFile — Security Audit #1

Scope: security posture of CryptoFile 1.0.6 at `D:\App Dev\CryptoFile\`.
Methodology: `/security-audit` five-phase (scope, static, MITRE mapping,
threat hunting, findings). Reference library: `D:\Research\Security\` —
stack-relevant chapters 03 (Audit), 09 (Crypto), 13 (DevSecOps/Threat
modeling), 22 (Attack Vectors), 28 (Supply Chain), 33 (Secure Coding
— Argon2id/AES-256-GCM), 34 (Privacy).

Cross-checked against `BUG_HUNT_10.md` — security-adjacent findings flagged
against that document's severities.

**CVSS v4.0 Base (AV/AC/AT/PR/UI/VC/VI/VA/SC/SI/SA). Report only — no code
modified.**

---

## Severity counts

| Severity | Count |
|---|---|
| Critical | 0 |
| High     | 2 |
| Medium   | 6 |
| Low      | 7 |
| Info     | 4 |

---

## Threat-hunting pass — explicitly clean

- **No network egress**: zero imports of `urllib`, `http`, `requests`,
  `aiohttp`, `socket.create_connection`/`getaddrinfo` against anything
  other than `127.0.0.1` (Grep verified, `cryptofile/**`).
- **No telemetry / no updater / no remote config / no phone-home.** The
  only `socket` usage is `batch.py` bound to `127.0.0.1:0` for multi-select
  coordination.
- **No `eval` / `exec` / `compile` / `__import__` of user-controlled
  strings.** All imports are static.
- **No `subprocess`** in shipped code (Grep: zero matches). Only
  `tests/` uses `mklink` via subprocess for junction creation.
- **No `pickle` / `marshal` / `yaml.load`.** The only serialization on
  untrusted data is `json.loads` of a single-line `{"path": "..."}`
  message from the localhost coordinator socket with a 64 KiB cap
  (`batch.py:201-206`) — safe.
- **No dynamic DLL loading, no `ctypes.CDLL`, no `os.add_dll_directory`.**

Verdict: **the program is fully offline by design.** This eliminates
entire attack tactic families (TA0011 C2, TA0010 Exfiltration,
TA0008 Lateral Movement, most of TA0001 Initial Access).

---

## Focus-area assessments

### 1. Cryptographic implementation

The Argon2id + AES-256-GCM construction (Header → `crypto.py:222-304`
encrypt, `crypto.py:310-375` decrypt) is **sound as shipped**. The AAD
design is the strongest part of the codebase: binding
`header[0:52] || u32_be(chunk_index) || u8(is_final)` into every GCM
tag defeats the usual AEAD composition pitfalls simultaneously
(chunk swap, truncation, header tampering, cross-file splice, final-flag
forgery). See findings below for peripheral concerns; the AEAD
construction itself has no finding against it.

**Clean:** nonce construction, key/IV non-reuse, AAD completeness,
`is_final` authentication, zero-length edge case, `secrets.token_bytes`
entropy source (CSPRNG on all supported platforms). Argon2id parameter
choice (256 MiB, t=3, p=4) **meets or exceeds** OWASP 2025
recommendations (min 19 MiB, t=2) by a comfortable margin — reference:
`D:\Research\Security\33_Secure_Coding_Patterns.md` §Argon2id.

### 2. Wire-format integrity

Header parser (`Header.from_bytes` at `crypto.py:140-167`) validates
length, magic, version, KDF algo, cipher algo. Header reject paths all
raise `BadFormat` cleanly. See H1 below for **the one parser-DoS
vector**: `memory_kib` is read from untrusted input and passed
directly to Argon2id.

`plaintext_size` (`crypto.py:159`) is **not** used for pre-allocation —
it's only used as a loop counter in `decrypt_stream`. A `0xFFFF_FFFF_FFFF_FFFF`
declared plaintext size results in a read loop that stops at EOF with
`"truncated ciphertext"` — no memory blow-up. Clean.

Chunk truncation / swap / duplication / cross-file splicing: all
authenticated and covered by the test suite (`test_crypto.py`).

### 3. File I/O and secure-delete

Covered largely in BUG_HUNT_10. Security-specific items: M3 (tmpfile
ACL inheritance) and L5 (plain `unlink` of ciphertext) below.

### 4. Shell integration and registry

HKCU-only — consistent with the documented threat model
(`docs/SECURITY.md` §Shell-integration attack surface). See M4 (ProgID
collision with foreign `.lock` handlers) and L2 (icon extraction
IndexError) below.

### 5. Batch coordinator IPC

Documented attack surface (`docs/SECURITY.md` §Multi-file coordinator).
See H2 (peer-user trust boundary) — this is BUG_HUNT `M-new-2` re-rated
at High from a pure-security lens.

### 6. Password handling

See M2 (UTF-8 NFC normalization) and L1 (password lifetime in memory,
documented).

### 7. Supply chain / build

No code signing. `cryptography` and `argon2-cffi` are pinned with `>=`
floors, not upper bounds — see L6.

### 8. Windows-specific

Pagefile / hibernation / VSS leakage of pre-encrypt plaintext is honestly
documented in `docs/SECURITY.md` §What really survives. The right
answer is BitLocker. See I1 below for the one gap between documentation
and code.

---

## MITRE ATT&CK mapping (realistic paths)

| Tactic | Technique | Vector | Relevant finding |
|---|---|---|---|
| TA0002 Execution | T1204.002 User Execution: Malicious File | User double-clicks attacker-supplied `.lock` → CryptoFile decrypts; question is whether arbitrary code can run | **See verdict (c) below — no.** |
| TA0006 Credential Access | T1552.001 Credentials in Files | Password lives in Python `str` throughout encrypt/decrypt window; any local process at same integrity level can `ReadProcessMemory` | L1 |
| TA0006 Credential Access | T1056.001 Input Capture: Keylogging | Out of scope — documented in SECURITY.md |
| TA0009 Collection | T1005 Data from Local System | `.partial` files in user dirs readable by same-user processes during encryption | M3 |
| TA0040 Impact | T1565 Data Manipulation | Header parser DoS via malicious `.lock` forcing 4 TiB Argon2 allocation | **H1** |
| TA0040 Impact | T1486 Data Encrypted for Impact | Attacker gets us to encrypt files we'd then lose the plaintext of | H2 (batch path injection) |
| TA0005 Defense Evasion | T1546.001 Event Triggered Execution: Change Default File Association | HKCU ProgID override — documented limitation | M4 |
| TA0003 Persistence | T1547.014 Active Setup / T1546 — HKCU Shell verb hijack | Same-user process rewrites our `\command\(default)` to `attacker.exe` | Documented limitation (SECURITY.md); cannot be fixed in userspace |

No path identified for TA0010 Exfiltration, TA0011 C2, TA0008 Lateral
Movement, or TA0001 Initial Access.

---

## HIGH findings

### H1 — Parser DoS via untrusted Argon2 memory cost

**File:** `cryptofile/crypto.py:155` → `crypto.py:327` → `derive_key`
at `crypto.py:173-188`.

**CWE-400** (Uncontrolled Resource Consumption), **CWE-1284** (Improper
Validation of Specified Quantity in Input).

**CVSS v4.0:** AV:L/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L —
**Base 6.9 (Medium-High).** Attacker-required UI (victim opens a
malicious `.lock`) + availability impact on the decrypting machine.

`Header.from_bytes` accepts `memory_kib` as a raw u32 LE with **no upper
bound check** (line 155):

```python
memory_kib, time_cost = struct.unpack_from("<II", data, 8)
```

Then `derive_key(password, header)` (line 180-188) passes that
straight to `argon2.low_level.hash_secret_raw(memory_cost=...)`:

```python
return hash_secret_raw(
    secret=password.encode("utf-8"),
    salt=header.salt,
    time_cost=header.time_cost,
    memory_cost=header.memory_kib,   # untrusted u32 from file
    parallelism=header.parallelism,
    hash_len=KEY_SIZE,
    type=Argon2Type.ID,
)
```

A malicious `.lock` file that sets `memory_kib = 0xFFFFFFFF` declares a
**4 TiB Argon2 working set**. Outcomes:

1. On 16 GiB RAM systems: Argon2 allocates until Windows pagefile
   explodes or `MemoryError`; at minimum the decrypt process hangs
   under memory pressure and the UI becomes unresponsive for tens of
   seconds. Can crash the calling Explorer if paging cascades.
2. On systems with limited pagefile: immediate `malloc` failure →
   `argon2.exceptions.InsufficientMemory` propagates through the
   `except Exception` in `__main__._main_impl` safety net (line 44)
   → visible error messagebox. User-visible failure but not a crash.
3. `time_cost = 0xFFFFFFFF` + moderate memory: multi-hour CPU hang
   before first chunk verifies. Same UX class as (1).

**Attack scenario:** attacker mails a `.lock` file with a note "decrypt
this". User right-clicks → Decrypt → password prompt → Argon2id runs
with attacker-chosen cost → machine DoS for minutes-to-hours. This is
worse than "wrong password wastes one second" because the cost parameter
is **negotiated by the attacker, not the defender**.

Also a concern even for honestly-made files: if a future CryptoFile
version raised the default to e.g. 1 GiB, older machines decrypting that
file would hit memory pressure. This is not the attack case — but it
reinforces that per-file cost needs a ceiling.

**Fix:** validate in `Header.from_bytes`:

```python
MAX_MEMORY_KIB   = 2 * 1024 * 1024   # 2 GiB — 8× our default; plenty of headroom
MAX_TIME_COST    = 32
MAX_PARALLELISM  = 16

if not (8 <= memory_kib <= MAX_MEMORY_KIB):
    raise BadFormat(f"memory_kib out of range: {memory_kib}")
if not (1 <= time_cost <= MAX_TIME_COST):
    raise BadFormat(f"time_cost out of range: {time_cost}")
if not (1 <= parallelism <= MAX_PARALLELISM):
    raise BadFormat(f"parallelism out of range: {parallelism}")
```

Rationale for 2 GiB ceiling: OWASP 2025 recommends 19 MiB minimum, 1 GiB
as a reasonable ceiling for server-class hardening; 2 GiB leaves
forward-compatibility headroom for tightening our own default without
ever allowing an order-of-magnitude attacker advantage. `argon2-cffi`
itself enforces a lower bound (≥ 8 KiB) but no upper bound.

**Not in BUG_HUNT_10.** Genuinely new.

---

### H2 — Coordinator socket has no peer-user authentication

**File:** `cryptofile/batch.py:116-139` (server setup) +
`batch.py:192-227` (accept handler).

**CWE-306** (Missing Authentication for Critical Function) in a local
trust-boundary sense, **CWE-346** (Origin Validation Error).

**CVSS v4.0:** AV:L/AC:L/AT:P/PR:L/UI:A/VC:L/VI:H/VA:L/SC:N/SI:L/SA:N —
**Base 5.3 (Medium-High).** Requires local account + user interaction
(victim clicks "Encrypt all" on the dialog). Worth rating High because
the integrity impact is *data destruction* (original plaintext is
secure-deleted after encryption, unrecoverable).

**This is `BUG_HUNT_10.md M-new-2` re-rated.** From a pure-UX lens it
was Medium (another user on a shared machine is an odd threat model for
a personal encryption tool). From a security-audit lens it's High
because: **the batch list is a trust-critical decision** (the user
confirms it, but the file list is the attacker's injection point), and
the batch dialog auto-confirms on Enter (`gui.py:461`).

`socket.bind(("127.0.0.1", 0))` limits to localhost but **not to the
calling SID**. On a multi-user Windows box (Remote Desktop Services,
Terminal Server, shared workstation, CI runner) any logged-in user can:

1. `netstat -ano` to find the primary's port (their user doesn't own it
   but it's still enumerable).
2. Connect to `127.0.0.1:<port>`, send `{"path": "C:\\target\\file"}\n`.
3. Server-side `Path.is_file()` (line 216) only rejects non-existent
   paths — any real file the attacker points at is accepted.
4. Primary's batch password dialog lists the injected path. User (in a
   hurry, right-clicked 20 files) clicks Encrypt all → **attacker's
   chosen files are encrypted under victim's password**, original
   plaintexts secure-deleted.

Outcome: attacker doesn't get the ciphertext (it's written next to the
plaintext the victim chose), but the victim's system **loses access to
the injected files**. Destructive impact, not exfiltration.

Also note: the `Path.is_file()` check runs as the CryptoFile primary
user, which usually means the attacker can only inject files the victim
can already stat. On a system with multiple users sharing a home drive
or shared folders, this is still a meaningful attack surface.

**Fix (defense-in-depth, pick one or both):**

1. **Named pipe with SID-restrictive SDDL instead of TCP.** Python 3
   has no stdlib named-pipe server, but `win32pipe.CreateNamedPipe` with
   `SECURITY_DESCRIPTOR` restricting to the current user SID is ~15
   lines using `pywin32`. Drops the TCP stack entirely.

2. **Per-session token in the port file.** Write
   `<port>:<16 random bytes hex>` to the port file. Secondary reads
   both, sends `{"path": ..., "token": "..."}` over the socket.
   Server compares; reject if mismatch. Since the port file is created
   with default ACLs (inherited from `%LOCALAPPDATA%\CryptoFile\`, which
   is per-user), a different user can't read the token. This is the
   smaller change.

   ```python
   # batch.py:start_server
   self._token = secrets.token_hex(16)
   tmp.write_text(f"{port}:{self._token}", encoding="utf-8")
   # batch.py:_handle_connection
   if msg.get("token") != self._token:
       return
   # batch.py:send_to_primary
   port_s, token = self.port_path.read_text(encoding="utf-8").split(":", 1)
   s.sendall(json.dumps({"path": str(path), "token": token}).encode() + b"\n")
   ```

3. **Optional:** `SO_EXCLUSIVEADDRUSE` on Windows to prevent a malicious
   process from hijacking the port if the primary crashes mid-batch.

**Cross-check:** see `BUG_HUNT_10.md M-new-2` — **same issue; upgraded
from Medium to High under security lens** because the integrity (data
destruction) consequence wasn't the primary lens there.

---

## MEDIUM findings

### M1 — Uninstall leaves `CryptoFile.Locked` ProgID if it collides with another application's `.lock` binding

**File:** `cryptofile/shell_integration.py:211-226`.

**CWE-459** (Incomplete Cleanup).

**CVSS v4.0:** AV:L/AC:L/AT:N/PR:L/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N —
**Base 2.3 (Low-Medium)**; rated Medium because the symptom is a
silently-broken Windows shell state that the user can't self-diagnose.

The comment at lines 223-226 explains that we deliberately don't strip
the `.lock\(default)` → `CryptoFile.Locked` mapping because "another
tool might be relying on the ProgID." But the `install()` logic
**unconditionally overwrites** any pre-existing mapping at
`Software\Classes\.lock\(default)` (line 151). If the user had a prior
app handling `.lock` (e.g., `Lockbox`, `ESD File Shell`, several
password-manager / backup tools use `.lock`), the install **silently
rebinds** the extension to `CryptoFile.Locked` without stash-or-restore.
On uninstall, we then leave the broken binding in place.

**Attack relevance:** low — this is an application-hygiene issue, not
remote-exploitable. But: a malicious installer that registered
`CryptoFile.Locked` first, THEN the user installs CryptoFile, gets a
weak form of clobber persistence (their content-disposition lingers
only as a ProgID shell, though CryptoFile's install overwrites the
primary command).

**Fix:** (a) read-and-stash pattern: on install, if
`.lock\(default)` is set to a value other than `CryptoFile.Locked`,
save the old value under `Software\Classes\CryptoFile.Locked\PreviousProgID`
and restore on uninstall; (b) refuse to rebind `.lock` if it's already
non-empty and non-ours, emitting a messagebox asking the user.

### M2 — Password UTF-8 encoded without NFC normalization

**File:** `cryptofile/crypto.py:181`.

**CWE-176** (Improper Handling of Unicode Encoding).

**CVSS v4.0:** AV:L/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N —
**Base 2.0 (Low-Medium)**; rated Medium because it's latent data-loss
risk for non-Latin users.

```python
secret=password.encode("utf-8"),
```

Two Unicode strings that **render identically** can have different byte
representations pre-NFC:

- `"café"` composed: `c a f é` → 5 bytes
- `"café"` decomposed: `c a f e + combining acute` → 6 bytes

A user who types their password on Device A (IME emits NFC) and on
Device B (IME emits NFD — macOS APFS filesystem APIs do this routinely;
some Korean / Japanese IMEs also) will get **different Argon2 keys
from what reads as the same password**. The user sees "wrong password"
on device B despite typing correctly.

For Latin-only passwords this never triggers. For CJK / accented / emoji
passwords it will eventually bite a user, and the symptom will look
exactly like a corrupted file (by design — our error message is
"wrong password or file corrupted", `__main__.py:498-504`).

**Fix:** normalize before encode:

```python
import unicodedata
secret=unicodedata.normalize("NFC", password).encode("utf-8"),
```

NFC is the Unicode Consortium's Security Considerations recommendation
(UAX #15 §1.3, TR36 §3) and matches every modern password-manager's
behaviour. This is non-breaking for every Latin password (NFC-idempotent)
and for any existing CJK password whose input method was already NFC
— only NFD-encoded keys are affected, which are rare in Windows input
methods. Worth a 1.0.x bump with a note for users who find old files
un-openable after the change (unlikely population: macOS APFS-sourced
passwords, Korean IMEs emitting NFD).

### M3 — `.partial` files have no tightened ACL — default inherits parent

**File:** `cryptofile/file_ops.py:290-306, 331-347`.

**CWE-276** (Incorrect Default Permissions).

**CVSS v4.0:** AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N —
**Base 2.3 (Low-Medium)**; rated Medium because the leak window is
entire-file-duration during encryption of large files.

`tmp_out = final_out.with_name(final_out.name + ".partial")` +
`open(tmp_out, "wb")` creates the file with default Windows ACL =
inheritance from the parent directory. For the common case (user
encrypting a file in their own Documents folder), ACLs are
user-restricted and fine. For files in `C:\ProgramData\...`,
`C:\Temp\`, or any world-readable directory, the `.partial` is
readable by any local process **during the entire encryption window**.

Important: the `.partial` contains **ciphertext only** (the plaintext is
never written — see `crypto.encrypt_stream` line 254-287). So this
doesn't leak plaintext. What it does leak:

- File size (approximates plaintext size — same leak as the final
  `.lock` header's `plaintext_size` field, but available earlier).
- The fact that the user is encrypting a particular path right now.
- On crash: the `.partial` persists until cleaned up.

Low-severity but worth noting: for decrypt (`decrypt_file` at
`file_ops.py:314-356`), the `.partial` contains **plaintext** during
decryption. Same-user ACL attacker can read decrypted plaintext
mid-decrypt from a world-readable directory.

**Fix:** on Windows, call `os.open(tmp_out, os.O_WRONLY | os.O_CREAT |
os.O_EXCL, 0o600)` — Python's POSIX mode argument is honoured on
Windows as a partial ACL restriction (only to same-user read/write).
Better: explicit SDDL via `pywin32` set to owner-SID read/write, but
this adds a dep. Documenting the issue in SECURITY.md is the
minimum-viable response.

### M4 — `InitializeSetup` is a no-op but the comment says "refuse to install if running"

**File:** `installer.iss:102-109`.

**CWE-440** (Expected Behavior Violation), **CWE-754** (Improper Check
for Unusual Conditions).

**CVSS v4.0:** AV:L/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N —
**Base 3.4 (Low-Medium)**.

```pascal
function InitializeSetup(): Boolean;
begin
  Result := True;
end;
```

Installer silently overwrites `CryptoFile.exe` while the user's
currently-running instance holds the image. Windows kernel queues
`MOVEFILE_DELAY_UNTIL_REBOOT`, but the installer reports success. If
an attacker is racing a concurrent `.lock` double-click while the
installer runs, the "replacement" may not actually install until reboot
— during which the user believes they're on the new version. Matches
`BUG_HUNT_10 I-new-2`.

**Security-specific concern:** if a future release ships a security
hotfix, a user who installs the hotfix while a background instance is
running gets a pending-reboot install that *appears* successful. The
hotfix isn't actually deployed until reboot; any window between install
and reboot runs the vulnerable binary.

**Fix:** implement the tasklist check per Inno's example:

```pascal
function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
  OutputStr: string;
begin
  if Exec(ExpandConstant('{cmd}'), '/C tasklist /FI "IMAGENAME eq CryptoFile.exe" /NH | find /I "CryptoFile.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    if ResultCode = 0 then begin
      MsgBox('CryptoFile is running. Close all CryptoFile windows and try again.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  Result := True;
end;
```

Cross-check: `BUG_HUNT_10 I-new-2` — Info severity there; **rated
Medium here** because the security consequence (delayed hotfix
deployment) wasn't the BUG_HUNT lens.

### M5 — `_run_batch` per-file-password path re-uses batch `dummy_root` as `ask_password` parent

**File:** `cryptofile/__main__.py:368`.

See `BUG_HUNT_10 H-new-1` — **same issue, same severity (reliability
High there; here Medium from a security lens because it's not directly
exploitable)**. The *security*-relevant aspect: if the per-file password
dialog fails to render, the worker thread is blocked on `pw_done.wait()`
indefinitely (no timeout). Explorer launched the process; user sees a
stuck process they can only kill via Task Manager. While killed, the
primary's `.partial` for the currently-in-flight file is orphaned in
the user's file tree with ciphertext — same data-at-rest leak as M3
above, extended to whatever subset of files the batch processed before
the stuck dialog.

**Fix:** carried by the BUG_HUNT fix. No separate security fix needed.

### M6 — Argon2 `argon2-cffi` lower-bound only; no SBOM / lockfile

**File:** `pyproject.toml:10-13`.

**CWE-1104** (Use of Unmaintained Third Party Components — soft form),
**CWE-1357** (Reliance on Uncontrolled Component). Supply chain ref:
`D:\Research\Security\28_Supply_Chain_Security.md`.

**CVSS v4.0:** AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L —
**Base 3.9 (Medium)** under a dependency-confusion lens.

```toml
dependencies = [
    "cryptography>=42.0.0",
    "argon2-cffi>=23.1.0",
]
```

No upper bound; no `requirements.txt` lockfile; no `uv.lock`; no
`pip-compile`'d pins. A future `cryptography == 99.0` with a breaking
AESGCM API would silently deploy into every new build. Worse — a
malicious namespace-squatter (e.g. `argon2-cffi-x`, `pyargon2` are
common typo targets) would not be caught by any guard.

**Fix:**
1. Add a `requirements.lock` generated by `pip-compile` or `uv pip
   compile` pinned to exact versions + hashes (`--generate-hashes`).
2. `build_exe.py` reads from the lockfile instead of the
   `.venv`.
3. Generate an SBOM with `cyclonedx-bom` or `syft` for each release —
   ship as a release artifact alongside the installer.
4. Eventually: cosign-sign the installer (`sigstore-python` is stdlib-adjacent).

---

## LOW findings

### L1 — Password string never zeroed (documented)

`docs/SECURITY.md` §"Secure coding notes" already acknowledges this:
*"Python strings holding the password are not zeroed — bytes objects in
CPython are immutable and the GC eventually collects them."* Correct
and honest.

Code residual lifetime: `__main__._run_encrypt` line 257 — `pw` lives
in the lambda closure at line 264 until `run_with_progress` returns.
`__main__._run_batch` line 380 — `prompt.password` lives for the entire
batch duration. For a 500-file batch at 1 s/file + 1 GiB Argon2, that's
~10 minutes of memory residency. No code fix; documentation matches.

**CVSS v4.0:** AV:L/AC:H/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N —
**Base 1.0 (Low).**

### L2 — `_shell_exe_path()` called twice + `split('"')[1]` IndexError

See `BUG_HUNT_10 H-new-3`. **Same severity (Low under security lens)** —
a crash in `install-shell` is a hygiene issue, not exploitable.

### L3 — `non_conflicting_name` unbounded loop

See `BUG_HUNT_10 L-new-8`. Security lens: the unbounded loop can be
triggered by a same-user attacker pre-creating `foo (2).lock` …
`foo (N).lock`, forcing CryptoFile to stat-spin for N iterations before
writing. Minor DoS; cap at 10_000 + raise `FileOpError`.

### L4 — Port file dedup race on primary-close

See `BUG_HUNT_10 M-new-7`. Security consequence: on close, the secondary
falls back to standalone single-file mode, which re-prompts for
password. A confused user could enter the password twice, potentially
leaking it into a different process's clipboard if they used
paste-from-password-manager and the manager has a clipboard-clear
timer. Very indirect; rated Low.

### L5 — `.lock` source is `unlink`'d, not securely deleted on decrypt

**File:** `cryptofile/file_ops.py:349-355`.

```python
if delete_source:
    # The encrypted file doesn't need a "secure" overwrite — it's
    # already ciphertext — but a plain unlink reuses the same code path.
    try:
        src.unlink()
```

Correct reasoning. But: filesystem-layer forensics on a HDD + attacker
who later learns the password → recovered ciphertext bytes + password =
plaintext recoverable. A scenario the user might care about:

1. User encrypts sensitive file A.lock, ships to attacker.
2. User later decrypts A.lock locally; plain unlink leaves the
   ciphertext recoverable for a day on HDD.
3. Attacker later subpoenas / steals the machine, recovers A.lock from
   free-space, now has the password (it's the same for every file
   they have), reads the plaintext.

Scenario is thin — same-password attacker has already won. But a one-line
change fixes it: `secure_delete(src)` for the ciphertext too, so
plaintext-recoverable-via-password doesn't linger on free-space blocks.

### L6 — `plaintext_size` header field is a plaintext-size oracle

Documented in `docs/SECURITY.md` §Header metadata leakage. Not a code
finding — calling out for completeness.

### L7 — Chunk-0 `BadPassword` vs tamper indistinguishability (M1 in prior audits)

`crypto.py:353-359`. **Intentional** and documented in `PROTOCOL.md`
§Decrypt error mapping and `docs/SECURITY.md` §Secure coding notes.
Matches the standard AEAD guidance (don't distinguish padding-oracle
style failure modes). No finding; noting for audit completeness.

---

## INFO

### I1 — Pagefile / hibernation of Argon2 working set

`docs/SECURITY.md` §"What really survives" correctly names pagefile and
hiberfil as places plaintext can survive. It does **not** mention that
Argon2id's 256 MiB working buffer — which holds transformed password
state — can also spill to pagefile during the KDF. If the OS
memory-pressure-pages that buffer to disk mid-derivation, fragments of
an Argon2 intermediate state survive. Attacker with pagefile.sys could
in theory accelerate a brute force by seeding with that state. Very
speculative — no published attack — but worth a one-line mention.

**Fix:** add to SECURITY.md: "On low-memory machines, Argon2id's
working buffer can be paged to pagefile.sys mid-KDF. BitLocker remains
the right defense."

### I2 — PyInstaller `--onefile` unpacks to `%TEMP%\_MEI…` per run

Documented at `docs/SECURITY.md:253-255`. Race-condition swap of bundled
`python312.dll` etc. by a same-user attacker is theoretical. Noting
that the `_MEI` dir is created with random 6-char suffix and readable
by same-user processes — not a CryptoFile-specific issue, it's how
PyInstaller onefile works. Code signing + AppLocker are the defense
(out of scope for v1, as documented).

### I3 — No HSTS-equivalent for shell verb (can't bind verb to a signed exe)

On Windows, no mechanism exists to say "only run this verb's command
if the target exe's Authenticode signature matches a pinned thumbprint."
Windows Smart App Control + WDAC policies can approximate. Code-signing
the release binaries (L6-adjacent, supply chain) would allow users to
deploy WDAC rules of their own. **Not a CryptoFile bug** — noting as a
hardening option for a future supply-chain release.

### I4 — AppId GUID is public and stable across releases

`installer.iss:18`: `{{B6FAC9AA-8B9F-4EA1-9D25-6B0CE5C4A8E0}`. Correct
choice (enables in-place upgrades). Noting only that a typosquatting
installer with the same AppId would appear in Add/Remove Programs as
"CryptoFile" and trigger upgrade semantics. Mitigation: code-signing
(I3). Low-urgency until code-signing is in place.

---

## Verdicts (per the three explicit questions)

### (a) Is the Argon2id + AES-256-GCM construction sound as shipped?

**Yes.** The construction is clean, defensible, and matches PHC / OWASP
2025 recommendations. Specifically:

- Argon2id (not Argon2i or Argon2d) — correct choice for password hashing
  with side-channel resistance.
- 256 MiB / t=3 / p=4 — **exceeds** OWASP 2025 minimums by roughly an
  order of magnitude.
- 32-byte output → AES-256 key — correct.
- AES-256-GCM with 12-byte nonce = 8-byte random prefix + 4-byte BE
  counter — **structurally prevents nonce reuse within a file**, and
  per-file prefix randomization prevents cross-file reuse. Collision
  probability for the prefix across two files encrypted by the same user
  with the same password: 2^-64 → negligible.
- AAD = `header[0:52] || u32_be(chunk_index) || u8(is_final)` —
  simultaneously defeats chunk swap, truncation, header tampering,
  cross-file splicing, and final-chunk forgery. This is better than most
  real-world AEAD deployments I've audited.
- `is_final` is authenticated — **an attacker cannot fake a final chunk
  without the key**. Faking it requires either the Argon2-derived key
  or a GCM forgery (2^-128).
- Zero-length input: explicit final-chunk emission at
  `crypto.py:283-287` is correct.

Minor caveats already filed: M2 (NFC normalization for non-Latin
passwords) and H1 (untrusted parameters from the header — same key
material, but the attacker chooses the cost). Neither affects the
soundness of the primitives; both are parameter-handling bugs.

### (b) Any parser DoS vectors in header parsing?

**Yes — one: H1 (unbounded `memory_kib` / `time_cost` / `parallelism`).**
A malicious `.lock` file can force Argon2id allocation of up to 4 TiB
and/or unbounded iteration count. No other parser DoS vectors
identified:

- `plaintext_size` is used as a loop counter, never for pre-allocation
  (confirmed at `crypto.py:333-364`).
- Header size is fixed at 52 bytes — no length-field trust issue.
- Chunk size is fixed at CHUNK_SIZE (1 MiB) — decrypt reads a bounded
  number of bytes per iteration.
- No length-prefixed fields inside chunks.

The scope of the header-parser attack surface is exactly H1. Fix it and
header parsing is bulletproof.

### (c) Can a malicious `.lock` file harm the decrypting user beyond "wrong password"?

**Yes — limited to resource exhaustion (H1); no arbitrary code
execution path exists.**

Specifically:

- **No arbitrary code execution.** Decrypt pulls bytes, runs them
  through Argon2id (pure numeric) and AES-256-GCM (pure numeric).
  No `pickle`, no `eval`, no dynamic imports, no dlopen, no image
  codecs, no regex with catastrophic backtracking on attacker data.
  Decrypt output is written to a `.partial` file without any
  interpretation.
- **No out-of-bounds write** — `cryptography` and `argon2-cffi` are
  memory-safe at the Python layer; both bundled C implementations
  have no known recent advisories (Chapter 09 of the research library).
- **No filename traversal** — the decrypted output path is derived
  from the input filename via `decrypted_name()` (`file_ops.py:178-184`),
  which strips the `.lock` suffix; it doesn't consult any attacker-
  controlled path from inside the file.
- **H1 resource exhaustion** is the one damage path: DoS the machine
  for minutes to hours.

Secondary consequences a malicious `.lock` can cause:
- Fill disk via `.partial` write of declared `plaintext_size` up to
  `0xFFFFFFFFFFFFFFFF`. Except: decrypt stops at the first
  `"truncated ciphertext"` error, which triggers when the file doesn't
  contain enough ciphertext. So the `.partial` is never meaningfully
  oversized in practice — the attacker would need to actually ship
  exabytes of ciphertext to get a big `.partial`. Not a real issue.
- Waste ~1 s of CPU on Argon2 if cost parameters are honest. Acceptable.

**Fix H1, and the answer becomes an unqualified "no harm beyond wrong
password."**

---

## Top-5 findings (ranked by real-world risk)

1. **H1** — Parser DoS via untrusted Argon2 memory/time/parallelism
   parameters. **Only real attacker-controlled vector in the crypto
   path.** Fix with four lines in `Header.from_bytes`.
2. **H2** — Coordinator socket accepts paths from any local user on
   multi-user systems; integrity (data destruction) impact.
   BUG_HUNT_10 `M-new-2` escalated under security lens.
3. **M2** — Password UTF-8 encoded without NFC; non-Latin passwords
   will eventually lock out users who typed on a different-IME device.
   One-line fix.
4. **M3** — `.partial` files inherit parent ACLs; same-user attacker
   can read plaintext mid-decrypt from world-readable directories.
5. **M6** — Supply-chain: `>=`-only deps, no lockfile, no SBOM, no
   signing.

## Documentation vs. code consistency

- `docs/SECURITY.md` §Secure-coding notes — accurate.
- `docs/SECURITY.md` §Multi-file coordinator — **slightly understates**
  the issue (says "local malicious process can do anything the user
  can"; misses the multi-user case addressed in H2).
- `docs/PROTOCOL.md` §Decrypt error mapping — matches code.
- `CHANGELOG.md` — consistent with shipped 1.0.6.
- Installer `[Code] InitializeSetup` comment lies about behaviour (M4).

## References

- `D:\Research\Security\33_Secure_Coding_Patterns.md` §Argon2id,
  §AES-256-GCM (construction validated against these).
- `D:\Research\Security\09_Cryptography_OSINT_SocialEngineering.md`
  (Argon2 parameter recommendations).
- `D:\Research\Security\22_Attack_Vectors_DeepDive.md` (DoS via
  untrusted serialization parameters).
- `D:\Research\Security\28_Supply_Chain_Security.md` (M6 rationale).
- `D:\Research\Security\10_ExploitDev_RE_BugBounty.md` §CVSS v4.0
  (scoring methodology).
- `BUG_HUNT_10.md` (cross-check).

---
*Report complete. No code modified.*
