# CryptoFile — Bug Hunt #10 (post-1.0.5)

Cross-checked against current source in `D:\App Dev\CryptoFile\cryptofile\`,
tests in `D:\App Dev\CryptoFile\tests\` (56 passing), and the 1.0.5 edits
just made in `gui.py`. Reports only — no code modified.

## Severity counts

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 3 |
| Medium | 7 |
| Low | 8 |
| Info | 3 |
| Refactor | 4 |

## Status of previously deferred items

Confirmed **still unresolved** in current tree:

- **H1** non_conflicting_name TOCTOU — still present in `file_ops.py:187`.
- **H2** junction/case dedup — resolve()+case-normalize still missing in `batch.py:247`.
- **H3** primary-closed-before-secondary race — `coord.close()` called in `finally` of `_coordinate_and_run` before UI runs; late secondaries get OSError.
- **H4** stale port-file race — secondary reads `port_path` after primary closed; send fails → fallback to standalone (documented but no test).
- **M1** tag-tampering → "wrong password" on chunk 0 — intentional, unchanged.
- **M2** per-file batch ask_password uses dummy_root from `_run_batch`, which IS withdrawn (see H-new below).
- **M4** secure_delete hard-fail on AV lock — still unhandled.
- **M6** hard-coded `\\` separator in Listbox — still `gui.py:411`.
- **M7** wait_for_collection idle check — still has the double-guard at `batch.py:243`.
- Refactors #1–#4 — all four still pending (no atomic-write helper, no hidden_root ctxmgr, no runner.py, BatchPasswordResult still in gui.py).

Confirmed **silently fixed** (either in 1.0.1 or 1.0.2–1.0.5):

- C1/C2/C3/H5/M3/M5 — all fixed in 1.0.1; regression tests in `test_bug_fixes.py`.

---

## NEW FINDINGS (this pass)

### High

#### H-new-1 — `_run_batch` still uses the withdrawn-root pattern that caused 1.0.3 and 1.0.5
**File:** `cryptofile/__main__.py:329-330` (and 363 for the per-file password dialog spawned inside `_run_batch`).

The 1.0.5 edit fixed `ask_password`, `ask_batch_password`, and `run_with_progress` to use a 1×1 off-screen transparent real window instead of `withdraw()`. `_run_batch` is the one remaining caller that still does:

```python
dummy_root = tk.Tk()
dummy_root.withdraw()
win = gui.BatchProgressWindow(dummy_root, ...)
```

`BatchProgressWindow.__init__` now calls `_force_foreground()`, so this *may* render correctly on Windows 11. But the exact same `withdraw()`-as-transient-parent pattern is what produced the 1.0.3 PasswordDialog-invisible bug and the 1.0.5 ProgressWindow-invisible bug. Keeping it in `_run_batch` re-exposes multi-file encrypt to the same failure class — and this is the code path the user is *most* likely to hit (multi-select is the whole point of the batch coordinator).

Furthermore, `gui.ask_password(..., parent=dummy_root)` at `__main__.py:363` (per-file-password subpath) uses this withdrawn root as its *parent*, defeating the 1.0.5 `ask_password` fix for that subpath — `ask_password` only builds an off-screen root when `parent is None`.

**Suggested fix:** replace both `dummy_root = tk.Tk(); dummy_root.withdraw()` sites with the off-screen pattern used by `ask_password`, or consolidate via the pending `hidden_root()` contextmanager refactor:

```python
dummy_root = tk.Tk()
dummy_root.geometry("1x1+-2000+-2000")
dummy_root.overrideredirect(True)
dummy_root.attributes("-alpha", 0.0)
```

Cross-check: no test exercises this path; it would only be caught by running the frozen exe against multi-select.

#### H-new-2 — `installer.iss` still pinned to AppVersion 1.0.4
**File:** `installer.iss:12`.

```
#define AppVersion "1.0.4"
```

`cryptofile/__init__.py` is now `"1.0.5"` and `CHANGELOG.md` has a 1.0.5 entry. If the installer is rebuilt from the current script it will ship as "CryptoFile 1.0.4" in Add/Remove Programs and produce `CryptoFile-Setup-1.0.4.exe`, which overwrites the already-released 1.0.4 artifact naming. Users who upgrade from 1.0.4 → this build will see no version change in Settings. The `AppId` GUID is stable so the upgrade mechanic works — but the version number is wrong.

**Suggested fix:** bump to `"1.0.5"`. Also worth considering a small `build_installer.py` that reads `cryptofile/__version__` and injects it via `/D` to ISCC, so version drift can't happen again.

#### H-new-3 — `shell_integration._shell_exe_path()` icon path extraction is fragile in dev mode
**File:** `cryptofile/shell_integration.py:194`.

```python
icon_src = _shell_exe_path().split('"')[1] if '"' in _shell_exe_path() else _shell_exe_path()
```

In dev mode `_shell_exe_path()` returns `'"C:\...\pythonw.exe" "D:\...\cryptofile\__main__.py"'`. `.split('"')[1]` gives the pythonw path, which is what's wanted for the icon. In frozen mode `_shell_exe_path()` returns a bare path (no quotes), and the whole string is used. Fine today — but notice `_shell_exe_path()` is called *twice* on this one line. If anything in that function ever becomes non-deterministic (e.g. a resolved() that changes after a file move), the icon path and the command path would disagree. Separately, the `split('"')[1]` will throw `IndexError` if `_shell_exe_path()` ever returns a non-quoted string that happens to contain a stray `"` — extremely rare but crash-class.

**Suggested fix:** single-call + explicit extraction:

```python
raw = _shell_exe_path()
icon_src = _extract_exe_path(raw) or raw  # reuses the existing helper
```

### Medium

#### M-new-1 — No logging anywhere
**Files:** all of `cryptofile/`.

Four of the last four hotfixes (1.0.2–1.0.5) were "silent crash / silent invisible UI" in the `--windowed` exe. 1.0.3 added a last-resort messagebox, but there is no persistent log. When the next user reports "nothing happens when I right-click encrypt", you have nothing to ask them for except a task-manager screenshot.

**Suggested fix:** add a `cryptofile/_logging.py` that configures a `RotatingFileHandler` writing to `%LOCALAPPDATA%\CryptoFile\cryptofile.log` (already exists as the batch-coordinator dir — clean location), max 1 MiB × 3 files. Log at least: every `main()` invocation with argv, every coordinator primary/secondary decision, every encrypt/decrypt start + outcome, every caught exception in the `main()` safety net. Never log passwords, obviously. One line at the top of `main()`:

```python
_logging.configure()
log = _logging.get("main")
log.info("startup argv=%r frozen=%s", sys.argv, getattr(sys, "frozen", False))
```

This is a Medium and not a Low because the cost of the next silent-UI bug without logs is another 4-release hotfix chain.

#### M-new-2 — `_handle_connection` accepts from ANY local process, not just same-user
**File:** `cryptofile/batch.py:192`.

Bound to `127.0.0.1:0` so only localhost. But *any* process running as *any* user on this machine can `getsockopt()`-discover the ephemeral port by scanning (or by reading the port file if world-readable), then inject paths into the primary's batch. `Path.is_file()` limits the damage to files that actually exist — but any existing file the attacker can point at becomes a candidate for batch encryption under the victim's password. Password dialog does display the list so the user can cancel — this is the documented mitigation — but a user who reflexively clicks "Encrypt all" loses files they didn't pick.

**Suggested fix:** on accept, look up the peer's PID via `getsockopt(SO_CONNECT_PID)` (Windows 10+) or use `SIO_QUERY_TARGET_PNP_HANDLE` / `GetExtendedTcpTable` to verify the remote process is running as the same user. Simpler alternative: on Windows, use a named pipe with a SDDL restricting to the current SID instead of a localhost socket. This is a hardening, not an exploit — the multi-user attack scenario requires shared workstation + adversary already running as a different user.

#### M-new-3 — `encrypt_file`/`decrypt_file` cleanup-on-error uses `tmp_out.exists()` not the open-handle path
**File:** `cryptofile/file_ops.py:300-307, 341-347`.

```python
except BaseException:
    if tmp_out.exists():
        try:
            tmp_out.unlink()
        except OSError:
            pass
    raise
```

If `open(tmp_out, "wb")` succeeded but Python's GC hasn't yet closed the fout handle by the time we reach `unlink()`, Windows refuses the unlink with `PermissionError` and the `except OSError: pass` eats it. We leak `.partial` files. In practice the `with` block's `__exit__` runs before the `except BaseException` body executes, so this is fine *today* — but only because of Python's scoping. Explicit `fout.close()` before entering the except body would be robust. Worse: if `os.replace(tmp_out, final_out)` fails mid-rename (e.g. destination locked by AV), `tmp_out` may still exist AND the `with` block has already exited. This path IS reachable and would leak the partial.

**Suggested fix:** move the try/except/finally inside the `with` blocks — OR write the atomic-write helper (refactor #1) which gets this right in one place.

#### M-new-4 — `wait_for_collection` returns immediately if `add_local_path` is never called AND `_last_arrival == 0.0`
**File:** `cryptofile/batch.py:229-245`.

```python
with self._paths_lock:
    last = self._last_arrival or start
if (now - last) >= idle_s and (now - start) * 1000 >= idle_ms:
    break
```

If a caller does `try_become_primary() → start_server() → wait_for_collection()` without `add_local_path()`, `_last_arrival == 0.0` → `last = start`, first iteration `now - start` is near 0, so first branch fails, we sleep 20 ms, loop. Eventually `now - start >= idle_s` AND both clauses true → we exit at ~`idle_ms`. Correct for the current caller (`_coordinate_and_run` always calls `add_local_path` first) but brittle if a future caller forgets — collection exits at idle_ms with empty list, no error. The docstring says "Prime the idle clock from the primary's own arrival" but doesn't require it.

**Suggested fix:** make `add_local_path` mandatory — raise if `wait_for_collection` runs with `_last_arrival == 0.0 and not _paths`. Or initialize `_last_arrival = time.monotonic()` in `start_server()`.

#### M-new-5 — `BatchPasswordDialog.__init__` has no `_force_foreground`
**File:** `cryptofile/gui.py:367-464`.

`PasswordDialog`, `ProgressWindow`, and `BatchProgressWindow` all have `_force_foreground()` calls (topmost toggle + lift + focus_force) — the fix that makes them visible when launched from an Explorer shell verb. `BatchPasswordDialog` only has:

```python
self.after(50, lambda: (self.lift(), self.e_pw.focus_force()))
```

No topmost toggle. This is the exact subset of the pattern that was observed to not work reliably (which is why PasswordDialog got the fuller 150 ms topmost dance in 1.0.3). Now that `ask_batch_password` uses the off-screen real-window parent (1.0.5 fix), this *probably* works — but if the user files a "multi-select password dialog doesn't appear" bug next, this is the first place to look.

**Suggested fix:** factor `_force_foreground` into a free function (e.g. `_force_window_foreground(win: tk.Toplevel)`) and call it from all four Toplevel subclasses.

#### M-new-6 — `_run_batch` `worker_done.wait(timeout=5.0)` can miss slow cancel cleanup
**File:** `cryptofile/__main__.py:428`.

If the user clicks Cancel during a multi-GB chunk's AES-GCM authentication (not interruptible), the worker may take 10+ seconds to observe the cancel at the next chunk boundary. `dummy_root.wait_window(win)` returns when `signal_batch_complete` → drain → `win.destroy()` fires. `worker_done.wait(timeout=5.0)` then waits up to 5 s. If the worker is still authenticating a chunk, the 5 s expires, `dummy_root.destroy()` runs, but the worker thread continues (daemon=True, killed at process exit). Output: process appears to exit cleanly while the worker is still running — user sees summary with `skipped` entries for files the worker may or may not have touched. Edge case; in practice 1 MiB chunks auth in <<1 s.

**Suggested fix:** loop `worker_done.wait(timeout=0.5)` with a progress message "waiting for current file to finish…" in a new mini-dialog if it exceeds e.g. 3 s. Or document that daemon threads ARE expected to be killed at exit and the outcomes list is already materialized before the wait, so the summary is always accurate.

#### M-new-7 — Non-atomic port-file publish window is 0 — but the read-side race still exists
**File:** `cryptofile/batch.py:130-132, 268-272`.

Primary does atomic `os.replace(tmp, port_path)` → good. But secondary at `batch.py:268` does `if not self.port_path.exists(): sleep + continue`. Between `exists()` and `read_text()` the file can be deleted by primary's `close()` (primary finished collecting, wrote its own path, moved to UI). `read_text` then raises `OSError`, caught, we loop. By now the primary's socket is closed → `socket.create_connection` fails too → loop again. Eventually `deadline` hits → return False → `_coordinate_and_run` falls back to `_dispatch_paths(action, [our_path])` → secondary runs its own single-file flow. **Correct behavior** but pops a second password dialog for what the user thought was one batch. Rare (needs 300+ ms gap between Explorer's N launches).

**Suggested fix:** accept this as documented race (matches H3/H4 in the old deferred list). Test would be valuable: spawn primary, close it after 100 ms, spawn secondary at 150 ms, assert it falls back cleanly.

### Low

#### L-new-1 — `encrypt_stream` zero-byte path + non-zero final fallback interaction
**File:** `cryptofile/crypto.py:263-287`.

For `plaintext_size == 0`, `plain_in.read(CHUNK_SIZE)` returns `b""` immediately, main loop never executes, then the explicit `if plaintext_size == 0:` branch writes the empty-final chunk. Works. But if `plaintext_size > 0` and the reader produces `b""` as its very first read (bug in caller), we exit the loop at `bytes_done=0`, skip the `plaintext_size == 0` fallback, reach `bytes_done != plaintext_size` → `CryptoError`. Good. Only note: `read(1)` C1 guard at line 299 runs even after the `plaintext_size==0` fallback. For a caller that hands in a zero-size file that actually has bytes (source grew from 0 to N between stat and open), the guard catches it. Correct — but subtle; tests cover chunk-aligned grow and oversized-read, not 0→N grow. Minor.

#### L-new-2 — `decrypt_stream` chunk-0 `BadPassword` vs `BadFormat` ambiguity
**File:** `cryptofile/crypto.py:350-359`.

Any `InvalidTag` on chunk 0 → `BadPassword`. If the file had the right magic but a corrupt header (e.g. wrong salt written), `from_bytes` would have already raised `BadFormat`. But if a ciphertext byte in chunk 0 is flipped, this reports "wrong password" — indistinguishable from actual wrong-password. That's **intentional** (documented as M1 in the old triage) but worth a comment at the site cross-referencing the rationale.

#### L-new-3 — `secure_delete` single pass is fine on SSD; docstring could note `passes>1` is pure theatre
**File:** `cryptofile/file_ops.py:207-261`.

Passing `passes=2` or more does 2+ random overwrites. On SSD these hit different physical cells each time (wear leveling) so zero security gain, 2× wall time. The docstring *almost* says this but leaves the `passes` parameter looking like it's useful. Consider deprecating the parameter or documenting "ignored on SSD; HDD users who insist on multi-pass can set this."

#### L-new-4 — `_delete_tree` recursive deletion doesn't handle registry-access-denied
**File:** `cryptofile/shell_integration.py:229-248`.

Catches `FileNotFoundError` only. If another tool re-registered the key with a restrictive DACL (requires admin injection), `OpenKey(..., KEY_ALL_ACCESS)` raises `PermissionError` (OSError subclass), which escapes. Unlikely under HKCU. If hit, `uninstall()` leaves a partial state.

**Suggested fix:** catch `OSError` in `_delete_tree` and log (see M-new-1) rather than raising.

#### L-new-5 — `_extract_exe_path` fallback returns full command line on unquoted commands
**File:** `cryptofile/shell_integration.py:108-123`.

Frozen mode always writes quoted paths, so fallback is dead code. If a user hand-edits the registry to unquoted form (plausible on paths without spaces), `cmd.split(None, 1)[0]` returns the exe path, correct. OK but untested — consider dropping the fallback or testing it.

#### L-new-6 — `BatchPasswordDialog.assert len(files) >= 2` is a runtime assertion
**File:** `cryptofile/gui.py:378`.

`assert` is stripped under `python -O` (PyInstaller doesn't default to `-O` but builds can). A single-file caller that bypasses `_dispatch_paths` single-file shortcut would skip the assertion and try to render. Minor since `_dispatch_paths` enforces this correctly before calling.

**Suggested fix:** replace with `if len(files) < 2: raise ValueError(...)`.

#### L-new-7 — `ProgressWindow._drain` swallows `tk.TclError` and stops, but `set_progress` can raise non-TclError
**File:** `cryptofile/gui.py:267-285`.

If `self.lbl_detail.configure(text=...)` raises anything other than `tk.TclError` (very rare), `_drain` re-raises → tk mainloop swallows it → UI stops updating silently. The 1.0.3 safety net won't see it because it's inside tk's event loop, not `main()`.

**Suggested fix:** catch `Exception` around the `set_progress` call and log; only break out on `TclError`.

#### L-new-8 — `non_conflicting_name` loops without bound
**File:** `cryptofile/file_ops.py:187-201`.

In a pathological scenario (attacker created `foo (2).lock` through `foo (1000000).lock` in the target dir), `non_conflicting_name` spins. Cap at e.g. 10_000 attempts and raise `FileOpError` — the user gains nothing by waiting forever.

### Info

#### I-new-1 — Dead code: `_FileOutcome.output` field never read
**File:** `cryptofile/__main__.py:317`.

`output: Path | None = None` is populated at line 389 (`_FileOutcome(fpath, "ok", "", out)`) but `_show_batch_summary` never consumes it. Leave for future "Show output files" button, or drop the field.

#### I-new-2 — Installer `InitializeSetup` is a no-op comment
**File:** `installer.iss:102-109`.

```
function InitializeSetup(): Boolean;
begin
  Result := True;
end;
```

The comment above says "refuse to install if the target exe is already running" but the implementation doesn't do that. User already saw this bite them (the 1.0.3/1.0.4 pile-up). Either implement it (see Inno's [Code] examples for `CheckForMutexes` / tasklist-based check) or delete the stub + misleading comment.

#### I-new-3 — `CHANGELOG.md` 1.0.5 entry references "transient+withdraw invisibility" but `_run_batch` still uses that pattern
Consistency: either fix `_run_batch` (H-new-1) or add a note to the changelog explaining why it's exempt (spoiler: it isn't — `BatchProgressWindow` has `_force_foreground` which *masks* but doesn't *eliminate* the underlying invisibility pattern).

### Refactor (carried over from previous audit, confirmed still unresolved)

#### R1 — Atomic-write helper in `file_ops.py`
Covers M-new-3 too. Proposed:

```python
@contextmanager
def _atomic_write(src: Path, final_out: Path) -> Iterator[BinaryIO]:
    tmp = final_out.with_name(final_out.name + ".partial")
    try:
        with open(tmp, "wb") as fout:
            yield fout
            fout.flush()
            try:
                os.fsync(fout.fileno())
            except OSError:
                pass
        os.replace(tmp, final_out)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
```

Both `encrypt_file` and `decrypt_file` collapse to ~5 lines each.

#### R2 — `hidden_root()` contextmanager in `gui.py`
4 call sites duplicate the off-screen `tk.Tk()` setup. Proposed:

```python
@contextmanager
def hidden_root() -> Iterator[tk.Tk]:
    root = tk.Tk()
    root.geometry("1x1+-2000+-2000")
    root.overrideredirect(True)
    root.attributes("-alpha", 0.0)
    try:
        yield root
    finally:
        root.destroy()
```

Ensures the 1.0.5 pattern is used everywhere (would also fix H-new-1 automatically).

#### R3 — Split `runner.py` out of `__main__.py`
`__main__.py` is 608 lines; `_run_batch`, `_run_single`, `_run_encrypt`, `_run_decrypt`, `_FileOutcome`, `_show_batch_summary`, `_show_error`, `_require_file` → `cryptofile/runner.py`. `__main__.py` keeps only dispatch. Would also make the batch path unit-testable.

#### R4 — Move `BatchPasswordResult` out of `gui.py`
It's a plain dataclass with no tk dependency. Belongs in `runner.py` (after R3) or a new `types.py`.

---

## Test coverage gaps

Confirmed against `tests/` directory:

- **No tests for `shell_integration.py`** — `install()`/`uninstall()`/`is_installed()` entirely uncovered. Would need `HKCU` sandbox (e.g., `winreg` against a scratch subkey like `Software\Classes\CryptoFileTest\`).
- **No tests for `__main__.py` dispatch** — `_dispatch_paths` single-vs-batch routing, large-batch confirm threshold, empty-expansion messaging, install-shell/uninstall-shell exit codes.
- **No tests for `BatchProgressWindow` drain loop** — `report_file_start` → drain → `start_file` is untested despite being the 1.0.4 bugfix.
- **No test for the primary-closed-before-secondary race** (H3, H-new-M7).
- **No test for `secure_delete` on a locked file** (M4).
- **No integration test that runs the frozen `dist/CryptoFile.exe`** end-to-end — 4 of the last 4 hotfixes would have been caught.

Suggested minimum additions:
1. `test_shell_integration.py` using a throwaway ProgID name.
2. `test_dispatch.py` that monkeypatches `file_ops.encrypt_file`/`decrypt_file` and drives `_dispatch_paths` with synthetic Expansions.
3. `test_frozen_smoke.py` (guarded by `pytest.mark.skipif` on `dist/CryptoFile.exe` absence) that does `subprocess.run([exe, "settings"], timeout=5)` and checks exit code — at minimum confirms the exe launches.

---

## Security hygiene (light pass)

- **Password memory lifetime:** `pw` is a Python str, lives as long as the lambda closure in `_run_encrypt` / `_run_decrypt` and the `_worker` inner of `_run_batch`. For batch, `prompt.password` lives for the entire batch duration. Python str interning means there's no way to zero it. Acceptable for a desktop tool (attacker with ptrace access has already won), but document it in `docs/SECURITY.md` if not already there.
- **Temp file permissions:** `.partial` is created with `open(path, "wb")` → Python uses default ACLs = inherited from parent dir. On most user-owned folders this is fine. On `C:\ProgramData\...` the partial could be readable by all users. Matches the source file's exposure, so no regression — but worth noting.
- **User input into registry:** `ENCRYPT_LABEL` / `DECRYPT_LABEL` are constants — no user input reaches `winreg.SetValueEx`. `_shell_exe_path()` uses `sys.executable` / `Path(__file__).resolve()` — trusted. Clean.
- **User input into subprocess:** none. No `subprocess.run` calls in the shipped code (only in tests for `mklink`).
- **Password dialog memory:** `tk.StringVar` holds the password in the tk interp's memory; `destroy()` on the Toplevel releases it. Fine.

---

## Top-5 issues (ranked by blast radius × likelihood)

1. **H-new-1** — `_run_batch` withdrawn-root pattern is the same bug class that killed 1.0.3 and 1.0.5; this path is the most-used path for multi-select users.
2. **H-new-2** — installer version string stale at 1.0.4.
3. **M-new-1** — no logging; guarantees the next silent-UI regression will be another blind 4-release hotfix chain.
4. **M-new-3** — atomic-write cleanup path has a reachable `.partial` leak on `os.replace` failure.
5. **H-new-3** — shell_integration icon extraction is call-twice + index-unsafe; latent, but one bad refactor away from IndexError in install-shell.

## File paths referenced

- `D:\App Dev\CryptoFile\cryptofile\__main__.py`
- `D:\App Dev\CryptoFile\cryptofile\gui.py`
- `D:\App Dev\CryptoFile\cryptofile\batch.py`
- `D:\App Dev\CryptoFile\cryptofile\crypto.py`
- `D:\App Dev\CryptoFile\cryptofile\file_ops.py`
- `D:\App Dev\CryptoFile\cryptofile\shell_integration.py`
- `D:\App Dev\CryptoFile\installer.iss`
- `D:\App Dev\CryptoFile\tests\test_bug_fixes.py`
- `D:\App Dev\CryptoFile\CHANGELOG.md`
