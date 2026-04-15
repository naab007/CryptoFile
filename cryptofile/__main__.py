"""CryptoFile entry point.

Invocation modes::

    cryptofile.exe                         # Open the Settings window
    cryptofile.exe settings                # Same
    cryptofile.exe encrypt <file>          # Right-click verb: encrypt
    cryptofile.exe decrypt <file>          # Right-click verb: decrypt

Multi-file behaviour (batch)
----------------------------

When Explorer invokes the exe N times for N selected files (because ``%1``
only passes one path each), the :mod:`cryptofile.batch` coordinator funnels
all those invocations into one primary process, which then shows a single
password dialog + a two-level progress window (overall + current file).

The first process to acquire the per-user lock is primary; all others
connect to its local socket, deliver their path, and exit. Primary waits a
short collection window (300 ms with 150 ms idle reset) before moving to UI.
"""
from __future__ import annotations

import sys
import threading
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import messagebox, ttk

from . import __version__, batch, crypto, file_ops, gui, shell_integration


# ── Top-level dispatch ────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    """Top-level entry. Wrapping the whole dispatch in try/except so a
    silent crash in the frozen ``--windowed`` exe can never vanish — the
    user sees a messagebox with the exception instead of a silently-closing
    process that looks like "no dialog appeared"."""
    try:
        return _main_impl(sys.argv[1:] if argv is None else argv)
    except BaseException as e:  # noqa: BLE001 — final safety net
        import traceback
        tb = traceback.format_exc()
        try:
            messagebox.showerror(
                "CryptoFile — unexpected error",
                f"{type(e).__name__}: {e}\n\n{tb[-1200:]}",
            )
        except Exception:
            # If even tk can't show a dialog (e.g. the exception was tk
            # failing to initialize), fall back to stderr so `cryptofile.exe`
            # run from cmd.exe still surfaces *something*.
            print(tb, file=sys.stderr)
        return 1


def _main_impl(args: list[str]) -> int:
    if not args or args[0] in ("settings", "--settings", "-s"):
        return _run_settings()
    if len(args) < 2:
        return _run_settings()

    cmd = args[0]

    # Silent shell-registration modes used by the installer's [Run] /
    # [UninstallRun] sections. Exit codes: 0 success, 1 failure.
    if cmd == "install-shell":
        try:
            shell_integration.install()
            return 0
        except Exception as e:
            # Write to stderr so the installer's log captures the reason.
            print(f"install-shell failed: {e}", file=sys.stderr)
            return 1
    if cmd == "uninstall-shell":
        try:
            shell_integration.uninstall()
            return 0
        except Exception as e:
            print(f"uninstall-shell failed: {e}", file=sys.stderr)
            return 1

    target = Path(args[1]).expanduser()

    if cmd in ("encrypt", "--encrypt", "-e"):
        return _coordinate_and_run("encrypt", target)
    if cmd in ("decrypt", "--decrypt", "-d"):
        return _coordinate_and_run("decrypt", target)

    messagebox.showerror(
        "CryptoFile",
        f"Unknown command: {cmd!r}\n\n"
        "Usage:\n"
        "  cryptofile.exe encrypt <file>\n"
        "  cryptofile.exe decrypt <file>\n"
        "  cryptofile.exe settings",
    )
    return 2


# ── Coordinator entry ─────────────────────────────────────────────────────


LARGE_BATCH_CONFIRM_THRESHOLD = 500


def _coordinate_and_run(action: str, our_path: Path) -> int:
    """Try to become the primary for this action. If we can't, send our
    path to the primary and exit. If we can, collect any other incoming
    paths, expand folders, and run the batch UI."""
    coord = batch.BatchCoordinator(action)
    if not coord.try_become_primary():
        # Secondary — deliver our path, exit. If unreachable, fall back
        # to a standalone single-path flow.
        if coord.send_to_primary(our_path):
            return 0
        return _dispatch_paths(action, [our_path])
    try:
        coord.add_local_path(our_path)
        coord.start_server()
        raw_paths = coord.wait_for_collection(timeout_ms=300, idle_ms=150)
    finally:
        # Close the server before the UI starts — no more paths will be
        # accepted. Any further Explorer invocations fall back to their own
        # single-path flows (rare; would need user to click twice fast).
        coord.close()

    if not raw_paths:
        raw_paths = [our_path]
    return _dispatch_paths(action, raw_paths)


def _dispatch_paths(action: str, raw_paths: list[Path]) -> int:
    """Expand each raw path (file or folder) into the concrete list of files
    to process, then route single-file vs batch."""
    if action == "encrypt":
        exp = file_ops.expand_for_encrypt(raw_paths)
    else:
        exp = file_ops.expand_for_decrypt(raw_paths)

    any_folder_input = any(p.is_dir() for p in raw_paths if _safe_is_dir(p))

    # Early-exit with a friendly message when the expansion finds nothing.
    if not exp.files:
        _show_empty_expansion(action, raw_paths, exp, any_folder_input)
        return 0

    # Huge batches: confirm before the password prompt so the user can bail
    # out if they right-clicked the wrong folder.
    if len(exp.files) >= LARGE_BATCH_CONFIRM_THRESHOLD:
        if not _confirm_large_batch(action, exp):
            return 0

    if len(exp.files) == 1 and not any_folder_input and not _has_any_skip(exp):
        # True single-file right-click: preserve the v1 UX (no batch dialog).
        return _run_single(action, exp.files[0])
    return _run_batch(action, exp)


def _safe_is_dir(p: Path) -> bool:
    try:
        return p.is_dir()
    except OSError:
        return False


def _has_any_skip(exp: file_ops.Expansion) -> bool:
    return bool(
        exp.skipped_already_encrypted
        or exp.skipped_not_encrypted
        or exp.skipped_symlinks
        or exp.walk_errors
    )


def _show_empty_expansion(
    action: str,
    raw_paths: list[Path],
    exp: file_ops.Expansion,
    any_folder: bool,
) -> None:
    """Nothing matched the action. Tell the user why."""
    if action == "encrypt":
        if exp.skipped_already_encrypted and not any_folder:
            messagebox.showinfo(
                "CryptoFile",
                "Nothing to encrypt — every selected file is already a "
                ".lock file.\n\nUse Decrypt instead.",
            )
        elif any_folder:
            messagebox.showinfo(
                "CryptoFile",
                "The selected folder(s) contain no files to encrypt "
                f"(already-encrypted files are skipped: "
                f"{len(exp.skipped_already_encrypted)}; symlinks skipped: "
                f"{len(exp.skipped_symlinks)}).",
            )
        else:
            messagebox.showinfo("CryptoFile", "Nothing to encrypt.")
    else:
        if exp.skipped_not_encrypted and not any_folder:
            messagebox.showinfo(
                "CryptoFile",
                "Nothing to decrypt — selected files aren't .lock files.",
            )
        elif any_folder:
            messagebox.showinfo(
                "CryptoFile",
                "The selected folder(s) contain no .lock files to decrypt "
                f"(non-encrypted files skipped: {len(exp.skipped_not_encrypted)}).",
            )
        else:
            messagebox.showinfo("CryptoFile", "Nothing to decrypt.")


def _confirm_large_batch(action: str, exp: file_ops.Expansion) -> bool:
    label = "encrypt" if action == "encrypt" else "decrypt"
    msg_lines = [
        f"You're about to {label} {len(exp.files):,} files.",
        "",
        "Originals will be securely deleted after successful "
        f"{label}ion. This cannot be undone without the password.",
    ]
    if exp.skipped_already_encrypted and action == "encrypt":
        msg_lines.append(
            f"\n{len(exp.skipped_already_encrypted)} already-encrypted files "
            "will be skipped."
        )
    if exp.skipped_symlinks:
        msg_lines.append(f"\n{len(exp.skipped_symlinks)} symlinks will be skipped.")
    msg_lines.append("\nContinue?")
    return bool(messagebox.askyesno(f"CryptoFile — {label} {len(exp.files):,} files", "\n".join(msg_lines)))


# ── Single-file path (unchanged UX from v1) ───────────────────────────────


def _run_single(action: str, path: Path) -> int:
    if action == "encrypt":
        return _run_encrypt(path)
    return _run_decrypt(path)


def _run_encrypt(path: Path) -> int:
    if not _require_file(path):
        return 1
    if path.suffix.lower() == file_ops.ENCRYPTED_SUFFIX:
        if not messagebox.askyesno(
            "Already encrypted?",
            f"{path.name} has a .lock extension — did you mean to Decrypt?\n\n"
            "Click Yes to encrypt it again, No to cancel.",
        ):
            return 0
    pw = gui.ask_password(mode="encrypt", filename=path.name)
    if pw is None:
        return 0
    result, err = gui.run_with_progress(
        parent=None,
        title="CryptoFile — Encrypting",
        subtitle=f"Encrypting {path.name}",
        worker=lambda pw_win: file_ops.encrypt_file(
            path, pw,
            progress=pw_win.report_progress,   # thread-safe; no cross-thread tk
            cancel_check=pw_win.cancelled,
        ),
    )
    if isinstance(err, crypto.Cancelled):
        return 0
    if err is not None:
        _show_error(err)
        return 1
    assert isinstance(result, Path)
    messagebox.showinfo(
        "CryptoFile — Encrypted",
        f"{path.name}\n→ {result.name}\n\nOriginal securely deleted.",
    )
    return 0


def _run_decrypt(path: Path) -> int:
    if not _require_file(path):
        return 1
    pw = gui.ask_password(mode="decrypt", filename=path.name)
    if pw is None:
        return 0
    result, err = gui.run_with_progress(
        parent=None,
        title="CryptoFile — Decrypting",
        subtitle=f"Decrypting {path.name}",
        worker=lambda pw_win: file_ops.decrypt_file(
            path, pw,
            progress=pw_win.report_progress,   # thread-safe; no cross-thread tk
            cancel_check=pw_win.cancelled,
        ),
    )
    if isinstance(err, crypto.Cancelled):
        return 0
    if err is not None:
        _show_error(err)
        return 1
    assert isinstance(result, Path)
    messagebox.showinfo("CryptoFile — Decrypted", f"{path.name}\n→ {result.name}")
    return 0


# ── Batch path (2+ files) ─────────────────────────────────────────────────


@dataclass
class _FileOutcome:
    path: Path
    status: str   # "ok", "skipped", "cancelled", or error kind ("bad_password", "bad_format", ...)
    message: str  # human-readable detail; "" for ok
    output: Path | None = None


def _run_batch(action: str, exp: file_ops.Expansion) -> int:
    files = exp.files
    # First: gather passwords. Shared or per-file.
    prompt = gui.ask_batch_password(mode=action, files=files)
    if prompt.cancelled:
        return 0
    outcomes: list[_FileOutcome] = []

    # Set up one progress window for the whole batch.
    dummy_root = tk.Tk()
    dummy_root.withdraw()
    win = gui.BatchProgressWindow(
        dummy_root,
        title=f"CryptoFile — {'Encrypting' if action == 'encrypt' else 'Decrypting'} {len(files)} files",
        total_files=len(files),
    )

    worker_done = threading.Event()
    state: dict = {"cur_index": 0, "cur_total": 0}

    def _on_progress(done: int, total: int) -> None:
        state["cur_index"] = done
        state["cur_total"] = total
        win.report_progress(done, total)  # thread-safe; drained on main thread

    def _worker() -> None:
        for i, fpath in enumerate(files, start=1):
            if win.cancelled():
                # Mark remaining files as cancelled and stop.
                outcomes.append(_FileOutcome(fpath, "cancelled", "User cancelled"))
                for remaining in files[i:]:
                    outcomes.append(_FileOutcome(remaining, "cancelled", "User cancelled"))
                break
            win.report_file_start(i, fpath.name)

            # Determine the password for this file.
            if prompt.per_file:
                # Ask on the Tk thread, block worker until answered.
                pw_holder: list[str | None] = [None]
                pw_done = threading.Event()

                def _ask():
                    pw_holder[0] = gui.ask_password(
                        mode=action, filename=fpath.name, parent=dummy_root,
                    )
                    pw_done.set()

                win.after(0, _ask)
                pw_done.wait()
                pw = pw_holder[0]
                if pw is None:
                    outcomes.append(_FileOutcome(fpath, "skipped", "User skipped"))
                    win.report_file_finish()
                    continue
            else:
                pw = prompt.password

            # Run the actual crypto.
            try:
                if action == "encrypt":
                    out = file_ops.encrypt_file(
                        fpath, pw, progress=_on_progress,
                        cancel_check=win.cancelled,
                    )
                else:
                    out = file_ops.decrypt_file(
                        fpath, pw, progress=_on_progress,
                        cancel_check=win.cancelled,
                    )
                outcomes.append(_FileOutcome(fpath, "ok", "", out))
            except crypto.Cancelled:
                outcomes.append(_FileOutcome(fpath, "cancelled", "User cancelled"))
                # Honour the cancel: mark remaining as cancelled and stop.
                for remaining in files[i:]:
                    outcomes.append(_FileOutcome(remaining, "cancelled", "User cancelled"))
                break
            except crypto.BadPassword:
                outcomes.append(
                    _FileOutcome(fpath, "bad_password", "Wrong password or corrupted file"),
                )
                # If we used a shared password and it failed on the very first
                # file, the password is probably wrong for all. Offer to stop.
                if not prompt.per_file and i == 1 and len(files) > 1:
                    # Mark remaining as skipped; user decides on the summary.
                    for remaining in files[1:]:
                        outcomes.append(
                            _FileOutcome(
                                remaining, "skipped",
                                "Skipped after first-file password failure",
                            ),
                        )
                    break
            except crypto.BadFormat as e:
                outcomes.append(_FileOutcome(fpath, "bad_format", str(e)))
            except (crypto.CryptoError, file_ops.FileOpError) as e:
                outcomes.append(_FileOutcome(fpath, "error", str(e)))
            except Exception as e:  # noqa: BLE001
                outcomes.append(_FileOutcome(fpath, "error", f"{type(e).__name__}: {e}"))
            win.report_file_finish()
        worker_done.set()
        # Close the window on the main thread, not from the worker.
        # signal_batch_complete is thread-safe — the drain loop sees it
        # on its next tick and calls win.destroy() on the main thread.
        win.signal_batch_complete()

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    dummy_root.wait_window(win)
    worker_done.wait(timeout=5.0)
    dummy_root.destroy()

    _show_batch_summary(action, outcomes, exp)
    # Return code: 0 if all ok, 1 if any file errored.
    return 0 if all(o.status == "ok" for o in outcomes) else 1


def _show_batch_summary(
    action: str, outcomes: list[_FileOutcome], exp: file_ops.Expansion,
) -> None:
    ok = sum(1 for o in outcomes if o.status == "ok")
    failed = [o for o in outcomes if o.status not in ("ok", "skipped", "cancelled")]
    skipped = [o for o in outcomes if o.status in ("skipped", "cancelled")]

    lines = [
        f"{ok} of {len(outcomes)} "
        f"{'encrypted' if action == 'encrypt' else 'decrypted'} successfully.",
    ]
    if skipped:
        lines.append(f"{len(skipped)} skipped during processing.")

    # Folder-walk skip tallies (these weren't in `outcomes` — they never
    # entered the process loop). Surface them so the user knows the numbers
    # match their expectation.
    if action == "encrypt" and exp.skipped_already_encrypted:
        lines.append(
            f"{len(exp.skipped_already_encrypted)} already-encrypted files skipped."
        )
    if action == "decrypt" and exp.skipped_not_encrypted:
        lines.append(
            f"{len(exp.skipped_not_encrypted)} non-.lock files skipped."
        )
    if exp.skipped_symlinks:
        lines.append(f"{len(exp.skipped_symlinks)} symlinks skipped.")
    if exp.walk_errors:
        lines.append(f"{len(exp.walk_errors)} files could not be read (permission denied or I/O error).")

    if failed:
        lines.append(f"{len(failed)} failed:")
        for o in failed[:10]:
            lines.append(f"  • {o.path.name}: {o.message}")
        if len(failed) > 10:
            lines.append(f"  … and {len(failed) - 10} more")

    if failed:
        messagebox.showerror("CryptoFile — batch complete", "\n".join(lines))
    else:
        messagebox.showinfo("CryptoFile — batch complete", "\n".join(lines))


# ── Shared helpers ────────────────────────────────────────────────────────


def _require_file(path: Path) -> bool:
    if not path.exists():
        messagebox.showerror("CryptoFile", f"File not found:\n{path}")
        return False
    if not path.is_file():
        messagebox.showerror("CryptoFile", f"Not a file:\n{path}")
        return False
    return True


def _show_error(err: BaseException) -> None:
    if isinstance(err, crypto.BadPassword):
        messagebox.showerror(
            "CryptoFile",
            "Wrong password, or the file is corrupted.\n\n"
            "If the password is correct, the file may have been tampered "
            "with or damaged in transit.",
        )
    elif isinstance(err, crypto.BadFormat):
        messagebox.showerror(
            "CryptoFile",
            f"This doesn't look like a CryptoFile-encrypted file.\n\n{err}",
        )
    elif isinstance(err, crypto.CryptoError):
        messagebox.showerror("CryptoFile", f"Cryptographic error:\n{err}")
    elif isinstance(err, file_ops.FileOpError):
        messagebox.showerror("CryptoFile", f"File error:\n{err}")
    else:
        messagebox.showerror(
            "CryptoFile", f"Unexpected error:\n{type(err).__name__}: {err}"
        )


# ── Settings window ───────────────────────────────────────────────────────


def _run_settings() -> int:
    root = tk.Tk()
    root.title("CryptoFile — Settings")
    root.geometry("520x380")
    root.resizable(False, False)

    frame = ttk.Frame(root, padding=18)
    frame.pack(fill="both", expand=True)

    ttk.Label(
        frame, text=f"CryptoFile v{__version__}",
        font=("Segoe UI", 14, "bold"),
    ).pack(anchor="w")
    ttk.Label(
        frame,
        text="Right-click any file → Encrypt with CryptoFile.\n"
             "Right-click a .lock file → Decrypt with CryptoFile.\n"
             "Multi-select works — one password, one progress window for the batch.",
        foreground="#333",
    ).pack(anchor="w", pady=(4, 16))

    status_var = tk.StringVar()
    status_lbl = ttk.Label(frame, textvariable=status_var, font=("Segoe UI", 10, "bold"))
    status_lbl.pack(anchor="w")

    def _refresh_status() -> None:
        if sys.platform != "win32":
            status_var.set("Shell integration: unavailable (Windows only)")
            btn_install.state(["disabled"])
            btn_uninstall.state(["disabled"])
            return
        if shell_integration.is_installed():
            status_var.set("Shell integration: INSTALLED")
            status_lbl.configure(foreground="#1b5e20")
            btn_install.configure(text="Reinstall")
        else:
            status_var.set("Shell integration: not installed")
            status_lbl.configure(foreground="#b71c1c")
            btn_install.configure(text="Install")

    btn_row = ttk.Frame(frame)
    btn_row.pack(fill="x", pady=(12, 0))

    def _do_install() -> None:
        try:
            shell_integration.install()
            messagebox.showinfo(
                "CryptoFile",
                "Context menu installed.\n\nRight-click a file in Explorer to see the new options.",
            )
        except Exception as e:
            messagebox.showerror("Install failed", str(e))
        _refresh_status()

    def _do_uninstall() -> None:
        try:
            shell_integration.uninstall()
            messagebox.showinfo("CryptoFile", "Context menu removed.")
        except Exception as e:
            messagebox.showerror("Uninstall failed", str(e))
        _refresh_status()

    btn_install = ttk.Button(btn_row, text="Install", command=_do_install)
    btn_install.pack(side="left")
    btn_uninstall = ttk.Button(btn_row, text="Uninstall", command=_do_uninstall)
    btn_uninstall.pack(side="left", padx=(8, 0))

    about = ttk.Frame(frame)
    about.pack(fill="both", expand=True, pady=(24, 0))
    ttk.Label(about, text="Under the hood", font=("Segoe UI", 10, "bold")).pack(anchor="w")
    ttk.Label(
        about,
        text=(
            "• Key derivation: Argon2id (256 MiB, 3 iterations, 4 lanes)\n"
            "• Cipher: AES-256-GCM, 1 MiB chunks, per-chunk authentication\n"
            "• Header bound into every chunk's AAD — tampering is detected\n"
            "• Originals securely overwritten after a successful operation\n"
            "• Multi-select: single-instance coordinator batches N invocations into one UI"
        ),
        foreground="#555",
        justify="left",
    ).pack(anchor="w")

    _refresh_status()
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
