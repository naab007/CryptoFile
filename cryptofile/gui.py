"""Tkinter UIs: password prompt, progress window, settings window."""
from __future__ import annotations

import threading
import tkinter as tk
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Callable, Iterator, Optional


# ── Shared helpers (R2 refactor) ───────────────────────────────────────────


@contextmanager
def hidden_root() -> Iterator[tk.Tk]:
    """Yield a 1×1, off-screen, transparent, borderless ``tk.Tk()``.

    Background: ``Toplevel.transient(withdrawn_root)`` has been observed
    to render the Toplevel invisibly / off-screen on Windows when the
    exe is launched from a shell verb (right-click → Encrypt). We work
    around this by keeping the parent root "real" but positioned off
    screen with zero alpha.

    The four call sites (``ask_password``, ``run_with_progress``,
    ``ask_batch_password``, ``_run_batch``'s dummy) all share this
    exact setup; R2 refactor consolidates them here so any future tweak
    lands in one place.
    """
    root = tk.Tk()
    root.geometry("1x1+-2000+-2000")
    root.overrideredirect(True)
    root.attributes("-alpha", 0.0)
    try:
        yield root
    finally:
        try:
            root.destroy()
        except tk.TclError:
            pass


def _force_window_foreground(win: tk.Toplevel, focus_widget: tk.Misc | None = None) -> None:
    """Force a Toplevel to the foreground with the topmost-toggle dance.

    Used by PasswordDialog, ProgressWindow, BatchProgressWindow, AND
    BatchPasswordDialog (M-new-5 — previously only had a weaker
    lift+focus, no topmost toggle). Shell verbs leave focus with
    Explorer and the Toplevel otherwise lands behind it.
    """
    try:
        win.attributes("-topmost", True)
        win.lift()
        win.focus_force()
        if focus_widget is not None:
            try:
                focus_widget.focus_force()
            except tk.TclError:
                pass
        win.after(150, lambda: _safe_release_topmost(win))
    except tk.TclError:
        pass


def _safe_release_topmost(win: tk.Toplevel) -> None:
    try:
        win.attributes("-topmost", False)
    except tk.TclError:
        pass


# ── Password dialog ────────────────────────────────────────────────────────


class PasswordDialog(tk.Toplevel):
    """Modal dialog that prompts for a password.

    ``mode='encrypt'`` shows two fields (password + confirm); ``mode='decrypt'``
    shows one. On OK, ``self.password`` is set; on Cancel/close it stays None.
    """

    def __init__(self, parent: tk.Misc, mode: str, filename: str) -> None:
        super().__init__(parent)
        self.title(f"CryptoFile — {'Encrypt' if mode == 'encrypt' else 'Decrypt'}")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.password: Optional[str] = None
        self._mode = mode

        frame = ttk.Frame(self, padding=16)
        frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(
            frame,
            text=f"{'Encrypting' if mode == 'encrypt' else 'Decrypting'}:",
            font=("Segoe UI", 9, "bold"),
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            frame,
            text=filename,
            foreground="#333",
            wraplength=360,
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 12))

        ttk.Label(frame, text="Password").grid(row=2, column=0, sticky="w")
        self.v_pw = tk.StringVar()
        self.e_pw = ttk.Entry(frame, textvariable=self.v_pw, show="•", width=36)
        self.e_pw.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(2, 8))

        if mode == "encrypt":
            ttk.Label(frame, text="Confirm password").grid(row=4, column=0, sticky="w")
            self.v_confirm = tk.StringVar()
            self.e_confirm = ttk.Entry(frame, textvariable=self.v_confirm, show="•", width=36)
            self.e_confirm.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(2, 4))
            ttk.Label(
                frame,
                text=(
                    "Remember this password — there is no recovery. "
                    "The file will be unrecoverable without it."
                ),
                foreground="#b71c1c",
                wraplength=360,
                font=("Segoe UI", 9),
            ).grid(row=6, column=0, columnspan=2, sticky="w", pady=(4, 8))

        self.v_show = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            frame, text="Show password",
            variable=self.v_show, command=self._toggle_show,
        ).grid(row=7, column=0, sticky="w", pady=(4, 10))

        btns = ttk.Frame(frame)
        btns.grid(row=8, column=0, columnspan=2, sticky="ew")
        btns.columnconfigure(0, weight=1)
        ttk.Button(btns, text="Cancel", command=self._cancel).grid(row=0, column=1, padx=(4, 0))
        ttk.Button(
            btns, text="Encrypt" if mode == "encrypt" else "Decrypt",
            command=self._ok,
        ).grid(row=0, column=2, padx=(6, 0))

        self.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self._cancel())
        # Force this dialog to the foreground. When the exe is launched from
        # a Windows Explorer shell verb (right-click → Encrypt with CryptoFile)
        # the invoking Explorer window retains focus and our dialog lands
        # behind it — indistinguishable from "no dialog appeared". Toggle
        # -topmost briefly to force foreground, then release so the dialog
        # doesn't stay pinned above other windows forever.
        self.after(50, self._force_foreground)

    def _force_foreground(self) -> None:
        try:
            self.attributes("-topmost", True)
            self.lift()
            self.focus_force()
            self.e_pw.focus_force()
            self.after(150, lambda: self.attributes("-topmost", False))
        except tk.TclError:
            # If the window has been destroyed (user cancelled very fast),
            # ignore — nothing to focus.
            pass

    def _toggle_show(self) -> None:
        show = "" if self.v_show.get() else "•"
        self.e_pw.configure(show=show)
        if self._mode == "encrypt":
            self.e_confirm.configure(show=show)

    def _ok(self) -> None:
        pw = self.v_pw.get()
        if not pw:
            messagebox.showerror("Empty password", "Enter a password.", parent=self)
            return
        if self._mode == "encrypt":
            if pw != self.v_confirm.get():
                messagebox.showerror(
                    "Passwords don't match", "Retype the confirmation.", parent=self
                )
                return
            if len(pw) < 8:
                if not messagebox.askyesno(
                    "Short password",
                    f"Your password is only {len(pw)} characters. "
                    "Short passwords can be brute-forced quickly even with Argon2id. "
                    "Continue anyway?",
                    parent=self,
                ):
                    return
        self.password = pw
        self.destroy()

    def _cancel(self) -> None:
        self.password = None
        self.destroy()


def ask_password(mode: str, filename: str, parent: tk.Misc | None = None) -> Optional[str]:
    """Show the password dialog modally and return the entered password (or None).

    Creates a hidden parent root if none is supplied. The root is placed
    off-screen rather than `withdraw()`-ed, because ``Toplevel.transient()``
    on a withdrawn root has been observed to make the Toplevel itself
    invisible / taskbar-absent on some Windows versions when the exe is
    launched from a shell verb (right-click → Encrypt with CryptoFile).
    """
    if parent is not None:
        dlg = PasswordDialog(parent, mode=mode, filename=filename)
        parent.wait_window(dlg)
        return dlg.password
    # R2 refactor — shared ``hidden_root()`` context manager ensures
    # every ``ask_*`` call uses the exact same off-screen-root pattern.
    with hidden_root() as root:
        dlg = PasswordDialog(root, mode=mode, filename=filename)
        root.wait_window(dlg)
        return dlg.password


# ── Progress window ───────────────────────────────────────────────────────


class ProgressWindow(tk.Toplevel):
    """Progress window for long operations (Argon2 KDF + file I/O).

    Threading model: ``report_progress()`` and ``cancelled()`` are both
    thread-safe — workers call them directly without going through tk.
    The UI update happens on the main thread via a self-scheduled
    ``_drain`` loop that reads a locked snapshot of the progress state.

    Why not just ``pw_win.after(0, pw_win.set_progress, ...)``?
    `after()` from a non-main thread is documented as safe but has been
    observed to raise "main thread is not in main loop" intermittently
    in frozen `--windowed` PyInstaller builds on Windows (CryptoFile
    1.0.3 bug). Polling avoids it entirely.
    """

    def __init__(self, parent: tk.Misc, title: str, subtitle: str) -> None:
        super().__init__(parent)
        self.title(title)
        self.geometry("420x150")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self._cancel = threading.Event()

        # Thread-shared progress state — writes under lock; reads in _drain.
        self._p_done = 0
        self._p_total = 0
        self._p_dirty = False
        self._p_lock = threading.Lock()
        self._closed = False

        frame = ttk.Frame(self, padding=18)
        frame.pack(fill="both", expand=True)
        self.lbl_subtitle = ttk.Label(
            frame, text=subtitle, wraplength=380, font=("Segoe UI", 10, "bold"),
        )
        self.lbl_subtitle.pack(anchor="w")
        self.lbl_detail = ttk.Label(frame, text="Starting…", foreground="#555")
        self.lbl_detail.pack(anchor="w", pady=(4, 10))

        self.bar = ttk.Progressbar(frame, mode="determinate", length=380, maximum=100.0)
        self.bar.pack(fill="x")

        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=(10, 0))
        btns.columnconfigure(0, weight=1)
        ttk.Button(btns, text="Cancel", command=self._on_cancel).grid(row=0, column=1)

        self.protocol("WM_DELETE_WINDOW", self._on_cancel)
        # Start the main-thread drain loop.
        self.after(80, self._drain)
        # Same foreground-forcing dance as PasswordDialog — shell verbs leave
        # focus with Explorer and the Toplevel otherwise lands behind it
        # (indistinguishable from "no window opened"). CryptoFile 1.0.5 bug:
        # .partial file appeared but no progress UI was ever visible.
        self.after(50, self._force_foreground)

    def _force_foreground(self) -> None:
        try:
            self.attributes("-topmost", True)
            self.lift()
            self.focus_force()
            self.after(150, lambda: self.attributes("-topmost", False))
        except tk.TclError:
            pass

    def set_detail(self, text: str) -> None:
        self.lbl_detail.configure(text=text)

    def set_progress(self, done: int, total: int) -> None:
        """Main-thread only. Workers should call ``report_progress`` instead."""
        if total <= 0:
            self.bar.configure(mode="indeterminate")
            self.bar.step(2)
            return
        pct = (done / total) * 100.0
        self.bar.configure(mode="determinate", value=pct)
        self.lbl_detail.configure(text=f"{_fmt_bytes(done)} / {_fmt_bytes(total)}  ({pct:.1f}%)")

    def report_progress(self, done: int, total: int) -> None:
        """Thread-safe. Call from any thread — the main-thread drain loop
        picks up the new values and calls ``set_progress`` on the next tick."""
        with self._p_lock:
            self._p_done = done
            self._p_total = total
            self._p_dirty = True

    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def _on_cancel(self) -> None:
        self._cancel.set()
        try:
            self.lbl_detail.configure(text="Cancelling…")
        except tk.TclError:
            pass

    def _drain(self) -> None:
        if self._closed:
            return
        with self._p_lock:
            dirty = self._p_dirty
            d, t = self._p_done, self._p_total
            if dirty:
                self._p_dirty = False
        if dirty:
            try:
                self.set_progress(d, t)
            except tk.TclError:
                self._closed = True
                return
            except Exception:
                # L-new-7 — set_progress raising anything other than
                # TclError would silently kill the drain loop (tk's
                # mainloop swallows exceptions out of after-callbacks).
                # Log and continue; we still want the cancel button to
                # work even if the label update blew up.
                import logging
                logging.getLogger("cryptofile.gui").exception(
                    "ProgressWindow.set_progress raised unexpectedly"
                )
        try:
            self.after(80, self._drain)
        except tk.TclError:
            self._closed = True

    def destroy(self) -> None:  # type: ignore[override]
        self._closed = True
        super().destroy()


def _fmt_bytes(n: int) -> str:
    units = ("B", "KB", "MB", "GB", "TB")
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024
        i += 1
    return f"{f:.1f} {units[i]}"


def run_with_progress(
    parent: tk.Misc | None,
    title: str,
    subtitle: str,
    worker: Callable[["ProgressWindow"], object],
) -> tuple[Optional[object], Optional[BaseException]]:
    """Run ``worker`` on a background thread with a modal progress window.

    The worker receives the ``ProgressWindow`` so it can call
    ``set_progress`` / ``cancelled``. Returns ``(result, exception)``; exactly
    one of the two is None.
    """
    # R2 refactor — use the shared hidden_root() ctxmgr.
    def _run_with(owner: tk.Misc) -> tuple[Optional[object], Optional[BaseException]]:
        win = ProgressWindow(owner, title, subtitle)
        result: list[object] = []
        error: list[BaseException] = []

        def _target():
            try:
                result.append(worker(win))
            except BaseException as e:  # noqa: BLE001 — surface everything to caller
                error.append(e)

        thread = threading.Thread(target=_target, daemon=True)
        thread.start()

        def _poll():
            if thread.is_alive():
                win.after(80, _poll)
            else:
                win.after(50, win.destroy)

        win.after(80, _poll)
        owner.wait_window(win)
        thread.join(timeout=1.0)  # should already be done
        return (result[0] if result else None, error[0] if error else None)

    if parent is not None:
        return _run_with(parent)
    with hidden_root() as root:
        return _run_with(root)


# ── Batch UIs (multi-file invocations) ────────────────────────────────────


@dataclass
class BatchPasswordResult:
    """Outcome of the batch password dialog.

    ``per_file`` True means the caller should re-prompt individually for each
    file (the checkbox was ticked). ``password`` is None in that case.
    """

    password: Optional[str]
    per_file: bool
    cancelled: bool


class BatchPasswordDialog(tk.Toplevel):
    """Modal dialog for multi-file encrypt/decrypt.

    Shows a scrollable list of the files to be processed, a password field
    (confirm-field only on encrypt), and an optional "use a different
    password for each file" checkbox.
    """

    def __init__(self, parent: tk.Misc, mode: str, files: list[Path]) -> None:
        super().__init__(parent)
        # L-new-6 — runtime checks, not asserts: ``python -O`` strips
        # asserts, at which point invalid inputs would render a broken
        # dialog instead of failing fast.
        if mode not in ("encrypt", "decrypt"):
            raise ValueError(f"mode must be 'encrypt' or 'decrypt', got {mode!r}")
        if len(files) < 2:
            raise ValueError("BatchPasswordDialog requires >= 2 files; use PasswordDialog for single-file")
        self.title(f"CryptoFile — {'Encrypt' if mode == 'encrypt' else 'Decrypt'} {len(files)} files")
        self.geometry("480x440")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result: Optional[BatchPasswordResult] = None
        self._mode = mode

        frame = ttk.Frame(self, padding=16)
        frame.pack(fill="both", expand=True)

        ttk.Label(
            frame,
            text=f"{'Encrypting' if mode == 'encrypt' else 'Decrypting'} "
                 f"{len(files)} files:",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w")

        # Scrollable file list
        list_frame = ttk.Frame(frame)
        list_frame.pack(fill="x", pady=(4, 10))
        sb = ttk.Scrollbar(list_frame, orient="vertical")
        sb.pack(side="right", fill="y")
        self._listbox = tk.Listbox(
            list_frame, height=7, activestyle="none",
            font=("Segoe UI", 9), yscrollcommand=sb.set,
        )
        self._listbox.pack(side="left", fill="x", expand=True)
        sb.configure(command=self._listbox.yview)
        for f in files:
            # Show parent-folder + name so same-name files in different folders
            # aren't ambiguous.
            self._listbox.insert("end", f"{f.parent.name}\\{f.name}")

        ttk.Label(frame, text="Password").pack(anchor="w")
        self.v_pw = tk.StringVar()
        self.e_pw = ttk.Entry(frame, textvariable=self.v_pw, show="•")
        self.e_pw.pack(fill="x", pady=(2, 8))

        if mode == "encrypt":
            ttk.Label(frame, text="Confirm password").pack(anchor="w")
            self.v_confirm = tk.StringVar()
            self.e_confirm = ttk.Entry(frame, textvariable=self.v_confirm, show="•")
            self.e_confirm.pack(fill="x", pady=(2, 4))
            ttk.Label(
                frame,
                text=(
                    "The same password will be used for all files. Remember it — "
                    "there is no recovery."
                ),
                foreground="#b71c1c",
                wraplength=440,
                font=("Segoe UI", 9),
            ).pack(anchor="w", pady=(4, 8))
        else:
            self.v_confirm = tk.StringVar()  # unused, keeps _ok() symmetric

        self.v_show = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            frame, text="Show password", variable=self.v_show,
            command=self._toggle_show,
        ).pack(anchor="w")

        self.v_per_file = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            frame,
            text="Use a different password for each file (prompt one-by-one)",
            variable=self.v_per_file,
            command=self._toggle_per_file,
        ).pack(anchor="w", pady=(2, 10))

        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=(0, 0))
        btns.columnconfigure(0, weight=1)
        ttk.Button(btns, text="Cancel", command=self._cancel).grid(row=0, column=1, padx=(4, 0))
        self._btn_ok = ttk.Button(
            btns,
            text="Encrypt all" if mode == "encrypt" else "Decrypt all",
            command=self._ok,
        )
        self._btn_ok.grid(row=0, column=2, padx=(6, 0))

        self.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self._cancel())
        # M-new-5 — full foreground-forcing dance (topmost toggle) so the
        # batch password dialog is visible on shell-verb launches where
        # focus stays with Explorer. Earlier versions only did
        # lift+focus, which is unreliable on Win11.
        self.after(50, lambda: _force_window_foreground(self, self.e_pw))

    def _toggle_show(self) -> None:
        show = "" if self.v_show.get() else "•"
        self.e_pw.configure(show=show)
        if self._mode == "encrypt":
            self.e_confirm.configure(show=show)

    def _toggle_per_file(self) -> None:
        # When per-file is selected, clear + disable the password fields so
        # it's obvious they don't apply, and swap the OK button text.
        on = self.v_per_file.get()
        state = "disabled" if on else "normal"
        self.e_pw.configure(state=state)
        if self._mode == "encrypt":
            self.e_confirm.configure(state=state)
        if on:
            self.v_pw.set("")
            self.v_confirm.set("")
            self._btn_ok.configure(
                text="Next…" if self._mode == "encrypt" else "Next…",
            )
        else:
            self._btn_ok.configure(
                text="Encrypt all" if self._mode == "encrypt" else "Decrypt all",
            )

    def _ok(self) -> None:
        if self.v_per_file.get():
            self.result = BatchPasswordResult(password=None, per_file=True, cancelled=False)
            self.destroy()
            return
        pw = self.v_pw.get()
        if not pw:
            messagebox.showerror("Empty password", "Enter a password.", parent=self)
            return
        if self._mode == "encrypt":
            if pw != self.v_confirm.get():
                messagebox.showerror(
                    "Passwords don't match",
                    "Retype the confirmation.", parent=self,
                )
                return
            if len(pw) < 8:
                if not messagebox.askyesno(
                    "Short password",
                    f"Your password is only {len(pw)} characters — short "
                    "passwords can be brute-forced quickly even with Argon2id. "
                    "Use for all files anyway?",
                    parent=self,
                ):
                    return
        self.result = BatchPasswordResult(password=pw, per_file=False, cancelled=False)
        self.destroy()

    def _cancel(self) -> None:
        self.result = BatchPasswordResult(password=None, per_file=False, cancelled=True)
        self.destroy()


def ask_batch_password(
    mode: str, files: list[Path], parent: tk.Misc | None = None,
) -> BatchPasswordResult:
    if parent is not None:
        dlg = BatchPasswordDialog(parent, mode=mode, files=files)
        parent.wait_window(dlg)
        return dlg.result or BatchPasswordResult(None, False, True)
    with hidden_root() as root:
        dlg = BatchPasswordDialog(root, mode=mode, files=files)
        root.wait_window(dlg)
        return dlg.result or BatchPasswordResult(None, False, True)


class BatchProgressWindow(tk.Toplevel):
    """Two-level progress window: overall (files done / total) + current file bytes."""

    def __init__(self, parent: tk.Misc, title: str, total_files: int) -> None:
        super().__init__(parent)
        self.title(title)
        self.geometry("460x210")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self._cancel = threading.Event()
        self._total_files = total_files

        # Thread-shared state for the main-thread drain loop. See
        # ProgressWindow's docstring for why we poll instead of calling
        # `.after(0, ...)` from worker threads.
        self._state_lock = threading.Lock()
        self._state_dirty = False
        self._state_file_index = 1
        self._state_file_name = ""
        self._state_file_started = False
        self._state_file_finished = False
        self._state_p_done = 0
        self._state_p_total = 0
        self._should_close = False
        self._closed = False

        frame = ttk.Frame(self, padding=18)
        frame.pack(fill="both", expand=True)

        self.lbl_overall = ttk.Label(
            frame, text=f"File 1 of {total_files}",
            font=("Segoe UI", 10, "bold"),
        )
        self.lbl_overall.pack(anchor="w")
        self.bar_overall = ttk.Progressbar(
            frame, mode="determinate", length=420, maximum=total_files,
        )
        self.bar_overall.pack(fill="x", pady=(2, 12))

        self.lbl_current = ttk.Label(frame, text="", foreground="#333")
        self.lbl_current.pack(anchor="w")
        self.bar_current = ttk.Progressbar(
            frame, mode="determinate", length=420, maximum=100.0,
        )
        self.bar_current.pack(fill="x", pady=(2, 4))
        self.lbl_detail = ttk.Label(frame, text="", foreground="#555",
                                    font=("Segoe UI", 9))
        self.lbl_detail.pack(anchor="w")

        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=(12, 0))
        btns.columnconfigure(0, weight=1)
        ttk.Button(btns, text="Cancel", command=self._on_cancel).grid(row=0, column=1)
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        # Launch the drain loop.
        self.after(80, self._drain)
        # Force foreground — see ProgressWindow for rationale.
        self.after(50, self._force_foreground)

    def _force_foreground(self) -> None:
        try:
            self.attributes("-topmost", True)
            self.lift()
            self.focus_force()
            self.after(150, lambda: self.attributes("-topmost", False))
        except tk.TclError:
            pass

    # ── Thread-safe entry points for workers ──────────────────────────────

    def report_file_start(self, index_1_based: int, filename: str) -> None:
        """Thread-safe. Worker calls when it begins processing a new file."""
        with self._state_lock:
            self._state_file_index = index_1_based
            self._state_file_name = filename
            self._state_file_started = True
            self._state_p_done = 0
            self._state_p_total = 0
            self._state_dirty = True

    def report_progress(self, done: int, total: int) -> None:
        """Thread-safe. Worker calls for byte-level progress within a file."""
        with self._state_lock:
            self._state_p_done = done
            self._state_p_total = total
            self._state_dirty = True

    def report_file_finish(self) -> None:
        """Thread-safe. Worker calls when it finishes a file (success or skip)."""
        with self._state_lock:
            self._state_file_finished = True
            self._state_dirty = True

    def signal_batch_complete(self) -> None:
        """Thread-safe. Worker calls once after the whole batch is done
        (success, cancel, or error). The drain loop sees this on its next
        tick and destroys the window on the main thread — avoids calling
        `win.destroy()` or `win.after(…, win.destroy)` from the worker,
        either of which can raise "main thread is not in main loop"."""
        with self._state_lock:
            self._should_close = True
            self._state_dirty = True

    # ── Main-thread drain loop ────────────────────────────────────────────

    def _drain(self) -> None:
        if self._closed:
            return
        with self._state_lock:
            dirty = self._state_dirty
            idx = self._state_file_index
            name = self._state_file_name
            started = self._state_file_started
            finished = self._state_file_finished
            should_close = self._should_close
            d, t = self._state_p_done, self._state_p_total
            if dirty:
                self._state_dirty = False
                self._state_file_started = False
                self._state_file_finished = False
        if dirty:
            try:
                if started:
                    self.start_file(idx, name)
                if t > 0 or d > 0:
                    self.set_progress(d, t)
                if finished:
                    self.finish_file()
            except tk.TclError:
                self._closed = True
                return
        if should_close:
            self._closed = True
            try:
                self.destroy()
            except tk.TclError:
                pass
            return
        try:
            self.after(80, self._drain)
        except tk.TclError:
            self._closed = True

    def destroy(self) -> None:  # type: ignore[override]
        self._closed = True
        super().destroy()

    # ── Main-thread UI primitives (workers should call report_* instead) ──

    def start_file(self, index_1_based: int, filename: str) -> None:
        self.lbl_overall.configure(
            text=f"File {index_1_based} of {self._total_files}",
        )
        self.bar_overall.configure(value=index_1_based - 1)
        self.lbl_current.configure(text=filename)
        self.bar_current.configure(value=0)
        self.lbl_detail.configure(text="Deriving key…")

    def set_progress(self, done: int, total: int) -> None:
        if total <= 0:
            self.bar_current.configure(mode="indeterminate")
            self.bar_current.step(2)
            return
        pct = (done / total) * 100.0
        self.bar_current.configure(mode="determinate", value=pct)
        self.lbl_detail.configure(
            text=f"{_fmt_bytes(done)} / {_fmt_bytes(total)}  ({pct:.1f}%)",
        )

    def finish_file(self) -> None:
        self.bar_overall.step(1)

    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def _on_cancel(self) -> None:
        self._cancel.set()
        try:
            self.lbl_detail.configure(text="Cancelling after current file…")
        except tk.TclError:
            pass

