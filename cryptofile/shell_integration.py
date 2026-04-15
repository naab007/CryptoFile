"""Windows context-menu registration under HKCU (no admin required).

Verbs (identical labels across file and folder targets so Explorer shows
the same entry for mixed multi-select):

* ``Encrypt with CryptoFile``  — on every file (``*\\shell``) and every
  folder (``Directory\\shell``). Folder target triggers a recursive walk.
* ``Decrypt with CryptoFile``  — on ``.lock`` files (``.lock\\shell``
  via the ``CryptoFile.Locked`` ProgID) and every folder. Folder target
  walks for ``.lock`` files.

We register into the current user's hive so installation works without admin
and uninstallation is complete (no leftover machine-wide keys). Delete is
safe — we only touch keys we created.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable

# Only import winreg on Windows; the module imports cleanly on other OSes
# so tests can run cross-platform without needing a mock.
if sys.platform == "win32":
    import winreg
else:
    winreg = None  # type: ignore[assignment]


ENCRYPT_VERB = "CryptoFile.Encrypt"
DECRYPT_VERB = "CryptoFile.Decrypt"
ENCRYPT_LABEL = "Encrypt with CryptoFile"
DECRYPT_LABEL = "Decrypt with CryptoFile"
LOCK_EXTENSION = ".lock"
FILETYPE_NAME = "CryptoFile.Locked"  # ProgID backing .lock files


def _require_winreg():
    if winreg is None:
        raise OSError(
            "shell integration is Windows-only (winreg unavailable on this OS)"
        )


def _shell_exe_path() -> str:
    """Path that Windows Explorer will invoke. In frozen (PyInstaller) mode
    that's the one-file exe; in dev we wrap ``pythonw.exe`` around a
    ``-m cryptofile`` invocation so the same logic runs."""
    if getattr(sys, "frozen", False):
        return sys.executable
    # Development mode: `pythonw path/to/cryptofile ...`.
    # The console-less pythonw avoids a flash window behind the GUI.
    pyw = Path(sys.executable).with_name("pythonw.exe")
    if not pyw.exists():
        pyw = Path(sys.executable)
    project_dir = Path(__file__).resolve().parent.parent
    return f'"{pyw}" "{project_dir / "cryptofile" / "__main__.py"}"'


def _command_line(action: str) -> str:
    exe = _shell_exe_path()
    if exe.startswith('"'):
        # Dev-mode composite; append args directly.
        return f'{exe} {action} "%1"'
    return f'"{exe}" {action} "%1"'


# ── State queries ─────────────────────────────────────────────────────────


def is_installed() -> bool:
    """True iff every one of our verbs is registered AND the exe path in
    the command still resolves to a real file.

    Checking path validity here means Settings correctly shows "not
    installed / reinstall" after the user moves the exe to a new
    location. Without this, is_installed() would say INSTALLED but every
    right-click would quietly launch nothing.
    """
    if winreg is None:
        return False
    required = (
        rf"Software\Classes\*\shell\{ENCRYPT_VERB}",
        rf"Software\Classes\{LOCK_EXTENSION}\shell\{DECRYPT_VERB}",
        rf"Software\Classes\Directory\shell\{ENCRYPT_VERB}",
        rf"Software\Classes\Directory\shell\{DECRYPT_VERB}",
    )
    try:
        for subkey in required:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey):
                pass
        # Verify the command line still points at an existing exe. Read
        # the encrypt verb's command; they all share the same exe path so
        # one sample is enough.
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            rf"Software\Classes\*\shell\{ENCRYPT_VERB}\command",
        ) as k:
            cmd, _ = winreg.QueryValueEx(k, None)
        exe_path = _extract_exe_path(cmd)
        return bool(exe_path and Path(exe_path).is_file())
    except FileNotFoundError:
        return False
    except OSError:
        return False


def _extract_exe_path(cmd: str) -> str | None:
    """Pull the exe path out of the registered command line.

    Handles two shapes we write:
      "C:\\path\\CryptoFile.exe" encrypt "%1"       ← frozen build
      "C:\\...\\pythonw.exe" "C:\\...\\__main__.py" encrypt "%1"  ← dev mode

    Returns the first quoted token in either case.
    """
    cmd = cmd.strip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        if end > 0:
            return cmd[1:end]
    # Fallback: first whitespace-delimited token (unquoted).
    return cmd.split(None, 1)[0] if cmd else None


# ── Install ───────────────────────────────────────────────────────────────


def install() -> None:
    """Register both verbs + a basic ProgID for .lock files.

    Idempotent — re-running replaces the stored command, which is what you
    want after moving the exe to a new path.
    """
    _require_winreg()

    encrypt_cmd = _command_line("encrypt")
    decrypt_cmd = _command_line("decrypt")

    # Encrypt verb on all files
    _write_verb(
        parent_subkey=r"Software\Classes\*\shell",
        verb=ENCRYPT_VERB,
        label=ENCRYPT_LABEL,
        command=encrypt_cmd,
    )

    # ProgID for .lock so the decrypt verb + nicer display work.
    # HKCU\Software\Classes\.lock\(default) = CryptoFile.Locked
    # HKCU\Software\Classes\CryptoFile.Locked\(default) = "Encrypted CryptoFile"
    _write_default(rf"Software\Classes\{LOCK_EXTENSION}", FILETYPE_NAME)
    _write_default(rf"Software\Classes\{FILETYPE_NAME}", "Encrypted CryptoFile")

    # Decrypt verb on .lock files
    _write_verb(
        parent_subkey=rf"Software\Classes\{LOCK_EXTENSION}\shell",
        verb=DECRYPT_VERB,
        label=DECRYPT_LABEL,
        command=decrypt_cmd,
    )
    # Also register under the ProgID (Explorer may prefer it over the
    # extension key depending on how the file was opened before).
    _write_verb(
        parent_subkey=rf"Software\Classes\{FILETYPE_NAME}\shell",
        verb=DECRYPT_VERB,
        label=DECRYPT_LABEL,
        command=decrypt_cmd,
    )

    # Folder verbs — same labels, same commands. The exe detects a folder
    # target and walks it recursively (see cryptofile.file_ops.expand_*).
    _write_verb(
        parent_subkey=r"Software\Classes\Directory\shell",
        verb=ENCRYPT_VERB,
        label=ENCRYPT_LABEL,
        command=encrypt_cmd,
    )
    _write_verb(
        parent_subkey=r"Software\Classes\Directory\shell",
        verb=DECRYPT_VERB,
        label=DECRYPT_LABEL,
        command=decrypt_cmd,
    )


def _write_verb(parent_subkey: str, verb: str, label: str, command: str) -> None:
    # Verb key: MUIVerb = display text
    with winreg.CreateKey(  # type: ignore[union-attr]
        winreg.HKEY_CURRENT_USER, rf"{parent_subkey}\{verb}"
    ) as k:
        winreg.SetValueEx(k, "MUIVerb", 0, winreg.REG_SZ, label)
        # Icon alongside the verb so menu entries get a lock glyph when the
        # exe has one. Falls back gracefully if the index doesn't exist.
        # BUG_HUNT_10 H-new-3 — single call to _shell_exe_path() plus
        # explicit helper for extraction. The previous one-liner called
        # _shell_exe_path() twice AND used split('"')[1] which raises
        # IndexError on an unquoted path containing a stray quote.
        raw_exe = _shell_exe_path()
        icon_src = _extract_exe_path(raw_exe) or raw_exe
        winreg.SetValueEx(k, "Icon", 0, winreg.REG_SZ, f'"{icon_src}",0')
    # Command subkey: default value = command line
    with winreg.CreateKey(  # type: ignore[union-attr]
        winreg.HKEY_CURRENT_USER, rf"{parent_subkey}\{verb}\command"
    ) as k:
        winreg.SetValueEx(k, None, 0, winreg.REG_SZ, command)


def _write_default(subkey: str, value: str) -> None:
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, subkey) as k:  # type: ignore[union-attr]
        winreg.SetValueEx(k, None, 0, winreg.REG_SZ, value)


# ── Uninstall ─────────────────────────────────────────────────────────────


def uninstall() -> None:
    """Remove every verb we registered. Safe to call if not installed."""
    _require_winreg()
    _delete_tree(rf"Software\Classes\*\shell\{ENCRYPT_VERB}")
    _delete_tree(rf"Software\Classes\{LOCK_EXTENSION}\shell\{DECRYPT_VERB}")
    _delete_tree(rf"Software\Classes\{FILETYPE_NAME}\shell\{DECRYPT_VERB}")
    _delete_tree(rf"Software\Classes\Directory\shell\{ENCRYPT_VERB}")
    _delete_tree(rf"Software\Classes\Directory\shell\{DECRYPT_VERB}")
    # Only remove the ProgID if it looks empty (we might share it across
    # re-installs but the only things under it are our verbs).
    _delete_key_if_empty(rf"Software\Classes\{FILETYPE_NAME}\shell")
    _delete_key_if_empty(rf"Software\Classes\{FILETYPE_NAME}")
    # We deliberately do NOT remove the HKCU\Software\Classes\.lock mapping —
    # another tool might be relying on the ProgID. The ProgID itself is
    # uniquely ours (CryptoFile.Locked), so removing that is our call; but
    # the extension → ProgID mapping could have been edited by the user.


def _delete_tree(subkey: str) -> None:
    """Delete a registry key and all its children under HKCU. No-op if absent.

    BUG_HUNT_10 L-new-4 — catch the broader ``OSError`` rather than only
    ``FileNotFoundError``. If another tool re-registered the key with a
    restrictive DACL (unlikely under HKCU but possible), OpenKey raises
    ``PermissionError`` (OSError subclass). Leaving uninstall half-done
    strands the user with a broken shell entry they can't self-fix.
    """
    try:
        with winreg.OpenKey(  # type: ignore[union-attr]
            winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_ALL_ACCESS,
        ) as k:
            # Enumerate subkeys; winreg changes indices as you delete, so
            # always query index 0 until it errors out.
            while True:
                try:
                    child = winreg.EnumKey(k, 0)
                except OSError:
                    break
                _delete_tree(rf"{subkey}\{child}")
    except FileNotFoundError:
        return
    except OSError:
        # Access denied or similar — log and move on. uninstall() should
        # remove what it CAN rather than aborting on the first problem key.
        return
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey)  # type: ignore[union-attr]
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _delete_key_if_empty(subkey: str) -> None:
    try:
        with winreg.OpenKey(  # type: ignore[union-attr]
            winreg.HKEY_CURRENT_USER, subkey
        ) as k:
            subkey_count, value_count, _ = winreg.QueryInfoKey(k)  # type: ignore[union-attr]
            if subkey_count == 0 and value_count == 0:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey)  # type: ignore[union-attr]
    except FileNotFoundError:
        return
