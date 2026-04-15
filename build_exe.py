"""PyInstaller driver — build a single-file CryptoFile.exe.

Run from the project root with the venv's pyinstaller::

    .venv\\Scripts\\pyinstaller.exe build_exe.py

Produces ``dist\\CryptoFile.exe`` (console-less; a tkinter-based GUI).
"""
from __future__ import annotations

import os
import PyInstaller.__main__
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def build() -> None:
    PyInstaller.__main__.run([
        # Use the top-level run.py shim rather than cryptofile/__main__.py
        # directly. Entry-script mode strips __package__, breaking every
        # relative import in the package — the shim imports the package
        # proper, which preserves them.
        str(ROOT / "run.py"),
        "--name", "CryptoFile",
        "--onefile",
        "--windowed",              # no console window; tk is the UI
        "--clean",
        "--noconfirm",
        "--specpath", str(ROOT / "build"),
        # Use dist-release if a running instance locks dist/CryptoFile.exe
        # (see feedback_pyinstaller_locked_exe.md). Override with
        # CRYPTOFILE_DIST env var for one-off builds.
        "--distpath", os.environ.get("CRYPTOFILE_DIST", str(ROOT / "dist")),
        "--workpath", str(ROOT / "build" / "work"),
        # Hidden imports that PyInstaller's static analysis sometimes misses.
        "--hidden-import", "argon2.low_level",
        "--hidden-import", "cryptography.hazmat.primitives.ciphers.aead",
    ])


if __name__ == "__main__":
    build()
