"""Rotating-file logger for CryptoFile (1.0.7).

Writes to ``%LOCALAPPDATA%\\CryptoFile\\logs\\cryptofile.log`` with
rotation at ~5 MB / 3 backups. On non-Windows platforms falls back to
``~/.cache/CryptoFile/logs/`` so the module can be imported for tests
on Linux / macOS CI.

Design rules (strict — see ``docs/SECURITY.md`` §Logging):

* **Never log passwords, plaintext bytes, or ciphertext bytes.**
* **Never log paths outside the current user's profile.** We only accept
  ``Path`` objects and log the basename — the full path of a file
  the user owns is already hygienic-enough but bulk logs containing
  ``C:\\Users\\alice\\...\\secret.docx`` would be a privacy concern if
  the log ever leaked. Basenames only.
* Single source of truth: call :func:`configure` once per process at
  startup; subsequent calls are idempotent.
* Fail-soft: if the log directory can't be created (read-only profile,
  locked disk), degrade to a no-op logger rather than crashing the
  encryption flow.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional

_MAX_BYTES = 5 * 1024 * 1024   # ~5 MiB per file
_BACKUP_COUNT = 3
_LOGGER_NAME = "cryptofile"
_configured = False


def _log_dir() -> Path:
    """Per-user log directory — always under the user's profile."""
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / "CryptoFile" / "logs"
    return Path.home() / ".cache" / "CryptoFile" / "logs"


def configure(level: int = logging.INFO) -> logging.Logger:
    """Install the rotating file handler (idempotent). Returns the root
    CryptoFile logger.

    Fail-soft: on any OSError setting up the handler (read-only profile,
    locked disk, AV mid-scan), we fall back to a silent NullHandler. The
    app functions; we just lose log visibility for that run.
    """
    global _configured
    logger = logging.getLogger(_LOGGER_NAME)
    if _configured:
        return logger
    logger.setLevel(level)
    logger.propagate = False
    try:
        d = _log_dir()
        d.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = logging.handlers.RotatingFileHandler(
            d / "cryptofile.log",
            maxBytes=_MAX_BYTES,
            backupCount=_BACKUP_COUNT,
            encoding="utf-8",
            delay=True,
        )
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)
    except OSError:
        logger.addHandler(logging.NullHandler())
    _configured = True
    return logger


def get(child: Optional[str] = None) -> logging.Logger:
    """Fetch a child logger (``cryptofile.<child>``). Safe to call before
    ``configure()`` — the logger will just not emit anywhere useful."""
    if child:
        return logging.getLogger(f"{_LOGGER_NAME}.{child}")
    return logging.getLogger(_LOGGER_NAME)


def safe_name(path_or_str) -> str:
    """Return ONLY the basename of a path-like — never the full path.

    Use this everywhere a path would otherwise be logged. Keeps logs
    hygienic even if they later get shared with the developer for
    debugging.
    """
    try:
        return Path(str(path_or_str)).name or "<anonymous>"
    except (TypeError, ValueError):
        return "<invalid>"
