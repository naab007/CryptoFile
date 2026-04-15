"""Single-instance coordinator for multi-file context-menu invocations.

Windows Explorer's default behaviour when the user multi-selects files and
clicks a ``%1``-substituted verb is to launch the exe once per file. This
module funnels all those invocations into a single primary instance so the
user sees ONE password dialog and ONE progress window for the whole batch.

Mechanism
---------

1. Per-action lock file under ``%LOCALAPPDATA%\\CryptoFile\\`` held by
   ``msvcrt.locking`` (Windows) or ``fcntl.flock`` (anywhere else). The
   first process to grab the lock is the primary; later instances fail and
   become secondaries.
2. Primary binds ``127.0.0.1:0`` (OS-picked ephemeral port), writes the port
   number to a companion file ``<action>.port``, and starts a background
   thread that accepts connections.
3. Each secondary connects to that port, sends one JSON line
   ``{"path": "..."}``, closes, and exits.
4. Primary waits ``timeout_ms`` total (default 300 ms) for arrivals with an
   ``idle_ms`` reset (default 150 ms — any new arrival resets the idle clock)
   and then moves on with whatever it collected.
5. Server thread validates each arriving path (``Path.is_file()``) before
   queueing — a malicious local process can't inject a non-existent file.

Failure modes
-------------

* Lock file lingers after a crashed primary: secondaries that find a lock
  they can't acquire but no valid port file fall back to standalone
  single-file mode. The next clean run re-creates both files.
* Secondary's ``send_to_primary`` returns False if the primary window closed
  before it could connect; caller should fall back to single-file mode.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from . import _logging

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

_log = _logging.get("batch")

# Auth-token length (SECURITY_AUDIT_1 H2). 32 bytes → 64 hex chars; same
# entropy class as a TLS session cookie. Rotated on every new primary.
_TOKEN_BYTES = 32


ACTIONS = ("encrypt", "decrypt")


def _runtime_dir() -> Path:
    """Directory for this user's coordinator lock + port files.

    On Windows we use ``%LOCALAPPDATA%\\CryptoFile``; elsewhere ``~/.cache/CryptoFile``
    so tests can run cross-platform.
    """
    base = os.environ.get("LOCALAPPDATA")
    if base:
        d = Path(base) / "CryptoFile"
    else:
        d = Path.home() / ".cache" / "CryptoFile"
    d.mkdir(parents=True, exist_ok=True)
    return d


class BatchCoordinator:
    """Single-instance coordinator for one action (encrypt or decrypt)."""

    def __init__(self, action: str) -> None:
        if action not in ACTIONS:
            raise ValueError(f"action must be one of {ACTIONS}, got {action!r}")
        self.action = action
        self._dir = _runtime_dir()
        self.lock_path = self._dir / f"{action}.lock"
        self.port_path = self._dir / f"{action}.port"

        self._lock_fh = None  # stays open for the duration we hold the lock
        self._server_sock: Optional[socket.socket] = None
        self._server_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

        self._paths: list[Path] = []
        self._paths_lock = threading.Lock()
        self._last_arrival = 0.0
        # SECURITY_AUDIT_1 H2 — per-session auth token. Written to the
        # port file so only readers of that file (= same user, since it
        # lives under %LOCALAPPDATA%\CryptoFile\ which is per-user) can
        # connect. Rotated on every start_server() so a crashed primary
        # can't leave a replay window open for the next one.
        self._token: str = ""

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def try_become_primary(self) -> bool:
        """Grab the exclusive file lock. Returns False if another primary holds it."""
        try:
            self._lock_fh = open(self.lock_path, "a+b")
        except OSError:
            return False
        try:
            if sys.platform == "win32":
                # Non-blocking exclusive lock on one byte. Writes a byte at offset 0
                # if empty so there's something to lock.
                self._lock_fh.seek(0, os.SEEK_END)
                if self._lock_fh.tell() == 0:
                    self._lock_fh.write(b"\x00")
                    self._lock_fh.flush()
                self._lock_fh.seek(0)
                msvcrt.locking(self._lock_fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(self._lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._lock_fh.close()
            self._lock_fh = None
            return False
        return True

    def start_server(self) -> int:
        """Primary-only. Bind localhost, write port file, spawn accept thread.
        Returns the bound port."""
        if self._lock_fh is None:
            raise RuntimeError("start_server called without try_become_primary")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.listen(16)
        s.settimeout(0.1)  # accept() wakes every 100 ms so we can observe _stop
        self._server_sock = s

        # Rotate the auth token for this session (SECURITY_AUDIT_1 H2).
        self._token = secrets.token_hex(_TOKEN_BYTES)

        # M-new-4 — prime the idle clock from server-start time so a
        # caller that forgets to add_local_path() doesn't return
        # early with an empty list on the very first wait tick.
        self._last_arrival = time.monotonic()

        # Atomic port-file publish so secondaries never read a half-written
        # value. Format: ``<port>:<token_hex>\n``. The token is not a
        # secret in the crypto sense — it's a tamper-evident handle that
        # proves the connector can read our per-user file. A malicious
        # process running as a DIFFERENT local user can't read the token
        # (file lives under %LOCALAPPDATA%\CryptoFile\, per-user).
        tmp = self.port_path.with_name(self.port_path.name + ".tmp")
        tmp.write_text(f"{port}:{self._token}", encoding="utf-8")
        os.replace(tmp, self.port_path)
        _log.info(
            "coordinator primary start action=%s port=%d", self.action, port,
        )

        self._server_thread = threading.Thread(
            target=self._accept_loop, name=f"cryptofile-{self.action}-accept",
            daemon=True,
        )
        self._server_thread.start()
        return port

    def close(self) -> None:
        """Release server + lock + delete coordinator files. Idempotent."""
        _log.info("coordinator close action=%s", self.action)
        self._stop.set()
        if self._server_sock is not None:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
        if self._server_thread is not None:
            self._server_thread.join(timeout=1.5)
            self._server_thread = None
        for p in (self.port_path, self.lock_path):
            try:
                p.unlink()
            except OSError:
                pass
        if self._lock_fh is not None:
            try:
                if sys.platform == "win32":
                    try:
                        self._lock_fh.seek(0)
                        msvcrt.locking(self._lock_fh.fileno(), msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
                self._lock_fh.close()
            except OSError:
                pass
            self._lock_fh = None

    # ── Primary: accepting arrivals ────────────────────────────────────────

    def add_local_path(self, path: Path) -> None:
        """Add the primary's own file (the one it was invoked with)."""
        with self._paths_lock:
            self._paths.append(path)
            self._last_arrival = time.monotonic()

    def _accept_loop(self) -> None:
        assert self._server_sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_connection, args=(conn,), daemon=True,
            ).start()

    def _handle_connection(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(2.0)
            buf = bytearray()
            while b"\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                if len(buf) > 65536:
                    _log.warning("coordinator: oversize message rejected")
                    return  # refuse oversize (no response — secondary times out)
            try:
                msg = json.loads(buf.decode("utf-8").strip() or "{}")
            except json.JSONDecodeError:
                _log.warning("coordinator: non-JSON message rejected")
                return
            # SECURITY_AUDIT_1 H2 — require the per-session auth token.
            # A different-user process on the same box can't read our
            # per-user port file, so it can't learn this token.
            token = msg.get("token")
            if not isinstance(token, str) or not secrets.compare_digest(
                token, self._token,
            ):
                _log.warning(
                    "coordinator: auth-token mismatch, connection dropped",
                )
                return
            raw = msg.get("path")
            if not isinstance(raw, str):
                return
            path = Path(raw)
            # Validate: must be a real file we can stat. Ignores tamper attempts
            # that send nonexistent paths. ValueError catches paths with NUL
            # bytes or Windows-invalid chars that raise from the pathlib stat
            # call on some platforms.
            try:
                if not path.is_file():
                    return
            except (OSError, ValueError):
                return
            with self._paths_lock:
                self._paths.append(path)
                self._last_arrival = time.monotonic()
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def wait_for_collection(self, timeout_ms: int = 300, idle_ms: int = 150) -> list[Path]:
        """Block until ``idle_ms`` has passed since the last arrival, or
        ``timeout_ms`` total — whichever comes first. Returns collected paths,
        de-duplicated by resolved path."""
        start = time.monotonic()
        deadline = start + timeout_ms / 1000.0
        idle_s = idle_ms / 1000.0
        # Prime the idle clock from the primary's own arrival (add_local_path).
        while True:
            now = time.monotonic()
            if now >= deadline:
                break
            with self._paths_lock:
                last = self._last_arrival or start
            if (now - last) >= idle_s and (now - start) * 1000 >= idle_ms:
                break
            time.sleep(0.02)
        # Dedupe while preserving order.
        seen: set[str] = set()
        unique: list[Path] = []
        with self._paths_lock:
            for p in self._paths:
                try:
                    k = str(p.resolve())
                except OSError:
                    k = str(p)
                if k in seen:
                    continue
                seen.add(k)
                unique.append(p)
        return unique

    # ── Secondary: sending a path to the primary ───────────────────────────

    def send_to_primary(self, path: Path, timeout_s: float = 2.0) -> bool:
        """Connect to primary's port and send our path. Returns True on success,
        False if the primary's port file is missing or unreachable.

        Presents the per-session auth token from the port file
        (SECURITY_AUDIT_1 H2). If the file is in legacy ``<port>`` format
        (pre-1.0.7, shouldn't happen in practice since both ends upgrade
        together) we fall through to a tokenless attempt which the new
        primary will reject — secondary falls back to standalone.
        """
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if not self.port_path.exists():
                time.sleep(0.05)
                continue
            try:
                content = self.port_path.read_text(encoding="utf-8").strip()
                if ":" in content:
                    port_s, token = content.split(":", 1)
                else:
                    # Legacy format or corruption — no token available.
                    port_s, token = content, ""
                port = int(port_s)
            except (OSError, ValueError):
                time.sleep(0.05)
                continue
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1.0) as s:
                    payload = {"path": str(path), "token": token}
                    s.sendall(json.dumps(payload).encode("utf-8") + b"\n")
                return True
            except OSError:
                time.sleep(0.05)
                continue
        return False
