"""Daemon lifecycle + cross-process IPC (W01, CONTRACT §13.1).

v0.2 change: the daemon is a REAL separate process. The v0.1
process-local singleton is DELETED (not demoted to a default):
module-level ``status()`` / ``start()`` / ``stop()`` below are IPC
clients talking to a daemon started by any earlier CLI invocation.
A ``Daemon`` object still exists for in-process use and tests, but
it is never the CLI's daemon.

Rendezvous (how a later CLI finds the daemon):
  * Directory: ``$KEYHOLDER_DAEMON_DIR`` if set, else
    ``~/.keyholder/daemon``. Created 0700. It holds only
    ``control.sock`` (Unix, 0600), ``daemon.pid`` and, on Windows,
    ``control.port``. It holds NO session, token, PoP key, or key
    material of any kind.
  * Unix (Linux/macOS): Unix domain socket ``control.sock``.
  * Windows: loopback TCP on 127.0.0.1, ephemeral port, recorded in
    ``control.port`` (never 0.0.0.0, never a network address).
  * ``daemon start`` spawns and detaches the daemon process
    (``python -m keyholder.daemon --serve``), waits until the socket
    answers, and returns. ``daemon stop`` sends a stop command over
    IPC, which kills all sessions/workers first and then exits the
    daemon process. ``daemon status`` reports a daemon started by
    ANY earlier CLI invocation.

Protocol: newline-delimited JSON, one request and one reply per
connection: ``{"id", "cmd", "args"}`` ->
``{"id", "ok", "result"}`` or
``{"id", "ok": false, "error": {"code", "message"}}`` using the
v0.1 error codes (KH-xxxx). Commands: ``status``,
``sessions.list``, ``sessions.kill``, ``sessions.kill_all``,
``sessions.create`` (returns the token exactly once, over IPC only,
never logged, never written to disk), ``audit.verify``,
``doctor``, ``daemon.stop``, ``ping``. There is no approve command
anywhere in this module (CONTRACT §9); kill needs no auth.

Sessions are in-memory in the daemon only. Daemon death = session
death, never resurrection on restart: a restarted daemon starts
with zero sessions, and a token from a dead daemon resolves to
nothing. Orphan workers self-terminate <= 5 s after daemon loss:
workers poll the daemon PID (see supervisor.py) and exit when it
disappears; ``daemon stop`` additionally kills every worker
process group explicitly first.

Tier honesty (CONTRACT §10 / v3 §1A) — read this before citing
any of these controls: the socket directory (0700), the socket
(0600), and the peer-UID check below do NOT separate same-user
processes (Tier B). A process running as the same user can read
the socket directory and talk to the daemon. Only macOS keychain
access groups separate same-user processes, and they cannot be
proven on Linux. This daemon therefore claims Tier A separation
only for its socket, and ``doctor`` says so in plain words.
Peer-UID authentication (SO_PEERCRED on Linux, getpeereid on
macOS where available) is defence in depth against other-user
processes, not a Tier B control, and no file-stored control token
is added to paper over the Tier B limit (§13.1 forbids that fix).

audit.verify honesty: the daemon owns NO audit log (the AuditLog
needs an audit root + secret that no daemon in this slice is
given), so ``audit.verify`` over IPC returns KH-1005
(audit unavailable from the daemon). Inventing a verification
result for a log the daemon does not own would be a false claim;
wiring a real audit root into the daemon is manager work, not
something this module silently guesses at.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict
from pathlib import Path

from .broker import Broker, CreatedSession, SessionCreateError, SessionNotFound
from .sessions import (
    estimate_sleep_seconds as _estimate_sleep_seconds,
)
from .sessions import (
    sleep_aware_clock_name as _sleep_aware_clock_name,
)
from .sessions import (
    sleep_aware_monotonic as _sleep_aware_monotonic,
)
from .supervisor import Supervisor, WorkerAlreadyExists
from .types import (
    DaemonStatus,
    KillReceipt,
    Session,
    SessionClass,
    Transport,
)

MAX_REQUEST_BYTES = 1_048_576
CONNECTION_TIMEOUT_S = 10.0
START_WAIT_S = 10.0
STOP_WAIT_S = 5.0

TIER_B_NOTE = (
    "Tier B limit: this socket does NOT separate same-user processes. "
    "A process running as you can talk to the daemon; 0700/0600 "
    "permissions and peer-UID checks do not change that. Only macOS "
    "keychain access groups separate same-user processes."
)


class DaemonAlreadyRunning(Exception):
    pass


class DaemonNotRunning(Exception):
    pass


class DaemonError(Exception):
    """An IPC error carrying a CONTRACT §9 error code."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------- rendezvous


def daemon_dir() -> Path:
    """Rendezvous directory (0700). Env override exists so tests
    never touch the user's real daemon directory."""
    override = os.environ.get("KEYHOLDER_DAEMON_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".keyholder" / "daemon"


def _socket_path(directory: Path) -> Path:
    return directory / "control.sock"


def _pid_path(directory: Path) -> Path:
    return directory / "daemon.pid"


def _port_path(directory: Path) -> Path:
    return directory / "control.port"


def _log_path(directory: Path) -> Path:
    return directory / "daemon.log"


def _ensure_dir(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass  # Windows: chmod has no equivalent effect; loopback-only stands.


def _is_pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False
    except OSError:
        return False


def _read_pid(directory: Path) -> int | None:
    try:
        return int(_pid_path(directory).read_text().strip())
    except (OSError, ValueError):
        return None


def _read_port(directory: Path) -> int | None:
    try:
        return int(_port_path(directory).read_text().strip())
    except (OSError, ValueError):
        return None


def _use_unix_socket() -> bool:
    return sys.platform != "win32" and hasattr(socket, "AF_UNIX")


def _peer_uid(conn: socket.socket) -> tuple[int | None, bool]:
    """Peer UID for a Unix-socket connection, or (None, False).

    Linux: SO_PEERCRED (strict). macOS: getpeereid via libc where
    available. Anything else: not checked (the Tier B note applies
    regardless — this check never was the Tier B control).
    Returns (uid, checked).
    """
    if sys.platform == "win32":
        return None, False
    if hasattr(socket, "SO_PEERCRED"):
        try:
            raw = conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", raw)
            return int(uid), True
        except (OSError, struct.error):
            return None, False
    if sys.platform == "darwin":
        try:
            import ctypes

            libc = ctypes.CDLL(None, use_errno=True)
            euid = ctypes.c_uint32(0)
            egid = ctypes.c_uint32(0)
            rc = libc.getpeereid(conn.fileno(),
                                 ctypes.byref(euid), ctypes.byref(egid))
            if rc == 0:
                return int(euid.value), True
        except Exception:
            return None, False
    return None, False


def _session_dict(session: Session) -> dict:
    # asdict() of a Session contains identifiers and timestamps only;
    # tokens and PoP keys are never fields of Session (CONTRACT §2).
    return asdict(session)


def _receipt_dict(receipt: KillReceipt) -> dict:
    return asdict(receipt)


# ---------------------------------------------------------------- IPC client


class DaemonClient:
    """One-shot IPC client: one connection, one JSON line, one reply."""

    def __init__(self, directory: Path | None = None,
                 socket_path: Path | None = None) -> None:
        self.directory = directory if directory is not None else daemon_dir()
        self._socket_path = socket_path

    def _connect(self) -> socket.socket:
        if _use_unix_socket():
            path = self._socket_path or _socket_path(self.directory)
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.settimeout(CONNECTION_TIMEOUT_S)
            conn.connect(str(path))
            return conn
        port = _read_port(self.directory)
        if port is None:
            raise DaemonNotRunning("daemon is not running (no port file)")
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(CONNECTION_TIMEOUT_S)
        conn.connect(("127.0.0.1", port))
        return conn

    def request(self, cmd: str, args: dict | None = None) -> dict:
        """Send one request; return result or raise DaemonError /
        DaemonNotRunning. Never logs args (sessions.create args and
        results carry a token exactly once, over IPC only)."""
        try:
            conn = self._connect()
        except (OSError, DaemonNotRunning) as exc:
            if isinstance(exc, DaemonNotRunning):
                raise
            raise DaemonNotRunning(f"daemon is not running ({exc})") from exc
        with conn:
            payload = json.dumps(
                {"id": 1, "cmd": cmd, "args": args or {}}).encode() + b"\n"
            try:
                conn.sendall(payload)
                data = b""
                while b"\n" not in data and len(data) <= MAX_REQUEST_BYTES:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError as exc:
                raise DaemonNotRunning(
                    f"daemon connection failed ({exc})") from exc
            if not data:
                raise DaemonNotRunning("daemon closed the connection")
            try:
                reply = json.loads(data.decode())
            except ValueError as exc:
                raise DaemonError("KH-1006",
                                  f"malformed daemon reply: {exc}") from exc
        if reply.get("ok"):
            result = reply.get("result")
            return result if isinstance(result, dict) else {}
        error = reply.get("error") or {}
        raise DaemonError(str(error.get("code", "KH-1006")),
                          str(error.get("message", "daemon error")))


# ---------------------------------------------------------------- daemon


class Daemon:
    """A daemon instance: one Broker + one Supervisor, in memory.

    ``Daemon()`` with no directory is the in-process form used by
    v0.1 tests (ephemeral mkdtemp socket dir, server on a thread).
    The detached daemon process uses ``Daemon(directory, rendezvous
    =True)`` so later CLI invocations can find its socket/pid.
    """

    def __init__(self, directory: Path | None = None,
                 rendezvous: bool = False) -> None:
        self.supervisor = Supervisor()
        self.broker = Broker(supervisor=self.supervisor)
        self._running = False
        self._started_at: float | None = None
        self._detached = False  # set by serve_main for the real process
        self._rendezvous = rendezvous
        self._ephemeral = directory is None
        if directory is None:
            self._socket_dir = Path(tempfile.mkdtemp(prefix="keyholder-daemon-"))
        else:
            self._socket_dir = Path(directory)
            _ensure_dir(self._socket_dir)
        self._socket_path: str | None = None
        self._listener: socket.socket | None = None
        self._tcp_port: int | None = None
        self._accept_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._last_peer_checked: bool = False
        # -- clock/sleep section (W13, v0.2; IPC untouched) ----------
        # Optional SessionStore (W03) for wake-quarantine evaluation.
        # The broker path above is W01-owned: until W01 wires broker
        # sessions through this hook, these methods cover ONLY an
        # attached SessionStore and honestly report "wired": False
        # otherwise — they never pretend to quarantine broker sessions.
        self._session_store = None
        self._wake_quarantined = False

    # -- lifecycle ----------------------------------------------------
    def start(self) -> DaemonStatus:
        if self._running:
            raise DaemonAlreadyRunning("daemon already running")
        self._stop_event.clear()
        if _use_unix_socket():
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            path = _socket_path(self._socket_dir)
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
            listener.bind(str(path))
            listener.listen(5)
            listener.settimeout(0.2)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            self._listener = listener
            self._socket_path = str(path)
        else:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listener.listen(5)
            listener.settimeout(0.2)
            self._listener = listener
            self._tcp_port = listener.getsockname()[1]
            self._socket_path = f"127.0.0.1:{self._tcp_port}"
            if self._rendezvous:
                try:
                    _port_path(self._socket_dir).write_text(str(self._tcp_port))
                    os.chmod(_port_path(self._socket_dir), 0o600)
                except OSError:
                    pass
        if self._rendezvous:
            try:
                _pid_path(self._socket_dir).write_text(str(os.getpid()))
                os.chmod(_pid_path(self._socket_dir), 0o600)
            except OSError:
                pass
        self._running = True
        self._started_at = time.time()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        return self.status()

    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self._stop_event.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            handler = threading.Thread(
                target=self._handle_connection, args=(conn,), daemon=True)
            handler.start()

    def _handle_connection(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(CONNECTION_TIMEOUT_S)
            peer_uid, peer_checked = _peer_uid(conn)
            self._last_peer_checked = peer_checked
            # Peer-UID enforcement (Linux/macOS Unix sockets only):
            # another user's process is refused, generically.
            if peer_checked and peer_uid is not None \
                    and peer_uid != os.getuid():
                self._send_reply(conn, 0, None, "KH-3002",
                                 "peer UID does not match daemon owner")
                return
            data = b""
            try:
                while b"\n" not in data:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > MAX_REQUEST_BYTES:
                        self._send_reply(conn, 0, None, "KH-2001",
                                         "request too large")
                        return
            except OSError:
                return
            try:
                request = json.loads(data.decode() or "{}")
            except (ValueError, UnicodeDecodeError):
                self._send_reply(conn, 0, None, "KH-2001",
                                 "malformed JSON request")
                return
            req_id = request.get("id", 0)
            cmd = request.get("cmd")
            args = request.get("args") or {}
            if not isinstance(args, dict):
                self._send_reply(conn, req_id, None, "KH-2001",
                                 "args must be an object")
                return
            try:
                result = self._dispatch(cmd, args)
            except DaemonError as exc:
                self._send_reply(conn, req_id, None, exc.code, exc.message)
                return
            except Exception as exc:  # never crash the server on a bad cmd
                self._send_reply(conn, req_id, None, "KH-1006",
                                 f"daemon error: {exc}")
                return
            # NOTE: no logging of request or result here — a
            # sessions.create result carries the token exactly once
            # and must never reach a log file.
            self._send_reply(conn, req_id, result, None, None)
            if cmd == "daemon.stop":
                self._schedule_shutdown()

    @staticmethod
    def _send_reply(conn: socket.socket, req_id, result,
                    code: str | None, message: str | None) -> None:
        if code is None:
            payload = {"id": req_id, "ok": True, "result": result}
        else:
            payload = {"id": req_id, "ok": False,
                       "error": {"code": code, "message": message or code}}
        try:
            conn.sendall(json.dumps(payload).encode() + b"\n")
        except OSError:
            pass

    def _schedule_shutdown(self) -> None:
        """After the stop reply is sent, tear down and exit.

        Detached daemon process: exit the process outright so
        ``daemon stop`` is verifiably dead, not just quiet. In-process
        daemon: local stop only (never os._exit inside a test host).
        """
        def _shutdown() -> None:
            time.sleep(0.2)
            try:
                self.stop()
            except Exception:
                pass
            if self._detached:
                os._exit(0)

        threading.Thread(target=_shutdown, daemon=True).start()

    def _dispatch(self, cmd, args: dict) -> dict:
        if cmd == "status":
            return self._status_dict()
        if cmd == "ping":
            return {"ok": True}
        if cmd == "sessions.list":
            return {"sessions": [ _session_dict(s)
                                  for s in self.broker.list_sessions()]}
        if cmd == "sessions.create":
            try:
                created = self.broker.create_session(
                    key_id=args["key_id"], provider=args["provider"],
                    session_class=args["session_class"],
                    transport=args.get("transport", "absolute"),
                    process_group=args.get("process_group", ""),
                    ancestry=args.get("ancestry", ""),
                    requested_ttl_s=args.get("requested_ttl_s"),
                    idle_timeout_s=args.get("idle_timeout_s"),
                    port=args.get("port"))
            except KeyError as exc:
                raise DaemonError("KH-2001",
                                  f"missing session field: {exc}") from exc
            except SessionCreateError as exc:
                raise DaemonError("KH-2001", str(exc)) from exc
            except WorkerAlreadyExists as exc:
                raise DaemonError("KH-2001", str(exc)) from exc
            # Token returned exactly once, over IPC only.
            return {"session": _session_dict(created.session),
                    "token": created.token}
        if cmd == "sessions.kill":
            session_id = args.get("session_id")
            if not session_id:
                raise DaemonError("KH-2001", "session_id is required")
            try:
                receipt = self.broker.kill_session(session_id)
            except SessionNotFound:
                raise DaemonError("KH-1002",
                                  "session not found/expired/killed") from None
            return {"receipt": _receipt_dict(receipt)}
        if cmd == "sessions.kill_all":
            result = self.broker.kill_all()
            return {"snapshot": result["snapshot"],
                    "receipts": {sid: _receipt_dict(r)
                                 for sid, r in result["receipts"].items()},
                    "created_during_sweep": result["created_during_sweep"]}
        if cmd == "audit.verify":
            # Honest unavailable: this daemon owns no audit log; see
            # the module docstring. Never fabricate a verification.
            raise DaemonError(
                "KH-1005",
                "audit unavailable from the daemon: the daemon owns no "
                "audit log in this slice; verify through the audit "
                "module's own root, not over daemon IPC")
        if cmd == "doctor":
            return self._doctor_dict()
        if cmd == "daemon.stop":
            return {"stopped": True,
                    "session_count": len(self.broker.list_sessions())}
        raise DaemonError("KH-2001", f"unknown command: {cmd!r}")

    def _status_dict(self) -> dict:
        return {
            "running": self._running,
            "pid": os.getpid() if self._running else None,
            "socket_path": self._socket_path,
            "session_count": len(self.broker.list_sessions()),
            "started_at": self._started_at,
            "loopback_only": True,
            "transport": "unix" if _use_unix_socket() else "tcp-loopback",
            "peer_uid_checked": self._last_peer_checked,
            "tier_b_note": TIER_B_NOTE,
        }

    def _doctor_dict(self) -> dict:
        directory = self._socket_dir
        try:
            dir_mode = oct(os.stat(directory).st_mode & 0o777)
        except OSError:
            dir_mode = "unknown"
        socket_mode: str = "unknown"
        if _use_unix_socket() and self._socket_path:
            try:
                socket_mode = oct(
                    os.stat(self._socket_path).st_mode & 0o777)
            except OSError:
                socket_mode = "unknown"
        return {
            "running": self._running,
            "pid": os.getpid() if self._running else None,
            "platform": sys.platform,
            "transport": "unix" if _use_unix_socket() else "tcp-loopback",
            "loopback_only": True,
            "socket_dir": str(directory),
            "socket_dir_mode": dir_mode,
            "socket_mode": socket_mode,
            "socket_path": self._socket_path,
            "peer_uid_checked": self._last_peer_checked,
            "session_count": len(self.broker.list_sessions()),
            "worker_count": len(self.supervisor.live_workers()),
            "sessions_in_memory_only": True,
            "tier_b_note": TIER_B_NOTE,
            "git_push_note": "git pushes bypass the broker manifest and "
                             "are NOT logged/gated unless the git "
                             "helper/wrapper (W05, v0.2) is used",
        }

    def status(self) -> DaemonStatus:
        return DaemonStatus(
            running=self._running,
            pid=os.getpid() if self._running else None,
            socket_path=self._socket_path,
            session_count=len(self.broker.list_sessions()),
            started_at=self._started_at,
            loopback_only=True,
        )

    def stop(self) -> DaemonStatus:
        if not self._running:
            raise DaemonNotRunning("daemon is not running")
        self._stop_event.set()
        try:
            if self._listener is not None:
                self._listener.close()
        except OSError:
            pass
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2.0)
        # Kill-all first, then drop all in-memory state: no session
        # survives stop, so a later start cannot resurrect anything.
        try:
            self.broker.kill_all()
        finally:
            self.broker.shutdown()
        socket_dir = self._socket_dir
        self._running = False
        self._started_at = None
        self._socket_path = None
        self._tcp_port = None
        if self._rendezvous:
            for path in (_socket_path(socket_dir), _pid_path(socket_dir),
                         _port_path(socket_dir)):
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            # Keep the rendezvous directory itself (0700) for the
            # next start; only its rendezvous files are removed.
        elif self._ephemeral:
            try:
                _socket_path(socket_dir).unlink(missing_ok=True)
                socket_dir.rmdir()
            except OSError:
                pass
        return self.status()

    # -- session surface (delegates to the broker, in-process only) --
    def create_session(self, *, key_id: str, provider: str,
                       session_class: SessionClass,
                       transport: Transport = "absolute",
                       process_group: str = "",
                       ancestry: str = "",
                       requested_ttl_s: int | None = None,
                       idle_timeout_s: int | None = None,
                       port: int | None = None) -> CreatedSession:
        if not self._running:
            raise DaemonNotRunning("daemon is not running")
        return self.broker.create_session(
            key_id=key_id, provider=provider,
            session_class=session_class, transport=transport,
            process_group=process_group, ancestry=ancestry,
            requested_ttl_s=requested_ttl_s,
            idle_timeout_s=idle_timeout_s, port=port)

    def kill_session(self, session_id: str) -> KillReceipt:
        return self.broker.kill_session(session_id)

    def kill_all(self) -> dict:
        return self.broker.kill_all()

    def list_sessions(self) -> list[Session]:
        return self.broker.list_sessions()

    # -- clock/sleep section (W13, v0.2; IPC untouched) --------------
    # Sleep-aware clock naming lives in sessions.py (v3 N-F1):
    # Linux CLOCK_BOOTTIME, macOS mach_continuous_time as design
    # only. Nothing here changes start/stop/status, the accept loop,
    # or the IPC dispatch table (all W01).
    def attach_session_store(self, store) -> None:
        """Attach a W03 SessionStore so wake evaluation acts on it.
        In-process only; the detached daemon's broker sessions are
        covered only once W01 wires them through this hook."""
        self._session_store = store

    @staticmethod
    def sleep_clock_name() -> str:
        return _sleep_aware_clock_name()

    @staticmethod
    def sleep_aware_now() -> float:
        return _sleep_aware_monotonic()

    @staticmethod
    def estimate_sleep_seconds(
        wall_before: float, wall_after: float,
        mono_before: float, mono_after: float,
    ) -> float:
        return _estimate_sleep_seconds(
            wall_before, wall_after, mono_before, mono_after)

    def enter_wake_quarantine(self, reason: str = "wake") -> dict:
        """Quarantine on wake: refuse everything until evaluation
        completes (v3 N-F2). Delegates to the attached store when
        present; otherwise records only a daemon-level flag and says
        so — it does NOT claim broker sessions are quarantined."""
        if self._session_store is not None:
            self._session_store.begin_wake_quarantine(reason=reason)
            return {"wired": True, "quarantined": True, "reason": reason}
        self._wake_quarantined = True
        return {
            "wired": False,
            "quarantined": True,
            "reason": reason,
            "note": "no SessionStore attached; broker sessions are NOT "
            "quarantined by this flag — W01 wiring pending",
        }

    def evaluate_wake(self, sleep_seconds: float,
                      now_wall: float | None = None) -> dict:
        """Evaluate a wake event after quarantine. Delegates to the
        attached store when present; otherwise reports unevaluated
        for broker sessions rather than inventing an outcome."""
        now = time.time() if now_wall is None else float(now_wall)
        if self._session_store is not None:
            ev = self._session_store.evaluate_wake(
                float(sleep_seconds), now_wall=now)
            self._wake_quarantined = False
            return {
                "wired": True,
                "action": ev.action,
                "killed": ev.killed_session_ids,
                "suspended": ev.suspended_session_ids,
                "sleep_seconds": ev.sleep_seconds,
            }
        self._wake_quarantined = False
        return {
            "wired": False,
            "action": "unevaluated",
            "sleep_seconds": float(sleep_seconds),
            "note": "no SessionStore attached; broker sessions were NOT "
            "evaluated — W01 wiring pending",
        }


# ------------------------------------------------- module-level IPC API
# These are what the CLI calls (keyholder.cli._load_daemon). They are
# IPC clients to the detached daemon process — NOT a process-local
# singleton. The v0.1 singleton is deleted per CONTRACT §13.1.


def _cleanup_stale(directory: Path) -> None:
    """Remove rendezvous files for a dead daemon so a fresh start
    can proceed. Never kills a live PID (pid reuse is not assumed)."""
    pid = _read_pid(directory)
    if pid is not None and _is_pid_alive(pid):
        return
    for path in (_socket_path(directory), _pid_path(directory),
                 _port_path(directory)):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def _package_root() -> Path:
    return Path(__file__).resolve().parent.parent


def status() -> DaemonStatus:
    """Status of the daemon started by ANY earlier CLI invocation;
    running=False when no daemon answers (never a local singleton)."""
    directory = daemon_dir()
    try:
        result = DaemonClient(directory).request("status")
    except (DaemonNotRunning, DaemonError, OSError):
        return DaemonStatus(running=False, pid=None,
                            socket_path=str(_socket_path(directory))
                            if _use_unix_socket() else None,
                            session_count=0, started_at=None,
                            loopback_only=True)
    return DaemonStatus(
        running=bool(result.get("running")),
        pid=result.get("pid"),
        socket_path=result.get("socket_path"),
        session_count=int(result.get("session_count") or 0),
        started_at=result.get("started_at"),
        loopback_only=True)


def start() -> DaemonStatus:
    """Spawn and detach the daemon process, then wait for its socket.

    Raises DaemonAlreadyRunning if a live daemon already answers.
    Raises DaemonError(KH-1006) if the spawned daemon does not come
    up within START_WAIT_S (its log is daemon.log in the rendezvous
    directory; it never contains a token).
    """
    directory = daemon_dir()
    _ensure_dir(directory)
    _cleanup_stale(directory)
    try:
        live = DaemonClient(directory).request("status")
        if live.get("running"):
            raise DaemonAlreadyRunning(
                f"daemon already running (pid {live.get('pid')})")
    except DaemonNotRunning:
        pass
    env = dict(os.environ)
    env["PYTHONPATH"] = str(_package_root()) + os.pathsep + env.get(
        "PYTHONPATH", "")
    # Detached: the daemon must outlive this CLI process. Its stdio
    # goes to daemon.log (never a token: the server logs nothing
    # about requests or results).
    log_handle = open(_log_path(directory), "ab")
    cmd = [sys.executable, "-m", "keyholder.daemon", "--serve",
           "--dir", str(directory)]
    popen_kwargs: dict = {
        "cwd": str(_package_root()), "env": env,
        "stdin": subprocess.DEVNULL,
        "stdout": log_handle, "stderr": subprocess.STDOUT,
        "close_fds": True,
    }
    if sys.platform != "win32":
        popen_kwargs["start_new_session"] = True
    else:
        popen_kwargs["creationflags"] = (
            getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    proc = subprocess.Popen(cmd, **popen_kwargs)
    deadline = time.monotonic() + START_WAIT_S
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            result = DaemonClient(directory).request("status")
            if result.get("running"):
                return DaemonStatus(
                    running=True, pid=result.get("pid"),
                    socket_path=result.get("socket_path"),
                    session_count=int(result.get("session_count") or 0),
                    started_at=result.get("started_at"),
                    loopback_only=True)
        except (DaemonNotRunning, DaemonError, OSError) as exc:
            last_exc = exc
        time.sleep(0.1)
    raise DaemonError(
        "KH-1006",
        "daemon did not come up within "
        f"{START_WAIT_S}s (spawn exit={proc.poll()}; last error={last_exc}; "
        f"see {_log_path(directory)})")


def stop() -> DaemonStatus:
    """Stop the cross-process daemon: IPC stop kills all sessions
    and workers, then the daemon process exits. Raises
    DaemonNotRunning when no daemon answers."""
    directory = daemon_dir()
    try:
        DaemonClient(directory).request("daemon.stop")
    except DaemonNotRunning:
        raise
    except DaemonError as exc:
        # A daemon that answered stop but died mid-reply is still a
        # stop; anything else is a real failure.
        raise DaemonError(exc.code, exc.message) from exc
    deadline = time.monotonic() + STOP_WAIT_S
    while time.monotonic() < deadline:
        pid = _read_pid(directory)
        if pid is None:
            break
        if not _is_pid_alive(pid):
            break
        time.sleep(0.1)
    return DaemonStatus(running=False, pid=None, socket_path=None,
                        session_count=0, started_at=None,
                        loopback_only=True, sessions_killed=True)


# ---------------------------------------------------------------- serve


def serve_main(directory: Path) -> int:
    """Detached daemon process entry point."""
    _ensure_dir(directory)
    daemon = Daemon(directory, rendezvous=True)
    daemon._detached = True
    daemon.start()

    def _on_signal(signum, _frame):
        try:
            daemon.stop()
        except Exception:
            pass
        raise SystemExit(0)

    if sys.platform != "win32":
        signal.signal(signal.SIGTERM, _on_signal)
        signal.signal(signal.SIGINT, _on_signal)
    try:
        while daemon.status().running:
            time.sleep(0.2)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        try:
            daemon.stop()
        except Exception:
            pass
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="keyholder.daemon")
    parser.add_argument("--serve", action="store_true",
                        help="run as the detached daemon process")
    parser.add_argument("--dir", default=None,
                        help="rendezvous directory (default: daemon_dir())")
    args = parser.parse_args(argv)
    if not args.serve:
        print("keyholder.daemon: use --serve to run the daemon process, "
              "or the Daemon class / module functions for IPC",
              file=sys.stderr)
        return 2
    directory = Path(args.dir).expanduser() if args.dir else daemon_dir()
    return serve_main(directory)


if __name__ == "__main__":
    raise SystemExit(main())
