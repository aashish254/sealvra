"""Daemon lifecycle + cross-process IPC (W01, CONTRACT §13.1).

v0.2 change: the daemon is a REAL separate process. The v0.1
process-local singleton is DELETED (not demoted to a default):
module-level ``status()`` / ``start()`` / ``stop()`` below are IPC
clients talking to a daemon started by any earlier CLI invocation.
A ``Daemon`` object still exists for in-process use and tests, but
it is never the CLI's daemon.

Rendezvous (how a later CLI finds the daemon):
  * Directory: ``$SEALVRA_DAEMON_DIR`` if set, else
    ``~/.sealvra/daemon``. Created 0700. It holds only
    ``control.sock`` (Unix, 0600), ``daemon.pid`` and, on Windows,
    ``control.port``. It holds NO session, token, PoP key, or key
    material of any kind.
  * Unix (Linux/macOS): Unix domain socket ``control.sock``.
  * Windows: loopback TCP on 127.0.0.1, ephemeral port, recorded in
    ``control.port`` (never 0.0.0.0, never a network address).
  * ``daemon start`` spawns and detaches the daemon process
    (``python -m sealvra.daemon --serve``), waits until the socket
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
never logged, never written to disk; in test mode only it also returns
the PoP key minted by that same call -- CONTRACT section 4 permits
pipe/FD delivery, and no command can retrieve the credential of a
session the caller did not just mint), ``audit.verify``,
``audit.list`` (read-only tail of the live segment, closed-schema
fields only), ``vault.list`` (authenticated vault headers: id,
provider, label, 12-hex fingerprint, rotation state, the derived audit
pseudonym -- never a key value), ``packs.status`` (per-provider load state from the real
loader, trust-root key ids), ``doctor``, ``daemon.stop``, ``ping``.
The last four are read-only projections of what ``sealvra keys list``,
``sealvra audit`` and ``sealvra doctor`` already print; they add no
decision, no logging and no approval surface. There is no approve
command anywhere in this module (CONTRACT §9); kill needs no auth.

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

audit.verify honesty (v0.2, Phase 1): verification is a read-only
operation over the conventional audit root (``$SEALVRA_AUDIT_ROOT``,
else ``~/.sealvra``) that ``sealvra.audit`` resolves identically for
the CLI and for this daemon, so ``audit.verify`` over IPC now runs the
real hash-chain verifier and returns its status and CONTRACT section 8
exit code (OK 0, UNANCHORED 2, TAMPERED 3, MISSING-DIRECTORY 3). It
needs no pseudonym secret, because the chain hash does not use the
secret. When nothing has been written to that root the honest answer is
MISSING-DIRECTORY, which is reported as such rather than as a pass.

Proxy serving (v0.2, Phase 1): a detached daemon built with
``serve_proxy=True`` composes the real object graph from
``sealvra.runtime`` and listens on the proxy port. If that
composition fails -- an unmade owner decision (OD-12 wrapping-key
source), an unverified pack, a mock base missing in test mode -- the
failure is recorded, printed to stderr at start, and shown by
``daemon status`` as ``proxy.not_served_reason``. The daemon keeps
serving IPC so key and session commands stay usable; an unwired proxy
is never reported as a working broker.

Expiry sweep (v0.2, Phase 1): one background thread per running daemon
calls ``Broker.reap_expired`` every ``EXPIRY_SWEEP_INTERVAL_S`` seconds.
CONTRACT §3 says a session TERMINATES at its TTL or idle deadline; the
token denying on the next call is only half of that. The other half is
the worker process and the one-live-worker-per-key claim it holds, so
without the sweep an expired session strands its compartment until the
daemon restarts. Two views then differ, on purpose: ``sessions.list``
over IPC is the RECORD view (a killed session is still there, with
``killed`` set -- what the GUI reads), while ``session_count`` and
``sealvra sessions list`` are the LIVE view, because a terminated
session in an operator's list claims a dead token still works.
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

from . import audit as audit_module
from . import packs as packs_module
from . import runtime
from . import vault as vault_module
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
# Expiry sweep period. CONTRACT §3 makes expiry a TERMINATION, not a
# flag: the worker process must die and the compartment must be free for
# re-issuance. Nothing else drives that, so this is the daemon's own
# heartbeat; a session is torn down within one interval of its deadline
# (well inside the §3 <= 5 s teardown bound).
EXPIRY_SWEEP_INTERVAL_S = 1.0

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
    override = os.environ.get("SEALVRA_DAEMON_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".sealvra" / "daemon"


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


# ---------------------------------------------------------------- read-only
# IPC projections for the GUI (audit tail, vault headers, pack status).
# Every one of these is a READ of state the CLI can already print, over
# the same socket, with the same peer-UID check. None of them decides,
# logs, approves or kills anything.


def _pseudonym_or_blank(identifier: str) -> str:
    """The audit pseudonym for ``identifier``, or "" if unavailable.

    Uses the runtime's own accessor, which refuses a group/world
    readable secret file rather than deriving from it. A blank here is
    honest: the GUI then shows "—" for that column instead of inventing
    a link it cannot prove. It never falls back to echoing a key id or
    a session id, because that would put an internal identifier in a
    field the log reserves for pseudonyms.
    """
    if not identifier:
        return ""
    try:
        # Read-only: derive from an existing secret, never create one.
        # audit_secret() would mint a file on first use, and a listing
        # command must not have side effects on the audit root.
        raw = os.environ.get(runtime.AUDIT_SECRET_FILE_ENV, "")
        path = Path(raw).expanduser() if raw else (
            runtime.audit_root() / "audit_secret")
        if not path.exists():
            return ""
        return audit_module.pseudonym(runtime.audit_secret(),
                                      identifier)
    except Exception:
        return ""


def _with_pseudonyms(entry: dict) -> dict:
    """Attach the derived log pseudonyms to one ``sessions.list`` row.

    ``types.Session`` carries no pseudonym fields, so this is the only
    place they can be added, and they are added as DERIVED values from
    the same secret the writer uses -- the token and the PoP key are
    never touched. Callers that do not read these keys are unaffected.
    """
    session_id = entry.get("session_id") or ""
    key_id = entry.get("key_id") or ""
    if session_id and not entry.get("session_pseudonym"):
        entry["session_pseudonym"] = _pseudonym_or_blank(session_id)
    if key_id and not entry.get("key_pseudonym"):
        entry["key_pseudonym"] = _pseudonym_or_blank(key_id)
    return entry


AUDIT_TAIL_MAX_ENTRIES = 500
AUDIT_TAIL_MAX_BYTES = 4 * 1024 * 1024


def _audit_tail(limit: int) -> list[dict]:
    """The last ``limit`` live-segment entries, schema fields only.

    Deliberately dumb and deliberately narrow: it opens the one live
    segment under the conventional audit root (the same root
    ``audit.verify`` resolves; the layout is ``AuditLog``'s documented
    ``root/audit/audit.jsonl``), reads its tail, and projects
    ``audit.SCHEMA_FIELDS``. A field outside that closed schema is
    dropped, so nothing not-yet-in-the-schema can leave through this
    command, and the pseudonyms in the file are what the log already
    holds -- no secret is hashed or named here.
    """
    count = max(1, min(int(limit or 1), AUDIT_TAIL_MAX_ENTRIES))
    live = audit_module.default_audit_root() / "audit" / "audit.jsonl"
    try:
        size = live.stat().st_size
    except OSError:
        return []
    try:
        with live.open("rb") as handle:
            if size > AUDIT_TAIL_MAX_BYTES:
                handle.seek(size - AUDIT_TAIL_MAX_BYTES)
            data = handle.read()
    except OSError:
        return []
    lines = data.splitlines()
    if size > AUDIT_TAIL_MAX_BYTES and lines:
        lines = lines[1:]  # first line is partial after a mid-line seek
    entries: list[dict] = []
    for line in lines[-count:]:
        try:
            record = json.loads(line.decode())
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(record, dict):
            continue
        entries.append({name: record.get(name)
                        for name in audit_module.SCHEMA_FIELDS})
    return entries


def _packs_status_dict() -> dict:
    """Per-provider pack state, from the real loader (hash + signature).

    A refused pack reports its refusal. The trust root is named by key
    id only -- public ids, and the private half is destroyed (rotate
    only), so there is nothing secret to disclose here.
    """
    directory = runtime.packs_dir()
    out: dict = {"packs_dir": str(directory), "packs": [], "trust_root": {}}
    trust_path = directory / packs_module.TRUSTED_KEYS_FILENAME
    try:
        out["trust_root"] = {"path": str(trust_path),
                             "key_ids": sorted(packs_module.load_trusted_keys(
                                 trust_path))}
    except Exception as exc:
        out["trust_root"] = {"path": str(trust_path), "error": str(exc)}
    for provider in ("github", "gemini"):
        path = directory / f"{provider}.json"
        entry: dict = {"provider": provider, "file": str(path)}
        try:
            pack = packs_module.load_pack(path)
            signer = ""
            try:
                envelope = json.loads(
                    path.with_suffix(".sig").read_text(encoding="utf-8"))
                signer = str(envelope.get("key_id", ""))
            except Exception:
                signer = "(signature file unreadable)"
            entry.update({
                "loaded": True,
                "version": pack.version,
                "issued_at": str(pack.raw.get("issued_at", "")),
                "content_sha256": str(pack.raw.get("content_sha256", ""))[:12],
                "signer_key_id": signer,
                "endpoint_rules": len(pack.endpoints),
            })
        except Exception as exc:
            entry.update({"loaded": False,
                          "error": f"{type(exc).__name__}: {exc}"})
        out["packs"].append(entry)
    return out


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
                 rendezvous: bool = False,
                 serve_proxy: bool = False) -> None:
        self.supervisor = Supervisor()
        self.broker = Broker(supervisor=self.supervisor)
        self.serve_proxy = serve_proxy
        # Composition-root state (see the module docstring): either a
        # live Runtime or an honest reason there is none.
        self.runtime: runtime.Runtime | None = None
        self.runtime_error: str | None = None
        self.proxy_port: int | None = None
        self._running = False
        self._started_at: float | None = None
        self._detached = False  # set by serve_main for the real process
        self._rendezvous = rendezvous
        self._ephemeral = directory is None
        if directory is None:
            self._socket_dir = Path(tempfile.mkdtemp(prefix="sealvra-daemon-"))
        else:
            self._socket_dir = Path(directory)
            _ensure_dir(self._socket_dir)
        self._socket_path: str | None = None
        self._listener: socket.socket | None = None
        self._tcp_port: int | None = None
        self._accept_thread: threading.Thread | None = None
        self._expiry_thread: threading.Thread | None = None
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
        self._expiry_thread = threading.Thread(
            target=self._expiry_loop, name="sealvra-expiry", daemon=True)
        self._expiry_thread.start()
        if self.serve_proxy:
            self._start_runtime()
        return self.status()

    # -- expiry sweep (CONTRACT §3: expiry terminates) ----------------
    def _expiry_loop(self) -> None:
        """Reap expired/idle-dead sessions until the daemon stops.

        The proxy denies a dead token on its own; this loop is what makes
        "expired" mean "terminated": the worker process dies and the
        compartment is free for the next session. A raise here would
        strand every later expiry, so the failure is named on stderr
        rather than swallowed.
        """
        while not self._stop_event.wait(EXPIRY_SWEEP_INTERVAL_S):
            try:
                self.broker.reap_expired()
            except Exception as exc:  # noqa: BLE001 -- keep the sweep alive
                print("sealvra daemon: expiry sweep failed: %s: %s"
                      % (type(exc).__name__, exc), file=sys.stderr)

    # -- composition root ------------------------------------------------
    def _start_runtime(self) -> None:
        """Compose the real object graph and serve the proxy (v0.2 Phase 1).

        Never swallowed: a failure leaves ``runtime`` absent and records
        the exact exception, so ``daemon status`` and the stderr line at
        start both name the missing link instead of implying a broker
        that can forward.
        """
        try:
            built = runtime.build_runtime(self.broker)
        except Exception as exc:
            self.runtime_error = f"{type(exc).__name__}: {exc}"
            print(f"sealvra daemon: proxy NOT started: {self.runtime_error}",
                  file=sys.stderr)
            return
        try:
            self.proxy_port = built.start_proxy()
        except Exception as exc:
            self.runtime_error = f"{type(exc).__name__}: {exc}"
            try:
                built.shutdown()
            finally:
                built.audit.close()
            return
        self.runtime = built
        print(f"sealvra daemon: proxy serving on 127.0.0.1:{self.proxy_port}",
              file=sys.stderr)

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
            return {"sessions": [_with_pseudonyms(_session_dict(s))
                                 for s in self.list_sessions()]}
        if cmd == "sessions.create":
            # Daemon-side rotation gate. The CLI checks this too, but a
            # raw IPC client must not be able to skip it: an unknown
            # rotation state refuses, it never defaults to allow.
            self._require_key_creatable(args.get("key_id", ""))
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
            # Token returned exactly once, over IPC only. The PoP key
            # rides along ONLY in test mode, ONLY in the reply of the
            # call that just minted it, and ONLY for that new session:
            # CONTRACT section 4 allows pipe/FD delivery of a
            # creation-time handoff, and there is no command here that
            # discloses the credential of a pre-existing session. In
            # production the handoff stays the wrapper/sidecar (W12).
            reply = {"session": _session_dict(created.session),
                     "token": created.token}
            if vault_module.test_mode_enabled():
                reply["pop_key_hex"] = created.pop_key.hex()
            return reply
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
            # The real chain verifier, read-only, over the ONE
            # conventional audit root this daemon resolves (module
            # docstring): an IPC caller cannot point it at an arbitrary
            # directory. A failure to even read the root is KH-1005; a
            # bad chain is a status, not an error.
            try:
                result = audit_module.verify()
            except OSError as exc:
                raise DaemonError("KH-1005",
                                  f"audit unavailable: {exc}") from None
            return {
                "status": result.status,
                "exit_code": result.exit_code,
                "entries": result.entries,
                "anchored": result.anchored,
                "unanchored_tail": result.unanchored_tail,
                "last_seq": result.last_seq,
                "errors": list(result.errors),
                "warnings": list(result.warnings),
                "root": str(audit_module.default_audit_root()),
            }
        if cmd == "audit.list":
            # Read-only tail of the live segment for the GUI's Activity
            # view. Same conventional root as ``audit.verify`` -- an IPC
            # caller cannot point it at an arbitrary directory -- and the
            # reply carries ONLY the closed §8 schema fields, so nothing
            # outside the schema can ever ride out over this command.
            return {"entries": _audit_tail(int(args.get("limit") or 200)),
                    "root": str(audit_module.default_audit_root())}
        if cmd == "vault.list":
            # Read-only projection of the authenticated vault headers --
            # exactly what ``sealvra keys list`` already prints. No key
            # value is in a vault header and none is read here; the
            # secret stays inside the compartment.
            try:
                records = vault_module.list_keys()
            except vault_module.AuthRequired as exc:
                raise DaemonError("KH-1001", str(exc)) from None
            except vault_module.VaultError as exc:
                raise DaemonError(
                    "KH-1002", f"vault unavailable: {exc}") from None
            return {"keys": [
                {
                    "key_id": record.key_id,
                    "provider": record.provider,
                    "label": record.label,
                    "fingerprint": (record.fingerprint or "")[:12],
                    "needs_rotation": bool(record.needs_rotation),
                    "created_at": record.created_at,
                    "header_verified": bool(record.header_verified),
                    # The same HMAC pseudonym the audit log already
                    # writes for this key, so a caller can join a key
                    # row to its access log. It is derived, not stored,
                    # and is not a secret: without it the log's
                    # pseudonyms are unlinkable from the vault's ids,
                    # and a GUI that shows both can only guess.
                    "pseudonym": _pseudonym_or_blank(record.key_id),
                }
                for record in records]}
        if cmd == "packs.status":
            # Read-only: does each provider pack still load against the
            # trust root, and what version is pinned. This runs the real
            # loader (hash + signature + revocation), so a refused pack
            # reports the refusal instead of the GUI claiming a policy is
            # in force. It changes no decision and loads nothing new.
            return _packs_status_dict()
        if cmd == "doctor":
            return self._doctor_dict()
        if cmd == "daemon.stop":
            return {"stopped": True,
                    "session_count": len(self._live_sessions())}
        raise DaemonError("KH-2001", f"unknown command: {cmd!r}")

    @staticmethod
    def _require_key_creatable(key_id: str) -> None:
        """The vault gate every session must pass before it can exist.

        Three refusals, each with its own code, because they mean
        different things to the operator:

        * KH-1001 -- the store cannot be opened at all (production has no
          wrapping-key source until owner decision OD-12). This is never
          reported as "key not found".
        * KH-1002 -- the key is absent, or its authenticated header could
          not be read; an unknown rotation state never starts a session.
        * KH-1003 -- the key is known to be (or possibly was) pasted and
          not yet rotated.
        """
        try:
            record = vault_module.get_key(key_id)
        except vault_module.AuthRequired as exc:
            raise DaemonError("KH-1001", str(exc)) from None
        except vault_module.VaultError as exc:
            raise DaemonError("KH-1002", f"key unavailable: {exc}") from None
        if record is None:
            raise DaemonError(
                "KH-1002",
                f"key not found in the vault: {key_id!r}; a session is bound "
                "to a stored, verified compartment, not to an arbitrary id")
        if record.needs_rotation:
            raise DaemonError(
                "KH-1003",
                "NOT YET ROTATED: this key was (or may have been) pasted "
                "before import; rotate it at the provider and record the "
                "rotation before its first session")

    def _status_dict(self) -> dict:
        return {
            "running": self._running,
            "pid": os.getpid() if self._running else None,
            "socket_path": self._socket_path,
            "session_count": len(self._live_sessions()),
            "started_at": self._started_at,
            "loopback_only": True,
            "transport": "unix" if _use_unix_socket() else "tcp-loopback",
            "peer_uid_checked": self._last_peer_checked,
            "tier_b_note": TIER_B_NOTE,
            "proxy": self._proxy_dict(),
        }

    def _proxy_dict(self) -> dict:
        """What the proxy actually is: served or not, and where traffic
        would go. The E2E safety gate reads ``upstream_bases`` here and
        refuses to make a proxied call until it names loopback mocks, so
        these fields are the gate, not decoration.
        """
        info: dict = {
            "served": self.proxy_port is not None,
            "port": self.proxy_port,
        }
        if self.runtime_error:
            info["not_served_reason"] = self.runtime_error
        try:
            info.update(runtime.describe(self.runtime))
        except Exception as exc:
            info["describe_error"] = f"{type(exc).__name__}: {exc}"
        return info

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
            "session_count": len(self._live_sessions()),
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
            session_count=len(self._live_sessions()),
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
        if self._expiry_thread is not None:
            self._expiry_thread.join(timeout=2.0)
            self._expiry_thread = None
        # Proxy down first: no call may be accepted while sessions are
        # being torn down.
        rt = self.runtime
        self.runtime = None
        self.proxy_port = None
        self.runtime_error = None
        if rt is not None:
            rt.shutdown()
            rt.audit.close()
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
        """Every session record this daemon still holds, live or not.

        This is the IPC record view (`sessions.list`): a killed session's
        record is still returned, with `killed` set, which is what the
        GUI and the W01 IPC test read. The OPERATOR views -- `session_count`
        here and `sealvra sessions list` in the CLI -- show only the
        sessions that can still authenticate; see `_live_sessions`.
        """
        return self.broker.list_sessions()

    def _live_sessions(self) -> list[Session]:
        """The records whose token can still authenticate (CONTRACT §3).

        A session past its TTL or idle deadline, or killed, is
        TERMINATED: counting it as a live session would claim to an
        operator that a dead token still works, and the killed records
        accumulate for the daemon's whole lifetime.
        """
        return [s for s in self.broker.list_sessions() if self.broker.is_live(s)]

    # -- clock/sleep section (W13, v0.2; IPC untouched) --------------
    # Sleep-aware clock naming lives in sessions.py (v3 N-F1): Linux
    # CLOCK_BOOTTIME is the live sleep-aware clock; on macOS this build
    # uses plain time.monotonic and says NOT sleep-aware, because
    # mach_continuous_time has never been called here. Nothing here
    # changes start/stop/status, the accept loop, or the IPC dispatch
    # table (all W01).
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
# These are what the CLI calls (sealvra.cli._load_daemon). They are
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


def status_detail() -> dict:
    """The daemon's raw status dict, including the ``proxy`` section the
    fixed DaemonStatus dataclass cannot carry (v0.2 Phase 1).

    ``daemon status`` prints upstream bases and the bound proxy port
    from here because the E2E safety gate needs to confirm the proxy
    points at loopback mocks before it makes any proxied call. Returns
    {} when no daemon answers.
    """
    try:
        return DaemonClient(daemon_dir()).request("status")
    except (DaemonNotRunning, DaemonError, OSError):
        return {}


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
    cmd = [sys.executable, "-m", "sealvra.daemon", "--serve",
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
    daemon = Daemon(directory, rendezvous=True, serve_proxy=True)
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
    parser = argparse.ArgumentParser(prog="sealvra.daemon")
    parser.add_argument("--serve", action="store_true",
                        help="run as the detached daemon process")
    parser.add_argument("--dir", default=None,
                        help="rendezvous directory (default: daemon_dir())")
    args = parser.parse_args(argv)
    if not args.serve:
        print("sealvra.daemon: use --serve to run the daemon process, "
              "or the Daemon class / module functions for IPC",
              file=sys.stderr)
        return 2
    directory = Path(args.dir).expanduser() if args.dir else daemon_dir()
    return serve_main(directory)


if __name__ == "__main__":
    raise SystemExit(main())
