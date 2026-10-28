"""Supervisor: one worker per session, worker-per-key (W01).

Rules enforced here (CONTRACT §4/§12, v3 §1B N-B4, §1C N-C2/N-C6,
§1F N-F3):

- One worker serves exactly one session, which holds exactly one key.
  A second live worker for the same session_id OR the same key_id is
  refused (``WorkerAlreadyExists``). The worker process never receives
  a key value, a session token, or a PoP key -- only identifiers.
- Kill is by process group + child scan + port-release verification,
  never by PID alone. Teardown bound is 5 s (SIGTERM, then SIGKILL).
- Orphan workers self-terminate <= 5 s after supervisor loss: the
  worker polls its supervisor PID (default every 0.25 s) and exits
  when that PID no longer exists. This is checked by a release test
  in tests/test_w01_daemon.py.

Tier honesty (v3 §1A): process-group kill and supervisor-PID polling
are Tier A controls. They do not separate a Tier B (same-user,
shell-capable) agent, which can ptrace/fork around them; sandbox
profiles (not this module) are the Tier B control for workers.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .types import Session

WORKER_POLL_INTERVAL_S = 0.25
TEARDOWN_TIMEOUT_S = 5.0


class WorkerAlreadyExists(Exception):
    """A live worker already exists for this session_id or key_id."""


class WorkerNotFound(Exception):
    pass


@dataclass
class WorkerHandle:
    session_id: str
    key_id: str
    pid: int
    pgid: int
    started_at: float
    port: int | None = None
    process: subprocess.Popen | None = field(default=None, repr=False)

    def is_alive(self) -> bool:
        if self.process is not None:
            return self.process.poll() is None
        try:
            os.kill(self.pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False


def _package_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _scan_children(root_pid: int) -> list[int]:
    """Best-effort child scan on Linux via /proc; [] elsewhere."""
    proc = Path("/proc")
    if not proc.is_dir():
        return []
    ppid_of: dict[int, int] = {}
    try:
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                stat = (entry / "stat").read_text(errors="ignore")
                # comm may contain spaces/parens; ppid is field after ')'.
                rparen = stat.rfind(")")
                fields = stat[rparen + 2 :].split()
                ppid_of[int(entry.name)] = int(fields[1])
            except (ValueError, IndexError, OSError):
                continue
    except OSError:
        return []
    children: list[int] = []
    frontier = [root_pid]
    while frontier:
        parent = frontier.pop()
        for pid, ppid in ppid_of.items():
            if ppid == parent and pid not in children:
                children.append(pid)
                frontier.append(pid)
    return children


def _port_released(port: int, timeout_s: float = 1.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                time.sleep(0.1)
        except OSError:
            return True
    return False


def _worker_main(argv: list[str]) -> int:
    """Worker process entry point (identifiers only, no key material).

    Usage: python3 -m keyholder.supervisor --worker <session_id>
           <key_id> <supervisor_pid> [--bind-port <port>]
    Exits promptly when the supervisor PID disappears, and on SIGTERM.
    """
    if len(argv) < 4:
        print("usage: --worker <session_id> <key_id> <supervisor_pid>",
              file=sys.stderr)
        return 2
    _session_id, _key_id = argv[1], argv[2]
    try:
        supervisor_pid = int(argv[3])
    except ValueError:
        return 2
    bind_port: int | None = None
    if "--bind-port" in argv:
        try:
            bind_port = int(argv[argv.index("--bind-port") + 1])
        except (ValueError, IndexError):
            return 2
    listener: socket.socket | None = None
    if bind_port is not None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", bind_port))
        listener.listen(1)
        listener.settimeout(0.2)
    # Poll supervisor liveness; <= 5 s bound is met with large margin
    # (0.25 s poll). Also exits if reparented away from a live parent
    # is not detectable -- PID polling is the mechanism, documented.
    while True:
        try:
            os.kill(supervisor_pid, 0)
        except (ProcessLookupError, PermissionError):
            break
        if listener is not None:
            try:
                conn, _ = listener.accept()
                conn.close()
            except (socket.timeout, OSError):
                pass
        else:
            time.sleep(WORKER_POLL_INTERVAL_S)
    if listener is not None:
        listener.close()
    return 0


class Supervisor:
    """Spawns and kills one worker process per session."""

    def __init__(self) -> None:
        self._workers: dict[str, WorkerHandle] = {}

    # -- spawn ------------------------------------------------------
    def spawn(self, session: Session, port: int | None = None) -> WorkerHandle:
        for handle in self._workers.values():
            if not handle.is_alive():
                continue
            if handle.session_id == session.session_id:
                raise WorkerAlreadyExists(
                    f"live worker already exists for session {session.session_id}")
            if handle.key_id == session.key_id:
                raise WorkerAlreadyExists(
                    f"live worker already exists for key {session.key_id}")
        root = _package_root()
        env = dict(os.environ)
        env["PYTHONPATH"] = str(root) + os.pathsep + env.get("PYTHONPATH", "")
        cmd = [sys.executable, "-m", "keyholder.supervisor", "--worker",
               session.session_id, session.key_id, str(os.getpid())]
        if port is not None:
            cmd += ["--bind-port", str(port)]
        # start_new_session is POSIX-only; on Windows it is ignored by
        # subprocess, so pass it only on POSIX to keep the intent clear.
        popen_kwargs: dict = {
            "cwd": str(root), "env": env,
            "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
        }
        if sys.platform != "win32":
            popen_kwargs["start_new_session"] = True  # own pg for killpg
        proc = subprocess.Popen(cmd, **popen_kwargs)
        # No getpgid/killpg on Windows: pgid falls back to the PID and
        # terminate() below uses process.terminate() instead. The
        # guard is written as `sys.platform != "win32"` (not if/else)
        # because the Windows checker recognises that form.
        pgid = proc.pid
        if sys.platform != "win32":
            try:
                pgid = os.getpgid(proc.pid)
            except ProcessLookupError:
                pgid = proc.pid
        handle = WorkerHandle(
            session_id=session.session_id, key_id=session.key_id,
            pid=proc.pid, pgid=pgid, started_at=time.time(),
            port=port, process=proc)
        self._workers[session.session_id] = handle
        return handle

    def get(self, session_id: str) -> WorkerHandle | None:
        return self._workers.get(session_id)

    def live_workers(self) -> list[WorkerHandle]:
        return [h for h in self._workers.values() if h.is_alive()]

    # -- kill -------------------------------------------------------
    def terminate(self, session_id: str,
                  timeout_s: float = TEARDOWN_TIMEOUT_S) -> dict:
        """Kill by process group + child scan + port-release check.

        Returns dict with terminated, elapsed_s, within_5s, method,
        children_killed, port_released (None when no port tracked).
        """
        handle = self._workers.get(session_id)
        if handle is None:
            raise WorkerNotFound(session_id)
        started = time.monotonic()
        method = "already-dead"
        children_killed: list[int] = []
        if handle.is_alive():
            # Windows has no killpg/getpgid: terminate the process
            # itself (a job-object/process-tree kill is the post-push
            # Windows hardening item; this path must not crash with
            # AttributeError, which was the W16 finding). Guards are
            # written as `sys.platform != "win32"` because the
            # Windows checker recognises that form, not if/else.
            if sys.platform == "win32":
                # Terminate the whole tree (v0.2 §13.1: Windows
                # terminate tree, not just the worker PID).
                try:
                    done = subprocess.run(
                        ["taskkill", "/F", "/T", "/PID", str(handle.pid)],
                        capture_output=True, timeout=5)
                    method = ("taskkill-tree-win32" if done.returncode == 0
                              else "terminate-win32")
                    if done.returncode != 0:
                        handle.process.terminate()  # type: ignore[union-attr]
                except Exception:
                    try:
                        handle.process.terminate()  # type: ignore[union-attr]
                        method = "terminate-win32"
                    except Exception:
                        method = "already-dead"
            if sys.platform != "win32":
                try:
                    os.killpg(handle.pgid, signal.SIGTERM)
                    method = "SIGTERM-pgid"
                except (ProcessLookupError, PermissionError, AttributeError):
                    try:
                        os.kill(handle.pid, signal.SIGTERM)
                        method = "SIGTERM-pid"
                    except (ProcessLookupError, PermissionError, AttributeError):
                        method = "already-dead"
            try:
                handle.process.wait(timeout=timeout_s)  # type: ignore[union-attr]
            except subprocess.TimeoutExpired:
                if sys.platform == "win32":
                    try:
                        handle.process.kill()  # type: ignore[union-attr]
                        method = "kill-win32"
                    except Exception:
                        pass
                if sys.platform != "win32":
                    try:
                        os.killpg(handle.pgid, signal.SIGKILL)
                        method = "SIGKILL-pgid"
                    except (ProcessLookupError, PermissionError, AttributeError):
                        pass
                try:
                    handle.process.wait(timeout=2.0)  # type: ignore[union-attr]
                except subprocess.TimeoutExpired:
                    pass
            # Child scan: anything the worker forked must die too.
            for child in _scan_children(handle.pid):
                try:
                    os.kill(child, signal.SIGKILL)
                    children_killed.append(child)
                except (ProcessLookupError, PermissionError):
                    continue
        elapsed = time.monotonic() - started
        port_released: bool | None = None
        if handle.port is not None:
            port_released = _port_released(handle.port)
        self._workers.pop(session_id, None)
        return {
            "terminated": not handle.is_alive(),
            "elapsed_s": elapsed,
            "within_5s": elapsed <= timeout_s,
            "method": method,
            "children_killed": children_killed,
            "port_released": port_released,
        }

    def terminate_all(self) -> dict[str, dict]:
        """Terminate every tracked worker. Returns per-session results."""
        results: dict[str, dict] = {}
        for session_id in list(self._workers.keys()):
            results[session_id] = self.terminate(session_id)
        return results


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--worker":
        return _worker_main(sys.argv[1:])
    print("keyholder.supervisor: use Supervisor class or --worker",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
