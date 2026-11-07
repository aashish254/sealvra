"""W01 v0.2 tests: cross-process daemon IPC (unittest, fake keys only).

Proves CONTRACT §13.1 end to end with separate processes, not a
process-local singleton:

- ``sealvra daemon start`` in one CLI subprocess, ``status`` in
  another, reporting the SAME daemon pid;
- session create/list/kill issued from yet other subprocesses over
  the JSON-line IPC protocol (token exactly once, never in the
  daemon log, never in list output);
- ``daemon stop`` from a CLI subprocess kills the daemon and its
  workers; a restart starts with zero sessions (no resurrection),
  including after a SIGKILLed daemon (stale rendezvous cleanup);
- orphan workers self-terminate <= 5 s after daemon death;
- socket directory 0700, socket 0600 (Unix); doctor states the
  Tier B limit in plain words; audit.verify over IPC runs the real
  hash-chain verifier against the daemon's own audit root (v0.2
  Phase 1 wired the root in; the KH-1005 stub answer is gone).

v0.2 Phase 1 fixture change, stated honestly: the detached daemon now
composes the real object graph (runtime: proxy + vault + audit), so
every test here runs in SEALVRA_TEST_MODE with an isolated wrapping-key
file, an isolated vault and audit root, loopback mock upstream bases and
an ephemeral proxy port. Sessions are bound to real TEST-ONLY
compartments created through the vault -- the old synthetic key ids that
no vault held are exactly what the wired daemon now refuses (KH-1002),
and refusing them is the behaviour under test. No assertion was removed
or weakened; the fixtures were made real.

No real keys/tokens/credentials: all values are TEST-ONLY fakes.
Loopback only; no network, no GitHub, no provider contact.
Run from the build root: python3 -m unittest tests.test_daemon_ipc -v
"""

import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _proc_has_session(session_id: str) -> bool:
    """True if any live process cmdline mentions this session id.

    /proc on Linux, ``ps`` on macOS/BSD. A worker's argv always carries
    its session id (``python -m sealvra.supervisor --worker
    <session_id> ...``), so both scans look for the same thing. On a
    platform with neither this raises: answering False there would
    report "no worker" for a probe that never ran, which is a false pass
    for the teardown assertions, not an honest NOT-RUN.
    """
    proc = Path("/proc")
    if proc.is_dir():
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                cmdline = (entry / "cmdline").read_bytes()
            except OSError:
                continue
            if session_id.encode() in cmdline:
                return True
        return False
    try:
        out = subprocess.run(["ps", "-ax", "-o", "args="],
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise AssertionError(
            "no process scan on this platform: worker presence is NOT-RUN, "
            "not absent (%r)" % (exc,)) from None
    if out.returncode != 0:
        raise AssertionError("ps failed: worker presence is NOT-RUN, not "
                             "absent (%s)" % out.stderr[:200])
    return any(session_id in line for line in out.stdout.splitlines())


def _wait_until(predicate, timeout_s: float, interval: float = 0.1) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


class DaemonIPCTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="sealvra-ipc-test-")
        self.daemon_dir = Path(tmp) / "daemon"
        self.env = dict(os.environ)
        self.env["SEALVRA_DAEMON_DIR"] = str(self.daemon_dir)
        # Isolated test-mode object graph (see the module docstring).
        self.vault_dir = Path(tmp) / "vault"
        self.audit_dir = Path(tmp) / "audit"
        wrapping_key = Path(tmp) / "wrapping_key.hex"
        wrapping_key.write_text("11" * 32, encoding="utf-8")
        os.chmod(wrapping_key, 0o600)
        self.env.update({
            "SEALVRA_TEST_MODE": "1",
            "SEALVRA_TEST_APPROVER": "1",
            "SEALVRA_TEST_WRAPPING_KEY_FILE": str(wrapping_key),
            "SEALVRA_VAULT_DIR": str(self.vault_dir),
            "SEALVRA_AUDIT_ROOT": str(self.audit_dir),
            "SEALVRA_PROXY_PORT": "0",
            "SEALVRA_MOCK_GITHUB_BASE": "http://127.0.0.1:18765",
            "SEALVRA_MOCK_GEMINI_BASE": "http://127.0.0.1:18766",
        })
        self.env["PYTHONPATH"] = str(ROOT) + os.pathsep + self.env.get(
            "PYTHONPATH", "")
        self.addCleanup(self._force_cleanup)

    def _force_cleanup(self):
        try:
            self.cli("daemon", "stop")
        except Exception:
            pass
        pid_file = self.daemon_dir / "daemon.pid"
        try:
            pid = int(pid_file.read_text().strip())
        except (OSError, ValueError):
            pid = None
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            _wait_until(lambda: not self._pid_alive(pid), 5.0)
        # Best-effort removal of the temp tree (daemon dir kept only
        # as long as the test needs it; nothing in it is a secret).
        import shutil
        shutil.rmtree(self.daemon_dir.parent, ignore_errors=True)

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def cli(self, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "sealvra", *argv],
            cwd=str(ROOT), env=self.env, capture_output=True, text=True,
            timeout=60)

    def ipc(self, cmd: str, args: dict | None = None) -> dict:
        """Run ONE IPC request from a fresh subprocess (a different
        process from the daemon, and from this test process). Prints
        JSON; raises AssertionError on an error reply."""
        script = (
            "import json, sys; sys.path.insert(0, %r)\n"
            "from pathlib import Path\n"
            "from sealvra.daemon import DaemonClient, DaemonError\n"
            "try:\n"
            "    result = DaemonClient(Path(%r)).request(%r, %r)\n"
            "    print(json.dumps({'ok': True, 'result': result}))\n"
            "except DaemonError as e:\n"
            "    print(json.dumps({'ok': False, 'code': e.code,\n"
            "                      'message': e.message}))\n"
            % (str(ROOT), str(self.daemon_dir), cmd, args or {}))
        proc = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(ROOT), env=self.env, capture_output=True, text=True,
            timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def ipc_ok(self, cmd: str, args: dict | None = None) -> dict:
        reply = self.ipc(cmd, args)
        self.assertTrue(reply.get("ok"), reply)
        return reply["result"]

    def add_key(self, provider: str, label: str) -> str:
        """Mint one real TEST-ONLY compartment in this test's vault.

        Runs in a subprocess with the same fixture env, so the daemon and
        the CLI see the same store. The value is a fake, never a key.
        """
        fake = "TEST-ONLY-IPC-%s-FAKE-KEY-0001" % provider.upper()
        script = (
            "import os, sys; sys.path.insert(0, %r)\n"
            "from sealvra import vault\n"
            "print(vault.add_key(%r, %r, %r, False).key_id)\n"
            % (str(ROOT), provider, label, fake))
        proc = subprocess.run([sys.executable, "-c", script],
                              cwd=str(ROOT), env=self.env,
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout.strip().splitlines()[-1]

    def start_daemon(self) -> int:
        proc = self.cli("daemon", "start")
        self.assertIn("daemon: started", proc.stdout, proc.stderr)
        pid = int((self.daemon_dir / "daemon.pid").read_text().strip())
        return pid

    def test_cli_start_status_stop_across_invocations(self):
        pid = self.start_daemon()
        # A DIFFERENT CLI invocation reports the same daemon pid.
        status = self.cli("daemon", "status")
        self.assertIn(f"daemon: running (pid {pid})", status.stdout)
        # Second start refuses (already running), pid unchanged.
        again = self.cli("daemon", "start")
        self.assertIn("daemon: already running", again.stdout)
        self.assertEqual(
            pid, int((self.daemon_dir / "daemon.pid").read_text().strip()))
        stopped = self.cli("daemon", "stop")
        self.assertIn("daemon: stopped", stopped.stdout)
        self.assertIn("daemon: stopped",
                      self.cli("daemon", "status").stdout)
        self.assertFalse(self._pid_alive(pid), "daemon process must be dead")

    def test_socket_permissions_and_doctor_tier_b(self):
        self.start_daemon()
        dir_mode = stat.S_IMODE(os.stat(self.daemon_dir).st_mode)
        self.assertEqual(dir_mode, 0o700, "daemon dir must be 0700")
        sock_mode = stat.S_IMODE(
            os.stat(self.daemon_dir / "control.sock").st_mode)
        self.assertEqual(sock_mode, 0o600, "socket must be 0600")
        doctor = self.ipc_ok("doctor")
        self.assertTrue(doctor["loopback_only"])
        self.assertTrue(doctor["sessions_in_memory_only"])
        self.assertIn("Tier B", doctor["tier_b_note"])
        self.assertIn("does NOT separate same-user",
                      doctor["tier_b_note"])

    def test_create_list_kill_from_other_processes_token_once(self):
        self.start_daemon()
        key_id = self.add_key("github", "ipc-github")
        created = self.ipc_ok("sessions.create", {
            "key_id": key_id, "provider": "github",
            "session_class": "read_public"})
        token = created["token"]
        session_id = created["session"]["session_id"]
        self.assertTrue(token.startswith("kh_sess_"))
        # Token appears in NO other IPC output and NO daemon log.
        listing = self.ipc_ok("sessions.list")
        self.assertEqual(len(listing["sessions"]), 1)
        self.assertEqual(listing["sessions"][0]["session_id"], session_id)
        self.assertNotIn(token, json.dumps(listing))
        log_text = (self.daemon_dir / "daemon.log").read_text(
            errors="ignore")
        self.assertNotIn(token, log_text, "token must never be logged")
        # Kill from yet another process; receipt is generic-shaped.
        killed = self.ipc_ok("sessions.kill", {"session_id": session_id})
        self.assertEqual(killed["receipt"]["session_id"], session_id)
        self.assertTrue(killed["receipt"]["teardown_within_5s"])
        after = self.ipc_ok("sessions.list")
        self.assertTrue(after["sessions"][0]["killed"])
        # Unknown session kill is KH-1002, unknown command KH-2001.
        missing = self.ipc("sessions.kill",
                           {"session_id": "sess-TEST-ONLY-missing"})
        self.assertEqual(missing.get("code"), "KH-1002")
        bogus = self.ipc("bogus.command")
        self.assertEqual(bogus.get("code"), "KH-2001")

    def test_sessions_create_refuses_a_key_the_vault_does_not_hold(self):
        # A session must be bound to a stored compartment. An id no
        # vault holds is refused before a token can exist (v0.2 Phase 1:
        # the daemon gates creation on the verified vault record).
        self.start_daemon()
        reply = self.ipc("sessions.create", {
            "key_id": "key-TEST-ONLY-9199", "provider": "github",
            "session_class": "read_public"})
        self.assertFalse(reply.get("ok"))
        self.assertEqual(reply.get("code"), "KH-1002")

    def test_audit_verify_runs_the_real_verifier_over_ipc(self):
        # Was test_audit_verify_honestly_unavailable_from_daemon, which
        # asserted the KH-1005 stub. The daemon now owns a real audit
        # root, so the stub answer is gone and this asserts the real
        # chain: starting the daemon writes the genesis/chain_created
        # entry, and IPC verification must report it as a verified
        # chain (OK, exit 0) rather than a fabricated result.
        self.start_daemon()
        result = self.ipc_ok("audit.verify")
        self.assertEqual(result["status"], "OK", result)
        self.assertEqual(result["exit_code"], 0)
        self.assertGreaterEqual(result["entries"], 1)
        self.assertTrue((self.audit_dir / "audit" / "audit.jsonl").exists())
        self.assertEqual(Path(result["root"]), self.audit_dir)
        # An IPC caller cannot point the verifier at some other root:
        # a "root" argument is ignored, and the answer still describes
        # this daemon's own chain. Tamper detection itself is covered by
        # the audit module's own suite, not re-proved here.
        other = self.ipc_ok("audit.verify", {"root": "/nonexistent-root"})
        self.assertEqual(other["status"], "OK", other)
        self.assertEqual(Path(other["root"]), self.audit_dir)

    def test_stop_kills_workers_and_restart_has_no_sessions(self):
        self.start_daemon()
        key_id = self.add_key("gemini", "ipc-gemini")
        created = self.ipc_ok("sessions.create", {
            "key_id": key_id, "provider": "gemini",
            "session_class": "read_public"})
        session_id = created["session"]["session_id"]
        self.assertTrue(_wait_until(
            lambda: _proc_has_session(session_id), 5.0),
            "worker process for the session must exist")
        self.cli("daemon", "stop")
        self.assertTrue(_wait_until(
            lambda: not _proc_has_session(session_id), 5.0),
            "worker must die on daemon stop (<= 5 s)")
        # Restart: sessions are gone, never resurrected.
        self.start_daemon()
        listing = self.ipc_ok("sessions.list")
        self.assertEqual(listing["sessions"], [])

    def test_daemon_death_orphans_workers_and_stale_restart(self):
        pid = self.start_daemon()
        key_id = self.add_key("github", "ipc-github-orphan")
        created = self.ipc_ok("sessions.create", {
            "key_id": key_id, "provider": "github",
            "session_class": "read_public"})
        session_id = created["session"]["session_id"]
        self.assertTrue(_wait_until(
            lambda: _proc_has_session(session_id), 5.0))
        # Daemon death (SIGKILL, no graceful stop): workers must
        # self-terminate <= 5 s after supervisor loss.
        os.kill(pid, signal.SIGKILL)
        self.assertTrue(_wait_until(
            lambda: not self._pid_alive(pid), 5.0))
        self.assertTrue(_wait_until(
            lambda: not _proc_has_session(session_id), 5.0),
            "orphan worker must self-terminate <= 5 s after daemon death")
        self.assertIn("daemon: stopped",
                      self.cli("daemon", "status").stdout)
        # Stale rendezvous (dead pid + dead socket) must not block a
        # fresh start, and the fresh daemon has no sessions.
        self.start_daemon()
        self.assertEqual(self.ipc_ok("sessions.list")["sessions"], [])


if __name__ == "__main__":
    unittest.main()
