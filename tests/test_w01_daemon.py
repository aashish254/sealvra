"""W01 tests: daemon, broker, supervisor (unittest, fake keys only).

Covers: daemon start/stop/status, worker-per-session enforcement,
no session resurrection after restart, orphan worker self-terminate
<= 5 s after supervisor loss, kill bounds (deny-list <= 1 s,
teardown <= 5 s) and kill receipt contents, TTL clamps, token/PoP
handling, kill-all snapshot semantics, and the no-extension rule.

No real keys/tokens/credentials: all key ids are TEST-ONLY fakes.
Loopback mocks only; no network, no GitHub, no provider contact.
Run from the build root: python3 -m unittest tests.test_w01_daemon -v
(or python3 -m unittest discover -s tests -v).
"""

import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from keyholder.broker import Broker, SessionNotFound  # noqa: E402
from keyholder.daemon import Daemon, DaemonAlreadyRunning, DaemonNotRunning  # noqa: E402
from keyholder.supervisor import Supervisor, WorkerAlreadyExists  # noqa: E402
from keyholder.types import Session  # noqa: E402


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def make_daemon() -> Daemon:
    daemon = Daemon()
    daemon.start()
    return daemon


class DaemonLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.daemon = make_daemon()
        self.addCleanup(self._stop_quietly)

    def _stop_quietly(self):
        try:
            self.daemon.stop()
        except Exception:
            pass

    def test_start_status_stop(self):
        status = self.daemon.status()
        self.assertTrue(status.running)
        self.assertTrue(status.loopback_only)
        self.assertIsNotNone(status.socket_path)
        self.assertEqual(status.session_count, 0)
        # Socket path is inside a temp dir, never a fixed home path.
        self.assertNotIn(".keyholder/sessions", status.socket_path or "")
        stopped = self.daemon.stop()
        self.assertFalse(stopped.running)
        self.assertEqual(stopped.session_count, 0)
        with self.assertRaises(DaemonNotRunning):
            self.daemon.stop()

    def test_double_start_refused(self):
        with self.assertRaises(DaemonAlreadyRunning):
            self.daemon.start()

    def test_create_requires_running_daemon(self):
        daemon = Daemon()
        with self.assertRaises(DaemonNotRunning):
            daemon.create_session(key_id="key-TEST-ONLY-0001",
                                  provider="github",
                                  session_class="read_public")

    def test_no_resurrection_after_restart(self):
        created = self.daemon.create_session(
            key_id="key-TEST-ONLY-0002", provider="github",
            session_class="read_public")
        self.assertEqual(len(self.daemon.list_sessions()), 1)
        self.daemon.stop()
        fresh = Daemon()
        fresh.start()
        self.addCleanup(lambda: fresh.stop() if fresh.status().running else None)
        self.assertEqual(fresh.list_sessions(), [])
        # Old token resolves to nothing on the fresh daemon (generic None).
        self.assertIsNone(fresh.broker.validate_token(created.token))


class WorkerPerSessionTest(unittest.TestCase):
    def setUp(self):
        self.daemon = make_daemon()
        self.addCleanup(self._stop_quietly)

    def _stop_quietly(self):
        try:
            self.daemon.stop()
        except Exception:
            pass

    def test_one_worker_per_session_and_per_key(self):
        first = self.daemon.create_session(
            key_id="key-TEST-ONLY-0010", provider="github",
            session_class="read_public")
        # Second live session for the SAME key is refused: worker-per-
        # session = worker-per-key, never one worker serving two sessions.
        with self.assertRaises(WorkerAlreadyExists):
            self.daemon.create_session(
                key_id="key-TEST-ONLY-0010", provider="github",
                session_class="read_public")
        # First session is still live and its worker still tracked.
        self.assertIsNotNone(self.daemon.broker.get_session(
            first.session.session_id))
        handle = self.daemon.supervisor.get(first.session.session_id)
        self.assertIsNotNone(handle)
        self.assertTrue(handle.is_alive())

    def test_supervisor_refuses_duplicate_session_id(self):
        supervisor = Supervisor()
        session = Session(
            session_id="sess-TEST-ONLY-dup", key_id="key-TEST-ONLY-0011",
            provider="github", session_class="read_public",
            transport="absolute", created_at=time.time(),
            expires_at=time.time() + 3600,
            idle_deadline=time.time() + 300,
            process_group="pg-test", ancestry="test")
        handle = supervisor.spawn(session)
        try:
            with self.assertRaises(WorkerAlreadyExists):
                supervisor.spawn(session)
        finally:
            supervisor.terminate(session.session_id)
        self.assertFalse(handle.is_alive())

    def test_worker_holds_identifiers_only(self):
        created = self.daemon.create_session(
            key_id="key-TEST-ONLY-0012", provider="gemini",
            session_class="read_public")
        # Token/PoP key never appear in the Session object or its repr.
        self.assertNotIn(created.token, repr(created.session))
        self.assertNotIn(created.pop_key.hex(), repr(created.session))


class OrphanWorkerTest(unittest.TestCase):
    def test_orphan_self_terminates_after_supervisor_loss(self):
        # A dummy "supervisor" process: the worker only polls its PID.
        dummy = subprocess.Popen([sys.executable, "-c",
                                  "import time; time.sleep(30)"])
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        worker = subprocess.Popen(
            [sys.executable, "-m", "keyholder.supervisor", "--worker",
             "sess-TEST-ONLY-orphan", "key-TEST-ONLY-0020", str(dummy.pid)],
            cwd=str(ROOT), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(0.5)
            self.assertIsNone(worker.poll(), "worker died before supervisor loss")
            dummy.terminate()
            dummy.wait(timeout=5)
            # Orphan bound is <= 5 s; poll loop gives a large margin.
            worker.wait(timeout=5)
        finally:
            for proc in (worker, dummy):
                if proc.poll() is None:
                    proc.kill()

    def test_orphan_with_already_dead_supervisor_pid(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        worker = subprocess.Popen(
            [sys.executable, "-m", "keyholder.supervisor", "--worker",
             "sess-TEST-ONLY-orphan2", "key-TEST-ONLY-0021", "999999"],
            cwd=str(ROOT), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            worker.wait(timeout=5)
        finally:
            if worker.poll() is None:
                worker.kill()


class KillTest(unittest.TestCase):
    def setUp(self):
        self.daemon = make_daemon()
        self.addCleanup(self._stop_quietly)

    def _stop_quietly(self):
        try:
            self.daemon.stop()
        except Exception:
            pass

    def test_kill_bounds_and_receipt(self):
        port = free_port()
        created = self.daemon.create_session(
            key_id="key-TEST-ONLY-0030", provider="github",
            session_class="read_public", port=port)
        session_id = created.session.session_id
        # An already-forwarded call, completed during the kill window.
        self.daemon.broker.register_in_flight(session_id, "call-TEST-001")

        def finish_call():
            time.sleep(0.3)
            self.daemon.broker.complete_in_flight(session_id, "call-TEST-001")

        threading.Thread(target=finish_call, daemon=True).start()
        started = time.monotonic()
        receipt = self.daemon.kill_session(session_id)
        wall = time.monotonic() - started
        self.assertLess(receipt.deny_list_latency_s, 1.0,
                        "deny-list write must be <= 1 s")
        self.assertTrue(receipt.teardown_within_5s)
        self.assertLessEqual(receipt.teardown_s, 5.0)
        self.assertLess(wall, 5.5)
        self.assertEqual(receipt.session_id, session_id)
        self.assertIn(session_id, receipt.workers_terminated)
        self.assertEqual(receipt.in_flight_at_kill, ["call-TEST-001"])
        self.assertEqual(receipt.completed_during_kill, ["call-TEST-001"])
        self.assertEqual(receipt.still_running_at_receipt, [])
        self.assertTrue(receipt.port_released,
                        "worker port must be released after teardown")
        # Killed session: token dead, session marked killed.
        self.assertIsNone(self.daemon.broker.validate_token(created.token))
        self.assertTrue(self.daemon.broker.get_session(session_id).killed)
        # Supervisor no longer tracks the worker.
        self.assertIsNone(self.daemon.supervisor.get(session_id))

    def test_kill_unknown_session_is_generic_not_found(self):
        with self.assertRaises(SessionNotFound):
            self.daemon.kill_session("sess-TEST-ONLY-missing")

    def test_kill_needs_no_auth_and_kill_all_snapshot(self):
        first = self.daemon.create_session(
            key_id="key-TEST-ONLY-0031", provider="github",
            session_class="read_public")
        second = self.daemon.create_session(
            key_id="key-TEST-ONLY-0032", provider="gemini",
            session_class="read_public")
        broker = self.daemon.broker
        original_kill = broker.kill_session

        def kill_with_creation_during_sweep(session_id):
            if session_id == first.session.session_id:
                broker.create_session(
                    key_id="key-TEST-ONLY-0033", provider="github",
                    session_class="read_public")
            return original_kill(session_id)

        broker.kill_session = kill_with_creation_during_sweep  # type: ignore[method-assign]
        try:
            result = broker.kill_all()
        finally:
            broker.kill_session = original_kill  # type: ignore[method-assign]
        self.assertEqual(sorted(result["snapshot"]),
                         sorted([first.session.session_id,
                                 second.session.session_id]))
        self.assertEqual(set(result["receipts"]),
                         set(result["snapshot"]))
        # Created during the sweep: listed, not silently swept in.
        self.assertEqual(len(result["created_during_sweep"]), 1)
        survivor_id = result["created_during_sweep"][0]
        self.assertFalse(broker.get_session(survivor_id).killed)
        broker.kill_session(survivor_id)


class TokenPopTtlTest(unittest.TestCase):
    def setUp(self):
        self.daemon = make_daemon()
        self.addCleanup(self._stop_quietly)

    def _stop_quietly(self):
        try:
            self.daemon.stop()
        except Exception:
            pass

    def test_token_digest_only_and_validation(self):
        created = self.daemon.create_session(
            key_id="key-TEST-ONLY-0040", provider="github",
            session_class="read_public")
        self.assertTrue(created.token.startswith("kh_sess_"))
        digest = hashlib.sha256(created.token.encode()).hexdigest()
        # Broker stores the digest, never the token string itself.
        self.assertIn(digest, self.daemon.broker._token_digests)
        self.assertNotIn(created.token,
                         str(self.daemon.broker._token_digests))
        found = self.daemon.broker.validate_token(created.token)
        self.assertIsNotNone(found)
        self.assertEqual(found.session_id, created.session.session_id)
        self.assertIsNone(self.daemon.broker.validate_token("kh_sess_bogus"))

    def test_pop_verification_and_nonce_replay(self):
        created = self.daemon.create_session(
            key_id="key-TEST-ONLY-0041", provider="gemini",
            session_class="read_public")
        session = created.session
        body_sha = hashlib.sha256(b"{}").hexdigest()
        ts = int(time.time())
        canonical = f"POST\n127.0.0.1:8765\n/v1/models\n{body_sha}\n{ts}"
        pop = hmac.new(created.pop_key, canonical.encode(),
                       hashlib.sha256).hexdigest()
        self.assertTrue(self.daemon.broker.verify_pop(
            session, method="POST", host="127.0.0.1:8765",
            canonical_path="/v1/models", body_sha256_hex=body_sha,
            timestamp=ts, pop_hex=pop, nonce="nonce-TEST-001"))
        # Replay with the same nonce is denied (append-only cache).
        self.assertFalse(self.daemon.broker.verify_pop(
            session, method="POST", host="127.0.0.1:8765",
            canonical_path="/v1/models", body_sha256_hex=body_sha,
            timestamp=ts, pop_hex=pop, nonce="nonce-TEST-001"))
        # Tampered PoP and stale timestamps are denied, no fallback.
        self.assertFalse(self.daemon.broker.verify_pop(
            session, method="POST", host="127.0.0.1:8765",
            canonical_path="/v1/models", body_sha256_hex=body_sha,
            timestamp=ts, pop_hex="0" * 64))
        self.assertFalse(self.daemon.broker.verify_pop(
            session, method="POST", host="127.0.0.1:8765",
            canonical_path="/v1/models", body_sha256_hex=body_sha,
            timestamp=ts - 3600, pop_hex=pop))

    def test_ttl_table_clamps(self):
        destructive = self.daemon.create_session(
            key_id="key-TEST-ONLY-0042", provider="github",
            session_class="destructive", requested_ttl_s=999999)
        ttl = destructive.session.expires_at - destructive.session.created_at
        self.assertEqual(ttl, 15 * 60)  # destructive cap, not 2 h, not requested
        public = self.daemon.create_session(
            key_id="key-TEST-ONLY-0043", provider="gemini",
            session_class="read_public")
        ttl = public.session.expires_at - public.session.created_at
        self.assertEqual(ttl, 60 * 60)  # read_public default

    def test_connect_refused_for_write_and_destructive(self):
        from keyholder.broker import SessionCreateError
        with self.assertRaises(SessionCreateError):
            self.daemon.create_session(
                key_id="key-TEST-ONLY-0044", provider="github",
                session_class="write", transport="connect_allowed")
        with self.assertRaises(SessionCreateError):
            self.daemon.create_session(
                key_id="key-TEST-ONLY-0045", provider="github",
                session_class="destructive", transport="connect_allowed")

    def test_no_session_extension_api(self):
        # v3 §1B N-B2: no extensions, ever. Re-issuance = new session.
        self.assertFalse(hasattr(self.daemon.broker, "extend"))
        self.assertFalse(hasattr(self.daemon.broker, "extend_session"))

    def test_idle_refresh_only_on_successful_call(self):
        created = self.daemon.create_session(
            key_id="key-TEST-ONLY-0046", provider="github",
            session_class="read_public")
        before = created.session.idle_deadline
        time.sleep(0.05)
        self.assertTrue(self.daemon.broker.record_successful_call(
            created.session.session_id))
        after = self.daemon.broker.get_session(
            created.session.session_id).idle_deadline
        self.assertGreater(after, before)


class DaemonIPCProtocolTest(unittest.TestCase):
    """v0.2: the in-process Daemon serves the full JSON-line IPC
    protocol over its socket (status/sessions/doctor/errors), not
    just status/ping. Malformed input must not kill the server."""

    def setUp(self):
        self.daemon = make_daemon()
        self.addCleanup(self._stop_quietly)

    def _stop_quietly(self):
        try:
            self.daemon.stop()
        except Exception:
            pass

    def _rpc(self, request: dict) -> dict:
        path = self.daemon.status().socket_path
        self.assertIsNotNone(path)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(5.0)
            conn.connect(path)
            conn.sendall(json.dumps(request).encode() + b"\n")
            data = b""
            while b"\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
        return json.loads(data.decode())

    def test_json_line_protocol_and_errors(self):
        reply = self._rpc({"id": 7, "cmd": "status", "args": {}})
        self.assertTrue(reply["ok"])
        self.assertTrue(reply["result"]["running"])
        self.assertEqual(reply["id"], 7)
        self.assertEqual(self._rpc({"id": 8, "cmd": "sessions.list",
                                    "args": {}})["result"], {"sessions": []})
        doctor = self._rpc({"id": 9, "cmd": "doctor", "args": {}})["result"]
        self.assertIn("Tier B", doctor["tier_b_note"])
        audit = self._rpc({"id": 10, "cmd": "audit.verify", "args": {}})
        self.assertFalse(audit["ok"])
        self.assertEqual(audit["error"]["code"], "KH-1005")
        unknown = self._rpc({"id": 11, "cmd": "nope", "args": {}})
        self.assertEqual(unknown["error"]["code"], "KH-2001")

    def test_malformed_json_does_not_kill_server(self):
        path = self.daemon.status().socket_path
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(5.0)
            conn.connect(path)
            conn.sendall(b"{not json\n")
            data = conn.recv(4096)
        reply = json.loads(data.decode())
        self.assertFalse(reply["ok"])
        self.assertEqual(reply["error"]["code"], "KH-2001")
        # Server still answers afterwards.
        self.assertTrue(self._rpc({"id": 1, "cmd": "ping",
                                   "args": {}})["result"]["ok"])


if __name__ == "__main__":
    unittest.main()
