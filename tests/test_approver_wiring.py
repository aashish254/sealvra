"""W02 v0.2 — real approver wiring tests (CONTRACT §13.2).

Proves the proxy's PRODUCTION path uses the broker-owned real
approver (approval.RealApprover via approval.proxy_approver), and
that test approvers only enter through the explicit test-only
parameter under the test-harness marker SEALVRA_TEST_APPROVER=1
(set only by tests in this file, restored afterwards).

Loopback mocks only, fake TEST-ONLY keys only, no contact with any
real provider. Run with the project venv (cryptography is required
for the broker's signed decisions):
  .venv/bin/python -m unittest tests.test_approver_wiring -v
"""

import json
import os
import sys
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sealvra.approval import (  # noqa: E402
    ApprovalBroker,
    ApprovalDecision,
    ApprovalError,
    ApprovalKind,
    DenyReason,
    ProductionApprovalRequest,
    RealApprover,
    compute_production_request_hash,
    mark_test_approver,
    proxy_approver,
)
from sealvra.proxy import ProxyConfig, ProxyEngine, canonicalise_target  # noqa: E402
from sealvra.tokens import sign_request  # noqa: E402
from sealvra.types import PolicyDecision, Session  # noqa: E402

FAKE_KEY = "TEST-ONLY-GITHUB-FAKE-KEY-0001"
POP_KEY = b"TEST-ONLY-POP-KEY-0000000000000001"
TOKEN = "kh_sess_TEST-ONLY-TOKEN-0001"
MARKER = "SEALVRA_TEST_APPROVER"


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class _MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "W02Mock/0.1"

    def log_message(self, *args):
        pass

    def _handle(self, method):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        parsed = urllib.parse.urlparse(self.path)
        with self.server.lock:
            self.server.hits[parsed.path] = \
                self.server.hits.get(parsed.path, 0) + 1
            self.server.last_auth = self.headers.get("Authorization")
        payload = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = lambda self: self._handle("GET")
    do_POST = lambda self: self._handle("POST")
    do_PUT = lambda self: self._handle("PUT")
    do_DELETE = lambda self: self._handle("DELETE")


def _make_session(session_class="write"):
    now = time.time()
    return Session(session_id="sess-test0000000001", key_id="key-0123456789abcdef",
                   provider="github", session_class=session_class,
                   transport="absolute", created_at=now,
                   expires_at=now + 3600, idle_deadline=now + 300,
                   process_group="test-group", ancestry="test")


def _signed(session, base, method, target, body=b"", ts_offset=0):
    canon = canonicalise_target(target, None, base, test_mode=True)
    pop, ts = sign_request(POP_KEY, method, canon.host,
                           canon.canonical_path, body,
                           timestamp=int(time.time()) + ts_offset)
    headers = [("X-Sealvra-Session", TOKEN),
               ("X-Sealvra-Pop", pop),
               ("X-Sealvra-Timestamp", str(ts)),
               ("Host", canon.host)]
    return headers


def _real_approver(gesture=None, clock=None):
    broker = ApprovalBroker(clock=clock, min_card_dwell_s=0) \
        if clock is not None else ApprovalBroker(min_card_dwell_s=0)
    approver = RealApprover(broker, gesture=gesture,
                            clock=clock) if clock is not None \
        else RealApprover(broker, gesture=gesture)
    return approver, broker


def _resolver(session):
    return ("TEST-ONLY GitHub", "aabbccddeeff")


def _level3(session, method, path, body, content_type):
    return PolicyDecision(allowed=False, level=3, reason="needs approval",
                          rule_id="TEST-APPROVE")


class WiringTestBase(unittest.TestCase):
    mock = None

    @classmethod
    def setUpClass(cls):
        cls.mock = ThreadingHTTPServer(("127.0.0.1", 0), _MockHandler)
        cls.mock.daemon_threads = True
        cls.mock.lock = threading.Lock()
        cls.mock.hits = {}
        cls.mock.last_auth = None
        cls.port = cls.mock.server_address[1]
        cls.base = "http://127.0.0.1:%d" % cls.port
        thread = threading.Thread(target=cls.mock.serve_forever,
                                  kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.mock.shutdown()
        cls.mock.server_close()

    def setUp(self):
        self._saved_marker = os.environ.get(MARKER)
        self.mock.hits.clear()
        self.mock.last_auth = None

    def tearDown(self):
        if self._saved_marker is None:
            os.environ.pop(MARKER, None)
        else:
            os.environ[MARKER] = self._saved_marker

    def make_engine(self, session, approver=None, test_approver=None,
                    decide=None):
        cfg = ProxyConfig(test_mode=True, bases={"github": self.base})
        engine = ProxyEngine(
            cfg, lambda token: session if token == TOKEN else None,
            lambda sid: POP_KEY,
            decide or _level3,
            approver,
            lambda entry: None, lambda entry: None,
            lambda kid: FAKE_KEY, lambda sid: None,
            test_approver=test_approver)
        return engine


class TestProductionPath(WiringTestBase):
    def test_approved_call_forwards_with_real_approver(self):
        session = _make_session("write")
        approver, _ = _real_approver(gesture=lambda prompt: True)
        engine = self.make_engine(session,
                                  approver=proxy_approver(approver,
                                                          card_resolver=_resolver))
        resp = engine.handle("PUT", self.base + "/repos/o/r/contents/f.txt",
                             _signed(session, self.base, "PUT",
                                     self.base + "/repos/o/r/contents/f.txt",
                                     b"{}"), b"{}")
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.mock.hits.get("/repos/o/r/contents/f.txt"), 1)
        self.assertEqual(self.mock.last_auth, "Bearer " + FAKE_KEY)

    def test_refused_call_denies_and_never_forwards(self):
        session = _make_session("write")
        approver, _ = _real_approver(gesture=lambda prompt: False)
        engine = self.make_engine(session,
                                  approver=proxy_approver(approver,
                                                          card_resolver=_resolver))
        resp = engine.handle("PUT", self.base + "/repos/o/r/contents/f.txt",
                             _signed(session, self.base, "PUT",
                                     self.base + "/repos/o/r/contents/f.txt",
                                     b"{}"), b"{}")
        self.assertEqual(resp.status, 403)
        self.assertEqual(resp.body, b'{"error": "denied"}')
        self.assertIsNone(self.mock.hits.get("/repos/o/r/contents/f.txt"))

    def test_timed_out_call_denies(self):
        clock = FakeClock()
        session = _make_session("write")

        def slow_gesture(prompt):
            clock.advance(61.0)  # past the 60 s default, inside no opt-in
            return True

        approver, _ = _real_approver(gesture=slow_gesture, clock=clock)
        engine = self.make_engine(session,
                                  approver=proxy_approver(approver,
                                                          card_resolver=_resolver))
        resp = engine.handle("PUT", self.base + "/repos/o/r/contents/f.txt",
                             _signed(session, self.base, "PUT",
                                     self.base + "/repos/o/r/contents/f.txt",
                                     b"{}"), b"{}")
        self.assertEqual(resp.status, 403)
        self.assertIsNone(self.mock.hits.get("/repos/o/r/contents/f.txt"))
        # Direct proof of the reason, not just the generic denial body.
        decision = approver.approve(ProductionApprovalRequest(
            session_pseudonym="sess-test0000000001", session_id="sess-x",
            key_id="key-0123456789abcdef", provider="github", method="PUT",
            path="/repos/o/r/contents/f.txt", scope_summary="write file",
            key_label="TEST-ONLY GitHub", key_fingerprint_12="aabbccddeeff",
            permissions="write file", purpose="write file",
            kind=ApprovalKind.SESSION_SCOPE.value))
        self.assertFalse(decision.approved)
        self.assertEqual(decision.deny_reason,
                         DenyReason.TIMEOUT_DENY.value)

    def test_accessibility_timeout_120s_allows_61s_gesture(self):
        clock = FakeClock()
        session = _make_session("write")

        def slow_gesture(prompt):
            clock.advance(61.0)
            return True

        approver, _ = _real_approver(gesture=slow_gesture, clock=clock)
        approver.accessibility = True
        engine = self.make_engine(session,
                                  approver=proxy_approver(approver,
                                                          card_resolver=_resolver))
        resp = engine.handle("PUT", self.base + "/repos/o/r/contents/f.txt",
                             _signed(session, self.base, "PUT",
                                     self.base + "/repos/o/r/contents/f.txt",
                                     b"{}"), b"{}")
        self.assertEqual(resp.status, 200)

    def test_no_approver_denies_level3_fail_closed(self):
        session = _make_session("write")
        engine = self.make_engine(session, approver=None)
        resp = engine.handle("PUT", self.base + "/repos/o/r/contents/f.txt",
                             _signed(session, self.base, "PUT",
                                     self.base + "/repos/o/r/contents/f.txt",
                                     b"{}"), b"{}")
        self.assertEqual(resp.status, 403)
        self.assertIsNone(self.mock.hits.get("/repos/o/r/contents/f.txt"))

    def test_no_gesture_available_denies(self):
        # gesture=None = no OS system prompt on this machine: the real
        # approver must deny, never invent a yes.
        session = _make_session("write")
        approver, _ = _real_approver(gesture=None)
        engine = self.make_engine(session,
                                  approver=proxy_approver(approver,
                                                          card_resolver=_resolver))
        resp = engine.handle("PUT", self.base + "/repos/o/r/contents/f.txt",
                             _signed(session, self.base, "PUT",
                                     self.base + "/repos/o/r/contents/f.txt",
                                     b"{}"), b"{}")
        self.assertEqual(resp.status, 403)
        self.assertIsNone(self.mock.hits.get("/repos/o/r/contents/f.txt"))

    def test_destructive_call_forwards_only_with_fresh_approval(self):
        session = _make_session("destructive")
        approver, _ = _real_approver(gesture=lambda prompt: True)
        engine = self.make_engine(session,
                                  approver=proxy_approver(approver,
                                                          card_resolver=_resolver))
        resp = engine.handle("DELETE", self.base + "/repos/o/r",
                             _signed(session, self.base, "DELETE",
                                     self.base + "/repos/o/r"), b"")
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.mock.hits.get("/repos/o/r"), 1)

    def test_second_identical_call_needs_fresh_approval(self):
        # Gesture stub allows exactly one ceremony; the second
        # identical call must not ride the first approval.
        session = _make_session("write")
        calls = {"n": 0}

        def once(prompt):
            calls["n"] += 1
            return calls["n"] == 1

        approver, _ = _real_approver(gesture=once)
        engine = self.make_engine(session,
                                  approver=proxy_approver(approver,
                                                          card_resolver=_resolver))
        first = engine.handle("PUT", self.base + "/repos/o/r/contents/f.txt",
                              _signed(session, self.base, "PUT",
                                      self.base + "/repos/o/r/contents/f.txt",
                                      b"{}"), b"{}")
        # Distinct PoP (later timestamp) so the denial is the approval
        # gate, not the PoP replay cache (which would also deny, 401).
        second = engine.handle("PUT", self.base + "/repos/o/r/contents/f.txt",
                               _signed(session, self.base, "PUT",
                                       self.base + "/repos/o/r/contents/f.txt",
                                       b"{}", ts_offset=2), b"{}")
        self.assertEqual(first.status, 200)
        self.assertEqual(second.status, 403)
        self.assertEqual(self.mock.hits.get("/repos/o/r/contents/f.txt"), 1)


class TestReplayDenied(WiringTestBase):
    def _decision(self, approver):
        return approver.approve(ProductionApprovalRequest(
            session_pseudonym="sess-test0000000001", session_id="sess-x",
            key_id="key-0123456789abcdef", provider="github", method="PUT",
            path="/repos/o/r/contents/f.txt", scope_summary="write file",
            key_label="TEST-ONLY GitHub", key_fingerprint_12="aabbccddeeff",
            permissions="write file", purpose="write file",
            kind=ApprovalKind.SESSION_SCOPE.value))

    def test_replayed_decision_denied_at_consume(self):
        approver, _ = _real_approver(gesture=lambda prompt: True)
        decision = self._decision(approver)
        self.assertTrue(decision.approved)
        self.assertTrue(approver.consume(decision,
                                         request_hash=decision.request_hash))
        # Replay: same Decision presented a second time.
        self.assertFalse(approver.consume(
            decision, request_hash=decision.request_hash))
        # Wrong-hash presentation also denies.
        self.assertFalse(approver.consume(
            decision, request_hash="0" * 64))

    def test_replayed_signed_decision_rejected_by_broker(self):
        broker = ApprovalBroker(min_card_dwell_s=0)
        from sealvra.approval import build_card, compute_request_hash
        card = build_card(
            approval_id="appr-test", key_id="key-0123456789abcdef",
            provider="github", key_label="TEST-ONLY GitHub",
            key_fingerprint_12="aabbccddeeff", permissions="write file",
            purpose="write file", kind=ApprovalKind.SESSION_SCOPE.value,
            other_key_count=0)
        pending = broker.request(
            session_id="sess-x", card=card,
            request_hash=compute_request_hash(
                key_id="key-0123456789abcdef", provider="github",
                method="PUT", canonical_path="/repos/o/r/contents/f.txt",
                scope_summary="write file",
                kind=ApprovalKind.SESSION_SCOPE.value, level=2),
            kind=ApprovalKind.SESSION_SCOPE.value,
            key_id="key-0123456789abcdef", provider="github", level=2)
        broker.continue_from_card(pending.approval_id)
        broker.record_gesture(pending.approval_id, ok=True)
        signed = broker.confirm(pending.approval_id)
        self.assertTrue(broker.verify_and_consume(signed))
        with self.assertRaises(ApprovalError) as ctx:
            broker.verify_and_consume(signed)
        self.assertEqual(ctx.exception.reason, DenyReason.NONCE_REPLAY)

    def test_tampered_request_hash_denied(self):
        approver, _ = _real_approver(gesture=lambda prompt: True)
        decision = self._decision(approver)
        tampered = ApprovalDecision(
            approved=True, approval_id=decision.approval_id,
            consumed_nonce=decision.consumed_nonce,
            decided_at=decision.decided_at,
            request_hash="f" * 64)
        # Presenting the tampered hash against the ORIGINAL request
        # hash must deny: the binding, not the presented value, rules.
        self.assertFalse(approver.consume(
            tampered, request_hash=decision.request_hash))


class TestKillNeedsNoAuth(WiringTestBase):
    def test_kill_pending_without_any_gesture(self):
        broker = ApprovalBroker(min_card_dwell_s=0)
        approver = RealApprover(broker, gesture=lambda prompt: True)
        from sealvra.approval import build_card, compute_request_hash
        card = build_card(
            approval_id="appr-test", key_id="key-0123456789abcdef",
            provider="github", key_label="TEST-ONLY GitHub",
            key_fingerprint_12="aabbccddeeff", permissions="write file",
            purpose="write file", kind=ApprovalKind.SESSION_SCOPE.value,
            other_key_count=0)
        pending = broker.request(
            session_id="sess-x", card=card,
            request_hash=compute_request_hash(
                key_id="key-0123456789abcdef", provider="github",
                method="PUT", canonical_path="/repos/o/r/contents/f.txt",
                scope_summary="write file",
                kind=ApprovalKind.SESSION_SCOPE.value, level=2),
            kind=ApprovalKind.SESSION_SCOPE.value,
            key_id="key-0123456789abcdef", provider="github", level=2)
        # Kill with no gesture, no confirm, no auth of any kind.
        approver.kill(pending.approval_id)
        self.assertIsNone(broker.active())
        with self.assertRaises(Exception):
            broker.confirm(pending.approval_id)

    def test_killed_session_call_denied_by_proxy(self):
        session = _make_session("write")
        killed = Session(**{**session.__dict__, "killed": True})
        approver, _ = _real_approver(gesture=lambda prompt: True)
        engine = self.make_engine(killed,
                                  approver=proxy_approver(approver,
                                                          card_resolver=_resolver))
        resp = engine.handle("PUT", self.base + "/repos/o/r/contents/f.txt",
                             _signed(killed, self.base, "PUT",
                                     self.base + "/repos/o/r/contents/f.txt",
                                     b"{}"), b"{}")
        self.assertEqual(resp.status, 401)
        self.assertIsNone(self.mock.hits.get("/repos/o/r/contents/f.txt"))


class TestCeremonyRules(WiringTestBase):
    def _destructive_request(self, **overrides):
        params = dict(
            session_pseudonym="sess-test0000000001", session_id="sess-x",
            key_id="key-0123456789abcdef", provider="github",
            method="DELETE", path="/repos/o/r", scope_summary="delete repo",
            key_label="TEST-ONLY GitHub", key_fingerprint_12="aabbccddeeff",
            permissions="delete repo", purpose="delete repo",
            kind=ApprovalKind.DESTRUCTIVE.value, is_destructive=True)
        params.update(overrides)
        return ProductionApprovalRequest(**params)

    def test_x11_destructive_refused_without_gesture(self):
        seen = []
        approver, _ = _real_approver(gesture=lambda p: seen.append(p) or True)
        decision = approver.approve(self._destructive_request(
            display_protocol="x11"))
        self.assertFalse(decision.approved)
        self.assertEqual(decision.deny_reason,
                         DenyReason.X11_DESTRUCTIVE_REFUSED.value)
        self.assertEqual(seen, [])  # no prompt was ever shown

    def test_broker_window_destructive_never_approved(self):
        seen = []
        approver, _ = _real_approver(gesture=lambda p: seen.append(p) or True)
        decision = approver.approve(self._destructive_request(
            broker_window_t3=True))
        self.assertFalse(decision.approved)
        self.assertEqual(decision.deny_reason,
                         DenyReason.BROKER_WINDOW_DESTRUCTIVE.value)
        self.assertEqual(seen, [])

    def test_remote_destructive_refused(self):
        approver, _ = _real_approver(gesture=lambda p: True)
        decision = approver.approve(self._destructive_request(
            remote_session=True))
        self.assertFalse(decision.approved)
        self.assertEqual(decision.deny_reason,
                         DenyReason.REMOTE_DESTRUCTIVE_REFUSED.value)

    def test_breakglass_alone_never_approves_destructive(self):
        from sealvra.approval import BreakGlass
        glass = BreakGlass(activation_id="bg-test",
                           active_until_monotonic=1e9, presence_at_wall=0.0)
        self.assertFalse(glass.covers_destructive())
        approver, _ = _real_approver(gesture=lambda p: False)
        decision = approver.approve(self._destructive_request(
            breakglass=glass))
        self.assertFalse(decision.approved)

    def test_session_creation_requires_two_step(self):
        approver, _ = _real_approver(gesture=lambda p: False)
        decision = approver.approve_session_creation(ProductionApprovalRequest(
            session_pseudonym="sess-test0000000001", session_id="sess-x",
            key_id="key-0123456789abcdef", provider="github", method="GET",
            path="/repos", scope_summary="create session",
            key_label="TEST-ONLY GitHub", key_fingerprint_12="aabbccddeeff",
            permissions="create session", purpose="create session"))
        self.assertFalse(decision.approved)
        approver_ok, _ = _real_approver(gesture=lambda p: True)
        decision_ok = approver_ok.approve_session_creation(
            ProductionApprovalRequest(
                session_pseudonym="sess-test0000000001", session_id="sess-x",
                key_id="key-0123456789abcdef", provider="github",
                method="GET", path="/repos", scope_summary="create session",
                key_label="TEST-ONLY GitHub",
                key_fingerprint_12="aabbccddeeff",
                permissions="create session", purpose="create session"))
        self.assertTrue(decision_ok.approved)

    def test_plain_request_without_card_data_denied(self):
        from sealvra.types import ApprovalRequest
        approver, _ = _real_approver(gesture=lambda p: True)
        decision = approver.approve(ApprovalRequest(
            approval_id="appr-plain", session_pseudonym="sess-x",
            provider="github", method="GET", path="/repos",
            scope_summary="read repos", created_at=0.0))
        self.assertFalse(decision.approved)


class TestTestApproverGuard(WiringTestBase):
    def test_test_approver_without_marker_raises(self):
        os.environ.pop(MARKER, None)
        session = _make_session("write")
        with self.assertRaises(RuntimeError):
            self.make_engine(session, test_approver=lambda *a: (True, "x"))

    def test_flagged_test_approver_without_marker_raises(self):
        os.environ.pop(MARKER, None)
        session = _make_session("write")
        fn = mark_test_approver(lambda *a: (True, "x"))
        with self.assertRaises(RuntimeError):
            self.make_engine(session, approver=fn)

    def test_test_approver_with_marker_forwards(self):
        os.environ[MARKER] = "1"
        session = _make_session("write")
        engine = self.make_engine(
            session,
            test_approver=mark_test_approver(lambda *a: (True, "appr-test-1")))
        resp = engine.handle("PUT", self.base + "/repos/o/r/contents/f.txt",
                             _signed(session, self.base, "PUT",
                                     self.base + "/repos/o/r/contents/f.txt",
                                     b"{}"), b"{}")
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.mock.hits.get("/repos/o/r/contents/f.txt"), 1)

    def test_approve_and_test_approver_together_rejected(self):
        os.environ[MARKER] = "1"
        session = _make_session("write")
        with self.assertRaises(ValueError):
            self.make_engine(session, approver=lambda *a: (True, "x"),
                             test_approver=lambda *a: (True, "y"))


if __name__ == "__main__":
    unittest.main()
