"""Tests for keyholder/proxy.py (W04, CONTRACT §6, v3 §1G).

STUBS ONLY: the broker (W01/W03), policy (W05), approver (W08), audit
(W09), and vault (W02) modules are not all finished, so every boundary
is stubbed inside THIS file. Production code (proxy.py) contains no
stubs. When the real modules land, these stubs are replaced by thin
adapters -- the engine's behaviour under test must not change.

Loopback mocks only, fake TEST-ONLY keys only, no contact with GitHub
or any real provider. Mock ports are ephemeral (port 0), never the
W15 fixed ports, so this suite cannot clash with the E2E run.

Run:  python3 -m unittest tests.test_w04_proxy -v
  (from ~/workspace/keyholder-build)
"""

import gzip
import json
import socket
import sys
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from keyholder.proxy import (  # noqa: E402
    GENERIC_DENIAL_BODY,
    HOST_ONLY_LABEL,
    ProxyConfig,
    ProxyEngine,
    canonicalise_target,
    contains_secret,
    make_server,
    validate_loopback_host,
)
from keyholder.tokens import sign_request  # noqa: E402
from keyholder.types import PolicyDecision, Session  # noqa: E402

FAKE_GITHUB_KEY = "TEST-ONLY-GITHUB-FAKE-KEY-0001"
FAKE_GEMINI_KEY = "TEST-ONLY-GEMINI-FAKE-KEY-0001"
POP_KEY = b"TEST-ONLY-POP-KEY-0000000000000001"
TOKEN = "kh_sess_TESTTOKEN00000000000000000001"


# ---------------------------------------------------------------------------
# Loopback mock upstream (ephemeral port; records hits + last request)
# ---------------------------------------------------------------------------

class _MockState:
    def __init__(self):
        self.lock = threading.Lock()
        self.hits = {}
        self.last = {}
        self.order = []  # shared ordering probe with the audit stub

    def record(self, key, method, path, headers, body):
        with self.lock:
            self.hits[key] = self.hits.get(key, 0) + 1
            self.last[key] = {"method": method, "path": path,
                              "headers": {k.lower(): v for k, v in headers.items()},
                              "body": body}
            self.order.append("upstream")


class _MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "W04Mock/0.1"

    def log_message(self, *args):
        pass

    def _read_body(self):
        length = self.headers.get("Content-Length")
        if not length:
            return b""
        return self.rfile.read(int(length))

    def _send(self, status, body, content_type="application/json",
              extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for key, value in (extra or []):
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self, method):
        parsed = urllib.parse.urlparse(self.path)
        body = self._read_body()
        state = self.server.state
        key = self.server.key_for_path(parsed.path)
        state.record(key, method, parsed.path, self.headers, body)
        if parsed.path == "/echo-query":
            # Query-only echo (no credential echo): lets query
            # canonicalisation tests read the forwarded query back
            # without tripping the response secret scan.
            return self._send(200, json.dumps(
                {"query": parsed.query}).encode())
        if parsed.path == "/echo-headers":
            payload = {
                "authorization": self.headers.get("Authorization", ""),
                "x-goog-api-key": self.headers.get("x-goog-api-key", ""),
                "session_header_seen": self.headers.get("X-Keyholder-Session") is not None,
                "accept_encoding": self.headers.get("Accept-Encoding", ""),
                "path": parsed.path,
                "query": parsed.query,
            }
            return self._send(200, json.dumps(payload).encode())
        if parsed.path == "/echo-key-gzip":
            raw = json.dumps({"echoed": self.server.echo_key}).encode()
            return self._send(200, gzip.compress(raw), extra=[("Content-Encoding", "gzip")])
        if parsed.path == "/echo-key-hex":
            return self._send(200, self.server.echo_key.encode().hex().encode(),
                              content_type="text/plain")
        if parsed.path == "/echo-key-url":
            return self._send(200, urllib.parse.quote_plus(self.server.echo_key).encode(),
                              content_type="text/plain")
        if parsed.path == "/echo-key-jsonesc":
            # Emit the \u002d escapes RAW on the wire (json.dumps
            # would double-escape the backslash and defeat the test).
            escaped = self.server.echo_key.replace("-", "\\u002d")
            return self._send(200, ('{"k": "%s"}' % escaped).encode())
        if parsed.path == "/credential":
            return self._send(200, json.dumps(
                {"access_token": "TEST-ONLY-NEW-TOKEN-0001"}).encode())
        if parsed.path == "/big":
            return self._send(200, b"x" * 100_000, content_type="text/plain")
        if parsed.path == "/sse":
            # SSE body with filler first (so the usage line lands in
            # a later 64 KiB read chunk) then a cumulative
            # usageMetadata line. ``?over=1`` selects an over-cap
            # total; otherwise the total stays under the test cap.
            filler = b"data: {\"text\": \"%s\"}\n\n" % (b"y" * 1000,)
            chunks = [filler] * 70
            total = 900 if parsed.query == "over=1" else 50
            chunks.append(
                ('data: {"usageMetadata": {"promptTokenCount": 10, '
                 '"candidatesTokenCount": %d}}\n\n' % total).encode())
            return self._send(200, b"".join(chunks),
                              content_type="text/event-stream")
        if parsed.path == "/ok":
            return self._send(200, json.dumps({"ok": True}).encode())
        return self._send(200, json.dumps({"ok": True, "path": parsed.path}).encode())

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")

    def do_PATCH(self):
        self._handle("PATCH")

    def do_DELETE(self):
        self._handle("DELETE")


def _start_mock():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MockHandler)
    server.daemon_threads = True
    server.state = _MockState()
    server.echo_key = FAKE_GITHUB_KEY
    server.key_for_path = lambda p: p.strip("/").split("/")[0] or "root"
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    return server, thread


# ---------------------------------------------------------------------------
# Stub boundaries (test file only)
# ---------------------------------------------------------------------------

class _Stubs:
    """Fake broker/policy/approver/audit/vault for one engine."""

    def __init__(self, session, decide=None, approve=None,
                 fail_decision_audit=False, fail_outcome_audit=False):
        self.session = session
        self.sessions = {TOKEN: session}
        self.decide_fn = decide
        self.approve_fn = approve
        self.fail_decision_audit = fail_decision_audit
        self.fail_outcome_audit = fail_outcome_audit
        self.audit_entries = []
        self.success_calls = []
        self.lookup_calls = 0
        self.keys = {"key-github-0001": FAKE_GITHUB_KEY,
                     "key-gemini-0001": FAKE_GEMINI_KEY}

    def lookup(self, token):
        self.lookup_calls += 1
        return self.sessions.get(token)

    def pop_key_for(self, session_id):
        return POP_KEY

    def decide(self, session, method, path, body, content_type):
        if self.decide_fn is not None:
            return self.decide_fn(session, method, path, body, content_type)
        return PolicyDecision(allowed=True, level=1, reason="test allow",
                              rule_id="TEST-ALLOW")

    def approve(self, session, method, path, scope_summary):
        if self.approve_fn is not None:
            return self.approve_fn(session, method, path, scope_summary)
        return True, "appr-test-0001"

    def audit_decision(self, entry):
        if self.fail_decision_audit:
            raise OSError("simulated audit disk failure")
        self.audit_entries.append(("decision", dict(entry)))

    def audit_outcome(self, entry):
        if self.fail_outcome_audit:
            raise OSError("simulated audit disk failure")
        self.audit_entries.append(("outcome", dict(entry)))

    def key_for(self, key_id):
        return self.keys.get(key_id)

    def on_success(self, session_id):
        self.success_calls.append(session_id)


def _make_session(provider="github", session_class="read_public",
                  transport="absolute", key_id="key-github-0001",
                  expires_in=3600, idle_in=300, killed=False):
    now = time.time()
    return Session(session_id="sess-test0000000001", key_id=key_id,
                   provider=provider, session_class=session_class,
                   transport=transport, created_at=now,
                   expires_at=now + expires_in, idle_deadline=now + idle_in,
                   process_group="test-group", ancestry="test",
                   killed=killed)


class ProxyTestBase(unittest.TestCase):
    mock = None

    @classmethod
    def setUpClass(cls):
        cls.mock, cls._thread = _start_mock()
        cls.port = cls.mock.server_address[1]
        cls.base = "http://127.0.0.1:%d" % cls.port

    @classmethod
    def tearDownClass(cls):
        cls.mock.shutdown()
        cls.mock.server_close()

    def setUp(self):
        self.mock.state.hits.clear()
        self.mock.state.last.clear()
        self.mock.state.order.clear()
        self.mock.echo_key = FAKE_GITHUB_KEY

    def make_engine(self, session=None, config=None, **stub_kw):
        session = session or _make_session()
        stubs = _Stubs(session, **stub_kw)
        cfg = config or ProxyConfig(
            test_mode=True, bases={"github": self.base, "gemini": self.base})
        engine = ProxyEngine(cfg, stubs.lookup, stubs.pop_key_for,
                             stubs.decide, stubs.approve,
                             stubs.audit_decision, stubs.audit_outcome,
                             stubs.key_for, stubs.on_success)
        return engine, stubs

# The helper above needs the session, so tests build headers directly.
def signed_for(session, base, method, target, body=b"", host_header=None,
               token=TOKEN, pop_key=POP_KEY, timestamp=None, extra=None):
    canon = canonicalise_target(target, host_header, base, test_mode=True)
    ts = int(timestamp) if timestamp is not None else int(time.time())
    pop, ts = sign_request(pop_key, method, canon.host,
                           canon.canonical_path, body, ts)
    headers = [("X-Keyholder-Session", token),
               ("X-Keyholder-PoP", pop),
               ("X-Keyholder-Timestamp", str(ts))]
    if host_header:
        headers.append(("Host", host_header))
    if extra:
        headers.extend(extra)
    return headers, canon


class TestAbsoluteFormAndInjection(ProxyTestBase):
    def test_absolute_form_forwards_with_bearer_injection(self):
        session = _make_session()
        engine, stubs = self.make_engine(session)
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        resp = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(resp.status, 200)
        last = self.mock.state.last["ok"]
        self.assertEqual(last["headers"].get("authorization"),
                         "Bearer " + FAKE_GITHUB_KEY)
        self.assertIsNone(last["headers"].get("x-keyholder-session"))
        self.assertEqual(stubs.success_calls, ["sess-test0000000001"])

    def test_origin_form_forwards_with_matching_host(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        host = "127.0.0.1:%d" % self.port
        headers, _ = signed_for(session, self.base, "GET", "/ok",
                                host_header=host)
        resp = engine.handle("GET", "/ok", headers)
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.mock.state.hits.get("ok"), 1)

    def test_gemini_injects_x_goog_api_key_only(self):
        # NOTE: the relayed body is NOT asserted here -- the echo mock
        # returns the injected key in its body, so the response scanner
        # correctly blocks the relay (502). The injection proof is the
        # mock's recorded upstream headers.
        session = _make_session(provider="gemini", key_id="key-gemini-0001")
        engine, _ = self.make_engine(session)
        headers, _ = signed_for(session, self.base, "GET",
                                self.base + "/echo-headers")
        engine.handle("GET", self.base + "/echo-headers", headers)
        seen = self.mock.state.last["echo-headers"]["headers"]
        self.assertEqual(seen.get("x-goog-api-key"), FAKE_GEMINI_KEY)
        self.assertIsNone(seen.get("authorization"))

    def test_agent_authorization_is_stripped_not_forwarded(self):
        # Same note as above: assert on recorded upstream headers, not
        # the (correctly blocked) relayed echo body.
        session = _make_session()
        engine, _ = self.make_engine(session)
        headers, _ = signed_for(
            session, self.base, "GET", self.base + "/echo-headers",
            extra=[("Authorization", "Bearer AGENT-FAKE-KEY")])
        engine.handle("GET", self.base + "/echo-headers", headers)
        seen = self.mock.state.last["echo-headers"]["headers"]
        self.assertEqual(seen.get("authorization"), "Bearer " + FAKE_GITHUB_KEY)

    def test_query_key_param_denied(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        # Canonicalisation itself rejects credential query params.
        with self.assertRaises(ValueError):
            canonicalise_target(self.base + "/ok?key=EVIL", None,
                                self.base, test_mode=True)
        resp = engine.handle("GET", self.base + "/ok?key=EVIL",
                             [("X-Keyholder-Session", TOKEN)])
        self.assertEqual(resp.status, 400)
        self.assertEqual(self.mock.state.hits.get("ok"), None)


class TestCanonicalisationAttacks(ProxyTestBase):
    def test_asterisk_form_rejected(self):
        with self.assertRaises(ValueError):
            canonicalise_target("*", None, self.base, test_mode=True)

    def test_fragment_rejected(self):
        with self.assertRaises(ValueError):
            canonicalise_target(self.base + "/ok#frag", None,
                                self.base, test_mode=True)

    def test_backslash_rejected(self):
        with self.assertRaises(ValueError):
            canonicalise_target(self.base + "/repos\\evil", None,
                                self.base, test_mode=True)

    def test_split_first_then_decode_rejects_encoded_slash(self):
        # %2F must NOT become a segment separator (decode-then-split bug).
        with self.assertRaises(ValueError):
            canonicalise_target(self.base + "/repos/o%2Fr/contents/x", None,
                                self.base, test_mode=True)

    def test_encoded_dotdot_escape_rejected(self):
        with self.assertRaises(ValueError):
            canonicalise_target(self.base + "/%2e%2e/secret", None,
                                self.base, test_mode=True)

    def test_dot_segments_resolve_and_forwarded_equals_matched(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        headers, canon = signed_for(session, self.base, "GET",
                                    self.base + "/repos/a/../ok")
        self.assertEqual(canon.canonical_path, "/repos/ok")
        resp = engine.handle("GET", self.base + "/repos/a/../ok", headers)
        self.assertEqual(resp.status, 200)
        # The mock saw the canonical path, never the raw dotty path
        # (mock keys hits by first path segment: "repos").
        self.assertEqual(self.mock.state.last["repos"]["path"], "/repos/ok")

    def test_nul_rejected(self):
        # Canonicalisation runs before PoP, so a session header alone
        # is enough to reach the NUL rejection (no valid PoP can be
        # signed over an uncanonicalisable target).
        session = _make_session()
        engine, _ = self.make_engine(session)
        resp = engine.handle("GET", self.base + "/ok%00",
                             [("X-Keyholder-Session", TOKEN)])
        self.assertEqual(resp.status, 400)
        self.assertEqual(self.mock.state.hits.get("ok"), None)

    def test_non_provider_host_rejected(self):
        with self.assertRaises(ValueError):
            canonicalise_target("http://127.0.0.1:9999/ok", None,
                                self.base, test_mode=True)

    def test_duplicate_json_keys_rejected_at_depth(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        body = b'{"a": {"b": 1, "b": 2}}'
        headers, _ = signed_for(session, self.base, "POST",
                                self.base + "/ok", body=body,
                                extra=[("Content-Type", "application/json"),
                                       ("Content-Length", str(len(body)))])
        resp = engine.handle("POST", self.base + "/ok", headers, body)
        self.assertEqual(resp.status, 400)
        self.assertEqual(self.mock.state.hits.get("ok"), None)

    def test_cl_plus_te_rejected_by_engine(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok",
                                extra=[("Transfer-Encoding", "chunked")])
        resp = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(resp.status, 400)
        self.assertEqual(self.mock.state.hits.get("ok"), None)


class TestSessionAndPoP(ProxyTestBase):
    def test_missing_pop_denied(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        resp = engine.handle("GET", self.base + "/ok",
                             [("X-Keyholder-Session", TOKEN)])
        self.assertEqual(resp.status, 401)
        self.assertEqual(self.mock.state.hits.get("ok"), None)

    def test_bad_pop_denied(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok",
                                pop_key=b"WRONG-POP-KEY-00000000000000001")
        resp = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(resp.status, 401)
        self.assertEqual(self.mock.state.hits.get("ok"), None)

    def test_pop_replay_denied(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        first = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(first.status, 200)
        second = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(second.status, 401)
        self.assertEqual(self.mock.state.hits.get("ok"), 1)

    def test_pop_tampered_body_denied(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        headers, _ = signed_for(session, self.base, "POST",
                                self.base + "/ok", body=b"original")
        resp = engine.handle("POST", self.base + "/ok", headers, body=b"tampered")
        self.assertEqual(resp.status, 401)
        self.assertEqual(self.mock.state.hits.get("ok"), None)

    def test_pop_stale_timestamp_denied(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok",
                                timestamp=int(time.time()) - 1000)
        resp = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(resp.status, 401)

    def test_expired_killed_idle_sessions_denied(self):
        for kwargs in ({"expires_in": -10}, {"idle_in": -10},
                       {"killed": True}):
            session = _make_session(**kwargs)
            engine, _ = self.make_engine(session)
            headers, _ = signed_for(session, self.base, "GET",
                                    self.base + "/ok")
            resp = engine.handle("GET", self.base + "/ok", headers)
            self.assertEqual(resp.status, 401, kwargs)
            self.assertEqual(self.mock.state.hits.get("ok"), None)

    def test_denied_call_does_not_refresh_idle(self):
        session = _make_session()
        engine, stubs = self.make_engine(
            session, decide=lambda *a: PolicyDecision(
                allowed=False, level=4, reason="no", rule_id="TEST-DENY"))
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        resp = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(resp.status, 403)
        self.assertEqual(stubs.success_calls, [])

    def test_liveness_recheck_before_injection(self):
        session = _make_session()
        stubs = _Stubs(session)
        original_lookup = stubs.lookup
        state = {"calls": 0}

        def killing_lookup(token):
            state["calls"] += 1
            found = original_lookup(token)
            if found is not None and state["calls"] >= 2:
                found = Session(**{**found.__dict__, "killed": True})
            return found

        cfg = ProxyConfig(test_mode=True,
                          bases={"github": self.base, "gemini": self.base})
        engine = ProxyEngine(cfg, killing_lookup, stubs.pop_key_for,
                             stubs.decide, stubs.approve,
                             stubs.audit_decision, stubs.audit_outcome,
                             stubs.key_for, stubs.on_success)
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        resp = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(resp.status, 401)
        self.assertEqual(self.mock.state.hits.get("ok"), None)


class TestPolicyApprovalAudit(ProxyTestBase):
    def test_unmodelled_endpoint_denied(self):
        session = _make_session()
        engine, _ = self.make_engine(session, decide=lambda *a: None)
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        resp = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(resp.status, 403)
        self.assertEqual(self.mock.state.hits.get("ok"), None)

    def test_denials_are_generic(self):
        session = _make_session()
        engine, _ = self.make_engine(
            session, decide=lambda *a: PolicyDecision(
                allowed=False, level=4, reason="sensitive rule text",
                rule_id="R-123-SECRET"))
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        resp = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(resp.body, GENERIC_DENIAL_BODY)
        self.assertNotIn(b"R-123", resp.body)
        self.assertNotIn(b"sensitive", resp.body)

    def test_approval_gate_blocks_without_approval(self):
        session = _make_session()
        engine, _ = self.make_engine(
            session,
            decide=lambda *a: PolicyDecision(allowed=True, level=3,
                                              reason="needs approval",
                                              rule_id="TEST-APPROVE"),
            approve=lambda *a: (False, None))
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        resp = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(resp.status, 403)
        self.assertEqual(resp.body, GENERIC_DENIAL_BODY)
        self.assertEqual(self.mock.state.hits.get("ok"), None)

    def test_approval_gate_forwards_with_approval(self):
        session = _make_session()
        engine, stubs = self.make_engine(
            session,
            decide=lambda *a: PolicyDecision(allowed=True, level=3,
                                              reason="needs approval",
                                              rule_id="TEST-APPROVE"))
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        resp = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(resp.status, 200)
        kinds = [kind for kind, _ in stubs.audit_entries]
        self.assertIn("decision", kinds)
        decision = [e for k, e in stubs.audit_entries if k == "decision"][0]
        self.assertEqual(decision["approval_id"], "appr-test-0001")

    def test_audit_decision_written_before_forward(self):
        # Strict ordering proof: the decision audit and the mock both
        # append to the SAME shared list; decision must precede hit.
        session = _make_session()
        stubs = _Stubs(session)
        shared = self.mock.state.order

        def audit_decision(entry):
            shared.append("decision")
            stubs.audit_entries.append(("decision", dict(entry)))

        cfg = ProxyConfig(test_mode=True,
                          bases={"github": self.base, "gemini": self.base})
        engine = ProxyEngine(cfg, stubs.lookup, stubs.pop_key_for,
                             stubs.decide, stubs.approve, audit_decision,
                             stubs.audit_outcome, stubs.key_for,
                             stubs.on_success)
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        resp = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(resp.status, 200)
        self.assertEqual(shared, ["decision", "upstream"])

    def test_audit_failure_refuses_and_never_forwards(self):
        session = _make_session()
        engine, _ = self.make_engine(session, fail_decision_audit=True)
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        resp = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(resp.status, 503)
        self.assertEqual(resp.body, GENERIC_DENIAL_BODY)
        self.assertEqual(self.mock.state.hits.get("ok"), None)

    def test_outcome_audit_failure_degrades_future_calls(self):
        session = _make_session()
        engine, _ = self.make_engine(session, fail_outcome_audit=True)
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        first = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(first.status, 200)  # already forwarded: delivered
        self.assertTrue(engine.degraded)
        headers2, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        second = engine.handle("GET", self.base + "/ok", headers2)
        self.assertEqual(second.status, 503)
        self.assertEqual(self.mock.state.hits.get("ok"), 1)

    def test_credential_creating_endpoint_denied_before_forward(self):
        session = _make_session()
        decision = PolicyDecision(allowed=True, level=1, reason="ok",
                                  rule_id="TEST-CRED")
        decision.credential_creating = True
        engine, _ = self.make_engine(session, decide=lambda *a: decision)
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        resp = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(resp.status, 403)
        self.assertEqual(self.mock.state.hits.get("ok"), None)


class TestResponseScanning(ProxyTestBase):
    def _blocked(self, path):
        session = _make_session()
        engine, _ = self.make_engine(session)
        headers, _ = signed_for(session, self.base, "GET", self.base + path)
        resp = engine.handle("GET", self.base + path, headers)
        self.assertEqual(resp.status, 502, path)
        self.assertEqual(resp.body, GENERIC_DENIAL_BODY, path)
        self.assertNotIn(FAKE_GITHUB_KEY.encode(), resp.body, path)

    def test_gzipped_key_echo_blocked(self):
        self._blocked("/echo-key-gzip")

    def test_hex_key_echo_blocked(self):
        self._blocked("/echo-key-hex")

    def test_url_encoded_key_echo_blocked(self):
        self._blocked("/echo-key-url")

    def test_json_escaped_key_echo_blocked(self):
        self._blocked("/echo-key-jsonesc")

    def test_credential_creating_response_blocked(self):
        self._blocked("/credential")

    def test_contains_secret_forms(self):
        self.assertTrue(contains_secret(b"prefix " + FAKE_GITHUB_KEY.encode(), FAKE_GITHUB_KEY))
        self.assertTrue(contains_secret(FAKE_GITHUB_KEY.encode().hex().encode(), FAKE_GITHUB_KEY))
        self.assertTrue(contains_secret(
            urllib.parse.quote_plus(FAKE_GITHUB_KEY).encode(), FAKE_GITHUB_KEY))
        self.assertFalse(contains_secret(b"nothing here", FAKE_GITHUB_KEY))
        self.assertFalse(contains_secret(b"anything", ""))

    def test_stream_budget_aborts(self):
        session = _make_session()
        cfg = ProxyConfig(test_mode=True, max_response_bytes=1024,
                          bases={"github": self.base, "gemini": self.base})
        engine, _ = self.make_engine(session, config=cfg)
        headers, _ = signed_for(session, self.base, "GET", self.base + "/big")
        resp = engine.handle("GET", self.base + "/big", headers)
        self.assertEqual(resp.status, 502)
        self.assertEqual(resp.body, GENERIC_DENIAL_BODY)


class TestConnectAndLoopback(ProxyTestBase):
    def test_connect_refused_by_default(self):
        session = _make_session()  # transport="absolute"
        engine, _ = self.make_engine(session)
        decision = engine.authorize_connect(
            "127.0.0.1:%d" % self.port,
            [("X-Keyholder-Session", TOKEN)])
        self.assertFalse(decision.allowed)

    def test_connect_refused_for_write_session_even_when_opted_in(self):
        session = _make_session(session_class="write",
                                transport="connect_allowed")
        engine, _ = self.make_engine(session)
        decision = engine.authorize_connect(
            "127.0.0.1:%d" % self.port,
            [("X-Keyholder-Session", TOKEN)])
        self.assertFalse(decision.allowed)

    def test_connect_opt_in_labels_host_only_policy(self):
        session = _make_session(session_class="read_public",
                                transport="connect_allowed")
        engine, stubs = self.make_engine(session)
        host = "127.0.0.1"
        pop, ts = sign_request(POP_KEY, "CONNECT", host, "/", b"", None)
        decision = engine.authorize_connect(
            "127.0.0.1:%d" % self.port,
            [("X-Keyholder-Session", TOKEN),
             ("X-Keyholder-PoP", pop),
             ("X-Keyholder-Timestamp", str(ts))])
        self.assertTrue(decision.allowed)
        entry = [e for k, e in stubs.audit_entries if k == "decision"][0]
        self.assertEqual(entry["transport_label"], HOST_ONLY_LABEL)
        self.assertEqual(entry["method"], "CONNECT")

    def test_non_loopback_bind_refused(self):
        with self.assertRaises(ValueError):
            validate_loopback_host("0.0.0.0")
        with self.assertRaises(ValueError):
            validate_loopback_host("8.8.8.8")
        # The dataclass itself does not validate; the engine does.
        session = _make_session()
        with self.assertRaises(ValueError):
            self.make_engine(
                session,
                config=ProxyConfig(host="0.0.0.0", test_mode=True,
                                   bases={"github": self.base,
                                          "gemini": self.base}))

    def test_non_loopback_bind_refused_at_server(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        with self.assertRaises(ValueError):
            make_server(engine.config, engine, host="0.0.0.0", port=0)

    def test_plain_http_base_refused_outside_test_mode(self):
        session = _make_session()
        cfg = ProxyConfig(test_mode=False,
                          bases={"github": self.base, "gemini": self.base})
        engine, _ = self.make_engine(session, config=cfg)
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        resp = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(resp.status, 502)
        self.assertEqual(self.mock.state.hits.get("ok"), None)


class TestLiveServerSmuggling(ProxyTestBase):
    """Raw-socket tests against the real HTTP layer: bare LF, folding,
    CL+TE, and CONNECT refusal must be rejected before the engine."""

    def setUp(self):
        super().setUp()
        session = _make_session()
        self.engine, self.stubs = self.make_engine(session)
        self.server = make_server(self.engine.config, self.engine, port=0)
        self.port_proxy = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.05},
                                       daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def _raw(self, data: bytes) -> bytes:
        sock = socket.create_connection(("127.0.0.1", self.port_proxy),
                                        timeout=5)
        try:
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
            out = b""
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                out += chunk
            return out
        finally:
            sock.close()

    def _status(self, raw: bytes) -> int:
        return int(raw.split(b" ", 2)[1])

    def test_raw_cl_plus_te_rejected(self):
        raw = self._raw(
            b"GET http://127.0.0.1:%d/ok HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 0\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n" % self.port)
        self.assertEqual(self._status(raw), 400)

    def test_raw_bare_lf_rejected(self):
        raw = self._raw(
            b"GET http://127.0.0.1:%d/ok HTTP/1.1\n"
            b"Host: 127.0.0.1\n\n" % self.port)
        self.assertEqual(self._status(raw), 400)

    def test_raw_header_folding_rejected(self):
        raw = self._raw(
            b"GET http://127.0.0.1:%d/ok HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b" X-Folded: yes\r\n\r\n" % self.port)
        self.assertEqual(self._status(raw), 400)

    def test_raw_connect_refused_default(self):
        raw = self._raw(
            b"CONNECT 127.0.0.1:%d HTTP/1.1\r\n"
            b"Host: 127.0.0.1:%d\r\n\r\n" % (self.port, self.port))
        self.assertEqual(self._status(raw), 405)

    def test_raw_valid_request_flows(self):
        session = _make_session()
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        lines = b"GET " + (self.base + "/ok").encode() + b" HTTP/1.1\r\n"
        for name, value in headers:
            lines += ("%s: %s\r\n" % (name, value)).encode()
        lines += b"Connection: close\r\n\r\n"
        raw = self._raw(lines)
        self.assertEqual(self._status(raw), 200)
        self.assertIn(b'"ok": true', raw)

    def test_raw_connect_tunnel_opt_in(self):
        session = _make_session(session_class="read_public",
                                transport="connect_allowed")
        engine, stubs = self.make_engine(session)
        server = make_server(engine.config, engine, port=0)
        proxy_port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            pop, ts = sign_request(POP_KEY, "CONNECT", "127.0.0.1", "/", b"", None)
            sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
            try:
                sock.sendall(
                    b"CONNECT 127.0.0.1:%d HTTP/1.1\r\n"
                    b"Host: 127.0.0.1:%d\r\n"
                    b"X-Keyholder-Session: %s\r\n"
                    b"X-Keyholder-PoP: %s\r\n"
                    b"X-Keyholder-Timestamp: %s\r\n\r\n"
                    % (self.port, self.port, TOKEN.encode(), pop.encode(),
                       str(ts).encode()))
                head = b""
                while b"\r\n\r\n" not in head:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    head += chunk
                self.assertIn(b"200 Connection Established", head)
                sock.sendall(b"GET /ok HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                             b"Connection: close\r\n\r\n")
                out = head.split(b"\r\n\r\n", 1)[1]
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    out += chunk
                self.assertIn(b'"ok": true', out)
            finally:
                sock.close()
            entry = [e for k, e in stubs.audit_entries if k == "decision"][0]
            self.assertEqual(entry["transport_label"], HOST_ONLY_LABEL)
        finally:
            server.shutdown()
            server.server_close()


# ---------------------------------------------------------------------------
# W11 (v0.2) additions: f06 proxy/policy hardening. Every test below
# asserts a denied/allowed OUTCOME (status + whether the mock upstream
# was hit), not a code path. The approve callable is untouched: these
# tests use the same stub approve signature as the rest of the file.
# ---------------------------------------------------------------------------

def _sse_observer(cap_total):
    """Usage observer for the /sse mock: returns True (over cap)
    once a cumulative usageMetadata total exceeds ``cap_total``."""
    import json as _json

    def observe(chunk):
        for line in chunk.decode("utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("data:"):
                line = line[len("data:"):].strip()
            if not line.startswith("{"):
                continue
            try:
                payload = _json.loads(line)
            except ValueError:
                continue
            usage = payload.get("usageMetadata") or {}
            total = (usage.get("promptTokenCount", 0) or 0) \
                + (usage.get("candidatesTokenCount", 0) or 0)
            if total > cap_total:
                return True
        return False

    return observe


class TestW11QueryCanonicalisation(ProxyTestBase):
    """f06 F-13: split-first-then-decode, checked form == forwarded form."""

    def test_encoded_separator_survives_as_literal(self):
        session = _make_session()
        engine, stubs = self.make_engine(session)
        target = self.base + "/echo-query?q=a%26b%3Dc&x=1"
        headers, _ = signed_for(session, self.base, "GET", target)
        resp = engine.handle("GET", target, headers)
        self.assertEqual(resp.status, 200)
        payload = json.loads(resp.body.decode())
        # The forwarded query keeps %26 as a literal '&' in the
        # value; the mock must NOT see a second parameter.
        self.assertEqual(payload["query"], "q=a%26b%3Dc&x=1")

    def test_duplicate_params_preserved_in_order(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        target = self.base + "/echo-query?a=1&a=2&b=3"
        headers, _ = signed_for(session, self.base, "GET", target)
        resp = engine.handle("GET", target, headers)
        self.assertEqual(resp.status, 200)
        self.assertEqual(json.loads(resp.body.decode())["query"], "a=1&a=2&b=3")

    def test_semicolon_in_value_never_becomes_separator(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        target = self.base + "/echo-query?x=1%3B2"
        headers, _ = signed_for(session, self.base, "GET", target)
        resp = engine.handle("GET", target, headers)
        self.assertEqual(resp.status, 200)
        self.assertEqual(json.loads(resp.body.decode())["query"], "x=1%3B2")

    def test_encoded_credential_param_name_denied(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        # %6bey decodes to "key" -- split-first decoding must still
        # catch it; the upstream must never be hit. The request
        # cannot even be PoP-signed (signing canonicalises first
        # and rejects), so dummy session headers suffice: the
        # engine rejects at canonicalisation, before PoP.
        target = self.base + "/ok?%6bey=EVIL"
        headers = [("X-Keyholder-Session", TOKEN),
                   ("X-Keyholder-PoP", "00"),
                   ("X-Keyholder-Timestamp", str(int(time.time())))]
        resp = engine.handle("GET", target, headers)
        self.assertEqual(resp.status, 400)
        self.assertEqual(resp.body, GENERIC_DENIAL_BODY)
        self.assertNotIn("ok", self.mock.state.hits)


class TestW11FormAndMultipartBodies(ProxyTestBase):
    """f06 F-10: form/multipart bodies are parsed at the proxy, not
    hash-only forwarded."""

    def _post(self, engine, session, body, content_type):
        target = self.base + "/ok"
        extra = [("Content-Type", content_type),
                 ("Content-Length", str(len(body)))]
        headers, _ = signed_for(session, self.base, "POST", target,
                                body=body, extra=extra)
        return engine.handle("POST", target, headers, body)

    def test_valid_form_body_forwards(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        resp = self._post(engine, session, b"action=comment&body=hello",
                          "application/x-www-form-urlencoded")
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.mock.state.hits.get("ok"), 1)

    def test_form_credential_field_denied_without_forward(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        resp = self._post(engine, session, b"action=x&api_key=TEST-ONLY",
                          "application/x-www-form-urlencoded")
        self.assertEqual(resp.status, 400)
        self.assertEqual(resp.body, GENERIC_DENIAL_BODY)
        self.assertNotIn("ok", self.mock.state.hits)

    def test_form_malformed_escape_denied(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        # %ff decodes to a byte that is invalid UTF-8: strict
        # decoding must reject it. (A bare "%zz" is not an escape
        # at all -- urllib leaves it literal -- so it is not the
        # malformed case.)
        resp = self._post(engine, session, b"a=%ff",
                          "application/x-www-form-urlencoded")
        self.assertEqual(resp.status, 400)
        self.assertNotIn("ok", self.mock.state.hits)

    def _multipart(self, parts, boundary="BND"):
        body = b""
        for name, data, ct in parts:
            body += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n"
                     "Content-Type: %s\r\n\r\n" % (boundary, name, ct)).encode()
            body += data + b"\r\n"
        body += ("--%s--\r\n" % boundary).encode()
        return body, "multipart/form-data; boundary=%s" % boundary

    def test_valid_multipart_forwards(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        body, ct = self._multipart([("note", b"hello", "text/plain")])
        resp = self._post(engine, session, body, ct)
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.mock.state.hits.get("ok"), 1)

    def test_multipart_credential_part_denied(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        body, ct = self._multipart([("token", b"TEST-ONLY", "text/plain")])
        resp = self._post(engine, session, body, ct)
        self.assertEqual(resp.status, 400)
        self.assertNotIn("ok", self.mock.state.hits)

    def test_multipart_json_part_duplicate_keys_denied(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        body, ct = self._multipart(
            [("doc", b'{"a": 1, "a": 2}', "application/json")])
        resp = self._post(engine, session, body, ct)
        self.assertEqual(resp.status, 400)
        self.assertNotIn("ok", self.mock.state.hits)

    def test_multipart_missing_closing_delimiter_denied(self):
        session = _make_session()
        engine, _ = self.make_engine(session)
        body = (b"--BND\r\nContent-Disposition: form-data; "
                b"name=\"note\"\r\n\r\nhello\r\n")
        resp = self._post(engine, session, body,
                          "multipart/form-data; boundary=BND")
        self.assertEqual(resp.status, 400)
        self.assertNotIn("ok", self.mock.state.hits)

    def test_content_type_less_json_duplicate_keys_denied(self):
        # A JSON-looking body with NO content type is still checked:
        # declaring no type must not smuggle duplicate keys past the
        # JSON gate.
        session = _make_session()
        engine, _ = self.make_engine(session)
        body = b'{"a": 1, "a": 2}'
        target = self.base + "/ok"
        headers, _ = signed_for(
            session, self.base, "POST", target, body=body,
            extra=[("Content-Length", str(len(body)))])
        resp = engine.handle("POST", target, headers, body)
        self.assertEqual(resp.status, 400)
        self.assertNotIn("ok", self.mock.state.hits)


class TestW11ConnectAuditSurfaces(ProxyTestBase):
    """f06 F-01: a tunnel's decision AND outcome entries both carry
    HOST-ONLY POLICY, and the outcome reports relayed bytes."""

    def test_tunnel_decision_and_outcome_both_labelled_host_only(self):
        session = _make_session(session_class="read_public",
                                transport="connect_allowed")
        engine, stubs = self.make_engine(session)
        server = make_server(engine.config, engine, port=0)
        proxy_port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            pop, ts = sign_request(POP_KEY, "CONNECT", "127.0.0.1", "/", b"", None)
            sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
            try:
                sock.sendall(
                    b"CONNECT 127.0.0.1:%d HTTP/1.1\r\n"
                    b"Host: 127.0.0.1:%d\r\n"
                    b"X-Keyholder-Session: %s\r\n"
                    b"X-Keyholder-PoP: %s\r\n"
                    b"X-Keyholder-Timestamp: %s\r\n\r\n"
                    % (self.port, self.port, TOKEN.encode(), pop.encode(),
                       str(ts).encode()))
                head = b""
                while b"\r\n\r\n" not in head:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    head += chunk
                self.assertIn(b"200 Connection Established", head)
                sock.sendall(b"GET /ok HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                             b"Connection: close\r\n\r\n")
                out = head.split(b"\r\n\r\n", 1)[1]
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    out += chunk
                self.assertIn(b'"ok": true', out)
            finally:
                sock.close()
            # The outcome audit lands after the tunnel closes, in the
            # handler thread: poll briefly rather than racing it.
            deadline = time.time() + 5.0
            outcomes = []
            while time.time() < deadline:
                outcomes = [e for k, e in stubs.audit_entries if k == "outcome"]
                if outcomes:
                    break
                time.sleep(0.05)
            decisions = [e for k, e in stubs.audit_entries if k == "decision"]
            self.assertTrue(decisions)
            for entry in decisions + outcomes:
                self.assertEqual(entry["transport_label"], HOST_ONLY_LABEL)
                self.assertTrue(entry["host_only"])
                self.assertEqual(entry["transport"], "connect_allowed")
                self.assertEqual(entry["method"], "CONNECT")
            self.assertTrue(outcomes)
            self.assertGreater(outcomes[0]["bytes_relayed"], 0)
            self.assertGreater(outcomes[0]["bytes_out"], 0)
        finally:
            server.shutdown()
            server.server_close()

    def test_absolute_request_from_connect_allowed_session_stays_absolute(self):
        # A connect_allowed session's absolute-form requests are
        # fully policed: label "absolute", transport recorded.
        session = _make_session(session_class="read_public",
                                transport="connect_allowed")
        engine, stubs = self.make_engine(session)
        headers, _ = signed_for(session, self.base, "GET", self.base + "/ok")
        resp = engine.handle("GET", self.base + "/ok", headers)
        self.assertEqual(resp.status, 200)
        decision = [e for k, e in stubs.audit_entries if k == "decision"][0]
        self.assertEqual(decision["transport_label"], "absolute")
        self.assertFalse(decision["host_only"])
        self.assertEqual(decision["transport"], "connect_allowed")


class TestW11StreamingUsageObserver(ProxyTestBase):
    """f06 F-15.2: an over-cap stream aborts before relay; an
    under-cap stream relays in full."""

    def _engine_with_observer(self, session, cap_total):
        stubs = _Stubs(session)
        cfg = ProxyConfig(test_mode=True,
                          bases={"github": self.base, "gemini": self.base})
        engine = ProxyEngine(cfg, stubs.lookup, stubs.pop_key_for,
                             stubs.decide, stubs.approve,
                             stubs.audit_decision, stubs.audit_outcome,
                             stubs.key_for, stubs.on_success,
                             usage_observer=_sse_observer(cap_total))
        return engine, stubs

    def test_over_cap_stream_blocked_with_generic_denial(self):
        session = _make_session()
        engine, _ = self._engine_with_observer(session, 500)
        headers, _ = signed_for(session, self.base, "GET",
                                self.base + "/sse?over=1")
        resp = engine.handle("GET", self.base + "/sse?over=1", headers)
        self.assertEqual(resp.status, 502)
        self.assertEqual(resp.body, GENERIC_DENIAL_BODY)

    def test_under_cap_stream_relayed(self):
        session = _make_session()
        engine, _ = self._engine_with_observer(session, 500)
        headers, _ = signed_for(session, self.base, "GET",
                                self.base + "/sse?over=0")
        resp = engine.handle("GET", self.base + "/sse?over=0", headers)
        self.assertEqual(resp.status, 200)
        self.assertIn(b"usageMetadata", resp.body)


if __name__ == "__main__":
    unittest.main()
