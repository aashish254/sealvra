"""Manager integration tests (not a worker module).

Wires the REAL modules together in-process — Broker (W01), policy
packs + PolicyEngine (W05), AuditLog (W09), ProxyEngine (W04) — and
drives them against the loopback mock providers (W15) with clearly
fake TEST-ONLY keys. This is the E2E path actually proven in v0.1.

What this deliberately does NOT prove (honest limits, see
BUILD-AND-TEST-REPORT.md):
  * Cross-process CLI <-> daemon persistence: the CLI's daemon
    commands are process-local in v0.1 (daemon.py module functions).
    No test here pretends a background daemon survives a CLI process.
  * The W08 approval ceremony end-to-end: the approve callable here
    is a test double returning (True, id) / (False, None). The real
    ApprovalBroker/Approver two-step ceremony is unit-tested by W08;
    its wiring into the proxy's approve callable is the next slice.
  * Native OS behaviour (Keychain, Touch ID, DPAPI, Hello): NOT-RUN
    on this Linux VM, as everywhere else.
"""

import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from keyholder.audit import AuditLog, pseudonym
from keyholder.broker import Broker
from keyholder.packs import load_pack
from keyholder.policy import PolicyEngine
from keyholder.proxy import ProxyConfig, ProxyEngine
from keyholder.tokens import body_sha256_hex, compute_pop

from tests.mock_providers import (
    MockServer,
    _GeminiHandler,
    _GitHubHandler,
)

ROOT = Path(__file__).resolve().parent.parent
FAKE_GITHUB_KEY = "TEST-ONLY-gh-integration-key"
FAKE_GEMINI_KEY = "TEST-ONLY-gemini-integration-key"
AUDIT_SECRET = b"TEST-ONLY-audit-secret-integration"


def _signed_headers(token, pop_key, method, host, path, body):
    ts = int(time.time())
    pop = compute_pop(pop_key, method, host, path, body, ts)
    headers = {
        "x-keyholder-session": token,
        "x-keyholder-pop": pop,
        "x-keyholder-timestamp": str(ts),
    }
    if body:
        headers["content-type"] = "application/json"
    return headers


class IntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ephemeral ports, not the fixed 18765/18766: in a full-suite
        # run W15's mocks may still hold the fixed ports, and a
        # fixed-port bind would fail with "Address already in use".
        # MockServer(port=0) binds an ephemeral port; .port/.base are
        # corrected from the real bound address below.
        cls.github_mock = MockServer("127.0.0.1", 0, _GitHubHandler).start()
        cls.github_mock.port = cls.github_mock.httpd.server_address[1]
        cls.github_mock.base = f"http://127.0.0.1:{cls.github_mock.port}"
        try:
            cls.gemini_mock = MockServer("127.0.0.1", 0, _GeminiHandler).start()
            cls.gemini_mock.port = cls.gemini_mock.httpd.server_address[1]
            cls.gemini_mock.base = f"http://127.0.0.1:{cls.gemini_mock.port}"
        except Exception:
            cls.github_mock.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        for server in (cls.github_mock, cls.gemini_mock):
            if server is not None:
                try:
                    server.stop()
                except Exception:
                    pass

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.broker = Broker()
        self.audit = AuditLog(Path(self._tmp.name), AUDIT_SECRET)
        self.github_engine = PolicyEngine(load_pack(ROOT / "packs" / "github.json"))
        self.gemini_engine = PolicyEngine(load_pack(ROOT / "packs" / "gemini.json"))
        self.keys = {}
        self.pop_keys = {}
        self.approve_result = (True, "appr-integration-0001")
        config = ProxyConfig(
            bases={
                "github": self.github_mock.base,
                "gemini": self.gemini_mock.base,
            },
            test_mode=True,
        )
        self.proxy = ProxyEngine(
            config,
            lookup_session=self.broker.validate_token,
            pop_key_for=lambda sid: self.pop_keys.get(sid),
            decide=self._decide,
            approve=self._approve,
            audit_decision=self._audit_decision,
            audit_outcome=self._audit_outcome,
            key_for=lambda kid: self.keys.get(kid),
            on_success=lambda sid: None,
        )

    def tearDown(self):
        self.audit.close()
        self._tmp.cleanup()

    # -- wiring adapters ------------------------------------------------
    def _decide(self, session, method, path, body, content_type):
        engine = self.github_engine if session.provider == "github" else self.gemini_engine
        # Empty body = no body: W05's parser rejects b"" as bad JSON,
        # so pass None for bodyless requests (manager adapter note;
        # the engine itself still rejects malformed non-empty JSON).
        return engine.decide(method, path, session.session_class,
                             body_raw=body if body else None)

    def _approve(self, session, method, path, scope_summary):
        return self.approve_result

    def _audit_decision(self, entry):
        self.audit.write_decision(
            pseudonym(AUDIT_SECRET, entry["session_id"]),
            pseudonym(AUDIT_SECRET, entry["key_id"]),
            entry["provider"], entry["method"], entry["canonical_path"],
            entry["decision"], rule_id=entry.get("rule_id"),
            approval_id=entry.get("approval_id"))

    def _audit_outcome(self, entry):
        self.audit.write_outcome(
            pseudonym(AUDIT_SECRET, entry["session_id"]),
            pseudonym(AUDIT_SECRET, entry["key_id"]),
            entry["provider"], entry["method"], entry["canonical_path"],
            entry["decision"], rule_id=entry.get("rule_id"),
            outcome=entry.get("outcome", "relayed"),
            approval_id=entry.get("approval_id"))

    def _new_session(self, provider, session_class):
        key_id = f"key-TEST-ONLY-int-{provider}-{session_class}"
        created = self.broker.create_session(
            key_id=key_id, provider=provider, session_class=session_class)
        self.keys[key_id] = FAKE_GITHUB_KEY if provider == "github" else FAKE_GEMINI_KEY
        self.pop_keys[created.session.session_id] = created.pop_key
        return created

    def _call(self, created, method, path, body=b""):
        # Test-mode wiring: the proxy requires the target authority to
        # match the configured upstream base, which in tests is the
        # loopback mock (not the real provider host). PoP is signed
        # over the canonical host the proxy will see.
        base = self.github_mock.base if created.session.provider == "github" else self.gemini_mock.base
        port = self.github_mock.port if created.session.provider == "github" else self.gemini_mock.port
        host = f"127.0.0.1:{port}"
        headers = _signed_headers(
            created.token, created.pop_key, method, host, path, body)
        return self.proxy.handle(method, base + path, headers, body)

    # -- tests ----------------------------------------------------------
    def test_github_read_injects_bearer_and_logs_audit(self):
        created = self._new_session("github", "read_account")
        resp = self._call(created, "GET", "/repos/o/r/contents/file.txt")
        self.assertEqual(resp.status, 200)
        self.assertNotIn(FAKE_GITHUB_KEY, resp.body.decode())
        hit = self.github_mock.last("contents_read")
        self.assertEqual(hit.get("auth"), "Bearer " + FAKE_GITHUB_KEY)
        result = self.audit.verify()
        self.assertEqual(result.status, "OK")

    def test_github_write_requires_approval_and_forwards_when_approved(self):
        created = self._new_session("github", "write")
        body = json.dumps({"message": "test", "content": "aGVsbG8="}).encode()
        resp = self._call(created, "PUT", "/repos/o/r/contents/file.txt", body)
        self.assertEqual(resp.status, 201)
        self.assertEqual(self.github_mock.count("contents_write"), 1)

    def test_github_write_denied_when_approver_refuses(self):
        self.approve_result = (False, None)
        created = self._new_session("github", "write")
        body = json.dumps({"message": "test", "content": "aGVsbG8="}).encode()
        resp = self._call(created, "PUT", "/repos/o/r/contents/file.txt", body)
        self.assertEqual(resp.status, 403)
        self.assertEqual(resp.body, b'{"error": "denied"}')
        self.assertEqual(self.github_mock.count("contents_write"), 0)

    def test_github_graphql_and_secrets_write_denied_not_forwarded(self):
        created = self._new_session("github", "destructive")
        body = json.dumps({"query": "{ viewer { login } }"}).encode()
        resp = self._call(created, "POST", "/graphql", body)
        self.assertEqual(resp.status, 403)
        self.assertEqual(self.github_mock.count("graphql"), 0)
        resp2 = self._call(created, "PUT", "/repos/o/r/actions/secrets/TEST",
                           json.dumps({"encrypted_value": "x"}).encode())
        self.assertEqual(resp2.status, 403)
        self.assertEqual(self.github_mock.count("secrets_write"), 0)

    def test_gemini_generate_injects_header_key_not_query_key(self):
        created = self._new_session("gemini", "write")
        body = json.dumps({"contents": [{"parts": [{"text": "hi"}]}]}).encode()
        resp = self._call(created, "POST", "/v1beta/models/gemini-test:generateContent", body)
        self.assertEqual(resp.status, 200)
        hit = self.gemini_mock.last("generate_content")
        self.assertEqual(hit.get("auth"), FAKE_GEMINI_KEY)
        self.assertNotIn(FAKE_GEMINI_KEY, resp.body.decode())

    def test_gemini_interactions_denied(self):
        created = self._new_session("gemini", "write")
        resp = self._call(created, "POST", "/v1beta/interactions",
                          json.dumps({}).encode())
        self.assertEqual(resp.status, 403)
        self.assertEqual(self.gemini_mock.count("interactions"), 0)

    def test_killed_session_cannot_call(self):
        created = self._new_session("github", "read_account")
        self.broker.kill_session(created.session.session_id)
        resp = self._call(created, "GET", "/repos/o/r/contents/file.txt")
        self.assertIn(resp.status, (401, 403))

    def test_replayed_pop_denied(self):
        created = self._new_session("github", "read_account")
        headers = _signed_headers(created.token, created.pop_key, "GET",
                                  f"127.0.0.1:{self.github_mock.port}",
                                  "/repos/o/r/contents/file.txt", b"")
        target = self.github_mock.base + "/repos/o/r/contents/file.txt"
        first = self.proxy.handle("GET", target, headers, b"")
        self.assertEqual(first.status, 200)
        second = self.proxy.handle("GET", target, headers, b"")
        self.assertEqual(second.status, 401)


if __name__ == "__main__":
    unittest.main()
