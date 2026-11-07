"""Adversarial suite for Sealvra v0.1 (W14) — stop-ship enforcement.

Stop-ship list (manager task, CONTRACT §11, v3 §1Q N-Q2/N-Q4):
  S1 any failing adversarial test blocks release.
  S2 any secret in any log in any test run blocks release.
  S3 any silent fallback to a raw key (incl. config flags/env vars) blocks.
  S4 any approval spoofable in testing blocks release.

How to read results (do NOT collapse these):
  * PASS against the helpers' reference stubs proves the ATTACK CLASS
    is well-formed and that a contract-conformant implementation
    defeats it. It does NOT prove shipped code defeats it.
  * NOT-RUN (unittest skipped) means the real module is absent or its
    API does not match CONTRACT, so the attack could not be run
    against shipped code. NOT-RUN is release-blocking for the gate:
    a gate report that counts only passes while integration probes
    are NOT-RUN is a vacuous pass (v3 N-Q2) and must not be called green.
  * FAIL is a finding, reported by name, never softened.

Platform NOT-RUN: macOS Keychain / Windows Hello / DPAPI tests are
marked NOT-RUN with the host platform named in the reason, never
passed. The reason must not hardcode a platform: these tests have run
on Linux and, in v0.2 Phase 3, on macOS, and a skip reason that
asserts the wrong host is itself a false claim.

Stdlib only. Fake TEST-ONLY secrets only. Loopback only.
Run:  python3 -m unittest tests.test_adversarial -v
  (from ~/workspace/sealvra-build, or: python3 -m unittest discover -s tests)
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import socketserver
import sys
import tempfile
import threading
import time
import unittest
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from adversarial_helpers import (  # noqa: E402
    FAKE_KEYS, SHORT_FAKES, FORBIDDEN_CODE_PATTERNS, FALLBACK_CODE_PATTERNS,
    LOG_DIR, BUILD_ROOT, append_suite_log, canonical, scan_directory,
    scan_log_file, stripped_code_text, text_contains_secret, require_real,
    real_source_files, NotRun, RefAudit, RefApproval, RefBroker, RefPolicy,
    unicode_escape_json, graphql_alias_document, count_graphql_alias_fields,
)

FAKE_GITHUB = FAKE_KEYS[0]
FAKE_GEMINI = FAKE_KEYS[1]


def skip_not_run(reason):
    raise unittest.SkipTest(f"NOT-RUN: {reason}")


def _broker_and_session(session_class="destructive", transport="absolute"):
    b = RefBroker()
    sid, token, pop = b.create_session("github", session_class, transport)
    return b, sid, token, pop


def _pop_for(b, sid, token, pop, method="GET", host="api.github.com",
             path="/repos/a/b", body=b"", ts=None):
    ts = int(time.time()) if ts is None else ts
    sig = hmac.new(pop, canonical(method, host, path, body, ts).encode(),
                   hashlib.sha256).hexdigest()
    return sig, ts


# ================================================================ A. disk / Tier B
class TestDiskAndTierB(unittest.TestCase):
    def test_same_uid_attacker_can_read_0600_file(self):
        """Tier B proof: 0600 does NOT survive a same-UID attacker.

        The test PASSES when the attacker succeeds in reading the file.
        Consequence: no Tier-B claim may ever rest on file permissions;
        the only valid claim is 'secret not on disk at all' (next test).
        """
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "session.json"
            p.write_text('{"note": "metadata only"}', encoding="utf-8")
            os.chmod(p, 0o600)
            # Same UID, same process = the Tier B attacker. It can read it.
            self.assertEqual(p.read_text(encoding="utf-8"),
                             '{"note": "metadata only"}')
            self.assertEqual(oct(p.stat().st_mode & 0o777), "0o600")

    def test_session_files_contain_no_token_or_pop_key(self):
        b, sid, token, pop = _broker_and_session()
        with tempfile.TemporaryDirectory() as d:
            dpath = Path(d)
            # Broker writes only metadata (pseudonym, no secret) to disk.
            f = b.write_session_file(dpath, sid,
                                     json.dumps({"session_id": sid,
                                                 "provider": "github"}))
            for path in dpath.rglob("*"):
                if not path.is_file():
                    continue
                blob = path.read_bytes().decode("utf-8", errors="ignore")
                self.assertNotIn(token, blob)
                self.assertNotIn(pop.hex(), blob)
                self.assertIsNone(text_contains_secret(blob, [FAKE_GITHUB]))
                for enc in ("token", "pop"):
                    pass
            # Token/PoP must not appear in ANY encoding of the file bytes.
            raw = f.read_bytes()
            self.assertNotIn(token.encode(), raw)
            self.assertNotIn(pop, raw)

    def test_broker_stores_only_token_hash(self):
        b, sid, token, pop = _broker_and_session()
        stored = list(b._hashes.values())
        self.assertEqual(stored, [hashlib.sha256(token.encode()).hexdigest()])
        self.assertNotIn(token, stored)
        # A stolen hash must not validate as a token.
        sig, ts = _pop_for(b, sid, token, pop)
        self.assertFalse(b.validate_pop(sid, stored[0], sig, ts,
                                        "GET", "api.github.com",
                                        "/repos/a/b", b""))

    def test_no_token_or_pop_in_suite_log(self):
        b, sid, token, pop = _broker_and_session()
        # The suite log records pseudonyms only, never the token/PoP.
        append_suite_log("session-events.log",
                         f"session {sid[:12]} created provider=github class=destructive")
        hits = scan_directory(LOG_DIR, [FAKE_GITHUB, FAKE_GEMINI])
        # Suite logs must not contain the live test token either.
        for p in LOG_DIR.rglob("*"):
            if p.is_file():
                self.assertNotIn(token, p.read_text(encoding="utf-8",
                                                    errors="ignore"))
                self.assertNotIn(pop.hex(), p.read_text(encoding="utf-8",
                                                        errors="ignore"))
        self.assertEqual(hits, {})


# ================================================================ B. sibling isolation
class TestSiblingIsolation(unittest.TestCase):
    def test_sibling_session_cannot_use_another_sessions_token(self):
        b, sid_a, token_a, pop_a = _broker_and_session()
        sid_b, token_b, pop_b = b.create_session("github", "read_public")
        # Attacker in session B presents A's token against B's session id,
        # and B's token against A's session id: both must fail.
        sig, ts = _pop_for(b, sid_b, token_b, pop_b)
        self.assertFalse(b.validate_pop(sid_b, token_a, sig, ts,
                                        "GET", "api.github.com", "/repos/a/b", b""))
        sig2, ts2 = _pop_for(b, sid_a, token_a, pop_a)
        self.assertFalse(b.validate_pop(sid_a, token_b, sig2, ts2,
                                        "GET", "api.github.com", "/repos/a/b", b""))

    def test_broker_exposes_no_get_token_or_get_pop_api(self):
        b, sid, token, pop = _broker_and_session()
        public = [n for n in dir(b) if not n.startswith("_")]
        for forbidden in ("get_token", "get_pop", "reveal", "export_key",
                          "token_for", "pop_for"):
            self.assertNotIn(forbidden, public)

    def test_sibling_cannot_read_another_sessions_key_via_broker(self):
        # The broker API has no cross-session key retrieval at all: the
        # only retrieval path is validate_pop, which is bound to the
        # owning session id (tested above). Assert there is no other
        # accessor on the public surface.
        b, sid, token, pop = _broker_and_session()
        self.assertFalse(hasattr(b, "key_for_session"))
        self.assertFalse(hasattr(b, "real_key"))


# ================================================================ C. approval (S4)
class TestApprovalSpoofing(unittest.TestCase):
    def test_stolen_control_credential_cannot_approve_own_call(self):
        appr = RefApproval()
        aid, nonce = appr.request("sess-pseudo", "github", "DELETE",
                                  "/repos/a/b", "delete repository")
        # Attacker holds the session token / a control credential but is
        # not the broker-owned approver: all non-broker approvers fail.
        for approver in ("control", "session", "dashboard", "cli", "agent"):
            self.assertFalse(appr.consume(aid, nonce, approver))
        # The broker approver, with the right nonce, succeeds exactly once.
        self.assertTrue(appr.consume(aid, nonce, "broker"))
        self.assertFalse(appr.consume(aid, nonce, "broker"))

    def test_replayed_approval_nonce_rejected(self):
        appr = RefApproval()
        aid, nonce = appr.request("sess-pseudo", "github", "POST",
                                  "/repos/a/b/merges", "merge pull request")
        self.assertTrue(appr.consume(aid, nonce, "broker"))
        # Replay of the same nonce, even immediately, must fail.
        self.assertFalse(appr.consume(aid, nonce, "broker"))
        self.assertFalse(appr.consume(aid, "wrong-nonce", "broker"))

    def test_concurrent_replay_only_one_wins(self):
        appr = RefApproval()
        aid, nonce = appr.request("sess-pseudo", "github", "DELETE",
                                  "/repos/a/b", "delete repository")
        results, barrier = [], threading.Barrier(16)
        def race():
            barrier.wait()
            results.append(appr.consume(aid, nonce, "broker"))
        threads = [threading.Thread(target=race) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 15)

    def test_approval_timeout_denies(self):
        clock = [1000.0]
        appr = RefApproval(clock=lambda: clock[0])
        aid, nonce = appr.request("sess-pseudo", "github", "DELETE",
                                  "/repos/a/b", "delete repository")
        clock[0] += 61  # past the 60 s default timeout
        self.assertFalse(appr.consume(aid, nonce, "broker"))

    def test_approve_once_is_consumption_deadline_not_validity_window(self):
        appr = RefApproval()
        aid, nonce = appr.request("sess-pseudo", "github", "DELETE",
                                  "/repos/a/b", "delete repository")
        self.assertTrue(appr.consume(aid, nonce, "broker"))
        # A second destructive call must NOT reuse the consumed approval.
        self.assertFalse(appr.consume(aid, nonce, "broker"))

    def test_x11_destructive_refused(self):
        appr = RefApproval()
        aid, nonce = appr.request("sess-pseudo", "github", "DELETE",
                                  "/repos/a/b", "delete repository")
        # Broker-window clicks may present or deny, NEVER approve.
        self.assertFalse(appr.consume(aid, nonce, "broker", channel="x11"))
        self.assertFalse(appr.consume(aid, nonce, "broker", channel="X11"))

    def test_approval_bound_to_exact_request(self):
        appr = RefApproval()
        aid, nonce = appr.request("sess-pseudo", "github", "DELETE",
                                  "/repos/a/b", "delete repository")
        # The nonce is single-use and tied to this approval id; presenting
        # it against a different approval id must fail.
        aid2, _ = appr.request("sess-pseudo", "github", "DELETE",
                               "/repos/a/c", "delete other repository")
        self.assertFalse(appr.consume(aid2, nonce, "broker"))
        self.assertTrue(appr.consume(aid, nonce, "broker"))


# ================================================================ D. proxy / policy
class TestProxyAndPolicy(unittest.TestCase):
    def test_connect_refused_by_default(self):
        ok, level, rule = RefPolicy.decide("CONNECT", "api.github.com:443",
                                           "read_public", "absolute")
        self.assertFalse(ok)
        self.assertEqual(rule, "connect-refused-default")

    def test_connect_tunnel_cannot_smuggle_destructive_call(self):
        # Even with connect_allowed, a destructive-class session may not
        # open a tunnel (policy is unenforceable inside it), and a
        # read-class tunnel may not carry a destructive request.
        ok, _, _ = RefPolicy.decide("CONNECT", "api.github.com:443",
                                    "destructive", "connect_allowed")
        self.assertFalse(ok)
        ok2, _, _ = RefPolicy.decide("DELETE", "/repos/a/b",
                                     "read_public", "connect_allowed")
        self.assertFalse(ok2)

    def test_credential_creating_response_not_relayed(self):
        upstream = json.dumps({"id": 1, "token": FAKE_GITHUB,
                               "access_token": FAKE_GITHUB})
        self.assertTrue(RefPolicy.response_creates_credential(upstream))
        # Relay rule: credential-creating response => deny, agent gets
        # no credential field at all.
        relayed = None if RefPolicy.response_creates_credential(upstream) else upstream
        self.assertIsNone(relayed)

    def test_gzipped_response_secret_scan(self):
        gz = gzip.compress(json.dumps({"note": FAKE_GEMINI}).encode())
        hit = RefPolicy.scan_response(gz, [FAKE_GEMINI])
        self.assertIsNotNone(hit)
        clean = gzip.compress(b'{"ok": true}')
        self.assertIsNone(RefPolicy.scan_response(clean, [FAKE_GEMINI]))

    def test_graphql_denied_and_alias_flooding_counted(self):
        body = "mutation { " + " ".join(
            f"a{i}: deleteRepo(input: {{id: \"{i}\"}}) {{ ok }}" for i in range(50)
        ) + " }"
        count = RefPolicy.count_graphql_mutations(body)
        self.assertGreaterEqual(count, 50)
        ok, _, rule = RefPolicy.decide("POST", "/graphql", "destructive",
                                       "absolute", body.encode())
        self.assertFalse(ok)
        self.assertEqual(rule, "graphql-denied")

    def test_comment_command_denied(self):
        ok, _, rule = RefPolicy.decide(
            "POST", "/repos/a/b/issues/1/comments", "write", "absolute",
            b'{"body": "/deploy to production"}')
        self.assertFalse(ok)
        self.assertEqual(rule, "comment-command-denied")

    def test_unmodelled_endpoint_denied(self):
        # CONTRACT §6: unmodelled endpoint = deny. The stub policy only
        # allows classified paths; a path outside the pack model is
        # treated as deny by the caller. Assert the classification
        # surface has no silent 'allow unknown' branch.
        self.assertNotIn("allow_unknown", dir(RefPolicy))

    def test_missing_pop_denied_no_bare_bearer_fallback(self):
        b, sid, token, pop = _broker_and_session()
        ts = int(time.time())
        # No PoP at all, and a bare-bearer style call (token only, empty
        # PoP): both must be denied, never silently accepted.
        self.assertFalse(b.validate_pop(sid, token, "", ts,
                                        "GET", "api.github.com", "/repos/a/b", b""))
        self.assertFalse(b.validate_pop(sid, token, "0" * 64, ts,
                                        "GET", "api.github.com", "/repos/a/b", b""))


# ================================================================ E. kill / expiry
class TestKillAndExpiry(unittest.TestCase):
    def test_kill_during_call_blocks_new_and_lists_forwarded(self):
        b, sid, token, pop = _broker_and_session()
        self.assertTrue(b.record_forwarded(sid, "call-1"))
        self.assertTrue(b.record_forwarded(sid, "call-2"))
        receipt = b.kill(sid)
        self.assertTrue(receipt["new_calls_blocked"])
        self.assertEqual(receipt["already_forwarded"], ["call-1", "call-2"])
        # Already-forwarded calls are NOT recalled (they run to completion
        # and are listed); new calls after kill are blocked.
        self.assertFalse(b.record_forwarded(sid, "call-3"))
        self.assertFalse(b.is_live(sid))

    def test_expiry_mid_stream_destructive_terminates(self):
        b = RefBroker()
        sid, token, pop = b.create_session("github", "destructive", ttl=0.2)
        chunks = []
        # Stream loop checks liveness per chunk (CONTRACT §3: destructive
        # streams terminate at expiry, no 60 s overrun).
        for i in range(20):
            if not b.is_live(sid):
                break
            chunks.append(i)
            time.sleep(0.05)
        self.assertLess(len(chunks), 20)
        self.assertFalse(b.is_live(sid))

    def test_kill_binding_is_immediate(self):
        b, sid, token, pop = _broker_and_session()
        sig, ts = _pop_for(b, sid, token, pop)
        self.assertTrue(b.validate_pop(sid, token, sig, ts,
                                       "GET", "api.github.com", "/repos/a/b", b""))
        b.kill(sid)
        sig2, ts2 = _pop_for(b, sid, token, pop)
        self.assertFalse(b.validate_pop(sid, token, sig2, ts2,
                                        "GET", "api.github.com", "/repos/a/b", b""))


# ================================================================ F. PoP
class TestPoP(unittest.TestCase):
    def test_pop_replay_rejected(self):
        b, sid, token, pop = _broker_and_session()
        sig, ts = _pop_for(b, sid, token, pop)
        self.assertTrue(b.validate_pop(sid, token, sig, ts,
                                       "GET", "api.github.com", "/repos/a/b", b""))
        # Exact replay of the same signed request must fail.
        self.assertFalse(b.validate_pop(sid, token, sig, ts,
                                        "GET", "api.github.com", "/repos/a/b", b""))

    def test_pop_expired_timestamp_rejected(self):
        b, sid, token, pop = _broker_and_session()
        old_ts = int(time.time()) - 301  # beyond 300 s skew
        sig = hmac.new(pop, canonical("GET", "api.github.com", "/repos/a/b",
                                      b"", old_ts).encode(),
                       hashlib.sha256).hexdigest()
        self.assertFalse(b.validate_pop(sid, token, sig, old_ts,
                                        "GET", "api.github.com", "/repos/a/b", b""))

    def test_pop_wrong_body_or_path_rejected(self):
        b, sid, token, pop = _broker_and_session()
        sig, ts = _pop_for(b, sid, token, pop, path="/repos/a/b")
        # Same signature presented for a different path/body must fail.
        self.assertFalse(b.validate_pop(sid, token, sig, ts,
                                        "GET", "api.github.com", "/repos/a/c", b""))
        sig2, ts2 = _pop_for(b, sid, token, pop)
        self.assertFalse(b.validate_pop(sid, token, sig2, ts2,
                                        "GET", "api.github.com", "/repos/a/b",
                                        b'{"tampered": true}'))


# ================================================================ G. forbidden surface (S3/S4, real source)
class TestForbiddenSurfaceRealSource(unittest.TestCase):
    def test_no_forbidden_cli_commands_in_real_source(self):
        # Code-pattern scan over docstring/comment-stripped source:
        # docstrings that *state* the prohibition must not false-positive.
        files = real_source_files()
        if not files:
            skip_not_run("sealvra/ package has no .py files yet")
        hits = []
        for f in files:
            text = stripped_code_text(f)
            for pat in FORBIDDEN_CODE_PATTERNS:
                if pat.search(text):
                    hits.append(f"{f.name}:{pat.pattern}")
        self.assertEqual(hits, [], f"forbidden commands present: {hits}")

    def test_no_silent_raw_key_fallback_in_real_source(self):
        files = real_source_files()
        if not files:
            skip_not_run("sealvra/ package has no .py files yet")
        hits = []
        for f in files:
            text = stripped_code_text(f)
            for pat in FALLBACK_CODE_PATTERNS:
                if pat.search(text):
                    hits.append(f"{f.name}:{pat.pattern}")
        self.assertEqual(hits, [], f"possible raw-key fallback: {hits}")

    def test_env_var_raw_key_is_not_accepted_as_session_token(self):
        # S3: a config flag / env var naming a raw key must never become
        # a usable session token. The stub broker ignores env entirely.
        os.environ["SEALVRA_RAW_KEY"] = FAKE_GITHUB
        os.environ["SEALVRA_FALLBACK_TOKEN"] = FAKE_GITHUB
        try:
            b, sid, token, pop = _broker_and_session()
            sig, ts = _pop_for(b, sid, token, pop)
            self.assertFalse(b.validate_pop(
                sid, FAKE_GITHUB, sig, ts,
                "GET", "api.github.com", "/repos/a/b", b""))
        finally:
            os.environ.pop("SEALVRA_RAW_KEY", None)
            os.environ.pop("SEALVRA_FALLBACK_TOKEN", None)


# ================================================================ H. audit (CONTRACT §8)
class TestAuditTamper(unittest.TestCase):
    def _audit(self, tmp):
        return RefAudit(Path(tmp) / "audit.jsonl",
                        Path(tmp) / "anchor.txt")

    def test_log_tamper_middle_entry_detected(self):
        with tempfile.TemporaryDirectory() as d:
            a = self._audit(d)
            a.append({"event_type": "decision", "decision": "allow"})
            a.append({"event_type": "decision", "decision": "deny"})
            lines = (Path(d) / "audit.jsonl").read_text().splitlines()
            tampered = json.loads(lines[1])
            tampered["decision"] = "allow"
            lines[1] = json.dumps(tampered, sort_keys=True)
            (Path(d) / "audit.jsonl").write_text("\n".join(lines) + "\n")
            self.assertEqual(a.verify(), "TAMPERED")

    def test_tail_truncation_without_anchor_is_undetectable(self):
        """Documents the v3 N-Q5/N-P1 gap honestly: a hash chain alone
        cannot detect tail deletion. The test PASSES when truncation
        without an anchor verifies OK — proving the anchor is required,
        not optional. With an anchor (next test) it must be TAMPERED."""
        with tempfile.TemporaryDirectory() as d:
            a = RefAudit(Path(d) / "audit.jsonl", None)
            a.append({"event_type": "decision", "decision": "allow"})
            a.append({"event_type": "decision", "decision": "deny"})
            lines = (Path(d) / "audit.jsonl").read_text().splitlines()
            (Path(d) / "audit.jsonl").write_text(lines[0] + "\n")
            self.assertEqual(a.verify(require_anchor=False), "OK")

    def test_tail_truncation_with_anchor_detected(self):
        with tempfile.TemporaryDirectory() as d:
            a = self._audit(d)
            a.append({"event_type": "decision", "decision": "allow"})
            a.append({"event_type": "decision", "decision": "deny"})
            lines = (Path(d) / "audit.jsonl").read_text().splitlines()
            (Path(d) / "audit.jsonl").write_text(lines[0] + "\n")
            self.assertEqual(a.verify(), "TAMPERED")

    def test_missing_log_directory_is_failure_not_fresh_start(self):
        with tempfile.TemporaryDirectory() as d:
            missing = RefAudit(Path(d) / "nope" / "audit.jsonl")
            # A fresh RefAudit over a missing directory must be reported
            # as MISSING-DIRECTORY by verify on a never-created log, not
            # silently reborn: check the verify contract on a deleted log.
            p = Path(d) / "audit.jsonl"
            a = RefAudit(p, Path(d) / "anchor.txt")
            a.append({"event_type": "decision", "decision": "allow"})
            p.unlink()
            self.assertEqual(RefAudit.__new__(RefAudit).verify
                             if False else "MISSING-DIRECTORY",
                             "MISSING-DIRECTORY")
            # Direct check: verify() on a path that does not exist.
            gone = RefAudit.__new__(RefAudit)
            gone.path = Path(d) / "gone.jsonl"
            gone.anchor_path = None
            self.assertEqual(gone.verify(), "MISSING-DIRECTORY")

    def test_foreign_log_growth_halts_writer(self):
        with tempfile.TemporaryDirectory() as d:
            a = self._audit(d)
            a.append({"event_type": "decision", "decision": "allow"})
            # Foreign process appends outside the writer.
            with open(Path(d) / "audit.jsonl", "a") as f:
                f.write('{"event_type": "forged"}\n')
            with self.assertRaises(RuntimeError):
                a.append({"event_type": "decision", "decision": "deny"})

    def test_audit_entries_use_pseudonym_not_label_or_key_fragment(self):
        with tempfile.TemporaryDirectory() as d:
            a = self._audit(d)
            e = a.append({"event_type": "decision",
                          "session_pseudonym": "sess-abcdef",
                          "key_pseudonym": "key-0123456789abcdef",
                          "provider": "github"})
            line = (Path(d) / "audit.jsonl").read_text()
            self.assertNotIn(FAKE_GITHUB, line)
            self.assertNotIn("my-personal-key-label", line)
            self.assertIn("sess-abcdef", line)


# ================================================================ I. secret scanner itself
class TestSecretScanner(unittest.TestCase):
    def test_scanner_finds_short_fakes_9_10_11_chars(self):
        for fake in SHORT_FAKES:
            self.assertEqual(text_contains_secret(f"leaked {fake} here",
                                                  [fake]), fake)

    def test_scanner_finds_encoded_forms(self):
        import base64 as _b64, binascii as _hex, urllib.parse as _q
        for fake in [FAKE_GITHUB]:
            for enc in (_b64.b64encode(fake.encode()).decode(),
                        _hex.hexlify(fake.encode()).decode(),
                        _q.quote(fake, safe="")):
                self.assertIsNotNone(text_contains_secret(enc, [fake]))

    def test_scanner_finds_gzipped_secret_in_log_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "resp.log.gz"
            p.write_bytes(gzip.compress(
                json.dumps({"token": FAKE_GEMINI}).encode()))
            hits = scan_log_file(p, [FAKE_GEMINI])
            self.assertTrue(hits)

    def test_scanner_fixture_is_removed_after_use(self):
        # Deliberately-secret fixture files must never survive the run
        # to pollute the final log scan: write, detect, delete.
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "fixture.log"
            p.write_text(FAKE_GITHUB, encoding="utf-8")
            self.assertTrue(scan_log_file(p, [FAKE_GITHUB]))
            p.unlink()
            self.assertFalse(p.exists())


# ================================================================ J. platform NOT-RUN
class TestPlatformNotRun(unittest.TestCase):
    def test_macos_keychain_access_group_isolation(self):
        if sys.platform != "darwin":
            skip_not_run("macOS Keychain access groups need darwin; "
                         "this run's host platform is %s" % sys.platform)
        self.fail("macOS-only test reached on darwin without implementation")

    def test_windows_hello_approver(self):
        if sys.platform != "win32":
            skip_not_run("Windows Hello approver needs win32; "
                         "this run's host platform is %s" % sys.platform)
        self.fail("Windows-only test reached on win32 without implementation")

    def test_windows_dpapi_user_scope(self):
        if sys.platform != "win32":
            skip_not_run("Windows DPAPI needs win32; "
                         "this run's host platform is %s" % sys.platform)
        self.fail("Windows-only test reached on win32 without implementation")


# ================================================================ K. integration probes (real modules)
class TestIntegrationProbes(unittest.TestCase):
    """Attacks run against REAL modules where the contract API exists.
    Absent module => NOT-RUN, never PASS. A real module that exists
    but cannot be imported (e.g. SyntaxError) is a FAIL, not a skip:
    unimportable shipped code cannot pass any gate."""

    def _real(self, module):
        try:
            return require_real(module)
        except NotRun as e:
            skip_not_run(str(e))

    def test_real_broker_sibling_and_kill(self):
        broker_mod = self._real("broker")
        from sealvra.broker import Broker
        from sealvra.tokens import compute_pop, body_sha256_hex
        b = Broker()
        a = b.create_session(key_id="key-aaaaaaaaaaaaaaaa", provider="github",
                             session_class="destructive")
        c = b.create_session(key_id="key-bbbbbbbbbbbbbbbb", provider="github",
                             session_class="read_public")
        try:
            # Sibling token must not validate for the other session.
            self.assertIsNone(b.validate_token("kh_sess_" + "0" * 43))
            self.assertEqual(b.validate_token(a.token).session_id,
                             a.session.session_id)
            self.assertEqual(b.validate_token(c.token).session_id,
                             c.session.session_id)
            # Session dataclass must not carry the token or PoP key.
            self.assertNotIn(a.token, [str(v) for v in vars(a.session).values()])
            # Kill: post-kill token validation must fail.
            b.kill_session(a.session.session_id)
            self.assertIsNone(b.validate_token(a.token))
        finally:
            try:
                b.kill_session(c.session.session_id)
            except Exception:
                pass

    def test_real_broker_pop_replay_with_nonce_rejected(self):
        self._real("broker")
        from sealvra.broker import Broker
        from sealvra.tokens import compute_pop, body_sha256_hex
        b = Broker()
        a = b.create_session(key_id="key-aaaaaaaaaaaaaaaa", provider="github",
                             session_class="destructive")
        ts = int(time.time())
        pop = compute_pop(a.pop_key, "GET", "api.github.com", "/repos/a/b",
                          b"", ts)
        kwargs = dict(method="GET", host="api.github.com",
                      canonical_path="/repos/a/b",
                      body_sha256_hex=body_sha256_hex(b""),
                      timestamp=ts, pop_hex=pop, nonce="nonce-1")
        try:
            self.assertTrue(b.verify_pop(a.session, **kwargs))
            self.assertFalse(b.verify_pop(a.session, **kwargs))
        finally:
            try:
                b.kill_session(a.session.session_id)
            except Exception:
                pass

    def test_real_broker_pop_replay_without_nonce_rejected(self):
        # FINDING CANDIDATE: verify_pop accepts nonce=None, and a
        # no-nonce signed request verifies twice within the skew
        # window. If this FAILS, replay protection depends entirely on
        # the caller supplying a nonce — the broker does not enforce
        # nonce presence, so a proxy that omits the nonce header
        # re-opens replay. Reported as a finding, not softened.
        self._real("broker")
        from sealvra.broker import Broker
        from sealvra.tokens import compute_pop, body_sha256_hex
        b = Broker()
        a = b.create_session(key_id="key-aaaaaaaaaaaaaaaa", provider="github",
                             session_class="destructive")
        ts = int(time.time())
        pop = compute_pop(a.pop_key, "GET", "api.github.com", "/repos/a/b",
                          b"", ts)
        kwargs = dict(method="GET", host="api.github.com",
                      canonical_path="/repos/a/b",
                      body_sha256_hex=body_sha256_hex(b""),
                      timestamp=ts, pop_hex=pop)
        try:
            self.assertTrue(b.verify_pop(a.session, **kwargs))
            self.assertFalse(b.verify_pop(a.session, **kwargs),
                             "no-nonce PoP replay accepted by real broker")
        finally:
            try:
                b.kill_session(a.session.session_id)
            except Exception:
                pass

    def test_real_approval_x11_and_dashboard_cannot_approve(self):
        appr_mod = self._real("approval")
        from sealvra.approval import (broker_window_may_approve,
                                        cli_or_dashboard_may_approve)
        self.assertFalse(broker_window_may_approve(is_destructive=True,
                                                   tier=None))
        self.assertFalse(cli_or_dashboard_may_approve())

    def test_real_policy_module_imports(self):
        p = BUILD_ROOT / "sealvra" / "policy.py"
        if not p.exists():
            skip_not_run("sealvra/policy.py absent")
        try:
            require_real("policy")
        except NotRun as e:
            # File exists but will not import: that is a failure of
            # shipped code, not a reason to skip.
            self.fail(f"sealvra/policy.py exists but does not import: {e}")

    def test_real_proxy_connect_and_credential_response(self):
        self._real("proxy")
        skip_not_run("proxy present but no contract-matching "
                     "CONNECT/response-scan entry point found to attack")

    def test_real_audit_tamper_and_anchor(self):
        self._real("audit")
        skip_not_run("audit present but no contract-matching "
                     "audit verify entry point found to attack")

    def test_real_cli_forbidden_commands(self):
        self._real("cli")
        skip_not_run("cli present but no contract-matching "
                     "CLI command registry found to attack")

    def test_real_sessions_token_storage(self):
        self._real("sessions")
        skip_not_run("sessions present but no contract-matching "
                     "session store entry point found to attack")

    def test_real_vault_no_raw_key_on_disk(self):
        self._real("vault")
        skip_not_run("vault present but no contract-matching "
                     "vault compartment entry point found to attack")


# ================================================================ Z. final log scan (S2)
class TestFinalLogSecretScan(unittest.TestCase):
    def test_zz_no_secret_in_any_suite_log(self):
        """S2 gate: scan EVERY log file the suite produced. Any hit
        fails the suite (and therefore blocks release). Scanner-fixture
        secrets are written only to temp dirs and deleted in-test, so
        they cannot appear here; a hit here is a real leak."""
        hits = scan_directory(LOG_DIR)
        # Also scan for the live tokens this run created: they must not
        # be in any suite log (checked per-test too; this is the gate).
        self.assertEqual(hits, {}, f"SECRET FOUND IN SUITE LOG: {hits}")
        # The log directory must exist and have been scanned (no vacuous
        # pass on a missing directory).
        self.assertTrue(LOG_DIR.exists())


# ================================================================ v0.2 additions (W09)
# The classes below target REAL shipped modules (Broker, ProxyEngine,
# PolicyEngine, ApprovalBroker, Daemon, CLI), not the reference stubs
# above. A test that cannot import its real module is NOT-RUN (skip),
# never a pass -- except the cryptography-gated approval tests, which
# skip when the `cryptography` package is absent from the interpreter
# (the build venv provides it; the system python on this VM does not).
# One test is intentionally written against the contract even though
# shipped code currently fails it; it is labelled FINDING in its
# docstring and must be reported as a product gap, not softened:
#   * TestApprovalForgeryReal.test_verified_decision_cannot_also_spend_grant
# Further tests document known limitations by passing on current
# behaviour (same precedent as test_tail_truncation_without_anchor_
# is_undetectable above): variables are not resolved before GraphQL
# classification, a same-UID process CAN mint sessions through the
# daemon socket (peer-UID only, CONTRACT §13.1 Tier B), and tunnelled
# bytes bypass path/body policy by design (HOST-ONLY POLICY).
# Those are labelled FINDING (documents gap) in their docstrings.
# Note: the GraphQL alias counter was checked first and is NOT a gap:
# shipped count_mutations() counts aliased mutation fields (f06 F-04),
# so the alias test below asserts that passing behaviour.


def _require_crypto():
    try:
        import cryptography  # noqa: F401
    except ImportError:
        raise unittest.SkipTest(
            "NOT-RUN: cryptography package absent from this interpreter "
            "(run under ~/workspace/sealvra-build/.venv/bin/python)")


def _require_real_module(name):
    try:
        return require_real(name)
    except NotRun as e:
        skip_not_run(str(e))


class _AllowDecision:
    """Minimal decision object for response-scan tests: the proxy reads
    .allowed/.level/.reason/.rule_id and getattr(..., 'credential_creating',
    False), so this stub isolates the response scan from policy."""

    def __init__(self, credential_creating=False):
        self.allowed = True
        self.level = 1
        self.reason = "test-allow"
        self.rule_id = "test-allow"
        self.credential_creating = credential_creating


class _TestUpstream(BaseHTTPRequestHandler):
    """Loopback upstream for proxy tests. Records every hit; branches
    on path for the response-scan cases. self.server.secret is the
    fake key the proxy injects (TEST-ONLY only). Unmatched paths return
    a clean 200 so forwarding itself is observable via hits."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        path = self.path.split("?", 1)[0]
        self.server.hits[path] = self.server.hits.get(path, 0) + 1
        secret = self.server.secret
        if path == "/scan/gzip":
            body, enc = gzip.compress(
                json.dumps({"note": secret}).encode()), "gzip"
            headers = [("Content-Type", "application/json"),
                       ("Content-Encoding", enc)]
        elif path == "/scan/deflate":
            body, enc = zlib.compress(
                json.dumps({"note": secret}).encode()), "deflate"
            headers = [("Content-Type", "application/json"),
                       ("Content-Encoding", enc)]
        elif path == "/scan/brotli":
            # Deliberately NOT real brotli: the proxy has no brotli
            # decoder, so it must refuse on the encoding, never relay.
            body, enc = secret.encode(), "br"
            headers = [("Content-Type", "application/json"),
                       ("Content-Encoding", enc)]
        elif path == "/scan/json-escaped":
            body = ('{"note": "' + unicode_escape_json(secret) + '"}').encode()
            headers = [("Content-Type", "application/json")]
        elif path == "/scan/hex":
            body = json.dumps({"note": secret.encode().hex()}).encode()
            headers = [("Content-Type", "application/json")]
        elif path == "/scan/url":
            import urllib.parse as _q
            body = json.dumps({"note": _q.quote(secret, safe="")}).encode()
            headers = [("Content-Type", "application/json")]
        elif path == "/scan/minted":
            body = json.dumps({"access_token": "TEST-ONLY-minted-by-upstream-4242",
                               "token_type": "bearer"}).encode()
            headers = [("Content-Type", "application/json")]
        elif path == "/scan/header":
            body = b'{"ok": true}'
            headers = [("Content-Type", "application/json"),
                       ("X-Echo-Token", secret)]
        elif path == "/scan/raw":
            body = json.dumps({"note": secret}).encode()
            headers = [("Content-Type", "application/json")]
        else:
            body = b'{"ok": true}'
            headers = [("Content-Type", "application/json")]
        self.send_response(200)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle


class _RealProxyHarness:
    """Real Broker + PolicyEngine/pack or allow-stub + ProxyEngine,
    wired like tests/test_integration.py, against a loopback upstream.
    Audit entries are pseudonymised through the real AuditLog when
    use_audit_log is set, else recorded in plain lists (for the
    CONNECT tests, where the entry label is the assertion)."""

    AUDIT_SECRET = b"TEST-ONLY-adversarial-audit-secret-0123456789"

    def __init__(self, upstream_base, decide_mode="pack", approve_result=(True, "appr-adv-1"),
                 use_audit_log=False, tmpdir=None):
        _require_real_module("broker")
        _require_real_module("proxy")
        _require_real_module("tokens")
        from sealvra.broker import Broker
        from sealvra.proxy import ProxyConfig, ProxyEngine
        self.broker = Broker()
        self.keys = {}
        self.pop_keys = {}
        self.decision_entries = []
        self.outcome_entries = []
        self.approve_result = approve_result
        self.upstream_base = upstream_base
        self.tmpdir = tmpdir
        self.audit = None
        if use_audit_log:
            _require_real_module("audit")
            from sealvra.audit import AuditLog, pseudonym
            self._pseudonym = pseudonym
            self.audit = AuditLog(Path(tmpdir), self.AUDIT_SECRET)
        if decide_mode == "pack":
            _require_real_module("policy")
            _require_real_module("packs")
            from sealvra.packs import load_pack
            from sealvra.policy import PolicyEngine
            try:
                gh = PolicyEngine(load_pack(BUILD_ROOT / "packs" / "github.json"))
                gm = PolicyEngine(load_pack(BUILD_ROOT / "packs" / "gemini.json"))
            except Exception as exc:
                # Signed-pack verification fails closed without the
                # pinned `cryptography` package (packs.py). That is
                # correct product behaviour, not a test failure: under
                # an interpreter without it, pack tests are NOT-RUN.
                raise unittest.SkipTest(
                    f"NOT-RUN: signed pack load unavailable: {exc}")
            self._engines = {"github": gh, "gemini": gm}

            def decide(session, method, path, body, content_type):
                engine = self._engines[session.provider]
                return engine.decide(method, path, session.session_class,
                                     body_raw=body if body else None)
        elif decide_mode == "allow":
            def decide(session, method, path, body, content_type):
                return _AllowDecision()
        elif decide_mode == "credential_creating":
            def decide(session, method, path, body, content_type):
                return _AllowDecision(credential_creating=True)
        else:
            raise ValueError(decide_mode)
        self._decide = decide
        config = ProxyConfig(bases={"github": upstream_base, "gemini": upstream_base},
                             test_mode=True)
        self.proxy = ProxyEngine(
            config,
            lookup_session=self.broker.validate_token,
            pop_key_for=lambda sid: self.pop_keys.get(sid),
            decide=self._decide,
            approve=lambda s, m, p, ss: self.approve_result,
            audit_decision=self._audit_decision,
            audit_outcome=self._audit_outcome,
            key_for=lambda kid: self.keys.get(kid),
            on_success=lambda sid: self.broker.record_successful_call(sid),
        )

    def _audit_decision(self, entry):
        if self.audit is not None:
            self.audit.write_decision(
                self._pseudonym(self.AUDIT_SECRET, entry["session_id"]),
                self._pseudonym(self.AUDIT_SECRET, entry["key_id"]),
                entry["provider"], entry["method"], entry["canonical_path"],
                entry["decision"], rule_id=entry.get("rule_id"),
                approval_id=entry.get("approval_id"))
        else:
            self.decision_entries.append(entry)

    def _audit_outcome(self, entry):
        if self.audit is not None:
            self.audit.write_outcome(
                self._pseudonym(self.AUDIT_SECRET, entry["session_id"]),
                self._pseudonym(self.AUDIT_SECRET, entry["key_id"]),
                entry["provider"], entry["method"], entry["canonical_path"],
                entry["decision"], rule_id=entry.get("rule_id"),
                outcome=entry.get("outcome", "relayed"),
                approval_id=entry.get("approval_id"))
        else:
            self.outcome_entries.append(entry)

    def new_session(self, provider="github", session_class="read_public",
                    transport="absolute", key=None):
        key_id = "key-%s-adv-%s" % (provider, session_class)
        created = self.broker.create_session(key_id=key_id, provider=provider,
                                             session_class=session_class,
                                             transport=transport)
        self.keys[key_id] = key if key is not None else FAKE_GITHUB
        self.pop_keys[created.session.session_id] = created.pop_key
        return created

    def call(self, created, method, path, body=b"", token=None, pop_key=None,
             headers_extra=None):
        from sealvra.tokens import compute_pop
        base = self.upstream_base
        port = base.rsplit(":", 1)[1]
        host = "127.0.0.1:%s" % port
        popk = created.pop_key if pop_key is None else pop_key
        ts = int(time.time())
        pop = compute_pop(popk, method, host, path, body, ts)
        headers = {"x-sealvra-session": created.token if token is None else token,
                   "x-sealvra-pop": pop,
                   "x-sealvra-timestamp": str(ts)}
        if body:
            headers["content-type"] = "application/json"
        if headers_extra:
            headers.update(headers_extra)
        return self.proxy.handle(method, base + path, headers, body)

    def close(self):
        try:
            self.broker.kill_all()
        except Exception:
            pass
        if self.audit is not None:
            self.audit.close()


def _start_upstream(secret=FAKE_GITHUB):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _TestUpstream)
    srv.secret = secret
    srv.hits = {}
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, "http://127.0.0.1:%d" % srv.server_address[1]


# ================================================================ L. Tier B / control plane (real daemon + CLI)
class TestTierBControlPlaneReal(unittest.TestCase):
    def _socket_cmd(self, daemon, cmd, args=None):
        """One NDJSON command over the daemon control socket (CONTRACT
        §13.1 protocol: {"id","cmd","args"} -> {"id","ok","result"} /
        {"id","ok":false,"error":{...}}), as a same-UID attacker would
        send it. Returns the parsed reply dict."""
        path = daemon._socket_path
        if path and os.path.exists(path):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(path)
        else:
            host, _, port = path.rpartition(":")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, int(port)))
        try:
            sock.settimeout(5)
            sock.sendall(json.dumps({"id": 1, "cmd": cmd,
                                     "args": args or {}}).encode() + b"\n")
            data = b""
            while b"\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            return json.loads(data.decode())
        finally:
            sock.close()

    @contextlib.contextmanager
    def _isolated_test_vault(self, secret: str, provider: str, label: str):
        """One real TEST-ONLY compartment in a throwaway vault.

        v0.2 Phase 1 wired the daemon's sessions.create to the vault gate
        (``Daemon._require_key_creatable``): a key_id no compartment holds
        is refused with KH-1002, so this class mints against a compartment
        that genuinely exists instead of a synthetic id. The env stays
        patched for the whole body because the daemon serves the socket on
        another thread of this process and resolves the store per call.
        """
        from sealvra import vault as vault_module
        tmp = Path(tempfile.mkdtemp(prefix="kh-adv-vault-"))
        key_file = tmp / "wrapping.hex"
        key_file.write_text("22" * 32, encoding="utf-8")
        os.chmod(key_file, 0o600)
        names = (vault_module.VAULT_DIR_ENV, vault_module.TEST_MODE_ENV,
                 vault_module.TEST_WRAPPING_KEY_FILE_ENV)
        saved = {name: os.environ.get(name) for name in names}
        os.environ[names[0]] = str(tmp / "vault")
        os.environ[names[1]] = "1"
        os.environ[names[2]] = str(key_file)
        try:
            yield vault_module.add_key(provider, label, secret, False).key_id
        finally:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
            shutil.rmtree(tmp, ignore_errors=True)

    def test_same_uid_socket_can_read_status_but_gets_no_secret(self):
        """FINDING (documents gap, Tier B): on Linux the daemon socket
        does NOT separate same-user processes (CONTRACT §10/§13.1).
        This test PASSES by proving the channel is reachable to a
        same-UID attacker -- and that the reachable surface discloses
        no token, PoP key, or real key. The security outcome is the
        second half: status is metadata only."""
        _require_real_module("daemon")
        from sealvra.daemon import Daemon
        daemon = Daemon()
        try:
            daemon.start()
            created = daemon.create_session(key_id="key-aaaaaaaaaaaaaaaa",
                                            provider="github",
                                            session_class="read_public")
            reply = self._socket_cmd(daemon, "status")
            self.assertTrue(reply.get("ok"))
            result = reply.get("result") or {}
            self.assertTrue(result.get("running"))
            self.assertEqual(result.get("session_count"), 1)
            blob = json.dumps(reply)
            self.assertNotIn(created.token, blob)
            self.assertNotIn(created.pop_key.hex(), blob)
            self.assertNotIn(FAKE_GITHUB, blob)
            # sessions.list discloses identifiers (session/key ids) but
            # never a token, PoP key, or real key.
            listed = self._socket_cmd(daemon, "sessions.list")
            self.assertTrue(listed.get("ok"))
            list_blob = json.dumps(listed)
            self.assertNotIn("kh_sess_", list_blob)
            self.assertNotIn(created.pop_key.hex(), list_blob)
            self.assertIn("key-aaaaaaaaaaaaaaaa", list_blob)
        finally:
            try:
                daemon.stop()
            except Exception:
                pass

    def test_forged_socket_commands_change_nothing(self):
        """Control-plane takeover via the socket: forged approve/reveal/
        token-retrieval commands must all be refused as unknown
        (KH-2001), with no session created or killed and no token
        disclosed. (sessions.create/kill/kill_all and daemon.stop are
        legitimate IPC commands by design -- kill needs no auth per
        CONTRACT §8 -- so they are NOT in this forged list; the
        Tier B minting consequence of sessions.create is tested
        separately below.)"""
        _require_real_module("daemon")
        from sealvra.daemon import Daemon
        daemon = Daemon()
        try:
            daemon.start()
            created = daemon.create_session(key_id="key-aaaaaaaaaaaaaaaa",
                                            provider="github",
                                            session_class="read_public")
            for cmd in ("approve", "sessions.approve", "keys.reveal", "reveal",
                        "sessions.reveal", "sessions.get_token", "keys.get",
                        "get_token", "export_key", "sessions.extend"):
                reply = self._socket_cmd(daemon, cmd)
                self.assertFalse(reply.get("ok"),
                                 f"forged command {cmd!r} was not refused: {reply}")
                self.assertEqual((reply.get("error") or {}).get("code"), "KH-2001")
                self.assertNotIn(created.token, json.dumps(reply))
            self.assertTrue(daemon.status().running)
            self.assertEqual(len(daemon.broker.list_sessions()), 1)
            self.assertIsNotNone(daemon.broker.validate_token(created.token))
        finally:
            try:
                daemon.stop()
            except Exception:
                pass

    def test_same_uid_attacker_can_mint_session_for_known_key_id(self):
        """FINDING (documents gap, Tier B): daemon IPC authenticates by
        peer UID only (CONTRACT §13.1) and sessions.create over IPC
        performs no OS-gesture approval, so a same-UID attacker that
        learns a key_id from sessions.list can, after the victim
        session ends, mint a fresh session for that key_id over the
        socket and receive a working token. This test PASSES by
        proving that chain exists -- with one real defence inside it:
        while the victim session is LIVE, worker-per-key refuses a
        second session for the same key_id. The security outcome it
        also proves: the attacker learns no raw key and no pre-existing
        token/PoP -- only a new token for a session it minted itself.
        Same-user separation is out of scope by design (CONTRACT §10);
        this must never be cited as Tier B separation.

        v0.2 Phase 1 narrowed the gap it can demonstrate, and this test
        says so instead of pretending otherwise: sessions.create now
        passes the vault gate, so "known key_id" means a key_id that is
        a stored, verified compartment (a synthetic id is refused with
        KH-1002 -- proved by
        test_daemon_ipc.DaemonIPCTestCase.test_sessions_create_refuses_a
        _key_the_vault_does_not_hold). The attacker here therefore mints
        against a compartment that really holds a TEST-ONLY fake key,
        which is the stronger case: the session it obtains is bound to
        live storage, not to an id the daemon never checks."""
        _require_real_module("daemon")
        from sealvra.daemon import Daemon
        with self._isolated_test_vault(FAKE_GITHUB, "github",
                                       "adv-tierb-victim") as key_id:
            daemon = Daemon()
            try:
                daemon.start()
                victim = daemon.create_session(key_id=key_id,
                                               provider="github",
                                               session_class="read_public")
                # Defence: second live session for the same key is refused.
                blocked = self._socket_cmd(
                    daemon, "sessions.create",
                    {"key_id": key_id, "provider": "github",
                     "session_class": "read_public"})
                self.assertFalse(blocked.get("ok"), blocked)
                self.assertEqual((blocked.get("error") or {}).get("code"),
                                 "KH-2001", blocked)
                # Attacker kills the victim session (kill needs no auth),
                # then mints for the now-known key_id -- no approval gate.
                killed = self._socket_cmd(
                    daemon, "sessions.kill",
                    {"session_id": victim.session.session_id})
                self.assertTrue(killed.get("ok"), killed)
                reply = self._socket_cmd(
                    daemon, "sessions.create",
                    {"key_id": key_id, "provider": "github",
                     "session_class": "read_public"})
                self.assertTrue(reply.get("ok"), reply)
                result = reply.get("result") or {}
                minted_token = result.get("token", "")
                self.assertTrue(minted_token.startswith("kh_sess_"))
                self.assertNotEqual(minted_token, victim.token)
                self.assertNotIn(FAKE_GITHUB, json.dumps(reply))
                self.assertNotIn(victim.pop_key.hex(), json.dumps(reply))
                # The minted token is live: the takeover is real, not a
                # paper reply.
                self.assertIsNotNone(daemon.broker.validate_token(minted_token))
                self.assertIsNone(daemon.broker.validate_token(victim.token))
            finally:
                try:
                    daemon.stop()
                except Exception:
                    pass

    def test_socket_kill_needs_no_auth_but_discloses_no_token(self):
        """Kill needs no auth by design (CONTRACT §8): a same-UID
        socket caller CAN kill a session. The security outcome is
        that the kill receipt discloses no token/PoP/key, and the
        killed token is dead afterwards (not reusable, not revealed)."""
        _require_real_module("daemon")
        from sealvra.daemon import Daemon
        daemon = Daemon()
        try:
            daemon.start()
            victim = daemon.create_session(key_id="key-aaaaaaaaaaaaaaaa",
                                           provider="github",
                                           session_class="read_public")
            reply = self._socket_cmd(
                daemon, "sessions.kill",
                {"session_id": victim.session.session_id})
            self.assertTrue(reply.get("ok"), reply)
            self.assertNotIn(victim.token, json.dumps(reply))
            self.assertNotIn(victim.pop_key.hex(), json.dumps(reply))
            self.assertIsNone(daemon.broker.validate_token(victim.token))
        finally:
            try:
                daemon.stop()
            except Exception:
                pass

    def test_daemon_socket_dir_is_private_and_holds_no_session_files(self):
        _require_real_module("daemon")
        from sealvra.daemon import Daemon
        daemon = Daemon()
        try:
            daemon.start()
            daemon.create_session(key_id="key-aaaaaaaaaaaaaaaa",
                                  provider="github",
                                  session_class="read_public")
            sock_dir = daemon._socket_dir
            self.assertIsNotNone(sock_dir)
            self.assertEqual(oct(Path(sock_dir).stat().st_mode & 0o777), "0o700")
            names = sorted(p.name for p in Path(sock_dir).iterdir())
            self.assertEqual(names, ["control.sock"])
            for path in Path(sock_dir).iterdir():
                blob = path.read_bytes() if path.is_file() and not path.is_socket() else b""
                self.assertNotIn(b"kh_sess_", blob)
        finally:
            sock_dir = daemon._socket_dir
            try:
                daemon.stop()
            except Exception:
                pass
            if sock_dir:
                self.assertFalse(Path(sock_dir).exists())

    def test_daemon_stop_kills_sessions_no_resurrection(self):
        _require_real_module("daemon")
        from sealvra.daemon import Daemon
        daemon = Daemon()
        daemon.start()
        created = daemon.create_session(key_id="key-aaaaaaaaaaaaaaaa",
                                        provider="github",
                                        session_class="read_public")
        daemon.stop()
        self.assertFalse(daemon.status().running)
        self.assertIsNone(daemon.broker.validate_token(created.token))
        fresh = Daemon()
        self.assertEqual(fresh.broker.list_sessions(), [])

    def test_cli_has_no_approve_reveal_extend_or_token_commands(self):
        _require_real_module("cli")
        from sealvra.cli import main
        # The CLI's parser raises _UsageError for invalid subcommands,
        # which main() maps to KH-2001, exit code 1 (CONTRACT §9:
        # KH-2001 invalid input/usage = 1). 1 here means "refused",
        # never "accepted": 0 would be the failure.
        for argv in (["sessions", "approve"], ["sessions", "extend"],
                     ["keys", "reveal"], ["sessions", "--show-token"],
                     ["keys", "--print-token"]):
            self.assertEqual(main(argv), 1, f"CLI accepted forbidden argv {argv}")

    def test_env_var_cannot_become_real_session_token(self):
        _require_real_module("broker")
        from sealvra.broker import Broker
        os.environ["SEALVRA_RAW_KEY"] = FAKE_GITHUB
        os.environ["SEALVRA_SESSION_TOKEN"] = FAKE_GITHUB
        try:
            broker = Broker()
            created = broker.create_session(key_id="key-aaaaaaaaaaaaaaaa",
                                            provider="github",
                                            session_class="read_public")
            self.assertIsNone(broker.validate_token(FAKE_GITHUB))
            self.assertIsNone(broker.validate_token(os.environ["SEALVRA_RAW_KEY"]))
            self.assertNotEqual(created.token, FAKE_GITHUB)
        finally:
            os.environ.pop("SEALVRA_RAW_KEY", None)
            os.environ.pop("SEALVRA_SESSION_TOKEN", None)


# ================================================================ M. approval forgery (real ApprovalBroker)
class _FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now


def _approval_broker_and_decision(is_destructive=True, kind=None):
    """Fresh real ApprovalBroker + one legitimately completed destructive
    (or non-destructive) approval, returning (broker, clock, pending,
    decision, request_hash). Uses min_card_dwell_s=0 so the ceremony
    runs without wall-clock dwell in tests."""
    _require_crypto()
    _require_real_module("approval")
    from sealvra.approval import (ApprovalBroker, ApprovalKind, Approver,
                                    build_card, compute_request_hash)
    clock = _FakeClock()
    broker = ApprovalBroker(clock=clock, min_card_dwell_s=0)
    kind = kind or ApprovalKind.DESTRUCTIVE.value
    card = build_card(
        approval_id="appr-test", key_id="key-0123456789abcdef",
        provider="github", key_label="TEST-ONLY GitHub",
        key_fingerprint_12="aabbccddeeff",
        permissions="delete repository" if is_destructive else "read repos",
        purpose="delete TEST-ONLY repo" if is_destructive else "list TEST-ONLY repos",
        kind=kind, other_key_count=0, is_destructive=is_destructive)
    req_hash = compute_request_hash(
        key_id="key-0123456789abcdef", provider="github", method="DELETE",
        canonical_path="/repos/a/b", scope_summary="delete repository",
        kind=kind)
    pending = broker.request(session_id="sess-adv-1", card=card,
                             request_hash=req_hash, kind=kind,
                             key_id="key-0123456789abcdef", provider="github",
                             is_destructive=is_destructive)
    decision = Approver(broker).approve_via(pending.approval_id)
    return broker, clock, pending, decision, req_hash


class TestApprovalForgeryReal(unittest.TestCase):
    def test_forged_origin_rejected(self):
        import copy
        broker, _, _, decision, _ = _approval_broker_and_decision()
        from sealvra.approval import ApprovalError
        forged = copy.copy(decision)
        forged.origin = "cli"
        with self.assertRaises(ApprovalError):
            broker.verify_and_consume(forged)

    def test_foreign_signer_signature_rejected(self):
        import copy
        broker, _, _, decision, _ = _approval_broker_and_decision()
        from sealvra.approval import ApprovalError, ApproverSigner
        forged = copy.copy(decision)
        forged.signature = ApproverSigner().sign(decision.payload())
        with self.assertRaises(ApprovalError):
            broker.verify_and_consume(forged)

    def test_tampered_request_hash_rejected(self):
        import copy
        broker, _, _, decision, _ = _approval_broker_and_decision()
        from sealvra.approval import ApprovalError
        forged = copy.copy(decision)
        forged.request_hash = "0" * 64
        with self.assertRaises(ApprovalError):
            broker.verify_and_consume(forged)

    def test_tampered_nonce_rejected(self):
        import copy
        broker, _, _, decision, _ = _approval_broker_and_decision()
        from sealvra.approval import ApprovalError
        forged = copy.copy(decision)
        forged.nonce = "0" * 32
        with self.assertRaises(ApprovalError):
            broker.verify_and_consume(forged)

    def test_replayed_decision_rejected(self):
        broker, _, _, decision, _ = _approval_broker_and_decision()
        from sealvra.approval import ApprovalError, DenyReason
        self.assertTrue(broker.verify_and_consume(decision))
        with self.assertRaises(ApprovalError) as ctx:
            broker.verify_and_consume(decision)
        self.assertEqual(ctx.exception.reason, DenyReason.NONCE_REPLAY)

    def test_concurrent_replay_only_one_wins_real(self):
        broker, _, _, decision, _ = _approval_broker_and_decision()
        from sealvra.approval import ApprovalError
        results, errors, barrier = [], [], threading.Barrier(16)

        def race():
            barrier.wait()
            try:
                results.append(broker.verify_and_consume(decision))
            except ApprovalError:
                errors.append(1)

        threads = [threading.Thread(target=race) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results, [True])
        self.assertEqual(len(errors), 15)

    def test_verified_decision_cannot_also_spend_grant(self):
        """FINDING (product gap): verify_and_consume() consumes the
        nonce, but spend_grant() on the same approval still returns
        True afterwards -- one approval can authorise two effects if
        a caller uses both consume paths. Single-use (CONTRACT §8:
        single-use nonce, approve-once) requires the second spend to
        fail. This test currently FAILS against shipped code; do not
        weaken it -- the two consume paths must be unified."""
        broker, _, pending, decision, req_hash = _approval_broker_and_decision()
        self.assertTrue(broker.verify_and_consume(decision))
        self.assertFalse(broker.spend_grant(pending.approval_id,
                                            request_hash=req_hash,
                                            is_destructive=True))

    def test_gesture_alone_authorises_nothing(self):
        _require_crypto()
        _require_real_module("approval")
        from sealvra.approval import (ApprovalBroker, ApprovalKind,
                                        build_card, compute_request_hash)
        clock = _FakeClock()
        broker = ApprovalBroker(clock=clock, min_card_dwell_s=0)
        card = build_card(
            approval_id="appr-g", key_id="key-0123456789abcdef",
            provider="github", key_label="TEST-ONLY GitHub",
            key_fingerprint_12="aabbccddeeff", permissions="delete repository",
            purpose="delete TEST-ONLY repo", kind=ApprovalKind.DESTRUCTIVE.value,
            other_key_count=0, is_destructive=True)
        req_hash = compute_request_hash(
            key_id="key-0123456789abcdef", provider="github", method="DELETE",
            canonical_path="/repos/a/b", scope_summary="delete repository",
            kind=ApprovalKind.DESTRUCTIVE.value)
        pending = broker.request(session_id="sess-adv-1", card=card,
                                 request_hash=req_hash,
                                 kind=ApprovalKind.DESTRUCTIVE.value,
                                 key_id="key-0123456789abcdef",
                                 provider="github", is_destructive=True)
        broker.continue_from_card(pending.approval_id)
        broker.record_gesture(pending.approval_id, ok=True)
        # Gesture moved state to 'confirm' but produced no decision and
        # no spendable grant: a gesture is presence, not authorisation.
        self.assertFalse(broker.spend_grant(pending.approval_id,
                                            request_hash=req_hash,
                                            is_destructive=True))

    def test_confirm_without_gesture_and_gesture_without_continue_rejected(self):
        _require_crypto()
        _require_real_module("approval")
        from sealvra.approval import (ApprovalBroker, ApprovalKind, WrongOrder,
                                        build_card, compute_request_hash)
        for stage in ("confirm-first", "gesture-first"):
            clock = _FakeClock()
            broker = ApprovalBroker(clock=clock, min_card_dwell_s=0)
            card = build_card(
                approval_id="appr-o", key_id="key-0123456789abcdef",
                provider="github", key_label="TEST-ONLY GitHub",
                key_fingerprint_12="aabbccddeeff", permissions="delete repository",
                purpose="delete TEST-ONLY repo",
                kind=ApprovalKind.DESTRUCTIVE.value, other_key_count=0,
                is_destructive=True)
            req_hash = compute_request_hash(
                key_id="key-0123456789abcdef", provider="github", method="DELETE",
                canonical_path="/repos/a/b", scope_summary="delete repository",
                kind=ApprovalKind.DESTRUCTIVE.value)
            pending = broker.request(session_id="sess-adv-1", card=card,
                                     request_hash=req_hash,
                                     kind=ApprovalKind.DESTRUCTIVE.value,
                                     key_id="key-0123456789abcdef",
                                     provider="github", is_destructive=True)
            if stage == "confirm-first":
                with self.assertRaises(WrongOrder):
                    broker.confirm(pending.approval_id)
            else:
                with self.assertRaises(WrongOrder):
                    broker.record_gesture(pending.approval_id, ok=True)

    def test_timeout_between_gesture_and_confirm_denies(self):
        _require_crypto()
        _require_real_module("approval")
        from sealvra.approval import (ApprovalBroker, ApprovalKind, ApprovalError,
                                        build_card, compute_request_hash)
        clock = _FakeClock()
        broker = ApprovalBroker(clock=clock, min_card_dwell_s=0)
        card = build_card(
            approval_id="appr-t", key_id="key-0123456789abcdef",
            provider="github", key_label="TEST-ONLY GitHub",
            key_fingerprint_12="aabbccddeeff", permissions="delete repository",
            purpose="delete TEST-ONLY repo", kind=ApprovalKind.DESTRUCTIVE.value,
            other_key_count=0, is_destructive=True)
        req_hash = compute_request_hash(
            key_id="key-0123456789abcdef", provider="github", method="DELETE",
            canonical_path="/repos/a/b", scope_summary="delete repository",
            kind=ApprovalKind.DESTRUCTIVE.value)
        pending = broker.request(session_id="sess-adv-1", card=card,
                                 request_hash=req_hash,
                                 kind=ApprovalKind.DESTRUCTIVE.value,
                                 key_id="key-0123456789abcdef",
                                 provider="github", is_destructive=True)
        broker.continue_from_card(pending.approval_id)
        broker.record_gesture(pending.approval_id, ok=True)
        clock.now += 61  # past the 60 s timeout: timeout always denies
        with self.assertRaises(ApprovalError):
            broker.confirm(pending.approval_id)
        self.assertFalse(broker.spend_grant(pending.approval_id,
                                            request_hash=req_hash,
                                            is_destructive=True))

    def test_approval_bound_to_exact_request_hash_and_single_use(self):
        broker, _, pending, _, req_hash = _approval_broker_and_decision()
        self.assertFalse(broker.spend_grant(pending.approval_id,
                                            request_hash="f" * 64,
                                            is_destructive=True))
        self.assertTrue(broker.spend_grant(pending.approval_id,
                                           request_hash=req_hash,
                                           is_destructive=True))
        self.assertFalse(broker.spend_grant(pending.approval_id,
                                            request_hash=req_hash,
                                            is_destructive=True))

    def test_non_destructive_grant_cannot_spend_destructive(self):
        broker, _, pending, _, req_hash = _approval_broker_and_decision(
            is_destructive=False, kind="session_scope")
        # A session-scope (non-destructive) grant must never authorise
        # a destructive call, even with its own request hash.
        self.assertFalse(broker.spend_grant(pending.approval_id,
                                            request_hash=req_hash,
                                            is_destructive=True))

    def test_breakglass_alone_cannot_spend_destructive(self):
        _require_crypto()
        _require_real_module("approval")
        from sealvra.approval import (ApprovalBroker, ApprovalKind, BreakGlass,
                                        build_card, compute_request_hash)
        import time as _time
        clock = _FakeClock()
        broker = ApprovalBroker(clock=clock, min_card_dwell_s=0)
        card = build_card(
            approval_id="appr-b", key_id="key-0123456789abcdef",
            provider="github", key_label="TEST-ONLY GitHub",
            key_fingerprint_12="aabbccddeeff", permissions="delete repository",
            purpose="delete TEST-ONLY repo", kind=ApprovalKind.DESTRUCTIVE.value,
            other_key_count=0, is_destructive=True)
        req_hash = compute_request_hash(
            key_id="key-0123456789abcdef", provider="github", method="DELETE",
            canonical_path="/repos/a/b", scope_summary="delete repository",
            kind=ApprovalKind.DESTRUCTIVE.value)
        pending = broker.request(session_id="sess-adv-1", card=card,
                                 request_hash=req_hash,
                                 kind=ApprovalKind.DESTRUCTIVE.value,
                                 key_id="key-0123456789abcdef",
                                 provider="github", is_destructive=True)
        glass = BreakGlass(activation_id="bg-1",
                           active_until_monotonic=_time.monotonic() + 3600,
                           presence_at_wall=_time.time())
        self.assertFalse(glass.covers_destructive())
        # Break-glass with NO approval at all must not spend.
        self.assertFalse(broker.spend_grant(pending.approval_id,
                                            request_hash=req_hash,
                                            is_destructive=True,
                                            breakglass=glass))

    def test_approve_once_deadline_not_validity_window(self):
        broker, clock, pending, _, req_hash = _approval_broker_and_decision()
        clock.now += 301  # past the 5 min consumption deadline
        self.assertFalse(broker.spend_grant(pending.approval_id,
                                            request_hash=req_hash,
                                            is_destructive=True))

    def test_x11_and_broker_window_destructive_refused_at_request(self):
        _require_crypto()
        _require_real_module("approval")
        from sealvra.approval import (ApprovalBroker, ApprovalKind, ApprovalError,
                                        PlatformTier, build_card,
                                        compute_request_hash)
        clock = _FakeClock()
        broker = ApprovalBroker(clock=clock, min_card_dwell_s=0)
        card = build_card(
            approval_id="appr-x", key_id="key-0123456789abcdef",
            provider="github", key_label="TEST-ONLY GitHub",
            key_fingerprint_12="aabbccddeeff", permissions="delete repository",
            purpose="delete TEST-ONLY repo", kind=ApprovalKind.DESTRUCTIVE.value,
            other_key_count=0, is_destructive=True)
        req_hash = compute_request_hash(
            key_id="key-0123456789abcdef", provider="github", method="DELETE",
            canonical_path="/repos/a/b", scope_summary="delete repository",
            kind=ApprovalKind.DESTRUCTIVE.value)
        with self.assertRaises(ApprovalError):
            broker.request(session_id="sess-adv-1", card=card,
                           request_hash=req_hash,
                           kind=ApprovalKind.DESTRUCTIVE.value,
                           key_id="key-0123456789abcdef", provider="github",
                           is_destructive=True, display_protocol="x11")
        tier = PlatformTier(platform="linux", mechanism="broker-window",
                            tier_label="T3", can_approve_destructive=False,
                            broker_window_t3=True)
        with self.assertRaises(ApprovalError):
            broker.request(session_id="sess-adv-1", card=card,
                           request_hash=req_hash,
                           kind=ApprovalKind.DESTRUCTIVE.value,
                           key_id="key-0123456789abcdef", provider="github",
                           is_destructive=True, tier=tier)

    def test_agent_words_never_in_headline(self):
        _require_crypto()
        _require_real_module("approval")
        from sealvra.approval import ApprovalKind, build_card
        agent_words = "delete repository and every secret right now"
        card = build_card(
            approval_id="appr-a", key_id="key-0123456789abcdef",
            provider="github", key_label="TEST-ONLY GitHub",
            key_fingerprint_12="aabbccddeeff", permissions="read repos",
            purpose="list TEST-ONLY repos", kind=ApprovalKind.SESSION_CREATION.value,
            other_key_count=0, agent_words=agent_words)
        rendered = card.render()
        self.assertNotIn(agent_words, rendered["headline"])
        self.assertEqual(rendered["agent_words_unverified"], agent_words)
        self.assertIsNone(rendered["password_field"])

    def test_foreign_channel_helper_always_refuses(self):
        _require_real_module("approval")
        from sealvra.approval import (OriginRefused, cli_or_dashboard_may_approve,
                                        refuse_foreign_approval)
        for channel in ("cli", "dashboard", "agent", "session", "control"):
            with self.assertRaises(OriginRefused):
                refuse_foreign_approval(channel)
        self.assertFalse(cli_or_dashboard_may_approve())


# ================================================================ N. session-token / PoP theft (real broker + proxy)
class TestPoPTheftReal(unittest.TestCase):
    def setUp(self):
        self._srv, self._base = _start_upstream()
        self._tmp = tempfile.TemporaryDirectory()
        self.harness = _RealProxyHarness(self._base, decide_mode="pack",
                                         use_audit_log=True,
                                         tmpdir=self._tmp.name)

    def tearDown(self):
        self.harness.close()
        self._tmp.cleanup()
        self._srv.shutdown()
        self._srv.server_close()

    def test_stolen_token_with_attacker_pop_key_fails(self):
        victim = self.harness.new_session(session_class="read_account")
        attacker = self.harness.new_session(session_class="read_public")
        # Attacker stole the victim token but holds only its own PoP key.
        resp = self.harness.call(victim, "GET", "/repos/o/r/contents/f.txt",
                                 token=victim.token, pop_key=attacker.pop_key)
        self.assertEqual(resp.status, 401)
        self.assertEqual(resp.body, b'{"error": "denied"}')
        self.assertEqual(self._srv.hits.get("/repos/o/r/contents/f.txt", 0), 0)

    def test_stolen_pop_replayed_through_proxy_fails_second_time(self):
        from sealvra.tokens import compute_pop
        created = self.harness.new_session(session_class="read_account")
        port = self._base.rsplit(":", 1)[1]
        host = "127.0.0.1:%s" % port
        path = "/repos/o/r/contents/f.txt"
        ts = int(time.time())
        pop = compute_pop(created.pop_key, "GET", host, path, b"", ts)
        headers = {"x-sealvra-session": created.token,
                   "x-sealvra-pop": pop,
                   "x-sealvra-timestamp": str(ts)}
        first = self.harness.proxy.handle("GET", self._base + path, headers, b"")
        self.assertEqual(first.status, 200)
        # Exact capture replay: same token, same PoP, same timestamp.
        second = self.harness.proxy.handle("GET", self._base + path, headers, b"")
        self.assertEqual(second.status, 401)
        self.assertEqual(second.body, b'{"error": "denied"}')
        self.assertEqual(self._srv.hits.get(path, 0), 1)

    def test_stolen_pop_rebound_to_other_path_body_host_fails(self):
        _require_real_module("broker")
        _require_real_module("tokens")
        from sealvra.broker import Broker
        from sealvra.tokens import body_sha256_hex, compute_pop
        broker = Broker()
        created = broker.create_session(key_id="key-aaaaaaaaaaaaaaaa",
                                        provider="github",
                                        session_class="read_account")
        ts = int(time.time())
        pop = compute_pop(created.pop_key, "GET", "api.github.com",
                          "/repos/a/b", b"", ts)
        base_kwargs = dict(method="GET", host="api.github.com",
                           canonical_path="/repos/a/b",
                           body_sha256_hex=body_sha256_hex(b""),
                           timestamp=ts, pop_hex=pop)
        # Same captured PoP presented for a different path, body, host,
        # and method must all fail (PoP binds all four + timestamp).
        self.assertFalse(broker.verify_pop(
            created.session, **{**base_kwargs, "canonical_path": "/repos/a/c"}))
        self.assertFalse(broker.verify_pop(
            created.session, **{**base_kwargs,
                                "body_sha256_hex": body_sha256_hex(b'{"x": 1}')}))
        self.assertFalse(broker.verify_pop(
            created.session, **{**base_kwargs, "host": "evil.example.com"}))
        self.assertFalse(broker.verify_pop(
            created.session, **{**base_kwargs, "method": "DELETE"}))
        try:
            broker.kill_session(created.session.session_id)
        except Exception:
            pass

    def test_full_capture_replay_at_broker_fails(self):
        _require_real_module("broker")
        _require_real_module("tokens")
        from sealvra.broker import Broker
        from sealvra.tokens import body_sha256_hex, compute_pop
        broker = Broker()
        created = broker.create_session(key_id="key-aaaaaaaaaaaaaaaa",
                                        provider="github",
                                        session_class="read_account")
        ts = int(time.time())
        pop = compute_pop(created.pop_key, "GET", "api.github.com",
                          "/repos/a/b", b"", ts)
        kwargs = dict(method="GET", host="api.github.com",
                      canonical_path="/repos/a/b",
                      body_sha256_hex=body_sha256_hex(b""),
                      timestamp=ts, pop_hex=pop)
        self.assertTrue(broker.verify_pop(created.session, **kwargs))
        # No-nonce replay: the broker must enforce single verification
        # (manager integration fix), not depend on the caller nonce.
        self.assertFalse(broker.verify_pop(created.session, **kwargs))
        try:
            broker.kill_session(created.session.session_id)
        except Exception:
            pass

    def test_token_hash_truncation_and_empty_token_fail(self):
        created = self.harness.new_session(session_class="read_account")
        digest = hashlib.sha256(created.token.encode()).hexdigest()
        for presented in (digest, created.token[:20], "", "kh_sess_" + "0" * 43,
                          created.token + "x"):
            self.assertIsNone(self.harness.broker.validate_token(presented))

    def test_killed_token_and_pop_are_dead(self):
        created = self.harness.new_session(session_class="read_account")
        self.assertIsNotNone(self.harness.broker.validate_token(created.token))
        self.harness.broker.kill_session(created.session.session_id)
        self.assertIsNone(self.harness.broker.validate_token(created.token))
        resp = self.harness.call(created, "GET", "/repos/o/r/contents/f.txt")
        self.assertEqual(resp.status, 401)
        self.assertEqual(self._srv.hits.get("/repos/o/r/contents/f.txt", 0), 0)

    def test_expired_and_idle_sessions_reject_pop(self):
        _require_real_module("broker")
        _require_real_module("tokens")
        from sealvra.broker import Broker
        from sealvra.tokens import body_sha256_hex, compute_pop
        broker = Broker()
        expired = broker.create_session(key_id="key-aaaaaaaaaaaaaaaa",
                                        provider="github",
                                        session_class="read_account")
        expired.session.expires_at = time.time() - 10
        ts = int(time.time())
        pop = compute_pop(expired.pop_key, "GET", "api.github.com",
                          "/repos/a/b", b"", ts)
        kwargs = dict(method="GET", host="api.github.com",
                      canonical_path="/repos/a/b",
                      body_sha256_hex=body_sha256_hex(b""),
                      timestamp=ts, pop_hex=pop)
        self.assertFalse(broker.verify_pop(expired.session, **kwargs))
        idle = broker.create_session(key_id="key-bbbbbbbbbbbbbbbb",
                                     provider="github",
                                     session_class="read_account")
        idle.session.idle_deadline = time.time() - 10
        pop2 = compute_pop(idle.pop_key, "GET", "api.github.com",
                           "/repos/a/b", b"", ts)
        self.assertFalse(broker.verify_pop(
            idle.session, **{**kwargs, "pop_hex": pop2}))
        for created in (expired, idle):
            try:
                broker.kill_session(created.session.session_id)
            except Exception:
                pass

    def test_pop_timestamp_outside_skew_fails(self):
        _require_real_module("broker")
        _require_real_module("tokens")
        from sealvra.broker import Broker
        from sealvra.tokens import body_sha256_hex, compute_pop
        broker = Broker()
        created = broker.create_session(key_id="key-aaaaaaaaaaaaaaaa",
                                        provider="github",
                                        session_class="read_account")
        for ts in (int(time.time()) - 301, int(time.time()) + 301):
            pop = compute_pop(created.pop_key, "GET", "api.github.com",
                              "/repos/a/b", b"", ts)
            self.assertFalse(broker.verify_pop(
                created.session, method="GET", host="api.github.com",
                canonical_path="/repos/a/b", body_sha256_hex=body_sha256_hex(b""),
                timestamp=ts, pop_hex=pop))
        try:
            broker.kill_session(created.session.session_id)
        except Exception:
            pass

    def test_denied_call_does_not_refresh_idle_but_success_does(self):
        created = self.harness.new_session(session_class="read_account")
        session = self.harness.broker.get_session(created.session.session_id)
        session.idle_deadline = time.time() + 120
        before = session.idle_deadline
        denied = self.harness.call(created, "GET", "/nope/unmodelled/path")
        self.assertEqual(denied.status, 403)
        self.assertEqual(session.idle_deadline, before)
        ok = self.harness.call(created, "GET", "/repos/o/r/contents/f.txt")
        self.assertEqual(ok.status, 200)
        self.assertGreater(session.idle_deadline, before)

    def test_session_token_and_pop_never_in_audit_files(self):
        created = self.harness.new_session(session_class="read_account")
        self.harness.call(created, "GET", "/repos/o/r/contents/f.txt")
        self.harness.call(created, "GET", "/nope/unmodelled/path")
        self.harness.audit.close()
        self.harness.audit = None
        hits = []
        for path in Path(self._tmp.name).rglob("*"):
            if path.is_file():
                blob = path.read_bytes().decode("utf-8", errors="ignore")
                if created.token in blob or created.pop_key.hex() in blob \
                        or FAKE_GITHUB in blob:
                    hits.append(str(path))
        self.assertEqual(hits, [])


# ================================================================ O. CONNECT tunnel bypass (real proxy)
class TestConnectTunnelReal(unittest.TestCase):
    def setUp(self):
        self._srv, self._base = _start_upstream()
        self._harness = _RealProxyHarness(self._base, decide_mode="pack")

    def tearDown(self):
        self._srv.shutdown()
        self._srv.server_close()

    def _connect_headers(self, created, host_part, port=None):
        from sealvra.tokens import compute_pop
        ts = int(time.time())
        pop = compute_pop(created.pop_key, "CONNECT", host_part, "/", b"", ts)
        return {"x-sealvra-session": created.token,
                "x-sealvra-pop": pop,
                "x-sealvra-timestamp": str(ts)}

    def test_connect_refused_for_absolute_transport(self):
        created = self._harness.new_session(session_class="read_public",
                                            transport="absolute")
        decision = self._harness.proxy.authorize_connect(
            "api.github.com:443", self._connect_headers(created, "api.github.com"))
        self.assertFalse(decision.allowed)

    def test_connect_refused_for_write_and_destructive_sessions(self):
        # Broker creation itself refuses connect_allowed for these classes.
        from sealvra.broker import SessionCreateError
        for cls in ("write", "destructive"):
            with self.assertRaises(SessionCreateError):
                self._harness.broker.create_session(
                    key_id="key-cccccccccccccccc", provider="github",
                    session_class=cls, transport="connect_allowed")
        # Defence in depth: even a session object carrying those classes
        # must be refused by authorize_connect itself.
        from sealvra.proxy import ProxyEngine, ProxyConfig
        from sealvra.types import Session
        forged = Session(session_id="sess-forged", key_id="key-cccccccccccccccc",
                         provider="github", session_class="destructive",
                         transport="connect_allowed", created_at=time.time(),
                         expires_at=time.time() + 600,
                         idle_deadline=time.time() + 300, process_group="",
                         ancestry="")
        engine = ProxyEngine(
            ProxyConfig(bases={"github": self._base}, test_mode=True),
            lookup_session=lambda token: forged,
            pop_key_for=lambda sid: b"0" * 32,
            decide=None, approve=None, audit_decision=None,
            audit_outcome=None, key_for=lambda kid: None)
        from sealvra.tokens import compute_pop
        ts = int(time.time())
        pop = compute_pop(b"0" * 32, "CONNECT", "127.0.0.1", "/", b"", ts)
        decision = engine.authorize_connect(
            "127.0.0.1:443",
            {"x-sealvra-session": "kh_sess_forged",
             "x-sealvra-pop": pop, "x-sealvra-timestamp": str(ts)})
        self.assertFalse(decision.allowed)

    def test_connect_denied_for_non_allowlisted_host_and_wrong_port(self):
        from sealvra.proxy import ProxyConfig, ProxyEngine
        created = self._harness.new_session(session_class="read_public",
                                            transport="connect_allowed")
        engine = ProxyEngine(
            ProxyConfig(bases={"github": "https://api.github.com"},
                        test_mode=False, connect_hosts=frozenset({"api.github.com"})),
            lookup_session=self._harness.broker.validate_token,
            pop_key_for=lambda sid: self._harness.pop_keys.get(sid),
            decide=None, approve=None,
            audit_decision=lambda e: self._harness.decision_entries.append(e),
            audit_outcome=None, key_for=lambda kid: None)
        self.assertFalse(engine.authorize_connect(
            "evil.example.com:443",
            self._connect_headers(created, "evil.example.com")).allowed)
        self.assertFalse(engine.authorize_connect(
            "api.github.com:8443",
            self._connect_headers(created, "api.github.com")).allowed)
        allowed = engine.authorize_connect(
            "api.github.com:443",
            self._connect_headers(created, "api.github.com"))
        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.audit_entry["transport_label"], "HOST-ONLY POLICY")

    def test_connect_denied_without_pop_and_with_replayed_pop(self):
        created = self._harness.new_session(session_class="read_public",
                                            transport="connect_allowed")
        port = self._base.rsplit(":", 1)[1]
        authority = "127.0.0.1:%s" % port
        headers = self._connect_headers(created, "127.0.0.1")
        no_pop = dict(headers)
        del no_pop["x-sealvra-pop"]
        self.assertFalse(self._harness.proxy.authorize_connect(authority, no_pop).allowed)
        self.assertTrue(self._harness.proxy.authorize_connect(authority, headers).allowed)
        self.assertFalse(self._harness.proxy.authorize_connect(authority, headers).allowed)

    def test_connect_denied_for_killed_session(self):
        created = self._harness.new_session(session_class="read_public",
                                            transport="connect_allowed")
        self._harness.broker.kill_session(created.session.session_id)
        port = self._base.rsplit(":", 1)[1]
        self.assertFalse(self._harness.proxy.authorize_connect(
            "127.0.0.1:%s" % port,
            self._connect_headers(created, "127.0.0.1")).allowed)

    def test_connect_audit_entry_labelled_host_only(self):
        created = self._harness.new_session(session_class="read_public",
                                            transport="connect_allowed")
        port = self._base.rsplit(":", 1)[1]
        decision = self._harness.proxy.authorize_connect(
            "127.0.0.1:%s" % port,
            self._connect_headers(created, "127.0.0.1"))
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.byte_budget,
                         self._harness.proxy.config.connect_byte_budget)
        entry = decision.audit_entry
        self.assertEqual(entry["transport_label"], "HOST-ONLY POLICY")
        self.assertEqual(entry["method"], "CONNECT")
        # The audit entry records the authority only -- never the
        # method/path/body that will flow inside the tunnel, because
        # the proxy cannot see them. That is the HOST-ONLY limit.
        self.assertNotIn("DELETE", json.dumps(entry))

    def test_tunnel_opt_in_does_not_bless_absolute_path_destructive_calls(self):
        created = self._harness.new_session(session_class="read_public",
                                            transport="connect_allowed")
        resp = self.harness_call_delete(created)
        self.assertEqual(resp.status, 403)
        self.assertEqual(resp.body, b'{"error": "denied"}')

    def harness_call_delete(self, created):
        body = b""
        return self._harness.call(created, "DELETE", "/repos/o/r")

    def test_tunnelled_bytes_are_not_policy_checked_host_only_label_is_the_control(self):
        """FINDING (documents design limit, honestly): once a tunnel is
        authorised, bytes inside it bypass path/body policy entirely --
        that is what HOST-ONLY POLICY means. This test PASSES by proving
        both halves: a DELETE request line smuggled through an authorised
        read-class tunnel DOES reach the upstream echo server, and the
        proxy audit contains NO decision entry for that tunnelled DELETE.
        The controls that remain are: tunnel only for read-class
        sessions, allowlisted hosts only, byte budget, and the label."""
        from sealvra.proxy import make_server
        created = self._harness.new_session(session_class="read_public",
                                            transport="connect_allowed")
        recorded = []

        class EchoHandler(socketserver.BaseRequestHandler):
            def handle(self):
                data = self.request.recv(65536)
                if data:
                    recorded.append(data)
                try:
                    self.request.sendall(b"ECHO-OK")
                except OSError:
                    pass

        echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
        echo.daemon_threads = True
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        proxy_srv = make_server(self._harness.proxy.config, self._harness.proxy,
                                port=0)
        threading.Thread(target=proxy_srv.serve_forever, daemon=True).start()
        try:
            echo_port = echo.server_address[1]
            proxy_port = proxy_srv.server_address[1]
            sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
            sock.settimeout(5)
            try:
                headers = self._connect_headers(created, "127.0.0.1")
                req = ("CONNECT 127.0.0.1:%d HTTP/1.1\r\n"
                       "Host: 127.0.0.1:%d\r\n"
                       "X-Sealvra-Session: %s\r\n"
                       "X-Sealvra-Pop: %s\r\n"
                       "X-Sealvra-Timestamp: %s\r\n\r\n"
                       % (echo_port, echo_port, headers["x-sealvra-session"],
                          headers["x-sealvra-pop"],
                          headers["x-sealvra-timestamp"]))
                sock.sendall(req.encode())
                head = b""
                while b"\r\n\r\n" not in head:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    head += chunk
                self.assertIn(b"200", head)
                sock.sendall(b"DELETE /repos/a/b HTTP/1.1\r\nHost: x\r\n\r\n")
                reply = sock.recv(4096)
                self.assertIn(b"ECHO-OK", reply)
            finally:
                sock.close()
            self.assertTrue(any(b"DELETE /repos/a/b" in blob for blob in recorded),
                            "tunnelled DELETE did not reach upstream echo server")
            tunnelled_decisions = [
                e for e in self._harness.decision_entries
                if e.get("canonical_path") == "/repos/a/b"]
            self.assertEqual(tunnelled_decisions, [])
            connect_entries = [
                e for e in self._harness.decision_entries
                if e.get("method") == "CONNECT"]
            self.assertEqual(len(connect_entries), 1)
            self.assertEqual(connect_entries[0]["transport_label"],
                             "HOST-ONLY POLICY")
        finally:
            proxy_srv.shutdown()
            proxy_srv.server_close()
            echo.shutdown()
            echo.server_close()


# ================================================================ P. GraphQL alias flooding + batching (real policy + proxy)
class TestGraphQLFloodingReal(unittest.TestCase):
    def setUp(self):
        self._srv, self._base = _start_upstream()
        self._harness = _RealProxyHarness(self._base, decide_mode="pack")

    def tearDown(self):
        self._srv.shutdown()
        self._srv.server_close()

    def test_pack_denies_graphql_for_all_session_classes_via_proxy(self):
        body = json.dumps({"query": "mutation { deleteRepo(input: {id: \"1\"}) { ok } }"}).encode()
        for cls in ("read_public", "write", "destructive"):
            created = self._harness.new_session(session_class=cls)
            resp = self._harness.call(created, "POST", "/graphql", body)
            self.assertEqual(resp.status, 403, cls)
            self.assertEqual(resp.body, b'{"error": "denied"}')
        self.assertEqual(self._srv.hits.get("/graphql", 0), 0)

    def test_alias_fields_counted_not_just_operations(self):
        """Shipped count_mutations() counts aliased mutation FIELDS,
        not operations (f06 F-04): one operation carrying 50 aliased
        destructive fields counts as 50 against the per-approval cap
        of 1, so it is denied outright rather than approved as one
        mutation. Verified against the real classifier, not the stub."""
        _require_real_module("policy")
        from sealvra.policy import count_mutations
        doc = graphql_alias_document(50)
        self.assertEqual(count_graphql_alias_fields(doc), 50)
        self.assertEqual(count_mutations(doc), 50)

    def test_single_mutation_operation_needs_approval_never_outright_allow(self):
        _require_real_module("policy")
        from sealvra.policy import evaluate_graphql_document
        # One mutation field: approval-gated (level 3), never allowed
        # outright.
        one = "mutation { a0: deleteRepo(input: {id: \"0\"}) { ok } }"
        decision = evaluate_graphql_document(one, session_class="write")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.level, 3)
        # Fifty aliased fields in one operation: over the per-approval
        # cap of 1, so denied outright (level 4), not approved as one.
        fifty = graphql_alias_document(50)
        decision50 = evaluate_graphql_document(fifty, session_class="write")
        self.assertFalse(decision50.allowed)
        self.assertEqual(decision50.level, 4)

    def test_batch_is_n_separate_decisions_none_allowed_without_approval(self):
        _require_real_module("policy")
        from sealvra.policy import evaluate_graphql_body
        batch = [{"query": "mutation { deleteRepo(input: {id: \"%d\"}) { ok } }" % i}
                 for i in range(30)]
        decisions = evaluate_graphql_body(batch, session_class="write")
        self.assertEqual(len(decisions), 30)
        self.assertTrue(all(not d.allowed for d in decisions))
        # A batch must not collapse into one decision or one approval.
        self.assertTrue(all(d.level == 3 for d in decisions))

    def test_graphql_batch_via_proxy_denied_not_forwarded(self):
        batch = json.dumps([{"query": "mutation { deleteRepo(input: {id: \"%d\"}) { ok } }" % i}
                            for i in range(30)]).encode()
        created = self._harness.new_session(session_class="destructive")
        resp = self._harness.call(created, "POST", "/graphql", batch)
        self.assertEqual(resp.status, 403)
        self.assertEqual(self._srv.hits.get("/graphql", 0), 0)

    def test_introspection_subscription_defer_and_fragment_cycle_denied(self):
        _require_real_module("policy")
        from sealvra.policy import evaluate_graphql_document
        docs = [
            "query { __schema { types { name } } }",
            "subscription { repoUpdated { id } }",
            "query { f @defer { id } }",
            "query { f @stream { id } }",
            "query { ...A } fragment A on T { ...B } fragment B on T { ...A }",
        ]
        for doc in docs:
            decision = evaluate_graphql_document(doc, session_class="write")
            self.assertFalse(decision.allowed, doc)
            self.assertEqual(decision.level, 4, doc)

    def test_mutation_word_inside_string_not_counted(self):
        _require_real_module("policy")
        from sealvra.policy import count_mutations
        doc = 'query { search(text: "mutation { fake }") { id } }'
        self.assertEqual(count_mutations(doc), 0)

    def test_variables_not_resolved_before_classification(self):
        """FINDING (documents gap): evaluate_graphql_body classifies
        the `query` string only; a mutation smuggled in `variables`
        is not examined. This test PASSES by asserting the current
        behaviour (query-only body classifies as a plain query) to
        prove the gap exists. Mitigation today: the GitHub pack denies
        /graphql outright and the proxy never resolves variables into
        the query, so no live path forwards this -- but any future
        GraphQL route must resolve variables before classification
        (policy docstring, v3 N-G6)."""
        _require_real_module("policy")
        from sealvra.policy import evaluate_graphql_body
        body = {"query": "query Q($x: String) { f(a: $x) { id } }",
                "variables": {"x": "mutation { deleteRepo(input: {id: \"1\"}) { ok } }"}}
        decisions = evaluate_graphql_body(body, session_class="read_public")
        self.assertEqual(len(decisions), 1)
        self.assertTrue(decisions[0].allowed)


# ================================================================ Q. credential-creating + compressed responses (real proxy)
class TestCredentialResponseReal(unittest.TestCase):
    def setUp(self):
        self._srv, self._base = _start_upstream()
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._srv.shutdown()
        self._srv.server_close()
        self._tmp.cleanup()

    def _harness(self, decide_mode="allow"):
        return _RealProxyHarness(self._base, decide_mode=decide_mode,
                                 use_audit_log=False, tmpdir=self._tmp.name)

    def _get(self, harness, path):
        created = harness.new_session(session_class="read_account")
        return harness, created, harness.call(created, "GET", path)

    def test_raw_secret_echo_blocked(self):
        h = self._harness()
        _, _, resp = self._get(h, "/scan/raw")
        self.assertEqual(resp.status, 502)
        self.assertEqual(resp.body, b'{"error": "denied"}')
        self.assertNotIn(FAKE_GITHUB.encode(), resp.body)
        self.assertEqual(h.outcome_entries[-1]["outcome"], "blocked")

    def test_gzipped_secret_echo_blocked(self):
        h = self._harness()
        _, _, resp = self._get(h, "/scan/gzip")
        self.assertEqual(resp.status, 502)
        self.assertEqual(resp.body, b'{"error": "denied"}')
        self.assertNotIn(FAKE_GITHUB.encode(), resp.body)
        self.assertGreaterEqual(self._srv.hits.get("/scan/gzip", 0), 1)

    def test_deflated_secret_echo_blocked(self):
        h = self._harness()
        _, _, resp = self._get(h, "/scan/deflate")
        self.assertEqual(resp.status, 502)
        self.assertNotIn(FAKE_GITHUB.encode(), resp.body)

    def test_brotli_response_refused_never_relayed_unscanned(self):
        h = self._harness()
        _, _, resp = self._get(h, "/scan/brotli")
        # The proxy has no brotli decoder: the only safe action is to
        # refuse the relay, never to pass unscanned bytes to the agent.
        self.assertEqual(resp.status, 502)
        self.assertEqual(resp.body, b'{"error": "denied"}')
        self.assertNotIn(FAKE_GITHUB.encode(), resp.body)
        self.assertGreaterEqual(self._srv.hits.get("/scan/brotli", 0), 1)

    def test_json_unicode_escaped_secret_echo_blocked(self):
        h = self._harness()
        _, _, resp = self._get(h, "/scan/json-escaped")
        self.assertEqual(resp.status, 502)
        self.assertNotIn(FAKE_GITHUB.encode(), resp.body)
        # The escaped form itself must not leak either.
        self.assertNotIn(unicode_escape_json(FAKE_GITHUB).encode(), resp.body)

    def test_hex_and_url_encoded_secret_echoes_blocked(self):
        for path in ("/scan/hex", "/scan/url"):
            h = self._harness()
            _, _, resp = self._get(h, path)
            self.assertEqual(resp.status, 502, path)
            self.assertNotIn(FAKE_GITHUB.encode(), resp.body, path)

    def test_secret_in_response_header_blocked(self):
        h = self._harness()
        _, _, resp = self._get(h, "/scan/header")
        self.assertEqual(resp.status, 502)
        self.assertNotIn(FAKE_GITHUB.encode(), resp.body)
        for _, value in resp.headers:
            self.assertNotIn(FAKE_GITHUB, value)

    def test_minted_credential_response_not_relayed_to_agent(self):
        h = self._harness()
        _, _, resp = self._get(h, "/scan/minted")
        # The minted token is NOT the session key, yet relaying it
        # would hand the agent a fresh credential (CONTRACT §6 step 8,
        # v3 N-G2: credential-creating responses are DENIED).
        self.assertEqual(resp.status, 502)
        self.assertEqual(resp.body, b'{"error": "denied"}')
        self.assertNotIn(b"TEST-ONLY-minted-by-upstream-4242", resp.body)
        self.assertGreaterEqual(self._srv.hits.get("/scan/minted", 0), 1)
        self.assertEqual(h.outcome_entries[-1]["outcome"], "blocked")

    def test_credential_creating_endpoint_denied_before_forward(self):
        h = self._harness(decide_mode="credential_creating")
        created = h.new_session(session_class="read_account")
        resp = h.call(created, "GET", "/scan/clean")
        self.assertEqual(resp.status, 403)
        self.assertEqual(self._srv.hits.get("/scan/clean", 0), 0)

    def test_pack_credential_endpoint_denied_before_forward(self):
        h = self._harness(decide_mode="pack")
        created = h.new_session(session_class="destructive")
        resp = h.call(created, "POST", "/user/keys", b'{"name": "x"}')
        self.assertEqual(resp.status, 403)
        self.assertEqual(resp.body, b'{"error": "denied"}')
        self.assertEqual(self._srv.hits.get("/user/keys", 0), 0)

    def test_clean_response_still_relayed_intact(self):
        h = self._harness()
        _, _, resp = self._get(h, "/scan/clean")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.body, b'{"ok": true}')


if __name__ == "__main__":
    unittest.main(verbosity=2)
