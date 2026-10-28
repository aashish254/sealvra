"""W05 git interposition tests (unittest, stdlib only).

No real GitHub, no real keys: every key is a TEST-ONLY fake, every
session token is freshly generated in-process, and the only network
use is a loopback fake remote that validates a session token the
same way a Keyholder git proxy would (token + scope + expiry).
Real git is never run against a real remote: wrapper runs go to a
recording stub (or a fake-git script for the named-remote path).
"""

import base64
import http.client
import http.server
import json
import os
import stat
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from keyholder import git as g
from keyholder.audit import AuditLog
from keyholder.tokens import generate_token

REAL_KEY = "TEST-ONLY-ghp_fakekeythatisnotreal000000000000"
HOST = "127.0.0.1"
REPO = "octo/hello"
NOW = 1_800_000_000.0


def make_session(session_class="write", expires=NOW + 600):
    return g.GitSession(
        session_id="sess-test0000000001", key_id="key-test0000000001",
        scope=g.GitScope(HOST, REPO), expires_at=expires,
        session_class=session_class)


_USE_STUB = object()


def make_wrapper(session=None, token=None, approvals=None, sink=None,
                 runner=_USE_STUB, git_binary="git"):
    session = session or make_session()
    token = token if token is not None else generate_token()
    calls = []

    def default_runner(argv, env):
        calls.append({"argv": argv, "prompt_off": env.get("GIT_TERMINAL_PROMPT") == "0",
                      "has_token": bool(env.get("KH_GIT_SESSION_TOKEN")),
                      "scope_host": env.get("KH_GIT_SCOPE_HOST"),
                      "scope_repo": env.get("KH_GIT_SCOPE_REPO")})
        return 0

    wrapper = g.GitWrapper(session, token, audit_sink=sink,
                           approvals=approvals, git_binary=git_binary,
                           runner=default_runner if runner is _USE_STUB else runner)
    return wrapper, calls, token


def list_sink():
    events = []

    def sink(event):
        events.append(event)

    return events, sink


def url_for(host, repo, port=None):
    if port is not None:
        return f"http://{host}:{port}/{repo}.git"
    return f"https://{host}/{repo}.git"


class TestCredentialProtocol(unittest.TestCase):
    def test_parse_stops_at_blank_line(self):
        fields = g.parse_credential_input(
            "protocol=https\nhost=example.com\npath=o/r\n\nusername=x\n")
        self.assertEqual(fields, {"protocol": "https", "host": "example.com",
                                  "path": "o/r"})

    def test_parse_ignores_malformed_lines(self):
        self.assertEqual(g.parse_credential_input("nonsense\nhost=h\n"),
                         {"host": "h"})

    def test_format_round_trips(self):
        block = g.format_credential_output({"host": "h", "username": "u"})
        self.assertTrue(block.endswith("\n\n"))
        self.assertEqual(g.parse_credential_input(block),
                         {"host": "h", "username": "u"})


class TestGitUrlAndScope(unittest.TestCase):
    def test_https_with_port_and_git_suffix(self):
        self.assertEqual(g.parse_git_url("http://127.0.0.1:18777/o/r.git"),
                         ("127.0.0.1:18777", "o/r"))

    def test_scp_like(self):
        self.assertEqual(g.parse_git_url("git@github.com:octo/hello.git"),
                         ("github.com", "octo/hello"))

    def test_unparsable_returns_none(self):
        self.assertIsNone(g.parse_git_url("not-a-url"))
        self.assertIsNone(g.parse_git_url("ftp://h/o/r"))

    def test_scope_exact_match_only(self):
        scope = g.GitScope(HOST, REPO)
        self.assertTrue(scope.matches(HOST, "octo/hello.git"))
        self.assertFalse(scope.matches(HOST, "octo/other"))
        self.assertFalse(scope.matches("evil.example", "octo/hello"))
        self.assertFalse(scope.matches(HOST, "octo/hello/sub"))


class TestIssuer(unittest.TestCase):
    def test_issue_returns_session_token_never_real_key(self):
        token = generate_token()
        cred = g.GitCredentialIssuer(make_session(), token).issue(HOST, REPO, now=NOW)
        self.assertIsNotNone(cred)
        self.assertEqual(cred.password, token)
        self.assertEqual(cred.username, "keyholder")
        self.assertNotIn(REAL_KEY, cred.password)
        self.assertTrue(cred.password.startswith("kh_sess_"))

    def test_issue_refuses_wrong_host_repo_and_expiry(self):
        token = generate_token()
        issuer = g.GitCredentialIssuer(make_session(), token)
        self.assertIsNone(issuer.issue("evil.example", REPO, now=NOW))
        self.assertIsNone(issuer.issue(HOST, "octo/other", now=NOW))
        self.assertIsNone(issuer.issue(HOST, REPO, now=NOW + 601))
        self.assertIsNone(issuer.issue_for_url("https://evil.example/o/r", now=NOW))

    def test_issuer_rejects_non_session_token(self):
        with self.assertRaises(ValueError):
            g.GitCredentialIssuer(make_session(), REAL_KEY)


class TestHelperHandling(unittest.TestCase):
    def context(self, expires=NOW + 600):
        return g.GitHelperContext(token=generate_token(), expires_at=expires,
                                  scope_host=HOST, scope_repo=REPO)

    def test_get_in_scope(self):
        ctx = self.context()
        out, code = g.handle_helper(
            "get", f"protocol=https\nhost={HOST}\npath={REPO}\n\n", ctx, now=NOW)
        self.assertEqual(code, 0)
        fields = g.parse_credential_input(out)
        self.assertEqual(fields["password"], ctx.token)
        self.assertEqual(fields["username"], "keyholder")
        self.assertNotIn(REAL_KEY, out)

    def test_get_denies_out_of_scope_expired_and_missing_fields(self):
        ctx = self.context()
        for text in (f"host=evil.example\npath={REPO}\n\n",
                     f"host={HOST}\npath=octo/other\n\n",
                     f"host={HOST}\n\n"):
            out, code = g.handle_helper("get", text, ctx, now=NOW)
            self.assertEqual((out, code), ("", 1))
            self.assertNotIn(ctx.token, out)
        out, code = g.handle_helper(
            "get", f"host={HOST}\npath={REPO}\n\n", ctx, now=NOW + 601)
        self.assertEqual((out, code), ("", 1))

    def test_store_and_erase_are_noops(self):
        ctx = self.context()
        for action in ("store", "erase"):
            self.assertEqual(g.handle_helper(action, "host=h\n\n", ctx, now=NOW),
                             ("", 0))
        self.assertEqual(g.handle_helper("bogus", "", ctx, now=NOW), ("", 1))
        self.assertEqual(g.handle_helper("get", "", None, now=NOW), ("", 1))

    def test_context_from_env_rejects_non_session_token(self):
        env = {"KH_GIT_SESSION_TOKEN": REAL_KEY,
               "KH_GIT_EXPIRES_AT": str(NOW + 600),
               "KH_GIT_SCOPE_HOST": HOST, "KH_GIT_SCOPE_REPO": REPO}
        self.assertIsNone(g.GitHelperContext.from_env(env))
        env["KH_GIT_SESSION_TOKEN"] = generate_token()
        self.assertIsNotNone(g.GitHelperContext.from_env(env))


class TestParseGitArgs(unittest.TestCase):
    def test_force_variants(self):
        for argv in (["push", "origin", "--force", "main"],
                     ["push", "origin", "-f", "main"],
                     ["push", "origin", "--force-with-lease", "main"],
                     ["push", "origin", "--force-with-lease=main:abc", "main"],
                     ["push", "origin", "+main"],
                     ["push", "origin", "--force-if-includes", "main"]):
            op = g.parse_git_args(argv)
            self.assertTrue(op.force, argv)
            self.assertTrue(op.needs_force_approval, argv)

    def test_delete_variants(self):
        for argv in (["push", "origin", "--delete", "feature"],
                     ["push", "origin", "-d", "feature"],
                     ["push", "origin", ":feature"],
                     ["push", "origin", "main", ":old"]):
            op = g.parse_git_args(argv)
            self.assertTrue(op.deletes, argv)
            self.assertTrue(op.needs_delete_approval, argv)

    def test_mirror_needs_both(self):
        op = g.parse_git_args(["push", "origin", "--mirror"])
        self.assertTrue(op.force and op.deletes)
        self.assertEqual(op.refs, ("*",))

    def test_normal_push_and_ref_normalisation(self):
        op = g.parse_git_args(["push", "origin", "main"])
        self.assertFalse(op.force or op.deletes)
        self.assertEqual(op.refs, ("refs/heads/main",))
        op = g.parse_git_args(["push", "origin", "main:dev"])
        self.assertEqual(op.refs, ("refs/heads/dev",))

    def test_bare_push_refused_and_unknown_command_refused(self):
        with self.assertRaises(g.GitDenied):
            g.parse_git_args(["push"])
        with self.assertRaises(g.GitDenied):
            g.parse_git_args(["status"])

    def test_fetch_force_is_not_push_force(self):
        op = g.parse_git_args(["fetch", "origin", "--force"])
        self.assertFalse(op.needs_force_approval)
        op = g.parse_git_args(["clone", "https://127.0.0.1/octo/hello.git"])
        self.assertEqual(op.command, "clone")


class TestApprovalMatching(unittest.TestCase):
    def test_kind_ref_and_expiry_matching(self):
        approval = g.Approval("appr-1", "sess-test0000000001",
                              frozenset({"force_push"}),
                              frozenset({"main"}), NOW + 300)
        self.assertTrue(approval.covers("sess-test0000000001", "force_push",
                                        ("refs/heads/main",), now=NOW))
        self.assertFalse(approval.covers("sess-test0000000001", "ref_delete",
                                         ("refs/heads/main",), now=NOW))
        self.assertFalse(approval.covers("sess-test0000000001", "force_push",
                                         ("refs/heads/other",), now=NOW))
        self.assertFalse(approval.covers("sess-test0000000001", "force_push",
                                         ("refs/heads/main",), now=NOW + 301))
        self.assertFalse(approval.covers("sess-other", "force_push",
                                         ("refs/heads/main",), now=NOW))

    def test_superset_refs_cover_subset(self):
        approval = g.Approval("appr-2", "sess-test0000000001",
                              frozenset({"ref_delete"}),
                              frozenset({"main", "dev"}), NOW + 300)
        self.assertTrue(approval.covers("sess-test0000000001", "ref_delete",
                                        ("refs/heads/main",), now=NOW))
        self.assertFalse(approval.covers("sess-test0000000001", "ref_delete",
                                         ("refs/heads/main", "refs/heads/x"),
                                         now=NOW))


class TestWrapperGating(unittest.TestCase):
    def test_normal_push_runs_with_locked_down_env_and_audit(self):
        events, sink = list_sink()
        wrapper, calls, token = make_wrapper(sink=sink)
        result = wrapper.run(["push", url_for(HOST, REPO), "main"], now=NOW)
        self.assertTrue(result.allowed)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(len(calls), 1)
        argv = calls[0]["argv"]
        self.assertEqual(argv[1:7], ["-c", "credential.helper=",
                                     "-c", f"credential.helper={g.helper_script_path()}",
                                     "-c", "credential.useHttpPath=true"])
        self.assertTrue(calls[0]["prompt_off"])
        self.assertTrue(calls[0]["has_token"])
        self.assertEqual(calls[0]["scope_host"], HOST)
        self.assertEqual(calls[0]["scope_repo"], REPO)
        kinds = [e.kind for e in events]
        self.assertEqual(kinds, ["decision", "outcome"])
        self.assertEqual(events[0].decision, "allow")
        self.assertEqual(events[1].outcome, "success")

    def test_force_push_denied_without_approval_and_git_not_run(self):
        events, sink = list_sink()
        wrapper, calls, _ = make_wrapper(sink=sink)
        result = wrapper.run(["push", url_for(HOST, REPO), "--force", "main"],
                             now=NOW)
        self.assertFalse(result.allowed)
        self.assertEqual(result.rule_id, "GIT-FORCE-01")
        self.assertEqual(calls, [])
        self.assertEqual([e.decision for e in events], ["deny"])

    def test_force_push_allowed_with_matching_approval(self):
        events, sink = list_sink()
        approval = g.Approval("appr-9", "sess-test0000000001",
                              frozenset({"force_push"}), frozenset({"main"}),
                              NOW + 300)
        wrapper, calls, _ = make_wrapper(sink=sink, approvals=[approval])
        result = wrapper.run(["push", url_for(HOST, REPO), "--force", "main"],
                             now=NOW)
        self.assertTrue(result.allowed)
        self.assertEqual(result.approval_id, "appr-9")
        self.assertEqual(len(calls), 1)

    def test_ref_delete_denied_and_mirror_needs_both_approvals(self):
        events, sink = list_sink()
        wrapper, calls, _ = make_wrapper(sink=sink)
        result = wrapper.run(["push", url_for(HOST, REPO), "--delete", "old"],
                             now=NOW)
        self.assertFalse(result.allowed)
        self.assertEqual(result.rule_id, "GIT-DELETE-01")
        force_only = g.Approval("appr-f", "sess-test0000000001",
                                frozenset({"force_push"}), frozenset({"*"}),
                                NOW + 300)
        wrapper, calls, _ = make_wrapper(sink=sink, approvals=[force_only])
        result = wrapper.run(["push", url_for(HOST, REPO), "--mirror"], now=NOW)
        self.assertFalse(result.allowed)  # delete approval still missing
        self.assertEqual(calls, [])

    def test_out_of_scope_and_bare_push_denied(self):
        _, sink = list_sink()
        wrapper, calls, _ = make_wrapper(sink=sink)
        result = wrapper.run(["push", "https://127.0.0.1/octo/other.git", "main"],
                             now=NOW)
        self.assertFalse(result.allowed)
        self.assertEqual(result.rule_id, "GIT-SCOPE-02")
        result = wrapper.run(["push"], now=NOW)
        self.assertFalse(result.allowed)
        self.assertEqual(calls, [])

    def test_read_session_cannot_push_but_can_fetch(self):
        _, sink = list_sink()
        wrapper, calls, _ = make_wrapper(session=make_session("read_account"),
                                         sink=sink)
        self.assertFalse(wrapper.run(
            ["push", url_for(HOST, REPO), "main"], now=NOW).allowed)
        self.assertTrue(wrapper.run(
            ["fetch", url_for(HOST, REPO)], now=NOW).allowed)
        self.assertEqual(len(calls), 1)

    def test_expired_session_denied(self):
        _, sink = list_sink()
        wrapper, calls, _ = make_wrapper(session=make_session(expires=NOW - 1),
                                         sink=sink)
        result = wrapper.run(["fetch", url_for(HOST, REPO)], now=NOW)
        self.assertFalse(result.allowed)
        self.assertEqual(result.rule_id, "GIT-SESSION-01")
        self.assertEqual(calls, [])

    def test_audit_failure_is_fail_closed(self):
        def failing_sink(event):
            raise RuntimeError("disk full (test)")

        wrapper, calls, _ = make_wrapper(sink=failing_sink)
        result = wrapper.run(["push", url_for(HOST, REPO), "main"], now=NOW)
        self.assertFalse(result.allowed)
        self.assertEqual(result.rule_id, "GIT-AUDIT-02")
        self.assertEqual(calls, [])

    def test_no_sink_is_fail_closed(self):
        wrapper, calls, _ = make_wrapper(sink=None)
        result = wrapper.run(["fetch", url_for(HOST, REPO)], now=NOW)
        self.assertFalse(result.allowed)
        self.assertEqual(calls, [])

    def test_outcome_sink_failure_is_reported_not_hidden(self):
        seen = []

        def flaky_sink(event):
            seen.append(event.kind)
            if event.kind == "outcome":
                raise RuntimeError("outcome log lost (test)")

        wrapper, calls, _ = make_wrapper(sink=flaky_sink)
        result = wrapper.run(["fetch", url_for(HOST, REPO)], now=NOW)
        self.assertTrue(result.allowed)
        self.assertFalse(result.outcome_logged)


FAKE_GIT_SCRIPT = '''#!/usr/bin/env python3
import json, os, sys
record = os.environ["FAKE_GIT_RECORD"]
entry = {"argv": sys.argv[1:], "prompt_off": os.environ.get("GIT_TERMINAL_PROMPT") == "0",
         "has_token": bool(os.environ.get("KH_GIT_SESSION_TOKEN"))}
if sys.argv[1:3] == ["remote", "get-url"]:
    name = sys.argv[3]
    if name == "origin":
        print(os.environ.get("FAKE_GIT_ORIGIN_URL", ""))
        sys.exit(0)
    sys.exit(1)
with open(record, "a") as f:
    f.write(json.dumps(entry) + "\\n")
sys.exit(0)
'''


class TestWrapperNamedRemoteAndHelperScript(unittest.TestCase):
    def test_named_remote_resolves_and_helper_script_runs(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "fake-git"
            fake.write_text(FAKE_GIT_SCRIPT)
            fake.chmod(0o700)
            record = Path(tmp) / "record.jsonl"
            env = dict(os.environ, FAKE_GIT_RECORD=str(record),
                       FAKE_GIT_ORIGIN_URL=url_for(HOST, REPO))
            old_env = dict(os.environ)
            os.environ.clear()
            os.environ.update(env)
            try:
                events, sink = list_sink()
                wrapper, _, _ = make_wrapper(sink=sink, runner=None,
                                             git_binary=str(fake))
                result = wrapper.run(["push", "origin", "main"], now=NOW)
            finally:
                os.environ.clear()
                os.environ.update(old_env)
            self.assertTrue(result.allowed)
            entries = [json.loads(ln) for ln in record.read_text().splitlines()]
            self.assertEqual(len(entries), 1)
            self.assertTrue(entries[0]["prompt_off"])
            self.assertTrue(entries[0]["has_token"])

            # The real helper script, run as a subprocess, issues the
            # session credential and never writes anything to disk.
            home = Path(tmp) / "home"
            home.mkdir()
            helper = Path(__file__).resolve().parent.parent / "scripts" / "git-credential-helper"
            self.assertTrue(os.access(helper, os.X_OK))
            token = generate_token()
            helper_env = dict(os.environ, HOME=str(home),
                              KH_GIT_SESSION_TOKEN=token,
                              KH_GIT_EXPIRES_AT=str(int(NOW + 600)),
                              KH_GIT_SCOPE_HOST=HOST,
                              KH_GIT_SCOPE_REPO=REPO)
            proc = subprocess.run(
                [str(helper), "get"], input=f"host={HOST}\npath={REPO}\n\n",
                capture_output=True, text=True, env=helper_env)
            self.assertEqual(proc.returncode, 0)
            self.assertIn(f"password={token}", proc.stdout)
            self.assertNotIn(REAL_KEY, proc.stdout)
            self.assertNotIn(token, proc.stderr)
            proc = subprocess.run(
                [str(helper), "store"], input=f"host={HOST}\npath={REPO}\n\n",
                capture_output=True, text=True, env=helper_env)
            self.assertEqual(proc.returncode, 0)
            self.assertFalse((home / ".git-credentials").exists())
            proc = subprocess.run(
                [str(helper), "get"], input="host=evil.example\npath=o/r\n\n",
                capture_output=True, text=True, env=helper_env)
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(proc.stdout, "")


class FakeRemoteHandler(http.server.BaseHTTPRequestHandler):
    expected_token = ""
    expires_at = 0.0

    def log_message(self, *args):  # keep test output clean
        pass

    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        want = "Basic " + base64.b64encode(
            f"keyholder:{self.expected_token}".encode()).decode()
        if self.path.startswith("/octo/hello") and auth == want \
                and time.time() < self.expires_at:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"fake git remote: authenticated")
        else:
            self.send_response(401)
            self.end_headers()


class TestFakeRemoteCredentialFlow(unittest.TestCase):
    def test_helper_credential_authenticates_to_fake_remote(self):
        token = generate_token()
        server = http.server.HTTPServer(("127.0.0.1", 0), FakeRemoteHandler)
        FakeRemoteHandler.expected_token = token
        FakeRemoteHandler.expires_at = time.time() + 600
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            scope = g.GitScope(f"127.0.0.1:{port}", REPO)
            session = g.GitSession("sess-test0000000001", "key-test0000000001",
                                   scope, time.time() + 600)
            cred = g.GitCredentialIssuer(session, token).issue(
                f"127.0.0.1:{port}", REPO)
            self.assertIsNotNone(cred)
            auth = "Basic " + base64.b64encode(
                f"{cred.username}:{cred.password}".encode()).decode()
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", f"/{REPO}.git/info/refs",
                         headers={"Authorization": auth})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            resp.read()
            # A wrong token is refused by the fake remote.
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", f"/{REPO}.git/info/refs",
                         headers={"Authorization": "Basic " + base64.b64encode(
                             b"keyholder:wrong").decode()})
            self.assertEqual(conn.getresponse().status, 401)
        finally:
            server.shutdown()
            server.server_close()


class TestAuditBackedWrapper(unittest.TestCase):
    def test_real_audit_log_has_decision_and_outcome_without_token(self):
        import tempfile
        token = generate_token()
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(tmp, b"TEST-ONLY-audit-secret")
            sink = g.make_audit_sink(log, b"TEST-ONLY-audit-secret",
                                     "sess-test0000000001", "key-test0000000001")
            wrapper, calls, _ = make_wrapper(sink=sink)
            # Rebuild the wrapper with the real token so the sink's
            # session matches; the token itself must never be logged.
            wrapper._token = token
            result = wrapper.run(["push", url_for(HOST, REPO), "main"], now=NOW)
            self.assertTrue(result.allowed)
            text = (Path(tmp) / "audit" / "audit.jsonl").read_text()
            self.assertIn("GIT_PUSH", text)
            self.assertIn('"decision":"allow"', text)
            self.assertNotIn(token, text)
            self.assertNotIn(REAL_KEY, text)
            self.assertEqual(log.verify().status, "OK")


class TestDoctorFlagsStandingGitCredentials(unittest.TestCase):
    def test_doctor_inventory_includes_git_credential_stores(self):
        import tempfile
        from keyholder.cli import _doctor_findings
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".git-credentials").write_text(
                "https://user:TEST-ONLY-pass@github.com\n")
            gh_dir = Path(tmp) / ".config" / "gh"
            gh_dir.mkdir(parents=True)
            (gh_dir / "hosts.yml").write_text("github.com:\n  oauth_token: x\n")
            findings = _doctor_findings(tmp, tmp, {})
            joined = "\n".join(findings)
            self.assertIn(".git-credentials", joined)
            self.assertIn("hosts.yml", joined)
            self.assertNotIn("TEST-ONLY-pass", joined)


class TestCoverageStatement(unittest.TestCase):
    def test_bypass_is_stated_not_hidden(self):
        report = g.coverage_report()
        self.assertIn("direct git with standing credentials", report)
        self.assertIn("NOT COVERED", report)
        self.assertIn("never a real key", g.COVERAGE["helper_get"])


if __name__ == "__main__":
    unittest.main()
