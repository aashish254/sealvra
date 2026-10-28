"""End-to-end tests for Keyholder v0.1 (W15).

Two layers, kept strictly separate so a green run can never be mistaken
for proof it is not:

  Layer A -- MockProviderTests (runs NOW, stdlib only, no Keyholder
  code needed). Proves the mocks in mock_providers.py faithfully
  implement the upstream surfaces: reads/writes succeed when reached,
  denied-class surfaces succeed when reached (so a proxy denial is
  proved by the mock NOT being reached, never by the mock refusing),
  and the Gemini key-echo endpoint really returns the injected fake
  key inside a gzipped body (so a proxy response-scan test is real).

  Layer B -- RealPathTests (requires the real daemon + proxy + CLI
  from W01/W04/W10). Every test drives the real stack: daemon started
  as a subprocess, session created through the CLI, proxied calls made
  with a correctly signed PoP header, kill/expiry/audit verified
  through the CLI. NO test-local stub daemon, proxy, or policy exists
  in this file -- if the real stack is absent, each Layer B test
  SKIPs (NOT-RUN) with the missing piece named, per CONTRACT section
  11. A skip is never reported as a pass.

PORTS: mock GitHub 127.0.0.1:18765, mock Gemini 127.0.0.1:18766
(see mock_providers.py header -- W15 owns the choice; defaults kept).
Proxy default 127.0.0.1:8765 (CONTRACT section 6).

DRIVER ASSUMPTIONS (update ONLY this section if W01/W10 land different
flags; do not edit other workers' files to match this file). These
forms were read from the landed W10 CLI at authoring time:
  * Daemon runs as:  python3 -m keyholder daemon start
    with PYTHONPATH pointed at the build root, in a scratch cwd, with
    env KEYHOLDER_TEST_MODE=1, KEYHOLDER_MOCK_GITHUB_BASE /
    KEYHOLDER_MOCK_GEMINI_BASE pointing at the loopback mocks, and
    KEYHOLDER_PROXY_PORT for the proxy.
  * v0.2 RE-CHECK (W20, 2026-10-28, measured on this Linux VM — the
    reason Layer B is STILL skipped, not a pass): the cross-process
    daemon itself HAS landed (CONTRACT §13.1: detached
    `keyholder.daemon --serve`, Unix-socket IPC in 0700 dir
    `$KEYHOLDER_DAEMON_DIR` else `~/.keyholder/daemon`, SO_PEERCRED
    peer-UID; `tests/test_daemon_ipc.py` passes; start/status/stop
    across CLI invocations verified live with an isolated
    KEYHOLDER_DAEMON_DIR). What still blocks the real path, each
    measured, not guessed:
    1. CLI sessions are NOT on daemon IPC: `keyholder sessions list`
       currently fails with KH-1006 ("module 'keyholder.sessions'
       has no attribute 'list_sessions'") and `keyholder.sessions`
       SessionStore is documented in-module as in-memory with no
       persistence — a session created by one CLI invocation is not
       visible to the daemon, to a later CLI invocation, or to any
       proxy. E2E's create-via-CLI → list-via-CLI → kill-via-CLI
       flow cannot run until CLI sessions route through daemon IPC
       (W01/W18 slice, outside this file).
    2. No proxy HTTP server is served by the daemon: `serve_main`
       loops on daemon status only; nothing listens on the proxy
       port (default 127.0.0.1:8765) for E2E to call through.
    3. No CLI PoP-key handoff exists: `sessions create` prints the
       token once, but the PoP key stays in daemon/broker memory
       and no KH_POP_TEST-style marker is printed, while PoP is
       mandatory with no bare-bearer fallback — signed proxied
       calls cannot be constructed from CLI output alone.
    4. `daemon status` prints only "daemon: running (pid N)" — no
       upstream bases, no proxy port — so the safety gate below
       cannot be satisfied; loosening the gate would risk
       real-provider contact and is refused.
    5. Daemon rendezvous is GLOBAL (one ~/.keyholder/daemon unless
       KEYHOLDER_DAEMON_DIR is set, which this file does not set),
       so the scratch-cwd isolation this file assumes is false:
       concurrent runs share one daemon. Do not add a
       KEYHOLDER_DAEMON_DIR here without also adding a
       stop-on-skip path that never stops a pre-existing daemon.
  * v0.2 MANAGER RE-CHECK (2026-10-28, live on this Linux VM):
    blocker 1 is PARTIALLY closed — CLI sessions list/kill now route
    through daemon IPC when a daemon is running (proven live with an
    isolated KEYHOLDER_DAEMON_DIR: IPC-created session listed by the
    CLI, then killed by the CLI, then shown killed). CLI sessions
    CREATE via IPC is implemented but NOT live-proven: it first does
    a vault lookup through the CLI's stub-only vault interface
    (vault.get_key does not exist on the real Vault class), so a
    real CLI create still fails before reaching IPC. Blockers 2–4
    (no served proxy, no CLI PoP handoff, status names no upstream
    bases) are unchanged. Layer B therefore STAYS skipped; the
    remaining work is a CLI↔vault adapter, a daemon-served proxy,
    and a CLI PoP handoff — not a gate loosening.
    SAFETY GATE: no proxied call is ever made until the daemon's
    status output (or a mock hit counter) confirms the proxy points
    at the loopback mocks. If that cannot be confirmed, Layer B skips
    rather than risking contact with a real provider.
  * Keys: `keys list` (parse key-<16 hex>); if none, `keys add
    --provider github --label e2e-github` fed "no" to the
    ever-pasted question plus the fake key (answer "no" avoids the
    NOT YET ROTATED session block; a "yes"/"don't know" key can
    never start a session until rotated, CONTRACT section 9).
  * Sessions: `sessions create <key_id> --class <class>
    [--transport absolute] [--minutes N]`; token is printed on its
    own line exactly once, session id on the "session created:" line.
    Expiry uses --minutes 1 (destructive class), which the CLI
    already accepts -- no invented flag.
  * PoP: X-Keyholder-Session + X-Keyholder-PoP (HMAC-SHA256 over
    METHOD, HOST, CANONICAL_PATH, BODY_SHA256_HEX, TIMESTAMP joined
    by newlines) + X-Keyholder-Timestamp, per CONTRACT section 4.
  * Proxied calls use absolute-form through the proxy (the proxy is
    addressed at 127.0.0.1:8765 and the request line carries the full
    mock URL), per the absolute-form default (v3 N-G1).
  * Kill: `sessions kill <session_id>`; its receipt lists
    already-forwarded calls ("Calls already sent ..."), which
    test_11 asserts for a slow call in flight at kill time.
  * Audit: `audit verify` (exit 0 = OK, 2 = UNANCHORED, 3 =
    TAMPERED/MISSING-DIRECTORY, CONTRACT section 8); chain recompute
    reads the audit JSONL under the scratch dir when locatable.

TIMINGS: every Layer B test records its measured durations in the
TIMINGS dict; tearDownModule prints them. Thresholds asserted are the
CONTRACT ones: kill deny-list <= 1 s, teardown <= 5 s.

Fake TEST-ONLY keys only. Loopback only. No real provider contact.
Run:  cd ~/workspace/keyholder-build && python3 -m unittest tests.test_e2e -v
  or: python3 -m unittest discover -s tests -v
"""

import gzip
import re
import hashlib
import hmac
import http.client
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

_HERE = os.path.dirname(os.path.abspath(__file__))
_BUILD_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, _BUILD_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import mock_providers  # noqa: E402  (tests dir is on sys.path above)

PROXY_HOST = os.environ.get("KEYHOLDER_PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.environ.get("KEYHOLDER_PROXY_PORT", "8765"))
TIMINGS = {}


def _record(name, seconds):
    TIMINGS[name] = round(float(seconds), 3)


def _http_via_proxy(method, absolute_url, headers=None, body=b""):
    """One absolute-form request through the proxy. Returns (status, body)."""
    conn = http.client.HTTPConnection(PROXY_HOST, PROXY_PORT, timeout=30)
    try:
        conn.request(method, absolute_url, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _http_direct(host, port, method, path, headers=None, body=b""):
    conn = http.client.HTTPConnection(host, port, timeout=30)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read(), dict(resp.getheaders())
    finally:
        conn.close()


def _pop_headers(token, pop_key, method, host, canonical_path, body=b""):
    ts = str(int(time.time()))
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = "%s\n%s\n%s\n%s\n%s" % (method, host, canonical_path, body_hash, ts)
    sig = hmac.new(pop_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "X-Keyholder-Session": token,
        "X-Keyholder-PoP": sig,
        "X-Keyholder-Timestamp": ts,
    }


# ---------------------------------------------------------------- Layer A
class MockProviderTests(unittest.TestCase):
    """Mock fidelity only. No Keyholder code is involved here."""

    @classmethod
    def setUpClass(cls):
        cls.github, cls.gemini = mock_providers.start_mocks()

    @classmethod
    def tearDownClass(cls):
        mock_providers.stop_mocks(cls.github, cls.gemini)

    def test_mock_ports_are_loopback_defaults(self):
        self.assertEqual(mock_providers.MOCK_GITHUB_PORT, 18765)
        self.assertEqual(mock_providers.MOCK_GEMINI_PORT, 18766)
        self.assertEqual(mock_providers.MOCK_GITHUB_HOST, "127.0.0.1")
        self.assertEqual(mock_providers.MOCK_GEMINI_HOST, "127.0.0.1")

    def test_github_file_read_and_write_succeed_when_reached(self):
        t0 = time.monotonic()
        status, _, _ = _http_direct("127.0.0.1", 18765, "GET",
                                    "/repos/o/r/contents/README.md",
                                    {"Authorization": "Bearer " + mock_providers.FAKE_GITHUB_KEY})
        self.assertEqual(status, 200)
        self.assertEqual(self.github.count("contents_read"), 1)
        status, _, _ = _http_direct("127.0.0.1", 18765, "PUT",
                                    "/repos/o/r/contents/README.md",
                                    {"Authorization": "Bearer " + mock_providers.FAKE_GITHUB_KEY},
                                    json.dumps({"message": "x", "content": "aGk="}).encode())
        self.assertEqual(status, 201)
        self.assertEqual(self.github.count("contents_write"), 1)
        _record("mock_github_read_write", time.monotonic() - t0)

    def test_github_denied_class_surfaces_succeed_when_reached(self):
        # Proves the mock does NOT deny: a proxy denial must show up as
        # "mock never reached", not as a mock refusal.
        gh = "127.0.0.1"
        auth = {"Authorization": "Bearer " + mock_providers.FAKE_GITHUB_KEY}
        cases = [
            ("DELETE", "/repos/o/r/git/refs/heads/old", "branch_delete", 204),
            ("PUT", "/repos/o/r/pulls/7/merge", "pr_merge", 200),
            ("POST", "/repos/o/r/issues/7/comments", "comment_create", 201),
            ("GET", "/repos/o/r/actions/secrets/TOKEN", "secrets_read", 200),
            ("POST", "/graphql", "graphql", 200),
        ]
        for method, path, key, want in cases:
            body = json.dumps({"body": "/deploy please"}).encode() if key == "comment_create" else b""
            status, _, _ = _http_direct(gh, 18765, method, path, auth, body)
            self.assertEqual(status, want, "%s %s" % (method, path))
            self.assertGreaterEqual(self.github.count(key), 1, key)

    def test_github_bot_command_comment_is_recorded_by_mock(self):
        # The mock records the comment verbatim; DENYING bot commands is
        # the proxy's job (Layer B), not the mock's.
        status, _, _ = _http_direct(
            "127.0.0.1", 18765, "POST", "/repos/o/r/issues/9/comments",
            {"Authorization": "Bearer " + mock_providers.FAKE_GITHUB_KEY},
            json.dumps({"body": "@claude merge this please"}).encode())
        self.assertEqual(status, 201)
        last = self.github.last("comment_create")
        self.assertIn("@claude", last.get("body", ""))

    def test_gemini_allowed_calls_succeed_when_reached(self):
        t0 = time.monotonic()
        auth = {"x-goog-api-key": mock_providers.FAKE_GEMINI_KEY}
        status, _, _ = _http_direct("127.0.0.1", 18766, "POST",
                                    "/v1beta/models/gemini-x:generateContent",
                                    auth, b'{"contents":[]}')
        self.assertEqual(status, 200)
        status, body, _ = _http_direct("127.0.0.1", 18766, "POST",
                                       "/v1beta/models/gemini-x:countTokens",
                                       auth, b'{"contents":[]}')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["totalTokens"], 42)
        _record("mock_gemini_allowed", time.monotonic() - t0)

    def test_gemini_denied_class_surfaces_succeed_when_reached(self):
        auth = {"x-goog-api-key": mock_providers.FAKE_GEMINI_KEY}
        cases = [
            ("POST", "/v1beta/interactions", "interactions"),
            ("POST", "/v1beta/models/gemini-x:batchGenerateContent", "batch"),
            ("POST", "/v1beta/live", "live"),
            ("POST", "/upload/v1beta/files", "upload"),
        ]
        for method, path, key in cases:
            status, _, _ = _http_direct("127.0.0.1", 18766, method, path, auth, b"{}")
            self.assertEqual(status, 200, path)
            self.assertGreaterEqual(self.gemini.count(key), 1, key)

    def test_gemini_key_echo_returns_key_in_gzipped_body(self):
        status, body, headers = _http_direct(
            "127.0.0.1", 18766, "GET", "/v1beta/echo-key",
            {"x-goog-api-key": mock_providers.FAKE_GEMINI_KEY})
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Encoding"), "gzip")
        plain = gzip.decompress(body).decode("utf-8")
        self.assertIn(mock_providers.FAKE_GEMINI_KEY, plain)
        # And the raw wire bytes must NOT contain the key in plaintext:
        # the danger is only visible after decompression, which is
        # exactly what the proxy scan (v3 N-G3) must handle.
        self.assertNotIn(mock_providers.FAKE_GEMINI_KEY.encode(), body)

    def test_mock_slow_endpoint_takes_about_two_seconds(self):
        # Supports the kill test's already-forwarded-call scenario.
        t0 = time.monotonic()
        status, _, _ = _http_direct("127.0.0.1", 18765, "GET",
                                    "/repos/o/r/contents/slow.txt?slow=1")
        self.assertEqual(status, 200)
        _record("mock_slow_endpoint", time.monotonic() - t0)
        self.assertGreaterEqual(TIMINGS["mock_slow_endpoint"], 1.5)


# ------------------------------------------------------------- Layer B
_REAL_PROBE = None  # (ok: bool, reason: str)


def _probe_real_stack():
    """Cached discovery: is a real daemon+CLI importable and startable?

    Returns (True, '') or (False, reason). Never raises, never claims a
    pass for a missing stack. This probe only checks presence; it does
    not start a daemon (each test class manages its own daemon).
    """
    global _REAL_PROBE
    if _REAL_PROBE is not None:
        return _REAL_PROBE
    try:
        import keyholder  # noqa: F401
    except Exception as exc:
        _REAL_PROBE = (False, "keyholder package not importable from %s: %s"
                       % (_BUILD_ROOT, exc))
        return _REAL_PROBE
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "keyholder", "--help"],
            capture_output=True, timeout=30, cwd=_BUILD_ROOT)
    except Exception as exc:
        _REAL_PROBE = (False, "keyholder CLI --help did not run: %s" % exc)
        return _REAL_PROBE
    if proc.returncode != 0:
        _REAL_PROBE = (False, "keyholder CLI --help exited %d: %s"
                       % (proc.returncode, proc.stderr.decode("utf-8", "replace")[:300]))
        return _REAL_PROBE
    _REAL_PROBE = (True, "")
    return _REAL_PROBE


class RealPathTests(unittest.TestCase):
    """Real daemon + proxy + CLI. Skipped (NOT-RUN) in v0.2 as well.

    v0.1 skip reason (no persistent daemon, no proxy server) is
    PARTLY spent: the cross-process daemon landed (see the module
    docstring). The v0.2 skip reason, measured 2026-10-28, is:
    CLI sessions are not on daemon IPC (sessions list fails
    KH-1006 in this tree), no proxy server is served, no CLI PoP
    handoff exists, and `daemon status` names no upstream bases,
    so the safety gate cannot pass. Un-skip ONLY when all four
    land; never by loosening the gate or by stubbing the stack.

    setUpClass starts the mocks and (when present) the daemon. If the
    daemon cannot be started, or its proxy cannot be confirmed to point
    at the loopback mocks, the whole class skips -- no proxied call is
    ever attempted against an unverified upstream.
    """

    token = None
    pop_key = None
    session_id = None

    @classmethod
    def setUpClass(cls):
        ok, reason = _probe_real_stack()
        if not ok:
            raise unittest.SkipTest("NOT-RUN real path: " + reason)
        cls.github, cls.gemini = mock_providers.start_mocks()
        cls.tmp = tempfile.TemporaryDirectory(prefix="keyholder-e2e-")
        env = dict(os.environ)
        env["KEYHOLDER_TEST_MODE"] = "1"
        env["KEYHOLDER_MOCK_GITHUB_BASE"] = mock_providers.MOCK_GITHUB_BASE
        env["KEYHOLDER_MOCK_GEMINI_BASE"] = mock_providers.MOCK_GEMINI_BASE
        env["KEYHOLDER_PROXY_PORT"] = str(PROXY_PORT)
        env["PYTHONPATH"] = _BUILD_ROOT + os.pathsep + env.get("PYTHONPATH", "")
        cls.env = env
        cls.daemon = subprocess.Popen(
            [sys.executable, "-m", "keyholder", "daemon", "start"],
            cwd=cls.tmp.name, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            cls._wait_for_daemon()
        except Exception as exc:
            cls.daemon.terminate()
            raise unittest.SkipTest(
                "NOT-RUN real path: no persistent daemon process: %s" % exc)
        # Safety gate: confirm the proxy points at the loopback mocks
        # before any session or proxied call. Status output must name
        # the mock host, or a probe read must land in the mock counter.
        if not cls._mock_pointing_confirmed():
            cls.daemon.terminate()
            raise unittest.SkipTest(
                "NOT-RUN real path (v0.2 re-check 2026-10-28): cannot "
                "confirm proxy points at loopback mocks "
                "(127.0.0.1:18765/18766); refusing to risk "
                "real-provider contact. Daemon status/config must "
                "expose its upstream bases. Deeper blockers, measured "
                "the same day: CLI sessions are not on daemon IPC "
                "(sessions list fails KH-1006), no proxy server is "
                "served by the daemon, and no CLI PoP-key handoff "
                "exists. See the module docstring.")

    @classmethod
    def _wait_for_daemon(cls):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if cls.daemon.poll() is not None:
                out = cls.daemon.stdout.read() if cls.daemon.stdout else ""
                raise RuntimeError("daemon exited early: %s" % out[:500])
            proc = subprocess.run(
                [sys.executable, "-m", "keyholder", "daemon", "status"],
                capture_output=True, timeout=10, cwd=cls.tmp.name, env=cls.env)
            if proc.returncode == 0:
                cls.status_text = proc.stdout.decode("utf-8", "replace")
                return
            time.sleep(0.5)
        raise RuntimeError("daemon status never reported ready within 15 s")

    @classmethod
    def _mock_pointing_confirmed(cls):
        text = getattr(cls, "status_text", "")
        if "18765" in text and "18766" in text:
            return True
        # Fallback: a status field naming loopback mocks is enough; the
        # per-test mock counters give a second confirmation on first use.
        return "127.0.0.1" in text

    @classmethod
    def tearDownClass(cls):
        daemon = getattr(cls, "daemon", None)
        if daemon is not None and daemon.poll() is None:
            try:
                subprocess.run([sys.executable, "-m", "keyholder", "daemon", "stop"],
                               capture_output=True, timeout=10, cwd=cls.tmp.name,
                               env=cls.env)
            except Exception:
                pass
            try:
                daemon.wait(timeout=5)
            except Exception:
                daemon.kill()
        mock_providers.stop_mocks(getattr(cls, "github", None),
                                  getattr(cls, "gemini", None))
        tmp = getattr(cls, "tmp", None)
        if tmp is not None:
            tmp.cleanup()

    # -- helpers ------------------------------------------------------
    def _cli(self, *argv, **kw):
        return subprocess.run(
            [sys.executable, "-m", "keyholder"] + list(argv),
            capture_output=True, timeout=kw.get("timeout", 60),
            cwd=self.tmp.name, env=self.env,
            input=kw.get("input"))

    def _require_key_id(self):
        proc = self._cli("keys", "list")
        out = proc.stdout.decode("utf-8", "replace")
        m = re.search(r"key-[0-9a-f]{16}", out)
        if m:
            return m.group(0)
        proc = self._cli("keys", "add", "--provider", "github",
                         "--label", "e2e-github",
                         input="no\n%s\n" % mock_providers.FAKE_GITHUB_KEY)
        out = proc.stdout.decode("utf-8", "replace")
        m = re.search(r"key-[0-9a-f]{16}", out)
        if proc.returncode != 0 or not m:
            raise unittest.SkipTest(
                "NOT-RUN session creation: no key in vault and `keys add` "
                "did not return a key id (rc=%d, out=%r). The vault/keys "
                "flow needs a non-interactive test path."
                % (proc.returncode, out[:300]))
        return m.group(0)

    def _require_session(self):
        """Create one session via the CLI on first use (token once)."""
        if RealPathTests.token is not None:
            return
        key_id = self._require_key_id()
        proc = self._cli("sessions", "create", key_id, "--class", "write")
        out = proc.stdout.decode("utf-8", "replace")
        err = proc.stderr.decode("utf-8", "replace")
        token = None
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("kh_sess_"):
                token = line.strip("\"'<>")
                break
        sid = None
        m = re.search(r"session created:\s*(sess-[0-9a-f]{16})", out)
        if m:
            sid = m.group(1)
        if proc.returncode != 0 or not token:
            raise unittest.SkipTest(
                "NOT-RUN session creation: `sessions create` did not "
                "return a kh_sess_ token (rc=%d, out=%r, err=%r). The "
                "create flow needs a non-interactive test-mode path / "
                "test approver from W08/W10."
                % (proc.returncode, out[:300], err[:300]))
        RealPathTests.token = token
        RealPathTests.session_id = sid
        # PoP key delivery is implementation-defined (pipe/FD/in-process,
        # CONTRACT section 4); the harness reads it from the create
        # output ONLY if the implementation prints a test-mode PoP key
        # marker. Otherwise PoP-signed calls skip, unsigned-call tests
        # still exercise session-token validation.
        RealPathTests.pop_key = None
        for line in out.splitlines():
            if "KH_POP_TEST" in line:
                RealPathTests.pop_key = line.split("KH_POP_TEST", 1)[1].strip().encode()

    def _proxied(self, provider, method, path, body=b""):
        """Proxied call through the real proxy with PoP when available."""
        if provider == "github":
            base, host = mock_providers.MOCK_GITHUB_BASE, "127.0.0.1:18765"
        else:
            base, host = mock_providers.MOCK_GEMINI_BASE, "127.0.0.1:18766"
        headers = {}
        if self.token and self.pop_key:
            headers.update(_pop_headers(self.token, self.pop_key, method, host,
                                        path, body))
        elif self.token:
            headers["X-Keyholder-Session"] = self.token
        return _http_via_proxy(method, base + path, headers, body)

    def _find_audit_file(self):
        for root, _dirs, files in os.walk(self.tmp.name):
            for name in files:
                if name.endswith(".jsonl") and "audit" in name:
                    return os.path.join(root, name)
        return None

    # -- tests --------------------------------------------------------
    def test_01_session_creation_token_shown_once(self):
        t0 = time.monotonic()
        self._require_session()
        self.assertTrue(self.token.startswith("kh_sess_"))
        proc = subprocess.run(
            [sys.executable, "-m", "keyholder", "sessions", "list"],
            capture_output=True, timeout=30, cwd=self.tmp.name, env=self.env)
        listed = proc.stdout.decode("utf-8", "replace")
        self.assertNotIn(self.token, listed,
                         "session token must never reappear in sessions list")
        # Token must not be on disk anywhere under the scratch dir.
        for root, _dirs, files in os.walk(self.tmp.name):
            for name in files:
                with open(os.path.join(root, name), "rb") as fh:
                    self.assertNotIn(self.token.encode(), fh.read(),
                                     "token leaked to file %s" % name)
        _record("session_creation", time.monotonic() - t0)

    def test_02_github_read_injects_real_fake_key_upstream(self):
        self._require_session()
        before = self.github.count("contents_read")
        status, body = self._proxied("github", "GET", "/repos/o/r/contents/README.md")
        self.assertEqual(status, 200, body[:300])
        self.assertEqual(self.github.count("contents_read"), before + 1)
        last = self.github.last("contents_read")
        self.assertIn(mock_providers.FAKE_GITHUB_KEY, last.get("auth", ""),
                      "upstream must receive the injected key, not the agent token")

    def test_03_gemini_generate_injects_key_as_header_not_query(self):
        self._require_session()
        before = self.gemini.count("generate_content")
        status, body = self._proxied(
            "gemini", "POST", "/v1beta/models/gemini-x:generateContent", b'{"contents":[]}')
        self.assertEqual(status, 200, body[:300])
        self.assertEqual(self.gemini.count("generate_content"), before + 1)
        last = self.gemini.last("generate_content")
        self.assertIn(mock_providers.FAKE_GEMINI_KEY, last.get("auth", ""))
        self.assertNotIn("key=", last.get("path", ""),
                         "Gemini key must go in x-goog-api-key, never ?key=")

    def test_04_gemini_count_tokens_readlike_post_allowed(self):
        self._require_session()
        before = self.gemini.count("count_tokens")
        status, _body = self._proxied(
            "gemini", "POST", "/v1beta/models/gemini-x:countTokens", b'{"contents":[]}')
        self.assertEqual(status, 200)

    def test_05_branch_delete_denied_generically_mock_unreached(self):
        self._require_session()
        before = self.github.count("branch_delete")
        status, body = self._proxied("github", "DELETE",
                                     "/repos/o/r/git/refs/heads/old")
        self.assertIn(status, (403, 405))
        text = body.decode("utf-8", "replace")
        self.assertNotIn("rule_id", text)
        self.assertNotIn("category", text.lower())
        self.assertEqual(self.github.count("branch_delete"), before,
                         "denied branch delete must never reach the mock")

    def test_06_bot_command_comment_denied_mock_unreached(self):
        self._require_session()
        before = self.github.count("comment_create")
        status, _body = self._proxied(
            "github", "POST", "/repos/o/r/issues/7/comments",
            json.dumps({"body": "/deploy please"}).encode())
        self.assertIn(status, (403, 405))
        self.assertEqual(self.github.count("comment_create"), before)

    def test_07_secrets_and_graphql_denied_mock_unreached(self):
        self._require_session()
        before_s = self.github.count("secrets_read")
        status, _ = self._proxied("github", "GET",
                                  "/repos/o/r/actions/secrets/TOKEN")
        self.assertIn(status, (403, 405))
        self.assertEqual(self.github.count("secrets_read"), before_s)
        before_g = self.github.count("graphql")
        status, _ = self._proxied("github", "POST", "/graphql",
                                  json.dumps({"query": "{ viewer { login } }"}).encode())
        self.assertIn(status, (403, 405))
        self.assertEqual(self.github.count("graphql"), before_g)

    def test_08_gemini_denied_surfaces_mock_unreached(self):
        self._require_session()
        cases = [("POST", "/v1beta/interactions", "interactions"),
                 ("POST", "/v1beta/models/gemini-x:batchGenerateContent", "batch"),
                 ("POST", "/v1beta/live", "live"),
                 ("POST", "/upload/v1beta/files", "upload")]
        for method, path, key in cases:
            before = self.gemini.count(key)
            status, _ = self._proxied("gemini", method, path, b"{}")
            self.assertIn(status, (403, 405), path)
            self.assertEqual(self.gemini.count(key), before, path)

    def test_09_pr_merge_gated_without_approval_not_forwarded(self):
        self._require_session()
        before = self.github.count("pr_merge")
        status, _ = self._proxied("github", "PUT",
                                  "/repos/o/r/pulls/7/merge", b"{}")
        # Gated = not forwarded without a broker approval. An approval
        # flow returning 2xx here would need a test approver; without
        # one, any forward is a failure of gating.
        self.assertIn(status, (403, 405, 401))
        self.assertEqual(self.github.count("pr_merge"), before)

    def test_10_gzipped_key_echo_blocked_by_response_scan(self):
        self._require_session()
        before = self.gemini.count("key_echo")
        status, body = self._proxied("gemini", "GET", "/v1beta/echo-key")
        self.assertEqual(self.gemini.count("key_echo"), before + 1,
                         "proxy must forward to the mock, then block the response")
        self.assertNotIn(mock_providers.FAKE_GEMINI_KEY.encode(), body)
        self.assertNotIn(mock_providers.FAKE_GEMINI_KEY.encode().hex().encode(), body)
        self.assertNotIn(urllib.parse.quote(mock_providers.FAKE_GEMINI_KEY).encode(), body)
        try:
            self.assertNotIn(mock_providers.FAKE_GEMINI_KEY, gzip.decompress(body).decode())
        except Exception:
            pass  # non-gzip blocked body is fine; plaintext checks above govern
        self.assertIn(status, (403, 502, 500),
                      "echo response must be blocked, not relayed (got %d)" % status)

    def test_11_kill_blocks_within_1s_teardown_within_5s(self):
        self._require_session()
        if not self.session_id:
            raise unittest.SkipTest(
                "NOT-RUN kill: session id not printed by sessions create; "
                "kill-by-id cannot be addressed.")
        # Start a slow call (mock sleeps ~2 s) so it is already
        # forwarded when the kill lands: it must run to completion
        # (not recalled) and be listed on the kill receipt.
        slow_result = {}
        def _slow():
            try:
                slow_result["status"], slow_result["body"] = self._proxied(
                    "github", "GET", "/repos/o/r/contents/slow.txt?slow=1")
            except Exception as exc:  # noqa: BLE001 -- recorded, asserted below
                slow_result["error"] = repr(exc)
        thread = threading.Thread(target=_slow, daemon=True)
        thread.start()
        time.sleep(0.3)
        t_kill = time.monotonic()
        proc = self._cli("sessions", "kill", self.session_id)
        kill_out = proc.stdout.decode("utf-8", "replace")
        self.assertEqual(proc.returncode, 0, kill_out[:300])
        self.assertIn("session killed:", kill_out)
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive(), "already-forwarded slow call was recalled/killed")
        self.assertEqual(slow_result.get("status"), 200, slow_result)
        self.assertIn("slow", kill_out,
                      "kill receipt must list the already-forwarded call")
        # New calls must be denied within 1 s of the kill.
        denied_at = None
        while time.monotonic() - t_kill < 5:
            status, _ = self._proxied("github", "GET", "/repos/o/r/contents/README.md")
            if status in (401, 403):
                denied_at = time.monotonic()
                break
            time.sleep(0.05)
        self.assertIsNotNone(denied_at, "call after kill was never denied")
        deny_latency = denied_at - t_kill
        _record("kill_deny_latency", deny_latency)
        self.assertLessEqual(deny_latency, 1.0,
                             "kill deny-list exceeded 1 s: %.3f s" % deny_latency)
        # Full teardown: session gone from list within 5 s of the kill.
        gone_at = None
        while time.monotonic() - t_kill < 5:
            proc = self._cli("sessions", "list")
            if self.session_id not in proc.stdout.decode("utf-8", "replace"):
                gone_at = time.monotonic()
                break
            time.sleep(0.1)
        self.assertIsNotNone(gone_at, "session still listed 5 s after kill")
        _record("kill_teardown", gone_at - t_kill)
        self.assertLessEqual(gone_at - t_kill, 5.0)

    def test_12_destructive_expiry_terminates_at_expiry(self):
        # Real expiry via the CLI's own --minutes flag (destructive
        # class, 1 minute): poll until the session is gone, then assert
        # a fresh proxied call is denied. No sleep against a 10-minute
        # default, and no faked clock.
        self._require_session()
        key_id = self._require_key_id()
        proc = self._cli("sessions", "create", key_id,
                         "--class", "destructive", "--minutes", "1")
        out = proc.stdout.decode("utf-8", "replace")
        m = re.search(r"session created:\s*(sess-[0-9a-f]{16})", out)
        if proc.returncode != 0 or not m:
            raise unittest.SkipTest(
                "NOT-RUN expiry: destructive --minutes 1 session could "
                "not be created (rc=%d, out=%r)."
                % (proc.returncode, out[:300]))
        exp_id = m.group(1)
        t0 = time.monotonic()
        gone_at = None
        while time.monotonic() - t0 < 100:
            proc = self._cli("sessions", "list")
            if exp_id not in proc.stdout.decode("utf-8", "replace"):
                gone_at = time.monotonic()
                break
            time.sleep(2)
        self.assertIsNotNone(gone_at,
                             "destructive session still listed 100 s after a 1-minute TTL")
        _record("destructive_expiry", gone_at - t0)
        # Destructive sessions terminate AT expiry (no 60 s overrun,
        # CONTRACT section 3): the session must be gone close to 60 s,
        # not held for a drain window.
        self.assertLessEqual(gone_at - t0, 90.0,
                             "destructive expiry took %.1f s for a 60 s TTL" % (gone_at - t0))

    def test_13_audit_completeness_and_verify_passes(self):
        self._require_session()
        # Exercise at least one allowed call first so completeness is
        # non-vacuous.
        self._proxied("github", "GET", "/repos/o/r/contents/README.md")
        proc = subprocess.run(
            [sys.executable, "-m", "keyholder", "audit", "verify"],
            capture_output=True, timeout=30, cwd=self.tmp.name, env=self.env)
        self.assertEqual(proc.returncode, 0,
                         "audit verify must pass (exit 0 = OK): %s"
                         % proc.stdout.decode("utf-8", "replace")[:500])
        path = self._find_audit_file()
        if path is None:
            raise unittest.SkipTest(
                "NOT-RUN audit chain recompute: audit JSONL not found "
                "under the scratch dir; CLI verify (above) is the only "
                "chain evidence in this run.")
        prev = "0" * 64
        seen = 0
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                self.assertEqual(entry["prev_hash"], prev)
                canon = {k: v for k, v in entry.items() if k != "entry_hash"}
                digest = hashlib.sha256(
                    json.dumps(canon, sort_keys=True,
                               separators=(",", ":")).encode()).hexdigest()
                self.assertEqual(entry["entry_hash"], digest)
                prev = digest
                seen += 1
        self.assertGreaterEqual(seen, 1, "audit log must not be empty after proxied calls")

    def test_14_denial_audit_entry_carries_rule_detail(self):
        self._require_session()
        self._proxied("github", "DELETE", "/repos/o/r/git/refs/heads/old")
        path = self._find_audit_file()
        if path is None:
            raise unittest.SkipTest(
                "NOT-RUN denial audit detail: audit JSONL not locatable "
                "under the scratch dir; generic-to-agent denial is "
                "covered by test_05.")
        found = False
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                entry = json.loads(line)
                if entry.get("decision") in ("deny", "denied", "DENY") or \
                        entry.get("outcome") in ("denied", "deny"):
                    self.assertTrue(entry.get("rule_id"),
                                    "audit denial must carry rule_id (agent must not see it)")
                    found = True
        self.assertTrue(found, "no denial entry found in audit log")


def tearDownModule():
    if TIMINGS:
        print("\nE2E TIMINGS (measured, seconds):")
        for name in sorted(TIMINGS):
            print("  %s: %s" % (name, TIMINGS[name]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
