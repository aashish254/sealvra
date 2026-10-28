"""Mock providers for Keyholder v0.1 end-to-end tests (W15).

Loopback ONLY. Fake TEST-ONLY keys ONLY. No contact with GitHub, Google,
or any real provider. Nothing here is a real credential, and nothing
leaves this machine: both servers bind 127.0.0.1 explicitly.

PORTS (W15 owns the final choice; other workers must read this header
before hard-coding a port -- CONTRACT section 11):
    Mock GitHub: 127.0.0.1:18765
    Mock Gemini: 127.0.0.1:18766
These are the CONTRACT defaults, unchanged. If a port is already in use
the server raises instead of silently moving, so a port clash is a loud
failure rather than a hidden divergence.

DESIGN NOTE -- what the mocks do and do not prove:
  Each mock implements the upstream endpoint faithfully enough that a
  request reaching it SUCCEEDS (2xx). Denials in the E2E suite are
  therefore proved the only honest way: by asserting the mock was NEVER
  reached (hit counter stays 0) while the agent-facing response is a
  generic denial. A mock that itself denied would prove nothing about
  the proxy/policy under test.
  The single exception is the Gemini key-echo endpoint, which exists
  precisely so the proxy's RESPONSE scan can be tested: it returns the
  injected fake key inside a gzipped body. The proxy must catch/block
  that response (v3 N-G3); the mock deliberately does not protect it.

STATE: hit counters and last-request records live in memory only, in
the test process. They are never written to disk. The recorded
Authorization / x-goog-api-key values are the fake TEST-ONLY keys the
test itself injected; recording them lets the E2E test prove the proxy
injected the right key upstream. Never point a mock at a real key.

Usage (from tests/test_e2e.py):
    from mock_providers import start_mocks, stop_mocks
    github, gemini = start_mocks()
    ... github.hits["contents_read"] ...
    stop_mocks(github, gemini)

Stdlib only. No third-party imports.
"""

import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

MOCK_GITHUB_HOST = "127.0.0.1"
MOCK_GITHUB_PORT = 18765
MOCK_GEMINI_HOST = "127.0.0.1"
MOCK_GEMINI_PORT = 18766

MOCK_GITHUB_BASE = "http://%s:%d" % (MOCK_GITHUB_HOST, MOCK_GITHUB_PORT)
MOCK_GEMINI_BASE = "http://%s:%d" % (MOCK_GEMINI_HOST, MOCK_GEMINI_PORT)

# Fake TEST-ONLY keys. These are not credentials; they are test fixtures
# that the E2E test hands to the daemon/vault so the proxy has something
# to inject. Never replace them with a real key.
FAKE_GITHUB_KEY = "TEST-ONLY-GITHUB-FAKE-KEY-0001"
FAKE_GEMINI_KEY = "TEST-ONLY-GEMINI-FAKE-KEY-0001"


class _State:
    """Per-mock in-memory state: hit counters + last request per key."""

    def __init__(self):
        self.lock = threading.Lock()
        self.hits = {}
        self.last = {}  # key -> dict(method, path, auth_header, body_text)

    def record(self, key, method, path, auth_header, body_text):
        with self.lock:
            self.hits[key] = self.hits.get(key, 0) + 1
            self.last[key] = {
                "method": method,
                "path": path,
                "auth": auth_header,
                "body": body_text,
            }

    def count(self, key):
        with self.lock:
            return self.hits.get(key, 0)

    def snapshot_hits(self):
        with self.lock:
            return dict(self.hits)


def _send_json(handler, status, payload):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_body(handler):
    length = handler.headers.get("Content-Length")
    if length is None:
        return ""
    try:
        n = int(length)
    except ValueError:
        return ""
    if n <= 0:
        return ""
    return handler.rfile.read(n).decode("utf-8", "replace")


class _GitHubHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MockGitHub/0.1"

    def log_message(self, *args):  # keep test output readable
        pass

    def _auth(self):
        return self.headers.get("Authorization", "")

    def _handle(self, method):
        parsed = urlparse(self.path)
        path = parsed.path
        body = _read_body(self) if method in ("POST", "PUT", "PATCH", "DELETE") else ""
        state = self.server.state
        auth = self._auth()
        # Route table. Every route succeeds if reached -- see header note.
        if method == "GET" and "slow" in path:
            # Slow endpoint for the kill test's already-forwarded call:
            # a call in flight when kill lands must run to completion.
            import time as _time
            state.record("slow", method, path, auth, body)
            _time.sleep(2)
            return _send_json(self, 200, {"slow": True})
        if method == "GET" and path.startswith("/repos/") and "/contents/" in path:
            state.record("contents_read", method, path, auth, body)
            return _send_json(self, 200, {
                "type": "file", "encoding": "base64", "content": "aGVsbG8=",
                "name": path.rsplit("/", 1)[-1], "path": path,
            })
        if method == "PUT" and path.startswith("/repos/") and "/contents/" in path:
            state.record("contents_write", method, path, auth, body)
            return _send_json(self, 201, {
                "content": {"name": path.rsplit("/", 1)[-1], "sha": "deadbeef"},
                "commit": {"sha": "deadbeef", "message": "mock write"},
            })
        if method == "DELETE" and path.startswith("/repos/") and "/git/refs/" in path:
            state.record("branch_delete", method, path, auth, body)
            return _send_json(self, 204, {})
        if method == "DELETE" and path.startswith("/repos/") and path.count("/") == 3:
            # DELETE /repos/{owner}/{repo} -- repo deletion surface.
            state.record("repo_delete", method, path, auth, body)
            return _send_json(self, 204, {})
        if method == "PUT" and path.startswith("/repos/") and "/pulls/" in path \
                and path.endswith("/merge"):
            state.record("pr_merge", method, path, auth, body)
            return _send_json(self, 200, {"merged": True, "sha": "deadbeef"})
        if method == "POST" and path.startswith("/repos/") and "/issues/" in path \
                and path.endswith("/comments"):
            state.record("comment_create", method, path, auth, body)
            return _send_json(self, 201, {"id": 1, "body": "mock comment"})
        if method == "GET" and path.startswith("/repos/") and "/actions/secrets" in path:
            state.record("secrets_read", method, path, auth, body)
            return _send_json(self, 200, {"total_count": 0, "secrets": []})
        if method in ("PUT", "POST", "DELETE") and "/actions/secrets" in path:
            state.record("secrets_write", method, path, auth, body)
            return _send_json(self, 201, {})
        if method == "POST" and path == "/graphql":
            state.record("graphql", method, path, auth, body)
            return _send_json(self, 200, {"data": {}})
        if method == "GET" and path == "/user":
            state.record("user_read", method, path, auth, body)
            return _send_json(self, 200, {"login": "mock-user"})
        state.record("unmodelled", method, path, auth, body)
        return _send_json(self, 404, {"message": "mock: no such endpoint"})

    def do_GET(self):
        self._handle("GET")

    def do_PUT(self):
        self._handle("PUT")

    def do_POST(self):
        self._handle("POST")

    def do_PATCH(self):
        self._handle("PATCH")

    def do_DELETE(self):
        self._handle("DELETE")


class _GeminiHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "MockGemini/0.1"

    def log_message(self, *args):
        pass

    def _auth(self):
        return self.headers.get("x-goog-api-key", "")

    def _handle(self, method):
        parsed = urlparse(self.path)
        path = parsed.path
        body = _read_body(self) if method in ("POST", "PUT", "PATCH") else ""
        state = self.server.state
        auth = self._auth()
        if method == "POST" and path.endswith(":generateContent"):
            state.record("generate_content", method, path, auth, body)
            return _send_json(self, 200, {
                "candidates": [{"content": {"parts": [{"text": "mock reply"}]}}],
            })
        if method == "POST" and path.endswith(":countTokens"):
            state.record("count_tokens", method, path, auth, body)
            return _send_json(self, 200, {"totalTokens": 42})
        if method == "POST" and "/interactions" in path:
            state.record("interactions", method, path, auth, body)
            return _send_json(self, 200, {"name": "mock-interaction"})
        if method == "POST" and ("/batch" in path or path.endswith(":batchGenerateContent")):
            state.record("batch", method, path, auth, body)
            return _send_json(self, 200, {"responses": []})
        if method in ("GET", "POST") and ("/live" in path or path.endswith(":liveConnect")):
            state.record("live", method, path, auth, body)
            return _send_json(self, 200, {"session": "mock-live"})
        if method in ("POST", "PUT") and path.startswith("/upload/"):
            state.record("upload", method, path, auth, body)
            return _send_json(self, 200, {"name": "mock-upload"})
        if method == "GET" and path.endswith("/echo-key"):
            # Deliberately dangerous mock surface: returns the injected
            # fake key inside a GZIPPED body. A correct proxy (v3 N-G3)
            # strips/decompresses, scans, and blocks this response; the
            # agent must never receive the key back. Query-string keys
            # are also echoed if present, to catch ?key= forwarding.
            state.record("key_echo", method, path, auth, body)
            query_key = ""
            if "key=" in parsed.query:
                for part in parsed.query.split("&"):
                    if part.startswith("key="):
                        query_key = part[4:]
            echoed = auth or query_key or "no-key-received"
            raw = json.dumps({"echoed_key": echoed}).encode("utf-8")
            gz = gzip.compress(raw)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(gz)))
            self.end_headers()
            self.wfile.write(gz)
            return
        state.record("unmodelled", method, path, auth, body)
        return _send_json(self, 404, {"error": "mock: no such endpoint"})

    def do_GET(self):
        self._handle("GET")

    def do_PUT(self):
        self._handle("PUT")

    def do_POST(self):
        self._handle("POST")

    def do_PATCH(self):
        self._handle("PATCH")

    def do_DELETE(self):
        self._handle("DELETE")


class MockServer:
    """A running mock provider: .hits/.last via .state, .base URL."""

    def __init__(self, host, port, handler_cls):
        self.state = _State()
        # Bind loopback only; a busy port raises loudly (see header).
        self.httpd = ThreadingHTTPServer((host, port), handler_cls)
        self.httpd.state = self.state
        self.httpd.daemon_threads = True
        self.host = host
        self.port = port
        self.base = "http://%s:%d" % (host, port)
        self._thread = threading.Thread(target=self.httpd.serve_forever,
                                        kwargs={"poll_interval": 0.05},
                                        daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(timeout=5)

    def count(self, key):
        return self.state.count(key)

    def last(self, key):
        with self.state.lock:
            return dict(self.state.last.get(key, {}))


def start_mocks():
    """Start both mocks. Returns (github, gemini) MockServer pair."""
    github = MockServer(MOCK_GITHUB_HOST, MOCK_GITHUB_PORT, _GitHubHandler).start()
    try:
        gemini = MockServer(MOCK_GEMINI_HOST, MOCK_GEMINI_PORT, _GeminiHandler).start()
    except Exception:
        github.stop()
        raise
    return github, gemini


def stop_mocks(github, gemini):
    for server in (github, gemini):
        if server is not None:
            try:
                server.stop()
            except Exception:
                pass
