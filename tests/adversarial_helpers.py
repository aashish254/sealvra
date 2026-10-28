"""Adversarial helpers for Keyholder v0.1 (W14).

Stdlib only. FAKE TEST-ONLY secrets only, loopback only, nothing here
touches a real provider, a real key, or the network beyond loopback.

Design note (honest labelling, CONTRACT §11 / v3 §1Q N-Q2):
  * The reference broker/policy/approval/audit classes in this file are
    *specification stubs*: minimal implementations of CONTRACT §4/§6/§8
    used so the attack classes can be exercised before the real modules
    land. A pass against a stub is NOT a pass against shipped code.
  * Every test in test_adversarial.py that targets real shipped code
    goes through ``require_real()`` and is marked NOT-RUN (unittest
    SkipTest) while that module is absent or its public API does not
    match the contract. Skipped tests never count as passes, and the
    suite's gate summary treats any NOT-RUN integration probe as
    release-blocking: the gate cannot be claimed green on stubs alone.
  * Tier statement (CONTRACT §10): 0600/0700 permissions, file-stored
    control tokens and peer-credential checks do NOT survive Tier B
    (same-UID attacker). Tests here prove that directly: a same-UID
    attacker CAN read a 0600 file, so the only Tier-B-safe claim is
    "the secret is not on disk at all", which is what the disk scans
    assert.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
from pathlib import Path

# ---------------------------------------------------------------- fake data
# Every fake secret is registered here so the log scanner can find it in
# ANY encoding, including deliberately short ones (9-11 chars). A scanner
# with a minimum-length cutoff >= 12 would miss these: that is exactly
# the bug the short-secret tests exist to catch.
FAKE_KEYS = [
    "TEST-ONLY-github-pat-abc123def456",   # realistic length
    "TEST-ONLY-gemini-key-xyz789",         # realistic length
    "TEST-ONLY-9char",                     # 9 chars after prefix? see below
    "TESTONLY9",                           # 9 chars total
    "TESTONLY10",                          # 10 chars total
    "TESTONLY10a",                         # 11 chars total
    "TEST-ONLY-short12",
    "TEST-ONLY-" + "k" * 40,
]
# Short bare fakes, exactly 9 / 10 / 11 chars, for the length-cutoff test.
SHORT_FAKES = ["TESTONLY9", "TESTONLY10", "TESTONLY10a"]
assert len(SHORT_FAKES[0]) == 9 and len(SHORT_FAKES[1]) == 10 and len(SHORT_FAKES[2]) == 11

FAKE_TOKEN_PREFIX = "kh_sess_TEST-ONLY-"
FORBIDDEN_COMMANDS = [
    "keys reveal", "sessions approve", "sessions extend",
    "--show-token", "--print-token", "clipboard",
]
# Code patterns (NOT prose) that indicate a forbidden surface or a
# silent fallback to a raw key (stop-ship S3/S4). These are matched
# against code with docstrings and comments stripped, because the
# shipped modules correctly *state* the prohibitions in docstrings
# ("no sessions approve equivalent", "no fallback to bare bearer") —
# a naive substring scan false-positives on exactly those sentences.
# Only executable code counts: argparse registration, command dispatch,
# clipboard libraries, or a fallback branch that returns True/allows.
FORBIDDEN_CODE_PATTERNS = [
    re.compile(r"add_argument\([^)]*(--show-token|--print-token)"),
    re.compile(r"add_parser\(\s*['\"](approve|reveal|extend)['\"]"),
    re.compile(r"\bdef\s+(reveal|approve_session|extend_session)\b"),
    re.compile(r"pyperclip|pbcopy|xclip|wl-copy|import clipboard|from clipboard"),
    re.compile(r"subprocess\.[^)]*(pbcopy|xclip|wl-copy)"),
]
FALLBACK_CODE_PATTERNS = [
    re.compile(r"if not \w*pop\w*:\s*\n\s*return True"),
    re.compile(r"if not \w*pop\w*:\s*\n\s*allowed\s*=\s*True"),
    re.compile(r"except\b[^:]*:\s*\n\s*return True\s*#.*fallback"),
    re.compile(r"os\.environ\.get\([^)]*\)\s*or\s*\w*[Tt]oken"),
    re.compile(r"getenv\([^)]*[Kk][Ee][Yy][^)]*\)\s*or\s"),
]


def stripped_code_text(path: Path) -> str:
    """Source with docstrings and comments removed (line count kept).

    Falls back to the raw text if the file does not parse — a syntax
    error is reported separately by the importability test, not hidden
    by this scanner.
    """
    text = path.read_text(encoding="utf-8", errors="ignore")
    try:
        import ast, io, tokenize
        tree = ast.parse(text)
        doc_lines = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)):
                if node.body and isinstance(node.body[0], ast.Expr) \
                        and isinstance(node.body[0].value, ast.Constant) \
                        and isinstance(node.body[0].value.value, str):
                    stmt = node.body[0]
                    doc_lines.update(range(stmt.lineno, (stmt.end_lineno or stmt.lineno) + 1))
        lines = text.splitlines()
        for ln in doc_lines:
            if 1 <= ln <= len(lines):
                lines[ln - 1] = ""
        text2 = "\n".join(lines)
        out_lines = text2.splitlines()
        try:
            toks = list(tokenize.generate_tokens(io.StringIO(text2).readline))
            for tok in toks:
                if tok.type == tokenize.COMMENT:
                    ln, col = tok.start
                    if 1 <= ln <= len(out_lines):
                        out_lines[ln - 1] = out_lines[ln - 1][:col]
        except Exception:
            pass
        return "\n".join(out_lines)
    except Exception:
        return text

BUILD_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = Path(__file__).resolve().parent
LOG_DIR = TESTS_DIR / ".adversarial_logs"
LOG_DIR.mkdir(exist_ok=True)


def append_suite_log(name: str, text: str) -> Path:
    """Write one suite-produced log file (scanned by the final test)."""
    p = LOG_DIR / name
    with open(p, "a", encoding="utf-8") as f:
        f.write(text + "\n")
    return p


# ---------------------------------------------------------------- secret scan
def _encodings(secret: str):
    b = secret.encode()
    yield secret
    yield base64.b64encode(b).decode()
    yield base64.urlsafe_b64encode(b).decode()
    yield binascii.hexlify(b).decode()
    yield urllib.parse.quote(secret, safe="")
    # split form: secret broken by single spaces / dashes (transcript scan)
    yield " ".join(secret)
    yield "-".join(secret)


def text_contains_secret(text: str, secrets_list=None) -> str | None:
    """Return the first fake secret found in ``text`` in any encoding, else None.

    Registry-based (not length-gated): a 9-char fake must be found.
    """
    for s in (secrets_list or FAKE_KEYS):
        for enc in _encodings(s):
            if enc and enc in text:
                return s
    if "TEST-ONLY-" in text:
        return "TEST-ONLY- (unregistered prefix hit)"
    return None


def scan_log_file(path: Path, secrets_list=None) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    text = data.decode("utf-8", errors="ignore")
    # Also scan gzip-compressed content inside the file.
    hits = []
    found = text_contains_secret(text, secrets_list)
    if found:
        hits.append(found)
    # Try decompressing any gzip blob present in the raw bytes.
    idx = data.find(b"\x1f\x8b")
    while idx != -1:
        try:
            dec = gzip.decompress(data[idx:]).decode("utf-8", errors="ignore")
            f2 = text_contains_secret(dec, secrets_list)
            if f2:
                hits.append("gzip:" + f2)
            break
        except Exception:
            idx = data.find(b"\x1f\x8b", idx + 1)
    return hits


def scan_directory(directory: Path, secrets_list=None) -> dict[str, list[str]]:
    out = {}
    if not directory.exists():
        return out
    for p in sorted(directory.rglob("*")):
        if p.is_file():
            hits = scan_log_file(p, secrets_list)
            if hits:
                out[str(p)] = hits
    return out


# ---------------------------------------------------------------- NOT-RUN gate
class NotRun(Exception):
    """Raised when a probe cannot run; converted to SkipTest by tests."""


def require_real(module_name: str):
    """Import a real keyholder module or raise NotRun (never a pass)."""
    try:
        return __import__(f"keyholder.{module_name}", fromlist=["*"])
    except Exception as exc:  # module absent OR broken import: not runnable
        raise NotRun(f"keyholder.{module_name} not importable: {exc}")


def real_source_files():
    """Existing .py files under keyholder/ (empty until workers land)."""
    pkg = BUILD_ROOT / "keyholder"
    if not pkg.exists():
        return []
    return sorted(pkg.rglob("*.py"))


# ---------------------------------------------------------------- reference stubs
# Minimal CONTRACT-conformant behaviour, used ONLY to exercise attack
# classes. These stubs are not shipped code and never prove shipped code.

def canonical(method: str, host: str, path: str, body: bytes, ts: int) -> str:
    return f"{method}\n{host}\n{path}\n{hashlib.sha256(body).hexdigest()}\n{ts}"


class RefBroker:
    """In-memory broker: token stored only as SHA-256 hash, PoP key in
    memory only, never written to disk. Mirrors CONTRACT §4."""

    def __init__(self):
        self._hashes = {}      # session_id -> sha256(token)
        self._pop = {}         # session_id -> pop key bytes (memory only)
        self._meta = {}        # session_id -> dict
        self._nonces = {}      # session_id -> set of used (ts, pop) pairs
        self._killed = set()
        self._forwarded = {}   # session_id -> list of forwarded call ids
        self._lock = threading.Lock()
        self.session_dir = None

    def create_session(self, provider, session_class, transport="absolute",
                       ttl=600.0, now=None):
        now = time.time() if now is None else now
        sid = "sess-" + secrets.token_hex(8)
        token = "kh_sess_" + secrets.token_urlsafe(32)
        pop = secrets.token_bytes(32)
        with self._lock:
            self._hashes[sid] = hashlib.sha256(token.encode()).hexdigest()
            self._pop[sid] = pop
            self._meta[sid] = dict(provider=provider, session_class=session_class,
                                   transport=transport, expires_at=now + ttl,
                                   idle_deadline=now + 300)
            self._nonces[sid] = set()
            self._forwarded[sid] = []
        return sid, token, pop

    def validate_pop(self, sid, token, pop_hex, ts, method, host, path, body):
        """Returns True only for live session + correct token + correct
        PoP + fresh timestamp + unseen nonce. No fallback to bare bearer."""
        with self._lock:
            if sid in self._killed or sid not in self._hashes:
                return False
            if not hmac.compare_digest(
                    hashlib.sha256(token.encode()).hexdigest(), self._hashes[sid]):
                return False
            meta = self._meta[sid]
            if time.time() > meta["expires_at"] or time.time() > meta["idle_deadline"]:
                return False
            if abs(time.time() - ts) > 300:
                return False
            expect = hmac.new(self._pop[sid],
                              canonical(method, host, path, body, ts).encode(),
                              hashlib.sha256).hexdigest()
            if not hmac.compare_digest(pop_hex, expect):
                return False
            key = (ts, pop_hex)
            if key in self._nonces[sid]:
                return False
            self._nonces[sid].add(key)
            return True

    def kill(self, sid):
        with self._lock:
            self._killed.add(sid)
            forwarded = list(self._forwarded[sid]) if sid in self._forwarded else []
        return {"killed": sid, "new_calls_blocked": True,
                "already_forwarded": forwarded,
                "note": "already-forwarded calls are NOT recalled"}

    def record_forwarded(self, sid, call_id):
        with self._lock:
            if sid in self._killed:
                return False
            self._forwarded[sid].append(call_id)
            return True

    def is_live(self, sid):
        with self._lock:
            if sid in self._killed or sid not in self._meta:
                return False
            return time.time() < self._meta[sid]["expires_at"]

    # --- session files: the broker must never put token/PoP on disk ---
    def write_session_file(self, directory: Path, sid, content: str):
        directory.mkdir(parents=True, exist_ok=True)
        p = directory / f"{sid}.json"
        p.write_text(content, encoding="utf-8")
        os.chmod(p, 0o600)
        return p


class RefPolicy:
    """Capability classification + deny rules (CONTRACT §6/§7)."""

    GRAPHQL_PATHS = ("/graphql",)
    COMMENT_COMMANDS = ("/deploy", "/approve", "/backport", "@claude merge",
                        "@claude lgtm", "@claude approve")

    @staticmethod
    def classify(method: str, path: str, body: bytes = b""):
        if path in RefPolicy.GRAPHQL_PATHS:
            return ("deny", 4, "graphql-denied")
        low = (path + " " + body.decode("utf-8", errors="ignore")).lower()
        for cmd in RefPolicy.COMMENT_COMMANDS:
            if cmd in low:
                return ("deny", 4, "comment-command-denied")
        if method == "DELETE" or "merge" in path:
            return ("destructive", 4, "destructive")
        if method in ("POST", "PUT", "PATCH"):
            return ("write", 2, "write")
        return ("read", 1, "read")

    @staticmethod
    def decide(method: str, path: str, session_class: str, transport: str,
               body: bytes = b""):
        if method == "CONNECT" and transport != "connect_allowed":
            return (False, 4, "connect-refused-default")
        if method == "CONNECT" and session_class == "destructive":
            return (False, 4, "connect-destructive-refused")
        cls, level, rule = RefPolicy.classify(method, path, body)
        if cls == "deny":
            return (False, 4, rule)
        if cls == "destructive" and session_class != "destructive":
            return (False, 4, "class-exceeded")
        return (True, level, rule)

    @staticmethod
    def count_graphql_mutations(body_text: str) -> int:
        """Count mutations incl. aliased fields: each 'alias: mutation'
        or field under a mutation block counts. Flooding = many aliases."""
        n = len(re.findall(r"\bmutation\b", body_text))
        aliases = re.findall(r"(\w+)\s*:\s*\w+\s*\(", body_text)
        return max(n, len(aliases) if "mutation" in body_text else 0)

    @staticmethod
    def response_creates_credential(body_text: str) -> bool:
        low = body_text.lower()
        return any(k in low for k in
                   ('"token":', '"access_token":', '"api_key":', '"secret":',
                    '"private_key":', "new_token", "created_token"))

    @staticmethod
    def scan_response(raw: bytes, secrets_list=None) -> str | None:
        """Decompress gzip, then scan plaintext + hex/url forms."""
        body = raw
        if raw[:2] == b"\x1f\x8b":
            try:
                body = gzip.decompress(raw)
            except Exception:
                return "undecodable-gzip"
        text = body.decode("utf-8", errors="ignore")
        try:
            unescaped = json.loads(text) if text.strip().startswith("{") else text
            text = json.dumps(unescaped) if not isinstance(unescaped, str) else unescaped
        except Exception:
            pass
        return text_contains_secret(text, secrets_list)


class RefApproval:
    """Broker-owned approver only (CONTRACT §8). No CLI/dashboard path."""

    def __init__(self, clock=None):
        self._clock = clock or time.time
        self._pending = {}
        self._lock = threading.Lock()

    def request(self, session_pseudonym, provider, method, path, scope_summary):
        aid = "appr-" + secrets.token_hex(8)
        nonce = secrets.token_urlsafe(24)
        with self._lock:
            self._pending[aid] = dict(nonce=nonce, created=self._clock(),
                                      consumed=False, session_pseudonym=session_pseudonym,
                                      provider=provider, method=method, path=path,
                                      scope_summary=scope_summary)
        return aid, nonce

    def consume(self, aid, nonce, approver: str, channel: str = "broker"):
        """Only approver=='broker' via broker channel, once, within 60s.
        X11 channel can present/deny, never approve. Control-credential
        holders (approver != broker) cannot approve their own call."""
        with self._lock:
            rec = self._pending.get(aid)
            if rec is None or rec["consumed"]:
                return False
            if approver != "broker" or channel != "broker":
                return False
            if channel == "x11":
                return False
            if not hmac.compare_digest(nonce, rec["nonce"]):
                return False
            if self._clock() - rec["created"] > 60:
                return False
            rec["consumed"] = True
            return True


class RefAudit:
    """Hash-chained JSONL audit log (CONTRACT §8) + external anchor."""

    def __init__(self, path: Path, anchor_path: Path | None = None):
        self.path = path
        self.anchor_path = anchor_path
        self._seq = 0
        self._prev = "0" * 64
        self._offset = 0
        if path.exists():
            self._load_existing()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()

    def _load_existing(self):
        lines = self.path.read_text(encoding="utf-8").splitlines()
        if lines:
            last = json.loads(lines[-1])
            self._seq = last["seq"]
            self._prev = last["entry_hash"]
            self._offset = self.path.stat().st_size

    def append(self, event: dict) -> dict:
        # Offset check: foreign growth since last append halts the writer.
        cur = self.path.stat().st_size if self.path.exists() else 0
        if cur != self._offset:
            raise RuntimeError("audit log grew outside writer (KH-1005)")
        self._seq += 1
        entry = dict(event)
        entry["seq"] = self._seq
        entry["prev_hash"] = self._prev
        canon = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        entry["entry_hash"] = hashlib.sha256(canon.encode()).hexdigest()
        line = json.dumps(entry, sort_keys=True) + "\n"
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        self._prev = entry["entry_hash"]
        self._offset = self.path.stat().st_size
        if self.anchor_path is not None:
            self.anchor_path.write_text(self._prev, encoding="utf-8")
        return entry

    def verify(self, require_anchor: bool = True):
        """OK / TAMPERED / UNANCHORED / MISSING-DIRECTORY (CONTRACT §8)."""
        if not self.path.exists():
            return "MISSING-DIRECTORY"
        lines = self.path.read_text(encoding="utf-8").splitlines()
        prev = "0" * 64
        for i, line in enumerate(lines, 1):
            try:
                e = json.loads(line)
            except Exception:
                return "TAMPERED"
            h = e.pop("entry_hash")
            if e.get("seq") != i or e.get("prev_hash") != prev:
                return "TAMPERED"
            if hashlib.sha256(json.dumps(e, sort_keys=True,
                                         separators=(",", ":")).encode()).hexdigest() != h:
                return "TAMPERED"
            prev = h
        if require_anchor:
            if self.anchor_path is None or not self.anchor_path.exists():
                return "UNANCHORED"
            if self.anchor_path.read_text(encoding="utf-8").strip() != prev:
                return "TAMPERED"  # tail truncation: head != anchored head
        return "OK"


# ---------------------------------------------------------------- v0.2 additions (W09)
# Helpers for the v0.2 adversarial classes in test_adversarial.py.
# All values are fake TEST-ONLY values; nothing here contacts a network
# beyond loopback.


def unicode_escape_json(secret: str) -> str:
    """Render ``secret`` as JSON \\uXXXX escapes, one escape per char.

    This is the form a secret takes when an upstream JSON body escapes
    every character instead of returning the secret literally. A
    response scanner that only matches the literal string misses it.
    """
    return "".join("\\u%04x" % ord(ch) for ch in secret)


def graphql_alias_document(n_fields: int, field: str = "deleteRepo") -> str:
    """One GraphQL mutation operation carrying ``n_fields`` aliased fields.

    GraphQL aliases let a single operation execute many distinct field
    actions (``a1: deleteRepo(...) a2: deleteRepo(...) ...``). A
    mutation counter that counts only the ``mutation`` keyword counts
    this whole document as ONE mutation whatever ``n_fields`` is.
    """
    fields = " ".join(
        f'a{i}: {field}(input: {{id: "{i}"}}) {{ ok }}' for i in range(n_fields)
    )
    return "mutation { " + fields + " }"


def count_graphql_alias_fields(document: str) -> int:
    """Count aliased field executions in a GraphQL document.

    Quoted string literals are stripped first so a field name inside a
    string value is not counted. Each ``alias: field(`` occurrence is
    one field execution, regardless of how many operations wrap it.
    """
    stripped = re.sub(r'"(?:\\.|[^"\\])*"', '""', document)
    stripped = re.sub(r"#.*", "", stripped)
    return len(re.findall(r"\b[A-Za-z_]\w*\s*:\s*[A-Za-z_]\w*\s*\(", stripped))
