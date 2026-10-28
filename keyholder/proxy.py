"""Loopback proxy engine for Keyholder v0.1 (W04, CONTRACT §6, v3 §1G).

Normative order of operations (CONTRACT §6, steps 1-9):

  1. Validate session + PoP (live, not killed, not expired, not
     idle-timed-out, transport allowed). PoP verification needs the
     canonical path, so canonicalisation runs first *internally*;
     nothing is forwarded until every check below has passed, so the
     observable order is identical to the contract's.
  2. Canonicalise method + path: split first, then decode each segment
     (decode-then-split is FORBIDDEN); reject duplicate JSON keys at
     any depth, CL+TE / bare-LF / folding / NUL smuggling.
  3. Classify by CAPABILITY via the policy boundary (W05). Unmodelled
     endpoint = deny (the policy decider returns None or allowed=False).
  4. Approval gate (broker-owned, W08) BEFORE forwarding, for level-3
     decisions only. Level 4 = deny. No approval = no forward.
  5. Audit decision entry fsynced BEFORE forwarding. Fail closed: if
     the audit writer raises, the call is refused and the daemon never
     runs blind (v3 N-G5; CONTRACT §6 step 6).
  6. Re-check liveness immediately before injection (v3 N-G12), then
     inject the real key at the last moment: GitHub
     ``Authorization: Bearer <key>``, Gemini ``x-goog-api-key: <key>``
     ONLY -- never ``?key=``.
  7. Forward upstream with ``http.client`` (HTTPS for real providers;
     HTTP only for explicitly configured loopback mock bases in test
     mode). ``Accept-Encoding`` is stripped so the response secret
     scan sees plaintext; a gzipped/deflated response is
     decompressed-then-scanned, and an unscannable encoding is refused.
  8. Responses are scanned in raw, JSON-unescaped, hex, and
     URL-encoded forms (v3 N-G3). Credential-creating responses are
     DENIED by default (v3 N-G2): a policy-flagged credential-issuing
     endpoint is denied before forwarding, and a response carrying a
     credential-shaped JSON field is blocked as a backstop.
  9. Log outcome. Streams: per-chunk budget enforcement; over-budget
     streams abort mid-stream.

CONNECT (v3 N-G1, CONTRACT §6): refused with HTTP 405 by default for
every session. Only a session with ``transport="connect_allowed"``
may use it, never for write/destructive sessions, only to hosts the
operator explicitly allowlisted, only on port 443 (or a loopback mock
port in test mode), and every audit entry for a tunnel is labelled
``HOST-ONLY POLICY`` (host + byte budget only; method/path/body
policy is unenforceable inside a tunnel). A "read-only" session must
never DELETE through a tunnel -- and no read-only claim is made for
CONNECT sessions at all.

Denials to the agent are generic (v3 N-G8): the agent-facing body is
exactly ``{"error": "denied"}`` with an HTTP status, never a rule_id,
never a category, never a reason string. rule_id, category, and the
CONTRACT §9 error code go to the audit entry only. No denial oracle.

Threat-tier honesty (CONTRACT §10 / v3 §1A): this proxy is a Tier A
(interface-bound agent) control. It does not separate same-user
(Tier B) processes: a shell-capable same-user agent can bypass any
loopback proxy by calling the provider directly with a key it can
read. Same-user malware / compromised OS account is out of scope by
design. macOS keychain access groups, OS-rendered prompts, and worker
sandbox profiles are the controls that survive Tier B -- none of them
live in this module.

Boundaries (all injectable callables; W01/W03/W05/W08/W09 own the real
implementations -- this module never imports them beyond types/tokens):

  lookup_session(token) -> Session | None
      Broker-side token-hash lookup (CONTRACT §4). The token string
      itself is never logged or stored by this module.
  pop_key_for(session_id) -> bytes | None
      In-memory PoP key for the session (broker-owned).
  decide(session, method, canonical_path, body, content_type)
      -> PolicyDecision | None (W05). None = unmodelled = deny.
      The decision object may carry an optional ``credential_creating``
      attribute (True = deny before forwarding, v3 N-G2).
  approve(session, method, canonical_path, scope_summary)
      -> (approved: bool, approval_id: str | None) (W08 broker-owned
      approver). Called only for level-3 decisions. v0.2 (CONTRACT
      §13.2): the production callable is ``proxy_approver`` from
      approval.py wrapping the real broker-owned approver, which
      returns an ApprovalDecision; the engine also accepts that
      Decision object directly (``approved`` / ``approval_id``
      attributes) as well as the legacy tuple, so the real approver
      needs no tuple shim. A TEST approver is injected only through
      the explicit ``test_approver`` parameter (or a callable flagged
      with approval.mark_test_approver), and the engine RAISES unless
      the test-harness marker env var KEYHOLDER_TEST_APPROVER is
      exactly "1" (set only by tests, never by production code).
      With no approver at all the engine denies level-3 calls
      (KH-1004, fail closed) — the default is never a test double.
  audit_decision(entry: dict) -> None
      W09 writer; MUST fsync before returning and MUST pseudonymise
      session/key ids before persisting. Raising = refuse the call.
  audit_outcome(entry: dict) -> None
      W09 writer for the outcome entry. A failure here cannot recall
      an already-forwarded call; the engine marks itself degraded and
      refuses all NEW calls (fail closed, CONTRACT §8 disk-full rule).
  key_for(key_id) -> str | None
      Vault-backed real key, held in memory only for injection.
  on_success(session_id) -> None
      Broker hook that refreshes the idle deadline. Called only for
      relayed 2xx/3xx responses ("successful proxied call",
      CONTRACT §3); denied calls never refresh idle.
  connect_host_allowed(session, host) -> bool
      Optional extra CONNECT host gate on top of the config allowlist.

Stdlib only. No real keys anywhere; tests use TEST-ONLY- fixtures.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import http.client
import os
import ipaddress
import json
import re
import socket
import threading
import time
import unicodedata
import urllib.parse
import zlib
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Mapping, Sequence

from keyholder.tokens import body_sha256_hex, verify_pop  # noqa: F401  (re-exported for W12)
from keyholder.types import PolicyDecision, Session

__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "GENERIC_DENIAL_BODY",
    "HOST_ONLY_LABEL",
    "ProxyConfig",
    "ProxyResponse",
    "ConnectDecision",
    "ProxyEngine",
    "ProxyError",
    "canonicalise_query",
    "canonicalise_target",
    "contains_secret",
    "validate_loopback_host",
    "make_server",
    "KeyholderProxyHandler",
]

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765

# v0.2 test-harness marker (CONTRACT §13.2; named identically in
# approval.py as TEST_APPROVER_ENV). Set ONLY by tests, never by
# production code. A test approver in the proxy without this marker
# exactly "1" raises at engine construction.
TEST_APPROVER_ENV = "KEYHOLDER_TEST_APPROVER"

# Agent-facing denial body: generic, always. No rule_id, no category,
# no reason, no CONTRACT error code (those go to audit only, v3 N-G8).
GENERIC_DENIAL_BODY = b'{"error": "denied"}'
HOST_ONLY_LABEL = "HOST-ONLY POLICY"

# Headers never forwarded upstream (hop-by-hop, proxy, or credential).
_HOP_BY_HOP = {
    "connection", "keep-alive", "te", "trailer", "trailerS".lower(),
    "transfer-encoding", "upgrade", "proxy-authorization",
    "proxy-connection", "proxy-authenticate",
}
_AGENT_CREDENTIAL_HEADERS = {"authorization", "x-goog-api-key"}
_SESSION_HEADERS = {"x-keyholder-session", "x-keyholder-pop", "x-keyholder-timestamp"}
# Response headers never relayed to the agent (credential/covert channels).
_STRIP_RESPONSE_HEADERS = {"set-cookie", "set-cookie2", "www-authenticate",
                           "proxy-authenticate", "content-encoding",
                           "content-length",  # re-added below with the true length
                           "transfer-encoding", "connection", "keep-alive",
                           "trailer", "upgrade"}
_CREDENTIAL_RESPONSE_FIELDS = {
    "access_token", "id_token", "refresh_token", "client_secret",
    "api_key", "secret_key", "private_key", "password", "session_token",
}
_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_MAX_HEADER_COUNT = 100
_MAX_HEADER_BYTES = 64 * 1024
_READ_CHUNK = 64 * 1024


class ProxyError(Exception):
    """Internal proxy failure. ``status`` is agent-facing; ``code`` and
    ``audit_note`` go to the audit entry only, never to the agent."""

    def __init__(self, status: int, code: str, audit_note: str = ""):
        super().__init__(audit_note or code)
        self.status = status
        self.code = code
        self.audit_note = audit_note


@dataclass
class ProxyConfig:
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    # provider -> upstream base URL, e.g. "https://api.github.com".
    # In test mode an http://127.0.0.1:<port> mock base is allowed.
    bases: dict[str, str] = field(default_factory=dict)
    test_mode: bool = False
    upstream_timeout_s: float = 30.0
    max_request_bytes: int = 32 * 1024 * 1024
    max_response_bytes: int = 32 * 1024 * 1024
    # CONNECT: explicitly allowlisted hosts only, plus byte budget.
    connect_hosts: frozenset[str] = frozenset()
    connect_byte_budget: int = 10 * 1024 * 1024
    connect_timeout_s: float = 60.0


@dataclass
class ProxyResponse:
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, name: str) -> str | None:
        want = name.lower()
        for key, value in self.headers:
            if key.lower() == want:
                return value
        return None


@dataclass
class ConnectDecision:
    allowed: bool
    host: str = ""
    port: int = 443
    byte_budget: int = 0
    session_id: str = ""
    # Audit entry the handler must record (decision entry, pre-tunnel).
    audit_entry: dict | None = None


# ---------------------------------------------------------------------------
# Canonicalisation (v3 N-G4: split first, then decode each segment)
# ---------------------------------------------------------------------------

def _reject_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key: %r" % (key,))
        obj[key] = value
    return obj


def _check_json_no_duplicates(body: bytes) -> None:
    """Reject duplicate JSON keys at any depth (v3 N-G7). Raises ValueError."""
    text = body.decode("utf-8")  # strict: invalid UTF-8 is rejected
    json.loads(text, object_pairs_hook=_reject_duplicate_keys)


def _remove_dot_segments(segments: list[str]) -> list[str]:
    out: list[str] = []
    for seg in segments:
        if seg in ("", "."):
            continue
        if seg == "..":
            if not out:
                raise ValueError("path escapes root")
            out.pop()
            continue
        out.append(seg)
    return out


def _decode_segment(raw: str) -> str:
    """Percent-decode ONE path segment (split-first rule). A decoded
    '/' or '\\' changes segment boundaries, so it is rejected rather
    than re-split -- that is exactly the decode-then-split attack."""
    if "\x00" in raw:
        raise ValueError("NUL in path")
    decoded = urllib.parse.unquote(raw, encoding="utf-8", errors="strict")
    if "/" in decoded or "\\" in decoded:
        raise ValueError("decoded segment separator")
    if "\x00" in decoded or any(ord(c) < 0x20 or ord(c) == 0x7F for c in decoded):
        raise ValueError("control character in path")
    return unicodedata.normalize("NFC", decoded)


# Field names that must never appear in a form/multipart body (the
# body-field twin of the query credential rule: they land in logs).
_CREDENTIAL_BODY_FIELDS = {
    "key", "api_key", "apikey", "access_token", "token", "secret",
    "password", "client_secret",
}


def canonicalise_query(query: str) -> str:
    """Canonicalise a raw query string, split-first-then-decode
    (f06 F-13, v3 N-G4 for queries).

    Splits the RAW string on unencoded ``&`` first (never ``;``),
    then percent-decodes each name and value exactly once, then
    re-encodes canonically. A value containing ``%26`` therefore
    survives as one literal ``&`` (re-encoded ``%26``), never as a
    new separator; ``%3D`` stays a literal ``=``; a raw ``;`` is
    re-encoded as ``%3B`` so no upstream can treat it as a
    separator either. Order and duplicates are preserved
    (all-values). Credential parameter names (after decoding) are
    rejected, as are NUL/CR/LF/control characters and malformed
    escapes. Raises ValueError on any violation.
    """
    if "\x00" in query or "\r" in query or "\n" in query:
        raise ValueError("NUL/CR/LF in query")
    if query == "":
        return ""
    safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    out: list[str] = []
    for segment in query.split("&"):
        if segment == "":
            continue  # trailing/double '&' carries no parameter
        name_raw, sep, value_raw = segment.partition("=")
        try:
            name = urllib.parse.unquote(name_raw, encoding="utf-8", errors="strict")
            value = urllib.parse.unquote(value_raw, encoding="utf-8", errors="strict") if sep else ""
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("malformed percent escape in query") from None
        if not name:
            raise ValueError("empty query parameter name")
        if name.lower() in ("key", "api_key", "apikey", "access_token", "token", "secret"):
            raise ValueError("credential parameter in query")
        for decoded in (name, value):
            if "\x00" in decoded or any(ord(c) < 0x20 or ord(c) == 0x7F for c in decoded):
                raise ValueError("control character in query")
        out.append("%s=%s" % (urllib.parse.quote(name, safe=safe),
                              urllib.parse.quote(value, safe=safe)) if sep
                   else urllib.parse.quote(name, safe=safe))
    return "&".join(out)


def _parse_form_body(body: bytes) -> list[tuple[str, str]]:
    """Parse ``application/x-www-form-urlencoded`` split-first (the
    proxy-side copy of policy.py's parser; proxy.py must not import
    policy.py -- its decide boundary is an injected callable).
    Raises ValueError on malformed escapes or control characters."""
    text = body.decode("utf-8")  # strict
    if "\x00" in text or "\r" in text or "\n" in text:
        raise ValueError("NUL/CR/LF in form body")
    pairs: list[tuple[str, str]] = []
    for segment in text.split("&"):
        if segment == "":
            continue
        name_raw, sep, value_raw = segment.partition("=")
        try:
            name = urllib.parse.unquote_plus(name_raw, encoding="utf-8", errors="strict")
            value = urllib.parse.unquote_plus(value_raw, encoding="utf-8", errors="strict") if sep else ""
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("malformed percent escape in form body") from None
        if not name:
            raise ValueError("empty form field name")
        for decoded in (name, value):
            if "\x00" in decoded or any(ord(c) < 0x20 and c != "\t" for c in decoded):
                raise ValueError("control character in form body")
        pairs.append((name, value))
    return pairs


def _parse_multipart_body(body: bytes, content_type: str) -> list[tuple[str, bytes, str]]:
    """Parse ``multipart/form-data`` strictly; returns (name, data,
    part content type) per part. Raises ValueError on any framing
    violation (see policy.parse_multipart_body for the rationale)."""
    base, _, params = content_type.partition(";")
    if base.strip().lower() != "multipart/form-data":
        raise ValueError("not a multipart content type")
    boundary = None
    for segment in params.split(";"):
        segment = segment.strip()
        if segment.lower().startswith("boundary="):
            boundary = segment[len("boundary="):].strip().strip('"')
            break
    if not boundary or "\x00" in boundary:
        raise ValueError("multipart body without a boundary")
    delimiter = b"--" + boundary.encode("utf-8")
    if not body.startswith(delimiter):
        raise ValueError("multipart body does not start with its boundary")
    chunks = body.split(delimiter)
    parts: list[tuple[str, bytes, str]] = []
    closed = False
    for chunk in chunks[1:]:
        if chunk.startswith(b"--"):
            if chunk[2:].strip() not in (b"", b"\r\n"):
                raise ValueError("trailing data after multipart closing delimiter")
            closed = True
            break
        if not chunk.startswith(b"\r\n"):
            raise ValueError("multipart part without CRLF framing")
        head, sep, data = chunk[len(b"\r\n"):].partition(b"\r\n\r\n")
        if not sep:
            raise ValueError("multipart part without a header/body separator")
        if data.endswith(b"\r\n"):
            data = data[:-2]
        headers: dict[str, str] = {}
        for line in head.split(b"\r\n"):
            if b"\x00" in line or b":" not in line:
                raise ValueError("malformed multipart part header")
            name, _, val = line.partition(b":")
            headers[name.decode("iso-8859-1").strip().lower()] = val.decode("iso-8859-1").strip()
        disp = headers.get("content-disposition", "")
        name = None
        for segment in disp.split(";"):
            segment = segment.strip()
            if segment.lower().startswith("name="):
                name = segment[len("name="):].strip().strip('"')
                break
        if not name:
            raise ValueError("multipart part without a field name")
        parts.append((name, data, headers.get("content-type", "text/plain")))
    if not closed:
        raise ValueError("multipart body without a closing delimiter")
    return parts


@dataclass
class CanonicalTarget:
    """Canonical form: match, log, approve, and forward derive from this
    and nothing else (v3 N-G4). ``canonical_path`` is the decoded,
    NFC-normalised, dot-resolved path (+ verbatim query) used for
    policy matching, PoP, and audit. ``forward_path`` is the
    percent-encoded rendering of exactly that canonical path, so the
    forwarded request can never differ from the matched request."""

    host: str  # lowercase authority (host[:port]) the request targets
    canonical_path: str
    forward_path: str
    provider_base: str


def canonicalise_target(
    target: str,
    host_header: str | None,
    provider_base: str,
    test_mode: bool = False,
) -> CanonicalTarget:
    """Canonicalise a proxy request target. Raises ValueError on any
    smuggling/malformed form. Origin-form, asterisk-form, fragments,
    backslashes, userinfo, and non-provider hosts are all rejected
    except as documented below.

    Accepted forms: absolute-form (``scheme://authority/path?query``)
    and origin-form (``/path?query`` with a Host header matching the
    provider base). Asterisk-form (``*``) and authority-form are
    rejected -- they carry no provider path to classify.
    """
    if not target or any(c in target for c in ("\x00", "\r", "\n", " ")):
        raise ValueError("malformed target")
    if "#" in target:
        raise ValueError("fragment in target")
    if target == "*" or target.startswith("CONNECT "):
        raise ValueError("asterisk/authority form not proxied")

    base = urllib.parse.urlsplit(provider_base)
    base_host = base.hostname.lower() if base.hostname else ""
    base_port = base.port
    if not base_host:
        raise ValueError("provider base has no host")

    def authority_matches(authority: str) -> str:
        if "@" in authority:
            raise ValueError("userinfo in authority")
        if authority.startswith("["):
            # IPv6 literal: [::1]:port
            bracket = authority.find("]")
            if bracket < 0:
                raise ValueError("malformed IPv6 authority")
            host_part = authority[1:bracket].lower()
            rest = authority[bracket + 1:]
            port_part = rest[1:] if rest.startswith(":") else None
        else:
            if authority.count(":") > 1:
                raise ValueError("malformed authority")
            host_part, _, port_part = authority.partition(":")
            host_part = host_part.lower()
        if host_part != base_host:
            raise ValueError("host does not match provider base")
        if port_part:
            try:
                port_num = int(port_part)
            except ValueError:
                raise ValueError("malformed authority port") from None
            expected = base_port or (443 if base.scheme == "https" else 80)
            if port_num != expected:
                raise ValueError("port does not match provider base")
            return "%s:%d" % (host_part, port_num)
        return host_part

    if "://" in target:
        parts = urllib.parse.urlsplit(target)
        if parts.scheme not in ("http", "https"):
            raise ValueError("unsupported scheme")
        if not test_mode and parts.scheme != "https":
            raise ValueError("plain HTTP upstream outside test mode")
        if parts.username or parts.password or parts.hostname is None:
            raise ValueError("malformed absolute-form target")
        authority = authority_matches(parts.netloc.lower())
        raw_path = parts.path or "/"
        query = parts.query
    else:
        if not target.startswith("/"):
            raise ValueError("origin-form target must start with /")
        if host_header is None:
            raise ValueError("origin-form target needs a Host header")
        authority = authority_matches(host_header.strip().lower())
        split = target.split("?", 1)
        raw_path, query = split[0], (split[1] if len(split) == 2 else "")

    if "\\" in raw_path:
        raise ValueError("backslash in path")
    segments = raw_path.split("/")[1:]  # leading '/' consumed
    try:
        decoded = [_decode_segment(seg) for seg in segments]
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("bad path segment: %s" % (exc,)) from None
    resolved = _remove_dot_segments(decoded)
    canonical = "/" + "/".join(resolved)
    if query:
        # One canonical query, used for policy matching, PoP, audit,
        # AND forwarding alike (f06 F-05/F-13: checked form ==
        # forwarded form, always).
        canonical_query = canonicalise_query(query)
        canonical_path = canonical + "?" + canonical_query
    else:
        canonical_path = canonical
        canonical_query = ""
    safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@"
    forward = "/" + "/".join(urllib.parse.quote(seg, safe=safe) for seg in resolved)
    if canonical_query:
        forward += "?" + canonical_query
    return CanonicalTarget(host=authority, canonical_path=canonical_path,
                           forward_path=forward, provider_base=provider_base)


def validate_loopback_host(host: str) -> None:
    """Refuse any non-loopback bind address (CONTRACT §6: loopback
    only, never 0.0.0.0). Raises ValueError."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("proxy host is not a loopback IP: %r" % (host,)) from None
    if not ip.is_loopback:
        raise ValueError("proxy host is not loopback: %r" % (host,))


# ---------------------------------------------------------------------------
# Response secret scanning (v3 N-G3)
# ---------------------------------------------------------------------------

def _json_unescaped_variants(text: str) -> str:
    """Undo JSON string escaping (\\uXXXX, \\/, \\n, ...) so a key
    hidden behind JSON escaping is still found by the scan."""
    def _sub(match):
        esc = match.group(1)
        if esc.startswith("u") and len(esc) == 5:
            try:
                return chr(int(esc[1:], 16))
            except ValueError:
                return match.group(0)
        return {"n": "\n", "t": "\t", "r": "\r", "/": "/",
                "\\": "\\", '"': '"', "b": "\b", "f": "\f"}.get(esc, match.group(0))
    return re.sub(r"\\(u[0-9a-fA-F]{4}|.)", _sub, text)


def contains_secret(body: bytes, secret: str) -> bool:
    """True if ``secret`` appears in ``body`` in raw, JSON-unescaped,
    hex (either case), or URL-encoded form. Empty secrets never match
    (an empty scan would block everything)."""
    if not secret:
        return False
    raw = secret.encode("utf-8", "surrogatepass")
    if raw in body:
        return True
    hex_lower = secret.encode("utf-8", "surrogatepass").hex().encode("ascii")
    if hex_lower in body.lower():
        return True
    for encoded in (urllib.parse.quote(secret, safe=""),
                    urllib.parse.quote_plus(secret)):
        if encoded.encode("ascii", "ignore") in body:
            return True
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if secret in _json_unescaped_variants(text):
        return True
    return False


def _looks_credential_creating(body: bytes, content_type: str) -> bool:
    """Backstop heuristic (v3 N-G2): a JSON response carrying a
    credential-shaped field with a non-empty string value is treated
    as credential-creating and blocked. This is a backstop only -- the
    primary enforcement is the policy decision's ``credential_creating``
    flag, which denies the endpoint before forwarding."""
    if "json" not in (content_type or "").lower():
        return False
    try:
        payload = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return False
    stack = [payload]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if key.lower() in _CREDENTIAL_RESPONSE_FIELDS \
                        and isinstance(value, str) and value.strip():
                    return True
                stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)
    return False


# ---------------------------------------------------------------------------
# Proxy engine
# ---------------------------------------------------------------------------

class ProxyEngine:
    """Stateless-per-request engine; all cross-request state is the
    append-only PoP replay cache (per session, never evicted, v3 §1C)
    and the degraded flag (audit failure => refuse new calls)."""

    def __init__(
        self,
        config: ProxyConfig,
        lookup_session: Callable[[str], Session | None],
        pop_key_for: Callable[[str], bytes | None],
        decide: Callable[..., PolicyDecision | None] | None,
        approve: Callable[..., tuple[bool, str | None]] | None,
        audit_decision: Callable[[dict], None] | None,
        audit_outcome: Callable[[dict], None] | None,
        key_for: Callable[[str], str | None],
        on_success: Callable[[str], None] | None = None,
        connect_host_allowed: Callable[[Session, str], bool] | None = None,
        test_approver: Callable[..., object] | None = None,
        # Streaming usage observer (W11, f06 F-15.2): called with
        # every raw upstream chunk; returning True aborts the relay
        # before any bytes reach the agent. Typically a wrapper over
        # policy.StreamingTokenAccount.observe (which returns a
        # decision, not a bool -- wrap it as
        # ``lambda c: account.observe(c) is not None``). The approve
        # callable above is untouched: W02 owns it (CONTRACT §13.2).
        usage_observer: Callable[[bytes], bool] | None = None,
    ):
        validate_loopback_host(config.host)
        # v0.2 guard (CONTRACT §13.2): a test approver is allowed
        # ONLY through the explicit test_approver parameter (or a
        # callable flagged as a test approver) AND only when the
        # test-harness marker is set. Outside that marker, raise —
        # never silently fall back to a test double in production.
        # NOTE: unflagged legacy callables passed via ``approve`` are
        # accepted as before (pre-existing W04/integration suites pass
        # plain lambdas); they are NOT the production path — production
        # passes approval.proxy_approver(real_approver) explicitly,
        # and no approver at all denies level-3 calls fail-closed.
        if test_approver is not None and approve is not None:
            raise ValueError("approve and test_approver are mutually exclusive")
        if test_approver is not None:
            if os.environ.get(TEST_APPROVER_ENV) != "1":
                raise RuntimeError(
                    "test approver refused outside the test harness: "
                    "set %s=1 only in tests" % TEST_APPROVER_ENV)
            approve = test_approver
        elif approve is not None and getattr(
                approve, "_keyholder_test_approver", False):
            if os.environ.get(TEST_APPROVER_ENV) != "1":
                raise RuntimeError(
                    "test approver refused outside the test harness: "
                    "set %s=1 only in tests" % TEST_APPROVER_ENV)
        self.config = config
        self.lookup_session = lookup_session
        self.pop_key_for = pop_key_for
        self.decide = decide
        self.approve = approve
        self.test_approver = test_approver
        self.audit_decision = audit_decision
        self.audit_outcome = audit_outcome
        self.key_for = key_for
        self.on_success = on_success
        self.connect_host_allowed = connect_host_allowed
        self.usage_observer = usage_observer
        self._pop_seen: dict[str, set[str]] = {}  # session_id -> pop hexes
        self._pop_lock = threading.Lock()
        self._degraded = False
        self._degraded_lock = threading.Lock()

    # -- degraded flag (audit failure => refuse new calls) ----------------
    @property
    def degraded(self) -> bool:
        with self._degraded_lock:
            return self._degraded

    def _set_degraded(self) -> None:
        with self._degraded_lock:
            self._degraded = True

    # -- request plumbing ---------------------------------------------------
    @staticmethod
    def _normalise_headers(
        headers: Mapping[str, str] | Sequence[tuple[str, str]],
    ) -> dict[str, str]:
        """Lower-cased header map. Rejects NUL/CR/LF in names/values,
        non-token names, and duplicate singleton headers (a classic
        smuggling vector: two Content-Lengths the upstream may resolve
        differently)."""
        pairs = headers.items() if isinstance(headers, Mapping) else headers
        out: dict[str, str] = {}
        singletons = {"content-length", "host", "x-keyholder-session",
                      "x-keyholder-pop", "x-keyholder-timestamp",
                      "transfer-encoding", "content-type"}
        for raw_name, raw_value in pairs:
            if not isinstance(raw_name, str) or not isinstance(raw_value, str):
                raise ProxyError(400, "KH-2001", "non-string header")
            name = raw_name.strip().lower()
            if not _TOKEN_RE.match(name) or "\x00" in raw_value \
                    or "\r" in raw_value or "\n" in raw_value:
                raise ProxyError(400, "KH-2001", "bad header")
            if name in singletons and name in out:
                raise ProxyError(400, "KH-2001", "duplicate header: %s" % name)
            out[name] = raw_value.strip()
        return out

    def _deny(self, status: int, code: str, note: str) -> ProxyResponse:
        return ProxyResponse(status=status, headers=[
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(GENERIC_DENIAL_BODY))),
        ], body=GENERIC_DENIAL_BODY)

    def _audit(self, writer, entry: dict) -> None:
        if writer is None:
            raise ProxyError(503, "KH-1005", "no audit writer configured")
        writer(entry)  # raises on failure -> caller refuses (fail closed)

    def _check_session_live(self, session: Session, now: float) -> None:
        if session.killed:
            raise ProxyError(401, "KH-1002", "session killed")
        if now >= session.expires_at:
            raise ProxyError(401, "KH-1002", "session expired")
        if now >= session.idle_deadline:
            raise ProxyError(401, "KH-1002", "session idle-timed-out")

    def handle(
        self,
        method: str,
        target: str,
        headers: Mapping[str, str] | Sequence[tuple[str, str]],
        body: bytes = b"",
    ) -> ProxyResponse:
        """Handle one proxied request. Never raises for agent-visible
        failures: every refusal is a generic ProxyResponse. Only
        programming errors (bad callable wiring) propagate."""
        now = time.time()
        try:
            return self._handle_inner(method, target, headers, body, now)
        except ProxyError as exc:
            return self._deny(exc.status, exc.code, exc.audit_note)
        except Exception:
            # Never leak a traceback or hang the connection: an
            # unexpected internal failure is a generic upstream error
            # to the agent (details belong in daemon logs, not here).
            return self._deny(502, "KH-1006", "unexpected proxy failure")

    def _handle_inner(self, method, target, headers, body, now) -> ProxyResponse:
        if self.degraded:
            raise ProxyError(503, "KH-1005", "proxy degraded after audit failure")
        if not isinstance(method, str) or not _TOKEN_RE.match(method or ""):
            raise ProxyError(400, "KH-2001", "bad method")
        method = method.upper()
        if method == "CONNECT":
            # CONNECT is tunnelled, not proxied; the handler layer calls
            # authorize_connect() and performs the relay itself.
            raise ProxyError(405, "KH-2001", "CONNECT via handle() refused")
        if len(body) > self.config.max_request_bytes:
            raise ProxyError(413, "KH-2001", "request body over budget")
        hdrs = self._normalise_headers(headers)
        if "transfer-encoding" in hdrs:
            # Chunked bodies are never forwarded partially (v3 N-G7:
            # streamed bodies are buffered-then-decided). The HTTP
            # layer rejects TE outright; reaching here is a second net.
            raise ProxyError(400, "KH-2001", "transfer-encoding refused")
        if "content-length" in hdrs:
            try:
                claimed = int(hdrs["content-length"])
            except ValueError:
                raise ProxyError(400, "KH-2001", "bad content-length") from None
            if claimed != len(body):
                raise ProxyError(400, "KH-2001", "content-length mismatch")

        token = hdrs.get("x-keyholder-session")
        if not token:
            raise ProxyError(401, "KH-1002", "missing session token")
        session = self.lookup_session(token)
        if session is None:
            raise ProxyError(401, "KH-1002", "session not found")

        base = self.config.bases.get(session.provider)
        if base is None:
            raise ProxyError(502, "KH-1006", "no upstream base for provider")
        if not self.config.test_mode:
            if not base.lower().startswith("https://"):
                raise ProxyError(502, "KH-1006", "non-HTTPS upstream outside test mode")
        else:
            parsed_base = urllib.parse.urlsplit(base)
            if parsed_base.scheme == "http" and parsed_base.hostname not in (
                    "127.0.0.1", "localhost", "::1"):
                raise ProxyError(502, "KH-1006", "plain HTTP mock base not loopback")

        try:
            canon = canonicalise_target(target, hdrs.get("host"), base,
                                        test_mode=self.config.test_mode)
        except ValueError as exc:
            raise ProxyError(400, "KH-2001", "canonicalisation: %s" % (exc,)) from None

        self._check_session_live(session, now)

        # PoP (CONTRACT §4): HMAC over METHOD\nHOST\nCANONICAL_PATH\n
        # BODY_SHA256\nTIMESTAMP, 300 s skew, append-only replay cache.
        pop_key = self.pop_key_for(session.session_id)
        pop_hex = hdrs.get("x-keyholder-pop")
        timestamp = hdrs.get("x-keyholder-timestamp")
        if pop_key is None or not verify_pop(pop_key, method, canon.host,
                                             canon.canonical_path, body,
                                             timestamp, pop_hex, now=now):
            raise ProxyError(401, "KH-1002", "PoP verification failed")
        with self._pop_lock:
            seen = self._pop_seen.setdefault(session.session_id, set())
            if pop_hex in seen:
                raise ProxyError(401, "KH-1002", "PoP replay")
            seen.add(pop_hex)  # append-only for the session lifetime

        content_type = hdrs.get("content-type", "")
        base_ct = content_type.split(";")[0].strip().lower()
        if base_ct.startswith("application/json") or base_ct.endswith("+json") \
                or (not base_ct and body.strip()[:1] in (b"{", b"[")):
            # JSON, JSON-like, or content-type-less JSON-looking
            # bodies: duplicate keys at any depth are a deny (f06
            # F-11). A declared non-JSON type is NOT JSON-parsed
            # here -- the provider dispatches on content type, and
            # parsing it as JSON would diverge from the provider.
            try:
                _check_json_no_duplicates(body)
            except (ValueError, UnicodeDecodeError) as exc:
                raise ProxyError(400, "KH-2001", "bad JSON body: %s" % (exc,)) from None
        elif base_ct == "application/x-www-form-urlencoded":
            # Form bodies are parsed, not hash-only (f06 F-10a):
            # malformed framing and credential-named fields deny.
            try:
                pairs = _parse_form_body(body)
            except (ValueError, UnicodeDecodeError) as exc:
                raise ProxyError(400, "KH-2001", "bad form body: %s" % (exc,)) from None
            if any(name.lower() in _CREDENTIAL_BODY_FIELDS for name, _ in pairs):
                raise ProxyError(400, "KH-2001", "credential field in form body")
        elif base_ct == "multipart/form-data":
            # Multipart bodies are parsed, not hash-only (f06 F-10b).
            try:
                parts = _parse_multipart_body(body, content_type)
            except ValueError as exc:
                raise ProxyError(400, "KH-2001", "bad multipart body: %s" % (exc,)) from None
            for part_name, part_data, part_ct in parts:
                if part_name.lower() in _CREDENTIAL_BODY_FIELDS:
                    raise ProxyError(400, "KH-2001", "credential field in multipart body")
                if part_ct.split(";")[0].strip().lower().endswith("json"):
                    try:
                        _check_json_no_duplicates(part_data)
                    except (ValueError, UnicodeDecodeError) as exc:
                        raise ProxyError(400, "KH-2001", "bad JSON multipart part: %s" % (exc,)) from None

        # Policy classification by capability (W05). None = unmodelled = deny.
        decision = self.decide(session, method, canon.canonical_path, body,
                               content_type) if self.decide else None
        # Manager integration fix: W05's level-3 decisions carry
        # allowed=False *until* the broker-owned approver grants them
        # (decision_after_approval). Denying on allowed=False here
        # would make approval-gated calls unreachable — the approver
        # would never be consulted. Level 3 therefore passes this
        # gate and is decided by the approval step below; only
        # level 4 / non-level-3 denials are denied here.
        if decision is None or decision.level >= 4:
            raise ProxyError(403, "KH-1003", "policy denied")
        if not decision.allowed and decision.level != 3:
            raise ProxyError(403, "KH-1003", "policy denied")
        if getattr(decision, "credential_creating", False):
            # v3 N-G2: credential-issuing endpoints are denied in v1.
            raise ProxyError(403, "KH-1003", "credential-creating endpoint")

        approval_id = None
        if decision.level == 3:
            if self.approve is None:
                raise ProxyError(403, "KH-1004", "no approver configured")
            try:
                result = self.approve(
                    session, method, canon.canonical_path,
                    "provider=%s class=%s path=%s" % (
                        session.provider, session.session_class, canon.canonical_path))
            except Exception as exc:
                # An approver failure is an approval denial, never a
                # forward and never an upstream-error leak to the agent.
                raise ProxyError(403, "KH-1004",
                                 "approver failure: %r" % (exc,)) from None
            if hasattr(result, "approved"):
                # v0.2 real approver: ApprovalDecision object.
                approved = bool(result.approved)
                approval_id = getattr(result, "approval_id", None) or None
            else:
                # Legacy tuple: (approved: bool, approval_id | None).
                approved, approval_id = result
            if not approved:
                raise ProxyError(403, "KH-1004", "approval denied/timeout")
            # Post-approval decision, mirroring W05 decision_after_approval:
            # allowed, now at allow-with-log level.
            decision = PolicyDecision(
                allowed=True, level=2, reason=decision.reason,
                rule_id=decision.rule_id)

        decision_entry = {
            "event_type": "proxy_decision",
            "session_id": session.session_id,
            "key_id": session.key_id,
            "provider": session.provider,
            "method": method,
            "canonical_path": canon.canonical_path,
            "decision": "allow",
            "rule_id": decision.rule_id,
            "level": decision.level,
            "approval_id": approval_id,
            # Every audit surface carries BOTH the session transport
            # mode and the effective policy label: an absolute-form
            # request from a connect_allowed session is still fully
            # policed, so its label stays "absolute" while the
            # transport field records the session mode (f06 F-01).
            "transport": session.transport,
            "transport_label": "absolute",
            "host_only": False,
        }
        try:
            self._audit(self.audit_decision, decision_entry)
        except ProxyError:
            raise
        except Exception as exc:
            # Audit failure = refuse, never run blind (v3 N-G5).
            raise ProxyError(503, "KH-1005", "audit decision write failed: %r" % (exc,)) from None

        # N-G12: liveness re-checked immediately before injection.
        fresh = self.lookup_session(token)
        if fresh is None:
            raise ProxyError(401, "KH-1002", "session vanished before injection")
        self._check_session_live(fresh, time.time())

        real_key = self.key_for(session.key_id)
        if not real_key:
            raise ProxyError(502, "KH-1006", "key unavailable")

        forward_headers = {
            name: value for name, value in hdrs.items()
            if name not in _HOP_BY_HOP
            and name not in _AGENT_CREDENTIAL_HEADERS
            and name not in _SESSION_HEADERS
            and name != "accept-encoding"  # strip so scan sees plaintext
            and name != "host"
        }
        forward_headers["host"] = canon.host
        forward_headers["accept-encoding"] = "identity"
        if session.provider == "github":
            forward_headers["authorization"] = "Bearer " + real_key
        elif session.provider == "gemini":
            forward_headers["x-goog-api-key"] = real_key
        else:
            raise ProxyError(502, "KH-1006", "unknown provider")
        if "content-length" in forward_headers:
            forward_headers["content-length"] = str(len(body))
        elif body:
            forward_headers["content-length"] = str(len(body))

        status, resp_headers, resp_body = self._forward(
            base, method, canon.forward_path, forward_headers, body)
        content_type_out = ""
        for key, value in resp_headers:
            if key.lower() == "content-type":
                content_type_out = value
                break
        blocked = False
        block_note = ""
        if contains_secret(resp_body, real_key):
            blocked, block_note = True, "secret detected in response"
        elif _looks_credential_creating(resp_body, content_type_out):
            blocked, block_note = True, "credential-creating response"
        for key, value in resp_headers:
            if real_key in value:
                blocked, block_note = True, "secret detected in response header"
                break
        outcome = {
            "event_type": "proxy_outcome",
            "session_id": session.session_id,
            "key_id": session.key_id,
            "provider": session.provider,
            "method": method,
            "canonical_path": canon.canonical_path,
            "decision": "allow",
            "rule_id": decision.rule_id,
            "approval_id": approval_id,
            "outcome": "blocked" if blocked else "relayed",
            "upstream_status": status,
            "bytes_in": len(body),
            "bytes_out": 0 if blocked else len(resp_body),
            "transport": session.transport,
            "transport_label": "absolute",
            "host_only": False,
        }
        if blocked:
            try:
                self._audit(self.audit_outcome, outcome)
            except Exception:
                self._set_degraded()
            return self._deny(502, "KH-1006", block_note)
        try:
            self._audit(self.audit_outcome, outcome)
        except Exception:
            # The call already completed; it cannot be recalled. The
            # response is delivered, but the proxy refuses NEW calls
            # until the operator restarts it (fail closed, CONTRACT §8).
            self._set_degraded()
        if 200 <= status < 400 and self.on_success is not None:
            try:
                self.on_success(session.session_id)
            except Exception:
                pass
        safe_headers = [(k, v) for k, v in resp_headers
                        if k.lower() not in _STRIP_RESPONSE_HEADERS]
        safe_headers.append(("Content-Length", str(len(resp_body))))
        return ProxyResponse(status=status, headers=safe_headers, body=resp_body)

    # -- upstream forwarding -------------------------------------------------
    def _forward(self, base, method, path, headers, body):
        parts = urllib.parse.urlsplit(base)
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        conn_cls = http.client.HTTPSConnection if parts.scheme == "https" \
            else http.client.HTTPConnection
        conn = conn_cls(host, port, timeout=self.config.upstream_timeout_s)
        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_headers = list(resp.getheaders())
            encoding = ""
            for key, value in resp_headers:
                if key.lower() == "content-encoding":
                    encoding = value.lower().strip()
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = resp.read(_READ_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.config.max_response_bytes:
                    raise ProxyError(502, "KH-1006", "response over budget")
                if self.usage_observer is not None:
                    # Streaming token/spend accounting (f06 F-15.2):
                    # an over-cap observer aborts BEFORE any byte is
                    # relayed to the agent, even though _forward
                    # buffers the response first.
                    try:
                        over_cap = self.usage_observer(chunk)
                    except Exception:
                        over_cap = False
                    if over_cap:
                        raise ProxyError(502, "KH-1006", "stream usage cap exceeded (estimated)")
                chunks.append(chunk)
            raw = b"".join(chunks)
            if encoding in ("gzip", "x-gzip"):
                try:
                    raw = gzip.decompress(raw)
                except (OSError, EOFError) as exc:
                    raise ProxyError(502, "KH-1006", "bad gzip body") from None
            elif encoding == "deflate":
                try:
                    raw = zlib.decompress(raw)
                except zlib.error as exc:
                    raise ProxyError(502, "KH-1006", "bad deflate body") from None
            elif encoding not in ("", "identity"):
                # Unscannable encoding (e.g. br, no stdlib decoder):
                # refuse the relay rather than pass unscanned bytes.
                raise ProxyError(502, "KH-1006", "unscannable encoding: %s" % encoding)
            return resp.status, resp_headers, raw
        except ProxyError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise ProxyError(502, "KH-1006", "upstream error: %r" % (exc,)) from None
        finally:
            try:
                conn.close()
            except Exception:
                pass

    # -- CONNECT ---------------------------------------------------------------
    def authorize_connect(
        self,
        authority: str,
        headers: Mapping[str, str] | Sequence[tuple[str, str]],
        body: bytes = b"",
    ) -> ConnectDecision:
        """Validate a CONNECT request. Returns a decision; the HTTP
        handler performs the tunnel only when allowed, and records the
        audit entry (labelled HOST-ONLY POLICY) before relaying bytes.
        Refusals are generic 405s at the handler layer."""
        try:
            hdrs = self._normalise_headers(headers)
        except ProxyError:
            return ConnectDecision(allowed=False)
        if self.degraded:
            return ConnectDecision(allowed=False)
        token = hdrs.get("x-keyholder-session")
        if not token:
            return ConnectDecision(allowed=False)
        session = self.lookup_session(token)
        if session is None:
            return ConnectDecision(allowed=False)
        if session.transport != "connect_allowed":
            return ConnectDecision(allowed=False)
        # v3 N-G1: CONNECT is refused for write/destructive sessions
        # and for any provider whose policy uses path/body rules. The
        # proxy enforces the class half; the host hook covers the rest.
        if session.session_class in ("write", "destructive"):
            return ConnectDecision(allowed=False)
        now = time.time()
        try:
            self._check_session_live(session, now)
        except ProxyError:
            return ConnectDecision(allowed=False)
        if ":" in authority and not authority.startswith("["):
            host_part, _, port_part = authority.rpartition(":")
            try:
                port = int(port_part)
            except ValueError:
                return ConnectDecision(allowed=False)
        else:
            host_part, port = authority, 443
        host_part = host_part.lower()
        if self.config.test_mode:
            if host_part not in ("127.0.0.1", "localhost", "::1"):
                return ConnectDecision(allowed=False)
        else:
            if port != 443:
                return ConnectDecision(allowed=False)
            if host_part not in self.config.connect_hosts and not (
                    self.connect_host_allowed is not None
                    and self.connect_host_allowed(session, host_part)):
                return ConnectDecision(allowed=False)
        # PoP for CONNECT signs method CONNECT, host = authority, and
        # canonical path "/" (W03 compute_pop requires a non-empty
        # path; "/" is the CONNECT convention -- see module docstring
        # note for the W12 wrapper).
        pop_key = self.pop_key_for(session.session_id)
        pop_hex = hdrs.get("x-keyholder-pop")
        timestamp = hdrs.get("x-keyholder-timestamp")
        if pop_key is None or not verify_pop(pop_key, "CONNECT", host_part,
                                             "/", body, timestamp, pop_hex,
                                             now=now):
            return ConnectDecision(allowed=False)
        with self._pop_lock:
            seen = self._pop_seen.setdefault(session.session_id, set())
            if pop_hex in seen:
                return ConnectDecision(allowed=False)
            seen.add(pop_hex)
        entry = {
            "event_type": "proxy_decision",
            "session_id": session.session_id,
            "key_id": session.key_id,
            "provider": session.provider,
            "method": "CONNECT",
            "canonical_path": authority,
            "decision": "allow",
            "rule_id": None,
            "level": 2,
            "approval_id": None,
            # CONNECT entries are HOST-ONLY on every surface: the
            # tunnel carries no method/path/body policy, only host +
            # byte budget (f06 F-01). ``host_only`` is the machine-
            # readable twin of the label for UI/audit consumers.
            "transport": session.transport,
            "transport_label": HOST_ONLY_LABEL,
            "host_only": True,
        }
        try:
            self._audit(self.audit_decision, entry)
        except Exception:
            return ConnectDecision(allowed=False)
        return ConnectDecision(allowed=True, host=host_part, port=port,
                               byte_budget=self.config.connect_byte_budget,
                               session_id=session.session_id,
                               audit_entry=entry)

    def audit_connect_outcome(self, decision: ConnectDecision,
                              bytes_to_upstream: int,
                              bytes_to_client: int) -> None:
        """Record the tunnel OUTCOME entry (f06 F-01 completeness).

        Previously only the CONNECT decision was audited; the bytes
        actually relayed through the tunnel were never recorded, so
        a tunnel's audit trail ended at authorisation. The outcome
        entry carries the same HOST-ONLY POLICY label and
        ``host_only`` flag as the decision entry, plus per-direction
        byte counts (the tunnel byte budget is enforced on the
        total; the directions are reported separately so a reviewer
        can see exfiltration-shaped asymmetry).
        Raises when the audit writer fails; the handler marks the
        proxy degraded in that case (the tunnel is already closed,
        so nothing can be recalled -- but no NEW call may proceed
        unaudited).
        """
        entry = {
            "event_type": "proxy_outcome",
            "session_id": decision.session_id,
            "provider": "",
            "method": "CONNECT",
            "canonical_path": "%s:%d" % (decision.host, decision.port),
            "decision": "allow",
            "rule_id": None,
            "level": 2,
            "approval_id": None,
            "outcome": "relayed",
            "bytes_in": bytes_to_upstream,
            "bytes_out": bytes_to_client,
            "bytes_relayed": bytes_to_upstream + bytes_to_client,
            "transport": "connect_allowed",
            "transport_label": HOST_ONLY_LABEL,
            "host_only": True,
        }
        self._audit(self.audit_outcome, entry)


# ---------------------------------------------------------------------------
# HTTP server layer (loopback only; raw-head smuggling guards)
# ---------------------------------------------------------------------------

def _read_raw_head(rfile, limit=_MAX_HEADER_BYTES):
    """Read request line + headers as raw lines. Every line must end
    CRLF (a bare LF is a smuggling attempt), no NUL bytes, no
    obs-fold continuation lines (a line starting with SP/HTAB), at
    most 100 headers. Raises ProxyError(400) on violation."""
    lines: list[bytes] = []
    total = 0
    while True:
        line = rfile.readline(_MAX_HEADER_BYTES)
        if not line:
            raise ProxyError(400, "KH-2001", "EOF in request head")
        total += len(line)
        if total > limit or len(lines) > _MAX_HEADER_COUNT:
            raise ProxyError(400, "KH-2001", "request head too large")
        if b"\x00" in line:
            raise ProxyError(400, "KH-2001", "NUL in request head")
        if not line.endswith(b"\r\n"):
            raise ProxyError(400, "KH-2001", "bare LF in request head")
        stripped = line[:-2]
        if stripped == b"":
            break
        if stripped[:1] in (b" ", b"\t"):
            raise ProxyError(400, "KH-2001", "header folding refused")
        lines.append(stripped)
    return lines


class KeyholderProxyHandler(BaseHTTPRequestHandler):
    """HTTP layer for the proxy engine. Parses the raw head itself so
    bare-LF / folding / NUL smuggling is rejected before any header
    parsing library can silently normalise it away."""

    protocol_version = "HTTP/1.1"
    server_version = "KeyholderProxy/0.1"
    engine: ProxyEngine  # set by make_server

    def log_message(self, *args):  # keep test/daemon output readable
        pass

    def _send(self, resp: ProxyResponse) -> None:
        try:
            self.send_response(resp.status)
            sent_length = False
            for key, value in resp.headers:
                self.send_header(key, value)
                if key.lower() == "content-length":
                    sent_length = True
            if not sent_length:
                self.send_header("Content-Length", str(len(resp.body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if resp.body:
                self.wfile.write(resp.body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.close_connection = True

    def _deny(self, status: int) -> None:
        self._send(ProxyResponse(status=status, headers=[
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(GENERIC_DENIAL_BODY))),
        ], body=GENERIC_DENIAL_BODY))

    def handle_one_request(self) -> None:
        # Defaults so _deny() can answer even when head parsing itself
        # fails (send_response/log_request read these attributes).
        self.requestline = ""
        self.command = ""
        self.path = ""
        self.request_version = "HTTP/1.1"
        try:
            lines = _read_raw_head(self.rfile)
        except ProxyError:
            self._deny(400)
            return
        except (OSError, ValueError):
            self._deny(400)
            return
        if not lines:
            self._deny(400)
            return
        try:
            request_line = lines[0].decode("iso-8859-1")
            parts = request_line.split(" ")
        except (UnicodeDecodeError, ValueError):
            self._deny(400)
            return
        if len(parts) != 3:
            self._deny(400)
            return
        method, target, _version = parts
        # parse_request() is bypassed (raw-head parsing above), so
        # set the attributes send_response/log_request expect.
        self.requestline = request_line
        self.command = method
        self.path = target
        self.request_version = _version
        headers: list[tuple[str, str]] = []
        for raw in lines[1:]:
            try:
                text = raw.decode("iso-8859-1")
            except UnicodeDecodeError:
                self._deny(400)
                return
            if ":" not in text:
                self._deny(400)
                return
            name, _, value = text.partition(":")
            if not name.strip():
                self._deny(400)
                return
            headers.append((name.strip(), value.strip()))
        header_map = {name.lower(): value for name, value in headers}
        if "transfer-encoding" in header_map:
            self._deny(400)  # chunked/CL+TE smuggling refused outright
            return
        content_length = 0
        if "content-length" in header_map:
            try:
                content_length = int(header_map["content-length"])
            except ValueError:
                self._deny(400)
                return
            if content_length < 0 or content_length > self.engine.config.max_request_bytes:
                self._deny(400)
                return
        if header_map.get("expect", "").lower() == "100-continue":
            try:
                self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            except OSError:
                return
        body = b""
        if content_length:
            try:
                body = self.rfile.read(content_length)
            except OSError:
                self._deny(400)
                return
            if len(body) != content_length:
                self._deny(400)
                return
        if method.upper() == "CONNECT":
            self._handle_connect(target, headers)
            return
        resp = self.engine.handle(method, target, headers, body)
        self._send(resp)

    def _handle_connect(self, authority: str, headers) -> None:
        decision = self.engine.authorize_connect(authority, headers)
        if not decision.allowed:
            self._deny(405)
            return
        try:
            upstream = socket.create_connection(
                (decision.host, decision.port),
                timeout=self.engine.config.connect_timeout_s)
        except OSError:
            self._deny(502)
            return
        try:
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except OSError:
            upstream.close()
            return
        to_up, to_client = self._relay_tunnel(
            self.connection, upstream, decision.byte_budget)
        try:
            upstream.close()
        except OSError:
            pass
        try:
            self.engine.audit_connect_outcome(decision, to_up, to_client)
        except Exception:
            # Tunnel already closed; it cannot be recalled, but the
            # proxy must not serve new calls unaudited (fail closed).
            self.engine._set_degraded()
        self.close_connection = True

    @staticmethod
    def _relay_tunnel(client: socket.socket, upstream: socket.socket,
                      budget: int) -> tuple[int, int]:
        """Byte-counted tunnel relay. Either direction exceeding the
        budget, or an error, closes both sides. Returns
        (client->upstream bytes, upstream->client bytes) for the
        tunnel outcome audit entry. No content inspection is
        possible inside a tunnel -- that is why every surface
        labels it HOST-ONLY POLICY."""
        import select
        for sock in (client, upstream):
            try:
                sock.setblocking(False)
            except OSError:
                return (0, 0)
        total = 0
        to_upstream = 0
        to_client = 0
        sockets = {client: upstream, upstream: client}
        try:
            while True:
                readable, _, _ = select.select([client, upstream], [], [], 30.0)
                if not readable:
                    break
                progress = False
                for sock in readable:
                    try:
                        data = sock.recv(65536)
                    except OSError:
                        return (to_upstream, to_client)
                    if not data:
                        return (to_upstream, to_client)
                    total += len(data)
                    if total > budget:
                        return (to_upstream, to_client)
                    try:
                        sockets[sock].sendall(data)
                    except OSError:
                        return (to_upstream, to_client)
                    if sock is client:
                        to_upstream += len(data)
                    else:
                        to_client += len(data)
                    progress = True
                if not progress:
                    break
        except (OSError, ValueError):
            return (to_upstream, to_client)
        return (to_upstream, to_client)

def make_server(config: ProxyConfig, engine: ProxyEngine,
                host: str | None = None, port: int | None = None) -> ThreadingHTTPServer:
    """Build a loopback-only ThreadingHTTPServer. Raises ValueError for
    any non-loopback host, including 0.0.0.0."""
    bind_host = host if host is not None else config.host
    validate_loopback_host(bind_host)
    bind_port = port if port is not None else config.port

    class _Handler(KeyholderProxyHandler):
        pass

    _Handler.engine = engine
    server = ThreadingHTTPServer((bind_host, bind_port), _Handler)
    server.daemon_threads = True
    return server
