"""Keyholder v0.1 policy decision engine (W05).

Implements CONTRACT section 6 and v3 plan section 1G (proxy/policy).
Tier statement: this engine is a Tier A control (interface-bound agent).
It does NOT survive a Tier B (shell-capable same-user) agent on its own:
a Tier B agent can bypass the proxy entirely, so the engine's guarantees
hold only for traffic that actually flows through the broker proxy.

Levels (CONTRACT section 2 / section 6):
    1 = allow
    2 = allow-with-log
    3 = approve (broker-owned approval required BEFORE forwarding;
        ``allowed`` is False until approval is granted, see
        :func:`decision_after_approval`)
    4 = deny

Rules that are load-bearing for the manager check:
  * Unmodelled endpoint = deny (level 4). Never default-allow.
  * Decision cache: ALLOW (level 1) only, 60 s, never for spend-flagged
    (cap-conditioned) or approval-gated (level 3) rules.
  * Agent-facing denials are generic: no rule_id, no category. The
    rule_id/category live in the audit log only (CONTRACT section 6,
    v3 N-G8). Use :func:`agent_denial_message` for agent output and
    never serialise ``PolicyDecision.rule_id`` to the agent.
  * Spend caps are estimates. Every user-facing spend string produced
    here says "spend alerts (estimated)" and never promises a hard cap.
  * Stale packs: refusal (level 4) for destructive / financial /
    metered (spend-flagged) endpoints and for destructive sessions;
    graduated escalation (+1 level) for everything else. This follows
    the CONTRACT section 6 / task wording ("refusal for
    destructive/metered sessions"); v3 N-G11's graduated-only scheme
    would escalate destructive endpoints instead of refusing them, so
    the stricter refusal wins for those endpoints (flagged in the W05
    report for the manager to reconcile).
  * Capability classification: highest class wins; paid inference is
    write class; "financial" is reserved for money/billing only.
  * GraphQL: mutations are counted per document, not per request; a
    JSON-array batch body is N separately evaluated requests; the
    mutation cap per approval defaults to 1 (v3 N-G6).
  * Read-like POSTs (e.g. Gemini ``countTokens``) are read class, not
    write, via the pack's ``read_like_posts`` exemption list (v3 N-B6).

This module is stdlib-only. It deliberately does NOT import
``keyholder.types``: W01 owns that file and it does not exist yet in
this build root. ``PolicyDecision`` here mirrors the CONTRACT section 2
shape exactly (allowed, level, reason, rule_id) so W01/W04 can swap the
import without changing call sites; the manager should confirm the
single canonical home for the dataclass.
"""

from __future__ import annotations

import json
import math
import re
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

# ---------------------------------------------------------------- levels

LEVEL_ALLOW = 1
LEVEL_ALLOW_WITH_LOG = 2
LEVEL_APPROVE = 3
LEVEL_DENY = 4

#: Generic agent-facing denial. Contains no rule_id and no category.
GENERIC_DENIAL = "Request denied by policy."

#: The only spend wording user-facing copy may use (v3 N-G10).
SPEND_ALERT_LABEL = "spend alerts (estimated)"

#: Decision-cache TTL in seconds (CONTRACT section 6).
CACHE_TTL_SECONDS = 60.0

#: Default cap on GraphQL mutations per approval (v3 N-G6).
DEFAULT_MUTATIONS_PER_APPROVAL = 1

#: Cumulative-estimate error above which spend tracking pauses (v3 N-G10).
SPEND_ESTIMATE_ERROR_PAUSE_THRESHOLD = 0.20

# ------------------------------------------------------- capability ranks

# Highest class wins. "financial" is a separate top rank: it is money /
# billing only, and no session class in v0.1 (destructive / write /
# read_account / read_public) satisfies it, so financial endpoints are
# denied unless a future contract adds a financial session class.
_CAPABILITY_RANK = {
    "read_public": 0,
    "read_account": 1,
    "write": 2,
    "destructive": 3,
    "financial": 4,
}

_SESSION_CLASS_RANK = {
    "read_public": 0,
    "read_account": 1,
    "write": 2,
    "destructive": 3,
}

# Session classes that may ever use a CONNECT (tunnel) transport are
# none in v0.1 policy terms: CONNECT is refused by default and, when
# opted in, is HOST-ONLY POLICY (CONTRACT section 6). The engine does
# not authorise CONNECT itself; the proxy enforces it. This constant
# documents that no policy decision here blesses tunnelled traffic.
CONNECT_ALLOWED_SESSION_CLASSES: frozenset = frozenset()


@dataclass(frozen=True)
class PolicyDecision:
    """Mirrors CONTRACT section 2 exactly (allowed, level, reason, rule_id).

    ``reason`` and ``rule_id`` are for the audit log and operator
    surfaces only. Never send them to the agent (see GENERIC_DENIAL).
    Level 3 means approval is required: ``allowed`` is False until the
    broker-owned approver grants it; use :func:`decision_after_approval`
    to produce the post-approval decision.
    """

    allowed: bool
    level: int
    reason: str
    rule_id: str | None = None


def agent_denial_message(decision: PolicyDecision) -> str:
    """Generic agent-facing denial text (no rule_id, no category)."""
    if decision.level == LEVEL_DENY or not decision.allowed:
        return GENERIC_DENIAL
    return ""


def decision_after_approval(decision: PolicyDecision) -> PolicyDecision:
    """Convert a level-3 (approve) decision into a post-approval allow.

    Approval is single-use and bound to the exact request by the
    approver (W08); this function only restates the level, it does not
    perform approval. Non-level-3 decisions pass through unchanged.
    """
    if decision.level != LEVEL_APPROVE:
        return decision
    return PolicyDecision(
        allowed=True,
        level=LEVEL_ALLOW_WITH_LOG,
        reason="approved: " + decision.reason,
        rule_id=decision.rule_id,
    )


def spend_alert_copy(detail: str = "") -> str:
    """User-facing spend wording. Always carries the estimated label."""
    base = SPEND_ALERT_LABEL
    return f"{base}: {detail}" if detail else base


# ------------------------------------------------------------- canonical path

class CanonicalisationError(ValueError):
    """Raised when a raw path cannot be canonicalised safely."""


def canonicalise_path(raw_path: str) -> str:
    """Return the canonical path for matching, logging and forwarding.

    Split FIRST, then percent-decode each segment (CONTRACT section 6 /
    v3 N-G4: decode-then-split is forbidden, because an encoded ``%2F``
    must not become a path separator). Rejects fragments, backslashes,
    NUL bytes, empty segments created by ``//`` (except the root), and
    non-string input. Segments are NFC-normalised at match time (the
    pattern compiler does the same), so equivalent spellings match.
    The query string is stripped: policy matches the path only, and the
    proxy must never forward a raw query it has not split first.
    """
    if not isinstance(raw_path, str) or not raw_path:
        raise CanonicalisationError("empty or non-string path")
    if "\x00" in raw_path:
        raise CanonicalisationError("NUL byte in path")
    if "#" in raw_path:
        raise CanonicalisationError("fragment in path")
    if "\\" in raw_path:
        raise CanonicalisationError("backslash in path")
    path = raw_path.split("?", 1)[0]
    if not path.startswith("/"):
        raise CanonicalisationError("path must be absolute")
    segments = path.split("/")[1:]
    if any(seg == "" for seg in segments):
        raise CanonicalisationError("empty path segment")
    decoded: list[str] = []
    for seg in segments:
        decoded_seg = _percent_decode_segment(seg)
        if decoded_seg in (".", ".."):
            raise CanonicalisationError("dot segment in path")
        decoded.append(decoded_seg)
    normalised = [unicodedata.normalize("NFC", s) for s in decoded]
    return "/" + "/".join(normalised)


def _percent_decode_segment(seg: str) -> str:
    """Percent-decode one segment; malformed escapes are rejected."""
    out = bytearray()
    i = 0
    while i < len(seg):
        ch = seg[i]
        if ch == "%":
            hexpart = seg[i + 1 : i + 3]
            if len(hexpart) != 2 or not all(c in "0123456789abcdefABCDEF" for c in hexpart):
                raise CanonicalisationError("malformed percent escape")
            out.append(int(hexpart, 16))
            i += 3
        else:
            out.extend(ch.encode("utf-8"))
            i += 1
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanonicalisationError("non-UTF-8 percent-decoded segment") from exc


# ------------------------------------------------------------ glob matching

def match_pattern(pattern: str, canonical_path: str) -> bool:
    """Match a canonical path against a ``*`` / ``**`` segment glob.

    Each pattern segment is matched against exactly one path segment
    with a shell-style glob (``*`` matches any characters within the
    segment, e.g. ``*:countTokens``); ``**`` as a whole segment matches
    the rest of the path. Matching is linear in the number of segments:
    each pattern segment is tried at most once per path position, so no
    backtracking blow-up (v3 N-G4 linear-time matcher requirement).
    Pattern segments are NFC-normalised at match time, mirroring
    :func:`canonicalise_path`.
    """
    pat_segs = [unicodedata.normalize("NFC", s) for s in pattern.split("/")[1:]]
    path_segs = canonical_path.split("/")[1:]
    return _match_segments(pat_segs, path_segs)


def _match_segments(pat: list[str], path: list[str]) -> bool:
    import fnmatch

    i = j = 0
    star_star = -1  # index in pat of the last ** seen
    star_star_path = 0
    while j < len(path):
        if i < len(pat) and pat[i] != "**" and fnmatch.fnmatchcase(path[j], pat[i]):
            i += 1
            j += 1
        elif i < len(pat) and pat[i] == "**":
            star_star = i
            star_star_path = j
            i += 1
        elif star_star != -1:
            i = star_star + 1
            star_star_path += 1
            j = star_star_path
        else:
            return False
    while i < len(pat) and pat[i] == "**":
        i += 1
    return i == len(pat)


# ------------------------------------------------------------- JSON strictness

class DuplicateKeyError(ValueError):
    """A JSON body contained a duplicate key at some depth (v3 N-G7)."""


def parse_json_no_duplicates(raw: bytes | str) -> object:
    """Parse JSON, rejecting duplicate keys at any depth.

    The engine and upstream parsers must not silently pick different
    values for the same key, so duplicates are a deny, not a warning.
    """
    def _no_dup(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise DuplicateKeyError(f"duplicate JSON key: {key!r}")
            obj[key] = value
        return obj

    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    return json.loads(text, object_pairs_hook=_no_dup)


# ------------------------------------------------- form / multipart bodies
# (f06 F-10: JSON-only parsing leaves form and multipart bodies
# entirely unchecked. These parsers are the policy side; the proxy
# carries its own copies because proxy.py must not import policy.py
# -- its decide boundary is an injected callable.)

#: Field names that must never carry a value in a form/multipart body
#: (mirrors the proxy's query-parameter rule: credentials in a body
#: field land in logs and provider-side records).
_CREDENTIAL_FIELD_NAMES = {
    "key", "api_key", "apikey", "access_token", "token", "secret",
    "password", "client_secret",
}


def parse_query_split_first(query: str) -> list[tuple[str, str]]:
    """Parse a raw query string, split-first-then-decode (f06 F-13).

    Splits the RAW string on unencoded ``&`` first (never ``;``),
    then percent-decodes each name and value exactly once. A value
    containing ``%26`` therefore stays one literal ``&`` character,
    never a new separator, and ``%3D`` stays a literal ``=``. Order
    and duplicates are preserved (duplicate query parameters are
    all-values, never silently collapsed). Raises ValueError on
    malformed escapes, NUL/control characters, or empty names.
    """
    if not isinstance(query, str):
        raise ValueError("query is not a string")
    if "\x00" in query or "\r" in query or "\n" in query:
        raise ValueError("NUL/CR/LF in query")
    pairs: list[tuple[str, str]] = []
    if query == "":
        return pairs
    for segment in query.split("&"):
        if segment == "":
            continue  # trailing/double '&' carries no parameter
        name_raw, sep, value_raw = segment.partition("=")
        try:
            name = urllib.parse.unquote(name_raw, encoding="utf-8", errors="strict")
            value = urllib.parse.unquote(value_raw, encoding="utf-8", errors="strict") if sep else ""
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("malformed percent escape in query") from exc
        if not name:
            raise ValueError("empty query parameter name")
        for decoded in (name, value):
            if "\x00" in decoded or any(ord(c) < 0x20 or ord(c) == 0x7F for c in decoded):
                raise ValueError("control character in query")
        pairs.append((name, value))
    return pairs


def parse_form_body(raw: bytes | str) -> list[tuple[str, str]]:
    """Parse ``application/x-www-form-urlencoded`` split-first.

    Splits on raw ``&`` first, then decodes each name/value once
    (``+`` decodes to space, as form encoding defines). Preserves
    order and duplicates (all values are checked, never collapsed).
    Raises ValueError on malformed escapes or control characters.
    """
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    if "\x00" in text or "\r" in text or "\n" in text:
        raise ValueError("NUL/CR/LF in form body")
    pairs: list[tuple[str, str]] = []
    if text == "":
        return pairs
    for segment in text.split("&"):
        if segment == "":
            continue
        name_raw, sep, value_raw = segment.partition("=")
        try:
            name = urllib.parse.unquote_plus(name_raw, encoding="utf-8", errors="strict")
            value = urllib.parse.unquote_plus(value_raw, encoding="utf-8", errors="strict") if sep else ""
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("malformed percent escape in form body") from exc
        if not name:
            raise ValueError("empty form field name")
        for decoded in (name, value):
            if "\x00" in decoded or any(ord(c) < 0x20 and c != "\t" for c in decoded):
                raise ValueError("control character in form body")
        pairs.append((name, value))
    return pairs


@dataclass
class MultipartPart:
    """One part of a ``multipart/form-data`` body."""

    name: str
    filename: str | None
    content_type: str
    data: bytes


def _parse_content_disposition(value: str) -> dict[str, str]:
    params: dict[str, str] = {}
    for segment in value.split(";"):
        segment = segment.strip()
        if "=" not in segment:
            continue
        key, _, val = segment.partition("=")
        val = val.strip()
        if len(val) >= 2 and val.startswith('"') and val.endswith('"'):
            val = val[1:-1].replace('\\"', '"').replace("\\\\", "\\")
        params[key.strip().lower()] = val
    return params


def parse_multipart_body(raw: bytes, content_type: str) -> list[MultipartPart]:
    """Parse ``multipart/form-data`` strictly (f06 F-10b).

    Requires a boundary, a closing delimiter, CRLF part framing, and
    a ``Content-Disposition`` with a field name on every part. A
    malformed body is a deny, not a best-effort parse: a parser that
    guesses at framing is exactly how a body action smuggles past
    the engine while the provider reads something else. Raises
    ValueError on any violation.
    """
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
    if not raw.startswith(delimiter):
        raise ValueError("multipart body does not start with its boundary")
    chunks = raw.split(delimiter)
    parts: list[MultipartPart] = []
    closed = False
    for chunk in chunks[1:]:
        if chunk.startswith(b"--"):
            # Closing delimiter: nothing but optional whitespace may follow.
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
        disposition = _parse_content_disposition(headers.get("content-disposition", ""))
        name = disposition.get("name")
        if not name:
            raise ValueError("multipart part without a field name")
        parts.append(MultipartPart(
            name=name,
            filename=disposition.get("filename"),
            content_type=headers.get("content-type", "text/plain"),
            data=data,
        ))
    if not closed:
        raise ValueError("multipart body without a closing delimiter")
    return parts


# ------------------------------------------------------------------- packs

@dataclass
class EndpointRule:
    method: str
    path_pattern: str
    capability: str  # read_public | read_account | write | destructive | financial
    level: int
    spend: bool = False
    body_schema: str | None = None
    # Cap-conditioned: the rule's effective decision can change when a
    # shared counter moves (spend/request cap, rate cap). Such rules
    # are NEVER decision-cached (f06 F-16, option b): the 60 s cache
    # must not serve a stale ALLOW past cap exhaustion in another
    # session sharing the same key/provider/day counter.
    cap_conditioned: bool = False
    # Multipart bodies are denied for body-constrained endpoints
    # unless the pack explicitly allows them (f06 F-10b). A pack that
    # allows multipart must still declare the body schema the parts
    # are checked against.
    multipart_allowed: bool = False
    # Accepted request content types for this endpoint (base types,
    # e.g. "application/json"). None = no content-type gate (the
    # legacy shipped packs leave this unset); when set, any other
    # content type denies (f06 F-10c).
    content_types: tuple[str, ...] | None = None

    def matches(self, method: str, canonical_path: str) -> bool:
        return self.method.upper() == method.upper() and match_pattern(
            self.path_pattern, canonical_path
        )


@dataclass
class ProviderPack:
    name: str
    version: str
    endpoints: list[EndpointRule]
    read_like_posts: list[EndpointRule] = field(default_factory=list)
    body_schemas: dict = field(default_factory=dict)
    issued_at: str | None = None  # ISO-8601 date, e.g. "2026-10-28"
    max_age_days: int = 90
    spend_alerts_estimated: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict, repr=False)

    def find(self, method: str, canonical_path: str) -> EndpointRule | None:
        """First matching endpoint rule, or None (caller denies)."""
        for rule in self.endpoints:
            if rule.matches(method, canonical_path):
                return rule
        return None

    def is_read_like_post(self, method: str, canonical_path: str) -> bool:
        return any(r.matches(method, canonical_path) for r in self.read_like_posts)

    def is_stale(self, now: float | None = None) -> bool:
        """True when the pack is older than ``max_age_days``.

        A pack without ``issued_at`` is treated as stale (fail closed):
        staleness cannot be proven, so it must not be assumed fresh.
        """
        if not self.issued_at:
            return True
        try:
            import datetime

            issued = datetime.date.fromisoformat(self.issued_at)
            today = (
                datetime.datetime.fromtimestamp(now, tz=datetime.timezone.utc).date()
                if now is not None
                else datetime.datetime.now(datetime.timezone.utc).date()
            )
        except ValueError:
            return True
        return (today - issued).days > self.max_age_days


# -------------------------------------------------------------------- cache

class DecisionCache:
    """ALLOW-only (level 1), 60 s cache.

    Refusals, approvals and log-gated decisions are never cached, and
    the engine never stores a spend-flagged (cap-conditioned) decision.
    Entries expire strictly after ``CACHE_TTL_SECONDS``.
    """

    def __init__(self, ttl_seconds: float = CACHE_TTL_SECONDS, clock=time.monotonic):
        self._ttl = ttl_seconds
        self._clock = clock
        self._entries: dict[tuple, tuple[float, PolicyDecision]] = {}

    def get(self, key: tuple) -> PolicyDecision | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        stored_at, decision = entry
        if self._clock() - stored_at > self._ttl:
            del self._entries[key]
            return None
        return decision

    def put(self, key: tuple, decision: PolicyDecision, *, spend: bool,
            cap_conditioned: bool = False) -> None:
        """Store only level-1, non-spend, non-cap-conditioned decisions.

        Cap-conditioned rules are never cached (f06 F-16): a cached
        ALLOW must never survive cap exhaustion in another session
        sharing the same counter. Silently ignores the rest.
        """
        if decision.level != LEVEL_ALLOW or not decision.allowed:
            return
        if spend or cap_conditioned:
            return
        self._entries[key] = (self._clock(), decision)

    def note_counter_change(self) -> None:
        """Invalidate the whole cache when any shared counter moves.

        Cross-session invalidation is deliberately coarse: shared
        key/provider/day counters are owned outside this cache, so
        the only safe invalidation on a counter change the engine
        learns about is to drop every entry (f06 F-16). Entries are
        cheap to recompute (sub-10 ms evaluation).
        """
        self._entries.clear()

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


# ------------------------------------------------------------------ engine

class PolicyEngine:
    """Decides one proxied request against one provider pack."""

    def __init__(self, pack: ProviderPack, cache: DecisionCache | None = None):
        self.pack = pack
        self.cache = cache if cache is not None else DecisionCache()
        self._cap_epoch = 0

    def note_cap_change(self) -> None:
        """Invalidate cached decisions when any cap counter moves.

        Bumps the cache-key epoch AND clears the cache (f06 F-16):
        a decision cached before a cap change must never be served
        after it, even to a different session sharing the counter.
        """
        self._cap_epoch += 1
        self.cache.note_counter_change()

    # -- public entry point ------------------------------------------------
    def decide(
        self,
        method: str,
        raw_path: str,
        session_class: str,
        *,
        body: object = None,
        body_raw: bytes | str | None = None,
        allowed_file_uris: frozenset | None = None,
        now: float | None = None,
        content_type: str | None = None,
    ) -> PolicyDecision:
        """Decide a request. Unmodelled endpoint = deny, always.

        ``body`` (already parsed) or ``body_raw`` (parsed here with
        duplicate-key rejection) is checked against the endpoint's body
        schema when one is declared. ``allowed_file_uris`` is the
        session's creation ledger: a ``fileData.fileUri`` reference in
        an otherwise-allowed call is denied unless its URI is in the
        ledger (CONTRACT section 7, Gemini). Pass an empty set (the
        default) and every such reference is denied.
        """
        try:
            path = canonicalise_path(raw_path)
        except CanonicalisationError as exc:
            return PolicyDecision(False, LEVEL_DENY, f"path rejected: {exc}", "canonicalisation")

        rule = self.pack.find(method, path)
        if rule is None:
            return PolicyDecision(False, LEVEL_DENY, "endpoint not modelled in pack", "unmodelled")

        if session_class not in _SESSION_CLASS_RANK:
            return PolicyDecision(False, LEVEL_DENY, "unknown session class", "session_class")
        if rule.capability not in _CAPABILITY_RANK:
            return PolicyDecision(False, LEVEL_DENY, "unknown capability in pack", "pack_capability")

        # Capability check: highest wins; a session may only perform
        # capabilities at or below its class. Financial is never
        # satisfied by any v0.1 session class.
        if rule.capability == "financial" or (
            _CAPABILITY_RANK[rule.capability] > _SESSION_CLASS_RANK[session_class]
        ):
            return PolicyDecision(
                False, LEVEL_DENY, "capability exceeds session class", "capability"
            )

        # Read-like POST exemption is informational here: the pack
        # already declares the read capability for such endpoints, and
        # this check records that the POST method alone must not
        # upgrade the call to write class (v3 N-B6).
        _ = self.pack.is_read_like_post(method, path)

        # Content-type gate (f06 F-10c): a pack that declares accepted
        # types denies everything else rather than hash-only handling.
        base_ct = (content_type or "").split(";")[0].strip().lower()
        if rule.content_types is not None and base_ct not in {
                c.lower() for c in rule.content_types}:
            return PolicyDecision(False, LEVEL_DENY, "content type not accepted for endpoint", "content_type")

        # GraphQL endpoints are classified by document, not just by
        # path (f06 F-04/F-08/F-09): batch totals, alias counts, and
        # per-element denials are decided here, before body schemas.
        # A pack-level deny (level 4, e.g. GitHub's /graphql) still
        # wins over a classifier approval -- the classifier can only
        # deny harder or approve up to the pack's level.
        if path.endswith("/graphql"):
            gql_decision = self._check_graphql(rule, body, body_raw, session_class, now)
            if gql_decision is not None:
                return gql_decision

        # Body checks (duplicate keys, schema, ledger references,
        # form/multipart parsing).
        body_decision = self._check_body(
            rule, body, body_raw, allowed_file_uris or frozenset(), content_type)
        if body_decision is not None:
            return body_decision

        # Cache lookup: level-1 only, never for spend, approval, or
        # cap-conditioned rules. The key carries the cap epoch so a
        # counter change retires entries even without an explicit
        # clear (f06 F-16).
        cache_key = (method.upper(), path, session_class, self.pack.version, self._cap_epoch)
        if rule.level == LEVEL_ALLOW and not rule.spend and not rule.cap_conditioned:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached

        level = rule.level
        reason = f"pack rule {rule.method} {rule.path_pattern} ({rule.capability})"
        rule_id = f"{self.pack.name}:{rule.method}:{rule.path_pattern}"

        # Stale-pack handling: refusal for destructive / financial /
        # metered endpoints and destructive sessions; +1 level otherwise.
        if self.pack.is_stale(now):
            if (
                rule.capability in ("destructive", "financial")
                or rule.spend
                or session_class == "destructive"
            ):
                return PolicyDecision(
                    False, LEVEL_DENY, "stale pack: refusal for destructive/metered request", "stale_pack"
                )
            level = min(level + 1, LEVEL_DENY)
            reason += " [stale pack: level escalated]"
            rule_id = "stale_pack"

        if level == LEVEL_ALLOW:
            decision = PolicyDecision(True, LEVEL_ALLOW, reason, rule_id)
        elif level == LEVEL_ALLOW_WITH_LOG:
            decision = PolicyDecision(True, LEVEL_ALLOW_WITH_LOG, reason, rule_id)
        elif level == LEVEL_APPROVE:
            decision = PolicyDecision(False, LEVEL_APPROVE, "approval required: " + reason, rule_id)
        else:
            decision = PolicyDecision(False, LEVEL_DENY, reason, rule_id)

        self.cache.put(cache_key, decision, spend=rule.spend,
                       cap_conditioned=rule.cap_conditioned)
        return decision

    # -- GraphQL ------------------------------------------------------------
    def _check_graphql(self, rule, body, body_raw, session_class, now=None):
        """Classify a GraphQL request body. Returns a decision, or None
        to fall through to the pack decision (query-only bodies on a
        pack that allows the endpoint)."""
        parsed = body
        if parsed is None and body_raw is not None:
            try:
                parsed = parse_json_no_duplicates(body_raw)
            except (DuplicateKeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                return PolicyDecision(False, LEVEL_DENY, f"body rejected: {exc}", "body_parse")
        if parsed is None:
            return PolicyDecision(False, LEVEL_DENY, "empty GraphQL document", "graphql_empty")
        batch = evaluate_graphql_batch(parsed, session_class=session_class)
        if batch.level == LEVEL_DENY:
            return batch
        if batch.level == LEVEL_APPROVE:
            if rule.level == LEVEL_DENY:
                return PolicyDecision(False, LEVEL_DENY, "endpoint denied by pack", "pack_rule")
            # Stale-pack refusal must not be bypassed by returning
            # early here: a mutation on a stale pack for a
            # destructive/metered session or endpoint is refused,
            # exactly as the main stale path below refuses it.
            if self.pack.is_stale(now) and (
                rule.capability in ("destructive", "financial")
                or rule.spend
                or rule.cap_conditioned
                or session_class == "destructive"
            ):
                return PolicyDecision(
                    False, LEVEL_DENY, "stale pack: refusal for destructive/metered request", "stale_pack"
                )
            return batch
        return None

    # -- body checks --------------------------------------------------------
    def _apply_schema(self, rule, field_names, body_text, body, allowed_file_uris):
        """Apply a body schema to already-parsed fields. Returns a deny
        decision or None. ``field_names`` is the set of top-level
        field names; ``body_text`` is the searchable text form."""
        schema = self.pack.body_schemas.get(rule.body_schema) if rule.body_schema else None
        if schema is None:
            return None
        # field_names=None (a non-object body) skips key checks but
        # still runs substring and ledger checks below.
        if field_names is not None:
            for required_key in schema.get("required", []):
                if required_key not in field_names:
                    return PolicyDecision(
                        False, LEVEL_DENY, f"body missing required key: {required_key}", "body_schema"
                    )
            for forbidden_key in schema.get("forbidden", []):
                if forbidden_key in field_names:
                    return PolicyDecision(
                        False, LEVEL_DENY, f"body contains forbidden key: {forbidden_key}", "body_schema"
                    )
        for substring in schema.get("forbidden_substrings", []):
            if substring in body_text:
                return PolicyDecision(
                    False, LEVEL_DENY, "body contains forbidden content", "body_schema"
                )
        # fileData.fileUri ledger check (Gemini, CONTRACT section 7).
        for uri in _find_file_uris(body):
            if uri not in allowed_file_uris:
                return PolicyDecision(
                    False, LEVEL_DENY, "referenced file object not in session creation ledger", "ledger"
                )
        return None

    def _check_body(self, rule, body, body_raw, allowed_file_uris, content_type=None):
        base_ct = (content_type or "").split(";")[0].strip().lower()
        # Form bodies: parsed like JSON (field-value machinery, f06
        # F-10a) -- required/forbidden/substring checks run over ALL
        # values of every field, never just the first.
        if base_ct == "application/x-www-form-urlencoded":
            if body_raw is None:
                return PolicyDecision(False, LEVEL_DENY, "form body missing", "body_parse")
            try:
                pairs = parse_form_body(body_raw)
            except ValueError as exc:
                return PolicyDecision(False, LEVEL_DENY, f"body rejected: {exc}", "body_parse")
            for name, _value in pairs:
                if name.lower() in _CREDENTIAL_FIELD_NAMES:
                    return PolicyDecision(False, LEVEL_DENY, "credential field in form body", "body_parse")
            field_names = {name for name, _ in pairs}
            body_text = "&".join(f"{name}={value}" for name, value in pairs)
            return self._apply_schema(rule, field_names, body_text, dict(pairs), allowed_file_uris)
        # Multipart bodies: body-constrained endpoints deny outright
        # unless the pack declares multipart (f06 F-10b); otherwise
        # parts are parsed, credential fields denied, and JSON parts
        # get the same duplicate-key rejection as JSON bodies.
        if base_ct == "multipart/form-data":
            if body_raw is None or not isinstance(body_raw, (bytes, str)):
                return PolicyDecision(False, LEVEL_DENY, "multipart body missing", "body_parse")
            raw_bytes = body_raw if isinstance(body_raw, bytes) else body_raw.encode("utf-8")
            if rule.body_schema is not None and not rule.multipart_allowed:
                return PolicyDecision(False, LEVEL_DENY, "multipart body not declared for body-constrained endpoint", "body_parse")
            try:
                parts = parse_multipart_body(raw_bytes, content_type or base_ct)
            except ValueError as exc:
                return PolicyDecision(False, LEVEL_DENY, f"body rejected: {exc}", "body_parse")
            field_names = set()
            texts: list[str] = []
            for part in parts:
                field_names.add(part.name)
                if part.name.lower() in _CREDENTIAL_FIELD_NAMES:
                    return PolicyDecision(False, LEVEL_DENY, "credential field in multipart body", "body_parse")
                part_ct = part.content_type.split(";")[0].strip().lower()
                if part_ct.endswith("json") or part_ct == "application/json":
                    try:
                        parse_json_no_duplicates(part.data)
                    except (DuplicateKeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                        return PolicyDecision(False, LEVEL_DENY, f"body rejected: {exc}", "body_parse")
                try:
                    texts.append(part.data.decode("utf-8"))
                except UnicodeDecodeError:
                    pass
            return self._apply_schema(rule, field_names, "\n".join(texts), {}, allowed_file_uris)
        # JSON (or content-type-less) bodies: duplicate keys at any
        # depth are a deny (f06 F-11). A declared non-JSON content
        # type that is neither form nor multipart (e.g. text/plain,
        # octet-stream) is length-checked upstream and carries no
        # parsed constraints -- it must not be JSON-parsed here, or
        # the provider's own content-type dispatch would diverge.
        if base_ct and not (base_ct.endswith("json") or base_ct == "application/json"):
            return None
        if body_raw is not None:
            try:
                body = parse_json_no_duplicates(body_raw)
            except (DuplicateKeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                return PolicyDecision(False, LEVEL_DENY, f"body rejected: {exc}", "body_parse")
        if body is None:
            return None
        if isinstance(body, dict):
            field_names = set(body.keys())
        else:
            field_names = None
        body_text = json.dumps(body, sort_keys=True, default=str)
        return self._apply_schema(rule, field_names, body_text, body, allowed_file_uris)


def _find_file_uris(node: object) -> list[str]:
    """Collect every ``fileData.fileUri`` value in a parsed body."""
    found: list[str] = []
    if isinstance(node, dict):
        file_data = node.get("fileData")
        if isinstance(file_data, dict) and isinstance(file_data.get("fileUri"), str):
            found.append(file_data["fileUri"])
        for value in node.values():
            found.extend(_find_file_uris(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_find_file_uris(item))
    return found


# ------------------------------------------------------------- spend caps

@dataclass
class SpendCap:
    """An estimated spend limiter. Estimates only, never exact claims.

    ``cap_estimate`` is the alert threshold in the pack's currency
    units. Crossing it denies further metered calls until the window
    resets; user-facing copy must use :func:`spend_alert_copy`.
    """

    cap_estimate: float
    spent_estimate: float = 0.0

    def record(self, amount_estimate: float) -> PolicyDecision | None:
        """Record an estimated charge; deny (and do not record past the
        cap) once the cap would be exceeded. Returns a deny decision or
        None when the charge fits."""
        if self.spent_estimate + amount_estimate > self.cap_estimate:
            return PolicyDecision(
                False,
                LEVEL_DENY,
                spend_alert_copy("estimated spend cap reached"),
                "spend_cap",
            )
        self.spent_estimate += amount_estimate
        return None

    @staticmethod
    def estimate_error_pauses(estimated: float, actual: float) -> bool:
        """True when cumulative estimate error exceeds 20% (v3 N-G10):
        spend tracking pauses (fail closed) until reconciled."""
        if actual == 0:
            return estimated != 0
        return abs(estimated - actual) / abs(actual) > SPEND_ESTIMATE_ERROR_PAUSE_THRESHOLD


# ------------------------------------------------------- spend ledger
# (f06 F-15.1: per-key caps alone do not survive key-splitting -- a
# second key doubles the budget. A ledger shared across sessions
# aggregates session, key, provider, and UTC-day scopes, and denies
# when ANY scope would be exceeded. All amounts are ESTIMATES and
# every user-facing string says so via spend_alert_copy.)

@dataclass
class SpendLedger:
    """Multi-scope estimated spend ledger.

    ``caps`` maps a scope name to its estimated cap, e.g.
    ``{"provider:gemini": 10.0, "key:key-abc": 5.0}``. A scope with
    no cap entry is untracked (unlimited for that scope only -- the
    caller must still pass the scopes it wants enforced). ``record``
    is atomic across scopes: if any scope would exceed its cap,
    nothing is recorded and a deny decision is returned. ``version``
    increments on every successful record so decision caches keyed
    on it retire stale ALLOWs (f06 F-16).
    """

    caps: dict[str, float] = field(default_factory=dict)
    spent: dict[str, float] = field(default_factory=dict, init=False)
    version: int = field(default=0, init=False)

    @staticmethod
    def day_scope(provider: str, now: float | None = None) -> str:
        """UTC-day scope for a provider (f06 F-31: cap arithmetic
        uses UTC internally; local time is display only, so DST
        never extends or shortens a day cap)."""
        import datetime

        day = (
            datetime.datetime.fromtimestamp(now, tz=datetime.timezone.utc).date()
            if now is not None
            else datetime.datetime.now(datetime.timezone.utc).date()
        )
        return f"day:{provider}:{day.isoformat()}"

    def spent_for(self, scope: str) -> float:
        return self.spent.get(scope, 0.0)

    def record(self, scopes: list[str], amount_estimate: float) -> PolicyDecision | None:
        """Record an estimated charge against every scope, or deny.

        Returns a deny decision (labelled estimated) when any capped
        scope would be exceeded; in that case no scope is charged.
        Returns None when the charge fits and is recorded.
        """
        for scope in scopes:
            cap = self.caps.get(scope)
            if cap is not None and self.spent.get(scope, 0.0) + amount_estimate > cap:
                return PolicyDecision(
                    False,
                    LEVEL_DENY,
                    spend_alert_copy(f"estimated spend cap reached for {scope}"),
                    "spend_cap",
                )
        for scope in scopes:
            self.spent[scope] = self.spent.get(scope, 0.0) + amount_estimate
        self.version += 1
        return None


# ------------------------------------------------ streaming token accounting
# (f06 F-15.2: a streaming call must not generate unbounded output
# while the cap is only reconciled after the stream ends. Usage
# deltas are parsed DURING the stream and the stream aborts mid-
# flight on a cap hit. Provider usage reports are CUMULATIVE per
# stream (Gemini usageMetadata semantics, also f08): totals are the
# latest reported values, never the sum of chunks -- summing would
# over-count and false-deny. When a stream reports no usage at all,
# tokens are estimated conservatively from bytes (4 chars/token)
# so an unmetered stream still has a bound. Everything here is an
# ESTIMATE and every deny reason says so.)

class StreamingTokenAccount:
    """Per-stream estimated token/spend accounting.

    Feed raw response chunks (SSE ``data:`` lines or bare JSON
    lines) to :meth:`observe`; it returns a deny decision the moment
    an estimated token or spend cap is exceeded, and None otherwise.
    The proxy aborts the relay on a deny, so no further bytes reach
    the agent. Call :meth:`finish` at stream end for the totals.
    """

    def __init__(
        self,
        *,
        token_cap_estimate: int | None = None,
        spend_cap_estimate: float | None = None,
        price_per_1k_input_estimate: float = 0.0,
        price_per_1k_output_estimate: float = 0.0,
        byte_budget: int | None = None,
    ):
        self.token_cap_estimate = token_cap_estimate
        self.spend_cap_estimate = spend_cap_estimate
        self.price_per_1k_input_estimate = price_per_1k_input_estimate
        self.price_per_1k_output_estimate = price_per_1k_output_estimate
        self.byte_budget = byte_budget
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.bytes_seen = 0
        self.chunks_seen = 0
        self.saw_usage = False

    @property
    def estimated_tokens(self) -> int:
        if self.saw_usage:
            return self.prompt_tokens + self.completion_tokens
        return self.bytes_seen // 4

    @property
    def estimated_spend(self) -> float:
        return (
            self.prompt_tokens / 1000.0 * self.price_per_1k_input_estimate
            + self.completion_tokens / 1000.0 * self.price_per_1k_output_estimate
        )

    def _ingest_payload(self, payload: object) -> None:
        if not isinstance(payload, dict):
            return
        usage = payload.get("usageMetadata") or payload.get("usage")
        if not isinstance(usage, dict):
            # Gemini nests usageMetadata inside candidates' chunks in
            # some shapes; also accept a bare usageMetadata dict.
            return
        prompt = usage.get("promptTokenCount", usage.get("prompt_tokens"))
        completion = usage.get(
            "candidatesTokenCount",
            usage.get("completion_tokens", usage.get("candidates_token_count")),
        )
        thinking = usage.get("thoughtsTokenCount", usage.get("thinking_tokens", 0))
        try:
            if prompt is not None:
                self.prompt_tokens = max(self.prompt_tokens, int(prompt or 0))
            if completion is not None or thinking:
                self.completion_tokens = max(
                    self.completion_tokens,
                    int(completion or 0) + int(thinking or 0),
                )
            self.saw_usage = True
        except (TypeError, ValueError):
            pass

    def observe(self, chunk: bytes) -> PolicyDecision | None:
        """Account one raw response chunk; deny on cap hit."""
        self.chunks_seen += 1
        self.bytes_seen += len(chunk)
        if self.byte_budget is not None and self.bytes_seen > self.byte_budget:
            return PolicyDecision(False, LEVEL_DENY, "stream byte budget exceeded", "stream_budget")
        try:
            text = chunk.decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                line = line[len("data:"):].strip()
            if line == "[DONE]" or not line.startswith("{"):
                continue
            try:
                self._ingest_payload(json.loads(line))
            except ValueError:
                continue
        if self.token_cap_estimate is not None and self.estimated_tokens > self.token_cap_estimate:
            return PolicyDecision(
                False, LEVEL_DENY,
                spend_alert_copy(f"estimated stream tokens ({self.estimated_tokens}) exceed estimated cap ({self.token_cap_estimate})"),
                "spend_cap",
            )
        if self.spend_cap_estimate is not None and self.estimated_spend > self.spend_cap_estimate:
            return PolicyDecision(
                False, LEVEL_DENY,
                spend_alert_copy(f"estimated stream spend ({self.estimated_spend:.4f}) exceeds estimated cap ({self.spend_cap_estimate})"),
                "spend_cap",
            )
        return None

    def finish(self) -> dict:
        """Stream totals. All values are estimates -- see class doc."""
        return {
            "prompt_tokens_estimate": self.prompt_tokens,
            "completion_tokens_estimate": self.completion_tokens,
            "tokens_estimate": self.estimated_tokens,
            "spend_estimate": self.estimated_spend,
            "bytes_seen": self.bytes_seen,
            "chunks_seen": self.chunks_seen,
            "saw_usage": self.saw_usage,
        }


# ----------------------------------------------------------------- GraphQL

_GRAPHQL_KEYWORD = re.compile(r"\b(mutation|query|subscription)\b")
_DIRECTIVE_DENY = ("@defer", "@stream")
_INTROSPECTION_DENY = "__schema"


def _strip_graphql_strings_and_comments(document: str) -> str:
    """Remove GraphQL string literals, block strings and comments so
    keyword counting cannot be fooled by words inside string values."""
    out: list[str] = []
    i = 0
    n = len(document)
    while i < n:
        ch = document[i]
        if ch == "#":
            while i < n and document[i] != "\n":
                i += 1
        elif document.startswith('"""', i):
            end = document.find('"""', i + 3)
            i = n if end == -1 else end + 3
            out.append(" ")
        elif ch == '"':
            i += 1
            while i < n and document[i] != '"':
                if document[i] == "\\":
                    i += 1
                i += 1
            i += 1
            out.append(" ")
        else:
            out.append(ch)
            i += 1
    return "".join(out)


# Fragment-expansion guards (f06 F-08): a small document can expand
# combinatorially through repeated spreads, so counting is bounded
# by a step budget (loop iterations, counting whitespace skips too --
# a mutation body needing more steps than this is flooding, not a
# legitimate request, and saturates to a denying count).
_GRAPHQL_EXPANSION_MAX_DEPTH = 32
_GRAPHQL_EXPANSION_MAX_NODES = 10000


def _extract_braced(text: str, open_idx: int) -> tuple[str, int]:
    """Return (body, index just past the matching close brace)."""
    depth = 0
    i = open_idx
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : i], i + 1
        i += 1
    raise ValueError("unbalanced braces in GraphQL document")


def _scan_operation_body(text: str, start: int) -> tuple[str, int]:
    """From just after an operation keyword, find the body block.

    Variable definitions (``(...)``) may contain default object
    values with braces; braces inside parentheses are not the body
    opener. Raises ValueError when no body block follows.
    """
    paren = 0
    i = start
    while i < len(text):
        ch = text[i]
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
        elif ch == "{" and paren == 0:
            return _extract_braced(text, i)
        i += 1
    raise ValueError("GraphQL operation without a body block")


def _parse_graphql_document(stripped: str) -> tuple[dict[str, str], list[str]]:
    """Parse top-level operations of a stripped document.

    Returns (fragment definitions by name, mutation operation bodies
    in order). Keywords inside nested selection sets are never
    mistaken for operations: scanning only matches keywords at brace
    depth 0. Fragment definitions are recorded, not counted.
    """
    fragments: dict[str, str] = {}
    mutations: list[str] = []
    depth = 0
    i = 0
    n = len(stripped)
    while i < n:
        ch = stripped[i]
        if ch == "{":
            depth += 1
            i += 1
            continue
        if ch == "}":
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth != 0:
            i += 1
            continue
        match = re.match(r"(mutation|query|subscription|fragment)\b", stripped[i:])
        if not match:
            i += 1
            continue
        kind = match.group(1)
        j = i + match.end()
        if kind == "fragment":
            name_match = re.match(r"\s+(\w+)", stripped[j:])
            if not name_match:
                i = j
                continue
            j += name_match.end()
            try:
                body, end = _scan_operation_body(stripped, j)
            except ValueError:
                i = j
                continue
            fragments[name_match.group(1)] = body
            i = end
            continue
        try:
            body, end = _scan_operation_body(stripped, j)
        except ValueError:
            i = j
            continue
        if kind == "mutation":
            mutations.append(body)
        i = end
    return fragments, mutations


def _count_fields_in_body(body: str, fragments: dict[str, str],
                          active: frozenset, depth: int,
                          budget: list[int]) -> int:
    """Count root fields of one selection set, expanding spreads.

    Each aliased field counts separately (f06 F-04: fifty aliased
    copies of one mutation are fifty effects, not one). Nested
    selection sets are skipped, not counted: only the root fields of
    a mutation operation are effects. ``__``-prefixed fields
    (``__typename``) are not effects and are not counted. A spread
    cycle is guarded by ``active`` (the cycle itself is denied by
    :func:`evaluate_graphql_document`); expansion beyond the node
    budget saturates the count so the approval cap denies.
    """
    if depth > _GRAPHQL_EXPANSION_MAX_DEPTH:
        return _GRAPHQL_EXPANSION_MAX_NODES + 1
    count = 0
    i = 0
    n = len(body)
    while i < n:
        if budget[0] <= 0:
            return _GRAPHQL_EXPANSION_MAX_NODES + 1
        budget[0] -= 1
        ch = body[i]
        if ch.isspace() or ch == ",":
            i += 1
            continue
        if body.startswith("...", i):
            spread = re.match(r"\.\.\.\s*(\w+)", body[i:])
            if not spread:
                i += 3
                continue
            name = spread.group(1)
            i += spread.end()
            if name in fragments and name not in active:
                count += _count_fields_in_body(
                    fragments[name], fragments, active | {name},
                    depth + 1, budget)
            continue
        name_match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", body[i:])
        if not name_match:
            i += 1
            continue
        field = name_match.group(0)
        i += name_match.end()
        # Alias: ``alias: field`` -- the field after the colon is the
        # effect; the alias itself is just a response label.
        j = i
        while j < n and body[j].isspace():
            j += 1
        if j < n and body[j] == ":":
            j += 1
            while j < n and body[j].isspace():
                j += 1
            aliased = re.match(r"[A-Za-z_][A-Za-z0-9_]*", body[j:])
            if aliased:
                field = aliased.group(0)
                i = j + aliased.end()
        # Skip arguments, directives, and any nested selection set.
        while True:
            while i < n and body[i].isspace():
                i += 1
            if i < n and body[i] == "(":
                # Balanced-paren skip (braces are not parens).
                paren = 0
                while i < n:
                    if body[i] == "(":
                        paren += 1
                    elif body[i] == ")":
                        paren -= 1
                        if paren == 0:
                            i += 1
                            break
                    i += 1
                continue
            if i < n and body[i] == "@":
                directive = re.match(r"@[A-Za-z_][A-Za-z0-9_]*", body[i:])
                i += directive.end() if directive else 1
                continue
            break
        if i < n and body[i] == "{":
            try:
                _, i = _extract_braced(body, i)
            except ValueError:
                i = n
        if not field.startswith("__"):
            count += 1
    return count


def count_mutations(document: str) -> int:
    """Count mutation EFFECTS (fields) in one GraphQL document.

    This counts aliased root fields of mutation operations, not
    operations and not requests (f06 F-04): ``mutation { a1: del
    a2: del }`` is 2, and a fragment spread expanding to three
    mutation fields is 3. Anonymous shorthand (``{ ... }``) is a
    query, not a mutation, so it is not counted. ``mutation`` inside
    strings/comments is not counted. Fragment definitions are not
    operations and are not counted (their spreads are, when used
    inside a mutation). Expansion beyond the step budget saturates
    at ``_GRAPHQL_EXPANSION_MAX_NODES + 1`` so any approval cap
    denies rather than under-counts.
    """
    if not isinstance(document, str):
        return 0
    stripped = _strip_graphql_strings_and_comments(document)
    try:
        fragments, mutations = _parse_graphql_document(stripped)
    except ValueError:
        return 0
    total = 0
    for body in mutations:
        budget = [_GRAPHQL_EXPANSION_MAX_NODES]
        total += _count_fields_in_body(body, fragments, frozenset(), 0, budget)
        if total > _GRAPHQL_EXPANSION_MAX_NODES:
            return _GRAPHQL_EXPANSION_MAX_NODES + 1
    return total


def _has_fragment_cycle(document: str) -> bool:
    """Detect a fragment-spread cycle (``...A`` inside ``fragment A``).

    Conservative: builds the spread graph from ``fragment X on ...``
    definitions and reports any cycle reachable in that graph.
    """
    stripped = _strip_graphql_strings_and_comments(document)
    graph: dict[str, set[str]] = {}
    for match in re.finditer(r"\bfragment\s+(\w+)\s+on\s+\w+\s*\{", stripped):
        name = match.group(1)
        depth = 1
        i = match.end()
        while i < len(stripped) and depth > 0:
            if stripped[i] == "{":
                depth += 1
            elif stripped[i] == "}":
                depth -= 1
            i += 1
        body = stripped[match.end() : i - 1]
        graph[name] = set(re.findall(r"\.\.\.(\w+)", body))
    visited: set[str] = set()

    def _reaches(node: str, stack: set[str]) -> bool:
        if node in stack:
            return True
        if node in visited or node not in graph:
            return False
        stack.add(node)
        result = any(_reaches(nxt, stack) for nxt in graph[node])
        stack.discard(node)
        visited.add(node)
        return result

    return any(_reaches(name, set()) for name in graph)


def evaluate_graphql_document(
    document: str,
    *,
    max_mutations_per_approval: int = DEFAULT_MUTATIONS_PER_APPROVAL,
    session_class: str = "read_public",
) -> PolicyDecision:
    """Evaluate ONE GraphQL document (v3 N-G6).

    Denied: subscriptions, ``@defer``/``@stream``, ``__schema``
    introspection, fragment cycles, and any mutation count above the
    per-approval cap. ``__typename`` is an accepted residual (recorded
    here, not denied). A document with no mutations is a query: it is
    allowed only at level 1 when the session class permits reads, and
    the caller (proxy) must still route it through the pack decision
    for the GraphQL endpoint itself -- this function classifies the
    document, it does not authorise the endpoint. GitHub's pack denies
    its GraphQL endpoint outright (CONTRACT section 7), so for GitHub
    this function is a defence-in-depth classifier, not an allow path.
    """
    if not isinstance(document, str) or not document.strip():
        return PolicyDecision(False, LEVEL_DENY, "empty GraphQL document", "graphql_empty")
    stripped = _strip_graphql_strings_and_comments(document)
    if re.search(r"\bsubscription\b", stripped):
        return PolicyDecision(False, LEVEL_DENY, "GraphQL subscriptions denied", "graphql_subscription")
    if any(d in stripped for d in _DIRECTIVE_DENY):
        return PolicyDecision(False, LEVEL_DENY, "GraphQL defer/stream denied", "graphql_directive")
    if _INTROSPECTION_DENY in stripped:
        return PolicyDecision(False, LEVEL_DENY, "GraphQL introspection denied", "graphql_introspection")
    if _has_fragment_cycle(document):
        return PolicyDecision(False, LEVEL_DENY, "GraphQL fragment cycle denied", "graphql_cycle")
    mutations = count_mutations(document)
    if mutations > max_mutations_per_approval:
        return PolicyDecision(
            False,
            LEVEL_DENY,
            f"GraphQL mutation fields ({mutations}) exceed per-approval cap ({max_mutations_per_approval})",
            "graphql_mutation_cap",
        )
    if mutations > 0:
        # A mutation is a write at minimum; a read-only session cannot
        # carry one, and any mutation needs broker approval.
        if _SESSION_CLASS_RANK.get(session_class, 0) < _SESSION_CLASS_RANK["write"]:
            return PolicyDecision(False, LEVEL_DENY, "GraphQL mutation exceeds session class", "graphql_capability")
        return PolicyDecision(False, LEVEL_APPROVE, "GraphQL mutation requires approval", "graphql_mutation")
    return PolicyDecision(True, LEVEL_ALLOW, "GraphQL query document (no mutations)", "graphql_query")


def evaluate_graphql_body(
    body: object,
    *,
    max_mutations_per_approval: int = DEFAULT_MUTATIONS_PER_APPROVAL,
    session_class: str = "read_public",
) -> list[PolicyDecision]:
    """Evaluate a GraphQL request body as N separate requests.

    A JSON-array batch body is N separately evaluated requests
    (v3 N-G6): one decision per array element, in order. A single
    object body yields one decision. Anything else is denied.
    Variables are not resolved here -- the proxy must resolve variables
    before classification (v3 N-G6); a body whose ``query`` is not a
    string is denied rather than guessed at.
    """
    if isinstance(body, list):
        requests = body
    elif isinstance(body, dict):
        requests = [body]
    else:
        return [PolicyDecision(False, LEVEL_DENY, "GraphQL body is not an object or array", "graphql_body")]
    decisions: list[PolicyDecision] = []
    for request in requests:
        if not isinstance(request, dict) or not isinstance(request.get("query"), str):
            decisions.append(
                PolicyDecision(False, LEVEL_DENY, "GraphQL request without a string query", "graphql_body")
            )
            continue
        decisions.append(
            evaluate_graphql_document(
                request["query"],
                max_mutations_per_approval=max_mutations_per_approval,
                session_class=session_class,
            )
        )
    return decisions


def count_mutations_in_body(body: object) -> int | None:
    """Total mutation fields across a GraphQL body, or None when the
    body is not an object/array of string-query requests."""
    if isinstance(body, dict):
        requests = [body]
    elif isinstance(body, list):
        requests = body
    else:
        return None
    total = 0
    for request in requests:
        if not isinstance(request, dict) or not isinstance(request.get("query"), str):
            return None
        total += count_mutations(request["query"])
    return total


def evaluate_graphql_batch(
    body: object,
    *,
    max_mutations_per_approval: int = DEFAULT_MUTATIONS_PER_APPROVAL,
    session_class: str = "read_public",
) -> PolicyDecision:
    """One decision for a whole GraphQL batch (f06 F-04).

    A JSON-array body is N requests, but the approval cap is on
    mutation FIELDS across the whole batch, not per request: two
    single-mutation requests in one batch are two effects under one
    approval, so with the default cap of 1 the batch denies. Any
    denied element denies the whole batch (a batch with a denied
    element must never partially forward). A batch whose elements
    are all queries (or one approved mutation within cap) returns
    the corresponding single decision.
    """
    decisions = evaluate_graphql_body(
        body,
        max_mutations_per_approval=max_mutations_per_approval,
        session_class=session_class,
    )
    for decision in decisions:
        if decision.level == LEVEL_DENY:
            return decision
    total = count_mutations_in_body(body)
    if total is None:
        return PolicyDecision(False, LEVEL_DENY, "GraphQL body is not an object or array", "graphql_body")
    if total > max_mutations_per_approval:
        return PolicyDecision(
            False,
            LEVEL_DENY,
            f"GraphQL batch mutation fields ({total}) exceed per-approval cap ({max_mutations_per_approval})",
            "graphql_mutation_cap",
        )
    if any(d.level == LEVEL_APPROVE for d in decisions):
        return PolicyDecision(
            False, LEVEL_APPROVE,
            f"GraphQL mutation requires approval: {total} mutation field(s) in {len(decisions)} request(s)",
            "graphql_mutation",
        )
    return PolicyDecision(True, LEVEL_ALLOW, "GraphQL batch: queries only, no mutations", "graphql_query")


def classify_capability(capabilities: list[str]) -> str:
    """Highest-wins capability classification (v3 N-B6)."""
    if not capabilities:
        raise ValueError("no capabilities to classify")
    for cap in capabilities:
        if cap not in _CAPABILITY_RANK:
            raise ValueError(f"unknown capability: {cap!r}")
    return max(capabilities, key=lambda c: _CAPABILITY_RANK[c])


def is_paid_inference_capability(capability: str) -> bool:
    """Paid inference counts as write class (v3 N-B6), never read."""
    return capability == "write"


__all__ = [
    "LEVEL_ALLOW",
    "LEVEL_ALLOW_WITH_LOG",
    "LEVEL_APPROVE",
    "LEVEL_DENY",
    "GENERIC_DENIAL",
    "SPEND_ALERT_LABEL",
    "CACHE_TTL_SECONDS",
    "DEFAULT_MUTATIONS_PER_APPROVAL",
    "SPEND_ESTIMATE_ERROR_PAUSE_THRESHOLD",
    "PolicyDecision",
    "CanonicalisationError",
    "DuplicateKeyError",
    "EndpointRule",
    "ProviderPack",
    "DecisionCache",
    "PolicyEngine",
    "SpendCap",
    "SpendLedger",
    "StreamingTokenAccount",
    "MultipartPart",
    "parse_form_body",
    "parse_multipart_body",
    "parse_query_split_first",
    "agent_denial_message",
    "decision_after_approval",
    "spend_alert_copy",
    "canonicalise_path",
    "match_pattern",
    "parse_json_no_duplicates",
    "count_mutations",
    "count_mutations_in_body",
    "evaluate_graphql_document",
    "evaluate_graphql_body",
    "evaluate_graphql_batch",
    "classify_capability",
    "is_paid_inference_capability",
]
