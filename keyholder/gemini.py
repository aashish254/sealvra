"""Gemini adapter for Keyholder v0.1 (W07, rewritten per audit f08 / v3 §1I).

Normative sources: ~/workspace/keyholder-build/CONTRACT.md §7 (Gemini) and
KEYHOLDER-PLAN-V3-FINALCHECK.md §1I (N-I1..N-I6). v3 wins over v1/v2; the old
R06 text is NOT a source for this module.

Auth-key model ONLY
------------------
Since 28 May 2026 all new Google AI Studio keys are authorisation (auth)
keys bound to a Google Cloud service account, Gemini-only by default, with
fast leak enforcement. The retiring standard-key model, its import flow,
and its "key authenticates the project, not a person" claim are DELETED
from this module. Requests made with an auth key run under the identity
of the bound service account: the account must stay least-privilege and
must keep its Gemini-only restriction, otherwise the blast radius widens
in a way this adapter cannot narrow. Auth keys do NOT give per-model,
per-endpoint, per-budget, or per-key-expiry scoping -- the proxy remains
the only narrowing layer for those (v3 N-I1, N-I5).

No shape gate (v3 N-I2)
-----------------------
There is NO hard-coded ``AIza`` shape check and NO hard-coded auth-key
prefix (the reported ``AQ.`` prefix is third-party-only and unverified).
``classify_key`` never rejects a key on prefix alone; a non-empty value
is accepted as an auth key (key type is user-attested metadata, exactly
like tier -- see v3/f08 F-26). The only validity proof is a live
``models.list`` probe, which this adapter does not perform (no real
Gemini calls in v0.1; loopback mocks / fixtures only).

Authentication (v3 N-I3, CONTRACT §6 step 7)
--------------------------------------------
Native mode: ``x-goog-api-key`` header ONLY. ``?key=`` query form is
refused (it lands in logs), and every other auth form is denied.
Compat (OpenAI-format) mode: strip-and-inject -- the client Bearer
value is the *session credential*, never the real key. It is stripped,
the session is authenticated elsewhere (broker), and the real key is
injected as ``x-goog-api-key``. A Bearer value that equals the real key
is denied with a security event, never forwarded. Native mode denies
ALL Bearer headers. Header names are matched case-insensitively.

DENIED in v0.1 (they outlive sessions or create unpoliced server-side
state -- v3 N-I4, CONTRACT §7):
  * Interactions API (``/interactions``): server-side state by default,
    ``background=true`` (violates the session-kill promise exactly like
    batch), managed agents, remote MCP tools, file search stores.
    ``background``, ``store``, ``previous_interaction_id`` and
    agent/MCP-tool fields are denied wherever they appear.
  * Batch jobs: resources are ``batches/*`` (NOT ``batch/*`` -- a
    ``batch/*`` deny pattern would pass vacuously, f08 F-10), plus
    ``batchGenerateContent`` / ``batchEmbedContents`` methods.
  * Live API (``BidiGenerateContent``, ``/live``), tuned models,
    cached-contents endpoints, file search stores, ``operations/*``,
    ``files:register`` (registers arbitrary ``gs://`` URIs as readable
    File resources, f08 F-20.3).
  * Upload paths: ``/upload/...`` and resumable-upload session URLs
    (capability-bearing URLs, f08 F-09). The proxy must terminate any
    resumable protocol itself; upload URLs are never logged and never
    returned to the agent. In v0.1 uploads are DENIED outright -- they
    are not modelled in the pack yet, so there is no "modelled" path
    that would admit them.

Server-side references (v3 N-I4, f08 F-05/F-06)
----------------------------------------------
``cachedContent`` and ``fileData.fileUri`` inside otherwise-allowed
calls are denied unless the referenced object is in the session's
creation ledger (see :class:`CreationLedger`). Files carry no creator
identity, so "own objects only" is enforceable ONLY through that
ledger: a file name is recorded when an upload response arrives inside
the session, and get/delete/reference are allowed only for ledger
names. Caches cannot be created in v0.1 (cached-contents endpoints are
denied), so no cache name can ever legitimately enter the ledger and
``cachedContent`` is denied in practice in every template.
``files.list`` enumerates the whole project inventory, so it is modelled
as ``read_account`` with a warning, never as a quiet read.

Response side (f08 F-07)
------------------------
Model-proposed ``functionCall`` parts are validated, not blindly
relayed: every call must match a function declared at session creation
and its arguments must satisfy the declared schema (required fields,
JSON types). Undeclared / schema-violating calls are STRIPPED from the
response and reported as violations (stripping is the stated rule;
blocking the whole turn is available via ``block_on_violation``).
Side-effecting calls (delete/publish/network) that survive validation
are flagged ``requires_approval`` -- declaration alone never authorises
them; they need the broker approval flow.

Streaming usage accounting (f08 F-18, v3 N-I5)
----------------------------------------------
Last-chunk-cumulative: ``usageMetadata`` in later stream chunks is
cumulative, not per-chunk deltas. Spend is computed from the FINAL
chunk only; per-chunk values are early-warning estimates, never summed.

Spend limiters (v3 N-I5, f08 F-12)
----------------------------------
Per-tier limiters below are PACK DATA, labelled ESTIMATED -- they are
not a guaranteed cap (CONTRACT §6: copy must say "spend alerts
(estimated)"). Prices are the October 2026 table, estimated, and will
rot; templates must show actual prices for exact models, never a fixed
multiple. RPM caps are NOT derived from tier (Google publishes no
per-model RPM); any RPM cap is a user-configured number, not modelled
here. Thinking tokens are billed as output.

Tier scope (CONTRACT §10)
------------------------
Tier A (interface-bound agent): the controls here hold. Tier B
(shell-capable same-user agent): file permissions / peer checks do not
separate same-user processes; this adapter makes no Tier B claim.

This module makes NO real Gemini calls, holds no real keys, and never
logs a key value, an upload session URL, or a session token. Test keys
in tests/fixtures are ``TEST-ONLY-...`` only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlparse

__all__ = [
    "GEMINI_HOST",
    "COMPAT_BASE",
    "Decision",
    "CreationLedger",
    "StreamingUsageTracker",
    "FunctionCallValidation",
    "classify_key",
    "classify_request",
    "build_upstream_headers",
    "reject_query_key",
    "extract_file_name",
    "validate_response_function_calls",
    "account_stream",
    "estimate_cost_usd",
    "SPEND_LIMITERS",
    "PRICE_TABLE_USD_PER_MILLION",
    "DENIED_PATTERNS",
]

GEMINI_HOST = "generativelanguage.googleapis.com"
COMPAT_BASE = "/v1beta/openai/"

# Session-class privilege order (CONTRACT §2): a higher class may do
# everything a lower class may, except where a rule says otherwise.
_CLASS_RANK = {
    "read_public": 1,
    "read_account": 2,
    "write": 3,
    "destructive": 4,
}

# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    """Adapter verdict. ``rule_id``/``category`` go to the audit log ONLY;
    the agent-facing denial must be generic (CONTRACT §6: no denial oracle)."""

    allowed: bool
    level: int  # 1 allow, 2 allow-with-log, 3 approve, 4 deny
    reason: str
    rule_id: str | None = None
    warning: str | None = None  # user-visible warning, e.g. files.list

    def public_denial(self) -> str:
        """Generic agent-facing denial: no rule_id, no category."""
        return "denied by policy" if not self.allowed else "allowed"


def _deny(reason: str, rule_id: str) -> Decision:
    return Decision(allowed=False, level=4, reason=reason, rule_id=rule_id)


def _allow(reason: str, rule_id: str, level: int = 1,
           warning: str | None = None) -> Decision:
    return Decision(allowed=True, level=level, reason=reason,
                    rule_id=rule_id, warning=warning)


# ---------------------------------------------------------------------------
# Key model: auth keys only, no shape gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthKeyInfo:
    """User-attested key metadata. ``key_type`` is attested, never
    inferred from prefix: Google publishes no auth-key prefix registry."""

    key_type: str  # always "auth" in v0.1; standard keys are legacy/deleted
    warning: str | None = None


def classify_key(value: str) -> AuthKeyInfo:
    """Classify an imported key value WITHOUT a shape gate (v3 N-I2).

    Returns auth-key metadata for any non-empty value, whatever its
    prefix. Empty/whitespace-only values are the only shape failure,
    and that is an empty-input failure, not a prefix rejection.
    Raises ValueError on empty input.
    """
    if not value or not value.strip():
        raise ValueError("empty key value")
    return AuthKeyInfo(
        key_type="auth",
        warning=(
            "Key type is user-attested: confirm this is a Gemini auth key "
            "from AI Studio bound to a least-privilege service account "
            "with its Gemini-only restriction intact. The only validity "
            "proof is a live models.list probe."
        ),
    )


# ---------------------------------------------------------------------------
# Creation ledger (f08 F-06)
# ---------------------------------------------------------------------------


class CreationLedger:
    """Per-session ledger of server-side objects created inside the
    session. The ONLY mechanism that makes "own objects only"
    enforceable, because File resources carry no creator identity.

    Only file names are recordable: caches cannot be created in v0.1,
    so no ``record_cache`` method exists by design -- a ``cachedContent``
    reference can therefore never satisfy the ledger check.
    """

    def __init__(self) -> None:
        self._files: set[str] = set()

    def record_file(self, name: str) -> None:
        """Record a file name from an upload response inside this session."""
        if name:
            self._files.add(_normalise_object_name(name))

    def contains(self, name: str) -> bool:
        return _normalise_object_name(name) in self._files if name else False

    def file_names(self) -> frozenset[str]:
        return frozenset(self._files)


def _normalise_object_name(name: str) -> str:
    name = name.strip().strip("/")
    # Accept full resource names ("files/abc") and bare ids ("abc").
    return name


def extract_file_name(file_uri: str) -> str | None:
    """Extract the ``files/<id>`` resource name from a fileUri, or None.

    Handles full URLs (https://.../v1beta/files/<id>) and bare
    ``files/<id>`` names. Anything else (e.g. a gs:// URI, an unrelated
    host) yields None and is denied downstream.
    """
    if not file_uri:
        return None
    parsed = urlparse(file_uri)
    path = parsed.path if parsed.netloc else file_uri
    match = re.search(r"(files/[A-Za-z0-9_-]+)", path)
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# Request classification
# ---------------------------------------------------------------------------

# Denied path families (matched against the lower-cased path, segments
# split BEFORE decoding -- decode-then-split is forbidden, CONTRACT §6).
# Each entry: (substring/regex, rule_id, reason).
DENIED_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (r"/interactions\b", "GEM-DENY-INTERACTIONS",
     "Interactions API denied in v0.1: server-side state, background "
     "execution, managed agents, remote MCP, file search stores"),
    (r"/batches\b", "GEM-DENY-BATCH",
     "Batch jobs denied: jobs outlive sessions (batches/* resources)"),
    (r":batchgeneratecontent\b", "GEM-DENY-BATCH",
     "Batch generation denied: outlives sessions"),
    (r":batchembedcontents\b", "GEM-DENY-BATCH",
     "Batch embeddings denied: outlives sessions"),
    (r"/live\b", "GEM-DENY-LIVE", "Live API denied in v0.1"),
    (r"bidigeneratecontent", "GEM-DENY-LIVE", "Live API denied in v0.1"),
    (r"/tunedmodels\b", "GEM-DENY-TUNED", "Tuned models denied in v0.1"),
    (r"/cachedcontents\b", "GEM-DENY-CACHE",
     "Cached contents denied in v0.1: no cache may be created"),
    (r"/filesearchstores\b", "GEM-DENY-FSS",
     "File search stores denied in v0.1"),
    (r"/operations\b", "GEM-DENY-OPS",
     "Operations denied in v0.1: unmodelled (file-search imports)"),
    (r":register\b", "GEM-DENY-REGISTER",
     "files:register denied: registers arbitrary gs:// URIs as readable files"),
    (r"^/upload/", "GEM-DENY-UPLOAD",
     "Upload prefix denied in v0.1: not modelled in the pack"),
)

# Allowed endpoint families: (regex, minimum session class, rule_id, reason).
# Paid inference (generate/stream/embed) is write class (CONTRACT §6).
_ALLOWED: tuple[tuple[str, str, str, str], ...] = (
    (r"/models/?$", "read_public", "GEM-ALLOW-MODELS",
     "models.list is a public read"),
    (r"/models/[^/:]+/?$", "read_public", "GEM-ALLOW-MODELS",
     "models.get is a public read (colon methods excluded: a method "
     "suffix like :generateContent is not a models.get)"),
    (r":generatecontent$", "write", "GEM-ALLOW-GENERATE",
     "generateContent is paid inference (write class)"),
    (r":streamgeneratecontent$", "write", "GEM-ALLOW-GENERATE",
     "streamGenerateContent is paid inference (write class)"),
    (r":counttokens$", "read_public", "GEM-ALLOW-COUNT",
     "countTokens is free of charge, separately quota'd (f08 F-22)"),
    (r":embedcontent$", "write", "GEM-ALLOW-EMBED",
     "embedContent is paid inference (write class)"),
    # Compat (OpenAI-format) endpoints live under /v1beta/openai/.
    (r"/openai/chat/completions$", "write", "GEM-ALLOW-COMPAT",
     "OpenAI-compat chat completions are paid inference (write class)"),
    (r"/openai/models/?$", "read_public", "GEM-ALLOW-COMPAT",
     "OpenAI-compat models list is a public read"),
    (r"/openai/embeddings$", "write", "GEM-ALLOW-COMPAT",
     "OpenAI-compat embeddings are paid inference (write class)"),
)

# Body fields denied wherever they appear (Interactions / server state).
_DENIED_BODY_FIELDS = (
    "background", "previous_interaction_id", "store",
)
# Tool types denied: managed agents / remote MCP / file search.
_DENIED_TOOL_TYPES = ("mcp", "remote_mcp", "managed_agent", "file_search",
                      "fileSearch", "code_execution_agent")


def _walk(obj, path: str = "$"):
    """Yield (path, key, value) for every dict key at any depth."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield path, key, value
            yield from _walk(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from _walk(item, f"{path}[{i}]")


def _find_references(body) -> list[tuple[str, str]]:
    """Return [(kind, name)] for cachedContent / fileData.fileUri refs."""
    refs: list[tuple[str, str]] = []
    if not isinstance(body, dict):
        return refs
    for _path, key, value in _walk(body):
        if key == "cachedContent" and isinstance(value, str) and value:
            refs.append(("cachedContent", value))
        if key == "fileUri" and isinstance(value, str) and value:
            refs.append(("fileUri", value))
    return refs


def reject_query_key(url: str) -> Decision | None:
    """Refuse ``?key=`` in any form. Returns a deny Decision, or None
    if no key query parameter is present. Never strips-and-continues:
    the query form is refused outright (it lands in logs)."""
    query = urlparse(url).query
    for name, _value in parse_qsl(query, keep_blank_values=True):
        if name.lower() == "key":
            return _deny("?key= query authentication refused; header only",
                         "GEM-DENY-QUERYKEY")
    return None


def _canonical_path(raw_path: str) -> str:
    """Lower-cased path for pattern matching (matching is
    case-insensitive so casing cannot bypass a deny rule)."""
    return urlparse(raw_path).path.lower()


def classify_request(method: str, path: str, body=None,
                     session_class: str = "read_public",
                     mode: str = "native",
                     ledger: CreationLedger | None = None,
                     pinned_safety_settings: dict | None = None,
                     allowed_models: set[str] | None = None) -> Decision:
    """Classify one Gemini request. Unmodelled endpoint = deny.

    ``path`` may be a path or a full URL. ``body`` is the parsed JSON
    request body (dict) or None. ``ledger`` defaults to an empty ledger
    (nothing is ledgered, so every reference is denied).
    """
    method = method.upper()
    if session_class not in _CLASS_RANK:
        return _deny("unknown session class", "GEM-DENY-INPUT")
    if mode not in ("native", "compat"):
        return _deny("unknown adapter mode", "GEM-DENY-INPUT")
    if method not in ("GET", "POST", "DELETE"):
        return _deny("method not modelled for Gemini in v0.1",
                     "GEM-DENY-METHOD")
    # DELETE is admitted only for ledgered files.delete below; every
    # other DELETE falls through to the unmodelled deny.

    # ?key= refusal comes first: it is an auth-form violation, not a
    # routing question.
    query_denial = reject_query_key(path)
    if query_denial is not None:
        return query_denial

    canon = _canonical_path(path)
    ledger = ledger if ledger is not None else CreationLedger()

    # Compat mode is confined to the compat base; native mode must not
    # be used to reach the compat base (mode confusion is a deny).
    if mode == "compat" and "/openai/" not in canon:
        return _deny("compat mode requires the /v1beta/openai/ base",
                     "GEM-DENY-MODE")
    if mode == "native" and "/openai/" in canon:
        return _deny("native mode must not use the compat base",
                     "GEM-DENY-MODE")

    # Upload prefix / resumable session URLs: denied in v0.1 outright.
    if canon.startswith("/upload/") or "/upload/" in canon:
        return _deny("upload paths denied in v0.1: not modelled in the pack",
                     "GEM-DENY-UPLOAD")
    if "upload" in canon and "resumable" in canon:
        return _deny("resumable upload session URLs denied in v0.1",
                     "GEM-DENY-UPLOAD")

    # Denied families (checked before the allowlist: deny wins).
    for pattern, rule_id, reason in DENIED_PATTERNS:
        if re.search(pattern, canon):
            return _deny(reason, rule_id)

    # Body-level denials, for otherwise-allowed calls.
    if isinstance(body, dict):
        for _p, key, value in _walk(body):
            if key in _DENIED_BODY_FIELDS and value not in (False, None, ""):
                return _deny(
                    f"field {key!r} denied: server-side state / background "
                    "execution outlives sessions", "GEM-DENY-BODYFIELD")
            if key == "type" and isinstance(value, str) and \
                    value.lower().replace("_", "") in {
                        t.lower().replace("_", "") for t in _DENIED_TOOL_TYPES}:
                return _deny("managed-agent / remote-MCP / file-search tool "
                             "denied in v0.1", "GEM-DENY-TOOL")
        # Safety settings: if pinned at session creation, mid-session
        # changes are denied (f08 F-11: flag-only contradicts
        # "policy never changes mid-session"). No pin => no check.
        if pinned_safety_settings is not None and "safetySettings" in body:
            if body["safetySettings"] != pinned_safety_settings:
                return _deny("safetySettings change mid-session denied: "
                             "settings are pinned at session creation",
                             "GEM-DENY-SAFETY")
        # Model pinning: if an allowlist is supplied, exact match only.
        if allowed_models is not None and "model" in body:
            if body["model"] not in allowed_models:
                return _deny("model not in session allowlist (exact match)",
                             "GEM-DENY-MODEL")
        # Server-side references: ledger-gated, always.
        for kind, value in _find_references(body):
            if kind == "cachedContent":
                # No cache can enter the ledger (creation denied), so
                # this is denied in every v0.1 template; the check is
                # still ledger-shaped, not a separate hard-coded ban.
                if not ledger.contains(value):
                    return _deny("cachedContent reference denied: object "
                                 "not in the session creation ledger",
                                 "GEM-DENY-REF")
            else:  # fileUri
                name = extract_file_name(value)
                if name is None or not ledger.contains(name):
                    return _deny("fileData.fileUri reference denied: object "
                                 "not in the session creation ledger",
                                 "GEM-DENY-REF")

    # File endpoints: split out of any family (f08 F-06).
    files_match = re.search(r"/files(?:/([^/?]+))?/?$", canon)
    if files_match and "/files" in canon and ":generatecontent" not in canon:
        if method == "GET" and files_match.group(1) is None:
            # files.list: full project inventory leak.
            if _CLASS_RANK[session_class] < _CLASS_RANK["read_account"]:
                return _deny("files.list requires read_account or higher",
                             "GEM-DENY-FILES")
            return _allow("files.list allowed with inventory warning",
                          "GEM-ALLOW-FILES-LIST", level=2,
                          warning="files.list exposes the full project "
                          "file inventory (names, metadata, URIs), "
                          "including files from other sessions/keys")
        name = files_match.group(1)
        if name is None:
            return _deny("file path not modelled", "GEM-DENY-FILES")
        full_name = f"files/{name}"
        if not ledger.contains(full_name):
            return _deny("file object denied: not in the session creation "
                         "ledger (own objects only)", "GEM-DENY-FILES")
        if method == "GET":
            if _CLASS_RANK[session_class] < _CLASS_RANK["read_account"]:
                return _deny("files.get requires read_account or higher",
                             "GEM-DENY-FILES")
            return _allow("ledgered file get allowed", "GEM-ALLOW-FILES")
        if method == "DELETE":
            if _CLASS_RANK[session_class] < _CLASS_RANK["write"]:
                return _deny("files.delete requires write or higher",
                             "GEM-DENY-FILES")
            return _allow("ledgered file delete allowed", "GEM-ALLOW-FILES")
        return _deny("file method not modelled", "GEM-DENY-FILES")

    # Allowlist: highest class wins; unmodelled = deny.
    for pattern, min_class, rule_id, reason in _ALLOWED:
        if re.search(pattern, canon):
            if _CLASS_RANK[session_class] < _CLASS_RANK[min_class]:
                return _deny(f"endpoint requires {min_class} or higher",
                             "GEM-DENY-CLASS")
            return _allow(reason, rule_id)
    return _deny("unmodelled endpoint: deny by default", "GEM-DENY-UNMODELLED")


# ---------------------------------------------------------------------------
# Header handling: native deny-all-Bearer, compat strip-and-inject
# ---------------------------------------------------------------------------


def build_upstream_headers(client_headers: dict, mode: str,
                           real_key: str) -> dict:
    """Build the upstream header set from client-supplied headers.

    - Every client ``Authorization`` / ``x-goog-api-key`` header (any
      casing) is stripped, never forwarded as-is.
    - Native mode: any client ``Authorization`` header => deny
      (ValueError). Bearer does not authenticate native Gemini.
    - Compat mode: a client Bearer value is treated as the session
      credential only. If it equals the real key => deny (security
      event, never forward). Otherwise it is stripped and the real key
      is injected as ``x-goog-api-key``.
    - Non-Bearer Authorization in compat mode (Basic, etc.) => deny.
    - Any other auth-shaped header (``x-goog-api-key`` from the client,
      ``x-goog-upload-url``, upload-command headers) => stripped/denied:
      upload headers deny outright (capability-bearing URLs).
    Raises ValueError on denial; the caller maps it to KH-1003.
    The returned dict never contains a client credential, and callers
    must never log the returned ``x-goog-api-key`` value.
    """
    if mode not in ("native", "compat"):
        raise ValueError("unknown adapter mode")
    if not real_key:
        raise ValueError("no real key supplied for injection")
    lowered: dict[str, str] = {}
    for key, value in (client_headers or {}).items():
        lowered[key.lower()] = value
    if "x-goog-upload-url" in lowered or "x-goog-upload-command" in lowered:
        raise ValueError("resumable upload session headers denied in v0.1")
    auth = lowered.get("authorization")
    if auth is not None:
        if mode == "native":
            raise ValueError("Authorization header denied in native mode: "
                             "use x-goog-api-key (injected by the proxy)")
        # Compat mode.
        match = re.match(r"^Bearer\s+(.+)$", auth.strip(), re.IGNORECASE)
        if not match:
            raise ValueError("only Bearer session credentials are accepted "
                             "in compat mode")
        bearer_value = match.group(1).strip()
        if bearer_value == real_key:
            raise ValueError("Bearer value matches the real key: denied, "
                             "security event (never forwarded)")
    out: dict[str, str] = {}
    for key, value in (client_headers or {}).items():
        lk = key.lower()
        if lk in ("authorization", "x-goog-api-key"):
            continue
        out[key] = value
    out["x-goog-api-key"] = real_key
    return out


# ---------------------------------------------------------------------------
# Response-side functionCall validation (f08 F-07)
# ---------------------------------------------------------------------------

_SIDE_EFFECTING = {"delete", "publish", "fetch", "request", "send",
                   "upload", "write_file", "execute", "run_command"}

# Declared-function schema shape: {"name": {"required": [...],
# "properties": {"arg": "string"|"integer"|"number"|"boolean"|"object"|"array"}}}
_JSON_TYPES = {
    "string": str, "integer": int, "number": (int, float),
    "boolean": bool, "object": dict, "array": list,
}


@dataclass
class FunctionCallValidation:
    sanitized: dict  # response with violating calls stripped
    violations: list[str] = field(default_factory=list)
    requires_approval: bool = False  # a surviving side-effecting call
    blocked: bool = False  # whole response blocked (block_on_violation)


def validate_response_function_calls(
        response: dict,
        declared_functions: dict,
        block_on_violation: bool = False) -> FunctionCallValidation:
    """Validate model-proposed functionCall parts in a response.

    Rule (stated, f08 F-07): undeclared functions and schema-violating
    arguments are STRIPPED, with a violation recorded for audit.
    ``block_on_violation=True`` instead blocks the whole response.
    A surviving side-effecting call (delete/publish/network/...) sets
    ``requires_approval`` -- declaration alone never authorises it.
    """
    import copy
    sanitized = copy.deepcopy(response)
    violations: list[str] = []
    requires_approval = False

    def _validate_part(part: dict) -> bool:
        nonlocal requires_approval
        call = part.get("functionCall")
        if not isinstance(call, dict):
            return True
        name = call.get("name")
        args = call.get("args", {})
        if name not in declared_functions:
            violations.append(f"undeclared function: {name!r}")
            return False
        schema = declared_functions[name] or {}
        if not isinstance(args, dict):
            violations.append(f"function {name!r}: args not an object")
            return False
        for req in schema.get("required", []):
            if req not in args:
                violations.append(f"function {name!r}: missing required "
                                  f"argument {req!r}")
                return False
        for arg, type_name in (schema.get("properties") or {}).items():
            if arg in args and type_name in _JSON_TYPES:
                expected = _JSON_TYPES[type_name]
                # bool is a subclass of int: exclude it from integer.
                if type_name == "integer" and isinstance(args[arg], bool):
                    violations.append(f"function {name!r}: argument {arg!r} "
                                      "must be integer")
                    return False
                if not isinstance(args[arg], expected):
                    violations.append(f"function {name!r}: argument {arg!r} "
                                      f"must be {type_name}")
                    return False
        if name.lower() in _SIDE_EFFECTING or \
                any(w in name.lower() for w in ("delete", "publish", "fetch")):
            requires_approval = True
        return True

    candidates = sanitized.get("candidates", [])
    if isinstance(candidates, list):
        for cand in candidates:
            content = cand.get("content", {}) if isinstance(cand, dict) else {}
            parts = content.get("parts", []) if isinstance(content, dict) else []
            if isinstance(parts, list):
                content["parts"] = [p for p in parts
                                    if not (isinstance(p, dict)
                                            and "functionCall" in p)
                                    or _validate_part(p)]
    if violations and block_on_violation:
        return FunctionCallValidation(sanitized={}, violations=violations,
                                      requires_approval=False, blocked=True)
    return FunctionCallValidation(sanitized=sanitized,
                                  violations=violations,
                                  requires_approval=requires_approval,
                                  blocked=False)


# ---------------------------------------------------------------------------
# Streaming usage accounting: last-chunk-cumulative (f08 F-18)
# ---------------------------------------------------------------------------


@dataclass
class _Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    thinking_tokens: int = 0  # billed as output, counted separately here


class StreamingUsageTracker:
    """Accumulate streaming usageMetadata WITHOUT summing chunks.

    Each chunk's usageMetadata is cumulative for the stream; only the
    LAST chunk's values are charged. Per-chunk values are visible as
    ``last_estimate`` for early warning only.
    """

    def __init__(self) -> None:
        self._last = _Usage()
        self._chunks = 0

    def update(self, usage_metadata: dict | None) -> None:
        if not usage_metadata:
            return
        self._chunks += 1
        self._last = _Usage(
            prompt_tokens=int(usage_metadata.get("promptTokenCount", 0) or 0),
            completion_tokens=int(
                usage_metadata.get("candidatesTokenCount", 0) or 0),
            thinking_tokens=int(
                usage_metadata.get("thoughtsTokenCount", 0) or 0),
        )

    @property
    def total(self) -> _Usage:
        """Charged usage: the final chunk's cumulative values only."""
        return self._last

    @property
    def chunks_seen(self) -> int:
        return self._chunks


def account_stream(chunks: list[dict]) -> _Usage:
    """Charge a scripted multi-chunk stream exactly once per stream:
    returns the final chunk's cumulative usageMetadata."""
    tracker = StreamingUsageTracker()
    for chunk in chunks:
        tracker.update(chunk.get("usageMetadata"))
    return tracker.total


# ---------------------------------------------------------------------------
# Spend limiters + price table (PACK DATA, ESTIMATED -- v3 N-I5)
# ---------------------------------------------------------------------------

# Estimated October 2026 prices, USD per 1M tokens (input, output).
# Thinking tokens billed as output. These WILL rot: re-verify against
# ai.google.dev/gemini-api/docs/pricing at each release (f08 F-23).
PRICE_TABLE_USD_PER_MILLION: dict[str, tuple[float, float]] = {
    "gemini-2.5-flash-lite": (0.10, 0.40),
    "gemini-2.5-flash": (0.30, 2.50),
    "gemini-2.5-pro": (2.00, 12.00),  # 2.00/12.00 base; higher above 200K input
}

# Per-tier spend limiters (f08 verified tier table). ESTIMATED -- copy
# must say "spend alerts (estimated)", never a guaranteed cap.
# per_10min is the limiter window; monthly is the billing-account cap
# family (a Tier 1 cap breach can pause sibling projects on the same
# billing account, f08 F-13).
SPEND_LIMITERS: dict[str, dict] = {
    "free": {"per_10min_usd": 0.0, "monthly_usd": 0.0,
             "hourly_ceiling_usd_estimated": 0.0, "estimated": True,
             "note": "Free tier: no paid spend; quota is the bound, not dollars."},
    "tier1": {"per_10min_usd": 10.0, "monthly_usd": 250.0,
              "hourly_ceiling_usd_estimated": 60.0, "estimated": True,
              "note": "Tier 1 ~$60/hr ceiling arithmetic (f08 verified)."},
    "tier2": {"per_10min_usd": 50.0, "monthly_usd": 2000.0,
              "hourly_ceiling_usd_estimated": 300.0, "estimated": True},
    "tier3": {"per_10min_usd": 200.0, "monthly_usd": 20000.0,
              "hourly_ceiling_usd_estimated": 1200.0, "estimated": True,
              "note": "Tier 3 monthly range $20,000-$100,000+; lower bound used."},
}


def estimate_cost_usd(model: str, prompt_tokens: int,
                      completion_tokens: int,
                      thinking_tokens: int = 0) -> float:
    """Estimated USD cost for one call. Thinking tokens bill as output.
    Raises KeyError for unmodelled models (no invented price)."""
    inp, out = PRICE_TABLE_USD_PER_MILLION[model]
    return ((prompt_tokens * inp)
            + ((completion_tokens + thinking_tokens) * out)) / 1_000_000


def spend_within_limiter(tier: str, spent_in_window_usd: float,
                         new_cost_usd: float) -> bool:
    """True if spent + new cost stays within the tier's per-10-min
    limiter (estimated). Free tier admits no paid cost."""
    limiter = SPEND_LIMITERS[tier]
    return spent_in_window_usd + new_cost_usd <= limiter["per_10min_usd"]
