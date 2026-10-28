"""W10 TEST SCALE ENGINE for Keyholder v0.2 (CONTRACT section 13.5).

Hand-written engine + its own tests. The engine generates the
``tests/test_generated_*.py`` files deterministically: same seed, same
cases, same order. Generated files are self-contained (each embeds its
case table and its runner); this file is never imported by them.

Counting rules enforced here (CONTRACT 13.5):
  * a case counts only with a distinct input AND at least one real
    assertion about a security-relevant outcome;
  * no duplicates: the dedup key of every generated case is registered
    in a single set and generation fails loudly on a collision;
  * no assertion-free tests, no "no crash" cases except fuzz cases
    with an explicit oracle (see the malformed-file runners);
  * unittest discovery counts them: generated files create real
    TestCase methods (``test_0001`` ...), never subTest-only cases.

Regenerate with:  ``python3 tests/test_scale_engine.py``
from the build root. Running this file under unittest only runs the
engine's own tests; it does not rewrite the generated files (the
committed files are checked against a fresh regeneration instead).

Fake data only: every key/token/secret value below is TEST-ONLY, and
no generated case contacts a real provider (loopback mocks only).
"""

import datetime
import hashlib
import json
import random
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from keyholder.packs import load_pack  # noqa: E402
from keyholder.policy import PolicyEngine  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = Path(__file__).resolve().parent
SEED = 20261028

# Fixed wall-clock instants (epoch seconds) so pack freshness never
# depends on the day the suite runs: packs ship issued 2026-10-28 with
# a 90-day max age, so 2026-10-28 is fresh and 2027-03-15 is stale.
FRESH_NOW = int(datetime.datetime(2026, 10, 28, 12, 0, tzinfo=datetime.timezone.utc).timestamp())
STALE_NOW = int(datetime.datetime(2027, 3, 15, 12, 0, tzinfo=datetime.timezone.utc).timestamp())
BASE_WALL = 1700000000.0

SESSION_CLASSES = ("destructive", "write", "read_account", "read_public")
TTL_TABLE = {
    "destructive": (600, 900),
    "write": (1200, 1800),
    "read_account": (1800, 3600),
    "read_public": (3600, 7200),
}
CAP_RANK = {"read_public": 0, "read_account": 1, "write": 2, "destructive": 3, "financial": 4}
CLASS_RANK = {"read_public": 0, "read_account": 1, "write": 2, "destructive": 3}
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")


def load_packs():
    """Load the shipped packs (hash-verified by load_pack)."""
    packs = {}
    for name in ("github", "gemini"):
        packs[name] = load_pack(ROOT / "packs" / f"{name}.json")
    return packs


PACKS = load_packs()
ENDPOINTS = []  # (provider, rule) in pack order, deterministic
for _provider in ("github", "gemini"):
    for _rule in PACKS[_provider].endpoints:
        ENDPOINTS.append((_provider, _rule))


# ------------------------------------------------------- path instantiation

# One filler per wildcard position, per shape variant. Variants are
# input SHAPES, not renames: plain, hyphen/underscore/digit, minimal,
# dotted, unicode, long-mixed. "**" takes a depth per variant.
_FILLERS = {
    0: ["acme", "widget", "main", "v1"],
    1: ["acme-corp", "my_repo-2", "release-1", "item42"],
    2: ["a", "x", "q", "z9"],
    3: ["v1.2", "rel.3", "north.wind", "2026.10"],
    4: ["münchen", "café-repo", "δelta", "naïve"],
    5: ["example-organisation", "sample_repository-2026", "long-segment-name", "archive-01"],
}
_STARSTAR_DEPTH = {0: 1, 1: 2, 2: 3, 3: 1, 4: 2, 5: 3}


def concrete_path(pattern, variant):
    """Instantiate a pack path pattern with variant-``variant`` fillers."""
    fillers = _FILLERS[variant]
    pos = 0
    out = []
    for seg in pattern.split("/")[1:]:
        if seg == "**":
            depth = _STARSTAR_DEPTH[variant]
            out.extend(fillers[(pos + k) % len(fillers)] for k in range(depth))
            pos += depth
        elif seg == "*":
            out.append(fillers[pos % len(fillers)])
            pos += 1
        elif seg.startswith("*:"):
            out.append(fillers[pos % len(fillers)] + ":" + seg[2:])
            pos += 1
        elif "*" in seg:  # pragma: no cover - no shipped pattern does this
            out.append(seg.replace("*", fillers[pos % len(fillers)]))
            pos += 1
        else:
            out.append(seg)
    return "/" + "/".join(out)


# ------------------------------------------- independent glob matcher (oracle)

def _segment_glob_to_regex(seg):
    parts = seg.split("*")
    return "^" + "[^/]*".join(re.escape(p) for p in parts) + "$"


def match_path(pattern, path):
    """Segment glob matcher, implemented independently of policy.py
    (regex translation here vs fnmatch there) so the oracle does not
    just re-call the code under test for matching."""
    pat = pattern.split("/")[1:]
    pth = path.split("/")[1:]

    def rec(pi, si):
        if pi == len(pat):
            return si == len(pth)
        if pat[pi] == "**":
            return any(rec(pi + 1, k) for k in range(si, len(pth) + 1))
        if si >= len(pth):
            return False
        if re.match(_segment_glob_to_regex(pat[pi]), pth[si]):
            return rec(pi + 1, si + 1)
        return False

    return rec(0, 0)


def find_rule(pack, method, path):
    """First matching rule for (method, path), or None (unmodelled)."""
    for rule in pack.endpoints:
        if rule.method.upper() == method.upper() and match_path(rule.path_pattern, path):
            return rule
    return None


def expected_decision(rule, session_class, stale, body_present=False):
    """Oracle for PolicyEngine.decide with no body, in decision order:
    unmodelled -> session class -> capability -> GraphQL-empty -> stale
    -> level map. Returns (allowed, level, rule_id).
    The GraphQL branch runs before body/stale handling: a body-less
    call to a /graphql endpoint with a capability-passing class is
    denied as graphql_empty, not by the pack level or stale rule."""
    if rule is None:
        return (False, 4, "unmodelled")
    if session_class not in CLASS_RANK:
        return (False, 4, "session_class")
    if rule.capability == "financial" or CAP_RANK[rule.capability] > CLASS_RANK[session_class]:
        return (False, 4, "capability")
    if rule.path_pattern == "/graphql" and not body_present:
        return (False, 4, "graphql_empty")
    level = rule.level
    rule_id = f"{rule_pack_name(rule)}:{rule.method}:{rule.path_pattern}"
    if stale:
        if rule.capability in ("destructive", "financial") or rule.spend or session_class == "destructive":
            return (False, 4, "stale_pack")
        level = min(level + 1, 4)
        rule_id = "stale_pack"
    if level == 1:
        return (True, 1, rule_id)
    if level == 2:
        return (True, 2, rule_id)
    if level == 3:
        return (False, 3, rule_id)
    return (False, 4, rule_id)


_RULE_PACK = {}


def rule_pack_name(rule):
    return _RULE_PACK.get(id(rule), "github")


for _provider, _rule in ENDPOINTS:
    _RULE_PACK[id(_rule)] = _provider


# ------------------------------------------------------------------ dedup

class DedupRegistry:
    """One registry for every generated case. A collision fails loudly
    instead of silently double-counting a case."""

    def __init__(self):
        self.seen = set()

    def add(self, key):
        key = tuple(key)
        if key in self.seen:
            raise AssertionError(f"duplicate generated case key: {key!r}")
        self.seen.add(key)
        return key


DEDUP = DedupRegistry()


def _exp(allowed, level, rule_id):
    return {"allowed": allowed, "level": level, "rule_id": rule_id}


# ------------------------------------------------------------ policy specs

def build_policy_specs(reg):
    specs = []

    def add(spec):
        spec["key"] = list(reg.add(spec["key"]))
        specs.append(spec)

    # 1. Full matrix: endpoint x variant x session class x freshness.
    for provider, rule in ENDPOINTS:
        pack = PACKS[provider]
        for variant in range(6):
            path = concrete_path(rule.path_pattern, variant)
            assert find_rule(pack, rule.method, path) is rule, (provider, rule, variant, path)
            for session_class in SESSION_CLASSES:
                for stale, now in ((False, FRESH_NOW), (True, STALE_NOW)):
                    allowed, level, rule_id = expected_decision(rule, session_class, stale)
                    add({
                        "kind": "decision", "provider": provider,
                        "method": rule.method, "path": path,
                        "session_class": session_class, "stale": stale,
                        "body_kind": None, "body": None, "body_raw_kind": None,
                        "ledger": None,
                        "expected": _exp(allowed, level, rule_id),
                        "key": ["policy", provider, rule.method, rule.path_pattern,
                                variant, session_class, "stale" if stale else "fresh"],
                    })
    # 2. Method mismatch: every other method against every endpoint path.
    # A mismatch that lands on an existing endpoint with the same
    # (method, path, class) as a matrix case IS that matrix case
    # (same input, same outcome), so it is skipped, not double-counted.
    matrix_inputs = set()
    for provider, rule in ENDPOINTS:
        for session_class in SESSION_CLASSES:
            matrix_inputs.add((provider, rule.method, concrete_path(rule.path_pattern, 0),
                               session_class))
    for provider, rule in ENDPOINTS:
        pack = PACKS[provider]
        path = concrete_path(rule.path_pattern, 0)
        for method in METHODS:
            if method == rule.method:
                continue
            matched = find_rule(pack, method, path)
            for session_class in ("destructive", "read_public"):
                if (provider, method, path, session_class) in matrix_inputs:
                    continue
                matrix_inputs.add((provider, method, path, session_class))
                allowed, level, rule_id = expected_decision(matched, session_class, False)
                add({
                    "kind": "decision", "provider": provider, "method": method,
                    "path": path, "session_class": session_class, "stale": False,
                    "body_kind": None, "body": None, "body_raw_kind": None,
                    "ledger": None,
                    "expected": _exp(allowed, level, rule_id),
                    "key": ["policy-mismatch", provider, method, rule.path_pattern,
                            session_class],
                })
    # 3. Body-schema cases (fresh pack only; body checks precede stale).
    def body_case(provider, method, path, session_class, body, raw_kind,
                  ledger, expected):
        add({
            "kind": "decision", "provider": provider, "method": method,
            "path": path, "session_class": session_class, "stale": False,
            "body_kind": "dict" if body is not None else None, "body": body,
            "body_raw_kind": raw_kind, "ledger": ledger, "expected": expected,
            "key": ["policy-body", provider, method, path, session_class,
                    json.dumps(body, sort_keys=True) if body is not None else raw_kind,
                    json.dumps(ledger, sort_keys=True) if ledger is not None else ""],
        })

    gh = PACKS["github"]
    comment_paths = [
        (m, concrete_path(p, 0))
        for (m, p) in (("POST", "/repos/*/*/issues"),
                       ("POST", "/repos/*/*/issues/*/comments"),
                       ("POST", "/repos/*/*/pulls/*/comments"))
    ]
    forbidden = ["/deploy", "/approve", "/backport", "@claude merge",
                 "@claude lgtm", "@claude approve"]
    for method, path in comment_paths:
        rule = find_rule(gh, method, path)
        for session_class in ("write", "destructive"):
            base = expected_decision(rule, session_class, False)
            body_case("github", method, path, session_class,
                      {"body": "hello world"}, None, None, _exp(*base))
            for sub in forbidden:
                for shape, text in (("exact", sub),
                                    ("embedded", "please " + sub + " now"),
                                    ("upper", sub.upper())):
                    if shape == "upper":
                        body_case("github", method, path, session_class,
                                  {"body": text}, None, None, _exp(*base))
                    else:
                        body_case("github", method, path, session_class,
                                  {"body": text}, None, None,
                                  _exp(False, 4, "body_schema"))
    for method, path, valid, missings in (
        ("PUT", concrete_path("/repos/*/*/contents/**", 0),
         {"message": "m", "content": "YQ=="},
         [{"content": "YQ=="}, {"message": "m"}, {}]),
        ("DELETE", concrete_path("/repos/*/*/contents/**", 0),
         {"message": "m", "sha": "abc123"},
         [{"sha": "abc123"}, {"message": "m"}, {}]),
    ):
        rule = find_rule(gh, method, path)
        classes = ("write", "destructive") if method == "PUT" else ("destructive",)
        for session_class in classes:
            base = expected_decision(rule, session_class, False)
            body_case("github", method, path, session_class, valid, None, None, _exp(*base))
            for miss in missings:
                body_case("github", method, path, session_class, miss, None, None,
                          _exp(False, 4, "body_schema"))
    gm = PACKS["gemini"]
    for path in (concrete_path("/v1beta/models/*:generateContent", 0),
                 concrete_path("/v1beta/models/*:streamGenerateContent", 0)):
        rule = find_rule(gm, "POST", path)
        for session_class in ("write", "destructive"):
            base = expected_decision(rule, session_class, False)
            body_case("gemini", "POST", path, session_class,
                      {"contents": [{"parts": [{"text": "hi"}]}]}, None, None, _exp(*base))
            body_case("gemini", "POST", path, session_class,
                      {"cachedContent": "cachedContents/abc"}, None, None,
                      _exp(False, 4, "body_schema"))
            body_case("gemini", "POST", path, session_class,
                      {"contents": [{"parts": [{"text": "see urlContext here"}]}]},
                      None, None, _exp(False, 4, "body_schema"))
            body_case("gemini", "POST", path, session_class,
                      {"urlContext": {"x": 1}}, None, None, _exp(False, 4, "body_schema"))
            body_case("gemini", "POST", path, session_class,
                      {"contents": [{"parts": [{"fileData": {"fileUri": "files/abc123"}}]}]},
                      None, ["files/abc123"], _exp(*base))
            body_case("gemini", "POST", path, session_class,
                      {"contents": [{"parts": [{"fileData": {"fileUri": "files/abc123"}}]}]},
                      None, [], _exp(False, 4, "ledger"))
            body_case("gemini", "POST", path, session_class,
                      {"contents": [{"parts": [{"fileData": {"fileUri": "files/abc123"}},
                                                {"fileData": {"fileUri": "files/evil"}}]}]},
                      None, ["files/abc123"], _exp(False, 4, "ledger"))
    # 4. Duplicate-key / malformed raw bodies: every non-financial endpoint.
    for provider, rule in ENDPOINTS:
        if rule.capability == "financial":
            continue  # capability deny precedes body parsing
        path = concrete_path(rule.path_pattern, 0)
        for raw_kind in ("dup_top", "dup_nested", "dup_array", "dup_deep",
                         "truncated", "trailing_comma", "bad_utf8"):
            body_case(provider, rule.method, path, "destructive", None,
                      raw_kind, None, _exp(False, 4, "body_parse"))
    # 5. Post-approval conversion, level-3 rules only (destructive class):
    # for other levels decision_after_approval is the identity, so those
    # cases would duplicate the matrix cases with the same outcome.
    for provider, rule in ENDPOINTS:
        path = concrete_path(rule.path_pattern, 0)
        allowed, level, rule_id = expected_decision(rule, "destructive", False)
        if level != 3:
            continue
        after = _exp(True, 2, rule_id)
        add({
            "kind": "approval", "provider": provider, "method": rule.method,
            "path": path, "session_class": "destructive",
            "expected": after,
            "key": ["policy-approval", provider, rule.method, rule.path_pattern],
        })
    # 6. GraphQL documents.
    def gql_doc(spec_key, document, session_class, max_mut, expected):
        add({"kind": "graphql-doc", "document": document,
             "session_class": session_class, "max_mutations": max_mut,
             "expected": expected,
             "key": ["graphql-doc", spec_key, session_class, max_mut]})

    for count in range(6):
        doc = " ".join(f"mutation M{i} {{ field{i} }}" for i in range(count)) or "query { field }"
        for session_class in SESSION_CLASSES:
            for max_mut in (1, 2):
                if count > max_mut:
                    exp = _exp(False, 4, "graphql_mutation_cap")
                elif count > 0:
                    if CLASS_RANK[session_class] < CLASS_RANK["write"]:
                        exp = _exp(False, 4, "graphql_capability")
                    else:
                        exp = _exp(False, 3, "graphql_mutation")
                else:
                    exp = _exp(True, 1, "graphql_query")
                gql_doc(f"mutations-{count}", doc, session_class, max_mut, exp)
    special_docs = [
        ("subscription", "subscription { updates }", _exp(False, 4, "graphql_subscription")),
        ("defer", "query { f @defer }", _exp(False, 4, "graphql_directive")),
        ("stream", "query { f @stream }", _exp(False, 4, "graphql_directive")),
        ("introspection", "query { __schema { types { name } } }", _exp(False, 4, "graphql_introspection")),
        ("cycle", "fragment A on T { ...B } fragment B on T { ...A } query { ...A }",
         _exp(False, 4, "graphql_cycle")),
        ("string-hidden", 'query { f(arg: "mutation { x }") }', _exp(True, 1, "graphql_query")),
        ("comment-hidden", "# mutation { x }\nquery { f }", _exp(True, 1, "graphql_query")),
        ("typename", "query { __typename }", _exp(True, 1, "graphql_query")),
        ("empty", "", _exp(False, 4, "graphql_empty")),
        ("whitespace", "   \n  ", _exp(False, 4, "graphql_empty")),
    ]
    for name, doc, exp in special_docs:
        for session_class in ("read_public", "write"):
            gql_doc("special-" + name, doc, session_class, 1, exp)
    # Batch bodies: element-type sequences.
    batch_docs = {
        "query": ("query { f }", _exp(True, 1, "graphql_query")),
        "mutation": ("mutation M { f }", _exp(False, 3, "graphql_mutation")),
        "subscription": ("subscription { u }", _exp(False, 4, "graphql_subscription")),
    }
    rng = random.Random(SEED)
    combos = []
    for a in batch_docs:
        for b in batch_docs:
            combos.append((a, b))
    for a in batch_docs:
        for b in batch_docs:
            for c in batch_docs:
                combos.append((a, b, c))
    rng.shuffle(combos)
    for combo in combos:
        body = [{"query": batch_docs[k][0]} for k in combo]
        expected = [batch_docs[k][1] for k in combo]
        add({"kind": "graphql-batch", "body": body, "expected_list": expected,
             "key": ["graphql-batch", "+".join(combo)]})
    add({"kind": "graphql-batch", "body": [{"query": "query { f }"}, {"noquery": 1}],
         "expected_list": [_exp(True, 1, "graphql_query"), _exp(False, 4, "graphql_body")],
         "key": ["graphql-batch", "missing-query"]})
    add({"kind": "graphql-batch", "body": "not an object",
         "expected_list": [_exp(False, 4, "graphql_body")],
         "key": ["graphql-batch", "non-object-body"]})
    return specs


# ---------------------------------------------------------- sessions specs

def _ttl_values(session_class):
    default, cap = TTL_TABLE[session_class]
    vals = [1, 60, 299, 300, 301, default - 1, default, default + 1,
            cap - 1, cap, cap + 1, 7199, 7200, 7201]
    seen, out = set(), []
    for v in vals:
        if v not in seen and v > 0:
            seen.add(v)
            out.append(v)
    return out


def build_session_specs(reg):
    specs = []

    def add(spec):
        spec["key"] = list(reg.add(spec["key"]))
        specs.append(spec)

    # 1. Create matrix: class x ttl x idle x transport x provider.
    for session_class in SESSION_CLASSES:
        default_ttl, cap_ttl = TTL_TABLE[session_class]
        for ttl in _ttl_values(session_class):
            for idle in (119, 120, 121, 299, 300, 301, 899, 900, 901, 0):
                for transport in ("absolute", "connect_allowed", "bogus"):
                    for provider in ("github", "gemini"):
                        ok = (ttl <= cap_ttl and 120 <= idle <= 900
                              and transport in ("absolute", "connect_allowed")
                              and not (transport == "connect_allowed"
                                       and session_class in ("write", "destructive")))
                        add({
                            "kind": "create", "provider": provider,
                            "session_class": session_class, "ttl": ttl,
                            "idle": idle, "transport": transport,
                            "expected_ok": ok,
                            "key": ["session-create", session_class, ttl, idle,
                                    transport, provider],
                        })
    # 2. Liveness / idle / kill / prune matrices (default TTL).
    for session_class in SESSION_CLASSES:
        for idle in (120, 300, 900):
            for time_kind in ("idle-1", "idle", "idle+1", "ttl-1", "ttl", "ttl+1"):
                add({"kind": "validate", "session_class": session_class,
                     "idle": idle, "time_kind": time_kind,
                     "key": ["session-validate", session_class, idle, time_kind]})
            for action in ("denied", "poll"):
                add({"kind": "no-reset", "action": action,
                     "session_class": session_class, "idle": idle,
                     "key": ["session-no-reset", action, session_class, idle]})
            if idle - 1 < TTL_TABLE[session_class][0]:
                add({"kind": "success-reset", "session_class": session_class,
                     "idle": idle,
                     "key": ["session-success-reset", session_class, idle]})
            add({"kind": "kill", "session_class": session_class, "idle": idle,
                 "key": ["session-kill", session_class, idle]})
            for time_kind in ("ttl-1", "ttl+1"):
                add({"kind": "prune", "session_class": session_class,
                     "idle": idle, "time_kind": time_kind,
                     "key": ["session-prune", session_class, idle, time_kind]})
    for session_class in SESSION_CLASSES:
        add({"kind": "killall", "session_class": session_class,
             "key": ["session-killall", session_class]})
    add({"kind": "killall-mixed", "key": ["session-killall", "mixed"]})
    for session_class in SESSION_CLASSES:
        add({"kind": "inflight", "session_class": session_class,
             "complete_one": False,
             "key": ["session-inflight", session_class, "both"]})
        add({"kind": "inflight", "session_class": session_class,
             "complete_one": True,
             "key": ["session-inflight", session_class, "one-completed"]})
    for bad_key in (["key-a"], {"k": "v"}, "", None):
        add({"kind": "badkey", "bad_key": bad_key,
             "key": ["session-badkey", json.dumps(bad_key, sort_keys=True, default=str)]})
    add({"kind": "noextend", "key": ["session-noextend"]})
    # 3. PoP verification matrix.
    pop_bodies = {"empty": b"", "json": b'{"a": 1}', "x64": b"x" * 64}
    for field in ("method", "host", "path", "body"):
        for body_kind in ("empty", "json", "x64"):
            add({"kind": "pop", "tamper": field, "body_kind": body_kind,
                 "expected": False,
                 "key": ["pop-tamper", field, body_kind]})
    for variant in ("flip", "truncate", "empty", "none", "upper"):
        for body_kind in ("empty", "json"):
            add({"kind": "pop", "tamper": "pop-" + variant, "body_kind": body_kind,
                 "expected": False,
                 "key": ["pop-tamper", "pop-" + variant, body_kind]})
    for offset in (-86400, -3600, -301, -300, -299, -60, 0, 60, 299, 300, 301, 3600):
        add({"kind": "pop-skew", "offset": offset, "expected": abs(offset) <= 300,
             "key": ["pop-skew", offset]})
    for ts_kind in ("str-valid", "str-invalid", "none", "float"):
        add({"kind": "pop-tstype", "ts_kind": ts_kind,
             "expected": ts_kind in ("str-valid", "float"),
             "key": ["pop-tstype", ts_kind]})
    for name in ("replay-first-ok", "replay-second", "new-timestamp-ok",
                 "tampered-after", "missing-pop", "missing-ts",
                 "killed-session", "expired-session", "idle-session"):
        add({"kind": "pop-sequence", "name": name,
             "key": ["pop-sequence", name]})
    # 4. Capability classification: method x flag combinations.
    for method in ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "FOO"):
        for destructive in (False, True):
            for paid in (False, True):
                for financial in (False, True):
                    for read_like in (False, True):
                        for public in (False, True):
                            m = method.upper()
                            if destructive or m == "DELETE":
                                expected = "destructive"
                            elif paid or financial:
                                expected = "write"
                            elif m in ("POST", "PUT", "PATCH") and not read_like:
                                expected = "write"
                            elif m in ("GET", "HEAD", "OPTIONS") or read_like:
                                expected = "read_public" if public else "read_account"
                            else:
                                expected = "write"
                            add({
                                "kind": "classify", "method": method,
                                "destructive": destructive, "paid": paid,
                                "financial": financial, "read_like": read_like,
                                "public": public, "expected": expected,
                                "key": ["classify", method, destructive, paid,
                                        financial, read_like, public],
                            })
    cap_lists = [["read_public"], ["read_account"], ["write"], ["destructive"], ["financial"]]
    caps = ["read_public", "read_account", "write", "destructive", "financial"]
    for i in range(len(caps)):
        for j in range(i, len(caps)):
            cap_lists.append([caps[i], caps[j]])
    rng = random.Random(SEED + 1)
    triples = set()
    while len(triples) < 30:
        triples.add(tuple(rng.choice(caps) for _ in range(3)))
    cap_lists.extend([list(t) for t in sorted(triples)])
    for lst in cap_lists:
        expected = max(lst, key=lambda c: CAP_RANK[c])
        add({"kind": "capability", "capabilities": lst, "expected": expected,
             "key": ["capability", "+".join(lst)]})
    for lst in (["bogus"], ["read_public", "bogus"], ["bogus", "write"], []):
        add({"kind": "capability-error", "capabilities": lst,
             "key": ["capability-error", "+".join(lst) if lst else "empty"]})
    for session_class, drain in (("read_account", 60), ("read_public", 60),
                                 ("write", 0), ("destructive", 0)):
        add({"kind": "drain", "session_class": session_class, "expected": drain,
             "key": ["drain", session_class]})
    for bad in ("bogus", "financial", ""):
        add({"kind": "drain-error", "session_class": bad,
             "key": ["drain-error", bad if bad else "empty"]})
    # 5. CONNECT decisions.
    loopback = ("127.0.0.1", "localhost", "::1")
    for test_mode in (True, False):
        authorities = (("127.0.0.1:8443", "127.0.0.1", "localhost:9000",
                        "api.github.com:443") if test_mode else
                       ("api.github.com:443", "api.github.com:8443",
                        "hook.example.com:443", "evil.example.com:443"))
        for transport in ("absolute", "connect_allowed"):
            for session_class in SESSION_CLASSES:
                for authority in authorities:
                    host_part = authority.rpartition(":")[0] if ":" in authority else authority
                    port = int(authority.rpartition(":")[2]) if ":" in authority else 443
                    if test_mode:
                        host_ok = host_part in loopback
                        port_ok = True
                    else:
                        host_ok = host_part in ("api.github.com", "hook.example.com")
                        port_ok = port == 443
                    expected = (transport == "connect_allowed"
                                and session_class not in ("write", "destructive")
                                and host_ok and port_ok)
                    add({
                        "kind": "connect", "transport": transport,
                        "session_class": session_class, "authority": authority,
                        "test_mode": test_mode, "expected": expected,
                        "key": ["connect", test_mode, transport, session_class, authority],
                    })
    for state in ("killed", "expired", "idle"):
        add({"kind": "connect-dead", "state": state, "expected": False,
             "key": ["connect-dead", state]})
    for name in ("missing-token", "missing-pop", "bad-pop", "replay"):
        add({"kind": "connect-auth", "name": name, "expected": name != "replay",
             "key": ["connect-auth", name]})
    return specs


# -------------------------------------------------------------- audit specs

def build_audit_specs(reg):
    specs = []

    def add(spec):
        spec["key"] = list(reg.add(spec["key"]))
        specs.append(spec)

    for length in (1, 2, 3, 5, 8, 13):
        for variant in range(40):
            add({"kind": "sequence", "length": length, "variant": variant,
                 "key": ["audit-sequence", length, variant]})
    for position in range(6):
        for tamper in ("decision", "method", "path", "seq", "hash", "bytes"):
            add({"kind": "tamper", "length": 5, "position": position,
                 "tamper": tamper,
                 "key": ["audit-tamper", position, tamper]})
    for op in ("delete", "duplicate", "forged", "malformed"):
        add({"kind": "tamper-op", "length": 5, "op": op,
             "key": ["audit-tamper-op", op]})
    for length in (3, 5, 8):
        for (frm, to, expected) in ((1, 1, "OK"), (1, 4, "OK"), (2, 3, "OK"),
                                    (4, 4, "OK"), (4, 5, "OK"),
                                    (0, 1, "TAMPERED"), (0, 99, "TAMPERED"),
                                    (5, 99, "TAMPERED"), (3, 2, "TAMPERED")):
            # Range endpoints are seq numbers; a length-3 log holds
            # seqs 1..4 (genesis + 3 events), length-5 holds 1..6,
            # length-8 holds 1..9. verify_range requires the end seq
            # to exist: (4,5) is OK only when the log reaches seq 5.
            exp = expected
            if (frm, to) == (4, 5):
                exp = "OK" if length >= 5 else "TAMPERED"
            add({"kind": "range", "length": length, "from_seq": frm,
                 "to_seq": to, "expected": exp,
                 "key": ["audit-range", length, frm, to]})
    for key_id in ("key-aaaa1111bbbb2222", "key-0000000000000000",
                   "key-ffffffffffffffff", "key-1234567890abcdef",
                   "key-deadbeefcafebabe", "key-0123456789abcdef",
                   "key-aaaaaaaaaaaaaaaa", "key-5555555555555555",
                   "key-9999999999999999", "key-abcdef0123456789",
                   "key-fedcba9876543210", "key-1111222233334444"):
        for secret_label in ("A", "B", "C"):
            add({"kind": "pseudonym", "key_id": key_id, "secret_label": secret_label,
                 "key": ["audit-pseudonym", key_id, secret_label]})
    for field in ("canonical_path", "method"):
        for secret in ("TEST-ONLY-secret-xyz", "TEST-ONLY-other-secret-123"):
            add({"kind": "scrub", "field": field, "secret": secret,
                 "key": ["audit-scrub", field, secret]})
    add({"kind": "scrub-clean", "key": ["audit-scrub", "clean-control"]})
    for length in (1, 3, 8):
        add({"kind": "anchor", "length": length,
             "key": ["audit-anchor", length]})
    for length in (1, 3):
        for variant in range(4):
            add({"kind": "csv", "length": length, "variant": variant,
                 "key": ["audit-csv", length, variant]})
    return specs


# ----------------------------------------------------------- malformed specs

_POLICY_CANON_RAISES = [
    "", "user", "/a//b", "/a/", "/a/./b", "/a/../b", "/.", "/..",
    "/a\\b", "/a\x00b", "/a#b", "/a/%", "/a/%2", "/a/%zz",
    "/a/%2E/b", "/a/%2e%2e/b", "/a/%C3%28/b", "/a/%ff/b",
]
_POLICY_CANON_OK = [
    ("/a/b", "/a/b"), ("/a/%41/b", "/a/A/b"), ("/a/%20/b", "/a/ /b"),
    ("/a/b?x=1", "/a/b"), ("/a/b?key=abc", "/a/b"),
    ("/münchen/café", "/münchen/café"), ("/a/v1.2/b", "/a/v1.2/b"),
    ("/repos/o/r", "/repos/o/r"),
]


def _safe_segments(rng, count):
    alphabet = "abcdefghij0123456789-_~"
    segs = []
    for _ in range(count):
        style = rng.randrange(5)
        if style == 0:
            segs.append("".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 9))))
        elif style == 1:
            segs.append("v" + str(rng.randrange(10)) + "." + str(rng.randrange(10)))
        elif style == 2:
            segs.append(rng.choice(["%41", "%20", "%7E", "%C3%A9"]) + "x")
        elif style == 3:
            segs.append(rng.choice(["münchen", "café", "δelta", "naïve"]))
        else:
            segs.append("seg-" + str(rng.randrange(1000)))
    return segs


def build_malformed_specs(reg):
    specs = []

    def add(spec):
        spec["key"] = list(reg.add(spec["key"]))
        specs.append(spec)

    for path in _POLICY_CANON_RAISES:
        add({"kind": "policy-canon", "path": path, "expected": None,
             "key": ["policy-canon-raise", path]})
    for path, expected in _POLICY_CANON_OK:
        add({"kind": "policy-canon", "path": path, "expected": expected,
             "key": ["policy-canon-ok", path]})
    rng = random.Random(SEED + 2)
    seen_paths = set()
    while len(seen_paths) < 900:
        segs = _safe_segments(rng, rng.randrange(1, 5))
        path = "/" + "/".join(segs)
        if path in seen_paths:
            continue
        seen_paths.add(path)
        add({"kind": "policy-fuzz", "path": path,
             "key": ["policy-fuzz", path]})
    seen_raise = set()
    while len(seen_raise) < 100:
        bad = rng.choice([".", ".."])
        segs = _safe_segments(rng, 2)
        path = "/" + segs[0] + "/" + bad + "/" + segs[1]
        if path in seen_raise:
            continue
        seen_raise.add(path)
        add({"kind": "policy-fuzz-raise", "path": path,
             "key": ["policy-fuzz-raise", path]})
    # Proxy canonicalise_target: fixed shapes x base.
    base_gh = "http://127.0.0.1:18765"
    base_gm = "http://127.0.0.1:18766"
    shapes = [
        ("origin", "/repos/o/r", "127.0.0.1:18765", True, "/repos/o/r", "/repos/o/r"),
        ("origin-notest", "/repos/o/r", "127.0.0.1:18765", False, "/repos/o/r", "/repos/o/r"),
        ("dotdot", "/a/../b", "127.0.0.1:18765", True, "/b", "/b"),
        ("dot", "/a/./b", "127.0.0.1:18765", True, "/a/b", "/a/b"),
        ("escape-slash", "/a/%2F/b", "127.0.0.1:18765", True, None, None),
        ("escape-ok", "/a/%41/b", "127.0.0.1:18765", True, "/a/A/b", "/a/A/b"),
        ("query-ok", "/repos/o/r?page=2", "127.0.0.1:18765", True,
         "/repos/o/r?page=2", "/repos/o/r?page=2"),
        ("absolute", "http://127.0.0.1:18765/repos/o/r", None, True,
         "/repos/o/r", "/repos/o/r"),
        ("absolute-plain-notest", "http://127.0.0.1:18765/repos/o/r", None, False, None, None),
        ("absolute-https", "https://127.0.0.1:18765/repos/o/r", None, True,
         "/repos/o/r", "/repos/o/r"),
        ("wrong-host", "http://evil.example.com/repos/o/r", None, True, None, None),
        ("wrong-port", "http://127.0.0.1:9999/repos/o/r", None, True, None, None),
        ("userinfo", "http://user@127.0.0.1:18765/repos/o/r", None, True, None, None),
        ("asterisk", "*", "127.0.0.1:18765", True, None, None),
        ("backslash", "/a\\b", "127.0.0.1:18765", True, None, None),
        ("fragment", "/a#b", "127.0.0.1:18765", True, None, None),
        ("empty", "", "127.0.0.1:18765", True, None, None),
        ("no-host-header", "/repos/o/r", None, True, None, None),
        ("space", "/a b/c", "127.0.0.1:18765", True, None, None),
        ("escape-backslash", "/a/%5C/b", "127.0.0.1:18765", True, None, None),
    ]
    for name, target, host, test_mode, canon, fwd in shapes:
        add({"kind": "proxy-target", "target": target, "host": host,
             "base": base_gh, "test_mode": test_mode,
             "expected_canon": canon, "expected_fwd": fwd,
             "key": ["proxy-target", name, test_mode]})
    for qname in ("key", "api_key", "apikey", "access_token", "token", "secret"):
        add({"kind": "proxy-target", "target": f"/repos/o/r?{qname}=abc",
             "host": "127.0.0.1:18765", "base": base_gh, "test_mode": True,
             "expected_canon": None, "expected_fwd": None,
             "key": ["proxy-target", "cred-query", qname]})
    for name, target, host in (
        ("gemini-origin", "/v1beta/models", "127.0.0.1:18766"),
        ("gemini-absolute", "http://127.0.0.1:18766/v1beta/models", None),
    ):
        add({"kind": "proxy-target", "target": target, "host": host,
             "base": base_gm, "test_mode": True,
             "expected_canon": "/v1beta/models", "expected_fwd": "/v1beta/models",
             "key": ["proxy-target", name]})
    rng = random.Random(SEED + 3)
    seen_fuzz = set()
    while len(seen_fuzz) < 300:
        segs = _safe_segments(rng, rng.randrange(1, 4))
        qkey = rng.choice(["page", "per_page", "sort", "state"])
        path = "/" + "/".join(segs) + f"?{qkey}={rng.randrange(100)}"
        if path in seen_fuzz:
            continue
        seen_fuzz.add(path)
        add({"kind": "proxy-fuzz", "target": path, "host": "127.0.0.1:18765",
             "base": base_gh, "key": ["proxy-fuzz", path]})
    # Header normalisation through ProxyEngine.handle (fails before
    # any upstream contact, so no mock server is needed here).
    header_shapes = [
        ("dup-content-length", [("Content-Length", "0"), ("Content-Length", "0")]),
        ("dup-host", [("Host", "127.0.0.1:18765"), ("Host", "127.0.0.1:18765")]),
        ("dup-session", [("X-Keyholder-Session", "a"), ("X-Keyholder-Session", "b")]),
        ("bad-name", [("Bad Name", "x")]),
        ("cr-value", [("X-Test", "a\rb")]),
        ("lf-value", [("X-Test", "a\nb")]),
        ("nul-value", [("X-Test", "a\x00b")]),
        ("empty-name", [("", "x")]),
    ]
    for name, headers in header_shapes:
        for method in ("GET", "POST"):
            add({"kind": "proxy-header", "headers": headers, "method": method,
                 "expected_status": 400,
                 "key": ["proxy-header", name, method]})
    for name, raw in (
        ("dup-top", '{"a": 1, "a": 2}'),
        ("dup-nested", '{"a": {"b": 1, "b": 2}}'),
        ("dup-array", '[{"a": 1, "a": 2}]'),
        ("dup-deep", '{"a": {"b": {"c": 1, "c": 2}}}'),
        ("dup-unicode-escape", '{"a": 1, "\\u0061": 2}'),
        ("distinct-case", '{"a": 1, "A": 2}'),
        ("clean", '{"a": 1, "b": {"c": 2}}'),
    ):
        add({"kind": "json-dup", "raw": raw, "expected_raise": name.startswith("dup"),
             "key": ["json-dup", name]})
    # Glob non-matches: one altered segment per pattern.
    for provider, rule in ENDPOINTS:
        path = concrete_path(rule.path_pattern, 0)
        segs = path.split("/")[1:]
        if segs:
            segs[0] = "zzz-no-such-segment"
        bad_path = "/" + "/".join(segs)
        add({"kind": "glob-nomatch", "pattern": rule.path_pattern,
             "path": bad_path, "expected": False,
             "key": ["glob-nomatch", provider, rule.method, rule.path_pattern]})
    glob_edges = [
        ("/repos/**", "/repos", True), ("/repos/**", "/repos/a/b/c", True),
        ("/repos/*/*", "/repos/a", False), ("/repos/*/*", "/repos/a/b/c", False),
        ("/v1beta/models/*:generateContent", "/v1beta/models/m:generateContent", True),
        ("/v1beta/models/*:generateContent", "/v1beta/models/m:other", False),
        ("/v1beta/models/*", "/v1beta/models/a/b", False),
        ("/a/**/b", "/a/b", True), ("/a/**/b", "/a/x/y/b", True),
        ("/a/**/b", "/a/x/y/c", False),
    ]
    for pattern, path, expected in glob_edges:
        add({"kind": "glob", "pattern": pattern, "path": path, "expected": expected,
             "key": ["glob-edge", pattern, path]})
    return specs


# -------------------------------------------------------------- proxy specs

def build_proxy_specs(reg):
    specs = []

    def add(spec):
        spec["key"] = list(reg.add(spec["key"]))
        specs.append(spec)

    for provider, rule in ENDPOINTS:
        if rule.capability == "financial":
            continue  # no session class can ever satisfy financial
        pack = PACKS[provider]
        for variant in (0, 1):
            path = concrete_path(rule.path_pattern, variant)
            assert find_rule(pack, rule.method, path) is rule
            passing = [c for c in SESSION_CLASSES
                       if CAP_RANK[rule.capability] <= CLASS_RANK[c]]
            for session_class in passing:
                allowed, level, rule_id = expected_decision(rule, session_class, False)
                if level == 3:
                    for approve in (True, False):
                        add({
                            "kind": "endpoint", "provider": provider,
                            "method": rule.method, "path": path,
                            "session_class": session_class, "approve": approve,
                            "expected_relay": approve, "expected_level": 2 if approve else 3,
                            "key": ["proxy-endpoint", provider, rule.method,
                                    rule.path_pattern, variant, session_class, approve],
                        })
                elif level == 4:
                    add({
                        "kind": "endpoint", "provider": provider,
                        "method": rule.method, "path": path,
                        "session_class": session_class, "approve": None,
                        "expected_relay": False, "expected_level": 4,
                        "key": ["proxy-endpoint", provider, rule.method,
                                rule.path_pattern, variant, session_class, "deny"],
                    })
                else:
                    add({
                        "kind": "endpoint", "provider": provider,
                        "method": rule.method, "path": path,
                        "session_class": session_class, "approve": None,
                        "expected_relay": True, "expected_level": level,
                        "key": ["proxy-endpoint", provider, rule.method,
                                rule.path_pattern, variant, session_class, "allow"],
                    })
    for provider, path, key in (
        ("github", "/user", "TEST-ONLY-gh-proxy-key"),
        ("gemini", "/v1beta/models", "TEST-ONLY-gemini-proxy-key"),
    ):
        for resp in ("secret", "secrethex", "credential", "credential-nested",
                     "credential-list", "secret-header", "clean"):
            add({"kind": "blocking", "provider": provider, "path": path,
                 "resp": resp, "expected_blocked": resp != "clean",
                 "key": ["proxy-blocking", provider, resp]})
    for name in ("missing-token", "unknown-token", "missing-pop", "bad-pop",
                 "replay", "killed", "expired", "idle"):
        add({"kind": "auth", "name": name, "key": ["proxy-auth", name]})
    for provider, path in (("github", "/user"), ("gemini", "/v1beta/models")):
        add({"kind": "audit-fail-decision", "provider": provider, "path": path,
             "key": ["proxy-audit-fail-decision", provider]})
    add({"kind": "audit-fail-outcome", "key": ["proxy-audit-fail-outcome"]})
    add({"kind": "oversize-body", "key": ["proxy-oversize-body"]})
    add({"kind": "length-mismatch", "key": ["proxy-length-mismatch"]})
    add({"kind": "transfer-encoding", "key": ["proxy-transfer-encoding"]})
    for qname in ("key", "access_token"):
        add({"kind": "cred-query", "qname": qname,
             "key": ["proxy-cred-query", qname]})
    add({"kind": "plain-http-base", "key": ["proxy-plain-http-base"]})
    return specs


# --------------------------------------------------------------- misc specs

def build_misc_specs(reg):
    specs = []

    def add(spec):
        spec["key"] = list(reg.add(spec["key"]))
        specs.append(spec)

    for first_level in (1, 2, 3, 4):
        for spend in (False, True):
            for variation in ("same", "diff-method", "diff-path", "diff-class", "diff-version"):
                for offset in (0, 30, 59, 60, 61):
                    hit = first_level == 1 and not spend and variation == "same" and offset <= 60
                    add({
                        "kind": "cache", "first_level": first_level, "spend": spend,
                        "variation": variation, "offset": offset, "expected_hit": hit,
                        "key": ["cache", first_level, spend, variation, offset],
                    })
    rng = random.Random(SEED + 4)
    for cap in (0, 10, 50):
        seen = set()
        while len(seen) < 64:
            seq = tuple(rng.choice([0, 5, 10, 50]) for _ in range(3))
            seen.add(seq)
        for seq in sorted(seen):
            total, deny_at = 0, None
            for i, amount in enumerate(seq):
                if total + amount > cap:
                    deny_at = i
                    break
                total += amount
            add({"kind": "spend", "cap": cap, "amounts": list(seq),
                 "expected_spent": total, "expected_deny_at": deny_at,
                 "key": ["spend", cap, "+".join(str(a) for a in seq)]})
    for estimated, actual, expected in (
        (0, 0, False), (10, 0, True), (100, 100, False), (119, 100, False),
        (121, 100, True), (80, 100, False), (79, 100, True), (0, 100, True),
        (100, 0, True), (150, 100, True), (99, 100, False), (50, 200, True),
    ):
        add({"kind": "spend-error", "estimated": estimated, "actual": actual,
             "expected": expected,
             "key": ["spend-error", estimated, actual]})
    for detail in ("", "tier flash", "per-session"):
        add({"kind": "spend-copy", "detail": detail,
             "key": ["spend-copy", detail if detail else "empty"]})
    # Pack integrity: mutate one endpoint's level, re-finalise, reload.
    import copy as _copy
    from keyholder.packs import finalise_pack, parse_pack  # noqa: F401 (used by runner via import)
    for provider, rule in ENDPOINTS:
        raw = PACKS[provider].raw
        mutated = _copy.deepcopy(raw)
        for entry in mutated["endpoints"]:
            if entry["method"] == rule.method and entry["path_pattern"] == rule.path_pattern:
                entry["level"] = 1 if rule.level != 1 else 2
                break
        mutated = finalise_pack(mutated)
        add({"kind": "pack-mutate", "provider": provider,
             "method": rule.method, "pattern": rule.path_pattern,
             "mutated_level": 1 if rule.level != 1 else 2,
             "pack": mutated,
             "key": ["pack-mutate", provider, rule.method, rule.path_pattern]})
    for provider in ("github", "gemini"):
        raw = PACKS[provider].raw
        tampered = _copy.deepcopy(raw)
        tampered["content_sha256"] = "0" * 64
        add({"kind": "pack-refused", "provider": provider, "pack": tampered,
             "reason": "hash",
             "key": ["pack-refused", provider, "hash"]})
        for field in ("name", "version", "endpoints", "content_sha256"):
            missing = _copy.deepcopy(raw)
            del missing[field]
            add({"kind": "pack-refused", "provider": provider, "pack": missing,
                 "reason": "missing-" + field,
                 "key": ["pack-refused", provider, "missing-" + field]})
        badcap = _copy.deepcopy(raw)
        badcap["endpoints"][0]["capability"] = "bogus"
        badcap = finalise_pack(badcap)
        add({"kind": "pack-refused", "provider": provider, "pack": badcap,
             "reason": "badcap",
             "key": ["pack-refused", provider, "badcap"]})
        badlevel = _copy.deepcopy(raw)
        badlevel["endpoints"][0]["level"] = 9
        badlevel = finalise_pack(badlevel)
        add({"kind": "pack-refused", "provider": provider, "pack": badlevel,
             "reason": "badlevel",
             "key": ["pack-refused", provider, "badlevel"]})
    secrets = ["TEST-ONLY-scan-key-1", "TEST-ONLY scan key 2",
               "TEST-ONLY-scan/key+3", "TEST-ONLY-scan-key-ü4",
               "TEST-ONLY-scan'key\"5", "TEST-ONLY-scan-key-6"]
    for secret in secrets:
        for encoding in ("raw", "hex-lower", "hex-upper", "quote", "quote-plus",
                         "json-unicode", "json-slash"):
            add({"kind": "secret-scan", "secret": secret, "encoding": encoding,
                 "expected": True,
                 "key": ["secret-scan", secret, encoding]})
        for variant in ("one-char-diff", "prefix-only"):
            add({"kind": "secret-scan", "secret": secret, "encoding": variant,
                 "expected": False,
                 "key": ["secret-scan", secret, variant]})
    for host, expected_ok in (("127.0.0.1", True), ("::1", True),
                              ("0.0.0.0", False), ("8.8.8.8", False),
                              ("192.168.1.1", False), ("localhost", False),
                              ("", False), ("256.1.1.1", False)):
        add({"kind": "loopback", "host": host, "expected_ok": expected_ok,
             "key": ["loopback", host if host else "empty"]})
    base_entry = {"seq": 7, "ts": "2026-10-28T00:00:00+00:00",
                  "prev_hash": "a" * 64, "event_type": "decision",
                  "session_pseudonym": "ps", "key_pseudonym": "pk",
                  "provider": "github", "method": "GET", "canonical_path": "/user",
                  "decision": "allow", "rule_id": "r", "outcome": "relayed",
                  "bytes_in": 0, "bytes_out": 10, "approval_id": None}
    for field in ("decision", "method", "canonical_path", "provider", "seq",
                  "bytes_out", "outcome", "session_pseudonym"):
        add({"kind": "entry-hash", "base": base_entry, "field": field,
             "key": ["entry-hash", field]})
    add({"kind": "entry-hash-same", "base": base_entry,
         "key": ["entry-hash", "same"]})
    return specs


# ------------------------------------------------------------- runners
# Each runner is embedded verbatim into its generated file, so the
# generated files are self-contained. Runner code asserts at least
# two security-relevant facts per case (decision fields, chain links,
# injection vs non-injection, kill/expiry effects, no secret output).

POLICY_RUNNER = r'''
from keyholder.policy import (
    GENERIC_DENIAL, PolicyEngine, agent_denial_message,
    decision_after_approval, evaluate_graphql_body, evaluate_graphql_document,
)

FRESH_NOW = 1793188800
STALE_NOW = 1805112000
PACKS = {}
for _name in ("github", "gemini"):
    PACKS[_name] = load_pack(ROOT / "packs" / (_name + ".json"))

_RAW_BODIES = {
    "dup_top": b'{"a": 1, "a": 2}',
    "dup_nested": b'{"a": {"b": 1, "b": 2}}',
    "dup_array": b'[{"a": 1, "a": 2}]',
    "dup_deep": b'{"a": {"b": {"c": 1, "c": 2}}}',
    "truncated": b'{"a":',
    "trailing_comma": b'{"a": 1,}',
    "bad_utf8": b'\xff\xfe{"a": 1}',
}


def _check_fields(decision, expected):
    assert decision.allowed == expected["allowed"], (decision, expected)
    assert decision.level == expected["level"], (decision, expected)
    assert decision.rule_id == expected["rule_id"], (decision, expected)
    if decision.allowed:
        assert agent_denial_message(decision) == ""
    else:
        assert agent_denial_message(decision) == GENERIC_DENIAL


def run_case(self, spec):
    kind = spec["kind"]
    if kind == "decision":
        engine = PolicyEngine(PACKS[spec["provider"]])
        now = STALE_NOW if spec["stale"] else FRESH_NOW
        body_raw = _RAW_BODIES[spec["body_raw_kind"]] if spec["body_raw_kind"] else None
        ledger = frozenset(spec["ledger"]) if spec["ledger"] is not None else frozenset()
        decision = engine.decide(spec["method"], spec["path"], spec["session_class"],
                                 body=spec["body"], body_raw=body_raw,
                                 allowed_file_uris=ledger, now=now)
        _check_fields(decision, spec["expected"])
    elif kind == "approval":
        engine = PolicyEngine(PACKS[spec["provider"]])
        before = engine.decide(spec["method"], spec["path"], spec["session_class"],
                               now=FRESH_NOW)
        after = decision_after_approval(before)
        _check_fields(after, spec["expected"])
    elif kind == "graphql-doc":
        decision = evaluate_graphql_document(spec["document"],
                                             max_mutations_per_approval=spec["max_mutations"],
                                             session_class=spec["session_class"])
        _check_fields(decision, spec["expected"])
    elif kind == "graphql-batch":
        decisions = evaluate_graphql_body(spec["body"], session_class="write")
        assert len(decisions) == len(spec["expected_list"]), (decisions, spec["expected_list"])
        for decision, expected in zip(decisions, spec["expected_list"]):
            _check_fields(decision, expected)
    else:  # pragma: no cover
        raise AssertionError("unknown policy spec kind: %r" % (kind,))
'''

SESSION_RUNNER = r'''
import time
from keyholder.policy import classify_capability
from keyholder.proxy import ProxyConfig, ProxyEngine
from keyholder.sessions import (
    SessionError, SessionStore, classify, expiry_drain_seconds,
)
from keyholder.tokens import compute_pop, verify_pop
from keyholder.types import Session as TypesSession

BASE_WALL = 1700000000.0
POP_KEY = b"TEST-ONLY-pop-key-00000000000001"
POP_NOW = 1700000000
TTL_TABLE = {"destructive": (600, 900), "write": (1200, 1800),
             "read_account": (1800, 3600), "read_public": (3600, 7200)}
IDLE_DEFAULT = 300


def _live(expires, idle_deadline, t):
    return t < expires and t < idle_deadline


def _offset(session_class, idle, time_kind):
    default_ttl = TTL_TABLE[session_class][0]
    return {"idle-1": idle - 1, "idle": idle, "idle+1": idle + 1,
            "ttl-1": default_ttl - 1, "ttl": default_ttl,
            "ttl+1": default_ttl + 1}[time_kind]


def run_case(self, spec):
    kind = spec["kind"]
    if kind == "create":
        store = SessionStore()
        try:
            session, token = store.create_session(
                "key-TEST-ONLY-scale", spec["provider"], spec["session_class"],
                "pg-scale", requested_ttl_seconds=spec["ttl"],
                idle_seconds=spec["idle"], transport=spec["transport"],
                now_wall=BASE_WALL, now_mono=1000.0)
        except SessionError as exc:
            assert spec["expected_ok"] is False, spec
            assert exc.code == "KH-2001", exc.code
            return
        assert spec["expected_ok"] is True, spec
        assert session.expires_at == BASE_WALL + spec["ttl"], session
        assert session.idle_deadline == BASE_WALL + spec["idle"], session
        assert token.startswith("kh_sess_"), token[:9]
        assert session.session_id.startswith("sess-"), session.session_id
        receipt = store.kill(session.session_id, now_wall=BASE_WALL)
        assert receipt.teardown_within_5s is True, receipt
        return
    if kind == "validate":
        store = SessionStore()
        session, token = store.create_session(
            "key-TEST-ONLY-scale", "github", spec["session_class"], "pg-scale",
            idle_seconds=spec["idle"], now_wall=BASE_WALL, now_mono=1000.0)
        off = _offset(spec["session_class"], spec["idle"], spec["time_kind"])
        t = BASE_WALL + off
        expected_live = _live(session.expires_at, session.idle_deadline, t)
        found = store.validate_token(token, now_wall=t)
        assert (found is not None) == expected_live, (spec, found)
        found2, code = store.validate_token_detailed(token, now_wall=t)
        assert (found2 is not None) == expected_live, (spec, found2)
        if not expected_live:
            assert code == "KH-1002", code
        store.kill(session.session_id, now_wall=t)
        return
    if kind == "no-reset":
        store = SessionStore()
        session, token = store.create_session(
            "key-TEST-ONLY-scale", "github", spec["session_class"], "pg-scale",
            idle_seconds=spec["idle"], now_wall=BASE_WALL, now_mono=1000.0)
        if spec["action"] == "denied":
            store.record_denied_call(session.session_id)
        else:
            store.record_status_poll(session.session_id)
        assert session.idle_deadline == BASE_WALL + spec["idle"], session
        assert store.validate_token(token, now_wall=BASE_WALL + spec["idle"] + 1) is None
        store.kill(session.session_id, now_wall=BASE_WALL)
        return
    if kind == "success-reset":
        store = SessionStore()
        session, token = store.create_session(
            "key-TEST-ONLY-scale", "github", spec["session_class"], "pg-scale",
            idle_seconds=spec["idle"], now_wall=BASE_WALL, now_mono=1000.0)
        t1 = BASE_WALL + spec["idle"] - 1
        assert store.record_successful_call(session.session_id, now_wall=t1) is True
        assert session.idle_deadline == t1 + spec["idle"], session
        t2 = BASE_WALL + spec["idle"] + 1
        expected_live = _live(session.expires_at, session.idle_deadline, t2)
        assert (store.validate_token(token, now_wall=t2) is not None) == expected_live
        store.kill(session.session_id, now_wall=t2)
        return
    if kind == "kill":
        store = SessionStore()
        session, token = store.create_session(
            "key-TEST-ONLY-scale", "github", spec["session_class"], "pg-scale",
            idle_seconds=spec["idle"], now_wall=BASE_WALL, now_mono=1000.0)
        t = BASE_WALL + spec["idle"] - 1
        receipt = store.kill(session.session_id, now_wall=t)
        assert receipt is not None, spec
        assert receipt.teardown_within_5s is True, receipt
        assert receipt.deny_list_latency_s == 0.0, receipt
        assert receipt.in_flight_at_kill == [], receipt
        assert store.validate_token(token, now_wall=t) is None
        _, code = store.validate_token_detailed(token, now_wall=t)
        assert code == "KH-1002", code
        return
    if kind == "prune":
        store = SessionStore()
        session, token = store.create_session(
            "key-TEST-ONLY-scale", "github", spec["session_class"], "pg-scale",
            idle_seconds=spec["idle"], now_wall=BASE_WALL, now_mono=1000.0)
        off = _offset(spec["session_class"], spec["idle"], spec["time_kind"])
        t = BASE_WALL + off
        expected_live = _live(session.expires_at, session.idle_deadline, t)
        pruned = store.prune_expired(now_wall=t)
        # v0.2: prune tears down ABSOLUTE-EXPIRED sessions only; an
        # idle-suspended session is pruned only at absolute expiry.
        assert (session.session_id in pruned) == (t >= session.expires_at), (spec, pruned)
        assert (session.session_id in store.live_session_ids(now_wall=t)) == expected_live
        return
    if kind in ("killall", "killall-mixed"):
        store = SessionStore()
        classes = SESSION_CLASSES if kind == "killall-mixed" else [spec["session_class"]]
        created = []
        for cls in classes:
            session, token = store.create_session(
                "key-TEST-ONLY-scale", "github", cls, "pg-scale",
                now_wall=BASE_WALL, now_mono=1000.0)
            created.append((session, token))
        receipt = store.kill_all(now_wall=BASE_WALL + 10)
        assert set(receipt.killed_session_ids) == {s.session_id for s, _ in created}, receipt
        for session, token in created:
            assert store.validate_token(token, now_wall=BASE_WALL + 10) is None
        return
    if kind == "inflight":
        store = SessionStore()
        session, token = store.create_session(
            "key-TEST-ONLY-scale", "github", spec["session_class"], "pg-scale",
            now_wall=BASE_WALL, now_mono=1000.0)
        assert store.begin_call(session.session_id, "call-1") is True
        assert store.begin_call(session.session_id, "call-2") is True
        if spec["complete_one"]:
            store.complete_call(session.session_id, "call-1")
        receipt = store.kill(session.session_id, now_wall=BASE_WALL)
        expected = ["call-2"] if spec["complete_one"] else ["call-1", "call-2"]
        assert receipt.in_flight_at_kill == expected, receipt
        return
    if kind == "badkey":
        store = SessionStore()
        try:
            store.create_session(spec["bad_key"], "github", "read_public", "pg-scale",
                                 now_wall=BASE_WALL, now_mono=1000.0)
        except SessionError as exc:
            assert exc.code == "KH-2001", exc.code
            return
        raise AssertionError("bad key_id accepted: %r" % (spec["bad_key"],))
    if kind == "noextend":
        assert not hasattr(SessionStore(), "extend"), "extend must not exist"
        return
    if kind == "pop":
        body = {"empty": b"", "json": b'{"a": 1}', "x64": b"x" * 64}[spec["body_kind"]]
        pop = compute_pop(POP_KEY, "GET", "api.github.com", "/user", body, POP_NOW)
        verify = {"method": "GET", "host": "api.github.com", "path": "/user",
                  "body": body, "timestamp": POP_NOW, "pop": pop}
        tamper = spec["tamper"]
        if tamper == "method":
            verify["method"] = "POST"
        elif tamper == "host":
            verify["host"] = "evil.example.com"
        elif tamper == "path":
            verify["path"] = "/admin"
        elif tamper == "body":
            verify["body"] = b'{"a": 2}' if body != b'{"a": 2}' else b'{"a": 3}'
        elif tamper == "pop-flip":
            verify["pop"] = ("1" if pop[0] == "0" else "0") + pop[1:]
        elif tamper == "pop-truncate":
            verify["pop"] = pop[:10]
        elif tamper == "pop-empty":
            verify["pop"] = ""
        elif tamper == "pop-none":
            verify["pop"] = None
        elif tamper == "pop-upper":
            upper = pop.upper()
            verify["pop"] = upper if upper != pop else upper + "0"
        result = verify_pop(POP_KEY, verify["method"], verify["host"], verify["path"],
                            verify["body"], verify["timestamp"], verify["pop"], now=POP_NOW)
        assert result == spec["expected"], (spec, result)
        return
    if kind == "pop-skew":
        ts = POP_NOW + spec["offset"]
        pop = compute_pop(POP_KEY, "GET", "api.github.com", "/user", b'{"a": 1}', ts)
        result = verify_pop(POP_KEY, "GET", "api.github.com", "/user", b'{"a": 1}',
                            ts, pop, now=POP_NOW)
        assert result == spec["expected"], (spec, result)
        return
    if kind == "pop-tstype":
        ts_map = {"str-valid": str(POP_NOW), "str-invalid": "not-a-time",
                  "none": None, "float": POP_NOW + 0.9}
        ts = ts_map[spec["ts_kind"]]
        pop = compute_pop(POP_KEY, "GET", "api.github.com", "/user", b"", POP_NOW)
        result = verify_pop(POP_KEY, "GET", "api.github.com", "/user", b"",
                            ts, pop, now=POP_NOW)
        assert result == spec["expected"], (spec, ts, result)
        return
    if kind == "pop-sequence":
        store = SessionStore()
        session, token = store.create_session(
            "key-TEST-ONLY-scale", "github", "write", "pg-scale",
            now_wall=BASE_WALL, now_mono=1000.0)
        pop_key = store._pop_keys[session.session_id]
        ts = int(BASE_WALL)

        def auth(method="GET", body=b"", timestamp=ts, pop=None, when=BASE_WALL):
            if pop is None:
                pop = compute_pop(pop_key, method, "api.github.com", "/user", body, timestamp)
            return store.authenticate_request(token, method, "api.github.com", "/user",
                                              body, timestamp, pop, now_wall=when)

        name = spec["name"]
        if name == "replay-first-ok":
            assert auth() is not None
        elif name == "replay-second":
            assert auth() is not None
            assert auth() is None, "PoP replay must be denied"
        elif name == "new-timestamp-ok":
            assert auth() is not None
            assert auth(timestamp=ts + 1) is not None
        elif name == "tampered-after":
            assert auth() is not None
            pop_get = compute_pop(pop_key, "GET", "api.github.com", "/user", b"", ts)
            assert store.authenticate_request(token, "POST", "api.github.com", "/user",
                                              b"", ts, pop_get, now_wall=BASE_WALL) is None
        elif name == "missing-pop":
            assert store.authenticate_request(token, "GET", "api.github.com", "/user",
                                              b"", ts, None, now_wall=BASE_WALL) is None
        elif name == "missing-ts":
            pop = compute_pop(pop_key, "GET", "api.github.com", "/user", b"", ts)
            assert store.authenticate_request(token, "GET", "api.github.com", "/user",
                                              b"", None, pop, now_wall=BASE_WALL) is None
        elif name == "killed-session":
            store.kill(session.session_id, now_wall=BASE_WALL)
            assert auth() is None
        elif name == "expired-session":
            when = BASE_WALL + 1201
            pop_fresh = compute_pop(pop_key, "GET", "api.github.com", "/user", b"", int(when))
            assert store.authenticate_request(token, "GET", "api.github.com", "/user",
                                              b"", int(when), pop_fresh, now_wall=when) is None
        elif name == "idle-session":
            when = BASE_WALL + 301
            pop_fresh = compute_pop(pop_key, "GET", "api.github.com", "/user", b"", int(when))
            assert store.authenticate_request(token, "GET", "api.github.com", "/user",
                                              b"", int(when), pop_fresh, now_wall=when) is None
        else:  # pragma: no cover
            raise AssertionError(name)
        return
    if kind == "classify":
        result = classify(spec["method"], "", destructive=spec["destructive"],
                          paid_inference=spec["paid"], financial=spec["financial"],
                          read_like_post=spec["read_like"], public_read=spec["public"])
        assert result == spec["expected"], (spec, result)
        return
    if kind == "capability":
        assert classify_capability(spec["capabilities"]) == spec["expected"], spec
        return
    if kind == "capability-error":
        try:
            classify_capability(spec["capabilities"])
        except ValueError:
            return
        raise AssertionError("capability list accepted: %r" % (spec["capabilities"],))
    if kind == "drain":
        assert expiry_drain_seconds(spec["session_class"]) == spec["expected"], spec
        return
    if kind == "drain-error":
        try:
            expiry_drain_seconds(spec["session_class"])
        except SessionError:
            return
        raise AssertionError("drain accepted: %r" % (spec["session_class"],))
    if kind in ("connect", "connect-dead", "connect-auth"):
        now = time.time()
        session = TypesSession(
            session_id="sess-test", key_id="key-TEST-ONLY", provider="github",
            session_class=spec.get("session_class", "read_public"),
            transport=spec.get("transport", "connect_allowed"),
            created_at=now - 10, expires_at=now + 3600,
            idle_deadline=now + 300, process_group="pg", ancestry="")
        if kind == "connect-dead":
            if spec["state"] == "killed":
                session.killed = True
            elif spec["state"] == "expired":
                session.expires_at = now - 10
            else:
                session.idle_deadline = now - 10
        recorded = []

        def audit_decision(entry):
            recorded.append(entry)

        engine = ProxyEngine(
            ProxyConfig(test_mode=spec.get("test_mode", True),
                        connect_hosts=frozenset({"api.github.com"})),
            lookup_session=lambda tok: session if tok == "tok-test" else None,
            pop_key_for=lambda sid: POP_KEY,
            decide=None, approve=None, audit_decision=audit_decision,
            audit_outcome=None, key_for=lambda kid: None,
            connect_host_allowed=lambda s, h: h == "hook.example.com")
        authority = spec.get("authority", "127.0.0.1:8443")
        host_part = authority.rpartition(":")[0] if ":" in authority else authority
        ts = int(time.time())
        pop = compute_pop(POP_KEY, "CONNECT", host_part, "/", b"", ts)
        headers = [("X-Keyholder-Session", "tok-test"),
                   ("X-Keyholder-Pop", pop),
                   ("X-Keyholder-Timestamp", str(ts))]
        if kind == "connect-auth" and spec["name"] == "missing-token":
            headers = [h for h in headers if h[0] != "X-Keyholder-Session"]
            decision = engine.authorize_connect(authority, headers)
            assert decision.allowed is False, decision
            return
        if kind == "connect-auth" and spec["name"] == "missing-pop":
            headers = [h for h in headers if h[0] != "X-Keyholder-Pop"]
            decision = engine.authorize_connect(authority, headers)
            assert decision.allowed is False, decision
            return
        if kind == "connect-auth" and spec["name"] == "bad-pop":
            headers = [(k, ("0" if v[0] != "0" else "1") + v[1:] if k == "X-Keyholder-Pop" else v)
                       for k, v in headers]
            decision = engine.authorize_connect(authority, headers)
            assert decision.allowed is False, decision
            return
        if kind == "connect-auth" and spec["name"] == "replay":
            first = engine.authorize_connect(authority, headers)
            second = engine.authorize_connect(authority, headers)
            assert first.allowed is True, first
            assert second.allowed is False, second
            return
        decision = engine.authorize_connect(authority, headers)
        assert decision.allowed == spec["expected"], (spec, decision)
        if decision.allowed:
            assert recorded, "allowed CONNECT must be audited"
            assert recorded[-1]["transport_label"] == "HOST-ONLY POLICY", recorded[-1]
        return
    raise AssertionError("unknown session spec kind: %r" % (kind,))  # pragma: no cover
'''


AUDIT_RUNNER = r'''
import json
import tempfile
from pathlib import Path
from keyholder.audit import (
    AuditLog, SecretDetectedError, SecretScrubber, entry_hash_of, pseudonym,
)

SECRET_A = b"TEST-ONLY-audit-secret-A"
SECRETS = {"A": b"TEST-ONLY-audit-secret-A",
           "B": b"TEST-ONLY-audit-secret-B",
           "C": b"TEST-ONLY-audit-secret-C"}


def _stream(log, length, variant):
    entries = []
    for i in range(length):
        sp = pseudonym(SECRET_A, "sess-%d-%d" % (variant, i))
        kp = pseudonym(SECRET_A, "key-%d-%d" % (variant, i))
        provider = "github" if (i + variant) % 2 == 0 else "gemini"
        method = ("GET", "POST", "DELETE")[i % 3]
        decision = "allow" if i % 2 == 0 else "deny"
        entry = log.write_event(
            "decision", sp, kp, provider, method, "/obj/%d/%d" % (variant, i),
            decision, rule_id="rule-%d" % i,
            outcome="relayed" if decision == "allow" else "denied",
            bytes_in=i * 7, bytes_out=i * 11,
            approval_id=("appr-%d" % i) if i % 2 == 0 else None)
        entries.append(entry)
    return entries


def _read_entries(log):
    lines = [ln for ln in log.live_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return [json.loads(ln) for ln in lines]


def _assert_chain(log, length):
    entries = _read_entries(log)
    assert len(entries) == length + 1, (len(entries), length)
    assert [e["seq"] for e in entries] == list(range(1, length + 2)), entries
    for prev, cur in zip(entries, entries[1:]):
        assert cur["prev_hash"] == prev["entry_hash"], (prev, cur)
    for entry in entries:
        without = {k: v for k, v in entry.items() if k != "entry_hash"}
        assert entry_hash_of(without) == entry["entry_hash"], entry
    result = log.verify()
    assert result.status == "OK", result
    assert result.entries == length + 1, result


def run_case(self, spec):
    kind = spec["kind"]
    if kind == "sequence":
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp), SECRET_A)
            entries = _stream(log, spec["length"], spec["variant"])
            for i, entry in enumerate(entries):
                assert entry["seq"] == i + 2, entry
            _assert_chain(log, spec["length"])
            text = log.live_path.read_text(encoding="utf-8")
            for i in range(spec["length"]):
                assert ("sess-%d-%d" % (spec["variant"], i)) not in text, "raw id leaked"
                assert ("key-%d-%d" % (spec["variant"], i)) not in text, "raw id leaked"
                assert pseudonym(SECRET_A, "sess-%d-%d" % (spec["variant"], i)) in text
            log.close()
        return
    if kind == "tamper":
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp), SECRET_A)
            _stream(log, spec["length"], 0)
            lines = [ln for ln in log.live_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            entry = json.loads(lines[spec["position"]])
            tamper = spec["tamper"]
            if tamper == "decision":
                entry["decision"] = "deny" if entry["decision"] != "deny" else "allow"
            elif tamper == "method":
                entry["method"] = "POST" if entry["method"] != "POST" else "GET"
            elif tamper == "path":
                entry["canonical_path"] = "/tampered"
            elif tamper == "seq":
                entry["seq"] = entry["seq"] + 100
            elif tamper == "hash":
                h = entry["entry_hash"]
                entry["entry_hash"] = ("0" if h[0] != "0" else "1") + h[1:]
            elif tamper == "bytes":
                entry["bytes_in"] = entry["bytes_in"] + 1
            lines[spec["position"]] = json.dumps(entry, sort_keys=True)
            log.live_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            result = log.verify()
            assert result.status == "TAMPERED", (spec, result)
            log.close()
        return
    if kind == "tamper-op":
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp), SECRET_A)
            _stream(log, spec["length"], 0)
            lines = [ln for ln in log.live_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            op = spec["op"]
            if op == "delete":
                del lines[2]
            elif op == "duplicate":
                lines.insert(3, lines[2])
            elif op == "forged":
                lines.append(json.dumps({"seq": 999, "prev_hash": "0" * 64,
                                         "entry_hash": "1" * 64,
                                         "event_type": "decision"}, sort_keys=True))
            elif op == "malformed":
                lines.append("not json {{{")
            log.live_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            result = log.verify()
            assert result.status == "TAMPERED", (spec, result)
            log.close()
        return
    if kind == "range":
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp), SECRET_A)
            _stream(log, spec["length"], 0)
            result = log.verify_range(spec["from_seq"], spec["to_seq"])
            assert result.status == spec["expected"], (spec, result)
            log.close()
        return
    if kind == "pseudonym":
        secret = SECRETS[spec["secret_label"]]
        p = pseudonym(secret, spec["key_id"])
        assert len(p) == 16, p
        assert all(c in "0123456789abcdef" for c in p), p
        assert p == pseudonym(secret, spec["key_id"]), "pseudonym must be deterministic"
        assert p != spec["key_id"], "pseudonym must not be the raw id"
        assert pseudonym(secret, spec["key_id"] + "x") != p, "ids must differ"
        other_secret = SECRETS["B" if spec["secret_label"] != "B" else "A"]
        assert pseudonym(other_secret, spec["key_id"]) != p, "secrets must differ"
        return
    if kind == "scrub":
        with tempfile.TemporaryDirectory() as tmp:
            scrubber = SecretScrubber()
            scrubber.add_secret(spec["secret"])
            log = AuditLog(Path(tmp), SECRET_A, scrubber=scrubber)
            before = len(_read_entries(log))
            kwargs = {"event_type": "decision", "session_pseudonym": "s",
                      "key_pseudonym": "k", "provider": "github", "method": "GET",
                      "canonical_path": "/p", "decision": "allow"}
            kwargs[spec["field"]] = "/x/" + spec["secret"] if spec["field"] == "canonical_path" else "GET-" + spec["secret"]
            try:
                log.write_event(**kwargs)
            except SecretDetectedError:
                pass
            else:
                raise AssertionError("secret in audit field was not refused: %r" % (spec,))
            assert len(_read_entries(log)) == before, "refused entry must not append"
            assert log.verify().status == "OK", log.verify()
            log.close()
        return
    if kind == "scrub-clean":
        with tempfile.TemporaryDirectory() as tmp:
            scrubber = SecretScrubber()
            scrubber.add_secret("TEST-ONLY-secret-xyz")
            log = AuditLog(Path(tmp), SECRET_A, scrubber=scrubber)
            log.write_event("decision", "s", "k", "github", "GET", "/clean", "allow")
            assert log.verify().status == "OK", log.verify()
            log.close()
        return
    if kind == "anchor":
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp), SECRET_A)
            _stream(log, spec["length"], 0)
            log.anchor()
            result = log.verify()
            assert result.status == "OK", result
            assert result.anchored is True, result
            log.close()
        return
    if kind == "csv":
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp), SECRET_A)
            _stream(log, spec["length"], spec["variant"])
            csv_text = log.export_csv()
            assert csv_text.startswith("seq,ts,"), csv_text[:50]
            rows = csv_text.splitlines()
            assert len(rows) == spec["length"] + 2, rows
            for i in range(spec["length"]):
                assert ("sess-%d-%d" % (spec["variant"], i)) not in csv_text
                assert pseudonym(SECRET_A, "sess-%d-%d" % (spec["variant"], i)) in csv_text
            log.close()
        return
    raise AssertionError("unknown audit spec kind: %r" % (kind,))  # pragma: no cover
'''

MALFORMED_RUNNER = r'''
import urllib.parse
from keyholder.policy import (
    CanonicalisationError, canonicalise_path, match_pattern,
    parse_json_no_duplicates,
)
from keyholder.proxy import (
    GENERIC_DENIAL_BODY, ProxyConfig, ProxyEngine, canonicalise_target,
)


def run_case(self, spec):
    kind = spec["kind"]
    if kind == "policy-canon":
        if spec["expected"] is None:
            try:
                canonicalise_path(spec["path"])
            except CanonicalisationError:
                return
            raise AssertionError("path accepted: %r" % (spec["path"],))
        assert canonicalise_path(spec["path"]) == spec["expected"], spec
        return
    if kind == "policy-fuzz":
        try:
            result = canonicalise_path(spec["path"])
        except CanonicalisationError:
            return
        assert result.startswith("/"), result
        segments = result.split("/")[1:]
        assert all(s not in ("", ".", "..") for s in segments), result
        assert "\x00" not in result and "\\" not in result, result
        assert canonicalise_path(result) == result, (spec["path"], result)
        return
    if kind == "policy-fuzz-raise":
        try:
            canonicalise_path(spec["path"])
        except CanonicalisationError:
            return
        raise AssertionError("dot/empty segment accepted: %r" % (spec["path"],))
    if kind == "proxy-target":
        try:
            target = canonicalise_target(spec["target"], spec["host"], spec["base"],
                                          test_mode=spec["test_mode"])
        except ValueError:
            assert spec["expected_canon"] is None, spec
            return
        assert spec["expected_canon"] is not None, spec
        assert target.canonical_path == spec["expected_canon"], target
        assert target.forward_path == spec["expected_fwd"], target
        return
    if kind == "proxy-fuzz":
        try:
            target = canonicalise_target(spec["target"], spec["host"], spec["base"],
                                          test_mode=True)
        except ValueError:
            return
        base_host = urllib.parse.urlsplit(spec["base"]).hostname
        assert target.host.startswith(base_host), target
        canon_path = target.canonical_path.split("?", 1)[0]
        fwd_path = target.forward_path.split("?", 1)[0]
        canon_segs = canon_path.split("/")[1:]
        fwd_segs = [urllib.parse.unquote(s) for s in fwd_path.split("/")[1:]]
        assert canon_segs == fwd_segs, (canon_path, fwd_path)
        query = target.canonical_path.split("?", 1)[1] if "?" in target.canonical_path else ""
        for pair in query.split("&"):
            name = urllib.parse.unquote_plus(pair.split("=", 1)[0]).lower()
            assert name not in ("key", "api_key", "apikey", "access_token", "token", "secret"), query
        return
    if kind == "proxy-header":
        engine = ProxyEngine(
            ProxyConfig(), lookup_session=lambda tok: None,
            pop_key_for=lambda sid: None, decide=None, approve=None,
            audit_decision=None, audit_outcome=None, key_for=lambda kid: None)
        resp = engine.handle(spec["method"], "/user", spec["headers"], b"")
        assert resp.status == spec["expected_status"], (spec, resp.status)
        assert resp.body == GENERIC_DENIAL_BODY, resp.body
        return
    if kind == "json-dup":
        try:
            parsed = parse_json_no_duplicates(spec["raw"])
        except ValueError:
            assert spec["expected_raise"] is True, spec
            return
        assert spec["expected_raise"] is False, spec
        assert isinstance(parsed, (dict, list)), parsed
        return
    if kind in ("glob-nomatch", "glob"):
        assert match_pattern(spec["pattern"], spec["path"]) == spec["expected"], spec
        return
    raise AssertionError("unknown malformed spec kind: %r" % (kind,))  # pragma: no cover
'''

PROXY_RUNNER = r'''
import http.server
import threading
import time
import urllib.parse
from keyholder.broker import Broker
from keyholder.packs import load_pack
from keyholder.policy import PolicyEngine
from keyholder.proxy import GENERIC_DENIAL_BODY, ProxyConfig, ProxyEngine
from keyholder.tokens import compute_pop

FRESH_NOW = 1793188800
FAKE_KEYS = {"github": "TEST-ONLY-gh-proxy-key", "gemini": "TEST-ONLY-gemini-proxy-key"}
PACK_ENGINES = {name: PolicyEngine(load_pack(ROOT / "packs" / (name + ".json")))
                for name in ("github", "gemini")}
HITS = []
SERVER = None
BASES = {}


class _MockHandler(http.server.BaseHTTPRequestHandler):
    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        resp_kind = query.get("resp", [None])[0]
        auth = self.headers.get("Authorization", "")
        gkey = self.headers.get("X-Goog-Api-Key", "")
        key = auth[7:] if auth.startswith("Bearer ") else gkey
        HITS.append({"method": self.command, "path": parsed.path,
                     "auth": auth, "gkey": gkey})
        if resp_kind == "secret":
            payload = ("leak:" + key).encode()
            extra = []
        elif resp_kind == "secrethex":
            payload = key.encode().hex().encode()
            extra = []
        elif resp_kind == "credential":
            payload = b'{"access_token": "TEST-ONLY-minted-token"}'
            extra = []
        elif resp_kind == "credential-nested":
            payload = b'{"data": {"refresh_token": "TEST-ONLY-minted-2"}}'
            extra = []
        elif resp_kind == "credential-list":
            payload = b'[{"api_key": "TEST-ONLY-minted-3"}]'
            extra = []
        elif resp_kind == "secret-header":
            payload = b'{"ok": true}'
            extra = [("X-Leak", key)]
        else:
            payload = b'{"ok": true}'
            extra = []
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        for k, v in extra:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

    def log_message(self, *args):
        pass


def _ensure_server():
    """Start the loopback mock on demand. setUpModule normally does
    this, but a test must never depend on module-fixture ordering
    alone: if setUpModule did not run for this module object (e.g. a
    second import of the file under another module name in a big
    discovery run), the first test starts the server itself instead
    of failing with an empty BASES map."""
    global SERVER
    if SERVER is not None:
        return
    SERVER = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MockHandler)
    SERVER.daemon_threads = True
    port = SERVER.server_address[1]
    BASES["github"] = "http://127.0.0.1:%d" % port
    BASES["gemini"] = "http://127.0.0.1:%d" % port
    thread = threading.Thread(target=SERVER.serve_forever, daemon=True)
    thread.start()


def setUpModule():
    _ensure_server()


def tearDownModule():
    global SERVER
    if SERVER is not None:
        SERVER.shutdown()
        SERVER.server_close()
        SERVER = None
    BASES.clear()


def _signed(token, pop_key, method, host, path, body=b""):
    ts = int(time.time())
    pop = compute_pop(pop_key, method, host, path, body, ts)
    return [("X-Keyholder-Session", token), ("X-Keyholder-Pop", pop),
            ("X-Keyholder-Timestamp", str(ts))]


def _make_proxy(broker, created, provider, approve_fn, decisions, outcomes):
    def decide(session, method, path, body, content_type):
        engine = PACK_ENGINES[session.provider]
        return engine.decide(method, path, session.session_class,
                             body_raw=body if body else None, now=FRESH_NOW)

    return ProxyEngine(
        ProxyConfig(bases={provider: BASES[provider]}, test_mode=True),
        lookup_session=broker.validate_token,
        pop_key_for=lambda sid: created.pop_key if sid == created.session.session_id else None,
        decide=decide, approve=approve_fn,
        audit_decision=lambda e: decisions.append(e),
        audit_outcome=lambda e: outcomes.append(e),
        key_for=lambda kid: FAKE_KEYS[provider],
        on_success=lambda sid: None)


def _host(provider):
    return "127.0.0.1:%d" % int(BASES[provider].rsplit(":", 1)[1])


def run_case(self, spec):
    _ensure_server()
    kind = spec["kind"]
    if kind == "endpoint":
        provider = spec["provider"]
        broker = Broker()
        created = broker.create_session(
            key_id="key-TEST-ONLY-proxy", provider=provider,
            session_class=spec["session_class"], process_group="pg-scale")
        approve_calls = []

        def approve(session, method, path, scope):
            approve_calls.append((method, path))
            if spec["approve"] is None:
                return (False, None)
            return (spec["approve"], "appr-scale-1" if spec["approve"] else None)

        decisions, outcomes = [], []
        proxy = _make_proxy(broker, created, provider, approve, decisions, outcomes)
        before = len(HITS)
        headers = _signed(created.token, created.pop_key, spec["method"],
                          _host(provider), spec["path"])
        resp = proxy.handle(spec["method"], BASES[provider] + spec["path"], headers, b"")
        key = FAKE_KEYS[provider]
        if spec["expected_relay"]:
            assert resp.status == 200, (spec, resp.status, resp.body)
            assert len(HITS) == before + 1, (spec, HITS[before:])
            hit = HITS[-1]
            assert hit["path"] == spec["path"], hit
            if provider == "github":
                assert hit["auth"] == "Bearer " + key, hit
                assert hit["gkey"] == "", hit
            else:
                assert hit["gkey"] == key, hit
                assert hit["auth"] == "", hit
            assert key.encode() not in resp.body, "real key leaked to agent"
            assert decisions and decisions[-1]["decision"] == "allow", decisions
            assert decisions[-1]["level"] == spec["expected_level"], decisions[-1]
            assert outcomes and outcomes[-1]["outcome"] == "relayed", outcomes
            if spec["approve"] is not None:
                assert approve_calls, "approval-gated call must consult approver"
        else:
            assert resp.status == 403, (spec, resp.status)
            assert resp.body == GENERIC_DENIAL_BODY, resp.body
            assert len(HITS) == before, (spec, HITS[before:])
            assert len(decisions) == 0, "denied call must not write a decision entry"
        return
    if kind == "blocking":
        provider = spec["provider"]
        session_class = "read_account" if provider == "github" else "read_public"
        broker = Broker()
        created = broker.create_session(
            key_id="key-TEST-ONLY-proxy", provider=provider,
            session_class=session_class, process_group="pg-scale")
        decisions, outcomes = [], []
        proxy = _make_proxy(broker, created, provider,
                            lambda s, m, p, sc: (True, "appr-scale-1"),
                            decisions, outcomes)
        target_path = spec["path"] + "?resp=" + spec["resp"]
        headers = _signed(created.token, created.pop_key, "GET",
                          _host(provider), target_path)
        resp = proxy.handle("GET", BASES[provider] + target_path, headers, b"")
        if spec["expected_blocked"]:
            assert resp.status == 502, (spec, resp.status)
            assert resp.body == GENERIC_DENIAL_BODY, resp.body
            assert outcomes and outcomes[-1]["outcome"] == "blocked", outcomes
            assert outcomes[-1]["bytes_out"] == 0, outcomes[-1]
        else:
            assert resp.status == 200, (spec, resp.status)
            assert outcomes and outcomes[-1]["outcome"] == "relayed", outcomes
        return
    if kind == "auth":
        broker = Broker()
        created = broker.create_session(
            key_id="key-TEST-ONLY-proxy", provider="github",
            session_class="read_account", process_group="pg-scale")
        decisions, outcomes = [], []
        proxy = _make_proxy(broker, created, "github",
                            lambda s, m, p, sc: (True, "appr-scale-1"),
                            decisions, outcomes)
        name = spec["name"]
        base_headers = _signed(created.token, created.pop_key, "GET",
                               _host("github"), "/user")

        def call(headers):
            before = len(HITS)
            resp = proxy.handle("GET", BASES["github"] + "/user", headers, b"")
            return resp, before

        if name == "missing-token":
            headers = [h for h in base_headers if h[0] != "X-Keyholder-Session"]
            resp, before = call(headers)
            assert resp.status == 401 and resp.body == GENERIC_DENIAL_BODY
            assert len(HITS) == before
        elif name == "unknown-token":
            headers = [(k, "kh_sess_" + "x" * 32 if k == "X-Keyholder-Session" else v)
                       for k, v in base_headers]
            resp, before = call(headers)
            assert resp.status == 401 and resp.body == GENERIC_DENIAL_BODY
            assert len(HITS) == before
        elif name == "missing-pop":
            headers = [h for h in base_headers if h[0] != "X-Keyholder-Pop"]
            resp, before = call(headers)
            assert resp.status == 401 and resp.body == GENERIC_DENIAL_BODY
            assert len(HITS) == before
        elif name == "bad-pop":
            headers = [(k, ("0" if v[0] != "0" else "1") + v[1:] if k == "X-Keyholder-Pop" else v)
                       for k, v in base_headers]
            resp, before = call(headers)
            assert resp.status == 401 and resp.body == GENERIC_DENIAL_BODY
            assert len(HITS) == before
        elif name == "replay":
            resp, _ = call(base_headers)
            assert resp.status == 200, resp.status
            before = len(HITS)
            resp, _ = call(base_headers)
            assert resp.status == 401 and resp.body == GENERIC_DENIAL_BODY
            assert len(HITS) == before
        elif name == "killed":
            broker.kill_session(created.session.session_id)
            resp, before = call(base_headers)
            assert resp.status == 401 and resp.body == GENERIC_DENIAL_BODY
            assert len(HITS) == before
        elif name == "expired":
            created.session.expires_at = time.time() - 10
            resp, before = call(base_headers)
            assert resp.status == 401 and resp.body == GENERIC_DENIAL_BODY
            assert len(HITS) == before
        elif name == "idle":
            created.session.idle_deadline = time.time() - 10
            resp, before = call(base_headers)
            assert resp.status == 401 and resp.body == GENERIC_DENIAL_BODY
            assert len(HITS) == before
        return
    if kind == "audit-fail-decision":
        provider = spec["provider"]
        broker = Broker()
        created = broker.create_session(
            key_id="key-TEST-ONLY-proxy", provider=provider,
            session_class="read_account", process_group="pg-scale")

        def decide(session, method, path, body, content_type):
            return PACK_ENGINES[session.provider].decide(
                method, path, session.session_class, now=FRESH_NOW)

        def boom(entry):
            raise RuntimeError("TEST-ONLY audit failure")

        proxy = ProxyEngine(
            ProxyConfig(bases={provider: BASES[provider]}, test_mode=True),
            lookup_session=broker.validate_token,
            pop_key_for=lambda sid: created.pop_key,
            decide=decide, approve=lambda s, m, p, sc: (True, "a"),
            audit_decision=boom, audit_outcome=lambda e: None,
            key_for=lambda kid: FAKE_KEYS[provider])
        before = len(HITS)
        headers = _signed(created.token, created.pop_key, "GET",
                          _host(provider), spec["path"])
        resp = proxy.handle("GET", BASES[provider] + spec["path"], headers, b"")
        assert resp.status == 503, (spec, resp.status)
        assert resp.body == GENERIC_DENIAL_BODY, resp.body
        assert len(HITS) == before, "audit failure must not forward"
        return
    if kind == "audit-fail-outcome":
        broker = Broker()
        created = broker.create_session(
            key_id="key-TEST-ONLY-proxy", provider="github",
            session_class="read_account", process_group="pg-scale")

        def decide(session, method, path, body, content_type):
            return PACK_ENGINES["github"].decide(method, path, session.session_class,
                                                 now=FRESH_NOW)

        def boom(entry):
            raise RuntimeError("TEST-ONLY audit failure")

        proxy = ProxyEngine(
            ProxyConfig(bases={"github": BASES["github"]}, test_mode=True),
            lookup_session=broker.validate_token,
            pop_key_for=lambda sid: created.pop_key,
            decide=decide, approve=lambda s, m, p, sc: (True, "a"),
            audit_decision=lambda e: None, audit_outcome=boom,
            key_for=lambda kid: FAKE_KEYS["github"])
        headers = _signed(created.token, created.pop_key, "GET", _host("github"), "/user")
        first = proxy.handle("GET", BASES["github"] + "/user", headers, b"")
        assert first.status == 200, "already-forwarded call cannot be recalled"
        headers2 = _signed(created.token, created.pop_key, "GET", _host("github"), "/user")
        second = proxy.handle("GET", BASES["github"] + "/user", headers2, b"")
        assert second.status == 503, "degraded proxy must refuse new calls"
        assert second.body == GENERIC_DENIAL_BODY, second.body
        return
    if kind == "oversize-body":
        broker = Broker()
        created = broker.create_session(
            key_id="key-TEST-ONLY-proxy", provider="github",
            session_class="read_account", process_group="pg-scale")
        proxy = _make_proxy(broker, created, "github",
                            lambda s, m, p, sc: (True, "a"), [], [])
        body = b"x" * (32 * 1024 * 1024 + 1)
        headers = _signed(created.token, created.pop_key, "GET", _host("github"), "/user", body)
        resp = proxy.handle("GET", BASES["github"] + "/user", headers, body)
        assert resp.status == 413, resp.status
        assert resp.body == GENERIC_DENIAL_BODY, resp.body
        return
    if kind == "length-mismatch":
        broker = Broker()
        created = broker.create_session(
            key_id="key-TEST-ONLY-proxy", provider="github",
            session_class="read_account", process_group="pg-scale")
        proxy = _make_proxy(broker, created, "github",
                            lambda s, m, p, sc: (True, "a"), [], [])
        headers = _signed(created.token, created.pop_key, "GET", _host("github"), "/user")
        headers.append(("Content-Length", "5"))
        resp = proxy.handle("GET", BASES["github"] + "/user", headers, b"hello world longer")
        assert resp.status == 400, resp.status
        assert resp.body == GENERIC_DENIAL_BODY, resp.body
        return
    if kind == "transfer-encoding":
        broker = Broker()
        created = broker.create_session(
            key_id="key-TEST-ONLY-proxy", provider="github",
            session_class="read_account", process_group="pg-scale")
        proxy = _make_proxy(broker, created, "github",
                            lambda s, m, p, sc: (True, "a"), [], [])
        headers = _signed(created.token, created.pop_key, "GET", _host("github"), "/user")
        headers.append(("Transfer-Encoding", "chunked"))
        resp = proxy.handle("GET", BASES["github"] + "/user", headers, b"")
        assert resp.status == 400, resp.status
        assert resp.body == GENERIC_DENIAL_BODY, resp.body
        return
    if kind == "cred-query":
        broker = Broker()
        created = broker.create_session(
            key_id="key-TEST-ONLY-proxy", provider="github",
            session_class="read_account", process_group="pg-scale")
        proxy = _make_proxy(broker, created, "github",
                            lambda s, m, p, sc: (True, "a"), [], [])
        path = "/user?" + spec["qname"] + "=abc"
        headers = _signed(created.token, created.pop_key, "GET", _host("github"), path)
        resp = proxy.handle("GET", BASES["github"] + path, headers, b"")
        assert resp.status == 400, resp.status
        assert resp.body == GENERIC_DENIAL_BODY, resp.body
        return
    if kind == "plain-http-base":
        broker = Broker()
        created = broker.create_session(
            key_id="key-TEST-ONLY-proxy", provider="github",
            session_class="read_account", process_group="pg-scale")
        proxy = ProxyEngine(
            ProxyConfig(bases={"github": BASES["github"]}, test_mode=False),
            lookup_session=broker.validate_token,
            pop_key_for=lambda sid: created.pop_key,
            decide=lambda s, m, p, b, c: PACK_ENGINES["github"].decide(m, p, s.session_class, now=FRESH_NOW),
            approve=lambda s, m, p, sc: (True, "a"),
            audit_decision=lambda e: None, audit_outcome=lambda e: None,
            key_for=lambda kid: FAKE_KEYS["github"])
        headers = _signed(created.token, created.pop_key, "GET", _host("github"), "/user")
        resp = proxy.handle("GET", BASES["github"] + "/user", headers, b"")
        assert resp.status == 502, resp.status
        assert resp.body == GENERIC_DENIAL_BODY, resp.body
        return
    raise AssertionError("unknown proxy spec kind: %r" % (kind,))  # pragma: no cover
'''

MISC_RUNNER = r'''
import urllib.parse
from keyholder.packs import PackRefusedError, parse_pack
from keyholder.policy import (
    DecisionCache, PolicyDecision, SpendCap, spend_alert_copy,
)
from keyholder.audit import entry_hash_of
from keyholder.proxy import contains_secret, validate_loopback_host


def run_case(self, spec):
    kind = spec["kind"]
    if kind == "cache":
        clock = [0.0]
        cache = DecisionCache(clock=lambda: clock[0])
        base_key = ("GET", "/user", "read_account", "0.1.0")
        if spec["variation"] == "same":
            key = base_key
        elif spec["variation"] == "diff-method":
            key = ("POST", "/user", "read_account", "0.1.0")
        elif spec["variation"] == "diff-path":
            key = ("GET", "/other", "read_account", "0.1.0")
        elif spec["variation"] == "diff-class":
            key = ("GET", "/user", "write", "0.1.0")
        else:
            key = ("GET", "/user", "read_account", "0.2.0")
        decision = PolicyDecision(allowed=spec["first_level"] in (1, 2),
                                  level=spec["first_level"], reason="r", rule_id="x")
        cache.put(base_key, decision, spend=spec["spend"])
        clock[0] = float(spec["offset"])
        found = cache.get(key)
        assert (found is not None) == spec["expected_hit"], (spec, found)
        if spec["expected_hit"]:
            assert found.level == spec["first_level"], found
        if spec["offset"] == 61:
            assert cache.get(key) is None, "expired entry must not revive"
        return
    if kind == "spend":
        cap = SpendCap(float(spec["cap"]))
        for i, amount in enumerate(spec["amounts"]):
            if spec["expected_deny_at"] is not None and i >= spec["expected_deny_at"]:
                break
            result = cap.record(float(amount))
            assert result is None, (spec, i, result)
        if spec["expected_deny_at"] is not None:
            result = cap.record(float(spec["amounts"][spec["expected_deny_at"]]))
            assert result is not None and result.level == 4, (spec, result)
            assert result.allowed is False, result
        assert cap.spent_estimate == float(spec["expected_spent"]), (spec, cap.spent_estimate)
        return
    if kind == "spend-error":
        assert SpendCap.estimate_error_pauses(spec["estimated"], spec["actual"]) == spec["expected"], spec
        return
    if kind == "spend-copy":
        text = spend_alert_copy(spec["detail"])
        assert text.startswith("spend alerts (estimated)"), text
        if spec["detail"]:
            assert spec["detail"] in text, text
        else:
            assert text == "spend alerts (estimated)", text
        return
    if kind == "pack-mutate":
        parsed = parse_pack(spec["pack"])
        assert parsed.name == spec["provider"], parsed
        rule = None
        for entry in parsed.endpoints:
            if entry.method == spec["method"] and entry.path_pattern == spec["pattern"]:
                rule = entry
                break
        assert rule is not None, spec
        assert rule.level == spec["mutated_level"], rule
        return
    if kind == "pack-refused":
        try:
            parse_pack(spec["pack"])
        except PackRefusedError:
            return
        raise AssertionError("refused pack loaded: %r" % (spec["reason"],))
    if kind == "secret-scan":
        secret = spec["secret"]
        enc = spec["encoding"]
        if enc == "raw":
            body = ("prefix " + secret + " suffix").encode()
        elif enc == "hex-lower":
            body = secret.encode().hex().encode()
        elif enc == "hex-upper":
            body = secret.encode().hex().upper().encode()
        elif enc == "quote":
            body = urllib.parse.quote(secret, safe="").encode()
        elif enc == "quote-plus":
            body = urllib.parse.quote_plus(secret).encode()
        elif enc == "json-unicode":
            import json as _json
            body = _json.dumps({"v": secret}).encode()
        elif enc == "json-slash":
            body = ('{"v": "' + secret.replace("/", "\\/") + '"}').encode()
        elif enc == "one-char-diff":
            diff = secret[:-1] + ("Z" if secret[-1] != "Z" else "Y")
            body = ("prefix " + diff + " suffix").encode()
        elif enc == "prefix-only":
            body = secret[:-1].encode()
        else:  # pragma: no cover
            raise AssertionError(enc)
        assert contains_secret(body, secret) == spec["expected"], (spec, body)
        return
    if kind == "loopback":
        try:
            validate_loopback_host(spec["host"])
        except ValueError:
            assert spec["expected_ok"] is False, spec
            return
        assert spec["expected_ok"] is True, spec
        return
    if kind == "entry-hash":
        h1 = entry_hash_of(spec["base"])
        assert len(h1) == 64 and all(c in "0123456789abcdef" for c in h1), h1
        mutated = dict(spec["base"])
        field = spec["field"]
        if field == "decision":
            mutated[field] = "deny"
        elif field == "method":
            mutated[field] = "POST"
        elif field == "canonical_path":
            mutated[field] = "/other"
        elif field == "provider":
            mutated[field] = "gemini"
        elif field == "seq":
            mutated[field] = 8
        elif field == "bytes_out":
            mutated[field] = 11
        elif field == "outcome":
            mutated[field] = "denied"
        elif field == "session_pseudonym":
            mutated[field] = "qz"
        assert entry_hash_of(mutated) != h1, (spec, h1)
        return
    if kind == "entry-hash-same":
        assert entry_hash_of(spec["base"]) == entry_hash_of(dict(spec["base"])), spec
        return
    raise AssertionError("unknown misc spec kind: %r" % (kind,))  # pragma: no cover
'''


# ------------------------------------------------------------- generation

FILE_SPECS = (
    ("test_generated_policy.py", "Policy", build_policy_specs, POLICY_RUNNER,
     "import sys\nimport unittest\nfrom pathlib import Path\n\n"
     "sys.path.insert(0, str(Path(__file__).resolve().parent.parent))\n\n"
     "from keyholder.packs import load_pack\n\n"
     "ROOT = Path(__file__).resolve().parent.parent\n"),
    ("test_generated_sessions.py", "Sessions", build_session_specs, SESSION_RUNNER,
     "import sys\nimport unittest\nfrom pathlib import Path\n\n"
     "sys.path.insert(0, str(Path(__file__).resolve().parent.parent))\n\n"
     "ROOT = Path(__file__).resolve().parent.parent\n"
     "SESSION_CLASSES = (\"destructive\", \"write\", \"read_account\", \"read_public\")\n"),
    ("test_generated_audit.py", "Audit", build_audit_specs, AUDIT_RUNNER,
     "import sys\nimport unittest\nfrom pathlib import Path\n\n"
     "sys.path.insert(0, str(Path(__file__).resolve().parent.parent))\n\n"
     "ROOT = Path(__file__).resolve().parent.parent\n"),
    ("test_generated_malformed.py", "Malformed", build_malformed_specs, MALFORMED_RUNNER,
     "import sys\nimport unittest\nfrom pathlib import Path\n\n"
     "sys.path.insert(0, str(Path(__file__).resolve().parent.parent))\n\n"
     "ROOT = Path(__file__).resolve().parent.parent\n"),
    ("test_generated_proxy.py", "Proxy", build_proxy_specs, PROXY_RUNNER,
     "import sys\nimport unittest\nfrom pathlib import Path\n\n"
     "sys.path.insert(0, str(Path(__file__).resolve().parent.parent))\n\n"
     "ROOT = Path(__file__).resolve().parent.parent\n"),
    ("test_generated_misc.py", "Misc", build_misc_specs, MISC_RUNNER,
     "import sys\nimport unittest\nfrom pathlib import Path\n\n"
     "sys.path.insert(0, str(Path(__file__).resolve().parent.parent))\n\n"
     "ROOT = Path(__file__).resolve().parent.parent\n"),
)

_METHOD_GEN = '''
class Generated%s(unittest.TestCase):
    """Generated cases (engine: tests/test_scale_engine.py, seed %d)."""


def _make_test(spec):
    def test(self):
        run_case(self, spec)
    test.__doc__ = "generated case %%s" %% (spec["key"],)
    return test


for _i, _spec in enumerate(CASES):
    setattr(Generated%s, "test_%%04d" %% (_i + 1), _make_test(_spec))
'''


def render_file(class_name, specs, runner, preamble):
    header = ('"""GENERATED FILE - DO NOT HAND-EDIT.\n\n'
              'Produced by tests/test_scale_engine.py (seed %d). Regenerate\n'
              'with: python3 tests/test_scale_engine.py\n'
              'Each case has a distinct input and asserts a security outcome\n'
              '(see the runner below the case table).\n"""\n\n' % SEED)
    body = (preamble + "\nCASES = " + repr(specs) + "\n\n"
            "CASE_COUNT = len(CASES)\n" + runner + "\n"
            + (_METHOD_GEN % (class_name, SEED, class_name)))
    return header + body


def generate_all(out_dir):
    """Build every generated file into ``out_dir`` with a fresh dedup
    registry. Returns (counts, total). Deterministic: same seed, same
    bytes, every run."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    reg = DedupRegistry()
    counts = {}
    for filename, class_name, builder, runner, preamble in FILE_SPECS:
        specs = builder(reg)
        text = render_file(class_name, specs, runner, preamble)
        (out_dir / filename).write_text(text, encoding="utf-8")
        counts[filename] = len(specs)
    manifest = {"seed": SEED, "counts": counts, "total_generated": sum(counts.values())}
    (out_dir / "generated_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return counts, sum(counts.values())


def main():
    counts, total = generate_all(TESTS_DIR)
    for filename in sorted(counts):
        print(f"{filename}: {counts[filename]}")
    print(f"total generated: {total}")


# ------------------------------------------------------- engine's own tests

class TestScaleEngine(unittest.TestCase):
    """Hand-written tests for the engine itself (not generated)."""

    def test_pack_endpoint_totals(self):
        self.assertEqual(len(PACKS["github"].endpoints), 42)
        self.assertEqual(len(PACKS["gemini"].endpoints), 23)
        self.assertEqual(len(ENDPOINTS), 65)

    def test_concrete_instantiation_matches_own_rule(self):
        from keyholder.policy import match_pattern

        for provider, rule in ENDPOINTS:
            pack = PACKS[provider]
            for variant in range(6):
                path = concrete_path(rule.path_pattern, variant)
                self.assertIs(find_rule(pack, rule.method, path), rule,
                              (provider, rule, variant, path))
                self.assertTrue(match_pattern(rule.path_pattern, path), path)

    def test_oracle_known_decisions(self):
        gh = PACKS["github"]
        user_rule = find_rule(gh, "GET", "/user")
        # GET /user is read_account: read_account passes, read_public
        # is capability-denied, and a fresh pack escalates read_account
        # to allow-with-log when stale.
        self.assertEqual(expected_decision(user_rule, "read_account", False),
                         (True, 1, "github:GET:/user"))
        self.assertEqual(expected_decision(user_rule, "read_account", True),
                         (True, 2, "stale_pack"))
        self.assertEqual(expected_decision(user_rule, "read_public", False),
                         (False, 4, "capability"))
        graphql_rule = find_rule(gh, "POST", "/graphql")
        self.assertEqual(expected_decision(graphql_rule, "destructive", False),
                         (False, 4, "graphql_empty"))
        billing_rule = find_rule(gh, "GET", "/user/settings/billing/x")
        self.assertEqual(expected_decision(billing_rule, "destructive", False),
                         (False, 4, "capability"))
        self.assertEqual(expected_decision(None, "read_public", False),
                         (False, 4, "unmodelled"))
        # The GraphQL branch precedes stale handling, so a body-less
        # /graphql call is graphql_empty even on a stale pack.
        self.assertEqual(expected_decision(graphql_rule, "destructive", True),
                         (False, 4, "graphql_empty"))

    def test_oracle_agrees_with_engine_on_matrix_sample(self):
        # Spot-check the oracle against the real engine on one case
        # per endpoint (fresh pack, destructive class).
        for provider, rule in ENDPOINTS:
            engine = PolicyEngine(PACKS[provider])
            path = concrete_path(rule.path_pattern, 0)
            decision = engine.decide(rule.method, path, "destructive", now=FRESH_NOW)
            allowed, level, rule_id = expected_decision(rule, "destructive", False)
            self.assertEqual((decision.allowed, decision.level, decision.rule_id),
                             (allowed, level, rule_id), (provider, rule, path))

    def test_dedup_registry_rejects_collisions(self):
        reg = DedupRegistry()
        reg.add(["a", 1])
        with self.assertRaises(AssertionError):
            reg.add(["a", 1])
        self.assertEqual(len(reg.seen), 1)

    def test_generation_is_deterministic(self):
        import tempfile

        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            counts_a, total_a = generate_all(a)
            counts_b, total_b = generate_all(b)
            self.assertEqual(counts_a, counts_b)
            self.assertEqual(total_a, total_b)
            for filename in counts_a:
                self.assertEqual((Path(a) / filename).read_bytes(),
                                 (Path(b) / filename).read_bytes(), filename)

    def test_committed_files_match_engine(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            counts, _total = generate_all(tmp)
            for filename in counts:
                self.assertEqual((Path(tmp) / filename).read_bytes(),
                                 (TESTS_DIR / filename).read_bytes(), filename)

    def test_generated_total_and_runner_assertions(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            counts, total = generate_all(tmp)
            self.assertGreaterEqual(total, 10000, counts)
            for _filename, _cls, _builder, runner, _pre in FILE_SPECS:
                self.assertIn("assert", runner)
            self.assertTrue(all(count > 0 for count in counts.values()), counts)


if __name__ == "__main__":
    main()
