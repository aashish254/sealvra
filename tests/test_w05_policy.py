"""W05 policy engine + provider pack tests (unittest, stdlib only).

Fake data only: no real keys, no network, no provider contact. Packs
under test are built in-memory via ``finalise_pack`` or loaded from
``packs/*.json`` in the build root.
"""

import base64
import copy
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from keyholder.packs import (
    PackRefusedError,
    finalise_pack,
    load_pack,
    load_pack_directory,
    parse_pack,
)
from keyholder.policy import (
    LEVEL_ALLOW,
    LEVEL_ALLOW_WITH_LOG,
    LEVEL_APPROVE,
    LEVEL_DENY,
    DecisionCache,
    EndpointRule,
    PolicyEngine,
    ProviderPack,
    SpendCap,
    SpendLedger,
    StreamingTokenAccount,
    agent_denial_message,
    canonicalise_path,
    classify_capability,
    count_mutations,
    count_mutations_in_body,
    decision_after_approval,
    evaluate_graphql_batch,
    evaluate_graphql_body,
    evaluate_graphql_document,
    match_pattern,
    parse_form_body,
    parse_multipart_body,
    parse_query_split_first,
    parse_json_no_duplicates,
    spend_alert_copy,
)

ROOT = Path(__file__).resolve().parent.parent


def _base_pack(**overrides):
    pack = {
        "name": "testpack",
        "version": "0.1.0",
        "issued_at": "2026-10-28",
        "max_age_days": 3650,  # fresh for decision tests unless overridden
        "endpoints": [
            {"method": "GET", "path_pattern": "/public/*", "capability": "read_public", "level": 1},
            {"method": "GET", "path_pattern": "/account", "capability": "read_account", "level": 1},
            {"method": "GET", "path_pattern": "/account/logged", "capability": "read_account", "level": 2},
            {"method": "POST", "path_pattern": "/write", "capability": "write", "level": 3},
            {"method": "POST", "path_pattern": "/paid", "capability": "write", "level": 2, "spend": True},
            {"method": "DELETE", "path_pattern": "/boom", "capability": "destructive", "level": 3},
            {"method": "GET", "path_pattern": "/billing", "capability": "financial", "level": 4},
            {"method": "POST", "path_pattern": "/count", "capability": "read_account", "level": 1},
        ],
        "read_like_posts": [
            {"method": "POST", "path_pattern": "/count", "capability": "read_account", "level": 1},
        ],
        "body_schemas": {
            "needs_msg": {"required": ["message"]},
        },
    }
    pack.update(overrides)
    return finalise_pack(pack)


def _engine(pack_dict=None, **kw):
    return PolicyEngine(parse_pack(pack_dict or _base_pack()), **kw)


class TestPackLoading(unittest.TestCase):
    def test_loads_shipped_packs_with_valid_hash(self):
        packs = load_pack_directory(ROOT / "packs")
        self.assertIn("github", packs)
        self.assertIn("gemini", packs)
        self.assertEqual(packs["github"].version, "0.1.0")
        self.assertEqual(packs["gemini"].version, "0.1.0")

    def test_hash_mismatch_is_refused_never_loaded(self):
        pack = _base_pack()
        pack["endpoints"] = pack["endpoints"][:-1]  # tamper after hashing
        with self.assertRaises(PackRefusedError):
            parse_pack(pack)

    def test_tampered_file_is_refused(self):
        # W04 v0.2 flip: disk loads now require a signature, so the
        # fixture is signed with a test-generated key (never the
        # shipped key) and trust files live in the same temp dir.
        from keyholder.packs import (
            RevokedLists,
            generate_pack_keypair,
            pack_key_id,
            public_key_bytes,
            sign_pack_dict,
        )

        pack = _base_pack()
        priv, pub = generate_pack_keypair()
        trusted = {pack_key_id(pub): pub}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evil.json"
            path.write_text(json.dumps(pack), encoding="utf-8")
            path.with_suffix(".sig").write_text(
                json.dumps(sign_pack_dict(pack, priv)), encoding="utf-8")
            (Path(tmp) / "trusted_keys.json").write_text(json.dumps({
                "keys": [{
                    "key_id": pack_key_id(pub),
                    "algorithm": "Ed25519",
                    "public_key": base64.b64encode(public_key_bytes(priv)).decode("ascii"),
                }],
            }), encoding="utf-8")
            (Path(tmp) / "revoked.json").write_text(json.dumps({
                "revoked_key_ids": [], "revoked_pack_versions": [],
            }), encoding="utf-8")
            loaded = load_pack(path, trusted_keys=trusted,
                               revoked=RevokedLists(frozenset(), frozenset()))
            self.assertEqual(loaded.name, "testpack")
            tampered = json.loads(path.read_text())
            tampered["version"] = "9.9.9"
            path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(PackRefusedError):
                load_pack(path, trusted_keys=trusted,
                          revoked=RevokedLists(frozenset(), frozenset()))

    def test_missing_field_is_refused(self):
        pack = _base_pack()
        del pack["endpoints"]
        # Re-hash so the failure is the missing field, not the hash.
        from keyholder.packs import compute_content_hash

        pack["content_sha256"] = compute_content_hash(pack)
        with self.assertRaises(PackRefusedError):
            parse_pack(pack)

    def test_unknown_capability_or_level_is_refused(self):
        pack = _base_pack()
        pack["endpoints"].append(
            {"method": "GET", "path_pattern": "/nope", "capability": "superuser", "level": 1}
        )
        pack = finalise_pack({k: v for k, v in pack.items() if k != "content_sha256"})
        with self.assertRaises(PackRefusedError):
            parse_pack(pack)


class TestDecisions(unittest.TestCase):
    def test_unmodelled_endpoint_is_deny(self):
        d = _engine().decide("GET", "/definitely/not/modelled", "destructive")
        self.assertFalse(d.allowed)
        self.assertEqual(d.level, LEVEL_DENY)
        self.assertEqual(d.rule_id, "unmodelled")

    def test_allow_and_allow_with_log(self):
        e = _engine()
        d = e.decide("GET", "/public/thing", "read_public")
        self.assertTrue(d.allowed)
        self.assertEqual(d.level, LEVEL_ALLOW)
        d2 = e.decide("GET", "/account/logged", "read_account")
        self.assertTrue(d2.allowed)
        self.assertEqual(d2.level, LEVEL_ALLOW_WITH_LOG)

    def test_approval_gated_then_approved(self):
        e = _engine()
        d = e.decide("POST", "/write", "write")
        self.assertFalse(d.allowed)
        self.assertEqual(d.level, LEVEL_APPROVE)
        approved = decision_after_approval(d)
        self.assertTrue(approved.allowed)
        self.assertEqual(approved.level, LEVEL_ALLOW_WITH_LOG)

    def test_capability_exceeds_session_class_is_deny(self):
        e = _engine()
        self.assertEqual(e.decide("POST", "/write", "read_account").level, LEVEL_DENY)
        self.assertEqual(e.decide("DELETE", "/boom", "write").level, LEVEL_DENY)
        # Destructive session may perform destructive endpoints (approval-gated).
        self.assertEqual(e.decide("DELETE", "/boom", "destructive").level, LEVEL_APPROVE)

    def test_financial_is_money_billing_only(self):
        e = _engine()
        # Even a destructive session cannot satisfy a financial endpoint.
        d = e.decide("GET", "/billing", "destructive")
        self.assertFalse(d.allowed)
        self.assertEqual(d.level, LEVEL_DENY)
        # And ordinary write endpoints are not financial.
        d2 = e.decide("POST", "/write", "write")
        self.assertNotEqual(d2.rule_id, "financial")

    def test_read_like_post_stays_read_class(self):
        e = _engine()
        # POST /count is a read-like POST: a read_account session may use it,
        # and it must not be upgraded to write class.
        d = e.decide("POST", "/count", "read_account")
        self.assertTrue(d.allowed)
        self.assertEqual(d.level, LEVEL_ALLOW)
        # A read_public session still cannot use a read_account endpoint.
        self.assertEqual(e.decide("POST", "/count", "read_public").level, LEVEL_DENY)

    def test_agent_denial_carries_no_rule_id_or_category(self):
        e = _engine()
        d = e.decide("GET", "/definitely/not/modelled", "destructive")
        msg = agent_denial_message(d)
        self.assertNotIn("unmodelled", msg)
        self.assertNotIn(d.rule_id or "RULE_ID_PRESENT", msg)

    def test_canonicalisation_split_first(self):
        # %2F inside a segment must NOT become a separator: the decoded
        # segment still contains a literal slash character, but it was
        # decoded after splitting, so it stays one segment.
        self.assertEqual(canonicalise_path("/a/b%2Fc"), "/a/b/c")
        self.assertEqual(canonicalise_path("/repos/o/r"), "/repos/o/r")
        with self.assertRaises(Exception):
            canonicalise_path("/a/../b")
        with self.assertRaises(Exception):
            canonicalise_path("/a\\b")
        with self.assertRaises(Exception):
            canonicalise_path("/a#b")
        # Split-first: an encoded slash in the query never affects the path.
        self.assertEqual(canonicalise_path("/a/b?x=1%2F2"), "/a/b")
        # The canonical form is what is matched and forwarded, so a
        # decoded %2F joins the canonical string; a one-segment glob
        # must not match the resulting multi-segment canonical path.
        self.assertTrue(match_pattern("/a/b/c", canonicalise_path("/a/b%2Fc")))
        self.assertFalse(match_pattern("/a/*", canonicalise_path("/a/b%2Fc")))

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(Exception):
            parse_json_no_duplicates(b'{"a": 1, "a": 2}')
        with self.assertRaises(Exception):
            parse_json_no_duplicates(b'{"a": {"b": 1, "b": 2}}')
        self.assertEqual(parse_json_no_duplicates('{"a": 1}'), {"a": 1})

    def test_highest_capability_wins(self):
        self.assertEqual(classify_capability(["read_public", "write", "read_account"]), "write")
        self.assertEqual(classify_capability(["read_account", "destructive"]), "destructive")
        self.assertEqual(classify_capability(["write", "financial"]), "financial")

    def test_body_schema_required_key(self):
        pack = _base_pack()
        pack["endpoints"].append(
            {"method": "POST", "path_pattern": "/needs", "capability": "write", "level": 2, "body_schema": "needs_msg"}
        )
        pack = finalise_pack({k: v for k, v in pack.items() if k != "content_sha256"})
        e = PolicyEngine(parse_pack(pack))
        self.assertEqual(e.decide("POST", "/needs", "write", body={}).level, LEVEL_DENY)
        self.assertTrue(e.decide("POST", "/needs", "write", body={"message": "hi"}).allowed)


class TestCacheRules(unittest.TestCase):
    def test_allow_only_cached(self):
        clock = [1000.0]
        cache = DecisionCache(clock=lambda: clock[0])
        e = _engine(cache=cache)
        d1 = e.decide("GET", "/public/thing", "read_public")
        self.assertEqual(len(cache), 1)
        d2 = e.decide("GET", "/public/thing", "read_public")
        self.assertEqual(d1, d2)
        # Expire after 60 s.
        clock[0] += 61.0
        self.assertIsNone(cache.get(("GET", "/public/thing", "read_public", "0.1.0")))

    def test_log_and_approval_and_spend_never_cached(self):
        e = _engine()
        e.decide("GET", "/account/logged", "read_account")
        e.decide("POST", "/write", "write")
        e.decide("POST", "/paid", "write")
        self.assertEqual(len(e.cache), 0)

    def test_denials_never_cached(self):
        e = _engine()
        e.decide("GET", "/definitely/not/modelled", "destructive")
        self.assertEqual(len(e.cache), 0)


class TestGraphQL(unittest.TestCase):
    def test_count_mutations_not_requests(self):
        self.assertEqual(count_mutations("mutation { deleteRepo }"), 1)
        self.assertEqual(count_mutations("mutation A { x } mutation B { y }"), 2)
        self.assertEqual(count_mutations("{ viewer { login } }"), 0)
        # The word "mutation" inside a string is not a mutation.
        self.assertEqual(count_mutations('query { field(arg: "mutation") }'), 0)
        # Fragment definitions are not operations.
        self.assertEqual(count_mutations("fragment F on T { x } query { ...F }"), 0)

    def test_mutation_cap_default_one(self):
        d = evaluate_graphql_document("mutation A { x } mutation B { y }", session_class="write")
        self.assertEqual(d.level, LEVEL_DENY)
        d2 = evaluate_graphql_document("mutation A { x }", session_class="write")
        self.assertEqual(d2.level, LEVEL_APPROVE)
        # Read-only sessions cannot carry mutations at all.
        d3 = evaluate_graphql_document("mutation A { x }", session_class="read_account")
        self.assertEqual(d3.level, LEVEL_DENY)

    def test_batch_body_is_n_separate_requests(self):
        body = [
            {"query": "mutation A { x }"},
            {"query": "{ viewer { login } }"},
            {"query": "mutation B { y } mutation C { z }"},
        ]
        decisions = evaluate_graphql_body(body, session_class="write")
        self.assertEqual(len(decisions), 3)
        self.assertEqual(decisions[0].level, LEVEL_APPROVE)
        self.assertTrue(decisions[1].allowed)
        self.assertEqual(decisions[2].level, LEVEL_DENY)

    def test_defer_stream_subscription_introspection_denied(self):
        for doc in (
            "query @defer { x }",
            "query { x @stream }",
            "subscription { x }",
            "query { __schema { types { name } } }",
        ):
            self.assertEqual(evaluate_graphql_document(doc).level, LEVEL_DENY, doc)
        # __typename is an accepted residual.
        d = evaluate_graphql_document("query { x { __typename } }")
        self.assertTrue(d.allowed)

    def test_fragment_cycle_denied(self):
        doc = "fragment A on T { ...B } fragment B on T { ...A } query { ...A }"
        self.assertEqual(evaluate_graphql_document(doc).level, LEVEL_DENY)


class TestSpendCaps(unittest.TestCase):
    def test_spend_copy_says_estimated(self):
        copy_text = spend_alert_copy("cap reached")
        self.assertIn("spend alerts (estimated)", copy_text)
        self.assertNotIn("guaranteed", copy_text.lower())
        # Shipped Gemini pack carries the same wording.
        packs = load_pack_directory(ROOT / "packs")
        self.assertIn("spend alerts (estimated)", str(packs["gemini"].spend_alerts_estimated))

    def test_spend_cap_denies_past_estimate(self):
        cap = SpendCap(cap_estimate=10.0)
        self.assertIsNone(cap.record(6.0))
        denied = cap.record(5.0)
        self.assertIsNotNone(denied)
        self.assertEqual(denied.level, LEVEL_DENY)
        self.assertIn("spend alerts (estimated)", denied.reason)
        self.assertEqual(cap.spent_estimate, 6.0)  # denied charge not recorded

    def test_estimate_error_pause_threshold(self):
        self.assertTrue(SpendCap.estimate_error_pauses(12.5, 10.0))  # 25% error, over 20%
        self.assertFalse(SpendCap.estimate_error_pauses(12.0, 10.0))  # exactly 20% is not over
        self.assertFalse(SpendCap.estimate_error_pauses(10.5, 10.0))


class TestStalePacks(unittest.TestCase):
    def test_stale_refuses_destructive_and_metered(self):
        pack = _base_pack(issued_at="2020-01-01", max_age_days=90)
        e = PolicyEngine(parse_pack(pack))
        self.assertEqual(e.decide("DELETE", "/boom", "destructive").level, LEVEL_DENY)
        self.assertEqual(e.decide("POST", "/paid", "write").level, LEVEL_DENY)
        # Destructive session, even on a read endpoint, is refused on stale packs.
        self.assertEqual(e.decide("GET", "/public/thing", "destructive").level, LEVEL_DENY)

    def test_stale_escalates_non_destructive(self):
        pack = _base_pack(issued_at="2020-01-01", max_age_days=90)
        e = PolicyEngine(parse_pack(pack))
        d = e.decide("GET", "/public/thing", "read_public")
        self.assertTrue(d.allowed)
        self.assertEqual(d.level, LEVEL_ALLOW_WITH_LOG)  # escalated 1 -> 2

    def test_pack_without_issued_at_is_stale(self):
        pack = _base_pack()
        del pack["issued_at"]
        pack = finalise_pack({k: v for k, v in pack.items() if k != "content_sha256"})
        parsed = parse_pack(pack)
        self.assertTrue(parsed.is_stale())


class TestShippedPacks(unittest.TestCase):
    def test_github_core_classifications(self):
        packs = load_pack_directory(ROOT / "packs")
        gh = PolicyEngine(packs["github"])
        self.assertEqual(gh.decide("POST", "/graphql", "destructive").level, LEVEL_DENY)
        self.assertEqual(gh.decide("DELETE", "/repos/o/r", "destructive").level, LEVEL_DENY)
        self.assertEqual(gh.decide("PUT", "/repos/o/r/actions/secrets/TOKEN", "destructive").level, LEVEL_DENY)
        self.assertEqual(gh.decide("POST", "/user/keys", "destructive").level, LEVEL_DENY)
        self.assertEqual(gh.decide("POST", "/gists", "destructive").level, LEVEL_DENY)
        # Merge is approval-gated, not silently allowed.
        self.assertEqual(gh.decide("POST", "/repos/o/r/pulls/1/merge", "destructive").level, LEVEL_APPROVE)
        # Comment commands denied via body schema.
        d = gh.decide("POST", "/repos/o/r/issues/1/comments", "write",
                      body={"body": "looks good /deploy now"})
        self.assertEqual(d.level, LEVEL_DENY)
        # Plain comment allowed with log.
        d2 = gh.decide("POST", "/repos/o/r/issues/1/comments", "write",
                       body={"body": "thanks, this helped"})
        self.assertTrue(d2.allowed)

    def test_gemini_core_classifications(self):
        packs = load_pack_directory(ROOT / "packs")
        gm = PolicyEngine(packs["gemini"])
        # countTokens is a read-like POST: read_account session, level 1.
        d = gm.decide("POST", "/v1beta/models/gemini-2.0-flash:countTokens", "read_account")
        self.assertTrue(d.allowed)
        self.assertEqual(d.level, LEVEL_ALLOW)
        # Paid inference is write class + spend flagged (allow-with-log, never cached).
        # The one cache entry is the earlier level-1 countTokens decision;
        # generateContent must not add another.
        self.assertEqual(len(gm.cache), 1)
        d2 = gm.decide("POST", "/v1beta/models/gemini-2.0-flash:generateContent", "write")
        self.assertTrue(d2.allowed)
        self.assertEqual(d2.level, LEVEL_ALLOW_WITH_LOG)
        self.assertEqual(len(gm.cache), 1)
        # Denied surfaces.
        self.assertEqual(gm.decide("POST", "/v1beta/cachedContents", "write").level, LEVEL_DENY)
        self.assertEqual(gm.decide("POST", "/v1beta/interactions/x", "write").level, LEVEL_DENY)
        self.assertEqual(gm.decide("POST", "/upload/v1beta/files", "write").level, LEVEL_DENY)
        # cachedContent smuggled into generateContent is denied.
        d3 = gm.decide("POST", "/v1beta/models/m:generateContent", "write",
                       body={"cachedContent": "cachedContents/abc", "contents": []})
        self.assertEqual(d3.level, LEVEL_DENY)
        # fileData reference outside the ledger is denied; inside it passes.
        body = {"contents": [{"parts": [{"fileData": {"fileUri": "files/abc"}}]}]}
        self.assertEqual(gm.decide("POST", "/v1beta/models/m:generateContent", "write", body=body).level, LEVEL_DENY)
        ok = gm.decide("POST", "/v1beta/models/m:generateContent", "write", body=body,
                       allowed_file_uris=frozenset({"files/abc"}))
        self.assertTrue(ok.allowed)


# ---------------------------------------------------------------------------
# W11 (v0.2) additions: f06 proxy/policy hardening. Every test below
# asserts a denied/allowed OUTCOME, not a code path.
# ---------------------------------------------------------------------------

def _graphql_pack(**overrides):
    pack = {
        "name": "gqlpack",
        "version": "0.1.0",
        "issued_at": "2026-10-28",
        "max_age_days": 3650,
        "endpoints": [
            {"method": "POST", "path_pattern": "/graphql",
             "capability": "write", "level": 2},
        ],
    }
    pack.update(overrides)
    return finalise_pack(pack)


class TestGraphQLAliasCapsAndBatchTotals(unittest.TestCase):
    """f06 F-04: count mutation FIELDS, not operations or requests."""

    def test_aliased_fields_each_count(self):
        doc = "mutation { a1: deleteRepo(id: 1) a2: deleteRepo(id: 2) a3: deleteRepo(id: 3) }"
        self.assertEqual(count_mutations(doc), 3)

    def test_nested_selection_fields_not_counted(self):
        self.assertEqual(count_mutations("mutation { updateRepo(id: 1) { name id } }"), 1)

    def test_fragment_spread_fields_counted(self):
        doc = "fragment F on T { del1 del2 } mutation { ...F }"
        self.assertEqual(count_mutations(doc), 2)

    def test_fifty_aliased_deletes_denied(self):
        fields = " ".join("a%d: deleteRepo(id: %d)" % (i, i) for i in range(50))
        d = evaluate_graphql_document("mutation { %s }" % fields, session_class="write")
        self.assertEqual(d.level, LEVEL_DENY)
        self.assertFalse(d.allowed)

    def test_batch_total_across_requests_denied(self):
        # Two single-mutation requests = two effects under one
        # approval; the default cap is 1, so the batch denies even
        # though each element alone would only need approval.
        body = [{"query": "mutation A { x }"}, {"query": "mutation B { y }"}]
        self.assertEqual(count_mutations_in_body(body), 2)
        d = evaluate_graphql_batch(body, session_class="write")
        self.assertEqual(d.level, LEVEL_DENY)
        self.assertFalse(d.allowed)

    def test_batch_with_one_mutation_total_approves(self):
        body = [{"query": "mutation A { x }"}, {"query": "{ viewer { login } }"}]
        d = evaluate_graphql_batch(body, session_class="write")
        self.assertEqual(d.level, LEVEL_APPROVE)
        self.assertFalse(d.allowed)  # approval-gated, not allowed yet

    def test_batch_with_denied_element_denies_whole_batch(self):
        body = [{"query": "{ viewer { login } }"},
                {"query": "subscription { x }"}]
        d = evaluate_graphql_batch(body, session_class="write")
        self.assertEqual(d.level, LEVEL_DENY)

    def test_engine_graphql_endpoint_counts_batch(self):
        e = PolicyEngine(parse_pack(_graphql_pack()))
        two = json.dumps([{"query": "mutation A { x }"},
                          {"query": "mutation B { y }"}])
        d = e.decide("POST", "/graphql", "write", body_raw=two.encode())
        self.assertEqual(d.level, LEVEL_DENY)
        one = json.dumps({"query": "mutation A { x }"})
        d2 = e.decide("POST", "/graphql", "write", body_raw=one.encode())
        self.assertEqual(d2.level, LEVEL_APPROVE)
        query_only = json.dumps({"query": "{ viewer { login } }"})
        d3 = e.decide("POST", "/graphql", "write", body_raw=query_only.encode())
        self.assertTrue(d3.allowed)

    def test_engine_graphql_mutation_on_stale_metered_pack_denied(self):
        # Stale refusal must not be bypassed by the early GraphQL
        # return: a spend-flagged /graphql rule on a stale pack
        # refuses the mutation instead of approving it. (The pack
        # dict is mutated BEFORE finalise_pack, or the content
        # hash refuses the pack -- correctly -- at load.)
        pack = {
            "name": "gqlpack",
            "version": "0.1.0",
            "issued_at": "2020-01-01",
            "max_age_days": 90,
            "endpoints": [
                {"method": "POST", "path_pattern": "/graphql",
                 "capability": "write", "level": 2, "spend": True},
            ],
        }
        e = PolicyEngine(parse_pack(finalise_pack(pack)))
        d = e.decide("POST", "/graphql", "write",
                     body_raw=json.dumps({"query": "mutation A { x }"}).encode())
        self.assertEqual(d.level, LEVEL_DENY)

    def test_duplicate_keys_inside_graphql_variables_denied(self):
        raw = b'{"query": "mutation A { x }", "variables": {"a": 1, "a": 2}}'
        e = PolicyEngine(parse_pack(_graphql_pack()))
        d = e.decide("POST", "/graphql", "write", body_raw=raw)
        self.assertEqual(d.level, LEVEL_DENY)


class TestQuerySplitFirst(unittest.TestCase):
    """f06 F-13: split raw on '&' first, decode each piece once."""

    def test_encoded_separator_stays_literal(self):
        pairs = parse_query_split_first("q=a%26b%3Dc&a=1&a=2")
        self.assertEqual(pairs, [("q", "a&b=c"), ("a", "1"), ("a", "2")])

    def test_semicolon_stays_literal(self):
        self.assertEqual(parse_query_split_first("x=1%3B2"), [("x", "1;2")])

    def test_malformed_escape_rejected(self):
        # %ff is an invalid UTF-8 byte under strict decoding.
        with self.assertRaises(ValueError):
            parse_query_split_first("q=%ff")


class TestFormAndMultipartPolicy(unittest.TestCase):
    """f06 F-10: form/multipart bodies are parsed and constrained."""

    def _form_engine(self):
        pack = {
            "name": "formpack",
            "version": "0.1.0",
            "issued_at": "2026-10-28",
            "max_age_days": 3650,
            "endpoints": [
                {"method": "POST", "path_pattern": "/form",
                 "capability": "write", "level": 1, "body_schema": "form_schema"},
                {"method": "POST", "path_pattern": "/plain",
                 "capability": "write", "level": 1},
            ],
            "body_schemas": {
                "form_schema": {"required": ["message"],
                                "forbidden": ["admin"],
                                "forbidden_substrings": ["/deploy"]},
            },
        }
        return PolicyEngine(parse_pack(finalise_pack(pack)))

    def test_form_schema_applies_to_all_values(self):
        e = self._form_engine()
        ct = "application/x-www-form-urlencoded"
        ok = e.decide("POST", "/form", "write", body_raw=b"message=hi",
                      content_type=ct)
        self.assertTrue(ok.allowed)
        # Forbidden substring in a SECOND field's value still denies.
        bad = e.decide("POST", "/form", "write",
                       body_raw=b"message=hi&note=/deploy", content_type=ct)
        self.assertEqual(bad.level, LEVEL_DENY)
        missing = e.decide("POST", "/form", "write", body_raw=b"note=hi",
                           content_type=ct)
        self.assertEqual(missing.level, LEVEL_DENY)

    def test_form_credential_field_denied(self):
        e = self._form_engine()
        d = e.decide("POST", "/form", "write", body_raw=b"message=hi&token=x",
                     content_type="application/x-www-form-urlencoded")
        self.assertEqual(d.level, LEVEL_DENY)

    def test_form_parsing_helpers(self):
        self.assertEqual(parse_form_body(b"a=1&a=2&b=x+y"),
                         [("a", "1"), ("a", "2"), ("b", "x y")])

    def _multipart(self, parts, boundary="BOUNDARY"):
        body = b""
        for name, data, ct in parts:
            body += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n"
                     "Content-Type: %s\r\n\r\n" % (boundary, name, ct)).encode()
            body += data + b"\r\n"
        body += ("--%s--\r\n" % boundary).encode()
        return body, "multipart/form-data; boundary=%s" % boundary

    def test_multipart_denied_for_body_constrained_endpoint(self):
        e = self._form_engine()
        body, ct = self._multipart([("message", b"hi", "text/plain")])
        d = e.decide("POST", "/form", "write", body_raw=body, content_type=ct)
        self.assertEqual(d.level, LEVEL_DENY)

    def test_multipart_valid_on_unconstrained_endpoint_allowed(self):
        e = self._form_engine()
        body, ct = self._multipart([("note", b"hello", "text/plain")])
        d = e.decide("POST", "/plain", "write", body_raw=body, content_type=ct)
        self.assertTrue(d.allowed)

    def test_multipart_json_part_duplicate_keys_denied(self):
        e = self._form_engine()
        body, ct = self._multipart(
            [("doc", b'{"a": 1, "a": 2}', "application/json")])
        d = e.decide("POST", "/plain", "write", body_raw=body, content_type=ct)
        self.assertEqual(d.level, LEVEL_DENY)

    def test_multipart_without_closing_delimiter_denied(self):
        e = self._form_engine()
        body = (b"--BOUNDARY\r\nContent-Disposition: form-data; "
                b"name=\"note\"\r\n\r\nhello\r\n")
        d = e.decide("POST", "/plain", "write", body_raw=body,
                     content_type="multipart/form-data; boundary=BOUNDARY")
        self.assertEqual(d.level, LEVEL_DENY)
        with self.assertRaises(ValueError):
            parse_multipart_body(body, "multipart/form-data; boundary=BOUNDARY")

    def test_content_type_gate(self):
        rule = EndpointRule(method="POST", path_pattern="/ct",
                            capability="write", level=1,
                            content_types=("application/json",))
        pack = ProviderPack(name="ctpack", version="0.1.0",
                            endpoints=[rule], issued_at="2026-10-28",
                            max_age_days=3650)
        e = PolicyEngine(pack)
        denied = e.decide("POST", "/ct", "write", body_raw=b"{}",
                          content_type="text/plain")
        self.assertEqual(denied.level, LEVEL_DENY)
        allowed = e.decide("POST", "/ct", "write", body_raw=b"{}",
                           content_type="application/json; charset=utf-8")
        self.assertTrue(allowed.allowed)


class TestCacheInvalidationForCapRules(unittest.TestCase):
    """f06 F-16: cap-conditioned rules are never cached; counter
    changes invalidate everything else."""

    def test_cap_conditioned_rule_never_cached(self):
        rule = EndpointRule(method="GET", path_pattern="/cap",
                            capability="read_public", level=1,
                            cap_conditioned=True)
        pack = ProviderPack(name="cappack", version="0.1.0",
                            endpoints=[rule], issued_at="2026-10-28",
                            max_age_days=3650)
        cache = DecisionCache()
        e = PolicyEngine(pack, cache=cache)
        self.assertTrue(e.decide("GET", "/cap", "read_public").allowed)
        self.assertTrue(e.decide("GET", "/cap", "read_public").allowed)
        self.assertEqual(len(cache), 0)

    def test_counter_change_invalidates_cached_allow(self):
        cache = DecisionCache()
        e = _engine(cache=cache)
        d1 = e.decide("GET", "/public/thing", "read_public")
        self.assertTrue(d1.allowed)
        self.assertEqual(len(cache), 1)
        e.note_cap_change()
        self.assertEqual(len(cache), 0)
        d2 = e.decide("GET", "/public/thing", "read_public")
        self.assertTrue(d2.allowed)
        self.assertEqual(len(cache), 1)


class TestSpendLedgerAndStreaming(unittest.TestCase):
    """f06 F-15: provider-scope caps (key-splitting closed) and
    streaming token accounting -- all estimates, all labelled."""

    def test_provider_scope_blocks_key_splitting(self):
        ledger = SpendLedger(caps={"provider:gemini": 10.0, "key:k1": 6.0})
        self.assertIsNone(ledger.record(["provider:gemini", "key:k1"], 5.0))
        self.assertIsNone(ledger.record(["provider:gemini"], 4.0))
        # Fresh key, same provider: the provider cap still binds.
        denied = ledger.record(["provider:gemini", "key:k2"], 2.0)
        self.assertIsNotNone(denied)
        self.assertEqual(denied.level, LEVEL_DENY)
        self.assertIn("spend alerts (estimated)", denied.reason)
        self.assertEqual(ledger.spent_for("provider:gemini"), 9.0)

    def test_denied_charge_not_recorded(self):
        ledger = SpendLedger(caps={"key:k1": 6.0})
        self.assertIsNone(ledger.record(["key:k1"], 5.0))
        self.assertIsNotNone(ledger.record(["key:k1"], 2.0))
        self.assertEqual(ledger.spent_for("key:k1"), 5.0)

    def test_day_scope_is_utc(self):
        import datetime
        # 2026-10-28 23:30 UTC is 2026-10-29 05:15 in Kathmandu; the
        # cap day must still be the UTC day.
        now = datetime.datetime(2026, 10, 28, 23, 30,
                                tzinfo=datetime.timezone.utc).timestamp()
        self.assertEqual(SpendLedger.day_scope("gemini", now),
                         "day:gemini:2026-10-28")

    def test_stream_usage_is_cumulative_not_summed(self):
        acct = StreamingTokenAccount()
        self.assertIsNone(acct.observe(
            b'data: {"usageMetadata": {"promptTokenCount": 100, '
            b'"candidatesTokenCount": 50}}\n\n'))
        self.assertIsNone(acct.observe(
            b'data: {"usageMetadata": {"promptTokenCount": 100, '
            b'"candidatesTokenCount": 900}}\n\n'))
        totals = acct.finish()
        self.assertEqual(totals["tokens_estimate"], 1000)  # not 100+50+100+900
        self.assertTrue(totals["saw_usage"])

    def test_stream_token_cap_denies_mid_stream(self):
        acct = StreamingTokenAccount(token_cap_estimate=500)
        self.assertIsNone(acct.observe(
            b'data: {"usageMetadata": {"promptTokenCount": 100, '
            b'"candidatesTokenCount": 50}}\n\n'))
        denied = acct.observe(
            b'data: {"usageMetadata": {"promptTokenCount": 100, '
            b'"candidatesTokenCount": 600}}\n\n')
        self.assertIsNotNone(denied)
        self.assertEqual(denied.level, LEVEL_DENY)
        self.assertIn("spend alerts (estimated)", denied.reason)

    def test_stream_without_usage_falls_back_to_byte_estimate(self):
        acct = StreamingTokenAccount(token_cap_estimate=500)
        denied = acct.observe(b"x" * 4000)  # ~1000 tokens estimated
        self.assertIsNotNone(denied)
        self.assertEqual(denied.level, LEVEL_DENY)
        small = StreamingTokenAccount(token_cap_estimate=500)
        self.assertIsNone(small.observe(b"hello world"))
        self.assertEqual(small.finish()["tokens_estimate"], 2)

    def test_stream_spend_cap_labelled_estimated(self):
        acct = StreamingTokenAccount(
            spend_cap_estimate=0.01,
            price_per_1k_input_estimate=0.0,
            price_per_1k_output_estimate=1.0)
        denied = acct.observe(
            b'data: {"usageMetadata": {"promptTokenCount": 0, '
            b'"candidatesTokenCount": 20}}\n\n')
        self.assertIsNotNone(denied)
        self.assertIn("spend alerts (estimated)", denied.reason)


if __name__ == "__main__":
    unittest.main()
