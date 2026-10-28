"""W07 Gemini adapter tests (unittest). No real Gemini calls, no real
keys: TEST-ONLY fixtures only. Run: python3 -m unittest discover -s tests -v
from ~/workspace/keyholder-build/"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keyholder.gemini import (  # noqa: E402
    CreationLedger, StreamingUsageTracker, account_stream, build_upstream_headers,
    classify_key, classify_request, estimate_cost_usd, extract_file_name,
    reject_query_key, spend_within_limiter, validate_response_function_calls,
    SPEND_LIMITERS,
)

REAL = "TEST-ONLY-AUTH-KEY-1234567890"
GEN = "/v1beta/models/gemini-2.5-flash:generateContent"
STREAM = "/v1beta/models/gemini-2.5-flash:streamGenerateContent"


def allowed(method="POST", path=GEN, **kw):
    kw.setdefault("session_class", "write")
    return classify_request(method, path, **kw)


class TestAuthKeyModel(unittest.TestCase):
    def test_any_prefix_accepted_no_aiza_gate(self):
        # Auth keys do not use the AIza shape; neither AIza nor AQ.
        # nor any other prefix may be rejected on shape alone (N-I2).
        for value in ("TEST-ONLY-AUTH-KEY-xyz", "AIzaTEST-ONLY-xyz",
                      "AQ.TEST-ONLY-xyz", "TEST-ONLY-random-string"):
            info = classify_key(value)
            self.assertEqual(info.key_type, "auth")
            self.assertIsNotNone(info.warning)

    def test_empty_key_rejected_as_empty_input_not_prefix(self):
        with self.assertRaises(ValueError):
            classify_key("   ")

    def test_key_authenticates_project_claim_deleted(self):
        # The deleted R06 claim must appear only as a DELETED claim,
        # never as an asserted fact, in the module docstring.
        import keyholder.gemini as g
        self.assertIn("are DELETED", g.__doc__)
        self.assertNotIn("key authenticates the project, not a person\" claim",
                         g.__doc__.replace("and its \"key authenticates the "
                                           "project, not a person\" claim "
                                           "are DELETED", ""))


class TestHeaderOnlyAuth(unittest.TestCase):
    def test_native_strips_client_api_key_and_injects_real(self):
        out = build_upstream_headers({"X-Goog-Api-Key": "TEST-ONLY-CLIENT",
                                      "Content-Type": "application/json"},
                                     "native", REAL)
        self.assertEqual(out["x-goog-api-key"], REAL)
        self.assertEqual(out["Content-Type"], "application/json")

    def test_query_key_refused(self):
        d = reject_query_key("/v1beta/models?key=TEST-ONLY-xyz")
        self.assertIsNotNone(d)
        self.assertFalse(d.allowed)
        self.assertEqual(d.public_denial(), "denied by policy")
        # And via classification: zero upstream would follow.
        self.assertFalse(allowed(path=GEN + "?key=TEST-ONLY-xyz").allowed)
        self.assertIsNone(reject_query_key("/v1beta/models?foo=bar"))

    def test_other_auth_forms_denied_native(self):
        # Authorization in any casing is denied in native mode.
        for hdr in ("Authorization", "authorization", "AUTHORIZATION"):
            with self.assertRaises(ValueError):
                build_upstream_headers({hdr: "Bearer TEST-ONLY-x"},
                                       "native", REAL)


class TestBearerModes(unittest.TestCase):
    def test_native_denies_all_bearer(self):
        with self.assertRaises(ValueError):
            build_upstream_headers({"Authorization": "Bearer TEST-ONLY-session"},
                                   "native", REAL)

    def test_compat_strips_session_bearer_and_injects(self):
        out = build_upstream_headers(
            {"Authorization": "Bearer TEST-ONLY-session-token"},
            "compat", REAL)
        self.assertEqual(out["x-goog-api-key"], REAL)
        self.assertNotIn("Authorization", out)
        self.assertNotIn("authorization", out)

    def test_compat_real_key_bearer_denied_never_forwarded(self):
        with self.assertRaises(ValueError):
            build_upstream_headers({"Authorization": f"Bearer {REAL}"},
                                   "compat", REAL)

    def test_compat_non_bearer_denied(self):
        with self.assertRaises(ValueError):
            build_upstream_headers({"Authorization": "Basic TEST-ONLY-x"},
                                   "compat", REAL)

    def test_compat_requires_openai_base(self):
        self.assertFalse(allowed(path=GEN, mode="compat").allowed)
        self.assertTrue(allowed(path="/v1beta/openai/chat/completions",
                                mode="compat").allowed)


class TestDeniedFamilies(unittest.TestCase):
    def test_interactions_denied(self):
        for path in ("/v1beta/interactions", "/v1beta/interactions/abc",
                     "/v1beta/models/x:generateContent"):
            if "interactions" in path:
                self.assertFalse(allowed(path=path).allowed, path)
        self.assertFalse(allowed(path="/v1beta/interactions").allowed)
        # Background / store / previous-interaction fields denied in
        # otherwise-allowed calls.
        for body in ({"background": True}, {"store": True},
                     {"previous_interaction_id": "interactions/1"}):
            self.assertFalse(allowed(body=body).allowed, body)

    def test_batch_denied_correct_resources(self):
        # batches/* (real) denied; batch/* alone must NOT be the pattern.
        for path in ("/v1beta/batches/abc", "/v1beta/batches",
                     "/v1beta/models/x:batchGenerateContent",
                     "/v1beta/models/x:batchEmbedContents"):
            self.assertFalse(allowed(path=path).allowed, path)

    def test_live_managed_mcp_fss_denied(self):
        for path in ("/v1beta/models/x:BidiGenerateContent",
                     "/v1beta/live", "/v1beta/tunedModels/abc",
                     "/v1beta/cachedContents/abc",
                     "/v1beta/fileSearchStores/abc",
                     "/v1beta/operations/abc",
                     "/v1beta/files:register"):
            self.assertFalse(allowed(path=path).allowed, path)
        self.assertFalse(allowed(
            body={"tools": [{"type": "remote_mcp"}]}).allowed)
        self.assertFalse(allowed(
            body={"tools": [{"type": "managed_agent"}]}).allowed)

    def test_unmodelled_denied(self):
        self.assertFalse(allowed(path="/v1beta/something-new").allowed)


class TestLedgerGatedReferences(unittest.TestCase):
    def test_cached_content_denied_without_ledger(self):
        body = {"cachedContent": "cachedContents/planted",
                "contents": [{"parts": [{"text": "hi"}]}]}
        self.assertFalse(allowed(body=body).allowed)

    def test_foreign_file_uri_denied(self):
        body = {"contents": [{"parts": [{"fileData": {
            "fileUri": "https://generativelanguage.googleapis.com/"
                       "v1beta/files/other-session-file"}}]}]}
        self.assertFalse(allowed(body=body).allowed)

    def test_ledgered_file_uri_allowed(self):
        ledger = CreationLedger()
        ledger.record_file("files/own-file-1")
        body = {"contents": [{"parts": [{"fileData": {
            "fileUri": "https://generativelanguage.googleapis.com/"
                       "v1beta/files/own-file-1"}}]}]}
        self.assertTrue(allowed(body=body, ledger=ledger).allowed)

    def test_files_list_is_read_account_with_warning(self):
        d = classify_request("GET", "/v1beta/files", session_class="read_public")
        self.assertFalse(d.allowed)
        d = classify_request("GET", "/v1beta/files", session_class="read_account")
        self.assertTrue(d.allowed)
        self.assertIsNotNone(d.warning)
        self.assertIn("inventory", d.warning)

    def test_own_objects_only_get_delete(self):
        ledger = CreationLedger()
        ledger.record_file("files/mine")
        self.assertTrue(classify_request(
            "GET", "/v1beta/files/mine", session_class="read_account",
            ledger=ledger).allowed)
        self.assertFalse(classify_request(
            "GET", "/v1beta/files/notmine", session_class="read_account",
            ledger=ledger).allowed)
        self.assertFalse(classify_request(
            "DELETE", "/v1beta/files/notmine", session_class="write",
            ledger=ledger).allowed)
        self.assertTrue(classify_request(
            "DELETE", "/v1beta/files/mine", session_class="write",
            ledger=ledger).allowed)

    def test_extract_file_name(self):
        self.assertEqual(
            extract_file_name("https://generativelanguage.googleapis.com/"
                              "v1beta/files/abc-123"), "files/abc-123")
        self.assertIsNone(extract_file_name("gs://bucket/object"))


class TestUploadDenial(unittest.TestCase):
    def test_upload_prefix_denied(self):
        self.assertFalse(allowed(path="/upload/v1beta/files").allowed)

    def test_upload_session_headers_denied(self):
        with self.assertRaises(ValueError):
            build_upstream_headers(
                {"x-goog-upload-url": "https://example.invalid/session"},
                "native", REAL)


class TestResponseValidation(unittest.TestCase):
    DECLARED = {"read_file": {"required": ["path"],
                              "properties": {"path": "string"}}}

    def test_declared_call_passes(self):
        resp = {"candidates": [{"content": {"parts": [
            {"functionCall": {"name": "read_file",
                             "args": {"path": "/tmp/x"}}}]}}]}
        v = validate_response_function_calls(resp, self.DECLARED)
        self.assertEqual(v.violations, [])
        self.assertFalse(v.blocked)
        self.assertEqual(len(v.sanitized["candidates"][0]["content"]["parts"]), 1)

    def test_undeclared_call_stripped(self):
        resp = {"candidates": [{"content": {"parts": [
            {"text": "ok"},
            {"functionCall": {"name": "delete_file",
                             "args": {"path": "/tmp/x"}}}]}}]}
        v = validate_response_function_calls(resp, self.DECLARED)
        self.assertTrue(v.violations)
        parts = v.sanitized["candidates"][0]["content"]["parts"]
        self.assertEqual(len(parts), 1)
        self.assertEqual(parts[0]["text"], "ok")

    def test_schema_violation_stripped(self):
        resp = {"candidates": [{"content": {"parts": [
            {"functionCall": {"name": "read_file",
                             "args": {"path": 42}}}]}}]}
        v = validate_response_function_calls(resp, self.DECLARED)
        self.assertTrue(v.violations)
        self.assertEqual(
            v.sanitized["candidates"][0]["content"]["parts"], [])

    def test_side_effecting_flagged_for_approval(self):
        declared = {"delete_file": {"required": ["path"],
                                    "properties": {"path": "string"}}}
        resp = {"candidates": [{"content": {"parts": [
            {"functionCall": {"name": "delete_file",
                             "args": {"path": "/tmp/x"}}}]}}]}
        v = validate_response_function_calls(resp, declared)
        self.assertTrue(v.requires_approval)
        self.assertFalse(v.blocked)

    def test_block_on_violation(self):
        resp = {"candidates": [{"content": {"parts": [
            {"functionCall": {"name": "nope", "args": {}}}]}}]}
        v = validate_response_function_calls(resp, self.DECLARED,
                                             block_on_violation=True)
        self.assertTrue(v.blocked)


class TestStreamingAndSpend(unittest.TestCase):
    def test_last_chunk_cumulative_not_summed(self):
        chunks = [
            {"usageMetadata": {"promptTokenCount": 10,
                               "candidatesTokenCount": 5}},
            {"usageMetadata": {"promptTokenCount": 10,
                               "candidatesTokenCount": 20}},
            {"usageMetadata": {"promptTokenCount": 10,
                               "candidatesTokenCount": 40}},
        ]
        total = account_stream(chunks)
        self.assertEqual(total.completion_tokens, 40)  # not 5+20+40=65
        self.assertEqual(total.prompt_tokens, 10)
        t = StreamingUsageTracker()
        for c in chunks:
            t.update(c["usageMetadata"])
        self.assertEqual(t.chunks_seen, 3)
        self.assertEqual(t.total.completion_tokens, 40)

    def test_spend_limiters_labelled_estimated(self):
        for tier, lim in SPEND_LIMITERS.items():
            self.assertTrue(lim["estimated"], tier)
        self.assertEqual(SPEND_LIMITERS["tier1"]["per_10min_usd"], 10.0)
        self.assertEqual(SPEND_LIMITERS["tier1"]["monthly_usd"], 250.0)
        self.assertEqual(SPEND_LIMITERS["tier2"]["per_10min_usd"], 50.0)
        self.assertEqual(SPEND_LIMITERS["tier3"]["per_10min_usd"], 200.0)

    def test_estimate_cost_thinking_as_output(self):
        # Flash: 1M prompt @0.30 + 1M completion @2.50 = 2.80.
        self.assertAlmostEqual(
            estimate_cost_usd("gemini-2.5-flash", 1_000_000, 1_000_000), 2.80)
        # Thinking tokens bill as output, not free.
        self.assertAlmostEqual(
            estimate_cost_usd("gemini-2.5-flash", 0, 0, 1_000_000), 2.50)
        self.assertTrue(spend_within_limiter("tier1", 5.0, 4.0))
        self.assertFalse(spend_within_limiter("tier1", 5.0, 6.0))
        with self.assertRaises(KeyError):
            estimate_cost_usd("gemini-unknown-model", 10, 10)

    def test_generate_requires_write_class(self):
        self.assertFalse(classify_request(
            "POST", GEN, session_class="read_account").allowed)
        self.assertTrue(classify_request(
            "POST", GEN, session_class="write").allowed)
        # countTokens is a free read.
        self.assertTrue(classify_request(
            "POST", "/v1beta/models/x:countTokens",
            session_class="read_public").allowed)


if __name__ == "__main__":
    unittest.main()
