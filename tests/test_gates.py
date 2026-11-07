"""Release-gate behaviour tests for Sealvra v0.2 (W08).

Covers, with synthetic cases plus the real tree where honest:
- master test registry: discovered == registry, executed == registry
  count (f17 P-05/P-07);
- exception registry: mechanical rejection of S1-S4 IDs, expired
  entries, second renewals, disguised re-registrations, self-
  approval, missing signature/disclosure, over-long grants, and
  unknown test IDs (f17 P-02/P-19/P-20);
- skip / mute / deletion definitions (f17 P-07/P-19);
- artifact binding to shipped commit + build hash, including the
  honest UNBOUND case (no commit supplied at all, f17 P-06);
- grep gates on synthetic losing/winning/superseded passages and
  on the real document set (v3 G0-18).

These tests never claim a live release passes: the full-suite gate
on this Mac would fail on platform skips (correctly -- a skip counts
as a failure unless validly excepted), and artifact binding is
UNPROVEN here because the tested commit is not on the remote (see
the registry docstring). What is asserted here is
that the gate machinery itself refuses exactly the cases it must
refuse and passes exactly the cases it must pass (f17 P-21, the
"test the gates" requirement, applied to the gate code in this
tree). Only fake TEST-ONLY values are used.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import test_registry as reg

# grep_gates.py is a script under scripts/, not an installed package:
# load it by file location instead of a top-level import, so the
# macOS checker's import classifier (W17, scripts/macos_check.py)
# does not misread it as an unapproved third-party import.
import importlib.util as _importlib_util

_grep_spec = _importlib_util.spec_from_file_location(
    "grep_gates",
    Path(__file__).resolve().parent.parent / "scripts" / "grep_gates.py",
)
_grep_mod = _importlib_util.module_from_spec(_grep_spec)
sys.modules["grep_gates"] = _grep_mod  # dataclasses needs this at exec time
_grep_spec.loader.exec_module(_grep_mod)
check_text = _grep_mod.check_text
check_tree = _grep_mod.check_tree

TODAY = date(2026, 10, 28)


def _valid_entry(**overrides):
    data = {
        "entry_id": "exc-001",
        "test_id": "",
        "reason": "flaky on CI runner only, tracked upstream",
        "risk": "low: non-security UI test",
        "compensating_control": "manual re-run recorded in release notes",
        "blast_radius": "one GUI label test",
        "approver_name": "Owner",
        "reviewer_name": "Reviewer Of Record",
        "reviewer_signature_present": True,
        "granted": "2026-10-20",
        "expiry": "2026-11-10",
        "renewal_count": 0,
        "renewal_of": None,
        "disclosed_in_release_notes": True,
    }
    data.update(overrides)
    return reg.ExceptionEntry.from_dict(data)


def _non_s_test_id():
    for test_id in reg.REGISTRY_IDS:
        if not reg.classify_stop_ship(test_id):
            return test_id
    raise AssertionError("no non-stop-ship test in registry")


def _all_passed_outcomes():
    return {
        "passed": set(reg.REGISTRY_IDS),
        "failed": set(),
        "errored": set(),
        "skipped": set(),
        "muted": set(),
    }


def _artifact():
    return reg.GateArtifact(
        commit="a" * 40, build_hash="b" * 64, build_hash_kind="pyz",
        verdict="pass", counts={"registry": len(reg.REGISTRY_IDS)},
    )


class TestRegistryCountAssertion(unittest.TestCase):
    def test_discovery_equals_registry(self):
        discovered, failures = reg.discover_test_ids()
        self.assertEqual(failures, [])
        self.assertEqual(discovered, list(reg.REGISTRY_IDS))
        self.assertEqual(len(discovered), len(reg.REGISTRY_IDS))

    def test_release_gate_passes_on_full_pass_synthetic(self):
        result = reg.evaluate_release_gate(
            discovered=list(reg.REGISTRY_IDS),
            outcomes=_all_passed_outcomes(),
            artifact=_artifact(),
            expected_commit="a" * 40,
            expected_build_hash="b" * 64,
            expected_kind="pyz",
            today=TODAY,
        )
        self.assertTrue(result.ok, result.report())
        self.assertEqual(result.counts["executed"], result.counts["registry"])

    def test_release_gate_fails_on_deletion(self):
        discovered = [t for t in reg.REGISTRY_IDS if "adversarial" not in t]
        result = reg.evaluate_release_gate(
            discovered=discovered,
            outcomes=_all_passed_outcomes(),
            artifact=_artifact(),
            expected_commit="a" * 40,
            expected_build_hash="b" * 64,
            today=TODAY,
        )
        self.assertFalse(result.ok)
        self.assertTrue(result.missing)

    def test_release_gate_fails_on_unregistered_test(self):
        discovered = list(reg.REGISTRY_IDS) + ["test_new.TestNew.test_brand_new"]
        outcomes = _all_passed_outcomes()
        outcomes["passed"] = outcomes["passed"] | {"test_new.TestNew.test_brand_new"}
        result = reg.evaluate_release_gate(
            discovered=discovered, outcomes=outcomes, artifact=_artifact(),
            expected_commit="a" * 40, expected_build_hash="b" * 64, today=TODAY,
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.extra, ["test_new.TestNew.test_brand_new"])

    def test_release_gate_fails_when_a_test_never_ran(self):
        outcomes = _all_passed_outcomes()
        dropped = reg.REGISTRY_IDS[0]
        outcomes["passed"] = outcomes["passed"] - {dropped}
        result = reg.evaluate_release_gate(
            discovered=list(reg.REGISTRY_IDS), outcomes=outcomes,
            artifact=_artifact(), expected_commit="a" * 40,
            expected_build_hash="b" * 64, today=TODAY,
        )
        self.assertFalse(result.ok)
        self.assertIn("never ran", result.report())


class TestStopShipClassification(unittest.TestCase):
    def test_adversarial_module_is_s1(self):
        adv = [t for t in reg.REGISTRY_IDS if t.startswith("test_adversarial.")]
        self.assertGreater(len(adv), 0)
        for test_id in adv:
            self.assertIn("S1", reg.classify_stop_ship(test_id), test_id)

    def test_known_s2_s3_s4_spot_checks(self):
        by_suffix = {}
        for test_id in reg.REGISTRY_IDS:
            by_suffix[test_id.rsplit(".", 1)[-1]] = test_id
        self.assertIn("S2", reg.classify_stop_ship(
            by_suffix["test_zz_no_secret_in_any_suite_log"]))
        self.assertIn("S3", reg.classify_stop_ship(
            by_suffix["test_no_silent_raw_key_fallback_in_real_source"]))
        self.assertIn("S4", reg.classify_stop_ship(
            by_suffix["test_replayed_approval_nonce_rejected"]))
        self.assertIn("S2", reg.classify_stop_ship(
            by_suffix["test_scanner_finds_encoded_forms"]))

    def test_documented_exclusions_are_not_misclassified(self):
        by_suffix = {}
        for test_id in reg.REGISTRY_IDS:
            by_suffix[test_id.rsplit(".", 1)[-1]] = test_id
        self.assertNotIn("S3", reg.classify_stop_ship(
            by_suffix["test_posix_scan_allows_attributeerror_fallback"]))
        self.assertNotIn("S2", reg.classify_stop_ship(
            by_suffix["test_import_refuses_ssh_keys_gists_secrets"]))
        self.assertNotIn("S4", reg.classify_stop_ship(
            by_suffix["test_broker_rejects_forged_origin_decision"]))


class TestExceptionRegistryRejections(unittest.TestCase):
    def assert_rejected(self, entry, fragment):
        errors = reg.validate_exception_registry([entry], today=TODAY)
        self.assertTrue(
            any(fragment in e for e in errors),
            f"expected {fragment!r} in {errors}",
        )

    def test_s1_id_rejected(self):
        adv = next(t for t in reg.REGISTRY_IDS if t.startswith("test_adversarial."))
        self.assert_rejected(_valid_entry(test_id=adv), "REJECTED")

    def test_s2_s3_s4_ids_rejected(self):
        for suffix in ("test_zz_no_secret_in_any_suite_log",
                       "test_no_silent_raw_key_fallback_in_real_source",
                       "test_replayed_approval_nonce_rejected"):
            test_id = next(t for t in reg.REGISTRY_IDS if t.endswith(suffix))
            self.assert_rejected(_valid_entry(test_id=test_id), "REJECTED")

    def test_expired_entry_rejected(self):
        self.assert_rejected(
            _valid_entry(test_id=_non_s_test_id(), granted="2026-09-01",
                         expiry="2026-09-20"),
            "EXPIRED",
        )

    def test_over_30_day_grant_rejected(self):
        self.assert_rejected(
            _valid_entry(test_id=_non_s_test_id(), granted="2026-10-01",
                         expiry="2026-11-15"),
            "max is 30",
        )

    def test_second_renewal_rejected(self):
        test_id = _non_s_test_id()
        entries = [
            _valid_entry(entry_id="e1", test_id=test_id),
            _valid_entry(entry_id="e2", test_id=test_id, renewal_count=1,
                         renewal_of="e1"),
            _valid_entry(entry_id="e3", test_id=test_id, renewal_count=2,
                         renewal_of="e2"),
        ]
        errors = reg.validate_exception_registry(entries, today=TODAY)
        self.assertTrue(any("second renewal" in e for e in errors), errors)

    def test_disguised_reregistration_rejected(self):
        test_id = _non_s_test_id()
        entries = [
            _valid_entry(entry_id="e1", test_id=test_id),
            _valid_entry(entry_id="e2", test_id=test_id),  # renewal_count 0 again
        ]
        errors = reg.validate_exception_registry(entries, today=TODAY)
        self.assertTrue(any("renewal" in e for e in errors), errors)

    def test_self_approval_rejected(self):
        self.assert_rejected(
            _valid_entry(test_id=_non_s_test_id(), approver_name="Owner",
                         reviewer_name="Owner"),
            "must differ",
        )

    def test_missing_signature_rejected(self):
        self.assert_rejected(
            _valid_entry(test_id=_non_s_test_id(),
                         reviewer_signature_present=False),
            "signature missing",
        )

    def test_missing_disclosure_rejected(self):
        self.assert_rejected(
            _valid_entry(test_id=_non_s_test_id(),
                         disclosed_in_release_notes=False),
            "disclosure missing",
        )

    def test_unknown_test_id_rejected(self):
        self.assert_rejected(
            _valid_entry(test_id="test_nope.TestNope.test_nope"),
            "not in the master registry",
        )

    def test_missing_registry_file_is_an_error(self):
        _, errors = reg.load_exception_registry(Path("/nonexistent-dir/exc.json"))
        self.assertTrue(errors)

    def test_malformed_registry_file_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "exc.json"
            path.write_text("{not json", encoding="utf-8")
            _, errors = reg.load_exception_registry(path)
            self.assertTrue(errors)

    def test_valid_exception_and_valid_renewal_pass(self):
        test_id = _non_s_test_id()
        entries = [
            _valid_entry(entry_id="e1", test_id=test_id),
            _valid_entry(entry_id="e2", test_id=test_id, renewal_count=1,
                         renewal_of="e1", granted="2026-10-20",
                         expiry="2026-11-10"),
        ]
        self.assertEqual(reg.validate_exception_registry(entries, today=TODAY), [])


class TestSkipMuteDeletionDefinitions(unittest.TestCase):
    def _gate_with(self, outcomes, exceptions=()):
        return reg.evaluate_release_gate(
            discovered=list(reg.REGISTRY_IDS), outcomes=outcomes,
            exceptions=list(exceptions), artifact=_artifact(),
            expected_commit="a" * 40, expected_build_hash="b" * 64,
            today=TODAY,
        )

    def test_skip_without_exception_fails(self):
        test_id = _non_s_test_id()
        outcomes = _all_passed_outcomes()
        outcomes["passed"] -= {test_id}
        outcomes["skipped"] = {test_id}
        result = self._gate_with(outcomes)
        self.assertFalse(result.ok)
        self.assertEqual(result.unexcused_skips, [test_id])

    def test_skip_with_valid_exception_passes(self):
        test_id = _non_s_test_id()
        outcomes = _all_passed_outcomes()
        outcomes["passed"] -= {test_id}
        outcomes["skipped"] = {test_id}
        result = self._gate_with(outcomes, [_valid_entry(test_id=test_id)])
        self.assertTrue(result.ok, result.report())
        self.assertEqual(result.excused_skips, [test_id])

    def test_muted_xfail_without_exception_fails(self):
        test_id = _non_s_test_id()
        outcomes = _all_passed_outcomes()
        outcomes["passed"] -= {test_id}
        outcomes["muted"] = {test_id}
        self.assertFalse(self._gate_with(outcomes).ok)

    def test_quarantine_is_a_skip(self):
        # Quarantine has no separate outcome: a quarantined test shows
        # up as skipped, and only a valid exception excuses it.
        test_id = _non_s_test_id()
        outcomes = _all_passed_outcomes()
        outcomes["passed"] -= {test_id}
        outcomes["skipped"] = {test_id}
        self.assertFalse(self._gate_with(outcomes).ok)
        self.assertTrue(self._gate_with(
            outcomes, [_valid_entry(test_id=test_id)]).ok)

    def test_failed_test_is_never_excused(self):
        test_id = _non_s_test_id()
        outcomes = _all_passed_outcomes()
        outcomes["passed"] -= {test_id}
        outcomes["failed"] = {test_id}
        result = self._gate_with(outcomes, [_valid_entry(test_id=test_id)])
        self.assertFalse(result.ok)
        self.assertIn("never exceptable", result.report())


class TestArtifactBinding(unittest.TestCase):
    def test_matching_artifact_passes(self):
        self.assertEqual(reg.verify_gate_artifact(
            _artifact(), "a" * 40, "b" * 64, "pyz"), [])

    def test_wrong_commit_fails(self):
        errors = reg.verify_gate_artifact(_artifact(), "c" * 40, "b" * 64)
        self.assertTrue(any("different commit" in e for e in errors), errors)

    def test_wrong_build_hash_fails(self):
        errors = reg.verify_gate_artifact(_artifact(), "a" * 40, "d" * 64)
        self.assertTrue(any("different build" in e for e in errors), errors)

    def test_missing_artifact_fails(self):
        self.assertTrue(reg.verify_gate_artifact(None, "a" * 40, "b" * 64))

    def test_unknown_commit_is_unbound_not_passing(self):
        # The fail-closed case: no commit supplied -> refuse.
        errors = reg.verify_gate_artifact(_artifact(), None, "b" * 64)
        self.assertTrue(any("UNBOUND" in e for e in errors), errors)

    def test_release_gate_refuses_unbound_artifact(self):
        result = reg.evaluate_release_gate(
            discovered=list(reg.REGISTRY_IDS),
            outcomes=_all_passed_outcomes(),
            artifact=_artifact(),
            expected_commit=None,  # no commit supplied, on purpose
            expected_build_hash="b" * 64,
            today=TODAY,
        )
        self.assertFalse(result.ok)
        self.assertIn("UNBOUND", result.report())

    def test_build_hash_is_deterministic(self):
        root = Path(__file__).resolve().parent.parent
        h1, k1 = reg.compute_build_hash(root)
        h2, k2 = reg.compute_build_hash(root)
        self.assertEqual((h1, k1), (h2, k2))
        self.assertEqual(len(h1), 64)


class TestGrepGatesSynthetic(unittest.TestCase):
    def assert_gate_fails(self, text, fragment=None):
        hits = check_text(text, "synthetic.md")
        failing = [h for h in hits if not h.allowed]
        self.assertTrue(failing, f"expected a failing hit in {text!r}, got {hits}")
        if fragment:
            self.assertTrue(any(fragment in h.reason for h in failing), failing)

    def assert_gate_passes(self, text):
        hits = check_text(text, "synthetic.md")
        failing = [h for h in hits if not h.allowed]
        self.assertEqual(failing, [], hits)

    def test_losing_ttl_passages_fail(self):
        self.assert_gate_fails("sessions last 8 h by default\n", "losing TTL")
        self.assert_gate_fails("the session TTL is 24 h\n", "losing TTL")
        self.assert_gate_fails("templates expire after 4 hours\n", "losing TTL")
        self.assert_gate_fails("grants last 24-hour\n", "losing TTL")

    def test_losing_feature_passages_fail(self):
        self.assert_gate_fails("run with --show-token to print the key\n")
        self.assert_gate_fails("use Reveal to display the secret\n")
        self.assert_gate_fails("the clipboard handoff is enabled\n")
        self.assert_gate_fails("approvals support opt-out for level 3\n")
        self.assert_gate_fails("enable PoP-off mode for speed\n")
        self.assert_gate_fails("the vault-kek encrypts everything\n")
        self.assert_gate_fails("learned approvals skip future prompts\n")
        self.assert_gate_fails("the TESS module handles tokens\n")

    def test_winning_rule_passages_pass(self):
        self.assert_gate_passes("there is no reveal command, no --show-token flag\n")
        self.assert_gate_passes("no clipboard handoff of a key is provided\n")
        self.assert_gate_passes("no level-3 opt-out exists in this build\n")
        self.assert_gate_passes(".biometryCurrentSet strict mode, opt-in only\n")

    def test_superseded_history_passes(self):
        self.assert_gate_passes(
            "The old 4-hour figures are deleted.\n"
            "This section is superseded history: the TESS design was removed.\n")
        self.assert_gate_passes(
            "Deleted v1/v2 passages (the vault-kek-v1 design) are never built.\n")

    def test_non_ttl_number_contexts_pass(self):
        self.assert_gate_passes("OAuth tokens may expire (8 h access + 6 mo refresh)\n")
        self.assert_gate_passes("enforced 24 h cooldown between full-vault exports\n")
        self.assert_gate_passes("3 forged/replayed decisions in 24 h pauses approvals\n")

    def test_will_not_do_list_passes(self):
        self.assert_gate_passes(
            "## What Sealvra will not do, even if asked\n"
            "\n"
            "- Show a real key, copy a key to the clipboard, or print a session\n"
            "  token after creation. There is no command for any of these.\n")


class TestGrepGatesRealTree(unittest.TestCase):
    def test_real_document_set_passes_with_every_hit_reported(self):
        root = Path(__file__).resolve().parent.parent
        report = check_tree(root)
        self.assertTrue(report.ok, report.render())
        # The gate must actually SEE hits (a gate that matches nothing
        # proves nothing): the tree contains winning-rule mentions.
        self.assertGreater(len(report.hits), 0, "grep gate matched nothing")


if __name__ == "__main__":
    unittest.main()
