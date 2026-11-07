"""W17 macOS verification tests (unittest).

Runs scripts/macos_check.py against the real build root and against
small synthetic fixture trees, and records macOS-real checks as
NOT-RUN (never PASSED) — they require a real Mac.

Fake keys only: fixtures use TEST-ONLY values. No real credentials
anywhere in this file.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BUILD_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = BUILD_ROOT / "scripts" / "macos_check.py"

# macOS-real checks: recorded as NOT-RUN here, by design. If any of
# these ever appears as "passed" in a Linux-side report, that report
# is wrong.
MACOS_REAL_CHECKS = [
    "Real macOS Keychain store/retrieve",
    "Touch ID / LAContext biometric prompt",
    "Sandboxed approver XPC service",
    "DMG install + Gatekeeper",
    "End-to-end run on the user's M5 Mac",
]


def run_checker(root: Path):
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root), "--json"],
        capture_output=True, text=True, timeout=120,
    )
    return proc, json.loads(proc.stdout) if proc.stdout.strip() else {}


class TestW17MacosChecker(unittest.TestCase):
    def test_script_exists_and_is_python(self):
        self.assertTrue(SCRIPT.exists())
        compile(SCRIPT.read_text(encoding="utf-8"), str(SCRIPT), "exec")

    def test_checker_runs_on_real_build_root_without_violations(self):
        proc, report = run_checker(BUILD_ROOT)
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertEqual(report["verdict"], "NO-CHECKABLE-VIOLATION")
        self.assertEqual(report["violations"], [])
        self.assertEqual(report["fake_success_stubs"], [])
        self.assertEqual(report["binary_artifacts"], [])

    def test_compile_check_covers_build_tree(self):
        _, report = run_checker(BUILD_ROOT)
        self.assertGreater(report["compile"]["checked"], 0)
        self.assertEqual(report["compile"]["failed"], 0)

    def test_macos_interfaces_reported_honestly(self):
        """Interfaces are PRESENT or ABSENT — never claimed PASSED
        when the implementation is missing (platform.py is W13's)."""
        _, report = run_checker(BUILD_ROOT)
        ids = {i["id"] for i in report["macos_interfaces"]}
        self.assertEqual(
            ids,
            {"keychain-one-item-per-key",
             "userPresence-enrolment-change",
             "biometryCurrentSet-strict-opt-in",
             "sandboxed-approver",
             "touch-id-gesture-not-authorisation"},
        )
        for iface in report["macos_interfaces"]:
            self.assertIn(iface["status"], ("PRESENT", "ABSENT"))

    def test_macos_real_checks_are_not_run_never_passed(self):
        _, report = run_checker(BUILD_ROOT)
        listed = [item["check"] for item in report["not_run_here"]]
        for check in MACOS_REAL_CHECKS:
            self.assertTrue(
                any(check.split(" (")[0] in entry or check in entry
                    for entry in listed),
                msg=f"macOS-real check missing from NOT-RUN list: {check}",
            )
        # The report must never claim these passed.
        self.assertNotIn("macOS PASSED", json.dumps(report))
        self.assertIn("aarch64", report["aarch64_note"])
        self.assertIn("no compiled", report["aarch64_note"].lower()
                      .replace("no compiled macos binary", "no compiled"))

    def test_linux_only_import_outside_platform_is_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sealvra").mkdir()
            (root / "sealvra" / "leaky.py").write_text(
                "import dbus\n\nTEST_KEY = 'TEST-ONLY-macos-fixture-001'\n",
                encoding="utf-8",
            )
            proc, report = run_checker(root)
            self.assertEqual(proc.returncode, 1)
            self.assertTrue(any("dbus" in v
                                for v in report["violations"]))

    def test_fake_success_stub_is_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sealvra").mkdir()
            (root / "sealvra" / "platform.py").write_text(
                "def touch_id_approve():\n    return True\n",
                encoding="utf-8",
            )
            proc, report = run_checker(root)
            self.assertEqual(proc.returncode, 1)
            self.assertTrue(any("touch_id_approve" in v
                                for v in report["fake_success_stubs"]))

    def test_marked_not_implemented_stub_is_not_a_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sealvra").mkdir()
            (root / "sealvra" / "platform.py").write_text(
                "def touch_id_approve():\n"
                "    # NOT-IMPLEMENTED-ON-LINUX: requires LAContext\n"
                "    raise NotImplementedError('requires macOS')\n",
                encoding="utf-8",
            )
            proc, report = run_checker(root)
            self.assertEqual(proc.returncode, 0, msg=proc.stdout)
            self.assertEqual(report["fake_success_stubs"], [])

    def test_unapproved_third_party_import_is_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sealvra").mkdir()
            (root / "sealvra" / "other.py").write_text(
                "import requests\n", encoding="utf-8")
            proc, report = run_checker(root)
            self.assertEqual(proc.returncode, 1)
            self.assertTrue(any("requests" in v
                                for v in report["violations"]))

    def test_compile_failure_is_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sealvra").mkdir()
            (root / "sealvra" / "broken.py").write_text(
                "def broken(:\n", encoding="utf-8")
            proc, report = run_checker(root)
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(report["compile"]["failed"], 1)

    def test_docs_state_not_run_honestly(self):
        doc = (BUILD_ROOT / "docs" / "macos.md").read_text(encoding="utf-8")
        self.assertIn("NOT-RUN", doc)
        # The headline must assert the native gap. It used to read
        # "nothing in this document was run on a Mac", which became
        # false once the suite ran on macOS in v0.2 Phase 1/3; the
        # replacement states the invariant that run does not change.
        self.assertIn("no native macOS behaviour is implemented or proven",
                      doc)
        self.assertIn("TEST-ONLY", doc)
        for forbidden_claim in ("macOS binary is available",
                                "tested on a Mac"):
            self.assertNotIn(forbidden_claim, doc)

    def test_no_real_keys_in_w17_files(self):
        # Prefixes assembled at runtime so this test file itself never
        # contains a literal credential-shaped prefix.
        prefixes = ["gh" + "p_", "gh" + "o_", "sk" + "-", "AI" + "za"]
        for path in (SCRIPT, BUILD_ROOT / "docs" / "macos.md",
                     Path(__file__)):
            text = path.read_text(encoding="utf-8")
            for prefix in prefixes:
                self.assertNotIn(prefix, text, msg=f"{path}: {prefix}")


if __name__ == "__main__":
    unittest.main()


class TestW17MacosReadinessV02(unittest.TestCase):
    """v0.2 C8/C9 readiness tests (W07).

    Design markers are checked, never native macOS behaviour: every
    SPEC-ONLY result means "design present, native proof NOT-RUN".
    No test here claims a Mac run.
    """

    def test_readiness_section_has_all_five_areas(self):
        _, report = run_checker(BUILD_ROOT)
        ids = {a["id"] for a in report["macos_readiness"]}
        self.assertEqual(
            ids,
            {"keychain-one-item-per-key",
             "touch-id-two-step",
             "sandboxed-approver-xpc",
             "dmg-packaging",
             "daemon-ipc-macos"},
        )
        for area in report["macos_readiness"]:
            self.assertIn(area["status"], ("SPEC-ONLY", "PARTIAL", "GAP"))

    def test_readiness_gaps_never_flip_verdict(self):
        """Gaps are reported, not hidden — and not violations."""
        proc, report = run_checker(BUILD_ROOT)
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertEqual(report["verdict"], "NO-CHECKABLE-VIOLATION")
        # The expected native gaps must be listed explicitly.
        joined = "\n".join(report["readiness_gaps"])
        self.assertIn("XPC service bundle", joined)
        self.assertIn("sandbox profile", joined)
        self.assertIn("Signed DMG", joined)
        self.assertIn("Code-signing identity", joined)

    def test_keychain_design_is_one_item_per_key_via_platform(self):
        sys.path.insert(0, str(BUILD_ROOT))
        try:
            from sealvra.platform import macos_keychain_design
        finally:
            sys.path.remove(str(BUILD_ROOT))
        design = macos_keychain_design()
        self.assertIn("one Keychain item per", design["items"])
        self.assertNotIn("vault-wide KEK item", design["items"].replace(
            "no vault-wide KEK item", ""))
        self.assertEqual(design["storage_tier"], "S1")
        strict = macos_keychain_design(strict_biometry=True)
        self.assertTrue(any("biometryCurrentSet" in f
                            for f in strict["access_control_flags"]))
        default = macos_keychain_design(strict_biometry=False)
        self.assertTrue(any(".userPresence" in f
                            for f in default["access_control_flags"]))

    def test_touch_id_order_is_gesture_first_confirm_second(self):
        approval = (BUILD_ROOT / "sealvra" / "approval.py").read_text(
            encoding="utf-8")
        self.assertIn("card -> gesture -> confirm", approval)
        platform = (BUILD_ROOT / "sealvra" / "platform.py").read_text(
            encoding="utf-8")
        self.assertIn("gesture + explicit confirm", platform)
        self.assertIn("reuse duration zero", platform)
        # The doc states the same order (C9), correcting the v0.1 doc.
        _, report = run_checker(BUILD_ROOT)
        self.assertTrue(report["doc_honesty"]["checked"])
        self.assertEqual(report["doc_honesty"]["touch_id_order"],
                         "gesture-first-confirm-second")

    def test_approver_xpc_spec_markers_present(self):
        combined = ""
        for name in ("sealvra/platform.py", "sealvra/approval.py"):
            combined += (BUILD_ROOT / name).read_text(encoding="utf-8")
        for marker in ("sealvra-approver", "unprivileged",
                       "metadata only", "single-use", "request hash",
                       "enclave", "code-signing identity"):
            self.assertIn(marker, combined, msg=f"missing XPC marker: {marker}")

    def test_dmg_is_spec_only_no_artifact_no_claim(self):
        _, report = run_checker(BUILD_ROOT)
        self.assertEqual(report["native_macos_artifacts_present"], [])
        self.assertEqual(report["binary_artifacts"], [])
        dmg = [a for a in report["macos_readiness"]
               if a["id"] == "dmg-packaging"][0]
        self.assertEqual(dmg["status"], "SPEC-ONLY")
        ci = (BUILD_ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8")
        self.assertIn("macos", ci)
        self.assertIn("macos_check.py", ci)
        doc = (BUILD_ROOT / "docs" / "macos.md").read_text(encoding="utf-8")
        self.assertIn("spec only", doc)
        self.assertIn("Gatekeeper", doc)

    def test_daemon_ipc_design_present_native_proof_not_run(self):
        _, report = run_checker(BUILD_ROOT)
        daemon = [a for a in report["macos_readiness"]
                  if a["id"] == "daemon-ipc-macos"][0]
        # v0.2 daemon.py (W01) now has the explicit darwin peer-UID
        # branch (getpeereid) plus 0700/0600 socket permissions, so
        # the design is SPEC-ONLY. SPEC-ONLY is not a Mac proof:
        # the native run is still NOT-RUN (docs/macos.md §6 D4).
        self.assertEqual(daemon["status"], "SPEC-ONLY")
        self.assertEqual(daemon["missing_marker_groups"], [])
        daemon_py = (BUILD_ROOT / "sealvra" / "daemon.py").read_text(
            encoding="utf-8")
        self.assertIn('sys.platform == "darwin"', daemon_py)
        self.assertIn("getpeereid", daemon_py)

    def test_docs_section6_covers_mac_plan(self):
        doc = (BUILD_ROOT / "docs" / "macos.md").read_text(encoding="utf-8")
        for required in ("TEST-ONLY-macos-m5-001", "Keychain",
                         "Touch ID", "approver", "DMG", "Gatekeeper",
                         "gesture first", "confirm second",
                         "NOT-RUN", "Result table"):
            self.assertIn(required, doc, msg=f"missing from macos.md §6: {required}")
        # Enrolment test must not ask the user to touch their own prints.
        self.assertIn("Do not remove or re-enrol", doc)

    def test_missing_platform_tree_reports_gaps_without_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sealvra").mkdir()
            (root / "sealvra" / "other.py").write_text(
                "x = 1\n", encoding="utf-8")
            proc, report = run_checker(root)
            self.assertEqual(proc.returncode, 0, msg=proc.stdout)
            statuses = {a["status"] for a in report["macos_readiness"]}
            self.assertIn("GAP", statuses)
            self.assertFalse(report["doc_honesty"]["checked"])

    def test_doc_missing_headline_is_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sealvra").mkdir()
            (root / "sealvra" / "other.py").write_text(
                "x = 1\n", encoding="utf-8")
            (root / "docs").mkdir()
            (root / "docs" / "macos.md").write_text(
                "no headline here\n", encoding="utf-8")
            proc, report = run_checker(root)
            self.assertEqual(proc.returncode, 1)
            self.assertTrue(any("headline" in v
                                for v in report["violations"]))
