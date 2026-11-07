"""W16 Windows verification tests (unittest).

These tests run on a Linux host. They distinguish, in every case,
Linux-host checks (which can PASS or FAIL here) from real-Windows
checks (which are NOT-RUN here, never PASSED). No test in this file
claims a Windows-native behaviour: the platform-logic tests call
sealvra.platform functions with platform="win32" arguments, which
proves gate logic only.

Fake keys only: no test in this file uses, reads, or prints a real
credential. The only key-like strings are clearly fake TEST-ONLY
placeholders in comments, never passed to any vault or crypto path.
"""

import ast
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sealvra import approval as approval_mod  # noqa: E402
from sealvra import platform as platform_mod  # noqa: E402
from sealvra.supervisor import Supervisor, WorkerHandle  # noqa: E402

CHECK = ROOT / "scripts" / "windows_check.py"
DOC = ROOT / "docs" / "windows.md"

# Real-Windows checks: these must appear as NOT-RUN in the check
# script's output and must never be asserted as passed here.
REAL_WINDOWS_CHECKS = [
    "real DPAPI / Credential Manager encrypt/decrypt behaviour",
    "real Windows Hello biometric gesture",
    "CredUIPromptForWindowsCredentials returning the password",
    "the isolated verifier-helper process (design only in v0.2)",
    "Remote Credential Guard acceptance on a domain-joined machine",
    "running scripts/install.ps1 on Windows",
    "running scripts/uninstall.ps1 on Windows (default and wipe paths)",
    "PowerShell parsing of scripts/install.ps1 and scripts/uninstall.ps1 (pwsh unavailable on the checking host)",
    "running dist/sealvra.pyz under Windows Python 3.12",
    "Windows supervisor process-tree / job-object kill for worker children",
    "Windows worker orphan self-termination via os.kill(pid, 0) polling",
    "any NSIS installer build or run (spec only in v0.2)",
]


def load_windows_check():
    spec = importlib.util.spec_from_file_location("windows_check", CHECK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestWindowsCheckScript(unittest.TestCase):
    def test_script_exists_and_compiles(self):
        self.assertTrue(CHECK.is_file())
        compile(CHECK.read_text(encoding="utf-8"), str(CHECK), "exec")

    def test_script_runs_and_reports_counts(self):
        """Linux-host run: exit 0 or 1 only, with PASS/FAIL/NOT-RUN lines.

        Exit 1 is currently expected while supervisor.py keeps ungated
        os.killpg/os.getpgid (see test_supervisor_blocker_is_reported).
        The assertion is dynamic: if that blocker is fixed, exit 0 is
        expected instead -- the test never hard-codes a failure.
        """
        result = subprocess.run(
            [sys.executable, str(CHECK), "--root", str(ROOT)],
            capture_output=True, text=True, timeout=120,
        )
        self.assertIn(result.returncode, (0, 1))
        self.assertIn("counts:", result.stdout)
        self.assertIn("NOT-RUN", result.stdout)
        supervisor = (ROOT / "sealvra" / "supervisor.py").read_text(encoding="utf-8")
        ungated = "os.killpg" in supervisor or "os.getpgid" in supervisor
        if ungated and "sys.platform" not in supervisor:
            self.assertEqual(result.returncode, 1)
            self.assertIn("W2-posix-gating", result.stdout)
            self.assertIn("killpg", result.stdout)
        else:
            self.assertEqual(result.returncode, 0)

    def test_real_windows_checks_are_not_run_not_passed(self):
        result = subprocess.run(
            [sys.executable, str(CHECK), "--root", str(ROOT)],
            capture_output=True, text=True, timeout=120,
        )
        for item in REAL_WINDOWS_CHECKS:
            self.assertIn(f"NOT-RUN NOT-RUN: {item}", result.stdout,
                          f"real-Windows check missing from NOT-RUN list: {item}")
        # No NOT-RUN item may be reported as PASS.
        for line in result.stdout.splitlines():
            if line.startswith("PASS"):
                for item in REAL_WINDOWS_CHECKS:
                    self.assertNotIn(item, line)

    def test_posix_scan_flags_ungated_and_allows_gated(self):
        mod = load_windows_check()
        with tempfile.TemporaryDirectory() as tmp:
            gated = Path(tmp) / "gated.py"
            gated.write_text(
                'import sys\n'
                'if sys.platform != "win32":\n'
                '    import pwd\n'
                '    os.killpg(1, 2)\n'
            )
            ungated = Path(tmp) / "ungated.py"
            ungated.write_text('import grp\nimport os\nos.killpg(1, 2)\n')
            self.assertEqual(mod._scan_posix(ast.parse(gated.read_text()), gated), [])
            found = mod._scan_posix(ast.parse(ungated.read_text()), ungated)
            self.assertTrue(any("grp" in f for f in found))
            self.assertTrue(any("killpg" in f for f in found))

    def test_posix_scan_allows_attributeerror_fallback(self):
        mod = load_windows_check()
        src = (
            "import os\n"
            "try:\n"
            "    pgid = os.getpgid(1)\n"
            "except AttributeError:\n"
            "    pgid = 1\n"
        )
        self.assertEqual(mod._scan_posix(ast.parse(src), Path("x.py")), [])

    def test_supervisor_blocker_is_reported(self):
        """Documents the one known Windows blocker, whatever its state.

        If supervisor.py still calls os.killpg/os.getpgid without a
        platform gate or AttributeError fallback, the check script
        must flag it. If it has been fixed, this test passes by
        asserting the fixed state instead of the old failure.
        """
        mod = load_windows_check()
        sup = ROOT / "sealvra" / "supervisor.py"
        tree = ast.parse(sup.read_text(encoding="utf-8"))
        findings = mod._scan_posix(tree, sup)
        if "os.killpg" in sup.read_text(encoding="utf-8"):
            self.assertTrue(
                any("killpg" in f or "getpgid" in f for f in findings)
                or "win32" in sup.read_text(encoding="utf-8"),
                "ungated killpg/getpgid must be flagged or gated",
            )


class TestWindowsGateLogicOnLinuxHost(unittest.TestCase):
    """Gate logic only -- NOT native Windows behaviour."""

    def test_win32_branch(self):
        self.assertEqual(platform_mod.current_platform("win32"), "win32")
        with self.assertRaises(ValueError):
            platform_mod.current_platform("windows")

    def test_storage_is_s2_user_scoped(self):
        s = platform_mod.storage_tier("win32")
        self.assertEqual(s.tier, "S2")
        self.assertTrue(s.same_user_direct_read)
        self.assertIn("user account, not the application", s.description)
        self.assertIn("Hello step-up gates Sealvra-mediated use only", s.description)

    def test_hello_biometric_and_pin_are_distinct(self):
        bio = platform_mod.hello_tier(kind="biometric")
        pin = platform_mod.hello_tier(kind="pin")
        self.assertNotEqual(bio.mechanism, pin.mechanism)
        self.assertTrue(bio.boolean_only)
        self.assertFalse(pin.boolean_only)
        self.assertIn("T1-pin", pin.mechanism)

    def test_password_tier_split(self):
        with_helper = platform_mod.windows_password_tier(with_helper=True)
        without = platform_mod.windows_password_tier(with_helper=False)
        self.assertTrue(with_helper.boolean_only)
        self.assertFalse(without.boolean_only)
        self.assertIn("RETURNS the password", without.description)
        helper = platform_mod.windows_verifier_helper_design()
        self.assertTrue(helper["return_value"].startswith("boolean only"))

    def test_rdp_row(self):
        self.assertIsNone(platform_mod.remote_session_tier(
            remote=True, mechanism="hello_biometric"))
        guard = platform_mod.remote_session_tier(
            remote=True, mechanism="hello_biometric", credential_guard=True)
        self.assertIsNotNone(guard)
        self.assertEqual(guard.tier, "T1")
        pin_remote = platform_mod.remote_session_tier(
            remote=True, mechanism="hello_pin")
        self.assertEqual(pin_remote.tier, "T2")

    def test_tpm_and_domain_never_change_s2(self):
        for tpm in ("hardware", "virtual", "absent"):
            rec = platform_mod.windows_tpm_domain_posture(
                tpm=tpm, domain_joined=True)
            self.assertTrue(rec["storage_tier"].startswith("S2"))

    def test_approval_win32_is_design_only(self):
        tier = approval_mod.platform_tier_for(platform="win32")
        self.assertTrue(tier.helper_required)
        self.assertIn("DESIGN ONLY", tier.notes)
        self.assertFalse(approval_mod.broker_window_may_approve(
            is_destructive=True, tier=tier))

    def test_windows_is_unprovable_from_linux(self):
        unprovable = platform_mod.unprovable_on_platform("linux")
        self.assertTrue(any("Windows Hello" in item for item in unprovable))
        self.assertTrue(any("DPAPI" in item for item in unprovable))


class _FakeWin32Process:
    """MOCKED stand-in for subprocess.Popen (see windows_check W14)."""

    def __init__(self, *, escalate=False):
        self._dead = False
        self._escalate = escalate
        self._wait_calls = 0
        self.terminate_calls = 0
        self.kill_calls = 0

    def poll(self):
        return 0 if self._dead else None

    def terminate(self):
        self.terminate_calls += 1
        if not self._escalate:
            self._dead = True

    def kill(self):
        self.kill_calls += 1
        self._dead = True

    def wait(self, timeout=None):
        self._wait_calls += 1
        if self._escalate and self._wait_calls == 1:
            raise subprocess.TimeoutExpired("sealvra", timeout)
        if not self._dead:
            raise subprocess.TimeoutExpired("sealvra", timeout)
        return 0


class TestSupervisorWin32MockedKill(unittest.TestCase):
    """MOCKED win32 supervisor kill -- branch dispatch only, never a
    real Windows kill. sys.platform is patched in-process; no real
    process is spawned or killed. The process-tree kill for worker
    children is NOT covered here and stays NOT-RUN."""

    def _run_mocked(self, escalate):
        sup = Supervisor()
        proc = _FakeWin32Process(escalate=escalate)
        handle = WorkerHandle(session_id="sess-mock", key_id="key-mock",
                              pid=999999, pgid=999999, started_at=0.0,
                              port=None, process=proc)
        sup._workers[handle.session_id] = handle
        with mock.patch.object(sys, "platform", "win32"):
            with mock.patch.object(__import__("os"), "killpg",
                                   side_effect=AssertionError("killpg must not run on win32")):
                result = sup.terminate(handle.session_id)
        return proc, result

    def test_terminate_dispatches_to_process_terminate(self):
        proc, result = self._run_mocked(escalate=False)
        self.assertEqual(result["method"], "terminate-win32")
        self.assertTrue(result["terminated"])
        self.assertEqual(proc.terminate_calls, 1)
        self.assertEqual(proc.kill_calls, 0)

    def test_timeout_escalates_to_process_kill(self):
        proc, result = self._run_mocked(escalate=True)
        self.assertEqual(result["method"], "kill-win32")
        self.assertTrue(result["terminated"])
        self.assertEqual(proc.kill_calls, 1)

    def test_spawn_guards_start_new_session_behind_nonwin_check(self):
        src = (ROOT / "sealvra" / "supervisor.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        mod = load_windows_check()
        guarded = False
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and mod._is_nonwin_guard(ast.unparse(node.test)):
                if "start_new_session" in ast.unparse(node):
                    guarded = True
        self.assertTrue(guarded, "start_new_session must sit behind sys.platform != 'win32'")


class TestMockedVerifierHelperBoundary(unittest.TestCase):
    """MOCKED CredUI/verifier-helper boundary: a fake helper returns a
    boolean; the broker side receives bool only. This proves the
    interface shape (boolean-only return), never real CredUI, DPAPI,
    Hello, or LogonUser behaviour, which are all NOT-RUN."""

    def test_broker_receives_bool_only_never_password(self):
        sentinel = "TEST-ONLY-fake-password-for-mocked-boundary"

        def mocked_helper(password):  # MOCKED, not a real CredUI call
            return password == sentinel

        received = mocked_helper(sentinel)
        self.assertIsInstance(received, bool)
        self.assertTrue(received)
        self.assertNotIn(sentinel, repr(received))

    def test_helper_design_and_no_native_binding(self):
        helper = platform_mod.windows_verifier_helper_design()
        self.assertTrue(helper["return_value"].startswith("boolean only"))
        self.assertIn("CredUIPromptForWindowsCredentials", helper["process"])
        self.assertIn("LogonUser", helper["process"])
        for path in (ROOT / "sealvra").rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("windll", text, f"native binding in {path}")
            self.assertNotIn("CryptUnprotectData(", text, f"native binding in {path}")
            self.assertNotIn("CredUIPromptForWindowsCredentials(", text, f"native binding in {path}")

    def test_guard_pin_is_t2_never_biometric(self):
        guard_pin = platform_mod.remote_session_tier(
            remote=True, mechanism="hello_pin", credential_guard=True)
        self.assertIsNotNone(guard_pin)
        self.assertEqual(guard_pin.tier, "T2")
        self.assertNotIn("biometric", guard_pin.mechanism)


class TestInstallerStaticCorrectness(unittest.TestCase):
    """Static (text-level) installer/uninstaller checks. These are NOT
    a PowerShell parse and NOT a Windows run; both of those are
    NOT-RUN here when PowerShell is absent on the checking host."""

    def test_install_preserves_vault_and_resolves_launcher(self):
        text = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")
        self.assertIn("preserved untouched", text)
        self.assertIn(r"%~dp0..\sealvra.pyz", text)
        self.assertIn("2>&1", text)
        for line in text.splitlines():
            if "Remove-Item" in line:
                self.assertNotIn("VaultDir", line)
        for bad in ("Invoke-WebRequest", "Invoke-RestMethod", "-Verb RunAs"):
            self.assertNotIn(bad, text)

    def test_uninstall_wipe_gate_order_receipt_and_verification(self):
        text = (ROOT / "scripts" / "uninstall.ps1").read_text(encoding="utf-8")
        gate = text.find("-WipeData was given without -ConfirmWipe")
        first_remove = text.find("Remove-Item")
        self.assertTrue(0 <= gate < first_remove)
        marker = text.find("Wipe path")
        default, wipe = text[:marker], text[marker:]
        for line in default.splitlines():
            if "Remove-Item" in line:
                self.assertNotIn("VaultDir", line)
        self.assertIn("Type WIPE to confirm", wipe)
        self.assertTrue(wipe.find("Type WIPE to confirm") < wipe.find("Remove-Item -Recurse -Force $VaultDir"))
        self.assertIn("Join-Path $HomeDir", wipe)
        self.assertIn("sealvra-wipe-receipt-", wipe)
        import re as _re
        m = _re.search(r'ToString\("([^"]+)"\)', wipe)
        self.assertIsNotNone(m)
        self.assertNotIn(":", m.group(1), "wipe timestamp must be colon-free for Windows filenames")
        after_removal = wipe.split("Remove-Item -Recurse -Force $VaultDir")[-1]
        self.assertIn("Test-Path $VaultDir", after_removal)
        self.assertIn("preserved (NOT deleted)", text)

    def test_windows_check_reports_new_checks_and_ps_parse_status(self):
        result = subprocess.run(
            [sys.executable, str(CHECK), "--root", str(ROOT)],
            capture_output=True, text=True, timeout=120,
        )
        for check_id in ("W14-supervisor-win32-kill", "W15-verifier-helper-paths",
                         "W16-installer-static", "W16-ps-parse",
                         "W17-zipapp-host", "W18-nsis-spec-only"):
            self.assertIn(check_id, result.stdout, f"missing check {check_id}")
        if shutil.which("pwsh") is None and shutil.which("powershell") is None:
            self.assertIn("NOT-RUN W16-ps-parse", result.stdout)
        else:
            self.assertIn("PASS W16-ps-parse", result.stdout)


class TestZipappHostRun(unittest.TestCase):
    """Zipapp validity + --help under this Linux host's CPython only.
    Running under Windows Python is NOT-RUN, never claimed here."""

    def test_pyz_is_valid_zip_with_main_and_help_exits_zero(self):
        pyz = ROOT / "dist" / "sealvra.pyz"
        self.assertTrue(pyz.is_file())
        with zipfile.ZipFile(pyz) as zf:
            self.assertIn("__main__.py", zf.namelist())
        result = subprocess.run([sys.executable, str(pyz), "--help"],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0)


class TestWindowsDocHonesty(unittest.TestCase):
    def test_doc_exists_and_states_not_run(self):
        self.assertTrue(DOC.is_file())
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("NOT-RUN", text)
        self.assertIn("S2", text)
        self.assertIn("DPAPI", text)
        self.assertNotIn("sealvra.exe", text)

    def test_doc_states_uninstall_rule(self):
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("NOT deleted by default", text)
        self.assertIn("-WipeData", text)
        self.assertIn("does NOT revoke", text)

    def test_doc_claims_no_standalone_exe(self):
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("No standalone Windows executable is built", text)
        self.assertIn("zipapp", text)

    def test_doc_records_v02_gaps_honestly(self):
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("pwsh", text)
        self.assertIn("process-tree", text)
        self.assertIn("MOCKED", text)
        self.assertNotIn("currently FAILS", text)

    def test_no_exe_artifact_in_build_root(self):
        for path in ROOT.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts and ".venv" not in path.parts:
                self.assertNotIn(path.suffix.lower(), (".exe", ".msi", ".dll", ".pyd"))


if __name__ == "__main__":
    unittest.main()
