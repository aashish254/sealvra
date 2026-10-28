"""W20 packaging tests (unittest).

Covers: scripts/make_zipapp.py determinism and --help behaviour,
scripts/install.sh + scripts/uninstall.sh syntax and sandbox
install/uninstall behaviour, scripts/install.ps1 +
scripts/uninstall.ps1 (PowerShell parse check where PowerShell is
available, otherwise honestly SKIPPED -- never claimed passed), and
.github/workflows/ci.yml structure.

No real keys anywhere: fixture vault markers use TEST-ONLY strings.
No real uninstall of a user's data is ever performed: every
install/uninstall run here uses a temporary sandbox HOME, never the
real home directory.

The real keyholder/ package is NOT built by these tests as a
pass/fail gate on its own behaviour: W10 owns it and it has not
landed yet. test_real_package_build_fails_closed_or_builds records
the current state honestly -- fail-closed while __main__.py is
missing, a successful build once it lands.
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

BUILD_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = BUILD_ROOT / "scripts"
MAKE_ZIPAPP = SCRIPTS / "make_zipapp.py"
CI_YML = BUILD_ROOT / ".github" / "workflows" / "ci.yml"

FIXTURE_MAIN = '''\
import sys


def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print("usage: keyholder [--help]")
        return 0
    print("keyholder fixture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def run(cmd, env=None, input_text=None):
    merged = dict(os.environ)
    if env:
        merged.update(env)
    return subprocess.run(
        cmd, capture_output=True, text=True, env=merged, input=input_text
    )


class FixtureMixin(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="keyholder-w20-"))
        self.fixture_root = self.tmp / "fixture"
        pkg = self.fixture_root / "keyholder"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text('"""Fixture package."""\n')
        (pkg / "__main__.py").write_text(FIXTURE_MAIN)
        (pkg / "cli.py").write_text('"""Fixture cli module."""\n')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def build_fixture(self, name, epoch):
        out = self.tmp / name
        result = run(
            [sys.executable, str(MAKE_ZIPAPP),
             "--root", str(self.fixture_root), "--output", str(out)],
            env={"SOURCE_DATE_EPOCH": str(epoch)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return out


class TestZipapp(FixtureMixin):
    def test_deterministic_same_epoch(self):
        a = self.build_fixture("a.pyz", 1700000000)
        b = self.build_fixture("b.pyz", 1700000000)
        self.assertEqual(a.read_bytes(), b.read_bytes())

    def test_different_epoch_changes_output(self):
        # Zip DOS timestamps have 2-second resolution, so epochs must
        # differ by more than 2 seconds to change the stored timestamp.
        a = self.build_fixture("a.pyz", 1700000000)
        b = self.build_fixture("b.pyz", 1700000010)
        self.assertNotEqual(a.read_bytes(), b.read_bytes())
        with zipfile.ZipFile(a) as za, zipfile.ZipFile(b) as zb:
            self.assertNotEqual(
                za.getinfo("__main__.py").date_time,
                zb.getinfo("__main__.py").date_time)

    def test_zipapp_help_runs(self):
        pyz = self.build_fixture("keyholder.pyz", 1700000000)
        result = run([sys.executable, str(pyz), "--help"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage: keyholder", result.stdout)

    def test_shebang_and_no_absolute_paths(self):
        pyz = self.build_fixture("keyholder.pyz", 1700000000)
        raw = pyz.read_bytes()
        self.assertTrue(raw.startswith(b"#!/usr/bin/env python3\n"))
        with zipfile.ZipFile(pyz) as zf:
            names = zf.namelist()
            top_main = zf.read("__main__.py").decode()
        self.assertEqual(names, sorted(names))
        # Top-level entry is a shim delegating to W10's package, not
        # a copy of it (the package entry uses a relative import).
        self.assertIn("run_module", top_main)
        self.assertIn("keyholder", top_main)
        for name in names:
            self.assertFalse(name.startswith("/"), name)
            self.assertNotIn(str(self.fixture_root), name)
        self.assertIn("__main__.py", names)
        self.assertIn("keyholder/__main__.py", names)

    def test_real_package_build_fails_closed_or_builds(self):
        entry = BUILD_ROOT / "keyholder" / "__main__.py"
        out = self.tmp / "real.pyz"
        result = run(
            [sys.executable, str(MAKE_ZIPAPP),
             "--root", str(BUILD_ROOT), "--output", str(out)],
            env={"SOURCE_DATE_EPOCH": "1700000000"},
        )
        if not entry.is_file():
            # W10 has not landed yet: the only honest behaviour is a
            # non-zero exit and NO output file.
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(out.exists())
        else:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(out.exists())


class TestScriptSyntax(unittest.TestCase):
    def test_install_sh_syntax(self):
        result = run(["bash", "-n", str(SCRIPTS / "install.sh")])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_uninstall_sh_syntax(self):
        result = run(["bash", "-n", str(SCRIPTS / "uninstall.sh")])
        self.assertEqual(result.returncode, 0, result.stderr)

    def _powershell_parse(self, path):
        pwsh = shutil.which("pwsh") or shutil.which("powershell")
        if pwsh is None:
            self.skipTest(
                "PowerShell unavailable on this machine -- parse check "
                "NOT RUN, not passed"
            )
        script = (
            "$errors = $null; $tokens = $null; "
            "[System.Management.Automation.Language.Parser]::ParseFile"
            f"('{path}', [ref]$tokens, [ref]$errors) | Out-Null; "
            "if ($errors.Count -gt 0) { $errors | ForEach-Object { "
            "Write-Output $_.Message }; exit 1 }"
        )
        result = run([pwsh, "-NoProfile", "-Command", script])
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_install_ps1_parse(self):
        self._powershell_parse(SCRIPTS / "install.ps1")

    def test_uninstall_ps1_parse(self):
        self._powershell_parse(SCRIPTS / "uninstall.ps1")

    def test_uninstall_scripts_state_wipe_does_not_revoke(self):
        for name in ("uninstall.sh", "uninstall.ps1"):
            text = (SCRIPTS / name).read_text()
            self.assertIn("does NOT revoke", text, name)
        self.assertIn("--wipe-data", (SCRIPTS / "uninstall.sh").read_text())
        self.assertIn("-WipeData", (SCRIPTS / "uninstall.ps1").read_text())

    def test_install_scripts_state_vault_preserved_on_reinstall(self):
        for name in ("install.sh", "install.ps1"):
            text = (SCRIPTS / name).read_text()
            self.assertIn("preserved", text.lower(), name)


class TestInstallUninstallSandbox(FixtureMixin):
    def sandbox(self):
        home = self.tmp / "home"
        (home / ".local" / "bin").mkdir(parents=True)
        (home / ".local" / "share" / "keyholder").mkdir(parents=True)
        launcher = home / ".local" / "bin" / "keyholder"
        launcher.write_text("#!/bin/sh\nexit 0\n")
        launcher.chmod(0o755)
        program = home / ".local" / "share" / "keyholder" / "keyholder.pyz"
        program.write_text("# fake program\n")
        vault = home / ".keyholder"
        vault.mkdir()
        marker = vault / "marker.txt"
        marker.write_text("TEST-ONLY-vault-marker\n")
        return home, launcher, program, vault, marker

    def test_uninstall_default_preserves_data(self):
        home, launcher, program, vault, marker = self.sandbox()
        result = run(
            ["sh", str(SCRIPTS / "uninstall.sh")],
            env={"HOME": str(home), "PATH": os.environ["PATH"]},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(launcher.exists())
        self.assertFalse(program.exists())
        self.assertTrue(marker.exists())
        self.assertEqual(marker.read_text(), "TEST-ONLY-vault-marker\n")
        self.assertIn("preserved", result.stdout.lower())

    def test_uninstall_wipe_without_confirm_refuses(self):
        home, launcher, program, vault, marker = self.sandbox()
        result = run(
            ["sh", str(SCRIPTS / "uninstall.sh"), "--wipe-data"],
            env={"HOME": str(home), "PATH": os.environ["PATH"]},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(marker.exists())
        self.assertTrue(vault.exists())

    def test_uninstall_wipe_with_confirm_deletes_and_keeps_receipt(self):
        home, launcher, program, vault, marker = self.sandbox()
        result = run(
            ["sh", str(SCRIPTS / "uninstall.sh"),
             "--wipe-data", "--confirm-wipe"],
            env={"HOME": str(home), "PATH": os.environ["PATH"]},
            input_text="WIPE\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(vault.exists())
        self.assertIn("does NOT revoke", result.stdout)
        receipts = list(home.glob("keyholder-wipe-receipt-*.json"))
        self.assertEqual(len(receipts), 1)
        self.assertIn("vault_wipe", receipts[0].read_text())

    def test_install_then_reinstall_preserves_vault(self):
        home = self.tmp / "home2"
        home.mkdir()
        pyz = self.build_fixture("keyholder.pyz", 1700000000)
        vault = home / "vault"
        prefix = home / ".local"
        env = {"HOME": str(home), "PATH": os.environ["PATH"]}
        result = run(
            ["sh", str(SCRIPTS / "install.sh"), str(pyz),
             "--prefix", str(prefix), "--vault-dir", str(vault)],
            env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        installed = prefix / "share" / "keyholder" / "keyholder.pyz"
        launcher = prefix / "bin" / "keyholder"
        self.assertTrue(installed.exists())
        self.assertTrue(launcher.exists())
        self.assertEqual(stat.S_IMODE(vault.stat().st_mode), 0o700)
        help_result = run([str(launcher), "--help"], env=env)
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("usage: keyholder", help_result.stdout)
        marker = vault / "marker.txt"
        marker.write_text("TEST-ONLY-vault-marker\n")
        result2 = run(
            ["sh", str(SCRIPTS / "install.sh"), str(pyz),
             "--prefix", str(prefix), "--vault-dir", str(vault)],
            env=env,
        )
        self.assertEqual(result2.returncode, 0, result2.stderr)
        self.assertTrue(marker.exists())
        self.assertIn("preserved", result2.stdout.lower())


class TestCIWorkflow(unittest.TestCase):
    def test_ci_structure(self):
        # Deliberately stdlib-only text checks: the v0.1 stack allows
        # exactly two third-party dependencies (cryptography,
        # argon2-cffi), so this test must not import PyYAML even
        # though it happens to be installed on this machine.
        import re

        text = CI_YML.read_text()
        self.assertIn("PREPARED, NOT RUN", text)
        self.assertNotIn("shields.io", text)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("GITHUB_TOKEN", text)
        # One job block per OS, each on the contracted runner.
        for name, runner in (("linux", "ubuntu-latest"),
                             ("windows", "windows-latest"),
                             ("macos", "macos-latest")):
            block = re.search(
                r"(?m)^  " + name + r":\n(.*?)(?=^  \w+:|\Z)",
                text, re.DOTALL)
            self.assertIsNotNone(block, name)
            self.assertIn(runner, block.group(1), name)
            self.assertIn("3.12", block.group(1), name)
            self.assertIn("unittest discover", block.group(1), name)
            self.assertIn("make_zipapp", block.group(1), name)
            self.assertIn("upload-artifact", block.group(1), name)
            self.assertIn("requirements.txt", block.group(1), name)
        windows = re.search(
            r"(?m)^  windows:\n(.*?)(?=^  \w+:|\Z)", text, re.DOTALL)
        macos = re.search(
            r"(?m)^  macos:\n(.*?)(?=^  \w+:|\Z)", text, re.DOTALL)
        self.assertIn("scripts/windows_check.py", windows.group(1))
        self.assertIn("scripts/macos_check.py", macos.group(1))


class TestW19SupplyChainGates(unittest.TestCase):
    """W19 v0.2 additions: dependency gates, SBOM diff, CI validity.

    The SBOM/repro scripts pick the build root's .venv interpreter
    themselves, so these tests run them with the test runner's
    interpreter and still check the pinned versions. No real keys
    anywhere; fixtures use TEST-ONLY strings only.
    """

    def run_script(self, script, args):
        return run([sys.executable, str(SCRIPTS / script)] + args)

    def test_requirements_exactly_two_pinned(self):
        text = (BUILD_ROOT / "requirements.txt").read_text()
        pins = [ln.strip() for ln in text.splitlines()
                if ln.strip() and not ln.strip().startswith("#")]
        self.assertEqual(sorted(pins),
                         ["argon2-cffi==25.1.0", "cryptography==50.0.2"])
        for token in ("--extra-index-url", "--index-url", ">=", "~=", "-e "):
            self.assertNotIn(token, text)

    def test_sbom_gate_rejects_third_dependency(self):
        # sbom.py checks the requirements set before installed
        # versions, so this fails fast regardless of interpreter.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "requirements.txt").write_text(
                "cryptography==50.0.2\nargon2-cffi==25.1.0\n"
                "requests==2.32.0\n")
            (root / "scripts").mkdir()
            result = self.run_script("sbom.py", ["--root", str(root)])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("exactly", result.stderr + result.stdout)

    def test_sbom_gate_rejects_registry_redirection(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "requirements.txt").write_text(
                "cryptography==50.0.2\nargon2-cffi==25.1.0\n"
                "--extra-index-url https://example.invalid/simple\n")
            (root / "scripts").mkdir()
            result = self.run_script("sbom.py", ["--root", str(root)])
            self.assertNotEqual(result.returncode, 0)

    def test_sbom_diff_vs_committed_passes(self):
        with tempfile.TemporaryDirectory() as td:
            fresh = Path(td) / "fresh.json"
            result = self.run_script(
                "sbom.py", ["--diff", str(BUILD_ROOT / "sbom.json"),
                            "--output", str(fresh)])
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("no component change", result.stdout)

    def test_sbom_diff_fails_on_component_change(self):
        import json

        with tempfile.TemporaryDirectory() as td:
            tampered = Path(td) / "tampered.json"
            bom = json.loads((BUILD_ROOT / "sbom.json").read_text())
            for comp in bom["components"]:
                if comp["name"] == "cffi":
                    comp["version"] = "9.9.9"
            tampered.write_text(json.dumps(bom))
            result = self.run_script(
                "sbom.py", ["--diff", str(tampered),
                            "--output", str(Path(td) / "fresh.json")])
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("version change cffi", result.stdout)

    def test_sbom_has_build_time_inventory_and_cap(self):
        import json

        bom = json.loads((BUILD_ROOT / "sbom.json").read_text())
        self.assertIn("build_time", bom)
        self.assertIn("pip", bom["build_time"]["tools"])
        script_paths = [s["path"] for s in bom["build_time"]["scripts"]]
        self.assertIn("scripts/sbom.py", script_paths)
        self.assertIn("scripts/make_zipapp.py", script_paths)
        direct = [c for c in bom["components"]
                  if c["properties"][0]["value"] == "direct"]
        transitive = [c for c in bom["components"]
                      if c["properties"][0]["value"] == "transitive"]
        self.assertEqual(len(direct), 2)
        self.assertLessEqual(len(transitive), 10)
        self.assertLessEqual(len(bom["components"]), 12)
        self.assertEqual(bom["metadata"]["component"]["version"], "0.2")

    def test_repro_check_packaging_epoch_passes_and_cold_cache_reported(self):
        # repro_check exits 1 while the known make_zipapp pycache
        # defect is open (see docs/supply-chain.md §9): the only
        # FAIL line must be packaging-cold-cache, and it must name
        # __pycache__. Once W20 fixes make_zipapp, this test passes
        # with zero FAIL lines -- either state is accepted, any
        # OTHER failure is not.
        env = dict(os.environ, SOURCE_DATE_EPOCH="1700000000")
        result = run([sys.executable, str(SCRIPTS / "repro_check.py")], env=env)
        fails = [ln for ln in result.stdout.splitlines() if "FAIL " in ln]
        self.assertIn("PASS packaging-epoch", result.stdout)
        self.assertIn("PASS registry-config", result.stdout)
        for ln in fails:
            self.assertIn("packaging-cold-cache", ln, ln)
            self.assertIn("__pycache__", ln, ln)
        self.assertLessEqual(len(fails), 1)
        self.assertIn(result.returncode, (0, 1))


class TestW19CIWorkflowValidity(unittest.TestCase):
    """W19 v0.2 additions: ci.yml parses as YAML and has the v0.2 job shape."""

    def _load(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML unavailable to this interpreter -- "
                          "YAML parse NOT RUN, not passed")
        with open(CI_YML, encoding="utf-8") as fh:
            return yaml.safe_load(fh)

    def test_ci_yaml_parses_and_jobs(self):
        data = self._load()
        jobs = data["jobs"]
        for name in ("linux", "windows", "macos", "rebuild", "sign"):
            self.assertIn(name, jobs, name)
        self.assertEqual(jobs["linux"]["runs-on"], "ubuntu-latest")
        self.assertEqual(jobs["windows"]["runs-on"], "windows-latest")
        self.assertEqual(jobs["macos"]["runs-on"], "macos-latest")
        self.assertEqual(jobs["sign"]["environment"], "signing")
        self.assertEqual(jobs["rebuild"]["needs"], ["linux"])
        self.assertEqual(jobs["sign"]["needs"], ["rebuild"])

    def test_ci_sign_job_has_no_checkout_and_is_fail_closed(self):
        import re

        data = self._load()
        sign_steps = data["jobs"]["sign"]["steps"]
        for step in sign_steps:
            self.assertNotIn("actions/checkout", str(step.get("uses", "")))
        text = CI_YML.read_text()
        sign_block = re.search(r"(?m)^  sign:\n(.*)\Z", text, re.DOTALL).group(1)
        self.assertIn("environment: signing", sign_block)
        # No checkout ACTION in the sign job (comments may mention
        # the absence of one -- that is the point, not a violation).
        self.assertNotIn("actions/checkout", sign_block)
        self.assertIn("NOT CONFIGURED", sign_block)

    def test_ci_structure_v02(self):
        import re

        text = CI_YML.read_text()
        self.assertIn("PREPARED, NOT RUN", text)
        self.assertIn("NEVER RUN", text)
        self.assertNotIn("shields.io", text)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("GITHUB_TOKEN", text)
        self.assertNotIn("pull_request_target", text)
        # Every build job: cold-cache install, SBOM gates, SDE, zipapp.
        for name in ("linux", "windows", "macos"):
            block = re.search(
                r"(?m)^  " + name + r":\n(.*?)(?=^  \w+:|\Z)",
                text, re.DOTALL)
            self.assertIsNotNone(block, name)
            body = block.group(1)
            self.assertIn("--no-cache-dir", body, name)
            self.assertIn("scripts/sbom.py", body, name)
            self.assertIn("--diff sbom.json", body, name)
            self.assertIn("scripts/repro_check.py", body, name)
            self.assertIn("SOURCE_DATE_EPOCH", body, name)
            self.assertIn("make_zipapp", body, name)
            self.assertIn("unittest discover", body, name)
        # Rebuild job compares hashes; sign job validates pre-sign.
        self.assertIn("Rebuild hash must equal build hash", text)
        self.assertIn("Pre-sign validation checklist", text)


class TestW19ColdCachePackaging(unittest.TestCase):
    """v0.2: a fresh-copy (cold-cache) zipapp build vs working tree.

    This test documents the open make_zipapp pycache defect rather
    than hiding it: the two builds must either match, or differ
    ONLY by __pycache__/*.pyc entries. Any other difference fails.
    """

    def test_cold_copy_differs_only_by_pycache(self):
        import shutil
        import zipfile

        env = dict(os.environ, SOURCE_DATE_EPOCH="1700000000")
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            working = td / "working.pyz"
            result = run([sys.executable, str(SCRIPTS / "make_zipapp.py"),
                          "--root", str(BUILD_ROOT), "--output", str(working)],
                         env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            cold = td / "cold"
            shutil.copytree(BUILD_ROOT / "keyholder", cold / "keyholder",
                            ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(BUILD_ROOT / "scripts", cold / "scripts",
                            ignore=shutil.ignore_patterns("__pycache__"))
            cold_out = td / "cold.pyz"
            result = run([sys.executable, str(cold / "scripts" / "make_zipapp.py"),
                          "--root", str(cold), "--output", str(cold_out)],
                         env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            with zipfile.ZipFile(working) as zw, zipfile.ZipFile(cold_out) as zc:
                only_working = sorted(set(zw.namelist()) - set(zc.namelist()))
                only_cold = sorted(set(zc.namelist()) - set(zw.namelist()))
                shared_diff = [n for n in zw.namelist()
                               if n in zc.namelist()
                               and zw.read(n) != zc.read(n)]
            self.assertEqual(only_cold, [])
            self.assertEqual(shared_diff, [])
            for name in only_working:
                self.assertTrue("__pycache__" in name or name.endswith(".pyc"),
                                name)


if __name__ == "__main__":
    unittest.main()
