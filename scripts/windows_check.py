#!/usr/bin/env python3
"""Windows verification for Sealvra v0.2 (W16).

Runs on the checking host, whatever platform that is, and checks
everything checkable WITHOUT Windows:

  W1  every Python file under sealvra/, scripts/, tests/ compiles
  W2  no POSIX-only import or process-group API (pwd, grp, fcntl,
      os.fork, os.killpg, os.getpgid, os.setsid, os.setpgid) is used
      outside code gated to a non-Windows platform (or an
      AttributeError fallback) -- ungated use would crash on Windows,
      where those names do not exist
  W3  sealvra/platform.py Windows branches are syntactically valid
      and branch on sys.platform == 'win32' (via current_platform)
  W4  Windows storage is S2, user-scoped (DPAPI boundary = user
      account, not application; same-user direct read = True)
  W5  Hello biometric and Hello PIN do not share an unqualified T1
  W6  Windows password tier is split: boolean-only ONLY via the
      isolated verifier-helper design; without it the tier is
      password-in-memory and must be displayed as such
  W7  RDP row: consumer RDP destructive effectively refused (no
      usable local gesture -> None); Remote Credential Guard +
      biometric = T1 with badge; remote-typed PIN <= T2, never T1
  W8  TPM/domain posture never changes the S2 storage tier
  W9  sealvra/approval.py Windows branch is DESIGN ONLY and
      requires the verifier helper (destructive approval is not
      runnable from that module until the helper exists)
  W10 daemon control plane falls back to loopback TCP (127.0.0.1)
      where AF_UNIX is unavailable (CONTRACT section 4)
  W11 only the two approved third-party dependencies are imported
      (cryptography, argon2-cffi); everything else is stdlib
  W12 no standalone Windows executable is present or claimed:
      no .exe/.msi/.dll/.pyd artifact, make_zipapp.py says it is NOT
      a standalone executable, install.ps1 preserves an existing
      vault, uninstall.ps1 preserves data by default
  W14 Windows supervisor kill path: source inspection (spawn guards
      start_new_session behind sys.platform != "win32"; terminate
      has terminate-win32 / kill-win32 branches) PLUS a mocked
      win32 run -- sys.platform patched to "win32" in-process and a
      fake worker process, labelled MOCKED. This proves the branch
      logic, never a real Windows kill. The process-tree / job-object
      kill for worker *children* is NOT covered: _scan_children reads
      /proc (Linux) or shells out to ps (macOS/BSD) and returns [] on
      Windows, so terminate() on Windows kills the direct worker only.
  W15 DPAPI/Hello/CredUI verifier-helper paths: gate logic only
      (boolean-only helper design, password-in-memory warning
      without it, Hello biometric vs PIN split, Guard+PIN = T2) plus
      an absence check -- no native DPAPI/CredUI binding (windll /
      CryptUnprotectData) exists in sealvra/, so nothing pretends
      to call the real APIs -- plus a MOCKED boolean-only boundary
      simulation (a fake helper returning bool; the broker side
      receives bool only, never the password string).
  W16 installer/uninstaller static correctness (no pwsh here, so
      this is text-level, not a parse): param blocks, vault
      preservation, wipe gate ordering (gate before any removal,
      WIPE typed before vault removal, receipt outside the vault),
      colon-free wipe-receipt timestamp (colons are illegal in
      Windows filenames), post-wipe deletion verification, launcher
      resolution, Python-version handling, no network cmdlets, no
      admin elevation. PowerShell *parsing* is a separate check:
      it runs only when pwsh is available and is otherwise NOT-RUN.
  W17 zipapp host run: dist/sealvra.pyz is a valid zip with
      __main__.py and runs --help under the checking host's CPython.
      That proves the zipapp, not Windows Python (NOT-RUN).
  W18 NSIS spec-only: no .nsi file and no installer binary exist;
      docs/windows.md states the NSIS shape as spec only.

What this script CANNOT check (recorded as NOT-RUN, never PASSED):
  real DPAPI / Credential Manager behaviour, real Windows Hello
  (biometric or PIN), CredUIPromptForWindowsCredentials, the isolated
  verifier-helper process, Remote Credential Guard, running
  install.ps1 / uninstall.ps1 on Windows, PowerShell parsing of
  install.ps1 / uninstall.ps1 (pwsh is unavailable on the checking
  host unless PowerShell is installed), running the zipapp under
  Windows Python, the Windows
  supervisor process-tree / job-object kill for worker children,
  Windows worker orphan self-termination (os.kill(pid, 0) polling),
  SendInput injection behaviour, and any NSIS installer build or
  run (spec only in v0.2 -- see docs/windows.md). Those need
  the post-push Windows CI steps in docs/windows.md.

Exit codes: 0 = no checkable violation found; 1 = a checkable
violation (compile failure, ungated POSIX-only use, a Windows design
statement that does not match the code, an unapproved dependency, a
claimed executable). Warnings do not flip the exit code, but they are
printed and must be resolved or accepted by the manager in writing.
2 = usage error.

Usage: python3 scripts/windows_check.py [--root DIR] [--json]
Fake keys only: this script contains no credentials of any kind.
"""

import argparse
import ast
import re
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

POSIX_ONLY_IMPORTS = {"pwd", "grp", "fcntl", "termios", "resource"}
POSIX_ONLY_ATTRS = {
    "fork", "killpg", "getpgid", "setpgid", "setsid", "getsid",
}
APPROVED_THIRD_PARTY = {"cryptography", "argon2_cffi", "argon2"}
BINARY_SUFFIXES = {".exe", ".msi", ".dll", ".pyd", ".app"}

NOT_RUN = [
    "real DPAPI / Credential Manager encrypt/decrypt behaviour",
    "real Windows Hello biometric gesture",
    "real Windows Hello PIN entry (and lookalike-dialog harvesting)",
    "CredUIPromptForWindowsCredentials returning the password",
    "the isolated verifier-helper process (design only in v0.2)",
    "Remote Credential Guard acceptance on a domain-joined machine",
    "running scripts/install.ps1 on Windows",
    "running scripts/uninstall.ps1 on Windows (default and wipe paths)",
    "PowerShell parsing of scripts/install.ps1 and scripts/uninstall.ps1 (pwsh unavailable on the checking host)",
    "running dist/sealvra.pyz under Windows Python 3.12",
    "Windows supervisor process-tree / job-object kill for worker children",
    "Windows worker orphan self-termination via os.kill(pid, 0) polling",
    "SendInput injection against a broker-window destructive prompt",
    "any NSIS installer build or run (spec only in v0.2)",
    "Windows daemon control-plane TCP fallback at runtime",
]


def _is_nonwin_guard(test_src: str) -> bool:
    """True if an `if` test confines its body to non-Windows platforms."""
    if "win32" in test_src and "!=" in test_src:
        return True
    if "==" in test_src and any(
        q in test_src for q in ('"linux"', "'linux'", '"darwin"', "'darwin'")
    ):
        return True
    return False


def _scan_posix(tree: ast.AST, path: Path) -> list[str]:
    """Ungated POSIX-only uses in one file, as file:line descriptions."""
    findings: list[str] = []

    def walk(node: ast.AST, guarded: bool) -> None:
        if isinstance(node, ast.If):
            test_src = ast.unparse(node.test)
            body_guarded = guarded or _is_nonwin_guard(test_src)
            for child in node.body:
                walk(child, body_guarded)
            for child in node.orelse:
                walk(child, guarded)
            return
        if isinstance(node, ast.Try):
            # An AttributeError handler is a real fallback for a
            # missing POSIX name on Windows; other handlers are not.
            handler_guarded = guarded or any(
                isinstance(h.type, ast.Name) and h.type.id == "AttributeError"
                for h in node.handlers
            ) or any(
                isinstance(h.type, ast.Tuple)
                and any(
                    isinstance(e, ast.Name) and e.id == "AttributeError"
                    for e in h.type.elts
                )
                for h in node.handlers
            )
            for child in node.body:
                walk(child, handler_guarded)
            for child in node.orelse:
                walk(child, guarded)
            for handler in node.handlers:
                for child in handler.body:
                    walk(child, guarded)
            for child in node.finalbody:
                walk(child, guarded)
            return
        if not guarded:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in POSIX_ONLY_IMPORTS:
                        findings.append(f"{path}:{node.lineno}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in POSIX_ONLY_IMPORTS:
                    findings.append(
                        f"{path}:{node.lineno}: from {node.module} import ..."
                    )
            elif isinstance(node, ast.Attribute):
                if (
                    isinstance(node.value, ast.Name)
                    and node.value.id == "os"
                    and node.attr in POSIX_ONLY_ATTRS
                ):
                    findings.append(f"{path}:{node.lineno}: os.{node.attr}")
        for child in ast.iter_child_nodes(node):
            walk(child, guarded)

    walk(tree, guarded=False)
    return findings


def _check_compile(root: Path) -> tuple[str, str]:
    bad: list[str] = []
    count = 0
    for sub in ("sealvra", "scripts", "tests"):
        for path in sorted((root / sub).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            count += 1
            try:
                compile(path.read_text(encoding="utf-8"), str(path), "exec")
            except (SyntaxError, UnicodeDecodeError) as exc:
                bad.append(f"{path}: {exc}")
    if bad:
        return "FAIL", "; ".join(bad)
    return "PASS", f"{count} Python files compile"


def _check_posix(root: Path) -> tuple[str, str]:
    findings: list[str] = []
    for sub in ("sealvra", "scripts", "tests"):
        for path in sorted((root / sub).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:
                continue  # W1 already reports compile failures
            findings.extend(_scan_posix(tree, path))
    if findings:
        return "FAIL", "; ".join(findings)
    return "PASS", "no ungated POSIX-only import or process-group API use"


def _check_deps(root: Path) -> tuple[str, str]:
    stdlib = sys.stdlib_module_names
    # First-party: the build root's own package (absolute imports such
    # as `from sealvra import daemon` inside the package) is not a
    # third-party dependency.
    first_party = {"sealvra"}
    bad: list[str] = []
    for sub in ("sealvra", "scripts"):
        for path in sorted((root / sub).rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module.split(".")[0]]
                for name in names:
                    if name not in stdlib and name not in APPROVED_THIRD_PARTY and name not in first_party:
                        bad.append(f"{path}:{node.lineno}: {name}")
    if bad:
        return "FAIL", "; ".join(sorted(set(bad)))
    return "PASS", "only cryptography + argon2-cffi beyond stdlib"


def _check_no_exe(root: Path) -> tuple[str, str]:
    artifacts = [
        str(p) for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in BINARY_SUFFIXES
        and "__pycache__" not in p.parts and ".git" not in p.parts
        and ".venv" not in p.parts  # local virtualenv, never committed
    ]
    zipapp = (root / "scripts" / "make_zipapp.py").read_text(encoding="utf-8")
    problems: list[str] = []
    if artifacts:
        problems.append(f"binary artifacts present: {', '.join(artifacts)}")
    if "NOT a standalone executable" not in zipapp:
        problems.append("make_zipapp.py does not disclaim a standalone executable")
    install = (root / "scripts" / "install.ps1").read_text(encoding="utf-8")
    uninstall = (root / "scripts" / "uninstall.ps1").read_text(encoding="utf-8")
    if "existing data preserved" not in install and "preserved untouched" not in install:
        problems.append("install.ps1 does not state vault preservation on reinstall")
    if "preserved (NOT deleted)" not in uninstall:
        problems.append("uninstall.ps1 does not state default data preservation")
    if problems:
        return "FAIL", "; ".join(problems)
    return "PASS", "no .exe/.msi artifact; zipapp disclaimed as non-standalone; install/uninstall preserve data by default"


def _load_platform(root: Path):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from sealvra import platform as plat  # noqa: PLC0415

    return plat


class _FakeWin32Process:
    """Stand-in for subprocess.Popen in MOCKED win32 kill tests.

    Not a real Windows process: it only records terminate()/kill()
    calls and flips poll() to dead. Used by W14 to prove the win32
    branch dispatches to terminate()/kill() instead of killpg.
    """

    def __init__(self, *, escalate: bool = False):
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


def _check_supervisor_win32(root: Path) -> tuple[str, str]:
    """W14: supervisor win32 kill path (AST + MOCKED dynamic run)."""
    sup_path = root / "sealvra" / "supervisor.py"
    src = sup_path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    # start_new_session must sit inside a `sys.platform != "win32"` If.
    guarded_start = False
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and _is_nonwin_guard(ast.unparse(node.test)):
            if "start_new_session" in ast.unparse(node):
                guarded_start = True
    if not guarded_start:
        return "FAIL", "supervisor spawn does not guard start_new_session behind sys.platform != 'win32'"
    if "terminate-win32" not in src or "kill-win32" not in src:
        return "FAIL", "supervisor terminate lacks terminate-win32 / kill-win32 branches"
    # Dynamic MOCKED run: patch sys.platform to win32, fake process.
    try:
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from sealvra.supervisor import Supervisor, WorkerHandle  # noqa: PLC0415
        original_platform = sys.platform
        try:
            sys.platform = "win32"  # type: ignore[assignment]  # MOCKED only
            sup = Supervisor()
            for escalate, expected in ((False, "terminate-win32"), (True, "kill-win32")):
                proc = _FakeWin32Process(escalate=escalate)
                handle = WorkerHandle(
                    session_id=f"sess-mock-{expected}", key_id="key-mock",
                    pid=999999, pgid=999999, started_at=0.0,
                    port=None, process=proc)
                sup._workers[handle.session_id] = handle
                result = sup.terminate(handle.session_id)
                assert result["method"] == expected, (
                    f"MOCKED win32 terminate: expected {expected}, got {result['method']}")
                assert result["terminated"] is True
                assert proc.terminate_calls == 1
            # Children note: _scan_children uses /proc or ps; the win32
            # branch returns [] before either, so a real Windows host
            # kills the direct worker only -- recorded, not hidden.
            assert "Path(\"/proc\")" in src or 'Path("/proc")' in src
        finally:
            sys.platform = original_platform
    except Exception as exc:  # noqa: BLE001
        return "FAIL", f"MOCKED win32 supervisor kill failed: {exc}"
    return "PASS", (
        "MOCKED win32 run: terminate() -> terminate-win32, timeout -> kill-win32, "
        "no killpg; worker-children tree kill remains NOT-RUN "
        "(the /proc-or-ps scan has a win32 branch that returns [])")


def _check_verifier_helper_paths(root: Path) -> tuple[str, str]:
    """W15: DPAPI/Hello/CredUI gate logic + no native binding + MOCKED boundary."""
    try:
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from sealvra import platform as plat  # noqa: PLC0415
        helper = plat.windows_verifier_helper_design()
        assert helper["return_value"].startswith("boolean only")
        assert "CredUIPromptForWindowsCredentials" in helper["process"]
        assert "LogonUser" in helper["process"]
        assert "mlocked" in helper["password_handling"]
        assert "zeroed" in helper["password_handling"]
        assert plat.hello_tier(kind="biometric").boolean_only is True
        assert plat.hello_tier(kind="pin").boolean_only is False
        assert plat.approval_tier("win32", mechanism="windows_password_helper").boolean_only is True
        assert plat.approval_tier("win32", mechanism="windows_password_in_memory").boolean_only is False
        guard_pin = plat.remote_session_tier(
            remote=True, mechanism="hello_pin", credential_guard=True)
        assert guard_pin is not None and guard_pin.tier == "T2"
        assert "biometric" not in guard_pin.mechanism
    except Exception as exc:  # noqa: BLE001
        return "FAIL", f"verifier-helper gate logic failed: {exc}"
    # Absence check: no native DPAPI/CredUI binding anywhere in
    # sealvra/. Prose mentions of CryptUnprotectData in design
    # descriptions (platform.py) are not bindings, and daemon.py's
    # ctypes use is macOS getpeereid behind a win32 early-return --
    # neither counts. A binding means windll or a real Win32 API
    # call site (name followed by "(").
    bindings = []
    for path in sorted((root / "sealvra").rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if ("windll" in text or "CryptProtectData(" in text
                or "CryptUnprotectData(" in text
                or "CredUIPromptForWindowsCredentials(" in text
                or "CredRead(" in text):
            bindings.append(str(path))
    if bindings:
        return "FAIL", f"native DPAPI binding present (unverified on Windows): {', '.join(bindings)}"
    # MOCKED boundary simulation: a fake helper returns bool only;
    # the broker side must receive bool, never the password string.
    sentinel = "TEST-ONLY-fake-password-for-mocked-boundary"
    def _mocked_helper(_password: str) -> bool:  # MOCKED, not a real CredUI call
        return _password == sentinel
    broker_received = _mocked_helper(sentinel)
    if not isinstance(broker_received, bool) or sentinel in repr(broker_received):
        return "FAIL", "MOCKED verifier boundary leaked the password to the broker side"
    return "PASS", (
        "helper design is boolean-only (CredUI + LogonUser, mlocked, zeroed); "
        "Hello PIN never boolean-only; Guard+PIN = T2, never biometric; "
        "no native DPAPI binding in sealvra/; MOCKED boundary returns bool only")


def _check_installer_static(root: Path) -> tuple[str, str]:
    """W16: install/uninstall static correctness (text-level, NOT a parse)."""
    install = (root / "scripts" / "install.ps1").read_text(encoding="utf-8")
    uninstall = (root / "scripts" / "uninstall.ps1").read_text(encoding="utf-8")
    problems: list[str] = []
    for name, text in (("install.ps1", install), ("uninstall.ps1", uninstall)):
        if "[CmdletBinding()]" not in text:
            problems.append(f"{name}: missing [CmdletBinding()]")
        if '$ErrorActionPreference = "Stop"' not in text:
            problems.append(f"{name}: missing ErrorActionPreference Stop")
        for bad in ("Invoke-WebRequest", "Invoke-RestMethod", "-Verb RunAs",
                    "Start-Process -Verb RunAs"):
            if bad in text:
                problems.append(f"{name}: unexpected {bad} (network/elevation)")
        if "curl " in text or "wget " in text:
            problems.append(f"{name}: unexpected network download command")
    if "%~dp0..\\sealvra.pyz" not in install:
        problems.append("install.ps1: launcher does not resolve sealvra.pyz relative to itself")
    if "existing data preserved" not in install and "preserved untouched" not in install:
        problems.append("install.ps1: vault preservation not stated")
    for line in install.splitlines():
        if "Remove-Item" in line and "VaultDir" in line:
            problems.append("install.ps1: removes vault data")
            break
    if "2>&1" not in install:
        problems.append("install.ps1: python --version output not captured from both streams (version may be lost)")
    py_assign = install.find("$PyVersion =")
    if "try {" not in install or not (0 <= install.find("try {") < py_assign):
        problems.append("install.ps1: missing-python case not wrapped for a friendly error")
    # Uninstall ordering: wipe gate BEFORE any removal; WIPE typed
    # BEFORE vault removal; receipt OUTSIDE the vault.
    gate_idx = uninstall.find("-WipeData was given without -ConfirmWipe")
    first_remove = uninstall.find("Remove-Item")
    if not (0 <= gate_idx < first_remove):
        problems.append("uninstall.ps1: wipe gate does not precede all removals")
    wipe_marker = uninstall.find("Wipe path")
    wipe_section = uninstall[wipe_marker:] if wipe_marker >= 0 else ""
    default_section = uninstall[:wipe_marker] if wipe_marker >= 0 else uninstall
    for line in default_section.splitlines():
        if "Remove-Item" in line and "VaultDir" in line:
            problems.append("uninstall.ps1: default (non-wipe) section touches the vault")
            break
    if 'Type WIPE to confirm' not in wipe_section:
        problems.append("uninstall.ps1: wipe section lacks the typed-WIPE prompt")
    vault_remove = wipe_section.find("Remove-Item -Recurse -Force $VaultDir")
    typed_idx = wipe_section.find("Type WIPE to confirm")
    if not (0 <= typed_idx < vault_remove):
        problems.append("uninstall.ps1: vault removal does not follow the typed-WIPE check")
    if "sealvra-wipe-receipt-" not in wipe_section or "Join-Path $HomeDir" not in wipe_section:
        problems.append("uninstall.ps1: wipe receipt is not placed outside the vault (user home)")
    # Receipt timestamp must be colon-free: colons are illegal in
    # Windows filenames, and the old format aborted the wipe.
    m = re.search(r'ToString\("([^"]+)"\)', wipe_section)
    if not m:
        problems.append("uninstall.ps1: wipe timestamp format not found")
    elif ":" in m.group(1):
        problems.append(f"uninstall.ps1: wipe timestamp format {m.group(1)!r} contains ':' (illegal in Windows filenames)")
    if "Test-Path $VaultDir" not in wipe_section.split("Remove-Item -Recurse -Force $VaultDir")[-1]:
        problems.append("uninstall.ps1: wipe does not verify the vault is actually gone before reporting deletion")
    if problems:
        return "FAIL", "; ".join(problems)
    return "PASS", (
        "install/uninstall static checks pass: vault preserved by default, wipe gated "
        "(ConfirmWipe, typed WIPE, receipt outside vault, colon-free timestamp, "
        "deletion verified); launcher resolves relative to itself; no network/elevation")


def _check_ps_parse(root: Path) -> tuple[str, str]:
    """W16-parse: real PowerShell parse when pwsh exists, else NOT-RUN."""
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if pwsh is None:
        return "NOT-RUN", (
            "pwsh/powershell unavailable on the checking host (%s): "
            "parse-check NOT-RUN, never claimed" % sys.platform)
    for name in ("install.ps1", "uninstall.ps1"):
        path = root / "scripts" / name
        expr = (
            "$e = $null; $t = $null; "
            f"[System.Management.Automation.Language.Parser]::ParseFile('{path}', [ref]$t, [ref]$e) | Out-Null; "
            "if ($e.Count -gt 0) { $e | ForEach-Object { Write-Output $_.Message }; exit 1 }"
        )
        result = subprocess.run([pwsh, "-NoProfile", "-Command", expr],
                                capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return "FAIL", f"{name} PowerShell parse errors: {result.stdout.strip() or result.stderr.strip()}"
    return "PASS", "pwsh Parser::ParseFile reports no errors for install.ps1 and uninstall.ps1"


def _check_zipapp_host(root: Path) -> tuple[str, str]:
    """W17: zipapp valid + runs --help on the checking host (NOT Windows Python)."""
    pyz = root / "dist" / "sealvra.pyz"
    if not pyz.is_file():
        return "FAIL", "dist/sealvra.pyz missing -- rebuild with scripts/make_zipapp.py"
    try:
        with zipfile.ZipFile(pyz) as zf:
            names = zf.namelist()
        assert "__main__.py" in names, "zipapp lacks __main__.py"
    except Exception as exc:  # noqa: BLE001
        return "FAIL", f"dist/sealvra.pyz is not a valid zipapp: {exc}"
    result = subprocess.run([sys.executable, str(pyz), "--help"],
                            capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        return "FAIL", f"zipapp --help failed on Linux host: {result.stderr.strip()[:300]}"
    return "PASS", "zipapp is a valid zip with __main__.py and --help exits 0 on Linux-host CPython (Windows Python is NOT-RUN)"


def _check_nsis_spec_only(root: Path) -> tuple[str, str]:
    """W18: NSIS remains spec-only -- no script, no installer binary."""
    nsi = [str(p) for p in root.rglob("*.nsi") if ".git" not in p.parts and ".venv" not in p.parts]
    if nsi:
        return "FAIL", f"NSIS script present but unbuilt/unrun: {', '.join(nsi)}"
    doc = (root / "docs" / "windows.md").read_text(encoding="utf-8")
    if "spec only" not in doc:
        return "FAIL", "docs/windows.md does not label NSIS as spec only"
    return "PASS", "no .nsi file, no installer binary; NSIS shape is spec only in docs/windows.md"


def run_checks(root: Path) -> list[dict]:
    """Return one result dict per check: id, status, detail."""
    results: list[dict] = []

    def add(check_id: str, status: str, detail: str) -> None:
        results.append({"id": check_id, "status": status, "detail": detail})

    status, detail = _check_compile(root)
    add("W1-compile", status, detail)
    status, detail = _check_posix(root)
    add("W2-posix-gating", status, detail)
    status, detail = _check_deps(root)
    add("W11-dependencies", status, detail)
    status, detail = _check_no_exe(root)
    add("W12-no-exe-claim", status, detail)

    # W3/W4/W5/W6/W7/W8: pure gate-logic functions in platform.py,
    # called with platform="win32" on the checking host. These prove the
    # gate logic only -- never native Windows behaviour (NOT-RUN).
    try:
        plat = _load_platform(root)
    except Exception as exc:  # noqa: BLE001 -- report, do not crash
        for check_id in ("W3-win32-branch", "W4-storage-S2", "W5-hello-split",
                         "W6-verifier-helper", "W7-rdp-row", "W8-tpm-domain"):
            add(check_id, "FAIL", f"cannot import sealvra.platform: {exc}")
        plat = None
    if plat is not None:
        try:
            assert plat.current_platform("win32") == "win32"
            try:
                plat.current_platform("windows")
                add("W3-win32-branch", "FAIL", "unknown platform did not raise")
            except ValueError:
                add("W3-win32-branch", "PASS",
                    "current_platform('win32') == 'win32'; unknown platforms raise (branch on sys.platform == 'win32')")
        except Exception as exc:  # noqa: BLE001
            add("W3-win32-branch", "FAIL", str(exc))
        try:
            s = plat.storage_tier("win32")
            assert s.tier == "S2" and s.same_user_direct_read is True
            assert "user account, not the application" in s.description
            assert "Hello step-up gates Sealvra-mediated use only" in s.description
            add("W4-storage-S2", "PASS",
                "win32 storage = S2, user-scoped, same-user direct read True")
        except Exception as exc:  # noqa: BLE001
            add("W4-storage-S2", "FAIL", str(exc))
        try:
            bio = plat.hello_tier(kind="biometric")
            pin = plat.hello_tier(kind="pin")
            assert bio.mechanism != pin.mechanism
            assert bio.boolean_only is True and pin.boolean_only is False
            assert "T1-pin" in pin.mechanism and "harvest" in pin.description
            add("W5-hello-split", "PASS",
                "Hello biometric (boolean-only) and Hello PIN (T1-pin, harvestable) are distinct mechanisms")
        except Exception as exc:  # noqa: BLE001
            add("W5-hello-split", "FAIL", str(exc))
        try:
            helper = plat.windows_verifier_helper_design()
            assert helper["return_value"].startswith("boolean only")
            assert "CredUIPromptForWindowsCredentials" in helper["process"]
            assert "LogonUser" in helper["process"]
            with_helper = plat.windows_password_tier(with_helper=True)
            without = plat.windows_password_tier(with_helper=False)
            assert with_helper.boolean_only is True and without.boolean_only is False
            assert "RETURNS the password" in without.description
            add("W6-verifier-helper", "PASS",
                "verifier helper returns boolean only; without it the tier is password-in-memory, displayed as such")
        except Exception as exc:  # noqa: BLE001
            add("W6-verifier-helper", "FAIL", str(exc))
        try:
            assert plat.remote_session_tier(remote=True, mechanism="hello_biometric") is None
            guard = plat.remote_session_tier(
                remote=True, mechanism="hello_biometric", credential_guard=True)
            assert guard is not None and guard.tier == "T1"
            pin_remote = plat.remote_session_tier(remote=True, mechanism="hello_pin")
            assert pin_remote is not None and pin_remote.tier == "T2"
            add("W7-rdp-row", "PASS",
                "consumer RDP: no usable local gesture (refused); Credential Guard + biometric = T1; remote PIN = T2")
        except Exception as exc:  # noqa: BLE001
            add("W7-rdp-row", "FAIL", str(exc))
        # Guard + PIN collapses to the biometric label in current code.
        # That mislabels the mechanism (v3 N-N3: display must carry the
        # mechanism). Reported as a warning, not a failure, because
        # v3 N-N4 states the Guard row as "T1 with badge" without
        # splitting PIN from biometric there; the manager must decide.
        try:
            guard_pin = plat.remote_session_tier(
                remote=True, mechanism="hello_pin", credential_guard=True)
            if guard_pin is not None and "biometric" in guard_pin.mechanism:
                add("W7-guard-pin-label", "WARN",
                    "Remote Credential Guard + PIN returns the biometric "
                    "mechanism label; a PIN approval must not be displayed "
                    "as biometric (manager decision needed, v3 N-N3 vs N-N4)")
            else:
                add("W7-guard-pin-label", "PASS",
                    "Remote Credential Guard + PIN keeps a distinct mechanism label")
        except Exception as exc:  # noqa: BLE001
            add("W7-guard-pin-label", "FAIL", str(exc))
        try:
            for tpm in ("hardware", "virtual", "absent"):
                rec = plat.windows_tpm_domain_posture(tpm=tpm, domain_joined=True)
                assert rec["storage_tier"].startswith("S2")
            assert "domain DPAPI backup keys" in plat.windows_tpm_domain_posture(
                tpm="hardware", domain_joined=True)["domain_note"]
            add("W8-tpm-domain", "PASS",
                "TPM hardware/virtual/absent and domain-joined never change S2")
        except Exception as exc:  # noqa: BLE001
            add("W8-tpm-domain", "FAIL", str(exc))

    # W9: approval.py Windows branch (W08's file -- reported, not edited).
    try:
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from sealvra import approval as appr  # noqa: PLC0415
        tier = appr.platform_tier_for(platform="win32")
        assert tier.helper_required is True
        assert "DESIGN ONLY" in tier.notes and "not runnable" in tier.notes
        assert appr.broker_window_may_approve(is_destructive=True, tier=tier) is False
        add("W9-approval-win32-design", "PASS",
            "approval.py win32 branch is DESIGN ONLY, helper-required, broker-window clicks never approve destructive")
    except Exception as exc:  # noqa: BLE001
        add("W9-approval-win32-design", "FAIL", f"cannot verify approval.py win32 branch: {exc}")

    # W10: daemon loopback-TCP fallback, by source inspection (runtime
    # behaviour on Windows is NOT-RUN).
    try:
        daemon_src = (root / "sealvra" / "daemon.py").read_text(encoding="utf-8")
        assert "AF_UNIX" in daemon_src and "AF_INET" in daemon_src
        assert "127.0.0.1" in daemon_src
        assert "never 0.0.0.0" in daemon_src or "never a network-facing" in daemon_src
        add("W10-daemon-tcp-fallback", "PASS",
            "daemon.py has AF_UNIX with a 127.0.0.1 AF_INET fallback; never 0.0.0.0 (runtime on Windows is NOT-RUN)")
    except Exception as exc:  # noqa: BLE001
        add("W10-daemon-tcp-fallback", "FAIL", str(exc))

    # W13: docs/windows.md must exist and must not claim an exe.
    try:
        doc = (root / "docs" / "windows.md").read_text(encoding="utf-8")
        assert "NOT-RUN" in doc and "sealvra.exe" not in doc
        assert "DPAPI" in doc and "S2" in doc
        add("W13-windows-doc", "PASS",
            "docs/windows.md exists, states NOT-RUN items, claims no sealvra.exe")
    except Exception as exc:  # noqa: BLE001
        add("W13-windows-doc", "FAIL", f"docs/windows.md check failed: {exc}")

    status, detail = _check_supervisor_win32(root)
    add("W14-supervisor-win32-kill", status, detail)
    status, detail = _check_verifier_helper_paths(root)
    add("W15-verifier-helper-paths", status, detail)
    status, detail = _check_installer_static(root)
    add("W16-installer-static", status, detail)
    status, detail = _check_ps_parse(root)
    add("W16-ps-parse", status, detail)
    status, detail = _check_zipapp_host(root)
    add("W17-zipapp-host", status, detail)
    status, detail = _check_nsis_spec_only(root)
    add("W18-nsis-spec-only", status, detail)

    for item in NOT_RUN:
        results.append({"id": "NOT-RUN", "status": "NOT-RUN", "detail": item})
    return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Windows verification for Sealvra v0.2 (W16).")
    parser.add_argument("--root", default=None, help="Build root (default: parent of scripts/).")
    parser.add_argument("--json", action="store_true", help="Print results as JSON.")
    args = parser.parse_args(argv)
    root = Path(args.root) if args.root else Path(__file__).resolve().parent.parent
    if not (root / "sealvra").is_dir():
        print(f"windows_check: no sealvra/ package under {root}", file=sys.stderr)
        return 2
    results = run_checks(root)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"{r['status']} {r['id']}: {r['detail']}")
        counts: dict[str, int] = {}
        for r in results:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        print(f"counts: {counts}")
    if any(r["status"] == "FAIL" for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
