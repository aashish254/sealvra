#!/usr/bin/env python3
"""macOS verification for Sealvra v0.1 (W17).

Runs on the checking host, whatever platform that is, and checks
everything checkable WITHOUT a Mac:

  C1  every Python file under the build root compiles (compileall equivalent)
  C2  no Linux-only import is used outside sealvra/platform.py
  C3  no macOS behaviour is implemented outside sealvra/platform.py
  C4  macOS design interfaces are present in sealvra/platform.py
      (Keychain one-item-per-key, .userPresence + enrolment-change
      detection, .biometryCurrentSet strict-mode opt-in only, sandboxed
      approver design, Touch ID as gesture not authorisation)
  C5  no fake-"success" stub stands in for a macOS API (Security
      framework / LAContext) — unimplemented macOS paths must carry an
      explicit NOT-IMPLEMENTED-ON-LINUX marker or raise
      NotImplementedError, never return a success value
  C6  only the two approved third-party dependencies are imported
      (cryptography, argon2-cffi); everything else must be stdlib
  C7  no compiled macOS binary artifact is present or claimed
      (Python source is architecture-independent; there is no Darwin
      build here — see docs/macos.md)
  C8  macOS readiness, per area (Keychain one-item-per-key, Touch ID
      two-step, sandboxed approver XPC, DMG/packaging, daemon IPC on
      macOS): design markers are checked in sealvra/platform.py,
      sealvra/approval.py, sealvra/vault.py and sealvra/daemon.py
      plus packaging files. A present design is reported SPEC-ONLY
      (never READY, never PASSED — the native behaviour is NOT-RUN
      without a Mac). A missing design marker is a GAP, reported in
      "readiness_gaps"; gaps do NOT flip the exit code, because the
      native files belong to other workers (W13/W08/W20) and the
      native proof belongs on a Mac. Expected gaps (no XPC service
      bundle/plist, no sandbox profile, no signed DMG, no code-signing
      identity check) are listed explicitly so they can never be
      mistaken for done work.
  C9  docs/macos.md honesty: the NOT-RUN headline and TEST-ONLY
      wording must be present when the doc exists; the Touch ID order
      in the doc (gesture first, confirm second) is verified and
      reported. A missing headline/TEST-ONLY wording IS a violation
      (the doc is W17's own file). Doc checks are skipped for fixture
      trees that contain no docs/macos.md.

What this script CANNOT check (recorded as NOT-RUN, never PASSED):
  real macOS Keychain behaviour, Touch ID, the sandboxed approver XPC
  service, DMG install, Gatekeeper, and anything requiring a real Mac.
  Those need the M5 Mac test plan in docs/macos.md.

Exit codes: 0 = no checkable violation found (gaps in C4 are reported
separately and do NOT flip the exit code, because sealvra/platform.py
is W13's file area — W17 reports the gap, it does not write W13's file).
1 = a checkable violation (compile failure, Linux-only leak, fake
success stub, unapproved dependency, binary artifact).
2 = usage error.

Usage: python3 scripts/macos_check.py [--root DIR] [--json]
Fake keys only: this script contains no credentials of any kind.
"""

import argparse
import ast
import json
import sys
from pathlib import Path

# Modules that exist only on Linux (or only make sense there). fcntl,
# pwd, grp and resource are Unix-wide and also exist on macOS, so they
# are deliberately NOT in this list.
LINUX_ONLY_MODULES = {
    "dbus",
    "gi",
    "secretstorage",
    "keyutils",
    "pam",
    "systemd",
    "selinux",
    "polkit",
}

APPROVED_THIRD_PARTY = {"cryptography", "argon2_cffi", "argon2"}

# Binary artifacts: their presence would contradict "no macOS binary
# is produced here" and must be flagged, not silently accepted.
BINARY_SUFFIXES = {".so", ".dylib", ".pyd", ".dll", ".o"}

# (interface id, description, marker strings — at least one must appear
# in sealvra/platform.py for the interface to count as PRESENT)
MACOS_INTERFACES = [
    (
        "keychain-one-item-per-key",
        "One macOS Keychain item per key (v3 N-D1); no vault-wide KEK item",
        ["one_item_per_key", "one keychain item per key", "per-key item",
         "one item per key", "one Keychain item per stored key",
         "SecItemAdd", "SecItemCopyMatching"],
    ),
    (
        "userPresence-enrolment-change",
        "Default .userPresence plus enrolment-change detection with "
        "step-up (v3 N-D2)",
        ["userPresence", "enrolment-change", "enrolment_change",
         "enrollment-change", "enrollment_change"],
    ),
    (
        "biometryCurrentSet-strict-opt-in",
        ".biometryCurrentSet strict mode is opt-in only, with a re-wrap "
        "ceremony on enrolment change — never combined with a passcode "
        "fallback (v3 N-D2)",
        ["biometryCurrentSet"],
    ),
    (
        "sandboxed-approver",
        "Sandboxed, unprivileged XPC sealvra-approver as the ONLY "
        "approval renderer (v3 N-E1)",
        ["sealvra-approver", "approver", "XPC"],
    ),
    (
        "touch-id-gesture-not-authorisation",
        "Touch ID / OS auth is a presence gesture, NOT the authorisation: "
        "two-step approval (gesture + explicit confirm, in that order) "
        "(v3 N-E2)",
        ["gesture", "two-step", "two_step", "explicit confirm"],
    ),
]

NOT_IMPLEMENTED_MARKERS = (
    "NOT-IMPLEMENTED-ON-LINUX",
    "NotImplementedError",
    "not implemented on linux",
    "requires macos",
    "requires macOS",
)


def iter_py_files(root: Path):
    """All Python files under root, excluding the local venv."""
    for path in sorted(root.rglob("*.py")):
        if ".venv" in path.parts:
            continue
        yield path


def check_compile(root: Path):
    """C1: compile every Python file; collect per-file results."""
    results = []
    for path in iter_py_files(root):
        try:
            source = path.read_text(encoding="utf-8")
            compile(source, str(path), "exec")
            results.append({"file": str(path.relative_to(root)), "ok": True})
        except Exception as exc:  # SyntaxError, UnicodeDecodeError, ...
            results.append(
                {"file": str(path.relative_to(root)), "ok": False,
                 "error": f"{type(exc).__name__}: {exc}"}
            )
    return results


def _top_module(name: str) -> str:
    return name.split(".")[0]


def scan_imports(root: Path):
    """C2/C6: per-file import findings.

    Returns (violations, findings): a Linux-only import outside
    sealvra/platform.py is a violation; an unapproved third-party
    import anywhere is a violation; anything else is informational.
    """
    violations = []
    findings = []
    stdlib = sys.stdlib_module_names
    for path in iter_py_files(root):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except Exception:
            continue  # C1 already reports the compile failure
        rel = str(path.relative_to(root))
        # Manager integration fix (v0.2): C6 gates SHIPPED dependencies
        # (the zipapp packs sealvra/ only). Test files are not
        # shipped, and an optional test-only import guarded by
        # try/except ImportError -> skipTest (PyYAML in
        # tests/test_w20_packaging.py) is an honest NOT-RUN, not a
        # product dependency. Skipping tests/ here, as C5 already
        # does, removes that false positive without weakening the
        # product-code scan.
        if rel.startswith("tests/"):
            continue
        is_platform = rel == "sealvra/platform.py"
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                # Relative imports (from .x import ...) are intra-package
                # and never third-party; skip them.
                if node.level and node.level > 0:
                    continue
                names = [node.module]
            for name in names:
                top = _top_module(name)
                if top == "sealvra":
                    continue  # the project's own package, not a dependency
                # Manager integration fix: first-party test helpers
                # (tests/adversarial_helpers.py, tests/mock_providers.py,
                # and `tests.`-qualified imports of them) are project
                # code, not third-party dependencies.
                if top == "tests" and (root / "tests").is_dir():
                    continue
                if (root / "tests" / f"{top}.py").exists() or (
                        root / f"{top}.py").exists():
                    continue
                if top in LINUX_ONLY_MODULES and not is_platform:
                    violations.append(
                        f"{rel}: Linux-only import '{name}' outside "
                        "sealvra/platform.py"
                    )
                elif top not in stdlib and top not in APPROVED_THIRD_PARTY:
                    violations.append(
                        f"{rel}: unapproved third-party import '{name}' "
                        "(approved: cryptography, argon2-cffi only)"
                    )
                elif top in LINUX_ONLY_MODULES and is_platform:
                    findings.append(
                        f"{rel}: Linux-only import '{name}' inside "
                        "platform.py (allowed only inside a Linux branch)"
                    )
    return violations, findings


def scan_macos_outside_platform(root: Path):
    """C3: macOS API names used outside sealvra/platform.py.

    Informational, not a violation on its own: a doc or a test may
    mention them. It becomes a violation only together with C5 (a stub
    returning success), which is checked separately.
    """
    markers = ("SecItem", "LAContext", "LocalAuthentication",
               "kSecAttrAccessible", "biometryCurrentSet")
    hits = []
    for path in iter_py_files(root):
        if str(path.relative_to(root)) == "sealvra/platform.py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for marker in markers:
            if marker in text:
                hits.append(f"{path.relative_to(root)}: mentions {marker}")
    return hits


def check_macos_interfaces(root: Path):
    """C4: presence of each designed macOS interface in platform.py.

    ABSENT is a gap for W13/manager, not a W17 violation and not a
    failure of this script — it is reported, never papered over.
    """
    platform_py = root / "sealvra" / "platform.py"
    if not platform_py.exists():
        return [
            {"id": iface_id, "description": desc, "status": "ABSENT",
             "reason": "sealvra/platform.py does not exist yet (W13 owns it)"}
            for iface_id, desc, _ in MACOS_INTERFACES
        ]
    text = platform_py.read_text(encoding="utf-8", errors="replace")
    results = []
    for iface_id, desc, markers in MACOS_INTERFACES:
        found = [m for m in markers if m in text]
        results.append({
            "id": iface_id, "description": desc,
            "status": "PRESENT" if found else "ABSENT",
            "matched_markers": found,
        })
    return results


def scan_fake_success_stubs(root: Path):
    """C5: macOS-named functions that return success without doing the
    macOS work and without a NOT-IMPLEMENTED marker.

    A function whose name mentions keychain/touchid/biometry/approver/
    la_context and whose body is a bare `return True` / `return None`
    (or a constant) with no marker and no NotImplementedError is a
    fake-success stub and a hard violation.
    """
    violations = []
    stub_names = ("keychain", "touchid", "touch_id", "biometr",
                  "la_context", "approver", "secitem")
    for path in iter_py_files(root):
        # Manager integration fix: C5 is about shipped product code.
        # Test functions are not shipped, and a test named after a
        # platform feature is not a fake-success stub — skipping
        # tests/ (and any test_* function) removes the false
        # positives that blocked the real-root check, without
        # weakening the product-code scan.
        rel = str(path.relative_to(root))
        if rel.startswith("tests/"):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name.startswith("test_"):
                continue
            lname = node.name.lower()
            if not any(s in lname for s in stub_names):
                continue
            body_src = ast.get_source_segment(text, node) or ""
            has_marker = any(m in body_src for m in NOT_IMPLEMENTED_MARKERS)
            returns = [n for n in ast.walk(node) if isinstance(n, ast.Return)]
            trivial = all(
                r.value is None
                or (isinstance(r.value, ast.Constant)
                    and r.value.value in (True, False, None, "", 0))
                for r in returns
            )
            raises = any(isinstance(n, ast.Raise) for n in ast.walk(node))
            if trivial and not has_marker and not raises:
                violations.append(
                    f"{rel}:{node.name}: macOS-named function returns a "
                    "trivial value with no NOT-IMPLEMENTED-ON-LINUX marker "
                    "— fake-success stub"
                )
    return violations


def check_binary_artifacts(root: Path):
    """C7: no compiled binary artifact in the tree."""
    found = []
    for path in sorted(root.rglob("*")):
        if ".venv" in path.parts or not path.is_file():
            continue
        if path.suffix in BINARY_SUFFIXES:
            found.append(str(path.relative_to(root)))
    return found


# Checks this script does not perform, whatever host runs it. Listed
# explicitly so a reader can never mistake "checked here" for "tested
# on a Mac". "NOT-RUN here" means not covered by this static script
# only: some items (for example cross-process daemon IPC) are exercised
# by the unittest suite when it runs on a real Mac, and the suite's own
# per-test result is the authority for those -- never this list.
NOT_RUN_HERE = [
    {"check": "Real macOS Keychain store/retrieve (Security framework)",
     "reason": "Requires the macOS Security framework; the checking host "
                "is %s" % sys.platform},
    {"check": "Touch ID / LAContext biometric prompt",
     "reason": "Requires macOS LocalAuthentication + enrolled biometrics"},
    {"check": "Sandboxed approver XPC service (sealvra-approver)",
     "reason": "Requires macOS XPC + sandbox profiles + code signing"},
    {"check": "DMG install + Gatekeeper notarisation check",
     "reason": "No macOS binary is produced here; DMG shape is spec only"},
    {"check": "aarch64-apple-darwin build",
     "reason": "Python source is architecture-independent; no Darwin "
                "build is produced or claimed here"},
    {"check": "End-to-end run on the user's M5 Mac",
     "reason": "Requires the user's Mac; see the test plan in docs/macos.md"},
    {"check": "Enrolment-change invalidation + strict-mode re-wrap ceremony",
     "reason": "Requires changing Touch ID enrolment on a real Mac; "
                "do not test by removing the user's own fingerprints"},
    {"check": "XPC approver code-signing identity check + sandbox profile",
     "reason": "Requires the built XPC service, a signing identity, and macOS"},
    {"check": "Daemon Unix-socket IPC on macOS (v0.2 §13.1)",
     "reason": "Requires the daemon installed as a launchd/service-manager "
               "job on macOS. The C8 status here is a design-marker read, "
               "not a run statement: the cross-process daemon itself DID "
               "run on this host in v0.2 Phase 1/3 (0700 dir, 0600 "
               "control.sock observed with stat, peer-UID accept, tests/"
               "test_daemon_ipc.py 8/8 ok) — see docs/macos.md §1.1"},
    {"check": "Screen-lock suspend + kill after 15 min locked on macOS",
     "reason": "Requires a locked macOS session and a 15-minute wait"},
    {"check": "Keychain ACL Tier B separation (same-user read attempt)",
     "reason": "Requires a second same-user process on macOS attempting "
                "a Keychain read; only the Mac run can show the prompt"},
]


# ---------------------------------------------------------------------------
# C8/C9: macOS readiness (design vs native proof) and doc honesty.
# ---------------------------------------------------------------------------

# (area id, description, files to search, required marker groups:
#  at least one marker per group must appear for the group to count)
READINESS_AREAS = [
    (
        "keychain-one-item-per-key",
        "Keychain: one item per key, own wrapping key/version/backup, "
        "per-app access group, .userPresence default, enrolment-change "
        "step-up, .biometryCurrentSet strict opt-in + re-wrap, no "
        "vault-wide KEK item (v3 N-D1/N-D2)",
        ("sealvra/platform.py", "sealvra/vault.py"),
        [
            ["one Keychain item per", "one item per key"],
            ["access group"],
            [".userPresence"],
            ["enrolment-change", "enrolment_change",
             "enrollment-change", "enrollment_change"],
            ["biometryCurrentSet"],
            ["re-wrap", "rewrap"],
            ["no vault-wide", "no single", "no vault-wide KEK"],
        ],
    ),
    (
        "touch-id-two-step",
        "Touch ID: gesture FIRST, explicit confirm SECOND, in that "
        "order; fresh LAContext per approval, reuse duration zero; "
        "biometric-only only for identical-scope re-approval (v3 N-E2)",
        ("sealvra/platform.py", "sealvra/approval.py"),
        [
            ["gesture"],
            ["explicit confirm"],
            ["in that order", "card -> gesture -> confirm",
             "gesture -> confirm"],
            ["fresh LAContext", "reuse duration zero"],
            ["identical-scope re-approval", "identical-scope"],
        ],
    ),
    (
        "sandboxed-approver-xpc",
        "Sandboxed approver: unprivileged XPC sealvra-approver, ONLY "
        "approval renderer, metadata only, signed single-use decision "
        "bound to the request hash, UI never originates, enclave-bound "
        "signature for HIGH/CRITICAL, code-signing identity check "
        "(v3 N-E1)",
        ("sealvra/platform.py", "sealvra/approval.py"),
        [
            ["sealvra-approver"],
            ["unprivileged"],
            ["metadata only"],
            ["signed", "single-use"],
            ["request hash"],
            ["never originate", "never originates", "NEVER originates"],
            ["enclave"],
            ["code-signing identity", "code signing"],
        ],
    ),
    (
        "dmg-packaging",
        "DMG/packaging readiness: zipapp is the shipped shape, DMG is "
        "spec only, install.sh covers macOS, CI runs a macos job with "
        "this checker (W20 owns the DMG itself; no DMG/.app is built "
        "here)",
        ("scripts/make_zipapp.py", "scripts/install.sh",
         ".github/workflows/ci.yml"),
        [
            ["DMG"],
            ["macOS"],
            ["macos_check.py"],
        ],
    ),
    (
        "daemon-ipc-macos",
        "Daemon IPC on macOS (v0.2 §13.1): Unix domain socket on "
        "darwin, socket/dir permissions, Tier B honesty (peer-UID "
        "does NOT separate same-user processes)",
        ("sealvra/daemon.py",),
        [
            ["AF_UNIX"],
            ["darwin"],
            ["0700", "0600", "0o700", "0o600"],
        ],
    ),
]

# Native artifacts whose ABSENCE is an expected, honest gap (not a
# violation): they can only be produced/verified on a Mac with a
# signing identity. If one ever appears, it is listed, not celebrated
# — an unverified artifact is not proof.
EXPECTED_NATIVE_GAPS = [
    ("XPC service bundle / launchd plist for sealvra-approver",
     ("*.plist",)),
    ("macOS sandbox profile (.sb) for the approver",
     ("*.sb",)),
    ("Signed DMG / .app bundle",
     ("*.dmg",)),
    ("Code-signing identity / notarisation config",
     ("*.entitlements",)),
]

NATIVE_ARTIFACT_SUFFIXES = {".dmg", ".app", ".plist", ".sb",
                            ".entitlements"}


def _read_if_exists(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def check_macos_readiness(root: Path):
    """C8: per-area readiness. Status is SPEC-ONLY (design markers
    present, native proof NOT-RUN), PARTIAL (some groups present) or
    GAP (design missing). Never READY/PASSED on this VM."""
    areas = []
    gaps = []
    for area_id, desc, files, groups in READINESS_AREAS:
        combined = "\n".join(
            _read_if_exists(root / f) for f in files)
        missing_groups = []
        for group in groups:
            if not any(m in combined for m in group):
                missing_groups.append(group[0])
        if not missing_groups:
            status = "SPEC-ONLY"
        elif len(missing_groups) < len(groups):
            status = "PARTIAL"
        else:
            status = "GAP"
        if missing_groups:
            gaps.append(
                f"{area_id}: design markers missing: "
                + ", ".join(missing_groups))
        areas.append({
            "id": area_id, "description": desc, "status": status,
            "missing_marker_groups": missing_groups,
        })
    # Expected native gaps: listed, never papered over.
    native_present = []
    for path in sorted(root.rglob("*")):
        if ".venv" in path.parts or not path.is_file():
            continue
        if path.suffix in NATIVE_ARTIFACT_SUFFIXES:
            native_present.append(str(path.relative_to(root)))
    for label, _patterns in EXPECTED_NATIVE_GAPS:
        gaps.append(f"NOT-CLOSED (expected, needs a Mac + signing): {label}")
    return areas, gaps, native_present


def check_doc_honesty(root: Path):
    """C9: docs/macos.md headline/TEST-ONLY wording + Touch ID order.

    Returns (doc_honesty dict, violations). Skipped (empty) when the
    doc does not exist, so synthetic fixture trees are unaffected."""
    doc = root / "docs" / "macos.md"
    if not doc.exists():
        return {"checked": False}, []
    text = _read_if_exists(doc)
    low = text.lower()
    # The required headline states the honest invariant: nothing native
    # is proven. It must NOT claim the suite never ran on a Mac, because
    # the suite does now run on macOS (v0.2 Phase 1/3) -- and that run
    # proves no native API behaviour, which is what this headline guards.
    headline_ok = ("no native macos behaviour is implemented or proven"
                   in low)
    testonly_ok = "TEST-ONLY" in text
    order_ok = "gesture first" in low and "confirm second" in low
    violations = []
    if not headline_ok:
        violations.append(
            "docs/macos.md: missing NOT-RUN headline "
            "('no native macOS behaviour is implemented or proven')")
    if not testonly_ok:
        violations.append("docs/macos.md: missing TEST-ONLY wording")
    return {
        "checked": True,
        "not_run_headline": headline_ok,
        "test_only_wording": testonly_ok,
        "touch_id_order": (
            "gesture-first-confirm-second" if order_ok
            else "UNVERIFIED-ORDER"),
    }, violations


def run(root: Path):
    """Run all checks; return the report dict."""
    compile_results = check_compile(root)
    compile_failures = [r for r in compile_results if not r["ok"]]
    import_violations, import_findings = scan_imports(root)
    outside_hits = scan_macos_outside_platform(root)
    interfaces = check_macos_interfaces(root)
    stub_violations = scan_fake_success_stubs(root)
    binaries = check_binary_artifacts(root)
    readiness, readiness_gaps, native_present = check_macos_readiness(root)
    doc_honesty, doc_violations = check_doc_honesty(root)
    if doc_honesty.get("touch_id_order") == "UNVERIFIED-ORDER":
        readiness_gaps.append(
            "touch-id-two-step: docs/macos.md does not state the "
            "gesture-first / confirm-second order explicitly")

    violations = []
    violations += [f"compile: {r['file']}: {r['error']}"
                   for r in compile_failures]
    violations += import_violations
    violations += stub_violations
    violations += [f"binary artifact present: {b}" for b in binaries]
    violations += doc_violations

    return {
        "root": str(root),
        "platform": sys.platform,
        "compile": {"checked": len(compile_results),
                    "failed": len(compile_failures),
                    "failures": compile_failures},
        "linux_only_imports_outside_platform": import_violations,
        "platform_py_import_notes": import_findings,
        "macos_api_mentions_outside_platform": outside_hits,
        "macos_interfaces": interfaces,
        "fake_success_stubs": stub_violations,
        "binary_artifacts": binaries,
        "macos_readiness": readiness,
        "readiness_gaps": readiness_gaps,
        "native_macos_artifacts_present": native_present,
        "doc_honesty": doc_honesty,
        "not_run_here": NOT_RUN_HERE,
        "aarch64_note": (
            "Python source is architecture-independent: no compiled "
            "macOS binary is produced here, so there is no "
            "aarch64-apple-darwin build to verify. The aarch64 check is "
            "compile + interface + CI-job readiness (see docs/macos.md), "
            "not a Darwin build."
        ),
        "violations": violations,
        "verdict": "NO-CHECKABLE-VIOLATION" if not violations else "VIOLATION",
    }


def render_human(report: dict) -> str:
    lines = [
        "Sealvra macOS check (W17) — run on Linux, macOS-real checks NOT-RUN",
        f"root: {report['root']}  platform: {report['platform']}",
        "",
        f"C1 compile: {report['compile']['checked']} files checked, "
        f"{report['compile']['failed']} failed",
    ]
    for failure in report["compile"]["failures"]:
        lines.append(f"  FAIL {failure['file']}: {failure['error']}")
    lines.append(
        "C2/C6 import violations: "
        f"{len(report['linux_only_imports_outside_platform'])}"
    )
    for violation in report["linux_only_imports_outside_platform"]:
        lines.append(f"  VIOLATION {violation}")
    lines.append("C4 macOS interfaces in sealvra/platform.py:")
    for iface in report["macos_interfaces"]:
        lines.append(f"  {iface['status']}: {iface['id']} — {iface['description']}")
    lines.append(f"C5 fake-success stubs: {len(report['fake_success_stubs'])}")
    for stub in report["fake_success_stubs"]:
        lines.append(f"  VIOLATION {stub}")
    lines.append(f"C7 binary artifacts: {len(report['binary_artifacts'])}")
    for binary in report["binary_artifacts"]:
        lines.append(f"  VIOLATION binary artifact present: {binary}")
    lines.append("C8 macOS readiness (SPEC-ONLY = design present, native "
                 "proof NOT-RUN; gaps do NOT flip the verdict):")
    for area in report["macos_readiness"]:
        lines.append(f"  {area['status']}: {area['id']}")
        for missing in area["missing_marker_groups"]:
            lines.append(f"    missing marker: {missing}")
    lines.append("C8/C9 readiness gaps (NOT-CLOSED until a Mac run proves them):")
    for gap in report["readiness_gaps"]:
        lines.append(f"  GAP: {gap}")
    lines.append(
        "Native macOS artifacts present: "
        f"{report['native_macos_artifacts_present'] or 'none'}")
    if report["doc_honesty"].get("checked"):
        lines.append(
            "C9 docs/macos.md honesty: headline="
            f"{report['doc_honesty']['not_run_headline']} test-only="
            f"{report['doc_honesty']['test_only_wording']} touch-id-order="
            f"{report['doc_honesty']['touch_id_order']}")
    lines.append("")
    lines.append("NOT-RUN here (never PASSED — requires a real Mac):")
    for item in report["not_run_here"]:
        lines.append(f"  NOT-RUN: {item['check']} — {item['reason']}")
    lines.append("")
    lines.append(report["aarch64_note"])
    lines.append(f"verdict: {report['verdict']}")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=None,
                        help="build root (default: parent of scripts/)")
    parser.add_argument("--json", action="store_true",
                        help="emit the report as JSON instead of text")
    args = parser.parse_args(argv)
    if args.root:
        root = Path(args.root).resolve()
    else:
        root = Path(__file__).resolve().parent.parent
    if not root.is_dir():
        print(f"error: root is not a directory: {root}", file=sys.stderr)
        return 2
    report = run(root)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_human(report), end="")
    return 0 if report["verdict"] == "NO-CHECKABLE-VIOLATION" else 1


if __name__ == "__main__":
    raise SystemExit(main())
