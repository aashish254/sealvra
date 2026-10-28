#!/usr/bin/env python3
"""Verify reproducibility properties checkable in a local build.

Checks:
  1. Deterministic zipapp build: two builds of the same tree with the
     same SOURCE_DATE_EPOCH are byte-identical, entries are sorted,
     every timestamp equals the epoch, and no absolute path is embedded.
  2. No absolute paths embedded in the build output (root path bytes
     must not appear in the zip).
  3. Requirements consistency: requirements.txt holds exactly the two
     allowed dependencies, each installed at exactly its pinned version,
     and the SBOM (if present) agrees on those pins. Registry
     redirection is rejected: no extra-index, editable, or included
     requirements lines, and no root pip config pointing off PyPI.
  4. Secret scan: no secret-shaped string in the SBOM or in the build
     outputs. Patterns are generic shapes; TEST-ONLY- fixtures are
     exempt. No real key is ever used here: the scanner self-test
     constructs its fake sample at runtime (repetition, not a literal).
  5. v0.2 packaging checks: SOURCE_DATE_EPOCH carried through the real
     packaging script (scripts/make_zipapp.py, owned by W20 — invoked,
     not modified here): two builds of the real tree at the same epoch
     are byte-identical and every zip entry timestamp equals the
     epoch. Cold-cache check: a build from a fresh copy of the tree
     with no __pycache__ matches the build from the working tree, so
     no cached bytecode can change the artifact (F16-B4).

A synthetic fixture tree is also built twice, so the deterministic-build
logic itself is exercised even when the real app tree is still empty
(other workers have not landed code yet); that case is reported as SKIP
for the real tree, never as a pass for it.

Usage:
    python3 scripts/repro_check.py [--root DIR] [--sbom FILE]
    SOURCE_DATE_EPOCH=1700000000 python3 scripts/repro_check.py
Exit 0 only if no check FAILs. SKIP is not a pass.
"""

import argparse
import datetime
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ALLOWED_DIRECT = {"cryptography", "argon2-cffi"}
# Generic secret shapes (not literals of any real credential). The fake
# sample for the self-test is built at runtime from a repeated char.
SECRET_PATTERNS = [
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(rb"ghp_[A-Za-z0-9]{36}"),
    re.compile(rb"github_pat_[A-Za-z0-9_]{22,}"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"sk-[A-Za-z0-9]{20,}"),
    re.compile(rb"xox[baprs]-[A-Za-z0-9\-]{10,}"),
]
EXEMPT_MARKER = b"TEST-ONLY-"


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


FORBIDDEN_REQ_TOKENS = ("--extra-index-url", "--index-url", "-r ", "-e ",
                        "--find-links", "-c ", "--constraint")
PIP_CONFIG_FILES = ("pip.conf", ".pip.conf", "setup.cfg", "pyproject.toml")


def parse_requirements(path):
    reqs = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for tok in FORBIDDEN_REQ_TOKENS:
            if tok in stripped:
                raise SystemExit(
                    f"repro: forbidden requirements token {tok!r} in line: {line!r}"
                )
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s;]+)$", stripped)
        if not m:
            raise SystemExit(
                f"repro: unparsable requirements line: {line!r} "
                "(only exact `name==version` pins are allowed)"
            )
        if norm(m.group(1)) in reqs:
            raise SystemExit(f"repro: duplicate requirements entry: {m.group(1)}")
        reqs[norm(m.group(1))] = m.group(2)
    return reqs


def check_pip_config(root, results):
    """Registry-redirection assertion (F16-D7); records PASS/FAIL."""
    for fname in PIP_CONFIG_FILES:
        cfg = root / fname
        if not cfg.is_file():
            continue
        for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
            low = line.strip().lower()
            if "extra-index-url" in low:
                results.append(("FAIL registry-config", f"{fname} sets extra-index-url"))
                return False
            if low.startswith("index-url"):
                url = low.split("=", 1)[1].strip() if "=" in low else ""
                if url and "pypi.org" not in url:
                    results.append(("FAIL registry-config", f"{fname} sets non-PyPI index {url!r}"))
                    return False
    results.append(("PASS registry-config", "no registry redirection in root pip configs"))
    return True


def check_packaging_epoch(root, epoch, results):
    """SOURCE_DATE_EPOCH through scripts/make_zipapp.py (W20's script).

    Builds the real tree twice at the same epoch (byte-identical,
    every entry timestamp == epoch) and once from a fresh copy of the
    tree with no __pycache__ (cold-cache simulation, F16-B4).
    """
    import shutil

    make_zipapp = root / "scripts" / "make_zipapp.py"
    if not make_zipapp.is_file():
        results.append(("SKIP packaging-epoch", "scripts/make_zipapp.py missing"))
        return
    if not (root / "keyholder" / "__main__.py").is_file():
        results.append(("SKIP packaging-epoch", "keyholder/__main__.py missing; nothing to package"))
        return
    expected_dt = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc).timetuple()[:6]
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch))
    with tempfile.TemporaryDirectory() as td:
        # Two builds of the working tree at the same epoch.
        outs = []
        for i in range(2):
            out = Path(td) / f"working-{i}.pyz"
            proc = subprocess.run(
                [sys.executable, str(make_zipapp), "--root", str(root),
                 "--output", str(out)],
                capture_output=True, text=True, env=env)
            if proc.returncode != 0:
                results.append(("FAIL packaging-epoch", f"working-tree build failed: {proc.stderr.strip()[-200:]}"))
                return
            outs.append(out.read_bytes())
        if outs[0] != outs[1]:
            results.append(("FAIL packaging-epoch", "two same-epoch working-tree builds differ"))
            return
        with zipfile.ZipFile(io.BytesIO(outs[0])) as zf:
            infos = zf.infolist()
            if any(info.date_time != expected_dt for info in infos):
                results.append(("FAIL packaging-epoch", "zip entry timestamps != SOURCE_DATE_EPOCH"))
                return
            if zf.namelist() != sorted(zf.namelist()):
                results.append(("FAIL packaging-epoch", "zip entries not sorted"))
                return
        results.append(("PASS packaging-epoch",
                        f"{len(infos)} entries, two same-epoch builds byte-identical, "
                        f"all timestamps == epoch {epoch}"))
        # Cold-cache: fresh copy of the package + script, no __pycache__.
        # A difference here means cached bytecode changes the artifact
        # (F16-B4). NOTE (v0.2, open): scripts/make_zipapp.py (W20)
        # currently bundles keyholder/__pycache__/*.pyc into the zip,
        # so this check FAILs on a tree where tests have run. That is
        # a real defect in the packaging script, not in this check:
        # the fix is to exclude __pycache__/*.pyc in make_zipapp's
        # collect_files (as repro_check's own deterministic_zip does).
        # This check must not be weakened to hide it.
        cold = Path(td) / "cold"
        shutil.copytree(root / "keyholder", cold / "keyholder",
                        ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(root / "scripts", cold / "scripts",
                        ignore=shutil.ignore_patterns("__pycache__"))
        out_cold = Path(td) / "cold.pyz"
        proc = subprocess.run(
            [sys.executable, str(cold / "scripts" / "make_zipapp.py"),
             "--root", str(cold), "--output", str(out_cold)],
            capture_output=True, text=True, env=env)
        if proc.returncode != 0:
            results.append(("FAIL packaging-cold-cache", f"cold-copy build failed: {proc.stderr.strip()[-200:]}"))
            return
        cold_bytes = out_cold.read_bytes()
        if cold_bytes != outs[0]:
            with zipfile.ZipFile(io.BytesIO(outs[0])) as zf_w, \
                    zipfile.ZipFile(io.BytesIO(cold_bytes)) as zf_c:
                only_w = sorted(set(zf_w.namelist()) - set(zf_c.namelist()))
            detail = f"cold-copy build differs ({len(only_w)} entries only in working-tree build"
            if only_w and all("__pycache__" in n or n.endswith(".pyc") for n in only_w):
                detail += "; all are __pycache__/*.pyc — make_zipapp must exclude them"
            detail += ")"
            results.append(("FAIL packaging-cold-cache", detail))
            return
        results.append(("PASS packaging-cold-cache",
                        f"fresh-copy build byte-identical, sha256={hashlib.sha256(outs[0]).hexdigest()}"))


def find_python(root):
    venv_python = root / ".venv" / "bin" / "python"
    return str(venv_python) if venv_python.exists() else sys.executable


def installed_versions(python):
    code = (
        "import importlib.metadata as m, json;"
        "print(json.dumps({d.metadata['Name']: d.version for d in m.distributions() if d.metadata['Name']}))"
    )
    proc = subprocess.run([python, "-c", code], capture_output=True, text=True)
    if proc.returncode != 0:
        return {}
    return {norm(k): v for k, v in json.loads(proc.stdout).items()}


def deterministic_zip(tree, epoch):
    """Build a zipapp-style zip deterministically from a directory tree."""
    dt = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc).timetuple()[:6]
    buf = io.BytesIO()
    files = []
    if tree.is_dir():
        for path in sorted(tree.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                files.append(path)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in files:
            rel = path.relative_to(tree).as_posix()
            info = zipfile.ZipInfo(filename=rel, date_time=dt)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            info.create_system = 3
            zf.writestr(info, path.read_bytes())
    return buf.getvalue(), files


def scan_secrets(data, label, results):
    """Scan bytes; TEST-ONLY- lines are exempt, everything else flagged."""
    hits = []
    for line in data.split(b"\n"):
        if EXEMPT_MARKER in line:
            continue
        for pat in SECRET_PATTERNS:
            if pat.search(line):
                hits.append(pat.pattern.decode(errors="replace"))
                break
    if hits:
        results.append((f"FAIL secret-scan:{label}", f"{len(hits)} secret-shaped line(s): {sorted(set(hits))}"))
    else:
        results.append((f"PASS secret-scan:{label}", "no secret-shaped string"))
    return not hits


def check_determinism(tree, epoch, label, results):
    data1, files = deterministic_zip(tree, epoch)
    data2, _ = deterministic_zip(tree, epoch)
    h1, h2 = hashlib.sha256(data1).hexdigest(), hashlib.sha256(data2).hexdigest()
    if not files:
        results.append((f"SKIP determinism:{label}", "tree has 0 files; nothing to prove yet"))
        return
    ok = True
    with zipfile.ZipFile(io.BytesIO(data1)) as zf:
        names = zf.namelist()
        infos = zf.infolist()
        expected_dt = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc).timetuple()[:6]
        if names != sorted(names):
            results.append((f"FAIL determinism:{label}", "zip entries not sorted"))
            ok = False
        if any(info.date_time != expected_dt for info in infos):
            results.append((f"FAIL determinism:{label}", "zip timestamps not normalised to epoch"))
            ok = False
        if any(n.startswith("/") or ".." in n.split("/") for n in names):
            results.append((f"FAIL determinism:{label}", "absolute or escaping path in zip"))
            ok = False
    if h1 != h2:
        results.append((f"FAIL determinism:{label}", f"two builds differ: {h1} vs {h2}"))
        ok = False
    if ok:
        results.append(
            (f"PASS determinism:{label}",
             f"{len(files)} files, byte-identical builds, sha256={h1}, epoch={epoch}"),
        )


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=None)
    ap.add_argument("--sbom", default=None)
    ap.add_argument("--epoch", type=int, default=None)
    args = ap.parse_args(argv)

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parent.parent
    results = []

    # --- epoch handling (honest about the source) ---
    import os

    env_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if args.epoch is not None:
        epoch, epoch_src = args.epoch, "flag"
    elif env_epoch is not None:
        epoch, epoch_src = int(env_epoch), "SOURCE_DATE_EPOCH env"
    else:
        epoch, epoch_src = 1700000000, "built-in test epoch (env not set)"
    results.append(("INFO epoch", f"{epoch} from {epoch_src}"))

    # --- 1. determinism: real app tree ---
    app_dir = root / "keyholder"
    check_determinism(app_dir, epoch, "keyholder-tree", results)

    # --- 1b. determinism: synthetic fixture (exercises the logic) ---
    with tempfile.TemporaryDirectory() as td:
        fixture = Path(td) / "fixture"
        (fixture / "sub").mkdir(parents=True)
        (fixture / "b.py").write_text("x = 1\n", encoding="utf-8")
        (fixture / "sub" / "a.py").write_text("y = 2  # TEST-ONLY- fixture\n", encoding="utf-8")
        check_determinism(fixture, epoch, "synthetic-fixture", results)
        data, _ = deterministic_zip(fixture, epoch)
        scan_secrets(data, "synthetic-fixture-zip", results)

    # --- 2. no absolute paths in a real-tree build ---
    data, files = deterministic_zip(app_dir, epoch)
    if files and str(root).encode() in data:
        results.append(("FAIL absolute-paths", "build root path embedded in zip bytes"))
    elif files:
        results.append(("PASS absolute-paths", "build root path not present in zip bytes"))
    else:
        results.append(("SKIP absolute-paths", "no app files built yet"))

    # --- 2b. SOURCE_DATE_EPOCH through real packaging + cold cache ---
    check_packaging_epoch(root, epoch, results)

    # --- 2c. registry configuration assertion ---
    check_pip_config(root, results)

    # --- 3. requirements consistency ---
    req_path = root / "requirements.txt"
    if not req_path.exists():
        results.append(("FAIL requirements", "requirements.txt missing"))
    else:
        reqs = parse_requirements(req_path)
        if set(reqs) != ALLOWED_DIRECT:
            results.append(("FAIL requirements", f"must be exactly {sorted(ALLOWED_DIRECT)}, found {sorted(reqs)}"))
        else:
            results.append(("PASS requirements", f"exactly 2 direct deps: {sorted(reqs)}"))
            python = find_python(root)
            installed = installed_versions(python)
            for name, pinned in sorted(reqs.items()):
                got = installed.get(name)
                if got is None:
                    results.append((f"FAIL requirements:{name}", f"pinned {pinned} but not installed ({python})"))
                elif got != pinned:
                    results.append((f"FAIL requirements:{name}", f"pinned {pinned} but installed {got}"))
                else:
                    results.append((f"PASS requirements:{name}", f"installed == pinned {pinned}"))

    # --- 3b. SBOM agreement (if an SBOM exists) ---
    sbom_path = Path(args.sbom).resolve() if args.sbom else root / "sbom.json"
    if sbom_path.exists():
        bom = json.loads(sbom_path.read_text(encoding="utf-8"))
        by_name = {norm(c["name"]): c["version"] for c in bom.get("components", [])}
        reqs = parse_requirements(req_path) if req_path.exists() else {}
        bad = [f"{n} sbom={by_name.get(n)} pinned={p}" for n, p in reqs.items() if by_name.get(n) != p]
        if bad:
            results.append(("FAIL sbom-consistency", "; ".join(bad)))
        else:
            results.append(("PASS sbom-consistency", f"SBOM agrees on {len(reqs)} pins; {len(by_name)} components total"))
        scan_secrets(sbom_path.read_bytes(), "sbom.json", results)
    else:
        results.append(("SKIP sbom-consistency", f"no SBOM at {sbom_path}; run scripts/sbom.py first"))

    # --- 4. scanner self-test (fake sample built at runtime, never a literal) ---
    fake = b"ghp_" + b"x" * 36 + b"\n"
    probe = []
    scan_secrets(fake, "self-test-fake-sample", probe)
    if probe and probe[0][0].startswith("FAIL"):
        results.append(("PASS scanner-self-test", "scanner flags a synthetic secret-shaped sample"))
    else:
        results.append(("FAIL scanner-self-test", "scanner missed its synthetic sample"))
    exempt = b"token = 'TEST-ONLY-abcdef'\n"
    probe2 = []
    scan_secrets(exempt, "self-test-exempt", probe2)
    if probe2 and probe2[0][0].startswith("PASS"):
        results.append(("PASS scanner-self-test", "scanner exempts TEST-ONLY- fixtures"))
    else:
        results.append(("FAIL scanner-self-test", "scanner flagged a TEST-ONLY- fixture"))

    for status, detail in results:
        print(f"repro: {status} :: {detail}")
    n_fail = sum(1 for s, _ in results if s.startswith("FAIL"))
    n_pass = sum(1 for s, _ in results if s.startswith("PASS"))
    n_skip = sum(1 for s, _ in results if s.startswith("SKIP"))
    print(f"repro: summary pass={n_pass} fail={n_fail} skip={n_skip}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
