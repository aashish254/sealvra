#!/usr/bin/env python3
"""Generate a CycloneDX-style SBOM from the actual source tree + requirements.

Reads (never hand-writes the inventory):
  - requirements.txt in the build root: the direct dependencies + pins.
  - The installed environment (the build root's .venv if present, else the
    running interpreter): full installed set, versions, licences.
  - The source tree itself: every file under the root except .venv,
    __pycache__, .git, build outputs and the SBOM output file itself,
    recorded with its SHA-256.

What this SBOM is NOT: proof that a dependency is safe, proof that a
built artifact matches this source, or proof that a release was
authorised. See docs/supply-chain.md. Licence compatibility is a legal
gate, not evidence of safety.

Usage:
    python3 scripts/sbom.py [--root DIR] [--output FILE]
    python3 scripts/sbom.py --diff BASELINE_SBOM [--output FILE]
Exit non-zero if a pinned requirement is missing from the installed
environment or installed at a different version.

Dependency gates enforced here (F16-D3/D4/D7/D8, re-audited for v0.2):
  - requirements.txt must contain exactly the two allowed direct
    dependencies, each with an exact `==` pin. Any third direct
    dependency fails, with or without a decision record: adding one
    needs a CONTRACT amendment first, and only then a record in
    docs/dependency-decisions/<name>.md landed in the same change.
    (The record alone never authorises a new dependency.)
  - No registry redirection: lines adding an extra index, a local
    path/editable install, or an include are rejected, and a pip
    config file in the build root that sets a non-PyPI index fails.
  - Transitive closure cap: at most 10 transitive packages
    (12 total). The v0.2 closure is 3 transitive / 5 total.
  - `--diff` compares a freshly generated SBOM against a committed
    baseline: any component added, removed, version-changed, or
    licence-changed exits 2 and is a review-triggering event. Source
    file changes are reported but do not fail the diff (source
    changes on every commit; components must not change silently).
  - Build-time inventory: pip/setuptools versions and the hashes of
    every file under scripts/ are recorded under "build_time", so
    incident response can answer which releases ran which build
    script (F16-D1). Build-time tools are NOT runtime components
    and are not counted in the closure cap.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path

ALLOWED_DIRECT = {"cryptography", "argon2-cffi"}
# Installer tooling present in every venv; not runtime dependencies.
TOOLING = {"pip", "setuptools", "wheel", "pkg_resources"}
# F16-D3 hard cap on the transitive closure (set, then enforced).
MAX_TRANSITIVE = 10
MAX_TOTAL = 12
# Files that may redirect installs to another registry (F16-D7).
PIP_CONFIG_FILES = ("pip.conf", ".pip.conf", "setup.cfg", "pyproject.toml")
FORBIDDEN_REQ_TOKENS = ("--extra-index-url", "--index-url", "-r ", "-e ",
                        "--find-links", "-c ", "--constraint")


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(path):
    reqs = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for tok in FORBIDDEN_REQ_TOKENS:
            if tok in stripped:
                raise SystemExit(
                    f"sbom: forbidden requirements token {tok!r} in line: {line!r} "
                    "(registry redirection / editable / included files are not allowed)"
                )
        m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s;]+)$", stripped)
        if not m:
            raise SystemExit(
                f"sbom: unparsable requirements line: {line!r} "
                "(only exact `name==version` pins are allowed; no ranges, "
                "no markers, no extras)"
            )
        name = norm(m.group(1))
        if name in reqs:
            raise SystemExit(f"sbom: duplicate requirements entry: {name}")
        reqs[name] = m.group(2)
    return reqs


def check_pip_config(root):
    """Fail if a root pip config redirects installs off PyPI (F16-D7)."""
    for fname in PIP_CONFIG_FILES:
        cfg = root / fname
        if not cfg.is_file():
            continue
        text = cfg.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            low = line.strip().lower()
            if "extra-index-url" in low:
                raise SystemExit(
                    f"sbom: {fname} sets extra-index-url (registry "
                    "redirection is forbidden; see docs/supply-chain.md)"
                )
            if low.startswith("index-url"):
                url = low.split("=", 1)[1].strip() if "=" in low else ""
                if url and "pypi.org" not in url:
                    raise SystemExit(
                        f"sbom: {fname} sets a non-PyPI index-url: {url!r}"
                    )


def build_time_inventory(root, python):
    """Build-time tools + build-script hashes (F16-D1). Not components."""
    installed = installed_metadata(python)
    tools = {
        name: installed[name]["version"]
        for name in ("pip", "setuptools", "wheel")
        if name in installed
    }
    scripts = []
    for path in sorted((root / "scripts").rglob("*")):
        if path.is_file() and path.suffix in (".py", ".sh", ".ps1"):
            scripts.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
    return {"tools": tools, "scripts": scripts}


def diff_sboms(old, new):
    """Return (component_diffs, file_diffs) as human-readable lines."""
    old_c = {norm(c["name"]): c for c in old.get("components", [])}
    new_c = {norm(c["name"]): c for c in new.get("components", [])}
    comp_diffs = []
    for name in sorted(set(old_c) | set(new_c)):
        if name not in old_c:
            comp_diffs.append(f"added component {name}=={new_c[name]['version']}")
        elif name not in new_c:
            comp_diffs.append(f"removed component {name}=={old_c[name]['version']}")
        else:
            o, n = old_c[name], new_c[name]
            if o["version"] != n["version"]:
                comp_diffs.append(
                    f"version change {name}: {o['version']} -> {n['version']}")
            if o.get("licenses") != n.get("licenses"):
                comp_diffs.append(f"licence change {name}: {o.get('licenses')} -> {n.get('licenses')}")
            old_scope = o["properties"][0]["value"] if o.get("properties") else "?"
            new_scope = n["properties"][0]["value"] if n.get("properties") else "?"
            if old_scope != new_scope:
                comp_diffs.append(f"scope change {name}: {old_scope} -> {new_scope}")
    old_f = {f["path"]: f["sha256"] for f in old.get("source_files", [])}
    new_f = {f["path"]: f["sha256"] for f in new.get("source_files", [])}
    file_diffs = []
    for path in sorted(set(old_f) | set(new_f)):
        if path not in old_f:
            file_diffs.append(f"added file {path}")
        elif path not in new_f:
            file_diffs.append(f"removed file {path}")
        elif old_f[path] != new_f[path]:
            file_diffs.append(f"changed file {path}")
    return comp_diffs, file_diffs


def find_python(root):
    venv_python = root / ".venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    return sys.executable


def installed_metadata(python):
    """Return {normalised-name: {version, licence}} from that interpreter."""
    code = "\n".join(
        [
            "import importlib.metadata as m, json",
            "out = {}",
            "for d in m.distributions():",
            "    n = d.metadata['Name'] or ''",
            "    lic = d.metadata.get('License-Expression') or d.metadata.get('License') or ''",
            "    out[n] = {'version': d.version, 'licence': lic.strip()}",
            "print(json.dumps(out))",
        ]
    )
    proc = subprocess.run(
        [python, "-c", code], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise SystemExit(f"sbom: cannot read installed metadata: {proc.stderr.strip()}")
    raw = json.loads(proc.stdout)
    return {norm(k): v for k, v in raw.items() if k}


def tree_inventory(root, exclude_paths):
    entries = []
    skip_dirs = {".venv", ".git", "__pycache__", "dist", "build"}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path in exclude_paths:
            continue
        if any(part in skip_dirs for part in path.relative_to(root).parts):
            continue
        if path.suffix == ".pyc":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": digest,
                "size": path.stat().st_size,
            }
        )
    return entries


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=None, help="build root (default: parent of scripts/)")
    ap.add_argument("--output", default=None, help="output JSON path (default: <root>/sbom.json)")
    ap.add_argument("--diff", default=None, metavar="BASELINE",
                    help="compare the fresh SBOM against BASELINE SBOM JSON; "
                    "exit 2 on any component add/remove/version/licence change")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parent.parent
    req_path = root / "requirements.txt"
    if not req_path.exists():
        raise SystemExit(f"sbom: missing {req_path}")
    check_pip_config(root)
    reqs = parse_requirements(req_path)
    if set(reqs) != ALLOWED_DIRECT:
        raise SystemExit(
            f"sbom: requirements must contain exactly {sorted(ALLOWED_DIRECT)}, "
            f"found {sorted(reqs)}"
        )

    python = find_python(root)
    installed = installed_metadata(python)

    errors = []
    for name, pinned in reqs.items():
        got = installed.get(name)
        if got is None:
            errors.append(f"{name}: pinned {pinned} but not installed under {python}")
        elif got["version"] != pinned:
            errors.append(f"{name}: pinned {pinned} but installed {got['version']}")
    if errors:
        raise SystemExit("sbom: requirements/installed mismatch:\n  " + "\n  ".join(errors))

    output = Path(args.output).resolve() if args.output else root / "sbom.json"
    files = tree_inventory(root, exclude_paths={output})

    components = []
    for name, meta in sorted(installed.items()):
        if name in TOOLING:
            continue
        components.append(
            {
                "type": "library",
                "name": name,
                "version": meta["version"],
                "licenses": (
                    [{"license": {"id": meta["licence"]}}]
                    if meta["licence"] and meta["licence"] != "UNKNOWN"
                    else [{"license": {"name": "NOASSERTION"}}]
                ),
                "properties": [
                    {
                        "name": "keyholder:dependency-scope",
                        "value": "direct" if name in reqs else "transitive",
                    },
                    {
                        "name": "keyholder:pinned-in-requirements",
                        "value": "true" if name in reqs else "false",
                    },
                ],
            }
        )
    direct = [c for c in components if c["properties"][0]["value"] == "direct"]
    transitive = [c for c in components if c["properties"][0]["value"] == "transitive"]
    if len(transitive) > MAX_TRANSITIVE or len(components) > MAX_TOTAL:
        raise SystemExit(
            f"sbom: transitive closure cap exceeded: {len(direct)} direct + "
            f"{len(transitive)} transitive (caps: {MAX_TRANSITIVE} transitive, "
            f"{MAX_TOTAL} total) — a closure change is a review event, "
            "not a silent bump"
        )

    seed = hashlib.sha256(
        json.dumps(
            {"components": components, "files": files}, sort_keys=True
        ).encode()
    ).hexdigest()
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, seed)}",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "keyholder", "version": "0.2"},
            "properties": [
                {"name": "keyholder:generated-by", "value": "scripts/sbom.py"},
                {"name": "keyholder:generated-from", "value": "requirements.txt + installed environment + source tree"},
                {"name": "keyholder:interpreter", "value": python},
                {
                    "name": "keyholder:honesty-note",
                    "value": (
                        "Inventory only. This SBOM does not prove a dependency "
                        "is safe, that a built artifact matches this source, "
                        "or that any release was authorised. Build-time "
                        "tooling (pip/setuptools) is excluded from components; "
                        "see docs/supply-chain.md for that gap."
                    ),
                },
            ],
        },
        "components": components,
        "properties": [
            {"name": "keyholder:source-files", "value": str(len(files))},
            {"name": "keyholder:direct-dependencies", "value": str(len(direct))},
            {"name": "keyholder:transitive-dependencies", "value": str(len(transitive))},
        ],
        "source_files": files,
        "build_time": build_time_inventory(root, python),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"sbom: wrote {output}")
    print(f"sbom: direct={len(direct)} transitive={len(transitive)} source_files={len(files)}")
    for c in components:
        scope = c["properties"][0]["value"]
        lic = c["licenses"][0]["license"].get("id") or c["licenses"][0]["license"].get("name")
        print(f"sbom: {scope:10s} {c['name']}=={c['version']} licence={lic}")
    bt = bom["build_time"]
    print(f"sbom: build-time tools={bt['tools']} build-scripts={len(bt['scripts'])}")
    if args.diff:
        baseline_path = Path(args.diff)
        if not baseline_path.exists():
            raise SystemExit(f"sbom: diff baseline missing: {baseline_path}")
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        comp_diffs, file_diffs = diff_sboms(baseline, bom)
        for line in file_diffs:
            print(f"sbom-diff: file: {line}")
        if comp_diffs:
            for line in comp_diffs:
                print(f"sbom-diff: COMPONENT REVIEW-TRIGGER: {line}")
            print("sbom-diff: FAIL component set changed vs baseline "
                  "(review + decision record required; see docs/supply-chain.md)")
            return 2
        print(f"sbom-diff: PASS no component change vs baseline "
              f"({len(file_diffs)} source-file change(s) reported, not gated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
