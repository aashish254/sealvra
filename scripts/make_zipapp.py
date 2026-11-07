#!/usr/bin/env python3
"""Build the Sealvra v0.1 distribution as a deterministic zipapp.

W20 owns this file (CONTRACT.md section 12; W16 owns only the Windows
section of packaging, W17 only the macOS section -- neither owns this
script file, and this script does not edit their files).

Distribution shape for v0.1 (honest, no over-claim):
  * The v0.1 distribution for Linux, Windows, and macOS is this zipapp:
    ``dist/sealvra.pyz``, run as ``python3 sealvra.pyz --help``.
  * The target machine must already have Python 3.12 plus the two
    pinned dependencies from requirements.txt (``cryptography`` and
    ``argon2-cffi``); they are NOT bundled into the zipapp.
  * This is NOT a standalone executable. DMG / NSIS installer / .deb
    shapes are specifications only in v0.1 and are NOT built by this
    script; nothing here claims they exist.
  * The GitHub Actions workflow in .github/workflows/ci.yml is
    PREPARED, NOT RUN: it is not on the pushed branch of the public
    repository (only README.md is), so no CI run has
    happened and no passing run is claimed anywhere in this file.

Determinism:
  * Files are added in sorted order, with fixed permissions (0644).
  * Every zip entry timestamp comes from SOURCE_DATE_EPOCH when set
    (an --epoch flag overrides it for local testing); when neither is
    set, 1980-01-01 00:00:00 UTC is used so two builds are still
    byte-identical. No absolute paths are stored: archive names are
    relative (``sealvra/...`` plus a top-level ``__main__.py``).
  * The top-level ``__main__.py`` is a two-line shim that runs the
    package itself (``runpy.run_module("sealvra")``). W10's
    ``sealvra/__main__.py`` uses a relative import (``from .cli
    import main``), which cannot work as a top-level file, so a
    verbatim copy would break the zipapp; the shim delegates every
    CLI behaviour to W10's package and invents none of its own.

Fail-closed behaviour:
  * If ``sealvra/__main__.py`` is missing, the build fails with a
    non-zero exit and writes NO output file. A missing or half-built
    package must never be shipped as an apparently valid zipapp.
  * No key, token, or credential is read, embedded, or printed here.
    The only hash printed is the SHA-256 of the built artifact itself,
    so a test registry can bind a test report to this exact build
    (v3 section 1Q, N-Q1: wrong-artifact testing is closed by binding
    evidence to the artifact hash, not to a filename alone).

Usage:
    python3 scripts/make_zipapp.py [--root DIR] [--output FILE]
                                   [--epoch SECONDS]
    SOURCE_DATE_EPOCH=... python3 scripts/make_zipapp.py
"""

import argparse
import hashlib
import os
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path

SHEBANG = b"#!/usr/bin/env python3\n"
# Zip entries cannot predate 1980-01-01; use it as the deterministic
# fallback when no epoch is supplied at all.
FALLBACK_EPOCH = 315_532_800  # 1980-01-01 00:00:00 UTC


def zip_datetime(epoch: int) -> tuple:
    """Convert an epoch to the (Y, M, D, h, m, s) tuple zipfile needs."""
    if epoch < FALLBACK_EPOCH:
        epoch = FALLBACK_EPOCH
    t = time.gmtime(epoch)
    return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)


def resolve_epoch(args_epoch, env_epoch) -> int:
    """Flag wins over environment; both must be plain integers."""
    raw = args_epoch if args_epoch is not None else env_epoch
    if raw is None:
        return FALLBACK_EPOCH
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise SystemExit(f"make_zipapp: invalid epoch {raw!r}: not an integer")


def collect_files(package_dir: Path) -> list:
    """All files under the package dir, sorted by relative path.

    Bytecode caches are EXCLUDED (v0.2 manager fix for W19's
    cold-cache FAIL): bundling ``__pycache__/*.pyc`` made a
    test-run tree build differ from a fresh-copy build by 23 entries.
    Source files only, so any tree with the same sources builds the
    same zipapp.
    """
    files = []
    for path in sorted(package_dir.rglob("*")):
        if path.is_file() and not path.is_symlink():
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            files.append(path)
    return files


def build_zipapp(root: Path, output: Path, epoch: int) -> Path:
    """Build the zipapp. Returns the output path. Fails closed."""
    package_dir = root / "sealvra"
    entry_point = package_dir / "__main__.py"
    if not entry_point.is_file():
        raise SystemExit(
            "make_zipapp: refusing to build: "
            f"{entry_point} is missing (W10 has not landed the package "
            "entry point yet). No output file was written."
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    date_time = zip_datetime(epoch)

    with tempfile.TemporaryDirectory(prefix="sealvra-zipapp-") as tmp:
        tmp_path = Path(tmp) / "sealvra.pyz"
        with zipfile.ZipFile(
            tmp_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as zf:
            # Top-level entry point: shim that runs W10's package as
            # a module, so its relative imports keep working.
            top = zipfile.ZipInfo("__main__.py", date_time=date_time)
            top.external_attr = 0o644 << 16
            top.create_system = 3
            zf.writestr(
                top,
                b"import runpy, sys\n"
                b"if __name__ == '__main__':\n"
                b"    sys.exit(runpy.run_module('sealvra', "
                b"run_name='__main__'))\n",
            )
            for path in collect_files(package_dir):
                arcname = path.relative_to(root).as_posix()
                info = zipfile.ZipInfo(arcname, date_time=date_time)
                info.external_attr = 0o644 << 16
                info.create_system = 3
                zf.writestr(info, path.read_bytes())
        # Prepend the shebang and move into place atomically.
        data = tmp_path.read_bytes()
        final = SHEBANG + data
        staging = output.with_suffix(output.suffix + ".tmp")
        staging.write_bytes(final)
        os.chmod(staging, 0o755)
        os.replace(staging, output)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"built {output} sha256={digest}")
    return output


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Build dist/sealvra.pyz deterministically."
    )
    parser.add_argument(
        "--root",
        default=None,
        help="Build root containing the sealvra/ package "
        "(default: parent of this script's directory).",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output path (default: <root>/dist/sealvra.pyz).",
    )
    parser.add_argument(
        "--epoch",
        default=None,
        help="Epoch seconds for zip entry timestamps "
        "(overrides SOURCE_DATE_EPOCH).",
    )
    args = parser.parse_args(argv)
    root = Path(args.root) if args.root else Path(__file__).resolve().parent.parent
    output = (
        Path(args.output) if args.output else root / "dist" / "sealvra.pyz"
    )
    epoch = resolve_epoch(args.epoch, os.environ.get("SOURCE_DATE_EPOCH"))
    build_zipapp(root, output, epoch)
    return 0


if __name__ == "__main__":
    sys.exit(main())
