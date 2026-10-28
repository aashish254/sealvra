#!/usr/bin/env python3
"""Mechanical consistency gate for Keyholder v0.2 (W08).

Implements plan v3 SS4A G0-18 (f01 punch 11, f20 punch 12) as code
instead of prose: grep the final document set for losing passages
and FAIL unless every hit is the winning rule or an
explicitly-marked superseded historical note.

Pattern catalogue (gate data -- terms searched for, not claims):
TTL numbers, --show-token/--print-token, reveal, clipboard, opt-out,
PoP-off, vault-kek, learned approvals, TESS, biometryCurrentSet.

Losing passages searched (v3 G0-18 terms, plus the task's list):

- TTL numbers ``8h`` / ``24h`` / ``4h`` (catalogue forms: any of
  ``8 h``, ``8h``, ``8-hour``, ``8 hours`` and the 24/4 equivalents)
  -- the old R06/R14 TTL tables. A hit FAILS unless it is:
  (a) explicitly marked superseded history (``superseded``,
  ``deleted``, ``old ... figures are deleted``, ``never built`` in
  the surrounding window), or
  (b) a NON-TTL context: provider OAuth token lifetimes, the
  full-vault export cooldown, or an approval-anomaly window
  (``3 in 24 h pauses``). Those are not session TTLs, and the gate
  records the reason for each instead of failing on the number.
  A TTL number next to ``session`` / ``grant`` / ``template`` /
  ``ttl`` with no superseded marker FAILS -- that is the losing
  passage shape.
- The catalogue terms above -- each hit FAILS unless its surrounding
  window states the winning rule: a negation / deletion / refusal
  (``no``, ``never``, ``not``, ``deleted``, ``forbidden``,
  ``refused``, ``rejected``, ``without``, ``must not`` ...), a
  strict-opt-in statement for biometryCurrentSet, or an explicit
  superseded/deleted marker. Examples of winning-rule hits that
  correctly PASS: "there is no reveal command", "no clipboard
  handoff", "no level-3 opt-out", ".biometryCurrentSet strict
  mode, opt-in only", "the vault-kek-v1 design ... are never
  built", "the old 4-hour figures are deleted".

Mechanics (f17 P-08 spirit: a gate that cannot be audited is prose):

- Every hit is reported with file, line, matched text, verdict
  (ALLOW/FAIL), and the reason (which marker matched). A reviewer
  can audit the gate by reading the report, not by trusting it.
- Context window: the hit line plus 2 lines on either side. A
  winning rule stated as a section heading ("What Keyholder will
  not do") or a following sentence ("There is no command for any
  of these") is therefore recognised; a bare losing passage with
  no such window FAILS. The window rule is deliberately narrow
  (2 lines): widening it would let a distant negation bless a
  losing passage.
- Default document set (the "final document set"): README.md,
  CONTRACT.md, BUILD-AND-TEST-REPORT.md, docs/*.md,
  keyholder/*.py, packs/*.json, scripts/*.py, relative to the
  build root. Test files are NOT in the set: tests legitimately
  name forbidden things to assert their absence (e.g. the
  adversarial helpers' forbidden-flag list), and scanning them
  would either false-fail or teach the classifier to bless test
  contexts. The .github workflow is W20-owned and is not in the
  default set yet; extending the set to it is a one-line change
  to DOCSET_GLOBS once W20 wires the release job (see README G0
  table -- that wiring is OPEN).

Usage::

    python3 scripts/grep_gates.py [--root <build-root>]

Exit 0 when every hit is allowed, 1 when any hit fails (or when a
document-set file cannot be read). Stdlib only. No real keys,
tokens, or credentials are read, printed, or matched: the patterns
are feature names and TTL numbers, never secret shapes.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

BUILD_ROOT = Path(__file__).resolve().parent.parent

DOCSET_GLOBS = [
    "README.md",
    "CONTRACT.md",
    "BUILD-AND-TEST-REPORT.md",
    "docs/*.md",
    "keyholder/*.py",
    "packs/*.json",
    "scripts/*.py",
]

WINDOW = 2  # lines on either side of a hit line

# --- Patterns ---------------------------------------------------------------

TTL_RE = re.compile(r"\b(?:8|24|4)\s*-?\s*(?:hours?|h)\b", re.IGNORECASE)

FEATURE_PATTERNS = [
    ("--show-token", re.compile(r"--show-token")),
    ("--print-token", re.compile(r"--print-token")),
    ("Reveal", re.compile(r"\breveal\b", re.IGNORECASE)),
    ("clipboard", re.compile(r"\bclipboard\b", re.IGNORECASE)),
    ("opt-out", re.compile(r"opt[-\s]out", re.IGNORECASE)),
    ("PoP-off", re.compile(r"pop-off", re.IGNORECASE)),
    ("vault-kek", re.compile(r"vault[-_]kek", re.IGNORECASE)),
    ("learned approvals", re.compile(r"learned approvals", re.IGNORECASE)),
    ("TESS", re.compile(r"\bTESS\b")),
    ("biometryCurrentSet", re.compile(r"biometryCurrentSet")),
]

# --- Classifier markers (matched against the lowercased window) --------------

# A hit inside a gate/scanner pattern catalogue is detection data,
# not a product claim: the gate's own FEATURE_PATTERNS list, a
# scanner's marker tuple, or a docstring section labelled as the
# catalogue. The report names this reason so it stays auditable.
CATALOGUE_MARKERS = (
    "pattern catalogue",
    "catalogue",
    "gate data",
    "markers =",
    "marker strings",
)

SUPERSEDED_MARKERS = (
    "superseded",
    "never built",
    "are deleted",
    "is deleted",
    "figures are deleted",
    "deleted v1",
    "deleted passage",
)

# Non-TTL contexts: a TTL-looking number that is NOT a session TTL.
NON_TTL_MARKERS = (
    "cooldown",
    "export",
    "oauth",
    "expires_in",
    "anomaly",
    "threshold",
    "forged",
    "replayed",
    "pauses approvals",
    "pauses",
)

TTL_CONTEXT_WORDS = ("session", "grant", "template", "ttl")

WINNING_MARKERS = (
    "there is no",
    "there are no",
    "no reveal",
    "no clipboard",
    "no level-3 opt-out",
    "no opt-out",
    "no ",
    "never",
    "not ",
    "deleted",
    "deletion",
    "forbidden",
    "refused",
    "reject",
    "absence",
    "without",
    "must not",
    "cannot",
    "is not",
    "are not",
    "removed",
    "will not do",
    "no command",
    "deliberately no",
    "opt-in only",
    "strict mode",
    "strict-mode opt-in",
    "rejection of",
)


def _window_text(lines: list, index: int) -> str:
    start = max(0, index - WINDOW)
    end = min(len(lines), index + WINDOW + 1)
    return " ".join(lines[start:end]).lower()


@dataclass
class GrepHit:
    path: str
    line_no: int
    pattern: str
    matched: str
    allowed: bool
    reason: str


def classify_hit(window_lower: str, pattern_name: str, hit_line_lower: str) -> tuple:
    """Classify one hit. Returns (allowed, reason)."""
    if "re.compile" in hit_line_lower:
        return True, "forbidden-term pattern definition (gate data)"
    if any(m in window_lower for m in CATALOGUE_MARKERS):
        return True, "gate/scanner pattern catalogue (detection data, not a product claim)"
    if any(m in window_lower for m in SUPERSEDED_MARKERS):
        return True, "explicitly-marked superseded/deleted history"
    if pattern_name == "TTL":
        if any(m in window_lower for m in NON_TTL_MARKERS):
            return True, "non-TTL context (provider OAuth / export cooldown / anomaly window)"
        if any(w in window_lower for w in TTL_CONTEXT_WORDS):
            return False, "losing TTL passage: TTL number in a session/grant/template context"
        return False, "unclassified TTL number: neither superseded history nor a non-TTL context"
    if any(m in window_lower for m in WINNING_MARKERS):
        return True, "winning rule stated in context (negation/deletion/refusal/opt-in-only)"
    return False, "losing passage presented without a winning-rule or superseded marker"


def check_text(text: str, display_path: str) -> list:
    """Check one document's text. Returns its GrepHit list."""
    lines = text.splitlines()
    hits: list = []
    for index, line in enumerate(lines):
        window = _window_text(lines, index)
        line_lower = line.lower()
        for match in TTL_RE.finditer(line):
            allowed, reason = classify_hit(window, "TTL", line_lower)
            hits.append(GrepHit(display_path, index + 1, "TTL", match.group(0), allowed, reason))
        for name, pattern in FEATURE_PATTERNS:
            for match in pattern.finditer(line):
                allowed, reason = classify_hit(window, name, line_lower)
                hits.append(GrepHit(display_path, index + 1, name, match.group(0), allowed, reason))
    return hits


def docset_files(root: Path) -> list:
    """Expand DOCSET_GLOBS under root, sorted, excluding caches."""
    root = Path(root)
    files: list = []
    for glob in DOCSET_GLOBS:
        files.extend(p for p in root.glob(glob) if p.is_file())
    files = [p for p in files if "__pycache__" not in p.parts]
    return sorted(set(files))


@dataclass
class GrepReport:
    hits: list = field(default_factory=list)
    unreadable: list = field(default_factory=list)

    @property
    def failures(self) -> list:
        return [h for h in self.hits if not h.allowed]

    @property
    def ok(self) -> bool:
        return not self.failures and not self.unreadable

    def render(self) -> str:
        out = [f"grep gate: {'PASS' if self.ok else 'FAIL'} "
               f"({len(self.hits)} hits, {len(self.failures)} failing)"]
        for hit in self.hits:
            verdict = "ALLOW" if hit.allowed else "FAIL "
            out.append(
                f"  [{verdict}] {hit.path}:{hit.line_no} "
                f"[{hit.pattern} {hit.matched!r}] {hit.reason}"
            )
        for path in self.unreadable:
            out.append(f"  [FAIL ] unreadable document-set file: {path}")
        return "\n".join(out)


def check_tree(root: Path | None = None) -> GrepReport:
    """Run the grep gate over the default document set under root."""
    root = Path(root) if root is not None else BUILD_ROOT
    report = GrepReport()
    for path in docset_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            report.unreadable.append(f"{path}: {exc}")
            continue
        report.hits.extend(check_text(text, path.relative_to(root).as_posix()))
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Keyholder v0.2 grep gate (G0-18).")
    parser.add_argument("--root", default=str(BUILD_ROOT), help="build root to scan")
    args = parser.parse_args(argv)
    report = check_tree(Path(args.root))
    print(report.render())
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
