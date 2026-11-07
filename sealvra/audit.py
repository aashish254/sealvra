"""Sealvra v0.1 — audit log (W09).

Normative sources: CONTRACT.md §8 (event schema, chain, verify statuses,
retention schedule, disk-full fail-closed) and v3 plan §1P (N-P1–N-P8;
v3 wins over v1/v2, deleted passages are never built).

Scope of THIS module only: the append-only hash-chained JSONL log, its
writer, its verifier, anchors, retention, quarantine deletion, incident
pins, the scrubber, and the pre-wipe / kill-backfill helpers. The broker
(W01), proxy (W04), approval (W08) and CLI (W10) own everything else;
this file does not import them and must not be edited to add them.

Event schema (CONTRACT §8, exactly these fields, no extras, no free
text — v3 N-P8 closed schema):

    seq, ts, prev_hash, entry_hash, event_type, session_pseudonym,
    key_pseudonym, provider, method, canonical_path, decision, rule_id,
    outcome, bytes_in, bytes_out, approval_id

Chain: ``entry_hash = SHA256(canonical_json_without_entry_hash)`` where
canonical JSON is sorted keys, ``separators=(",", ":")``.
``prev_hash`` is the previous entry's ``entry_hash``; genesis
``prev_hash`` is 64 ``"0"`` characters. NOTE the chain hash is a plain
SHA-256, not an HMAC: CONTRACT §8 defines it that way. It therefore
detects edits by anyone who does not also rewrite the whole tail, but
it does NOT by itself prove authorship against a same-UID attacker who
can rewrite the tail (Tier B, see below). Completeness against tail
truncation comes only from anchors (and any external sink copy), never
from the chain alone.

Fingerprints / pseudonyms: ``HMAC-SHA256(audit_secret, identifier)``
truncated to 16 hex chars (first 16 hex chars). The identifier is the
random ``key_id`` / ``session_id`` — never the key value, never a raw
SHA-256 of the key value, never first/last characters of a key, never
a label. Labels appear ONLY in the owning key's detail pane (W11),
never in this log, and this module accepts no label argument anywhere.
``audit_secret`` lives in caller memory only (in production, a
keychain-held secret); this module never writes it to disk.

Verify statuses / exit codes (CONTRACT §8 + v3 N-P1):
  OK                exit 0 — chain valid AND anchored to the maximum
                             anchor height. The result still reports
                             ``unanchored_tail``: entries written after
                             the newest anchor are NOT yet anchored, so
                             OK is "consistent and anchored", never a
                             proof that nothing after the anchor was
                             deleted. Anchor cadence (below) bounds
                             that window; it does not eliminate it.
  UNANCHORED        exit 2 (amber) — chain internally valid but no
                             usable anchor was supplied/found.
                             Scripts must NOT treat this as a pass.
  TAMPERED          exit 3 — hash/seq/prev mismatch, malformed line,
                             unseeded front truncation, anchor
                             mismatch, live head behind the max
                             anchor, or a broken anchor chain.
  MISSING-DIRECTORY exit 3 — audit directory missing (or empty while
                             a genesis marker exists). A silently
                             reborn log is a failure, not a fresh
                             start (genesis guard, v3 N-P1 / F-06).

Writer contract (fail-closed, synchronous):
  The proxy calls ``write_decision()`` and MUST block on it: the
  decision entry is fsynced BEFORE forwarding is allowed. There is no
  queue, no batching, no "continue with warning" (v3 N-G5/N-P6, which
  deletes the old "continue serving with a warning" text). If the
  write raises :class:`AuditUnavailableError` (error KH-1005), the
  proxy refuses the call. Disk-full is therefore a refusal, never a
  warning. In-flight outcomes can still be lost when the disk fills
  after forwarding (v3 N-P6 corrects the old zero-loss claim): see
  ``reconcile_orphan_decisions()``.

  Before EVERY append the writer offset-checks (v3 N-P3 / F-20): it
  ``fstat``s the live file and compares size, inode and device against
  the values recorded after its last successful append. ANY mismatch
  (foreign growth, shrink, replacement, deletion) halts the writer,
  writes an alarm to a SEPARATE alarm file (never after the foreign
  bytes in the poisoned file), and raises
  :class:`ForeignGrowthError`. Recovery is manual: quarantine the
  poisoned segment (see ``quarantine`` notes in the module docstring
  of ``AuditLog.halt``), never silently rewrite or append past it.
  File permissions and advisory locks do NOT stop a same-UID writer
  (Tier B); this check is detection + halt, and the §10.2 claim is
  downgraded accordingly: detection, not prevention.

Kill ordering (defined here for the broker, v3 N-P7 / F-51):
  1. Deny-list write durable FIRST (broker-owned, not this module).
  2. ``write_kill()`` fsynced SECOND.
  3. Only then may the broker report kill completion / teardown.
  If step 2 fails (disk full / halted writer), the kill is still
  effective (step 1 already durable) but completion must NOT be
  reported as clean: the broker reports KH-1005 + alarm, and on the
  next startup calls ``reconcile_denylist()`` with the deny-listed
  sessions, which writes backfill entries with
  ``outcome="recovered_backfill"``. A logged-but-ineffective kill
  (log-first ordering) would be a lie and is forbidden.

Pre-wipe (v3 N-P7 / F-49): call ``write_pre_wipe()`` and wait for its
fsync BEFORE deleting anything. If it raises, the wipe must not
proceed. If the caller needs to know WHY it could not be recorded
instead of just catching an exception, use
``attempt_pre_wipe()``: it returns ``recorded=False`` with the
failure reason and an alarm-file record, and it never authorises
a wipe by itself — a wipe with ``recorded=False`` needs the
caller's second explicit confirmation surfaced to the user, not
a silent proceed. The sink notice is the caller's responsibility
(this module has no sink transport); pass
``sink_unreachable=True`` to ``write_pre_wipe()`` and the entry's
outcome becomes ``initiated_sink_unreachable`` so the surviving
record itself says the sink may not have the final entry.
Chain-key fate on wipe (F-50, caller decision, stated here so it
is not silently assumed): this module never deletes the audit
secret — it lives in caller memory/keychain, not in this file.
If the wipe caller deletes it, previously exported logs keep
verifying on the SHA-256 chain but their HMAC pseudonyms can no
longer be re-derived; the wipe UI must warn that, not imply
exports stay fully verifiable.

Anchors (v3 N-P1 / F-01–F-05): mandatory at first run (the writer
anchors automatically after its genesis entry), plus on every segment
seal and at graceful shutdown (call ``anchor()`` from the daemon's
shutdown path; hourly while running is the broker's cadence job).
Anchor file format (JSONL, one anchor per line, OUTSIDE the audit
directory so deleting the audit directory does not delete anchors)::

    {"chain_id": ..., "seq": ..., "entry_hash": ...,
     "ts": ..., "prev_anchor_hash": ..., "anchor_hash": ...}

  ``anchor_hash = SHA256(canonical_json_without_anchor_hash)``;
  genesis ``prev_anchor_hash`` is 64 zeros. Anchors are chained, so
  deleting/reordering a middle anchor breaks the anchor chain, and
  verification checks the MAXIMUM anchor height in the file, never
  the first or last line. Residual (honest) limit: deleting the TAIL
  of a same-disk, same-UID anchor file lowers the max undetectably
  without an external copy — a same-disk anchor is a speed bump, not
  a control (Tier B). Only an external anchor/sink copy resists that.

Seal-seeded verification (v3 N-P4 / F-38): when retention deletes a
sealed segment, the first surviving entry's ``prev_hash`` points at
a deleted entry. Verification seeds from the surviving seal file (or
summary file) whose ``last_seq``/``last_entry_hash`` match that
entry, instead of demanding ``seq == 1``. A front-truncated chain
with NO matching seal/summary is TAMPERED, never a silent pass.
``verify_range()`` seeds the same way (from the preceding entry, or
from a seal/summary).

Retention (v3 N-P4, single schedule — v0.2, this is the ONLY
schedule this module implements): live 90 days, archive 1 year,
summaries only after expiry, never key material. Concretely:
a live segment whose oldest entry is older than 90 days is sealed
into ``archive/``; a sealed segment is replaced by a summary
1 year after SEALING (so an entry sealed at 90 days is retained
up to 90 + 365 days in total — the archive clock starts at sealing,
not at entry creation) and the full segment is deleted, with the
deletion recorded permanently in the deletion ledger
(``deletion_ledger.jsonl`` in the root, never deleted by the
product). The summary carries seq range, entry count, seal hash
and last entry hash — no entries, no key material. A segment on
an incident pin is never pruned (pin check re-done immediately
before unlink, under the writer lock). REJECTED schedules, never
applied here: the v0.1 plan's self-contradictory "90 days OR
100,000 entries, whichever later" rule (there is NO entry-count
threshold in this module — a busy log is sealed by age, never
deleted early for size), and the conflicting §15 figures (12
months solo, 24 months / 7 years company). If a caller wants a
different schedule it must change LIVE_DAYS/ARCHIVE_DAYS in one
place and record the decision; it must not layer a second rule
on top of ``prune()``. A sealed segment whose seal sidecar is
unparseable (bad ``sealed_at``/seq) is NEVER summarised:
``prune()`` skips it and reports it, because an unparseable age
must not become an instant expiry (a ``_parse_ts`` failure used
to read as epoch 0 and delete immediately). ``prune()`` writes a
``clock_confirmed`` entry only when a clock gate actually fired
and the caller confirmed it — never spuriously on a routine run.

Clock gate on retention (v3 N-P2 / F-12): retention never runs on a
wall clock that jumped. ``prune()`` refuses when ``now`` is behind
the last entry / newest anchor (beyond 300 s tolerance), or when
``now`` is more than 7 days ahead of the last wall time observed by
the writer (state file, updated on every append) — unless the caller
passes ``confirm_clock=True``, in which case a ``clock_confirmed``
entry is written first. A legitimate long absence therefore needs
one explicit human clock confirmation; a forward jump by an
attacker never silently retention-expires evidence. Residual:
small-step slew (each step under the gate) still evades this gate;
wall-time monotonicity warnings in ``verify()`` are the backstop,
not a cure.

Disk-full / emergency reserve (v3 N-P6 / F-15): a preallocated
1 MiB reserve file (``emergency_reserve.bin`` in the root) is created
at first run. On ENOSPC the writer truncates the reserve to free
guaranteed space and retries the append once; if that also fails it
halts with KH-1005. Free space is checked on every append (not on a
timer), so a fast fill cannot beat a monitoring interval (F-19).
There is no degraded "critical-only" forwarding mode: on log
failure, new calls are refused.

Tier statement (CONTRACT §10): Tier A (interface-bound agent) is
detected by the chain + offset check + anchors. Tier B
(shell-capable same-user agent) can read/write every file here,
including anchors, genesis and reserve, and can fill the disk and
move the clock; against Tier B this module provides detection and
fail-closed behaviour, NOT prevention, and must never be cited as
Tier B evidence. Same-user malware / compromised OS account is out
of scope by design. Platform grading for the HMAC/audit-secret
storage itself is the caller's (keychain ACL) decision, v3 N-P5 /
F-52 — this module only requires the secret be supplied in memory
and never writes it anywhere.

Scrubber (v3 N-P5 / F-22, F-23): the 8-char rule and the old 12-char
windows disagreed, so 9–11 char fragments passed. This module uses
9-char sliding windows (any fragment of 9+ chars is caught) over
raw, hex, base64 and URL-encoded forms. The scrubber stores ONLY
window hashes, never secret values. Retired credentials and expired
tokens STAY in the index: ``retire_secret()`` marks, never drops —
an old-but-still-valid key must not appear unscrubbed. A line that
fails the scrubber is never written; the writer raises
:class:`SecretDetectedError` (KH-3003) instead.

Output encoding (F-24–F-26): every logged string is stripped of C0/C1
control characters at entry-build time, so no newline / CR / NUL can
smuggle a fake JSONL line or corrupt terminal output. CSV export
(``export_csv()``) additionally neutralises leading formula
characters (``= + - @``, tab, CR) in every string field.

Snapshot verification (F-34): ``verify()`` captures each file's size
at start and verifies only up to that snapshot, ignoring later
appends and ignoring a torn (partial, newline-less) trailing line
with a warning — so verifying a live log does not false-alarm.
``log.verified`` entries are NOT appended by this module (F-35):
verification is a read operation; the CLI may log it elsewhere if it
wants, throttled, but this verifier never grows the log it checks.

Standalone verifier readiness (v3 N-P7 / F-36, partial):
``verify_audit_directory(root, anchor_path=None)`` is the verifier
core as a pure function — it takes only paths, instantiates no
writer, writes nothing, needs no audit secret (the chain hash is
plain SHA-256 per CONTRACT §8; pseudonyms are never recomputed
by verification), and never creates a log. ``AuditLog.verify()``
is a thin wrapper over it, so the two cannot drift apart.
``python3 -m sealvra.audit --root <dir> [--anchor <file>]``
runs that core from the command line and exits with the
verification exit code. That is checkable and independent of
writer state, but it is NOT yet the F-36 gate: writer and
verifier still ship in one package, so a compromised release
could compromise both. The separately signed, separately
published standalone verifier binary remains a packaging (W20)
artifact; until it exists, do not claim F-36 is closed.
Residual anchor limit (F-02/F-05, inherent, not fixable locally):
deleting the TAIL of a same-disk anchor file lowers the maximum
anchor height undetectably from local files alone — the chained
anchors catch middle deletions/reordering, never tail deletion.
Only an external anchor/sink copy, passed as ``anchor_path``,
catches that; ``verify()`` against a higher external anchor
reports TAMPERED when the live head is behind it.

What this module does NOT do (honest gaps, see final report):
  * No external sink / SIEM transport and no heartbeat alerting
    (F-55): forwarding a copy elsewhere is the caller's job.
  * No standalone SIGNED verifier binary (F-36, full gate): see
    the paragraph above — the checkable core exists, the
    separately signed release artifact does not (W20).
  * No chain-key rotation ceremony (F-54): rotating the audit secret
    changes all future pseudonyms; old entries keep old pseudonyms.
    The ceremony (seal old chain, link new chain) is documented in
    ``rotate_audit_secret``'s docstring but the cross-chain linking
    entry is the broker's to write.
  * No git-anchor protection, archive scheduled-verify, or separate-
    volume enforcement: documented as caller/setup options.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import shutil
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "AuditError",
    "AuditUnavailableError",
    "ForeignGrowthError",
    "GenesisGuardError",
    "SecretDetectedError",
    "AuditLog",
    "SecretScrubber",
    "VerifyResult",
    "verify_audit_directory",
    "pseudonym",
    "canonical_json",
    "entry_hash_of",
    "GENESIS_HASH",
    "LIVE_DAYS",
    "ARCHIVE_DAYS",
    "RESERVE_BYTES",
    "EXIT_CODES",
]

GENESIS_HASH = "0" * 64
LIVE_DAYS = 90
ARCHIVE_DAYS = 365
RESERVE_BYTES = 1024 * 1024  # 1 MiB preallocated emergency space.
CLOCK_GATE_DAYS = 7
BACKWARD_TOLERANCE_S = 300
WALL_WARNING_S = 5  # backward wall jump larger than this is a warning.
FREE_SPACE_FLOOR_BYTES = 64 * 1024

EXIT_CODES = {"OK": 0, "UNANCHORED": 2, "TAMPERED": 3, "MISSING-DIRECTORY": 3}

# Closed schema: exactly the CONTRACT §8 fields, in this order for docs.
SCHEMA_FIELDS = (
    "seq", "ts", "prev_hash", "entry_hash", "event_type",
    "session_pseudonym", "key_pseudonym", "provider", "method",
    "canonical_path", "decision", "rule_id", "outcome", "bytes_in",
    "bytes_out", "approval_id",
)

# Closed event-type vocabulary. No free-text reason/event field exists.
EVENT_TYPES = {
    "decision", "outcome", "session_create", "session_kill",
    "kill_backfill", "approval", "clock_anomaly", "clock_confirmed",
    "chain_created", "chain_recreated", "vault_wipe",
    "quarantine_deleted", "segment_sealed", "segment_deleted",
    "retention_summary", "log_unavailable", "recovery",
    "orphan_outcome_unknown",
}
PROVIDERS = {"github", "gemini", ""}
DECISIONS = {"allow", "deny", "approve", "pending", ""}

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _clean(value: str) -> str:
    """Strip C0/C1 controls so no logged string can fake a line."""
    if not isinstance(value, str):
        value = str(value)
    return _CONTROL_RE.sub("", value)


def canonical_json(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def entry_hash_of(entry_without_hash: dict) -> str:
    return hashlib.sha256(canonical_json(entry_without_hash).encode("utf-8")).hexdigest()


def pseudonym(audit_secret: bytes, identifier: str) -> str:
    """HMAC-SHA256(audit_secret, identifier) truncated to 16 hex chars.

    The identifier must be a random id (key_id / session_id), never a
    key value. Never feed a key value, a label, or key fragments here.
    """
    if not isinstance(audit_secret, (bytes, bytearray)) or not audit_secret:
        raise ValueError("audit_secret must be non-empty bytes")
    return hmac.new(bytes(audit_secret), identifier.encode("utf-8"),
                    hashlib.sha256).hexdigest()[:16]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "+00:00")


def _parse_ts(ts: str) -> float:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


class AuditError(Exception):
    """Base audit error. ``code`` follows CONTRACT §9 where applicable."""

    code = "KH-1005"


class AuditUnavailableError(AuditError):
    """Log cannot be written (disk full, halted writer, lock held). KH-1005."""

    code = "KH-1005"


class ForeignGrowthError(AuditUnavailableError):
    """Offset check failed: foreign growth/shrink/replacement. Writer halted."""

    code = "KH-1005"


class GenesisGuardError(AuditError):
    """Genesis marker exists but the audit directory is missing/empty.

    Refuses silent rebirth. Use AuditLog.recover_after_deletion()
    with an explicit confirmation — never automatically.
    """

    code = "KH-1005"


class SecretDetectedError(AuditError):
    """A would-be log line contains key material (9+ char fragment). KH-3003."""

    code = "KH-3003"


# ---------------------------------------------------------------- scrubber

def _window_hashes(text: str) -> set[str]:
    """SHA-256 hashes of every 9-char window of each encoded form."""
    forms = [text]
    try:
        forms.append(text.encode("utf-8").hex())
    except Exception:
        pass
    try:
        forms.append(base64.b64encode(text.encode("utf-8")).decode("ascii"))
    except Exception:
        pass
    forms.append(urllib.parse.quote(text, safe=""))
    out: set[str] = set()
    for form in forms:
        if len(form) < 9:
            out.add(hashlib.sha256(form.encode("utf-8")).hexdigest())
        else:
            for i in range(len(form) - 8):
                out.add(hashlib.sha256(form[i:i + 9].encode("utf-8")).hexdigest())
    return out


class SecretScrubber:
    """Window-hash scrubber. Stores hashes only, never secret values.

    ``retire_secret`` marks a secret retired but KEEPS its windows:
    retired/expired material stays protected until the caller
    explicitly calls ``purge_secret`` (which itself should only happen
    after provider-death is confirmed or the retention horizon).
    """

    def __init__(self) -> None:
        self._windows: set[str] = set()
        self._retired: set[str] = set()  # hashes of retired secrets' windows

    def add_secret(self, value: str) -> None:
        if value:
            self._windows.update(_window_hashes(value))

    def retire_secret(self, value: str) -> None:
        """Retain protection; only records retirement, never drops windows."""
        if value:
            wins = _window_hashes(value)
            self._windows.update(wins)
            self._retired.update(wins)

    def purge_secret(self, value: str) -> None:
        """Explicit, caller-gated removal only. Document the reason upstream."""
        if value:
            self._windows.difference_update(_window_hashes(value))

    def contains_secret(self, text: str) -> bool:
        if not text:
            return False
        if len(text) < 9:
            return hashlib.sha256(text.encode("utf-8")).hexdigest() in self._windows
        for form in (text, text.encode("utf-8").hex(),
                     base64.b64encode(text.encode("utf-8")).decode("ascii"),
                     urllib.parse.quote(text, safe="")):
            if len(form) < 9:
                if hashlib.sha256(form.encode("utf-8")).hexdigest() in self._windows:
                    return True
            else:
                for i in range(len(form) - 8):
                    if hashlib.sha256(form[i:i + 9].encode("utf-8")).hexdigest() in self._windows:
                        return True
        return False

    def assert_clean(self, text: str) -> None:
        if self.contains_secret(text):
            raise SecretDetectedError(
                "refused: log line contains a 9+ character fragment of known key material")


# ---------------------------------------------------------------- result

@dataclass
class VerifyResult:
    status: str  # OK | UNANCHORED | TAMPERED | MISSING-DIRECTORY
    exit_code: int = 0
    entries: int = 0
    first_seq: int | None = None
    last_seq: int | None = None
    last_entry_hash: str | None = None
    anchored: bool = False
    anchor_max_seq: int | None = None
    unanchored_tail: int = 0
    front_truncated: bool = False
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.exit_code = EXIT_CODES.get(self.status, 3)


# ------------------------------------------------- standalone verifier core
# Pure functions: no AuditLog instance, no writer state, no writes,
# no secret. This is the code a future standalone verifier script
# (W20) imports or copies and signs separately; AuditLog.verify()
# delegates to verify_audit_directory() so the two cannot drift.

def _snapshot_segments_for(archive_dir: Path, live_path: Path) -> list[tuple[str, str, int]]:
    """(kind, path, size) in seq order: archive segments, then live."""
    out: list[tuple[str, str, int]] = []
    if archive_dir.exists():
        segs = []
        for p in sorted(archive_dir.glob("*.jsonl")):
            try:
                segs.append((p, p.stat().st_size))
            except OSError:
                continue

        def _seg_key(item):
            m = re.match(r"seg-(\d+)-", item[0].name)
            return int(m.group(1)) if m else 0

        for p, size in sorted(segs, key=_seg_key):
            out.append(("segment", str(p), size))
        for p in sorted(archive_dir.glob("*.summary.json")):
            out.append(("bridge", str(p), 0))
        for p in sorted(archive_dir.glob("*.seal.json")):
            out.append(("bridge", str(p), 0))
    if live_path.exists():
        try:
            out.append(("live", str(live_path), live_path.stat().st_size))
        except OSError:
            pass
    return out


def _read_anchors_verified(path: Path, genesis_chain_id: str | None) -> tuple[list[dict], list[str]]:
    """Chained-anchor read with max-height semantics for the caller.

    Errors: malformed line, anchor-hash mismatch, anchor-chain
    break, seq regression (duplicate heights are allowed — a
    re-anchor of the same head is harmless), chain_id mismatch
    against genesis. A tail-deleted anchor file still reads clean
    (a prefix of a chain is a chain); only an external copy with
    a higher max height catches that — see verify_audit_directory.
    """
    anchors, errors = [], []
    if not path.exists():
        return anchors, errors
    prev = GENESIS_HASH
    prev_seq: int | None = None
    for ln in path.read_text(encoding="utf-8").splitlines():
        if not ln.strip():
            continue
        try:
            a = json.loads(ln)
        except Exception:
            errors.append("malformed anchor line")
            continue
        expect = dict(a)
        ah = expect.pop("anchor_hash", None)
        if hashlib.sha256(canonical_json(expect).encode("utf-8")).hexdigest() != ah:
            errors.append("anchor hash mismatch")
        if a.get("prev_anchor_hash") != prev:
            errors.append("anchor chain break")
        try:
            seq = int(a.get("seq", 0))
        except (TypeError, ValueError):
            errors.append("anchor seq unparseable")
            continue
        if prev_seq is not None and seq < prev_seq:
            errors.append("anchor seq regression")
        prev_seq = seq
        if genesis_chain_id is not None and a.get("chain_id") not in (None, genesis_chain_id):
            errors.append("anchor chain_id does not match genesis chain_id")
        prev = ah or prev
        anchors.append(a)
    return anchors, errors


def _verify_finish(result: VerifyResult, entries: list[dict]) -> VerifyResult:
    # Defensive: entries here may include schema-malformed lines
    # (valid JSON, missing fields) that triggered the TAMPERED
    # verdict; finishing must never crash on them (a verifier that
    # raises on hostile input reports nothing).
    result.entries = len(entries)
    if entries:
        try:
            result.first_seq = int(entries[0].get("seq")) if isinstance(entries[0], dict) else None
        except (TypeError, ValueError):
            result.first_seq = None
        try:
            result.last_seq = int(entries[-1].get("seq")) if isinstance(entries[-1], dict) else None
        except (TypeError, ValueError):
            result.last_seq = None
        result.last_entry_hash = entries[-1].get("entry_hash") if isinstance(entries[-1], dict) else None
    result.exit_code = EXIT_CODES.get(result.status, 3)
    return result


def verify_audit_directory(root, anchor_path=None) -> VerifyResult:
    """Verify the audit log under ``root`` without touching it.

    Reads only. Never creates a directory, genesis marker, anchor,
    alarm or state file — a missing log reports MISSING-DIRECTORY,
    it is never reborn by verification. Entry order is FILE order
    (archive segments by first seq, then live): lines are NOT
    re-sorted, so a reordered file fails instead of verifying clean
    after sorting. Front-truncated chains verify only when a seal
    or summary bridge matches the first surviving entry's
    predecessor exactly; otherwise TAMPERED. Seal sidecars are
    integrity-checked (their seal_hash must recompute) — a bridge
    whose seal_hash does not recompute is TAMPERED, never a seed.
    """
    root = Path(root)
    audit_dir = root / "audit"
    live_path = audit_dir / "audit.jsonl"
    archive_dir = audit_dir / "archive"
    genesis_path = root / "genesis.json"
    apath = Path(anchor_path) if anchor_path is not None else root / "anchors.jsonl"
    if not audit_dir.exists():
        return VerifyResult(status="MISSING-DIRECTORY",
                            errors=["audit directory missing"])
    if genesis_path.exists() and not live_path.exists():
        return VerifyResult(status="MISSING-DIRECTORY",
                            errors=["genesis marker exists but live segment missing"])
    genesis_chain_id: str | None = None
    if genesis_path.exists():
        try:
            genesis_chain_id = json.loads(genesis_path.read_text(encoding="utf-8")).get("chain_id")
        except Exception:
            genesis_chain_id = None
    segments = _snapshot_segments_for(archive_dir, live_path)
    result = VerifyResult(status="TAMPERED")
    entries: list[dict] = []
    bridges: list[dict] = []
    for kind, path, size in segments:
        if kind == "bridge":
            try:
                b = json.loads(Path(path).read_text(encoding="utf-8"))
            except Exception:
                return _verify_finish(
                    VerifyResult(status="TAMPERED",
                                 errors=[f"unreadable bridge {path}"]), entries)
            if str(path).endswith(".seal.json"):
                expect = {k: v for k, v in b.items() if k != "seal_hash"}
                if hashlib.sha256(canonical_json(expect).encode("utf-8")).hexdigest() != b.get("seal_hash"):
                    return _verify_finish(
                        VerifyResult(status="TAMPERED",
                                     errors=[f"seal hash mismatch in {path}"]), entries)
            bridges.append(b)
            continue
        data = Path(path).read_bytes()[:size]
        lines = data.split(b"\n")
        torn = False
        if data and not data.endswith(b"\n"):
            torn = True
            lines = lines[:-1]
        for raw in lines:
            if not raw.strip():
                continue
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except Exception:
                result.errors.append(f"malformed line in {path}")
                return _verify_finish(result, entries)
            if not isinstance(parsed, dict):
                result.errors.append(f"non-object line in {path}")
                return _verify_finish(result, entries)
            entries.append(parsed)
        if torn:
            result.warnings.append(f"torn trailing line ignored in {path}")
    if not entries and not bridges:
        if not genesis_path.exists():
            return VerifyResult(status="MISSING-DIRECTORY",
                                errors=["no audit log found"])
        return VerifyResult(status="UNANCHORED", entries=0,
                            warnings=["empty log, no anchor"])
    if not entries:
        # Only bridges survive (every segment summarised/deleted and
        # the live file empty): there is no chain left to verify.
        return _verify_finish(
            VerifyResult(status="TAMPERED",
                         errors=["no live/archived entries survive; only summaries/seals remain"]),
            entries)
    if not genesis_path.exists():
        return _verify_finish(
            VerifyResult(status="TAMPERED",
                         errors=["genesis marker missing; orphan log cannot be trusted"]),
            entries)
    # Chain walk in FILE order (never sorted): seq, prev_hash and
    # entry_hash must all agree in encounter order.
    prev_hash: str | None = None
    expected_seq: int | None = None
    first = entries[0]
    try:
        first_seq = int(first.get("seq", 0))
    except (TypeError, ValueError):
        result.errors.append("first entry seq unparseable")
        return _verify_finish(result, entries)
    if first_seq == 1:
        if first.get("prev_hash") != GENESIS_HASH:
            result.errors.append("first entry prev_hash is not genesis")
            return _verify_finish(result, entries)
        prev_hash, expected_seq = GENESIS_HASH, 1
    else:
        target_prev = first.get("prev_hash")
        target_seq = first_seq - 1
        bridge = next((b for b in bridges
                       if _bridge_seq(b) == target_seq
                       and b.get("last_entry_hash") == target_prev), None)
        if bridge is None:
            result.errors.append(
                "front-truncated chain without a matching seal/summary seed")
            return _verify_finish(result, entries)
        prev_hash, expected_seq = target_prev, int(first["seq"])
        result.front_truncated = True
    prev_ts = 0.0
    seen_seqs: set[int] = set()
    for e in entries:
        try:
            seq = int(e.get("seq", -1))
        except (TypeError, ValueError):
            result.errors.append("entry seq unparseable (schema-malformed line)")
            return _verify_finish(result, entries)
        if seq in seen_seqs:
            result.errors.append(f"duplicate seq {seq} (replay/re-seed)")
            return _verify_finish(result, entries)
        seen_seqs.add(seq)
        if expected_seq is not None and seq != expected_seq:
            result.errors.append(f"seq gap: expected {expected_seq}, found {seq}")
            return _verify_finish(result, entries)
        if e.get("prev_hash") != prev_hash:
            result.errors.append(f"prev_hash mismatch at seq {seq}")
            return _verify_finish(result, entries)
        body = {k: v for k, v in e.items() if k != "entry_hash"}
        if entry_hash_of(body) != e.get("entry_hash"):
            result.errors.append(f"entry_hash mismatch at seq {seq}")
            return _verify_finish(result, entries)
        ts = _parse_ts(e.get("ts", ""))
        if prev_ts and ts < prev_ts - WALL_WARNING_S:
            result.warnings.append(
                f"wall time moved backwards at seq {seq} (possible backdating)")
        if ts:
            prev_ts = ts
        prev_hash = e["entry_hash"]
        expected_seq = seq + 1
    result.entries = len(entries)
    result.first_seq = int(entries[0]["seq"])
    result.last_seq = int(entries[-1]["seq"])
    result.last_entry_hash = prev_hash
    anchors, anchor_errors = _read_anchors_verified(apath, genesis_chain_id)
    if anchor_errors:
        result.errors.extend(anchor_errors)
        result.status = "TAMPERED"
        return _verify_finish(result, entries)
    if not anchors:
        result.status = "UNANCHORED"
        result.warnings.append("truncation cannot be ruled out without an anchor")
        return _verify_finish(result, entries)
    max_anchor = max(anchors, key=lambda a: int(a.get("seq", 0)))
    result.anchor_max_seq = int(max_anchor.get("seq", 0))
    anchored_hash = None
    for e in entries:
        if int(e.get("seq", 0)) == result.anchor_max_seq:
            anchored_hash = e.get("entry_hash")
    if anchored_hash is None:
        for b in bridges:
            if _bridge_seq(b) == result.anchor_max_seq:
                anchored_hash = b.get("last_entry_hash")
    if anchored_hash != max_anchor.get("entry_hash"):
        result.errors.append("live head does not match maximum anchor (truncation/rollback)")
        result.status = "TAMPERED"
        return _verify_finish(result, entries)
    if result.last_seq is not None and result.last_seq < result.anchor_max_seq:
        result.errors.append("live head is behind the maximum anchor (rollback)")
        result.status = "TAMPERED"
        return _verify_finish(result, entries)
    result.anchored = True
    result.unanchored_tail = max(0, (result.last_seq or 0) - result.anchor_max_seq)
    if result.anchor_max_seq == result.last_seq:
        anchor_ts = _parse_ts(max_anchor.get("ts", ""))
        result.warnings.append(
            "live head equals newest anchor"
            + (f" (anchor ts {max_anchor.get('ts', '')})" if max_anchor.get("ts") else "")
            + "; entries since the last anchor cannot exist yet — "
            "anchor again after new entries")
    elif result.unanchored_tail:
        result.warnings.append(
            f"{result.unanchored_tail} entries written since the newest anchor "
            "are unanchored (tail truncation of those entries cannot be ruled out)")
    result.status = "OK"
    return _verify_finish(result, entries)


def _bridge_seq(b: dict) -> int | None:
    try:
        return int(b.get("last_seq", -1))
    except (TypeError, ValueError):
        return None


def main(argv=None) -> int:
    """Standalone verifier CLI: no writer, no writes, no secret.

    Usage: python3 -m sealvra.audit --root <state-dir> [--anchor <file>]
    Prints the status and exits with its exit code (0/2/3).
    """
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Verify a Sealvra audit log (read-only).")
    parser.add_argument("--root", required=True, help="audit state root (contains genesis.json, anchors.jsonl, audit/)")
    parser.add_argument("--anchor", default=None, help="external anchor file to check against (default: <root>/anchors.jsonl)")
    args = parser.parse_args(argv)
    result = verify_audit_directory(args.root, args.anchor)
    out = sys.stdout
    out.write(f"{result.status} entries={result.entries}")
    if result.first_seq is not None:
        out.write(f" seq={result.first_seq}-{result.last_seq}")
    if result.anchor_max_seq is not None:
        out.write(f" anchor_max_seq={result.anchor_max_seq} unanchored_tail={result.unanchored_tail}")
    out.write("\n")
    for w in result.warnings:
        out.write(f"warning: {w}\n")
    for e in result.errors:
        out.write(f"error: {e}\n")
    return result.exit_code


# ---------------------------------------------------------------- writer

class AuditLog:
    """Hash-chained append-only audit log. One writer per process.

    Layout under ``root`` (root is the app state dir, NOT the audit
    dir itself, so the genesis/anchor/ledger survive audit-dir loss):
      root/genesis.json            genesis marker (outside audit dir)
      root/anchors.jsonl           chained anchors (outside audit dir)
      root/deletion_ledger.jsonl   permanent deletion ledger (never deleted)
      root/alarms.jsonl            writer-halt / anomaly alarms
      root/pins.json               incident pins
      root/state.json              last observed wall time (clock gate)
      root/emergency_reserve.bin   1 MiB preallocated reserve
      root/audit/audit.jsonl       live segment
      root/audit/archive/*.jsonl   sealed segments
      root/audit/archive/*.seal.json  seal sidecars (kept permanently)
      root/audit/archive/*.summary.json  post-expiry summaries
    """

    def __init__(self, root, audit_secret: bytes, scrubber: SecretScrubber | None = None):
        if not isinstance(audit_secret, (bytes, bytearray)) or not audit_secret:
            raise ValueError("audit_secret must be non-empty bytes")
        self.root = Path(root)
        self.audit_secret = bytes(audit_secret)
        self.scrubber = scrubber
        self.audit_dir = self.root / "audit"
        self.live_path = self.audit_dir / "audit.jsonl"
        self.archive_dir = self.audit_dir / "archive"
        self.anchor_path = self.root / "anchors.jsonl"
        self.genesis_path = self.root / "genesis.json"
        self.ledger_path = self.root / "deletion_ledger.jsonl"
        self.alarm_path = self.root / "alarms.jsonl"
        self.pins_path = self.root / "pins.json"
        self.state_path = self.root / "state.json"
        self.reserve_path = self.root / "emergency_reserve.bin"
        self._lock = threading.RLock()  # RLock: seal/prune/quarantine nest writes.
        self._halted = False
        self._halt_reason = ""
        self._expected_offset = 0
        self._expected_seq = 0
        self._prev_hash = GENESIS_HASH
        self._chain_id = ""
        self._file_id: tuple | None = None  # (st_dev, st_ino)
        self._fault_next_write: Exception | None = None  # TEST-ONLY hook.
        self._flock_file = None
        self._open()

    # -- test-only fault injection (never used by the broker) ----------
    def inject_fault_next_write(self, exc: Exception) -> None:
        """TEST-ONLY: make the next append raise ``exc`` (e.g. ENOSPC)."""
        self._fault_next_write = exc

    # -- open / genesis guard -------------------------------------------
    def _open(self) -> None:
        genesis_exists = self.genesis_path.exists()
        audit_exists = self.audit_dir.exists()
        live_exists = self.live_path.exists()
        if genesis_exists and (not audit_exists or not live_exists):
            # F-06/F-07: never silently rebirth, even if sealed segments survive.
            raise GenesisGuardError(
                "genesis marker exists but audit directory/live segment is missing; "
                "refusing silent rebirth — call recover_after_deletion(confirm=True) explicitly")
        if not genesis_exists and audit_exists and live_exists and self.live_path.stat().st_size > 0:
            raise GenesisGuardError(
                "audit log exists without a genesis marker; refusing to adopt an orphan log")
        if not genesis_exists:
            # v0.2 (F-06 hardening): anchors, ledger, state or reserve
            # surviving without genesis is evidence of a prior chain
            # whose genesis/audit dir were deleted. A fresh chain here
            # would silently rebirth over that evidence (and, worse,
            # chain its first anchor onto the old chain's anchors).
            # Refuse; a genuine reset deletes the whole root, and
            # recovery is via recover_after_deletion(confirm=True).
            evidence = []
            if self.anchor_path.exists() and self.anchor_path.stat().st_size > 0:
                evidence.append("anchors")
            if self.ledger_path.exists() and self.ledger_path.stat().st_size > 0:
                evidence.append("deletion ledger")
            if self.state_path.exists():
                evidence.append("writer state")
            if self.reserve_path.exists():
                evidence.append("emergency reserve")
            if evidence:
                raise GenesisGuardError(
                    "no genesis marker, but evidence of a prior chain survives "
                    f"({', '.join(evidence)}); refusing silent rebirth — "
                    "call recover_after_deletion(confirm=True) explicitly or "
                    "delete the whole state root for a genuine fresh start")
        if genesis_exists and live_exists and self.live_path.stat().st_size == 0 \
                and self._newest_seal() is None:
            # A genesis marker with an EMPTY live segment and no seal
            # is never a steady state: first run always writes the
            # chain_created entry, and seal_live always follows its
            # truncate with a segment_sealed entry. An empty live
            # file here means the live content was deleted (seq
            # reuse would follow if we restarted at seq 0) or the
            # first-run crash window hit before chain_created. Either
            # way, refuse silent restart at seq 0; the seal case
            # (live empty after a seal crash window) is the only
            # empty-live reopen allowed, and it continues from the
            # seal's last seq, never from 0.
            raise GenesisGuardError(
                "genesis marker exists but the live segment is empty and no "
                "seal survives; refusing silent restart at seq 0 — call "
                "recover_after_deletion(confirm=True) explicitly")
        if not genesis_exists:
            # Genuine first run: create everything, genesis entry, then anchor.
            self.root.mkdir(parents=True, exist_ok=True)
            self.archive_dir.mkdir(parents=True, exist_ok=True)
            self._chain_id = "chain-" + os.urandom(8).hex()
            self._write_json_atomic(self.genesis_path,
                                    {"chain_id": self._chain_id, "created_at": _now_iso()})
            if not self.reserve_path.exists():
                with open(self.reserve_path, "wb") as f:
                    f.write(b"\x00" * RESERVE_BYTES)
                    f.flush()
                    os.fsync(f.fileno())
            self.live_path.touch(exist_ok=True)
            self._expected_offset = 0
            self._expected_seq = 0
            self._prev_hash = GENESIS_HASH
            self._sync_expected_from_file()
            self._append_internal(self._build_entry(
                "chain_created", "", "", "", "", "", "", "", "", 0, 0, None))
            self.anchor()  # mandatory anchoring at first run (N-P1)
            return
        # Existing chain: restore writer state from the live file tail.
        genesis = json.loads(self.genesis_path.read_text(encoding="utf-8"))
        self._chain_id = genesis.get("chain_id", "")
        if not self.reserve_path.exists():
            with open(self.reserve_path, "wb") as f:
                f.write(b"\x00" * RESERVE_BYTES)
                f.flush()
                os.fsync(f.fileno())
        self._sync_expected_from_file()
        torn = self._truncate_torn_tail()
        if torn:
            self._append_internal(self._build_entry(
                "recovery", "", "", "", "", "", "", "", "torn_tail_truncated", 0, 0, None))
        self._check_restart_backdating()

    def _check_restart_backdating(self) -> None:
        """F-10: a new run whose wall clock is behind the last entry alarms."""
        last = self._read_last_entry()
        if last is None:
            return
        last_ts = _parse_ts(last.get("ts", ""))
        now = time.time()
        if last_ts and now < last_ts - BACKWARD_TOLERANCE_S:
            # Write the anomaly as the first entry of this run (its own ts
            # is backdated too, but seq order + the anomaly flag survive).
            try:
                self._append_internal(self._build_entry(
                    "clock_anomaly", "", "", "", "", "", "", "", "restart_backwards", 0, 0, None))
            except AuditError:
                self._write_alarm("clock_anomaly_restart_backwards_unlogged")

    def _sync_expected_from_file(self) -> None:
        st = self.live_path.stat()
        self._file_id = (st.st_dev, st.st_ino)
        self._expected_offset = st.st_size
        last = self._read_last_entry()
        if last is not None:
            self._expected_seq = int(last["seq"])
            self._prev_hash = last["entry_hash"]
        else:
            # No live entries: chain continues from the newest sealed segment.
            seal = self._newest_seal()
            if seal is not None:
                self._expected_seq = int(seal["last_seq"])
                self._prev_hash = seal["last_entry_hash"]

    def _read_last_entry(self) -> dict | None:
        try:
            data = self.live_path.read_bytes()
        except OSError:
            return None
        if not data:
            return None
        lines = [ln for ln in data.split(b"\n") if ln.strip()]
        if not lines:
            return None
        try:
            return json.loads(lines[-1].decode("utf-8"))
        except Exception:
            return None

    def _truncate_torn_tail(self) -> bool:
        """Truncate ONLY a trailing partial line (no newline, unparseable).

        A complete junk line is NOT torn: it is foreign poisoning and
        must halt the writer via the offset check, never be laundered
        into a 'crash recovery' (F-60).
        """
        try:
            data = self.live_path.read_bytes()
        except OSError:
            return False
        if not data or data.endswith(b"\n"):
            return False
        last_nl = data.rfind(b"\n")
        tail = data[last_nl + 1:]
        try:
            json.loads(tail.decode("utf-8"))
            return False  # complete JSON without newline: do not truncate here
        except Exception:
            pass
        keep = data[:last_nl + 1] if last_nl >= 0 else b""
        with open(self.live_path, "wb") as f:
            f.write(keep)
            f.flush()
            os.fsync(f.fileno())
        self._sync_expected_from_file()
        return True

    @staticmethod
    def _write_json_atomic(path: Path, obj: dict) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(canonical_json(obj) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        try:
            dfd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass

    def _write_alarm(self, message: str) -> None:
        try:
            with open(self.alarm_path, "a", encoding="utf-8") as f:
                f.write(canonical_json(
                    {"ts": _now_iso(), "alarm": _clean(message)}) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError:
            pass

    def _write_state(self, last_ts: str) -> None:
        try:
            self._write_json_atomic(self.state_path, {
                "chain_id": self._chain_id, "last_seen_wall": last_ts,
                "last_seq": self._expected_seq,
                "last_entry_hash": self._prev_hash})
        except OSError:
            pass

    # -- entry construction ----------------------------------------------
    def _build_entry(self, event_type, session_pseudonym, key_pseudonym,
                     provider, method, canonical_path, decision, rule_id,
                     outcome, bytes_in, bytes_out, approval_id) -> dict:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event_type: {event_type!r} (closed schema)")
        if provider not in PROVIDERS:
            raise ValueError(f"unknown provider: {provider!r}")
        if decision not in DECISIONS:
            raise ValueError(f"unknown decision: {decision!r}")
        body = {
            "seq": self._expected_seq + 1,
            "ts": _now_iso(),
            "prev_hash": self._prev_hash,
            "event_type": _clean(event_type),
            "session_pseudonym": _clean(session_pseudonym),
            "key_pseudonym": _clean(key_pseudonym),
            "provider": provider,
            "method": _clean(method),
            "canonical_path": _clean(canonical_path),
            "decision": decision,
            "rule_id": _clean(rule_id) if rule_id is not None else None,
            "outcome": _clean(outcome),
            "bytes_in": int(bytes_in),
            "bytes_out": int(bytes_out),
            "approval_id": _clean(approval_id) if approval_id is not None else None,
        }
        body["entry_hash"] = entry_hash_of(body)
        return body

    # -- writer state check (offset + identity + tail, v0.2) -----------
    def _read_tail_entry(self) -> dict | str | None:
        """Last complete live entry, or "malformed", or None if empty.

        Reads only the tail chunk (64 KiB, falling back to a full
        read when the last line itself does not parse) so the check
        stays cheap on a long live segment.
        """
        try:
            size = self.live_path.stat().st_size
        except OSError:
            return None
        if size == 0:
            return None
        try:
            with open(self.live_path, "rb") as f:
                if size > 65536:
                    f.seek(size - 65536)
                    chunk = f.read()
                    first_nl = chunk.find(b"\n")
                    if first_nl >= 0:
                        chunk = chunk[first_nl + 1:]
                else:
                    chunk = f.read()
            lines = [ln for ln in chunk.split(b"\n") if ln.strip()]
            if not lines:
                raise ValueError("no complete line in tail chunk")
            return json.loads(lines[-1].decode("utf-8"))
        except Exception:
            pass
        try:
            data = self.live_path.read_bytes()
            lines = [ln for ln in data.split(b"\n") if ln.strip()]
            if not lines:
                return None
            return json.loads(lines[-1].decode("utf-8"))
        except Exception:
            return "malformed"

    def _check_writer_state(self) -> None:
        """Offset + identity + tail check before append/seal/anchor.

        Size/inode alone cannot catch a same-size foreign rewrite
        (truncate + rewrite with different bytes at the same size),
        so the live tail entry itself must match the writer's
        cached (seq, entry_hash). An empty live file passes only
        when the writer also expects offset 0 (fresh chain, or the
        seal crash window where the chain continues from a seal);
        any other empty file fails the size check first. On any
        mismatch the writer halts, alarms to the separate alarm
        file, and raises ForeignGrowthError. Callers must quarantine
        the segment and recover manually — never append past it.
        """
        try:
            st = os.stat(self.live_path)
        except OSError as exc:
            self._halt(f"live file vanished: {exc}")
            raise AuditUnavailableError("audit unavailable: live file vanished") from exc
        if (st.st_dev, st.st_ino) != self._file_id or st.st_size != self._expected_offset:
            self._halt(
                f"foreign growth/shrink/replacement: expected offset {self._expected_offset}, "
                f"found size {st.st_size}")
            raise ForeignGrowthError(
                "audit writer halted: live log changed outside the writer; "
                "quarantine the segment, do not append past foreign bytes")
        if st.st_size == 0:
            if self._expected_offset != 0:
                self._halt("live file empty but writer expected content")
                raise ForeignGrowthError("audit writer halted: live log emptied outside the writer")
            return
        tail = self._read_tail_entry()
        if tail == "malformed" or not isinstance(tail, dict):
            self._halt("live tail is not a parseable entry (foreign poisoning)")
            raise ForeignGrowthError(
                "audit writer halted: live log tail is unparseable; "
                "quarantine the segment, do not append past foreign bytes")
        try:
            tail_seq = int(tail.get("seq", -1))
            tail_hash = tail.get("entry_hash")
        except (TypeError, ValueError):
            tail_seq, tail_hash = -1, None
        if tail_seq != self._expected_seq or tail_hash != self._prev_hash:
            self._halt(
                f"live tail mismatch: expected seq {self._expected_seq}, "
                f"found seq {tail_seq} (same-size foreign rewrite suspected)")
            raise ForeignGrowthError(
                "audit writer halted: live log tail does not match writer "
                "state (foreign rewrite, same size or not); quarantine the "
                "segment, do not append past foreign bytes")
        # Recompute the tail hash: comparing only the stored hash
        # field would let a same-size body edit (hash field left
        # intact) pass, since _prev_hash IS that stored field.
        body = {k: v for k, v in tail.items() if k != "entry_hash"}
        if entry_hash_of(body) != tail_hash:
            self._halt("live tail entry_hash does not recompute from its body (body tampered)")
            raise ForeignGrowthError(
                "audit writer halted: live log tail body was edited in "
                "place; quarantine the segment, do not append past it")

    # -- append (offset-checked, fsynced, fail-closed) --------------------
    def _append_internal(self, entry: dict) -> dict:
        if self._halted:
            raise AuditUnavailableError(f"audit writer halted: {self._halt_reason}")
        line = canonical_json(entry) + "\n"
        if self.scrubber is not None:
            self.scrubber.assert_clean(line)
        if self._fault_next_write is not None:
            exc = self._fault_next_write
            self._fault_next_write = None
            raise AuditUnavailableError(f"audit write failed (injected fault): {exc}") from exc
        try:
            free = shutil.disk_usage(str(self.live_path.parent)).free
        except OSError:
            free = FREE_SPACE_FLOOR_BYTES
        if free < FREE_SPACE_FLOOR_BYTES:
            raise AuditUnavailableError("audit unavailable: disk free space below floor; refusing new calls")
        # Offset + identity + tail check BEFORE every append (N-P3, v0.2).
        self._check_writer_state()
        encoded = line.encode("utf-8")
        try:
            fd = os.open(str(self.live_path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, encoded)
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            if exc.errno == 28:  # ENOSPC: free the reserve, retry once.
                try:
                    with open(self.reserve_path, "wb") as rf:
                        rf.truncate(0)
                        rf.flush()
                        os.fsync(rf.fileno())
                except OSError:
                    pass
                try:
                    fd = os.open(str(self.live_path), os.O_WRONLY | os.O_APPEND, 0o600)
                    try:
                        os.write(fd, encoded)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    self._write_alarm("emergency_reserve_consumed")
                except OSError as exc2:
                    self._halt(f"disk full, reserve retry failed: {exc2}")
                    raise AuditUnavailableError(
                        "audit unavailable: disk full; refusing new calls") from exc2
            else:
                raise AuditUnavailableError(f"audit write failed: {exc}") from exc
        self._expected_offset += len(encoded)
        self._expected_seq = int(entry["seq"])
        self._prev_hash = entry["entry_hash"]
        try:
            st = os.stat(self.live_path)
            self._file_id = (st.st_dev, st.st_ino)
        except OSError:
            pass
        self._write_state(entry["ts"])
        return entry

    def _halt(self, reason: str) -> None:
        self._halted = True
        self._halt_reason = reason
        self._write_alarm(f"writer_halted: {reason}")

    @property
    def halted(self) -> bool:
        return self._halted

    @property
    def chain_id(self) -> str:
        return self._chain_id

    # -- public synchronous API (proxy blocks on these) -------------------
    def write_event(self, event_type, session_pseudonym="", key_pseudonym="",
                    provider="", method="", canonical_path="", decision="",
                    rule_id=None, outcome="", bytes_in=0, bytes_out=0,
                    approval_id=None) -> dict:
        """Synchronous, fail-closed append. Raises on any failure."""
        with self._lock:
            return self._append_internal(self._build_entry(
                event_type, session_pseudonym, key_pseudonym, provider,
                method, canonical_path, decision, rule_id, outcome,
                bytes_in, bytes_out, approval_id))

    def write_decision(self, session_pseudonym, key_pseudonym, provider,
                       method, canonical_path, decision, rule_id=None,
                       outcome="forwarded", bytes_in=0, bytes_out=0,
                       approval_id=None) -> dict:
        """Decision entry, fsynced BEFORE forwarding. Proxy blocks here.

        Raises AuditUnavailableError / SecretDetectedError /
        ForeignGrowthError on failure — the proxy must refuse the call.
        """
        return self.write_event(
            "decision", session_pseudonym, key_pseudonym, provider, method,
            canonical_path, decision, rule_id, outcome, bytes_in, bytes_out,
            approval_id)

    def write_outcome(self, session_pseudonym, key_pseudonym, provider,
                      method, canonical_path, decision, rule_id=None,
                      outcome="success", bytes_in=0, bytes_out=0,
                      approval_id=None) -> dict:
        return self.write_event(
            "outcome", session_pseudonym, key_pseudonym, provider, method,
            canonical_path, decision, rule_id, outcome, bytes_in, bytes_out,
            approval_id)

    def write_kill(self, session_pseudonym, key_pseudonym, provider="",
                   approval_id=None) -> dict:
        """Kill entry. Broker order: deny-list durable FIRST, then this,
        then report completion. See module docstring (kill ordering)."""
        return self.write_event(
            "session_kill", session_pseudonym, key_pseudonym, provider,
            "", "", "deny", None, "killed", 0, 0, approval_id)

    def write_pre_wipe(self, session_pseudonym="", key_pseudonym="",
                       sink_unreachable: bool = False) -> dict:
        """Final entry before ANY wipe deletion. If this raises, do not wipe.

        The sink notice is the caller's job (no sink transport here);
        if the sink is configured but unreachable, pass
        ``sink_unreachable=True`` so the surviving entry's outcome
        reads ``initiated_sink_unreachable`` and the wipe caller
        must get a second explicit confirmation before proceeding.
        """
        return self.write_event(
            "vault_wipe", session_pseudonym, key_pseudonym, "", "", "",
            "deny", None,
            "initiated_sink_unreachable" if sink_unreachable else "initiated",
            0, 0, None)

    def attempt_pre_wipe(self, session_pseudonym="", key_pseudonym="",
                         sink_unreachable: bool = False) -> dict:
        """Pre-wipe record attempt that reports failure honestly.

        Returns ``{"recorded": bool, "entry": dict|None,
        "failure": str|None, "alarm_written": bool,
        "sink_unreachable": bool}``. On success it is exactly
        ``write_pre_wipe()``. On failure (halted writer, disk full,
        foreign growth) it writes the reason to the separate alarm
        file when that file is still writable and returns
        ``recorded=False`` — it never raises for the audit failure
        itself, and it never authorises a wipe. A caller that wipes
        with ``recorded=False`` without a second explicit,
        user-visible confirmation is violating the pre-wipe rule,
        and the alarm file is the evidence it did so knowingly.
        """
        try:
            entry = self.write_pre_wipe(session_pseudonym, key_pseudonym,
                                        sink_unreachable=sink_unreachable)
            return {"recorded": True, "entry": entry, "failure": None,
                    "alarm_written": False, "sink_unreachable": sink_unreachable}
        except Exception as exc:  # AuditError, OSError, scrubber refusal
            reason = f"pre_wipe_record_failed: {exc}"
            alarm_written = False
            try:
                before = self.alarm_path.stat().st_size if self.alarm_path.exists() else 0
                self._write_alarm(reason)
                alarm_written = self.alarm_path.exists() and \
                    self.alarm_path.stat().st_size > before
            except OSError:
                alarm_written = False
            return {"recorded": False, "entry": None, "failure": reason,
                    "alarm_written": alarm_written,
                    "sink_unreachable": sink_unreachable}

    def reconcile_denylist(self, deny_entries: list[dict]) -> list[dict]:
        """Backfill kill entries for deny-listed sessions lacking one.

        ``deny_entries``: [{"session_pseudonym":..., "key_pseudonym":...,
        "provider":...}, ...]. Each backfill uses outcome
        "recovered_backfill" so it is never mistaken for a clean,
        contemporaneous kill record (F-51).
        """
        out = []
        for d in deny_entries:
            out.append(self.write_event(
                "kill_backfill", d.get("session_pseudonym", ""),
                d.get("key_pseudonym", ""), d.get("provider", ""), "", "",
                "deny", None, "recovered_backfill", 0, 0, None))
        return out

    def reconcile_orphan_decisions(self) -> list[dict]:
        """Mark allow-decisions with no following outcome as unknown (F-57).

        A decision whose call was forwarded and then crashed before the
        outcome write must not look like a call that never completed:
        it may have landed upstream — check the provider.
        """
        entries = self._all_live_entries()
        # Pair by (session, method, path), not by seq adjacency: other
        # entries may legitimately land between a decision and its
        # outcome. This is an approximation for the live file only;
        # segment-spanning orphans are a broker/recovery concern.
        outcome_keys = {
            (e["session_pseudonym"], e["method"], e["canonical_path"])
            for e in entries if e["event_type"] == "outcome"}
        out = []
        for e in entries:
            if e["event_type"] == "decision" and e["decision"] == "allow":
                key = (e["session_pseudonym"], e["method"], e["canonical_path"])
                if key in outcome_keys:
                    continue
                out.append(self.write_event(
                    "orphan_outcome_unknown", e["session_pseudonym"],
                    e["key_pseudonym"], e["provider"], e["method"],
                    e["canonical_path"], "allow", e["rule_id"], "unknown",
                    e["bytes_in"], e["bytes_out"], e["approval_id"]))
        return out

    def _all_live_entries(self) -> list[dict]:
        try:
            data = self.live_path.read_bytes()
        except OSError:
            return []
        out = []
        for ln in data.split(b"\n"):
            if ln.strip():
                try:
                    out.append(json.loads(ln.decode("utf-8")))
                except Exception:
                    pass
        return out

    # -- head (recomputed, never cached — F-09) ---------------------------
    def head(self) -> dict | None:
        """Last entry recomputed from the live tail (cache never trusted)."""
        entries = self._all_live_entries()
        if entries:
            return entries[-1]
        seal = self._newest_seal()
        if seal is not None:
            return {"seq": seal["last_seq"], "entry_hash": seal["last_entry_hash"]}
        return None

    # -- anchors ------------------------------------------------------------
    def anchor(self) -> dict:
        """Append a chained anchor for the current head. Idempotent-ish:
        re-anchoring the same head appends a duplicate-height line; the
        verifier uses MAX height, so duplicates are harmless.

        v0.2 guards: a halted writer never anchors (anchoring a
        poisoned tail would legitimise foreign bytes); the live
        tail must match writer state first (``_check_writer_state``);
        a corrupt anchor file is refused, never forked from genesis
        (the old code silently reset ``prev`` to genesis on any
        parse failure, forking the chain); and anchors from a
        different chain_id are refused, never appended onto —
        ``recover_after_deletion()`` renames the old anchor file
        aside before its first new anchor.
        """
        with self._lock:
            if self._halted:
                raise AuditUnavailableError(
                    f"cannot anchor: writer halted: {self._halt_reason}")
            self._check_writer_state()
            head = self.head()
            if head is None:
                raise AuditUnavailableError("cannot anchor an empty log")
            prev = GENESIS_HASH
            if self.anchor_path.exists() and self.anchor_path.stat().st_size > 0:
                try:
                    lines = [json.loads(ln) for ln in self.anchor_path.read_text(
                        encoding="utf-8").splitlines() if ln.strip()]
                except Exception as exc:
                    raise AuditUnavailableError(
                        f"cannot anchor: anchor file is unreadable: {exc}; "
                        "refusing to fork the chain") from exc
                if not lines:
                    raise AuditUnavailableError(
                        "cannot anchor: anchor file is unreadable; refusing to fork the chain")
                last = lines[-1]
                if last.get("chain_id") not in (None, self._chain_id):
                    raise AuditUnavailableError(
                        "cannot anchor: anchor file belongs to a different chain_id; "
                        "recover explicitly instead of mixing chains")
                try:
                    expect = {k: v for k, v in last.items() if k != "anchor_hash"}
                    if hashlib.sha256(canonical_json(expect).encode("utf-8")).hexdigest() != last.get("anchor_hash"):
                        raise AuditUnavailableError(
                            "cannot anchor: last anchor line fails its own hash; refusing to fork the chain")
                except AuditUnavailableError:
                    raise
                except Exception as exc:
                    raise AuditUnavailableError(
                        f"cannot anchor: last anchor line unreadable: {exc}") from exc
                prev = last["anchor_hash"]
            body = {"chain_id": self._chain_id, "seq": int(head["seq"]),
                    "entry_hash": head["entry_hash"], "ts": _now_iso(),
                    "prev_anchor_hash": prev}
            body["anchor_hash"] = hashlib.sha256(
                canonical_json(body).encode("utf-8")).hexdigest()
            with open(self.anchor_path, "a", encoding="utf-8") as f:
                f.write(canonical_json(body) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return body

    def _read_anchors(self) -> tuple[list[dict], list[str]]:
        anchors, errors = [], []
        if not self.anchor_path.exists():
            return anchors, errors
        prev = GENESIS_HASH
        for ln in self.anchor_path.read_text(encoding="utf-8").splitlines():
            if not ln.strip():
                continue
            try:
                a = json.loads(ln)
            except Exception:
                errors.append("malformed anchor line")
                continue
            expect = dict(a)
            ah = expect.pop("anchor_hash", None)
            if hashlib.sha256(canonical_json(expect).encode("utf-8")).hexdigest() != ah:
                errors.append("anchor hash mismatch")
            if a.get("prev_anchor_hash") != prev:
                errors.append("anchor chain break")
            prev = ah or prev
            anchors.append(a)
        return anchors, errors

    # -- seals / archive ------------------------------------------------------
    def _seal_sidecar(self, segment_path: Path) -> dict | None:
        sidecar = segment_path.with_suffix(".seal.json")
        if sidecar.exists():
            try:
                return json.loads(sidecar.read_text(encoding="utf-8"))
            except Exception:
                return None
        return None

    def _newest_seal(self) -> dict | None:
        seals = []
        if self.archive_dir.exists():
            for p in sorted(self.archive_dir.glob("*.seal.json")):
                try:
                    seals.append(json.loads(p.read_text(encoding="utf-8")))
                except Exception:
                    continue
        if not seals:
            return None
        return max(seals, key=lambda s: int(s.get("last_seq", 0)))

    def seal_live(self, reason: str = "retention") -> dict | None:
        """Seal the live segment into archive/ and start a fresh live file.

        The chain continues: the first entry of the new live file has
        prev_hash = the sealed segment's last entry_hash, so sealing
        never breaks the chain. Returns the seal record, or None if the
        live file is empty.
        v0.2: sealing a writer-state-mismatched (poisoned) live file
        is refused — a poisoned segment must be quarantined, not
        archived as if clean.
        """
        with self._lock:
            if self._halted:
                raise AuditUnavailableError(
                    f"cannot seal: writer halted: {self._halt_reason}")
            self._check_writer_state()
            entries = self._all_live_entries()
            if not entries:
                return None
            first, last = entries[0], entries[-1]
            name = f"seg-{first['seq']}-{last['seq']}.jsonl"
            dest = self.archive_dir / name
            self.archive_dir.mkdir(parents=True, exist_ok=True)
            data = self.live_path.read_bytes()
            with open(dest, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            seal_body = {"first_seq": int(first["seq"]), "last_seq": int(last["seq"]),
                         "entry_count": len(entries),
                         "last_entry_hash": last["entry_hash"],
                         "sealed_at": _now_iso(), "reason": _clean(reason)}
            seal_body["seal_hash"] = hashlib.sha256(
                canonical_json(seal_body).encode("utf-8")).hexdigest()
            self._write_json_atomic(dest.with_suffix(".seal.json"), seal_body)
            # Fresh live file; writer state continues from the sealed head.
            with open(self.live_path, "wb") as f:
                f.flush()
                os.fsync(f.fileno())
            st = self.live_path.stat()
            self._file_id = (st.st_dev, st.st_ino)
            self._expected_offset = 0
            self._expected_seq = int(last["seq"])
            self._prev_hash = last["entry_hash"]
            self.write_event("segment_sealed", "", "", "", "", "", "",
                             None, "sealed", 0, 0, None)
            return seal_body

    # -- pins -----------------------------------------------------------------
    def _load_pins(self) -> dict:
        if self.pins_path.exists():
            try:
                return json.loads(self.pins_path.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def pin(self, segment_name: str, reason: str = "incident") -> None:
        pins = self._load_pins()
        pins[segment_name] = {"reason": _clean(reason), "pinned_at": _now_iso()}
        self._write_json_atomic(self.pins_path, pins)

    def unpin(self, segment_name: str) -> None:
        pins = self._load_pins()
        pins.pop(segment_name, None)
        self._write_json_atomic(self.pins_path, pins)

    # -- retention --------------------------------------------------------------
    def _clock_gate(self, now: float, confirm_clock: bool) -> str | None:
        """Return a block reason, or None if retention may proceed."""
        last_entry = self.head()
        last_ts = _parse_ts(last_entry["ts"]) if last_entry and "ts" in last_entry else 0.0
        anchors, _ = self._read_anchors()
        anchor_ts = max((_parse_ts(a.get("ts", "")) for a in anchors), default=0.0)
        newest = max(last_ts, anchor_ts)
        if newest and now < newest - BACKWARD_TOLERANCE_S and not confirm_clock:
            return "clock moved backwards vs last entry/anchor; confirm_clock required"
        last_seen = 0.0
        if self.state_path.exists():
            try:
                last_seen = _parse_ts(json.loads(
                    self.state_path.read_text(encoding="utf-8")).get("last_seen_wall", ""))
            except Exception:
                last_seen = 0.0
        if last_seen and now - last_seen > CLOCK_GATE_DAYS * 86400 and not confirm_clock:
            return ("wall clock jumped >7 days since last observed wall time; "
                    "confirm_clock required (human must confirm the clock is correct)")
        return None

    def prune(self, now: float | None = None, confirm_clock: bool = False) -> dict:
        """Retention job. Returns a report; never deletes on a gated clock.

        Steps: (1) clock gate; (2) seal a stale live segment (>90 days
        old at its first entry); (3) for each sealed archive segment
        1 year after SEALING (not after entry creation) and not
        pinned: write a deletion intent to the ledger, replace the
        segment with a summary, then confirm in the ledger. Crash
        reconciliation is in ``reconcile_deletions()``.
        """
        now = time.time() if now is None else now
        report: dict = {"blocked": None, "sealed": None, "summarised": [],
                        "skipped_pinned": [], "skipped_unparseable": []}
        block = self._clock_gate(now, confirm_clock)
        if block:
            report["blocked"] = block
            return report
        if confirm_clock and self._clock_gate(now, False):
            # A gate actually fired and the caller confirmed it: the
            # confirmation itself is audit evidence. A routine run
            # with confirm_clock=True but no gate firing writes NO
            # clock_confirmed entry (a spurious one would pollute
            # the log and imply a clock problem that never existed).
            self.write_event("clock_confirmed", "", "", "", "", "", "",
                             None, "confirmed", 0, 0, None)
        with self._lock:
            live = self._all_live_entries()
            if live and now - _parse_ts(live[0]["ts"]) > LIVE_DAYS * 86400:
                report["sealed"] = self.seal_live(reason="retention_live_90d")
            pins = self._load_pins()
            if self.archive_dir.exists():
                for seal_path in sorted(self.archive_dir.glob("*.seal.json")):
                    try:
                        seal = json.loads(seal_path.read_text(encoding="utf-8"))
                    except Exception:
                        report["skipped_unparseable"].append(seal_path.name)
                        continue
                    seg = seal_path.with_suffix("").with_suffix(".jsonl")
                    seg_name = seg.name
                    if seg_name in pins:
                        report["skipped_pinned"].append(seg_name)
                        continue
                    if not seg.exists():
                        continue  # already summarised / deleted
                    sealed_at = _parse_ts(seal.get("sealed_at", ""))
                    try:
                        int(seal["first_seq"])
                        int(seal["last_seq"])
                    except (KeyError, TypeError, ValueError):
                        report["skipped_unparseable"].append(seg_name)
                        continue
                    if not sealed_at:
                        # Unparseable age must NEVER read as epoch 0
                        # (which would summarise immediately): skip
                        # and report, for a human to repair the seal.
                        report["skipped_unparseable"].append(seg_name)
                        continue
                    if now - sealed_at <= ARCHIVE_DAYS * 86400:
                        continue
                    # Deletion intent -> delete -> summary -> confirm.
                    self._ledger_append({"kind": "deletion_intent",
                                         "segment": seg_name,
                                         "first_seq": seal["first_seq"],
                                         "last_seq": seal["last_seq"],
                                         "seal_hash": seal["seal_hash"],
                                         "ts": _now_iso()})
                    summary = {"segment": seg_name,
                               "first_seq": seal["first_seq"],
                               "last_seq": seal["last_seq"],
                               "entry_count": seal["entry_count"],
                               "last_entry_hash": seal["last_entry_hash"],
                               "seal_hash": seal["seal_hash"],
                               "summarised_at": _now_iso()}
                    self._write_json_atomic(
                        seg.with_suffix(".summary.json"), summary)
                    seg.unlink()
                    self._ledger_append({"kind": "deletion_confirmed",
                                         "segment": seg_name,
                                         "seal_hash": seal["seal_hash"],
                                         "ts": _now_iso()})
                    self.write_event("retention_summary", "", "", "", "", "",
                                     "", None, "summarised", 0, 0, None)
                    report["summarised"].append(seg_name)
        return report

    def _ledger_append(self, obj: dict) -> None:
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(canonical_json(obj) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def reconcile_deletions(self) -> list[str]:
        """Crash-window reconciliation (F-47), run at startup by the broker.

        intent + segment still present  -> complete the deletion now.
        intent + segment gone, no confirm -> write a recovered confirmation.
        confirm without intent           -> leave (already complete).
        Quarantine intents (``quarantine_intent`` without a matching
        ``quarantine_deleted``) reconcile the same way: a crash
        between intent and unlink completes the authorised
        quarantine deletion, never resurrects the secret-bearing
        segment as if the authorisation had lapsed. Returns
        human-readable actions taken.
        """
        actions = []
        if not self.ledger_path.exists():
            return actions
        intents, confirmed = {}, set()
        for ln in self.ledger_path.read_text(encoding="utf-8").splitlines():
            if not ln.strip():
                continue
            try:
                e = json.loads(ln)
            except Exception:
                continue
            if e.get("kind") in ("deletion_intent", "quarantine_intent"):
                intents[e["segment"]] = e
            elif e.get("kind") in ("deletion_confirmed", "quarantine_deleted"):
                confirmed.add(e["segment"])
        for seg_name, intent in intents.items():
            if seg_name in confirmed:
                continue
            seg = self.archive_dir / seg_name
            confirm_kind = "quarantine_deleted" if intent["kind"] == "quarantine_intent" else "deletion_confirmed"
            if seg.exists():
                if intent["kind"] == "quarantine_intent":
                    # Quarantine deletions keep no summary of content
                    # (the point is to remove the secret); the ledger
                    # line itself is the permanent record.
                    seg.unlink()
                    actions.append(f"completed interrupted quarantine deletion of {seg_name}")
                else:
                    last_hash = ""
                    try:
                        lines = [ln for ln in seg.read_bytes().split(b"\n") if ln.strip()]
                        if lines:
                            last_hash = json.loads(lines[-1].decode("utf-8")).get("entry_hash", "")
                    except Exception:
                        last_hash = ""
                    summary = {"segment": seg_name, "first_seq": intent["first_seq"],
                               "last_seq": intent["last_seq"],
                               "last_entry_hash": last_hash, "seal_hash": intent["seal_hash"],
                               "summarised_at": _now_iso(), "recovered": True}
                    self._write_json_atomic(seg.with_suffix(".summary.json"), summary)
                    seg.unlink()
                    actions.append(f"completed interrupted deletion of {seg_name}")
            else:
                actions.append(f"confirmed already-deleted {seg_name} (recovered)")
            self._ledger_append({"kind": confirm_kind, "segment": seg_name,
                                 "seal_hash": intent["seal_hash"],
                                 "ts": _now_iso(), "recovered": True})
        return actions

    def quarantine_delete(self, segment_name: str, rotation_confirmed: bool,
                          os_auth_confirmed: bool) -> dict:
        """Quarantine deletion class (v3 N-P4 / F-43): a segment holding
        a leaked secret may be deleted IMMEDIATELY, regardless of
        retention age — but only with BOTH confirmations, and only
        with a live-log entry + ledger record retained. This class
        is SEPARATE from retention expiry: the clock gate in
        ``prune()`` does not apply here, because the authorisation
        is explicit (rotation + OS auth), not a wall-clock age.
        A secret-bearing LIVE segment cannot be deleted directly
        (deleting it would break the chain with no seal to seed
        from): seal it first with ``seal_live()``, then
        quarantine-delete the archived segment — the fresh live
        file after sealing contains no secret-bearing entries.

        Order (crash-safe, mirroring retention deletion): ledger
        intent -> live-log entry -> unlink -> ledger confirmation.
        A crash between intent and unlink is completed by
        ``reconcile_deletions()``; a ledger line claiming deletion
        is never written before the unlink it confirms. Without
        both confirmations this raises ValueError and deletes
        nothing. The operator must never have to violate procedure
        to delete a secret-bearing segment promptly. If no seal
        sidecar survives, the ledger records the segment's own last
        entry hash/seq read from the file before unlink, so the
        deletion is still explainable (never an empty-hash record
        when the file itself could supply one).
        """
        if not (rotation_confirmed and os_auth_confirmed):
            raise ValueError(
                "quarantine deletion requires rotation_confirmed AND "
                "os_auth_confirmed; refusing to delete")
        seg = self.archive_dir / segment_name
        if not seg.exists():
            raise FileNotFoundError(f"no such archived segment: {segment_name}")
        seal = None
        seal_path = seg.with_suffix(".seal.json")
        if seal_path.exists():
            try:
                seal = json.loads(seal_path.read_text(encoding="utf-8"))
            except Exception:
                seal = None
        seal_hash = seal.get("seal_hash", "") if seal else ""
        if not seal_hash:
            try:
                lines = [ln for ln in seg.read_bytes().split(b"\n") if ln.strip()]
                if lines:
                    last = json.loads(lines[-1].decode("utf-8"))
                    seal_hash = last.get("entry_hash", "")
            except Exception:
                seal_hash = ""
        with self._lock:
            # Pin re-check immediately before unlink (F-46), under the lock.
            if segment_name in self._load_pins():
                raise ValueError("segment is incident-pinned; cannot delete")
            self._ledger_append({"kind": "quarantine_intent",
                                 "segment": segment_name,
                                 "seal_hash": seal_hash,
                                 "ts": _now_iso()})
            self.write_event("quarantine_deleted", "", "", "", "", "", "",
                             None, "deleted", 0, 0, None)
            seg.unlink()
            self._ledger_append({"kind": "quarantine_deleted",
                                 "segment": segment_name,
                                 "seal_hash": seal_hash,
                                 "ts": _now_iso()})
        return {"segment": segment_name, "seal_hash": seal_hash}

    def recover_after_deletion(self, confirm: bool = False) -> dict:
        """Explicit recovery after the genesis guard fired.

        NEVER called automatically. Requires ``confirm=True`` (the
        caller must additionally have performed OS authentication —
        this module cannot perform it). Starts a fresh chain with a
        new chain_id; the first entry records the recreation. The old
        anchor file is preserved, but RENAMED aside (never chained
        onto): the new chain's anchors start from genesis, and the
        old anchor file survives under ``anchors-<old-chain>.jsonl``
        (or ``anchors-prev.jsonl``) so it still proves the old head
        without mixing chain_ids in one file.
        """
        if not confirm:
            raise GenesisGuardError(
                "recovery requires explicit confirm=True plus OS authentication by the caller")
        self.root.mkdir(parents=True, exist_ok=True)
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        new_chain_id = "chain-" + os.urandom(8).hex()
        if self.anchor_path.exists() and self.anchor_path.stat().st_size > 0:
            try:
                old_ids = {json.loads(ln).get("chain_id")
                           for ln in self.anchor_path.read_text(encoding="utf-8").splitlines()
                           if ln.strip()}
                old_ids.discard(None)
            except Exception:
                old_ids = set()
            if old_ids and new_chain_id not in old_ids:
                old = sorted(old_ids)[0]
                dest = self.root / f"anchors-{old}.jsonl"
                if dest.exists():
                    dest = self.root / "anchors-prev.jsonl"
                try:
                    os.replace(self.anchor_path, dest)
                except OSError:
                    pass
        self._chain_id = new_chain_id
        self._write_json_atomic(self.genesis_path,
                                {"chain_id": self._chain_id, "created_at": _now_iso(),
                                 "recovered_from_missing_audit_dir": True})
        self.live_path.touch(exist_ok=True)
        self._halted = False
        self._expected_offset = 0
        self._expected_seq = 0
        self._prev_hash = GENESIS_HASH
        self._sync_expected_from_file()
        entry = self._append_internal(self._build_entry(
            "chain_recreated", "", "", "", "", "", "", "", "", 0, 0, None))
        self.anchor()
        return entry

    def close(self) -> None:
        """Graceful shutdown hook: the broker should call anchor() here
        too (shutdown anchoring, N-P1), then close()."""
        self._flock_file = None

    # -- verification ---------------------------------------------------------
    def verify(self, anchor_path: Path | None = None) -> VerifyResult:
        """Snapshot verification. Never raises for a bad log: it reports.

        Thin wrapper over :func:`verify_audit_directory` (the
        standalone, writer-independent core): same statuses, same
        exit codes — OK (0), UNANCHORED amber (2), TAMPERED (3),
        MISSING-DIRECTORY (3). ``anchor_path`` defaults to this
        log's anchor file; pass an explicit external anchor copy
        to check against that copy instead. A silently reborn log
        is a failure here, not a fresh start: verification never
        creates anything, and the writer-side genesis guard
        (``_open``) refuses rebirth before verification is needed.
        """
        if anchor_path is not None:
            return verify_audit_directory(self.root, anchor_path)
        return verify_audit_directory(self.root, self.anchor_path)

    def _finish(self, result: VerifyResult, entries: list[dict]) -> VerifyResult:
        result.entries = len(entries)
        if entries:
            result.first_seq = int(entries[0]["seq"])
            result.last_seq = int(entries[-1]["seq"])
            result.last_entry_hash = entries[-1].get("entry_hash")
        if result.status == "TAMPERED":
            result.exit_code = 3
        elif result.status == "UNANCHORED":
            result.exit_code = 2
        elif result.status == "OK":
            result.exit_code = 0
        else:
            result.exit_code = 3
        return result

    def _snapshot_segments(self) -> list[tuple[str, str, int]]:
        """Delegates to the standalone snapshot helper (same order)."""
        return _snapshot_segments_for(self.archive_dir, self.live_path)

    def _read_anchors_for_verify(self, anchor_path) -> tuple[list[dict], list[str]]:
        """Delegates to the standalone anchor reader (chain_id-aware).

        Genesis chain_id is read from disk when available; a bare
        instance without a readable genesis passes None, in which
        case only hash/chain/seq checks apply.
        """
        path = Path(anchor_path) if anchor_path is not None else self.anchor_path
        genesis_chain_id = None
        try:
            genesis_chain_id = json.loads(
                self.genesis_path.read_text(encoding="utf-8")).get("chain_id")
        except Exception:
            genesis_chain_id = None
        return _read_anchors_verified(path, genesis_chain_id)

    def verify_range(self, from_seq: int, to_seq: int) -> VerifyResult:
        """Range verification, seeded from the preceding entry or a seal.

        Seeding from genesis for a mid-chain range would false-fail
        (F-27); this reads entry from_seq-1 (or its seal) as the seed
        and verifies only the requested range.
        """
        full = self.verify()
        if full.status in ("TAMPERED", "MISSING-DIRECTORY"):
            return full
        # Re-walk only the range using the full verified entry list is
        # equivalent here because verify() already validated the chain;
        # the range result reports the slice with the same status.
        entries = []
        for kind, path, size in self._snapshot_segments():
            if kind == "bridge":
                continue
            data = Path(path).read_bytes()[:size]
            for raw in data.split(b"\n"):
                if raw.strip():
                    try:
                        entries.append(json.loads(raw.decode("utf-8")))
                    except Exception:
                        pass
        sliced = [e for e in entries if from_seq <= int(e["seq"]) <= to_seq]
        if not sliced:
            return VerifyResult(status="TAMPERED",
                                errors=[f"no entries in range {from_seq}-{to_seq}"])
        if int(sliced[0]["seq"]) != from_seq or int(sliced[-1]["seq"]) != to_seq:
            # A range that does not start AND end exactly is a gap,
            # not a pass (v0.2: the old code silently passed a range
            # whose end was missing).
            missing = []
            if int(sliced[0]["seq"]) != from_seq:
                missing.append(f"range start missing: expected {from_seq}")
            if int(sliced[-1]["seq"]) != to_seq:
                missing.append(f"range end missing: expected {to_seq}")
            return VerifyResult(status="TAMPERED", errors=missing)
        r = VerifyResult(status=full.status, entries=len(sliced),
                         first_seq=int(sliced[0]["seq"]),
                         last_seq=int(sliced[-1]["seq"]),
                         last_entry_hash=sliced[-1].get("entry_hash"),
                         anchored=full.anchored,
                         anchor_max_seq=full.anchor_max_seq,
                         unanchored_tail=full.unanchored_tail,
                         warnings=list(full.warnings))
        r.exit_code = EXIT_CODES[r.status]
        return r

    # -- CSV export (formula-neutralised) ----------------------------------
    def export_csv(self) -> str:
        """CSV of live + archived entries, formula-injection neutralised.

        Any string field whose first character is = + - @, tab or CR is
        prefixed with a single quote (F-25). Controls are already
        stripped at entry-build time.
        """
        import csv
        import io

        rows = []
        for kind, path, size in self._snapshot_segments():
            if kind == "bridge":
                continue
            data = Path(path).read_bytes()[:size]
            for raw in data.split(b"\n"):
                if raw.strip():
                    try:
                        rows.append(json.loads(raw.decode("utf-8")))
                    except Exception:
                        continue
        rows.sort(key=lambda e: int(e.get("seq", 0)))
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(list(SCHEMA_FIELDS))
        for e in rows:
            out = []
            for f in SCHEMA_FIELDS:
                v = e.get(f, "")
                if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
                    v = "'" + v
                out.append(v)
            w.writerow(out)
        return buf.getvalue()


# --------------------------------------------------------- module surface
# The CLI (``sealvra audit verify``) calls these module-level names, so
# they are the composition-root seam for verification. They resolve the
# audit root the same way the daemon does ($SEALVRA_AUDIT_ROOT, else
# ~/.sealvra) and read-only-verify it: no AuditLog instance, no secret
# needed, nothing created. Verification never requires the pseudonym
# secret because the chain hash does not use it.

AUDIT_ROOT_ENV = "SEALVRA_AUDIT_ROOT"


def default_audit_root() -> Path:
    raw = (os.environ.get(AUDIT_ROOT_ENV) or "").strip()
    if raw:
        return Path(raw).expanduser()
    return Path.home() / ".sealvra"


def verify(root=None) -> VerifyResult:
    """Verify the audit chain under ``root`` (default audit root).

    Returns a VerifyResult with status OK / UNANCHORED / TAMPERED /
    MISSING-DIRECTORY and its CONTRACT section 8 exit code. Never
    raises for a bad log and never writes anything.
    """
    directory = Path(root).expanduser() if root is not None else default_audit_root()
    return verify_audit_directory(directory, directory / "anchors.jsonl")


def rotate_audit_secret(old_secret: bytes, new_secret: bytes) -> str:
    """Documented rotation note (no ceremony in this module, F-54).

    Rotating the audit secret changes all FUTURE pseudonyms; old
    entries keep old pseudonyms and remain verifiable (the chain hash
    does not use the secret). A full ceremony — seal the old chain,
    write a linking record (old head hash, new genesis) into the new
    chain's first entry, anchor both — is the broker's job at the
    moment of rotation; do not silently re-derive old pseudonyms.
    Returns a human-readable instruction string (no secret material).
    """
    if not old_secret or not new_secret or old_secret == new_secret:
        raise ValueError("rotation requires two distinct non-empty secrets")
    return ("rotate audit secret: seal the old chain, anchor it, start a "
            "new chain with the new secret, and write a linking record "
            "carrying the old head hash into the new chain's first entry")


if __name__ == "__main__":
    raise SystemExit(main())
