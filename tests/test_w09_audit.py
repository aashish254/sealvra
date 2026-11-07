"""W09 audit tests (unittest). Fake TEST-ONLY material only, no real keys.

Run from ~/workspace/sealvra-build:  python3 -m unittest tests.test_w09_audit -v
"""
import hashlib
import hmac
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sealvra.audit import (  # noqa: E402
    AuditLog, SecretScrubber, pseudonym, canonical_json, entry_hash_of,
    GENESIS_HASH, AuditUnavailableError, ForeignGrowthError,
    GenesisGuardError, SecretDetectedError,
)

SECRET = b"TEST-ONLY-audit-secret"
FAKE_KEY_ID = "key-0123456789abcdef"


def make_log(testcase):
    tmp = tempfile.mkdtemp(prefix="kh-audit-")
    testcase.addCleanup(shutil.rmtree, tmp, True)
    return AuditLog(Path(tmp), SECRET), Path(tmp)


def dec(log, seq_note=""):
    return log.write_decision(
        pseudonym(SECRET, "sess-aaaaaaaaaaaaaaa1"),
        pseudonym(SECRET, FAKE_KEY_ID),
        "github", "GET", "/repos/x/y", "allow", rule_id="R-1",
        outcome="forwarded", bytes_in=10, bytes_out=20)


class TestChainAndVerify(unittest.TestCase):
    def test_genesis_and_first_run_anchor_mandatory(self):
        log, root = make_log(self)
        self.assertTrue((root / "anchors.jsonl").exists())
        anchors = (root / "anchors.jsonl").read_text().strip().splitlines()
        self.assertEqual(len(anchors), 1)
        a = json.loads(anchors[0])
        self.assertEqual(a["prev_anchor_hash"], GENESIS_HASH)
        self.assertEqual(a["seq"], 1)  # genesis entry anchored
        self.assertTrue((root / "genesis.json").exists())
        # Genesis marker lives OUTSIDE the audit dir.
        self.assertFalse((root / "audit" / "genesis.json").exists())

    def test_schema_exact_and_hash(self):
        log, root = make_log(self)
        e = dec(log)
        self.assertEqual(set(e.keys()), {
            "seq", "ts", "prev_hash", "entry_hash", "event_type",
            "session_pseudonym", "key_pseudonym", "provider", "method",
            "canonical_path", "decision", "rule_id", "outcome", "bytes_in",
            "bytes_out", "approval_id"})
        body = {k: v for k, v in e.items() if k != "entry_hash"}
        self.assertEqual(entry_hash_of(body), e["entry_hash"])

    def test_verify_ok_when_anchored(self):
        log, root = make_log(self)
        dec(log)
        dec(log)
        log.anchor()
        r = log.verify()
        self.assertEqual(r.status, "OK")
        self.assertEqual(r.exit_code, 0)
        self.assertTrue(r.anchored)

    def test_verify_unanchored_amber_exit2(self):
        log, root = make_log(self)
        dec(log)
        # Remove anchor file -> chain valid but unanchored.
        (root / "anchors.jsonl").unlink()
        r = log.verify()
        self.assertEqual(r.status, "UNANCHORED")
        self.assertEqual(r.exit_code, 2)

    def test_tamper_detection(self):
        log, root = make_log(self)
        dec(log)
        dec(log)
        log.anchor()
        p = root / "audit" / "audit.jsonl"
        lines = p.read_text().splitlines()
        obj = json.loads(lines[-1])
        obj["bytes_out"] = 99999  # tamper without fixing the hash
        lines[-1] = canonical_json(obj)
        p.write_text("\n".join(lines) + "\n")
        r = log.verify()
        self.assertEqual(r.status, "TAMPERED")
        self.assertEqual(r.exit_code, 3)

    def test_tail_truncation_unanchored_not_ok_and_anchored_is_tampered(self):
        log, root = make_log(self)
        dec(log)
        dec(log)
        log.anchor()
        p = root / "audit" / "audit.jsonl"
        lines = p.read_text().splitlines()
        p.write_text("\n".join(lines[:-1]) + "\n")  # delete tail entry
        # Without anchor it must NOT report OK (amber, not false OK).
        (root / "anchors.jsonl").unlink()
        r = log.verify()
        self.assertEqual(r.status, "UNANCHORED")
        self.assertNotEqual(r.status, "OK")
        # With the anchor at the higher head, truncation is TAMPERED.
        log2, _ = make_log(self)  # placeholder to keep helper shape
        # Rebuild the same scenario with anchor intact:
        tmp = tempfile.mkdtemp(prefix="kh-audit-")
        self.addCleanup(shutil.rmtree, tmp, True)
        log3 = AuditLog(Path(tmp), SECRET)
        dec(log3)
        dec(log3)
        log3.anchor()
        p3 = Path(tmp) / "audit" / "audit.jsonl"
        ls = p3.read_text().splitlines()
        p3.write_text("\n".join(ls[:-1]) + "\n")
        r3 = log3.verify()
        self.assertEqual(r3.status, "TAMPERED")
        self.assertEqual(r3.exit_code, 3)

    def test_replay_duplicate_seq_rejected(self):
        log, root = make_log(self)
        dec(log)
        p = root / "audit" / "audit.jsonl"
        lines = p.read_text().splitlines()
        # Replay the first entry as an extra line (same seq, same hash).
        p.write_text("\n".join(lines + [lines[0]]) + "\n")
        r = log.verify()
        self.assertEqual(r.status, "TAMPERED")

    def test_anchor_max_height_and_broken_anchor_chain(self):
        log, root = make_log(self)
        dec(log)
        log.anchor()
        dec(log)
        log.anchor()
        dec(log)
        # Anchor file has max seq 3 (genesis anchor seq1 + two more);
        # corrupting the middle anchor line must break verification.
        ap = root / "anchors.jsonl"
        lines = ap.read_text().splitlines()
        mid = json.loads(lines[1])
        mid["seq"] = 99
        lines[1] = canonical_json(mid)
        ap.write_text("\n".join(lines) + "\n")
        r = log.verify()
        self.assertEqual(r.status, "TAMPERED")

    def test_verify_range_seeded_midchain(self):
        log, root = make_log(self)
        for _ in range(5):
            dec(log)
        log.anchor()
        r = log.verify_range(2, 4)
        self.assertEqual(r.status, "OK")
        self.assertEqual(r.first_seq, 2)
        self.assertEqual(r.last_seq, 4)

    def test_wall_time_warning_not_silent(self):
        log, root = make_log(self)
        dec(log)
        dec(log)
        log.anchor()
        # Rewrite second entry's ts far earlier (and fix its hash chain
        # naively is impossible without breaking hashes, so instead check
        # the warning path via a chain that is re-hashed consistently:
        # rebuild a log whose entries are re-hashed with decreasing ts).
        tmp = tempfile.mkdtemp(prefix="kh-audit-")
        self.addCleanup(shutil.rmtree, tmp, True)
        log2 = AuditLog(Path(tmp), SECRET)
        e1 = dec(log2)
        # Craft a second entry with an earlier ts but a valid chain link.
        body = {"seq": e1["seq"] + 1, "ts": "2020-01-01T00:00:00+00:00",
                "prev_hash": e1["entry_hash"], "event_type": "decision",
                "session_pseudonym": "x", "key_pseudonym": "y",
                "provider": "github", "method": "GET", "canonical_path": "/a",
                "decision": "allow", "rule_id": None, "outcome": "forwarded",
                "bytes_in": 0, "bytes_out": 0, "approval_id": None}
        body["entry_hash"] = entry_hash_of(body)
        # v0.2: anchor BEFORE the direct append — anchoring after a
        # foreign append is now refused by the writer (it would
        # legitimise foreign bytes), so the anchor here covers the
        # pre-craft head and the crafted entry is the unanchored tail.
        log2.anchor()
        # Append via a fresh writer is blocked by offset tracking, so
        # write directly and verify (verifier is independent of writer).
        p = Path(tmp) / "audit" / "audit.jsonl"
        with open(p, "a") as f:
            f.write(canonical_json(body) + "\n")
        r = log2.verify()
        # Chain is valid; wall regression must surface as a warning.
        self.assertTrue(any("backwards" in w for w in r.warnings),
                        f"warnings were {r.warnings}")

    def test_torn_tail_ignored_not_tampered(self):
        log, root = make_log(self)
        dec(log)
        log.anchor()
        p = root / "audit" / "audit.jsonl"
        with open(p, "ab") as f:
            f.write(b'{"seq": 99, "partial')
        r = log.verify()
        self.assertIn(r.status, ("OK", "UNANCHORED"))
        self.assertTrue(any("torn" in w for w in r.warnings))


class TestGenesisGuardAndOffset(unittest.TestCase):
    def test_missing_directory_genesis_guard(self):
        log, root = make_log(self)
        dec(log)
        shutil.rmtree(root / "audit")
        with self.assertRaises(GenesisGuardError):
            AuditLog(root, SECRET)
        # And verify() reports MISSING-DIRECTORY exit 3, not OK.
        # verify() needs an instance; use a fresh root-free check via a
        # second AuditLog is impossible (guard), so check the guard
        # itself plus the status mapping through a bare verify on a
        # missing-dir root using a new object created before deletion.
        # (Covered by the guard raise above; status constant checked:)
        from sealvra.audit import EXIT_CODES
        self.assertEqual(EXIT_CODES["MISSING-DIRECTORY"], 3)

    def _bare_log(self, root):
        """Instance without __init__ (needed because __init__ guards)."""
        import threading
        obj = AuditLog.__new__(AuditLog)
        obj.root = Path(root)
        obj.audit_secret = SECRET
        obj.scrubber = None
        obj.audit_dir = Path(root) / "audit"
        obj.live_path = obj.audit_dir / "audit.jsonl"
        obj.archive_dir = obj.audit_dir / "archive"
        obj.anchor_path = Path(root) / "anchors.jsonl"
        obj.genesis_path = Path(root) / "genesis.json"
        obj.ledger_path = Path(root) / "deletion_ledger.jsonl"
        obj.alarm_path = Path(root) / "alarms.jsonl"
        obj.pins_path = Path(root) / "pins.json"
        obj.state_path = Path(root) / "state.json"
        obj.reserve_path = Path(root) / "emergency_reserve.bin"
        obj._lock = threading.RLock()
        obj._halted = False
        obj._halt_reason = ""
        obj._expected_offset = 0
        obj._expected_seq = 0
        obj._prev_hash = GENESIS_HASH
        obj._chain_id = ""
        obj._file_id = None
        obj._fault_next_write = None
        obj._flock_file = None
        return obj

    def test_verify_missing_directory_status(self):
        log, root = make_log(self)
        dec(log)
        shutil.rmtree(root / "audit")
        bare = self._bare_log(root)
        r = bare.verify()
        self.assertEqual(r.status, "MISSING-DIRECTORY")
        self.assertEqual(r.exit_code, 3)

    def test_explicit_recovery_success_path(self):
        log, root = make_log(self)
        dec(log)
        shutil.rmtree(root / "audit")
        bare = self._bare_log(root)
        e = bare.recover_after_deletion(confirm=True)
        self.assertEqual(e["event_type"], "chain_recreated")
        self.assertTrue((root / "audit" / "audit.jsonl").exists())
        # New chain re-anchors (old anchor file preserved alongside).
        self.assertTrue((root / "anchors.jsonl").exists())

    def test_explicit_recovery_only(self):
        log, root = make_log(self)
        dec(log)
        shutil.rmtree(root / "audit")
        with self.assertRaises(GenesisGuardError):
            # recover_after_deletion is a method on a live instance;
            # simulate it by creating an instance on a copy is not
            # possible, so assert the guard API requires confirm via
            # the class-level contract: calling it without confirm on
            # the original (still-open) instance raises.
            log.recover_after_deletion(confirm=False)

    def test_offset_check_halts_on_foreign_growth(self):
        log, root = make_log(self)
        dec(log)
        p = root / "audit" / "audit.jsonl"
        with open(p, "a") as f:
            f.write('{"foreign": true}\n')
        with self.assertRaises(ForeignGrowthError):
            dec(log)
        self.assertTrue(log.halted)
        with self.assertRaises(AuditUnavailableError):
            dec(log)
        # No genuine entry was appended after the foreign bytes.
        self.assertIn('{"foreign": true}', p.read_text())
        self.assertEqual(p.read_text().count('"event_type":"decision"'), 1)
        # Alarm recorded separately.
        self.assertTrue((root / "alarms.jsonl").exists())

    def test_head_recomputed_not_cached(self):
        log, root = make_log(self)
        dec(log)
        h1 = log.head()
        dec(log)
        h2 = log.head()
        self.assertNotEqual(h1["seq"], h2["seq"])
        self.assertEqual(h2["seq"], h1["seq"] + 1)


class TestPseudonymsAndScrubber(unittest.TestCase):
    def test_fingerprint_is_hmac_16hex_not_raw_hash(self):
        fp = pseudonym(SECRET, FAKE_KEY_ID)
        self.assertEqual(len(fp), 16)
        self.assertNotEqual(fp, hashlib.sha256(FAKE_KEY_ID.encode()).hexdigest()[:16])
        self.assertEqual(fp, hmac.new(SECRET, FAKE_KEY_ID.encode(),
                                      hashlib.sha256).hexdigest()[:16])

    def test_no_label_or_key_fragment_in_log(self):
        log, root = make_log(self)
        e = dec(log)
        text = (root / "audit" / "audit.jsonl").read_text()
        self.assertNotIn("my-secret-label", text)
        self.assertNotIn(FAKE_KEY_ID, text)
        # Pseudonym is present, raw id is not.
        self.assertIn(pseudonym(SECRET, FAKE_KEY_ID), text)

    def test_scrubber_catches_9_to_11_char_fragments(self):
        scrub = SecretScrubber()
        key = "TEST-ONLY-abcdefghij"  # 20 chars; prefix is 10 chars
        scrub.add_secret(key)
        # 9, 10 and 11-char fragments must all be caught (old
        # 12-char windows missed them).
        self.assertTrue(scrub.contains_secret(key[10:19]))  # 9 chars
        self.assertTrue(scrub.contains_secret(key[10:20]))  # 10 chars
        self.assertTrue(scrub.contains_secret(key[9:20]))   # 11 chars
        # Short fake keys of 9-11 chars themselves are caught whole.
        for short in ("TEST-ONLY-1", "TEST-ONLY-12", "TEST-ONLY-123"):
            s2 = SecretScrubber()
            s2.add_secret(short)
            self.assertTrue(s2.contains_secret(short))

    def test_scrubber_blocks_write_and_retired_stays(self):
        scrub = SecretScrubber()
        secret = "TEST-ONLY-abcdefghij"
        scrub.add_secret(secret)
        scrub.retire_secret(secret)  # retire must NOT drop protection
        log, root = make_log(self)
        log.scrubber = scrub
        with self.assertRaises(SecretDetectedError):
            log.write_decision(
                pseudonym(SECRET, "sess-1"), pseudonym(SECRET, FAKE_KEY_ID),
                "github", "GET", "/x/" + secret[5:16], "allow")
        # The refused line never reached the file.
        self.assertNotIn(secret[5:16], (root / "audit" / "audit.jsonl").read_text())

    def test_no_key_material_in_any_emitted_line(self):
        scrub = SecretScrubber()
        scrub.add_secret("TEST-ONLY-abcdefghij")
        log, root = make_log(self)
        log.scrubber = scrub
        dec(log)
        for ln in (root / "audit" / "audit.jsonl").read_text().splitlines():
            self.assertFalse(scrub.contains_secret(ln))

    def test_csv_formula_neutralised(self):
        log, root = make_log(self)
        log.write_decision(
            pseudonym(SECRET, "sess-1"), pseudonym(SECRET, FAKE_KEY_ID),
            "github", "GET", "/x", "allow", outcome="forwarded")
        # Directly craft a row via canonical_path starting with '=' by
        # writing an event whose path is formula-shaped (paths are
        # cleaned of controls but '=' survives, as it should).
        log.write_event("decision", "s", "k", "github", "GET",
                        "=cmd|/c calc", "allow", None, "forwarded")
        csv_text = log.export_csv()
        self.assertIn("'=cmd", csv_text)
        self.assertNotIn("\n=cmd", csv_text)


class TestRetentionClockGateSealQuarantine(unittest.TestCase):
    def test_seal_seeded_front_truncation_verifies(self):
        log, root = make_log(self)
        dec(log)
        dec(log)
        seal = log.seal_live(reason="test")
        self.assertIsNotNone(seal)
        dec(log)
        log.anchor()
        # Delete the sealed segment but keep its seal sidecar: the
        # surviving chain is front-truncated yet seal-seeded.
        seg = root / "audit" / "archive" / f"seg-{seal['first_seq']}-{seal['last_seq']}.jsonl"
        seg.unlink()
        r = log.verify()
        # First surviving entry is the post-seal entry (seq 4) whose
        # prev points at the sealed head; seal sidecar seeds it.
        # Note: segment_sealed entry itself is in the live file, so
        # verification walks live entries from the seal.
        self.assertEqual(r.status, "OK")

    def test_unseeded_front_truncation_is_tampered(self):
        log, root = make_log(self)
        dec(log)
        dec(log)
        seal = log.seal_live(reason="test")
        dec(log)
        log.anchor()
        seg = root / "audit" / "archive" / f"seg-{seal['first_seq']}-{seal['last_seq']}.jsonl"
        seg.unlink()
        (seg.with_suffix(".seal.json")).unlink()  # no seed left
        # Also remove the live segment_sealed entry's predecessor link
        # by truncating live to only the newest decision: emulate by
        # deleting the whole live file content except last line.
        p = root / "audit" / "audit.jsonl"
        lines = p.read_text().splitlines()
        p.write_text(lines[-1] + "\n")
        r = log.verify()
        self.assertEqual(r.status, "TAMPERED")

    def test_retention_clock_gate_blocks_forward_jump(self):
        log, root = make_log(self)
        dec(log)
        seal = log.seal_live(reason="test")
        # Pretend "now" is 13 months after the last observed wall time.
        import time as _time
        future = _time.time() + 400 * 86400
        report = log.prune(now=future, confirm_clock=False)
        self.assertIsNotNone(report["blocked"])
        # The sealed segment must still exist (evidence not destroyed).
        seg = root / "audit" / "archive" / f"seg-{seal['first_seq']}-{seal['last_seq']}.jsonl"
        self.assertTrue(seg.exists())
        # With explicit human confirmation, pruning proceeds to summary.
        report2 = log.prune(now=future, confirm_clock=True)
        self.assertIsNone(report2["blocked"])
        self.assertFalse(seg.exists())
        summary = seg.with_suffix(".summary.json")
        self.assertTrue(summary.exists())
        self.assertNotIn("decision", summary.read_text().replace("entry_count", ""))
        # Deletion ledger permanently records the seal hash.
        ledger = (root / "deletion_ledger.jsonl").read_text()
        self.assertIn(seal["seal_hash"], ledger)

    def test_pin_blocks_prune(self):
        log, root = make_log(self)
        dec(log)
        seal = log.seal_live(reason="test")
        seg_name = f"seg-{seal['first_seq']}-{seal['last_seq']}.jsonl"
        log.pin(seg_name, reason="incident")
        import time as _time
        report = log.prune(now=_time.time() + 400 * 86400, confirm_clock=True)
        self.assertIn(seg_name, report["skipped_pinned"])
        self.assertTrue((root / "audit" / "archive" / seg_name).exists())

    def test_quarantine_deletion_immediate_with_both_confirmations(self):
        log, root = make_log(self)
        dec(log)
        seal = log.seal_live(reason="test")
        seg_name = f"seg-{seal['first_seq']}-{seal['last_seq']}.jsonl"
        with self.assertRaises(ValueError):
            log.quarantine_delete(seg_name, rotation_confirmed=True,
                                  os_auth_confirmed=False)
        self.assertTrue((root / "audit" / "archive" / seg_name).exists())
        out = log.quarantine_delete(seg_name, rotation_confirmed=True,
                                    os_auth_confirmed=True)
        self.assertEqual(out["seal_hash"], seal["seal_hash"])
        self.assertFalse((root / "audit" / "archive" / seg_name).exists())
        self.assertIn(seal["seal_hash"], (root / "deletion_ledger.jsonl").read_text())

    def test_pre_wipe_entry_before_deletion(self):
        log, root = make_log(self)
        dec(log)
        e = log.write_pre_wipe()
        self.assertEqual(e["event_type"], "vault_wipe")
        # Entry is fsynced in the file before any caller deletion.
        self.assertIn("vault_wipe", (root / "audit" / "audit.jsonl").read_text())

    def test_kill_backfill(self):
        log, root = make_log(self)
        dec(log)
        out = log.reconcile_denylist([{
            "session_pseudonym": pseudonym(SECRET, "sess-dead"),
            "key_pseudonym": pseudonym(SECRET, FAKE_KEY_ID),
            "provider": "github"}])
        self.assertEqual(out[0]["event_type"], "kill_backfill")
        self.assertEqual(out[0]["outcome"], "recovered_backfill")

    def test_disk_full_fail_closed_via_fault(self):
        log, root = make_log(self)
        dec(log)
        log.inject_fault_next_write(OSError(28, "No space left on device"))
        with self.assertRaises(AuditUnavailableError):
            dec(log)
        # Reserve file exists (preallocated emergency space).
        self.assertTrue((root / "emergency_reserve.bin").exists())

    def test_orphan_reconciliation_ignores_matched_outcome(self):
        log, root = make_log(self)
        sp = pseudonym(SECRET, "sess-1")
        kp = pseudonym(SECRET, FAKE_KEY_ID)
        log.write_decision(sp, kp, "github", "GET", "/repos/x", "allow")
        log.write_event("session_create", sp, kp, "github", "", "", "")
        log.write_outcome(sp, kp, "github", "GET", "/repos/x", "allow",
                          outcome="success")
        self.assertEqual(log.reconcile_orphan_decisions(), [])
        # A decision with no matching outcome is marked unknown.
        log.write_decision(sp, kp, "github", "GET", "/repos/y", "allow")
        out = log.reconcile_orphan_decisions()
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["outcome"], "unknown")

    def test_decision_is_synchronous_and_fsynced(self):
        log, root = make_log(self)
        e = dec(log)
        # Immediately readable from disk after the call returns: the
        # proxy may forward only after this returns, so no queueing.
        text = (root / "audit" / "audit.jsonl").read_text()
        self.assertIn(e["entry_hash"], text)


class TestV02AuditHardening(unittest.TestCase):
    """v0.2 (W15) additions: re-audit against f13.

    Covers: file-order verification (no sorting), genesis/rebirth
    guards, writer tail checks (incl. same-size rewrites), anchor
    guards, seal-bridge integrity, external-anchor rollback,
    retention single-schedule semantics, quarantine crash safety,
    pre-wipe failure honesty, and the standalone verifier core.
    """

    def _bare_log(self, root):
        import threading
        obj = AuditLog.__new__(AuditLog)
        obj.root = Path(root)
        obj.audit_secret = SECRET
        obj.scrubber = None
        obj.audit_dir = Path(root) / "audit"
        obj.live_path = obj.audit_dir / "audit.jsonl"
        obj.archive_dir = obj.audit_dir / "archive"
        obj.anchor_path = Path(root) / "anchors.jsonl"
        obj.genesis_path = Path(root) / "genesis.json"
        obj.ledger_path = Path(root) / "deletion_ledger.jsonl"
        obj.alarm_path = Path(root) / "alarms.jsonl"
        obj.pins_path = Path(root) / "pins.json"
        obj.state_path = Path(root) / "state.json"
        obj.reserve_path = Path(root) / "emergency_reserve.bin"
        obj._lock = threading.RLock()
        obj._halted = False
        obj._halt_reason = ""
        obj._expected_offset = 0
        obj._expected_seq = 0
        obj._prev_hash = GENESIS_HASH
        obj._chain_id = ""
        obj._file_id = None
        obj._fault_next_write = None
        obj._flock_file = None
        return obj

    def _files(self, root):
        return sorted(str(p.relative_to(root)) for p in Path(root).rglob("*") if p.is_file())

    # -- verification honesty -------------------------------------------
    def test_reordered_lines_are_tampered_not_sorted_clean(self):
        log, root = make_log(self)
        dec(log)
        dec(log)
        dec(log)
        log.anchor()
        p = root / "audit" / "audit.jsonl"
        lines = p.read_text().splitlines()
        p.write_text("\n".join([lines[0], lines[1], lines[3], lines[2]]) + "\n")
        r = log.verify()
        self.assertEqual(r.status, "TAMPERED")

    def test_truncation_to_anchor_head_is_ok_but_warned(self):
        # Inherent residual, stated honestly: truncating exactly to
        # an anchor head is indistinguishable from "no new entries".
        # It must still carry the head-equals-anchor warning, never a
        # bare clean pass.
        log, root = make_log(self)
        dec(log)
        dec(log)
        log.anchor()
        dec(log)
        p = root / "audit" / "audit.jsonl"
        lines = p.read_text().splitlines()
        p.write_text("\n".join(lines[:-1]) + "\n")
        r = log.verify()
        self.assertEqual(r.status, "OK")
        self.assertTrue(any("equals newest anchor" in w for w in r.warnings))

    def test_external_anchor_catches_rollback_and_truncation(self):
        log, root = make_log(self)
        dec(log)
        dec(log)
        log.anchor()
        external = root / "external-anchors.jsonl"
        external.write_text((root / "anchors.jsonl").read_text())
        p = root / "audit" / "audit.jsonl"
        lines = p.read_text().splitlines()
        p.write_text("\n".join(lines[:-1]) + "\n")  # rollback by one entry
        r = log.verify(anchor_path=external)
        self.assertEqual(r.status, "TAMPERED")
        # Without any anchor the same truncation is UNANCHORED, never OK.
        (root / "anchors.jsonl").unlink()
        r2 = log.verify()
        self.assertEqual(r2.status, "UNANCHORED")
        self.assertNotEqual(r2.status, "OK")

    def test_corrupt_seal_bridge_is_tampered(self):
        log, root = make_log(self)
        dec(log)
        seal = log.seal_live(reason="test")
        dec(log)
        log.anchor()
        sealpath = root / "audit" / "archive" / f"seg-{seal['first_seq']}-{seal['last_seq']}.seal.json"
        d = json.loads(sealpath.read_text())
        d["last_entry_hash"] = "0" * 64  # breaks the seal_hash, not just the seed
        sealpath.write_text(canonical_json(d) + "\n")
        r = log.verify()
        self.assertEqual(r.status, "TAMPERED")

    def test_genesis_missing_with_entries_is_tampered(self):
        from sealvra.audit import verify_audit_directory
        log, root = make_log(self)
        dec(log)
        log.anchor()
        (root / "genesis.json").unlink()
        r = verify_audit_directory(root)
        self.assertEqual(r.status, "TAMPERED")
        self.assertTrue(any("genesis" in e for e in r.errors))

    def test_anchor_chain_id_mismatch_is_tampered(self):
        from sealvra.audit import verify_audit_directory
        log, root = make_log(self)
        dec(log)
        log.anchor()
        ap = root / "anchors.jsonl"
        lines = [json.loads(ln) for ln in ap.read_text().splitlines()]
        lines[-1]["chain_id"] = "chain-other"
        ap.write_text("\n".join(canonical_json(a) for a in lines) + "\n")
        r = verify_audit_directory(root)
        self.assertEqual(r.status, "TAMPERED")

    def test_anchor_seq_regression_is_tampered(self):
        from sealvra.audit import verify_audit_directory, GENESIS_HASH as GH
        log, root = make_log(self)
        dec(log)
        log.anchor()
        head = log.head()
        def _anchor(seq, prev, entry_hash):
            body = {"chain_id": log.chain_id, "seq": seq, "entry_hash": entry_hash,
                    "ts": "2026-01-01T00:00:00+00:00", "prev_anchor_hash": prev}
            body["anchor_hash"] = hashlib.sha256(canonical_json(body).encode()).hexdigest()
            return body
        a1 = _anchor(1, GH, head["entry_hash"])
        a2 = _anchor(3, a1["anchor_hash"], head["entry_hash"])
        a3 = _anchor(2, a2["anchor_hash"], head["entry_hash"])  # regression, valid chain links
        (root / "anchors.jsonl").write_text(
            "\n".join(canonical_json(a) for a in (a1, a2, a3)) + "\n")
        r = verify_audit_directory(root)
        self.assertEqual(r.status, "TAMPERED")

    def test_verify_range_end_missing_is_tampered(self):
        log, root = make_log(self)
        for _ in range(5):
            dec(log)
        log.anchor()
        r = log.verify_range(2, 99)
        self.assertEqual(r.status, "TAMPERED")
        self.assertTrue(any("end missing" in e for e in r.errors))

    # -- rebirth guards ---------------------------------------------------
    def test_anchors_only_rebirth_refused(self):
        log, root = make_log(self)
        dec(log)
        shutil.rmtree(root / "audit")
        (root / "genesis.json").unlink()
        # Anchors (plus state/ledger/reserve) survive: fresh start refused.
        with self.assertRaises(GenesisGuardError):
            AuditLog(root, SECRET)
        # And the anchor file was NOT chained onto by a reborn log.
        self.assertEqual(len((root / "anchors.jsonl").read_text().splitlines()), 1)

    def test_live_emptied_without_seal_refused_no_seq_reuse(self):
        log, root = make_log(self)
        dec(log)
        (root / "audit" / "audit.jsonl").write_text("")
        with self.assertRaises(GenesisGuardError):
            AuditLog(root, SECRET)

    def test_live_emptied_with_seal_continues_from_seal(self):
        # The one legitimate empty-live reopen: the seal crash window
        # (seal written, live truncated, segment_sealed entry lost).
        log, root = make_log(self)
        dec(log)
        seal = log.seal_live(reason="test")
        (root / "audit" / "audit.jsonl").write_text("")
        log2 = AuditLog(root, SECRET)
        e = dec(log2)
        self.assertEqual(e["seq"], seal["last_seq"] + 1)
        self.assertEqual(e["prev_hash"], seal["last_entry_hash"])
        log2.anchor()
        self.assertEqual(log2.verify().status, "OK")

    def test_recovery_renames_old_anchors_aside(self):
        log, root = make_log(self)
        dec(log)
        old_chain = log.chain_id
        shutil.rmtree(root / "audit")
        bare = self._bare_log(root)
        e = bare.recover_after_deletion(confirm=True)
        self.assertEqual(e["event_type"], "chain_recreated")
        new_anchors = [json.loads(ln) for ln in (root / "anchors.jsonl").read_text().splitlines()]
        self.assertEqual(new_anchors[-1]["chain_id"], bare.chain_id)
        self.assertNotEqual(bare.chain_id, old_chain)
        preserved = list(root.glob("anchors-chain-*.jsonl")) + list(root.glob("anchors-prev.jsonl"))
        self.assertTrue(preserved, "old anchor file must survive the recovery, renamed aside")
        log2 = AuditLog(root, SECRET)
        self.assertEqual(log2.verify().status, "OK")

    # -- writer offset / tail checks --------------------------------------
    def test_same_size_body_rewrite_halts_writer(self):
        log, root = make_log(self)
        dec(log)
        p = root / "audit" / "audit.jsonl"
        lines = p.read_text().splitlines()
        obj = json.loads(lines[-1])
        obj["bytes_out"] = 21  # same width as 20: file size unchanged
        lines[-1] = canonical_json(obj)
        p.write_text("\n".join(lines) + "\n")
        self.assertEqual(p.stat().st_size, log._expected_offset)
        with self.assertRaises(ForeignGrowthError):
            dec(log)
        self.assertTrue(log.halted)

    def test_seal_of_poisoned_live_refused(self):
        log, root = make_log(self)
        dec(log)
        p = root / "audit" / "audit.jsonl"
        with open(p, "a") as f:
            f.write('{"foreign": true}\n')
        with self.assertRaises(AuditUnavailableError):
            log.seal_live(reason="test")
        self.assertEqual(list((root / "audit" / "archive").glob("*.jsonl")), [])

    def test_anchor_on_corrupt_anchor_file_refused_not_forked(self):
        log, root = make_log(self)
        dec(log)
        ap = root / "anchors.jsonl"
        before = ap.read_text()
        with open(ap, "a") as f:
            f.write('{"broken json\n')
        with self.assertRaises(AuditUnavailableError):
            log.anchor()
        self.assertEqual(ap.read_text(), before + '{"broken json\n')

    def test_anchor_on_cross_chain_file_refused(self):
        log, root = make_log(self)
        dec(log)
        ap = root / "anchors.jsonl"
        lines = [json.loads(ln) for ln in ap.read_text().splitlines()]
        lines[-1]["chain_id"] = "chain-other"
        ap.write_text("\n".join(canonical_json(a) for a in lines) + "\n")
        with self.assertRaises(AuditUnavailableError):
            log.anchor()

    # -- retention: one schedule ------------------------------------------
    def test_prune_writes_no_spurious_clock_confirmed(self):
        import time as _time
        log, root = make_log(self)
        dec(log)
        log.prune(now=_time.time(), confirm_clock=True)
        text = (root / "audit" / "audit.jsonl").read_text()
        self.assertNotIn("clock_confirmed", text)

    def test_prune_backwards_clock_blocked(self):
        log, root = make_log(self)
        dec(log)
        report = log.prune(now=0, confirm_clock=False)
        self.assertIsNotNone(report["blocked"])

    def test_prune_unparseable_seal_never_expires(self):
        log, root = make_log(self)
        dec(log)
        seal = log.seal_live(reason="test")
        seg = root / "audit" / "archive" / f"seg-{seal['first_seq']}-{seal['last_seq']}.jsonl"
        sealpath = seg.with_suffix(".seal.json")
        d = json.loads(sealpath.read_text())
        d["sealed_at"] = "not-a-date"
        sealpath.write_text(canonical_json(d) + "\n")
        report = log.prune(confirm_clock=False)
        self.assertTrue(seg.exists())
        self.assertIn(seg.name, report["skipped_unparseable"])

    def test_archive_clock_starts_at_sealing_not_entry(self):
        import time as _time
        # Entries 100 days old, seal fresh: NOT summarised (archive
        # year has not run since sealing).
        log, root = make_log(self)
        dec(log)
        seal = log.seal_live(reason="test")
        seg = root / "audit" / "archive" / f"seg-{seal['first_seq']}-{seal['last_seq']}.jsonl"
        report = log.prune(now=_time.time() + 100 * 86400, confirm_clock=True)
        self.assertEqual(report["summarised"], [])
        self.assertTrue(seg.exists())
        # Seal 400 days old, entries minutes old: summarised (the
        # archive year runs from sealing, not from entry creation).
        sealpath = seg.with_suffix(".seal.json")
        d = json.loads(sealpath.read_text())
        from datetime import datetime, timezone, timedelta
        d["sealed_at"] = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
        body = {k: v for k, v in d.items() if k != "seal_hash"}
        d["seal_hash"] = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        sealpath.write_text(canonical_json(d) + "\n")
        report2 = log.prune(confirm_clock=False)
        self.assertIn(seg.name, report2["summarised"])
        self.assertFalse(seg.exists())
        self.assertTrue(seg.with_suffix(".summary.json").exists())

    def test_entry_count_alone_never_triggers_retention(self):
        import time as _time
        log, root = make_log(self)
        for _ in range(30):
            dec(log)
        report = log.prune(now=_time.time(), confirm_clock=False)
        self.assertIsNone(report["sealed"])
        self.assertEqual(report["summarised"], [])

    # -- quarantine deletion class -----------------------------------------
    def test_quarantine_uses_intent_then_confirmation(self):
        log, root = make_log(self)
        dec(log)
        seal = log.seal_live(reason="test")
        seg_name = f"seg-{seal['first_seq']}-{seal['last_seq']}.jsonl"
        out = log.quarantine_delete(seg_name, rotation_confirmed=True, os_auth_confirmed=True)
        self.assertEqual(out["seal_hash"], seal["seal_hash"])
        ledger = (root / "deletion_ledger.jsonl").read_text()
        self.assertIn('"kind":"quarantine_intent"', ledger)
        self.assertIn('"kind":"quarantine_deleted"', ledger)
        self.assertFalse((root / "audit" / "archive" / seg_name).exists())

    def test_quarantine_live_segment_requires_seal_first(self):
        log, root = make_log(self)
        dec(log)
        with self.assertRaises(FileNotFoundError):
            log.quarantine_delete("audit.jsonl", True, True)

    def test_quarantine_without_seal_records_last_entry_hash(self):
        log, root = make_log(self)
        e = dec(log)
        seal = log.seal_live(reason="test")
        seg = root / "audit" / "archive" / f"seg-{seal['first_seq']}-{seal['last_seq']}.jsonl"
        (seg.with_suffix(".seal.json")).unlink()  # seal lost: ledger must not go empty-hash
        out = log.quarantine_delete(seg.name, True, True)
        self.assertEqual(out["seal_hash"], e["entry_hash"])
        self.assertNotEqual(out["seal_hash"], "")

    def test_quarantine_crash_intent_completed_by_reconcile(self):
        log, root = make_log(self)
        dec(log)
        seal = log.seal_live(reason="test")
        seg_name = f"seg-{seal['first_seq']}-{seal['last_seq']}.jsonl"
        log._ledger_append({"kind": "quarantine_intent", "segment": seg_name,
                            "seal_hash": seal["seal_hash"], "ts": "2026-01-01T00:00:00+00:00"})
        actions = log.reconcile_deletions()
        self.assertFalse((root / "audit" / "archive" / seg_name).exists())
        self.assertTrue(any(seg_name in a for a in actions))
        self.assertIn('"kind":"quarantine_deleted"', (root / "deletion_ledger.jsonl").read_text())

    # -- pre-wipe honesty ----------------------------------------------------
    def test_pre_wipe_sink_unreachable_outcome(self):
        log, root = make_log(self)
        dec(log)
        e = log.write_pre_wipe(sink_unreachable=True)
        self.assertEqual(e["outcome"], "initiated_sink_unreachable")
        self.assertIn("initiated_sink_unreachable", (root / "audit" / "audit.jsonl").read_text())

    def test_attempt_pre_wipe_reports_failure_honestly(self):
        log, root = make_log(self)
        dec(log)
        log.inject_fault_next_write(OSError(28, "No space left on device"))
        result = log.attempt_pre_wipe()
        self.assertFalse(result["recorded"])
        self.assertIsNotNone(result["failure"])
        self.assertTrue((root / "alarms.jsonl").exists())
        self.assertIn("pre_wipe_record_failed", (root / "alarms.jsonl").read_text())
        # The strict path still raises: a failed record never authorises a wipe.
        log.inject_fault_next_write(OSError(28, "No space left on device"))
        with self.assertRaises(AuditUnavailableError):
            log.write_pre_wipe()

    # -- standalone verifier ---------------------------------------------------
    def test_standalone_verifier_agrees_and_writes_nothing(self):
        from sealvra.audit import verify_audit_directory
        log, root = make_log(self)
        dec(log)
        dec(log)
        log.anchor()
        before = self._files(root)
        live_before = (root / "audit" / "audit.jsonl").read_bytes()
        r1 = log.verify()
        r2 = verify_audit_directory(root)
        self.assertEqual((r1.status, r1.exit_code), (r2.status, r2.exit_code))
        self.assertEqual(r2.status, "OK")
        self.assertEqual(self._files(root), before)
        self.assertEqual((root / "audit" / "audit.jsonl").read_bytes(), live_before)
        # Tampered: both agree, standalone still writes nothing.
        p = root / "audit" / "audit.jsonl"
        lines = p.read_text().splitlines()
        obj = json.loads(lines[-1])
        obj["bytes_out"] = 99999
        lines[-1] = canonical_json(obj)
        p.write_text("\n".join(lines) + "\n")
        self.assertEqual(verify_audit_directory(root).status, "TAMPERED")
        self.assertEqual(log.verify().status, "TAMPERED")

    def test_standalone_missing_directory_writes_nothing(self):
        from sealvra.audit import verify_audit_directory
        log, root = make_log(self)
        dec(log)
        shutil.rmtree(root / "audit")
        before = self._files(root)
        r = verify_audit_directory(root)
        self.assertEqual(r.status, "MISSING-DIRECTORY")
        self.assertEqual(r.exit_code, 3)
        self.assertEqual(self._files(root), before)

    def test_standalone_verifier_works_on_halted_writer_log(self):
        from sealvra.audit import verify_audit_directory
        log, root = make_log(self)
        dec(log)
        log.anchor()
        p = root / "audit" / "audit.jsonl"
        with open(p, "a") as f:
            f.write('{"foreign": true}\n')
        with self.assertRaises(ForeignGrowthError):
            dec(log)
        self.assertTrue(log.halted)
        # Verifier needs no writer state: it still reports, honestly.
        self.assertEqual(verify_audit_directory(root).status, "TAMPERED")

    def test_standalone_cli_exit_codes(self):
        import subprocess
        build_root = str(Path(__file__).resolve().parent.parent)
        log, root = make_log(self)
        dec(log)
        log.anchor()
        ok = subprocess.run([sys.executable, "-m", "sealvra.audit", "--root", str(root)],
                            cwd=build_root, capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0)
        self.assertTrue(ok.stdout.startswith("OK"))
        p = root / "audit" / "audit.jsonl"
        lines = p.read_text().splitlines()
        obj = json.loads(lines[-1])
        obj["bytes_out"] = 99999
        lines[-1] = canonical_json(obj)
        p.write_text("\n".join(lines) + "\n")
        bad = subprocess.run([sys.executable, "-m", "sealvra.audit", "--root", str(root)],
                             cwd=build_root, capture_output=True, text=True)
        self.assertEqual(bad.returncode, 3)
        self.assertTrue(bad.stdout.startswith("TAMPERED"))


if __name__ == "__main__":
    unittest.main()
