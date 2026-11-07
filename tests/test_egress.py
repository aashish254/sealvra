"""Egress / privacy tests (W17, v0.2) — re-audit against f11.

Covers, with real assertions (not "no crash"):
  * update-check payload: version + OS + arch and NOTHING else
    (f11 F-C1, v3 N-L3); rollout buckets client-side, bucket
    number only (or time-based, i.e. no extra field at all).
  * update-check default: f16 recommendation recorded as a
    recommendation ONLY; owner decision OD-13 undecided (f11 F-C6).
  * pack-update egress path: packs ship inside product updates
    only — no separate connection, no per-pack identifier
    (f11 F-K1, v3 N-L4).
  * company-ledger rows: OUT OF SCOPE in the v0.2 personal
    edition — recorded as out of scope, never as passing
    (f11 F-J1, v3 N-L6).
  * crash scrubber: hash-only matching (f11 F-E1, v3 N-L8);
    key-add-time wiring and locked-keychain fail-closed are
    NOT-CLOSED gaps, marked as expected failures with the exact
    owner fix in their docstrings — they are not claimed passing.

All fixtures are clearly fake TEST-ONLY values. No network is
touched: the payload builder is pure, and no test opens a socket.
"""

import base64
import os
import sys
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sealvra import cli
from sealvra.audit import SecretScrubber, SecretDetectedError

FAKE_SECRET = "TEST-ONLY-egress-scrubber-secret-12345"
BUILD_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _allowlist_row(name):
    for row in cli.UPDATE_EGRESS_ALLOWLIST:
        if row["name"] == name:
            return row
    raise AssertionError(f"allowlist row missing: {name}")


class TestUpdateCheckPayload(unittest.TestCase):
    def test_base_payload_is_exactly_three_fields(self):
        payload = cli.build_update_check_payload("0.2.0", "Darwin", "arm64")
        self.assertEqual(payload, {"version": "0.2.0", "os": "macos", "arch": "arm64"})

    def test_payload_has_no_identity_or_channel_or_time_field(self):
        payload = cli.build_update_check_payload("0.2.0", "Linux", "x86_64")
        forbidden = {
            "device_id", "installation_id", "install_id", "user_id",
            "channel", "timestamp", "day", "date", "uuid", "fingerprint",
            "machine_id", "stable_hash",
        }
        self.assertFalse(forbidden & set(payload))
        blob = repr(payload).lower()
        for word in ("device", "install", "uuid", "channel"):
            self.assertNotIn(word, blob)

    def test_os_and_arch_are_coarse_families_only(self):
        self.assertEqual(
            cli.build_update_check_payload("1", "Windows", "AMD64")["os"], "windows")
        self.assertEqual(
            cli.build_update_check_payload("1", "Windows", "AMD64")["arch"], "x86_64")
        self.assertEqual(
            cli.build_update_check_payload("1", "Linux", "aarch64")["arch"], "arm64")
        # Unknown/exotic platform strings collapse, never leak verbatim.
        weird = cli.build_update_check_payload("1", "SomeOS 99.2 (build 7)", "riscv-9000")
        self.assertEqual(weird["os"], "other")
        self.assertEqual(weird["arch"], "other")
        self.assertNotIn("99.2", repr(weird))

    def test_default_payload_on_this_machine_is_three_fields(self):
        payload = cli.default_update_check_payload()
        self.assertEqual(set(payload), {"version", "os", "arch"})
        self.assertEqual(payload["version"], cli.VERSION)

    def test_empty_version_rejected(self):
        with self.assertRaises(Exception):
            cli.build_update_check_payload("", "Linux", "x86_64")

    def test_rollout_bucket_is_client_side_and_number_only(self):
        bucket = cli.client_rollout_bucket("TEST-ONLY-local-seed-1")
        self.assertIsInstance(bucket, int)
        self.assertTrue(0 <= bucket < cli.UPDATE_CHECK_ROLLOUT_BUCKETS)
        # Deterministic for the same local seed, and the payload
        # carries the number — never the seed, never its hash.
        self.assertEqual(bucket, cli.client_rollout_bucket("TEST-ONLY-local-seed-1"))
        payload = cli.build_update_check_payload(
            "0.2.0", "Linux", "x86_64", rollout_bucket=bucket)
        self.assertEqual(
            set(payload), {"version", "os", "arch", "rollout_bucket"})
        self.assertEqual(payload["rollout_bucket"], bucket)
        self.assertNotIn("TEST-ONLY-local-seed-1", repr(payload))
        import hashlib
        self.assertNotIn(
            hashlib.sha256(b"TEST-ONLY-local-seed-1").hexdigest(), repr(payload))

    def test_rollout_bucket_rejects_bool_and_out_of_range(self):
        for bad in (True, -1, cli.UPDATE_CHECK_ROLLOUT_BUCKETS, "42", 1.5):
            with self.assertRaises(Exception):
                cli.build_update_check_payload(
                    "0.2.0", "Linux", "x86_64", rollout_bucket=bad)

    def test_time_based_rollout_needs_no_extra_field(self):
        # Time-based rollout is decided locally from the calendar;
        # it adds no field to the payload at all.
        payload = cli.build_update_check_payload("0.2.0", "Linux", "x86_64")
        self.assertEqual(set(payload), {"version", "os", "arch"})

    def test_payload_builder_makes_no_network_call(self):
        # Static check: the CLI payload section performs no I/O.
        # (The builder itself is also exercised above with no
        # network available to it.)
        with open(os.path.join(BUILD_ROOT, "sealvra", "cli.py"),
                  encoding="utf-8") as handle:
            source = handle.read()
        for token in ("urlopen", "http.client", "requests.", "socket.create"):
            self.assertNotIn(token, source)


class TestUpdateCheckDefault(unittest.TestCase):
    def test_default_is_undecided_pending_owner_confirmation(self):
        resolved = cli.resolve_update_check_default()
        self.assertIsNone(resolved["default"])
        self.assertIsNone(cli.UPDATE_CHECK_DEFAULT)
        self.assertIn("OD-13", resolved["status"])
        self.assertIn("pending", resolved["status"])

    def test_recommendation_is_recorded_but_not_the_decision(self):
        # f16 recommends ON with a clear off switch. That is a
        # recommendation, and the test pins it as one: the decided
        # default must stay None until the owner confirms OD-13.
        self.assertEqual(cli.UPDATE_CHECK_RECOMMENDED_DEFAULT, "on")
        self.assertIsNot(cli.UPDATE_CHECK_RECOMMENDED_DEFAULT,
                         cli.UPDATE_CHECK_DEFAULT)


class TestPackUpdatePath(unittest.TestCase):
    def test_pack_update_has_no_separate_connection(self):
        row = _allowlist_row("pack-update")
        self.assertFalse(row["separate_connection"])
        self.assertIsNone(row["per_pack_identifier"])

    def test_pack_update_rides_product_updates_only(self):
        row = _allowlist_row("pack-update")
        text = (row["trigger"] + " " + row["destination"] + " " + row["payload"]).lower()
        self.assertIn("inside", text)
        self.assertIn("product update", text)

    def test_update_check_and_download_rows_are_allowlisted(self):
        check = _allowlist_row("update-check")
        self.assertIn("version", check["payload"])
        download = _allowlist_row("update-download")
        # The row forbids per-client URLs; the wording says so
        # explicitly ("no per-client signed URL tokens").
        self.assertIn("no per-client", download["payload"].lower())
        self.assertIn("generic", download["payload"].lower())

    def test_docs_name_the_same_chosen_pack_path(self):
        with open(os.path.join(BUILD_ROOT, "docs", "security-model.md"),
                  encoding="utf-8") as handle:
            text = handle.read()
        egress = text.split("## Egress and privacy", 1)[1]
        self.assertIn("ship inside product updates only", egress)
        self.assertIn("no separate pack fetch", egress)
        self.assertIn("no per-pack identifier", egress)


class TestCompanyLedgerOutOfScope(unittest.TestCase):
    def test_docs_record_company_rows_as_out_of_scope_never_passing(self):
        with open(os.path.join(BUILD_ROOT, "docs", "security-model.md"),
                  encoding="utf-8") as handle:
            text = handle.read()
        egress = " ".join(
            text.split("## Egress and privacy", 1)[1].split())
        self.assertIn("OUT OF SCOPE", egress)
        self.assertIn("not verified, not passing", egress)
        self.assertIn("company-edition column", egress)

    def test_no_company_relay_sender_exists_in_tree(self):
        # The personal edition must not contain an org relay
        # sender that the docs could be misread as covering.
        for name in os.listdir(os.path.join(BUILD_ROOT, "sealvra")):
            self.assertNotIn("company", name)
            self.assertNotIn("relay", name)


class TestCrashScrubberHashOnly(unittest.TestCase):
    def test_scrubber_stores_hashes_not_secret_values(self):
        scrubber = SecretScrubber()
        scrubber.add_secret(FAKE_SECRET)
        stored = repr(scrubber.__dict__)
        self.assertNotIn(FAKE_SECRET, stored)
        self.assertNotIn("TEST-ONLY-egress", stored)
        for window_hash in scrubber._windows:
            self.assertNotIn(FAKE_SECRET, window_hash)

    def test_fragment_detected_in_raw_hex_base64_and_url_forms(self):
        scrubber = SecretScrubber()
        scrubber.add_secret(FAKE_SECRET)
        fragment = FAKE_SECRET[5:20]  # 15-char fragment, well over 9
        self.assertTrue(scrubber.contains_secret(f"crash at {fragment} here"))
        self.assertTrue(scrubber.contains_secret(fragment.encode("utf-8").hex()))
        # Base64 detection only aligns when the fragment starts on a
        # 3-byte boundary of the secret; use a boundary-aligned
        # fragment here (first 15 chars = 5 whole 3-byte groups).
        aligned = FAKE_SECRET[0:15]
        self.assertTrue(
            scrubber.contains_secret(
                base64.b64encode(aligned.encode("utf-8")).decode("ascii")))
        self.assertTrue(
            scrubber.contains_secret(urllib.parse.quote(fragment, safe="")))

    def test_clean_text_passes_and_retired_secret_stays_indexed(self):
        # NOTE (scrubber limitation, fail-closed direction): the
        # hex-form check uses 9 hex chars = ~4.5 bytes, so generic
        # byte sequences collide — e.g. text containing "secrets"
        # trips on the shared "secr" hex window. That refuses a
        # clean line (availability cost), never leaks a secret, so
        # the clean-text fixture below avoids the word "secret".
        # W15 may tighten hex windows; until then this is the
        # honest behaviour to pin.
        scrubber = SecretScrubber()
        scrubber.add_secret(FAKE_SECRET)
        self.assertFalse(scrubber.contains_secret("ordinary stack trace, nothing here"))
        scrubber.retire_secret(FAKE_SECRET)
        self.assertTrue(scrubber.contains_secret(FAKE_SECRET[5:20]))
        scrubber.assert_clean("ordinary stack trace, nothing here")
        with self.assertRaises(SecretDetectedError):
            scrubber.assert_clean(f"leaked {FAKE_SECRET[5:20]}")

    @unittest.expectedFailure
    def test_locked_keychain_scrubber_fails_closed(self):
        """NOT-CLOSED (needs audit.py change by its owner, W15).

        When the keychain is locked, hash material is unavailable
        and the scrubber must FAIL CLOSED (refuse the report),
        not report "clean". Today an unfed SecretScrubber reports
        clean, because it has no locked/unavailable flag and
        assert_clean only raises on a positive match. Required
        fix: add a locked/unavailable state to the scrubber on
        which assert_clean raises, and wire the crash path (when
        one exists) to set it when the keychain is locked.
        """
        scrubber = SecretScrubber()  # unfed: simulates locked keychain
        with self.assertRaises(SecretDetectedError):
            scrubber.assert_clean("some crash report text")

    @unittest.expectedFailure
    def test_scrubber_fed_at_key_add_time_by_production_code(self):
        """NOT-CLOSED (needs vault/broker wiring by their owners).

        v3 N-L8 requires scrubber hashes to be computed at key-add
        time. Today no production call site feeds the scrubber:
        grep finds no add_secret() caller in sealvra/ outside
        audit.py itself, and AuditLog defaults to no scrubber.
        Required fix: wire add_secret at key-add AND key-rotate
        time (retired secrets stay indexed), and only then add a
        crash-report sender behind per-report approval.
        """
        call_sites = 0
        pkg = os.path.join(BUILD_ROOT, "sealvra")
        for name in os.listdir(pkg):
            if not name.endswith(".py") or name == "audit.py":
                continue
            with open(os.path.join(pkg, name), encoding="utf-8") as handle:
                if "add_secret(" in handle.read():
                    call_sites += 1
        self.assertGreaterEqual(call_sites, 1)


if __name__ == "__main__":
    unittest.main()
