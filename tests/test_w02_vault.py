"""W02 vault + crypto tests (unittest, fake TEST-ONLY keys only).

Covers CONTRACT §5 / v3 N-D1, N-D5, N-D6, N-S2, N-S3, KS-09:
compartment independence, header/body AEAD tamper rejection, nonce
uniqueness, Argon2id parameters, atomic-write behaviour (snapshot
before overwrite), and backup-export guards (interactive auth,
synced folders, 24 h full-vault cooldown, restore kill-gate).

Run from the build root:  python3 -m unittest tests.test_w02_vault -v
(or with the .venv interpreter). Tests insert the build root into
sys.path so the keyholder package imports without installation.
"""

import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from keyholder import crypto, vault
from keyholder.crypto import CryptoTamperError
from keyholder.vault import (
    AuthRequired,
    BackupRefused,
    CompartmentExists,
    CompartmentNotFound,
    RestoreBlocked,
    TicketError,
    UnsupportedFormatError,
    Vault,
    VaultError,
)

PW = b"TEST-ONLY-vault-password"
PW2 = b"TEST-ONLY-other-password"
KEY_A = b"TEST-ONLY-github-key-aaaa-1111"
KEY_B = b"TEST-ONLY-gemini-key-bbbb-2222"
KEY_A2 = b"TEST-ONLY-github-key-aaaa-9999-rotated"


def _read_envelope(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


class VaultTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "vault"
        self.v = Vault(self.dir, platform_store="linux-file")

    def tearDown(self):
        self.tmp.cleanup()

    def store_a(self, secret=KEY_A, password=PW):
        return self.v.store_secret("key-aaaaaaaaaaaaaaaa", "github", secret, password=password)

    def store_b(self, secret=KEY_B, password=PW):
        return self.v.store_secret("key-bbbbbbbbbbbbbbbb", "gemini", secret, password=password)


class TestCompartmentIndependence(VaultTestBase):
    def test_two_compartments_have_distinct_salts(self):
        self.store_a()
        self.store_b()
        ea = _read_envelope(self.dir / "key-aaaaaaaaaaaaaaaa.khcomp.json")
        eb = _read_envelope(self.dir / "key-bbbbbbbbbbbbbbbb.khcomp.json")
        self.assertNotEqual(ea["salt_b64"], eb["salt_b64"])
        self.assertNotEqual(ea["body_ct_b64"], eb["body_ct_b64"])

    def test_compromising_one_wrapping_key_opens_only_that_compartment(self):
        # Platform-mode compartments, each with its own wrapping key:
        # an attacker who learns A's key must not open B.
        wk_a = bytes(range(32))
        wk_b = bytes([255 - i for i in range(32)])
        self.v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, wrapping_key=wk_a)
        self.v.store_secret("key-bbbbbbbbbbbbbbbb", "gemini", KEY_B, wrapping_key=wk_b)
        self.assertEqual(self.v.open_secret("key-aaaaaaaaaaaaaaaa", wrapping_key=wk_a), KEY_A)
        with self.assertRaises(CryptoTamperError):
            self.v.open_secret("key-bbbbbbbbbbbbbbbb", wrapping_key=wk_a)
        self.assertEqual(self.v.open_secret("key-bbbbbbbbbbbbbbbb", wrapping_key=wk_b), KEY_B)
        # A password-scheme compartment also refuses a raw wrapping key:
        # the envelope scheme binds which credential form may open it.
        with tempfile.TemporaryDirectory() as td:
            pv = Vault(Path(td) / "vault")
            pv.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, password=PW)
            with self.assertRaises(VaultError):
                pv.open_secret("key-aaaaaaaaaaaaaaaa", wrapping_key=wk_a)

    def test_wrong_password_rejected(self):
        self.store_a()
        with self.assertRaises(CryptoTamperError):
            self.v.open_secret("key-aaaaaaaaaaaaaaaa", password=PW2)

    def test_no_vault_wide_master_key_api(self):
        # There is deliberately no vault-wide unlock/lock/master API.
        for name in ("unlock_vault", "lock_vault", "master_key", "vault_key", "get_master_key"):
            self.assertFalse(hasattr(self.v, name), name)

    def test_list_and_metadata_expose_no_secret(self):
        self.store_a()
        listing = json.dumps(self.v.list_compartments())
        meta = json.dumps(self.v.get_metadata("key-aaaaaaaaaaaaaaaa"))
        for blob in (listing, meta):
            self.assertNotIn("TEST-ONLY-github", blob)
            self.assertNotIn(KEY_A.decode(), blob)

    def test_unknown_compartment(self):
        with self.assertRaises(CompartmentNotFound):
            self.v.open_secret("key-cccccccccccccccc", password=PW)
        with self.assertRaises(CompartmentExists):
            self.store_a()
            self.store_a()

    def test_provider_and_key_id_validation(self):
        with self.assertRaises(VaultError):
            self.v.store_secret("key-aaaaaaaaaaaaaaaa", "bitbucket", KEY_A, password=PW)
        with self.assertRaises(VaultError):
            self.v.store_secret("not-a-key-id", "github", KEY_A, password=PW)


class TestHeaderAeadTamper(VaultTestBase):
    def _tamper(self, key_id, field, value):
        path = self.dir / f"{key_id}.khcomp.json"
        env = _read_envelope(path)
        env[field] = value
        path.write_text(json.dumps(env), encoding="utf-8")

    def test_header_ct_tamper_rejected(self):
        self.store_a()
        env = _read_envelope(self.dir / "key-aaaaaaaaaaaaaaaa.khcomp.json")
        raw = bytearray(base64.b64decode(env["header_ct_b64"]))
        raw[0] ^= 1
        self._tamper("key-aaaaaaaaaaaaaaaa", "header_ct_b64", base64.b64encode(bytes(raw)).decode())
        with self.assertRaises(CryptoTamperError):
            self.v.open_secret("key-aaaaaaaaaaaaaaaa", password=PW)

    def test_body_ct_tamper_rejected(self):
        self.store_a()
        env = _read_envelope(self.dir / "key-aaaaaaaaaaaaaaaa.khcomp.json")
        raw = bytearray(base64.b64decode(env["body_ct_b64"]))
        raw[-1] ^= 1
        self._tamper("key-aaaaaaaaaaaaaaaa", "body_ct_b64", base64.b64encode(bytes(raw)).decode())
        with self.assertRaises(CryptoTamperError):
            self.v.open_secret("key-aaaaaaaaaaaaaaaa", password=PW)

    def test_header_nonce_tamper_rejected(self):
        self.store_a()
        env = _read_envelope(self.dir / "key-aaaaaaaaaaaaaaaa.khcomp.json")
        raw = bytearray(base64.b64decode(env["header_nonce_b64"]))
        raw[0] ^= 1
        self._tamper("key-aaaaaaaaaaaaaaaa", "header_nonce_b64", base64.b64encode(bytes(raw)).decode())
        with self.assertRaises(CryptoTamperError):
            self.v.open_secret("key-aaaaaaaaaaaaaaaa", password=PW)

    def test_version_in_metadata_tamper_rejected(self):
        # AAD binds compartment_version: editing the envelope version
        # without re-encrypting must fail authentication.
        self.store_a()
        self._tamper("key-aaaaaaaaaaaaaaaa", "compartment_version", 99)
        with self.assertRaises((CryptoTamperError, VaultError)):
            self.v.open_secret("key-aaaaaaaaaaaaaaaa", password=PW)

    def test_provider_swap_tamper_rejected(self):
        self.store_a()
        self._tamper("key-aaaaaaaaaaaaaaaa", "provider", "gemini")
        with self.assertRaises((CryptoTamperError, VaultError)):
            self.v.open_secret("key-aaaaaaaaaaaaaaaa", password=PW)

    def test_backup_blob_cannot_replay_as_live_compartment(self):
        self.store_a()
        dest = Path(self.tmp.name) / "a.khbackup.json"
        self.v.export_compartment(
            "key-aaaaaaaaaaaaaaaa", dest, password=PW,
            export_password=PW2, auth_method="interactive_os",
        )
        # Copying a backup container over the live file must not open:
        # distinct format + distinct HKDF info strings + backup AAD marker.
        live = self.dir / "key-aaaaaaaaaaaaaaaa.khcomp.json"
        live.write_bytes(dest.read_bytes())
        with self.assertRaises(VaultError):
            self.v.open_secret("key-aaaaaaaaaaaaaaaa", password=PW)


class TestNonceUniqueness(unittest.TestCase):
    def test_aes_gcm_nonces_unique_across_many_encryptions(self):
        key = os.urandom(32)
        nonces = set()
        for _ in range(1000):
            nonce, _ct = crypto.aes_gcm_encrypt(key, b"TEST-ONLY-plaintext", b"aad")
            self.assertEqual(len(nonce), 12)
            nonces.add(nonce)
        self.assertEqual(len(nonces), 1000)

    def test_rotate_produces_fresh_nonces_and_salt(self):
        with tempfile.TemporaryDirectory() as td:
            v = Vault(Path(td) / "vault")
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, password=PW)
            before = _read_envelope(Path(td) / "vault" / "key-aaaaaaaaaaaaaaaa.khcomp.json")
            v.rotate_secret("key-aaaaaaaaaaaaaaaa", KEY_A2, password=PW)
            after = _read_envelope(Path(td) / "vault" / "key-aaaaaaaaaaaaaaaa.khcomp.json")
            self.assertNotEqual(before["salt_b64"], after["salt_b64"])
            self.assertNotEqual(before["header_nonce_b64"], after["header_nonce_b64"])
            self.assertNotEqual(before["body_nonce_b64"], after["body_nonce_b64"])
            self.assertEqual(after["compartment_version"], 2)
            self.assertEqual(v.open_secret("key-aaaaaaaaaaaaaaaa", password=PW), KEY_A2)


class TestArgon2Parameters(unittest.TestCase):
    def test_pinned_parameters_match_contract(self):
        self.assertEqual(crypto.ARGON2_PARAMS["type"], "argon2id")
        self.assertEqual(crypto.ARGON2_PARAMS["time_cost"], 3)
        self.assertEqual(crypto.ARGON2_PARAMS["memory_cost_kib"], 64 * 1024)
        self.assertEqual(crypto.ARGON2_PARAMS["parallelism"], 1)
        self.assertEqual(crypto.ARGON2_PARAMS["hash_len"], 32)

    def test_derive_is_deterministic_and_salt_sensitive(self):
        salt = crypto.new_salt()
        k1 = crypto.derive_wrapping_key(PW, salt)
        k2 = crypto.derive_wrapping_key(PW, salt)
        k3 = crypto.derive_wrapping_key(PW, crypto.new_salt())
        self.assertEqual(k1, k2)
        self.assertNotEqual(k1, k3)
        self.assertEqual(len(k1), 32)

    def test_hkdf_info_strings_distinct(self):
        ikm = os.urandom(32)
        keys = {
            crypto.hkdf_derive(ikm, info)
            for info in (crypto.INFO_HEADER, crypto.INFO_BODY,
                         crypto.INFO_BACKUP_HEADER, crypto.INFO_BACKUP_BODY)
        }
        self.assertEqual(len(keys), 4)


class TestAtomicWrites(VaultTestBase):
    def test_snapshot_before_overwrite_on_rotate(self):
        self.store_a()
        live = self.dir / "key-aaaaaaaaaaaaaaaa.khcomp.json"
        original = live.read_bytes()
        self.v.rotate_secret("key-aaaaaaaaaaaaaaaa", KEY_A2, password=PW)
        snaps = self.v.list_snapshots("key-aaaaaaaaaaaaaaaa")
        self.assertEqual(len(snaps), 1)
        snap_bytes = (self.dir / ".snapshots" / snaps[0]).read_bytes()
        self.assertEqual(snap_bytes, original)
        # The snapshot generation still decrypts to the OLD secret:
        # copy it back as the live file in a scratch vault and open it.
        scratch = Path(self.tmp.name) / "scratch"
        scratch.mkdir()
        (scratch / "key-aaaaaaaaaaaaaaaa.khcomp.json").write_bytes(snap_bytes)
        sv = Vault(scratch)
        self.assertEqual(sv.open_secret("key-aaaaaaaaaaaaaaaa", password=PW), KEY_A)

    def test_no_temp_files_left_after_write(self):
        self.store_a()
        self.v.rotate_secret("key-aaaaaaaaaaaaaaaa", KEY_A2, password=PW)
        leftovers = [p for p in self.dir.iterdir() if ".tmp." in p.name]
        self.assertEqual(leftovers, [])
        leftovers_snap = [p for p in self.dir.joinpath(".snapshots").iterdir()
                          if ".tmp." in p.name]
        self.assertEqual(leftovers_snap, [])

    def test_delete_receipt_is_honest_about_backups(self):
        self.store_a()
        self.v.rotate_secret("key-aaaaaaaaaaaaaaaa", KEY_A2, password=PW)
        receipt = self.v.delete_compartment("key-aaaaaaaaaaaaaaaa")
        self.assertTrue(receipt["live_deleted"])
        self.assertEqual(len(receipt["snapshots_remaining"]), 1)
        self.assertIn("NOT deleted", receipt["still_to_purge"])
        self.assertIn("does not revoke", receipt["still_to_purge"])
        with self.assertRaises(CompartmentNotFound):
            self.v.open_secret("key-aaaaaaaaaaaaaaaa", password=PW)


class TestFingerprintAndTiers(unittest.TestCase):
    def test_fingerprint_is_first_12_hex_of_sha256(self):
        import hashlib
        self.assertEqual(
            crypto.fingerprint(KEY_A), hashlib.sha256(KEY_A).hexdigest()[:12]
        )
        self.assertEqual(len(crypto.fingerprint(KEY_A)), 12)

    def test_storage_tier_honesty(self):
        self.assertEqual(vault.storage_tier_for("macos-keychain"), "os-enforced-per-key")
        for store in ("linux-secret-service", "linux-file", "windows-dpapi", "unknown-store"):
            self.assertEqual(vault.storage_tier_for(store), "user-scoped")
        linux_text = vault.posture_text("linux-file")
        self.assertIn("USER-SCOPED", linux_text)
        self.assertIn("not OS-enforced", linux_text)
        self.assertIn("same-user", linux_text)
        mac_text = vault.posture_text("macos-keychain")
        self.assertIn("OS-enforced", mac_text)


class TestBackupExportGuards(VaultTestBase):
    def test_control_socket_auth_alone_refused(self):
        self.store_a()
        dest = Path(self.tmp.name) / "a.khbackup.json"
        for bad_auth in ("control-socket", "pairing-token", "", "none"):
            with self.assertRaises(AuthRequired, msg=bad_auth):
                self.v.export_compartment(
                    "key-aaaaaaaaaaaaaaaa", dest, password=PW,
                    export_password=PW2, auth_method=bad_auth,
                )
        self.assertFalse(dest.exists())

    def test_synced_folder_refused_without_typed_confirmation(self):
        self.store_a()
        synced = Path(self.tmp.name) / "Dropbox" / "a.khbackup.json"
        synced.parent.mkdir(parents=True)
        with self.assertRaises(BackupRefused):
            self.v.export_compartment(
                "key-aaaaaaaaaaaaaaaa", synced, password=PW,
                export_password=PW2, auth_method="interactive_os",
            )
        self.assertFalse(synced.exists())

    def test_synced_folder_allowed_with_exact_typed_confirmation(self):
        self.store_a()
        synced = Path(self.tmp.name) / "OneDrive" / "a.khbackup.json"
        synced.parent.mkdir(parents=True)
        result = self.v.export_compartment(
            "key-aaaaaaaaaaaaaaaa", synced, password=PW,
            export_password=PW2, auth_method="interactive_os",
            risk_confirmation="I UNDERSTAND THIS FOLDER MAY SYNC",
        )
        self.assertTrue(Path(result["dest"]).exists())
        # Near-miss confirmation text is NOT enough.
        synced2 = Path(self.tmp.name) / "OneDrive" / "b.khbackup.json"
        with self.assertRaises(BackupRefused):
            self.v.export_compartment(
                "key-aaaaaaaaaaaaaaaa", synced2, password=PW,
                export_password=PW2, auth_method="interactive_os",
                risk_confirmation="i understand",
            )

    def test_per_compartment_export_round_trip(self):
        self.store_a()
        dest = Path(self.tmp.name) / "a.khbackup.json"
        self.v.export_compartment(
            "key-aaaaaaaaaaaaaaaa", dest, password=PW,
            export_password=PW2, auth_method="interactive_os",
        )
        # Backup container must not open with the live vault password
        # path confusion: it opens only under its export credential,
        # and a backup blob is not a live compartment.
        env = _read_envelope(dest)
        self.assertEqual(env["format"], "KHBACKUP1")
        self.assertEqual(env["container"], "backup")

    def test_full_vault_export_cooldown_enforced(self):
        self.store_a()
        self.store_b()
        dest_dir = Path(self.tmp.name) / "full"
        dest_dir.mkdir()
        creds = {
            "key-aaaaaaaaaaaaaaaa": {"password": PW},
            "key-bbbbbbbbbbbbbbbb": {"password": PW},
            "__export__": {"export_password": PW2},
        }
        first = self.v.export_all(dest_dir, credentials=creds, auth_method="interactive_os")
        self.assertEqual(sorted(first["exported"]), ["key-aaaaaaaaaaaaaaaa", "key-bbbbbbbbbbbbbbbb"])
        with self.assertRaises(BackupRefused) as ctx:
            self.v.export_all(dest_dir, credentials=creds, auth_method="interactive_os")
        self.assertIn("cooldown", str(ctx.exception))

    def test_per_compartment_export_ignores_full_cooldown(self):
        self.store_a()
        self.store_b()
        dest_dir = Path(self.tmp.name) / "full"
        dest_dir.mkdir()
        creds = {
            "key-aaaaaaaaaaaaaaaa": {"password": PW},
            "key-bbbbbbbbbbbbbbbb": {"password": PW},
            "__export__": {"export_password": PW2},
        }
        self.v.export_all(dest_dir, credentials=creds, auth_method="interactive_os")
        # Per-compartment export still works during the cooldown.
        single = Path(self.tmp.name) / "single.khbackup.json"
        self.v.export_compartment(
            "key-aaaaaaaaaaaaaaaa", single, password=PW,
            export_password=PW2, auth_method="interactive_os",
        )
        self.assertTrue(single.exists())


class TestRestoreKillGate(VaultTestBase):
    def _backup_a(self):
        self.store_a()
        dest = Path(self.tmp.name) / "a.khbackup.json"
        self.v.export_compartment(
            "key-aaaaaaaaaaaaaaaa", dest, password=PW,
            export_password=PW2, auth_method="interactive_os",
        )
        return dest

    def test_restore_refused_while_sessions_live(self):
        dest = self._backup_a()
        self.v.delete_compartment("key-aaaaaaaaaaaaaaaa", purge_snapshots=True)
        with self.assertRaises(RestoreBlocked):
            self.v.restore_compartment(
                dest, export_password=PW2, password=PW,
                live_sessions=["sess-0123456789abcdef"],
            )
        # Bare flag without a callback is also refused.
        with self.assertRaises(RestoreBlocked):
            self.v.restore_compartment(
                dest, export_password=PW2, password=PW,
                live_sessions=["sess-0123456789abcdef"],
                broker_confirmed_kill=True, kill_callback=None,
            )
        # Unknown live-session state is refused.
        with self.assertRaises(RestoreBlocked):
            self.v.restore_compartment(
                dest, export_password=PW2, password=PW, live_sessions=None,
            )

    def test_restore_proceeds_after_broker_kill_callback(self):
        dest = self._backup_a()
        self.v.rotate_secret("key-aaaaaaaaaaaaaaaa", KEY_A2, password=PW)
        killed = []
        def kill_all():
            killed.append("sess-0123456789abcdef")
            return list(killed)
        result = self.v.restore_compartment(
            dest, export_password=PW2, password=PW,
            live_sessions=["sess-0123456789abcdef"],
            broker_confirmed_kill=True, kill_callback=kill_all,
            overwrite=True, allow_resurrect=True,
        )
        self.assertEqual(killed, ["sess-0123456789abcdef"])
        self.assertEqual(result["sessions_killed"], ["sess-0123456789abcdef"])
        # Restored compartment holds the BACKUP secret (pre-rotation),
        # version re-baselined to the backup version, old live snapshotted.
        self.assertEqual(self.v.open_secret("key-aaaaaaaaaaaaaaaa", password=PW), KEY_A)
        self.assertEqual(self.v.get_metadata("key-aaaaaaaaaaaaaaaa")["compartment_version"], 1)
        self.assertTrue(self.v.list_snapshots("key-aaaaaaaaaaaaaaaa"))

    def test_restore_refuses_auto_merge_and_resurrect_without_flag(self):
        dest = self._backup_a()  # backup at version 1
        self.v.rotate_secret("key-aaaaaaaaaaaaaaaa", KEY_A2, password=PW)  # live now v2
        with self.assertRaises(RestoreBlocked):
            self.v.restore_compartment(
                dest, export_password=PW2, password=PW,
                live_sessions=[], overwrite=False,
            )
        with self.assertRaises(RestoreBlocked):
            self.v.restore_compartment(
                dest, export_password=PW2, password=PW,
                live_sessions=[], overwrite=True, allow_resurrect=False,
            )
        result = self.v.restore_compartment(
            dest, export_password=PW2, password=PW,
            live_sessions=[], overwrite=True, allow_resurrect=True,
        )
        self.assertEqual(result["compartment_version"], 1)
        self.assertEqual(self.v.open_secret("key-aaaaaaaaaaaaaaaa", password=PW), KEY_A)

    def test_restore_with_empty_live_list_works(self):
        dest = self._backup_a()
        self.v.delete_compartment("key-aaaaaaaaaaaaaaaa", purge_snapshots=True)
        result = self.v.restore_compartment(
            dest, export_password=PW2, password=PW, live_sessions=[],
        )
        self.assertEqual(result["key_id"], "key-aaaaaaaaaaaaaaaa")
        self.assertEqual(self.v.open_secret("key-aaaaaaaaaaaaaaaa", password=PW), KEY_A)


class TestRebuildIndex(VaultTestBase):
    def test_quarantine_of_corrupt_envelope(self):
        self.store_a()
        self.store_b()
        bad = self.dir / "key-bbbbbbbbbbbbbbbb.khcomp.json"
        bad.write_text("{not json", encoding="utf-8")
        index = self.v.rebuild_index()
        self.assertEqual([e["key_id"] for e in index["ok"]], ["key-aaaaaaaaaaaaaaaa"])
        self.assertEqual(index["quarantined"], ["key-bbbbbbbbbbbbbbbb.khcomp.json"])


# ---------------------------------------------------------------------------
# v0.2 additions (W12): header AEAD spec, migration decision, dual-factor
# recovery, password discipline, restore kill ordering, differ/bundle rules.
# Fake TEST-ONLY values only. Platform wrapping keys are used wherever
# the property under test does not itself need password derivation, to
# keep the suite fast (Argon2id m=64MiB/t=3 is deliberately expensive).
# ---------------------------------------------------------------------------

WK1 = bytes(range(32))
WK2 = bytes([255 - i for i in range(32)])
WK3 = bytes([7] * 32)
REC_KEY = bytes([0xA5] * 32)


def _platform_vault(tmpdir):
    return Vault(Path(tmpdir) / "vault", platform_store="linux-file")


class TestHeaderAeadSpec(unittest.TestCase):
    def test_spec_values_are_the_implementation_values(self):
        spec = crypto.HEADER_AEAD_SPEC
        self.assertEqual(spec["cipher"], "AES-256-GCM")
        self.assertEqual(spec["key_bytes"], 32)
        self.assertEqual(spec["tag_bits"], 128)
        self.assertEqual(spec["nonce_bits"], 96)
        self.assertIsNone(spec["kdf_salt"])
        self.assertEqual(spec["info"]["live_header"], b"keyholder-v1/header")
        self.assertEqual(spec["info"]["backup_body"], b"keyholder-v1/backup-body")
        self.assertNotEqual(spec["info"]["live_header"], spec["info"]["live_body"])

    def test_aad_helpers_match_canonical_recomputation(self):
        fields = ["auth_scheme", "compartment_version", "key_id", "provider"]
        expected_h = json.dumps(
            ["backup", "key-aaaaaaaaaaaaaaaa", "github", 1, fields],
            sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(
            crypto.header_aad(["backup"], "key-aaaaaaaaaaaaaaaa", "github", 1, fields),
            expected_h)
        expected_b = json.dumps(
            ["backup", "key-aaaaaaaaaaaaaaaa", "github", 1, fields, "password"],
            sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(
            crypto.body_aad(["backup"], "key-aaaaaaaaaaaaaaaa", "github", 1,
                            fields, "password"),
            expected_b)

    def test_header_and_body_keys_differ_and_nonces_differ_in_envelope(self):
        with tempfile.TemporaryDirectory() as td:
            v = _platform_vault(td)
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, wrapping_key=WK1)
            env = _read_envelope(Path(td) / "vault" / "key-aaaaaaaaaaaaaaaa.khcomp.json")
            hk = crypto.hkdf_derive(WK1, crypto.INFO_HEADER)
            bk = crypto.hkdf_derive(WK1, crypto.INFO_BODY)
            self.assertNotEqual(hk, bk)
            self.assertEqual(len(base64.b64decode(env["header_nonce_b64"])), 12)
            self.assertEqual(len(base64.b64decode(env["body_nonce_b64"])), 12)
            self.assertNotEqual(env["header_nonce_b64"], env["body_nonce_b64"])

    def test_envelope_nonces_unique_across_many_envelopes(self):
        # Same wrapping key, many envelopes: (key, nonce) pairs must
        # never repeat — this is the no-reuse property at vault volume.
        with tempfile.TemporaryDirectory() as td:
            v = _platform_vault(td)
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, wrapping_key=WK1)
            seen = set()
            env0 = _read_envelope(
                Path(td) / "vault" / "key-aaaaaaaaaaaaaaaa.khcomp.json")
            seen.add(env0["header_nonce_b64"])
            seen.add(env0["body_nonce_b64"])
            for _ in range(6):
                v.rotate_secret("key-aaaaaaaaaaaaaaaa", KEY_A, wrapping_key=WK1)
                env = _read_envelope(
                    Path(td) / "vault" / "key-aaaaaaaaaaaaaaaa.khcomp.json")
                for field in ("header_nonce_b64", "body_nonce_b64"):
                    self.assertNotIn(env[field], seen)
                    seen.add(env[field])
            self.assertEqual(len(seen), 14)  # 1 store + 6 rotates, x2 nonces

    def test_header_fields_tamper_fails_via_aad(self):
        with tempfile.TemporaryDirectory() as td:
            v = _platform_vault(td)
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, wrapping_key=WK1)
            path = Path(td) / "vault" / "key-aaaaaaaaaaaaaaaa.khcomp.json"
            env = _read_envelope(path)
            env["header_fields"] = sorted(env["header_fields"] + ["extra_field"])
            path.write_text(json.dumps(env), encoding="utf-8")
            with self.assertRaises(CryptoTamperError):
                v.open_secret("key-aaaaaaaaaaaaaaaa", wrapping_key=WK1)

    def test_metadata_is_marked_unverified(self):
        with tempfile.TemporaryDirectory() as td:
            v = _platform_vault(td)
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, wrapping_key=WK1)
            self.assertFalse(v.get_metadata("key-aaaaaaaaaaaaaaaa")["header_verified"])
            listing = v.list_compartments()
            self.assertEqual(len(listing), 1)
            self.assertFalse(listing[0]["header_verified"])
            self.assertFalse(v.rebuild_index()["ok"][0]["header_verified"])


class TestMigrationDecision(unittest.TestCase):
    def test_legacy_single_dek_file_is_reported_not_misread(self):
        with tempfile.TemporaryDirectory() as td:
            v = _platform_vault(td)
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, wrapping_key=WK1)
            legacy = Path(td) / "vault" / "vault.json"
            legacy.write_text(
                json.dumps({"format": "KHVAULT1", "dek_wrapped": "TEST-ONLY"}),
                encoding="utf-8")
            status = v.migration_status()
            self.assertEqual(status["decision"],
                             "COMPARTMENTS_FIRST_NO_IN_PLACE_MIGRATION")
            self.assertIn("no in-place migration", status["decision_text"])
            kinds = {s["name"]: s["kind"] for s in status["stray_files"]}
            self.assertEqual(kinds["vault.json"], "foreign-or-legacy")
            # The legacy file is never listed as a compartment.
            self.assertEqual([c["key_id"] for c in status["compartments"]],
                             ["key-aaaaaaaaaaaaaaaa"])
            self.assertIn("restore_compartment", status["import_paths"]["KHBACKUP1"])

    def test_unknown_format_envelope_refused_with_migration_text(self):
        with tempfile.TemporaryDirectory() as td:
            v = _platform_vault(td)
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, wrapping_key=WK1)
            path = Path(td) / "vault" / "key-aaaaaaaaaaaaaaaa.khcomp.json"
            env = _read_envelope(path)
            env["format"] = "KHVAULT1"
            path.write_text(json.dumps(env), encoding="utf-8")
            with self.assertRaises(UnsupportedFormatError) as ctx:
                v.open_secret("key-aaaaaaaaaaaaaaaa", wrapping_key=WK1)
            self.assertIn("no in-place migration", str(ctx.exception))
            # UnsupportedFormatError is still a VaultError for old callers.
            with self.assertRaises(VaultError):
                v.open_secret("key-aaaaaaaaaaaaaaaa", wrapping_key=WK1)
            index = v.rebuild_index()
            self.assertEqual(index["quarantined"],
                             ["key-aaaaaaaaaaaaaaaa.khcomp.json"])

    def test_backup_inside_vault_dir_classified_not_listed(self):
        with tempfile.TemporaryDirectory() as td:
            v = _platform_vault(td)
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, wrapping_key=WK1)
            dest = Path(td) / "vault" / "key-aaaaaaaaaaaaaaaa.khbackup.json"
            v.export_compartment(
                "key-aaaaaaaaaaaaaaaa", dest, wrapping_key=WK1,
                export_wrapping_key=WK2, auth_method="interactive_os")
            stray = {s["name"]: s["kind"]
                     for s in v.migration_status()["stray_files"]}
            self.assertEqual(stray["key-aaaaaaaaaaaaaaaa.khbackup.json"], "backup")
            self.assertEqual(len(v.list_compartments()), 1)


class TestRecoveryTwoWrappings(unittest.TestCase):
    def _dual(self, td):
        v = _platform_vault(td)
        v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, wrapping_key=WK1)
        dest = Path(td) / "a.khbackup.json"
        v.export_with_recovery(
            "key-aaaaaaaaaaaaaaaa", dest, wrapping_key=WK1,
            export_wrapping_key=WK2, recovery_wrapping_key=REC_KEY,
            auth_method="interactive_os")
        return v, dest

    def test_either_factor_alone_opens(self):
        with tempfile.TemporaryDirectory() as td:
            v, dest = self._dual(td)
            info = v.inspect_backup(dest)
            self.assertEqual(info["format"], "KHBACKUP2")
            self.assertEqual(info["factors"], ["primary", "recovery"])
            self.assertFalse(info["header_verified"])
            for kwargs in ({"export_wrapping_key": WK2},
                           {"recovery_wrapping_key": REC_KEY}):
                v.delete_compartment("key-aaaaaaaaaaaaaaaa", purge_snapshots=True)
                result = v.restore_compartment(
                    dest, password=b"TEST-ONLY-new-live-password", live_sessions=[],
                    **kwargs)
                self.assertEqual(result["key_id"], "key-aaaaaaaaaaaaaaaa")
                self.assertEqual(v.open_secret("key-aaaaaaaaaaaaaaaa",
                                               password=b"TEST-ONLY-new-live-password"),
                                 KEY_A)

    def test_wrong_both_factors_and_no_factor_fail(self):
        with tempfile.TemporaryDirectory() as td:
            v, dest = self._dual(td)
            v.delete_compartment("key-aaaaaaaaaaaaaaaa", purge_snapshots=True)
            with self.assertRaises(CryptoTamperError):
                v.restore_compartment(
                    dest, export_wrapping_key=WK3, recovery_wrapping_key=WK3,
                    password=b"TEST-ONLY-new-live-password", live_sessions=[])
            with self.assertRaises(VaultError):
                v.restore_compartment(
                    dest, password=b"TEST-ONLY-new-live-password", live_sessions=[])

    def test_identical_factors_refused(self):
        with tempfile.TemporaryDirectory() as td:
            v = _platform_vault(td)
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, wrapping_key=WK1)
            dest = Path(td) / "a.khbackup.json"
            with self.assertRaises(BackupRefused):
                v.export_with_recovery(
                    "key-aaaaaaaaaaaaaaaa", dest, wrapping_key=WK1,
                    export_wrapping_key=WK2, recovery_wrapping_key=WK2,
                    auth_method="interactive_os")
            self.assertFalse(dest.exists())

    def test_factor_transplant_fails(self):
        # Swap the recovery wrapping's body ciphertext into the primary
        # wrapping: the factor label in the AAD must reject it.
        with tempfile.TemporaryDirectory() as td:
            v, dest = self._dual(td)
            env = _read_envelope(dest)
            env["wrappings"][0]["body_ct_b64"] = env["wrappings"][1]["body_ct_b64"]
            dest.write_text(json.dumps(env), encoding="utf-8")
            v.delete_compartment("key-aaaaaaaaaaaaaaaa", purge_snapshots=True)
            with self.assertRaises(CryptoTamperError):
                v.restore_compartment(
                    dest, export_wrapping_key=WK2,
                    password=b"TEST-ONLY-new-live-password", live_sessions=[])

    def test_recovery_creds_for_single_factor_container_refused(self):
        with tempfile.TemporaryDirectory() as td:
            v = _platform_vault(td)
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, wrapping_key=WK1)
            dest = Path(td) / "a.khbackup.json"
            v.export_compartment(
                "key-aaaaaaaaaaaaaaaa", dest, wrapping_key=WK1,
                export_wrapping_key=WK2, auth_method="interactive_os")
            v.delete_compartment("key-aaaaaaaaaaaaaaaa", purge_snapshots=True)
            with self.assertRaises(VaultError):
                v.restore_compartment(
                    dest, export_wrapping_key=WK2, recovery_wrapping_key=REC_KEY,
                    password=b"TEST-ONLY-new-live-password", live_sessions=[])

    def test_dual_container_cannot_replay_as_live(self):
        with tempfile.TemporaryDirectory() as td:
            v, dest = self._dual(td)
            live = Path(td) / "vault" / "key-aaaaaaaaaaaaaaaa.khcomp.json"
            live.write_bytes(dest.read_bytes())
            with self.assertRaises(UnsupportedFormatError):
                v.open_secret("key-aaaaaaaaaaaaaaaa", wrapping_key=WK1)

    def test_recovery_key_generator(self):
        k1 = crypto.new_recovery_key()
        k2 = crypto.new_recovery_key()
        self.assertEqual(len(k1), 32)
        self.assertNotEqual(k1, k2)


class TestPasswordDiscipline(unittest.TestCase):
    def test_vault_retains_no_password_or_derived_key(self):
        with tempfile.TemporaryDirectory() as td:
            v = Vault(Path(td) / "vault")
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, password=PW)
            v.open_secret("key-aaaaaaaaaaaaaaaa", password=PW)
            wk = crypto.derive_wrapping_key(
                PW, base64.b64decode(_read_envelope(
                    Path(td) / "vault" / "key-aaaaaaaaaaaaaaaa.khcomp.json")["salt_b64"]))
            for value in vars(v).values():
                if isinstance(value, (bytes, bytearray)):
                    self.assertNotEqual(bytes(value), PW)
                    self.assertNotEqual(bytes(value), wk)

    def test_ticket_single_use_version_bound_and_zeroing(self):
        with tempfile.TemporaryDirectory() as td:
            v = Vault(Path(td) / "vault")
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, password=PW)
            pw_buf = bytearray(PW)
            ticket = v.issue_ticket("key-aaaaaaaaaaaaaaaa", password=pw_buf)
            # The caller's bytearray password is zeroed after derivation.
            self.assertEqual(bytes(pw_buf), b"\x00" * len(PW))
            self.assertEqual(ticket.key_id, "key-aaaaaaaaaaaaaaaa")
            self.assertEqual(ticket.compartment_version, 1)
            self.assertEqual(v.open_with_ticket(ticket), KEY_A)
            self.assertTrue(ticket.consumed)
            with self.assertRaises(TicketError):
                v.open_with_ticket(ticket)
            # A ticket issued before rotation is stale after rotation.
            ticket2 = v.issue_ticket("key-aaaaaaaaaaaaaaaa", password=PW)
            v.rotate_secret("key-aaaaaaaaaaaaaaaa", KEY_A2, password=PW)
            with self.assertRaises(TicketError):
                v.open_with_ticket(ticket2)

    def test_ticket_wrong_password_fails_without_decrypting_secret(self):
        with tempfile.TemporaryDirectory() as td:
            v = Vault(Path(td) / "vault")
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, password=PW)
            with self.assertRaises(CryptoTamperError):
                v.issue_ticket("key-aaaaaaaaaaaaaaaa", password=PW2)

    def test_one_entry_does_not_silently_open_another_compartment(self):
        # Same password for two compartments: each open still needs its
        # own ticket, and a ticket for A returns A's secret only, once.
        with tempfile.TemporaryDirectory() as td:
            v = Vault(Path(td) / "vault")
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, password=PW)
            v.store_secret("key-bbbbbbbbbbbbbbbb", "gemini", KEY_B, password=PW)
            ticket_a = v.issue_ticket("key-aaaaaaaaaaaaaaaa", password=PW)
            self.assertEqual(v.open_with_ticket(ticket_a), KEY_A)
            self.assertNotEqual(KEY_A, KEY_B)
            with self.assertRaises(TicketError):
                v.open_with_ticket(ticket_a)

    def test_strict_mode_refuses_direct_password_open_but_allows_ticket(self):
        with tempfile.TemporaryDirectory() as td:
            v = Vault(Path(td) / "vault", strict_password_tickets=True)
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, password=PW)
            with self.assertRaises(VaultError):
                v.open_secret("key-aaaaaaaaaaaaaaaa", password=PW)
            ticket = v.issue_ticket("key-aaaaaaaaaaaaaaaa", password=PW)
            self.assertEqual(v.open_with_ticket(ticket), KEY_A)
            # Platform compartments are unaffected by strict mode.
            v.store_secret("key-bbbbbbbbbbbbbbbb", "gemini", KEY_B, wrapping_key=WK1)
            self.assertEqual(v.open_secret("key-bbbbbbbbbbbbbbbb",
                                           wrapping_key=WK1), KEY_B)

    def test_discipline_text_states_one_entry_one_compartment(self):
        self.assertIn("ONE compartment", vault.PASSWORD_DISCIPLINE)
        self.assertIn("never stores", vault.PASSWORD_DISCIPLINE)
        self.assertIn("ONE compartment", vault.posture_text("linux-file"))


class TestRestoreKillOrdering(unittest.TestCase):
    def _live_and_backup(self, td):
        v = _platform_vault(td)
        v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, wrapping_key=WK1)
        dest = Path(td) / "a.khbackup.json"
        v.export_compartment(
            "key-aaaaaaaaaaaaaaaa", dest, wrapping_key=WK1,
            export_wrapping_key=WK2, auth_method="interactive_os")
        return v, dest

    def test_refused_restore_does_not_kill(self):
        with tempfile.TemporaryDirectory() as td:
            v, dest = self._live_and_backup(td)
            v.rotate_secret("key-aaaaaaaaaaaaaaaa", KEY_A2, wrapping_key=WK1)
            killed = []
            with self.assertRaises(RestoreBlocked):
                v.restore_compartment(
                    dest, export_wrapping_key=WK2, wrapping_key=WK1,
                    live_sessions=["sess-0123456789abcdef"],
                    broker_confirmed_kill=True, kill_callback=lambda: killed.append(1),
                    overwrite=True, allow_resurrect=False)
            self.assertEqual(killed, [])

    def test_bad_backup_credential_does_not_kill(self):
        with tempfile.TemporaryDirectory() as td:
            v, dest = self._live_and_backup(td)
            killed = []
            with self.assertRaises(CryptoTamperError):
                v.restore_compartment(
                    dest, export_wrapping_key=WK3, wrapping_key=WK1,
                    live_sessions=["sess-0123456789abcdef"],
                    broker_confirmed_kill=True, kill_callback=lambda: killed.append(1),
                    overwrite=True, allow_resurrect=True)
            self.assertEqual(killed, [])

    def test_kill_runs_before_any_write(self):
        with tempfile.TemporaryDirectory() as td:
            v, dest = self._live_and_backup(td)
            v.rotate_secret("key-aaaaaaaaaaaaaaaa", KEY_A2, wrapping_key=WK1)
            live_path = Path(td) / "vault" / "key-aaaaaaaaaaaaaaaa.khcomp.json"
            before = live_path.read_bytes()
            order = []
            def kill_all():
                # At kill time the live file must still be the old one.
                order.append(live_path.read_bytes() == before)
                return ["sess-0123456789abcdef"]
            result = v.restore_compartment(
                dest, export_wrapping_key=WK2, wrapping_key=WK1,
                live_sessions=["sess-0123456789abcdef"],
                broker_confirmed_kill=True, kill_callback=kill_all,
                overwrite=True, allow_resurrect=True)
            self.assertEqual(order, [True])
            self.assertEqual(result["sessions_killed"], ["sess-0123456789abcdef"])
            self.assertEqual(v.open_secret("key-aaaaaaaaaaaaaaaa",
                                           wrapping_key=WK1), KEY_A)

    def test_provider_mismatch_refuses_without_kill(self):
        with tempfile.TemporaryDirectory() as td:
            v, dest = self._live_and_backup(td)
            # A backup for the SAME key_id but the OTHER provider.
            other = Vault(Path(td) / "other")
            other.store_secret("key-aaaaaaaaaaaaaaaa", "gemini", KEY_B, wrapping_key=WK1)
            other_dest = Path(td) / "other.khbackup.json"
            other.export_compartment(
                "key-aaaaaaaaaaaaaaaa", other_dest, wrapping_key=WK1,
                export_wrapping_key=WK2, auth_method="interactive_os")
            killed = []
            with self.assertRaises(RestoreBlocked):
                v.restore_compartment(
                    other_dest, export_wrapping_key=WK2, wrapping_key=WK1,
                    live_sessions=["sess-0123456789abcdef"],
                    broker_confirmed_kill=True, kill_callback=lambda: killed.append(1),
                    overwrite=True, allow_resurrect=True)
            self.assertEqual(killed, [])

    def test_restore_all_kills_exactly_once_and_reports_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            v = _platform_vault(td)
            backup_dir = Path(td) / "backups"
            backup_dir.mkdir()
            for key_id, provider, secret in (
                    ("key-aaaaaaaaaaaaaaaa", "github", KEY_A),
                    ("key-bbbbbbbbbbbbbbbb", "gemini", KEY_B)):
                v.store_secret(key_id, provider, secret, wrapping_key=WK1)
                v.export_compartment(
                    key_id, backup_dir / f"{key_id}.khbackup.json",
                    wrapping_key=WK1, export_wrapping_key=WK2,
                    auth_method="interactive_os")
            # One dual container, one unreadable stray container file.
            v.export_with_recovery(
                "key-aaaaaaaaaaaaaaaa", backup_dir / "key-aaaaaaaaaaaaaaaa.khbackup.json",
                wrapping_key=WK1, export_wrapping_key=WK2,
                recovery_wrapping_key=REC_KEY, auth_method="interactive_os",
                overwrite=True)
            (backup_dir / "key-cccccccccccccccc.khbackup.json").write_text(
                "{not json", encoding="utf-8")
            v.delete_compartment("key-aaaaaaaaaaaaaaaa", purge_snapshots=True)
            v.delete_compartment("key-bbbbbbbbbbbbbbbb", purge_snapshots=True)
            kills = []
            def kill_all():
                kills.append(1)
                return ["sess-0123456789abcdef"]
            result = v.restore_all(
                backup_dir, export_wrapping_key=WK2, recovery_wrapping_key=REC_KEY,
                credentials={
                    "key-aaaaaaaaaaaaaaaa": {"wrapping_key": WK1},
                    "key-bbbbbbbbbbbbbbbb": {"wrapping_key": WK1},
                },
                live_sessions=["sess-0123456789abcdef"],
                broker_confirmed_kill=True, kill_callback=kill_all,
                overwrite=True)
            self.assertEqual(kills, [1])
            self.assertEqual(sorted(result["restored"]),
                             ["key-aaaaaaaaaaaaaaaa", "key-bbbbbbbbbbbbbbbb"])
            self.assertEqual([s["file"] for s in result["skipped"]],
                             ["key-cccccccccccccccc.khbackup.json"])


class TestBackupDifferAndBundle(unittest.TestCase):
    def test_export_password_equal_to_vault_password_refused(self):
        with tempfile.TemporaryDirectory() as td:
            v = Vault(Path(td) / "vault")
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, password=PW)
            dest = Path(td) / "a.khbackup.json"
            with self.assertRaises(BackupRefused):
                v.export_compartment(
                    "key-aaaaaaaaaaaaaaaa", dest, password=PW,
                    export_password=PW, auth_method="interactive_os")
            self.assertFalse(dest.exists())

    def test_recovery_factor_equal_to_vault_password_refused(self):
        with tempfile.TemporaryDirectory() as td:
            v = Vault(Path(td) / "vault")
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, password=PW)
            dest = Path(td) / "a.khbackup.json"
            with self.assertRaises(BackupRefused):
                v.export_with_recovery(
                    "key-aaaaaaaaaaaaaaaa", dest, password=PW,
                    export_password=PW2, recovery_password=PW,
                    auth_method="interactive_os")
            self.assertFalse(dest.exists())

    def test_platform_export_reports_differ_check_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            v = _platform_vault(td)
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, wrapping_key=WK1)
            dest = Path(td) / "a.khbackup.json"
            result = v.export_compartment(
                "key-aaaaaaaaaaaaaaaa", dest, wrapping_key=WK1,
                export_password=PW2, auth_method="interactive_os")
            self.assertIn("skipped-platform-mode",
                          result["vault_password_differ_check"])

    def test_export_via_ticket_in_strict_vault(self):
        with tempfile.TemporaryDirectory() as td:
            v = Vault(Path(td) / "vault", strict_password_tickets=True)
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, password=PW)
            dest = Path(td) / "a.khbackup.json"
            ticket = v.issue_ticket("key-aaaaaaaaaaaaaaaa", password=PW)
            result = v.export_compartment(
                "key-aaaaaaaaaaaaaaaa", dest, export_password=PW2,
                auth_method="interactive_os", ticket=ticket)
            self.assertTrue(Path(result["dest"]).exists())
            self.assertIn("skipped-ticket-mode",
                          result["vault_password_differ_check"])

    def test_full_export_carries_bundle_warning(self):
        with tempfile.TemporaryDirectory() as td:
            v = _platform_vault(td)
            v.store_secret("key-aaaaaaaaaaaaaaaa", "github", KEY_A, wrapping_key=WK1)
            dest_dir = Path(td) / "full"
            dest_dir.mkdir()
            result = v.export_all(
                dest_dir,
                credentials={
                    "key-aaaaaaaaaaaaaaaa": {"wrapping_key": WK1},
                    "__export__": {"export_wrapping_key": WK2},
                },
                auth_method="interactive_os")
            self.assertIn("EVERY key in this bundle", result["bundle_warning"])


if __name__ == "__main__":
    unittest.main()
