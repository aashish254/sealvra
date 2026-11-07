"""Pack signing tests (W04, CONTRACT section 13.3).

All signing keys here are generated fresh inside each test. No test
ever uses the shipped trusted key in packs/trusted_keys.json, and no
test pack is ever written to packs/: fixtures live in temp dirs.
Fake data only, no real keys, no network, no provider contact.
"""

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sealvra.packs import (
    PackRefusedError,
    RevokedLists,
    generate_pack_keypair,
    load_pack,
    load_pack_directory,
    finalise_pack,
    pack_key_id,
    parse_pack,
    public_key_bytes,
    sign_pack_dict,
    verify_pack_signature,
)

ROOT = Path(__file__).resolve().parent.parent
EMPTY_REVOKED = RevokedLists(frozenset(), frozenset())


def _base_pack(**overrides):
    pack = {
        "name": "testpack",
        "version": "0.1.0",
        "issued_at": "2026-10-28",
        "max_age_days": 3650,
        "endpoints": [
            {"method": "GET", "path_pattern": "/public/*",
             "capability": "read_public", "level": 1},
        ],
    }
    pack.update(overrides)
    return finalise_pack(pack)


def _trusted_entry(private_key):
    public_bytes = public_key_bytes(private_key)
    return {
        "key_id": pack_key_id(public_bytes),
        "algorithm": "Ed25519",
        "public_key": base64.b64encode(public_bytes).decode("ascii"),
    }


def _write_trust_files(directory, private_keys, revoked=None):
    trusted = {"keys": [_trusted_entry(k) for k in private_keys]}
    (Path(directory) / "trusted_keys.json").write_text(
        json.dumps(trusted, indent=2, sort_keys=True), encoding="utf-8")
    revoked_dict = (revoked.to_dict() if isinstance(revoked, RevokedLists)
                    else {"revoked_key_ids": [], "revoked_pack_versions": []})
    (Path(directory) / "revoked.json").write_text(
        json.dumps(revoked_dict, indent=2, sort_keys=True), encoding="utf-8")
    return {e["key_id"]: base64.b64decode(e["public_key"]) for e in trusted["keys"]}


def _write_pack(directory, pack_dict, private_key=None, name="testpack"):
    directory = Path(directory)
    pack_path = directory / f"{name}.json"
    pack_path.write_text(json.dumps(pack_dict, indent=2, sort_keys=True),
                         encoding="utf-8")
    if private_key is not None:
        envelope = sign_pack_dict(pack_dict, private_key)
        pack_path.with_suffix(".sig").write_text(
            json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")
        return pack_path, envelope
    return pack_path, None


class TestValidPackLoads(unittest.TestCase):
    def test_valid_signed_pack_loads(self):
        priv, _ = generate_pack_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            trusted = _write_trust_files(tmp, [priv])
            pack_path, _ = _write_pack(tmp, _base_pack(), priv)
            loaded = load_pack(pack_path, trusted_keys=trusted, revoked=EMPTY_REVOKED)
            self.assertEqual(loaded.name, "testpack")
            self.assertEqual(loaded.version, "0.1.0")

    def test_valid_pack_loads_via_sibling_trust_files(self):
        # The production path: no explicit trust args, trust discovered
        # from trusted_keys.json / revoked.json next to the pack.
        priv, _ = generate_pack_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            _write_trust_files(tmp, [priv])
            pack_path, _ = _write_pack(tmp, _base_pack(), priv)
            loaded = load_pack(pack_path)
            self.assertEqual(loaded.name, "testpack")

    def test_shipped_packs_load_with_shipped_signatures(self):
        packs = load_pack_directory(ROOT / "packs")
        self.assertEqual(set(packs), {"github", "gemini"})
        self.assertEqual(packs["github"].version, "0.1.0")
        self.assertEqual(packs["gemini"].version, "0.1.0")

    def test_directory_load_skips_trust_files(self):
        # trusted_keys.json / revoked.json must not be parsed as packs.
        packs = load_pack_directory(ROOT / "packs")
        self.assertNotIn("trusted_keys", packs)
        self.assertNotIn("revoked", packs)

    def test_test_keys_never_equal_shipped_key(self):
        shipped = json.loads((ROOT / "packs" / "trusted_keys.json").read_text())
        shipped_pubs = {e["public_key"] for e in shipped["keys"]}
        priv, pub = generate_pack_keypair()
        self.assertNotIn(base64.b64encode(pub).decode("ascii"), shipped_pubs)
        self.assertNotIn(pack_key_id(pub), {e["key_id"] for e in shipped["keys"]})


class TestRefusals(unittest.TestCase):
    def test_tampered_pack_refused(self):
        priv, _ = generate_pack_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            trusted = _write_trust_files(tmp, [priv])
            pack_path, _ = _write_pack(tmp, _base_pack(), priv)
            tampered = json.loads(pack_path.read_text())
            tampered["endpoints"] = []  # content changed after signing
            pack_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(PackRefusedError):
                load_pack(pack_path, trusted_keys=trusted, revoked=EMPTY_REVOKED)

    def test_tampered_and_rehashed_pack_refused(self):
        # Recomputing content_sha256 after tampering fixes the hash but
        # not the signature: the signature binds the original bytes.
        priv, _ = generate_pack_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            trusted = _write_trust_files(tmp, [priv])
            pack_path, _ = _write_pack(tmp, _base_pack(), priv)
            tampered = json.loads(pack_path.read_text())
            tampered["endpoints"] = []
            tampered = finalise_pack(
                {k: v for k, v in tampered.items() if k != "content_sha256"})
            pack_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(PackRefusedError):
                load_pack(pack_path, trusted_keys=trusted, revoked=EMPTY_REVOKED)

    def test_corrupt_hash_field_refused_despite_signature(self):
        priv, _ = generate_pack_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            trusted = _write_trust_files(tmp, [priv])
            pack_path, _ = _write_pack(tmp, _base_pack(), priv)
            tampered = json.loads(pack_path.read_text())
            tampered["content_sha256"] = "0" * 64
            pack_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaises(PackRefusedError):
                load_pack(pack_path, trusted_keys=trusted, revoked=EMPTY_REVOKED)

    def test_wrong_key_pack_refused(self):
        signer, _ = generate_pack_keypair()
        other, _ = generate_pack_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            # Trust file lists ONLY the other key, not the signer.
            trusted = _write_trust_files(tmp, [other])
            pack_path, _ = _write_pack(tmp, _base_pack(), signer)
            with self.assertRaises(PackRefusedError):
                load_pack(pack_path, trusted_keys=trusted, revoked=EMPTY_REVOKED)

    def test_revoked_key_refused(self):
        priv, pub = generate_pack_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            trusted = _write_trust_files(tmp, [priv])
            pack_path, _ = _write_pack(tmp, _base_pack(), priv)
            revoked = RevokedLists(frozenset({pack_key_id(pub)}), frozenset())
            with self.assertRaises(PackRefusedError):
                load_pack(pack_path, trusted_keys=trusted, revoked=revoked)

    def test_revoked_pack_version_refused(self):
        priv, _ = generate_pack_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            trusted = _write_trust_files(tmp, [priv])
            pack_path, _ = _write_pack(tmp, _base_pack(), priv)
            revoked = RevokedLists(
                frozenset(), frozenset({("testpack", "0.1.0")}))
            with self.assertRaises(PackRefusedError):
                load_pack(pack_path, trusted_keys=trusted, revoked=revoked)

    def test_unsigned_pack_refused_after_flip(self):
        # No .sig file at all: refused, never hash-only loaded.
        priv, _ = generate_pack_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            trusted = _write_trust_files(tmp, [priv])
            pack_path, _ = _write_pack(tmp, _base_pack(), private_key=None)
            with self.assertRaises(PackRefusedError):
                load_pack(pack_path, trusted_keys=trusted, revoked=EMPTY_REVOKED)

    def test_missing_trust_files_refused(self):
        priv, _ = generate_pack_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            # Pack + signature present, but no trusted_keys.json /
            # revoked.json anywhere resolvable: unknown trust state.
            pack_path, _ = _write_pack(tmp, _base_pack(), priv)
            with self.assertRaises(PackRefusedError):
                load_pack(pack_path)

    def test_malformed_signature_refused(self):
        priv, _ = generate_pack_keypair()
        cases = [
            {"algorithm": "Ed25519", "key_id": "pk-xxx", "signature": "!!!not-base64!!!"},
            {"algorithm": "RSA", "key_id": "pk-xxx", "signature": "AAAA"},
            {"algorithm": "Ed25519", "key_id": "pk-xxx",
             "signature": base64.b64encode(b"\x00" * 64).decode("ascii")},
            "not-an-object",
        ]
        for bad_envelope in cases:
            with tempfile.TemporaryDirectory() as tmp:
                trusted = _write_trust_files(tmp, [priv])
                pack_path, _ = _write_pack(tmp, _base_pack(), priv)
                pack_path.with_suffix(".sig").write_text(
                    json.dumps(bad_envelope), encoding="utf-8")
                with self.subTest(envelope=bad_envelope):
                    with self.assertRaises(PackRefusedError):
                        load_pack(pack_path, trusted_keys=trusted,
                                  revoked=EMPTY_REVOKED)

    def test_revocation_beats_trust_when_key_listed_and_revoked(self):
        priv, pub = generate_pack_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            trusted = _write_trust_files(tmp, [priv])
            pack_path, _ = _write_pack(tmp, _base_pack(), priv)
            # Key is BOTH trusted and revoked: revocation wins.
            revoked = RevokedLists(frozenset({pack_key_id(pub)}), frozenset())
            with self.assertRaises(PackRefusedError):
                load_pack(pack_path, trusted_keys=trusted, revoked=revoked)

    def test_parse_pack_alone_is_not_disk_trust(self):
        # Documented boundary: parse_pack (hash-only, in-memory) still
        # parses a valid-hash dict, but the same unsigned bytes on
        # disk are refused by load_pack. No silent fallback exists.
        pack = _base_pack()
        parsed = parse_pack(pack)
        self.assertEqual(parsed.name, "testpack")
        priv, _ = generate_pack_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            trusted = _write_trust_files(tmp, [priv])
            pack_path, _ = _write_pack(tmp, pack, private_key=None)
            with self.assertRaises(PackRefusedError):
                load_pack(pack_path, trusted_keys=trusted, revoked=EMPTY_REVOKED)


class TestRotation(unittest.TestCase):
    def test_dual_key_rotation(self):
        old_priv, old_pub = generate_pack_keypair()
        new_priv, new_pub = generate_pack_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            trusted = _write_trust_files(tmp, [old_priv, new_priv])
            # Both keys coexist: a pack signed by either loads.
            old_path, _ = _write_pack(tmp, _base_pack(), old_priv, name="oldpack")
            new_pack = _base_pack(name="newpack")
            new_path, _ = _write_pack(tmp, new_pack, new_priv, name="newpack")
            self.assertEqual(load_pack(old_path, trusted_keys=trusted,
                                       revoked=EMPTY_REVOKED).name, "testpack")
            self.assertEqual(load_pack(new_path, trusted_keys=trusted,
                                       revoked=EMPTY_REVOKED).name, "newpack")
            # After the old key is revoked, old-signed packs refuse
            # while new-signed packs keep loading.
            revoked = RevokedLists(frozenset({pack_key_id(old_pub)}), frozenset())
            with self.assertRaises(PackRefusedError):
                load_pack(old_path, trusted_keys=trusted, revoked=revoked)
            self.assertEqual(load_pack(new_path, trusted_keys=trusted,
                                       revoked=revoked).name, "newpack")

    def test_verify_returns_signer_key_id(self):
        priv, pub = generate_pack_keypair()
        pack = _base_pack()
        envelope = sign_pack_dict(pack, priv)
        trusted = {pack_key_id(pub): pub}
        signer = verify_pack_signature(pack, envelope, trusted, EMPTY_REVOKED)
        self.assertEqual(signer, pack_key_id(pub))


class TestSignScript(unittest.TestCase):
    def test_verify_script_accepts_shipped_packs(self):
        for name in ("github", "gemini"):
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "sign_pack.py"),
                 "verify", str(ROOT / "packs" / f"{name}.json")],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertIn("OK", result.stdout)

    def test_script_gen_key_sign_verify_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            key_path = tmp / "signing.pem"
            gen = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "sign_pack.py"),
                 "gen-key", "--out", str(key_path)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(gen.returncode, 0, msg=gen.stderr)
            import stat as _stat
            self.assertEqual(_stat.S_IMODE(key_path.stat().st_mode), 0o600)
            # Build the trusted_keys.json from the script's pubkey output.
            pub = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "sign_pack.py"),
                 "pubkey", "--key", str(key_path)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(pub.returncode, 0, msg=pub.stderr)
            entry = json.loads(pub.stdout)
            (tmp / "trusted_keys.json").write_text(
                json.dumps({"keys": [entry]}), encoding="utf-8")
            (tmp / "revoked.json").write_text(
                json.dumps({"revoked_key_ids": [], "revoked_pack_versions": []}),
                encoding="utf-8")
            pack_path = tmp / "roundtrip.json"
            pack_path.write_text(json.dumps(_base_pack()), encoding="utf-8")
            sign = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "sign_pack.py"),
                 "sign", str(pack_path), "--key", str(key_path)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(sign.returncode, 0, msg=sign.stderr)
            verify = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "sign_pack.py"),
                 "verify", str(pack_path)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(verify.returncode, 0, msg=verify.stderr)
            # Tamper, then verify must refuse (exit 1).
            tampered = json.loads(pack_path.read_text())
            tampered["endpoints"] = []
            pack_path.write_text(json.dumps(tampered), encoding="utf-8")
            refused = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "sign_pack.py"),
                 "verify", str(pack_path)],
                capture_output=True, text=True, timeout=60)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("REFUSED", refused.stderr)


if __name__ == "__main__":
    unittest.main()
