"""Provider pack loading, hash verification, and Ed25519 pack signing (W04/W05).

Packs are JSON files in ``packs/`` with ``name``, ``version``,
``content_sha256`` and ``endpoints[]`` (method, path pattern, class,
level, spend flag, body schema name), plus the pack-level fields the
engine needs: ``read_like_posts``, ``body_schemas``, ``issued_at``,
``max_age_days`` and ``spend_alerts_estimated``.

Two independent checks gate every disk load (CONTRACT section 13.3,
the v0.2 flip from hash-only verification):

1. Content hash: ``content_sha256`` is the SHA-256 of the canonical
   JSON (sorted keys, compact separators, UTF-8) of the pack object
   with the ``content_sha256`` field itself removed.
2. Detached signature: ``packs/<name>.sig`` holds a JSON envelope
   ``{"algorithm": "Ed25519", "key_id": ..., "signature": <base64>}``
   where the signature is Ed25519 over exactly the canonical bytes
   the hash covers (the pack minus ``content_sha256``). The envelope
   form is a deliberate, disclosed choice over a bare base64 blob: it
   binds the signature to one key ID so revocation is checked
   explicitly before cryptography runs and the signer is auditable.
   The signature bytes themselves are base64 Ed25519, as specified.

A pack that fails EITHER check is REFUSED, never loaded. There is no
warn-and-continue path and no silent fallback to an unsigned or
hash-only pack: ``load_pack`` / ``load_pack_directory`` always
require a signature. ``parse_pack`` is the exception, and it is
deliberately narrow: it verifies the hash of an already-in-memory
dict (used by tests building packs in memory). It is NOT a trust
boundary for disk packs -- any pack read from disk must go through
``load_pack``.

Trust files (both required for a signed load; a missing file means
"trust state unknown", not "nothing to check", so the load is
refused):

* ``packs/trusted_keys.json``: ``{"keys": [{"key_id", "algorithm",
  "public_key": <base64 raw 32-byte Ed25519 public key>}]}``. A
  key ID must equal the derived ID for its public key (see
  :func:`pack_key_id`); a mislabelled entry refuses the whole file.
  Two keys may coexist during rotation: a pack signed by EITHER
  trusted, non-revoked key loads.
* ``packs/revoked.json``: ``{"revoked_key_ids": [...],
  "revoked_pack_versions": [{"name", "version"}, ...]}``. Revocation
  beats trust: a revoked key's packs are refused even if the hash
  and signature are otherwise valid, and a revoked (name, version)
  pair is refused whoever signed it. An empty revoked file is the
  explicit "nothing revoked" statement.

Key IDs for pack-signing keys are ``"pk-" + first 16 hex of
SHA-256(raw public key)``. They are unrelated to vault key IDs.

Tier statement (honest limits, cf. v3 N-G11 / f16-S7): pack signing
detects tampering with pack files by anyone who cannot also rewrite
``trusted_keys.json``. It does NOT survive a Tier B agent (or a
compromised commit) that rewrites both a pack and the trust file --
the trust anchor is repo review / commit integrity, and a valid
signature proves "these bytes match a listed key", never "this pack
was authorised". Signing helpers live here; the signing CLI is
``scripts/sign_pack.py`` and the ceremony is ``packs/SIGNING.md``.

Test packs use test-generated keys and live under ``tests/``
fixtures, never in ``packs/`` (CONTRACT section 13.3). Tests must
never use the shipped trusted key.

This module is stdlib-only except for Ed25519, which comes from the
already-pinned ``cryptography`` dependency and is imported lazily:
if it is unavailable, signed loads fail closed (``PackRefusedError``)
and hash-only ``parse_pack`` still works.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .policy import EndpointRule, ProviderPack

try:  # cryptography is a pinned dependency; fail closed without it.
    from cryptography.exceptions import InvalidSignature as _InvalidSignature
    from cryptography.hazmat.primitives import serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _Ed25519PrivateKey,
        Ed25519PublicKey as _Ed25519PublicKey,
    )

    _CRYPTO_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only without the dep
    _InvalidSignature = None  # type: ignore[assignment]
    _serialization = None  # type: ignore[assignment]
    _Ed25519PrivateKey = None  # type: ignore[assignment]
    _Ed25519PublicKey = None  # type: ignore[assignment]
    _CRYPTO_AVAILABLE = False

REQUIRED_PACK_FIELDS = ("name", "version", "content_sha256", "endpoints")
REQUIRED_ENDPOINT_FIELDS = ("method", "path_pattern", "capability", "level")
VALID_CAPABILITIES = ("read_public", "read_account", "write", "destructive", "financial")
VALID_LEVELS = (1, 2, 3, 4)

SIGNATURE_ALGORITHM = "Ed25519"
TRUSTED_KEYS_FILENAME = "trusted_keys.json"
REVOKED_FILENAME = "revoked.json"
# Trust files are not packs; directory loads must skip them.
_NON_PACK_FILENAMES = frozenset({TRUSTED_KEYS_FILENAME, REVOKED_FILENAME})


class PackRefusedError(ValueError):
    """A pack was refused: hash/signature mismatch, revocation, or bad shape."""


# ---------------------------------------------------------------- canonical

def canonical_json(obj: object) -> bytes:
    """Canonical JSON bytes: sorted keys, compact separators, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_content_hash(pack_dict: dict) -> str:
    """SHA-256 of the canonical pack JSON with ``content_sha256`` removed."""
    content = {k: v for k, v in pack_dict.items() if k != "content_sha256"}
    return hashlib.sha256(canonical_json(content)).hexdigest()


def signing_canonical_bytes(pack_dict: dict) -> bytes:
    """The exact bytes a pack signature covers.

    Identical to the hash preimage: canonical JSON of the pack with
    ``content_sha256`` removed. One byte string serves both checks, so
    a signature cannot be valid for bytes whose hash does not match.
    """
    content = {k: v for k, v in pack_dict.items() if k != "content_sha256"}
    return canonical_json(content)


def finalise_pack(pack_dict: dict) -> dict:
    """Return a copy of ``pack_dict`` with a correct ``content_sha256``.

    Used when authoring packs (and by tests building fixtures). Loading
    never calls this: loading only verifies.
    """
    finalised = dict(pack_dict)
    finalised["content_sha256"] = compute_content_hash(pack_dict)
    return finalised


# ---------------------------------------------------------------- key IDs

def pack_key_id(public_key_bytes: bytes) -> str:
    """Deterministic key ID for a raw 32-byte Ed25519 public key."""
    if not isinstance(public_key_bytes, (bytes, bytearray)) or len(public_key_bytes) != 32:
        raise PackRefusedError("pack-signing public key must be 32 raw bytes")
    return "pk-" + hashlib.sha256(bytes(public_key_bytes)).hexdigest()[:16]


def _b64decode(data: object, *, what: str) -> bytes:
    if not isinstance(data, str):
        raise PackRefusedError(f"{what} is not a base64 string")
    try:
        return base64.b64decode(data.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise PackRefusedError(f"{what} is not valid base64: {exc}") from exc


# ---------------------------------------------------------------- trust files

def parse_trusted_keys(trusted_dict: dict, *, source: str = "<trusted_keys>") -> dict[str, bytes]:
    """Validate a parsed ``trusted_keys.json`` object.

    Returns ``{key_id: raw public key bytes}``. Any malformed entry,
    duplicate ID, non-Ed25519 algorithm, wrong-length key, or key ID
    that does not match the derived ID for its public key refuses
    the whole file -- a partially trusted trust file is not trusted.
    """
    if not isinstance(trusted_dict, dict) or not isinstance(trusted_dict.get("keys"), list):
        raise PackRefusedError(f"trusted keys {source} is not an object with a 'keys' list")
    trusted: dict[str, bytes] = {}
    for entry in trusted_dict["keys"]:
        if not isinstance(entry, dict):
            raise PackRefusedError(f"trusted keys {source} has a non-object entry")
        key_id = entry.get("key_id")
        algorithm = entry.get("algorithm")
        public_b64 = entry.get("public_key")
        if algorithm != SIGNATURE_ALGORITHM:
            raise PackRefusedError(
                f"trusted keys {source} entry has unsupported algorithm: {algorithm!r}"
            )
        if not isinstance(key_id, str) or not key_id:
            raise PackRefusedError(f"trusted keys {source} entry has no key_id")
        public_key = _b64decode(public_b64, what=f"trusted keys {source} public_key")
        if len(public_key) != 32:
            raise PackRefusedError(
                f"trusted keys {source} entry {key_id} public key is not 32 bytes"
            )
        if pack_key_id(public_key) != key_id:
            raise PackRefusedError(
                f"trusted keys {source} entry key_id {key_id} does not match its public key"
            )
        if key_id in trusted:
            raise PackRefusedError(f"trusted keys {source} has duplicate key_id: {key_id}")
        trusted[key_id] = public_key
    return trusted


def load_trusted_keys(path: str | Path) -> dict[str, bytes]:
    """Load and validate a ``trusted_keys.json`` file."""
    path = Path(path)
    try:
        trusted_dict = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PackRefusedError(f"cannot read trusted keys {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PackRefusedError(f"trusted keys {path} is not valid JSON: {exc}") from exc
    return parse_trusted_keys(trusted_dict, source=str(path))


@dataclass(frozen=True)
class RevokedLists:
    """Revocation state. Empty sets are the explicit 'nothing revoked'."""

    revoked_key_ids: frozenset = frozenset()
    revoked_pack_versions: frozenset = frozenset()  # (name, version) pairs

    @classmethod
    def from_dict(cls, data: dict, *, source: str = "<revoked>") -> "RevokedLists":
        if not isinstance(data, dict):
            raise PackRefusedError(f"revoked list {source} is not an object")
        key_ids = data.get("revoked_key_ids", [])
        versions = data.get("revoked_pack_versions", [])
        if not isinstance(key_ids, list) or not all(isinstance(k, str) for k in key_ids):
            raise PackRefusedError(f"revoked list {source} revoked_key_ids is not a string list")
        if not isinstance(versions, list):
            raise PackRefusedError(
                f"revoked list {source} revoked_pack_versions is not a list"
            )
        pairs = set()
        for entry in versions:
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("name"), str)
                or not isinstance(entry.get("version"), str)
            ):
                raise PackRefusedError(
                    f"revoked list {source} has a malformed revoked_pack_versions entry"
                )
            pairs.add((entry["name"], entry["version"]))
        return cls(frozenset(key_ids), frozenset(pairs))

    def to_dict(self) -> dict:
        return {
            "revoked_key_ids": sorted(self.revoked_key_ids),
            "revoked_pack_versions": [
                {"name": name, "version": version}
                for name, version in sorted(self.revoked_pack_versions)
            ],
        }


def load_revoked(path: str | Path) -> RevokedLists:
    """Load and validate a ``revoked.json`` file."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PackRefusedError(f"cannot read revoked list {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PackRefusedError(f"revoked list {path} is not valid JSON: {exc}") from exc
    return RevokedLists.from_dict(data, source=str(path))


def _resolve_trusted_keys(
    trusted_keys, *, sibling: Path, source: str
) -> dict[str, bytes]:
    """Resolve the ``trusted_keys`` argument for one load.

    Accepts a ``{key_id: raw bytes | base64 str}`` mapping, a path to
    a trusted-keys JSON file, or ``None`` (sibling
    ``trusted_keys.json`` next to the pack). A missing trust file is
    a refusal, never an empty trust set.
    """
    if trusted_keys is None:
        candidate = sibling / TRUSTED_KEYS_FILENAME
        if not candidate.is_file():
            raise PackRefusedError(
                f"pack {source} refused: no trusted-keys file resolvable "
                f"(looked for {candidate}); unsigned/unanchored packs are never loaded"
            )
        return load_trusted_keys(candidate)
    if isinstance(trusted_keys, (str, Path)):
        return load_trusted_keys(trusted_keys)
    if isinstance(trusted_keys, dict):
        resolved: dict[str, bytes] = {}
        for key_id, public in trusted_keys.items():
            raw = public if isinstance(public, (bytes, bytearray)) else _b64decode(
                public, what="trusted_keys mapping public_key"
            )
            if len(raw) != 32:
                raise PackRefusedError(f"trusted key {key_id} public key is not 32 bytes")
            if pack_key_id(bytes(raw)) != key_id:
                raise PackRefusedError(
                    f"trusted key {key_id} does not match its public key"
                )
            resolved[key_id] = bytes(raw)
        return resolved
    raise PackRefusedError("trusted_keys must be a mapping, a path, or None")


def _resolve_revoked(revoked, *, sibling: Path, source: str) -> RevokedLists:
    """Resolve the ``revoked`` argument. Same missing-file rule as trust."""
    if revoked is None:
        candidate = sibling / REVOKED_FILENAME
        if not candidate.is_file():
            raise PackRefusedError(
                f"pack {source} refused: no revoked list resolvable "
                f"(looked for {candidate}); revocation state unknown is never treated as clean"
            )
        return load_revoked(candidate)
    if isinstance(revoked, RevokedLists):
        return revoked
    if isinstance(revoked, (str, Path)):
        return load_revoked(revoked)
    if isinstance(revoked, dict):
        return RevokedLists.from_dict(revoked, source="revoked argument")
    raise PackRefusedError("revoked must be a RevokedLists, a mapping, a path, or None")


# ---------------------------------------------------------------- signing

def _require_crypto() -> None:
    if not _CRYPTO_AVAILABLE:
        raise PackRefusedError(
            "Ed25519 verification unavailable: the pinned 'cryptography' "
            "dependency is not installed; signed pack loads fail closed"
        )


def generate_pack_keypair():
    """Generate a fresh Ed25519 pack-signing keypair (test/ceremony use).

    Returns ``(private_key, raw_public_key_bytes)``. The private key
    object is never serialised by this module; ``scripts/sign_pack.py``
    handles PEM output with 0600 permissions, and the ceremony in
    ``packs/SIGNING.md`` governs custody. Never use a shipped trusted
    key in tests -- tests call this to make their own key.
    """
    _require_crypto()
    private_key = _Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        _serialization.Encoding.Raw, _serialization.PublicFormat.Raw
    )
    return private_key, public_bytes


def private_key_to_pem(private_key) -> bytes:
    """Serialise a private key as unencrypted PKCS#8 PEM (ceremony use only)."""
    _require_crypto()
    return private_key.private_bytes(
        _serialization.Encoding.PEM,
        _serialization.PrivateFormat.PKCS8,
        _serialization.NoEncryption(),
    )


def private_key_from_pem(pem_bytes: bytes):
    """Load an unencrypted PKCS#8 PEM private key; refuses anything else."""
    _require_crypto()
    try:
        private_key = _serialization.load_pem_private_key(pem_bytes, password=None)
    except (ValueError, TypeError) as exc:
        raise PackRefusedError(f"cannot load pack-signing private key: {exc}") from exc
    if not isinstance(private_key, _Ed25519PrivateKey):
        raise PackRefusedError("pack-signing private key is not Ed25519")
    return private_key


def public_key_bytes(private_key) -> bytes:
    """Raw 32-byte public key for a private key object."""
    _require_crypto()
    return private_key.public_key().public_bytes(
        _serialization.Encoding.Raw, _serialization.PublicFormat.Raw
    )


def sign_pack_dict(pack_dict: dict, private_key) -> dict:
    """Sign a finalised pack dict. Returns the ``.sig`` envelope dict.

    Refuses to sign a pack whose recorded ``content_sha256`` does not
    match its content: sign only finalised packs (see
    :func:`finalise_pack`), never a stale-hash pack.
    """
    _require_crypto()
    if not isinstance(pack_dict, dict) or "content_sha256" not in pack_dict:
        raise PackRefusedError("cannot sign a pack without a content_sha256 field")
    if pack_dict["content_sha256"] != compute_content_hash(pack_dict):
        raise PackRefusedError(
            "cannot sign a pack whose content_sha256 does not match its content; "
            "finalise the pack first"
        )
    public_bytes = public_key_bytes(private_key)
    signature = private_key.sign(signing_canonical_bytes(pack_dict))
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": pack_key_id(public_bytes),
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_pack_signature(
    pack_dict: dict,
    envelope: dict,
    trusted_keys: dict[str, bytes],
    revoked: RevokedLists,
) -> str:
    """Verify one pack's signature envelope. Returns the signer key_id.

    Order is deliberate: envelope shape, algorithm, signer trusted,
    signer NOT revoked, pack version NOT revoked, then cryptography.
    Revocation beats trust at every step. Raises
    :class:`PackRefusedError` on any failure; never returns False.
    """
    _require_crypto()
    if not isinstance(envelope, dict):
        raise PackRefusedError("pack signature envelope is not an object")
    if envelope.get("algorithm") != SIGNATURE_ALGORITHM:
        raise PackRefusedError(
            f"pack signature algorithm is not {SIGNATURE_ALGORITHM}: "
            f"{envelope.get('algorithm')!r}"
        )
    key_id = envelope.get("key_id")
    if not isinstance(key_id, str) or key_id not in trusted_keys:
        raise PackRefusedError(
            f"pack signature key_id is not a trusted key: {key_id!r}"
        )
    if key_id in revoked.revoked_key_ids:
        raise PackRefusedError(f"pack signature key is revoked: {key_id}")
    name = pack_dict.get("name")
    version = pack_dict.get("version")
    if (name, version) in revoked.revoked_pack_versions:
        raise PackRefusedError(f"pack version is revoked: {name} {version}")
    signature = _b64decode(envelope.get("signature"), what="pack signature")
    if len(signature) != 64:
        raise PackRefusedError("pack signature is not 64 bytes")
    public_key = _Ed25519PublicKey.from_public_bytes(trusted_keys[key_id])
    try:
        public_key.verify(signature, signing_canonical_bytes(pack_dict))
    except _InvalidSignature as exc:
        raise PackRefusedError(
            "pack signature verification failed: signature does not match pack content"
        ) from exc
    return key_id


# ---------------------------------------------------------------- loading

def parse_pack(pack_dict: dict, *, source: str = "<dict>") -> ProviderPack:
    """Verify the hash of and parse an already-loaded pack dict.

    Hash-only: this checks ``content_sha256`` and structure, but NOT
    a signature. It is the parsing primitive for in-memory packs
    (tests, policy-engine construction). It is NOT sufficient for
    disk trust -- packs read from disk must go through
    :func:`load_pack`, which additionally verifies the signature,
    trust, and revocation. Same refusal rules for hash/structure.
    """
    if not isinstance(pack_dict, dict):
        raise PackRefusedError(f"pack {source} is not a JSON object")
    for field_name in REQUIRED_PACK_FIELDS:
        if field_name not in pack_dict:
            raise PackRefusedError(f"pack {source} missing field: {field_name}")
    expected = compute_content_hash(pack_dict)
    if pack_dict["content_sha256"] != expected:
        raise PackRefusedError(
            f"pack {source} content hash mismatch: recorded hash does not match content; pack refused"
        )
    if not isinstance(pack_dict["endpoints"], list):
        raise PackRefusedError(f"pack {source} endpoints is not a list")
    endpoints = [_parse_endpoint(e, source) for e in pack_dict["endpoints"]]
    read_like = [
        _parse_endpoint(e, source) for e in pack_dict.get("read_like_posts", [])
    ]
    body_schemas = pack_dict.get("body_schemas", {})
    if not isinstance(body_schemas, dict):
        raise PackRefusedError(f"pack {source} body_schemas is not an object")
    issued_at = pack_dict.get("issued_at")
    if issued_at is not None and not isinstance(issued_at, str):
        raise PackRefusedError(f"pack {source} issued_at is not a string")
    max_age_days = pack_dict.get("max_age_days", 90)
    if not isinstance(max_age_days, int) or max_age_days < 0:
        raise PackRefusedError(f"pack {source} max_age_days is not a non-negative integer")
    return ProviderPack(
        name=str(pack_dict["name"]),
        version=str(pack_dict["version"]),
        endpoints=endpoints,
        read_like_posts=read_like,
        body_schemas=body_schemas,
        issued_at=issued_at,
        max_age_days=max_age_days,
        spend_alerts_estimated=pack_dict.get("spend_alerts_estimated", {}),
        raw=pack_dict,
    )


def _parse_endpoint(entry: object, source: str) -> EndpointRule:
    if not isinstance(entry, dict):
        raise PackRefusedError(f"pack {source} endpoint is not an object")
    for field_name in REQUIRED_ENDPOINT_FIELDS:
        if field_name not in entry:
            raise PackRefusedError(f"pack {source} endpoint missing field: {field_name}")
    if entry["capability"] not in VALID_CAPABILITIES:
        raise PackRefusedError(
            f"pack {source} endpoint has unknown capability: {entry['capability']!r}"
        )
    if entry["level"] not in VALID_LEVELS:
        raise PackRefusedError(f"pack {source} endpoint has invalid level: {entry['level']!r}")
    if not isinstance(entry["path_pattern"], str) or not entry["path_pattern"].startswith("/"):
        raise PackRefusedError(f"pack {source} endpoint has bad path_pattern: {entry['path_pattern']!r}")
    return EndpointRule(
        method=str(entry["method"]).upper(),
        path_pattern=entry["path_pattern"],
        capability=entry["capability"],
        level=int(entry["level"]),
        spend=bool(entry.get("spend", False)),
        body_schema=entry.get("body_schema"),
    )


def load_pack(
    path: str | Path,
    *,
    trusted_keys=None,
    revoked=None,
) -> ProviderPack:
    """Load a pack from disk with hash AND signature verification.

    The signature file is ``<pack stem>.sig`` next to the pack file
    (``github.json`` -> ``github.sig``). ``trusted_keys`` / ``revoked``
    default to the sibling ``trusted_keys.json`` / ``revoked.json``
    files; either may also be given as a mapping / ``RevokedLists`` /
    path (see the ``_resolve_*`` helpers). A pack with no signature
    file, an untrusted or revoked signer, a revoked version, or a
    missing trust file is REFUSED -- there is no hash-only fallback.
    """
    path = Path(path)
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PackRefusedError(f"cannot read pack {path}: {exc}") from exc
    try:
        pack_dict = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise PackRefusedError(f"pack {path} is not valid JSON: {exc}") from exc
    # Hash + structure first (parse_pack), then signature + trust.
    pack = parse_pack(pack_dict, source=str(path))
    sig_path = path.with_suffix(".sig")
    if not sig_path.is_file():
        raise PackRefusedError(
            f"pack {path} refused: unsigned pack (no signature file {sig_path}); "
            "unsigned packs are never loaded"
        )
    try:
        envelope = json.loads(sig_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PackRefusedError(f"cannot read pack signature {sig_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PackRefusedError(f"pack signature {sig_path} is not valid JSON: {exc}") from exc
    trusted = _resolve_trusted_keys(trusted_keys, sibling=path.parent, source=str(path))
    revoked_lists = _resolve_revoked(revoked, sibling=path.parent, source=str(path))
    verify_pack_signature(pack_dict, envelope, trusted, revoked_lists)
    return pack


def load_pack_directory(
    directory: str | Path,
    *,
    trusted_keys=None,
    revoked=None,
) -> dict[str, ProviderPack]:
    """Load every ``*.json`` pack in a directory, keyed by pack name.

    ``trusted_keys.json`` and ``revoked.json`` are trust files, not
    packs, and are skipped (they used to be misparsed as packs before
    this module distinguished them). Any single refusal aborts the
    whole load: a partially loaded pack set must never serve decisions.
    Trust files given explicitly apply to every pack in the directory.
    """
    directory = Path(directory)
    trusted = _resolve_trusted_keys(trusted_keys, sibling=directory, source=str(directory))
    revoked_lists = _resolve_revoked(revoked, sibling=directory, source=str(directory))
    packs: dict[str, ProviderPack] = {}
    for pack_path in sorted(directory.glob("*.json")):
        if pack_path.name in _NON_PACK_FILENAMES:
            continue
        pack = load_pack(pack_path, trusted_keys=trusted, revoked=revoked_lists)
        if pack.name in packs:
            raise PackRefusedError(f"duplicate pack name: {pack.name}")
        packs[pack.name] = pack
    return packs


__all__ = [
    "PackRefusedError",
    "RevokedLists",
    "SIGNATURE_ALGORITHM",
    "TRUSTED_KEYS_FILENAME",
    "REVOKED_FILENAME",
    "canonical_json",
    "compute_content_hash",
    "signing_canonical_bytes",
    "finalise_pack",
    "pack_key_id",
    "parse_trusted_keys",
    "load_trusted_keys",
    "load_revoked",
    "generate_pack_keypair",
    "private_key_to_pem",
    "private_key_from_pem",
    "public_key_bytes",
    "sign_pack_dict",
    "verify_pack_signature",
    "parse_pack",
    "load_pack",
    "load_pack_directory",
]
