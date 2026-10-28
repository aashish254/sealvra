"""Keyholder v0.1 — low-level crypto primitives (W02).

Tier statement (CONTRACT §10): these primitives are pure computation.
They provide NO Tier B (same-user-process) separation on their own.
Separation comes only from the platform store holding each compartment's
wrapping key (macOS keychain access groups, Tier A+B) or, on
Linux/Windows, from user-scoped storage (Tier A only — see
``vault.storage_tier`` and ``vault.posture_text``).

Construction (CONTRACT §5, v3 N-D5):
- Body: AES-256-GCM, 96-bit random nonce, never reused (fresh
  ``os.urandom(12)`` per encryption; uniqueness is tested, not assumed).
- Header AEAD: key derived from the compartment wrapping key via
  HKDF-SHA256 with a distinct info string per use; AAD =
  (key_id, provider, compartment_version, header field names).
- Body AAD = the same tuple plus ``auth_scheme`` (v3 N-D5).
- Backup containers use their own distinct HKDF info strings and
  include a ``"backup"`` marker in their AAD, so a backup blob can
  never be replayed as a live compartment (or vice versa).
- Password mode: Argon2id, m=64 MiB, t=3, p=1, via argon2-cffi.
  There is NO fallback KDF. If argon2-cffi or cryptography is
  unavailable this module fails closed (see ``CryptoUnavailable``):
  a home-made cipher or scrypt substitution is never silently used.

v0.2 — normative header AEAD specification (f07 H2, v3 N-D5; the
single source of truth is ``HEADER_AEAD_SPEC`` plus ``header_aad`` /
``body_aad`` below, which ``vault.py`` calls instead of re-implementing
the AAD — spec and implementation cannot drift apart):
- Cipher: AES-256-GCM, 128-bit tag appended to the ciphertext by
  ``cryptography``'s AESGCM. Key length is always 32 bytes.
- KDF: HKDF-SHA256, salt=None (``cryptography`` treats None as zeros
  of hash length), output length 32, info strings exactly as listed in
  ``HEADER_AEAD_SPEC["info"]`` — one info string per use, never reused
  across header/body or live/backup roles. Header key != body key is
  asserted at envelope build time (fail closed on the impossible).
- Nonce: 96-bit, fresh ``os.urandom(12)`` per encryption, stored in
  the envelope next to its ciphertext. Header and body nonces are drawn
  independently AND use independently derived keys, so a (key, nonce)
  pair is never reused even if the two draws collided; ``vault.py``
  additionally re-draws the body nonce if it equals the header nonce
  inside one envelope. Random-nonce volume bound (NIST SP 800-38D):
  2**32 invocations per key; vault volumes (create/rotate/restore)
  are orders of magnitude below it, and no per-key counter is stored
  in the v0.1/v0.2 envelope format — a counter would be a format
  change (KHCOMP2) and is recorded as future work, not silently
  claimed here.
- AAD encoding: canonical JSON — ``json.dumps(obj, sort_keys=True,
  separators=(",", ":"))`` — of a list. Header AAD =
  ``marker + [key_id, provider, compartment_version, header_fields]``;
  body AAD = header AAD list plus ``auth_scheme``. ``marker`` is []
  for live compartments, ``["backup"]`` for single-factor backup
  containers, and ``["backup", "recovery", factor]`` for each wrapping
  of a dual-factor (KHBACKUP2) container, where ``factor`` is
  ``"primary"`` or ``"recovery"``. ``header_fields`` is the sorted list
  of the header plaintext's keys, so every header field — including
  ``auth_scheme`` (f07 M2) and, for dual wrappings, ``wrapping`` — is
  authenticated by both the header tag and (via the AAD list) the body
  tag. Changing any header field, the format marker, or the factor
  label fails authentication.
- Verification order (mandatory, f07 H2): decrypt and authenticate the
  header FIRST, check the decrypted header's key_id / provider /
  version / auth_scheme / field list against the envelope's plaintext
  metadata, and only then decrypt the body. No header field is USED
  for any security decision before header verification. The only
  exception is display: ``vault.get_metadata`` / ``list_compartments``
  copy plaintext metadata without verification and mark every entry
  ``header_verified: False`` — display-only, never a security input.
- Argon2 input mapping (f07 M1, honestly recorded): this format uses
  password-field = password bytes only and salt = fresh 16-byte
  CSPRNG per compartment. It does NOT use an Argon2 associated-data
  (context) field — the pinned argon2-cffi's ``hash_secret_raw``
  exposes no associated-data parameter, and changing KDF inputs would
  orphan every v0.1 compartment. Context separation is instead
  provided by (a) the fresh per-compartment salt, (b) the distinct
  HKDF info strings, and (c) the AAD binding above: two compartments
  sharing one password still yield different wrapping keys, different
  AEAD keys, and non-interchangeable ciphertexts. A future KHCOMP2
  format that adopts Argon2 AD must be a new format with its own
  migration decision, never a silent change to this one.

No real keys are handled here in tests or fixtures — callers pass
bytes; this module never logs, prints, or stores secret material.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets

try:
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw as _argon2_raw
    from cryptography.exceptions import InvalidTag as _CryptographyInvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes as _hashes
except ImportError as _import_error:  # Fail closed, never substitute.
    _IMPORT_ERROR = _import_error
    _Argon2Type = None  # type: ignore[assignment]
    _argon2_raw = None  # type: ignore[assignment]
    _CryptographyInvalidTag = None  # type: ignore[assignment]
    AESGCM = None  # type: ignore[assignment]
    HKDF = None  # type: ignore[assignment]
    _hashes = None  # type: ignore[assignment]
else:
    _IMPORT_ERROR = None


class CryptoUnavailable(RuntimeError):
    """A required crypto dependency is missing. Fail closed."""


class CryptoTamperError(ValueError):
    """AEAD authentication failed: tampered, wrong key, or wrong AAD."""


def _require_deps() -> None:
    if _IMPORT_ERROR is not None:
        raise CryptoUnavailable(
            "cryptography and argon2-cffi are required; refusing to "
            f"substitute a weaker construction ({_IMPORT_ERROR})"
        )


# Argon2id parameters — CONTRACT §5, exactly. Do not tune silently.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 64 * 1024  # 64 MiB
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16
ARGON2_PARAMS = {
    "type": "argon2id",
    "time_cost": ARGON2_TIME_COST,
    "memory_cost_kib": ARGON2_MEMORY_KIB,
    "parallelism": ARGON2_PARALLELISM,
    "hash_len": ARGON2_HASH_LEN,
}

NONCE_LEN = 12  # 96-bit GCM nonce
WRAPPING_KEY_LEN = 32  # AES-256

# Distinct HKDF info strings per use (v3 N-D5). Never reuse one.
INFO_HEADER = b"keyholder-v1/header"
INFO_BODY = b"keyholder-v1/body"
INFO_BACKUP_HEADER = b"keyholder-v1/backup-header"
INFO_BACKUP_BODY = b"keyholder-v1/backup-body"
# Dual-factor (KHBACKUP2) wrappings reuse the backup info strings but
# are separated from single-factor backups — and from each other — by
# the factor label in the AAD (see header_aad/body_aad). A wrapping
# cannot be transplanted between factors, containers, or roles without
# failing authentication.
INFO_RECOVERY_HEADER = INFO_BACKUP_HEADER
INFO_RECOVERY_BODY = INFO_BACKUP_BODY


def _canonical_json(obj) -> bytes:
    """Canonical JSON bytes: sorted keys, tight separators.

    This is the single AAD encoding for the whole vault. ``vault.py``
    must call ``header_aad`` / ``body_aad``, never re-implement it.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def header_aad(marker, key_id: str, provider: str, version: int, fields) -> bytes:
    """Header AAD: canonical JSON of ``marker + [key_id, provider,
    version, sorted header field names]``. ``marker`` is [] (live),
    ["backup"] (single-factor backup), or ["backup", "recovery",
    factor] (one wrapping of a dual-factor container)."""
    return _canonical_json(list(marker) + [key_id, provider, version, list(fields)])


def body_aad(marker, key_id: str, provider: str, version: int, fields,
             auth_scheme: str) -> bytes:
    """Body AAD: header AAD list plus ``auth_scheme`` (f07 M2)."""
    return _canonical_json(
        list(marker) + [key_id, provider, version, list(fields), auth_scheme]
    )


# Normative header AEAD specification (v3 N-D5, f07 H2). Tests assert
# the implementation matches these values; changing any entry here is
# a format change and must be treated as one (new format, migration
# decision, never a silent edit).
HEADER_AEAD_SPEC = {
    "cipher": "AES-256-GCM",
    "key_bytes": 32,
    "tag_bits": 128,
    "nonce_bits": 96,
    "nonce_source": "os.urandom(12), fresh per encryption, stored in envelope",
    "kdf": "HKDF-SHA256",
    "kdf_salt": None,  # cryptography: None == zeros of hash length
    "kdf_length": 32,
    "info": {
        "live_header": INFO_HEADER,
        "live_body": INFO_BODY,
        "backup_header": INFO_BACKUP_HEADER,
        "backup_body": INFO_BACKUP_BODY,
        "recovery_header": INFO_RECOVERY_HEADER,
        "recovery_body": INFO_RECOVERY_BODY,
    },
    "aad_encoding": 'canonical JSON, sort_keys=True, separators=(",", ":")',
    "header_aad": "marker + [key_id, provider, compartment_version, header_fields]",
    "body_aad": "header_aad_list + [auth_scheme]",
    "markers": {
        "live": [],
        "backup": ["backup"],
        "recovery_primary": ["backup", "recovery", "primary"],
        "recovery_recovery": ["backup", "recovery", "recovery"],
    },
    "verification_order": [
        "decrypt and authenticate header",
        "check decrypted header fields against envelope metadata",
        "decrypt and authenticate body",
    ],
    "nonce_volume_bound": "2**32 invocations per key (NIST SP 800-38D); "
    "vault volumes are orders of magnitude below it",
}


def new_recovery_key() -> bytes:
    """Generate a fresh 32-byte recovery key.

    The caller (broker/UI) must record it offline exactly once and
    never store it in the vault: a recovery key kept next to the
    container it opens is no second factor at all. This function only
    generates; it never stores, logs, or returns the key anywhere else.
    """
    return secrets.token_bytes(32)


def derive_wrapping_key(password: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte wrapping key from a password via Argon2id.

    ``salt`` must be fresh random bytes (16) per compartment; reusing a
    salt across compartments does not merge them (each compartment also
    has its own wrapping key), but fresh salts are mandatory.
    """
    _require_deps()
    if len(salt) < ARGON2_SALT_LEN:
        raise ValueError("salt too short")
    return _argon2_raw(
        secret=password,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=_Argon2Type.ID,
    )


def hkdf_derive(ikm: bytes, info: bytes, length: int = WRAPPING_KEY_LEN) -> bytes:
    """HKDF-SHA256 with a caller-supplied distinct info string."""
    _require_deps()
    return HKDF(algorithm=_hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt. Returns (nonce, ciphertext_with_tag).

    The nonce is fresh 96-bit randomness per call and is never reused
    for the same key: each call draws new entropy.
    """
    _require_deps()
    if len(key) != WRAPPING_KEY_LEN:
        raise ValueError("AES-256 requires a 32-byte key")
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM decrypt; any tamper/wrong-key/wrong-AAD raises."""
    _require_deps()
    if len(key) != WRAPPING_KEY_LEN:
        raise ValueError("AES-256 requires a 32-byte key")
    if len(nonce) != NONCE_LEN:
        raise ValueError("nonce must be 96 bits")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except _CryptographyInvalidTag as exc:
        raise CryptoTamperError("AEAD authentication failed") from exc


def fingerprint(secret: bytes) -> str:
    """Display fingerprint: first 12 hex chars of SHA-256(secret).

    CONTRACT §5 / v3 N-D6: display in the owning key's detail pane
    ONLY. Never in global audit entries, never first/last characters
    of a real key. This function computes the value; callers enforce
    where it may be shown.
    """
    return hashlib.sha256(secret).hexdigest()[:12]


def new_salt() -> bytes:
    return secrets.token_bytes(ARGON2_SALT_LEN)


def zero(bytearray_obj: bytearray) -> None:
    """Best-effort zeroing of a mutable secret buffer."""
    for i in range(len(bytearray_obj)):
        bytearray_obj[i] = 0


def constant_time_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)
