"""Keyholder v0.1 — per-compartment vault (W02).

Implements CONTRACT §5 and v3 N-D1–N-D8, N-S2, N-S3:

- One encrypted compartment per key. NO vault-wide master key, NO
  single DEK, NO master derivation tree (v3 N-D1). Each compartment
  has its own wrapping key, its own version counter, and its own
  backup container. Compromising one compartment's wrapping key opens
  exactly that compartment — tested in ``tests/test_w02_vault.py``.
- Compartments are the FIRST vault format (v3 N-D1 / N-S1): there is
  no v1-format vault to migrate from, so no migration path is built.
  An envelope whose ``format`` is not ``KHCOMP1`` is refused, not
  converted.
- NO vault-wide lock state (v3 N-D4): there is deliberately no
  ``unlock_vault`` / ``lock_vault`` method here. Screen-lock suspend
  and kill-after-15-minutes are broker/session-layer behaviour (W01,
  W03); this module never auto-resumes anything.
- Atomic writes (v3 N-S2, corrected order): snapshot the live file
  FIRST, then temp-file + fsync + rename + directory fsync. The old
  generation is never destroyed before its snapshot exists.
- Restore kills live sessions first (v3 N-S3): see
  :meth:`Vault.restore_compartment` — the broker must either pass an
  empty live-session list or confirm the kill AND supply a
  ``kill_callback`` that performs it. A bare flag with live sessions
  still present is refused.
- Backup export: per-compartment by default; interactive OS auth is
  required every time (control-socket auth alone is never enough);
  synced folders are refused without the exact typed risk
  confirmation; full-vault exports enforce a 24-hour cooldown
  (v3 KS-09, CONTRACT §5).
- Storage honesty (v3 N-D8 / N-H1): on Linux and Windows, per-key
  granularity is broker-side accounting, NOT an OS-enforced gate.
  Only macOS keychain access groups make a per-key gate OS-enforced.
  :meth:`Vault.posture_text` says so in plain words; the doctor and
  posture surfaces (W10/W13) must reproduce it, not soften it.

v0.2 additions (W12; CONTRACT §13.6 file area: this file, crypto.py,
tests/test_w02_vault.py additions only):
- Migration decision, implemented (v3 N-S1 / G0-15, f07 H5): compartments
  (KHCOMP1) are the FIRST vault format — v0.1 shipped them, no
  single-DEK v1 vault ever shipped. There is therefore NO in-place
  converter, and one is never built silently: any envelope whose
  ``format`` is not KHCOMP1 (or a recognised backup format) raises
  :class:`UnsupportedFormatError` naming the decision and the only
  import paths (KHBACKUP1/KHBACKUP2 via restore; anything else is
  re-imported key by key after provider rotation). Stray files in the
  vault directory are never silently ignored: :meth:`Vault.migration_status`
  and :meth:`Vault.rebuild_index` report them, and the broker/doctor
  must call ``migration_status`` at startup (that call site is outside
  this file's area and remains an integration note, not a claim).
- Recovery-key two wrappings, implemented (v3 N-H2 / N-S4, f07 M5):
  :meth:`Vault.export_with_recovery` writes ONE KHBACKUP2 container
  holding two independent wrappings of the same secret — "primary"
  and "recovery" — each with its own salt, HKDF-derived keys, nonces,
  and factor label in the AAD. Either factor alone opens the container
  (OR semantics, stated plainly — this is NOT dual control, and the
  v1 "derived from BOTH, either alone insufficient" contradiction is
  deleted, not reinterpreted). The two factors must differ, and in
  password mode neither may equal the live vault password. A single
  KHBACKUP1 container still restores exactly as in v0.1.
- Password-mode caching discipline, defined and enforced (v3 N-D3,
  f07 H4): one password entry opens ONE compartment, ONCE. The Vault
  object never stores a password, derived key, or secret as instance
  state; every password-mode open derives fresh from the stored salt.
  :meth:`Vault.issue_ticket` / :meth:`Vault.open_with_ticket` make the
  discipline mechanical: a ticket is bound to one key_id and one
  compartment version, is consumed atomically (a failed open still
  consumes it), and its wrapping key is zeroed on consumption. A
  ``bytearray`` password passed to ``issue_ticket`` is zeroed after
  derivation (``bytes`` passwords cannot be zeroed by Python — pass a
  bytearray). With ``strict_password_tickets=True`` the direct
  ``password=`` path of :meth:`Vault.open_secret` is refused and only
  tickets may open password compartments; the default (False) keeps
  the v0.1 API for existing callers, so broker adoption of strict mode
  is a recorded integration step, not a silently assumed one.
- Header AEAD spec completion (v3 N-D5, f07 H2/M2/M3): the normative
  spec lives in ``crypto.HEADER_AEAD_SPEC`` and the AAD is built only
  by ``crypto.header_aad`` / ``crypto.body_aad`` — this module no
  longer constructs AAD by hand. Metadata display functions mark
  their output ``header_verified: False`` (f07 H2: display may copy
  unverified fields, use may not).
- Restore ordering hardened (v3 N-S3): restore now validates the
  backup and the live target BEFORE invoking the kill callback, then
  kills live sessions, then touches compartments. A restore that
  would refuse (bad backup, overwrite refusal, resurrect refusal)
  no longer kills sessions pointlessly; a restore that proceeds
  still kills before any compartment is written. ``restore_all``
  pre-validates every selected container, kills exactly once, then
  writes; unreadable containers are reported as ``skipped``, never
  silently dropped.

Platform-keychain mode: this module does NOT call any OS keychain
API (W13 owns that). In platform mode the caller supplies the
per-key wrapping key bytes obtained from the platform store
(one keychain item per key on macOS). The vault treats that key as
opaque and never derives it from a password.

Password mode: Argon2id m=64 MiB, t=3, p=1 (see ``crypto.py``).
Password mode is strictly weaker (v3 N-D3): a stolen vault password
exposes every compartment derived from it. The posture text says so.

Fingerprint (v3 N-D6): first 12 hex of SHA-256(secret), display in
the owning key's detail pane only — see ``crypto.fingerprint``.
This module never writes a fingerprint into audit-shaped records;
audit pseudonyms are W09's job.

This module never logs, prints, or returns secret material except
through the explicit ``open_secret`` / ``rotate`` return values to
the broker, which owns session memory. File names contain key_ids
only, never secret material.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import re
import tempfile
import time
from pathlib import Path

from .crypto import (
    INFO_BACKUP_BODY,
    INFO_BACKUP_HEADER,
    INFO_BODY,
    INFO_HEADER,
    INFO_RECOVERY_BODY,
    INFO_RECOVERY_HEADER,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    body_aad,
    derive_wrapping_key,
    header_aad,
    hkdf_derive,
    new_salt,
)

PROVIDERS = ("github", "gemini")
_KEY_ID_RE = re.compile(r"^key-[0-9a-f]{16}$")

COMPARTMENT_FORMAT = "KHCOMP1"
BACKUP_FORMAT = "KHBACKUP1"
# Dual-factor recovery container (v0.2, v3 N-H2): one container, two
# independent wrappings ("primary" + "recovery"); either alone opens it.
BACKUP_FORMAT2 = "KHBACKUP2"
RECOVERY_FACTORS = ("primary", "recovery")

# Migration decision (v3 N-S1, f07 H5), stated as data so error text
# and migration_status() cannot drift apart. Compartments are the
# first vault format; there is no in-place conversion from any
# single-DEK vault, ever, in this format generation.
MIGRATION_DECISION = (
    "Compartments (KHCOMP1) are the first vault format; no single-DEK "
    "v1 vault ever shipped, so there is no in-place migration path and "
    "none is performed silently. A KHBACKUP1/KHBACKUP2 container can be "
    "imported with restore_compartment; any other format must be "
    "re-imported key by key after provider rotation — never copied "
    "over a live compartment."
)

# Password-mode caching discipline (v3 N-D3, f07 H4), normative text.
# The Vault object enforces the mechanical parts (no instance-state
# retention, single-use version-bound tickets, strict-mode refusal of
# direct password opens); the broker enforces the human part
# (re-prompt per compartment, per session — never reuse one entry
# across compartments, never cache a password for a later session).
PASSWORD_DISCIPLINE = (
    "Password-mode discipline: one password entry opens ONE compartment, "
    "ONCE. The vault never stores a password, derived wrapping key, or "
    "secret as instance state; every password-mode open derives fresh "
    "from the compartment's stored salt. A password-derived wrapping key "
    "is used for that compartment's open only and is never carried over "
    "to another compartment or a later session — each compartment open "
    "re-prompts. Tickets (issue_ticket/open_with_ticket) make this "
    "mechanical: one ticket, one key_id, one compartment version, "
    "consumed atomically on first use (a failed open still consumes "
    "it). Password mode is strictly weaker than platform-keychain mode: "
    "a stolen vault password exposes every compartment derived from "
    "it, and a cached password would do the same without any theft — "
    "which is why caching is refused by this discipline, not merely "
    "discouraged."
)

# Interactive-OS-auth is the ONLY accepted auth method for backup
# export. Any other string (including anything control-socket-shaped)
# is refused. There is no fallback.
INTERACTIVE_OS_AUTH = "interactive_os"

# Refusing a synced folder requires the user to type this exactly.
SYNC_RISK_CONFIRMATION = "I UNDERSTAND THIS FOLDER MAY SYNC"

FULL_EXPORT_COOLDOWN_SECONDS = 24 * 3600  # 24 h, enforced, not advisory

# Directory names that indicate a synced folder. Matched against
# individual path components (case-insensitive), not substrings, so
# an innocent directory named e.g. "drive-reports" is not flagged
# while "Dropbox" / "OneDrive" / "Google Drive" are.
SYNCED_DIR_NAMES = {
    "dropbox",
    "onedrive",
    "googledrive",
    "google drive",
    "icloud drive",
    "icloud",
    "nextcloud",
    "syncthing",
    "box sync",
    "mega",
}

# Storage tiers (v3 N-N1 / N-D8). The tier value is part of the
# doctor/posture output and must be quoted honestly, not upgraded.
STORAGE_TIER_MACOS_KEYCHAIN = "os-enforced-per-key"
STORAGE_TIER_USER_SCOPED = "user-scoped"

PLATFORM_STORES = (
    "macos-keychain",
    "linux-secret-service",
    "linux-file",
    "windows-dpapi",
)


class VaultError(Exception):
    """Base vault error. Maps to KH-1001 on the CLI surface."""


class CompartmentNotFound(VaultError):
    pass


class CompartmentExists(VaultError):
    pass


class BackupRefused(VaultError):
    """Backup export refused by a guard (auth, synced folder, cooldown)."""


class RestoreBlocked(VaultError):
    """Restore refused: live sessions, existing compartment, or resurrect."""


class AuthRequired(VaultError):
    """Interactive OS auth required and not supplied."""


class UnsupportedFormatError(VaultError):
    """Envelope format refused: not KHCOMP1 / KHBACKUP1 / KHBACKUP2.

    This is the migration decision made visible (v3 N-S1): an unknown
    or legacy single-DEK format is never converted, never misread as
    a compartment, and never silently locked out without explanation.
    The message always carries MIGRATION_DECISION so the caller — and
    the user — sees the import path instead of a bare refusal.
    """


class TicketError(VaultError):
    """Single-use compartment ticket refused: consumed, stale, or mismatched."""


def password_discipline_text() -> str:
    """Normative password-mode caching discipline (v3 N-D3, f07 H4)."""
    return PASSWORD_DISCIPLINE


class CompartmentTicket:
    """Single-use, single-compartment open ticket (v3 N-D3, f07 H4).

    Bound to exactly one ``key_id`` and one ``compartment_version``.
    The wrapping key is held as a ``bytearray`` and zeroed the moment
    the ticket is consumed — consumption happens BEFORE decryption, so
    a failed open still kills the ticket (fail closed, no replay).
    A ticket never leaves this process as a stored value: it is an
    in-memory object returned to the broker, which must use it once
    and drop it. It contains no secret key material — only the
    compartment's wrapping key, which is useless without the live
    envelope and is zeroed after one use.
    """

    def __init__(self, key_id: str, compartment_version: int, wrapping_key: bytes):
        self.key_id = key_id
        self.compartment_version = int(compartment_version)
        self._wrapping_key = bytearray(wrapping_key)
        self._consumed = False

    @property
    def consumed(self) -> bool:
        return self._consumed

    def consume(self) -> bytes:
        """Atomically consume the ticket; returns the wrapping key once.

        Second consumption raises, and the internal buffer is zeroed
        immediately after copying, so a consumed ticket holds nothing.
        """
        if self._consumed:
            raise TicketError("compartment ticket already consumed (single use)")
        self._consumed = True
        key = bytes(self._wrapping_key)
        for i in range(len(self._wrapping_key)):
            self._wrapping_key[i] = 0
        return key


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _canonical(obj) -> bytes:
    """Canonical JSON bytes: sorted keys, tight separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _is_synced_path(path: Path) -> bool:
    parts = {p.lower() for p in path.resolve().parts} if _path_exists(path) else {p.lower() for p in path.parts}
    # Resolve when possible (handles symlinks into synced folders);
    # fall back to the literal parts for not-yet-existing destinations.
    return bool(parts & SYNCED_DIR_NAMES)


def _path_exists(path: Path) -> bool:
    try:
        path.resolve(strict=False)
        return path.exists() or path.parent.exists()
    except (OSError, RuntimeError):
        return False


def storage_tier_for(platform_store: str) -> str:
    """Return the storage tier value for a platform store.

    Only ``macos-keychain`` is OS-enforced per key. Every other store
    — including Linux Secret Service and Windows DPAPI — is
    USER-SCOPED: a same-user process is not separated by the store,
    and per-key granularity there is broker accounting only.
    Unknown stores are user-scoped, never upgraded by default.
    """
    if platform_store == "macos-keychain":
        return STORAGE_TIER_MACOS_KEYCHAIN
    return STORAGE_TIER_USER_SCOPED


def posture_text(platform_store: str) -> str:
    """Honest posture paragraph for doctor/posture surfaces.

    Callers (W10/W13) must reproduce this wording, not soften it.
    """
    tier = storage_tier_for(platform_store)
    if tier == STORAGE_TIER_MACOS_KEYCHAIN:
        gate = (
            "Per-key storage is OS-enforced on this platform: each key "
            "has its own macOS keychain item, and keychain access groups "
            "bind release to the broker's signing identity."
        )
    else:
        gate = (
            "Per-key storage on this platform is USER-SCOPED, not "
            "OS-enforced: a process running as the same user is not "
            "separated from another key's compartment by the store "
            "itself. Per-key granularity here is broker-side accounting "
            "and audit granularity only — it does not survive a "
            "same-user (Tier B) attacker. Only macOS keychain access "
            "groups make a per-key gate OS-enforced."
        )
    return (
        f"Storage tier: {tier} (platform store: {platform_store}).\n"
        f"{gate}\n"
        "Password mode, where used, is strictly weaker: a stolen vault "
        "password exposes every compartment derived from it. Platform "
        "keychain mode is the recommended default. Same-user malware or "
        "a compromised OS account is out of scope by design.\n"
        + PASSWORD_DISCIPLINE
    )


def classify_vault_file(path: str | Path) -> dict:
    """Classify one file found in a vault directory (migration, N-S1).

    Kinds: ``compartment`` (KHCOMP1 file name; format checked by the
    caller via the envelope), ``backup`` (a backup container sitting
    inside the vault directory — misplaced, restore it, never copy it
    over a live file), ``internal`` (vault bookkeeping), or
    ``foreign-or-legacy`` (anything else: a would-be single-DEK vault,
    a stray JSON file, a foreign file — never opened, never converted,
    reported so it is never silently ignored or misread).
    The classification reads file NAMES only for non-compartment files
    (a foreign file's contents are never parsed as an envelope).
    """
    p = Path(path)
    name = p.name
    if name in (".export-state.json",):
        return {"name": name, "kind": "internal"}
    if re.match(r"^key-[0-9a-f]{16}\.khcomp\.json$", name):
        return {"name": name, "kind": "compartment"}
    if name.endswith(".khbackup.json"):
        return {"name": name, "kind": "backup",
                "note": "backup container inside the vault directory; "
                "import it with restore_compartment, never copy it "
                "over a live compartment file"}
    return {"name": name, "kind": "foreign-or-legacy",
            "note": MIGRATION_DECISION}


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write atomically: temp file in the same directory, fsync,
    rename over the destination, fsync the directory.

    Never rename over the live file before snapshotting — callers
    that overwrite a live compartment must snapshot first (see
    ``Vault._snapshot_live``); this helper only guarantees the write
    itself is atomic and durable.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".tmp.")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    # Directory fsync so the rename itself is durable.
    try:
        dir_fd = os.open(str(path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


class Vault:
    """Per-compartment encrypted vault rooted at ``vault_dir``.

    Layout (all under ``vault_dir``)::
        <key_id>.khcomp.json   live compartment envelope (one per key)
        .snapshots/            pre-overwrite snapshots, one per generation
        .export-state.json     last full-vault export timestamp (cooldown)

    The vault holds no vault-wide key and no session state. Live
    sessions are the broker's (W01/W03) responsibility; this class
    only enforces the restore kill-gate at its boundary.
    """

    def __init__(self, vault_dir: str | Path, platform_store: str = "linux-file",
                 strict_password_tickets: bool = False):
        self.vault_dir = Path(vault_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.snapshot_dir = self.vault_dir / ".snapshots"
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        if platform_store not in PLATFORM_STORES:
            # Unknown store: never claim OS enforcement.
            platform_store = "linux-file"
        self.platform_store = platform_store
        # Password discipline switch (v3 N-D3, f07 H4): when True, the
        # direct password= path of open_secret is refused and only
        # single-use tickets may open password compartments. Default
        # False preserves the v0.1 API; the broker must opt in and
        # record that it did — the vault never claims strict mode it
        # was not constructed with. No password, derived key, or
        # secret is ever stored on this instance in either mode.
        self.strict_password_tickets = bool(strict_password_tickets)

    # -- tier / posture -------------------------------------------------

    @property
    def storage_tier(self) -> str:
        return storage_tier_for(self.platform_store)

    def posture(self) -> str:
        return posture_text(self.platform_store)

    # -- paths / validation ---------------------------------------------

    def _check_key_id(self, key_id: str) -> None:
        if not isinstance(key_id, str) or not _KEY_ID_RE.match(key_id):
            raise VaultError(f"invalid key_id shape: {key_id!r}")

    def _check_provider(self, provider: str) -> None:
        if provider not in PROVIDERS:
            raise VaultError(f"unknown provider: {provider!r}")

    def _compartment_path(self, key_id: str) -> Path:
        self._check_key_id(key_id)
        return self.vault_dir / f"{key_id}.khcomp.json"

    # -- envelope construction ------------------------------------------

    def _header_fields(self, header: dict) -> list[str]:
        return sorted(header.keys())

    def _build_envelope(
        self,
        *,
        fmt: str,
        key_id: str,
        provider: str,
        version: int,
        auth_scheme: str,
        salt: bytes,
        wrapping_key: bytes,
        secret: bytes,
        backup_marker: bool,
    ) -> dict:
        """Build an AEAD envelope (live compartment or backup container).

        Header plaintext carries key_id / provider / version /
        auth_scheme (+ container marker for backups). The header is
        AEAD-encrypted under HKDF(wrapping_key, header-info); the body
        under HKDF(wrapping_key, body-info). Header AAD =
        (key_id, provider, version, header field names); body AAD =
        that tuple plus auth_scheme (and the backup marker for backup
        containers), so a blob cannot be replayed across compartments,
        versions, schemes, or live/backup roles.
        """
        if backup_marker:
            header = {
                "key_id": key_id,
                "provider": provider,
                "compartment_version": version,
                "auth_scheme": auth_scheme,
                "container": "backup",
            }
            header_info, body_info = INFO_BACKUP_HEADER, INFO_BACKUP_BODY
            marker: list[str] = ["backup"]
        else:
            header = {
                "key_id": key_id,
                "provider": provider,
                "compartment_version": version,
                "auth_scheme": auth_scheme,
            }
            header_info, body_info = INFO_HEADER, INFO_BODY
            marker = []
        fields = self._header_fields(header)
        # AAD is built ONLY by crypto.header_aad/body_aad (v0.2 spec
        # single source of truth; see crypto.HEADER_AEAD_SPEC).
        h_aad = header_aad(marker, key_id, provider, version, fields)
        b_aad = body_aad(marker, key_id, provider, version, fields, auth_scheme)
        header_key = hkdf_derive(wrapping_key, header_info)
        body_key = hkdf_derive(wrapping_key, body_info)
        if header_key == body_key:
            # Impossible with distinct info strings; fail closed rather
            # than encrypting header and body under one key.
            raise VaultError("header/body derived keys collided; refusing to encrypt")
        header_nonce, header_ct = aes_gcm_encrypt(header_key, _canonical(header), h_aad)
        body_nonce, body_ct = aes_gcm_encrypt(body_key, secret, b_aad)
        # Defence in depth: header and body already use different keys,
        # so equal nonces would still not be a (key, nonce) reuse — but
        # never emit an envelope whose two nonces are equal either.
        while body_nonce == header_nonce:
            body_nonce, body_ct = aes_gcm_encrypt(body_key, secret, b_aad)
        envelope = {
            "format": fmt,
            "key_id": key_id,
            "provider": provider,
            "compartment_version": version,
            "auth_scheme": auth_scheme,
            "salt_b64": _b64e(salt),
            "header_nonce_b64": _b64e(header_nonce),
            "header_ct_b64": _b64e(header_ct),
            "body_nonce_b64": _b64e(body_nonce),
            "body_ct_b64": _b64e(body_ct),
            "header_fields": fields,
        }
        if backup_marker:
            envelope["container"] = "backup"
        return envelope

    def _marker_and_info(self, envelope: dict) -> tuple[list[str], bytes, bytes]:
        """Marker + HKDF info pair for an envelope's role (live/backup)."""
        if envelope.get("container") == "backup":
            return ["backup"], INFO_BACKUP_HEADER, INFO_BACKUP_BODY
        return [], INFO_HEADER, INFO_BODY

    def _verify_header(self, envelope: dict, wk: bytes) -> dict:
        """Decrypt + authenticate the header and check it against the
        envelope's plaintext metadata — BEFORE the body is touched
        (f07 H2 verification order). No header field is used for any
        security decision until this returns. Raises CryptoTamperError
        on AEAD failure, VaultError on field mismatch."""
        try:
            header_nonce = _b64d(envelope["header_nonce_b64"])
            header_ct = _b64d(envelope["header_ct_b64"])
            key_id = envelope["key_id"]
            provider = envelope["provider"]
            version = int(envelope["compartment_version"])
            auth_scheme = envelope["auth_scheme"]
            fields = list(envelope["header_fields"])
        except (KeyError, ValueError, TypeError) as exc:
            raise VaultError(f"malformed envelope: {exc}") from exc
        marker, header_info, _body_info = self._marker_and_info(envelope)
        header = json.loads(
            aes_gcm_decrypt(
                hkdf_derive(wk, header_info), header_nonce, header_ct,
                header_aad(marker, key_id, provider, version, fields),
            ).decode("utf-8")
        )
        if (
            header.get("key_id") != key_id
            or header.get("provider") != provider
            or int(header.get("compartment_version", -1)) != version
            or header.get("auth_scheme") != auth_scheme
            or sorted(header.keys()) != fields
        ):
            raise VaultError("header contents do not match envelope metadata")
        return header

    def _open_with_wrapping_key(
        self, envelope: dict, wk: bytes, *, expected_format: str
    ) -> tuple[bytes, dict]:
        """Open an envelope with an already-derived wrapping key.

        Used by ticket opens (the ticket IS the derived key) and, after
        credential resolution, by _open_envelope. Format is checked
        first; header verification precedes body decryption.
        """
        if envelope.get("format") != expected_format:
            raise UnsupportedFormatError(
                f"refusing envelope with format {envelope.get('format')!r}: "
                f"expected {expected_format!r}. {MIGRATION_DECISION}"
            )
        header = self._verify_header(envelope, wk)
        try:
            body_nonce = _b64d(envelope["body_nonce_b64"])
            body_ct = _b64d(envelope["body_ct_b64"])
            key_id = envelope["key_id"]
            provider = envelope["provider"]
            version = int(envelope["compartment_version"])
            auth_scheme = envelope["auth_scheme"]
            fields = list(envelope["header_fields"])
        except (KeyError, ValueError, TypeError) as exc:
            raise VaultError(f"malformed envelope: {exc}") from exc
        _marker, _header_info, body_info = self._marker_and_info(envelope)
        secret = aes_gcm_decrypt(
            hkdf_derive(wk, body_info), body_nonce, body_ct,
            body_aad(_marker, key_id, provider, version, fields, auth_scheme),
        )
        return secret, header

    def _open_envelope(
        self,
        envelope: dict,
        *,
        expected_format: str,
        password: bytes | None,
        wrapping_key: bytes | None,
    ) -> tuple[bytes, dict]:
        """Verify and decrypt an envelope. Returns (secret, header).

        Any format mismatch, header/body AEAD failure, or key_id /
        version inconsistency raises (tamper/wrong-key/wrong-AAD are
        indistinguishable by design — all surface as AEAD failure).
        """
        if envelope.get("format") != expected_format:
            raise UnsupportedFormatError(
                f"refusing envelope with format {envelope.get('format')!r}: "
                f"expected {expected_format!r}. {MIGRATION_DECISION}"
            )
        try:
            salt = _b64d(envelope["salt_b64"])
            auth_scheme = envelope["auth_scheme"]
        except (KeyError, ValueError, TypeError) as exc:
            raise VaultError(f"malformed envelope: {exc}") from exc
        if auth_scheme == "password":
            if password is None:
                raise VaultError("password required to open this compartment")
            wk = derive_wrapping_key(password, salt)
        elif auth_scheme == "platform-keychain":
            if wrapping_key is None or len(wrapping_key) != 32:
                raise VaultError("platform wrapping key (32 bytes) required")
            wk = wrapping_key
        else:
            raise VaultError(f"unknown auth_scheme: {auth_scheme!r}")
        return self._open_with_wrapping_key(envelope, wk, expected_format=expected_format)

    # -- snapshots ---------------------------------------------------------

    def _snapshot_live(self, key_id: str) -> Path | None:
        """Snapshot the live compartment BEFORE overwriting it (N-S2).

        Returns the snapshot path, or None if no live file existed.
        Snapshot names are unique per generation so a re-baselined
        version can never silently overwrite an older snapshot.
        """
        live = self._compartment_path(key_id)
        if not live.exists():
            return None
        raw = live.read_bytes()
        try:
            version = int(json.loads(raw.decode("utf-8")).get("compartment_version", 0))
        except (ValueError, TypeError, KeyError):
            version = 0
        base = self.snapshot_dir / f"{key_id}.v{version}.json"
        target = base
        suffix = 1
        while target.exists():
            target = self.snapshot_dir / f"{key_id}.v{version}.{suffix}.json"
            suffix += 1
        atomic_write_bytes(target, raw)
        return target

    def list_snapshots(self, key_id: str) -> list[str]:
        self._check_key_id(key_id)
        return sorted(p.name for p in self.snapshot_dir.glob(f"{key_id}.v*.json"))

    # -- compartment lifecycle --------------------------------------------

    def _resolve_new_wrapping(
        self, *, password: bytes | None, wrapping_key: bytes | None
    ) -> tuple[str, bytes, bytes]:
        """Exactly one of password / wrapping_key. Returns (scheme, salt, wk)."""
        if (password is None) == (wrapping_key is None):
            raise VaultError("supply exactly one of password or wrapping_key")
        if password is not None:
            salt = new_salt()
            return "password", salt, derive_wrapping_key(password, salt)
        if len(wrapping_key) != 32:
            raise VaultError("platform wrapping key must be 32 bytes")
        # Platform mode: the salt is stored for envelope shape parity
        # but is NOT used to derive the platform key.
        return "platform-keychain", new_salt(), bytes(wrapping_key)

    def store_secret(
        self,
        key_id: str,
        provider: str,
        secret: bytes,
        *,
        password: bytes | None = None,
        wrapping_key: bytes | None = None,
    ) -> dict:
        """Create a new compartment (version 1). Refuses if one exists."""
        self._check_key_id(key_id)
        self._check_provider(provider)
        path = self._compartment_path(key_id)
        if path.exists():
            raise CompartmentExists(f"compartment already exists: {key_id}")
        scheme, salt, wk = self._resolve_new_wrapping(
            password=password, wrapping_key=wrapping_key
        )
        envelope = self._build_envelope(
            fmt=COMPARTMENT_FORMAT,
            key_id=key_id,
            provider=provider,
            version=1,
            auth_scheme=scheme,
            salt=salt,
            wrapping_key=wk,
            secret=secret,
            backup_marker=False,
        )
        atomic_write_bytes(path, _canonical(envelope))
        return {"key_id": key_id, "provider": provider, "compartment_version": 1,
                "auth_scheme": scheme}

    def open_secret(
        self,
        key_id: str,
        *,
        password: bytes | None = None,
        wrapping_key: bytes | None = None,
    ) -> bytes:
        """Decrypt and return the live secret for one compartment.

        In strict mode (``strict_password_tickets=True`` at Vault
        construction) a direct ``password=`` open is refused — password
        compartments open only via ``issue_ticket`` /
        ``open_with_ticket``. Platform-keychain opens are unaffected
        (no password is cached there to discipline). This Vault never
        retains the password or the derived key after the call returns,
        in either mode.
        """
        if self.strict_password_tickets and password is not None:
            raise VaultError(
                "strict password discipline: direct password opens are "
                "refused; use issue_ticket/open_with_ticket for one "
                "single-use, version-bound open per password entry"
            )
        path = self._compartment_path(key_id)
        if not path.exists():
            raise CompartmentNotFound(f"no compartment: {key_id}")
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise VaultError(f"unreadable compartment envelope: {exc}") from exc
        if envelope.get("key_id") != key_id:
            raise VaultError("envelope key_id does not match file name")
        secret, _header = self._open_envelope(
            envelope, expected_format=COMPARTMENT_FORMAT,
            password=password, wrapping_key=wrapping_key,
        )
        return secret

    # -- password discipline: single-use tickets (v3 N-D3, f07 H4) ------

    def issue_ticket(
        self,
        key_id: str,
        *,
        password: bytes | bytearray | None = None,
        wrapping_key: bytes | None = None,
    ) -> CompartmentTicket:
        """Issue a single-use ticket for one compartment open.

        The credential is verified against the header AEAD only — the
        body (the secret) is NOT decrypted here, so issuing a ticket
        never exposes the secret. The derived wrapping key goes into
        the ticket's zeroable buffer; the Vault keeps no copy. If
        ``password`` is a ``bytearray`` it is zeroed after derivation
        (the discipline's re-prompt rule: the caller must ask again
        for the next compartment). ``bytes`` passwords are accepted
        but cannot be zeroed by Python — prefer ``bytearray``.
        Exactly one of password / wrapping_key, as in store_secret.
        """
        path = self._compartment_path(key_id)
        if not path.exists():
            raise CompartmentNotFound(f"no compartment: {key_id}")
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise VaultError(f"unreadable compartment envelope: {exc}") from exc
        if envelope.get("format") != COMPARTMENT_FORMAT:
            raise UnsupportedFormatError(
                f"refusing envelope with format {envelope.get('format')!r}. "
                f"{MIGRATION_DECISION}"
            )
        if envelope.get("key_id") != key_id:
            raise VaultError("envelope key_id does not match file name")
        try:
            salt = _b64d(envelope["salt_b64"])
            auth_scheme = envelope["auth_scheme"]
        except (KeyError, ValueError, TypeError) as exc:
            raise VaultError(f"malformed envelope: {exc}") from exc
        if (password is None) == (wrapping_key is None):
            raise VaultError("supply exactly one of password or wrapping_key")
        if auth_scheme == "password":
            if password is None:
                raise VaultError("password required to open this compartment")
            wk = derive_wrapping_key(bytes(password), salt)
            if isinstance(password, bytearray):
                for i in range(len(password)):
                    password[i] = 0
        elif auth_scheme == "platform-keychain":
            if wrapping_key is None or len(wrapping_key) != 32:
                raise VaultError("platform wrapping key (32 bytes) required")
            wk = bytes(wrapping_key)
        else:
            raise VaultError(f"unknown auth_scheme: {auth_scheme!r}")
        # Header-only verification: wrong credential fails here, before
        # any ticket exists, and without decrypting the secret.
        self._verify_header(envelope, wk)
        version = int(envelope["compartment_version"])
        return CompartmentTicket(key_id, version, wk)

    def open_with_ticket(self, ticket: CompartmentTicket) -> bytes:
        """Open a compartment with a single-use ticket (see issue_ticket).

        Consumption precedes decryption: a failed open still consumes
        the ticket. A ticket for another key_id, or for a superseded
        compartment version (rotated since issue), is refused without
        decrypting anything.
        """
        if not isinstance(ticket, CompartmentTicket):
            raise TicketError("open_with_ticket requires a CompartmentTicket")
        wk = ticket.consume()  # raises if already consumed; zeroes buffer
        meta = self.get_metadata(ticket.key_id)
        if int(meta["compartment_version"]) != ticket.compartment_version:
            raise TicketError(
                f"ticket is stale: issued for version "
                f"{ticket.compartment_version}, live version is "
                f"{meta['compartment_version']} (rotated since issue)"
            )
        path = self._compartment_path(ticket.key_id)
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise VaultError(f"unreadable compartment envelope: {exc}") from exc
        if envelope.get("key_id") != ticket.key_id:
            raise VaultError("envelope key_id does not match ticket key_id")
        secret, _header = self._open_with_wrapping_key(
            envelope, wk, expected_format=COMPARTMENT_FORMAT
        )
        return secret

    def get_metadata(self, key_id: str) -> dict:
        """Metadata only — never secret material, never a fingerprint.

        DISPLAY ONLY (f07 H2): these fields are copied from the
        envelope's plaintext metadata WITHOUT AEAD verification, so
        every entry carries ``header_verified: False``. Never use them
        for a security decision. ``rotate_secret`` is safe despite
        using them because it calls ``open_secret`` (full verification)
        before building anything from them.
        """
        path = self._compartment_path(key_id)
        if not path.exists():
            raise CompartmentNotFound(f"no compartment: {key_id}")
        envelope = json.loads(path.read_text(encoding="utf-8"))
        return {
            "key_id": envelope.get("key_id"),
            "provider": envelope.get("provider"),
            "compartment_version": envelope.get("compartment_version"),
            "auth_scheme": envelope.get("auth_scheme"),
            "storage_tier": self.storage_tier,
            "header_verified": False,
        }

    def list_compartments(self) -> list[dict]:
        """Metadata for every live compartment. No secrets, no labels.

        DISPLAY ONLY (f07 H2): ``header_verified`` is always False
        here — fields are copied from plaintext metadata, not verified.
        """
        out = []
        for path in sorted(self.vault_dir.glob("key-*.khcomp.json")):
            try:
                envelope = json.loads(path.read_text(encoding="utf-8"))
                out.append({
                    "key_id": envelope.get("key_id"),
                    "provider": envelope.get("provider"),
                    "compartment_version": envelope.get("compartment_version"),
                    "auth_scheme": envelope.get("auth_scheme"),
                    "header_verified": False,
                })
            except (ValueError, OSError, KeyError):
                out.append({"key_id": path.stem, "provider": None,
                            "compartment_version": None, "auth_scheme": None,
                            "quarantined": True, "header_verified": False})
        return out

    def migration_status(self) -> dict:
        """Migration decision report for this vault directory (N-S1).

        Scans the vault root (not snapshots): live compartments, any
        backup container misplaced inside the vault directory, and any
        foreign/legacy file. A foreign file is reported, never opened
        and never converted — the decision is explicit so a would-be
        single-DEK vault can neither be misread as compartments nor
        silently lock the user out without an explanation. The broker
        / doctor must call this at startup (outside this file's area).
        """
        compartments = self.list_compartments()
        stray = []
        compartment_names = {f"{c['key_id']}.khcomp.json" for c in compartments
                             if c.get("key_id")}
        for path in sorted(self.vault_dir.iterdir()):
            if path.is_dir() or path.name in (".export-state.json",):
                continue
            if path.name in compartment_names:
                continue
            stray.append(classify_vault_file(path))
        return {
            "format": COMPARTMENT_FORMAT,
            "decision": "COMPARTMENTS_FIRST_NO_IN_PLACE_MIGRATION",
            "decision_text": MIGRATION_DECISION,
            "compartments": compartments,
            "stray_files": stray,
            "import_paths": {
                "KHBACKUP1": "restore_compartment",
                "KHBACKUP2": "restore_compartment (either factor)",
                "other": "re-import key by key after provider rotation; "
                "never copy over a live compartment file",
            },
        }

    def rebuild_index(self) -> dict:
        """Scan the vault directory and quarantine unreadable envelopes.

        Returns {"ok": [...], "quarantined": [...], "stray": [...]}.
        A quarantined compartment is listed, never auto-repaired and
        never silently dropped. ``stray`` lists non-compartment files
        in the vault root (foreign/legacy files, misplaced backups)
        via :func:`classify_vault_file` — rebuild may copy header
        fields for display but must mark them unverified (f07 H2), so
        ``ok`` entries carry ``header_verified: False``.
        """
        ok, quarantined = [], []
        for path in sorted(self.vault_dir.glob("key-*.khcomp.json")):
            try:
                envelope = json.loads(path.read_text(encoding="utf-8"))
                if envelope.get("format") != COMPARTMENT_FORMAT:
                    raise ValueError("unknown format")
                ok.append({"key_id": envelope["key_id"],
                           "provider": envelope["provider"],
                           "compartment_version": envelope["compartment_version"],
                           "header_verified": False})
            except (ValueError, OSError, KeyError):
                quarantined.append(path.name)
        stray = []
        ok_names = {f"{e['key_id']}.khcomp.json" for e in ok}
        quarantined_set = set(quarantined)
        for path in sorted(self.vault_dir.iterdir()):
            if path.is_dir() or path.name in (".export-state.json",):
                continue
            if path.name in ok_names or path.name in quarantined_set:
                continue
            stray.append(classify_vault_file(path))
        return {"ok": ok, "quarantined": quarantined, "stray": stray}

    def rotate_secret(
        self,
        key_id: str,
        new_secret: bytes,
        *,
        password: bytes | None = None,
        wrapping_key: bytes | None = None,
        new_wrapping_key: bytes | None = None,
    ) -> dict:
        """Replace the secret, snapshotting the old generation first.

        Version increments by 1. Password mode re-derives from a fresh
        salt (new wrapping key); platform mode keeps the caller's
        wrapping key unless ``new_wrapping_key`` is supplied (keychain
        item rotation is W13's job; this only re-wraps under it).
        """
        meta = self.get_metadata(key_id)
        # Verify the caller can open the current compartment first:
        # rotation must not orphan a compartment the caller cannot read.
        self.open_secret(key_id, password=password, wrapping_key=wrapping_key)
        if meta["auth_scheme"] == "password":
            if password is None:
                raise VaultError("password required to rotate this compartment")
            salt = new_salt()
            wk = derive_wrapping_key(password, salt)
            scheme = "password"
        else:
            if new_wrapping_key is not None:
                if len(new_wrapping_key) != 32:
                    raise VaultError("platform wrapping key must be 32 bytes")
                wk = bytes(new_wrapping_key)
            elif wrapping_key is not None:
                wk = bytes(wrapping_key)
            else:
                raise VaultError("platform wrapping key required")
            salt = new_salt()
            scheme = "platform-keychain"
        new_version = int(meta["compartment_version"]) + 1
        snapshot = self._snapshot_live(key_id)
        envelope = self._build_envelope(
            fmt=COMPARTMENT_FORMAT,
            key_id=key_id,
            provider=meta["provider"],
            version=new_version,
            auth_scheme=scheme,
            salt=salt,
            wrapping_key=wk,
            secret=new_secret,
            backup_marker=False,
        )
        atomic_write_bytes(self._compartment_path(key_id), _canonical(envelope))
        return {"key_id": key_id, "provider": meta["provider"],
                "compartment_version": new_version,
                "snapshot": snapshot.name if snapshot else None}

    def delete_compartment(self, key_id: str, *, purge_snapshots: bool = False) -> dict:
        """Delete the live compartment. The receipt is honest (N-D7):
        it states what was deleted from the live vault and what the
        user must still purge (snapshots kept, plus any backup copies
        made by export, which this vault cannot enumerate)."""
        path = self._compartment_path(key_id)
        if not path.exists():
            raise CompartmentNotFound(f"no compartment: {key_id}")
        snapshots = self.list_snapshots(key_id)
        path.unlink()
        purged: list[str] = []
        if purge_snapshots:
            for name in snapshots:
                (self.snapshot_dir / name).unlink(missing_ok=True)
                purged.append(name)
            snapshots = []
        return {
            "key_id": key_id,
            "live_deleted": True,
            "snapshots_purged": purged,
            "snapshots_remaining": snapshots,
            "still_to_purge": (
                "Any backup containers exported from this compartment, "
                "and any OS/user backup copies (e.g. Time Machine) that "
                "contain them, are NOT deleted by this receipt and must "
                "be purged separately. Deleting the live compartment "
                "does not revoke the key at the provider."
            ),
        }

    # -- backup export ------------------------------------------------------

    def _check_export_guards(
        self, dest: Path, *, auth_method: str, risk_confirmation: str | None
    ) -> None:
        if auth_method != INTERACTIVE_OS_AUTH:
            raise AuthRequired(
                "backup export requires interactive OS auth every time; "
                "control-socket auth alone is never sufficient"
            )
        if _is_synced_path(dest):
            if risk_confirmation != SYNC_RISK_CONFIRMATION:
                raise BackupRefused(
                    "refusing to export into a synced folder without "
                    "the typed risk confirmation "
                    f"({SYNC_RISK_CONFIRMATION!r})"
                )

    def _export_state_path(self) -> Path:
        return self.vault_dir / ".export-state.json"

    def _last_full_export(self) -> float | None:
        try:
            state = json.loads(self._export_state_path().read_text(encoding="utf-8"))
            return float(state.get("last_full_export_epoch", 0)) or None
        except (OSError, ValueError, TypeError):
            return None

    def _record_full_export(self) -> None:
        atomic_write_bytes(
            self._export_state_path(),
            _canonical({"last_full_export_epoch": time.time()}),
        )

    def export_compartment(
        self,
        key_id: str,
        dest: str | Path,
        *,
        password: bytes | None = None,
        wrapping_key: bytes | None = None,
        export_password: bytes | None = None,
        export_wrapping_key: bytes | None = None,
        auth_method: str,
        risk_confirmation: str | None = None,
        overwrite: bool = False,
        ticket: CompartmentTicket | None = None,
    ) -> dict:
        """Export ONE compartment to its own backup container (default).

        The caller opens the live compartment with its vault
        credentials (``password``/``wrapping_key``, or a single-use
        ``ticket`` in strict mode); the container is wrapped under a
        separate export credential (``export_password`` /
        ``export_wrapping_key``) so a backup container never shares
        the live compartment's wrapping key. Per-compartment export is
        NOT subject to the full-vault 24 h cooldown.
        """
        dest = Path(dest)
        self._check_export_guards(dest, auth_method=auth_method,
                                  risk_confirmation=risk_confirmation)
        if dest.exists() and not overwrite:
            raise BackupRefused(f"destination already exists: {dest}")
        if ticket is not None:
            if password is not None or wrapping_key is not None:
                raise VaultError("supply exactly one of ticket or password/wrapping_key")
            if ticket.key_id != key_id:
                raise TicketError("ticket is for a different compartment")
            secret = self.open_with_ticket(ticket)
        else:
            secret = self.open_secret(key_id, password=password, wrapping_key=wrapping_key)
        meta = self.get_metadata(key_id)
        # Differ-ness (f07 M6), enforced only where it is checkable:
        # in password mode both passwords are in memory here, so an
        # export password equal to the vault password is refused (it
        # would make the backup no stronger than the vault). In
        # platform mode the vault password is not in memory — nothing
        # to compare against — so the check is reported as skipped
        # with an explicit warning, never silently claimed as passed.
        # A stored fast hash verifier is never created for this check.
        if ticket is not None:
            differ_check = ("skipped-ticket-mode: the live password was "
                            "not supplied for this export (ticket open), "
                            "so differ-ness cannot be checked — do not "
                            "reuse the vault password as the export password")
        elif meta["auth_scheme"] == "password" and password is not None \
                and export_password is not None:
            if hmac.compare_digest(bytes(password), bytes(export_password)):
                raise BackupRefused(
                    "export password must differ from the vault password "
                    "(a backup protected by the same password adds no "
                    "protection if the vault password is guessed or leaked)"
                )
            differ_check = "pass"
        elif export_wrapping_key is not None:
            differ_check = "not-applicable (export wrapped under a key, not a password)"
        else:
            differ_check = ("skipped-platform-mode: the vault password is "
                            "not in memory in platform mode, so differ-ness "
                            "cannot be checked — do not reuse the vault "
                            "password as the export password")
        scheme, salt, wk = self._resolve_new_wrapping(
            password=export_password, wrapping_key=export_wrapping_key
        )
        envelope = self._build_envelope(
            fmt=BACKUP_FORMAT,
            key_id=key_id,
            provider=meta["provider"],
            version=int(meta["compartment_version"]),
            auth_scheme=scheme,
            salt=salt,
            wrapping_key=wk,
            secret=secret,
            backup_marker=True,
        )
        atomic_write_bytes(dest, _canonical(envelope))
        return {"key_id": key_id, "provider": meta["provider"],
                "compartment_version": meta["compartment_version"],
                "dest": str(dest), "container": "backup",
                "vault_password_differ_check": differ_check}

    # -- dual-factor recovery container (v3 N-H2 / N-S4, f07 M5) --------

    def _build_dual_envelope(
        self, *, key_id: str, provider: str, version: int, secret: bytes,
        factors: list[tuple[str, str, bytes, bytes]],
    ) -> dict:
        """Build a KHBACKUP2 envelope: one wrapping per factor.

        ``factors`` is a list of (factor_label, auth_scheme, salt,
        wrapping_key) with labels "primary" then "recovery". Each
        wrapping encrypts the SAME header (plus its own ``wrapping``
        label) and the SAME secret under its own HKDF-derived keys,
        its own salt, and its own fresh nonces, with the factor label
        in the AAD — so a wrapping cannot be transplanted to the other
        factor, to a single-factor container, or to a live compartment.
        Either wrapping alone decrypts the secret (OR semantics).
        """
        wrappings = []
        for factor, auth_scheme, salt, wk in factors:
            header = {
                "key_id": key_id,
                "provider": provider,
                "compartment_version": version,
                "auth_scheme": auth_scheme,
                "container": "backup",
                "wrapping": factor,
            }
            fields = self._header_fields(header)
            marker = ["backup", "recovery", factor]
            h_aad = header_aad(marker, key_id, provider, version, fields)
            b_aad = body_aad(marker, key_id, provider, version, fields, auth_scheme)
            header_key = hkdf_derive(wk, INFO_RECOVERY_HEADER)
            body_key = hkdf_derive(wk, INFO_RECOVERY_BODY)
            if header_key == body_key:
                raise VaultError("header/body derived keys collided; refusing to encrypt")
            header_nonce, header_ct = aes_gcm_encrypt(
                header_key, _canonical(header), h_aad)
            body_nonce, body_ct = aes_gcm_encrypt(body_key, secret, b_aad)
            while body_nonce == header_nonce:
                body_nonce, body_ct = aes_gcm_encrypt(body_key, secret, b_aad)
            wrappings.append({
                "factor": factor,
                "auth_scheme": auth_scheme,
                "salt_b64": _b64e(salt),
                "header_nonce_b64": _b64e(header_nonce),
                "header_ct_b64": _b64e(header_ct),
                "body_nonce_b64": _b64e(body_nonce),
                "body_ct_b64": _b64e(body_ct),
                "header_fields": fields,
            })
        return {
            "format": BACKUP_FORMAT2,
            "key_id": key_id,
            "provider": provider,
            "compartment_version": version,
            "auth_scheme": "dual",  # per-wrapping schemes live in wrappings[]
            "container": "backup",
            "wrappings": wrappings,
        }

    def _open_dual_envelope(
        self,
        envelope: dict,
        *,
        export_password: bytes | None,
        export_wrapping_key: bytes | None,
        recovery_password: bytes | None,
        recovery_wrapping_key: bytes | None,
    ) -> tuple[bytes, str]:
        """Open a KHBACKUP2 envelope with EITHER factor. Returns
        (secret, factor_used). A factor whose credential is not
        supplied is skipped, not failed; a supplied credential that
        fails authentication is recorded and the other factor is still
        tried — but if every supplied credential fails, the failure
        surfaces (tamper/wrong-key, indistinguishable by design). If
        NO factor credential is supplied at all, opening is refused.
        """
        if envelope.get("format") != BACKUP_FORMAT2:
            raise UnsupportedFormatError(
                f"refusing envelope with format {envelope.get('format')!r}. "
                f"{MIGRATION_DECISION}"
            )
        creds = {
            "primary": (export_password, export_wrapping_key),
            "recovery": (recovery_password, recovery_wrapping_key),
        }
        if all(p is None and w is None for p, w in creds.values()):
            raise VaultError("a primary or recovery credential is required")
        try:
            key_id = envelope["key_id"]
            provider = envelope["provider"]
            version = int(envelope["compartment_version"])
            wrappings = envelope["wrappings"]
        except (KeyError, ValueError, TypeError) as exc:
            raise VaultError(f"malformed dual envelope: {exc}") from exc
        last_error: Exception | None = None
        for wrapping in wrappings:
            factor = wrapping.get("factor")
            if factor not in creds:
                continue
            password, wrapping_key = creds[factor]
            if password is None and wrapping_key is None:
                continue
            try:
                salt = _b64d(wrapping["salt_b64"])
                header_nonce = _b64d(wrapping["header_nonce_b64"])
                header_ct = _b64d(wrapping["header_ct_b64"])
                body_nonce = _b64d(wrapping["body_nonce_b64"])
                body_ct = _b64d(wrapping["body_ct_b64"])
                auth_scheme = wrapping["auth_scheme"]
                fields = list(wrapping["header_fields"])
            except (KeyError, ValueError, TypeError) as exc:
                raise VaultError(f"malformed dual envelope wrapping: {exc}") from exc
            if auth_scheme == "password":
                if password is None:
                    continue
                wk = derive_wrapping_key(password, salt)
            elif auth_scheme == "platform-keychain":
                if wrapping_key is None or len(wrapping_key) != 32:
                    continue
                wk = wrapping_key
            else:
                raise VaultError(f"unknown auth_scheme: {auth_scheme!r}")
            marker = ["backup", "recovery", factor]
            try:
                header = json.loads(
                    aes_gcm_decrypt(
                        hkdf_derive(wk, INFO_RECOVERY_HEADER), header_nonce,
                        header_ct,
                        header_aad(marker, key_id, provider, version, fields),
                    ).decode("utf-8")
                )
            except Exception as exc:  # AEAD failure for this factor: try next
                last_error = exc
                continue
            if (
                header.get("key_id") != key_id
                or header.get("provider") != provider
                or int(header.get("compartment_version", -1)) != version
                or header.get("auth_scheme") != auth_scheme
                or header.get("wrapping") != factor
                or sorted(header.keys()) != fields
            ):
                last_error = VaultError("dual wrapping header mismatch")
                continue
            try:
                secret = aes_gcm_decrypt(
                    hkdf_derive(wk, INFO_RECOVERY_BODY), body_nonce, body_ct,
                    body_aad(marker, key_id, provider, version, fields, auth_scheme),
                )
            except Exception as exc:
                last_error = exc
                continue
            return secret, factor
        if last_error is not None:
            raise last_error
        raise VaultError("no supplied credential matched a dual wrapping")

    def export_with_recovery(
        self,
        key_id: str,
        dest: str | Path,
        *,
        password: bytes | None = None,
        wrapping_key: bytes | None = None,
        export_password: bytes | None = None,
        export_wrapping_key: bytes | None = None,
        recovery_password: bytes | None = None,
        recovery_wrapping_key: bytes | None = None,
        auth_method: str,
        risk_confirmation: str | None = None,
        overwrite: bool = False,
    ) -> dict:
        """Export ONE compartment as a dual-factor KHBACKUP2 container.

        Two independent wrappings, either factor alone opens it (v3
        N-H2, OR semantics — NOT dual control). The caller opens the
        live compartment with ``password``/``wrapping_key``; the
        "primary" wrapping uses ``export_password``/``export_wrapping_key``
        and the "recovery" wrapping uses ``recovery_password``/
        ``recovery_wrapping_key`` (generate one with
        ``crypto.new_recovery_key`` and record it offline — the vault
        never stores it). Honest warnings, stated here and in the
        result: (a) OR semantics means compromise of EITHER factor
        plus this container opens the compartment — store the two
        factors separately, never together; (b) one bundle/container
        password protects every key it contains only in the sense of
        this one compartment — this export is per-compartment, and a
        full-vault bundle password would protect every key in the
        bundle (see export_all); (c) losing BOTH factors loses the
        container — there is no third path. Per-compartment export:
        NOT subject to the full-vault 24 h cooldown.
        The two factors must differ (same bytes twice is one factor
        wearing two labels), and in password mode neither may equal
        the live vault password.
        """
        dest = Path(dest)
        self._check_export_guards(dest, auth_method=auth_method,
                                  risk_confirmation=risk_confirmation)
        if dest.exists() and not overwrite:
            raise BackupRefused(f"destination already exists: {dest}")
        secret = self.open_secret(key_id, password=password, wrapping_key=wrapping_key)
        meta = self.get_metadata(key_id)
        # Factor differ-ness: compare only like forms (two passwords,
        # or two wrapping keys). A password factor and a wrapping-key
        # factor cannot be meaningfully compared; the caller must not
        # deliberately set them equal, and the two wrappings still use
        # independent salts/keys even then.
        if export_password is not None and recovery_password is not None \
                and hmac.compare_digest(bytes(export_password), bytes(recovery_password)):
            raise BackupRefused("recovery factor must differ from the primary factor")
        if export_wrapping_key is not None and recovery_wrapping_key is not None \
                and hmac.compare_digest(bytes(export_wrapping_key), bytes(recovery_wrapping_key)):
            raise BackupRefused("recovery factor must differ from the primary factor")
        if meta["auth_scheme"] == "password" and password is not None:
            for factor_pw in (export_password, recovery_password):
                if factor_pw is not None and hmac.compare_digest(
                        bytes(password), bytes(factor_pw)):
                    raise BackupRefused(
                        "a recovery/export factor must differ from the "
                        "live vault password"
                    )
        primary = self._resolve_new_wrapping(
            password=export_password, wrapping_key=export_wrapping_key)
        recovery = self._resolve_new_wrapping(
            password=recovery_password, wrapping_key=recovery_wrapping_key)
        factors = [
            ("primary", primary[0], primary[1], primary[2]),
            ("recovery", recovery[0], recovery[1], recovery[2]),
        ]
        envelope = self._build_dual_envelope(
            key_id=key_id, provider=meta["provider"],
            version=int(meta["compartment_version"]), secret=secret,
            factors=factors,
        )
        atomic_write_bytes(dest, _canonical(envelope))
        return {"key_id": key_id, "provider": meta["provider"],
                "compartment_version": meta["compartment_version"],
                "dest": str(dest), "container": "backup",
                "format": BACKUP_FORMAT2, "factors": list(RECOVERY_FACTORS),
                "semantics": "OR: either factor alone opens this container; "
                "store the two factors separately"}

    def inspect_backup(self, backup_path: str | Path) -> dict:
        """Plaintext backup metadata for display (never a security input).

        Returns format, key_id, provider, version, and — for KHBACKUP2
        — the factor labels. Fields are UNVERIFIED (``header_verified:
        False``): only a restore attempt authenticates them.
        """
        try:
            envelope = json.loads(Path(backup_path).read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise VaultError(f"unreadable backup container: {exc}") from exc
        fmt = envelope.get("format")
        if fmt == BACKUP_FORMAT2:
            factors = [w.get("factor") for w in envelope.get("wrappings", [])]
        elif fmt == BACKUP_FORMAT:
            factors = ["primary"]
        else:
            raise UnsupportedFormatError(
                f"refusing backup with format {fmt!r}. {MIGRATION_DECISION}"
            )
        return {"format": fmt, "key_id": envelope.get("key_id"),
                "provider": envelope.get("provider"),
                "compartment_version": envelope.get("compartment_version"),
                "container": envelope.get("container"),
                "factors": factors, "header_verified": False}

    def export_all(
        self,
        dest_dir: str | Path,
        *,
        credentials: dict,
        auth_method: str,
        risk_confirmation: str | None = None,
    ) -> dict:
        """Full-vault export: one container per compartment, with the
        enforced 24 h cooldown between full-vault exports.

        ``credentials`` maps key_id -> {"password": ...} or
        {"wrapping_key": ...} for opening each live compartment, plus
        an optional ``"__export__"`` entry with the export credential
        (``{"export_password": ...}`` / ``{"export_wrapping_key": ...}``)
        shared across containers. The cooldown timestamp is recorded
        only after every container is written successfully.
        """
        dest_dir = Path(dest_dir)
        self._check_export_guards(dest_dir, auth_method=auth_method,
                                  risk_confirmation=risk_confirmation)
        last = self._last_full_export()
        now = time.time()
        if last is not None and now - last < FULL_EXPORT_COOLDOWN_SECONDS:
            remaining = FULL_EXPORT_COOLDOWN_SECONDS - (now - last)
            raise BackupRefused(
                "full-vault export cooldown active: "
                f"{remaining / 3600:.1f} h remaining (24 h between "
                "full-vault exports, enforced)"
            )
        export_cred = credentials.get("__export__", {})
        exported = []
        for meta in self.list_compartments():
            if meta.get("quarantined"):
                raise BackupRefused(
                    f"refusing full export with quarantined compartment: "
                    f"{meta.get('key_id')}"
                )
            key_id = meta["key_id"]
            cred = credentials.get(key_id, {})
            self.export_compartment(
                key_id,
                dest_dir / f"{key_id}.khbackup.json",
                password=cred.get("password"),
                wrapping_key=cred.get("wrapping_key"),
                export_password=export_cred.get("export_password"),
                export_wrapping_key=export_cred.get("export_wrapping_key"),
                auth_method=auth_method,
                risk_confirmation=risk_confirmation,
                overwrite=True,
            )
            exported.append(key_id)
        self._record_full_export()
        return {"exported": exported, "dest_dir": str(dest_dir),
                "cooldown_seconds": FULL_EXPORT_COOLDOWN_SECONDS,
                # f07 M3 bundle warning, stated in the result itself:
                # one bundle password does NOT multiply entropy across
                # containers — one guessed password opens every key in
                # the bundle. Use a different, strong password per
                # bundle, or export compartments separately.
                "bundle_warning": (
                    "This bundle password protects EVERY key in this "
                    "bundle. If it is guessed or leaked, every key in "
                    "the bundle is exposed. Use a different, strong "
                    "password for each bundle, or export compartments "
                    "separately."
                )}

    # -- restore ---------------------------------------------------------------

    def _enforce_restore_kill_gate(
        self,
        *,
        live_sessions: list | None,
        broker_confirmed_kill: bool,
        kill_callback,
    ) -> dict:
        """Restore kill-gate (v3 N-S3), defined exactly:

        - ``live_sessions``: the broker's current live-session list
          (contents opaque to the vault; only emptiness matters).
          ``None`` is treated as unknown and refused.
        - If it is empty: proceed.
        - If it is non-empty: proceed ONLY if ``broker_confirmed_kill``
          is True AND ``kill_callback`` is supplied; the vault CALLS
          ``kill_callback()`` itself before touching any compartment,
          and records whatever it returns as the kill receipt. A bare
          flag without a callback, or a callback the vault never
          invokes, is not a kill — both are refused.
        - ORDERING (v0.2 hardening): callers validate the backup and
          the live target BEFORE calling this gate, so a restore that
          would refuse never kills sessions pointlessly; the gate is
          still invoked BEFORE any compartment is written, so a
          restore that proceeds always kills first.
        """
        if live_sessions is None:
            raise RestoreBlocked(
                "restore refused: live-session state unknown; the broker "
                "must pass its live-session list (empty if none live)"
            )
        if not live_sessions:
            return {"sessions_killed": []}
        if not broker_confirmed_kill or kill_callback is None:
            raise RestoreBlocked(
                "restore refused while sessions are live: the broker "
                "must confirm the kill and supply a kill_callback that "
                "this vault invokes before any compartment is touched"
            )
        receipt = kill_callback()
        return {"sessions_killed": receipt}

    def _open_backup_secret(
        self,
        backup_path: str | Path,
        *,
        export_password: bytes | None,
        export_wrapping_key: bytes | None,
        recovery_password: bytes | None = None,
        recovery_wrapping_key: bytes | None = None,
    ) -> tuple[bytes, str, str, int]:
        """Decrypt a backup container (either format). Returns
        (secret, key_id, provider, version). For a single-factor
        container, recovery credentials must NOT be supplied — they
        would be silently ignored, so supplying them is refused
        explicitly instead."""
        backup_path = Path(backup_path)
        try:
            envelope = json.loads(backup_path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise VaultError(f"unreadable backup container: {exc}") from exc
        fmt = envelope.get("format")
        if fmt == BACKUP_FORMAT:
            if recovery_password is not None or recovery_wrapping_key is not None:
                raise VaultError(
                    "recovery credentials supplied for a single-factor "
                    "backup container: they would be silently ignored. "
                    "Pass only the export credential, or use a KHBACKUP2 "
                    "container for dual-factor restore"
                )
            secret, _header = self._open_envelope(
                envelope, expected_format=BACKUP_FORMAT,
                password=export_password, wrapping_key=export_wrapping_key,
            )
        elif fmt == BACKUP_FORMAT2:
            secret, _factor = self._open_dual_envelope(
                envelope,
                export_password=export_password,
                export_wrapping_key=export_wrapping_key,
                recovery_password=recovery_password,
                recovery_wrapping_key=recovery_wrapping_key,
            )
        else:
            raise UnsupportedFormatError(
                f"refusing backup with format {fmt!r}. {MIGRATION_DECISION}"
            )
        key_id = envelope["key_id"]
        provider = envelope["provider"]
        backup_version = int(envelope["compartment_version"])
        self._check_key_id(key_id)
        self._check_provider(provider)
        return secret, key_id, provider, backup_version

    def _validate_restore_target(
        self, key_id: str, provider: str, backup_version: int,
        *, overwrite: bool, allow_resurrect: bool,
    ) -> None:
        """Validate the live target BEFORE any kill or write (v0.2).

        Refuses auto-merge, provider mismatch, and resurrecting a
        rotated-out key without the explicit flag. The live version
        here comes from unverified display metadata (f07 H2) — that
        is fail-closed: it can cause a false refusal, never a false
        acceptance, since the restored secret itself comes from the
        fully authenticated backup.
        """
        live_path = self._compartment_path(key_id)
        if not live_path.exists():
            return
        if not overwrite:
            raise RestoreBlocked(
                f"compartment already exists: {key_id} "
                "(restore refuses to auto-merge; pass overwrite=True)"
            )
        meta = self.get_metadata(key_id)
        if meta["provider"] != provider:
            raise RestoreBlocked(
                f"live compartment provider {meta['provider']!r} does not "
                f"match backup provider {provider!r}; refusing to "
                f"overwrite one key's compartment with another's"
            )
        current_version = int(meta["compartment_version"])
        if backup_version < current_version and not allow_resurrect:
            raise RestoreBlocked(
                f"backup version {backup_version} is older than live "
                f"version {current_version}: restoring would resurrect "
                "a rotated-out key; pass allow_resurrect=True only "
                "after warning the user"
            )

    def _write_restored_compartment(
        self, *, key_id: str, provider: str, version: int, secret: bytes,
        password: bytes | None, wrapping_key: bytes | None,
        backup_name: str,
    ) -> dict:
        """Snapshot-then-write a restored live compartment. Called
        ONLY after validation and after the kill gate has run."""
        scheme, salt, wk = self._resolve_new_wrapping(
            password=password, wrapping_key=wrapping_key
        )
        snapshot = self._snapshot_live(key_id)
        new_envelope = self._build_envelope(
            fmt=COMPARTMENT_FORMAT,
            key_id=key_id,
            provider=provider,
            version=version,
            auth_scheme=scheme,
            salt=salt,
            wrapping_key=wk,
            secret=secret,
            backup_marker=False,
        )
        # Informational only: NOT in the header, NOT in any AAD, never
        # trusted on a later open (extra top-level fields are ignored
        # by _open_envelope).
        new_envelope["restored_from"] = backup_name
        atomic_write_bytes(self._compartment_path(key_id), _canonical(new_envelope))
        return {"key_id": key_id, "provider": provider,
                "compartment_version": version,
                "snapshot": snapshot.name if snapshot else None}

    def restore_compartment(
        self,
        backup_path: str | Path,
        *,
        export_password: bytes | None = None,
        export_wrapping_key: bytes | None = None,
        recovery_password: bytes | None = None,
        recovery_wrapping_key: bytes | None = None,
        password: bytes | None = None,
        wrapping_key: bytes | None = None,
        live_sessions: list | None,
        broker_confirmed_kill: bool = False,
        kill_callback=None,
        overwrite: bool = False,
        allow_resurrect: bool = False,
    ) -> dict:
        """Restore ONE compartment from its backup container.

        Order (v0.2, v3 N-S3): (1) decrypt + authenticate the backup
        (either factor for KHBACKUP2); (2) validate the live target
        (no auto-merge, no provider mismatch, no silent resurrect);
        (3) kill live sessions via the broker callback; (4) snapshot
        the previous live generation and write the restored
        compartment, re-baselining the version chain to the backup's
        version. No step (3) happens for a restore that refuses at
        (1) or (2); no step (4) happens before (3). Restored sessions
        are never created: sessions are broker state, not vault state.
        """
        secret, key_id, provider, backup_version = self._open_backup_secret(
            backup_path,
            export_password=export_password,
            export_wrapping_key=export_wrapping_key,
            recovery_password=recovery_password,
            recovery_wrapping_key=recovery_wrapping_key,
        )
        self._validate_restore_target(
            key_id, provider, backup_version,
            overwrite=overwrite, allow_resurrect=allow_resurrect,
        )
        kill_info = self._enforce_restore_kill_gate(
            live_sessions=live_sessions,
            broker_confirmed_kill=broker_confirmed_kill,
            kill_callback=kill_callback,
        )
        result = self._write_restored_compartment(
            key_id=key_id, provider=provider, version=backup_version,
            secret=secret, password=password, wrapping_key=wrapping_key,
            backup_name=Path(backup_path).name,
        )
        return {**result, **kill_info}

    def restore_all(
        self,
        backup_dir: str | Path,
        *,
        key_ids: list[str] | None = None,
        export_password: bytes | None = None,
        export_wrapping_key: bytes | None = None,
        recovery_password: bytes | None = None,
        recovery_wrapping_key: bytes | None = None,
        credentials: dict | None = None,
        live_sessions: list | None,
        broker_confirmed_kill: bool = False,
        kill_callback=None,
        overwrite: bool = False,
        allow_resurrect: bool = False,
    ) -> dict:
        """Restore compartments from a directory of backup containers.

        Order (v0.2, v3 N-S3): (1) pre-validate EVERY selected
        container (decrypt + authenticate; a bad credential or a
        tampered container aborts the whole restore before any kill
        or write, so there is no partial restore from bad input);
        (2) validate every live target; (3) kill live sessions
        EXACTLY ONCE via the broker callback; (4) write every
        restored compartment. Files in the directory whose key_id
        cannot even be read are NOT silently dropped: they are
        reported in ``skipped`` with a reason. A write failure during
        (4) propagates after the kill — earlier writes stand, and a
        retry must use ``overwrite=True``. ``key_ids`` selects a
        subset (per-compartment select, v3 N-S3); ``None`` restores
        every container found. ``credentials`` maps key_id -> vault
        credential for the restored live compartment. Recovery
        credentials are passed only to KHBACKUP2 containers (passing
        them to a single-factor container would be refused as a
        silent-ignore risk — see _open_backup_secret).
        """
        backup_dir = Path(backup_dir)
        credentials = credentials or {}
        planned = []  # (path, secret, key_id, provider, version, live cred)
        skipped = []
        for path in sorted(backup_dir.glob("*.khbackup.json")):
            try:
                peek = json.loads(path.read_text(encoding="utf-8"))
                peek_key_id = peek["key_id"]
                peek_format = peek.get("format")
            except (ValueError, OSError, KeyError):
                skipped.append({"file": path.name,
                                "reason": "unreadable: key_id not determinable; "
                                "not restored, not silently dropped"})
                continue
            if key_ids is not None and peek_key_id not in key_ids:
                continue
            if peek_format == BACKUP_FORMAT2:
                rec_pw, rec_wk = recovery_password, recovery_wrapping_key
            else:
                rec_pw, rec_wk = None, None
            secret, key_id, provider, version = self._open_backup_secret(
                path,
                export_password=export_password,
                export_wrapping_key=export_wrapping_key,
                recovery_password=rec_pw,
                recovery_wrapping_key=rec_wk,
            )
            self._validate_restore_target(
                key_id, provider, version,
                overwrite=overwrite, allow_resurrect=allow_resurrect,
            )
            cred = credentials.get(key_id, {})
            planned.append((path, secret, key_id, provider, version, cred))
        kill_info = self._enforce_restore_kill_gate(
            live_sessions=live_sessions,
            broker_confirmed_kill=broker_confirmed_kill,
            kill_callback=kill_callback,
        )
        restored = []
        for path, secret, key_id, provider, version, cred in planned:
            self._write_restored_compartment(
                key_id=key_id, provider=provider, version=version,
                secret=secret, password=cred.get("password"),
                wrapping_key=cred.get("wrapping_key"),
                backup_name=path.name,
            )
            restored.append(key_id)
        return {"restored": restored, "skipped": skipped, **kill_info}
