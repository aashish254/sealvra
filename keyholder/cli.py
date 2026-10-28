"""Keyholder CLI (W10) — exact command surface, CONTRACT §9.

Commands (exact, no others exist):

    keyholder daemon start|stop|status
    keyholder keys add|list|show|delete|rotate
    keyholder sessions list|create|kill|kill-all
    keyholder audit verify|export
    keyholder doctor
    keyholder prove-isolation
    keyholder --help
    keyholder --version

Deliberately absent — there is no command or flag that displays a
stored key, re-displays a session token, approves a session or call,
extends a session, or hands a token to another program. Unknown
commands and unknown flags are usage errors (KH-2001, exit 1), never
silently accepted. Approval decisions come ONLY from the broker-owned
approver (W08); this CLI is read + kill only for approvals, and kill
needs no auth.

Error catalogue (CONTRACT §9 — one table, same event, same code,
every surface; v3 §1M N-M4 rebuild, f12 C6 fixes):

    KH-1001 vault locked (exit 1)
    KH-1002 session not found / expired / killed (exit 2)
    KH-1003 policy denied (exit 2)
    KH-1004 approval denied / timeout (exit 2)
    KH-1005 audit unavailable (exit 3)
    KH-1006 provider / upstream error (exit 1)
    KH-2001 invalid input / usage (exit 1)
    KH-3001 platform unsupported for this action (exit 1)
    KH-3002 isolation / proof failure (exit 3)
    KH-3003 secret detected in log (exit 3)

  Families (f12 C6 fix 1): KH-1xxx are operational events, KH-2xxx is
  input/usage ONLY (KH-2001 alone), KH-3xxx are platform/isolation/
  secret events. Approval, SSH, and grant decision failures are
  approval events (KH-1004), never vault-family codes: the retired
  approval-family codes (KH-2003–KH-2008, GUI KH-6001–KH-6004) map
  through ``RETIRED_CODES`` to KH-1004 and must never be emitted.
  Approval failed / cancelled / dismissed / timed out / unavailable
  are ONE event (KH-1004); surfaces may add detail, never a new code.
  Every code carries exactly one next step (``NEXT_STEPS``) — no code
  has a "none" next step; a cancelled/dismissed approval is a normal
  outcome whose next step says so.
  Cross-key access attempt (legacy KH-1009) is deterministically
  KH-1003, exit 2 — a routine policy denial, never exit 1, never
  exit 3. KH-1009 itself is retired and must never be emitted.
  Failed ``prove-isolation`` is KH-3002, exit 3: its own self-test
  code, never the routine policy denial KH-1003 (exit 2). Any
  backend failure inside the prove-isolation command is also
  KH-3002 (a proof that cannot run is a failed proof, not a
  provider error). A broker cross-accept found by the self-test is
  KH-3002; an agent's cross-key attempt denied at the proxy is
  KH-1003 — the two are different events and must not share a code.

Two catalogue notes, applied honestly rather than silently:
  * ``audit verify`` UNANCHORED is amber with exit 2 per CONTRACT §8,
    while TAMPERED and MISSING-DIRECTORY exit 3. All three are
    reported under KH-1005 (the only audit code); the status word and
    the exit code carry the distinction. This is the single
    CONTRACT-mandated exception to "one code, one exit", and it is
    documented here rather than hidden: the event differs by status
    word (UNANCHORED vs TAMPERED), not by surface.
  * The catalogue has no "backend module not yet installed" code. A
    missing dependency module is reported as KH-1006 (exit 1), except
    for audit commands, where it is KH-1005 (exit 3). The message
    always names the missing module.

Backend seams (no stubs in production code):
  Dependency modules (W01 daemon/broker, W02 vault, W03 sessions,
  W09 audit) do not exist yet at the time this CLI was written. Each
  ``_load_*`` function below imports its module lazily and raises a
  catalogue error when it is absent. Tests stub these loader
  functions inside the test file only. The interfaces this CLI
  expects from those modules are:

  * daemon: ``status()`` -> {"running": bool, "pid": int|None,
    "socket": str|None}; ``start()`` / ``stop()`` -> dict, where
    ``stop()`` may report "sessions_killed": bool.
  * vault: ``list_keys()``; ``get_key(key_id)`` -> record or None;
    ``add_key(provider, label, secret, ever_pasted)`` -> record;
    ``delete_key(key_id)``; ``rotate_key(key_id, new_secret)``
    -> record. Records expose ``key_id``, ``provider``, ``label``,
    ``created_at``, ``needs_rotation`` (bool) and, for the owning
    key's detail view only, ``fingerprint`` (first 12 hex chars of
    SHA-256 of the secret).
  * sessions: ``list_sessions()``; ``create_session(key_id,
    provider, session_class, transport, minutes, label)`` -> object
    with ``session_id``, ``token`` (returned exactly once),
    ``expires_at``; ``kill_session(session_id)`` -> receipt dict;
    ``kill_all()`` -> receipt dict. Receipts may carry
    "already_forwarded": [descriptions] for the kill receipt.
  * audit: ``verify()`` -> {"status": "OK"|"UNANCHORED"|"TAMPERED"|
    "MISSING-DIRECTORY", "entries": int}; ``export(path)`` ->
    {"entries": int, "path": str}.
  * broker (prove-isolation): preferred self-performed check —
    sessions exposes ``create_ephemeral_session()`` returning
    (session_id, token) pairs and broker exposes
    ``validate_token(session_id, token)`` -> bool; the CLI mints two
    ephemeral sessions and requires each token to validate for its
    own session and be denied for the other. Fallback — broker
    exposes ``prove_isolation()`` -> {"ok": bool, "detail": str}.
    If neither interface exists, the proof FAILS (exit 3, KH-3002);
    an unprovable claim is never reported as a pass.
  Backend errors that carry a ``code`` attribute in the catalogue
  above are passed through unchanged; other backend exceptions map
  to KH-1006.

  KNOWN INTEGRATION GAP (observed, not yet adjudicated): the
  dependency modules as landed are class-based and in-process
  (``Daemon``/``Broker``/``SessionStore``/``Vault``/``AuditLog``),
  and the daemon's loopback socket currently answers only
  status/ping — there is no CLI client protocol for keys, sessions
  or audit export, and no agreed vault-dir / audit-root convention
  for a CLI process to instantiate them. Until the manager defines
  that client interface, this CLI's loader seam above is the
  integration point and the fakes in tests/test_w10_cli.py stand in
  for it. The CLI must NOT instantiate those classes itself: a
  second in-process daemon is not the running daemon, and a CLI-side
  vault instance would guess at another worker's state layout.

  Approval (W08) is intentionally never imported here: the CLI must
  not be able to approve anything.

TTL table (CONTRACT §3, v3 §1B R07 — the ONLY table), minutes:
  destructive  default 10, cap 15
  write        default 20, cap 30
  read_account default 30, cap 60
  read_public  default 60, cap 120
  Absolute hard cap 2 hours for everything. No session extensions,
  ever: re-issuance is a new session plus a fresh gesture.

Quit semantics (v3 §1M N-M2, one rule for every quit path):
quit confirmation defaults to Keep sessions, never to destruction.
There is no quit command in this surface; ``daemon stop`` keeps
sessions unless the daemon reports otherwise, and ending them is
always the separate, explicit ``sessions kill-all`` action. The GUI
quit path (gui.py) shares this default: closing the window never
kills sessions; "Quit and kill all" is a separate, explicit action.
See ``QUIT_DEFAULT`` / ``quit_confirmation_text`` and ``DEFAULTS``.

Defaults (v3 §1M N-M5, one table — ``DEFAULTS`` below, mirrored in
gui.py; no surface restates a number): TTL per class per CONTRACT §3
with the 2 h absolute hard cap (no duration offer above 2 h anywhere;
``--minutes`` above the class cap is KH-2001); approval timeout 60 s
default, 120 s accessibility opt-in ONLY (the 15–300 s and 30–300 s
ranges are deleted); session idle 5 min default, range 2–15 min,
cannot be disabled, and there is NO vault-idle setting (deleted per
v3 N-B3); no-OS-auth rule is refuse (see ``NO_OS_AUTH_RULE``);
update-check default is UNDECIDED — G0 decision OD-13, owned with W17
(see ``DEFAULTS["update_check_default"]``: None until the manager
records it; neither surface may claim on or off before then). There
is no credential-clipboard handoff in this build, so no auto-clear
value is published at all.

Wired-token lifecycle (v3 §1M N-M6, specified end to end — pure
helpers below; the future wiring writer must consume them, they do
not by themselves write any config): on kill AND on expiry the wired
token is stripped or the config is restored from its pre-wiring
backup (see ``end_wired_session``); a backup that itself contains a
live token is NEVER restored and is deleted; no ``.bak`` containing
a live token is ever left behind; the wiring surface carries
``WIRED_TOKEN_SHARE_WARNING`` (do not share, sync, or commit the
wired config); "Copy agent setup" from a live session copies setup
WITHOUT the token (``copy_agent_setup`` refuses any snippet
containing the token) — the token is shown exactly once, at
creation, and a second agent is wired by creating a new session.

No-OS-auth rule (v3 §1E N-E13, the ONLY rule): refuse. No competing
fallback survives in this module: session-starting and approval
actions are impossible without OS authentication, and the OS
password via the system prompt is the floor. See
``NO_OS_AUTH_RULE`` / ``no_os_auth_error`` (KH-1004, exit 2).

Trust copy (v3 §3 P-01/P-10, §4A G0-21/G0-22): the first-run screen
leads with the key-theft/data-theft distinction, states that this
product will never contact the user out of the blue (a defence
against fake-product squatting), and carries the counter with its
"*since import*" qualifier in the screen itself, not a footnote.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import re
import sys

VERSION = "0.1.0"

# ------------------------------------------- update-check payload (W17, v0.2)
#
# Scope of this section (CONTRACT §13.6, W17): the update-check
# payload ONLY. There is no updater, no update command, and no
# network call in this module — v0.2 still ships no updater (see
# docs/supply-chain.md), so with defaults untouched there is zero
# update traffic. These pure functions exist so that when an
# updater slice lands it cannot reintroduce the v3/f11 defect:
# §18's first-install UUID whose stable hash selected the served
# manifest — a stable identifier on every check, linkable across
# days, that §11 forbade and never disclosed (f11 F-C1, v3 N-L3).
#
# Payload rule (f11 F-C1, v3 N-L3, fixed here): an update check
# sends version + OS family + arch and NOTHING else. No user id,
# no device id, no installation id, no stable hash of any of
# them, no timestamp/day, no channel. Rollout targeting, if used
# at all, is computed CLIENT-SIDE: the local installation value
# is hashed locally and only the resulting bucket NUMBER leaves
# (or rollout is time-based, in which case no extra field leaves
# at all). The bucket number is optional and is the only field
# ever added to the base three, and only when the caller passes
# it explicitly. Nothing in this section generates, stores, or
# sends an installation/device identifier.
#
# Default (f11 F-C6, v3 N-L5 / OD-13): the update-check default
# is an owner G0 decision (OD-13) that has NOT been made. The
# f16 audit recommends ON with a clear off switch; that
# recommendation is recorded below as a recommendation ONLY and
# must never be read as the decided default. UPDATE_CHECK_DEFAULT
# stays None (undecided) until the owner confirms OD-13; W18
# owns wiring the eventual default into settings/CLI, and must
# not treat the recommendation as the decision. Until then no
# code path may enable update checks by default.
#
# Pack updates (f11 F-K1, v3 N-L4, chosen path): provider packs
# ship INSIDE product updates only. There is no separate pack
# fetch, no per-pack identifier in any request, and no
# independent pack-update poller (pack staleness is computed
# locally only). A future separate pack fetch is forbidden
# until the allowlist below is amended and a test asserting
# no per-provider selection signal lands with it.

UPDATE_CHECK_PAYLOAD_FIELDS = ("version", "os", "arch")
UPDATE_CHECK_RECOMMENDED_DEFAULT = "on"  # f16 recommendation, NOT decided
UPDATE_CHECK_DEFAULT = None  # undecided pending owner confirmation (OD-13)
UPDATE_CHECK_ROLLOUT_BUCKETS = 100

# Egress allowlist rows for the update channel (v0.2). Each row is
# the complete, honest statement of that connection; anything not
# listed here does not happen over the network. "destination" is
# deliberately generic: no canonical update host exists yet
# because no updater ships — inventing a hostname here would be
# a claim about infrastructure that does not exist.
UPDATE_EGRESS_ALLOWLIST = (
    {
        "name": "update-check",
        "trigger": "only when the user has opted into automatic checks "
        "(default pending owner confirmation, OD-13) or runs a "
        "manual check",
        "destination": "canonical product update host (to be named by "
        "the updater slice; no host exists in v0.2)",
        "payload": "version + OS family + arch only; optionally a "
        "client-side rollout bucket number and nothing else",
        "separate_connection": True,
        "per_pack_identifier": None,
        "implemented_in_v0_2": False,
    },
    {
        "name": "update-download",
        "trigger": "only after the user accepts an offered update",
        "destination": "canonical artifact host (to be named by the "
        "updater slice; no host exists in v0.2)",
        "payload": "none beyond the artifact request itself; artifact "
        "URLs are generic and identical for all clients of a "
        "version/arch — no per-client signed URL tokens",
        "separate_connection": True,
        "per_pack_identifier": None,
        "implemented_in_v0_2": False,
    },
    {
        "name": "pack-update",
        "trigger": "never separately: packs arrive inside a product "
        "update download only",
        "destination": "none (no separate connection; rides the "
        "update-download above)",
        "payload": "none (no request of its own, so no per-pack "
        "identifier can leak provider inventory)",
        "separate_connection": False,
        "per_pack_identifier": None,
        "implemented_in_v0_2": True,
    },
)

_OS_FAMILY = {"darwin": "macos", "windows": "windows", "linux": "linux"}
_ARCH_NORMALISED = {
    "x86_64": "x86_64", "amd64": "x86_64",
    "arm64": "arm64", "aarch64": "arm64",
}


def _normalise_os_family(system_name: str) -> str:
    """Coarse OS family only — never a version, build, or distro string."""
    return _OS_FAMILY.get(str(system_name).strip().lower(), "other")


def _normalise_arch(machine: str) -> str:
    """Coarse arch only; unknown machines collapse to 'other' rather
    than leaking a detailed platform string."""
    return _ARCH_NORMALISED.get(str(machine).strip().lower(), "other")


def client_rollout_bucket(local_seed: str, num_buckets: int = UPDATE_CHECK_ROLLOUT_BUCKETS) -> int:
    """Compute a rollout bucket CLIENT-SIDE from a local value.

    Only the returned integer may ever leave the machine. The seed
    itself, and the hash of the seed, are never sent, never logged,
    and never stored in a payload: a bucket number is not a stable
    identifier (many installations share each bucket), while a
    stable hash of an installation UUID is (f11 F-C1). The seed
    must be a local-only value; callers must not pass a device id,
    installation id, or any value that is itself sent elsewhere.
    """
    if not isinstance(local_seed, str) or not local_seed:
        raise _err("KH-2001", "rollout bucket needs a non-empty local seed")
    if not isinstance(num_buckets, int) or num_buckets <= 0:
        raise _err("KH-2001", "rollout bucket count must be a positive integer")
    digest = hashlib.sha256(local_seed.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % num_buckets


def build_update_check_payload(
    version: str,
    os_family: str,
    arch: str,
    rollout_bucket: int | None = None,
) -> dict:
    """Build the exact update-check payload — and nothing else.

    Keys are exactly {"version", "os", "arch"}, plus
    "rollout_bucket" only when the caller explicitly passes a
    client-side bucket number (see client_rollout_bucket). Any
    other field — device/installation id, channel, timestamp,
    user id — is a consent defect, not a typo, and this function
    has no parameter that could carry one. This function performs
    no I/O and no network call; it only builds the dict.
    """
    if not version or not isinstance(version, str):
        raise _err("KH-2001", "update-check payload needs a version string")
    payload: dict = {
        "version": version,
        "os": _normalise_os_family(os_family),
        "arch": _normalise_arch(arch),
    }
    if rollout_bucket is not None:
        if (
            not isinstance(rollout_bucket, int)
            or isinstance(rollout_bucket, bool)
            or not 0 <= rollout_bucket < UPDATE_CHECK_ROLLOUT_BUCKETS
        ):
            raise _err(
                "KH-2001",
                f"rollout_bucket must be an int in [0, {UPDATE_CHECK_ROLLOUT_BUCKETS})",
            )
        payload["rollout_bucket"] = rollout_bucket
    return payload


def default_update_check_payload() -> dict:
    """Payload for this build on this machine (pure, no network)."""
    import platform

    return build_update_check_payload(
        VERSION, platform.system(), platform.machine()
    )


def resolve_update_check_default() -> dict:
    """Report the update-check default state without deciding it.

    Returns {"default": None, "recommended": "on",
    "status": "pending-owner-confirmation (OD-13)"}. Callers must
    treat default None as "do not enable checks": the f16
    recommendation for ON is not the owner's decision, and no
    fresh install may send update traffic on the strength of it.
    """
    return {
        "default": UPDATE_CHECK_DEFAULT,
        "recommended": UPDATE_CHECK_RECOMMENDED_DEFAULT,
        "status": "pending-owner-confirmation (OD-13)",
    }


# ---------------------------------------------------------------- errors

ERROR_CATALOGUE = {
    "KH-1001": (1, "vault locked"),
    "KH-1002": (2, "session not found / expired / killed"),
    "KH-1003": (2, "policy denied"),
    "KH-1004": (2, "approval denied / timeout"),
    "KH-1005": (3, "audit unavailable"),
    "KH-1006": (1, "provider / upstream error"),
    "KH-2001": (1, "invalid input / usage"),
    "KH-3001": (1, "platform unsupported for this action"),
    "KH-3002": (3, "isolation / proof failure"),
    "KH-3003": (3, "secret detected in log"),
}

# Retired codes: never emitted. A backend emitting one is remapped
# by _backend_error to the canonical code (same event, same code).
# KH-1009 cross-key attempt -> KH-1003 (exit 2, deterministic).
# KH-2003/2004/2008 approval failures and KH-6001-6004 GUI approval
# codes -> KH-1004. KH-2005/2006/2007 (approval/SSH/grant decision
# failures with no exit code in the old scheme) -> KH-1004 as
# approval events; a pure usage error in those commands is KH-2001.
RETIRED_CODES = {
    "KH-1009": "KH-1003",
    "KH-2003": "KH-1004",
    "KH-2004": "KH-1004",
    "KH-2005": "KH-1004",
    "KH-2006": "KH-1004",
    "KH-2007": "KH-1004",
    "KH-2008": "KH-1004",
    "KH-6001": "KH-1004",
    "KH-6002": "KH-1004",
    "KH-6003": "KH-1004",
    "KH-6004": "KH-1004",
}

# One event = one code, by event name (surfaces add detail, never a
# new code for the same event).
EVENT_TO_CODE = {
    "vault_locked": "KH-1001",
    "session_not_found": "KH-1002",
    "session_expired": "KH-1002",
    "session_killed": "KH-1002",
    "policy_denied": "KH-1003",
    "cross_key_attempt": "KH-1003",
    "approval_failed": "KH-1004",
    "approval_cancelled": "KH-1004",
    "approval_dismissed": "KH-1004",
    "approval_timeout": "KH-1004",
    "approval_unavailable": "KH-1004",
    "os_auth_unavailable": "KH-1004",
    "audit_unavailable": "KH-1005",
    "provider_error": "KH-1006",
    "invalid_input": "KH-2001",
    "platform_unsupported": "KH-3001",
    "prove_isolation_failed": "KH-3002",
    "isolation_failure": "KH-3002",
    "secret_detected": "KH-3003",
}

# Exactly one next step per canonical code (f12 C6 fix 5). A
# cancelled/dismissed approval is a normal outcome: its next step
# says no action is needed, it does not say "none".
NEXT_STEPS = {
    "KH-1001": "unlock the vault, then retry",
    "KH-1002": "list sessions to check state, then create a new session if needed",
    "KH-1003": "narrow the request to the session's approved scope, or create a new session with that scope",
    "KH-1004": "re-request approval if you still want the call to proceed; no action is needed if you dismissed it",
    "KH-1005": "do not proceed with new calls until the audit log is available again",
    "KH-1006": "retry later, or check the provider status, then retry",
    "KH-2001": "rerun with valid input (see --help)",
    "KH-3001": "use a supported platform for this action",
    "KH-3002": "stop using sessions, kill all sessions, and report this as a possible isolation failure",
    "KH-3003": "remove the secret from the log source and rotate the affected key at the provider",
}

# One defaults table (v3 N-M5). Mirrored verbatim in gui.py; the
# cross-module test asserts the shared keys are identical, so no
# surface can drift a number on its own. update_check_default is
# None by design: G0 decision OD-13 is undecided, W17 owns the
# payload, and no surface may claim on or off until the manager
# records the decision.
DEFAULTS = {
    "ttl_minutes": {
        "destructive": (10, 15),
        "write": (20, 30),
        "read_account": (30, 60),
        "read_public": (60, 120),
    },
    "hard_cap_minutes": 120,
    "approval_timeout_s": 60,
    "approval_timeout_accessibility_s": 120,
    "idle_default_minutes": 5,
    "idle_min_minutes": 2,
    "idle_max_minutes": 15,
    "idle_can_disable": False,
    "quit_default": "keep_sessions",
    "no_os_auth": "refuse",
    "update_check_default": None,
}

QUIT_DEFAULT = "keep_sessions"
QUIT_CONFIRM_DEFAULT = "Keep sessions"

# The single no-OS-auth rule (v3 N-E13). Competing fallbacks are
# deleted, not kept alongside this rule.
NO_OS_AUTH_RULE = (
    "refuse: without OS authentication, session-starting and "
    "approval actions are impossible. No substitute authentication "
    "is offered by the app itself; the OS password via the system "
    "prompt is the floor everywhere."
)

WIRED_TOKEN_SHARE_WARNING = (
    "Warning: this agent config file now contains a live session "
    "token. Do not share, sync, or commit this file, and do not "
    "paste its contents into a chat or issue. The token dies with "
    "the session, but while the session is live it can be used by "
    "anyone holding this file."
)

COPY_SETUP_RULE = (
    "Copy agent setup from a live session copies setup WITHOUT the "
    "session token. The token is shown exactly once, at creation, "
    "and is never re-displayed. To wire another agent, kill this "
    "session if needed and create a new session."
)

WIRED_TOKEN_LIFECYCLE = {
    "on_kill": "strip the token from the config, or restore the pre-wiring backup, then delete the .bak",
    "on_expiry": "same as on kill: strip the token, or restore the pre-wiring backup, then delete the .bak",
    "bak_with_live_token": "never restored, always deleted; no .bak containing a live token is ever left behind",
    "bak_without_live_token": "restored on kill/expiry, then deleted",
    "share_warning": WIRED_TOKEN_SHARE_WARNING,
    "copy_setup": COPY_SETUP_RULE,
}


class KeyholderError(Exception):
    """A catalogue error: same event, same code, every surface."""

    def __init__(self, code: str, message: str | None = None):
        self.code = code
        self.exit_code, default = ERROR_CATALOGUE[code]
        super().__init__(message or default)
        self.message = message or default


class _UsageError(Exception):
    """argparse-level usage problem, reported as KH-2001."""


def _err(code: str, message: str | None = None) -> KeyholderError:
    return KeyholderError(code, message)


def _backend_error(exc: Exception) -> KeyholderError:
    """Map a backend exception onto the catalogue, passing codes through."""
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code in RETIRED_CODES:
        return KeyholderError(RETIRED_CODES[code], str(exc) or None)
    if isinstance(code, str) and code in ERROR_CATALOGUE:
        return KeyholderError(code, str(exc) or None)
    if isinstance(exc, KeyholderError):
        return exc
    return KeyholderError("KH-1006", f"backend error: {exc}")


def canonical_code(code: str) -> str:
    """Canonical code for a current or retired code. Raises KH-2001
    for a code that is neither current nor retired."""
    if code in ERROR_CATALOGUE:
        return code
    if code in RETIRED_CODES:
        return RETIRED_CODES[code]
    raise _err("KH-2001", f"unknown error code: {code!r}")


def error_for_event(event: str, message: str | None = None) -> KeyholderError:
    """One event = one code: build the catalogue error for an event."""
    code = EVENT_TO_CODE.get(event)
    if code is None:
        raise _err("KH-2001", f"unknown error event: {event!r}")
    return KeyholderError(code, message)


def no_os_auth_error() -> KeyholderError:
    """The single no-OS-auth outcome: refuse, as KH-1004 (exit 2)."""
    return KeyholderError("KH-1004", NO_OS_AUTH_RULE)


def resolve_approval_timeout(accessibility: bool = False) -> int:
    """Approval timeout in seconds: 60 default, 120 accessibility
    opt-in only. No other value exists; the old ranges are deleted."""
    return DEFAULTS["approval_timeout_accessibility_s"] if accessibility else DEFAULTS["approval_timeout_s"]


def resolve_approval_timeout_value(requested: int | None, accessibility: bool = False) -> int:
    """Validate an explicitly requested approval timeout: only 60,
    or 120 with the accessibility opt-in. Anything else is KH-2001."""
    if requested is None:
        return resolve_approval_timeout(accessibility)
    if requested == DEFAULTS["approval_timeout_s"]:
        return requested
    if requested == DEFAULTS["approval_timeout_accessibility_s"] and accessibility:
        return requested
    raise _err(
        "KH-2001",
        "approval timeout is 60 seconds, or 120 seconds with the "
        "accessibility opt-in only; no other value is offered",
    )


def resolve_idle_minutes(requested: int | None = None) -> int:
    """Session idle timeout in minutes: 5 default, range 2-15, cannot
    be disabled (0 or out-of-range is KH-2001). There is no separate
    vault-idle setting."""
    if requested is None:
        return DEFAULTS["idle_default_minutes"]
    if not isinstance(requested, int) or isinstance(requested, bool):
        raise _err("KH-2001", "idle timeout must be a whole number of minutes")
    if requested < DEFAULTS["idle_min_minutes"] or requested > DEFAULTS["idle_max_minutes"]:
        raise _err(
            "KH-2001",
            "idle timeout must be 2-15 minutes and cannot be disabled",
        )
    return requested


def quit_confirmation_text(live_count: int | None = None) -> str:
    """Quit confirmation copy. The default choice is always Keep
    sessions; destruction is a separate, explicit action."""
    count = f"{live_count} live session(s) " if live_count is not None else "live sessions "
    return (
        f"Quitting closes Keyholder but does not kill {count}or stop "
        "the daemon's sessions. Default: Keep sessions. To end "
        "sessions, use the separate `keyholder sessions kill-all` "
        "action (or 'Quit and kill all' in the GUI)."
    )


def strip_wired_token(config_text: str, token: str) -> str:
    """Reference strip for the wiring writer: remove every occurrence
    of the wired token from config text. Other content is untouched."""
    if not token:
        raise _err("KH-2001", "cannot strip an empty wired token")
    return config_text.replace(token, "")


def end_wired_session(wired_config: str, token: str, backup_config: str | None,
                      backup_had_live_token: bool) -> dict:
    """End-of-life for a wired config, on kill and on expiry alike.

    backup_config is the pre-wiring file content (or None if there
    was no backup). A backup without a live token is restored and
    then deleted. A backup WITH a live token is never restored —
    restoring it would re-plant a live token — and is deleted.
    With no usable backup, the token is stripped from the wired
    config. In every case no .bak is left behind.
    Returns {"config_text", "backup_action", "token_remaining"}.
    """
    if not token:
        raise _err("KH-2001", "cannot end a wired session without its token")
    if backup_config is not None and not backup_had_live_token:
        return {
            "config_text": backup_config,
            "backup_action": "restored-and-deleted",
            "token_remaining": token in backup_config,
        }
    stripped = strip_wired_token(wired_config, token)
    return {
        "config_text": stripped,
        "backup_action": "deleted-without-restore",
        "token_remaining": token in stripped,
    }


def copy_agent_setup(snippet: str, token: str | None) -> str:
    """Copy-setup rule, enforced: a snippet containing the token is
    refused (KH-2001) — the token is never re-displayed. A clean
    snippet is returned with the copy-setup rule attached."""
    if token and token in snippet:
        raise _err(
            "KH-2001",
            "copy agent setup must never contain the session token; "
            "the token is shown exactly once, at creation",
        )
    return snippet + "\n" + COPY_SETUP_RULE


# ------------------------------------------------------------ backend seams


def _load_daemon():
    try:
        from keyholder import daemon

        return daemon
    except ImportError as exc:
        raise _err(
            "KH-1006", f"daemon unavailable: keyholder.daemon is not installed ({exc.name})"
        ) from exc


def _load_vault():
    try:
        from keyholder import vault

        return vault
    except ImportError as exc:
        raise _err(
            "KH-1006", f"vault unavailable: keyholder.vault is not installed ({exc.name})"
        ) from exc


def _load_sessions():
    try:
        from keyholder import sessions

        return sessions
    except ImportError as exc:
        raise _err(
            "KH-1006",
            f"sessions unavailable: keyholder.sessions is not installed ({exc.name})",
        ) from exc


def _load_broker():
    try:
        from keyholder import broker

        return broker
    except ImportError as exc:
        raise _err(
            "KH-3002",
            f"isolation proof failed: keyholder.broker is not installed ({exc.name}); "
            "an unprovable isolation claim is never reported as a pass",
        ) from exc


def _load_audit():
    try:
        from keyholder import audit

        return audit
    except ImportError as exc:
        raise _err(
            "KH-1005", f"audit unavailable: keyholder.audit is not installed ({exc.name})"
        ) from exc


def _field(obj, name, default=None):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


# ------------------------------------------------------------------- TTL

TTL_TABLE = {
    "destructive": (10, 15),
    "write": (20, 30),
    "read_account": (30, 60),
    "read_public": (60, 120),
}
HARD_CAP_MINUTES = 120


def _resolve_minutes(session_class: str, minutes) -> int:
    default, cap = TTL_TABLE[session_class]
    if minutes is None:
        return default
    if not isinstance(minutes, int) or minutes <= 0:
        raise _err("KH-2001", "duration must be a positive number of minutes")
    if minutes > cap:
        raise _err(
            "KH-2001",
            f"{session_class} sessions are capped at {cap} minutes "
            f"(absolute hard cap {HARD_CAP_MINUTES} minutes for everything); "
            "sessions are never extended — create a new session instead",
        )
    return minutes


# ---------------------------------------------------------------- prompts


def _ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError as exc:
        raise _err("KH-2001", "input is required but none was provided") from exc


def _ask_secret(prompt: str) -> str:
    try:
        value = getpass.getpass(prompt)
    except EOFError as exc:
        raise _err("KH-2001", "input is required but none was provided") from exc
    if not value:
        raise _err("KH-2001", "empty key is not accepted")
    return value


def _fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()[:12]


# ------------------------------------------------------------- first run

FIRST_RUN_TEXT = """Keyholder {version} — first run
================================

A note on trust: we will never contact you. If anyone claiming to be Keyholder emails,
messages, or calls you asking for a key, a token, or a recovery phrase,
it is not us. This product has no account, no cloud, and no support
channel that reaches out to you.

What Keyholder does: it stops *key* theft, not *data* theft.
Your long-lived keys are stored only on this machine and are never
sent to us. An agent's approved API call does send the key in that
call's header to the provider you chose — that is the job you
approved. A session token the agent holds is scoped, short-lived,
and worthless once the session is killed or expires — but while a
session is live, a leaked token can still be used until you kill it.

The product never syncs on its own, ever. Backups you export yourself
into a cloud folder leave by your action, not by sync.

Keys in your vault: 0. Times any key has left this machine *since import*: 0
— counting only broker-observed departures. Approved calls send the key
to the provider (see above); undetected leaks would not increment
this counter.

Next steps:
  keyholder keys add     import a key (you will be asked whether it
                         was ever pasted anywhere)
  keyholder doctor       inventory standing credentials on this machine
  keyholder --help       full command list
"""


def _cmd_first_run(out) -> int:
    out.write(FIRST_RUN_TEXT.format(version=VERSION))
    return 0


# ---------------------------------------------------------------- daemon


def _cmd_daemon(args, out) -> int:
    daemon = _load_daemon()
    try:
        if args.daemon_cmd == "status":
            info = daemon.status()
            if _field(info, "running"):
                pid = _field(info, "pid")
                out.write(f"daemon: running{f' (pid {pid})' if pid else ''}\n")
            else:
                out.write("daemon: stopped\n")
            return 0
        if args.daemon_cmd == "start":
            info = daemon.status()
            if _field(info, "running"):
                out.write("daemon: already running\n")
                return 0
            daemon.start()
            out.write("daemon: started\n")
            return 0
        if args.daemon_cmd == "stop":
            info = daemon.status()
            if not _field(info, "running"):
                out.write("daemon: not running\n")
                return 0
            result = daemon.stop()
            killed = _field(result, "sessions_killed")
            if killed:
                out.write(
                    "daemon: stopped — note: the daemon reported live sessions "
                    "were ended by this stop\n"
                )
            elif killed is False:
                out.write(
                    "daemon: stopped — sessions kept (quit defaults to Keep "
                    "sessions; end them explicitly with "
                    "`keyholder sessions kill-all`)\n"
                )
            else:
                # Backend did not report a disposition: never claim
                # sessions were kept when that is unknown.
                out.write(
                    "daemon: stopped — session disposition not reported by "
                    "the daemon; end any remaining sessions explicitly with "
                    "`keyholder sessions kill-all`\n"
                )
            return 0
    except KeyholderError:
        raise
    except Exception as exc:  # backend failure, catalogue-mapped
        raise _backend_error(exc) from exc
    raise _err("KH-2001", "unknown daemon command")


# ------------------------------------------------------------------ keys


def _cmd_keys(args, out) -> int:
    vault = _load_vault()
    try:
        if args.keys_cmd == "list":
            keys = vault.list_keys()
            if not keys:
                out.write("no keys in vault\n")
            for record in keys:
                line = (
                    f"{_field(record, 'key_id')}  "
                    f"{_field(record, 'provider')}  "
                    f"{_field(record, 'label')}  "
                    f"created {_field(record, 'created_at')}"
                )
                out.write(line + "\n")
                if _field(record, "needs_rotation"):
                    out.write(
                        "  WARNING: NOT YET ROTATED — this key was (or may "
                        "have been) pasted somewhere before import. Rotate "
                        "it at the provider before its first session, then "
                        "record the rotation with `keyholder keys rotate "
                        f"{_field(record, 'key_id')}`. This warning stays "
                        "until rotation is recorded.\n"
                    )
            out.write(
                "Broker-observed departures are counted in the audit log; "
                "undetected leaks would not appear there.\n"
            )
            return 0

        if args.keys_cmd == "show":
            record = vault.get_key(args.key_id)
            if record is None:
                raise _err("KH-1002", f"key not found: {args.key_id}")
            out.write(f"key_id: {_field(record, 'key_id')}\n")
            out.write(f"provider: {_field(record, 'provider')}\n")
            out.write(f"label: {_field(record, 'label')}\n")
            out.write(f"created_at: {_field(record, 'created_at')}\n")
            fingerprint = _field(record, "fingerprint")
            if fingerprint:
                out.write(f"fingerprint: {fingerprint}\n")
            if _field(record, "needs_rotation"):
                out.write(
                    "WARNING: NOT YET ROTATED — this key was (or may have "
                    "been) pasted somewhere before import. Rotate it at the "
                    "provider before its first session, then record the "
                    "rotation with `keyholder keys rotate "
                    f"{_field(record, 'key_id')}`.\n"
                )
            return 0

        if args.keys_cmd == "add":
            provider = args.provider or _ask("Provider (github/gemini): ").strip()
            if provider not in ("github", "gemini"):
                raise _err("KH-2001", f"unknown provider: {provider!r} (github/gemini only)")
            label = args.label or _ask("Label for this key: ").strip()
            if not label:
                raise _err("KH-2001", "label must not be empty")
            out.write(
                "A key pasted into an IDE chat or another app can live on "
                "in that app's cloud history even after you delete it here "
                "— that paste never dies on its own, which is why rotation "
                "matters.\n"
            )
            answer = ""
            while answer not in ("yes", "no", "don't know"):
                answer = (
                    _ask("Was this key ever pasted anywhere? (yes/no/don't know): ")
                    .strip()
                    .lower()
                )
            ever_pasted = answer in ("yes", "don't know")
            secret = _ask_secret("Paste key (input hidden, never printed): ")
            try:
                record = vault.add_key(provider, label, secret, ever_pasted)
            finally:
                # Transient only: the CLI keeps no copy of the secret.
                fingerprint = _fingerprint(secret)
                del secret
            out.write(f"key added: {_field(record, 'key_id')} ({provider}, {label})\n")
            out.write(f"fingerprint: {fingerprint}\n")
            if ever_pasted:
                out.write(
                    "WARNING: NOT YET ROTATED — this key was (or may have "
                    "been) pasted somewhere before import. You must rotate "
                    "it at the provider before its first session, then "
                    "record the rotation with `keyholder keys rotate "
                    f"{_field(record, 'key_id')}`. This warning stays until "
                    "rotation is recorded, and no session can start for "
                    "this key until then.\n"
                )
            return 0

        if args.keys_cmd == "delete":
            record = vault.get_key(args.key_id)
            if record is None:
                raise _err("KH-1002", f"key not found: {args.key_id}")
            confirm = _ask(
                f"Type the key id to confirm deletion of {args.key_id}: "
            ).strip()
            if confirm != args.key_id:
                out.write("deletion aborted — key id did not match\n")
                return 0
            vault.delete_key(args.key_id)
            out.write(f"key deleted: {args.key_id}\n")
            return 0

        if args.keys_cmd == "rotate":
            record = vault.get_key(args.key_id)
            if record is None:
                raise _err("KH-1002", f"key not found: {args.key_id}")
            out.write(
                "Rotate the key at the provider first, then paste the NEW "
                "key here so the vault holds only the rotated key.\n"
            )
            secret = _ask_secret("Paste NEW key (input hidden, never printed): ")
            try:
                vault.rotate_key(args.key_id, secret)
            finally:
                del secret
            out.write(
                f"key rotated: {args.key_id} — NOT YET ROTATED warning cleared; "
                "sessions may now start for this key\n"
            )
            return 0
    except KeyholderError:
        raise
    except Exception as exc:
        raise _backend_error(exc) from exc
    raise _err("KH-2001", "unknown keys command")


# -------------------------------------------------------------- sessions


def _daemon_sessions_client():
    """Daemon IPC client if a daemon is running, else None.

    Sessions live in the daemon (v0.2 gap 1); CLI sessions commands
    talk to it first. When no daemon is running, the caller falls back
    to the process-local sessions module (the path CLI tests stub).
    A ping failure means "no daemon", never a partial session state.
    """
    try:
        daemon = _load_daemon()
        client = daemon.DaemonClient()
        client.request("ping")
    except Exception:
        return None
    return client


def _cmd_sessions_daemon(client, args, out) -> int:
    """Sessions commands over daemon IPC (v0.2 manager integration).

    Returns an exit code. Raises KeyholderError (via _backend_error
    mapping of DaemonError codes) on daemon-side failures. The token
    is printed exactly once, at creation, from the IPC reply only.
    """
    if args.sessions_cmd == "list":
        result = client.request("sessions.list")
        items = result.get("sessions", [])
        if not items:
            out.write("no sessions\n")
        for item in items:
            out.write(
                f"{_field(item, 'session_id')}  "
                f"key {_field(item, 'key_id')}  "
                f"{_field(item, 'provider')}  "
                f"{_field(item, 'session_class')}  "
                f"transport {_field(item, 'transport')}  "
                f"expires {_field(item, 'expires_at')}  "
                f"killed={_field(item, 'killed')}\n"
            )
        out.write("Session tokens are never shown here — a token is shown exactly once, at creation.\n")
        return 0
    if args.sessions_cmd == "create":
        vault = _load_vault()
        record = vault.get_key(args.key_id)
        if record is None:
            raise _err("KH-1002", f"key not found: {args.key_id}")
        if _field(record, "needs_rotation"):
            raise _err(
                "KH-1003",
                "NOT YET ROTATED: this key was (or may have been) pasted "
                "somewhere before import. Rotate it at the provider and "
                f"record the rotation with `keyholder keys rotate {args.key_id}` "
                "before its first session",
            )
        session_class = args.session_class
        transport = args.transport
        minutes = _resolve_minutes(session_class, args.minutes)
        result = client.request("sessions.create", {
            "key_id": args.key_id,
            "provider": _field(record, "provider"),
            "session_class": session_class,
            "transport": transport,
            "requested_ttl_s": minutes * 60,
        })
        session = result.get("session", {})
        token = result.get("token")
        out.write(f"session created: {_field(session, 'session_id')}\n")
        out.write(f"key: {args.key_id} ({_field(record, 'provider')})\n")
        out.write(f"class: {session_class}  duration: {minutes} minutes\n")
        out.write(f"transport: {transport}\n")
        if transport == "connect_allowed":
            out.write(
                "transport policy: HOST-ONLY POLICY — host + byte budget "
                "only; method/path/body policy is unenforceable in a tunnel\n"
            )
        if token:
            out.write(
                "Session token (shown exactly once — it will not be shown again, "
                "and no command can display it later):\n"
            )
            out.write(f"{token}\n")
            out.write(
                "Save it now in the agent's own session setup. If it is lost, "
                "kill this session and create a new one — sessions are never extended.\n"
            )
        return 0
    if args.sessions_cmd == "kill":
        result = client.request("sessions.kill",
                                {"session_id": args.session_id})
        receipt = result.get("receipt", {})
        out.write(f"session killed: {args.session_id}\n")
        out.write(
            "New calls are blocked within 1 second and the session is "
            "fully torn down within 5 seconds. Calls already sent to "
            "the provider are not recalled and run to completion.\n"
        )
        forwarded = (
            _field(receipt, "in_flight_at_kill")
            or _field(receipt, "already_forwarded")
            or []
        )
        if forwarded:
            out.write("Calls already sent (ran to completion, listed on this receipt):\n")
            for call in forwarded:
                out.write(f"  {call}\n")
        else:
            out.write("No calls were already sent at kill time.\n")
        return 0
    if args.sessions_cmd == "kill-all":
        if not args.yes:
            confirm = _ask("Kill ALL sessions? Type KILL ALL to confirm: ").strip()
            if confirm != "KILL ALL":
                out.write("kill-all aborted — sessions kept\n")
                return 0
        result = client.request("sessions.kill_all")
        snapshot = result.get("snapshot", [])
        count = len(snapshot) if isinstance(snapshot, list) else None
        out.write(
            f"all sessions killed{f' ({count} sessions)' if count is not None else ''} — "
            "new calls blocked within 1 second, teardown within 5 seconds; "
            "calls already sent are not recalled\n"
        )
        return 0
    raise _err("KH-2001", "unknown sessions command")


def _cmd_sessions(args, out) -> int:
    client = _daemon_sessions_client()
    if client is not None:
        try:
            return _cmd_sessions_daemon(client, args, out)
        except KeyholderError:
            raise
        except Exception as exc:
            raise _backend_error(exc) from exc
    sessions = _load_sessions()
    try:
        if args.sessions_cmd == "list":
            items = sessions.list_sessions()
            if not items:
                out.write("no sessions\n")
            for item in items:
                out.write(
                    f"{_field(item, 'session_id')}  "
                    f"key {_field(item, 'key_id')}  "
                    f"{_field(item, 'provider')}  "
                    f"{_field(item, 'session_class')}  "
                    f"transport {_field(item, 'transport')}  "
                    f"expires {_field(item, 'expires_at')}  "
                    f"killed={_field(item, 'killed')}\n"
                )
            out.write("Session tokens are never shown here — a token is shown exactly once, at creation.\n")
            return 0

        if args.sessions_cmd == "create":
            vault = _load_vault()
            record = vault.get_key(args.key_id)
            if record is None:
                raise _err("KH-1002", f"key not found: {args.key_id}")
            if _field(record, "needs_rotation"):
                raise _err(
                    "KH-1003",
                    "NOT YET ROTATED: this key was (or may have been) pasted "
                    "somewhere before import. Rotate it at the provider and "
                    f"record the rotation with `keyholder keys rotate {args.key_id}` "
                    "before its first session",
                )
            session_class = args.session_class
            transport = args.transport
            minutes = _resolve_minutes(session_class, args.minutes)
            created = sessions.create_session(
                key_id=args.key_id,
                provider=_field(record, "provider"),
                session_class=session_class,
                transport=transport,
                minutes=minutes,
                label=args.label,
            )
            token = _field(created, "token")
            out.write(f"session created: {_field(created, 'session_id')}\n")
            out.write(f"key: {args.key_id} ({_field(record, 'provider')})\n")
            out.write(f"class: {session_class}  duration: {minutes} minutes\n")
            out.write(f"transport: {transport}\n")
            if transport == "connect_allowed":
                out.write(
                    "transport policy: HOST-ONLY POLICY — host + byte budget "
                    "only; method/path/body policy is unenforceable in a tunnel\n"
                )
            if token:
                out.write(
                    "Session token (shown exactly once — it will not be shown again, "
                    "and no command can display it later):\n"
                )
                out.write(f"{token}\n")
                out.write(
                    "Save it now in the agent's own session setup. If it is lost, "
                    "kill this session and create a new one — sessions are never extended.\n"
                )
            return 0

        if args.sessions_cmd == "kill":
            receipt = sessions.kill_session(args.session_id)
            out.write(f"session killed: {args.session_id}\n")
            out.write(
                "New calls are blocked within 1 second and the session is "
                "fully torn down within 5 seconds. Calls already sent to "
                "the provider are not recalled and run to completion.\n"
            )
            forwarded = _field(receipt, "already_forwarded") or []
            if forwarded:
                out.write("Calls already sent (ran to completion, listed on this receipt):\n")
                for call in forwarded:
                    out.write(f"  {call}\n")
            else:
                out.write("No calls were already sent at kill time.\n")
            return 0

        if args.sessions_cmd == "kill-all":
            if not args.yes:
                confirm = _ask("Kill ALL sessions? Type KILL ALL to confirm: ").strip()
                if confirm != "KILL ALL":
                    out.write("kill-all aborted — sessions kept\n")
                    return 0
            receipt = sessions.kill_all()
            count = _field(receipt, "killed_count")
            out.write(
                f"all sessions killed{f' ({count} sessions)' if count is not None else ''} — "
                "new calls blocked within 1 second, teardown within 5 seconds; "
                "calls already sent are not recalled\n"
            )
            return 0
    except KeyholderError:
        raise
    except Exception as exc:
        raise _backend_error(exc) from exc
    raise _err("KH-2001", "unknown sessions command")


# ----------------------------------------------------------------- audit


def _cmd_audit(args, out) -> int:
    audit = _load_audit()
    try:
        if args.audit_cmd == "verify":
            result = audit.verify()
            status = _field(result, "status")
            entries = _field(result, "entries")
            if status == "OK":
                out.write(f"audit: OK ({entries} entries, chain intact)\n")
                return 0
            if status == "UNANCHORED":
                # Amber, exit 2 per CONTRACT §8; reported under KH-1005
                # (the only audit code) with the status word carrying the
                # distinction — see module docstring.
                out.write(
                    "audit: UNANCHORED (amber) — the chain verifies but is "
                    f"not anchored ({entries} entries); treat recent entries "
                    "as provisional until anchored\n"
                )
                return 2
            if status == "TAMPERED":
                raise _err("KH-1005", "audit: TAMPERED — chain verification failed")
            if status == "MISSING-DIRECTORY":
                raise _err(
                    "KH-1005",
                    "audit: MISSING-DIRECTORY — a silently reborn log is a "
                    "failure, not a fresh start",
                )
            raise _err("KH-1005", f"audit: unknown verification status: {status!r}")
        if args.audit_cmd == "export":
            result = audit.export(args.output)
            entries = _field(result, "entries")
            path = _field(result, "path") or args.output
            out.write(
                f"audit exported{f' ({entries} entries)' if entries is not None else ''} "
                f"to {path} — key material is never exported\n"
            )
            return 0
    except KeyholderError:
        raise
    except Exception as exc:
        raise _backend_error(exc) from exc
    raise _err("KH-2001", "unknown audit command")


# ---------------------------------------------------------------- doctor

SHELL_PROFILES = (
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".config/fish/config.fish",
)
CREDENTIAL_STORES = (
    ".aws/credentials",
    ".aws/config",
    ".config/gh/hosts.yml",
    ".docker/config.json",
    ".netrc",
    ".git-credentials",
    ".npmrc",
    ".kube/config",
    ".config/gcloud/credentials.db",
)
MCP_CONFIGS = (
    ".claude.json",
    ".config/Claude/claude_desktop_config.json",
    "Library/Application Support/Claude/claude_desktop_config.json",
    ".cursor/mcp.json",
    ".config/Code/User/mcp.json",
    ".mcp.json",
)
IDE_SETTINGS = (
    ".config/Code/User/settings.json",
    "Library/Application Support/Code/User/settings.json",
    ".cursor/settings.json",
)
_SECRET_NAME = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Za-z0-9_]*)\b"
)
_ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def _doctor_findings(home: str, cwd: str, environ) -> list:
    """Inventory standing credentials. Returns warning strings only.

    Values are NEVER read into output: file scans report paths, line
    numbers and variable/setting names only; environment scans report
    variable names only.
    """
    findings = []

    def _scan_profile(path: str):
        try:
            with open(path, "r", errors="replace") as handle:
                for lineno, line in enumerate(handle, 1):
                    match = _ASSIGNMENT.match(line)
                    if match and _SECRET_NAME.search(match.group(1)):
                        findings.append(
                            f"standing credential in shell profile: {path} "
                            f"line {lineno} sets {match.group(1)} "
                            "(value not shown)"
                        )
        except OSError:
            pass

    for rel in SHELL_PROFILES:
        _scan_profile(os.path.join(home, rel))
    for rel in CREDENTIAL_STORES:
        path = os.path.join(home, rel)
        if os.path.exists(path):
            try:
                mode = oct(os.stat(path).st_mode & 0o777)
            except OSError:
                mode = "unknown"
            findings.append(
                f"CLI credential store present: {path} (mode {mode}) — "
                "any process running as you can read it; prefer moving "
                "this key into Keyholder and rotating it at the provider"
            )
    for rel in MCP_CONFIGS:
        base = cwd if rel == ".mcp.json" else home
        path = os.path.join(base, rel)
        if os.path.exists(path):
            findings.append(
                f"MCP/agent config present: {path} — check it for stored "
                "keys; agent configs are synced and committed by accident"
            )
    for rel in IDE_SETTINGS:
        path = os.path.join(home, rel)
        try:
            with open(path, "r", errors="replace") as handle:
                text = handle.read()
        except OSError:
            continue
        for name in sorted(set(_SECRET_NAME.findall(text))):
            findings.append(
                f"IDE settings mention a credential-like setting: {path} "
                f"names {name} (value not shown)"
            )
    for name in sorted(environ):
        if _SECRET_NAME.search(name):
            findings.append(
                f"credential-like environment variable set: {name} "
                "(name only — value not shown; environment variables are "
                "visible to child processes)"
            )
    return findings


def _cmd_doctor(args, out) -> int:
    home = os.path.expanduser("~")
    findings = _doctor_findings(home, os.getcwd(), os.environ)
    out.write("doctor: standing-credential inventory (key values are never printed)\n")
    if not findings:
        out.write("no standing credentials found in the locations checked\n")
    for finding in findings:
        out.write(f"warning: {finding}\n")
    out.write(
        "Note: on Linux, stored credentials are user-scoped — another "
        "process running as you can read them. Keyholder's vault does "
        "not change that for keys left standing outside it; move them "
        "in and rotate them at the provider.\n"
    )
    out.write(f"doctor: {len(findings)} warning(s)\n")
    return 0


# ------------------------------------------------------- prove-isolation


def _cmd_prove_isolation(args, out) -> int:
    broker = _load_broker()
    sessions = _load_sessions()
    try:
        mint = getattr(sessions, "create_ephemeral_session", None)
        validate = getattr(broker, "validate_token", None)
        if callable(mint) and callable(validate):
            # Real same-user separation check through the broker API:
            # session A must not accept session B's token, and vice versa.
            session_a, token_a = mint()
            session_b, token_b = mint()
            id_a = _field(session_a, "session_id") or session_a
            id_b = _field(session_b, "session_id") or session_b
            control_a = validate(id_a, token_a)
            control_b = validate(id_b, token_b)
            cross_ab = validate(id_a, token_b)
            cross_ba = validate(id_b, token_a)
            if control_a and control_b and not cross_ab and not cross_ba:
                out.write(
                    "prove-isolation: PASS — session A cannot read session "
                    "B's key/token via the broker API, and vice versa\n"
                )
                return 0
            if not (control_a and control_b):
                raise _err(
                    "KH-3002",
                    "prove-isolation: FAILED — the control check did not "
                    "validate a session's own token, so separation could "
                    "not be proven",
                )
            raise _err(
                "KH-3002",
                "prove-isolation: FAILED — a session accepted another "
                "session's token via the broker API (isolation broken)",
            )
        prove = getattr(broker, "prove_isolation", None)
        if callable(prove):
            result = prove()
            if _field(result, "ok"):
                out.write(
                    f"prove-isolation: PASS (broker-reported)"
                    f"{': ' + str(_field(result, 'detail')) if _field(result, 'detail') else ''}\n"
                )
                return 0
            raise _err(
                "KH-3002",
                f"prove-isolation: FAILED — {_field(result, 'detail') or 'broker self-test failed'}",
            )
        raise _err(
            "KH-3002",
            "prove-isolation: FAILED — no broker isolation-check interface "
            "is available; an unprovable claim is never reported as a pass",
        )
    except KeyholderError:
        raise
    except Exception as exc:
        # A proof that cannot run, or whose backend fails, is a FAILED
        # proof (KH-3002), never a provider error (KH-1006) and never
        # a routine policy denial (KH-1003).
        raise _err(
            "KH-3002",
            f"prove-isolation: FAILED — isolation could not be proven ({exc})",
        ) from exc


# ---------------------------------------------------------------- parser


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise _UsageError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="keyholder",
        description=(
            "Keyholder v0.1 — local-first key holder for AI agents. "
            "Long-lived keys stay on this machine; agents get only scoped, "
            "short-lived session tokens through the broker."
        ),
    )
    parser.add_argument("--version", action="version", version=f"keyholder {VERSION}")
    sub = parser.add_subparsers(dest="command")

    daemon_p = sub.add_parser("daemon", help="start, stop, or report the daemon")
    daemon_sub = daemon_p.add_subparsers(dest="daemon_cmd", required=True)
    daemon_sub.add_parser("start", help="start the daemon")
    daemon_sub.add_parser("stop", help="stop the daemon (sessions kept by default)")
    daemon_sub.add_parser("status", help="report whether the daemon is running")

    keys_p = sub.add_parser("keys", help="manage vault keys (never displays a key value)")
    keys_sub = keys_p.add_subparsers(dest="keys_cmd", required=True)
    keys_sub.add_parser("list", help="list keys with rotation warnings")
    show_p = keys_sub.add_parser("show", help="show one key's detail (fingerprint only, never the key)")
    show_p.add_argument("key_id", help="key id, e.g. key-<16 hex chars>")
    add_p = keys_sub.add_parser("add", help="import a key (asks whether it was ever pasted anywhere)")
    add_p.add_argument("--provider", choices=("github", "gemini"), help="provider of the key")
    add_p.add_argument("--label", help="label for the key")
    delete_p = keys_sub.add_parser("delete", help="delete a key (typed confirmation required)")
    delete_p.add_argument("key_id", help="key id to delete")
    rotate_p = keys_sub.add_parser(
        "rotate", help="record a provider rotation by storing the new key"
    )
    rotate_p.add_argument("key_id", help="key id to rotate")

    sessions_p = sub.add_parser("sessions", help="manage sessions (tokens shown exactly once, at creation)")
    sessions_sub = sessions_p.add_subparsers(dest="sessions_cmd", required=True)
    sessions_sub.add_parser("list", help="list sessions (tokens are never shown here)")
    create_p = sessions_sub.add_parser("create", help="create a session (token shown exactly once)")
    create_p.add_argument("key_id", help="key id for this session (exactly one key per session)")
    create_p.add_argument(
        "--class",
        dest="session_class",
        choices=("destructive", "write", "read_account", "read_public"),
        default="read_public",
        help="session class (default read_public)",
    )
    create_p.add_argument(
        "--transport",
        choices=("absolute", "connect_allowed"),
        default="absolute",
        help="absolute (default) or connect_allowed (HOST-ONLY POLICY)",
    )
    create_p.add_argument(
        "--minutes", type=int, default=None, help="duration in minutes (class cap applies)"
    )
    create_p.add_argument("--label", default=None, help="label for the session")
    kill_p = sessions_sub.add_parser("kill", help="kill one session")
    kill_p.add_argument("session_id", help="session id to kill")
    kill_all_p = sessions_sub.add_parser("kill-all", help="kill all sessions (confirmation required)")
    kill_all_p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")

    audit_p = sub.add_parser("audit", help="verify or export the audit log")
    audit_sub = audit_p.add_subparsers(dest="audit_cmd", required=True)
    audit_sub.add_parser("verify", help="verify the audit chain (OK / UNANCHORED / TAMPERED / MISSING-DIRECTORY)")
    export_p = audit_sub.add_parser("export", help="export the audit log (key material is never exported)")
    export_p.add_argument("--output", required=True, help="path to write the export to")

    sub.add_parser("doctor", help="inventory standing credentials on this machine (never prints values)")
    sub.add_parser(
        "prove-isolation",
        help="run a real same-user separation check: session A must not read session B's key/token",
    )
    return parser


_COMMANDS = {
    "daemon": _cmd_daemon,
    "keys": _cmd_keys,
    "sessions": _cmd_sessions,
    "audit": _cmd_audit,
    "doctor": _cmd_doctor,
    "prove-isolation": _cmd_prove_isolation,
}


def main(argv=None) -> int:
    """Run the CLI. Returns a process exit code; never raises SystemExit
    except for --help/--version passthrough handled here."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except _UsageError as exc:
        print(
            f"error KH-2001: invalid input / usage: {exc} "
            f"(next step: {NEXT_STEPS['KH-2001']})",
            file=sys.stderr,
        )
        return 1
    except SystemExit as exc:
        # --help / --version: argparse already printed; pass the code through.
        return int(exc.code or 0)
    try:
        if args.command is None:
            return _cmd_first_run(sys.stdout)
        return _COMMANDS[args.command](args, sys.stdout)
    except KeyholderError as exc:
        print(
            f"error {exc.code}: {exc.message} "
            f"(next step: {NEXT_STEPS.get(exc.code, 'see --help')})",
            file=sys.stderr,
        )
        return exc.exit_code
    except BrokenPipeError:
        return 1
