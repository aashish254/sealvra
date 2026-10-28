"""Keyholder v0.1 — approval ceremony (W08).

Broker-owned approver ONLY. This module is the single place where an
approval decision can originate, and the single place where the broker
verifies one. It implements CONTRACT §8 and v3 plan §1E (N-E1..N-E14,
N-N2..N-N6); where v1/v2 disagreed with v3, v3 wins and the deleted
passages are never built.

Normative rules enforced here (not merely documented):

* Decisions originate ONLY from the approver process. There is no CLI
  approve and no dashboard approve: both are read + kill only, and any
  approval request arriving from another channel is refused.
* Two-step, in order, for session creation and destructive calls: OS
  gesture (system prompt) FIRST, explicit confirm click SECOND.
  A gesture alone mints nothing; a confirm before the gesture is
  rejected. There is NO biometric-only path in this module for any
  kind: biometric alone is presence, not authorisation, and the
  earlier "identical-scope re-approval" shorthand is deleted — a
  re-approval is a fresh two-step ceremony like any other.
* Card-to-prompt race (v3 N-E7): the card requires an explicit
  "Review and continue" click BEFORE any system prompt fires
  (``begin_system_prompt`` refuses to fire from any other state);
  the card must still be frontmost when the prompt fires and while
  it is up (focus loss voids the pending approval to deny); a random
  pairing word appears on BOTH the card headline and the system-prompt
  reason string (``os_prompt_reason``). Platform limits are recorded
  honestly in ``pairing_word_os_prompt_support``: macOS LA reason
  strings carry the word verbatim; Linux polkit agents may truncate
  or reword it (partial); Windows Hello does not render a caller
  reason string verbatim (unsupported — card-frontmost + continue +
  confirm are the defences there); broker-window and headless flows
  have no OS prompt at all, so no pairing word can appear in one.
* Seal (v3 N-E7 — the side v3 took, implemented exactly, dissent
  NOT re-litigated): passphrase + image + receipt is MANDATORY,
  keychain-ACL-gated only, never a 0600 file. The R03 dissent
  (phishable/redundant, v3 §5 OD-04) is recorded and does NOT change
  the rule. The seal is defence-in-depth for non-shell attackers
  only; Gate 2 (OS keychain item access control) is the backstop.
  Production brokers MUST be constructed with a seal
  (``ApprovalBroker(seal=..., seal_required=True)``); a broker built
  without one accepts seal-less cards only as a test-compat path and
  must never be used in production. On this Linux build the
  ``SealStore`` is an in-memory holder: the macOS production path
  must substitute a real keychain-ACL-backed store, and a
  file-backed store is refused by construction, never silently used.
* Every decision is bound to the exact request hash and a single-use
  nonce. The nonce is consumed atomically (compare-and-swap under a
  lock) BEFORE any side effect, so concurrent replays cannot both win.
* Timeout always denies. Default 60 s, 120 s accessibility opt-in.
  The clock starts at the system prompt and uses a monotonic clock;
  wall clock is display-only. The card itself is untimed for reading,
  and a card older than 5 min at gesture time must be re-rendered.
* Approve-once = a 5-minute CONSUMPTION DEADLINE for one single use,
  NOT a 5-minute validity window for repeat calls. A second identical
  destructive call needs a fresh approval.
* Destructive calls: fresh per-call approval, no session-scope reuse,
  no level-3 opt-out, no break-glass bypass for destructive. Break-glass
  (if active) covers MEDIUM/session prompts only.
* Kill needs no auth and is never blocked.
* One visible/focusable prompt at a time: pending approvals are queued
  invisibly; only the active one can be decided.
* Cards show permissions AND purpose (broker-known fields only), never
  agent free text in the headline, with the key fingerprint (12 hex)
  and a COUNT-ONLY negative list ("and N other keys are NOT included",
  never named lists). No card ever contains a passcode field:
  Keyholder never asks for a device passcode inside an app window.
* Enrolment change, single posture (N-E6): kill-all + password-only
  next, pending HIGH/CRITICAL fail closed. Monitoring hooks are
  wake / unlock / approval / 15-min poll (see ``EnrolmentMonitor``);
  the platform layer (W13) supplies the domain-state value — this
  module cannot read a macOS LA domain state on Linux and does not
  pretend to.
* No app password, ever (N-E13). No duress mechanism in v0.1 (explicit
  owner decision recorded in v3 §5; absence is deliberate, not a gap
  for a future contributor to fill silently).

Platform tiers, stated honestly (Tier A = interface-bound agent,
Tier B = shell-capable same-user agent; see CONTRACT §10):

* macOS: sandboxed approver (XPC service design) + Touch ID system
  prompt; HIGH/CRITICAL decisions are enclave-bound-signed in the
  design. On this Linux build the enclave binding is NOT available:
  decisions are approver-signed (Ed25519, per-invocation key) and
  ``enclave_bound`` is reported False — never claimed True.
* Linux: polkit / OS password via system UI where available, broker
  window as degraded T3 where not. Broker-window clicks may present
  or deny a destructive call, NEVER approve it.
* Windows: verifier-helper design (boolean-only, never returning the
  password to the app). The helper itself is not built in this module;
  ``platform_tier_for("windows")`` reports it as required, not present.
* X11 (including XWayland, and xrdp/WSL treated as X11): destructive
  approvals are REFUSED outright (N-N2). Read-only may stay, badged.
* SSH/headless: DECISION (one of the two options v3 leaves open) —
  console grants ONLY. An SSH/headless approval without a live console
  grant covering exactly this key and scope is refused (T0). A grant
  is at most 2 h, a single session start, non-destructive, seat-verified
  and audited. The alternative (refuse SSH outright) was NOT chosen,
  so the CLI/GUI record must match this choice (W10/W18 record it).

Fatigue — one state machine (N-E4, core counters implemented here,
full machine documented below): 20 approvals/session, >10 prompts in
5 min, max 3 pending, per-intent failure limits. Progressive friction:
typed confirmation required at the 3rd prompt in 5 min; at the 5th,
approvals enter a 15-min auto-deny window. Recovery is that 15-min
window only (R04's open-ended pause-until-OS-auth is deleted, except
the separate 3-approver-crashes/24 h rule, which the broker owns and
is documented, not implemented, here). A forged/replayed-decision
anomaly threshold (3 in 24 h) pauses approvals and forces seal
rotation before resumption (f04 F-03); seal rotation itself is a
vault/broker operation, flagged here, not performed here.

Full fatigue machine (states: NORMAL -> FRICTION -> PAUSED ->
NORMAL-after-window; every counter counts SHOWN prompts only, never
auto-denied ones; a single resume path — the 15-min window expiring):
  NORMAL: prompts shown, session counter < 20, window counter < 3.
  FRICTION (3rd prompt in 5 min): typed confirmation required
    (``typed_confirmation_required``) in addition to the two steps.
  PAUSED (5th prompt in 5 min, or 3 forged/replayed decisions in 24 h,
    or session counter reaching 20): all approvals auto-deny for
    15 min; the window expiry is the only resume path. Pending prompts
    queued during PAUSED are auto-denied, not silently held.
  Session budget (20/session) and pending cap (3) are hard denies, not
  pauses: they deny the individual request, not the session.

Threat-tier note: file permissions, control tokens and peer-credential
checks do NOT survive Tier B and are never cited here as Tier B
evidence. Only OS-rendered prompts, macOS keychain access groups and
the sandboxed approver survive Tier B. Same-user malware / a
compromised OS account is out of scope by design.

No real keys anywhere: tests and examples use only TEST-ONLY values.
The key fingerprint accepted here is a caller-supplied 12-hex display
value (computed by the vault, CONTRACT §5, from the secret); this
module never sees a secret and never computes a fingerprint from one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import string
import threading
import time
from dataclasses import dataclass, field
from enum import Enum

# ---------------------------------------------------------------------------
# Constants (CONTRACT §8, v3 N-E4/N-E5)
# ---------------------------------------------------------------------------

APPROVER_CHANNEL = "keyholder-approver"
"""The only channel whose decisions the broker accepts."""

FORBIDDEN_CHANNELS = ("cli", "dashboard", "agent", "ui", "terminal")
"""Channels that must never originate an approval (read + kill only)."""

DEFAULT_TIMEOUT_S = 60.0
ACCESSIBILITY_TIMEOUT_S = 120.0
STALE_CARD_S = 300.0  # re-render a card older than 5 min before gesturing
MIN_CARD_DWELL_S = 2.0  # continue click disabled for the first 2 s
APPROVE_ONCE_CONSUME_DEADLINE_S = 300.0  # 5 min to consume, single use
SESSION_APPROVAL_BUDGET = 20
BURST_WINDOW_S = 300.0  # 5 min
BURST_TYPED_CONFIRM_AT = 3  # 3rd prompt in 5 min needs typed confirmation
BURST_PAUSE_AT = 5  # 5th prompt in 5 min pauses approvals
PAUSE_WINDOW_S = 900.0  # 15-min auto-deny window (only resume path)
MAX_PENDING = 3
ANOMALY_PAUSE_THRESHOLD = 3  # forged/replayed decisions in 24 h
ANOMALY_WINDOW_S = 86400.0
CONSOLE_GRANT_MAX_S = 7200.0  # 2 h absolute cap

CARD_FOOTER = (
    "Keyholder never asks for your device passcode. "
    "Any window asking for it inside an app is fake."
)
PRESENCE_NOTE = (
    "Touching only proves you are here — check the scope above before "
    "you touch. Your approval is the confirm click that follows."
)


class ApprovalKind(str, Enum):
    SESSION_CREATION = "session_creation"
    DESTRUCTIVE = "destructive"
    SESSION_SCOPE = "session_scope"  # level <= 2, non-destructive, in-scope


class DenyReason(str, Enum):
    EXPLICIT_DENY = "explicit-deny"
    TIMEOUT_DENY = "timeout-deny"
    CANCEL_DENY = "cancel-deny"
    CLOSE_DENY = "close-deny"
    FOCUS_LOSS_DENY = "focus-loss-deny"
    LOCK_DENY = "lock-deny"
    ORIGIN_REFUSED = "origin-refused"
    NONCE_REPLAY = "nonce-replay"
    REQUEST_HASH_MISMATCH = "request-hash-mismatch"
    STALE_CARD = "stale-card"
    WRONG_ORDER = "wrong-order"
    GESTURE_ONLY = "gesture-only"
    X11_DESTRUCTIVE_REFUSED = "x11-destructive-refused"
    REMOTE_DESTRUCTIVE_REFUSED = "remote-destructive-refused"
    HEADLESS_NO_GRANT = "headless-no-grant"
    BREAKGLASS_DESTRUCTIVE = "breakglass-destructive-excluded"
    SESSION_SCOPE_DESTRUCTIVE = "session-scope-cannot-approve-destructive"
    SEAL_MISSING = "seal-missing"
    SEAL_MISMATCH = "seal-mismatch"
    SEAL_STORAGE_REFUSED = "seal-storage-refused"
    SEAL_ROTATION_REQUIRED = "seal-rotation-required"
    FATIGUE_PAUSED = "fatigue-paused"
    SESSION_BUDGET_EXHAUSTED = "session-budget-exhausted"
    PENDING_CAP = "pending-cap"
    ENROLMENT_CHANGE = "enrolment-change"
    BROKER_WINDOW_DESTRUCTIVE = "broker-window-cannot-approve-destructive"
    APP_PASSWORD_REFUSED = "app-password-refused"
    ALREADY_CONSUMED = "already-consumed"
    CONSUME_DEADLINE_PASSED = "consume-deadline-passed"
    KEY_LIFECYCLE_VOID = "key-lifecycle-void"
    UNSUMMARISABLE_DESTRUCTIVE = "unsummarisable-destructive-denied"


class ApprovalError(Exception):
    """Base error; carrying a DenyReason keeps surfaces consistent."""

    def __init__(self, reason: DenyReason, message: str = "") -> None:
        self.reason = reason
        super().__init__(message or reason.value)


class OriginRefused(ApprovalError):
    def __init__(self, channel: str) -> None:
        super().__init__(
            DenyReason.ORIGIN_REFUSED,
            f"approval refused: channel {channel!r} may not originate "
            f"approvals; only {APPROVER_CHANNEL!r} may",
        )


class WrongOrder(ApprovalError):
    def __init__(self, message: str) -> None:
        super().__init__(DenyReason.WRONG_ORDER, message)


# ---------------------------------------------------------------------------
# Request hash and card rendering
# ---------------------------------------------------------------------------

def compute_request_hash(
    *,
    key_id: str,
    provider: str,
    method: str,
    canonical_path: str,
    body_sha256_hex: str = "",
    scope_summary: str = "",
    kind: str = ApprovalKind.DESTRUCTIVE.value,
    level: int = 3,
) -> str:
    """Bind an approval to the exact request. Any change -> new hash."""
    canonical = {
        "body_sha256_hex": body_sha256_hex,
        "canonical_path": canonical_path,
        "key_id": key_id,
        "kind": kind,
        "level": level,
        "method": method.upper(),
        "provider": provider,
        "scope_summary": scope_summary,
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def pairing_word() -> str:
    """Random 4–6 char word shared by card headline and OS reason string."""
    alphabet = string.ascii_lowercase
    return "".join(secrets.choice(alphabet) for _ in range(5))


# ---------------------------------------------------------------------------
# Seal (v3 N-E7, mandatory) and system-prompt reason string
# ---------------------------------------------------------------------------

@dataclass
class ApprovalSeal:
    """Anti-spoofing mark: passphrase + image, keychain-gated (N-E7).

    v3 ADOPTED this as mandatory (R04/R11/R10 position); the R03
    dissent (phishable/redundant, §5 OD-04) is recorded and does not
    change the rule — this module does not re-litigate it. The
    passphrase is a display mark, not a secret: it is shown on the
    card and spoken in the system-prompt reason string so the user
    can match card ↔ prompt at a glance. It is defence-in-depth for
    non-shell attackers only; Gate 2 is the backstop. ``version``
    increments on every rotation; rotation is mandatory after an
    approver anomaly (f04 F-03), not offered.
    """

    passphrase: str
    image_id: str  # identifier of the user-chosen seal image, not bytes
    version: int = 1


class SealStore:
    """Keychain-ACL-gated seal storage — the ONLY accepted backend.

    ``backend`` must be exactly ``"keychain-acl"``. Any file-backed
    backend (a 0600 user-owned file is readable by any same-user
    process, f04 I-12) is refused by construction. On this Linux
    build the store is an in-memory holder: the macOS production
    path must substitute a real keychain-ACL-backed store behind
    this same interface. This class never accepts a filesystem path.
    """

    def __init__(self, *, backend: str) -> None:
        if backend != "keychain-acl":
            raise ApprovalError(
                DenyReason.SEAL_STORAGE_REFUSED,
                f"seal storage backend {backend!r} refused: keychain-ACL "
                "only, never a file",
            )
        self.backend = backend
        self._seal: ApprovalSeal | None = None

    def save(self, seal: ApprovalSeal, *, path: str | None = None) -> None:
        if path is not None:
            raise ApprovalError(
                DenyReason.SEAL_STORAGE_REFUSED,
                "seal must never be written to a file path",
            )
        self._seal = seal

    def load(self) -> ApprovalSeal:
        if self._seal is None:
            raise ApprovalError(DenyReason.SEAL_MISSING, "no seal stored")
        return self._seal


def os_prompt_reason(card: "ApprovalCard") -> str:
    """System-prompt reason string for a card (v3 N-E7, f04 A-03/A-04).

    Carries the card's pairing word AND, when the card carries one,
    the seal passphrase, so the authentication moment itself — not
    just the card — shows a matchable mark. The platform may or may
    not render this verbatim; see ``pairing_word_os_prompt_support``.
    """
    reason = f"[{card.pairing}] Allow Keyholder to use key {card.key_label}"
    if card.seal_passphrase:
        reason += f" — seal: {card.seal_passphrase}"
    return reason


def pairing_word_os_prompt_support(platform: str) -> str:
    """Honest per-platform limit for the pairing word in OS prompts.

    Returns "full" | "partial" | "unsupported". "partial" means the
    platform's prompt agent may truncate or reword the reason string,
    so the pairing word is a best-effort match there, never the sole
    defence — card-frontmost + click-to-continue + confirm still hold.
    CLI note (f04 A-02, unverified on this Linux build): a CLI tool
    must NOT call the OS prompt directly; it must route the gesture
    through the broker UI process so the dialog is Keyholder's, since
    a Terminal-invoked dialog's app name is not established here.
    """
    platform = platform.lower()
    if platform == "darwin":
        return "full"  # LA reason string rendered verbatim
    if platform == "linux":
        return "partial"  # polkit agent may truncate/reword; no OS
        # prompt at all in broker-window mode
    if platform == "win32":
        return "unsupported"  # Hello UI renders no caller reason verbatim
    return "unsupported"


def requires_two_step(*, kind: str, is_destructive: bool) -> bool:
    """Universal two-step rule (f04 J-01): session creation and every
    destructive call require gesture + confirm, no exceptions, no
    biometric-only shortcut. (In this module ``confirm`` enforces the
    gesture-first rule for every kind, which is strictly stronger.)"""
    return (
        kind == ApprovalKind.SESSION_CREATION.value
        or kind == ApprovalKind.DESTRUCTIVE.value
        or is_destructive
    )


def _validate_fingerprint(value: str) -> str:
    if len(value) != 12 or any(c not in string.hexdigits for c in value):
        raise ValueError("key fingerprint must be exactly 12 hex chars")
    return value.lower()


@dataclass
class ApprovalCard:
    """What the approver renders. Headline = broker-known fields ONLY.

    ``agent_words`` (session name, job purpose, agent reason) is carried
    separately under an explicit unverified label and is NEVER merged
    into the headline. ``other_key_count`` is count-only: the negative
    list is rendered as "and N other keys are NOT included", never as
    a named list of other keys. There is deliberately no password /
    passcode field anywhere on this card.
    """

    approval_id: str
    key_id: str
    provider: str
    key_label: str
    key_fingerprint_12: str
    permissions: str  # broker-known permissions
    purpose: str  # broker-known purpose (NOT agent free text)
    kind: str
    other_key_count: int
    pairing: str
    rendered_at_monotonic: float = field(default_factory=time.monotonic)
    rendered_at_wall: float = field(default_factory=time.time)
    agent_words: str = ""  # labelled unverified, never in the headline
    is_destructive: bool = False
    seal_passphrase: str = ""  # N-E7 seal mark shown on the card
    seal_image_id: str = ""
    seal_version: int = 0

    def headline(self) -> str:
        return (
            f"[{self.pairing}] Allow Keyholder to use key "
            f"{self.key_label} ({self.key_fingerprint_12}) on "
            f"{self.provider} — {self.permissions}"
        )

    def negative_list_text(self) -> str:
        if self.other_key_count <= 0:
            return "No other keys are included."
        return f"and {self.other_key_count} other keys are NOT included"

    def render(self) -> dict:
        """Full card payload; assert headline contains no agent words."""
        head = self.headline()
        if self.agent_words and self.agent_words in head:
            raise ValueError("agent-supplied text leaked into card headline")
        return {
            "approval_id": self.approval_id,
            "headline": head,
            "permissions": self.permissions,
            "purpose": self.purpose,
            "provider": self.provider,
            "key_fingerprint_12": self.key_fingerprint_12,
            "negative_list": self.negative_list_text(),
            "agent_words_unverified": self.agent_words,
            "pairing_word": self.pairing,
            "presence_note": PRESENCE_NOTE,
            "footer": CARD_FOOTER,
            "is_destructive": self.is_destructive,
            "password_field": None,  # by construction: never a passcode field
            "seal": (
                {
                    "passphrase": self.seal_passphrase,
                    "image_id": self.seal_image_id,
                    "version": self.seal_version,
                }
                if self.seal_passphrase or self.seal_image_id
                else None
            ),
        }


def build_card(
    *,
    approval_id: str,
    key_id: str,
    provider: str,
    key_label: str,
    key_fingerprint_12: str,
    permissions: str,
    purpose: str,
    kind: str,
    other_key_count: int,
    agent_words: str = "",
    is_destructive: bool = False,
    seal: ApprovalSeal | None = None,
) -> ApprovalCard:
    """Build a card, refusing an unstatable worst case (v3 N-E11).

    A destructive card whose permissions/purpose cannot be stated as a
    concrete effect is a card-rendering error: the request is denied
    without a prompt, never shown with a vague blast radius.
    """
    if is_destructive and (not permissions.strip() or not purpose.strip()):
        raise ApprovalError(
            DenyReason.UNSUMMARISABLE_DESTRUCTIVE,
            "destructive approval refused: worst case cannot be stated "
            "plainly, so no card is rendered",
        )
    if other_key_count < 0:
        raise ValueError("other_key_count cannot be negative")
    return ApprovalCard(
        approval_id=approval_id,
        key_id=key_id,
        provider=provider,
        key_label=key_label,
        key_fingerprint_12=_validate_fingerprint(key_fingerprint_12),
        permissions=permissions,
        purpose=purpose,
        kind=kind,
        other_key_count=other_key_count,
        pairing=pairing_word(),
        agent_words=agent_words,
        is_destructive=is_destructive,
        seal_passphrase=seal.passphrase if seal else "",
        seal_image_id=seal.image_id if seal else "",
        seal_version=seal.version if seal else 0,
    )


# ---------------------------------------------------------------------------
# Platform tiers and display-protocol detection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PlatformTier:
    platform: str
    mechanism: str
    tier_label: str
    can_approve_destructive: bool
    broker_window_t3: bool = False
    helper_required: bool = False
    enclave_bound_available: bool = False
    notes: str = ""


def detect_display_protocol(env: dict | None = None) -> str:
    """Return 'wayland' | 'x11' | 'headless' | 'unknown'.

    XWayland counts as X11 (N-N6): the toolkit backend, not
    XDG_SESSION_TYPE, decides. An explicit ``KEYHOLDER_X11_BACKEND``
    marker (used by the forced-X11-backend CI test) also means X11.
    """
    import os

    env = env if env is not None else dict(os.environ)
    if env.get("KEYHOLDER_X11_BACKEND") == "1":
        return "x11"
    if env.get("WAYLAND_DISPLAY"):
        # A Wayland session can still run an X11 client via XWayland;
        # callers that know the toolkit backend must pass it explicitly
        # via detect_display_protocol's backend parameter instead.
        return "wayland"
    if env.get("DISPLAY"):
        return "x11"
    if env.get("SSH_CONNECTION") or env.get("SSH_TTY"):
        return "headless"
    return "unknown"


def detect_display_protocol_with_backend(
    *, backend: str | None, env: dict | None = None
) -> str:
    """Backend-aware variant: backend 'x11'/'xwayland' always means X11."""
    if backend in ("x11", "xwayland"):
        return "x11"
    if backend == "wayland":
        return "wayland"
    return detect_display_protocol(env)


def platform_tier_for(
    platform: str,
    *,
    display_protocol: str = "unknown",
    remote_session: bool = False,
    system_prompt_available: bool = False,
) -> PlatformTier:
    """Honest tier for this platform/mode. Never claims what is absent.

    Linux broker-window (T3) clicks may present/deny destructive calls
    but NEVER approve them — enforced by ``broker_window_may_approve``.
    """
    platform = platform.lower()
    if display_protocol == "x11":
        return PlatformTier(
            platform=platform,
            mechanism="X11 (incl. XWayland)",
            tier_label="REFUSED for destructive",
            can_approve_destructive=False,
            notes="X11 destructive refused (N-N2): keylogging + XTEST "
            "forgery defeat password and click alike; read-only may stay, badged.",
        )
    if remote_session:
        return PlatformTier(
            platform=platform,
            mechanism="remote session",
            tier_label="REFUSED for destructive",
            can_approve_destructive=False,
            notes="Destructive refused during remote sessions (N-N4); "
            "remote-typed PIN is at most T2, never T1.",
        )
    if platform == "darwin":
        return PlatformTier(
            platform=platform,
            mechanism="sandboxed approver (XPC) + Touch ID",
            tier_label="T1 biometric (macOS design)",
            can_approve_destructive=True,
            enclave_bound_available=True,
            notes="Design: sandboxed XPC keyholder-approver, enclave-bound "
            "signature for HIGH/CRITICAL. Enclave binding is a macOS-only "
            "design property; this Linux build reports it, not proves it.",
        )
    if platform == "linux":
        if system_prompt_available:
            return PlatformTier(
                platform=platform,
                mechanism="polkit / OS password via system UI",
                tier_label="T2 (Linux, system prompt)",
                can_approve_destructive=True,
                notes="Fresh per-approval polkit challenge; retained "
                "(_keep) authorisations refused; enrolment failure/daemon "
                "crash fails closed to T2 password, never to T3.",
            )
        return PlatformTier(
            platform=platform,
            mechanism="broker window (degraded)",
            tier_label="T3 (Linux, broker window)",
            can_approve_destructive=False,
            broker_window_t3=True,
            notes="Broker-window clicks may present or deny a destructive "
            "call, NEVER approve it. Non-destructive approvals only.",
        )
    if platform == "win32":
        return PlatformTier(
            platform=platform,
            mechanism="verifier-helper (boolean-only) design",
            tier_label="T2 (Windows, helper design)",
            can_approve_destructive=True,
            helper_required=True,
            notes="DESIGN ONLY in this module: an isolated verifier-helper "
            "must return boolean-only and never return the password to "
            "the app (N-N3). Until that helper exists, Windows destructive "
            "approval is not runnable from this module.",
        )
    return PlatformTier(
        platform=platform,
        mechanism="unknown",
        tier_label="T0/refused",
        can_approve_destructive=False,
        notes="Unsupported platform for approval: refuse, no app password ever.",
    )


def broker_window_may_approve(*, is_destructive: bool, tier: PlatformTier) -> bool:
    """Broker-window T3 rule: present/deny destructive, never approve."""
    if is_destructive:
        return False
    return True


def refuse_app_password() -> None:
    """N-E13: there is no app-password approval path, ever."""
    raise ApprovalError(
        DenyReason.APP_PASSWORD_REFUSED,
        "refused: no app password ever; OS authentication only",
    )


# ---------------------------------------------------------------------------
# Signed decision artifact (one artifact, approver-signed)
# ---------------------------------------------------------------------------

def _canonical_decision_bytes(decision: dict) -> bytes:
    return json.dumps(decision, sort_keys=True, separators=(",", ":")).encode()


class ApproverSigner:
    """Per-invocation approver signing key (Ed25519, cryptography).

    HIGH/CRITICAL decisions are enclave-bound-signed on macOS by design;
    on this build ``enclave_bound`` is False unless the caller proves a
    macOS enclave binding — it is never faked. The public key is handed
    to the broker out-of-band at approver start (in-process here).
    """

    def __init__(self, *, enclave_bound: bool = False) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        self._key = Ed25519PrivateKey.generate()
        self.public_key = self._key.public_key()
        self.enclave_bound = enclave_bound

    def sign(self, decision: dict) -> bytes:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        assert isinstance(self._key, Ed25519PrivateKey)
        return self._key.sign(_canonical_decision_bytes(decision))


@dataclass
class SignedDecision:
    approval_id: str
    request_hash: str
    nonce: str
    outcome: str  # "approved" | "denied"
    origin: str
    key_id: str
    kind: str
    signature: bytes = b""
    deny_reason: str = ""
    enclave_bound: bool = False
    grant_id: str = ""  # console-grant id, if grant-backed (audit only)
    seal_version: int = 0  # N-E7 seal version at approval time

    def payload(self) -> dict:
        return {
            "approval_id": self.approval_id,
            "deny_reason": self.deny_reason,
            "enclave_bound": self.enclave_bound,
            "grant_id": self.grant_id,
            "key_id": self.key_id,
            "kind": self.kind,
            "nonce": self.nonce,
            "origin": self.origin,
            "outcome": self.outcome,
            "request_hash": self.request_hash,
            "seal_version": self.seal_version,
        }


# ---------------------------------------------------------------------------
# Fatigue state machine (one machine, core counters)
# ---------------------------------------------------------------------------

class FatigueState(str, Enum):
    NORMAL = "normal"
    FRICTION = "friction"
    PAUSED = "paused"


@dataclass
class FatigueTracker:
    """One fatigue state machine per session (v3 N-E4).

    Counts SHOWN prompts only. ``record_shown`` is called when a prompt
    becomes visible/focusable; auto-denied prompts never increment it.
    """

    session_id: str
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    shown_at: list[float] = field(default_factory=list)  # monotonic
    session_count: int = 0
    paused_until_monotonic: float = 0.0
    anomaly_at: list[float] = field(default_factory=list)
    anomaly_paused: bool = False
    # Seal binding (f04 F-03, mandatory rotation): when a broker binds
    # its seal version here, clearing an anomaly pause REQUIRES a new
    # seal version. Unbound (None) trackers keep the legacy no-arg
    # clear — test-only; production brokers always bind.
    seal_version: int | None = None
    seal_version_at_pause: int | None = None

    def state(self, *, now: float | None = None) -> FatigueState:
        now = time.monotonic() if now is None else now
        if now < self.paused_until_monotonic or self.anomaly_paused:
            return FatigueState.PAUSED
        recent = [t for t in self.shown_at if now - t <= BURST_WINDOW_S]
        if len(recent) >= BURST_PAUSE_AT:
            return FatigueState.PAUSED
        if len(recent) >= BURST_TYPED_CONFIRM_AT:
            return FatigueState.FRICTION
        return FatigueState.NORMAL

    def typed_confirmation_required(self, *, now: float | None = None) -> bool:
        return self.state(now=now) in (FatigueState.FRICTION, FatigueState.PAUSED)

    def record_shown(self, *, now: float | None = None) -> FatigueState:
        """Record a newly visible prompt; returns the resulting state.

        Raises ApprovalError on hard caps (session budget, pause).
        The 5th prompt in 5 min enters the 15-min auto-deny window.
        """
        now = time.monotonic() if now is None else now
        with self._lock:
            if self.session_count >= SESSION_APPROVAL_BUDGET:
                raise ApprovalError(
                    DenyReason.SESSION_BUDGET_EXHAUSTED,
                    f"session approval budget ({SESSION_APPROVAL_BUDGET}) exhausted",
                )
            if now < self.paused_until_monotonic or self.anomaly_paused:
                raise ApprovalError(
                    DenyReason.FATIGUE_PAUSED, "approvals paused (fatigue window)"
                )
            self.shown_at.append(now)
            self.session_count += 1
            recent = [t for t in self.shown_at if now - t <= BURST_WINDOW_S]
            if len(recent) >= BURST_PAUSE_AT:
                self.paused_until_monotonic = now + PAUSE_WINDOW_S
                return FatigueState.PAUSED
            if len(recent) >= BURST_TYPED_CONFIRM_AT:
                return FatigueState.FRICTION
            return FatigueState.NORMAL

    def record_anomaly(self, *, now: float | None = None) -> bool:
        """A forged/replayed/hash-mismatched decision. 3 in 24 h pauses."""
        now = time.monotonic() if now is None else now
        with self._lock:
            self.anomaly_at.append(now)
            recent = [t for t in self.anomaly_at if now - t <= ANOMALY_WINDOW_S]
            if len(recent) >= ANOMALY_PAUSE_THRESHOLD:
                self.anomaly_paused = True
                self.seal_version_at_pause = self.seal_version
                return True
            return False

    def clear_anomaly_pause_after_seal_rotation(
        self, new_seal_version: int | None = None
    ) -> None:
        """Resume only after mandatory seal rotation (f04 F-03).

        When a seal is bound, a rotation MUST be proven: the caller
        passes the new seal version, which must differ from the
        version at pause time. An unbound tracker (test-only) keeps
        the legacy no-arg clear.
        """
        with self._lock:
            if self.seal_version is not None:
                if new_seal_version is None:
                    raise ApprovalError(
                        DenyReason.SEAL_ROTATION_REQUIRED,
                        "anomaly pause clears only after seal rotation: "
                        "pass the new seal version",
                    )
                if new_seal_version == self.seal_version_at_pause:
                    raise ApprovalError(
                        DenyReason.SEAL_ROTATION_REQUIRED,
                        "new seal version must differ from the version "
                        "at pause time",
                    )
                self.seal_version = new_seal_version
            self.anomaly_paused = False
            self.anomaly_at.clear()
            self.seal_version_at_pause = None


# ---------------------------------------------------------------------------
# Console grants (SSH/headless: grants only, never bare approval)
# ---------------------------------------------------------------------------

@dataclass
class ConsoleGrant:
    grant_id: str
    key_id: str
    scope_summary: str
    created_at_monotonic: float
    expires_at_monotonic: float
    seat_verified: bool
    starts_used: int = 0

    def covers(self, *, key_id: str, scope_summary: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        return (
            self.seat_verified
            and self.key_id == key_id
            and self.scope_summary == scope_summary
            and now < self.expires_at_monotonic
            and self.starts_used < 1  # single session start per grant
        )


def create_console_grant(
    *,
    key_id: str,
    scope_summary: str,
    seat_verified: bool,
    duration_s: float = CONSOLE_GRANT_MAX_S,
    is_destructive_scope: bool = False,
) -> ConsoleGrant:
    """Create a console grant. Never destructive, max 2 h, seat-verified."""
    if is_destructive_scope:
        raise ApprovalError(
            DenyReason.HEADLESS_NO_GRANT,
            "console grants are never destructive (N-E12)",
        )
    if not seat_verified:
        raise ApprovalError(
            DenyReason.HEADLESS_NO_GRANT,
            "console grant requires a verified local active seat session "
            "(class=user, seat assigned, remote=false, active=true)",
        )
    if duration_s <= 0 or duration_s > CONSOLE_GRANT_MAX_S:
        raise ApprovalError(
            DenyReason.HEADLESS_NO_GRANT,
            "console grant duration must be > 0 and <= 2 h",
        )
    now = time.monotonic()
    return ConsoleGrant(
        grant_id="grant-" + secrets.token_hex(8),
        key_id=key_id,
        scope_summary=scope_summary,
        created_at_monotonic=now,
        expires_at_monotonic=now + duration_s,
        seat_verified=True,
    )


# ---------------------------------------------------------------------------
# Break-glass: MEDIUM/session prompts only, NEVER destructive
# ---------------------------------------------------------------------------

@dataclass
class BreakGlass:
    """A break-glass activation is a pre-authorisation, not an approval.

    It is labelled as such on every backed call (presence timestamp +
    activation id in the audit entry). It never authorises destructive
    calls: those still need fresh per-call approval.
    """

    activation_id: str
    active_until_monotonic: float
    presence_at_wall: float

    def covers_medium(self, *, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        return now < self.active_until_monotonic

    def covers_destructive(self, **_kwargs) -> bool:
        return False  # unconditional: break-glass never covers destructive

    def preauthorisation_label(self) -> str:
        """N-E9 labelling: break-glass is a pre-authorisation, never
        described as an "approval". Every backed call's audit entry
        must carry this label + the presence timestamp."""
        presence = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.presence_at_wall)
        )
        return (
            f"pre-authorisation {self.activation_id}: presence at "
            f"{presence} authorises MEDIUM/session use until window end "
            f"without further gestures — not an approval, never "
            f"destructive"
        )


# ---------------------------------------------------------------------------
# Enrolment-change monitor (single posture: kill-all + password-only next)
# ---------------------------------------------------------------------------

class EnrolmentMonitor:
    """Continuous monitoring hooks: wake, unlock, approval, 15-min poll.

    The platform layer supplies ``domain_state`` (e.g. the macOS
    evaluatedPolicyDomainState blob, or a Linux enrolment fingerprint
    where one exists). Any change triggers the single posture:
    kill-all + password-only next + pending HIGH/CRITICAL fail closed.
    Approval-time-only checking is deleted by v3 and is not offered.
    """

    POLL_INTERVAL_S = 900.0  # 15 min

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.known_state: str | None = None
        self.last_poll_monotonic: float = 0.0
        self.password_only_next: bool = False
        self.kill_all_triggered: bool = False

    def observe(self, domain_state: str, *, trigger: str) -> bool:
        """Return True if this observation is an enrolment CHANGE."""
        with self._lock:
            if self.known_state is None:
                self.known_state = domain_state
                self.last_poll_monotonic = time.monotonic()
                return False
            if domain_state != self.known_state:
                self.known_state = domain_state
                self.password_only_next = True
                self.kill_all_triggered = True
                self.last_poll_monotonic = time.monotonic()
                return True
            if trigger == "poll":
                self.last_poll_monotonic = time.monotonic()
            return False

    def poll_due(self, *, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        return (now - self.last_poll_monotonic) >= self.POLL_INTERVAL_S

    def acknowledge_password_only_next(self) -> None:
        with self._lock:
            self.password_only_next = False


# ---------------------------------------------------------------------------
# Pending approval + broker (approver-only origin, serialised, two-step)
# ---------------------------------------------------------------------------

@dataclass
class PendingApproval:
    approval_id: str
    request_hash: str
    nonce: str
    card: ApprovalCard
    kind: str
    key_id: str
    provider: str
    level: int
    is_destructive: bool
    session_id: str = ""
    created_monotonic: float = field(default_factory=time.monotonic)
    gesture_at_monotonic: float | None = None  # system-prompt start
    gesture_ok: bool = False
    timeout_s: float = DEFAULT_TIMEOUT_S
    card_rendered_monotonic: float = field(default_factory=time.monotonic)
    state: str = "card"  # card -> gesture -> confirm -> decided
    typed_confirmation_done: bool = False
    grant_id: str = ""
    # Card-to-prompt race (N-E7): the card must still be frontmost
    # when the system prompt fires and while it is up. Focus loss
    # voids the approval to deny (see mark_card_obscured).
    card_frontmost: bool = True
    # Monotonic start of the actual OS prompt (N-E5 clock). The 60 s
    # timeout is measured from here, not from the continue click.
    prompt_started_monotonic: float | None = None


class ApprovalBroker:
    """Broker side: queues, serialises, verifies, consumes.

    The broker NEVER originates a decision. ``decide`` accepts only
    decisions whose origin is the approver channel and whose signature
    verifies against the approver's public key, and consumes the nonce
    atomically (CAS) before any side effect. The approver side is
    ``Approver`` below; in-process tests wire the two together, which
    mirrors the XPC pairing (code-signing identity + parent-PID check
    are platform-layer duties of W13, never PID alone).
    """

    def __init__(
        self,
        *,
        approver_signer: ApproverSigner | None = None,
        min_card_dwell_s: float = MIN_CARD_DWELL_S,
        clock: callable | None = None,
        seal: ApprovalSeal | None = None,
        seal_required: bool = False,
    ) -> None:
        self.signer = approver_signer or ApproverSigner()
        self.min_card_dwell_s = min_card_dwell_s
        self._clock = clock or time.monotonic
        # Seal (N-E7): production brokers MUST pass seal + seal_required
        # =True. A seal-less broker is a test-compat path only.
        self.seal = seal
        self.seal_required = seal_required
        self._lock = threading.Lock()
        self._pending: dict[str, PendingApproval] = {}
        self._queue: list[str] = []  # approval_ids in arrival order
        self._active_id: str | None = None
        self._consumed_nonces: set[str] = set()
        self._grants: dict[str, object] = {}  # approval_id -> ApproveOnceGrant
        self.fatigue: dict[str, FatigueTracker] = {}
        self.enrolment = EnrolmentMonitor()

    # -- queue / serialisation -------------------------------------------
    def request(
        self,
        *,
        session_id: str,
        card: ApprovalCard,
        request_hash: str,
        kind: str,
        key_id: str,
        provider: str,
        level: int = 3,
        is_destructive: bool = False,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        display_protocol: str = "unknown",
        remote_session: bool = False,
        tier: PlatformTier | None = None,
        headless: bool = False,
        console_grant: ConsoleGrant | None = None,
        breakglass: BreakGlass | None = None,
    ) -> PendingApproval:
        """Queue an approval. Raises (denies) on hard rule violations.

        X11/remote destructive, headless-without-grant, broker-window
        destructive and session-scope-for-destructive are refused here,
        before any prompt is shown — a refused request never becomes a
        prompt the user could be tricked into approving.
        """
        if kind == ApprovalKind.DESTRUCTIVE.value or is_destructive:
            if display_protocol == "x11":
                raise ApprovalError(
                    DenyReason.X11_DESTRUCTIVE_REFUSED,
                    "X11 destructive refused (N-N2)",
                )
            if remote_session:
                raise ApprovalError(
                    DenyReason.REMOTE_DESTRUCTIVE_REFUSED,
                    "destructive refused during remote session (N-N4)",
                )
            if tier is not None and tier.broker_window_t3:
                raise ApprovalError(
                    DenyReason.BROKER_WINDOW_DESTRUCTIVE,
                    "broker-window clicks may present/deny destructive, "
                    "never approve it",
                )
            # Break-glass exclusion (N-E9, f04 H-03): break-glass
            # presence changes NOTHING here. A destructive request
            # still goes through the full two-step ceremony; there
            # is no shortcut branch, and spend_grant() enforces the
            # same exclusion at spend time. No second, narrower
            # break-glass activation for destructive calls is
            # implemented in v0.2 — destructive always needs a
            # fresh per-call approval.
        if headless:
            if console_grant is None or not console_grant.covers(
                key_id=key_id, scope_summary=card.purpose
            ):
                raise ApprovalError(
                    DenyReason.HEADLESS_NO_GRANT,
                    "SSH/headless approval refused: no live console grant "
                    "covers exactly this key/scope (N-E12)",
                )
        with self._lock:
            if len(self._pending) >= MAX_PENDING:
                raise ApprovalError(
                    DenyReason.PENDING_CAP,
                    f"max {MAX_PENDING} pending prompts",
                )
            # Seal enforcement (N-E7): when this broker carries a
            # seal, the card must carry exactly that seal; when
            # seal_required, a seal-less card is refused outright.
            if self.seal is not None and (
                card.seal_passphrase != self.seal.passphrase
                or card.seal_image_id != self.seal.image_id
            ):
                raise ApprovalError(
                    DenyReason.SEAL_MISMATCH,
                    "card seal does not match the broker seal: refused, "
                    "no prompt is shown",
                )
            if self.seal_required and not (
                card.seal_passphrase and card.seal_image_id
            ):
                raise ApprovalError(
                    DenyReason.SEAL_MISSING,
                    "seal-required broker refuses a seal-less card",
                )
            tracker = self.fatigue.setdefault(session_id, FatigueTracker(session_id))
            if self.seal is not None:
                tracker.seal_version = self.seal.version
            # Fatigue counting happens when the prompt becomes VISIBLE,
            # not at queue time; see activate(). Queueing never counts.
            approval_id = "appr-" + secrets.token_hex(8)
            pending = PendingApproval(
                approval_id=approval_id,
                request_hash=request_hash,
                nonce=secrets.token_hex(16),
                card=card,
                kind=kind,
                key_id=key_id,
                provider=provider,
                level=level,
                is_destructive=is_destructive,
                timeout_s=timeout_s,
                grant_id=console_grant.grant_id if console_grant else "",
                session_id=session_id,
            )
            self._pending[approval_id] = pending
            self._queue.append(approval_id)
            self._maybe_activate_locked()
            return pending

    def _maybe_activate_locked(self) -> None:
        # Fatigue counts SHOWN prompts only: counting happens here, at
        # activation (visibility), never at queue time. A prompt that
        # trips a hard fatigue cap is auto-denied, never silently held.
        while self._active_id is None and self._queue:
            candidate_id = self._queue.pop(0)
            candidate = self._pending.get(candidate_id)
            if candidate is None:
                continue
            tracker = self.fatigue.setdefault(
                candidate.session_id, FatigueTracker(candidate.session_id)
            )
            try:
                tracker.record_shown(now=self._clock())
            except ApprovalError:
                candidate.state = "decided"  # auto-denied, never held
                self._pending.pop(candidate_id, None)
                continue
            self._active_id = candidate_id
            candidate.card_rendered_monotonic = self._clock()
            candidate.card.rendered_at_monotonic = candidate.card_rendered_monotonic

    def active(self) -> PendingApproval | None:
        with self._lock:
            return self._pending.get(self._active_id) if self._active_id else None

    def queued_ids(self) -> list[str]:
        with self._lock:
            return list(self._queue)

    # -- card re-render (stale-card rule) ---------------------------------
    def re_render_card(self, approval_id: str) -> ApprovalCard:
        """Re-render a stale (>5 min) card; returns the fresh card."""
        with self._lock:
            pending = self._pending[approval_id]
            original_count = pending.card.other_key_count
            pending.card = build_card(
                approval_id=approval_id,
                key_id=pending.key_id,
                provider=pending.provider,
                key_label=pending.card.key_label,
                key_fingerprint_12=pending.card.key_fingerprint_12,
                permissions=pending.card.permissions,
                purpose=pending.card.purpose,
                kind=pending.kind,
                other_key_count=original_count,
                agent_words=pending.card.agent_words,
                is_destructive=pending.is_destructive,
            )
            pending.card_rendered_monotonic = self._clock()
            pending.state = "card"
            pending.gesture_ok = False
            pending.gesture_at_monotonic = None
            pending.prompt_started_monotonic = None
            pending.card_frontmost = True
            return pending.card

    # -- two-step ceremony -------------------------------------------------
    def continue_from_card(self, approval_id: str) -> PendingApproval:
        """The explicit 'Review and continue' click, BEFORE any OS prompt.

        Enforces minimum card dwell (2 s) and the stale-card rule.
        Only the active (visible/focusable) prompt can continue.
        """
        with self._lock:
            pending = self._require_active_locked(approval_id)
            if not pending.card_frontmost:
                self._deny_locked(pending, DenyReason.FOCUS_LOSS_DENY)
                raise ApprovalError(
                    DenyReason.FOCUS_LOSS_DENY,
                    "card no longer frontmost: approval voided to deny",
                )
            if pending.state != "card":
                raise WrongOrder(f"cannot continue from state {pending.state!r}")
            now = self._clock()
            if now - pending.card_rendered_monotonic < self.min_card_dwell_s:
                raise WrongOrder("card dwell not yet satisfied (min 2 s)")
            if now - pending.card_rendered_monotonic > STALE_CARD_S:
                raise ApprovalError(
                    DenyReason.STALE_CARD,
                    "card older than 5 min: re-render before gesturing",
                )
            pending.state = "gesture"
            pending.gesture_at_monotonic = now
            return pending

    def system_prompt_reason(self, approval_id: str) -> str:
        """Reason string for the OS prompt of the active approval.

        The pairing word (and seal passphrase, when present) in this
        string is what lets the user match card ↔ prompt at a glance
        (N-E7). Call only after ``continue_from_card``; the string is
        handed to the OS prompt by ``begin_system_prompt``."""
        with self._lock:
            pending = self._require_active_locked(approval_id)
            return os_prompt_reason(pending.card)

    def begin_system_prompt(self, approval_id: str) -> PendingApproval:
        """Fire the OS prompt — ONLY after the continue click (N-E7).

        This is the click-to-continue enforcement point: calling it
        from any state other than "gesture" (i.e. before continue)
        is a WrongOrder error, so no OS prompt can ever fire
        automatically after card display. The card must still be
        frontmost; otherwise the approval voids to deny. The 60 s
        timeout clock (N-E5) starts HERE, not at the continue click.
        """
        with self._lock:
            pending = self._require_active_locked(approval_id)
            if pending.state != "gesture":
                raise WrongOrder(
                    "system prompt requires the continue click first "
                    f"(state is {pending.state!r})"
                )
            if not pending.card_frontmost:
                self._deny_locked(pending, DenyReason.FOCUS_LOSS_DENY)
                raise ApprovalError(
                    DenyReason.FOCUS_LOSS_DENY,
                    "card no longer frontmost when the system prompt "
                    "would fire: approval voided to deny",
                )
            pending.prompt_started_monotonic = self._clock()
            return pending

    def mark_card_obscured(self, approval_id: str) -> bool:
        """Focus left the card (A-03): void the pending approval to deny.

        Returns True if a pending approval was voided. Any prompt —
        active or queued — voided here can never be decided later;
        voiding the active prompt activates the next queued one.
        """
        with self._lock:
            pending = self._pending.get(approval_id)
            if pending is None:
                return False
            pending.card_frontmost = False
            self._deny_locked(pending, DenyReason.FOCUS_LOSS_DENY)
            return True

    def rotate_seal(self, new_seal: ApprovalSeal) -> ApprovalSeal:
        """Mandatory seal rotation (f04 F-03): new seal must differ.

        Advances the broker seal and clears anomaly pauses on every
        session tracker, proving rotation per tracker. A rotation to
        an identical seal is refused."""
        with self._lock:
            if self.seal is not None and (
                new_seal.passphrase == self.seal.passphrase
                and new_seal.image_id == self.seal.image_id
            ):
                raise ApprovalError(
                    DenyReason.SEAL_ROTATION_REQUIRED,
                    "rotated seal must differ from the current seal",
                )
            self.seal = new_seal
            for tracker in self.fatigue.values():
                if tracker.anomaly_paused:
                    tracker.clear_anomaly_pause_after_seal_rotation(
                        new_seal.version
                    )
                tracker.seal_version = new_seal.version
            return new_seal

    def _timeout_base_locked(self, pending: PendingApproval) -> float:
        """N-E5 clock: system-prompt start when recorded, else the
        continue-click time (legacy direct callers that never called
        begin_system_prompt)."""
        assert pending.gesture_at_monotonic is not None
        return (
            pending.prompt_started_monotonic
            if pending.prompt_started_monotonic is not None
            else pending.gesture_at_monotonic
        )

    def _require_frontmost_locked(self, pending: PendingApproval) -> None:
        if not pending.card_frontmost:
            self._deny_locked(pending, DenyReason.FOCUS_LOSS_DENY)
            raise ApprovalError(
                DenyReason.FOCUS_LOSS_DENY,
                "card no longer frontmost: approval voided to deny",
            )

    def record_gesture(self, approval_id: str, *, ok: bool) -> PendingApproval:
        """OS gesture result (system prompt). Timeout always denies.

        The clock starts at the system prompt (gesture_at_monotonic).
        A gesture alone NEVER approves: state moves to 'confirm' and
        only the subsequent confirm click completes the approval.
        """
        with self._lock:
            pending = self._require_active_locked(approval_id)
            if pending.state != "gesture":
                raise WrongOrder(
                    f"gesture requires state 'gesture', got {pending.state!r}"
                )
            self._require_frontmost_locked(pending)
            now = self._clock()
            if now - self._timeout_base_locked(pending) > pending.timeout_s:
                self._deny_locked(pending, DenyReason.TIMEOUT_DENY)
                raise ApprovalError(
                    DenyReason.TIMEOUT_DENY, "approval timed out: denied"
                )
            if not ok:
                self._deny_locked(pending, DenyReason.CANCEL_DENY)
                raise ApprovalError(DenyReason.CANCEL_DENY, "gesture denied")
            pending.gesture_ok = True
            pending.state = "confirm"
            return pending

    def confirm(self, approval_id: str, *, typed: str | None = None) -> SignedDecision:
        """The explicit confirm click AFTER the gesture: the approval act.

        Returns the approver-signed decision. The broker-side consume
        (``verify_and_consume``) must still be called before any side
        effect; this method alone authorises nothing downstream.
        """
        with self._lock:
            pending = self._require_active_locked(approval_id)
            if pending.state != "confirm" or not pending.gesture_ok:
                raise WrongOrder(
                    "confirm requires a successful gesture first "
                    "(biometric is presence, not authorisation)"
                )
            self._require_frontmost_locked(pending)
            now = self._clock()
            if now - self._timeout_base_locked(pending) > pending.timeout_s:
                self._deny_locked(pending, DenyReason.TIMEOUT_DENY)
                raise ApprovalError(
                    DenyReason.TIMEOUT_DENY, "approval timed out: denied"
                )
            # Progressive friction (N-E4): at the 3rd prompt in 5 min
            # the confirm click alone is not enough — typed
            # confirmation of the action is required as well.
            tracker = self.fatigue.get(pending.session_id)
            if tracker is not None and tracker.typed_confirmation_required(now=now):
                if not (typed and typed.strip()):
                    raise WrongOrder(
                        "typed confirmation required (fatigue friction): "
                        "type the action before confirming"
                    )
                pending.typed_confirmation_done = True
            pending.state = "decided"
            decision = SignedDecision(
                approval_id=approval_id,
                request_hash=pending.request_hash,
                nonce=pending.nonce,
                outcome="approved",
                origin=APPROVER_CHANNEL,
                key_id=pending.key_id,
                kind=pending.kind,
                enclave_bound=self.signer.enclave_bound,
                grant_id=pending.grant_id,
                seal_version=pending.card.seal_version,
            )
            decision.signature = self.signer.sign(decision.payload())
            self._grants[approval_id] = ApproveOnceGrant(
                approval_id=approval_id,
                request_hash=pending.request_hash,
                approved_at_monotonic=now,
                is_destructive=pending.is_destructive,
                nonce=pending.nonce,
            )
            self._finish_locked(approval_id)
            return decision

    def deny(self, approval_id: str, *, reason: DenyReason = DenyReason.EXPLICIT_DENY) -> None:
        """Deny (and kill) needs no auth; any pending prompt can be denied."""
        with self._lock:
            pending = self._pending.get(approval_id)
            if pending is None:
                return
            self._deny_locked(pending, reason)

    def kill_pending(self, approval_id: str) -> None:
        """Kill needs no auth and is never blocked (frictionless 'no')."""
        self.deny(approval_id, reason=DenyReason.EXPLICIT_DENY)

    def void_on_key_lifecycle(self, *, key_id: str) -> list[str]:
        """Pending approvals void on key rotation/deletion/disable (G-02)."""
        voided: list[str] = []
        with self._lock:
            for pid, pending in list(self._pending.items()):
                if pending.key_id == key_id:
                    self._deny_locked(pending, DenyReason.KEY_LIFECYCLE_VOID)
                    voided.append(pid)
        return voided

    def enrolment_changed(self) -> list[str]:
        """Single posture: kill-all pending, password-only next (N-E6)."""
        with self._lock:
            voided = [
                pid
                for pid, pending in list(self._pending.items())
                if pending.level >= 3 or pending.is_destructive
            ]
            for pid in voided:
                self._deny_locked(
                    self._pending[pid], DenyReason.ENROLMENT_CHANGE
                )
            self.enrolment.password_only_next = True
            self.enrolment.kill_all_triggered = True
            return voided

    # -- broker verification (CAS nonce consume) ---------------------------
    def verify_decision(self, decision: SignedDecision) -> bool:
        """Verify a signed decision WITHOUT consuming it.

        Origin -> signature -> request-hash checks only. Used by the
        production approver at ceremony time; consumption happens
        exactly once at forward time via verify_and_consume or
        spend_grant (unified single-use, v0.2 manager fix). A verified
        decision alone authorises no forward.
        """
        if decision.origin != APPROVER_CHANNEL:
            raise OriginRefused(decision.origin)
        # Signature verification (approver-signed artifact, N-E1).
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        try:
            assert isinstance(self.signer.public_key, Ed25519PublicKey)
            self.signer.public_key.verify(
                decision.signature, _canonical_decision_bytes(decision.payload())
            )
        except InvalidSignature as exc:
            raise ApprovalError(
                DenyReason.REQUEST_HASH_MISMATCH, "decision signature invalid"
            ) from exc
        with self._lock:
            pending = self._pending.get(decision.approval_id)
            # Note: confirm() already finished the pending entry; the
            # binding check uses the grant record instead (see below).
            grant = self._grants.get(decision.approval_id)
            expected_hash = (
                grant.request_hash if grant is not None
                else (pending.request_hash if pending else None)
            )
            if expected_hash is None or not hmac.compare_digest(
                expected_hash, decision.request_hash
            ):
                raise ApprovalError(
                    DenyReason.REQUEST_HASH_MISMATCH,
                    "decision request hash does not match the approved request",
                )
            return decision.outcome == "approved"

    def verify_and_consume(self, decision: SignedDecision) -> bool:
        """Broker-side acceptance. Returns True iff this decision may act.

        Order (normative, f04 D-02): origin check -> signature check ->
        request-hash check -> ATOMIC nonce consume -> accept. The nonce
        is consumed before any side effect, so concurrent replays lose.
        UNIFIED single-use (v0.2 manager fix): consuming here also
        marks the approve-once grant consumed, and spending the grant
        first also consumes the nonce — so verify_and_consume and
        spend_grant can never authorise two effects from one approval.
        """
        outcome = self.verify_decision(decision)
        with self._lock:
            grant = self._grants.get(decision.approval_id)
            if grant is not None and grant.consumed:
                raise ApprovalError(
                    DenyReason.NONCE_REPLAY, "grant already spent"
                )
            if decision.nonce in self._consumed_nonces:
                raise ApprovalError(
                    DenyReason.NONCE_REPLAY, "nonce already consumed (replay)"
                )
            # Atomic compare-and-swap: this insert IS the consume.
            self._consumed_nonces.add(decision.nonce)
            if grant is not None:
                grant.consumed = True
            return outcome

    def _require_active_locked(self, approval_id: str) -> PendingApproval:
        if self._active_id != approval_id:
            raise WrongOrder(
                "only the single visible/focusable prompt can be decided; "
                "other pending approvals are queued invisibly"
            )
        pending = self._pending.get(approval_id)
        if pending is None:
            raise ApprovalError(DenyReason.EXPLICIT_DENY, "approval not found")
        return pending

    def _deny_locked(self, pending: PendingApproval, reason: DenyReason) -> None:
        pending.state = "decided"
        self._finish_locked(pending.approval_id)

    def _finish_locked(self, approval_id: str) -> None:
        self._pending.pop(approval_id, None)
        if self._active_id == approval_id:
            self._active_id = None
        if approval_id in self._queue:
            self._queue.remove(approval_id)
        self._maybe_activate_locked()

    # -- approve-once grant spending ---------------------------------------
    def spend_grant(
        self,
        approval_id: str,
        *,
        request_hash: str,
        is_destructive: bool,
        breakglass: BreakGlass | None = None,
        now: float | None = None,
    ) -> bool:
        """Spend an approve-once grant for exactly one call.

        Destructive calls: fresh per-call approval only — a
        session-scope grant never spends here, break-glass never spends
        here, and a consumed grant never spends twice. Non-destructive
        session-scope calls are handled by the session layer, not here.
        """
        now = self._clock() if now is None else now
        with self._lock:
            grant = self._grants.get(approval_id)
            if grant is None:
                return False
            if is_destructive:
                # Break-glass exclusion, explicit (N-E9): break-glass
                # presence NEVER spends here. Only a fresh per-call
                # destructive grant spends, with or without break-glass
                # active. A non-destructive grant + break-glass also
                # spends nothing destructive.
                if not grant.is_destructive:
                    return False
            if not hmac.compare_digest(grant.request_hash, request_hash):
                return False
            if grant.consumed:
                return False
            # Unified single-use: a nonce consumed via verify_and_consume
            # already spent this approval, so spending the grant too
            # would be a second effect from one approval.
            if grant.nonce and grant.nonce in self._consumed_nonces:
                return False
            if now - grant.approved_at_monotonic > APPROVE_ONCE_CONSUME_DEADLINE_S:
                # Consumption deadline passed: prune so a stale grant
                # can never be spent later, and cannot be mistaken
                # for a live one.
                self._grants.pop(approval_id, None)
                return False
            grant.consumed = True  # single use, consumed atomically here
            if grant.nonce:
                self._consumed_nonces.add(grant.nonce)
            return True


@dataclass
class ApproveOnceGrant:
    approval_id: str
    request_hash: str
    approved_at_monotonic: float
    is_destructive: bool
    consumed: bool = False
    nonce: str = ""


# ---------------------------------------------------------------------------
# Approver side (renderer): the ONLY origin of decisions
# ---------------------------------------------------------------------------

class Approver:
    """The broker-owned approver process (renderer side).

    In production this is the sandboxed XPC service (macOS), the
    polkit/system-prompt caller (Linux), or the verifier-helper caller
    (Windows). It receives metadata only, renders the card, runs the
    two-step ceremony through the broker, and returns the signed
    decision. It holds no keys and no network access.

    ``approve_via`` is the ONLY approval entry point. Any caller that
    tries to approve through another object (CLI, dashboard) must use
    ``refuse_foreign_approval`` — which always raises OriginRefused.
    """

    def __init__(self, broker: ApprovalBroker) -> None:
        self.broker = broker

    def approve_via(
        self,
        approval_id: str,
        *,
        gesture_ok: bool = True,
        typed_confirmation: str | None = None,
    ) -> SignedDecision:
        """Run the two steps in order: continue -> system prompt ->
        gesture -> confirm. The system prompt never fires before the
        continue click (begin_system_prompt enforces the order)."""
        self.broker.continue_from_card(approval_id)
        self.broker.begin_system_prompt(approval_id)
        self.broker.record_gesture(approval_id, ok=gesture_ok)
        return self.broker.confirm(approval_id, typed=typed_confirmation)


def refuse_foreign_approval(channel: str) -> None:
    """CLI/dashboard/agent approval attempts always raise.

    Only the Approver object itself may originate a decision; this
    helper is what CLI/dashboard code paths must call, and it refuses
    every non-approver channel unconditionally.
    """
    if channel != APPROVER_CHANNEL:
        raise OriginRefused(channel)


def cli_or_dashboard_may_approve() -> bool:
    """Constant False, kept as a callable so no caller can drift."""
    return False


# ---------------------------------------------------------------------------
# v0.2 — real approver wiring (CONTRACT §13.2, W02)
#
# This section is the ONLY production approver callable for the proxy.
# It adapts the v0.1 broker ceremony above (two-step, signed decision,
# atomic broker-nonce consume) to the §13.2 interface:
#
#     approve(request: ApprovalRequest) -> Decision
#
# ``ApprovalRequest`` here is ``keyholder.types.ApprovalRequest`` when
# the caller has only the shared fields, and ``ProductionApprovalRequest``
# (below) when the caller can also supply the ceremony fields the
# broker needs to render an honest card (key label, 12-hex fingerprint,
# permissions, purpose, kind, display protocol). A plain request with
# no card data is DENIED, never rendered with a made-up label or
# fingerprint: the card must be built from broker-known fields only.
#
# Test-harness marker (named here, in proxy.py, and in the wiring
# tests; set ONLY by tests, never by production code):
#     KEYHOLDER_TEST_APPROVER=1
# A callable flagged with ``mark_test_approver`` — or passed through
# the proxy's explicit ``test_approver`` parameter — is refused by the
# proxy unless that marker is exactly "1". The production default is
# NOT a test double: with no approver the proxy denies level-3 calls
# (KH-1004); production wiring passes ``proxy_approver(real_approver)``
# explicitly.
#
# Gesture seam: ``gesture`` is the platform OS-prompt implementation
# (W13 owns the real one: Touch ID / polkit / Hello system prompt).
# ``gesture=None`` means NO system prompt is available on this machine,
# so the approver DENIES (fail closed) rather than inventing a yes.
# A test gesture that returns True simulates a user who passed the OS
# prompt; it does NOT bypass the ceremony — the broker still runs
# continue -> gesture -> confirm in order, still verifies the signed
# decision, and still consumes the nonce atomically. Timeout is
# enforced by the broker from the system-prompt start (the continue
# click that immediately precedes the prompt; conservative, since the
# prompt starts after continue): 60 s default, 120 s accessibility
# opt-in. ``decided_at`` is MONOTONIC clock seconds (the timeout /
# consumption-deadline clock), not wall time.
#
# Single use, two layers: (1) the broker consumes its own nonce
# atomically in ``verify_and_consume`` (concurrent replay loses,
# f04 D-02); (2) the production nonce below is consumed atomically
# in ``consume()`` at forward time, within the 5-minute consumption
# deadline. Presenting a Decision a second time therefore denies.
# Break-glass never approves a destructive call: it is checked only
# to document the exclusion — a destructive call still needs the full
# fresh ceremony. Kill needs no auth: ``RealApprover.kill`` delegates
# to ``ApprovalBroker.kill_pending`` with no gesture and no confirm.
# ---------------------------------------------------------------------------

import os as _os

TEST_APPROVER_ENV = "KEYHOLDER_TEST_APPROVER"
"""Env var set ONLY by tests to allow a test approver in the proxy.

Production code must never set it. The proxy raises unless it is
exactly "1" when a test approver is present.
"""


def test_approver_marker_set() -> bool:
    """True iff the test-harness marker is set (tests only)."""
    return _os.environ.get(TEST_APPROVER_ENV) == "1"


def mark_test_approver(fn):
    """Flag a callable as a TEST approver. The proxy refuses it
    outside the test-harness marker (see ``test_approver_marker_set``).
    Production adapters (``proxy_approver``) are never flagged."""
    fn._keyholder_test_approver = True  # type: ignore[attr-defined]
    return fn


def is_test_approver(fn) -> bool:
    """True iff ``fn`` was flagged with ``mark_test_approver``."""
    return bool(getattr(fn, "_keyholder_test_approver", False))


def compute_production_request_hash(
    *,
    session_pseudonym: str,
    provider: str,
    method: str,
    path: str,
    scope_summary: str,
    nonce: str,
    kind: str = ApprovalKind.DESTRUCTIVE.value,
    is_destructive: bool = False,
) -> str:
    """§13.2 request hash: binds pseudonym, provider, method,
    canonical path, scope summary, kind/destructiveness, and the
    single-use nonce. Any change -> a different hash -> the broker
    refuses the decision (request-hash mismatch)."""
    canonical = {
        "is_destructive": bool(is_destructive),
        "kind": kind,
        "method": method.upper(),
        "nonce": nonce,
        "path": path,
        "provider": provider,
        "scope_summary": scope_summary,
        "session_pseudonym": session_pseudonym,
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


@dataclass
class ProductionApprovalRequest:
    """§13.2 approval request, ceremony-complete form.

    ``approval_id`` is a caller placeholder (the broker mints the real
    pending id); ``key_id`` is the owning key; ``session_pseudonym``
    is the audit pseudonym for the session (never a token). A plain
    ``keyholder.types.ApprovalRequest`` is also accepted by
    ``RealApprover.approve`` and converted with ``key_id`` =
    ``session_pseudonym`` and no card data, which denies unless the
    caller also supplies card data via ``card_resolver`` (see
    ``proxy_approver``) — an honest card cannot be rendered without it.
    """

    session_pseudonym: str
    provider: str
    method: str
    path: str
    scope_summary: str
    session_id: str = ""
    key_id: str = ""
    approval_id: str = ""
    created_at: float = 0.0
    # Ceremony fields (broker-known only; never agent free text).
    key_label: str = ""
    key_fingerprint_12: str = ""
    permissions: str = ""
    purpose: str = ""
    kind: str = ApprovalKind.DESTRUCTIVE.value
    is_destructive: bool = False
    timeout_s: float | None = None
    accessibility: bool = False
    display_protocol: str = "unknown"
    remote_session: bool = False
    broker_window_t3: bool = False
    headless: bool = False
    console_grant: ConsoleGrant | None = None
    breakglass: BreakGlass | None = None


@dataclass
class ApprovalDecision:
    """§13.2 Decision: ``approved``, ``approval_id`` (broker pending
    id, also the approve-once grant id), ``consumed_nonce`` (the
    production nonce, consumed atomically by ``consume()`` at forward
    time), and ``decided_at`` (monotonic clock seconds). A denied
    decision carries ``deny_reason`` and an empty ``consumed_nonce``:
    nothing about it may ever be spent."""

    approved: bool
    approval_id: str
    consumed_nonce: str
    decided_at: float
    request_hash: str = ""
    deny_reason: str = ""


class RealApprover:
    """The broker-owned real approver (production callable).

    Wraps an ``ApprovalBroker`` and runs the full two-step ceremony
    for session creation and destructive calls, and the same
    broker ceremony for other approval-gated calls. It never approves
    from a CLI/dashboard channel, never approves a destructive call
    from a broker-window click or under X11 / a remote session, and
    never lets break-glass stand in for a fresh approval.
    """

    def __init__(
        self,
        broker: ApprovalBroker | None = None,
        *,
        gesture=None,
        clock=None,
        accessibility: bool = False,
    ) -> None:
        """``gesture``: callable(prompt: dict) -> bool, the platform
        OS-prompt seam. None = no system prompt available = deny.
        ``clock``: monotonic clock callable; defaults to the broker's
        clock when a broker is supplied, else ``time.monotonic``.
        Tests pass the SAME fake clock to broker and approver so a
        gesture stub can advance time past the timeout."""
        self.broker = broker if broker is not None else ApprovalBroker()
        if clock is not None:
            self._clock = clock
        else:
            self._clock = getattr(self.broker, "_clock", time.monotonic)
        self.gesture = gesture
        self.accessibility = accessibility
        self._lock = threading.Lock()
        self._consumed_nonces: set[str] = set()
        self._decisions: dict[str, ApprovalDecision] = {}
        self._signed: dict[str, object] = {}

    # -- helpers ---------------------------------------------------------
    def _deny(self, reason: str, request_hash: str = "") -> ApprovalDecision:
        return ApprovalDecision(
            approved=False,
            approval_id="",
            consumed_nonce="",
            decided_at=self._clock(),
            request_hash=request_hash,
            deny_reason=reason,
        )

    def _timeout_for(self, request: ProductionApprovalRequest) -> float:
        if request.timeout_s is not None:
            return float(request.timeout_s)
        if request.accessibility or self.accessibility:
            return ACCESSIBILITY_TIMEOUT_S
        return DEFAULT_TIMEOUT_S

    def _normalise(self, request) -> ProductionApprovalRequest:
        if isinstance(request, ProductionApprovalRequest):
            return request
        # Plain types.ApprovalRequest: shared fields only.
        return ProductionApprovalRequest(
            session_pseudonym=getattr(request, "session_pseudonym", ""),
            provider=getattr(request, "provider", ""),
            method=getattr(request, "method", ""),
            path=getattr(request, "path", ""),
            scope_summary=getattr(request, "scope_summary", ""),
            approval_id=getattr(request, "approval_id", ""),
            created_at=getattr(request, "created_at", 0.0),
            key_id=getattr(request, "session_pseudonym", ""),
        )

    # -- §13.2 interface --------------------------------------------------
    def approve(self, request) -> ApprovalDecision:
        """Run the ceremony for one request. Returns a Decision;
        ``approved`` is True only after gesture + confirm + broker
        verification. Never raises for a denial: denials are Decisions
        with ``approved=False`` (callers that need the broker reason
        use ``deny_reason``; the agent-facing surface stays generic)."""
        req = self._normalise(request)
        timeout_s = self._timeout_for(req)
        nonce = secrets.token_hex(16)
        request_hash = compute_production_request_hash(
            session_pseudonym=req.session_pseudonym,
            provider=req.provider,
            method=req.method,
            path=req.path,
            scope_summary=req.scope_summary,
            nonce=nonce,
            kind=req.kind,
            is_destructive=req.is_destructive,
        )
        # Hard refusals BEFORE any prompt is shown (a refused request
        # never becomes a prompt the user could be tricked into
        # approving). Gesture is not called on any of these paths.
        if req.is_destructive or req.kind == ApprovalKind.DESTRUCTIVE.value:
            if req.display_protocol == "x11":
                return self._deny(DenyReason.X11_DESTRUCTIVE_REFUSED.value,
                                  request_hash)
            if req.remote_session:
                return self._deny(DenyReason.REMOTE_DESTRUCTIVE_REFUSED.value,
                                  request_hash)
            if req.broker_window_t3:
                return self._deny(DenyReason.BROKER_WINDOW_DESTRUCTIVE.value,
                                  request_hash)
            if req.kind == ApprovalKind.SESSION_SCOPE.value:
                return self._deny(
                    DenyReason.SESSION_SCOPE_DESTRUCTIVE.value, request_hash)
        # Break-glass exclusion is absolute for destructive calls: its
        # presence changes nothing here — the ceremony below still
        # runs in full, and a gesture failure still denies.
        if not req.key_label or not req.key_fingerprint_12:
            # No honest card can be rendered without broker-known
            # label + fingerprint: fail closed, never invent them.
            return self._deny("card-data-missing", request_hash)
        try:
            card = build_card(
                approval_id="appr-" + secrets.token_hex(8),
                key_id=req.key_id or req.session_pseudonym,
                provider=req.provider,
                key_label=req.key_label,
                key_fingerprint_12=req.key_fingerprint_12,
                permissions=req.permissions or req.scope_summary,
                purpose=req.purpose or req.scope_summary,
                kind=req.kind,
                other_key_count=0,
                is_destructive=bool(req.is_destructive),
            )
        except (ApprovalError, ValueError) as exc:
            reason = getattr(exc, "reason", None)
            return self._deny(
                reason.value if isinstance(reason, DenyReason) else str(exc),
                request_hash)
        tier = None
        if req.broker_window_t3:
            tier = PlatformTier(
                platform="linux", mechanism="broker window (degraded)",
                tier_label="T3 (Linux, broker window)",
                can_approve_destructive=False, broker_window_t3=True)
        try:
            pending = self.broker.request(
                session_id=req.session_id or req.session_pseudonym,
                card=card,
                request_hash=request_hash,
                kind=req.kind,
                key_id=req.key_id or req.session_pseudonym,
                provider=req.provider,
                level=3 if req.is_destructive
                or req.kind == ApprovalKind.SESSION_CREATION.value else 2,
                is_destructive=bool(req.is_destructive),
                timeout_s=timeout_s,
                display_protocol=req.display_protocol,
                remote_session=req.remote_session,
                tier=tier,
                headless=req.headless,
                console_grant=req.console_grant,
                breakglass=req.breakglass,
            )
        except ApprovalError as exc:
            return self._deny(exc.reason.value, request_hash)
        approval_id = pending.approval_id
        try:
            # Step 1: explicit continue click, BEFORE any OS prompt
            # (f04 A-03: LA must never fire automatically after display).
            # The card dwell (2 s, real clock) is honoured, not skipped:
            # a dwell refusal waits out the remainder once and retries.
            # Test brokers use min_card_dwell_s=0, so no wait there.
            try:
                self.broker.continue_from_card(approval_id)
            except WrongOrder as exc:
                if "dwell" not in str(exc):
                    raise
                time.sleep(self.broker.min_card_dwell_s)
                self.broker.continue_from_card(approval_id)
            # Step 2a: OS gesture (system prompt). None = no system
            # prompt available on this machine = deny, fail closed.
            if self.gesture is None:
                self.broker.deny(approval_id)
                return self._deny(DenyReason.CANCEL_DENY.value, request_hash)
            prompt = {
                "approval_id": approval_id,
                "pairing": card.pairing,
                "headline": card.headline(),
                "kind": req.kind,
                "is_destructive": bool(req.is_destructive),
                "timeout_s": timeout_s,
            }
            try:
                gesture_ok = bool(self.gesture(prompt))
            except Exception:
                gesture_ok = False
            # Step 2b: record the gesture result, then the explicit
            # confirm click AFTER it. Gesture alone mints nothing.
            self.broker.record_gesture(approval_id, ok=gesture_ok)
            signed = self.broker.confirm(approval_id)
        except ApprovalError as exc:
            return self._deny(exc.reason.value, request_hash)
        except WrongOrder as exc:
            return self._deny(DenyReason.WRONG_ORDER.value, request_hash)
        # Broker verification WITHOUT consuming (v0.2 manager fix):
        # origin -> signature -> request-hash only. Consumption
        # happens exactly once at forward time in spend_for_forward,
        # so one approval can never authorise two forwards.
        try:
            verified = self.broker.verify_decision(signed)
        except ApprovalError as exc:
            return self._deny(exc.reason.value, request_hash)
        if not verified:
            return self._deny(DenyReason.EXPLICIT_DENY.value, request_hash)
        decision = ApprovalDecision(
            approved=True,
            approval_id=approval_id,
            consumed_nonce=nonce,
            decided_at=self._clock(),
            request_hash=request_hash,
            deny_reason="",
        )
        with self._lock:
            self._decisions[approval_id] = decision
            self._signed[approval_id] = signed
        return decision

    def approve_session_creation(self, request) -> ApprovalDecision:
        """Session creation: always the full two-step ceremony, any
        tier, any scope (f04 E-03: R03 Tier 0 wins over the v1 MEDIUM
        'unlocked broker suffices' sentence)."""
        req = self._normalise(request)
        req.kind = ApprovalKind.SESSION_CREATION.value
        return self.approve(req)

    def consume(self, decision: ApprovalDecision, *, request_hash: str) -> bool:
        """Spend a Decision for exactly one forward, atomically.

        Returns True once, within the 5-minute consumption deadline;
        every replay (same nonce, wrong hash, past deadline) returns
        False. This is the forward-time single-use consume: ``approve``
        alone authorises nothing downstream until ``consume`` succeeds.
        """
        now = self._clock()
        with self._lock:
            if decision.consumed_nonce in self._consumed_nonces:
                return False
            if not hmac.compare_digest(decision.request_hash, request_hash):
                return False
            if now - decision.decided_at > APPROVE_ONCE_CONSUME_DEADLINE_S:
                return False
            if not decision.approved:
                return False
            self._consumed_nonces.add(decision.consumed_nonce)
            return True

    def spend_for_forward(self, decision: ApprovalDecision, *,
                          is_destructive: bool) -> bool:
        """Consume BOTH layers for one proxied forward, exactly once:
        the production nonce (above) and the broker decision/grant
        (verify_and_consume, which also marks the grant consumed).
        Either layer refusing denies the forward. Break-glass never
        spends here. A second spend_for_forward for the same decision
        always fails: production nonce consumed, broker nonce consumed,
        grant consumed."""
        signed = self._signed.get(decision.approval_id)
        if signed is None:
            return False
        # Grant checks BEFORE consuming anything, so a denied forward
        # does not burn the decision: grant must exist, a destructive
        # forward needs a destructive grant (spend_grant's old rule),
        # and the grant must be within its consumption deadline.
        grant = self.broker._grants.get(decision.approval_id)
        if grant is None:
            return False
        if is_destructive and not grant.is_destructive:
            return False
        if (
            self._clock() - grant.approved_at_monotonic
            > APPROVE_ONCE_CONSUME_DEADLINE_S
        ):
            return False
        if not self.consume(decision, request_hash=decision.request_hash):
            return False
        try:
            return bool(self.broker.verify_and_consume(signed))
        except ApprovalError:
            return False

    def kill(self, approval_id: str) -> None:
        """Kill needs no auth and is never blocked (frictionless 'no').
        Any pending prompt can be killed this way, gesture or not."""
        self.broker.kill_pending(approval_id)


def proxy_approver(approver: RealApprover, *, card_resolver=None,
                   display_protocol: str = "unknown",
                   remote_session: bool = False,
                   broker_window_t3: bool = False):
    """Production proxy adapter: the callable the proxy calls for
    level-3 decisions. Signature matches the proxy's approve boundary:
    ``(session, method, canonical_path, scope_summary) ->
    (approved: bool, approval_id: str | None)``.

    ``card_resolver(session)`` must return ``(key_label,
    key_fingerprint_12)`` from broker/vault-known data, or None (then
    the call is denied — no card is invented). The adapter is NOT a
    test approver and is never flagged as one. After an approved
    Decision it spends the grant for exactly one forward; a failed
    spend denies the call.
    """
    def _adapter(session, method, canonical_path, scope_summary):
        resolved = card_resolver(session) if card_resolver is not None else None
        if resolved is None:
            return False, None
        key_label, fingerprint = resolved
        is_destructive = getattr(session, "session_class", "") == "destructive"
        request = ProductionApprovalRequest(
            session_pseudonym=getattr(session, "session_id", ""),
            session_id=getattr(session, "session_id", ""),
            key_id=getattr(session, "key_id", ""),
            provider=getattr(session, "provider", ""),
            method=method,
            path=canonical_path,
            scope_summary=scope_summary,
            key_label=key_label,
            key_fingerprint_12=fingerprint,
            permissions=scope_summary,
            purpose=scope_summary,
            kind=(ApprovalKind.DESTRUCTIVE.value if is_destructive
                  else ApprovalKind.SESSION_SCOPE.value),
            is_destructive=is_destructive,
            display_protocol=display_protocol,
            remote_session=remote_session,
            broker_window_t3=broker_window_t3,
        )
        decision = approver.approve(request)
        if not decision.approved:
            return False, None
        if not approver.spend_for_forward(decision,
                                          is_destructive=is_destructive):
            return False, None
        return True, decision.approval_id

    return _adapter
