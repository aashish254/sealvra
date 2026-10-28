"""W13 — platform abstraction for Keyholder v0.1.

Normative sources: CONTRACT.md §5 (storage tiers) and §10 (Tier A/B),
KEYHOLDER-PLAN-V3-FINALCHECK.md §1D (vault/keychain) and §1N (parity),
finalcheck/f14-parity-audit.md. v3 wins over v1/v2; deleted passages
are never built — in particular:

* No screen-sharing detector is implemented here, on any platform.
  No API enumerates other applications' capture sessions, so any
  such detector would be fake. Destructive approvals carry a
  universal standing reminder instead (v3 §1N N-N7, f14 F-08).
* No "Hello step-up addresses DPAPI" claim. Hello/polkit gestures
  gate Keyholder-mediated use only (v3 §1N N-N1, f14 F-01).
* X11 destructive and key-lifecycle approvals are REFUSED, not
  polkit-password-plus-rate-limit (v3 §1N N-N2, f14 F-02).
* Windows password approval is NOT boolean-only by API design:
  CredUIPromptForWindowsCredentials returns the password to the
  calling app. The design below requires an isolated boolean-only
  verifier-helper process; without it the tier must be displayed
  as password-in-memory (v3 §1N N-N3, f14 F-03).
* XWayland is detected from the actual toolkit backend at every
  approval, never from XDG_SESSION_TYPE alone (v3 §1N N-N6, f14 F-07).
* Polkit custom actions need a system install in
  /usr/share/polkit-1/actions/; per-user installs are NOT recognised.
  "Action installed?" is probed separately from "agent running?"
  (v3 §1N N-N5, f14 F-05).

Scope of THIS module (honest boundary):
  This is a pure, stdlib-only abstraction: explicit sys.platform
  branches, tier/mechanism reporting, gate logic, and design
  specifications for OS facilities. It makes NO native OS calls
  (no Keychain, DPAPI, Credential Manager, Secret Service, polkit,
  LAContext, or Hello calls) — those belong to the native check
  workers (W16 Windows, W17 macOS) and to the vault/approval
  workers that own the actual bindings. A tier reported here is
  therefore a *design gate* for the caller to enforce with a real
  OS call; it is not itself proof that the OS call happened.
  Callers must pass the *observed* mechanism (e.g. the method a
  polkit agent actually offered), never a presumed one.

Tier A vs Tier B (CONTRACT §10), stated for every control below:
  Tier A = interface-bound agent (acts only through Keyholder).
  Tier B = shell-capable same-user agent (can run arbitrary
  same-user code, read same-user files/stores, inject input
  where the platform allows it).
  Controls that survive Tier B: macOS Keychain access groups,
  OS-rendered prompts, worker sandbox profiles.
  Controls that do NOT survive Tier B and must never be cited as
  Tier B evidence: 0600/0700 file permissions, file-stored control
  tokens, peer-credential checks, pairing tokens.
  Same-user malware / compromised OS account is out of scope by
  design — this module says so; it does not imply otherwise.

What CANNOT be proven on Linux (for W18 docs — see also
``unprovable_on_platform``):
  macOS Keychain per-app ACLs, macOS Touch ID / LAContext
  behaviour, Windows Hello (biometric or PIN), Windows DPAPI /
  Credential Manager behaviour, and Windows Remote Credential
  Guard. Symmetrically, on macOS/Windows this module cannot prove
  Linux polkit agent identity, Secret Service lock state, or
  Wayland/X11 backend state. Tests run on one platform prove
  nothing about another platform's native behaviour; mocked-
  platform tests are labelled as such in the test file.

Working title is Keyholder. This module does NOT rename anything
to Keyseal. No real keys are used anywhere here; tests use only
TEST-ONLY fake values. No network, no push, no provider contact.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field

__all__ = [
    "PlatformUnsupportedError",
    "StorageTierInfo",
    "ApprovalTierInfo",
    "ApprovalDecision",
    "PolkitStatus",
    "HONEST_PARITY_STATEMENT",
    "STANDING_DESTRUCTIVE_REMINDER",
    "SUPPORTED_PLATFORMS",
    "current_platform",
    "storage_tier",
    "approval_tier",
    "display_label",
    "detect_display_backend",
    "is_x11_backend",
    "approval_allowed_for_session_class",
    "broker_window_can_approve",
    "macos_keychain_design",
    "windows_verifier_helper_design",
    "windows_password_tier",
    "hello_tier",
    "evaluate_polkit",
    "verify_polkit_agent_owner",
    "polkit_probe",
    "check_keyring_migration",
    "keyring_lock_posture",
    "remote_access_coverage",
    "remote_session_tier",
    "headless_approval",
    "console_grant_allowed",
    "scope_for_environment",
    "windows_tpm_domain_posture",
    "vault_unlock_password_entry",
    "grace_window_valid",
    "screen_sharing_status",
    "posture",
    "unprovable_on_platform",
    "tier_scope",
]

SUPPORTED_PLATFORMS = ("darwin", "win32", "linux")

HONEST_PARITY_STATEMENT = (
    "On macOS, stored keys are additionally gated by per-application "
    "Keychain ACLs. On Windows and Linux, stored keys are readable by "
    "any process running as your user. Keyholder's approval tiers, "
    "Hello/polkit gestures, and kill switch control what Keyholder "
    "itself does with your keys; they do not stop another program "
    "running as you from reading them directly from Credential "
    "Manager or your unlocked keyring. If that threat matters to "
    "you, macOS is currently the only platform where this product "
    "narrows it."
)

STANDING_DESTRUCTIVE_REMINDER = (
    "Close screen sharing before approving destructive actions. "
    "Keyholder cannot detect whether another app is capturing the "
    "screen, so this reminder is shown on every destructive approval."
)

# Known system polkit agent owner paths, by desktop. Anything else is
# treated as "no agent" (f14 F-06). This list is deliberately closed:
# an unknown owner is never upgraded to T2 on the strength of a name.
KNOWN_POLKIT_AGENT_PATHS = (
    "/usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1",
    "/usr/libexec/polkit-gnome-authentication-agent-1",
    "/usr/lib/polkit-kde-authentication-agent-1",
    "/usr/libexec/polkit-kde-authentication-agent-1",
    "/usr/bin/gnome-shell",
    "/usr/bin/plasmashell",
    "/usr/libexec/gsd-polkit-agent",
)

REMOTE_TOOLS_NOT_DETECTED = (
    "VNC",
    "TeamViewer",
    "AnyDesk",
    "Parsec",
    "SSH with X forwarding",
    "IPMI/KVM console",
)

# Session classes that are refused on X11 (v3 N-N2). "key_lifecycle"
# covers reveal/rotate/remove/backup-style operations; the CONTRACT
# SessionClass set does not include it, so callers pass it as an
# explicit string for approval gating.
X11_REFUSED_CLASSES = ("destructive", "key_lifecycle")


class PlatformUnsupportedError(ValueError):
    """Raised for an unsupported platform instead of silent fallthrough.

    Tier A/B: raising is Tier-A-neutral and Tier-B-neutral — it
    prevents a weaker platform's rules being silently applied to an
    unknown platform. Callers map this to CONTRACT error KH-3001
    (platform unsupported for this action, exit 1).
    """


@dataclass(frozen=True)
class StorageTierInfo:
    """Storage tier, distinct from the approval tier (v3 N-N1).

    Tier A: the tier describes what Keyholder's own unwrap path does.
    Tier B: only S1 (macOS Keychain per-app ACL) narrows same-user
    direct reads. S2/S3/S0 do NOT survive Tier B — a same-user
    process reads the store directly without any Keyholder gate.
    """

    tier: str  # S1 | S2 | S3 | S0
    mechanism: str  # always displayed with the tier (f14 F-17)
    platform: str
    same_user_direct_read: bool
    description: str
    tier_a: str = "Tier A: Keyholder-mediated unwrap is gated as described."
    tier_b: str = (
        "Tier B: survives only for S1 (macOS Keychain ACL). "
        "S2/S3/S0 are readable by any same-user process directly."
    )


@dataclass(frozen=True)
class ApprovalTierInfo:
    """Approval tier WITH mechanism — never an unqualified tier (f14 F-17).

    Tier A: the tier gates what Keyholder does on this approval.
    Tier B: a broker-window click (T3) does not survive Tier B on
    X11 (XTEST injection) or on Windows (same-integrity SendInput);
    a system gesture (T1/T2) survives Tier B only in the sense that
    a fake dialog cannot forge its boolean result — a typed
    PIN/password string itself remains phishable (f14 F-03).
    """

    tier: str  # T1 | T2 | T3 | T0
    mechanism: str  # e.g. "T1-biometric", "T1-pin", "T2-polkit-password"
    platform: str
    boolean_only: bool  # True if the password/PIN never reaches app memory
    description: str
    tier_a: str = "Tier A: gates Keyholder-mediated approval as described."
    tier_b: str = (
        "Tier B: system-gesture booleans cannot be forged by a fake "
        "dialog; typed strings can be harvested by a lookalike dialog; "
        "broker-window clicks are injectable on X11 and Windows."
    )

    def label(self) -> str:
        """Display label: tier always carries its mechanism."""
        return f"{self.tier} · {self.mechanism}"


@dataclass(frozen=True)
class ApprovalDecision:
    allowed: bool
    reason: str
    approval: ApprovalTierInfo | None = None
    badge: str = ""


@dataclass(frozen=True)
class PolkitStatus:
    """Polkit state with action-installed kept separate from agent-running.

    Tier A: these fields gate Keyholder's own approval path.
    Tier B: polkit does not gate direct Secret Service reads at all;
    a correct polkit decision still leaves S3 storage readable by
    any same-user process while unlocked.
    """

    action_installed: bool  # /usr/share/polkit-1/actions/ entry present
    agent_running: bool
    agent_owner_path: str | None = None  # executable of the agent owner
    allow_any: str = "no"  # must be "no"; any other value fails closed
    allow_inactive: str = "no"  # must be "no"
    retained_authorisation: bool = False  # any _keep grant: refused
    fresh_challenge: bool = True  # per-approval challenge, not cached "yes"
    observed_method: str | None = None  # method the agent ACTUALLY offered


def current_platform(platform: str | None = None) -> str:
    """Normalise a platform string with an explicit cfg-style gate.

    Tier A/B: platform selection is not a security control itself,
    but a silent fallthrough here would apply one platform's rules
    to another — so unknown values raise instead of defaulting.
    """
    value = platform if platform is not None else sys.platform
    if value == "darwin":
        return "darwin"
    if value == "win32":
        return "win32"
    if value.startswith("linux"):
        return "linux"
    raise PlatformUnsupportedError(
        f"unsupported platform for Keyholder approval/storage: {value!r} "
        f"(supported: darwin, win32, linux) [KH-3001]"
    )


def storage_tier(
    platform: str | None = None,
    *,
    backend: str = "platform_store",
) -> StorageTierInfo:
    """Return the storage tier for a platform + backend.

    Backends: "platform_store" (recommended default where available)
    or "password_file" (S0 on every platform).

    Tier A: per-record wrapping keys structure broker-side unwrapping
    and auditing on Windows/Linux; they are NOT OS-enforced gates
    there (v3 §1D N-D8, f14 F-23).
    Tier B: only darwin/platform_store (S1) narrows direct same-user
    reads. win32/platform_store is S2 (DPAPI user-scoped: any
    same-user process can call CryptUnprotectData; Credential
    Manager has no per-app ACL). linux/platform_store is S3
    (Secret Service / GNOME Keyring: any same-user process can read
    an unlocked keyring). S0 strength is the password only.
    """
    plat = current_platform(platform)
    if backend == "password_file":
        return StorageTierInfo(
            tier="S0",
            mechanism="password-encrypted file",
            platform=plat,
            same_user_direct_read=True,
            description=(
                "Password-encrypted file (S0). Strength is the password "
                "only; a stolen vault password exposes all compartments. "
                "Platform keychain mode is the recommended default."
            ),
        )
    if backend != "platform_store":
        raise ValueError(f"unknown storage backend: {backend!r}")
    if plat == "darwin":
        return StorageTierInfo(
            tier="S1",
            mechanism="macOS Keychain, one item per key, per-app ACL",
            platform=plat,
            same_user_direct_read=False,
            description=(
                "Per-application Keychain ACL (S1). A same-user process "
                "that is not Keyholder cannot read Keyholder's items "
                "without a system prompt; user-presence-gated items "
                "cannot be read silently at all."
            ),
        )
    if plat == "win32":
        return StorageTierInfo(
            tier="S2",
            mechanism="Windows Credential Manager / DPAPI, user-scoped",
            platform=plat,
            same_user_direct_read=True,
            description=(
                "User-scoped store (S2). DPAPI's boundary is the user "
                "account, not the application: any same-user process "
                "can call CryptUnprotectData with no prompt and no "
                "per-app isolation, and CredRead has no per-app ACL. "
                "Hello step-up gates Keyholder-mediated use only."
            ),
        )
    # linux
    return StorageTierInfo(
        tier="S3",
        mechanism="Secret Service / GNOME Keyring, session-scoped unlocked",
        platform=plat,
        same_user_direct_read=True,
        description=(
            "Session-scoped store, readable while unlocked (S3). Any "
            "application running as the user can read any unlocked "
            "keyring. A locked collection only narrows the window; "
            "while unlocked for a legitimate session, every item in "
            "the collection is readable by same-user processes."
        ),
    )


def approval_tier(
    platform: str | None = None,
    *,
    mechanism: str,
) -> ApprovalTierInfo:
    """Return an approval tier for an explicitly named mechanism.

    The mechanism string is the caller-observed mechanism, never a
    presumption (e.g. polkit T1 only when the agent actually offered
    fingerprint — f14 F-16). Unknown mechanisms raise rather than
    falling through to a weaker tier silently.

    Tier A: tiers measure Keyholder's gates, not platform storage.
    Tier B: see ApprovalTierInfo.tier_b; T1-pin and T2-windows-
    password are weaker than their tier letters suggest, which is
    exactly why the mechanism must be displayed (f14 F-17).
    """
    plat = current_platform(platform)
    table: dict[str, ApprovalTierInfo] = {
        "touch_id": ApprovalTierInfo(
            "T1", "T1-biometric (Touch ID)", plat, True,
            "macOS Touch ID via LAContext, fresh context per approval, "
            "boolean result only. The boolean is NOT authorisation: "
            "a two-step ceremony (gesture + explicit confirm, in that "
            "order) is still required (v3 §1D/§1E)."),
        "hello_biometric": ApprovalTierInfo(
            "T1", "T1-biometric (Windows Hello)", plat, True,
            "Windows Hello biometric, fresh context per approval, "
            "boolean result. A fake dialog cannot forge this boolean."),
        "hello_pin": ApprovalTierInfo(
            "T1", "T1-pin (Windows Hello PIN)", plat, False,
            "Windows Hello PIN. Must NOT share an unqualified T1 with "
            "biometric: a typed PIN is harvestable by a lookalike "
            "dialog, and a PIN typed into a remote session is at most "
            "T2 (input channel is the network). Displayed as T1-pin, "
            "never bare T1."),
        "la_context_password": ApprovalTierInfo(
            "T2", "T2-macOS LAContext password (boolean-only)", plat, True,
            "macOS LAContext password authentication: boolean-only, "
            "the password never reaches app memory."),
        "polkit_password": ApprovalTierInfo(
            "T2", "T2-polkit password (boolean-only)", plat, True,
            "Linux polkit password via the system agent: boolean-only, "
            "the password never reaches app memory. Requires the "
            "system-installed action and a verified agent (see "
            "evaluate_polkit); otherwise this tier is unavailable."),
        "polkit_fingerprint_observed": ApprovalTierInfo(
            "T1", "T1-fingerprint via polkit (observed)", plat, True,
            "Linux fingerprint via polkit, ONLY when a real test "
            "authorisation observed the agent actually offering "
            "fingerprint. fprintd presence or enrolment alone never "
            "implies this tier (f14 F-16)."),
        "windows_password_helper": ApprovalTierInfo(
            "T2", "T2-Windows password via verifier helper (boolean-only)",
            plat, True,
            "Windows password verified inside the isolated verifier-"
            "helper process (see windows_verifier_helper_design); "
            "only a boolean returns to the broker."),
        "windows_password_in_memory": ApprovalTierInfo(
            "T2", "T2-Windows password (password in app memory)", plat, False,
            "Windows CredUI password WITHOUT the verifier helper: "
            "CredUIPromptForWindowsCredentials RETURNS the password "
            "to the calling app by API design. Display this warning "
            "verbatim; mitigations are mlock, immediate zeroing, and "
            "never logging — not equivalence with boolean-only T2."),
        "broker_window_wayland": ApprovalTierInfo(
            "T3", "T3-broker window (Wayland)", plat, False,
            "Broker-window click on Wayland: compositor-isolated from "
            "other apps' input injection, but it is NOT a system "
            "prompt and must be labelled as such. Never approves a "
            "destructive call (see broker_window_can_approve)."),
        "broker_window_x11": ApprovalTierInfo(
            "T3", "T3-broker window (X11 — injectable)", plat, False,
            "Broker-window click on X11: injectable via XTEST and "
            "keyloggable. Same tier letter as Wayland, different "
            "attacker powers — the mechanism must be displayed."),
        "none": ApprovalTierInfo(
            "T0", "T0-refused (no approval)", plat, False,
            "No approval mechanism available: refused. Headless "
            "approval without a live console grant is T0."),
    }
    if plat == "darwin" and mechanism not in (
        "touch_id", "la_context_password", "broker_window_wayland",
        "broker_window_x11", "none",
    ):
        raise ValueError(f"mechanism {mechanism!r} is not a macOS mechanism")
    if plat == "win32" and mechanism not in (
        "hello_biometric", "hello_pin", "windows_password_helper",
        "windows_password_in_memory", "broker_window_wayland",
        "broker_window_x11", "none",
    ):
        raise ValueError(f"mechanism {mechanism!r} is not a Windows mechanism")
    if plat == "linux" and mechanism not in (
        "polkit_password", "polkit_fingerprint_observed",
        "broker_window_wayland", "broker_window_x11", "none",
    ):
        raise ValueError(f"mechanism {mechanism!r} is not a Linux mechanism")
    if mechanism not in table:
        raise ValueError(f"unknown approval mechanism: {mechanism!r}")
    return table[mechanism]


def display_label(tier_info: ApprovalTierInfo | StorageTierInfo) -> str:
    """Display label for a tier: tier always carries its mechanism."""
    if isinstance(tier_info, ApprovalTierInfo):
        return tier_info.label()
    return f"{tier_info.tier} · {tier_info.mechanism}"


def detect_display_backend(
    *,
    toolkit_backend: str | None = None,
    env: dict | None = None,
) -> dict:
    """Detect the display protocol from the actual toolkit backend.

    Tier A/B: this runs in the approval-UI process at EVERY approval,
    not at daemon startup and not once at install (f14 F-07/F-20).
    XDG_SESSION_TYPE is deliberately NOT an input: it describes the
    login session, not the protocol this app speaks, and an app in a
    Wayland session can still be an X11 client via XWayland. Any
    caller that only has XDG_SESSION_TYPE must treat the result as
    unknown and apply the X11 row (fail closed).

    ``toolkit_backend`` is the backend the toolkit is actually using
    ("wayland", "x11"/"xcb", or None when undiscoverable). ``env`` is
    a mapping for GDK_BACKEND / QT_QPA_PLATFORM / WAYLAND_DISPLAY /
    DISPLAY when the toolkit backend is not directly available.
    Returns a dict with backend ("wayland"|"x11"|"xwayland"|
    "headless"|"ambiguous") and a reason. "ambiguous" must be treated
    exactly like X11 by every caller (see is_x11_backend).
    """
    env = dict(env or {})
    backend = (toolkit_backend or "").strip().lower()
    if not backend:
        for key in ("GDK_BACKEND", "QT_QPA_PLATFORM"):
            value = str(env.get(key, "")).strip().lower()
            if value in ("wayland", "x11", "xcb"):
                backend = "xcb" if value == "xcb" else value
                break
    wayland_display = bool(env.get("WAYLAND_DISPLAY"))
    x_display = bool(env.get("DISPLAY"))
    if backend == "wayland":
        return {"backend": "wayland",
                "reason": "toolkit backend is Wayland"}
    if backend in ("x11", "xcb"):
        if wayland_display:
            return {"backend": "xwayland",
                    "reason": "toolkit backend is X11 inside a Wayland "
                              "session (XWayland); X11 row applies"}
        return {"backend": "x11",
                "reason": "toolkit backend is X11"}
    if not backend and wayland_display and not x_display:
        # Env-inferred only; callers that need proof must pass the
        # toolkit backend. Recorded honestly as inferred, not proven.
        return {"backend": "wayland",
                "reason": "inferred from WAYLAND_DISPLAY alone (no "
                          "toolkit backend supplied); prefer passing "
                          "the toolkit backend at every approval"}
    if not backend and not wayland_display and not x_display:
        return {"backend": "headless",
                "reason": "no display backend discoverable"}
    # Both displays present, or a backend we cannot classify: the app
    # could be either, so fail closed to the X11 row.
    return {"backend": "ambiguous",
            "reason": "display protocol ambiguous from available inputs "
                      "(XDG_SESSION_TYPE is never sufficient); "
                      "treated as X11"}


def is_x11_backend(backend_info: dict | str) -> bool:
    """True for x11, xwayland, and ambiguous backends (fail closed).

    Tier A: X11-row enforcement is a Keyholder gate.
    Tier B: X11/XWayland input is observable and forgeable by any
    same-user process (keylogging, XTEST), which is why the row
    refuses destructive approvals rather than rate-limiting them.
    """
    backend = backend_info["backend"] if isinstance(backend_info, dict) else backend_info
    return backend in ("x11", "xwayland", "ambiguous")


def approval_allowed_for_session_class(
    session_class: str,
    *,
    backend_info: dict | str,
) -> ApprovalDecision:
    """Gate an approval by session class and display backend.

    Destructive and key-lifecycle approvals on X11/XWayland are
    REFUSED (v3 N-N2). Read-only approvals may proceed with the X11
    badge (bounded scope, no secret typed, no destructive effect).
    Non-destructive write/read_account approvals are not in the
    v3 refusal set, so they proceed with the badge — but a broker-
    window click still never approves a destructive call, and any
    approval on X11 must show the injectable badge.

    Tier A: this is a Keyholder gate on its own approvals.
    Tier B: refusal is the only honest X11 answer because a
    keylogger captures the polkit/login password and XTEST forges
    the click; a rate limit cannot repair a single approval.
    """
    x11 = is_x11_backend(backend_info)
    backend = backend_info["backend"] if isinstance(backend_info, dict) else backend_info
    if x11 and session_class in X11_REFUSED_CLASSES:
        return ApprovalDecision(
            allowed=False,
            reason=(
                f"{session_class} approvals are REFUSED on {backend}: "
                "any program running as you can observe and forge "
                "approvals there. Switch to a Wayland session, or "
                "perform destructive actions at a Wayland console."
            ),
            badge=f"X11 ({backend}) — destructive refused",
        )
    if x11:
        return ApprovalDecision(
            allowed=True,
            reason=(
                f"{session_class} approval on {backend} proceeds with "
                "the X11 badge: bounded scope, no secret typed, no "
                "destructive effect. Broker-window clicks on X11 are "
                "injectable; system gestures are still required "
                "where the matrix reserves them."
            ),
            badge=f"X11 ({backend}) — injectable, badge shown",
        )
    return ApprovalDecision(
        allowed=True,
        reason=f"{session_class} approval on {backend} proceeds.",
        badge="",
    )


def broker_window_can_approve(session_class: str) -> bool:
    """A broker-window click may present or deny, NEVER approve destructive.

    Tier A: this gate binds Keyholder's own approval UI.
    Tier B: on Windows same-integrity SendInput and on X11 XTEST
    forge broker-window clicks, so a destructive click-approval
    would be forgeable on both platforms (f14 F-13, v3 N-N9).
    Destructive per-call approval is a fresh system gesture bound
    to the exact call fingerprint, on every platform.
    """
    return session_class not in ("destructive", "key_lifecycle")


def macos_keychain_design(*, strict_biometry: bool = False) -> dict:
    """macOS Keychain design (design specification, not a native call).

    Tier A: per-item ACLs gate Keyholder's own fetches.
    Tier B: Keychain access groups DO survive Tier B — this is the
    only platform where stored keys are narrowed against same-user
    processes. A single vault-wide KEK item is DELETED design (v3
    §1D N-D1, f14 F-23): one item per key, each with its own ACL.
    """
    flags = [".userPresence", "enrolment-change detection with step-up"]
    if strict_biometry:
        flags.append(
            ".biometryCurrentSet (strict-mode opt-in ONLY, with a "
            "re-wrap ceremony on enrolment change; per-item "
            "invalidation on enrolment change, recovery via backup "
            "export — never silent survival)"
        )
    return {
        "items": "one Keychain item per stored key (no vault-wide KEK item)",
        "access_group_gating": (
            "Keyholder's access group only; other same-user apps "
            "cannot read items without a system prompt"
        ),
        "access_control_flags": flags,
        "strict_biometry_note": (
            ".biometryCurrentSet is opt-in strict mode only. The "
            "deleted claim that it 'falls back to the device passcode' "
            "is NOT built: AND semantics kill passcode fallback, OR "
            "semantics kill enrolment-change invalidation."
        ),
        "approver": (
            "sandboxed, unprivileged approver process is the ONLY "
            "approval renderer; it receives metadata only and returns "
            "a signed, single-use decision bound to the request hash"
        ),
        "touch_id_rule": (
            "Touch ID via LAContext returns a BOOLEAN only. That "
            "boolean is NOT authorisation: session creation and "
            "destructive calls require gesture + explicit confirm, "
            "in that order, with a fresh LAContext per approval "
            "(reuse duration zero). Biometric-only is allowed only "
            "for identical-scope re-approval."
        ),
        "storage_tier": "S1",
        "tier_a": "Tier A: per-item ACLs gate Keyholder fetches.",
        "tier_b": "Tier B: Keychain access groups survive Tier B.",
    }


def windows_verifier_helper_design() -> dict:
    """Design for the isolated Windows password-verifier helper.

    Tier A: the helper gates Keyholder's own password approvals.
    Tier B: isolating the password in a helper process means a
    broker compromise does not yield the account password; it does
    NOT change S2 storage (Credential Manager remains directly
    readable by same-user processes). If this helper is not built,
    docs must state password-in-memory plainly (see
    windows_password_tier with_helper=False).
    """
    return {
        "process": (
            "Isolated verifier-helper process, separate from the "
            "broker. It — and only it — calls "
            "CredUIPromptForWindowsCredentials and verifies via "
            "LogonUser."
        ),
        "password_handling": (
            "Password lives only in helper memory, is mlocked, is "
            "zeroed immediately after verification, and is never "
            "logged, never returned, never written to disk."
        ),
        "return_value": "boolean only to the broker (verified / not verified)",
        "fallback_if_not_built": (
            "Without this helper, Windows password approvals are "
            "T2-windows-password-in-memory and must be displayed "
            "with that warning. Do NOT display them as equivalent "
            "to boolean-only T2."
        ),
        "tier_a": "Tier A: helper gates Keyholder password approvals.",
        "tier_b": (
            "Tier B: helper isolation narrows broker-compromise blast "
            "radius; it does not narrow S2 direct store reads."
        ),
    }


def windows_password_tier(*, with_helper: bool) -> ApprovalTierInfo:
    """Windows password tier, split by whether the helper exists."""
    return approval_tier(
        "win32",
        mechanism="windows_password_helper" if with_helper
        else "windows_password_in_memory",
    )


def hello_tier(*, kind: str) -> ApprovalTierInfo:
    """Windows Hello tier: 'biometric' and 'pin' are different tiers.

    Tier A: both gate Keyholder approvals.
    Tier B: biometric booleans cannot be forged by a fake dialog;
    a PIN string can be harvested by a lookalike dialog, and a PIN
    typed into a remote session is at most T2 (see
    remote_session_tier). They must never share an unqualified T1.
    """
    if kind == "biometric":
        return approval_tier("win32", mechanism="hello_biometric")
    if kind == "pin":
        return approval_tier("win32", mechanism="hello_pin")
    raise ValueError(f"unknown Hello kind: {kind!r} (biometric|pin)")


def verify_polkit_agent_owner(owner_path: str | None) -> bool:
    """True only if the polkit agent owner is a known system component.

    Tier A/B: an unknown owner is treated as "no agent" (T3/refusal),
    never as T2 — a malicious same-user process can otherwise
    register as the agent first on setups with no legitimate agent
    running and auto-approve prompts (f14 F-06).
    """
    return owner_path is not None and owner_path in KNOWN_POLKIT_AGENT_PATHS


def polkit_probe(*, action_installed: bool, agent_running: bool) -> dict:
    """First-run polkit probe: action-installed SEPARATE from agent-running.

    Tier A: both must be true for the polkit path to be available.
    Tier B: neither field changes S3 direct-read exposure.
    """
    return {
        "polkit_action_installed": action_installed,
        "polkit_agent_running": agent_running,
        "polkit_path_available": bool(action_installed and agent_running),
        "install_requirement": (
            "Custom polkit actions live in /usr/share/polkit-1/actions/ "
            "and require a system install (deb/rpm or an explicit "
            "admin step). Per-user installs are NOT recognised by "
            "polkit. Without the system install, approvals degrade "
            "to T3/refusal and the posture card must say so."
        ),
    }


def evaluate_polkit(status: PolkitStatus) -> ApprovalDecision:
    """Evaluate a polkit approval attempt; fails closed on every gap.

    Normative defaults: allow_any=no, allow_inactive=no (v3 N-N5).
    Retained (_keep) authorisations are refused; a cached "yes" is
    never an approval — only a fresh per-approval challenge counts.
    Agent identity is verified; an unknown owner is "no agent".
    Observed method rules: T1 only when the agent actually offered
    fingerprint (real test authorisation); fprintd presence or
    enrolment alone never implies T1; enrolment failure / daemon
    crash fails closed to T2 password, never to T3 for reserved
    actions and never to a silent T1 claim.

    Tier A: gates Keyholder's polkit approvals.
    Tier B: polkit gates Keyholder only; unlocked Secret Service
    items remain directly readable by same-user processes.
    """
    if not status.action_installed:
        return ApprovalDecision(
            False,
            "Polkit action not installed (system install required in "
            "/usr/share/polkit-1/actions/). Approvals degrade to "
            "T3/refusal; posture card must state the degradation.",
            approval_tier("linux", mechanism="none"),
            badge="polkit action not installed",
        )
    if not status.agent_running or not verify_polkit_agent_owner(
        status.agent_owner_path
    ):
        return ApprovalDecision(
            False,
            "Polkit agent not verified as a known system component "
            "(not running, or owner is unknown). Treated as no agent: "
            "T3/refusal, never T2.",
            approval_tier("linux", mechanism="none"),
            badge="polkit agent unverified",
        )
    if status.allow_any != "no" or status.allow_inactive != "no":
        return ApprovalDecision(
            False,
            "Polkit action defaults unsafe: allow_any and "
            "allow_inactive must both be 'no'. Refused.",
            approval_tier("linux", mechanism="none"),
            badge="polkit defaults unsafe",
        )
    if status.retained_authorisation:
        return ApprovalDecision(
            False,
            "Retained (_keep) polkit authorisation refused: a fresh "
            "per-approval challenge is required; a cached 'yes' is "
            "never an approval.",
            approval_tier("linux", mechanism="none"),
            badge="retained authorisation refused",
        )
    if not status.fresh_challenge:
        return ApprovalDecision(
            False,
            "Polkit approval requires a fresh per-approval challenge "
            "for this exact approval; a prior authorisation is not "
            "an approval.",
            approval_tier("linux", mechanism="none"),
            badge="fresh challenge required",
        )
    if status.observed_method == "fingerprint":
        return ApprovalDecision(
            True, "Polkit fingerprint observed via real authorisation.",
            approval_tier("linux", mechanism="polkit_fingerprint_observed"),
            badge="T1 · fingerprint via polkit (observed)",
        )
    # Observed password, or no observed method recorded: T2 password.
    # Never T3 for reserved actions, never a silent T1 claim.
    return ApprovalDecision(
        True, "Polkit password (boolean-only) via verified system agent.",
        approval_tier("linux", mechanism="polkit_password"),
        badge="T2 · polkit password",
    )


def check_keyring_migration(
    *,
    new_password_differs_from_login: bool,
    old_items_deleted_and_verified: bool,
    lock_state_checked_at_mint: bool,
) -> dict:
    """Validate a move from an auto-unlocked to a locked collection.

    Tier A: gates Keyholder's destructive mint posture.
    Tier B: even a correct migration only narrows the window — while
    the collection is unlocked for a session, any same-user process
    reads every item in it. Posture wording must say "narrows the
    window", never "prevents".
    All three checks must pass; a new collection with the login
    password is PAM-unlocked at login too (placebo), surviving old
    items are still readable, and a cached lock state is stale the
    moment another app unlocks the collection.
    """
    failures = []
    if not new_password_differs_from_login:
        failures.append(
            "new collection password must differ from the login "
            "password (else PAM unlocks it at login too); verify "
            "with a logout/login still-locked test"
        )
    if not old_items_deleted_and_verified:
        failures.append(
            "old items must be deleted from the login keyring and "
            "deletion verified (re-open + lookup must fail)"
        )
    if not lock_state_checked_at_mint:
        failures.append(
            "lock state must be read synchronously at every mint "
            "(collection Locked property), not cached from unlock"
        )
    return {
        "migration_valid": not failures,
        "failures": failures,
        "posture_wording": (
            "Locked collection: reduces the window during which "
            "same-user processes can read stored keys; it does not "
            "prevent it during an active session."
        ),
    }


def keyring_lock_posture(*, locked_at_mint: bool) -> dict:
    """Lock-state posture read at mint time, plus explicit lock rules.

    Tier A: Keyholder locks its collection explicitly on session
    end, screen lock, and suspend (never assumed from the desktop).
    Tier B: GNOME Keyring is not locked on user switching, and
    lock-on-suspend is configuration-dependent — neither may be
    assumed.
    """
    return {
        "locked_at_mint": locked_at_mint,
        "destructive_mint_allowed": bool(locked_at_mint),
        "explicit_lock_on": ("session end", "screen lock", "suspend"),
        "tier_b_caveats": (
            "GNOME Keyring is not locked on user switching; "
            "lock-on-suspend is configuration-dependent."
        ),
    }


def remote_access_coverage() -> dict:
    """Remote-access coverage table (v3 N-N4, f14 F-09).

    Tier A: RDP detection (SM_REMOTESESSION on Windows) gates
    Keyholder's remote badge/row.
    Tier B: undetected remote tools present a remote user as local;
    an approval through one is indistinguishable from a local
    approval. Remote state is re-probed at every approval, not at
    session start.
    """
    return {
        "detected": ("RDP via SM_REMOTESESSION (Windows only)",),
        "not_detected": REMOTE_TOOLS_NOT_DETECTED,
        "residual": (
            "Do not approve destructive actions while any "
            "remote-access tool is running; undetected tools look "
            "local to Keyholder."
        ),
    }


def remote_session_tier(
    *,
    remote: bool,
    mechanism: str,
    credential_guard: bool = False,
) -> ApprovalTierInfo | None:
    """Tier for an approval made in a remote session.

    Consumer RDP collapses in practice to destructive refusal (no
    local Hello gesture exists inside a remote session; Hello for
    Business is not supported for authentication on the remote
    device itself). Remote Credential Guard deployments may accept
    a Hello gesture as T1 with the remote badge. A PIN typed into a
    remote session is at most T2, never T1. Callers combine this
    with approval_allowed_for_session_class for the refusal itself;
    this function returns None when no tier is available (refused).
    """
    if not remote:
        return None  # not a remote session; local tiering applies
    if credential_guard and mechanism == "hello_biometric":
        # Guard case is the only remote Hello acceptance; badge it.
        return approval_tier("win32", mechanism="hello_biometric")
    if credential_guard and mechanism == "hello_pin":
        # Manager integration fix (W16 warning): a PIN approval must
        # never display as biometric, and a remote-typed PIN is at
        # most T2 even under Credential Guard — never T1/T1-pin.
        return ApprovalTierInfo(
            "T2", "T2-remote-typed PIN via Credential Guard (never T1)",
            "win32", False,
            "PIN typed into a remote session: input channel is the "
            "network, so it proves PIN knowledge, not local presence. "
            "At most T2, never T1, even with Credential Guard.")
    if mechanism == "hello_pin":
        return ApprovalTierInfo(
            "T2", "T2-remote-typed PIN (never T1)", "win32", False,
            "PIN typed into a remote session: input channel is "
            "the network, so it proves PIN knowledge, not local "
            "presence. At most T2, never T1.")
    return None  # consumer RDP: no usable local gesture -> refused


def headless_approval(*, under_console_grant: bool) -> ApprovalDecision:
    """Headless approval is T0/refused except under a live console grant.

    Tier A: CLI may list and kill, never approve or mint without an
    OS-owned gesture (or a live grant, below).
    Tier B: terminal password prompts over SSH are forbidden —
    readable by terminal logging/recording and by same-user
    processes that can open the session's pty.
    """
    if not under_console_grant:
        return ApprovalDecision(
            False,
            "Headless approval refused (T0): no GUI/OS gesture "
            "available. CLI may list and kill sessions only.",
            approval_tier("linux", mechanism="none"),
            badge="headless — T0 refused",
        )
    return ApprovalDecision(
        True,
        "Headless approval only via a live console grant (see "
        "console_grant_allowed); destructive scope is never granted.",
        approval_tier("linux", mechanism="none"),
        badge="console grant",
    )


def console_grant_allowed(
    *,
    seat_active: bool,
    seat_assigned: bool,
    remote: bool,
    gui_present: bool,
    scope: str,
) -> dict:
    """Console-grant creation/use predicate (v3 §1E/§1N, f14 F-04).

    Grants are read-only and non-destructive scope ONLY.
    Destructive-class sessions and key-lifecycle operations always
    require console presence; no grant can authorise them. Grant
    creation must verify a local active seat session (logind class
    user, seat assigned, remote=false, active=true, GUI present) —
    "created at the console" is a checked predicate, not a phrase.
    Grant creation over SSH with X forwarding fails. Use is audited
    as approval_method=console_grant with grant id + creation time
    (the audit worker owns that field; this function returns the
    method string to record).
    """
    checks = {
        "seat_active": seat_active,
        "seat_assigned": seat_assigned,
        "not_remote": not remote,
        "gui_present": gui_present,
        "scope_non_destructive": scope in (
            "read_only", "read_public", "read_account", "write_non_destructive",
        ),
    }
    allowed = all(checks.values())
    return {
        "allowed": allowed,
        "failed_checks": [k for k, v in checks.items() if not v],
        "approval_method": "console_grant" if allowed else None,
        "note": (
            "Headless servers (no GUI session ever) can never create "
            "a console grant: servers are out of scope for session "
            "minting in v1 (kill/list only)."
            if not gui_present else
            "Destructive scope is never grantable, even with a live grant."
        ),
    }


def scope_for_environment(environment: str) -> dict:
    """v1 scoping for unscoped platforms (v3 N-N6, f14 F-18).

    WSL, containers, and ChromeOS Linux (Crostini/Sommelier) are out
    of scope for session minting in v1 (kill/list only, with an
    explanatory refusal). xrdp sessions are X11 sessions for all
    matrix purposes. Sommelier/Crostini is treated as XWayland
    (X11 row) until proven otherwise.
    """
    table = {
        "wsl": ("T0", False, "WSL: out of scope for session minting in v1 "
                 "(no polkit agent, keyring daemon, or GUI session); "
                 "kill/list only."),
        "container": ("T0", False, "Container: out of scope for session "
                      "minting in v1 (no seat, agent, or keyring); "
                      "kill/list only."),
        "crostini": ("X11", False, "ChromeOS Linux (Crostini/Sommelier): "
                     "treated as XWayland (X11 row) until proven "
                     "otherwise; destructive refused."),
        "xrdp": ("X11", False, "xrdp: an X11 session for all matrix "
                 "purposes (not Windows-RDP treatment); destructive "
                 "refused."),
        "native": ("native", True, "Native seat session: matrix applies."),
    }
    if environment not in table:
        raise ValueError(f"unknown environment: {environment!r}")
    row, mint, note = table[environment]
    return {"environment": environment, "matrix_row": row,
            "session_mint_allowed": mint, "note": note}


def windows_tpm_domain_posture(
    *,
    tpm: str,
    domain_joined: bool,
) -> dict:
    """Windows TPM/domain posture, honestly stated (v3 N-N10, f14 F-12).

    TPM-less TTL caps narrow the session-token-theft window slightly
    and do NOTHING for Credential Manager readability. A virtual TPM
    in a VM reports present while the host can read its state, so
    hardware/virtual/absent are split. Domain DPAPI backup keys mean
    domain admins can decrypt user DPAPI data (recovery path AND
    threat-model fact). Warn-and-proceed: refusing to run would push
    users back to pasting keys into chats, which is worse — but a
    TPM-backed card must never imply stored keys are safe from
    same-user processes.
    """
    if tpm not in ("hardware", "virtual", "absent"):
        raise ValueError(f"unknown TPM state: {tpm!r}")
    return {
        "tpm": tpm,
        "tpm_note": {
            "hardware": "Hardware TPM present.",
            "virtual": "Virtual TPM only: host can read vTPM state; "
                       "do not treat as hardware TPM.",
            "absent": "No TPM: destructive TTL capped at the short end "
                      "of the class table (token-theft window only); "
                      "this does not mitigate Credential Manager reads.",
        }[tpm],
        "domain_joined": domain_joined,
        "domain_note": (
            "Domain-joined: domain DPAPI backup keys mean domain "
            "administrators can decrypt user DPAPI data; admin "
            "password reset typically recovers DPAPI data."
            if domain_joined else
            "Local account: no DPAPI backup key; admin password "
            "reset usually means permanent DPAPI data loss — "
            "restore from encrypted backup."
        ),
        "storage_tier": "S2 (unchanged by TPM or domain status)",
        "target_name_note": (
            "Opaque Credential Manager target names hide provider "
            "names from casual listing only; anyone who can read "
            "the vault file maps IDs to providers trivially."
        ),
    }


def vault_unlock_password_entry(*, backend_info: dict | str) -> dict:
    """Bounded carve-out for password-mode vault-unlock entry (f14 F-14).

    The rule "Keyholder never implements its own password prompt"
    is unsatisfiable for password mode: polkit/LAContext/Hello return
    booleans, never a passphrase, so vault-unlock passphrase entry
    MUST be a broker-drawn field. The carve-out covers vault unlock
    ONLY — never session or per-call approvals, which remain
    system-gesture-only. On X11 the typed passphrase is keyloggable
    (a further reason X11 destructive is refused even in password
    mode); elsewhere the passphrase still transits broker memory
    and must be mlocked and zeroed immediately.
    """
    x11 = is_x11_backend(backend_info)
    return {
        "carve_out": "vault-unlock passphrase entry only (broker window)",
        "never_extends_to": ("session approval", "per-call approval"),
        "x11_keyloggable": x11,
        "handling": "mlocked, zeroed immediately, never logged",
        "warning": (
            "On X11 the typed passphrase is observable by any "
            "same-user program."
            if x11 else
            "Window input is isolated from other apps on this "
            "backend, but the passphrase still transits broker memory."
        ),
    }


def grace_window_valid(
    *,
    session_class: str,
    session_type_changed: bool,
    screen_locked: bool,
) -> bool:
    """Grace-window validity (v3 §1D N-C10, f14 F-11).

    Grace windows are BANNED for destructive and key-lifecycle
    sessions, invalidated by any session-type change (local→RDP,
    Wayland→X11/XWayland, seat change) and by screen lock, and must
    record the original gesture's timestamp in the audit entry.
    Tier A: a Keyholder-side reuse rule. Tier B: a grace window
    never narrows direct store reads.
    """
    if session_class in ("destructive", "key_lifecycle"):
        return False
    if session_type_changed or screen_locked:
        return False
    return True


def screen_sharing_status() -> dict:
    """Screen-sharing state: ALWAYS unknown. There is no detector.

    Deleted claim (v3 N-N7, f14 F-08): no API on any platform
    enumerates other apps' capture sessions — the portal ScreenCast
    interface, Windows Graphics Capture, and macOS ScreenCaptureKit
    serve the capturing app, not a bystander. This function exists
    so callers have one honest value to record, and so no caller
    invents a detector: do NOT add a detect_screen_sharing function.
    Approval/reveal windows never contain secret values (the only
    reliable capture control), and the standing reminder is shown
    on every destructive approval on every platform.
    """
    return {
        "screen_sharing_known": False,
        "screen_sharing_active": None,  # unknown, never False-by-default
        "detector": None,
        "standing_reminder": STANDING_DESTRUCTIVE_REMINDER,
        "note": (
            "A field claiming 'not sharing' when sharing is "
            "undetectable would be worse than no field. Record "
            "unknown, show the reminder."
        ),
    }


def posture(
    *,
    platform: str | None = None,
    storage_backend: str = "platform_store",
    approval_mechanism: str,
    backend_info: dict | str | None = None,
    toolkit_backend: str | None = None,
    env: dict | None = None,
    seat: str | None = None,
    remote: bool = False,
    tpm: str | None = None,
    domain_joined: bool | None = None,
) -> dict:
    """Per-approval posture record (CONTRACT §8/§10, v3 §1N).

    Records storage tier + approval mechanism + session/display
    type + seat + remote flag per approval, with the honest parity
    statement attached. Detection inputs are the approval-UI
    process's own backend at this approval (see
    detect_display_backend); a session minted on Wayland must not
    accept approvals from an X11 GUI process and vice versa —
    callers enforce cross-session denial by comparing this record's
    backend with the session's mint backend (f14 F-20).

    Tier A: this record gates/audits Keyholder approvals.
    Tier B: it does not, by itself, stop direct store reads on
    Windows/Linux — the parity statement says so in the record.
    """
    plat = current_platform(platform)
    storage = storage_tier(plat, backend=storage_backend)
    approval = approval_tier(plat, mechanism=approval_mechanism)
    if backend_info is None:
        backend_info = detect_display_backend(
            toolkit_backend=toolkit_backend, env=env)
    backend = backend_info["backend"] if isinstance(backend_info, dict) else backend_info
    record: dict = {
        "platform": plat,
        "storage_tier": storage.tier,
        "storage_mechanism": storage.mechanism,
        "storage_label": display_label(storage),
        "same_user_direct_read": storage.same_user_direct_read,
        "approval_tier": approval.tier,
        "approval_mechanism": approval.mechanism,
        "approval_label": display_label(approval),
        "approval_boolean_only": approval.boolean_only,
        "session_type": backend,
        "display_backend": backend,
        "seat": seat,
        "remote": remote,
        "remote_coverage": remote_access_coverage(),
        "screen_sharing": screen_sharing_status(),
        "honest_parity_statement": HONEST_PARITY_STATEMENT,
        "tier_a": (
            "Tier A (interface-bound agent): storage and approval "
            "tiers above gate what Keyholder itself does."
        ),
        "tier_b": (
            "Tier B (shell-capable same-user agent): only macOS S1 "
            "Keychain ACLs narrow direct reads. On Windows/Linux, "
            "tiers control Keyholder-mediated use only."
        ),
    }
    if plat == "win32" and tpm is not None:
        record["tpm_domain"] = windows_tpm_domain_posture(
            tpm=tpm, domain_joined=bool(domain_joined))
    if plat == "win32" and domain_joined is not None and tpm is None:
        record["domain_joined"] = domain_joined
    return record


def unprovable_on_platform(platform: str | None = None) -> list[str]:
    """What cannot be proven on this platform (for W18 docs).

    Tier A/B: listing unprovable claims prevents a test run on one
    platform being cited as evidence for another platform's native
    behaviour. A mocked-platform test proves the gate logic only.
    """
    plat = current_platform(platform)
    table = {
        "linux": [
            "macOS Keychain per-app ACL behaviour",
            "macOS Touch ID / LAContext behaviour",
            "Windows Hello (biometric or PIN) behaviour",
            "Windows DPAPI / Credential Manager behaviour",
            "Windows Remote Credential Guard behaviour",
        ],
        "darwin": [
            "Linux polkit agent identity and action-install state",
            "Linux Secret Service lock state",
            "Linux Wayland/X11/XWayland backend state",
            "Windows Hello / DPAPI / Credential Manager behaviour",
        ],
        "win32": [
            "macOS Keychain / Touch ID behaviour",
            "Linux polkit agent identity and action-install state",
            "Linux Secret Service lock state",
            "Linux Wayland/X11/XWayland backend state",
        ],
    }
    return table[plat]


def tier_scope(control: str) -> dict:
    """Tier A vs Tier B scope for a named control (CONTRACT §10).

    Use in docs/README sections: every claimed control states which
    tier it survives. Unknown controls raise rather than defaulting
    to a reassuring answer.
    """
    table = {
        "macos_keychain_acl": (
            "Survives Tier B (per-app ACL, OS-enforced)."),
        "os_rendered_prompt": (
            "Survives Tier B as a boolean result (a fake dialog "
            "cannot forge it); typed strings within it do not."),
        "worker_sandbox_profile": (
            "Survives Tier B (OS-enforced sandbox)."),
        "file_permissions_0600": (
            "Does NOT survive Tier B. Never cite as Tier B evidence."),
        "file_stored_control_token": (
            "Does NOT survive Tier B. Never cite as Tier B evidence."),
        "peer_credential_check": (
            "Does NOT survive Tier B. Never cite as Tier B evidence."),
        "pairing_token": (
            "Does NOT survive Tier B. Never cite as Tier B evidence."),
        "hello_step_up_windows_linux": (
            "Tier A only for storage: gates Keyholder-mediated use; "
            "does NOT stop direct Credential Manager / keyring reads."),
        "polkit_gesture": (
            "Tier A only for storage: gates Keyholder-mediated use; "
            "does NOT stop direct keyring reads."),
        "kill_switch": (
            "Tier A only: kills Keyholder sessions; does not recall "
            "already-forwarded calls and does not revoke direct "
            "store reads."),
    }
    if control not in table:
        raise ValueError(f"unknown control for tier scoping: {control!r}")
    return {"control": control, "tier_scope": table[control]}
