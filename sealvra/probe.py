"""Sealvra W12 — probe: expiring per-model/per-surface matrix.

What the probe IS (v3 N-K2, f10 §3):
- A drift / misconfiguration detector. It proves that a canary-marked
  request *arrived* at the broker with the expected host, path, model
  ID and auth scheme, from a loopback source, for one (agent, build,
  surface, model, harness) cell.
- Verdicts carry the agent build + config hash they were verified
  against and EXPIRE on any change to either. Re-probe on model
  switch, config change, and agent upgrade.
- Continuous absence detection: an active agent session with zero
  proxy traffic over the window is "unverified", not "brokered".

What the probe is NOT (stated in every probe report):
- It does NOT prove routing for a malicious agent. A malicious agent
  holding a token can send one probe-shaped request through the proxy
  and then route real traffic direct. Never claim otherwise.
- There is NO single "brokered" badge for an agent with mixed cells.
  Cursor custom-model pass + built-in-model bypass = mixed, and the
  summary says so per cell.

Cursor case (v3 N-K3): Cursor Class M via override is REFUSED by
default in v0.1. Probing it uses a zero-scope, 5-minute, single-use
canary credential — NEVER the real session token, because entering a
token in Cursor's API Key field transmits it to Cursor's backend on
every request (final prompt construction happens there). The canary
is revoked before any real session is minted.

No real keys, no real vendor calls: all probe traffic in tests is
loopback mock traffic with TEST-ONLY canary values.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field

PROBE_DISCLAIMER = (
    "PROBE LIMIT: this probe attests ARRIVAL of a canary-marked request "
    "at the broker, NOT routing for a malicious agent. A malicious agent "
    "holding a token can pass the probe and then route real traffic "
    "direct to the vendor. This probe defeats benign misconfiguration "
    "and vendor drift only; it is not a security control against a "
    "malicious agent."
)

# Per-surface cells known from f10 §1, each probe-gated separately.
# "bypass_by_design" surfaces are documented, never probed-pass.
KNOWN_SURFACES = {
    "claude": ["chat", "subagent_spawn", "agent_teams"],
    "codex": ["chat", "post_config_rewrite"],
    "cursor": ["custom_model_override", "builtin_anthropic_model",
               "builtin_google_model", "tab_completion", "composer_apply"],
    "copilot": ["chat", "inline_completions", "pr_summary",
                "code_review", "remote_session"],
}
BYPASS_BY_DESIGN = {
    ("cursor", "builtin_anthropic_model"),
    ("cursor", "builtin_google_model"),
    ("cursor", "tab_completion"),
    ("cursor", "composer_apply"),
    ("copilot", "inline_completions"),
    ("copilot", "pr_summary"),
    ("copilot", "code_review"),
    ("copilot", "remote_session"),
}


@dataclass
class CanaryCredential:
    """Zero-scope probe credential. Never a real session token."""
    token: str
    created_at: float
    ttl_seconds: int = 300  # 5 minutes, v3 N-K2
    scope: str = "zero"
    single_use: bool = True
    _consumed: bool = False
    revoked: bool = False

    def is_valid(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return ((not self._consumed) and (not self.revoked)
                and (now - self.created_at <= self.ttl_seconds))

    def consume(self) -> None:
        if self._consumed:
            raise ValueError("canary credential is single-use and already consumed")
        self._consumed = True

    def revoke(self) -> None:
        """Revoke the canary. Cursor probe step 4: revoke BEFORE any
        real session is minted (v3 N-K2/N-K3). Revocation is terminal:
        a revoked canary is never valid again, consumed or not."""
        self.revoked = True


def assert_canary_revoked(canary: CanaryCredential) -> None:
    """Refuse to mint a real session until the probe canary is revoked."""
    if not canary.revoked:
        raise ValueError(
            "refusing to mint a real session: probe canary has not "
            "been revoked yet (revoke it first, then mint)")


def mint_canary_credential() -> CanaryCredential:
    return CanaryCredential(token="kh_canary_" + secrets.token_urlsafe(32),
                            created_at=time.time())


def require_canary_token(token: str) -> None:
    """Reject a real session token where a canary is required (f10 P4)."""
    if token.startswith("kh_sess_"):
        raise ValueError(
            "refusing to probe with a real session token; use a "
            "zero-scope 5-minute single-use canary credential instead")
    if not token.startswith("kh_canary_"):
        raise ValueError("probe credential must be a kh_canary_ canary")


# ---------------------------------------------------------------------------
# Probe log entry assertions (f10 P5/P6)
# ---------------------------------------------------------------------------

@dataclass
class ProbeRequest:
    agent: str
    build: str
    surface: str
    model: str
    harness: str
    config_hash: str
    canary_id: str
    upstream_host: str
    path: str
    model_id: str
    auth_scheme: str
    source_ip: str
    timestamp: float = field(default_factory=time.time)
    # Source assertion (f10 P6): tunneled=True means the request
    # arrived via forwarded headers / a tunnel, even if source_ip
    # looks like loopback. credential_kind must be "canary": a probe
    # entry made with a real session token is a failure (f10 P4),
    # not a pass, because the probe itself would have exposed it.
    tunneled: bool = False
    credential_kind: str = "canary"


def assert_probe_entry(request: ProbeRequest, expected_host: str,
                       expected_path: str, expected_model_id: str,
                       expected_auth_scheme: str) -> list:
    """Assert the probe log entry. Any mismatch = probe failure.

    Also asserts loopback source: a request arriving via a tunnel
    fails here even if everything else matches (f10 P6) — tunneled
    setups are the separately named 'remote endpoint mode', never a
    probe pass, and remote-mode consent never converts a tunneled
    probe entry into a pass. A probe entry made with a real session
    credential (not a canary) likewise fails.
    """
    failures = []
    if request.upstream_host != expected_host:
        failures.append("upstream host mismatch")
    if request.path != expected_path:
        failures.append("path mismatch")
    if request.model_id != expected_model_id:
        failures.append("model ID mismatch")
    if request.auth_scheme != expected_auth_scheme:
        failures.append("auth scheme mismatch")
    if request.source_ip not in ("127.0.0.1", "::1", "localhost"):
        failures.append(
            "source is not loopback (tunneled loopback setup: requires "
            "separately consented 'remote endpoint mode', not a probe pass)")
    if request.tunneled:
        failures.append(
            "request arrived tunneled (forwarded headers): tunneled "
            "loopback is the separately named 'remote endpoint mode', "
            "never a passing probe, even when consented")
    if request.credential_kind != "canary":
        failures.append(
            "probe entry used a non-canary credential; probes use "
            "zero-scope canaries only, never a real session token")
    if (request.agent, request.surface) in BYPASS_BY_DESIGN:
        failures.append("surface is bypass-by-design for this agent")
    return failures


# ---------------------------------------------------------------------------
# Verdicts: carry build + config hash, expire on change (f10 P3, N-K2)
# ---------------------------------------------------------------------------

@dataclass
class ProbeVerdict:
    agent: str
    build: str
    surface: str
    model: str
    harness: str
    config_hash: str
    status: str  # "pass" | "fail" | "unverified"
    canary_id: str
    created_at: float = field(default_factory=time.time)
    # Source the verdict was observed from. Only "loopback" may ever
    # carry a pass: a tunneled observation is the separately named
    # remote endpoint mode, never a probe pass (f10 P6).
    source: str = "loopback"

    def is_current(self, build: str, config_hash: str,
                   now: float | None = None,
                   max_age_seconds: float | None = None) -> bool:
        """Current only while build AND config hash are unchanged,
        and (when a max age is given) the verdict is not stale."""
        if self.build != build or self.config_hash != config_hash:
            return False
        if max_age_seconds is not None:
            now = time.time() if now is None else now
            if (now - self.created_at) > max_age_seconds:
                return False
        return True


@dataclass
class RemoteEndpointMode:
    """Separately named, separately consented tunneled mode (f10 P6).

    This is NOT a probe verdict and never appears as a probe pass.
    It records that the user knowingly chose a tunneled loopback
    setup, with its loopback guarantees void, under this exact name.
    Any other mode name is rejected: a misspelled or vague consent
    string must not accidentally authorise a tunnel.
    """
    mode_name: str
    consented: bool
    consented_at: float = field(default_factory=time.time)
    note: str = ("tunneled loopback: local-only reachability, no "
                 "internet exposure of the key-injecting endpoint, "
                 "and no token-traversal guarantees are void in this "
                 "mode; it is a separate threat review, not a probe")

    def __post_init__(self):
        if self.mode_name != "remote endpoint mode" or not self.consented:
            raise ValueError(
                "remote endpoint mode requires the exact mode name "
                "'remote endpoint mode' and explicit consent; "
                "anything else is not consent")


class ProbeMatrix:
    """(agent, build, surface, model, harness) -> verdict, per cell.

    There is deliberately no method returning a single boolean badge
    for an agent. :meth:`per_cell_status` is the summary; mixed cells
    are reported as mixed.
    """

    def __init__(self, verdict_ttl_seconds: float | None = None):
        # Optional time expiry on top of build/config expiry. None
        # (default) means verdicts expire only on build/config change,
        # preserving v0.1 behaviour; pass a TTL to also expire stale
        # verdicts (drift is continuous, f10 P3).
        self.verdict_ttl_seconds = verdict_ttl_seconds
        self._cells: dict = {}

    @staticmethod
    def _key(agent, surface, model, harness):
        return (agent, surface, model, harness)

    def record(self, verdict: ProbeVerdict) -> None:
        """Record a verdict. Guards against dishonest passes.

        A pass observed from a non-loopback source, or a pass for a
        bypass-by-design surface, is refused outright — it must
        never sit in the matrix looking like a verified cell.
        """
        if verdict.status == "pass" and verdict.source != "loopback":
            raise ValueError(
                "refusing to record a passing probe verdict from a "
                "non-loopback source; tunneled setups are the "
                "separately named 'remote endpoint mode', never a pass")
        if verdict.status == "pass" and (
                verdict.agent, verdict.surface) in BYPASS_BY_DESIGN:
            raise ValueError(
                "refusing to record a passing probe verdict for a "
                "bypass-by-design surface %s/%s"
                % (verdict.agent, verdict.surface))
        self._cells[self._key(verdict.agent, verdict.surface,
                              verdict.model, verdict.harness)] = verdict

    def get(self, agent, surface, model, harness) -> ProbeVerdict | None:
        return self._cells.get(self._key(agent, surface, model, harness))

    def per_cell_status(self, agent: str, build: str,
                        config_hash: str, now: float | None = None,
                        max_age_seconds: float | None = None) -> dict:
        """Cell -> 'pass' / 'fail' / 'unverified' / 'expired'."""
        effective_age = (max_age_seconds if max_age_seconds is not None
                         else self.verdict_ttl_seconds)
        out = {}
        for (ag, surface, model, harness), verdict in self._cells.items():
            if ag != agent:
                continue
            if not verdict.is_current(build, config_hash, now=now,
                                      max_age_seconds=effective_age):
                out[(surface, model, harness)] = "expired"
            else:
                out[(surface, model, harness)] = verdict.status
        return out

    def is_fully_verified(self, agent: str, build: str,
                          config_hash: str, cells: list,
                          now: float | None = None,
                          max_age_seconds: float | None = None) -> bool:
        """True only if EVERY listed cell is currently passing."""
        effective_age = (max_age_seconds if max_age_seconds is not None
                         else self.verdict_ttl_seconds)
        for (surface, model, harness) in cells:
            verdict = self.get(agent, surface, model, harness)
            if verdict is None or verdict.status != "pass":
                return False
            if not verdict.is_current(build, config_hash, now=now,
                                      max_age_seconds=effective_age):
                return False
        return True


# ---------------------------------------------------------------------------
# Continuous absence detection (f10 P1(c), v3 N-K2)
# ---------------------------------------------------------------------------

class AbsenceDetector:
    """Agent active + zero proxy traffic over the window = 'unverified'."""

    def __init__(self, window_seconds: float = 300):
        self.window_seconds = window_seconds
        self._last_traffic: dict = {}
        self._active: set = set()

    def mark_active(self, session_id: str) -> None:
        self._active.add(session_id)

    def mark_inactive(self, session_id: str) -> None:
        self._active.discard(session_id)

    def record_traffic(self, session_id: str, at: float | None = None) -> None:
        self._last_traffic[session_id] = time.time() if at is None else at

    def status(self, session_id: str, now: float | None = None) -> str:
        now = time.time() if now is None else now
        if session_id not in self._active:
            return "inactive"
        last = self._last_traffic.get(session_id)
        if last is None or (now - last) > self.window_seconds:
            return "unverified"  # active + zero proxy traffic
        return "verified_traffic_seen"


# ---------------------------------------------------------------------------
# Cursor Class M gate (v3 N-K3)
# ---------------------------------------------------------------------------

def cursor_class_m_allowed(backend_transmission_consent: bool = False) -> bool:
    """Cursor Class M via override: REFUSED by default in v0.1.

    Only an explicit, separate backend-transmission consent (the user
    understanding the token goes to Cursor's servers) overturns the
    refusal — and even then only with a canary-first probe.
    Kept for compatibility; new callers should use
    :func:`cursor_class_m_decision`, which also gates on plan and
    per-model routing instead of consent alone.
    """
    return bool(backend_transmission_consent)


CURSOR_BACKEND_TRANSMISSION_WARNING = (
    "WARNING: a token entered in Cursor's API Key field is sent with "
    "every request to Cursor's backend, because final prompt "
    "construction happens there. The token leaves this machine by "
    "design on this path; killing the session stops future use but "
    "cannot un-disclose a value already sent to the vendor (f10 B5, "
    "v3 N-K3). Never enter a real session token here — probe with a "
    "zero-scope canary first, revoke it, and only then decide."
)

# Free-plan gating (f10 U2, v3 N-K3): since January 2026 Cursor
# ignores a user's own keys on the Free plan, so an override on
# Free silently no-injects. Plans other than "free" are treated as
# paid only when explicitly named; an unconfirmed plan gates, it
# never defaults to "brokered".
_CURSOR_PAID_PLANS = {"pro", "business", "enterprise", "team", "ultra"}
_CURSOR_BYPASS_SURFACES = {"tab_completion", "composer_apply",
                           "tab", "apply"}


def classify_cursor_model(model_id: str) -> str:
    """Route class for one Cursor model ID (f10 U5, v3 N-K3).

    - "builtin_anthropic_bypass" / "builtin_google_bypass": built-in
      Anthropic/Google IDs NEVER use the override — traffic goes to
      Cursor's channel, invisible to the broker, while the override
      still shows as "on".
    - "cursor_own_via_override": Cursor's own models are swept to
      the override endpoint while it is on (global override).
    - "custom_via_override": a custom model name routes via override.
    - "unknown_probe_required": empty/unrecognised IDs are never
      assumed brokered; they need their own probe cell.
    Prefix rules are a heuristic from vendor docs at audit time and
    must be re-probed per build; they are not a routing guarantee.
    """
    model = (model_id or "").strip().lower()
    if not model:
        return "unknown_probe_required"
    if model.startswith("claude-") or model.startswith("anthropic/"):
        return "builtin_anthropic_bypass"
    if model.startswith("gemini-") or model.startswith("gemma-") \
            or model.startswith("google/"):
        return "builtin_google_bypass"
    if model.startswith("cursor-") or model in ("composer",):
        return "cursor_own_via_override"
    return "custom_via_override"


@dataclass
class CursorClassMDecision:
    allowed: bool
    routing: str  # "via_override" | "bypass_by_design" | "ignored_by_plan"
                  # | "gated" (consent/plan/canary still missing)
    reason: str
    warning: str | None  # backend-transmission warning, when relevant
    requires_canary_probe: bool = False


def cursor_class_m_decision(model_id: str, plan: str | None = None,
                            surface: str | None = None,
                            backend_transmission_consent: bool = False,
                            canary_probed: bool = False) -> CursorClassMDecision:
    """Honest gate for Cursor Class M via override (f10 B4/B5/U2).

    Refusal order, fail-closed at every step — never a silent
    no-inject presented as brokered:
    1. Free plan -> refused (own keys ignored, U2).
    2. Unconfirmed plan -> gated (cannot claim brokered).
    3. Bypass surface (Tab/Apply/Composer) or built-in
       Anthropic/Google model -> refused as bypass-by-design (B4).
    4. No backend-transmission consent -> refused (B5).
    5. Consent but no passing canary probe -> gated (canary first).
    6. All gates passed -> allowed via override, WITH the
       backend-transmission warning still attached: allowing the
       path does not make the token stay local.
    """
    if plan is not None and plan.strip().lower() == "free":
        return CursorClassMDecision(
            False, "ignored_by_plan",
            "refused: Cursor ignores a user's own keys on the Free "
            "plan (since Jan 2026), so the override would silently "
            "no-inject; never present this as brokered",
            CURSOR_BACKEND_TRANSMISSION_WARNING)
    if plan is None or plan.strip().lower() not in _CURSOR_PAID_PLANS:
        return CursorClassMDecision(
            False, "gated",
            "gated: Cursor plan is unconfirmed, and the Free plan "
            "ignores own keys; confirm a paid plan before any "
            "brokered claim for this path",
            CURSOR_BACKEND_TRANSMISSION_WARNING)
    if surface is not None and surface.strip().lower() in _CURSOR_BYPASS_SURFACES:
        return CursorClassMDecision(
            False, "bypass_by_design",
            "refused: %s requires Cursor's own models and does not "
            "work with custom keys regardless of configuration"
            % surface,
            None)
    routing = classify_cursor_model(model_id)
    if routing in ("builtin_anthropic_bypass", "builtin_google_bypass"):
        return CursorClassMDecision(
            False, "bypass_by_design",
            "refused: built-in %s model %r never uses the override; "
            "its traffic goes to Cursor's channel, invisible to the "
            "broker, while the override still shows as 'on'"
            % ("Anthropic" if "anthropic" in routing else "Google",
               model_id),
            None)
    if routing == "unknown_probe_required":
        return CursorClassMDecision(
            False, "gated",
            "gated: model %r is unrecognised; it needs its own probe "
            "cell before any brokered claim" % model_id,
            CURSOR_BACKEND_TRANSMISSION_WARNING)
    if not backend_transmission_consent:
        return CursorClassMDecision(
            False, "gated",
            "refused by default: entering a token in Cursor's API "
            "Key field sends it to Cursor's backend on every "
            "request; separate backend-transmission consent is "
            "required, and even then only with a canary-first probe",
            CURSOR_BACKEND_TRANSMISSION_WARNING,
            requires_canary_probe=True)
    if not canary_probed:
        return CursorClassMDecision(
            False, "gated",
            "gated: backend-transmission consent recorded, but the "
            "canary probe has not passed; do not mint a real "
            "session until it has, and revoke the canary first",
            CURSOR_BACKEND_TRANSMISSION_WARNING,
            requires_canary_probe=True)
    return CursorClassMDecision(
        True, "via_override",
        "allowed via override for this custom/cursor-own model "
        "only; built-in Anthropic/Google models and Tab/Apply/"
        "Composer remain bypass-by-design, and the token still "
        "travels to Cursor's backend on this path",
        CURSOR_BACKEND_TRANSMISSION_WARNING)


def cursor_probe_plan() -> dict:
    """Canary-first probe plan for the Cursor override path."""
    return {
        "step_1": "mint zero-scope 5-minute single-use canary credential",
        "step_2": "enter ONLY the canary in Cursor's API Key field; "
                  "never the real session token",
        "step_3": "verify canary arrival at the proxy with expected "
                  "host/path/model/auth + loopback source",
        "step_4": "revoke the canary BEFORE minting any real session",
        "step_5": "per-model probe: custom model pass does NOT cover "
                  "built-in Anthropic/Google models (they never use the "
                  "override) — each model is its own matrix cell",
        "refusal_default": "Cursor Class M via override is refused in "
                           "v0.1 unless separately consented (N-K3)",
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def format_probe_report(matrix: ProbeMatrix, agent: str, build: str,
                        config_hash: str) -> str:
    """Per-cell report. Always carries the arrival-not-routing limit."""
    lines = [PROBE_DISCLAIMER, "",
             "probe report: agent=%s build=%s" % (agent, build)]
    cells = matrix.per_cell_status(agent, build, config_hash)
    if not cells:
        lines.append("no probe cells recorded: status unverified")
    for (surface, model, harness), status in sorted(cells.items()):
        lines.append("  %s / %s / %s: %s" % (surface, model, harness, status))
    lines.append("note: verdicts expire on agent-build or config-hash change; "
                 "re-probe on model switch, config change, and upgrade.")
    return "\n".join(lines)
