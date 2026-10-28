"""Shared types for Keyholder v0.1 (W01-owned, CONTRACT §2).

Normative shapes: names and fields below match CONTRACT §2 exactly.
Extra fields are optional (defaulted) so other workers' imports keep
working; no token or PoP key ever appears in any dataclass here.

Threat-tier honesty (CONTRACT §10 / v3 §1A): nothing in this module
is a Tier B control. In-memory-only storage is a Tier A control; it
does not separate same-user (Tier B) processes.

No real keys/tokens/credentials anywhere in this file; test fixtures
use ``TEST-ONLY-`` prefixed values only.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Literal

Provider = Literal["github", "gemini"]
SessionClass = Literal["destructive", "write", "read_account", "read_public"]
Transport = Literal["absolute", "connect_allowed"]

# ---------------------------------------------------------------- TTL (§3)
# R07 table, the ONLY table (v3 §1B N-B1). Absolute hard cap 2 h for
# everything. Idle: 5 min default, range 2-15 min, cannot be disabled;
# refreshed ONLY by a successful proxied call (CONTRACT §3).
TTL_TABLE: dict[str, tuple[int, int]] = {
    "destructive": (10 * 60, 15 * 60),
    "write": (20 * 60, 30 * 60),
    "read_account": (30 * 60, 60 * 60),
    "read_public": (60 * 60, 120 * 60),
}
ABSOLUTE_TTL_CAP_S = 2 * 60 * 60
IDLE_DEFAULT_S = 5 * 60
IDLE_MIN_S = 2 * 60
IDLE_MAX_S = 15 * 60

# Token format (CONTRACT §4): "kh_sess_" + token_urlsafe(32). Only the
# SHA-256 hex digest is ever stored; see broker.py.
SESSION_TOKEN_PREFIX = "kh_sess_"
POP_TIMESTAMP_MAX_SKEW_S = 300

# Error catalogue (CONTRACT §9): same event = same code on every surface.
ERROR_CODES: dict[str, tuple[str, int]] = {
    "KH-1001": ("vault locked", 1),
    "KH-1002": ("session not found/expired/killed", 2),
    "KH-1003": ("policy denied", 2),
    "KH-1004": ("approval denied/timeout", 2),
    "KH-1005": ("audit unavailable", 3),
    "KH-1006": ("provider/upstream error", 1),
    "KH-2001": ("invalid input/usage", 1),
    "KH-3001": ("platform unsupported for this action", 1),
    "KH-3002": ("isolation/proof failure", 3),
    "KH-3003": ("secret detected in log", 3),
}


def ttl_for(session_class: SessionClass) -> tuple[int, int]:
    """Return (default_seconds, cap_seconds) for a session class."""
    return TTL_TABLE[session_class]


def clamp_ttl(session_class: SessionClass, requested: int | None) -> int:
    """Clamp a requested TTL to [default-if-None, class cap, 2 h cap]."""
    default, cap = ttl_for(session_class)
    if requested is None:
        return default
    return max(1, min(int(requested), cap, ABSOLUTE_TTL_CAP_S))


def clamp_idle(requested: int | None) -> int:
    """Clamp idle timeout to [2 min, 15 min]; default 5 min."""
    if requested is None:
        return IDLE_DEFAULT_S
    return max(IDLE_MIN_S, min(int(requested), IDLE_MAX_S))


def wall_now() -> float:
    return time.time()


@dataclass
class KeyRecord:
    key_id: str  # "key-<16 hex chars from secrets.token_hex(8)>"
    provider: Provider
    label: str  # user-chosen, never shown in global audit entries
    created_at: str  # UTC ISO-8601
    compartment_version: int = 1
    # NOTE: the real key value is NEVER stored in a KeyRecord, never
    # logged, never returned by any API. It lives only in a vault
    # compartment and in worker memory during a session.


@dataclass
class Session:
    session_id: str  # "sess-<16 hex>" (internal id, NOT the token)
    key_id: str  # exactly one key_id, never a list
    provider: Provider
    session_class: SessionClass
    transport: Transport
    created_at: float  # wall-clock epoch
    expires_at: float  # wall-clock epoch; absolute, never sliding
    idle_deadline: float  # refreshed only by successful proxied calls
    process_group: str  # agent process-group identifier for kill binding
    ancestry: str  # free-text process ancestry recorded in audit
    killed: bool = False
    # Optional monotonic counterpart to created_at (CONTRACT §2 says
    # both monotonic and wall clock are recorded; wall clock is the
    # authoritative field above). Token and PoP key are NOT fields
    # here. They live only in broker memory. Any code that puts them
    # in a dataclass, file, log, or repr is a security bug.
    created_mono: float = 0.0


@dataclass
class PolicyDecision:
    allowed: bool
    level: int  # 1 allow, 2 allow-with-log, 3 approve, 4 deny
    reason: str
    rule_id: str | None


@dataclass
class ApprovalRequest:
    approval_id: str
    session_pseudonym: str
    provider: Provider
    method: str
    path: str  # canonical path, never raw bytes
    scope_summary: str  # permissions AND purpose, never agent free text
    created_at: float


@dataclass
class KillReceipt:
    """Kill receipt (CONTRACT §3 / v3 §1B N-B4).

    Already-forwarded calls are NOT recalled: they run to completion
    and are listed here. ``in_flight_at_kill`` is the snapshot taken
    at kill invocation; ``completed_during_kill`` is the subset that
    finished within the teardown window; anything still running at
    receipt time is listed in ``still_running_at_receipt`` (never
    silently dropped).
    """

    session_id: str
    killed_at: float
    deny_listed_at: float
    deny_list_latency_s: float
    teardown_s: float
    teardown_within_5s: bool
    workers_terminated: list[str] = field(default_factory=list)
    in_flight_at_kill: list[str] = field(default_factory=list)
    completed_during_kill: list[str] = field(default_factory=list)
    still_running_at_receipt: list[str] = field(default_factory=list)
    port_released: bool | None = None


@dataclass
class DaemonStatus:
    running: bool
    pid: int | None
    socket_path: str | None
    session_count: int
    started_at: float | None
    loopback_only: bool = True
    # v0.2 (§13.1): daemon stop kills all sessions/workers, so a
    # cross-process stop reports sessions_killed=True. In-process
    # v0.1-style status leaves this None (unknown/not reported).
    sessions_killed: bool | None = None
