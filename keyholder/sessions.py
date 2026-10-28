"""In-memory session store for Keyholder v0.1 (W03).

Normative sources: CONTRACT.md §2–§4 and plan v3 §1B (N-B1–N-B7) and
§1C (N-C1–N-C3). Where v1/v2 disagree with v3, v3 wins; deleted v1/v2
passages (session extensions, multi-key sessions, fixed session
directories, on-disk tokens/PoP keys) are never built here.

Rules enforced by this module:

* In memory only. A reboot (a new store, a dead daemon) revokes every
  session: there is no persistence, no resurrection, and no method that
  saves or reloads a session, token, or PoP key.
* One session = one key, at schema level. ``key_id`` is a single string;
  a list/tuple/dict is rejected, so a multi-key session is
  unconstructable through this API.
* TTL table (the ONLY table): destructive 10/15 min, write 20/30,
  read_account 30/60, read_public 60/120 (default/cap, minutes).
  Absolute hard cap: 2 hours for everything. A requested TTL above the
  class cap — or above 2 h — is rejected, never clamped silently.
* Idle timeout: 5 min default, range 2–15 min, cannot be disabled.
  The idle deadline is reset ONLY by a successful proxied call
  (``record_successful_call``). Denied calls and status polls do not
  reset it; the corresponding methods are explicit no-ops so a caller
  cannot reset idle by accident.
* NO extensions, ever. There is no ``extend`` method on any class here;
  re-issuance is a brand-new session (fresh token, fresh PoP key,
  fresh gesture by the caller). Any test asserting this checks
  ``hasattr(store, "extend")`` is False.
* Tokens/PoP keys live in memory only, delivered in-process. The broker
  stores only the SHA-256 hex of the token (see tokens.py). Session
  temp dirs use ``tempfile.mkdtemp`` and are deleted on session end;
  this module never writes a token or PoP key into them (it writes
  nothing into them at all).
* Kill: once ``kill`` returns, the session token is denied immediately
  (deny-list effect, well within the ≤1 s bound — it is synchronous),
  the temp dir is removed and secrets zeroed before return (teardown,
  within the ≤5 s bound). Already-forwarded calls are NOT recalled:
  calls in flight at kill time are snapshotted onto the kill receipt
  and run to completion by their owner. ``kill_all`` snapshots the
  session list at invocation; sessions created during the sweep are
  not silently included or excluded — they are simply not in the
  snapshot, and the receipt lists exactly the snapshot.
* Expiry drain: reads/idempotent calls get up to 60 s of drain;
  destructive writes and streams terminate at expiry (0 s drain).
  This module reports the drain window; terminating streams is the
  proxy's job (W04) using :func:`expiry_drain_seconds`.
* Classification is by capability, highest class wins
  (see :func:`classify`). Paid inference is write class; "financial"
  applies to money/billing only and floors a call at write class.
  The provider pack (W05) refines this; this helper is the shared
  capability floor the policy engine uses.

Error codes (contract §9): dead/expired/killed sessions report
``KH-1002``; invalid session-creation input reports ``KH-2001``.
Denials to the agent carry no rule_id or category (those go to the
audit log, owned by W09, not here).

Shared types come from W01's ``keyholder.types`` (contract §2), which
this module imports and re-exports: :class:`Session` below subclasses
the W01 Session, adding only the two fields this module needs that
contract §2 does not name — ``idle_seconds`` (to enforce the idle
rule) and ``temp_dir`` (to clean the session up) — and
:class:`KillReceipt` is the W01 receipt shape, populated with the
in-flight snapshot at kill time. Token and PoP key are NOT fields on
Session, by design: they live only in the store's private maps.
Note one deliberate divergence from W01 helpers: W01's ``clamp_ttl``
/ ``clamp_idle`` silently clamp out-of-range values, but contract §3
/ v3 N-B1 as assigned to W03 require REJECTION of over-cap TTLs and
out-of-range idle values, so this module validates and raises instead
of clamping. If types.py is ever absent, local fallback definitions
with the same field names are used.

Tier note (contract §10): in-memory storage plus process-group kill
binding holds against Tier A. It is not claimed as Tier B separation:
a shell-capable same-user process can read broker memory. OS-level
separation is owned by other workers.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any

try:  # W01-owned shared types (contract §2); fallback if absent.
    from .types import (
        ABSOLUTE_TTL_CAP_S,
        IDLE_DEFAULT_S,
        IDLE_MAX_S,
        IDLE_MIN_S,
        TTL_TABLE as _W01_TTL_TABLE,
    )
    from .types import KillReceipt as _W01KillReceipt
    from .types import Session as _W01Session

    _HAS_TYPES = True
except ImportError:  # pragma: no cover - types.py is present in the build
    _HAS_TYPES = False

from .tokens import (
    TOKEN_PREFIX,
    generate_pop_key,
    generate_token,
    hash_token,
    verify_pop,
    verify_token,
    zero_secret,
)

PROVIDERS = ("github", "gemini")
SESSION_CLASSES = ("destructive", "write", "read_account", "read_public")
TRANSPORTS = ("absolute", "connect_allowed")

if _HAS_TYPES:
    TTL_TABLE = dict(_W01_TTL_TABLE)
    ABSOLUTE_HARD_CAP_SECONDS = ABSOLUTE_TTL_CAP_S
    IDLE_DEFAULT_SECONDS = IDLE_DEFAULT_S
    IDLE_MIN_SECONDS = IDLE_MIN_S
    IDLE_MAX_SECONDS = IDLE_MAX_S
    KillReceipt = _W01KillReceipt
else:  # fallback definitions, same field names as W01 types.py
    TTL_TABLE: dict[str, tuple[int, int]] = {
        "destructive": (10 * 60, 15 * 60),
        "write": (20 * 60, 30 * 60),
        "read_account": (30 * 60, 60 * 60),
        "read_public": (60 * 60, 120 * 60),
    }
    ABSOLUTE_HARD_CAP_SECONDS = 2 * 60 * 60
    IDLE_DEFAULT_SECONDS = 5 * 60
    IDLE_MIN_SECONDS = 2 * 60
    IDLE_MAX_SECONDS = 15 * 60

    @dataclass
    class _FallbackSession:  # type: ignore[no-redef]
        session_id: str
        key_id: str
        provider: str
        session_class: str
        transport: str = "absolute"
        created_at: float = 0.0
        expires_at: float = 0.0
        idle_deadline: float = 0.0
        process_group: str = ""
        ancestry: str = ""
        killed: bool = False
        created_mono: float = 0.0

    _W01Session = _FallbackSession  # type: ignore[assignment]

    @dataclass
    class KillReceipt:  # type: ignore[no-redef]
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

EXPIRY_DRAIN_READ_SECONDS = 60  # reads/idempotent only. v3 N-B5.

ERR_SESSION_DEAD = "KH-1002"  # session not found / expired / killed
ERR_INVALID_INPUT = "KH-2001"  # invalid input / usage

# -- v0.2 lifecycle hardening (W13): sleep-aware clocks, quarantine,
# suspend/resume, kill reconciliation, rotation journal, freeze,
# console-grant linkage (v3 §1F N-F1/N-F2/N-F4/N-F5/N-F6, f05).
# Plain time.monotonic() is FORBIDDEN for sleep-accounting timers:
# it stops during suspend on Linux/macOS, so a laptop that sleeps
# 8 h would show ~0 elapsed time and sleep thresholds could never
# fire. All TTL arithmetic still uses UTC epoch (time.time()), so a
# DST fallback can never suspend everything (f05 L-06).
CLOCK_BOOTTIME = getattr(time, "CLOCK_BOOTTIME", None)
CLOCK_JUMP_THRESHOLD_S = 60  # cumulative wall/sleep-aware divergence
SLEEP_KILL_AFTER_S = 3600  # >1 h slept kills sessions (v3 K6)
LOCK_KILL_AFTER_S = 900  # >15 min locked kills sessions (v3 K4)
CONSOLE_GRANT_MAX_S = 2 * 60 * 60  # 2 h absolute cap, all grants
MACOS_SLEEP_CLOCK_DESIGN = (
    "macOS sleep-aware clock (DESIGN ONLY, never claimed run on macOS "
    "in v0.2; this build runs on Linux): mach_continuous_time from "
    "libSystem, which includes sleep — NOT mach_absolute_time, which "
    "excludes sleep. On Linux the equivalent is CLOCK_BOOTTIME, "
    "implemented below. On Windows the equivalent is "
    "QueryPerformanceCounter, which includes sleep."
)


def sleep_aware_clock_name() -> str:
    """Name of the sleep-aware clock for this platform (v3 N-F1)."""
    if sys.platform == "darwin":
        return "mach_continuous_time (design only, not run)"
    if CLOCK_BOOTTIME is not None:
        return "CLOCK_BOOTTIME"
    return "time.monotonic (NOT sleep-aware)"


def sleep_aware_available() -> bool:
    """True only when a real sleep-aware clock exists on this machine."""
    return CLOCK_BOOTTIME is not None


def sleep_aware_monotonic() -> float:
    """Sleep-aware monotonic reading: CLOCK_BOOTTIME on Linux, plain
    monotonic elsewhere (flagged NOT sleep-aware by the name above;
    never silently claimed as sleep-aware)."""
    if CLOCK_BOOTTIME is not None:
        return time.clock_gettime(CLOCK_BOOTTIME)
    return time.monotonic()


def estimate_sleep_seconds(
    wall_before: float, wall_after: float, mono_before: float, mono_after: float
) -> float:
    """Estimate sleep from a suspend/wake pair: wall clock advances
    across sleep, plain monotonic does not, so the difference is the
    sleep duration (floored at 0). Pure function, unit-testable."""
    return max(0.0, (wall_after - wall_before) - (mono_after - mono_before))


def cross_check_sleep_delta(wall_delta: float, sleep_aware_delta: float) -> float:
    """Cross-check (f05 L-07): wall delta minus sleep-aware delta.
    Near zero when the sleep-aware clock is behaving; a large value
    means one of the clocks cannot be trusted for this interval."""
    return wall_delta - sleep_aware_delta


class ClockSanity:
    """Cumulative clock-jump detector (v3 N-F2, f05 L-06).

    The baseline is fixed at enable time, never slid forward, so
    gradual sub-threshold drift accumulates and trips the >60 s
    threshold instead of being absorbed step by step. Any backward
    wall-clock movement fails immediately. Comparisons use UTC
    epoch only (time.time()), never local time, so DST is inert.
    Plain-monotonic divergence is NOT checked here: it is expected
    after sleep (monotonic excludes sleep) and is the input to
    estimate_sleep_seconds instead.
    """

    def __init__(
        self,
        baseline_wall: float,
        baseline_sleep_aware: float | None = None,
    ) -> None:
        self._base_wall = float(baseline_wall)
        self._base_sleep = (
            None if baseline_sleep_aware is None else float(baseline_sleep_aware)
        )
        self._last_wall = float(baseline_wall)

    def check(
        self, now_wall: float, sleep_aware_now: float | None = None
    ) -> tuple[bool, str]:
        now_wall = float(now_wall)
        if now_wall < self._last_wall:
            return False, "wall clock moved backward"
        if (
            sleep_aware_now is not None
            and self._base_sleep is not None
        ):
            divergence = abs(
                (now_wall - self._base_wall)
                - (float(sleep_aware_now) - self._base_sleep)
            )
            if divergence > CLOCK_JUMP_THRESHOLD_S:
                return (
                    False,
                    f"cumulative wall/sleep-aware divergence "
                    f"{divergence:.1f}s exceeds {CLOCK_JUMP_THRESHOLD_S}s",
                )
        self._last_wall = now_wall
        return True, "ok"


@dataclass
class SuspendReceipt:
    """What suspension did to in-flight calls (f05 L-08): destructive
    and write calls are aborted (the proxy must terminate them);
    read calls may drain for at most 60 s past suspension."""

    suspended_at: float
    reason: str
    session_ids: list[str] = field(default_factory=list)
    aborted_call_ids: list[str] = field(default_factory=list)
    draining_call_ids: list[str] = field(default_factory=list)
    drain_until: float | None = None


@dataclass
class WakeEvaluation:
    """Result of evaluating one wake event after quarantine lifts."""

    sleep_seconds: float
    action: str  # "none" | "suspend_all" | "kill_all"
    killed_session_ids: list[str] = field(default_factory=list)
    suspended_session_ids: list[str] = field(default_factory=list)


@dataclass
class GrantRevocation:
    """Revoking a console grant stops NEW issuance under it but does
    NOT silently kill derived sessions (f05 L-21): the derived live
    sessions are listed, and the caller must kill them explicitly
    (see revoke_grant_and_kill) or accept their continued life."""

    grant_id: str
    revoked_at: float
    derived_live_session_ids: list[str] = field(default_factory=list)
    derived_killed_session_ids: list[str] = field(default_factory=list)


@dataclass
class ConsoleGrant:
    """Session-side console-grant record (v3 N-E12, f05 L-21).

    This is the lifecycle linkage only (scope frozen at creation,
    2 h max, single start, non-destructive, seat-verified, suspend
    on lock, dead after 15 min locked / 1 h slept). The approval
    ceremony itself lives in approval.py (W02/W14), which this module
    does not duplicate or override."""

    grant_id: str
    key_id: str
    scope: str  # frozen at creation; preset edits never widen it
    duration_s: int
    created_at: float
    seat_verified: bool = True
    started: bool = False
    revoked: bool = False
    status: str = "live"  # live | suspended | dead

    @property
    def expires_at(self) -> float:
        return self.created_at + self.duration_s


def validate_console_grant(
    duration_s: int, destructive: bool, seat_verified: bool
) -> None:
    """Enforce console-grant rules; raises SessionError (KH-2001)."""
    if destructive:
        raise SessionError(
            "console grants are never destructive", ERR_INVALID_INPUT
        )
    if not isinstance(duration_s, int) or isinstance(duration_s, bool):
        raise SessionError("grant duration must be an integer", ERR_INVALID_INPUT)
    if duration_s <= 0 or duration_s > CONSOLE_GRANT_MAX_S:
        raise SessionError(
            f"console grant duration must be > 0 and <= 2 h "
            f"({CONSOLE_GRANT_MAX_S}s)",
            ERR_INVALID_INPUT,
        )
    if not seat_verified:
        raise SessionError(
            "console grant requires a verified local seat", ERR_INVALID_INPUT
        )


ROTATION_STEPS = (
    "INTENT",
    "PROVIDER_REVOKED",
    "NEW_KEY_STORED",
    "COMPLETE",
    "ABORTED",
)


def _fsync_dir(directory: str) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class RotationJournal:
    """Crash-safe rotation journal (v3 N-F4, f05 L-16).

    A fsynced INTENT record is written BEFORE provider revocation, so
    a crash after revocation but before the replacement is stored
    leaves a recoverable record instead of limbo (old key dead, no
    replacement). The journal stores key_ids and step names ONLY —
    never key material, never tokens, never PoP keys. Callers must
    not pass secrets in ``detail``.
    """

    def __init__(self, directory: str) -> None:
        os.makedirs(directory, exist_ok=True)
        self._path = os.path.join(directory, "rotation-journal.jsonl")

    def record(self, key_id: str, step: str, detail: str = "") -> dict:
        if step not in ROTATION_STEPS:
            raise SessionError(f"unknown rotation step: {step!r}", ERR_INVALID_INPUT)
        entry = {
            "key_id": key_id,
            "step": step,
            "detail": detail,
            "ts": time.time(),
        }
        with open(self._path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        _fsync_dir(os.path.dirname(self._path))
        return entry

    def records(self, key_id: str | None = None) -> list[dict]:
        if not os.path.exists(self._path):
            return []
        out: list[dict] = []
        with open(self._path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if key_id is None or entry.get("key_id") == key_id:
                    out.append(entry)
        return out

    def recovery_status(self, key_id: str) -> dict:
        """Clean iff no records, or the last record is COMPLETE or
        ABORTED; otherwise interrupted at the last recorded step."""
        recs = self.records(key_id)
        if not recs:
            return {"state": "clean", "interrupted_at_step": None, "key_id": key_id}
        last = recs[-1]["step"]
        if last in ("COMPLETE", "ABORTED"):
            return {"state": "clean", "interrupted_at_step": None, "key_id": key_id}
        return {
            "state": "interrupted",
            "interrupted_at_step": last,
            "key_id": key_id,
            "resume": "store a new key, then record NEW_KEY_STORED and COMPLETE",
            "abort": "record ABORTED and freeze the key (old key is known-dead)",
        }

    def complete(self, key_id: str) -> dict:
        return self.record(key_id, "COMPLETE")

    def abort(self, key_id: str) -> dict:
        return self.record(key_id, "ABORTED")


class FreezeStore:
    """Persisted freeze state (v3 N-F5, f05 L-15): a frozen key stays
    frozen across daemon restart — in-memory-only freeze silently
    clearing on restart is deleted as a behaviour. Written via
    temp file + fsync + rename + directory fsync. Stores key_ids
    only, never key material."""

    def __init__(self, directory: str) -> None:
        os.makedirs(directory, exist_ok=True)
        self._path = os.path.join(directory, "frozen-keys.json")
        self._frozen: dict[str, str] = {}
        if os.path.exists(self._path):
            with open(self._path, encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, dict):
                raise ValueError("frozen-keys file is corrupt: not an object")
            self._frozen = {str(k): str(v) for k, v in data.items()}

    def _save(self) -> None:
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._frozen, fh, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self._path)
        _fsync_dir(os.path.dirname(self._path))

    def freeze(self, key_id: str, reason: str = "") -> None:
        self._frozen[key_id] = reason
        self._save()

    def unfreeze(self, key_id: str) -> None:
        self._frozen.pop(key_id, None)
        self._save()

    def is_frozen(self, key_id: str) -> bool:
        return key_id in self._frozen

    def frozen_keys(self) -> list[str]:
        return sorted(self._frozen)


class SessionError(ValueError):
    """Invalid session input or dead session. ``code`` is KH-1002/KH-2001."""

    def __init__(self, message: str, code: str = ERR_INVALID_INPUT):
        super().__init__(message)
        self.code = code


@dataclass
class Session(_W01Session):  # type: ignore[valid-type,misc]
    """One session, one key (W01 fields + W03-only extras).

    Token and PoP key are NOT stored here. ``temp_dir`` is a scratch
    directory only; it never holds a token or PoP key."""

    idle_seconds: int = IDLE_DEFAULT_SECONDS
    temp_dir: str = ""
    # v0.2 lifecycle state (W13): suspended sessions are NOT live,
    # but are NOT dead either — they resume only via resume_session
    # with system auth (never by unlock alone, never by one click).
    suspended: bool = False
    suspended_reason: str = ""
    suspended_at: float = 0.0
    grant_id: str = ""  # console grant this session was derived from, if any


@dataclass
class KillAllReceipt:
    """Snapshot semantics: exactly the sessions listed here were killed."""

    killed_at: float
    killed_session_ids: list[str] = field(default_factory=list)
    receipts: list[KillReceipt] = field(default_factory=list)


def classify(
    method: str,
    path: str = "",
    *,
    destructive: bool = False,
    paid_inference: bool = False,
    financial: bool = False,
    read_like_post: bool = False,
    public_read: bool = False,
) -> str:
    """Classify one call by capability; highest class wins.

    Returns a SessionClass string the policy engine (W05) uses as the
    capability floor for the call:

    * ``destructive`` — explicit destructive capability, or DELETE.
    * ``write`` — paid inference (always write class), any financial
      (money/billing only) call, or any non-read-like mutating method
      (POST/PUT/PATCH). ``financial`` floors at write, it is not a
      separate session class; a financial call that is also
      destructive is destructive.
    * ``read_account`` — default for reads. The same path can return
      public or private data (v3 N-B6), so a read is account-class
      unless the caller explicitly asserts it is public.
    * ``read_public`` — only when ``public_read`` is asserted and no
      higher capability applies.
    * Read-like POSTs (e.g. a token-count call) are exempted from the
      mutating-method rule by ``read_like_post``; the provider pack
      owns the exemption list, this flag is its input.

    ``method``/``path`` alone never decide: capability flags dominate.
    """
    m = (method or "").upper()
    if destructive or m == "DELETE":
        return "destructive"
    if paid_inference or financial:
        return "write"
    if m in ("POST", "PUT", "PATCH") and not read_like_post:
        return "write"
    if m in ("GET", "HEAD", "OPTIONS") or read_like_post:
        return "read_public" if public_read else "read_account"
    # Unknown method: fail closed toward write, never toward public read.
    return "write"


def expiry_drain_seconds(session_class: str) -> int:
    """Seconds a call of this class may drain past expiry: 60 for reads,
    0 (terminate at expiry) for destructive writes and streams."""
    if session_class in ("read_account", "read_public"):
        return EXPIRY_DRAIN_READ_SECONDS
    if session_class in ("write", "destructive"):
        return 0
    raise SessionError(f"unknown session class: {session_class!r}")


class SessionStore:
    """In-memory session broker state. No persistence of any kind."""

    def __init__(self, freeze_dir: str | None = None) -> None:
        # session_id -> Session (public record, no secrets)
        self._sessions: dict[str, Session] = {}
        # token SHA-256 hex -> session_id (token string never stored)
        self._token_hashes: dict[str, str] = {}
        # session_id -> PoP key (memory only, zeroed on teardown)
        self._pop_keys: dict[str, bytearray] = {}
        # session_id -> append-only set of accepted (timestamp, pop_hex)
        # pairs; never evicted during the session lifetime (contract §4).
        self._nonce_cache: dict[str, set[tuple[int, str]]] = {}
        # session_id -> in-flight call ids (for kill receipts)
        self._in_flight: dict[str, list[str]] = {}
        # session_id -> {call_id: call class} for suspend semantics
        self._in_flight_classes: dict[str, dict[str, str]] = {}
        # (session_id, call_id) -> drain deadline for suspended reads
        self._draining: dict[tuple[str, str], float] = {}
        # v0.2 lifecycle state
        self._quarantined: bool = False
        self._quarantine_reason: str = ""
        self._locked: bool = False  # lock flag only; never auto-resumes
        self._clock_sanity: ClockSanity | None = None
        self._kill_receipts: dict[str, KillReceipt] = {}
        self._killed_in_flight: dict[str, dict[str, list[str]]] = {}
        self._grants: dict[str, ConsoleGrant] = {}
        self.freeze_store: FreezeStore | None = (
            FreezeStore(freeze_dir) if freeze_dir is not None else None
        )

    # -- creation ----------------------------------------------------

    def create_session(
        self,
        key_id: Any,
        provider: str,
        session_class: str,
        process_group: str,
        ancestry: str = "",
        requested_ttl_seconds: int | None = None,
        idle_seconds: int | None = None,
        transport: str = "absolute",
        now_wall: float | None = None,
        now_mono: float | None = None,
        grant_id: str | None = None,
    ) -> tuple[Session, str]:
        """Create a session. Returns (Session, token); the token string
        is handed out exactly once here and is never stored.

        Raises SessionError (KH-2001) on any invalid input, including:
        a non-string key_id (a list is unconstructable, v3 N-C1), an
        unknown provider/class/transport, a TTL above the class cap or
        above the 2 h hard cap, an idle value outside 2–15 min or an
        attempt to disable idle (0), and ``connect_allowed`` transport
        for write/destructive sessions (v3 §1G: tunnels hide method,
        path and body, so they cannot carry write/destructive policy).
        """
        # Wake quarantine refuses ALL requests, including creation
        # (v3 N-F2: refuse everything until sleep evaluation completes).
        if self._quarantined:
            raise SessionError(
                f"wake quarantine active ({self._quarantine_reason}); "
                "no sessions are created until evaluation completes",
                ERR_INVALID_INPUT,
            )
        if self.freeze_store is not None and isinstance(key_id, str):
            if self.freeze_store.is_frozen(key_id):
                raise SessionError(
                    "key is frozen; unfreeze it explicitly before creating "
                    "a session",
                    ERR_INVALID_INPUT,
                )
        if grant_id is not None:
            grant = self._grants.get(grant_id)
            wall_pre = float(now_wall) if now_wall is not None else time.time()
            if grant is None or grant.revoked or grant.status != "live":
                raise SessionError(
                    "console grant is not live; no session may be "
                    "derived from it",
                    ERR_INVALID_INPUT,
                )
            if wall_pre >= grant.expires_at:
                grant.status = "dead"
                raise SessionError(
                    "console grant has expired; no session may be "
                    "derived from it",
                    ERR_INVALID_INPUT,
                )
        # One session = one key, at schema level: reject any list.
        if not isinstance(key_id, str) or not key_id:
            raise SessionError(
                "key_id must be a single non-empty string, never a list",
                ERR_INVALID_INPUT,
            )
        if provider not in PROVIDERS:
            raise SessionError(f"unknown provider: {provider!r}", ERR_INVALID_INPUT)
        if session_class not in SESSION_CLASSES:
            raise SessionError(
                f"unknown session class: {session_class!r}", ERR_INVALID_INPUT
            )
        if transport not in TRANSPORTS:
            raise SessionError(f"unknown transport: {transport!r}", ERR_INVALID_INPUT)
        if transport == "connect_allowed" and session_class in ("write", "destructive"):
            raise SessionError(
                "connect_allowed transport is refused for write/destructive "
                "sessions (HOST-ONLY POLICY cannot enforce path/body rules)",
                ERR_INVALID_INPUT,
            )
        default_ttl, cap_ttl = TTL_TABLE[session_class]
        ttl = default_ttl if requested_ttl_seconds is None else requested_ttl_seconds
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
            raise SessionError("requested TTL must be a positive integer", ERR_INVALID_INPUT)
        if ttl > cap_ttl:
            raise SessionError(
                f"requested TTL {ttl}s exceeds {session_class} cap {cap_ttl}s",
                ERR_INVALID_INPUT,
            )
        if ttl > ABSOLUTE_HARD_CAP_SECONDS:
            raise SessionError(
                f"requested TTL {ttl}s exceeds absolute hard cap "
                f"{ABSOLUTE_HARD_CAP_SECONDS}s",
                ERR_INVALID_INPUT,
            )
        idle = IDLE_DEFAULT_SECONDS if idle_seconds is None else idle_seconds
        if (
            not isinstance(idle, int)
            or isinstance(idle, bool)
            or idle < IDLE_MIN_SECONDS
            or idle > IDLE_MAX_SECONDS
        ):
            raise SessionError(
                "idle timeout must be 2–15 minutes and cannot be disabled",
                ERR_INVALID_INPUT,
            )
        if not isinstance(process_group, str) or not process_group:
            raise SessionError("process_group is required", ERR_INVALID_INPUT)

        wall = float(now_wall) if now_wall is not None else time.time()
        mono = float(now_mono) if now_mono is not None else time.monotonic()
        session = Session(
            session_id="sess-" + secrets.token_hex(8),
            key_id=key_id,
            provider=provider,
            session_class=session_class,
            transport=transport,
            created_at=wall,
            created_mono=mono,
            expires_at=wall + ttl,
            idle_deadline=wall + idle,
            idle_seconds=idle,
            process_group=process_group,
            ancestry=ancestry or "",
            temp_dir=tempfile.mkdtemp(prefix="kh-sess-"),
            grant_id=grant_id or "",
        )
        token = generate_token()
        self._sessions[session.session_id] = session
        self._token_hashes[hash_token(token)] = session.session_id
        self._pop_keys[session.session_id] = generate_pop_key()
        self._nonce_cache[session.session_id] = set()
        self._in_flight[session.session_id] = []
        return session, token

    # -- liveness ----------------------------------------------------

    def _is_live(self, session: Session, now_wall: float) -> bool:
        if session.killed:
            return False
        if session.suspended:
            return False
        if now_wall >= session.expires_at:
            return False
        # Idle timer pauses while any call is in flight (f05 L-11):
        # a long stream must not idle-time-out mid-stream. With no
        # call in flight, the idle deadline is a hard liveness bound.
        if now_wall >= session.idle_deadline and not self._in_flight.get(
            session.session_id
        ):
            return False
        return True

    def _apply_idle_suspend(self, session: Session, now_wall: float) -> None:
        """Lazily mark an idle-timed-out session suspended (v3 N-F2 /
        f05 L-11/L-12): it stops validating, but it is NOT dead — it
        resumes only via resume_session with system auth, and it
        still dies at its absolute expiry."""
        if (
            not session.killed
            and not session.suspended
            and now_wall < session.expires_at
            and now_wall >= session.idle_deadline
            and not self._in_flight.get(session.session_id)
        ):
            session.suspended = True
            session.suspended_reason = "idle"
            session.suspended_at = now_wall

    def get_session(self, session_id: str) -> Session | None:
        """Public record lookup (no secrets); None if unknown."""
        return self._sessions.get(session_id)

    def validate_token(
        self,
        token: str,
        now_wall: float | None = None,
        sleep_aware_now: float | None = None,
    ) -> Session | None:
        """Resolve a token to its live session, else None (generic
        dead-token result: unknown, expired, idle-timed-out and killed
        are indistinguishable to the caller, v3 N-C9).

        While wake quarantine is active, every token denies (v3 N-F2).
        When clock sanity is enabled and ``sleep_aware_now`` is given,
        the sanity check runs BEFORE authentication (f05 L-06); a
        failed check suspends all sessions and denies this request.
        Clock sanity is only engaged when the caller supplies the
        sleep-aware reading, so callers using fake wall clocks in
        tests are not spuriously suspended."""
        if self._quarantined:
            return None
        if not isinstance(token, str):
            return None
        now = float(now_wall) if now_wall is not None else time.time()
        if self._clock_sanity is not None and sleep_aware_now is not None:
            ok, _reason = self._clock_sanity.check(now, sleep_aware_now)
            if not ok:
                self.suspend_all(reason="clock_jump", now_wall=now)
                return None
        session_id = None
        # Constant-time comparison against stored hashes.
        for stored_hash, sid in self._token_hashes.items():
            if verify_token(token, stored_hash):
                session_id = sid
                break
        if session_id is None:
            return None
        session = self._sessions.get(session_id)
        if session is None:
            return None
        self._apply_idle_suspend(session, now)
        if not self._is_live(session, now):
            return None
        return session

    def validate_token_detailed(
        self,
        token: str,
        now_wall: float | None = None,
        sleep_aware_now: float | None = None,
    ) -> tuple[Session | None, str | None]:
        """Like validate_token, plus the internal error code (KH-1002)
        for the audit log. The agent-facing surface must still report
        only the generic denial (contract §6, no denial oracle)."""
        session = self.validate_token(
            token, now_wall=now_wall, sleep_aware_now=sleep_aware_now
        )
        if session is None:
            return None, ERR_SESSION_DEAD
        return session, None

    # -- PoP / authenticated requests --------------------------------

    def authenticate_request(
        self,
        token: str,
        method: str,
        host: str,
        canonical_path: str,
        body: bytes,
        timestamp: int | str | None,
        pop_hex: str | None,
        now_wall: float | None = None,
        sleep_aware_now: float | None = None,
    ) -> Session | None:
        """Full per-request authentication: live session + valid PoP +
        fresh nonce. Missing or invalid PoP is a deny with NO bare-
        bearer fallback. A replayed (timestamp, pop_hex) pair is a deny
        and is never removed from the cache (append-only, contract §4).
        On success the nonce is recorded; the caller must still call
        record_successful_call ONLY after the proxied call succeeds —
        authentication alone does not reset idle."""
        session = self.validate_token(
            token, now_wall=now_wall, sleep_aware_now=sleep_aware_now
        )
        if session is None:
            return None
        pop_key = self._pop_keys.get(session.session_id)
        if pop_key is None:
            return None
        now = float(now_wall) if now_wall is not None else time.time()
        if not verify_pop(
            pop_key, method, host, canonical_path, body, timestamp, pop_hex, now=now
        ):
            return None
        try:
            nonce = (int(timestamp), pop_hex)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None
        cache = self._nonce_cache.setdefault(session.session_id, set())
        if nonce in cache:
            return None  # replay
        cache.add(nonce)
        return session

    # -- idle accounting ----------------------------------------------

    def record_successful_call(
        self, session_id: str, now_wall: float | None = None
    ) -> bool:
        """Reset the idle deadline after a SUCCESSFUL proxied call.
        Returns False if the session is dead or suspended (no
        resurrection, and a success during suspension does not
        unsuspend — only resume_session with system auth does)."""
        session = self._sessions.get(session_id)
        if session is None or session.killed or session.suspended:
            return False
        now = float(now_wall) if now_wall is not None else time.time()
        if now >= session.expires_at:
            return False
        session.idle_deadline = now + session.idle_seconds
        return True

    def record_denied_call(self, session_id: str) -> None:
        """Explicit no-op: a denied call MUST NOT reset idle (v3 N-B3)."""

    def record_status_poll(self, session_id: str) -> None:
        """Explicit no-op: a status poll MUST NOT reset idle (v3 N-B3)."""

    # -- in-flight tracking (kill receipts) ---------------------------

    def begin_call(
        self, session_id: str, call_id: str, call_class: str = "write"
    ) -> bool:
        """Mark a call forwarded; it will appear on a kill receipt if
        kill lands while it is in flight. False if the session is
        dead, suspended, or the store is quarantined. ``call_class``
        defaults to "write" (fail closed for suspend semantics:
        unknown classes are aborted on suspend, never drained).
        Beginning or completing a call NEVER resets idle — only
        record_successful_call does, after the proxied call succeeds."""
        if self._quarantined:
            return False
        session = self._sessions.get(session_id)
        if session is None or session.killed or session.suspended:
            return False
        self._in_flight.setdefault(session_id, []).append(call_id)
        self._in_flight_classes.setdefault(session_id, {})[call_id] = call_class
        return True

    def complete_call(self, session_id: str, call_id: str) -> None:
        """Mark a forwarded call finished (removes it from in-flight)."""
        calls = self._in_flight.get(session_id)
        if calls is not None and call_id in calls:
            calls.remove(call_id)
        classes = self._in_flight_classes.get(session_id)
        if classes is not None:
            classes.pop(call_id, None)
        self._draining.pop((session_id, call_id), None)

    # -- kill / expiry -------------------------------------------------

    def kill(self, session_id: str, now_wall: float | None = None) -> KillReceipt | None:
        """Kill one session. Synchronous: the token is denied from the
        moment this returns (≤1 s deny bound), and teardown — PoP key
        zeroed, token hash dropped, temp dir deleted — completes before
        return (≤5 s teardown bound). Already-forwarded calls are
        listed on the receipt, NOT recalled. Unknown sessions return
        None (kill needs no auth, contract §8, and never enumerates).
        Re-killing an already-killed session returns its receipt shape
        with no already-forwarded calls."""
        session = self._sessions.get(session_id)
        if session is None:
            return None
        kill_start = time.monotonic()
        now = float(now_wall) if now_wall is not None else time.time()
        already = list(self._in_flight.get(session_id, []))
        session.killed = True
        session.suspended = False
        session.suspended_reason = ""
        # Drop the token hash so the token denies immediately.
        for h, sid in list(self._token_hashes.items()):
            if sid == session_id:
                del self._token_hashes[h]
        pop_key = self._pop_keys.pop(session_id, None)
        zero_secret(pop_key)
        # Nonce cache is append-only during life; it dies with the session.
        self._nonce_cache.pop(session_id, None)
        self._in_flight.pop(session_id, None)
        self._in_flight_classes.pop(session_id, None)
        for key in [k for k in self._draining if k[0] == session_id]:
            del self._draining[key]
        if session.temp_dir:
            shutil.rmtree(session.temp_dir, ignore_errors=True)
            session.temp_dir = ""
        teardown_s = time.monotonic() - kill_start
        receipt = KillReceipt(
            session_id=session_id,
            killed_at=now,
            deny_listed_at=now,
            deny_list_latency_s=0.0,  # token hash dropped synchronously above
            teardown_s=teardown_s,
            teardown_within_5s=teardown_s <= 5.0,
            in_flight_at_kill=already,
            still_running_at_receipt=list(already),
        )
        # First kill wins the registry: a re-kill returns its own
        # receipt shape but must not erase completed-call history.
        if session_id not in self._kill_receipts:
            self._kill_receipts[session_id] = receipt
            self._killed_in_flight[session_id] = {
                "at_kill": list(already),
                "completed": [],
            }
        return receipt

    def complete_killed_call(self, session_id: str, call_id: str) -> bool:
        """Reconcile a kill (f05 L-01): an already-forwarded call is
        NOT recalled — it runs to completion, and its owner reports
        that completion here so the kill receipt lists it. Returns
        False for unknown sessions or calls that were not in flight
        at kill time. The receipt is updated in place."""
        record = self._killed_in_flight.get(session_id)
        if record is None or call_id not in record["at_kill"]:
            return False
        if call_id in record["completed"]:
            return False
        record["completed"].append(call_id)
        receipt = self._kill_receipts.get(session_id)
        if receipt is not None:
            receipt.completed_during_kill = list(record["completed"])
            receipt.still_running_at_receipt = [
                c for c in record["at_kill"] if c not in record["completed"]
            ]
        return True

    def get_kill_receipt(self, session_id: str) -> KillReceipt | None:
        """Current kill receipt, with completed/still-running lists
        updated by complete_killed_call reports. None if never killed."""
        return self._kill_receipts.get(session_id)

    def kill_all(self, now_wall: float | None = None) -> KillAllReceipt:
        """Kill every live session, snapshotted at invocation. Sessions
        created after the snapshot are not in the receipt and are not
        killed by this sweep (v3 N-B4)."""
        now = float(now_wall) if now_wall is not None else time.time()
        snapshot = [sid for sid, s in self._sessions.items() if not s.killed]
        receipts: list[KillReceipt] = []
        for sid in snapshot:
            receipt = self.kill(sid, now_wall=now)
            if receipt is not None:
                receipts.append(receipt)
        return KillAllReceipt(
            killed_at=now,
            killed_session_ids=[r.session_id for r in receipts],
            receipts=receipts,
        )

    def prune_expired(self, now_wall: float | None = None) -> list[str]:
        """Tear down ABSOLUTE-EXPIRED sessions only (v0.2 change, v3
        N-F2: suspended sessions still expire at their original time,
        but idle suspension is NOT expiry — an idle-suspended session
        is pruned only when its absolute expiry passes, so it stays
        resumable with system auth until then). Returns pruned ids."""
        now = float(now_wall) if now_wall is not None else time.time()
        pruned: list[str] = []
        for sid, session in list(self._sessions.items()):
            if not session.killed and now >= session.expires_at:
                self.kill(sid, now_wall=now)
                pruned.append(sid)
        return pruned

    def live_session_ids(self, now_wall: float | None = None) -> list[str]:
        """Ids of currently live sessions (for the broker's own use;
        never expose this list to an agent — v3 N-C9, no inventory
        oracle)."""
        now = float(now_wall) if now_wall is not None else time.time()
        return [sid for sid, s in self._sessions.items() if self._is_live(s, now)]

    # -- v0.2: clock sanity -------------------------------------------
    def enable_clock_sanity(
        self, baseline_wall: float, baseline_sleep_aware: float | None = None
    ) -> None:
        """Arm cumulative clock-jump detection (v3 N-F2). Must be
        called with real clock readings before any request that
        passes sleep_aware_now; without it, no jump check runs."""
        self._clock_sanity = ClockSanity(baseline_wall, baseline_sleep_aware)

    def check_clock(
        self, now_wall: float, sleep_aware_now: float | None = None
    ) -> tuple[bool, str]:
        """Public clock check (daemon polling path). On failure the
        caller should suspend all sessions; this method itself does
        not suspend, so a polling loop can report before acting."""
        if self._clock_sanity is None:
            return True, "clock sanity not enabled"
        return self._clock_sanity.check(now_wall, sleep_aware_now)

    def note_clock_event(
        self, now_wall: float, sleep_aware_now: float | None = None
    ) -> bool:
        """Daemon clock-poll hook: on a failed check, suspend every
        session immediately (fail closed, f05 L-06) and return False."""
        ok, _reason = self.check_clock(now_wall, sleep_aware_now)
        if not ok:
            self.suspend_all(reason="clock_jump", now_wall=now_wall)
            return False
        return True

    # -- v0.2: wake quarantine -----------------------------------------
    def begin_wake_quarantine(self, reason: str = "wake") -> None:
        """Enter quarantine: refuse ALL requests (validate, auth,
        begin_call, create) until evaluate_wake completes (v3 N-F2,
        f05 L-08). A request arriving between wake and evaluation
        gets nothing, not a free call."""
        self._quarantined = True
        self._quarantine_reason = reason

    def is_quarantined(self) -> bool:
        return self._quarantined

    def evaluate_wake(
        self, sleep_seconds: float, now_wall: float | None = None
    ) -> WakeEvaluation:
        """End quarantine and act on the measured sleep duration:
        >1 h slept kills everything (v3 K6); any positive sleep
        suspends everything (v3 K5); zero sleep changes nothing.
        Grants follow the same rule: dead after >1 h slept, else
        suspended. Quarantine always lifts when this returns —
        evaluation must complete, not linger."""
        now = float(now_wall) if now_wall is not None else time.time()
        self._quarantined = False
        self._quarantine_reason = ""
        if sleep_seconds > SLEEP_KILL_AFTER_S:
            killed = self.kill_all(now_wall=now)
            for grant in self._grants.values():
                if grant.status != "dead":
                    grant.status = "dead"
                    grant.revoked = True
            return WakeEvaluation(
                sleep_seconds=float(sleep_seconds),
                action="kill_all",
                killed_session_ids=list(killed.killed_session_ids),
            )
        if sleep_seconds > 0:
            receipt = self.suspend_all(reason="sleep", now_wall=now)
            return WakeEvaluation(
                sleep_seconds=float(sleep_seconds),
                action="suspend_all",
                suspended_session_ids=list(receipt.session_ids),
            )
        return WakeEvaluation(sleep_seconds=float(sleep_seconds), action="none")

    def evaluate_lock_duration(
        self, locked_seconds: float, now_wall: float | None = None
    ) -> WakeEvaluation:
        """Lock-duration twin of evaluate_wake (v3 K4): >15 min
        locked kills everything and kills grants; shorter lock time
        leaves the lock suspension in place (it does not resume)."""
        now = float(now_wall) if now_wall is not None else time.time()
        if locked_seconds > LOCK_KILL_AFTER_S:
            killed = self.kill_all(now_wall=now)
            for grant in self._grants.values():
                if grant.status != "dead":
                    grant.status = "dead"
                    grant.revoked = True
            return WakeEvaluation(
                sleep_seconds=float(locked_seconds),
                action="kill_all",
                killed_session_ids=list(killed.killed_session_ids),
            )
        return WakeEvaluation(
            sleep_seconds=float(locked_seconds), action="none"
        )

    # -- v0.2: suspend / lock / resume ---------------------------------
    def suspend_session(
        self, session_id: str, reason: str, now_wall: float | None = None
    ) -> SuspendReceipt | None:
        """Suspend one live session. In-flight destructive/write calls
        are aborted (removed from in-flight; the proxy must terminate
        them); in-flight reads may drain until now+60 s (f05 L-08).
        Suspended sessions deny new requests until resume_session."""
        session = self._sessions.get(session_id)
        if session is None or session.killed or session.suspended:
            return None
        now = float(now_wall) if now_wall is not None else time.time()
        if now >= session.expires_at:
            return None
        session.suspended = True
        session.suspended_reason = reason
        session.suspended_at = now
        calls = self._in_flight_classes.get(session_id, {})
        aborted = [c for c, cls in calls.items() if cls not in ("read_account", "read_public")]
        draining = [c for c, cls in calls.items() if cls in ("read_account", "read_public")]
        drain_until = (now + EXPIRY_DRAIN_READ_SECONDS) if draining else None
        for call_id in aborted:
            inflight = self._in_flight.get(session_id)
            if inflight is not None and call_id in inflight:
                inflight.remove(call_id)
        self._in_flight_classes[session_id] = {
            c: cls for c, cls in calls.items() if c in draining
        }
        for call_id in draining:
            assert drain_until is not None
            self._draining[(session_id, call_id)] = drain_until
        return SuspendReceipt(
            suspended_at=now,
            reason=reason,
            session_ids=[session_id],
            aborted_call_ids=aborted,
            draining_call_ids=draining,
            drain_until=drain_until,
        )

    def suspend_all(
        self, reason: str, now_wall: float | None = None
    ) -> SuspendReceipt:
        """Suspend every live session (lock/sleep/clock-jump path).
        Live grants suspend too. Returns the combined receipt."""
        now = float(now_wall) if now_wall is not None else time.time()
        combined = SuspendReceipt(suspended_at=now, reason=reason)
        for sid in list(self._sessions):
            receipt = self.suspend_session(sid, reason, now_wall=now)
            if receipt is not None:
                combined.session_ids.append(sid)
                combined.aborted_call_ids.extend(receipt.aborted_call_ids)
                combined.draining_call_ids.extend(receipt.draining_call_ids)
                if receipt.drain_until is not None:
                    combined.drain_until = receipt.drain_until
        for grant in self._grants.values():
            if grant.status == "live":
                grant.status = "suspended"
        return combined

    def lock_suspend_all(self, now_wall: float | None = None) -> SuspendReceipt:
        """Screen lock (v3 N-D4/N-F6, f05 L-13): set the lock flag
        AND suspend all live sessions immediately."""
        self._locked = True
        return self.suspend_all(reason="lock", now_wall=now_wall)

    def is_locked(self) -> bool:
        return self._locked

    def clear_lock(self) -> list[str]:
        """Unlock clears the lock flag ONLY. It never auto-resumes
        any session (v3 N-D4/N-F6): suspended sessions stay suspended
        until resume_session with system auth. Returns the ids that
        are still suspended, as proof unlock did not resume them."""
        self._locked = False
        return [
            sid for sid, s in self._sessions.items() if s.suspended and not s.killed
        ]

    def call_may_drain(
        self, session_id: str, call_id: str, now_wall: float | None = None
    ) -> bool:
        """True iff a suspended session's read call is still inside
        its 60 s drain window. The proxy must terminate it at the
        deadline; the store does not forward anything itself."""
        now = float(now_wall) if now_wall is not None else time.time()
        deadline = self._draining.get((session_id, call_id))
        return deadline is not None and now <= deadline

    def resume_session(
        self,
        session_id: str,
        *,
        system_auth: bool,
        now_wall: float | None = None,
        proximity: bool = False,
    ) -> tuple[Session, str] | None:
        """Resume a suspended session (v3 N-F2, f05 L-10/L-12).

        Requires system auth: a biometric or typed system password,
        explicitly EXCLUDING proximity/watch auto-unlock
        (proximity=True always refuses, even with system_auth=True).
        One unauthenticated click never resumes. On success the token
        AND PoP key rotate (f05 L-17/K1): the old token denies, a
        fresh token is returned exactly once here, and the idle
        deadline restarts. The caller (approver/OS layer) must only
        pass system_auth=True after a real OS gesture; this store
        cannot verify the gesture itself, so a False claim here is a
        caller bug, stated plainly rather than papered over.
        Returns None (session stays suspended) on any refusal, on
        expiry, or when the session was never suspended."""
        session = self._sessions.get(session_id)
        if session is None or session.killed or not session.suspended:
            return None
        now = float(now_wall) if now_wall is not None else time.time()
        if now >= session.expires_at:
            return None
        if not system_auth or proximity:
            return None
        # Rotate token + PoP key; old material is dropped and zeroed.
        for h, sid in list(self._token_hashes.items()):
            if sid == session_id:
                del self._token_hashes[h]
        old_pop = self._pop_keys.pop(session_id, None)
        zero_secret(old_pop)
        new_token = generate_token()
        self._token_hashes[hash_token(new_token)] = session_id
        self._pop_keys[session_id] = generate_pop_key()
        self._nonce_cache[session_id] = set()
        for key in [k for k in self._draining if k[0] == session_id]:
            del self._draining[key]
        session.suspended = False
        session.suspended_reason = ""
        session.suspended_at = 0.0
        session.idle_deadline = now + session.idle_seconds
        return session, new_token

    # -- v0.2: freeze / rotation kill -----------------------------------
    def freeze_key(self, key_id: str, reason: str = "") -> None:
        if self.freeze_store is None:
            raise SessionError(
                "no freeze store configured for this session store",
                ERR_INVALID_INPUT,
            )
        self.freeze_store.freeze(key_id, reason)

    def unfreeze_key(self, key_id: str) -> None:
        if self.freeze_store is None:
            raise SessionError(
                "no freeze store configured for this session store",
                ERR_INVALID_INPUT,
            )
        self.freeze_store.unfreeze(key_id)

    def is_key_frozen(self, key_id: str) -> bool:
        return self.freeze_store is not None and self.freeze_store.is_frozen(key_id)

    def kill_sessions_for_key(
        self, key_id: str, now_wall: float | None = None
    ) -> list[KillReceipt]:
        """Rotation kills live sessions for that key (v3 N-F4):
        rotation must not be weaker than deletion. Killed sessions
        only; already-killed sessions are not re-killed."""
        now = float(now_wall) if now_wall is not None else time.time()
        receipts: list[KillReceipt] = []
        for sid, session in list(self._sessions.items()):
            if session.key_id == key_id and not session.killed:
                receipt = self.kill(sid, now_wall=now)
                if receipt is not None:
                    receipts.append(receipt)
        return receipts

    # -- v0.2: console grants (lifecycle linkage) ------------------------
    def create_console_grant(
        self,
        grant_id: str,
        key_id: str,
        scope: str,
        duration_s: int,
        *,
        seat_verified: bool,
        destructive: bool = False,
        now_wall: float | None = None,
    ) -> ConsoleGrant:
        """Create a console grant record: 2 h max, single start,
        non-destructive, seat-verified (f05 L-21). Scope is frozen
        at creation. This record alone grants nothing — issuance
        under it still goes through create_session with grant_id."""
        validate_console_grant(duration_s, destructive, seat_verified)
        if grant_id in self._grants:
            raise SessionError(
                f"console grant already exists: {grant_id!r}", ERR_INVALID_INPUT
            )
        now = float(now_wall) if now_wall is not None else time.time()
        grant = ConsoleGrant(
            grant_id=grant_id,
            key_id=key_id,
            scope=scope,
            duration_s=duration_s,
            created_at=now,
            seat_verified=seat_verified,
        )
        self._grants[grant_id] = grant
        return grant

    def start_console_grant(self, grant_id: str) -> bool:
        """Single start: the first start succeeds, a second start
        raises (a grant is one activation, never restarted silently).
        A revoked, dead, or expired grant cannot start."""
        grant = self._grants.get(grant_id)
        if grant is None:
            raise SessionError(f"unknown console grant: {grant_id!r}", ERR_INVALID_INPUT)
        if grant.started:
            raise SessionError(
                "console grant has already started (single start)",
                ERR_INVALID_INPUT,
            )
        if grant.revoked or grant.status == "dead":
            raise SessionError(
                "console grant is revoked or dead and cannot start",
                ERR_INVALID_INPUT,
            )
        grant.started = True
        return True

    def resume_console_grant(
        self, grant_id: str, *, system_auth: bool, proximity: bool = False
    ) -> bool:
        """Resume a lock/sleep-suspended grant. Same rule as session
        resume: system auth required, proximity/watch excluded.
        Unlock alone never resumes a grant."""
        grant = self._grants.get(grant_id)
        if grant is None or grant.status != "suspended" or grant.revoked:
            return False
        if not system_auth or proximity:
            return False
        grant.status = "live"
        return True

    def revoke_grant(
        self, grant_id: str, now_wall: float | None = None
    ) -> GrantRevocation | None:
        """Revoke a grant: derived live sessions are LISTED, not
        killed (f05 L-21). The revocation receipt states their
        continued life explicitly; use revoke_grant_and_kill to end
        them in the same step."""
        grant = self._grants.get(grant_id)
        if grant is None:
            return None
        now = float(now_wall) if now_wall is not None else time.time()
        grant.revoked = True
        grant.status = "dead"
        derived = [
            sid
            for sid, s in self._sessions.items()
            if s.grant_id == grant_id and not s.killed and now < s.expires_at
        ]
        return GrantRevocation(
            grant_id=grant_id, revoked_at=now, derived_live_session_ids=derived
        )

    def revoke_grant_and_kill(
        self, grant_id: str, now_wall: float | None = None
    ) -> tuple[GrantRevocation, list[KillReceipt]] | None:
        """Revoke a grant AND kill every live session derived from
        it. The receipt lists both the derived sessions and the ones
        actually killed (identical here by construction)."""
        revocation = self.revoke_grant(grant_id, now_wall=now_wall)
        if revocation is None:
            return None
        now = float(now_wall) if now_wall is not None else time.time()
        receipts: list[KillReceipt] = []
        for sid in revocation.derived_live_session_ids:
            receipt = self.kill(sid, now_wall=now)
            if receipt is not None:
                receipts.append(receipt)
        revocation.derived_killed_session_ids = [r.session_id for r in receipts]
        return revocation, receipts

    # NOTE: there is deliberately no `extend` method anywhere in this
    # module. Re-issuance is create_session() with a fresh gesture.
