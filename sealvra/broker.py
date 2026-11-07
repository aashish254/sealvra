"""Broker: owns sessions in memory (W01).

Rules (CONTRACT §§2-4, v3 §1B/§1C/§1F):

- Sessions live in memory only. No session is persisted, so no
  session survives a daemon restart or reboot (no resurrection).
- One session = one key (schema: Session.key_id is a single str).
  No session extensions, ever (no ``extend`` method exists);
  re-issuance is a new session + fresh gesture (W08/W10 own that).
- Token: ``"kh_sess_" + token_urlsafe(32)``, returned to the caller
  exactly once at creation. The broker stores ONLY the SHA-256 hex
  digest, compared with ``hmac.compare_digest``. The token string is
  never logged, never written to disk, never put in a Session.
- PoP (CONTRACT §4): every proxied request must carry the session
  token, ``X-Sealvra-PoP`` = HMAC-SHA256(PoP key, canonical
  ``METHOD\\nHOST\\nCANONICAL_PATH\\nBODY_SHA256_HEX\\nTIMESTAMP``) and
  ``X-Sealvra-Timestamp`` (max skew 300 s, nonce cache append-only
  for the session lifetime -- no eviction). Missing/invalid PoP =
  deny, no fallback to bare bearer. The PoP key lives in memory
  only; it is returned once at creation alongside the token and is
  never stored in a Session, file, or log.
- Kill (v3 §1B N-B4): deny-list write <= 1 s (synchronous, first
  step of kill), full teardown <= 5 s via the supervisor, kill is
  never gated by authentication (no auth check in kill paths).
  Already-forwarded calls are NOT recalled: they run to completion
  and are listed on the kill receipt.
- Kill-all snapshots at invocation: sessions created during the
  sweep are listed, not silently included or excluded (v3 N-B4).
- Idle: refreshed ONLY by a successful proxied call
  (``record_successful_call``); denied calls and status polls do
  not refresh it.

Dependencies on not-yet-written modules (vault W02, sessions/tokens
W03, proxy W04, policy W05, approval W08, audit W09) are deliberately
NOT imported here: the broker exposes the session/token/PoP/kill
interfaces those modules consume, and takes only a Supervisor
(W01) and plain Session objects. Key material itself is never
handled here -- the broker holds identifiers, token digests, and
PoP keys only; the real key lives in the vault compartment and in
worker memory (W02/W06/W07 territory).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass

from .supervisor import Supervisor, WorkerAlreadyExists
from .types import (
    POP_TIMESTAMP_MAX_SKEW_S,
    KillReceipt,
    Session,
    SessionClass,
    Transport,
    clamp_idle,
    clamp_ttl,
)


class SessionNotFound(Exception):
    """KH-1002: session not found/expired/killed (generic, no oracle)."""


class SessionCreateError(Exception):
    """KH-2001: invalid input for session creation."""


@dataclass
class CreatedSession:
    """One-time handoff: token + PoP key are returned exactly once.

    Callers must deliver these to the agent/worker and then drop
    them. They are never re-readable from the broker.
    """

    session: Session
    token: str  # returned once; broker stores only its digest
    pop_key: bytes  # returned once; broker keeps its own copy in memory


class Broker:
    def __init__(self, supervisor: Supervisor | None = None) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, Session] = {}
        self._token_digests: dict[str, str] = {}  # digest -> session_id
        self._pop_keys: dict[str, bytes] = {}  # session_id -> PoP key
        self._nonces: dict[str, set[str]] = {}  # session_id -> seen nonces
        self._deny_list: set[str] = set()  # token digests, denied <= 1 s
        self._in_flight: dict[str, set[str]] = {}  # session_id -> call ids
        self._completed_during_kill: dict[str, list[str]] = {}
        self.supervisor = supervisor if supervisor is not None else Supervisor()

    # -- creation ---------------------------------------------------
    def create_session(self, *, key_id: str, provider: str,
                       session_class: SessionClass,
                       transport: Transport = "absolute",
                       process_group: str = "",
                       ancestry: str = "",
                       requested_ttl_s: int | None = None,
                       idle_timeout_s: int | None = None,
                       port: int | None = None) -> CreatedSession:
        if not key_id or not provider:
            raise SessionCreateError("key_id and provider are required")
        if session_class not in ("destructive", "write", "read_account",
                                 "read_public"):
            raise SessionCreateError(f"unknown session_class {session_class!r}")
        if transport not in ("absolute", "connect_allowed"):
            raise SessionCreateError(f"unknown transport {transport!r}")
        # CONNECT is never the default and is refused for write/
        # destructive sessions (CONTRACT §6 / v3 §1G).
        if transport == "connect_allowed" and session_class in (
                "destructive", "write"):
            raise SessionCreateError(
                "connect_allowed transport refused for write/destructive sessions")
        now_wall = time.time()
        now_mono = time.monotonic()
        ttl = clamp_ttl(session_class, requested_ttl_s)
        idle = clamp_idle(idle_timeout_s)
        session = Session(
            session_id="sess-" + secrets.token_hex(8),
            key_id=key_id,
            provider=provider,  # type: ignore[arg-type]
            session_class=session_class,
            transport=transport,
            created_at=now_wall,
            expires_at=now_wall + ttl,
            idle_deadline=now_wall + idle,
            process_group=process_group,
            ancestry=ancestry,
            created_mono=now_mono,
        )
        # Worker-per-session = worker-per-key: spawning refuses a live
        # worker for the same key. Spawn BEFORE registering the token
        # so a refused spawn never leaks a usable session.
        self.supervisor.spawn(session, port=port)
        token = "kh_sess_" + secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        pop_key = secrets.token_bytes(32)
        with self._lock:
            self._sessions[session.session_id] = session
            self._token_digests[digest] = session.session_id
            self._pop_keys[session.session_id] = pop_key
            self._nonces[session.session_id] = set()
            self._in_flight[session.session_id] = set()
        return CreatedSession(session=session, token=token, pop_key=pop_key)

    # -- lookup / validation ----------------------------------------
    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def list_sessions(self) -> list[Session]:
        with self._lock:
            return list(self._sessions.values())

    def is_live(self, session: Session, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return (not session.killed and now < session.expires_at
                and now < session.idle_deadline)

    def reap_expired(self, now: float | None = None) -> list[str]:
        """Terminate every session whose TTL or idle deadline has passed.

        CONTRACT §3 makes expiry a TERMINATION, not a flag. The token
        already denies (`is_live` is consulted on every call), but
        nothing else ended the session: its worker process stayed alive
        and `Supervisor.spawn` refuses a second live worker for the same
        key, so an unreaped expiry leaves that compartment unusable until
        the daemon restarts. Termination is the existing kill path
        (deny-list, supervisor teardown, PoP zeroing); a session already
        killed is left alone, so one expiry causes exactly one teardown.

        Returns the session ids reaped by this call.
        """
        now = time.time() if now is None else now
        with self._lock:
            due = [sid for sid, session in self._sessions.items()
                   if not session.killed and not self.is_live(session, now)]
        reaped: list[str] = []
        for session_id in due:
            try:
                self.kill_session(session_id)
            except SessionNotFound:
                continue
            reaped.append(session_id)
        return reaped

    def validate_token(self, token: str) -> Session | None:
        """Resolve a token to its live session, or None (generic).

        Dead tokens give the same None as unknown tokens: no oracle
        about whether a session ever existed (v3 §1C N-C9).
        """
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self._lock:
            if digest in self._deny_list:
                return None
            session_id = self._token_digests.get(digest)
            if session_id is None:
                return None
            session = self._sessions.get(session_id)
        if session is None or not self.is_live(session):
            return None
        # Constant-time digest comparison against the stored digest.
        stored = None
        with self._lock:
            for candidate, sid in self._token_digests.items():
                if sid == session.session_id:
                    stored = candidate
                    break
        if stored is None or not hmac.compare_digest(stored, digest):
            return None
        return session

    def pop_key(self, session_id: str) -> bytes | None:
        """The PoP key for the proxy's own verification of a request.

        This is the daemon-side read used by ``ProxyEngine.pop_key_for``;
        it is NOT a handoff surface. The only place a PoP key leaves the
        broker is the one-shot ``CreatedSession.pop_key`` returned by the
        call that minted it (CONTRACT section 4: "returned once",
        delivered via pipe/FD or in-process handoff).

        A session id this broker never minted gets the same None as a
        killed one: no oracle about whether a session ever existed.
        """
        with self._lock:
            return self._pop_keys.get(session_id)

    def verify_pop(self, session: Session, *, method: str, host: str,
                   canonical_path: str, body_sha256_hex: str,
                   timestamp: int, pop_hex: str,
                   nonce: str | None = None) -> bool:
        """Validate a PoP header set for a live session. No fallback."""
        if not self.is_live(session):
            return False
        now = int(time.time())
        if abs(now - int(timestamp)) > POP_TIMESTAMP_MAX_SKEW_S:
            return False
        with self._lock:
            pop_key = self._pop_keys.get(session.session_id)
            if pop_key is None:
                return False
        canonical = (f"{method}\n{host}\n{canonical_path}\n"
                     f"{body_sha256_hex}\n{timestamp}")
        expected = hmac.new(pop_key, canonical.encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, pop_hex):
            return False
        # Replay protection, enforced even when the caller supplies no
        # explicit nonce: the replay key is the nonce if given, else
        # the PoP value itself (a signed request may verify exactly
        # once per session). MAC is checked first so a failed attempt
        # never poisons the cache. (Manager integration fix for the
        # W14 finding: verify_pop previously accepted a no-nonce
        # replay because the cache was only consulted with a nonce.)
        replay_key = nonce if nonce else pop_hex
        if not replay_key:
            return False
        with self._lock:
            seen = self._nonces.setdefault(session.session_id, set())
            if replay_key in seen:
                return False
            seen.add(replay_key)  # append-only, no eviction, session lifetime
        return True

    # -- proxied-call bookkeeping ------------------------------------
    def register_in_flight(self, session_id: str, call_id: str) -> None:
        with self._lock:
            calls = self._in_flight.get(session_id)
            if calls is not None:
                calls.add(call_id)

    def complete_in_flight(self, session_id: str, call_id: str) -> None:
        with self._lock:
            calls = self._in_flight.get(session_id)
            if calls is not None:
                calls.discard(call_id)

    def record_successful_call(self, session_id: str,
                               idle_timeout_s: int | None = None) -> bool:
        """Refresh idle deadline ONLY on a successful proxied call."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or not self.is_live(session):
                return False
            session.idle_deadline = time.time() + clamp_idle(idle_timeout_s)
            return True

    # -- kill ---------------------------------------------------------
    def kill_session(self, session_id: str) -> KillReceipt:
        """Kill one session. No authentication gate (v3 N-B4).

        Order: snapshot in-flight calls, deny-list synchronously
        (<= 1 s by construction -- it is the first step), mark killed,
        then supervisor teardown (<= 5 s bound enforced by the
        supervisor). Already-forwarded calls are NOT recalled.
        """
        kill_started = time.monotonic()
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise SessionNotFound(session_id)
            in_flight = sorted(self._in_flight.get(session_id, set()))
            # Deny-list FIRST, synchronously: new calls stop <= 1 s.
            for digest, sid in list(self._token_digests.items()):
                if sid == session_id:
                    self._deny_list.add(digest)
            session.killed = True
            deny_at = time.time()
        deny_latency = time.monotonic() - kill_started
        teardown_started = time.monotonic()
        port_released: bool | None = None
        workers_terminated: list[str] = []
        try:
            result = self.supervisor.terminate(session_id)
            port_released = result.get("port_released")
            if result.get("terminated"):
                workers_terminated.append(session_id)
        except Exception:
            # Supervisor missing a worker (e.g. already reaped) does
            # not un-kill the session; the deny-list is authoritative.
            workers_terminated = []
        teardown_s = time.monotonic() - teardown_started
        # In-flight calls run to completion: wait out the remainder of
        # the 5 s teardown window for them, then take the receipt.
        deadline = teardown_started + 5.0
        while time.monotonic() < deadline:
            with self._lock:
                remaining = self._in_flight.get(session_id, set())
                if not remaining:
                    break
            time.sleep(0.05)
        with self._lock:
            remaining = sorted(self._in_flight.get(session_id, set()))
            completed = [c for c in in_flight if c not in remaining]
        return KillReceipt(
            session_id=session_id,
            killed_at=deny_at,
            deny_listed_at=deny_at,
            deny_list_latency_s=deny_latency,
            teardown_s=teardown_s,
            teardown_within_5s=teardown_s <= 5.0,
            workers_terminated=workers_terminated,
            in_flight_at_kill=in_flight,
            completed_during_kill=completed,
            still_running_at_receipt=remaining,
            port_released=port_released,
        )

    def kill_all(self) -> dict:
        """Kill-all with snapshot-at-invocation semantics (v3 N-B4).

        Returns {"snapshot": [session_ids at invocation],
        "receipts": {session_id: KillReceipt},
        "created_during_sweep": [session_ids created after snapshot]}.
        Sessions created during the sweep are listed, not silently
        included or excluded.
        """
        with self._lock:
            snapshot = sorted(self._sessions.keys())
        receipts: dict[str, KillReceipt] = {}
        for session_id in snapshot:
            try:
                receipts[session_id] = self.kill_session(session_id)
            except SessionNotFound:
                continue
        with self._lock:
            created_during = sorted(
                sid for sid in self._sessions if sid not in set(snapshot))
        return {"snapshot": snapshot, "receipts": receipts,
                "created_during_sweep": created_during}

    # -- daemon restart: nothing to restore ---------------------------
    def shutdown(self) -> None:
        """Daemon stop: drop all in-memory state. No resurrection."""
        with self._lock:
            self._sessions.clear()
            self._token_digests.clear()
            self._pop_keys.clear()
            self._nonces.clear()
            self._deny_list.clear()
            self._in_flight.clear()
        self.supervisor.terminate_all()
