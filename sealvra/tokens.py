"""Session tokens and proof-of-possession (PoP) for Sealvra v0.1.

W03 module. Contract §4 and plan v3 §1C (N-C3) rules implemented here:

* Session tokens are opaque: ``"kh_sess_" + secrets.token_urlsafe(32)``.
  Only the SHA-256 hex digest of a token is ever stored; comparison uses
  ``hmac.compare_digest``. The token string itself is returned to the
  caller exactly once at session creation and is never logged, never
  written to disk, and never placed in an environment variable that
  survives the session.
* PoP: every proxied request must carry a valid HMAC-SHA256 over
  ``METHOD\\nHOST\\nCANONICAL_PATH\\nBODY_SHA256_HEX\\nTIMESTAMP``.
  Maximum timestamp skew is 300 seconds. Missing or invalid PoP is a
  deny, with no fallback to a bare bearer token.
* There is deliberately NO reveal path and NO clipboard credential path
  in this module (or anywhere in W03's files). Nothing here returns a
  real key, a token, or a PoP key after creation.

Tier note (contract §10): these controls hold against a Tier A
(interface-bound) agent. They do not, by themselves, separate same-user
(Tier B) processes; that separation comes from OS controls owned by
other workers (keychain access groups, OS-rendered prompts, sandboxes).

Only the Python standard library is used.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

TOKEN_PREFIX = "kh_sess_"
POP_MAX_SKEW_SECONDS = 300
POP_KEY_BYTES = 32


def generate_token() -> str:
    """Create a fresh opaque session token (returned exactly once)."""
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 hex digest of a token — the only form ever stored."""
    if not isinstance(token, str):
        raise TypeError("token must be a str")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token(presented: str, stored_hash: str) -> bool:
    """Constant-time comparison of a presented token against a stored hash.

    Returns False (never raises) for malformed input, so dead-token
    errors stay generic and reveal nothing about what exists.
    """
    if not isinstance(presented, str) or not isinstance(stored_hash, str):
        return False
    if not presented.startswith(TOKEN_PREFIX):
        return False
    try:
        presented_hash = hashlib.sha256(presented.encode("utf-8")).hexdigest()
    except Exception:
        return False
    return hmac.compare_digest(presented_hash, stored_hash)


def generate_pop_key() -> bytearray:
    """Fresh 32-byte PoP key, held in memory only (mutable so it can be zeroed)."""
    return bytearray(secrets.token_bytes(POP_KEY_BYTES))


# v0.2 lifecycle (W13, f05 L-17): resume rotates BOTH the session token
# and the PoP key, so a credential captured before suspension is dead
# after resume. The proxy reason for presenting a pre-rotation token
# is distinct from "session dead": the agent must re-read its session
# material, not ask the user for a new session.
ROTATED_SESSION_REASON = "session_rotated"


def rotate_pop_key(old_key: bytearray | None) -> bytearray:
    """Rotate a PoP key: zero the old key in place, return a fresh
    one. The old key must never be usable after this returns."""
    zero_secret(old_key)
    return generate_pop_key()


def zero_secret(buf: bytearray | None) -> None:
    """Best-effort zeroing of an in-memory secret buffer."""
    if buf is not None:
        for i in range(len(buf)):
            buf[i] = 0


def canonical_string(
    method: str,
    host: str,
    canonical_path: str,
    body_sha256_hex: str,
    timestamp: int,
) -> str:
    """The exact string PoP is computed over (contract §4)."""
    return "\n".join(
        [method.upper(), host, canonical_path, body_sha256_hex, str(int(timestamp))]
    )


def body_sha256_hex(body: bytes) -> str:
    """SHA-256 hex of a request body (empty body hashes as b\"\")."""
    if not isinstance(body, (bytes, bytearray)):
        raise TypeError("body must be bytes")
    return hashlib.sha256(bytes(body)).hexdigest()


def compute_pop(
    pop_key: bytes | bytearray,
    method: str,
    host: str,
    canonical_path: str,
    body: bytes,
    timestamp: int,
) -> str:
    """HMAC-SHA256 PoP hex for one request. Raises on bad input, never
    returns a fallback value."""
    if not isinstance(pop_key, (bytes, bytearray)) or len(pop_key) == 0:
        raise TypeError("pop_key must be non-empty bytes")
    if not method or not host or not canonical_path:
        raise ValueError("method, host and canonical_path are required")
    message = canonical_string(
        method, host, canonical_path, body_sha256_hex(body), int(timestamp)
    ).encode("utf-8")
    return hmac.new(bytes(pop_key), message, hashlib.sha256).hexdigest()


def sign_request(
    pop_key: bytes | bytearray,
    method: str,
    host: str,
    canonical_path: str,
    body: bytes,
    timestamp: int | None = None,
) -> tuple[str, int]:
    """Sign one request; returns (pop_hex, timestamp) for the headers."""
    ts = int(timestamp) if timestamp is not None else int(time.time())
    return compute_pop(pop_key, method, host, canonical_path, body, ts), ts


def verify_pop(
    pop_key: bytes | bytearray,
    method: str,
    host: str,
    canonical_path: str,
    body: bytes,
    timestamp: int | str | None,
    pop_hex: str | None,
    now: float | None = None,
) -> bool:
    """Validate one PoP value. False on missing/invalid input, stale or
    future timestamps outside the 300 s skew window, or a bad MAC.

    Replay protection (append-only nonce cache) lives in the session
    store, not here: this function is stateless, the store records each
    accepted (timestamp, pop_hex) pair per session for its lifetime.
    """
    if pop_hex is None or not isinstance(pop_hex, str):
        return False
    if not isinstance(pop_key, (bytes, bytearray)) or len(pop_key) == 0:
        return False
    try:
        ts = int(timestamp)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    now_s = int(now) if now is not None else int(time.time())
    if abs(now_s - ts) > POP_MAX_SKEW_SECONDS:
        return False
    try:
        expected = compute_pop(pop_key, method, host, canonical_path, body, ts)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, pop_hex)
