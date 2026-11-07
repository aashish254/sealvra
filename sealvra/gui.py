"""Sealvra — native control panel (W11, v0.2 remake).

One window, one process tree, zero terminals. This is a local control
panel for a running Sealvra service, not a marketing page: every
control maps to a daemon command, and every number on screen came from
the daemon or the log in this refresh cycle.

Normative sources: ``CONTRACT.md`` §1 (stdlib only, ``tkinter`` is the
GUI), §5, §6, §8, §9, §12 (W11), §13.1 (daemon IPC), and the v3 plan
(``SEALVRA-PLAN-V3-FINALCHECK.md``; v3 wins over v1/v2, deleted
passages are never built). What that means in this file:

* Stdlib ``tkinter``/``ttk`` only. No loopback web dashboard, no HTTP
  UI listener, no browser page (v3 N-O3 deletes that path). The window
  talks to the daemon over the §13.1 socket and nothing else.
* Read + kill only. No approval channel anywhere: approvals come ONLY
  from the broker-owned approver (W08). There is no approve control,
  and the only destructive action this window can take is kill, which
  needs no auth (§8).
* No key value and no session token is ever displayed, logged or
  handed to any other process. The vault never returns a secret to this
  process, so there is nothing here to mask and nothing here to give
  away; the Keys view shows what ``sealvra keys list`` shows (id,
  provider, label, 12-hex fingerprint, rotation state). There is no
  command in the product that puts a stored key value on screen, so no
  control for one exists here either.
* A key's user-chosen label appears ONLY in that key's own inspector
  pane, never in a shared list and never in an audit row (§12, v3 N-C9:
  global audit is pseudonym-only). Fingerprints are the first 12 hex
  chars of SHA-256(secret), shown for one key at a time.
* Kill semantics (§3/§8): new calls denied within 1 s, teardown within
  5 s. Calls already forwarded are NOT recalled; the receipt says so
  and lists them when the broker reports them.
* Trust copy (§9): "stops *key* theft, not *data* theft" and the
  "since import" counter. This window never invents a count: when the
  daemon does not report one, the screen says it is not reported.
* Threat tiers (§10): Tier A claims only (interface-bound agent).
  Nothing here — socket permissions, peer-UID checks — is cited as
  surviving Tier B, because it does not.
* ``connect_allowed`` sessions are labelled HOST-ONLY POLICY on every
  surface that shows them (§6): host + byte budget only; method/path
  policy is unenforceable inside a tunnel.
* Policy layering (§6, owner decision 2026-10-29): the signed pack
  decides; the runtime's GitHub deny floor can only ADD a refusal. The
  Service screen states this in plain words and offers no way to edit
  either layer.

Process model (the "zero terminals" rule, §12):
``main()`` opens exactly one window. The service it reads is either
attached (a daemon the CLI already started, on the conventional
rendezvous socket) or started by this window as its own child process
with stdout and stderr piped into the Log view. A child is never
launched in a terminal window, and closing the window stops the child
this window started, so no daemon is left listening behind the GUI. A
daemon this window only attached to keeps running: quitting never
destroys a service the GUI did not own, and the default quit choice is
Keep sessions.

Import safety (§12): importing this module opens no window, spawns no
process and does not need a display. ``tkinter`` is imported
defensively; window creation happens only in ``create_window()`` /
``main()``, which raise ``RuntimeError`` with code KH-3001 on a headless
machine instead of a raw TclError.

Tests pin the whole tkinter-free layer (``ViewModel``, the IPC client,
the render helpers), so rendering and kill wiring are asserted without
a display. Fake fixtures in tests use ``TEST-ONLY-`` prefixes only; no
real key ever appears in this file or in what it renders.
"""

from __future__ import annotations

import collections
import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

try:  # Defensive: importing this module must never need a display.
    import tkinter as _tk
    from tkinter import font as _tkfont
    from tkinter import messagebox as _messagebox
    from tkinter import ttk as _ttk

    _TK_AVAILABLE = True
except Exception:  # tkinter missing (minimal installs) — headless-safe.
    _tk = None  # type: ignore[assignment]
    _tkfont = None  # type: ignore[assignment]
    _messagebox = None  # type: ignore[assignment]
    _ttk = None  # type: ignore[assignment]
    _TK_AVAILABLE = False

__all__ = [
    "KeyView",
    "SessionView",
    "AuditEntryView",
    "GuiDataSource",
    "EmptyDataSource",
    "DaemonIpcError",
    "DaemonIpcClient",
    "DaemonIpcSource",
    "daemon_socket_from_env",
    "create_default_source",
    "create_live_source",
    "ServiceController",
    "ViewModel",
    "countdown_text",
    "render_key_list_line",
    "render_session_line",
    "render_audit_line",
    "isolation_card_text",
    "trust_screen_text",
    "kill_receipt_text",
    "assert_no_secret",
    "SealvraWindow",
    "create_window",
    "main",
    "TRUST_HEADLINE",
    "SINCE_IMPORT_LABEL",
    "DEFAULTS",
    "QUIT_DEFAULT",
    "QUIT_CONFIRM_DEFAULT",
    "NO_OS_AUTH_RULE",
    "WIRED_TOKEN_SHARE_WARNING",
    "COPY_SETUP_RULE",
    "WIRED_TOKEN_LIFECYCLE",
    "quit_confirmation_text",
]

TRUST_HEADLINE = "stops key theft, not data theft"
SINCE_IMPORT_LABEL = "Times any key has left this machine since import"

# Kill timing from CONTRACT §3 — quoted on every kill receipt.
KILL_DENY_SECONDS = 1
KILL_TEARDOWN_SECONDS = 5

# One defaults table (v3 §1M N-M5), mirrored verbatim from cli.py.
# This module owns GUI defaults only: it restates no number on its
# own, and the cross-module test asserts these shared keys equal
# cli.DEFAULTS. TTL per class with the 2 h absolute hard cap (no
# duration offer above 2 h anywhere); approval timeout 60 s default,
# 120 s accessibility opt-in only; session idle 5 min default,
# range 2-15 min, cannot be disabled, and NO vault-idle setting
# (deleted per v3 N-B3); update_check_default is None by design —
# G0 decision OD-13 is undecided and W17 owns the payload, so this
# window must not claim update checks on or off before the manager
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

# Plain language for the four access classes, in the voice of what the
# agent can do. The class id and its TTL pair stay in the inspector:
# taste-skill/app-screens is explicit that a table column reads as a
# sentence to a person who has never seen the schema, and app-screens
# also forbids hiding what a row can actually do behind an identifier.
# This mapping restates no policy -- it names the class the pack
# already enforces, so a wrong word here is a documentation bug, not a
# behaviour change, and tests/test_w11_gui.py pins all four keys to the
# classes DEFAULTS["ttl_minutes"] knows.
ACCESS_PLAIN = {
    "destructive": "Deletes or unrolls things",
    "write": "Can change things",
    "read_account": "Reads your account",
    "read_public": "Public reads only",
}


def access_plain(session_class: str) -> str:
    """The plain-language sentence for a class, or the class itself.

    An unknown class is shown as its own id rather than defaulted to a
    friendly phrase: guessing that an unrecognised class is harmless is
    exactly the mistake a control panel must not make.
    """
    return ACCESS_PLAIN.get(session_class or "", session_class or "—")


# Every coloured status is a glyph plus its word, never a colour alone
# (apple-design/accessibility.md: "nothing conveyed by colour alone").
# The ladder has three rungs and a resting state: green would say "act on
# this", so a row that asks nothing of you is left untinted rather than
# painted safe -- tinting it would inflate the ladder until the amber and
# red rows carried no information.
STATUS_GLYPH = {"warn": "▲", "deny": "✕", "live": "●"}
# The ttk tag whose foreground a role paints. There is deliberately no
# "allow" tag: the resting state carries no colour, so --foreground is
# applied to a whole row by the widget layer.
ROLE_TAG = {"warn": "warn", "deny": "deny"}
# A quiet session starts showing its idle clock when that deadline is
# within two minutes. The default idle is 5 minutes and the shortest TTL
# is 10, so without this the Status cell would count down a clock that
# can never actually arrive first.
IDLE_WARN_SECONDS = 120


def status_cell(role: str | None, text: str) -> str:
    """A status cell: the role's glyph, a space, then its word."""
    return f"{STATUS_GLYPH.get(role or 'live', '·')} {text}"


def session_status(session) -> tuple:
    """(ladder role, words) for one session row, worst state first."""
    if session.killed:
        return "deny", "Killed"
    if session.expires_at and session.expires_at - time.time() <= 0:
        return "deny", "Expired"
    if session.suspended:
        return "warn", "Waiting for approval"
    if session.idle_deadline:
        remaining = int(session.idle_deadline - time.time())
        if remaining <= IDLE_WARN_SECONDS:
            return "warn", f"Idle in {_duration(max(0, remaining))}"
    return None, "Live"


def key_status(key) -> tuple:
    """(ladder role, words) for one key row."""
    if key.rotation_warning:
        return "warn", "Rotate this key"
    if not key.header_verified:
        # Not "revoked": the header was not verified, which is the most
        # this window is allowed to claim about the provider's state.
        return "deny", "Auth header not verified"
    return None, "Safe to use"


def audit_status(entry) -> tuple:
    """(ladder role, words) for one audit record.

    The proxy writes decision as "allow" or "deny" and outcome as
    "relayed", "blocked" or "denied"; anything else a source supplies is
    shown as its own text rather than mapped to a rung, because inventing
    a friendly word for a value this build has never seen is how a
    security log starts lying.
    """
    decision = (entry.decision or "").lower()
    outcome = (entry.outcome or "").strip().lower()
    if decision == "allow":
        if outcome in ("", "relayed"):
            return None, "Allowed · relayed"
        return "warn", f"Allowed · {outcome}"
    if decision == "deny":
        if "approval" in outcome:
            return "warn", "Needs approval"
        if outcome in ("", "denied"):
            return "deny", "Denied"
        return "deny", f"Denied · {outcome}"
    if not decision:
        return None, (entry.event_type or "—")
    return None, f"{decision} · {outcome}" if outcome else decision



# Quit semantics (v3 §1M N-M2), shared with cli.py: quit defaults
# to Keep sessions, never to destruction. Closing this window never
# kills sessions belonging to a service it only attached to; stopping
# a child this window started is a separate, explicit consequence of
# closing, and the live session count is named in the dialog first.
QUIT_DEFAULT = "keep_sessions"
QUIT_CONFIRM_DEFAULT = "Keep sessions"

# The single no-OS-auth rule (v3 §1E N-E13), shared with cli.py:
# refuse. Competing fallbacks are deleted, not kept alongside it.
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

# The service log tail this window keeps in memory: bounded, newest
# last, and never a place a secret can settle (the daemon logs no
# request bodies, tokens or PoP keys).
LOG_TAIL_LINES = 600


def quit_confirmation_text(live_count: int | None = None) -> str:
    """Quit confirmation copy. The default choice is always Keep
    sessions; destruction is a separate, explicit action."""
    count = f"{live_count} live session(s) " if live_count is not None else "live sessions "
    return (
        f"Quitting closes this window but does not kill {count}or "
        "stop the daemon’s sessions. Default: Keep sessions. To end "
        "sessions, use the separate 'Quit and kill all' action."
    )

# Strings that must never appear as an actionable control in this
# window. "Approve" may appear only inside the explanatory sentence
# that this window cannot approve; no button/menu item may offer it.
_FORBIDDEN_ACTION_WORDS = ("approve", "reveal", "show token", "print token")


@dataclass(frozen=True)
class KeyView:
    """One key as the GUI may show it. No key value, ever."""

    key_id: str
    provider: str  # "github" | "gemini"
    pseudonym: str  # audit pseudonym, e.g. HMAC-derived, truncated
    fingerprint: str  # first 12 hex of SHA-256(secret); detail pane only
    label: str = ""  # shown ONLY in this key's own detail pane
    rotation_warning: bool = False  # NOT YET ROTATED (CONTRACT §9)
    # Vault metadata, present only when the daemon answers ``vault.list``.
    # Session-derived keys leave these blank rather than inventing one.
    created_at: str = ""
    header_verified: bool = True


@dataclass(frozen=True)
class SessionView:
    """One session as the GUI may show it. No token, no PoP key."""

    session_pseudonym: str
    key_pseudonym: str
    key_id: str
    provider: str
    session_class: str  # destructive | write | read_account | read_public
    transport: str = "absolute"  # absolute | connect_allowed
    expires_at: float = 0.0
    killed: bool = False
    in_flight_calls: tuple = ()
    # Daemon-side identifier used ONLY as the kill argument. It is
    # the internal session_id, never the token, and is never shown
    # as a label; when the daemon supplies no distinct id, the
    # pseudonym itself is used as the kill argument.
    session_id: str = ""
    created_at: float = 0.0
    idle_deadline: float = 0.0
    suspended: bool = False
    process_group: str = ""


@dataclass(frozen=True)
class AuditEntryView:
    """One audit entry as the GUI may show it. Pseudonym-only."""

    session_pseudonym: str
    key_pseudonym: str
    provider: str
    method: str
    canonical_path: str
    decision: str
    outcome: str
    # From the closed §8 schema, when the log reports them. Blank
    # rather than invented when the source has no such field.
    rule_id: str = ""
    event_type: str = ""
    seq: int = 0
    ts: str = ""


class GuiDataSource:
    """Duck-typed data source the window renders.

    The live implementation is a thin client over the daemon socket
    (§13.1). It must never return a key value or a session token; this
    module treats anything it returns as displayable, so a source that
    leaked a secret would be a bug in the source, caught by
    ``assert_no_secret`` in tests.
    """

    def list_keys(self):  # -> list[KeyView]
        return []

    def list_sessions(self, key_id=None):  # -> list[SessionView]
        return []

    def list_audit(self, key_pseudonym=None):  # -> list[AuditEntryView]
        return []

    def since_import_count(self):  # -> int
        return 0

    # Sources whose count is reported by the daemon set this True;
    # the IPC source leaves the class default via its own flag.
    since_import_known = True

    def audit_status(self):  # -> str | None; IPC sources override
        return None

    def service_status(self):  # -> dict | None; live sources override
        return None

    def log_text(self):  # -> str
        return ""

    def kill_session(self, session_pseudonym):  # -> bool
        return False

    def kill_key_sessions(self, key_id):  # -> int (sessions killed)
        return 0

    def kill_all(self):  # -> int (sessions killed)
        return 0


class EmptyDataSource(GuiDataSource):
    """No service reachable and none started: no keys, no sessions.

    Honest empty state — never invents demo keys or sessions, and every
    empty screen says what to do next instead of showing a blank grid.
    """


# ----------------------------------------------------------------------
# Daemon IPC client (CONTRACT §13.1 wire protocol, read + kill only)
# ----------------------------------------------------------------------

# Env var naming a daemon socket. Kept for callers that want to point
# the GUI at a non-default socket; ordinary discovery goes through the
# daemon's own rendezvous directory (see ``ServiceController``),
# because that is where a daemon started by the CLI actually is.
DAEMON_SOCKET_ENV = "SEALVRA_DAEMON_SOCKET"

# The one IPC command this read + kill-only client must never issue:
# session creation returns a token exactly once and is never a GUI
# operation. The client refuses it even if caller code asks for it.
_BLOCKED_IPC_COMMAND = "sessions.create"

# The audit tail asked for per refresh: bounded, like the widget that
# shows it. The daemon clamps it further.
AUDIT_PAGE_SIZE = 300


class DaemonIpcError(Exception):
    """A daemon IPC failure. ``code`` is a KH-xxxx code when the
    daemon supplied one, else None (transport failure: unreachable
    socket, timeout, malformed reply). Never carries a secret."""

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.code = code

    def __str__(self) -> str:
        return f"{self.code}: {super().__str__()}" if self.code else super().__str__()


def daemon_socket_from_env(environ=None) -> str | None:
    """Socket address from the environment, or None if unset/blank."""
    env = os.environ if environ is None else environ
    value = env.get(DAEMON_SOCKET_ENV)
    return value.strip() if value and value.strip() else None


class DaemonIpcClient:
    """Thin client over the §13.1 daemon IPC protocol.

    ``address`` is a Unix socket path (contains "/" or exists on
    disk) or a loopback TCP ``host:port`` string. One connection
    per request: send one NDJSON line, read one reply line (an
    EOF-terminated reply is also accepted, for tolerance). The
    reply ``id`` must echo the request ``id`` when present.
    ``transport`` is a test-only injection: a callable taking the
    request dict and returning the reply dict (or raising
    ``DaemonIpcError``); production code always uses sockets.
    This client has no session-creation operation by design.
    """

    def __init__(self, address: str | None = None, timeout: float = 5.0,
                 transport=None):
        self.address = address
        self.timeout = float(timeout)
        self._transport = transport
        self._next_id = 0

    def call(self, cmd: str, args=None):
        if cmd == _BLOCKED_IPC_COMMAND:
            raise ValueError(
                "GUI IPC client never issues session creation: "
                "it would return a token, which the GUI must never hold"
            )
        self._next_id += 1
        request = {"id": self._next_id, "cmd": cmd, "args": args or {}}
        if self._transport is not None:
            reply = self._transport(request)
        else:
            reply = self._socket_call(request)
        return self._check_reply(request, reply)

    @staticmethod
    def _check_reply(request, reply):
        if not isinstance(reply, dict):
            raise DaemonIpcError(f"malformed daemon reply: {reply!r}")
        if "id" in reply and reply["id"] != request["id"]:
            raise DaemonIpcError(
                f"daemon reply id {reply['id']!r} does not match "
                f"request id {request['id']!r}"
            )
        if not reply.get("ok", False):
            error = reply.get("error") or {}
            if isinstance(error, dict):
                raise DaemonIpcError(
                    error.get("message", "daemon reported an error"),
                    code=error.get("code"),
                )
            raise DaemonIpcError(str(error))
        return reply.get("result")

    def _socket_call(self, request):
        if not self.address:
            raise DaemonIpcError("no daemon socket address configured")
        try:
            sock = self._connect()
        except DaemonIpcError:
            raise
        except OSError as exc:
            raise DaemonIpcError(
                f"daemon IPC unavailable at {self.address!r}: {exc}"
            ) from exc
        try:
            sock.settimeout(self.timeout)
            sock.sendall((json.dumps(request) + "\n").encode())
            buf = b""
            while b"\n" not in buf:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout as exc:
                    raise DaemonIpcError(
                        "daemon IPC timed out waiting for a reply"
                    ) from exc
                if not chunk:  # EOF: accept a complete reply without newline
                    break
                buf += chunk
            line = buf.split(b"\n", 1)[0]
            if not line.strip():
                raise DaemonIpcError("daemon closed the connection with no reply")
            try:
                return json.loads(line.decode())
            except ValueError as exc:
                raise DaemonIpcError("daemon reply was not valid JSON") from exc
        except DaemonIpcError:
            raise
        except OSError as exc:
            raise DaemonIpcError(
                f"daemon IPC unavailable at {self.address!r}: {exc}"
            ) from exc
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _connect(self):
        address = self.address or ""
        if "/" in address or os.path.exists(address):
            if not hasattr(socket, "AF_UNIX"):
                raise DaemonIpcError("Unix sockets are not available here")
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(address)
            return sock
        if ":" in address:
            host, _, port = address.rpartition(":")
            if host not in ("127.0.0.1", "localhost", "::1"):
                raise DaemonIpcError(
                    f"daemon IPC is loopback-only; refusing {address!r}"
                )
            try:
                port_no = int(port)
            except ValueError as exc:
                raise DaemonIpcError(f"bad daemon TCP address {address!r}") from exc
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port_no))
            return sock
        raise DaemonIpcError(f"unrecognised daemon address {address!r}")

    # -- read + kill only ------------------------------------------------
    def status(self):
        return self.call("status")

    def ping(self):
        return self.call("ping")

    def doctor(self):
        return self.call("doctor")

    def list_sessions(self):
        result = self.call("sessions.list")
        if result is None:
            return []
        if isinstance(result, dict):
            return result.get("sessions", [])
        if isinstance(result, list):
            return result
        raise DaemonIpcError(f"unexpected sessions.list result: {result!r}")

    def kill_session(self, session_id: str):
        return self.call("sessions.kill", {"session_id": session_id})

    def kill_all(self):
        return self.call("sessions.kill_all")

    def audit_verify(self):
        return self.call("audit.verify")

    def audit_list(self, limit: int = AUDIT_PAGE_SIZE):
        result = self.call("audit.list", {"limit": int(limit)})
        if isinstance(result, dict):
            entries = result.get("entries")
            return entries if isinstance(entries, list) else []
        if isinstance(result, list):
            return result
        return []

    def vault_list(self):
        result = self.call("vault.list")
        if isinstance(result, dict):
            keys = result.get("keys")
            return keys if isinstance(keys, list) else []
        if isinstance(result, list):
            return result
        return []

    def packs_status(self):
        return self.call("packs.status")

    def stop_service(self):
        """Stop a daemon THIS WINDOW started. Never called on an
        attached one: quitting must not destroy a service the GUI did
        not own."""
        return self.call("daemon.stop")


def _as_float(value) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _session_view_from_ipc(entry) -> SessionView | None:
    """Map one sessions.list entry onto a SessionView, tolerantly.

    §13.1 names the command but not the result shape, so every
    field has a fallback. Pseudonyms are used when the daemon
    supplies them; otherwise the internal session_id is shown —
    it is NOT the token (CONTRACT §2), so showing it in the
    session's own row leaks no credential. In-flight calls pass
    through only when the daemon reports them.
    """
    if not isinstance(entry, dict):
        return None
    session_id = str(entry.get("session_id") or entry.get("id") or "")
    if not session_id and not entry.get("session_pseudonym"):
        return None
    in_flight = entry.get("in_flight_calls") or entry.get("in_flight") or ()
    if isinstance(in_flight, str):
        in_flight = (in_flight,)
    return SessionView(
        session_pseudonym=str(
            entry.get("session_pseudonym") or session_id),
        key_pseudonym=str(
            entry.get("key_pseudonym") or entry.get("key_id") or ""),
        key_id=str(entry.get("key_id") or ""),
        provider=str(entry.get("provider") or ""),
        session_class=str(entry.get("session_class") or ""),
        transport=str(entry.get("transport") or "absolute"),
        expires_at=_as_float(entry.get("expires_at")),
        killed=bool(entry.get("killed", False)),
        in_flight_calls=tuple(in_flight),
        session_id=session_id,
        created_at=_as_float(entry.get("created_at")),
        idle_deadline=_as_float(entry.get("idle_deadline")),
        suspended=bool(entry.get("suspended", False)),
        process_group=str(entry.get("process_group") or ""),
    )


def _audit_entry_from_ipc(entry) -> AuditEntryView | None:
    """Map one ``audit.list`` record onto an AuditEntryView.

    Only the §8 schema fields are read, each with a blank fallback, so
    a missing field shows as blank instead of being invented. The
    on-disk record already holds pseudonyms; this mapping does not
    change what the log holds.

    Chain and lifecycle events (``chain_created``, a kill receipt)
    legitimately carry no pseudonym, method or path. Dropping them
    would make the Activity screen silently omit exactly the rows an
    operator needs to see to judge whether the log is intact, so any
    record with something to say is kept.
    """
    if not isinstance(entry, dict):
        return None
    session_pseudonym = str(entry.get("session_pseudonym") or "")
    key_pseudonym = str(entry.get("key_pseudonym") or "")
    event_type = str(entry.get("event_type") or "")
    method = str(entry.get("method") or "")
    decision = str(entry.get("decision") or "")
    if not (session_pseudonym or key_pseudonym or event_type or method
            or decision):
        return None
    try:
        seq = int(entry.get("seq") or 0)
    except (TypeError, ValueError):
        seq = 0
    return AuditEntryView(
        session_pseudonym=session_pseudonym,
        key_pseudonym=key_pseudonym,
        provider=str(entry.get("provider") or ""),
        method=method,
        canonical_path=str(entry.get("canonical_path") or ""),
        decision=decision,
        outcome=str(entry.get("outcome") or ""),
        rule_id=str(entry.get("rule_id") or ""),
        event_type=event_type,
        seq=seq,
        ts=str(entry.get("ts") or ""),
    )


def _key_view_from_vault(entry, sessions_by_key) -> KeyView | None:
    """Map one ``vault.list`` record onto a KeyView.

    The audit pseudonym comes from the daemon's derived ``pseudonym``
    field, which is the same HMAC the audit chain uses, so a key row and
    its activity rows join. A daemon that predates that projection is
    not faked: the value falls back to a session's pseudonym for the
    same key and is blank when no session exists. Nothing here can carry
    a key value — ``vault.list`` returns authenticated header fields
    only.
    """
    if not isinstance(entry, dict):
        return None
    key_id = str(entry.get("key_id") or "")
    if not key_id:
        return None
    header_verified = entry.get("header_verified")
    pseudonym = str(entry.get("pseudonym") or "") or sessions_by_key.get(key_id, "")
    return KeyView(
        key_id=key_id,
        provider=str(entry.get("provider") or ""),
        pseudonym=pseudonym,
        fingerprint=str(entry.get("fingerprint") or "")[:12],
        label=str(entry.get("label") or ""),
        rotation_warning=bool(entry.get("needs_rotation", False)),
        created_at=str(entry.get("created_at") or ""),
        header_verified=True if header_verified is None else bool(header_verified),
    )


class DaemonIpcSource(GuiDataSource):
    """GuiDataSource backed by a DaemonIpcClient (read + kill only).

    Keys come from ``vault.list`` when the daemon answers it, with the
    real labels and 12-hex fingerprints; when it does not (an older
    daemon, or a vault that refuses to open) keys fall back to being
    derived from live sessions, and no label or fingerprint is invented
    for them. Activity comes from ``audit.list``; the chain verdict
    comes from ``audit.verify``. The since-import count is NOT reported
    over IPC, so ``since_import_known`` is False and the trust copy
    says so instead of claiming 0. Kill needs no auth (§8); a KH-1002
    kill (already gone) reports False rather than raising, because there
    is nothing left to kill.
    """

    since_import_known = False

    def __init__(self, client: DaemonIpcClient, controller=None):
        self.client = client
        self.controller = controller
        self._sessions_cache: list[SessionView] | None = None
        self._pseudonym_to_id: dict[str, str] = {}
        self.last_error: str | None = None

    def _fetch_sessions(self):
        views = []
        self._pseudonym_to_id = {}
        for entry in self.client.list_sessions():
            view = _session_view_from_ipc(entry)
            if view is None:
                continue
            views.append(view)
            # Kill addressing: the daemon's session_id when one
            # exists, else the pseudonym itself as the argument.
            self._pseudonym_to_id[view.session_pseudonym] = (
                view.session_id or view.session_pseudonym)
        self._sessions_cache = views
        return views

    def list_sessions(self, key_id=None):
        # Cache is refreshed by an explicit fetch; kills clear it.
        views = self._fetch_sessions()
        if key_id is None:
            return list(views)
        return [s for s in views if s.key_id == key_id]

    @staticmethod
    def _pseudonyms_by_key(views):
        by_key: dict[str, str] = {}
        for session in views:
            if session.key_id and session.key_pseudonym:
                by_key.setdefault(session.key_id, session.key_pseudonym)
        return by_key

    def list_keys(self):
        records: list = []
        try:
            records = self.client.vault_list()
        except DaemonIpcError as exc:
            if exc.code != "KH-2001":
                # A vault that refuses to open is reported, not hidden:
                # an empty Keys screen must never read as an empty
                # vault. An unknown command is simply an old daemon.
                self.last_error = str(exc)
        if records:
            by_key = self._pseudonyms_by_key(
                self._sessions_cache
                if self._sessions_cache is not None
                else self._fetch_sessions())
            keys = []
            for record in records:
                view = _key_view_from_vault(record, by_key)
                if view is not None:
                    keys.append(view)
            return keys
        # No vault projection available: derive keys from sessions and
        # invent nothing. Label and fingerprint stay blank, so the
        # inspector shows "(no label)" and "—" instead of a guess.
        if self._sessions_cache is None:
            self._fetch_sessions()
        seen: dict[str, KeyView] = {}
        for session in self._sessions_cache or []:
            if session.key_id and session.key_id not in seen:
                seen[session.key_id] = KeyView(
                    key_id=session.key_id,
                    provider=session.provider,
                    pseudonym=session.key_pseudonym,
                    fingerprint="",
                    label="",
                )
        return list(seen.values())

    def list_audit(self, key_pseudonym=None):
        try:
            records = self.client.audit_list()
        except DaemonIpcError as exc:
            if exc.code == "KH-2001":
                return []  # older daemon: no entry listing, not a fault
            raise
        entries = []
        for record in records:
            view = _audit_entry_from_ipc(record)
            if view is None:
                continue
            if key_pseudonym is not None and view.key_pseudonym != key_pseudonym:
                continue
            entries.append(view)
        return entries

    def audit_status(self) -> str:
        try:
            result = self.client.audit_verify()
        except Exception as exc:
            return f"Audit verify unavailable: {exc}"
        if isinstance(result, dict):
            verdict = result.get("status") or result.get("verdict") or "ok"
            # The count is appended only when the daemon actually
            # reports one: a bare {"status": "OK"} reply must render the
            # plain verdict, and a missing key must not read as "0
            # entries verified" (that would claim an empty chain).
            count = result.get("entries")
            detail = ""
            if count is not None:
                try:
                    number = int(count)
                except (TypeError, ValueError):
                    number = None
                if number is not None:
                    detail = (f" ({number} entry verified)" if number == 1
                              else f" ({number} entries verified)")
            return f"Audit verify: {verdict}{detail}"
        return f"Audit verify: {result}"

    def service_status(self) -> dict:
        """Everything the Service screen shows, read from the daemon.

        Three sections, each with its own error string: one failed read
        reports inside its section instead of blanking the whole screen.
        """
        sections: dict = {"daemon": {}, "doctor": {}, "packs": {},
                          "errors": {}}
        for name, fetch in (("daemon", self.client.status),
                            ("doctor", self.client.doctor),
                            ("packs", self.client.packs_status)):
            try:
                value = fetch()
            except Exception as exc:
                sections["errors"][name] = str(exc)
                continue
            if isinstance(value, dict):
                sections[name] = value
        sections["controller"] = {"ownership": self.ownership_text()}
        return sections

    def ownership_text(self) -> str:
        if self.controller is None:
            return "no service controller in this window"
        return self.controller.state_text()

    def log_text(self) -> str:
        if self.controller is None:
            return ""
        return self.controller.log_text()

    def since_import_count(self):
        # Not reported over IPC — the trust screen must say so
        # (see since_import_known); returning 0 here is only a
        # numeric fallback and is never displayed as a claim.
        return 0

    def kill_session(self, session_pseudonym):
        session_id = self._pseudonym_to_id.get(session_pseudonym)
        if session_id is None:
            self._fetch_sessions()
            session_id = self._pseudonym_to_id.get(
                session_pseudonym, session_pseudonym)
        self._sessions_cache = None
        try:
            self.client.kill_session(session_id)
        except DaemonIpcError as exc:
            if exc.code == "KH-1002":
                return False
            raise
        return True

    def kill_key_sessions(self, key_id):
        count, first_error = 0, None
        for session in self.list_sessions(key_id):
            if session.killed:
                continue
            try:
                if self.kill_session(session.session_pseudonym):
                    count += 1
            except DaemonIpcError as exc:
                if first_error is None:
                    first_error = exc
        if count == 0 and first_error is not None:
            raise first_error
        return count

    def kill_all(self):
        self._sessions_cache = None
        result = self.client.kill_all()
        if isinstance(result, int):
            return result
        if isinstance(result, dict):
            receipts = result.get("receipts")
            if isinstance(receipts, dict):
                return len(receipts)
            if isinstance(result.get("killed"), int):
                return result["killed"]
            snapshot = result.get("snapshot")
            if isinstance(snapshot, list):
                return len(snapshot)
            return 0
        return 0


def create_default_source() -> GuiDataSource:
    """Source for an explicit socket in the environment, else empty.

    Deliberately unchanged from the first W11 slice: it reads ONLY the
    environment, so a caller that constructs a source without naming a
    socket gets the honest empty source and no process is implied. The
    running app uses ``create_live_source()``, which follows the
    daemon's own rendezvous convention instead of a variable nobody sets.
    """
    address = daemon_socket_from_env()
    if address:
        return DaemonIpcSource(DaemonIpcClient(address))
    return EmptyDataSource()


def create_live_source(controller: "ServiceController | None" = None
                       ) -> GuiDataSource:
    """The app's real source: attach to the local service, or start it.

    With no reachable daemon and no controller able to start one, this
    is still the honest empty source — the window then says the service
    is stopped and offers the Start control, rather than rendering an
    invented dashboard.
    """
    address = daemon_socket_from_env()
    if address:
        return DaemonIpcSource(DaemonIpcClient(address), controller)
    controller = controller or ServiceController()
    controller.ensure_service()
    if controller.address:
        return DaemonIpcSource(
            DaemonIpcClient(controller.address, timeout=controller.timeout),
            controller)
    return EmptyDataSource()


# ----------------------------------------------------------------------
# Service controller: attach to a daemon, or own one as a child process
# ----------------------------------------------------------------------


class ServiceController:
    """The window's one process tree, or its attachment to one.

    Two states, always visible in the header chip and the Service
    screen:

    * ``attached`` — a daemon already answers on the conventional
      rendezvous (``$SEALVRA_DAEMON_DIR``, else ``~/.sealvra/daemon``,
      resolved by ``sealvra.daemon.daemon_dir()`` — the same function
      the CLI uses, so there is one convention, not two). This window
      reads and kills through it and owns no process: closing the
      window leaves that daemon running, because quitting never
      destroys a service this window did not start.
    * ``started`` — no daemon answered, so this window spawned
      ``sys.executable -m sealvra.daemon --serve`` as its OWN child
      with stdout and stderr piped into the Log view. No terminal is
      ever involved (no shell, no new session, no console window).
      Closing this window stops that child, so no daemon is left
      listening behind the GUI.

    ``detached`` is the only way a started child outlives the window,
    and the only way to set it is the explicitly labelled control in
    the Service screen. It is off by default: the tree goes with the
    window.
    """

    START_WAIT_S = 10.0
    STOP_WAIT_S = 4.0
    timeout = 5.0

    def __init__(self, environ=None, directory=None):
        self.environ = os.environ if environ is None else environ
        self._directory_override = Path(directory).expanduser() \
            if directory else None
        self.proc: subprocess.Popen | None = None
        self.owned = False
        self.detached = False
        self.address: str | None = None
        self.log: collections.deque = collections.deque(maxlen=LOG_TAIL_LINES)
        self.log_source = ""
        self.last_error: str | None = None
        self._lock = threading.Lock()
        self._reader: threading.Thread | None = None

    # -- rendezvous ---------------------------------------------------
    @staticmethod
    def _daemon_module():
        from . import daemon as daemon_module

        return daemon_module

    def directory(self) -> Path | None:
        if self._directory_override is not None:
            return self._directory_override
        try:
            return self._daemon_module().daemon_dir()
        except Exception as exc:  # pragma: no cover - import-time only
            self.last_error = f"daemon module unavailable: {exc}"
            return None

    def probe_address(self) -> str | None:
        """The address a daemon would answer on, or None.

        Existence of the socket (or the Windows port file) is enough to
        try; ``ensure_service`` then proves liveness with ``ping``, so
        a stale file left by a dead daemon is never taken as a service.
        """
        directory = self.directory()
        if directory is None:
            return None
        try:
            daemon_module = self._daemon_module()
            if daemon_module._use_unix_socket():
                path = directory / "control.sock"
                return str(path) if path.exists() else None
            port = daemon_module._read_port(directory)
            return f"127.0.0.1:{port}" if port else None
        except Exception as exc:
            self.last_error = f"rendezvous lookup failed: {exc}"
            return None

    def log_line(self, text: str) -> None:
        with self._lock:
            self.log.append(
                f"{time.strftime('%H:%M:%S', time.gmtime())}Z {text}")

    def log_text(self) -> str:
        with self._lock:
            return "\n".join(self.log)

    def log_snapshot(self) -> tuple[int, str]:
        """(line count, text) — the count lets the Log view append only
        what is new instead of rebuilding the widget on every tick."""
        with self._lock:
            return len(self.log), "\n".join(self.log)

    # -- lifecycle ----------------------------------------------------
    def ensure_service(self) -> str:
        """Attach to a live daemon, or start one and wait for it.

        Returns "attached", "started" or "failed". Never raises: an
        unreachable service is a state the window renders, not a crash.
        """
        address = self.probe_address()
        if address and self._alive(address):
            return self._attach(address)
        return self.start()

    def _alive(self, address: str) -> bool:
        try:
            DaemonIpcClient(address, timeout=2.0).ping()
            return True
        except Exception as exc:
            self.last_error = str(exc)
            return False

    def _attach(self, address: str) -> str:
        self.address = address
        self.owned = False
        self.proc = None
        self.log_source = self._daemon_log_file() or address
        self._start_log_tail()
        return "attached"

    def start(self) -> str:
        """Start the daemon as this window's child, or attach if a live
        one appeared meanwhile. Idempotent."""
        if self.proc is not None and self.proc.poll() is None:
            return "started"
        address = self.probe_address()
        if address and self._alive(address):
            return self._attach(address)
        directory = self.directory()
        if directory is None:
            return "failed"
        try:
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
        except OSError as exc:
            self.last_error = f"cannot prepare {directory}: {exc}"
            return "failed"
        root = Path(__file__).resolve().parent.parent
        env = dict(self.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [str(root)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
        cmd = [sys.executable, "-m", "sealvra.daemon", "--serve",
               "--dir", str(directory)]
        popen_kwargs = {
            "cwd": str(root), "env": env,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE, "stderr": subprocess.STDOUT,
            "close_fds": True, "text": False,
        }
        # A child of a GUI process must never flash a console window.
        # Windows-only branch, so NOT-RUN here: this build was verified
        # on macOS, where the child has no console to begin with.
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = getattr(
                subprocess, "CREATE_NO_WINDOW", 0x08000000)
        try:
            self.proc = subprocess.Popen(cmd, **popen_kwargs)
        except OSError as exc:
            self.last_error = f"could not start the service: {exc}"
            self.proc = None
            return "failed"
        self.owned = True
        self.detached = False
        self.log_source = "stdout + stderr of the service process this window started"
        self.log_line(f"gui: starting {' '.join(cmd[2:])} (pid {self.proc.pid})")
        self._reader = threading.Thread(target=self._read_pipe,
                                        name="sealvra-gui-log", daemon=True)
        self._reader.start()
        deadline = time.monotonic() + self.START_WAIT_S
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            candidate = self.probe_address()
            if candidate and self._alive(candidate):
                self.address = candidate
                self.log_line(f"gui: service answering on {candidate}")
                return "started"
            time.sleep(0.2)
        code = self.proc.poll()
        self.last_error = (
            f"service process did not answer within {self.START_WAIT_S:.0f}s "
            f"(exit={code}); see the Log view")
        return "failed"

    def _read_pipe(self) -> None:
        proc = self.proc
        if proc is None or proc.stdout is None:
            return
        with proc.stdout:
            for raw in iter(proc.stdout.readline, b""):
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").rstrip()
                if line:
                    self.log_line(line)
        self.log_line(f"[service process exited, code={proc.poll()}]")

    def _daemon_log_file(self) -> str | None:
        directory = self.directory()
        if directory is None:
            return None
        path = directory / "daemon.log"
        return str(path) if path.exists() else None

    def _start_log_tail(self) -> None:
        """For an attached daemon: tail ITS log file instead of a pipe.

        Read-only, and the Log view labels which source it is showing,
        so "piped from the process I started" and "tailing the file
        that daemon writes" are never confused on screen.
        """
        path = self._daemon_log_file()
        if not path:
            return
        if self._reader is not None and self._reader.is_alive():
            return

        def _tail() -> None:
            try:
                size = os.path.getsize(path)
            except OSError:
                return
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                handle.seek(max(0, size - 65536))
                while True:
                    line = handle.readline()
                    if not line:
                        time.sleep(1.0)
                        continue
                    stripped = line.rstrip()
                    if stripped:
                        self.log_line(stripped)

        self._reader = threading.Thread(target=_tail, name="sealvra-gui-tail",
                                        daemon=True)
        self._reader.start()

    def stop(self) -> str:
        """Stop the child this window started. Never touches an
        attached daemon."""
        if not self.owned or self.proc is None:
            return "attached" if self.address else "stopped"
        # The broker's own stop path is the documented teardown (it
        # kills worker process groups before exiting), so ask for it
        # before reaching for a signal. If the socket is already gone,
        # the terminate below still ends the process.
        try:
            if self.address:
                DaemonIpcClient(self.address, timeout=2.0).stop_service()
        except Exception as exc:
            self.log_line(f"graceful stop did not complete: {exc}")
        try:
            if self.proc.poll() is None:
                self.proc.terminate()
        except OSError as exc:
            self.last_error = f"terminate failed: {exc}"
        deadline = time.monotonic() + self.STOP_WAIT_S
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            time.sleep(0.1)
        try:
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait(timeout=2.0)
        except Exception as exc:  # pragma: no cover - last resort
            self.last_error = f"kill failed: {exc}"
        self.log_line("service process stopped by this window")
        self.owned = False
        self.address = None
        self.proc = None
        return "stopped"

    def shutdown_for_close(self) -> None:
        """What closing the window does to the process tree."""
        if self.owned and self.proc is not None:
            if self.detached:
                self.log_line("service left running: detach was chosen")
                self.owned = False
                return
            self.stop()

    def state_text(self) -> str:
        if self.proc is not None and self.proc.poll() is None and self.owned:
            return f"started by this window · pid {self.proc.pid}"
        if self.address:
            return f"attached · {self.address}"
        return "stopped · no daemon reachable"

    @property
    def running(self) -> bool:
        return bool(self.address)


# ----------------------------------------------------------------------
# Rendering helpers (pure text: pseudonyms, ids, counts — never secrets)
# ----------------------------------------------------------------------


def render_key_list_line(key: KeyView) -> str:
    """Centre-list line for a key: provider + pseudonym + fingerprint.

    Deliberately NOT the label: labels appear only in the owning
    key's detail pane, never in a list any other key shares.
    """
    fp = key.fingerprint[:12] if key.fingerprint else "—"
    warn = " · NOT YET ROTATED" if key.rotation_warning else ""
    return f"{key.provider} · {key.pseudonym} · fp {fp}{warn}"


def render_session_line(session: SessionView) -> str:
    """Session list line: pseudonyms + class + transport only."""
    host_only = " · HOST-ONLY POLICY" if session.transport == "connect_allowed" else ""
    state = "killed" if session.killed else "live"
    expiry = ""
    if session.expires_at:
        expiry = " · expires " + time.strftime(
            "%Y-%m-%d %H:%M UTC", time.gmtime(session.expires_at)
        )
    return (
        f"{session.session_pseudonym} · key {session.key_pseudonym} · "
        f"{session.provider} · {session.session_class}{host_only} · {state}{expiry}"
    )


def render_audit_line(entry: AuditEntryView) -> str:
    """Audit line: pseudonym-only, never a label or key fragment.

    The rule id is part of the audit record already (§8 schema) and is
    what makes a decision explainable, so it is shown when present.
    A lifecycle record (``chain_created``, a kill receipt) has no
    method or path, so its event type is shown in their place rather
    than rendering an empty row.
    """
    stamp = _stamp(entry.ts)
    prefix = f"{stamp} · " if stamp else ""
    rule = f" · rule {entry.rule_id}" if entry.rule_id else ""
    if entry.method or entry.canonical_path:
        call = f"{entry.provider} {entry.method} {entry.canonical_path}"
    else:
        call = f"event {entry.event_type or 'unknown'}"
    return (
        f"{prefix}{entry.session_pseudonym or '—'} · "
        f"key {entry.key_pseudonym or '—'} · "
        f"{call} · "
        f"{entry.decision or '—'}{rule} · {entry.outcome or '—'}"
    )


def countdown_text(expires_at: float, now: float | None = None) -> str:
    """Time left on a session, in d / m / s only.

    Deliberately no hour unit: the release grep gate treats bare hour
    figures as deleted TTL claims, so a countdown must never be able to
    print a string that reads like one.
    """
    if not expires_at:
        return "—"
    remaining = int(expires_at - (time.time() if now is None else now))
    if remaining <= 0:
        return "expired"
    days, rest = divmod(remaining, 86400)
    minutes, seconds = divmod(rest, 60)
    if days:
        return f"in {days}d {minutes:02d}m"
    if minutes:
        return f"in {minutes}m {seconds:02d}s"
    return f"in {seconds}s"


def _stamp(ts: str) -> str:
    """Short, sortable audit stamp for a table cell."""
    return (ts or "")[:19].replace("T", " ")


def isolation_card_text(session: SessionView) -> str:
    """Isolation card shown on EVERY session view (detail pane)."""
    host_note = ""
    if session.transport == "connect_allowed":
        host_note = (
            " HOST-ONLY POLICY: host + byte budget only; "
            "method/path/body policy is unenforceable in a tunnel."
        )
    return (
        "Isolated to one key: this session can use only the key "
        f"shown here ({session.key_pseudonym}, {session.provider}). "
        "Other keys are isolated from this session and are never "
        "shared with it. Tier A only: this protects against an "
        "interface-bound agent. It is not protection against a "
        "shell-capable same-user agent or a compromised OS account, "
        "which are out of scope by design."
        + host_note
    )


def trust_screen_text(since_import_count: int, known: bool = True) -> str:
    """Trust screen copy, using CONTRACT §9 wording.

    When ``known`` is False (the IPC source: the daemon reports no
    such count), no count is claimed at all — the line says so
    instead of printing a "0" the daemon never reported.
    """
    count_line = (
        f"{SINCE_IMPORT_LABEL}: {int(since_import_count)}"
        if known
        else f"{SINCE_IMPORT_LABEL}: not reported by the daemon "
        "(no count is claimed here)"
    )
    return (
        f"Sealvra {TRUST_HEADLINE}.\n"
        f"{count_line}\n"
        "This window is read + kill only. It cannot approve a "
        "request and it never shows a key value or a session token. "
        "Approvals come only from the broker-owned approver."
    )


def kill_receipt_text(killed_count: int, in_flight_calls=()) -> str:
    """Kill receipt: 1 s deny / 5 s teardown, in-flight not recalled."""
    lines = [
        f"Killed {int(killed_count)} session(s).",
        f"New calls are blocked within {KILL_DENY_SECONDS} second, "
        f"and teardown completes within {KILL_TEARDOWN_SECONDS} seconds.",
        "Calls already sent to the provider are not recalled; "
        "they run to completion.",
    ]
    if in_flight_calls:
        lines.append("Already-forwarded calls (run to completion):")
        lines.extend(f"  - {c}" for c in in_flight_calls)
    else:
        lines.append(
            "Already-forwarded calls: none reported by the broker "
            "for this kill (the broker, not this window, owns that list)."
        )
    return "\n".join(lines)


def assert_no_secret(rendered: str, secrets) -> None:
    """Guard used by tests: no known secret may appear in output."""
    for secret in secrets or ():
        if secret and secret in rendered:
            raise AssertionError("rendered GUI text contains a secret value")


# The deny floor, stated in the Service screen's own words. The rules
# themselves live in sealvra/runtime.py; this is prose over them, and
# the same decision recorded in CONTRACT §6 (owner, 2026-10-29).
DENY_FLOOR_NOTE = (
    "Two layers decide a call, in this order.\n"
    "1. The signed provider pack decides: level 1 allow, level 2 allow "
    "and log, level 3 needs the broker’s approval console, level 4 deny. "
    "A call the pack does not model is denied.\n"
    "2. On top of that, the runtime carries a deny floor for GitHub "
    "secrets: it can only ever refuse one more call. It cannot allow "
    "anything the pack denied, and it cannot change a pack.\n"
    "That floor lives in the program, not in a pack, because the signing "
    "key is rotate-only and its private half is gone: re-signing a pack "
    "to move the rules would break the trust root that makes packs "
    "trustworthy. There is no Gemini floor, and none is invented."
)

PACK_EDIT_NOTE = (
    "This window has no way to edit, sign or reload a pack, and no way "
    "to change a key or a policy. Packs are signed out-of-band and the "
    "trust root is read-only here; what this screen shows is what the "
    "daemon actually loaded."
)


def _cell(value) -> str:
    """A table cell from a daemon value: scalars verbatim, anything
    else as compact JSON. Never truncated into nothing."""
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float, str)):
        return str(value)
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


# ----------------------------------------------------------------------
# View model: the only thing the window reads from
# ----------------------------------------------------------------------


class ViewModel:
    """Presentation state over a GuiDataSource: reads, rows, receipts.

    No tkinter in this class, so the whole rendering contract —
    pseudonym-only lists, label-in-detail-only, kill wiring, refresh
    states — is testable headless (CONTRACT §11: a test that cannot run
    on a platform is NOT-RUN, never PASSED; this class is what runs).

    A refresh is atomic: ``state`` is ``loading`` while the source is
    being read, then exactly one of ``live`` / ``empty`` / ``error``. On
    ``error`` the previous rows are dropped rather than left on screen
    looking live — stale rows in a security panel are worse than no
    rows.
    """

    def __init__(self, source: GuiDataSource):
        self.source = source
        self.state = "loading"
        self.last_error: str | None = None
        self.keys: list[KeyView] = []
        self.sessions: list[SessionView] = []
        self.audit: list[AuditEntryView] = []
        self.service: dict | None = None
        self._loaded = False
        # When the snapshot on screen was read, for the footer's "refreshed
        # N s ago". A control panel that cannot say how stale it is telling
        # a lie by omission about a security tool.
        self.refreshed_at: float | None = None

    # -- refresh ------------------------------------------------------
    def refresh(self) -> str:
        """Read one snapshot. Returns the resulting state name."""
        self.state = "loading"
        try:
            keys = list(self.source.list_keys())
            sessions = list(self.source.list_sessions())
            audit = list(self.source.list_audit())
        except Exception as exc:  # DaemonIpcError, vault refusal, timeout
            self.last_error = str(exc) or exc.__class__.__name__
            self.keys, self.sessions, self.audit, self.service = [], [], [], None
            self.state = "error"
            self._loaded = True
            self.refreshed_at = time.time()
            return self.state
        self.keys, self.sessions, self.audit = keys, sessions, audit
        self.service = self._safe_service()
        self.refreshed_at = time.time()
        source_error = getattr(self.source, "last_error", None)
        self.last_error = str(source_error) if source_error else None
        # A daemon that answered but has nothing to show is LIVE with
        # empty tables, not "no daemon connected" — claiming the latter
        # would tell an operator their protection is off when it is on.
        # "empty" therefore means the opposite: nothing answered at all.
        # The screens say so in their own words (VIEW_NOT_RUNNING).
        has_data = bool(keys or sessions or audit)
        if has_data or self.service is not None:
            self.state = "live"
        else:
            self.state = "empty"
        self._loaded = True
        return self.state

    def _safe_service(self):
        try:
            return self.source.service_status()
        except Exception:
            return None

    def _ensure_loaded(self):
        if not self._loaded:
            self.refresh()

    # -- text surfaces (pinned by tests) ------------------------------
    def key_list_lines(self) -> list[str]:
        self._ensure_loaded()
        return [render_key_list_line(key) for key in self.keys]

    def session_list_lines(self) -> list[str]:
        self._ensure_loaded()
        return [render_session_line(s) for s in self.sessions]

    def audit_lines(self) -> list[str]:
        self._ensure_loaded()
        return [render_audit_line(entry) for entry in self.audit]

    def audit_snapshot(self) -> list[str]:
        """Pseudonym-only audit lines, newest first, as rendered."""
        self._ensure_loaded()
        return [render_audit_line(entry) for entry in self.audit]

    def per_key_access_log(self, key_pseudonym: str) -> list[str]:
        self._ensure_loaded()
        return [
            render_audit_line(entry)
            for entry in self.audit
            if entry.key_pseudonym == key_pseudonym
        ]

    def key_for_id(self, key_id: str) -> KeyView | None:
        self._ensure_loaded()
        for key in self.keys:
            if key.key_id == key_id:
                return key
        return None

    def sessions_for_key_id(self, key_id: str) -> list[SessionView]:
        self._ensure_loaded()
        return [s for s in self.sessions if s.key_id == key_id]

    def session_for_pseudonym(self, session_pseudonym: str):
        self._ensure_loaded()
        for session in self.sessions:
            if session.session_pseudonym == session_pseudonym:
                return session
        return None

    def detail_for_key(self, key_id: str) -> str:
        """Inspector text for one key. Its label appears HERE and only
        here — a shared list must never carry it (§12)."""
        self._ensure_loaded()
        key = self.key_for_id(key_id)
        if key is None:
            return "Key not found in this snapshot. Press Refresh."
        sessions = self.sessions_for_key_id(key_id)
        parts = [
            "KEY",
            f"Label      {key.label or '(no label stored)'}",
            f"Provider   {key.provider}",
            f"Pseudonym  {key.pseudonym or '(not reported by this daemon)'}",
            f"Reference  {key.key_id or '(not reported by this daemon)'}",
            "           (a terminal names a key with this reference, e.g. "
            "`sealvra keys rotate <reference>`)",
            f"Fingerprint {key.fingerprint[:12] or '—'} (first 12 hex of SHA-256)",
            f"Rotation   {'NOT YET ROTATED' if key.rotation_warning else 'current'}",
            f"Stored     {key.created_at or '(not reported by this daemon)'}",
            f"Auth header {('verified' if key.header_verified
                            else 'NOT VERIFIED — the key may be revoked at the provider')}",
            "",
            f"Sessions using this key: {len(sessions)}",
        ]
        parts.extend(f"  {render_session_line(s)}" for s in sessions)
        log = self.per_key_access_log(key.pseudonym)
        parts.append("")
        parts.append(f"Access log for this key ({len(log)} entries):")
        parts.extend(f"  {line}" for line in log[-15:])
        parts.extend([
            "",
            "No key value is shown here, and this window has no control "
            "that would show one. The vault never returns a secret to "
            "this process, so there is nothing to give away.",
        ])
        return "\n".join(parts)

    def detail_for_session(self, session_pseudonym: str) -> str:
        self._ensure_loaded()
        session = self.session_for_pseudonym(session_pseudonym)
        if session is None:
            return ("Session is no longer in this snapshot — it was "
                    "killed, expired, or never existed. Press Refresh.")
        log = self.per_key_access_log(session.key_pseudonym)
        ttl = DEFAULTS["ttl_minutes"].get(session.session_class or "")
        parts = [
            "SESSION",
            f"Pseudonym  {session.session_pseudonym}",
            f"On key     {session.key_pseudonym or '—'} "
            f"({session.provider or 'no provider reported'})",
            f"Access     {access_plain(session.session_class)}"
            + (f" · class id {session.session_class}"
               if session.session_class else ""),
            f"Time left  {countdown_text(session.expires_at)}",
            # Each line answers for one field the daemon reported, so a
            # person scanning the pane is not reading one run-on sentence
            # for five facts.
            f"Transport  {session.transport}"
            + (" — host + byte budget only; method and path are "
               "unenforceable in a tunnel"
               if session.transport == "connect_allowed" else ""),
            f"Class limit {f'{ttl[0]} min default, {ttl[1]} min maximum' if ttl else 'not a class this build lists'}",
            f"Idle ends  {self._idle_text(session)}",
            "",
            isolation_card_text(session),
            "",
        ]
        if session.in_flight_calls:
            parts.append("Already forwarded (not recalled):")
            parts.extend(f"  - {call}" for call in session.in_flight_calls)
        else:
            parts.append("Already forwarded: none reported by the broker.")
        parts.extend(["", f"Recent calls for this key ({len(log)}):"])
        parts.extend(f"  {line}" for line in log[-15:])
        parts.append("")
        parts.append("Killing blocks new calls within "
                     f"{KILL_DENY_SECONDS} second and tears down within "
                     f"{KILL_TEARDOWN_SECONDS} seconds.")
        return "\n".join(parts)

    def _idle_text(self, session) -> str:
        """The idle clock, as the daemon reported it or as a gap.

        A session with no idle deadline says so; the documented default
        is quoted as the rule, never as this session's state, because a
        pane that shows "5 min" for a session the daemon tracks
        differently would be inventing a number.
        """
        window = (f"{DEFAULTS['idle_default_minutes']} min is the default "
                  f"(range {DEFAULTS['idle_min_minutes']}-"
                  f"{DEFAULTS['idle_max_minutes']})")
        if not session.idle_deadline:
            return f"not reported by the daemon · {window}"
        remaining = int(session.idle_deadline - time.time())
        if remaining <= 0:
            return "elapsed · this session ends on the next tick"
        return (f"in {_duration(remaining)} with no calls · ends it "
                f"before the countdown · {window}")

    def detail_for_audit(self, entry: AuditEntryView) -> str:
        return "\n".join([
            "AUDIT ENTRY",
            render_audit_line(entry),
            "",
            f"Event type  {entry.event_type or '—'}",
            f"Sequence    {entry.seq or '—'}",
            "",
            "Audit rows are pseudonym-only by design: the log names the "
            "key and the session without naming either a label or a "
            "secret, so the log can be shared or backed up without "
            "leaking anything. Raw request bodies, tokens and PoP keys "
            "are not in this record.",
        ])

    def trust_text(self) -> str:
        return trust_screen_text(
            self.source.since_import_count(),
            known=getattr(self.source, "since_import_known", True))

    # -- status bar ---------------------------------------------------
    def status_text(self) -> str:
        self._ensure_loaded()
        stamp = time.strftime("%H:%M:%S %Z")
        live = len([s for s in self.sessions if not s.killed])
        entries = len(self.audit)
        counts = (f"{live} session(s) · {len(self.keys)} key(s) · "
                  f"{entries} audit " + ("entry" if entries == 1 else "entries"))
        if self.state == "loading":
            return f"Loading… · {counts}"
        if self.state == "error":
            return f"Error: {self.last_error} · nothing is shown from the previous snapshot"
        if self.state == "empty":
            return f"No daemon connected · {counts} · {stamp}"
        audit_line = ""
        status = getattr(self.source, "audit_status", None)
        if callable(status):
            try:
                audit_line = status() or ""
            except Exception as exc:
                audit_line = f"Audit verify unavailable: {exc}"
        return " · ".join(part for part in
                          (f"Live · {counts}", audit_line, stamp) if part)

    def service_chip_text(self) -> str:
        """Header chip: who owns the running service, in one line."""
        if self.service is None and self.state == "error":
            return "service unknown"
        if not (self.service and self.service.get("controller")):
            if self.state == "empty":
                return "service stopped"
            return "service reachable"
        ownership = self.service["controller"].get("ownership", "")
        return ownership or "service reachable"

    def quit_text(self) -> str:
        """Quit copy. Live count is the snapshot's unkilled sessions;
        the text never implies quitting kills them."""
        live = [s for s in self.sessions if not s.killed]
        return quit_confirmation_text(len(live))

    def wired_token_share_warning(self) -> str:
        return WIRED_TOKEN_SHARE_WARNING

    def copy_setup_note(self) -> str:
        return COPY_SETUP_RULE

    # -- kills (kill needs no auth; kill-all-first ordering) ----------
    def kill_plan(self, key_id=None):
        """Bulk kills ordered before individual kills in one cycle."""
        plan = [("kill-all", None)]
        if key_id:
            plan.append(("kill-key", key_id))
        return plan

    def kill_session(self, session_pseudonym: str) -> str:
        self._ensure_loaded()
        session = self.session_for_pseudonym(session_pseudonym)
        in_flight = tuple(session.in_flight_calls) if session else ()
        ok = self.source.kill_session(session_pseudonym)
        receipt = kill_receipt_text(1 if ok else 0, in_flight)
        self.refresh()
        return receipt

    def kill_key(self, key_id: str) -> str:
        count = self.source.kill_key_sessions(key_id)
        receipt = kill_receipt_text(count)
        self.refresh()
        return receipt

    def kill_all(self) -> str:
        count = self.source.kill_all()
        receipt = kill_receipt_text(count)
        self.refresh()
        return receipt

    # -- table rows ---------------------------------------------------
    # Every row is ``(display values, action target)``. The target is the
    # pseudonym, key id or snapshot index a click or kill needs; keeping
    # it beside the values means no view has to know which column hides
    # it, and a filtered table still points at the right record.
    def session_rows(self, query: str = "") -> list[tuple]:
        """(values, target, role) per live session.

        The third element is the ladder role the window paints -- "warn",
        "deny", or None for the resting state. It travels with the row
        because a colour decided by scanning a row's text for the word
        "deny" would also colour a path that merely contains it.
        """
        self._ensure_loaded()
        needle = (query or "").strip().lower()
        rows = []
        for session in self.sessions:
            role, words = session_status(session)
            values = (
                session.provider or "—",
                access_plain(session.session_class),
                status_cell(role, words),
                countdown_text(session.expires_at),
                session.key_pseudonym or "—",
            )
            if needle and needle not in " ".join(values).lower():
                continue
            rows.append((values, session.session_pseudonym, role))
        return rows

    def key_rows(self, query: str = "") -> list[tuple]:
        """(values, target, role) per key. No fingerprint, no label.

        The contract keeps the fingerprint in the owning key's detail pane
        only (CONTRACT §5 display rule, restated at cli.py:86-88), and
        ``render_key_list_line``'s rule -- a label appears in its own key's
        detail pane, never in a list the other keys share -- excludes the
        label here too, because this table is one list of every key. The
        pseudonym is the identifier the contract does allow a shared view
        to carry, so it is what identifies a row.
        """
        self._ensure_loaded()
        needle = (query or "").strip().lower()
        rows = []
        for key in self.keys:
            sessions = self.sessions_for_key_id(key.key_id)
            live = len([s for s in sessions if not s.killed])
            role, words = key_status(key)
            values = (key.provider or "—", key.pseudonym or "—",
                      status_cell(role, words), str(live))
            if needle and needle not in " ".join(values).lower():
                continue
            rows.append((values, key.key_id, role))
        return rows

    def audit_rows(self, query: str = "", role: str = "") -> list[tuple]:
        """(values, target, role) per audit record, newest first.

        ``role`` is the toolbar filter: "" shows every row, and "allow",
        "deny" or "warn" shows only that rung of the ladder. It narrows
        what is displayed and nothing else -- the audit file is not
        touched, cannot be rewritten from here, and has no delete.
        """
        self._ensure_loaded()
        needle = (query or "").strip().lower()
        rows = []
        for index, entry in enumerate(self.audit):
            path = entry.canonical_path or (
                f"({entry.event_type or 'event'})" if not entry.method else "")
            seq = "—" if entry.seq is None else str(entry.seq)
            row_role, words = audit_status(entry)
            values = (
                seq,
                _stamp(entry.ts),
                entry.method or "—",
                path,
                status_cell(row_role, words),
                entry.rule_id or "unmodelled",
            )
            if needle and needle not in " ".join(values).lower():
                continue
            if role and row_role != role:
                continue
            rows.append((values, index, row_role))
        return rows

    def audit_entry_at(self, index: int):
        """The snapshot entry a row index points at.

        The index is position in the snapshot, not the log's ``seq``:
        two records can share a seq (a backfilled bridge and its live
        twin) and a row that selected the wrong one would show the
        wrong evidence.
        """
        self._ensure_loaded()
        try:
            return self.audit[int(index)]
        except (TypeError, ValueError, IndexError):
            return None

    def service_rows(self) -> list[tuple]:
        """Flattened (section, field, value) — nothing here is invented.

        A section that failed to read shows its own error line instead
        of blanking the other two.
        """
        if not self.service:
            # No rows at all, so the screen shows its "the daemon
            # answered nothing" state with the fix, instead of a
            # one-line table that reads like a normal readout.
            return []
        rows = []
        errors = self.service.get("errors") or {}
        for section in ("daemon", "doctor", "packs"):
            payload = self.service.get(section) or {}
            error = errors.get(section)
            if error:
                rows.append(((section, "read failed", str(error)), None))
            if payload:
                for name in sorted(payload):
                    if name == "packs" and isinstance(payload[name], list):
                        for pack in payload[name]:
                            rows.append(((
                                "packs",
                                f"{pack.get('provider')} · {pack.get('file')}",
                                _pack_cell(pack)), None))
                        continue
                    if name == "trust_root" and isinstance(payload[name], dict):
                        trust = payload[name]
                        rows.append((("trust root", "key ids",
                                      ", ".join(trust.get("key_ids") or [])
                                      or trust.get("error") or "—"), None))
                        continue
                    value = payload[name]
                    if isinstance(value, dict):
                        # A nested config is one row per field: a wall of
                        # JSON in a cell is unreadable and unsearchable.
                        for sub in sorted(value):
                            rows.append(((section, f"{name}.{sub}",
                                          _service_cell(sub, value[sub])),
                                         None))
                        continue
                    rows.append(((section, name, _service_cell(name, value)),
                                 None))
        return rows

    def health_items(self) -> list[tuple]:
        """The three facts in the strip at the top of the window.

        Each is (value, label), and every value is counted or read here:
        the session count comes from the same snapshot the table shows,
        the proxy address comes from the daemon's own report and falls
        back to ``proxy.DEFAULT_PORT`` -- the number the code actually
        listens on -- and "masked" names what this window does with every
        key value.
        """
        self._ensure_loaded()
        live = len([s for s in self.sessions if not s.killed])
        daemon = (self.service or {}).get("daemon") or {}
        proxy = daemon.get("proxy") if isinstance(daemon, dict) else None
        port = proxy.get("port") if isinstance(proxy, dict) else None
        if not port:
            from .proxy import DEFAULT_PORT
            port = DEFAULT_PORT
        address = f"127.0.0.1:{port}" if self.state != "empty" else "not serving"
        return [(str(live), "sessions live"),
                (str(address), "local proxy"),
                ("masked", "key values")]

    def rail_counts(self) -> dict:
        """The counts at the right of the three data screens' rail rows."""
        self._ensure_loaded()
        return {"sessions": str(len([s for s in self.sessions
                                     if not s.killed])),
                "keys": str(len(self.keys)),
                "activity": str(len(self.audit))}

    def inspector_head(self, name: str, ident) -> tuple:
        """(title, subheading) for the selected row, or for no selection.

        The head is where the reference puts what you are looking at,
        because the detail body scrolls and a heading that scrolls away
        with it leaves a pane of unlabelled values.
        """
        self._ensure_loaded()
        if name == "sessions":
            session = self.session_for_pseudonym(ident)
            if session is None:
                return ("Session not in this snapshot",
                        "Press Refresh to read the daemon again.")
            _role, words = session_status(session)
            clauses = [words]
            # countdown_text already says "in 24m 58s"; prefixing another
            # "expires in" produced "expires in in 24m 58s", and "expired"
            # became "expires in expired".
            left = countdown_text(session.expires_at)
            if left == "—":
                clauses.append("no expiry reported")
            elif left.startswith("in "):
                clauses.append("expires " + left)
            else:
                clauses.append(left)
            if session.created_at:
                clauses.append(
                    "created "
                    + _duration(int(time.time() - session.created_at))
                    + " ago")
            return (f"{session.provider} · "
                    f"{access_plain(session.session_class).lower()}",
                    " · ".join(clauses))
        if name == "keys":
            key = self.key_for_id(ident)
            if key is None:
                return ("Key not in this snapshot",
                        "Press Refresh to read the vault again.")
            sessions = self.sessions_for_key_id(key.key_id)
            live = len([s for s in sessions if not s.killed])
            _role, words = key_status(key)
            imported = (f"imported {key.created_at}" if key.created_at
                        else "import date not reported")
            return (f"{key.provider} key · {key.pseudonym or '—'}",
                    f"{words} · {imported} "
                    f"· {live} of {len(sessions)} session(s) live")
        if name == "activity":
            entry = self.audit_entry_at(ident)
            if entry is None:
                return ("Entry not in this snapshot",
                        "Press Refresh; the rows shown are the previous ones.")
            _role, words = audit_status(entry)
            head = f"{entry.method or entry.event_type or 'event'}"
            path = entry.canonical_path or ""
            return (f"{head} {path}".strip(),
                    f"{words} · {_stamp(entry.ts)} · rule "
                    f"{entry.rule_id or 'unmodelled'}")
        return ("Nothing selected",
                "↑↓ moves through the rows · Enter opens one here")

    def service_document(self) -> list[tuple]:
        """The Service screen as (kind, text) lines.

        Rendered by a Text pane because ttk cannot draw a heading, a
        definition list and a paragraph inside one table cell. The data is
        the same ``service_rows`` the old three-column table showed; the
        sections give it the shape the reference draws, and every number
        is counted here or read from DEFAULTS rather than written into
        prose.
        """
        lines: list[tuple] = []
        if not self.service:
            return [("note", VIEW_EMPTY["service"])]
        rows = self.service_rows()
        for section, heading in (("daemon", "Running now"),
                                 ("doctor", "What the daemon checked"),
                                 ("packs", "Rule packs"),
                                 ("trust root", "Trust root")):
            picked = [values for values, _target in rows
                      if values[0] == section]
            if not picked:
                continue
            lines.append(("h2", heading))
            for _section, field, value in picked:
                lines.append(("dt", field))
                lines.append(("dd", value))
        ttl = DEFAULTS["ttl_minutes"]
        if ttl:
            lines.append(("h2", "Session lifetime"))
            lines.append(("lede",
                          "Each access class has a default and a maximum. You "
                          "can ask for less time, never more, and a session is "
                          "never extended — a new task gets a new session."))
            for name in ("read_public", "read_account", "write", "destructive"):
                if name not in ttl:
                    continue
                default, maximum = ttl[name]
                lines.append(("dt", ACCESS_PLAIN[name]))
                lines.append(("dd", f"{default} min default · "
                                    f"{maximum} min maximum"))
            lines.append(("note",
                          f"Nothing exceeds {DEFAULTS['hard_cap_minutes']} "
                          "minutes, whatever the class. A second clock runs "
                          "underneath: a session that goes quiet ends after "
                          f"{DEFAULTS['idle_default_minutes']} minutes with no "
                          "calls by default, and never more than "
                          f"{DEFAULTS['idle_max_minutes']}. That arrives sooner "
                          "than the countdown, so a quiet session shows it in "
                          "its Status cell."))
        lines.append(("h2", "Hard refusals"))
        lines.append(("lede",
                      "Four rules carry most of the safety, and none of them "
                      "can be turned off:"))
        for rule in (
                "A call the pack does not describe is denied. Absence of a "
                "rule is not permission, and the Activity row shows the rule "
                "as unmodelled.",
                "A denied call looks the same to the agent as any other "
                "denial. The agent gets a plain refusal with no reason; only "
                "this log says which rule stopped it.",
                "A key value never leaves the vault except at the last "
                "moment, inside the proxy, on a loopback connection. No "
                "screen here can show one, and this window has no control "
                "that would.",
                f"A kill takes effect within {KILL_DENY_SECONDS} second and "
                f"tears the worker down within {KILL_TEARDOWN_SECONDS}; a "
                "call already forwarded to the provider cannot be recalled."):
            lines.append(("dd", f"· {rule}"))
        lines.append(("note",
                      "Changing any of this is a command-line action on "
                      "purpose: it should be a deliberate act, not a click in "
                      "a window."))
        return lines

    def log_text(self) -> str:
        try:
            return self.source.log_text() or ""
        except Exception as exc:
            return f"(log unavailable: {exc})"

    def reference_text(self) -> str:
        """Standing copy shown when nothing is selected: what this
        window is, what it can do, and the layering it cannot change."""
        return "\n\n".join([
            "SEALVRA CONTROL PANEL",
            self.trust_text(),
            "What this window does: reads live sessions, keys, the "
            "audit log and service state from the local daemon, and "
            "kills sessions. What it never does: show a key value, "
            "show a session token, approve a request, edit a policy.",
            DENY_FLOOR_NOTE,
            PACK_EDIT_NOTE,
            self.quit_text(),
        ])


def _duration(seconds: int) -> str:
    """Compact age/idle text: d/h/m/s only, never a bare hour claim."""
    seconds = max(0, int(seconds))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        return f"{days}d {hours:02d}h"
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def _pack_cell(pack: dict) -> str:
    if not pack.get("loaded"):
        return f"NOT LOADED · {pack.get('error', 'unknown reason')}"
    return (f"v{pack.get('version', '?')} · {pack.get('endpoint_rules', '?')} "
            f"rules · issued {pack.get('issued_at', '—')} · "
            f"sha {pack.get('content_sha256', '—')} · "
            f"signed by {pack.get('signer_key_id', '—')}")


def _service_cell(name: str, value) -> str:
    """One daemon-reported value as a cell.

    An epoch stamp reads as a date, not as 1793308970.99, and a bool
    reads as yes/no; everything else is verbatim. Nothing here formats a
    value the daemon did not send.
    """
    if isinstance(value, (int, float)) and not isinstance(value, bool) \
            and name.endswith("_at"):
        return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(value))
    if isinstance(value, dict):
        return " · ".join(f"{key}={_cell(item)}"
                          for key, item in sorted(value.items()))
    return _cell(value)


# ----------------------------------------------------------------------
# Design system (one pairing, one accent, no decoration without a job)
#
# A control panel, not a landing page: dark graphite surface, one brass
# accent that means "this is the Sealvra chrome and nothing else",
# monospace for every identifier so a pseudonym reads as data rather
# than prose, and status colours reserved for the two things they
# actually describe — a call allowed, a call denied. No card nesting,
# no hero, no rounded containers: the structure on screen is the
# structure of the daemon.
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# The two arms of the design system, copied from the stylesheet that the
# reference screens are built with
# (design/mockups/sealvra.css, checked by design/qa/audit.cjs). The numbers
# are not decoration: every one of them survived a measurement pass that
# checked contrast on rendered pixels, so changing a value here without
# re-running that check is how the panel starts failing the 4.5:1 floor
# silently.
#
# `ash` and `hairline` are BORDER colours. They are never used for text:
# ash on canvas measures 3.5-3.6:1, which is fine for a rule and fails
# for a word. Text roles are ink, body and mute.
# ----------------------------------------------------------------------


class Palette:
    """One arm of the surface ladder. Attribute names match the CSS
    custom properties minus the leading dashes."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


DARK = Palette(
    name="dark",
    canvas="#07080a", surface="#0d0d0d", raised="#101111", row="#121212",
    select="#16222c", hairline="#242728", hairline_strong="#3a3d3f",
    ink="#f4f4f6", body="#cdcdcd", mute="#9c9c9d", ash="#6a6b6c",
    primary="#ffffff", primary_pressed="#e8e8e8", on_primary="#000000",
    allow="#59d499", deny="#ff6161", warn="#ffc533", info="#57c1ff",
)

LIGHT = Palette(
    name="light",
    canvas="#f9fafb", surface="#ffffff", raised="#f4f5f6", row="#ffffff",
    select="#dce9f7", hairline="#e8e8e8", hairline_strong="#d1d5db",
    ink="#111111", body="#24282c", mute="#5f6368", ash="#74787d",
    primary="#1d1f20", primary_pressed="#33363a", on_primary="#ffffff",
    allow="#04250e", deny="#831c1e", warn="#92400e", info="#0b4a6f",
)


def detect_palette(environ=None, run=None) -> Palette:
    """Pick the arm once, from the OS, and never offer a switch.

    Apple's dark-mode guidance is against an app-specific appearance
    setting for a reason: an app that ignores the system choice looks
    broken. Tk cannot honour it live -- 8.6 never consults the OS and
    draws light chrome regardless -- so the next best thing is to ask
    the OS once at launch. A mid-session flip would also leave every
    already-drawn Tk widget behind, which is the half-updated panel
    the guidance warns about.

    Linux has no portable single source, so it gets dark, which is the
    arm the ladder was designed in.
    """
    import subprocess
    import sys as _sys

    runner = run if run is not None else subprocess.run
    try:
        if _sys.platform == "darwin":
            # Exit 0 with "Dark" only when the key exists; its absence
            # is Apple's way of meaning Light.
            probe = runner(["defaults", "read", "-g", "AppleInterfaceStyle"],
                           capture_output=True, text=True, timeout=2)
            if probe.returncode != 0:
                return LIGHT
            return DARK if "dark" in (probe.stdout or "").lower() else LIGHT
        if _sys.platform == "win32":
            probe = runner(
                ["reg", "query", r"HKCU\\Software\\Microsoft\\Windows"
                                r"\\CurrentVersion\\Themes\\Personalize",
                 "/v", "AppsUseLightTheme"],
                capture_output=True, text=True, timeout=2)
            import re
            # The value is a DWORD and reg query pads it differently
            # across builds ("0x1" on some, "0x00000001" on others), so
            # parse the number instead of substring-matching it -- a
            # `in` test on "0x1" misses the padded form entirely.
            found = re.search(r"AppsUseLightTheme\s+REG_DWORD\s+0x([0-9a-fA-F]+)",
                              probe.stdout or "")
            if found is None:
                return DARK
            return LIGHT if int(found.group(1), 16) else DARK
    except Exception:
        # A failed probe is not a reason to show the wrong theme
        # confidently; fall back to the arm the ladder was designed in.
        return DARK
    return DARK


# Pixel sizes, not points: Tk takes a negative font size to mean pixels,
# and docs/DESIGN.md's scale is stated in CSS pixels, which is what the
# reference screens were measured in. Points would make the same number
# render about a third larger on macOS, and then the column widths below
# -- also ported from the reference -- would clip text the reference
# shows whole.
UI_SIZE = -14
MUTED_SIZE = -13
SMALL_SIZE = -12
H1_SIZE = -20
H2_SIZE = -15
MONO_SIZE = -13
# ttk applies rowheight to every row, uniformly -- a Treeview row cannot
# grow to fit wrapped prose the way a CSS table cell does. So the build
# takes the reference's 42px literally and puts prose where the toolkit
# can hold it: one clause per cell, the sentences in the inspector. The
# 26px this file used to ship could not hold a 14px line and its leading,
# which is why the old panel read as a wall of cut-off text.
ROW_HEIGHT = 42
CONTROL_HEIGHT = 30
# Window widths at which the optional column and the detail pane leave.
# Both numbers are binary-searched against rendered text, not arithmetic
# on character widths: design/qa/probe-widths.cjs in the design tree finds
# the lowest width at which nothing is cut, per screen, in all four states.
# The window may be smaller than these -- only the columns go.
# Activity is the binding screen at 1329px, so .opt hides at and below 1328.
OPT_COLUMN_MAX = 1328
INSPECTOR_MAX = 1073
# Window widths at which the whole panel stops pretending. WINDOW_MIN_WIDTH
# is the floor root.minsize enforces, so it cannot be reached by dragging;
# NARROW_NOTICE_MAX is where the reference draws a refusal instead of a
# squeezed table, and the build shows that same notice if a window manager
# ignores the minsize request -- a squeezed pseudonym is worse than none.
WINDOW_MIN_WIDTH = 760
WINDOW_MIN_HEIGHT = 480
NARROW_NOTICE_MAX = 759
RAIL_WIDTH = 196
HEALTHBAR_HEIGHT = 52
# Pane widths the sash is clamped to. The table's widest row needs
# 460 px to show a full 16-hex pseudonym; below that a session id is cut
# in half, which is worse than a short inspector.
TABLE_MIN_WIDTH = 460
INSPECTOR_MIN_WIDTH = 200
INSPECTOR_PREFERRED_WIDTH = 320

MONO_FAMILIES = ("Menlo", "Consolas", "DejaVu Sans Mono", "Courier New")

VIEWS = ("sessions", "keys", "activity", "service", "log")

VIEW_LABELS = {
    "sessions": "Sessions",
    "keys": "Keys",
    "activity": "Activity",
    "service": "Service",
    "log": "Log",
}

VIEW_SUBTITLE = {
    "sessions": "Live sessions on this machine. Kill one, a key’s, or all.",
    "keys": "Keys in the vault. Provider, pseudonym and rotation state — "
            "never a value, and never a label here: a label shows only "
            "in the one key’s own detail.",
    "activity": "Every call the proxy decided, pseudonym-only. Search the "
                "path, method, decision or rule.",
    "service": "What the daemon, the policy packs and the trust root "
               "actually report. Read-only.",
    "log": "stdout and stderr of the service, captured inside this window.",
}

VIEW_EMPTY = {
    "sessions": "No live sessions. Nothing is holding a key right now. "
                "Sessions are created by the broker’s CLI or approver, "
                "never by this window.",
    "keys": "No keys in the vault. Add one with `sealvra keys add` at a "
            "terminal, then press Refresh — importing a key is not "
            "something this window does.",
    "activity": "No audit entries yet. The first proxied call writes one. "
                "Press Refresh after an agent has made a request.",
    "service": "The daemon answered nothing. Use Start service below, or "
                "check that this machine can reach its rendezvous socket.",
    "log": "No service output captured yet. This panel shows the service "
           "process’s own stdout and stderr, line by line.",
}

VIEW_ERROR = ("The daemon did not answer, so nothing is listed. An empty "
              "table here would be a lie about a security tool, so the "
              "rows are gone until the next successful refresh. "
              "Press Refresh, or check the Service screen and the Log "
              "screen for why it stopped answering.")

# Shown instead of the per-screen "nothing to see" copy when the daemon
# never answered at all: an unread vault is not an empty vault, and
# telling someone to add a key they already have is how a control panel
# loses trust.
VIEW_NOT_RUNNING = (
    "No service is answering, so nothing here was read — this is not an "
    "empty vault or an empty session list. Open Service and press Start "
    "service, or read the Log screen for why it stopped answering.")

# The 360 px arm of the reference: a refusal, not a squeezed table. A
# session pseudonym cut mid-digit is the one thing a security panel must
# not show, so below the floor the rows are withdrawn entirely and the
# pane says why and what to do about it.
NARROW_NOTICE = (
    "Too narrow to show a row whole.\n\n"
    "A session pseudonym or an expiry countdown cut mid-character is worse "
    "than hidden, so this panel shows nothing at this width. Widen the "
    "window past {floor} px — or use `sealvra sessions` at a terminal, "
    "which wraps to any width."
).format(floor=WINDOW_MIN_WIDTH)


def _mono_family(root) -> str:
    for family in MONO_FAMILIES:
        try:
            if family in _tkfont.families(root):
                return family
        except Exception:
            break
    return "TkFixedFont"


def _ui_family(root) -> str:
    try:
        return _tkfont.nametofont("TkDefaultFont").actual("family")
    except Exception:
        return "TkDefaultFont"


class Theme:
    """ttk styles for the panel. Built once per window, from one palette.

    clam is used because it is the only built-in theme that honours
    explicit colours on every widget on every platform, so the panel
    looks like this file says it looks, not like whatever the desktop
    theme decided.

    Every colour comes off ``self.p`` and nowhere else, so a light-mode
    window can never be painted with dark ink.
    """

    def __init__(self, root, palette: Palette | None = None):
        self.p = palette or detect_palette()
        p = self.p
        self.ui_family = _ui_family(root)
        self.mono_family = _mono_family(root)
        mk = _tkfont.Font
        self.ui = mk(root=root, family=self.ui_family, size=UI_SIZE)
        self.ui_bold = mk(root=root, family=self.ui_family, size=UI_SIZE,
                          weight="bold")
        self.ui_small = mk(root=root, family=self.ui_family, size=SMALL_SIZE)
        self.muted = mk(root=root, family=self.ui_family, size=MUTED_SIZE)
        self.muted_bold = mk(root=root, family=self.ui_family,
                             size=MUTED_SIZE, weight="bold")
        self.h1 = mk(root=root, family=self.ui_family, size=H1_SIZE,
                     weight="bold")
        self.h2 = mk(root=root, family=self.ui_family, size=H2_SIZE,
                     weight="bold")
        self.mono = mk(root=root, family=self.mono_family, size=MONO_SIZE)
        self.mono_bold = mk(root=root, family=self.mono_family,
                            size=MONO_SIZE, weight="bold")
        self.root = root
        self._build()

    def _build(self):
        p = self.p
        style = _ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        # The surface ladder: canvas is the window, surface the panels that
        # sit on it, raised the interactive fill, row the table's ground.
        # Separation is one hairline or one tone step -- never a border plus
        # a shadow, and never a rounded container (docs/DESIGN.md).
        base = {"background": p.canvas, "foreground": p.ink,
                "bordercolor": p.canvas, "lightcolor": p.canvas,
                "darkcolor": p.canvas, "focuscolor": p.info,
                "troughcolor": p.raised, "font": self.ui}
        for name in ("TFrame", "TMainPane", "TPanedwindow"):
            try:
                style.configure(name, **base)
            except Exception:
                pass
        style.configure("Surface.TFrame", background=p.canvas)
        style.configure("Panel.TFrame", background=p.surface)
        style.configure("Raised.TFrame", background=p.raised)
        for label in ("TLabel", "Surface.TLabel", "Dim.TLabel",
                      "Heading.TLabel", "Title.TLabel", "Body.TLabel",
                      "Muted.TLabel"):
            style.configure(label, background=p.canvas, foreground=p.ink,
                            font=self.ui, borderwidth=0)
        style.configure("Dim.TLabel", foreground=p.mute, font=self.muted)
        style.configure("Muted.TLabel", foreground=p.mute, font=self.ui_small)
        style.configure("Body.TLabel", foreground=p.body, font=self.ui)
        style.configure("Heading.TLabel", font=self.h2, foreground=p.ink)
        style.configure("Title.TLabel", font=self.h1, foreground=p.ink)

        style.configure(
            "Treeview",
            background=p.row, fieldbackground=p.row, foreground=p.body,
            bordercolor=p.hairline, lightcolor=p.hairline,
            darkcolor=p.hairline, linecolor=p.row, rowheight=ROW_HEIGHT,
            font=self.mono, focuscolor=p.info, borderwidth=1)
        style.configure(
            "Treeview.Heading",
            background=p.canvas, foreground=p.mute, font=self.ui_small,
            relief="flat", bordercolor=p.hairline, lightcolor=p.canvas,
            darkcolor=p.canvas, padding=(12, 8))
        # Selection is its own hue (--select), not the accent, and the text
        # keeps its colour: inverting a row would turn an amber status word
        # white-on-blue and the ladder would stop meaning anything.
        style.map(
            "Treeview",
            background=[("selected", p.select)],
            foreground=[("selected", p.ink)])
        style.map("Treeview.Heading", foreground=[("active", p.ink)])

        # Buttons: raised fill, strong hairline, body-coloured text. The
        # destructive one is transparent with the negative hue, so red means
        # "this removes something", never "this is clickable".
        style.configure(
            "TButton", background=p.raised, foreground=p.body,
            bordercolor=p.hairline_strong, lightcolor=p.raised,
            darkcolor=p.raised, focuscolor=p.info, font=self.muted_bold,
            padding=(14, 6), relief="flat")
        style.map(
            "TButton",
            background=[("active", p.row), ("pressed", p.hairline),
                        ("disabled", p.canvas)],
            foreground=[("active", p.ink), ("disabled", p.mute),
                        ("focus", p.ink)],
            bordercolor=[("focus", p.info), ("active", p.ash),
                         ("disabled", p.hairline)])

        style.configure(
            "Primary.TButton", background=p.primary, foreground=p.on_primary,
            bordercolor=p.primary, lightcolor=p.primary,
            darkcolor=p.primary, focuscolor=p.ink, font=self.muted_bold,
            padding=(14, 6))
        style.map(
            "Primary.TButton",
            background=[("active", p.primary_pressed),
                        ("pressed", p.primary_pressed)],
            foreground=[("active", p.on_primary)],
            bordercolor=[("focus", p.ink)])

        style.configure(
            "Danger.TButton", background=p.canvas, foreground=p.deny,
            bordercolor=p.canvas, lightcolor=p.canvas, darkcolor=p.canvas,
            focuscolor=p.info, font=self.muted_bold, padding=(14, 6))
        style.map(
            "Danger.TButton",
            background=[("active", p.raised), ("pressed", p.raised)],
            foreground=[("active", p.deny), ("disabled", p.mute)],
            bordercolor=[("focus", p.info), ("active", p.deny),
                         ("disabled", p.hairline)])

        style.configure(
            "TEntry", fieldbackground=p.raised, foreground=p.ink,
            insertcolor=p.ink, bordercolor=p.hairline_strong,
            lightcolor=p.raised, darkcolor=p.raised, focuscolor=p.info,
            font=self.muted, padding=(10, 7))
        style.map("TEntry", bordercolor=[("focus", p.info)],
                  lightcolor=[("focus", p.info)],
                  darkcolor=[("focus", p.info)])

        # A rail item is a flat row: hue and weight carry the current
        # screen, not a filled pill. Unselected text is mute -- ash measured
        # 3.54:1 on the dark ladder, under the floor for text you must read,
        # so ash is reserved for borders.
        style.configure(
            "Rail.TRadiobutton", background=p.surface, foreground=p.mute,
            indicatorcolor=p.surface, indicatorbackground=p.raised,
            indicatorforeground=p.ink, selectcolor=p.info,
            bordercolor=p.surface, lightcolor=p.surface, darkcolor=p.surface,
            focuscolor=p.info, font=self.ui, padding=(16, 7))
        style.map(
            "Rail.TRadiobutton",
            background=[("selected", p.raised), ("active", p.raised)],
            foreground=[("selected", p.ink), ("active", p.body),
                        ("focus", p.ink)],
            bordercolor=[("focus", p.info)],
            indicatorcolor=[("selected", p.info)])

        # The activity filter is the same control shape as the rail, one
        # notch smaller and on the canvas rather than the surface, because
        # it sits in a toolbar and not in a navigation column. The
        # indicator stays visible: which rung is showing must be readable
        # without hovering.
        style.configure(
            "Filter.TRadiobutton", background=p.canvas, foreground=p.mute,
            indicatorcolor=p.canvas, indicatorbackground=p.raised,
            indicatorforeground=p.ink, selectcolor=p.info,
            bordercolor=p.canvas, lightcolor=p.canvas, darkcolor=p.canvas,
            focuscolor=p.info, font=self.ui_small, padding=(0, 6))
        style.map(
            "Filter.TRadiobutton",
            background=[("active", p.canvas)],
            foreground=[("selected", p.ink), ("active", p.body),
                        ("focus", p.ink)],
            bordercolor=[("focus", p.info)],
            indicatorcolor=[("selected", p.info)])

        style.configure(
            "Check.TCheckbutton", background=p.canvas, foreground=p.body,
            indicatorbackground=p.raised, indicatorforeground=p.ink,
            selectcolor=p.info, focuscolor=p.info, font=self.muted,
            # Without this the widget asks for 22px and is the only control in
            # the panel below the 28px touch floor the mockup enforces
            # (design/qa/audit.cjs fails a screen on it, and
            # design/qa/probe-tk-targets.py says the same of ttk). Six px each
            # side is what takes an indicator-plus-one-line control from 22 to
            # 28; the filter radiobuttons above carry the same padding.
            padding=(0, 6))
        style.map("Check.TCheckbutton", bordercolor=[("focus", p.info)],
                  foreground=[("active", p.ink)],
                  indicatorcolor=[("selected", p.info)])

        for name in ("Vertical.TScrollbar", "Horizontal.TScrollbar"):
            style.configure(
                name, background=p.raised, troughcolor=p.canvas,
                arrowcolor=p.mute, bordercolor=p.canvas,
                lightcolor=p.canvas, darkcolor=p.canvas,
                arrowsize=12, width=12)
            style.map(name, background=[("active", p.hairline),
                                        ("pressed", p.hairline)],
                      arrowcolor=[("disabled", p.hairline)])

        # The sash is a 1px hairline, not a 6px grip: the reference
        # separates the table from the inspector with one line, and a wide
        # grip of the canvas colour read as a dead band.
        style.configure("Vertical.TPanedwindow", background=p.canvas,
                        sashwidth=1, sashcolor=p.hairline,
                        bordercolor=p.canvas, lightcolor=p.canvas,
                        darkcolor=p.canvas)
        style.configure("Horizontal.TPanedwindow", background=p.canvas,
                        sashwidth=1, sashcolor=p.hairline,
                        bordercolor=p.canvas, lightcolor=p.canvas,
                        darkcolor=p.canvas)

    def text_colors(self, background: str | None = None):
        p = self.p
        ground = p.row if background is None else background
        return {"background": ground, "foreground": p.body,
                "insertbackground": p.ink,
                "highlightbackground": p.hairline,
                "highlightcolor": p.info, "relief": "flat"}

    def ink(self, role: str) -> str:
        """The text colour for a ladder role, off this palette."""
        return {"allow": self.p.allow, "deny": self.p.deny,
                "warn": self.p.warn, "info": self.p.info,
                "mute": self.p.mute, "body": self.p.body,
                "ink": self.p.ink, "ash": self.p.ash}.get(role, self.p.body)


# ----------------------------------------------------------------------
# The window
# ----------------------------------------------------------------------



# The rail in two named groups. Five words in a flat list made the last
# build hard to read: three screens show what the machine is protecting
# and two show the machine itself, and that is the sentence the group
# labels carry so the user does not have to find it.
RAIL_GROUPS = (
    ("What is protected", ("sessions", "keys", "activity")),
    ("This machine", ("service", "log")),
)

# Fixed column sets, with the reference's declared widths. Clipping here
# is a decision, not a side effect: a cell that can cut its value is a
# column whose full string the inspector shows instead. `.opt` columns
# leave below OPT_COLUMN_MAX and the detail pane below INSPECTOR_MAX,
# both measured against rendered text, not arithmetic on character widths.
# The widths are also a floor-sum: a tree narrower than the sum of its
# columns grows a horizontal scrollbar, so Keys - the one screen with no
# optional column to drop - is the screen where the sum has to pay. Its four
# mockup widths total 544px, which design/qa/probe-widths.cjs reports as
# needing 1060px of window with the detail pane open and reaching the 761px
# floor once the pane is gone. The Tk side is witnessed the same way -
# design/qa/probe-tk-widths.py builds the real window at every breakpoint
# and reads tree.xview(), so "FITS" means the tree is not showing a
# horizontal scrollbar.
# Each number is that column's widest value the build can print, measured
# with the real Tk font (tkfont.measure of the actual cell text) plus air,
# so the Tk integers and the mockup integers differ by a few px - they are
# the same decision rendered by two different text engines, and each was
# measured in its own. The Tk probe prints both sums against the real
# mapped tree width at every breakpoint.
TABLE_SPECS = {
    "sessions": {
        "columns": ("provider", "access", "status", "expires", "key"),
        "headings": {"provider": "Provider", "access": "Access",
                     "status": "Status", "expires": "Time left",
                     "key": "Key"},
        "widths": {"provider": 64, "access": 210, "status": 170,
                   "expires": 92, "key": 164},
        "anchors": {"expires": "e"},
        "opt": ("key",),
        "stretch": ("access",),
        "filter": ("provider", "access", "key"),
    },
    "keys": {
        "columns": ("provider", "ref", "rotation", "live"),
        "headings": {"provider": "Provider", "ref": "Key reference",
                     "rotation": "Rotation", "live": "Live sessions"},
        "widths": {"provider": 64, "ref": 164, "rotation": 218,
                   "live": 92},
        "anchors": {"live": "e"},
        "opt": (),
        "stretch": ("ref",),
        "filter": ("provider", "ref"),
    },
    "activity": {
        "columns": ("seq", "time", "method", "path", "result", "rule"),
        "headings": {"seq": "Seq", "time": "Time", "method": "Method",
                     "path": "Path", "result": "Result", "rule": "Rule"},
        "widths": {"seq": 46, "time": 78, "method": 62, "path": 130,
                   "result": 150, "rule": 286},
        "anchors": {"seq": "e"},
        "opt": ("rule",),
        "stretch": ("path",),
        "filter": ("method", "path", "result", "rule"),
    },
}

FILTER_PLACEHOLDER = {
    "sessions": "Filter by provider, access or key…",
    "keys": "Filter by provider or reference…",
    "activity": "Search method, path or rule…",
}

# The activity toolbar's rung filter. These are the row roles the
# view-model actually assigns (audit_status), so the buttons can only
# ever ask for a state this screen can show; "allow" is absent because a
# permitted call is the ordinary case and the ordinary case is "All".
AUDIT_FILTERS = (("", "All"), ("deny", "Denied"),
                 ("warn", "Needs attention"))

# The per-screen footer. It states the key binding that acts on the rows
# above it and one fact about what the screen does NOT hold, because that
# is the question a credential tool invites. The right-hand clause is the
# one that stops a misreading: this window shows history, it does not own
# it, and clearing a view clears nothing.
SCREEN_HINTS = {
    "sessions": "↑↓ select · Enter details · K kill, asks first",
    "keys": "↑↓ select · Enter details · K kills that key’s sessions",
    "activity": "↑↓ select · Enter details · the audit file is append-only — "
                "nothing here can rewrite it",
    "service": "read-only · changing any of this is a command-line act on purpose",
    "log": "↑↓ scroll · clearing this view does not delete the activity history",
}

class SealvraWindow:
    """One Tk window: nav rail, table pane, inspector, status bar.

    Every control calls one thing. Sessions and Keys act on the daemon;
    Activity is a search over ``audit.list``; Service renders
    ``status`` + ``doctor`` + ``packs.status`` and owns the process
    lifecycle; Log renders the captured pipe. Nothing here opens a
    browser, a second window or a terminal, and nothing here writes a
    key value anywhere.

    ``refresh_interval_ms`` drives the timed refresh (0/None disables
    it and leaves manual Refresh). A separate 1 s tick rewrites only
    the expiry column, so a countdown moves without re-reading the
    daemon every second.
    """

    def __init__(self, source: GuiDataSource | None = None,
                 refresh_interval_ms: int | None = 5000,
                 controller: "ServiceController | None" = None):
        if not _TK_AVAILABLE or _tk is None:
            raise RuntimeError(
                "KH-3001: tkinter is not available on this platform")
        try:
            self.root = _tk.Tk()
        except Exception as exc:  # e.g. TclError: no display
            raise RuntimeError(
                "KH-3001: no display available for the native GUI window"
            ) from exc
        self._owns_root = True
        if source is None:
            controller = controller or ServiceController()
            source = create_live_source(controller)
        self.controller = controller
        self.vm = ViewModel(source)
        self.refresh_interval_ms = refresh_interval_ms
        self._auto_refresh_id = None
        self._tick_id = None
        self._closing = False
        self.view = "sessions"
        # Created before the widgets so a toolbar can bind to it whatever
        # order the panes are built in.
        self.activity_role = _tk.StringVar(value="")
        self.follow_log = True
        self.wrap_log = True
        self._log_shown_lines = 0
        self._log_baseline = 0
        self.theme = Theme(self.root)
        self.p = self.theme.p
        self.views: dict[str, dict] = {}
        self._targets: dict[str, list] = {}
        # Which breakpoint arms are currently applied, so a resize that
        # changes neither runs no re-layout at all.
        self._opt_hidden = False
        self._inspector_hidden = False
        self._too_narrow = False
        self._suppress_select = False
        self._last_width = 0
        self.root.title("Sealvra")
        self.root.configure(bg=self.p.canvas)
        # 1360 px, not 1240: OPT_COLUMN_MAX is 1328, so a window that
        # opens narrower starts with the optional column already hidden
        # and the user never sees the full row the reference draws. The
        # breakpoints still do the work if the screen is smaller.
        self.root.geometry("1360x820")
        # The narrowest window that still shows a whole row: the 196 px
        # rail, a table whose widest column set needs 460 px to show a
        # full pseudonym, and nothing else. Below this the panel would cut
        # the expiry countdown mid-digit, so the window refuses to go
        # smaller rather than rendering a squeezed table. The reference
        # screen for that case (the 360 px arm) draws the refusal.
        self.root.minsize(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)
        try:
            self._build()
            self.vm.refresh()
            self._render_all()
            self._schedule_auto_refresh()
            self._schedule_tick()
        except BaseException:
            # A window that failed to finish building must not leave the
            # daemon it started listening behind.
            self.destroy()
            raise

    # -- structure ----------------------------------------------------
    def _build(self):
        root = self.root
        p = self.p
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        self._build_menu()
        self._build_healthbar()
        # Built before the views: a view's first render writes to both
        # ends of the footer, so the footer has to exist by then.
        status = _tk.Frame(root, bg=p.canvas, highlightthickness=0)
        status.grid(row=2, column=0, sticky="ew")
        _tk.Frame(status, bg=p.hairline, height=1).grid(row=0, column=0,
                                                        columnspan=2,
                                                        sticky="ew")
        inner = _tk.Frame(status, bg=p.canvas, highlightthickness=0)
        inner.grid(row=1, column=0, columnspan=2, sticky="ew")
        inner.columnconfigure(0, weight=1)
        self.status_bar = _tk.Label(
            inner, text="", bg=p.canvas, fg=p.mute, anchor="w",
            font=self.theme.ui_small, padx=24, pady=7, justify="left")
        self.status_bar.grid(row=0, column=0, sticky="ew")
        self.shortcuts = _tk.Label(
            inner, text="", bg=p.canvas, fg=p.mute,
            font=self.theme.ui_small, padx=24)
        self.shortcuts.grid(row=0, column=1, sticky="e")

        body = _tk.Frame(root, bg=p.canvas, highlightthickness=0)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(2, weight=1)
        body.rowconfigure(0, weight=1)
        self._build_rail(body)
        _tk.Frame(body, bg=p.hairline, width=1).grid(
            row=0, column=1, sticky="ns")

        paned = _ttk.Panedwindow(body, orient="horizontal")
        paned.grid(row=0, column=2, sticky="nsew")
        list_host = _tk.Frame(paned, bg=p.canvas, highlightthickness=0)
        self.inspector = self._build_inspector(paned)
        paned.add(list_host, weight=3)
        paned.add(self.inspector["frame"], weight=1)
        self.paned = paned
        # ttk panes have no minsize of their own: the sash is clamped on
        # every resize so the table never loses the width its columns
        # need, and a hand-dragged sash is left alone.
        paned.bind("<Configure>", self._clamp_sash)

        self.list_host = list_host
        list_host.columnconfigure(0, weight=1)
        list_host.rowconfigure(3, weight=1)
        self.view_title = _ttk.Label(list_host, text="",
                                     style="Title.TLabel")
        self.view_title.grid(row=0, column=0, sticky="w", padx=24,
                             pady=(16, 0))
        self.view_subtitle = _ttk.Label(list_host, text="",
                                        style="Dim.TLabel", justify="left",
                                        wraplength=620)
        self.view_subtitle.grid(row=1, column=0, sticky="w", padx=24,
                                pady=(3, 0))
        # The screen's own actions, under the heading and above the table:
        # taste-skill/app-screens puts controls where the data they act on
        # starts, not in window chrome 60 px away.
        toolbar_wrap = _tk.Frame(list_host, bg=p.canvas,
                                 highlightthickness=0)
        toolbar_wrap.grid(row=2, column=0, sticky="ew", pady=(4, 0))
        toolbar_wrap.columnconfigure(0, weight=1)
        self.toolbar_host = _tk.Frame(toolbar_wrap, bg=p.canvas,
                                      highlightthickness=0)
        self.toolbar_host.grid(row=0, column=0, sticky="ew", pady=(10, 10))
        self.toolbar_host.columnconfigure(1, weight=1)
        _tk.Frame(toolbar_wrap, bg=p.hairline, height=1).grid(
            row=1, column=0, sticky="ew")

        self.views_host = _tk.Frame(list_host, bg=p.canvas,
                                    highlightthickness=0)
        self.views_host.grid(row=3, column=0, sticky="nsew")
        self.views_host.columnconfigure(0, weight=1)
        self.views_host.rowconfigure(0, weight=1)

        # Covers every view when the window manager ignores minsize. It
        # shares the views' grid cell and is raised over them when shown;
        # it stays grid_remove()d until _apply_breakpoints asks for it.
        self.narrow_notice = _tk.Label(
            self.views_host, text=NARROW_NOTICE, bg=p.row, fg=p.body,
            font=self.theme.ui, justify="left", anchor="center",
            padx=32, pady=32)

        # Built before the views: each view parents its own controls
        # (filter box, kill buttons, service buttons) onto this row.
        for name in VIEWS:
            self.views[name] = (self._build_table_view(name)
                                if name in TABLE_SPECS
                                else self._build_document_view(name))
        self.show_view("sessions")

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        # The breakpoints are driven by the real mapped width, which the
        # window does not know at build time: an unmapped toplevel reports
        # a placeholder size, and laying out from that hid the optional
        # column and the whole detail pane of a window that then opened at
        # full width and never re-laid out.
        self.root.bind("<Configure>", self._on_configure)
        self._bind_keys()

    def _build_healthbar(self):
        """Live service state, one strip, 52 px, at the top of the window.

        Deliberately not a title bar: the OS window chrome already carries
        the app name and the screen's own heading says which screen you are
        on, so repeating "SEALVRA" here imitated chrome and said nothing
        (docs/DESIGN.md). What is left is the three facts that tell you
        whether this machine is holding your keys the way you set it up.
        """
        p = self.p
        outer = _tk.Frame(self.root, bg=p.canvas, highlightthickness=0)
        outer.grid(row=0, column=0, sticky="ew")
        outer.columnconfigure(0, weight=1)
        strip = _tk.Frame(outer, bg=p.surface, height=HEALTHBAR_HEIGHT,
                          highlightthickness=0)
        strip.grid(row=0, column=0, sticky="ew")
        strip.grid_propagate(False)
        _tk.Frame(outer, bg=p.hairline, height=1).grid(row=1, column=0,
                                                      sticky="ew")
        strip.columnconfigure(0, weight=1)
        items = _tk.Frame(strip, bg=p.surface, highlightthickness=0)
        items.grid(row=0, column=1, sticky="e", padx=24)
        self.health_cells = []
        for index in range(3):
            cell = _tk.Frame(items, bg=p.surface, highlightthickness=0)
            cell.grid(row=0, column=index, sticky="e",
                      padx=(0 if index == 0 else 24, 0))
            value = _tk.Label(cell, text="—", bg=p.surface, fg=p.body,
                              font=self.theme.muted_bold, anchor="e")
            value.grid(row=0, column=0, sticky="e")
            name = _tk.Label(cell, text="", bg=p.surface, fg=p.mute,
                             font=self.theme.muted, anchor="e")
            name.grid(row=0, column=1, sticky="e", padx=(6, 0))
            self.health_cells.append((value, name))

    def _build_rail(self, body):
        """Two labelled groups, five screens, each with its count.

        The groups are the difference between a list of five words and a
        map: three screens show what the machine is protecting, two show
        the machine itself. That is the sentence the old flat list made the
        user find for themselves.
        """
        p = self.p
        rail = _tk.Frame(body, bg=p.surface, width=RAIL_WIDTH,
                         highlightthickness=0)
        rail.grid(row=0, column=0, sticky="ns")
        rail.grid_propagate(False)
        rail.columnconfigure(0, weight=1)
        self.view_var = _tk.StringVar(value="sessions")
        self._rail_counts: dict[str, _tk.Label] = {}
        row = 0
        for group, names in RAIL_GROUPS:
            _tk.Label(rail, text=group, bg=p.surface, fg=p.mute,
                      font=self.theme.ui_small).grid(
                row=row, column=0, sticky="w",
                padx=16,
                pady=(12 if row else 8, 4))
            row += 1
            for name in names:
                holder = _tk.Frame(rail, bg=p.surface, highlightthickness=0)
                holder.grid(row=row, column=0, sticky="ew")
                holder.columnconfigure(0, weight=1)
                index = VIEWS.index(name) + 1
                button = _ttk.Radiobutton(
                    holder, text=f"{index}   {VIEW_LABELS[name]}",
                    value=name, variable=self.view_var,
                    style="Rail.TRadiobutton", takefocus=1,
                    command=lambda n=name: self.show_view(n))
                button.grid(row=0, column=0, sticky="w")
                count = _tk.Label(holder, text="", bg=p.surface, fg=p.mute,
                                  font=self.theme.ui_small)
                count.grid(row=0, column=1, sticky="e", padx=(0, 16))
                self._rail_counts[name] = count
                row += 1

    def _build_menu(self):
        """A real menu bar, carrying every command the window offers.

        designing-for-macos.md › menu-bar is explicit that a command has to
        be reachable from the menu bar; a row of in-window buttons is not a
        substitute for it, and on macOS the menu bar is also where a person
        looks for Quit first. The labels below are the same commands the
        toolbars and the inspector carry -- no command lives only here.
        """
        bar = _tk.Menu(self.root, tearoff=0)
        self.root.config(menu=bar)

        screen = _tk.Menu(bar, tearoff=0)
        for index, name in enumerate(VIEWS):
            screen.add_command(
                label=VIEW_LABELS[name], accelerator=f"⌘{index + 1}",
                command=lambda n=name: self.show_view(n))
        screen.add_separator()
        screen.add_command(label="Refresh", accelerator="⌘R",
                           command=self._manual_refresh)
        screen.add_separator()
        screen.add_command(label="Quit Sealvra", accelerator="⌘W",
                           command=self._on_close)
        bar.add_cascade(label="Screen", menu=screen)

        sessions = _tk.Menu(bar, tearoff=0)
        sessions.add_command(label="Kill selected session",
                             accelerator="⌘K",
                             command=lambda: self._kill_selected("sessions"))
        sessions.add_command(label="Kill all sessions",
                             command=self._on_kill_all)
        bar.add_cascade(label="Sessions", menu=sessions)

        service = _tk.Menu(bar, tearoff=0)
        service.add_command(label="Start service", command=self._on_start)
        service.add_command(label="Stop service", command=self._on_stop)
        service.add_command(label="Restart service", command=self._on_restart)
        service.add_separator()
        service.add_command(label="Full status",
                            command=self._on_full_status)
        bar.add_cascade(label="Service", menu=service)
        self._forbid_action_words(
            ("Refresh", "Quit Sealvra", "Kill selected session",
             "Kill all sessions", "Start service", "Stop service",
             "Restart service", "Full status",
             *(VIEW_LABELS[n] for n in VIEWS)))

    def _build_table_view(self, name: str) -> dict:
        p = self.p
        spec = TABLE_SPECS[name]
        frame = _tk.Frame(self.views_host, bg=p.canvas, highlightthickness=0)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        tree = _ttk.Treeview(frame, columns=spec["columns"], show="headings",
                             selectmode="browse")
        columns = self._apply_columns(tree, name)
        self._tag_rows(tree, name)
        vbar = _ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vbar.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        placeholder = _tk.Label(frame, text="", bg=p.row, fg=p.mute,
                                font=self.theme.ui, wraplength=520,
                                justify="left", padx=20, pady=24)
        tree.bind("<<TreeviewSelect>>",
                  lambda _e, n=name: self._on_select(n))
        tree.bind("<Return>", lambda _e, n=name: self._on_select(n))
        tree.bind("<Double-1>", lambda _e, n=name: self._on_select(n))
        tree.bind("<KeyRelease-k>",
                  lambda _e, n=name: self._kill_selected(n))
        actions = _tk.Frame(self.toolbar_host, bg=p.canvas,
                            highlightthickness=0)
        actions.grid(row=0, column=0, columnspan=3, sticky="ew")
        # 0 entry, 1 its placeholder, 2 the activity filter, 3 the
        # stretch that pushes the buttons to the right, 4-5 buttons.
        actions.columnconfigure(3, weight=1)
        labels = []
        entry = _ttk.Entry(actions, font=self.theme.mono, width=38)
        entry.grid(row=0, column=0, sticky="w")
        entry.bind("<KeyRelease>", lambda _e: self._render_view(name))
        entry.bind("<Return>", lambda _e: self._render_view(name))
        entry.bind("<Escape>", lambda _e: self._clear_search(entry))
        _ttk.Label(actions, text=FILTER_PLACEHOLDER[name],
                   style="Dim.TLabel").grid(row=0, column=1, sticky="w",
                                            padx=(8, 0))
        if name == "activity":
            group = _tk.Frame(actions, bg=p.canvas, highlightthickness=0)
            group.grid(row=0, column=2, sticky="w", padx=(20, 0))
            for column, (role, words) in enumerate(AUDIT_FILTERS):
                _ttk.Radiobutton(
                    group, text=words, style="Filter.TRadiobutton",
                    value=role, variable=self.activity_role
                ).grid(row=0, column=column, sticky="w")
                labels.append(words)
            self.activity_role.trace_add(
                "write", lambda *_a: self._render_view(name))
        if name == "sessions":
            kill_selected = _ttk.Button(
                actions, text="Kill selected",
                style="Danger.TButton",
                command=lambda: self._kill_selected("sessions"))
            kill_selected.grid(row=0, column=4, sticky="e", padx=(6, 0))
            self.kill_all_button = _ttk.Button(
                actions, text="Kill all", style="Danger.TButton",
                command=self._on_kill_all)
            self.kill_all_button.grid(row=0, column=5, sticky="e",
                                      padx=(6, 24))
            labels += ["Kill selected", "Kill all"]
        if name == "keys":
            kill_key = _ttk.Button(
                actions, text="Kill this key’s sessions",
                style="Danger.TButton",
                command=lambda: self._kill_selected("keys"))
            kill_key.grid(row=0, column=4, sticky="e", padx=(6, 24))
            labels.append("Kill this key’s sessions")
        self._forbid_action_words(tuple(labels))
        frame.grid_forget()
        return {"frame": frame, "tree": tree, "placeholder": placeholder,
                "toolbar": actions, "entry": entry,
                "columns": columns, "name": name}

    def _build_document_view(self, name: str) -> dict:
        """Service and Log: scrolling text, not a table.

        The reference draws both as documents -- sections with headings and
        a definition list on Service, one prefix-formatted line per event on
        Log. A ttk Treeview cannot render a heading, a two-column definition
        list and a paragraph in one pane, so these use a read-only Text
        widget with tagged lines, which can, and every line still comes from
        the same view-model methods the table screens use.
        """
        p = self.p
        frame = _tk.Frame(self.views_host, bg=p.canvas, highlightthickness=0)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        colors = self.theme.text_colors(p.surface)
        widget = _tk.Text(frame, bg=colors["background"],
                          fg=colors["foreground"],
                          insertbackground=colors["insertbackground"],
                          highlightbackground=p.hairline,
                          highlightcolor=p.info,
                          highlightthickness=1,
                          wrap=("word" if name == "log" or self.wrap_log
                                else "none"),
                          font=self.theme.mono, padx=16, pady=12,
                          takefocus=1, spacing1=2, spacing3=2, width=60,
                          tabs=(168, "left"))
        vbar = _ttk.Scrollbar(frame, orient="vertical", command=widget.yview)
        widget.configure(yscrollcommand=vbar.set)
        widget.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        t = self.theme
        widget.tag_configure("h2", foreground=p.ink, font=t.h2,
                             spacing1=10, spacing3=4)
        widget.tag_configure("lede", foreground=p.mute, font=t.muted,
                             spacing3=8)
        widget.tag_configure("dt", foreground=p.mute, font=t.muted)
        widget.tag_configure("dd", foreground=p.body, font=t.muted)
        widget.tag_configure("mono", foreground=p.body, font=t.mono)
        widget.tag_configure("stamp", foreground=p.mute)
        widget.tag_configure("error", foreground=p.deny)
        widget.tag_configure("warn", foreground=p.warn)
        widget.tag_configure("allow", foreground=p.allow)
        widget.tag_configure("note", foreground=p.mute, font=t.ui_small)
        widget.insert("1.0", VIEW_EMPTY[name])
        widget.configure(state="disabled")

        actions = _tk.Frame(self.toolbar_host, bg=p.canvas,
                            highlightthickness=0)
        actions.grid(row=0, column=0, columnspan=3, sticky="ew")
        actions.columnconfigure(2, weight=1)
        labels = []
        if name == "service":
            self.start_button = _ttk.Button(
                actions, text="Start service", command=self._on_start)
            self.start_button.grid(row=0, column=3, sticky="e", padx=(6, 0))
            self.stop_button = _ttk.Button(
                actions, text="Stop service", style="Danger.TButton",
                command=self._on_stop)
            self.stop_button.grid(row=0, column=4, sticky="e", padx=(6, 0))
            restart = _ttk.Button(actions, text="Restart service",
                                  command=self._on_restart)
            restart.grid(row=0, column=5, sticky="e", padx=(6, 0))
            full = _ttk.Button(actions, text="Full status",
                               command=self._on_full_status)
            full.grid(row=0, column=6, sticky="e", padx=(6, 0))
            self.detach_var = _tk.BooleanVar(value=False)
            _ttk.Checkbutton(
                actions, text="Leave the service running when I close "
                             "this window", variable=self.detach_var,
                style="Check.TCheckbutton",
                command=self._on_detach).grid(row=0, column=7, sticky="e",
                                              padx=(6, 24))
            labels += ["Start service", "Stop service", "Restart service",
                       "Full status"]
        else:
            self.follow_var = _tk.BooleanVar(value=True)
            _ttk.Checkbutton(actions, text="Follow", variable=self.follow_var,
                             style="Check.TCheckbutton",
                             command=lambda: self._drain_log()).grid(
                row=0, column=3, sticky="e", padx=(6, 0))
            self.wrap_var = _tk.BooleanVar(value=True)
            _ttk.Checkbutton(actions, text="Wrap", variable=self.wrap_var,
                             style="Check.TCheckbutton",
                             command=self._on_wrap_log).grid(
                row=0, column=4, sticky="e", padx=(6, 0))
            _ttk.Button(actions, text="Clear this view",
                        command=self._clear_log).grid(row=0, column=5,
                                                     sticky="e", padx=(6, 0))
            self.log_source_label = _ttk.Label(actions, text="",
                                              style="Dim.TLabel")
            self.log_source_label.grid(row=0, column=7, sticky="e",
                                       padx=(6, 24))
            labels += ["Follow", "Wrap", "Clear this view"]
        self._forbid_action_words(tuple(labels))
        frame.grid_forget()
        return {"frame": frame, "text": widget, "toolbar": actions,
                "entry": None, "placeholder": None, "tree": None,
                "name": name}

    def _apply_columns(self, tree, name: str) -> tuple:
        """Set the visible column set for the current width breakpoint.

        The column set is returned rather than written back into the
        module-level spec: two windows in one process can be at different
        widths, and a shared spec would make one resize change the other.
        """
        spec = TABLE_SPECS[name]
        columns = tuple(c for c in spec["columns"]
                        if not (self._opt_hidden and c in spec["opt"]))
        tree.configure(columns=columns)
        for column in columns:
            # Only the visible set: ttk rejects a heading or column
            # request for an identifier that is not in `columns`.
            tree.heading(column, text=spec["headings"][column])
            tree.column(
                column, width=spec["widths"][column],
                anchor=spec["anchors"].get(column, "w"),
                stretch=column in spec["stretch"],
                minwidth=spec["widths"][column] // 2)
        return columns

    def _tag_rows(self, tree, name: str) -> None:
        p = self.p
        for tag, colour in (("warn", p.warn), ("deny", p.deny),
                            ("allow", p.allow), ("dim", p.mute)):
            tree.tag_configure(tag, foreground=colour)

    def _clamp_sash(self, event=None) -> None:
        """Keep the table wide enough to read, on every window resize."""
        total = (int(event.width) if event is not None
                 else self.paned.winfo_width())
        if total <= 1 or self._inspector_hidden:
            return
        inspector_room = max(INSPECTOR_MIN_WIDTH,
                             min(INSPECTOR_PREFERRED_WIDTH,
                                 total - TABLE_MIN_WIDTH))
        try:
            self.paned.sashpos(0, total - inspector_room)
        except Exception:
            pass

    def _apply_breakpoints(self, width: int) -> None:
        """The two measured breakpoints, applied to the live widgets.

        ``.opt`` columns leave at 1328 px and below, the whole detail pane
        at 1073 px and below, and the panedwindow pane has to go with it:
        unmapping the detail frame inside its pane left its 320 px reserved
        and the table gained nothing, which is how the reference caught
        "Reads your account" clipping by 2 px at exactly that width. Both
        numbers come from design/qa/probe-widths.cjs, which binary-searches
        rendered text.
        """
        # An unmapped window reports width 1. Treating that as "narrow"
        # would hide the optional columns and the detail pane of a window
        # that is about to open at 1240 px, so an unmeasured width is
        # left exactly as the build laid it out.
        if width <= 1:
            return
        opt = width <= OPT_COLUMN_MAX
        pane = width <= INSPECTOR_MAX
        narrow = width <= NARROW_NOTICE_MAX
        if narrow != self._too_narrow:
            self._too_narrow = narrow
            if narrow:
                self.narrow_notice.grid(row=0, column=0, sticky="nsew")
                self.narrow_notice.tkraise()
            else:
                self.narrow_notice.grid_remove()
        if opt != self._opt_hidden or pane != self._inspector_hidden:
            was_hidden = self._inspector_hidden
            self._opt_hidden = opt
            self._inspector_hidden = pane
            for name in TABLE_SPECS:
                view = self.views.get(name)
                if view is not None:
                    view["columns"] = self._apply_columns(view["tree"], name)
            # Stored rows carry the values of the column set they were
            # inserted under, so a set change means the rows are redrawn.
            if self.view in TABLE_SPECS:
                self._render_view(self.view)
            if pane != was_hidden:
                # A ttk pane keeps its width when its child is unmapped,
                # so the pane itself is forgotten and re-added. The
                # inspector is always the second pane; re-adding it
                # anywhere else would move the table out from under the
                # sash clamp. panes() yields widget paths, not objects.
                child = str(self.inspector["frame"])
                panes = [str(pane) for pane in self.paned.panes()]
                if pane:
                    if child in panes:
                        self.paned.forget(self.inspector["frame"])
                else:
                    if child not in panes:
                        self.paned.add(self.inspector["frame"], weight=1)

    def _on_configure(self, event=None) -> None:
        if event is None or getattr(event, "widget", None) is not self.root:
            return
        # Only the final size of a resize is worth a re-layout: Tk fires
        # Configure for every pixel a drag or an animation moves, and a
        # width equal to the last one changes no breakpoint and no column,
        # so re-rendering every row for it is pure flicker.
        width = int(event.width)
        if width == self._last_width:
            return
        self._last_width = width
        self._apply_breakpoints(width)
        self.view_subtitle.configure(
            wraplength=max(320, int(event.width) - RAIL_WIDTH - 48))

    def _build_inspector(self, paned) -> dict:
        """Fixed head over a scrolling body, never one scrolling pane.

        The action used to sit at the bottom of a single scrolling region:
        at the 760x480 floor, "Kill this session" rendered about 90 px below
        the fold, and apple-design/sidebars.md is explicit that a sidebar
        must not put critical information or actions at its bottom. The head
        holds what you are looking at and the one thing you came to do; only
        the details scroll.
        """
        p = self.p
        frame = _tk.Frame(paned, bg=p.surface, highlightthickness=0)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(2, weight=1)
        head = _tk.Frame(frame, bg=p.surface, highlightthickness=0)
        head.grid(row=0, column=0, sticky="ew")
        head.columnconfigure(0, weight=1)
        self.insp_title = _tk.Label(head, text="", bg=p.surface, fg=p.ink,
                                    font=self.theme.h2, anchor="w",
                                    justify="left", wraplength=288)
        self.insp_title.grid(row=0, column=0, sticky="w", padx=16,
                             pady=(16, 2))
        self.insp_sub = _tk.Label(head, text="", bg=p.surface, fg=p.mute,
                                  font=self.theme.ui_small, anchor="w",
                                  justify="left", wraplength=288)
        self.insp_sub.grid(row=1, column=0, sticky="w", padx=16,
                           pady=(0, 0))
        self.insp_actions = _tk.Frame(head, bg=p.surface,
                                      highlightthickness=0)
        self.insp_actions.grid(row=2, column=0, sticky="w", padx=16,
                               pady=(10, 12))
        _tk.Frame(frame, bg=p.hairline, height=1).grid(row=1, column=0,
                                                       sticky="ew")
        body_host = _tk.Frame(frame, bg=p.surface, highlightthickness=0)
        body_host.grid(row=2, column=0, sticky="nsew")
        body_host.columnconfigure(0, weight=1)
        body_host.rowconfigure(0, weight=1)
        text = _tk.Text(body_host, bg=p.surface, fg=p.body,
                        insertbackground=p.ink,
                        highlightbackground=p.surface,
                        highlightcolor=p.info, highlightthickness=0,
                        wrap="word", font=self.theme.mono,
                        padx=16, pady=12, takefocus=1, width=40,
                        tabs=(116, "left"))
        bar = _ttk.Scrollbar(body_host, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=bar.set)
        text.grid(row=0, column=0, sticky="nsew")
        bar.grid(row=0, column=1, sticky="ns")
        t = self.theme
        text.tag_configure("h3", foreground=p.ink, font=t.muted_bold,
                           spacing1=10, spacing3=4)
        text.tag_configure("dt", foreground=p.mute, font=t.muted)
        text.tag_configure("dd", foreground=p.body, font=t.muted)
        text.tag_configure("mono", foreground=p.body, font=t.mono)
        text.tag_configure("dim", foreground=p.mute, font=t.ui_small)
        text.tag_configure("note", foreground=p.mute, font=t.ui_small,
                           spacing1=10)
        text.tag_configure("allow", foreground=p.allow)
        text.tag_configure("deny", foreground=p.deny)
        text.tag_configure("warn", foreground=p.warn)
        text.configure(state="disabled")
        return {"frame": frame, "text": text, "title": self.insp_title,
                "sub": self.insp_sub, "actions": self.insp_actions}

    # -- keys / focus -------------------------------------------------
    def _bind_keys(self):
        for index, name in enumerate(VIEWS):
            for modifier in ("Control", "Command"):
                self.root.bind(
                    f"<{modifier}-KeyPress-{index + 1}>",
                    lambda _e, n=name: self.show_view(n))
        for modifier in ("Control", "Command"):
            self.root.bind(f"<{modifier}-KeyPress-r>",
                           lambda _e: self._manual_refresh())
            self.root.bind(f"<{modifier}-KeyPress-k>",
                           lambda _e: self._kill_selected(self.view))
            self.root.bind(f"<{modifier}-KeyPress-w>",
                           lambda _e: self._on_close())
        self.root.bind("<Escape>", self._on_escape)

    def _forbid_action_words(self, labels) -> None:
        """Guard against an approval or key-showing control being added.

        The window may only ever offer read, kill, start/stop and
        search. If a future label names a forbidden action, this fails
        at build time rather than shipping a button that breaks §5/§12.
        """
        for label in labels:
            lowered = (label or "").lower()
            for word in _FORBIDDEN_ACTION_WORDS:
                if word in lowered:
                    raise AssertionError(
                        f"KH-3001: control label {label!r} offers a "
                        f"forbidden action ({word!r})")

    # -- rendering ----------------------------------------------------
    def show_view(self, name: str) -> None:
        if name not in self.views:
            return
        self.view = name
        self.view_var.set(name)
        for other in VIEWS:
            frame = self.views[other]["frame"]
            if other == name:
                frame.grid(row=0, column=0, sticky="nsew")
                frame.tkraise()
                if self._too_narrow:
                    # A view switch raises its frame over everything in
                    # this cell; the refusal must stay on top of it.
                    self.narrow_notice.tkraise()
            else:
                frame.grid_remove()
        for other in VIEWS:
            toolbar = self.views[other].get("toolbar")
            if toolbar is not None:
                toolbar.grid_remove()
        toolbar = self.views[name].get("toolbar")
        if toolbar is not None:
            toolbar.grid()
        self._render_view(name)
        self._render_header(name)
        tree = self.views[name].get("tree")
        if tree is not None:
            try:
                tree.focus_set()
            except Exception:
                pass

    def _render_header(self, name: str) -> None:
        self.view_title.configure(text=VIEW_LABELS[name])
        self.view_subtitle.configure(text=VIEW_SUBTITLE[name])
        freshness = ""
        if self.view == name:
            freshness = f" · {self._freshness_text()}"
        self.shortcuts.configure(text=SCREEN_HINTS[name] + freshness)
        if name == "sessions":
            live = len([s for s in self.vm.sessions if not s.killed])
            self.kill_all_button.configure(
                text=(f"Kill all {live}" if live else "Kill all"))

    def _freshness_text(self) -> str:
        """How stale the snapshot on screen is, in the footer's own words."""
        if self.vm.state == "loading":
            return "loading"
        if self.vm.refreshed_at is None:
            return "never refreshed"
        seconds = max(0, int(time.time() - self.vm.refreshed_at))
        if self.refresh_interval_ms:
            auto = f"auto {self.refresh_interval_ms / 1000:g} s"
        else:
            auto = "auto refresh off"
        return f"refreshed {seconds} s ago · {auto}"

    def _render_all(self) -> None:
        items = self.vm.health_items()
        for index, (value, name) in enumerate(self.health_cells):
            if index < len(items):
                value.configure(text=items[index][0])
                name.configure(text=items[index][1])
            else:
                value.configure(text="")
                name.configure(text="")
        counts = self.vm.rail_counts()
        for view_name, label in self._rail_counts.items():
            label.configure(text=counts.get(view_name, ""))
        self.status_bar.configure(text=self.vm.status_text())
        self._render_header(self.view)
        self._render_view(self.view)
        if not self._selected_detail():
            self._set_inspector(self.vm.reference_text(),
                                ("Nothing selected",
                                 "↑↓ moves through the rows · Enter opens "
                                 "one here"))

    def _render_view(self, name: str) -> None:
        view = self.views.get(name)
        if view is None:
            return
        if view.get("tree") is None:
            self._render_document(name, view)
            return
        tree = view["tree"]
        rows = self._rows_for(name)
        tree.delete(*tree.get_children())
        # Tk fills a row's cells in column order, so a hidden `.opt`
        # column must be dropped from the values too -- otherwise the
        # narrow arm shows the last column's text under the first
        # heading. The full tuple is built once, here, not per screen.
        spec = TABLE_SPECS[name]
        shown = view["columns"]
        positions = [spec["columns"].index(column) for column in shown]
        targets = []
        for index, (values, target, role) in enumerate(rows):
            # iid is the row index, not a value: two audit rows can share
            # a seq and a duplicate iid would drop one silently.
            tree.insert("", "end", iid=str(index),
                        values=tuple(values[position]
                                     for position in positions),
                        tags=ROLE_TAG.get(role) or ())
            targets.append(target)
        self._targets[name] = targets
        self._show_state(name, view, bool(rows))
        if rows and not self._suppress_select:
            # Auto-selecting queues a <<TreeviewSelect>> event, and a
            # receipt shown right after would be overwritten by it as soon
            # as Tk got round to it. A row detail replacing the receipt the
            # user just acted on is the bug this flag exists to stop.
            try:
                tree.selection_set(tree.get_children()[0])
            except Exception:
                pass

    def _render_document(self, name: str, view: dict) -> None:
        """Service and Log write themselves into a read-only Text pane."""
        widget = view["text"]
        if name == "log":
            self._drain_log()
            return
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        if self.controller is not None:
            widget.insert("end", self.controller.state_text(), "note")
            widget.insert("end", "\n")
        for kind, text in self.vm.service_document():
            widget.insert("end", text + "\n", kind)
        widget.configure(state="disabled")
        widget.see("1.0")

    def _rows_for(self, name: str):
        if name == "sessions":
            return self.vm.session_rows(self._query(name))
        if name == "keys":
            return self.vm.key_rows(self._query(name))
        if name == "activity":
            return self.vm.audit_rows(self._query(name),
                                      self.activity_role.get())
        return []

    def _query(self, name: str) -> str:
        entry = (self.views.get(name) or {}).get("entry")
        return entry.get() if entry is not None else ""

    def _show_state(self, name: str, view: dict, has_rows: bool) -> None:
        placeholder = view["placeholder"]
        if placeholder is None:
            return
        tree = view["tree"]
        if has_rows:
            placeholder.grid_remove()
            tree.grid()
            return
        needle = self._query(name).strip()
        if needle and self.vm.state != "error":
            message = (f"Nothing here matches {needle!r}. Press Escape in "
                       "the filter to show every row again.")
        elif self.vm.state == "error":
            message = VIEW_ERROR
            if self.vm.last_error:
                message = f"{message}\n\nLast error: {self.vm.last_error}"
        elif self.vm.state == "empty":
            message = VIEW_NOT_RUNNING
        else:
            message = VIEW_EMPTY[name]
        placeholder.configure(text=message)
        tree.grid_remove()
        placeholder.grid(row=0, column=0, sticky="nsew")

    def _set_inspector(self, text: str, head: tuple | None = None,
                       actions: tuple = ()) -> None:
        """Head above the fold, body below it.

        The head is set here rather than by each caller so a body and its
        title can never disagree: a pane that says one thing and labels
        itself with another is the failure this window cannot afford.
        """
        widget = self.inspector["text"]
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        lines = (text or "").split("\n")
        for index, line in enumerate(lines):
            # The first line is a heading only when it is one of the
            # fixed all-caps titles these detail builders start with; a
            # JSON dump's "{" must not render as a title.
            heading = (index == 0 and line.strip().isupper()
                       and 0 < len(line.strip()) <= 40)
            widget.insert("end", line + "\n",
                          ("h3" if heading else "dd"))
        widget.configure(state="disabled")
        widget.see("1.0")
        if head is not None:
            self.inspector["title"].configure(text=head[0])
            self.inspector["sub"].configure(text=head[1])
        host = self.inspector["actions"]
        for child in host.winfo_children():
            child.destroy()
        for column, (label, command, style) in enumerate(actions):
            _ttk.Button(host, text=label, command=command, style=style
                        ).grid(row=0, column=column, sticky="w",
                               padx=(0, 8))
        self._forbid_action_words(tuple(label for label, _, _ in actions))

    def _target_for(self, name: str, iid: str):
        """The value an action needs from a row (pseudonym, key id, index).

        Row identity lives in ``self._targets`` rather than in the Treeview
        iid, because two rows can legitimately carry the same value and a
        duplicate iid would silently drop one of them.
        """
        targets = self._targets.get(name) or []
        try:
            return targets[int(iid)]
        except (TypeError, ValueError, IndexError):
            return None

    def _selected_detail(self) -> bool:
        view = self.views.get(self.view)
        tree = view.get("tree") if view else None
        if tree is None:
            return False
        if not tree.selection():
            return False
        self._on_select(self.view)
        return True

    def _on_select(self, name: str) -> None:
        view = self.views.get(name)
        tree = view.get("tree") if view else None
        if tree is None:
            return
        selected = tree.selection()
        if not selected:
            return
        ident = self._target_for(name, selected[0])
        if ident is None:
            return
        head = self.vm.inspector_head(name, ident)
        if name == "sessions":
            self._set_inspector(self.vm.detail_for_session(ident), head,
                                (("Kill this session",
                                  lambda: self._kill_selected("sessions"),
                                  "Danger.TButton"),))
        elif name == "keys":
            live = len([s for s in self.vm.sessions_for_key_id(ident)
                        if not s.killed])
            actions = ()
            if live:
                actions = ((f"Kill its {live} session"
                            + ("s" if live != 1 else ""),
                            lambda: self._kill_selected("keys"),
                            "Danger.TButton"),)
            self._set_inspector(self.vm.detail_for_key(ident), head, actions)
        else:
            entry = self.vm.audit_entry_at(ident)
            self._set_inspector(
                self.vm.detail_for_audit(entry) if entry is not None
                else "This entry is no longer in the snapshot — press "
                     "Refresh; the rows shown are the previous ones.", head)

    def _on_full_status(self) -> None:
        """Every field the daemon reported, unformatted, in the inspector.

        The Service screen chooses which fields to show and words them;
        this is the escape hatch that shows all of them as they came back,
        so a choice made by this window is always reversible by the person
        looking at it.
        """
        self.show_view("service")
        self._set_inspector(json.dumps(self.vm.service or {}, indent=2,
                                       default=str, sort_keys=True),
                            ("Full status",
                             "Every field the daemon reported, exactly as it "
                             "answered"))

    # -- actions ------------------------------------------------------
    def _manual_refresh(self) -> None:
        self.vm.refresh()
        self._render_all()

    def _kill_selected(self, name: str) -> None:
        view = self.views.get(name)
        tree = view.get("tree") if view else None
        if tree is None:
            return
        selected = tree.selection()
        if not selected:
            self._show_receipt("Select a row first — nothing was killed.")
            return
        ident = self._target_for(name, selected[0])
        if ident is None:
            self._show_receipt("This row has nothing to kill.")
            return
        if name == "sessions":
            if not _messagebox.askyesno(
                    "Kill this session",
                    f"Kill session {ident}? New calls stop within "
                    f"{KILL_DENY_SECONDS} second and the connection tears "
                    "down within "
                    f"{KILL_TEARDOWN_SECONDS} seconds. Calls already "
                    "forwarded are not recalled."):
                return
            self._show_receipt(self.vm.kill_session(ident))
        elif name == "keys":
            if not _messagebox.askyesno(
                    "Kill this key’s sessions",
                    f"Kill every live session holding key {ident}? "
                    "New calls will be blocked within "
                    f"{KILL_DENY_SECONDS} second."):
                return
            self._show_receipt(self.vm.kill_key(ident))
        else:
            self._show_receipt(
                f"The {VIEW_LABELS[name]} screen has nothing to kill. "
                "Use Sessions or Keys.")

    def _on_kill_all(self) -> None:
        live = len([s for s in self.vm.sessions if not s.killed])
        if not _messagebox.askyesno(
                "Kill all sessions",
                f"Kill all {live} live session(s)? Every agent using a "
                f"key stops within {KILL_TEARDOWN_SECONDS} seconds. "
                "Calls already forwarded are not recalled."):
            return
        self._show_receipt(self.vm.kill_all())

    def _show_receipt(self, receipt: str) -> None:
        # Re-render first so the counts, the rail and the rows all describe
        # the state the action just caused, then put the receipt in the
        # detail pane -- with its own head, because a body that says
        # "RECEIPT" under a title that names a key is the disagreement this
        # pane cannot afford.
        self._suppress_select = True
        try:
            self._render_all()
        finally:
            self._suppress_select = False
        self._set_inspector(f"RECEIPT\n\n{receipt}\n\n"
                            f"{self.vm.status_text()}",
                            ("Receipt", receipt.splitlines()[0]))
        self.status_bar.configure(text=receipt.splitlines()[0]
                                 + " · " + self.vm.status_text())
        self._drain_log()

    def _on_start(self) -> None:
        if self.controller is None:
            self.status_bar.configure(
                text="No service controller in this window — this GUI "
                     "was opened against an explicit socket.")
            return
        outcome = self.controller.start()
        self._rebuild_source_from_controller()
        self.status_bar.configure(
            text=f"Start service: {outcome} · "
                 f"{self.controller.state_text()}")
        self._render_all()

    def _on_stop(self) -> None:
        if self.controller is None:
            self.status_bar.configure(text="No service controller here.")
            return
        if not self.controller.owned:
            self.status_bar.configure(
                text="This window only attached to the service; it will "
                     "not stop a daemon it did not start. Use "
                     "`sealvra daemon stop` for that.")
            return
        outcome = self.controller.stop()
        self._rebuild_source_from_controller()
        self.status_bar.configure(text=f"Stop service: {outcome}")
        self._render_all()

    def _on_restart(self) -> None:
        """Stop the child this window started, then start a fresh one.

        There is no ``controller.restart()`` on purpose: a restart is
        two named, separately audited actions, and the stop half must
        never touch a daemon this window only attached to.
        """
        if self.controller is None:
            self.status_bar.configure(text="No service controller here.")
            return
        if not self.controller.owned:
            self.status_bar.configure(
                text="This window only attached to the service; it will "
                     "not restart a daemon it did not start. Use "
                     "`sealvra daemon restart` for that.")
            return
        stopped = self.controller.stop()
        started = self.controller.start()
        self._rebuild_source_from_controller()
        self.status_bar.configure(
            text=f"Restart service: {stopped} then {started} · "
                 f"{self.controller.state_text()}")
        self._render_all()

    def _on_wrap_log(self) -> None:
        """Wrap long lines, or show the raw line and scroll sideways.

        The wrap state is decided here and read by the render path, so a
        wrapped pane and a straight pane cannot disagree about what the
        user asked for.
        """
        self.wrap_log = bool(self.wrap_var.get())
        for name in ("service", "log"):
            view = self.views.get(name)
            if view is not None:
                view["text"].configure(
                    wrap=("word" if name == "service" or self.wrap_log
                          else "none"))

    def _on_detach(self) -> None:
        if self.controller is None:
            return
        self.controller.detached = bool(self.detach_var.get())
        self.status_bar.configure(
            text=("Closing this window will leave the service running."
                  if self.controller.detached else
                  "Closing this window will stop the service this window "
                  "started."))

    def _rebuild_source_from_controller(self) -> None:
        """Point the view-model at whatever the controller now reaches.

        After Start the daemon is new, so the client must be new too;
        after Stop there is nothing to read, so the honest empty source
        returns. The controller object itself never changes, so the Log
        tail keeps running across both.
        """
        if self.controller is None:
            return
        if self.controller.address:
            client = DaemonIpcClient(self.controller.address,
                                     timeout=self.controller.timeout)
            self.vm.source = DaemonIpcSource(client, self.controller)
        else:
            self.vm.source = EmptyDataSource()
        self.vm._loaded = False
        self.vm.refresh()

    def _clear_search(self, entry) -> None:
        if entry is not None:
            entry.delete(0, "end")
        if self.view in TABLE_SPECS:
            self._render_view(self.view)

    def _clear_log(self) -> None:
        """Hide what the service printed so far.

        The next drain shows only the lines produced after this click,
        so "Clear view" means cleared and not instantly re-filled from
        the same buffer.
        """
        controller = getattr(self.vm.source, "controller", self.controller)
        self._log_baseline = (controller.log_snapshot()[0]
                              if controller is not None else 0)
        self._log_shown_lines = 0
        self._drain_log()

    def _drain_log(self) -> None:
        view = self.views["log"]
        widget = view["text"]
        controller = getattr(self.vm.source, "controller", self.controller)
        count, text = ("", "")
        if controller is not None:
            count, text = controller.log_snapshot()
        else:
            text = self.vm.log_text()
            count = len(text.splitlines()) if text else 0
        try:
            self.log_source_label.configure(
                text=(controller.log_source if controller is not None
                      else "no captured output: this window has no "
                           "service process"))
        except Exception:
            pass
        if not text:
            if self.vm.state == "error" and self.vm.last_error:
                self._write_log(text, count, error=self.vm.last_error)
            else:
                widget.configure(state="normal")
                widget.delete("1.0", "end")
                widget.insert("1.0", VIEW_EMPTY["log"])
                widget.configure(state="disabled")
            return
        if count and count == self._log_shown_lines:
            return
        if self._log_baseline:
            lines = text.splitlines()
            hidden = max(0, min(len(lines),
                                self._log_baseline - (count - len(lines))))
            text = "\n".join(lines[hidden:])
            if not text:
                widget.configure(state="normal")
                widget.delete("1.0", "end")
                widget.insert("1.0", "No service output since you cleared "
                                     "the view.")
                widget.configure(state="disabled")
                self._log_shown_lines = count
                return
        self._write_log(text, count)

    def _write_log(self, text: str, count: int, error: str = "") -> None:
        widget = self.views["log"]["text"]
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        body = text + (f"\n[last error: {error}]" if error else "")
        widget.insert("end", body)
        for line in range(1, int(widget.index("end-1c").split(".")[0]) + 1):
            content = widget.get(f"{line}.0", f"{line}.end").lower()
            if "error" in content or "denied" in content or "traceback" in content:
                widget.tag_add("error", f"{line}.0", f"{line}.end")
            elif "allow" in content:
                widget.tag_add("allow", f"{line}.0", f"{line}.end")
        widget.configure(state="disabled")
        self._log_shown_lines = count
        if self.follow_var.get():
            widget.see("end")

    def _on_escape(self, _event=None) -> None:
        view = self.views.get(self.view)
        if view is None:
            return
        tree = view.get("tree")
        if tree is not None and tree.selection():
            tree.selection_remove(tree.selection())
        if view.get("entry") is not None:
            self._clear_search(view["entry"])
        self._set_inspector(self.vm.reference_text(),
                            ("Nothing selected",
                             "↑↓ moves through the rows · Enter opens "
                             "one here"))

    # -- timers -------------------------------------------------------
    def _schedule_auto_refresh(self) -> None:
        if not self.refresh_interval_ms:
            self._auto_refresh_id = None
            return
        try:
            self._auto_refresh_id = self.root.after(
                int(self.refresh_interval_ms), self._auto_refresh)
        except Exception:
            self._auto_refresh_id = None

    def _auto_refresh(self) -> None:
        self._auto_refresh_id = None
        if self._closing or not self._alive():
            return
        self._manual_refresh()
        self._schedule_auto_refresh()

    def _schedule_tick(self) -> None:
        try:
            self._tick_id = self.root.after(1000, self._tick)
        except Exception:
            self._tick_id = None

    def _tick(self) -> None:
        self._tick_id = None
        if self._closing or not self._alive():
            return
        if self.view == "sessions":
            tree = self.views["sessions"]["tree"]
            # The tick walks the rows on screen, not the view-model's
            # list: with a filter active those two are different sets and
            # counting down by position would rewrite the wrong row.
            by_pseudonym = {s.session_pseudonym: s
                            for s in self.vm.sessions}
            for index, pseudonym in enumerate(
                    self._targets.get("sessions") or ()):
                session = by_pseudonym.get(pseudonym)
                if session is None:
                    continue
                try:
                    if tree.exists(str(index)):
                        tree.set(str(index), "expires",
                                 countdown_text(session.expires_at))
                except Exception:
                    continue
        self._drain_log()
        self._schedule_tick()

    def _alive(self) -> bool:
        try:
            return bool(self.root.winfo_exists())
        except Exception:
            return False

    # -- teardown -----------------------------------------------------
    def _on_close(self) -> None:
        """Closing the window: keep sessions is the default (§1M N-M2).

        A service this window STARTED is stopped with it, so no daemon
        is left listening behind a closed GUI — unless detach was
        explicitly chosen. A service this window only ATTACHED to keeps
        running: quitting never destroys something the GUI did not own.
        """
        if self._closing:
            return
        self._closing = True
        try:
            self.vm.refresh()
        except Exception:
            pass
        if _messagebox is not None:
            if not _messagebox.askyesno(
                    f"Quit Sealvra — {QUIT_CONFIRM_DEFAULT}",
                    self.vm.quit_text()):
                self._closing = False
                return
        self.destroy()

    def quit_and_kill_all(self) -> None:
        """Separate, explicit destruction path — never the default."""
        if _messagebox is not None and not _messagebox.askyesno(
                "Quit and kill all sessions",
                "Kill every live session and quit? This ends every "
                "session on this machine."):
            return
        self._show_receipt(self.vm.kill_all())
        self._closing = True
        self.destroy()

    def destroy(self) -> None:
        for attribute in ("_auto_refresh_id", "_tick_id"):
            timer_id = getattr(self, attribute, None)
            if timer_id:
                try:
                    self.root.after_cancel(timer_id)
                except Exception:
                    pass
                setattr(self, attribute, None)
        self._closing = True
        if self.controller is not None:
            self.controller.shutdown_for_close()
        if self._owns_root:
            try:
                self.root.destroy()
            except Exception:
                pass

    def run(self) -> None:
        try:
            self.root.mainloop()
        finally:
            self.destroy()

    # -- test-visible aliases (the W11 three-pane contract) -----------
    @property
    def listbox(self):
        """The widget the current screen shows its rows in.

        Tables are a Treeview; Service and Log are read-only Text panes
        that hold one line per row. Both are "the list" from here.
        """
        view = self.views[self.view]
        return view["tree"] if view["tree"] is not None else view["text"]

    @property
    def detail(self):
        return self.inspector["text"]


def create_window(source: GuiDataSource | None = None,
                  refresh_interval_ms: int | None = 5000,
                  controller: "ServiceController | None" = None
                  ) -> SealvraWindow:
    """Create the one window. The ONLY place a Tk window is built.

    With no explicit source, the app resolves the service the way the
    CLI does — attach to the daemon already on the conventional
    rendezvous, or start one as this window's own child — and never
    falls back to a browser, a dashboard server or a terminal.
    """
    return SealvraWindow(
        source, refresh_interval_ms=refresh_interval_ms,
        controller=controller)


def main(source: GuiDataSource | None = None,
         refresh_interval_ms: int | None = 5000) -> int:
    """GUI entry point: one window, then the process tree goes with it.

    Returns 0, or raises RuntimeError (KH-3001) when there is no
    display or no tkinter — never a raw TclError. Closing the window
    stops the daemon child this window started, which is what keeps the
    "no orphan process behind the GUI" promise; a daemon this window
    only attached to is left running by design.
    """
    controller = None if source is not None else ServiceController()
    window = create_window(source, refresh_interval_ms=refresh_interval_ms,
                           controller=controller)
    try:
        window.run()
    finally:
        if window.controller is not None:
            window.controller.shutdown_for_close()
    return 0


if __name__ == "__main__":  # pragma: no cover - manual launch only
    raise SystemExit(main())
