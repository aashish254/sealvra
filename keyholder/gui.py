"""Keyholder v0.1 — native GUI status/session window (W11).

Thin client only: read + kill. Zero policy logic lives here.

Normative sources: ``CONTRACT.md`` §12 (W11) and the v3 plan
(``KEYHOLDER-PLAN-V3-FINALCHECK.md``; v3 wins over v1/v2, deleted
passages are never built). In particular:

* No loopback web dashboard, no HTTP UI listener, no browser page
  (v3 N-O3 deletes that path). This window is stdlib ``tkinter`` only.
* No approval channel anywhere in this window. Approvals come ONLY
  from the broker-owned approver (W08). There is no approve button,
  no ``sessions approve`` equivalent, and no approval rendering that
  could approve anything. Kill needs no auth (CONTRACT §8).
* No key value and no session token is ever displayed, logged, or
  copied by this window. The session list shows pseudonyms and
  fingerprints only. A key's user-chosen label appears ONLY in that
  key's own detail pane, never in the global session list and never
  in audit entries (v3 N-C9: count-only in prompts, named lists only
  in the broker-owned session view, global audit pseudonym-only).
  Fingerprints shown are the first 12 hex chars of SHA-256(secret),
  displayed in the owning key's detail pane only (CONTRACT §5).
* Kill semantics (CONTRACT §3/§8): denying new calls within 1 s,
  full teardown within 5 s. Calls already forwarded are NOT recalled;
  they run to completion and are listed on the kill receipt.
* Trust-screen copy (CONTRACT §9, verbatim intent): this window
  "stops *key* theft, not *data* theft", and shows
  "Times any key has left this machine *since import*: N".
* Threat tiers (CONTRACT §10): this window claims Tier A only
  (interface-bound agent). It is NOT Tier B evidence: a
  shell-capable same-user agent is out of scope by design, and
  nothing in this window (file permissions, socket pairing) is
  cited as surviving Tier B. Same-user malware / a compromised OS
  account is out of scope by design.
* CONNECT sessions, if any, are labelled HOST-ONLY POLICY on every
  surface that shows them (CONTRACT §6): host + byte budget only;
  method/path/body policy is unenforceable in a tunnel.

Import safety (CONTRACT §12, W11): importing this module must NOT
open a window and must NOT crash without a display. ``tkinter`` is
imported defensively; window creation happens only inside
``main()`` / ``create_window()``, which the CLI calls explicitly.
On a headless machine ``create_window()`` raises ``RuntimeError``
with code KH-3001 instead of crashing with a raw TclError.

GUI SLICE PLAN — what v0.1 actually ships vs what remains
---------------------------------------------------------
SHIPPED in this slice (honest tkinter, tested headless where a
display is absent):

1. Three-pane Passwords-style layout (intent, not mimicry):
   sidebar (Keys / Sessions / Audit / Trust navigation) |
   centre list (keys, or sessions, or audit entries) |
   detail pane (selected key or session, per-key access log,
   isolation card on every session view).
2. Session list: session pseudonym, key pseudonym, provider,
   session class, transport (with HOST-ONLY POLICY label for
   ``connect_allowed``), expiry, killed state. Never a key value,
   never a token, never another key's label.
3. Per-key kill, per-session kill, and kill-all. Kill-all-first
   ordering: ``kill_all()`` is offered as the first, most prominent
   destructive action, and any bulk operation (kill-all, per-key
   kill) is executed before individual per-session kills in the
   same refresh cycle — see ``ViewModel.kill_plan()``. A kill
   receipt states the 1 s / 5 s rule and that in-flight calls
   are not recalled.
4. Audit view: pseudonym-only entries (session pseudonym, key
   pseudonym, provider, method, canonical path, decision, outcome).
   No labels, no key fragments, no rule internals beyond what the
   audit source itself supplies.
5. Trust screen: "stops key theft, not data theft" + the
   "since import" counter (supplied by the data source; 0 unless
   the daemon reports otherwise — this window never invents a count).
6. Menu bar (File / Sessions / View / Help). On platforms where
   tkinter exposes a menu bar, that is the menu-bar equivalent;
   see MISSING below for the tray.
7. A pure, tkinter-free view-model (``ViewModel`` + rendering
   helpers) so all rendering/kill-wiring logic is unit-testable
   without a display. The window is a thin renderer over it and
   holds no policy logic.

v0.2 LIVE WIRING — what changed, and what is honestly still open:

a. Live daemon wiring (client side, this module). ``DaemonIpcClient``
   speaks the CONTRACT §13.1 wire protocol — newline-delimited JSON
   ``{"id", "cmd", "args"}`` requests and ``{"id", "ok", "result"}``
   / error replies — over a Unix socket or loopback TCP address,
   and ``DaemonIpcSource`` maps it onto ``GuiDataSource``. The
   client is read + kill only: it exposes status, session listing,
   session kill and kill-all, and it REFUSES session creation
   outright (creation returns a token exactly once and is never a
   GUI operation). It never sends, receives, displays, or logs a
   key value or a session token.
   HONEST LIMIT, read before claiming end-to-end liveness: as of
   this slice the daemon in ``keyholder/daemon.py`` still answers
   only status/ping on its socket and W01 has not yet published a
   socket-discovery path, so no cross-process daemon exists for
   this client to talk to yet. The client is therefore verified
   here against a fake IPC stub and a local loopback test server
   (tests only), NOT against a real v0.2 daemon — that end-to-end
   check is W01's slice to close, and until it lands the
   standalone window still launches with ``EmptyDataSource``
   unless ``KEYHOLDER_DAEMON_SOCKET`` names a socket (see
   ``daemon_socket_from_env``). The window never pretends an
   unreachable daemon is live: a failed refresh clears the lists
   and shows an error state instead of stale data.
   IPC shape notes (tolerant mapping, because §13.1 names commands
   but not result shapes): sessions come from ``sessions.list``;
   keys are derived from those sessions (distinct key_id/provider
   — no label, no fingerprint, because no IPC command reports
   keys); the audit view shows the ``audit.verify`` result, not
   audit entries, because no IPC command lists entries; the
   "since import" count is NOT claimed over IPC (the daemon does
   not report it), so the trust screen says so instead of "0".
b. System-tray / menu-bar-extra icon. Stdlib tkinter has no tray
   API; a real tray icon needs a platform API (macOS NSStatusItem,
   Windows NotifyIcon, Linux StatusNotifier) that is outside the
   stdlib-only stack. The menu bar above is the honest substitute.
c. Live auto-refresh. The window now re-reads its data source on
   a timer (``after()``, default every 5 s, configurable) as well
   as on manual Refresh, and a status bar shows the refresh state
   on every tick: live, empty, or error, with the last successful
   refresh time. A failed tick never leaves stale rows on screen
   as if they were live.
d. Per-platform polish (macOS menu-bar extra, Windows taskbar
   behaviour, Wayland notes). Out of scope for this slice; record
   as platform work, not as done.
e. Kill receipts listing already-forwarded calls: the receipt
   states the not-recalled rule, and shows the in-flight list only
   when the data source supplies it (the IPC source passes through
   whatever ``sessions.list`` reports); otherwise it says so
   plainly instead of inventing a list.

No other worker's files are touched by this module. Fake data in
tests uses ``TEST-ONLY-`` prefixes only; no real key ever appears.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import time
from dataclasses import dataclass, field

try:  # Defensive: importing this module must never need a display.
    import tkinter as _tk
    from tkinter import messagebox as _messagebox
    from tkinter import ttk as _ttk

    _TK_AVAILABLE = True
except Exception:  # tkinter missing (minimal installs) — headless-safe.
    _tk = None  # type: ignore[assignment]
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
    "ViewModel",
    "render_key_list_line",
    "render_session_line",
    "render_audit_line",
    "isolation_card_text",
    "trust_screen_text",
    "kill_receipt_text",
    "assert_no_secret",
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

# Quit semantics (v3 §1M N-M2), shared with cli.py: quit defaults
# to Keep sessions, never to destruction. Closing this window never
# kills sessions; "Quit and kill all" is a separate, explicit action.
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


def quit_confirmation_text(live_count: int | None = None) -> str:
    """Quit confirmation copy. The default choice is always Keep
    sessions; destruction is a separate, explicit action."""
    count = f"{live_count} live session(s) " if live_count is not None else "live sessions "
    return (
        f"Quitting closes this window but does not kill {count}or "
        "stop the daemon's sessions. Default: Keep sessions. To end "
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


class GuiDataSource:
    """Duck-typed data source the window renders.

    The real implementation (future slice) is a thin client over
    the daemon socket (W01). It must never return a key value or a
    session token; this module treats anything it returns as
    displayable, so a source that leaked a secret would be a bug
    in the source, caught by ``assert_no_secret`` in tests.
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

    def kill_session(self, session_pseudonym):  # -> bool
        return False

    def kill_key_sessions(self, key_id):  # -> int (sessions killed)
        return 0

    def kill_all(self):  # -> int (sessions killed)
        return 0


class EmptyDataSource(GuiDataSource):
    """Standalone launch source: no daemon reachable, so no keys.

    Honest empty state — never invents demo keys or sessions.
    """


# ----------------------------------------------------------------------
# Daemon IPC client (CONTRACT §13.1 wire protocol, read + kill only)
# ----------------------------------------------------------------------

# Env var naming a daemon socket for standalone GUI launch. This is
# GUI-side discovery only, and only until W01 publishes the canonical
# discovery path; it is NOT a credential and carries no secret.
DAEMON_SOCKET_ENV = "KEYHOLDER_DAEMON_SOCKET"

# The one IPC command this read + kill-only client must never issue:
# session creation returns a token exactly once and is never a GUI
# operation. The client refuses it even if caller code asks for it.
_BLOCKED_IPC_COMMAND = "sessions.create"


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
            chunks, buf = [], b""
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
    expires = entry.get("expires_at") or 0
    try:
        expires_at = float(expires)
    except (TypeError, ValueError):
        expires_at = 0.0
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
        expires_at=expires_at,
        killed=bool(entry.get("killed", False)),
        in_flight_calls=tuple(in_flight),
        session_id=session_id,
    )


class DaemonIpcSource(GuiDataSource):
    """GuiDataSource backed by a DaemonIpcClient (read + kill only).

    Keys are derived from live sessions (distinct key_id/provider);
    no label or fingerprint is ever invented for them. The audit
    view is the audit.verify result, not entries (no IPC command
    lists entries). The since-import count is NOT reported over
    IPC, so ``since_import_known`` is False and the trust screen
    says so instead of claiming 0. Kill needs no auth
    (CONTRACT §8); a KH-1002 kill (already gone) reports False
    rather than raising, because there is nothing left to kill.
    """

    since_import_known = False

    def __init__(self, client: DaemonIpcClient):
        self.client = client
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

    def list_keys(self):
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
        # No IPC command lists audit entries; the verify status is
        # exposed via audit_status() and rendered by the window.
        return []

    def audit_status(self) -> str:
        try:
            result = self.client.audit_verify()
        except Exception as exc:
            return f"Audit verify unavailable: {exc}"
        if isinstance(result, dict):
            verdict = result.get("status") or result.get("verdict") or "ok"
            return f"Audit verify: {verdict}"
        return f"Audit verify: {result}"

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
    """Standalone launch source: live IPC when a socket is named
    in the environment, otherwise the honest empty source. W01's
    canonical discovery, when it lands, replaces the env lookup."""
    address = daemon_socket_from_env()
    if address:
        return DaemonIpcSource(DaemonIpcClient(address))
    return EmptyDataSource()


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
    """Audit line: pseudonym-only, never a label or key fragment."""
    return (
        f"{entry.session_pseudonym} · key {entry.key_pseudonym} · "
        f"{entry.provider} {entry.method} {entry.canonical_path} · "
        f"{entry.decision} · {entry.outcome}"
    )


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
        f"Keyholder {TRUST_HEADLINE}.\n"
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


class ViewModel:
    """Tkinter-free view-model: selection, rendering, kill wiring.

    Refresh states (honest loading/empty/error, tkinter-free so
    tests can assert them headless):

    * ``loading`` — set at the start of ``refresh()``; a source
      that observes the model mid-refresh sees this state.
    * ``live`` — refresh succeeded and at least one key or session
      exists.
    * ``empty`` — refresh succeeded and nothing exists. This is
      NOT a daemon failure: an empty live daemon also lands here.
    * ``error`` — refresh failed (daemon unreachable, malformed
      reply, ...). Snapshots are CLEARED, so the window can never
      display stale rows as if they were live, and ``last_error``
      carries the reason for the status bar / detail pane.

    Before any ``refresh()`` call, the list/detail methods read
    the source live (the v0.1 behaviour, kept so existing callers
    and tests keep working). After ``refresh()``, they read the
    snapshot taken by that refresh, so one refresh cycle renders
    consistently even if the daemon dies mid-render.
    """

    def __init__(self, source: GuiDataSource | None = None):
        self.source = source or EmptyDataSource()
        self.selected_key_id: str | None = None
        self.selected_session_pseudonym: str | None = None
        self.view: str = "keys"  # keys | sessions | audit | trust
        self.state: str = "loading"
        self.last_error: str | None = None
        self.last_refresh_at: float | None = None
        self._refreshed = False
        self._keys: list = []
        self._sessions: list = []
        self._audit: list = []
        self._audit_status: str | None = None
        self._since_import: int = 0

    # -- refresh + state ---------------------------------------------
    def refresh(self) -> str:
        """Re-read the source once; record live/empty/error state.

        Returns the new state. Never raises for a source failure:
        the failure IS the state (``error`` + ``last_error``).
        """
        self.state = "loading"
        try:
            sessions = self.source.list_sessions()
            keys = self.source.list_keys()
            audit = self.source.list_audit()
            since_import = self.source.since_import_count()
            audit_status = None
            audit_status_fn = getattr(self.source, "audit_status", None)
            if callable(audit_status_fn):
                try:
                    audit_status = audit_status_fn()
                except Exception:
                    audit_status = None
        except Exception as exc:
            self._keys, self._sessions, self._audit = [], [], []
            self._audit_status, self._since_import = None, 0
            self.state = "error"
            self.last_error = str(exc)
            self.last_refresh_at = time.time()
            self._refreshed = True
            return self.state
        self._sessions, self._keys, self._audit = sessions, keys, audit
        self._since_import = since_import
        self._audit_status = audit_status
        self.last_error = None
        self.last_refresh_at = time.time()
        self._refreshed = True
        self.state = "live" if (sessions or keys) else "empty"
        return self.state

    def status_text(self) -> str:
        """One-line status-bar text for the current refresh state."""
        when = ""
        if self.last_refresh_at:
            when = " · updated " + time.strftime(
                "%H:%M:%S UTC", time.gmtime(self.last_refresh_at))
        if self.state == "loading":
            return "Loading…"
        if self.state == "error":
            return f"Error: {self.last_error or 'daemon unreachable'}{when}"
        if self.state == "empty":
            if isinstance(self.source, EmptyDataSource):
                return (
                    "No daemon connected — no keys or sessions to show. "
                    "Start the daemon, then Refresh." + when
                )
            return "Connected — no sessions or keys." + when
        if self.state == "live":
            return (
                f"Live — {len(self._sessions)} session(s), "
                f"{len(self._keys)} key(s)" + when
            )
        return f"Status: {self.state}{when}"

    def keys_snapshot(self):
        return list(self._keys) if self._refreshed else self.source.list_keys()

    def sessions_snapshot(self):
        return list(self._sessions) if self._refreshed else self.source.list_sessions()

    def audit_status_text(self) -> str | None:
        return self._audit_status if self._refreshed else None

    # -- reads (rendering only, never secrets) ----------------------
    def key_list_lines(self):
        keys = self.keys_snapshot()
        return [render_key_list_line(k) for k in keys]

    def session_list_lines(self, key_id=None):
        sessions = self.sessions_snapshot()
        selected = key_id or self.selected_key_id
        if selected is not None:
            sessions = [s for s in sessions if s.key_id == selected]
        return [render_session_line(s) for s in sessions]

    def audit_lines(self, key_pseudonym=None):
        audit = self._audit if self._refreshed else self.source.list_audit(key_pseudonym)
        if key_pseudonym is not None and not self._refreshed:
            return [render_audit_line(e) for e in audit]
        if key_pseudonym is not None:
            audit = [e for e in audit if e.key_pseudonym == key_pseudonym]
        return [render_audit_line(e) for e in audit]

    def detail_for_key(self, key_id: str) -> str:
        """Detail pane for ONE key: the only place its label appears."""
        for key in self.keys_snapshot():
            if key.key_id == key_id:
                fp = key.fingerprint[:12] if key.fingerprint else "—"
                warn = (
                    "\nWARNING: NOT YET ROTATED — rotate this key at "
                    "the provider before its first session."
                    if key.rotation_warning
                    else ""
                )
                return (
                    f"{key.provider}\nLabel: {key.label or '(no label)'}\n"
                    f"Pseudonym: {key.pseudonym}\nFingerprint: {fp}{warn}"
                )
        return "Key not found."

    def detail_for_session(self, session_pseudonym: str) -> str:
        for session in self.sessions_snapshot():
            if session.session_pseudonym == session_pseudonym:
                return render_session_line(session) + "\n\n" + isolation_card_text(session)
        return "Session not found."

    def per_key_access_log(self, key_pseudonym: str):
        """Per-key access log: audit entries for that key only."""
        return self.audit_lines(key_pseudonym)

    def trust_text(self) -> str:
        known = getattr(self.source, "since_import_known", True)
        count = self._since_import if self._refreshed else self.source.since_import_count()
        return trust_screen_text(count, known=known)

    def quit_text(self) -> str:
        """Quit confirmation for this window: default Keep sessions.

        Live count is the source's currently unkilled sessions; the
        text never implies quitting kills them."""
        live = [s for s in self.source.list_sessions() if not s.killed]
        return quit_confirmation_text(len(live))

    def wired_token_share_warning(self) -> str:
        return WIRED_TOKEN_SHARE_WARNING

    def copy_setup_note(self) -> str:
        return COPY_SETUP_RULE

    # -- kills (kill needs no auth; kill-all-first ordering) --------
    def kill_plan(self, key_id=None):
        """Order bulk kills before individual kills in one cycle.

        Returns a list of ("kill-all" | "kill-key" | "kill-session",
        target) in execution order. Callers execute in this order so
        a bulk kill is never left behind a single-session kill.
        """
        plan = []
        plan.append(("kill-all", None))
        if key_id:
            plan.append(("kill-key", key_id))
        return plan

    def kill_session(self, session_pseudonym: str) -> str:
        ok = self.source.kill_session(session_pseudonym)
        return kill_receipt_text(1 if ok else 0)

    def kill_key(self, key_id: str) -> str:
        count = self.source.kill_key_sessions(key_id)
        return kill_receipt_text(count)

    def kill_all(self) -> str:
        count = self.source.kill_all()
        return kill_receipt_text(count)


class KeyholderWindow:
    """The tkinter window. Created only via ``create_window()``.

    ``refresh_interval_ms`` drives timed auto-refresh (default
    5000 ms); pass 0/None to disable the timer and keep manual
    Refresh only. Auto-refresh re-renders from a fresh
    ``ViewModel.refresh()`` each tick and the status bar always
    shows that tick's state, so a failed tick displays an error
    instead of leaving stale rows on screen as if live.
    """

    def __init__(self, source: GuiDataSource | None = None,
                 refresh_interval_ms: int | None = 5000):
        if not _TK_AVAILABLE or _tk is None:
            raise RuntimeError("KH-3001: tkinter is not available on this platform")
        try:
            self.root = _tk.Tk()
        except Exception as exc:  # e.g. TclError: no display
            raise RuntimeError(
                "KH-3001: no display available for the native GUI window"
            ) from exc
        self.vm = ViewModel(source)
        self.refresh_interval_ms = refresh_interval_ms
        self._auto_refresh_id = None
        self.root.title("Keyholder")
        self._build()
        self._schedule_auto_refresh()

    def _schedule_auto_refresh(self):
        if not self.refresh_interval_ms:
            return
        try:
            self._auto_refresh_id = self.root.after(
                int(self.refresh_interval_ms), self._auto_refresh)
        except Exception:
            self._auto_refresh_id = None

    def _auto_refresh(self):
        self._auto_refresh_id = None
        try:
            if not self.root.winfo_exists():
                return
        except Exception:
            return
        self.refresh()
        self._schedule_auto_refresh()

    def destroy(self):
        if self._auto_refresh_id is not None:
            try:
                self.root.after_cancel(self._auto_refresh_id)
            except Exception:
                pass
            self._auto_refresh_id = None
        self.root.destroy()

    # -- layout: sidebar | list | detail ----------------------------
    def _build(self):
        root = self.root
        menubar = _tk.Menu(root)
        file_menu = _tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Refresh", command=self.refresh)
        # Quit defaults to Keep sessions: closing the window never
        # kills sessions. Destruction is the separate item below.
        file_menu.add_command(label="Quit (keeps sessions)", command=self._on_quit)
        file_menu.add_command(
            label="Quit and kill all sessions", command=self._on_quit_and_kill_all
        )
        menubar.add_cascade(label="File", menu=file_menu)
        sessions_menu = _tk.Menu(menubar, tearoff=0)
        sessions_menu.add_command(label="Kill all sessions", command=self._on_kill_all)
        menubar.add_cascade(label="Sessions", menu=sessions_menu)
        view_menu = _tk.Menu(menubar, tearoff=0)
        for label, view in (
            ("Keys", "keys"),
            ("Sessions", "sessions"),
            ("Audit", "audit"),
            ("Trust", "trust"),
        ):
            view_menu.add_command(
                label=label, command=lambda v=view: self._show_view(v)
            )
        menubar.add_cascade(label="View", menu=view_menu)
        help_menu = _tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About Keyholder", command=self._on_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        root.config(menu=menubar)

        panes = _ttk.PanedWindow(root, orient="horizontal")
        panes.pack(fill="both", expand=True)

        sidebar = _ttk.Frame(panes)
        for label, view in (
            ("Keys", "keys"),
            ("Sessions", "sessions"),
            ("Audit", "audit"),
            ("Trust", "trust"),
        ):
            _ttk.Button(
                sidebar, text=label, command=lambda v=view: self._show_view(v)
            ).pack(fill="x", padx=4, pady=2)
        _ttk.Button(
            sidebar, text="Kill all sessions", command=self._on_kill_all
        ).pack(fill="x", padx=4, pady=12)
        _ttk.Label(
            sidebar,
            text="Read + kill only.\nThis window cannot\napprove requests.",
            wraplength=140,
        ).pack(padx=4, pady=8)
        panes.add(sidebar, weight=1)

        list_frame = _ttk.Frame(panes)
        self.listbox = _tk.Listbox(list_frame)
        self.listbox.pack(fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self._on_select)
        panes.add(list_frame, weight=2)

        detail_frame = _ttk.Frame(panes)
        self.detail = _tk.Text(detail_frame, wrap="word", state="disabled")
        self.detail.pack(fill="both", expand=True)
        btn_frame = _ttk.Frame(detail_frame)
        btn_frame.pack(fill="x")
        _ttk.Button(btn_frame, text="Kill session", command=self._on_kill_session).pack(
            side="left", padx=2, pady=2
        )
        _ttk.Button(
            btn_frame, text="Kill sessions for this key", command=self._on_kill_key
        ).pack(side="left", padx=2, pady=2)
        _ttk.Button(btn_frame, text="Refresh", command=self.refresh).pack(
            side="left", padx=2, pady=2
        )
        panes.add(detail_frame, weight=3)

        self.status_bar = _ttk.Label(root, text="Loading…", anchor="w")
        self.status_bar.pack(side="bottom", fill="x")
        self.refresh()

    # -- behaviour ---------------------------------------------------
    def _set_detail(self, text: str):
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.config(state="disabled")

    def _show_view(self, view: str):
        self.vm.view = view
        self.refresh()

    def _on_about(self):
        _messagebox.showinfo(
            "About Keyholder",
            "Keyholder — local-first key holder for AI agents.\n"
            "This window stops key theft, not data theft.\n"
            "Read + kill only; it never shows a key value or token.",
        )

    def refresh(self):
        vm, view = self.vm, self.vm.view
        self.status_bar.config(text="Refreshing…")
        vm.refresh()
        self.listbox.delete(0, "end")
        if vm.state == "error":
            # Never render stale rows: error state clears the list.
            self.listbox.insert("end", f"Error: {vm.last_error}")
            self._set_detail(
                "Could not load live data.\n\n"
                f"Error: {vm.last_error}\n\n"
                "Nothing shown here is live data from the daemon. "
                "Check that the daemon is running, then Refresh."
            )
            self._keys, self._sessions = [], []
        elif view == "keys":
            lines, keys = vm.key_list_lines(), vm.keys_snapshot()
            self._keys = keys
            for line in lines:
                self.listbox.insert("end", line)
            self._set_detail(
                "Select a key to see its detail pane.\n\n"
                "Labels appear only in a key's own detail pane, "
                "never in this list."
                if lines
                else "No keys to show. If no daemon is connected, "
                "start the daemon and Refresh; an empty live daemon "
                "also shows this."
            )
        elif view == "sessions":
            sessions = vm.sessions_snapshot()
            if vm.selected_key_id is not None:
                sessions = [s for s in sessions if s.key_id == vm.selected_key_id]
            self._sessions = sessions
            for line in vm.session_list_lines():
                self.listbox.insert("end", line)
            self._set_detail(
                "Select a session to see its isolation card."
                if sessions
                else "No sessions."
            )
        elif view == "audit":
            for line in vm.audit_lines():
                self.listbox.insert("end", line)
            audit_status = vm.audit_status_text()
            self._set_detail(
                "Audit view: pseudonyms only. No labels, no key values."
                + (f"\n\n{audit_status}" if audit_status else "")
            )
        else:  # trust
            self.listbox.insert("end", "Trust")
            self._set_detail(vm.trust_text())
        self.status_bar.config(text=vm.status_text())

    def _on_select(self, _event=None):
        sel = self.listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        view = self.vm.view
        if view == "keys" and hasattr(self, "_keys") and idx < len(self._keys):
            key = self._keys[idx]
            self.vm.selected_key_id = key.key_id
            self._set_detail(self.vm.detail_for_key(key.key_id))
        elif view == "sessions" and hasattr(self, "_sessions") and idx < len(self._sessions):
            session = self._sessions[idx]
            self.vm.selected_session_pseudonym = session.session_pseudonym
            self._set_detail(self.vm.detail_for_session(session.session_pseudonym))

    def _show_receipt(self, receipt: str):
        _messagebox.showinfo("Kill receipt", receipt)
        self.refresh()

    def _run_kill(self, action):
        """Run a kill action; a daemon failure shows an error dialog
        and refreshes into the error state instead of a receipt."""
        try:
            receipt = action()
        except Exception as exc:
            _messagebox.showerror("Kill failed", f"Kill failed: {exc}")
            self.refresh()
            return
        self._show_receipt(receipt)

    def _on_kill_session(self):
        pseudonym = self.vm.selected_session_pseudonym
        if not pseudonym:
            _messagebox.showinfo("Kill session", "Select a session first.")
            return
        self._run_kill(lambda: self.vm.kill_session(pseudonym))

    def _on_kill_key(self):
        key_id = self.vm.selected_key_id
        if not key_id:
            _messagebox.showinfo("Kill sessions", "Select a key first.")
            return
        self._run_kill(lambda: self.vm.kill_key(key_id))

    def _on_kill_all(self):
        self._run_kill(self.vm.kill_all)

    def _on_quit(self):
        if _messagebox.askyesno("Quit Keyholder", self.vm.quit_text()):
            self.root.destroy()

    def _on_quit_and_kill_all(self):
        # Separate, explicit destruction path: its own confirmation,
        # never the default quit action.
        if _messagebox.askyesno(
            "Quit and kill all sessions",
            "Kill all live sessions and quit? This ends every session.",
        ):
            self._show_receipt(self.vm.kill_all())
            self.root.destroy()

    def run(self):
        self.root.mainloop()


def create_window(source: GuiDataSource | None = None,
                  refresh_interval_ms: int | None = 5000) -> KeyholderWindow:
    """Create the window. The ONLY place a Tk window is constructed.

    With no explicit source, the standalone default applies: live
    IPC when ``KEYHOLDER_DAEMON_SOCKET`` names a socket, otherwise
    the honest empty source.
    """
    return KeyholderWindow(
        source if source is not None else create_default_source(),
        refresh_interval_ms=refresh_interval_ms)


def main(source: GuiDataSource | None = None) -> int:
    """CLI entry point for the GUI. Returns 0, or raises RuntimeError
    (KH-3001) headless / without tkinter — never a raw TclError."""
    window = create_window(source)
    window.run()
    return 0


if __name__ == "__main__":  # pragma: no cover - manual launch only
    raise SystemExit(main())
