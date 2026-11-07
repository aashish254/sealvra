"""Sealvra W12 — MCP server (loopback only).

Corrected to the 2026-07-28 MCP spec revision (v3 N-K7):
- Streamable HTTP is the standard; HTTP+SSE is deprecated.
- ``Mcp-Session-Id``, the standalone GET stream, and resumable streams
  were REMOVED. Session binding here does NOT rely on
  ``Mcp-Session-Id`` at all — a client may send it, it is ignored,
  never trusted. Binding is explicit (see :class:`McpSessionBinding`):
  bearer-token hash + loopback peer + a server-issued binding id +
  (for host-spawned stdio) a consumed one-shot spawn token.
- Loopback only: bind ``127.0.0.1`` (or ``::1``), Origin validation,
  loopback-source assertion. A tunneled loopback setup is NOT a silent
  pass: it is a separately consented, separately named mode
  ("remote endpoint mode"), never granted by a passing probe.
- No generic ``http_call`` tool, ever. No fallback to raw keys, ever.
  Refusal to launch when the daemon is down, ever.
- Bearer tokens in IDE settings: secret-storage indirection ONLY
  (``${input:...}``-style reference, never a literal), with a
  sync-scope warning — Settings Sync can carry a settings file (and
  anything in it) to another machine.

Tier statement (CONTRACT §10): loopback binding + Origin validation
are Tier A defence-in-depth. They do NOT survive Tier B: any same-user
process can connect to a loopback socket and, if it can read the IDE
settings store, the bearer. That limit is stated, not hidden.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Loopback + Origin validation (f10 B17, v3 N-K7)
# ---------------------------------------------------------------------------

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
FORWARDED_HEADERS = ("x-forwarded-for", "x-forwarded-host",
                     "forwarded", "x-real-ip", "cf-connecting-ip")


def is_loopback_host(host: str) -> bool:
    """True only for literal loopback hosts. DNS names are not trusted."""
    host = host.strip().strip("[]").lower().rstrip(".")
    if host in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _authority_host(authority: str) -> str:
    """Host part of a URL authority, or raise on userinfo tricks.

    An authority containing ``@`` (``http://127.0.0.1@evil.example``
    or ``http://evil.example@127.0.0.1``) is refused outright: a
    naive split would read one side as the host and bless the other.
    Bracketed IPv6 (``[::1]:9000``) is handled; the port is stripped.
    """
    if "@" in authority:
        raise McpRefusal(
            "Origin/Host authority contains userinfo; refused (DNS "
            "rebinding defence)")
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            raise McpRefusal("invalid bracketed host; refused")
        return authority[1:end]
    return authority.split(":", 1)[0]


def validate_host_header(host: str | None) -> None:
    """Host-header rebinding defence (f10 B17, v3 N-K7).

    A DNS-rebinding page can reach 127.0.0.1 while sending
    ``Host: evil.example``; Origin validation alone misses
    non-browser clients that send no Origin. A present Host header
    must therefore name a loopback host. Absent Host (HTTP/1.0) is
    allowed — the peer-IP loopback check still applies.
    """
    if host is None or host == "":
        return
    if not is_loopback_host(_authority_host(host.strip())):
        raise McpRefusal(
            "Host %s is not a loopback host; refused (DNS rebinding)" % host)


def assert_loopback_source(peer_ip: str, headers: dict | None = None,
                           remote_endpoint_consented: bool = False,
                           remote_mode_name: str | None = None) -> None:
    """Raise McpRefusal unless the peer is loopback and untunneled.

    Any forwarded header is treated as tunnel evidence: the request is
    refused unless ``remote_endpoint_consented`` is True AND
    ``remote_mode_name`` is the separately named mode
    ("remote endpoint mode"). A passing probe never grants this.
    """
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    tunneled = any(h in headers for h in FORWARDED_HEADERS)
    if tunneled:
        if not (remote_endpoint_consented
                and remote_mode_name == "remote endpoint mode"):
            raise McpRefusal(
                "request carries forwarded headers (tunneled loopback); "
                "refused. Tunneled setups require the separately named "
                "'remote endpoint mode' consent, never a silent pass")
    if not is_loopback_host(peer_ip):
        raise McpRefusal(
            "MCP request source %s is not loopback; refused" % peer_ip)


def validate_origin(origin: str | None, allowed_origins: set | None = None) -> None:
    """Origin validation per the MCP spec for local servers.

    - No Origin header (non-browser client, e.g. a CLI/IDE host): pass.
    - Origin present: it must be a loopback origin, or in
      ``allowed_origins``. Anything else (e.g. https://evil.example)
      -> 403-style refusal (DNS rebinding defence, f10 B17).
    """
    if origin is None or origin == "":
        return
    allowed_origins = allowed_origins or set()
    if origin in allowed_origins:
        return
    # Parse scheme://authority[/...]; authority may be bracketed IPv6.
    try:
        rest = origin.split("://", 1)[1]
    except IndexError:
        raise McpRefusal("invalid Origin header; refused")
    authority = rest.split("/", 1)[0].split("?", 1)[0]
    host = _authority_host(authority)
    if not is_loopback_host(host):
        raise McpRefusal(
            "Origin %s is not a loopback origin; refused (DNS rebinding)" % origin)


def validate_bind_address(host: str) -> None:
    """The MCP server binds loopback only. 0.0.0.0 / LAN hosts refuse."""
    if not is_loopback_host(host):
        raise McpRefusal(
            "MCP server refuses to bind non-loopback host %s" % host)


class McpRefusal(Exception):
    """Refusal safe to return to an MCP client (no secrets, no internals)."""


class DaemonDown(McpRefusal):
    pass


# ---------------------------------------------------------------------------
# Session binding WITHOUT Mcp-Session-Id (v3 N-K7)
# ---------------------------------------------------------------------------

@dataclass
class McpSessionBinding:
    """Explicit Streamable HTTP session binding.

    Binding = sha256(bearer token) + loopback peer address + a
    server-issued ``binding_id`` returned on the first authenticated
    exchange + (stdio hosts) a consumed one-shot spawn token.
    ``Mcp-Session-Id`` is never read, never stored, never trusted:
    the 2026-07-28 spec removed it, and a design keyed to it would
    break on current hosts and could be spoofed by any client that
    echoes a header.
    """
    binding_id: str
    bearer_hash: str
    peer_ip: str
    created_at: float
    spawn_token_hash: str | None = None


class BindingStore:
    """In-memory binding store (bindings die with the daemon)."""

    def __init__(self):
        self._bindings: dict = {}

    def create(self, bearer_token: str, peer_ip: str,
               spawn_token_hash: str | None = None) -> McpSessionBinding:
        assert_loopback_source(peer_ip)
        binding = McpSessionBinding(
            binding_id="kh_bind_" + secrets.token_hex(8),
            bearer_hash=hashlib.sha256(bearer_token.encode()).hexdigest(),
            peer_ip=peer_ip,
            created_at=time.time(),
            spawn_token_hash=spawn_token_hash)
        self._bindings[binding.binding_id] = binding
        return binding

    def validate(self, bearer_token: str, peer_ip: str,
                 binding_id: str, headers: dict | None = None,
                 remote_endpoint_consented: bool = False,
                 remote_mode_name: str | None = None) -> McpSessionBinding:
        """Validate a request. Mcp-Session-Id in headers is ignored.

        Tunneled requests are refused unless the separately named
        remote endpoint mode is consented (see
        :func:`assert_loopback_source`); a passing probe never grants
        that consent.
        """
        assert_loopback_source(peer_ip, headers,
                               remote_endpoint_consented,
                               remote_mode_name)
        binding = self._bindings.get(binding_id)
        if binding is None:
            raise McpRefusal("unknown MCP binding id")
        if not hmac.compare_digest(
                binding.bearer_hash,
                hashlib.sha256(bearer_token.encode()).hexdigest()):
            raise McpRefusal("MCP bearer does not match binding")
        if binding.peer_ip != peer_ip:
            raise McpRefusal("MCP binding peer mismatch")
        return binding


# ---------------------------------------------------------------------------
# One-shot spawn tokens for host-spawned stdio (f10 B9, v3 N-K7)
# ---------------------------------------------------------------------------

class SpawnTokenStore:
    """Broker-issued one-shot spawn tokens.

    Delivered over the control socket, NOT in the config file and NOT
    on the command line (command lines are visible in ``ps``). Each
    token is verified once at server start, bound to the spawning
    process identity string supplied by the broker, and dead
    immediately after (60 s expiry, single use).
    """

    TTL = 60

    def __init__(self):
        self._tokens: dict = {}  # hash -> (expiry, spawner_id)

    def issue(self, spawner_id: str) -> str:
        token = "kh_spawn_" + secrets.token_urlsafe(32)
        self._tokens[hashlib.sha256(token.encode()).hexdigest()] = (
            time.time() + self.TTL, spawner_id)
        return token

    def consume(self, token: str, spawner_id: str) -> bool:
        """Single-use consume. Returns True only on first valid use."""
        key = hashlib.sha256(token.encode()).hexdigest()
        entry = self._tokens.pop(key, None)
        if entry is None:
            return False
        expiry, expected_spawner = entry
        if time.time() > expiry or expected_spawner != spawner_id:
            return False
        return True


# ---------------------------------------------------------------------------
# Tools: allowlist only. No generic http_call, no raw-key fallback.
# ---------------------------------------------------------------------------

# The ONLY tools this server exposes. Anything else, including
# "http_call", "http_request", "fetch", "shell", "exec", is refused.
ALLOWED_TOOLS = (
    "sealvra.proxy_request",
    "sealvra.session_status",
)

FORBIDDEN_TOOL_NAMES = ("http_call", "http_request", "fetch", "shell",
                        "exec", "raw_request", "direct_call")


def has_tool(name: str) -> bool:
    return name in ALLOWED_TOOLS


def call_tool(name: str, arguments: dict, daemon_up: bool,
              bearer_present: bool) -> dict:
    """Dispatch one tool call. Refusals carry no rule internals."""
    if not daemon_up:
        raise DaemonDown(
            "daemon is down; MCP server refuses to serve (no fallback)")
    if name in FORBIDDEN_TOOL_NAMES or name not in ALLOWED_TOOLS:
        raise McpRefusal("tool %r is not offered by this server" % name)
    if not bearer_present:
        raise McpRefusal("MCP request without bearer; refused, no fallback")
    # Tool bodies are implemented by the broker (W01/W04). This module
    # proves the gate: only allowlisted tools reach the broker, with a
    # bearer, from loopback. It never touches a raw key.
    #
    # Phase 2 honesty label: nothing in this build dispatches to a
    # broker. `sealvra.mcp` is not imported by the daemon or the CLI,
    # so no MCP server is served here; this return value is the gate
    # decision, not evidence that a tool ran. Do not read `accepted`
    # as a call having happened.
    return {"tool": name, "accepted": True,
            "note": ("gate only: this build serves no MCP server, so the "
                     "tool was checked, not dispatched; raw keys are never "
                     "used here")}


# ---------------------------------------------------------------------------
# Bearer in secret-storage indirection only + sync-scope warning
# ---------------------------------------------------------------------------

def bearer_config_entry(reference: str) -> dict:
    """Build an MCP config entry for a bearer *reference*, not a value.

    ``reference`` must look like ``${input:sealvra-bearer}`` (VS Code /
    Cursor secret-storage indirection). A literal bearer value is
    refused here — writing one into a settings file is exactly the
    B9/B12 leak (plaintext in a synced settings file).
    """
    if not (reference.startswith("${input:") and reference.endswith("}")):
        raise McpRefusal(
            "MCP bearer must be a secret-storage reference "
            "(${input:...}), never a literal value")
    return {"type": "bearer_reference", "value": reference}


def check_sync_scope(config_path: str, synced_paths: list) -> str | None:
    """Warn if a bearer-bearing settings file is inside a synced scope.

    Returns a warning string, or None when the file is not synced.
    Settings Sync can carry the settings file to another machine; a
    bearer that was 'loopback-only' is then on a second machine and on
    the vendor's sync infrastructure (f10 B9).
    """
    for synced in synced_paths:
        if config_path.startswith(synced.rstrip("/") + "/") or config_path == synced:
            return ("WARNING: MCP settings file %s is inside synced scope "
                    "%s; bearer references can travel to other machines "
                    "via Settings Sync" % (config_path, synced))
    return None


def check_team_distribution(config_scope: str) -> None:
    """Never distribute a Sealvra MCP entry via Team MCP (f10 B8/B11)."""
    if config_scope.lower() in ("team", "shared", "organisation", "organization"):
        raise McpRefusal(
            "refusing to write a Sealvra MCP entry into team/shared "
            "config: team servers reach the whole team and Cloud Agents")


# ---------------------------------------------------------------------------
# Request validation entry point (pure, testable without a live server)
# ---------------------------------------------------------------------------

def validate_mcp_request(headers: dict, peer_ip: str, bearer_token: str | None,
                         binding_id: str | None, store: BindingStore,
                         daemon_up: bool = True,
                         remote_endpoint_consented: bool = False,
                         remote_mode_name: str | None = None) -> McpSessionBinding | None:
    """Validate one Streamable HTTP MCP request end to end.

    Returns the binding for a bound request, or None for the very
    first (binding-creation) request, which carries a bearer but no
    binding id yet. Raises McpRefusal / DaemonDown otherwise.
    ``Mcp-Session-Id`` is ignored by design (see module docstring).
    Checks, in order: loopback source (+ tunnel evidence), Host
    header, Origin header. Tunneled requests pass only under the
    separately named, separately consented remote endpoint mode —
    never by default, never via a probe.
    """
    if not daemon_up:
        raise DaemonDown("daemon is down; MCP server refuses to serve")
    lowered = {k.lower(): v for k, v in headers.items()}
    assert_loopback_source(peer_ip, lowered,
                           remote_endpoint_consented, remote_mode_name)
    validate_host_header(lowered.get("host"))
    validate_origin(lowered.get("origin"))
    if not bearer_token:
        raise McpRefusal("MCP request without bearer; refused, no fallback")
    if binding_id is None:
        return None
    return store.validate(bearer_token, peer_ip, binding_id, lowered,
                          remote_endpoint_consented, remote_mode_name)


def serve_loopback_http(handler_cls, host: str = "127.0.0.1", port: int = 0):
    """Bind a loopback-only HTTP server (stdlib). Refuses other hosts."""
    from http.server import ThreadingHTTPServer
    validate_bind_address(host)
    return ThreadingHTTPServer((host, port), handler_cls)
