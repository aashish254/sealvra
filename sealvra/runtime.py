"""Composition root: the one place that wires broker + vault + policy +
audit + approver into a live proxy server (v0.2, W15 Phase 1).

Before this module existed, ``ProxyEngine`` was only ever instantiated
by tests. The daemon served IPC and nothing else: no process listened on
the proxy port, so the documented chain

    CLI -> daemon IPC -> proxy HTTP -> policy -> approval -> audit ->
    key injection -> response re-scan

had never run outside an in-process test fixture. This module builds the
production object graph from the real classes, with no stubs and no
silent fallbacks: any adapter whose backing decision is unmade raises
instead of substituting a double.

What this module deliberately does NOT decide:

* the wrapping-key source (OD-12). ``vault.wrapping_key_for`` has one
  implemented source, the test-mode key file; in production it raises
  ``AuthRequired`` naming the open owner decision. The runtime does not
  catch that to keep a proxy "running" without a usable store.
* the OS approval gesture. ``approval.RealApprover`` takes a
  ``gesture`` callable; no platform gesture is implemented in this tree
  yet, so the runtime builds the approver with the default (``None``)
  and every level-3 call is denied fail-closed. That is the honest
  behaviour of an un-implemented prompt, not a wired-up one.
* any credential handoff that would let a process use a session it did
  not create (see ``daemon``: the PoP key leaves the daemon only inside
  the one-shot reply of the call that minted it, and only in test mode).

Environment (all read here, so `daemon status` can print the truth):
``SEALVRA_VAULT_DIR``, ``SEALVRA_AUDIT_ROOT``, ``SEALVRA_PACKS_DIR``,
``SEALVRA_AUDIT_SECRET_FILE``, ``SEALVRA_PROXY_HOST``,
``SEALVRA_PROXY_PORT``, ``SEALVRA_MOCK_GITHUB_BASE``,
``SEALVRA_MOCK_GEMINI_BASE``, ``SEALVRA_CONNECT_HOSTS``,
``SEALVRA_TEST_MODE``.
"""

from __future__ import annotations

import os
import secrets
import threading
from dataclasses import dataclass, field
from pathlib import Path

from . import vault as vault_module
from . import audit as audit_module
from . import github as github_module
from .audit import AuditLog, pseudonym
from .broker import Broker
from .packs import load_pack
from .policy import PolicyEngine
from .proxy import (DEFAULT_HOST, DEFAULT_PORT, ProxyConfig,
                     ProxyEngine, make_server)
from .types import PolicyDecision

AUDIT_ROOT_ENV = audit_module.AUDIT_ROOT_ENV
AUDIT_SECRET_FILE_ENV = "SEALVRA_AUDIT_SECRET_FILE"
PACKS_DIR_ENV = "SEALVRA_PACKS_DIR"
PROXY_HOST_ENV = "SEALVRA_PROXY_HOST"
PROXY_PORT_ENV = "SEALVRA_PROXY_PORT"
MOCK_GITHUB_BASE_ENV = "SEALVRA_MOCK_GITHUB_BASE"
MOCK_GEMINI_BASE_ENV = "SEALVRA_MOCK_GEMINI_BASE"
CONNECT_HOSTS_ENV = "SEALVRA_CONNECT_HOSTS"
TEST_MODE_ENV = vault_module.TEST_MODE_ENV

BUILD_ROOT = Path(__file__).resolve().parent.parent

#: The only providers in this product, and where their real traffic goes.
REAL_PROVIDERS = {
    "github": "https://api.github.com",
    "gemini": "https://generativelanguage.googleapis.com",
}

PROVIDERS = ("github", "gemini")

_MIN_AUDIT_SECRET_BYTES = 32


# ---------------------------------------------------------------------------
# directory / secret resolution
# ---------------------------------------------------------------------------

def _loop(value: str) -> str:
    return (value or "").strip()


def packs_dir() -> Path:
    raw = _loop(os.environ.get(PACKS_DIR_ENV, ""))
    if raw:
        return Path(raw).expanduser()
    return BUILD_ROOT / "packs"


def audit_root() -> Path:
    # Delegates to the audit module so the daemon's writer and the CLI's
    # read-only verifier can never resolve different roots.
    return audit_module.default_audit_root()


def _audit_secret_path() -> Path:
    raw = _loop(os.environ.get(AUDIT_SECRET_FILE_ENV, ""))
    if raw:
        return Path(raw).expanduser()
    return audit_root() / "audit_secret"


def _refuse_loose_mode(path: Path) -> None:
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise RuntimeError(
            f"audit secret file {path} is group/world accessible "
            f"(mode {oct(mode)}); refusing to derive pseudonyms from it")


def audit_secret() -> bytes:
    """The HMAC key for audit pseudonyms, read from a 0600 file.

    Created on first use, never committed, never synced-folder resident.
    Losing it does not lose the log; it loses the ability to correlate
    pseudonyms written before the loss, which is the intended property.
    """
    path = _audit_secret_path()
    if path.exists():
        _refuse_loose_mode(path)
        data = path.read_bytes().strip()
        if len(data) < _MIN_AUDIT_SECRET_BYTES:
            raise RuntimeError(
                f"audit secret file {path} is shorter than "
                f"{_MIN_AUDIT_SECRET_BYTES} bytes")
        return data
    path.parent.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_bytes(_MIN_AUDIT_SECRET_BYTES)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, secret)
    finally:
        os.close(fd)
    _refuse_loose_mode(path)
    return secret


def open_audit_log() -> AuditLog:
    return AuditLog(audit_root(), audit_secret())


def policy_engines() -> dict[str, PolicyEngine]:
    """One engine per provider, from the signed packs on disk.

    A pack that fails hash OR signature verification raises here: the
    runtime refuses to serve rather than deciding against an unverified
    policy (there is no unsigned fallback in ``packs.load_pack``).
    """
    directory = packs_dir()
    engines: dict[str, PolicyEngine] = {}
    for provider in PROVIDERS:
        engines[provider] = PolicyEngine(load_pack(directory / f"{provider}.json"))
    return engines


def upstream_bases(*, test_mode: bool) -> dict[str, str]:
    """Where forwarded calls actually go — the whole real-provider safety
    question lives here.

    Test mode refuses to run without BOTH mock bases set, and refuses any
    mock base that is not loopback. Production uses the canonical
    provider hosts. There is no default to a real host while a test is
    asking for a mock: an unset mock base is an error, never a fallback.
    """
    if not test_mode:
        return dict(REAL_PROVIDERS)
    github = _loop(os.environ.get(MOCK_GITHUB_BASE_ENV, ""))
    gemini = _loop(os.environ.get(MOCK_GEMINI_BASE_ENV, ""))
    if not github or not gemini:
        raise RuntimeError(
            "test mode requires both "
            f"{MOCK_GITHUB_BASE_ENV} and {MOCK_GEMINI_BASE_ENV} to be set; "
            "no mock base defaults to a real provider")
    bases = {"github": github, "gemini": gemini}
    for provider, base in bases.items():
        if not base.startswith("http://127.0.0.1:") and not base.startswith(
                "http://localhost:"):
            raise RuntimeError(
                f"{provider} mock base {base!r} is not loopback; refusing "
                "to forward test-mode traffic anywhere else")
    return bases


def connect_hosts() -> frozenset[str]:
    raw = _loop(os.environ.get(CONNECT_HOSTS_ENV, ""))
    if not raw:
        return frozenset()
    return frozenset(host.strip().lower() for host in raw.split(",")
                     if host.strip())


# ---------------------------------------------------------------------------
# runtime
# ---------------------------------------------------------------------------

@dataclass
class Runtime:
    """The wired object graph plus the proxy server it can serve."""

    broker: Broker
    audit: AuditLog
    engines: dict[str, PolicyEngine]
    config: ProxyConfig
    approver: object | None
    test_mode: bool
    approver_mode: str = ""
    server: object | None = None
    thread: threading.Thread | None = None
    _engine: ProxyEngine | None = field(default=None, repr=False)

    @property
    def port(self) -> int | None:
        if self.server is None:
            return None
        return self.server.server_address[1]

    # -- serving ---------------------------------------------------------
    def start_proxy(self, *, host: str | None = None,
                    port: int | None = None) -> int:
        """Serve the real proxy on a loopback port in a background thread.

        The engine is built lazily here (not in ``build_runtime``) so the
        daemon can finish its IPC listener first; a failure to bind or to
        construct the engine propagates to the caller instead of leaving
        a half-started daemon.
        """
        if self.server is not None:
            raise RuntimeError("proxy server already started")
        engine = self.build_engine()
        server = make_server(self.config, engine, host=host, port=port)
        bound_port = server.server_address[1]
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.1},
            name="sealvra-proxy",
            daemon=True)
        self.server = server
        self.thread = thread
        thread.start()
        return bound_port

    def shutdown(self) -> None:
        if self.server is not None:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
            self.server = None
        if self.thread is not None:
            self.thread.join(timeout=5.0)
            self.thread = None
        if self._engine is not None:
            self._engine = None

    # -- engine construction --------------------------------------------
    def build_engine(self) -> ProxyEngine:
        engine = ProxyEngine(
            self.config,
            lookup_session=self.broker.validate_token,
            pop_key_for=self.broker.pop_key,
            decide=self._decide,
            approve=self._approve,
            audit_decision=self._audit_decision,
            audit_outcome=self._audit_outcome,
            key_for=vault_module.secret_for,
            on_success=self.broker.record_successful_call,
            begin_call=self._begin_call,
            end_call=self._end_call,
            connect_host_allowed=self._connect_host_allowed,
        )
        self._engine = engine
        return engine

    # -- adapters (same shapes the integration tests exercise) ----------
    def _decide(self, session, method, path, body, content_type):
        policy = self.engines.get(session.provider)
        if policy is None:
            return None
        # An empty body is no body: the policy parser rejects b"" as
        # malformed JSON, so a bodyless request must not be decided as
        # one (manager adapter note, tests/test_integration.py).
        decision = policy.decide(method, path, session.session_class,
                                 body_raw=body if body else None,
                                 content_type=content_type)
        return self._deny_floor(session, method, path, decision)

    @staticmethod
    def _deny_floor(session, method, path, decision):
        """First-party hard refusals, applied over the pack's answer.

        ``sealvra.github.classify`` carries hard denials the signed packs
        do not model. Reading ``/repos/{owner}/{repo}/actions/secrets/{name}``
        is the case that made this seam necessary: the packs deny the
        write verbs on secrets and model no GET, and ``GET /repos/**`` is
        an allow -- so a read-class session could enumerate secret names.

        CONTRACT §6 keeps the pack as the policy source, so this floor may
        only ever ADD a refusal: a pack deny or level-4 is returned
        untouched, a level-3 is left to the approver, and only a
        pack-allowed call that the adapter classifies level 4 is turned
        into a deny, carrying the adapter's rule id into the audit row.
        The adapter's body-dependent rules are not reached here because
        ``classify`` wants parsed JSON while the proxy hands this adapter
        raw bytes; path and method refusals are what is enforced.
        """
        if decision is None or session.provider != "github":
            return decision
        if not decision.allowed or decision.level >= 4:
            return decision
        floor = github_module.classify(method, path)
        if not floor.allowed and floor.level >= 4:
            return PolicyDecision(allowed=False, level=4,
                                  reason=floor.reason, rule_id=floor.rule_id)
        return decision

    def _approve(self, session, method, path, scope_summary):
        if self.approver is None:
            # Fail closed: no approver means level-3 calls deny. There is
            # no auto-approve path in this product.
            return False, None
        return self.approver(session, method, path, scope_summary)

    def _audit_decision(self, entry):
        self.audit.write_decision(
            pseudonym(self.audit.audit_secret, entry["session_id"]),
            pseudonym(self.audit.audit_secret, entry["key_id"]),
            entry["provider"], entry["method"], entry["canonical_path"],
            entry["decision"], rule_id=entry.get("rule_id"),
            outcome="forwarded",
            approval_id=entry.get("approval_id"))

    def _audit_outcome(self, entry):
        self.audit.write_outcome(
            pseudonym(self.audit.audit_secret, entry["session_id"]),
            pseudonym(self.audit.audit_secret, entry["key_id"]),
            entry["provider"], entry["method"], entry["canonical_path"],
            entry["decision"], rule_id=entry.get("rule_id"),
            outcome=entry.get("outcome", "success"),
            bytes_in=entry.get("bytes_in", 0),
            bytes_out=entry.get("bytes_out", 0),
            approval_id=entry.get("approval_id"))

    def _connect_host_allowed(self, session, host) -> bool:
        if session.transport != "connect_allowed":
            return False
        return host.lower() in self.config.connect_hosts

    def _begin_call(self, session, call_id) -> None:
        """Name the forwarded call in the broker's in-flight registry.

        The kill receipt is built from this set: an unwired registry
        silently reports "no calls were already sent", which is the one
        thing the receipt must never say about a call already upstream.
        """
        self.broker.register_in_flight(session.session_id, call_id)

    def _end_call(self, session, call_id) -> None:
        self.broker.complete_in_flight(session.session_id, call_id)


def _card_resolver(session):
    """(label, fingerprint) for the approval card, from vault data only.

    Returns None when the record cannot be read: the approver adapter then
    denies rather than inventing a card the user cannot verify against.
    """
    record = vault_module.get_key(session.key_id)
    if record is None or not record.header_verified:
        return None
    return record.label, record.fingerprint


def production_approver():
    """The real proxy approver, over ``RealApprover`` with no gesture
    seam implemented. Nothing here is a test double: with no OS gesture
    available, level-3 calls are denied (``gesture=None`` means deny), and
    the denial reason reaches the audit trail as a denial."""
    from .approval import RealApprover, proxy_approver

    approver = RealApprover()
    return proxy_approver(approver, card_resolver=_card_resolver), approver


def test_harness_approver():
    """A level-3 approver for the test harness only.

    Refuses to exist unless ``SEALVRA_TEST_APPROVER=1`` is set, matching
    the ``ProxyEngine`` marker rule; the flag never reaches production
    because ``build_runtime`` only calls this when ``test_mode`` is on.
    """
    if os.environ.get("SEALVRA_TEST_APPROVER") != "1":
        raise RuntimeError(
            "test approver refused outside the test harness: set "
            "SEALVRA_TEST_APPROVER=1 only in tests")

    def _approve(session, method, path, scope_summary):
        # The harness marker on the callable is what ProxyEngine checks.
        return True, "appr-harness-" + session.session_id

    _approve._sealvra_test_approver = True
    return _approve


def build_runtime(broker: Broker | None = None, *,
                  approver: object | None = None,
                  audit: AuditLog | None = None,
                  engines: dict[str, PolicyEngine] | None = None,
                  config: ProxyConfig | None = None) -> Runtime:
    """Assemble the production object graph.

    ``test_mode`` comes from the environment, not from a parameter: the
    same switch that gates the wrapping-key file gates the mock bases, so
    a runtime can never be half-test/half-production by argument drift.
    ``approver`` may be passed explicitly by a test; when it is not,
    production gets the real approver and test mode gets the harness one.
    """
    test_mode = vault_module.test_mode_enabled()
    broker = broker if broker is not None else Broker()
    if approver is None:
        if test_mode and os.environ.get("SEALVRA_TEST_APPROVER") == "1":
            approver = test_harness_approver()
            approver_mode = "test-harness"
        else:
            approver, _real = production_approver()
            approver_mode = ("production (no OS gesture implemented: "
                             "level-3 calls deny)")
    else:
        approver_mode = "explicit"
    if config is None:
        config = ProxyConfig(
            host=_loop(os.environ.get(PROXY_HOST_ENV, "")) or DEFAULT_HOST,
            port=int(_loop(os.environ.get(PROXY_PORT_ENV, "")) or DEFAULT_PORT),
            bases=upstream_bases(test_mode=test_mode),
            test_mode=test_mode,
            connect_hosts=connect_hosts(),
        )
    return Runtime(
        broker=broker,
        audit=audit if audit is not None else open_audit_log(),
        engines=engines if engines is not None else policy_engines(),
        config=config,
        approver=approver,
        approver_mode=approver_mode,
        test_mode=test_mode,
    )


def describe(runtime: Runtime | None = None) -> dict:
    """What a daemon actually is serving — for `daemon status`.

    The E2E safety gate reads this: no proxied call is made until the
    status output confirms the proxy's upstream bases are the loopback
    mocks. Printing the bases is what makes that confirmable, so the
    fields here are the gate, not decoration.
    """
    test_mode = vault_module.test_mode_enabled()
    out = {
        "vault_dir": str(vault_module.vault_dir()),
        "audit_root": str(audit_root()),
        "packs_dir": str(packs_dir()),
        "proxy_host": _loop(os.environ.get(PROXY_HOST_ENV, "")) or DEFAULT_HOST,
        "proxy_port": int(_loop(os.environ.get(PROXY_PORT_ENV, "")) or DEFAULT_PORT),
        "test_mode": test_mode,
        "connect_hosts": sorted(connect_hosts()),
        "build_root": str(BUILD_ROOT),
    }
    try:
        out["upstream_bases"] = upstream_bases(test_mode=test_mode)
    except RuntimeError as exc:
        out["upstream_bases"] = None
        out["upstream_bases_error"] = str(exc)
    if runtime is not None:
        out["proxy_port_bound"] = runtime.port
        out["approver_mode"] = runtime.approver_mode
    return out
