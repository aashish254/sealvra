"""Keyholder v0.2 — git interposition: credential helper + wrapper (W05).

Normative sources: CONTRACT.md §13.4 (git interposition boundary) and
v3 plan §1J as corrected by final-check audit f09 (GitHub adapter).
This module implements the helper+wrapper slice ONLY. It does not
rewrite any other module, and it does not claim full git coverage.

What this slice IS
-----------------
1. A git credential helper speaking git's credential protocol
   (``get`` / ``store`` / ``erase`` on stdin/stdout, ``key=value``
   lines terminated by a blank line). On ``get`` it returns a
   SESSION-SCOPED credential: username ``keyholder`` and password =
   the proxy session token (``kh_sess_...``), bound to exactly one
   key, one repo scope (host + owner/repo), and TTL-capped by the
   session's expiry. It NEVER returns, prints, or stores the real
   provider key. The real key is never an input to this module at
   all: the issuer is constructed with a session record and a
   session token only, so there is no code path here that could
   leak a real key even by accident.
2. A wrapper (``GitWrapper``) for ``push`` / ``pull`` / ``fetch`` /
   ``clone`` that, before running git: checks the session is live,
   checks the session class (a read session cannot push), resolves
   the remote and checks it against the repo scope, and denies
   force-push and ref-deletion unless a matching, live approval
   exists. Every attempt is logged to the audit log (decision
   BEFORE git runs, outcome AFTER) through a caller-supplied sink;
   if the audit sink fails on the decision write, git is NOT run
   (fail closed, CONTRACT §6 / §8).

What this slice is NOT (honest boundary, CONTRACT §13.4)
--------------------------------------------------------
* There is NO git smart-HTTP proxy in this slice. The session-token
  credential the helper returns is meaningful only to a Keyholder
  git proxy (not yet built) or to the loopback fake remote used in
  tests, which validates the token, scope, and expiry itself. Sent
  directly to github.com it would simply fail authentication —
  which is why the helper REFUSES any host other than the scope
  host, and the wrapper configures git with ONLY this helper
  (``credential.helper=`` reset, then this script) and
  ``GIT_TERMINAL_PROMPT=0`` so git cannot fall back to an
  interactive prompt or a standing credential helper.
* A git client run DIRECTLY by the agent with standing credentials
  outside the wrapper/helper bypasses the broker completely: it is
  NOT logged and NOT gated. That path is the residual risk. Mitigations
  that exist elsewhere (not invented here): ``keyholder doctor``
  already inventories standing git credentials (``.git-credentials``
  and ``.config/gh/hosts.yml`` are in its credential-store list in
  ``cli.py``) — run it and remove/rotate anything it flags. The
  wrapper cannot police a process it never parents.
* Credential-helper ``get`` calls themselves are not individually
  audit-logged in this slice: git invokes the helper as a child
  process and the helper has no safe concurrent writer into the
  broker's hash-chained log (a second writer would trip the log's
  offset check). What IS logged is every wrapper operation
  (push/pull/fetch/clone attempt + outcome), which is the unit the
  user approves. A helper ``get`` outside the wrapper, with
  wrapper-set environment variables, is still scope- and
  expiry-checked by the helper itself, but that check leaves no
  audit entry — stated here, not hidden.
* Path restriction inside a push is NOT enforced here (f09 F18):
  a push is a whole-tree commit, and per-path rules cannot be
  checked from refspecs alone. A path-bound template must use
  API-only sessions, not git.
* Delete-then-recreate (f09 F21) across the git/REST boundary is
  only half covered: a delete denied here never reaches the
  remote, but a recreate via REST after a direct-git delete is
  the REST adapter's ``RefRewriteTracker`` problem, not this
  module's. Within git, delete + recreate in one push is denied
  because the delete half already requires approval.

Tier statement (CONTRACT §10): the helper and wrapper hold against
a Tier A (interface-bound) agent that uses the wrapper. They do NOT
survive Tier B (a shell-capable same-user agent): such an agent can
read the wrapper-set environment of its own git child, run git
directly with standing credentials, or edit its own git config.
Same-user malware / compromised OS account is out of scope by
design. The wrapper-set token environment lives only for the git
child process lifetime; it is never written to disk, never put in
a remote URL, and never put in a git config file.

Fixtures: fake keys/tokens only, prefixed ``TEST-ONLY-`` for keys
and ``kh_sess_`` for session tokens. No real provider is contacted;
the only network use in tests is loopback.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .tokens import TOKEN_PREFIX

__all__ = [
    "HELPER_USERNAME",
    "GitScope",
    "GitSession",
    "GitCredential",
    "GitCredentialIssuer",
    "Approval",
    "GitOperation",
    "GitAuditEvent",
    "GitResult",
    "GitDenied",
    "GitWrapper",
    "GitHelperContext",
    "parse_credential_input",
    "format_credential_output",
    "normalize_repo_path",
    "parse_git_url",
    "parse_git_args",
    "make_audit_sink",
    "handle_helper",
    "coverage_report",
    "COVERAGE",
]

HELPER_USERNAME = "keyholder"

# Error codes (CONTRACT §9, same event = same code on every surface).
ERR_POLICY_DENIED = "KH-1003"
ERR_SESSION_DEAD = "KH-1002"
ERR_AUDIT_UNAVAILABLE = "KH-1005"
ERR_USAGE = "KH-2001"
ERR_UPSTREAM = "KH-1006"

# Options of `git push` that consume a following argument. Everything
# else is treated as a boolean flag. Unknown long options are treated
# as boolean (fail-closed direction: a misparsed value becomes a
# positional, which then fails the scope/ref checks, never an allow).
_PUSH_VALUE_OPTIONS = {
    "--repo", "--receive-pack", "--exec", "--push-option", "--signed",
}
_PUSH_SHORT_VALUE_OPTIONS = {"o"}  # -o/--push-option
_SUPPORTED_COMMANDS = ("push", "pull", "fetch", "clone")


def normalize_repo_path(path: str) -> str:
    """Normalise a repo path for scope comparison.

    Strips a leading slash, a trailing ``.git``, and trailing
    slashes. ``owner/repo`` and ``owner/repo.git`` compare equal;
    nothing else is folded (case is significant).
    """
    p = (path or "").strip()
    if p.startswith("/"):
        p = p[1:]
    p = p.rstrip("/")
    if p.endswith(".git"):
        p = p[:-4]
    return p


def parse_git_url(url: str) -> tuple[str, str] | None:
    """Parse a git remote URL into (host, repo) or None if unparsable.

    Supports https/http URLs (host may carry a port, which is part
    of the host for scope matching — loopback fake remotes need it)
    and scp-like ``git@host:owner/repo`` / ``ssh://`` forms. The
    repo is normalised with :func:`normalize_repo_path`.
    """
    url = (url or "").strip()
    if not url:
        return None
    host = ""
    path = ""
    if "://" in url:
        scheme, rest = url.split("://", 1)
        if scheme not in ("http", "https", "ssh", "git"):
            return None
        if "@" in rest.split("/", 1)[0]:
            rest = rest.split("@", 1)[1]
        parts = rest.split("/", 1)
        host = parts[0]
        path = parts[1] if len(parts) > 1 else ""
    elif "@" in url and ":" in url:
        # scp-like: [user@]host:path
        before, path = url.split(":", 1)
        host = before.split("@", 1)[-1]
    else:
        return None
    if not host or not path:
        return None
    repo = normalize_repo_path(path)
    if "/" not in repo:
        return None
    return host, repo


def parse_credential_input(text: str) -> dict[str, str]:
    """Parse one git credential-protocol block.

    ``key=value`` lines up to the first blank line. Lines without
    ``=`` are ignored; later duplicates win (git never sends any).
    """
    fields: dict[str, str] = {}
    for line in (text or "").splitlines():
        if line == "":
            break
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        fields[key] = value
    return fields


def format_credential_output(fields: dict[str, str]) -> str:
    """Serialise credential fields as a protocol block + blank line."""
    return "".join(f"{k}={v}\n" for k, v in fields.items()) + "\n"


@dataclass(frozen=True)
class GitScope:
    """The one repo a git session may touch: host + owner/repo."""

    host: str
    repo: str  # "owner/name", normalised (no .git, no leading slash)

    def __post_init__(self) -> None:
        object.__setattr__(self, "repo", normalize_repo_path(self.repo))

    def matches(self, host: str, path: str) -> bool:
        """True iff a credential request is for exactly this repo."""
        return host == self.host and normalize_repo_path(path) == self.repo

    def matches_url(self, url: str) -> bool:
        parsed = parse_git_url(url)
        return parsed is not None and parsed == (self.host, self.repo)


@dataclass
class GitSession:
    """In-memory binding for one git session. Contains NO real key.

    The session token lives only in the issuer/wrapper that the
    broker constructs; this record carries the binding metadata
    (session id, key id, scope, expiry, class) used for checks.
    """

    session_id: str
    key_id: str
    scope: GitScope
    expires_at: float
    session_class: str = "write"
    provider: str = "github"

    def is_live(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return now < self.expires_at


@dataclass(frozen=True)
class GitCredential:
    """What the helper returns: a session token, never a real key."""

    username: str
    password: str  # the session token (kh_sess_...), NOT the provider key
    host: str
    repo: str
    expires_at: float


class GitCredentialIssuer:
    """Issues session-scoped git credentials for one live session.

    Constructed by the broker/wrapper with the session record and
    the session token string (in memory only). ``issue`` enforces
    liveness, host, and exact repo scope on every call; anything
    else returns None (deny, no credential, no detail to git).
    """

    def __init__(self, session: GitSession, token: str):
        if not isinstance(token, str) or not token.startswith(TOKEN_PREFIX):
            raise ValueError("git issuer requires a session token (kh_sess_...)")
        if session.provider != "github":
            raise ValueError("git issuer is GitHub-only in v0.2")
        self.session = session
        self._token = token

    def issue(self, host: str, path: str, now: float | None = None) -> GitCredential | None:
        now = time.time() if now is None else now
        if not self.session.is_live(now):
            return None
        if not self.session.scope.matches(host, path):
            return None
        return GitCredential(
            username=HELPER_USERNAME,
            password=self._token,
            host=self.session.scope.host,
            repo=self.session.scope.repo,
            expires_at=self.session.expires_at,
        )

    def issue_for_url(self, url: str, now: float | None = None) -> GitCredential | None:
        parsed = parse_git_url(url)
        if parsed is None:
            return None
        host, repo = parsed
        return self.issue(host, repo, now=now)


def _normalize_ref(ref: str) -> str:
    """Normalise a ref name for approval matching.

    Bare branch names become ``refs/heads/<name>`` (that is where a
    push of ``main`` lands); ``heads/x`` and ``tags/x`` gain the
    ``refs/`` prefix; full refs and ``*`` pass through unchanged.
    Approval refs are normalised the same way, so ``main`` and
    ``refs/heads/main`` match each other but nothing else does.
    """
    ref = (ref or "").strip()
    if ref in ("*", ""):
        return ref
    if ref.startswith("refs/"):
        return ref
    if ref.startswith("heads/") or ref.startswith("tags/"):
        return "refs/" + ref
    return "refs/heads/" + ref


@dataclass(frozen=True)
class Approval:
    """One broker-owned approval for git destruction.

    ``kinds`` is a subset of {"force_push", "ref_delete"}; ``refs``
    is the set of normalised refs it covers (``"*"`` covers all
    refs, and is required for ``--mirror``). An approval covers a
    request only when session, kind, refs (superset), and expiry
    all match — a force-push approval never authorises a deletion
    and vice versa.
    """

    approval_id: str
    session_id: str
    kinds: frozenset
    refs: frozenset
    expires_at: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "kinds", frozenset(self.kinds))
        object.__setattr__(
            self, "refs", frozenset(_normalize_ref(r) for r in self.refs))

    def covers(self, session_id: str, kind: str, refs: tuple[str, ...],
               now: float | None = None) -> bool:
        now = time.time() if now is None else now
        if self.session_id != session_id or kind not in self.kinds:
            return False
        if now >= self.expires_at:
            return False
        if "*" in self.refs:
            return True
        wanted = {_normalize_ref(r) for r in refs}
        return wanted <= set(self.refs)


class GitDenied(Exception):
    """Wrapper denial. ``code`` follows CONTRACT §9; ``message`` is
    the generic text shown to the agent (no rule internals)."""

    def __init__(self, message: str, code: str = ERR_POLICY_DENIED,
                 rule_id: str | None = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.rule_id = rule_id


@dataclass
class GitOperation:
    """Parsed remote git operation (wrapper input, never executed)."""

    command: str  # push | pull | fetch | clone
    remote: str | None  # raw remote arg (name or URL); None if absent
    refs: tuple[str, ...] = ()  # normalised refs (push refspec targets)
    force: bool = False  # gating-relevant force (push only)
    deletes: bool = False  # ref deletion requested (push only)
    flags: tuple[str, ...] = ()

    @property
    def needs_force_approval(self) -> bool:
        return self.command == "push" and self.force

    @property
    def needs_delete_approval(self) -> bool:
        return self.command == "push" and self.deletes


def _parse_push_refspec(spec: str, op_force: bool, op_deletes: bool,
                        refs: list[str]) -> tuple[bool, bool]:
    """Fold one push refspec into (force, deletes); appends its target."""
    force, deletes = op_force, op_deletes
    s = spec
    if s.startswith("+"):
        force = True
        s = s[1:]
    if ":" in s:
        src, dst = s.split(":", 1)
        if src == "":
            deletes = True
            refs.append(_normalize_ref(dst))
        else:
            refs.append(_normalize_ref(dst or src))
    else:
        refs.append(_normalize_ref(s))
    return force, deletes


def parse_git_args(argv: list[str]) -> GitOperation:
    """Parse wrapper argv (without the leading ``git``) into an operation.

    Only push/pull/fetch/clone are supported; anything else raises
    :class:`GitDenied` (KH-2001) because the wrapper is a remote-ops
    gate, not a general git passthrough — local commands (status,
    log, ...) must use plain git, where no credential is involved.
    The parser is deliberately strict about push: an unrecognised
    positional after the remote is treated as a refspec, which can
    only add approval requirements, never remove them.
    """
    if not argv:
        raise GitDenied("no git command given", ERR_USAGE, "GIT-USAGE-01")
    command = argv[0]
    if command not in _SUPPORTED_COMMANDS:
        raise GitDenied(
            f"git {command} is not a wrapped remote operation; "
            "use plain git for local commands",
            ERR_USAGE, "GIT-USAGE-02")
    rest = argv[1:]
    flags: list[str] = []
    positionals: list[str] = []
    i = 0
    force = False
    deletes = False
    all_refs = False
    delete_mode = False
    mirror = False
    while i < len(rest):
        arg = rest[i]
        if arg == "--":
            positionals.extend(rest[i + 1:])
            break
        if arg.startswith("--"):
            name, _, _value = arg.partition("=")
            flags.append(name)
            if name in ("--force", "--force-with-lease", "--force-if-includes"):
                if command == "push":
                    force = True
            elif name == "--delete":
                if command == "push":
                    deletes = True
                    delete_mode = True
            elif name == "--mirror":
                if command == "push":
                    force = True
                    deletes = True
                    mirror = True
            elif name in ("--all", "--tags"):
                if command == "push":
                    all_refs = True
            elif name in _PUSH_VALUE_OPTIONS:
                if "=" not in arg:
                    i += 1  # consume the option's value
            # Other long flags are boolean for parsing purposes.
        elif arg.startswith("-") and arg != "-":
            flags.append(arg)
            cluster = arg[1:]
            consumed_next = False
            for ch in cluster:
                if ch == "f" and command == "push":
                    force = True
                elif ch == "d" and command == "push":
                    deletes = True
                    delete_mode = True
                elif ch in _PUSH_SHORT_VALUE_OPTIONS:
                    # -o consumes the rest of the cluster or next arg.
                    if cluster.index(ch) < len(cluster) - 1:
                        break
                    consumed_next = True
                    break
            if consumed_next:
                i += 1
        else:
            positionals.append(arg)
        i += 1

    if command == "clone":
        if not positionals:
            raise GitDenied("git clone needs a URL", ERR_USAGE, "GIT-USAGE-03")
        return GitOperation(command=command, remote=positionals[0],
                            refs=(), flags=tuple(flags))
    if not positionals:
        # push/pull/fetch with no explicit remote: fail closed. The
        # configured upstream cannot be verified against the scope
        # without trusting repo config, so the wrapper refuses.
        raise GitDenied(
            "wrapper requires an explicit remote (name or URL); "
            "a bare git push/pull/fetch cannot be scope-checked",
            ERR_USAGE, "GIT-USAGE-04")
    remote = positionals[0]
    rest_pos = positionals[1:]
    refs: list[str] = []
    if command == "push":
        if mirror or all_refs:
            refs = ["*"]
        elif delete_mode:
            refs = [_normalize_ref(r) for r in rest_pos]
        else:
            for spec in rest_pos:
                force, deletes = _parse_push_refspec(spec, force, deletes, refs)
    else:
        # pull/fetch: positionals after the remote are branch names
        # or refspecs; logged, never gating (fetch --force only moves
        # local refs, it does not rewrite the remote).
        refs = tuple(_normalize_ref(r.split(":", 1)[-1].lstrip("+"))
                     for r in rest_pos)
        refs = list(refs)
    return GitOperation(command=command, remote=remote, refs=tuple(refs),
                        force=force, deletes=deletes, flags=tuple(flags))


@dataclass
class GitAuditEvent:
    """One wrapper audit event, handed to the caller's sink."""

    kind: str  # "decision" | "outcome"
    operation: str
    host: str
    repo: str
    refs: tuple[str, ...]
    decision: str  # "allow" | "deny"
    rule_id: str | None
    outcome: str
    approval_id: str | None = None


@dataclass
class GitResult:
    """Outcome of one wrapper run (agent-facing text stays generic)."""

    allowed: bool
    exit_code: int | None
    decision: str
    rule_id: str | None
    outcome: str
    approval_id: str | None = None
    message: str = ""
    outcome_logged: bool = True


def make_audit_sink(audit_log, audit_secret: bytes, session_id: str,
                    key_id: str):
    """Adapt a W09 AuditLog to the wrapper's sink callable.

    Pseudonyms are HMAC-SHA256(audit_secret, id) truncated to 16 hex
    (``audit.pseudonym``); the session token and the real key are
    never passed here and never appear in any entry. Decision events
    use ``write_decision`` and outcome events ``write_outcome``
    (CONTRACT §8 closed schema).
    """
    from .audit import pseudonym as _pseudonym

    session_pseudo = _pseudonym(audit_secret, session_id)
    key_pseudo = _pseudonym(audit_secret, key_id)

    def sink(event: GitAuditEvent) -> None:
        method = "GIT_" + event.operation.upper()
        canonical_path = f"git/{event.host}/{event.repo}"
        if event.kind == "decision":
            audit_log.write_decision(
                session_pseudo, key_pseudo, "github", method,
                canonical_path, event.decision, event.rule_id,
                event.outcome, 0, 0, event.approval_id)
        else:
            audit_log.write_outcome(
                session_pseudo, key_pseudo, "github", method,
                canonical_path, event.decision, event.rule_id,
                event.outcome, 0, 0, event.approval_id)

    return sink


def helper_script_path() -> Path | None:
    """Locate scripts/git-credential-helper next to this package."""
    candidate = Path(__file__).resolve().parent.parent / "scripts" / "git-credential-helper"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return candidate
    return None


class GitWrapper:
    """Gate + log + run for remote git operations through one session.

    ``token`` is held in memory only and is placed in the git child's
    environment (``KH_GIT_*``) so the credential helper can issue
    the session credential; it is never written to disk, a URL, or
    a config file. ``approval_gate`` is either a list of
    :class:`Approval` objects or a callable
    ``(session_id, kind, refs, now) -> approval_id | None``.
    ``audit_sink`` receives :class:`GitAuditEvent`; if it is None,
    git is never run (an unwitnessed push is a fail-closed deny).
    ``runner`` (tests only) replaces the git subprocess call with
    ``runner(argv, env) -> exit_code``.
    """

    def __init__(self, session: GitSession, token: str,
                 audit_sink=None, approvals=None,
                 git_binary: str = "git", runner=None):
        if not isinstance(token, str) or not token.startswith(TOKEN_PREFIX):
            raise ValueError("wrapper requires a session token (kh_sess_...)")
        self.session = session
        self._token = token
        self.audit_sink = audit_sink
        self.git_binary = git_binary
        self.runner = runner
        if approvals is None:
            self._approvals: list[Approval] = []
            self._gate = None
        elif callable(approvals):
            self._approvals = []
            self._gate = approvals
        else:
            self._approvals = list(approvals)
            self._gate = None

    # -- approvals ---------------------------------------------------
    def _approval_for(self, kind: str, refs: tuple[str, ...],
                      now: float) -> str | None:
        if self._gate is not None:
            return self._gate(self.session.session_id, kind, refs, now)
        for approval in self._approvals:
            if approval.covers(self.session.session_id, kind, refs, now):
                return approval.approval_id
        return None

    # -- remote resolution -------------------------------------------
    def _resolve_remote(self, remote: str) -> tuple[str, str] | None:
        """Resolve a remote arg to (host, repo): URL direct, or a
        remote name via ``git remote get-url`` (local, no network).
        None means unresolvable — fail closed, never guess."""
        parsed = parse_git_url(remote)
        if parsed is not None:
            return parsed
        if "/" in remote or "@" in remote or ":" in remote:
            return None  # looks like a URL but unparsable: refuse
        try:
            proc = subprocess.run(
                [self.git_binary, "remote", "get-url", remote],
                capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0:
            return None
        return parse_git_url(proc.stdout.strip())

    def _log(self, event: GitAuditEvent) -> None:
        if self.audit_sink is None:
            raise GitDenied("audit unavailable; refusing git operation",
                            ERR_AUDIT_UNAVAILABLE, "GIT-AUDIT-01")
        self.audit_sink(event)  # raises -> caller turns it into a deny

    # -- main entry ----------------------------------------------------
    def run(self, argv: list[str], now: float | None = None) -> GitResult:
        now = time.time() if now is None else now
        try:
            op = parse_git_args(argv)
        except GitDenied as exc:
            return GitResult(False, 2, "deny", exc.rule_id, "denied",
                             message="git operation refused")
        host = repo = ""
        try:
            if not self.session.is_live(now):
                raise GitDenied("session is not live", ERR_SESSION_DEAD,
                                "GIT-SESSION-01")
            if op.command == "push" and self.session.session_class not in (
                    "write", "destructive"):
                raise GitDenied("read session cannot push", ERR_POLICY_DENIED,
                                "GIT-CLASS-01")
            resolved = self._resolve_remote(op.remote) if op.remote else None
            if resolved is None:
                raise GitDenied("remote cannot be resolved to a scoped URL",
                                ERR_POLICY_DENIED, "GIT-SCOPE-01")
            host, repo = resolved
            if (host, repo) != (self.session.scope.host, self.session.scope.repo):
                raise GitDenied("remote is outside the session repo scope",
                                ERR_POLICY_DENIED, "GIT-SCOPE-02")
            approval_id = None
            if op.needs_force_approval:
                approval_id = self._approval_for("force_push", op.refs, now)
                if approval_id is None:
                    raise GitDenied(
                        "force-push requires a matching approval",
                        ERR_POLICY_DENIED, "GIT-FORCE-01")
            if op.needs_delete_approval:
                delete_approval = self._approval_for("ref_delete", op.refs, now)
                if delete_approval is None:
                    raise GitDenied(
                        "ref deletion requires a matching approval",
                        ERR_POLICY_DENIED, "GIT-DELETE-01")
                approval_id = approval_id or delete_approval
            helper = helper_script_path()
            if helper is None:
                raise GitDenied(
                    "git credential helper is not installed; refusing "
                    "to run git without it", ERR_UPSTREAM, "GIT-HELPER-01")
            # Decision entry BEFORE git runs (fail closed on sink error).
            try:
                self._log(GitAuditEvent(
                    "decision", op.command, host, repo, op.refs, "allow",
                    "GIT-ALLOW-01", "forwarded", approval_id))
            except GitDenied:
                raise
            except Exception as exc:
                raise GitDenied("audit unavailable; refusing git operation",
                                ERR_AUDIT_UNAVAILABLE, "GIT-AUDIT-02") from exc
            env = dict(os.environ)
            env["KH_GIT_SESSION_TOKEN"] = self._token
            env["KH_GIT_EXPIRES_AT"] = str(int(self.session.expires_at))
            env["KH_GIT_SCOPE_HOST"] = self.session.scope.host
            env["KH_GIT_SCOPE_REPO"] = self.session.scope.repo
            env["GIT_TERMINAL_PROMPT"] = "0"
            git_argv = [
                self.git_binary,
                "-c", "credential.helper=",
                "-c", f"credential.helper={helper}",
                "-c", "credential.useHttpPath=true",
            ] + argv
            if self.runner is not None:
                exit_code = self.runner(git_argv, env)
            else:
                proc = subprocess.run(git_argv, env=env)
                exit_code = proc.returncode
            outcome = "success" if exit_code == 0 else "failure"
            outcome_logged = True
            try:
                self._log(GitAuditEvent(
                    "outcome", op.command, host, repo, op.refs, "allow",
                    "GIT-ALLOW-01", outcome, approval_id))
            except Exception:
                outcome_logged = False
            return GitResult(True, exit_code, "allow", "GIT-ALLOW-01",
                             outcome, approval_id,
                             message="git operation completed"
                             if exit_code == 0 else "git operation failed",
                             outcome_logged=outcome_logged)
        except GitDenied as exc:
            # Deny entry: best effort, but a sink failure must not
            # turn a deny into anything else — the operation is
            # already refused, so record the failure in the result.
            try:
                if host and repo:
                    self._log(GitAuditEvent(
                        "decision", op.command, host, repo, op.refs, "deny",
                        exc.rule_id, "denied", None))
            except Exception:
                pass
            return GitResult(False, 2, "deny", exc.rule_id, "denied",
                             message="git operation refused")


# ------------------------------------------------------- helper protocol

@dataclass
class GitHelperContext:
    """Wrapper-set environment for one helper invocation.

    Read from ``KH_GIT_*`` by the helper script. The token is
    present only in the git child's environment, never on disk.
    """

    token: str
    expires_at: float
    scope_host: str
    scope_repo: str
    username: str = HELPER_USERNAME

    @classmethod
    def from_env(cls, env) -> "GitHelperContext | None":
        token = env.get("KH_GIT_SESSION_TOKEN", "")
        if not isinstance(token, str) or not token.startswith(TOKEN_PREFIX):
            return None
        try:
            expires_at = float(env.get("KH_GIT_EXPIRES_AT", "0"))
        except (TypeError, ValueError):
            return None
        scope_host = env.get("KH_GIT_SCOPE_HOST", "")
        scope_repo = normalize_repo_path(env.get("KH_GIT_SCOPE_REPO", ""))
        if not scope_host or not scope_repo or "/" not in scope_repo:
            return None
        return cls(token=token, expires_at=expires_at,
                   scope_host=scope_host, scope_repo=scope_repo)

    def to_issuer(self) -> GitCredentialIssuer:
        session = GitSession(
            session_id="helper-session", key_id="helper-key",
            scope=GitScope(self.scope_host, self.scope_repo),
            expires_at=self.expires_at, session_class="write")
        return GitCredentialIssuer(session, self.token)


def handle_helper(action: str, input_text: str,
                  context: GitHelperContext | None,
                  now: float | None = None) -> tuple[str, int]:
    """Serve one git credential-helper action. Returns (stdout, exit).

    ``get``: returns the session credential iff the context is
    present, live, and the requested host/path match the scope
    exactly; otherwise empty output + exit 1 (no credential, no
    detail — and never the token on a deny path).
    ``store`` / ``erase``: deliberate no-ops (exit 0, no output).
    A session credential must NEVER be persisted into a git
    credential store (that would create exactly the standing
    credential this product exists to remove), and there is nothing
    stored to erase. Unknown actions: exit 1, no output.
    """
    now = time.time() if now is None else now
    if action in ("store", "erase"):
        return "", 0
    if action != "get" or context is None:
        return "", 1
    fields = parse_credential_input(input_text)
    host = fields.get("host", "")
    path = fields.get("path", "")
    if not host or not path:
        return "", 1
    credential = context.to_issuer().issue(host, path, now=now)
    if credential is None:
        return "", 1
    out = format_credential_output({
        "protocol": fields.get("protocol", "https"),
        "host": credential.host,
        "path": credential.repo,
        "username": credential.username,
        "password": credential.password,
    })
    return out, 0


COVERAGE: dict[str, object] = {
    "helper_get": "session token only, scope host + exact repo, TTL-capped; "
                  "refuses other hosts/repos and expired sessions; never a real key",
    "helper_store_erase": "deliberate no-ops: session credentials are never persisted",
    "wrapper_logged_gated": "push/pull/fetch/clone via the wrapper: decision "
                             "logged before git runs, outcome after; force-push and "
                             "ref deletion denied without a matching live approval",
    "wrapper_scope": "remote must resolve to exactly the session repo scope; "
                     "bare push/pull/fetch with no explicit remote refused",
    "wrapper_credential_lockdown": "git runs with ONLY this helper "
        "(credential.helper reset first) and GIT_TERMINAL_PROMPT=0",
    "not_covered": [
        "direct git with standing credentials outside the wrapper/helper: "
        "not logged, not gated (doctor must flag standing credentials)",
        "direct git with a stolen/standing session token: not gated "
        "(Tier B; same-user process can reuse anything it can read)",
        "git-protocol traffic to a real provider: no Keyholder git proxy "
        "exists in this slice, so the helper credential authenticates only "
        "against a proxy/fake remote that validates session tokens",
        "per-path restriction inside a push: not enforceable from refspecs "
        "(use API-only sessions for path-bound templates)",
        "helper get calls outside the wrapper: scope/expiry-checked but "
        "not individually audit-logged (see module docstring)",
        "clone/fetch of a repo the session scope allows but the provider "
        "key cannot read: fails at the provider, not at the wrapper",
    ],
}


def coverage_report() -> str:
    lines = ["Keyholder git interposition — coverage (v0.2 helper+wrapper slice):"]
    for key, value in COVERAGE.items():
        if isinstance(value, list):
            lines.append(f"  NOT COVERED:")
            for item in value:
                lines.append(f"    - {item}")
        else:
            lines.append(f"  {key}: {value}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":  # pragma: no cover - exercised via the script
    sys.stderr.write("use scripts/git-credential-helper, not this module\n")
    sys.exit(2)
