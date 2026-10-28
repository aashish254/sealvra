"""Keyholder GitHub adapter (W06) — rewritten per audit f09 / plan v3 §1J.

This module is the GitHub provider pack logic for Keyholder v0.1:
fine-grained PAT primary, REST-only, GraphQL denied. It performs NO
network calls to GitHub itself; every function here is pure
classification / verification-helper logic over a method, path and
(optional) request body. The broker (W04/W05) owns forwarding, approval
and audit; this module tells it what a request *is*.

Corrected classification — the core f09 fix (N-J2):
  ``Contents: write`` is NOT "files only". Per GitHub's own
  permissions documentation it also covers branch/tag create AND
  delete, ref updates, branch rename, merges, PR merge, release
  create/delete + asset delete, repository dispatches and
  merge-upstream. Every one of those is classified write/destructive
  in the pack data below, never passed through as a plain file edit.

Decision levels (CONTRACT §2, shared with the broker):
  1 = allow, 2 = allow-with-log, 3 = approve (broker-owned approval
  required before forwarding), 4 = deny. A level-4 result from this
  module means "do not forward on the session's authority alone".
  Merge endpoints return level 4: merges are NEVER auto-allowed by a
  session; they require a fresh broker-owned approval (CONTRACT §8:
  destructive calls get fresh per-call approval, no session-scope
  reuse) and this module on its own never grants one.

GraphQL — denied, enumerated (N-J7):
  ``POST /graphql`` (api.github.com and any GitHub Enterprise Server
  host) is denied outright. The GraphQL-only destructive operations
  that this deny covers are enumerated in GRAPHQL_ONLY_DESTRUCTIVES
  below, because a future GraphQL allowlist would have to deny each
  of them by name: deleteDiscussion, deleteDiscussionComment,
  deleteIssue, deleteEnvironment, pinIssue/unpinIssue, transferIssue,
  enablePullRequestAutoMerge/disablePullRequestAutoMerge,
  enqueuePullRequest/dequeuePullRequest (merge queue),
  dismissPullRequestReview, dismissRepositoryVulnerabilityAlert,
  updateBranchProtectionRule/deleteBranchProtectionRule,
  resolveReviewThread/unresolveReviewThread,
  deleteProjectV2/deleteProjectV2Item/deleteProjectV2Field, plus the
  whole Discussions and Projects v2 surfaces. Discussions and
  Projects v2 have NO REST API; any old mapping of them to
  issue/repo scopes was fiction and is not reproduced here.

Import-time HARD DENIES (N-J5) — refuse the key, not just warn:
  * account SSH keys write (Git SSH keys, GPG keys, SSH signing keys):
    adding an attacker key gives git push access as the user to EVERY
    repo the user can access, bypassing the repo allowlist, the
    compartment, the proxy and the kill switch in one call.
  * gists write: a public exfiltration channel (private-repo content
    posted to a public gist; the repo allowlist cannot see it because
    the destination is not a repository).
  * secrets write/rotate/delete, all families: repository Actions,
    organization Actions, environment, repository + organization
    Dependabot, repository + organization + user Codespaces, and
    agents-session secrets. Rationale corrected (f09 F15): GitHub's
    API never returns secret *values* (list/get return names and
    metadata only), so the risk is not "reading a secret" — it is
    write/rotate to an attacker-known value (persistence/takeover)
    and write + workflow execution = exfiltration.
  * repository deletion (DELETE /repos/{owner}/{repo}): refused in
    v0.1 — the broker never proxies it; the user does it directly
    in GitHub. (This resolves the v1 contradiction: refusal wins,
    the approval flow for repo deletion is dead text and is not
    implemented.)

Comment-command deny (N-J3, f09 F24):
  Comments are a command channel. Repos running ``issue_comment``-
  triggered bots obey any write-access commenter — which the session
  identity is, by construction. A single comment body starting with
  ``/deploy`` can deploy to production AND merge the PR; ``/approve``,
  ``/backport``, ``@claude merge`` / ``lgtm`` / ``approve`` approve
  and enable auto-merge. Broker-fill does NOT close this hole: the
  comment still posts under the user's identity. Comment bodies
  matching COMMENT_COMMAND_PATTERNS are denied at the proxy, comment
  targets are bound to the session repo allowlist (checked by the
  broker, not here), and sessions targeting repos with
  ``issue_comment``-triggered workflows must be warned at creation
  (see ``comment_workflow_warning``).

PAT verification corrections (N-J8, f09 F26/F27/F28):
  * The ``permissions`` object on a repository response
    (admin/maintain/push/triage/pull) is a ROLE, not a grant. It has
    five fields and cannot express ~50 fine-grained permissions; a
    contents:read-only token on an admin-owned repo and a
    contents:write + actions:write token on the same repo are
    indistinguishable through it. It must NEVER be presented as grant
    verification. ``verify_token()`` therefore marks every permission
    it cannot probe "unverified" (fail closed) and never infers a
    grant from the role object.
  * Fine-grained PATs return NO ``X-OAuth-Scopes`` header. Absence of
    that header for a fine-grained PAT means nothing — it must not be
    read as "no permissions" or "all permissions".
  * Classic PATs DO return ``X-OAuth-Scopes``; import enumerates the
    actual scopes from that header where present. Classic ``repo``
    excludes workflow-file updates (separate ``workflow`` scope) and
    repo deletion (separate ``delete_repo`` scope).
  * SAML: fine-grained PATs are authorised DURING creation — a token
    that skipped SSO authorisation simply 404s; the fix is to
    RE-CREATE the token, not to follow an authorisation URL. The
    classic 403 + ``X-GitHub-SSO`` flow (URL expires after 1 hour,
    never cached) is classic-only. GitHub App tokens are
    auto-authorised and need no SAML handling.
  * PAT expiry is USER-ATTESTED, never verified: GitHub exposes no
    endpoint returning a PAT's expiry. Fine-grained PATs may have NO
    expiration at all (not "max 366 days"); a no-expiry PAT is
    flagged like a coarse credential. Pending org approval is
    indistinguishable from no access (public reads succeed, private
    reads 404) and is surfaced as an explicit diagnostic hypothesis.
  * Token lifetimes are read from the token response (``expires_in``),
    never assumed: OAuth tokens may expire (8 h access + 6 mo refresh
    via app opt-in or ``offline_access``); GitHub App user tokens are
    8 h only when expiration is enabled (the app owner can disable
    it); installation tokens are RE-MINTED before expiry (1 h), never
    "refreshed", with mint-time repository + permission subsetting.

Rate limits (N-J1, f09 F04/F30) — recorded, not enforced here:
  installation 5,000/hr minimum (scaling to 12,500 by repo/user
  count), 15,000/hr only for GitHub Enterprise Cloud org/enterprise
  installations. Requests on a user's behalf count toward the user's
  personal 5,000/hr pool, and higher-limit app usage eats the
  lower-limit budget — session budgets must be computed per shared
  pool, not per credential. Secondary limits: 100 concurrent
  requests, 900 points/min REST, 2,000 points/min GraphQL, plus a
  5,000 points/hr GraphQL budget if GraphQL ever ships. The broker
  owns budget enforcement; this module only supplies the constants.

Git-protocol pushes — NOT INTERPOSED in v0.1 (N-J4, f09 F22):
  ``GIT_INTERPOSITION_BUILT`` is False, honestly. A ``git push``,
  ``git push --force`` or ``git push :branch`` over HTTPS talks to
  github.com (or the GHES host) directly and never becomes a REST
  call the proxy can inspect — so the merge gate, force-push gate,
  branch-delete gate and path restriction do NOT apply to it. Git
  pushes bypass the broker manifest and are NOT logged/gated. The
  README note W18 must carry is in ``GIT_PUSH_README_NOTE``; no
  caller may claim otherwise. API-only sessions (no git-usable
  credential handed to the agent) are the only v0.1 mitigation, and
  that is a broker/session-template decision, not something this
  module can enforce after the fact. Release-asset upload goes to
  ``uploads.github.com``, not ``api.github.com`` — the host allowlist
  must name it (see ALLOWED_HOSTS).

Threat tiers (CONTRACT §10): every control in this module binds an
interface-bound (Tier A) agent going through the proxy. NOTHING here
survives a shell-capable same-user (Tier B) agent that holds the raw
key or talks to GitHub directly — including via git protocol (above)
or via a second credential. Same-user malware / compromised OS
account is out of scope by design.

Session-end artifact inventory (N-J9, f09 F29):
  Killing a session revokes the session credential; it does NOT kill
  what the session created on the provider. Webhooks (permanent
  exfiltration to an attacker URL), deploy keys (permanent push
  credential), collaborator invites and org invitations all survive
  the kill switch. ``ArtifactInventory`` records artifacts created
  during a session window so the broker can present them for
  one-click removal at kill/end. Default templates deny webhook
  creation, deploy-key creation and collaborator invites outright
  (persistence primitives, not job actions); this module classifies
  them level 4 so a template cannot silently enable them by granting
  a broad permission.

Tier note for the remaining classifications: PR approvals, review
dismissal, update-branch (merges base into head), conversation
resolution, issue transfer and run/log/artifact deletion are trust
actions, not comments (N-J6). Checks/statuses write can fabricate
green CI and is merge-adjacent. Environments write can remove
required reviewers; fork-PR workflow-run approval hands repo
secrets to unreviewed code (pwn-request vector) and is in the
deployment approval class. None of these is auto-allowed here.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------- constants

API_VERSION_PIN = "2022-11-28"
# Per-host pins must be reviewed at every adapter release (f09 F07);
# github.com and each GHES host version independently. This pin is the
# github.com default only and must not be assumed valid for a GHES host.
GITHUB_COM_HOST = "api.github.com"
ALLOWED_HOSTS = ("api.github.com", "uploads.github.com", "github.com")
# uploads.github.com exists ONLY for release-asset upload; it is not a
# general API host and must not be allowlisted for other paths.

# Rate-limit constants (f09 F04/F30) — for the broker's budget planner.
RATE_LIMIT_USER_PER_HOUR = 5_000
RATE_LIMIT_INSTALLATION_MIN_PER_HOUR = 5_000
RATE_LIMIT_INSTALLATION_SCALED_MAX_PER_HOUR = 12_500
RATE_LIMIT_ENTERPRISE_CLOUD_PER_HOUR = 15_000
SECONDARY_LIMIT_CONCURRENT = 100
SECONDARY_LIMIT_REST_POINTS_PER_MIN = 900
SECONDARY_LIMIT_GRAPHQL_POINTS_PER_MIN = 2_000
GRAPHQL_BUDGET_POINTS_PER_HOUR = 5_000

# Git interposition: NOT built in v0.1. See module docstring.
GIT_INTERPOSITION_BUILT = False
GIT_PUSH_README_NOTE = (
    "Git-protocol pushes bypass the broker manifest and are NOT "
    "logged/gated: `git push`, `git push --force` and `git push "
    ":branch` over HTTPS never become REST calls the proxy can "
    "inspect, so the merge gate, force-push gate, branch-delete gate "
    "and path restriction do not apply to them. Use API-only "
    "sessions (no git-usable credential handed to the agent) if "
    "push control is required."
)

MERGE_APPROVAL_LEVEL = 4  # merges are never auto-allowed (see docstring)


@dataclass(frozen=True)
class Decision:
    """Classification result. Mirrors CONTRACT §2 PolicyDecision shape.

    allowed=False with level=3 means "forward only after a fresh
    broker-owned approval"; allowed=False with level=4 means "deny".
    This module never grants an approval itself, so merge/level-4
    results are always allowed=False here.
    """

    allowed: bool
    level: int  # 1 allow, 2 allow-with-log, 3 approve, 4 deny
    reason: str
    rule_id: str | None = None


def _deny(reason: str, rule_id: str) -> Decision:
    return Decision(allowed=False, level=4, reason=reason, rule_id=rule_id)


def _approve(reason: str, rule_id: str) -> Decision:
    return Decision(allowed=False, level=3, reason=reason, rule_id=rule_id)


# ---------------------------------------------------------------- path utils

def canonical_path(raw_path: str) -> str:
    """Split-first path canonicalisation (CONTRACT §6 rule 2).

    The query string is dropped before any decoding, so an encoded
    ``?`` or ``/`` in a segment cannot smuggle a different endpoint.
    Returns the path with duplicate slashes collapsed and a trailing
    slash removed (except for the root).
    """
    path = raw_path.split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    path = re.sub(r"/+", "/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


def _segments(path: str) -> list[str]:
    return [s for s in canonical_path(path).split("/") if s]


def _match(pattern: str, path: str) -> dict[str, str] | None:
    """Match a ``/repos/{owner}/{repo}/...`` pattern. ``{name}`` binds
    one segment; a trailing ``{rest+}`` binds the remainder."""
    p_segs = [s for s in pattern.split("/") if s]
    s_segs = _segments(path)
    out: dict[str, str] = {}
    i = 0
    for p in p_segs:
        if p.startswith("{") and p.endswith("+}"):
            name = p[1:-2]
            if i >= len(s_segs):
                return None
            out[name] = "/".join(s_segs[i:])
            return out
        if i >= len(s_segs):
            return None
        if p.startswith("{") and p.endswith("}"):
            out[p[1:-1]] = s_segs[i]
        elif p != s_segs[i]:
            return None
        i += 1
    if i != len(s_segs):
        return None
    return out


# ------------------------------------------------------- Contents:write (N-J2)

# Every Contents:write member that is NOT a plain file edit. Each is
# separately denied unless a template explicitly enables that exact
# action AND a fresh broker approval is granted (level 4 here = the
# module never auto-allows it; the broker's approval path is the only
# route, and for branch/tag/release deletion the v0.1 default is
# deny-with-typed-confirmation, not silent approval).
CONTENTS_WRITE_ACTIONS: dict[str, str] = {
    "DELETE /git/refs": "branch/tag delete (Contents:write, not admin)",
    "POST /git/refs": "branch/tag create",
    "PATCH /git/refs": "ref update (force:true is a force-push, denied)",
    "POST /branches/{branch}/rename": "branch rename",
    "POST /merges": "branch-to-branch merge with no pull request",
    "PUT /pulls/{n}/merge": "PR merge (merge gate, level 4)",
    "PUT /pulls/{n}/merge-async": "async PR merge (Oct 1 GA; bypass flag denied)",
    "POST /releases": "release create",
    "DELETE /releases": "release delete",
    "POST /releases/assets": "release asset create (uploads.github.com)",
    "DELETE /releases/assets": "release asset delete",
    "POST /dispatches": "repository dispatch (workflow trigger)",
    "POST /merge-upstream": "merge-upstream",
    "PATCH /comments": "commit-comment edit",
    "DELETE /comments": "commit-comment delete",
    "DELETE /contents": "file delete (destructive; approval-gated, not a plain edit)",
    "POST /dependency-graph/snapshots": "dependency-graph snapshot submit",
}

# Deletion matrix (f09 F20): every delete path, its gating permission
# and its v0.1 default. "refused" = broker never proxies it in v0.1.
DELETION_MATRIX: tuple[dict[str, str], ...] = (
    {"path": "DELETE /repos/{owner}/{repo}", "permission": "Administration:write (classic: delete_repo)",
     "default": "refused in v0.1 — do it directly in GitHub"},
    {"path": "DELETE /git/refs/heads/* or /git/refs/tags/*", "permission": "Contents:write",
     "default": "denied unless template enables + typed confirmation"},
    {"path": "DELETE /releases/{id} (+ asset delete)", "permission": "Contents:write",
     "default": "denied unless template enables + typed confirmation"},
    {"path": "DELETE /contents/.github/workflows/*", "permission": "Contents:write + Workflows:write",
     "default": "denied unless template enables workflow-file deletion"},
    {"path": "PUT /actions/workflows/{id}/disable", "permission": "Actions:write",
     "default": "denied (workflow kill, not just an edit)"},
    {"path": "DELETE /actions/runs/{id} (+ artifacts, logs)", "permission": "Actions:write",
     "default": "hard-denied in every template (evidence destruction)"},
    {"path": "DELETE /branches/{branch}/protection", "permission": "Administration:write",
     "default": "denied unless Administration withheld (no separate gate)"},
    {"path": "DELETE /rulesets/{id} / PUT /rulesets/{id}", "permission": "Administration:write",
     "default": "hard-denied for bypass-actor edits (voids all gates)"},
    {"path": "DELETE /environments/{name}", "permission": "Environments:write",
     "default": "denied unless template enables"},
    {"path": "DELETE /deployments/{id}", "permission": "Deployments:write",
     "default": "denied unless template enables"},
    {"path": "GraphQL deleteDiscussion / deleteDiscussionComment / deleteIssue / deleteEnvironment / deleteProjectV2*",
     "permission": "Discussions/Projects:write (GraphQL-only)",
     "default": "denied with /graphql in v0.1"},
    {"path": "DELETE /issues/comments/{id} / DELETE /pulls/comments/{id}", "permission": "Issues:write / Pull requests:write",
     "default": "denied in comment templates (evidence destruction)"},
    {"path": "DELETE /labels/{name} / DELETE /milestones/{n}", "permission": "Issues:write",
     "default": "denied unless template enables"},
    {"path": "DELETE /hooks/{id}", "permission": "Webhooks:write",
     "default": "denied; also hides session-created webhooks (see inventory)"},
    {"path": "DELETE /keys/{id} / DELETE /collaborators/{user}", "permission": "Administration:write",
     "default": "denied unless template enables"},
    {"path": "DELETE /orgs/{org}/members/{user}", "permission": "Members:write (org)",
     "default": "denied (unmapped in v1; mapped here as deny)"},
    {"path": "DELETE self-hosted runner", "permission": "Self-hosted runners:write (org)",
     "default": "denied (unmapped in v1; mapped here as deny)"},
)

# ------------------------------------------------------------- GraphQL deny

GRAPHQL_ONLY_DESTRUCTIVES: tuple[str, ...] = (
    "deleteDiscussion", "deleteDiscussionComment", "deleteIssue",
    "deleteEnvironment", "pinIssue", "unpinIssue", "transferIssue",
    "enablePullRequestAutoMerge", "disablePullRequestAutoMerge",
    "enqueuePullRequest", "dequeuePullRequest",
    "dismissPullRequestReview", "dismissRepositoryVulnerabilityAlert",
    "updateBranchProtectionRule", "deleteBranchProtectionRule",
    "resolveReviewThread", "unresolveReviewThread",
    "deleteProjectV2", "deleteProjectV2Item", "deleteProjectV2Field",
    "createDiscussion", "updateDiscussion", "createDiscussionComment",
    "updateDiscussionComment", "createProjectV2", "updateProjectV2",
    "all Projects v2 mutations",
)


def is_graphql(path: str) -> bool:
    """True for any GraphQL endpoint on any host (path-complete AND
    host-complete: api.github.com/graphql and GHES equivalents)."""
    return canonical_path(path) == "/graphql"


# ------------------------------------------------------- comment commands

# Slash commands denied at the start of any comment line (f09 F24).
# The list is extensible per repo: brokers should append repo-specific
# bot commands discovered from the repo's workflow files.
SLASH_COMMANDS: tuple[str, ...] = (
    "deploy", "merge", "approve", "test", "backport", "rebase",
    "release", "run", "retest", "ok-to-test", "teardown", "review",
    "describe", "improve", "ship", "lgtm",
)
# Bot @-mentions denied anywhere in a comment body.
BOT_MENTIONS: tuple[str, ...] = ("@claude", "@copilot")

COMMENT_COMMAND_PATTERNS: tuple[str, ...] = tuple(
    [f"/{c}" for c in SLASH_COMMANDS] + list(BOT_MENTIONS)
)

_SLASH_RE = re.compile(
    r"(?m)^[ \t]*/(" + "|".join(SLASH_COMMANDS) + r")\b", re.IGNORECASE)
_BOT_RE = re.compile(
    r"(?i)(?:^|[\s,;:(])(" + "|".join(re.escape(b) for b in BOT_MENTIONS) + r")\b")


def check_comment_body(body: str) -> Decision:
    """Deny comment bodies that are bot commands (f09 F24).

    Matches a slash command at the start of ANY line (not just the
    first — a command buried mid-comment still fires the bot) and any
    bot @-mention. Returns level 4 deny; anything else is level 2
    (allow-with-log: comments are public and attributable, so the
    broker logs target + body hash). Plain text that merely mentions
    the word "deploy" without a leading slash is not denied.
    """
    if not isinstance(body, str):
        return _deny("comment body is not text", "GH-COMMENT-01")
    m = _SLASH_RE.search(body)
    if m:
        return _deny(
            f"comment contains bot slash-command '/{m.group(1).lower()}'",
            "GH-COMMENT-01")
    m = _BOT_RE.search(body)
    if m:
        return _deny(
            f"comment mentions bot account '{m.group(1).lower()}'",
            "GH-COMMENT-02")
    return Decision(allowed=True, level=2,
                    reason="comment body has no bot command pattern",
                    rule_id="GH-COMMENT-OK")


def comment_workflow_warning(has_issue_comment_workflow: bool) -> str | None:
    """Session-creation warning (N-J3): warn when the target repo
    contains issue_comment-triggered workflows, because then ANY
    write-access commenter — including this session — can trigger
    bot automation. Returns None when no warning applies."""
    if has_issue_comment_workflow:
        return (
            "Warning: this repository has issue_comment-triggered "
            "workflows. Comments posted by this session can trigger "
            "bot automation (deploy/merge/approve) even though the "
            "session has no merge or deploy permission. "
            "Command-pattern comments are denied by the proxy."
        )
    return None


# ------------------------------------------------------- import hard denies

# Import-time HARD DENIES: refuse the key, do not just warn (N-J5).
# Keys are fine-grained permission names as the user would tick them
# at token creation, plus classic scopes that imply them.
HARD_DENY_IMPORT: tuple[dict[str, str], ...] = (
    {"permission": "Git SSH keys:write",
     "why": "account takeover: attacker key = push as user to every repo"},
    {"permission": "GPG keys:write",
     "why": "account signing-key takeover"},
    {"permission": "SSH signing keys:write",
     "why": "account signing-key takeover"},
    {"permission": "Gists:write",
     "why": "public exfiltration channel (destination is not a repo)"},
    {"permission": "Secrets:write (all families)",
     "why": "write/rotate to attacker-known value = persistence/takeover; "
            "write + workflow execution = exfiltration (values are "
            "never readable via the API, so 'read' is not the risk)"},
    {"permission": "Administration:write for repo deletion",
     "why": "repo deletion is refused in v0.1 regardless of template"},
)

SECRET_FAMILIES: tuple[str, ...] = (
    "repository Actions secrets", "organization Actions secrets",
    "environment secrets", "repository Dependabot secrets",
    "organization Dependabot secrets", "repository Codespaces secrets",
    "organization Codespaces secrets", "user Codespaces secrets",
    "agents-session secrets",
)

# Unmapped-in-v1 permissions, mapped here as deny-by-default (f09 F16).
UNMAPPED_DENY_DEFAULT: tuple[str, ...] = (
    "Webhooks:write", "Attestations:write", "Codespaces:write",
    "Codespaces lifecycle admin", "Codespaces secrets:write",
    "Custom properties:write", "Vulnerability alerts:write",
    "Repository advisories:write", "Secret scanning alerts:write",
    "Security events:write", "Variables:write", "Merge queues:write",
    "Members:write", "Self-hosted runners:write",
    "Custom organization roles:write", "Organization webhooks:write",
    "Organization Codespaces:write", "Team discussions:write",
    "Knowledge bases:write", "Personal access tokens (review/revoke)",
    "Organization announcement banners:write", "Events:write",
    "Blocking users:write", "Email addresses:write", "Profile:write",
    "Followers:write", "Interaction limits:write", "Starring:write",
    "Watching:write", "Plan:write", "Copilot:write",
)


def check_import_permissions(permissions: list[str]) -> list[dict[str, str]]:
    """Return one refusal entry per hard-deny permission present.

    Matching is case-insensitive and substring-based on the family
    name, so "account SSH keys", "gists" with write, and any
    "secrets" write/rotate entry are caught even when the token UI
    words them differently. An empty return means no hard deny fired
    — it does NOT mean the key is least-privilege.
    """
    refusals: list[dict[str, str]] = []
    lowered = [p.lower() for p in permissions]
    probes = (
        ("ssh key", "Git SSH keys:write"),
        ("gpg key", "GPG keys:write"),
        ("signing key", "SSH signing keys:write"),
        ("gist", "Gists:write"),
        ("secret", "Secrets:write (all families)"),
    )
    for needle, name in probes:
        if any(needle in p and "write" in p for p in lowered) or (
                needle == "secret" and any(needle in p for p in lowered)):
            why = next((d["why"] for d in HARD_DENY_IMPORT
                        if d["permission"].startswith(name.split(":")[0])),
                       "import-time hard deny")
            refusals.append({"permission": name, "why": why})
    return refusals


# ------------------------------------------------------- main classifier

def _is_merge_path(method: str, path: str) -> str | None:
    """Return a merge-path label or None. All three merge paths are
    gated (N-J2): REST merge, merge-async (202 + rules-bypass flag),
    and merge queue (REST + GraphQL enqueue)."""
    segs = _segments(path)
    if len(segs) >= 5 and segs[0] == "repos" and segs[3] == "pulls":
        if method == "PUT" and segs[-1] == "merge":
            return "REST PR merge"
        if method == "PUT" and segs[-1] == "merge-async":
            return "async PR merge"
        if method == "PUT" and segs[-1] == "update-branch":
            return "PR update-branch (merges base into head)"
        if method == "POST" and segs[-1] == "merge":
            return "PR merge (POST form)"
    if method == "POST" and canonical_path(path) == "/merges":
        return "branch-to-branch merge (no PR)"
    return None


def classify(method: str, path: str, body: dict | None = None,
             repo_allowlist: tuple[str, ...] | None = None) -> Decision:
    """Classify one GitHub REST request. Unmodelled endpoint = deny
    (CONTRACT §6 rule 4). ``body`` is the already-parsed JSON object
    (duplicate-key rejection and smuggling checks are the proxy's
    job, not this module's). ``repo_allowlist`` entries are
    "owner/repo" strings; a request outside it is denied here so a
    broker that forgets the check still fails closed for repo paths.
    """
    method = method.upper()
    cpath = canonical_path(path)
    body = body or {}

    # 0. GraphQL: always denied.
    if is_graphql(cpath):
        return _deny("GraphQL denied in v0.1 (see GRAPHQL_ONLY_DESTRUCTIVES)",
                     "GH-GRAPHQL-01")

    # 0b. Repo allowlist binding (also applies to comment targets).
    m = _match("/repos/{owner}/{repo}/{rest+}", cpath)
    if m and repo_allowlist is not None:
        if f"{m['owner']}/{m['repo']}" not in repo_allowlist:
            return _deny("repository outside session allowlist",
                         "GH-ALLOWLIST-01")

    # 1. Repo deletion: refused in v0.1, always.
    if method == "DELETE" and _match("/repos/{owner}/{repo}", cpath):
        return _deny("repository deletion refused in v0.1 (do it in GitHub)",
                     "GH-DELETE-01")

    # 2. Merge paths: level 4, never auto-allowed.
    merge = _is_merge_path(method, cpath)
    if merge:
        if cpath.endswith("merge-async") and body.get("bypass_rules") is True:
            return _deny("async merge with rules-bypass flag denied",
                         "GH-MERGE-02")
        return Decision(allowed=False, level=MERGE_APPROVAL_LEVEL,
                        reason=f"{merge} requires fresh broker-owned approval",
                        rule_id="GH-MERGE-01")

    # 3. Comment bodies: command-pattern deny (checked for both issue
    # and PR comments, create and edit).
    if method in ("POST", "PATCH") and (
            _match("/repos/{owner}/{repo}/issues/{n}/comments", cpath)
            or _match("/repos/{owner}/{repo}/pulls/{n}/comments", cpath)
            or _match("/repos/{owner}/{repo}/issues/comments/{id}", cpath)
            or _match("/repos/{owner}/{repo}/pulls/comments/{id}", cpath)):
        if method == "PATCH" or (
                _match("/repos/{owner}/{repo}/issues/comments/{id}", cpath)
                or _match("/repos/{owner}/{repo}/pulls/comments/{id}", cpath)):
            # Comment edit/delete in comment templates = evidence
            # destruction (f09 F25): denied unless a template
            # explicitly enables it — this module defaults to deny.
            if method == "PATCH" and "body" in body:
                d = check_comment_body(str(body["body"]))
                if not d.allowed:
                    return d
            return _deny("comment edit/delete denied by default",
                         "GH-COMMENT-03")
        d = check_comment_body(str(body.get("body", "")))
        if not d.allowed:
            return d
        return Decision(allowed=True, level=2,
                        reason="comment allowed with logging (public, attributable)",
                        rule_id="GH-COMMENT-OK")

    # 4. Ref operations (Contents:write, not files-only).
    if _match("/repos/{owner}/{repo}/git/refs/{rest+}", cpath) or (
            method == "POST"
            and _match("/repos/{owner}/{repo}/git/refs", cpath)):
        if method == "DELETE":
            return _deny("branch/tag delete is Contents:write, not admin; "
                         "denied unless template enables + typed confirmation",
                         "GH-REF-01")
        if method == "POST":
            return _approve("branch/tag create needs broker approval",
                            "GH-REF-02")
        if method == "PATCH":
            if body.get("force") is True:
                return _deny("force ref update (force:true) denied unless "
                             "template explicitly allows force-push",
                             "GH-REF-03")
            return _approve("ref update needs broker approval", "GH-REF-04")
    if _match("/repos/{owner}/{repo}/branches/{branch}/rename", cpath):
        return _deny("branch rename denied unless template enables",
                     "GH-REF-05")
    if _match("/repos/{owner}/{repo}/merges", cpath) and method == "POST":
        return Decision(allowed=False, level=MERGE_APPROVAL_LEVEL,
                        reason="branch-to-branch merge requires fresh approval",
                        rule_id="GH-MERGE-01")

    # 5. Releases (+ assets, uploads host).
    if _match("/repos/{owner}/{repo}/releases/{rest+}", cpath) or \
            _match("/repos/{owner}/{repo}/releases", cpath):
        if method in ("POST", "DELETE", "PATCH"):
            return _deny("release create/delete/asset delete denied unless "
                         "template enables + approval", "GH-RELEASE-01")
        return Decision(allowed=True, level=2, reason="release read",
                        rule_id="GH-RELEASE-OK")
    if method == "POST" and cpath == "/releases/assets":
        return _deny("release asset upload denied unless template enables",
                     "GH-RELEASE-02")

    # 6. Dispatches / merge-upstream (Contents:write).
    if cpath.endswith("/dispatches") and method == "POST":
        return _deny("repository dispatch denied unless template enables",
                     "GH-CONTENTS-01")
    if cpath.endswith("/merge-upstream") and method == "POST":
        return _deny("merge-upstream denied unless template enables",
                     "GH-CONTENTS-02")

    # 7. File contents: create/update are write (approval per template
    # is the broker's job — here they are allow-with-log so the broker
    # can apply template path rules); file DELETE is destructive.
    if _match("/repos/{owner}/{repo}/contents/{rest+}", cpath):
        if method == "DELETE":
            return _deny("file delete denied unless template enables + approval",
                         "GH-CONTENTS-03")
        if method in ("PUT", "POST", "PATCH"):
            return Decision(allowed=True, level=2,
                            reason="file create/update (template path rules "
                                   "applied by broker; workflow files need "
                                   "Workflows:write in addition)",
                            rule_id="GH-CONTENTS-OK")
        return Decision(allowed=True, level=1, reason="file read",
                        rule_id="GH-CONTENTS-OK")

    # 8. Secrets: never proxied (all families, all verbs).
    if "/actions/secrets" in cpath or "/dependabot/secrets" in cpath \
            or "/codespaces/secrets" in cpath:
        return _deny("secrets never proxied (all families)", "GH-SECRET-01")

    # 9. Webhooks / deploy keys / collaborators: persistence primitives.
    if "/hooks" in cpath and method in ("POST", "DELETE", "PATCH"):
        return _deny("webhook create/delete denied (persistence primitive; "
                     "see session-end artifact inventory)", "GH-PERSIST-01")
    if "/keys" in cpath and method in ("POST", "DELETE"):
        return _deny("deploy-key create/delete denied in default templates",
                     "GH-PERSIST-02")
    if "/collaborators" in cpath and method in ("PUT", "DELETE"):
        return _deny("collaborator invite/remove denied in default templates",
                     "GH-PERSIST-03")

    # 10. Actions:write members, each separately denied by default.
    if "/actions/runs" in cpath:
        if method == "POST" and cpath.endswith("/approve"):
            return _deny("fork-PR workflow-run approval denied (pwn-request "
                         "vector: hands repo secrets to unreviewed code)",
                         "GH-ACTIONS-01")
        if method == "DELETE":
            return _deny("workflow run/log/artifact delete hard-denied "
                         "(evidence destruction)", "GH-ACTIONS-02")
        if method == "POST" and ("rerun" in cpath or "cancel" in cpath):
            return _approve("workflow rerun/cancel needs broker approval",
                            "GH-ACTIONS-03")
        if method == "POST":
            return _approve("workflow trigger needs broker approval",
                            "GH-ACTIONS-04")
    if "/actions/workflows" in cpath and cpath.endswith("/disable") \
            and method == "PUT":
        return _deny("workflow disable denied (workflow kill)", "GH-ACTIONS-05")

    # 11. PR trust actions (N-J6): approvals, dismissal, resolution.
    if "/reviews" in cpath and method == "POST":
        event = str(body.get("event", "")).upper()
        if event == "APPROVE":
            return Decision(allowed=False, level=MERGE_APPROVAL_LEVEL,
                            reason="PR approval is a trust action (can satisfy "
                                   "required-review gates); same class as merge",
                            rule_id="GH-PR-01")
        if event == "REQUEST_CHANGES" or "dismiss" in cpath:
            return _approve("review action needs broker approval", "GH-PR-02")
        return Decision(allowed=True, level=2, reason="review comment",
                        rule_id="GH-PR-OK")
    if _match("/repos/{owner}/{repo}/pulls/{n}/update-branch", cpath):
        return Decision(allowed=False, level=MERGE_APPROVAL_LEVEL,
                        reason="update-branch merges base into head",
                        rule_id="GH-PR-03")
    if "/transfer" in cpath and method == "POST":
        return _deny("issue transfer denied (cross-repo leak channel; "
                     "target must be allowlisted + approved)", "GH-ISSUE-01")

    # 12. Checks / statuses: fake-green-CI risk (merge-adjacent).
    if ("/check-runs" in cpath or "/statuses" in cpath) and method == "POST":
        return _approve("check/status write is merge-adjacent (can fabricate "
                        "green CI); needs broker approval", "GH-CI-01")

    # 13. Environments / deployments / pages.
    if "/environments" in cpath and method in ("PUT", "POST", "DELETE", "PATCH"):
        return _deny("environment create/delete/protection change denied "
                     "unless template enables + snapshot at session start",
                     "GH-ENV-01")
    if "/deployments" in cpath and method in ("POST", "DELETE"):
        return _deny("deployment create/delete denied unless template enables",
                     "GH-DEPLOY-01")
    if "/pages" in cpath and method in ("POST", "PUT", "DELETE"):
        return _deny("Pages write denied (one-call public disclosure)",
                     "GH-PAGES-01")

    # 14. Administration: bypass actors, visibility, repo transfer.
    if "/rulesets" in cpath and method in ("PUT", "DELETE", "POST"):
        return _deny("ruleset/bypass-actor edit hard-denied (voids all gates)",
                     "GH-ADMIN-01")
    if _match("/repos/{owner}/{repo}/transfer", cpath):
        return _deny("repository transfer hard-denied", "GH-ADMIN-02")
    if method == "PATCH" and _match("/repos/{owner}/{repo}", cpath) \
            and body.get("private") is False:
        return _deny("private->public visibility change hard-denied",
                     "GH-ADMIN-03")

    # 15. Plain reads on modelled repo paths.
    if method == "GET" and _match("/repos/{owner}/{repo}/{rest+}", cpath):
        return Decision(allowed=True, level=1, reason="modelled read",
                        rule_id="GH-READ-OK")
    if method == "GET" and _match("/repos/{owner}/{repo}", cpath):
        return Decision(allowed=True, level=1, reason="modelled read",
                        rule_id="GH-READ-OK")
    if method == "GET" and _match("/user/{rest+}", cpath):
        return Decision(allowed=True, level=1, reason="modelled read",
                        rule_id="GH-READ-OK")

    # 16. Unmodelled endpoint = deny (fail closed).
    return _deny("unmodelled GitHub endpoint", "GH-UNKNOWN-01")


def git_push_policy() -> dict[str, object]:
    """Honest git-protocol statement (N-J4). Returns a dict, not a
    classification, because there is nothing to classify: git traffic
    never reaches this module. Callers must surface ``note`` wherever
    push control is described."""
    return {
        "git_interposition_built": GIT_INTERPOSITION_BUILT,
        "gated": False,
        "logged": False,
        "note": GIT_PUSH_README_NOTE,
    }


# ------------------------------------------------- force-push: delete+recreate

class RefRewriteTracker:
    """Detects delete-then-recreate of the same ref within a session
    (f09 F21): history rewrite with no ``force: true`` flag anywhere.
    The broker feeds it ref DELETEs and POSTs; ``check_create`` denies
    a recreate of a ref deleted earlier in the same session."""

    def __init__(self) -> None:
        self._deleted: dict[str, float] = {}

    def record_delete(self, ref: str) -> None:
        self._deleted[ref] = time.time()

    def check_create(self, ref: str) -> Decision:
        if ref in self._deleted:
            return _deny(
                "delete-then-recreate of the same ref is a force-push "
                "with no force flag; denied", "GH-REF-06")
        return Decision(allowed=True, level=2,
                        reason="ref create (no prior delete in session)",
                        rule_id="GH-REF-OK")


# ------------------------------------------------------- artifact inventory

@dataclass
class Artifact:
    kind: str  # "webhook" | "deploy_key" | "collaborator_invite" | "org_invite"
    identifier: str
    repo: str
    created_at: float = field(default_factory=time.time)


class ArtifactInventory:
    """Session-end artifact inventory (N-J9). The broker records
    every provider-side artifact the session creates; ``list_for_removal``
    is what kill/end must present to the user, because the kill
    switch alone revokes only the credential."""

    KINDS = ("webhook", "deploy_key", "collaborator_invite", "org_invite")

    def __init__(self) -> None:
        self._items: list[Artifact] = []

    def record(self, kind: str, identifier: str, repo: str) -> None:
        if kind not in self.KINDS:
            raise ValueError(f"unknown artifact kind: {kind!r}")
        self._items.append(Artifact(kind=kind, identifier=identifier, repo=repo))

    def list_for_removal(self) -> list[Artifact]:
        return list(self._items)

    def kill_switch_copy(self) -> str:
        return (
            "Kill revokes the session credential; artifacts created "
            "during the session are listed separately and are NOT "
            "removed by the kill alone."
        )


# ------------------------------------------------------- PAT verification

def detect_token_kind(token: str) -> str:
    """Classify a TEST-ONLY token by prefix. Never called with a real
    token in this codebase; prefixes are public format facts."""
    if token.startswith("github_pat_"):
        return "fine-grained"
    if token.startswith("ghp_"):
        return "classic"
    if token.startswith("gho_"):
        return "oauth"
    if token.startswith("ghu_"):
        return "github_app_user"
    if token.startswith("ghs_"):
        return "github_app_installation"
    return "unknown"


def parse_classic_scopes(scopes_header: str | None) -> list[str]:
    """Enumerate actual classic-PAT scopes from X-OAuth-Scopes where
    present (f09 F28). Empty input = no scopes reported, NOT proof of
    anything — callers must distinguish 'header absent' from 'empty'.
    Note: classic ``repo`` excludes workflow updates and repo
    deletion; see CLASSIC_SCOPE_EXCLUSIONS."""
    if not scopes_header:
        return []
    return [s.strip() for s in scopes_header.split(",") if s.strip()]


CLASSIC_SCOPE_EXCLUSIONS: dict[str, tuple[str, ...]] = {
    "repo": ("workflow (workflow-file updates)", "delete_repo (repo deletion)"),
}


def saml_guidance(token_kind: str, status: int,
                  sso_header: str | None = None) -> str:
    """SAML guidance per credential type (N-J8). The 1-hour
    X-GitHub-SSO URL is returned for display only and must never be
    cached or redisplayed after expiry."""
    if token_kind == "fine-grained":
        if status == 404:
            return ("Fine-grained PATs are authorised for SAML SSO "
                    "DURING creation. A 404 here usually means SSO "
                    "authorisation was skipped: re-create the token "
                    "with SSO authorisation during creation.")
        return "Fine-grained PAT SAML: authorised during creation; no post-creation flow."
    if token_kind == "classic":
        if status == 403 and sso_header:
            return ("Classic PAT SAML: follow the X-GitHub-SSO URL to "
                    "authorise (URL expires after 1 hour; do not cache "
                    "or redisplay it).")
        return "Classic PAT SAML: post-creation authorisation via X-GitHub-SSO."
    if token_kind in ("github_app_user", "github_app_installation"):
        return "GitHub App tokens are auto-authorised for SAML SSO; no handling needed."
    return "Unknown token kind: SAML behaviour cannot be determined."


@dataclass
class TokenVerification:
    token_kind: str
    # The 5-field role object, if one was observed. It is a ROLE, not
    # a grant — see module docstring. Never use it to claim a grant.
    role_permissions: dict[str, bool] | None = None
    classic_scopes: list[str] | None = None  # None = header absent
    expiry: str | None = None  # user-attested only, never verified
    pending_org_approval: bool = False
    warnings: list[str] = field(default_factory=list)
    unverified: list[str] = field(default_factory=list)


def verify_token(token_kind: str,
                 role_permissions: dict[str, bool] | None = None,
                 scopes_header: str | None = None,
                 scopes_header_present: bool = False,
                 user_attested_expiry: str | None = None,
                 pending_org_approval: bool = False) -> TokenVerification:
    """Build a verification record with the f09 corrections baked in.

    * ``role_permissions`` is recorded but NEVER interpreted as grants;
      every fine-grained permission not individually probed goes into
      ``unverified`` (fail closed).
    * For fine-grained PATs, ``scopes_header_present`` must be False
      (GitHub returns no X-OAuth-Scopes for them); a True value here
      is itself suspicious and is warned about.
    * ``user_attested_expiry`` is labelled attested, never verified:
      no GitHub endpoint returns a PAT's expiry.
    """
    warnings: list[str] = []
    unverified: list[str] = [
        "every fine-grained permission not individually probed "
        "(role object cannot express them)"]
    if role_permissions is not None:
        warnings.append(
            "permissions object is a repository ROLE (admin/maintain/"
            "push/triage/pull), not a token grant; it cannot confirm "
            "or deny any fine-grained permission.")
    classic_scopes: list[str] | None = None
    if token_kind == "fine-grained":
        if scopes_header_present:
            warnings.append(
                "unexpected X-OAuth-Scopes header on a fine-grained "
                "PAT (GitHub returns none); do not trust it.")
        if user_attested_expiry is None:
            warnings.append(
                "fine-grained PAT expiry is user-attested only; a "
                "no-expiration PAT is flagged like a coarse credential.")
    elif token_kind == "classic":
        classic_scopes = parse_classic_scopes(
            scopes_header if scopes_header_present else None)
        if not scopes_header_present:
            warnings.append("X-OAuth-Scopes header absent for a classic "
                            "token; scopes could not be enumerated.")
        elif "repo" in (classic_scopes or []):
            warnings.append(
                "classic 'repo' does NOT include workflow-file updates "
                "or repo deletion (separate scopes).")
        warnings.append(
            "classic PATs are NOT subject to org fine-grained approval "
            "gates and are valid for every repo the user can access: "
            "a proxy bug exposes everything at once (fail-open).")
    if pending_org_approval:
        warnings.append(
            "pending org approval is indistinguishable from no access "
            "(public reads succeed, private reads 404): check "
            "Settings -> Personal access tokens -> Pending requests.")
    return TokenVerification(
        token_kind=token_kind, role_permissions=role_permissions,
        classic_scopes=classic_scopes, expiry=user_attested_expiry,
        pending_org_approval=pending_org_approval,
        warnings=warnings, unverified=unverified)


def merge_requires_approval() -> bool:
    """True: every merge path (REST merge, merge-async, merge queue)
    requires a fresh broker-owned approval at level 4."""
    return True
