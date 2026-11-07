# Sealvra v0.1 — adapters (GitHub + Gemini, corrected)

> **DRAFT.** These adapter rules are the corrected v3 rules
> (GitHub: v3 §1J; Gemini: v3 §1I, rewritten — do NOT build from the
> older R06 Gemini draft), and they match what `github.py` and
> `gemini.py` actually contain at final check (including the GitHub
> adapter's own `GIT_INTERPOSITION_BUILT = False` flag). No pack JSON
> files exist yet and there is no proxy to enforce these rules, so
> this is module-level agreement, not end-to-end verified behaviour.
> Both adapters are in the v0.1 scope; neither may ship with the old
> classification.

## Common rules (both providers)

- Provider packs live in `packs/` as JSON with a name, version, and
  content hash. Pack loading verifies the hash; a mismatching pack is
  refused, not loaded. Stale packs: refusal for destructive and
  metered sessions (a warning is not enough).
- Unmodelled endpoint = deny. Classification is by capability, not by
  path or method alone; where two rules could apply, the highest
  class wins.
- Paid inference counts as write class, plus spend caps. "Financial"
  is reserved for money movement and billing admin only.
- Read-like POSTs are handled by an explicit exemption list in the
  pack, not by a method rule.
- Credential-creating responses are denied by default in v1. The
  only permitted flow is vault-native interception: the new
  credential goes into the vault, the agent gets a reference, never
  the value.
- Spend limits are "spend alerts (estimated)", never a guaranteed
  cap, with a pause when the cumulative estimate error exceeds 20%.
- Denials to the agent are generic (no rule id, no category).

## GitHub adapter (corrected)

- **Token type:** fine-grained personal access token is primary.
  Fine-grained tokens can have no expiration (the old "max 366 days"
  claim is wrong); classic-token scope rules differ and must not be
  mixed into the fine-grained table.
- **Contents:write is NOT "files only".** It covers branch and tag
  create and delete, ref updates, branch rename, merges, pull-request
  merge, release create and delete plus asset delete, dispatches, and
  merge-upstream. All of these are write/destructive class in the
  pack. A session described as "files and comments only" must not be
  able to merge by any of the three merge paths (REST merge, merge
  queue, merge-async).
- **Deletion matrix:** rebuilt from GitHub's own permissions
  documentation (20 paths). Only repo deletion, GraphQL-only deletes,
  and genuinely admin-family deletes sit outside the contents-write
  correction.
- **Import-time HARD DENIES (refuse the key, do not just warn):**
  account SSH keys write, gists write, secrets write/rotate, and repo
  deletion. The SSH-keys case is critical: adding an attacker SSH key
  gives push access as the user to every repository, bypassing the
  allowlist, the compartment, the proxy, and the kill switch.
  Secrets note, corrected: GitHub's API never returns secret values;
  the real secrets risks are write/rotate (persistence) and
  workflow-pair exfiltration.
- **Comments are a command channel.** Repositories running
  issue-comment-triggered bots obey any write-access commenter —
  which the session identity is, by construction. Comment-command
  patterns (`/deploy`, `/backport`, `/approve`, `@claude merge/lgtm/
  approve`, and similar) are denied. Before any comment template
  ships, it needs a command-pattern deny, a target allowlist binding,
  and a workflow-presence warning.
- **"Comment" permissions hide trust actions.** Pull-request
  approvals (which satisfy required-review gates), review dismissal,
  update-branch, conversation resolution, run/log/artifact deletion
  (evidence destruction), and issue transfer are classified as trust
  actions, not comments. Issue deletion does exist via GraphQL.
- **GraphQL: denied, enumerated.** The deny list includes
  deleteDiscussion, deleteIssue, deleteEnvironment,
  pin/transferIssue, enablePullRequestAutoMerge, enqueuePullRequest,
  dismissPullRequestReview, dismissRepositoryVulnerabilityAlert, and
  the rest of the GraphQL-only destructive list.
- **Merge is gated** (approval level 4 in the pack model).
- **Git-protocol pushes — v0.2 helper+wrapper slice (partial, not
  full interposition).** A `git push --force` or `git push :branch`
  over HTTPS never becomes a REST call the proxy can inspect, so
  v0.2 adds the honest slice in `sealvra/git.py` plus
  `scripts/git-credential-helper`, and NOT a git smart-HTTP proxy:
  the helper speaks git's credential protocol (`get`/`store`/`erase`)
  and on `get` returns a session-scoped credential — username
  `sealvra`, password = the proxy session token bound to one key,
  one repo scope (host + owner/repo), and TTL-capped — never the
  real key; `store`/`erase` are deliberate no-ops so a session
  credential is never persisted into a credential store. The
  wrapper (`GitWrapper`, for push/pull/fetch/clone) checks session
  liveness and class (read sessions cannot push), resolves the
  remote and checks it against the exact repo scope (bare
  push/pull/fetch with no explicit remote is refused), denies
  force-push (`--force`, `-f`, `--force-with-lease`, `+refspec`,
  `--mirror`) and ref deletion (`--delete`, `:ref`, `--mirror`)
  unless a matching live approval exists for that kind and those
  refs, runs git with ONLY this helper (`credential.helper` reset
  first) and `GIT_TERMINAL_PROMPT=0`, and logs a decision entry
  before git runs and an outcome entry after (audit failure on the
  decision write means git is not run). **What still bypasses it,
  stated plainly: a git client run directly with standing
  credentials outside the wrapper/helper is NOT logged and NOT
  gated** — `sealvra doctor` must flag standing git credentials
  (it already inventories `.git-credentials` and
  `.config/gh/hosts.yml`); per-path restriction inside a push is
  not enforceable from refspecs (use API-only sessions for
  path-bound templates); helper `get` calls outside the wrapper
  are scope/expiry-checked but not individually audit-logged; and
  the helper credential authenticates only against a Sealvra git
  proxy (not yet built) or a loopback fake remote that validates
  session tokens — sent directly to github.com it would simply
  fail authentication, which is why the helper refuses any host
  other than the scope host. Do not claim that every push is
  logged: only wrapper-run pushes are. (The REST adapter's own
  `GIT_INTERPOSITION_BUILT` flag in `github.py` is W06's to flip
  on integration; this slice does not rewrite it.)
- **Kill does not kill provider-side artifacts.** Webhooks, deploy
  keys, and collaborator invites created during a session outlive the
  kill switch unless inventoried and revoked. Session end requires an
  artifact inventory.
- **Other classifications:** webhooks, attestations, codespaces,
  security/vulnerability/secret-scanning alerts, variables, merge
  queues, single-file permission, members write, self-hosted runners
  write, org webhooks, team discussions, and token requests are all
  mapped in the pack — none left "unmapped". Environment
  protection-rule removal, fake-green-CI via checks/statuses write,
  workflow-disable kills, and fork-PR workflow-run approval (which
  hands repository secrets to unreviewed code) are classified.

### Where the adapter's hard denials are actually enforced (v0.2, 2026-10-29)

`sealvra/github.py::classify` carries first-party refusals the signed
packs do not model — `GH-SECRET-01` denies the whole secrets family
("secrets never proxied (all families)"). Until v0.2 Phase 4 that module
was advisory in the proxy path: the daemon's composition root asked the
**pack** and nothing else, so a `read`-class session could
`GET /repos/{owner}/{repo}/actions/secrets/{name}` and be allowed,
because the pack models `GET /repos/**` as a level-1 read and has no GET
rule for that family.

The seam is now wired, and it is deliberately narrow. In
`sealvra/runtime.py::_deny_floor`, applied to every decision the pack
returns for a GitHub session:

- The pack stays the policy source (CONTRACT §6 "Policy layering"). The
  floor can only **add** a refusal. A pack `None`, deny, or level ≥ 4 is
  returned untouched; a level-3 decision is left to the approver; only a
  pack-**allowed** call that `classify` puts at level 4 becomes a deny,
  and it carries the adapter's rule id so the audit row names the rule
  that fired. The agent still sees a generic denial.
- Path and method rules are what is enforced here. `classify` also takes
  a parsed body and a repo allowlist; this seam receives raw bytes, so
  body-dependent rules are not reachable from it and the pack remains
  the only source for anything body-shaped.
- It is GitHub-only. There is no equivalent floor for Gemini, so for
  that provider the pack is the whole answer — stated as an asymmetry,
  not a symmetry claimed. The asymmetry is a fact about the adapters,
  not a shortcut: only GitHub has a hard denial the pack fails to model
  (`GH-SECRET-01`). No Gemini floor is to be invented until a Gemini
  adapter hard denial exists to enforce; adding one now would be a
  second policy source with nothing legitimate for it to catch.

Closed by this: `tests/test_e2e.py::RealPathTests::test_07`. Verified
load-bearing by mutation (disable the floor, the test fails with the
mock's 200 — see `BUILD-AND-TEST-REPORT.md` §"Layer B closed — the two
fixes").

**Owner decision (2026-10-29): the floor stays in `sealvra/runtime.py`.**
These rules are NOT moving into a re-signed pack. The pack signing key
`pk-a584d783bdcd5feb` is rotate-only — its private half was destroyed —
so re-signing the GitHub pack would change `content_sha256` and break
the trust root for no security gain. The layering the decision rests on
is written into CONTRACT §6; this page is the adapter-facing view of it.

## Gemini adapter (corrected — rewritten, not copied from R06)

- **Key type, corrected.** Since 28 May 2026, all new AI Studio keys
  are authorisation keys bound to a Google Cloud service account,
  Gemini-only by default, with fast leak enforcement. The older
  standard-key import flow, restriction warning, "key authenticates
  the project" claim, and rotation IAM are written for the retiring
  key type and are deleted. Unrestricted standard keys have been
  rejected since 19 June 2026, so no "unrestricted key, capped
  harder" flow exists. Do not hard-code any key-shape check as a
  gate: authorisation keys do not use the old shape, and any reported
  prefix from third-party sources is unverified.
- **Authentication:** native mode uses the `x-goog-api-key` header
  only and denies all other auth forms. Compat (OpenAI-format) mode
  strips the client's bearer token and injects the real key; a
  real-key-shaped bearer token is always denied. Bearer handling is
  therefore mode-dependent — a blanket "deny all Bearer" rule would
  break compat mode, and a blanket "accept Bearer" rule would leak in
  native mode.
- **Denied outright** (they outlive sessions or create server-side
  state the broker cannot police): the Interactions API as an
  unmodelled surface, batch jobs, the Live API, managed agents,
  remote MCP, and file search stores. `generateContent` is the legacy
  call; the Interactions API is the current recommended surface and
  must be modelled (including its server-side state by default and
  its background mode, which violates the kill promise exactly like
  batch jobs) before the adapter ships that surface.
- **Server-side references:** `cachedContent` and `fileData.fileUri`
  references inside otherwise-allowed calls are denied unless the
  referenced object is in the session's creation ledger. "Own objects
  only" without a ledger is unenforceable (files carry no creator
  identity), so the ledger is built or the claim is dropped.
  `files.list` leaks full project inventory and is classified
  accordingly.
- **Uploads:** upload paths and resumable-upload session URLs
  (capability-bearing URLs) are denied in v0.1 unless modelled in
  the pack.
- **What survives from the older draft (do not rewrite):** header
  auth, pinned host plus the OpenAI-compat base path, core endpoint
  families, the full tier table, the per-10-minute spend limiters
  with their hourly ceiling, the October 2026 price table, per-project
  quotas, free-vs-paid data terms, dormant-key blocking from 7 May
  2026, no in-place regeneration, thinking tokens billed as output,
  and "proxy is the only narrowing layer" (with the authorisation-key
  qualification above). Streaming usage accounting is
  last-chunk-cumulative. "RPM cap below tier" is deleted (no
  per-model RPM is published).
- **Templates re-capped** to the single TTL table (destructive
  10/15 min, write 20/30, read_account 30/60, read_public 60/120, 2-hour
  absolute cap). The old 4-hour figures are deleted.
- **Free-tier warning:** a blocking free-tier warning is shown at
  Gemini session creation (per the kill-shot copy corrections).
