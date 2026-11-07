# Sealvra v0.2 (draft) — security model

> **v0.2 DRAFT.** Stated from `CONTRACT.md` and plan v3 §1A/§1N,
> amended for the v0.2 slices measured 2026-10-28 on Linux and
> re-measured 2026-10-29 on macOS (daemon IPC, real-approver wiring,
> pack signing, git helper + wrapper).
> The CLI, proxy, and audit modules exist, and the joined
> CLI → daemon → proxy → vault path is now proven end-to-end against
> built code (CLI-created session, PoP-signed proxied calls, kill,
> audit verify — `tests/test_e2e.py` Layer B, 14/14 on macOS with
> TEST-ONLY keys and loopback mocks). It is verified for that path
> only: no real provider was contacted and no native OS approval
> gesture exists, so a production level-3 call still denies
> fail-closed. Tier labels follow v3: a control is only ever claimed
> for the tier it actually holds against. The egress sections below
> ("Egress and privacy") are W17's and are not rewritten here.

## The two agent tiers — stated per control, always

- **Tier A — interface-bound agent.** The agent can only use the
  broker's interfaces. It cannot run arbitrary commands as your user.
- **Tier B — shell-capable same-user agent.** The agent runs
  arbitrary commands as your user id. A coding agent *is* a same-user
  process, so Tier B is in scope — it is not an edge case.

Controls that survive Tier B: macOS keychain access groups (the
operating system, not Sealvra, enforces which application may read
a keychain item), OS-rendered approval prompts, and worker sandbox
profiles. Controls that do **not** survive Tier B and must never be
cited as Tier B evidence: file permissions (0600/0700), file-stored
control tokens, peer-credential checks, and pairing tokens. A
same-user process can read any file your user can read.

**Out of scope by design:** same-user malware and a compromised OS
account. Sealvra defends against a compromised *agent*, not a
compromised machine. Nothing in this doc set claims otherwise.

## Per-control tier table (specified behaviour)

| Control | Holds vs Tier A | Holds vs Tier B | Notes |
|---|---|---|---|
| Session token + per-request proof signature; missing/invalid proof = deny, no bare-token fallback | Yes | Broker-path only | A Tier B agent that bypasses the proxy entirely is outside the broker path; see the probe limit below |
| One session = one key; one worker per session; no key-fetch verb for workers | Yes | Broker-path only | Enforced by broker design, not by the OS, except on macOS keychain |
| macOS keychain access groups (per-key item, per-application ACL) | Yes | Yes (OS-enforced) | The only storage gate that survives Tier B |
| Windows DPAPI / Linux keyring storage | Yes (broker path) | No | Boundary is the user account, not the application; any same-user process can read an unlocked store |
| Per-compartment vault (own wrapping key, version, backup) | Yes | Accounting only on Windows/Linux | On Windows/Linux this is broker-side granularity, not an OS gate |
| File permissions on vault/session files | Yes (other users) | No | Never cite as isolation evidence for Tier B |
| In-memory-only session tokens and proof keys; temp session dir deleted on session end | Yes | Broker-path only | A Tier B agent with memory access to the broker process is outside this control's scope |
| OS-rendered approval prompts (two-step: OS gesture + explicit confirm, bound to exact request hash) | Yes | Yes, for the approval itself | A prompt cannot be forged by the agent; but see X11 below |
| Approval budgets (20/session, rate limits, max 3 pending, serialised prompts) | Yes | Broker-path only | Limits prompt-fatigue attacks through the broker |
| Broker-window clicks | Present/deny only | Present/deny only | A broker-window click may present or deny a destructive call, never approve it, on all platforms |
| X11 destructive sessions | Refused | Refused | Refused outright: keyloggers capture the approval password and injected input forges clicks |
| CONNECT host-only labelling | Yes | Labelling only | In a tunnel, method/path/body policy is unenforceable for any tier |
| Audit-before-forward, hash-chained log, fail-closed on audit failure | Yes | Broker-path only | Calls outside the proxy are not logged by Sealvra at all |
| Kill (deny-list ≤1 s, teardown ≤5 s) | Yes | Broker-path only | Already-forwarded calls run to completion; provider-side artifacts may outlive kill |
| Git-push gating (wrapper-run pushes only) | Yes, wrapper path | Broker-path only | v0.2 helper + wrapper log and gate wrapper-run push/pull/fetch and deny force-push/ref-deletion without approval; direct-client pushes still bypass — see adapters doc (git section, W05) |
| Daemon IPC authentication (v0.2) | Yes (other users excluded) | No | Unix socket 0600 in a 0700 dir, SO_PEERCRED peer-UID (loopback-only on Windows): same-UID only, never cited as Tier B separation; no file-stored control token |
| Provider-pack signature verification (v0.2) | Yes | Yes, for pack trust | Loader verifies content hash AND Ed25519 signature against a trusted, non-revoked key; failing packs refused, never fallen back to unsigned/hash-only; missing trust/revocation files also refuse |
| Real-approver wiring (v0.2) | Yes, proxy path | Broker-path only | Production proxy approve callable is the real broker-owned approver; test approvers refused without the `SEALVRA_TEST_APPROVER` harness marker; joined CLI → daemon → proxy approval proven on macOS with the harness approver (approved level-3 call forwarded, key injected, chain intact) — the production OS gesture still does not exist, so production level-3 denies |
| Adapter hard-deny floor (v0.2) | Yes | Broker-path only | Composition root adds `sealvra/github.py::classify` level-4 refusals over a pack **allow** only (deny-only, never widens); path and method rules, not body-dependent; GitHub only, no Gemini floor (owner decision 2026-10-29: the floor stays in `sealvra/runtime.py` and the packs are not re-signed — `pk-a584d783bdcd5feb` is rotate-only, so re-signing would break the trust root for no gain; layering stated in CONTRACT §6); inside the broker path, so a Tier B agent that never uses the proxy is untouched |

## The honest parity statement (verbatim substance, v3 §1N)

"On macOS, keys are additionally gated by per-application Keychain
ACLs. On Windows/Linux, keys are readable by any process running as
your user. Tiers control what Sealvra itself does, not direct store
reads."

A posture card therefore carries two separate things that must not be
confused: an **approval tier** (what Sealvra's gates do) and a
**storage tier** (S1 per-app ACL / S2 user-scoped / S3
session-scoped-unlocked / S0 password-file). A high approval tier on
a user-scoped store does not make the store application-scoped.

## What the probe can and cannot prove

`sealvra prove-isolation` runs checks through the broker path. A
passing probe shows that broker-path requests are gated as specified.
**On this build a probe cannot pass and no pass has ever been
recorded** (measured 2026-10-31: exit 3, KH-3002 — the interfaces the
command specifies, `sessions.create_ephemeral_session()` and a
module-level broker `validate_token`, do not exist; see the measured
note in `sealvra/cli.py`). The command fails closed, which is the
correct behaviour, but it means session separation is UNPROVEN rather
than verified, and nothing in this document should be read as claiming
otherwise. It does **not** prove that a malicious agent routed all of its
traffic through the broker: an agent that calls a provider directly,
skipping the proxy, generates no broker record at all, and no probe
of the broker path can attest to traffic it never saw. A failed probe
is exit 3 (isolation/proof failure), never a routine policy denial.
Treat a probe result as evidence about the broker, not as a guarantee
about the agent.

## Data theft vs key theft

Sealvra stops *key* theft and bounds data exposure. It does not
stop data exfiltration through an approved scope: an approved read
scope is a data-exfiltration scope, and kill cannot retract prompts
or calls already sent. Additional bounds in v3: per-session read-byte
caps, cross-provider pattern alerts, and a blocking free-tier warning
at Gemini session creation. These bound exposure; they do not prevent
an approved read from being read.

## Residual risks that survive v3 (named, not hidden)

A compromised maintainer account (mitigated, not eliminated, by
hardware second factor, signed tags, and threshold release approval);
a subtle dependency backdoor below the detection threshold (mitigated
by a minimal dependency set — two pinned dependencies — plus
vendoring and egress testing); a compromised toolchain (bounded, not
solved, by pinning and independent rebuilds); a fully compromised
machine or OS account (out of scope by design); data exfiltration
through an approved scope (bounded, not prevented); already-forwarded
calls surviving kill; provider-side artifacts surviving kill unless
inventoried; traffic shape and timing surviving encryption; and
agent-vendor telemetry outside Sealvra's control.

## Egress and privacy (v0.2, W17 — re-audit against f11)

Scoped claim (v3 N-L1, replacing any "nothing leaves the machine"
wording): with all opt-ins off, the only data leaving the machine
is the agent's own approved API request to the provider the user
chose (key in header) plus unavoidable DNS/SNI hostname metadata,
and a denied call leaves nothing at all. That sentence is the whole
claim; it does not cover corporate TLS interception, OS-level
diagnostic sharing, machine backups, or the agent tool's own vendor
telemetry, each of which is a separate channel outside Sealvra's
control and is named below rather than folded into the claim.

### Update-check payload: version + OS + arch and nothing else

Implemented in `sealvra/cli.py` (`build_update_check_payload`,
pure, no network call) and pinned by `tests/test_egress.py`:

- Payload keys are exactly `version`, `os`, `arch`. Forbidden and
  unrepresentable in the builder: user id, device id,
  installation id, any stable hash of an installation id, channel,
  timestamp/day. There is no installation id in v0.2 — nothing
  generates one, and the v1 §18 first-install UUID / server-side
  manifest selection by stable hash (f11 F-C1, v3 N-L3) is deleted,
  not reimplemented.
- Rollout targeting, if ever used, is computed client-side
  (`client_rollout_bucket`): a local value is hashed locally and
  only the resulting bucket number (an int in [0, 100)) may be
  added to the payload — or rollout is time-based, in which case
  no extra field is added at all. A bucket number is shared by
  many installations; a stable hash is a 1:1 identifier and is
  never sent.
- The update download is allowlisted as its own row (f11 F-C2):
  only after the user accepts an update, to the canonical
  artifact host, with no payload beyond the artifact request
  itself. Artifact URLs are generic and identical for all clients
  of a version/arch — no per-client signed URL tokens (f11 F-C4).
  Sigstore/Rekor verification, when the updater slice lands, is
  offline with a bundled trust root; it must not itself phone
  home (f11 F-C8).
- CDN/IP wording is downgraded to its verifiable form (f11 F-C3):
  servers and CDN are *configured* not to retain IP addresses;
  no client test can prove a third-party CDN's configuration, and
  no doc or screen in this tree claims otherwise. The deleted
  sentence "two machines produce indistinguishable requests"
  (f11 F-J4) stays deleted.
- Update-check default — NOT DECIDED (v3 OD-13, f11 F-C6): the
  f16 audit recommends ON with a clear off switch. That
  recommendation is recorded in code as
  `UPDATE_CHECK_RECOMMENDED_DEFAULT = "on"` and labelled as a
  recommendation only; `UPDATE_CHECK_DEFAULT` stays unset
  (None) pending owner confirmation. No code path enables checks
  by default on the strength of the recommendation, and W18 owns
  wiring the eventual decided default into settings. Shipped
  behaviour in v0.2 regardless: no updater ships at all (see
  `docs/supply-chain.md`), so a fresh install sends zero update
  traffic under any reading of the default.

### Egress allowlist (v0.2, complete for the update channel)

| Connection | Trigger | Payload |
|---|---|---|
| Update check | Only when the user opted into automatic checks (default pending OD-13) or runs a manual check | version + OS family + arch only, optionally a client-side bucket number |
| Update download | Only after the user accepts an offered update | None beyond the generic artifact request |
| Pack update | Never separately — see below | None (no request of its own) |

### Provider-pack updates: shipped inside product updates only

Chosen path (f11 F-K1, v3 N-L4 — one of the two permitted shapes,
now decided): provider packs ship inside product updates only.
There is no separate pack fetch, no per-pack identifier in any
request, and no independent pack-update poller, so a pack update
cannot disclose provider inventory ("this machine just updated
the Gemini pack") to the vendor. Pack staleness is computed
locally only (f11 F-K2). A future separate pack fetch — even a
single all-packs bundle — is forbidden until this allowlist is
amended and a test asserting no per-provider selection signal
lands with it. Packs already in `packs/` are hash-verified on
load; a mismatched pack is refused, never loaded.

### Company-edition ledger rows: OUT OF SCOPE in v0.2, never passing

v0.2 is the personal edition only: there is no company edition,
no org relay, and no org-bound metadata flow in the tree. The
v1-plan ledger rows that say denied calls, kills, and expiries
go "Nowhere" / "Nothing" are therefore recorded here as
**OUT OF SCOPE — not verified, not passing** for any company
edition: in a company edition those same events would generate
`provider.call` (deny), `session.killed`, and `session.expired`
events to the org server (f11 F-J1, v3 N-L6), and the solo
wording must never be quoted for that edition. If a company
edition is ever built, every ledger row gains a company-edition
column naming the org recipient explicitly before any row is
marked passing. No test in this tree marks a company row as
passing, and none may be added without that column.

### Crash scrubber: hash-only, key-add-time hashes, fail closed

Rule (f11 F-E1, v3 N-L8): the crash scrubber holds only hashes,
computed at key-add time and stored separately; at crash time it
hashes candidate token-shaped strings from the report and compares
hashes, never decrypting stored keys. If the keychain is locked
at crash time, the scrubber fails closed — the report is not
sent — rather than sending with known-secret matching skipped.
"Send and remember for this crash type" is deleted (f11 F-E2):
it breaks per-report approval. OS crash reporters are a separate
channel outside this rule: macOS/Windows diagnostic sharing, if
the user enabled it, uploads product crash data to Apple/
Microsoft outside Sealvra's scrubber and approval entirely
(f11 F-E3) — users should check those OS settings separately.

Status, honestly split (see `tests/test_egress.py`): the
primitive in `sealvra/audit.py` (`SecretScrubber`) already
satisfies hash-only storage — it stores 9-char window hashes
only, never secret values, and detects raw, hex, base64, and
URL-encoded fragments — and that is proven by test. What is
**NOT CLOSED** in v0.2, because it lives in modules outside
the W17 file area and no crash-report sender ships at all: (a)
no production call site feeds the scrubber at key-add/rotate
time (no `add_secret` caller exists in `sealvra/` today, and
`AuditLog` defaults to no scrubber), and (b) there is no
locked-keychain fail-closed gate on any crash path, because
there is no crash path. The required fix, for the audit/vault
owner, is: wire `add_secret` at key-add and key-rotate time
(and keep retired secrets indexed), add a locked/unavailable
flag on which `assert_clean` raises instead of approving, and
only then add a crash-report sender behind per-report approval.
Until that lands, no doc or screen may claim crash reports are
scrubbed — v0.2 sends no crash reports at all, which is the
only scrubbing claim that currently holds.

### Telemetry wording, and what W17 does not close

No telemetry channel ships in v0.2, and no label in this tree
may call pseudonymous data "anonymous" (f11 F-D1, v3 N-L7):
bucketed reports would be "usage statistics (bucketed, no
identifiers)" with the small-cell residual stated, not
"anonymous". Items from f11 that this task does not close and
that must not be read as closed by this section: corporate TLS
interception detection (F-B5), OCSP/CRL egress (F-B4),
system-proxy/PAC behaviour (F-B6), agent User-Agent forwarding
(F-A2), TLS session resumption for vendor endpoints (F-A4),
and the first-run screen's missing honest limits (F-J3/F-L1 —
copy pass owned by W18/W20, not changed here).

## Password mode, plainly

In password mode a stolen vault password exposes all compartments.
Platform-keychain mode is the recommended default. Whether password
fallback defaults on or off is an open owner decision (OD-12); this
doc set does not decide it. Screen lock suspends sessions and kills
them after 15 minutes locked; unlocking never auto-resumes them.
There is no "unlock the vault" state that re-opens sessions.
