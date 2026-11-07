# Sealvra v0.2 (draft) — personal edition

> **v0.2 DRAFT — NOT release-ready, see "Release readiness (v0.2
> draft)" below and `BUILD-AND-TEST-REPORT.md` §"v0.2 draft".**
> v0.2 slices are landing in this tree concurrently (cross-process
> daemon IPC, real-approver wiring, pack signing, git helper +
> wrapper, test registry, egress sections); the v0.1 text below is
> kept and amended where v0.2 changed it, and every v0.2 claim is
> dated to its measurement. Do not quote this README as a release
> claim until the manager finalises the v0.2 report and the
> release checklist passes.
>
> **Manager-finalised (v0.1).** This README describes the v0.1 design
> specified in `CONTRACT.md` and in plan v3
> (`SEALVRA-PLAN-V3-FINALCHECK.md`, which wins over v1/v2), checked
> against the complete build tree after integration. All 20 modules
> are present, including `sealvra/cli.py`, `sealvra/proxy.py`,
> `sealvra/audit.py`, and `packs/github.json` + `packs/gemini.json`.
> Measured counts are in `BUILD-AND-TEST-REPORT.md`, labelled by the
> machine that produced them: the Linux build VM (v0.1: 577 tests, 0
> failures, 13 skipped; v0.2 final: 11,771 discovered) and this Mac
> (v0.2 Phase 1–4: 11,786 discovered, 1 failing, 0 errors, 14 NOT-RUN).
> No Linux count is presented as a Mac count or the reverse. Claims
> below are marked by what the code shows; anything not run on a
> platform is labelled NOT-RUN, never PASSED. Windows and macOS
> *native* behaviour has still not run anywhere.

## What Sealvra is, in plain language

Sealvra is a small program that runs only on your own computer. You
store a long-lived API key in it once — for GitHub or for Gemini, the
only two providers in v0.1. When an AI coding agent needs to call that
provider, it does **not** get your real key. Instead, Sealvra gives
the agent a short-lived, narrowly scoped session token. The agent sends
its request to Sealvra's local proxy, Sealvra checks the request
against the rules for that session, and only then does it attach your
real key to the request at the last moment and forward it to the
provider. When the session ends, or when you kill it, the token stops
working.

One session holds exactly one key, always. There is no multi-key
session, no "approve all my keys" button, and no way to get the real
key back out of Sealvra: there is no reveal command, no clipboard
handoff of a key, and no command that prints a key or a session token
after it was first shown.

## What Sealvra is not

- **Not a company edition.** v0.1 is the personal edition only: one
  user, one machine. There is no team sharing, no shared-key tier, no
  company gateway, and no server that holds keys.
- **Not a sync product.** It never syncs on its own, ever, and no sync
  feature will be added silently. If you export a backup yourself into
  a cloud folder, that copy leaves by your action, not by sync.
- **Not a cloud service.** Nothing about your keys is sent to us.
  The only data that leaves the machine in normal use is the agent's
  own approved API request to the provider you chose, plus unavoidable
  network metadata (such as the hostname). A denied call leaves
  nothing at all.
- **Not a way to take back data.** See "The honest promise" below.
  Sealvra stops *key* theft; it does not stop *data* theft through
  a scope you approved.
- **Not a GitHub or Gemini product, and not a replacement for
  revoking a key at the provider.** If a key may already be exposed,
  rotate or revoke it at the provider. Sealvra cannot revoke a
  provider key for you; at most it can point you to the provider.
- **Not "Keyseal".** The working title throughout v0.1 is Sealvra.
  A different brand name was only recommended in the plan, never
  confirmed, and no rename is made in v0.1.

## The honest promise (corrected wording — use these words, not the old ones)

These are the v3 corrected wordings. Any other wording found in older
drafts ("keys never leave your machine", "killed" with no qualifier,
"every call is logged" with no qualifier) must not be shipped.

- **Keys and the machine.** "In the personal edition, your long-lived
  keys are stored only on this machine and are never sent to us. An
  agent's approved API call does send the key in that call's header
  to the provider you chose — that is the job you approved."
- **Key theft, not data theft.** The trust screen leads with: Sealvra
  "stops *key* theft, not *data* theft". An approved read scope *is* a
  data-exfiltration scope: if you approve reading a private repository,
  the agent can read that repository. Kill cannot retract prompts or
  calls already sent.
- **The counter.** Wherever a counter appears it says: "Times any key
  has left this machine *since import*: 0 — counting only
  broker-observed departures. Approved calls send the key to the
  provider; undetected leaks would not increment this counter."
  The "*since import*" qualifier is part of the wording itself, not a
  footnote.
- **Kill.** "One click blocks new calls within 1 second and tears the
  session down within 5 seconds. Calls already sent to the provider
  are not recalled and run to completion; they are listed on the kill
  receipt." On the command line, kill is a command, not a click.
- **Spend alerts are estimated.** Spend limits are "spend alerts
  (estimated)", never a guaranteed cap. Provider billing can differ
  from the estimate; set provider-side billing alerts as well.
- **CONNECT is host-only.** A session that opts into CONNECT
  tunnelling is labelled HOST-ONLY POLICY everywhere: only the host
  and a byte budget are policed; method, path, and body rules cannot
  be enforced inside a tunnel. CONNECT is refused by default for every
  session, and is never the default transport.
- **No sync, stated precisely.** "The product never syncs on its own,
  ever, and no sync feature will be added silently. Backups you export
  yourself into a cloud folder leave by your action, not by sync."
- **Timeout means deny.** "Timeout always means deny: the 60-second
  clock (120 seconds with the accessibility opt-in) starts at the
  system prompt. The broker card itself is untimed for reading."

## Quick start (command surface — runnable on Linux, verified)

> v0.1, verified by the manager on the Linux build VM: `python3 -m
> sealvra --help` exits 0 and prints the real command surface,
> `doctor` runs and reports names only, `daemon status`/`daemon
> start` work process-locally, and `keys reveal` / `sessions
> approve` are rejected with KH-2001. The commands below are the
> surface from `CONTRACT.md` §9. The in-process E2E path (broker +
> policy packs + audit + proxy against loopback mocks) is proven by
> `tests/test_integration.py` (8/8 in v0.1; re-verify against the
> v0.2 pack-signing flip — packs are now refused unless signed,
> see below). The same command surface was re-run on macOS in the
> v0.2 Phase 1 proof (see `BUILD-AND-TEST-REPORT.md` §"Mac
> measurements"), against loopback mocks and TEST-ONLY keys only.
>
> v0.2, measured 2026-10-28 on the Linux build VM and re-measured the
> same day on macOS (see `BUILD-AND-TEST-REPORT.md` §"Mac
> measurements"): the daemon is now a
> real cross-process daemon (CONTRACT §13.1) — `daemon start`
> spawns a detached `sealvra.daemon --serve` process, `daemon
> status` in a later CLI invocation reports that same daemon
> (verified live with an isolated `SEALVRA_DAEMON_DIR`), and
> `daemon stop` kills its workers. The rendezvous directory is
> `$SEALVRA_DAEMON_DIR` if set, else `~/.sealvra/daemon`
> (0700 dir, 0600 socket, SO_PEERCRED peer-UID on Unix) — it is
> GLOBAL by default, not per-working-directory, so concurrent runs
> share one daemon unless each sets its own
> `SEALVRA_DAEMON_DIR`. IPC auth is same-UID only: it does NOT
> separate same-user processes (Tier B), stated honestly in
> `docs/security-model.md`, never papered over with a control
> token. **Fixed in the v0.2 Phase 1 pass: `sealvra sessions`
> commands are routed through daemon IPC** whenever a daemon is
> reachable (`sealvra/cli.py:_cmd_sessions` prefers
> `_daemon_sessions_client()` and only falls back to the in-process
> store when no daemon is running), which closes the KH-1006
> `list_sessions` breakage this section previously recorded.
> The W15 real-path E2E tests are no longer class-skipped; all 14 run
> on macOS and all 14 pass. `test_07` (a `read`-class session could
> enumerate GitHub Actions secret names because `GET /repos/**` is a
> pack allow and the packs model no GET on secrets) is closed by wiring
> the first-party refusals into the composition root
> (`sealvra/runtime.py:_deny_floor`), which can only add a denial — no
> pack was edited or re-signed. `test_10` (gzipped key echo) is closed
> by pointing the call at a path the shipped Gemini pack models as a
> read, so the response scanner is actually reached; its assertions are
> unchanged. The mock layer (8 tests) also passes.

Requirements: Python 3.12. Only two external dependencies, pinned in
`requirements.txt`: `cryptography` (AES-256-GCM) and `argon2-cffi`
(Argon2id). Everything else is standard library.

```text
# From the build root, with a virtual environment active:
python3 -m sealvra --help
python3 -m sealvra --version

# Start the local daemon (loopback only; see the security model doc):
sealvra daemon start
sealvra daemon status

# Add a key (you will be asked: "Was this key ever pasted anywhere?"
# Answering "don't know" counts as yes — see "First import" below):
sealvra keys add
sealvra keys list
sealvra keys show <key-id>

# Create a session for exactly one key, use it through the local proxy,
# then kill it:
sealvra sessions create
sealvra sessions list  # requires a running daemon; see the v0.2 note below
sealvra sessions kill <session-id>
sealvra sessions kill-all

> **v0.2 note (measured 2026-10-31 on macOS):** `sessions list` routes
> through the daemon's IPC when a daemon is running. Without a daemon,
> the CLI falls back to the process-local sessions module, which lacks
> `list_sessions()` — that invocation exits 1 with error KH-1006. The
> same backend test harness supplies a fake sessions stub for CLI tests.
> A daemon-created session is always found by `sessions list`; killing a
> live session or calling `kill_all` works over IPC the same way. This
> replaces the 2026-10-28 snapshot claim that `sessions list` was not on
> IPC and failed KH-1006 in this build.

# Check the audit log and the health of the installation:
sealvra audit verify
sealvra audit export
sealvra doctor
sealvra prove-isolation
```

`sealvra prove-isolation` is present and, on this build, always exits 3
with KH-3002: the broker interfaces it specifies were never implemented,
so it fails closed rather than reporting an unprovable pass. No passing
isolation probe has ever been recorded (limitation 5 below names the
measured detail).

A proxied call works like this: the agent sends its request to the
local proxy (default `127.0.0.1:8765`, loopback only, never exposed to
the network) carrying the session token and a per-request proof
signature. Sealvra validates the session, checks the request against
the provider pack, writes the audit decision entry *before*
forwarding, attaches the real key at the last moment, and forwards the
call. GitHub calls use an `Authorization: Bearer` header with the real
key; Gemini calls use the `x-goog-api-key` header only, never a key
in the URL.

There is deliberately **no** `keys reveal`, no flag that prints a
token, no `sessions approve`, and no `sessions extend`. Sessions are
never extended; a new session needs a fresh approval gesture.

### First import — the question you must answer honestly

When you add a key, Sealvra asks: "Was this key ever pasted
anywhere?" If the answer is yes, or "don't know", you must rotate the
key at the provider before the first session, and a permanent
NOT YET ROTATED warning stays on that key until rotation is recorded.
This matters because a key once pasted into an agent chat may already
live in a vendor cloud no local scanner can see. Adding it to
Sealvra does not un-expose it.

### Sessions and time limits

One table only (defaults / caps). Nothing may exceed the 2-hour
absolute hard cap — not a session, a grant, or a template:

| Session class | Default | Cap |
|---|---|---|
| destructive | 10 min | 15 min |
| write (non-destructive, including paid inference) | 20 min | 30 min |
| read_account | 30 min | 60 min |
| read_public | 60 min | 120 min |

Idle timeout is 5 minutes (adjustable 2–15 minutes, cannot be
disabled) and is reset only by a *successful* proxied call — not by a
denied call and not by a status poll. Expiry drain: reads and
idempotent calls get at most 60 seconds to finish; destructive writes
and streams stop at expiry.

## Per-OS status — honest, measured

| Platform | Measured result |
|---|---|
| Linux (build VM), v0.1 final | Measured there: full suite 577 tests, 0 failures, 13 skipped (`.venv` Python 3.12); integration E2E 8/8; `windows_check.py` 14 PASS / 12 NOT-RUN; `macos_check.py` exit 0, all 5 macOS interfaces PRESENT |
| Linux (build VM), v0.2 snapshot 2026-10-28 | Tree in flux while v0.2 workers landed concurrently — those counts are a timestamped Linux snapshot, not a final tally; see `BUILD-AND-TEST-REPORT.md` §"v0.2 draft". Two failures recorded in that snapshot were since closed and are NOT open any more: `test_discovery_equals_registry` (the frozen registry now matches discovery exactly, 11,786) and CLI `sessions list` KH-1006 (CLI sessions now route through daemon IPC). W15 real-path E2E (Layer B) is no longer class-skipped in this tree — the skip was removed and all 14 run and pass on the Mac measurement below. |
| macOS (this machine), v0.2 Phase 1–4, 2026-10-28 | **Mac-measured:** Python 3.12.13 on macOS 27.0.1 arm64, full suite 11,786 discovered, 1 failing, 0 errors, 14 NOT-RUN, 2 expected failures, 164.5 s. The one failure is intentional: `test_macos_keychain_access_group_isolation` fails on darwin on purpose because there is no Keychain implementation to test. The real CLI → daemon IPC → proxy → vault chain passed 34/34 end-to-end steps against loopback mocks with TEST-ONLY keys, including PoP verification, replay denial, fail-closed level-3 denial and an approved level-3 call forwarded with the key injected. `macos_check.py` exits 0. Still NOT run on macOS: Keychain access groups, Touch ID, XPC approver, DMG/Gatekeeper. Full table per test name: `BUILD-AND-TEST-REPORT.md` §"Mac measurements" |
| Windows | Checked on the checking host, NOT run on Windows: `scripts/windows_check.py` passes its gate-logic checks (19 PASS / 16 NOT-RUN on macOS), but DPAPI, Hello, CredUI, verifier helper, installer runs, and the zipapp under Windows Python are all NOT-RUN until a real Windows run |
| Native macOS behaviour | Designed, not implemented: `scripts/macos_check.py` exits 0 with all 5 interfaces PRESENT as design markers only; real Keychain, Touch ID, sandboxed approver XPC, DMG install and Gatekeeper remain NOT-RUN until the M5 Mac plan in `docs/macos.md` §6 runs with TEST-ONLY keys |

No Windows test is claimed anywhere in this document set, and no native
macOS API behaviour (Keychain, Touch ID, XPC, Gatekeeper) is claimed: the
Python suite runs on macOS and reports what that run shows, which does
not include any native-API pass. A test not run on a platform is NOT-RUN,
never PASSED. A snapshot count taken while other workers are landing is
not a release count: the full suite is re-run on a frozen tree before any
release claim.

## Security limitations — read before trusting v0.1

These are limits of the design itself, not bugs to be fixed later in
v0.1. Each is also stated, per control, in `docs/security-model.md`
with its Tier A / Tier B status.

1. **Same-user processes (Tier B) on Windows and Linux.** On macOS,
   keys are additionally gated by per-application keychain access
   groups. On Windows and Linux, keys are readable by any process
   running as your user: Windows DPAPI's boundary is the user account,
   not the application, and on Linux any application running as the
   user can read an unlocked keyring. Tiers describe what Sealvra
   itself does, not direct reads of the store. A malicious same-user
   process (for example a rogue editor extension) bypasses the broker
   entirely: it reads the store, unwraps the vault, and holds every
   real key, with no gesture, tier, TTL, or kill switch consulted.
   On Windows/Linux, per-key compartments are broker-side accounting
   and audit granularity, not OS-enforced gates.
2. **Same-user malware / compromised OS account is out of scope by
   design.** Sealvra defends against a compromised *agent*, not a
   compromised operating system account. Do not read any claim here
   as protection against that case.
3. **CONNECT host-only mode.** In a CONNECT tunnel, method, path, and
   body policy are unenforceable. A "read-only" CONNECT session must
   never be described as unable to write — only the host and byte
   budget are policed, and the session must carry the HOST-ONLY
   POLICY label.
4. **Git-push bypass gap — narrowed in v0.2, NOT closed.**
   A `git push` over HTTPS never becomes a REST call the proxy can
   inspect. v0.2 adds the honest slice in `sealvra/git.py` plus
   `scripts/git-credential-helper` (see `docs/adapters.md`, git
   section — W05 owns that section, this README does not rewrite
   it): the helper returns a session-scoped credential (never the
   real key) and the wrapper logs and gates wrapper-run
   push/pull/fetch, denying force-push and ref deletion without a
   matching approval. What still bypasses it, stated plainly: a
   git client run directly with standing credentials outside the
   wrapper/helper is NOT logged and NOT gated; `doctor` must flag
   standing git credentials; and the helper credential only
   authenticates against a Sealvra git proxy (not yet built) or
   a loopback fake remote — sent directly to github.com it simply
   fails authentication. The REST adapter's own
   `GIT_INTERPOSITION_BUILT` flag in `github.py` is still `False`
   (W06's to flip on integration). Never claim that every push is
   logged: only wrapper-run pushes are.

5. **The probe attests arrival, not routing, for a malicious agent —
   and on this build the probe cannot run at all.**
   The isolation probe can show that a request arrived through the
   broker path; it cannot prove that a malicious agent, which controls
   its own network calls, actually routed all of its traffic through
   the broker. An agent that talks to a provider directly, outside the
   proxy, is outside what the probe can attest. Measured 2026-10-31,
   the weaker fact comes first: `sealvra prove-isolation` (and the same
   command through `dist/sealvra.pyz`) exits 3 with KH-3002 because
   `sealvra.sessions` has no `create_ephemeral_session` and
   `sealvra.broker` has no module-level `validate_token` /
   `prove_isolation` for it to call. That fail-closed branch is
   asserted by `tests/test_w10_cli.py`, so session separation is
   UNPROVEN on this build; wiring a real proof changes what a security
   claim asserts and is an owner decision.
6. **Approved scope is data exposure.** See "The honest promise"
   above. Provider-side artifacts created during a session (webhooks,
   deploy keys, collaborator invites) can outlive the kill switch
   unless they are inventoried and revoked; kill alone does not clean
   them up.
7. **X11 destructive sessions are refused.** On Linux under X11,
   destructive sessions are refused outright (a keylogger can capture
   the approval password, and injected input can forge the click).
   Read-only sessions may stay, with a badge stating the limit.
8. **Password mode is strictly weaker.** In password mode, a stolen
   vault password exposes all compartments. Platform-keychain mode is
   the recommended default. Whether a password fallback is on by
   default is still an open owner decision (see below).
9. **Already-sent calls survive kill; streams and budgets are
   estimates.** Kill stops new calls within 1 second and tears the
   session down within 5 seconds, but calls already forwarded run to
   completion and are listed on the kill receipt. Spend alerts are
   estimated, not exact.
10. **Daemon IPC does not separate same-user processes (v0.2).**
    The cross-process daemon authenticates IPC by peer UID
    (SO_PEERCRED on Unix, loopback-only on Windows) in a 0700
    directory with a 0600 socket. That keeps other users out; it
    does NOT keep another process running as your user out. No
    file-stored control token was added to pretend otherwise.
    On macOS only, keychain access groups add the per-application
    gate; on Windows/Linux the storage tier stays user-scoped
    (see limitation 1).
11. **Provider packs are now refused unless signed (v0.2 flip).**
    `packs/*.json` ship with detached Ed25519 signatures
    (`packs/*.sig`), a trust list (`packs/trusted_keys.json`), and
    a revocation list (`packs/revoked.json`); the loader verifies
    BOTH the content hash AND the signature against a trusted,
    non-revoked key, and refuses a pack failing either — never
    silently falling back to an unsigned or hash-only pack
    (format and ceremony: `packs/SIGNING.md`, signer:
    `scripts/sign_pack.py`). A missing trust or revocation file
    also refuses the load. Test packs use their own test key and
    live under `tests/` fixtures, never in `packs/`.
12. **CLI sessions are the daemon's sessions (v0.2, re-measured
    2026-10-29 on macOS).** `sessions create/list/kill/kill-all`
    route through daemon IPC when a daemon is running and use the
    process-local store only when none is, so a session created via
    the CLI is the daemon's session, and the joined
    CLI → daemon → proxy → vault path is proven end-to-end against
    built code by `tests/test_e2e.py` Layer B (14/14 on this Mac,
    TEST-ONLY keys, loopback mocks). This replaces the 2026-10-28
    snapshot statement that the CLI commands were not on IPC and
    `sessions list` failed KH-1006. What still holds: sessions live
    in daemon memory only — daemon death is session death, and the
    rendezvous dir defaults to `~/.sealvra/daemon` unless
    `SEALVRA_DAEMON_DIR` is set.

## Gate G0 — closed, partially closed, or limitation (from plan v3 §4A)

Marked from the integrated code plus measured runs (see
`BUILD-AND-TEST-REPORT.md`). "Closed in code" means the rule is
implemented and covered by a passing test on the Linux build VM and
re-run on macOS.
"Partially closed" means the module code matches the rule but a
slice is still next-step work (real approver wiring, CLI daemon
persistence, or a real Mac/Windows run). "Limitation" means the item
cannot be verified in code yet. The git-push interposition gap
inside G0-12 stays open by the adapter code's own flag.

| G0 item | Status after integration | Basis |
|---|---|---|
| G0-01 single merged normative document | Partially closed | v3 is the single normative plan; this doc set follows v3 + CONTRACT; integration fixes recorded in the report, not yet in a merged decision log |
| G0-02 threat-model tier rewrite | Partially closed | `platform.py` tier machinery + `gui.py` Tier A/B labelling; Tier B native enforcement still needs real OS runs |
| G0-03 delete CLI/dashboard approve; approver-only | Closed in code | CLI rejects `sessions approve` (KH-2001, verified live); GUI read + kill only; `approval.py` approver signer present |
| G0-04 native-token mode decision | Partially closed | Wrapper states proxy/MCP first with no native-token preference; no native-token path found; labelled-exception overturn still an owner decision (OD-18) |
| G0-05 TTL table applied everywhere | Partially closed | `sessions.py` rejects over-cap; broker clamps over-cap — both never exceed the 2 h cap, but the reject-vs-clamp divergence is recorded as a v0.2 unification item, not silently unified; re-checked 2026-10-28, still divergent (`broker.py` still calls `clamp_ttl`/`clamp_idle`; `sessions.py` still documents rejection) |
| G0-06 reveal/clipboard/extension/opt-out/PoP-off deletions | Closed in code | Tests assert absence from CLI help and dispatch; source grep-clean for the forbidden literals; mechanically enforced in v0.2 by `scripts/grep_gates.py` (see G0-18) |
| G0-07 per-compartment vault + AEAD spec | Partially closed | `vault.py` per-compartment envelopes, own wrapping key/version/backup, atomic writes; 34 vault tests pass; OS keychain enforcement itself is W13 design, NOT-RUN here |
| G0-08 sandboxed approver, two-step, enrolment posture, fingerprint, count-only list | Partially closed | `approval.py` card, signer, fatigue tracker (37 tests pass); the macOS sandboxed XPC approver itself is design-only, NOT-RUN here |
| G0-09 approval cluster rewrite (timeouts, approve-once, budgets) | Partially closed | `approval.py` timeout/approve-once/fatigue machinery tested; v0.2: the proxy's production approve callable is now the real broker-owned approver (CONTRACT §13.2) — a test approver is refused unless the test-harness env marker `SEALVRA_TEST_APPROVER` is set, proved by `tests/test_approver_wiring.py`. Closed on 2026-10-29: the joined CLI → daemon → proxy approval path is proven with the harness approver (an approved level-3 call is forwarded, the key is injected, the audit chain still verifies — `/tmp/kh_e2e_proof_FINAL.txt`, 34/34 steps), and CLI sessions are on daemon IPC (limitation 12). Still open: no real OS approval gesture, so the production approver only denies |
| G0-10 console grants narrowed or deleted | Partially closed | `approval.py` console grant present: never destructive, max 2 h, seat-verified; end-to-end use unverified |
| G0-11 Gemini adapter rewrite | Partially closed | `gemini.py` corrected rules (32 tests pass) and the Gemini pack enforce them through the proxy in the integration test; real Gemini calls never made |
| G0-12 GitHub permission table rebuilt | Partially closed | `github.py` corrected rules (53 tests pass) and the GitHub pack enforce them through the proxy in the integration test; v0.2 git slice: helper + wrapper landed (`sealvra/git.py`, `scripts/git-credential-helper`, `tests/test_git.py` passing alone) and `docs/adapters.md` (git section, W05) records exactly what it covers and what still bypasses it. Full interposition still NOT built: the adapter's `GIT_INTERPOSITION_BUILT` flag is still `False`, direct-client pushes bypass the broker, and no Sealvra git proxy exists yet |
| G0-13 proxy P0 fixes | Closed in code | `proxy.py` present (50 tests pass); manager fixed the level-3 approval reachability bug and the PoP replay bug; integration test proves decision-before-forward, injection, denials, kill, and replay rejection |
| G0-14 audit-log P0 fixes | Closed in code | `audit.py` present (33 tests pass); integration test proves fsynced decision-before-forward and `verify()` OK on a real chain |
| G0-15 vault migration decision + atomic writes + restore-kills-sessions | Partially closed | `vault.py` atomic writes + restore kill-gate tested; migration decision record not in tree |
| G0-16 master test registry + independent reviewer + exception registry | Closed in code (gate machinery; reviewer appointment still OPEN) — but the gate FAILS at the 2026-10-28 snapshot | `tests/test_registry.py` is the frozen master registry (every release-blocking test by stable unittest ID; the release gate asserts discovered == registry and executed == registry count, skipped/muted == 0 unless validly excepted, deletion/unregistered == fail) plus the mechanical exception registry (rejects S1–S4 IDs, expired entries, second renewals, disguised re-registrations, self-approval, missing signature/disclosure) and artifact binding (gate artifacts carry commit + build hash; verification refuses mismatches). Proved by `tests/test_gates.py`. Snapshot failure (not a machinery failure): `test_discovery_equals_registry` fails because discovered tests outnumber the frozen registry (47 additional elements at the snapshot) — other workers' new tests landed without a registry regeneration. Regenerate with `python3 tests/test_registry.py --regenerate` and review the diff; never silently drop a hard test. OPEN, not closed here: (a) the independent reviewer of record is not appointed, so reviewer signatures are presence-checked only and solo-phase gates remain self-attested; (b) CI wiring (`.github/workflows/ci.yml` calling the gate) is not yet landed; (c) commit binding is still UNPROVEN: `.git` exists and `detect_commit()` returns this tree’s local HEAD, but that commit is not on the remote — `origin/main` is the initial commit whose tree is one file (`README.md`) — so a bound artifact would name a commit nobody else can fetch. The gate refuses an unbound release rather than inventing a commit; closing this is the owner’s commit-and-push, then a gate re-run against the pushed commit |
| G0-17 update architecture decision (TUF etc.) | Limitation | No updater in v0.1 (manual re-downloads); TUF-lite design recorded as a requirement on the future updater slice, not implemented |
| G0-18 mechanical consistency re-run (grep gate) | Closed in code | `scripts/grep_gates.py` runs the G0-18 grep mechanically over README, CONTRACT, the report, docs, code, packs, and scripts: every hit for 8h/24h/4h TTL numbers, --show-token/--print-token, Reveal, clipboard, opt-out, PoP-off, vault-kek, learned approvals, TESS, biometryCurrentSet must be the winning rule, explicitly-marked superseded history, a non-TTL context (provider OAuth lifetimes, export cooldown, anomaly window), or gate/scanner catalogue data — any other hit fails the gate (exit 1) with file, line, and reason reported per hit. Passes on the current document set; proved by `tests/test_gates.py` (synthetic losing/winning/superseded cases plus the real-tree run). The CI-workflow call is the same OPEN wiring item as G0-16 |
| G0-19 company-edition structural decisions recorded | Limitation | Company edition is out of v0.1 scope; no decision record in tree |
| G0-20 name-asset reservation before announcement | Limitation | No announcement or name reservation has been made. The repository is public (`github.com/aashish254/sealvra`) but its pushed branch carries only `README.md`, so nothing in this build is published yet and nothing is claimed |
| G0-21 import question + rotation gate | Closed in code | CLI `keys add` always asks "Was this key ever pasted anywhere?" (don't-know = yes) and forces rotation before the first session (W10 tests pass); GUI `NOT YET ROTATED` warning present |
| G0-22 kill-shot copy corrections | Partially closed | Copy corrections applied in this doc set and in `gui.py` labels; CLI surfaces verified for the forbidden commands only |
| G0-23 single normative UX decisions applied | Partially closed | GUI decisions (read + kill only, no per-key tray browsing, HOST-ONLY labels) tested headless; GUI live-daemon wiring is the next slice (window renders its data source, manual Refresh) |
| G0-24 parity decisions applied | Partially closed | `platform.py` X11 refusal, Wayland/XWayland detection, broker-window-injectable warnings; platform checks pass on Linux gates; native runs NOT-RUN |

Items marked **limitation**: G0-17, G0-19, G0-20
(3 items). Closed in code: G0-03, G0-06, G0-13, G0-14, G0-16
(gate machinery; reviewer appointment, CI wiring, and repo commit
binding still OPEN as stated in that row), G0-18, G0-21
(7 items). Partially closed: the other 14 items, including G0-12
whose git-push gap stays open. No item is claimed closed on a Mac
or Windows run that never happened. The v0.2 registry count moves
as other workers land tests: after any test is added, removed, or
renamed, regenerate with `python3 tests/test_registry.py
--regenerate` and review the diff — a regeneration that silently
drops a hard test is the vacuous-suite bypass the registry exists
to prevent.

## Owner decisions (plan v3 §5) — 17 open, OD-01 closed by the owner

None of these is settled by this doc set. An owner decision is closed
only when recorded in the decision log with a date and, where stated,
a mechanical enforcement (test, gate, or check).

1. **OD-01** Name confirmation — **CLOSED by the owner: the product is
   Sealvra.** The owner settled this on 2026-10-28 and directed the
   rename pass; it is recorded here as the owner's decision, not as a
   worker's. The v0.2 Phase 3 pass renamed the package, CLI entry,
   imports, docs, scripts, tests and the zipapp from `keyholder` to
   `sealvra`, deliberately preserving the HKDF info literals
   (`keyholder-v1/*` in `sealvra/crypto.py`) and the signed pack
   contents, whose `content_sha256` covers their own wording. Version
   is unchanged at 0.1.0 — a version bump is a separate owner call.
   What remains of the old item is now OD-02, below.
2. **OD-02** Registrar + trademark execution — domain, proper
   trademark search, org and package reservation. Web searches are
   not trademark clearance. **Still open.**
3. **OD-03** Session-extension dissent — v3 adopts no-renewal; the
   owner may overturn in writing only, which re-opens the TTL table
   and the surfaces that delete extension.
4. **OD-04** Anti-spoofing passphrase mandate vs dissent — v3 adopts
   passphrase + image + receipt, keychain-gated.
5. **OD-05** CLI reveal fallback dissent — v3 deletes reveal
   entirely; overturning is for a later version only, not v1.
6. **OD-06** Approval timeout accessibility value — 120 seconds in
   v3; a different value must be recorded (the old 15–300 second
   range does not return).
7. **OD-07** Dogfood cohort — who dogfoods, for how long, what
   sign-off looks like.
8. **OD-08** External audit firm selection — required before 1.0;
   firm, scope, and timing are the owner's call.
9. **OD-09** Update rollout percentages — one schedule in both
   sections (recommendation: the later section's stages with the
   earlier section's soak times).
10. **OD-10** Audit retention schedule — one schedule, stating both
    log data and case files.
11. **OD-11** Vendor jurisdiction + representatives — relevant to
    company-edition sales, not to personal v0.1.
12. **OD-12** Password-fallback default — ON or OFF (plan audit
    recommends ON).
13. **OD-13** Update-check default — ON or OFF, stated identically
    everywhere, proved by a fresh-install zero-traffic test if OFF.
14. **OD-14** Solo-mode release authorisation — deputy with threshold
    approval, or cooling-off + public pre-announcement; "two-person
    review" is unenforceable for a solo project and is not an
    acceptable answer.
15. **OD-15** Company N-T1 fork — per-session memory-only leases +
    mandatory rotation on departure, or a rescoped promise. Company
    G0 only; shipping neither is forbidden.
16. **OD-16** Degraded-safe mode — grace periods and exact behaviour
    for versions on the revoked list.
17. **OD-17** Stack + packaging decisions — language, GUI framework,
    and HTTP/TLS stack with a CVE-burden analysis (the contract pins
    Python 3.12 for v0.1; the remaining choices still need recording).
18. **OD-18** Native-mode overturn (contingent) — only if the owner
    overturns the deletion: labelled-exception wording, badge,
    provider-verified revocation on kill, and a high-value-key ban
    must all ship together. Partial overturn is not available.

Explicitly **not** open (do not re-open without new evidence): X11
destructive refusal, no-extension default, the 2-hour TTL cap, PoP
mandatory, no reveal, no credential clipboard, per-compartment vault,
sandboxed approver, CONNECT absolute-only default, credential-creating
responses denied in v1.

## Release readiness (v0.2 draft) — verdict: NOT READY for a public release

Draft checklist from measured runs on the Linux build VM
(2026-10-28 snapshot) and re-measured on macOS the same day; the Mac
columns are in `BUILD-AND-TEST-REPORT.md` §"Mac measurements". No
Linux-only pass is relabelled as a Mac pass anywhere in this tree.
No item below may be marked passing on the strength of a worker
claim — only on a run recorded in `BUILD-AND-TEST-REPORT.md`.

| Release gate | v0.2 snapshot verdict | What would close it |
|---|---|---|
| Full suite green on a frozen tree | FAIL — snapshot runs show failures while workers land (registry-gate failure; earlier pack-signing flip transiently broke the integration suite until `.sig` files landed; egress-test failures in the same window) | Freeze the tree, regenerate the registry, re-run `python3 -m unittest discover -s tests` to 0 failures/errors, and record the count |
| W15 real-path E2E (CLI → daemon → proxy → mocks) | RUN on this Mac — 14/14 pass (`tests/test_e2e.py` Layer B, class skip removed); the 8 mock-fidelity tests pass too. Earlier Linux runs had it class-skipped, then 2 red. **Re-checked 2026-10-31: the 14 class-skipped, by the gate doing its job** - a daemon left running by an earlier GUI test reports the real upstreams (`api.github.com`, `generativelanguage.googleapis.com`), so the module refuses to aim proxied calls anywhere; no call was attempted, no provider contacted. Needs a clean-environment re-run with that daemon stopped | Closed on 2026-10-29 by real code, not by loosening the gate. `test_07` needed the first-party refusals wired into the composition root (`sealvra/runtime.py:_deny_floor`, deny-only); `test_10` needed the call aimed at a Gemini path the shipped pack models as a read, so the response scanner is actually reached. No pack edited, no signature touched, no assertion weakened |
| Real Mac run (Keychain, Touch ID, sandboxed approver, DMG, Gatekeeper) | NOT-RUN | `docs/macos.md` §6 on the M5 Mac with TEST-ONLY keys |
| Real Windows run (DPAPI, Hello, CredUI, installers, zipapp) | NOT-RUN | `docs/windows.md` plan on real Windows |
| Pack signing end-to-end | PASS (isolated) — signed packs load, unsigned/refused, revocation beats trust (`tests/test_pack_signing.py`) | Re-verify on the frozen tree; record the signing ceremony's key custody (private key never in the tree) |
| Daemon IPC end-to-end | PASS (isolated) — `tests/test_daemon_ipc.py`; cross-process start/status/stop verified live with an isolated daemon dir | Re-verify on the frozen tree; CLI sessions on IPC (above) |
| Real-approver wiring | PASS (Mac-measured) — production approver is the default and denies level-3 fail-closed; the joined CLI → daemon → proxy approval path was proven with the test-harness approver (approved level-3 call forwarded, key injected, audit chain intact — `BUILD-AND-TEST-REPORT.md` §"Mac measurements", 34/34 steps) | A real OS gesture behind `RealApprover(gesture=…)`; until then the production approver only denies |
| Git boundary honesty | PARTIAL — helper + wrapper pass alone; direct-client bypass and missing git proxy stated in `docs/adapters.md` | Git proxy built, or release notes carry the bypass in plain words and `doctor` flags standing credentials (it already inventories them) |
| G0 gate | PARTIAL — the registry gate is closed (`tests/test_registry.py` matches discovery exactly at 11,788 and `tests.test_registry tests.test_gates` = 43 OK on this Mac; `scripts/grep_gates.py` exits 0); reviewer-of-record still unappointed, CI gate steps are wired but the workflow has never run, and commit binding is still unproven, because the tested commit exists only in this tree — the remote’s pushed branch is the initial commit, one file | Appoint the reviewer, push (on the user's named approval) so `ci.yml` and the tested commit reach the remote, then run CI for the first time against them |
| Owner decisions OD-01–OD-18 | OD-01 CLOSED by the owner (name = Sealvra, rename shipped in v0.2 Phase 3); OD-02–OD-18 STILL OPEN (see below) | Owner records each decision with date + mechanical enforcement; OD-01/OD-02 block any name announcement or reservation |
| No real keys, no push, no announcement | HOLD — nothing of this build is pushed (the public repo’s pushed branch is the initial commit, one file), no name reserved, only TEST-ONLY values and loopback mocks in this tree | Keep holding until the user approves a push by name |

**Verdict: do not publish, tag, or announce v0.2.** The architecture
slices v0.2 promised are landed and, on this Mac, joined: CLI sessions →
daemon → proxy → vault is proven end-to-end (Layer B 14/14, plus a 34-step
chain proof), the registry and grep gates pass, and the full suite runs
here at 11,774 executed tests (the gate’s id list is 11,788) with one intentional failure. Release is still blocked by
what no local run can close: no real OS approval gesture, so production
level-3 calls only deny; no Windows run and no native macOS proof
(Keychain access groups, Touch ID, XPC, DMG/Gatekeeper); CI never run — `ci.yml` is not on the
pushed branch and `gh run list` returns zero runs; and all of owner decisions OD-02–OD-18 still open. Shipping now
would mean shipping a broker whose approval path works in a test harness
but not for a human, on platforms that have never been exercised.

## Exact next step for the push — no push now

**Do not push, create a repo, contact GitHub, or announce a name.**
v0.1 is local build and test only. The push happens only in this
order, and only after the user approves it explicitly:

1. The user connects GitHub himself, in his own browser, under his own
   account (the assistant never logs in, never handles his password
   or second factor, and never receives a token in this chat).
2. The user reviews the finished tree and approves the push step by
   name.
3. Only then is a push made, to the repo the user names, after the
   checkout identity (remote URL and repo name) is verified to match
   that repo.

Until then, nothing leaves this machine except loopback mock traffic.

## Appendix — technical summary

- **Package layout (specified):** `sealvra/` package run as
  `python3 -m sealvra` from the build root; `tests/` runnable with
  plain `python3 -m unittest`; `packs/` provider packs (JSON, signed,
  content-hash verified — a pack whose hash mismatches is refused,
  not loaded); `scripts/`, `docs/`, `.github/workflows/`.
- **Design layout (added by the GUI remake, not by the contract):**
  `design/mockups/` holds the five reference screens and the stylesheet
  `sealvra/gui.py` copies its colours and measurements from;
  `design/qa/` holds the harnesses that measure them (Chromium geometry
  and real-pixel contrast for the mockups, `tkfont.measure` plus
  `tree.xview()` for the live Tk panel). `CONTRIBUTING.md` prints the
  invocations. The layout numbers in `TABLE_SPECS`, `OPT_COLUMN_MAX` and
  `INSPECTOR_MAX` come from those runs, so a layout change is re-measured
  rather than retuned by eye.
- **Vault (specified):** one encrypted compartment per key — own
  wrapping key, own version counter, own backup container, own
  platform keychain item on macOS. No vault-wide master key, no single
  key-encryption key. Header AEAD: key derived from the compartment
  key via HKDF-SHA256 with distinct info strings per use; 96-bit
  random nonce, never reused; body AES-256-GCM. Password mode:
  Argon2id, 64 MiB memory, 3 iterations, parallelism 1.
  Fingerprint shown only in the owning key's detail pane: first 12
  hex characters of SHA-256 of the secret. Audit entries use
  pseudonyms (HMAC-SHA256 of an audit secret over the key id,
  truncated to 16 hex), never labels, never key fragments.
- **Sessions and tokens (specified):** session token format is a
  fixed prefix plus a random URL-safe string; the broker stores only
  its SHA-256 hash, compared in constant time. The token is returned
  exactly once at creation, never logged, never written to disk.
  Every proxied request carries the token, a proof signature
  (HMAC-SHA256 over method, host, canonical path, body hash, and
  timestamp), and a timestamp (max skew 300 seconds). Missing or
  invalid proof means deny, with no fallback to a bare token.
  Temporary session files, if unavoidable, live in a fresh temporary
  directory that is deleted on session end — never a fixed home
  directory path.
- **Proxy and policy (specified):** loopback proxy, default
  `127.0.0.1:8765`. Requests are canonicalised (split first, then
  decode each segment; decode-then-split is forbidden), classified by
  capability (highest class wins; paid inference counts as write),
  decided against a signed, version-pinned provider pack (unmodelled
  endpoint = deny), approved through the broker-owned approver where
  gated, audit-logged with fsync *before* forwarding, and only then
  forwarded with the real key injected. Denials to the agent are
  generic (no rule id, no category); rule ids and categories go to
  the audit log only. Response bodies are scanned for credential
  echoes (including encoded and compressed forms) before relay; a
  response that would mint a new credential is denied by default.
- **Approval (specified):** decisions come only from the
  broker-owned approver. No CLI approve command, no dashboard approve
  button; dashboard and CLI are read + kill only, and kill needs no
  auth. Session creation and destructive calls need two steps in
  order: an OS gesture (Touch ID / Hello / polkit / system password
  UI) plus an explicit confirm, bound to the exact request hash with
  a single-use nonce. Approve-once means a 5-minute *consumption
  deadline* for one use, not a 5-minute window for repeat calls.
  Destructive calls always need a fresh per-call approval.
  Broker-window clicks may present or deny a destructive call, never
  approve it. X11 destructive sessions are refused.
- **Audit (specified):** JSON lines, canonical JSON with sorted keys,
  hash-chained (each entry's hash covers the canonical entry without
  its own hash; each entry links to the previous entry's hash;
  genesis links to all zeros). `verify` reports OK, UNANCHORED
  (amber, exit 2), TAMPERED (exit 3), or MISSING-DIRECTORY (exit 3 —
  a silently reborn log is a failure, not a fresh start). Retention:
  live 90 days, archive 1 year, summaries only after expiry, never
  key material. Disk-full means refuse new calls (fail closed), never
  "continue with a warning".
- **Error catalogue (specified, one table, all surfaces):** KH-1001
  vault locked (exit 1); KH-1002 session not found / expired / killed
  (exit 2); KH-1003 policy denied (exit 2); KH-1004 approval denied
  or timeout (exit 2); KH-1005 audit unavailable (exit 3); KH-1006
  provider/upstream error (exit 1); KH-2001 invalid input/usage
  (exit 1); KH-3001 platform unsupported for this action (exit 1);
  KH-3002 isolation/proof failure (exit 3); KH-3003 secret detected
  in log (exit 3). Same event = same code on every surface.
- **Docs in this set:** `docs/user-guide.md` (how to use it),
  `docs/security-model.md` (Tier A/B per control),
  `docs/adapters.md` (GitHub + Gemini, corrected),
  `docs/troubleshooting.md` (common failures and what they mean).
  Windows and macOS platform docs are owned separately
  (`docs/windows.md`, `docs/macos.md`). `BUILD-AND-TEST-REPORT.md`
  is the manager-finalised report with measured counts.
