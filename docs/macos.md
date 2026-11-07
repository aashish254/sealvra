# macOS status for Sealvra v0.2 (W17)

Product name: **Sealvra** (owner-decided; the v0.2 Phase 3 pass renamed
the package, CLI and docs from `keyholder` to `sealvra`). Trademark
clearance and registrar execution remain an open owner decision (OD-02)
— the rename is a code-tree fact, not a legal claim.

> Honest headline: **no native macOS behaviour is implemented or proven.**
> The Python suite has now been run on a Mac (v0.2 Phase 1 and Phase 3,
> measured on the maintainer's Mac in this tree — see
> `BUILD-AND-TEST-REPORT.md` §"Mac measurements"), and that run does
> NOT turn any macOS item below into a pass: `tests.test_adversarial.
> TestPlatformNotRun.test_macos_keychain_access_group_isolation`
> deliberately FAILS on darwin because no Keychain access-group
> implementation exists to test. Real Keychain, Touch ID, sandboxed
> approver XPC, DMG install and Gatekeeper remain NOT-RUN until the
> M5 Mac plan in §6 runs with TEST-ONLY keys. A check that was not run
> against the native API is NOT-RUN, never PASSED.

## 1. What was checked here (static script; §1.1 records the Mac suite run)

Run it yourself from the build root:

```sh
python3 scripts/macos_check.py
python3 -m unittest tests.test_w17_macos -v
```

| Check | Result on the checking host |
| --- | --- |
| All Python files compile (`compileall` equivalent, C1) | Checked — see the script output for the file count |
| No Linux-only import outside `sealvra/platform.py` (C2) | Checked — `dbus`, `gi`, `secretstorage`, `keyutils`, `pam`, `systemd`, `selinux`, `polkit` flagged anywhere else |
| No macOS behaviour implemented outside `sealvra/platform.py` (C3) | Checked — mentions of `SecItem`, `LAContext`, `kSecAttrAccessible`, `biometryCurrentSet` outside `platform.py` are reported |
| macOS design interfaces present in `sealvra/platform.py` (C4) | **PRESENT (design only)** — all five v0.1 interfaces are present as design specifications in `platform.py` / `approval.py`; none of them is a native macOS call proven on a Mac (see §2) |
| No fake-"success" stub for a macOS API (C5) | Checked — a macOS-named function that returns a trivial value with no `NOT-IMPLEMENTED-ON-LINUX` marker and no `NotImplementedError` is a hard violation |
| Only `cryptography` + `argon2-cffi` as third-party deps (C6) | Checked — any other third-party import is a violation |
| No compiled macOS binary artifact (C7) | Checked — no `.so`, `.dylib`, `.pyd`, `.dll`, `.o` in the tree |
| macOS readiness per area (C8) | Checked — Keychain, Touch ID two-step, sandboxed approver XPC, DMG/packaging, daemon IPC on macOS are each reported as SPEC-ONLY, PARTIAL, or GAP. SPEC-ONLY means the design markers are present and the native proof is NOT-RUN; it is never a pass |
| `docs/macos.md` honesty (C9) | Checked — the NOT-RUN headline and TEST-ONLY wording must be present, and §6 must state the Touch ID order (gesture first, confirm second) |

## 1.1 The Mac suite run (what changed in v0.2 Phase 1–4)

`scripts/macos_check.py` was run on macOS here and exits 0
(`verdict: NO-CHECKABLE-VIOLATION`), and the full unittest suite ran on
macOS 27.0.1 arm64 with Python 3.12.13: 11,786 discovered, 1 failing,
0 errors, 14 NOT-RUN, 2 expected failures, 164.5 s. The single failure
is the Keychain tripwire named below, which fails on purpose. The W15
real-path E2E class (`tests/test_e2e.py` Layer B, 14 tests) is no longer
class-skipped: all 14 run here and all 14 pass. Per-name results and
the 34-step end-to-end chain proof are in
`BUILD-AND-TEST-REPORT.md` §"Mac measurements".

What that run does and does not establish:

- Established on macOS: the CLI → daemon IPC → proxy → vault chain works
  cross-process on this platform (newline-delimited JSON over
  `control.sock`, peer-UID check via `getpeereid`), the rendezvous
  directory and socket carry the modes §13.1 requires — `stat` on this
  Mac printed `drwx------` for the daemon dir and `srw-------` for
  `control.sock` — PoP verification and
  replay denial behave as specified, audit hash-chain verify passes from
  both the CLI and over IPC, and the supervisor's descendant scan uses
  `ps -A -o pid=,ppid=` because `/proc` does not exist here.
- Not established: anything about the native Security framework.
  `test_macos_keychain_access_group_isolation` FAILS on darwin by
  design — it is a tripwire that fires precisely because no Keychain
  access-group implementation exists. Two sleep-aware clock claims were
  removed rather than implemented: on this platform the label now reads
  `time.monotonic (NOT sleep-aware)` and `mach_continuous_time` is
  recorded as design-only, never called in this tree.
- Still required from the user's Mac, per §6: Keychain one-item-per-key,
  Touch ID two-step approval, sandboxed approver XPC, DMG install and
  Gatekeeper — with TEST-ONLY keys only.

## 2. Current status: designed, not natively implemented

The five v0.1 design interfaces are PRESENT in `platform.py` and
`approval.py` (verified by C4/C8), but every one of them is a design
specification plus in-process logic — not a native macOS call:

1. **Keychain one-item-per-key** (v3 §1D N-D1): one macOS Keychain
   item per key, own wrapping key, own version counter, own backup
   container. No vault-wide KEK item. The deleted v1/v2 passages (the
   `vault-kek-v1` design, the rejection of per-key items) are never
   built. What is NOT here: any `SecItemAdd` / `SecItemCopyMatching`
   call, any access-group entitlement, any Keychain Access proof.
2. **Default `.userPresence` + enrolment-change detection with
   step-up** (v3 §1D N-D2). The enrolment monitor in `approval.py`
   (kill-all + password-only next on a domain-state change) is
   in-process logic driven by a supplied domain state; no Mac has
   supplied a real `evaluatedPolicyDomainState` blob yet.
3. **`.biometryCurrentSet` strict mode, opt-in only**, with a re-wrap
   ceremony on enrolment change — never combined with a device-passcode
   fallback (the AND/OR semantics problem in v3 N-D2: a combined flag
   either kills passcode fallback or kills enrolment-change
   invalidation). The strict flag exists in `macos_keychain_design()`;
   no strict-mode item has ever been created on a Mac.
4. **Sandboxed approver design** (v3 §1E N-E1): the sandboxed,
   unprivileged XPC `sealvra-approver` is the ONLY approval renderer.
   It receives metadata only and returns a signed, single-use decision
   bound to the exact request hash. UI processes never originate
   approvals. What is NOT here: no XPC service bundle, no launchd
   plist, no sandbox profile (`.sb`), no code-signing identity check
   code — the in-process `Approver`/`ApprovalBroker` pair mirrors the
   XPC pairing; it is not the XPC service.
5. **Touch ID as gesture, not authorisation** (v3 §1E N-E2): session
   creation and destructive calls require biometric/OS-auth presence
   PLUS an explicit confirm click, in that order — gesture first,
   confirm second. A gesture alone mints nothing; a confirm before
   the gesture is refused (`approval.py`: card → gesture → confirm →
   decided). Biometric-only is allowed only for identical-scope
   re-approval. **Correction to the v0.1 doc:** the v0.1 §6 step
   listed the order backwards (confirm before Touch ID). The code
   order — gesture first, confirm second — is the correct one, and
   §6 below now states it that way.

Until a Mac run proves otherwise, any macOS-only path in the codebase
must carry an explicit `NOT-IMPLEMENTED-ON-LINUX` marker or raise
`NotImplementedError` — never a stub that returns success. The
checker enforces this (C5).

Tier honesty (CONTRACT §10, v3 §1A/§1N): on macOS, keys are
additionally gated by per-application Keychain ACLs — that is the
one control in this product that survives a Tier B (shell-capable
same-user) agent. On Linux/Windows, keys are readable by any process
running as the user's account; file permissions, control tokens and
pairing tokens provide zero separation from a Tier B agent and are
never cited as isolation evidence. Same-user malware / a compromised
OS account is out of scope by design.

## 3. What was NOT run on a Mac (NOT-RUN, never PASSED)

- Real macOS Keychain store / retrieve / ACL gating (Security
  framework, `SecItemAdd` / `SecItemCopyMatching`).
- Touch ID / `LAContext` biometric prompt, including enrolment-change
  invalidation and the strict-mode re-wrap ceremony.
- The sandboxed approver XPC service, its code-signing identity check,
  and its signed single-use decision.
- DMG install and Gatekeeper behaviour (see §6 group G — conditional
  on a signed DMG ever being supplied by W20; none exists now).
- Daemon Unix-socket IPC in its installed form on macOS (v0.2 §13.1):
  a launchd-managed job, login persistence and restart-after-kill under
  a service manager. The socket itself is no longer a NOT-RUN item —
  see §1.1, which records `sealvra daemon start` running as a real
  subprocess here with a `0700` directory and a `srw-------`
  (`0600`) `control.sock`, measured with `stat` on this Mac.
- Screen-lock suspend + kill after 15 minutes locked, on macOS.
- Keychain ACL Tier B separation: a second same-user process
  attempting a Keychain read and getting a system prompt.
- Any end-to-end run that exercises a native macOS API on Apple
  silicon, and any run on Intel. The pure-Python chain (CLI → daemon
  IPC → proxy → vault → loopback mocks) did run on this Apple-silicon
  Mac in v0.2 Phase 1/3, 34/34 steps — §1.1 — and that run touches no
  native API, so nothing below becomes a pass because of it.
- The `aarch64-apple-darwin` "build": see §5 — there is no Darwin
  build here at all.

## 4. How a Mac user runs v0.2 today

v0.2 is Python, not a compiled app. There is no macOS binary to
download in v0.2, and no DMG is produced by this build. The runnable
shape is the zipapp plus `install.sh` (W20 owns both files):

```sh
python3 --version   # must be 3.12
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt   # cryptography + argon2-cffi only
python3 -m sealvra --help
python3 -m sealvra doctor
```

DMG shape is **spec only** (for W20/packaging, not built here): a
future DMG would bundle the Python zipapp plus a launcher, and would
still need Gatekeeper/notarisation handling that has not been tested.
Do not describe the DMG as existing or tested.

Storage on macOS (v3 §1D N-D3, §1N N-N1): platform-keychain mode is
the recommended default. Password mode is strictly weaker — a stolen
vault password exposes all compartments — and that must be stated
wherever password mode is offered. There is no vault-wide lock state
(v3 N-D4): screen lock suspends sessions and kills them after 15
minutes locked; unlocking never auto-resumes them.

## 5. aarch64-apple-darwin check (honest record)

Python source is architecture-independent, so there is no
architecture-specific macOS build to verify:

- No compiled macOS binary is produced here (checked: C7 finds no
  binary artifacts).
- The aarch64 check is therefore **compile + interface + CI-job
  readiness**, not a Darwin build. The CI macOS job (`.github/
  workflows/ci.yml`, `macos` job on `macos-latest`) runs the unit
  tests, this checker, and a zipapp build — it still does not run
  Keychain, Touch ID, or XPC checks, which stay NOT-RUN until a
  human runs the §6 plan on a real Mac. Note the CI workflow is
  prepared, not run: the public repository
  (`github.com/aashish254/sealvra`) has only `README.md` on its
  pushed branch, so `ci.yml` is not on the remote and `gh run list`
  returns zero runs — no CI run has happened and no passing CI run
  is claimed.
- Never claim a macOS binary, an Apple-silicon build, or a Mac test
  run from this Linux-side work.

## 6. Test plan for the user's M5 Mac

Run only after the code is pushed and pulled onto the Mac. **Fake
TEST-ONLY keys only — never a real GitHub or Gemini key, even on the
Mac.** Use throwaway test values that could never authenticate
anywhere, for example `TEST-ONLY-macos-m5-001` (GitHub) and
`TEST-ONLY-macos-m5-002` (Gemini). Never paste a test value into any
chat, issue, or log; never paste output that contains one anywhere
outside the Mac. Delete both keys and their Keychain items at the
end (group H). Record every step as PASS / FAIL / NOT-RUN in the
table at the end of this section — a step that could not be run is
NOT-RUN, never PASSED.

### Before you start

- 0.1 Confirm the Mac is the M5 machine, macOS version is recorded
  (Apple menu → About This Mac), and Touch ID is already enrolled
  for the user's own finger. **Do not remove or re-enrol the user's
  own fingerprints for this plan.** The enrolment-change step (F3)
  runs only in a separate macOS test user account, or is recorded
  NOT-RUN.
- 0.2 Work in a throwaway directory, not the user's real vault
  location, and set a throwaway vault home for the run (for
  example `SEALVRA_HOME` pointing at a fresh test directory) so
  no real vault is ever touched. Confirm the real vault directory
  is untouched at the end.

### A. Install (zipapp path — the only runnable shape today)

- A1. Clone/pull the repo on the Mac, create the venv, install
  `requirements.txt`, confirm `python3 --version` is 3.12 and
  `python3 -m sealvra --help` prints.
- A2. Run `python3 scripts/macos_check.py` on the Mac and record the
  C8 readiness lines. Expected: all five areas at SPEC-ONLY
  (design present, native proof NOT-RUN). Any C1–C7 violation on
  the Mac is a FAIL, not a Mac quirk.
- A3. Run the W17 tests: `python3 -m unittest tests.test_w17_macos -v`
  and record pass/fail counts.

### B. Doctor and posture

- B1. Run `python3 -m sealvra doctor` and record the posture
  output verbatim, including the storage-tier line (macOS Keychain
  ACL gating, S1) and the Tier A / Tier B wording. FAIL if the
  output claims Tier B separation for anything other than Keychain
  access groups, or if it claims a background daemon exists when
  only a process-local one is running (v0.2 §13.1: the CLI must
  never report a process-local daemon as a background daemon).
- B2. Run `python3 -m sealvra prove-isolation` and record its exact
  result; a FAIL here is exit 3 by contract, never a routine denial.
  Expected on this build: **exit 3, KH-3002** — measured 2026-10-31,
  because the broker interfaces the probe specifies were never
  implemented (`docs/security-model.md` names the two). Record that as
  "separation unproven", not as a separation failure and not as a pass.

### C. Keychain: one item per key (v3 N-D1)

- C1. Add `TEST-ONLY-macos-m5-001` as a GitHub key (label it clearly
  TEST-ONLY). Answer the mandatory "Was this key ever pasted
  anywhere?" prompt honestly for a test key (a test value typed
  only into this run still counts as pasted — record the answer
  given and the NOT YET ROTATED warning that must follow).
- C2. Add `TEST-ONLY-macos-m5-002` as a Gemini key. Then open
  Keychain Access, search for the two labels, and count items:
  expected **two items, one per key**. FAIL if there is one
  combined item, or any item that looks like a vault-wide KEK item
  (a single item holding everything).
- C3. Attribute-only check (do NOT use `security ... -w`, which
  prints the value): in Keychain Access, open each item and confirm
  its access control shows Sealvra as the allowed application and
  that no other application is listed. Record what the Access
  Control tab actually shows.
- C4. Tier B spot-check (same-user separation): from a second
  same-user process (a plain Terminal command or a small script
  that is NOT Sealvra), attempt to read one of the two items.
  Expected: macOS shows a system prompt / denies the read without
  Sealvra's involvement. Record exactly what happened; if the
  read succeeds silently, that is a FAIL of the S1 claim — record
  it, do not explain it away.
- C5. Delete one test key through Sealvra, then confirm in
  Keychain Access that exactly that one item is gone and the other
  remains. Re-add it if later steps need two keys.

### D. Sessions and proxied mock calls

- D1. Create a read-only session for the GitHub TEST-ONLY key.
  Confirm the session token is shown exactly once, is never written
  to any file or log you can find, and the TTL matches the v0.2
  table (read_public default 60 min, cap 120 min; absolute cap 2 h
  for everything).
- D2. Point the proxy at a loopback mock provider (never a real
  provider) and make one allowed read call through it. Confirm the
  key is injected at the last moment and the audit entry is written
  before forwarding (check the audit log line exists before the
  mock sees the call, as far as the run can show it).
- D3. Kill the session; confirm new calls stop within 1 s,
  teardown completes within 5 s, and the kill receipt lists any
  calls completed during the kill. Already-forwarded calls are not
  recalled — record that honestly if one was in flight.
- D4. Daemon IPC (v0.2 §13.1): start the daemon from one CLI
  invocation, then run `daemon status` and `sessions list` from a
  second, separate CLI invocation and confirm they see the same
  daemon (not a fresh process-local one). Then `daemon stop` and
  confirm all sessions are dead and a new daemon starts with zero
  sessions (daemon death = session death, never resurrection).
  Record the socket location and its permissions as observed
  (`ls -l` on the socket path the daemon reports); FAIL if the
  socket is anything other than loopback-local.

### E. Touch ID two-step approval (v3 N-E2) — gesture first, confirm second

- E1. Trigger an approval-gated call (a level-3 call, not a
  destructive one first). Confirm the order, in this exact
  sequence: (1) the broker/approver card is shown, (2) the Touch ID
  gesture prompt appears — gesture first, (3) only after a
  successful gesture, the explicit confirm click is offered —
  confirm second, (4) the call proceeds. FAIL if the confirm click
  comes before the gesture, or if Touch ID alone (no confirm)
  approves anything.
- E2. Single-use: immediately make a second, identical destructive
  call. Confirm it does NOT execute on the first approval — a fresh
  gesture + confirm is required. (Approve-once is a 5-minute
  consumption deadline for one call, not a validity window.)
- E3. Timeout: start an approval, let the 60-second timeout expire
  without touching anything, and confirm the call is denied (a
  timeout always denies; nothing proceeds silently).
- E4. Kill needs no auth: kill a live session from the CLI and
  confirm no Touch ID prompt appears for the kill.
- E5. Broker-window rule: confirm that no broker-window click path
  can approve a destructive call — destructive approval must come
  through the system gesture + confirm ceremony, never through a
  dashboard/GUI button alone.

### F. Approver and enrolment posture (v3 N-E1, N-D2, N-E6)

- F1. Approver origin: confirm the approval card identifies the
  broker-owned approver as the decision origin, and that no CLI or
  dashboard approve action exists or works (there is no `sessions
  approve` command by contract — trying it must fail as unknown
  usage, not approve anything).
- F2. Signed decision: record whether the decision presented to the
  broker is verifiably bound to the exact request (method, path,
  scope summary, session pseudonym, single-use nonce). On this
  Python build the binding is the in-process signer; the XPC
  service's code-signing identity check is NOT present and must be
  recorded NOT-RUN, not assumed from the in-process signature.
- F3. Enrolment change — ONLY in a separate macOS test user account,
  never by touching the user's own fingerprints: in the test
  account, enrol a fingerprint, create a session, then add/remove
  a fingerprint and confirm the posture is kill-all + password-only
  next, with pending HIGH/CRITICAL approvals failing closed. If no
  test account is available, record F3 NOT-RUN with that reason.
- F4. Strict mode (opt-in only): if strict `.biometryCurrentSet`
  mode is offered, confirm it is OFF by default, that turning it on
  requires an explicit opt-in, and that an enrolment change in the
  test account invalidates the item with recovery via backup
  export — never silent survival, never a passcode fallback. If
  strict mode is not offered in this build, record F4 NOT-RUN.

### G. DMG install + Gatekeeper — conditional, NOT-RUN until a signed DMG exists

No DMG exists in this build, so G1–G4 below are a plan for the day
W20 supplies a signed DMG — they are NOT steps to improvise now.
If no DMG is supplied, record the whole group NOT-RUN and install
via the zipapp path (group A) instead. Do not build an unsigned DMG
locally and present it as the Gatekeeper test.

- G1. Verify the DMG before opening it: record its SHA-256, compare
  it against the hash published with the release, and confirm they
  match. A mismatch stops the group.
- G2. Mount/install the DMG, then run Gatekeeper's own verdicts
  before first launch: `spctl -a -vv /path/to/Sealvra.app` and
  `xcrun stapler validate /path/to/Sealvra.app` (notarisation
  staple). Record both outputs verbatim; a staple failure or a
  Gatekeeper rejection is a FAIL, not a "click through it" step.
- G3. First launch: record the exact Gatekeeper dialog shown (or
  its absence), and confirm the app launches from
  `/Applications` — not from the mounted DMG — after install.
- G4. Quarantine check: confirm the installed app carries no
  leftover quarantine surprise on second launch, and that removing
  the DMG after install does not break the installed app.

### H. Audit, uninstall, cleanup

- H1. Run `sealvra audit verify` and record OK / UNANCHORED /
  TAMPERED exactly as reported (UNANCHORED is amber, exit 2;
  TAMPERED is exit 3 — never paraphrase either as "fine").
- H2. Optional screen-lock step (time-boxed): lock the Mac with a
  live session, wait 15 minutes locked, unlock, and confirm the
  session was killed (never auto-resumed). If the wait is not
  feasible, record H2 NOT-RUN rather than shortening the window.
- H3. Uninstall with vault-preservation check: run the uninstall
  script, then confirm: the app is gone, and the vault/Keychain
  items are either preserved (record which) or deleted with a
  receipt that states what backup copies the user must still purge
  (v3 N-D7 — Time Machine or user backups may retain copies; never
  claim whole-vault loss).
- H4. Cleanup: delete both TEST-ONLY keys and their Keychain items,
  confirm deletion in Keychain Access, remove the throwaway vault
  directory, and confirm the user's real vault directory (if any)
  is untouched. Record the whole run back to the build log.

### Result table (copy and fill in on the Mac run)

| Step | Result (PASS / FAIL / NOT-RUN) | Evidence / notes |
| --- | --- | --- |
| A1–A3 install + checker + tests | | |
| B1–B2 doctor + posture | | |
| C1–C5 Keychain one-item-per-key | | |
| D1–D4 sessions, proxy, daemon IPC | | |
| E1–E5 Touch ID two-step | | |
| F1–F4 approver + enrolment | | |
| G1–G4 DMG + Gatekeeper | | |
| H1–H4 audit, uninstall, cleanup | | |

## 8. Known limits and NOT-CLOSED items

- The checker can only verify structure (compiles, imports,
  interface markers, no fake stubs). It cannot verify that a macOS
  implementation is correct — only a real Mac run can.
- `platform.py` is W13's file and `approval.py` is W08/W02's; the
  design markers C4/C8 report are theirs. W17 reports gaps, it does
  not rewrite their files.
- NOT-CLOSED (each needs a Mac, and the last two need other workers
  first):
  1. Real Keychain store/retrieve + ACL gating — needs the §6 C
     group on the M5 Mac.
  2. Touch ID gesture + confirm order on a real prompt — needs §6 E.
  3. Enrolment-change invalidation + strict-mode re-wrap — needs §6
     F3/F4 in a test account.
  4. Sandboxed XPC approver service, sandbox profile, and
     code-signing identity check — no bundle/plist/profile exists
     in this tree (W08/W13/W20 area); §6 F2 stays NOT-RUN until
     they land and a Mac runs them.
  5. Signed DMG + Gatekeeper/notarisation — no DMG exists (W20
     area); §6 G stays NOT-RUN until one is supplied.
  6. Daemon Unix-socket IPC on macOS — `daemon.py` (W01 area) now
     has the darwin peer-UID branch (`getpeereid`) and 0700/0600
     socket permissions, so C8 reports SPEC-ONLY. C8 is a
     design-marker read, not a run statement: §6 D4 was performed on
     this Mac in v0.2 Phase 1/3 — one daemon seen from separate CLI
     invocations over `control.sock`, with the modes observed by
     `stat` — and `tests/test_daemon_ipc.py` is 8/8 ok here (§1.1).
     Still NOT-RUN: the installed shape (launchd job, login
     persistence, restart under a service manager).
  7. Screen-lock kill-after-15-min on macOS — needs §6 H2.
- Gatekeeper, notarisation, sandbox-profile enforcement, and
  enrolment-change behaviour are all NOT-RUN here.


## 7. v0.2 session-list defect (measured on this Mac, 2026-10-31)
--------------------------------------------------------------------

Command: `sealvra sessions list` with no daemon running.  
Result: exit 1, error KH-1006: backend error: module 'sealvra.sessions' has no attribute 'list_sessions'.

**Root cause:** CLI sessions commands route through daemon IPC when a daemon is running; without one they fall back to the process-local sessions module, which lacks `list_sessions()`, `create_session()`, `kill_session()`, and `kill_all()` as module-level names. Those exist only as methods on `SessionStore` (sealvra/sessions.py:640+) and are invoked via IPC `sessions.list` from the daemon.

**Evidence:** reproduced in a sandboxed HOME against both real daemon (exit 0, correct listing) and no-daemon (exit 1, dead). test_w10_cli.py stubs a FakeSessions mock to exercise the fallback-only branch. The joined CLI → daemon → proxy path is proven end-to-end by tests.test_e2e Layer B (14/14 on this Mac, now green per §"Mac measurements").

**Fix priced as needs-owner:** wire `sealvra.sessions` to a SessionStore or provide module-level proxies matching the CLI's call shape; keep IPC-first, fallback-second policy but ensure the fallback actually implements the commands listed in README.md. Record in docs/CLI-SERVICES.md with explicit notes on what runs without a daemon.

The design note in sealvra/cli.py at :718–727 and :1122–1136 documents that IPC is first, local store second — this build measures that claim but exposes the missing implementation gap. This replaces the 2026-10-28 snapshot claim that "CLI sessions are not on daemon IPC and `sessions list` failed KH-1006" — IPC *is* live-proven (a daemon-created session is always found by `sessions list`), but the non-daemon fallback remains unimplemented.

