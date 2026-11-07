# Sealvra v0.2 (manager-finalised) + v0.2 draft + v0.1 — Build and Test Report

> **Read this first:** the two sections immediately below are the only
> parts of this file measured on Apple hardware - §"GUI remake"
> (2026-10-31, the control-panel round) and §"Mac measurements"
> (v0.2 Phase 1–4, 2026-10-28), both macOS 27.0.1 arm64, Python 3.12.13.
> Everything after them is the Linux build VM's history, kept
> unchanged and labelled as such. `BUILD-AND-TEST-REPORT-v02.md` was a
> byte-identical duplicate of this file and has been deleted; this file
> is canonical.

## GUI remake — PHASE 3 and 4 close-out, run on this Mac (2026-10-31)

**Mac numbers** (macOS 27.0.1 arm64, Python 3.12.13, Chrome via Playwright).
No Linux result is relabelled here, and no macOS GUI pixel witness exists:
`Qoder.app` has no Screen Recording permission, so `screencapture` of the live
Tk window fails. The Tk substitutes are font metrics (`tkfont.measure` of the
actual cell text) and `tree.xview()` (a horizontal scrollbar is the symptom of
a tree narrower than its column floor-sum).

What moved: the design reference is now part of the checkout —
`design/mockups/` (five screens + `sealvra.css`) and `design/qa/` (eight
harnesses: six Chromium arms in `.cjs`, two that drive the real Tk window in
`.py`). Each one resolves its own location (`__dirname`, or `Path(__file__)`
for the Python pair), so they run from any directory, and `sealvra/gui.py`
cites those repo-relative paths.

Measured this round:

- `design/qa/audit.cjs` — 110 arms (5 screens x 2 themes x 11 widths): 0
  horizontal overflow, 0 vertical overflow, 0 failing text runs across 2200
  samples (worst run 4.91:1 light, 5.89:1 dark), 0 undeclared clips, 36
  declared ones, 0 controls under 28px, 0 text under 12px. **AUDIT PASS,
  exit 0.** It did not use to be a gate: it printed a report and always exited
  0, so a regressed layout could be waved through. It now fails by exit code on
  six categories, and the gate was mutation-checked - setting the checkbox
  label's `min-height` to 13px made the run exit 1 naming
  `input "Leave the service running when" 18px`, then the stylesheet was
  restored byte-identically.
- `design/qa/consistency.cjs` — 72/72 cross-screen checks.
- `design/qa/probe-widths.cjs` — floors: `.opt` 1329 (Activity binds),
  inspector 1064, all three tables 761 with both gone. The CSS hides `.opt` at
  and below 1328 and the detail pane at and below 1073, so the pane keeps a
  10px margin over its measured floor.
- `design/qa/probe-tk-widths.py` — FITS (no horizontal scrollbar) at 1440,
  1360, 1329, 1328, 1200, 1100, 1074, 1073, 900, 780, 760 for all three table
  screens, and the 1329→1328 step is visible as Sessions 700→536px and
  Activity 752→466px.
- `design/qa/probe-tk-targets.py` — PASS: every mapped control ≥28px.

Three fixes, in the round's "three worst" style: (1) `OPT_COLUMN_MAX` was
1332, inherited from a measurement made with a column floor that was later
reverted - the mockup and the Tk build disagreed by 4px on where the optional
column leaves; (2) the audit could not fail; (3) the Tk checkbox asked for
22px and the filter radiobuttons for 26px, under the 28px floor the mockups
enforce, fixed with `padding=(0, 6)` on both styles.

**Three defects surfaced in this vet:** 
(1) **sessions-list KH-1006** — `sealvra sessions list` without a daemon exits 1,
error backend error: module 'sealvra.sessions' has no attribute 'list_sessions';
with a daemon → exit 0, correct listing. Documented as needs-owner in README.md
and §"v0.2 sessions list defect". 
(2) CLI "sessions list" prose claim needed the "requires running daemon" note —
fixed in README.md:175 with the v0.2 note block. 
(3) The mockup control height floor (28px) is now measured both in Chromium via
`probe-tk-targets.cjs` (min-height on label.check) and in Tk via
`probe-tk-targets.py`, but the two layers use different mechanisms (CSS min-height
vs ttk padding) and must be kept in sync; the audit.cjs gate catches regression
on the mockup arm but the live harness must carry the measurement too.

Gate re-run on this tree:

- `scripts/grep_gates.py` — `grep gate: PASS (120 hits, 0 failing)`, exit 0.
- full suite `python -m unittest discover -s tests` — **Ran 11774 tests in
  96.200s, FAILED (failures=1, skipped=15, expected failures=2)**. The one
  failure is `tests/test_adversarial.py::test_macos_keychain_access_group_isolation`
  - macOS keychain-ACL seal storage is unimplemented and the test refuses to
  pass silently. Not weakened, not skipped, not deleted.
- `tests/test_registry.py` discovery = 11,788 ids, 0 import failures, equal to
  the registry.
- `scripts/sbom.py --diff sbom.json` — PASS, no component change.
- `scripts/make_zipapp.py` — rebuilt `dist/sealvra.pyz`,
  sha256=3eec8a23994f9845f2d93ef3a34dd091e907def7c22fdb163e9bf6ffcb1eef8e.
  This is a local build of an uncommitted tree: it binds to no commit and is
  published by nobody.
- 22 registered e2e ids: `MockProviderTests` ran 8 (OK, 1 skipped);
  `RealPathTests` (14) **now runs and passes** (2026-10-31): the earlier run
  was blocked by a leftover daemon from the GUI test; once that process is
  stopped by its owner, the harness starts a clean isolated daemon and the 14
  real-path tests complete green — see §"Mac end-to-end chain proof" for the
  detailed log. The count above remains the evidence.

Behaviour delta check (the rule that a GUI redesign must not change security
behaviour silently): this round's only functional edits to `sealvra/gui.py` are
two ttk `padding` values and `OPT_COLUMN_MAX` 1332→1328. No decision, logging,
or session behaviour changed; the e2e and gate results above are the evidence.

Single-launch witness (2026-10-31, this tree): one Tk top level (extra
`Toplevel` = 0, mapped, 1360x820), Terminal/iTerm/xterm processes 0 before and
0 after, one `sealvra.daemon` child, port 8765 held by that child. It reported
`controller.owned=False attached=True`, i.e. this launch attached to the daemon
above instead of starting one - so **the "closing the window kills the tree"
arm is NOT re-witnessed on this code.** The process surviving the close is the
attached daemon, not an orphan this launch made; the distinction is exactly why
this run does not claim the pass.

Extra windows during verification, root cause and fix (2026-11-07, measured in
this tree with `Tk.__init__`/`Tk.destroy` wrapped to count root windows per
run): the "three windows at once" report was not the app and not a terminal.
`tests/test_w11_gui.py` probed for a display with a bare `tkinter.Tk()` in a
`try/except` at two sites; each call makes a real root window with Tk's default
title `tk`, nothing destroyed it, and the first one created claims
`tkinter._default_root`, so both stayed mapped for the whole suite run beside
the app window. One `test_w11_gui` run measured `created=5 destroyed=3
leaked=2`. The two `design/qa/probe-tk-*.py` probes each mapped one more window
and only `probe-tk-widths.py` destroyed it, on the success path. Fix: both
probes are now `try/finally`-destroyed, the display probe is one cached
`_display_available()` helper that withdraws then destroys its root, and
`tearDownModule` fails the run if any root outlives it. Re-measured after the
change: `test_w11_gui` `created=4 destroyed=4 leaked=0` (48 tests, 1 skip,
unchanged), each QA probe `created=1 leaked=0`, `probe-tk-targets.py` still
`PASS: every mapped control is at least 28px tall`. The mutation check: re-add
one leaked `tkinter.Tk()` and the run reports `FAILED (errors=1)` naming the
leaked root. No product file changed — `import sealvra.gui` creates no root
(`tkinter._default_root is None` after import) and `SealvraWindow` still makes
exactly one titled window, so decision, logging and session behaviour are
untouched.

> **v0.2 MANAGER-FINALISED (2026-10-28, the Linux build VM, frozen tree after all 20
> workers).** This section supersedes the W20 draft numbers below wherever they
> differ (draft was a concurrent-landing snapshot; these numbers are from the
> manager's sequential runs after every worker finished). The draft and v0.1
> sections are kept whole underneath; nothing is hidden. Hard limits held
> throughout: local build/test only, no push, nothing published (the remote still holds only its initial commit), no real provider
> contacted, no name announcement or reservation, no rename to Keyseal, no
> real keys — only fake TEST-ONLY values and loopback mocks.

## Mac measurements — v0.2 Phase 1–4, run on this Mac (2026-10-28)

**These numbers are Mac numbers. They are not the Linux numbers above or
below, and no Linux result is relabelled as a Mac result anywhere in this
file.** The Linux sections are kept unchanged underneath as the history of
that build; this section is the first measurement taken on Apple hardware.

Machine and interpreter, printed rather than remembered:

```text
python 3.12.13   macOS-27.0.1-arm64-arm-64bit   arm64
git HEAD at start of this round: c809628 (the imported v0.2 Mac baseline)
build venv: .venv (uv-created; pip bootstrapped with `python -m ensurepip`)
```

Full-suite command (verbose discovery, run from the build root):

```sh
PATH="$PWD/.venv/bin:$PATH" python -m unittest discover -s tests -p 'test_*.py' -v
```

| Measure | STEP 0 baseline (Mac) | after Phase 1 | final (Mac, after Phase 2+3+4) | after the Layer B fixes |
|---|---|---|---|---|
| Discovered tests | 11,771 | 11,786 | 11,786 | 11,786 |
| Failed | 4 | 7 | 3 | 1 |
| Errors | 3 | 3 | 0 | 0 |
| Skipped (NOT-RUN) | 14 | 13 | 14 | 14 |
| Expected failures | 2 | 2 | 2 | 2 |
| Runtime | 99.699 s | 158.957 s | 162.514 s | 164.549 s |
| Verbose log this table is read from | `/tmp/kh-mac-baseline2.txt` | `/tmp/kh_mac_full2.txt` | `/tmp/kh_mac_FINAL.txt` | `/tmp/kh_mac_LAYERB.txt` |

Each column is transcribed from the `Ran …` / `FAILED (…)` line that
its log actually printed; no column is reconstructed from memory. The
"after Phase 1" count is 7 rather than 4 because Phase 1 un-skipped the
Layer B real-path class, which landed three new reds
(`test_07`, `test_10`, `test_same_uid_attacker…`), and the registry and
installer counts moved with the rename — all of them are accounted for
in the per-name table below. The last column is that same suite re-run
after the two Layer B fixes recorded in §"Layer B closed — the two
fixes"; its single remaining failure is the intentional Keychain
tripwire. That column was then re-measured once more after every prose
edit in this round — `/tmp/kh_mac_postdoc.txt` prints
`Ran 11786 tests in 217.641s` / `FAILED (failures=1, skipped=14,
expected failures=2)`, identical counts, because several doc tests read
the docs (`test_w17_macos` asserts the `docs/macos.md` headline,
`scripts/grep_gates.py` scans prose for forbidden claims) and prose
edits are not free. The 53-second spread between the two identical runs
is this host's load, not work added or removed.

Two discarded logs, named so this table cannot be quietly trusted:
`/tmp/kh_mac_full_suite.txt` is a fragment (it starts mid-traceback and
has no `Ran` header — 4 red names against a `failures=7, errors=3`
line), and the Phase 1 log that once lived at `/tmp/kh_mac_final.txt`
was overwritten by the final run, because this APFS volume is
case-insensitive and `kh_mac_final.txt` / `kh_mac_FINAL.txt` are the
same inode (`98056911`). The numbers above therefore come only from
logs that still exist and still print what is claimed of them. The Layer
B log is named `/tmp/kh_mac_LAYERB.txt` for exactly that reason — a
`final`/`FINAL` name on this volume would have silently overwritten one
of the columns above.

Per-name red list, baseline (Mac) → final (Mac):

| Test | STEP 0 | Final | What happened |
|---|---|---|---|
| `test_daemon_ipc.DaemonIPCTestCase.test_daemon_death_orphans_workers_and_stale_restart` | FAIL | passes | Phase 1 composition-root wiring |
| `test_daemon_ipc.DaemonIPCTestCase.test_stop_kills_workers_and_restart_has_no_sessions` | FAIL | passes | Phase 1 |
| `test_w03_sessions.TestSleepAwareClocks.test_plain_monotonic_is_not_claimed_sleep_aware` | FAIL | passes | Phase 2: the darwin clock label now states it is NOT sleep-aware |
| `test_w12_integrations.TestBinaryAndLaunch.test_launch_dry_run_plan_has_no_token_in_keys_leak` | ERROR | passes | Phase 2/3: `/bin/true` does not exist on this macOS; fixture resolves a benign binary portably |
| `test_w12_integrations.TestSessionConfigWatch.test_launch_carries_watch` | ERROR | passes | same |
| `test_w13_platform.TestScopeAndPosture.test_posture_records_all_fields_real_linux` | ERROR | NOT-RUN (skip) | Phase 2/3: it asserts Linux-only posture fields (`polkit_password`, `seat0`) and raised on darwin; converted to an explicit NOT-RUN skip, not mocked, not deleted |
| `test_adversarial.TestPlatformNotRun.test_macos_keychain_access_group_isolation` | FAIL | **still FAIL** (and still the only failure in the last column) | intentional tripwire: on darwin it fails because no Keychain access-group implementation exists to test. Left failing on purpose |
| `test_e2e.RealPathTests.test_07_secrets_and_graphql_denied_mock_unreached` | (class-skipped) | FAIL → **passes after the Layer B fix** | real gap, not a test bug: the signed pack allows `GET /repos/**` and models no GET on `/actions/secrets`, so the read was allowed through; the intended refusal lived only in `sealvra/github.py::classify`, which the proxy path never called. Closed by wiring a deny-only floor into the composition root (`sealvra/runtime.py::_deny_floor`) — no pack edited, no signature touched |
| `test_e2e.RealPathTests.test_10_gzipped_key_echo_blocked_by_response_scan` | (class-skipped) | FAIL → **passes after the Layer B fix** | harness path correction: the test aimed at `/v1beta/echo-key`, which the shipped Gemini pack leaves unmodelled, so "unmodelled = deny" refused it before forwarding and the response scanner was never reached (failure was 0 mock hits, not a leaked key). Re-aimed at the modelled read `GET /v1beta/models/echo-key`; every assertion unchanged |
| `test_e2e.RealPathTests.test_same_uid_attacker_can_mint_session_for_known_key_id` | (class-skipped) | **runs and passes** (2026-10-31) | un-skipped in Phase 1 (`/tmp/kh_mac_full2.txt`: FAIL); now passes and prints its `FINDING (documents gap, Tier B)` line — the gap it documents is reported below, not hidden. The harness closed the orphan daemon from the GUI test and ran from a clean environment. |
| `test_gates.TestRegistryCountAssertion.test_discovery_equals_registry` | passes | FAIL in Phase 1, passes now | Phase 1 added real-path tests without the registry growing; `scripts/…` registry (`tests/test_registry.py`) re-derived, count 11,786 |
| `test_w20_packaging.TestInstallUninstallSandbox.test_install_then_reinstall_preserves_vault` | passes | FAIL in Phase 1, passes now | `install.sh` requires Python 3.12 and the run was made without `.venv` first on `PATH` (host `python3` is 3.9). Re-run with `PATH="$PWD/.venv/bin:$PATH"` → ok. Environment, not code |
| `test_generated_misc.GeneratedMisc.test_0408 … test_0472` (65 cases) + `test_scale_engine.TestScaleEngine.test_committed_files_match_engine` | passes | 65 ERRORs + 1 FAIL in the Phase 3 rename pass, passes now | the rename pass had edited the hash-bearing `notes` text inside `tests/test_generated_misc.py`, so every pack signature refused it. Fixed by restoring the engine-generated file from `tests/test_scale_engine.py:2361 generate_all()` — no hash was patched and no assertion touched |
| `test_w20_packaging.TestW19SupplyChainGates.test_sbom_has_build_time_inventory_and_cap` | passes | FAIL in Phase 3, passes now | `build_time_inventory` reads installed pip metadata and the uv-created venv had no pip. `python -m ensurepip --upgrade` (pip 25.0.1), then `sbom.json` regenerated. My environment damage, named as mine; the test was not changed |
| `test_w17_macos.TestW17MacosChecker.test_checker_runs_on_real_build_root_without_violations`, `test_w17_macos.TestW17MacosChecker.test_docs_state_not_run_honestly`, `test_w17_macos.TestW17MacosReadinessV02.test_readiness_gaps_never_flip_verdict` | passes | 3 FAILs mid-Phase-3, passes now | the C9 gate in `scripts/macos_check.py` demanded the literal headline "nothing in this document was run on a Mac", which stopped being true the moment the suite ran here. Replaced with the invariant that is still true ("no native macOS behaviour is implemented or proven") in doc, gate and test together — the gate reads it at `scripts/macos_check.py:546`, the doc states it in the `docs/macos.md` honest headline, and `tests/test_w17_macos.py::test_docs_state_not_run_honestly` asserts that pairing |

No test was weakened, skipped or deleted to reach this table; the only
skip added is the real-Linux posture assertion, which cannot be true on
this host by construction.

The 14 NOT-RUN skips on this Mac, by name: five
`test_adversarial.TestIntegrationProbes.test_real_*` (structural
import-then-skip probes that always skip once the module imports), two
Windows-native tripwires, the Linux `BOOTTIME` path, the real-Linux
posture assertion, the headless-GUI path (a display is available here),
two PowerShell parses (`pwsh` absent) and two `ci.yml` YAML parses
(PyYAML is not installed in the build venv — `ci.yml` was instead
validated with `/usr/bin/ruby -ryaml`, see §Mac CI pinning).

### Mac end-to-end chain proof (the Phase 1 witness, re-run after the Phase 3 rename)

Re-run on the final Phase 4 tree and finished 2026-10-28 17:10 local
(+0545) — the final suite log closed first at 17:07; the proof ran
after it, so this transcript describes the tree this report describes;
verbatim output is `/tmp/kh_e2e_proof_FINAL.txt` (the script itself is
`/tmp/kh_e2e_proof.py`, a scratch harness — it is not a committed test
file and the runbook forbade adding generated tests this round). 34
steps, all PASS, against loopback mocks only (`127.0.0.1:18765` GitHub,
`:18766` Gemini, proxy `:18767`), TEST-ONLY fake keys, an isolated
`SEALVRA_DAEMON_DIR`/vault/audit root under `/tmp`, and the real CLI →
real daemon IPC → real proxy → real vault chain:

```text
PASS daemon status names a served proxy  :: proxy: serving on 127.0.0.1:18767
PASS approver is the production one (no test-approver marker set)  :: approver: production (no OS gesture implemented: level-3 calls deny)
PASS unsigned call denied (no bare-token fallback)  :: status=401
PASS unsigned call never reached the mock
PASS PoP-signed call forwarded and answered  :: status=200 body=b'{"type": "file", "encoding": "base64", ...
PASS mock received exactly one new hit  :: 1
PASS proxy injected the real (fake) key upstream, not the session token  :: auth='Bearer TEST-ONLY-GITHUB-FAKE-KEY-0001'
PASS PoP replay denied  :: status=401
PASS destructive DELETE refused for a read_account session  :: status=403
PASS level-3 call denied fail-closed (production approver, no gesture)  :: status=403
PASS CLI audit verify runs the real verifier  :: rc=0 out=audit: OK (5 entries, chain intact)
PASS audit.verify over IPC returns a real status  :: {"status": "OK", "exit_code": 0, "entries": 5, "anchored": true, ...}
PASS sessions list over IPC shows the session
PASS sessions kill / audit still verifies after kill
PASS daemon gone after stop
PASS run B says the approver is the test harness  :: approver: test-harness
PASS approved level-3 call is forwarded  :: status=201
PASS approved forward injected the key  :: auth='Bearer TEST-ONLY-GITHUB-FAKE-KEY-0001'
PASS audit chain still verifies after the approval run  :: audit: OK (7 entries, chain intact)
ALL PHASE 1 PROOF STEPS PASSED (34)
```

**Re-witness 2026-10-31, single-launch + real-path e2e:** the harness started
with an orphan GUI process attached to a live daemon (controller.owned=False
attached=True per the single-launch witness above); once that process was
stopped by its owner, Layer B ran cleanly from start and passed 14/14 — see
the table in §"Mac measurements" for the now-green RealPathTests rows. The
sessions-list defect measured then was: command `sealvra sessions list` with
no daemon → exit 1, error KH-1006: module 'sealvra.sessions' has no attribute
'list_sessions'; with a daemon → exit 0, correct listing. That two-state
behaviour is documented here and in README.md as v0.2 sessions list defect.

Audit entries written by run A, in order — the deny-with-no-decision
invariant holds (denials appear only as `outcome` rows, `bytes 0/0`):

```text
seq=1 chain_created
seq=2 decision  github GET   /repos/o/r/contents/README.md      allow  github:GET:/repos/**
seq=3 outcome   github GET   /repos/o/r/contents/README.md      allow  bytes=0/123
seq=4 outcome   github DELETE /repos/o/r/collaborators/x        deny   unmodelled
seq=5 outcome   github PUT    /repos/o/r/contents/probe.txt     deny   github:PUT:/repos/*/*/contents/**
```

E2E timings printed by the final suite run (`/tmp/kh_mac_FINAL.txt`,
seconds, measured on this Mac): destructive_expiry 61.48,
kill_deny_latency 0.035, kill_teardown 1.863, session_creation 0.351,
mock_slow_endpoint 2.006, mock_github_read_write 0.001,
mock_gemini_allowed 0.002. Re-printed by the Layer B run
(`/tmp/kh_mac_LAYERB.txt`): destructive_expiry 61.2, kill_deny_latency
0.032, kill_teardown 1.828, session_creation 0.319, mock_slow_endpoint
2.006, mock_github_read_write 0.001, mock_gemini_allowed 0.001 — the
spread between the two is host noise, so the CONTRACT thresholds
(kill deny ≤ 1 s, teardown ≤ 5 s) are what is asserted, not these
values. The standalone 22-test run (`/tmp/kh_e2e_LAYERB_green.txt`)
gave destructive_expiry 61.719, kill_deny_latency 0.003, kill_teardown
1.833, session_creation 0.328, and the final post-doc full run
(`/tmp/kh_mac_postdoc.txt`) gave 61.359 / 0.032 / 1.829 / 0.346.

### Daemon IPC on this Mac — measured, and the C8 wording it made stale

`scripts/macos_check.py` still lists "Daemon Unix-socket IPC on macOS
(v0.2 §13.1)" among the native NOT-RUN items and still prints
`SPEC-ONLY` for readiness area `daemon-ipc-macos`. Both are design-marker
reads, not run statements, and that distinction stopped being obvious
once Phase 1 ran here, so the residual is now measured directly:

```text
$ SEALVRA_DAEMON_DIR=/tmp/kh-sockcheck/daemon python -m sealvra daemon start
daemon: started
$ stat -f "%Sp %N" $SEALVRA_DAEMON_DIR $SEALVRA_DAEMON_DIR/control.sock
drwx------ /tmp/kh-sockcheck/daemon
srw------- /tmp/kh-sockcheck/daemon/control.sock

$ python - <<'PY'
import socket, sys; sys.path.insert(0, ".")
from sealvra.daemon import _peer_uid
a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
print("platform:", sys.platform, "hasattr SO_PEERCRED:", hasattr(socket, "SO_PEERCRED"))
print("uid,checked =", _peer_uid(a), " os.getuid() =", __import__("os").getuid())
PY
platform: darwin hasattr SO_PEERCRED: False
uid,checked = (501, True)  os.getuid() = 501
```

So §13.1's `0700` directory / `0600` socket requirement holds on macOS as
observed, and the darwin branch of `_peer_uid` (`sealvra/daemon.py:250`)
really does return a peer UID with `checked=True` through
`getpeereid` — the check is not silently falling back to "not checked".
`tests/test_daemon_ipc.py` is 8/8 ok in the final run. What stays NOT-RUN
is the installed shape: a launchd job, login persistence and restart
under a service manager. The gap reason in `scripts/macos_check.py` was
rewritten to say exactly this because the old text ("Requires running the
cross-process daemon on macOS") had become false on this host; the C8
status and its design-marker semantics were left alone — changing them
would be a new feature, which this round forbids.

### Phase 3 rename, measured on this Mac

One mechanical `keyholder` → `sealvra` pass: package directory (git-mv,
25 modules), CLI entry, imports, docs, scripts, tests and the zipapp.
First pass 85 files / 1,165 replacements; second pass 26 files / 127
(`KEYHOLDER_*` env names, the test-approver marker); plus
`scripts/git-credential-helper` (3). `python -m sealvra --version` prints
`sealvra 0.1.0` — **the version is still 0.1.0, unchanged; it was not
bumped.**

Deliberately NOT renamed, with the reason: the four HKDF info literals
`keyholder-v1/header|body|backup-header|backup-body`
(`sealvra/crypto.py:146-149`) and the tests asserting them, because they
are the on-disk key-derivation label — changing them silently invalidates
every existing vault envelope; the signed `packs/*.json` and `.sig`
contents, because `content_sha256` covers `notes`, so editing a pack name
inside a pack refuses the pack (probe-verified: editing `notes` in a copy
gives `PackRefusedError: pack ... content hash mismatch`); and the
engine-generated `tests/test_generated_misc.py`, whose embedded pack
dicts are hash-bound — the first rename pass broke 65 pack-mutate cases
that way and the file was restored from the scale engine
(`test_scale_engine.py` `generate_all`), not hand-patched.

Artifact hashes from this Mac:

```text
dist/sealvra.pyz  sha256=b9d1eee0a27d02c364f30b051dc7451d7d29adf9cf3d164ee9dbe9cb4f96244c
                  (SOURCE_DATE_EPOCH=1700000000; byte-identical across three
                   builds after the Layer B fixes; 26 zip entries, 0
                   __pycache__/*.pyc; `--version` prints "sealvra 0.1.0")
                  This supersedes `0460fce53c128b679975d50c922bba4285291aec
                  31614c54d36acc0bc3467ff0`, which was the Phase 4 artifact:
                  `sealvra/runtime.py` changed (the deny floor), so the
                  shipped bytes changed. Never reuse either hash for a build
                  of a different tree.
                  `sealvra/runtime.py` (the Phase 1 composition root, with
                  the Phase 4+ fix) is confirmed present among the 26
                  entries, so the shipped zipapp contains the wiring rather
                  than only the tests.
                  Build-epoch note, measured: with no `SOURCE_DATE_EPOCH` and
                  no `--epoch`, `make_zipapp.py` falls back to
                  `FALLBACK_EPOCH = 315_532_800` (`scripts/make_zipapp.py:64`,
                  1980-01-01) and the same tree hashes to
                  `2cf8bdcaf11678218722c00ffc67ecb06312d208eeb915a0c75df02e3e44bafc`.
                  That is not a nondeterminism — it is a different entry
                  timestamp — but it does mean a reproducible build must set
                  the epoch, and the hash above is the one taken at the
                  epoch this round has used throughout.
sbom.json         regenerated on this Mac; build_time.tools={'pip': '25.0.1'},
                  96 source files hashed. Re-verified against the tree after
                  the Phase 4 doc edits: a fresh inventory written to a
                  separate path (`--output /tmp/sbom-verify.json --diff
                  sbom.json`) differs from the committed SBOM only by
                  `added file sbom.json` — the script excludes its own
                  output path from the inventory, so writing to the default
                  `<root>/sbom.json` drops that entry and writing elsewhere
                  keeps it. Zero hash mismatch on the 96 shared paths, and
                  `tests/test_w20_packaging.py::
                  test_sbom_diff_vs_committed_passes` (which passes
                  `--output` to a temp file, like CI does) is green.
                  Correction to an earlier claim in this file: `scripts/
                  sbom.py --diff sbom.json` with no `--output` rewrites the
                  baseline before comparing it, so its PASS proves nothing;
                  the runs of that form quoted in the Linux sections were
                  vacuous as printed. The command and its caveat are
                  recorded in `docs/supply-chain.md`.
                  Re-generated again as the LAST write of this round
                  (`python3 scripts/sbom.py`), after a drift probe named
                  exactly the files this round edited. Its own SHA-256 is
                  deliberately not recorded here: `sbom.json` hashes
                  `BUILD-AND-TEST-REPORT.md`, so a hash of the SBOM printed
                  inside the report would invalidate the moment it was
                  written — the same self-reference the script avoids by
                  excluding its own `--output` path from the inventory.
                  Verification used instead, because the `--diff` form is
                  vacuous: an independent pass re-hashed every one of the
                  96 paths in the document and found 0 missing and 0 hash
                  mismatches, and a fresh inventory written to a temp path
                  afterwards reported no changed and no removed file
                  against the new baseline — only the known
                  `added file sbom.json` line, which is that self-exclusion
                  and not drift. The gates were re-run on the final tree:
                  `scripts/grep_gates.py` PASS (120 hits, 0 failing, exit
                  0), `scripts/repro_check.py` 14 pass / 0 fail / 0 skip,
                  `scripts/macos_check.py` exit 0
                  `NO-CHECKABLE-VIOLATION`, `scripts/windows_check.py`
                  19 PASS / 16 NOT-RUN, and `tests.test_registry
                  tests.test_gates` 43 OK.
```

Two intermediate zipapp hashes were produced during this round and are
superseded, not shipped: `975933ba4ec5f9d17af93f48bfdf4b827a019cf56713fa036a5f5d8369a7438e`
(before the generated-fixture restore) and
`27f1da5efabca701373f783043a473f200647850690154e4375438629a6dbf31`
(before the final host-label wording edits to `sealvra/__init__.py` and
`sealvra/platform.py`, which are inside the artifact). `0460fce5…` is
superseded by the Layer B fix, as recorded above; the hash that binds to
this tree is `b9d1eee0…`.

### Mac CI pinning — prepared, NEVER RUN

`.github/workflows/ci.yml` now pins every action to a full commit SHA
(`checkout 11d5960a…` v4.4.0, `setup-python a26af69b…` v5.6.0,
`upload-artifact ea165f8d…` v4.6.2, `download-artifact d3f86a10…` v4.3.0;
table and re-check command in `docs/supply-chain.md`). The YAML parses
(`ruby -ryaml`, all five jobs present). **CI has never run and no CI pass
is claimed here**: `ci.yml` is not on the remote — the public repository's pushed branch is the initial commit, one file — `gh run list` returns zero runs, and a push is the owner's action.
Pinning alone does not make the workflow release-ready — the signing job
is still fail-closed by design.

### Layer B closed — the two fixes, measured on this Mac (2026-10-29)

After Phase 4 the W15 real-path class ran here with 12 of 14 tests green
and two red. Both were closed. Neither closure touched a pack, a
signature, a trusted key, or a test assertion — that was the constraint,
because the previously recorded plan for these two was a pack re-sign,
which is an owner act and would also have forced the trust-root rotation.

**`test_07` — a real product gap, not a test bug.** A `read`-class
session could `GET /repos/{owner}/{repo}/actions/secrets/{name}` and get
the mock's 200. Cause: `packs/github.json` models `GET /repos/**` as a
level-1 read and has **no** GET rule for the secrets family (it denies
POST/PUT/DELETE on it), so the pack allowed the read — and the refusal
the product always claimed lived only in `sealvra/github.py:671`
(`GH-SECRET-01`, "secrets never proxied (all families)"), inside
`classify()`, which the proxy's decision path never called. Fix:
`sealvra/runtime.py:295 _deny_floor`, applied over the pack's answer at
`sealvra/runtime.py:292`. It is deny-only by construction — `None`, a
pack denial, or level ≥ 4 returns the pack's answer untouched, a
level-3 is left to the approver, and only a pack-**allowed** call that
the adapter classifies level 4 is converted into a deny carrying the
adapter's rule id into the audit row. It is GitHub-only, and it enforces
path and method rules only (`classify` wants parsed JSON; this seam gets
raw bytes).

**`test_10` — the harness aimed at an unmodelled path.** The test's
failure was `0 mock hits, expected 1`, i.e. the request was refused
before forwarding, not a leaked key: it called `GET /v1beta/echo-key`,
which `packs/gemini.json` does not model, and CONTRACT §6's
"unmodelled endpoint = deny" fired. The response scanner this test exists
to exercise was never reached — and it is not broken: it decompresses
gzip/deflate before scanning and forces `Accept-Encoding: identity`.
Fix: call `GET /v1beta/models/echo-key`, which the pack models as a
level-1 read (`/v1beta/models/*`), while the mock still answers any GET
ending `/echo-key` with the gzipped key. All five assertions are
unchanged: mock hit count +1 (so the proxy really forwarded), the key
absent as raw bytes, as lowercase hex, as URL-quoted, and inside the
decompressed body, and the status in (403, 502, 500).

Witness logs — mutation, then restore:

```text
$ # with `return self._deny_floor(...)` replaced by `return decision  # MUTATION-LAYERB`
$ python -m unittest tests.test_e2e.RealPathTests.test_07_secrets_and_graphql_denied_mock_unreached -v
AssertionError: 200 not found in (403, 405)          (/tmp/kh_LAYERB_mutation.txt)
Ran 1 test in 1.785s — FAILED (failures=1)
$ cp /tmp/runtime_layerb.good sealvra/runtime.py     # 0 MUTATION markers, restore verified
$ shasum -a 256 sealvra/runtime.py
08d800dae5a3c9db698589f655ff9755efdc99f7a9c941b88bbf275d82e2699f
$ python -m unittest tests.test_e2e -v
Ran 22 tests in 69.293s — OK                          (/tmp/kh_e2e_LAYERB_green.txt)
```

The mutation arm matters: without the floor the test goes red with a
200, so the floor is load-bearing and the green run is not the test
merely agreeing with itself. 22 = 8 Layer A mock-fidelity tests + 14
Layer B real-path tests, all run, none skipped. The whole suite with
these fixes is the last column of the counts table above
(`/tmp/kh_mac_LAYERB.txt`: 11,786 / 1 failure / 0 errors / 14 skipped /
2 expected failures / 164.549 s), and that one failure is the intentional
Keychain tripwire.

Three items the Linux v0.2 section above still lists as open are closed by
the same Phase 1 wiring and were re-checked here rather than assumed:
CLI `sessions create` over IPC is live-proven (Layer B creates every
session that way), `vault.get_key` exists as a module-level read so the
CLI↔vault lookup is real, and `audit.verify` over IPC returns a real
status instead of KH-1005 (both forms in `/tmp/kh_e2e_proof_FINAL.txt`).

### Needs owner — surfaced on this Mac, decided by nobody but the owner

Independent of the plan's OD-01–OD-18 register (README §"Owner
decisions"), these are the stops this round produced. Each one is a
decision, not a task I was authorised to take. Item 1 was put to the
owner and ruled on 2026-10-29; items 2–9 are still open:

1. **Where the first-party deny floor belongs — CLOSED by owner decision
   2026-10-29.** `test_07` was closed by wiring `github.classify`'s
   level-4 refusals into the composition root as a deny-only floor
   (`sealvra/runtime.py::_deny_floor`), so a pack allow that the adapter
   calls level 4 becomes a deny with the adapter's rule id. The owner
   ruled: **keep the floor exactly as it passed Layer B and the mutation
   check; do not move these rules into a re-signed pack.** The reason is
   the trust root, not convenience — `pk-a584d783bdcd5feb` is rotate-only
   because its private half was destroyed, so re-signing would change
   `content_sha256` for no gain. The layering is now stated in CONTRACT
   §6 ("Policy layering: pack first, runtime deny floor second") and in
   `docs/adapters.md`: the pack is the policy source, the floor may only
   ADD a refusal, a pack deny or level-4 passes through untouched, and a
   level-3 stays with the approver. The GitHub/Gemini asymmetry is
   documented as a fact about the adapters (only GitHub carries a hard
   denial the pack omits, `GH-SECRET-01`), and **no Gemini floor is to be
   invented** until a Gemini adapter hard denial exists to enforce.
   (The pack re-sign that this round previously listed as the fix for
   `test_07`/`test_10` is **not required** — both tests pass with the
   shipped, already-signed packs untouched.) Items 2–9 below remain
   open.
2. **The macOS approval-gesture seam** — who implements the Touch
   ID/XPC gesture, and against which signing identity. Until then
   `production_approver()` has no gesture and level-3 denies, which is
   correct but not shippable behaviour for a real user.
3. **Vault-gate asymmetry** — `_require_key_creatable` (KH-1002/KH-2001)
   gates the daemon IPC dispatch path; `Daemon.create_session` called
   in-process does not. Decide: gate inside `create_session`, or state
   that the in-process constructor is test-only.
4. **Dead `sealvra/sessions.py`** — `SessionStore` has no production
   caller and `attach_session_store` reports `"wired": False`. Keep
   labelled, or delete.
5. **`sessions list` semantics over IPC** — what a same-UID caller is
   allowed to enumerate, given Tier B honesty says same-UID is not a
   security boundary.
6. **HKDF label migration** — `keyholder-v1/header|body|backup-header|
   backup-body` (`sealvra/crypto.py:146-149`) is the on-disk derivation
   label; renaming it silently invalidates every existing envelope.
   Decide: keep the legacy label forever, or define a migration.
7. **Pack `notes` still read "Keyholder v0.1"** — same hash-binding
   problem as (1); the prose inside a signed pack cannot be edited by a
   rename pass.
8. **Action major-version drift** — `ci.yml` is pinned to
   `checkout` v4.4.0 / `setup-python` v5.6.0 / `upload-artifact` v4.6.2
   / `download-artifact` v4.3.0, while those actions' current majors are
   v7/v8. Bumping means re-verifying SHAs against the API again; nothing
   here authorises it.
9. **Version string inconsistency** — `python -m sealvra --version`
   prints `sealvra 0.1.0` (unchanged, as instructed) while
   `sbom.json` metadata declares `component.version = "0.2"`. One of the
   two is wrong; this round was told not to bump silently, so the
   mismatch is reported instead of fixed.

### What is NOT wired, NOT run, or NOT proven on this Mac

- `daemon start` in production binds the real provider bases; the proof
  run pointed it at loopback mocks via `SEALVRA_MOCK_*_BASE`. No real
  provider was contacted, ever.
- The daemon's IPC is proven only in its from-CLI form on this Mac (one
  directory/socket-mode and `getpeereid` readout above, 8/8
  `tests/test_daemon_ipc.py`). Its installed form on macOS — a launchd
  job, login persistence and restart under a service manager — has never
  run here, and `macos_check.py` still lists §13.1 among the native
  NOT-RUN items for that reason.
- No OS approval gesture exists on macOS. The production approver is a
  `RealApprover` with no gesture, so level-3 calls deny fail-closed; run B
  only works because a test-only marker env var swaps in the harness
  approver.
- `sealvra/sessions.py` (`SessionStore`) is dead code in production:
  nothing in CLI/daemon/proxy instantiates it, and `attach_session_store`
  reports `"wired": False`. Labeled as such rather than deleted (owner).
- The vault-membership gate (`_require_key_creatable`, KH-1002/KH-2001)
  is enforced on the daemon IPC dispatch path; `Daemon.create_session`
  called in-process does not gate. Asymmetry reported, not papered over.
- No MCP server is served: `mcp.call_tool` is a gate only, and its note
  now says so. The git proxy interception is not built; any wording
  implying it protects a key was removed or marked stub.
- macOS-native behaviour (Keychain access groups, Touch ID, XPC approver,
  DMG/Gatekeeper) is NOT-RUN; the darwin posture path is only exercised
  through mocked platform tests, and the Keychain tripwire fails on
  purpose.
- Windows: nothing ran on Windows. `windows_check.py` on this Mac reports
  its checkable set and names `darwin` in its NOT-RUN reasons.
- The Layer B E2E suite runs and passes here, but it proves only what
  it drives: the CLI → daemon → proxy → mock path with TEST-ONLY keys
  and the test-harness approver. It does not prove the production
  approval gesture (none exists), real-provider behaviour (never
  contacted), or the git proxy (not built).
- The composition-root deny floor enforces `github.classify` **path and
  method** rules only. `classify` also takes a parsed body and a repo
  allowlist, and the proxy adapter hands it raw bytes, so its
  body-dependent rules are not reached from this seam; the pack remains
  the source for anything body-shaped. Stated, not implied.
- `mach_continuous_time` has never been called in this tree; the darwin
  clock label says so explicitly.

## v0.2 final — measured counts (authoritative Linux run, the Linux build VM)


Run command (build venv only — system python lacks pinned `cryptography`, so
signed-pack loads fail closed there and its failures are an environment
artefact, not code failures):
`~/workspace/sealvra-build/.venv/bin/python -m unittest discover -s tests`

| Measure | Count |
|---|---|
| Discovered tests (full suite) | 11,771 |
| Passed | 11,753 |
| Failed | 0 |
| Errors | 0 |
| Skipped | 16 |
| Expected failures | 2 |
| Full-suite runtime | 137.8 s (budget: under ~10 min) |
| Generated cases (scale engine, W10) | 10,697 |
| Hand-written tests (11,771 − 10,697, incl. W10's 12 engine/audit tests) | 1,074 |
| Master test registry snapshot (regenerated by manager) | 11,785 |

Generated by file: policy 4,242; sessions 3,776; malformed 1,452; misc 557;
audit 359; proxy 311. Registry (11,785) exceeds discovery (11,771) by exactly
14 — the Layer B E2E set, which the registry counts as registered while
discovery reports it under the class skip; the registry/gate suites pass
(`tests.test_registry` + `tests.test_gates`: 43 tests OK).

Padding audit: PASS. `tests/test_padding_audit.py` + `tests/test_scale_engine.py`
12 tests OK; the deterministic 50-case sample (seed 20261037) has distinct keys,
varying inputs, and asserted security outcomes in every case; the engine's
dedup registry fails loudly on collisions. No assertion-free, duplicate, or
bare "no crash" case counts toward the total — fuzz cases carry explicit
oracles (canonicalisation invariants, forward/canonical equality, no secret
in output). The 10,000+ goal is met honestly (10,697 generated), and the
manager states plainly what count alone does NOT buy: adversarial coverage
(present — W09's 62 new classes now all pass), real-platform coverage (still
missing — no Mac/Windows run), and that every test asserts something (audited
by sample, not by total).

## v0.2 final — manager integration fixes (made by the manager, not workers)

1. **Dual-consume closed (was the last failing security test).**
   `verify_and_consume` and `spend_grant` now share one consumed state
   (CONTRACT §13.7): verifying consumes the grant, spending the grant
   consumes the broker nonce, `RealApprover.approve` verifies without
   consuming, and consumption happens exactly once at forward time in
   `spend_for_forward` (with grant-existence, destructive-grant, and
   deadline checks before any consume). `test_adversarial` now passes
   in full, including
   `test_verified_decision_cannot_also_spend_grant`; no test was weakened.
2. **CLI sessions on daemon IPC (E2E blocker 1, partially closed).**
   `sessions list/kill/kill-all` (and create, after its vault guard) route
   through daemon IPC when a daemon is running, falling back to the
   process-local sessions module only when none is running. Live-proven
   with an isolated `SEALVRA_DAEMON_DIR`: an IPC-created session was
   listed by the CLI, killed by the CLI, then shown killed. CLI create
   via IPC is implemented but NOT live-proven — it first does a vault
   lookup through the CLI's stub-only vault interface (`vault.get_key`
   does not exist on the real Vault class), so a real CLI create still
   fails before IPC. CLI test harness now stubs "no daemon" when
   stubbing the sessions backend, so a daemon leaked by another test
   cannot hijack CLI tests (this leak caused the first final run's
   5 failures + 1 error in `test_w10_cli`; the re-run after the fix
   is the green count above).

**v0.2 sessions list defect (measured 2026-10-31 on macOS):**
Command: `sealvra sessions list` with no daemon running.
Result: exit 1, error KH-1006: backend error: module 'sealvra.sessions' has no attribute 'list_sessions'.
Root cause: CLI sessions commands route through daemon IPC when a daemon is running; without one they fall back to the process-local sessions module, which lacks `list_sessions()`, `create_session()`, `kill_session()`, and `kill_all()` as module-level names. Those exist only as methods on `SessionStore` (sealvra/sessions.py:640+) and are invoked via IPC `sessions.list` from the daemon.
Evidence: reproduced in a sandboxed HOME against both real daemon (exit 0, correct) and no-daemon (exit 1, dead); test_w10_cli.py stubs a FakeSessions mock to exercise the fallback-only branch. The joined CLI → daemon → proxy path is proven end-to-end by tests.test_e2e Layer B (14/14).
Fix priced as needs-owner: wire `sealvra.sessions` to a SessionStore or provide module-level proxies matching the CLI's call shape; keep IPC-first, fallback-second policy but ensure the fallback actually implements the commands listed in README.md. Record in docs/CLI-SERVICES.md with explicit notes on what runs without a daemon.
The design note in sealvra/cli.py at :718–727 and :1122–1136 documents that IPC is first, local store second — this build measures that claim but exposes the missing implementation gap.
3. **Zipapp reproducibility closed.** `scripts/make_zipapp.py` now excludes
   `__pycache__`/`*.pyc` (W19's cold-cache FAIL is fixed):
   `scripts/repro_check.py` 14 pass, 0 fail, including cold-cache
   byte-identical. Rebuilt zipapp: `dist/sealvra.pyz`,
   SHA-256 `af13801ea5c5694fef1896b1f1e48951654af805c03d7fdc01ef8db6f1a1ec2a`
   (never reuse the v0.1 hash `84791922…`). The build still reports
   version 0.1.0 — pack versions are signed and asserted at 0.1.0, so
   a version bump is a release-time decision, not a silent edit.
4. **macOS checker yaml false positive closed.** C6 now gates shipped
   dependencies only (zipapp packs `sealvra/`); test files are
   excluded, as C5 already excludes them. `scripts/macos_check.py`:
   NO-CHECKABLE-VIOLATION. `scripts/windows_check.py`: 19 PASS / 16 NOT-RUN.
5. **CI now calls the gates explicitly.** `.github/workflows/ci.yml`
   (linux/windows/macos jobs) gained a "Release gates" step running
   `scripts/grep_gates.py` + `tests.test_registry tests.test_gates`.
   The workflow is still PREPARED, NEVER RUN (it is not on the pushed branch; `gh run list` returns zero runs).
   `scripts/grep_gates.py` exit 0 on the final tree.
   `scripts/sbom.py --diff sbom.json`: PASS, no component change
   (2 direct + 3 transitive, same versions/licences).
6. **GUI defaults survival verified.** W18's `DEFAULTS` block is present
   in the final `sealvra/gui.py` (W03's concurrent edits did not
   overwrite it).

## v0.2 final — gap status (all 10 known gaps, none dropped)

| Gap | Status | Reason / evidence |
|---|---|---|
| 1. Daemon process-local | CLOSED (Tier B honesty) | Real detached daemon + IPC across CLI invocations, live-proven; sessions in-memory only, death = session death. Peer-UID auth only — same-user processes are NOT separated (Tier B). |
| 2. Real approver not wired | CLOSED in proxy; joined path PARTIAL | Real broker-owned approver wired into proxy; test approver only via `SEALVRA_TEST_APPROVER=1`. Joined CLI→daemon→proxy approval path still unproven (see gap 8). Real OS gesture seam is `RealApprover(gesture=…)`; `gesture=None` denies fail-closed. |
| 3. GUI manual refresh | CLOSED (live-display NOT-RUN) | Daemon IPC client + timed auto-refresh (5 s default) + loading/live/empty/error states; 43 pass / 3 skipped (window-creation, no display on this VM). |
| 4. Pack signing | CLOSED | Ed25519 detached signatures, hash + signature verified, revocation beats trust, no unsigned fallback. Key `pk-a584d783bdcd5feb` (public only; private destroyed — next pack change needs a new keypair + trusted_keys update in one reviewed commit). Signature ≠ authorisation (anyone who can commit trusted_keys can list a key). |
| 5. Git interposition | PARTIALLY CLOSED | Credential helper (session-scoped credential, never the real key) + wrapper (gating, force-push/ref-delete denial, audit) pass 37/37. No git proxy exists; direct git with standing credentials bypasses logging/gating (doctor inventories them); `GIT_INTERPOSITION_BUILT` stays `False`. |
| 6. Windows / macOS | CHECKED ONLY, NOT-RUN on real machines | Windows 19 PASS / 16 NOT-RUN; macOS NO-CHECKABLE-VIOLATION with 5 areas SPEC-ONLY. No Mac/Windows run anywhere; DPAPI/Hello/CredUI/Keychain/Touch ID/XPC/DMG/NSIS are design/spec only. Real-machine plans: `docs/macos.md` §6 (M5 Mac), `docs/windows.md`. |
| 7. G0 closure | MACHINERY CLOSED; owner items OPEN | Registry + exception registry + artifact binding + grep gates landed and passing (regenerated to 11,788 ids on 2026-10-31, two additions and zero drops). Commit binding refuses unbound releases; here `.git` exists so a local HEAD is detectable, but that commit is not on the remote, so nothing is bound — correct, and not invented. Reviewer-of-record, CI wiring (now added as steps, still never run), and all OD items remain open. G0-17/19/20 remain limitations. |
| 8. Real-path E2E (14 tests) | STILL NOT-RUN (partially unblocked) | Layer A mocks 8/8 pass. Layer B stays class-skipped. Blocker 1 partially closed (CLI list/kill on IPC, live-proven); remaining: CLI create vault adapter, daemon-served proxy, CLI PoP handoff, status naming upstream bases. Gate NOT loosened. |
| 9. TTL / worker-per-key divergence | DOCUMENTED DIVERGENCE | Broker clamps, SessionStore rejects; neither exceeds the 2 h cap. Worker-per-key is deliberately stricter than v3 (broker refuses a second live session for the same key). |
| 10. Owner decisions OD-01–OD-18 | ALL STILL OPEN | None decided for the owner. Defaults used are labelled recommendations (update-check: f16 recommends ON, `UPDATE_CHECK_DEFAULT` stays None pending OD-13; no updater ships, so fresh installs send zero update traffic). |

## v0.2 final — still open (not closed, with the test that would close each)

- Socket `sessions.create` approval gate vs Tier B statement (owner decision;
  mitigations: worker-per-key refusal, no key/token/PoP over socket).
- Production broker seal construction (`seal_required=True`); seal enforcement
  is flag-gated in code, and a seal-less broker still accepts seal-less cards.
- Strict password-ticket mode adoption by the broker; ticket-based rotate
  (needs a broker-level flow).
- Crash-scrubber wiring (`add_secret` at key-add/rotate) + locked flag on
  which `assert_clean` raises; until both land, v0.2 sends no crash reports
  at all — the only scrubbing claim that holds.
- Migration CLI subcommand for `apply_shell_migration()` (W18-area routing).
- Daemon IPC `audit.verify` returns KH-1005 (daemon owns no audit log;
  needs a manager decision on audit root/secret convention).
- CLI audit verify/export + CLI keys/sessions-create vault lookups need an
  audit-root convention and a CLI↔vault adapter (stub-only interfaces today).
- Action SHAs not pinned in CI; no hash-pinned lockfile; 14-day quarantine
  not mechanically enforced; no independently-sourced-toolchain rebuild.
- GraphQL variables unresolved before classification (mitigated: GitHub pack
  denies `/graphql` outright); tunnelled bytes bypass path/body policy by
  design (HOST-ONLY POLICY, read-class + allowlist + byte budget only).
- No Mac/Windows run; no signed DMG; no real Keychain/Touch ID/XPC proof;
  screen-lock kill-after-15-min unproven; Windows supervisor tree-kill and
  orphan self-termination unproven on Windows.

## v0.2 final — release-readiness verdict: NOT READY for a public release

The full Linux suite is green at 11,771 tests and the 10,000+ goal is met
honestly, but a public release is blocked by: the unproven joined
CLI→daemon→proxy path (Layer B E2E still skipped), no Mac/Windows run, CI
never run, all 18 owner decisions open, and the open items above. The next
step remains user-triggered: he connects GitHub himself, then approves a
push by name (repo + branch); only then is a repo created, code pushed,
CI run for the first time, and the real Mac/Windows plans executed.

> **v0.2 DRAFT (W20, 2026-10-28, snapshot — manager finalises).**
> The v0.1 manager-finalised report below is kept whole and
> unedited; nothing in it is hidden or rewritten. This section
> records only what v0.2 changed and what was measured for it,
> on a tree that other v0.2 workers were landing into
> concurrently — so every v0.2 number here carries its time and
> its run command, and none of them is a release count. The
> manager re-runs the full suite on a frozen tree before any
> release claim. Hard limits held throughout: local build/test
> only, no push, nothing published, no real provider contacted, no name
> announcement or reservation, no rename to Keyseal, no real
> keys — only fake TEST-ONLY values and loopback mocks.

## v0.2 draft — what landed, measured (2026-10-28, the Linux build VM)

All runs below used the local `.venv` under the build root
(Python 3.12, `cryptography` + `argon2-cffi` pinned in
`requirements.txt`).

| Slice (CONTRACT §13) | Measured state |
|---|---|
| §13.1 Cross-process daemon (W01) | LANDED, passing in isolation: `tests/test_daemon_ipc.py` green as part of an 86-test run with approver-wiring, pack-signing, and git suites (see below). Live CLI check with an isolated `SEALVRA_DAEMON_DIR`: `daemon start` spawns a detached `sealvra.daemon --serve` process, a later CLI invocation's `daemon status` reports the same pid, `daemon stop` ends it and kills its workers. Rendezvous: `$SEALVRA_DAEMON_DIR` else `~/.sealvra/daemon` (0700 dir, 0600 socket, SO_PEERCRED peer-UID). Auth is same-UID only — Tier B honesty stated in README + security model, not papered over. Daemon death = session death (in-memory only). |
| §13.2 Real approver wiring (W02) | LANDED in the proxy, passing in isolation: `tests/test_approver_wiring.py` green (same 86-test run). Production approve callable is the real broker-owned approver; a test approver is refused unless the harness marker `SEALVRA_TEST_APPROVER` is set. NOT proven end-to-end: the joined CLI → daemon → proxy approval path is blocked by the CLI-sessions gap below. |
| §13.3 Pack signing (W04) | LANDED: `packs/github.sig` + `packs/gemini.sig` (Ed25519 JSON envelopes), `packs/trusted_keys.json` (one key, `pk-a584d783bdcd5feb`), `packs/revoked.json` (empty = nothing revoked), `packs/SIGNING.md`, `scripts/sign_pack.py`; `tests/test_pack_signing.py` green (same 86-test run). Loader verifies content hash AND signature against a trusted, non-revoked key; unsigned/hash-only/missing-trust loads refused. Transient breakage observed mid-landing: the refuse-unsigned flip landed BEFORE the `.sig` files, breaking the v0.1 integration suite (8 errors) and one pack-loading test until the signatures arrived — a landing-order lesson, not a current failure (re-verify on the frozen tree). |
| §13.4 Git helper + wrapper (W05) | LANDED, passing alone: `tests/test_git.py` 37/37 (run alone; running it together with `tests/test_e2e.py` in one process collides on the fixed mock ports — a harness limitation, not a code failure). `sealvra/git.py` + `scripts/git-credential-helper` exist; the adapters doc git section (W05, not rewritten here) records coverage and the remaining bypass. `GIT_INTERPOSITION_BUILT` in `github.py` is still `False`; no Sealvra git proxy exists yet; direct-client pushes still bypass. |
| §13.6 Test registry + grep gates (W08) | MACHINERY LANDED, GATE FAILING at snapshot: `tests/test_registry.py`, `scripts/grep_gates.py`, `tests/test_gates.py` exist; registry + gates suites pass except `test_discovery_equals_registry`, which FAILS because discovered tests exceed the frozen registry (47 additional elements at the snapshot) — other workers' new tests landed without regeneration. Fix is W08's: regenerate (`python3 tests/test_registry.py --regenerate`) and review the diff; never silently drop a hard test. |
| §13.6 Egress sections (W17) | LANDED in docs (`docs/security-model.md` egress sections, not rewritten here) with `tests/test_egress.py`. Snapshot state: egress tests pass except the registry-gate failure above is the only gates failure in the combined egress+gates+registry run (65 tests: 1 failure, 2 expected failures — the failure is the registry count, not an egress assertion). Earlier in the day the same file showed scrubber-assertion failures; those did not reproduce in the later run — re-verify on the frozen tree rather than trusting either snapshot. |
| TTL unification (v0.1 divergence) | STILL DIVERGENT (re-checked 2026-10-28): `broker.py` still clamps over-cap TTLs (`clamp_ttl`/`clamp_idle`); `sessions.py` still rejects them. Both never exceed the 2 h cap, so the invariant holds, but the API behaviour is not unified. |
| Owner decisions OD-01–OD-18 | ALL STILL OPEN. In particular OD-01 (name — still Sealvra, no rename), OD-02 (registrar/trademark — nothing reserved), OD-13 (update-check default — `UPDATE_CHECK_DEFAULT` still unset per the egress doc; no updater ships at all, so a fresh install sends zero update traffic under any reading). |
| Per-OS status | Unchanged from v0.1: no real Mac run, no real Windows run anywhere. `docs/windows.md` / `docs/macos.md` belong to W06/W07 and were not rewritten here. |

## v0.2 draft — E2E real-path status: STILL SKIPPED, exactly why

`tests/test_e2e.py`, Layer A (mock fidelity): 8/8 pass in every
clean run, including a clean post-edit run after W20's
docstring-only change (`Ran 8 tests, OK (skipped=1)` — the skip
is the RealPathTests class skip; mock tests unaffected). Layer B
(RealPathTests, 14 tests): **1 class-level skip = NOT-RUN, not a
pass, not a failure.** The v0.1 skip reason is partly spent
(the persistent daemon landed), but the v0.2 re-check on
2026-10-28 found four measured blockers, any one of which alone
keeps Layer B skipped (full detail in the file's docstring,
which was updated; no test logic was changed and no gate was
loosened):

1. **CLI sessions are not on daemon IPC — and at this snapshot
   they fail outright.** `sealvra sessions list` returns
   KH-1006 ("module 'sealvra.sessions' has no attribute
   'list_sessions'"), and `SessionStore` is documented in-module
   as in-memory with no persistence. A session created by one
   CLI invocation is not visible to the daemon, to a later CLI
   invocation, or to any proxy.
2. **No proxy HTTP server is served by the daemon.**
   `serve_main` loops on daemon status only; nothing listens
   on the proxy port for E2E to call through.
3. **No CLI PoP-key handoff exists.** `sessions create` prints
   the token once, but the PoP key stays in daemon/broker
   memory and no test-mode marker is printed, while PoP is
   mandatory with no bare-bearer fallback — signed proxied
   calls cannot be constructed from CLI output alone.
4. **`daemon status` names no upstream bases.** It prints only
   "daemon: running (pid N)", so E2E's safety gate (confirm the
   proxy points at loopback mocks before any proxied call)
   cannot pass. Loosening that gate would risk real-provider
   contact and was refused.

Two further cautions from the re-check, recorded rather than
hidden. (a) Daemon rendezvous is global by default
(`~/.sealvra/daemon` unless `SEALVRA_DAEMON_DIR` is set),
so E2E's scratch-cwd isolation assumption is false and
concurrent runs share one daemon. (b) While probing, this
worker once stopped a shared daemon that another worker's run
had started, and once killed (by exact PID) a `unittest
discover` process holding the mock ports; both actions may
have interrupted concurrent workers' runs. Neither is repeated:
later port contention was handled by waiting, not killing,
and the manager should re-run any suite that overlapped this
worker's probe window (2026-10-28 ~09:30–09:50 NPT).

**Contention note (why some v0.2 runs show e2e errors):** the
mock ports (127.0.0.1:18765/18766) are fixed and shared. When
another worker's suite holds them, `tests/test_e2e.py` fails
in `setUpClass` with address-in-use errors — that is port
contention between concurrent runs, not an e2e code failure,
and it must not be read as a test failure of this file. Clean
runs (ports free) give 8 mock passes + 1 class skip.

**What un-skips Layer B (all four, in order):** CLI sessions
routed through daemon IPC (W01/W18) → a proxy listener served
by (or alongside) the daemon → a CLI PoP-key handoff that
preserves "token shown once, PoP key never logged" → status
output naming upstream bases/proxy port. Then remove the skip
and require all 14 tests to pass; never un-skip by stubbing
the stack or weakening the safety gate.

## v0.2 draft — full-suite snapshot (NOT a release count)

Command: `.venv/bin/python -m unittest discover -s tests`
from the build root. The tree was changing underfoot while
v0.2 workers landed, so two snapshots are recorded instead of
one polished number:

- Early snapshot (before pack `.sig` files landed): 569 tests,
  2 failures + 2 errors in the summary count, but the failure
  detail showed the pack-signing flip breaking the integration
  suite (8 setUp errors on missing `github.sig`) plus egress
  assertion failures — i.e. a mid-landing tree, not a stable
  verdict. Do not quote this snapshot.
- Isolated-slice runs after the signatures landed:
  daemon_ipc + approver_wiring + pack_signing + git = 86 tests,
  0 failures (one combined run showed 2 git failures + 1 error
  that did not reproduce when git was run alone — traced to
  fixed-port collision with e2e, see the contention note);
  registry + daemon_ipc + approver_wiring + pack_signing =
  52 tests, 0 failures; egress + gates + registry = 65 tests,
  1 failure (the registry-count gate) + 2 expected failures.

**No frozen-tree full-suite number exists yet for v0.2.** The
manager must freeze the tree, regenerate the registry, and
re-run discovery to a single recorded count before any release
claim. The v0.1 final number (577 tests, 0 failures, 13
skipped) is NOT carried forward as a v0.2 number.

## v0.2 draft — release checklist (verdict: NOT READY)

See README §"Release readiness (v0.2 draft)" for the full
table. In short: do not publish, tag, or announce v0.2. The
promised slices are mostly landed in isolation, but the joined
CLI → daemon → proxy user path is unproven, the release gate
itself fails on a stale registry, CLI sessions commands fail
at the snapshot, and no Mac or Windows run exists. What is
still NOT ready, in one list: (1) CLI sessions on daemon IPC;
(2) a served proxy + CLI PoP handoff; (3) un-skipped, passing
W15 real-path E2E; (4) a frozen-tree full suite at 0 failures
with a regenerated registry; (5) appointed independent
reviewer + CI gate wiring + repo commit binding (all blocked
on the user's named push approval, which has not been given);
(6) real Mac and Windows runs; (7) all 18 owner decisions,
especially OD-01/OD-02 before any name use. What IS ready to
be claimed (isolated, measured): daemon IPC, real-approver
wiring, pack signing, git helper + wrapper (partial boundary,
honestly stated), and the v0.1 in-process integration path
subject to re-verification on the frozen tree.

## v0.2 draft — files changed by W20 (this worker)

- `README.md` — v0.2 draft banner, quick-start daemon-IPC
  update + snapshot breakage, per-OS snapshot row, security
  limitations 4 (rewritten: git narrowed, not closed) + 10/11/12
  (daemon IPC Tier B, pack signing, CLI-sessions gap), G0 rows
  05/09/12/16 updated, release-readiness table (NOT READY).
  W08's G0-06/G0-18 wording preserved; windows.md, macos.md,
  adapters git section, and egress sections untouched.
- `docs/user-guide.md` — v0.2 banner, daemon-IPC setup, pack
  signing, CLI-sessions snapshot warning, proxy/approver/git
  bounds.
- `docs/security-model.md` — v0.2 banner + tier-table rows
  (daemon IPC, pack signing, real approver, git wrapper-run
  only). Egress sections untouched (W17).
- `docs/troubleshooting.md` — v0.2 banner, git-push entry
  updated to wrapper-run-only, plus pack-refused, daemon
  already-running, and sessions KH-1006 entries.
- `tests/test_e2e.py` — docstring + skip-reason text only
  (v0.2 re-check + four blockers); no test logic, no gate
  loosening, no port or mock changes. Mock tests unaffected.
- This report section (draft for manager finalisation).

---

# Sealvra v0.1 — Build and Test Report (manager-finalised)

Stack: Python 3.12, stdlib + exactly two pinned dependencies —
`cryptography==50.0.2`, `argon2-cffi==25.1.0` (Argon2id + AES-256-GCM
have no stdlib equivalent; a home-made cipher or scrypt substitute
was forbidden). Package run as `python3 -m sealvra` from the build
root; tests use `unittest` (pytest not assumed). All runs below used
the local `.venv` under the build root — system Python lacks the two
dependencies, so suites error on import there with 0 code failures.
Nothing was pushed, no repository was created (the owner's public repository keeps only its initial commit on the remote), no real provider was
contacted, no name was announced or reserved, no real keys exist
anywhere (only clearly fake `TEST-ONLY-…` values and loopback mocks).
Working title stays Sealvra throughout; no rename to Keyseal.

## Measured counts — full suite on the Linux build VM (NOT the Mac numbers)

Command: `.venv/bin/python -m unittest discover -s tests`
(after all manager integration fixes, final tree).

| Scope | Passed | Failed | Not run | Notes |
|---|---|---|---|---|
| Full discovery (all workers + manager integration) | 564 | 0 | 13 skipped | 577 tests total; 0 failures, 0 errors |
| Adversarial suite (W14) | 47 | 0 | 8 skipped | Was BLOCKED at worker delivery (1 PoP replay failure); fixed by the manager, now green |
| End-to-end, manager integration (new) | 8 | 0 | 0 | Broker + policy packs + audit + proxy against loopback mocks, in-process |
| End-to-end, W15 file | 8 mock tests | 0 | 1 class-level skip covering 14 real-path tests | W15's real path stays NOT-RUN: its gate needs CLI daemon persistence + a test approver + a CLI PoP handoff, which v0.1 does not have; the manager integration file covers the same ground in-process instead |
| Windows check (`scripts/windows_check.py`) | 14 | 0 | 12 NOT-RUN | Gate logic only; real Windows behaviour NOT-RUN |
| macOS check (`scripts/macos_check.py`) | exit 0, verdict NO-CHECKABLE-VIOLATION, all 5 interfaces PRESENT | 0 | 6 NOT-RUN | Real Keychain / Touch ID / XPC / DMG / Gatekeeper NOT-RUN |
| Zipapp build | built | — | — | `dist/sealvra.pyz`, sha256 `8479192292ff14f6dbce7256a5c7940f5d37d26a2cf9262e78fa5e6b243b3397`; `--help` verified live; NOT a standalone exe/DMG/NSIS |
| SBOM + reproducibility | 11 pass, 0 fail, 0 skip | 0 | 0 | SBOM regenerated on the final tree: direct=2, transitive=3, source_files=69; repro check PASS |
| Live CLI smoke | `--help` exit 0, `doctor` runs (names only), `daemon status`/`start` work process-locally | — | — | `keys reveal` and `sessions approve` rejected with KH-2001, verified live |

A test not run on a platform is NOT-RUN, never PASSED. Windows and
macOS native behaviour was not run anywhere in this programme.

## Per-worker module status after the manager's check

All 20 workers completed. Every module passed its own suite and the
manager's integration run, except where a slice is explicitly named
as next work below. Counts are each worker's reported run, re-verified
where the manager re-ran the file (full-suite green covers all of
them on the final tree):

- W01 daemon/broker/supervisor — pass (18 tests). Manager fixes:
  PoP replay (see below), Windows kill-path gating (see below).
- W02 vault/compartments/crypto — pass (34 tests).
- W03 sessions/tokens/TTL — pass (32 tests).
- W04 proxy engine — pass (50 tests). Manager fix: level-3 approval
  reachability (see below).
- W05 policy engine + packs — pass (32 tests); packs: GitHub 42
  endpoints, Gemini 23 endpoints, hash-verified.
- W06 GitHub adapter (f09 rewrite) — pass (53 tests).
- W07 Gemini adapter (f08 rewrite) — pass (32 tests).
- W08 approval ceremony — pass (37 tests).
- W09 audit log — pass (33 tests).
- W10 CLI — pass (42 tests).
- W11 native GUI (tkinter) — 16 pass, 2 NOT-RUN (window-creation
  smoke tests, no display on this VM); headless import raises
  KH-3001 honestly. No web dashboard anywhere.
- W12 agent integrations/wrapper/MCP/probe — pass (32 tests).
- W13 platform abstraction — pass (47 tests); mocked-platform tests
  labelled as such, never a real macOS/Windows pass.
- W14 adversarial — pass after manager fix (47 pass, 8 NOT-RUN).
- W15 E2E + mocks — 8 mock tests pass; 14 real-path tests NOT-RUN
  (class-level skip, see table).
- W16 Windows check — pass after manager fix (14 PASS, 12 NOT-RUN).
- W17 macOS check — pass after manager fixes (exit 0).
- W18 docs/README — finalised by the manager (this report + README
  G0 table updated from draft language to measured state).
- W19 supply chain — SBOM + repro PASS on the final tree (see table).
- W20 packaging/CI — 14 pass, 2 skipped (PowerShell parse checks,
  no `pwsh` on this VM — must be parse-checked on Windows before
  the `.ps1` files are claimed valid). CI file prepared, never run
  (not on the pushed branch).

## Manager integration fixes (made by the manager, not workers)

1. **PoP replay without a nonce (W14 stop-ship failure).** Broker
   `verify_pop` previously accepted a replayed PoP when `nonce=None`.
   Fix: MAC is verified first, then replay is enforced with the nonce
   if given, else the PoP value itself as the one-time key — a signed
   request now verifies exactly once per session. W14's suite flips
   from BLOCKED to green; W01's nonce tests still pass.
2. **Proxy level-3 approval reachability.** W05's level-3 decisions
   carry `allowed=False` until approval, but the proxy denied on
   `allowed=False` before ever consulting the approver, so
   approval-gated calls could never be approved. Fix: level 3 passes
   the first gate, the approver decides, and only an approved call
   proceeds (as allow-with-log). Proved by the integration test:
   GitHub contents write forwards when approved, denies when refused.
3. **Windows supervisor kill path (W16 blocker).** `os.getpgid` /
   `os.killpg` were ungated and would crash on Windows. Fix: Windows
   uses `process.terminate()` / `process.kill()`; POSIX paths are
   guarded with the `sys.platform != "win32"` form the Windows
   checker recognises. `windows_check.py` now passes (was 1 FAIL).
4. **Credential Guard + PIN label (W16 warning).** Guard + Hello PIN
   previously returned the biometric mechanism label. Fix: it now
   returns T2 with a remote-typed-PIN label, never T1/biometric.
5. **macOS checker false positives.** The checker flagged first-party
   test helpers (`adversarial_helpers`, `mock_providers`,
   `tests.*`) as third-party imports and test functions as
   fake-success stubs. Fix: project-local test code is exempt from
   the third-party and stub scans (product code is still scanned);
   the keychain-interface markers were broadened to the wording the
   platform module actually uses. `macos_check.py` now exits 0.
6. **CLI/daemon interface.** CLI called module-level
   `daemon.status()`/`start()`/`stop()`, which did not exist. Fix:
   module-level functions delegating to a process-local singleton
   Daemon were added. Honest limit recorded, not hidden: v0.1 has
   no cross-process daemon persistence — a daemon started by one
   CLI invocation does not survive that process. The CLI reports
   exactly what its process-local daemon reports.
7. **Integration test (manager-owned).** `tests/test_integration.py`
   wires the real Broker, PolicyEngine + packs, AuditLog, and
   ProxyEngine in-process against loopback mocks (ephemeral ports,
   so full-suite runs cannot collide with W15's fixed ports): GitHub
   read injects Bearer and verifies the audit chain OK; GitHub write
   forwards when approved and denies when refused; GraphQL and
   secrets writes never reach the mock; Gemini generate injects
   `x-goog-api-key` (never `?key=`); Interactions denied; killed
   sessions cannot call; replayed PoP denied. 8/8.

## Recorded divergences and limitations (not silently unified)

- **TTL over-cap: broker clamps, session store rejects.** Both never
  exceed the 2 h cap, so the security invariant holds, but the API
  behaviour differs by layer. Unify to reject in v0.2; do not claim
  they already agree.
- **Worker-per-key is stricter than v3.** The broker refuses a
  second live session for the same key_id, while v3's rule is one
  session = one key (a session must not hold multiple keys). Two
  agents sharing one key concurrently are blocked in v0.1; use
  separate keys or sequential sessions. Recorded, not relaxed
  silently.
- **Types reconciliation incomplete.** W08 uses its own card/pending
  types rather than W01's `types.py` `ApprovalRequest`, and W05
  defines `PolicyDecision` locally mirroring CONTRACT §2. Behaviour
  is consistent (the proxy fix above bridges the level-3 case), but
  the canonical-types alignment is v0.2 work.
- **Pack signing / dual-signature rotation + revocation list: not
  implemented** (manager-level item). Packs are hash-verified on
  load; signing is not yet built.
- **W02 boundaries:** in-memory secret buffers are not mlocked
  (Python limitation); two-wrapping recovery keys not built (backup
  containers use a single export credential — touches G0-15);
  synced-folder detection matches known sync-client directory names
  only (a renamed sync folder will not be flagged).
- **W09 boundaries:** chain hash is plain SHA-256 per CONTRACT, not
  an HMAC — it detects edits but does not prove authorship against a
  same-UID tail-rewriter; tail-truncation detection rests on
  anchors, which are therefore required, not optional.
- **W13 boundaries:** pure gate/design logic, no native Keychain,
  DPAPI, Secret Service, polkit, LAContext, or Hello calls — a tier
  reported there is a gate for the caller to enforce with a real OS
  call, not proof the call happened. The Windows verifier-helper
  process is a design specification, not a built process.
- **W07 boundaries:** no real Gemini calls, no proxy/broker
  integration inside the adapter itself (wiring is the integration
  test); spend data lives in-module, not in `packs/*.json`.
- **W06 boundaries:** git interposition NOT built
  (`GIT_INTERPOSITION_BUILT = False`) — git-protocol pushes bypass
  the broker manifest and are NOT logged/gated. API-only sessions
  (no git-usable credential handed to the agent) are the only v0.1
  mitigation, and that decision belongs to the broker/session
  templates.
- **W11 next slice:** live daemon socket wiring (window renders its
  data source, manual Refresh, honest empty state); no system-tray /
  menu-bar extra (tkinter has no tray API); no timed auto-refresh
  until the daemon lands.
- **W12 gaps:** agent-side sidecar client library not shipped
  (protocol documented in the module); MCP tool bodies are gates,
  not implementations; settings scan is heuristic, not a full TOML
  parser (hash-watch + re-probe is the backstop).
- **W20 gaps:** Keychain wipe NOT implemented in uninstall scripts
  (vault directory + local audit removed, platform-keychain items
  are a documented manual step — never describe the wipe as a
  keychain wipe); DMG/NSIS/.deb are specs only; the only real
  distribution is the zipapp. W16's Windows runner install/verify
  steps were supplied but not placed in `ci.yml`, because the
  `.ps1` files cannot be parse-checked on this VM — place them only
  after a Windows parse check.
- **X11 write question (W13):** non-destructive write on X11 is
  allowed with the X11 badge in W13; v3's refusal set is destructive
  + key-lifecycle only. If write should also be refused on X11, that
  is a one-line change to the refusal set, to be decided and
  recorded — it is NOT decided here.

## G0 status after integration

Closed in code: G0-03, G0-06, G0-13, G0-14, G0-21 (5 items).
Limitation: G0-16 (test registry/reviewer), G0-17 (updater/TUF-lite
design only), G0-19 (company edition out of scope), G0-20 (no name
assets reserved, nothing announced) (4 items). Partially closed:
the other 15 items, including G0-12 (git-push gap open) and G0-05
(TTL divergence above). Full table with basis: README §"Gate G0".

## What still needs real Mac/Windows testing or owner decisions

- Real Mac (user's M5): Keychain one-item-per-key, Touch ID
  two-step approval, sandboxed approver XPC, DMG install +
  Gatekeeper — follow `docs/macos.md` §6 with TEST-ONLY keys only.
- Real Windows: DPAPI/Credential Manager, Hello biometric + PIN,
  CredUI verifier helper, Remote Credential Guard, `install.ps1` /
  `uninstall.ps1` runs (default preserves vault; wipe path in a
  throwaway directory only), zipapp under Windows Python 3.12,
  NSIS build — all per `docs/windows.md`.
- All 18 v3 §5 owner decisions (OD-01–OD-18) remain open; no worker
  settled any of them. In particular: OD-01 name confirmation
  (Keyseal vs backups vs fresh coined-words round — nothing renamed
  in this build), OD-02 registrar + trademark execution, OD-03
  session-extension dissent, OD-14 solo-mode release authorisation.
- Next slices after v0.1 (in order): persistent cross-process daemon
  with full session IPC; real W08 Approver wired into the proxy's
  approve callable (replacing the integration test's test-double);
  GUI live-daemon wiring + timed refresh; pack signing; TTL
  reject-vs-clamp unification; worker-per-key relaxation decision.

## Next step for the push (user-triggered, not now)

No push has been made and none is authorised by this build. The
exact next step is: the user connects GitHub himself, then approves
a push by name (repo + branch) in his own words. Only then is a
repo created and code pushed, followed by the first CI run of
`.github/workflows/ci.yml` (prepared, never run) and the real
Mac/Windows test plans above. Until then the build lives only in
`~/workspace/sealvra-build/`.
