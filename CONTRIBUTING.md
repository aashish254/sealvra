# Contributing

Sealvra is a local credential broker: you import a real API key once, and
the daemon mints short-lived opaque stand-ins that only work through its
loopback proxy, injecting the real key at the last moment. The GUI is a
local control panel over that daemon — read, kill, start/stop, search.

Everything below is the command set this repository actually ships. The
normative source is `CONTRACT.md`; `README.md` is the state of the build;
`BUILD-AND-TEST-REPORT.md` is the measured history.

## Setup

Python 3.12 only. Two direct dependencies, pinned — nothing else without a
CONTRACT amendment (see "Dependencies" below).

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

`requirements.txt` pins `cryptography==50.0.2` and `argon2-cffi==25.1.0`.
The transitive closure is recorded in `sbom.json`, not listed here.

## Running things

```sh
.venv/bin/python -m unittest discover -s tests   # the whole suite
.venv/bin/python -m unittest tests.test_w11_gui  # one module
.venv/bin/python -m sealvra                      # the CLI
.venv/bin/python -m sealvra.gui                  # the control panel
```

`unittest` is the canonical runner. `pytest` produces different test IDs
and is not what the release gate counts (CONTRACT §11).

Measured on Apple-silicon macOS with Python 3.12.13 (2026-10-31): 11774
tests executed in 96.2 s — 1 failure, 15 skips, 2 expected failures. The
one failure is intentional and platform-shaped: `tests/test_adversarial.py`
fails on darwin because macOS keychain-ACL seal storage is unimplemented,
and the test refuses to pass silently. Do not "fix" it by relaxing it.

## The gates

```sh
.venv/bin/python scripts/grep_gates.py                    # exit 0 or the build fails
.venv/bin/python scripts/sbom.py --diff sbom.json          # dependency drift
.venv/bin/python tests/test_registry.py --regenerate       # only when you add tests
```

`scripts/grep_gates.py` scans the document set (README, CONTRACT, the
report, `docs/*.md`, `sealvra/*.py`, `scripts/*.py`) and fails if a claim
that this build deleted reappears in prose. Its allowed-context list is in
that file — read it rather than copying it here.

`tests/test_registry.py` freezes every release-blocking test by stable
unittest ID, and `tests.test_registry tests.test_gates` (43 tests) asserts
discovery equals the registry exactly. Add a test, regenerate, and read the
diff: the regeneration may only ADD. A dropped or renamed ID is a fail, not
a tidy-up. Never delete a hard test to make the count match.

## Rules that are not style preferences

- **Test-only fakes.** Never use, paste, store, or ask for a real provider
  key. Sample values in this tree are clearly fake and loopback-only.
- **No real provider calls** from tests, scripts, or a dev run.
- **Never weaken, skip, or delete a failing test to get green.** Fix the
  code, or leave it failing and say so in your change description.
- **Never invent a commit hash, build hash, CI result, or platform run.**
  A test that ran on Linux is not a Windows or macOS pass, and an
  unpushed commit cannot bind a release artifact.
- **Dependencies.** A third direct dependency needs a `CONTRACT.md`
  amendment and a `docs/dependency-decisions/<name>.md` record in the same
  change — and the record alone never authorises it. `scripts/sbom.py`
  enforces this mechanically.
- **Version.** The product version is `0.1.0`. Changing it is an owner
  decision; do not bump it inside a feature change.
- **GUI scope.** The control panel reads and kills. It must never print a
  stored key, mint a session, or offer an approval action — a control
  label that does is rejected at build time by
  `SealvraWindow._forbid_action_words()`. Design decisions belong in the
  single `docs/DESIGN.md`, not a second style doc.

## Design reference

`design/mockups/` holds one HTML screen per view plus `sealvra.css` — the
layout of record, rendered in a browser before any Tk code was written.
`design/qa/` holds the harnesses that measure it; they resolve paths
relative to their own file, so they run from any directory:

```sh
NODE_PATH="<a node_modules containing playwright>" node design/qa/audit.cjs        # geometry, real-pixel contrast, clipping
NODE_PATH="<same>" node design/qa/consistency.cjs                                  # do the five screens agree with each other
NODE_PATH="<same>" node design/qa/probe-widths.cjs                                 # the lowest width at which nothing is cut
.venv/bin/python design/qa/probe-tk-widths.py                                      # the same proof against the real Tk window
.venv/bin/python design/qa/probe-tk-targets.py                                     # the 28px touch-target floor, same window
```

They need Chrome and take a minute. `audit.cjs` exits non-zero on an
undeclared clip, an overflow, or a text run under 4.5:1. The numbers it
produces are what `TABLE_SPECS` and the two breakpoint constants in
`sealvra/gui.py` are set from, so a layout change is re-measured, not
retuned by eye. Generated output (`*.png`, `measurements.json`,
`report.txt`) is git-ignored.

### A Tk root is a window on the owner's desktop

`tkinter.Tk()` draws a real, default-titled `tk` window the moment it
succeeds, and the first root created becomes `tkinter._default_root` — which
`messagebox` and `font` then attach to. Two consequences that were both live
defects:

- a "is there a display?" probe written as a bare `tkinter.Tk()` in a
  `try/except` leaks a visible window for the whole run; use
  `tests.test_w11_gui._display_available()`, which withdraws and destroys the
  root and caches the answer;
- a QA probe that ends in `sys.exit(1)`, or in an exception, must destroy its
  window in a `finally`, not on the success path.

`tearDownModule` in `tests/test_w11_gui.py` fails the run if a root outlives
it, so this cannot silently come back. To re-measure it: wrap `Tk.__init__`
and `Tk.destroy` and print the two counts — the report quotes
`created/destroyed/leaked` per run.

## Key inventory and the compromise workflow

Three Phase 0 surfaces, and each has a trap that is easy to re-break:

- **`display_name`** is chosen at import (`keys add`, or `--display-name`)
  and defaults to `Provider • <first 4 hex of key_id>`. The default can only
  be minted where the id exists, which is inside `vault.add_key` — not in the
  CLI prompt. The prompt text must be the argument to `_ask()`, not a separate
  `out.write`: the mandatory-question test reads `input()`'s arguments.
- **`compromised`** lives in the compartment's authenticated AEAD header,
  beside the rotation state, for the reason `Vault._checked_extra_header`
  documents: the session layer makes a security decision with it, so it cannot
  live in an unverified sidecar. It survives `keys rotate` and is cleared only
  by deletion. Setting it must not go through `store_secret` — that refuses an
  existing compartment, and passing an empty secret would destroy the key.
  `mark_key_compromised` re-writes under the key's own secret instead, and the
  witness for that is that `secret_for()` still returns the original value.
- **Anything reaching `osascript`** is passed as `argv`, never interpolated
  into script source. `tests.test_w10_cli` mutation-checks this: splicing the
  message back into an f-string fails the suite on purpose.

`keys mark-compromised` writes the block *before* it tries to kill sessions,
and swallows failures from the kill step. That is not tidiness: with no daemon
there is no `list_sessions()`, and an aborting kill path would report a
compromise as a failed command while leaving the key usable. See
`docs/CLI-SERVICES.md` §"Compromise workflow".

## Before you open a change

1. Run the full suite and `scripts/grep_gates.py`; quote both results.
2. If you touched `sealvra/gui.py`, re-check the rendered screens: the
   layout numbers in `TABLE_SPECS`, `OPT_COLUMN_MAX` and `INSPECTOR_MAX`
   are measured from real text, not arithmetic on character widths.
3. If you changed a decision, logging, or session behaviour, say so
   explicitly — those are contract-visible, not incidental.
4. Pushing, tagging, releasing, and changing repository visibility are the
   owner's actions. Prepare the change; do not publish it.
