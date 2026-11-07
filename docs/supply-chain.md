# Supply chain — Sealvra v0.2

Product name Sealvra (owner-decided). This document covers the local v0.2
build only.
It makes no claim about any future release, and nothing in it is a
release, a signature, or an authorisation. Where a control is planned
but not built, this document says so plainly. (Plan source: v3 wins over
v1/v2; deleted passages are never built.)

## 0. v0.2 re-audit against f16/f17 — what changed, what did not

Re-audited for v0.2 against the f16 supply-chain audit and the f17
gate audit. Changes in this round (W19 files only):

- **Dependency gates are now mechanical, not policy-only** (f16-D4,
  f16-D7, f17 P-05/P-07 in this module's scope). `scripts/sbom.py`
  fails on any third direct dependency, any non-`==` pin, and any
  registry redirection; `scripts/sbom.py --diff` fails (exit 2) on
  any component add/remove/version/licence change vs the committed
  SBOM; CI runs both. A dependency change can now only land in the
  same change as an updated committed SBOM plus a CONTRACT amendment
  and a `docs/dependency-decisions/<name>.md` record — the SBOM diff
  is what forces that change to be visible, not reviewer diligence.
- **SBOM diff on the v0.2 tree**: regenerated against the v0.1
  baseline (kept by the auditor outside the tree during the diff;
  the committed `sbom.json` is now the v0.2 SBOM). Result: **zero
  component changes** — same 2 direct + 3 transitive packages at
  the same versions and licences. 25 source-file changes (v0.2 work
  by other workers, plus this module's own files) are reported by
  the diff and are not gated, by design.
- **Build-time inventory** (f16-D1, partial): the SBOM now carries a
  `build_time` section — pip/setuptools/wheel versions plus the
  SHA-256 of every file under `scripts/` — so incident response can
  answer which releases ran which build script. What is still NOT
  built: an allowlist that *enforces* which build scripts may run
  (there is no build system here that executes dependency scripts:
  installs are plain `pip install` of two wheels, and the packaging
  script is first-party code under `scripts/`; the residual is that
  a compromised wheel's install-time code is not sandboxed — see §9).
- **Transitive closure cap** (f16-D3): 10 transitive / 12 total,
  enforced by `scripts/sbom.py`. Current closure: 3 / 5.
- **Reproducibility through packaging** (f16-B3/B4/B5): CI sets
  `SOURCE_DATE_EPOCH` for every build job and
  `scripts/repro_check.py` now proves it through the real packaging
  script (two same-epoch builds byte-identical, every entry
  timestamp == epoch) plus a cold-cache check. **Open defect, not
  hidden**: the cold-cache check FAILs because
  `scripts/make_zipapp.py` (W20's file, not edited here) bundles
  `sealvra/__pycache__/*.pyc` into the zip, so the artifact
  depends on whether tests ran before the build (23 extra entries
  on a test-run tree vs a fresh copy). Fix owned by W20: exclude
  `__pycache__`/`*.pyc` in `collect_files`. Until then the honest
  statement is: same-tree builds are deterministic; clean-tree vs
  test-run-tree builds are NOT byte-identical.
- **CI for v0.2 + the 10k suite** (f17 P-05/P-06/P-07 in this
  module's scope): `.github/workflows/ci.yml` now has linux /
  windows / macos jobs (full unittest discovery, SBOM gates,
  zipapp build, artifact + hash upload), a `rebuild` job whose hash
  must equal the build hash, and a fail-closed `sign` job (see §5).
  It is still PREPARED, NEVER RUN: the repository is public but only
  `README.md` is on its pushed branch, this workflow is not, and
  `gh run list` returns zero runs — so no run is
  claimed, and the signing job deliberately fails until a protected
  environment with two approvers exists in repository settings.
- **Still NOT closed in v0.2** (see §9 for the full list): no
  hash-pinned lockfile (exact pins, not artifact hashes); no
  vulnerability scan executed or named as a gate; no 14-day
  quarantine enforcement (rule recorded, no date arithmetic in any
  gate — a new version's age is not checked mechanically); action
  SHAs not pinned (none invented); no independently-sourced
  toolchain rebuild; no updater/TUF design (no updater exists);
  solo-mode release authorisation still undecided (deputy vs
  cooling-off); installer reproducibility unproven (no installer
  is built in v0.2 — the zipapp is the only artifact).

## 1. Pinned dependencies — policy

- Exactly two direct external dependencies are allowed in v0.1
  (CONTRACT §1). Everything else is Python 3.12 stdlib.
- Pins are exact (`==`), in `requirements.txt`, and were recorded from
  versions actually installed in a local `.venv` — not copied from a
  plan, a README, or another machine.

| Direct dependency | Pinned version (installed) | Licence (from installed metadata) | Use |
| --- | --- | --- | --- |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | AES-256-GCM |
| argon2-cffi | 25.1.0 | MIT | Argon2id |

- A build that installs a different version of either pinned dependency
  fails `scripts/sbom.py` and `scripts/repro_check.py`; it does not
  silently proceed. Never substitute a weaker library or a home-made
  cipher/KDF if a pinned dependency cannot be installed — the vault
  fails closed and the failure is reported.
- Adding a dependency requires a CONTRACT amendment plus a written
  adoption record in `docs/dependency-decisions/<name>.md`, in the
  same change. This is now a MECHANICAL gate in v0.2, not policy
  only: `scripts/sbom.py` refuses any requirements file that does
  not contain exactly the two allowed direct dependencies, and
  `scripts/sbom.py --diff` (run by CI against the committed SBOM)
  fails on any component change. The record alone never authorises
  a new dependency — the CONTRACT amendment does, and the diff is
  what makes a silent change visible. A licence change in a later
  version is treated like a new dependency (the diff fails on it).

### Transitive closure — the honest count

Pinning two direct dependencies does **not** mean only two packages are
installed. The installed closure at generation time was:

| Package | Version | Scope | Licence |
| --- | --- | --- | --- |
| cryptography | 50.0.2 | direct | Apache-2.0 OR BSD-3-Clause |
| argon2-cffi | 25.1.0 | direct | MIT |
| argon2-cffi-bindings | 26.1.0 | transitive (via argon2-cffi) | MIT |
| cffi | 2.1.1 | transitive (via cryptography) | MIT-0 |
| pycparser | 3.12 | transitive (via cffi) | BSD-3-Clause |

So: 2 direct, 3 transitive, 5 installed packages in total. The SBOM
lists all five, marked direct/transitive. Any future change to this
closure — including a transitive change caused by a minor bump — is a
review-triggering event, because a transitive package inside the vault
or proxy tree runs with that component's privileges. Licence
compatibility is a legal gate only: a permissive licence is **not**
evidence that a package is safe, and a licence change in a later
version must be treated like a new dependency.

## 2. Vendoring stance for v0.1: none vendored

No dependency is vendored in v0.1 — there is no `vendor/` tree, and
the SBOM source inventory (regenerated per build) would show one if
it appeared. Reasons, stated so they can be challenged:

- The closure is tiny (5 packages). Vendoring would buy little
  isolation and cost the known failure mode: vendored code goes stale,
  accumulates CVEs, and diverges from upstream through local patches.
- The two direct dependencies are mature, widely used crypto
  libraries; deliberately updating them via a reviewed pin bump keeps
  the tree auditable without a fork to maintain.
- This stance is for v0.1 only. If the closure grows, or if a future
  audit requires vendoring a security-critical dependency, that
  decision gets its own record with a watch schedule (weekly upstream
  CVE check), an update SLA, and a divergence rule (local patches
  recorded with a reason and an expiry, or submitted upstream).
  Until then, "vendored" must never be claimed.

## 3. SBOM — how it is made, and what it does not prove

Generate it; never hand-write it:

```sh
python3 scripts/sbom.py          # writes sbom.json in the build root
python3 scripts/repro_check.py   # verifies pins, SBOM agreement, determinism
```

`scripts/sbom.py` builds a CycloneDX-style JSON document from three
real inputs: `requirements.txt`, the installed environment (the build
root's `.venv` if present, else the running interpreter), and the
actual source tree (file paths + SHA-256, excluding `.venv`,
`__pycache__`, `.git`, build outputs, and the SBOM file itself).
It fails if a pinned dependency is missing or installed at a
different version, and it refuses any requirements file that does not
contain exactly the two allowed direct dependencies. In v0.2 it
also records a `build_time` section (installer-tool versions +
SHA-256 of every file under `scripts/`) and supports
`--diff BASELINE`: a fresh SBOM is compared against the committed
one, and any component add/remove/version/licence change exits 2.
CI runs the diff on every job, so the committed SBOM is the
baseline a dependency change must visibly move.

Provenance honesty — what the SBOM does **not** prove:

- It does not prove a dependency is safe, backdoor-free, or
  vulnerability-free. It is an inventory, not an audit.
- It does not prove a built artifact matches this source. That needs
  a reproducible build plus an independent rebuild, neither of which
  exists as a release process in v0.1 (see §4 and §7).
- It does not prove a release was authorised. A valid SBOM, and later
  a valid Sigstore attestation, can exist for a rogue release built
  by the genuine pipeline from an unauthorised tag. Authorisation is
  a separate record (who proposed, who approved, what hash), and it
  does not exist in v0.1.
- It is a snapshot. Other workers' code was still landing while this
  SBOM was generated, so its source-file inventory is true only for
  the tree at generation time. Regenerate it for every build; never
  ship a stale SBOM as if it described the shipped tree.

## 4. Reproducibility — what is checkable here

`scripts/repro_check.py` verifies, on this machine:

1. **Deterministic zipapp build.** Two builds of the same tree with
   the same epoch are byte-identical; zip entries are sorted;
   every entry timestamp equals the epoch; no entry path is absolute
   or escapes the tree. In v0.2 this is additionally proven
   THROUGH the real packaging script (`scripts/make_zipapp.py`,
   invoked not modified): two same-epoch builds of the real tree
   are byte-identical with every entry timestamp == the epoch,
   and a cold-cache build from a fresh copy of the tree (no
   `__pycache__`) must match — currently FAILing on the pycache
   defect documented in §9/§0, which is reported, not hidden.
2. **No absolute paths embedded.** The build-root path string must not
   appear in the zip bytes.
3. **Requirements consistency.** `requirements.txt` holds exactly the
   two allowed dependencies, each installed at exactly its pinned
   version, and the SBOM (if present) agrees on those pins.
4. **Secret scan.** No secret-shaped string in the SBOM or in the
   build outputs. The scanner exempts `TEST-ONLY-` fixtures and is
   self-tested with a synthetic sample constructed at runtime — no
   real key is ever used, and no real-shaped credential literal is
   stored in the scripts.

`SOURCE_DATE_EPOCH` handling: if the environment sets it, the check
uses it; otherwise it uses an explicit test epoch and says so in its
output. For a real release, the epoch must come from the **signed
tag's timestamp**, not from a git commit timestamp — commit
timestamps are committer-controlled and a moved tag changes them.
That release rule is recorded here; it is not exercised by any local
build in v0.1.

What is **not** claimed: installer reproducibility. No installer is
built in v0.1, and the old blanket carve-out ("installers need not be
reproducible") is not accepted — when installers are built, they get
their own determinism statement (deterministic DMG/NSIS builds,
`SOURCE_DATE_EPOCH` carried through packaging, maintainer scripts
hash-covered and reviewed), or the non-reproducible component is
named explicitly with a compensating control. Nothing in v0.1
pre-judges that.

## 5. Signing prep — prepared, NOT executed

No signing has been performed for v0.2. No keys have been generated,
no signatures have been made, no identity has been claimed, and no
artifact has been published. The `sign` job in
`.github/workflows/ci.yml` is the prepared form of this section, and
it is hardened as follows (f16 punch 13, f16-S1/S2):

- It runs in the `signing` environment, which MUST have two required
  human reviewers, allowed-tag rules, and a wait timer configured in
  repository settings. Those rules cannot be expressed in YAML; this
  file alone does not enforce two-person approval, and anyone who
  claims otherwise is wrong.
- It has NO source checkout step: it downloads only the build and
  rebuild artifacts and runs a pre-sign validation checklist in
  code — build hash == rebuild hash, fresh SBOM components ==
  committed SBOM components — before any signing step could ever
  be added. Mismatch = halt, never sign.
- Its final step deliberately FAILS ("signing not configured")
  until signing keys, the protected environment, and a release
  record exist. A prepared job that cannot sign is honest; a
  prepared job that pretends to sign would not be.
- Signature verification by a separate job before publishing is
  still open (no signature exists to verify).

The following is the workflow to be used for a future release,
prepared in advance so a release does not have to invent it under
pressure:

1. Build twice, on independent runners, from the same signed tag;
   hashes must match before anything is signed.
2. The signing job verifies the artifact hash against the hash
   attested by the independent rebuild job (delivered via a separate
   channel, not a value the build job wrote) **before** signing.
   Mismatch = halt + incident, never sign.
3. Sign with Sigstore keyless signing, and publish one signed
   statement binding tag, unsigned hash, signed artifact hash, and
   signer identity together — not two adjacent hashes on a page.
4. The release publishes an authorisation record alongside the
   attestation: proposer, approver, approval timestamp, artifact
   hash, provenance reference. A valid attestation means the genuine
   pipeline built this artifact from this tag. It does **not** mean
   the tag was authorised — verifiers must check the authorisation
   record too.
5. Platform-certificate revocation blocks **new installs and first
   launches only**; it does not disable already-installed copies.
   It must never be listed as a containment step for installed
   users on its own — that needs the update channel plus the
   degraded-safe mode in §6, once those exist.

## 6. Verification-command rule — exact identity, never a regex

This rule is release-blocking for any future release documentation,
and it is the correction to the v1 §18.6.3 defect (a published
command whose identity pattern accepted any workflow in the repo —
the exact thing §12.8.3 forbids):

- A published verification command must pin the **exact identity**:
  the exact workflow file path **and** the exact release tag.
- Any identity expressed as a pattern/regex is forbidden, including
  patterns that merely add one path segment to a wildcard. If a
  command contains a pattern identity, it fails the release gate,
  however it is worded.
- A future CI check must verify that every published verification
  command satisfies this rule. That check does not exist in v0.1
  (no CI publishes verification commands yet); it must exist before
  the first release page does.

Example command that satisfies the rule — for future releases only,
with placeholders (the real organisation/repository are not known to
this local build and must never be invented here):

```sh
cosign verify \
  --certificate-identity 'https://github.com/<org>/<repo>/.github/workflows/release.yml@refs/tags/vX.Y.Z' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  <artifact>
```

Replace `<org>`, `<repo>`, and `vX.Y.Z` with the real values at
release time, and only then. Do not publish this command with
placeholders filled in by guessing.

## 7. Update architecture decision record (G0-17)

**Decision for v0.1: there is no auto-updater, and the TUF-lite
design is deferred to the updater slice — it is not implemented.**

- v0.1 has **NO auto-updater**. Updates are manual re-downloads by
  the user. There is no update check, no manifest, no staged rollout,
  no revoked-versions floor, and no degraded-safe mode in v0.1, and
  none of those must ever be claimed for v0.1.
- The G0-17 decision (TUF roles, or a documented TUF-lite: offline
  root with threshold signing, offline targets, a short-expiry
  timestamp role, a signed revoked-versions floor, and channel
  binding) is recorded as a **requirement on the updater slice**,
  to be decided **before the updater is written** — not as
  something v0.1 already does. A single update key with no role
  separation must not be built: stealing that one key would buy the
  whole fleet, and a 30-day manifest window would let a freeze
  attack hold users on a vulnerable version for a month.
- Likewise deferred with the updater: the update-check default, the
  solo-mode release authorisation mechanism (deputy with threshold
  approval, or cooling-off + public pre-announcement, enforced
  mechanically with no-bypass branch/tag rules), and the
  degraded-safe mode for revoked versions (refuse new sessions/key
  injection while preserving vault access and export — never a
  kill switch that locks users out of their own keys).
- Until the updater exists, the honest user-facing statement is:
  "v0.1 does not check for updates. Check for a new version yourself
  and re-download it manually." Any advisory path that assumes
  in-app update checks does not apply to v0.1.

## 8. Threat tiers for these controls

Supply-chain controls in this document are **release-integrity**
controls, not runtime isolation. They do not stop a Tier B attacker
(a shell-capable same-user process, or same-user malware) from
replacing installed files on the user's machine — file permissions
and SBOMs are not Tier B evidence, and must never be cited as such.
What they do is let a verifier check, for a future release, whether
the artifact they downloaded is the artifact the genuine pipeline
built from the stated source, and whether its dependency inventory
matches the pinned list. Same-user malware and a compromised OS
account are out of scope by design; this document does not imply
otherwise.

## 9. Known gaps (v0.2, to be closed before any public release)

- **Cold-cache defect (OPEN, W20-owned):**
  `scripts/make_zipapp.py` bundles `sealvra/__pycache__/*.pyc`
  into the zipapp, so a build from a test-run tree differs from a
  build from a fresh copy (23 extra entries measured in v0.2).
  `scripts/repro_check.py` reports this as FAIL
  `packaging-cold-cache` with the diagnosis; it is not waived or
  worked around here. Fix: exclude `__pycache__`/`*.pyc` in
  `make_zipapp.py`'s `collect_files`.
- No hash-pinned lockfile: pins are exact versions, not artifact
  hashes. A pinned version that is itself compromised is frozen in
  place until a human notices. The 14-day quarantine rule for new
  non-security versions is recorded (§1) but NOT mechanically
  enforced — no gate checks a version's age — and registry-signal
  monitoring still has no named owner and no SLA.
- No vulnerability scan has been run as part of this module (no
  scanner is named or executed in v0.2); a scan gate (Critical =
  no exceptions, ever; High exceptions need a named security
  owner, ≤14-day expiry, and a public record) is a release
  requirement, not a v0.2 claim. The shipped/dev distinction for
  the gate is the SBOM scope field (direct/transitive vs
  build-time), which is now recorded.
- Build-time enforcement is partial: build scripts are inventoried
  with hashes in the SBOM (`build_time` section) but there is no
  allowlist gate that refuses an unlisted build script, and a
  compromised wheel's install-time code is not sandboxed. The
  mitigation in v0.2 is the tiny closure (2 direct wheels) plus
  the inventory; it is not a sandbox claim.
- CI gates now exist in this module's scope (dependency gate, SBOM
  diff, cold-cache pip installs, rebuild hash comparison,
  fail-closed signing job), but the workflow has NEVER RUN: it is not
  on the remote's pushed branch (`gh run list` returns zero runs), and
  the verification-command check (every
  published command must pin the exact workflow + tag identity, §6)
  still has no CI implementation because no release page publishes
  commands yet.
- Action pinning (F16-C7) is done locally: every `uses:` in
  `.github/workflows/ci.yml` names a full commit SHA, not a movable
  tag. The SHAs below were read on 2026-10-28 from the public GitHub
  References API **on the Mac** (not from a CI run — the workflow has
  never run), each confirmed `type=commit` and confirmed to also carry
  the patch tag named:

  | Action | Pinned commit SHA | Tag it names | Patch release |
  |---|---|---|---|
  | `actions/checkout` | `11d5960a326750d5838078e36cf38b85af677262` | `v4` | v4.4.0 |
  | `actions/setup-python` | `a26af69be951a213d495a4c3e4e4022e16d87065` | `v5` | v5.6.0 |
  | `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` | `v4` | v4.6.2 |
  | `actions/download-artifact` | `d3f86a106a0bac45b974a628896c90dbdf5c8093` | `v4` | v4.3.0 |

  Re-check command (must be run again by a human before the first real
  run, and the YAML re-validated; local validation used
  `/usr/bin/ruby -ryaml` because PyYAML is not installed in the build
  venv, so the two `test_ci_yaml_*` tests skip as NOT-RUN on this
  machine):

  ```sh
  gh api repos/actions/checkout/git/ref/tags/v4 --jq '.object.type + " " + .object.sha'
  ```

  Drift, stated rather than hidden: these are the heads of the **v4/v5
  lines**, not the current upstream majors, which on the same date were
  `checkout v7` = `3d3c42e5aac5ba805825da76410c181273ba90b1`,
  `setup-python v7` = `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0`,
  `upload-artifact v7` = `cf430e030ddbb5b0abf93d22962f4752f3646cd9`,
  `download-artifact v8` = `9000827ccba6bdab643e8b6fd33ac0654aef8333`.
  A major-line bump changes artifact retention and runner behaviour, so
  it is an owner decision, not a mechanical edit. Pinning is a
  supply-chain hygiene step only; it does not make this workflow
  release-ready, because the signing job is still fail-closed and no
  run exists.
- No provenance, attestation, or authorisation record exists in
  v0.2 (§5 is preparation only). No independently-sourced-toolchain
  rebuild exists; the CI `rebuild` job is a same-pipeline
  determinism check, not independence evidence, and SLSA L3 must
  not be claimed from it.
- No updater exists in v0.2, so the TUF-lite decision, the
  update-check default, and the degraded-safe mode remain G0
  decisions for the updater slice (§7), and solo-mode release
  authorisation (deputy vs cooling-off + pre-announcement) is
  still undecided. Installer reproducibility is unproven because
  no installer is built in v0.2 — the zipapp is the only artifact,
  and `SOURCE_DATE_EPOCH` is carried through it (see §4), not yet
  through any DMG/NSIS packaging.
- The SBOM is a snapshot of a tree that is still changing; regenerate it
  after all workers land code and re-run `scripts/sbom.py --diff sbom.json
  --output sbom.fresh.json` (the form CI uses) before any release claim.
  Running it without `--output` is a trap, not a check: the default
  output is `<root>/sbom.json`, so the script rewrites the baseline it is
  then asked to compare against and can only ever print PASS. CI
  (`ci.yml`, the "Release gates" steps) and
  `tests/test_w20_packaging.py::test_sbom_diff_vs_committed_passes` both
  pass `--output` to a separate path and are therefore not affected.
- No keys, real or otherwise, were used or generated anywhere in
  this module. Test fixtures elsewhere in the tree use `TEST-ONLY-`
  markers only; the secret scanner in `scripts/repro_check.py`
  exempts exactly that marker.
