# Keyholder v0.2 on Windows — honest status (W16)

Working title Keyholder. No standalone Windows executable is built or
claimed in v0.2. The distribution is the Python zipapp plus PowerShell
install/uninstall scripts (see "How a Windows user runs v0.2" below).
Anything in this document that has not actually run on Windows is
labelled NOT-RUN, never PASSED (CONTRACT §11).

## What changed in v0.2 (this worker's area only)

- The v0.1 supervisor blocker is CLOSED upstream (W01): `supervisor.py`
  now guards `start_new_session` behind `sys.platform != "win32"`,
  falls back to `pgid = pid` on Windows, and `terminate()` dispatches
  to `process.terminate()` (`terminate-win32`, escalating to
  `process.kill()` / `kill-win32` on timeout) instead of `killpg`.
  `windows_check.py` now exits 0 on this Linux host, and adds a
  MOCKED win32 kill run (sys.platform patched in-process, fake
  worker process) proving the branch dispatch — not a real Windows
  kill. What is still NOT proven: killing a worker's *children* on
  Windows (`_scan_children` is `/proc`-only and returns `[]` there,
  so `terminate()` kills the direct worker only) and the Windows
  job-object / process-tree kill, which is post-push work.
- The Remote Credential Guard + Hello PIN label warning is CLOSED:
  `platform.remote_session_tier` now returns a distinct T2
  remote-typed-PIN mechanism for Guard + PIN, never the biometric
  label and never T1.
- Two installer bugs found by static review (not by a Windows run)
  and fixed in this round: (1) the wipe receipt timestamp used
  `HH:mm:ss`, and `:` is illegal in Windows filenames, so receipt
  creation failed and aborted the wipe before any deletion;
  the format is now colon-free (`yyyy-MM-ddTHHmmssZ`). (2) The
  wipe path printed "deleted vault directory" without checking;
  it now verifies `Test-Path` after removal and warns if the
  directory is still present. `install.ps1` now also captures
  `python --version` from both streams and gives a friendly error
  when `python` is missing, instead of a bare
  CommandNotFoundException.
- New static coverage: `windows_check.py` W14–W18 (supervisor win32
  kill, verifier-helper paths, installer/uninstaller static
  correctness, zipapp host run, NSIS spec-only). PowerShell
  *parsing* is checked by `windows_check.py` only when `pwsh` is
  available; on this Linux VM `pwsh` is unavailable, so parsing is
  recorded as NOT-RUN, never claimed.

## The honest Windows statement (v3 §1N, f14)

On macOS, stored keys are additionally gated by per-application
Keychain ACLs. On Windows, stored keys are readable by any process
running as your user. Keyholder's approval tiers, Hello gestures, and
kill switch control what Keyholder itself does with your keys; they do
not stop another program running as you from reading them directly
from Credential Manager or the vault file.

Concretely, Windows storage is **S2 (user-scoped)**: DPAPI's boundary
is the user account, not the application. Any same-user process can
call `CryptUnprotectData` with no prompt, no permission check, and no
per-app isolation, and `CredRead` has no per-app ACL. A Hello step-up
gates Keyholder-mediated use only — it does not "address" DPAPI. The
tiers (T1/T2/T3/T0) measure Keyholder's gates, not platform storage.
Per-record wrapping keys are broker-side accounting and audit
granularity on Windows, not OS-enforced gates. Same-user malware / a
compromised OS account is out of scope by design. Opaque Credential
Manager target names hide provider names from casual listing only;
anyone who can read the vault file maps identifiers to providers
trivially.

## What was checked here (Linux host, 2026-10-28)

Run `python scripts/windows_check.py` from the build root. On this
Linux VM it checks, without Windows (exit 0 in v0.2):

- Every Python file under `keyholder/`, `scripts/`, `tests/` compiles.
- No POSIX-only import or process-group API (`pwd`, `grp`, `fcntl`,
  `os.fork`, `os.killpg`, `os.getpgid`, `os.setsid`, `os.setpgid`) is
  used outside code gated to a non-Windows platform.
- `keyholder/platform.py` Windows branches branch on
  `sys.platform == 'win32'`; storage is S2 with same-user direct read;
  Hello biometric and Hello PIN are distinct mechanisms (PIN is
  `T1-pin`, harvestable by a lookalike dialog, never bare T1); the
  Windows password tier is split (boolean-only only via the isolated
  verifier-helper design, otherwise password-in-memory); the RDP row
  (consumer RDP effectively refused, Remote Credential Guard +
  biometric = T1 with badge, remote PIN at most T2, including
  Guard + PIN); TPM hardware/virtual/absent and domain-joined
  status never change S2.
- `keyholder/approval.py`'s Windows branch is DESIGN ONLY and
  requires the verifier helper; broker-window clicks may present or
  deny a destructive call, never approve it.
- The daemon falls back to a loopback TCP listener on `127.0.0.1`
  where `AF_UNIX` is unavailable (CONTRACT §4/§13.1: loopback only,
  never `0.0.0.0`). On Linux/Windows that control plane does NOT separate
  same-user processes (Tier B) — only macOS keychain access groups
  do that.
- Only `cryptography` and `argon2-cffi` are imported beyond the
  standard library; no executable artifact is present or claimed.
- W14 supervisor win32 kill: source inspection plus a MOCKED win32
  run (sys.platform patched, fake worker process) showing
  `terminate-win32` dispatch and `kill-win32` escalation. This
  proves branch logic only; a real Windows kill is NOT-RUN.
- W15 verifier-helper paths: gate logic (boolean-only helper design
  with CredUI + LogonUser, mlocked, zeroed; password-in-memory
  warning without it; Hello PIN never boolean-only; Guard + PIN =
  T2), an absence check proving no native DPAPI/CredUI binding
  (windll / Win32 API call site) exists in `keyholder/` — so nothing
  pretends to call the real APIs — and a MOCKED boolean-only
  boundary simulation (fake helper returns bool; broker receives
  bool only, never the password string).
- W16 installer/uninstaller static correctness (text-level, NOT a
  parse): param blocks, vault preservation by default, wipe gate
  ordering (ConfirmWipe gate before any removal, typed WIPE before
  vault removal, receipt outside the vault, colon-free timestamp,
  deletion verified after removal), launcher resolving the zipapp
  relative to itself, Python-version handling, no network cmdlets,
  no admin elevation. PowerShell parsing itself is NOT-RUN here:
  `pwsh` is unavailable on this Linux VM, and `windows_check.py`
  reports W16-ps-parse as NOT-RUN in that case.
- W17 zipapp host run: `dist/keyholder.pyz` is a valid zip with
  `__main__.py` and `--help` exits 0 under this Linux host's
  CPython. That proves the zipapp artifact, not Windows Python.
- W18 NSIS spec-only: no `.nsi` file and no installer binary exist.

These are gate-logic, static, and mocked checks run on Linux. They
prove the logic, not native Windows behaviour. Every mocked check
says MOCKED in its detail line.

## Remaining gaps (not blockers for the Linux-host check, open for a real Windows run)

- Windows supervisor process-tree / job-object kill: `terminate()`
  kills the direct worker only on Windows; worker children are not
  covered (`_scan_children` is `/proc`-only). A Windows test must
  spawn a worker with a child process, kill the session, and verify
  both are gone within 5 s.
- Windows worker orphan self-termination: the worker polls its
  supervisor PID with `os.kill(pid, 0)`; whether that behaves as
  intended on Windows (where `os.kill` semantics differ) is
  unverified and must be tested on a real Windows host, not assumed.
- The verifier helper is still a design, not a built process. Until
  it exists, Windows destructive approval is not runnable from the
  approval module, and Windows password approvals remain
  password-in-memory with the warning displayed.
- `install.ps1` / `uninstall.ps1` have never been parsed by
  `pwsh` (unavailable here) nor run on Windows; the static checks
  above are not a substitute for either.

## What was NOT run on Windows (NOT-RUN, never PASSED)

- Real DPAPI / Credential Manager encryption and decryption.
- Real Windows Hello biometric gestures and Hello PIN entry.
- `CredUIPromptForWindowsCredentials` (which returns the password to
  the calling application by API design — hence the isolated
  verifier-helper design: the helper alone calls CredUI and verifies
  via `LogonUser`, zeroes the password immediately, and returns only
  a boolean to the broker. **The helper is a design in v0.2, not a
  built process.** Without it, Windows password approvals are
  password-in-memory and must be displayed with that warning; they
  are not equivalent to boolean-only T2. Until the helper exists,
  Windows destructive approval is not runnable from the approval
  module — see `platform_tier_for(platform="win32")`.
- Remote Credential Guard on a domain-joined machine.
- Running `scripts/install.ps1` or `scripts/uninstall.ps1`.
- PowerShell parsing of `install.ps1` / `uninstall.ps1` (`pwsh`
  unavailable on this Linux VM; `windows_check.py` W16-ps-parse
  is NOT-RUN here).
- Running the zipapp under Windows Python (the Linux-host `--help`
  run in W17 is not evidence for Windows Python).
- Windows supervisor process-tree / job-object kill for worker
  children, and Windows worker orphan self-termination.
- Windows daemon control-plane TCP fallback at runtime (source
  shows the `127.0.0.1` AF_INET fallback; no Windows runtime run).
- `SendInput` injection against a broker-window destructive prompt
  (a broker-window click must never approve a destructive call;
  approval is a fresh system gesture bound to the exact call
  fingerprint).
- Any NSIS installer build or run (spec only — see below).
- Screen-sharing / capture detection on Windows: no detection is
  claimed. Approval and reveal windows never contain secret values,
  and a standing reminder to close screen sharing before approving
  destructive actions is shown instead.
- Remote-access coverage beyond RDP: `SM_REMOTESESSION` detects
  Microsoft RDP only. VNC, TeamViewer, AnyDesk, Parsec, SSH with X
  forwarding, and IPMI/KVM are NOT detected and look local to
  Keyholder. Do not approve destructive actions while any
  remote-access tool is running. Remote state is re-probed at every
  approval, not once at daemon start.

## How a Windows user runs v0.2

Prerequisites: Python 3.12 and the two pinned dependencies from
`requirements.txt` (`cryptography`, `argon2-cffi`). They are NOT
bundled in the zipapp; if they are missing, `install.ps1` warns and
does not silently substitute anything.

1. Build (on any machine): `python scripts/make_zipapp.py` produces
   `dist/keyholder.pyz`. The file is a zipapp, not a standalone
   executable — it needs Python on the target machine.
2. Install (PowerShell, from the build root):
   `powershell -ExecutionPolicy Bypass -File scripts\install.ps1`
   This copies `keyholder.pyz` to `%LOCALAPPDATA%\Keyholder\` and
   writes a launcher at `%LOCALAPPDATA%\Keyholder\bin\keyholder.cmd`.
   Add that `bin` directory to `PATH`, then run `keyholder --help`.
   The vault directory defaults to
   `%LOCALAPPDATA%\Keyholder\vault` (or `%KEYHOLDER_HOME%` when set).
3. Run: `keyholder daemon start`, then the usual CLI surface
   (`keys add|list|show|delete|rotate`, `sessions list|create|kill`,
   `audit verify|export`, `doctor`, `prove-isolation`). There is no
   `keys reveal`, no `--show-token`, no `sessions approve`, and no
   `sessions extend` on any platform.
4. Control plane on Windows: loopback TCP on `127.0.0.1` with an
   ephemeral port (the Unix-socket path is unavailable). It is
   loopback only and does not separate same-user processes.

Out of scope for session minting in v0.2: WSL, containers, and
ChromeOS Linux (kill/list only, with an explanatory refusal). A
Linux build run inside WSL is not the Windows build, and the Windows
build outside WSL cannot see into it.

## Windows packaging notes

### Program and data are separate

- Program: `%LOCALAPPDATA%\Keyholder\keyholder.pyz` plus
  `%LOCALAPPDATA%\Keyholder\bin\keyholder.cmd`.
- Data: the vault directory (default above). Reinstalling replaces
  the program files only; if the vault directory already exists its
  contents are left exactly as they are, and data carries over
  across reinstalls. That separation is what makes the uninstall
  rule below safe to state simply.

### NSIS shape (spec only — not executed, no installer built)

A future NSIS installer for v0.2 must follow this shape and no other:

- Per-user install, no administrator rights required; program files
  go to the per-user program directory above, data stays in the
  vault directory, and the two are never merged.
- The installer checks for Python 3.12 and the two dependencies and
  stops with a plain error if they are missing, rather than bundling
  a runtime or substituting a weaker dependency.
- The installer creates the vault directory only if it does not
  already exist, and never deletes, moves, or overwrites existing
  vault contents on install, repair, or upgrade.
- The uninstaller removes the program only (see the next section).
  No NSIS script has been run and no installer binary exists in
  v0.2; do not distribute or link one until the post-push CI steps
  below have actually run on a Windows runner.

### Uninstall behaviour

Uninstalling removes the program only. Vault data, platform-keychain
items, and audit data are NOT deleted by default. Deleting data
requires the separate, explicitly confirmed wipe path
(`-WipeData -ConfirmWipe` plus typing `WIPE` at the prompt), which
first writes a pre-wipe audit record both to the vault audit log and
to a wipe-receipt file outside the vault, so evidence of the wipe
survives the wipe itself. Wiping the local vault does NOT revoke
provider-side keys — revoking or rotating keys at GitHub / Gemini is
a separate user step, and keychain cleanup, if any items exist, is a
manual step the wipe script prints rather than claims to perform.
Reinstalling after a default uninstall picks the preserved data
back up.

## Exact post-push CI steps that will prove Windows

These steps have not run anywhere yet: no repository exists, so no
CI run is claimed. When a repository exists, the Windows job in
`.github/workflows/ci.yml` must, in order:

1. Check out, set up Python 3.12, install `requirements.txt`.
2. Run the full unit-test suite (`python -m unittest discover -s tests -v`).
3. Run `python scripts/windows_check.py` and require exit 0 (it
   exits 0 on the Linux host in v0.2; on the Windows runner it
   must also exit 0, and W16-ps-parse must report PASS there now
   that `pwsh` exists — a NOT-RUN parse on the Windows runner is
   a job failure, not a pass).
4. Parse-check both PowerShell scripts explicitly with
   `pwsh -NoProfile` (`Parser::ParseFile`, zero errors; run
   PSScriptAnalyzer too if it is available) — this is the check
   that cannot run on the Linux VM and must not be skipped.
5. Build the zipapp (`python scripts/make_zipapp.py`) and record its
   SHA-256, so later evidence binds to that exact artifact.
6. On the Windows runner itself (this is the part no Linux-host
   check can replace): run `install.ps1` into a temporary install
   root and vault directory, run `keyholder --help` and `keyholder
   doctor` from the installed launcher, run `uninstall.ps1` with
   default options and verify the vault directory is untouched, then
   run the wipe path in a throwaway directory and verify the receipt
   file survives and the vault directory is actually gone. Fake test
   keys only; no real keys on any runner.
7. On the Windows runner, run the supervisor kill test for real:
   spawn a session worker with a child process, kill the session,
   and verify worker and child are both gone within 5 s; kill the
   supervisor and verify the orphan worker self-terminates within
   5 s. Until this passes, the process-tree kill is unproven even
   though the direct-worker `terminate-win32` branch is mocked.
8. Only after steps 1–7 pass on a real Windows runner may any
   document claim a Windows behaviour as tested. DPAPI, Hello,
   CredUI, the verifier helper, and Remote Credential Guard each
   need their own dedicated runner test before they are claimed —
   a green zipapp build is not evidence for any of them.

## Interface agreed with W20 (make_zipapp.py)

W20 owns `scripts/make_zipapp.py`; W16 owns only its Windows section
in the sense of this document and `windows_check.py`. The agreed
interface, already present in `.github/workflows/ci.yml`, is:
the Windows job runs `python scripts/windows_check.py` from the
repository root, taking no arguments, exiting 0 on pass and non-zero
on failure, before building the zipapp. W16 has not edited
`make_zipapp.py` or `ci.yml`. The additional runner steps in the
previous section are supplied as a text block for W20 / the manager
to place in `ci.yml`; they are not yet in the workflow file.
