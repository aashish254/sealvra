# Sealvra v0.2 (draft) — user guide

> **v0.2 DRAFT.** This guide describes v0.1 behaviour as amended
> by the v0.2 slices (cross-process daemon IPC, real-approver wiring,
> pack signing, git helper + wrapper), measured 2026-10-28 on the
> Linux build VM and re-measured 2026-10-29 on macOS 27.0.1 arm64
> with Python 3.12.13. The CLI itself exists
> (`python3 -m sealvra --help` exits 0), the daemon
> start/status/stop cycle works across CLI invocations with an
> isolated daemon directory, and the CLI sessions commands
> (`create`/`list`/`kill`/`kill-all`) now route through daemon IPC
> while a daemon is running, falling back to the process-local
> session store when none is. That whole flow — CLI → daemon →
> proxy → mock, with a PoP-signed call, a kill, and an audit verify —
> is what `tests/test_e2e.py` Layer B runs end-to-end against built
> code (14/14 pass on macOS 2026-10-29, TEST-ONLY keys, loopback
> mocks). The git section of `docs/adapters.md`
> (W05) and the egress sections of `docs/security-model.md`
> (W17) are owned by other workers and are not rewritten here.

## Who this is for

One person, on one machine, who wants an AI coding agent to use a
GitHub or Gemini key without ever handing the agent the real key.
If you need team sharing, stop here — v0.1 has no company edition.

## Setup

1. Use Python 3.12. Create a virtual environment in the build root
   and install the two pinned dependencies from `requirements.txt`
   (`cryptography`, `argon2-cffi`). Nothing else is required.
2. Start the daemon: `sealvra daemon start`. Check it:
   `sealvra daemon status`. In v0.2 the daemon is a real
   separate process speaking newline-delimited JSON over a Unix
   socket (Linux/macOS) or loopback TCP (Windows) in a 0700
   directory — `$SEALVRA_DAEMON_DIR` if set, else
   `~/.sealvra/daemon` — with a 0600 socket and peer-UID
   authentication. That directory is GLOBAL by default: set a
   distinct `SEALVRA_DAEMON_DIR` per test run or per user
   context, or concurrent runs share one daemon. Daemon death
   means session death: sessions live in daemon memory only and
   are never resurrected on restart. IPC authentication is
   same-UID only and does NOT separate same-user processes
   (Tier B) — see the security model doc; no control token
   pretends otherwise.
3. Add your first key: `sealvra keys add`. Answer the import
   question honestly (see below). Prefer platform-keychain mode on
   macOS; on Linux and Windows, understand that storage is
   user-scoped (see the security model doc) before you proceed.
   Provider packs are now signature-verified on load
   (`packs/*.sig` + `packs/trusted_keys.json` +
   `packs/revoked.json`): a pack failing its content hash or its
   Ed25519 signature against a trusted, non-revoked key is
   refused, never loaded — see `packs/SIGNING.md`.

## Adding a key — the import question

You will be asked: "Was this key ever pasted anywhere?" Answering
"don't know" counts as yes. In either case, rotate the key at the
provider before the first session, and expect a permanent NOT YET
ROTATED warning on that key until rotation is recorded. A key pasted
into an agent chat may already live in a vendor cloud; Sealvra
cannot undo that, and adding the key here does not make the old
copies go away.

Give each key a label for your own detail pane. Labels never appear
in global audit entries — those use pseudonyms only.

## Creating a session

> **Re-measured 2026-10-29 on macOS (was a v0.2 gap).** At the
> 2026-10-28 snapshot the CLI sessions commands were not on daemon
> IPC and `sealvra sessions list` failed with KH-1006 ("module
> 'sealvra.sessions' has no attribute 'list_sessions'"). That is
> closed: `sessions create/list/kill/kill-all` now dispatch over
> daemon IPC when a daemon is running and fall back to the
> process-local store only when none is, and a CLI-created session
> **is** the daemon's session — the daemon binds it to a real vault
> compartment and refuses a key id whose authenticated record it
> cannot read. The flow is verified end-to-end against built code by
> `tests/test_e2e.py` Layer B (session created by the CLI, PoP-signed
> proxied calls, kill, audit verify — 14/14 pass here), and the
> daemon-IPC session path itself is covered by
> `tests/test_daemon_ipc.py` (`sessions.create` over IPC
> returns the token exactly once, never logged).
> One caveat that still holds: sessions live in daemon memory only —
> if the daemon dies, every session dies with it.

`sealvra sessions create` creates a session for exactly one key.
Choose:

- **Provider:** `github` or `gemini` only.
- **Session class:** `destructive`, `write`, `read_account`, or
  `read_public`. Pick the narrowest class that does the job.
  Destructive means it can delete or rewrite things; write covers
  non-destructive writes and paid inference; read_account reads
  account data; read_public reads public data only.
- **Transport:** `absolute` (default — full method/path/body policy)
  or `connect_allowed` (explicit opt-in only, labelled HOST-ONLY
  POLICY everywhere; never choose this for a write or destructive
  session, and never for a provider whose policy uses path/body
  rules).

Session creation needs two steps in order: an OS gesture (Touch ID /
Hello / polkit / system password UI) plus an explicit confirm. The
session token is shown exactly once, at creation. It is never logged,
never written to disk, and cannot be shown again. If you lose it
before handing it to the agent setup, create a new session.

Sessions are never extended. When one expires, or when you kill it,
make a new session with a fresh gesture. Idle timeout is 5 minutes
by default (2–15 minutes, cannot be disabled) and resets only on a
successful proxied call.

## Making a proxied call

Point the agent at the local proxy (default `127.0.0.1:8765`) and
give it the session token plus its per-request proof signature (or
use the wrapper/sidecar, which signs for agents that cannot sign
themselves). The agent never sees the real key. Sealvra checks the
session, checks the call against the provider pack, asks for approval
where the call is gated, writes the audit entry before forwarding,
then injects the real key and forwards the call.

Two v0.2 facts bound this section. First, the production
proxy approve callable is now the real broker-owned approver
(CONTRACT §13.2): a test approver is refused unless the
test-harness marker `SEALVRA_TEST_APPROVER` is set, so a
test double can never silently become the production path. Because
no OS approval gesture is implemented, that means a real level-3
call is denied — approval works in the harness, not yet for a user.
Second, the joined path is now proven end-to-end: the daemon serves
the proxy, `daemon status` names the bound port and both upstream
bases, and a CLI-created session can drive a PoP-signed proxied
call — which is what `tests/test_e2e.py` Layer B does, 14/14 on
macOS 2026-10-29. The PoP key leaves the daemon in one place only:
`SEALVRA_TEST_MODE=1` makes `sessions create` print it once next to
the token, for the test harness that must sign a request. In normal
mode the token is the only thing printed and nothing re-displays
either, which is why a production agent signs through the
wrapper/sidecar instead of holding the key from CLI output. The
proxy engine itself is also proven in-process against loopback
mocks (`tests/test_integration.py`).

For git work, use the wrapper, not a bare git client: see
`docs/adapters.md` (git section) for the helper + wrapper
contract and for what still bypasses it. A git client run
directly with standing credentials outside the wrapper/helper
is not logged and not gated — `sealvra doctor` inventories
standing git credentials (including `.git-credentials`) so you
can find them.

What the agent sees on denial is generic on purpose: no rule id, no
category. That detail lives in your audit log, not in the agent's
error message. If a call is denied, check the audit log rather than
asking the agent to guess why.

## Killing a session

`sealvra sessions kill <session-id>` blocks new calls within 1
second and tears the session down within 5 seconds. Calls already
sent run to completion and are listed on the kill receipt — read the
receipt; "killed" does not mean "undone". `sealvra sessions
kill-all` snapshots the session list at invocation; sessions created
during the sweep are listed, not silently included or excluded.
Kill needs no authentication, by design: in an emergency you must
not be locked out of killing by an approval prompt.

## Rotating, deleting, and backing up a key

- **Rotate:** `sealvra keys rotate`. Rotation kills live sessions
  for that key, and is crash-safe: if the machine dies mid-rotation,
  the recovery path must not leave the old key dead with no
  replacement recorded. (Verify this path in code before release.)
- **Delete:** `sealvra keys delete`. The deletion receipt states
  honestly what was deleted from the live vault and what backup
  copies you must still purge yourself — it does not claim that
  every copy everywhere is gone, because your own backups may retain
  one.
- **Back up:** export is per-compartment by default, needs
  interactive OS auth every time (control-socket auth alone is never
  enough), refuses a synced folder without a typed risk confirmation,
  and enforces a 24-hour cooldown between full-vault exports. Restore
  kills live sessions first.

## Checking the audit log

`sealvra audit verify` reports one of: OK; UNANCHORED (amber, exit
2); TAMPERED (exit 3); MISSING-DIRECTORY (exit 3). A missing log
directory is a failure, not a fresh start — a silently reborn log
would hide tampering. `sealvra audit export` exports the log for
your own review. Audit entries carry pseudonyms, never labels and
never key fragments; if you ever see a real key fragment in a log,
treat it as a KH-3003 secret-in-log failure (exit 3) and stop.

## The dashboard and the counter

The dashboard is read + kill only. It has no approve button and no
per-key browsing from the tray. The counter reads: "Times any key has
left this machine *since import*: 0 — counting only broker-observed
departures." Approved calls send the key to the provider; undetected
leaks would not increment the counter. Do not read the counter as
proof that no leak ever happened — it counts what the broker saw.

## What Sealvra will not do, even if asked

- Show a real key, copy a key to the clipboard, or print a session
  token after creation. There is no command for any of these.
- Extend a session, approve from the CLI or dashboard, or let a
  broker-window click approve a destructive call.
- Run a destructive session under X11 on Linux (refused).
- Forward a call that would mint a new credential to the agent. The
  only permitted flow is vault-native interception: the new
  credential goes into the vault, the agent gets a reference, never
  the value.
- Log a call it cannot audit: if the audit log cannot be written,
  the call is refused and the daemon does not run blind.
