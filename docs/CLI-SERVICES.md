# CLI → Daemon → Proxy Services

This file documents which `sealvra` commands require a running daemon and which can run standalone.

## Service boundary: IPC-first, fallback-second

All session commands route through daemon IPC when a daemon is running. Without a daemon, they fall back to the process-local sessions module. This design ensures cross-process isolation but exposes an implementation gap: the fallback-only branch lacks full command support (see §"Known limitation").

## Commands and their service requirements

| Command | Requires daemon? | Fallback works? | Notes |
|---|---|---|---|
| `sealvra --help` | No | Yes | Help text |
| `sealvra daemon start` | No | N/A | Starts the daemon |
| `sealvra daemon status` | No | Yes | Reports existing daemon |
| `sealvra daemon stop` | No | Yes | Stops the daemon |
| `sealvra keys add` | No | Yes | Vault operation |
| `sealvra keys list` | No | Yes | Vault operation |
| `sealvra keys show <id>` | No | Yes | Vault operation |
| `sealvra keys reveal <id>` | No | No | Rejected with KH-2001 |
| `sealvra keys rotate <id>` | No | Yes | Vault operation |
| `sealvra keys mark-compromised <id>` | Partly | Yes (blocked, not killed) | Flags the vault record always; kills live sessions only when the session backend is reachable — see §"Compromise workflow" |
| `sealvra sessions create <key-id>` | **IPC** | **No** | Fallback rejects with KH-1006 without vault |
| `sealvra sessions list` | **IPC** | **No** | Fallback rejects with KH-1006; see §"Known limitation" |
| `sealvra sessions kill <session-id>` | **IPC** | **No** | Fallback stub does not implement this |
| `sealvra sessions kill-all` | **IPC** | **No** | Fallback stub does not implement this |
| `sealvra audit verify` | No | Yes | Reads log file |
| `sealvra audit export` | No | Yes | Reads log file |
| `sealvra doctor` | No | Yes | Health check |
| `sealvra prove-isolation` | No | Yes | Exits 3 KH-3002 (measured); broker interfaces missing |

## v0.2 Known limitation: non-daemon fallback gaps

Command: `sealvra sessions list` with no daemon running.  
Result: exit 1, error KH-1006: backend error: module 'sealvra.sessions' has no attribute 'list_sessions'.

The same failure applies to `sessions create`, `kill`, and `kill-all` in a no-daemon environment because these commands exist only as methods on `SessionStore` (sealvra/sessions.py:640+) and are invoked via IPC from the daemon. The CLI stubs in tests.test_w10_cli provide fake implementations for unit testing.

This limitation is measured, documented, and priced as a needs-owner decision: wire `sealvra.sessions` to a SessionStore or provide module-level proxies matching the CLI's call shape; keep IPC-first, fallback-second policy but ensure the fallback actually implements all commands listed here.

## Compromise workflow (`keys mark-compromised`, v0.2 Phase 0)

`sealvra keys mark-compromised <key-id>` is the owner-reported-leak path.
It does three things, and the order is deliberate:

1. **Flags the vault record.** `compromised: True` is written into the
   compartment's authenticated AEAD header, the same place the rotation gate
   lives, because the session layer makes a security decision with it and an
   unverified plaintext field may never drive one. The flag is preserved
   through `keys rotate`, so rotating a leaked key does not revive it; only
   `keys delete` removes it.
2. **Kills live sessions bound to that key.** This needs the session
   backend. With a daemon running the kills go over IPC; without one,
   `sealvra.sessions` exposes no `list_sessions()` (§"Known limitation"), so
   the command prints that sessions could not be enumerated and exits 0
   anyway. The block is what must never fail, so it is written first and the
   kill step cannot abort it. A session already minted before that failure
   stays alive until it expires.
3. **Posts a macOS notification** via `osascript` (`display notification`),
   on darwin only, best-effort. The message is passed as an `argv` element
   rather than spliced into AppleScript source: the display name is
   user-chosen text, and interpolating it would let one quote character run
   arbitrary script.

**Audit.** `audit.EVENT_TYPES` is a closed vocabulary with no
`key_compromised` member, and there is no free-text event field. This command
therefore does not mint a new event type; adding one is a CONTRACT change, not
a CLI one. The sessions it kills are recorded as `session_kill` by the kill
path that performs them, and the durable record of the compromise itself is
the authenticated header flag.

**Not yet closed:** the refusal reaches `sessions create` through the CLI's
own gate and the daemon's `needs_rotation` check. The daemon refuses safely
for a compromised key but still prints the generic NOT YET ROTATED wording,
because it tests `needs_rotation` rather than the new flag. Same outcome,
worse advice — owner call on whether to change `daemon.py`.

## How sessions work over IPC

1. `sessions.create(key-id, ...)` → daemon creates session in `Broker` → returns token + PoP key (hex) for test mode
2. `sessions.list()` → daemon reads all live + terminated sessions from `Broker` → JSON array of `Session` objects
3. `sessions.kill(session-id)` → daemon terminates worker + sets `killed` flag → marks RECORD view as killed
4. `sessions.kill-all()` → daemon reaps all sessions for all keys

The daemon stores sessions in memory only: daemon death is session death. The rendezvous directory defaults to `~/.sealvra/daemon` unless `SEALVRA_DAEMON_DIR` is set. The socket path uses Unix-domain sockets with peer-UID authentication (`getpeereid` on macOS, `/proc/<pid>/peer` on Linux).

## Proven paths (end-to-end witnesses)

- `tests/test_e2e.py::RealPathTests`: 14/14 green on macOS 27.0.1 arm64, Python 3.12.13 (2026-10-31), loopback mocks only, TEST-ONLY keys.
- `/tmp/kh_e2e_proof_FINAL.txt`: 34-step chain proof (Phase 1 witness), CLI → daemon IPC → proxy → vault.
- `scripts/grep_gates.py`: PASS (120 hits, 0 failing), forbidden claims deleted.

## Not proven on macOS (yet)

- Keychain one-item-per-key storage (`test_macos_keychain_access_group_isolation` FAILS BY DESIGN)
- Touch ID gesture + confirm order (§6 E)
- Sandboxed XPC approver bundle (§6 F2)
- Signed DMG + Gatekeeper (§6 G)

These remain NOT-RUN until a Mac owner runs them with TEST-ONLY keys.

