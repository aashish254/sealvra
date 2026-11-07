# Sealvra v0.2 (draft) — troubleshooting

> **v0.2 DRAFT.** Error codes are the specified single catalogue from
> `CONTRACT.md` §9: the same event carries the same code on every
> surface. The CLI module now exists (`--help` exits 0; daemon
> start/status/stop work across invocations), and as of the 2026-10-29
> re-measurement on macOS the CLI sessions commands **are** routed
> through daemon IPC when a daemon is running (`create`/`list`/`kill`/
> `kill-all`), falling back to the process-local session store only when
> none is — the KH-1006 reported for `sessions list` at the
> 2026-10-28 snapshot is closed. Entries below that depend on CLI
> sessions are now verified behaviour, not specified-only.

## Error codes

| Code (exit) | Meaning | What to do |
|---|---|---|
| KH-1001 (1) | Vault locked | Unlock via the platform flow; note that unlocking never auto-resumes suspended sessions — create new sessions |
| KH-1002 (2) | Session not found, expired, or killed | Create a new session with a fresh approval gesture; sessions are never extended |
| KH-1003 (2) | Policy denied | The call is outside the session's scope or pack rules. Check the audit log (rule detail lives there, not in the agent's error). Do not widen scope by retrying; create a correctly scoped session instead |
| KH-1004 (2) | Approval denied or timed out | Timeout always means deny. Re-request the call; the 60-second clock (120 with the accessibility opt-in) starts at the system prompt |
| KH-1005 (3) | Audit unavailable | Stop. The daemon refuses new calls rather than running blind. Fix the log (disk space, permissions, directory) before retrying |
| KH-1006 (1) | Provider/upstream error | The provider side failed. Check the provider status and your provider-side key state; Sealvra cannot revoke or repair a provider key |
| KH-2001 (1) | Invalid input or usage | Check the command syntax (`--help`); check that provider, class, and transport values are exactly the specified strings |
| KH-3001 (1) | Platform unsupported for this action | The action is not available on this platform (for example, a destructive session under X11, which is refused) |
| KH-3002 (3) | Isolation/proof failure | A failed `prove-isolation` result. Treat as a real failure, not a routine denial; do not work around it by using the key directly |
| KH-3003 (3) | Secret detected in log | A real key fragment was found where it must never appear. Stop, treat the log as contaminated, rotate the affected key at the provider, and do not forward the log anywhere |

## Common situations

**"My session stopped working after a few minutes."**
Likely the 5-minute idle timeout (reset only by a successful proxied
call), a TTL expiry, or a screen-lock suspension (sessions are killed
after 15 minutes locked). All three are by design. Create a new
session; none of them is extended.

**"The agent says denied but won't say why."**
By design. Denials to the agent are generic; rule detail is in your
audit log only, so a denied agent cannot probe the rules. Look the
call up in the audit log by session pseudonym and canonical path.

**"Audit verify says UNANCHORED."**
Amber, exit 2. The chain is not anchored where verification expected
it to be. Do not ignore it and do not delete the log to "fix" it —
a reborn log is itself a TAMPERED/MISSING-DIRECTORY failure. Keep the
log intact and investigate what changed.

**"Audit verify says TAMPERED or MISSING-DIRECTORY."**
Exit 3. Stop using sessions that depend on that log's integrity
story, preserve the log directory exactly as it is, and rotate keys
whose recent history you can no longer trust the log to account for.

**"A git push didn't appear in the audit log."**
Expected unless the push ran through the wrapper: v0.2 logs and
gates wrapper-run push/pull/fetch (`sealvra/git.py` +
`scripts/git-credential-helper`), but a git client run directly
with standing credentials outside the wrapper/helper is NOT
logged and NOT gated, and no Sealvra git proxy exists yet —
so a direct-client push never appears in the log. Do not treat
the absence of a push from the log as proof that no push
happened. Run `sealvra doctor` to inventory standing git
credentials, and use API-only sessions for path-bound templates
(see `docs/adapters.md`, git section).

**"A provider pack is refused as unsigned."**
Expected since the v0.2 signing flip: the loader verifies BOTH
the content hash AND the Ed25519 signature against a trusted,
non-revoked key, and refuses a pack failing either — there is
no fallback to an unsigned or hash-only pack, and a missing
`trusted_keys.json` or `revoked.json` also refuses the load.
Re-sign with `scripts/sign_pack.py` (sign only after the pack
hash is finalised) and verify with `sign_pack.py verify`; never
put a private signing key in the tree. Test packs use their own
test key under `tests/` fixtures, never in `packs/`.

**"Daemon start says 'already running' but I started nothing."**
The daemon rendezvous is global by default
(`~/.sealvra/daemon`): another run — or a previous test run —
already owns it. Either use that daemon (`daemon status`
shows its pid) or set a distinct `SEALVRA_DAEMON_DIR` for
your run before starting. Never stop a daemon you did not
start without checking whose sessions it holds: `daemon stop`
kills its workers and ends its sessions.

**"Sessions list fails with KH-1006."**
This was the known v0.2 gap at the 2026-10-28 snapshot (CLI sessions not
on daemon IPC). It is closed and re-measured on macOS on 2026-10-29:
`sessions create/list/kill/kill-all` go through daemon IPC while a daemon
is running, and `tests/test_e2e.py` Layer B exercises exactly that flow.
If you see KH-1006 from a sessions command now, read it as what §9 says
it means — a provider/upstream error, e.g. the daemon could not read the
key's authenticated vault record — not as the old routing gap. Check
`daemon status` (it names the proxy port and both upstream bases) and
`keys list`; do not work around it by using a key directly.

**"I killed the session but the effect still happened."**
Expected for calls already forwarded before the kill: they run to
completion and are listed on the kill receipt. Also check
provider-side artifacts (webhooks, deploy keys, collaborator invites)
created during the session — kill does not revoke those; inventory
and revoke them at the provider.

**"The counter says 0 but I approved calls."**
The counter counts broker-observed departures *since import*, and its
wording says so. Approved calls do send the key to the provider in
the call header — that is the approved job. The counter is not proof
that no undetected leak ever happened.

**"Sealvra won't run a destructive session on my Linux desktop."**
If the session is X11, destructive sessions are refused outright.
Use a Wayland session for destructive work, or restrict the X11
session to read-only with its badge understood.

**"I pasted this key into an agent chat before. Is it safe now?"**
No. Adding it to Sealvra does not un-expose the pasted copy.
Rotate it at the provider before the first session, and keep the
NOT YET ROTATED warning until rotation is recorded.

**"The daemon refuses new calls and mentions the audit log."**
Audit failure means refuse, everywhere. The daemon exits rather than
running blind. Fix disk space, log permissions, or the log directory
itself; never work around it by pointing the log at a scratch location
you will discard.

**"Something in a doc or a screen says 'never', 'guaranteed', or
'proof'."**
That wording must map to an enforcing mechanism or be rewritten to
the corrected wording in the README. Report it as a doc bug: absolute
promises are the exact failure v3's wording table exists to prevent.
