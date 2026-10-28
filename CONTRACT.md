# Keyholder v0.1 — Interface Contract (MANAGER-ISSUED, READ FIRST)

This contract is normative for every worker. If your module spec and this
contract disagree, this contract wins for interfaces; the v3 plan wins for
security rules. Do not invent a second interface. Do not rewrite another
worker's files. If an interface in this contract cannot be implemented,
report it to the manager in your final report and implement the closest
honest subset — never silently diverge.

## 0. Source of truth and hard limits

- Normative plan: `~/workspace/keyholder-plan/KEYHOLDER-PLAN-V3-FINALCHECK.md`
  (v3 wins over v1/v2; deleted/superseded passages in v3 are never built).
- Build + local test ONLY. No push, no GitHub repo, no contact with GitHub
  or any real provider, no name announcement/reservation, no publishing.
  Nothing leaves this machine except loopback mock traffic.
- No real keys/tokens/credentials anywhere: code, tests, fixtures, logs,
  docs. Use only clearly fake test keys (`TEST-ONLY-...`).
- Working title Keyholder, binary/command `keyholder`. Do NOT rename to
  Keyseal (unconfirmed, not trademark-cleared).
- Stop version: v0.1 personal edition, single user, local-only, no sync
  ever, no company edition, no cloud, no server. GitHub + Gemini only.

## 1. Stack and layout (non-negotiable)

- Language: Python 3.12. External dependencies, exactly two, pinned by
  W19 in `requirements.txt` (and recorded with versions actually installed):
  `cryptography` (AES-256-GCM) and `argon2-cffi` (Argon2id). No other
  dependencies. Everything else is stdlib (including `tkinter` for the GUI).
  If a dependency cannot be installed in your worker, the vault must fail
  closed and you must report it — never substitute a home-made cipher or
  a weaker KDF silently (scrypt is NOT an approved substitute in v0.1).
- Repo root: `~/workspace/keyholder-build/`
  - `keyholder/` — package, run as `python3 -m keyholder` from the root
    (tests insert the root into `sys.path`).
  - `tests/` — pytest-style test files runnable with plain `python3 -m
    unittest` discovery OR `pytest` if available; do NOT assume pytest is
    installed. Prefer `unittest` so the manager's integration run works.
  - `scripts/`, `docs/`, `packs/`, `.github/workflows/`
- Virtualenv (for local runs, never committed): `.venv/` in the build root.
- Never write into `~/workspace/keyholder-plan/` or `~/workspace/your_files/`.
  Keep deliverables under `~/workspace/keyholder-build/`, never `/tmp`.

## 2. Shared types (use these names and shapes exactly)

```python
# keyholder/types.py — W01 owns this file; all workers import from it.
Provider = "github" | "gemini"   # literal strings only
SessionClass = "destructive" | "write" | "read_account" | "read_public"
Transport = "absolute" | "connect_allowed"  # default "absolute"

@dataclass KeyRecord:
    key_id: str            # "key-<16 hex chars from secrets.token_hex(8)>"
    provider: Provider
    label: str             # user-chosen, never shown in global audit entries
    created_at: str        # UTC ISO-8601
    compartment_version: int = 1
    # NOTE: the real key value is NEVER stored in a KeyRecord, never logged,
    # never returned by any API. It lives only in a vault compartment and
    # in worker memory during a session.

@dataclass Session:
    session_id: str        # "sess-<16 hex>" (internal id, NOT the token)
    key_id: str            # exactly one key_id, never a list
    provider: Provider
    session_class: SessionClass
    transport: Transport
    created_at: float      # time.monotonic() + time.time() both recorded
    expires_at: float      # wall-clock epoch; absolute, never sliding
    idle_deadline: float   # refreshed only by successful proxied calls
    process_group: str     # agent process-group identifier for kill binding
    ancestry: str          # free-text process ancestry recorded in audit
    killed: bool = False
    # token and PoP key are NOT fields here. They live only in memory
    # in the broker (see §4). Any code that puts them in a dataclass,
    # file, log, or repr is a security bug.

@dataclass PolicyDecision:
    allowed: bool
    level: int             # 1 allow, 2 allow-with-log, 3 approve, 4 deny
    reason: str
    rule_id: str | None

@dataclass ApprovalRequest:
    approval_id: str
    session_pseudonym: str
    provider: Provider
    method: str
    path: str              # canonical path, never raw bytes
    scope_summary: str     # permissions AND purpose, never agent free text
    created_at: float
```

## 3. TTL table (v3 §1B, R07 — the ONLY table)

- destructive: default 10 min, cap 15 min
- write (non-destructive, incl. paid inference): default 20 min, cap 30 min
- read_account: default 30 min, cap 60 min
- read_public: default 60 min, cap 120 min
- ABSOLUTE HARD CAP: 2 hours for everything (session, grant, template).
- Idle timeout: 5 min (range 2–15, cannot be disabled). Idle is reset ONLY
  by a successful proxied call (not by denied calls, not by status polls).
- No session extensions, ever. Re-issuance = new session + fresh gesture.
- Kill: deny-list ≤1 s, full teardown ≤5 s, already-forwarded calls are
  NOT recalled (they run to completion and are listed on the kill receipt).
- Expiry drain: reads/idempotent ≤60 s; destructive writes and streams
  terminate at expiry. No 60 s overrun for destructive/stream by default.

## 4. Tokens, PoP, and handoff (v3 §1C)

- Session token format: `"kh_sess_" + secrets.token_urlsafe(32)`.
  The broker stores ONLY `hashlib.sha256(token.encode()).hexdigest()`,
  compared with `hmac.compare_digest`. The token string is returned to
  the caller exactly once at session creation and never logged, never
  written to disk, never put in an env var that survives the session.
- PoP: every proxied request must carry `X-Keyholder-Session` (the token),
  `X-Keyholder-PoP` = HMAC-SHA256 (PoP key, canonical string
  `METHOD\nHOST\nCANONICAL_PATH\nBODY_SHA256_HEX\nTIMESTAMP`),
  and `X-Keyholder-Timestamp` (epoch seconds, max skew 300 s, nonce
  cache is append-only for the session lifetime — no eviction).
  PoP key lives in memory only, delivered via pipe/FD or in-process
  handoff, never in a 0600 file. Missing/invalid PoP = deny, no fallback
  to bare bearer. Agents that cannot sign use the wrapper/sidecar
  (W12) or are refused.
- Session directory (if any temporary files are unavoidable): use
  `tempfile.mkdtemp`, never a fixed `~/.keyholder/sessions/` path, and
  delete the directory on session end. Session files must never contain
  a token or PoP key.
- Control plane: there is NO file-based control token in v0.1. The CLI
  talks to the daemon over a loopback Unix socket (Linux/macOS) or
  loopback TCP (Windows) with an in-memory pairing established at daemon
  start. Document honestly that on Linux/Windows this does NOT separate
  same-user processes (Tier B) — only macOS keychain access groups do
  that, and they cannot be proven on Linux.

## 5. Vault (W02, v3 §1D)

- One encrypted compartment per key. No vault-wide master key, no single
  DEK. Each compartment: own wrapping key, own version counter, own
  backup container. Header AEAD: key derived from the compartment key
  via HKDF-SHA256 with distinct info strings per use; nonce = 96-bit
  random, never reused; AAD = (key_id, provider, compartment_version,
  header field names). Body: AES-256-GCM.
- Password mode: Argon2id, m=64 MiB, t=3, p=1 (from `argon2-cffi`).
  Platform-keychain mode is the recommended default on macOS; on Linux
  (Secret Service where available, else encrypted file vault) and
  Windows (DPAPI) the storage is USER-SCOPED — the README, the doctor
  output, and the posture output must say so in plain words.
- Fingerprint: first 12 hex chars of SHA-256 of the SECRET (for display
  in the owning key's detail pane only). Global audit entries use the
  pseudonym (see §8), never the label, never key fragments.
- Atomic writes: write temp file in the same directory, fsync, rename,
  fsync directory. Never rename over the live file before snapshotting.
  Restore kills live sessions first. Backup export: per-compartment by
  default, interactive OS auth every time, never control-socket auth
  alone, refuse synced folders without typed risk confirmation, 24 h
  cooldown between full-vault exports (enforced, not advisory).

## 6. Proxy and policy (W04, W05, v3 §1G)

- Loopback proxy, default `127.0.0.1:8765` (configurable port, loopback
  only, never 0.0.0.0). Request handling:
  1. Read session token + PoP, validate session live, not killed, not
     expired, not idle-timed-out, transport allowed.
  2. Canonicalise method + path (decode-then-split is FORBIDDEN for
     query handling — split first, then decode each segment; reject
     duplicate JSON keys at any depth, reject chunked/CL+TE smuggling,
     reject bare LF/folding/NUL).
  3. Classify by CAPABILITY (not path/method alone): highest class wins;
     paid inference = write class; financial = money/billing only.
     Read-like POST exemption list lives in the provider pack.
  4. Policy decision (provider pack, signed, version-pinned). Unmodelled
     endpoint = deny. Decision cache: ALLOW-only, 60 s, never for
     cap-conditioned or approval-gated rules.
  5. Approval-gated calls: broker-owned approval (W08) BEFORE forwarding.
     No approval = no forward.
  6. Audit decision entry fsynced BEFORE forwarding (fail closed: if
     the log cannot be written, refuse the call, daemon does not run blind).
  7. Inject the real key at the last moment (GitHub: `Authorization:
     Bearer <key>`; Gemini: `x-goog-api-key: <key>` ONLY — never `?key=`).
  8. Forward upstream with `http.client` (HTTPS for real providers;
     HTTP only for explicitly configured loopback mock bases in test mode).
     Strip `Accept-Encoding` (or decompress-then-scan) so the response
     secret scan sees plaintext; scan JSON-unescaped, hex, and
     URL-encoded forms. Credential-creating responses are DENIED by
     default (never relay a newly minted credential to the agent).
  9. Log outcome. Streams: per-chunk budget enforcement.
- CONNECT: refused (HTTP 405) by default for every session. A session
  may opt in ONLY with `transport="connect_allowed"`, explicitly
  requested, and every UI/audit surface must label it HOST-ONLY POLICY
  (host + byte budget only; method/path/body policy unenforceable in a
  tunnel). CONNECT is never the default transport.
- Denials to the agent are generic (no rule_id, no category). rule_id
  and category go to the audit log only. No denial oracle.
- Provider packs: JSON in `packs/`, with `name`, `version`,
  `content_sha256`, `endpoints[]` (method, path pattern, class, level,
  spend flag, body schema name). Pack loading verifies the content hash;
  a pack whose hash mismatches is refused, not loaded. Stale packs:
  refusal for destructive/metered sessions. Spend caps are estimates —
  copy must say "spend alerts (estimated)", never a guaranteed cap.

## 7. Adapters (W06, W07 — rewritten, never copied from old R06/§9)

- GitHub (W06): fine-grained PAT primary. Corrected classification:
  Contents:write INCLUDES branch/tag create+delete, ref updates, branch
  rename, merges, PR merge, release create/delete + asset delete,
  dispatches, merge-upstream — all of these are write/destructive class
  in the pack, never "files only". Import-time HARD DENIES (refuse the
  key, do not just warn): account SSH keys write, gists write, secrets
  write/rotate, repo deletion. Comment-command patterns (`/deploy`,
  `/approve`, `/backport`, `@claude merge/lgtm/approve`, etc.) denied.
  GraphQL denied (enumerate GraphQL-only destructives in the pack docs).
  Merge gated (approval level 4). Git-protocol pushes: if git
  interposition is NOT built, the README and the adapter doc MUST say
  git pushes bypass the broker manifest and are NOT logged/gated —
  never claim otherwise.
- Gemini (W07): auth-key model only (post-May-2026 AI Studio keys are
  authorization keys bound to a Google Cloud service account). Native
  mode: `x-goog-api-key` header, deny all other auth forms. Compat
  (OpenAI-format) mode: strip-and-inject (never forward a real-key
  Bearer). Interactions API, batch jobs, Live API, managed agents,
  remote MCP, file search stores: DENIED (they outlive sessions or
  create server-side state the broker cannot police). `cachedContent`
  and `fileData.fileUri` references inside otherwise-allowed calls:
  denied unless the referenced object is in the session's creation
  ledger. Upload paths (`/upload/...`, resumable session URLs): denied
  in v0.1 unless modelled in the pack. Spend limiters per tier in the pack.

## 8. Approval (W08) and audit (W09)

- Approval decisions come ONLY from the broker-owned approver (W08).
  No `sessions approve` CLI command, no dashboard approve button.
  Dashboard/CLI are read + kill only. Kill needs no auth.
- Two-step for session creation and destructive calls: OS gesture
  (Touch ID / Hello / polkit / system password UI) + explicit confirm,
  in that order, bound to the exact request hash (single-use nonce,
  atomic consume). Timeout always denies: 60 s default, 120 s
  accessibility opt-in, clock starting at the system prompt.
  Approve-once = consumption deadline (5 min to consume, single use),
  NOT a 5-minute validity window for repeat calls. Destructive calls:
  fresh per-call approval, no session-scope reuse, no level-3 opt-out.
  Break-glass (if implemented): MEDIUM/session prompts only, NEVER
  destructive. Console grants: 2 h max, single start, non-destructive,
  seat-verified, audited — or deleted (W08 decides, W10/W18 record it).
  X11 destructive: REFUSED. Broker-window clicks may present or deny
  a destructive call, NEVER approve it.
- Audit event (JSONL, one event per line, canonical JSON, sorted keys):
  `seq, ts, prev_hash, entry_hash, event_type, session_pseudonym,
  key_pseudonym, provider, method, canonical_path, decision,
  rule_id, outcome, bytes_in, bytes_out, approval_id`.
  Chain: `entry_hash = SHA256(canonical_json_without_entry_hash)`,
  `prev_hash` = previous entry's `entry_hash` (genesis: all zeros).
  Fingerprints in audit = HMAC-SHA256(audit_secret, key_id) truncated
  to 16 hex — never raw key hashes, never first/last key characters.
  Writer offset-checks before every append (halt + alarm on foreign
  growth). `verify` must report: OK / UNANCHORED (amber, exit 2) /
  TAMPERED (exit 3) / MISSING-DIRECTORY (exit 3, genesis guard — a
  silently reborn log is a failure, not a fresh start). Retention
  (single schedule for v0.1): live 90 days, archive 1 year, summaries
  only after expiry, never key material. Disk-full = refuse new calls
  (fail closed), never "continue with a warning".

## 9. CLI surface (W10) and error catalogue (one table, all surfaces)

Commands (exact): `keyholder daemon start|stop|status`,
`keyholder keys add|list|show|delete|rotate`,
`keyholder sessions list|create|kill|kill-all`,
`keyholder audit verify|export`, `keyholder doctor`, `keyholder prove-isolation`,
`keyholder --help`, `keyholder --version`.
There is NO `keys reveal`, NO `--show-token`, NO `--print-token`,
NO `sessions approve`, NO `sessions extend`, NO clipboard handoff.
Any worker adding one of these fails the manager check.
Error codes (exit codes in parentheses): KH-1001 vault locked (1),
KH-1002 session not found/expired/killed (2), KH-1003 policy denied (2),
KH-1004 approval denied/timeout (2), KH-1005 audit unavailable (3),
KH-1006 provider/upstream error (1), KH-2001 invalid input/usage (1),
KH-3001 platform unsupported for this action (1),
KH-3002 isolation/proof failure (3), KH-3003 secret detected in log (3).
Same event = same code on every surface. Failed `prove-isolation`
is exit 3, never a routine policy denial.
Import flow: mandatory question "Was this key ever pasted anywhere?"
(answer "don't know" = yes) → forced provider rotation before the
first session + permanent NOT YET ROTATED warning until rotation is
recorded. Dashboard/counter copy (wherever it appears) says
"Times any key has left this machine *since import*: 0" and the trust
screen leads with "stops *key* theft, not *data* theft".

## 10. Threat tiers, stated per invariant (v3 §1A)

Every module doc and README section must state Tier A (interface-bound
agent) vs Tier B (shell-capable same-user agent) for each control it
claims. Controls that survive Tier B: macOS keychain access groups,
OS-rendered prompts, worker sandbox profiles. Controls that do NOT
survive Tier B and must never be cited as Tier B evidence: 0600/0700
file permissions, file-stored control tokens, peer-credential checks,
pairing tokens. Same-user malware / compromised OS account is out of
scope by design — say so, do not imply otherwise.

## 11. Tests and fixtures

- Every module ships its own `tests/test_wNN_<module>.py` (unittest).
  W14 owns `tests/test_adversarial.py`; W15 owns `tests/test_e2e.py`
  and `tests/mock_providers.py`. No other worker writes those files.
- Fixtures: fake keys only, prefixed `TEST-ONLY-`. Mock providers run
  on loopback only, with fixed ports chosen by W15 and documented here
  by amendment if they change (default: mock GitHub 127.0.0.1:18765,
  mock Gemini 127.0.0.1:18766 — W15 owns the final choice, all workers
  must read W15's file before hard-coding a port).
- A test that was not run on a platform is NOT-RUN, never PASSED.
  A test that fails is FAILED with the reason. The manager counts
  pass/fail/not-run from actual runs, not from worker claims.

## 12. Module file areas (do not write outside your area)

- W01: `keyholder/types.py`, `keyholder/daemon.py`, `keyholder/broker.py`,
  `keyholder/supervisor.py`, `tests/test_w01_daemon.py`
- W02: `keyholder/vault.py`, `keyholder/crypto.py`, `tests/test_w02_vault.py`
- W03: `keyholder/sessions.py`, `keyholder/tokens.py`, `tests/test_w03_sessions.py`
- W04: `keyholder/proxy.py`, `tests/test_w04_proxy.py`
- W05: `keyholder/policy.py`, `keyholder/packs.py`, `packs/*.json`,
  `tests/test_w05_policy.py`
- W06: `keyholder/github.py`, `tests/test_w06_github.py`
- W07: `keyholder/gemini.py`, `tests/test_w07_gemini.py`
- W08: `keyholder/approval.py`, `tests/test_w08_approval.py`
- W09: `keyholder/audit.py`, `tests/test_w09_audit.py`
- W10: `keyholder/cli.py`, `keyholder/__main__.py`, `keyholder/__init__.py`,
  `tests/test_w10_cli.py`
- W11: `keyholder/gui.py`, `tests/test_w11_gui.py` (GUI must import
  safely headless: importing gui.py must not open a window or crash
  without a display; window creation only inside `main()`/a function
  the CLI calls explicitly)
- W12: `keyholder/wrapper.py`, `keyholder/mcp.py`, `keyholder/probe.py`,
  `tests/test_w12_integrations.py`
- W13: `keyholder/platform.py`, `tests/test_w13_platform.py`
- W14: `tests/test_adversarial.py` (+ `tests/adversarial_helpers.py`)
- W15: `tests/test_e2e.py`, `tests/mock_providers.py`
- W16: `scripts/windows_check.py`, `scripts/make_zipapp.py` (shared with
  W20 — W16 owns the Windows section, W20 owns the script file; agree
  the interface in your reports, do not both edit it),
  `docs/windows.md`, `tests/test_w16_windows.py`
- W17: `scripts/macos_check.py`, `docs/macos.md`, `tests/test_w17_macos.py`
- W18: `README.md`, `docs/*.md` (except windows.md/macos.md),
  `BUILD-AND-TEST-REPORT.md` (draft — manager finalises)
- W19: `requirements.txt`, `scripts/sbom.py`, `scripts/repro_check.py`,
  `docs/supply-chain.md`
- W20: `.github/workflows/ci.yml`, `scripts/make_zipapp.py`,
  `scripts/install.sh`, `scripts/install.ps1`, `scripts/uninstall.sh`,
  `scripts/uninstall.ps1`, `tests/test_w20_packaging.py`
- Shared types file (`keyholder/types.py`) is W01's: W01 writes it FIRST
  in substance (other workers may import it and, if a field is missing,
  report the gap to the manager instead of editing types.py themselves).

## Manager integration amendments (final tree)

These amendments were made by the manager during integration and are
normative for v0.1 alongside the sections above. Where they conflict
with a worker's earlier reading, this section wins.

1. PoP replay: a signed request verifies exactly once per session.
   The broker checks the MAC first, then the replay cache keyed by
   the nonce if given, else by the PoP value itself. A no-nonce
   replay is therefore rejected (W14 stop-ship fix).
2. Level-3 decisions: `allowed=False` until approval is the
   PolicyEngine's pre-approval state, not a proxy denial. The proxy
   passes level 3 to the approver; only an approved call proceeds
   (as allow-with-log). Level 4 and non-level-3 denials are denied
   before approval.
3. Windows supervisor kill: Windows uses `process.terminate()` /
   `process.kill()`; POSIX `killpg`/`getpgid` paths are guarded with
   `sys.platform != "win32"` (the form the Windows checker
   recognises). A job-object/process-tree kill is post-push work.
4. Credential Guard + Hello PIN returns T2 with a remote-typed-PIN
   label, never T1 or a biometric label.
5. CLI daemon commands (`daemon start|stop|status`) are process-local
   in v0.1 via module-level functions on a singleton Daemon. There
   is no cross-process daemon persistence in v0.1; the CLI must never
   claim a background daemon exists. Persistent daemon IPC is the
   next slice.
6. Recorded divergences, NOT unified: TTL over-cap (broker clamps,
   session store rejects — both never exceed the 2 h cap);
   worker-per-key (broker refuses a second live session for the same
   key, stricter than v3's one-session-one-key); canonical types
   (W08/W05 local types alongside `types.py`). See
   BUILD-AND-TEST-REPORT.md for the full list.
7. Manager-owned integration test: `tests/test_integration.py` wires
   the real Broker, PolicyEngine + packs, AuditLog, and ProxyEngine
   in-process against loopback mocks on ephemeral ports. It is the
   E2E proof for v0.1; W15's CLI-daemon real-path tests remain
   class-skipped (NOT-RUN) because they need the slice in item 5
   plus a test approver.

---

## 13. v0.2 integration rules (MANAGER-ISSUED, READ FIRST — v0.2)

Stop version is v0.2 personal edition, single user, local-only, no sync
ever, no company edition, no cloud, no server. GitHub + Gemini only.
v0.1 rules above stay in force unless this section explicitly changes
them. Where this section and a v0.1 section disagree, this section wins
for v0.2 interfaces only; v3 wins for security rules.

### 13.1 Cross-process daemon (W01 owns daemon.py, supervisor.py, types.py IPC shape)
- The daemon is a real separate process. CLI invocations talk to it over
  IPC, not via a process-local singleton. `daemon start` spawns and
  detaches it; `daemon stop` kills it and its workers; `daemon status`
  reports a daemon started by ANY earlier CLI invocation.
- IPC transport: Unix domain socket on Linux/macOS, loopback TCP on
  Windows. Socket directory is 0700, socket is 0600. Authentication is
  SO_PEERCRED / peer-UID on Unix (same UID only) and loopback-only on
  Windows — and this must be documented as Tier B honestly: it does NOT
  separate same-user processes. No file-stored control token is added
  to fix that; the Tier B limit is stated, not papered over.
- Protocol: newline-delimited JSON requests with `{"id", "cmd", "args"}`
  and `{"id", "ok", "result"}` / `{"id", "ok": false, "error": {"code",
  "message"}}` replies, using the v0.1 error codes (KH-xxxx). Commands
  at minimum: `status`, `sessions.list`, `sessions.kill`,
  `sessions.kill_all`, `sessions.create` (returns token exactly once,
  over IPC only, never logged), `audit.verify`, `doctor`.
- Sessions are in-memory in the daemon only. Daemon death = session
  death, never resurrection on restart. The daemon must self-terminate
  orphan workers ≤5 s after supervisor loss, and `daemon stop` must
  kill the whole worker process group (POSIX killpg, Windows terminate
  tree), verified by test.
- Backwards compatibility: the v0.1 process-local singleton code path
  is deleted or demoted to a test-only fallback, never the default.
  CLI must never report a process-local daemon as a background daemon.

### 13.2 Real approver wiring (W02 owns the production approver callable)
- The proxy's approve callable in the PRODUCTION path is the real
  broker-owned approver (approval.py), never a test double. A test
  approver may be injected only in tests, through an explicit
  test-only parameter; it must never be the default, and the proxy
  must raise if a test approver is present outside a test harness
  marker (an env var set only by tests, named in code and docs).
- Approver interface: `approve(request: ApprovalRequest) -> Decision`
  where Decision carries `approved: bool`, `approval_id`,
  `consumed_nonce`, `decided_at`. The request hash binds provider,
  method, canonical path, scope summary, session pseudonym, and a
  single-use nonce consumed atomically. Timeout always denies (60 s
  default, 120 s accessibility opt-in, clock from system prompt).
  Two-step for session creation and destructive calls: OS gesture +
  explicit confirm, in that order. Broker-window clicks may present
  or deny, NEVER approve a destructive call. Kill needs no auth.
  X11 destructive: REFUSED.
- Break-glass, if present: MEDIUM/session prompts only, NEVER
  destructive calls. This is a hard rule, not a default.

### 13.3 Pack signing (W04 owns packs.py, packs/*.sig, scripts/sign_pack.py)
- Format: each provider pack `packs/<name>.json` ships with a
  detached signature `packs/<name>.sig` — base64 Ed25519 signature
  over the pack's canonical bytes (sorted keys, no whitespace, the
  exact bytes the verifier hashes). `packs/trusted_keys.json` lists
  key IDs and public keys; `packs/revoked.json` lists revoked key
  IDs and revoked pack versions.
- Verification: on load, verify signature against a trusted,
  non-revoked key AND verify the content hash. A pack that fails
  either check is REFUSED, never loaded, never silently fallen back
  to an unsigned or hash-only pack. Key rotation: two trusted keys
  may coexist during rotation; a revoked key's packs are refused
  even if the hash matches.
- Test/dev packs: tests use their own test key, generated in the
  test, never the shipped trusted key, and test packs live under
  tests/ fixtures, never in packs/.
- Until W04 lands signing, hash verification stays as in v0.1. The
  flip to refuse-unsigned is a single, tested change, recorded in
  the report — not a silent behaviour change.

### 13.4 Git interposition boundary (W05 owns keyholder/git.py + git helper)
- The agent must NEVER receive the real key for git. The git path
  is: a git credential helper (`keyholder git-credential`) that
  issues a session-scoped credential (proxy session token bound to
  one key, one repo scope, TTL-capped), plus a wrapper
  (`keyholder git` / documented wrapper script) that logs push,
  pull, and fetch attempts to the audit log and denies force-push
  and ref-deletion unless the matching approval exists.
- Honest boundary, stated in docs and code: a git client run
  directly by the agent with standing credentials outside the
  wrapper/helper bypasses the broker. That path is NOT logged or
  gated, and `doctor` must flag standing git credentials. W05 must
  record exactly what the helper+wrapper covers and what still
  bypasses it; claiming full git coverage when the wrapper is
  bypassable is a report failure.
- Git credential protocol: the helper speaks git's credential
  protocol (get/store/erase) on stdin/stdout, never prints a real
  key, and the credential it returns expires with the session.

### 13.5 Test-scale rules (W10 owns the scale engine — read this before counting anything)
- A generated case counts ONLY if it has a distinct input AND at
  least one real assertion about a security-relevant outcome
  (allow/deny/approve, injection or non-injection, audit presence,
  kill/expiry effect, no secret in output). A case that only checks
  "no crash" does NOT count toward the security total unless it is
  a fuzz case with an explicit oracle: no secret leaked, no fallback
  to a raw key, no unlogged forward.
- No duplicates: two cases with the same (provider, endpoint,
  method, scope, class, input shape) and the same expected outcome
  are ONE case, not two. No assertion-free tests. No tests that
  assert `True` or that merely import a module.
- Counting: unittest discovery must count them. Use dynamic
  TestCase generation (load_tests or generated test methods in
  generated files), not subTest alone — subTests do not count as
  separate discovered tests. Verify the count with the exact
  discovery command and record it; the manager audits a random
  sample of 50 generated cases for distinct inputs + assertions
  and rejects padding.
- Generated files live in tests/test_generated_*.py, generated by
  tests/test_scale_engine.py (the engine itself is hand-written
  and tested). Regeneration must be deterministic: same seed,
  same cases, same order. The report must state: total discovered,
  passed/failed/skipped, generated vs hand-written counts, and
  the padding-audit result.
- Runtime budget: the full suite must finish on this VM in a
  reasonable time (target under ~10 minutes). If 10,000 cases
  cannot honestly be reached, report the honest count — padding
  to hit 10,000 is a failure of this round.

### 13.6 v0.2 file areas (workers stay inside their area; cross-area changes go through the manager)
- W01: keyholder/daemon.py, keyholder/supervisor.py, tests/test_w01_daemon.py, tests/test_daemon_ipc.py (new)
- W02: keyholder/approval.py, keyholder/proxy.py (approver callable only), tests/test_w08_approval.py additions via a new tests/test_approver_wiring.py (do not rewrite W08's file wholesale)
- W03: keyholder/gui.py, tests/test_w11_gui.py
- W04: keyholder/packs.py, packs/*.json, packs/*.sig, packs/trusted_keys.json, packs/revoked.json, scripts/sign_pack.py, tests/test_pack_signing.py (new)
- W05: keyholder/git.py, scripts/git-credential-helper (new, executable), tests/test_git.py (new), docs/adapters.md (git section only)
- W06: scripts/windows_check.py, scripts/install.ps1, scripts/uninstall.ps1, docs/windows.md, tests/test_w16_windows.py
- W07: scripts/macos_check.py, docs/macos.md, tests/test_w17_macos.py
- W08: tests/test_registry.py (new: master test registry), scripts/grep_gates.py (new), README Gate G0 table (with W20), tests/test_gates.py (new)
- W09: tests/test_adversarial.py (additions only, append new classes), tests/adversarial_helpers.py
- W10: tests/test_scale_engine.py, tests/test_generated_*.py (generated), tests/test_padding_audit.py (new)
- W11: keyholder/proxy.py (policy hardening only, coordinate with W02), keyholder/policy.py, tests/test_w04_proxy.py, tests/test_w05_policy.py (additions)
- W12: keyholder/vault.py, keyholder/crypto.py, tests/test_w02_vault.py (additions)
- W13: keyholder/sessions.py, keyholder/tokens.py, keyholder/daemon.py (clock/sleep sections only, coordinate with W01), tests/test_w03_sessions.py (additions)
- W14: keyholder/approval.py (ceremony hardening only, coordinate with W02), tests/test_w08_approval.py (additions)
- W15: keyholder/audit.py, tests/test_w09_audit.py (additions)
- W16: keyholder/wrapper.py, keyholder/mcp.py, keyholder/probe.py, tests/test_w12_integrations.py (additions)
- W17: keyholder/cli.py (update-check payload only, coordinate with W18), keyholder/approval.py (no change), docs/*.md (egress sections), tests/test_egress.py (new)
- W18: keyholder/cli.py (error table + defaults only, coordinate with W17), keyholder/gui.py (defaults only, coordinate with W03), tests/test_w10_cli.py (additions)
- W19: requirements.txt, scripts/sbom.py, scripts/repro_check.py, .github/workflows/ci.yml, docs/supply-chain.md, tests/test_w20_packaging.py (additions)
- W20: README.md, docs/*.md (except windows.md/macos.md/adapters git section/egress sections), BUILD-AND-TEST-REPORT.md (manager finalises from measured runs), tests/test_e2e.py (real-path un-skip, with W01/W02)
- Shared: no worker edits CONTRACT.md. If an interface above cannot be implemented, report it to the manager and implement the closest honest subset.

### 13.7 Manager integration amendments (v0.2 finalisation, 2026-10-28)
- Unified single-use approval (dual-consume fix): `ApprovalBroker.verify_and_consume`
  and `spend_grant` now share one consumed state. Verifying consumes the grant;
  spending the grant consumes the broker nonce (grants carry their nonce).
  `RealApprover.approve` verifies WITHOUT consuming (`verify_decision`); consumption
  happens exactly once at forward time in `spend_for_forward` (production nonce +
  broker verify-and-consume, with grant-existence, destructive-grant, and deadline
  checks before any consume). One approval can never authorise two forwards.
- CLI sessions are daemon-first: `keyholder sessions list/kill/kill-all` (and
  create, after its vault guard) route through daemon IPC when a daemon is running,
  and fall back to the process-local sessions module only when no daemon is running.
  Live-proven for list/kill; create via CLI is implemented but not live-proven
  (see below). CLI test harness stubs "no daemon" when stubbing the sessions
  backend, so a daemon leaked by another test cannot hijack CLI tests.
- CLI audit verify/export and CLI keys/sessions-create vault lookups still use a
  stub-only interface (`audit.verify`/`audit.export`, `vault.get_key` do not exist on
  the real classes). Real wiring needs an audit-root convention and a CLI↔vault
  adapter; neither was guessed. These are open v0.2 gaps, not closed ones.
- Zipapp reproducibility: `scripts/make_zipapp.py` excludes `__pycache__`/`*.pyc`.
  Cold-cache builds are byte-identical; v0.2 zipapp SHA-256 is recorded in the
  report (never reuse the v0.1 hash).
- macOS checker scope: C6 gates SHIPPED dependencies (the zipapp packs
  `keyholder/` only). Test files are excluded from the third-party import scan,
  as C5 already excludes them; an optional test-only import guarded by
  try/except ImportError -> skipTest is an honest NOT-RUN, not a product dependency.
- TTL divergence (gap 9) resolved as a documented divergence, not a unification:
  the broker (daemon path) clamps over-cap TTLs, the SessionStore (in-process path)
  rejects them; neither path ever exceeds the 2 h absolute cap. Worker-per-key is
  deliberately stricter than v3: the broker refuses a second live session for the
  same key, while v3 requires only one session = one key.
- Tier B socket minting (W09 finding): `sessions.create` over daemon IPC is
  peer-UID only with no OS-gesture approval. This is NOT closed by the peer-UID
  check alone; it stays open pending an owner decision (approval gate for socket
  creation vs an explicit Tier B statement). Mitigations in place: worker-per-key
  refusal of a second live session for the same key, and no raw key or pre-existing
  token/PoP ever disclosed over the socket.
