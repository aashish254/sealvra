# Sealvra v0.2 — Test Scale Report (W10)

Engine: `tests/test_scale_engine.py` (hand-written, seed 20261028).
Generated files are self-contained: each embeds its case table plus its runner;
regeneration is deterministic (same seed, same cases, same order) and is
checked by `test_committed_files_match_engine` and `test_generation_is_deterministic`.

## Counts (full discovery: `.venv/bin/python -m unittest discover -s tests`)

| measure | count |
|---|---|
| discovered (full suite) | 11771 |
| passed | 11750 |
| failed | 3 (all sibling files, none in W10 files — see below) |
| skipped | 16 |
| expected failures | 2 |
| full-suite runtime | 139.0 s (budget: under ~10 min) |
| generated cases | 10697 |
| hand-written W10 tests (engine 8 + padding audit 4) | 12 |
| other pre-existing / sibling tests | 1062 |

### Generated cases by file

| file | cases |
|---|---|
| test_generated_policy.py | 4242 |
| test_generated_sessions.py | 3776 |
| test_generated_audit.py | 359 |
| test_generated_malformed.py | 1452 |
| test_generated_proxy.py | 311 |
| test_generated_misc.py | 557 |
| **total generated** | **10697** |

### Remaining full-suite failures (not W10) — MANAGER CORRECTION (2026-10-28)

The two items below are SUPERSEDED by manager integration fixes and no longer
fail: the dual-consume product gap is closed in `sealvra/approval.py`
(unified single-use; `test_adversarial` passes in full), and the `yaml`
checker flag is closed by the macOS checker's shipped-code scope (tests
excluded). The manager's final full run is green: 11,771 tests, 0 failures,
0 errors, 16 skipped, 2 expected failures. The original section is kept
below for the record.

### Remaining full-suite failures (not W10)

- `test_adversarial.TestApprovalForgeryReal.test_verified_decision_cannot_also_spend_grant`:
  product gap in approval/spend-grant logic (sibling W02/W14 area); W10 touches no product modules.
- `test_w17_macos` checker + readiness tests: the checker flags a `yaml` import in
  `tests/test_w20_packaging.py` and macOS API mentions in scripts/other test files;
  no W10 file is cited. W10 files import stdlib + `sealvra` only.
- Note: an earlier full run also showed `test_e2e` fixed-port (18765/18766) clashes and
  a `test_gates` registry-count failure; both cleared in the final run (sibling churn /
  ordering interference), and `test_e2e.MockProviderTests` passes standalone.

### Counting rules honoured (CONTRACT 13.5)

- Distinct input + at least one real security assertion per case; the engine's single
  dedup registry fails loudly on any key collision (several were caught and fixed
  during generation: method-mismatch cases landing on existing endpoints, approval
  cases for non-level-3 rules, repeated fuzz paths, repeated capability triples).
- No subTest-only counting: generated files create real `TestCase` methods.
- No assertion-free or bare 'no crash' cases; fuzz cases carry explicit oracles
  (canonicalisation invariants, forward/canonical segment equality, no secret in output).
- 10,000 was reached honestly (10697); no padding was added to hit the number.

## Padding audit — 50-case sample

Deterministic sample (`tests/test_padding_audit.py::sample_cases`, seed 20261037).
Each row shows the case's input and the security outcome its runner asserts.
All 50 keys are distinct; every sampled spec maps to a runner branch that asserts.

### 1. test_generated_audit.py case 93 — kind `sequence`

```json
{
  "key": [
    "audit-sequence",
    3,
    12
  ],
  "kind": "sequence",
  "length": 3,
  "variant": 12
}
```

Asserted outcome: chain links + hashes verify OK; raw ids absent from log

### 2. test_generated_audit.py case 263 — kind `tamper`

```json
{
  "key": [
    "audit-tamper",
    3,
    "hash"
  ],
  "kind": "tamper",
  "length": 5,
  "position": 3,
  "tamper": "hash"
}
```

Asserted outcome: verify reports TAMPERED

### 3. test_generated_malformed.py case 248 — kind `policy-fuzz`

```json
{
  "key": [
    "policy-fuzz",
    "/b07-i6/seg-170"
  ],
  "kind": "policy-fuzz",
  "path": "/b07-i6/seg-170"
}
```

Asserted outcome: raises, or canonical + idempotent + no dot/empty segments

### 4. test_generated_malformed.py case 277 — kind `policy-fuzz`

```json
{
  "key": [
    "policy-fuzz",
    "/\u03b4elta/seg-121/4d0be8"
  ],
  "kind": "policy-fuzz",
  "path": "/\u03b4elta/seg-121/4d0be8"
}
```

Asserted outcome: raises, or canonical + idempotent + no dot/empty segments

### 5. test_generated_malformed.py case 493 — kind `policy-fuzz`

```json
{
  "key": [
    "policy-fuzz",
    "/seg-876"
  ],
  "kind": "policy-fuzz",
  "path": "/seg-876"
}
```

Asserted outcome: raises, or canonical + idempotent + no dot/empty segments

### 6. test_generated_malformed.py case 549 — kind `policy-fuzz`

```json
{
  "key": [
    "policy-fuzz",
    "/caf\u00e9/v2.2"
  ],
  "kind": "policy-fuzz",
  "path": "/caf\u00e9/v2.2"
}
```

Asserted outcome: raises, or canonical + idempotent + no dot/empty segments

### 7. test_generated_malformed.py case 709 — kind `policy-fuzz`

```json
{
  "key": [
    "policy-fuzz",
    "/m\u00fcnchen/18ag2/%C3%A9x/%20x"
  ],
  "kind": "policy-fuzz",
  "path": "/m\u00fcnchen/18ag2/%C3%A9x/%20x"
}
```

Asserted outcome: raises, or canonical + idempotent + no dot/empty segments

### 8. test_generated_malformed.py case 1028 — kind `proxy-target`

```json
{
  "base": "http://127.0.0.1:18765",
  "expected_canon": "/repos/o/r",
  "expected_fwd": "/repos/o/r",
  "host": "127.0.0.1:18765",
  "key": [
    "proxy-target",
    "origin-notest",
    false
  ],
  "kind": "proxy-target",
  "target": "/repos/o/r",
  "test_mode": false
}
```

Asserted outcome: canonical=/repos/o/r forward=/repos/o/r

### 9. test_generated_malformed.py case 1048 — kind `proxy-target`

```json
{
  "base": "http://127.0.0.1:18765",
  "expected_canon": null,
  "expected_fwd": null,
  "host": "127.0.0.1:18765",
  "key": [
    "proxy-target",
    "cred-query",
    "api_key"
  ],
  "kind": "proxy-target",
  "target": "/repos/o/r?api_key=abc",
  "test_mode": true
}
```

Asserted outcome: ValueError

### 10. test_generated_malformed.py case 1057 — kind `proxy-fuzz`

```json
{
  "base": "http://127.0.0.1:18765",
  "host": "127.0.0.1:18765",
  "key": [
    "proxy-fuzz",
    "/85f2?sort=78"
  ],
  "kind": "proxy-fuzz",
  "target": "/85f2?sort=78"
}
```

Asserted outcome: raises, or forward segments decode to canonical segments

### 11. test_generated_malformed.py case 1251 — kind `proxy-fuzz`

```json
{
  "base": "http://127.0.0.1:18765",
  "host": "127.0.0.1:18765",
  "key": [
    "proxy-fuzz",
    "/_iec4/v0.5/g--~~d-?page=61"
  ],
  "kind": "proxy-fuzz",
  "target": "/_iec4/v0.5/g--~~d-?page=61"
}
```

Asserted outcome: raises, or forward segments decode to canonical segments

### 12. test_generated_malformed.py case 1262 — kind `proxy-fuzz`

```json
{
  "base": "http://127.0.0.1:18765",
  "host": "127.0.0.1:18765",
  "key": [
    "proxy-fuzz",
    "/seg-533/if_9/%C3%A9x?state=36"
  ],
  "kind": "proxy-fuzz",
  "target": "/seg-533/if_9/%C3%A9x?state=36"
}
```

Asserted outcome: raises, or forward segments decode to canonical segments

### 13. test_generated_malformed.py case 1299 — kind `proxy-fuzz`

```json
{
  "base": "http://127.0.0.1:18765",
  "host": "127.0.0.1:18765",
  "key": [
    "proxy-fuzz",
    "/%7Ex?per_page=98"
  ],
  "kind": "proxy-fuzz",
  "target": "/%7Ex?per_page=98"
}
```

Asserted outcome: raises, or forward segments decode to canonical segments

### 14. test_generated_misc.py case 284 — kind `spend`

```json
{
  "amounts": [
    5,
    0,
    50
  ],
  "cap": 10,
  "expected_deny_at": 2,
  "expected_spent": 5,
  "key": [
    "spend",
    10,
    "5+0+50"
  ],
  "kind": "spend"
}
```

Asserted outcome: spent=5, deny_at=2

### 15. test_generated_misc.py case 496 — kind `secret-scan`

```json
{
  "encoding": "raw",
  "expected": true,
  "key": [
    "secret-scan",
    "TEST-ONLY scan key 2",
    "raw"
  ],
  "kind": "secret-scan",
  "secret": "TEST-ONLY scan key 2"
}
```

Asserted outcome: true

### 16. test_generated_misc.py case 537 — kind `secret-scan`

```json
{
  "encoding": "json-unicode",
  "expected": true,
  "key": [
    "secret-scan",
    "TEST-ONLY-scan-key-6",
    "json-unicode"
  ],
  "kind": "secret-scan",
  "secret": "TEST-ONLY-scan-key-6"
}
```

Asserted outcome: true

### 17. test_generated_policy.py case 359 — kind `decision`

```json
{
  "body": null,
  "body_kind": null,
  "body_raw_kind": null,
  "expected": {
    "allowed": false,
    "level": 4,
    "rule_id": "capability"
  },
  "key": [
    "policy",
    "github",
    "PATCH",
    "/gists/*",
    2,
    "read_public",
    "fresh"
  ],
  "kind": "decision",
  "ledger": null,
  "method": "PATCH",
  "path": "/gists/a",
  "provider": "github",
  "session_class": "read_public",
  "stale": false
}
```

Asserted outcome: {"allowed": false, "level": 4, "rule_id": "capability"}

### 18. test_generated_policy.py case 610 — kind `decision`

```json
{
  "body": null,
  "body_kind": null,
  "body_raw_kind": null,
  "expected": {
    "allowed": false,
    "level": 4,
    "rule_id": "stale_pack"
  },
  "key": [
    "policy",
    "github",
    "DELETE",
    "/repos/*/*",
    4,
    "destructive",
    "stale"
  ],
  "kind": "decision",
  "ledger": null,
  "method": "DELETE",
  "path": "/repos/m\u00fcnchen/caf\u00e9-repo",
  "provider": "github",
  "session_class": "destructive",
  "stale": true
}
```

Asserted outcome: {"allowed": false, "level": 4, "rule_id": "stale_pack"}

### 19. test_generated_policy.py case 858 — kind `decision`

```json
{
  "body": null,
  "body_kind": null,
  "body_raw_kind": null,
  "expected": {
    "allowed": false,
    "level": 4,
    "rule_id": "stale_pack"
  },
  "key": [
    "policy",
    "github",
    "POST",
    "/repos/*/*/merges",
    5,
    "destructive",
    "stale"
  ],
  "kind": "decision",
  "ledger": null,
  "method": "POST",
  "path": "/repos/example-organisation/sample_repository-2026/merges",
  "provider": "github",
  "session_class": "destructive",
  "stale": true
}
```

Asserted outcome: {"allowed": false, "level": 4, "rule_id": "stale_pack"}

### 20. test_generated_policy.py case 997 — kind `decision`

```json
{
  "body": null,
  "body_kind": null,
  "body_raw_kind": null,
  "expected": {
    "allowed": false,
    "level": 4,
    "rule_id": "capability"
  },
  "key": [
    "policy",
    "github",
    "POST",
    "/repos/*/*/dispatches",
    4,
    "read_account",
    "fresh"
  ],
  "kind": "decision",
  "ledger": null,
  "method": "POST",
  "path": "/repos/m\u00fcnchen/caf\u00e9-repo/dispatches",
  "provider": "github",
  "session_class": "read_account",
  "stale": false
}
```

Asserted outcome: {"allowed": false, "level": 4, "rule_id": "capability"}

### 21. test_generated_policy.py case 1150 — kind `decision`

```json
{
  "body": null,
  "body_kind": null,
  "body_raw_kind": null,
  "expected": {
    "allowed": false,
    "level": 4,
    "rule_id": "capability"
  },
  "key": [
    "policy",
    "github",
    "DELETE",
    "/repos/*/*/releases/assets/*",
    5,
    "read_account",
    "stale"
  ],
  "kind": "decision",
  "ledger": null,
  "method": "DELETE",
  "path": "/repos/example-organisation/sample_repository-2026/releases/assets/long-segment-name",
  "provider": "github",
  "session_class": "read_account",
  "stale": true
}
```

Asserted outcome: {"allowed": false, "level": 4, "rule_id": "capability"}

### 22. test_generated_policy.py case 1324 — kind `decision`

```json
{
  "body": null,
  "body_kind": null,
  "body_raw_kind": null,
  "expected": {
    "allowed": false,
    "level": 3,
    "rule_id": "stale_pack"
  },
  "key": [
    "policy",
    "github",
    "POST",
    "/repos/*/*/issues",
    3,
    "write",
    "stale"
  ],
  "kind": "decision",
  "ledger": null,
  "method": "POST",
  "path": "/repos/v1.2/rel.3/issues",
  "provider": "github",
  "session_class": "write",
  "stale": true
}
```

Asserted outcome: {"allowed": false, "level": 3, "rule_id": "stale_pack"}

### 23. test_generated_policy.py case 1569 — kind `decision`

```json
{
  "body": null,
  "body_kind": null,
  "body_raw_kind": null,
  "expected": {
    "allowed": true,
    "level": 2,
    "rule_id": "github:PATCH:/repos/*/*/issues/*"
  },
  "key": [
    "policy",
    "github",
    "PATCH",
    "/repos/*/*/issues/*",
    4,
    "destructive",
    "fresh"
  ],
  "kind": "decision",
  "ledger": null,
  "method": "PATCH",
  "path": "/repos/m\u00fcnchen/caf\u00e9-repo/issues/\u03b4elta",
  "provider": "github",
  "session_class": "destructive",
  "stale": false
}
```

Asserted outcome: {"allowed": true, "level": 2, "rule_id": "github:PATCH:/repos/*/*/issues/*"}

### 24. test_generated_policy.py case 1769 — kind `decision`

```json
{
  "body": null,
  "body_kind": null,
  "body_raw_kind": null,
  "expected": {
    "allowed": true,
    "level": 1,
    "rule_id": "github:GET:/user/keys"
  },
  "key": [
    "policy",
    "github",
    "GET",
    "/user/keys",
    5,
    "destructive",
    "fresh"
  ],
  "kind": "decision",
  "ledger": null,
  "method": "GET",
  "path": "/user/keys",
  "provider": "github",
  "session_class": "destructive",
  "stale": false
}
```

Asserted outcome: {"allowed": true, "level": 1, "rule_id": "github:GET:/user/keys"}

### 25. test_generated_policy.py case 1965 — kind `decision`

```json
{
  "body": null,
  "body_kind": null,
  "body_raw_kind": null,
  "expected": {
    "allowed": true,
    "level": 1,
    "rule_id": "github:GET:/users/*"
  },
  "key": [
    "policy",
    "github",
    "GET",
    "/users/*",
    5,
    "read_account",
    "fresh"
  ],
  "kind": "decision",
  "ledger": null,
  "method": "GET",
  "path": "/users/example-organisation",
  "provider": "github",
  "session_class": "read_account",
  "stale": false
}
```

Asserted outcome: {"allowed": true, "level": 1, "rule_id": "github:GET:/users/*"}

### 26. test_generated_policy.py case 2320 — kind `decision`

```json
{
  "body": null,
  "body_kind": null,
  "body_raw_kind": null,
  "expected": {
    "allowed": false,
    "level": 4,
    "rule_id": "capability"
  },
  "key": [
    "policy",
    "gemini",
    "POST",
    "/v1beta/batches",
    1,
    "read_public",
    "stale"
  ],
  "kind": "decision",
  "ledger": null,
  "method": "POST",
  "path": "/v1beta/batches",
  "provider": "gemini",
  "session_class": "read_public",
  "stale": true
}
```

Asserted outcome: {"allowed": false, "level": 4, "rule_id": "capability"}

### 27. test_generated_policy.py case 2352 — kind `decision`

```json
{
  "body": null,
  "body_kind": null,
  "body_raw_kind": null,
  "expected": {
    "allowed": false,
    "level": 4,
    "rule_id": "capability"
  },
  "key": [
    "policy",
    "gemini",
    "POST",
    "/v1beta/batches",
    5,
    "read_public",
    "stale"
  ],
  "kind": "decision",
  "ledger": null,
  "method": "POST",
  "path": "/v1beta/batches",
  "provider": "gemini",
  "session_class": "read_public",
  "stale": true
}
```

Asserted outcome: {"allowed": false, "level": 4, "rule_id": "capability"}

### 28. test_generated_policy.py case 2605 — kind `decision`

```json
{
  "body": null,
  "body_kind": null,
  "body_raw_kind": null,
  "expected": {
    "allowed": false,
    "level": 4,
    "rule_id": "capability"
  },
  "key": [
    "policy",
    "gemini",
    "POST",
    "/v1beta/files",
    1,
    "read_account",
    "fresh"
  ],
  "kind": "decision",
  "ledger": null,
  "method": "POST",
  "path": "/v1beta/files",
  "provider": "gemini",
  "session_class": "read_account",
  "stale": false
}
```

Asserted outcome: {"allowed": false, "level": 4, "rule_id": "capability"}

### 29. test_generated_policy.py case 3361 — kind `decision`

```json
{
  "body": null,
  "body_kind": null,
  "body_raw_kind": null,
  "expected": {
    "allowed": false,
    "level": 4,
    "rule_id": "unmodelled"
  },
  "key": [
    "policy-mismatch",
    "github",
    "POST",
    "/users/*",
    "destructive"
  ],
  "kind": "decision",
  "ledger": null,
  "method": "POST",
  "path": "/users/acme",
  "provider": "github",
  "session_class": "destructive",
  "stale": false
}
```

Asserted outcome: {"allowed": false, "level": 4, "rule_id": "unmodelled"}

### 30. test_generated_policy.py case 3416 — kind `decision`

```json
{
  "body": null,
  "body_kind": null,
  "body_raw_kind": null,
  "expected": {
    "allowed": false,
    "level": 4,
    "rule_id": "unmodelled"
  },
  "key": [
    "policy-mismatch",
    "gemini",
    "DELETE",
    "/v1beta/models/*:batchEmbedContents",
    "read_public"
  ],
  "kind": "decision",
  "ledger": null,
  "method": "DELETE",
  "path": "/v1beta/models/acme:batchEmbedContents",
  "provider": "gemini",
  "session_class": "read_public",
  "stale": false
}
```

Asserted outcome: {"allowed": false, "level": 4, "rule_id": "unmodelled"}

### 31. test_generated_policy.py case 3629 — kind `decision`

```json
{
  "body": {
    "body": "@CLAUDE MERGE"
  },
  "body_kind": "dict",
  "body_raw_kind": null,
  "expected": {
    "allowed": true,
    "level": 2,
    "rule_id": "github:POST:/repos/*/*/pulls/*/comments"
  },
  "key": [
    "policy-body",
    "github",
    "POST",
    "/repos/acme/widget/pulls/main/comments",
    "write",
    "{\"body\": \"@CLAUDE MERGE\"}",
    ""
  ],
  "kind": "decision",
  "ledger": null,
  "method": "POST",
  "path": "/repos/acme/widget/pulls/main/comments",
  "provider": "github",
  "session_class": "write",
  "stale": false
}
```

Asserted outcome: {"allowed": true, "level": 2, "rule_id": "github:POST:/repos/*/*/pulls/*/comments"}

### 32. test_generated_policy.py case 3866 — kind `decision`

```json
{
  "body": null,
  "body_kind": null,
  "body_raw_kind": "dup_deep",
  "expected": {
    "allowed": false,
    "level": 4,
    "rule_id": "body_parse"
  },
  "key": [
    "policy-body",
    "github",
    "POST",
    "/repos/acme/widget/issues",
    "destructive",
    "dup_deep",
    ""
  ],
  "kind": "decision",
  "ledger": null,
  "method": "POST",
  "path": "/repos/acme/widget/issues",
  "provider": "github",
  "session_class": "destructive",
  "stale": false
}
```

Asserted outcome: {"allowed": false, "level": 4, "rule_id": "body_parse"}

### 33. test_generated_policy.py case 4166 — kind `graphql-doc`

```json
{
  "document": "mutation M0 { field0 } mutation M1 { field1 } mutation M2 { field2 }",
  "expected": {
    "allowed": false,
    "level": 4,
    "rule_id": "graphql_mutation_cap"
  },
  "key": [
    "graphql-doc",
    "mutations-3",
    "read_account",
    2
  ],
  "kind": "graphql-doc",
  "max_mutations": 2,
  "session_class": "read_account"
}
```

Asserted outcome: {"allowed": false, "level": 4, "rule_id": "graphql_mutation_cap"}

### 34. test_generated_policy.py case 4238 — kind `graphql-batch`

```json
{
  "body": [
    {
      "query": "query { f }"
    },
    {
      "query": "mutation M { f }"
    },
    {
      "query": "mutation M { f }"
    }
  ],
  "expected_list": [
    {
      "allowed": true,
      "level": 1,
      "rule_id": "graphql_query"
    },
    {
      "allowed": false,
      "level": 3,
      "rule_id": "graphql_mutation"
    },
    {
      "allowed": false,
      "level": 3,
      "rule_id": "graphql_mutation"
    }
  ],
  "key": [
    "graphql-batch",
    "query+mutation+mutation"
  ],
  "kind": "graphql-batch"
}
```

Asserted outcome: [{"allowed": true, "level": 1, "rule_id": "graphql_query"}, {"allowed": false, "level": 3, "rule_id": "graphql_mutation"}, {"allowed": false, "level": 3, "rule_id": "graphql_mutation"}]

### 35. test_generated_sessions.py case 393 — kind `create`

```json
{
  "expected_ok": false,
  "idle": 301,
  "key": [
    "session-create",
    "destructive",
    600,
    301,
    "connect_allowed",
    "github"
  ],
  "kind": "create",
  "provider": "github",
  "session_class": "destructive",
  "transport": "connect_allowed",
  "ttl": 600
}
```

Asserted outcome: create refused (KH-2001)

### 36. test_generated_sessions.py case 911 — kind `create`

```json
{
  "expected_ok": false,
  "idle": 120,
  "key": [
    "session-create",
    "write",
    60,
    120,
    "bogus",
    "github"
  ],
  "kind": "create",
  "provider": "github",
  "session_class": "write",
  "transport": "bogus",
  "ttl": 60
}
```

Asserted outcome: create refused (KH-2001)

### 37. test_generated_sessions.py case 1062 — kind `create`

```json
{
  "expected_ok": false,
  "idle": 899,
  "key": [
    "session-create",
    "write",
    300,
    899,
    "bogus",
    "gemini"
  ],
  "kind": "create",
  "provider": "gemini",
  "session_class": "write",
  "transport": "bogus",
  "ttl": 300
}
```

Asserted outcome: create refused (KH-2001)

### 38. test_generated_sessions.py case 1118 — kind `create`

```json
{
  "expected_ok": true,
  "idle": 899,
  "key": [
    "session-create",
    "write",
    301,
    899,
    "absolute",
    "gemini"
  ],
  "kind": "create",
  "provider": "gemini",
  "session_class": "write",
  "transport": "absolute",
  "ttl": 301
}
```

Asserted outcome: create succeeds

### 39. test_generated_sessions.py case 1142 — kind `create`

```json
{
  "expected_ok": false,
  "idle": 119,
  "key": [
    "session-create",
    "write",
    1199,
    119,
    "absolute",
    "gemini"
  ],
  "kind": "create",
  "provider": "gemini",
  "session_class": "write",
  "transport": "absolute",
  "ttl": 1199
}
```

Asserted outcome: create refused (KH-2001)

### 40. test_generated_sessions.py case 1239 — kind `create`

```json
{
  "expected_ok": false,
  "idle": 899,
  "key": [
    "session-create",
    "write",
    1200,
    899,
    "connect_allowed",
    "github"
  ],
  "kind": "create",
  "provider": "github",
  "session_class": "write",
  "transport": "connect_allowed",
  "ttl": 1200
}
```

Asserted outcome: create refused (KH-2001)

### 41. test_generated_sessions.py case 1278 — kind `create`

```json
{
  "expected_ok": false,
  "idle": 121,
  "key": [
    "session-create",
    "write",
    1201,
    121,
    "bogus",
    "gemini"
  ],
  "kind": "create",
  "provider": "gemini",
  "session_class": "write",
  "transport": "bogus",
  "ttl": 1201
}
```

Asserted outcome: create refused (KH-2001)

### 42. test_generated_sessions.py case 1721 — kind `create`

```json
{
  "expected_ok": false,
  "idle": 899,
  "key": [
    "session-create",
    "read_account",
    1,
    899,
    "bogus",
    "github"
  ],
  "kind": "create",
  "provider": "github",
  "session_class": "read_account",
  "transport": "bogus",
  "ttl": 1
}
```

Asserted outcome: create refused (KH-2001)

### 43. test_generated_sessions.py case 1826 — kind `create`

```json
{
  "expected_ok": true,
  "idle": 300,
  "key": [
    "session-create",
    "read_account",
    299,
    300,
    "absolute",
    "gemini"
  ],
  "kind": "create",
  "provider": "gemini",
  "session_class": "read_account",
  "transport": "absolute",
  "ttl": 299
}
```

Asserted outcome: create succeeds

### 44. test_generated_sessions.py case 1839 — kind `create`

```json
{
  "expected_ok": true,
  "idle": 899,
  "key": [
    "session-create",
    "read_account",
    299,
    899,
    "connect_allowed",
    "github"
  ],
  "kind": "create",
  "provider": "github",
  "session_class": "read_account",
  "transport": "connect_allowed",
  "ttl": 299
}
```

Asserted outcome: create succeeds

### 45. test_generated_sessions.py case 2019 — kind `create`

```json
{
  "expected_ok": true,
  "idle": 899,
  "key": [
    "session-create",
    "read_account",
    1799,
    899,
    "connect_allowed",
    "github"
  ],
  "kind": "create",
  "provider": "github",
  "session_class": "read_account",
  "transport": "connect_allowed",
  "ttl": 1799
}
```

Asserted outcome: create succeeds

### 46. test_generated_sessions.py case 2983 — kind `create`

```json
{
  "expected_ok": true,
  "idle": 900,
  "key": [
    "session-create",
    "read_public",
    3601,
    900,
    "absolute",
    "github"
  ],
  "kind": "create",
  "provider": "github",
  "session_class": "read_public",
  "transport": "absolute",
  "ttl": 3601
}
```

Asserted outcome: create succeeds

### 47. test_generated_sessions.py case 3028 — kind `create`

```json
{
  "expected_ok": true,
  "idle": 300,
  "key": [
    "session-create",
    "read_public",
    7199,
    300,
    "connect_allowed",
    "gemini"
  ],
  "kind": "create",
  "provider": "gemini",
  "session_class": "read_public",
  "transport": "connect_allowed",
  "ttl": 7199
}
```

Asserted outcome: create succeeds

### 48. test_generated_sessions.py case 3120 — kind `create`

```json
{
  "expected_ok": false,
  "idle": 0,
  "key": [
    "session-create",
    "read_public",
    7200,
    0,
    "bogus",
    "gemini"
  ],
  "kind": "create",
  "provider": "gemini",
  "session_class": "read_public",
  "transport": "bogus",
  "ttl": 7200
}
```

Asserted outcome: create refused (KH-2001)

### 49. test_generated_sessions.py case 3640 — kind `classify`

```json
{
  "destructive": true,
  "expected": "destructive",
  "financial": false,
  "key": [
    "classify",
    "FOO",
    true,
    true,
    false,
    true,
    true
  ],
  "kind": "classify",
  "method": "FOO",
  "paid": true,
  "public": true,
  "read_like": true
}
```

Asserted outcome: "destructive"

### 50. test_generated_sessions.py case 3666 — kind `capability`

```json
{
  "capabilities": [
    "destructive",
    "financial",
    "read_account"
  ],
  "expected": "financial",
  "key": [
    "capability",
    "destructive+financial+read_account"
  ],
  "kind": "capability"
}
```

Asserted outcome: "financial"
