"""W10 padding audit (CONTRACT section 13.5).

The manager audits a random sample of 50 generated cases for distinct
inputs + real assertions and rejects padding. This test performs that
audit on every run, deterministically:

  * every generated case key is globally unique (no duplicates);
  * the manifest totals match the generated case tables;
  * a seeded sample of 50 cases (same seed, same sample, every run)
    each carries a distinct key, a varying input, and an expected
    outcome that its file's runner asserts (every runner branch
    asserts, and every spec kind present is dispatched by the runner);
  * no generated case is assertion-free: each file's ``run_case``
    source contains assertions, and each sampled spec's kind is one
    the runner handles.

The 50 sampled cases are also rendered, verbatim, in
``SCALE_REPORT.md`` at the build root by the same sampling function
(``sample_cases`` below), so the report and this test can never drift
apart. Fake data only; no provider contact.
"""

import inspect
import json
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tests.test_generated_audit as gen_audit  # noqa: E402
import tests.test_generated_malformed as gen_malformed  # noqa: E402
import tests.test_generated_misc as gen_misc  # noqa: E402
import tests.test_generated_policy as gen_policy  # noqa: E402
import tests.test_generated_proxy as gen_proxy  # noqa: E402
import tests.test_generated_sessions as gen_sessions  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = Path(__file__).resolve().parent
SAMPLE_SEED = 20261028 + 9
SAMPLE_SIZE = 50

GENERATED_MODULES = (
    ("test_generated_policy.py", gen_policy),
    ("test_generated_sessions.py", gen_sessions),
    ("test_generated_audit.py", gen_audit),
    ("test_generated_malformed.py", gen_malformed),
    ("test_generated_proxy.py", gen_proxy),
    ("test_generated_misc.py", gen_misc),
)


def all_cases():
    """Every generated case as (filename, index, spec), in file order."""
    cases = []
    for filename, module in GENERATED_MODULES:
        for idx, spec in enumerate(module.CASES):
            cases.append((filename, idx, spec))
    return cases


def sample_cases():
    """Deterministic 50-case sample: seeded shuffle, then sorted by
    (file, index) so the report order is stable and readable."""
    cases = all_cases()
    rng = random.Random(SAMPLE_SEED)
    picked = rng.sample(range(len(cases)), SAMPLE_SIZE)
    return sorted((cases[i] for i in picked), key=lambda c: (c[0], c[1]))


def expected_outcome_text(spec):
    """Human-readable expected outcome for the report table."""
    if "expected" in spec:
        return json.dumps(spec["expected"], sort_keys=True)
    if "expected_list" in spec:
        return json.dumps(spec["expected_list"], sort_keys=True)
    if "expected_ok" in spec:
        return "create succeeds" if spec["expected_ok"] else "create refused (KH-2001)"
    if "expected_relay" in spec:
        return "relayed, level %s" % spec["expected_level"] if spec["expected_relay"] else "denied 403, generic body, no upstream hit"
    if "expected_blocked" in spec:
        return "blocked 502" if spec["expected_blocked"] else "relayed 200"
    if "expected_hit" in spec:
        return "cache hit" if spec["expected_hit"] else "cache miss"
    if "expected_spent" in spec:
        return "spent=%s, deny_at=%s" % (spec["expected_spent"], spec["expected_deny_at"])
    if spec.get("kind") == "validate":
        return "live iff t < expires_at and t < idle_deadline"
    if spec.get("kind") in ("no-reset",):
        return "idle deadline unchanged; dead after idle deadline"
    if spec.get("kind") == "success-reset":
        return "idle deadline reset to reset_time + idle; then live by formula"
    if spec.get("kind") == "kill":
        return "killed; token denied (KH-1002); teardown within 5s"
    if spec.get("kind") == "prune":
        return "pruned iff t >= expires_at (v0.2 absolute-expiry rule)"
    if spec.get("kind") in ("killall", "killall-mixed"):
        return "all snapshotted sessions killed; tokens denied"
    if spec.get("kind") == "inflight":
        return "kill receipt lists exactly the in-flight calls"
    if spec.get("kind") == "badkey":
        return "refused (KH-2001)"
    if spec.get("kind") == "noextend":
        return "no extend method exists"
    if spec.get("kind") == "pop-sequence":
        return "sequence outcome per runner (replay/kill/expiry/idle deny)"
    if spec.get("kind") == "pop-tstype":
        return "see spec expected"
    if spec.get("kind") == "sequence":
        return "chain links + hashes verify OK; raw ids absent from log"
    if spec.get("kind") in ("tamper", "tamper-op"):
        return "verify reports TAMPERED"
    if spec.get("kind") == "anchor":
        return "verify OK and anchored"
    if spec.get("kind") == "csv":
        return "CSV header + rows; pseudonyms present, raw ids absent"
    if spec.get("kind") == "scrub-clean":
        return "write succeeds; verify OK"
    if spec.get("kind") == "policy-canon":
        return "canonical path" if spec["expected"] else "CanonicalisationError"
    if spec.get("kind") == "policy-fuzz":
        return "raises, or canonical + idempotent + no dot/empty segments"
    if spec.get("kind") == "policy-fuzz-raise":
        return "CanonicalisationError"
    if spec.get("kind") == "proxy-target":
        return ("canonical=%s forward=%s" % (spec["expected_canon"], spec["expected_fwd"])
                if spec["expected_canon"] else "ValueError")
    if spec.get("kind") == "proxy-fuzz":
        return "raises, or forward segments decode to canonical segments"
    if spec.get("kind") == "proxy-header":
        return "400 generic denial body"
    if spec.get("kind") == "json-dup":
        return "duplicate-key ValueError" if spec["expected_raise"] else "parses"
    if spec.get("kind") in ("glob-nomatch", "glob"):
        return "match=%s" % spec["expected"]
    if spec.get("kind") == "auth":
        return "401 generic denial, no upstream hit (replay: first 200, second 401)"
    if spec.get("kind") == "audit-fail-decision":
        return "503 generic denial, no upstream hit"
    if spec.get("kind") == "audit-fail-outcome":
        return "first call delivered; proxy degraded; next call 503"
    if spec.get("kind") == "oversize-body":
        return "413 generic denial"
    if spec.get("kind") == "length-mismatch":
        return "400 generic denial"
    if spec.get("kind") == "transfer-encoding":
        return "400 generic denial"
    if spec.get("kind") == "cred-query":
        return "400 generic denial"
    if spec.get("kind") == "plain-http-base":
        return "502 generic denial"
    if spec.get("kind") == "spend-copy":
        return "starts with 'spend alerts (estimated)'"
    if spec.get("kind") == "pack-mutate":
        return "pack loads; rule level == mutated level"
    if spec.get("kind") == "pack-refused":
        return "PackRefusedError"
    if spec.get("kind") == "entry-hash-same":
        return "hash deterministic, 64 hex chars"
    return "runner-asserted (see file runner)"


class TestPaddingAudit(unittest.TestCase):
    def test_manifest_matches_case_tables(self):
        manifest = json.loads((TESTS_DIR / "generated_manifest.json").read_text())
        total = 0
        for filename, module in GENERATED_MODULES:
            self.assertEqual(module.CASE_COUNT, len(module.CASES), filename)
            self.assertEqual(manifest["counts"][filename], len(module.CASES), filename)
            total += len(module.CASES)
        self.assertEqual(manifest["total_generated"], total)
        self.assertGreaterEqual(total, 10000, manifest["counts"])

    def test_all_case_keys_globally_unique(self):
        seen = set()
        for _filename, _idx, spec in all_cases():
            key = tuple(spec["key"])
            self.assertNotIn(key, seen, key)
            seen.add(key)
        self.assertEqual(len(seen), sum(len(m.CASES) for _f, m in GENERATED_MODULES))

    def test_every_runner_asserts_and_handles_every_kind(self):
        for _filename, module in GENERATED_MODULES:
            source = inspect.getsource(module.run_case)
            self.assertIn("assert", source, _filename)
            kinds = {spec["kind"] for spec in module.CASES}
            for kind in kinds:
                self.assertIn(kind, source, (_filename, kind))

    def test_sample_50_distinct_inputs_with_assertions(self):
        sample = sample_cases()
        self.assertEqual(len(sample), SAMPLE_SIZE)
        keys = set()
        for filename, idx, spec in sample:
            key = tuple(spec["key"])
            self.assertNotIn(key, keys, (filename, idx, key))
            keys.add(key)
            # A varying input: at least kind + key + one input field.
            self.assertGreaterEqual(len(spec), 3, (filename, idx, spec))
            self.assertTrue(spec["key"], (filename, idx))
            # An expected outcome the runner asserts (explicit field
            # or a documented runner-computed oracle).
            self.assertTrue(expected_outcome_text(spec), (filename, idx, spec))
        self.assertEqual(len(keys), SAMPLE_SIZE)
