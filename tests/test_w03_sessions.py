"""W03 tests: sessions, tokens, TTL, idle, PoP, kill, expiry.

unittest only. Fake identifiers only (no real keys anywhere; sessions
never hold a real key in this module at all). Run from the build root:

    python3 -m unittest tests.test_w03_sessions -v
"""

import hashlib
import hmac
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sealvra.sessions import (  # noqa: E402
    ABSOLUTE_HARD_CAP_SECONDS,
    IDLE_DEFAULT_SECONDS,
    MACOS_SLEEP_CLOCK_DESIGN,
    ClockSanity,
    FreezeStore,
    KillReceipt,
    RotationJournal,
    Session,
    SessionError,
    SessionStore,
    TTL_TABLE,
    classify,
    cross_check_sleep_delta,
    estimate_sleep_seconds,
    expiry_drain_seconds,
    sleep_aware_available,
    sleep_aware_clock_name,
    sleep_aware_monotonic,
    validate_console_grant,
)
from sealvra.tokens import (  # noqa: E402
    ROTATED_SESSION_REASON,
    TOKEN_PREFIX,
    generate_pop_key,
    generate_token,
    hash_token,
    rotate_pop_key,
    sign_request,
    verify_pop,
    verify_token,
)

T0 = 1_800_000_000.0  # fixed wall clock for deterministic TTL tests


def make_store():
    return SessionStore()


def create(store, cls="read_public", **kw):
    kw.setdefault("key_id", "key-0123456789abcdef")
    kw.setdefault("provider", "github")
    kw.setdefault("process_group", "pg-TEST-ONLY-1")
    kw.setdefault("now_wall", T0)
    return store.create_session(session_class=cls, **kw)


def pop_key_of(store, session):
    return store._pop_keys[session.session_id]


def auth(store, session, token, method="GET", host="api.github.com",
         path="/repos/a/b", body=b"", ts=None):
    ts = int(T0) if ts is None else ts
    pop, _ = sign_request(pop_key_of(store, session), method, host, path, body, ts)
    return store.authenticate_request(
        token, method, host, path, body, ts, pop, now_wall=T0)


class TestTokens(unittest.TestCase):
    def test_token_format_and_uniqueness(self):
        a, b = generate_token(), generate_token()
        self.assertTrue(a.startswith(TOKEN_PREFIX))
        self.assertNotEqual(a, b)
        self.assertGreater(len(a), len(TOKEN_PREFIX) + 20)

    def test_hash_is_sha256_and_token_never_stored(self):
        token = generate_token()
        self.assertEqual(hash_token(token), hashlib.sha256(token.encode()).hexdigest())
        store = make_store()
        session, issued = create(store)
        # Only hashes live in the store; the token string appears nowhere.
        self.assertNotIn(issued, store._token_hashes)
        self.assertIn(hash_token(issued), store._token_hashes)
        self.assertNotIn(issued, repr(session))
        self.assertFalse(hasattr(session, "token"))
        self.assertFalse(hasattr(session, "pop_key"))

    def test_constant_time_compare(self):
        token = generate_token()
        good = hash_token(token)
        self.assertTrue(verify_token(token, good))
        # Wrong token, wrong hash, malformed input: all False, none raise.
        self.assertFalse(verify_token(generate_token(), good))
        self.assertFalse(verify_token(token, hash_token(generate_token())))
        self.assertFalse(verify_token("bearer-xyz", good))
        self.assertFalse(verify_token("", good))
        self.assertFalse(verify_token(None, good))  # type: ignore[arg-type]
        self.assertFalse(verify_token(token, None))  # type: ignore[arg-type]
        # Stored hash itself is compared with compare_digest (spot-check
        # that tampering with one hex char fails).
        bad = ("0" if good[0] != "0" else "1") + good[1:]
        self.assertFalse(verify_token(token, bad))

    def test_pop_round_trip_and_tamper(self):
        key = generate_pop_key()
        pop, ts = sign_request(key, "GET", "api.github.com", "/repos/a/b", b"")
        self.assertTrue(verify_pop(key, "GET", "api.github.com", "/repos/a/b", b"", ts, pop, now=T0 if False else ts))
        # Any tamper breaks the MAC.
        self.assertFalse(verify_pop(key, "POST", "api.github.com", "/repos/a/b", b"", ts, pop, now=ts))
        self.assertFalse(verify_pop(key, "GET", "api.github.com", "/repos/a/c", b"", ts, pop, now=ts))
        self.assertFalse(verify_pop(key, "GET", "api.github.com", "/repos/a/b", b"x", ts, pop, now=ts))
        self.assertFalse(verify_pop(key, "GET", "api.github.com", "/repos/a/b", b"", ts, "0" * 64, now=ts))
        self.assertFalse(verify_pop(key, "GET", "api.github.com", "/repos/a/b", b"", ts, None, now=ts))

    def test_pop_skew_300s(self):
        key = generate_pop_key()
        pop, ts = sign_request(key, "GET", "h", "/p", b"", 1000)
        self.assertTrue(verify_pop(key, "GET", "h", "/p", b"", 1000, pop, now=1300))
        self.assertTrue(verify_pop(key, "GET", "h", "/p", b"", 1000, pop, now=700))
        self.assertFalse(verify_pop(key, "GET", "h", "/p", b"", 1000, pop, now=1301))
        self.assertFalse(verify_pop(key, "GET", "h", "/p", b"", 1000, pop, now=699))

    def test_no_reveal_or_clipboard_surface(self):
        import sealvra.sessions as s_mod
        import sealvra.tokens as t_mod
        for mod in (s_mod, t_mod):
            names = " ".join(dir(mod)).lower()
            self.assertNotIn("reveal", names)
            self.assertNotIn("clipboard", names)
            self.assertNotIn("show_token", names)
            self.assertNotIn("print_token", names)


class TestOneKeySchema(unittest.TestCase):
    def test_key_id_must_be_single_string(self):
        store = make_store()
        for bad in (["key-a", "key-b"], ("key-a",), {"key-a"}, None, "", 42):
            with self.assertRaises(SessionError):
                store.create_session(bad, "github", "read_public", "pg-1", now_wall=T0)

    def test_session_record_shape(self):
        store = make_store()
        session, _ = create(store, cls="write")
        self.assertIsInstance(session, Session)
        self.assertTrue(session.session_id.startswith("sess-"))
        self.assertIsInstance(session.key_id, str)
        self.assertEqual(session.transport, "absolute")
        self.assertFalse(session.killed)


class TestTTL(unittest.TestCase):
    def test_ttl_table_exact(self):
        self.assertEqual(TTL_TABLE, {
            "destructive": (600, 900),
            "write": (1200, 1800),
            "read_account": (1800, 3600),
            "read_public": (3600, 7200),
        })
        self.assertEqual(ABSOLUTE_HARD_CAP_SECONDS, 7200)

    def test_defaults_and_caps(self):
        store = make_store()
        for cls, (default, cap) in TTL_TABLE.items():
            s, _ = create(store, cls=cls)
            self.assertEqual(s.expires_at - s.created_at, default, cls)
            s2, _ = create(store, cls=cls, requested_ttl_seconds=cap)
            self.assertEqual(s2.expires_at - s2.created_at, cap, cls)

    def test_over_cap_rejected_not_clamped(self):
        store = make_store()
        for cls, (_, cap) in TTL_TABLE.items():
            with self.assertRaises(SessionError, msg=cls):
                create(store, cls=cls, requested_ttl_seconds=cap + 1)

    def test_hard_cap_2h_rejects_longer(self):
        store = make_store()
        with self.assertRaises(SessionError):
            create(store, cls="read_public", requested_ttl_seconds=7201)
        with self.assertRaises(SessionError):
            create(store, cls="read_public", requested_ttl_seconds=8 * 3600)
        # Exactly 2 h is the read_public cap and is allowed.
        s, _ = create(store, cls="read_public", requested_ttl_seconds=7200)
        self.assertEqual(s.expires_at - s.created_at, 7200)

    def test_bad_ttl_and_class_rejected(self):
        store = make_store()
        for bad in (0, -60, "600"):
            with self.assertRaises(SessionError):
                create(store, cls="write", requested_ttl_seconds=bad)
        with self.assertRaises(SessionError):
            create(store, cls="nonsense")
        with self.assertRaises(SessionError):
            create(store, cls="write", provider="slack")


class TestIdle(unittest.TestCase):
    def test_idle_default_5min_range_2_to_15_no_disable(self):
        store = make_store()
        s, _ = create(store)
        self.assertEqual(s.idle_seconds, IDLE_DEFAULT_SECONDS)
        self.assertEqual(IDLE_DEFAULT_SECONDS, 300)
        for ok in (120, 900):
            s2, _ = create(store, idle_seconds=ok)
            self.assertEqual(s2.idle_seconds, ok)
        for bad in (0, 60, 119, 901, None.__class__ and -1):
            with self.assertRaises(SessionError, msg=str(bad)):
                create(store, idle_seconds=bad)

    def test_idle_reset_only_by_successful_call(self):
        store = make_store()
        s, token = create(store, idle_seconds=300)
        # At T0+299 the session is live; a denied call and a status poll
        # must not move the deadline.
        self.assertIsNotNone(store.validate_token(token, now_wall=T0 + 299))
        store.record_denied_call(s.session_id)
        store.record_status_poll(s.session_id)
        self.assertEqual(s.idle_deadline, T0 + 300)
        self.assertIsNone(store.validate_token(token, now_wall=T0 + 300))
        # Fresh session: a successful call at T0+299 pushes idle to +599.
        s2, token2 = create(store, idle_seconds=300)
        self.assertTrue(store.record_successful_call(s2.session_id, now_wall=T0 + 299))
        self.assertEqual(s2.idle_deadline, T0 + 599)
        self.assertIsNotNone(store.validate_token(token2, now_wall=T0 + 598))
        self.assertIsNone(store.validate_token(token2, now_wall=T0 + 599))

    def test_successful_call_does_not_extend_absolute_expiry(self):
        store = make_store()
        s, _ = create(store, cls="destructive", idle_seconds=300)  # 600 s life
        store.record_successful_call(s.session_id, now_wall=T0 + 590)
        self.assertEqual(s.expires_at, T0 + 600)  # absolute, never sliding


class TestNoExtension(unittest.TestCase):
    def test_no_extend_anywhere(self):
        store = make_store()
        self.assertFalse(hasattr(store, "extend"))
        self.assertFalse(hasattr(store, "extend_session"))
        self.assertFalse(hasattr(store, "renew"))
        import sealvra.sessions as mod
        with open(mod.__file__) as fh:
            src = fh.read()
        self.assertNotIn("def extend", src)
        self.assertNotIn("sessions extend", src)

    def test_reissuance_is_new_session(self):
        store = make_store()
        s1, t1 = create(store)
        store.kill(s1.session_id, now_wall=T0)
        s2, t2 = create(store)
        self.assertNotEqual(s1.session_id, s2.session_id)
        self.assertNotEqual(t1, t2)
        self.assertIsNone(store.validate_token(t1, now_wall=T0))


class TestPoPInStore(unittest.TestCase):
    def test_missing_pop_denied_no_bearer_fallback(self):
        store = make_store()
        s, token = create(store)
        # Bare bearer: valid token, no PoP at all.
        self.assertIsNone(store.authenticate_request(
            token, "GET", "api.github.com", "/repos/a/b", b"", int(T0), None, now_wall=T0))
        # Valid token + garbage PoP also denied.
        self.assertIsNone(store.authenticate_request(
            token, "GET", "api.github.com", "/repos/a/b", b"", int(T0), "0" * 64, now_wall=T0))
        # And the token alone still validates as a session (PoP is a
        # per-request gate, not a session-validity gate).
        self.assertIsNotNone(store.validate_token(token, now_wall=T0))

    def test_valid_pop_authenticates_and_replay_rejected(self):
        store = make_store()
        s, token = create(store)
        self.assertIsNotNone(auth(store, s, token))
        # Same (timestamp, pop) pair replayed: denied, even though the
        # signature itself is still cryptographically valid.
        pop, ts = sign_request(pop_key_of(store, s), "GET", "api.github.com",
                               "/repos/a/b", b"", int(T0))
        self.assertIsNone(store.authenticate_request(
            token, "GET", "api.github.com", "/repos/a/b", b"", ts, pop, now_wall=T0))
        # A fresh timestamp with a fresh signature still works.
        self.assertIsNotNone(auth(store, s, token, ts=int(T0) + 10))

    def test_nonce_cache_never_evicted_during_life(self):
        store = make_store()
        s, token = create(store)
        self.assertIsNotNone(auth(store, s, token, ts=int(T0)))
        cache = store._nonce_cache[s.session_id]
        self.assertEqual(len(cache), 1)
        self.assertIsNotNone(auth(store, s, token, ts=int(T0) + 1))
        self.assertEqual(len(cache), 2)  # append-only: nothing evicted
        pop, ts = sign_request(pop_key_of(store, s), "GET", "api.github.com",
                               "/repos/a/b", b"", int(T0))
        self.assertIsNone(store.authenticate_request(
            token, "GET", "api.github.com", "/repos/a/b", b"", ts, pop, now_wall=T0))

    def test_auth_does_not_reset_idle(self):
        store = make_store()
        s, token = create(store, idle_seconds=300)
        self.assertIsNotNone(auth(store, s, token))
        self.assertEqual(s.idle_deadline, T0 + 300)  # only success resets it

    def test_pop_key_never_on_disk(self):
        store = make_store()
        s, _ = create(store)
        self.assertTrue(os.path.isdir(s.temp_dir))
        # The module writes nothing into the temp dir, and certainly
        # never the token or PoP key.
        self.assertEqual(os.listdir(s.temp_dir), [])


class TestExpiryAndKill(unittest.TestCase):
    def test_expiry_at_absolute_deadline(self):
        store = make_store()
        # read_public = 3600 s; idle (max 900 s) is kept alive by
        # successful calls so the test isolates absolute expiry, which
        # no successful call may move.
        s, token = create(store, cls="read_public", idle_seconds=900)
        for t in (T0 + 899, T0 + 1798, T0 + 2697, T0 + 3596):
            self.assertTrue(store.record_successful_call(s.session_id, now_wall=t))
        self.assertIsNotNone(store.validate_token(token, now_wall=T0 + 3599))
        self.assertIsNone(store.validate_token(token, now_wall=T0 + 3600))
        code_session, code = store.validate_token_detailed(token, now_wall=T0 + 3600)
        self.assertIsNone(code_session)
        self.assertEqual(code, "KH-1002")

    def test_expiry_drain_split(self):
        self.assertEqual(expiry_drain_seconds("read_public"), 60)
        self.assertEqual(expiry_drain_seconds("read_account"), 60)
        self.assertEqual(expiry_drain_seconds("write"), 0)
        self.assertEqual(expiry_drain_seconds("destructive"), 0)

    def test_kill_denies_immediately_and_tears_down(self):
        store = make_store()
        s, token = create(store)
        tmp = s.temp_dir
        self.assertTrue(os.path.isdir(tmp))
        receipt = store.kill(s.session_id, now_wall=T0 + 5)
        self.assertIsInstance(receipt, KillReceipt)
        self.assertIsNone(store.validate_token(token, now_wall=T0 + 5))
        self.assertIsNone(store.authenticate_request(
            token, "GET", "h", "/p", b"", int(T0), "0" * 64, now_wall=T0 + 5))
        self.assertFalse(os.path.exists(tmp))
        self.assertNotIn(s.session_id, store._pop_keys)
        self.assertTrue(s.killed)
        # Kill needs no auth and unknown ids stay generic.
        self.assertIsNone(store.kill("sess-deadbeefdeadbeef", now_wall=T0))

    def test_kill_receipt_lists_already_forwarded_not_recalled(self):
        store = make_store()
        s, _ = create(store)
        store.begin_call(s.session_id, "call-1")
        store.begin_call(s.session_id, "call-2")
        store.complete_call(s.session_id, "call-2")
        receipt = store.kill(s.session_id, now_wall=T0)
        self.assertEqual(receipt.in_flight_at_kill, ["call-1"])
        self.assertTrue(receipt.teardown_within_5s)

    def test_kill_all_snapshot_semantics(self):
        store = make_store()
        s1, _ = create(store)
        s2, _ = create(store)
        receipt = store.kill_all(now_wall=T0)
        self.assertEqual(set(receipt.killed_session_ids), {s1.session_id, s2.session_id})
        self.assertTrue(s1.killed and s2.killed)
        # A session created after the sweep is untouched by it.
        s3, t3 = create(store)
        self.assertIsNotNone(store.validate_token(t3, now_wall=T0))

    def test_prune_expired_tears_down(self):
        store = make_store()
        s, token = create(store, cls="destructive")
        tmp = s.temp_dir
        pruned = store.prune_expired(now_wall=T0 + 601)
        self.assertIn(s.session_id, pruned)
        self.assertFalse(os.path.exists(tmp))
        self.assertIsNone(store.validate_token(token, now_wall=T0 + 601))

    def test_reboot_revokes_everything(self):
        store = make_store()
        _, token = create(store)
        fresh = make_store()  # a new process / reboot: empty memory
        self.assertEqual(fresh.live_session_ids(now_wall=T0), [])
        self.assertIsNone(fresh.validate_token(token, now_wall=T0))


class TestClassify(unittest.TestCase):
    def test_highest_wins(self):
        self.assertEqual(classify("GET", "/x"), "read_account")
        self.assertEqual(classify("GET", "/x", public_read=True), "read_public")
        self.assertEqual(classify("POST", "/x"), "write")
        self.assertEqual(classify("POST", "/x", read_like_post=True), "read_account")
        self.assertEqual(classify("POST", "/x", read_like_post=True, public_read=True), "read_public")
        self.assertEqual(classify("POST", "/x", paid_inference=True), "write")
        self.assertEqual(classify("GET", "/x", paid_inference=True), "write")
        self.assertEqual(classify("GET", "/x", financial=True), "write")
        self.assertEqual(classify("DELETE", "/x"), "destructive")
        self.assertEqual(classify("POST", "/x", destructive=True), "destructive")
        self.assertEqual(classify("GET", "/x", destructive=True, public_read=True), "destructive")
        # Unknown method fails closed toward write, never public read.
        self.assertEqual(classify("BREW", "/x"), "write")

    def test_connect_allowed_refused_for_write_and_destructive(self):
        store = make_store()
        for cls in ("write", "destructive"):
            with self.assertRaises(SessionError):
                create(store, cls=cls, transport="connect_allowed")
        s, _ = create(store, cls="read_public", transport="connect_allowed")
        self.assertEqual(s.transport, "connect_allowed")


if __name__ == "__main__":
    unittest.main()


# ------------------------------------------------------------------
# v0.2 lifecycle hardening additions (W13, f05 re-audit).
# Fake identifiers only; no real keys, no network, no provider calls.
# ------------------------------------------------------------------
import sys as _sys
import tempfile as _tempfile


class TestSleepAwareClocks(unittest.TestCase):
    def test_linux_boottime_path(self):
        # This VM is Linux: the BOOTTIME path must be the live one.
        if _sys.platform != "linux":
            self.skipTest("Linux-only BOOTTIME assertion")
        self.assertTrue(sleep_aware_available())
        self.assertEqual(sleep_aware_clock_name(), "CLOCK_BOOTTIME")
        import time as _time
        boottime = _time.clock_gettime(_time.CLOCK_BOOTTIME)
        # Sleep-aware reading tracks CLOCK_BOOTTIME, not plain monotonic.
        self.assertAlmostEqual(sleep_aware_monotonic(), boottime, delta=1.0)

    def test_plain_monotonic_is_not_claimed_sleep_aware(self):
        # On a platform without BOOTTIME the name must say so plainly.
        if sleep_aware_available():
            self.assertNotIn("NOT sleep-aware", sleep_aware_clock_name())
        else:
            self.assertIn("NOT sleep-aware", sleep_aware_clock_name())

    def test_macos_path_is_design_only_never_claimed_run(self):
        self.assertIn("mach_continuous_time", MACOS_SLEEP_CLOCK_DESIGN)
        self.assertIn("NOT mach_absolute_time", MACOS_SLEEP_CLOCK_DESIGN)
        self.assertIn("DESIGN ONLY", MACOS_SLEEP_CLOCK_DESIGN)
        # On Linux the live clock must be BOOTTIME, never the macOS one.
        if _sys.platform == "linux":
            self.assertEqual(sleep_aware_clock_name(), "CLOCK_BOOTTIME")

    def test_estimate_sleep_from_wall_minus_mono(self):
        # 3600 s of wall time, 10 s of plain monotonic time: 3590 s slept.
        self.assertAlmostEqual(
            estimate_sleep_seconds(1000.0, 4600.0, 500.0, 510.0), 3590.0)
        # No sleep: wall and mono advance together.
        self.assertAlmostEqual(
            estimate_sleep_seconds(1000.0, 1010.0, 500.0, 510.0), 0.0)

    def test_cross_check_sleep_delta(self):
        self.assertAlmostEqual(cross_check_sleep_delta(3600.0, 3600.0), 0.0)
        self.assertAlmostEqual(cross_check_sleep_delta(3600.0, 10.0), 3590.0)


class TestWakeQuarantine(unittest.TestCase):
    def test_quarantine_refuses_everything_until_evaluation(self):
        store = make_store()
        s, token = create(store)
        store.begin_wake_quarantine(reason="wake")
        self.assertTrue(store.is_quarantined())
        self.assertIsNone(store.validate_token(token, now_wall=T0))
        self.assertIsNone(auth(store, s, token))
        self.assertFalse(store.begin_call(s.session_id, "call-q"))
        with self.assertRaises(SessionError):
            create(store)
        # Evaluation with a short sleep suspends (does not kill).
        ev = store.evaluate_wake(30, now_wall=T0)
        self.assertEqual(ev.action, "suspend_all")
        self.assertIn(s.session_id, ev.suspended_session_ids)
        self.assertFalse(store.is_quarantined())
        # Suspended session still denies after quarantine lifts.
        self.assertIsNone(store.validate_token(token, now_wall=T0))

    def test_wake_over_1h_kills(self):
        store = make_store()
        s1, _ = create(store)
        s2, _ = create(store)
        store.begin_wake_quarantine()
        ev = store.evaluate_wake(7200, now_wall=T0)
        self.assertEqual(ev.action, "kill_all")
        self.assertEqual(set(ev.killed_session_ids), {s1.session_id, s2.session_id})
        self.assertTrue(s1.killed and s2.killed)

    def test_wake_zero_sleep_changes_nothing(self):
        store = make_store()
        s, token = create(store)
        store.begin_wake_quarantine()
        ev = store.evaluate_wake(0, now_wall=T0)
        self.assertEqual(ev.action, "none")
        self.assertIsNotNone(store.validate_token(token, now_wall=T0))


class TestLockSuspendResume(unittest.TestCase):
    def test_lock_suspends_unlock_never_resumes(self):
        store = make_store()
        s, token = create(store)
        store.lock_suspend_all(now_wall=T0)
        self.assertTrue(store.is_locked())
        self.assertTrue(s.suspended)
        self.assertIsNone(store.validate_token(token, now_wall=T0))
        still = store.clear_lock()
        self.assertFalse(store.is_locked())
        self.assertIn(s.session_id, still)  # proof unlock did not resume
        self.assertTrue(s.suspended)
        self.assertIsNone(store.validate_token(token, now_wall=T0))

    def test_resume_requires_system_auth_not_proximity_not_click(self):
        store = make_store()
        s, token = create(store)
        store.lock_suspend_all(now_wall=T0)
        # No auth: refused, stays suspended.
        self.assertIsNone(store.resume_session(
            s.session_id, system_auth=False, now_wall=T0))
        self.assertTrue(s.suspended)
        # Proximity/watch auto-unlock: refused even with the flag set.
        self.assertIsNone(store.resume_session(
            s.session_id, system_auth=True, proximity=True, now_wall=T0))
        self.assertTrue(s.suspended)
        # Real system auth: resumes, rotates token + PoP key.
        resumed = store.resume_session(
            s.session_id, system_auth=True, now_wall=T0)
        self.assertIsNotNone(resumed)
        session2, new_token = resumed
        self.assertFalse(session2.suspended)
        self.assertNotEqual(new_token, token)
        self.assertIsNone(store.validate_token(token, now_wall=T0))
        self.assertIsNotNone(store.validate_token(new_token, now_wall=T0))

    def test_idle_suspended_resumes_only_with_auth(self):
        store = make_store()
        s, token = create(store, idle_seconds=300)
        # Idle deadline passes with nothing in flight: suspended, not dead.
        self.assertIsNone(store.validate_token(token, now_wall=T0 + 300))
        self.assertTrue(s.suspended)
        self.assertEqual(s.suspended_reason, "idle")
        # A successful call during suspension does NOT resurrect it.
        self.assertFalse(store.record_successful_call(
            s.session_id, now_wall=T0 + 300))
        self.assertIsNone(store.validate_token(token, now_wall=T0 + 300))
        resumed = store.resume_session(
            s.session_id, system_auth=True, now_wall=T0 + 300)
        self.assertIsNotNone(resumed)
        _, new_token = resumed
        self.assertIsNotNone(store.validate_token(new_token, now_wall=T0 + 300))

    def test_idle_suspended_not_pruned_before_absolute_expiry(self):
        store = make_store()
        s, token = create(store, cls="read_public", idle_seconds=300)
        self.assertIsNone(store.validate_token(token, now_wall=T0 + 300))
        self.assertEqual(store.prune_expired(now_wall=T0 + 300), [])
        self.assertFalse(s.killed)  # still resumable until absolute expiry
        self.assertIn(s.session_id, store.prune_expired(now_wall=T0 + 3600))

    def test_suspend_in_flight_aborts_writes_drains_reads(self):
        store = make_store()
        s, _ = create(store)
        store.begin_call(s.session_id, "read-1", call_class="read_public")
        store.begin_call(s.session_id, "write-1", call_class="write")
        store.begin_call(s.session_id, "del-1", call_class="destructive")
        receipt = store.suspend_session(s.session_id, "lock", now_wall=T0)
        self.assertEqual(set(receipt.aborted_call_ids), {"write-1", "del-1"})
        self.assertEqual(receipt.draining_call_ids, ["read-1"])
        self.assertEqual(receipt.drain_until, T0 + 60)
        self.assertTrue(store.call_may_drain(s.session_id, "read-1", now_wall=T0 + 60))
        self.assertFalse(store.call_may_drain(
            s.session_id, "read-1", now_wall=T0 + 61))


class TestIdleDefinition(unittest.TestCase):
    def test_in_flight_pauses_idle_but_never_resets_it(self):
        store = make_store()
        s, token = create(store, idle_seconds=300)
        # A forwarded call in flight pauses the idle timer mid-stream.
        self.assertTrue(store.begin_call(s.session_id, "stream-1",
                                        call_class="read_public"))
        self.assertIsNotNone(store.validate_token(token, now_wall=T0 + 600))
        self.assertEqual(s.idle_deadline, T0 + 300)  # paused, not reset
        # Stream ends without a successful-call record: idle fires.
        store.complete_call(s.session_id, "stream-1")
        self.assertIsNone(store.validate_token(token, now_wall=T0 + 600))

    def test_begin_and_complete_never_reset_idle(self):
        store = make_store()
        s, token = create(store, idle_seconds=300)
        store.begin_call(s.session_id, "c1", call_class="read_public")
        store.complete_call(s.session_id, "c1")
        self.assertEqual(s.idle_deadline, T0 + 300)
        self.assertIsNone(store.validate_token(token, now_wall=T0 + 300))


class TestClockJump(unittest.TestCase):
    def test_backward_wall_fails_and_suspends(self):
        store = make_store()
        s, token = create(store)
        store.enable_clock_sanity(T0, T0)
        self.assertTrue(store.check_clock(T0 + 10, T0 + 10)[0])
        self.assertFalse(store.note_clock_event(T0 + 5, T0 + 5))
        self.assertTrue(s.suspended)
        self.assertIsNone(store.validate_token(token, now_wall=T0 + 5))

    def test_cumulative_drift_trips_not_single_steps(self):
        sanity = ClockSanity(1000.0, 1000.0)
        # Sub-threshold steps accumulate against the fixed baseline.
        self.assertTrue(sanity.check(1050.0, 1040.0)[0])  # 10 s divergence
        self.assertFalse(sanity.check(1200.0, 1100.0)[0])  # 100 s cumulative

    def test_sanity_runs_before_auth(self):
        store = make_store()
        s, token = create(store)
        store.enable_clock_sanity(T0, T0)
        # Jumped wall clock + jumped sleep-aware clock in lockstep
        # would hide divergence, but a wall jump against a steady
        # sleep-aware clock trips before authentication.
        self.assertIsNone(store.validate_token(
            token, now_wall=T0 + 500, sleep_aware_now=T0 + 10))
        self.assertTrue(s.suspended)


class TestKillReconciliation(unittest.TestCase):
    def test_completed_during_kill_listed_on_receipt(self):
        store = make_store()
        s, _ = create(store)
        store.begin_call(s.session_id, "call-1")
        store.begin_call(s.session_id, "call-2")
        receipt = store.kill(s.session_id, now_wall=T0)
        self.assertEqual(receipt.in_flight_at_kill, ["call-1", "call-2"])
        self.assertEqual(receipt.completed_during_kill, [])
        self.assertEqual(receipt.still_running_at_receipt, ["call-1", "call-2"])
        # Already-forwarded calls run to completion; owners report it.
        self.assertTrue(store.complete_killed_call(s.session_id, "call-1"))
        updated = store.get_kill_receipt(s.session_id)
        self.assertEqual(updated.completed_during_kill, ["call-1"])
        self.assertEqual(updated.still_running_at_receipt, ["call-2"])
        # Unknown calls and double reports are refused.
        self.assertFalse(store.complete_killed_call(s.session_id, "call-9"))
        self.assertFalse(store.complete_killed_call(s.session_id, "call-1"))
        self.assertIsNone(store.get_kill_receipt("sess-unknown"))


class TestRotationJournalAndFreeze(unittest.TestCase):
    def test_journal_reports_interrupted_rotation(self):
        with _tempfile.TemporaryDirectory() as d:
            journal = RotationJournal(d)
            journal.record("key-TEST-ONLY-1", "INTENT")
            journal.record("key-TEST-ONLY-1", "PROVIDER_REVOKED")
            status = journal.recovery_status("key-TEST-ONLY-1")
            self.assertEqual(status["state"], "interrupted")
            self.assertEqual(status["interrupted_at_step"], "PROVIDER_REVOKED")
            journal.record("key-TEST-ONLY-1", "NEW_KEY_STORED")
            journal.complete("key-TEST-ONLY-1")
            self.assertEqual(
                journal.recovery_status("key-TEST-ONLY-1")["state"], "clean")
            # Journal is on disk, fsynced, and parseable line by line.
            with open(journal._path) as fh:
                lines = [ln for ln in fh.read().splitlines() if ln.strip()]
            self.assertEqual(len(lines), 4)
            for ln in lines:
                self.assertNotIn("TEST-ONLY-SECRET", ln)

    def test_journal_abort_is_clean_and_bad_step_rejected(self):
        with _tempfile.TemporaryDirectory() as d:
            journal = RotationJournal(d)
            journal.record("key-TEST-ONLY-2", "INTENT")
            journal.abort("key-TEST-ONLY-2")
            self.assertEqual(
                journal.recovery_status("key-TEST-ONLY-2")["state"], "clean")
            with self.assertRaises(SessionError):
                journal.record("key-TEST-ONLY-2", "BOGUS")

    def test_freeze_persists_across_store_restart(self):
        with _tempfile.TemporaryDirectory() as d:
            store = SessionStore(freeze_dir=d)
            store.freeze_key("key-0123456789abcdef", reason="incident")
            self.assertTrue(store.is_key_frozen("key-0123456789abcdef"))
            with self.assertRaises(SessionError):
                create(store)
            # A fresh store over the same directory still sees the freeze.
            store2 = SessionStore(freeze_dir=d)
            self.assertTrue(store2.is_key_frozen("key-0123456789abcdef"))
            with self.assertRaises(SessionError):
                create(store2)
            store2.unfreeze_key("key-0123456789abcdef")
            s, token = create(store2)
            self.assertIsNotNone(store2.validate_token(token, now_wall=T0))

    def test_rotation_kills_live_sessions_for_key(self):
        store = make_store()
        s1, _ = create(store)
        s2, _ = create(store, key_id="key-aaaaaaaaaaaaaaaa")
        receipts = store.kill_sessions_for_key(
            "key-0123456789abcdef", now_wall=T0)
        self.assertEqual([r.session_id for r in receipts], [s1.session_id])
        self.assertTrue(s1.killed)
        self.assertFalse(s2.killed)


class TestConsoleGrants(unittest.TestCase):
    def test_grant_rules_2h_max_non_destructive_seat_verified(self):
        with self.assertRaises(SessionError):
            validate_console_grant(7201, False, True)
        with self.assertRaises(SessionError):
            validate_console_grant(0, False, True)
        with self.assertRaises(SessionError):
            validate_console_grant(3600, True, True)  # destructive refused
        with self.assertRaises(SessionError):
            validate_console_grant(3600, False, False)  # seat unverified
        validate_console_grant(7200, False, True)  # exactly 2 h allowed

    def test_grant_single_start(self):
        store = make_store()
        store.create_console_grant("g-1", "key-0123456789abcdef", "read",
                                   3600, seat_verified=True, now_wall=T0)
        self.assertTrue(store.start_console_grant("g-1"))
        with self.assertRaises(SessionError):
            store.start_console_grant("g-1")

    def test_revocation_lists_derived_offers_kill(self):
        store = make_store()
        store.create_console_grant("g-1", "key-0123456789abcdef", "read",
                                   3600, seat_verified=True, now_wall=T0)
        s, token = create(store, grant_id="g-1")
        rev = store.revoke_grant("g-1", now_wall=T0)
        self.assertEqual(rev.derived_live_session_ids, [s.session_id])
        # Revocation alone does NOT kill the derived session.
        self.assertIsNotNone(store.validate_token(token, now_wall=T0))
        # The kill path (fresh grant, since g-1 is already revoked)
        # ends derived sessions and names them.
        store.create_console_grant("g-2", "key-0123456789abcdef", "read",
                                   3600, seat_verified=True, now_wall=T0)
        s2, token2 = create(store, grant_id="g-2")
        rev2, receipts = store.revoke_grant_and_kill("g-2", now_wall=T0)
        self.assertEqual(rev2.derived_live_session_ids, [s2.session_id])
        self.assertEqual(rev2.derived_killed_session_ids, [s2.session_id])
        self.assertIsNone(store.validate_token(token2, now_wall=T0))

    def test_grant_scope_frozen_and_lock_suspends_grant(self):
        store = make_store()
        grant = store.create_console_grant(
            "g-1", "key-0123456789abcdef", "read-only", 3600,
            seat_verified=True, now_wall=T0)
        self.assertEqual(grant.scope, "read-only")
        store.lock_suspend_all(now_wall=T0)
        self.assertEqual(grant.status, "suspended")
        # Suspended grant derives nothing; unlock alone does not revive it.
        with self.assertRaises(SessionError):
            create(store, grant_id="g-1")
        store.clear_lock()
        self.assertEqual(grant.status, "suspended")
        self.assertTrue(store.resume_console_grant(
            "g-1", system_auth=True, proximity=False))
        self.assertEqual(grant.status, "live")
        # Sleep over 1 h kills grants outright.
        store.lock_suspend_all(now_wall=T0)
        store.begin_wake_quarantine()
        ev = store.evaluate_wake(7200, now_wall=T0)
        self.assertEqual(ev.action, "kill_all")
        self.assertEqual(grant.status, "dead")


class TestTokenRotation(unittest.TestCase):
    def test_rotate_pop_key_zeroes_old(self):
        old = generate_pop_key()
        snapshot = bytes(old)
        new = rotate_pop_key(old)
        self.assertNotEqual(bytes(new), snapshot)
        self.assertEqual(bytes(old), b"\x00" * len(old))
        self.assertEqual(ROTATED_SESSION_REASON, "session_rotated")


class TestDaemonClockSection(unittest.TestCase):
    def test_daemon_clock_helpers_and_store_delegation(self):
        from sealvra.daemon import Daemon
        daemon = Daemon()
        if _sys.platform == "linux":
            self.assertEqual(daemon.sleep_clock_name(), "CLOCK_BOOTTIME")
        # Unwired: honest, never pretending broker sessions are covered.
        unwired = daemon.enter_wake_quarantine()
        self.assertFalse(unwired["wired"])
        unwired_eval = daemon.evaluate_wake(30)
        self.assertEqual(unwired_eval["action"], "unevaluated")
        # Wired: delegation to the attached store actually quarantines.
        store = make_store()
        s, token = create(store)
        daemon.attach_session_store(store)
        wired = daemon.enter_wake_quarantine()
        self.assertTrue(wired["wired"])
        self.assertIsNone(store.validate_token(token, now_wall=T0))
        ev = daemon.evaluate_wake(30, now_wall=T0)
        self.assertTrue(ev["wired"])
        self.assertEqual(ev["action"], "suspend_all")
        self.assertIn(s.session_id, ev["suspended"])
