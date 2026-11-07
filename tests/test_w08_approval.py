"""W08 approval ceremony tests (unittest). Fake TEST-ONLY values only.

Covers: approver-only origin, two-step ordering, nonce single-use +
concurrent replay, timeout-deny, approve-once semantics, destructive
fresh-approval, X11 refusal, break-glass destructive exclusion, plus
serialisation, card content rules, console grants, fatigue counters
and enrolment posture. Run: python3 -m unittest tests.test_w08_approval -v
from ~/workspace/sealvra-build (tests also insert the root on sys.path).
"""

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sealvra.approval import (  # noqa: E402
    APPROVER_CHANNEL,
    ApprovalBroker,
    ApprovalError,
    ApprovalKind,
    ApprovalSeal,
    Approver,
    BreakGlass,
    ConsoleGrant,
    DenyReason,
    FatigueTracker,
    OriginRefused,
    SealStore,
    WrongOrder,
    broker_window_may_approve,
    build_card,
    cli_or_dashboard_may_approve,
    compute_request_hash,
    create_console_grant,
    detect_display_protocol,
    detect_display_protocol_with_backend,
    os_prompt_reason,
    pairing_word_os_prompt_support,
    platform_tier_for,
    refuse_app_password,
    refuse_foreign_approval,
    requires_two_step,
)


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_broker(**kwargs):
    clock = FakeClock()
    broker = ApprovalBroker(clock=clock, min_card_dwell_s=0, **kwargs)
    return broker, clock


def make_card(**overrides):
    params = dict(
        approval_id="appr-test",
        key_id="key-0123456789abcdef",
        provider="github",
        key_label="TEST-ONLY GitHub",
        key_fingerprint_12="aabbccddeeff",
        permissions="read repos",
        purpose="list repositories for a TEST-ONLY recap job",
        kind=ApprovalKind.SESSION_CREATION.value,
        other_key_count=2,
        agent_words="please approve fast",
        is_destructive=False,
    )
    params.update(overrides)
    return build_card(**params)


def request_approval(broker, card=None, **overrides):
    card = card or make_card()
    params = dict(
        session_id="sess-test",
        card=card,
        request_hash=compute_request_hash(
            key_id="key-0123456789abcdef",
            provider="github",
            method="GET",
            canonical_path="/repos",
            scope_summary="read repos",
            kind=ApprovalKind.SESSION_CREATION.value,
            level=2,
        ),
        kind=ApprovalKind.SESSION_CREATION.value,
        key_id="key-0123456789abcdef",
        provider="github",
        level=2,
        is_destructive=False,
    )
    params.update(overrides)
    return broker.request(**params)


def full_two_step(broker, pending):
    broker.continue_from_card(pending.approval_id)
    broker.record_gesture(pending.approval_id, ok=True)
    return broker.confirm(pending.approval_id)


class TestApproverOnlyOrigin(unittest.TestCase):
    def test_cli_and_dashboard_cannot_approve(self):
        for channel in ("cli", "dashboard", "agent", "ui", "terminal"):
            with self.assertRaises(OriginRefused):
                refuse_foreign_approval(channel)
        self.assertFalse(cli_or_dashboard_may_approve())

    def test_broker_rejects_forged_origin_decision(self):
        broker, _ = make_broker()
        pending = request_approval(broker)
        decision = full_two_step(broker, pending)
        decision.origin = "dashboard"  # forged after the fact
        with self.assertRaises(OriginRefused):
            broker.verify_and_consume(decision)

    def test_approver_signed_decision_verifies(self):
        broker, _ = make_broker()
        pending = request_approval(broker)
        decision = full_two_step(broker, pending)
        self.assertEqual(decision.origin, APPROVER_CHANNEL)
        self.assertTrue(broker.verify_and_consume(decision))


class TestTwoStepOrdering(unittest.TestCase):
    def test_confirm_before_gesture_rejected(self):
        broker, _ = make_broker()
        pending = request_approval(broker)
        with self.assertRaises(WrongOrder):
            broker.confirm(pending.approval_id)

    def test_gesture_before_continue_rejected(self):
        broker, _ = make_broker()
        pending = request_approval(broker)
        with self.assertRaises(WrongOrder):
            broker.record_gesture(pending.approval_id, ok=True)

    def test_gesture_alone_mints_nothing(self):
        broker, _ = make_broker()
        pending = request_approval(broker)
        broker.continue_from_card(pending.approval_id)
        broker.record_gesture(pending.approval_id, ok=True)
        # No decision exists yet: nothing to verify/consume, and the
        # pending entry is still awaiting the confirm click.
        self.assertEqual(broker.active().state, "confirm")
        self.assertEqual(len(broker._grants), 0)

    def test_failed_gesture_denies(self):
        broker, _ = make_broker()
        pending = request_approval(broker)
        broker.continue_from_card(pending.approval_id)
        with self.assertRaises(ApprovalError):
            broker.record_gesture(pending.approval_id, ok=False)
        self.assertIsNone(broker.active())

    def test_approver_runs_steps_in_order(self):
        broker, _ = make_broker()
        pending = request_approval(broker)
        decision = Approver(broker).approve_via(pending.approval_id)
        self.assertEqual(decision.outcome, "approved")
        self.assertTrue(broker.verify_and_consume(decision))


class TestNonceSingleUse(unittest.TestCase):
    def test_sequential_replay_rejected(self):
        broker, _ = make_broker()
        pending = request_approval(broker)
        decision = full_two_step(broker, pending)
        self.assertTrue(broker.verify_and_consume(decision))
        with self.assertRaises(ApprovalError) as ctx:
            broker.verify_and_consume(decision)
        self.assertEqual(ctx.exception.reason, DenyReason.NONCE_REPLAY)

    def test_concurrent_replay_at_most_one_wins(self):
        broker, _ = make_broker()
        pending = request_approval(broker)
        decision = full_two_step(broker, pending)
        results = []

        def attempt():
            try:
                results.append(broker.verify_and_consume(decision))
            except ApprovalError:
                results.append(False)

        threads = [threading.Thread(target=attempt) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 15)

    def test_request_hash_mismatch_rejected(self):
        broker, _ = make_broker()
        pending = request_approval(broker)
        decision = full_two_step(broker, pending)
        decision.request_hash = "0" * 64
        # Signature no longer matches the tampered payload either.
        with self.assertRaises(ApprovalError):
            broker.verify_and_consume(decision)


class TestTimeoutDeny(unittest.TestCase):
    def test_timeout_at_gesture_denies(self):
        broker, clock = make_broker()
        pending = request_approval(broker, timeout_s=60.0)
        broker.continue_from_card(pending.approval_id)
        clock.advance(61.0)
        with self.assertRaises(ApprovalError) as ctx:
            broker.record_gesture(pending.approval_id, ok=True)
        self.assertEqual(ctx.exception.reason, DenyReason.TIMEOUT_DENY)
        self.assertIsNone(broker.active())

    def test_timeout_at_confirm_denies(self):
        broker, clock = make_broker()
        pending = request_approval(broker, timeout_s=60.0)
        broker.continue_from_card(pending.approval_id)
        broker.record_gesture(pending.approval_id, ok=True)
        clock.advance(61.0)
        with self.assertRaises(ApprovalError) as ctx:
            broker.confirm(pending.approval_id)
        self.assertEqual(ctx.exception.reason, DenyReason.TIMEOUT_DENY)

    def test_accessibility_timeout_120s(self):
        broker, clock = make_broker()
        pending = request_approval(broker, timeout_s=120.0)
        broker.continue_from_card(pending.approval_id)
        clock.advance(90.0)
        broker.record_gesture(pending.approval_id, ok=True)
        decision = broker.confirm(pending.approval_id)
        self.assertEqual(decision.outcome, "approved")

    def test_stale_card_requires_rerender(self):
        broker, clock = make_broker()
        pending = request_approval(broker)
        clock.advance(301.0)
        with self.assertRaises(ApprovalError) as ctx:
            broker.continue_from_card(pending.approval_id)
        self.assertEqual(ctx.exception.reason, DenyReason.STALE_CARD)
        old_pairing = pending.card.pairing
        fresh = broker.re_render_card(pending.approval_id)
        self.assertNotEqual(fresh.pairing, old_pairing)
        self.assertIs(broker.active().card, fresh)


class TestApproveOnce(unittest.TestCase):
    def test_single_use_only(self):
        broker, _ = make_broker()
        req_hash = compute_request_hash(
            key_id="key-0123456789abcdef", provider="github",
            method="DELETE", canonical_path="/repos/x",
            body_sha256_hex="ab" * 32, scope_summary="delete repo",
            kind=ApprovalKind.DESTRUCTIVE.value, level=4,
        )
        card = make_card(
            permissions="delete repository", purpose="delete TEST-ONLY repo",
            kind=ApprovalKind.DESTRUCTIVE.value, is_destructive=True,
        )
        pending = request_approval(
            broker, card=card, request_hash=req_hash,
            kind=ApprovalKind.DESTRUCTIVE.value, level=4, is_destructive=True,
        )
        full_two_step(broker, pending)
        self.assertTrue(broker.spend_grant(
            pending.approval_id, request_hash=req_hash, is_destructive=True))
        # Second identical destructive call within 5 min: NOT authorised.
        self.assertFalse(broker.spend_grant(
            pending.approval_id, request_hash=req_hash, is_destructive=True))

    def test_consumption_deadline_not_validity_window(self):
        broker, clock = make_broker()
        req_hash = compute_request_hash(
            key_id="key-0123456789abcdef", provider="github",
            method="DELETE", canonical_path="/repos/x",
            scope_summary="delete repo",
            kind=ApprovalKind.DESTRUCTIVE.value, level=4,
        )
        card = make_card(
            permissions="delete repository", purpose="delete TEST-ONLY repo",
            kind=ApprovalKind.DESTRUCTIVE.value, is_destructive=True,
        )
        pending = request_approval(
            broker, card=card, request_hash=req_hash,
            kind=ApprovalKind.DESTRUCTIVE.value, level=4, is_destructive=True,
        )
        full_two_step(broker, pending)
        clock.advance(301.0)
        self.assertFalse(broker.spend_grant(
            pending.approval_id, request_hash=req_hash, is_destructive=True))


class TestDestructiveFreshApproval(unittest.TestCase):
    def test_session_scope_grant_cannot_spend_destructive(self):
        broker, _ = make_broker()
        pending = request_approval(broker)  # non-destructive session grant
        full_two_step(broker, pending)
        req_hash = compute_request_hash(
            key_id="key-0123456789abcdef", provider="github",
            method="DELETE", canonical_path="/repos/x",
            scope_summary="delete repo",
            kind=ApprovalKind.DESTRUCTIVE.value, level=4,
        )
        self.assertFalse(broker.spend_grant(
            pending.approval_id, request_hash=req_hash, is_destructive=True))

    def test_no_level3_optout_path_exists(self):
        # There is deliberately no opt-out parameter anywhere: the
        # broker.request signature has no opt_out, and a destructive
        # request always goes through the full two-step ceremony.
        import inspect

        from sealvra import approval

        self.assertNotIn("opt_out", inspect.signature(broker_request := approval.ApprovalBroker.request).parameters)
        self.assertNotIn("opt_out", inspect.signature(approval.ApprovalBroker.confirm).parameters)


class TestX11AndPlatform(unittest.TestCase):
    def test_x11_destructive_refused(self):
        broker, _ = make_broker()
        card = make_card(
            permissions="delete repository", purpose="delete TEST-ONLY repo",
            kind=ApprovalKind.DESTRUCTIVE.value, is_destructive=True,
        )
        with self.assertRaises(ApprovalError) as ctx:
            request_approval(
                broker, card=card, kind=ApprovalKind.DESTRUCTIVE.value,
                level=4, is_destructive=True, display_protocol="x11",
            )
        self.assertEqual(ctx.exception.reason, DenyReason.X11_DESTRUCTIVE_REFUSED)

    def test_xwayland_counts_as_x11(self):
        self.assertEqual(
            detect_display_protocol_with_backend(backend="xwayland"), "x11")
        self.assertEqual(
            detect_display_protocol({"DISPLAY": ":0"}), "x11")
        self.assertEqual(
            detect_display_protocol({"WAYLAND_DISPLAY": "wayland-1"}), "wayland")

    def test_broker_window_never_approves_destructive(self):
        tier = platform_tier_for("linux", system_prompt_available=False)
        self.assertTrue(tier.broker_window_t3)
        self.assertFalse(tier.can_approve_destructive)
        self.assertFalse(broker_window_may_approve(is_destructive=True, tier=tier))
        self.assertTrue(broker_window_may_approve(is_destructive=False, tier=tier))

    def test_remote_destructive_refused(self):
        broker, _ = make_broker()
        card = make_card(
            permissions="delete repository", purpose="delete TEST-ONLY repo",
            kind=ApprovalKind.DESTRUCTIVE.value, is_destructive=True,
        )
        with self.assertRaises(ApprovalError):
            request_approval(
                broker, card=card, kind=ApprovalKind.DESTRUCTIVE.value,
                level=4, is_destructive=True, remote_session=True,
            )

    def test_no_app_password_ever(self):
        with self.assertRaises(ApprovalError) as ctx:
            refuse_app_password()
        self.assertEqual(ctx.exception.reason, DenyReason.APP_PASSWORD_REFUSED)


class TestBreakGlass(unittest.TestCase):
    def test_breakglass_never_covers_destructive(self):
        bg = BreakGlass(
            activation_id="bg-test", active_until_monotonic=999999.0,
            presence_at_wall=0.0,
        )
        self.assertTrue(bg.covers_medium())
        self.assertFalse(bg.covers_destructive())

    def test_breakglass_alone_cannot_spend_destructive(self):
        broker, _ = make_broker()
        bg = BreakGlass(
            activation_id="bg-test", active_until_monotonic=999999.0,
            presence_at_wall=0.0,
        )
        # No grant at all: break-glass presence is not a grant.
        self.assertFalse(broker.spend_grant(
            "appr-nonexistent", request_hash="x" * 64,
            is_destructive=True, breakglass=bg))


class TestSerialisationAndCards(unittest.TestCase):
    def test_one_visible_prompt_at_a_time(self):
        broker, _ = make_broker()
        first = request_approval(broker)
        second = request_approval(broker)
        third = request_approval(broker)
        self.assertEqual(broker.active().approval_id, first.approval_id)
        self.assertEqual(broker.queued_ids(), [second.approval_id, third.approval_id])
        with self.assertRaises(WrongOrder):
            broker.continue_from_card(second.approval_id)
        full_two_step(broker, first)
        self.assertEqual(broker.active().approval_id, second.approval_id)

    def test_max_three_pending(self):
        broker, _ = make_broker()
        request_approval(broker)
        request_approval(broker)
        request_approval(broker)
        with self.assertRaises(ApprovalError) as ctx:
            request_approval(broker)
        self.assertEqual(ctx.exception.reason, DenyReason.PENDING_CAP)

    def test_card_headline_has_no_agent_text_and_count_only_negative(self):
        card = make_card()
        rendered = card.render()
        self.assertNotIn("please approve fast", rendered["headline"])
        self.assertIn("please approve fast", rendered["agent_words_unverified"])
        self.assertEqual(
            rendered["negative_list"], "and 2 other keys are NOT included")
        self.assertIn("never asks for your device passcode", rendered["footer"])
        self.assertIsNone(rendered["password_field"])
        self.assertEqual(rendered["key_fingerprint_12"], "aabbccddeeff")

    def test_kill_needs_no_auth(self):
        broker, _ = make_broker()
        pending = request_approval(broker)
        broker.kill_pending(pending.approval_id)
        self.assertIsNone(broker.active())

    def test_key_lifecycle_voids_pending(self):
        broker, _ = make_broker()
        pending = request_approval(broker)
        voided = broker.void_on_key_lifecycle(key_id="key-0123456789abcdef")
        self.assertIn(pending.approval_id, voided)
        self.assertIsNone(broker.active())


class TestConsoleGrants(unittest.TestCase):
    def test_grant_max_two_hours_and_single_start(self):
        with self.assertRaises(ApprovalError):
            create_console_grant(
                key_id="key-1", scope_summary="read repos",
                seat_verified=True, duration_s=7201.0)
        with self.assertRaises(ApprovalError):
            create_console_grant(
                key_id="key-1", scope_summary="read repos",
                seat_verified=False)
        with self.assertRaises(ApprovalError):
            create_console_grant(
                key_id="key-1", scope_summary="delete repo",
                seat_verified=True, is_destructive_scope=True)
        grant = create_console_grant(
            key_id="key-1", scope_summary="read repos", seat_verified=True)
        self.assertIsInstance(grant, ConsoleGrant)
        self.assertTrue(grant.covers(key_id="key-1", scope_summary="read repos"))
        self.assertFalse(grant.covers(key_id="key-2", scope_summary="read repos"))
        grant.starts_used = 1
        self.assertFalse(grant.covers(key_id="key-1", scope_summary="read repos"))

    def test_headless_without_grant_refused(self):
        broker, _ = make_broker()
        with self.assertRaises(ApprovalError) as ctx:
            request_approval(broker, headless=True)
        self.assertEqual(ctx.exception.reason, DenyReason.HEADLESS_NO_GRANT)


class TestFatigueAndEnrolment(unittest.TestCase):
    def test_fatigue_progressive_friction(self):
        tracker = FatigueTracker("sess-1")
        import time as _time

        base = _time.monotonic()
        self.assertEqual(tracker.record_shown(now=base).value, "normal")
        tracker2 = FatigueTracker("sess-2")
        tracker2.record_shown(now=base)
        tracker2.record_shown(now=base + 10)
        tracker2.record_shown(now=base + 20)
        self.assertTrue(tracker2.typed_confirmation_required(now=base + 20))
        tracker2.record_shown(now=base + 30)
        tracker2.record_shown(now=base + 40)
        self.assertEqual(tracker2.state(now=base + 40).value, "paused")

    def test_fatigue_anomaly_threshold_pauses(self):
        tracker = FatigueTracker("sess-1")
        self.assertFalse(tracker.record_anomaly())
        self.assertFalse(tracker.record_anomaly())
        self.assertTrue(tracker.record_anomaly())
        self.assertEqual(tracker.state().value, "paused")
        tracker.clear_anomaly_pause_after_seal_rotation()
        self.assertEqual(tracker.state().value, "normal")

    def test_typed_confirmation_enforced_at_third_prompt(self):
        broker, _ = make_broker()
        for _ in range(2):
            pending = request_approval(broker)
            full_two_step(broker, pending)
        third = request_approval(broker)
        broker.continue_from_card(third.approval_id)
        broker.record_gesture(third.approval_id, ok=True)
        with self.assertRaises(WrongOrder):
            broker.confirm(third.approval_id)
        decision = broker.confirm(third.approval_id, typed="list repositories")
        self.assertEqual(decision.outcome, "approved")

    def test_enrolment_change_posture(self):
        monitor_broker, _ = make_broker()
        card = make_card(
            permissions="delete repository", purpose="delete TEST-ONLY repo",
            kind=ApprovalKind.DESTRUCTIVE.value, is_destructive=True,
        )
        pending = request_approval(
            monitor_broker, card=card, kind=ApprovalKind.DESTRUCTIVE.value,
            level=4, is_destructive=True,
        )
        monitor_broker.enrolment.observe("state-a", trigger="approval")
        self.assertFalse(monitor_broker.enrolment.observe("state-a", trigger="poll"))
        voided = monitor_broker.enrolment_changed()
        self.assertIn(pending.approval_id, voided)
        self.assertTrue(monitor_broker.enrolment.password_only_next)
        self.assertTrue(monitor_broker.enrolment.kill_all_triggered)


# ---------------------------------------------------------------------------
# W14 (v0.2) additions: approval hardening against f04
# ---------------------------------------------------------------------------

TEST_SEAL = ApprovalSeal(passphrase="TEST-ONLY-harbour-lamp", image_id="img-test-1", version=1)
TEST_SEAL_V2 = ApprovalSeal(passphrase="TEST-ONLY-river-stone", image_id="img-test-2", version=2)


def make_sealed_card(seal=TEST_SEAL, **overrides):
    return make_card(seal=seal, **overrides)


def make_sealed_broker(seal=TEST_SEAL, **kwargs):
    clock = FakeClock()
    broker = ApprovalBroker(
        clock=clock, min_card_dwell_s=0, seal=seal, seal_required=True,
        **kwargs,
    )
    return broker, clock


def request_destructive(broker, card=None, **overrides):
    card = card or make_card(
        permissions="delete repository", purpose="delete TEST-ONLY repo",
        kind=ApprovalKind.DESTRUCTIVE.value, is_destructive=True,
    )
    req_hash = compute_request_hash(
        key_id="key-0123456789abcdef", provider="github",
        method="DELETE", canonical_path="/repos/x",
        body_sha256_hex="ab" * 32, scope_summary="delete repo",
        kind=ApprovalKind.DESTRUCTIVE.value, level=4,
    )
    params = dict(
        session_id="sess-test", card=card, request_hash=req_hash,
        kind=ApprovalKind.DESTRUCTIVE.value,
        key_id="key-0123456789abcdef", provider="github", level=4,
        is_destructive=True,
    )
    params.update(overrides)
    return broker.request(**params), req_hash


class TestTwoStepUniversalW14(unittest.TestCase):
    """f04 J-01: two-step universally for session creation + destructive.

    Biometric alone is presence, not authorisation: no kind has a
    gesture-only approval path, and no identical-scope shortcut exists.
    """

    def test_destructive_gesture_alone_mints_nothing(self):
        broker, _ = make_broker()
        pending, _ = request_destructive(broker)
        broker.continue_from_card(pending.approval_id)
        broker.record_gesture(pending.approval_id, ok=True)
        self.assertEqual(broker.active().state, "confirm")
        self.assertEqual(len(broker._grants), 0)

    def test_session_creation_gesture_alone_mints_nothing(self):
        broker, _ = make_broker()
        pending = request_approval(broker)
        broker.continue_from_card(pending.approval_id)
        broker.record_gesture(pending.approval_id, ok=True)
        self.assertEqual(broker.active().state, "confirm")
        self.assertEqual(len(broker._grants), 0)

    def test_requires_two_step_truth_table(self):
        self.assertTrue(requires_two_step(
            kind=ApprovalKind.SESSION_CREATION.value, is_destructive=False))
        self.assertTrue(requires_two_step(
            kind=ApprovalKind.DESTRUCTIVE.value, is_destructive=True))
        self.assertTrue(requires_two_step(
            kind=ApprovalKind.SESSION_SCOPE.value, is_destructive=True))
        # Non-destructive in-session routine calls are the only kind
        # outside the universal rule (authorised at session creation).
        self.assertFalse(requires_two_step(
            kind=ApprovalKind.SESSION_SCOPE.value, is_destructive=False))

    def test_no_biometric_only_path_exists(self):
        import inspect

        from sealvra import approval

        for name in ("identical_scope_reapproval", "biometric_only_approve",
                     "approve_with_gesture_only"):
            self.assertFalse(hasattr(approval, name), name)
        self.assertNotIn("gesture_only",
                         inspect.signature(approval.ApprovalBroker.confirm).parameters)


class TestCardToPromptRaceW14(unittest.TestCase):
    """f04 A-03/A-04, v3 N-E7: click-to-continue, frontmost, pairing word."""

    def test_system_prompt_cannot_fire_before_continue(self):
        broker, _ = make_broker()
        pending = request_approval(broker)
        with self.assertRaises(WrongOrder):
            broker.begin_system_prompt(pending.approval_id)
        # Approver path fires the prompt only after the continue click.
        decision = Approver(broker).approve_via(pending.approval_id)
        self.assertEqual(decision.outcome, "approved")

    def test_pairing_word_on_card_and_prompt_reason(self):
        card = make_card()
        reason = os_prompt_reason(card)
        self.assertIn(card.pairing, card.headline())
        self.assertIn(card.pairing, reason)
        self.assertIn("Sealvra", reason)

    def test_pairing_word_platform_limits_honest(self):
        self.assertEqual(pairing_word_os_prompt_support("darwin"), "full")
        self.assertEqual(pairing_word_os_prompt_support("linux"), "partial")
        self.assertEqual(pairing_word_os_prompt_support("win32"), "unsupported")
        self.assertEqual(pairing_word_os_prompt_support("headless"), "unsupported")

    def test_timeout_clock_starts_at_system_prompt_not_continue(self):
        broker, clock = make_broker()
        pending = request_approval(broker, timeout_s=60.0)
        broker.continue_from_card(pending.approval_id)
        clock.advance(50.0)  # slow reader between card and prompt: untimed
        broker.begin_system_prompt(pending.approval_id)
        clock.advance(30.0)  # only 30 s of prompt time
        broker.record_gesture(pending.approval_id, ok=True)
        decision = broker.confirm(pending.approval_id)
        self.assertEqual(decision.outcome, "approved")

    def test_focus_loss_voids_active_and_activates_next(self):
        broker, _ = make_broker()
        first = request_approval(broker)
        second = request_approval(broker)
        self.assertTrue(broker.mark_card_obscured(first.approval_id))
        self.assertEqual(broker.active().approval_id, second.approval_id)
        with self.assertRaises(WrongOrder):
            broker.continue_from_card(first.approval_id)

    def test_focus_loss_during_gesture_denies(self):
        broker, _ = make_broker()
        pending = request_approval(broker)
        broker.continue_from_card(pending.approval_id)
        broker.begin_system_prompt(pending.approval_id)
        broker.mark_card_obscured(pending.approval_id)
        self.assertIsNone(broker.active())

    def test_queued_prompt_cannot_fire_system_prompt(self):
        broker, _ = make_broker()
        request_approval(broker)
        second = request_approval(broker)
        with self.assertRaises(WrongOrder):
            broker.begin_system_prompt(second.approval_id)
        with self.assertRaises(WrongOrder):
            broker.record_gesture(second.approval_id, ok=True)


class TestSealMandatoryW14(unittest.TestCase):
    """v3 N-E7 side taken: passphrase + image + receipt, keychain-gated,
    mandatory. The OD-04 dissent is recorded, not implemented."""

    def test_seal_store_refuses_file_backends(self):
        for backend in ("file", "0600-file", "plaintext", ""):
            with self.assertRaises(ApprovalError) as ctx:
                SealStore(backend=backend)
            self.assertEqual(ctx.exception.reason, DenyReason.SEAL_STORAGE_REFUSED)
        store = SealStore(backend="keychain-acl")
        with self.assertRaises(ApprovalError) as ctx:
            store.save(TEST_SEAL, path="/tmp/TEST-ONLY-seal.json")
        self.assertEqual(ctx.exception.reason, DenyReason.SEAL_STORAGE_REFUSED)
        store.save(TEST_SEAL)
        self.assertEqual(store.load(), TEST_SEAL)

    def test_sealed_card_carries_seal_and_prompt_reason(self):
        card = make_sealed_card()
        rendered = card.render()
        self.assertEqual(rendered["seal"]["passphrase"], TEST_SEAL.passphrase)
        self.assertEqual(rendered["seal"]["image_id"], TEST_SEAL.image_id)
        self.assertIn(TEST_SEAL.passphrase, os_prompt_reason(card))

    def test_seal_mismatch_refused_no_prompt_shown(self):
        broker, _ = make_sealed_broker()
        wrong = make_card(seal=ApprovalSeal(
            passphrase="TEST-ONLY-wrong", image_id="img-test-9", version=9))
        with self.assertRaises(ApprovalError) as ctx:
            request_approval(broker, card=wrong)
        self.assertEqual(ctx.exception.reason, DenyReason.SEAL_MISMATCH)
        self.assertIsNone(broker.active())

    def test_seal_required_refuses_seal_less_card(self):
        # Seal-less card on a sealed broker: mismatch (empty != seal).
        broker, _ = make_sealed_broker()
        with self.assertRaises(ApprovalError) as ctx:
            request_approval(broker, card=make_card())
        self.assertEqual(ctx.exception.reason, DenyReason.SEAL_MISMATCH)
        # Seal-required broker with no seal configured: seal-less card
        # is refused as missing, not silently accepted.
        clock = FakeClock()
        bare_required = ApprovalBroker(
            clock=clock, min_card_dwell_s=0, seal=None, seal_required=True)
        with self.assertRaises(ApprovalError) as ctx:
            request_approval(bare_required, card=make_card())
        self.assertEqual(ctx.exception.reason, DenyReason.SEAL_MISSING)

    def test_sealed_approval_binds_seal_version(self):
        broker, _ = make_sealed_broker()
        pending = request_approval(broker, card=make_sealed_card())
        decision = Approver(broker).approve_via(pending.approval_id)
        self.assertEqual(decision.seal_version, TEST_SEAL.version)
        self.assertTrue(broker.verify_and_consume(decision))

    def test_anomaly_pause_needs_real_rotation_when_seal_bound(self):
        broker, _ = make_sealed_broker()
        pending = request_approval(broker, card=make_sealed_card())
        tracker = broker.fatigue[pending.session_id]
        tracker.record_anomaly()
        tracker.record_anomaly()
        tracker.record_anomaly()
        self.assertEqual(tracker.state().value, "paused")
        # No-arg clear is refused once a seal is bound.
        with self.assertRaises(ApprovalError) as ctx:
            tracker.clear_anomaly_pause_after_seal_rotation()
        self.assertEqual(ctx.exception.reason, DenyReason.SEAL_ROTATION_REQUIRED)
        # Same-version "rotation" is refused too.
        with self.assertRaises(ApprovalError):
            tracker.clear_anomaly_pause_after_seal_rotation(TEST_SEAL.version)
        # Broker rotation to a genuinely new seal clears the pause.
        broker.rotate_seal(TEST_SEAL_V2)
        self.assertEqual(tracker.state().value, "normal")
        self.assertEqual(broker.seal, TEST_SEAL_V2)
        with self.assertRaises(ApprovalError):
            broker.rotate_seal(TEST_SEAL_V2)  # identical re-rotation refused


class TestTwoIdenticalDestructiveCallsW14(unittest.TestCase):
    """f04 D-03 / task-required test: the second identical destructive
    call needs its OWN approval; approve-once is a consumption
    deadline, not a validity window."""

    def test_second_identical_call_needs_own_approval(self):
        broker, clock = make_broker()
        pending1, req_hash = request_destructive(broker)
        full_two_step(broker, pending1)
        self.assertTrue(broker.spend_grant(
            pending1.approval_id, request_hash=req_hash, is_destructive=True))
        # Identical second call, 60 s later, on the first approval: denied.
        clock.advance(60.0)
        self.assertFalse(broker.spend_grant(
            pending1.approval_id, request_hash=req_hash, is_destructive=True))
        # A fresh full ceremony for the identical call authorises it.
        pending2, req_hash2 = request_destructive(broker)
        self.assertEqual(req_hash2, req_hash)
        full_two_step(broker, pending2)
        self.assertTrue(broker.spend_grant(
            pending2.approval_id, request_hash=req_hash2, is_destructive=True))

    def test_expired_grant_is_pruned_not_reusable(self):
        broker, clock = make_broker()
        pending, req_hash = request_destructive(broker)
        full_two_step(broker, pending)
        clock.advance(301.0)
        self.assertFalse(broker.spend_grant(
            pending.approval_id, request_hash=req_hash, is_destructive=True))
        self.assertNotIn(pending.approval_id, broker._grants)


class TestBreakGlassExclusionW14(unittest.TestCase):
    """v3 N-E9 / f04 H-03: break-glass never substitutes for a
    destructive approval, with or without any grant."""

    def test_breakglass_plus_nondestructive_grant_cannot_spend_destructive(self):
        broker, _ = make_broker()
        bg = BreakGlass(
            activation_id="bg-test", active_until_monotonic=999999.0,
            presence_at_wall=0.0,
        )
        pending = request_approval(broker)  # non-destructive session grant
        full_two_step(broker, pending)
        req_hash = compute_request_hash(
            key_id="key-0123456789abcdef", provider="github",
            method="DELETE", canonical_path="/repos/x",
            scope_summary="delete repo",
            kind=ApprovalKind.DESTRUCTIVE.value, level=4,
        )
        self.assertFalse(broker.spend_grant(
            pending.approval_id, request_hash=req_hash,
            is_destructive=True, breakglass=bg))

    def test_destructive_with_breakglass_still_needs_full_ceremony(self):
        broker, _ = make_broker()
        bg = BreakGlass(
            activation_id="bg-test", active_until_monotonic=999999.0,
            presence_at_wall=0.0,
        )
        pending, req_hash = request_destructive(broker, breakglass=bg)
        # No spend possible before the ceremony, break-glass or not.
        self.assertFalse(broker.spend_grant(
            pending.approval_id, request_hash=req_hash,
            is_destructive=True, breakglass=bg))
        full_two_step(broker, pending)
        self.assertTrue(broker.spend_grant(
            pending.approval_id, request_hash=req_hash,
            is_destructive=True, breakglass=bg))

    def test_breakglass_labelled_preauthorisation_not_approval(self):
        bg = BreakGlass(
            activation_id="bg-test", active_until_monotonic=999999.0,
            presence_at_wall=0.0,
        )
        label = bg.preauthorisation_label()
        self.assertIn("pre-authorisation", label)
        self.assertIn("not an approval", label)
        self.assertIn("never destructive", label)


class TestSerialisationAndFatigueSingleMachineW14(unittest.TestCase):
    """v3 N-E4: ONE fatigue state machine; no second set of limits,
    no second resume path. Recovery is the 15-min window only."""

    def test_pause_resume_is_window_expiry_only(self):
        broker, clock = make_broker()
        # Drive 5 prompts in 5 min: the 5th enters the pause window.
        for _ in range(5):
            pending = request_approval(broker)
            # 3rd+ prompts need typed confirmation (friction).
            broker.continue_from_card(pending.approval_id)
            broker.record_gesture(pending.approval_id, ok=True)
            try:
                broker.confirm(pending.approval_id)
            except WrongOrder:
                broker.confirm(pending.approval_id, typed="TEST-ONLY action")
        tracker = broker.fatigue["sess-test"]
        # Tracker state is clocked by the broker's FakeClock here, not
        # wall monotonic (production uses real monotonic throughout).
        self.assertEqual(tracker.state(now=clock.now).value, "paused")
        self.assertEqual(tracker.session_count, 5)
        # Queued prompts during the pause auto-deny WITHOUT counting.
        for _ in range(2):
            request_approval(broker)
        self.assertIsNone(broker.active())
        self.assertEqual(tracker.session_count, 5)
        # Still paused before the window expires; normal after it.
        # (Activation auto-denies during the pause: request() itself
        # does not raise, it just leaves no active prompt.)
        clock.advance(899.0)
        request_approval(broker)
        self.assertIsNone(broker.active())
        clock.advance(2.0)
        pending = request_approval(broker)
        self.assertIs(broker.active(), pending)

    def test_no_second_fatigue_resume_api(self):
        import inspect

        from sealvra import approval

        for name in ("resume_with_os_auth", "reenable_with_os_auth",
                     "resume_after_review", "os_auth_resume"):
            self.assertFalse(hasattr(approval, name), name)
            self.assertFalse(hasattr(approval.FatigueTracker, name), name)
        self.assertNotIn("os_auth",
                         inspect.signature(
                             approval.FatigueTracker.clear_anomaly_pause_after_seal_rotation
                         ).parameters)

    def test_auto_denied_prompts_do_not_count(self):
        tracker = FatigueTracker("sess-1")
        import time as _time

        base = _time.monotonic()
        for i in range(5):
            tracker.record_shown(now=base + i * 10)
        self.assertEqual(tracker.state(now=base + 50).value, "paused")
        with self.assertRaises(ApprovalError) as ctx:
            tracker.record_shown(now=base + 60)
        self.assertEqual(ctx.exception.reason, DenyReason.FATIGUE_PAUSED)
        self.assertEqual(tracker.session_count, 5)


if __name__ == "__main__":
    unittest.main()
