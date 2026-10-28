"""W13 platform tests (unittest).

IMPORTANT LABELLING: this VM runs Linux. Tests that pass an explicit
platform argument ("darwin", "win32") are MOCKED-PLATFORM tests: they
exercise the gate logic for that platform branch, and they are NEVER
a pass on real macOS or real Windows, and never prove native
Keychain/DPAPI/Hello behaviour. Only tests with no platform argument
(or platform="linux") run on the real platform here, and even those
prove gate logic only — this module makes no native OS calls.

No real keys anywhere: only TEST-ONLY fake values, and none are
needed here at all.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from keyholder import platform as P


def mocked(platform_name):
    """Marker helper: documents that a test is mocked-platform."""
    return platform_name


class TestStorageTiers(unittest.TestCase):
    def test_macos_is_s1_mocked_platform(self):
        info = P.storage_tier(mocked("darwin"))
        self.assertEqual(info.tier, "S1")
        self.assertFalse(info.same_user_direct_read)

    def test_windows_is_s2_not_s1_mocked_platform(self):
        info = P.storage_tier(mocked("win32"))
        self.assertEqual(info.tier, "S2")
        self.assertTrue(info.same_user_direct_read)
        self.assertIn("CryptUnprotectData", info.description)

    def test_linux_is_s3_mocked_platform(self):
        info = P.storage_tier(mocked("linux"))
        self.assertEqual(info.tier, "S3")
        self.assertTrue(info.same_user_direct_read)

    def test_password_file_is_s0_everywhere(self):
        for plat in ("darwin", "win32", "linux"):
            self.assertEqual(
                P.storage_tier(mocked(plat), backend="password_file").tier, "S0")

    def test_unknown_platform_raises_not_fallthrough(self):
        with self.assertRaises(P.PlatformUnsupportedError):
            P.storage_tier("plan9")
        with self.assertRaises(P.PlatformUnsupportedError):
            P.current_platform("freebsd")

    def test_unknown_backend_raises(self):
        with self.assertRaises(ValueError):
            P.storage_tier("linux", backend="magic")


class TestApprovalMechanisms(unittest.TestCase):
    def test_hello_pin_and_biometric_are_different_mocked_platform(self):
        bio = P.hello_tier(kind="biometric")
        pin = P.hello_tier(kind="pin")
        self.assertEqual(bio.tier, "T1")
        self.assertEqual(pin.tier, "T1")
        self.assertNotEqual(bio.mechanism, pin.mechanism)
        self.assertIn("pin", pin.mechanism.lower())
        self.assertTrue(bio.boolean_only)
        self.assertFalse(pin.boolean_only)

    def test_windows_password_split_mocked_platform(self):
        helper = P.windows_password_tier(with_helper=True)
        raw = P.windows_password_tier(with_helper=False)
        self.assertTrue(helper.boolean_only)
        self.assertFalse(raw.boolean_only)
        self.assertIn("app memory", raw.mechanism.lower())

    def test_t2_macos_linux_boolean_only_vs_windows_in_memory(self):
        la = P.approval_tier(mocked("darwin"), mechanism="la_context_password")
        pol = P.approval_tier(mocked("linux"), mechanism="polkit_password")
        self.assertTrue(la.boolean_only and pol.boolean_only)
        raw = P.approval_tier(mocked("win32"),
                              mechanism="windows_password_in_memory")
        self.assertFalse(raw.boolean_only)

    def test_t3_wayland_vs_x11_labels_differ(self):
        w = P.approval_tier("linux", mechanism="broker_window_wayland")
        x = P.approval_tier("linux", mechanism="broker_window_x11")
        self.assertEqual(w.tier, x.tier)
        self.assertNotEqual(w.mechanism, x.mechanism)
        self.assertIn("injectable", x.mechanism.lower())

    def test_labels_always_carry_mechanism(self):
        info = P.approval_tier("linux", mechanism="polkit_password")
        self.assertIn("polkit", P.display_label(info).lower())

    def test_unknown_mechanism_raises(self):
        with self.assertRaises(ValueError):
            P.approval_tier("linux", mechanism="face_id")


class TestDisplayBackend(unittest.TestCase):
    def test_toolkit_x11_beats_xdg_session_type(self):
        # XDG_SESSION_TYPE is not even an input; a Wayland login
        # session with an X11 toolkit backend is XWayland.
        info = P.detect_display_backend(
            toolkit_backend="x11", env={"WAYLAND_DISPLAY": "wayland-1"})
        self.assertEqual(info["backend"], "xwayland")
        self.assertTrue(P.is_x11_backend(info))

    def test_wayland_toolkit_is_not_x11(self):
        info = P.detect_display_backend(toolkit_backend="wayland")
        self.assertEqual(info["backend"], "wayland")
        self.assertFalse(P.is_x11_backend(info))

    def test_ambiguous_is_treated_as_x11(self):
        info = P.detect_display_backend(
            env={"WAYLAND_DISPLAY": "wayland-1", "DISPLAY": ":0"})
        self.assertEqual(info["backend"], "ambiguous")
        self.assertTrue(P.is_x11_backend(info))

    def test_headless_detected(self):
        info = P.detect_display_backend(env={})
        self.assertEqual(info["backend"], "headless")

    def test_gdk_backend_env_parsed(self):
        info = P.detect_display_backend(env={"GDK_BACKEND": "x11"})
        self.assertEqual(info["backend"], "x11")


class TestX11Refusal(unittest.TestCase):
    def test_destructive_refused_on_x11_and_xwayland(self):
        for backend in ("x11", "xwayland", "ambiguous"):
            dec = P.approval_allowed_for_session_class(
                "destructive", backend_info={"backend": backend})
            self.assertFalse(dec.allowed, backend)

    def test_key_lifecycle_refused_on_x11(self):
        dec = P.approval_allowed_for_session_class(
            "key_lifecycle", backend_info={"backend": "x11"})
        self.assertFalse(dec.allowed)

    def test_read_only_allowed_with_badge_on_x11(self):
        dec = P.approval_allowed_for_session_class(
            "read_public", backend_info={"backend": "x11"})
        self.assertTrue(dec.allowed)
        self.assertIn("X11", dec.badge)

    def test_destructive_allowed_on_wayland_gate_only(self):
        dec = P.approval_allowed_for_session_class(
            "destructive", backend_info={"backend": "wayland"})
        self.assertTrue(dec.allowed)

    def test_broker_click_never_approves_destructive(self):
        self.assertFalse(P.broker_window_can_approve("destructive"))
        self.assertFalse(P.broker_window_can_approve("key_lifecycle"))
        self.assertTrue(P.broker_window_can_approve("read_public"))


class TestPolkit(unittest.TestCase):
    def good(self, **over):
        base = dict(action_installed=True, agent_running=True,
                    agent_owner_path="/usr/lib/polkit-gnome/"
                    "polkit-gnome-authentication-agent-1",
                    allow_any="no", allow_inactive="no",
                    retained_authorisation=False, fresh_challenge=True,
                    observed_method="password")
        base.update(over)
        return P.PolkitStatus(**base)

    def test_action_and_agent_probed_separately(self):
        probe = P.polkit_probe(action_installed=True, agent_running=False)
        self.assertTrue(probe["polkit_action_installed"])
        self.assertFalse(probe["polkit_path_available"])
        probe2 = P.polkit_probe(action_installed=False, agent_running=True)
        self.assertFalse(probe2["polkit_path_available"])

    def test_missing_action_degrades(self):
        dec = P.evaluate_polkit(self.good(action_installed=False))
        self.assertFalse(dec.allowed)

    def test_unknown_agent_treated_as_absent(self):
        dec = P.evaluate_polkit(
            self.good(agent_owner_path="/tmp/evil-agent"))
        self.assertFalse(dec.allowed)
        dec2 = P.evaluate_polkit(self.good(agent_owner_path=None))
        self.assertFalse(dec2.allowed)

    def test_allow_any_or_inactive_refused(self):
        self.assertFalse(P.evaluate_polkit(self.good(allow_any="yes")).allowed)
        self.assertFalse(
            P.evaluate_polkit(self.good(allow_inactive="auth_self")).allowed)

    def test_retained_and_stale_refused(self):
        self.assertFalse(
            P.evaluate_polkit(self.good(retained_authorisation=True)).allowed)
        self.assertFalse(
            P.evaluate_polkit(self.good(fresh_challenge=False)).allowed)

    def test_fingerprint_only_when_observed(self):
        dec = P.evaluate_polkit(self.good(observed_method="fingerprint"))
        self.assertTrue(dec.allowed)
        self.assertIn("fingerprint", dec.approval.mechanism.lower())
        dec2 = P.evaluate_polkit(self.good(observed_method=None))
        self.assertTrue(dec2.allowed)
        self.assertEqual(dec2.approval.tier, "T2")  # never silent T1

    def test_system_install_path_in_probe_text(self):
        probe = P.polkit_probe(action_installed=False, agent_running=False)
        self.assertIn("/usr/share/polkit-1/actions/",
                      probe["install_requirement"])


class TestKeyringAndRemote(unittest.TestCase):
    def test_migration_requires_all_three_checks(self):
        ok = P.check_keyring_migration(
            new_password_differs_from_login=True,
            old_items_deleted_and_verified=True,
            lock_state_checked_at_mint=True)
        self.assertTrue(ok["migration_valid"])
        bad = P.check_keyring_migration(
            new_password_differs_from_login=False,
            old_items_deleted_and_verified=True,
            lock_state_checked_at_mint=True)
        self.assertFalse(bad["migration_valid"])

    def test_remote_typed_pin_never_t1(self):
        tier = P.remote_session_tier(remote=True, mechanism="hello_pin")
        self.assertIsNotNone(tier)
        self.assertEqual(tier.tier, "T2")

    def test_consumer_rdp_no_tier(self):
        self.assertIsNone(P.remote_session_tier(
            remote=True, mechanism="hello_biometric"))

    def test_remote_credential_guard_t1_with_badge_context(self):
        tier = P.remote_session_tier(
            remote=True, mechanism="hello_biometric", credential_guard=True)
        self.assertIsNotNone(tier)
        self.assertEqual(tier.tier, "T1")

    def test_remote_coverage_lists_undetected_tools(self):
        cov = P.remote_access_coverage()
        self.assertIn("TeamViewer", cov["not_detected"])
        self.assertIn("VNC", cov["not_detected"])

    def test_headless_refused_without_grant(self):
        self.assertFalse(
            P.headless_approval(under_console_grant=False).allowed)

    def test_console_grant_never_destructive(self):
        grant = P.console_grant_allowed(
            seat_active=True, seat_assigned=True, remote=False,
            gui_present=True, scope="destructive")
        self.assertFalse(grant["allowed"])

    def test_console_grant_requires_local_active_seat(self):
        grant = P.console_grant_allowed(
            seat_active=True, seat_assigned=True, remote=True,
            gui_present=True, scope="read_only")
        self.assertFalse(grant["allowed"])
        good = P.console_grant_allowed(
            seat_active=True, seat_assigned=True, remote=False,
            gui_present=True, scope="read_only")
        self.assertTrue(good["allowed"])
        self.assertEqual(good["approval_method"], "console_grant")


class TestScopeAndPosture(unittest.TestCase):
    def test_wsl_container_crostini_xrdp_scoping(self):
        self.assertFalse(P.scope_for_environment("wsl")["session_mint_allowed"])
        self.assertFalse(
            P.scope_for_environment("container")["session_mint_allowed"])
        self.assertEqual(
            P.scope_for_environment("xrdp")["matrix_row"], "X11")
        self.assertEqual(
            P.scope_for_environment("crostini")["matrix_row"], "X11")

    def test_screen_sharing_is_unknown_not_false(self):
        status = P.screen_sharing_status()
        self.assertFalse(status["screen_sharing_known"])
        self.assertIsNone(status["screen_sharing_active"])
        self.assertIsNone(status["detector"])
        self.assertIn("screen sharing", status["standing_reminder"].lower())
        self.assertFalse(hasattr(P, "detect_screen_sharing"))

    def test_posture_records_all_fields_real_linux(self):
        # Real-platform test (this VM is Linux): no mocked platform.
        rec = P.posture(
            approval_mechanism="polkit_password",
            backend_info={"backend": "wayland"},
            seat="seat0", remote=False)
        self.assertEqual(rec["storage_tier"], "S3")
        self.assertEqual(rec["approval_tier"], "T2")
        self.assertEqual(rec["display_backend"], "wayland")
        self.assertEqual(rec["seat"], "seat0")
        self.assertFalse(rec["remote"])
        self.assertIn("macOS", rec["honest_parity_statement"])

    def test_posture_mocked_windows_carries_tpm_domain(self):
        rec = P.posture(
            platform=mocked("win32"),
            approval_mechanism="hello_biometric",
            backend_info={"backend": "wayland"},
            tpm="virtual", domain_joined=True)
        self.assertEqual(rec["storage_tier"], "S2")
        self.assertEqual(rec["tpm_domain"]["tpm"], "virtual")
        self.assertTrue(rec["tpm_domain"]["domain_joined"])

    def test_grace_window_banned_for_destructive(self):
        self.assertFalse(P.grace_window_valid(
            session_class="destructive", session_type_changed=False,
            screen_locked=False))
        self.assertFalse(P.grace_window_valid(
            session_class="read_public", session_type_changed=True,
            screen_locked=False))
        self.assertTrue(P.grace_window_valid(
            session_class="read_public", session_type_changed=False,
            screen_locked=False))

    def test_unprovable_on_linux_lists_macos_windows(self):
        missing = P.unprovable_on_platform("linux")
        self.assertTrue(any("Keychain" in m for m in missing))
        self.assertTrue(any("Hello" in m for m in missing))

    def test_tier_scope_known_and_unknown(self):
        self.assertIn("NOT survive", P.tier_scope("file_permissions_0600")["tier_scope"])
        with self.assertRaises(ValueError):
            P.tier_scope("telepathy")

    def test_macos_design_mocked(self):
        design = P.macos_keychain_design(strict_biometry=True)
        self.assertEqual(design["storage_tier"], "S1")
        self.assertIn("one Keychain item per stored key", design["items"])
        self.assertTrue(any("biometryCurrentSet" in f
                            for f in design["access_control_flags"]))

    def test_windows_helper_design_is_boolean_only(self):
        design = P.windows_verifier_helper_design()
        self.assertIn("boolean only", design["return_value"])

    def test_vault_unlock_carve_out_x11_warning(self):
        entry = P.vault_unlock_password_entry(backend_info={"backend": "x11"})
        self.assertTrue(entry["x11_keyloggable"])
        self.assertIn("session approval", entry["never_extends_to"])


if __name__ == "__main__":
    unittest.main()
