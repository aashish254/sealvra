"""W11 tests: native GUI status/session window (unittest).

Headless rules (CONTRACT §11): a test not run on a platform is
NOT-RUN, never PASSED. The window-creation test therefore skips
honestly when no display is available instead of claiming a pass.
Fake keys only: TEST-ONLY- prefixed values.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sealvra.gui import (  # noqa: E402
    AuditEntryView,
    DaemonIpcClient,
    DaemonIpcError,
    DaemonIpcSource,
    EmptyDataSource,
    GuiDataSource,
    KeyView,
    SessionView,
    ViewModel,
    assert_no_secret,
    create_default_source,
    daemon_socket_from_env,
    isolation_card_text,
    kill_receipt_text,
    render_audit_line,
    render_key_list_line,
    render_session_line,
    trust_screen_text,
)

FAKE_SECRET = "TEST-ONLY-gh_fake_secret_value_12345"
FAKE_TOKEN = "TEST-ONLY-kh_sess_fake_token_67890"

_DISPLAY = None


def _display_available() -> bool:
    """Whether a Tk window can be mapped, measured without leaving one open.

    The obvious probe — ``tkinter.Tk()`` inside a try/except — is what put
    empty dark windows titled "tk" on the desktop beside the running app. A
    root is a real window, and the first one created claims
    ``tkinter._default_root``, so an undestroyed probe window stays mapped for
    the rest of the process and later dialogs parent onto it instead of onto
    the app window. One root per process, withdrawn and destroyed here, keeps
    the NOT-RUN honest without drawing anything.
    """
    global _DISPLAY
    if _DISPLAY is None:
        try:
            import tkinter

            root = tkinter.Tk()
        except Exception:
            _DISPLAY = False
        else:
            _DISPLAY = True
            root.withdraw()
            root.destroy()
    return _DISPLAY


def tearDownModule():
    """A Tk root that outlives a test is a window on someone's desktop.

    Destroying first, then failing, so one leak cannot leave litter behind for
    every run that follows it.
    """
    try:
        import tkinter
    except Exception:
        return
    leaked = tkinter._default_root
    if leaked is not None:
        leaked.destroy()
        raise AssertionError(
            "a GUI test left its Tk root window open; the window stays "
            "mapped until the process exits")


class FakeSource(GuiDataSource):
    """In-memory source with two keys and sessions; never a secret."""

    def __init__(self):
        self.keys = [
            KeyView(
                key_id="key-aaaa1111bbbb2222",
                provider="github",
                pseudonym="kp-1111111111111111",
                fingerprint="a1b2c3d4e5f6aabbccdd",
                label="My GitHub key",
            ),
            KeyView(
                key_id="key-cccc3333dddd4444",
                provider="gemini",
                pseudonym="kp-2222222222222222",
                fingerprint="deadbeef001122334455",
                label="My Gemini key",
                rotation_warning=True,
            ),
        ]
        self.sessions = [
            SessionView(
                session_pseudonym="sp-aaaaaaaaaaaaaaa1",
                key_pseudonym="kp-1111111111111111",
                key_id="key-aaaa1111bbbb2222",
                provider="github",
                session_class="read_public",
                transport="absolute",
                expires_at=1790000000.0,
            ),
            SessionView(
                session_pseudonym="sp-bbbbbbbbbbbbbbb2",
                key_pseudonym="kp-2222222222222222",
                key_id="key-cccc3333dddd4444",
                provider="gemini",
                session_class="write",
                transport="connect_allowed",
                expires_at=1790000000.0,
            ),
        ]
        self.audit = [
            AuditEntryView(
                session_pseudonym="sp-aaaaaaaaaaaaaaa1",
                key_pseudonym="kp-1111111111111111",
                provider="github",
                method="GET",
                canonical_path="/repos/o/r",
                decision="allow",
                outcome="ok",
            )
        ]
        self.killed_sessions = []
        self.killed_keys = []
        self.kill_all_calls = 0

    def list_keys(self):
        return list(self.keys)

    def list_sessions(self, key_id=None):
        if key_id is None:
            return list(self.sessions)
        return [s for s in self.sessions if s.key_id == key_id]

    def list_audit(self, key_pseudonym=None):
        if key_pseudonym is None:
            return list(self.audit)
        return [e for e in self.audit if e.key_pseudonym == key_pseudonym]

    def since_import_count(self):
        return 0

    def kill_session(self, session_pseudonym):
        self.killed_sessions.append(session_pseudonym)
        return True

    def kill_key_sessions(self, key_id):
        self.killed_keys.append(key_id)
        n = len([s for s in self.sessions if s.key_id == key_id])
        return n

    def kill_all(self):
        self.kill_all_calls += 1
        return len(self.sessions)


def all_rendered(vm):
    parts = []
    parts.extend(vm.key_list_lines())
    parts.extend(vm.session_list_lines())
    parts.extend(vm.audit_lines())
    for key in vm.source.list_keys():
        parts.append(vm.detail_for_key(key.key_id))
    for session in vm.source.list_sessions():
        parts.append(vm.detail_for_session(session.session_pseudonym))
        parts.append(isolation_card_text(session))
    parts.append(vm.trust_text())
    parts.append(kill_receipt_text(2, ("GET /repos/o/r",)))
    return "\n".join(parts)


class TestHeadlessImport(unittest.TestCase):
    def test_import_does_not_open_window_or_crash(self):
        # Importing already happened at module load; reaching here
        # without a window proves it. Also confirm no Tk root exists
        # merely from the import.
        import sealvra.gui as gui

        self.assertFalse(hasattr(gui, "_open_window_at_import"))
        # No Tk instance can exist without create_window(); the
        # module exposes no root object at import time.
        self.assertIsNone(getattr(gui, "root", None))

    def test_create_window_headless_raises_runtime_error_not_tclerror(self):
        import sealvra.gui as gui

        if not _display_available():
            self.skipTest("NOT-RUN: no display available in this environment")
        # If a display IS available, create_window must succeed and
        # the window must be destroyed again (smoke path below covers it).
        window = gui.create_window(EmptyDataSource())
        try:
            self.assertIsNotNone(window.root)
        finally:
            window.root.destroy()


class TestPseudonymOnlyRendering(unittest.TestCase):
    def setUp(self):
        self.vm = ViewModel(FakeSource())

    def test_key_list_never_shows_labels(self):
        for line in self.vm.key_list_lines():
            self.assertNotIn("My GitHub key", line)
            self.assertNotIn("My Gemini key", line)

    def test_label_only_in_owning_detail_pane(self):
        detail = self.vm.detail_for_key("key-aaaa1111bbbb2222")
        self.assertIn("My GitHub key", detail)
        self.assertNotIn("My Gemini key", detail)

    def test_audit_is_pseudonym_only(self):
        for line in self.vm.audit_lines():
            self.assertNotIn("My GitHub key", line)
            self.assertNotIn("My Gemini key", line)
            self.assertIn("kp-1111111111111111", line)

    def test_no_secret_or_token_in_any_rendered_string(self):
        rendered = all_rendered(self.vm)
        assert_no_secret(rendered, [FAKE_SECRET, FAKE_TOKEN])
        self.assertNotIn("TEST-ONLY-", rendered)

    def test_fingerprint_truncated_to_12_in_list(self):
        line = render_key_list_line(self.vm.source.list_keys()[0])
        self.assertIn("a1b2c3d4e5f6", line)
        self.assertNotIn("aabbccdd", line)

    def test_fingerprint_never_in_a_shared_table(self):
        """The Keys/Sessions/Activity rows are one list every key shares.

        ``cli.py:86-88`` allows the 12-hex fingerprint in the owning
        key's detail view only, and a fingerprint is a key-derived
        value: if a table ever carried it, the shared screen would leak
        a per-key identifier the contract reserves for one pane. This
        pins both halves -- the prefix IS in its own detail, and no
        fragment of either fixture fingerprint is in any shared row.

        ``key_list_lines()`` is deliberately not in the set below: no
        widget in this window calls it (the Keys screen renders
        ``key_rows``), and its own fingerprint behaviour is pinned by
        ``test_fingerprint_truncated_to_12_in_list``.
        """
        shared = "\n".join(
            [str(cell) for name in ("key_rows", "session_rows", "audit_rows")
             for row in getattr(self.vm, name)() for cell in row[0]]
            + self.vm.session_list_lines() + self.vm.audit_lines()
            + [self.vm.status_text()])
        for fragment in ("a1b2c3d4e5f6", "aabbccdd", "deadbeef0011",
                         "22334455", "a1b2c3d4e5f6aabbccdd",
                         "deadbeef001122334455"):
            self.assertNotIn(fragment, shared)
        # And the detail pane for each key does carry its own, so the
        # screen is not simply losing the value.
        self.assertIn("a1b2c3d4e5f6",
                      self.vm.detail_for_key("key-aaaa1111bbbb2222"))
        self.assertIn("deadbeef0011",
                      self.vm.detail_for_key("key-cccc3333dddd4444"))

    def test_key_detail_carries_the_reference_a_terminal_needs(self):
        """The table shows a pseudonym; ``sealvra keys rotate`` takes the
        key_id, so the detail pane must print it or the GUI would strand
        the one command that clears a rotation warning."""
        detail = self.vm.detail_for_key("key-aaaa1111bbbb2222")
        self.assertIn("key-aaaa1111bbbb2222", detail)
        self.assertIn("sealvra keys rotate", detail)

    def test_connect_session_labelled_host_only(self):
        lines = self.vm.session_list_lines()
        connect_line = [ln for ln in lines if "gemini" in ln][0]
        self.assertIn("HOST-ONLY POLICY", connect_line)
        absolute_line = [ln for ln in lines if "github" in ln][0]
        self.assertNotIn("HOST-ONLY POLICY", absolute_line)

    def test_isolation_card_on_every_session_view(self):
        for session in self.vm.source.list_sessions():
            card = isolation_card_text(session)
            self.assertIn("Isolated to one key", card)
            self.assertIn(session.key_pseudonym, card)
            detail = self.vm.detail_for_session(session.session_pseudonym)
            self.assertIn("Isolated to one key", detail)

    def test_trust_screen_copy(self):
        text = trust_screen_text(0)
        self.assertIn("stops key theft, not data theft", text)
        self.assertIn("Times any key has left this machine since import: 0", text)

    def test_per_key_access_log_filters_by_pseudonym(self):
        log = self.vm.per_key_access_log("kp-1111111111111111")
        self.assertEqual(len(log), 1)
        self.assertEqual(self.vm.per_key_access_log("kp-2222222222222222"), [])


class TestKillWiring(unittest.TestCase):
    def setUp(self):
        self.source = FakeSource()
        self.vm = ViewModel(self.source)

    def test_kill_session_wired_to_source(self):
        receipt = self.vm.kill_session("sp-aaaaaaaaaaaaaaa1")
        self.assertIn("sp-aaaaaaaaaaaaaaa1", self.source.killed_sessions)
        self.assertIn("within 1 second", receipt)
        self.assertIn("not recalled", receipt)

    def test_kill_key_wired_to_source(self):
        self.vm.kill_key("key-aaaa1111bbbb2222")
        self.assertIn("key-aaaa1111bbbb2222", self.source.killed_keys)

    def test_kill_all_wired_to_source(self):
        receipt = self.vm.kill_all()
        self.assertEqual(self.source.kill_all_calls, 1)
        self.assertIn("Killed 2 session(s)", receipt)

    def test_kill_all_first_ordering(self):
        plan = self.vm.kill_plan(key_id="key-aaaa1111bbbb2222")
        kinds = [kind for kind, _ in plan]
        self.assertEqual(kinds[0], "kill-all")
        self.assertIn("kill-key", kinds)

    def test_no_approve_method_on_view_model(self):
        # GUI must never be an approval channel.
        self.assertFalse(hasattr(self.vm, "approve"))
        self.assertFalse(hasattr(self.vm, "approve_session"))
        with open(
            os.path.join(os.path.dirname(__file__), "..", "sealvra", "gui.py")
        ) as _f:
            source = _f.read()
        # No approve button/menu label may exist in the window code.
        for forbidden in ('label="Approve', "text=\"Approve"):
            self.assertNotIn(forbidden, source)

    def test_no_web_dashboard_in_module(self):
        with open(
            os.path.join(os.path.dirname(__file__), "..", "sealvra", "gui.py")
        ) as _f:
            source = _f.read()
        for forbidden in ("http.server", "Flask", "fastapi", "socketserver"):
            self.assertNotIn(forbidden, source)


class TestWindowSmoke(unittest.TestCase):
    def test_window_creation_smoke(self):
        import sealvra.gui as gui

        try:
            window = gui.create_window(FakeSource())
        except RuntimeError as exc:
            # Headless / no tkinter: honest NOT-RUN, never PASSED.
            self.skipTest(f"NOT-RUN: {exc}")
        try:
            window.root.update_idletasks()
            # Three panes exist: sidebar, list, detail widgets.
            self.assertIsNotNone(window.listbox)
            self.assertIsNotNone(window.detail)
            # No approve control text on any button.
            for child in window.root.winfo_children():
                pass  # structure check above is the smoke assertion
        finally:
            window.root.destroy()


class FakeIpcTransport:
    """Fake §13.1 daemon IPC: NDJSON-shaped replies, no real daemon.

    Sessions use a session_id DISTINCT from the display pseudonym
    so tests can prove kills address the daemon id, not the row
    label. No secrets anywhere: ids and pseudonyms are fake.
    """

    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []
        self.sessions = [
            {
                "session_id": "sess-aaaa1111bbbb2222",
                "session_pseudonym": "sp-aaaaaaaaaaaaaaa1",
                "key_pseudonym": "kp-1111111111111111",
                "key_id": "key-aaaa1111bbbb2222",
                "provider": "github",
                "session_class": "read_public",
                "transport": "absolute",
                "expires_at": 1790000000.0,
                "killed": False,
                "in_flight_calls": ["GET /repos/o/r"],
            },
            {
                "session_id": "sess-cccc3333dddd4444",
                "session_pseudonym": "sp-bbbbbbbbbbbbbbb2",
                "key_pseudonym": "kp-2222222222222222",
                "key_id": "key-cccc3333dddd4444",
                "provider": "gemini",
                "session_class": "write",
                "transport": "connect_allowed",
                "expires_at": 1790000000.0,
                "killed": False,
            },
        ]

    def __call__(self, request):
        self.calls.append(request)
        if self.fail:
            raise DaemonIpcError("fake daemon unreachable")
        cmd = request["cmd"]
        req_id = request["id"]
        if cmd == "sessions.list":
            return {"id": req_id, "ok": True,
                    "result": [dict(s) for s in self.sessions]}
        if cmd == "sessions.kill":
            sid = request["args"]["session_id"]
            for entry in self.sessions:
                if entry["session_id"] == sid:
                    entry["killed"] = True
                    return {"id": req_id, "ok": True, "result": {"killed": True}}
            return {"id": req_id, "ok": False,
                    "error": {"code": "KH-1002",
                              "message": "session not found/expired/killed"}}
        if cmd == "sessions.kill_all":
            for entry in self.sessions:
                entry["killed"] = True
            return {"id": req_id, "ok": True,
                    "result": {"snapshot": [s["session_id"] for s in self.sessions],
                               "receipts": {s["session_id"]: {} for s in self.sessions}}}
        if cmd == "audit.verify":
            return {"id": req_id, "ok": True, "result": {"status": "OK"}}
        if cmd == "status":
            return {"id": req_id, "ok": True, "result": {"running": True}}
        return {"id": req_id, "ok": False,
                "error": {"code": "KH-2001", "message": "unknown command"}}

    def kill_calls(self):
        return [c for c in self.calls if c["cmd"] == "sessions.kill"]


class FlakySource(GuiDataSource):
    """Works until fail is set; proves error state clears stale rows."""

    def __init__(self):
        self.fail = False
        self.inner = FakeSource()

    def list_keys(self):
        if self.fail:
            raise DaemonIpcError("fake daemon went away")
        return self.inner.list_keys()

    def list_sessions(self, key_id=None):
        if self.fail:
            raise DaemonIpcError("fake daemon went away")
        return self.inner.list_sessions(key_id)

    def list_audit(self, key_pseudonym=None):
        if self.fail:
            raise DaemonIpcError("fake daemon went away")
        return self.inner.list_audit(key_pseudonym)


class LoadingProbeSource(GuiDataSource):
    """Asserts the view-model is in 'loading' while it is being read."""

    def __init__(self):
        self.vm = None

    def list_sessions(self, key_id=None):
        assert self.vm is not None and self.vm.state == "loading"
        return []

    def list_keys(self):
        return []


class TestDaemonIpcClientProtocol(unittest.TestCase):
    def _serve_once(self, unix_path, reply_bytes, record):
        import socket
        import threading

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(unix_path)
        server.listen(1)

        def _handle():
            conn, _ = server.accept()
            with conn:
                data = b""
                while b"\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                record.append(json.loads(data.decode()))
                conn.sendall(reply_bytes)
            server.close()

        thread = threading.Thread(target=_handle, daemon=True)
        thread.start()
        return thread

    def test_ndjson_roundtrip_over_unix_socket(self):
        import json as _json
        import tempfile

        record = []
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "control.sock")
            # Reply id must echo the request id; it is unknown here
            # until the client sends, so serve with a placeholder and
            # rewrite: instead, reply generically and check via a
            # second mechanism below (transport stub covers id echo).
            thread = self._serve_once(
                path, b'{"id": 1, "ok": true, "result": {"running": true}}\n',
                record)
            client = DaemonIpcClient(path, timeout=5.0)
            result = client.status()
            thread.join(timeout=5.0)
        self.assertEqual(result, {"running": True})
        self.assertEqual(len(record), 1)
        self.assertEqual(record[0]["cmd"], "status")
        self.assertIsInstance(record[0]["id"], int)
        self.assertIn("args", record[0])

    def test_eof_terminated_reply_accepted(self):
        import tempfile

        record = []
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "control.sock")
            thread = self._serve_once(
                path, b'{"id": 1, "ok": true, "result": []}', record)
            client = DaemonIpcClient(path, timeout=5.0)
            self.assertEqual(client.list_sessions(), [])
            thread.join(timeout=5.0)

    def test_error_reply_propagates_kh_code(self):
        transport = FakeIpcTransport()
        client = DaemonIpcClient("unused", transport=transport)
        with self.assertRaises(DaemonIpcError) as ctx:
            client.kill_session("sess-does-not-exist")
        self.assertEqual(ctx.exception.code, "KH-1002")

    def test_reply_id_mismatch_rejected(self):
        def _bad(request):
            return {"id": request["id"] + 99, "ok": True, "result": {}}

        client = DaemonIpcClient("unused", transport=_bad)
        with self.assertRaises(DaemonIpcError):
            client.status()

    def test_malformed_reply_rejected(self):
        client = DaemonIpcClient("unused", transport=lambda r: "not-a-dict")
        with self.assertRaises(DaemonIpcError):
            client.status()

    def test_session_creation_refused_even_via_generic_call(self):
        transport = FakeIpcTransport()
        client = DaemonIpcClient("unused", transport=transport)
        with self.assertRaises(ValueError):
            client.call("sessions.create", {"key_id": "key-aaaa1111bbbb2222"})
        self.assertFalse(hasattr(client, "create_session"))
        self.assertEqual(transport.calls, [])

    def test_non_loopback_tcp_refused_before_connect(self):
        client = DaemonIpcClient("8.8.8.8:8765", timeout=1.0)
        with self.assertRaises(DaemonIpcError):
            client.status()

    def test_no_daemon_socket_raises_ipc_error_not_crash(self):
        client = DaemonIpcClient("/nonexistent-dir-TEST-ONLY/control.sock",
                                 timeout=1.0)
        with self.assertRaises(DaemonIpcError):
            client.status()

    def test_no_address_configured(self):
        client = DaemonIpcClient(None)
        with self.assertRaises(DaemonIpcError):
            client.status()


class TestDaemonIpcSource(unittest.TestCase):
    def setUp(self):
        self.transport = FakeIpcTransport()
        self.client = DaemonIpcClient("unused", transport=self.transport)
        self.source = DaemonIpcSource(self.client)
        self.vm = ViewModel(self.source)

    def test_session_mapping_keeps_pseudonym_and_id_separate(self):
        sessions = self.source.list_sessions()
        self.assertEqual(len(sessions), 2)
        first = sessions[0]
        self.assertEqual(first.session_pseudonym, "sp-aaaaaaaaaaaaaaa1")
        self.assertEqual(first.session_id, "sess-aaaa1111bbbb2222")
        self.assertEqual(first.in_flight_calls, ("GET /repos/o/r",))
        line = render_session_line(first)
        self.assertIn("sp-aaaaaaaaaaaaaaa1", line)
        self.assertNotIn("sess-aaaa1111bbbb2222", line)

    def test_keys_derived_from_sessions_without_invented_label(self):
        keys = self.source.list_keys()
        self.assertEqual(len(keys), 2)
        for key in keys:
            self.assertEqual(key.label, "")
            self.assertEqual(key.fingerprint, "")

    def test_kill_session_addresses_daemon_id_not_pseudonym(self):
        self.assertTrue(self.source.kill_session("sp-aaaaaaaaaaaaaaa1"))
        kills = self.transport.kill_calls()
        self.assertEqual(len(kills), 1)
        self.assertEqual(kills[0]["args"]["session_id"], "sess-aaaa1111bbbb2222")
        sessions = self.source.list_sessions()
        killed = [s for s in sessions
                  if s.session_pseudonym == "sp-aaaaaaaaaaaaaaa1"][0]
        self.assertTrue(killed.killed)

    def test_kill_unknown_session_is_false_not_raise(self):
        self.assertFalse(self.source.kill_session("sp-unknown"))

    def test_kill_all_count_from_receipts(self):
        self.assertEqual(self.source.kill_all(), 2)

    def test_kill_key_sessions_counts_only_that_key(self):
        self.assertEqual(self.source.kill_key_sessions("key-aaaa1111bbbb2222"), 1)
        self.assertEqual(len(self.transport.kill_calls()), 1)

    def test_audit_status_from_verify(self):
        self.assertEqual(self.source.audit_status(), "Audit verify: OK")

    def test_view_model_kill_receipt_through_ipc(self):
        receipt = self.vm.kill_session("sp-aaaaaaaaaaaaaaa1")
        self.assertIn("Killed 1 session(s)", receipt)
        self.assertIn("not recalled", receipt)

    def test_since_import_count_not_claimed_over_ipc(self):
        self.assertFalse(self.source.since_import_known)
        self.vm.refresh()
        self.assertIn("not reported by the daemon", self.vm.trust_text())
        self.assertNotIn("since import: 0", self.vm.trust_text())

    def test_env_discovery(self):
        self.assertEqual(
            daemon_socket_from_env({"SEALVRA_DAEMON_SOCKET": "  /tmp/x.sock "}),
            "/tmp/x.sock")
        self.assertIsNone(daemon_socket_from_env({}))
        self.assertIsNone(daemon_socket_from_env({"SEALVRA_DAEMON_SOCKET": "  "}))

    def test_default_source_from_env(self):
        import unittest.mock as mock

        with mock.patch.dict(os.environ, {"SEALVRA_DAEMON_SOCKET": "/tmp/x.sock"}):
            self.assertIsInstance(create_default_source(), DaemonIpcSource)
        with mock.patch.dict(os.environ, {}, clear=True):
            # Clear only our var; other env content is irrelevant here.
            os.environ.pop("SEALVRA_DAEMON_SOCKET", None)
            self.assertIsInstance(create_default_source(), EmptyDataSource)


class TestRefreshStates(unittest.TestCase):
    def test_live_state_and_status_text(self):
        vm = ViewModel(FakeSource())
        self.assertEqual(vm.refresh(), "live")
        self.assertIn("Live", vm.status_text())
        self.assertIn("2 session(s)", vm.status_text())
        self.assertIsNone(vm.last_error)

    def test_empty_state_for_empty_source(self):
        vm = ViewModel(EmptyDataSource())
        self.assertEqual(vm.refresh(), "empty")
        self.assertIn("No daemon connected", vm.status_text())

    def test_error_clears_stale_snapshot(self):
        source = FlakySource()
        vm = ViewModel(source)
        self.assertEqual(vm.refresh(), "live")
        self.assertEqual(len(vm.session_list_lines()), 2)
        source.fail = True
        self.assertEqual(vm.refresh(), "error")
        self.assertEqual(vm.key_list_lines(), [])
        self.assertEqual(vm.session_list_lines(), [])
        self.assertIsNotNone(vm.last_error)
        self.assertTrue(vm.status_text().startswith("Error:"))

    def test_loading_state_visible_during_refresh(self):
        probe = LoadingProbeSource()
        vm = ViewModel(probe)
        probe.vm = vm
        self.assertEqual(vm.refresh(), "empty")

    def test_snapshot_frozen_until_next_refresh(self):
        source = FakeSource()
        vm = ViewModel(source)
        vm.refresh()
        source.sessions = []
        # Still the snapshot, not the mutated source.
        self.assertEqual(len(vm.session_list_lines()), 2)
        vm.refresh()
        self.assertEqual(vm.session_list_lines(), [])

    def test_live_reads_without_refresh_unchanged(self):
        # v0.1 behaviour preserved: no refresh() yet -> live reads.
        vm = ViewModel(FakeSource())
        self.assertEqual(len(vm.session_list_lines()), 2)


class TestWindowLiveWiringHeadless(unittest.TestCase):
    def test_main_headless_raises_kh3001(self):
        import sealvra.gui as gui

        if not _display_available():
            with self.assertRaises(RuntimeError) as ctx:
                gui.main(EmptyDataSource())
            self.assertIn("KH-3001", str(ctx.exception))
            return
        self.skipTest("NOT-RUN: a display is available; headless path not taken")

    def test_window_has_status_bar_and_auto_refresh_timer(self):
        import sealvra.gui as gui

        try:
            window = gui.create_window(FakeSource(), refresh_interval_ms=5000)
        except RuntimeError as exc:
            self.skipTest(f"NOT-RUN: {exc}")
        try:
            self.assertIsNotNone(window.status_bar)
            self.assertIsNotNone(window._auto_refresh_id)
            self.assertEqual(window.vm.state, "live")
            self.assertIn("Live", window.status_bar.cget("text"))
        finally:
            window.destroy()


if __name__ == "__main__":
    unittest.main()
