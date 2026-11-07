"""W10 CLI tests (unittest).

Backend modules (W01 daemon/broker, W02 vault, W03 sessions, W09
audit) landed mid-task as class-based, in-process modules with no CLI
client protocol (daemon socket answers status/ping only), so the
boundary is stubbed INSIDE THIS TEST FILE ONLY: fake backends are
injected by patching sealvra.cli's _loader functions. Production
code (sealvra/cli.py) contains no stubs. When the manager defines
the CLI client interface, these fakes should be replaced by the real
one and the same assertions kept.

All keys/tokens below are fake TEST-ONLY values. No real credential
appears anywhere in this file.

Run:  python3 -m unittest tests.test_w10_cli -v   (from the build root)
  or: python3 -m unittest discover -s tests -v
"""

import contextlib
import io
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sealvra import cli  # noqa: E402
from sealvra.cli import ERROR_CATALOGUE, SealvraError, main  # noqa: E402

FAKE_KEY = "TEST-ONLY-FAKEKEY-aaaa1111"
FAKE_KEY_2 = "TEST-ONLY-FAKEKEY-bbbb2222"
FAKE_TOKEN = "kh_sess_TEST-ONLY-token-aaaa"


class CodedError(Exception):
    """Backend-style error carrying a catalogue code."""

    def __init__(self, code, message=""):
        super().__init__(message or code)
        self.code = code


# ------------------------------------------------------------- fakes


class FakeVault:
    def __init__(self):
        self.keys = {}
        self.counter = 0

    def _record(self, key_id, provider, label, needs_rotation):
        import hashlib

        return SimpleNamespace(
            key_id=key_id,
            provider=provider,
            label=label,
            created_at="2026-10-28T00:00:00Z",
            needs_rotation=needs_rotation,
            fingerprint=hashlib.sha256(FAKE_KEY.encode()).hexdigest()[:12],
            display_name=None,
            compromised=False,
        )

    def list_keys(self):
        return list(self.keys.values())

    def get_key(self, key_id):
        return self.keys.get(key_id)

    def add_key(self, provider, label, secret, ever_pasted, display_name=None):
        self.counter += 1
        key_id = f"key-{'%016x' % self.counter}"
        record = self._record(key_id, provider, label, ever_pasted)
        record.display_name = display_name
        self.keys[key_id] = record
        return record

    def delete_key(self, key_id):
        self.keys.pop(key_id, None)

    def rotate_key(self, key_id, new_secret):
        record = self.keys[key_id]
        record.needs_rotation = False
        return record

    def mark_key_compromised(self, key_id):
        if key_id not in self.keys:
            raise CodedError("KH-1002", f"key not found: {key_id}")
        record = self.keys[key_id]
        # Mark as compromised by setting needs_rotation=True and flagging it
        record.needs_rotation = True
        record.compromised = True
        return record


class FakeSessions:
    def __init__(self):
        self.items = {}
        self.counter = 0
        self.created = []
        self.killed = []

    def list_sessions(self):
        return list(self.items.values())

    def create_session(self, key_id, provider, session_class, transport, minutes, label):
        self.counter += 1
        session = SimpleNamespace(
            session_id=f"sess-{'%016x' % self.counter}",
            key_id=key_id,
            provider=provider,
            session_class=session_class,
            transport=transport,
            minutes=minutes,
            label=label,
            token=FAKE_TOKEN,
            expires_at="2026-10-28T01:00:00Z",
            killed=False,
        )
        self.items[session.session_id] = session
        self.created.append(session)
        return session

    def kill_session(self, session_id):
        if session_id not in self.items:
            raise CodedError("KH-1002", f"session not found: {session_id}")
        self.killed.append(session_id)
        return {"already_forwarded": ["GET /repos/example (forwarded before kill)"]}

    def kill_all(self):
        count = len(self.items)
        self.items.clear()
        return {"killed_count": count}


class FakeDaemon:
    def __init__(self, running=False):
        self.running = running
        self.started = False
        self.stopped = False

    def status(self):
        return {"running": self.running, "pid": 1234 if self.running else None}

    def start(self):
        self.running = True
        self.started = True
        return {"running": True}

    def stop(self):
        self.running = False
        self.stopped = True
        return {"running": False, "sessions_killed": False}


class FakeAudit:
    def __init__(self, status="OK"):
        self.status = status
        self.exported = []

    def verify(self):
        return {"status": self.status, "entries": 42}

    def export(self, path):
        self.exported.append(path)
        return {"entries": 42, "path": path}


class FakeBroker:
    """validate_token enforces separation unless leak=True."""

    def __init__(self, leak=False, control_ok=True):
        self.leak = leak
        self.control_ok = control_ok
        self.tokens = {}

    def validate_token(self, session_id, token):
        if not self.control_ok:
            return False
        if self.leak:
            return True
        return self.tokens.get(session_id) == token


class FakeSessionsEphemeral:
    """Mint two ephemeral sessions bound to a FakeBroker."""

    def __init__(self, broker):
        self.broker = broker
        self.counter = 0

    def create_ephemeral_session(self):
        self.counter += 1
        session_id = f"sess-ephemeral-{self.counter}"
        token = f"kh_sess_TEST-ONLY-ephemeral-{self.counter}"
        self.broker.tokens[session_id] = token
        return SimpleNamespace(session_id=session_id), token


# ------------------------------------------------------------- helpers


class CliTestCase(unittest.TestCase):
    def run_cli(self, argv, inputs=None, secrets=None):
        """Run main() capturing stdout/stderr; inputs feed input(),
        secrets feed getpass.getpass(). Returns (exit_code, out, err)."""
        out, err = io.StringIO(), io.StringIO()
        input_iter = iter(inputs or [])
        secret_iter = iter(secrets or [])
        with mock.patch.object(cli, "_load_daemon", side_effect=ImportError("no daemon")), \
                mock.patch("builtins.input", side_effect=lambda *a: next(input_iter)), \
                mock.patch("getpass.getpass", side_effect=lambda *a: next(secret_iter)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            # Default loaders raise ImportError; individual tests override
            # via _with_backends. Here we only reach this path for
            # help/version/first-run/doctor tests that need no backend.
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def run_with(self, argv, vault=None, sessions=None, daemon=None,
                 audit=None, broker=None, inputs=None, secrets=None):
        out, err = io.StringIO(), io.StringIO()
        input_iter = iter(inputs or [])
        secret_iter = iter(secrets or [])
        patches = [
            mock.patch("builtins.input", side_effect=lambda *a: next(input_iter)),
            mock.patch("getpass.getpass", side_effect=lambda *a: next(secret_iter)),
        ]
        if vault is not None:
            patches.append(mock.patch.object(cli, "_load_vault", return_value=vault))
        if sessions is not None:
            patches.append(mock.patch.object(cli, "_load_sessions", return_value=sessions))
        if daemon is not None:
            patches.append(mock.patch.object(cli, "_load_daemon", return_value=daemon))
        elif sessions is not None:
            # Manager integration fix (v0.2): CLI sessions commands
            # prefer a running daemon over the sessions module. A
            # daemon leaked by an earlier test in the same discovery
            # run would otherwise hijack these stub-backend tests.
            # Stubbing "no daemon" isolates the sessions backend the
            # same way the sessions stub itself does.
            patches.append(mock.patch.object(
                cli, "_load_daemon", side_effect=ImportError("no daemon")))
        if audit is not None:
            patches.append(mock.patch.object(cli, "_load_audit", return_value=audit))
        if broker is not None:
            patches.append(mock.patch.object(cli, "_load_broker", return_value=broker))
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(argv)
        return code, out.getvalue(), err.getvalue()


# ------------------------------------------------------------- help/usage


class TestHelpAndUsage(CliTestCase):
    def test_top_help_lists_every_command(self):
        code, out, _ = self.run_cli(["--help"])
        self.assertEqual(code, 0)
        for word in ("daemon", "keys", "sessions", "audit", "doctor", "prove-isolation"):
            self.assertIn(word, out)

    def test_version(self):
        code, out, _ = self.run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("sealvra 0.1.0", out)

    def test_subcommand_helps(self):
        for argv in (["daemon", "--help"], ["keys", "--help"], ["sessions", "--help"],
                     ["audit", "--help"], ["doctor", "--help"], ["prove-isolation", "--help"]):
            code, _, _ = self.run_cli(argv)
            self.assertEqual(code, 0, argv)

    def test_bare_invocation_is_first_run_screen(self):
        code, out, _ = self.run_cli([])
        self.assertEqual(code, 0)
        self.assertIn("we will never contact you", out)
        self.assertIn("stops *key* theft, not *data* theft", out)
        self.assertIn("Times any key has left this machine *since import*: 0", out)

    def test_bare_subcommand_is_usage_error(self):
        for argv in (["daemon"], ["keys"], ["sessions"], ["audit"]):
            code, _, err = self.run_cli(argv)
            self.assertEqual(code, 1, argv)
            self.assertIn("KH-2001", err)

    def test_unknown_command_is_usage_error(self):
        code, _, err = self.run_cli(["frobnicate"])
        self.assertEqual(code, 1)
        self.assertIn("KH-2001", err)


class TestForbiddenSurface(CliTestCase):
    FORBIDDEN = ("reveal", "approve", "extend", "--show-token", "--print-token")

    def test_forbidden_words_absent_from_all_help(self):
        helps = []
        for argv in (["--help"], ["daemon", "--help"], ["keys", "--help"],
                     ["sessions", "--help"], ["audit", "--help"]):
            _, out, _ = self.run_cli(argv)
            helps.append(out)
        blob = "\n".join(helps)
        for word in self.FORBIDDEN:
            self.assertNotIn(word, blob, f"forbidden surface leaked into help: {word}")

    def test_forbidden_commands_rejected(self):
        for argv in (["keys", "reveal", "key-0000000000000001"],
                     ["sessions", "approve", "sess-0000000000000001"],
                     ["sessions", "extend", "sess-0000000000000001"]):
            code, _, err = self.run_cli(argv)
            self.assertEqual(code, 1, argv)
            self.assertIn("KH-2001", err)

    def test_forbidden_flags_rejected(self):
        for argv in (["keys", "list", "--show-token"],
                     ["sessions", "create", "key-0000000000000001", "--print-token"],
                     ["sessions", "create", "key-0000000000000001", "--extend"]):
            code, _, err = self.run_cli(argv)
            self.assertEqual(code, 1, argv)
            self.assertIn("KH-2001", err)


class TestErrorCatalogue(CliTestCase):
    def test_catalogue_matches_contract_exactly(self):
        expected = {
            "KH-1001": 1, "KH-1002": 2, "KH-1003": 2, "KH-1004": 2,
            "KH-1005": 3, "KH-1006": 1, "KH-2001": 1, "KH-3001": 1,
            "KH-3002": 3, "KH-3003": 3,
        }
        self.assertEqual({k: v[0] for k, v in ERROR_CATALOGUE.items()}, expected)

    def test_backend_code_passes_through_unchanged(self):
        sessions = FakeSessions()
        code, _, err = self.run_with(
            ["sessions", "kill", "sess-missing"], sessions=sessions)
        self.assertEqual(code, 2)
        self.assertIn("KH-1002", err)

    def test_missing_backend_module_maps_to_catalogue(self):
        # Loader failures (the missing-module path) map onto the
        # catalogue: non-audit backends KH-1006/exit 1, audit KH-1005/exit 3.
        # Loader stubs are used because whether the real modules exist
        # depends on other workers' landing order, not on this CLI.
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(
                cli, "_load_vault",
                side_effect=SealvraError("KH-1006", "vault unavailable")), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["keys", "list"])
        self.assertEqual(code, 1)
        self.assertIn("KH-1006", err.getvalue())
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(
                cli, "_load_audit",
                side_effect=SealvraError("KH-1005", "audit unavailable")), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["audit", "verify"])
        self.assertEqual(code, 3)
        self.assertIn("KH-1005", err.getvalue())

    def test_key_not_found_is_kh1002(self):
        vault = FakeVault()
        code, _, err = self.run_with(["keys", "show", "key-missing"], vault=vault)
        self.assertEqual(code, 2)
        self.assertIn("KH-1002", err)


# ------------------------------------------------------------- import flow


class TestImportAndRotation(CliTestCase):
    def _add(self, vault, answers, secret=FAKE_KEY):
        return self.run_with(
            ["keys", "add", "--provider", "github", "--label", "testkey"],
            vault=vault, inputs=answers, secrets=[secret])

    def test_add_never_pasted_has_no_rotation_gate(self):
        vault = FakeVault()
        code, out, _ = self._add(vault, ["", "no"])
        self.assertEqual(code, 0)
        self.assertNotIn("NOT YET ROTATED", out)
        record = vault.list_keys()[0]
        self.assertFalse(record.needs_rotation)

    def test_add_pasted_yes_forces_rotation_gate(self):
        vault = FakeVault()
        code, out, _ = self._add(vault, ["", "yes"])
        self.assertEqual(code, 0)
        self.assertIn("NOT YET ROTATED", out)
        self.assertIn("before its first session", out)
        self.assertTrue(vault.list_keys()[0].needs_rotation)

    def test_add_dont_know_means_yes(self):
        vault = FakeVault()
        code, out, _ = self._add(vault, ["", "don't know"])
        self.assertEqual(code, 0)
        self.assertIn("NOT YET ROTATED", out)
        self.assertTrue(vault.list_keys()[0].needs_rotation)

    def test_add_reprompts_on_invalid_answer(self):
        vault = FakeVault()
        code, out, _ = self._add(vault, ["", "maybe", "no"])
        self.assertEqual(code, 0)
        self.assertNotIn("NOT YET ROTATED", out)

    def test_add_asks_the_mandatory_question(self):
        vault = FakeVault()
        with mock.patch("builtins.input", side_effect=["", "no"]) as patched_input, \
                mock.patch("getpass.getpass", return_value=FAKE_KEY), \
                mock.patch.object(cli, "_load_vault", return_value=vault), \
                contextlib.redirect_stdout(io.StringIO()):
            main(["keys", "add", "--provider", "gemini", "--label", "k"])
        asked = " ".join(call.args[0] for call in patched_input.call_args_list)
        self.assertIn("What would you like to call this key?", asked)
        self.assertIn("Was this key ever pasted anywhere?", asked)

    def test_import_warns_on_display_name_collision(self):
        vault = FakeVault()
        self.run_with(
            ["keys", "add", "--provider", "github", "--label", "a",
             "--display-name", "Work"],
            vault=vault, inputs=["no"], secrets=[FAKE_KEY])
        code, out, err = self.run_with(
            ["keys", "add", "--provider", "github", "--label", "b",
             "--display-name", "Work"],
            vault=vault, inputs=["n", "no"], secrets=[FAKE_KEY])
        self.assertEqual(code, 0, out + err)
        self.assertIn("already called", out)
        # Declining the clashing name leaves the vault to mint its default.
        self.assertIsNone(vault.list_keys()[1].display_name)

    def test_collision_answer_yes_keeps_the_shared_name(self):
        vault = FakeVault()
        self.run_with(
            ["keys", "add", "--provider", "github", "--label", "a",
             "--display-name", "Work"],
            vault=vault, inputs=["no"], secrets=[FAKE_KEY])
        code, out, err = self.run_with(
            ["keys", "add", "--provider", "github", "--label", "b",
             "--display-name", "Work"],
            vault=vault, inputs=["y", "no"], secrets=[FAKE_KEY])
        self.assertEqual(code, 0, out + err)
        self.assertIn("already called", out)
        self.assertEqual(vault.list_keys()[1].display_name, "Work")

    def test_list_and_show_carry_permanent_warning_until_rotation(self):
        vault = FakeVault()
        self._add(vault, ["", "yes"])
        key_id = vault.list_keys()[0].key_id
        _, out, _ = self.run_with(["keys", "list"], vault=vault)
        self.assertIn("NOT YET ROTATED", out)
        _, out, _ = self.run_with(["keys", "show", key_id], vault=vault)
        self.assertIn("NOT YET ROTATED", out)

    def test_rotation_gate_blocks_first_session(self):
        vault = FakeVault()
        sessions = FakeSessions()
        self._add(vault, ["", "yes"])
        key_id = vault.list_keys()[0].key_id
        code, _, err = self.run_with(
            ["sessions", "create", key_id], vault=vault, sessions=sessions)
        self.assertEqual(code, 2)
        self.assertIn("KH-1003", err)
        self.assertIn("NOT YET ROTATED", err)
        self.assertEqual(sessions.created, [])

    def test_rotate_clears_gate_and_session_then_starts(self):
        vault = FakeVault()
        sessions = FakeSessions()
        self._add(vault, ["", "don't know"])
        key_id = vault.list_keys()[0].key_id
        code, out, _ = self.run_with(
            ["keys", "rotate", key_id], vault=vault, secrets=[FAKE_KEY_2])
        self.assertEqual(code, 0)
        self.assertIn("NOT YET ROTATED warning cleared", out)
        code, out, _ = self.run_with(
            ["sessions", "create", key_id], vault=vault, sessions=sessions)
        self.assertEqual(code, 0)
        self.assertEqual(len(sessions.created), 1)

    def test_secret_never_appears_in_list_or_show_output(self):
        vault = FakeVault()
        self._add(vault, ["", "no"])
        key_id = vault.list_keys()[0].key_id
        _, list_out, _ = self.run_with(["keys", "list"], vault=vault)
        _, show_out, _ = self.run_with(["keys", "show", key_id], vault=vault)
        self.assertNotIn(FAKE_KEY, list_out)
        self.assertNotIn(FAKE_KEY, show_out)
        # Detail pane may show the fingerprint, never the key itself.
        self.assertIn("fingerprint:", show_out)
        self.assertNotIn("fingerprint:", list_out)

    def test_delete_requires_typed_confirmation(self):
        vault = FakeVault()
        self._add(vault, ["", "no"])
        key_id = vault.list_keys()[0].key_id
        code, out, _ = self.run_with(
            ["keys", "delete", key_id], vault=vault, inputs=["wrong"])
        self.assertEqual(code, 0)
        self.assertIn("aborted", out)
        self.assertIsNotNone(vault.get_key(key_id))
        code, out, _ = self.run_with(
            ["keys", "delete", key_id], vault=vault, inputs=[key_id])
        self.assertEqual(code, 0)
        self.assertIn("key deleted", out)
        self.assertIsNone(vault.get_key(key_id))


# ------------------------------------------------------------- Mark Compromised Tests


class TestMarkCompromised(CliTestCase):
    def _key(self, vault, pasted="no"):
        with mock.patch("builtins.input", return_value=pasted), \
                mock.patch("getpass.getpass", return_value=FAKE_KEY), \
                mock.patch.object(cli, "_load_vault", return_value=vault), \
                contextlib.redirect_stdout(io.StringIO()):
            main(["keys", "add", "--provider", "github", "--label", "k"])
        return vault.list_keys()[0].key_id

    def test_mark_compromised_kills_sessions_and_blocks_new_ones(self):
        vault = FakeVault()
        sessions = FakeSessions()
        key_id = self._key(vault)
        self.run_with(
            ["sessions", "create", key_id], vault=vault, sessions=sessions)
        self.assertEqual(len(sessions.created), 1)
        session_id = sessions.created[0].session_id
        created_before = list(sessions.created)

        code, out, err = self.run_with(
            ["keys", "mark-compromised", key_id], vault=vault, sessions=sessions)
        self.assertEqual(code, 0, out + err)
        self.assertIn("COMPROMISED", out)
        self.assertIn("sessions killed: 1", out)
        self.assertIn(session_id, sessions.killed)

        # A new session for a compromised key is refused before it is minted.
        code, _, err = self.run_with(
            ["sessions", "create", key_id], vault=vault, sessions=sessions)
        self.assertEqual(code, 2)
        self.assertIn("KH-1003", err)
        self.assertEqual(sessions.created, created_before)

    def test_mark_compromised_still_blocks_the_key_when_kill_path_is_unavailable(self):
        """No daemon means no list_sessions(); the block must still land.

        Otherwise reporting a leak looks like a command that failed and the
        compromised key stays usable — the fail-open case this ordering fixes.
        """
        vault = FakeVault()
        key_id = self._key(vault)
        broken = mock.Mock()
        broken.list_sessions.side_effect = AttributeError("list_sessions")
        code, out, err = self.run_with(
            ["keys", "mark-compromised", key_id], vault=vault, sessions=broken)
        self.assertEqual(code, 0, out + err)
        self.assertIn("could not enumerate sessions", out)
        self.assertIn("COMPROMISED", out)
        self.assertTrue(vault.get_key(key_id).compromised)
        code, _, err = self.run_with(
            ["sessions", "create", key_id], vault=vault, sessions=broken)
        self.assertEqual(code, 2)
        self.assertIn("COMPROMISED", err)

    def test_notify_passes_user_text_as_data_never_as_script_source(self):
        """A display name is attacker-influenceable text reaching osascript.

        It must arrive as an argv element, not inside the -e source, or one
        quote character turns `keys mark-compromised` into code execution.
        """
        evil = 'x" with title "y"; do shell script "touch /tmp/SEALVRA_INJECTED"'
        with mock.patch.object(sys, "platform", "darwin"), \
                mock.patch("subprocess.run") as run:
            cli._notify(evil)
        self.assertTrue(run.called)
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "osascript")
        source = argv[argv.index("-e") + 1]
        self.assertNotIn(evil, source)
        self.assertNotIn("do shell script", source)
        self.assertIn(evil, argv[argv.index("-e") + 2:])

    def test_notify_is_silent_off_macos(self):
        with mock.patch.object(sys, "platform", "linux"), \
                mock.patch("subprocess.run") as run:
            cli._notify("anything")
        self.assertFalse(run.called)


class TestSessions(CliTestCase):
    def _key(self, vault, pasted="no"):
        with mock.patch("builtins.input", return_value=pasted), \
                mock.patch("getpass.getpass", return_value=FAKE_KEY), \
                mock.patch.object(cli, "_load_vault", return_value=vault), \
                contextlib.redirect_stdout(io.StringIO()):
            main(["keys", "add", "--provider", "github", "--label", "k"])
        return vault.list_keys()[0].key_id

    def test_create_shows_token_once_with_warning(self):
        vault, sessions = FakeVault(), FakeSessions()
        key_id = self._key(vault)
        code, out, _ = self.run_with(
            ["sessions", "create", key_id], vault=vault, sessions=sessions)
        self.assertEqual(code, 0)
        self.assertIn(FAKE_TOKEN, out)
        self.assertIn("will not be shown again", out)
        _, list_out, _ = self.run_with(
            ["sessions", "list"], vault=vault, sessions=sessions)
        self.assertNotIn(FAKE_TOKEN, list_out)

    def test_create_uses_class_defaults_and_enforces_caps(self):
        vault, sessions = FakeVault(), FakeSessions()
        key_id = self._key(vault)
        for session_class, default in (("destructive", 10), ("write", 20),
                                       ("read_account", 30), ("read_public", 60)):
            code, _, _ = self.run_with(
                ["sessions", "create", key_id, "--class", session_class],
                vault=vault, sessions=sessions)
            self.assertEqual(code, 0, session_class)
            self.assertEqual(sessions.created[-1].minutes, default)
        code, _, err = self.run_with(
            ["sessions", "create", key_id, "--class", "destructive", "--minutes", "16"],
            vault=vault, sessions=sessions)
        self.assertEqual(code, 1)
        self.assertIn("KH-2001", err)
        code, _, err = self.run_with(
            ["sessions", "create", key_id, "--class", "bogus"],
            vault=vault, sessions=sessions)
        self.assertEqual(code, 1)
        self.assertIn("KH-2001", err)

    def test_create_connect_allowed_is_labelled_host_only(self):
        vault, sessions = FakeVault(), FakeSessions()
        key_id = self._key(vault)
        code, out, _ = self.run_with(
            ["sessions", "create", key_id, "--transport", "connect_allowed"],
            vault=vault, sessions=sessions)
        self.assertEqual(code, 0)
        self.assertIn("HOST-ONLY POLICY", out)

    def test_kill_receipt_wording(self):
        vault, sessions = FakeVault(), FakeSessions()
        key_id = self._key(vault)
        self.run_with(["sessions", "create", key_id], vault=vault, sessions=sessions)
        session_id = sessions.created[0].session_id
        code, out, _ = self.run_with(
            ["sessions", "kill", session_id], sessions=sessions)
        self.assertEqual(code, 0)
        self.assertIn("blocked within 1 second", out)
        self.assertIn("torn down within 5 seconds", out)
        self.assertIn("not recalled", out)
        self.assertIn("already sent", out)

    def test_kill_all_defaults_to_keep(self):
        sessions = FakeSessions()
        code, out, _ = self.run_with(
            ["sessions", "kill-all"], sessions=sessions, inputs=[""])
        self.assertEqual(code, 0)
        self.assertIn("sessions kept", out)
        code, out, _ = self.run_with(
            ["sessions", "kill-all", "--yes"], sessions=sessions)
        self.assertEqual(code, 0)
        self.assertIn("all sessions killed", out)


# ------------------------------------------------------------- daemon


class TestDaemon(CliTestCase):
    def test_status_start_stop(self):
        daemon = FakeDaemon(running=False)
        code, out, _ = self.run_with(["daemon", "status"], daemon=daemon)
        self.assertEqual(code, 0)
        self.assertIn("stopped", out)
        code, out, _ = self.run_with(["daemon", "start"], daemon=daemon)
        self.assertEqual(code, 0)
        self.assertIn("started", out)
        code, out, _ = self.run_with(["daemon", "status"], daemon=daemon)
        self.assertIn("running", out)
        code, out, _ = self.run_with(["daemon", "stop"], daemon=daemon)
        self.assertEqual(code, 0)
        self.assertIn("sessions kept", out)
        self.assertNotIn("sessions killed", out.replace("sessions kept", ""))

    def test_stop_with_unknown_session_disposition_claims_nothing(self):
        daemon = FakeDaemon(running=True)

        def stop_unknown():
            daemon.running = False
            return {"running": False}  # no sessions_killed field

        daemon.stop = stop_unknown
        code, out, _ = self.run_with(["daemon", "stop"], daemon=daemon)
        self.assertEqual(code, 0)
        self.assertIn("disposition not reported", out)
        self.assertNotIn("sessions kept", out)

    def test_stop_when_not_running_is_not_an_error(self):
        daemon = FakeDaemon(running=False)
        code, out, _ = self.run_with(["daemon", "stop"], daemon=daemon)
        self.assertEqual(code, 0)
        self.assertIn("not running", out)


# ------------------------------------------------------------- audit


class TestAudit(CliTestCase):
    def test_verify_statuses_and_exits(self):
        cases = [("OK", 0), ("UNANCHORED", 2), ("TAMPERED", 3), ("MISSING-DIRECTORY", 3)]
        for status, expected_code in cases:
            audit = FakeAudit(status=status)
            code, out, err = self.run_with(["audit", "verify"], audit=audit)
            self.assertEqual(code, expected_code, status)
            if status == "OK":
                self.assertIn("audit: OK", out)
            elif status == "UNANCHORED":
                self.assertIn("UNANCHORED", out)
            else:
                self.assertIn("KH-1005", err)

    def test_export_requires_output_and_reports_no_key_material(self):
        audit = FakeAudit()
        code, _, err = self.run_with(["audit", "export"], audit=audit)
        self.assertEqual(code, 1)
        self.assertIn("KH-2001", err)
        code, out, _ = self.run_with(
            ["audit", "export", "--output", "/tmp/kh-audit-export.jsonl"], audit=audit)
        self.assertEqual(code, 0)
        self.assertIn("key material is never exported", out)
        self.assertEqual(audit.exported, ["/tmp/kh-audit-export.jsonl"])


# ------------------------------------------------------------- doctor


class TestDoctor(CliTestCase):
    def test_doctor_warns_on_planted_profile_but_never_prints_values(self):
        with tempfile.TemporaryDirectory() as home:
            with open(os.path.join(home, ".bashrc"), "w") as handle:
                handle.write("export GITHUB_TOKEN=TEST-ONLY-FAKEVALUE-12345\n")
            with mock.patch.dict(os.environ, {"MY_TEST_SECRET": "TEST-ONLY-ENV-999"}, clear=False), \
                    mock.patch("os.path.expanduser", return_value=home), \
                    mock.patch("os.getcwd", return_value=home):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = main(["doctor"])
        output = out.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("GITHUB_TOKEN", output)
        self.assertIn("MY_TEST_SECRET", output)
        self.assertNotIn("TEST-ONLY-FAKEVALUE-12345", output)
        self.assertNotIn("TEST-ONLY-ENV-999", output)
        self.assertIn("warning:", output)

    def test_doctor_clean_home_reports_no_warnings(self):
        with tempfile.TemporaryDirectory() as home, \
                mock.patch("os.path.expanduser", return_value=home), \
                mock.patch("os.getcwd", return_value=home), \
                mock.patch.dict(os.environ, {}, clear=True):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(["doctor"])
        self.assertEqual(code, 0)
        self.assertIn("0 warning(s)", out.getvalue())

    def test_doctor_warns_on_credential_store_presence(self):
        with tempfile.TemporaryDirectory() as home:
            os.makedirs(os.path.join(home, ".aws"), exist_ok=True)
            with open(os.path.join(home, ".aws", "credentials"), "w") as handle:
                handle.write("[default]\n")
            with mock.patch("os.path.expanduser", return_value=home), \
                    mock.patch("os.getcwd", return_value=home):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = main(["doctor"])
        self.assertEqual(code, 0)
        self.assertIn(".aws/credentials", out.getvalue())
        self.assertIn("warning:", out.getvalue())


# ------------------------------------------------------- prove-isolation


class TestProveIsolation(CliTestCase):
    def test_self_check_pass(self):
        broker = FakeBroker()
        sessions = FakeSessionsEphemeral(broker)
        code, out, _ = self.run_with(
            ["prove-isolation"], sessions=sessions, broker=broker)
        self.assertEqual(code, 0)
        self.assertIn("PASS", out)

    def test_self_check_cross_token_leak_is_exit_3(self):
        broker = FakeBroker(leak=True)
        sessions = FakeSessionsEphemeral(broker)
        code, _, err = self.run_with(
            ["prove-isolation"], sessions=sessions, broker=broker)
        self.assertEqual(code, 3)
        self.assertIn("KH-3002", err)

    def test_self_check_control_failure_is_exit_3_not_a_pass(self):
        broker = FakeBroker(control_ok=False)
        sessions = FakeSessionsEphemeral(broker)
        code, _, err = self.run_with(
            ["prove-isolation"], sessions=sessions, broker=broker)
        self.assertEqual(code, 3)
        self.assertIn("KH-3002", err)

    def test_broker_reported_path(self):
        broker = SimpleNamespace(
            prove_isolation=lambda: {"ok": True, "detail": "2 sessions cross-checked"})
        sessions = SimpleNamespace()  # no ephemeral mint: fallback path
        code, out, _ = self.run_with(
            ["prove-isolation"], sessions=sessions, broker=broker)
        self.assertEqual(code, 0)
        self.assertIn("PASS", out)
        broker_bad = SimpleNamespace(
            prove_isolation=lambda: {"ok": False, "detail": "cross-accept observed"})
        code, _, err = self.run_with(
            ["prove-isolation"], sessions=sessions, broker=broker_bad)
        self.assertEqual(code, 3)
        self.assertIn("KH-3002", err)

    def test_prove_isolation_without_broker_fails_closed(self):
        out, err = io.StringIO(), io.StringIO()
        sessions = FakeSessions()
        with mock.patch.object(cli, "_load_sessions", return_value=sessions), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["prove-isolation"])
        self.assertEqual(code, 3)
        self.assertIn("KH-3002", err.getvalue())

    def test_failed_proof_is_never_a_routine_denial(self):
        broker = FakeBroker(leak=True)
        sessions = FakeSessionsEphemeral(broker)
        _, _, err = self.run_with(
            ["prove-isolation"], sessions=sessions, broker=broker)
        self.assertNotIn("KH-1003", err)


# ------------------------------------------------- v0.2 W18 additions
# Error-code table, defaults table, quit semantics, wired-token
# lifecycle, and the single no-OS-auth rule (v3 N-M4/N-M5/N-M2/N-M6/
# N-E13; f12 C2/C4/C6/C7/C8). All values below are fake TEST-ONLY.


class TestErrorCatalogueV02(CliTestCase):
    def test_family_rule_2xxx_is_usage_only(self):
        codes_2xxx = [c for c in ERROR_CATALOGUE if c.startswith("KH-2")]
        self.assertEqual(codes_2xxx, ["KH-2001"])

    def test_retired_codes_are_never_emitted(self):
        for retired in ("KH-1009", "KH-2003", "KH-2004", "KH-2005",
                        "KH-2006", "KH-2007", "KH-2008",
                        "KH-6001", "KH-6002", "KH-6003", "KH-6004"):
            self.assertNotIn(retired, ERROR_CATALOGUE, retired)

    def test_canonical_mapping_of_retired_codes(self):
        self.assertEqual(cli.canonical_code("KH-1009"), "KH-1003")
        self.assertEqual(ERROR_CATALOGUE["KH-1003"][0], 2)
        for retired in ("KH-2003", "KH-2004", "KH-2005", "KH-2006",
                        "KH-2007", "KH-2008", "KH-6001", "KH-6002",
                        "KH-6003", "KH-6004"):
            self.assertEqual(cli.canonical_code(retired), "KH-1004", retired)
            self.assertEqual(ERROR_CATALOGUE["KH-1004"][0], 2)
        with self.assertRaises(SealvraError) as caught:
            cli.canonical_code("KH-9999")
        self.assertEqual(caught.exception.code, "KH-2001")

    def test_backend_emitting_retired_code_is_remapped(self):
        sessions = FakeSessions()
        sessions.kill_session = lambda sid: (_ for _ in ()).throw(
            CodedError("KH-1009", "cross-key attempt"))
        code, _, err = self.run_with(
            ["sessions", "kill", "sess-1"], sessions=sessions)
        self.assertEqual(code, 2)
        self.assertIn("KH-1003", err)
        self.assertNotIn("KH-1009", err)

    def test_same_event_same_code_across_approval_outcomes(self):
        for event in ("approval_failed", "approval_cancelled",
                      "approval_dismissed", "approval_timeout",
                      "approval_unavailable", "os_auth_unavailable"):
            err = cli.error_for_event(event)
            self.assertEqual(err.code, "KH-1004", event)
            self.assertEqual(err.exit_code, 2, event)
        self.assertEqual(cli.error_for_event("cross_key_attempt").code, "KH-1003")
        self.assertEqual(cli.error_for_event("cross_key_attempt").exit_code, 2)
        self.assertEqual(cli.error_for_event("prove_isolation_failed").code, "KH-3002")
        self.assertNotEqual(
            cli.error_for_event("prove_isolation_failed").exit_code,
            cli.error_for_event("policy_denied").exit_code)

    def test_every_code_has_a_nonempty_next_step_and_prints_it(self):
        for code in ERROR_CATALOGUE:
            step = cli.NEXT_STEPS[code]
            self.assertTrue(step and step.strip() and step.lower() != "none", code)
        # A real CLI error line carries its next step.
        code, _, err = self.run_with(
            ["sessions", "kill", "sess-missing"], sessions=FakeSessions())
        self.assertEqual(code, 2)
        self.assertIn("KH-1002", err)
        self.assertIn("next step:", err)

    def test_no_os_auth_refuses_as_kh1004(self):
        err = cli.no_os_auth_error()
        self.assertEqual(err.code, "KH-1004")
        self.assertEqual(err.exit_code, 2)
        self.assertIn("refuse", err.message)

    def test_prove_isolation_backend_failure_is_kh3002_not_provider_error(self):
        broker = FakeBroker()
        sessions = FakeSessionsEphemeral(broker)

        def _boom(session_id, token):
            raise RuntimeError("TEST-ONLY broker boom")

        broker.validate_token = _boom
        code, _, err = self.run_with(
            ["prove-isolation"], sessions=sessions, broker=broker)
        self.assertEqual(code, 3)
        self.assertIn("KH-3002", err)
        self.assertNotIn("KH-1003", err)
        self.assertNotIn("KH-1006", err)


class TestDefaultsTableV02(CliTestCase):
    def test_cli_and_gui_defaults_tables_agree(self):
        from sealvra import gui

        self.assertEqual(cli.DEFAULTS, gui.DEFAULTS)
        self.assertEqual(cli.QUIT_DEFAULT, gui.QUIT_DEFAULT)
        self.assertEqual(cli.NO_OS_AUTH_RULE, gui.NO_OS_AUTH_RULE)
        self.assertEqual(cli.WIRED_TOKEN_SHARE_WARNING, gui.WIRED_TOKEN_SHARE_WARNING)

    def test_no_duration_above_the_2h_hard_cap(self):
        for session_class, (default, cap) in cli.DEFAULTS["ttl_minutes"].items():
            self.assertLessEqual(cap, 120, session_class)
            self.assertLessEqual(default, cap, session_class)
        self.assertEqual(cli.DEFAULTS["hard_cap_minutes"], 120)
        self.assertEqual(max(cap for _, cap in cli.DEFAULTS["ttl_minutes"].values()), 120)
        vault, sessions = FakeVault(), FakeSessions()
        with mock.patch("builtins.input", return_value="no"), \
                mock.patch("getpass.getpass", return_value=FAKE_KEY), \
                mock.patch.object(cli, "_load_vault", return_value=vault), \
                contextlib.redirect_stdout(io.StringIO()):
            main(["keys", "add", "--provider", "github", "--label", "k"])
        key_id = vault.list_keys()[0].key_id
        code, _, err = self.run_with(
            ["sessions", "create", key_id, "--class", "read_public", "--minutes", "121"],
            vault=vault, sessions=sessions)
        self.assertEqual(code, 1)
        self.assertIn("KH-2001", err)

    def test_approval_timeout_is_60_or_120_accessibility_only(self):
        self.assertEqual(cli.resolve_approval_timeout(), 60)
        self.assertEqual(cli.resolve_approval_timeout(accessibility=True), 120)
        self.assertEqual(cli.resolve_approval_timeout_value(60), 60)
        self.assertEqual(
            cli.resolve_approval_timeout_value(120, accessibility=True), 120)
        for bad in (30, 120, 300):
            # 120 without the accessibility opt-in, and every other
            # value from the deleted ranges, are usage errors.
            with self.assertRaises(SealvraError) as caught:
                cli.resolve_approval_timeout_value(bad)
            self.assertEqual(caught.exception.code, "KH-2001")

    def test_idle_lock_is_single_value_5_range_2_to_15_no_disable(self):
        self.assertEqual(cli.resolve_idle_minutes(), 5)
        self.assertEqual(cli.resolve_idle_minutes(2), 2)
        self.assertEqual(cli.resolve_idle_minutes(15), 15)
        for bad in (0, 1, 16, 60):
            with self.assertRaises(SealvraError) as caught:
                cli.resolve_idle_minutes(bad)
            self.assertEqual(caught.exception.code, "KH-2001")

    def test_update_check_default_undecided_and_unclaimed(self):
        # G0 OD-13 undecided: the table records None and neither
        # surface claims on or off (W17 owns the payload).
        self.assertIsNone(cli.DEFAULTS["update_check_default"])
        self.assertNotIn("update check", cli.FIRST_RUN_TEXT)
        from sealvra import gui

        self.assertNotIn("update check", gui.trust_screen_text(0))


class TestQuitSemanticsV02(CliTestCase):
    def test_quit_default_is_keep_sessions_never_destruction(self):
        self.assertEqual(cli.QUIT_DEFAULT, "keep_sessions")
        self.assertEqual(cli.QUIT_CONFIRM_DEFAULT, "Keep sessions")
        text = cli.quit_confirmation_text(2)
        self.assertIn("Keep sessions", text)
        self.assertIn("does not kill", text)
        self.assertIn("kill-all", text)

    def test_gui_quit_text_matches_keep_semantics(self):
        from sealvra import gui

        vm = gui.ViewModel(gui.EmptyDataSource())
        text = vm.quit_text()
        self.assertIn("Keep sessions", text)
        self.assertIn("does not kill", text)
        self.assertIn("Quit and kill all", text)


class TestWiredTokenLifecycleV02(CliTestCase):
    TOKEN = "kh_sess_TEST-ONLY-wired-1"

    def test_strip_removes_token_and_keeps_rest(self):
        stripped = cli.strip_wired_token(
            "proxy = https://127.0.0.1:8765\ntoken = " + self.TOKEN + "\nmode = on\n",
            self.TOKEN)
        self.assertNotIn(self.TOKEN, stripped)
        self.assertIn("mode = on", stripped)

    def test_end_restores_clean_backup_and_deletes_bak(self):
        result = cli.end_wired_session(
            "wired " + self.TOKEN, self.TOKEN, "original-config", False)
        self.assertEqual(result["config_text"], "original-config")
        self.assertEqual(result["backup_action"], "restored-and-deleted")
        self.assertFalse(result["token_remaining"])

    def test_end_never_restores_a_bak_holding_a_live_token(self):
        result = cli.end_wired_session(
            "wired " + self.TOKEN, self.TOKEN,
            "old-config " + self.TOKEN, True)
        self.assertNotIn(self.TOKEN, result["config_text"])
        self.assertEqual(result["backup_action"], "deleted-without-restore")
        self.assertFalse(result["token_remaining"])

    def test_end_without_backup_strips_and_deletes_bak(self):
        result = cli.end_wired_session("wired " + self.TOKEN, self.TOKEN, None, False)
        self.assertNotIn(self.TOKEN, result["config_text"])
        self.assertEqual(result["backup_action"], "deleted-without-restore")

    def test_kill_and_expiry_share_one_lifecycle(self):
        # One function serves both ends; the spec table says so too.
        self.assertEqual(
            cli.WIRED_TOKEN_LIFECYCLE["on_kill"],
            "strip the token from the config, or restore the pre-wiring backup, then delete the .bak")
        self.assertTrue(
            cli.WIRED_TOKEN_LIFECYCLE["on_expiry"].startswith("same as on kill"))
        self.assertIn("delete the .bak", cli.WIRED_TOKEN_LIFECYCLE["on_expiry"])

    def test_share_warning_present_on_both_surfaces(self):
        from sealvra import gui

        for warning in (cli.WIRED_TOKEN_SHARE_WARNING, gui.WIRED_TOKEN_SHARE_WARNING):
            self.assertIn("Do not share, sync, or commit", warning)

    def test_copy_setup_never_carries_the_token(self):
        with self.assertRaises(SealvraError) as caught:
            cli.copy_agent_setup("token = " + self.TOKEN, self.TOKEN)
        self.assertEqual(caught.exception.code, "KH-2001")
        clean = cli.copy_agent_setup("proxy = https://127.0.0.1:8765", self.TOKEN)
        self.assertNotIn(self.TOKEN, clean)
        self.assertIn("WITHOUT the session token", clean)


class TestSingleNoOsAuthRuleV02(CliTestCase):
    FORBIDDEN_FALLBACK_PHRASES = (
        "Allow with password",
        "verified against the vault",
        "Sealvra passphrase",
    )

    def test_no_competing_fallback_text_in_cli_or_gui_source(self):
        import pathlib

        root = pathlib.Path(__file__).resolve().parent.parent
        for name in ("sealvra/cli.py", "sealvra/gui.py"):
            text = (root / name).read_text()
            for phrase in self.FORBIDDEN_FALLBACK_PHRASES:
                self.assertNotIn(phrase, text, f"{name} still carries: {phrase}")

    def test_single_rule_text_shared_by_both_surfaces(self):
        from sealvra import gui

        self.assertEqual(cli.NO_OS_AUTH_RULE, gui.NO_OS_AUTH_RULE)
        self.assertTrue(cli.NO_OS_AUTH_RULE.startswith("refuse:"))
        self.assertEqual(cli.DEFAULTS["no_os_auth"], "refuse")
        self.assertEqual(gui.DEFAULTS["no_os_auth"], "refuse")


if __name__ == "__main__":
    unittest.main()
