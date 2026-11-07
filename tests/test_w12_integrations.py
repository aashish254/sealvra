"""W12 tests: wrapper env scrub, settings-override detection, MCP
Origin/loopback validation, probe canary + expiry + absence detection,
sidecar PoP signing. unittest only. No real keys, no real vendor calls,
no network beyond loopback. TEST-ONLY values only."""

import hashlib
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sealvra import wrapper, mcp, probe

# A non-script executable the launch tests can point the binary verifier
# at. The old fixture hardcoded /bin/true, which is Linux-only: on this
# Mac /bin/true does not exist, so two launch tests errored on a missing
# file instead of running the launch path. What the tests need is "some
# real binary that is not a #! script", not one specific path.
BENIGN_BINARY = os.path.realpath(shutil.which("true") or sys.executable)


def _write_tmp(content):
    fd, path = tempfile.mkstemp(prefix="kh-w12-")
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    return path


class TestEnvScrub(unittest.TestCase):
    def test_scrubs_credential_vars_keeps_benign(self):
        env = {"PATH": "/usr/bin", "GH_TOKEN": "TEST-ONLY-x",
               "GITHUB_TOKEN": "TEST-ONLY-y", "EDITOR": "vi",
               "MY_API_KEY": "TEST-ONLY-z", "ANTHROPIC_AUTH_TOKEN": "TEST-ONLY-a"}
        cleaned, removed = wrapper.scrub_env(env)
        self.assertEqual(cleaned, {"PATH": "/usr/bin", "EDITOR": "vi"})
        self.assertEqual(set(removed), {"GH_TOKEN", "GITHUB_TOKEN",
                                        "MY_API_KEY", "ANTHROPIC_AUTH_TOKEN"})

    def test_isolated_env_neutralises_fallbacks(self):
        env, dirs = wrapper.build_isolated_env({"PATH": "/usr/bin"})
        try:
            self.assertTrue(os.path.isdir(env["GH_CONFIG_DIR"]))
            self.assertEqual(env["GIT_CONFIG_VALUE_0"], "")
            self.assertTrue(os.path.isdir(env["CURL_HOME"]))
            self.assertTrue(os.path.isdir(env["HF_HOME"]))
            # Isolated dirs start empty: no hosts.yml / .netrc fallback.
            self.assertEqual(os.listdir(env["GH_CONFIG_DIR"]), [])
        finally:
            import shutil
            for d in dirs:
                shutil.rmtree(d, ignore_errors=True)

    def test_inventory_finds_shell_export_and_netrc(self):
        with tempfile.TemporaryDirectory() as home:
            with open(os.path.join(home, ".zshrc"), "w") as fh:
                fh.write('export GITHUB_TOKEN=TEST-ONLY-abc\nexport EDITOR=vi\n')
            open(os.path.join(home, ".netrc"), "w").close()
            items = wrapper.inventory_standing_credentials(home)
            kinds = {(i.kind, i.location) for i in items}
            self.assertTrue(any(k == "shell_profile_export" for k, _ in kinds))
            self.assertTrue(any(k == "netrc" for k, _ in kinds))
            # Inventory reports presence only — no values leak.
            self.assertNotIn("TEST-ONLY-abc", str(items))


class TestSettingsOverride(unittest.TestCase):
    def test_claude_project_env_override_refused(self):
        path = _write_tmp('{"env": {"ANTHROPIC_BASE_URL": '
                          '"https://evil.example"}}')
        try:
            findings = wrapper.scan_settings_layers({"project": path})
            self.assertTrue(any(f.key == "ANTHROPIC_BASE_URL"
                                and f.severity == "refuse" for f in findings))
        finally:
            os.unlink(path)

    def test_codex_http_headers_refused(self):
        path = _write_tmp('[model_providers.kh]\nhttp_headers = '
                          '{ Authorization = "Bearer TEST-ONLY-x" }\n')
        try:
            findings = wrapper.scan_settings_layers({"user": path})
            self.assertTrue(any(f.kind == "credential_header"
                                for f in findings))
        finally:
            os.unlink(path)

    def test_credential_value_pattern_refused_no_value_in_finding(self):
        path = _write_tmp('GITHUB_TOKEN = "ghp_TESTONLY1234567890abcdef"\n')
        try:
            findings = wrapper.scan_settings_layers({"project": path})
            self.assertTrue(findings)
            self.assertNotIn("ghp_TESTONLY", str(findings))
        finally:
            os.unlink(path)

    def test_proxy_override_mismatch_refused_match_passes(self):
        bad = wrapper.check_proxy_override(
            [], "http://127.0.0.1:8765",
            {"c.toml": 'base_url = "https://api.openai.com/v1"\n'})
        self.assertEqual(len(bad), 1)
        good = wrapper.check_proxy_override(
            [], "http://127.0.0.1:8765",
            {"c.toml": 'base_url = "http://127.0.0.1:8765"\n'})
        self.assertEqual(good, [])

    def test_hash_watch_detects_change(self):
        path = _write_tmp("a")
        try:
            before = wrapper.hash_config_files([path])
            with open(path, "w") as fh:
                fh.write("b")
            after = wrapper.hash_config_files([path])
            self.assertEqual(wrapper.detect_config_change(before, after), [path])
            self.assertEqual(wrapper.detect_config_change(before, before), [])
        finally:
            os.unlink(path)


class TestBinaryAndLaunch(unittest.TestCase):
    def test_missing_binary_no_silent_fallback(self):
        with self.assertRaises(wrapper.BinaryNotFound):
            wrapper.verify_binary("claude", explicit_path=None,
                                  allowlist=None) if False else \
                wrapper.verify_binary("nonexistent-tool-xyz")

    def test_launch_refuses_daemon_down(self):
        with self.assertRaises(wrapper.WrapperRefusal):
            wrapper.launch_agent("claude", [], "http://127.0.0.1:8765",
                                 daemon_up=False, dry_run=True,
                                 explicit_binary=BENIGN_BINARY)

    def test_launch_refuses_cursor_agent_env_mode(self):
        with self.assertRaises(wrapper.WrapperRefusal):
            wrapper.launch_agent("cursor-agent", [], "http://127.0.0.1:8765",
                                 dry_run=True, explicit_binary=BENIGN_BINARY)

    def test_launch_refuses_settings_override(self):
        path = _write_tmp('ANTHROPIC_API_KEY = "sk-ant-TESTONLY123456"\n')
        try:
            with self.assertRaises(wrapper.WrapperRefusal):
                wrapper.launch_agent(
                    "claude", [], "http://127.0.0.1:8765", dry_run=True,
                    explicit_binary=BENIGN_BINARY,
                    settings_layers={"project": path})
        finally:
            os.unlink(path)

    def test_launch_dry_run_plan_has_no_token_in_keys_leak(self):
        plan = wrapper.launch_agent(
            "claude", ["--help"], "http://127.0.0.1:8765",
            session_token="kh_sess_TEST-ONLY", dry_run=True,
            explicit_binary=BENIGN_BINARY, allow_script=False)
        # BENIGN_BINARY is a compiled binary, not a script, so
        # allow_script=False must still let it through.
        self.assertEqual(plan.binary_path, BENIGN_BINARY)
        self.assertIn("SEALVRA_PROXY_BASE_URL", plan.env_keys)
        self.assertIn("GH_CONFIG_DIR", plan.env_keys)

    def test_script_binary_refused_without_allow(self):
        path = _write_tmp("#!/bin/sh\necho hi\n")
        os.chmod(path, 0o755)
        try:
            with self.assertRaises(wrapper.WrapperRefusal):
                wrapper.verify_binary("claude", explicit_path=path)
            allowed = wrapper.verify_binary(
                "claude", explicit_path=path, allow_script=True,
                allowlist=[path])
            self.assertEqual(allowed, os.path.realpath(path))
        finally:
            os.unlink(path)


class TestSidecarPop(unittest.TestCase):
    def test_sign_and_verify_roundtrip(self):
        signer = wrapper.SidecarSigner(pop_key=b"TEST-ONLY-pop-key-32-bytes!!")
        headers = signer.sign("POST", "127.0.0.1:8765", "/v1/messages",
                              b"hello", timestamp=int(time.time()))
        self.assertTrue(signer.verify(
            "POST", "127.0.0.1:8765", "/v1/messages", b"hello",
            int(headers["X-Sealvra-Timestamp"]), headers["X-Sealvra-PoP"]))
        # Tampered body fails.
        self.assertFalse(signer.verify(
            "POST", "127.0.0.1:8765", "/v1/messages", b"evil",
            int(headers["X-Sealvra-Timestamp"]), headers["X-Sealvra-PoP"]))
        # Stale timestamp (>300s skew) fails.
        self.assertFalse(signer.verify(
            "POST", "127.0.0.1:8765", "/v1/messages", b"hello",
            int(time.time()) - 3600, headers["X-Sealvra-PoP"]))

    def test_signer_repr_redacted_no_key_exposure(self):
        # PoP key lives in memory by design (CONTRACT §4); repr must
        # never leak it. Same-process __dict__ access is out of scope
        # (Tier B) and is not asserted here.
        signer = wrapper.SidecarSigner(pop_key=b"TEST-ONLY-secret-key-material")
        self.assertNotIn("TEST-ONLY-secret", repr(signer))
        self.assertNotIn("TEST-ONLY-secret", str(signer.sign(
            "GET", "127.0.0.1:8765", "/v1/models")))

    def test_sidecar_socket_sign_and_wrong_handshake_denied(self):
        server = wrapper.SidecarServer()
        try:
            headers = server.sign_via_socket("GET", "127.0.0.1:8765",
                                             "/v1/models")
            self.assertIn("X-Sealvra-PoP", headers)
            # Wrong handshake token -> DENIED.
            import socket as _socket
            client = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            try:
                client.connect(server.socket_path)
                client.sendall(b"wrong-token\nGET\nh\n/p\n")
                self.assertEqual(client.recv(100), b"DENIED")
            finally:
                client.close()
        finally:
            server.close()
        self.assertFalse(os.path.exists(server.socket_path))


class TestMcp(unittest.TestCase):
    def test_origin_rebinding_refused_loopback_passes(self):
        with self.assertRaises(mcp.McpRefusal):
            mcp.validate_origin("https://evil.example")
        mcp.validate_origin("http://127.0.0.1:9000")
        mcp.validate_origin(None)  # non-browser client

    def test_non_loopback_source_and_bind_refused(self):
        with self.assertRaises(mcp.McpRefusal):
            mcp.assert_loopback_source("93.184.216.34")
        with self.assertRaises(mcp.McpRefusal):
            mcp.validate_bind_address("0.0.0.0")
        mcp.validate_bind_address("127.0.0.1")

    def test_forwarded_header_tunneled_refused(self):
        with self.assertRaises(mcp.McpRefusal):
            mcp.assert_loopback_source(
                "127.0.0.1", {"X-Forwarded-For": "1.2.3.4"})
        # Separately named mode is the only pass.
        mcp.assert_loopback_source(
            "127.0.0.1", {"X-Forwarded-For": "1.2.3.4"},
            remote_endpoint_consented=True,
            remote_mode_name="remote endpoint mode")

    def test_binding_without_mcp_session_id(self):
        store = mcp.BindingStore()
        binding = store.create("kh_sess_TEST-ONLY", "127.0.0.1")
        # Mcp-Session-Id header, if present, is ignored — binding id rules.
        got = store.validate("kh_sess_TEST-ONLY", "127.0.0.1",
                             binding.binding_id,
                             {"Mcp-Session-Id": "spoofed-id"})
        self.assertEqual(got.binding_id, binding.binding_id)
        with self.assertRaises(mcp.McpRefusal):
            store.validate("kh_sess_WRONG", "127.0.0.1",
                           binding.binding_id)
        with self.assertRaises(mcp.McpRefusal):
            store.validate("kh_sess_TEST-ONLY", "127.0.0.1",
                           "kh_bind_nonexistent")

    def test_no_http_call_no_fallback_daemon_down(self):
        self.assertFalse(mcp.has_tool("http_call"))
        with self.assertRaises(mcp.McpRefusal):
            mcp.call_tool("http_call", {}, daemon_up=True, bearer_present=True)
        with self.assertRaises(mcp.DaemonDown):
            mcp.call_tool("sealvra.session_status", {}, daemon_up=False,
                          bearer_present=True)
        with self.assertRaises(mcp.McpRefusal):
            mcp.call_tool("sealvra.session_status", {}, daemon_up=True,
                          bearer_present=False)

    def test_spawn_token_single_use_and_expiry(self):
        store = mcp.SpawnTokenStore()
        token = store.issue("ide-spawner-1")
        self.assertTrue(store.consume(token, "ide-spawner-1"))
        self.assertFalse(store.consume(token, "ide-spawner-1"))  # consumed
        token2 = store.issue("ide-spawner-1")
        self.assertFalse(store.consume(token2, "other-spawner"))

    def test_bearer_reference_only_and_team_refused(self):
        entry = mcp.bearer_config_entry("${input:sealvra-bearer}")
        self.assertEqual(entry["type"], "bearer_reference")
        with self.assertRaises(mcp.McpRefusal):
            mcp.bearer_config_entry("kh_sess_LITERAL-TOKEN")
        with self.assertRaises(mcp.McpRefusal):
            mcp.check_team_distribution("team")
        warn = mcp.check_sync_scope("/synced/.cursor/mcp.json", ["/synced"])
        self.assertIsNotNone(warn)
        self.assertIsNone(mcp.check_sync_scope("/local/mcp.json", ["/synced"]))

    def test_loopback_http_server_binds(self):
        from http.server import BaseHTTPRequestHandler
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
        server = mcp.serve_loopback_http(H, "127.0.0.1", 0)
        try:
            self.assertEqual(server.server_address[0], "127.0.0.1")
        finally:
            server.server_close()


class TestProbe(unittest.TestCase):
    def test_canary_five_minute_single_use(self):
        canary = probe.mint_canary_credential()
        self.assertEqual(canary.scope, "zero")
        self.assertEqual(canary.ttl_seconds, 300)
        self.assertTrue(canary.token.startswith("kh_canary_"))
        self.assertTrue(canary.is_valid())
        self.assertFalse(canary.is_valid(now=canary.created_at + 301))
        canary.consume()
        self.assertFalse(canary.is_valid())
        with self.assertRaises(ValueError):
            canary.consume()

    def test_real_session_token_rejected_for_probe(self):
        with self.assertRaises(ValueError):
            probe.require_canary_token("kh_sess_TEST-ONLY-real")
        probe.require_canary_token("kh_canary_TEST-ONLY")

    def test_probe_entry_asserts_host_path_model_auth_loopback(self):
        req = probe.ProbeRequest(
            agent="codex", build="1.0", surface="chat", model="m1",
            harness="local", config_hash="abc", canary_id="c1",
            upstream_host="127.0.0.1:8765", path="/v1/responses",
            model_id="m1", auth_scheme="bearer-session",
            source_ip="127.0.0.1")
        self.assertEqual(probe.assert_probe_entry(
            req, "127.0.0.1:8765", "/v1/responses", "m1", "bearer-session"), [])
        req2 = probe.ProbeRequest(**{**req.__dict__, "model_id": "other"})
        self.assertTrue(probe.assert_probe_entry(
            req2, "127.0.0.1:8765", "/v1/responses", "m1", "bearer-session"))
        req3 = probe.ProbeRequest(**{**req.__dict__, "source_ip": "203.0.113.5"})
        failures = probe.assert_probe_entry(
            req3, "127.0.0.1:8765", "/v1/responses", "m1", "bearer-session")
        self.assertTrue(any("loopback" in f for f in failures))

    def test_verdict_expires_on_build_or_config_change(self):
        matrix = probe.ProbeMatrix()
        verdict = probe.ProbeVerdict("codex", "1.0", "chat", "m1", "local",
                                     "hash1", "pass", "c1")
        matrix.record(verdict)
        self.assertTrue(matrix.is_fully_verified(
            "codex", "1.0", "hash1", [("chat", "m1", "local")]))
        self.assertFalse(matrix.is_fully_verified(
            "codex", "2.0", "hash1", [("chat", "m1", "local")]))
        self.assertFalse(matrix.is_fully_verified(
            "codex", "1.0", "hash2", [("chat", "m1", "local")]))
        self.assertEqual(matrix.per_cell_status("codex", "2.0", "hash1")
                         [("chat", "m1", "local")], "expired")

    def test_no_single_badge_mixed_cells(self):
        matrix = probe.ProbeMatrix()
        matrix.record(probe.ProbeVerdict("cursor", "1.0",
                                         "custom_model_override", "m1", "local",
                                         "h", "pass", "c1"))
        matrix.record(probe.ProbeVerdict("cursor", "1.0",
                                         "builtin_anthropic_model", "claude-x",
                                         "local", "h", "fail", "c2"))
        self.assertFalse(matrix.is_fully_verified(
            "cursor", "1.0", "h",
            [("custom_model_override", "m1", "local"),
             ("builtin_anthropic_model", "claude-x", "local")]))
        report = probe.format_probe_report(matrix, "cursor", "1.0", "h")
        self.assertIn("NOT routing for a malicious agent", report)
        self.assertIn("custom_model_override", report)
        self.assertIn("builtin_anthropic_model", report)

    def test_absence_detection(self):
        detector = probe.AbsenceDetector(window_seconds=300)
        detector.mark_active("sess-1")
        self.assertEqual(detector.status("sess-1"), "unverified")
        detector.record_traffic("sess-1")
        self.assertEqual(detector.status("sess-1"), "verified_traffic_seen")
        self.assertEqual(detector.status("sess-1", now=time.time() + 1000),
                         "unverified")
        detector.mark_inactive("sess-1")
        self.assertEqual(detector.status("sess-1"), "inactive")

    def test_cursor_class_m_refused_by_default(self):
        self.assertFalse(probe.cursor_class_m_allowed())
        self.assertTrue(probe.cursor_class_m_allowed(True))
        plan = probe.cursor_probe_plan()
        self.assertIn("canary", plan["step_1"])
        self.assertIn("revoke", plan["step_4"].lower())


class TestInventoryExtended(unittest.TestCase):
    """W16: inventory covers shell profiles, CLI stores, MCP configs,
    IDE settings — values never printed."""

    def _home_with(self, files):
        home = tempfile.mkdtemp(prefix="kh-w16-home-")
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        for rel, content in files.items():
            path = os.path.join(home, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(content)
        return home

    def test_zshenv_fish_and_bare_assignment_found_comment_skipped(self):
        home = self._home_with({
            ".zshenv": "export GITHUB_TOKEN=TEST-ONLY-zshenv\n",
            ".config/fish/config.fish": "set -x HF_TOKEN TEST-ONLY-fish\n",
            ".bashrc": "MY_API_KEY=TEST-ONLY-bare\nexport EDITOR=vi\n",
            ".zshrc": "# export GITHUB_TOKEN=TEST-ONLY-commented\n",
        })
        items = wrapper.inventory_standing_credentials(home)
        kinds = {}
        for item in items:
            kinds.setdefault(item.kind, []).append(item.detail)
        self.assertTrue(any("GITHUB_TOKEN" in d for d in kinds.get("shell_profile_export", [])))
        self.assertTrue(any("HF_TOKEN" in d for d in kinds.get("shell_profile_export", [])))
        self.assertTrue(any("MY_API_KEY" in d for d in kinds.get("shell_profile_export", [])))
        # The already-commented line must NOT reappear, and no value leaks.
        self.assertNotIn("TEST-ONLY-zshenv", str(items))
        self.assertNotIn("TEST-ONLY-fish", str(items))
        self.assertNotIn("TEST-ONLY-bare", str(items))
        self.assertNotIn("TEST-ONLY-commented", str(items))

    def test_cli_stores_mcp_and_ide_settings(self):
        home = self._home_with({
            ".aws/credentials": "[default]\naws_secret_access_key = TEST-ONLY-aws\n",
            ".cursor/mcp.json": '{"mcpServers": {"kh": {"env": '
                                '{"MY_API_KEY": "TEST-ONLY-mcp"}}}}',
            ".config/Code/User/settings.json": '{"github.copilot.chat.apikey": '
                                               '"TEST-ONLY-ide", "editor.fontSize": 14}',
        })
        items = wrapper.inventory_standing_credentials(home)
        kinds = {i.kind for i in items}
        self.assertIn("cli_store", kinds)
        self.assertIn("mcp_config", kinds)
        self.assertIn("mcp_config_credential", kinds)
        self.assertIn("ide_settings_credential", kinds)
        self.assertNotIn("TEST-ONLY-aws", str(items))
        self.assertNotIn("TEST-ONLY-mcp", str(items))
        self.assertNotIn("TEST-ONLY-ide", str(items))

    def test_project_mcp_config_scanned_when_given(self):
        home = self._home_with({})
        proj = tempfile.mkdtemp(prefix="kh-w16-proj-")
        self.addCleanup(lambda: __import__("shutil").rmtree(proj, ignore_errors=True))
        with open(os.path.join(proj, ".mcp.json"), "w") as fh:
            fh.write('{"mcpServers": {"x": {"env": {"GH_TOKEN": "TEST-ONLY-proj"}}}}')
        without = wrapper.inventory_standing_credentials(home)
        with_proj = wrapper.inventory_standing_credentials(home, proj)
        self.assertFalse(any(i.kind == "mcp_config_credential" for i in without))
        self.assertTrue(any(i.kind == "mcp_config_credential" for i in with_proj))
        self.assertNotIn("TEST-ONLY-proj", str(with_proj))


class TestMigration(unittest.TestCase):
    def test_migrate_comments_exports_backs_up_verifies_no_value_leak(self):
        home = tempfile.mkdtemp(prefix="kh-w16-mig-")
        self.addCleanup(lambda: __import__("shutil").rmtree(home, ignore_errors=True))
        with open(os.path.join(home, ".zshrc"), "w") as fh:
            fh.write('export GITHUB_TOKEN=TEST-ONLY-mig\nexport EDITOR=vi\n')
        with open(os.path.join(home, ".netrc"), "w") as fh:
            fh.write("machine example.test login u password TEST-ONLY-netrc\n")
        # Dry run changes nothing.
        dry = wrapper.apply_shell_migration(home, dry_run=True)
        with open(os.path.join(home, ".zshrc")) as fh:
            self.assertIn("export GITHUB_TOKEN=", fh.read())
        self.assertEqual(len(dry["migrated"]), 1)
        # Real run: commented, backed up, verified, manual store untouched.
        report = wrapper.apply_shell_migration(home)
        self.assertEqual(report["remaining"], [])
        with open(os.path.join(home, ".zshrc")) as fh:
            text = fh.read()
        self.assertIn("# sealvra-migrated: export GITHUB_TOKEN=", text)
        self.assertIn("export EDITOR=vi", text)
        backup = os.path.join(home, ".zshrc.kh-migrate-bak")
        self.assertTrue(os.path.exists(backup))
        self.assertEqual(oct(os.stat(backup).st_mode & 0o777), "0o600")
        with open(os.path.join(home, ".netrc")) as fh:
            self.assertIn("TEST-ONLY-netrc", fh.read())  # manual, not edited
        self.assertNotIn("TEST-ONLY-mig", str(report))
        self.assertIn("rotate", report["limit"])
        # Idempotent: second run migrates nothing, keeps original backup.
        again = wrapper.apply_shell_migration(home)
        self.assertEqual(again["migrated"], [])
        with open(backup) as fh:
            self.assertIn("export GITHUB_TOKEN=TEST-ONLY-mig", fh.read())
        # Plan marks the store manual, never comment_out.
        plan = wrapper.plan_migration(home)
        self.assertTrue(any(i.action == "manual" and i.location.endswith(".netrc")
                            for i in plan))
        self.assertFalse(any(i.action == "comment_out" for i in plan))


class TestSessionConfigWatch(unittest.TestCase):
    def test_change_suspends_and_failed_reprobe_keeps_suspension(self):
        path = _write_tmp("v1")
        try:
            watch = wrapper.SessionConfigWatch([path])
            self.assertEqual(watch.status(), "verified")
            self.assertEqual(watch.check(), [])
            with open(path, "w") as fh:
                fh.write("v2")
            changed = watch.check()
            self.assertEqual(changed, [path])
            self.assertEqual(watch.status(), "suspended_unverified")
            self.assertTrue(watch.needs_reprobe)
            self.assertFalse(watch.acknowledge_reprobe(False))
            self.assertEqual(watch.status(), "suspended_unverified")
            self.assertTrue(watch.acknowledge_reprobe(True))
            self.assertEqual(watch.status(), "verified")
            self.assertEqual(watch.check(), [])
        finally:
            os.unlink(path)

    def test_created_and_deleted_files_suspend(self):
        tmpdir = tempfile.mkdtemp(prefix="kh-w16-watch-")
        self.addCleanup(lambda: __import__("shutil").rmtree(tmpdir, ignore_errors=True))
        path = os.path.join(tmpdir, "cfg.toml")
        watch = wrapper.SessionConfigWatch([path])  # starts MISSING
        with open(path, "w") as fh:
            fh.write("x")
        self.assertEqual(watch.check(), [path])
        self.assertTrue(watch.acknowledge_reprobe(True))
        os.unlink(path)
        self.assertEqual(watch.check(), [path])

    def test_watch_expires_probe_verdicts_via_combined_hash(self):
        path = _write_tmp("v1")
        try:
            watch = wrapper.SessionConfigWatch([path])
            cfg_hash = watch.combined_config_hash()
            matrix = probe.ProbeMatrix()
            matrix.record(probe.ProbeVerdict("codex", "1.0", "chat", "m1",
                                             "local", cfg_hash, "pass", "c1"))
            self.assertTrue(matrix.is_fully_verified(
                "codex", "1.0", cfg_hash, [("chat", "m1", "local")]))
            with open(path, "w") as fh:
                fh.write("v2")
            self.assertTrue(watch.check())
            new_hash = watch.combined_config_hash()
            self.assertNotEqual(new_hash, cfg_hash)
            self.assertEqual(matrix.per_cell_status("codex", "1.0", new_hash)
                             [("chat", "m1", "local")], "expired")
        finally:
            os.unlink(path)

    def test_launch_carries_watch(self):
        path = _write_tmp("v1")
        try:
            plan = wrapper.launch_agent(
                "claude", [], "http://127.0.0.1:8765", dry_run=True,
                explicit_binary=BENIGN_BINARY, watch_config_paths=[path])
            self.assertIsNotNone(plan.config_watch)
            self.assertEqual(plan.config_watch.status(), "verified")
            with open(path, "w") as fh:
                fh.write("v2")
            self.assertEqual(plan.config_watch.check(), [path])
        finally:
            os.unlink(path)

    def test_cursor_cli_route_is_mcp_not_env(self):
        route = wrapper.cursor_cli_launch_route()
        self.assertEqual(route["env_mode"], "refused")
        self.assertEqual(route["mcp_mode"], "primary")


class TestMcpOriginHost(unittest.TestCase):
    def test_ipv6_origin_passes_userinfo_refused(self):
        mcp.validate_origin("http://[::1]:9000")
        mcp.validate_origin("http://localhost:3000")
        with self.assertRaises(mcp.McpRefusal):
            mcp.validate_origin("http://127.0.0.1@evil.example")
        with self.assertRaises(mcp.McpRefusal):
            mcp.validate_origin("http://evil.example@127.0.0.1")

    def test_host_header_rebinding_refused(self):
        with self.assertRaises(mcp.McpRefusal):
            mcp.validate_host_header("evil.example")
        with self.assertRaises(mcp.McpRefusal):
            mcp.validate_host_header("127.0.0.1.evil.example")
        mcp.validate_host_header("127.0.0.1:9000")
        mcp.validate_host_header(None)
        store = mcp.BindingStore()
        with self.assertRaises(mcp.McpRefusal):
            mcp.validate_mcp_request(
                {"Host": "evil.example"}, "127.0.0.1",
                "kh_sess_TEST-ONLY", None, store)

    def test_tunneled_via_validate_request_needs_named_consent(self):
        store = mcp.BindingStore()
        binding = store.create("kh_sess_TEST-ONLY", "127.0.0.1")
        with self.assertRaises(mcp.McpRefusal):
            mcp.validate_mcp_request(
                {"X-Forwarded-For": "1.2.3.4"}, "127.0.0.1",
                "kh_sess_TEST-ONLY", binding.binding_id, store)
        with self.assertRaises(mcp.McpRefusal):
            mcp.validate_mcp_request(
                {"X-Forwarded-For": "1.2.3.4"}, "127.0.0.1",
                "kh_sess_TEST-ONLY", binding.binding_id, store,
                remote_endpoint_consented=True,
                remote_mode_name="tunnel mode")
        got = mcp.validate_mcp_request(
            {"X-Forwarded-For": "1.2.3.4"}, "127.0.0.1",
            "kh_sess_TEST-ONLY", binding.binding_id, store,
            remote_endpoint_consented=True,
            remote_mode_name="remote endpoint mode")
        self.assertEqual(got.binding_id, binding.binding_id)


class TestCursorClassMDecision(unittest.TestCase):
    def test_free_plan_refused_never_silent(self):
        d = probe.cursor_class_m_decision("my-model", plan="free",
                                          backend_transmission_consent=True,
                                          canary_probed=True)
        self.assertFalse(d.allowed)
        self.assertEqual(d.routing, "ignored_by_plan")

    def test_unconfirmed_plan_gated(self):
        d = probe.cursor_class_m_decision("my-model", plan=None,
                                          backend_transmission_consent=True,
                                          canary_probed=True)
        self.assertFalse(d.allowed)
        self.assertEqual(d.routing, "gated")

    def test_builtin_models_bypass_even_with_consent_and_canary(self):
        for model in ("claude-opus-4-x", "gemini-2-x"):
            d = probe.cursor_class_m_decision(
                model, plan="pro", backend_transmission_consent=True,
                canary_probed=True)
            self.assertFalse(d.allowed, model)
            self.assertEqual(d.routing, "bypass_by_design", model)

    def test_bypass_surfaces_refused(self):
        d = probe.cursor_class_m_decision(
            "my-model", plan="pro", surface="tab_completion",
            backend_transmission_consent=True, canary_probed=True)
        self.assertFalse(d.allowed)
        self.assertEqual(d.routing, "bypass_by_design")

    def test_consent_without_canary_gated_canary_with_consent_allowed_with_warning(self):
        gated = probe.cursor_class_m_decision(
            "my-model", plan="pro", backend_transmission_consent=True,
            canary_probed=False)
        self.assertFalse(gated.allowed)
        self.assertTrue(gated.requires_canary_probe)
        refused = probe.cursor_class_m_decision(
            "my-model", plan="pro", backend_transmission_consent=False,
            canary_probed=True)
        self.assertFalse(refused.allowed)
        allowed = probe.cursor_class_m_decision(
            "my-model", plan="pro", backend_transmission_consent=True,
            canary_probed=True)
        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.routing, "via_override")
        # Allowed does NOT mean the token stays local: warning persists.
        self.assertIn("Cursor's backend", allowed.warning)

    def test_classify_cursor_model(self):
        self.assertEqual(probe.classify_cursor_model("claude-sonnet-4"),
                         "builtin_anthropic_bypass")
        self.assertEqual(probe.classify_cursor_model("gemini-2.5-pro"),
                         "builtin_google_bypass")
        self.assertEqual(probe.classify_cursor_model("my-custom-model"),
                         "custom_via_override")
        self.assertEqual(probe.classify_cursor_model(""),
                         "unknown_probe_required")


class TestProbeHardening(unittest.TestCase):
    def test_tunneled_and_session_credential_entries_fail(self):
        base = dict(agent="codex", build="1.0", surface="chat", model="m1",
                    harness="local", config_hash="abc", canary_id="c1",
                    upstream_host="127.0.0.1:8765", path="/v1/responses",
                    model_id="m1", auth_scheme="bearer-session",
                    source_ip="127.0.0.1")
        tunneled = probe.ProbeRequest(**{**base, "tunneled": True})
        failures = probe.assert_probe_entry(
            tunneled, "127.0.0.1:8765", "/v1/responses", "m1", "bearer-session")
        self.assertTrue(any("tunneled" in f for f in failures))
        session_cred = probe.ProbeRequest(**{**base, "credential_kind": "session"})
        failures = probe.assert_probe_entry(
            session_cred, "127.0.0.1:8765", "/v1/responses", "m1", "bearer-session")
        self.assertTrue(any("canary" in f for f in failures))
        clean = probe.ProbeRequest(**base)
        self.assertEqual(probe.assert_probe_entry(
            clean, "127.0.0.1:8765", "/v1/responses", "m1", "bearer-session"), [])

    def test_matrix_refuses_tunneled_and_bypass_passes(self):
        matrix = probe.ProbeMatrix()
        with self.assertRaises(ValueError):
            matrix.record(probe.ProbeVerdict(
                "codex", "1.0", "chat", "m1", "local", "h", "pass", "c1",
                source="tunneled"))
        with self.assertRaises(ValueError):
            matrix.record(probe.ProbeVerdict(
                "cursor", "1.0", "builtin_anthropic_model", "claude-x",
                "local", "h", "pass", "c2"))
        # Fail verdicts for bypass surfaces are recordable (honest state).
        matrix.record(probe.ProbeVerdict(
            "cursor", "1.0", "builtin_anthropic_model", "claude-x",
            "local", "h", "fail", "c2"))
        self.assertEqual(matrix.per_cell_status("cursor", "1.0", "h")
                         [("builtin_anthropic_model", "claude-x", "local")],
                         "fail")

    def test_remote_endpoint_mode_exact_name_only(self):
        with self.assertRaises(ValueError):
            probe.RemoteEndpointMode("tunnel mode", True)
        with self.assertRaises(ValueError):
            probe.RemoteEndpointMode("remote endpoint mode", False)
        mode = probe.RemoteEndpointMode("remote endpoint mode", True)
        self.assertEqual(mode.mode_name, "remote endpoint mode")

    def test_verdict_time_expiry(self):
        matrix = probe.ProbeMatrix(verdict_ttl_seconds=300)
        matrix.record(probe.ProbeVerdict("codex", "1.0", "chat", "m1",
                                         "local", "h", "pass", "c1",
                                         created_at=1000.0))
        self.assertTrue(matrix.is_fully_verified(
            "codex", "1.0", "h", [("chat", "m1", "local")], now=1200.0))
        self.assertFalse(matrix.is_fully_verified(
            "codex", "1.0", "h", [("chat", "m1", "local")], now=2000.0))

    def test_canary_revoke_before_real_session(self):
        canary = probe.mint_canary_credential()
        with self.assertRaises(ValueError):
            probe.assert_canary_revoked(canary)
        canary.revoke()
        probe.assert_canary_revoked(canary)  # no raise
        self.assertFalse(canary.is_valid())


if __name__ == "__main__":
    unittest.main()
