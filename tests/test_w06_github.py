"""W06 GitHub adapter tests (unittest, stdlib only).

No real GitHub calls. Network use is limited to one loopback
http.server mock that returns fake X-OAuth-Scopes headers, proving
the classic-scopes parsing path against a real HTTP round-trip.
All tokens are TEST-ONLY fakes.
"""

import http.client
import http.server
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sealvra import github as gh


def cls(method, path, body=None, allowlist=None):
    return gh.classify(method, path, body=body, repo_allowlist=allowlist)


class TestContentsWriteClassification(unittest.TestCase):
    def test_file_edit_is_write_not_plain_allow(self):
        d = cls("PUT", "/repos/o/r/contents/docs/a.md", {"message": "x"})
        self.assertTrue(d.allowed)
        self.assertEqual(d.level, 2)  # allow-with-log, template rules by broker

    def test_branch_delete_is_not_files_only(self):
        d = cls("DELETE", "/repos/o/r/git/refs/heads/feature")
        self.assertFalse(d.allowed)
        self.assertEqual(d.level, 4)

    def test_tag_delete_denied(self):
        d = cls("DELETE", "/repos/o/r/git/refs/tags/v1")
        self.assertFalse(d.allowed)

    def test_ref_create_needs_approval(self):
        d = cls("POST", "/repos/o/r/git/refs", {"ref": "refs/heads/x"})
        self.assertFalse(d.allowed)
        self.assertEqual(d.level, 3)

    def test_force_ref_update_denied(self):
        d = cls("PATCH", "/repos/o/r/git/refs/heads/main",
                {"sha": "abc", "force": True})
        self.assertFalse(d.allowed)
        self.assertEqual(d.level, 4)

    def test_nonforce_ref_update_needs_approval(self):
        d = cls("PATCH", "/repos/o/r/git/refs/heads/main", {"sha": "abc"})
        self.assertFalse(d.allowed)
        self.assertEqual(d.level, 3)

    def test_branch_rename_denied(self):
        d = cls("POST", "/repos/o/r/branches/main/rename", {"new_name": "x"})
        self.assertFalse(d.allowed)

    def test_merges_endpoint_denied(self):
        d = cls("POST", "/repos/o/r/merges", {})
        self.assertFalse(d.allowed)
        self.assertEqual(d.level, 4)

    def test_release_create_and_delete_denied(self):
        self.assertFalse(cls("POST", "/repos/o/r/releases", {}).allowed)
        self.assertFalse(cls("DELETE", "/repos/o/r/releases/1").allowed)
        self.assertFalse(cls("DELETE", "/repos/o/r/releases/assets/1").allowed)

    def test_dispatch_and_merge_upstream_denied(self):
        self.assertFalse(cls("POST", "/repos/o/r/dispatches", {}).allowed)
        self.assertFalse(cls("POST", "/repos/o/r/merge-upstream", {}).allowed)

    def test_file_delete_denied(self):
        d = cls("DELETE", "/repos/o/r/contents/docs/a.md", {"message": "x"})
        self.assertFalse(d.allowed)

    def test_deletion_matrix_covers_repo_and_branch(self):
        paths = [row["path"] for row in gh.DELETION_MATRIX]
        self.assertTrue(any("DELETE /repos/{owner}/{repo}" in p for p in paths))
        self.assertTrue(any("git/refs" in p for p in paths))
        self.assertGreaterEqual(len(gh.DELETION_MATRIX), 15)


class TestHardDenies(unittest.TestCase):
    def test_repo_delete_refused(self):
        d = cls("DELETE", "/repos/o/r")
        self.assertFalse(d.allowed)
        self.assertIn("refused", d.reason)

    def test_secrets_never_proxied_all_families(self):
        for p in ("/repos/o/r/actions/secrets/X",
                  "/repos/o/r/dependabot/secrets/X",
                  "/repos/o/r/codespaces/secrets/X",
                  "/orgs/o/actions/secrets/X"):
            self.assertFalse(cls("PUT", p, {}).allowed, p)
            self.assertFalse(cls("GET", p).allowed, p)

    def test_import_refuses_ssh_keys_gists_secrets(self):
        refusals = gh.check_import_permissions(
            ["Git SSH keys:write", "Gists:write", "Secrets:write"])
        names = [r["permission"] for r in refusals]
        self.assertIn("Git SSH keys:write", names)
        self.assertIn("Gists:write", names)
        self.assertTrue(any("Secrets" in n for n in names))

    def test_import_clean_key_no_refusal(self):
        self.assertEqual(
            gh.check_import_permissions(["Contents:read", "Issues:read"]), [])

    def test_webhook_deploykey_collaborator_denied(self):
        self.assertFalse(cls("POST", "/repos/o/r/hooks", {}).allowed)
        self.assertFalse(cls("POST", "/repos/o/r/keys", {}).allowed)
        self.assertFalse(cls("PUT", "/repos/o/r/collaborators/bob", {}).allowed)

    def test_ruleset_bypass_edit_hard_denied(self):
        self.assertFalse(cls("PUT", "/repos/o/r/rulesets/1", {}).allowed)

    def test_private_to_public_denied(self):
        d = cls("PATCH", "/repos/o/r", {"private": False})
        self.assertFalse(d.allowed)


class TestCommentCommandDeny(unittest.TestCase):
    def test_deploy_slash_denied(self):
        d = gh.check_comment_body("/deploy production")
        self.assertFalse(d.allowed)
        self.assertEqual(d.level, 4)

    def test_command_on_later_line_denied(self):
        d = gh.check_comment_body("looks good\n/backport release-1")
        self.assertFalse(d.allowed)

    def test_claude_merge_denied(self):
        self.assertFalse(gh.check_comment_body("@claude merge").allowed)
        self.assertFalse(gh.check_comment_body("please @claude approve").allowed)

    def test_plain_comment_allowed_with_log(self):
        d = gh.check_comment_body("this fix looks right, thanks")
        self.assertTrue(d.allowed)
        self.assertEqual(d.level, 2)

    def test_word_deploy_without_slash_allowed(self):
        self.assertTrue(gh.check_comment_body("we deploy on fridays").allowed)

    def test_comment_endpoint_enforces_command_deny(self):
        d = cls("POST", "/repos/o/r/issues/1/comments", {"body": "/deploy"})
        self.assertFalse(d.allowed)
        d = cls("POST", "/repos/o/r/issues/1/comments", {"body": "nice work"})
        self.assertTrue(d.allowed)

    def test_comment_edit_denied_by_default(self):
        d = cls("PATCH", "/repos/o/r/issues/comments/9", {"body": "edited"})
        self.assertFalse(d.allowed)

    def test_workflow_warning_present(self):
        self.assertIsNotNone(gh.comment_workflow_warning(True))
        self.assertIsNone(gh.comment_workflow_warning(False))


class TestGraphQLDeny(unittest.TestCase):
    def test_graphql_path_denied(self):
        d = cls("POST", "/graphql", {"query": "mutation { deleteIssue }"})
        self.assertFalse(d.allowed)
        self.assertEqual(d.level, 4)

    def test_graphql_list_enumerates_destructives(self):
        for name in ("deleteIssue", "deleteDiscussion", "deleteEnvironment",
                     "transferIssue", "enablePullRequestAutoMerge",
                     "enqueuePullRequest", "dismissPullRequestReview",
                     "dismissRepositoryVulnerabilityAlert"):
            self.assertIn(name, gh.GRAPHQL_ONLY_DESTRUCTIVES)


class TestMergeGating(unittest.TestCase):
    def test_rest_merge_level4(self):
        d = cls("PUT", "/repos/o/r/pulls/5/merge", {"merge_method": "squash"})
        self.assertFalse(d.allowed)
        self.assertEqual(d.level, gh.MERGE_APPROVAL_LEVEL)
        self.assertEqual(d.level, 4)

    def test_merge_async_level4_and_bypass_denied(self):
        d = cls("PUT", "/repos/o/r/pulls/5/merge-async", {})
        self.assertFalse(d.allowed)
        self.assertEqual(d.level, 4)
        d = cls("PUT", "/repos/o/r/pulls/5/merge-async",
                {"bypass_rules": True})
        self.assertFalse(d.allowed)
        self.assertIn("bypass", d.reason)

    def test_merge_requires_approval_flag(self):
        self.assertTrue(gh.merge_requires_approval())

    def test_pr_approval_is_merge_class(self):
        d = cls("POST", "/repos/o/r/pulls/5/reviews", {"event": "APPROVE"})
        self.assertFalse(d.allowed)
        self.assertEqual(d.level, 4)

    def test_update_branch_is_merge_class(self):
        d = cls("PUT", "/repos/o/r/pulls/5/update-branch", {})
        self.assertFalse(d.allowed)
        self.assertEqual(d.level, 4)

    def test_fork_run_approval_denied(self):
        d = cls("POST", "/repos/o/r/actions/runs/7/approve", {})
        self.assertFalse(d.allowed)

    def test_run_delete_hard_denied(self):
        self.assertFalse(cls("DELETE", "/repos/o/r/actions/runs/7").allowed)

    def test_issue_transfer_denied(self):
        d = cls("POST", "/repos/o/r/issues/1/transfer",
                {"new_organization": "x", "new_repository": "y"})
        self.assertFalse(d.allowed)

    def test_fake_green_ci_needs_approval(self):
        d = cls("POST", "/repos/o/r/statuses/abc", {"state": "success"})
        self.assertFalse(d.allowed)
        self.assertEqual(d.level, 3)


class TestForcePushAndAllowlist(unittest.TestCase):
    def test_delete_then_recreate_denied(self):
        t = gh.RefRewriteTracker()
        t.record_delete("refs/heads/feature")
        d = t.check_create("refs/heads/feature")
        self.assertFalse(d.allowed)
        self.assertTrue(t.check_create("refs/heads/other").allowed)

    def test_allowlist_binding(self):
        d = cls("GET", "/repos/other/r/issues", allowlist=("o/r",))
        self.assertFalse(d.allowed)
        d = cls("GET", "/repos/o/r/issues", allowlist=("o/r",))
        self.assertTrue(d.allowed)

    def test_unmodelled_endpoint_denied(self):
        self.assertFalse(cls("POST", "/repos/o/r/some-new-endpoint", {}).allowed)

    def test_git_interposition_honestly_not_built(self):
        self.assertFalse(gh.GIT_INTERPOSITION_BUILT)
        pol = gh.git_push_policy()
        self.assertFalse(pol["gated"])
        self.assertFalse(pol["logged"])
        self.assertIn("NOT", pol["note"])
        self.assertIn("bypass", pol["note"])


class TestArtifactInventory(unittest.TestCase):
    def test_inventory_lists_created_artifacts(self):
        inv = gh.ArtifactInventory()
        inv.record("webhook", "hook-1", "o/r")
        inv.record("deploy_key", "key-1", "o/r")
        inv.record("collaborator_invite", "bob", "o/r")
        self.assertEqual(len(inv.list_for_removal()), 3)
        self.assertIn("NOT", inv.kill_switch_copy())

    def test_unknown_kind_rejected(self):
        with self.assertRaises(ValueError):
            gh.ArtifactInventory().record("fork", "x", "o/r")


class TestPATVerificationCorrections(unittest.TestCase):
    def test_role_object_is_not_a_grant(self):
        v = gh.verify_token("fine-grained",
                            role_permissions={"admin": True, "push": True})
        self.assertTrue(any("ROLE" in w for w in v.warnings))
        self.assertTrue(v.unverified)  # fail closed, nothing inferred

    def test_fine_grained_has_no_scopes_header(self):
        v = gh.verify_token("fine-grained", scopes_header_present=False)
        self.assertIsNone(v.classic_scopes)
        v2 = gh.verify_token("fine-grained", scopes_header_present=True)
        self.assertTrue(any("unexpected" in w for w in v2.warnings))

    def test_classic_scopes_enumerated_and_exclusions_noted(self):
        scopes = gh.parse_classic_scopes("repo, gist, read:user")
        self.assertIn("repo", scopes)
        v = gh.verify_token("classic", scopes_header="repo",
                            scopes_header_present=True)
        self.assertIn("repo", v.classic_scopes)
        self.assertTrue(any("workflow" in w for w in v.warnings))

    def test_classic_repo_excludes_workflow_and_delete(self):
        self.assertIn("workflow", str(gh.CLASSIC_SCOPE_EXCLUSIONS["repo"]))
        self.assertIn("delete_repo", str(gh.CLASSIC_SCOPE_EXCLUSIONS["repo"]))

    def test_saml_flows_split_by_kind(self):
        fg = gh.saml_guidance("fine-grained", 404)
        self.assertIn("re-create", fg)
        cl = gh.saml_guidance("classic", 403, "https://example.invalid/sso")
        self.assertIn("1 hour", cl)
        app = gh.saml_guidance("github_app_user", 200)
        self.assertIn("auto-authorised", app)

    def test_pending_org_approval_diagnostic(self):
        v = gh.verify_token("fine-grained", pending_org_approval=True)
        self.assertTrue(any("Pending requests" in w for w in v.warnings))

    def test_expiry_is_attested_not_verified(self):
        v = gh.verify_token("fine-grained", user_attested_expiry="2030-01-01")
        self.assertEqual(v.expiry, "2030-01-01")
        # No verification claim exists on the record:
        self.assertNotIn("verified", " ".join(v.warnings).lower().replace(
            "user-attested", ""))

    def test_token_kind_detection(self):
        self.assertEqual(gh.detect_token_kind("github_pat_TEST-ONLY-x"),
                         "fine-grained")
        self.assertEqual(gh.detect_token_kind("ghp_TEST-ONLY-x"), "classic")


class _ScopesHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - stdlib handler name
        self.send_response(200)
        self.send_header("X-OAuth-Scopes", "repo, gist")
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"login": "TEST-ONLY-user"}')

    def log_message(self, *args):
        pass


class TestLoopbackMockScopes(unittest.TestCase):
    """Classic scopes header parsed from a real loopback HTTP round-trip."""

    def test_scopes_header_from_loopback_mock(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), _ScopesHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port,
                                              timeout=5)
            conn.request("GET", "/user")
            resp = conn.getresponse()
            resp.read()
            header = resp.getheader("X-OAuth-Scopes")
            self.assertEqual(gh.parse_classic_scopes(header),
                             ["repo", "gist"])
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
