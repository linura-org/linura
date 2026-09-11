from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
CLOSURE = ROOT / ".github/workflows/post-release-closure.yml"
CLEANUP = ROOT / ".github/workflows/post-release-cleanup.yml"
CLEANUP_TOOL = ROOT / "tools/release_branch_cleanup.py"
NATIVE_GATE_TOOL = ROOT / "tools/release_native_gates.py"
CI = ROOT / ".github/workflows/ci.yml"


class PostReleaseMachineHandoffSecurityTests(unittest.TestCase):
    def _closure(self) -> str:
        return CLOSURE.read_text(encoding="utf-8")

    def _cleanup(self) -> str:
        return CLEANUP.read_text(encoding="utf-8")

    def test_machine_closure_has_no_conversational_review_dependency(self) -> None:
        workflow = self._closure()
        self.assertNotIn("@codex review", workflow)
        self.assertNotIn("CODEX_BOT_USER_ID", workflow)
        self.assertNotIn("chatgpt-codex-connector", workflow)
        self.assertNotIn("issues/$PR_NUMBER/comments", workflow)
        self.assertNotIn("issues: write", workflow)

    def test_native_pr_gate_is_ruleset_authoritative_and_dispatch_is_not_a_substitute(self) -> None:
        workflow = self._closure()
        gate = workflow.split("- name: Require GitHub-native closure PR gates", 1)[1].split(
            "- name: Re-prove and squash merge exact deterministic closure", 1
        )[0]
        self.assertIn("tools/release_native_gates.py", gate)
        self.assertIn("--pr-number", gate)
        self.assertIn("--base-sha", gate)
        self.assertIn("--expected-changed-files", gate)
        self.assertNotIn("release_workflow_dispatch.py", gate)

        native_tool = NATIVE_GATE_TOOL.read_text(encoding="utf-8")
        self.assertIn('event="pull_request"', native_tool)
        self.assertIn('conclusion != "success"', native_tool)
        self.assertIn("refuses to substitute workflow_dispatch evidence", native_tool)
        self.assertIn('mergeable_state != "clean"', native_tool)
        self.assertIn("_unresolved_threads", native_tool)
        self.assertIn("reviewThreads(first:100, after:$cursor)", native_tool)

    def test_merge_boundary_reproves_native_gate_branch_parent_and_message(self) -> None:
        merge = self._closure().split(
            "- name: Re-prove and squash merge exact deterministic closure", 1
        )[1].split("- name: Confirm event-driven terminal cleanup handoff", 1)[0]
        self.assertIn("tools/release_native_gates.py", merge)
        self.assertIn("--timeout-seconds 0", merge)
        self.assertIn('test "$BRANCH" = "automation/post-release-${RELEASE_TAG}-${HEAD_SHA}"', merge)
        self.assertIn('test "$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/$BRANCH" --jq .object.sha)" = "$HEAD_SHA"', merge)
        self.assertIn("'.parents | length'", merge)
        self.assertIn("'.parents[0].sha'", merge)
        self.assertIn('= "$BASE_SHA"', merge)
        self.assertIn('chore: close $RELEASE_TAG release state', merge)
        self.assertIn('pulls/$PR_NUMBER/merge', merge)

    def test_cleanup_runs_only_after_native_main_push_gates(self) -> None:
        cleanup = self._cleanup()
        self.assertIn("workflow_run:", cleanup)
        self.assertIn("workflows: [\"CI\", \"Security\", \"CodeQL\"]", cleanup)
        self.assertIn("types: [completed]", cleanup)
        self.assertIn("branches: [main]", cleanup)
        self.assertIn('github.event.workflow_run.event == \'push\'', cleanup)
        self.assertIn('startsWith(github.event.workflow_run.head_commit.message, \'chore: close v\')', cleanup)
        self.assertIn("Require all native protected-main gates on closure commit", cleanup)
        self.assertIn("tools/release_native_gates.py", cleanup)
        self.assertIn("commit --event push", cleanup)

    def test_main_ci_does_not_cancel_exact_closure_gate_runs(self) -> None:
        ci = CI.read_text(encoding="utf-8")
        self.assertIn("group: ci-${{ github.ref }}", ci)
        self.assertIn("cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}", ci)

    def test_cleanup_authority_is_immutable_closure_commit_and_ancestry(self) -> None:
        cleanup = self._cleanup()
        self.assertIn('CLOSURE_SHA: ${{ github.event.workflow_run.head_sha }}', cleanup)
        self.assertIn('git fetch --no-tags origin "refs/heads/main:refs/remotes/origin/main" --force', cleanup)
        self.assertIn('git cat-file -e "$CLOSURE_SHA^{commit}"', cleanup)
        self.assertIn('git merge-base --is-ancestor "$CLOSURE_SHA" refs/remotes/origin/main', cleanup)
        self.assertIn('git show "$CLOSURE_SHA:contracts/release-branch-cleanup.toml"', cleanup)
        self.assertNotIn('test "$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main" --jq .object.sha)" = "$CLOSURE_SHA"', cleanup)

    def test_cleanup_uses_narrow_app_token_and_atomic_exact_ref_leases(self) -> None:
        workflow = self._cleanup()
        self.assertIn("Mint cleanup-scoped Release App token", workflow)
        self.assertIn("permission-contents: write", workflow)
        self.assertIn("permission-pull-requests: read", workflow)
        self.assertNotIn("permission-actions: write", workflow.split("Mint cleanup-scoped Release App token", 1)[1])
        self.assertIn("tools/release_branch_cleanup.py", workflow)

        tool = CLEANUP_TOOL.read_text(encoding="utf-8")
        for marker in (
            "automation/release-prep-",
            "automation/release-reprepare-",
            "automation/release-authorization-",
            "automation/post-release-",
        ):
            self.assertIn(marker, tool)
        self.assertNotIn("verify-release/", tool)
        self.assertIn("expected_sha", tool)
        self.assertIn("sha-addressed-automation", tool)
        self.assertIn("explicit-ledger", tool)
        self.assertIn("_open_pr_count", tool)
        self.assertIn("preserved open-PR branch", tool)
        self.assertIn("preserved moved branch", tool)
        self.assertIn("preserved concurrently moved branch", tool)
        self.assertIn("--force-with-lease=", tool)
        self.assertIn("_atomic_delete", tool)
        self.assertNotIn("tmp/{re.escape(series)}", tool)
        self.assertNotIn("cleanup|compact|minimal|review|release", tool)
        self.assertNotIn('"fix/"', tool)
        self.assertNotIn('"release/"', tool)

    def test_cleanup_absence_and_http_failures_are_distinct(self) -> None:
        tool = CLEANUP_TOOL.read_text(encoding="utf-8")
        self.assertIn("expected={200, 404}", tool)
        self.assertIn("if status == 404", tool)
        self.assertIn("already absent", tool)
        self.assertIn("raise CleanupError", tool)
        self.assertNotIn("except Exception: pass", tool)


if __name__ == "__main__":
    unittest.main()
