from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
CLOSURE_WORKFLOW = ROOT / ".github/workflows/post-release-closure.yml"
CLEANUP_WORKFLOW = ROOT / ".github/workflows/post-release-cleanup.yml"
PROMOTION_WORKFLOW = ROOT / ".github/workflows/release-promotion.yml"
PROBE_TOOL = "tools/probe_release_automation_authority.py"
NATIVE_GATES = "tools/release_native_gates.py"
CLEANUP_TOOL = "tools/release_branch_cleanup.py"
APP_ACTION = "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"


class PostReleaseAutomationAuthorityTests(unittest.TestCase):
    def _closure(self) -> str:
        return CLOSURE_WORKFLOW.read_text(encoding="utf-8")

    def _cleanup(self) -> str:
        return CLEANUP_WORKFLOW.read_text(encoding="utf-8")

    def test_promotion_proves_release_app_closure_authority_before_publication(self) -> None:
        workflow = PROMOTION_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("closure-readiness:", workflow)
        self.assertIn("prove Release App closure authority before publication", workflow)
        self.assertIn(APP_ACTION, workflow)
        self.assertIn("LINURA_RELEASE_APP_CLIENT_ID", workflow)
        self.assertIn("LINURA_RELEASE_APP_PRIVATE_KEY", workflow)
        self.assertIn("permission-actions: write", workflow)
        self.assertIn("permission-contents: write", workflow)
        self.assertIn("permission-pull-requests: write", workflow)
        self.assertIn(PROBE_TOOL, workflow)
        self.assertIn("--credential-source github-app", workflow)
        self.assertIn("needs: [validate, closure-readiness]", workflow)

        preflight = workflow.index("closure-readiness:")
        app = workflow.index(APP_ACTION)
        probe = workflow.index(PROBE_TOOL)
        dispatch = workflow.index("\n  dispatch:")
        release_dispatch = workflow.index("gh workflow run release.yml")
        self.assertLess(preflight, app)
        self.assertLess(app, probe)
        self.assertLess(probe, dispatch)
        self.assertLess(dispatch, release_dispatch)

    def test_closure_mutation_uses_release_app_and_native_pr_gates(self) -> None:
        workflow = self._closure()
        self.assertIn(APP_ACTION, workflow)
        self.assertIn("LINURA_RELEASE_APP_CLIENT_ID", workflow)
        self.assertIn("LINURA_RELEASE_APP_PRIVATE_KEY", workflow)
        self.assertIn("--credential-source github-app", workflow)
        self.assertIn(PROBE_TOOL, workflow)
        self.assertIn(NATIVE_GATES, workflow)
        self.assertIn("--expected-changed-files", workflow)
        self.assertIn('pulls/$PR_NUMBER/merge', workflow)
        self.assertIn("automation/post-release-${RELEASE_TAG}-${head_sha}", workflow)
        self.assertNotIn("@codex review", workflow)
        self.assertNotIn("release_workflow_dispatch.py", workflow)
        self.assertNotIn("Delete obsolete release-scoped branches", workflow)

    def test_closure_retry_reuses_exact_sha_addressed_branch_and_pr(self) -> None:
        workflow = self._closure()
        commit = workflow.split("- name: Commit or re-prove SHA-addressed deterministic closure", 1)[1].split(
            "- name: Open or re-prove protected closure PR", 1
        )[0]
        open_pr = workflow.split("- name: Open or re-prove protected closure PR", 1)[1].split(
            "- name: Require GitHub-native closure PR gates", 1
        )[0]

        self.assertIn('expected_tree="$(git write-tree)"', commit)
        self.assertIn('existing_json="$(gh pr list --state open --base main', commit)
        self.assertIn('test "$branch" = "automation/post-release-${RELEASE_TAG}-${head_sha}"', commit)
        self.assertIn("'.parents | length'", commit)
        self.assertIn("'.parents[0].sha'", commit)
        self.assertIn('jq -r .tree.sha', commit)
        self.assertIn('= "$expected_tree"', commit)
        self.assertIn('gh pr list --state open --base main --head "$BRANCH"', open_pr)
        self.assertIn('test "$(jq -r \' .[0].headRefOid\' <<<"$existing")" = "$HEAD_SHA"'.replace("' .", "'."), open_pr)

    def test_closure_merge_reproves_native_gate_immediately_before_mutation(self) -> None:
        workflow = self._closure()
        merge = workflow.split("- name: Re-prove and squash merge exact deterministic closure", 1)[1].split(
            "- name: Confirm event-driven terminal cleanup handoff", 1
        )[0]
        self.assertIn(NATIVE_GATES, merge)
        self.assertIn("--timeout-seconds 0", merge)
        self.assertIn('test "$BRANCH" = "automation/post-release-${RELEASE_TAG}-${HEAD_SHA}"', merge)
        self.assertIn('test "$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"', merge)
        self.assertIn('test "$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/$BRANCH" --jq .object.sha)" = "$HEAD_SHA"', merge)
        self.assertIn("'.parents | length'", merge)
        self.assertIn("'.parents[0].sha'", merge)
        self.assertIn('pulls/$PR_NUMBER/merge', merge)

    def test_cleanup_is_separate_event_driven_retryable_transaction(self) -> None:
        closure = self._closure()
        cleanup = self._cleanup()
        self.assertIn("post-release-cleanup.yml", closure)
        self.assertIn("workflow_run:", cleanup)
        self.assertIn('startsWith(github.event.workflow_run.head_commit.message, \'chore: close v\')', cleanup)
        self.assertIn(NATIVE_GATES, cleanup)
        self.assertIn(CLEANUP_TOOL, cleanup)
        self.assertIn("cancel-in-progress: false", cleanup)
        self.assertNotIn("gh workflow run post-release-cleanup.yml", closure)

    def test_cleanup_authority_is_exact_qualified_closure_commit(self) -> None:
        cleanup = self._cleanup()
        self.assertIn('CLOSURE_SHA: ${{ github.event.workflow_run.head_sha }}', cleanup)
        self.assertIn('git fetch --no-tags origin "refs/heads/main:refs/remotes/origin/main" --force', cleanup)
        self.assertIn('git cat-file -e "$CLOSURE_SHA^{commit}"', cleanup)
        self.assertIn('git merge-base --is-ancestor "$CLOSURE_SHA" refs/remotes/origin/main', cleanup)
        self.assertIn('git show "$CLOSURE_SHA:contracts/release-branch-cleanup.toml"', cleanup)
        self.assertIn("contracts/release-branch-cleanup.toml", cleanup)
        self.assertNotIn('test "$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main" --jq .object.sha)" = "$CLOSURE_SHA"', cleanup)

    def test_cleanup_token_is_narrower_than_closure_mutation_token(self) -> None:
        cleanup = self._cleanup()
        token_block = cleanup.split("- name: Mint cleanup-scoped Release App token", 1)[1].split(
            "- name: Delete only exact release-owned branches under ref leases", 1
        )[0]
        self.assertIn(APP_ACTION, token_block)
        self.assertIn("permission-contents: write", token_block)
        self.assertIn("permission-pull-requests: read", token_block)
        self.assertNotIn("permission-actions: write", token_block)
        self.assertNotIn("permission-pull-requests: write", token_block)

    def test_cleanup_tool_contract_has_sha_addressed_namespaces_and_atomic_leases(self) -> None:
        tool = (ROOT / "tools/release_branch_cleanup.py").read_text(encoding="utf-8")
        for marker in (
            "automation/release-prep-",
            "automation/release-reprepare-",
            "automation/release-authorization-",
            "automation/post-release-",
            "sha-addressed-automation",
            "explicit-ledger",
            "expected_sha",
            "preserved concurrently moved branch",
            "preserved open-PR branch",
            "--force-with-lease=",
        ):
            self.assertIn(marker, tool)
        self.assertNotIn("verify-release/", tool)
        self.assertNotIn("series =", tool)
        self.assertNotIn("(cleanup|compact|minimal|review|release)", tool)
        self.assertNotIn('"fix/"', tool)
        self.assertNotIn('"release/"', tool)

    def test_closed_release_retry_is_idempotent_and_does_not_rewrite_state(self) -> None:
        workflow = self._closure()
        self.assertIn("Confirm idempotent already-closed state", workflow)
        closed = workflow.split("- name: Confirm idempotent already-closed state", 1)[1]
        self.assertIn("python3 tools/check_roadmap.py", closed)
        self.assertNotIn("git commit", closed)
        self.assertNotIn("gh pr create", closed)
        self.assertNotIn("pulls/$PR_NUMBER/merge", closed)

    def test_legacy_repository_token_mutation_authority_is_removed(self) -> None:
        closure = self._closure()
        promotion = PROMOTION_WORKFLOW.read_text(encoding="utf-8")
        for workflow in (closure, promotion):
            self.assertNotIn("--credential-source github\n", workflow)
            self.assertNotIn("RELEASE_AUTOMATION_TOKEN || github.token", workflow)
        self.assertNotIn("token: ${{ github.token }}", closure)


if __name__ == "__main__":
    unittest.main()
