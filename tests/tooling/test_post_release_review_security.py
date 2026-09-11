from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/post-release-closure.yml"


class PostReleaseMachineHandoffSecurityTests(unittest.TestCase):
    def _workflow(self) -> str:
        return WORKFLOW.read_text(encoding="utf-8")

    def _gate_block(self) -> str:
        workflow = self._workflow()
        return workflow.split("- name: Require exact-head checks and zero unresolved review threads", 1)[1].split(
            "- name: Re-prove and squash merge exact deterministic closure", 1
        )[0]

    def _merge_block(self) -> str:
        workflow = self._workflow()
        return workflow.split("- name: Re-prove and squash merge exact deterministic closure", 1)[1].split(
            "- name: Resolve post-closure protected-main SHA", 1
        )[0]

    def _cleanup_block(self) -> str:
        return self._workflow().split("- name: Delete obsolete release-scoped branches", 1)[1]

    def test_machine_closure_has_no_conversational_review_dependency(self) -> None:
        workflow = self._workflow()
        self.assertNotIn("@codex review", workflow)
        self.assertNotIn("CODEX_BOT_USER_ID", workflow)
        self.assertNotIn("has_exact_codex_review", workflow)
        self.assertNotIn("has_clean_codex_comment", workflow)
        self.assertNotIn("issues/$PR_NUMBER/comments", workflow)
        self.assertNotIn("issues: write", workflow)

    def test_exact_head_gate_is_dispatch_bound_and_review_thread_fail_closed(self) -> None:
        gate = self._gate_block()
        self.assertIn("release_workflow_dispatch.py verify", gate)
        self.assertIn("post-release-closure-head-runs.jsonl", gate)
        self.assertIn("gh api graphql --paginate", gate)
        self.assertIn("reviewThreads(first:100, after:$endCursor)", gate)
        self.assertIn("pageInfo { hasNextPage endCursor }", gate)
        self.assertIn("awk '{ total += $1 } END { print total + 0 }'", gate)
        self.assertIn('test "$unresolved" = "0"', gate)
        self.assertIn('test "$(gh pr view "$PR_NUMBER" --json headRefOid --jq .headRefOid)" = "$HEAD_SHA"', gate)
        self.assertIn('test "$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"', gate)

    def test_merge_boundary_reproves_discussion_branch_parent_and_message(self) -> None:
        merge = self._merge_block()
        self.assertIn("release_workflow_dispatch.py verify", merge)
        self.assertIn("gh api graphql --paginate", merge)
        self.assertIn('test "$unresolved" = "0"', merge)
        self.assertIn('test "$(jq -r .headRefOid <<<"$pr")" = "$HEAD_SHA"', merge)
        self.assertIn('test "$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/$BRANCH" --jq .object.sha)" = "$HEAD_SHA"', merge)
        self.assertIn("'.parents | length'", merge)
        self.assertIn("'.parents[0].sha'", merge)
        self.assertIn('= "$BASE_SHA"', merge)
        self.assertIn('chore: close $RELEASE_TAG release state', merge)
        self.assertIn('pulls/$PR_NUMBER/merge', merge)
        self.assertIn("deterministic closure proof", merge)

    def test_cleanup_requires_owned_namespace_exact_ledger_target_lease_and_final_main_authority(self) -> None:
        cleanup = self._cleanup_block()
        self.assertIn("automation/release-prep-", cleanup)
        self.assertIn("automation/release-reprepare-", cleanup)
        self.assertIn("automation/release-authorization-", cleanup)
        self.assertIn("automation/post-release-", cleanup)
        self.assertIn("verify-release/", cleanup)
        self.assertIn("contracts/release-branch-cleanup.toml", cleanup)
        self.assertIn('MAIN_SHA: ${{ steps.final_main.outputs.main_sha }}', cleanup)
        self.assertIn('git show "$MAIN_SHA:contracts/release-branch-cleanup.toml"', cleanup)
        self.assertIn('test "$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main" --jq .object.sha)" = "$MAIN_SHA"', cleanup)
        self.assertIn('authority_sha="$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main" --jq .object.sha)"', cleanup)
        self.assertIn('test "$authority_sha" = "$MAIN_SHA"', cleanup)
        self.assertIn('cleanup_contract.get("schema_version") != 1', cleanup)
        self.assertIn('item.get("release") != tag', cleanup)
        self.assertIn('name.startswith("tmp/")', cleanup)
        self.assertIn('re.fullmatch(r"[0-9a-f]{40}", expected_sha)', cleanup)
        self.assertIn('lease_sha="$expected_sha"', cleanup)
        self.assertIn('current_sha" != "$lease_sha"', cleanup)
        self.assertIn("preserving legacy branch whose ref moved", cleanup)
        self.assertIn('git check-ref-format --branch "$branch"', cleanup)
        self.assertIn('git push --force-with-lease="$ref:$lease_sha" origin ":$ref"', cleanup)
        self.assertIn("preserving branch moved during cleanup lease", cleanup)
        self.assertIn("failed to delete unchanged release branch under exact SHA lease", cleanup)
        self.assertNotIn('gh api --method DELETE "repos/$GITHUB_REPOSITORY/git/refs/heads/$branch"', cleanup)
        self.assertNotIn("tmp/{re.escape(series)}", cleanup)
        self.assertNotIn("cleanup|compact|minimal|review|release", cleanup)
        self.assertIn('gh api --paginate --method GET "repos/$GITHUB_REPOSITORY/pulls"', cleanup)
        self.assertIn('-f head="${GITHUB_REPOSITORY%/*}:$branch"', cleanup)
        self.assertIn("preserving branch used by an open PR", cleanup)
        self.assertNotIn('"fix/"', cleanup)
        self.assertNotIn('"release/"', cleanup)

    def test_cleanup_distinguishes_absence_from_lookup_failure(self) -> None:
        cleanup = self._cleanup_block()
        self.assertGreaterEqual(cleanup.count('git ls-remote --exit-code --refs origin "$ref"'), 2)
        self.assertIn('case "$lookup_status" in', cleanup)
        self.assertIn('case "$latest_status" in', cleanup)
        self.assertIn('release branch already absent before cleanup', cleanup)
        self.assertIn('failed to resolve release branch before cleanup', cleanup)
        self.assertIn('failed to resolve release branch after rejected leased deletion', cleanup)
        self.assertIn('git ls-remote exit $lookup_status', cleanup)
        self.assertIn('git ls-remote exit $latest_status', cleanup)


if __name__ == "__main__":
    unittest.main()
