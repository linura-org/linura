from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
CLOSURE_WORKFLOW = ROOT / ".github/workflows/post-release-closure.yml"
PROMOTION_WORKFLOW = ROOT / ".github/workflows/release-promotion.yml"
PROBE_TOOL = "tools/probe_release_automation_authority.py"


class PostReleaseAutomationAuthorityTests(unittest.TestCase):
    def _closure_workflow(self) -> str:
        return CLOSURE_WORKFLOW.read_text(encoding="utf-8")

    def _closure_preflight(self) -> str:
        workflow = self._closure_workflow()
        return workflow.split("- name: Prove closure automation capabilities", 1)[1].split(
            "- name: Generate deterministic closure tree", 1
        )[0]

    def test_full_capability_probe_runs_before_closure_mutation(self) -> None:
        workflow = self._closure_workflow()

        self.assertIn("contents: write", workflow)
        self.assertIn("pull-requests: write", workflow)
        self.assertIn("actions: write", workflow)
        self.assertNotIn("issues: write", workflow)
        self.assertIn("GH_TOKEN: ${{ github.token }}", workflow)
        self.assertNotIn("RELEASE_AUTOMATION_TOKEN || github.token", workflow)
        self.assertIn("--credential-source github", workflow)
        self.assertIn("Prove closure automation capabilities", workflow)
        self.assertIn(PROBE_TOOL, workflow)
        self.assertIn("token: ${{ github.token }}", workflow)

        preflight = workflow.index("Prove closure automation capabilities")
        generate = workflow.index("Generate deterministic closure tree")
        commit = workflow.index("Commit or re-prove deterministic closure commit")
        open_pr = workflow.index("Open or re-prove protected closure PR")
        self.assertLess(preflight, generate)
        self.assertLess(generate, commit)
        self.assertLess(commit, open_pr)

    def test_closure_rechecks_current_main_before_capability_probe(self) -> None:
        preflight = self._closure_preflight()

        self.assertIn(
            'current_main="$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/main" --jq .object.sha)"',
            preflight,
        )
        self.assertIn('test "$(git rev-parse HEAD)" = "$current_main"', preflight)
        self.assertIn(PROBE_TOOL, preflight)
        self.assertNotIn("git push", preflight)
        self.assertNotIn("git commit", preflight)
        self.assertNotIn("gh pr create", preflight)

    def test_promotion_and_closure_require_same_repository_scoped_authority(self) -> None:
        closure = self._closure_workflow()
        promotion = PROMOTION_WORKFLOW.read_text(encoding="utf-8")

        for workflow in (closure, promotion):
            self.assertIn(PROBE_TOOL, workflow)
            self.assertIn("GH_TOKEN: ${{ github.token }}", workflow)
            self.assertIn("--credential-source github", workflow)
            self.assertNotIn("RELEASE_AUTOMATION_TOKEN || github.token", workflow)

    def test_closure_uses_explicit_exact_head_checks_without_conversational_gate(self) -> None:
        workflow = self._closure_workflow()
        self.assertNotIn("@codex review", workflow)
        self.assertNotIn("CODEX_BOT_USER_ID", workflow)
        self.assertNotIn("issues/$PR_NUMBER/comments", workflow)
        self.assertNotIn("has_clean_codex_comment", workflow)
        self.assertNotIn("has_exact_codex_review", workflow)
        self.assertIn("event=workflow_dispatch", workflow)
        self.assertIn('pulls/$PR_NUMBER/merge', workflow)
        self.assertNotIn('gh pr merge "$PR_NUMBER"', workflow)

        gate = workflow.split("- name: Require exact-head checks and zero unresolved review threads", 1)[1].split(
            "- name: Re-prove and squash merge exact deterministic closure", 1
        )[0]
        self.assertIn("release_workflow_dispatch.py verify", gate)
        self.assertIn("post-release-closure-head-runs.jsonl", gate)
        self.assertIn("gh api graphql --paginate", gate)
        self.assertIn("reviewThreads(first:100, after:$endCursor)", gate)
        self.assertIn("pageInfo { hasNextPage endCursor }", gate)
        self.assertIn('unresolved="$(gh api graphql --paginate', gate)
        self.assertIn('test "$unresolved" = "0"', gate)
        self.assertIn('test "$(gh pr view "$PR_NUMBER" --json headRefOid --jq .headRefOid)" = "$HEAD_SHA"', gate)

        merge = workflow.split("- name: Re-prove and squash merge exact deterministic closure", 1)[1].split(
            "- name: Resolve post-closure protected-main SHA", 1
        )[0]
        self.assertIn("release_workflow_dispatch.py verify", merge)
        self.assertIn("gh api graphql --paginate", merge)
        self.assertIn("reviewThreads(first:100, after:$endCursor)", merge)
        self.assertIn('test "$unresolved" = "0"', merge)
        self.assertIn('test "$(jq -r .headRefOid <<<"$pr")" = "$HEAD_SHA"', merge)
        self.assertIn("'.parents | length'", merge)
        self.assertIn("'.parents[0].sha'", merge)
        self.assertIn('= "$BASE_SHA"', merge)
        self.assertIn("deterministic closure proof", merge)
        self.assertLess(
            merge.index("reviewThreads(first:100, after:$endCursor)"),
            merge.index('pulls/$PR_NUMBER/merge'),
        )

    def test_closure_retries_reprove_and_reuse_exact_branch_and_pr(self) -> None:
        workflow = self._closure_workflow()
        commit = workflow.split("- name: Commit or re-prove deterministic closure commit", 1)[1].split(
            "- name: Open or re-prove protected closure PR", 1
        )[0]
        open_pr = workflow.split("- name: Open or re-prove protected closure PR", 1)[1].split(
            "- name: Dispatch and require exact-head closure checks", 1
        )[0]

        self.assertIn('expected_tree="$(git write-tree)"', commit)
        self.assertIn('branch_payload="$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/$branch"', commit)
        self.assertIn("reusing exact deterministic closure branch", commit)
        self.assertIn("'.parents | length'", commit)
        self.assertIn("'.parents[0].sha'", commit)
        self.assertIn('jq -r .tree.sha', commit)
        self.assertIn('= "$expected_tree"', commit)

        self.assertIn('gh pr list --state open --base main --head "$BRANCH"', open_pr)
        self.assertIn("reusing exact open closure PR", open_pr)
        self.assertIn('test "$(jq -r .headRefOid <<<"$pr")" = "$HEAD_SHA"', open_pr)
        self.assertIn('test "$(jq -r .baseRefName <<<"$pr")" = "main"', open_pr)
        self.assertIn("deterministic tree proof", open_pr)

    def test_closed_release_retry_still_requires_fresh_main_before_cleanup(self) -> None:
        workflow = self._closure_workflow()
        final_main = workflow.index("Resolve post-closure protected-main SHA")
        fresh_main = workflow.index("Dispatch and require explicit fresh-main CI, Security and CodeQL")
        cleanup = workflow.index("Delete obsolete release-scoped branches")
        self.assertLess(final_main, fresh_main)
        self.assertLess(fresh_main, cleanup)

        fresh_block = workflow.split("- name: Dispatch and require explicit fresh-main CI, Security and CodeQL", 1)[1].split(
            "- name: Delete obsolete release-scoped branches", 1
        )[0]
        self.assertNotIn("if: steps.state.outputs.state == 'pending'", fresh_block)
        self.assertIn("steps.final_main.outputs.main_sha", fresh_block)
        self.assertIn("post-release-closure-main-runs.jsonl", fresh_block)
        self.assertIn("tools/release_workflow_dispatch.py dispatch", fresh_block)
        self.assertIn("tools/release_workflow_dispatch.py wait", fresh_block)
        self.assertNotIn("dispatch-boundaries.tsv", fresh_block)
        self.assertNotIn(".id > $boundary", fresh_block)

    def test_cleanup_is_limited_to_owned_namespaces_exact_legacy_provenance_and_atomic_leases(self) -> None:
        workflow = self._closure_workflow()
        cleanup = workflow.split("- name: Delete obsolete release-scoped branches", 1)[1]
        self.assertIn("automation/release-prep-", cleanup)
        self.assertIn("automation/release-reprepare-", cleanup)
        self.assertIn("automation/release-authorization-", cleanup)
        self.assertIn("automation/post-release-", cleanup)
        self.assertIn("verify-release/", cleanup)
        self.assertIn("contracts/release-branch-cleanup.toml", cleanup)
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
        self.assertNotIn("series =", cleanup)
        self.assertNotIn("(cleanup|compact|minimal|review|release)", cleanup)
        self.assertNotIn('branch == "tmp/zero-diff-authorization-probe"', cleanup)
        self.assertNotIn('"fix/"', cleanup)
        self.assertNotIn('"release/"', cleanup)
        self.assertIn("preserving branch used by an open PR", cleanup)
        self.assertIn('repos/$GITHUB_REPOSITORY/pulls', cleanup)
        self.assertIn('-f head="${GITHUB_REPOSITORY%/*}:$branch"', cleanup)

    def test_legacy_fallback_authority_is_removed(self) -> None:
        workflow = self._closure_workflow()

        self.assertNotIn("Verify closure PR automation authority", workflow)
        self.assertNotIn("DEDICATED_AUTOMATION_TOKEN", workflow)
        self.assertNotIn("RELEASE_AUTOMATION_CREDENTIAL_SOURCE", workflow)
        self.assertNotIn("Linura release automation authority probe", workflow)
        self.assertNotIn("No commits between main and main", workflow)


if __name__ == "__main__":
    unittest.main()
