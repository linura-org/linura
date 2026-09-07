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
        self.assertIn("issues: write", workflow)
        self.assertIn(
            "GH_TOKEN: ${{ secrets.RELEASE_AUTOMATION_TOKEN }}",
            workflow,
        )
        self.assertNotIn("RELEASE_AUTOMATION_TOKEN || github.token", workflow)
        self.assertIn("RELEASE_AUTOMATION_TOKEN is required", workflow)
        self.assertIn("Prove closure automation capabilities", workflow)
        self.assertIn(PROBE_TOOL, workflow)
        self.assertIn('--credential-source dedicated', workflow)
        self.assertIn("token: ${{ secrets.RELEASE_AUTOMATION_TOKEN }}", workflow)

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

    def test_promotion_and_closure_require_the_same_dedicated_authority(self) -> None:
        closure = self._closure_workflow()
        promotion = PROMOTION_WORKFLOW.read_text(encoding="utf-8")

        for workflow in (closure, promotion):
            self.assertIn(PROBE_TOOL, workflow)
            self.assertIn(
                "GH_TOKEN: ${{ secrets.RELEASE_AUTOMATION_TOKEN }}",
                workflow,
            )
            self.assertIn("RELEASE_AUTOMATION_TOKEN is required", workflow)
            self.assertIn("--credential-source dedicated", workflow)
            self.assertNotIn("RELEASE_AUTOMATION_TOKEN || github.token", workflow)

    def test_closure_waits_for_native_pr_checks_and_codex_review(self) -> None:
        workflow = self._closure_workflow()
        self.assertIn("@codex review", workflow)
        self.assertIn("event=pull_request", workflow)
        self.assertGreaterEqual(workflow.count("reviewThreads(first:100)"), 2)
        self.assertIn("chatgpt-codex-connector", workflow)
        self.assertIn('pulls/$PR_NUMBER/merge', workflow)
        self.assertNotIn('gh pr merge "$PR_NUMBER"', workflow)
        self.assertIn("event=push", workflow)

        merge = workflow.split("- name: Re-prove and squash merge exact reviewed closure", 1)[1].split(
            "- name: Resolve post-closure protected-main SHA", 1
        )[0]
        self.assertIn("REVIEW_COMMENT_ID", merge)
        self.assertIn("reviewThreads(first:100)", merge)
        self.assertIn('test "$unresolved" = "0"', merge)
        self.assertIn("exact_codex_review", merge)
        self.assertIn("codex_clean_reaction", merge)
        self.assertLess(merge.index("reviewThreads(first:100)"), merge.index('pulls/$PR_NUMBER/merge'))

    def test_closure_retries_reprove_and_reuse_exact_branch_and_pr(self) -> None:
        workflow = self._closure_workflow()
        commit = workflow.split("- name: Commit or re-prove deterministic closure commit", 1)[1].split(
            "- name: Open or re-prove protected closure PR", 1
        )[0]
        open_pr = workflow.split("- name: Open or re-prove protected closure PR", 1)[1].split(
            "- name: Request exact-head Codex review", 1
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

    def test_closed_release_retry_still_requires_fresh_main_before_cleanup(self) -> None:
        workflow = self._closure_workflow()
        final_main = workflow.index("Resolve post-closure protected-main SHA")
        fresh_main = workflow.index("Require native fresh-main CI, Security and CodeQL")
        cleanup = workflow.index("Delete obsolete release-scoped branches")
        self.assertLess(final_main, fresh_main)
        self.assertLess(fresh_main, cleanup)

        fresh_block = workflow.split("- name: Require native fresh-main CI, Security and CodeQL", 1)[1].split(
            "- name: Delete obsolete release-scoped branches", 1
        )[0]
        self.assertNotIn("if: steps.state.outputs.state == 'pending'", fresh_block)
        self.assertIn("steps.final_main.outputs.main_sha", fresh_block)

    def test_cleanup_covers_release_branches_and_legacy_probe(self) -> None:
        workflow = self._closure_workflow()
        cleanup = workflow.split("- name: Delete obsolete release-scoped branches", 1)[1]
        self.assertIn('"release/"', cleanup)
        self.assertIn('branch == "tmp/zero-diff-authorization-probe"', cleanup)
        self.assertIn("preserving branch used by an open PR", cleanup)

    def test_legacy_fallback_authority_is_removed(self) -> None:
        workflow = self._closure_workflow()

        self.assertNotIn("Verify closure PR automation authority", workflow)
        self.assertNotIn("DEDICATED_AUTOMATION_TOKEN", workflow)
        self.assertNotIn("RELEASE_AUTOMATION_CREDENTIAL_SOURCE", workflow)
        self.assertNotIn("Linura release automation authority probe", workflow)
        self.assertNotIn("No commits between main and main", workflow)


if __name__ == "__main__":
    unittest.main()
