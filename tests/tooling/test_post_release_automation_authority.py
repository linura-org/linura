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
        self.assertIn(
            "GH_TOKEN: ${{ secrets.RELEASE_AUTOMATION_TOKEN || github.token }}",
            workflow,
        )
        self.assertIn(
            "RELEASE_AUTOMATION_CREDENTIAL_SOURCE: ${{ secrets.RELEASE_AUTOMATION_TOKEN != '' && 'dedicated' || 'github' }}",
            workflow,
        )
        self.assertIn("Prove closure automation capabilities", workflow)
        self.assertIn(PROBE_TOOL, workflow)
        self.assertIn('--credential-source "$RELEASE_AUTOMATION_CREDENTIAL_SOURCE"', workflow)

        preflight = workflow.index("Prove closure automation capabilities")
        generate = workflow.index("Generate deterministic closure tree")
        commit = workflow.index("Commit and push one closure commit")
        open_pr = workflow.index("Open protected closure PR")
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

    def test_promotion_and_closure_share_the_same_authority_contract(self) -> None:
        closure = self._closure_workflow()
        promotion = PROMOTION_WORKFLOW.read_text(encoding="utf-8")

        for workflow in (closure, promotion):
            self.assertIn(PROBE_TOOL, workflow)
            self.assertIn(
                "GH_TOKEN: ${{ secrets.RELEASE_AUTOMATION_TOKEN || github.token }}",
                workflow,
            )
            self.assertIn("RELEASE_AUTOMATION_CREDENTIAL_SOURCE", workflow)

    def test_legacy_pr_only_probe_is_removed(self) -> None:
        workflow = self._closure_workflow()

        self.assertNotIn("Verify closure PR automation authority", workflow)
        self.assertNotIn("DEDICATED_AUTOMATION_TOKEN", workflow)
        self.assertNotIn("extract_probe_json", workflow)
        self.assertNotIn("Linura release automation authority probe", workflow)
        self.assertNotIn("No commits between main and main", workflow)


if __name__ == "__main__":
    unittest.main()
