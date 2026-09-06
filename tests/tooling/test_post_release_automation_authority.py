from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/post-release-closure.yml"


class PostReleaseAutomationAuthorityTests(unittest.TestCase):
    def _preflight(self) -> str:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        return workflow.split("- name: Verify closure PR automation authority", 1)[1].split(
            "- name: Generate deterministic closure tree", 1
        )[0]

    def test_pr_authority_is_probed_before_closure_mutation(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(
            "GH_TOKEN: ${{ secrets.RELEASE_AUTOMATION_TOKEN || github.token }}",
            workflow,
        )
        self.assertIn("Verify closure PR automation authority", workflow)
        self.assertIn("RELEASE_AUTOMATION_TOKEN", workflow)
        self.assertIn("-f head='main'", workflow)
        self.assertIn("-f base='main'", workflow)
        self.assertIn("HTTP/[0-9.]+ 422", workflow)
        self.assertIn("HTTP/[0-9.]+ 403", workflow)
        self.assertIn("Allow GitHub Actions to create and approve pull requests", workflow)

        preflight = workflow.index("Verify closure PR automation authority")
        generate = workflow.index("Generate deterministic closure tree")
        commit = workflow.index("Commit and push one closure commit")
        open_pr = workflow.index("Open protected closure PR")
        self.assertLess(preflight, generate)
        self.assertLess(generate, commit)
        self.assertLess(commit, open_pr)

    def test_permission_probe_is_intentionally_non_mutating(self) -> None:
        preflight = self._preflight()

        self.assertIn("identical base/head can never be created", preflight)
        self.assertIn("-f head='main'", preflight)
        self.assertIn("-f base='main'", preflight)
        self.assertNotIn("git push", preflight)
        self.assertNotIn("git commit", preflight)
        self.assertNotIn("gh pr create", preflight)

    def test_422_authority_probe_requires_exact_same_head_validation(self) -> None:
        preflight = self._preflight()

        self.assertIn('probe_json="$(extract_probe_json', preflight)
        self.assertIn('.message == "Validation Failed"', preflight)
        self.assertIn('.resource == "PullRequest"', preflight)
        self.assertIn('.code == "custom"', preflight)
        self.assertIn('.message == "No commits between main and main"', preflight)
        self.assertIn("Ambiguous release automation probe", preflight)
        self.assertIn("unexpected 422 response", preflight)


if __name__ == "__main__":
    unittest.main()
