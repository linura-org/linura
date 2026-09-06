from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


class ReleaseWorkflowDispatchTests(unittest.TestCase):
    def test_workflow_dispatch_commands_are_repository_explicit(self) -> None:
        failures: list[str] = []

        for workflow in sorted(WORKFLOWS.glob("*.yml")):
            lines = workflow.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                if "gh workflow run" not in line:
                    continue

                command_lines = [line]
                cursor = index
                while command_lines[-1].rstrip().endswith("\\") and cursor + 1 < len(lines):
                    cursor += 1
                    command_lines.append(lines[cursor])

                command = "\n".join(command_lines)
                if '--repo "$GITHUB_REPOSITORY"' not in command:
                    failures.append(
                        f"{workflow.relative_to(ROOT)}:{index + 1}: "
                        "gh workflow run must pass --repo \"$GITHUB_REPOSITORY\""
                    )

        self.assertEqual([], failures, "\n".join(failures))

    def test_release_verification_dispatch_uses_release_tag_ref(self) -> None:
        release_workflow = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        verification_dispatch = next(
            line
            for line in release_workflow.splitlines()
            if "gh workflow run release-verification.yml" in line
        )
        self.assertIn(
            '--ref "$RELEASE_TAG"',
            verification_dispatch,
            "normal independent verification must execute the workflow definition frozen in the published release tag",
        )

    def test_release_verification_does_not_require_downloaded_executable_mode(self) -> None:
        verification_workflow = (WORKFLOWS / "release-verification.yml").read_text(encoding="utf-8")
        self.assertIn("test -f published/linura-authorityd", verification_workflow)
        self.assertNotIn(
            "test -x published/linura-authorityd",
            verification_workflow,
            "downloaded GitHub Release assets must be verified by content, not local Unix mode bits",
        )
        self.assertIn("python3 tools/release_contract.py verify", verification_workflow)
        self.assertIn("python3 tools/release_verify.py published", verification_workflow)
        self.assertIn("gh release verify-asset", verification_workflow)
        self.assertIn("gh attestation verify", verification_workflow)

    def test_release_verification_recovery_ref_is_marker_scoped(self) -> None:
        verification_workflow = (WORKFLOWS / "release-verification.yml").read_text(encoding="utf-8")
        self.assertIn('"verify-release/v*"', verification_workflow)
        self.assertIn('".github/release-verification-recovery/**"', verification_workflow)
        self.assertIn('tag="${RECOVERY_REF#verify-release/}"', verification_workflow)

    def test_post_release_closure_authenticates_recovery_ref(self) -> None:
        closure_workflow = (WORKFLOWS / "post-release-closure.yml").read_text(encoding="utf-8")
        self.assertIn('verification_head_branch" == "verify-release/$tag"', closure_workflow)
        self.assertIn('test "$verification_event" = "push"', closure_workflow)
        self.assertIn('git merge-base --is-ancestor "$recovery_base" origin/main', closure_workflow)
        self.assertIn('marker_path=".github/release-verification-recovery/$tag"', closure_workflow)
        self.assertIn('test "$changed_paths" = "$marker_path"', closure_workflow)
        self.assertIn('"verify-release/"', closure_workflow)


if __name__ == "__main__":
    unittest.main()
