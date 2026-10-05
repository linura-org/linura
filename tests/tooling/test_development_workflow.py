from __future__ import annotations

from pathlib import Path
import shutil
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import check_development_workflow as workflow  # noqa: E402


class DevelopmentWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path in sorted(set(workflow.REQUIRED) |
                           set(workflow.discover_scoped_agents(ROOT))):
            destination = self.root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, destination)

    def edit(self, path: str, before: str, after: str) -> None:
        target = self.root / path
        source = target.read_text(encoding="utf-8")
        self.assertIn(before, source)
        target.write_text(source.replace(before, after, 1), encoding="utf-8")

    def test_repository_and_fixture_are_aligned(self):
        self.assertEqual(workflow.check(ROOT), [])
        self.assertEqual(workflow.check(self.root), [])

    def test_canonical_stage_reordering_fails(self):
        self.edit("docs/development-infrastructure.md",
                  "→ request Codex review",
                  "→ request review before gates")
        errors = workflow.check(self.root)
        self.assertTrue(any("review stage order drift" in error
                            for error in errors), errors)

    def test_root_and_codex_stage_mismatch_fails(self):
        for path, before in (
            ("AGENTS.md", "→ full gates → Codex review"),
            ("docs/codex-development.md",
             "→ run full gates → request Codex review"),
        ):
            with self.subTest(path=path):
                target = self.root / path
                original = target.read_text(encoding="utf-8")
                self.edit(path, before, "→ request Codex review → run gates")
                self.assertTrue(any("review-stage order drift" in error
                                    for error in workflow.check(self.root)))
                target.write_text(original, encoding="utf-8")

    def test_missing_regression_impact_review_fails(self):
        self.edit("AGENTS.md",
                  "6. Perform a regression-impact review",
                  "6. Perform a cursory review")
        self.assertTrue(any("regression-impact review" in error
                            for error in workflow.check(self.root)))

    def test_contributor_guidance_must_preserve_regression_review(self):
        self.edit("CONTRIBUTING.md",
                  "Perform a regression-impact review",
                  "Perform an informal check")
        self.assertTrue(any(
            "CONTRIBUTING.md: missing development-workflow contract:"
            " regression-impact review" in error
            for error in workflow.check(self.root)))

    def test_pr_template_must_retain_regression_and_review_record(self):
        for before in (
            "## Regression impact",
            "## Internal review",
            "## Applicable qualification",
            "All applicable checks passed on the final exact head",
            "Final Codex review requested only after internal review and green gates",
        ):
            with self.subTest(item=before):
                target = self.root / ".github/PULL_REQUEST_TEMPLATE.md"
                original = target.read_text(encoding="utf-8")
                self.edit(".github/PULL_REQUEST_TEMPLATE.md",
                          before, "policy content deleted")
                self.assertTrue(any(".github/PULL_REQUEST_TEMPLATE.md:"
                                    " missing development-workflow contract"
                                    in error for error in workflow.check(self.root)))
                target.write_text(original, encoding="utf-8")

    def test_pr_template_attestations_must_start_unchecked(self):
        target = self.root / ".github/PULL_REQUEST_TEMPLATE.md"
        original = target.read_text(encoding="utf-8")
        self.assertIn("- [ ]", original)
        target.write_text(original.replace("- [ ]", "- [x]"), encoding="utf-8")
        errors = workflow.check(self.root)
        self.assertTrue(any(
            ".github/PULL_REQUEST_TEMPLATE.md: missing development-workflow contract:"
            in error for error in errors
        ), errors)

    def test_scoped_inheritance_and_missing_scoped_agent_fail(self):
        path = "qualification/AGENTS.md"
        self.edit(path, "Root `AGENTS.md` remains applicable.",
                  "Root instructions are optional.")
        self.assertTrue(any("must explicitly inherit root AGENTS.md"
                            in error for error in workflow.check(self.root)))
        (self.root / path).unlink()
        self.assertTrue(any("missing scoped agent instructions: " + path == error
                            for error in workflow.check(self.root)))

    def test_new_scoped_agent_is_discovered_and_must_inherit_root(self):
        target = self.root / "new-subsystem/AGENTS.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("local instructions only\n", encoding="utf-8")
        errors = workflow.check(self.root)
        self.assertTrue(any(
            "new-subsystem/AGENTS.md: must explicitly inherit root AGENTS.md" == error
            for error in errors
        ), errors)
        target.write_text("Root `AGENTS.md` remains applicable.\n",
                          encoding="utf-8")
        self.assertEqual(workflow.check(self.root), [])

    def test_repository_validator_cannot_drop_development_check(self):
        self.edit("scripts/check_repository.py",
                  'str(ROOT / "tools/check_development_workflow.py")',
                  'str(ROOT / "tools/not_a_development_check.py")')
        self.assertTrue(any("canonical development-workflow checker invocation disconnected"
                            in error for error in workflow.check(self.root)))

    def test_repository_validator_rejects_inert_literal_or_dead_branch(self):
        target = self.root / "scripts/check_repository.py"
        original = target.read_text(encoding="utf-8")
        active = textwrap.indent(workflow.CANONICAL_REPOSITORY_HOOK, "    ")
        self.assertIn(active, original)

        inert = '    development_checker = "tools/check_development_workflow.py"\n'
        target.write_text(original.replace(active, inert, 1), encoding="utf-8")
        errors = workflow.check(self.root)
        self.assertTrue(any("canonical development-workflow checker invocation disconnected"
                            in error for error in errors), errors)

        dead = "    if False:\n" + textwrap.indent(
            workflow.CANONICAL_REPOSITORY_HOOK, "        "
        )
        target.write_text(original.replace(active, dead, 1), encoding="utf-8")
        errors = workflow.check(self.root)
        self.assertTrue(any("canonical development-workflow checker invocation disconnected"
                            in error for error in errors), errors)

    def test_repository_validator_rejects_pre_hook_exit_paths(self):
        target = self.root / "scripts/check_repository.py"
        original = target.read_text(encoding="utf-8")
        active = textwrap.indent(workflow.CANONICAL_REPOSITORY_HOOK, "    ")
        self.assertIn(active, original)
        for bypass in (
            "    if True:\n        return 0\n\n",
            "    if skip_workflow_check:\n        return 0\n\n",
            "    if skip_workflow_check:\n        sys.exit(0)\n\n",
        ):
            with self.subTest(bypass=bypass.strip()):
                target.write_text(
                    original.replace(active, bypass + active, 1),
                    encoding="utf-8",
                )
                errors = workflow.check(self.root)
                self.assertTrue(any(
                    "canonical development-workflow checker invocation disconnected"
                    in error for error in errors
                ), errors)
                target.write_text(original, encoding="utf-8")

    def test_repository_validator_rejects_post_hook_success_bypass(self):
        target = self.root / "scripts/check_repository.py"
        original = target.read_text(encoding="utf-8")
        active = textwrap.indent(workflow.CANONICAL_REPOSITORY_HOOK, "    ")
        self.assertIn(active, original)
        for bypass in (
            "    return 0\n\n",
            "    if bypass_condition:\n        return 0\n\n",
            "    failures.clear()\n\n",
            "    alias = failures\n    alias.clear()\n\n",
        ):
            with self.subTest(bypass=bypass.strip()):
                target.write_text(
                    original.replace(active, active + bypass, 1),
                    encoding="utf-8",
                )
                errors = workflow.check(self.root)
                self.assertTrue(any(
                    "canonical development-workflow checker invocation disconnected"
                    in error for error in errors
                ), errors)
                target.write_text(original, encoding="utf-8")

    def test_repository_validator_requires_canonical_final_failure_exit(self):
        target = self.root / "scripts/check_repository.py"
        original = target.read_text(encoding="utf-8")
        epilogue = textwrap.indent(workflow.CANONICAL_REPOSITORY_EPILOGUE, "    ")
        self.assertIn(epilogue, original)
        weakened = epilogue.replace("return 1", "return 0", 1)
        target.write_text(original.replace(epilogue, weakened, 1), encoding="utf-8")
        errors = workflow.check(self.root)
        self.assertTrue(any(
            "canonical development-workflow checker invocation disconnected"
            in error for error in errors
        ), errors)

    def test_repository_validator_requires_canonical_module_entry(self):
        target = self.root / "scripts/check_repository.py"
        original = target.read_text(encoding="utf-8")
        entry = workflow.CANONICAL_REPOSITORY_ENTRY
        self.assertIn(entry, original)
        target.write_text(
            original.replace(entry, 'if __name__ == "__main__":\n    raise SystemExit(0)\n', 1),
            encoding="utf-8",
        )
        errors = workflow.check(self.root)
        self.assertTrue(any(
            "canonical development-workflow checker invocation disconnected"
            in error for error in errors
        ), errors)

    def test_repository_validator_requires_failure_propagation(self):
        target = self.root / "scripts/check_repository.py"
        original = target.read_text(encoding="utf-8")
        active = textwrap.indent(workflow.CANONICAL_REPOSITORY_HOOK, "    ")
        weakened = textwrap.indent(
            workflow.CANONICAL_REPOSITORY_HOOK.replace(
                "development_result.returncode != 0",
                "development_result.returncode == 0",
            ),
            "    ",
        )
        self.assertIn(active, original)
        target.write_text(original.replace(active, weakened, 1), encoding="utf-8")
        errors = workflow.check(self.root)
        self.assertTrue(any("canonical development-workflow checker invocation disconnected"
                            in error for error in errors), errors)

    def test_missing_primary_guidance_fails_closed(self):
        (self.root / "AGENTS.md").unlink()
        self.assertTrue(any(error == "missing development-workflow file: AGENTS.md"
                            for error in workflow.check(self.root)))


if __name__ == "__main__":
    unittest.main()
