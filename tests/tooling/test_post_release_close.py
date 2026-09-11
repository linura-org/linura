from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "post_release_close.py"
SPEC = importlib.util.spec_from_file_location("post_release_close", TOOL_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load post_release_close")
post_release_close = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(post_release_close)


class Args:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.tag = "v0.5.0"
        self.source_sha = "a" * 40
        self.proof_run_id = "101"
        self.promotion_run_id = "102"
        self.release_run_id = "103"
        self.release_id = "104"
        self.verification_run_id = "105"
        self.published_at = "2026-09-05T12:00:00Z"


class PostReleaseCloseTests(unittest.TestCase):
    def _fixture(self, root: Path) -> None:
        (root / "contracts").mkdir()
        (root / "docs" / "milestones").mkdir(parents=True)
        (root / "docs" / "qualification").mkdir(parents=True)
        (root / "docs" / "releases").mkdir(parents=True)

        (root / "contracts" / "roadmap.toml").write_text(
            '''schema_version = 1
current_release = "v0.4.0"
next_release = "v0.5.0"

[[milestone]]
version = "v0.4.0"
title = "previous"
status = "released"
milestone_contract = "docs/milestones/v0.4.0.md"
release_contract = "docs/releases/v0.4.0.md"
qualification = "docs/qualification/v0.4.0.md"

[[milestone]]
version = "v0.5.0"
title = "executor"
status = "planned"
milestone_contract = "docs/milestones/v0.5.0.md"
release_contract = "docs/releases/v0.5.0.md"
qualification = "docs/qualification/v0.5.0.md"

[[milestone]]
version = "v0.6.0"
title = "next"
status = "planned"
milestone_contract = "docs/milestones/v0.6.0.md"
release_contract = "docs/releases/v0.6.0.md"
qualification = "docs/qualification/v0.6.0.md"
''',
            encoding="utf-8",
        )
        (root / "docs" / "milestones" / "v0.5.0.md").write_text(
            '''# v0.5.0

## Release gate

- [ ] canonical CI, Security and CodeQL pass on the exact candidate source;
- [ ] Trusted Release Proof reruns all mandatory qualification against the exact release authorization;
- [ ] independent binary reproduction succeeds;
- [ ] tag-last publication succeeds;
- [ ] independent published-release verification succeeds;
- [ ] post-release closure advances machine roadmap state only after immutable publication evidence exists.
''',
            encoding="utf-8",
        )
        (root / "docs" / "milestones" / "v0.4.0.md").write_text("# v0.4.0\n", encoding="utf-8")
        (root / "docs" / "milestones" / "v0.6.0.md").write_text("# v0.6.0\n", encoding="utf-8")
        (root / "docs" / "qualification" / "v0.5.0.md").write_text(
            '''# v0.5.0 qualification

## Terminal release evidence

Publication not yet complete.
''',
            encoding="utf-8",
        )
        (root / "docs" / "qualification" / "v0.4.0.md").write_text("# old\n", encoding="utf-8")
        (root / "docs" / "qualification" / "v0.6.0.md").write_text("# next\n", encoding="utf-8")
        (root / "docs" / "releases" / "v0.4.0.md").write_text("# old\n", encoding="utf-8")
        (root / "docs" / "releases" / "v0.5.0.md").write_text("# frozen v0.5\n", encoding="utf-8")
        (root / "docs" / "releases" / "v0.6.0.md").write_text("# next\n", encoding="utf-8")
        (root / "docs" / "releases" / "README.md").write_text("# Releases\n", encoding="utf-8")

    def test_close_release_advances_roadmap_and_writes_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._fixture(root)
            frozen = root / "docs/releases/v0.5.0.md"
            frozen_before = frozen.read_bytes()

            post_release_close.close_release(Args(root))

            roadmap = (root / "contracts/roadmap.toml").read_text(encoding="utf-8")
            self.assertIn('current_release = "v0.5.0"', roadmap)
            self.assertIn('next_release = "v0.6.0"', roadmap)
            self.assertIn('version = "v0.5.0"\ntitle = "executor"\nstatus = "released"', roadmap)
            self.assertEqual(frozen_before, frozen.read_bytes())

            publication = (root / "docs/qualification/v0.5.0-publication.md").read_text(encoding="utf-8")
            self.assertIn("101", publication)
            self.assertIn("105", publication)
            published = (root / "docs/releases/published-v0.5.0.md").read_text(encoding="utf-8")
            self.assertIn("v0.5.0", published)
            milestone = (root / "docs/milestones/v0.5.0.md").read_text(encoding="utf-8")
            self.assertNotIn("- [ ]", milestone)

    def test_release_gate_closes_split_v06_terminal_controls(self) -> None:
        milestone = '''# v0.6.0

## Release gate

v0.6.0 is not releaseable until:

- [ ] canonical CI, Security and CodeQL pass on the exact candidate source;
- [ ] dedicated v0.6 managed-lifecycle disposable-VM qualification passes on the exact candidate source;
- [ ] Trusted Release Proof reruns all mandatory inherited v0.4/v0.5 qualifications plus the v0.6 qualification against the exact release authorization;
- [ ] independent binary reproduction succeeds;
- [ ] tag-last publication succeeds;
- [ ] independent published-release verification succeeds;
- [ ] post-release closure advances machine roadmap state only after immutable publication evidence exists.

## Explicit non-claims

No widened claim.
'''
        updated = post_release_close.close_release_control_criteria(milestone, "v0.6.0")

        self.assertNotIn("- [ ]", updated.split("## Explicit non-claims", 1)[0])
        self.assertEqual(7, updated.count("- [x]"))
        self.assertIn("- [x] tag-last publication succeeds;", updated)
        self.assertIn("- [x] independent published-release verification succeeds;", updated)
        self.assertIn("- [x] post-release closure advances machine roadmap state", updated)

    def test_release_gate_rejects_unmapped_unchecked_criterion(self) -> None:
        milestone = '''# future

## Release gate

- [ ] tag-last publication succeeds;
- [ ] independent published-release verification succeeds;
- [ ] manually rotate an unrelated external credential.
'''
        with self.assertRaisesRegex(
            post_release_close.ClosureError,
            "unchecked release-gate criteria are not exactly mapped to terminal release evidence",
        ):
            post_release_close.close_release_control_criteria(milestone, "v9.9.9")

    def test_release_gate_rejects_misleading_keyword_collision(self) -> None:
        milestone = '''# future

## Release gate

- [ ] tag-last publication succeeds;
- [ ] independent published-release verification succeeds;
- [ ] Security tabletop exercise with external responders is complete.
'''
        with self.assertRaisesRegex(
            post_release_close.ClosureError,
            "Security tabletop exercise with external responders is complete",
        ):
            post_release_close.close_release_control_criteria(milestone, "v9.9.9")

    def test_release_gate_requires_exact_publication_and_verification_mappings(self) -> None:
        milestone = '''# future

## Release gate

- [ ] Trusted Release Proof succeeds.
'''
        with self.assertRaisesRegex(post_release_close.ClosureError, "exactly mapped publication criterion"):
            post_release_close.close_release_control_criteria(milestone, "v9.9.9")

    def test_closure_rejects_non_next_release(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._fixture(root)
            contract = root / "contracts/roadmap.toml"
            contract.write_text(
                contract.read_text(encoding="utf-8").replace(
                    'next_release = "v0.5.0"', 'next_release = "v0.6.0"', 1
                ),
                encoding="utf-8",
            )
            with self.assertRaises(post_release_close.ClosureError):
                post_release_close.close_release(Args(root))

    def test_existing_publication_evidence_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._fixture(root)
            publication = root / "docs/qualification/v0.5.0-publication.md"
            publication.write_text("conflicting evidence\n", encoding="utf-8")
            with self.assertRaises(post_release_close.ClosureError):
                post_release_close.close_release(Args(root))

    def test_workflow_pins_protected_deterministic_closure_sequence(self) -> None:
        workflow = (ROOT / ".github/workflows/post-release-closure.yml").read_text(encoding="utf-8")
        for marker in (
            "workflow_dispatch:",
            "INPUT_VERIFICATION_RUN_ID",
            'test "$verification_event" = "workflow_dispatch"',
            'test "$verification_event" = "push"',
            "python3 tools/post_release_close.py",
            "python3 tools/post_release_terminal_sync.py",
            "--credential-source github",
            "token: ${{ github.token }}",
            "event=workflow_dispatch",
            "gh api graphql --paginate",
            "$endCursor:String",
            "reviewThreads(first:100, after:$endCursor)",
            "pageInfo { hasNextPage endCursor }",
            'test "$unresolved" = "0"',
            'pulls/$PR_NUMBER/merge',
            "deterministic closure proof",
            "Delete obsolete release-scoped branches",
        ):
            self.assertIn(marker, workflow)
        self.assertGreaterEqual(workflow.count("gh api graphql --paginate"), 2)
        self.assertGreaterEqual(workflow.count("reviewThreads(first:100, after:$endCursor)"), 2)
        self.assertNotIn("@codex review", workflow)
        self.assertNotIn("chatgpt-codex-connector", workflow)
        self.assertNotIn('workflows: ["Verify published release"]', workflow)
        self.assertNotIn("github.event.workflow_run", workflow)
        self.assertNotIn("git push origin main", workflow)
        self.assertNotIn('gh pr merge "$PR_NUMBER"', workflow)
        self.assertNotIn("RELEASE_AUTOMATION_TOKEN || github.token", workflow)

        for path in ("ci.yml", "security.yml", "codeql.yml"):
            text = (ROOT / ".github/workflows" / path).read_text(encoding="utf-8")
            self.assertIn("pull_request:", text)
            self.assertIn("workflow_dispatch:", text)


if __name__ == "__main__":
    unittest.main()
