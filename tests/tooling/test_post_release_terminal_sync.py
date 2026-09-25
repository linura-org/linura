from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/post_release_terminal_sync.py"
SPEC = importlib.util.spec_from_file_location("post_release_terminal_sync", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
sync_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync_tool)


class TerminalSyncTests(unittest.TestCase):
    def test_published_record_persists_crates_io_provenance(self) -> None:
        args = SimpleNamespace(
            tag="v0.9.0",
            source_sha="a" * 40,
            proof_run_id=101,
            promotion_run_id=102,
            release_run_id=103,
            release_id=104,
            verification_run_id=105,
            crates_io_run_id=106,
            crate_version="0.9.0",
            crate_package_sha256="b" * 64,
            published_at="2026-09-25T17:00:00Z",
        )
        record = sync_tool.published_record(
            args,
            {
                "title": "fixture",
                "claim_class": "Experimental",
                "executor_state": "qualified",
                "complete_lifecycle": True,
                "managed_mutation_support": "narrow",
                "platform_support": "reference",
                "agent_role": "proposal",
            },
            "v0.10.0",
        )
        self.assertIn("crates.io publication: workflow run `106`", record)
        self.assertIn("`linura 0.9.0`", record)
        self.assertIn(args.crate_package_sha256, record)

    def test_qualification_state_and_terminal_matrix_are_normalized(self) -> None:
        text = """# qualification

**State:** implementation qualified; release authorization and terminal publication evidence pending

## Qualification matrix

| Claim | Evidence | System evidence | State |
| --- | --- | --- | --- |
| durable state | unit tests | CI | qualified |
| inherited authority | boundary | Trusted Release Proof inherited v0.6 evidence | pending |
| Release provenance | digests | Trusted Release Proof + independent verification | pending |

## Terminal publication evidence

complete
"""
        updated = sync_tool.normalize_qualification_terminal_state(text, "v0.7.0")
        self.assertIn(
            "**State:** released; terminal publication and independent verification complete",
            updated,
        )
        self.assertNotIn("| pending |", updated)
        self.assertEqual(updated.count("| qualified |"), 3)

    def test_qualification_rejects_unknown_pending_matrix_row(self) -> None:
        text = """# qualification

**Status:** released

## Qualification matrix

| Claim | Evidence | System evidence | State |
| --- | --- | --- | --- |
| external manual task | operator | unrelated external ceremony | pending |
"""
        with self.assertRaisesRegex(sync_tool.TerminalSyncError, "unrecognized pending terminal row"):
            sync_tool.normalize_qualification_terminal_state(text, "v9.9.9")

    def test_completed_milestone_cannot_claim_remaining_unchecked_criteria(self) -> None:
        text = """# milestone

## Release gate

- [x] tag-last publication succeeds;
- [x] independent published-release verification succeeds;
- [x] post-release closure advances machine roadmap state only after immutable publication evidence exists.

The remaining unchecked criteria use the canonical terminal closure vocabulary.

## Explicit non-claims

none
"""
        updated = sync_tool.normalize_milestone_terminal_prose(text, "v0.7.0")
        self.assertNotIn("remaining unchecked criteria", updated)
        self.assertIn("All release-gate criteria above are now complete", updated)

    def test_completed_milestone_rejects_an_unchecked_gate(self) -> None:
        text = """# milestone

## Release gate

- [x] tag-last publication succeeds;
- [ ] independent published-release verification succeeds;
"""
        with self.assertRaisesRegex(sync_tool.TerminalSyncError, "unchecked release-gate criteria"):
            sync_tool.normalize_milestone_terminal_prose(text, "v9.9.9")

    def test_docs_index_moves_old_current_links_without_concatenating_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for relative in (
                "docs/milestones/v0.7.0.md",
                "docs/qualification/v0.7.0.md",
                "docs/releases/v0.7.0.md",
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n", encoding="utf-8")
            text = """# index

### Current v0.6.0 documentation set
- [v0.6.0 milestone contract](milestones/v0.6.0.md)
- [v0.6.0 qualification dossier](qualification/v0.6.0.md)

### Prior release documentation
- [v0.5.0 milestone contract](milestones/v0.5.0.md)

## More
"""
            updated = sync_tool.update_docs_index(text, root, "v0.7.0")
            self.assertIn("### Current v0.7.0 documentation set", updated)
            self.assertIn(
                "- [v0.6.0 qualification dossier](qualification/v0.6.0.md)\n- [v0.5.0 milestone contract]",
                updated,
            )
            self.assertNotIn("v0.6.0.md)- [v0.5.0", updated)

    def test_reference_release_advances_explicit_qualification_environment_support(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            matrix = root / "hardware/support-matrix.json"
            matrix.parent.mkdir(parents=True, exist_ok=True)
            matrix.write_text(
                '{"schema_version":1,"qualification_environments":{"release_qualified":[]},"machine_classes":{},"domains":{},"note":"development"}\n',
                encoding="utf-8",
            )
            changed: list[str] = []
            sync_tool.sync_release_qualified_environments(
                root,
                {"hardware_support_matrix": "hardware/support-matrix.json"},
                {
                    "platform_support": "reference-experimental",
                    "release_qualified_qualification_environments": [
                        "qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless"
                    ],
                },
                changed,
            )
            updated = __import__("json").loads(matrix.read_text(encoding="utf-8"))
            self.assertEqual(
                updated["qualification_environments"]["release_qualified"],
                ["qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless"],
            )
            self.assertIn("hardware/support-matrix.json", changed)

    def test_release_workflows_require_release_app_native_gates_and_deterministic_closure(self) -> None:
        closure = (ROOT / ".github/workflows/post-release-closure.yml").read_text(encoding="utf-8")
        cleanup = (ROOT / ".github/workflows/post-release-cleanup.yml").read_text(encoding="utf-8")
        promotion = (ROOT / ".github/workflows/release-promotion.yml").read_text(encoding="utf-8")

        self.assertIn("tools/post_release_terminal_sync.py", closure)
        self.assertIn("--credential-source github-app", closure)
        self.assertIn("actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1", closure)
        self.assertIn("tools/release_native_gates.py", closure)
        self.assertNotIn("@codex review", closure)
        self.assertNotIn("chatgpt-codex-connector", closure)
        self.assertNotIn("release_workflow_dispatch.py", closure)
        self.assertIn('pulls/$PR_NUMBER/merge', closure)
        self.assertNotIn('gh pr merge "$PR_NUMBER"', closure)
        self.assertIn("post-release-cleanup.yml", closure)

        self.assertIn("workflow_run:", cleanup)
        self.assertIn("tools/release_native_gates.py", cleanup)
        self.assertIn("tools/release_branch_cleanup.py", cleanup)
        self.assertIn("permission-contents: write", cleanup)
        self.assertIn("permission-pull-requests: read", cleanup)

        self.assertIn("actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1", promotion)
        self.assertIn("--credential-source github-app", promotion)
        self.assertIn("prove Release App closure authority before publication", promotion)


if __name__ == "__main__":
    unittest.main()
