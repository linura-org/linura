from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/post_release_terminal_sync.py"
SPEC = importlib.util.spec_from_file_location("post_release_terminal_sync", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
sync_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync_tool)


class TerminalSyncTests(unittest.TestCase):
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

    def test_release_workflows_require_dedicated_credential_and_review_before_merge(self) -> None:
        closure = (ROOT / ".github/workflows/post-release-closure.yml").read_text(encoding="utf-8")
        promotion = (ROOT / ".github/workflows/release-promotion.yml").read_text(encoding="utf-8")

        self.assertIn("tools/post_release_terminal_sync.py", closure)
        self.assertIn("RELEASE_AUTOMATION_TOKEN is required", closure)
        self.assertIn("token: ${{ secrets.RELEASE_AUTOMATION_TOKEN }}", closure)
        self.assertNotIn("RELEASE_AUTOMATION_TOKEN || github.token", closure)
        self.assertIn("@codex review", closure)
        self.assertIn("event=pull_request", closure)
        self.assertIn("reviewThreads(first:100)", closure)
        self.assertIn("chatgpt-codex-connector", closure)
        self.assertIn('pulls/$PR_NUMBER/merge', closure)
        self.assertIn('event=push', closure)
        self.assertNotIn('gh pr merge "$PR_NUMBER"', closure)

        self.assertIn("GH_TOKEN: ${{ secrets.RELEASE_AUTOMATION_TOKEN }}", promotion)
        self.assertIn("RELEASE_AUTOMATION_TOKEN is required", promotion)
        self.assertNotIn("RELEASE_AUTOMATION_TOKEN || github.token", promotion)


if __name__ == "__main__":
    unittest.main()
