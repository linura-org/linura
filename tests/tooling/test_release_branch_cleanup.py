from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/release_branch_cleanup.py"
SPEC = importlib.util.spec_from_file_location("release_branch_cleanup", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
cleanup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cleanup)


class ReleaseBranchCleanupTests(unittest.TestCase):
    def test_selects_only_owned_namespace_and_exact_legacy_entries(self) -> None:
        tag = "v0.8.0"
        legacy = {"tmp/v08-reviewed": "a" * 40}
        branches = [
            "main",
            "automation/release-prep-v0.8.0-0123456789ab",
            "automation/release-authorization-v0.8.0-abcdefabcdef",
            "automation/post-release-v0.8.0-12345",
            "verify-release/v0.8.0",
            "tmp/v08-reviewed",
            "tmp/v08-unreviewed",
            "automation/release-prep-v0.9.0-0123456789ab",
            "feature/user-work",
        ]
        selected = cleanup.select_candidates(branches, tag, legacy)
        self.assertEqual(
            [
                "automation/post-release-v0.8.0-12345",
                "automation/release-authorization-v0.8.0-abcdefabcdef",
                "automation/release-prep-v0.8.0-0123456789ab",
                "tmp/v08-reviewed",
                "verify-release/v0.8.0",
            ],
            [item.name for item in selected],
        )
        legacy_item = next(item for item in selected if item.name == "tmp/v08-reviewed")
        self.assertEqual("a" * 40, legacy_item.expected_sha)
        self.assertEqual("legacy-ledger", legacy_item.source)

    def test_load_legacy_rejects_non_tmp_branch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "cleanup.toml"
            path.write_text(
                'schema_version = 1\n\n[[legacy_branch]]\nrelease = "v0.8.0"\nname = "feature/user-work"\nexpected_sha = "' + "a" * 40 + '"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(cleanup.CleanupError, "invalid legacy cleanup branch name"):
                cleanup.load_legacy(path, "v0.8.0")

    def test_moved_legacy_branch_is_preserved(self) -> None:
        candidate = cleanup.Candidate("tmp/v08-reviewed", "a" * 40, "legacy-ledger")
        with (
            mock.patch.object(cleanup, "_open_pr_count", return_value=0),
            mock.patch.object(cleanup, "_ref_sha", return_value="b" * 40),
        ):
            result = cleanup.delete_candidate("linura-org/linura", candidate, "token")
        self.assertIn("preserved moved legacy branch", result)

    def test_concurrently_moved_automation_branch_is_preserved(self) -> None:
        candidate = cleanup.Candidate(
            "automation/release-authorization-v0.8.0-abcdefabcdef",
            None,
            "automation-owned",
        )
        with (
            mock.patch.object(cleanup, "_open_pr_count", return_value=0),
            mock.patch.object(cleanup, "_ref_sha", side_effect=["a" * 40, "b" * 40]),
        ):
            result = cleanup.delete_candidate("linura-org/linura", candidate, "token")
        self.assertIn("preserved concurrently moved branch", result)

    def test_open_pr_branch_is_preserved_without_ref_deletion(self) -> None:
        candidate = cleanup.Candidate(
            "automation/release-prep-v0.8.0-0123456789ab",
            None,
            "automation-owned",
        )
        with (
            mock.patch.object(cleanup, "_open_pr_count", return_value=1),
            mock.patch.object(cleanup, "_ref_sha") as ref_sha,
            mock.patch.object(cleanup, "_request") as request,
        ):
            result = cleanup.delete_candidate("linura-org/linura", candidate, "token")
        self.assertIn("preserved open-PR branch", result)
        ref_sha.assert_not_called()
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
