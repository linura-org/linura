from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/release_branch_cleanup.py"
SPEC = importlib.util.spec_from_file_location("release_branch_cleanup", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
cleanup = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cleanup
SPEC.loader.exec_module(cleanup)


class ReleaseBranchCleanupTests(unittest.TestCase):
    def test_selects_only_sha_addressed_namespace_and_exact_ledger_entries(self) -> None:
        tag = "v0.8.0"
        prep_sha = "1" * 40
        auth_sha = "2" * 40
        closure_sha = "3" * 40
        legacy = {"tmp/v08-reviewed": "a" * 40}
        branches = [
            "main",
            f"automation/release-prep-v0.8.0-{prep_sha}",
            f"automation/release-authorization-v0.8.0-{auth_sha}",
            f"automation/post-release-v0.8.0-{closure_sha}",
            "automation/release-prep-v0.8.0-0123456789ab",
            "automation/post-release-v0.8.0-12345",
            "verify-release/v0.8.0",
            "tmp/v08-reviewed",
            "tmp/v08-unreviewed",
            f"automation/release-prep-v0.9.0-{prep_sha}",
            "feature/user-work",
        ]
        selected = cleanup.select_candidates(branches, tag, legacy)
        self.assertEqual(
            [
                f"automation/post-release-v0.8.0-{closure_sha}",
                f"automation/release-authorization-v0.8.0-{auth_sha}",
                f"automation/release-prep-v0.8.0-{prep_sha}",
                "tmp/v08-reviewed",
            ],
            [item.name for item in selected],
        )
        by_name = {item.name: item for item in selected}
        self.assertEqual(prep_sha, by_name[f"automation/release-prep-v0.8.0-{prep_sha}"].expected_sha)
        self.assertEqual("sha-addressed-automation", by_name[f"automation/release-prep-v0.8.0-{prep_sha}"].source)
        self.assertEqual("a" * 40, by_name["tmp/v08-reviewed"].expected_sha)
        self.assertEqual("explicit-ledger", by_name["tmp/v08-reviewed"].source)

    def test_load_legacy_rejects_main(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "cleanup.toml"
            path.write_text(
                'schema_version = 1\n\n[[legacy_branch]]\nrelease = "v0.8.0"\nname = "main"\nexpected_sha = "' + "a" * 40 + '"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(cleanup.CleanupError, "invalid explicit cleanup branch name"):
                cleanup.load_legacy(path, "v0.8.0")

    def test_moved_ledger_branch_is_preserved(self) -> None:
        candidate = cleanup.Candidate("tmp/v08-reviewed", "a" * 40, "explicit-ledger")
        with (
            mock.patch.object(cleanup, "_open_pr_count", return_value=0),
            mock.patch.object(cleanup, "_ref_sha", return_value="b" * 40),
            mock.patch.object(cleanup, "_atomic_delete") as atomic_delete,
        ):
            result = cleanup.delete_candidate("linura-org/linura", candidate, "token")
        self.assertIn("preserved moved branch", result)
        atomic_delete.assert_not_called()

    def test_atomic_lease_preserves_concurrently_moved_automation_branch(self) -> None:
        expected = "a" * 40
        candidate = cleanup.Candidate(
            f"automation/release-authorization-v0.8.0-{expected}",
            expected,
            "sha-addressed-automation",
        )
        failed = subprocess.CompletedProcess(
            args=["git", "push"], returncode=1, stdout="", stderr="stale info"
        )
        with (
            mock.patch.object(cleanup, "_open_pr_count", return_value=0),
            mock.patch.object(cleanup, "_ref_sha", side_effect=[expected, "b" * 40]),
            mock.patch.object(cleanup, "_atomic_delete", return_value=failed),
        ):
            result = cleanup.delete_candidate("linura-org/linura", candidate, "token")
        self.assertIn("preserved concurrently moved branch", result)

    def test_exact_atomic_lease_deletes_expected_branch(self) -> None:
        expected = "a" * 40
        candidate = cleanup.Candidate(
            f"automation/release-prep-v0.8.0-{expected}",
            expected,
            "sha-addressed-automation",
        )
        succeeded = subprocess.CompletedProcess(
            args=["git", "push"], returncode=0, stdout="", stderr=""
        )
        with (
            mock.patch.object(cleanup, "_open_pr_count", return_value=0),
            mock.patch.object(cleanup, "_ref_sha", return_value=expected),
            mock.patch.object(cleanup, "_atomic_delete", return_value=succeeded) as atomic_delete,
        ):
            result = cleanup.delete_candidate("linura-org/linura", candidate, "token")
        self.assertIn("deleted", result)
        atomic_delete.assert_called_once_with(
            "linura-org/linura", candidate.name, expected, "token"
        )

    def test_open_pr_branch_is_preserved_without_ref_deletion(self) -> None:
        expected = "a" * 40
        candidate = cleanup.Candidate(
            f"automation/release-prep-v0.8.0-{expected}",
            expected,
            "sha-addressed-automation",
        )
        with (
            mock.patch.object(cleanup, "_open_pr_count", return_value=1),
            mock.patch.object(cleanup, "_ref_sha") as ref_sha,
            mock.patch.object(cleanup, "_atomic_delete") as atomic_delete,
        ):
            result = cleanup.delete_candidate("linura-org/linura", candidate, "token")
        self.assertIn("preserved open-PR branch", result)
        ref_sha.assert_not_called()
        atomic_delete.assert_not_called()


if __name__ == "__main__":
    unittest.main()
