from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/release_branch_discovery.py"
WORKFLOW_PATH = ROOT / ".github/workflows/post-release-cleanup.yml"
SPEC = importlib.util.spec_from_file_location("release_branch_discovery", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
discovery = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = discovery
SPEC.loader.exec_module(discovery)


class ReleaseBranchDiscoveryTests(unittest.TestCase):
    def test_discovers_broad_release_adjacent_namespaces_without_user_branches(self) -> None:
        branches = [
            discovery.BranchRef("main", "0" * 40, True),
            discovery.BranchRef("tmp/pr129-precompact-safety", "1" * 40, False),
            discovery.BranchRef("work/release-scratch", "2" * 40, False),
            discovery.BranchRef("chore/release-scratch", "3" * 40, False),
            discovery.BranchRef("automation/manual-scratch", "4" * 40, False),
            discovery.BranchRef("verify-release/v0.9.0", "5" * 40, False),
            discovery.BranchRef("release/support", "6" * 40, False),
            discovery.BranchRef("feature/user-work", "7" * 40, False),
            discovery.BranchRef("fix/user-work", "8" * 40, False),
            discovery.BranchRef("dependabot/actions/example", "9" * 40, False),
        ]
        self.assertEqual(
            [
                "automation/manual-scratch",
                "chore/release-scratch",
                "release/support",
                "tmp/pr129-precompact-safety",
                "verify-release/v0.9.0",
                "work/release-scratch",
            ],
            [item.name for item in discovery.select_discoveries(branches)],
        )

    def test_inspection_is_observational_and_retains_protection_and_open_pr_state(self) -> None:
        branches = [
            discovery.BranchRef("tmp/closed", "a" * 40, False),
            discovery.BranchRef("release/protected", "b" * 40, True),
        ]
        with mock.patch.object(
            discovery, "_has_open_pr", side_effect=[False, True]
        ) as open_pr:
            items = discovery.inspect_discoveries(
                "linura-org/linura", branches, "token"
            )
        self.assertEqual(
            [
                discovery.Discovery("release/protected", "b" * 40, True, False),
                discovery.Discovery("tmp/closed", "a" * 40, False, True),
            ],
            items,
        )
        self.assertEqual(2, open_pr.call_count)

    def test_branch_listing_requires_exact_sha_and_protection_metadata(self) -> None:
        payload = [
            {
                "name": "tmp/test",
                "commit": {"sha": "a" * 40},
                "protected": False,
            },
            {
                "name": "main",
                "commit": {"sha": "b" * 40},
                "protected": True,
            },
        ]
        with mock.patch.object(discovery, "_request", return_value=(200, payload)):
            refs = discovery._list_branches("linura-org/linura", "token")
        self.assertEqual(
            [
                discovery.BranchRef("tmp/test", "a" * 40, False),
                discovery.BranchRef("main", "b" * 40, True),
            ],
            refs,
        )

    def test_duplicate_branch_listing_fails_closed(self) -> None:
        payload = [
            {
                "name": "tmp/test",
                "commit": {"sha": "a" * 40},
                "protected": False,
            },
            {
                "name": "tmp/test",
                "commit": {"sha": "b" * 40},
                "protected": False,
            },
        ]
        with mock.patch.object(discovery, "_request", return_value=(200, payload)):
            with self.assertRaisesRegex(
                discovery.DiscoveryError, "invalid branch metadata"
            ):
                discovery._list_branches("linura-org/linura", "token")

    def test_text_report_states_that_discovery_is_not_deletion_authority(self) -> None:
        text = discovery.render_text(
            [discovery.Discovery("release/support", "a" * 40, False, False)]
        )
        self.assertIn("discovery is read-only", text)
        self.assertIn("generic discoveries are not deletion authority", text)
        self.assertIn("reviewed exact name+SHA cleanup ledger", text)

    def test_source_contains_no_ref_mutation_path(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("--force-with-lease", source)
        self.assertNotIn("_atomic_delete", source)
        self.assertNotIn('"DELETE"', source)
        self.assertNotIn("git push", source)

    def test_workflow_separates_read_only_discovery_from_write_authority(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        discovery_step = workflow.index(
            "- name: Discover broad release-adjacent branch residue without mutation authority"
        )
        mint_step = workflow.index("- name: Mint cleanup-scoped Release App token")
        delete_step = workflow.index(
            "- name: Delete only exact release-owned branches under ref leases"
        )
        self.assertLess(discovery_step, mint_step)
        self.assertLess(mint_step, delete_step)

        discovery_block = workflow[discovery_step:mint_step]
        self.assertIn("tools/release_branch_discovery.py", discovery_block)
        self.assertIn("GH_TOKEN: ${{ github.token }}", discovery_block)
        self.assertNotIn("permission-contents: write", discovery_block)
        self.assertNotIn("steps.release_app.outputs.token", discovery_block)


if __name__ == "__main__":
    unittest.main()
