from __future__ import annotations

from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/branch-hygiene.yml"
CONTRACT = ROOT / "contracts/release-branch-cleanup.toml"


class BranchHygieneWorkflowTests(unittest.TestCase):
    def _workflow(self) -> str:
        return WORKFLOW.read_text(encoding="utf-8")

    def test_manual_hygiene_binds_to_exact_current_main(self) -> None:
        workflow = self._workflow()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("authority_sha:", workflow)
        self.assertIn("release:", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn('test "$GITHUB_SHA" = "$AUTHORITY_SHA"', workflow)
        self.assertIn('test "$(git rev-parse HEAD)" = "$AUTHORITY_SHA"', workflow)
        self.assertIn(
            'test "$(git rev-parse refs/remotes/origin/main)" = "$AUTHORITY_SHA"',
            workflow,
        )
        self.assertIn("branch hygiene requires a released roadmap milestone", workflow)

    def test_native_main_gates_and_frozen_ledger_precede_discovery(self) -> None:
        workflow = self._workflow()
        gates = workflow.index(
            "- name: Require all native protected-main gates on authority commit"
        )
        freeze = workflow.index("- name: Freeze reviewed cleanup ledger to authority commit")
        discovery = workflow.index(
            "- name: Discover broad release-adjacent branch residue without mutation authority"
        )
        self.assertLess(gates, freeze)
        self.assertLess(freeze, discovery)
        self.assertIn("tools/release_native_gates.py", workflow[gates:freeze])
        self.assertIn("commit --event push", workflow[gates:freeze])
        self.assertIn(
            'git show "$AUTHORITY_SHA:contracts/release-branch-cleanup.toml"',
            workflow[freeze:discovery],
        )

    def test_read_only_discovery_precedes_narrow_write_authority(self) -> None:
        workflow = self._workflow()
        discovery = workflow.index(
            "- name: Discover broad release-adjacent branch residue without mutation authority"
        )
        reconfirm = workflow.index(
            "- name: Reconfirm main has not moved before write authority"
        )
        mint = workflow.index("- name: Mint cleanup-scoped Release App token")
        delete = workflow.index(
            "- name: Delete only reviewed exact release-owned branches under ref leases"
        )
        verify = workflow.index("- name: Verify reviewed cleanup candidates are absent")
        self.assertLess(discovery, reconfirm)
        self.assertLess(reconfirm, mint)
        self.assertLess(mint, delete)
        self.assertLess(delete, verify)

        before_mint = workflow[discovery:mint]
        self.assertIn("tools/release_branch_discovery.py", before_mint)
        self.assertIn("GH_TOKEN: ${{ github.token }}", before_mint)
        self.assertNotIn("steps.release_app.outputs.token", before_mint)

        write_block = workflow[mint:delete]
        self.assertIn("permission-contents: write", write_block)
        self.assertIn("permission-pull-requests: read", write_block)
        self.assertNotIn("permission-actions: write", write_block)

    def test_mutation_reuses_exact_lease_cleanup_tool_and_fails_if_residue_remains(self) -> None:
        workflow = self._workflow()
        delete = workflow.index(
            "- name: Delete only reviewed exact release-owned branches under ref leases"
        )
        verify = workflow.index("- name: Verify reviewed cleanup candidates are absent")
        block = workflow[delete:verify]
        self.assertIn("tools/release_branch_cleanup.py", block)
        self.assertIn('--tag "$RELEASE_TAG"', block)
        self.assertIn(
            '--contract "$RUNNER_TEMP/release-branch-cleanup.toml"',
            block,
        )
        self.assertNotIn('"tmp/"', block)
        self.assertNotIn('"release/"', block)
        self.assertNotIn('"work/"', block)
        self.assertNotIn('"chore/"', block)

        verification = workflow[verify:]
        self.assertIn("cleanup.load_legacy", verification)
        self.assertIn("cleanup.select_candidates", verification)
        self.assertIn("cleanup._list_branches", verification)
        self.assertIn(
            "reviewed cleanup candidates remain after leased deletion",
            verification,
        )

    def test_v09_residue_has_exact_reviewed_name_and_sha_authority(self) -> None:
        contract = tomllib.loads(CONTRACT.read_text(encoding="utf-8"))
        entries = {
            item["name"]: item["expected_sha"]
            for item in contract["legacy_branch"]
            if item["release"] == "v0.9.0"
        }
        self.assertEqual(
            {
                "tmp/pr128-recovery-record-repair": "8b822d6ff883791ebd739dca3f5381da00d09e3c",
                "tmp/pr129-precompact-safety": "742ac6d90462944b262b17701fa075ddddf75b8a",
                "tmp/pr129-review-validation": "0a06b63c3e07183567799f3743f237a7ff9d9cbd",
                "tmp/pr133-precompact-safety": "87157d88ce3e1b2cb91bdfde0d369d96ae397cf1",
                "tmp/topology-compact-base": "fc0a69b08ec94052d5663e761c8b22e4b387435f",
                "tmp/v09-semantic-rebase-check": "1f96adfb7e8f4cc83e63d9fb2551ce05b7221483",
            },
            entries,
        )


if __name__ == "__main__":
    unittest.main()
