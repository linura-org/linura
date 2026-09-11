from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
HELPER = ROOT / "tools" / "release_workflow_dispatch.py"

spec = importlib.util.spec_from_file_location("release_workflow_dispatch", HELPER)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReleaseDispatchIdentityTests(unittest.TestCase):
    def test_canonical_gates_expose_nonce_correlated_manual_dispatch(self) -> None:
        for filename, name in (("ci.yml", "CI"), ("security.yml", "Security"), ("codeql.yml", "CodeQL")):
            text = (WORKFLOWS / filename).read_text(encoding="utf-8")
            self.assertIn("dispatch_nonce:", text, filename)
            self.assertIn("inputs.dispatch_nonce || github.sha", text, filename)
            self.assertIn("github.workflow", text, filename)

    def test_matching_runs_requires_nonce_title_exact_sha_ref_path_and_boundary(self) -> None:
        expected = {
            "id": 101,
            "event": "workflow_dispatch",
            "head_sha": "a" * 40,
            "head_branch": "main",
            "display_title": "CI :: secret-nonce",
            "path": ".github/workflows/ci.yml",
        }
        distractors = [
            {**expected, "id": 99},
            {**expected, "id": 102, "display_title": "CI :: other-nonce"},
            {**expected, "id": 103, "head_sha": "b" * 40},
            {**expected, "id": 104, "head_branch": "other"},
            {**expected, "id": 105, "path": ".github/workflows/security.yml"},
        ]
        matches = module.matching_runs(
            distractors + [expected], boundary=100, head_sha="a" * 40, ref="main", title="CI :: secret-nonce", workflow="ci.yml"
        )
        self.assertEqual([101], [run["id"] for run in matches])

    def test_validate_run_rejects_identity_substitution(self) -> None:
        evidence = {
            "workflow": "ci.yml",
            "run_id": 101,
            "head_sha": "a" * 40,
            "ref": "main",
            "title": "CI :: secret-nonce",
        }
        valid = {
            "id": 101,
            "event": "workflow_dispatch",
            "head_sha": "a" * 40,
            "head_branch": "main",
            "display_title": "CI :: secret-nonce",
            "path": ".github/workflows/ci.yml",
        }
        module.validate_run(valid, evidence)
        for key, value in (("id", 102), ("head_sha", "b" * 40), ("head_branch", "other"), ("display_title", "CI :: other")):
            with self.subTest(key=key):
                with self.assertRaises(RuntimeError):
                    module.validate_run({**valid, key: value}, evidence)

    def test_release_preparation_has_dedicated_fresh_main_gate(self) -> None:
        text = (WORKFLOWS / "release-preparation.yml").read_text(encoding="utf-8")
        self.assertIn("fresh-main:", text)
        self.assertIn("name: require current-attempt protected-main canonical gates", text)
        self.assertIn("needs: [qualify, fresh-main]", text)
        self.assertIn("release-preparation-readiness-main-runs.jsonl", text)
        self.assertNotIn("if any(.[]; .status == \"completed\" and .conclusion == \"success\")", text)

    def test_all_release_owned_canonical_gate_dispatches_use_exact_evidence_files(self) -> None:
        expected = {
            "release-preparation.yml": (
                "release-preparation-readiness-main-runs.jsonl",
                "release-preparation-head-runs.jsonl",
                "release-preparation-main-runs.jsonl",
            ),
            "release-authorization.yml": (
                "release-authorization-head-runs.jsonl",
                "release-authorization-main-runs.jsonl",
            ),
            "post-release-closure.yml": (
                "post-release-closure-head-runs.jsonl",
                "post-release-closure-main-runs.jsonl",
            ),
        }
        for filename, evidence_files in expected.items():
            text = (WORKFLOWS / filename).read_text(encoding="utf-8")
            for evidence in evidence_files:
                self.assertIn(evidence, text, f"{filename}: {evidence}")
            self.assertNotIn("dispatch-boundaries.tsv", text, filename)
            self.assertNotIn("sort_by([.created_at, .id]) | last", text, filename)

    def test_helper_persists_and_rechecks_exact_run_identity(self) -> None:
        text = HELPER.read_text(encoding="utf-8")
        self.assertIn('"run_id": selected["id"]', text)
        self.assertIn('display_title', text)
        self.assertIn('len(matches) > 1', text)
        self.assertIn('/actions/runs/{record[\'run_id\']}', text)
        self.assertIn('validate_run(payload, record)', text)

    def test_release_stage_timeouts_cover_bounded_gate_and_review_windows(self) -> None:
        preparation = (WORKFLOWS / "release-preparation.yml").read_text(encoding="utf-8")
        authorization = (WORKFLOWS / "release-authorization.yml").read_text(encoding="utf-8")
        closure = (WORKFLOWS / "post-release-closure.yml").read_text(encoding="utf-8")

        self.assertIn("fresh-main:\n    name: require current-attempt protected-main canonical gates\n    needs: qualify\n    runs-on: ubuntu-24.04\n    timeout-minutes: 45", preparation)
        self.assertIn("prepare:\n    name: create, review and merge mechanical release preparation\n    needs: [qualify, fresh-main]\n    runs-on: ubuntu-24.04\n    timeout-minutes: 180", preparation)
        self.assertIn("qualify:\n    name: qualify reviewed release preparation", authorization)
        self.assertIn("runs-on: ubuntu-24.04\n    timeout-minutes: 45", authorization.split("authorize:", 1)[0])
        self.assertIn("authorize:\n    name: create, review and merge protected metadata-only authorization\n    needs: qualify\n    runs-on: ubuntu-24.04\n    timeout-minutes: 180", authorization)
        self.assertIn("close:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 180", closure)


if __name__ == "__main__":
    unittest.main()
