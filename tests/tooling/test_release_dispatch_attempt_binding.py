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
            distractors + [expected],
            boundary=100,
            head_sha="a" * 40,
            ref="main",
            title="CI :: secret-nonce",
            workflow="ci.yml",
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
        for key, value in (
            ("id", 102),
            ("head_sha", "b" * 40),
            ("head_branch", "other"),
            ("display_title", "CI :: other"),
        ):
            with self.subTest(key=key):
                with self.assertRaises(RuntimeError):
                    module.validate_run({**valid, key: value}, evidence)
        module.validate_run(valid, evidence)

    def test_release_preparation_requires_native_exact_main_push_gates(self) -> None:
        text = (WORKFLOWS / "release-preparation.yml").read_text(encoding="utf-8")
        authority = text.split("- name: Prove Release App automation authority", 1)[1].split(
            "- name: Build or re-prove SHA-addressed mechanical preparation", 1
        )[0]
        self.assertIn("python3 tools/release_native_gates.py", authority)
        self.assertIn('--head-sha "$SOURCE_SHA"', authority)
        self.assertIn("--head-branch main", authority)
        self.assertIn("--timeout-seconds 1800", authority)
        self.assertIn("commit --event push", authority)
        self.assertNotIn("release_workflow_dispatch.py", authority)

    def test_machine_handoffs_use_native_gate_tool_not_dispatched_gate_evidence(self) -> None:
        expected = {
            "release-preparation.yml": ("commit --event push", '--expected-changed-files "$EXPECTED_CHANGED_FILES"'),
            "release-authorization.yml": ("commit --event push", "--expected-changed-files 0"),
            "post-release-closure.yml": ("--expected-changed-files", "--timeout-seconds 0"),
        }
        for filename, markers in expected.items():
            text = (WORKFLOWS / filename).read_text(encoding="utf-8")
            self.assertIn("tools/release_native_gates.py", text, filename)
            for marker in markers:
                self.assertIn(marker, text, f"{filename}: {marker}")
            self.assertNotIn("release_workflow_dispatch.py", text, filename)
            self.assertNotIn("dispatch-boundaries.tsv", text, filename)

        preparation = (WORKFLOWS / "release-preparation.yml").read_text(encoding="utf-8")
        self.assertIn('[[ "$EXPECTED_CHANGED_FILES" = "0" || "$EXPECTED_CHANGED_FILES" = "2" ]]', preparation)
        self.assertIn("expected_changed_files=0", preparation)
        self.assertIn("expected_changed_files=2", preparation)

    def test_helper_persists_and_rechecks_exact_run_identity(self) -> None:
        text = HELPER.read_text(encoding="utf-8")
        self.assertIn('"run_id": selected["id"]', text)
        self.assertIn("display_title", text)
        self.assertIn("len(matches) > 1", text)
        self.assertIn("/actions/runs/{record['run_id']}", text)
        self.assertIn("validate_run(payload, record)", text)

    def test_release_stage_timeouts_cover_bounded_native_gate_windows(self) -> None:
        preparation = (WORKFLOWS / "release-preparation.yml").read_text(encoding="utf-8")
        authorization = (WORKFLOWS / "release-authorization.yml").read_text(encoding="utf-8")
        closure = (WORKFLOWS / "post-release-closure.yml").read_text(encoding="utf-8")

        self.assertIn(
            "qualify:\n    name: qualify reviewed release readiness\n"
            "    if:",
            preparation,
        )
        self.assertIn("timeout-minutes: 20", preparation.split("  prepare:", 1)[0])
        self.assertIn(
            "prepare:\n    name: create and merge deterministic mechanical preparation\n"
            "    needs: qualify\n    runs-on: ubuntu-24.04\n    timeout-minutes: 55",
            preparation,
        )
        self.assertIn("--timeout-seconds 1800", preparation)

        self.assertIn("qualify:\n    name: qualify reviewed release preparation", authorization)
        self.assertIn("timeout-minutes: 20", authorization.split("  authorize:", 1)[0])
        self.assertIn(
            "authorize:\n    name: create and merge protected metadata-only authorization\n"
            "    needs: qualify\n    runs-on: ubuntu-24.04\n    timeout-minutes: 55",
            authorization,
        )
        self.assertIn("--timeout-seconds 1800", authorization)
        self.assertIn("close:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 55", closure)
        self.assertIn("--timeout-seconds 1800", closure)


if __name__ == "__main__":
    unittest.main()
