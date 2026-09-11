from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/release_native_gates.py"
SPEC = importlib.util.spec_from_file_location("release_native_gates", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
gates = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gates
SPEC.loader.exec_module(gates)


class NativeReleaseGateTests(unittest.TestCase):
    def _run(self, *, path: str, run_id: int, conclusion: str = "success") -> dict[str, object]:
        return {
            "id": run_id,
            "path": path,
            "head_sha": "a" * 40,
            "head_branch": "automation/release-test",
            "event": "pull_request",
            "status": "completed",
            "conclusion": conclusion,
            "pull_requests": [{"number": 17}],
        }

    def test_pull_request_gate_requires_native_pull_request_runs(self) -> None:
        payload = {
            "workflow_runs": [
                self._run(path=path, run_id=index + 1)
                for index, path in enumerate(gates.REQUIRED_WORKFLOWS)
            ]
        }
        with mock.patch.object(gates, "_request", return_value=(200, payload)):
            state = gates._runs(
                "linura-org/linura",
                head_sha="a" * 40,
                event="pull_request",
                head_branch="automation/release-test",
                pr_number=17,
                token="token",
            )
        self.assertTrue(state.ready)
        self.assertIn("success", state.detail)

    def test_action_required_native_run_is_a_hard_failure(self) -> None:
        payload = {
            "workflow_runs": [
                self._run(
                    path=path,
                    run_id=index + 1,
                    conclusion="action_required" if index == 0 else "success",
                )
                for index, path in enumerate(gates.REQUIRED_WORKFLOWS)
            ]
        }
        with mock.patch.object(gates, "_request", return_value=(200, payload)):
            with self.assertRaisesRegex(gates.NativeGateError, "refuses to substitute workflow_dispatch"):
                gates._runs(
                    "linura-org/linura",
                    head_sha="a" * 40,
                    event="pull_request",
                    head_branch="automation/release-test",
                    pr_number=17,
                    token="token",
                )

    def test_workflow_dispatch_does_not_satisfy_native_pr_gate(self) -> None:
        payload = {
            "workflow_runs": [
                {
                    **self._run(path=path, run_id=index + 1),
                    "event": "workflow_dispatch",
                }
                for index, path in enumerate(gates.REQUIRED_WORKFLOWS)
            ]
        }
        with mock.patch.object(gates, "_request", return_value=(200, payload)):
            state = gates._runs(
                "linura-org/linura",
                head_sha="a" * 40,
                event="pull_request",
                head_branch="automation/release-test",
                pr_number=17,
                token="token",
            )
        self.assertFalse(state.ready)
        self.assertIn("missing", state.detail)

    def test_pr_state_requires_clean_github_ruleset_state(self) -> None:
        pr = {
            "state": "open",
            "head": {"sha": "a" * 40, "ref": "automation/release-test"},
            "base": {"sha": "b" * 40, "ref": "main"},
            "changed_files": 0,
            "mergeable": True,
            "mergeable_state": "blocked",
        }
        native = gates.GateState(True, "native gates green")
        with (
            mock.patch.object(gates, "_request", return_value=(200, pr)),
            mock.patch.object(gates, "_runs", return_value=native),
            mock.patch.object(gates, "_unresolved_threads", return_value=0),
        ):
            state = gates._pr_state(
                "linura-org/linura",
                pr_number=17,
                head_sha="a" * 40,
                head_branch="automation/release-test",
                base_sha="b" * 40,
                expected_changed_files=0,
                token="token",
            )
        self.assertFalse(state.ready)
        self.assertIn("blocked", state.detail)

    def test_pr_state_rejects_unresolved_threads(self) -> None:
        pr = {
            "state": "open",
            "head": {"sha": "a" * 40, "ref": "automation/release-test"},
            "base": {"sha": "b" * 40, "ref": "main"},
            "changed_files": 0,
            "mergeable": True,
            "mergeable_state": "clean",
        }
        with (
            mock.patch.object(gates, "_request", return_value=(200, pr)),
            mock.patch.object(gates, "_runs", return_value=gates.GateState(True, "green")),
            mock.patch.object(gates, "_unresolved_threads", return_value=1),
        ):
            with self.assertRaisesRegex(gates.NativeGateError, "unresolved review thread"):
                gates._pr_state(
                    "linura-org/linura",
                    pr_number=17,
                    head_sha="a" * 40,
                    head_branch="automation/release-test",
                    base_sha="b" * 40,
                    expected_changed_files=0,
                    token="token",
                )


if __name__ == "__main__":
    unittest.main()
