from __future__ import annotations

from pathlib import Path
import copy
import importlib.util
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools/v010_slice_graph.py"
SPEC = importlib.util.spec_from_file_location("v010_slice_graph", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
graph = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(graph)


class V010SliceGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = tomllib.loads(
            (ROOT / "contracts/v010-workstation-slices.toml").read_text(encoding="utf-8")
        )

    def test_repository_graph_is_valid(self) -> None:
        self.assertEqual(graph.validate_graph_contract(self.contract), [])

    def test_current_frontier_exposes_parallel_ready_slices(self) -> None:
        self.assertEqual(
            graph.ready_slice_ids(self.contract),
            ["S17", "S18", "S19", "S20", "S26"],
        )
        payload = graph.status_payload(self.contract)
        self.assertEqual(payload["recommended_batch"], ["S17", "S18", "S19", "S20"])
        self.assertEqual(payload["max_parallel_active"], 4)

    def test_future_waves_are_deterministic(self) -> None:
        self.assertEqual(
            graph.schedule_waves(self.contract),
            [
                ["S17", "S18", "S19", "S20", "S26"],
                ["S21", "S23", "S24", "S27"],
                ["S22", "S25", "S28"],
                ["S29"],
                ["S30"],
                ["S31"],
                ["S32"],
            ],
        )

    def test_unknown_dependency_fails_closed(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["slice"][16]["depends_on"] = ["S99"]
        self.assertIn(
            "S17: unknown dependency S99",
            graph.validate_graph_contract(contract),
        )

    def test_cycle_is_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["slice"][15]["depends_on"] = ["S17"]
        failures = graph.validate_graph_contract(contract)
        self.assertTrue(any("dependency graph contains cycle" in item for item in failures))

    def test_completed_slice_cannot_depend_on_incomplete_slice(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["slice"][15]["depends_on"] = ["S17"]
        failures = graph.validate_graph_contract(contract)
        self.assertIn(
            "S16: completed slice dependency S17 is not complete",
            failures,
        )

    def test_duplicate_dependencies_are_rejected(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["slice"][16]["depends_on"] = ["S16", "S16"]
        self.assertIn(
            "S17: depends_on contains duplicate dependencies",
            graph.validate_graph_contract(contract),
        )


if __name__ == "__main__":
    unittest.main()
