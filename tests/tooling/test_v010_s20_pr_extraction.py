"""Inert S20 extraction contract cannot silently become an effect/release claim."""
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "contracts/v010-s20-pr-extraction.toml"
DESIGN = ROOT / "contracts/v010-s20-design.toml"
RUNTIME = ROOT / "contracts/operation-semantics.toml"

class S20ExtractionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = tomllib.loads(PLAN.read_text(encoding="utf-8"))
        cls.design = tomllib.loads(DESIGN.read_text(encoding="utf-8"))

    def test_plan_remains_inert_and_s08_untouched(self):
        self.assertEqual(self.plan["status"], "proposed")
        for flag in ("new_operation_registration", "new_effect_activation", "physical_q11_qualified", "release_ready"):
            self.assertFalse(self.plan[flag], flag)
        self.assertEqual(self.plan["s08_preserved_operation"], "operation:audio.output.set-session-volume")
        self.assertEqual(self.plan["s08_preserved_class"], "transient-external-effect")
        self.assertEqual(self.plan["s08_preserved_risk"], "user-state")
        self.assertTrue(self.plan["candidate_operations_must_remain_inert_until_separately_qualified"])
        self.assertIn(self.plan["s08_preserved_operation"], RUNTIME.read_text(encoding="utf-8"))

    def test_five_dag_units_and_single_candidate_owner(self):
        units = self.plan["unit"]
        ids = [unit["id"] for unit in units]
        self.assertEqual(ids, [f"S20-{i}" for i in range(1, 6)])
        self.assertEqual(self.plan["pr_count"], len(ids))
        owners = []
        for unit in units:
            self.assertFalse(unit["effects_authorized"])
            self.assertTrue(unit["required_tests"])
            self.assertTrue(unit["adversarial_cases"])
            self.assertTrue(unit["deliverables"])
            self.assertTrue(unit["source_areas"])
            self.assertTrue(set(unit["depends_on_units"]).issubset(set(ids[:ids.index(unit["id"])])))
            owners += unit["operation_owners"]
        self.assertEqual(len(owners), len(set(owners)))
        candidates = self.design["candidate_operation"]
        self.assertEqual(set(owners), {c["id"] for c in candidates})
        self.assertTrue(all(c["enabled"] is False for c in candidates))
        self.assertNotIn(self.plan["s08_preserved_operation"], owners)

    def test_all_phase1_adversarial_cases_owned(self):
        covered = {case for unit in self.plan["unit"] for case in unit["adversarial_cases"]}
        self.assertEqual(covered, {f"M20-{i:02d}" for i in range(1, 25)})
        self.assertEqual(self.plan["unit"][-1]["depends_on_units"],
                         [f"S20-{i}" for i in range(1, 5)])

if __name__ == "__main__":
    unittest.main()
