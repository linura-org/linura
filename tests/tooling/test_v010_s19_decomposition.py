"""S19 implementation PR boundaries must not bypass Phase-1 security design."""
from __future__ import annotations

import copy
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "contracts/v010-s19-pr-decomposition.toml"
DESIGN = ROOT / "contracts/v010-s19-design.toml"

EXPECTED_PRS = [f"S19-{i}" for i in range(1, 7)]
REQUIRED_FIELDS = (
    "slug", "title", "depends_on", "external_effects", "candidate_operations",
    "capabilities", "owned_paths", "requirements", "negative_cases",
    "acceptance", "qualification", "blocked_until",
)


def validate(plan: dict, design: dict) -> None:
    assert plan["schema_version"] == 1
    assert plan["milestone"] == "v0.10.0" and plan["slice"] == "S19"
    assert plan["status"] == "proposed" and plan["declared_slice_predecessor"] == "S16"
    assert plan["base_branch"] == "main"
    assert plan["phase1_reference_branch"] == "wip/v010-s19-bluetooth"
    assert plan["implementation_pr_count"] == 6
    for flag in ("runtime_effects_enabled", "evidence_accepted", "slice_complete",
                 "q11_physical_hardware_qualified", "merge_wip_directly"):
        assert plan[flag] is False, flag

    guard = plan["guardrails"]
    assert guard["system_bus_name"] == "org.bluez"
    assert guard["cross_provider_authority"] == "Linura Control"
    assert guard["observation_envelope"] == "linura-observation::ObservationEnvelope"
    assert "no blind replay" in guard["recovery"].lower()
    assert "Q11" in guard["qualification"]

    prs = plan["pull_request"]
    assert [pr["id"] for pr in prs] == EXPECTED_PRS
    owned_operations: list[str] = []
    for number, pr in enumerate(prs):
        assert all(field in pr for field in REQUIRED_FIELDS), pr["id"]
        assert len(pr["title"]) > 30 and pr["title"].startswith("feat(bluetooth): ")
        assert pr["slug"] and pr["owned_paths"]
        for field in ("capabilities", "requirements", "negative_cases",
                      "acceptance", "qualification", "blocked_until"):
            assert pr[field] and all(isinstance(item, str) and item for item in pr[field]), (pr["id"], field)
        assert len(pr["acceptance"]) >= 4
        assert len(set(pr["depends_on"])) == len(pr["depends_on"])
        assert all(d in EXPECTED_PRS[:number] for d in pr["depends_on"]), pr["id"]
        assert len(set(pr["candidate_operations"])) == len(pr["candidate_operations"])
        if number == 0 or number == 5:
            assert pr["external_effects"] is False and not pr["candidate_operations"]
        else:
            assert pr["external_effects"] is True and pr["candidate_operations"]
        owned_operations.extend(pr["candidate_operations"])

    design_ops = design["candidate_operation"]
    assert design["activation"] == "none"
    assert design["register_runtime_operations"] is False
    assert design["implements_effects"] is False
    assert all(op["enabled"] is False for op in design_ops)
    design_ids = [op["id"] for op in design_ops]
    assert len(design_ids) == len(set(design_ids)) == 12
    assert len(owned_operations) == len(set(owned_operations)) == 12
    assert set(owned_operations) == set(design_ids)
    assert all(op["class"] == "managed-external-effect" for op in design_ops)
    assert next(x for x in design_ops if x["id"] == "operation:bluetooth.device.remove")["risk_floor"] == "destructive"

    assert set(prs[2]["depends_on"]) >= {"S19-1", "S19-2"}
    assert "S19-3" in prs[3]["depends_on"]
    assert set(prs[5]["depends_on"]) == set(EXPECTED_PRS[:5])
    assert any("physical" in s.lower() or "hardware" in s.lower()
               for s in prs[5]["qualification"])
    assert all(not p.startswith("executors/") for pr in prs for p in pr["owned_paths"])


class S19DecompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = tomllib.loads(PLAN.read_text(encoding="utf-8"))
        cls.design = tomllib.loads(DESIGN.read_text(encoding="utf-8"))

    def test_plan_preserves_inactive_phase1_and_exact_operations(self) -> None:
        validate(self.plan, self.design)

    def test_no_effect_activation_or_evidence_promotion(self) -> None:
        for flag in ("runtime_effects_enabled", "evidence_accepted", "slice_complete",
                     "q11_physical_hardware_qualified"):
            mutated = copy.deepcopy(self.plan)
            mutated[flag] = True
            with self.subTest(flag=flag), self.assertRaises(AssertionError):
                validate(mutated, self.design)

    def test_operation_class_or_risk_downgrade_is_rejected(self) -> None:
        for operation, field, value in (
            ("operation:bluetooth.device.remove", "risk_floor", "user-state"),
            ("operation:bluetooth.device.pair", "class", "transient-external-effect"),
            ("operation:bluetooth.discovery.stop", "enabled", True),
        ):
            mutated = copy.deepcopy(self.design)
            target = next(x for x in mutated["candidate_operation"] if x["id"] == operation)
            target[field] = value
            with self.subTest(operation=operation), self.assertRaises(AssertionError):
                validate(self.plan, mutated)

    def test_duplicate_or_missing_operation_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.plan)
        mutated["pull_request"][4]["candidate_operations"][0] = "operation:bluetooth.device.pair"
        with self.assertRaises(AssertionError):
            validate(mutated, self.design)

    def test_forward_dependency_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.plan)
        mutated["pull_request"][0]["depends_on"] = ["S19-5"]
        with self.assertRaises(AssertionError):
            validate(mutated, self.design)

    def test_unreviewed_extra_pr_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.plan)
        mutated["pull_request"].append(copy.deepcopy(mutated["pull_request"][5]))
        with self.assertRaises(AssertionError):
            validate(mutated, self.design)


if __name__ == "__main__":
    unittest.main()
