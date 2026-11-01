"""Guard proposed S18 PR extraction against architecture and authority drift."""
from __future__ import annotations

import copy
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "contracts/v010-s18-pr-decomposition.toml"
DESIGN = ROOT / "contracts/v010-s18-design.toml"
DOC = ROOT / "docs/workstreams/v010-s18-pr-decomposition.md"

EXPECTED_PRS = [f"S18-{number}" for number in range(1, 6)]
EXPECTED_OPERATIONS = {
    "operation:network.wifi.scan",
    "operation:network.networking.set-enabled",
    "operation:network.wifi.set-enabled",
    "operation:network.connection.activate",
    "operation:network.connection.deactivate",
    "operation:network.wifi.join",
    "operation:network.profile.create",
    "operation:network.profile.update",
    "operation:network.profile.delete",
}
EXPECTED_ASSIGNMENTS = {
    "S18-1": set(),
    "S18-2": {
        "operation:network.wifi.scan",
        "operation:network.networking.set-enabled",
        "operation:network.wifi.set-enabled",
    },
    "S18-3": {
        "operation:network.connection.activate",
        "operation:network.connection.deactivate",
        "operation:network.wifi.join",
    },
    "S18-4": {
        "operation:network.profile.create",
        "operation:network.profile.update",
        "operation:network.profile.delete",
    },
    "S18-5": set(),
}
REQUIRED_FIELDS = (
    "slug", "title", "depends_on", "external_effects", "candidate_operations",
    "capabilities", "owned_paths", "requirements", "negative_cases",
    "acceptance", "qualification", "blocked_until",
)
REQUIREMENTS = {
    "R18-OBS-01", "R18-OBS-02", "R18-OBS-03",
    "R18-AUTH-01", "R18-AUTH-02", "R18-SEC-01", "R18-REC-01",
    "R18-UX-01", "R18-UX-02", "R18-QUAL-01", "R18-REL-01",
}
THREATS = {f"T{index:02}" for index in range(1, 31)}
RISK_FLOORS = {
    "operation:network.wifi.scan": "user-state",
    "operation:network.networking.set-enabled": "security-sensitive",
    "operation:network.wifi.set-enabled": "security-sensitive",
    "operation:network.connection.activate": "security-sensitive",
    "operation:network.connection.deactivate": "security-sensitive",
    "operation:network.wifi.join": "security-sensitive",
    "operation:network.profile.create": "security-sensitive",
    "operation:network.profile.update": "security-sensitive",
    "operation:network.profile.delete": "destructive",
}


def validate(plan: dict, design: dict, document: str) -> None:
    assert plan["schema_version"] == 1
    assert (plan["milestone"], plan["slice"], plan["status"]) == (
        "v0.10.0", "S18", "proposed"
    )
    assert plan["declared_slice_predecessor"] == "S16"
    assert plan["base_branch"] == "main"
    assert plan["phase1_reference_branch"] == "wip/v010-s18-network"
    assert plan["implementation_pr_count"] == len(EXPECTED_PRS)
    assert plan["phase1_source"] == "docs/workstreams/v010-s18-network-phase1.md"
    assert plan["design_source"] == "contracts/v010-s18-design.toml"
    for flag in ("runtime_effects_enabled", "evidence_accepted", "slice_complete",
                 "q11_physical_hardware_qualified", "merge_wip_directly"):
        assert plan[flag] is False, flag

    guard = plan["guardrails"]
    assert guard["system_bus_name"] == "org.freedesktop.NetworkManager"
    assert guard["cross_provider_authority"] == "Linura Control"
    assert guard["observation_envelope"] == "linura-observation::ObservationEnvelope"
    assert "managedexternaleffect" in guard["effect_semantics"].lower()
    assert "no blind replay" in guard["recovery"].lower()
    assert "offline local" in guard["recovery"].lower()
    assert "Q11" in guard["qualification"]
    assert "RequestScan" in guard["scan_semantics"]

    prs = plan["pull_request"]
    assert [pr["id"] for pr in prs] == EXPECTED_PRS
    assigned: list[str] = []
    referenced_requirements: set[str] = set()
    referenced_threats: set[str] = set()
    for index, pr in enumerate(prs):
        assert all(field in pr for field in REQUIRED_FIELDS), pr["id"]
        assert pr["slug"] and pr["title"].startswith("feat(network): ")
        assert pr["owned_paths"] and len(set(pr["owned_paths"])) == len(pr["owned_paths"])
        for field in ("capabilities", "requirements", "negative_cases",
                      "acceptance", "qualification", "blocked_until"):
            values = pr[field]
            assert values and all(isinstance(value, str) and value for value in values), (
                pr["id"], field
            )
            assert len(set(values)) == len(values), (pr["id"], field)
        assert len(pr["acceptance"]) >= 5
        assert len(set(pr["depends_on"])) == len(pr["depends_on"])
        assert all(dependency in EXPECTED_PRS[:index]
                   for dependency in pr["depends_on"]), pr["id"]
        assert len(set(pr["candidate_operations"])) == len(pr["candidate_operations"])
        actual_operations = set(pr["candidate_operations"])
        assert actual_operations == EXPECTED_ASSIGNMENTS[pr["id"]], pr["id"]
        assert pr["external_effects"] is (index in (1, 2, 3)), pr["id"]
        assert not any(path.startswith("executors/") for path in pr["owned_paths"])
        assigned.extend(pr["candidate_operations"])
        referenced_requirements.update(pr["requirements"])
        referenced_threats.update(pr["negative_cases"])
        assert f"### {pr['id']} — {pr['title']}" in document
    assert len(assigned) == len(set(assigned)) == len(EXPECTED_OPERATIONS)
    assert set(assigned) == EXPECTED_OPERATIONS
    assert referenced_requirements == REQUIREMENTS
    assert referenced_threats == THREATS
    assert prs[0]["depends_on"] == []
    assert "S18-2" in prs[2]["depends_on"]
    assert "S18-3" in prs[3]["depends_on"]
    assert set(prs[4]["depends_on"]) == set(EXPECTED_PRS[:4])
    assert any("physical" in evidence.lower() or "hardware" in evidence.lower()
               for evidence in prs[4]["qualification"])

    assert design["slice"] == "S18" and design["status"] == "proposed"
    assert design["activation"] == "none"
    assert design["register_runtime_operations"] is False
    assert design["implements_effects"] is False
    assert design["runtime_support_promotion"] is False
    assert design["interactive_evidence_ready"] is False
    assert design["allow_interface_name_as_effect_identity"] is False
    assert design["require_local_recovery_for_connectivity_loss"] is True
    assert design["no_generic_dbus_forwarding"] is True
    assert design["no_shell_executor"] is True
    assert design["secrets_in_audit_or_intent"] is False
    assert design["indeterminate_replay"] is False
    assert design["provider_well_known_name"] == guard["system_bus_name"]
    assert design["existing_read_only"]["compatibility_required"] is True
    assert design["existing_read_only"]["aliases_grant_effect_authority"] is False
    assert design["qualification"]["fixture_evidence_is_physical"] is False
    assert design["qualification"]["require_indeterminate_no_replay"] is True
    assert design["qualification"]["require_network_loss_recovery"] is True
    assert design["qualification"]["require_credential_redaction"] is True
    assert design["qualification"]["video_is_correctness_oracle"] is False
    assert design["qualification"]["require_keyboard_pointer_accessibility"] is True
    assert all(value is False for value in design["unsupported_extensions"].values())
    for invariant in (
        "strict_single_owner_epoch", "bounded_device_enumeration",
        "bounded_access_point_enumeration", "bounded_profile_enumeration",
        "reject_duplicate_interface_aliases", "reject_mixed_owner_snapshots",
        "require_fresh_effect_preconditions", "control_owns_aggregation",
    ):
        assert design["proposed_observation"][invariant] is True, invariant
    operations = design["candidate_operation"]
    assert len(operations) == len(EXPECTED_OPERATIONS)
    assert {op["id"] for op in operations} == EXPECTED_OPERATIONS
    for operation in operations:
        assert operation["enabled"] is False, operation["id"]
        assert operation["provider"] == "networkmanager"
        assert operation["class"] == "managed-external-effect"
        assert operation["risk_floor"] == RISK_FLOORS[operation["id"]]
    assert "not assigned GitHub PR numbers" in document
    assert "Do not merge this branch directly" in document


class S18DecompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = tomllib.loads(PLAN.read_text(encoding="utf-8"))
        cls.design = tomllib.loads(DESIGN.read_text(encoding="utf-8"))
        cls.document = DOC.read_text(encoding="utf-8")

    def test_plan_preserves_inactive_phase1_and_exact_operations(self) -> None:
        validate(self.plan, self.design, self.document)

    def test_premature_activation_and_evidence_are_rejected(self) -> None:
        for flag in ("runtime_effects_enabled", "evidence_accepted", "slice_complete",
                     "q11_physical_hardware_qualified", "merge_wip_directly"):
            mutated = copy.deepcopy(self.plan)
            mutated[flag] = True
            with self.subTest(flag=flag), self.assertRaises(AssertionError):
                validate(mutated, self.design, self.document)

    def test_operation_downgrade_or_activation_is_rejected(self) -> None:
        cases = (
            ("operation:network.profile.delete", "risk_floor", "user-state"),
            ("operation:network.wifi.scan", "class", "authoritative-query"),
            ("operation:network.connection.activate", "class", "transient-external-effect"),
            ("operation:network.wifi.set-enabled", "enabled", True),
        )
        for operation_id, field, value in cases:
            mutated = copy.deepcopy(self.design)
            target = next(op for op in mutated["candidate_operation"]
                          if op["id"] == operation_id)
            target[field] = value
            with self.subTest(operation=operation_id), self.assertRaises(AssertionError):
                validate(self.plan, mutated, self.document)

    def test_duplicate_missing_or_reassigned_operation_is_rejected(self) -> None:
        for changed in ("duplicate", "missing", "reassigned"):
            mutated = copy.deepcopy(self.plan)
            if changed == "duplicate":
                mutated["pull_request"][3]["candidate_operations"][0] = (
                    "operation:network.wifi.scan"
                )
            elif changed == "missing":
                mutated["pull_request"][2]["candidate_operations"].pop()
            else:
                moved = mutated["pull_request"][1]["candidate_operations"].pop()
                mutated["pull_request"][2]["candidate_operations"].append(moved)
            with self.subTest(change=changed), self.assertRaises(AssertionError):
                validate(mutated, self.design, self.document)

    def test_forward_dependency_or_missing_predecessor_is_rejected(self) -> None:
        for change in ("forward", "missing"):
            mutated = copy.deepcopy(self.plan)
            if change == "forward":
                mutated["pull_request"][0]["depends_on"] = ["S18-4"]
            else:
                mutated["pull_request"][4]["depends_on"].remove("S18-3")
            with self.subTest(change=change), self.assertRaises(AssertionError):
                validate(mutated, self.design, self.document)

    def test_extra_unreviewed_pr_or_missing_evidence_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.plan)
        mutated["pull_request"].append(copy.deepcopy(mutated["pull_request"][4]))
        with self.assertRaises(AssertionError):
            validate(mutated, self.design, self.document)
        mutated = copy.deepcopy(self.plan)
        mutated["pull_request"][4]["qualification"] = []
        with self.assertRaises(AssertionError):
            validate(mutated, self.design, self.document)

    def test_unsupported_expansions_and_secret_policy_downgrade_are_rejected(self) -> None:
        for field, value in (
            ("no_generic_dbus_forwarding", False),
            ("no_shell_executor", False),
            ("secrets_in_audit_or_intent", True),
            ("indeterminate_replay", True),
            ("allow_interface_name_as_effect_identity", True),
        ):
            mutated = copy.deepcopy(self.design)
            mutated[field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                validate(self.plan, mutated, self.document)

    def test_budget_consistency_and_unsupported_scope_cannot_be_relaxed(self) -> None:
        mutated = copy.deepcopy(self.design)
        mutated["proposed_observation"]["reject_mixed_owner_snapshots"] = False
        with self.assertRaises(AssertionError):
            validate(self.plan, mutated, self.document)
        mutated = copy.deepcopy(self.design)
        mutated["unsupported_extensions"]["vpn_plugin_mutations"] = True
        with self.assertRaises(AssertionError):
            validate(self.plan, mutated, self.document)
        mutated = copy.deepcopy(self.design)
        mutated["qualification"]["video_is_correctness_oracle"] = True
        with self.assertRaises(AssertionError):
            validate(self.plan, mutated, self.document)


if __name__ == "__main__":
    unittest.main()
