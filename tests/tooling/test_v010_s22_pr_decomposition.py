"""Design-only S22 PR decomposition: fail closed against accidental promotion.

These are contract tests, not native compositor/clipboard/physical evidence.
"""
from __future__ import annotations

import copy
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "contracts/v010-s22-pr-decomposition.toml"
DESIGN = ROOT / "contracts/v010-s22-design.toml"
IDS = [f"S22-{i}" for i in range(1, 7)]
CASES = {f"U22-{i:02d}" for i in range(1, 29)}
REQUIREMENTS = {
    "R22-AUTH-01", "R22-OBS-01", "R22-CAP-01", "R22-CAP-02",
    "R22-REC-01", "R22-CLIP-01", "R22-HIST-01", "R22-SEC-01",
    "R22-UX-01", "R22-QUAL-01",
}
GATES = {
    "canonical-check", "dependency-audit", "analyze",
    "security-verification", "applicable-qualification",
}

def read(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))

def validate(plan: dict, design: dict) -> None:
    if (plan["schema_version"], plan["slice"], plan["milestone"], plan["profile"]) != (
        1, "S22", "v0.10.0", "arch-hyprland-v1"
    ):
        raise ValueError("unreviewed identity")
    if plan["status"] != "proposed" or plan["phase"] != "implementation-pr-decomposition":
        raise ValueError("unreviewed phase/state")
    if plan["expected_pr_count"] != 6 or plan["declared_roadmap_predecessor"] != "S16":
        raise ValueError("scope changed")
    for key in (
        "proposed_ids_are_github_numbers", "runtime_implementation_claim",
        "runtime_activation", "runtime_support_promotion", "slice_completion_claim",
        "native_evidence_claim", "physical_q11_claim", "release_ledger_change",
        "merge_wip_directly",
    ):
        if plan[key] is not False:
            raise ValueError(f"unsupported promotion: {key}")
    if not plan["extract_from_current_main"]:
        raise ValueError("implementation must use a clean current-main base")
    if set(plan["acceptance_levels"]) != {"A", "B", "C"} or set(plan["required_gates"]) != GATES:
        raise ValueError("qualification weakened")
    a = plan["authority"]
    if a["owner"] != "linura-control" or a["unsupported"] != "fail-closed":
        raise ValueError("Control authority weakened")
    for key in (
        "compositor_enforced_exclusion_required", "authenticated_session_seat_epoch_required",
        "independent_native_verification_required",
    ):
        if a[key] is not True:
            raise ValueError(f"missing prerequisite: {key}")
    for key in (
        "control_can_be_replaced_by_portal_grant", "untrusted_client_may_run_capture",
        "general_model_access_to_content", "clipboard_history_enabled_by_default",
        "recorder_without_native_stop", "implicit_s20_audio_consent",
        "automatic_upload_or_share", "unverified_effect_may_activate",
        "vm_counts_as_physical_q11",
    ):
        if a[key] is not False:
            raise ValueError(f"unsafe authority/feature promotion: {key}")
    prs = plan["pr"]
    if [p["id"] for p in prs] != IDS:
        raise ValueError("missing, duplicate or reordered PR")
    seen, ops, cases, requirements = set(), set(), set(), set()
    for p in prs:
        if p["state"] != "proposed" or p["runtime_activation"] or p["release_evidence_claim"]:
            raise ValueError("PR activation/evidence claim")
        if not p["create_as_draft"] or not p["requires_same_pr_code_tests_security_review"]:
            raise ValueError("incomplete review boundary")
        if not set(p["depends_on"]) <= seen:
            raise ValueError("out-of-order or cyclic dependency")
        if set(p["acceptance_levels"]) != {"A", "B", "C"} or set(p["required_gates"]) != GATES:
            raise ValueError("PR gates weakened")
        if not p["mandatory_native_proofs"] or not p["activation_rule"]:
            raise ValueError("missing native proof or activation rule")
        if not p["owned_implementation_paths"] or any(
            not s.startswith(("apps/", "crates/")) or ".." in s
            for s in p["owned_implementation_paths"]
        ):
            raise ValueError("missing/unsafe ownership")
        if not set(p["adversarial_cases"]) <= CASES or not set(p["requirements"]) <= REQUIREMENTS:
            raise ValueError("unknown acceptance identifier")
        if not p["adversarial_cases"] or not p["requirements"]:
            raise ValueError("empty acceptance")
        for op in p["owned_candidate_operations"]:
            if op in ops:
                raise ValueError("candidate owned by more than one PR")
            ops.add(op)
        cases.update(p["adversarial_cases"])
        requirements.update(p["requirements"])
        seen.add(p["id"])
    if cases != CASES or requirements != REQUIREMENTS:
        raise ValueError("missing threat or requirement")
    if ops != {o["id"] for o in design["candidate_operation"]}:
        raise ValueError("candidate ownership out of sync with Phase 1")
    if prs[0]["owned_candidate_operations"] or prs[5]["owned_candidate_operations"]:
        raise ValueError("foundation/UX activated effects")
    if prs[1]["depends_on"] != ["S22-1"] or prs[2]["depends_on"] != ["S22-1"]:
        raise ValueError("unprotected capture path")
    if prs[3]["depends_on"] or prs[4]["depends_on"] != ["S22-4"]:
        raise ValueError("clipboard dependency violated")
    if set(prs[5]["depends_on"]) != set(IDS[:-1]):
        raise ValueError("incomplete UI integration")
    if "S20" not in prs[2]["integration_slices"] or not {"S17", "S21"} <= set(prs[0]["integration_slices"]):
        raise ValueError("missing protected inter-slice boundary")

class S22PrDecompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan, cls.design = read(PLAN), read(DESIGN)

    def test_plan_is_consistent_and_inactive(self):
        validate(self.plan, self.design)

    def test_source_contracts_are_present(self):
        for name in ("source_architecture", "source_design", "source_adr", "source_qualification", "source_security"):
            with self.subTest(name=name):
                self.assertTrue((ROOT / self.plan[name]).is_file())

    def test_cannot_promote_unsupported_capabilities(self):
        for name in ("runtime_activation", "slice_completion_claim", "physical_q11_claim", "merge_wip_directly"):
            p = copy.deepcopy(self.plan)
            p[name] = True
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate(p, self.design)
        for name in ("unverified_effect_may_activate", "recorder_without_native_stop",
                     "general_model_access_to_content", "clipboard_history_enabled_by_default"):
            p = copy.deepcopy(self.plan)
            p["authority"][name] = True
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate(p, self.design)

    def test_missing_operations_and_dependencies_are_denied(self):
        p = copy.deepcopy(self.plan)
        p["pr"][4]["owned_candidate_operations"].pop()
        with self.assertRaises(ValueError):
            validate(p, self.design)
        p = copy.deepcopy(self.plan)
        p["pr"][2]["depends_on"] = []
        with self.assertRaises(ValueError):
            validate(p, self.design)
        p = copy.deepcopy(self.plan)
        p["pr"][5]["depends_on"] = ["S22-1"]
        with self.assertRaises(ValueError):
            validate(p, self.design)

    def test_qualification_and_attack_coverage_cannot_be_omitted(self):
        p = copy.deepcopy(self.plan)
        for part in p["pr"]:
            part["adversarial_cases"] = [s for s in part["adversarial_cases"] if s != "U22-28"]
        with self.assertRaises(ValueError):
            validate(p, self.design)
        p = copy.deepcopy(self.plan)
        p["pr"][0]["required_gates"].remove("applicable-qualification")
        with self.assertRaises(ValueError):
            validate(p, self.design)

if __name__ == "__main__":
    unittest.main()
