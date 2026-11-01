"""Non-activating S26 six-PR source and authority plan regression checks."""
import copy
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "contracts/v010-s26-pr-decomposition.toml"
DESIGN = ROOT / "contracts/v010-s26-design.toml"
ROADMAP = ROOT / "contracts/v010-workstation-slices.toml"
IDS = [f"S26-{i}" for i in range(1, 7)]
REQUIREMENTS = {
    "R26-BASE-01", "R26-OBS-01", "R26-STATE-01",
    "R26-PORT-01", "R26-ADOPT-01", "R26-OWN-01",
    "R26-REC-01", "R26-SEC-01", "R26-UX-01", "R26-QUAL-01",
}


def load(path):
    return tomllib.loads(path.read_text(encoding="utf-8"))


def validate(plan):
    expected = {
        "schema_version": 1, "slice": "S26", "milestone": "v0.10.0",
        "status": "proposed", "reference_branch": "wip/v010-s26-library",
        "extraction_base": "main", "depends_on_slice": "S16",
        "unblocks_slice": "S27", "library_schema_version": 1,
        "portable_format_version": 1, "proposed_pr_count": 6,
    }
    for key, value in expected.items():
        if plan[key] != value:
            raise ValueError(f"S26 plan drift: {key}")
    forbidden = (
        "implementation_extracted", "runtime_operations_registered",
        "generic_setup_executor_permitted", "machine_effects_enabled",
        "release_or_qualification_promotion", "vm_proves_physical_q11",
    )
    for key in forbidden:
        if plan[key] is not False:
            raise ValueError(f"unqualified S26 activation: {key}")
    authority = plan["authority"]
    for key in (
        "local_preflight_is_machine_plan", "imported_actor_is_principal",
        "imported_approval_is_valid", "portable_digest_grants_authority",
        "shared_resource_is_auto_removable", "restore_is_implicit_machine_rollback",
        "query_and_ui_have_effect_authority",
    ):
        if authority[key] is not False:
            raise ValueError(f"authority bypass: {key}")
    if authority["library"] != "crates/linura-library":
        raise ValueError("parallel Library")
    if authority["native_effect_rule"] != "fresh-canonical-control-plan-and-qualified-domain-operations-only":
        raise ValueError("unreviewed generic OS executor")
    if set(authority["machine_states"]) != {
        "selected", "persisted-local", "reviewed-plan", "authorized",
        "attempted", "verified", "indeterminate",
    }:
        raise ValueError("UI conflates desired and verified")
    gates = plan["global_gates"]
    if gates["decomposition_is_implementation_evidence"] or gates["decomposition_advances_ledger"]:
        raise ValueError("plan falsely promoted")
    if "Q11-maintained-physical-for-native-effects" not in gates["slice_completion"]:
        raise ValueError("physical qualification removed")
    prs = plan["pr"]
    if len(prs) != 6 or [x["id"] for x in prs] != IDS:
        raise ValueError("S26 six boundaries changed without explicit rebaseline")
    visited, coverage = set(), set()
    for pr in prs:
        if any(dep not in visited for dep in pr["depends_on"]):
            raise ValueError(f"invalid DAG at {pr['id']}")
        if not pr["branch_hint"].startswith("feat/v010-s26-"):
            raise ValueError("non-extractable PR")
        for key in ("semantics", "owned_areas", "requirements", "deliverables", "negative_tests", "proof"):
            if len(pr[key]) < 2:
                raise ValueError(f"incomplete {pr['id']}: {key}")
        if not pr["activation"] or not pr["merge_gate"]:
            raise ValueError("missing activation or review gate")
        coverage.update(pr["requirements"])
        visited.add(pr["id"])
    if coverage != REQUIREMENTS:
        raise ValueError("Phase-1 requirement coverage drift")
    if prs[0]["depends_on"] or set(prs[-1]["depends_on"]) != set(IDS[:-1]):
        raise ValueError("foundation first, integration last")
    for path in plan["baseline"].values():
        if not (ROOT / path).is_file():
            raise ValueError(f"missing reviewed source {path}")


class S26PRDecompositionTests(unittest.TestCase):
    def test_proposed_scope_and_existing_ledgers(self):
        validate(load(PLAN))
        design = load(DESIGN)
        self.assertEqual(design["activation"], "none")
        self.assertFalse(design["register_runtime_operations"])
        self.assertFalse(design["generic_apply_setup_executor"])
        ledger = {s["id"]: s for s in load(ROADMAP)["slice"]}
        self.assertEqual(ledger["S26"]["status"], "planned")
        self.assertEqual(ledger["S26"]["depends_on"], ["S16"])
        self.assertEqual(ledger["S26"]["evidence_prs"], [])
        self.assertIn("S26", ledger["S27"]["depends_on"])

    def test_fail_closed_negative_plan_mutations(self):
        valid = load(PLAN)
        for key, value in (
            ("machine_effects_enabled", True),
            ("generic_setup_executor_permitted", True),
            ("vm_proves_physical_q11", True),
            ("library_schema_version", 2),
        ):
            with self.subTest(key=key):
                bad = copy.deepcopy(valid)
                bad[key] = value
                with self.assertRaises(ValueError):
                    validate(bad)
        for change in ("missing", "forward", "tests", "coverage"):
            with self.subTest(change=change):
                bad = copy.deepcopy(valid)
                if change == "missing":
                    bad["pr"].pop()
                elif change == "forward":
                    bad["pr"][0]["depends_on"] = ["S26-5"]
                elif change == "tests":
                    bad["pr"][2]["negative_tests"] = []
                else:
                    for pr in bad["pr"]:
                        pr["requirements"] = [r for r in pr["requirements"] if r != "R26-QUAL-01"]
                with self.assertRaises(ValueError):
                    validate(bad)


if __name__ == "__main__":
    unittest.main()
