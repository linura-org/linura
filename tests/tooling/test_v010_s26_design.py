"""S26 proposed Library workstation contracts remain inert and nondelegating.

Static contract checks never substitute for native SQLite/recovery or Q11 proof.
"""

from __future__ import annotations

import copy
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DESIGN = ROOT / "contracts/v010-s26-design.toml"
REGISTRY = ROOT / "contracts/operation-semantics.toml"
LOCAL = {
    "operation:library.setup.save",
    "operation:library.profile.save",
    "operation:library.setup.import",
    "operation:library.profile.import",
}
EXTERNAL = {
    "operation:library.setup.export",
    "operation:library.profile.export",
    "operation:library.backup.create",
    "operation:library.backup.restore",
}
EXPECTED = LOCAL | EXTERNAL


def read(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def validate_inert(doc: dict) -> None:
    if doc["status"] != "proposed" or doc["activation"] != "none":
        raise ValueError("S26 proposed design activated")
    for key in (
        "register_runtime_operations", "implements_new_effects",
        "runtime_support_promotion", "interactive_evidence_ready",
        "shadow_library_database_allowed", "portable_artifact_grants_authority",
        "imported_actor_is_authenticated_principal",
        "adoption_preflight_is_executable_plan",
        "local_import_applies_machine_configuration",
        "operation_id_is_external_executor_grant",
        "replay_historical_approval_or_effect",
        "use_setup_title_or_latest_alias_as_identity",
        "assume_shared_resource_removable", "backup_restore_is_implicit_rollback",
        "generic_apply_setup_executor", "remote_sync_enabled",
        "unknown_or_incomplete_closure_is_safe",
    ):
        if doc[key] is not False:
            raise ValueError(f"unsafe Library capability activation: {key}")
    for key in (
        "preserve_released_v07_schema_and_format", "reuse_existing_local_library",
        "reuse_native_adoption_preflight", "require_authenticated_owner_and_exact_revisions",
        "require_complete_causal_ownership", "require_fresh_canonical_machine_plan_for_effects",
        "require_separate_local_commit_and_native_verification",
        "require_no_model_offline_paths", "require_sqlite_integrity_backup_and_recovery",
    ):
        if doc[key] is not True:
            raise ValueError(f"released authority/data boundary weakened: {key}")
    existing = doc["existing_local_library"]
    if existing["sqlite_schema_version"] != 1:
        raise ValueError("released SQLite Library schema changed")
    if existing["portable_format_version"] != 1:
        raise ValueError("released portable bundle format changed")
    for key, val in existing.items():
        if isinstance(val, bool) and val is not True:
            raise ValueError(f"released Library boundary weakened: {key}")
    identity = doc["revision_identity"]
    for key, value in (
        ("setup_revision_type", "u32"),
        ("profile_revision_type", "u32"),
        ("intent_revision_type", "u64"),
    ):
        if identity[key] != value:
            raise ValueError(f"wrong revision type: {key}")
    for section in ("revision_identity", "preflight", "machine_apply"):
        for key, value in doc[section].items():
            if isinstance(value, bool) and value is not True:
                raise ValueError(f"missing {section}.{key}")
    if doc["preflight"]["report_type"] != "AdoptionReport":
        raise ValueError("fresh machine planning replaced by preflight")
    if doc["preflight"]["requires_plan_field"] != "requires_plan":
        raise ValueError("requires_plan semantic boundary missing")
    if doc["machine_apply"]["source"] != "canonical-linura-control-planner":
        raise ValueError("generic executable Setup authority introduced")
    if any(doc["unsupported_extensions"].values()):
        raise ValueError("unsupported portable or privileged extension enabled")

    ops = doc["candidate_operation"]
    ids = [op["id"] for op in ops]
    if len(ids) != len(set(ids)) or set(ids) != EXPECTED:
        raise ValueError("missing, duplicate or unreviewed Library operation")
    for op in ops:
        if op["enabled"] is not False or not op["resource"].startswith("exact-"):
            raise ValueError("unregistered operation became active or alias-bound")
        if not op["requested_keys"] or not op["requires"]:
            raise ValueError("unbounded Library operation material")
        if op["id"] in LOCAL:
            if (
                op["provider"] != "linura-local-library"
                or op["class"] != "linura-owned-state"
                or op["risk_floor"] != "user-state"
            ):
                raise ValueError("local Library effect misclassified")
            if "atomic-local-commit" not in op["requires"]:
                raise ValueError("local atomic commit invariant lost")
        else:
            if (
                op["provider"] != "local-file-artifact"
                or op["class"] != "managed-external-effect"
            ):
                raise ValueError("external file effect downgraded")
            if "independent-reobserve" not in op["requires"]:
                raise ValueError("external artifact lacks independent verification")
            if op["risk_floor"] not in ("user-state", "security-sensitive", "destructive"):
                raise ValueError("unreviewed external file risk")
    for op_id in (
        "operation:library.setup.import", "operation:library.profile.import",
    ):
        op = next(item for item in ops if item["id"] == op_id)
        if not {"no-imported-authority", "operation-id-idempotency"} <= set(
            op["requires"]
        ):
            raise ValueError("portable import can launder/replay authority")
    restore = next(
        item for item in ops if item["id"] == "operation:library.backup.restore"
    )
    if restore["risk_floor"] != "destructive" or not {
        "quiescent-writers-and-readers", "schema-and-integrity-validation",
        "prior-state-recovery", "durable-prepare",
    } <= set(restore["requires"]):
        raise ValueError("unsafe active database restore")
    if any(doc["qualification"][key] is not False for key in (
        "static_or_mock_is_native_qualification", "vm_ui_proves_physical_effects",
        "video_is_correctness_oracle",
    )):
        raise ValueError("contract or VM falsely promoted to real machine evidence")
    for key, value in doc["qualification"].items():
        if key.startswith("require_") and value is not True:
            raise ValueError(f"qualification disabled: {key}")


class S26ProposedArchitectureTests(unittest.TestCase):
    def test_scope_inert_compatibility_and_eight_candidate_operations(self):
        doc = read(DESIGN)
        self.assertEqual(
            (doc["schema_version"], doc["slice"], doc["milestone"]),
            (1, "S26", "v0.10.0"),
        )
        self.assertEqual(
            (doc["profile"], doc["dependency"], doc["downstream_slice"]),
            ("arch-hyprland-v1", "S16", "S27"),
        )
        self.assertEqual(doc["unsupported_behavior"], "fail-closed")
        self.assertEqual(len(doc["candidate_operation"]), 8)
        validate_inert(doc)

    def test_released_sqlite_portable_and_adoption_apis_are_reused(self):
        doc = read(DESIGN)["existing_local_library"]
        for key in (
            "crate", "store", "adoption", "portable", "schema",
            "released_qualification",
        ):
            self.assertTrue((ROOT / doc[key]).is_file(), key)
        lib = (ROOT / doc["crate"]).read_text(encoding="utf-8")
        store = (ROOT / doc["store"]).read_text(encoding="utf-8")
        adoption = (ROOT / doc["adoption"]).read_text(encoding="utf-8")
        portable = (ROOT / doc["portable"]).read_text(encoding="utf-8")
        schema = (ROOT / doc["schema"]).read_text(encoding="utf-8")
        self.assertIn("pub struct StoredSetup", lib)
        self.assertIn("pub struct StoredProfile", lib)
        self.assertIn("pub struct AdoptionReport", lib)
        for name in (
            "pub fn save_setup(", "pub fn save_profile(",
            "pub fn removal_impact(", "pub fn backup_to(",
        ):
            self.assertIn(name, store)
        for name in (
            "pub fn preflight_setup_adoption(", "pub fn preflight_profile_adoption(",
            "pub fn adopt_setup_bundle(", "pub fn adopt_profile_bundle(",
        ):
            self.assertIn(name, adoption)
        self.assertIn("pub const PORTABLE_FORMAT_VERSION: u16 = 1", portable)
        self.assertIn("pub const LIBRARY_SCHEMA_VERSION: u32 = 1", schema)

    def test_no_generic_setup_executor_or_imported_authority_registered(self):
        registry = read(REGISTRY)
        self.assertEqual(
            registry["classification_owner"],
            "trusted-operation-registry-and-linura-control",
        )
        self.assertFalse(registry["client_classification_authority"])
        self.assertFalse(registry["provider_classification_authority"])
        self.assertEqual(registry["unknown_effect_behavior"], "fail-closed")
        live = {
            op["operation_id"]
            for op in registry["registered_operations"].values()
        }
        self.assertFalse(live & EXPECTED)
        doc = read(DESIGN)
        self.assertFalse(doc["generic_apply_setup_executor"])
        self.assertFalse(doc["adoption_preflight_is_executable_plan"])
        self.assertTrue(doc["machine_apply"]["no_generic_profile_execution"])

    def test_adversarial_mutations_fail_closed(self):
        valid = read(DESIGN)
        for key, value in (
            ("activation", "active"),
            ("register_runtime_operations", True),
            ("imported_actor_is_authenticated_principal", True),
            ("local_import_applies_machine_configuration", True),
            ("generic_apply_setup_executor", True),
            ("require_complete_causal_ownership", False),
            ("replay_historical_approval_or_effect", True),
        ):
            with self.subTest(flag=key):
                bad = copy.deepcopy(valid)
                bad[key] = value
                with self.assertRaises(ValueError):
                    validate_inert(bad)
        for operation_id, field, value in (
            ("operation:library.setup.save", "class", "managed-external-effect"),
            ("operation:library.setup.import", "enabled", True),
            ("operation:library.profile.import", "resource", "profile-name"),
            ("operation:library.setup.export", "class", "linura-owned-state"),
            ("operation:library.backup.restore", "risk_floor", "user-state"),
            ("operation:library.backup.create", "provider", "linura-local-library"),
        ):
            with self.subTest(operation=operation_id, field=field):
                bad = copy.deepcopy(valid)
                next(
                    item for item in bad["candidate_operation"]
                    if item["id"] == operation_id
                )[field] = value
                with self.assertRaises(ValueError):
                    validate_inert(bad)

    def test_security_documentation_and_ci_qualification_routing(self):
        doc = read(DESIGN)
        for key in (
            "architecture", "source_audit", "qualification_document",
            "security_qualification",
        ):
            self.assertTrue((ROOT / doc[key]).is_file(), key)
        self.assertIn(
            "0054-s26-local-library-workstation-authority.md",
            (ROOT / "docs/adr/README.md").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "v0.10.0-s26.md",
            (ROOT / "docs/milestones/v0.10.0.md").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "v0.10.0-s26-security.md",
            (ROOT / "docs/qualification/v0.10.0.md").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "ADR 0054",
            (ROOT / "docs/threat-model.md").read_text(encoding="utf-8"),
        )
        matrix = read(ROOT / "contracts/qualification-gate-matrix.toml")
        gate = next(x for x in matrix["gate"] if x["id"] == "v010-workstation")
        expected = {
            "contracts/v010-s26-design.toml", doc["architecture"],
            doc["qualification_document"], doc["security_qualification"],
            "tests/tooling/test_v010_s26_design.py",
        }
        self.assertTrue(expected <= set(gate["paths"]))
        routes = {x["path"]: x["gates"] for x in matrix["contract"]}
        self.assertIn("v010-workstation", routes["contracts/v010-s26-design.toml"])
        workflow = (ROOT / ".github/workflows/v010-qualification.yml").read_text()
        for path in expected:
            self.assertIn(f'"{path}"', workflow)

    def test_canonical_product_dependency_and_physical_proof_unchanged(self):
        ledger = {
            x["id"]: x
            for x in read(ROOT / "contracts/v010-workstation-slices.toml")["slice"]
        }
        self.assertEqual(ledger["S26"]["status"], "planned")
        self.assertEqual(ledger["S26"]["depends_on"], ["S16"])
        self.assertEqual(ledger["S26"]["evidence_prs"], [])
        self.assertIn("S26", ledger["S27"]["depends_on"])
        self.assertEqual(ledger["S16"]["status"], "complete")
        qual = read(DESIGN)["qualification"]
        self.assertFalse(qual["vm_ui_proves_physical_effects"])
        self.assertTrue(qual["require_v07_v08_v09_regression"])
        self.assertTrue(qual["require_no_replay_of_imported_acceptance_or_external_effect"])


if __name__ == "__main__":
    unittest.main()
