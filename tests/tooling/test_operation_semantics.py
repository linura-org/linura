from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("check_operation_semantics", ROOT / "tools/check_operation_semantics.py")
assert SPEC is not None and SPEC.loader is not None
check_operation_semantics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_operation_semantics)

FIXTURE_PATHS = (
    "contracts/operation-semantics.toml",
    "docs/adr/0032-classify-operations-before-authority.md",
    "docs/operation-semantics.md",
    "docs/threat-model.md",
    "crates/linura-core/src/lib.rs",
    "crates/linura-capability-sdk/src/lib.rs",
    "crates/linura-control/src/operation_semantics.rs",
    "crates/linura-control/src/operation_registry.rs",
    "crates/linura-control/src/managed_lifecycle.rs",
    "crates/linura-control/src/durable_authority.rs",
    "crates/linura-control/src/risk_classification.rs",
    "crates/linura-control/src/policy_review.rs",
    "SECURITY.md",
    "docs/milestones/v0.10.0.md",
    "docs/qualification/v0.10.0.md",
    "docs/ui-architecture.md",
    "AGENTS.md",
    "agents/skills/policy.md",
    "README.md",
)


class OperationSemanticsContractTests(unittest.TestCase):
    def _copy_fixture(self, destination: Path) -> None:
        for rel in FIXTURE_PATHS:
            source = ROOT / rel
            target = destination / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    def _rewrite_contract(self, root: Path, old: str, new: str) -> None:
        path = root / "contracts/operation-semantics.toml"
        text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count(old), 1)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def test_repository_contract_is_valid(self) -> None:
        self.assertEqual(check_operation_semantics.validate(ROOT), [])

    def test_empty_operation_semantics_contract_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            (root / "contracts/operation-semantics.toml").write_text("", encoding="utf-8")
            failures = check_operation_semantics.validate(root)
            self.assertIn("operation-semantics contract must not be empty", failures)

    def test_missing_adr_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            (root / "docs/adr/0032-classify-operations-before-authority.md").unlink()
            self.assertTrue(any("ADR 0032" in failure for failure in check_operation_semantics.validate(root)))

    def test_registered_authority_adr_cannot_drop_risk_floor_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            adr = root / "docs/adr/0032-classify-operations-before-authority.md"
            adr.write_text(
                adr.read_text(encoding="utf-8").replace(
                    "A registered risk floor is applied **before policy review**.",
                    "A registered risk floor is advisory.",
                    1,
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    "docs/adr/0032-classify-operations-before-authority.md missing operation-semantics marker"
                    in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_threat_model_cannot_drop_recovery_registry_revalidation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            threat = root / "docs/threat-model.md"
            threat.write_text(
                threat.read_text(encoding="utf-8").replace(
                    "managed restart and `Indeterminate` recovery re-establish authority from current registration",
                    "managed restart reuses prior registration",
                    1,
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    "docs/threat-model.md missing operation-semantics marker"
                    in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_transient_external_effect_cannot_gain_privileged_executor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._rewrite_contract(root, "privileged_executor_allowed = false\ncanonical_managed_lifecycle = false\npath = \"bounded-transient-effect\"", "privileged_executor_allowed = true\ncanonical_managed_lifecycle = false\npath = \"bounded-transient-effect\"")
            self.assertTrue(any("classes drifted" in failure for failure in check_operation_semantics.validate(root)))

    def test_managed_external_effect_cannot_drop_canonical_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._rewrite_contract(root, 'path = "canonical-managed-mutation"', 'path = "bounded-transient-effect"')
            self.assertTrue(any("classes drifted" in failure for failure in check_operation_semantics.validate(root)))

    def test_unknown_extra_operation_class_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/operation-semantics.toml"
            contract.write_text(contract.read_text(encoding="utf-8") + '\n[classes.unclassified-fast-path]\nrust_variant = "UnclassifiedFastPath"\n', encoding="utf-8")
            self.assertTrue(any("classes drifted" in failure for failure in check_operation_semantics.validate(root)))

    def test_transient_authorization_cannot_skip_canonical_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._rewrite_contract(
                root,
                'transient_effect_lifecycle = ["request", "observe", "plan", "validate-classify", "authorize", "execute", "verify", "audit"]',
                'transient_effect_lifecycle = ["request", "observe", "validate-classify", "authorize", "execute", "verify", "audit"]',
            )
            self.assertTrue(
                any(
                    "transient_effect_lifecycle drifted" in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_transient_class_cannot_drop_plan_bound_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/operation-semantics.toml"
            text = contract.read_text(encoding="utf-8")
            marker = (
                '[classes.transient-external-effect]\n'
                'rust_variant = "TransientExternalEffect"\n'
                'changes_external_state = true\n'
                'changes_linura_durable_state = false\n'
                'control_mediated = true\n'
                'risk_classification_required = true\n'
                'plan_bound_authorization = true\n'
            )
            self.assertIn(marker, text)
            contract.write_text(
                text.replace(
                    marker,
                    marker.replace(
                        "plan_bound_authorization = true",
                        "plan_bound_authorization = false",
                    ),
                    1,
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    "classes drifted" in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_transient_recovery_marker_is_not_bound_to_sentence_pronoun(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            qualification = root / "docs/qualification/v0.10.0.md"
            text = qualification.read_text(encoding="utf-8")
            self.assertIn("It has no durable prepare/commit/reconcile transaction", text)
            qualification.write_text(
                text.replace(
                    "It has no durable prepare/commit/reconcile transaction",
                    "This bounded path has no durable prepare/commit/reconcile transaction",
                    1,
                ),
                encoding="utf-8",
            )
            self.assertEqual(check_operation_semantics.validate(root), [])

    def test_transient_prepare_exemption_cannot_drift_from_security_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            security = root / "SECURITY.md"
            security.write_text(
                security.read_text(encoding="utf-8").replace(
                    "Prepare before managed external effects.",
                    "Prepare before external effects.",
                    1,
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    "SECURITY.md missing operation-semantics marker" in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_readme_cannot_reintroduce_universal_durable_prepare_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            readme = root / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8")
                + "\n- External effects require durable pre-execution prepare/recovery state.\n",
                encoding="utf-8",
            )
            failures = check_operation_semantics.validate(root)
            self.assertTrue(
                any(
                    "README.md contains forbidden operation-semantics marker"
                    in failure
                    for failure in failures
                )
            )
            self.assertFalse(
                any(
                    "README.md missing operation-semantics marker" in failure
                    for failure in failures
                )
            )

    def test_ui_cannot_drop_plan_bound_external_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            ui = root / "docs/ui-architecture.md"
            ui.write_text(
                ui.read_text(encoding="utf-8").replace(
                    "every external effect that reaches policy authorization is plan-bound",
                    "managed external effects are plan-bound",
                    1,
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    "docs/ui-architecture.md missing operation-semantics marker" in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_core_operation_variants_are_machine_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            core = root / "crates/linura-core/src/lib.rs"
            core.write_text(core.read_text(encoding="utf-8").replace("    TransientExternalEffect,\n", "", 1), encoding="utf-8")
            self.assertTrue(any("OperationClass variants drifted" in failure for failure in check_operation_semantics.validate(root)))

    def test_trusted_operation_registry_and_control_resolver_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)

            descriptor = root / "crates/linura-capability-sdk/src/lib.rs"
            descriptor.write_text(
                descriptor.read_text(encoding="utf-8").replace(
                    "pub struct OperationRegistry",
                    "struct OperationRegistry",
                    1,
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    "OperationDescriptor missing required fragment: pub struct OperationRegistry"
                    in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

            self._copy_fixture(root)
            descriptor = root / "crates/linura-capability-sdk/src/lib.rs"
            descriptor.write_text(
                descriptor.read_text(encoding="utf-8").replace(
                    "pub struct OperationEffectBinding",
                    "struct OperationEffectBinding",
                    1,
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    "OperationDescriptor missing required fragment: pub struct OperationEffectBinding"
                    in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

            self._copy_fixture(root)
            control = root / "crates/linura-control/src/operation_semantics.rs"
            control.write_text(
                control.read_text(encoding="utf-8").replace(
                    "pub fn resolve_external",
                    "fn resolve_external",
                    1,
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    "OperationSemanticsControl missing required fragment: pub fn resolve_external"
                    in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

            self._copy_fixture(root)
            control = root / "crates/linura-control/src/operation_semantics.rs"
            control.write_text(
                control.read_text(encoding="utf-8").replace(
                    "pub enum OperationPlanBindingMismatch",
                    "enum OperationPlanBindingMismatch",
                    1,
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    "OperationSemanticsControl missing required fragment: pub enum OperationPlanBindingMismatch"
                    in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_registered_managed_systemd_contract_cannot_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._rewrite_contract(
                root,
                'risk_floor = "security-sensitive"',
                'risk_floor = "user-state"',
            )
            self.assertTrue(
                any(
                    "registered_operations drifted" in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_registered_managed_systemd_resource_suffix_cannot_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._rewrite_contract(
                root,
                'resource_suffix = ".service"',
                'resource_suffix = ".timer"',
            )
            self.assertTrue(
                any(
                    "registered_operations drifted" in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_registered_risk_floor_authority_binding_cannot_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._rewrite_contract(
                root,
                'registered_risk_floor_authority_binding = "policy-review-and-durable-authority-binding"',
                'registered_risk_floor_authority_binding = "handoff-only"',
            )
            self.assertTrue(
                any(
                    "registered_risk_floor_authority_binding drifted"
                    in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_managed_candidate_cannot_drop_registered_risk_floor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            managed = root / "crates/linura-control/src/managed_lifecycle.rs"
            managed.write_text(
                managed.read_text(encoding="utf-8").replace(
                    "candidate_with_risk_floor(",
                    "candidate(",
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    "managed lifecycle missing trusted operation-registry integration"
                    in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_durable_authority_cannot_drop_floored_policy_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            durable = root / "crates/linura-control/src/durable_authority.rs"
            durable.write_text(
                durable.read_text(encoding="utf-8").replace(
                    "review_plan_with_classification(",
                    "review_plan(",
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    "durable authority floored policy-review path count drifted"
                    in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_managed_lifecycle_cannot_skip_trusted_registry_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            managed = root / "crates/linura-control/src/managed_lifecycle.rs"
            managed.write_text(
                managed.read_text(encoding="utf-8").replace(
                    "self.validate_registered_managed_systemd_candidate(&candidate)?;",
                    "",
                    1,
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    "managed lifecycle missing trusted operation-registry integration"
                    in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_reprepared_recovery_cannot_skip_registered_operation_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            managed = root / "crates/linura-control/src/managed_lifecycle.rs"
            marker = "self.handoff_registered_managed_systemd(&principal, prepared.as_mut())?"
            text = managed.read_text(encoding="utf-8")
            self.assertEqual(text.count(marker), 1)
            managed.write_text(text.replace(marker, "self.authority.handoff(&principal, prepared.as_mut())?", 1), encoding="utf-8")
            self.assertTrue(
                any(
                    "managed lifecycle missing trusted operation-registry integration"
                    in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_durable_handoff_stays_internal_and_exposes_plan_for_semantic_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            durable = root / "crates/linura-control/src/durable_authority.rs"
            durable.write_text(
                durable.read_text(encoding="utf-8").replace(
                    "pub(crate) fn handoff(",
                    "pub fn handoff(",
                    1,
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    "durable authority handoff boundary missing required fragment"
                    in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_builtin_registry_cannot_drop_managed_systemd_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            registry = root / "crates/linura-control/src/operation_registry.rs"
            registry.write_text(
                registry.read_text(encoding="utf-8").replace(
                    '"operation:systemd.unit.set-active-state"',
                    '"operation:systemd.unit.other"',
                    1,
                ),
                encoding="utf-8",
            )
            self.assertTrue(
                any(
                    "trusted Control operation registry missing required fragment"
                    in failure
                    for failure in check_operation_semantics.validate(root)
                )
            )

    def test_typed_operation_descriptor_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            descriptor = root / "crates/linura-capability-sdk/src/lib.rs"
            descriptor.write_text(descriptor.read_text(encoding="utf-8").replace("pub struct OperationDescriptor", "struct OperationDescriptor", 1), encoding="utf-8")
            self.assertTrue(any("OperationDescriptor missing" in failure for failure in check_operation_semantics.validate(root)))


if __name__ == "__main__":
    unittest.main()
