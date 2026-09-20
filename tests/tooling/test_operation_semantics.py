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
    "crates/linura-core/src/lib.rs",
    "crates/linura-capability-sdk/src/lib.rs",
    "SECURITY.md",
    "docs/milestones/v0.10.0.md",
    "docs/qualification/v0.10.0.md",
    "docs/ui-architecture.md",
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

    def test_ui_cannot_reintroduce_universal_plan_first_mutation_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            ui = root / "docs/ui-architecture.md"
            ui.write_text(
                ui.read_text(encoding="utf-8").replace(
                    "every `ManagedExternalEffect` is plan-first",
                    "every mutation is plan-first",
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

    def test_typed_operation_descriptor_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            descriptor = root / "crates/linura-capability-sdk/src/lib.rs"
            descriptor.write_text(descriptor.read_text(encoding="utf-8").replace("pub struct OperationDescriptor", "struct OperationDescriptor", 1), encoding="utf-8")
            self.assertTrue(any("OperationDescriptor missing" in failure for failure in check_operation_semantics.validate(root)))


if __name__ == "__main__":
    unittest.main()
