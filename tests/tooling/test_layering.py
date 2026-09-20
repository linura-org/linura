from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class LayeringContractTests(unittest.TestCase):
    def _run_checker(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/check_layering.py"), str(root)],
            capture_output=True,
            text=True,
            check=False,
        )

    def _copy_fixture(self, destination: Path) -> None:
        for rel in (
            "Cargo.toml",
            "contracts/layering.toml",
            "docs/terminology.md",
            "docs/provider-model.md",
            "docs/state-model.md",
            "docs/system-graph.md",
            "docs/action-lifecycle.md",
            "agents/skills/providers.md",
            "crates/linura-provider-sdk/src/lib.rs",
            "crates/linura-hardware/src/platform_profile.rs",
            "crates/linura-control/src/platform_compatibility.rs",
        ):
            source = ROOT / rel
            target = destination / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        for member in workspace["workspace"]["members"]:
            source = ROOT / member / "Cargo.toml"
            target = destination / member / "Cargo.toml"
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    def _add_dependency(self, manifest: Path, name: str, spec: str) -> None:
        text = manifest.read_text(encoding="utf-8")
        dependency = f"{name} = {spec}\n"
        if "[dependencies]\n" in text:
            text = text.replace("[dependencies]\n", "[dependencies]\n" + dependency, 1)
        elif "[lints]" in text:
            text = text.replace("[lints]", "[dependencies]\n" + dependency + "\n[lints]", 1)
        else:
            text += "\n[dependencies]\n" + dependency
        manifest.write_text(text, encoding="utf-8")

    def _add_target_dependency(self, manifest: Path, name: str, spec: str) -> None:
        text = manifest.read_text(encoding="utf-8")
        text += f'\n[target."cfg(unix)".dependencies]\n{name} = {spec}\n'
        manifest.write_text(text, encoding="utf-8")

    def _add_workspace_dependency(self, root: Path, alias: str, spec: str) -> None:
        workspace = root / "Cargo.toml"
        text = workspace.read_text(encoding="utf-8")
        text += f"\n[workspace.dependencies]\n{alias} = {spec}\n"
        workspace.write_text(text, encoding="utf-8")

    def test_repository_layering_contract_is_valid(self) -> None:
        result = self._run_checker(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_planner_cannot_gain_dbus_transport_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "crates/linura-planner/Cargo.toml"
            self._add_dependency(manifest, "zbus", '"5"')

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("linura-planner violates transport-neutral boundary", result.stderr)

    def test_aliased_transport_dependency_is_resolved_to_package_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "crates/linura-planner/Cargo.toml"
            self._add_dependency(manifest, "bus", '{ package = "zbus", version = "5" }')

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("linura-planner violates transport-neutral boundary", result.stderr)

    def test_target_specific_transport_dependency_is_checked(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "crates/linura-planner/Cargo.toml"
            self._add_target_dependency(
                manifest,
                "bus",
                '{ package = "zbus", version = "5" }',
            )

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("linura-planner violates transport-neutral boundary", result.stderr)

    def test_workspace_aliased_transport_dependency_is_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._add_workspace_dependency(
                root,
                "bus",
                '{ package = "zbus", version = "5" }',
            )
            manifest = root / "crates/linura-planner/Cargo.toml"
            self._add_dependency(manifest, "bus", "{ workspace = true }")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("linura-planner violates transport-neutral boundary", result.stderr)

    def test_dbus_transport_cannot_own_planner_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "crates/linura-dbus/Cargo.toml"
            self._add_dependency(
                manifest,
                "linura-planner",
                '{ path = "../linura-planner" }',
            )

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("linura-dbus violates inward dependency boundary", result.stderr)

    def test_semantic_crate_cannot_depend_on_concrete_executor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "crates/linura-core/Cargo.toml"
            self._add_dependency(
                manifest,
                "linura-executor-systemd",
                '{ path = "../../executors/linura-executor-systemd" }',
            )

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("linura-core violates concrete executor/provider boundary", result.stderr)

    def test_provenance_is_a_required_protected_semantic_crate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "crates/linura-provenance/Cargo.toml"
            self._add_dependency(manifest, "zbus", '"5"')

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("linura-provenance violates transport-neutral boundary", result.stderr)

    def test_required_package_rule_cannot_be_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/layering.toml"
            text = contract.read_text(encoding="utf-8")
            marker = '[[rules]]\npackage = "linura-provenance"\n'
            start = text.find(marker)
            self.assertNotEqual(start, -1)
            end = text.find("[[rules]]", start + len(marker))
            if end == -1:
                end = text.find("[[markers]]", start + len(marker))
            self.assertNotEqual(end, -1)
            contract.write_text(text[:start] + text[end:], encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("layering contract missing required package rules", result.stderr)
            self.assertIn("linura-provenance", result.stderr)

    def test_observation_control_cannot_gain_concrete_linux_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "crates/linura-observation-control/Cargo.toml"
            self._add_dependency(
                manifest,
                "linura-linux-observation",
                '{ path = "../linura-linux-observation" }',
            )

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "linura-observation-control violates inward dependency boundary",
                result.stderr,
            )

    def test_concrete_observer_cannot_gain_hardware_aggregation_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "crates/linura-linux-observation/Cargo.toml"
            self._add_dependency(
                manifest,
                "linura-hardware",
                '{ path = "../linura-hardware" }',
            )

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("linura-linux-observation violates inward dependency boundary", result.stderr)

    def test_hardware_contract_cannot_gain_concrete_linux_observer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "crates/linura-hardware/Cargo.toml"
            self._add_dependency(
                manifest,
                "linura-linux-observation",
                '{ path = "../linura-linux-observation" }',
            )

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("linura-hardware violates inward dependency boundary", result.stderr)

    def test_concrete_observer_cannot_gain_control_plane_orchestration(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "crates/linura-linux-observation/Cargo.toml"
            self._add_dependency(
                manifest,
                "linura-control",
                '{ path = "../linura-control" }',
            )

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("linura-linux-observation violates inward dependency boundary", result.stderr)

    def test_public_sdk_cannot_gain_provider_authority_internals(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "crates/linura-sdk/Cargo.toml"
            self._add_dependency(
                manifest,
                "linura-provider-sdk",
                '{ path = "../linura-provider-sdk" }',
            )

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("linura-sdk violates inward dependency boundary", result.stderr)

    def test_narrow_executor_cannot_gain_control_plane_orchestration(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "executors/linura-executor-systemd/Cargo.toml"
            self._add_dependency(
                manifest,
                "linura-control",
                '{ path = "../../crates/linura-control" }',
            )

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("linura-executor-systemd violates inward dependency boundary", result.stderr)

    def test_principal_terminology_cannot_be_downgraded_to_client_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            terminology = root / "docs/terminology.md"
            terminology.write_text(
                terminology.read_text(encoding="utf-8").replace(
                    "**Principal:** authenticated authority identity used to namespace policy/review/approval state.",
                    "**Principal:** identity supplied by the client.",
                    1,
                ),
                encoding="utf-8",
            )

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("layering marker missing from docs/terminology.md", result.stderr)

    def test_actor_terminology_cannot_be_repurposed_as_authority_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            terminology = root / "docs/terminology.md"
            terminology.write_text(
                terminology.read_text(encoding="utf-8").replace(
                    "**Actor:** request-provenance identity and classification attached to a request/plan",
                    "**Actor:** authority identity attached to a request/plan",
                    1,
                ),
                encoding="utf-8",
            )

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("layering marker missing from docs/terminology.md", result.stderr)

    def test_canonical_observation_marker_cannot_silently_disappear(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            sdk = root / "crates/linura-provider-sdk/src/lib.rs"
            sdk.write_text(
                sdk.read_text(encoding="utf-8").replace(
                    "Result<ObservationEnvelope, ProviderError>",
                    "Result<String, ProviderError>",
                    1,
                ),
                encoding="utf-8",
            )

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "layering marker missing from crates/linura-provider-sdk/src/lib.rs",
                result.stderr,
            )


if __name__ == "__main__":
    unittest.main()
