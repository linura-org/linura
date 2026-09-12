from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RoadmapContractTests(unittest.TestCase):
    def _run_checker(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/check_roadmap.py"), str(root)],
            capture_output=True,
            text=True,
            check=False,
        )

    def _run_machine_checker(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/check_machine_classes.py"), str(root)],
            capture_output=True,
            text=True,
            check=False,
        )

    def _copy_fixture(self, destination: Path) -> None:
        contract = tomllib.loads((ROOT / "contracts/roadmap.toml").read_text(encoding="utf-8"))
        paths = {
            "contracts/roadmap.toml",
            "docs/roadmap.md",
            "docs/system-domains.md",
            "docs/development-plan.md",
            "docs/versioning-and-release-policy.md",
            "docs/machine-profiles.md",
            "hardware/support-matrix.json",
        }
        for milestone in contract.get("milestone", []):
            for key in ("release_contract", "qualification"):
                value = milestone.get(key)
                if isinstance(value, str):
                    paths.add(value)
        for rel in sorted(paths):
            source = ROOT / rel
            target = destination / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

    def _mutate_milestone_field(self, text: str, version: str, old: str, new: str) -> str:
        pattern = re.compile(
            rf'(?ms)^\[\[milestone\]\]\nversion = "{re.escape(version)}"\n.*?(?=^\[\[milestone\]\]|\Z)'
        )
        match = pattern.search(text)
        self.assertIsNotNone(match, f"missing roadmap milestone {version}")
        assert match is not None
        block = match.group(0)
        self.assertEqual(block.count(old), 1, f"{version}: expected exactly one {old!r}")
        replacement = block.replace(old, new, 1)
        return text[: match.start()] + replacement + text[match.end() :]

    def test_repository_roadmap_contract_is_valid(self) -> None:
        result = self._run_checker(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_repository_machine_class_contract_is_valid(self) -> None:
        result = self._run_machine_checker(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_current_release_cannot_silently_move_backward(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/roadmap.toml"
            text = contract.read_text(encoding="utf-8")
            data = tomllib.loads(text)
            released = [item["version"] for item in data["milestone"] if item["status"] == "released"]
            current = data["current_release"]
            self.assertEqual(current, released[-1])
            self.assertGreaterEqual(len(released), 2)
            previous = released[-2]
            text = text.replace(
                f'current_release = "{current}"',
                f'current_release = "{previous}"',
                1,
            )
            contract.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("current_release must equal", result.stderr)

    def test_document_heading_cannot_drift_from_machine_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            roadmap = root / "docs/roadmap.md"
            text = roadmap.read_text(encoding="utf-8").replace(
                "## v0.3.0 — policy, authorization, approval, and plan review",
                "## v0.3.0 — generic execution",
                1,
            )
            roadmap.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("canonical roadmap missing exact heading", result.stderr)

    def test_supported_mutation_cannot_move_before_complete_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/roadmap.toml"
            text = contract.read_text(encoding="utf-8")
            text = self._mutate_milestone_field(
                text,
                "v0.3.0",
                'managed_mutation_support = "none"',
                'managed_mutation_support = "narrow-experimental"',
            )
            contract.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("architectural gate changed", result.stderr)
            self.assertIn("supported managed mutation requires complete lifecycle proof", result.stderr)

    def test_v05_executor_qualification_cannot_self_promote_to_supported_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/roadmap.toml"
            text = contract.read_text(encoding="utf-8")
            text = self._mutate_milestone_field(
                text,
                "v0.5.0",
                'managed_mutation_support = "none"',
                'managed_mutation_support = "narrow-experimental"',
            )
            contract.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("architectural gate changed", result.stderr)
            self.assertIn("supported managed mutation requires complete lifecycle proof", result.stderr)

    def test_product_stability_cannot_be_promoted_by_roadmap_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/roadmap.toml"
            text = contract.read_text(encoding="utf-8").replace(
                'product_stability = "experimental"',
                'product_stability = "stable"',
                1,
            )
            contract.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("product_stability must describe the current product as experimental", result.stderr)

    def test_machine_contract_cannot_redefine_canonical_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/roadmap.toml"
            text = contract.read_text(encoding="utf-8").replace(
                "request/intent → observe → plan → validate → authorize → prepare → execute → verify → commit → audit → reconcile",
                "request/intent → plan → execute",
                1,
            )
            contract.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("canonical_lifecycle changed", result.stderr)

    def test_canonical_eleven_stage_lifecycle_cannot_silently_drift_in_docs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            roadmap = root / "docs/roadmap.md"
            text = roadmap.read_text(encoding="utf-8").replace(
                "request/intent → observe → plan → validate → authorize → prepare → execute → verify → commit → audit → reconcile",
                "request/intent → plan → execute",
                1,
            )
            roadmap.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("canonical roadmap missing governance marker", result.stderr)

    def test_vm_management_cannot_be_confused_with_vm_test_infrastructure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            domains = root / "docs/system-domains.md"
            text = domains.read_text(encoding="utf-8").replace(
                "test infrastructure, not a product virtualization capability",
                "supported VM product capability",
                1,
            )
            domains.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("system domain map missing virtualization boundary marker", result.stderr)

    def test_development_plan_cannot_promote_v05_executor_to_product_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            development = root / "docs/development-plan.md"
            text = development.read_text(encoding="utf-8").replace(
                "**Phase 5 remains qualification-only:**",
                "**Phase 5 supports public mutation:**",
                1,
            )
            development.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("development plan missing roadmap alignment marker", result.stderr)

    def test_v010_remains_explicitly_experimental(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/roadmap.toml"
            text = contract.read_text(encoding="utf-8")
            text = self._mutate_milestone_field(
                text,
                "v0.10.0",
                'claim_class = "Experimental"',
                'claim_class = "Stable"',
            )
            contract.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("v0.10.0 must remain the explicitly Experimental", result.stderr)

    def test_v1_is_reserved_for_stable_supported_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/roadmap.toml"
            text = contract.read_text(encoding="utf-8")
            text = self._mutate_milestone_field(
                text,
                "v1.0.0",
                'claim_class = "Stable"',
                'claim_class = "Experimental"',
            )
            contract.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("v1.0.0 is reserved for the first Stable supported end-user contract", result.stderr)

    def test_versioning_policy_cannot_silently_redefine_v1_as_experimental(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            policy = root / "docs/versioning-and-release-policy.md"
            text = policy.read_text(encoding="utf-8").replace(
                "`v1.0.0` is the first stable end-user contract.",
                "`v1.0.0` is an experimental end-user milestone.",
                1,
            )
            policy.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("versioning policy missing Stable v1 invariant", result.stderr)

    def test_machine_class_set_cannot_silently_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/roadmap.toml"
            text = contract.read_text(encoding="utf-8").replace(
                'target_machine_classes = ["workstation", "server", "edge"]',
                'target_machine_classes = ["workstation", "server", "fleet"]',
                1,
            )
            contract.write_text(text, encoding="utf-8")

            result = self._run_machine_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("target_machine_classes must remain exactly workstation, server, edge", result.stderr)
            self.assertIn("fleet/enterprise must not be encoded as a local machine class", result.stderr)

    def test_fleet_must_remain_optional_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/roadmap.toml"
            text = contract.read_text(encoding="utf-8").replace(
                'fleet_model = "optional-overlay"',
                'fleet_model = "central-authority"',
                1,
            )
            contract.write_text(text, encoding="utf-8")

            result = self._run_machine_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("fleet_model must remain optional-overlay", result.stderr)

    def test_machine_classes_cannot_become_second_domain_maturity_ladder(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            domains = root / "docs/system-domains.md"
            text = domains.read_text(encoding="utf-8").replace(
                "Do not create a second D-like maturity ladder for workstation/server/edge.",
                "Workstation/server/edge use a second maturity ladder.",
                1,
            )
            domains.write_text(text, encoding="utf-8")

            result = self._run_machine_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("system domain map missing machine-class invariant", result.stderr)

    def test_machine_profile_document_cannot_turn_developer_into_fourth_class(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            profiles = root / "docs/machine-profiles.md"
            text = profiles.read_text(encoding="utf-8").replace(
                "`developer machine` is not a fourth class",
                "`developer machine` is a fourth class",
                1,
            )
            profiles.write_text(text, encoding="utf-8")

            result = self._run_machine_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("machine profile document missing machine-class invariant", result.stderr)

    def test_current_release_cannot_claim_machine_profiles_without_platform_support(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            matrix = root / "hardware/support-matrix.json"
            payload = json.loads(matrix.read_text(encoding="utf-8"))
            payload["machine_classes"]["workstation"]["release_qualified_profiles"] = [
                "workstation/example"
            ]
            matrix.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

            result = self._run_machine_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("current release has platform_support=none", result.stderr)

    def test_current_release_cannot_claim_qualification_environment_without_platform_support(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            matrix = root / "hardware/support-matrix.json"
            payload = json.loads(matrix.read_text(encoding="utf-8"))
            payload["qualification_environments"]["release_qualified"] = [
                "qualification/example"
            ]
            matrix.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

            result = self._run_machine_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("qualification_environments.release_qualified must remain empty", result.stderr)

    def test_qualification_environment_cannot_masquerade_as_platform_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            matrix = root / "hardware/support-matrix.json"
            payload = json.loads(matrix.read_text(encoding="utf-8"))
            payload["machine_classes"]["server"]["release_qualified_profiles"] = [
                "qualification/example"
            ]
            matrix.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

            result = self._run_machine_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("must not be encoded as a PlatformProfile", result.stderr)

    def test_hardware_matrix_cannot_encode_fleet_as_machine_class(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            matrix = root / "hardware/support-matrix.json"
            payload = json.loads(matrix.read_text(encoding="utf-8"))
            payload["machine_classes"]["fleet"] = {"release_qualified_profiles": []}
            matrix.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

            result = self._run_machine_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("hardware support matrix machine_classes must remain exactly", result.stderr)
            self.assertIn("fleet must not appear as a hardware support machine class", result.stderr)


if __name__ == "__main__":
    unittest.main()
