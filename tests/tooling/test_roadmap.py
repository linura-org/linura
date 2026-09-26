from __future__ import annotations

import hashlib
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
            "contracts/v010-workstation-slices.toml",
            "contracts/v010-workstation-qualification.toml",
            "docs/adr/0033-v010-complete-workstation-product-boundary.md",
            "crates/linura-intent/src/model.rs",
            "crates/linura-sdk/src/lib.rs",
            "docs/roadmap.md",
            "docs/system-domains.md",
            "docs/development-plan.md",
            "docs/versioning-and-release-policy.md",
            "docs/machine-profiles.md",
            "hardware/support-matrix.json",
            "schemas/portable-profile.v1.schema.json",
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

    def _make_no_platform_support_fixture(self, root: Path) -> None:
        contract_path = root / "contracts/roadmap.toml"
        text = contract_path.read_text(encoding="utf-8")
        contract = tomllib.loads(text)
        current = contract["current_release"]
        milestones = {
            milestone["version"]: milestone
            for milestone in contract["milestone"]
            if isinstance(milestone, dict) and isinstance(milestone.get("version"), str)
        }
        current_milestone = milestones[current]
        current_support = current_milestone["platform_support"]
        if current_support != "none":
            text = self._mutate_milestone_field(
                text,
                current,
                f'platform_support = "{current_support}"',
                'platform_support = "none"',
            )
            contract_path.write_text(text, encoding="utf-8")

        matrix = root / "hardware/support-matrix.json"
        payload = json.loads(matrix.read_text(encoding="utf-8"))
        for machine_class in payload["machine_classes"].values():
            machine_class["release_qualified_profiles"] = []
        payload["qualification_environments"]["release_qualified"] = []
        matrix.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

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

    def test_v010_slice_ledger_cannot_silently_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/v010-workstation-slices.toml"
            text = contract.read_text(encoding="utf-8").replace(
                "completed_slice_count = 14",
                "completed_slice_count = 15",
                1,
            )
            contract.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("completed_slice_count does not match", result.stderr)

    def test_v010_slice_scope_cannot_silently_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/v010-workstation-slices.toml"
            text = contract.read_text(encoding="utf-8").replace(
                'title = "lifecycle notifications and OSD"',
                'title = "unrelated trivial feature"',
                1,
            )
            contract.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("S15: slice title/scope drifted", result.stderr)

    def test_v010_release_requires_all_release_slices_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/roadmap.toml"
            text = contract.read_text(encoding="utf-8")
            text = text.replace(
                'current_release = "v0.9.0"',
                'current_release = "v0.10.0"',
                1,
            ).replace(
                'next_release = "v0.10.0"',
                'next_release = "v1.0.0"',
                1,
            )
            text = self._mutate_milestone_field(
                text,
                "v0.10.0",
                'status = "planned"',
                'status = "released"',
            )
            text = self._mutate_milestone_field(
                text,
                "v0.10.0",
                'qualification = "docs/qualification/v0.10.0.md"',
                'qualification = "docs/qualification/v0.10.0.md"\nrelease_contract = "docs/releases/v0.10.0.md"',
            )
            contract.write_text(text, encoding="utf-8")

            release_contract = root / "docs/releases/v0.10.0.md"
            release_contract.parent.mkdir(parents=True, exist_ok=True)
            release_contract.write_text("# v0.10.0 release fixture\n", encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "released v0.10 requires all release-required slices complete",
                result.stderr,
            )
            self.assertIn("released v0.10 must not retain a next_slice", result.stderr)


    def _promote_v010_fixture_to_released(self, root: Path) -> None:
        contract = root / "contracts/roadmap.toml"
        text = contract.read_text(encoding="utf-8")
        text = text.replace(
            'current_release = "v0.9.0"',
            'current_release = "v0.10.0"',
            1,
        ).replace(
            'next_release = "v0.10.0"',
            'next_release = "v1.0.0"',
            1,
        )
        text = self._mutate_milestone_field(
            text,
            "v0.10.0",
            'status = "planned"',
            'status = "released"',
        )
        text = self._mutate_milestone_field(
            text,
            "v0.10.0",
            'qualification = "docs/qualification/v0.10.0.md"',
            'qualification = "docs/qualification/v0.10.0.md"\nrelease_contract = "docs/releases/v0.10.0.md"',
        )
        contract.write_text(text, encoding="utf-8")
        release_contract = root / "docs/releases/v0.10.0.md"
        release_contract.parent.mkdir(parents=True, exist_ok=True)
        release_contract.write_text("# v0.10.0 release fixture\n", encoding="utf-8")

    def _complete_v010_slice_fixture(self, root: Path) -> None:
        contract = root / "contracts/v010-workstation-slices.toml"
        text = contract.read_text(encoding="utf-8")
        text = text.replace("completed_slice_count = 14", "completed_slice_count = 32", 1)
        text = text.replace('next_slice = "S15"', 'next_slice = ""', 1)
        text = text.replace('status = "planned"', 'status = "complete"')
        text = text.replace("evidence_prs = []", "evidence_prs = [999999]")
        contract.write_text(text, encoding="utf-8")

    def test_v010_slice_evidence_rejects_boolean_pr_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/v010-workstation-slices.toml"
            text = contract.read_text(encoding="utf-8").replace(
                "evidence_prs = [144, 145]",
                "evidence_prs = [true]",
                1,
            )
            contract.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("S01: evidence_prs must be positive PR numbers", result.stderr)

    def test_v010_planned_release_candidate_requires_qualification_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._complete_v010_slice_fixture(root)

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("released v0.10 requires frozen immutable Arch substrate", result.stderr)
            self.assertIn(
                "released v0.10 requires substrate.release_qualification_ready=true",
                result.stderr,
            )
            self.assertIn(
                "released v0.10 requires experience.experience_evidence_ready=true",
                result.stderr,
            )

    def test_v010_release_hashes_do_not_replace_semantic_qualification(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._complete_v010_slice_fixture(root)

            package_manifest = root / "qualification/v010/arch-packages.tsv"
            visual_manifest = root / "visual/baselines/manifest.json"
            experience_manifest = root / "qualification/v010/experience-evidence.json"
            package_manifest.parent.mkdir(parents=True, exist_ok=True)
            visual_manifest.parent.mkdir(parents=True, exist_ok=True)
            experience_manifest.parent.mkdir(parents=True, exist_ok=True)
            package_manifest.write_text("not a package manifest\n", encoding="utf-8")
            visual_manifest.write_text("not json\n", encoding="utf-8")
            experience_manifest.write_text("not json\n", encoding="utf-8")

            qualification = root / "contracts/v010-workstation-qualification.toml"
            text = qualification.read_text(encoding="utf-8")
            text = text.replace(
                'state = "source-pinned-package-set-pending"',
                'state = "frozen"',
                1,
            ).replace(
                'package_manifest = ""',
                'package_manifest = "qualification/v010/arch-packages.tsv"',
                1,
            ).replace(
                'package_manifest_sha256 = ""',
                f'package_manifest_sha256 = "{hashlib.sha256(package_manifest.read_bytes()).hexdigest()}"',
                1,
            ).replace(
                "release_qualification_ready = false",
                "release_qualification_ready = true",
                1,
            ).replace(
                "experience_evidence_ready = false",
                "experience_evidence_ready = true",
                1,
            ).replace(
                'visual_baseline_manifest_sha256 = ""',
                f'visual_baseline_manifest_sha256 = "{hashlib.sha256(visual_manifest.read_bytes()).hexdigest()}"',
                1,
            ).replace(
                'experience_evidence_manifest_sha256 = ""',
                f'experience_evidence_manifest_sha256 = "{hashlib.sha256(experience_manifest.read_bytes()).hexdigest()}"',
                1,
            )
            qualification.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "v0.10 semantic qualification: frozen package manifest identity headers do not match",
                result.stderr,
            )
            self.assertIn(
                "v0.10 semantic qualification: invalid v0.10 visual baseline manifest:",
                result.stderr,
            )

    def test_v010_release_requires_qualification_readiness_after_slices_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._promote_v010_fixture_to_released(root)
            self._complete_v010_slice_fixture(root)

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("released v0.10 requires frozen immutable Arch substrate", result.stderr)
            self.assertIn(
                "released v0.10 requires substrate.release_qualification_ready=true",
                result.stderr,
            )
            self.assertIn(
                "released v0.10 requires experience.experience_evidence_ready=true",
                result.stderr,
            )

    def test_v010_release_requires_digest_bound_qualification_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._promote_v010_fixture_to_released(root)
            self._complete_v010_slice_fixture(root)

            qualification = root / "contracts/v010-workstation-qualification.toml"
            text = qualification.read_text(encoding="utf-8")
            text = text.replace(
                'state = "source-pinned-package-set-pending"',
                'state = "frozen"',
                1,
            ).replace(
                'package_manifest = ""',
                'package_manifest = "qualification/v010/arch-packages.tsv"',
                1,
            ).replace(
                'package_manifest_sha256 = ""',
                'package_manifest_sha256 = "' + ("0" * 64) + '"',
                1,
            ).replace(
                "release_qualification_ready = false",
                "release_qualification_ready = true",
                1,
            ).replace(
                "experience_evidence_ready = false",
                "experience_evidence_ready = true",
                1,
            ).replace(
                'visual_baseline_manifest_sha256 = ""',
                'visual_baseline_manifest_sha256 = "' + ("0" * 64) + '"',
                1,
            ).replace(
                'experience_evidence_manifest_sha256 = ""',
                'experience_evidence_manifest_sha256 = "' + ("0" * 64) + '"',
                1,
            )
            qualification.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "released v0.10 qualification artifact missing or unsafe: qualification/v010/arch-packages.tsv",
                result.stderr,
            )
            self.assertIn(
                "released v0.10 qualification artifact missing or unsafe: visual/baselines/manifest.json",
                result.stderr,
            )
            self.assertIn(
                "released v0.10 qualification artifact missing or unsafe: qualification/v010/experience-evidence.json",
                result.stderr,
            )

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

    def test_no_platform_support_cannot_claim_machine_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._make_no_platform_support_fixture(root)
            matrix = root / "hardware/support-matrix.json"
            payload = json.loads(matrix.read_text(encoding="utf-8"))
            payload["machine_classes"]["workstation"]["release_qualified_profiles"] = [
                "workstation/example"
            ]
            matrix.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

            result = self._run_machine_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("current release has platform_support=none", result.stderr)

    def test_no_platform_support_cannot_claim_qualification_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            self._make_no_platform_support_fixture(root)
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
