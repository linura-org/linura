from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ToolingTests(unittest.TestCase):
    def run_tool(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=False)

    def test_asset_validation(self) -> None:
        result = self.run_tool("python3", "scripts/validate_assets.py")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_acceptance_scenarios_are_discoverable(self) -> None:
        result = self.run_tool("python3", "tools/acceptance.py", "list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("security-baseline", result.stdout)
        self.assertIn("recovery-native-path", result.stdout)
        self.assertIn("authoritative-observation", result.stdout)
        self.assertIn("control1-plan-preview", result.stdout)

    def test_acceptance_scenario_commands_are_valid_bash(self) -> None:
        scenario_ids: set[str] = set()
        for path in sorted((ROOT / "tests/acceptance").glob("*.json")):
            scenario = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(scenario.get("schema_version"), 1, path)
            scenario_id = scenario.get("id")
            self.assertIsInstance(scenario_id, str, path)
            assert isinstance(scenario_id, str)
            self.assertTrue(scenario_id, path)
            self.assertNotIn(scenario_id, scenario_ids, f"duplicate scenario id: {scenario_id}")
            scenario_ids.add(scenario_id)

            steps = scenario.get("steps")
            self.assertIsInstance(steps, list, path)
            assert isinstance(steps, list)
            self.assertTrue(steps, path)
            step_names: set[str] = set()
            for step in steps:
                self.assertIsInstance(step, dict, path)
                assert isinstance(step, dict)
                self.assertEqual(set(step), {"name", "command"}, path)
                name = step.get("name")
                command = step.get("command")
                self.assertIsInstance(name, str, path)
                self.assertIsInstance(command, str, path)
                assert isinstance(name, str)
                assert isinstance(command, str)
                self.assertTrue(name, path)
                self.assertTrue(command, path)
                self.assertNotIn(name, step_names, f"duplicate step name in {scenario_id}: {name}")
                step_names.add(name)

                result = self.run_tool("bash", "-n", "-c", command)
                self.assertEqual(
                    result.returncode,
                    0,
                    f"invalid bash in {path.name}:{name}: {result.stderr}",
                )

    def test_vm_plan_is_available_without_qemu(self) -> None:
        result = self.run_tool("python3", "tools/vm.py", "plan", "--image", "/tmp/linura.qcow2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("qemu-system-x86_64", result.stdout)
        self.assertIn("linura.qcow2", result.stdout)

    def test_vm_plan_supports_read_only_cloud_init_seed(self) -> None:
        result = self.run_tool(
            "python3",
            "tools/vm.py",
            "plan",
            "--image",
            "/tmp/linura.qcow2",
            "--seed",
            "/tmp/linura-seed.img",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("linura-seed.img", result.stdout)
        self.assertIn("readonly=on", result.stdout)
        self.assertIn("-snapshot", result.stdout)

    def test_vm_plan_can_force_tcg_without_kvm(self) -> None:
        result = self.run_tool(
            "python3",
            "tools/vm.py",
            "plan",
            "--image",
            "/tmp/linura.qcow2",
            "--accel",
            "tcg",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("q35,accel=tcg", result.stdout)
        self.assertIn("-cpu max", result.stdout)

    def test_vm_acceptance_uses_pinned_released_base_image(self) -> None:
        workflow = (ROOT / ".github/workflows/vm-acceptance.yml").read_text(encoding="utf-8")
        url_match = re.search(r"^\s*BASE_IMAGE_URL:\s*(\S+)\s*$", workflow, re.MULTILINE)
        digest_match = re.search(r"^\s*BASE_IMAGE_SHA256:\s*([0-9a-f]+)\s*$", workflow, re.MULTILINE)
        self.assertIsNotNone(url_match)
        self.assertIsNotNone(digest_match)
        assert url_match is not None
        assert digest_match is not None
        self.assertRegex(
            url_match.group(1),
            r"^https://cloud-images\.ubuntu\.com/releases/noble/release-[0-9]{8}/ubuntu-24\.04-server-cloudimg-amd64\.img$",
        )
        self.assertEqual(len(digest_match.group(1)), 64)
        self.assertNotIn("/current/", url_match.group(1))
        self.assertIn("sha256sum --check --strict", workflow)
        self.assertIn("cloud-localds", workflow)
        self.assertIn("cargo build --release --locked -p linurad -p linuractl", workflow)
        self.assertIn("VM-ACCEPTANCE-EVIDENCE.json", workflow)

    def test_vm_acceptance_artifacts_are_scenario_scoped(self) -> None:
        workflow = (ROOT / ".github/workflows/vm-acceptance.yml").read_text(encoding="utf-8")
        self.assertIn(
            "name: linura-vm-acceptance-${{ inputs.scenario || 'authoritative-observation' }}-${{ github.event.pull_request.head.sha || github.sha }}",
            workflow,
        )
        self.assertNotIn(
            "name: linura-vm-acceptance-${{ github.event.pull_request.head.sha || github.sha }}",
            workflow,
        )
        self.assertIn("name: exact-source disposable VM acceptance", workflow)
        self.assertIn("name: Run repository acceptance scenario", workflow)

    def test_control1_plan_preview_uses_reusable_exact_source_vm(self) -> None:
        workflow = (ROOT / ".github/workflows/control1-plan-preview-vm.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("uses: ./.github/workflows/vm-acceptance.yml", workflow)
        self.assertIn("scenario: control1-plan-preview", workflow)
        self.assertIn('"tests/acceptance/008-control1-plan-preview.json"', workflow)

    def test_hosted_vm_acceptance_is_tcg_and_fail_fast(self) -> None:
        workflow = (ROOT / ".github/workflows/vm-acceptance.yml").read_text(encoding="utf-8")
        self.assertRegex(workflow, r"(?m)^\s*VM_ACCELERATION:\s*tcg\s*$")
        self.assertIn('--accel "$VM_ACCELERATION"', workflow)
        self.assertIn('kill -0 "$VM_PID"', workflow)
        self.assertIn('"acceleration": os.environ["VM_ACCELERATION"]', workflow)

    def test_trusted_release_proof_requires_all_mandatory_vm_qualification(self) -> None:
        workflow = (ROOT / ".github/workflows/trusted-release-proof.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count("uses: ./.github/workflows/vm-acceptance.yml"), 2)
        self.assertIn("observation-acceptance:", workflow)
        self.assertIn("plan-preview-acceptance:", workflow)
        self.assertIn("scenario: authoritative-observation", workflow)
        self.assertIn("scenario: control1-plan-preview", workflow)
        self.assertIn("durability-qualification:", workflow)
        self.assertIn("uses: ./.github/workflows/v04-durability-vm.yml", workflow)
        self.assertIn("enospc-qualification:", workflow)
        self.assertIn("uses: ./.github/workflows/v04-enospc-recovery-vm.yml", workflow)
        self.assertIn("executor-verifier-qualification:", workflow)
        self.assertIn("uses: ./.github/workflows/v05-executor-verifier-vm.yml", workflow)
        self.assertIn(
            "needs: [validate, observation-acceptance, plan-preview-acceptance, durability-qualification, enospc-qualification, executor-verifier-qualification]",
            workflow,
        )
        self.assertIn(
            "needs: [validate, observation-acceptance, plan-preview-acceptance, durability-qualification, enospc-qualification, executor-verifier-qualification, build]",
            workflow,
        )
        self.assertIn("needs.observation-acceptance.result == 'success'", workflow)
        self.assertIn("needs.plan-preview-acceptance.result == 'success'", workflow)
        self.assertIn("needs.durability-qualification.result == 'success'", workflow)
        self.assertIn("needs.enospc-qualification.result == 'success'", workflow)
        self.assertIn("needs.executor-verifier-qualification.result == 'success'", workflow)

    def test_image_plan_is_available_without_mkarchiso(self) -> None:
        result = self.run_tool("python3", "tools/image.py", "plan")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mkarchiso", result.stdout)

    def test_release_manifest_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asset = root / "linurad"
            asset.write_bytes(b"linura")
            digest = hashlib.sha256(asset.read_bytes()).hexdigest()
            (root / "SHA256SUMS").write_text(f"{digest}  linurad\n", encoding="utf-8")
            result = self.run_tool("python3", "tools/release_verify.py", str(root))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_release_manifest_rejects_unchecksummed_payload_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asset = root / "linurad"
            asset.write_bytes(b"linura")
            (root / "untracked").write_bytes(b"unexpected")
            digest = hashlib.sha256(asset.read_bytes()).hexdigest()
            (root / "SHA256SUMS").write_text(f"{digest}  linurad\n", encoding="utf-8")
            result = self.run_tool("python3", "tools/release_verify.py", str(root))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("payload assets missing from checksum manifest", result.stderr)

    def test_release_payload_rejects_checksummed_undeclared_component_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            contract = root / "components.toml"
            contract.write_text(
                "schema_version = 1\n\n"
                "[[component]]\n"
                'id = "linurad"\n'
                'release_artifact = true\n'
                'binary = "linurad"\n',
                encoding="utf-8",
            )
            expected_files = {
                "linurad": b"binary",
                "BUILD-ENVIRONMENT.json": b"{}\n",
                "RELEASE-EVIDENCE.json": b"{}\n",
                "RELEASE_NOTES.md": b"notes\n",
                "RELEASE_TAG": b"v0.0.0\n",
                "SOURCE_SHA": b"0" * 40 + b"\n",
                "linura.spdx.json": b"{}\n",
                "surprise-binary": b"unexpected",
            }
            for name, content in expected_files.items():
                (root / name).write_bytes(content)
            manifest_lines = [
                f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}"
                for name in sorted(expected_files)
            ]
            (root / "SHA256SUMS").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")

            result = self.run_tool(
                "python3",
                "tools/release_verify.py",
                str(root),
                "--component-contract",
                str(contract),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("payload contains undeclared component/artifact files", result.stderr)
            self.assertIn("surprise-binary", result.stderr)


if __name__ == "__main__":
    unittest.main()
