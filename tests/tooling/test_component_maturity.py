from __future__ import annotations

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ComponentMaturityContractTests(unittest.TestCase):
    def _run_checker(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/check_component_maturity.py"), str(root)],
            capture_output=True,
            text=True,
            check=False,
        )

    def _copy_fixture(self, destination: Path) -> None:
        paths = (
            "Cargo.toml",
            "contracts/components.toml",
            "contracts/roadmap.toml",
            ".github/workflows/reusable-release-build.yml",
            "tools/image.py",
        )
        for rel in paths:
            source = ROOT / rel
            target = destination / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)

        contract = tomllib.loads((ROOT / "contracts/components.toml").read_text(encoding="utf-8"))
        for component in contract["component"]:
            path = destination / component["path"]
            path.mkdir(parents=True, exist_ok=True)
            if component["kind"] == "planned-app":
                (path / "README.md").write_text("planned\n", encoding="utf-8")

    def test_repository_component_maturity_contract_is_valid(self) -> None:
        result = self._run_checker(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_roadmap_scaffold_cannot_be_promoted_to_release_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/components.toml"
            text = contract.read_text(encoding="utf-8")
            pattern = re.compile(
                r'(?ms)^\[\[component\]\]\nid = "linura-firstboot"\n.*?(?=^\[\[component\]\]|\Z)'
            )
            match = pattern.search(text)
            self.assertIsNotNone(match)
            assert match is not None
            block = match.group(0).replace(
                "release_artifact = false\n",
                'release_artifact = true\nbinary = "linura-firstboot"\n',
                1,
            )
            contract.write_text(text[: match.start()] + block + text[match.end() :], encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("roadmap scaffold cannot be a release artifact", result.stderr)

    def test_release_payload_cannot_ship_an_undeclared_future_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            workflow = root / ".github/workflows/reusable-release-build.yml"
            text = workflow.read_text(encoding="utf-8")
            anchor = 'install -m 0755 "$binary_root/linuractl" "$PAYLOAD_DIR/linuractl"\n'
            self.assertIn(anchor, text)
            text = text.replace(
                anchor,
                anchor + '          install -m 0755 "$binary_root/linura-firstboot" "$PAYLOAD_DIR/linura-firstboot"\n',
                1,
            )
            workflow.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("release payload disagrees with component maturity contract", result.stderr)
            self.assertIn("linura-firstboot", result.stderr)

    def test_workspace_member_cannot_exist_without_maturity_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            manifest = root / "Cargo.toml"
            text = manifest.read_text(encoding="utf-8")
            anchor = 'members = [\n'
            self.assertIn(anchor, text)
            text = text.replace(anchor, anchor + '  "crates/unowned-component",\n', 1)
            manifest.write_text(text, encoding="utf-8")
            (root / "crates/unowned-component").mkdir(parents=True)

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("workspace members missing component maturity ownership", result.stderr)
            self.assertIn("crates/unowned-component", result.stderr)

    def test_proposal_only_component_cannot_gain_release_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            contract = root / "contracts/components.toml"
            text = contract.read_text(encoding="utf-8")
            pattern = re.compile(
                r'(?ms)^\[\[component\]\]\nid = "linura-agent-runtime"\n.*?(?=^\[\[component\]\]|\Z)'
            )
            match = pattern.search(text)
            self.assertIsNotNone(match)
            assert match is not None
            block = match.group(0)
            block = block.replace('maturity = "roadmap-scaffold"', 'maturity = "integrated-experimental"', 1)
            block = block.replace('activation_milestone = "v0.8.0"', 'activation_milestone = "v0.6.0"', 1)
            block = block.replace(
                "release_artifact = false\n",
                'release_artifact = true\nbinary = "linura-agent-runtime"\n',
                1,
            )
            contract.write_text(text[: match.start()] + block + text[match.end() :], encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("proposal-only component cannot be a release artifact", result.stderr)


if __name__ == "__main__":
    unittest.main()
