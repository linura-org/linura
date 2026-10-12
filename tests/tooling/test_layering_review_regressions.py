from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class LayeringReviewRegressionTests(unittest.TestCase):
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
            text = text.replace(
                "[lints]", "[dependencies]\n" + dependency + "\n[lints]", 1
            )
        else:
            text += "\n[dependencies]\n" + dependency
        manifest.write_text(text, encoding="utf-8")

    def test_semantic_crates_block_alternative_dbus_transports(self) -> None:
        for package in ("dbus", "dbus-tokio", "dbus-crossroads"):
            with (
                self.subTest(package=package),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                self._copy_fixture(root)
                manifest = root / "crates/linura-planner/Cargo.toml"
                self._add_dependency(manifest, package, '"1"')

                result = self._run_checker(root)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "linura-planner violates transport-neutral boundary", result.stderr
                )
                self.assertIn(package, result.stderr)

    def test_policy_and_lifecycle_cannot_depend_on_provider_or_control_plane(
        self,
    ) -> None:
        cases = (
            ("linura-policy", "linura-provider-sdk"),
            ("linura-policy", "linura-control"),
            ("linura-lifecycle", "linura-provider-sdk"),
            ("linura-lifecycle", "linura-control"),
        )
        for package, dependency in cases:
            with (
                self.subTest(package=package, dependency=dependency),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                root = Path(temp_dir)
                self._copy_fixture(root)
                manifest = root / f"crates/{package}/Cargo.toml"
                self._add_dependency(
                    manifest, dependency, f'{{ path = "../{dependency}" }}'
                )

                result = self._run_checker(root)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    f"{package} violates inward dependency boundary", result.stderr
                )
                self.assertIn(dependency, result.stderr)


if __name__ == "__main__":
    unittest.main()
