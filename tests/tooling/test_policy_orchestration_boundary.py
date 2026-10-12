from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PolicyOrchestrationBoundaryTests(unittest.TestCase):
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

    def _run_checker(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/check_layering.py"), str(root)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_only_control_may_consume_policy_domain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            planner = root / "crates/linura-planner/Cargo.toml"
            text = planner.read_text(encoding="utf-8")
            text = text.replace(
                "[dependencies]\n",
                '[dependencies]\nlinura-policy = { path = "../linura-policy" }\n',
                1,
            )
            planner.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "linura-policy must be consumed only by linura-control", result.stderr
            )
            self.assertIn("linura-planner", result.stderr)

    def test_control_policy_dependency_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._copy_fixture(root)
            control = root / "crates/linura-control/Cargo.toml"
            text = control.read_text(encoding="utf-8")
            text = text.replace(
                'linura-policy = { path = "../linura-policy" }\n',
                "",
                1,
            )
            control.write_text(text, encoding="utf-8")

            result = self._run_checker(root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "linura-policy must be consumed only by linura-control", result.stderr
            )
            self.assertIn("found policy consumers: []", result.stderr)


if __name__ == "__main__":
    unittest.main()
