from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "tools/check_approval_strength_contract.py"
sys.path.insert(0, str(ROOT))
from tools import check_approval_strength_contract as guard  # noqa: E402


class ApprovalStrengthContractGuardTests(unittest.TestCase):
    def test_production_approval_strength_mutations_are_killed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory)
            env = os.environ.copy()
            for key in (
                "CARGO_TARGET_DIR",
                "CARGO_BUILD_TARGET_DIR",
                "CARGO_BUILD_BUILD_DIR",
            ):
                env[key] = str(external / key)
            result = subprocess.run(
                [sys.executable, str(CHECKER), str(ROOT)],
                capture_output=True,
                text=True,
                check=False,
                env=env,
                timeout=180,
            )
            self.assertEqual(list(external.iterdir()), [])
        self.assertEqual(result.returncode, 0, f"{result.stdout}\n{result.stderr}")
        self.assertIn("approval-strength mutation contract passed", result.stdout)

    def test_mutation_build_locations_override_caller_configuration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mutation cache ") as directory:
            worktree = Path(directory) / 'quoted "worktree" 🐧'
            target = worktree / "target"
            build = target / "build"
            for inherited in ({}, {"CARGO_TARGET_DIR": "/caller/target"}):
                with self.subTest(inherited=inherited):
                    with (
                        mock.patch.dict(os.environ, inherited),
                        mock.patch.object(
                            guard.subprocess,
                            "run",
                            return_value=subprocess.CompletedProcess([], 0, "", ""),
                        ) as run,
                    ):
                        guard._run_contract(worktree)
                    args = run.call_args.args[0]
                    env = run.call_args.kwargs["env"]
                    self.assertIn("--locked", args)
                    self.assertEqual(args[args.index("--target-dir") + 1], str(target))
                    setting = args[args.index("--config") + 1]
                    self.assertEqual(
                        tomllib.loads(setting), {"build": {"build-dir": str(build)}}
                    )
                    self.assertEqual(env["CARGO_TARGET_DIR"], str(target))
                    self.assertEqual(env["CARGO_BUILD_TARGET_DIR"], str(target))
                    self.assertEqual(env["CARGO_BUILD_BUILD_DIR"], str(build))


if __name__ == "__main__":
    unittest.main()
