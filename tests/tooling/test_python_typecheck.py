"""Protect the repository's pinned Python basic-mode type-checking contract."""

from __future__ import annotations

import json
from pathlib import Path
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCOPES = [
    "tools",
    "scripts",
    "tests/tooling",
    "bindings/python/src",
    "bindings/python/tests",
    "qualification/v010",
]
VERSION = "1.1.408"
INTEGRITY = "sha512-N61pxaLLCsPcUuPPHMNIrGoZgGBgrbjBX5UqkaT5UV8NVZdL7ExsO6N3ectv1DzAUsLOzdlyqoYtX76u8eF4YA=="


class PythonTypecheckTests(unittest.TestCase):
    def test_scope_diagnostics_and_language_contract(self):
        config = json.loads((ROOT / "pyrightconfig.json").read_text(encoding="utf-8"))
        self.assertEqual(config["include"], SCOPES)
        self.assertEqual(config["extraPaths"], [".", "tools", "bindings/python/src"])
        self.assertEqual(config["pythonVersion"], "3.12")
        self.assertNotIn("executionEnvironments", config)
        package = tomllib.loads(
            (ROOT / "bindings/python/pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(package["project"]["requires-python"], ">=3.12")
        self.assertEqual(config["typeCheckingMode"], "basic")
        self.assertEqual(config["reportMissingImports"], "error")
        self.assertFalse(
            set(config) & {"ignore", "exclude", "strict", "diagnosticSeverityOverrides"}
        )
        self.assertFalse(
            any(
                key.startswith("report") and value in ("none", False)
                for key, value in config.items()
            )
        )

    def test_exact_dependency_and_integrity_are_locked(self):
        directory = ROOT / "tools/python-typecheck"
        package = json.loads((directory / "package.json").read_text(encoding="utf-8"))
        lock = json.loads((directory / "package-lock.json").read_text(encoding="utf-8"))
        self.assertEqual(package["devDependencies"], {"pyright": VERSION})
        self.assertEqual(
            package["scripts"]["check"], "pyright --project ../../pyrightconfig.json"
        )
        self.assertEqual(lock["lockfileVersion"], 3)
        self.assertEqual(lock["packages"][""]["devDependencies"], {"pyright": VERSION})
        installed = lock["packages"]["node_modules/pyright"]
        self.assertEqual(installed["version"], VERSION)
        self.assertEqual(
            installed["resolved"],
            f"https://registry.npmjs.org/pyright/-/pyright-{VERSION}.tgz",
        )
        self.assertEqual(installed["integrity"], INTEGRITY)

    def test_required_canonical_ci_runs_pinned_checker(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertEqual(
            workflow.count("      - name: Verify pinned Python basic-mode typing\n"), 1
        )
        step = workflow.split(
            "      - name: Verify pinned Python basic-mode typing\n", 1
        )[1].split("      - name:", 1)[0]
        self.assertNotIn("        if:", step)
        self.assertIn('typing_root="${RUNNER_TEMP:?}/linura-python-typecheck"', step)
        self.assertIn(
            'cp tools/python-typecheck/package.json tools/python-typecheck/package-lock.json "$typing_root/"',
            step,
        )
        self.assertNotIn("npm ci --prefix tools/python-typecheck", step)
        self.assertNotIn("tools/python-typecheck/node_modules/", step)
        self.assertIn("set -euo pipefail", step)
        self.assertIn(
            'npm ci --prefix "$typing_root" --ignore-scripts --omit=optional --no-audit --no-fund',
            step,
        )
        self.assertIn(
            'node "$typing_root/node_modules/pyright/index.js" --project pyrightconfig.json',
            step,
        )
        self.assertLess(
            workflow.index(
                "      - name: Validate trusted qualification publisher in canonical CI"
            ),
            workflow.index("      - name: Verify pinned Python basic-mode typing"),
        )
        self.assertNotIn("|| true", step)
        self.assertNotIn("continue-on-error", step)


if __name__ == "__main__":
    unittest.main()
