from __future__ import annotations

import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / "tests/acceptance"
sys.path.insert(0, str(ROOT))
from scripts.validate_assets import ValidationError, validate  # noqa: E402


class AcceptanceReadinessTests(unittest.TestCase):
    def test_executable_entrypoints_preserve_invocation_permissions(self) -> None:
        for path in ("tools/acceptance.py", "scripts/validate_assets.py"):
            with self.subTest(path=path):
                target = ROOT / path
                self.assertTrue(
                    target.read_bytes().startswith(b"#!/usr/bin/env python3\n")
                )
                self.assertTrue(target.stat().st_mode & stat.S_IXUSR)

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/acceptance.py"), *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_machine_discovery_lists_every_scenario_once(self) -> None:
        run = self.run_cli("list", "--json")
        self.assertEqual(run.returncode, 0, run.stderr)
        payload = json.loads(run.stdout)
        self.assertEqual(payload["schema_version"], 1)
        entries = payload["scenarios"]
        self.assertEqual(
            {entry["path"] for entry in entries},
            {path.relative_to(ROOT).as_posix() for path in SCENARIOS.glob("*.json")},
        )
        self.assertEqual(len({item["id"] for item in entries}), len(entries))
        self.assertTrue(
            all(
                item["execution_status"] in ("reserved", "executable")
                for item in entries
            )
        )

    def test_weak_legacy_scenarios_cannot_run_or_issue_evidence(self) -> None:
        for scenario_id in (
            "bootstrap-resume",
            "intent-retirement",
            "update-interruption",
            "recovery-native-path",
        ):
            with self.subTest(scenario=scenario_id):
                with tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / "result.json"
                    run = self.run_cli(
                        "run", scenario_id, "--dry-run", "--result-file", str(output)
                    )
                    self.assertNotEqual(run.returncode, 0)
                    self.assertIn("reserved", run.stderr)
                    self.assertFalse(output.exists())

    def test_reserved_scenario_rejected_even_without_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            run = self.run_cli(
                "run",
                "bootstrap-resume",
                "--result-file",
                str(output),
                "--source-sha",
                "a" * 40,
            )
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("reserved", run.stderr)
            self.assertFalse(output.exists())
            self.assertNotIn("scenario:", run.stdout)

    def test_schema_rejects_inconsistent_reservations(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/acceptance-scenario.v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        reserved = json.loads(
            (SCENARIOS / "001-bootstrap-resume.json").read_text(encoding="utf-8")
        )
        validate(reserved, schema, "reserved")
        candidates = [
            {key: val for key, val in reserved.items() if key != "reservation_reason"},
            {**reserved, "reservation_reason": "   "},
            {**reserved, "execution_status": "executable"},
        ]
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValidationError):
                    validate(candidate, schema, "invalid")

        executable = json.loads(
            (SCENARIOS / "007-authoritative-observation.json").read_text(
                encoding="utf-8"
            )
        )
        validate(executable, schema, "executable")
        with self.assertRaises(ValidationError):
            validate(
                {**executable, "reservation_reason": "not applicable"},
                schema,
                "invalid",
            )

    def test_release_routed_guest_scenarios_stay_executable(self) -> None:
        entries = {}
        for path in SCENARIOS.glob("*.json"):
            entry = json.loads(path.read_text(encoding="utf-8"))
            entries[entry["id"]] = entry
        for scenario_id in (
            "firstboot-offline",
            "authoritative-observation",
            "control1-plan-preview",
        ):
            with self.subTest(scenario=scenario_id):
                self.assertEqual(entries[scenario_id]["execution_status"], "executable")
                self.assertNotIn("reservation_reason", entries[scenario_id])

    def test_dry_run_cannot_write_pass_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            run = self.run_cli(
                "run",
                "authoritative-observation",
                "--dry-run",
                "--result-file",
                str(output),
            )
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("--dry-run cannot produce", run.stderr)
            self.assertFalse(output.exists())

    def test_invalid_source_identity_rejected_before_guest_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            for source_sha in ("missing", "bad-sha", "F" * 40):
                with self.subTest(source_sha=source_sha):
                    args: list[str] = []
                    if source_sha != "missing":
                        args = ["--source-sha", source_sha]
                    run = self.run_cli(
                        "run",
                        "authoritative-observation",
                        "--result-file",
                        str(output),
                        *args,
                    )
                    self.assertNotEqual(run.returncode, 0)
                    self.assertIn("--source-sha", run.stderr)
                    self.assertFalse(output.exists())
                    self.assertNotIn("scenario:", run.stdout)

    def test_executable_dry_run_without_evidence_remains_available(self) -> None:
        run = self.run_cli("run", "authoritative-observation", "--dry-run")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("scenario: authoritative-observation", run.stdout)


if __name__ == "__main__":
    unittest.main()
