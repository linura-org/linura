from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]

_STABLE_XML = """<node>
  <interface name=\"org.example.Control1\">
    <annotation name=\"org.linura.ContractId\" value=\"dbus.org.example.Control1\"/>
    <annotation name=\"org.linura.ContractVersion\" value=\"1\"/>
    <annotation name=\"org.linura.Stability\" value=\"stable\"/>
    <method name=\"Ping\">
      <arg name=\"value\" type=\"s\" direction=\"out\"/>
    </method>
  </interface>
</node>
"""


class ContractStabilityTests(unittest.TestCase):
    def _run_checker(
        self, root: Path, baseline: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(ROOT / "tools/check_contract_stability.py"),
            "--root",
            str(root),
        ]
        if baseline is not None:
            command.extend(("--baseline-root", str(baseline)))
        return subprocess.run(command, capture_output=True, text=True, check=False)

    def _write_fixture(self, root: Path, *, stability: str, xml: str) -> None:
        (root / "contracts").mkdir(parents=True)
        (root / "interfaces/dbus").mkdir(parents=True)
        (root / "schemas").mkdir(parents=True)
        (root / "docs").mkdir(parents=True)
        stable_metadata = (
            'since = "v1.0.0"\ncompatibility = "major-version-overlap"\n'
            if stability == "stable"
            else ""
        )
        (root / "contracts/stability.toml").write_text(
            "schema_version = 1\n"
            f'product_stability = "{stability}"\n'
            'default_contract_stability = "experimental"\n'
            'policy_document = "docs/api-versioning.md"\n\n'
            "[[contract]]\n"
            'id = "dbus.org.example.Control1"\n'
            'kind = "dbus-interface"\n'
            'path = "interfaces/dbus/org.example.Control1.xml"\n'
            'version = "1"\n'
            f'stability = "{stability}"\n'
            f"{stable_metadata}",
            encoding="utf-8",
        )
        (root / "interfaces/dbus/org.example.Control1.xml").write_text(
            xml, encoding="utf-8"
        )
        (root / "docs/api-versioning.md").write_text(
            "contract version contract stability Experimental Preview Stable "
            "Stability is never inferred Durable state is different\n",
            encoding="utf-8",
        )

    def test_repository_contract_registry_is_valid(self) -> None:
        result = self._run_checker(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ci_fetches_history_for_stable_contract_comparison(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("fetch-depth: 0", workflow)

    def test_version_one_does_not_imply_stable(self) -> None:
        registry = tomllib.loads(
            (ROOT / "contracts/stability.toml").read_text(encoding="utf-8")
        )
        by_path = {entry["path"]: entry for entry in registry["contract"]}
        control = by_path["interfaces/dbus/org.linura.Control1.xml"]
        self.assertEqual(control["version"], "1")
        self.assertEqual(control["stability"], "experimental")
        self.assertEqual(registry["product_stability"], "experimental")
        for schema in (ROOT / "schemas").glob("*.schema.json"):
            data = json.loads(schema.read_text(encoding="utf-8"))
            self.assertEqual(data["x-linura-stability"], "experimental")

    def test_stable_contract_cannot_be_downgraded(self) -> None:
        with (
            tempfile.TemporaryDirectory() as current_dir,
            tempfile.TemporaryDirectory() as baseline_dir,
        ):
            current = Path(current_dir)
            baseline = Path(baseline_dir)
            self._write_fixture(baseline, stability="stable", xml=_STABLE_XML)
            experimental_xml = _STABLE_XML.replace(
                'value="stable"', 'value="experimental"'
            )
            self._write_fixture(current, stability="experimental", xml=experimental_xml)

            result = self._run_checker(current, baseline)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("stability downgrade is forbidden", result.stderr)

    def test_stable_contract_cannot_be_removed_from_registry(self) -> None:
        with (
            tempfile.TemporaryDirectory() as current_dir,
            tempfile.TemporaryDirectory() as baseline_dir,
        ):
            current = Path(current_dir)
            baseline = Path(baseline_dir)
            self._write_fixture(baseline, stability="stable", xml=_STABLE_XML)
            self._write_fixture(current, stability="stable", xml=_STABLE_XML)
            (current / "contracts/stability.toml").write_text(
                "schema_version = 1\n"
                'product_stability = "experimental"\n'
                'default_contract_stability = "experimental"\n'
                'policy_document = "docs/api-versioning.md"\n',
                encoding="utf-8",
            )

            result = self._run_checker(current, baseline)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Stable contract removed from registry", result.stderr)

    def test_stable_dbus_contract_allows_additive_members(self) -> None:
        with (
            tempfile.TemporaryDirectory() as current_dir,
            tempfile.TemporaryDirectory() as baseline_dir,
        ):
            current = Path(current_dir)
            baseline = Path(baseline_dir)
            self._write_fixture(baseline, stability="stable", xml=_STABLE_XML)
            additive = _STABLE_XML.replace(
                "  </interface>",
                '    <method name="Pong"><arg name="value" type="s" direction="out"/></method>\n'
                "  </interface>",
            )
            self._write_fixture(current, stability="stable", xml=additive)

            result = self._run_checker(current, baseline)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_stable_dbus_contract_rejects_same_generation_breakage(self) -> None:
        with (
            tempfile.TemporaryDirectory() as current_dir,
            tempfile.TemporaryDirectory() as baseline_dir,
        ):
            current = Path(current_dir)
            baseline = Path(baseline_dir)
            self._write_fixture(baseline, stability="stable", xml=_STABLE_XML)
            breaking = _STABLE_XML.replace(
                '    <method name="Ping">\n      <arg name="value" type="s" direction="out"/>\n    </method>\n',
                "",
            )
            self._write_fixture(current, stability="stable", xml=breaking)

            result = self._run_checker(current, baseline)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("changed incompatibly within generation 1", result.stderr)


if __name__ == "__main__":
    unittest.main()
