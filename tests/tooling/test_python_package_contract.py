from __future__ import annotations

from pathlib import Path
import sys
import tomllib
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = ROOT / "bindings/python"
sys.path.insert(0, str(PACKAGE_ROOT / "src"))

import linura  # noqa: E402


class PythonPackageContractTests(unittest.TestCase):
    def test_pypi_identity_is_canonical_and_dependency_free(self) -> None:
        metadata = tomllib.loads(
            (PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]
        self.assertEqual(metadata["name"], "linura")
        self.assertEqual(metadata["version"], linura.__version__)
        self.assertEqual(metadata["dependencies"], [])

    def test_build_environment_is_fully_pinned(self) -> None:
        metadata = tomllib.loads(
            (PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            metadata["build-system"]["requires"],
            [
                "hatchling==1.27.0",
                "packaging==24.2",
                "pathspec==0.12.1",
                "pluggy==1.5.0",
                "trove-classifiers==2025.1.15.22",
            ],
        )

    def test_build_requirement_lock_matches_build_contract(self) -> None:
        metadata = tomllib.loads(
            (PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        expected = {"pip==25.0.1", *metadata["build-system"]["requires"]}
        lock = (PACKAGE_ROOT / "build-requirements.lock").read_text(encoding="utf-8")
        locked = {
            line[:-2]
            for line in lock.splitlines()
            if line.endswith(" \\")
        }
        self.assertEqual(locked, expected)
        hashes = [
            line.removeprefix("    --hash=sha256:")
            for line in lock.splitlines()
            if line.startswith("    --hash=sha256:")
        ]
        self.assertEqual(len(hashes), len(expected))
        self.assertEqual(len(set(hashes)), len(hashes))
        self.assertTrue(all(len(digest) == 64 for digest in hashes))
        self.assertTrue(all(set(digest) <= set("0123456789abcdef") for digest in hashes))

    def test_control1_metadata_tracks_checked_contract(self) -> None:
        root = ET.parse(ROOT / "interfaces/dbus/org.linura.Control1.xml").getroot()
        interface = root.find("interface")
        self.assertIsNotNone(interface)
        assert interface is not None

        annotations = {
            item.attrib["name"]: item.attrib["value"]
            for item in interface.findall("annotation")
        }
        self.assertEqual(interface.attrib["name"], linura.CONTROL1_INTERFACE)
        self.assertEqual(
            annotations["org.linura.ContractVersion"],
            str(linura.CONTROL1_CONTRACT_VERSION),
        )
        self.assertEqual(
            annotations["org.linura.Stability"],
            linura.CONTROL1_STABILITY,
        )

        runtime = (ROOT / "crates/linura-dbus/src/lib.rs").read_text(encoding="utf-8")
        self.assertIn(
            f'pub const SERVICE_NAME: &str = "{linura.CONTROL1_SERVICE}";',
            runtime,
        )
        self.assertIn(
            f'pub const OBJECT_PATH: &str = "{linura.CONTROL1_OBJECT_PATH}";',
            runtime,
        )

    def test_initial_surface_remains_non_executing(self) -> None:
        public = set(linura.__all__)
        self.assertNotIn("run", public)
        self.assertNotIn("execute", public)
        self.assertNotIn("apply", public)
        self.assertFalse(any("session" in name.casefold() for name in public))


if __name__ == "__main__":
    unittest.main()
