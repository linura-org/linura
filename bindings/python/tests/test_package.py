from __future__ import annotations

from pathlib import Path
import sys
import tomllib
import unittest
from unittest import mock

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src"
sys.path.insert(0, str(SOURCE_ROOT))

import linura  # noqa: E402


class LinuraPackageTests(unittest.TestCase):
    def test_metadata_matches_canonical_project(self) -> None:
        self.assertEqual(linura.NAME, "Linura")
        self.assertEqual(linura.HOMEPAGE, "https://linura.org")
        self.assertEqual(linura.REPOSITORY, "https://github.com/linura-org/linura")

    def test_control1_identifiers_match_public_contract(self) -> None:
        self.assertEqual(linura.CONTROL1_SERVICE, "org.linura.Control1")
        self.assertEqual(linura.CONTROL1_OBJECT_PATH, "/org/linura/Control1")
        self.assertEqual(linura.CONTROL1_INTERFACE, "org.linura.Control1")
        self.assertEqual(linura.CONTROL1_CONTRACT_VERSION, 1)
        self.assertEqual(linura.CONTROL1_STABILITY, "experimental")

    def test_distribution_and_module_versions_match(self) -> None:
        metadata = tomllib.loads(
            (PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["project"]["version"], linura.__version__)

    @mock.patch("linura.shutil.which", return_value="/usr/bin/linuractl")
    def test_find_installation_is_discovery_only(self, which: mock.Mock) -> None:
        installation = linura.find_installation(path="/usr/bin")
        self.assertEqual(
            installation,
            linura.Installation(Path("/usr/bin/linuractl")),
        )
        which.assert_called_once_with("linuractl", path="/usr/bin")

    @mock.patch("linura.shutil.which", return_value=None)
    def test_require_installation_fails_explicitly(self, _: mock.Mock) -> None:
        with self.assertRaisesRegex(linura.LinuraNotInstalledError, "linuractl"):
            linura.require_installation()


if __name__ == "__main__":
    unittest.main()
