from __future__ import annotations

import unittest

from tools.python_package_version import Pep440VersionError, normalize_pep440, wheel_version


class PythonPackageVersionTests(unittest.TestCase):
    def test_normalizes_pep440_equivalent_spellings(self) -> None:
        cases = {
            "0.1.0-rc.1": "0.1.0rc1",
            "v1.0-alpha": "1.0a0",
            "1.0-beta.2": "1.0b2",
            "1.0-pre3": "1.0rc3",
            "1.0-1": "1.0.post1",
            "1.0_rev_2": "1.0.post2",
            "1.0-dev": "1.0.dev0",
            "01.002+LOCAL-01": "1.2+local.1",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(normalize_pep440(raw), expected)

    def test_wheel_version_preserves_canonical_epoch_and_local_separators(self) -> None:
        self.assertEqual(wheel_version("1!2.0+ABC.1"), "1!2.0+abc.1")
        self.assertEqual(wheel_version("1.0-rc.1"), "1.0rc1")

    def test_invalid_version_is_rejected(self) -> None:
        with self.assertRaises(Pep440VersionError):
            normalize_pep440("release-one")


if __name__ == "__main__":
    unittest.main()
