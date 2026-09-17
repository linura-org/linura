from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
VERSIONED_DOMAIN_STEM = re.compile(
    r"(?:^|[-_.])v(?:\d{2}|\d+\.\d+(?:\.\d+)?)(?:$|[-_.])",
    re.IGNORECASE,
)
LEGACY_MODULE_ALIAS = re.compile(r"\bmod\s+legacy\s*;")


def current_domain_rust_files() -> list[Path]:
    files: list[Path] = []
    for parent in (ROOT / "apps", ROOT / "crates"):
        for path in parent.glob("*/src/**/*.rs"):
            if path.is_file():
                files.append(path)
    return sorted(files)


def current_domain_files() -> list[Path]:
    files = current_domain_rust_files()
    migrations = ROOT / "migrations"
    if migrations.is_dir():
        files.extend(path for path in migrations.rglob("*.json") if path.is_file())
    return sorted(files)


class DomainCodeNamingTests(unittest.TestCase):
    def test_current_domain_code_filenames_are_semantic(self) -> None:
        violations: list[str] = []
        for path in current_domain_files():
            stem = path.stem
            if VERSIONED_DOMAIN_STEM.search(stem):
                violations.append(str(path.relative_to(ROOT)))
        self.assertEqual(
            violations,
            [],
            "current domain-code filenames must describe the domain responsibility, not the milestone that introduced them",
        )

    def test_current_domain_modules_do_not_alias_active_code_as_legacy(self) -> None:
        violations: list[str] = []
        for path in current_domain_rust_files():
            if LEGACY_MODULE_ALIAS.search(path.read_text(encoding="utf-8")):
                violations.append(str(path.relative_to(ROOT)))
        self.assertEqual(
            violations,
            [],
            "active domain code must not be mounted through a misleading legacy module alias",
        )


if __name__ == "__main__":
    unittest.main()
