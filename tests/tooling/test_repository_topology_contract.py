from __future__ import annotations

from pathlib import Path
import sys
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.check_repository import repository_files  # noqa: E402

TOPOLOGY = ROOT / "contracts" / "repository-topology.toml"


class RepositoryTopologyContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = tomllib.loads(TOPOLOGY.read_text(encoding="utf-8"))
        cls.owned_files = repository_files()

    def test_forbidden_legacy_roots_are_absent(self) -> None:
        for root in self.contract["forbidden_legacy_roots"]:
            self.assertFalse(
                (ROOT / root).exists(),
                f"legacy placeholder root must stay removed: {root}",
            )

    def test_declared_roots_match_repository_owned_roots(self) -> None:
        declared = {entry["path"] for entry in self.contract["roots"]}
        actual = {
            relative.parts[0]
            for path in self.owned_files
            if len((relative := path.relative_to(ROOT)).parts) > 1
        }
        self.assertEqual(declared, actual)

    def test_roots_are_not_readme_only_placeholders(self) -> None:
        by_root: dict[str, list[Path]] = {}
        for path in self.owned_files:
            relative = path.relative_to(ROOT)
            if len(relative.parts) <= 1:
                continue
            by_root.setdefault(relative.parts[0], []).append(path)

        for entry in self.contract["roots"]:
            if entry.get("allow_readme_only", False):
                continue
            payloads = [
                path
                for path in by_root.get(entry["path"], [])
                if path.name.casefold() != "readme.md"
            ]
            self.assertTrue(
                payloads,
                f"{entry['path']} must own a tracked artifact, not only README scaffolding",
            )

    def test_concept_ownership_paths_exist(self) -> None:
        for concept in self.contract["concepts"]:
            for field in ("implementation", "declarative"):
                for relative in concept.get(field, []):
                    self.assertTrue(
                        (ROOT / relative).exists(),
                        f"{concept['name']} {field} path is missing: {relative}",
                    )

    def test_bootstrap_has_no_duplicate_top_level_implementation_root(self) -> None:
        bootstrap = next(
            concept
            for concept in self.contract["concepts"]
            if concept["name"] == "bootstrap"
        )
        self.assertEqual(bootstrap["legacy_roots"], ["bootstrap"])
        self.assertIn("apps/linura-firstboot", bootstrap["implementation"])
        self.assertIn("crates/linura-bootstrap", bootstrap["implementation"])
        self.assertIn("crates/linura-migrations", bootstrap["implementation"])
        self.assertIn("crates/linura-update", bootstrap["implementation"])

    def test_implementation_roots_are_explicit(self) -> None:
        root_by_path = {entry["path"]: entry for entry in self.contract["roots"]}
        for path in self.contract["policy"]["implementation_roots"]:
            self.assertIn(path, root_by_path)
            self.assertIn(
                root_by_path[path]["kind"],
                {"implementation", "tooling"},
                f"{path} must remain an implementation/tooling root",
            )

    def test_hidden_infrastructure_roots_are_explicit(self) -> None:
        root_by_path = {entry["path"]: entry for entry in self.contract["roots"]}
        for path in self.contract["policy"]["infrastructure_roots"]:
            self.assertTrue(path.startswith("."), f"infrastructure root must be hidden: {path}")
            self.assertIn(path, root_by_path)
            self.assertEqual(
                root_by_path[path]["kind"],
                "infrastructure",
                f"{path} must remain an explicit infrastructure root",
            )


if __name__ == "__main__":
    unittest.main()
