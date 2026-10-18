from __future__ import annotations

from pathlib import Path
import re
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "qualification/README.md"
LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
VERSION = re.compile(r"(?m)^\| (v0\.\d+) \|")
DOSSIER = re.compile(r"^v0\.\d+\.0\.md$")
MILESTONE_GATE = re.compile(r"^(v0\d|vm-acceptance|control1-plan-preview)")


def missing_execution_lane_links(root: Path, links: set[str]) -> dict[str, set[str]]:
    indexed: set[str] = set()
    for link in links:
        path = (root / "qualification" / link).resolve()
        if path.is_relative_to(root):
            indexed.add(path.relative_to(root).as_posix())

    envelopes = tomllib.loads(
        (root / "contracts/qualification-execution-envelopes.toml").read_text(
            encoding="utf-8"
        )
    )
    missing: dict[str, set[str]] = {}
    for lane in envelopes["lane"]:
        if not lane["id"].startswith(("v09", "v010")):
            continue
        required: set[str] = set()
        for field in ("workflow", "entrypoint"):
            path = lane.get(field)
            if isinstance(path, str) and path:
                required.add(path)
        absent = required - indexed if required else {"<no workflow or entrypoint>"}
        if absent:
            missing[lane["id"]] = absent
    return missing


class QualificationIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.index = INDEX.read_text(encoding="utf-8")
        cls.links = set(LINK.findall(cls.index))

    def test_all_index_links_resolve_inside_repository(self) -> None:
        for link in self.links:
            with self.subTest(link=link):
                self.assertNotIn("#", link)
                self.assertFalse(link.startswith("/"))
                path = (INDEX.parent / link).resolve()
                self.assertTrue(path.is_relative_to(ROOT), link)
                self.assertTrue(path.exists(), link)

    def test_each_exact_version_dossier_is_indexed_once(self) -> None:
        dossiers = {
            path.name.removesuffix(".0.md")
            for path in (ROOT / "docs/qualification").iterdir()
            if DOSSIER.fullmatch(path.name)
        }
        indexed = VERSION.findall(self.index)
        self.assertEqual(set(indexed), dossiers)
        self.assertEqual(len(indexed), len(set(indexed)))
        for version in dossiers:
            with self.subTest(version=version):
                self.assertIn(f"../docs/qualification/{version}.0.md", self.links)

    def test_milestone_gate_workflows_are_all_discoverable(self) -> None:
        matrix = tomllib.loads(
            (ROOT / "contracts/qualification-gate-matrix.toml").read_text(
                encoding="utf-8"
            )
        )
        for gate in matrix["gate"]:
            if MILESTONE_GATE.match(gate["id"]):
                workflow = "../" + gate["workflow"]
                with self.subTest(gate=gate["id"]):
                    self.assertIn(workflow, self.links)

    def test_execution_envelope_workflows_and_entrypoints_are_indexed(self) -> None:
        self.assertEqual(missing_execution_lane_links(ROOT, self.links), {})

    def test_omitted_physical_runner_is_detected(self) -> None:
        envelopes = tomllib.loads(
            (ROOT / "contracts/qualification-execution-envelopes.toml").read_text(
                encoding="utf-8"
            )
        )
        hardware = next(
            lane
            for lane in envelopes["lane"]
            if lane["id"] == "v010-maintained-hardware"
        )
        runner = hardware["entrypoint"]
        indexed_without_runner = {
            link
            for link in self.links
            if (INDEX.parent / link).resolve() != ROOT / runner
        }
        self.assertEqual(
            missing_execution_lane_links(ROOT, indexed_without_runner),
            {"v010-maintained-hardware": {runner}},
        )

    def test_machine_qualification_directories_are_indexed(self) -> None:
        for directory in (ROOT / "qualification").glob("v*"):
            if directory.is_dir():
                with self.subTest(directory=directory.name):
                    self.assertIn(f"]({directory.name}/)", self.index)


if __name__ == "__main__":
    unittest.main()
