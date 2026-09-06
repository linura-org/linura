from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("check_adrs", ROOT / "tools/check_adrs.py")
assert SPEC is not None and SPEC.loader is not None
check_adrs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_adrs)


def write_adr(root: Path, filename: str, heading_number: str, status: str = "Accepted") -> None:
    adr_dir = root / "docs/adr"
    adr_dir.mkdir(parents=True, exist_ok=True)
    (adr_dir / filename).write_text(
        f"# ADR {heading_number}: Example decision\n\n- Status: {status}\n\n## Decision\n\nExample.\n",
        encoding="utf-8",
    )


def write_index(root: Path, entries: list[tuple[str, str]]) -> None:
    adr_dir = root / "docs/adr"
    adr_dir.mkdir(parents=True, exist_ok=True)
    lines = ["# Architecture Decision Records", "", "## ADR ledger", ""]
    lines.extend(f"- [{number} — Example]({path})" for number, path in entries)
    (adr_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


class AdrGovernanceTests(unittest.TestCase):
    def test_repository_ledger_passes(self) -> None:
        self.assertEqual(check_adrs.validate(ROOT), [])

    def test_valid_ledger_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_adr(root, "0001-example.md", "0001")
            write_adr(root, "0002-second.md", "0002", "Proposed")
            write_index(root, [("0001", "0001-example.md"), ("0002", "0002-second.md")])
            self.assertEqual(check_adrs.validate(root), [])

    def test_duplicate_identifier_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_adr(root, "0001-example.md", "0001")
            write_adr(root, "0001-second.md", "0001")
            write_index(root, [("0001", "0001-example.md")])
            failures = check_adrs.validate(root)
            self.assertTrue(any("duplicate ADR identifier 0001" in failure for failure in failures))

    def test_unindexed_record_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_adr(root, "0001-example.md", "0001")
            write_adr(root, "0002-second.md", "0002")
            write_index(root, [("0001", "0001-example.md")])
            failures = check_adrs.validate(root)
            self.assertTrue(any("ADR records missing from index" in failure for failure in failures))

    def test_heading_must_match_filename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_adr(root, "0001-example.md", "0002")
            write_index(root, [("0001", "0001-example.md")])
            failures = check_adrs.validate(root)
            self.assertTrue(any("heading/filename mismatch" in failure for failure in failures))

    def test_invalid_status_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_adr(root, "0001-example.md", "0001", "Final")
            write_index(root, [("0001", "0001-example.md")])
            failures = check_adrs.validate(root)
            self.assertTrue(any("invalid ADR status" in failure for failure in failures))

    def test_superseded_record_requires_forward_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_adr(root, "0001-example.md", "0001", "Superseded")
            write_adr(root, "0002-second.md", "0002")
            write_index(root, [("0001", "0001-example.md"), ("0002", "0002-second.md")])
            failures = check_adrs.validate(root)
            self.assertTrue(any("must declare Superseded by" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
