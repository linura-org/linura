from __future__ import annotations

from datetime import date
from pathlib import Path
import re
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RADAR = Path("docs/research/technology-radar.md")
ENTRY_ROOT = Path("docs/research/entries")
ROW = re.compile(
    r"^\| \[([^\]]+)\]\((entries/[a-z0-9-]+\.md)\) "
    r"\| (Watch|Assess|Adopt|Hold) \| ([^|]+) "
    r"\| (\d{4}-\d{2}-\d{2}) \| (\d{4}-\d{2}-\d{2}) \|$"
)
REQUIRED_SECTIONS = (
    "## Summary and motivation",
    "## Evidence and source provenance",
    "## Benefits and architectural fit",
    "## Security and trust boundaries",
    "## Alternatives and costs",
    "## Investigation and acceptance gates",
    "## Reassessment triggers",
    "## Links and decision log",
)


def validate(root: Path) -> list[str]:
    failures: list[str] = []
    radar_path = root / RADAR
    radar = radar_path.read_text(encoding="utf-8")
    lines = radar.splitlines()
    header = "| Technology | State | Review owner | Last assessed | Next review |"
    headers = [index for index, line in enumerate(lines) if line == header]
    rows: list[str] = []
    if len(headers) != 1:
        failures.append("radar must contain exactly one canonical table header")
    else:
        start = headers[0] + 1
        separator = re.compile(r"(?:\|[ \t]*:?-{3,}:?[ \t]*){5}\|")
        if start >= len(lines) or separator.fullmatch(lines[start]) is None:
            failures.append("invalid radar table separator")
        else:
            for line in lines[start + 1:]:
                if not line.strip():
                    break
                rows.append(line)
    found: set[str] = set()
    found_names: set[str] = set()
    if not rows:
        failures.append("radar has no technology entries")
    for line in rows:
        match = ROW.fullmatch(line)
        if match is None:
            failures.append(f"invalid radar row: {line}")
            continue
        name, target, state, owner, assessed, review = match.groups()
        canonical_name = name.strip().casefold()
        if canonical_name in found_names:
            failures.append(f"duplicate technology name: {name}")
        found_names.add(canonical_name)
        if not owner.strip():
            failures.append(f"missing owner: {target}")
        if target in found:
            failures.append(f"duplicate radar record: {target}")
        found.add(target)
        try:
            last_date, next_date = date.fromisoformat(assessed), date.fromisoformat(review)
            interval = (next_date - last_date).days
            if interval <= 0:
                failures.append(f"review must follow assessment: {target}")
            if state in {"Watch", "Assess"} and interval > {"Watch": 90, "Assess": 30}[state]:
                failures.append(f"review interval exceeds {state} cadence: {target}")
        except ValueError:
            failures.append(f"invalid ISO date: {target}")
        record = (radar_path.parent / target)
        if not record.is_file():
            failures.append(f"missing research record: {target}")
            continue
        body = record.read_text(encoding="utf-8")
        if not body.startswith(f"# Technology: {name}\n"):
            failures.append(f"research title mismatch: {target}")
        expected_id = Path(target).stem
        if f"**Record ID:** `{expected_id}`" not in body:
            failures.append(f"research identity mismatch: {target}")
        for heading in REQUIRED_SECTIONS:
            if heading not in body:
                failures.append(f"missing {heading}: {target}")
        if re.search(r"^\*\*(?:Status|State|Classification):\*\*", body, re.MULTILINE):
            failures.append(f"entry duplicates canonical radar state: {target}")
    for entry in sorted((root / ENTRY_ROOT).glob("*.md")):
        target = "entries/" + entry.name
        if target not in found:
            failures.append(f"unindexed research entry: {target}")
    return failures


class TechnologyRadarTests(unittest.TestCase):
    def test_repository_radar_is_consistent(self) -> None:
        self.assertEqual(validate(ROOT), [])

    def test_rejects_invalid_assessment_review_order(self) -> None:
        source = (ROOT / RADAR).read_text(encoding="utf-8")
        self.assertIn("2027-01-08", source)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            dest = root / RADAR
            dest.parent.mkdir(parents=True)
            dest.write_text(source.replace("2027-01-08", "2026-10-10"), encoding="utf-8")
            errors = validate(root)
            self.assertTrue(any("review must follow assessment" in error for error in errors), errors)

    def test_rejects_duplicate_unsupported_or_missing_records(self) -> None:
        source = (ROOT / RADAR).read_text(encoding="utf-8")
        original = next(line for line in source.splitlines() if line.startswith("| ["))
        for change, reason in (
            (source.replace(original, original + "\n" + original, 1),
             "duplicate radar record"),
            (source.replace("| Watch |", "| Unknown |"),
             "invalid radar row"),
            (source.replace("entries/multikernel-linux.md", "entries/absent.md"),
             "missing research record"),
            (source.replace(
                original, original + "\n" + original.replace(
                    "multikernel-linux.md", "multikernel-linux-duplicate.md"), 1),
             "duplicate technology name"),
            (source.replace("2027-01-08", "2027-01-09"),
             "review interval exceeds Watch cadence"),
            (source.replace(
                original,
                original + "\n" +
                "| Multikernel Linux | Watch | Linura maintainers | 2026-10-10 | 2027-01-08 |",
                1),
             "invalid radar row"),
            (source.replace(
                original,
                original + "\n" +
                "Multikernel Linux | Watch | Linura maintainers | 2026-10-10 | 2027-01-08",
                1),
             "invalid radar row"),
            (source.replace(
                original,
                original + "\n" +
                "  | [Invalid](entries/invalid.md) | Watch | Linura maintainers | 2026-10-10 | 2027-01-08 |",
                1),
             "invalid radar row"),
            (source.replace(
                original,
                original + "\n" +
                "|  [Invalid](entries/invalid.md) | Watch | Linura maintainers | 2026-10-10 | 2027-01-08 |",
                1),
             "invalid radar row"),
            (source.replace(
                "| --- | --- | --- | --- | --- |",
                "| --- | --- | --- | --- | invalid |"),
             "invalid radar table separator"),
            (source.replace(
                "| Technology | State | Review owner | Last assessed | Next review |",
                "| Technology | State | Owner | Last assessed | Next review |"),
             "canonical table header"),
        ):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                dest = root / RADAR
                dest.parent.mkdir(parents=True)
                dest.write_text(change, encoding="utf-8")
                errors = validate(root)
                self.assertTrue(any(reason in error for error in errors), errors)
