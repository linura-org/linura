#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import re
import sys

FILENAME_RE = re.compile(r"^(?P<number>\d{4})-(?P<slug>[a-z0-9][a-z0-9.-]*)\.md$")
HEADING_RE = re.compile(r"^#\s+ADR\s+(?P<number>\d{4})\s*(?:[:—-])\s*\S.+$")
STATUS_RE = re.compile(r"^\s*-?\s*Status:\s*(?P<status>[A-Za-z]+)\s*$", re.MULTILINE | re.IGNORECASE)
INDEX_RE = re.compile(
    r"^\s*-\s+\[(?P<number>\d{4})\s+[—-]\s+[^\]]+\]\((?P<path>[^)]+\.md)\)\s*$",
    re.MULTILINE,
)
SUPERSEDES_RE = re.compile(r"^\s*-?\s*Supersedes:\s*(?P<value>.+?)\s*$", re.MULTILINE | re.IGNORECASE)
SUPERSEDED_BY_RE = re.compile(r"^\s*-?\s*Superseded by:\s*(?P<value>.+?)\s*$", re.MULTILINE | re.IGNORECASE)
ADR_REF_RE = re.compile(r"\b(?P<number>\d{4})\b")
ALLOWED_STATUSES = {"proposed", "accepted", "superseded", "deprecated", "rejected"}


def first_nonempty_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


def parse_refs(value: str) -> set[int]:
    return {int(match.group("number")) for match in ADR_REF_RE.finditer(value)}


def validate(root: Path) -> list[str]:
    failures: list[str] = []
    adr_dir = root / "docs/adr"
    index_path = adr_dir / "README.md"

    if not adr_dir.is_dir():
        return ["missing ADR directory: docs/adr"]
    if not index_path.is_file():
        return ["missing ADR index: docs/adr/README.md"]

    records: list[tuple[int, Path, str, str]] = []
    for path in sorted(adr_dir.glob("*.md")):
        if path.name == "README.md":
            continue
        match = FILENAME_RE.fullmatch(path.name)
        if match is None:
            failures.append(f"invalid ADR filename: {path.relative_to(root)}")
            continue

        number = int(match.group("number"))
        text = path.read_text(encoding="utf-8")
        heading = first_nonempty_line(text)
        heading_match = HEADING_RE.fullmatch(heading)
        if heading_match is None:
            failures.append(f"invalid ADR heading: {path.relative_to(root)} -> {heading!r}")
        elif int(heading_match.group("number")) != number:
            failures.append(
                f"ADR heading/filename mismatch: {path.relative_to(root)} -> {heading_match.group('number')}"
            )

        statuses = STATUS_RE.findall(text)
        if len(statuses) != 1:
            failures.append(
                f"ADR must declare exactly one Status: {path.relative_to(root)} (found {len(statuses)})"
            )
            status = ""
        else:
            status = statuses[0].lower()
            if status not in ALLOWED_STATUSES:
                failures.append(
                    f"invalid ADR status {statuses[0]!r}: {path.relative_to(root)}"
                )

        records.append((number, path, text, status))

    if not records:
        failures.append("no ADR records found")
        return failures

    counts = Counter(number for number, _, _, _ in records)
    for number, count in sorted(counts.items()):
        if count != 1:
            names = [path.name for value, path, _, _ in records if value == number]
            failures.append(f"duplicate ADR identifier {number:04d}: {names}")

    known_numbers = set(counts)
    for number, path, text, status in records:
        supersedes_match = SUPERSEDES_RE.search(text)
        if supersedes_match:
            refs = parse_refs(supersedes_match.group("value"))
            if not refs:
                failures.append(f"ADR Supersedes field has no ADR identifier: {path.relative_to(root)}")
            for ref in refs:
                if ref not in known_numbers:
                    failures.append(f"ADR {number:04d} supersedes missing ADR {ref:04d}")
                elif ref >= number:
                    failures.append(f"ADR {number:04d} must supersede an earlier ADR, not {ref:04d}")

        superseded_by_match = SUPERSEDED_BY_RE.search(text)
        if status == "superseded" and superseded_by_match is None:
            failures.append(f"superseded ADR {number:04d} must declare Superseded by")
        if superseded_by_match:
            refs = parse_refs(superseded_by_match.group("value"))
            if not refs:
                failures.append(f"ADR Superseded by field has no ADR identifier: {path.relative_to(root)}")
            for ref in refs:
                if ref not in known_numbers:
                    failures.append(f"ADR {number:04d} references missing superseding ADR {ref:04d}")
                elif ref <= number:
                    failures.append(f"ADR {number:04d} must be superseded by a later ADR, not {ref:04d}")

    index_text = index_path.read_text(encoding="utf-8")
    entries = list(INDEX_RE.finditer(index_text))
    if not entries:
        failures.append("ADR index contains no ledger entries")
        return failures

    index_numbers = [int(entry.group("number")) for entry in entries]
    index_paths = [entry.group("path") for entry in entries]

    if index_numbers != sorted(index_numbers):
        failures.append("ADR index entries must be ordered by identifier")

    for number, count in sorted(Counter(index_numbers).items()):
        if count != 1:
            failures.append(f"ADR index contains identifier {number:04d} {count} times")
    for path, count in sorted(Counter(index_paths).items()):
        if count != 1:
            failures.append(f"ADR index contains path {path!r} {count} times")

    record_paths = {path.name: number for number, path, _, _ in records}
    for entry in entries:
        number = int(entry.group("number"))
        rel_path = entry.group("path")
        if "/" in rel_path or rel_path.startswith("."):
            failures.append(f"ADR index entry must use a local filename: {rel_path}")
            continue
        expected = record_paths.get(rel_path)
        if expected is None:
            failures.append(f"ADR index references missing record: {rel_path}")
        elif expected != number:
            failures.append(
                f"ADR index number/path mismatch: {number:04d} -> {rel_path} is ADR {expected:04d}"
            )

    missing_from_index = sorted(set(record_paths) - set(index_paths))
    extra_in_index = sorted(set(index_paths) - set(record_paths))
    if missing_from_index:
        failures.append(f"ADR records missing from index: {missing_from_index}")
    if extra_in_index:
        failures.append(f"ADR index entries without records: {extra_in_index}")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Linura ADR ledger governance")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root",
    )
    args = parser.parse_args()

    failures = validate(args.root.resolve())
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1

    print("ADR governance checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
