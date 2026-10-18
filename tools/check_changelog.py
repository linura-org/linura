#!/usr/bin/env python3
"""Validate changelog release history against the canonical roadmap."""

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path
import re
import sys
import tomllib

SECTION_RE = re.compile(r"(?m)^## (?P<heading>[^\n]+)$")
VERSION_RE = re.compile(r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")
RELEASE_RE = re.compile(r"^\[(?P<version>[^]]+)\] - (?P<date>\d{4}-\d{2}-\d{2})$")


def validate(
    root: Path, roadmap: dict[str, object], *, release_candidate: str | None = None
) -> list[str]:
    path = root / "CHANGELOG.md"
    if not path.is_file():
        return ["CHANGELOG.md is missing"]
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as error:
        return [f"cannot read CHANGELOG.md: {error}"]
    failures: list[str] = []
    if not content.startswith("# Changelog\n"):
        failures.append("CHANGELOG.md must begin with '# Changelog'")

    matches = list(SECTION_RE.finditer(content))
    sections: dict[str, str] = {}
    ordered: list[str] = []
    for index, match in enumerate(matches):
        heading = match.group("heading")
        body = content[
            match.end() : (
                matches[index + 1].start() if index + 1 < len(matches) else len(content)
            )
        ]
        if heading == "[Unreleased]":
            key = "Unreleased"
        else:
            release = RELEASE_RE.fullmatch(heading)
            if (
                release is None
                or VERSION_RE.fullmatch(release.group("version")) is None
            ):
                failures.append(f"invalid changelog section: ## {heading}")
                continue
            key = "v" + release.group("version")
            try:
                date.fromisoformat(release.group("date"))
            except ValueError:
                failures.append(f"{key}: invalid release date {release.group('date')}")
        if key in sections:
            failures.append(f"duplicate changelog section: {key}")
        else:
            sections[key] = body
            ordered.append(key)

    if not ordered or ordered[0] != "Unreleased":
        failures.append(
            "CHANGELOG.md must start its version sections with ## [Unreleased]"
        )

    def version_key(tag: str) -> tuple[int, int, int]:
        major, minor, patch = (int(part) for part in tag[1:].split("."))
        return major, minor, patch

    recorded = [version for version in ordered if version != "Unreleased"]
    if recorded != sorted(recorded, key=version_key, reverse=True):
        failures.append("dated changelog releases must be in descending version order")

    milestones = roadmap.get("milestone")
    if not isinstance(milestones, list):
        return failures + ["roadmap milestone list is missing"]
    released: set[str] = set()
    for item in milestones:
        if not isinstance(item, dict):
            continue
        version = item.get("version")
        if item.get("status") == "released" and isinstance(version, str):
            released.add(version)
    for tag in sorted(released):
        if tag not in sections:
            failures.append(
                f"{tag}: released milestone missing dated CHANGELOG.md entry"
            )
        elif f"docs/releases/{tag}.md" not in sections[tag]:
            failures.append(
                f"{tag}: changelog entry must link the frozen release contract"
            )
    for tag in recorded:
        if tag not in released:
            failures.append(
                f"{tag}: dated changelog entry has no released roadmap milestone"
            )

    if release_candidate is not None:
        body = sections.get("Unreleased", "")
        marker = (
            f"Target milestone: [{release_candidate}]"
            f"(docs/milestones/{release_candidate}.md) "
            "— work in progress, not released."
        )
        if body.count(marker) != 1:
            failures.append(
                f"{release_candidate}: Unreleased must contain the exact "
                "prepublication milestone marker"
            )
        if not re.search(r"(?m)^- \S", body):
            failures.append(
                f"{release_candidate}: Unreleased must contain substantive change notes"
            )
    return failures


class ChangelogClosureError(ValueError):
    pass


def finalize_release(content: str, tag: str, published_at: str) -> str:
    """Move prepublication notes into a dated entry after verified publication."""
    if not tag.startswith("v") or VERSION_RE.fullmatch(tag[1:]) is None:
        raise ChangelogClosureError(f"invalid release tag: {tag!r}")
    try:
        published = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ChangelogClosureError("invalid release publication timestamp") from error
    if published.tzinfo is None or published.utcoffset() != timezone.utc.utcoffset(
        published
    ):
        raise ChangelogClosureError("release publication time must carry a UTC offset")
    published_date = published.date().isoformat()
    expected_heading = f"## [{tag[1:]}] - {published_date}"
    if re.search(rf"(?m)^## \[{re.escape(tag[1:])}\] - ", content):
        if expected_heading in content and f"docs/releases/{tag}.md" in content:
            return content
        raise ChangelogClosureError(f"{tag}: terminal changelog entry already differs")

    section = re.search(r"(?ms)^## \[Unreleased\]\n(?P<body>.*?)(?=^## |\Z)", content)
    if section is None:
        raise ChangelogClosureError("missing Unreleased changelog section")
    marker = (
        f"Target milestone: [{tag}](docs/milestones/{tag}.md) "
        "— work in progress, not released."
    )
    body = section.group("body")
    if body.count(marker) != 1:
        raise ChangelogClosureError(
            f"{tag}: missing unique prepublication milestone marker"
        )
    notes = body.replace(marker, "", 1).strip()
    if re.search(r"(?m)^- \S", notes) is None:
        raise ChangelogClosureError(f"{tag}: missing substantive release notes")
    updated = (
        "## [Unreleased]\n\n"
        f"{expected_heading}\n\n"
        "Release notes. Full release contract: "
        f"[`docs/releases/{tag}.md`](docs/releases/{tag}.md).\n\n"
        f"{notes}\n\n"
    )
    return content[: section.start()] + updated + content[section.end() :]


def main() -> int:
    root = (
        Path(sys.argv[1]).resolve()
        if len(sys.argv) == 2
        else Path(__file__).resolve().parents[1]
    )
    if len(sys.argv) > 2:
        print("usage: check_changelog.py [repository-root]", file=sys.stderr)
        return 2
    try:
        roadmap = tomllib.loads(
            (root / "contracts/roadmap.toml").read_text(encoding="utf-8")
        )
    except (OSError, tomllib.TOMLDecodeError) as error:
        print(f"invalid roadmap: {error}", file=sys.stderr)
        return 2
    failures = validate(root, roadmap)
    for failure in failures:
        print(f"ERROR: {failure}", file=sys.stderr)
    if not failures:
        print("changelog checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
