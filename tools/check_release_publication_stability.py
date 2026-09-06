#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
RELEASES_DIR = ROOT / "docs" / "releases"
MIN_PUBLICATION_STABLE_VERSION = (0, 7, 0)

# Match the SemVer shape accepted by the release workflow, including prerelease
# and build metadata.  The publication-stability policy is selected from the
# numeric core, so v0.7.0-rc.1 and v0.7.0+build.1 are guarded exactly like
# v0.7.0 rather than silently bypassing the checker.
VERSION_FILE_RE = re.compile(
    r"^v(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?P<prerelease>[0-9A-Za-z.-]+))?"
    r"(?:\+(?P<build>[0-9A-Za-z.-]+))?\.md$"
)
STATUS_RE = re.compile(r"^\*\*Status:\*\*\s*(?P<value>.+?)\s*$", re.MULTILINE)
PUBLICATION_SECTION_RE = re.compile(r"(?ms)^## Publication evidence\n(?P<body>.*?)(?=^## |\Z)")

# These are live lifecycle assertions, not timeless release-contract language.
# They are forbidden anywhere in a v0.7+ frozen contract because the exact
# bytes may become the immutable GitHub Release body.  Keep the patterns
# specific enough that timeless requirements such as "publication requires X"
# and artifact terms such as "candidate artifact" remain valid.
TEMPORARY_LIFECYCLE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("release candidate", re.compile(r"\brelease\s+candidate\b", re.IGNORECASE)),
    (
        "publication pending",
        re.compile(
            r"\bpublication(?:\s+evidence)?\s+(?:is\s+|remains\s+|is\s+currently\s+)?pending\b",
            re.IGNORECASE,
        ),
    ),
    (
        "not yet released/published",
        re.compile(r"\bnot\s+yet\s+(?:released|published)\b", re.IGNORECASE),
    ),
    (
        "release is not published/released",
        re.compile(
            r"\b(?:this\s+)?release\s+is\s+not\s+(?:yet\s+)?(?:released|published)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "publication is not established",
        re.compile(r"\bpublication\s+is\s+not\s+established\b", re.IGNORECASE),
    ),
    (
        "publication has not occurred/completed",
        re.compile(
            r"\bpublication\s+has\s+not\s+(?:yet\s+)?(?:occurred|completed|succeeded)\b",
            re.IGNORECASE,
        ),
    ),
)


class PublicationStabilityError(ValueError):
    pass


def version_from_path(path: Path) -> tuple[int, int, int] | None:
    match = VERSION_FILE_RE.fullmatch(path.name)
    if match is None:
        return None
    return tuple(int(match.group(name)) for name in ("major", "minor", "patch"))


def _find_temporary_lifecycle_assertion(text: str) -> tuple[str, int] | None:
    for label, pattern in TEMPORARY_LIFECYCLE_PATTERNS:
        match = pattern.search(text)
        if match is not None:
            return label, text.count("\n", 0, match.start()) + 1
    return None


def validate_contract(path: Path) -> None:
    version = version_from_path(path)
    if version is None or version < MIN_PUBLICATION_STABLE_VERSION:
        return

    text = path.read_text(encoding="utf-8")
    status_match = STATUS_RE.search(text)
    if status_match is None:
        raise PublicationStabilityError(f"{path}: missing **Status:** metadata")

    if PUBLICATION_SECTION_RE.search(text) is None:
        raise PublicationStabilityError(f"{path}: missing ## Publication evidence section")

    temporary = _find_temporary_lifecycle_assertion(text)
    if temporary is not None:
        label, line = temporary
        raise PublicationStabilityError(
            f"{path}:{line}: frozen contract contains temporary lifecycle assertion {label!r}; "
            "use publication-stable wording because these exact bytes may become the immutable GitHub Release body"
        )


def validate_tree(releases_dir: Path = RELEASES_DIR) -> None:
    if not releases_dir.is_dir():
        raise PublicationStabilityError(f"release directory does not exist: {releases_dir}")
    for path in sorted(releases_dir.iterdir()):
        if path.is_file():
            validate_contract(path)


def main() -> int:
    directory = Path(sys.argv[1]) if len(sys.argv) > 1 else RELEASES_DIR
    if len(sys.argv) > 2:
        print("usage: check_release_publication_stability.py [releases-dir]", file=sys.stderr)
        return 2
    try:
        validate_tree(directory)
    except PublicationStabilityError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
