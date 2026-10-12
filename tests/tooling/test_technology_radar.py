from __future__ import annotations

from datetime import date, datetime, timezone
import html
from pathlib import Path
import re
import string
import tempfile
import unicodedata
import unittest

ROOT = Path(__file__).resolve().parents[2]
RADAR = Path("docs/research/technology-radar.md")
ENTRY_ROOT = Path("docs/research/entries")
ROW = re.compile(
    r"^\| \[([^|\]\[]+)\]\((entries/[a-z0-9-]+\.md)\) "
    r"\| (Watch|Assess|Adopt|Hold) \| ([^|]+) "
    r"\| (\d{4}-\d{2}-\d{2}) \| (\d{4}-\d{2}-\d{2}) \|$"
)
# Governed research records are Markdown-only: deny any raw HTML opener,
# including custom elements, multiline tags, declarations and processing instructions.
RAW_HTML_BLOCK = re.compile(
    r"<(?:/?[A-Za-z][A-Za-z0-9-]*(?::[A-Za-z][A-Za-z0-9-]*)?(?=[ \t/>]|$)"
    r"|![A-Za-z]|!\[|\?)",
    re.IGNORECASE,
)


def symlink_in_source_path(root: Path, relative: Path) -> bool:
    """Do not traverse symlinked research ancestors outside the reviewed tree."""
    return any(
        (root / Path(*relative.parts[:depth])).is_symlink()
        for depth in range(1, len(relative.parts) + 1)
    )


def meaningful_label(value: str) -> bool:
    # GitHub renders HTML character references in Markdown table cells.
    visible = html.unescape(value)
    return any(char.isalnum() for char in visible) and not any(
        unicodedata.category(char) in {"Cc", "Cf"} for char in visible
    )


# Governed technology names are plain text, not inline Markdown.
# Rendered entities, Unicode compatibility and whitespace define uniqueness.
PLAIN_NAME = re.compile(r"[\w][\w .,:;/+()#&%-]*", re.UNICODE)


def canonical_technology_name(name: str) -> str:
    rendered = unicodedata.normalize("NFKC", html.unescape(name))
    return re.sub(r"\s+", " ", rendered).strip().casefold()


def plain_technology_name(name: str) -> bool:
    rendered = unicodedata.normalize("NFKC", html.unescape(name))
    return (
        rendered == rendered.strip()
        and PLAIN_NAME.fullmatch(rendered) is not None
        and re.search(r"(?<!\w)_|_(?!\w)", rendered) is None
        and "__" not in rendered
        and meaningful_label(name)
    )


# CommonMark only unescapes ASCII punctuation, and HTML references decode later.
MARKDOWN_ESCAPES = re.compile(r"\\([" + re.escape(string.punctuation) + r"])")

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


def escaped_markdown_punctuation(line: str, offset: int) -> bool:
    """CommonMark treats punctuation as escaped after an odd slash run."""
    index = offset
    while index > 0 and line[index - 1] == "\\":
        index -= 1
    return (offset - index) % 2 == 1


def unescaped_html_comment_start(line: str, offset: int) -> int:
    """Recognize comments only outside escaped Markdown and inline code."""
    position = offset
    code_span = 0
    while position < len(line):
        if line[position] == "`" and not escaped_markdown_punctuation(line, position):
            end = position
            while end < len(line) and line[end] == "`":
                end += 1
            length = end - position
            if code_span == 0:
                code_span = length
            elif code_span == length:
                code_span = 0
            position = end
            continue
        if (
            code_span == 0
            and line.startswith("<!--", position)
            and not escaped_markdown_punctuation(line, position)
        ):
            return position
        position += 1
    return -1


def has_unclosed_inline_code_span(line: str) -> bool:
    """The governed subset excludes code spans crossing physical lines."""
    position = 0
    open_length = 0
    while position < len(line):
        if line[position] != "`" or escaped_markdown_punctuation(line, position):
            position += 1
            continue
        end = position
        while end < len(line) and line[end] == "`":
            end += 1
        length = end - position
        if open_length == 0:
            open_length = length
        elif open_length == length:
            open_length = 0
        position = end
    return open_length != 0


def visible_state_field(line: str) -> bool:
    """Reject rendered duplicate classification in headings, lists and tables."""
    rendered = html.unescape(MARKDOWN_ESCAPES.sub(r"\1", line))
    if re.search(
        r"(\*\*|__|\*|_)(?:Status|State|Classification)(?::\1|\1:)",
        rendered,
        re.IGNORECASE,
    ):
        return True
    prefix = r"^\s*(?:(?:>\s*)|(?:[-+*]\s+)|(?:\d+[.)]\s+))*"
    metadata = r"(?:Status|State|Classification):\s*\S"
    if re.match(prefix + r"(?:#{1,6}\s+)?" + metadata, rendered, re.IGNORECASE):
        return True
    return (
        re.match(
            r"^\s*\|\s*(?:(?:\*\*|__|\*|_|\x60)?(?:Status|State|Classification):?"
            r"(?:\*\*|__|\*|_|\x60)?)\s*\|",
            rendered,
            re.IGNORECASE,
        )
        is not None
    )


def visible_markdown_lines(body: str) -> list[str | None]:
    """Keep rendered source lines; reject comment, fence and indented-code decoys."""
    visible_lines: list[str | None] = []
    fence_char: str | None = None
    fence_length = 0
    in_comment = False
    for raw in body.splitlines():
        if fence_char is not None:
            closing = (
                r" {0,3}"
                + re.escape(fence_char)
                + "{"
                + str(fence_length)
                + r",}[ \t]*"
            )
            if re.fullmatch(closing, raw):
                fence_char = None
            visible_lines.append(None)
            continue
        fragments: list[str] = []
        cursor = 0
        while cursor < len(raw):
            if in_comment:
                end = raw.find("-->", cursor)
                if end < 0:
                    break
                in_comment = False
                cursor = end + 3
            else:
                start = unescaped_html_comment_start(raw, cursor)
                if start < 0:
                    fragments.append(raw[cursor:])
                    break
                fragments.append(raw[cursor:start])
                in_comment = True
                cursor = start + 4
        rendered = "".join(fragments)
        opening = re.match(r"^ {0,3}(\x60{3,}|~{3,})(.*)$", rendered)
        if opening and (
            opening.group(1).startswith("~") or chr(96) not in opening.group(2)
        ):
            fence_char = opening.group(1)[0]
            fence_length = len(opening.group(1))
            visible_lines.append(None)
        elif rendered.startswith(("    ", "\t")):
            visible_lines.append(rendered)
        else:
            visible_lines.append(rendered)
    return visible_lines


def visible_markdown_headings(body: str) -> list[str]:
    """Count only actual, rendered, top-level level-two headings."""
    return [
        line
        for line in visible_markdown_lines(body)
        if line is not None and line.startswith("## ")
    ]


def validate(root: Path, *, as_of: date | None = None) -> list[str]:
    failures: list[str] = []
    if as_of is None:
        as_of = datetime.now(timezone.utc).date()
    radar_path = root / RADAR
    if symlink_in_source_path(root, RADAR) or symlink_in_source_path(root, ENTRY_ROOT):
        return ["research sources must not traverse symlinks"]
    radar = radar_path.read_text(encoding="utf-8")
    lines = visible_markdown_lines(radar)
    if any(
        line is not None and line.strip() and line.startswith(("    ", "\t"))
        for line in lines
    ):
        failures.append("unsupported indented Markdown in radar")
    if any(line is not None and has_unclosed_inline_code_span(line) for line in lines):
        failures.append("unsupported multiline inline code in radar")
    if any(line is not None and RAW_HTML_BLOCK.search(line) for line in lines):
        failures.append("raw HTML container is not allowed in radar")
    header = "| Technology | State | Review owner | Last assessed | Next review |"
    headers = [index for index, line in enumerate(lines) if line == header]
    rows: list[str] = []
    if len(headers) != 1:
        failures.append("radar must contain exactly one canonical table header")
    else:
        start = headers[0] + 1
        separator = re.compile(r"(?:\|[ \t]*:?-{3,}:?[ \t]*){5}\|")
        separator_line = lines[start] if start < len(lines) else None
        if separator_line is None or separator.fullmatch(separator_line) is None:
            failures.append("invalid radar table separator")
        else:
            for line in lines[start + 1 :]:
                if line is None:
                    failures.append("non-rendered content interrupts radar table")
                    break
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
        if not meaningful_label(name):
            failures.append(f"blank technology name: {target}")
        elif not plain_technology_name(name):
            failures.append(f"technology name must be plain text: {target}")
        canonical_name = canonical_technology_name(name)
        if canonical_name in found_names:
            failures.append(f"duplicate technology name: {name}")
        found_names.add(canonical_name)
        if not meaningful_label(owner):
            failures.append(f"missing owner: {target}")
        if target in found:
            failures.append(f"duplicate radar record: {target}")
        found.add(target)
        try:
            last_date, next_date = (
                date.fromisoformat(assessed),
                date.fromisoformat(review),
            )
            interval = (next_date - last_date).days
            if last_date > as_of:
                failures.append(f"assessment date is in the future: {target}")
            if interval <= 0:
                failures.append(f"review must follow assessment: {target}")
            if (
                state in {"Watch", "Assess"}
                and interval > {"Watch": 90, "Assess": 30}[state]
            ):
                failures.append(f"review interval exceeds {state} cadence: {target}")
        except ValueError:
            failures.append(f"invalid ISO date: {target}")
        record = radar_path.parent / target
        if (
            symlink_in_source_path(root, Path("docs/research") / target)
            or not record.is_file()
        ):
            failures.append(f"missing or unsafe research record: {target}")
            continue
        body = record.read_text(encoding="utf-8")
        if not body.startswith(f"# Technology: {name}\n"):
            failures.append(f"research title mismatch: {target}")
        expected_id = Path(target).stem
        rendered_lines = visible_markdown_lines(body)
        if any(
            line is not None and line.strip() and line.startswith(("    ", "\t"))
            for line in rendered_lines
        ):
            failures.append(
                f"unsupported indented Markdown in research record: {target}"
            )
        if any(
            line is not None and has_unclosed_inline_code_span(line)
            for line in rendered_lines
        ):
            failures.append(
                f"unsupported multiline inline code in research record: {target}"
            )
        if any(
            line is not None and RAW_HTML_BLOCK.search(line) for line in rendered_lines
        ):
            failures.append(
                f"raw HTML container is not allowed in research record: {target}"
            )
        expected_id_line = f"**Record ID:** {chr(96)}{expected_id}{chr(96)}"
        if (
            sum(
                line is not None and line.strip() == expected_id_line
                for line in rendered_lines
            )
            != 1
        ):
            failures.append(f"research identity mismatch: {target}")
        rendered_headings = visible_markdown_headings(body)
        for heading in REQUIRED_SECTIONS:
            if rendered_headings.count(heading) != 1:
                failures.append(f"missing or duplicate rendered {heading}: {target}")
        present = [
            heading for heading in rendered_headings if heading in REQUIRED_SECTIONS
        ]
        if present != list(REQUIRED_SECTIONS):
            failures.append(f"research sections out of order: {target}")
        if any(
            line is not None and visible_state_field(line) for line in rendered_lines
        ):
            failures.append(f"entry duplicates canonical radar state: {target}")
    entry_root = root / ENTRY_ROOT
    markdown_suffixes = {".md", ".markdown", ".mdown", ".mkd", ".mdx"}
    for entry in sorted(entry_root.rglob("*")):
        target = "entries/" + entry.relative_to(entry_root).as_posix()
        if entry.is_symlink():
            failures.append(f"unsafe symlink in research entries: {target}")
        elif entry.is_file() and entry.suffix.casefold() in markdown_suffixes:
            if entry.parent != entry_root:
                failures.append(f"nested research entry is unsupported: {target}")
            elif target not in found:
                failures.append(f"unindexed research entry: {target}")
    return failures


class TechnologyRadarTests(unittest.TestCase):
    def test_repository_radar_is_consistent(self) -> None:
        self.assertEqual(validate(ROOT), [])

    def test_names_are_plain_text_and_visually_unique(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        record = (ROOT / ENTRY_ROOT / "multikernel-linux.md").read_text(
            encoding="utf-8"
        )
        row = next(line for line in radar.splitlines() if line.startswith("| ["))
        for name in (
            "**Multikernel Linux**",
            "__Multikernel Linux__",
            chr(96) + "Multikernel Linux" + chr(96),
            "Multi*kernel* Linux",
            "&#42;&#42;Multikernel Linux&#42;&#42;",
            r"Multikernel\ Linux",
            "Multi__kernel Linux",
        ):
            with self.subTest(name=name):
                changed_radar = radar.replace("[Multikernel Linux]", f"[{name}]", 1)
                changed_record = record.replace(
                    "# Technology: Multikernel Linux", f"# Technology: {name}", 1
                )
                failures = self._validate_fixture(changed_radar, changed_record)
                self.assertTrue(
                    any(
                        "technology name must be plain text" in failure
                        for failure in failures
                    ),
                    failures,
                )
        for duplicate in (
            "MULTIKERNEL LINUX",
            "Multikernel  Linux",
            "Multikernel&nbsp;Linux",
            "Multikernel　Linux",
        ):
            with self.subTest(duplicate=duplicate):
                self.assertEqual(
                    canonical_technology_name(duplicate),
                    canonical_technology_name("Multikernel Linux"),
                )
                another = row.replace("Multikernel Linux", duplicate, 1).replace(
                    "multikernel-linux.md", "another-record.md", 1
                )
                failures = self._validate_fixture(
                    radar.replace(row, row + "\n" + another, 1), record
                )
                self.assertTrue(
                    any("duplicate technology name" in failure for failure in failures),
                    failures,
                )

    def test_heading_and_table_classification_are_not_authoritative(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        record = (ROOT / ENTRY_ROOT / "multikernel-linux.md").read_text(
            encoding="utf-8"
        )
        for field in (
            "## State: Adopt",
            "### Status: Hold",
            "> ## Classification: Assess",
            "- ### State: Adopt",
            "## **State:** Adopt",
            "### __Status:__ Hold",
            "| State | Adopt |",
            "| **Classification:** | Hold |",
            "state: adopt",
            "Some narrative __State:__ Adopt",
            "Some narrative **State**: Adopt",
            "Some narrative *Status:* Hold",
            "Some narrative _Classification_: Adopt",
            "| " + chr(96) + "State" + chr(96) + " | Adopt |",
        ):
            with self.subTest(field=field):
                failures = self._validate_fixture(radar, record + "\n" + field + "\n")
                self.assertTrue(
                    any(
                        "entry duplicates canonical radar state" in failure
                        for failure in failures
                    ),
                    failures,
                )
        for hidden in (
            "<!-- ## State: Adopt -->",
            chr(96) * 3 + "md\n## State: Adopt\n" + chr(96) * 3,
        ):
            with self.subTest(hidden=hidden):
                self.assertEqual(
                    self._validate_fixture(radar, record + "\n" + hidden + "\n"), []
                )

    def test_indented_markdown_cannot_hide_visible_metadata(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        record = (ROOT / ENTRY_ROOT / "multikernel-linux.md").read_text(
            encoding="utf-8"
        )
        for indented in (
            "    ## State: Adopt",
            "\t**State:** Adopt",
            "- A list item\n    ## Classification: Assess",
        ):
            with self.subTest(indented=indented):
                failures = self._validate_fixture(
                    radar, record + "\n" + indented + "\n"
                )
                self.assertTrue(
                    any(
                        "unsupported indented Markdown" in failure
                        for failure in failures
                    ),
                    failures,
                )
        table = "| Technology | State | Review owner | Last assessed | Next review |"
        changed = radar.replace(table, "    " + table, 1)
        failures = self._validate_fixture(changed, record)
        self.assertTrue(
            any(
                "unsupported indented Markdown in radar" in failure
                for failure in failures
            ),
            failures,
        )

    def test_research_sources_reject_symlinked_ancestors(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        for path, directory in ((RADAR, False), (ENTRY_ROOT, True)):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                destination = root / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                if directory:
                    (root / RADAR).write_text(radar, encoding="utf-8")
                destination.symlink_to(ROOT / path, target_is_directory=directory)
                self.assertIn(
                    "research sources must not traverse symlinks", validate(root)
                )

    def test_rejects_invalid_assessment_review_order(self) -> None:
        source = (ROOT / RADAR).read_text(encoding="utf-8")
        self.assertIn("2027-01-08", source)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            dest = root / RADAR
            dest.parent.mkdir(parents=True)
            dest.write_text(
                source.replace("2027-01-08", "2026-10-10"), encoding="utf-8"
            )
            errors = validate(root)
            self.assertTrue(
                any("review must follow assessment" in error for error in errors),
                errors,
            )

    def test_required_sections_are_rendered_complete_and_ordered(self) -> None:
        original = (ROOT / RADAR).read_text(encoding="utf-8")
        record_path = ROOT / ENTRY_ROOT / "multikernel-linux.md"
        record = record_path.read_text(encoding="utf-8")
        self.assertEqual(visible_markdown_headings(record)[:8], list(REQUIRED_SECTIONS))
        heading = REQUIRED_SECTIONS[0]
        for replacement in (
            f"### {heading.removeprefix('## ')}",
            f"<!-- {heading} -->",
            f"```md\n{heading}\n```",
            f"~~~md\n{heading}\n~~~",
            heading.replace("##", "## ", 1),
            "",
        ):
            with (
                self.subTest(replacement=replacement),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp)
                (root / RADAR).parent.mkdir(parents=True)
                (root / RADAR).write_text(original, encoding="utf-8")
                target = root / ENTRY_ROOT / "multikernel-linux.md"
                target.parent.mkdir(parents=True)
                target.write_text(
                    record.replace(heading, replacement, 1), encoding="utf-8"
                )
                errors = validate(root)
                self.assertTrue(
                    any(
                        "missing or duplicate rendered " + heading in error
                        for error in errors
                    ),
                    errors,
                )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / RADAR).parent.mkdir(parents=True)
            (root / RADAR).write_text(original, encoding="utf-8")
            target = root / ENTRY_ROOT / "multikernel-linux.md"
            target.parent.mkdir(parents=True)
            target.write_text(
                record.replace(heading, heading + "\n" + heading, 1), encoding="utf-8"
            )
            errors = validate(root)
            self.assertTrue(
                any(
                    "missing or duplicate rendered " + heading in error
                    for error in errors
                ),
                errors,
            )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / RADAR).parent.mkdir(parents=True)
            (root / RADAR).write_text(original, encoding="utf-8")
            target = root / ENTRY_ROOT / "multikernel-linux.md"
            target.parent.mkdir(parents=True)
            second = REQUIRED_SECTIONS[1]
            swapped = record.replace(heading, "__FIRST_SECTION__", 1)
            swapped = swapped.replace(second, heading, 1)
            swapped = swapped.replace("__FIRST_SECTION__", second, 1)
            target.write_text(swapped, encoding="utf-8")
            errors = validate(root)
            self.assertTrue(
                any("research sections out of order" in error for error in errors),
                errors,
            )

    def test_markdown_lookalikes_do_not_count_as_sections(self) -> None:
        heading = REQUIRED_SECTIONS[0]
        decoys = (
            f"<!-- {heading} -->",
            f"```markdown\n{heading}\n```",
            f"~~~markdown\n{heading}\n~~~",
            f"### {heading.removeprefix('## ')}",
            "    " + heading,
        )
        for decoy in decoys:
            with self.subTest(decoy=decoy):
                self.assertNotIn(heading, visible_markdown_headings(decoy))
        self.assertEqual(visible_markdown_headings(heading), [heading])

    def test_rejects_duplicate_unsupported_or_missing_records(self) -> None:
        source = (ROOT / RADAR).read_text(encoding="utf-8")
        original = next(line for line in source.splitlines() if line.startswith("| ["))
        for change, reason in (
            (
                source.replace(original, original + "\n" + original, 1),
                "duplicate radar record",
            ),
            (source.replace("| Watch |", "| Unknown |"), "invalid radar row"),
            (
                source.replace(
                    original, original.replace("Multikernel Linux", "   "), 1
                ),
                "blank technology name",
            ),
            (
                source.replace(
                    original, original.replace("Multikernel Linux", "\t "), 1
                ),
                "blank technology name",
            ),
            (
                source.replace(
                    original,
                    original.replace("Multikernel Linux", "Multi|kernel Linux"),
                    1,
                ),
                "invalid radar row",
            ),
            (
                source.replace(
                    original,
                    original.replace("Multikernel Linux", r"Multi\|kernel Linux"),
                    1,
                ),
                "invalid radar row",
            ),
            (
                source.replace(
                    original,
                    original.replace("Multikernel Linux", "Multi[ker]nel Linux"),
                    1,
                ),
                "invalid radar row",
            ),
            (
                source.replace("entries/multikernel-linux.md", "entries/absent.md"),
                "missing or unsafe research record",
            ),
            (
                source.replace(
                    original,
                    original
                    + "\n"
                    + original.replace(
                        "multikernel-linux.md", "multikernel-linux-duplicate.md"
                    ),
                    1,
                ),
                "duplicate technology name",
            ),
            (
                source.replace("2027-01-08", "2027-01-09"),
                "review interval exceeds Watch cadence",
            ),
            (
                source.replace(
                    original,
                    original
                    + "\n"
                    + "| Multikernel Linux | Watch | Linura maintainers | 2026-10-10 | 2027-01-08 |",
                    1,
                ),
                "invalid radar row",
            ),
            (
                source.replace(
                    original,
                    original
                    + "\n"
                    + "Multikernel Linux | Watch | Linura maintainers | 2026-10-10 | 2027-01-08",
                    1,
                ),
                "invalid radar row",
            ),
            (
                source.replace(
                    original,
                    original
                    + "\n"
                    + "  | [Invalid](entries/invalid.md) | Watch | Linura maintainers | 2026-10-10 | 2027-01-08 |",
                    1,
                ),
                "invalid radar row",
            ),
            (
                source.replace(
                    original,
                    original
                    + "\n"
                    + "|  [Invalid](entries/invalid.md) | Watch | Linura maintainers | 2026-10-10 | 2027-01-08 |",
                    1,
                ),
                "invalid radar row",
            ),
            (
                source.replace(
                    "| --- | --- | --- | --- | --- |",
                    "| --- | --- | --- | --- | invalid |",
                ),
                "invalid radar table separator",
            ),
            (
                source.replace(
                    "| Technology | State | Review owner | Last assessed | Next review |",
                    "| Technology | State | Owner | Last assessed | Next review |",
                ),
                "canonical table header",
            ),
        ):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                dest = root / RADAR
                dest.parent.mkdir(parents=True)
                dest.write_text(change, encoding="utf-8")
                errors = validate(root)
                self.assertTrue(any(reason in error for error in errors), errors)

    @staticmethod
    def _validate_fixture(
        radar: str, record: str, *, as_of: date | None = None
    ) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / RADAR
            target.parent.mkdir(parents=True)
            target.write_text(radar, encoding="utf-8")
            entry = root / ENTRY_ROOT / "multikernel-linux.md"
            entry.parent.mkdir(parents=True)
            entry.write_text(record, encoding="utf-8")
            return validate(root, as_of=as_of)

    def test_radar_table_must_be_rendered_not_in_comments_or_fences(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        record = (ROOT / ENTRY_ROOT / "multikernel-linux.md").read_text(
            encoding="utf-8"
        )
        header = "| Technology | State | Review owner | Last assessed | Next review |"
        start = radar.index(header)
        end = radar.index("\n\n", start)
        table = radar[start:end]
        fence = chr(96) * 3
        for hidden in (
            f"{fence}markdown\n{table}\n\n{fence}",
            f"~~~markdown\n{table}\n\n~~~",
            f"<!--\n{table}\n\n-->",
            "\n".join("    " + line for line in table.splitlines()),
        ):
            with self.subTest(hidden=hidden[:60]):
                errors = self._validate_fixture(radar.replace(table, hidden, 1), record)
                self.assertTrue(
                    any("canonical table header" in error for error in errors), errors
                )
        for hidden in (
            f"{fence}markdown\n{table}\n{fence}\n",
            f"<!--\n{table}\n-->\n",
        ):
            with self.subTest(decoy=hidden[:30]):
                self.assertEqual(
                    self._validate_fixture(hidden + "\n" + radar, record), []
                )

    def test_prefixed_duplicate_state_rejected_and_hidden_state_ignored(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        record = (ROOT / ENTRY_ROOT / "multikernel-linux.md").read_text(
            encoding="utf-8"
        )
        for state in (
            "> **State:** Adopt",
            "- **Status:** Hold",
            "1. **Classification:** Assess",
            "> - **State:** Adopt",
            "Some narrative **Status:** Hold",
        ):
            with self.subTest(state=state):
                errors = self._validate_fixture(radar, record + "\n" + state + "\n")
                self.assertTrue(
                    any(
                        "entry duplicates canonical radar state" in error
                        for error in errors
                    ),
                    errors,
                )
        fence = chr(96) * 3
        hidden = (
            "\n<!--\n> **State:** Adopt\n-->\n"
            + f"\n{fence}markdown\n- **Status:** Hold\n{fence}\n"
        )
        self.assertEqual(self._validate_fixture(radar, record + hidden), [])

    def test_record_identity_requires_a_visible_unique_field(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        record = (ROOT / ENTRY_ROOT / "multikernel-linux.md").read_text(
            encoding="utf-8"
        )
        identity = f"**Record ID:** {chr(96)}multikernel-linux{chr(96)}"
        for altered in (
            record.replace(identity, "Record identity withheld", 1)
            + "\n<!-- "
            + identity
            + " -->\n",
            record.replace(identity, "Record identity withheld", 1)
            + "\n"
            + chr(96) * 3
            + "\n"
            + identity
            + "\n"
            + chr(96) * 3
            + "\n",
            record + "\n" + identity + "\n",
        ):
            errors = self._validate_fixture(radar, altered)
            self.assertTrue(
                any("research identity mismatch" in error for error in errors), errors
            )

    def test_comment_markers_within_fences_do_not_hide_visible_table(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        record = (ROOT / ENTRY_ROOT / "multikernel-linux.md").read_text(
            encoding="utf-8"
        )
        prefix = "~~~markdown\n<!--\n~~~\n"
        self.assertEqual(self._validate_fixture(prefix + radar, record), [])

    def test_raw_html_containers_cannot_hide_governed_markup(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        record = (ROOT / ENTRY_ROOT / "multikernel-linux.md").read_text(
            encoding="utf-8"
        )
        start = radar.index(
            "| Technology | State | Review owner | Last assessed | Next review |"
        )
        end = radar.index("\n\n", start)
        table = radar[start:end]
        for tag in (
            "pre",
            "div",
            "details",
            "blockquote",
            "form",
            "fieldset",
            "svg",
            "x-custom-element",
            "x:custom",
            "table",
            "section",
            "style",
            "textarea",
            "script",
        ):
            with self.subTest(tag=tag):
                wrapper = f"<{tag}>\n{table}\n\n</{tag}>"
                errors = self._validate_fixture(
                    radar.replace(table, wrapper, 1), record
                )
                self.assertTrue(
                    any(
                        "raw HTML container is not allowed in radar" in error
                        for error in errors
                    ),
                    errors,
                )
                record_errors = self._validate_fixture(
                    radar, record + f"\n<{tag}>\n## Hidden section\n</{tag}>\n"
                )
                self.assertTrue(
                    any(
                        "raw HTML container is not allowed in research record" in error
                        for error in record_errors
                    ),
                    record_errors,
                )
        for syntax in ("<!DOCTYPE html>", "<?xml version='1.0'?>", "<![CDATA["):
            with self.subTest(syntax=syntax):
                errors = self._validate_fixture(syntax + "\n" + radar, record)
                self.assertTrue(
                    any(
                        "raw HTML container is not allowed in radar" in e
                        for e in errors
                    ),
                    errors,
                )
        self.assertEqual(
            self._validate_fixture("<!-- <pre> -->\n" + radar, record),
            [],
        )

    def test_encoded_invisible_metadata_is_rejected(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        record = (ROOT / ENTRY_ROOT / "multikernel-linux.md").read_text(
            encoding="utf-8"
        )
        for encoded in ("&#8203;", "&#x200B;", "&ZeroWidthSpace;", "&#32;", "&nbsp;"):
            with self.subTest(encoded=encoded):
                errors = self._validate_fixture(
                    radar.replace("Multikernel Linux", encoded, 1), record
                )
                self.assertTrue(
                    any("blank technology name" in e for e in errors), errors
                )
                errors = self._validate_fixture(
                    radar.replace("| Linura maintainers |", f"| {encoded} |", 1),
                    record,
                )
                self.assertTrue(any("missing owner" in e for e in errors), errors)

    def test_multiline_inline_code_cannot_mask_authoritative_content(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        record = (ROOT / ENTRY_ROOT / "multikernel-linux.md").read_text(
            encoding="utf-8"
        )
        header = "| Technology | State | Review owner | Last assessed | Next review |"
        start = radar.index(header)
        end = radar.index("\n\n", start)
        table = radar[start:end]
        tick = chr(96)
        hidden_table = radar.replace(table, tick + "\n" + table + "\n" + tick, 1)
        failures = self._validate_fixture(hidden_table, record)
        self.assertTrue(
            any("unsupported multiline inline code in radar" in e for e in failures),
            failures,
        )
        heading = REQUIRED_SECTIONS[0]
        hidden_heading = record.replace(heading, tick + "\n" + heading + "\n" + tick, 1)
        failures = self._validate_fixture(radar, hidden_heading)
        self.assertTrue(
            any(
                "unsupported multiline inline code in research record" in e
                for e in failures
            ),
            failures,
        )

    def test_escaped_comments_and_inline_code_cannot_hide_visible_state(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        record = (ROOT / ENTRY_ROOT / "multikernel-linux.md").read_text(
            encoding="utf-8"
        )
        for visible in (
            r"\<!-- **State:** Adopt -->",
            r"\<!-- - **Status:** Hold -->",
            "`<!--` **Classification:** Assess `-->`",
            r"\\**State:** Adopt",
            "&#42;&#42;State:&#42;&#42; Adopt",
            "Status: Hold",
            "> Classification: Assess",
            r"State\: Adopt",
            r"**State\:** Adopt",
            r"**State**\: Adopt",
            r"## State\: Adopt",
            r"| State\: | Adopt |",
            r"Status&#58; Hold",
        ):
            with self.subTest(visible=visible):
                failures = self._validate_fixture(radar, record + "\n" + visible + "\n")
                self.assertTrue(
                    any(
                        "entry duplicates canonical radar state" in item
                        for item in failures
                    ),
                    failures,
                )
        self.assertEqual(
            self._validate_fixture(radar, record + "\n<!-- **State:** Adopt -->\n"),
            [],
        )
        self.assertEqual(
            self._validate_fixture(
                radar, record + "\n" + r"\\<!-- **State:** Adopt -->" + "\n"
            ),
            [],
        )
        self.assertEqual(
            self._validate_fixture(radar, record + "\n" + r"State\\: Adopt" + "\n"),
            [],
        )

    def test_rejects_future_assessment_without_rejecting_future_review(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        record = (ROOT / ENTRY_ROOT / "multikernel-linux.md").read_text(
            encoding="utf-8"
        )
        assessed = date(2026, 10, 10)
        self.assertEqual(self._validate_fixture(radar, record, as_of=assessed), [])
        future = radar.replace(
            "| 2026-10-10 | 2027-01-08 |",
            "| 2026-10-11 | 2027-01-08 |",
        )
        self.assertNotEqual(future, radar)
        failures = self._validate_fixture(future, record, as_of=assessed)
        self.assertTrue(
            any("assessment date is in the future" in item for item in failures),
            failures,
        )

    def test_root_readme_links_to_research_without_support_claims(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            "| Technology research | [Technology Radar](docs/research/technology-radar.md)"
            " · [Research process](docs/research/README.md) |",
            readme,
        )

    def test_invisible_unicode_labels_cannot_supply_accountable_metadata(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        record = (ROOT / ENTRY_ROOT / "multikernel-linux.md").read_text(
            encoding="utf-8"
        )
        for label in ("\u200b", "\u2060", "\x00"):
            with self.subTest(label=repr(label)):
                changed = radar.replace("Multikernel Linux", label, 1)
                errors = self._validate_fixture(changed, record)
                self.assertTrue(
                    any("blank technology name" in error for error in errors),
                    errors,
                )
                changed_owner = radar.replace(
                    "| Linura maintainers |", f"| {label} |", 1
                )
                errors = self._validate_fixture(changed_owner, record)
                self.assertTrue(
                    any("missing owner" in error for error in errors),
                    errors,
                )

    def test_rejects_nested_or_unindexed_markdown_entries(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        record = (ROOT / ENTRY_ROOT / "multikernel-linux.md").read_text(
            encoding="utf-8"
        )
        for extra, reason in (
            ("archive/orphan.md", "nested research entry is unsupported"),
            ("archive/deep/orphan.MD", "nested research entry is unsupported"),
            ("archive/orphan.markdown", "nested research entry is unsupported"),
            ("unindexed.MD", "unindexed research entry"),
            ("unindexed.mdx", "unindexed research entry"),
        ):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                target = root / RADAR
                target.parent.mkdir(parents=True)
                target.write_text(radar, encoding="utf-8")
                indexed = root / ENTRY_ROOT / "multikernel-linux.md"
                indexed.parent.mkdir(parents=True)
                indexed.write_text(record, encoding="utf-8")
                orphan = root / ENTRY_ROOT / extra
                orphan.parent.mkdir(parents=True, exist_ok=True)
                orphan.write_text(record, encoding="utf-8")
                failures = validate(root)
                self.assertTrue(any(reason in error for error in failures), failures)

    def test_rejects_symlinked_nested_entry_directory(self) -> None:
        radar = (ROOT / RADAR).read_text(encoding="utf-8")
        record = (ROOT / ENTRY_ROOT / "multikernel-linux.md").read_text(
            encoding="utf-8"
        )
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / RADAR
            target.parent.mkdir(parents=True)
            target.write_text(radar, encoding="utf-8")
            indexed = root / ENTRY_ROOT / "multikernel-linux.md"
            indexed.parent.mkdir(parents=True)
            indexed.write_text(record, encoding="utf-8")
            external = root / "external"
            external.mkdir()
            (root / ENTRY_ROOT / "archive").symlink_to(
                external, target_is_directory=True
            )
            failures = validate(root)
            self.assertTrue(
                any(
                    "unsafe symlink in research entries" in error for error in failures
                ),
                failures,
            )
