#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re
import sys
import tomllib
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "README.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "SUPPORT.md",
    "CITATION.cff",
    ".github/FUNDING.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/ISSUE_TEMPLATE/feature.yml",
    ".github/ISSUE_TEMPLATE/compatibility.yml",
    ".github/ISSUE_TEMPLATE/rfc.yml",
    "docs/community/labels.md",
    "docs/community/repository-settings.md",
    "docs/community/sponsorship.md",
    "docs/rfcs/README.md",
    "docs/rfcs/0000-template.md",
]

REQUIRED_MARKERS = {
    "README.md": [
        "## Project navigation",
        "## Try Linura",
        "## Contributing",
        "## Community",
        "## Security",
        "## Support Linura",
    ],
    "CONTRIBUTING.md": [
        "## First contribution",
        "## Architecture and security contribution",
        "## Contribution licensing",
        "cargo xtask check",
    ],
    "GOVERNANCE.md": [
        "## Current governance state",
        "## Merge authority",
        "## Becoming a maintainer",
        "## Inactivity, removal, and succession",
        "## Conflicts of interest and sponsorship",
        "## Governance changes",
    ],
    "CODE_OF_CONDUCT.md": [
        "## Reporting",
        "## Handling and confidentiality",
        "## Enforcement",
        "## Appeals and mistakes",
    ],
    "SECURITY.md": [
        "GitHub private vulnerability reporting",
        "security@linura.org",
        "Do not open a public issue",
    ],
    "SUPPORT.md": [
        "GitHub Discussions",
        "Compatibility issue form",
        "Private reporting under `SECURITY.md`",
    ],
    "docs/rfcs/README.md": [
        "Draft → Discussion → Accepted | Rejected → Implemented → Superseded",
        "## Decision authority",
        "## Relationship to ADRs",
    ],
    "docs/community/sponsorship.md": [
        "Funding does **not** grant",
        "architectural decision authority",
        "security-policy exceptions",
        "release authority",
    ],
}

STALE_HOSTING_LANGUAGE = ("once hosted", "when hosted")

SUPPORTED_FUNDING_KEYS = frozenset({
    "github",
    "patreon",
    "open_collective",
    "ko_fi",
    "tidelift",
    "community_bridge",
    "liberapay",
    "issuehunt",
    "lfx_crowdfunding",
    "polar",
    "buy_me_a_coffee",
    "thanks_dev",
    "custom",
})
_PLACEHOLDER_FUNDING_VALUES = frozenset({
    "placeholder",
    "example",
    "tbd",
    "todo",
    "replace-me",
    "changeme",
})
_PLACEHOLDER_HOSTS = frozenset({"example.com", "example.org", "example.net"})
INACTIVE_SPONSORSHIP_STATUS = "Status: inactive pending a verified funding destination."
ACTIVE_SPONSORSHIP_STATUS = "Status: active with a verified funding destination."

_TIDELIFT_PLATFORMS = frozenset({
    "npm",
    "pypi",
    "rubygems",
    "maven",
    "packagist",
    "nuget",
})
_SINGLE_DESTINATION_FUNDING_KEYS = SUPPORTED_FUNDING_KEYS - {"github", "custom"}


def _strip_yaml_comment(value: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote == '"':
            escaped = True
            continue
        if char in {"'", '"'}:
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
            continue
        if char == "#" and quote is None:
            return value[:index].rstrip()
    return value.rstrip()


def _unquote_yaml_scalar(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {"'", '"'}:
        return stripped[1:-1].strip()
    return stripped


def _split_inline_yaml_list(value: str) -> list[str]:
    inner = value.strip()[1:-1]
    items: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for char in inner:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and quote == '"':
            current.append(char)
            escaped = True
            continue
        if char in {"'", '"'}:
            current.append(char)
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
            continue
        if char == "," and quote is None:
            items.append(_unquote_yaml_scalar("".join(current)))
            current = []
            continue
        current.append(char)
    if current or inner.strip():
        items.append(_unquote_yaml_scalar("".join(current)))
    return items


def _top_level_yaml_entries(text: str) -> list[tuple[str, str, list[str]]]:
    entries: list[tuple[str, str, list[str]]] = []
    lines = text.splitlines()
    active_indents = [
        len(raw) - len(raw.lstrip(" "))
        for raw in lines
        if raw.strip() and not raw.lstrip().startswith("#")
    ]
    root_indent = min(active_indents, default=0)
    normalized = [
        raw
        if not raw.strip() or raw.lstrip().startswith("#")
        else raw[root_indent:]
        if len(raw) >= root_indent
        else raw
        for raw in lines
    ]

    index = 0
    while index < len(normalized):
        raw = normalized[index]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        if raw[:1].isspace():
            entries.append(("", stripped, []))
            index += 1
            continue
        active = _strip_yaml_comment(raw).strip()
        match = re.fullmatch(r"([A-Za-z0-9_-]+)\s*:\s*(.*)", active)
        if match is None:
            entries.append(("", active, []))
            index += 1
            continue
        key, scalar = match.group(1), match.group(2).strip()
        children: list[str] = []
        cursor = index + 1
        while cursor < len(normalized):
            child_raw = normalized[cursor]
            child_stripped = child_raw.strip()
            if not child_stripped or child_stripped.startswith("#"):
                cursor += 1
                continue
            if not child_raw[:1].isspace():
                break
            child_active = _strip_yaml_comment(child_stripped).strip()
            if child_active.startswith("- "):
                item = _unquote_yaml_scalar(child_active[2:])
                if item:
                    children.append(item)
            cursor += 1
        entries.append((key, scalar, children))
        index = cursor
    return entries


def _yaml_scalar_syntax_failures(text: str, *, label: str) -> list[str]:
    failures: list[str] = []
    block_scalar_indent: int | None = None
    simple_double_escapes = frozenset('0abtnvfre "/\\N_LP')
    hex_escape_widths = {"x": 2, "u": 4, "U": 8}

    for line_number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        prefix = raw[: len(raw) - len(raw.lstrip())]
        if "\t" in prefix:
            failures.append(f"{label} line {line_number} must use spaces for indentation")
            continue

        indent = len(raw) - len(raw.lstrip(" "))
        if block_scalar_indent is not None and indent > block_scalar_indent:
            continue
        block_scalar_indent = None

        active = _strip_yaml_comment(raw).strip()
        if not active:
            continue
        candidate = active[2:].strip() if active.startswith("- ") else active
        if ":" in candidate:
            candidate = candidate.split(":", 1)[1].strip()
        if not candidate:
            continue
        if candidate in {"|", ">"}:
            block_scalar_indent = indent
            continue

        if candidate.startswith("[") and not candidate.endswith("]"):
            failures.append(
                f"{label} line {line_number} has an unterminated inline YAML sequence"
            )
            continue
        if candidate.startswith("{") and not candidate.endswith("}"):
            failures.append(
                f"{label} line {line_number} has an unterminated inline YAML mapping"
            )
            continue

        if candidate[0] not in {"'", '"'}:
            if re.search(r":(?:\s|$)", candidate):
                failures.append(
                    f"{label} line {line_number} contains an unquoted YAML mapping delimiter"
                )
            continue

        quote = candidate[0]
        closed_at: int | None = None
        invalid_escape = False
        index = 1
        while index < len(candidate):
            char = candidate[index]
            if quote == '"' and char == "\\":
                if index + 1 >= len(candidate):
                    failures.append(
                        f"{label} line {line_number} has an invalid double-quoted YAML escape"
                    )
                    invalid_escape = True
                    break
                escape = candidate[index + 1]
                if escape in simple_double_escapes:
                    index += 2
                    continue
                width = hex_escape_widths.get(escape)
                if width is not None:
                    digits = candidate[index + 2 : index + 2 + width]
                    if len(digits) != width or re.fullmatch(r"[0-9A-Fa-f]+", digits) is None:
                        failures.append(
                            f"{label} line {line_number} has an invalid double-quoted YAML escape"
                        )
                        invalid_escape = True
                        break
                    index += 2 + width
                    continue
                failures.append(
                    f"{label} line {line_number} has an invalid double-quoted YAML escape"
                )
                invalid_escape = True
                break
            if char == quote:
                if quote == "'" and index + 1 < len(candidate) and candidate[index + 1] == "'":
                    index += 2
                    continue
                closed_at = index
                break
            index += 1

        if invalid_escape:
            continue
        if closed_at is None:
            failures.append(
                f"{label} line {line_number} has an unterminated quoted YAML scalar"
            )
            continue
        if candidate[closed_at + 1 :].strip():
            failures.append(
                f"{label} line {line_number} has trailing content after a quoted YAML scalar"
            )

    return failures


def _funding_yaml_structure_failures(text: str) -> list[str]:
    failures: list[str] = []
    lines = text.splitlines()
    active_indents = [
        len(raw) - len(raw.lstrip(" "))
        for raw in lines
        if raw.strip() and not raw.lstrip().startswith("#")
    ]
    root_indent = min(active_indents, default=0)
    current_key: str | None = None
    current_has_scalar = False
    child_indent: int | None = None

    for line_number, original in enumerate(lines, start=1):
        if not original.strip() or original.lstrip().startswith("#"):
            continue
        raw = original[root_indent:] if len(original) >= root_indent else original
        indent = len(raw) - len(raw.lstrip(" "))
        active = _strip_yaml_comment(raw).strip()
        if not active:
            continue

        if indent == 0:
            match = re.fullmatch(r"([A-Za-z0-9_-]+)\s*:\s*(.*)", active)
            if match is None:
                failures.append(
                    f"FUNDING.yml line {line_number} is malformed"
                )
                current_key = None
                child_indent = None
                continue
            current_key = match.group(1)
            current_has_scalar = bool(match.group(2).strip())
            child_indent = None
            continue

        if current_key is None or current_has_scalar:
            failures.append(
                f"FUNDING.yml line {line_number} has an unexpected indented child"
            )
            continue
        if child_indent is None:
            child_indent = indent
        elif indent != child_indent:
            failures.append(
                f"FUNDING.yml line {line_number} has inconsistent child indentation"
            )
            continue
        match = re.fullmatch(r"-\s+(.+)", active)
        if match is None or not _unquote_yaml_scalar(match.group(1)).strip():
            failures.append(
                f"FUNDING.yml line {line_number} has a malformed funding list child"
            )

    return failures


def _effective_top_level_scalars(
    text: str, *, label: str, required: set[str]
) -> tuple[dict[str, str], list[str]]:
    failures = _yaml_scalar_syntax_failures(text, label=label)
    values: dict[str, str] = {}
    for key, scalar, _children in _top_level_yaml_entries(text):
        if not key:
            failures.append(f"{label} contains malformed top-level YAML")
            continue
        if key not in required:
            continue
        if key in values:
            failures.append(f"{label} contains duplicate top-level key: {key}")
            continue
        value = _unquote_yaml_scalar(_strip_yaml_comment(scalar).strip())
        if not value:
            failures.append(f"{label} top-level field {key} must be nonempty")
            continue
        values[key] = value
    return values, failures

def _validate_issue_form_yaml(text: str, rel: str) -> list[str]:
    failures = _yaml_scalar_syntax_failures(text, label=f"issue form {rel}")
    if failures:
        return failures

    active_lines = [
        raw
        for raw in text.splitlines()
        if raw.strip() and not raw.lstrip().startswith("#")
    ]
    if not active_lines:
        return [f"issue form {rel} is empty"]

    root_indent = min(len(raw) - len(raw.lstrip(" ")) for raw in active_lines)
    lines = [
        (line_number, raw[root_indent:])
        for line_number, raw in enumerate(text.splitlines(), start=1)
        if raw.strip() and not raw.lstrip().startswith("#")
    ]

    allowed_root = {"name", "description", "title", "labels", "assignees", "body"}
    allowed_types = {"markdown", "input", "textarea", "dropdown", "checkboxes"}
    seen_root: set[str] = set()
    body_items: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    section: str | None = None
    nested: str | None = None
    block_scalar_indent: int | None = None

    for line_number, raw in lines:
        indent = len(raw) - len(raw.lstrip(" "))
        active = _strip_yaml_comment(raw).strip()
        if not active:
            continue

        if block_scalar_indent is not None and indent > block_scalar_indent:
            continue
        block_scalar_indent = None

        if indent == 0:
            match = re.fullmatch(r"([A-Za-z0-9_-]+)\s*:\s*(.*)", active)
            if match is None:
                failures.append(f"issue form {rel} line {line_number} is malformed YAML")
                section = None
                current = None
                continue
            key, scalar = match.group(1), match.group(2).strip()
            if key not in allowed_root:
                failures.append(f"issue form {rel} has unsupported top-level key: {key}")
            if key in seen_root:
                failures.append(f"issue form {rel} contains duplicate top-level key: {key}")
            seen_root.add(key)
            current = None
            nested = None
            if key in {"body", "labels", "assignees"}:
                section = key
                if scalar and scalar != "[]":
                    failures.append(
                        f"issue form {rel} top-level {key} must use a block sequence"
                    )
            else:
                section = None
                if not scalar:
                    failures.append(f"issue form {rel} requires nonempty {key}")
                elif key in {"name", "description", "title"}:
                    _unquote_yaml_scalar(scalar)
            continue

        if section in {"labels", "assignees"}:
            if indent != 2 or not active.startswith("- "):
                failures.append(
                    f"issue form {rel} line {line_number} has invalid {section} structure"
                )
            elif not _unquote_yaml_scalar(active[2:]).strip():
                failures.append(
                    f"issue form {rel} line {line_number} has empty {section} entry"
                )
            continue

        if section != "body":
            failures.append(
                f"issue form {rel} line {line_number} has unexpected indentation"
            )
            continue

        if indent == 2:
            match = re.fullmatch(r"-\s+type\s*:\s*(.+)", active)
            if match is None:
                failures.append(
                    f"issue form {rel} line {line_number} must start a body item with '- type:'"
                )
                current = None
                nested = None
                continue
            item_type = _unquote_yaml_scalar(match.group(1))
            if item_type not in allowed_types:
                failures.append(
                    f"issue form {rel} line {line_number} has unsupported body type: {item_type!r}"
                )
            current = {"type": item_type, "id": None, "attributes": set(), "required": None}
            body_items.append(current)
            nested = None
            continue

        if current is None:
            failures.append(
                f"issue form {rel} line {line_number} appears outside a body item"
            )
            continue

        if indent == 4:
            match = re.fullmatch(r"([A-Za-z0-9_-]+)\s*:\s*(.*)", active)
            if match is None:
                failures.append(f"issue form {rel} line {line_number} is malformed YAML")
                continue
            key, scalar = match.group(1), match.group(2).strip()
            if key == "id":
                if not scalar:
                    failures.append(f"issue form {rel} body item id must be nonempty")
                else:
                    current["id"] = _unquote_yaml_scalar(scalar)
                nested = None
            elif key in {"attributes", "validations"}:
                if scalar:
                    failures.append(
                        f"issue form {rel} body item {key} must be a mapping"
                    )
                nested = key
            else:
                failures.append(
                    f"issue form {rel} line {line_number} has unsupported body key: {key}"
                )
                nested = None
            continue

        if indent == 6 and nested in {"attributes", "validations"}:
            match = re.fullmatch(r"([A-Za-z0-9_-]+)\s*:\s*(.*)", active)
            if match is None:
                failures.append(f"issue form {rel} line {line_number} is malformed YAML")
                continue
            key, scalar = match.group(1), match.group(2).strip()
            if nested == "attributes":
                attributes = current["attributes"]
                assert isinstance(attributes, set)
                attributes.add(key)
                if scalar in {"|", ">"}:
                    block_scalar_indent = indent
                elif not scalar:
                    failures.append(
                        f"issue form {rel} body attribute {key} must be nonempty"
                    )
                else:
                    _unquote_yaml_scalar(scalar)
            else:
                if key != "required":
                    failures.append(
                        f"issue form {rel} has unsupported validation key: {key}"
                    )
                elif scalar.lower() not in {"true", "false"}:
                    failures.append(
                        f"issue form {rel} validations.required must be boolean"
                    )
                else:
                    current["required"] = scalar.lower() == "true"
            continue

        failures.append(
            f"issue form {rel} line {line_number} has invalid structure or indentation"
        )

    for key in ("name", "description", "body"):
        if key not in seen_root:
            failures.append(f"issue form {rel} is missing required top-level key: {key}")
    if not body_items:
        failures.append(f"issue form {rel} requires at least one body item")

    seen_ids: set[str] = set()
    for index, item in enumerate(body_items, start=1):
        item_type = item["type"]
        attributes = item["attributes"]
        assert isinstance(attributes, set)
        if item_type == "markdown":
            if "value" not in attributes:
                failures.append(
                    f"issue form {rel} markdown item {index} requires attributes.value"
                )
            continue

        item_id = item["id"]
        if not isinstance(item_id, str) or re.fullmatch(r"[A-Za-z0-9_-]+", item_id) is None:
            failures.append(f"issue form {rel} body item {index} requires a stable id")
        elif item_id in seen_ids:
            failures.append(f"issue form {rel} contains duplicate body id: {item_id}")
        else:
            seen_ids.add(item_id)
        if "label" not in attributes:
            failures.append(
                f"issue form {rel} body item {index} requires attributes.label"
            )

    return failures

def _validate_issue_config_yaml(
    text: str,
    *,
    required_urls: dict[str, str] | None = None,
) -> list[str]:
    failures: list[str] = _yaml_scalar_syntax_failures(
        text, label="issue routing YAML"
    )
    if failures:
        return failures
    seen_top_level: set[str] = set()
    contact_links: list[dict[str, str]] = []
    current_link: dict[str, str] | None = None
    section: str | None = None

    for line_number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            failures.append(
                f"issue routing YAML line {line_number} must use spaces for indentation"
            )
            continue

        indent = len(raw) - len(raw.lstrip(" "))
        active = _strip_yaml_comment(raw).strip()
        if not active:
            continue

        if indent == 0:
            match = re.fullmatch(r"([A-Za-z0-9_-]+)\s*:\s*(.*)", active)
            if match is None:
                failures.append(
                    f"issue routing YAML line {line_number} is malformed: {active!r}"
                )
                section = None
                current_link = None
                continue
            key, scalar = match.group(1), match.group(2).strip()
            if key not in {"blank_issues_enabled", "contact_links"}:
                failures.append(
                    f"issue routing YAML line {line_number} has unsupported top-level key: {key}"
                )
            if key in seen_top_level:
                failures.append(
                    f"issue routing YAML contains duplicate top-level key: {key}"
                )
            seen_top_level.add(key)
            current_link = None

            if key == "blank_issues_enabled":
                section = None
                if scalar.lower() not in {"true", "false"}:
                    failures.append(
                        "issue routing blank_issues_enabled must be an explicit YAML boolean"
                    )
            elif key == "contact_links":
                section = "contact_links"
                if scalar:
                    failures.append(
                        "issue routing contact_links must be a block sequence"
                    )
            continue

        if indent == 2 and section == "contact_links":
            match = re.fullmatch(r"-\s+name\s*:\s*(.+)", active)
            if match is None:
                failures.append(
                    f"issue routing YAML line {line_number} must start a contact link with '- name:'"
                )
                current_link = None
                continue
            name = _unquote_yaml_scalar(match.group(1))
            if not name:
                failures.append(
                    f"issue routing YAML line {line_number} has an empty contact link name"
                )
                current_link = None
                continue
            current_link = {"name": name}
            contact_links.append(current_link)
            continue

        if indent == 4 and section == "contact_links" and current_link is not None:
            match = re.fullmatch(r"([A-Za-z0-9_-]+)\s*:\s*(.*)", active)
            if match is None:
                failures.append(
                    f"issue routing YAML line {line_number} is malformed: {active!r}"
                )
                continue
            key, scalar = match.group(1), _unquote_yaml_scalar(match.group(2))
            if key not in {"url", "about"}:
                failures.append(
                    f"issue routing YAML line {line_number} has unsupported contact-link key: {key}"
                )
                continue
            if key in current_link:
                failures.append(
                    f"issue routing YAML contact link contains duplicate key: {key}"
                )
                continue
            if not scalar:
                failures.append(
                    f"issue routing YAML contact link {key} must be nonempty"
                )
                continue
            current_link[key] = scalar
            continue

        failures.append(
            f"issue routing YAML line {line_number} has invalid structure or indentation"
        )

    if "blank_issues_enabled" not in seen_top_level:
        failures.append("issue routing YAML is missing blank_issues_enabled")
    if "contact_links" not in seen_top_level:
        failures.append("issue routing YAML is missing contact_links")
    if not contact_links:
        failures.append("issue routing YAML requires at least one contact link")
    for index, link in enumerate(contact_links, start=1):
        missing = {"name", "url", "about"} - set(link)
        if missing:
            failures.append(
                f"issue routing YAML contact link {index} is missing: {', '.join(sorted(missing))}"
            )

    if required_urls:
        parsed_urls = {
            link["url"]
            for link in contact_links
            if isinstance(link.get("url"), str)
        }
        for key, expected in required_urls.items():
            if expected not in parsed_urls:
                failures.append(
                    f"issue routing parsed contact links missing canonical {key} URL: {expected}"
                )

    return failures


def _funding_destinations(scalar: str, children: list[str]) -> list[str]:
    if children:
        return children
    value = _strip_yaml_comment(scalar).strip()
    if not value or value in {"[]", "null", "~"}:
        return []
    if value.startswith("[") and value.endswith("]"):
        return _split_inline_yaml_list(value)
    return [_unquote_yaml_scalar(value)]


def _github_login_is_valid(value: str) -> bool:
    return (
        len(value) <= 39
        and re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9]))*",
            value,
        )
        is not None
    )


def _valid_funding_destination(key: str, destination: str) -> bool:
    value = destination.strip()
    if not value or value.lower() in _PLACEHOLDER_FUNDING_VALUES:
        return False

    if key == "custom":
        parsed = urlparse(value)
        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.netloc)
            and parsed.hostname not in _PLACEHOLDER_HOSTS
            and not parsed.username
            and not parsed.password
        )

    if key == "github":
        return _github_login_is_valid(value)

    if key == "tidelift":
        platform, separator, package = value.partition("/")
        return (
            separator == "/"
            and platform in _TIDELIFT_PLATFORMS
            and bool(package)
            and not package.startswith("/")
            and not package.endswith("/")
            and not any(char.isspace() for char in package)
            and not package.startswith(("http://", "https://"))
        )

    if key == "thanks_dev":
        prefix = "u/gh/"
        return value.startswith(prefix) and _github_login_is_valid(value[len(prefix) :])

    return (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", value) is not None
        and not value.startswith(("http://", "https://"))
    )


def _funding_cardinality_is_valid(key: str, destinations: list[str]) -> bool:
    if key in {"github", "custom"}:
        return 1 <= len(destinations) <= 4
    if key in _SINGLE_DESTINATION_FUNDING_KEYS:
        return len(destinations) == 1
    return False

def read_text(root: Path, rel: str) -> str:
    path = root / rel
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def validate(root: Path) -> list[str]:
    failures: list[str] = []

    contract_path = root / "contracts/community.toml"
    if not contract_path.is_file():
        return ["missing required file: contracts/community.toml"]

    try:
        contract = tomllib.loads(contract_path.read_text(encoding="utf-8"))
    except Exception as error:
        return [f"invalid contracts/community.toml: {error}"]

    for rel in REQUIRED_FILES:
        if not (root / rel).is_file():
            failures.append(f"missing community file: {rel}")

    for rel, markers in REQUIRED_MARKERS.items():
        text = read_text(root, rel)
        for marker in markers:
            if marker not in text:
                failures.append(f"community marker missing: {rel} -> {marker!r}")

    for rel in ("README.md", "CONTRIBUTING.md", "SECURITY.md", "SUPPORT.md"):
        lowered = read_text(root, rel).lower()
        for stale in STALE_HOSTING_LANGUAGE:
            if stale in lowered:
                failures.append(f"stale hosted-state language: {rel} -> {stale!r}")

    channels = contract.get("channels", {})
    readme = read_text(root, "README.md")
    support = read_text(root, "SUPPORT.md")
    security = read_text(root, "SECURITY.md")
    conduct = read_text(root, "CODE_OF_CONDUCT.md")
    settings = read_text(root, "docs/community/repository-settings.md")
    labels_doc = read_text(root, "docs/community/labels.md")

    for key in ("website", "repository", "discussions", "issues", "security_policy", "releases"):
        value = channels.get(key)
        if not isinstance(value, str) or not value:
            failures.append(f"community channel missing from contract: {key}")

    for key in ("website", "discussions", "issues", "security_policy", "releases"):
        value = channels.get(key)
        if isinstance(value, str) and value not in readme:
            failures.append(f"README missing canonical channel URL: {key} -> {value}")

    security_email = channels.get("security_email")
    if isinstance(security_email, str) and security_email not in security:
        failures.append("SECURITY.md does not contain the canonical security email")

    conduct_email = channels.get("conduct_email")
    if isinstance(conduct_email, str) and conduct_email not in conduct:
        failures.append("CODE_OF_CONDUCT.md does not contain the canonical conduct email")

    governance = contract.get("governance", {})
    governance_text = read_text(root, "GOVERNANCE.md")
    for maintainer in governance.get("current_maintainers", []):
        if maintainer not in governance_text:
            failures.append(f"current maintainer missing from GOVERNANCE.md: {maintainer}")

    if governance.get("inbound_license") != "Apache-2.0":
        failures.append("community contract inbound license must remain Apache-2.0 unless governance is deliberately changed")
    if "Apache-2.0" not in read_text(root, "CONTRIBUTING.md"):
        failures.append("CONTRIBUTING.md must state the inbound Apache-2.0 policy")

    issue_config = read_text(root, ".github/ISSUE_TEMPLATE/config.yml")
    canonical_issue_urls = {
        key: value
        for key in ("discussions", "security_policy")
        if isinstance((value := channels.get(key)), str) and value
    }
    failures.extend(
        _validate_issue_config_yaml(
            issue_config,
            required_urls=canonical_issue_urls,
        )
    )
    for issue_form in (
        ".github/ISSUE_TEMPLATE/bug.yml",
        ".github/ISSUE_TEMPLATE/feature.yml",
        ".github/ISSUE_TEMPLATE/compatibility.yml",
        ".github/ISSUE_TEMPLATE/rfc.yml",
    ):
        failures.extend(_validate_issue_form_yaml(read_text(root, issue_form), issue_form))
    issue_entries = [
        (key, scalar)
        for key, scalar, _children in _top_level_yaml_entries(issue_config)
        if key == "blank_issues_enabled"
    ]
    if len(issue_entries) != 1 or issue_entries[0][1].strip().lower() != "false":
        failures.append("issue routing must keep blank issues disabled as the effective YAML setting")

    required_categories = contract.get("discussion_categories", {}).get("required", [])
    for category in required_categories:
        if category not in settings:
            failures.append(f"repository settings missing Discussion category: {category}")

    required_labels = contract.get("labels", {}).get("required", [])
    for label in required_labels:
        if label not in settings:
            failures.append(f"repository settings missing required label: {label}")
        if label not in labels_doc:
            failures.append(f"label documentation missing required label: {label}")

    repository_settings = contract.get("repository_settings", {})
    expected_settings = {
        "discussions": True,
        "wiki": False,
        "private_vulnerability_reporting": True,
        "organization_community_profile": True,
    }
    for key, expected in expected_settings.items():
        if repository_settings.get(key) is not expected:
            failures.append(f"community contract repository setting {key} must be {expected!r}")

    funding = contract.get("funding", {})
    funding_active = funding.get("active")
    funding_text = read_text(root, ".github/FUNDING.yml")
    failures.extend(_yaml_scalar_syntax_failures(funding_text, label="FUNDING.yml"))
    failures.extend(_funding_yaml_structure_failures(funding_text))
    funding_entries = _top_level_yaml_entries(funding_text)
    sponsorship = read_text(root, "docs/community/sponsorship.md")
    sponsorship_statuses = [
        line.strip()
        for line in sponsorship.splitlines()
        if line.strip().startswith("Status:")
    ]
    if funding_active is False:
        if funding_entries:
            failures.append("FUNDING.yml activates a destination while community contract funding.active=false")
        if sponsorship_statuses != [INACTIVE_SPONSORSHIP_STATUS]:
            failures.append(
                "inactive funding contract requires exactly the canonical inactive sponsorship status"
            )
    elif funding_active is True:
        if not funding_entries:
            failures.append("funding.active=true requires an active FUNDING.yml destination")
        valid_destinations = 0
        seen_funding_keys: set[str] = set()
        for key, scalar, children in funding_entries:
            if not key or key not in SUPPORTED_FUNDING_KEYS:
                failures.append(f"FUNDING.yml contains unsupported funding key: {key or scalar!r}")
                continue
            if key in seen_funding_keys:
                failures.append(f"FUNDING.yml contains duplicate funding key: {key}")
                continue
            seen_funding_keys.add(key)
            destinations = _funding_destinations(scalar, children)
            if not destinations:
                failures.append(f"FUNDING.yml funding key {key} requires a nonempty destination")
                continue
            if not _funding_cardinality_is_valid(key, destinations):
                if key in {"github", "custom"}:
                    failures.append(
                        f"FUNDING.yml funding key {key} supports between one and four destinations"
                    )
                else:
                    failures.append(
                        f"FUNDING.yml funding key {key} requires exactly one destination"
                    )
                continue
            invalid = [value for value in destinations if not _valid_funding_destination(key, value)]
            if invalid:
                failures.append(f"FUNDING.yml funding key {key} contains an invalid destination")
                continue
            valid_destinations += len(destinations)
        if valid_destinations == 0:
            failures.append("funding.active=true requires at least one supported usable FUNDING.yml destination")
        if sponsorship_statuses != [ACTIVE_SPONSORSHIP_STATUS]:
            failures.append(
                "active funding contract requires exactly the canonical active sponsorship status"
            )
    else:
        failures.append("community contract funding.active must be boolean")

    if "security vulnerability" not in support.lower():
        failures.append("SUPPORT.md must explicitly route security vulnerabilities")
    if "sponsorship" not in governance_text.lower():
        failures.append("GOVERNANCE.md must define sponsorship/conflict boundaries")

    citation = read_text(root, "CITATION.cff")
    citation_expected = {
        "cff-version": "1.2.0",
        "title": "Linura",
        "license": "Apache-2.0",
        "repository-code": "https://github.com/linura-org/linura",
    }
    citation_values, citation_failures = _effective_top_level_scalars(
        citation,
        label="CITATION.cff",
        required=set(citation_expected),
    )
    failures.extend(citation_failures)
    for key, expected in citation_expected.items():
        actual = citation_values.get(key)
        if actual != expected:
            failures.append(
                f"CITATION.cff effective {key} must be {expected!r}; got {actual!r}"
            )

    return failures


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else ROOT
    failures = validate(root)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("community contract checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
