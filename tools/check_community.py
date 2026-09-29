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
    return [item for item in items if item]


def _top_level_yaml_entries(text: str) -> list[tuple[str, str, list[str]]]:
    entries: list[tuple[str, str, list[str]]] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        if not stripped or raw[:1].isspace() or stripped.startswith("#"):
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
        while cursor < len(lines):
            child_raw = lines[cursor]
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


def _funding_destinations(scalar: str, children: list[str]) -> list[str]:
    if children:
        return children
    value = _strip_yaml_comment(scalar).strip()
    if not value or value in {"[]", "null", "~"}:
        return []
    if value.startswith("[") and value.endswith("]"):
        return _split_inline_yaml_list(value)
    return [_unquote_yaml_scalar(value)]


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
        )
    return (
        not any(char.isspace() for char in value)
        and value not in {"-", "_"}
        and not value.startswith(("http://", "https://"))
    )


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
    issue_entries = [
        (key, scalar)
        for key, scalar, _children in _top_level_yaml_entries(issue_config)
        if key == "blank_issues_enabled"
    ]
    if len(issue_entries) != 1 or issue_entries[0][1].strip().lower() != "false":
        failures.append("issue routing must keep blank issues disabled as the effective YAML setting")
    for key in ("discussions", "security_policy"):
        value = channels.get(key)
        if isinstance(value, str) and value not in issue_config:
            failures.append(f"issue routing missing canonical {key} link")

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
    funding_entries = _top_level_yaml_entries(funding_text)
    sponsorship = read_text(root, "docs/community/sponsorship.md")
    if funding_active is False:
        if funding_entries:
            failures.append("FUNDING.yml activates a destination while community contract funding.active=false")
        if "Status: inactive" not in sponsorship:
            failures.append("inactive funding contract requires explicit inactive sponsorship status")
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
            invalid = [value for value in destinations if not _valid_funding_destination(key, value)]
            if invalid:
                failures.append(f"FUNDING.yml funding key {key} contains an invalid destination")
                continue
            valid_destinations += len(destinations)
        if valid_destinations == 0:
            failures.append("funding.active=true requires at least one supported usable FUNDING.yml destination")
        if "Status: inactive" in sponsorship:
            failures.append("active funding contract cannot retain inactive sponsorship status")
    else:
        failures.append("community contract funding.active must be boolean")

    if "security vulnerability" not in support.lower():
        failures.append("SUPPORT.md must explicitly route security vulnerabilities")
    if "sponsorship" not in governance_text.lower():
        failures.append("GOVERNANCE.md must define sponsorship/conflict boundaries")

    citation = read_text(root, "CITATION.cff")
    for marker in ("cff-version: 1.2.0", 'title: "Linura"', 'license: "Apache-2.0"', "repository-code:"):
        if marker not in citation:
            failures.append(f"CITATION.cff missing required marker: {marker!r}")

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
