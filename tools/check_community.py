#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import sys
import tomllib

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
    if "blank_issues_enabled: false" not in issue_config:
        failures.append("issue routing must keep blank issues disabled")
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
    active_funding_lines = [
        line for line in funding_text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    sponsorship = read_text(root, "docs/community/sponsorship.md")
    if funding_active is False:
        if active_funding_lines:
            failures.append("FUNDING.yml activates a destination while community contract funding.active=false")
        if "Status: inactive" not in sponsorship:
            failures.append("inactive funding contract requires explicit inactive sponsorship status")
    elif funding_active is True:
        if not active_funding_lines:
            failures.append("funding.active=true requires an active FUNDING.yml destination")
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
