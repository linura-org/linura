#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path
import tomllib

TAG_RE = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_URL = "https://github.com/linura-org/linura"


class TerminalSyncError(RuntimeError):
    pass


def read(path: Path) -> str:
    if not path.is_file():
        raise TerminalSyncError(f"required file is missing: {path}")
    return path.read_text(encoding="utf-8")


def write_if_changed(path: Path, content: str, changed: list[str], root: Path) -> None:
    old = path.read_text(encoding="utf-8") if path.exists() else None
    if old == content:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    changed.append(path.relative_to(root).as_posix())


def _roadmap(root: Path, tag: str) -> tuple[dict[str, object], dict[str, object], str]:
    contract = tomllib.loads(read(root / "contracts/roadmap.toml"))
    if contract.get("current_release") != tag:
        raise TerminalSyncError(
            f"terminal sync requires current_release={tag}, found {contract.get('current_release')!r}"
        )
    milestones = contract.get("milestone")
    if not isinstance(milestones, list):
        raise TerminalSyncError("roadmap milestone array is missing")
    target_index = next((i for i, item in enumerate(milestones) if item.get("version") == tag), None)
    if target_index is None:
        raise TerminalSyncError(f"roadmap milestone is missing: {tag}")
    target = milestones[target_index]
    if target.get("status") != "released":
        raise TerminalSyncError(f"terminal sync requires released milestone: {tag}")
    next_release = contract.get("next_release")
    if not isinstance(next_release, str) or not TAG_RE.fullmatch(next_release):
        raise TerminalSyncError(f"invalid roadmap next_release: {next_release!r}")
    if target_index + 1 >= len(milestones) or milestones[target_index + 1].get("version") != next_release:
        raise TerminalSyncError("next_release must be the milestone immediately after the current release")
    return contract, target, next_release


def normalize_milestone_terminal_prose(text: str, tag: str) -> str:
    section = re.search(r"(?ms)^## (?:Release gate|Exit criteria)\s*\n(?P<body>.*?)(?=^## |\Z)", text)
    if section is None:
        raise TerminalSyncError(f"{tag} milestone has no release gate")
    body = section.group("body")
    if re.search(r"(?m)^\s*-\s+\[ \]", body):
        raise TerminalSyncError(f"{tag} milestone still contains unchecked release-gate criteria")

    paragraphs = re.split(r"(\n\s*\n)", body)
    replaced = False
    for i, paragraph in enumerate(paragraphs):
        if "remaining unchecked criteria" in paragraph.casefold():
            paragraphs[i] = (
                "All release-gate criteria above are now complete. The pre-publication criteria remain "
                "historical release evidence, while immutable publication, independent verification and "
                "protected post-release closure are recorded as completed terminal evidence."
            )
            replaced = True
    updated_body = "".join(paragraphs)
    if "remaining unchecked criteria" in updated_body.casefold():
        raise TerminalSyncError(f"{tag} milestone retains contradictory unchecked-criteria prose")
    if not replaced and "post-release closure" not in updated_body.casefold():
        raise TerminalSyncError(f"{tag} milestone lacks terminal closure explanation")
    return text[: section.start("body")] + updated_body + text[section.end("body") :]


def _terminal_evidence_row(line: str) -> bool:
    lower = line.casefold()
    markers = (
        "trusted release proof",
        "release verification",
        "independent verification",
        "release provenance",
        "publication",
        "inherited v0.6 evidence",
    )
    return any(marker in lower for marker in markers)


def normalize_qualification_terminal_state(text: str, tag: str) -> str:
    status_pattern = re.compile(r"(?m)^\*\*(?P<label>State|Status):\*\* .+$")
    matches = list(status_pattern.finditer(text))
    if len(matches) != 1:
        raise TerminalSyncError(f"{tag} qualification must contain exactly one State/Status field")
    match = matches[0]
    label = match.group("label")
    terminal = f"**{label}:** released; terminal publication and independent verification complete"
    text = text[: match.start()] + terminal + text[match.end() :]

    matrix = re.search(r"(?ms)^## Qualification matrix\s*\n(?P<body>.*?)(?=^## |\Z)", text)
    if matrix is not None:
        lines = matrix.group("body").splitlines(keepends=True)
        for index, line in enumerate(lines):
            if not line.lstrip().startswith("|") or "pending" not in line.casefold():
                continue
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if not cells or cells[-1].casefold() != "pending":
                continue
            if not _terminal_evidence_row(line):
                raise TerminalSyncError(
                    f"{tag} qualification contains an unrecognized pending terminal row: {line.strip()}"
                )
            cells[-1] = "qualified"
            newline = "\n" if line.endswith("\n") else ""
            lines[index] = "| " + " | ".join(cells) + " |" + newline
        body = "".join(lines)
        if re.search(r"(?im)^\|.*\|\s*pending\s*\|\s*$", body):
            raise TerminalSyncError(f"{tag} qualification matrix still contains pending terminal rows")
        text = text[: matrix.start("body")] + body + text[matrix.end("body") :]

    return text


def _documentation_links(root: Path, tag: str) -> list[str]:
    candidates = [
        (f"docs/milestones/{tag}.md", "milestone contract"),
        (f"docs/qualification/{tag}.md", "qualification dossier"),
        (f"docs/qualification/{tag}-security.md", "security qualification"),
        (f"docs/qualification/{tag}-release-review.md", "release-preparation review"),
        (f"docs/qualification/{tag}-publication.md", "publication evidence"),
        (f"docs/releases/{tag}.md", "frozen release contract"),
        (f"docs/releases/published-{tag}.md", "terminal release record"),
    ]
    links: list[str] = []
    for path, label in candidates:
        if (root / path).exists() or path.endswith(f"published-{tag}.md"):
            relative = path.removeprefix("docs/")
            links.append(f"- [{tag} {label}]({relative})")
    return links


def update_docs_index(text: str, root: Path, tag: str) -> str:
    pattern = re.compile(
        r"(?ms)^### Current (?P<old>v\d+\.\d+\.\d+) documentation set\n"
        r"(?P<current>.*?)(?=^### Prior release documentation\n)"
    )
    match = pattern.search(text)
    if match is None:
        raise TerminalSyncError("docs/index.md current-release section is missing")
    old_tag = match.group("old")
    old_lines = [line for line in match.group("current").splitlines() if line.startswith("- [")]
    current_block = f"### Current {tag} documentation set\n" + "\n".join(_documentation_links(root, tag)) + "\n\n"
    text = text[: match.start()] + current_block + text[match.end() :]

    prior = re.search(r"(?ms)^### Prior release documentation\n(?P<body>.*?)(?=^## |\Z)", text)
    if prior is None:
        raise TerminalSyncError("docs/index.md prior-release section is missing")
    body = prior.group("body")
    if old_tag != tag:
        existing = set(line for line in body.splitlines() if line.startswith("- ["))
        additions = [line for line in old_lines if line not in existing]
        if additions:
            body = "\n" + "\n".join(additions) + body.lstrip("\n")
    return text[: prior.start("body")] + body + text[prior.end("body") :]


def published_record(args: argparse.Namespace, milestone: dict[str, object], next_release: str) -> str:
    source = f"{REPOSITORY_URL}/commit/{args.source_sha}"
    return f"""# Linura {args.tag} — terminal release record

**Status:** released; immutable GitHub Release published and independently verified.
**Claim class:** {milestone.get('claim_class')}
**Published:** {args.published_at}
**Release ID:** `{args.release_id}`
**Release source:** `{args.source_sha}`

## Release outcome

Linura {args.tag} released **{milestone.get('title')}** within its frozen {milestone.get('claim_class')} claim. The release does not widen the authority boundary defined by the canonical roadmap or frozen release contract.

## Publication and verification

The repository-defined proof-first/tag-last lifecycle completed successfully:

- Trusted Release Proof: run `{args.proof_run_id}` — success;
- Release Promotion: run `{args.promotion_run_id}` — success;
- Release publication: run `{args.release_run_id}` — success;
- immutable GitHub Release: `{args.tag}`, release id `{args.release_id}`;
- independent Release Verification: run `{args.verification_run_id}` — success;
- post-release closure advanced the machine roadmap to `current_release = \"{args.tag}\"` and `next_release = \"{next_release}\"`.

The immutable `{args.tag}` tag and GitHub Release remain bound to source commit {source}.

## Frozen-contract distinction

[`{args.tag}.md`]({args.tag}.md) is the exact frozen release contract. It remains unchanged after publication. This terminal record, [`../qualification/{args.tag}-publication.md`](../qualification/{args.tag}-publication.md), and `contracts/roadmap.toml` are the authoritative current-state surfaces.

## Claim boundary retained

- `executor_state = \"{milestone.get('executor_state')}\"`;
- `complete_lifecycle = {str(milestone.get('complete_lifecycle')).lower()}`;
- `managed_mutation_support = \"{milestone.get('managed_mutation_support')}\"`;
- `platform_support = \"{milestone.get('platform_support')}\"`;
- `agent_role = \"{milestone.get('agent_role')}\"`.

Publication and post-release closure do not convert this release into a broader or more stable claim.

## Next milestone

The canonical roadmap is ready for `{next_release}`. Any later capability must preserve the released authority, durability, verification and fail-closed boundaries unless a future reviewed release contract explicitly changes them.
"""


def update_release_readme(text: str, args: argparse.Namespace, milestone: dict[str, object]) -> str:
    table = re.search(
        r"(?ms)(^\| Version \| Live status \| Frozen contract \| Terminal release record \| Terminal evidence \|\n"
        r"^\| --- \| --- \| --- \| --- \| --- \|\n)(?P<rows>.*?)(?=\n\n)",
        text,
    )
    if table is None:
        raise TerminalSyncError("docs/releases/README.md current-release table is missing")
    row = (
        f"| `{args.tag}` | **Released — {milestone.get('claim_class')}; independently verified** | "
        f"[`{args.tag}.md`]({args.tag}.md) | [`published-{args.tag}.md`](published-{args.tag}.md) | "
        f"[`../qualification/{args.tag}-publication.md`](../qualification/{args.tag}-publication.md) |"
    )
    text = text[: table.start("rows")] + row + text[table.end("rows") :]

    paragraph_start = text.find("\n\n", table.start())
    if paragraph_start == -1:
        return text
    publication_heading = text.find("\n## Publication-stable contracts", paragraph_start)
    if publication_heading == -1:
        raise TerminalSyncError("docs/releases/README.md publication-stability section is missing")
    paragraph = (
        f"\n\nThe immutable GitHub Release for `{args.tag}` is bound to the frozen publication-stable contract. "
        f"The terminal record [`published-{args.tag}.md`](published-{args.tag}.md), the publication-evidence dossier, "
        "and `contracts/roadmap.toml` are the live current-state authorities."
    )
    return text[:paragraph_start] + paragraph + text[publication_heading:]


def add_terminal_record_reference(publication: str, tag: str) -> str:
    marker = f"- Frozen release contract: `docs/releases/{tag}.md` (unchanged after publication)."
    record = f"- Terminal human-facing release record: `docs/releases/published-{tag}.md`."
    if record in publication:
        return publication
    if publication.count(marker) != 1:
        raise TerminalSyncError(f"{tag} publication evidence lacks unique frozen-contract identity line")
    return publication.replace(marker, marker + "\n" + record, 1)


def sync(args: argparse.Namespace) -> list[str]:
    root = args.root.resolve()
    if not TAG_RE.fullmatch(args.tag):
        raise TerminalSyncError(f"invalid tag: {args.tag!r}")
    if not SHA_RE.fullmatch(args.source_sha):
        raise TerminalSyncError("source_sha must be a lowercase 40-character SHA")
    for field in ("proof_run_id", "promotion_run_id", "release_run_id", "release_id", "verification_run_id"):
        if getattr(args, field) <= 0:
            raise TerminalSyncError(f"{field} must be positive")

    _contract, milestone, next_release = _roadmap(root, args.tag)
    changed: list[str] = []

    milestone_path_value = milestone.get("milestone_contract")
    qualification_path_value = milestone.get("qualification")
    if not isinstance(milestone_path_value, str) or not isinstance(qualification_path_value, str):
        raise TerminalSyncError(f"{args.tag} released milestone lacks milestone/qualification contracts")

    milestone_path = root / milestone_path_value
    write_if_changed(
        milestone_path,
        normalize_milestone_terminal_prose(read(milestone_path), args.tag),
        changed,
        root,
    )

    qualification_path = root / qualification_path_value
    write_if_changed(
        qualification_path,
        normalize_qualification_terminal_state(read(qualification_path), args.tag),
        changed,
        root,
    )

    record_path = root / f"docs/releases/published-{args.tag}.md"
    record = published_record(args, milestone, next_release)
    if record_path.exists() and read(record_path) != record:
        raise TerminalSyncError(f"existing terminal release record differs: {record_path}")
    write_if_changed(record_path, record, changed, root)

    publication_path = root / f"docs/qualification/{args.tag}-publication.md"
    write_if_changed(
        publication_path,
        add_terminal_record_reference(read(publication_path), args.tag),
        changed,
        root,
    )

    index_path = root / "docs/index.md"
    write_if_changed(index_path, update_docs_index(read(index_path), root, args.tag), changed, root)

    releases_readme = root / "docs/releases/README.md"
    write_if_changed(
        releases_readme,
        update_release_readme(read(releases_readme), args, milestone),
        changed,
        root,
    )

    return changed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Synchronize live terminal release documentation after protected closure.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--proof-run-id", type=int, required=True)
    parser.add_argument("--promotion-run-id", type=int, required=True)
    parser.add_argument("--release-run-id", type=int, required=True)
    parser.add_argument("--release-id", type=int, required=True)
    parser.add_argument("--verification-run-id", type=int, required=True)
    parser.add_argument("--published-at", required=True)
    return parser.parse_args()


def main() -> int:
    try:
        changed = sync(parse_args())
    except (TerminalSyncError, tomllib.TOMLDecodeError) as error:
        print(f"post-release terminal sync failed: {error}")
        return 2
    print("terminal sync changed: " + ", ".join(changed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
