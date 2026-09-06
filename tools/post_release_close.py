#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import tomllib

TAG_RE = re.compile(r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
RELEASE_GATE_HEADINGS = ("Release gate", "Exit criteria")
RELEASE_CONTROL_CRITERIA: dict[str, frozenset[str]] = {
    "protected proof-first/tag-last publication and independent release verification complete before roadmap bookkeeping advances to v0.6": frozenset(
        {"publication", "verification", "closure"}
    ),
    "canonical ci, security and codeql pass on the exact candidate source": frozenset({"pre-release-checks"}),
    "dedicated v0.6 managed-lifecycle disposable-vm qualification passes on the exact candidate source": frozenset(
        {"qualification"}
    ),
    "trusted release proof reruns all mandatory inherited v0.4/v0.5 qualifications plus the v0.6 qualification against the exact release authorization": frozenset(
        {"proof"}
    ),
    "independent binary reproduction succeeds": frozenset({"reproduction"}),
    "tag-last publication succeeds": frozenset({"publication"}),
    "independent published-release verification succeeds": frozenset({"verification"}),
    "post-release closure advances machine roadmap state only after immutable publication evidence exists": frozenset(
        {"closure"}
    ),
}
CHECKBOX_PATTERN = re.compile(r"^(?P<prefix>[ \t]*-[ \t]+\[)(?P<state>[ xX])(?P<suffix>\][ \t]+(?P<label>.+))$")


class ClosureError(RuntimeError):
    pass


def read(path: Path) -> str:
    if not path.is_file():
        raise ClosureError(f"required file is missing: {path}")
    return path.read_text(encoding="utf-8")


def write_if_changed(path: Path, content: str, changed: list[str], root: Path) -> None:
    previous = path.read_text(encoding="utf-8") if path.exists() else None
    if previous == content:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    changed.append(path.relative_to(root).as_posix())


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise ClosureError(f"{label}: expected exactly one occurrence, found {count}")
    return text.replace(old, new, 1)


def milestone_block(text: str, tag: str) -> tuple[int, int, str]:
    pattern = re.compile(
        rf'(?ms)^\[\[milestone\]\]\nversion = "{re.escape(tag)}"\n.*?(?=^\[\[milestone\]\]|\Z)'
    )
    match = pattern.search(text)
    if match is None:
        raise ClosureError(f"roadmap milestone block not found for {tag}")
    return match.start(), match.end(), match.group(0)


def replace_markdown_version_section(text: str, tag: str, transform) -> str:
    pattern = re.compile(rf'(?ms)(^## {re.escape(tag)} — [^\n]+\n)(.*?)(?=^## v\d+\.\d+\.\d+ — |\Z)')
    match = pattern.search(text)
    if match is None:
        raise ClosureError(f"canonical roadmap section not found for {tag}")
    body = transform(match.group(2))
    return text[: match.start(2)] + body + text[match.end(2) :]


def replace_heading_section(text: str, heading: str, body: str) -> str:
    pattern = re.compile(rf'(?ms)^{re.escape(heading)}\n.*?(?=^## |\Z)')
    match = pattern.search(text)
    replacement = f"{heading}\n\n{body.rstrip()}\n"
    if match is None:
        if not text.endswith("\n"):
            text += "\n"
        return text.rstrip() + "\n\n" + replacement
    return text[: match.start()] + replacement + text[match.end() :]


def normalize_pending_qualification(text: str, tag: str) -> str:
    publication_doc = f"docs/qualification/{tag}-publication.md"
    replacements = (
        (
            "Publication and independent verification remain pending until those repository-controlled terminal events complete.",
            f"Terminal publication and independent verification completed successfully; exact evidence is recorded in `{publication_doc}`.",
        ),
        (
            "Publication and independent verification remain pending.",
            f"Terminal publication and independent verification completed successfully; exact evidence is recorded in `{publication_doc}`.",
        ),
    )
    for old, new in replacements:
        if old in text:
            text = text.replace(old, new)
    return text


def normalize_release_control_label(label: str) -> str:
    normalized = re.sub(r"\s+", " ", label.strip()).rstrip(".;")
    return normalized.casefold()


def close_release_control_criteria(text: str, tag: str) -> str:
    heading_pattern = "|".join(re.escape(heading) for heading in RELEASE_GATE_HEADINGS)
    section_pattern = re.compile(
        rf"(?ms)^## (?:{heading_pattern})[ \t]*\n(?P<body>.*?)(?=^## |\Z)"
    )
    sections = list(section_pattern.finditer(text))
    if len(sections) != 1:
        raise ClosureError(
            f"{tag} milestone: expected exactly one release-gate/exit-criteria section, found {len(sections)}"
        )

    section = sections[0]
    body = section.group("body")
    lines = body.splitlines(keepends=True)
    checkbox_labels: list[str] = []
    mapped_evidence: set[str] = set()
    unknown_unchecked: list[str] = []
    changed = False

    for index, line in enumerate(lines):
        newline = "\n" if line.endswith("\n") else ""
        raw = line[:-1] if newline else line
        if raw.endswith("\r"):
            raw = raw[:-1]
            newline = "\r\n" if newline else "\r"
        match = CHECKBOX_PATTERN.fullmatch(raw)
        if match is None:
            continue

        label = match.group("label").strip()
        checkbox_labels.append(label)
        evidence = RELEASE_CONTROL_CRITERIA.get(normalize_release_control_label(label))
        state = match.group("state")

        if evidence is not None:
            mapped_evidence.update(evidence)
        if state == " " and evidence is None:
            unknown_unchecked.append(label)
            continue
        if state == " " and evidence is not None:
            lines[index] = f"{match.group('prefix')}x{match.group('suffix')}{newline}"
            changed = True

    if not checkbox_labels:
        raise ClosureError(f"{tag} milestone: release gate contains no checkbox criteria")
    if "publication" not in mapped_evidence:
        raise ClosureError(f"{tag} milestone: release gate does not contain an exactly mapped publication criterion")
    if "verification" not in mapped_evidence:
        raise ClosureError(f"{tag} milestone: release gate does not contain an exactly mapped verification criterion")
    if unknown_unchecked:
        rendered = "; ".join(unknown_unchecked)
        raise ClosureError(
            f"{tag} milestone: unchecked release-gate criteria are not exactly mapped to terminal release evidence: {rendered}"
        )
    if not changed and any("- [ ]" in line for line in lines):
        raise ClosureError(f"{tag} milestone: release gate still contains unchecked criteria")

    updated_body = "".join(lines)
    return text[: section.start("body")] + updated_body + text[section.end("body") :]


def terminal_body(args: argparse.Namespace, next_release: str) -> str:
    return f"""Linura {args.tag} completed the repository-defined protected proof-first, tag-last release lifecycle on {args.published_at[:10]}.

- Metadata-only release authorization: `{args.source_sha}`.
- Trusted Release Proof: GitHub Actions run `{args.proof_run_id}` — success.
- Release Promotion: run `{args.promotion_run_id}` — success.
- Release publication: run `{args.release_run_id}` — success.
- Immutable GitHub Release: `{args.tag}`, release id `{args.release_id}`, published `{args.published_at}`.
- Independent Release Verification: run `{args.verification_run_id}` — success.

The immutable tag resolves to `{args.source_sha}`. Independent verification checked out the frozen release tag and verified published digests, canonical release metadata, GitHub Release immutability/attestation, and build provenance for every published candidate asset.

Post-publication repository bookkeeping advances the canonical roadmap to `current_release = \"{args.tag}\"` and `next_release = \"{next_release}\"`. The frozen release contract and immutable GitHub Release remain unchanged."""


def publication_document(args: argparse.Namespace, milestone: dict[str, object], next_release: str) -> str:
    boundary = (
        f'executor_state = "{milestone.get("executor_state")}", '
        f'managed_mutation_support = "{milestone.get("managed_mutation_support")}", '
        f'complete_lifecycle = {str(milestone.get("complete_lifecycle")).lower()}, '
        f'platform_support = "{milestone.get("platform_support")}"'
    )
    return f"""# {args.tag} terminal publication evidence

Linura {args.tag} completed the repository-defined protected proof-first, tag-last release lifecycle on {args.published_at[:10]}.

## Exact release identity

- Frozen release contract: `docs/releases/{args.tag}.md` (unchanged after publication).
- Metadata-only release-authorization commit: `{args.source_sha}`.
- Immutable tag: `{args.tag}` → `{args.source_sha}`.

## Terminal release evidence

- Trusted Release Proof: GitHub Actions run `{args.proof_run_id}` — success.
- Release Promotion: run `{args.promotion_run_id}` — success.
- Release publication: run `{args.release_run_id}` — success.
- Immutable GitHub Release: `{args.tag}`, release id `{args.release_id}`, published `{args.published_at}`.
- Independent Release Verification: run `{args.verification_run_id}` — success.

Independent verification checked out and verified the frozen `{args.tag}` tag, including tag/source binding, published evidence and digests, canonical release metadata, GitHub Release immutability/attestation, and build provenance for every published candidate asset.

## Boundary retained

{args.tag} remains **{milestone.get("claim_class")}**. Publication does not widen the frozen release claim. The authoritative roadmap boundary remains `{boundary}`.

Post-release bookkeeping advances `current_release` to `{args.tag}` and `next_release` to `{next_release}` only after the terminal verification above succeeded. This file records terminal evidence; it does not modify the frozen release contract or immutable release assets.
"""


def close_release(args: argparse.Namespace) -> list[str]:
    root = args.root.resolve()
    if not TAG_RE.fullmatch(args.tag):
        raise ClosureError(f"invalid release tag: {args.tag!r}")
    if not SHA_RE.fullmatch(args.source_sha):
        raise ClosureError("source_sha must be a lowercase 40-character SHA")
    for field in ("proof_run_id", "promotion_run_id", "release_run_id", "release_id", "verification_run_id"):
        if getattr(args, field) <= 0:
            raise ClosureError(f"{field} must be positive")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T[^\s]+", args.published_at):
        raise ClosureError("published_at must be an ISO-8601 timestamp")

    contract_path = root / "contracts/roadmap.toml"
    contract_text = read(contract_path)
    contract = tomllib.loads(contract_text)
    milestones = contract.get("milestone")
    if not isinstance(milestones, list):
        raise ClosureError("roadmap milestone array is missing")

    target_index = next((i for i, item in enumerate(milestones) if item.get("version") == args.tag), None)
    if target_index is None:
        raise ClosureError(f"roadmap does not contain {args.tag}")
    target = milestones[target_index]
    if target.get("status") != "planned":
        raise ClosureError(f"{args.tag} must still be planned before closure")
    if contract.get("next_release") != args.tag:
        raise ClosureError(
            f"roadmap next_release must be {args.tag} before closure, found {contract.get('next_release')!r}"
        )
    if target_index + 1 >= len(milestones):
        raise ClosureError(f"{args.tag} has no following roadmap milestone")
    next_release = milestones[target_index + 1].get("version")
    if not isinstance(next_release, str) or not TAG_RE.fullmatch(next_release):
        raise ClosureError(f"invalid following milestone after {args.tag}: {next_release!r}")

    changed: list[str] = []

    old_current = contract.get("current_release")
    if not isinstance(old_current, str):
        raise ClosureError("current_release must be a string")
    updated_contract = replace_once(
        contract_text,
        f'current_release = "{old_current}"',
        f'current_release = "{args.tag}"',
        "current_release",
    )
    updated_contract = replace_once(
        updated_contract,
        f'next_release = "{args.tag}"',
        f'next_release = "{next_release}"',
        "next_release",
    )
    start, end, block = milestone_block(updated_contract, args.tag)
    updated_block = replace_once(block, 'status = "planned"', 'status = "released"', f"{args.tag} status")
    updated_contract = updated_contract[:start] + updated_block + updated_contract[end:]
    write_if_changed(contract_path, updated_contract, changed, root)

    roadmap_path = root / "docs/roadmap.md"
    roadmap_text = read(roadmap_path)

    def update_roadmap_body(body: str) -> str:
        body = replace_once(body, "**Status:** planned", "**Status:** released", f"{args.tag} roadmap status")
        body = re.sub(r"(?m)^(\*\*Status:\*\* released)[ \t]+$", r"\1", body)
        target_claim = f'**Target claim class:** {target.get("claim_class")}'
        claim = f'**Claim class:** {target.get("claim_class")}'
        if target_claim in body:
            body = replace_once(body, target_claim, claim, f"{args.tag} roadmap claim class")
        return body

    roadmap_text = replace_markdown_version_section(roadmap_text, args.tag, update_roadmap_body)
    write_if_changed(roadmap_path, roadmap_text, changed, root)

    milestone_path_value = target.get("milestone_contract")
    if not isinstance(milestone_path_value, str):
        raise ClosureError(f"{args.tag} does not name milestone_contract")
    milestone_path = root / milestone_path_value
    milestone_text = read(milestone_path)
    milestone_text = replace_once(
        milestone_text,
        "**Status:** release candidate; publication pending",
        "**Status:** released",
        f"{args.tag} milestone status",
    )
    milestone_text = close_release_control_criteria(milestone_text, args.tag)
    write_if_changed(milestone_path, milestone_text, changed, root)

    readme_path = root / "README.md"
    readme_text = read(readme_path)
    status_lines = [line for line in readme_text.splitlines() if line.startswith("Status:")]
    if len(status_lines) != 1:
        raise ClosureError(f"README: expected one Status line, found {len(status_lines)}")
    status = (
        f"Status: `{args.tag}` released — {target.get('claim_class')} {target.get('title')}. "
        "The immutable release is independently verified. "
        f"`executor_state = \"{target.get('executor_state')}\"`, "
        f"`managed_mutation_support = \"{target.get('managed_mutation_support')}\"`, "
        f"`complete_lifecycle = {str(target.get('complete_lifecycle')).lower()}` and "
        f"`platform_support = \"{target.get('platform_support')}\"` remain the authoritative {args.tag} boundary. "
        f"Linura remains Experimental; the next roadmap milestone is `{next_release}`."
    )
    readme_text = replace_once(readme_text, status_lines[0], status, "README status")
    write_if_changed(readme_path, readme_text, changed, root)

    qualification_path_value = target.get("qualification")
    if not isinstance(qualification_path_value, str):
        raise ClosureError(f"{args.tag} does not name qualification")
    qualification_path = root / qualification_path_value
    qualification_text = normalize_pending_qualification(read(qualification_path), args.tag)
    qualification_text = replace_heading_section(
        qualification_text,
        "## Terminal publication evidence",
        terminal_body(args, next_release),
    )
    write_if_changed(qualification_path, qualification_text, changed, root)

    review_path = root / f"docs/qualification/{args.tag}-release-review.md"
    review_text = read(review_path)
    review_text = replace_heading_section(
        review_text,
        "## Terminal publication evidence",
        terminal_body(args, next_release),
    )
    write_if_changed(review_path, review_text, changed, root)

    publication_path = root / f"docs/qualification/{args.tag}-publication.md"
    publication_text = publication_document(args, target, next_release)
    if publication_path.exists() and read(publication_path) != publication_text:
        raise ClosureError(f"existing publication evidence differs: {publication_path}")
    if not publication_path.exists():
        publication_path.parent.mkdir(parents=True, exist_ok=True)
        publication_path.write_text(publication_text, encoding="utf-8")
        changed.append(publication_path.relative_to(root).as_posix())

    frozen = root / f"docs/releases/{args.tag}.md"
    read(frozen)

    print(json.dumps({"tag": args.tag, "next_release": next_release, "changed": changed}, sort_keys=True))
    return changed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare deterministic post-release repository closure.")
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
        close_release(parse_args())
    except (ClosureError, tomllib.TOMLDecodeError) as error:
        print(f"post-release closure failed: {error}", flush=True)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
