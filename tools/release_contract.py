#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "linura-org/linura"

CLAIM_CLASSES = {
    "Architecture",
    "Experimental",
    "Developer Preview",
    "Supported Preview",
    "Supported",
    "Stable",
}

REQUIRED_HEADINGS = (
    "## Outcome",
    "## User-visible capability",
    "## Implemented scope",
    "## Authority and security boundary",
    "## Platform and hardware scope",
    "## Persistence, migration and upgrade",
    "## Recovery and rollback",
    "## Compatibility boundary",
    "## Required acceptance evidence",
    "## Known limitations and unsupported states",
    "## Explicit non-goals",
    "## Traceability",
    "## Artifacts and supply-chain evidence",
    "## Publication evidence",
    "## Next-version handoff",
)

TAG_RE = re.compile(r"^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PR_RE = re.compile(r"https://github\.com/linura-org/linura/pull/([1-9][0-9]*)")
COMMIT_RE = re.compile(r"https://github\.com/linura-org/linura/commit/([0-9a-f]{40})(?![0-9a-f])")
CLAIM_RE = re.compile(r"^\*\*Claim class:\*\*\s*(.+?)\s*$", re.MULTILINE)
PROFILES_RE = re.compile(r"^\*\*Supported platform profiles:\*\*\s*(.+?)\s*$", re.MULTILINE)
STATUS_RE = re.compile(r"^\*\*Status:\*\*\s*(.+?)\s*$", re.MULTILINE)
REVIEWED_SOURCE_RE = re.compile(r"^Reviewed-Source:\s*([0-9a-f]{40})\s*$", re.MULTILINE)
REVIEWED_TREE_RE = re.compile(r"^Reviewed-Tree:\s*([0-9a-f]{40})\s*$", re.MULTILINE)
QUALIFICATION_SOURCE_RE = re.compile(r"^Qualification-Source:\s*([0-9a-f]{40})\s*$", re.MULTILINE)
QUALIFICATION_TREE_RE = re.compile(r"^Qualification-Tree:\s*([0-9a-f]{40})\s*$", re.MULTILINE)


class ContractError(ValueError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_tag(tag: str) -> str:
    match = TAG_RE.fullmatch(tag)
    if match is None:
        raise ContractError(f"invalid release tag: {tag!r}")
    return match.group("version")


def extract_metadata(text: str) -> tuple[str, list[str]]:
    if STATUS_RE.search(text) is None:
        raise ContractError("release contract is missing **Status:** metadata")
    claim_match = CLAIM_RE.search(text)
    if claim_match is None:
        raise ContractError("release contract is missing **Claim class:** metadata")
    claim_class = claim_match.group(1).strip()
    if claim_class not in CLAIM_CLASSES:
        raise ContractError(f"unsupported claim class: {claim_class!r}")
    profiles_match = PROFILES_RE.search(text)
    if profiles_match is None:
        raise ContractError("release contract is missing **Supported platform profiles:** metadata")
    raw_profiles = profiles_match.group(1).strip()
    if raw_profiles.lower() == "none":
        profiles: list[str] = []
    else:
        profiles = [item.strip() for item in raw_profiles.split(",") if item.strip()]
        if not profiles:
            raise ContractError("supported platform profiles cannot be empty")
        if len(profiles) != len(set(profiles)):
            raise ContractError("supported platform profiles contain duplicates")
    return claim_class, profiles


def extract_traceability(text: str) -> tuple[list[int], list[str]]:
    pull_requests = sorted({int(value) for value in PR_RE.findall(text)})
    commits = sorted(set(COMMIT_RE.findall(text)))
    if not pull_requests and not commits:
        raise ContractError("release contract must contain at least one canonical PR or full-SHA commit link")
    return pull_requests, commits


def workspace_version() -> str:
    data = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    value = data.get("workspace", {}).get("package", {}).get("version")
    if not isinstance(value, str) or not value:
        raise ContractError("workspace.package.version is missing from Cargo.toml")
    return value


def _git(repository: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", None) or str(error)
        raise ContractError(f"git {' '.join(args)} failed: {detail.strip()}") from error
    return result.stdout.strip()


def validate_release_intent(source_sha: str, repository: Path = ROOT) -> dict[str, str]:
    """Prove a release-intent commit authorizes exactly its reviewed parent tree.

    The release-intent commit is metadata-only: it must have exactly one parent,
    its Git tree must be byte-for-byte identical to that parent's tree, and its
    commit message must explicitly record that reviewed parent and tree through
    `Reviewed-Source` and `Reviewed-Tree` trailers. Commit metadata can therefore
    record the reviewed tree without the self-reference that embedding a tree SHA
    inside a tracked file would create.
    """
    if SHA_RE.fullmatch(source_sha) is None:
        raise ContractError("release-intent source SHA must be lowercase 40-character hexadecimal")

    lineage = _git(repository, "rev-list", "--parents", "-n", "1", source_sha).split()
    if len(lineage) != 2 or lineage[0] != source_sha:
        raise ContractError("release-intent commit must exist and have exactly one reviewed parent")
    reviewed_source_sha = lineage[1]

    source_tree_sha = _git(repository, "rev-parse", f"{source_sha}^{{tree}}")
    reviewed_tree_sha = _git(repository, "rev-parse", f"{reviewed_source_sha}^{{tree}}")
    if source_tree_sha != reviewed_tree_sha:
        raise ContractError(
            "release-intent tree differs from its reviewed parent: "
            f"source={source_tree_sha} reviewed={reviewed_tree_sha}"
        )

    message = _git(repository, "show", "-s", "--format=%B", source_sha)
    reviewed_sources = REVIEWED_SOURCE_RE.findall(message)
    reviewed_trees = REVIEWED_TREE_RE.findall(message)
    qualification_sources = QUALIFICATION_SOURCE_RE.findall(message)
    qualification_trees = QUALIFICATION_TREE_RE.findall(message)
    if len(reviewed_sources) != 1 or len(reviewed_trees) != 1:
        raise ContractError(
            "release-intent commit must contain exactly one Reviewed-Source and Reviewed-Tree trailer"
        )
    if len(qualification_sources) != 1 or len(qualification_trees) != 1:
        raise ContractError(
            "release-intent commit must contain exactly one Qualification-Source and Qualification-Tree trailer"
        )
    if reviewed_sources[0] != reviewed_source_sha:
        raise ContractError(
            "release-intent Reviewed-Source does not match its immediate parent: "
            f"recorded={reviewed_sources[0]} actual={reviewed_source_sha}"
        )
    if reviewed_trees[0] != source_tree_sha:
        raise ContractError(
            "release-intent Reviewed-Tree does not match the identical source/parent tree: "
            f"recorded={reviewed_trees[0]} actual={source_tree_sha}"
        )

    qualification_source_sha = qualification_sources[0]
    qualification_tree_sha = qualification_trees[0]
    if qualification_source_sha == reviewed_source_sha:
        raise ContractError(
            "release-intent Qualification-Source must pre-exist the reviewed evidence seal"
        )
    if qualification_tree_sha == reviewed_tree_sha:
        raise ContractError(
            "release-intent Qualification-Tree must pre-exist and differ from the reviewed evidence-seal tree"
        )

    return {
        "source_sha": source_sha,
        "reviewed_source_sha": reviewed_source_sha,
        "reviewed_tree_sha": source_tree_sha,
        "qualification_source_sha": qualification_source_sha,
        "qualification_tree_sha": qualification_tree_sha,
    }



def validate_release_preparation(
    source_sha: str,
    tag: str,
    repository: Path = ROOT,
) -> dict[str, object]:
    """Validate a deterministic mechanical release-preparation commit.

    This shape is deliberately narrower than a release-intent commit. It may
    change only Cargo.toml and Cargo.lock (or be an idempotent zero-diff
    handoff), and its commit metadata must bind the pre-existing qualification
    source/tree. The binding is used by PR qualification to validate committed
    Q10-Q13 evidence against the source it actually attests; it does not grant
    release authority on its own.
    """
    parse_tag(tag)
    if SHA_RE.fullmatch(source_sha) is None:
        raise ContractError(
            "release-preparation source SHA must be lowercase 40-character hexadecimal"
        )

    lineage = _git(repository, "rev-list", "--parents", "-n", "1", source_sha).split()
    if len(lineage) != 2 or lineage[0] != source_sha:
        raise ContractError(
            "release-preparation commit must exist and have exactly one parent"
        )
    parent_sha = lineage[1]

    subject = _git(repository, "show", "-s", "--format=%s", source_sha)
    expected_prefix = f"release: prepare {tag} "
    if not subject.startswith(expected_prefix) or not subject[len(expected_prefix):].strip():
        raise ContractError(
            f"release-preparation subject must start with {expected_prefix!r} and include a theme"
        )

    message = _git(repository, "show", "-s", "--format=%B", source_sha)
    qualification_sources = QUALIFICATION_SOURCE_RE.findall(message)
    qualification_trees = QUALIFICATION_TREE_RE.findall(message)
    if len(qualification_sources) != 1 or len(qualification_trees) != 1:
        raise ContractError(
            "release-preparation commit must contain exactly one Qualification-Source and Qualification-Tree trailer"
        )
    qualification_source_sha = qualification_sources[0]
    qualification_tree_sha = qualification_trees[0]
    actual_qualification_tree = _git(
        repository, "rev-parse", f"{qualification_source_sha}^{{tree}}"
    )
    if actual_qualification_tree != qualification_tree_sha:
        raise ContractError(
            "release-preparation Qualification-Tree does not match Qualification-Source: "
            f"recorded={qualification_tree_sha} actual={actual_qualification_tree}"
        )

    parent_tree_sha = _git(repository, "rev-parse", f"{parent_sha}^{{tree}}")
    source_tree_sha = _git(repository, "rev-parse", f"{source_sha}^{{tree}}")
    if qualification_source_sha == parent_sha or qualification_tree_sha == parent_tree_sha:
        raise ContractError(
            "release-preparation qualification source/tree must pre-exist the reviewed evidence-seal parent"
        )

    changed_text = _git(
        repository,
        "diff",
        "--no-renames",
        "--name-only",
        parent_sha,
        source_sha,
    )
    changed_files = [line for line in changed_text.splitlines() if line]
    if changed_files not in ([], ["Cargo.lock", "Cargo.toml"]):
        raise ContractError(
            "release-preparation commit must change zero files or exactly Cargo.lock and Cargo.toml"
        )
    if not changed_files and source_tree_sha != parent_tree_sha:
        raise ContractError(
            "zero-diff release-preparation commit must preserve the parent tree exactly"
        )
    if changed_files and source_tree_sha == parent_tree_sha:
        raise ContractError(
            "two-file release-preparation commit must produce a changed tree"
        )

    return {
        "source_sha": source_sha,
        "parent_sha": parent_sha,
        "qualification_source_sha": qualification_source_sha,
        "qualification_tree_sha": qualification_tree_sha,
        "changed_files": changed_files,
    }

def validate_contract(notes: Path, tag: str, *, require_workspace_version: bool = False) -> dict[str, object]:
    version = parse_tag(tag)
    if not notes.is_file():
        raise ContractError(f"release contract does not exist: {notes}")
    text = notes.read_text(encoding="utf-8")
    first_line = text.splitlines()[0] if text else ""
    expected_title_prefix = f"# {tag} — "
    if not first_line.startswith(expected_title_prefix):
        raise ContractError(f"release contract title must start with {expected_title_prefix!r}")
    release_theme = first_line[len(expected_title_prefix) :].strip()
    if not release_theme:
        raise ContractError("release contract title must include a non-empty implementation theme")
    positions: list[int] = []
    for heading in REQUIRED_HEADINGS:
        position = text.find(heading)
        if position < 0:
            raise ContractError(f"release contract is missing required heading: {heading}")
        positions.append(position)
    if positions != sorted(positions):
        raise ContractError("release contract headings are not in canonical order")
    claim_class, profiles = extract_metadata(text)
    pull_requests, commits = extract_traceability(text)
    if require_workspace_version:
        current = workspace_version()
        if version != current:
            raise ContractError(f"tag version {version} does not match workspace version {current}")
    return {
        "version": version,
        "claim_class": claim_class,
        "supported_platform_profiles": profiles,
        "pull_requests": pull_requests,
        "commits": commits,
    }


def build_evidence(notes: Path, tag: str, source_sha: str, artifacts: list[Path]) -> dict[str, object]:
    if SHA_RE.fullmatch(source_sha) is None:
        raise ContractError("source SHA must be lowercase 40-character hexadecimal")
    metadata = validate_contract(notes, tag, require_workspace_version=True)
    if not artifacts:
        raise ContractError("at least one candidate artifact must be indexed")
    artifact_records: list[dict[str, str]] = []
    names: set[str] = set()
    for artifact in artifacts:
        if not artifact.is_file():
            raise ContractError(f"candidate artifact does not exist: {artifact}")
        name = artifact.name
        if name in names:
            raise ContractError(f"duplicate candidate artifact basename: {name}")
        names.add(name)
        artifact_records.append({"name": name, "sha256": sha256(artifact)})
    return {
        "$schema": "https://linura.org/schemas/release-evidence.v1.schema.json",
        "schema": 1,
        "tag": tag,
        "version": metadata["version"],
        "source_sha": source_sha,
        "claim_class": metadata["claim_class"],
        "supported_platform_profiles": metadata["supported_platform_profiles"],
        "release_notes": {"name": "RELEASE_NOTES.md", "sha256": sha256(notes)},
        "traceability": {"pull_requests": metadata["pull_requests"], "commits": metadata["commits"]},
        "artifacts": artifact_records,
    }


def write_evidence(notes: Path, tag: str, source_sha: str, artifacts: list[Path], output: Path) -> None:
    evidence = build_evidence(notes, tag, source_sha, artifacts)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verify_evidence(directory: Path, tag: str, source_sha: str) -> None:
    if SHA_RE.fullmatch(source_sha) is None:
        raise ContractError("source SHA must be lowercase 40-character hexadecimal")
    evidence_path = directory / "RELEASE-EVIDENCE.json"
    notes_path = directory / "RELEASE_NOTES.md"
    if not evidence_path.is_file():
        raise ContractError(f"missing release evidence: {evidence_path}")
    if not notes_path.is_file():
        raise ContractError(f"missing frozen release notes: {notes_path}")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    if not isinstance(evidence, dict):
        raise ContractError("release evidence must be a JSON object")
    if evidence.get("$schema") != "https://linura.org/schemas/release-evidence.v1.schema.json":
        raise ContractError("release evidence schema URI mismatch")
    if evidence.get("schema") != 1:
        raise ContractError("unsupported release evidence schema")
    if evidence.get("tag") != tag:
        raise ContractError("release evidence tag mismatch")
    if evidence.get("version") != parse_tag(tag):
        raise ContractError("release evidence version mismatch")
    if evidence.get("source_sha") != source_sha:
        raise ContractError("release evidence source SHA mismatch")
    notes_record = evidence.get("release_notes")
    if not isinstance(notes_record, dict):
        raise ContractError("release evidence release_notes record is invalid")
    if notes_record.get("name") != "RELEASE_NOTES.md":
        raise ContractError("release evidence notes name mismatch")
    if notes_record.get("sha256") != sha256(notes_path):
        raise ContractError("frozen release notes digest mismatch")
    metadata = validate_contract(notes_path, tag)
    if evidence.get("claim_class") != metadata["claim_class"]:
        raise ContractError("release evidence claim class mismatch")
    if evidence.get("supported_platform_profiles") != metadata["supported_platform_profiles"]:
        raise ContractError("release evidence supported-platform mismatch")
    expected_traceability = {"pull_requests": metadata["pull_requests"], "commits": metadata["commits"]}
    if evidence.get("traceability") != expected_traceability:
        raise ContractError("release evidence traceability mismatch")
    artifacts = evidence.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ContractError("release evidence artifacts must be a non-empty array")
    seen: set[str] = set()
    for record in artifacts:
        if not isinstance(record, dict):
            raise ContractError("release evidence artifact record is invalid")
        name = record.get("name")
        digest = record.get("sha256")
        if not isinstance(name, str) or not name:
            raise ContractError("release evidence artifact name is invalid")
        if name in seen:
            raise ContractError(f"duplicate release evidence artifact: {name}")
        seen.add(name)
        path = directory / name
        if not path.is_file():
            raise ContractError(f"release evidence artifact is missing: {name}")
        if digest != sha256(path):
            raise ContractError(f"release evidence digest mismatch: {name}")


def validate_tree(releases_dir: Path) -> None:
    contracts = sorted(releases_dir.glob("v*.md"))
    if not contracts:
        raise ContractError(f"no versioned release contracts found in {releases_dir}")
    for notes in contracts:
        validate_contract(notes, notes.stem)


def compare_release_body(notes: Path, body: Path) -> None:
    def normalized(path: Path) -> str:
        return path.read_text(encoding="utf-8").replace("\r\n", "\n").rstrip("\n")
    if normalized(notes) != normalized(body):
        raise ContractError("GitHub Release body does not match frozen release notes")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Linura release contracts and evidence")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--tag", required=True)
    validate_parser.add_argument("--notes", required=True, type=Path)
    validate_parser.add_argument("--require-workspace-version", action="store_true")
    intent_parser = subparsers.add_parser("validate-intent")
    intent_parser.add_argument("--source-sha", required=True)
    intent_parser.add_argument("--repository", type=Path, default=ROOT)
    intent_parser.add_argument("--json", action="store_true")
    preparation_parser = subparsers.add_parser("validate-preparation")
    preparation_parser.add_argument("--source-sha", required=True)
    preparation_parser.add_argument("--tag", required=True)
    preparation_parser.add_argument("--repository", type=Path, default=ROOT)
    preparation_parser.add_argument("--json", action="store_true")
    evidence_parser = subparsers.add_parser("evidence")
    evidence_parser.add_argument("--tag", required=True)
    evidence_parser.add_argument("--source-sha", required=True)
    evidence_parser.add_argument("--notes", required=True, type=Path)
    evidence_parser.add_argument("--output", required=True, type=Path)
    evidence_parser.add_argument("--artifact", dest="artifacts", required=True, action="append", type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--directory", required=True, type=Path)
    verify_parser.add_argument("--tag", required=True)
    verify_parser.add_argument("--source-sha", required=True)
    tree_parser = subparsers.add_parser("validate-tree")
    tree_parser.add_argument("--releases-dir", type=Path, default=ROOT / "docs" / "releases")
    body_parser = subparsers.add_parser("compare-body")
    body_parser.add_argument("--notes", required=True, type=Path)
    body_parser.add_argument("--body", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "validate":
            metadata = validate_contract(args.notes, args.tag, require_workspace_version=args.require_workspace_version)
            print("release contract valid: " f"{args.tag} / {metadata['claim_class']} / " f"{len(metadata['pull_requests'])} PR(s) / " f"{len(metadata['commits'])} commit(s)")
        elif args.command == "validate-intent":
            metadata = validate_release_intent(args.source_sha, args.repository)
            if args.json:
                print(json.dumps(metadata, sort_keys=True))
            else:
                print(
                    "release intent valid: "
                    f"source={metadata['source_sha']} / "
                    f"reviewed-source={metadata['reviewed_source_sha']} / "
                    f"reviewed-tree={metadata['reviewed_tree_sha']} / "
                    f"qualification-source={metadata['qualification_source_sha']} / "
                    f"qualification-tree={metadata['qualification_tree_sha']}"
                )
        elif args.command == "validate-preparation":
            metadata = validate_release_preparation(
                args.source_sha,
                args.tag,
                args.repository,
            )
            if args.json:
                print(json.dumps(metadata, sort_keys=True))
            else:
                print(
                    "release preparation valid: "
                    f"source={metadata['source_sha']} / "
                    f"parent={metadata['parent_sha']} / "
                    f"qualification-source={metadata['qualification_source_sha']} / "
                    f"qualification-tree={metadata['qualification_tree_sha']} / "
                    f"changed={','.join(metadata['changed_files']) or 'none'}"
                )
        elif args.command == "evidence":
            write_evidence(args.notes, args.tag, args.source_sha, args.artifacts, args.output)
            print(f"wrote release evidence: {args.output}")
        elif args.command == "verify":
            verify_evidence(args.directory, args.tag, args.source_sha)
            print("release evidence verified")
        elif args.command == "validate-tree":
            validate_tree(args.releases_dir)
            print(f"release contract tree valid: {args.releases_dir}")
        elif args.command == "compare-body":
            compare_release_body(args.notes, args.body)
            print("GitHub Release body matches frozen release notes")
        else:
            raise ContractError(f"unsupported command: {args.command}")
    except (ContractError, json.JSONDecodeError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
