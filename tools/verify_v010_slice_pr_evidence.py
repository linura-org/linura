#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
LEDGER = Path("contracts/v010-workstation-slices.toml")

# Canonical owned implementation/evidence surfaces for each v0.10 slice.
# A cited PR must touch at least one path owned by its assigned slice; this
# mapping lives outside the mutable ledger so evidence cannot self-declare scope.
SLICE_PATH_PREFIXES: dict[str, tuple[str, ...]] = {
    "S01": ("contracts/v010-workstation-qualification.toml", "docs/adr/0030-v010-first-interactive-platform-profile.md", "docs/qualification/v0.10.0.md", ".github/workflows/v010-qualification.yml"),
    "S02": ("crates/linura-hardware/", "docs/platform-profiles.md", "profiles/arch-hyprland-v1.toml"),
    "S03": ("crates/linura-linux-observation/", "crates/linura-control/src/platform_compatibility.rs"),
    "S04": ("contracts/operation-semantics.toml", "docs/adr/0031-v010-many-interfaces-one-authority-path.md", "docs/adr/0032-classify-operations-before-authority.md", "docs/operation-semantics.md", "docs/control-plane.md", "docs/managed-configuration.md", "docs/capability-composition.md", "docs/derived-surfaces.md", "docs/explainability.md", "docs/provider-model.md", "docs/security-model.md", "docs/threat-model.md"),
    "S05": ("crates/linura-control/src/operation_semantics.rs", "crates/linura-control/src/operation_registry.rs"),
    "S06": ("crates/linura-control/src/managed_lifecycle.rs", "crates/linura-control/src/durable_authority.rs", "crates/linura-control/src/operation_registry.rs"),
    "S07": ("crates/linura-control/src/transient_effect.rs",),
    "S08": ("apps/linurad/src/session_audio.rs", "apps/linurad/src/session_audit.rs", "packaging/wireplumber/", "crates/linura-dbus/src/session.rs"),
    "S09": ("apps/linura-shell/shell.qml", "apps/linura-shell/plugins/control-center/", "apps/linura-shell/bridge/"),
    "S10": ("apps/linura-shell/ui/", "design/tokens.json"),
    "S11": ("apps/linura-shell/plugins/command-palette/", "apps/linura-shell/org.linura.CommandPalette.desktop"),
    "S12": ("apps/linura-shell/integrations/hyprland/", "apps/linura-shell/integrations/xdg/"),
    "S13": ("apps/linura-shell/plugins/quick-settings/", "apps/linura-shell/org.linura.QuickSettings.desktop"),
    "S14": ("contracts/v010-shell-runtime-qualification.toml", "contracts/v010-shell-runtime-substrate.toml", "qualification/v010/shell-runtime/", ".github/workflows/v010-shell-runtime-qualification.yml"),
    "S15": ("apps/linura-shell/plugins/notifications/", "apps/linura-shell/plugins/osd/", "apps/linura-shell/integrations/lifecycle/"),
    "S16": ("apps/linura-shell/panel/", "apps/linura-shell/tray/", "apps/linura-shell/status/"),
    "S17": ("apps/linura-shell/plugins/session/", "apps/linura-shell/integrations/logind/", "apps/linura-shell/plugins/power/"),
    "S18": ("apps/linura-shell/plugins/network/", "crates/linura-provider-networkmanager/"),
    "S19": ("apps/linura-shell/plugins/bluetooth/", "crates/linura-provider-bluez/"),
    "S20": ("apps/linura-shell/plugins/audio/", "apps/linura-shell/plugins/media/", "apps/linurad/src/session_audio.rs"),
    "S21": ("apps/linura-shell/plugins/display/", "apps/linura-shell/plugins/power/", "apps/linura-shell/plugins/storage/", "crates/linura-provider-udisks2/"),
    "S22": ("apps/linura-shell/plugins/screenshot/", "apps/linura-shell/plugins/recording/", "apps/linura-shell/plugins/clipboard/"),
    "S23": ("apps/linura-shell/plugins/applications/", "apps/linura-shell/plugins/packages/", "apps/linura-shell/plugins/default-apps/"),
    "S24": ("apps/linura-shell/plugins/updates/", "apps/linura-shell/plugins/recovery/", "apps/linura-shell/plugins/snapshots/", "crates/linura-update/"),
    "S25": ("apps/linura-shell/plugins/personalization/", "apps/linura-shell/theme/", "design/"),
    "S26": ("apps/linura-shell/plugins/library/", "apps/linura-shell/plugins/setups/", "apps/linura-shell/plugins/machine-profiles/", "crates/linura-library/"),
    "S27": ("apps/linura-shell/plugins/declarative/", "apps/linura-agent-ui/", "crates/linura-intent/", "crates/linura-planner/"),
    "S28": ("apps/linura-installer/", "apps/linura-firstboot/", "docs/installer-bootstrap.md", "docs/first-boot.md"),
    "S29": (
        "visual/baselines/",
        "qualification/v010/experience/",
        "qualification/v010/experience-evidence.json",
        "tools/check_v010_workstation_qualification.py",
    ),
    "S30": (
        "qualification/v010/interactive-workstation/",
        "qualification/v010/interactive-workstation-evidence.json",
    ),
    "S31": (
        "qualification/v010/update-recovery/",
        "qualification/v010/update-recovery-evidence.json",
        "qualification/v010/security/",
        "qualification/v010/security-evidence.json",
        "tools/check_v010_workstation_qualification.py",
    ),
    "S32": (".github/workflows/release-preparation.yml", ".github/workflows/release-authorization.yml", ".github/workflows/trusted-release-proof.yml", ".github/workflows/post-release-closure.yml", "hardware/support-matrix.json"),
}

EVIDENCE_SEAL_EXACT_PATHS = {
    "contracts/v010-workstation-qualification.toml",
    "contracts/v010-workstation-slices.toml",
    "docs/qualification/v0.10.0.md",
    "docs/releases/v0.10.0.md",
}
EVIDENCE_SEAL_PREFIXES = (
    "qualification/v010/",
    "visual/baselines/",
)


class EvidenceError(RuntimeError):
    pass


def run(*args: str) -> str:
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()
    except subprocess.CalledProcessError as error:
        raise EvidenceError(
            f"command failed ({' '.join(args)}): {error.output.strip()}"
        ) from error


def load_completed_evidence(root: Path) -> dict[int, str]:
    path = root / LEDGER
    if not path.is_file():
        raise EvidenceError(f"missing v0.10 slice ledger: {LEDGER}")
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    slices = data.get("slice")
    if not isinstance(slices, list):
        raise EvidenceError("v0.10 slice ledger has no [[slice]] entries")

    owners: dict[int, str] = {}
    for item in slices:
        if not isinstance(item, dict) or item.get("status") != "complete":
            continue
        slice_id = item.get("id")
        evidence = item.get("evidence_prs")
        if not isinstance(slice_id, str) or slice_id not in SLICE_PATH_PREFIXES:
            raise EvidenceError(f"completed slice has no canonical path ownership: {slice_id!r}")
        if not isinstance(evidence, list) or not evidence:
            raise EvidenceError(f"completed slice {slice_id!r} lacks PR evidence")
        for value in evidence:
            if type(value) is not int or value <= 0:
                raise EvidenceError(f"{slice_id}: invalid evidence PR number {value!r}")
            previous = owners.get(value)
            if previous is not None:
                raise EvidenceError(f"PR #{value} is reused by {previous} and {slice_id}")
            owners[value] = slice_id
    return owners


def api_json(repository: str, endpoint: str) -> dict[str, object]:
    payload = json.loads(
        run(
            "gh",
            "api",
            "-H",
            "Accept: application/vnd.github+json",
            f"repos/{repository}/{endpoint}",
        )
    )
    if not isinstance(payload, dict):
        raise EvidenceError(f"unexpected GitHub response for {endpoint}")
    return payload


def recursive_tree_entries(
    repository: str,
    tree_sha: str,
) -> dict[str, tuple[str, str, str]]:
    payload = api_json(repository, f"git/trees/{tree_sha}?recursive=1")
    if payload.get("truncated") is not False:
        raise EvidenceError(
            f"recursive Git tree response is truncated or ambiguous for {tree_sha}; refusing incomplete evidence-seal validation"
        )
    entries = payload.get("tree")
    if not isinstance(entries, list):
        raise EvidenceError(f"recursive Git tree response is missing entries for {tree_sha}")
    result: dict[str, tuple[str, str, str]] = {}
    for item in entries:
        if not isinstance(item, dict):
            raise EvidenceError(f"recursive Git tree response has an invalid entry for {tree_sha}")
        kind = item.get("type")
        if kind == "tree":
            continue
        path = item.get("path")
        mode = item.get("mode")
        sha = item.get("sha")
        if (
            kind not in {"blob", "commit"}
            or not isinstance(path, str)
            or not path
            or not isinstance(mode, str)
            or not isinstance(sha, str)
            or SHA_RE.fullmatch(sha) is None
            or path in result
        ):
            raise EvidenceError(f"recursive Git tree response has an invalid leaf entry for {tree_sha}")
        result[path] = (mode, kind, sha)
    return result


def changed_tree_paths(
    repository: str,
    base_tree_sha: str,
    head_tree_sha: str,
) -> list[str]:
    base = recursive_tree_entries(repository, base_tree_sha)
    head = recursive_tree_entries(repository, head_tree_sha)
    return sorted(
        path
        for path in set(base) | set(head)
        if base.get(path) != head.get(path)
    )


def pr_file_records(repository: str, number: int) -> list[dict[str, object]]:
    output = run(
        "gh",
        "api",
        "--paginate",
        "--slurp",
        "-H",
        "Accept: application/vnd.github+json",
        f"repos/{repository}/pulls/{number}/files?per_page=100",
    )
    payload = json.loads(output)
    if not isinstance(payload, list):
        raise EvidenceError(f"PR #{number} changed-file response is not a page list")

    records: list[dict[str, object]] = []
    for page in payload:
        if not isinstance(page, list):
            raise EvidenceError(f"PR #{number} changed-file response contains an invalid page")
        for item in page:
            if not isinstance(item, dict):
                raise EvidenceError(f"PR #{number} changed-file response contains an invalid record")
            filename = item.get("filename")
            status = item.get("status")
            if not isinstance(filename, str) or not filename:
                raise EvidenceError(f"PR #{number} changed-file record is missing filename")
            if status not in {"added", "modified", "removed", "renamed"}:
                raise EvidenceError(
                    f"PR #{number} changed-file record has unsupported status {status!r}"
                )
            records.append(item)
    return records


def path_matches_slice(slice_id: str, path: str) -> bool:
    rules = SLICE_PATH_PREFIXES.get(slice_id)
    if not rules:
        return False
    return any(path == rule or (rule.endswith("/") and path.startswith(rule)) for rule in rules)


def require_slice_scope(repository: str, number: int, slice_id: str) -> None:
    records = pr_file_records(repository, number)
    if not records:
        raise EvidenceError(f"{slice_id}: PR #{number} has no reviewable changed files")

    matched = sorted(
        record["filename"]
        for record in records
        if record.get("status") in {"added", "modified"}
        and isinstance(record.get("filename"), str)
        and path_matches_slice(slice_id, record["filename"])
    )
    if not matched:
        owned = ", ".join(SLICE_PATH_PREFIXES[slice_id])
        raise EvidenceError(
            f"{slice_id}: PR #{number} does not add or modify a canonical owned path; "
            f"expected one of: {owned}"
        )


def evidence_seal_path_allowed(path: str) -> bool:
    return path in EVIDENCE_SEAL_EXACT_PATHS or any(
        path.startswith(prefix) for prefix in EVIDENCE_SEAL_PREFIXES
    )


def evidence_seal_record_paths(record: dict[str, object]) -> tuple[str, ...]:
    filename = record.get("filename")
    if not isinstance(filename, str) or not filename:
        raise EvidenceError("evidence-seal changed-file record is missing filename")
    if record.get("status") == "renamed":
        previous = record.get("previous_filename")
        if not isinstance(previous, str) or not previous:
            raise EvidenceError("renamed evidence-seal record is missing previous_filename")
        return (filename, previous)
    return (filename,)


def verify_evidence_seal(
    repository: str,
    qualification_source_sha: str,
    qualification_tree_sha: str,
    readiness_head_sha: str,
) -> str:
    readiness_commit = api_json(repository, f"git/commits/{readiness_head_sha}")
    parents = readiness_commit.get("parents")
    if (
        not isinstance(parents, list)
        or len(parents) != 1
        or not isinstance(parents[0], dict)
        or parents[0].get("sha") != qualification_source_sha
    ):
        raise EvidenceError(
            "readiness head must be exactly one evidence-seal commit above the qualification source"
        )

    comparison = api_json(
        repository,
        f"compare/{qualification_source_sha}...{readiness_head_sha}",
    )
    merge_base = comparison.get("merge_base_commit")
    merge_base_sha = merge_base.get("sha") if isinstance(merge_base, dict) else None
    if (
        comparison.get("status") != "ahead"
        or comparison.get("ahead_by") != 1
        or comparison.get("behind_by") != 0
        or comparison.get("total_commits") != 1
        or merge_base_sha != qualification_source_sha
    ):
        raise EvidenceError(
            "readiness head must be one linear evidence-seal commit above the qualification source"
        )

    # GitHub's compare file list is not complete for large diffs, but when a
    # rename record is present it carries source-path information that must not
    # be discarded. Validate both sides as an additional fail-closed check.
    comparison_files = comparison.get("files")
    if isinstance(comparison_files, list):
        for record in comparison_files:
            if not isinstance(record, dict):
                raise EvidenceError("evidence-seal compare returned an invalid changed-file record")
            for path in evidence_seal_record_paths(record):
                if not evidence_seal_path_allowed(path):
                    raise EvidenceError(
                        f"readiness evidence seal changed executable or non-evidence path: {path}"
                    )

    readiness_tree = readiness_commit.get("tree")
    readiness_tree_sha = readiness_tree.get("sha") if isinstance(readiness_tree, dict) else None
    if not isinstance(readiness_tree_sha, str) or SHA_RE.fullmatch(readiness_tree_sha) is None:
        raise EvidenceError("readiness evidence-seal tree identity is missing")

    # Compare API file lists are capped. Derive the complete changed path set from
    # the two immutable Git trees instead and fail closed if GitHub truncates either tree.
    changed = changed_tree_paths(
        repository,
        qualification_tree_sha,
        readiness_tree_sha,
    )
    if not changed:
        raise EvidenceError("readiness evidence seal must change at least one evidence-owned file")
    disallowed = sorted(path for path in changed if not evidence_seal_path_allowed(path))
    if disallowed:
        raise EvidenceError(
            "readiness evidence seal changed executable or non-evidence paths: "
            + ", ".join(disallowed)
        )
    return readiness_tree_sha

def verify(
    root: Path,
    repository: str,
    qualification_source_sha: str,
    *,
    readiness_pr_number: int,
    readiness_head_sha: str,
    readiness_merge_sha: str,
) -> None:
    if not re.fullmatch(r"[^/\s]+/[^/\s]+", repository):
        raise EvidenceError("repository must be owner/name")
    if SHA_RE.fullmatch(qualification_source_sha) is None:
        raise EvidenceError("qualification source must be a lowercase 40-hex Git SHA")
    if readiness_pr_number <= 0:
        raise EvidenceError("readiness PR number must be positive")
    if SHA_RE.fullmatch(readiness_head_sha) is None:
        raise EvidenceError("readiness head SHA must be a lowercase 40-hex Git SHA")
    if SHA_RE.fullmatch(readiness_merge_sha) is None:
        raise EvidenceError("readiness merge SHA must be a lowercase 40-hex Git SHA")

    source = api_json(repository, f"git/commits/{qualification_source_sha}")
    if source.get("sha") != qualification_source_sha:
        raise EvidenceError("qualification source commit identity mismatch")
    source_tree = source.get("tree")
    source_tree_sha = source_tree.get("sha") if isinstance(source_tree, dict) else None
    if not isinstance(source_tree_sha, str) or SHA_RE.fullmatch(source_tree_sha) is None:
        raise EvidenceError("qualification source tree identity is missing")

    readiness_tree_sha = verify_evidence_seal(
        repository,
        qualification_source_sha,
        source_tree_sha,
        readiness_head_sha,
    )

    owners = load_completed_evidence(root)
    if not owners:
        raise EvidenceError("v0.10 slice ledger has no completed PR evidence")

    for number, slice_id in sorted(owners.items()):
        payload = api_json(repository, f"pulls/{number}")
        if payload.get("number") != number:
            raise EvidenceError(f"{slice_id}: PR #{number} identity mismatch")
        if payload.get("state") != "closed" or not payload.get("merged_at"):
            raise EvidenceError(f"{slice_id}: PR #{number} is not merged")
        base = payload.get("base")
        if not isinstance(base, dict) or base.get("ref") != "main":
            raise EvidenceError(f"{slice_id}: PR #{number} was not merged to main")
        base_repo = base.get("repo")
        if not isinstance(base_repo, dict) or base_repo.get("full_name") != repository:
            raise EvidenceError(f"{slice_id}: PR #{number} targets a different repository")
        merge_sha = payload.get("merge_commit_sha")
        if not isinstance(merge_sha, str) or SHA_RE.fullmatch(merge_sha) is None:
            raise EvidenceError(f"{slice_id}: PR #{number} has no canonical merge commit")

        if number == readiness_pr_number:
            if merge_sha != readiness_merge_sha:
                raise EvidenceError(
                    f"{slice_id}: readiness PR #{number} merge does not match protected-main readiness source"
                )
            head = payload.get("head")
            head_sha = head.get("sha") if isinstance(head, dict) else None
            head_repo = head.get("repo") if isinstance(head, dict) else None
            if head_sha != readiness_head_sha:
                raise EvidenceError(
                    f"{slice_id}: readiness PR #{number} head is not the reviewed evidence-seal source"
                )
            if not isinstance(head_repo, dict) or head_repo.get("full_name") != repository:
                raise EvidenceError(f"{slice_id}: readiness PR #{number} head is not repository-owned")
            merge_commit = api_json(repository, f"git/commits/{merge_sha}")
            merge_tree = merge_commit.get("tree")
            merge_tree_sha = merge_tree.get("sha") if isinstance(merge_tree, dict) else None
            if merge_tree_sha != readiness_tree_sha:
                raise EvidenceError(
                    f"{slice_id}: readiness PR #{number} squash tree differs from reviewed evidence-seal tree"
                )
        else:
            comparison = api_json(
                repository,
                f"compare/{merge_sha}...{qualification_source_sha}",
            )
            merge_base = comparison.get("merge_base_commit")
            merge_base_sha = merge_base.get("sha") if isinstance(merge_base, dict) else None
            if comparison.get("status") not in {"ahead", "identical"} or merge_base_sha != merge_sha:
                raise EvidenceError(
                    f"{slice_id}: PR #{number} merge {merge_sha} is not an ancestor of the reviewed qualification source"
                )

        require_slice_scope(repository, number, slice_id)

    print(
        f"v0.10 merged-PR evidence verified: {len(owners)} unique PRs on {qualification_source_sha}"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify v0.10 slice PR evidence against GitHub, canonical slice ownership and reviewed source lineage."
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--qualification-source-sha", required=True)
    parser.add_argument("--readiness-pr-number", required=True, type=int)
    parser.add_argument("--readiness-head-sha", required=True)
    parser.add_argument("--readiness-merge-sha", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        verify(
            args.root.resolve(),
            args.repository,
            args.qualification_source_sha,
            readiness_pr_number=args.readiness_pr_number,
            readiness_head_sha=args.readiness_head_sha,
            readiness_merge_sha=args.readiness_merge_sha,
        )
    except (EvidenceError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        print(f"v0.10 slice PR evidence verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
