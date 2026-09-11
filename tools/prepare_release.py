#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import re
import tomllib

TAG_RE = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
PACKAGE_BLOCK_RE = re.compile(r"(?ms)^\[\[package\]\]\n.*?(?=^\[\[package\]\]\n|\Z)")
NAME_RE = re.compile(r'(?m)^name = "([^"]+)"$')
VERSION_LINE_RE = re.compile(r'(?m)^version = "([^"]+)"$')


class PreparationError(RuntimeError):
    pass


def _version_tuple(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value)
    if match is None:
        raise PreparationError(f"invalid workspace version: {value!r}")
    return tuple(int(part) for part in match.groups())


def _workspace_package_names(root: Path, workspace: dict[str, object]) -> set[str]:
    members = workspace.get("members")
    if not isinstance(members, list) or not members or not all(isinstance(item, str) for item in members):
        raise PreparationError("workspace.members must be a non-empty string array")

    names: set[str] = set()
    for member in members:
        manifest_path = root / member / "Cargo.toml"
        if not manifest_path.is_file():
            raise PreparationError(f"workspace member manifest is missing: {member}/Cargo.toml")
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        package = manifest.get("package")
        if not isinstance(package, dict):
            raise PreparationError(f"workspace member has no [package] table: {member}")
        name = package.get("name")
        if not isinstance(name, str) or not name:
            raise PreparationError(f"workspace member has invalid package name: {member}")

        version = package.get("version")
        uses_workspace_version = isinstance(version, dict) and version.get("workspace") is True
        if uses_workspace_version:
            names.add(name)
        elif isinstance(version, str):
            continue
        else:
            raise PreparationError(
                f"workspace member {name!r} must use version.workspace=true or an explicit version"
            )

    if not names:
        raise PreparationError("no workspace-versioned packages found")
    return names


def _replace_workspace_version(cargo_text: str, old: str, new: str) -> str:
    pattern = re.compile(
        r'(?ms)(^\[workspace\.package\]\n.*?^version = ")'
        + re.escape(old)
        + r'(".*?)(?=^\[|\Z)'
    )
    updated, count = pattern.subn(rf"\g<1>{new}\g<2>", cargo_text, count=1)
    if count != 1:
        raise PreparationError("unable to replace exactly one [workspace.package] version")
    return updated


def _rewrite_lock(lock_text: str, package_names: set[str], old: str, new: str) -> str:
    seen: set[str] = set()

    def rewrite(match: re.Match[str]) -> str:
        block = match.group(0)
        name_match = NAME_RE.search(block)
        version_match = VERSION_LINE_RE.search(block)
        if name_match is None or version_match is None:
            return block

        name = name_match.group(1)
        if name not in package_names:
            return block

        version = version_match.group(1)
        if version != old:
            raise PreparationError(
                f"workspace package {name!r} has lockfile version {version!r}; expected {old!r}"
            )
        if name in seen:
            raise PreparationError(f"duplicate workspace package in Cargo.lock: {name}")
        seen.add(name)
        start, end = version_match.span(1)
        return block[:start] + new + block[end:]

    updated = PACKAGE_BLOCK_RE.sub(rewrite, lock_text)
    missing = sorted(package_names - seen)
    if missing:
        raise PreparationError(f"workspace packages missing from Cargo.lock: {missing}")
    return updated


def prepare(root: Path, tag: str) -> list[str]:
    match = TAG_RE.fullmatch(tag)
    if match is None:
        raise PreparationError(f"invalid release tag: {tag!r}")
    target_version = tag[1:]

    roadmap_path = root / "contracts" / "roadmap.toml"
    cargo_path = root / "Cargo.toml"
    lock_path = root / "Cargo.lock"
    for path in (roadmap_path, cargo_path, lock_path):
        if not path.is_file():
            raise PreparationError(f"required file is missing: {path.relative_to(root)}")

    roadmap = tomllib.loads(roadmap_path.read_text(encoding="utf-8"))
    if roadmap.get("next_release") != tag:
        raise PreparationError(
            f"requested tag is not roadmap next_release: {tag!r} != {roadmap.get('next_release')!r}"
        )
    milestones = {
        item.get("version"): item
        for item in roadmap.get("milestone", [])
        if isinstance(item, dict) and isinstance(item.get("version"), str)
    }
    milestone = milestones.get(tag)
    if not isinstance(milestone, dict):
        raise PreparationError(f"roadmap milestone is missing: {tag}")
    if milestone.get("status") != "planned":
        raise PreparationError(
            f"release-preparation milestone must be planned: {tag} status={milestone.get('status')!r}"
        )

    release_contract = milestone.get("release_contract")
    qualification = milestone.get("qualification")
    milestone_contract = milestone.get("milestone_contract")
    for label, value in (
        ("release_contract", release_contract),
        ("qualification", qualification),
        ("milestone_contract", milestone_contract),
    ):
        if not isinstance(value, str) or not (root / value).is_file():
            raise PreparationError(f"{tag}: required {label} is missing or invalid: {value!r}")

    for required in (
        root / "docs" / "qualification" / f"{tag}-security.md",
        root / "docs" / "qualification" / f"{tag}-release-review.md",
    ):
        if not required.is_file():
            raise PreparationError(f"release-readiness document is missing: {required.relative_to(root)}")

    cargo_text = cargo_path.read_text(encoding="utf-8")
    cargo = tomllib.loads(cargo_text)
    workspace = cargo.get("workspace")
    if not isinstance(workspace, dict):
        raise PreparationError("Cargo.toml is missing [workspace]")
    workspace_package = workspace.get("package")
    if not isinstance(workspace_package, dict):
        raise PreparationError("Cargo.toml is missing [workspace.package]")
    current_version = workspace_package.get("version")
    if not isinstance(current_version, str):
        raise PreparationError("workspace.package.version must be a string")

    package_names = _workspace_package_names(root, workspace)
    lock_text = lock_path.read_text(encoding="utf-8")

    # Release preparation is deliberately idempotent. A retry/recovery may start from
    # an exact reviewed tree whose workspace metadata was already advanced by an
    # earlier preparation attempt. In that case we still fully validate Cargo.lock
    # coherence and return a zero-change result; the workflow records a zero-diff,
    # SHA-addressed preparation handoff instead of mutating the reviewed tree.
    if current_version == target_version:
        lock_verified = _rewrite_lock(lock_text, package_names, target_version, target_version)
        if lock_verified != lock_text:
            raise PreparationError("idempotent release preparation unexpectedly changed Cargo.lock")
        return []

    if _version_tuple(target_version) <= _version_tuple(current_version):
        raise PreparationError(
            f"release version must advance monotonically: {current_version} -> {target_version}"
        )

    cargo_updated = _replace_workspace_version(cargo_text, current_version, target_version)
    lock_updated = _rewrite_lock(lock_text, package_names, current_version, target_version)

    changed: list[str] = []
    if cargo_updated != cargo_text:
        cargo_path.write_text(cargo_updated, encoding="utf-8")
        changed.append("Cargo.toml")
    if lock_updated != lock_text:
        lock_path.write_text(lock_updated, encoding="utf-8")
        changed.append("Cargo.lock")

    if changed != ["Cargo.toml", "Cargo.lock"]:
        raise PreparationError(f"release preparation must change exactly Cargo.toml and Cargo.lock, got {changed}")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Apply Linura's deterministic release-preparation version bump, or validate an "
            "already-prepared target version idempotently."
        )
    )
    parser.add_argument("--tag", required=True)
    parser.add_argument("--root", default=".")
    args = parser.parse_args()

    try:
        changed = prepare(Path(args.root).resolve(), args.tag)
    except (OSError, tomllib.TOMLDecodeError, PreparationError) as error:
        print(f"release preparation failed: {error}", file=__import__("sys").stderr)
        return 2

    for path in changed:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
