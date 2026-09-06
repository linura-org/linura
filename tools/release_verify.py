#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import sys
import tomllib

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FIXED_RELEASE_PAYLOAD_FILES = {
    "BUILD-ENVIRONMENT.json",
    "RELEASE-EVIDENCE.json",
    "RELEASE_NOTES.md",
    "RELEASE_TAG",
    "SHA256SUMS",
    "SOURCE_SHA",
    "linura.spdx.json",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def declared_release_binaries(contract_path: Path) -> set[str]:
    data = tomllib.loads(contract_path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("unsupported component contract schema")
    raw_components = data.get("component")
    if not isinstance(raw_components, list):
        raise ValueError("component contract is missing [[component]] entries")

    binaries: set[str] = set()
    for component in raw_components:
        if not isinstance(component, dict) or component.get("release_artifact") is not True:
            continue
        binary = component.get("binary")
        if not isinstance(binary, str) or not binary or Path(binary).name != binary:
            raise ValueError(f"invalid release binary declaration: {binary!r}")
        if binary in binaries:
            raise ValueError(f"duplicate release binary declaration: {binary}")
        binaries.add(binary)
    return binaries


def regular_flat_files(directory: Path) -> tuple[set[str], list[str]]:
    names: set[str] = set()
    failures: list[str] = []
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file():
            failures.append(f"payload entry must be a flat regular file: {path.name}")
            continue
        names.add(path.name)
    return names, failures


def verify_manifest(directory: Path, manifest_name: str) -> tuple[set[str], list[str]]:
    manifest = directory / manifest_name
    if not manifest.is_file() or manifest.is_symlink():
        return set(), [f"missing checksum manifest: {manifest}"]

    failures: list[str] = []
    declared: dict[str, str] = {}
    for line_number, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        parts = raw.split(None, 1)
        if len(parts) != 2:
            failures.append(f"invalid checksum manifest line {line_number}")
            continue
        digest, filename = parts
        filename = filename.lstrip("*")
        if not SHA256_RE.fullmatch(digest):
            failures.append(f"invalid SHA-256 digest on line {line_number}: {digest!r}")
            continue
        if not filename or Path(filename).name != filename or filename == manifest_name:
            failures.append(f"invalid checksum filename on line {line_number}: {filename!r}")
            continue
        if filename in declared:
            failures.append(f"duplicate checksum entry: {filename}")
            continue
        declared[filename] = digest

    for filename, expected in declared.items():
        path = directory / filename
        if path.is_symlink() or not path.is_file():
            failures.append(f"missing regular asset: {filename}")
            continue
        actual = sha256(path)
        if actual != expected:
            failures.append(f"digest mismatch: {filename}: expected {expected}, got {actual}")

    actual_names, entry_failures = regular_flat_files(directory)
    failures.extend(entry_failures)
    expected_manifest_names = actual_names - {manifest_name}
    declared_names = set(declared)
    if declared_names != expected_manifest_names:
        missing = sorted(expected_manifest_names - declared_names)
        extra = sorted(declared_names - expected_manifest_names)
        if missing:
            failures.append(f"payload assets missing from checksum manifest: {missing}")
        if extra:
            failures.append(f"checksum manifest references non-payload assets: {extra}")

    return actual_names, failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Linura release payload integrity and membership")
    parser.add_argument("directory", type=Path)
    parser.add_argument("--manifest", default="SHA256SUMS")
    parser.add_argument("--component-contract", type=Path)
    args = parser.parse_args()

    directory = args.directory.resolve()
    if not directory.is_dir():
        print(f"release payload directory does not exist: {directory}", file=sys.stderr)
        return 2

    actual_names, failures = verify_manifest(directory, args.manifest)

    if args.component_contract is not None:
        try:
            binaries = declared_release_binaries(args.component_contract.resolve())
        except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
            failures.append(f"cannot load component release contract: {error}")
        else:
            expected_names = binaries | FIXED_RELEASE_PAYLOAD_FILES
            if actual_names != expected_names:
                unexpected = sorted(actual_names - expected_names)
                missing = sorted(expected_names - actual_names)
                if unexpected:
                    failures.append(f"payload contains undeclared component/artifact files: {unexpected}")
                if missing:
                    failures.append(f"payload is missing declared component/artifact files: {missing}")

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1

    checked = len(actual_names - {args.manifest})
    suffix = " with component-contract membership" if args.component_contract is not None else ""
    print(f"verified {checked} release assets{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
