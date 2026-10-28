"""Retain and check one exact-source, unqualified compositor build candidate.

This is a same-workflow build handoff, not a signed release, executable authority
or qualification evidence. The disposable guest independently compares the
candidate's native identity with its freshly configured protected owner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import qualification_build_artifacts as artifacts  # noqa: E402

FILES = {
    "Hyprland": 512 * 1024**2,
    "integration-build.h": 4096,
    "prepared-substrate.json": 1024 * 1024,
    "staged-source.json": 64 * 1024,
}
MANIFEST = "candidate.json"
HEX = re.compile(r"[0-9a-f]{64}")
HEADER = re.compile(
    rb"#pragma once\n\nnamespace Linura::HyprlandDisplay {\n"
    rb'inline constexpr char IntegrationSourceDigest\[\] = "([0-9a-f]{64})";\n}\n'
)
INPUTS = (
    "contracts/hyprland-display-integration.toml",
    "contracts/s21-hyprland-build-environment.toml",
    "apps/linura-hyprland-display/source_integration.py",
)


def regular(path: Path, limit: int) -> None:
    for parent in (path.parent, *path.parent.parents):
        if not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError("candidate has a substituted parent")
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or not 0 < info.st_size <= limit
    ):
        raise ValueError("candidate input is linked, missing, empty or oversized")


def read_bounded(path: Path, limit: int) -> bytes:
    regular(path, limit)
    descriptor = artifacts._open_source(path)
    try:
        before = os.fstat(descriptor)
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            payload = stream.read(limit + 1)
        artifacts._check_source(path, descriptor, before)
        if not 0 < len(payload) == before.st_size <= limit:
            raise ValueError("candidate changed or exceeded its read budget")
        return payload
    finally:
        os.close(descriptor)


def unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate candidate metadata key")
        result[key] = value
    return result


def document(path: Path, limit: int) -> dict:
    result = json.loads(read_bounded(path, limit), object_pairs_hook=unique)
    if not isinstance(result, dict):
        raise ValueError("candidate metadata must be an object")
    return result


def identity(header: Path) -> str:
    match = HEADER.fullmatch(read_bounded(header, FILES["integration-build.h"]))
    if match is None:
        raise ValueError("candidate native build identity is malformed")
    return match[1].decode("ascii")


def source_binding(root: Path, sha: str) -> dict:
    if re.fullmatch(r"[0-9a-f]{40}", sha) is None:
        raise ValueError("candidate requires an exact source SHA")
    inputs = {
        name: hashlib.sha256(read_bounded(root / name, 2 * 1024**2)).hexdigest()
        for name in INPUTS
    }
    pin = tomllib.loads(read_bounded(root / INPUTS[0], 65536).decode())
    return {
        "schema_version": 1,
        "claim": "unqualified-native-display-build-candidate",
        "source_sha": sha,
        "source_inputs": inputs,
        "upstream_commit": pin["upstream_commit"],
        "upstream_archive_sha256": pin["source_sha256"],
        "qualification_evidence": False,
        "native_execution_qualified": False,
        "rollback_qualified": False,
        "s17_qualified": False,
    }


def verify(
    root: Path, candidate: Path, sha: str, owner_header: Path | None = None
) -> dict:
    if not stat.S_ISDIR(candidate.lstat().st_mode) or {
        item.name for item in candidate.iterdir()
    } != {*FILES, MANIFEST}:
        raise ValueError("candidate file inventory differs from its closed contract")
    metadata = document(candidate / MANIFEST, 65536)
    expected = source_binding(root, sha)
    if set(metadata) != {
        *expected,
        "files",
        "integration_source_digest",
        "build_input_sha256",
    }:
        raise ValueError("candidate metadata schema differs from its closed contract")
    for key, value in expected.items():
        if type(metadata[key]) is not type(value) or metadata[key] != value:
            raise ValueError("candidate source, contract or claim mismatch: " + key)
    if not isinstance(metadata["build_input_sha256"], str) or not HEX.fullmatch(
        metadata["build_input_sha256"]
    ):
        raise ValueError("candidate build inputs are not digest-bound")
    records = metadata["files"]
    if not isinstance(records, dict) or set(records) != set(FILES):
        raise ValueError("candidate file bindings are incomplete")
    for name, limit in FILES.items():
        path = candidate / name
        regular(path, limit)
        digest, size = artifacts._bind_file(path, max_size=limit)
        if records[name] != {
            "path": "retained:" + name,
            "sha256": digest,
            "size": size,
        }:
            raise ValueError(
                "candidate retained bytes differ from their binding: " + name
            )
    native_identity = identity(candidate / "integration-build.h")
    if metadata["integration_source_digest"] != native_identity or (
        owner_header is not None and identity(owner_header) != native_identity
    ):
        raise ValueError(
            "compositor and protected owner native build identities differ"
        )
    prepared = document(
        candidate / "prepared-substrate.json", FILES["prepared-substrate.json"]
    )
    contract = tomllib.loads(read_bounded(root / INPUTS[1], 65536).decode())
    if (
        prepared.get("id") != contract["id"]
        or prepared.get("contract_sha256") != expected["source_inputs"][INPUTS[1]]
        or prepared.get("claim") != "non-authoritative-prepared-substrate"
        or prepared.get("qualification_evidence") is not False
        or prepared.get("sanitized") is not True
        or not isinstance(prepared.get("prepared_image_sha256"), str)
        or not HEX.fullmatch(prepared["prepared_image_sha256"])
    ):
        raise ValueError("candidate build substrate does not match its pinned contract")
    packages = prepared.get("package_versions")
    if not isinstance(packages, list) or any(
        not isinstance(row, str) or len(row.split(" ")) != 2 for row in packages
    ):
        raise ValueError("candidate package inventory is malformed")
    installed = dict(row.split(" ", 1) for row in packages)
    if len(installed) != len(packages) or any(
        installed.get(row["name"]) != row["version"]
        for row in [*contract["package"], contract["archived_package"]]
    ):
        raise ValueError("candidate package inventory differs from the pinned SDK")
    staged = document(candidate / "staged-source.json", FILES["staged-source.json"])
    if (
        staged.get("schema_version") != 1
        or staged.get("upstream_commit") != expected["upstream_commit"]
        or staged.get("source_sha256") != expected["upstream_archive_sha256"]
        or staged.get("integration_recipe_sha256")
        != expected["source_inputs"][INPUTS[2]]
        or staged.get("qualification_evidence") is not False
    ):
        raise ValueError("candidate staged source differs from the reviewed recipe")
    # ELF64, little-endian, version 1, AMD64. This rejects accidental script,
    # host/other-architecture and truncation handoffs; it is not code attestation.
    with (candidate / "Hyprland").open("rb") as stream:
        elf = stream.read(20)
    if len(elf) != 20 or elf[:7] != b"\x7fELF\x02\x01\x01" or elf[18:20] != b"\x3e\x00":
        raise ValueError("candidate is not an AMD64 ELF compositor")
    return metadata


def verify_runtime_packages(root: Path, candidate: Path, inventory: str) -> str:
    """Require the runtime's installed packages to agree with the frozen SDK.

    The build contains additional development packages. Those need not be
    installed in the runtime; installed runtime packages cannot substitute a
    different version or introduce an unbound package/provider.
    """
    if not 0 < len(inventory) <= 1024 * 1024:
        raise ValueError("runtime package inventory exceeds its bound")
    rows = inventory.splitlines()
    if len(rows) > 8192 or any(len(row.split(" ")) != 2 for row in rows):
        raise ValueError("runtime package inventory is malformed")
    observed = dict(row.split(" ", 1) for row in rows)
    prepared = document(
        candidate / "prepared-substrate.json", FILES["prepared-substrate.json"]
    )
    expected = dict(row.split(" ", 1) for row in prepared["package_versions"])
    contract = tomllib.loads(read_bounded(root / INPUTS[1], 65536).decode())
    if (
        len(observed) != len(rows)
        or not set(contract["runtime_packages"]) <= observed.keys()
        or any(expected.get(name) != version for name, version in observed.items())
    ):
        raise ValueError("runtime packages differ from the pinned compositor SDK")
    return hashlib.sha256(("\n".join(sorted(rows)) + "\n").encode()).hexdigest()


def retain(
    root: Path, destination: Path, sha: str, inputs: dict[str, Path], record: dict
) -> dict:
    if set(inputs) != set(FILES) or (
        record.get("source_sha") != sha
        or record.get("dirty") is not False
        or record.get("development") is not False
        or record.get("build_passed") is not True
        or record.get("qualification_evidence") is not False
    ):
        raise ValueError("only a completed clean exact-source build can be handed off")
    metadata = source_binding(root, sha)
    for name, path in inputs.items():
        regular(path, FILES[name])
    destination.mkdir(mode=0o700, exist_ok=False)
    metadata.update(
        files=artifacts.bind_artifacts(
            root, destination, inputs, dict(zip(FILES, FILES)), max_sizes=FILES
        ),
        integration_source_digest=identity(inputs["integration-build.h"]),
        build_input_sha256=record["build_input_sha256"],
    )
    with (destination / MANIFEST).open("x", encoding="utf-8") as stream:
        json.dump(metadata, stream, sort_keys=True, indent=2)
        stream.write("\n")
    return verify(root, destination, sha)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    verify(ROOT, args.candidate, args.source_sha)
    print(
        "Exact-source compositor candidate verified; native qualification remains required."
    )


if __name__ == "__main__":
    main()
