#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
QUALIFICATION_PATH = "qualification/v0.10/qualification-contract.toml"
PRE_SEAL_RUNTIME_PATH = "runtime/pre-seal/V010-SHELL-RUNTIME-EVIDENCE.json"
PREPARED_RUNTIME_PATH = "runtime/prepared-release/V010-SHELL-RUNTIME-EVIDENCE.json"


class ProofError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, label: str) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise ProofError(f"{label} is missing or unsafe: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProofError(f"{label} is not valid JSON: {path}") from error
    if not isinstance(value, dict):
        raise ProofError(f"{label} must be a JSON object")
    return value


def safe_relative_file(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProofError(f"{label} must be a non-empty relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ProofError(f"{label} is unsafe: {value!r}")
    return value


def valid_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ProofError(f"{label} must be a lowercase SHA-256 digest")
    return value


def runtime_authority(evidence: dict[str, object], label: str) -> dict[str, object]:
    if evidence.get("result") != "passed":
        raise ProofError(f"{label} did not pass")
    authority = evidence.get("authority_runtime")
    if not isinstance(authority, dict):
        raise ProofError(f"{label} authority_runtime is missing")
    return authority


def verify(
    proof_dir: Path,
    repository: str,
    source_sha: str,
    release_tag: str,
    release_version: str,
    proof_run_id: str,
    qualification_source_sha: str,
    qualification_tree_sha: str,
) -> None:
    if not re.fullmatch(r"[^/\s]+/[^/\s]+", repository):
        raise ProofError("repository must be owner/name")
    if SHA40_RE.fullmatch(source_sha) is None:
        raise ProofError("source SHA must be lowercase 40-hex")
    if SHA40_RE.fullmatch(qualification_source_sha) is None:
        raise ProofError("qualification source SHA must be lowercase 40-hex")
    if SHA40_RE.fullmatch(qualification_tree_sha) is None:
        raise ProofError("qualification tree SHA must be lowercase 40-hex")
    if not proof_run_id.isdigit():
        raise ProofError("proof run id must be numeric")
    if release_tag != f"v{release_version}":
        raise ProofError("release tag/version mismatch")

    root = proof_dir.resolve()
    if not root.is_dir() or root.is_symlink():
        raise ProofError("proof directory is missing or unsafe")
    payload = root / "release-payload"
    if not payload.is_dir() or payload.is_symlink():
        raise ProofError("release payload directory is missing or unsafe")

    receipt = load_json(root / "release-proof.json", "release proof receipt")
    if receipt.get("schema_version") != 2:
        raise ProofError("unsupported release proof schema")
    if receipt.get("repository") != repository:
        raise ProofError("release proof repository mismatch")
    if receipt.get("source_sha") != source_sha:
        raise ProofError("release proof source mismatch")
    if receipt.get("tag") != release_tag:
        raise ProofError("release proof tag mismatch")
    if receipt.get("version") != release_version:
        raise ProofError("release proof version mismatch")
    if str(receipt.get("run_id")) != proof_run_id:
        raise ProofError("release proof run mismatch")

    qualifications = receipt.get("qualifications")
    if not isinstance(qualifications, dict):
        raise ProofError("release proof qualification declaration missing")
    declaration = qualifications.get("v0.10")
    if not isinstance(declaration, dict):
        raise ProofError("v0.10 qualification declaration missing")
    if declaration.get("schema_version") != 1:
        raise ProofError("unexpected v0.10 qualification schema")
    if declaration.get("result") != "passed":
        raise ProofError("v0.10 qualification did not pass")
    if declaration.get("source_sha") != source_sha:
        raise ProofError("v0.10 prepared release source mismatch")
    if declaration.get("qualification_source_sha") != qualification_source_sha:
        raise ProofError("v0.10 qualification source mismatch")
    if declaration.get("qualification_tree_sha") != qualification_tree_sha:
        raise ProofError("v0.10 qualification tree mismatch")
    if declaration.get("path") != QUALIFICATION_PATH:
        raise ProofError("unexpected v0.10 qualification path")

    qualification_root = root / "qualification" / "v0.10"
    if not qualification_root.is_dir() or qualification_root.is_symlink():
        raise ProofError("v0.10 qualification directory is missing or unsafe")
    qualification_contract = root / QUALIFICATION_PATH
    if not qualification_contract.is_file() or qualification_contract.is_symlink():
        raise ProofError("v0.10 qualification contract is missing or unsafe")

    declared_files = declaration.get("files")
    if not isinstance(declared_files, list) or not declared_files:
        raise ProofError("v0.10 qualification file declaration missing")
    expected_files: dict[str, tuple[int, str]] = {}
    for item in declared_files:
        if not isinstance(item, dict):
            raise ProofError("invalid v0.10 qualification file declaration")
        name = safe_relative_file(item.get("name"), "v0.10 qualification file name")
        size = item.get("size")
        digest = valid_digest(item.get("sha256"), f"v0.10 qualification digest for {name}")
        if type(size) is not int or size < 0 or name in expected_files:
            raise ProofError(f"invalid or duplicate v0.10 qualification file declaration: {name}")
        expected_files[name] = (size, digest)

    actual_files: dict[str, tuple[int, str]] = {}
    for path in sorted(qualification_root.rglob("*")):
        if path.is_symlink():
            raise ProofError(f"v0.10 qualification contains a symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ProofError(f"v0.10 qualification contains a non-regular entry: {path}")
        relative = path.relative_to(qualification_root).as_posix()
        actual_files[relative] = (path.stat().st_size, sha256(path))
    if actual_files != expected_files:
        raise ProofError("v0.10 qualification evidence does not match proof receipt")

    runtime_binding = declaration.get("runtime_binding")
    if not isinstance(runtime_binding, dict):
        raise ProofError("v0.10 runtime binding is missing")
    if runtime_binding.get("qualification_source_evidence") != PRE_SEAL_RUNTIME_PATH:
        raise ProofError("unexpected v0.10 pre-seal runtime evidence path")
    if runtime_binding.get("prepared_release_evidence") != PREPARED_RUNTIME_PATH:
        raise ProofError("unexpected v0.10 prepared runtime evidence path")

    qualification_linurad = valid_digest(
        runtime_binding.get("qualification_linurad_sha256"),
        "v0.10 qualification linurad digest",
    )
    prepared_linurad = valid_digest(
        runtime_binding.get("prepared_linurad_sha256"),
        "v0.10 prepared linurad digest",
    )
    shell_bridge = valid_digest(
        runtime_binding.get("shell_bridge_sha256"),
        "v0.10 ShellBridge digest",
    )

    pre_seal = load_json(
        qualification_root / PRE_SEAL_RUNTIME_PATH,
        "v0.10 pre-seal runtime evidence",
    )
    prepared = load_json(
        qualification_root / PREPARED_RUNTIME_PATH,
        "v0.10 prepared runtime evidence",
    )
    if pre_seal.get("repository") != repository or prepared.get("repository") != repository:
        raise ProofError("v0.10 runtime evidence repository mismatch")
    if pre_seal.get("source_sha") != qualification_source_sha:
        raise ProofError("v0.10 pre-seal runtime source mismatch")
    if prepared.get("source_sha") != source_sha:
        raise ProofError("v0.10 prepared runtime source mismatch")

    pre_authority = runtime_authority(pre_seal, "v0.10 pre-seal runtime")
    prepared_authority = runtime_authority(prepared, "v0.10 prepared runtime")
    if pre_authority.get("linurad_sha256") != qualification_linurad:
        raise ProofError("v0.10 pre-seal linurad binding mismatch")
    if prepared_authority.get("linurad_sha256") != prepared_linurad:
        raise ProofError("v0.10 prepared linurad binding mismatch")
    if pre_authority.get("shell_bridge_sha256") != shell_bridge:
        raise ProofError("v0.10 pre-seal ShellBridge binding mismatch")
    if prepared_authority.get("shell_bridge_sha256") != shell_bridge:
        raise ProofError("v0.10 prepared ShellBridge binding mismatch")

    payload_linurad = payload / "linurad"
    if not payload_linurad.is_file() or payload_linurad.is_symlink():
        raise ProofError("release payload linurad is missing or unsafe")
    if sha256(payload_linurad) != prepared_linurad:
        raise ProofError("release payload linurad does not match prepared runtime proof")

    print(
        "v0.10 release proof verified: "
        f"{len(actual_files)} recursively sealed qualification files, "
        "pre-seal and prepared runtime bindings, and shipped linurad"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify the recursively sealed v0.10 qualification and runtime bindings in a Trusted Release Proof."
    )
    parser.add_argument("--proof-dir", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--proof-run-id", required=True)
    parser.add_argument("--qualification-source-sha", required=True)
    parser.add_argument("--qualification-tree-sha", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        verify(
            args.proof_dir,
            args.repository,
            args.source_sha,
            args.release_tag,
            args.release_version,
            args.proof_run_id,
            args.qualification_source_sha,
            args.qualification_tree_sha,
        )
    except ProofError as error:
        print(f"v0.10 release proof verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
