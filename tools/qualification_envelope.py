#!/usr/bin/env python3
"""Create and verify versioned qualification execution envelopes.

An execution envelope identifies the exact source/tree, repository-controlled
configuration, runner image identity, explicit dynamic digests, and verified
cache content that a qualification lane actually used. It is not a pass receipt.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = Path("contracts/qualification-execution-envelopes.toml")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
CONTRACT_IDENTITIES = {
    "schema_version": 2,
    "id": "qualification/execution-envelopes",
    "digest_algorithm": "sha256",
    "canonicalization": "json-sort-keys-compact-utf8-v1",
    "source_identity": "git-commit-and-tree-v1",
    "runner_identity": "explicit-runner-image-and-architecture-v1",
    "toolchain_identity": "repository-file-digests-v1",
    "cache_identity": "content-digest-after-independent-verification-v1",
    "freshness_identity": "separate-observation-not-deterministic-input-v1",
    "execution_identity": "orchestrator-and-execution-subject-v1",
}
HOSTED_INTEGRATION_ACTION = ".github/actions/qualification-envelope/action.yml"
OS_RELEASE_PATH = Path("/etc/os-release")
OS_RELEASE_ALLOWED_TARGETS = (
    Path("/etc/os-release"),
    Path("/usr/lib/os-release"),
)

REQUIRED_LANE_BINDINGS = {
    "canonical-ci": ("github-hosted", "workflow", ".github/workflows/ci.yml"),
    "security-rustsec": ("github-hosted", "workflow", ".github/workflows/security.yml"),
    "codeql": ("github-hosted", "workflow", ".github/workflows/codeql.yml"),
    "codex-environment": ("github-hosted", "workflow", ".github/workflows/codex-environment.yml"),
    "evidence-publication": ("github-hosted", "workflow", ".github/workflows/evidence-publication-checks.yml"),
    "vm-acceptance": ("github-hosted", "workflow", ".github/workflows/vm-acceptance.yml"),
    "control1-plan-preview-vm": ("github-hosted", "workflow", ".github/workflows/control1-plan-preview-vm.yml"),
    "v04-durability": ("github-hosted", "workflow", ".github/workflows/v04-durability-vm.yml"),
    "v04-enospc": ("github-hosted", "workflow", ".github/workflows/v04-enospc-recovery-vm.yml"),
    "v05-executor-verifier": ("github-hosted", "workflow", ".github/workflows/v05-executor-verifier-vm.yml"),
    "v06-managed-lifecycle": ("github-hosted", "workflow", ".github/workflows/v06-managed-lifecycle-vm.yml"),
    "v07-library": ("github-hosted", "workflow", ".github/workflows/v07-library-qualification.yml"),
    "v08-agent": ("github-hosted", "workflow", ".github/workflows/v08-agent-qualification.yml"),
    "v09-qualification-contract": ("github-hosted", "workflow", ".github/workflows/v09-qualification.yml"),
    "v09-qualification": ("github-hosted", "workflow", ".github/workflows/v09-qualification.yml"),
    "v09-adversarial-security": ("github-hosted", "workflow", ".github/workflows/v09-adversarial-security.yml"),
    "v09-adversarial-security-shard": ("github-hosted", "workflow", ".github/workflows/v09-adversarial-security.yml"),
    "v010-workstation-contract": ("github-hosted", "workflow", ".github/workflows/v010-qualification.yml"),
    "v010-shell-runtime": ("github-hosted", "workflow", ".github/workflows/v010-shell-runtime-qualification.yml"),
    "trusted-release-proof": ("github-hosted", "workflow", ".github/workflows/trusted-release-proof.yml"),
    "v010-maintained-hardware": (
        "physical",
        "entrypoint",
        "qualification/v010/workstation-acceptance/run-hardware-qualification.sh",
    ),
}
RUNNER_ARCHITECTURES = {"X64": "x86_64", "ARM64": "aarch64"}
PACKAGE_MANAGERS = ("dpkg", "pacman", "rpm")
EXECUTION_SUBJECTS = frozenset({"runner", "guest", "aggregate"})
GUEST_EXECUTION_LANES = frozenset({
    "vm-acceptance",
    "control1-plan-preview-vm",
    "v04-durability",
    "v04-enospc",
    "v05-executor-verifier",
    "v06-managed-lifecycle",
    "v09-adversarial-security-shard",
    "v010-shell-runtime",
})
GUEST_CAPTURE_FIELDS = {
    "schema_version",
    "kind",
    "architecture",
    "kernel_release",
    "os_release_sha256",
    "distribution_id",
    "distribution_version",
    "package_manager",
    "package_manifest_sha256",
    "package_count",
    "virtualization",
}
RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SHARD_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
V09_ADVERSARIAL_SHARDS = (
    ("primary", 1, 2, True, False),
    ("persistence", 3, 3, False, False),
    ("security", 4, 4, False, False),
    ("connectivity", 5, 6, False, False),
    ("discovery-source", 7, 8, False, False),
    ("observation-plan", 9, 10, False, False),
    ("checkpoint", 11, 11, False, False),
    ("owner-final", 12, 13, False, True),
)
V09_ADVERSARIAL_SHARD_IDS = frozenset(row[0] for row in V09_ADVERSARIAL_SHARDS)
QUALIFICATION_ENVIRONMENT_IDS = frozenset({
    "qualification/ubuntu-24.04-lts/amd64/qemu-tcg-headless",
})
TRUSTED_COMMAND_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
TRUSTED_EXECUTABLES = {
    "git": (Path("/usr/bin/git"), Path("/bin/git")),
    "dpkg-query": (Path("/usr/bin/dpkg-query"),),
    "pacman": (Path("/usr/bin/pacman"),),
    "rpm": (Path("/usr/bin/rpm"),),
    "systemd-detect-virt": (Path("/usr/bin/systemd-detect-virt"), Path("/bin/systemd-detect-virt")),
    "NetworkManager": (Path("/usr/bin/NetworkManager"),),
    "bluetoothd": (Path("/usr/lib/bluetooth/bluetoothd"), Path("/usr/bin/bluetoothd")),
    "pipewire": (Path("/usr/bin/pipewire"),),
    "wireplumber": (Path("/usr/bin/wireplumber"),),
    "udisksctl": (Path("/usr/bin/udisksctl"),),
    "pkcheck": (Path("/usr/bin/pkcheck"),),
}
ALLOWED_UNTRACKED_ROOTS = frozenset({
    "target",
    "coverage",
    "dist",
    "artifacts",
    ".artifacts",
})
ALLOWED_UNTRACKED_COMPONENTS = frozenset({
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
})
REPOSITORY_REDIRECTING_GIT_ENVIRONMENT = frozenset({
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_SYSTEM",
    "GIT_DIR",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_QUARANTINE_PATH",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
})
REPOSITORY_REDIRECTING_GIT_ENVIRONMENT_PREFIXES = (
    "GIT_CONFIG_KEY_",
    "GIT_CONFIG_VALUE_",
)


class EnvelopeError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EnvelopeError(message)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _safe_file(root: Path, relative: str) -> Path:
    _require(isinstance(relative, str) and relative and not relative.startswith("/"),
             "repository input path must be non-empty and relative")
    parts = Path(relative).parts
    _require(".." not in parts, "repository input path may not traverse parents")
    path = root / relative
    _require(path.is_file() and not path.is_symlink(),
             f"missing or unsafe repository input: {relative}")
    resolved = path.resolve()
    _require(resolved.is_relative_to(root.resolve()),
             f"repository input escapes root: {relative}")
    return path


def _sha256_file(path: Path) -> str:
    _require(path.is_file() and not path.is_symlink(),
             f"missing or unsafe file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_resolved_identity_file(
    path: Path, *, allowed_targets: tuple[Path, ...]
) -> str:
    _require(path.is_absolute(), f"identity file path must be absolute: {path}")
    allowed = {
        Path(os.path.abspath(candidate))
        for candidate in allowed_targets
    }
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise EnvelopeError(f"cannot resolve identity file {path}: {exc}") from exc
    _require(
        resolved in allowed,
        f"identity file target is not allowed: {path} -> {resolved}",
    )
    _require(
        resolved.is_file() and not resolved.is_symlink(),
        f"identity file target is missing or unsafe: {resolved}",
    )
    return _sha256_file(resolved)


def _trusted_command_environment() -> dict[str, str]:
    return {
        "LC_ALL": "C",
        "LANG": "C",
        "PATH": TRUSTED_COMMAND_PATH,
    }


def _trusted_executable(name: str, *, required: bool = True) -> str | None:
    candidates = TRUSTED_EXECUTABLES.get(name)
    _require(candidates is not None, f"unknown trusted executable: {name}")
    rejected: list[str] = []
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            rejected.append(f"{candidate}: {exc}")
            continue
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            rejected.append(f"{candidate}: not an executable regular file")
            continue
        info = resolved.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            rejected.append(f"{candidate}: executable is not root-owned and non-writable")
            continue
        return str(resolved)
    if required:
        detail = "; ".join(rejected) or "no reviewed path exists"
        raise EnvelopeError(f"trusted executable is unavailable for {name}: {detail}")
    return None


def _untracked_path_allowed(path_bytes: bytes) -> bool:
    relative = Path(os.fsdecode(path_bytes))
    parts = relative.parts
    if not parts:
        return False
    return (
        parts[0] in ALLOWED_UNTRACKED_ROOTS
        or any(part in ALLOWED_UNTRACKED_COMPONENTS for part in parts)
    )


def _require_no_untracked_source_inputs(root: Path) -> None:
    paths: set[bytes] = set()
    for ignored in (False, True):
        arguments = ["ls-files", "--others", "--exclude-standard", "--directory", "-z"]
        if ignored:
            arguments.insert(2, "--ignored")
        for record in _git_bytes(root, *arguments).split(b"\0"):
            if record:
                paths.add(record)
    unsafe = sorted(
        os.fsdecode(path) for path in paths if not _untracked_path_allowed(path)
    )
    _require(
        not unsafe,
        "untracked or ignored source inputs are forbidden: " + ", ".join(unsafe),
    )


def _repository_git_context(root: Path) -> tuple[Path, Path, Path]:
    resolved_root = root.resolve()
    marker = resolved_root / ".git"
    _require(marker.exists() and not marker.is_symlink(),
             "repository .git metadata is missing or unsafe")

    if marker.is_dir():
        git_dir = marker.resolve()
    else:
        _require(marker.is_file(), "repository .git metadata is not a file or directory")
        try:
            metadata = marker.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError) as exc:
            raise EnvelopeError(f"cannot read repository .git metadata: {exc}") from exc
        prefix = "gitdir: "
        _require(
            metadata.startswith(prefix)
            and "\n" not in metadata
            and "\r" not in metadata
            and len(metadata) > len(prefix),
            "repository .git file is malformed",
        )
        git_dir_text = metadata[len(prefix):]
        git_dir_path = Path(git_dir_text)
        if not git_dir_path.is_absolute():
            git_dir_path = resolved_root / git_dir_path
        git_dir = git_dir_path.resolve()

    _require(git_dir.is_dir(), "repository Git directory is missing")
    index = git_dir / "index"
    _require(index.is_file() and not index.is_symlink(),
             "repository Git index is missing or unsafe")
    return resolved_root, git_dir, index


def _git_environment(root: Path, git_dir: Path, index: Path) -> dict[str, str]:
    redirected = sorted(
        name
        for name in os.environ
        if (
            name in REPOSITORY_REDIRECTING_GIT_ENVIRONMENT
            or any(
                name.startswith(prefix)
                for prefix in REPOSITORY_REDIRECTING_GIT_ENVIRONMENT_PREFIXES
            )
        )
    )
    _require(
        not redirected,
        "repository-redirecting Git environment variables are forbidden: "
        + ", ".join(redirected),
    )

    environment = _trusted_command_environment()
    environment.update({
        "GIT_DIR": str(git_dir),
        "GIT_WORK_TREE": str(root),
        "GIT_INDEX_FILE": str(index),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
    })
    return environment

def _run_git(root: Path, *args: str, text: bool = False) -> subprocess.CompletedProcess:
    resolved_root, git_dir, index = _repository_git_context(root)
    completed = subprocess.run(
        [
            _trusted_executable("git"),
            "--no-replace-objects",
            f"--git-dir={git_dir}",
            f"--work-tree={resolved_root}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.ignoreStat=false",
            *args,
        ],
        cwd=resolved_root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
        env=_git_environment(resolved_root, git_dir, index),
    )
    return completed


def _git(root: Path, *args: str) -> str:
    completed = _run_git(root, *args, text=True)
    if completed.returncode != 0:
        raise EnvelopeError(
            "git command failed: " + " ".join(args) + ": " + completed.stderr.strip()
        )
    return completed.stdout.strip()


def _string_list(value: object, field: str, *, allow_empty: bool = True) -> list[str]:
    _require(isinstance(value, list), f"{field} must be an array")
    result: list[str] = []
    for item in value:
        _require(isinstance(item, str) and item, f"{field} entries must be non-empty strings")
        result.append(item)
    _require(len(result) == len(set(result)), f"{field} contains duplicates")
    if not allow_empty:
        _require(bool(result), f"{field} may not be empty")
    return result


def _require_exact_keys(value: dict, expected: set[str], field: str) -> None:
    _require(set(value) == expected,
             f"{field} fields mismatch: expected {sorted(expected)}, got {sorted(value)}")


def _single_line(value: object, field: str) -> str:
    _require(isinstance(value, str) and value and "\n" not in value and "\r" not in value,
             f"{field} must be a single-line non-empty string")
    return value


def load_contract(root: Path = ROOT) -> dict:
    path = _safe_file(root, CONTRACT_PATH.as_posix())
    try:
        contract = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise EnvelopeError(f"cannot load execution-envelope contract: {exc}") from exc

    expected_top = {
        *CONTRACT_IDENTITIES,
        "implementation_files",
        "toolchain_files",
        "authority_boundary",
        "cache_policy",
        "runner",
        "guest_profile",
        "v09_adversarial_shard",
        "lane",
    }
    _require_exact_keys(contract, expected_top, "execution-envelope contract")
    for field, expected in CONTRACT_IDENTITIES.items():
        _require(contract.get(field) == expected,
                 f"unexpected execution-envelope {field}")

    implementation = _string_list(
        contract.get("implementation_files"), "implementation_files", allow_empty=False
    )
    toolchain = _string_list(
        contract.get("toolchain_files"), "toolchain_files", allow_empty=False
    )
    for relative in [*implementation, *toolchain]:
        _safe_file(root, relative)

    authority_boundary = contract.get("authority_boundary")
    _require(
        authority_boundary
        == {
            "role": "execution-context-only",
            "accepts_qualification_evidence": False,
            "writes_pass_receipts": False,
            "binds_verifier_results": False,
            "binds_accepted_artifacts": False,
        },
        "execution-envelope authority boundary changed without schema review",
    )
    forbidden_core_tokens = (
        "qualification" + "_evidence.py",
        "from tools import qualification" + "_evidence",
        "import tools.qualification" + "_evidence",
        "evidence-" + "binding.json",
        "verifier-" + "result.json",
        "binding_" + "sha256",
    )
    for relative in implementation:
        source = _safe_file(root, relative).read_text(encoding="utf-8")
        for token in forbidden_core_tokens:
            _require(
                token not in source,
                f"execution-context implementation crosses evidence-acceptance boundary: {relative}:{token}",
            )

    cache_policy = contract.get("cache_policy")
    _require(isinstance(cache_policy, dict), "cache_policy must be a table")
    expected_cache_policy = {
        "cache_hit_is_qualification": False,
        "content_digest_required": True,
        "independent_verification_required": True,
        "source_pass_reuse_allowed": False,
        "qualification_evidence_cache_allowed": False,
        "build_output_cache_allowed": False,
    }
    _require(cache_policy == expected_cache_policy,
             "cache policy changed without schema review")

    runners = contract.get("runner")
    _require(isinstance(runners, dict), "runner profiles are missing")
    _require_exact_keys(runners, {"github_hosted", "physical"}, "runner")
    hosted = runners["github_hosted"]
    physical = runners["physical"]
    _require(isinstance(hosted, dict) and isinstance(physical, dict),
             "runner profiles must be tables")
    _require_exact_keys(
        hosted,
        {
            "required_environment",
            "package_manager",
            "require_kernel_release",
            "require_os_release_digest",
            "require_package_manifest",
        },
        "runner.github_hosted",
    )
    _require_exact_keys(
        physical,
        {
            "required_environment",
            "package_manager",
            "require_kernel_release",
            "require_os_release_digest",
            "require_package_manifest",
            "require_no_virtualization",
        },
        "runner.physical",
    )
    for name, profile in (("github_hosted", hosted), ("physical", physical)):
        _string_list(profile["required_environment"],
                     f"runner.{name}.required_environment")
        _require(
            profile["package_manager"] in PACKAGE_MANAGERS,
            f"runner.{name} package manager is unsupported",
        )
        _require(profile["require_kernel_release"] is True,
                 f"runner.{name} must bind kernel release")
        _require(profile["require_os_release_digest"] is True,
                 f"runner.{name} must bind /etc/os-release")
        _require(profile["require_package_manifest"] is True,
                 f"runner.{name} must bind an installed-package manifest")
    _require(physical["require_no_virtualization"] is True,
             "physical runner must reject virtualization")
    _require(hosted["package_manager"] == "dpkg",
             "GitHub-hosted runner package identity must use dpkg")
    _require(physical["package_manager"] == "pacman",
             "maintained Arch runner package identity must use pacman")

    guest_profiles = contract.get("guest_profile")
    expected_guest_profiles = {
        "ubuntu_24_04_qemu": {
            "architecture": "x86_64",
            "virtualization": "qemu",
            "acceleration": "tcg",
            "distribution_id": "ubuntu",
            "distribution_version": "24.04",
            "package_manager": "dpkg",
        },
        "arch_rolling_qemu": {
            "architecture": "x86_64",
            "virtualization": "qemu",
            "acceleration": "tcg",
            "distribution_id": "arch",
            "distribution_version": "rolling",
            "package_manager": "pacman",
        },
    }
    _require(
        guest_profiles == expected_guest_profiles,
        "guest execution profiles changed without schema review",
    )

    expected_v09_shards = [
        {
            "id": shard_id,
            "boundary_start": boundary_start,
            "boundary_end": boundary_end,
            "primary": primary,
            "final": final,
        }
        for shard_id, boundary_start, boundary_end, primary, final
        in V09_ADVERSARIAL_SHARDS
    ]
    _require(
        contract.get("v09_adversarial_shard") == expected_v09_shards,
        "v0.9 adversarial shard inventory changed without schema review",
    )

    lanes = contract.get("lane")
    _require(isinstance(lanes, list) and lanes, "lane inventory must be non-empty")
    seen: set[str] = set()
    targets: dict[str, str] = {}
    shared_target_pairs = frozenset({
        frozenset({"v09-qualification", "v09-qualification-contract"}),
        frozenset({"v09-adversarial-security", "v09-adversarial-security-shard"}),
    })
    for lane in lanes:
        _require(isinstance(lane, dict), "lane entry must be a table")
        required_lane_fields = {
            "id",
            "kind",
            "profile_version",
            "input_files",
            "required_digests",
            "required_cache_digests",
            "required_observations",
            "execution_subject",
        }
        allowed_lane_fields = {
            *required_lane_fields,
            "workflow",
            "entrypoint",
            "freshness_is_nondeterministic",
            "guest_profile",
        }
        _require(required_lane_fields.issubset(lane) and
                 set(lane).issubset(allowed_lane_fields),
                 "lane fields changed without schema review")

        lane_id = lane.get("id")
        _require(isinstance(lane_id, str) and NAME.fullmatch(lane_id) is not None,
                 f"invalid lane id: {lane_id!r}")
        _require(lane_id not in seen, f"duplicate lane id: {lane_id}")
        seen.add(lane_id)
        binding = REQUIRED_LANE_BINDINGS.get(lane_id)
        _require(binding is not None, f"unreviewed qualification lane: {lane_id}")
        expected_kind, target_field, target = binding
        _require(lane.get("kind") == expected_kind,
                 f"runner kind drift for {lane_id}")
        _require(lane.get(target_field) == target,
                 f"execution target drift for {lane_id}")
        other_field = "entrypoint" if target_field == "workflow" else "workflow"
        _require(lane.get(other_field) is None,
                 f"{lane_id} may not mix workflow and physical entrypoint")
        _safe_file(root, target)
        existing_lane = targets.get(target)
        if existing_lane is None:
            targets[target] = lane_id
        else:
            _require(
                frozenset({existing_lane, lane_id}) in shared_target_pairs,
                f"duplicate qualification execution target: {target}",
            )
        _require(isinstance(lane.get("profile_version"), int) and
                 not isinstance(lane["profile_version"], bool) and
                 lane["profile_version"] >= 1,
                 f"invalid profile_version for {lane_id}")
        execution_subject = lane.get("execution_subject")
        _require(
            execution_subject in EXECUTION_SUBJECTS,
            f"invalid execution subject for {lane_id}: {execution_subject!r}",
        )
        if execution_subject == "guest":
            _require(
                lane.get("guest_profile") in guest_profiles,
                f"guest lane lacks a reviewed guest profile: {lane_id}",
            )
        else:
            _require(
                lane.get("guest_profile") is None,
                f"non-guest lane may not declare a guest profile: {lane_id}",
            )
        input_files = _string_list(
            lane.get("input_files"), f"{lane_id}.input_files", allow_empty=False
        )
        for relative in input_files:
            _safe_file(root, relative)

        dynamic = _string_list(
            lane.get("required_digests"), f"{lane_id}.required_digests"
        )
        caches = _string_list(
            lane.get("required_cache_digests"),
            f"{lane_id}.required_cache_digests",
        )
        observations = _string_list(
            lane.get("required_observations"),
            f"{lane_id}.required_observations",
        )
        for field, items in (
            ("required_digests", dynamic),
            ("required_cache_digests", caches),
            ("required_observations", observations),
        ):
            for name in items:
                _require(NAME.fullmatch(name) is not None,
                         f"invalid {field} name for {lane_id}: {name!r}")
        _require(
            len(set(dynamic) | set(caches) | set(observations))
            == len(dynamic) + len(caches) + len(observations),
            f"dynamic/cache/observation names overlap for {lane_id}",
        )
        if execution_subject == "guest":
            _require(
                "base_image_sha256" in dynamic,
                f"guest lane must bind its base image: {lane_id}",
            )
        if execution_subject == "aggregate":
            _require(
                "component_envelope_set_sha256" in observations,
                f"aggregate lane must bind component envelopes: {lane_id}",
            )
        else:
            _require(
                "component_envelope_set_sha256" not in observations,
                f"non-aggregate lane may not bind component envelope sets: {lane_id}",
            )

        freshness = lane.get("freshness_is_nondeterministic", False)
        _require(isinstance(freshness, bool),
                 f"invalid freshness flag for {lane_id}")
        if lane_id == "security-rustsec":
            _require(freshness is True,
                     "RustSec freshness must stay nondeterministic")
            _require(
                set(observations)
                == {"advisory_db_identity", "advisory_retrieved_at"},
                "RustSec must record advisory identity and retrieval time",
            )
        else:
            _require(freshness is False,
                     f"only RustSec may declare nondeterministic freshness: {lane_id}")

    _require(seen == set(REQUIRED_LANE_BINDINGS),
             "qualification lane inventory does not match reviewed bindings")
    return contract


def lane_by_id(contract: dict, lane_id: str) -> dict:
    for lane in contract["lane"]:
        if lane["id"] == lane_id:
            return lane
    raise EnvelopeError(f"unknown qualification lane: {lane_id}")


def _parse_named(values: list[str], option: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in values:
        name, separator, value = raw.partition("=")
        _require(separator == "=" and NAME.fullmatch(name) is not None and value,
                 f"invalid {option}: {raw!r}")
        _require(name not in result, f"duplicate {option} name: {name}")
        result[name] = value
    return result


def _parse_digests(values: list[str], option: str) -> dict[str, str]:
    result = _parse_named(values, option)
    for name, digest in result.items():
        _require(HEX64.fullmatch(digest) is not None,
                 f"{option} {name} must be a lowercase sha256 digest")
    return dict(sorted(result.items()))


def _verified_caches(values: list[str]) -> dict[str, dict]:
    parsed = _parse_named(values, "verified cache")
    result: dict[str, dict] = {}
    for name, specification in parsed.items():
        path_text, separator, expected = specification.rpartition("@")
        _require(separator == "@" and path_text and HEX64.fullmatch(expected) is not None,
                 f"verified cache {name} must use NAME=PATH@SHA256")
        path = Path(path_text)
        _require(path.is_file() and not path.is_symlink(),
                 f"verified cache {name} is missing or unsafe")
        actual = _sha256_file(path)
        _require(actual == expected, f"verified cache {name} digest mismatch")
        result[name] = {
            "sha256": actual,
            "size": path.stat().st_size,
            "qualification_authority": False,
            "verification": "local-byte-sha256-match",
        }
    return dict(sorted(result.items()))


def _git_bytes(root: Path, *args: str) -> bytes:
    completed = _run_git(root, *args)
    if completed.returncode != 0:
        raise EnvelopeError(
            "git command failed: "
            + " ".join(args)
            + ": "
            + completed.stderr.decode("utf-8", errors="replace").strip()
        )
    return completed.stdout


def _git_blob_bytes(root: Path, source_sha: str, relative: str) -> bytes:
    return _git_bytes(root, "show", f"{source_sha}:{relative}")


def _require_no_suppressed_worktree_checks(root: Path) -> None:
    hidden: list[str] = []
    for record in _git_bytes(root, "ls-files", "-v", "-z").split(b"\0"):
        if not record:
            continue
        _require(
            len(record) >= 3 and record[1:2] == b" ",
            "unexpected git ls-files status record",
        )
        tag = chr(record[0])
        if tag.islower() or tag == "S":
            relative = record[2:].decode("utf-8", errors="replace")
            hidden.append(f"{tag}:{relative}")
    _require(
        not hidden,
        "tracked checkout uses git index flags that suppress worktree checks: "
        + ", ".join(hidden),
    )


def _parse_source_tree(root: Path, source_sha: str) -> dict[bytes, tuple[str, str, str]]:
    entries: dict[bytes, tuple[str, str, str]] = {}
    for record in _git_bytes(root, "ls-tree", "-r", "-z", source_sha).split(b"\0"):
        if not record:
            continue
        metadata, separator, path = record.partition(b"\t")
        _require(separator == b"\t" and path, "unexpected git tree record")
        fields = metadata.decode("ascii").split()
        _require(len(fields) == 3, "unexpected git tree metadata")
        mode, object_type, object_id = fields
        _require(object_id and path not in entries, "duplicate git tree path")
        entries[path] = (mode, object_type, object_id)
    return entries


def _parse_index(root: Path) -> dict[bytes, tuple[str, str]]:
    entries: dict[bytes, tuple[str, str]] = {}
    for record in _git_bytes(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        metadata, separator, path = record.partition(b"\t")
        _require(separator == b"\t" and path, "unexpected git index record")
        fields = metadata.decode("ascii").split()
        _require(len(fields) == 3, "unexpected git index metadata")
        mode, object_id, stage = fields
        _require(stage == "0", "tracked checkout contains unresolved index stages")
        _require(path not in entries, "duplicate git index path")
        entries[path] = (mode, object_id)
    return entries


def _git_blob_object_id(data: bytes) -> str:
    payload = b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    return hashlib.sha1(payload, usedforsecurity=False).hexdigest()


def _raw_worktree_blob(root: Path, path_bytes: bytes, mode: str) -> bytes:
    relative = os.fsdecode(path_bytes)
    path = root / relative
    if mode == "120000":
        _require(path.is_symlink(), f"tracked symlink changed type: {relative}")
        return os.fsencode(os.readlink(path))
    _require(
        mode in {"100644", "100755"},
        f"unsupported tracked blob mode in execution envelope: {mode} {relative}",
    )
    _require(path.is_file() and not path.is_symlink(),
             f"tracked worktree file is missing or changed type: {relative}")
    expected_executable = mode == "100755"
    actual_executable = bool(path.stat().st_mode & 0o100)
    _require(
        actual_executable == expected_executable,
        f"tracked worktree executable bit differs from declared source commit: {relative}",
    )
    return path.read_bytes()


def _require_clean_tracked_checkout(root: Path, source_sha: str) -> None:
    _require_no_suppressed_worktree_checks(root)
    _require_no_untracked_source_inputs(root)
    source = _parse_source_tree(root, source_sha)
    index = _parse_index(root)
    source_index = {
        path: (mode, object_id)
        for path, (mode, object_type, object_id) in source.items()
        if object_type in {"blob", "commit"}
    }
    _require(index == source_index, "tracked index differs from declared source commit")
    for path_bytes, (mode, object_type, object_id) in source.items():
        relative = os.fsdecode(path_bytes)
        if object_type == "commit":
            submodule = root / relative
            _require(submodule.is_dir(), f"tracked submodule is missing: {relative}")
            completed = subprocess.run(
                [_trusted_executable("git"), "-C", str(submodule), "rev-parse", "HEAD"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=_trusted_command_environment(),
            )
            _require(
                completed.returncode == 0 and completed.stdout.strip() == object_id,
                f"tracked submodule differs from declared source commit: {relative}",
            )
            continue
        _require(object_type == "blob",
                 f"unsupported tracked tree object: {object_type} {relative}")
        raw = _raw_worktree_blob(root, path_bytes, mode)
        _require(
            _git_blob_object_id(raw) == object_id,
            f"tracked worktree raw bytes differ from declared source commit: {relative}",
        )


def _repository_digests(
    root: Path, contract: dict, lane: dict, source_sha: str
) -> dict[str, str]:
    execution_target = REQUIRED_LANE_BINDINGS[lane["id"]][2]
    paths = [
        CONTRACT_PATH.as_posix(),
        *contract["implementation_files"],
        *contract["toolchain_files"],
        execution_target,
        *lane["input_files"],
    ]
    result: dict[str, str] = {}
    for relative in sorted(set(paths)):
        disk_digest = _sha256_file(_safe_file(root, relative))
        source_digest = _sha256_bytes(_git_blob_bytes(root, source_sha, relative))
        _require(
            disk_digest == source_digest,
            f"working-tree input differs from declared source commit: {relative}",
        )
        result[relative] = disk_digest
    return result


def _host_package_identity(manager: str) -> dict:
    commands = {
        "dpkg": ("dpkg-query", ["-W", "-f=${binary:Package}\\t${Version}\\n"]),
        "pacman": ("pacman", ["-Q"]),
        "rpm": ("rpm", ["-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}.%{ARCH}\\n"]),
    }
    _require(manager in commands, f"unsupported runner package manager: {manager}")
    executable_name, arguments = commands[manager]
    executable = _trusted_executable(executable_name)
    completed = subprocess.run(
        [executable, *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_trusted_command_environment(),
    )
    _require(
        completed.returncode == 0,
        f"cannot capture {manager} package manifest: {completed.stderr.strip()}",
    )
    lines = sorted(line for line in completed.stdout.splitlines() if line)
    _require(bool(lines), f"{manager} package manifest is empty")
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    return {
        "package_manager": manager,
        "package_manifest_sha256": _sha256_bytes(payload),
        "package_count": len(lines),
    }


def _detect_virtualization() -> str:
    executable = _trusted_executable("systemd-detect-virt")
    completed = subprocess.run(
        [executable],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_trusted_command_environment(),
    )
    if completed.returncode == 1:
        return "none"
    _require(
        completed.returncode == 0,
        "cannot determine runner virtualization: " + completed.stderr.strip(),
    )
    return _single_line(completed.stdout.strip(), "runner virtualization")


def _runner_identity(contract: dict, lane: dict, environment: dict[str, str]) -> dict:
    _require(platform.system() == "Linux",
             "qualification execution envelopes currently require Linux")
    kind = lane["kind"]
    profile_name = "github_hosted" if kind == "github-hosted" else "physical"
    profile = contract["runner"][profile_name]
    required = profile["required_environment"]
    missing = [key for key in required if not environment.get(key)]
    _require(not missing, "missing runner identity fields: " + ", ".join(missing))

    machine_arch = _single_line(platform.machine().lower(), "machine architecture")
    runner_arch = environment.get("RUNNER_ARCH")
    if runner_arch:
        runner_arch = _single_line(runner_arch, "RUNNER_ARCH")
        expected_machine = RUNNER_ARCHITECTURES.get(runner_arch)
        _require(expected_machine == machine_arch,
                 "runner architecture does not match executing machine")
    else:
        runner_arch = next(
            (name for name, machine in RUNNER_ARCHITECTURES.items()
             if machine == machine_arch),
            machine_arch,
        )

    runner_os = _single_line(
        environment.get("RUNNER_OS") or platform.system(), "runner OS"
    )
    _require(runner_os == "Linux", "runner OS must be Linux")
    os_release_sha256 = _sha256_resolved_identity_file(
        OS_RELEASE_PATH,
        allowed_targets=OS_RELEASE_ALLOWED_TARGETS,
    )
    package_identity = _host_package_identity(profile["package_manager"])
    identity = {
        "kind": kind,
        "architecture": machine_arch,
        "runner_architecture": runner_arch,
        "runner_os": runner_os,
        "kernel_release": _single_line(platform.release(), "kernel release"),
        "os_release_sha256": os_release_sha256,
        **package_identity,
        "virtualization": _detect_virtualization(),
    }

    if kind == "github-hosted":
        identity["image_os"] = _single_line(environment["ImageOS"], "ImageOS")
        identity["image_version"] = _single_line(
            environment["ImageVersion"], "ImageVersion"
        )
    else:
        _require(
            not environment.get("ImageOS") and not environment.get("ImageVersion"),
            "physical lane cannot use a GitHub-hosted runner image identity",
        )
        _require(identity["virtualization"] == "none",
                 "physical lane must execute on non-virtualized maintained hardware")
    return identity


def _validate_runner_binding(contract: dict, lane: dict, runner: object) -> dict:
    _require(isinstance(runner, dict), "execution envelope runner is missing")
    base_fields = {
        "kind",
        "architecture",
        "runner_architecture",
        "runner_os",
        "kernel_release",
        "os_release_sha256",
        "package_manager",
        "package_manifest_sha256",
        "package_count",
        "virtualization",
    }
    expected_fields = (
        base_fields | {"image_os", "image_version"}
        if lane["kind"] == "github-hosted"
        else base_fields
    )
    _require_exact_keys(runner, expected_fields, "execution envelope runner")
    _require(runner["kind"] == lane["kind"], "execution envelope runner kind mismatch")
    _require(_single_line(runner["runner_os"], "runner_os") == "Linux",
             "execution envelope runner OS mismatch")
    architecture = _single_line(runner["architecture"], "architecture")
    runner_arch = _single_line(runner["runner_architecture"], "runner_architecture")
    if lane["kind"] == "github-hosted":
        _require(
            runner_arch in RUNNER_ARCHITECTURES,
            "execution envelope hosted runner architecture is unsupported",
        )
        _require(
            RUNNER_ARCHITECTURES[runner_arch] == architecture,
            "execution envelope runner architecture mismatch",
        )
    elif runner_arch in RUNNER_ARCHITECTURES:
        _require(
            RUNNER_ARCHITECTURES[runner_arch] == architecture,
            "execution envelope runner architecture mismatch",
        )
    else:
        _require(
            runner_arch == architecture,
            "execution envelope physical runner architecture mismatch",
        )
    _single_line(runner["kernel_release"], "kernel_release")
    _require(isinstance(runner["os_release_sha256"], str) and
             HEX64.fullmatch(runner["os_release_sha256"]) is not None,
             "execution envelope os-release digest is invalid")
    _require(runner["package_manager"] in PACKAGE_MANAGERS,
             "execution envelope package manager is unsupported")
    runner_profile_name = (
        "github_hosted" if lane["kind"] == "github-hosted" else "physical"
    )
    expected_package_manager = contract["runner"][runner_profile_name]["package_manager"]
    _require(
        runner["package_manager"] == expected_package_manager,
        "execution envelope package manager does not match runner profile",
    )
    _require(isinstance(runner["package_manifest_sha256"], str) and
             HEX64.fullmatch(runner["package_manifest_sha256"]) is not None,
             "execution envelope package manifest digest is invalid")
    _require(isinstance(runner["package_count"], int) and
             not isinstance(runner["package_count"], bool) and
             runner["package_count"] > 0,
             "execution envelope package count is invalid")
    virtualization = _single_line(runner["virtualization"], "virtualization")
    if lane["kind"] == "github-hosted":
        _single_line(runner["image_os"], "image_os")
        _single_line(runner["image_version"], "image_version")
    else:
        _require(virtualization == "none",
                 "physical execution envelope may not claim virtualization")
    return runner


def _validate_observations(
    observations: object, expected_names: set[str], lane_id: str
) -> dict[str, str]:
    _require(
        isinstance(observations, dict) and set(observations) == expected_names,
        "execution envelope observation set mismatch",
    )
    for name, value in observations.items():
        value = _single_line(value, f"observation {name}")
        if name.endswith("_sha256"):
            _require(
                HEX64.fullmatch(value) is not None,
                f"observation {name} must be a lowercase sha256 digest",
            )
        if name == "advisory_db_identity":
            _require(
                HEX40.fullmatch(value) is not None,
                "RustSec advisory identity must be a lowercase full-length Git SHA",
            )
        elif name == "advisory_retrieved_at":
            _require(
                RFC3339_UTC.fullmatch(value) is not None,
                "RustSec advisory retrieval time must be UTC RFC3339 seconds",
            )
            try:
                datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError as exc:
                raise EnvelopeError("RustSec advisory retrieval time is invalid") from exc
        elif name == "qualification_environment_id":
            _require(
                value in QUALIFICATION_ENVIRONMENT_IDS,
                "qualification environment id is not reviewed",
            )
        elif name == "shard_id":
            _require(
                SHARD_ID.fullmatch(value) is not None,
                "adversarial shard id is invalid",
            )
            _require(
                value in V09_ADVERSARIAL_SHARD_IDS,
                "adversarial shard id is not reviewed",
            )
    if lane_id == "security-rustsec":
        _require(
            set(observations) == {"advisory_db_identity", "advisory_retrieved_at"},
            "RustSec observation contract drifted",
        )
    return observations


def _load_execution_subject_file(path: Path | None) -> dict | None:
    if path is None:
        return None
    _require(path.is_file() and not path.is_symlink(),
             "execution-subject file is missing or unsafe")
    _require(path.stat().st_size <= 64 * 1024,
             "execution-subject file exceeds size bound")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError(f"invalid execution-subject file: {exc}") from exc
    _require(isinstance(payload, dict), "execution-subject file must contain an object")
    return payload


def _runner_subject(runner: dict) -> dict:
    return {
        "kind": "runner",
        "runner_identity_sha256": _sha256_bytes(_canonical_json(runner)),
    }


def _validate_execution_subject(
    contract: dict,
    lane: dict,
    runner: dict,
    subject: object,
    digests: dict[str, str],
    observations: dict[str, str],
) -> dict:
    mode = lane["execution_subject"]
    _require(isinstance(subject, dict), "execution subject is missing")
    if mode == "runner":
        expected = _runner_subject(runner)
        _require(subject == expected, "runner execution subject binding mismatch")
        return subject
    if mode == "aggregate":
        _require_exact_keys(
            subject,
            {"kind", "component_envelope_set_sha256"},
            "aggregate execution subject",
        )
        _require(subject["kind"] == "aggregate", "aggregate execution subject kind mismatch")
        expected = observations["component_envelope_set_sha256"]
        _require(
            subject["component_envelope_set_sha256"] == expected
            and HEX64.fullmatch(expected) is not None,
            "aggregate component-envelope binding mismatch",
        )
        return subject

    _require(mode == "guest", f"unsupported execution subject mode: {mode}")
    expected_fields = GUEST_CAPTURE_FIELDS | {"acceleration", "image_digests"}
    _require_exact_keys(subject, expected_fields, "guest execution subject")
    _require(subject["schema_version"] == 1, "guest execution subject schema mismatch")
    _require(subject["kind"] == "virtual-machine", "guest execution subject kind mismatch")
    profile = contract["guest_profile"][lane["guest_profile"]]
    for name in (
        "architecture",
        "virtualization",
        "distribution_id",
        "distribution_version",
        "package_manager",
    ):
        _require(
            subject[name] == profile[name],
            f"guest execution subject {name} does not match reviewed profile",
        )
    _single_line(subject["kernel_release"], "guest kernel release")
    _require(
        isinstance(subject["os_release_sha256"], str)
        and HEX64.fullmatch(subject["os_release_sha256"]) is not None,
        "guest os-release digest is invalid",
    )
    _require(
        isinstance(subject["package_manifest_sha256"], str)
        and HEX64.fullmatch(subject["package_manifest_sha256"]) is not None,
        "guest package manifest digest is invalid",
    )
    _require(
        isinstance(subject["package_count"], int)
        and not isinstance(subject["package_count"], bool)
        and subject["package_count"] > 0,
        "guest package count is invalid",
    )
    _require(
        subject["acceleration"] == profile["acceleration"],
        "guest execution acceleration does not match reviewed profile",
    )
    expected_images = {
        name: value
        for name, value in digests.items()
        if name.endswith("_image_sha256")
    }
    _require(
        bool(expected_images) and subject["image_digests"] == dict(sorted(expected_images.items())),
        "guest execution image chain does not match lane bindings",
    )
    for name in ("guest_package_manifest_sha256", "runtime_package_manifest_sha256"):
        if name in digests:
            _require(
                digests[name] == subject["package_manifest_sha256"],
                f"{name} does not match guest execution subject",
            )
        if name in observations:
            _require(
                observations[name] == subject["package_manifest_sha256"],
                f"{name} does not match guest execution subject",
            )
    return subject


def _execution_subject_binding(
    contract: dict,
    lane: dict,
    runner: dict,
    captured: dict | None,
    digests: dict[str, str],
    observations: dict[str, str],
    environment: dict[str, str],
) -> dict:
    mode = lane["execution_subject"]
    if mode == "runner":
        _require(captured is None, "runner lane may not supply a guest execution subject")
        return _runner_subject(runner)
    if mode == "aggregate":
        _require(captured is None, "aggregate lane may not supply a guest execution subject")
        return {
            "kind": "aggregate",
            "component_envelope_set_sha256": observations["component_envelope_set_sha256"],
        }
    _require(captured is not None, "guest lane requires a captured execution subject")
    _require_exact_keys(captured, GUEST_CAPTURE_FIELDS, "captured guest execution subject")
    acceleration = _single_line(
        environment.get("VM_ACCELERATION"), "VM_ACCELERATION"
    )
    subject = dict(captured)
    subject["acceleration"] = acceleration
    subject["image_digests"] = dict(sorted(
        (name, value) for name, value in digests.items() if name.endswith("_image_sha256")
    ))
    return _validate_execution_subject(contract, lane, runner, subject, digests, observations)


def _validate_cache_bindings(caches: object, expected_names: set[str]) -> dict:
    _require(isinstance(caches, dict) and set(caches) == expected_names,
             "execution envelope verified-cache set mismatch")
    for name, entry in caches.items():
        _require(isinstance(entry, dict), f"invalid verified-cache binding: {name}")
        _require_exact_keys(
            entry,
            {"sha256", "size", "qualification_authority", "verification"},
            f"verified-cache {name}",
        )
        _require(
            isinstance(entry["sha256"], str)
            and HEX64.fullmatch(entry["sha256"]) is not None
            and isinstance(entry["size"], int)
            and not isinstance(entry["size"], bool)
            and entry["size"] >= 0
            and entry["qualification_authority"] is False
            and entry["verification"] == "local-byte-sha256-match",
            f"invalid verified-cache binding: {name}",
        )
    return caches

def _action_mapping_entry_block(
    source: str, mapping_name: str, entry_name: str
) -> str | None:
    """Return one direct entry from a top-level action mapping."""
    lines = source.splitlines()
    mapping_indexes = [
        index for index, line in enumerate(lines) if line == f"{mapping_name}:"
    ]
    if len(mapping_indexes) != 1:
        return None
    start = mapping_indexes[0]
    end = start + 1
    while end < len(lines):
        candidate = lines[end]
        if candidate.strip() and not candidate.lstrip().startswith("#"):
            if len(candidate) - len(candidate.lstrip()) == 0:
                break
        end += 1
    child_indents = [
        len(line) - len(line.lstrip())
        for line in lines[start + 1:end]
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not child_indents:
        return None
    entry_indent = min(child_indents)
    indexes = [
        index
        for index in range(start + 1, end)
        if (
            len(lines[index]) - len(lines[index].lstrip()) == entry_indent
            and _normalized_step_line(lines[index]) == f"{entry_name}:"
        )
    ]
    if len(indexes) != 1:
        return None
    entry_start = indexes[0]
    entry_end = entry_start + 1
    while entry_end < end:
        candidate = lines[entry_end]
        if candidate.strip() and not candidate.lstrip().startswith("#"):
            if len(candidate) - len(candidate.lstrip()) <= entry_indent:
                break
        entry_end += 1
    return "\n".join(lines[entry_start:entry_end])


def _block_mapping_value(block: str, mapping_name: str, key: str) -> str | None:
    """Return one immediate key from a direct nested mapping in a step."""
    lines = block.splitlines()
    if not lines:
        return None
    root_indent = len(lines[0]) - len(lines[0].lstrip())
    child_indents = [
        len(line) - len(line.lstrip())
        for line in lines[1:]
        if line.strip()
        and not line.lstrip().startswith("#")
        and len(line) - len(line.lstrip()) > root_indent
    ]
    if not child_indents:
        return None
    direct_indent = min(child_indents)
    mapping_indexes = [
        index
        for index, line in enumerate(lines[1:], start=1)
        if (
            line.strip()
            and not line.lstrip().startswith("#")
            and len(line) - len(line.lstrip()) == direct_indent
            and _normalized_step_line(line) == f"{mapping_name}:"
        )
    ]
    if len(mapping_indexes) != 1:
        return None
    mapping_index = mapping_indexes[0]
    nested = [
        len(line) - len(line.lstrip())
        for line in lines[mapping_index + 1:]
        if line.strip()
        and not line.lstrip().startswith("#")
        and len(line) - len(line.lstrip()) > direct_indent
    ]
    if not nested:
        return None
    value_indent = min(nested)
    prefix = f"{key}:"
    matches: list[str] = []
    for line in lines[mapping_index + 1:]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= direct_indent:
            break
        if indent != value_indent:
            continue
        normalized = _normalized_step_line(line)
        if normalized == key + ":":
            matches.append("")
        elif normalized.startswith(prefix):
            matches.append(normalized[len(prefix):].strip())
    return matches[0] if len(matches) == 1 else None


def _block_literal_scalar(block: str, key: str) -> str | None:
    """Return a direct literal block scalar body, excluding sibling fields."""
    lines = block.splitlines()
    if not lines:
        return None
    root_indent = len(lines[0]) - len(lines[0].lstrip())
    child_indents = [
        len(line) - len(line.lstrip())
        for line in lines[1:]
        if line.strip()
        and not line.lstrip().startswith("#")
        and len(line) - len(line.lstrip()) > root_indent
    ]
    if not child_indents:
        return None
    direct_indent = min(child_indents)
    markers = [
        index
        for index, line in enumerate(lines[1:], start=1)
        if (
            line.strip()
            and not line.lstrip().startswith("#")
            and len(line) - len(line.lstrip()) == direct_indent
            and _normalized_step_line(line) == f"{key}: |"
        )
    ]
    if len(markers) != 1:
        return None
    marker = markers[0]
    scalar_lines: list[str] = []
    scalar_indent: int | None = None
    for line in lines[marker + 1:]:
        if line.strip():
            indent = len(line) - len(line.lstrip())
            if indent <= direct_indent:
                break
            if scalar_indent is None:
                scalar_indent = indent
            if indent < scalar_indent:
                return None
        if scalar_indent is None:
            continue
        scalar_lines.append(
            line[scalar_indent:] if len(line) >= scalar_indent else ""
        )
    return "\n".join(scalar_lines) if scalar_indent is not None else None


def composite_action_step_blocks(source: str) -> list[tuple[int, str]]:
    """Return concrete runs.steps items from a composite action."""
    lines = source.splitlines()
    runs_indexes = [index for index, line in enumerate(lines) if line == "runs:"]
    if len(runs_indexes) != 1:
        return []
    runs_start = runs_indexes[0]
    runs_end = runs_start + 1
    while runs_end < len(lines):
        candidate = lines[runs_end]
        if candidate.strip() and not candidate.lstrip().startswith("#"):
            if len(candidate) - len(candidate.lstrip()) == 0:
                break
        runs_end += 1
    runs_block = "\n".join(lines[runs_start:runs_end])
    if _block_direct_value(runs_block, "using") != "composite":
        return []

    child_indents = [
        len(line) - len(line.lstrip())
        for line in lines[runs_start + 1:runs_end]
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not child_indents:
        return []
    direct_indent = min(child_indents)
    steps_indexes = [
        index
        for index in range(runs_start + 1, runs_end)
        if (
            len(lines[index]) - len(lines[index].lstrip()) == direct_indent
            and re.fullmatch(r"\s*steps:\s*(?:#.*)?", lines[index]) is not None
        )
    ]
    if len(steps_indexes) != 1:
        return []
    steps_start = steps_indexes[0]
    step_indent: int | None = None
    blocks: list[tuple[int, str]] = []
    index = steps_start + 1
    while index < runs_end:
        candidate = lines[index]
        if not candidate.strip() or candidate.lstrip().startswith("#"):
            index += 1
            continue
        indent = len(candidate) - len(candidate.lstrip())
        if indent <= direct_indent:
            break
        is_list_item = re.match(r"^\s*-\s+\S", candidate) is not None
        if step_indent is None:
            if not is_list_item:
                index += 1
                continue
            step_indent = indent
        if indent != step_indent or not is_list_item:
            index += 1
            continue
        end = index + 1
        while end < runs_end:
            following = lines[end]
            if following.strip() and not following.lstrip().startswith("#"):
                following_indent = len(following) - len(following.lstrip())
                if following_indent <= direct_indent:
                    break
                if (
                    following_indent == step_indent
                    and re.match(r"^\s*-\s+\S", following) is not None
                ):
                    break
            end += 1
        blocks.append((index + 1, "\n".join(lines[index:end])))
        index = end
    return blocks


def _hosted_action_has_integration(source: str) -> bool:
    """Verify the executable composite-action authority path structurally."""
    subject_input = _action_mapping_entry_block(
        source, "inputs", "execution-subject-file"
    )
    digest_output = _action_mapping_entry_block(source, "outputs", "sha256")
    if (
        subject_input is None
        or _block_direct_value(subject_input, "required") != "false"
        or _block_direct_value(subject_input, "default") not in {'""', "''"}
        or digest_output is None
        or _block_direct_value(digest_output, "value")
        != "${{ steps.envelope.outputs.sha256 }}"
    ):
        return False

    steps = composite_action_step_blocks(source)
    envelope_steps = [
        block for _, block in steps if _block_direct_value(block, "id") == "envelope"
    ]
    if len(envelope_steps) != 1:
        return False
    envelope_step = envelope_steps[0]
    if (
        _block_direct_value(envelope_step, "shell") != "bash"
        or workflow_step_direct_value(envelope_step, "if") is not None
        or workflow_block_is_error_tolerant(envelope_step)
        or _block_mapping_value(envelope_step, "env", "LINURA_ENVELOPE_LANE")
        != "${{ inputs.lane }}"
        or _block_mapping_value(
            envelope_step, "env", "LINURA_ENVELOPE_SOURCE_SHA"
        )
        != "${{ inputs.source-sha }}"
        or _block_mapping_value(
            envelope_step, "env", "LINURA_ENVELOPE_EXECUTION_SUBJECT_FILE"
        )
        != "${{ inputs.execution-subject-file }}"
    ):
        return False

    run = _block_literal_scalar(envelope_step, "run")
    if run is None:
        return False
    direct_commands = _shell_logical_commands(run, required_indent=0)
    required_commands = {
        "set -euo pipefail",
        'created="$(/usr/bin/python3 -I tools/qualification_envelope.py create-from-environment --lane "$LINURA_ENVELOPE_LANE" --source-sha "$LINURA_ENVELOPE_SOURCE_SHA" "${subject_args[@]}" --output "$output")"',
        'verified="$(/usr/bin/python3 -I tools/qualification_envelope.py verify --envelope "$output" --source-sha "$LINURA_ENVELOPE_SOURCE_SHA")"',
        'test "$created" = "$verified"',
        'printf \'sha256=%s\\n\' "$verified" >> "$GITHUB_OUTPUT"',
    }
    if not required_commands.issubset(set(direct_commands)):
        return False

    upload_steps = []
    for _, block in steps:
        uses = _block_direct_value(block, "uses")
        if (
            uses is not None
            and re.fullmatch(r"actions/upload-artifact@[0-9a-f]{40}", uses) is not None
        ):
            upload_steps.append(block)
    if len(upload_steps) != 1:
        return False
    upload = upload_steps[0]
    return (
        workflow_step_direct_value(upload, "if") is None
        and not workflow_block_is_error_tolerant(upload)
        and _block_with_value(upload, "path")
        == "${{ runner.temp }}/linura-qualification-envelope-${{ inputs.lane }}/"
        and _block_with_value(upload, "if-no-files-found") == "error"
        and _block_with_value(upload, "retention-days") == "30"
    )


def workflow_step_blocks(source: str) -> list[tuple[int, str]]:
    """Return only concrete jobs.*.steps list items.

    This is deliberately a bounded GitHub Actions workflow recognizer, not a
    general YAML parser. A line that merely looks like ``- uses:`` inside a
    block scalar, heredoc, comment, or another mapping must never satisfy a
    qualification integration invariant.
    """
    blocks: list[tuple[int, str]] = []
    for job_start_line, job_block in workflow_job_blocks(source):
        lines = job_block.splitlines()
        if not lines:
            continue

        job_indent = len(lines[0]) - len(lines[0].lstrip())
        child_indents = [
            len(line) - len(line.lstrip())
            for line in lines[1:]
            if line.strip()
            and not line.lstrip().startswith("#")
            and len(line) - len(line.lstrip()) > job_indent
        ]
        if not child_indents:
            continue
        direct_child_indent = min(child_indents)

        for steps_index, line in enumerate(lines[1:], start=1):
            if (
                len(line) - len(line.lstrip()) != direct_child_indent
                or re.fullmatch(r"\s*steps:\s*(?:#.*)?", line) is None
            ):
                continue

            steps_indent = direct_child_indent
            steps_end = steps_index + 1
            while steps_end < len(lines):
                candidate = lines[steps_end]
                if candidate.strip() and not candidate.lstrip().startswith("#"):
                    candidate_indent = len(candidate) - len(candidate.lstrip())
                    if candidate_indent <= steps_indent:
                        break
                steps_end += 1

            step_indent: int | None = None
            index = steps_index + 1
            while index < steps_end:
                candidate = lines[index]
                if not candidate.strip() or candidate.lstrip().startswith("#"):
                    index += 1
                    continue
                candidate_indent = len(candidate) - len(candidate.lstrip())
                is_list_item = re.match(r"^\s*-\s+\S", candidate) is not None
                if step_indent is None:
                    if not is_list_item or candidate_indent <= steps_indent:
                        index += 1
                        continue
                    step_indent = candidate_indent
                if candidate_indent != step_indent or not is_list_item:
                    index += 1
                    continue

                end_index = index + 1
                while end_index < steps_end:
                    following = lines[end_index]
                    if following.strip() and not following.lstrip().startswith("#"):
                        following_indent = len(following) - len(following.lstrip())
                        if following_indent <= steps_indent:
                            break
                        if (
                            following_indent == step_indent
                            and re.match(r"^\s*-\s+\S", following) is not None
                        ):
                            break
                    end_index += 1

                blocks.append(
                    (
                        job_start_line + index,
                        "\n".join(lines[index:end_index]),
                    )
                )
                index = end_index
    return blocks

def _normalized_step_line(line: str) -> str:
    value = line.strip()
    if value.startswith("- "):
        value = value[2:].lstrip()
    return value.split(" #", 1)[0].rstrip()


def _block_direct_value(block: str, key: str) -> str | None:
    """Return a direct mapping value, excluding nested or scalar text."""
    lines = block.splitlines()
    if not lines:
        return None
    first = _normalized_step_line(lines[0])
    prefix = f"{key}:"
    if first == key + ":":
        return ""
    if first.startswith(prefix):
        return first[len(prefix):].strip()

    root_indent = len(lines[0]) - len(lines[0].lstrip())
    child_indents = [
        len(line) - len(line.lstrip())
        for line in lines[1:]
        if line.strip()
        and not line.lstrip().startswith("#")
        and len(line) - len(line.lstrip()) > root_indent
    ]
    if not child_indents:
        return None
    direct_indent = min(child_indents)
    for line in lines[1:]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if len(line) - len(line.lstrip()) != direct_indent:
            continue
        normalized = _normalized_step_line(line)
        if normalized == key + ":":
            return ""
        if normalized.startswith(prefix):
            return normalized[len(prefix):].strip()
    return None


def _block_with_value(block: str, key: str) -> str | None:
    """Return one immediate child of the direct with mapping."""
    lines = block.splitlines()
    if not lines:
        return None
    root_indent = len(lines[0]) - len(lines[0].lstrip())
    child_indents = [
        len(line) - len(line.lstrip())
        for line in lines[1:]
        if line.strip()
        and not line.lstrip().startswith("#")
        and len(line) - len(line.lstrip()) > root_indent
    ]
    if not child_indents:
        return None
    direct_indent = min(child_indents)
    with_index: int | None = None
    for index, line in enumerate(lines[1:], start=1):
        if (
            line.strip()
            and not line.lstrip().startswith("#")
            and len(line) - len(line.lstrip()) == direct_indent
            and _normalized_step_line(line) == "with:"
        ):
            with_index = index
            break
    if with_index is None:
        return None

    nested = [
        len(line) - len(line.lstrip())
        for line in lines[with_index + 1:]
        if line.strip()
        and not line.lstrip().startswith("#")
        and len(line) - len(line.lstrip()) > direct_indent
    ]
    if not nested:
        return None
    input_indent = min(nested)
    prefix = f"{key}:"
    for line in lines[with_index + 1:]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= direct_indent:
            break
        if indent != input_indent:
            continue
        normalized = _normalized_step_line(line)
        if normalized == key + ":":
            return ""
        if normalized.startswith(prefix):
            return normalized[len(prefix):].strip()
    return None


def workflow_step_input_value(block: str, key: str) -> str | None:
    """Return one direct input from a concrete workflow step with-map."""
    return _block_with_value(block, key)


def workflow_step_direct_value(block: str, key: str) -> str | None:
    """Return one direct field from a concrete workflow step."""
    return _block_direct_value(block, key)


def workflow_step_has_value(block: str, key: str, value: str) -> bool:
    return workflow_step_input_value(block, key) == value


def workflow_block_is_statically_disabled(block: str) -> bool:
    """Reject reviewed workflow blocks that can never execute."""
    condition = _block_direct_value(block, "if")
    if condition is None:
        return False
    normalized = condition.strip()
    if (
        len(normalized) >= 2
        and normalized[0] == normalized[-1]
        and normalized[0] in {"'", '"'}
    ):
        normalized = normalized[1:-1].strip()
    expression = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", normalized)
    if expression is not None:
        normalized = expression.group(1).strip()
    normalized = re.sub(r"\s+", "", normalized).casefold()
    return normalized in {"false", "0", "-0", "null", "''", '""'}


def workflow_job_block_for_line(source: str, line_number: int) -> str | None:
    for start_line, block in workflow_job_blocks(source):
        end_line = start_line + len(block.splitlines()) - 1
        if start_line <= line_number <= end_line:
            return block
    return None


def workflow_action_steps(source: str, action: str) -> list[tuple[int, str]]:
    return [
        (start_line, block)
        for start_line, block in workflow_step_blocks(source)
        if _block_direct_value(block, "uses") == action
    ]


def workflow_job_blocks(source: str) -> list[tuple[int, str]]:
    """Return top-level job blocks from the workflow jobs mapping."""
    lines = source.splitlines()
    try:
        jobs_line = next(
            index for index, line in enumerate(lines) if line == "jobs:"
        )
    except StopIteration:
        return []
    blocks: list[tuple[int, str]] = []
    index = jobs_line + 1
    while index < len(lines):
        match = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", lines[index])
        if match is None:
            index += 1
            continue
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            if candidate and not candidate.startswith(" "):
                break
            if re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", candidate):
                break
            end += 1
        blocks.append((index + 1, "\n".join(lines[index:end])))
        index = end
    return blocks


def workflow_reusable_job_blocks(
    source: str, reusable_workflow: str
) -> list[tuple[int, str]]:
    return [
        (start_line, block)
        for start_line, block in workflow_job_blocks(source)
        if _block_direct_value(block, "uses") == reusable_workflow
    ]


def workflow_step_uses_prefix(block: str, prefix: str) -> bool:
    uses = _block_direct_value(block, "uses")
    return uses is not None and uses.startswith(prefix)


def workflow_block_is_error_tolerant(block: str) -> bool:
    """Return whether a reviewed workflow block can suppress execution failure."""
    value = _block_direct_value(block, "continue-on-error")
    if value is None:
        return False
    normalized = value.strip()
    if (
        len(normalized) >= 2
        and normalized[0] == normalized[-1]
        and normalized[0] in {"'", '"'}
    ):
        normalized = normalized[1:-1].strip()
    expression = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", normalized)
    if expression is not None:
        normalized = expression.group(1).strip()
    normalized = re.sub(r"\s+", "", normalized).casefold()
    return normalized not in {"false", "0", "-0", "null", "''", '""'}


def _shell_case_branch(source: str, label: str) -> str | None:
    lines = source.splitlines()
    starts = [index for index, line in enumerate(lines) if line.strip() == f"{label})"]
    if len(starts) != 1:
        return None
    branch_line = lines[starts[0]]
    branch_indent = len(branch_line) - len(branch_line.lstrip())
    closing_indent = branch_indent + 4
    start = starts[0] + 1
    for end in range(start, len(lines)):
        line = lines[end]
        if (
            line.strip() == ";;"
            and len(line) - len(line.lstrip()) == closing_indent
        ):
            return "\n".join(lines[start:end])
    return None


def _shell_logical_commands(
    source: str, *, required_indent: int | None = None
) -> list[str]:
    """Recognize executable shell commands while excluding comments/heredoc payloads."""
    lines = source.splitlines()
    commands: list[str] = []
    index = 0
    heredoc_delimiter: str | None = None
    while index < len(lines):
        stripped = lines[index].strip()
        if heredoc_delimiter is not None:
            if stripped == heredoc_delimiter:
                heredoc_delimiter = None
            index += 1
            continue
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        initial_indent = len(lines[index]) - len(lines[index].lstrip())
        if required_indent is not None and initial_indent != required_indent:
            index += 1
            continue

        parts = [stripped]
        while parts[-1].endswith("\\") and index + 1 < len(lines):
            parts[-1] = parts[-1][:-1].rstrip()
            index += 1
            parts.append(lines[index].strip())
        command = " ".join(part for part in parts if part)
        commands.append(command)

        heredoc = re.search(r"<<-?\s*(['\"]?)([A-Za-z0-9_]+)\1", command)
        if heredoc is not None:
            heredoc_delimiter = heredoc.group(2)
        index += 1
    return commands


def _physical_envelope_command_matches(command: str, subcommand: str) -> bool:
    try:
        tokens = shlex.split(command, comments=True, posix=True)
    except ValueError:
        return False
    if not tokens or tokens[0] != "/usr/bin/env":
        return False
    if any(token in {"||", "&&", ";"} for token in tokens):
        return False
    try:
        python_index = tokens.index("/usr/bin/python3")
        script_index = tokens.index(
            "$source_root/tools/qualification_envelope.py", python_index + 1
        )
    except ValueError:
        return False
    if "-I" not in tokens[python_index + 1:script_index]:
        return False
    if subcommand not in tokens[script_index + 1:]:
        return False

    def has_pair(option: str, value: str) -> bool:
        return any(
            tokens[index] == option
            and index + 1 < len(tokens)
            and tokens[index + 1] == value
            for index in range(script_index + 1, len(tokens))
        )

    if not has_pair("--root", "$source_root"):
        return False
    if subcommand == "create-physical":
        return (
            has_pair("--state-root", "$state_root")
            and has_pair("--output", "$envelope")
        )
    if subcommand == "verify":
        return (
            has_pair("--envelope", "$envelope")
            and has_pair("--source-sha", "$source_sha")
        )
    return False


def _physical_target_has_integration(source: str) -> bool:
    branch = _shell_case_branch(source, "finalize-run")
    if branch is None:
        return False
    direct_indent = next(
        (
            len(line) - len(line.lstrip())
            for line in branch.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ),
        None,
    )
    if direct_indent is None:
        return False
    commands = _shell_logical_commands(branch, required_indent=direct_indent)
    return (
        any(
            _physical_envelope_command_matches(command, "create-physical")
            for command in commands
        )
        and any(
            _physical_envelope_command_matches(command, "verify")
            for command in commands
        )
    )


def _hosted_target_has_integration(lane_id: str, source: str) -> bool:
    if lane_id == "control1-plan-preview-vm":
        return any(
            not workflow_block_is_statically_disabled(block)
            and not workflow_block_is_error_tolerant(block)
            and workflow_step_has_value(
                block, "envelope_lane", "control1-plan-preview-vm"
            )
            for _, block in workflow_reusable_job_blocks(
                source, "./.github/workflows/vm-acceptance.yml"
            )
        )

    expected_lane = (
        "${{ inputs.envelope_lane || 'vm-acceptance' }}"
        if lane_id == "vm-acceptance"
        else lane_id
    )
    for start_line, block in workflow_action_steps(
        source, "./.github/actions/qualification-envelope"
    ):
        # Envelope production is part of the lane's authority path. A step-level
        # condition can silently disconnect it from an otherwise successful job.
        if (
            workflow_step_direct_value(block, "if") is not None
            or workflow_block_is_error_tolerant(block)
        ):
            continue
        job_block = workflow_job_block_for_line(source, start_line)
        if (
            job_block is None
            or workflow_block_is_statically_disabled(job_block)
            or workflow_block_is_error_tolerant(job_block)
        ):
            continue
        if not workflow_step_has_value(block, "lane", expected_lane):
            continue
        if lane_id in GUEST_EXECUTION_LANES and "execution-subject-file:" not in block:
            continue
        return True
    return False


def validate_lane_integrations(root: Path, contract: dict) -> None:
    action = _safe_file(root, HOSTED_INTEGRATION_ACTION)
    action_text = action.read_text(encoding="utf-8")
    _require(
        _hosted_action_has_integration(action_text),
        "hosted envelope composite action is not structurally verification-bound",
    )

    delegated = _safe_file(root, ".github/workflows/vm-acceptance.yml").read_text(
        encoding="utf-8"
    )
    _require(
        _hosted_target_has_integration("vm-acceptance", delegated),
        "vm-acceptance reusable workflow does not bind delegated envelope lanes",
    )

    for lane in contract["lane"]:
        target = REQUIRED_LANE_BINDINGS[lane["id"]][2]
        source = _safe_file(root, target).read_text(encoding="utf-8")
        if lane["kind"] == "github-hosted":
            _require(
                _hosted_target_has_integration(lane["id"], source),
                f"qualification execution target lacks envelope integration: {lane['id']}",
            )
        else:
            _require(
                _physical_target_has_integration(source),
                "physical qualification entrypoint lacks execution-envelope finalization",
            )


def _environment_key(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", name).upper()


def _inputs_from_environment(lane: dict, environment: dict[str, str]) -> tuple[
    dict[str, str], dict[str, str], list[str]
]:
    digests: dict[str, str] = {}
    observations: dict[str, str] = {}
    caches: list[str] = []
    for name in lane["required_digests"]:
        key = _environment_key(name)
        value = environment.get(key)
        _require(value is not None and value != "", f"missing envelope environment: {key}")
        digests[name] = value
    for name in lane["required_observations"]:
        key = _environment_key(name)
        value = environment.get(key)
        _require(value is not None and value != "", f"missing envelope environment: {key}")
        observations[name] = value
    for name in lane["required_cache_digests"]:
        prefix = _environment_key(name)
        path = environment.get(prefix + "_PATH")
        digest = environment.get(prefix + "_SHA256")
        _require(path and digest, f"missing verified-cache environment for {name}")
        caches.append(f"{name}={path}@{digest}")
    return digests, observations, caches


def create_envelope(
    *,
    root: Path,
    lane_id: str,
    source_sha: str,
    digests: dict[str, str],
    observations: dict[str, str],
    verified_cache_specs: list[str],
    environment: dict[str, str],
    execution_subject: dict | None = None,
) -> dict:
    contract = load_contract(root)
    lane = lane_by_id(contract, lane_id)
    _require(
        HEX40.fullmatch(source_sha) is not None,
        "source SHA must be lowercase full-length git SHA",
    )
    head = _git(root, "rev-parse", "HEAD")
    _require(head == source_sha,
             "execution envelope must be created from exact checked-out source")
    _require_clean_tracked_checkout(root, source_sha)
    tree_sha = _git(root, "rev-parse", source_sha + "^{tree}")
    _require(HEX40.fullmatch(tree_sha) is not None,
             "invalid source tree identity")

    required_digests = set(lane["required_digests"])
    required_observations = set(lane["required_observations"])
    required_caches = set(lane["required_cache_digests"])
    _require(
        set(digests) == required_digests,
        f"{lane_id} digest set mismatch: expected {sorted(required_digests)}, "
        f"got {sorted(digests)}",
    )
    _require(
        all(isinstance(value, str) and HEX64.fullmatch(value) is not None
            for value in digests.values()),
        "dynamic digests must be lowercase sha256 values",
    )
    _require(
        set(observations) == required_observations,
        f"{lane_id} observation set mismatch: expected "
        f"{sorted(required_observations)}, got {sorted(observations)}",
    )
    _validate_observations(observations, required_observations, lane_id)

    caches = _verified_caches(verified_cache_specs)
    _require(
        set(caches) == required_caches,
        f"{lane_id} verified-cache set mismatch: expected "
        f"{sorted(required_caches)}, got {sorted(caches)}",
    )
    _validate_cache_bindings(caches, required_caches)

    runner = _runner_identity(contract, lane, environment)
    subject = _execution_subject_binding(
        contract, lane, runner, execution_subject, digests, observations, environment
    )
    if lane["kind"] == "physical":
        _require(
            digests["os_release_sha256"] == runner["os_release_sha256"],
            "physical os-release digest does not match executing runner",
        )
        _require(
            observations.get("kernel_release") == runner["kernel_release"],
            "physical kernel observation does not match executing runner",
        )
        _require(
            observations.get("virtualization") == runner["virtualization"],
            "physical virtualization observation does not match executing runner",
        )

    body = {
        "schema_version": 2,
        "contract": {
            "id": contract["id"],
            "sha256": _sha256_file(
                _safe_file(root, CONTRACT_PATH.as_posix())
            ),
        },
        "lane": {
            "id": lane_id,
            "profile_version": lane["profile_version"],
            "freshness_is_nondeterministic": lane.get(
                "freshness_is_nondeterministic", False
            ),
        },
        "source": {
            "commit_sha": source_sha,
            "tree_sha": tree_sha,
        },
        "runner": runner,
        "execution_subject": subject,
        "repository_inputs": _repository_digests(
            root, contract, lane, source_sha
        ),
        "dynamic_digests": dict(sorted(digests.items())),
        "verified_caches": caches,
        "observations": dict(sorted(observations.items())),
        "cache_policy": contract["cache_policy"],
    }
    body["envelope_sha256"] = _sha256_bytes(_canonical_json(body))
    return body


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_envelope(path: Path, envelope: dict) -> None:
    _require(not path.exists() or not path.is_symlink(),
             "execution envelope output may not be a symlink")
    checksum = path.with_name(path.name + ".sha256")
    _require(not checksum.exists() or not checksum.is_symlink(),
             "execution envelope checksum output may not be a symlink")
    _atomic_write_text(
        path, json.dumps(envelope, indent=2, sort_keys=True) + "\n"
    )
    digest = envelope["envelope_sha256"]
    _atomic_write_text(checksum, f"{digest}  {path.name}\n")

def verify_envelope(
    root: Path, path: Path, *, source_sha: str | None = None
) -> dict:
    _require(path.is_file() and not path.is_symlink(),
             "execution envelope is missing or unsafe")
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError(f"invalid execution envelope: {exc}") from exc
    _require(isinstance(envelope, dict),
             "execution envelope root must be an object")
    _require_exact_keys(
        envelope,
        {
            "schema_version",
            "contract",
            "lane",
            "source",
            "runner",
            "execution_subject",
            "repository_inputs",
            "dynamic_digests",
            "verified_caches",
            "observations",
            "cache_policy",
            "envelope_sha256",
        },
        "execution envelope",
    )
    digest = envelope.get("envelope_sha256")
    _require(
        isinstance(digest, str) and HEX64.fullmatch(digest) is not None,
        "execution envelope digest is invalid",
    )
    body = dict(envelope)
    body.pop("envelope_sha256", None)
    _require(
        _sha256_bytes(_canonical_json(body)) == digest,
        "execution envelope canonical digest mismatch",
    )

    checksum = path.with_name(path.name + ".sha256")
    _require(
        checksum.is_file() and not checksum.is_symlink(),
        "execution envelope checksum is missing",
    )
    _require(
        checksum.read_text(encoding="utf-8").strip()
        == f"{digest}  {path.name}",
        "execution envelope checksum binding mismatch",
    )

    contract = load_contract(root)
    _require(envelope["schema_version"] == 2,
             "execution envelope schema mismatch")

    lane = envelope["lane"]
    _require(isinstance(lane, dict),
             "execution envelope lane is missing")
    _require_exact_keys(
        lane,
        {"id", "profile_version", "freshness_is_nondeterministic"},
        "execution envelope lane",
    )
    lane_contract = lane_by_id(contract, lane["id"])
    _require(
        lane["profile_version"] == lane_contract["profile_version"],
        "execution envelope profile version mismatch",
    )
    _require(
        lane["freshness_is_nondeterministic"]
        == lane_contract.get("freshness_is_nondeterministic", False),
        "execution envelope freshness binding mismatch",
    )

    _require(
        envelope["contract"]
        == {
            "id": contract["id"],
            "sha256": _sha256_file(
                _safe_file(root, CONTRACT_PATH.as_posix())
            ),
        },
        "execution envelope contract binding mismatch",
    )

    source = envelope["source"]
    _require(isinstance(source, dict),
             "execution envelope source binding is missing")
    _require_exact_keys(source, {"commit_sha", "tree_sha"},
                        "execution envelope source")
    commit_sha = source["commit_sha"]
    tree_sha = source["tree_sha"]
    _require(
        isinstance(commit_sha, str) and HEX40.fullmatch(commit_sha) is not None,
        "execution envelope commit SHA is invalid",
    )
    _require(
        isinstance(tree_sha, str) and HEX40.fullmatch(tree_sha) is not None,
        "execution envelope tree SHA is invalid",
    )
    _require(
        _git(root, "rev-parse", "HEAD") == commit_sha,
        "execution envelope verification requires the exact source checkout",
    )
    _require_clean_tracked_checkout(root, commit_sha)
    _require(
        _git(root, "rev-parse", commit_sha + "^{tree}") == tree_sha,
        "execution envelope tree does not match source commit",
    )
    if source_sha is not None:
        _require(
            commit_sha == source_sha,
            "execution envelope source SHA mismatch",
        )

    expected_inputs = _repository_digests(
        root, contract, lane_contract, commit_sha
    )
    _require(
        envelope["repository_inputs"] == expected_inputs,
        "execution envelope repository input digest mismatch",
    )
    _require(
        envelope["cache_policy"] == contract["cache_policy"],
        "execution envelope cache policy mismatch",
    )

    runner = _validate_runner_binding(contract, lane_contract, envelope["runner"])
    dynamic = envelope["dynamic_digests"]
    observations = envelope["observations"]
    caches = envelope["verified_caches"]
    _require(
        isinstance(dynamic, dict)
        and set(dynamic) == set(lane_contract["required_digests"]),
        "execution envelope dynamic digest set mismatch",
    )
    _require(
        all(
            isinstance(value, str) and HEX64.fullmatch(value) is not None
            for value in dynamic.values()
        ),
        "execution envelope contains invalid dynamic digest",
    )
    _validate_observations(
        observations, set(lane_contract["required_observations"]), lane_contract["id"]
    )
    if lane_contract["kind"] == "physical":
        _require(
            dynamic["os_release_sha256"] == runner["os_release_sha256"],
            "physical os-release digest does not match runner binding",
        )
        _require(
            observations["kernel_release"] == runner["kernel_release"],
            "physical kernel observation does not match runner binding",
        )
        _require(
            observations["virtualization"] == runner["virtualization"] == "none",
            "physical virtualization binding is invalid",
        )
    _validate_execution_subject(
        contract,
        lane_contract,
        runner,
        envelope["execution_subject"],
        dynamic,
        observations,
    )
    _validate_cache_bindings(
        caches, set(lane_contract["required_cache_digests"])
    )
    return envelope


def _command_validate(args: argparse.Namespace) -> int:
    contract = load_contract(args.root)
    validate_lane_integrations(args.root, contract)
    result = {
        "ready": True,
        "schema_version": contract["schema_version"],
        "contract_id": contract["id"],
        "lanes": [lane["id"] for lane in contract["lane"]],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _command_create_from_environment(args: argparse.Namespace) -> int:
    contract = load_contract(args.root)
    lane = lane_by_id(contract, args.lane)
    digests, observations, caches = _inputs_from_environment(lane, dict(os.environ))
    envelope = create_envelope(
        root=args.root,
        lane_id=args.lane,
        source_sha=args.source_sha,
        digests=digests,
        observations=observations,
        verified_cache_specs=caches,
        environment=dict(os.environ),
        execution_subject=_load_execution_subject_file(args.execution_subject_file),
    )
    write_envelope(args.output, envelope)
    print(envelope["envelope_sha256"])
    return 0


def _physical_state_inputs(state_root: Path) -> tuple[str, Path, str, str]:
    state_path = state_root / "run-state.json"
    if not state_path.is_file():
        state_path = state_root / "state.json"
    _require(state_path.is_file() and not state_path.is_symlink(),
             "physical Q11 state is missing or unsafe")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    _require(isinstance(state, dict), "physical Q11 state must be an object")
    source_sha = _single_line(state.get("source_commit_sha"), "physical source commit")
    fixture_path = Path(_single_line(
        state.get("fixture_contract_path"), "physical fixture contract path"
    ))
    fixture_sha = _single_line(
        state.get("fixture_contract_sha256"), "physical fixture contract digest"
    )
    fixture = state.get("fixture")
    _require(isinstance(fixture, dict), "physical fixture state is missing")
    machine_class = _single_line(fixture.get("machine_class"), "physical machine class")
    return source_sha, fixture_path, fixture_sha, machine_class


def _physical_provider_manifest_sha256() -> str:
    commands = (
        ("networkmanager-version", "NetworkManager", ["--version"]),
        ("bluez-version", "bluetoothd", ["--version"]),
        ("pipewire-version", "pipewire", ["--version"]),
        ("wireplumber-version", "wireplumber", ["--version"]),
        ("udisks2-version", "udisksctl", ["--version"]),
        ("polkit-version", "pkcheck", ["--version"]),
    )
    lines: list[str] = []
    for name, executable_name, arguments in commands:
        executable = _trusted_executable(executable_name)
        completed = subprocess.run(
            [executable, *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_trusted_command_environment(),
        )
        _require(
            completed.returncode == 0,
            f"cannot capture physical provider identity {name}: " + completed.stderr.strip(),
        )
        output = completed.stdout.strip() or completed.stderr.strip()
        _require(output, f"physical provider identity is empty: {name}")
        value = _single_line(output.splitlines()[0], name)
        lines.append(f"{name}={value}")
    return _sha256_bytes(("\n".join(lines) + "\n").encode("utf-8"))

def _command_create_physical(args: argparse.Namespace) -> int:
    source_sha, fixture_path, fixture_sha, machine_class = _physical_state_inputs(
        args.state_root
    )
    _require(_sha256_file(fixture_path) == fixture_sha,
             "physical fixture contract changed before envelope finalization")
    envelope = create_envelope(
        root=args.root,
        lane_id="v010-maintained-hardware",
        source_sha=source_sha,
        digests={
            "machine_fixture_sha256": fixture_sha,
            "os_release_sha256": _sha256_resolved_identity_file(
                OS_RELEASE_PATH,
                allowed_targets=OS_RELEASE_ALLOWED_TARGETS,
            ),
            "provider_manifest_sha256": _physical_provider_manifest_sha256(),
        },
        observations={
            "kernel_release": _single_line(platform.release(), "kernel release"),
            "machine_class": machine_class,
            "virtualization": _detect_virtualization(),
        },
        verified_cache_specs=[],
        environment=dict(os.environ),
    )
    write_envelope(args.output, envelope)
    print(envelope["envelope_sha256"])
    return 0


def _command_create(args: argparse.Namespace) -> int:
    envelope = create_envelope(
        root=args.root,
        lane_id=args.lane,
        source_sha=args.source_sha,
        digests=_parse_digests(args.digest, "digest"),
        observations=dict(sorted(_parse_named(args.observation, "observation").items())),
        verified_cache_specs=args.verified_cache,
        environment=dict(os.environ),
        execution_subject=_load_execution_subject_file(args.execution_subject_file),
    )
    write_envelope(args.output, envelope)
    print(envelope["envelope_sha256"])
    return 0


def _command_verify(args: argparse.Namespace) -> int:
    envelope = verify_envelope(args.root, args.envelope, source_sha=args.source_sha)
    print(envelope["envelope_sha256"])
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate")
    validate.set_defaults(func=_command_validate)

    create_from_environment = sub.add_parser("create-from-environment")
    create_from_environment.add_argument("--lane", required=True)
    create_from_environment.add_argument("--source-sha", required=True)
    create_from_environment.add_argument("--execution-subject-file", type=Path)
    create_from_environment.add_argument("--output", required=True, type=Path)
    create_from_environment.set_defaults(func=_command_create_from_environment)

    create_physical = sub.add_parser("create-physical")
    create_physical.add_argument("--state-root", required=True, type=Path)
    create_physical.add_argument("--output", required=True, type=Path)
    create_physical.set_defaults(func=_command_create_physical)

    create = sub.add_parser("create")
    create.add_argument("--lane", required=True)
    create.add_argument("--source-sha", required=True)
    create.add_argument("--execution-subject-file", type=Path)
    create.add_argument("--output", required=True, type=Path)
    create.add_argument("--digest", action="append", default=[])
    create.add_argument("--observation", action="append", default=[])
    create.add_argument("--verified-cache", action="append", default=[])
    create.set_defaults(func=_command_create)

    verify = sub.add_parser("verify")
    verify.add_argument("--envelope", required=True, type=Path)
    verify.add_argument("--source-sha")
    verify.set_defaults(func=_command_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except EnvelopeError as exc:
        print(f"qualification envelope error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
