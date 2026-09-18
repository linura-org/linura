#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib
from urllib.parse import urlparse

CONTRACT_PATH = "contracts/v010-workstation-qualification.toml"
EXPECTED_PROFILE = "arch-hyprland-v1"
EXPECTED_MACHINE_CLASS = "workstation"
EXPECTED_EVIDENCE = ["disposable-arch", "interactive-workstation", "inherited-v0.9"]
EXPECTED_INTERACTION_ADR = "docs/adr/0031-v010-many-interfaces-one-authority-path.md"
EXPECTED_OPERATION_SEMANTICS_CONTRACT = "contracts/operation-semantics.toml"
EXPECTED_OPERATION_SEMANTICS_ADR = "docs/adr/0032-classify-operations-before-authority.md"
EXPECTED_INTERACTION_SURFACES = [
    "intent-state",
    "control-plane",
    "agent-conversational",
    "manual-no-ai",
    "library-setups-profiles",
    "control-center",
    "declarative-configuration",
    "keyboard",
    "command-palette",
    "quick-settings",
    "desktop-shell-integration",
    "launcher-workspace",
    "notifications-osd",
    "unified-visual-theme",
    "keyboard-mouse-parity",
]
EXPECTED_EXPERIENCE = {
    "interaction_model": "one-model-many-interfaces",
    "architecture_decision": EXPECTED_INTERACTION_ADR,
    "authority_convergence": "single-typed-machine-model-and-control-path",
    "required_surfaces": EXPECTED_INTERACTION_SURFACES,
    "declarative_configuration": "typed-versioned-previewable-non-authorizing",
    "command_palette": True,
    "keyboard_shortcuts": True,
    "quick_settings": True,
    "desktop_shell_integration": "bounded",
    "launcher_workspace": True,
    "notifications_osd": True,
    "unified_visual_theme": True,
    "keyboard_mouse_parity": True,
    "manual_no_ai_required": True,
    "agent_authority": "proposal-only",
    "full_shell_replacement_required": False,
    "no_parallel_mutation_paths": True,
    "operation_classification": "trusted-registry-plus-control",
    "transient_external_effect": "unprivileged-user-state-only",
    "managed_external_effect": "canonical-eleven-stage-lifecycle",
}
EXPECTED_REQUIRED_PACKAGES_PATH = "packaging/arch/archiso/packages.linura"
EXPECTED_MANIFEST_FORMAT = "linura-arch-package-manifest-v1"
EXPECTED_MANIFEST_DIRECTORY = "qualification/v010"
EXPECTED_BASE = {
    "distribution": "arch",
    "init": "systemd",
    "session": "wayland",
    "compositor": "hyprland",
}
EXPECTED_PROVIDERS = {
    "network": "networkmanager",
    "bluetooth": "bluez",
    "audio": "pipewire-wireplumber",
    "storage": "udisks2",
    "authorization": "polkit",
    "filesystem": "btrfs",
    "snapshots": "snapper",
}
EXPECTED_SECURITY = {
    "disk_encryption": "required_for_supported_install",
    "firewall_inbound": "deny_by_default",
    "ssh_initial_state": "disabled",
    "untrusted_package_sources": "disabled",
}
EXPECTED_UPDATES = {
    "coordinated": True,
    "direct_upgrade_guard": True,
    "break_glass_override": "LINURA_ALLOW_DIRECT_PACMAN=1",
}
OFFICIAL_REPOSITORIES = {"core", "extra", "multilib"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
PACKAGE_NAME_RE = re.compile(r"^[a-z0-9@._+-]+$")
ARCHIVE_RE = re.compile(
    r"^https://archive\.archlinux\.org/repos/(\d{4})/(\d{2})/(\d{2})/\$repo/os/\$arch$"
)


def _load_toml(path: Path, label: str, failures: list[str]) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        failures.append(f"missing or non-regular {label}: {path}")
        return {}
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        failures.append(f"invalid {label}: {error}")
        return {}
    if not isinstance(value, dict):
        failures.append(f"{label} root must be a table")
        return {}
    return value


def _load_json(path: Path, label: str, failures: list[str]) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        failures.append(f"missing or non-regular {label}: {path}")
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        failures.append(f"invalid {label}: {error}")
        return {}
    if not isinstance(value, dict):
        failures.append(f"{label} root must be an object")
        return {}
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _v010_milestone(roadmap: dict[str, object]) -> dict[str, object] | None:
    milestones = roadmap.get("milestone")
    if not isinstance(milestones, list):
        return None
    for value in milestones:
        if isinstance(value, dict) and value.get("version") == "v0.10.0":
            return value
    return None


def _load_required_packages(root: Path, value: object, failures: list[str]) -> set[str]:
    if value != EXPECTED_REQUIRED_PACKAGES_PATH:
        failures.append(
            f"substrate.required_packages_path must remain {EXPECTED_REQUIRED_PACKAGES_PATH}"
        )
    path = root / EXPECTED_REQUIRED_PACKAGES_PATH
    if not path.is_file() or path.is_symlink():
        failures.append(f"required package contract is missing or not a regular file: {path}")
        return set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeError:
        failures.append("required package contract must be valid UTF-8")
        return set()
    packages: list[str] = []
    for line_number, raw in enumerate(lines, start=1):
        name = raw.strip()
        if not name or name.startswith("#"):
            continue
        if not PACKAGE_NAME_RE.fullmatch(name):
            failures.append(
                f"invalid required package name at {EXPECTED_REQUIRED_PACKAGES_PATH}:{line_number}"
            )
            continue
        packages.append(name)
    if not packages:
        failures.append("required package contract must not be empty")
        return set()
    if len(packages) != len(set(packages)):
        failures.append("required package contract contains duplicate package names")
    return set(packages)


def _manifest_path(root: Path, value: str, failures: list[str]) -> Path | None:
    relative = Path(value)
    if (
        not value
        or relative.is_absolute()
        or ".." in relative.parts
        or not value.startswith(f"{EXPECTED_MANIFEST_DIRECTORY}/")
        or not value.endswith(".tsv")
    ):
        failures.append(
            f"frozen package_manifest must be a .tsv file under {EXPECTED_MANIFEST_DIRECTORY}/"
        )
        return None
    path = root / relative
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        failures.append("frozen package_manifest escapes the repository root")
        return None
    return path


def _valid_exact_version(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= 256
        and value.isascii()
        and all(not character.isspace() and ord(character) >= 32 and ord(character) != 127 for character in value)
    )


def _validate_package_manifest(
    path: Path,
    snapshot_date: str,
    architecture: str,
    required_packages: set[str],
    failures: list[str],
) -> None:
    if not path.is_file() or path.is_symlink():
        failures.append(f"frozen package manifest missing or not a regular file: {path}")
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeError:
        failures.append("frozen package manifest must be valid UTF-8")
        return

    expected_headers = [
        f"# {EXPECTED_MANIFEST_FORMAT}",
        f"# snapshot_date={snapshot_date}",
        f"# architecture={architecture}",
    ]
    if lines[:3] != expected_headers:
        failures.append("frozen package manifest identity headers do not match the qualification substrate")
        return

    records = lines[3:]
    if not records:
        failures.append("frozen package manifest must contain versioned package records")
        return
    if any(not line for line in records):
        failures.append("frozen package manifest must not contain blank record lines")

    parsed: list[tuple[str, str, str, str]] = []
    seen_names: set[str] = set()
    for line_number, line in enumerate(records, start=4):
        fields = line.split("\t")
        if len(fields) != 4:
            failures.append(
                f"frozen package manifest line {line_number} must contain repo, name, version and architecture"
            )
            continue
        repository, name, version, package_arch = fields
        valid = True
        if repository not in OFFICIAL_REPOSITORIES:
            failures.append(f"frozen package manifest line {line_number} uses a non-official repository")
            valid = False
        if not PACKAGE_NAME_RE.fullmatch(name):
            failures.append(f"frozen package manifest line {line_number} has an invalid package name")
            valid = False
        if not _valid_exact_version(version):
            failures.append(f"frozen package manifest line {line_number} has an invalid exact version")
            valid = False
        if package_arch not in {architecture, "any"}:
            failures.append(f"frozen package manifest line {line_number} has an invalid architecture")
            valid = False
        if name in seen_names:
            failures.append(f"frozen package manifest contains duplicate package record: {name}")
            valid = False
        seen_names.add(name)
        if valid:
            parsed.append((repository, name, version, package_arch))

    if not parsed:
        failures.append("frozen package manifest must contain parseable versioned package records")
        return
    if parsed != sorted(parsed, key=lambda item: (item[1], item[0], item[2], item[3])):
        failures.append("frozen package manifest records must use canonical package-name order")
    missing = sorted(required_packages - seen_names)
    if missing:
        failures.append(
            "frozen package manifest is missing required versioned packages: " + ", ".join(missing)
        )


def validate(root: Path) -> list[str]:
    failures: list[str] = []
    contract = _load_toml(root / CONTRACT_PATH, "v0.10 qualification contract", failures)
    roadmap = _load_toml(root / "contracts/roadmap.toml", "roadmap contract", failures)
    if not contract or not roadmap:
        return failures

    if contract.get("schema_version") != 1:
        failures.append("v0.10 qualification schema_version must remain 1")
    if contract.get("milestone") != "v0.10.0":
        failures.append("v0.10 qualification contract must bind milestone v0.10.0")
    if contract.get("claim_class") != "Experimental":
        failures.append("v0.10 qualification claim_class must remain Experimental")
    if contract.get("state") != "development":
        failures.append("v0.10 qualification state must remain development until release qualification")
    if contract.get("target_profile") != EXPECTED_PROFILE:
        failures.append(f"v0.10 target_profile must remain {EXPECTED_PROFILE}")
    if contract.get("target_machine_class") != EXPECTED_MACHINE_CLASS:
        failures.append("v0.10 target_machine_class must remain workstation")
    if contract.get("support_promotion_authority") != "protected-post-release-closure":
        failures.append("v0.10 support promotion authority must remain protected-post-release-closure")
    if contract.get("required_evidence") != EXPECTED_EVIDENCE:
        failures.append(f"v0.10 required_evidence must remain exactly {EXPECTED_EVIDENCE!r}")
    if contract.get("operation_semantics_contract") != EXPECTED_OPERATION_SEMANTICS_CONTRACT:
        failures.append("v0.10 operation_semantics_contract must bind the canonical operation-semantics contract")
    elif not (root / EXPECTED_OPERATION_SEMANTICS_CONTRACT).is_file():
        failures.append("v0.10 operation-semantics contract file is missing")
    if contract.get("experience") != EXPECTED_EXPERIENCE:
        failures.append("v0.10 experience contract drifted from the required multi-interface workstation boundary")
    if not (root / EXPECTED_INTERACTION_ADR).is_file():
        failures.append("v0.10 interaction ADR 0031 is missing")

    milestone = _v010_milestone(roadmap)
    if milestone is None:
        failures.append("roadmap missing v0.10.0 milestone")
    else:
        if milestone.get("target_platform_profiles") != [EXPECTED_PROFILE]:
            failures.append("roadmap v0.10 target_platform_profiles must remain exactly arch-hyprland-v1")
        if milestone.get("interaction_model") != "one-model-many-interfaces":
            failures.append("roadmap v0.10 interaction_model must remain one-model-many-interfaces")
        if milestone.get("required_interaction_surfaces") != EXPECTED_INTERACTION_SURFACES:
            failures.append("roadmap v0.10 required_interaction_surfaces drifted from the v0.10 experience contract")
        if milestone.get("desktop_shell_scope") != "bounded-integration-not-full-replacement":
            failures.append("roadmap v0.10 desktop_shell_scope must remain bounded-integration-not-full-replacement")
        if milestone.get("interaction_adr") != EXPECTED_INTERACTION_ADR:
            failures.append("roadmap v0.10 interaction_adr must bind ADR 0031")
        if milestone.get("operation_semantics_contract") != EXPECTED_OPERATION_SEMANTICS_CONTRACT:
            failures.append("roadmap v0.10 operation_semantics_contract must bind the canonical contract")
        if milestone.get("operation_semantics_adr") != EXPECTED_OPERATION_SEMANTICS_ADR:
            failures.append("roadmap v0.10 operation_semantics_adr must bind ADR 0032")
        if milestone.get("claim_class") != "Experimental":
            failures.append("roadmap v0.10 claim_class must remain Experimental")
        if milestone.get("qualification_contract") != CONTRACT_PATH:
            failures.append(f"roadmap v0.10 qualification_contract must point to {CONTRACT_PATH}")
        if milestone.get("qualification") != contract.get("qualification_document"):
            failures.append("roadmap and v0.10 qualification contract disagree on qualification document")

    profile_path_value = contract.get("profile_path")
    if profile_path_value != "profiles/arch-hyprland-v1.toml":
        failures.append("v0.10 profile_path must remain profiles/arch-hyprland-v1.toml")
        profile_path = root / "profiles/arch-hyprland-v1.toml"
    else:
        profile_path = root / profile_path_value
    profile = _load_toml(profile_path, "target PlatformProfile", failures)
    if profile:
        expected_digest = contract.get("profile_sha256")
        if not isinstance(expected_digest, str) or not SHA256_RE.fullmatch(expected_digest):
            failures.append("profile_sha256 must be a lowercase SHA-256 digest")
        elif _sha256(profile_path) != expected_digest:
            failures.append("arch-hyprland-v1 content does not match the qualification-bound profile_sha256")
        if profile.get("schema_version") != 1 or profile.get("id") != EXPECTED_PROFILE:
            failures.append("target PlatformProfile schema/id mismatch")
        if profile.get("status") != "development":
            failures.append("arch-hyprland-v1 must remain development before protected post-release closure")
        if profile.get("base") != EXPECTED_BASE:
            failures.append("arch-hyprland-v1 base identity drifted from the v0.10 qualification contract")
        if profile.get("providers") != EXPECTED_PROVIDERS:
            failures.append("arch-hyprland-v1 provider identity drifted from the v0.10 qualification contract")
        if profile.get("security") != EXPECTED_SECURITY:
            failures.append("arch-hyprland-v1 security baseline drifted from the v0.10 qualification contract")
        if profile.get("updates") != EXPECTED_UPDATES:
            failures.append("arch-hyprland-v1 update boundary drifted from the v0.10 qualification contract")

    identity = contract.get("profile_identity")
    if not isinstance(identity, dict):
        failures.append("v0.10 qualification contract missing profile_identity")
    else:
        for key, expected in EXPECTED_BASE.items():
            if identity.get(key) != expected:
                failures.append(f"profile_identity.{key} must remain {expected}")
        if identity.get("status_until_post_release_closure") != "development":
            failures.append("profile_identity must keep the target profile development until post-release closure")
        if identity.get("providers") != EXPECTED_PROVIDERS:
            failures.append("profile_identity.providers must remain exact")

    support_path = contract.get("support_matrix_path")
    if support_path != "hardware/support-matrix.json":
        failures.append("support_matrix_path must remain hardware/support-matrix.json")
        support_path = "hardware/support-matrix.json"
    support = _load_json(root / support_path, "hardware support matrix", failures)
    if support:
        classes = support.get("machine_classes")
        workstation = classes.get("workstation") if isinstance(classes, dict) else None
        profiles = workstation.get("release_qualified_profiles") if isinstance(workstation, dict) else None
        if not isinstance(profiles, list):
            failures.append("workstation release_qualified_profiles must be an array")
        elif EXPECTED_PROFILE in profiles:
            failures.append(
                "arch-hyprland-v1 cannot be release-qualified before immutable v0.10 publication and protected post-release closure"
            )

    qualification_document = contract.get("qualification_document")
    if qualification_document != "docs/qualification/v0.10.0.md":
        failures.append("qualification_document must remain docs/qualification/v0.10.0.md")
    elif not (root / qualification_document).is_file():
        failures.append("v0.10 qualification document is missing")

    substrate = contract.get("substrate")
    if not isinstance(substrate, dict):
        failures.append("v0.10 qualification contract missing substrate")
    else:
        state = substrate.get("state")
        if state not in {"source-pinned-package-set-pending", "frozen"}:
            failures.append("substrate.state must be source-pinned-package-set-pending or frozen")
        if substrate.get("source_kind") != "arch-linux-archive":
            failures.append("substrate.source_kind must remain arch-linux-archive")
        snapshot_date = substrate.get("snapshot_date")
        repository_url = substrate.get("repository_url")
        architecture = substrate.get("architecture")
        if not isinstance(snapshot_date, str) or not DATE_RE.fullmatch(snapshot_date):
            failures.append("substrate.snapshot_date must be an exact YYYY-MM-DD date")
        if not isinstance(repository_url, str):
            failures.append("substrate.repository_url must be a string")
        else:
            parsed_url = urlparse(repository_url)
            if parsed_url.scheme != "https" or parsed_url.netloc != "archive.archlinux.org":
                failures.append("substrate.repository_url must use the official Arch Linux Archive over HTTPS")
            match = ARCHIVE_RE.fullmatch(repository_url)
            if match is None:
                failures.append("substrate.repository_url must use an exact dated Arch Linux Archive repository path")
            elif isinstance(snapshot_date, str) and "-".join(match.groups()) != snapshot_date:
                failures.append("substrate snapshot_date and repository_url date must match")
            lowered = repository_url.lower()
            if any(f"/{name}/" in lowered for name in ("last", "week", "month")) or "latest" in lowered:
                failures.append("mutable Arch archive aliases/latest are forbidden for v0.10 qualification")
        if architecture != "x86_64":
            failures.append("v0.10 Arch qualification architecture must remain x86_64")

        required_packages = _load_required_packages(root, substrate.get("required_packages_path"), failures)
        if substrate.get("package_manifest_format") != EXPECTED_MANIFEST_FORMAT:
            failures.append(f"substrate.package_manifest_format must remain {EXPECTED_MANIFEST_FORMAT}")
        if substrate.get("package_manifest_directory") != EXPECTED_MANIFEST_DIRECTORY:
            failures.append(f"substrate.package_manifest_directory must remain {EXPECTED_MANIFEST_DIRECTORY}")
        for key in (
            "forbid_mutable_latest",
            "require_https",
            "require_snapshot_date",
            "require_package_manifest_digest",
            "require_exact_package_versions",
            "require_required_package_coverage",
            "require_official_repositories",
            "require_canonical_manifest_order",
        ):
            if substrate.get(key) is not True:
                failures.append(f"substrate.{key} must remain true")

        release_ready = substrate.get("release_qualification_ready")
        manifest_value = substrate.get("package_manifest")
        manifest_digest = substrate.get("package_manifest_sha256")
        if state == "source-pinned-package-set-pending":
            if release_ready is not False:
                failures.append("source-pinned/package-pending substrate cannot be release_qualification_ready")
            if manifest_value not in ("", None) or manifest_digest not in ("", None):
                failures.append("pending package-set state must not carry unverified package-manifest bindings")
        elif state == "frozen":
            if release_ready is not True:
                failures.append("frozen substrate must set release_qualification_ready=true")
            if not isinstance(manifest_value, str) or not manifest_value:
                failures.append("frozen substrate requires package_manifest")
            if not isinstance(manifest_digest, str) or not SHA256_RE.fullmatch(manifest_digest):
                failures.append("frozen substrate requires lowercase package_manifest_sha256")
            if isinstance(manifest_value, str) and manifest_value:
                manifest_path = _manifest_path(root, manifest_value, failures)
                if manifest_path is not None:
                    if isinstance(manifest_digest, str) and SHA256_RE.fullmatch(manifest_digest):
                        if manifest_path.is_file() and not manifest_path.is_symlink():
                            if _sha256(manifest_path) != manifest_digest:
                                failures.append("frozen package manifest digest mismatch")
                    if isinstance(snapshot_date, str) and isinstance(architecture, str):
                        _validate_package_manifest(
                            manifest_path,
                            snapshot_date,
                            architecture,
                            required_packages,
                            failures,
                        )

    if contract.get("security") != EXPECTED_SECURITY:
        failures.append("v0.10 contract security baseline must match the target PlatformProfile")
    if contract.get("updates") != EXPECTED_UPDATES:
        failures.append("v0.10 contract update boundary must match the target PlatformProfile")

    return failures


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    failures = validate(root)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("v0.10 workstation qualification contract checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
