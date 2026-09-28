#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
import tomllib
import zlib
from urllib.parse import urlparse

CONTRACT_PATH = "contracts/v010-workstation-qualification.toml"
EXPECTED_PROFILE = "arch-hyprland-v1"
EXPECTED_MACHINE_CLASS = "workstation"
EXPECTED_EVIDENCE = ["disposable-arch", "interactive-workstation", "inherited-v0.9"]
EXPECTED_INTERACTION_ADR = "docs/adr/0031-v010-many-interfaces-one-authority-path.md"
EXPECTED_PRODUCT_SCOPE_ADR = "docs/adr/0033-v010-complete-workstation-product-boundary.md"
EXPECTED_SLICE_CONTRACT = "contracts/v010-workstation-slices.toml"
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
    "shell-panel-tray-status",
    "launcher-workspace",
    "notifications-osd",
    "lock-session-controls",
    "network-connectivity",
    "bluetooth",
    "audio-media",
    "display-power",
    "desktop-utilities",
    "applications-packages",
    "updates-snapshots-recovery",
    "personalization",
    "install-first-boot",
    "unified-visual-theme",
    "keyboard-mouse-parity",
    "accessibility",
    "diagnostics-explanation-audit",
]
EXPECTED_REQUIRED_VISUAL_SURFACES = [
    "linura-firstboot",
    "linura-installer",
    "linura-control-center",
    "command-palette",
    "quick-settings",
    "desktop-shell-integration",
    "shell-panel-tray-status",
    "launcher-workspace",
    "notifications-osd",
    "lock-session-controls",
    "network-connectivity",
    "bluetooth",
    "audio-media",
    "display-power",
    "desktop-utilities",
    "applications-packages",
    "updates-snapshots-recovery",
    "personalization",
]
EXPECTED_ALLOWED_VISUAL_SURFACES = set(EXPECTED_REQUIRED_VISUAL_SURFACES) | {"approval-dialog"}
EXPECTED_Q10_SURFACE_WORKFLOW_OBSERVATIONS = {
    "linura-firstboot": ["owner-enrollment-workflow-completed", "qualified-profile-state-rendered", "manual-no-ai-completion-verified"],
    "linura-installer": ["supported-profile-install-plan-rendered", "destructive-step-review-completed", "installer-handoff-to-firstboot-verified"],
    "linura-control-center": ["authoritative-state-reobserved", "registered-typed-effect-dispatched", "post-effect-verification-rendered"],
    "command-palette": ["registered-target-resolved", "typed-operation-dispatched", "raw-privileged-shell-rejected"],
    "quick-settings": ["fresh-authoritative-state-rendered", "registered-typed-effect-dispatched", "stale-or-unavailable-mutation-disabled"],
    "desktop-shell-integration": ["verified-lifecycle-state-rendered", "shell-authority-escalation-absent", "session-restart-state-reconstructed"],
    "shell-panel-tray-status": ["authoritative-status-rendered", "entrypoint-navigation-completed", "status-surface-authority-escalation-absent"],
    "launcher-workspace": ["application-launch-completed", "workspace-navigation-completed", "ephemeral-navigation-not-recorded-as-durable-mutation"],
    "notifications-osd": ["verified-commit-precedes-success-notification", "failure-lifecycle-notification-rendered", "secret-bearing-material-redacted"],
    "lock-session-controls": ["authenticated-actor-bound", "registered-session-action-dispatched", "authority-unavailable-fails-closed"],
    "network-connectivity": ["fresh-networkmanager-state-observed", "registered-network-effect-dispatched", "post-effect-network-state-reobserved"],
    "bluetooth": ["fresh-bluez-state-observed", "registered-bluetooth-effect-dispatched", "post-effect-bluetooth-state-reobserved"],
    "audio-media": ["fresh-pipewire-wireplumber-state-observed", "registered-audio-effect-dispatched", "post-effect-audio-state-reobserved"],
    "display-power": ["fresh-display-power-state-observed", "supported-display-power-effect-dispatched", "unsupported-or-stale-state-rendered"],
    "desktop-utilities": ["screenshot-or-recording-workflow-completed", "clipboard-history-workflow-completed", "privileged-shell-shortcut-absent"],
    "applications-packages": ["typed-package-discovery-completed", "registered-package-install-remove-effect-dispatched", "arbitrary-package-or-shell-text-rejected"],
    "updates-snapshots-recovery": ["coordinated-update-workflow-completed", "snapshot-or-rollback-workflow-completed", "durable-recovery-state-reobserved"],
    "personalization": ["typed-preference-change-completed", "preference-persistence-reobserved", "authority-bearing-payload-rejected"],
}

EXPECTED_Q10_OVERLAY_INPUT_REGION_SURFACES = frozenset(
    {
        "command-palette",
        "quick-settings",
        "desktop-shell-integration",
        "shell-panel-tray-status",
        "launcher-workspace",
        "notifications-osd",
    }
)
EXPECTED_Q10_OVERLAY_INPUT_REGION = {
    "noninteractive_regions": "pass-through",
    "interactive_regions": "bounded-to-visible-controls",
}


EXPECTED_EXPERIENCE = {
    "interaction_model": "one-model-many-interfaces",
    "architecture_decision": EXPECTED_INTERACTION_ADR,
    "authority_convergence": "single-typed-machine-model-and-control-path",
    "experience_scope": "complete-daily-usable-workstation",
    "required_surfaces": EXPECTED_INTERACTION_SURFACES,
    "declarative_configuration": "typed-versioned-previewable-non-authorizing",
    "command_palette": True,
    "keyboard_shortcuts": True,
    "quick_settings": True,
    "desktop_shell_integration": "complete-first-party",
    "shell_panel_tray_status": True,
    "launcher_workspace": True,
    "notifications_osd": True,
    "lock_session_controls": True,
    "network_connectivity": True,
    "bluetooth": True,
    "audio_media": True,
    "display_power": True,
    "desktop_utilities": True,
    "applications_packages": True,
    "updates_snapshots_recovery": True,
    "personalization": True,
    "installation_path_required": True,
    "ordinary_workflows_terminal_optional": True,
    "complete_first_party_shell_required": True,
    "unified_visual_theme": True,
    "keyboard_mouse_parity": True,
    "accessibility_required": True,
    "noninteractive_surfaces_do_not_capture_input": True,
    "visual_baseline_manifest": "visual/baselines/manifest.json",
    "experience_evidence_manifest": "qualification/v010/experience-evidence.json",
    "authority_evidence_manifest": "qualification/v010/experience/authority-evidence.json",
    "representative_visual_scales": [1.0, 2.0],
    "representative_visual_resolutions": ["1280x800", "1440x900"],
    "required_visual_surfaces": EXPECTED_REQUIRED_VISUAL_SURFACES,
    "required_accessibility_surfaces": EXPECTED_REQUIRED_VISUAL_SURFACES,
    "require_reviewed_non_null_visual_baselines": True,
    "require_representative_resolution_scale_captures": True,
    "require_retained_visual_failure_diffs": True,
    "require_visual_interaction_evidence": True,
    "require_rendered_visual_content": True,
    "require_surface_workflow_observations": True,
    "require_screen_reader_semantics": True,
    "require_reduced_motion": True,
    "require_display_scaling": True,
    "require_offline_error_states": True,
    "manual_no_ai_required": True,
    "agent_authority": "proposal-only",
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
EXPECTED_Q11_SESSION_PACKAGE_VERSIONS = {
    "compositor_version": "hyprland",
    "quickshell_version": "quickshell",
    "qt_version": "qt6-base",
    "kernel_version": "linux",
    "systemd_version": "systemd",
}

EXPECTED_Q10_CASE_OBSERVATIONS = {
    "manual-no-model-workflow": [
        "model-providers-absent",
        "manual-path-completed",
        "configuration-path-completed",
        "keyboard-path-completed",
    ],
    "cross-interface-operation-class-convergence": [
        "cli-class-bound",
        "control-center-class-bound",
        "configuration-class-bound",
        "palette-shortcut-class-bound",
        "quick-settings-class-bound",
        "agent-proposal-class-bound",
        "classes-converged",
    ],
    "declarative-authority-smuggling-rejection": [
        "unknown-field-rejected",
        "shell-text-rejected",
        "authority-token-rejected",
        "policy-approval-material-rejected",
        "no-effect-dispatched",
    ],
    "unregistered-palette-operation-rejection": [
        "unregistered-operation-presented",
        "operation-rejected",
        "no-privileged-shell-dispatched",
    ],
    "operation-class-downgrade-rejection": [
        "stronger-effect-presented-as-transient",
        "trusted-registry-class-preserved",
        "downgrade-rejected",
    ],
    "stale-quick-settings-external-change": [
        "stale-observation-injected",
        "concurrent-external-change-injected",
        "mutation-disabled-or-revalidated",
        "authoritative-state-reobserved",
    ],
    "forged-premature-success-rejection": [
        "premature-success-injected",
        "final-success-withheld",
        "independent-verification-required",
    ],
    "malformed-malicious-interface-request": [
        "malformed-or-malicious-request-injected",
        "authority-not-widened",
        "no-unauthorized-effect-dispatched",
    ],
    "input-accessibility-regression-rejection": [
        "keyboard-or-pointer-regression-injected",
        "semantic-or-focus-regression-injected",
        "regression-detected",
    ],
    "visual-evidence-regression-rejection": [
        "null-or-unreviewed-baseline-injected",
        "coverage-or-interaction-gap-injected",
        "unretained-failure-diff-injected",
        "qualification-rejected",
    ],
    "offline-stale-error-reconnect": [
        "provider-or-network-unavailable",
        "stale-or-unknown-rendered",
        "success-not-fabricated",
        "reconnect-reobserved",
    ],
    "restart-during-managed-mutation": [
        "managed-mutation-in-flight",
        "surface-restart-injected",
        "stale-approval-not-resurrected",
        "effect-not-replayed",
        "authoritative-lifecycle-reconstructed",
    ],
}
EXPECTED_Q10_AUTHORITY_QUALIFICATION = {
    "evidence_manifest": "qualification/v010/experience/authority-evidence.json",
    "evidence_type": "exact-source-q10-experience-authority",
    "required_cases": list(EXPECTED_Q10_CASE_OBSERVATIONS),
}

EXPECTED_Q11_CASE_OBSERVATIONS = {
    "bounded-installer-lane": [
        "installer-started-from-supported-media",
        "arch-hyprland-v1-constructed-or-adopted",
        "disk-encryption-baseline-verified",
        "firewall-default-deny-verified",
        "ssh-disabled-default-verified",
        "owner-enrollment-completed",
        "install-interruption-injected",
        "interrupted-install-recovered",
        "post-install-first-boot-completed",
    ],
    "physical-session-start": ["physical-hardware-present", "wayland-session-active", "hyprland-session-active"],
    "session-supervision": [
        "hyprland-session-target-active",
        "graphical-session-target-active",
        "linura-shell-active-through-session-target",
        "linura-shell-binds-to-session-target",
        "linura-shell-part-of-session-target",
        "linura-shell-stopped-with-graphical-session",
    ],
    "shell-render-and-input": ["shell-rendered", "keyboard-input", "pointer-input"],
    "display-scale-and-hidpi": ["display-enumerated", "scale-applied", "hidpi-render-captured"],
    "accessibility-and-visual": [
        "screen-reader-semantics-verified",
        "focus-navigation-verified",
        "reduced-motion-verified",
        "visual-artifact-retained",
    ],
    "provider-runtime-identities": ["networkmanager-version", "bluez-version", "pipewire-version", "wireplumber-version", "udisks2-version", "polkit-version"],
    "restart-recovery": ["shell-restart", "authority-restart", "state-reobserved"],
}
EXPECTED_INTERACTIVE_WORKSTATION = {
    "evidence_manifest": "qualification/v010/interactive-workstation-evidence.json",
    "evidence_type": "maintainer-physical-workstation",
    "evidence_tier": "maintainer_hardware",
    "required_profile": EXPECTED_PROFILE,
    "required_machine_class": EXPECTED_MACHINE_CLASS,
    "required_session": "wayland",
    "required_compositor": "hyprland",
    "require_physical_hardware": True,
    "require_machine_environment_provenance": True,
    "require_raw_machine_probes": True,
    "require_case_execution_provenance": True,
    "require_bounded_installer_execution": True,
    "require_interrupted_install_recovery": True,
    "require_physical_accessibility_visual_evidence": True,
    "require_retained_physical_visual_artifact": True,
    "required_provider_ids": [
        "networkmanager",
        "bluez",
        "pipewire",
        "wireplumber",
        "udisks2",
        "polkit",
    ],
    "required_cases": [
        "bounded-installer-lane",
        "physical-session-start",
        "session-supervision",
        "shell-render-and-input",
        "display-scale-and-hidpi",
        "accessibility-and-visual",
        "provider-runtime-identities",
        "restart-recovery",
    ],
}
EXPECTED_Q11_EXECUTION_MECHANISMS = {
    "bounded-installer-lane": "physical-installer-execution",
    "physical-session-start": "physical-session-observation",
    "session-supervision": "systemd-session-observation",
    "shell-render-and-input": "physical-input-observation",
    "display-scale-and-hidpi": "physical-display-observation",
    "accessibility-and-visual": "physical-accessibility-visual-observation",
    "provider-runtime-identities": "physical-provider-observation",
    "restart-recovery": "physical-restart-observation",
}

EXPECTED_Q12_CASE_OBSERVATIONS = {
    "update-success": ["candidate-applied", "post-update-state-reobserved", "update-audit-bound"],
    "migration-v09-v010": ["v09-state-seeded", "v010-migration-applied", "persistent-state-reopened"],
    "pre-migration-backup": ["risky-migration-identified", "writer-safe-backup-created", "backup-integrity-verified"],
    "migration-failure-restore-retry": ["migration-failure-injected", "pre-migration-backup-restored", "retry-converged"],
    "update-interruption": ["candidate-update-started", "interruption-injected", "restart-detected-incomplete-update"],
    "restart-reobservation": ["restart-completed", "authoritative-state-reobserved", "reobserved-state-bound"],
    "crash-before-dispatch": ["pre-dispatch-crash-injected", "executor-not-dispatched", "recovery-converged"],
    "crash-after-effect-start": ["effect-start-confirmed", "post-effect-start-crash-injected", "reconciliation-converged"],
    "crash-around-durable-commit": ["commit-boundary-crash-injected", "durable-state-recovered", "commit-outcome-reconciled"],
    "indeterminate-external-outcome": ["external-outcome-made-indeterminate", "self-report-not-trusted", "authoritative-outcome-resolved"],
    "deterministic-reconciliation": ["drift-detected", "reconciliation-plan-deterministic", "verified-state-converged"],
    "power-loss-recovery": ["power-loss-injected", "durable-state-recovered", "external-state-reconciled"],
    "snapshot-rollback": ["btrfs-snapshot-identified", "snapper-rollback-applied", "rollback-state-verified"],
    "gui-unavailable-recovery": ["gui-unavailable", "native-recovery-invoked", "local-repair-completed"],
    "offline-local-recovery": ["model-unavailable", "network-unavailable", "local-material-recovery-completed"],
    "corrupt-newer-state-fail-closed": ["corrupt-state-injected", "unsupported-newer-state-injected", "state-open-failed-closed"],
}
EXPECTED_UPDATE_RECOVERY_QUALIFICATION = {
    "evidence_manifest": "qualification/v010/update-recovery-evidence.json",
    "evidence_type": "exact-source-q12-update-recovery",
    "required_cases": list(EXPECTED_Q12_CASE_OBSERVATIONS),
}

EXPECTED_Q13_CASE_OBSERVATIONS = {
    "inbound-firewall-default-deny": ["firewall-policy-loaded", "unsolicited-inbound-probe-denied", "no-exposure-created"],
    "ssh-disabled-default": ["ssh-unit-disabled", "ssh-listener-absent", "boot-state-verified"],
    "remote-exposure-typed-authority": ["remote-exposure-requested", "typed-authority-required", "unauthorized-enable-denied"],
    "untrusted-package-source-denied": ["untrusted-source-presented", "source-rejected", "no-package-effect-dispatched"],
    "polkit-authorization": ["polkit-policy-loaded", "unauthorized-caller-denied", "authorized-caller-bound"],
    "privilege-boundary": ["unprivileged-daemon-confirmed", "generic-root-shell-absent", "privileged-effect-denied-without-authority"],
    "binding-substitution-rejection": ["actor-substitution-rejected", "plan-substitution-rejected", "evidence-substitution-rejected", "session-substitution-rejected"],
    "independent-verification": ["executor-self-report-injected", "authoritative-reobservation-performed", "self-report-not-accepted-as-verification"],
    "authority-ceiling": ["gui-proposal-only", "model-proposal-only", "deterministic-protocol-authority-preserved"],
    "secret-redaction": ["secret-bearing-input-injected", "audit-redacted", "diagnostics-redacted"],
    "adversarial-input": ["malformed-input-rejected", "authority-not-widened", "no-effect-dispatched"],
    "malicious-inputs": ["malicious-client-rejected", "malicious-proposal-rejected", "malicious-profile-rejected", "malicious-import-rejected"],
    "recovery-boundary": ["gui-unavailable", "model-unavailable", "native-recovery-remains-available"],
}
EXPECTED_SECURITY_QUALIFICATION = {
    "evidence_manifest": "qualification/v010/security-evidence.json",
    "evidence_type": "exact-source-q13-workstation-security",
    "required_profile": EXPECTED_PROFILE,
    "required_machine_class": EXPECTED_MACHINE_CLASS,
    "require_frozen_package_manifest": True,
    "require_machine_execution_provenance": True,
    "required_cases": list(EXPECTED_Q13_CASE_OBSERVATIONS),
}
EXPECTED_UPDATE_RECOVERY_QUALIFICATION.update({
    "required_profile": EXPECTED_PROFILE,
    "required_machine_class": EXPECTED_MACHINE_CLASS,
    "require_frozen_package_manifest": True,
    "require_machine_execution_provenance": True,
    "require_external_fault_injection_provenance": True,
    "require_boot_transition_provenance": True,
})
EXPECTED_Q12_EXECUTION_MECHANISMS = {
    "update-success": "machine-update",
    "migration-v09-v010": "machine-migration",
    "pre-migration-backup": "machine-backup",
    "migration-failure-restore-retry": "externally-injected-migration-failure",
    "update-interruption": "externally-interrupted-update",
    "restart-reobservation": "machine-reboot",
    "crash-before-dispatch": "external-process-termination",
    "crash-after-effect-start": "external-process-termination",
    "crash-around-durable-commit": "external-process-termination",
    "indeterminate-external-outcome": "external-response-loss",
    "deterministic-reconciliation": "external-state-drift",
    "power-loss-recovery": "machine-power-cut",
    "snapshot-rollback": "snapper-rollback",
    "gui-unavailable-recovery": "shell-or-session-stop",
    "offline-local-recovery": "network-isolation",
    "corrupt-newer-state-fail-closed": "persistent-state-corruption",
}
BOOT_TRANSITION_MECHANISMS = {"machine-reboot", "machine-power-cut"}
EXPECTED_Q13_EXECUTION_MECHANISMS = {
    "inbound-firewall-default-deny": "inbound-network-probe",
    "ssh-disabled-default": "listener-and-unit-probe",
    "remote-exposure-typed-authority": "unauthorized-remote-exposure-attempt",
    "untrusted-package-source-denied": "untrusted-package-source-attempt",
    "polkit-authorization": "cross-principal-polkit-probe",
    "privilege-boundary": "privilege-boundary-probe",
    "binding-substitution-rejection": "binding-substitution-attempt",
    "independent-verification": "executor-self-report-tamper",
    "authority-ceiling": "surface-authority-probe",
    "secret-redaction": "secret-injection",
    "adversarial-input": "malformed-input-injection",
    "malicious-inputs": "malicious-input-corpus",
    "recovery-boundary": "gui-and-model-unavailability",
}
MACHINE_PROBE_NAMES = {"os_release", "root_filesystem", "virtualization", "boot_id"}
VM_EXTERNAL_CONTROLLERS = {"qemu-host", "systemd-host", "network-harness", "storage-harness"}
PHYSICAL_EXTERNAL_CONTROLLERS = {"maintainer-console", "systemd-host", "network-harness", "storage-harness"}
OFFICIAL_REPOSITORIES = {"core", "extra", "multilib"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
BOOT_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
PACKAGE_NAME_RE = re.compile(r"^[a-z0-9@._+-]+$")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_MAX_BYTES = 64 * 1024 * 1024
PNG_MAX_PIXELS = 32 * 1024 * 1024
VISUAL_MAX_TOTAL_PNG_BYTES = 256 * 1024 * 1024
VISUAL_MAX_TOTAL_DECODE_PIXELS = 64 * 1024 * 1024
VISUAL_MAX_FAILURE_DIFFS = 32
PNG_BYTES_PER_PIXEL = {0: 1, 2: 3, 4: 2, 6: 4}
PNG_UNSUPPORTED_COLOR_CHUNKS = {b"cHRM", b"gAMA", b"iCCP", b"sRGB", b"cICP", b"mDCV", b"cLLI"}
VISUAL_MAX_BASELINES = 128
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


def _read_bounded_bytes(
    path: Path,
    max_bytes: int,
    *,
    label: str,
    failures: list[str],
) -> bytes | None:
    try:
        with path.open("rb") as stream:
            data = stream.read(max_bytes + 1)
    except OSError as error:
        failures.append(f"{label} could not be read: {error}")
        return None
    if len(data) > max_bytes:
        failures.append(f"{label} exceeds the bounded PNG artifact size")
        return None
    return data


def _bounded_regular_path(
    root: Path,
    value: object,
    *,
    prefix: str,
    label: str,
    failures: list[str],
) -> Path | None:
    if not isinstance(value, str) or not value:
        failures.append(f"{label} must be a non-empty repository-relative path")
        return None
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts or not value.startswith(prefix):
        failures.append(f"{label} must stay under {prefix}")
        return None
    path = root / relative
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        failures.append(f"{label} escapes the repository root")
        return None
    if not path.is_file() or path.is_symlink():
        failures.append(f"{label} missing or not a regular file: {value}")
        return None
    return path


def _paeth_predictor(left: int, up: int, upper_left: int) -> int:
    candidate = left + up - upper_left
    distance_left = abs(candidate - left)
    distance_up = abs(candidate - up)
    distance_upper_left = abs(candidate - upper_left)
    if distance_left <= distance_up and distance_left <= distance_upper_left:
        return left
    if distance_up <= distance_upper_left:
        return up
    return upper_left


def _decode_png_pixels(
    data: bytes,
    *,
    label: str,
    failures: list[str],
) -> tuple[int, int, bytes] | None:
    if len(data) > PNG_MAX_BYTES:
        failures.append(f"{label} exceeds the bounded PNG artifact size")
        return None
    if not data.startswith(PNG_SIGNATURE):
        failures.append(f"{label} is not a PNG")
        return None

    position = len(PNG_SIGNATURE)
    chunk_index = 0
    width: int | None = None
    height: int | None = None
    color_type: int | None = None
    bytes_per_pixel: int | None = None
    transparent_gray: int | None = None
    transparent_rgb: tuple[int, int, int] | None = None
    seen_trns = False
    idat = bytearray()
    seen_idat = False
    idat_closed = False
    seen_iend = False

    while position < len(data):
        if len(data) - position < 12:
            failures.append(f"{label} has a truncated PNG chunk")
            return None
        length = struct.unpack_from(">I", data, position)[0]
        chunk_type = data[position + 4 : position + 8]
        chunk_end = position + 12 + length
        if chunk_end > len(data):
            failures.append(f"{label} has a truncated PNG chunk payload")
            return None
        payload = data[position + 8 : position + 8 + length]
        expected_crc = struct.unpack_from(">I", data, position + 8 + length)[0]
        actual_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            failures.append(f"{label} has an invalid PNG chunk CRC")
            return None
        if len(chunk_type) != 4 or not all(
            65 <= value <= 90 or 97 <= value <= 122 for value in chunk_type
        ):
            failures.append(f"{label} has an invalid PNG chunk type")
            return None

        if chunk_index == 0 and chunk_type != b"IHDR":
            failures.append(f"{label} does not begin with IHDR")
            return None

        if chunk_type == b"IHDR":
            if chunk_index != 0 or width is not None or length != 13:
                failures.append(f"{label} has an invalid IHDR chunk")
                return None
            (
                width,
                height,
                bit_depth,
                color_type,
                compression,
                filter_method,
                interlace,
            ) = struct.unpack(">IIBBBBB", payload)
            if width <= 0 or height <= 0 or width * height > PNG_MAX_PIXELS:
                failures.append(f"{label} has invalid or unbounded PNG dimensions")
                return None
            if bit_depth != 8 or color_type not in PNG_BYTES_PER_PIXEL:
                failures.append(
                    f"{label} must use a supported non-indexed 8-bit PNG color type"
                )
                return None
            if compression != 0 or filter_method != 0 or interlace != 0:
                failures.append(
                    f"{label} must use standard compression/filtering and non-interlaced PNG data"
                )
                return None
            bytes_per_pixel = PNG_BYTES_PER_PIXEL[color_type]
        elif chunk_type == b"PLTE":
            if width is None or seen_idat:
                failures.append(f"{label} has an out-of-order PLTE chunk")
                return None
        elif chunk_type == b"tRNS":
            if width is None or seen_idat or seen_trns:
                failures.append(f"{label} has an invalid or out-of-order tRNS chunk")
                return None
            seen_trns = True
            if color_type == 0:
                if length != 2:
                    failures.append(f"{label} has an invalid grayscale tRNS chunk")
                    return None
                transparent_gray = struct.unpack(">H", payload)[0]
                if transparent_gray > 255:
                    failures.append(f"{label} has an out-of-range grayscale tRNS sample")
                    return None
            elif color_type == 2:
                if length != 6:
                    failures.append(f"{label} has an invalid truecolor tRNS chunk")
                    return None
                transparent_rgb = struct.unpack(">HHH", payload)
                if any(sample > 255 for sample in transparent_rgb):
                    failures.append(f"{label} has an out-of-range truecolor tRNS sample")
                    return None
            else:
                failures.append(
                    f"{label} uses tRNS with a PNG color type that already carries alpha"
                )
                return None
        elif chunk_type in PNG_UNSUPPORTED_COLOR_CHUNKS:
            failures.append(
                f"{label} contains unsupported color-management PNG chunk {chunk_type.decode('ascii')}"
            )
            return None
        elif chunk_type == b"IDAT":
            if width is None or seen_iend or idat_closed:
                failures.append(f"{label} has an out-of-order IDAT chunk")
                return None
            seen_idat = True
            idat.extend(payload)
            if len(idat) > PNG_MAX_BYTES:
                failures.append(f"{label} has unbounded compressed PNG image data")
                return None
        elif chunk_type == b"IEND":
            if length != 0 or not seen_idat or seen_iend:
                failures.append(f"{label} has an invalid IEND chunk")
                return None
            seen_iend = True
            position = chunk_end
            if position != len(data):
                failures.append(f"{label} has trailing data after IEND")
                return None
            break
        else:
            if seen_idat:
                idat_closed = True
            if chunk_type[0] & 0x20 == 0:
                failures.append(
                    f"{label} contains unsupported critical PNG chunk {chunk_type.decode('ascii')}"
                )
                return None

        if seen_idat and chunk_type not in {b"IDAT", b"IEND"}:
            idat_closed = True
        position = chunk_end
        chunk_index += 1

    if width is None or height is None or color_type is None or bytes_per_pixel is None:
        failures.append(f"{label} is missing a valid IHDR")
        return None
    if not seen_idat:
        failures.append(f"{label} is missing IDAT image data")
        return None
    if not seen_iend:
        failures.append(f"{label} is missing IEND")
        return None

    row_bytes = width * bytes_per_pixel
    expected_raw_size = height * (row_bytes + 1)
    decompressor = zlib.decompressobj()
    try:
        # max_length is the hard memory bound. Never call flush() while untrusted input remains:
        # flush() has no output limit and can expand a small digest-valid artifact into gigabytes.
        raw = decompressor.decompress(bytes(idat), expected_raw_size + 1)
    except zlib.error as error:
        failures.append(f"{label} has invalid compressed PNG image data: {error}")
        return None
    if decompressor.unconsumed_tail:
        failures.append(f"{label} has overlong PNG image data")
        return None
    if (
        len(raw) != expected_raw_size
        or not decompressor.eof
        or decompressor.unused_data
    ):
        failures.append(f"{label} has incomplete or overlong PNG image data")
        return None

    rgba = bytearray(width * height * 4)
    previous = bytearray(row_bytes)
    raw_offset = 0
    rgba_offset = 0
    for _row in range(height):
        filter_type = raw[raw_offset]
        raw_offset += 1
        scanline = bytearray(raw[raw_offset : raw_offset + row_bytes])
        raw_offset += row_bytes

        for index in range(row_bytes):
            left = scanline[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
            up = previous[index]
            upper_left = previous[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
            if filter_type == 0:
                value = scanline[index]
            elif filter_type == 1:
                value = (scanline[index] + left) & 0xFF
            elif filter_type == 2:
                value = (scanline[index] + up) & 0xFF
            elif filter_type == 3:
                value = (scanline[index] + ((left + up) // 2)) & 0xFF
            elif filter_type == 4:
                value = (
                    scanline[index] + _paeth_predictor(left, up, upper_left)
                ) & 0xFF
            else:
                failures.append(f"{label} uses unsupported PNG filter type {filter_type}")
                return None
            scanline[index] = value

        for pixel_start in range(0, row_bytes, bytes_per_pixel):
            if color_type == 0:
                gray = scanline[pixel_start]
                alpha = 0 if transparent_gray == gray else 255
                pixel = (gray, gray, gray, alpha)
            elif color_type == 2:
                red = scanline[pixel_start]
                green = scanline[pixel_start + 1]
                blue = scanline[pixel_start + 2]
                alpha = 0 if transparent_rgb == (red, green, blue) else 255
                pixel = (red, green, blue, alpha)
            elif color_type == 4:
                gray = scanline[pixel_start]
                pixel = (gray, gray, gray, scanline[pixel_start + 1])
            else:
                pixel = (
                    scanline[pixel_start],
                    scanline[pixel_start + 1],
                    scanline[pixel_start + 2],
                    scanline[pixel_start + 3],
                )
            rgba[rgba_offset : rgba_offset + 4] = bytes(pixel)
            rgba_offset += 4
        previous = scanline

    return width, height, bytes(rgba)


def _png_declared_pixel_count(data: bytes) -> int | None:
    if len(data) < 33 or not data.startswith(PNG_SIGNATURE):
        return None
    if struct.unpack_from(">I", data, 8)[0] != 13 or data[12:16] != b"IHDR":
        return None
    width, height = struct.unpack_from(">II", data, 16)
    if width <= 0 or height <= 0:
        return None
    return width * height


def _validate_png_artifact(
    path: Path | None,
    expected_digest: object,
    *,
    label: str,
    failures: list[str],
    expected_width: int | None = None,
    expected_height: int | None = None,
    decode_byte_budget: list[int] | None = None,
    decode_pixel_budget: list[int] | None = None,
) -> tuple[int, int, bytes] | None:
    if path is None:
        return None
    if path.suffix.lower() != ".png":
        failures.append(f"{label} must be a PNG artifact")
        return None
    if not isinstance(expected_digest, str) or not SHA256_RE.fullmatch(expected_digest):
        failures.append(f"{label} must carry a lowercase SHA-256 digest")
        return None

    artifact_size = path.stat().st_size
    if decode_byte_budget is not None:
        if artifact_size > decode_byte_budget[0]:
            failures.append(
                f"{label} exceeds the aggregate PNG byte-work budget "
                f"{VISUAL_MAX_TOTAL_PNG_BYTES}"
            )
            return None
        decode_byte_budget[0] -= artifact_size

    data = _read_bounded_bytes(
        path,
        PNG_MAX_BYTES,
        label=label,
        failures=failures,
    )
    if data is None:
        return None
    if hashlib.sha256(data).hexdigest() != expected_digest:
        failures.append(f"{label} digest mismatch")
        return None

    declared_pixels = _png_declared_pixel_count(data)
    if (
        declared_pixels is not None
        and declared_pixels <= PNG_MAX_PIXELS
        and decode_pixel_budget is not None
    ):
        if declared_pixels > decode_pixel_budget[0]:
            failures.append(
                f"{label} exceeds the aggregate PNG decode-pixel budget "
                f"{VISUAL_MAX_TOTAL_DECODE_PIXELS}"
            )
            return None
        decode_pixel_budget[0] -= declared_pixels

    decoded = _decode_png_pixels(data, label=label, failures=failures)
    if decoded is None:
        return None
    width, height, _pixels = decoded
    if expected_width is not None and width != expected_width:
        failures.append(f"{label} PNG width does not match reviewed metadata")
        return None
    if expected_height is not None and height != expected_height:
        failures.append(f"{label} PNG height does not match reviewed metadata")
        return None
    return decoded


def _validate_structured_rendered_visual_content(
    decoded: tuple[int, int, bytes] | None,
    *,
    label: str,
    failures: list[str],
) -> None:
    if decoded is None:
        return
    width, height, pixels = decoded
    pixel_count = width * height
    if pixel_count <= 0:
        failures.append(f"{label} must contain rendered visual content")
        return

    rgba = memoryview(pixels)
    distinct_visible: set[int] = set()
    previous_row = [-1] * width
    transition_count = 0
    visible_count = 0
    min_luma = 255
    max_luma = 0

    for y in range(height):
        left_key = -1
        for x in range(width):
            offset = (y * width + x) * 4
            red = rgba[offset]
            green = rgba[offset + 1]
            blue = rgba[offset + 2]
            alpha = rgba[offset + 3]
            if alpha == 0:
                key = -1
            else:
                visible_count += 1
                key = (red << 24) | (green << 16) | (blue << 8) | alpha
                if len(distinct_visible) < 32:
                    distinct_visible.add(key)
                luma = (red * 299 + green * 587 + blue * 114) // 1000
                min_luma = min(min_luma, luma)
                max_luma = max(max_luma, luma)
            if x > 0 and key != left_key:
                transition_count += 1
            if y > 0 and key != previous_row[x]:
                transition_count += 1
            previous_row[x] = key
            left_key = key

    minimum_transitions = max(128, pixel_count // 500)
    if (
        visible_count == 0
        or len(distinct_visible) < 16
        or max_luma - min_luma < 24
        or transition_count < minimum_transitions
    ):
        failures.append(
            f"{label} must contain representative non-uniform rendered content; "
            "blank, near-uniform, or minimally perturbed captures are not qualification evidence"
        )


def _validate_digest_bound_json_artifact(
    root: Path,
    path_value: object,
    digest_value: object,
    *,
    label: str,
    failures: list[str],
) -> dict[str, object] | None:
    path = _bounded_regular_path(
        root,
        path_value,
        prefix="qualification/v010/",
        label=label,
        failures=failures,
    )
    if path is None:
        return None
    if not isinstance(digest_value, str) or not SHA256_RE.fullmatch(digest_value):
        failures.append(f"{label} must carry a lowercase SHA-256 digest")
        return None
    if _sha256(path) != digest_value:
        failures.append(f"{label} digest mismatch")
        return None
    return _load_json(path, label, failures)


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_runner_case_attestation(
    evidence_path: Path,
    *,
    case_name: str,
    manifest_run_id: object,
    source: dict[str, object],
    expected_observations: dict[str, object],
    label: str,
    failures: list[str],
) -> None:
    if evidence_path.suffix != ".json":
        failures.append(f"{label} must be a structured JSON runner attestation")
        return
    attestation = _load_json(evidence_path, label, failures)
    if not attestation:
        return
    if attestation.get("schema_version") != 1:
        failures.append(f"{label} schema_version must be 1")
    if attestation.get("attestation_type") != "linura-v010-qualification-case":
        failures.append(f"{label} attestation_type must be linura-v010-qualification-case")
    if attestation.get("case") != case_name or attestation.get("result") != "passed":
        failures.append(f"{label} must bind a passed {case_name} result")
    if attestation.get("run_id") != manifest_run_id:
        failures.append(f"{label} run_id must match the parent qualification run")
    if not _nonempty_string(attestation.get("captured_at_utc")):
        failures.append(f"{label} requires captured_at_utc")
    runner = attestation.get("runner")
    if not isinstance(runner, dict):
        failures.append(f"{label} missing runner provenance")
    else:
        if runner.get("id") != "qualification/v010/workstation-runner":
            failures.append(f"{label} runner.id must identify the v0.10 workstation runner")
        for key in ("commit_sha", "linurad_sha256", "shell_bridge_sha256"):
            if runner.get(key) != source.get(key):
                failures.append(f"{label} runner.{key} must match the parent source identity")
    observations = attestation.get("observations")
    if not isinstance(observations, list):
        failures.append(f"{label} observations must be an array")
        return
    by_name: dict[str, dict[str, object]] = {}
    for index, observation in enumerate(observations):
        if not isinstance(observation, dict):
            failures.append(f"{label} observation {index} must be an object")
            continue
        name = observation.get("name")
        if not isinstance(name, str) or name in by_name:
            failures.append(f"{label} observation {index} has invalid or duplicate name")
            continue
        by_name[name] = observation
    if set(by_name) != set(expected_observations):
        failures.append(f"{label} observation set does not prove the required case")
        return
    for name, expected_value in expected_observations.items():
        item = by_name[name]
        if item.get("result") != "passed":
            failures.append(f"{label} observation {name} must have result=passed")
        value = item.get("value")
        if isinstance(expected_value, bool):
            value_matches = type(value) is bool and value is expected_value
        else:
            value_matches = value == expected_value
        if not value_matches:
            failures.append(
                f"{label} observation {name} must carry the typed success value {expected_value!r}"
            )



def _validate_q11_bound_artifact(
    root: Path,
    binding: object,
    *,
    label: str,
    failures: list[str],
) -> Path | None:
    if not isinstance(binding, dict):
        failures.append(f"{label} binding must be an object")
        return None
    path = _bounded_regular_path(
        root,
        binding.get("path"),
        prefix="qualification/v010/interactive-workstation/",
        label=label,
        failures=failures,
    )
    digest = binding.get("sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        failures.append(f"{label} must carry a lowercase SHA-256 digest")
        return None
    if path is None:
        return None
    if _sha256(path) != digest:
        failures.append(f"{label} digest mismatch")
        return None
    return path


def _validate_q11_machine_environment(
    root: Path,
    manifest: dict[str, object],
    *,
    expected_profile_sha256: str | None,
    expected_package_manifest_sha256: str | None,
    expected_package_versions: dict[str, str] | None,
    expected_architecture: str | None,
    failures: list[str],
) -> tuple[str | None, str | None]:
    label = "interactive workstation machine environment"
    binding = manifest.get("machine_environment")
    environment_path = _validate_q11_bound_artifact(
        root,
        binding,
        label=label,
        failures=failures,
    )
    environment_sha256 = binding.get("sha256") if isinstance(binding, dict) else None
    if environment_path is None or not isinstance(environment_sha256, str):
        return None, None

    environment = _load_json(environment_path, label, failures)
    if not environment:
        return environment_sha256, None
    manifest_source = manifest.get("source")
    source_sha = (
        manifest_source.get("commit_sha")
        if isinstance(manifest_source, dict)
        else None
    )
    if environment.get("schema_version") != 1:
        failures.append(f"{label} schema_version must be 1")
    if environment.get("artifact_type") != "linura-v010-physical-workstation-environment":
        failures.append(f"{label} artifact_type must identify physical workstation provenance")
    if environment.get("source_commit_sha") != source_sha:
        failures.append(f"{label} source must match the interactive workstation source")
    if environment.get("run_id") != manifest.get("run_id"):
        failures.append(f"{label} run_id must match the parent qualification run")
    if environment.get("profile_id") != EXPECTED_PROFILE:
        failures.append(f"{label} must bind {EXPECTED_PROFILE}")
    if environment.get("machine_class") != EXPECTED_MACHINE_CLASS:
        failures.append(f"{label} machine_class must be workstation")
    if expected_profile_sha256 is None or environment.get("profile_sha256") != expected_profile_sha256:
        failures.append(f"{label} must bind the reviewed workstation profile digest")
    if (
        expected_package_manifest_sha256 is None
        or expected_package_versions is None
        or expected_architecture is None
    ):
        failures.append(f"{label} requires the frozen qualification substrate")
    elif environment.get("package_manifest_sha256") != expected_package_manifest_sha256:
        failures.append(f"{label} package manifest digest must match the frozen substrate")

    execution = environment.get("execution")
    boot_id: str | None = None
    virtualization: str | None = None
    if not isinstance(execution, dict):
        failures.append(f"{label} missing execution identity")
    else:
        if execution.get("scope") != "machine":
            failures.append(f"{label} execution.scope must be machine")
        if execution.get("kind") != "physical":
            failures.append(f"{label} execution.kind must be physical")
        if execution.get("architecture") != expected_architecture:
            failures.append(f"{label} architecture must match the frozen substrate")
        boot_value = execution.get("boot_id")
        if not isinstance(boot_value, str) or BOOT_ID_RE.fullmatch(boot_value) is None:
            failures.append(f"{label} boot_id must be a canonical UUID")
        else:
            boot_id = boot_value
        virtualization_value = execution.get("virtualization")
        if virtualization_value != "none":
            failures.append(f"{label} virtualization must be none")
        else:
            virtualization = virtualization_value

    package_inventory = _validate_q11_bound_artifact(
        root,
        environment.get("package_inventory"),
        label=f"{label} installed package inventory",
        failures=failures,
    )
    if package_inventory is not None and expected_package_versions is not None:
        observed_packages = _load_release_machine_package_inventory(
            package_inventory,
            label=f"{label} installed package inventory",
            failures=failures,
        )
        if observed_packages is not None and observed_packages != expected_package_versions:
            failures.append(
                f"{label} installed package inventory must exactly match the frozen package manifest"
            )

    probes = environment.get("probes")
    if not isinstance(probes, dict) or set(probes) != MACHINE_PROBE_NAMES:
        failures.append(f"{label} must retain exactly the required raw machine probes")
        probes = {}
    probe_paths: dict[str, Path] = {}
    for probe_name in sorted(MACHINE_PROBE_NAMES):
        probe_path = _validate_q11_bound_artifact(
            root,
            probes.get(probe_name),
            label=f"{label} machine probe {probe_name}",
            failures=failures,
        )
        if probe_path is not None:
            probe_paths[probe_name] = probe_path

    if "os_release" in probe_paths:
        try:
            os_release_lines = {
                line.strip()
                for line in probe_paths["os_release"].read_text(encoding="utf-8").splitlines()
                if line.strip()
            }
        except UnicodeError:
            failures.append(f"{label} os-release probe must be valid UTF-8")
        else:
            if "ID=arch" not in os_release_lines and 'ID="arch"' not in os_release_lines:
                failures.append(f"{label} os-release probe must independently identify Arch Linux")
    if "root_filesystem" in probe_paths:
        if probe_paths["root_filesystem"].read_text(encoding="utf-8").strip() != "btrfs":
            failures.append(f"{label} root-filesystem probe must independently identify btrfs")
    if "virtualization" in probe_paths:
        observed_virtualization = probe_paths["virtualization"].read_text(encoding="utf-8").strip()
        if observed_virtualization != "none":
            failures.append(f"{label} virtualization probe must independently prove no virtualization")
        if virtualization is not None and observed_virtualization != virtualization:
            failures.append(f"{label} virtualization probe must match the machine execution identity")
    if "boot_id" in probe_paths and boot_id is not None:
        if probe_paths["boot_id"].read_text(encoding="utf-8").strip() != boot_id:
            failures.append(f"{label} boot-id probe must match the machine execution identity")

    hardware_probe_path = _validate_q11_bound_artifact(
        root,
        environment.get("hardware_probe"),
        label=f"{label} physical hardware probe",
        failures=failures,
    )
    if hardware_probe_path is not None:
        hardware_probe = _load_json(
            hardware_probe_path,
            f"{label} physical hardware probe",
            failures,
        )
        if hardware_probe:
            if hardware_probe.get("schema_version") != 1:
                failures.append(f"{label} physical hardware probe schema_version must be 1")
            if hardware_probe.get("artifact_type") != "linura-v010-physical-hardware-probe":
                failures.append(f"{label} physical hardware probe artifact_type drifted")
            if hardware_probe.get("source_commit_sha") != source_sha:
                failures.append(f"{label} physical hardware probe source mismatch")
            if hardware_probe.get("run_id") != manifest.get("run_id"):
                failures.append(f"{label} physical hardware probe run_id mismatch")
            if hardware_probe.get("hardware") != manifest.get("hardware"):
                failures.append(f"{label} physical hardware probe must match manifest hardware identities")

    return environment_sha256, boot_id


def _validate_q11_case_execution(
    root: Path,
    attestation: dict[str, object],
    *,
    label: str,
    case_name: str,
    manifest: dict[str, object],
    environment_sha256: str | None,
    environment_boot_id: str | None,
    failures: list[str],
) -> None:
    execution = attestation.get("machine_execution")
    if not isinstance(execution, dict):
        failures.append(f"{label} missing machine_execution provenance")
        return
    if execution.get("scope") != "machine":
        failures.append(f"{label} machine_execution.scope must be machine")
    if environment_sha256 is None or execution.get("environment_sha256") != environment_sha256:
        failures.append(f"{label} machine_execution must bind the physical machine environment digest")
    if environment_boot_id is None or execution.get("boot_id") != environment_boot_id:
        failures.append(f"{label} machine_execution must bind the physical machine boot identity")
    controller = execution.get("controller")
    if controller not in PHYSICAL_EXTERNAL_CONTROLLERS:
        failures.append(f"{label} machine_execution controller must be an external physical-machine controller")
    expected_mechanism = EXPECTED_Q11_EXECUTION_MECHANISMS[case_name]
    if execution.get("mechanism") != expected_mechanism:
        failures.append(f"{label} machine_execution mechanism must be {expected_mechanism}")

    provenance_path = _validate_q11_bound_artifact(
        root,
        execution.get("provenance"),
        label=f"{label} machine execution provenance",
        failures=failures,
    )
    if provenance_path is None:
        return
    provenance = _load_json(
        provenance_path,
        f"{label} machine execution provenance",
        failures,
    )
    if not provenance:
        return
    if provenance.get("schema_version") != 1:
        failures.append(f"{label} machine execution provenance schema_version must be 1")
    if provenance.get("artifact_type") != "linura-v010-physical-workstation-case-provenance":
        failures.append(f"{label} machine execution provenance artifact_type drifted")
    manifest_source = manifest.get("source")
    source_sha = (
        manifest_source.get("commit_sha")
        if isinstance(manifest_source, dict)
        else None
    )
    if provenance.get("source_commit_sha") != source_sha:
        failures.append(f"{label} machine execution provenance source mismatch")
    if provenance.get("run_id") != manifest.get("run_id") or provenance.get("case") != case_name:
        failures.append(f"{label} machine execution provenance must bind the parent run and case")
    if provenance.get("environment_sha256") != environment_sha256:
        failures.append(f"{label} machine execution provenance environment binding mismatch")
    if provenance.get("boot_id") != environment_boot_id:
        failures.append(f"{label} machine execution provenance boot identity mismatch")
    if provenance.get("scope") != "machine":
        failures.append(f"{label} machine execution provenance scope must be machine")
    if provenance.get("controller") != controller:
        failures.append(f"{label} machine execution provenance controller mismatch")
    if provenance.get("mechanism") != expected_mechanism:
        failures.append(f"{label} machine execution provenance mechanism mismatch")
    if provenance.get("external_controller") is not True:
        failures.append(f"{label} machine execution provenance must prove external control")
    if provenance.get("process_local_mock") is not False:
        failures.append(f"{label} machine execution provenance process_local_mock must be false")

    event_log_path = _validate_q11_bound_artifact(
        root,
        provenance.get("event_log"),
        label=f"{label} machine execution event log",
        failures=failures,
    )
    if event_log_path is not None:
        try:
            event_lines = set(event_log_path.read_text(encoding="utf-8").splitlines())
        except UnicodeError:
            failures.append(f"{label} machine execution event log must be valid UTF-8")
        else:
            required_lines = {
                f"case={case_name}",
                f"controller={controller}",
                f"mechanism={expected_mechanism}",
                f"environment_sha256={environment_sha256}",
                f"source_commit_sha={source_sha}",
                f"run_id={manifest.get('run_id')}",
                "scope=machine",
                f"boot_id={environment_boot_id}",
            }
            if not required_lines.issubset(event_lines):
                failures.append(
                    f"{label} machine execution event log must bind the case, controller, "
                    "mechanism, environment, source, run, scope, and boot identity"
                )


def _validate_interactive_workstation_evidence(
    root: Path,
    interactive: dict[str, object],
    failures: list[str],
    *,
    expected_source_sha: str | None,
    expected_profile_sha256: str | None,
    expected_package_manifest_sha256: str | None,
    expected_provider_versions: dict[str, str] | None,
    expected_architecture: str | None,
    expected_linurad_sha256: str | None,
    expected_shell_bridge_sha256: str | None,
    require_binary_binding: bool,
) -> None:
    manifest = _validate_digest_bound_json_artifact(
        root,
        interactive.get("evidence_manifest"),
        interactive.get("evidence_manifest_sha256"),
        label="interactive workstation evidence manifest",
        failures=failures,
    )
    if manifest is None:
        return
    if manifest.get("schema_version") != 1:
        failures.append("interactive workstation evidence schema_version must be 1")
    if manifest.get("milestone") != "v0.10.0":
        failures.append("interactive workstation evidence must bind milestone v0.10.0")
    if manifest.get("profile_id") != EXPECTED_PROFILE:
        failures.append("interactive workstation evidence must bind arch-hyprland-v1")
    if manifest.get("machine_class") != EXPECTED_MACHINE_CLASS:
        failures.append("interactive workstation evidence machine_class must be workstation")
    if manifest.get("evidence_type") != "maintainer-physical-workstation":
        failures.append("interactive workstation evidence_type must be maintainer-physical-workstation")
    if manifest.get("evidence_tier") != "maintainer_hardware":
        failures.append("interactive workstation evidence_tier must be maintainer_hardware")
    if manifest.get("physical_hardware") is not True:
        failures.append("interactive workstation evidence must attest physical_hardware=true")
    if manifest.get("result") != "passed":
        failures.append("interactive workstation evidence result must be passed")
    if not _nonempty_string(manifest.get("run_id")):
        failures.append("interactive workstation evidence requires a non-empty run_id")
    if not _nonempty_string(manifest.get("captured_at_utc")):
        failures.append("interactive workstation evidence requires captured_at_utc")
    if expected_package_manifest_sha256 is None or expected_provider_versions is None:
        failures.append(
            "interactive workstation evidence requires the frozen qualification package manifest"
        )
    elif manifest.get("package_manifest_sha256") != expected_package_manifest_sha256:
        failures.append(
            "interactive workstation evidence package_manifest_sha256 must match the frozen qualification package manifest"
        )

    source = manifest.get("source")
    source_valid = isinstance(source, dict)
    if not source_valid:
        failures.append("interactive workstation evidence missing source identities")
        source = {}
    else:
        commit_sha = source.get("commit_sha")
        if not isinstance(commit_sha, str) or not GIT_SHA_RE.fullmatch(commit_sha):
            failures.append("interactive workstation source.commit_sha must be a lowercase 40-hex Git SHA")
        elif expected_source_sha is None:
            failures.append("interactive workstation evidence requires an expected release source SHA")
        elif commit_sha != expected_source_sha:
            failures.append("interactive workstation source.commit_sha does not match the expected release source")
        expected_binary_digests = {
            "linurad_sha256": expected_linurad_sha256,
            "shell_bridge_sha256": expected_shell_bridge_sha256,
        }
        for key, expected_digest in expected_binary_digests.items():
            value = source.get(key)
            if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
                failures.append(f"interactive workstation source.{key} must be a lowercase SHA-256 digest")
                continue
            if expected_digest is not None and value != expected_digest:
                failures.append(
                    f"interactive workstation source.{key} does not match independently qualified runtime artifact"
                )
            elif require_binary_binding and expected_digest is None:
                failures.append(
                    f"interactive workstation source.{key} requires an independently qualified expected digest"
                )

    display_by_connector: dict[str, dict[str, object]] = {}
    hardware = manifest.get("hardware")
    if not isinstance(hardware, dict):
        failures.append("interactive workstation evidence missing hardware identities")
    else:
        cpu = hardware.get("cpu")
        if not isinstance(cpu, dict) or any(not _nonempty_string(cpu.get(key)) for key in ("architecture", "vendor", "model")):
            failures.append("interactive workstation CPU identity must include architecture, vendor and model")
        else:
            if expected_architecture is None:
                failures.append(
                    "interactive workstation CPU architecture requires a frozen qualification substrate"
                )
            elif cpu.get("architecture") != expected_architecture:
                failures.append(
                    "interactive workstation CPU architecture must match the frozen qualification substrate"
                )
        gpu = hardware.get("gpu")
        if not isinstance(gpu, dict) or any(not _nonempty_string(gpu.get(key)) for key in ("vendor_id", "device_id", "driver", "driver_version")):
            failures.append("interactive workstation GPU identity must include vendor/device/driver/version")
        displays = hardware.get("displays")
        if not isinstance(displays, list) or not displays or len(displays) > 16:
            failures.append("interactive workstation evidence requires 1..16 identified displays")
        else:
            for index, display in enumerate(displays):
                if not isinstance(display, dict):
                    failures.append(f"interactive workstation display {index} must be an object")
                    continue
                connector = display.get("connector")
                if not _nonempty_string(connector):
                    failures.append(f"interactive workstation display {index} requires connector identity")
                elif connector in display_by_connector:
                    failures.append(
                        f"interactive workstation display {index} duplicates connector {connector}"
                    )
                else:
                    display_by_connector[connector] = display
                for key in ("width", "height", "refresh_millihz"):
                    value = display.get(key)
                    if type(value) is not int or value <= 0:
                        failures.append(f"interactive workstation display {index}.{key} must be a positive integer")
                scale = display.get("scale")
                if not isinstance(scale, (int, float)) or isinstance(scale, bool) or scale <= 0:
                    failures.append(f"interactive workstation display {index}.scale must be positive")

    session = manifest.get("session")
    if not isinstance(session, dict):
        failures.append("interactive workstation evidence missing session identities")
    else:
        if session.get("protocol") != "wayland":
            failures.append("interactive workstation session.protocol must be wayland")
        if session.get("compositor") != "hyprland":
            failures.append("interactive workstation session.compositor must be hyprland")
        for key in (
            "compositor_version",
            "quickshell_version",
            "qt_version",
            "kernel_version",
            "systemd_version",
        ):
            if not _nonempty_string(session.get(key)):
                failures.append(f"interactive workstation session.{key} must be non-empty")
        for key, package_name in EXPECTED_Q11_SESSION_PACKAGE_VERSIONS.items():
            value = session.get(key)
            if not _nonempty_string(value):
                continue
            if expected_provider_versions is None:
                failures.append(
                    f"interactive workstation session.{key} requires a frozen package manifest"
                )
                continue
            expected_version = expected_provider_versions.get(package_name)
            if expected_version is None:
                failures.append(
                    f"frozen package manifest is missing session package {package_name}"
                )
            elif value != expected_version:
                failures.append(
                    f"interactive workstation session.{key} must match frozen {package_name} version {expected_version}"
                )

    providers = manifest.get("providers")
    required_provider_ids = EXPECTED_INTERACTIVE_WORKSTATION["required_provider_ids"]
    if not isinstance(providers, dict) or set(providers) != set(required_provider_ids):
        failures.append("interactive workstation provider identities must match the required provider set")
    elif expected_provider_versions is None:
        failures.append("interactive workstation provider versions require a frozen package manifest")
    else:
        for provider_id in required_provider_ids:
            expected_version = expected_provider_versions.get(provider_id)
            if expected_version is None:
                failures.append(
                    f"frozen package manifest is missing required provider package {provider_id}"
                )
            elif providers.get(provider_id) != expected_version:
                failures.append(
                    f"interactive workstation provider {provider_id} must match frozen package version {expected_version}"
                )

    environment_sha256, environment_boot_id = _validate_q11_machine_environment(
        root,
        manifest,
        expected_profile_sha256=expected_profile_sha256,
        expected_package_manifest_sha256=expected_package_manifest_sha256,
        expected_package_versions=expected_provider_versions,
        expected_architecture=expected_architecture,
        failures=failures,
    )

    cases = manifest.get("cases")
    required_cases = EXPECTED_INTERACTIVE_WORKSTATION["required_cases"]
    if not isinstance(cases, list) or len(cases) != len(required_cases):
        failures.append("interactive workstation evidence must contain exactly the required Q11 cases")
        return
    by_name: dict[str, dict[str, object]] = {}
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            failures.append(f"interactive workstation case {index} must be an object")
            continue
        name = case.get("name")
        if not isinstance(name, str) or name in by_name:
            failures.append(f"interactive workstation case {index} has invalid or duplicate name")
            continue
        by_name[name] = case
    if set(by_name) != set(required_cases):
        failures.append("interactive workstation Q11 case set drifted from the qualification contract")
        return
    for name in required_cases:
        case = by_name[name]
        if case.get("result") != "passed":
            failures.append(f"interactive workstation case {name} must have result=passed")
        evidence_path = _bounded_regular_path(
            root,
            case.get("evidence"),
            prefix="qualification/v010/interactive-workstation/",
            label=f"interactive workstation case evidence {name}",
            failures=failures,
        )
        digest = case.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            failures.append(f"interactive workstation case {name} requires a lowercase SHA-256 digest")
        elif evidence_path is not None and _sha256(evidence_path) != digest:
            failures.append(f"interactive workstation case {name} evidence digest mismatch")
        elif evidence_path is not None and source_valid:
            expected_values: dict[str, object] = {
                observation_name: True
                for observation_name in EXPECTED_Q11_CASE_OBSERVATIONS[name]
            }
            if expected_provider_versions is not None:
                for provider_id, version in expected_provider_versions.items():
                    observation_name = f"{provider_id}-version"
                    if observation_name in expected_values:
                        expected_values[observation_name] = version
            _validate_runner_case_attestation(
                evidence_path,
                case_name=name,
                manifest_run_id=manifest.get("run_id"),
                source=source,
                expected_observations=expected_values,
                label=f"interactive workstation case evidence {name}",
                failures=failures,
            )
            attestation = _load_json(
                evidence_path,
                f"interactive workstation case evidence {name}",
                failures,
            )
            if attestation:
                _validate_q11_case_execution(
                    root,
                    attestation,
                    label=f"interactive workstation case evidence {name}",
                    case_name=name,
                    manifest=manifest,
                    environment_sha256=environment_sha256,
                    environment_boot_id=environment_boot_id,
                    failures=failures,
                )
                if name == "accessibility-and-visual":
                    visual_binding = attestation.get("visual_artifact")
                    visual_path = _validate_q11_bound_artifact(
                        root,
                        visual_binding,
                        label="interactive workstation physical accessibility visual artifact",
                        failures=failures,
                    )
                    if isinstance(visual_binding, dict):
                        if visual_binding.get("environment_sha256") != environment_sha256:
                            failures.append(
                                "interactive workstation physical accessibility visual artifact must bind the physical machine environment"
                            )
                        machine_execution = attestation.get("machine_execution")
                        provenance_binding = (
                            machine_execution.get("provenance")
                            if isinstance(machine_execution, dict)
                            else None
                        )
                        provenance_sha256 = (
                            provenance_binding.get("sha256")
                            if isinstance(provenance_binding, dict)
                            else None
                        )
                        if (
                            not isinstance(provenance_sha256, str)
                            or not SHA256_RE.fullmatch(provenance_sha256)
                            or visual_binding.get("execution_provenance_sha256") != provenance_sha256
                        ):
                            failures.append(
                                "interactive workstation physical accessibility visual artifact must bind the case execution provenance"
                            )
                        capture = visual_binding.get("capture")
                        expected_visual_width: int | None = None
                        expected_visual_height: int | None = None
                        if not isinstance(capture, dict):
                            failures.append(
                                "interactive workstation physical accessibility visual artifact capture metadata must be an object"
                            )
                        else:
                            if capture.get("kind") != "full-output":
                                failures.append(
                                    "interactive workstation physical accessibility visual artifact capture.kind must be full-output"
                                )
                            if capture.get("coordinate_space") != "physical-pixels":
                                failures.append(
                                    "interactive workstation physical accessibility visual artifact capture.coordinate_space must be physical-pixels"
                                )
                            connector = capture.get("connector")
                            if not _nonempty_string(connector):
                                failures.append(
                                    "interactive workstation physical accessibility visual artifact capture.connector must identify a physical display"
                                )
                            else:
                                display = display_by_connector.get(connector)
                                if display is None:
                                    failures.append(
                                        "interactive workstation physical accessibility visual artifact capture.connector must match an identified physical display"
                                    )
                                else:
                                    display_width = display.get("width")
                                    display_height = display.get("height")
                                    display_scale = display.get("scale")
                                    if type(display_width) is int and display_width > 0:
                                        expected_visual_width = display_width
                                    if type(display_height) is int and display_height > 0:
                                        expected_visual_height = display_height

                                    capture_width = capture.get("pixel_width")
                                    if type(capture_width) is not int or capture_width <= 0:
                                        failures.append(
                                            "interactive workstation physical accessibility visual artifact capture.pixel_width must be a positive integer"
                                        )
                                    elif capture_width != display_width:
                                        failures.append(
                                            "interactive workstation physical accessibility visual artifact capture.pixel_width must match the identified physical display"
                                        )

                                    capture_height = capture.get("pixel_height")
                                    if type(capture_height) is not int or capture_height <= 0:
                                        failures.append(
                                            "interactive workstation physical accessibility visual artifact capture.pixel_height must be a positive integer"
                                        )
                                    elif capture_height != display_height:
                                        failures.append(
                                            "interactive workstation physical accessibility visual artifact capture.pixel_height must match the identified physical display"
                                        )

                                    capture_scale = capture.get("scale")
                                    if (
                                        not isinstance(capture_scale, (int, float))
                                        or isinstance(capture_scale, bool)
                                        or capture_scale <= 0
                                    ):
                                        failures.append(
                                            "interactive workstation physical accessibility visual artifact capture.scale must be positive"
                                        )
                                    elif capture_scale != display_scale:
                                        failures.append(
                                            "interactive workstation physical accessibility visual artifact capture.scale must match the identified physical display"
                                        )

                        decoded_visual = _validate_png_artifact(
                            visual_path,
                            visual_binding.get("sha256"),
                            label="interactive workstation physical accessibility visual artifact",
                            failures=failures,
                            expected_width=expected_visual_width,
                            expected_height=expected_visual_height,
                        )
                        _validate_structured_rendered_visual_content(
                            decoded_visual,
                            label="interactive workstation physical accessibility visual artifact",
                            failures=failures,
                        )


def _load_release_machine_package_inventory(
    path: Path,
    *,
    label: str,
    failures: list[str],
) -> dict[str, str] | None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeError:
        failures.append(f"{label} must be valid UTF-8")
        return None
    packages: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        if not line:
            failures.append(f"{label} line {line_number} must not be empty")
            continue
        fields = line.split("\t")
        if len(fields) != 2:
            failures.append(f"{label} line {line_number} must contain name and exact version")
            continue
        name, version = fields
        if not PACKAGE_NAME_RE.fullmatch(name) or not _valid_exact_version(version):
            failures.append(f"{label} line {line_number} has an invalid package identity")
            continue
        if name in packages:
            failures.append(f"{label} contains duplicate package {name}")
            continue
        packages[name] = version
    if not packages:
        failures.append(f"{label} must contain installed package identities")
        return None
    if list(packages) != sorted(packages):
        failures.append(f"{label} must use canonical package-name order")
    return packages


def _validate_sha256_bound_release_artifact(
    root: Path,
    binding: object,
    *,
    label: str,
    failures: list[str],
) -> Path | None:
    if not isinstance(binding, dict):
        failures.append(f"{label} binding must be an object")
        return None
    path = _bounded_regular_path(
        root,
        binding.get("path"),
        prefix="qualification/v010/release-matrix/",
        label=label,
        failures=failures,
    )
    digest = binding.get("sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        failures.append(f"{label} must carry a lowercase SHA-256 digest")
        return None
    if path is None:
        return None
    if _sha256(path) != digest:
        failures.append(f"{label} digest mismatch")
        return None
    return path


def _validate_release_machine_environment(
    root: Path,
    manifest: dict[str, object],
    *,
    label: str,
    source_sha: object,
    run_id: object,
    expected_profile_sha256: str | None,
    expected_package_manifest_sha256: str | None,
    expected_package_versions: dict[str, str] | None,
    expected_architecture: str | None,
    expected_runtime_digests: dict[str, str] | None,
    failures: list[str],
) -> tuple[str | None, str | None, str | None]:
    binding = manifest.get("machine_environment")
    if not isinstance(binding, dict):
        failures.append(f"{label} evidence requires machine_environment binding")
        return None, None, None
    evidence_path = _validate_sha256_bound_release_artifact(
        root,
        {"path": binding.get("evidence"), "sha256": binding.get("sha256")},
        label=f"{label} machine environment",
        failures=failures,
    )
    environment_sha256 = binding.get("sha256")
    if evidence_path is None or not isinstance(environment_sha256, str):
        return None, None, None
    environment = _load_json(evidence_path, f"{label} machine environment", failures)
    if not environment:
        return environment_sha256, None, None

    if environment.get("schema_version") != 1:
        failures.append(f"{label} machine environment schema_version must be 1")
    if environment.get("artifact_type") != "linura-v010-machine-environment":
        failures.append(f"{label} machine environment artifact_type drifted")
    if environment.get("source_commit_sha") != source_sha:
        failures.append(f"{label} machine environment source must match the qualification source")
    if environment.get("run_id") != run_id:
        failures.append(f"{label} machine environment run_id must match the parent qualification run")
    if environment.get("profile_id") != EXPECTED_PROFILE:
        failures.append(f"{label} machine environment must bind {EXPECTED_PROFILE}")
    if environment.get("machine_class") != EXPECTED_MACHINE_CLASS:
        failures.append(f"{label} machine environment machine_class must be workstation")
    if expected_profile_sha256 is None or environment.get("profile_sha256") != expected_profile_sha256:
        failures.append(f"{label} machine environment must bind the reviewed workstation profile digest")
    if (
        expected_package_manifest_sha256 is None
        or expected_package_versions is None
        or expected_architecture is None
    ):
        failures.append(f"{label} machine environment requires a frozen qualification package manifest")
    elif environment.get("package_manifest_sha256") != expected_package_manifest_sha256:
        failures.append(f"{label} machine environment package manifest digest must match the frozen substrate")

    runtime = environment.get("runtime")
    if expected_runtime_digests is None:
        failures.append(f"{label} machine environment requires qualified Linura runtime digests")
    elif not isinstance(runtime, dict):
        failures.append(f"{label} machine environment missing runtime digest binding")
    elif runtime != expected_runtime_digests:
        failures.append(f"{label} machine environment runtime digests must match the qualification manifest")

    execution = environment.get("execution")
    boot_id: str | None = None
    environment_kind: str | None = None
    virtualization: str | None = None
    if not isinstance(execution, dict):
        failures.append(f"{label} machine environment missing execution identity")
    else:
        if execution.get("scope") != "machine":
            failures.append(f"{label} machine environment execution.scope must be machine")
        environment_kind = execution.get("kind") if isinstance(execution.get("kind"), str) else None
        if environment_kind not in {"physical", "virtual-machine"}:
            failures.append(f"{label} machine environment execution.kind must be physical or virtual-machine")
        if execution.get("architecture") != expected_architecture:
            failures.append(f"{label} machine environment architecture must match the frozen substrate")
        boot_value = execution.get("boot_id")
        if not isinstance(boot_value, str) or BOOT_ID_RE.fullmatch(boot_value) is None:
            failures.append(f"{label} machine environment boot_id must be a canonical UUID")
        else:
            boot_id = boot_value
        virtualization_value = execution.get("virtualization")
        if not _nonempty_string(virtualization_value):
            failures.append(f"{label} machine environment virtualization identity must be non-empty")
        else:
            virtualization = str(virtualization_value)
            if environment_kind == "physical" and virtualization != "none":
                failures.append(f"{label} physical machine environment must report virtualization=none")
            if environment_kind == "virtual-machine" and virtualization == "none":
                failures.append(f"{label} virtual-machine environment must identify its virtualization")

    storage = environment.get("storage")
    if not isinstance(storage, dict):
        failures.append(f"{label} machine environment missing storage identity")
    else:
        if storage.get("root_filesystem") != "btrfs":
            failures.append(f"{label} machine environment root filesystem must be btrfs")
        if storage.get("snapshot_provider") != "snapper":
            failures.append(f"{label} machine environment snapshot provider must be snapper")

    package_inventory_path = _validate_sha256_bound_release_artifact(
        root,
        environment.get("package_inventory"),
        label=f"{label} installed package inventory",
        failures=failures,
    )
    if package_inventory_path is not None and expected_package_versions is not None:
        observed_packages = _load_release_machine_package_inventory(
            package_inventory_path,
            label=f"{label} installed package inventory",
            failures=failures,
        )
        if observed_packages is not None and observed_packages != expected_package_versions:
            failures.append(
                f"{label} installed package inventory must exactly match the frozen package manifest"
            )

    probes = environment.get("probes")
    if not isinstance(probes, dict) or set(probes) != MACHINE_PROBE_NAMES:
        failures.append(
            f"{label} machine environment must retain exactly the required raw machine probes"
        )
        return environment_sha256, boot_id, environment_kind

    probe_paths: dict[str, Path] = {}
    for probe_name in sorted(MACHINE_PROBE_NAMES):
        probe_path = _validate_sha256_bound_release_artifact(
            root,
            probes.get(probe_name),
            label=f"{label} machine probe {probe_name}",
            failures=failures,
        )
        if probe_path is not None:
            probe_paths[probe_name] = probe_path

    if "os_release" in probe_paths:
        try:
            os_release_lines = {
                line.strip()
                for line in probe_paths["os_release"].read_text(encoding="utf-8").splitlines()
                if line.strip()
            }
        except UnicodeError:
            failures.append(f"{label} os-release probe must be valid UTF-8")
        else:
            if "ID=arch" not in os_release_lines and 'ID="arch"' not in os_release_lines:
                failures.append(f"{label} os-release probe must independently identify Arch Linux")
    if "root_filesystem" in probe_paths:
        if probe_paths["root_filesystem"].read_text(encoding="utf-8").strip() != "btrfs":
            failures.append(f"{label} root-filesystem probe must independently identify btrfs")
    if "virtualization" in probe_paths and virtualization is not None:
        if probe_paths["virtualization"].read_text(encoding="utf-8").strip() != virtualization:
            failures.append(f"{label} virtualization probe must match the machine environment identity")
    if "boot_id" in probe_paths and boot_id is not None:
        if probe_paths["boot_id"].read_text(encoding="utf-8").strip() != boot_id:
            failures.append(f"{label} boot-id probe must match the machine environment identity")

    return environment_sha256, boot_id, environment_kind


def _validate_machine_case_execution(
    root: Path,
    attestation: dict[str, object],
    *,
    label: str,
    case_name: str,
    source_sha: object,
    run_id: object,
    environment_sha256: str | None,
    environment_boot_id: str | None,
    environment_kind: str | None,
    expected_mechanism: str,
    failures: list[str],
) -> None:
    execution = attestation.get("machine_execution")
    if not isinstance(execution, dict):
        failures.append(f"{label} missing machine_execution provenance")
        return
    if execution.get("scope") != "machine":
        failures.append(f"{label} machine_execution.scope must be machine")
    if environment_sha256 is None or execution.get("environment_sha256") != environment_sha256:
        failures.append(f"{label} machine_execution must bind the parent machine environment digest")

    requires_boot_transition = expected_mechanism in BOOT_TRANSITION_MECHANISMS
    pre_boot_id: str | None = None
    post_boot_id: str | None = None
    if requires_boot_transition:
        pre_value = execution.get("pre_boot_id")
        post_value = execution.get("post_boot_id")
        if not isinstance(pre_value, str) or BOOT_ID_RE.fullmatch(pre_value) is None:
            failures.append(f"{label} machine_execution pre_boot_id must be a canonical UUID")
        else:
            pre_boot_id = pre_value
            if environment_boot_id is None or pre_boot_id != environment_boot_id:
                failures.append(
                    f"{label} machine_execution pre_boot_id must bind the parent machine boot identity"
                )
        if not isinstance(post_value, str) or BOOT_ID_RE.fullmatch(post_value) is None:
            failures.append(f"{label} machine_execution post_boot_id must be a canonical UUID")
        else:
            post_boot_id = post_value
            if pre_boot_id is not None and post_boot_id == pre_boot_id:
                failures.append(
                    f"{label} machine_execution pre_boot_id and post_boot_id must differ"
                )
        if "boot_id" in execution:
            failures.append(
                f"{label} rebooting machine_execution must use pre_boot_id/post_boot_id instead of boot_id"
            )
    elif environment_boot_id is None or execution.get("boot_id") != environment_boot_id:
        failures.append(f"{label} machine_execution must bind the parent machine boot identity")

    controller = execution.get("controller")
    allowed_controllers = (
        PHYSICAL_EXTERNAL_CONTROLLERS
        if environment_kind == "physical"
        else VM_EXTERNAL_CONTROLLERS
    )
    if controller not in allowed_controllers:
        failures.append(f"{label} machine_execution controller must be externally controlled")
    mechanism = execution.get("mechanism")
    if mechanism != expected_mechanism:
        failures.append(
            f"{label} machine_execution mechanism must be {expected_mechanism}"
        )

    provenance_path = _validate_sha256_bound_release_artifact(
        root,
        execution.get("provenance"),
        label=f"{label} machine execution provenance",
        failures=failures,
    )
    if provenance_path is None:
        return
    provenance = _load_json(provenance_path, f"{label} machine execution provenance", failures)
    if not provenance:
        return
    if provenance.get("schema_version") != 1:
        failures.append(f"{label} machine execution provenance schema_version must be 1")
    if provenance.get("artifact_type") != "linura-v010-machine-case-provenance":
        failures.append(f"{label} machine execution provenance artifact_type drifted")
    if provenance.get("source_commit_sha") != source_sha:
        failures.append(f"{label} machine execution provenance source must match the qualification source")
    if provenance.get("run_id") != run_id or provenance.get("case") != case_name:
        failures.append(f"{label} machine execution provenance must bind the parent run and case")
    if provenance.get("environment_sha256") != environment_sha256:
        failures.append(f"{label} machine execution provenance environment binding mismatch")
    if requires_boot_transition:
        if provenance.get("pre_boot_id") != pre_boot_id:
            failures.append(f"{label} machine execution provenance pre_boot_id mismatch")
        if provenance.get("post_boot_id") != post_boot_id:
            failures.append(f"{label} machine execution provenance post_boot_id mismatch")
        if "boot_id" in provenance:
            failures.append(
                f"{label} rebooting machine execution provenance must use pre_boot_id/post_boot_id"
            )
        post_boot_probe_path = _validate_sha256_bound_release_artifact(
            root,
            provenance.get("post_boot_probe"),
            label=f"{label} recovered boot probe",
            failures=failures,
        )
        if post_boot_probe_path is not None and post_boot_id is not None:
            try:
                observed_post_boot_id = post_boot_probe_path.read_text(encoding="utf-8").strip()
            except UnicodeError:
                failures.append(f"{label} recovered boot probe must be valid UTF-8")
            else:
                if observed_post_boot_id != post_boot_id:
                    failures.append(
                        f"{label} recovered boot probe must match post_boot_id"
                    )
    elif provenance.get("boot_id") != environment_boot_id:
        failures.append(f"{label} machine execution provenance boot identity mismatch")
    if provenance.get("scope") != "machine":
        failures.append(f"{label} machine execution provenance scope must be machine")
    if provenance.get("controller") != controller:
        failures.append(f"{label} machine execution provenance controller mismatch")
    if provenance.get("mechanism") != expected_mechanism:
        failures.append(f"{label} machine execution provenance mechanism mismatch")
    if provenance.get("external_controller") is not True:
        failures.append(f"{label} machine execution provenance must prove external control")
    if provenance.get("process_local_mock") is not False:
        failures.append(f"{label} machine execution provenance process_local_mock must be false")

    event_log_path = _validate_sha256_bound_release_artifact(
        root,
        provenance.get("event_log"),
        label=f"{label} machine execution event log",
        failures=failures,
    )
    if event_log_path is not None:
        try:
            event_lines = set(event_log_path.read_text(encoding="utf-8").splitlines())
        except UnicodeError:
            failures.append(f"{label} machine execution event log must be valid UTF-8")
        else:
            required_event_lines = {
                f"case={case_name}",
                f"controller={controller}",
                f"mechanism={expected_mechanism}",
                f"environment_sha256={environment_sha256}",
                f"source_commit_sha={source_sha}",
                f"run_id={run_id}",
                "scope=machine",
            }
            if requires_boot_transition and pre_boot_id is not None and post_boot_id is not None:
                required_event_lines.update(
                    {
                        f"pre_boot_id={pre_boot_id}",
                        f"post_boot_id={post_boot_id}",
                    }
                )
            elif environment_boot_id is not None:
                required_event_lines.add(f"boot_id={environment_boot_id}")
            if not required_event_lines.issubset(event_lines):
                failures.append(
                    f"{label} machine execution event log must bind the case, controller, "
                    "mechanism, environment, source, run, scope, and boot identity"
                )


def _validate_release_matrix_evidence(
    root: Path,
    section: dict[str, object],
    expected: dict[str, object],
    *,
    label: str,
    expected_source_sha: str | None,
    failures: list[str],
    expected_profile_sha256: str | None = None,
    expected_package_manifest_sha256: str | None = None,
    expected_package_versions: dict[str, str] | None = None,
    expected_architecture: str | None = None,
    expected_linurad_sha256: str | None = None,
    expected_shell_bridge_sha256: str | None = None,
    require_binary_binding: bool = False,
) -> None:
    manifest = _validate_digest_bound_json_artifact(
        root,
        section.get("evidence_manifest"),
        section.get("evidence_manifest_sha256"),
        label=f"{label} evidence manifest",
        failures=failures,
    )
    if manifest is None:
        return
    if manifest.get("schema_version") != 1:
        failures.append(f"{label} evidence schema_version must be 1")
    if manifest.get("milestone") != "v0.10.0":
        failures.append(f"{label} evidence must bind milestone v0.10.0")
    if manifest.get("evidence_type") != expected["evidence_type"]:
        failures.append(f"{label} evidence_type drifted")
    if manifest.get("profile_id") != EXPECTED_PROFILE:
        failures.append(f"{label} evidence must bind {EXPECTED_PROFILE}")
    if manifest.get("machine_class") != EXPECTED_MACHINE_CLASS:
        failures.append(f"{label} evidence machine_class must be workstation")
    if manifest.get("result") != "passed":
        failures.append(f"{label} evidence result must be passed")
    manifest_run_id = manifest.get("run_id")
    if not _nonempty_string(manifest_run_id):
        failures.append(f"{label} evidence requires run_id")
    if not _nonempty_string(manifest.get("captured_at_utc")):
        failures.append(f"{label} evidence requires captured_at_utc")
    source_sha = manifest.get("source_commit_sha")
    if not isinstance(source_sha, str) or not GIT_SHA_RE.fullmatch(source_sha):
        failures.append(f"{label} source_commit_sha must be a lowercase 40-hex Git SHA")
    elif expected_source_sha is None:
        failures.append(f"{label} evidence requires an expected release source SHA")
    elif source_sha != expected_source_sha:
        failures.append(f"{label} source_commit_sha does not match the expected release source")

    environment_sha256: str | None = None
    environment_boot_id: str | None = None
    environment_kind: str | None = None
    runtime_digests: dict[str, str] | None = None
    if expected["evidence_type"] in {
        "exact-source-q12-update-recovery",
        "exact-source-q13-workstation-security",
    }:
        runtime = manifest.get("runtime")
        if not isinstance(runtime, dict):
            failures.append(f"{label} evidence requires qualified Linura runtime digests")
        else:
            if runtime.get("source_commit_sha") != source_sha:
                failures.append(f"{label} runtime source must match the qualification source")
            runtime_digests = {}
            for key, expected_digest in (
                ("linurad_sha256", expected_linurad_sha256),
                ("shell_bridge_sha256", expected_shell_bridge_sha256),
            ):
                value = runtime.get(key)
                if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
                    failures.append(f"{label} runtime.{key} must be a lowercase SHA-256 digest")
                    runtime_digests = None
                    continue
                if expected_digest is not None and value != expected_digest:
                    failures.append(
                        f"{label} runtime.{key} does not match independently qualified runtime artifact"
                    )
                elif require_binary_binding and expected_digest is None:
                    failures.append(
                        f"{label} runtime.{key} requires an independently qualified expected digest"
                    )
                if runtime_digests is not None:
                    runtime_digests[key] = value
        environment_sha256, environment_boot_id, environment_kind = _validate_release_machine_environment(
            root,
            manifest,
            label=label,
            source_sha=source_sha,
            run_id=manifest_run_id,
            expected_profile_sha256=expected_profile_sha256,
            expected_package_manifest_sha256=expected_package_manifest_sha256,
            expected_package_versions=expected_package_versions,
            expected_architecture=expected_architecture,
            expected_runtime_digests=runtime_digests,
            failures=failures,
        )

    cases = manifest.get("cases")
    required_cases = expected["required_cases"]
    if not isinstance(cases, list) or len(cases) != len(required_cases):
        failures.append(f"{label} evidence must contain exactly the required cases")
        return
    by_name: dict[str, dict[str, object]] = {}
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            failures.append(f"{label} case {index} must be an object")
            continue
        name = case.get("name")
        if not isinstance(name, str) or name in by_name:
            failures.append(f"{label} case {index} has invalid or duplicate name")
            continue
        by_name[name] = case
    if set(by_name) != set(required_cases):
        failures.append(f"{label} case set drifted from the qualification contract")
        return
    if expected["evidence_type"] == "exact-source-q10-experience-authority":
        case_observations = EXPECTED_Q10_CASE_OBSERVATIONS
        case_mechanisms = {}
    elif expected["evidence_type"] == "exact-source-q12-update-recovery":
        case_observations = EXPECTED_Q12_CASE_OBSERVATIONS
        case_mechanisms = EXPECTED_Q12_EXECUTION_MECHANISMS
    else:
        case_observations = EXPECTED_Q13_CASE_OBSERVATIONS
        case_mechanisms = EXPECTED_Q13_EXECUTION_MECHANISMS
    for name in required_cases:
        case = by_name[name]
        if case.get("result") != "passed":
            failures.append(f"{label} case {name} must have result=passed")
        evidence_path = _bounded_regular_path(
            root,
            case.get("evidence"),
            prefix="qualification/v010/",
            label=f"{label} case evidence {name}",
            failures=failures,
        )
        digest = case.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            failures.append(f"{label} case {name} requires a lowercase SHA-256 digest")
            continue
        if evidence_path is None or _sha256(evidence_path) != digest:
            if evidence_path is not None:
                failures.append(f"{label} case {name} evidence digest mismatch")
            continue
        if evidence_path.suffix != ".json":
            failures.append(f"{label} case {name} must use a structured JSON runner attestation")
            continue
        attestation = _load_json(evidence_path, f"{label} case evidence {name}", failures)
        if not attestation:
            continue
        if attestation.get("schema_version") != 1:
            failures.append(f"{label} case {name} attestation schema_version must be 1")
        if attestation.get("attestation_type") != "linura-v010-release-qualification-case":
            failures.append(f"{label} case {name} attestation_type drifted")
        if attestation.get("case") != name or attestation.get("result") != "passed":
            failures.append(f"{label} case {name} attestation must bind a passed result")
        if attestation.get("source_commit_sha") != source_sha:
            failures.append(f"{label} case {name} attestation source must match the manifest")
        if attestation.get("run_id") != manifest_run_id:
            failures.append(f"{label} case {name} run_id must match the parent qualification run")
        if not _nonempty_string(attestation.get("captured_at_utc")):
            failures.append(f"{label} case {name} requires captured_at_utc")
        runner = attestation.get("runner")
        if not isinstance(runner, dict):
            failures.append(f"{label} case {name} missing runner provenance")
        else:
            if runner.get("id") != "qualification/v010/release-matrix-runner":
                failures.append(f"{label} case {name} runner.id must identify the v0.10 release-matrix runner")
            if not _nonempty_string(runner.get("version")):
                failures.append(f"{label} case {name} runner.version must be non-empty")
            if runner.get("commit_sha") != source_sha:
                failures.append(f"{label} case {name} runner.commit_sha must match the parent source identity")
            if name in case_mechanisms and runtime_digests is not None:
                for key, digest in runtime_digests.items():
                    if runner.get(key) != digest:
                        failures.append(
                            f"{label} case {name} runner.{key} must match the qualified runtime digest"
                        )

        if name in case_mechanisms:
            _validate_machine_case_execution(
                root,
                attestation,
                label=f"{label} case {name}",
                case_name=name,
                source_sha=source_sha,
                run_id=manifest_run_id,
                environment_sha256=environment_sha256,
                environment_boot_id=environment_boot_id,
                environment_kind=environment_kind,
                expected_mechanism=case_mechanisms[name],
                failures=failures,
            )

        observations = attestation.get("observations")
        if not isinstance(observations, list):
            failures.append(f"{label} case {name} observations must be an array")
            continue
        by_observation: dict[str, dict[str, object]] = {}
        for index, observation in enumerate(observations):
            if not isinstance(observation, dict):
                failures.append(f"{label} case {name} observation {index} must be an object")
                continue
            observation_name = observation.get("name")
            if not isinstance(observation_name, str) or observation_name in by_observation:
                failures.append(f"{label} case {name} observation {index} has invalid or duplicate name")
                continue
            by_observation[observation_name] = observation
        expected_observations = case_observations[name]
        if set(by_observation) != set(expected_observations):
            failures.append(f"{label} case {name} observation set does not prove the required case")
            continue
        for observation_name in expected_observations:
            observation = by_observation[observation_name]
            if observation.get("result") != "passed":
                failures.append(f"{label} case {name} observation {observation_name} must pass")
            if observation.get("value") is not True:
                failures.append(
                    f"{label} case {name} observation {observation_name} must carry boolean true"
                )

def _matches_canonical_visual_diff(
    baseline: tuple[int, int, bytes],
    capture: tuple[int, int, bytes],
    diff: tuple[int, int, bytes],
) -> bool:
    if baseline[:2] != capture[:2] or baseline[:2] != diff[:2]:
        return False
    baseline_pixels = baseline[2]
    capture_pixels = capture[2]
    diff_pixels = diff[2]
    if len(baseline_pixels) != len(capture_pixels) or len(baseline_pixels) != len(diff_pixels):
        return False
    for offset in range(0, len(baseline_pixels), 4):
        delta = max(
            abs(baseline_pixels[offset + channel] - capture_pixels[offset + channel])
            for channel in range(4)
        )
        if diff_pixels[offset : offset + 4] != bytes((delta, delta, delta, 255)):
            return False
    return True


def _visual_failure_binding_sha256(
    baseline_id: str,
    baseline_sha256: str,
    failed_capture_sha256: str,
    diff_sha256: str,
) -> str:
    payload = (
        "linura-v010-visual-failure-v1\n"
        f"{baseline_id}\n"
        f"{baseline_sha256}\n"
        f"{failed_capture_sha256}\n"
        f"{diff_sha256}\n"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _validate_experience_evidence(
    root: Path,
    experience: dict[str, object],
    failures: list[str],
    *,
    expected_source_sha: str | None,
) -> None:
    baseline_path = _bounded_regular_path(
        root,
        experience.get("visual_baseline_manifest"),
        prefix="visual/baselines/",
        label="visual baseline manifest",
        failures=failures,
    )
    baseline_digest = experience.get("visual_baseline_manifest_sha256")
    if not isinstance(baseline_digest, str) or not SHA256_RE.fullmatch(baseline_digest):
        failures.append("visual_baseline_manifest_sha256 must be a lowercase SHA-256 digest")
        return
    if baseline_path is None:
        return
    if _sha256(baseline_path) != baseline_digest:
        failures.append("v0.10 visual baseline manifest digest mismatch")
        return

    baseline_manifest = _load_json(baseline_path, "v0.10 visual baseline manifest", failures)
    if baseline_manifest.get("schema_version") != 1:
        failures.append("v0.10 visual baseline manifest schema_version must be 1")
    baselines = baseline_manifest.get("baselines") if baseline_manifest else None
    if not isinstance(baselines, list) or not baselines:
        failures.append("v0.10 experience readiness requires reviewed visual baselines")
        return
    if len(baselines) > VISUAL_MAX_BASELINES:
        failures.append(
            f"v0.10 visual baseline manifest exceeds bounded baseline count {VISUAL_MAX_BASELINES}"
        )
        return

    png_byte_budget = [VISUAL_MAX_TOTAL_PNG_BYTES]
    png_pixel_budget = [VISUAL_MAX_TOTAL_DECODE_PIXELS]
    baseline_ids: set[str] = set()
    baseline_metadata: dict[str, tuple[int, int, float, str]] = {}
    # Keep digest-sized normalized pixel identities so ordinary comparisons never decode
    # the reviewed baseline twice. Full RGBA is retained only for the current decode.
    baseline_artifacts: dict[str, tuple[Path, str]] = {}
    baseline_pixel_digests: dict[str, str] = {}
    baseline_digests: dict[str, str] = {}
    observed_scales: set[float] = set()
    observed_resolutions: set[str] = set()
    observed_surfaces: set[str] = set()

    for index, item in enumerate(baselines):
        if not isinstance(item, dict):
            failures.append(f"visual baseline entry {index} must be an object")
            continue
        baseline_id = item.get("id")
        surface = item.get("surface")
        width = item.get("width")
        height = item.get("height")
        scale = item.get("scale")
        if not isinstance(baseline_id, str) or not baseline_id or baseline_id in baseline_ids:
            failures.append(f"visual baseline entry {index} has invalid or duplicate id")
            continue
        baseline_ids.add(baseline_id)
        if not isinstance(surface, str) or surface not in EXPECTED_ALLOWED_VISUAL_SURFACES:
            failures.append(f"visual baseline {baseline_id} has unsupported surface")
            continue
        observed_surfaces.add(surface)
        if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
            failures.append(f"visual baseline {baseline_id} has invalid width")
            continue
        if not isinstance(height, int) or isinstance(height, bool) or height <= 0:
            failures.append(f"visual baseline {baseline_id} has invalid height")
            continue
        if not isinstance(scale, (int, float)) or isinstance(scale, bool) or scale <= 0:
            failures.append(f"visual baseline {baseline_id} has invalid scale")
            continue
        scale_value = float(scale)
        observed_scales.add(scale_value)
        observed_resolutions.add(f"{width}x{height}")
        baseline_metadata[baseline_id] = (width, height, scale_value, surface)
        artifact_path = _bounded_regular_path(
            root,
            item.get("baseline"),
            prefix="visual/baselines/",
            label=f"visual baseline artifact {baseline_id}",
            failures=failures,
        )
        baseline_digest = item.get("sha256")
        baseline_image = _validate_png_artifact(
            artifact_path,
            baseline_digest,
            label=f"visual baseline artifact {baseline_id}",
            failures=failures,
            expected_width=width,
            expected_height=height,
            decode_byte_budget=png_byte_budget,
            decode_pixel_budget=png_pixel_budget,
        )
        _validate_structured_rendered_visual_content(
            baseline_image,
            label=f"visual baseline artifact {baseline_id}",
            failures=failures,
        )
        if (
            baseline_image is not None
            and artifact_path is not None
            and isinstance(baseline_digest, str)
        ):
            baseline_artifacts[baseline_id] = (artifact_path, baseline_digest)
            baseline_pixel_digests[baseline_id] = hashlib.sha256(
                baseline_image[2]
            ).hexdigest()
            baseline_digests[baseline_id] = baseline_digest

    required_visual_surfaces = experience.get("required_visual_surfaces")
    if required_visual_surfaces != EXPECTED_REQUIRED_VISUAL_SURFACES:
        failures.append("experience required_visual_surfaces drifted from the qualified UI surface set")
    else:
        missing_surfaces = sorted(set(required_visual_surfaces) - observed_surfaces)
        if missing_surfaces:
            failures.append(
                "visual baseline coverage missing required surfaces: " + ", ".join(missing_surfaces)
            )

    required_scales = experience.get("representative_visual_scales")
    if not isinstance(required_scales, list) or any(
        not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0
        for value in required_scales
    ):
        failures.append("experience representative_visual_scales must contain positive numbers")
    else:
        missing_scales = sorted(
            float(value) for value in required_scales if float(value) not in observed_scales
        )
        if missing_scales:
            failures.append(f"visual baseline coverage missing representative scales: {missing_scales}")

    required_resolutions = experience.get("representative_visual_resolutions")
    if not isinstance(required_resolutions, list) or any(
        not isinstance(value, str) or not value for value in required_resolutions
    ):
        failures.append("experience representative_visual_resolutions must contain non-empty strings")
    else:
        missing_resolutions = sorted(set(required_resolutions) - observed_resolutions)
        if missing_resolutions:
            failures.append(
                "visual baseline coverage missing representative resolutions: "
                + ", ".join(missing_resolutions)
            )

    evidence_path = _bounded_regular_path(
        root,
        experience.get("experience_evidence_manifest"),
        prefix="qualification/v010/",
        label="v0.10 experience evidence manifest",
        failures=failures,
    )
    evidence_digest = experience.get("experience_evidence_manifest_sha256")
    if not isinstance(evidence_digest, str) or not SHA256_RE.fullmatch(evidence_digest):
        failures.append("experience_evidence_manifest_sha256 must be a lowercase SHA-256 digest")
        return
    if evidence_path is None:
        return
    if _sha256(evidence_path) != evidence_digest:
        failures.append("v0.10 experience evidence manifest digest mismatch")
        return

    evidence = _load_json(evidence_path, "v0.10 experience evidence manifest", failures)
    if evidence.get("schema_version") != 1:
        failures.append("v0.10 experience evidence manifest schema_version must be 1")
    source_sha = evidence.get("source_commit_sha")
    if not isinstance(source_sha, str) or not GIT_SHA_RE.fullmatch(source_sha):
        failures.append("v0.10 experience evidence source_commit_sha must be a lowercase 40-hex Git SHA")
    elif expected_source_sha is None:
        failures.append("v0.10 experience evidence requires an expected release source SHA")
    elif source_sha != expected_source_sha:
        failures.append(
            "v0.10 experience evidence source_commit_sha does not match the expected release source"
        )
    manifest_run_id = evidence.get("run_id")
    if not _nonempty_string(manifest_run_id):
        failures.append("v0.10 experience evidence requires run_id")
    if not _nonempty_string(evidence.get("captured_at_utc")):
        failures.append("v0.10 experience evidence requires captured_at_utc")

    _validate_release_matrix_evidence(
        root,
        {
            "evidence_manifest": experience.get("authority_evidence_manifest"),
            "evidence_manifest_sha256": experience.get("authority_evidence_manifest_sha256"),
        },
        EXPECTED_Q10_AUTHORITY_QUALIFICATION,
        label="Q10 experience authority/adversarial",
        expected_source_sha=expected_source_sha,
        failures=failures,
    )

    comparisons = evidence.get("visual_comparisons")
    covered_baselines: set[str] = set()
    if not isinstance(comparisons, list) or not comparisons:
        failures.append("v0.10 experience evidence requires visual_comparisons")
    else:
        if len(comparisons) > VISUAL_MAX_BASELINES:
            failures.append(
                f"v0.10 experience evidence exceeds bounded visual comparison count {VISUAL_MAX_BASELINES}"
            )
            comparisons = comparisons[:VISUAL_MAX_BASELINES]
        for index, item in enumerate(comparisons):
            if not isinstance(item, dict):
                failures.append(f"visual comparison {index} must be an object")
                continue
            baseline_id = item.get("baseline_id")
            metadata = baseline_metadata.get(str(baseline_id))
            if baseline_id not in baseline_ids or metadata is None:
                failures.append(f"visual comparison {index} references unknown or invalid baseline")
                continue
            baseline_key = str(baseline_id)
            if baseline_key in covered_baselines:
                failures.append(f"visual comparison {index} duplicates baseline {baseline_key}")
                continue
            covered_baselines.add(baseline_key)
            if item.get("status") != "pass" or item.get("reviewed") is not True:
                failures.append(f"visual comparison for {baseline_id} must be reviewed and passing")
            capture_path = _bounded_regular_path(
                root,
                item.get("capture"),
                prefix="qualification/v010/",
                label=f"visual capture for {baseline_id}",
                failures=failures,
            )
            capture_image = _validate_png_artifact(
                capture_path,
                item.get("capture_sha256"),
                label=f"visual capture for {baseline_id}",
                failures=failures,
                expected_width=metadata[0],
                expected_height=metadata[1],
                decode_byte_budget=png_byte_budget,
                decode_pixel_budget=png_pixel_budget,
            )
            _validate_structured_rendered_visual_content(
                capture_image,
                label=f"visual capture for {baseline_id}",
                failures=failures,
            )
            capture_attestation = _validate_digest_bound_json_artifact(
                root,
                item.get("capture_attestation"),
                item.get("capture_attestation_sha256"),
                label=f"visual capture attestation for {baseline_id}",
                failures=failures,
            )
            if capture_attestation is not None:
                if capture_attestation.get("schema_version") != 1:
                    failures.append(f"visual capture attestation for {baseline_id} schema_version must be 1")
                if capture_attestation.get("artifact_type") != "linura-v010-visual-capture-attestation":
                    failures.append(f"visual capture attestation for {baseline_id} artifact_type drifted")
                if capture_attestation.get("source_commit_sha") != source_sha:
                    failures.append(f"visual capture attestation for {baseline_id} source must match the experience run")
                if capture_attestation.get("run_id") != manifest_run_id:
                    failures.append(f"visual capture attestation for {baseline_id} run_id must match the experience run")
                if capture_attestation.get("platform") != EXPECTED_PROFILE:
                    failures.append(f"visual capture attestation for {baseline_id} platform must be {EXPECTED_PROFILE}")
                if capture_attestation.get("baseline_id") != baseline_id:
                    failures.append(f"visual capture attestation for {baseline_id} baseline binding mismatch")
                if capture_attestation.get("capture_sha256") != item.get("capture_sha256"):
                    failures.append(f"visual capture attestation for {baseline_id} capture digest mismatch")
                capture_runner = capture_attestation.get("runner")
                if not isinstance(capture_runner, dict):
                    failures.append(f"visual capture attestation for {baseline_id} missing runner provenance")
                else:
                    if capture_runner.get("id") != "qualification/v010/visual-capture-runner":
                        failures.append(f"visual capture attestation for {baseline_id} runner.id drifted")
                    if not _nonempty_string(capture_runner.get("version")):
                        failures.append(f"visual capture attestation for {baseline_id} runner.version must be non-empty")
                    if capture_runner.get("source_commit_sha") != source_sha:
                        failures.append(f"visual capture attestation for {baseline_id} runner source mismatch")
                    if capture_runner.get("run_id") != manifest_run_id:
                        failures.append(f"visual capture attestation for {baseline_id} runner run_id mismatch")
            baseline_pixel_digest = baseline_pixel_digests.get(str(baseline_id))
            if (
                baseline_pixel_digest is not None
                and capture_image is not None
                and hashlib.sha256(capture_image[2]).hexdigest() != baseline_pixel_digest
            ):
                failures.append(
                    f"visual comparison for {baseline_id} does not match baseline pixels"
                )
    missing_comparisons = sorted(baseline_ids - covered_baselines)
    if missing_comparisons:
        failures.append(
            "visual comparison evidence missing baselines: " + ", ".join(missing_comparisons)
        )

    failure_diffs = evidence.get("retained_failure_diffs")
    if not isinstance(failure_diffs, list) or not failure_diffs:
        failures.append("v0.10 experience evidence requires at least one retained reviewed failure diff")
    else:
        if len(failure_diffs) > VISUAL_MAX_FAILURE_DIFFS:
            failures.append(
                f"v0.10 experience evidence exceeds bounded retained failure diff count {VISUAL_MAX_FAILURE_DIFFS}"
            )
            failure_diffs = failure_diffs[:VISUAL_MAX_FAILURE_DIFFS]
        for index, item in enumerate(failure_diffs):
            label = f"retained failure diff {index}"
            if not isinstance(item, dict) or item.get("reviewed") is not True:
                failures.append(f"{label} must be a reviewed object")
                continue
            baseline_id = item.get("baseline_id")
            if not isinstance(baseline_id, str) or baseline_id not in baseline_metadata:
                failures.append(f"{label} must reference a valid baseline_id")
                continue
            metadata = baseline_metadata[baseline_id]
            baseline_digest = baseline_digests.get(baseline_id)
            if baseline_digest is None or item.get("baseline_sha256") != baseline_digest:
                failures.append(f"{label} baseline digest does not match the reviewed baseline")
                continue
            if item.get("status") != "fail":
                failures.append(f"{label} must record status=fail")

            failed_capture_path = _bounded_regular_path(
                root,
                item.get("failed_capture"),
                prefix="qualification/v010/",
                label=f"{label} failed capture",
                failures=failures,
            )
            failed_capture_digest = item.get("failed_capture_sha256")
            failed_capture_image = _validate_png_artifact(
                failed_capture_path,
                failed_capture_digest,
                label=f"{label} failed capture",
                failures=failures,
                expected_width=metadata[0],
                expected_height=metadata[1],
                decode_byte_budget=png_byte_budget,
                decode_pixel_budget=png_pixel_budget,
            )
            baseline_artifact = baseline_artifacts.get(baseline_id)
            baseline_image = (
                _validate_png_artifact(
                    baseline_artifact[0],
                    baseline_artifact[1],
                    label=f"visual baseline artifact {baseline_id}",
                    failures=failures,
                    expected_width=metadata[0],
                    expected_height=metadata[1],
                    decode_byte_budget=png_byte_budget,
                    decode_pixel_budget=png_pixel_budget,
                )
                if baseline_artifact is not None
                else None
            )
            if (
                baseline_image is not None
                and failed_capture_image is not None
                and failed_capture_image == baseline_image
            ):
                failures.append(f"{label} does not represent an actual failed pixel comparison")

            diff_path = _bounded_regular_path(
                root,
                item.get("diff"),
                prefix="qualification/v010/",
                label=label,
                failures=failures,
            )
            diff_digest = item.get("diff_sha256")
            diff_image = _validate_png_artifact(
                diff_path,
                diff_digest,
                label=label,
                failures=failures,
                expected_width=metadata[0],
                expected_height=metadata[1],
                decode_byte_budget=png_byte_budget,
                decode_pixel_budget=png_pixel_budget,
            )
            if (
                baseline_image is not None
                and failed_capture_image is not None
                and diff_image is not None
                and not _matches_canonical_visual_diff(
                    baseline_image, failed_capture_image, diff_image
                )
            ):
                failures.append(
                    f"{label} pixels do not match the canonical failed-pair diff"
                )
            if (
                isinstance(failed_capture_digest, str)
                and SHA256_RE.fullmatch(failed_capture_digest)
                and isinstance(diff_digest, str)
                and SHA256_RE.fullmatch(diff_digest)
            ):
                expected_binding = _visual_failure_binding_sha256(
                    baseline_id,
                    baseline_digest,
                    failed_capture_digest,
                    diff_digest,
                )
                if item.get("binding_sha256") != expected_binding:
                    failures.append(
                        f"{label} binding_sha256 does not bind the baseline/capture/diff digests"
                    )

    interactions = evidence.get("interaction_accessibility")
    required_surfaces = experience.get("required_accessibility_surfaces")
    if not isinstance(required_surfaces, list) or any(
        not isinstance(value, str) or not value for value in required_surfaces
    ):
        failures.append("experience required_accessibility_surfaces must contain non-empty strings")
        return
    records: dict[str, dict[str, object]] = {}
    if not isinstance(interactions, list):
        failures.append("v0.10 experience evidence requires interaction_accessibility reports")
        interactions = []
    for index, item in enumerate(interactions):
        if not isinstance(item, dict) or not isinstance(item.get("surface"), str):
            failures.append(f"interaction/accessibility evidence {index} must identify a surface")
            continue
        surface = item["surface"]
        if surface in records:
            failures.append(f"interaction/accessibility evidence has duplicate surface: {surface}")
            continue
        records[surface] = item

    required_checks = (
        "keyboard",
        "pointer",
        "focus_navigation",
        "screen_reader",
        "reduced_motion",
        "display_scaling",
        "offline_error",
        "reconnect",
    )
    for surface in required_surfaces:
        record = records.get(surface)
        if record is None:
            failures.append(f"interaction/accessibility evidence missing surface: {surface}")
            continue
        report = _validate_digest_bound_json_artifact(
            root,
            record.get("report"),
            record.get("report_sha256"),
            label=f"interaction/accessibility report {surface}",
            failures=failures,
        )
        if report is None:
            continue
        if report.get("schema_version") != 1:
            failures.append(f"interaction/accessibility report {surface} schema_version must be 1")
        if report.get("artifact_type") != "linura-v010-interaction-accessibility":
            failures.append(f"interaction/accessibility report {surface} has invalid artifact_type")
        if report.get("surface") != surface:
            failures.append(f"interaction/accessibility report {surface} surface binding mismatch")
        if report.get("result") != "pass":
            failures.append(f"interaction/accessibility report {surface} must record result=pass")
        if report.get("source_commit_sha") != source_sha:
            failures.append(
                f"interaction/accessibility report {surface} source must match the experience evidence manifest"
            )
        if report.get("run_id") != manifest_run_id:
            failures.append(
                f"interaction/accessibility report {surface} run_id must match the parent experience run"
            )

        runner = report.get("runner")
        if not isinstance(runner, dict):
            failures.append(f"interaction/accessibility report {surface} missing runner identity")
        else:
            for key in ("name", "version", "run_id", "platform"):
                value = runner.get(key)
                if not isinstance(value, str) or not value.strip():
                    failures.append(
                        f"interaction/accessibility report {surface} runner.{key} must be non-empty"
                    )
            if runner.get("platform") != EXPECTED_PROFILE:
                failures.append(
                    f"interaction/accessibility report {surface} runner.platform must be {EXPECTED_PROFILE}"
                )
            if runner.get("run_id") != manifest_run_id:
                failures.append(
                    f"interaction/accessibility report {surface} runner.run_id must match the parent experience run"
                )
            if runner.get("commit_sha") != source_sha:
                failures.append(
                    f"interaction/accessibility report {surface} runner.commit_sha must match the qualified source"
                )

        checks = report.get("checks")
        if not isinstance(checks, dict):
            failures.append(f"interaction/accessibility report {surface} missing checks")
            continue
        for key in required_checks:
            if checks.get(key) != "pass":
                failures.append(
                    f"interaction/accessibility report {surface} checks.{key} must be pass"
                )

        if surface in EXPECTED_Q10_OVERLAY_INPUT_REGION_SURFACES:
            if report.get("input_region") != EXPECTED_Q10_OVERLAY_INPUT_REGION:
                failures.append(
                    f"interaction/accessibility report {surface} must bind pass-through "
                    "noninteractive regions and bounded interactive controls"
                )

        expected_workflow_observations = EXPECTED_Q10_SURFACE_WORKFLOW_OBSERVATIONS.get(surface)
        workflow_observations = report.get("workflow_observations")
        if expected_workflow_observations is None:
            failures.append(
                f"interaction/accessibility report {surface} has no qualified workflow contract"
            )
        elif not isinstance(workflow_observations, dict):
            failures.append(
                f"interaction/accessibility report {surface} missing workflow_observations"
            )
        elif set(workflow_observations) != set(expected_workflow_observations):
            failures.append(
                f"interaction/accessibility report {surface} must contain exactly the required workflow observations"
            )
        else:
            for observation in expected_workflow_observations:
                if workflow_observations.get(observation) != "pass":
                    failures.append(
                        f"interaction/accessibility report {surface} workflow_observations.{observation} must be pass"
                    )


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
) -> dict[str, str] | None:
    if not path.is_file() or path.is_symlink():
        failures.append(f"frozen package manifest missing or not a regular file: {path}")
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeError:
        failures.append("frozen package manifest must be valid UTF-8")
        return None

    expected_headers = [
        f"# {EXPECTED_MANIFEST_FORMAT}",
        f"# snapshot_date={snapshot_date}",
        f"# architecture={architecture}",
    ]
    if lines[:3] != expected_headers:
        failures.append("frozen package manifest identity headers do not match the qualification substrate")
        return None

    records = lines[3:]
    if not records:
        failures.append("frozen package manifest must contain versioned package records")
        return None
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
        return None
    if parsed != sorted(parsed, key=lambda item: (item[1], item[0], item[2], item[3])):
        failures.append("frozen package manifest records must use canonical package-name order")
    missing = sorted(required_packages - seen_names)
    if missing:
        failures.append(
            "frozen package manifest is missing required versioned packages: " + ", ".join(missing)
        )
    return {name: version for _, name, version, _ in parsed}

def validate(
    root: Path,
    *,
    expected_source_sha: str | None = None,
    expected_linurad_sha256: str | None = None,
    expected_shell_bridge_sha256: str | None = None,
    require_binary_binding: bool = False,
    post_release_closed: bool = False,
) -> list[str]:
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
    if contract.get("product_scope_decision") != EXPECTED_PRODUCT_SCOPE_ADR:
        failures.append("v0.10 product_scope_decision must bind ADR 0033")
    elif not (root / EXPECTED_PRODUCT_SCOPE_ADR).is_file():
        failures.append("v0.10 product-scope ADR 0033 is missing")
    if contract.get("slice_contract") != EXPECTED_SLICE_CONTRACT:
        failures.append("v0.10 slice_contract must bind the canonical workstation slice ledger")
    elif not (root / EXPECTED_SLICE_CONTRACT).is_file():
        failures.append("v0.10 workstation slice ledger is missing")
    experience = contract.get("experience")
    if not isinstance(experience, dict):
        failures.append("v0.10 qualification contract missing experience")
    else:
        static_experience = dict(experience)
        static_experience.pop("experience_evidence_ready", None)
        static_experience.pop("experience_evidence_manifest_sha256", None)
        static_experience.pop("authority_evidence_manifest_sha256", None)
        static_experience.pop("visual_baseline_manifest_sha256", None)
        if static_experience != EXPECTED_EXPERIENCE:
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
        if milestone.get("desktop_shell_scope") != "complete-first-party-workstation-shell":
            failures.append("roadmap v0.10 desktop_shell_scope must remain complete-first-party-workstation-shell")
        if milestone.get("experience_scope") != "complete-daily-usable-workstation":
            failures.append("roadmap v0.10 experience_scope must remain complete-daily-usable-workstation")
        if milestone.get("installation_scope") != "bounded-qualified-install-plus-adoption":
            failures.append("roadmap v0.10 installation_scope must remain bounded-qualified-install-plus-adoption")
        if milestone.get("daily_use_target") is not True:
            failures.append("roadmap v0.10 daily_use_target must remain true")
        if milestone.get("product_scope_adr") != EXPECTED_PRODUCT_SCOPE_ADR:
            failures.append("roadmap v0.10 product_scope_adr must bind ADR 0033")
        if milestone.get("slice_contract") != EXPECTED_SLICE_CONTRACT:
            failures.append("roadmap v0.10 slice_contract must bind the workstation slice ledger")
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
        else:
            profile_bytes = profile_path.read_bytes()
            if post_release_closed:
                try:
                    profile_text = profile_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    failures.append("arch-hyprland-v1 must remain UTF-8 after support promotion")
                else:
                    promoted_marker = 'status = "release-qualified"'
                    if profile_text.count(promoted_marker) != 1:
                        failures.append(
                            "release-qualified arch-hyprland-v1 must contain one canonical promoted status field"
                        )
                    else:
                        profile_bytes = profile_text.replace(
                            promoted_marker,
                            'status = "development"',
                            1,
                        ).encode("utf-8")
            if hashlib.sha256(profile_bytes).hexdigest() != expected_digest:
                failures.append(
                    "arch-hyprland-v1 content does not match the qualification-bound profile_sha256"
                )
        if profile.get("schema_version") != 1 or profile.get("id") != EXPECTED_PROFILE:
            failures.append("target PlatformProfile schema/id mismatch")
        expected_profile_status = "release-qualified" if post_release_closed else "development"
        if profile.get("status") != expected_profile_status:
            if post_release_closed:
                failures.append(
                    "arch-hyprland-v1 must be release-qualified after protected post-release closure"
                )
            else:
                failures.append(
                    "arch-hyprland-v1 must remain development before protected post-release closure"
                )
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
        elif post_release_closed:
            if EXPECTED_PROFILE not in profiles:
                failures.append(
                    "arch-hyprland-v1 must be present in workstation release_qualified_profiles after protected post-release closure"
                )
        elif EXPECTED_PROFILE in profiles:
            failures.append(
                "arch-hyprland-v1 cannot be release-qualified before immutable v0.10 publication and protected post-release closure"
            )

    qualification_document = contract.get("qualification_document")
    if qualification_document != "docs/qualification/v0.10.0.md":
        failures.append("qualification_document must remain docs/qualification/v0.10.0.md")
    elif not (root / qualification_document).is_file():
        failures.append("v0.10 qualification document is missing")

    frozen_package_manifest_digest: str | None = None
    frozen_package_versions: dict[str, str] | None = None
    frozen_substrate_architecture: str | None = None
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
        if state == "frozen" and _nonempty_string(architecture):
            frozen_substrate_architecture = architecture

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
                    manifest_digest_matches = False
                    if isinstance(manifest_digest, str) and SHA256_RE.fullmatch(manifest_digest):
                        if manifest_path.is_file() and not manifest_path.is_symlink():
                            if _sha256(manifest_path) != manifest_digest:
                                failures.append("frozen package manifest digest mismatch")
                            else:
                                manifest_digest_matches = True
                    if isinstance(snapshot_date, str) and isinstance(architecture, str):
                        parsed_versions = _validate_package_manifest(
                            manifest_path,
                            snapshot_date,
                            architecture,
                            required_packages,
                            failures,
                        )
                        if manifest_digest_matches and parsed_versions is not None:
                            frozen_package_manifest_digest = manifest_digest
                            frozen_package_versions = parsed_versions

    if isinstance(experience, dict):
        experience_ready = experience.get("experience_evidence_ready")
        if not isinstance(experience_ready, bool):
            failures.append("experience.experience_evidence_ready must be boolean")
        if experience_ready is True:
            slice_contract = _load_toml(
                root / EXPECTED_SLICE_CONTRACT,
                "v0.10 workstation slice contract",
                failures,
            )
            slice_items = slice_contract.get("slice") if slice_contract else None
            status_by_id = {
                item.get("id"): item.get("status")
                for item in slice_items
                if isinstance(item, dict)
            } if isinstance(slice_items, list) else {}
            required_product_slices = [f"S{index:02d}" for index in range(1, 29)]
            incomplete_product_slices = [
                slice_id
                for slice_id in required_product_slices
                if status_by_id.get(slice_id) != "complete"
            ]
            if incomplete_product_slices:
                failures.append(
                    "experience evidence cannot be ready until product slices S01-S28 are complete: "
                    + ", ".join(incomplete_product_slices)
                )
            _validate_experience_evidence(
                root,
                experience,
                failures,
                expected_source_sha=expected_source_sha,
            )

    interactive = contract.get("interactive_workstation")
    if not isinstance(interactive, dict):
        failures.append("v0.10 qualification contract missing interactive_workstation evidence contract")
    else:
        static_interactive = dict(interactive)
        static_interactive.pop("evidence_ready", None)
        static_interactive.pop("evidence_manifest_sha256", None)
        if static_interactive != EXPECTED_INTERACTIVE_WORKSTATION:
            failures.append("v0.10 interactive workstation evidence contract drifted")
        evidence_ready = interactive.get("evidence_ready")
        if not isinstance(evidence_ready, bool):
            failures.append("interactive_workstation.evidence_ready must be boolean")
        elif evidence_ready:
            _validate_interactive_workstation_evidence(
                root,
                interactive,
                failures,
                expected_source_sha=expected_source_sha,
                expected_profile_sha256=(
                    contract.get("profile_sha256")
                    if isinstance(contract.get("profile_sha256"), str)
                    else None
                ),
                expected_package_manifest_sha256=frozen_package_manifest_digest,
                expected_provider_versions=frozen_package_versions,
                expected_architecture=frozen_substrate_architecture,
                expected_linurad_sha256=expected_linurad_sha256,
                expected_shell_bridge_sha256=expected_shell_bridge_sha256,
                require_binary_binding=require_binary_binding,
            )
        elif interactive.get("evidence_manifest_sha256") not in {"", None}:
            failures.append(
                "interactive_workstation evidence digest must remain empty until Q11 evidence is ready"
            )

    for section_name, expected, label in (
        ("update_recovery_qualification", EXPECTED_UPDATE_RECOVERY_QUALIFICATION, "Q12 update/recovery"),
        ("security_qualification", EXPECTED_SECURITY_QUALIFICATION, "Q13 workstation security"),
    ):
        section = contract.get(section_name)
        if not isinstance(section, dict):
            failures.append(f"v0.10 qualification contract missing {section_name}")
            continue
        static_section = dict(section)
        static_section.pop("evidence_ready", None)
        static_section.pop("evidence_manifest_sha256", None)
        if static_section != expected:
            failures.append(f"v0.10 {section_name} contract drifted")
        evidence_ready = section.get("evidence_ready")
        if not isinstance(evidence_ready, bool):
            failures.append(f"{section_name}.evidence_ready must be boolean")
        elif evidence_ready:
            _validate_release_matrix_evidence(
                root,
                section,
                expected,
                label=label,
                expected_source_sha=expected_source_sha,
                expected_profile_sha256=(
                    contract.get("profile_sha256")
                    if isinstance(contract.get("profile_sha256"), str)
                    else None
                ),
                expected_package_manifest_sha256=frozen_package_manifest_digest,
                expected_package_versions=frozen_package_versions,
                expected_architecture=frozen_substrate_architecture,
                expected_linurad_sha256=expected_linurad_sha256,
                expected_shell_bridge_sha256=expected_shell_bridge_sha256,
                require_binary_binding=require_binary_binding,
                failures=failures,
            )
        elif section.get("evidence_manifest_sha256") not in {"", None}:
            failures.append(f"{section_name} evidence digest must remain empty until evidence is ready")

    if contract.get("security") != EXPECTED_SECURITY:
        failures.append("v0.10 contract security baseline must match the target PlatformProfile")
    if contract.get("updates") != EXPECTED_UPDATES:
        failures.append("v0.10 contract update boundary must match the target PlatformProfile")

    return failures


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    post_release_closed = False
    roadmap_path = root / "contracts/roadmap.toml"
    if roadmap_path.is_file():
        try:
            roadmap = tomllib.loads(roadmap_path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError:
            roadmap = {}
        milestone = _v010_milestone(roadmap) if isinstance(roadmap, dict) else None
        post_release_closed = bool(
            isinstance(milestone, dict) and milestone.get("status") == "released"
        )
    expected_source_sha = os.environ.get("LINURA_EXPECTED_SOURCE_SHA")
    if expected_source_sha is not None and not GIT_SHA_RE.fullmatch(expected_source_sha):
        print("ERROR: LINURA_EXPECTED_SOURCE_SHA must be a lowercase 40-hex Git SHA", file=sys.stderr)
        return 1
    expected_linurad_sha256 = os.environ.get("LINURA_EXPECTED_LINURAD_SHA256")
    expected_shell_bridge_sha256 = os.environ.get("LINURA_EXPECTED_SHELL_BRIDGE_SHA256")
    require_binary_binding = os.environ.get("LINURA_REQUIRE_BINARY_BINDING") == "1"
    for name, value in (
        ("LINURA_EXPECTED_LINURAD_SHA256", expected_linurad_sha256),
        ("LINURA_EXPECTED_SHELL_BRIDGE_SHA256", expected_shell_bridge_sha256),
    ):
        if value is not None and not SHA256_RE.fullmatch(value):
            print(f"ERROR: {name} must be a lowercase SHA-256 digest", file=sys.stderr)
            return 1
    failures = validate(
        root,
        expected_source_sha=expected_source_sha,
        expected_linurad_sha256=expected_linurad_sha256,
        expected_shell_bridge_sha256=expected_shell_bridge_sha256,
        require_binary_binding=require_binary_binding,
        post_release_closed=post_release_closed,
    )
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("v0.10 workstation qualification contract checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
