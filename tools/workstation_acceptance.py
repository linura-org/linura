#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "contracts/v010-workstation-acceptance.toml"
DEFAULT_QUALIFICATION_CONTRACT = ROOT / "contracts/v010-workstation-qualification.toml"
DEFAULT_SLICE_CONTRACT = ROOT / "contracts/v010-workstation-slices.toml"
DEFAULT_HARDWARE_FIXTURE_CONTRACT = Path("/etc/linura/qualification-fixture.json")
HARDWARE_FIXTURE_MAX_BYTES = 16 * 1024
MONITOR_SNAPSHOT_MAX_BYTES = 256 * 1024
MONITOR_TEXT_MAX_CHARS = 128
MODES = ("automated", "interactive", "hardware")
INTERACTIVE_DISPLAYS = ("gtk", "vnc")

Q11_CASE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "id": "bounded-installer-lane",
        "mechanism": "physical-installer-execution",
        "prerequisite_slice": "S28",
        "required_observations": [
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
    },
    {
        "id": "physical-session-start",
        "mechanism": "physical-session-observation",
        "prerequisite_slice": "S16",
        "required_observations": [
            "physical-hardware-present",
            "wayland-session-active",
            "hyprland-session-active",
        ],
    },
    {
        "id": "session-supervision",
        "mechanism": "systemd-session-observation",
        "prerequisite_slice": "S16",
        "required_observations": [
            "hyprland-session-target-active",
            "graphical-session-target-active",
            "linura-shell-active-through-session-target",
            "linura-shell-binds-to-session-target",
            "linura-shell-part-of-session-target",
            "linura-shell-stopped-with-graphical-session",
        ],
    },
    {
        "id": "shell-render-and-input",
        "mechanism": "physical-input-observation",
        "prerequisite_slice": "S29",
        "required_observations": ["shell-rendered", "keyboard-input", "pointer-input"],
    },
    {
        "id": "display-scale-and-hidpi",
        "mechanism": "physical-display-observation",
        "prerequisite_slice": "S29",
        "required_observations": [
            "display-enumerated",
            "scale-applied",
            "hidpi-render-captured",
        ],
    },
    {
        "id": "accessibility-and-visual",
        "mechanism": "physical-accessibility-visual-observation",
        "prerequisite_slice": "S29",
        "required_observations": [
            "screen-reader-semantics-verified",
            "focus-navigation-verified",
            "reduced-motion-verified",
            "visual-artifact-retained",
        ],
    },
    {
        "id": "provider-runtime-identities",
        "mechanism": "physical-provider-observation",
        "prerequisite_slice": "S21",
        "required_observations": [
            "networkmanager-version",
            "bluez-version",
            "pipewire-version",
            "wireplumber-version",
            "udisks2-version",
            "polkit-version",
        ],
    },
    {
        "id": "session-audio-transient-effect",
        "mechanism": "physical-session-audio-effect",
        "prerequisite_slice": "S20",
        "required_observations": [
            "numeric-pipewire-output-bound",
            "typed-session-volume-operation-dispatched",
            "exact-node-post-effect-reobserved",
            "executor-failure-fails-closed",
            "timeout-fails-closed",
            "restart-reobservation-verified",
        ],
    },
    {
        "id": "restart-recovery",
        "mechanism": "physical-restart-observation",
        "prerequisite_slice": "S29",
        "required_observations": [
            "shell-restart",
            "authority-restart",
            "state-reobserved",
        ],
    },
)


class AcceptanceError(ValueError):
    pass


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict[str, Any]:
    try:
        contract = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise AcceptanceError(f"acceptance contract not found: {path}") from error
    except Exception as error:
        raise AcceptanceError(f"invalid acceptance contract: {error}") from error
    failures = validate_contract(contract)
    if failures:
        raise AcceptanceError("; ".join(failures))
    return contract


def validate_contract(contract: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    expected = {
        "schema_version": 1,
        "id": "qualification/v010-workstation-acceptance",
        "milestone": "v0.10.0",
        "target_profile": "arch-hyprland-v1",
        "runtime_contract": "contracts/v010-shell-runtime-qualification.toml",
        "substrate_contract": "contracts/v010-shell-runtime-substrate.toml",
        "vm_launcher": "qualification/v010/shell-runtime/start-vm.sh",
        "interactive_launcher": "qualification/v010/workstation-acceptance/launch-interactive.sh",
        "live_session": "qualification/v010/workstation-acceptance/run-live-session.sh",
        "guest_recorder": "qualification/v010/workstation-acceptance/record-session.sh",
        "hardware_capture": "qualification/v010/workstation-acceptance/capture-hardware-session.sh",
        "hardware_runner": "qualification/v010/workstation-acceptance/run-hardware-qualification.sh",
        "hardware_orchestrator": "tools/workstation_q11_runner.py",
        "hardware_fixture_schema": "schemas/v010-maintained-workstation-fixture.v1.schema.json",
        "recording_verifier": "tools/workstation_acceptance.py",
        "release_support_promotion": False,
    }
    for key, value in expected.items():
        if contract.get(key) != value:
            failures.append(f"acceptance contract {key} must remain {value!r}")

    level_a = contract.get("level_a")
    if not isinstance(level_a, dict):
        failures.append("acceptance contract level_a is missing")
    else:
        required = {
            "id": "automated-vm",
            "required": True,
            "vm_mode": "automated",
            "display_backend": "none",
            "recording": "required",
            "source_scope": "exact-pr-head",
            "evidence_scope": "development-runtime",
        }
        for key, value in required.items():
            if level_a.get(key) != value:
                failures.append(f"level_a.{key} must remain {value!r}")

    level_b = contract.get("level_b")
    if not isinstance(level_b, dict):
        failures.append("acceptance contract level_b is missing")
    else:
        required = {
            "id": "interactive-vm",
            "required": False,
            "vm_mode": "interactive",
            "display_backends": ["gtk", "vnc"],
            "recording": "optional",
            "same_runtime_contract": True,
            "same_substrate_contract": True,
            "same_exact_source_provisioning": True,
            "evidence_scope": "developer-interactive",
        }
        for key, value in required.items():
            if level_b.get(key) != value:
                failures.append(f"level_b.{key} must remain {value!r}")

    level_c = contract.get("level_c")
    if not isinstance(level_c, dict):
        failures.append("acceptance contract level_c is missing")
    else:
        required = {
            "id": "maintained-hardware",
            "required_for_release_gate": "Q11",
            "recording": "optional",
            "same_recording_contract": True,
            "virtualization_allowed": False,
            "evidence_scope": "maintained-physical-interactive",
            "runner": "qualification/v010/workstation-acceptance/run-hardware-qualification.sh",
            "capture": "qualification/v010/workstation-acceptance/capture-hardware-session.sh",
            "fixture_contract_default": "/etc/linura/qualification-fixture.json",
            "fixture_schema": "schemas/v010-maintained-workstation-fixture.v1.schema.json",
            "fixture_contract_max_bytes": 16384,
            "fixture_owner_uid": 0,
            "fixture_forbid_group_world_write": True,
            "physicality_probe": "systemd-detect-virt",
            "physicality_expected": "none",
            "required_case_source": "contracts/v010-workstation-qualification.toml#interactive_workstation.required_cases",
            "full_q11_case_set_required": True,
            "runner_may_promote_support": False,
            "case_protocol": "bounded-q11-case-request-v1",
            "run_state_protocol": "bounded-q11-run-state-v1",
            "case_evidence_protocol": "digest-bound-q11-case-attestation-v1",
            "candidate_verifier": "tools/check_v010_workstation_qualification.py",
            "run_state_outside_source_required": True,
            "candidate_finalization_may_promote_support": False,
            "arbitrary_commands_allowed": False,
            "full_run_requires_all_case_prerequisites": True,
        }
        for key, value in required.items():
            if level_c.get(key) != value:
                failures.append(f"level_c.{key} must remain {value!r}")

    expected_cases = [dict(item) for item in Q11_CASE_SPECS]
    if contract.get("level_c_case") != expected_cases:
        failures.append(
            "level_c_case registry must exactly match the bounded canonical Q11 case protocol"
        )

    recording = contract.get("recording")
    if not isinstance(recording, dict):
        failures.append("acceptance recording contract is missing")
    else:
        expected_recording = {
            "container": "matroska",
            "extension": ".mkv",
            "codec": "ffv1",
            "minimum_bytes": 1024,
            "maximum_bytes": 536870912,
            "minimum_duration_seconds": 0.25,
            "maximum_duration_seconds": 600.0,
            "maximum_width": 16384,
            "maximum_height": 16384,
            "video_stream_count": 1,
            "audio_streams_allowed": False,
            "metadata_schema_version": 1,
        }
        for key, value in expected_recording.items():
            if recording.get(key) != value:
                failures.append(f"recording.{key} must remain {value!r}")
    return failures



def q11_required_cases(path: Path = DEFAULT_QUALIFICATION_CONTRACT) -> list[str]:
    try:
        contract = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise AcceptanceError(f"qualification contract not found: {path}") from error
    except Exception as error:
        raise AcceptanceError(f"invalid qualification contract: {error}") from error
    interactive = contract.get("interactive_workstation")
    if not isinstance(interactive, dict):
        raise AcceptanceError("qualification contract is missing interactive_workstation")
    cases = interactive.get("required_cases")
    if (
        not isinstance(cases, list)
        or not cases
        or any(not isinstance(item, str) or not item for item in cases)
        or len(cases) != len(set(cases))
    ):
        raise AcceptanceError("interactive_workstation.required_cases must be a non-empty unique string list")
    expected = [item["id"] for item in Q11_CASE_SPECS]
    if list(cases) != expected:
        raise AcceptanceError(
            "interactive_workstation.required_cases drifted from the Level C bounded case protocol"
        )
    return list(cases)


def _slice_statuses(path: Path = DEFAULT_SLICE_CONTRACT) -> dict[str, str]:
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise AcceptanceError(f"slice contract not found: {path}") from error
    except Exception as error:
        raise AcceptanceError(f"invalid slice contract: {error}") from error
    items = document.get("slice")
    if not isinstance(items, list):
        raise AcceptanceError("slice contract is missing slice entries")
    statuses: dict[str, str] = {}
    for item in items:
        if not isinstance(item, dict):
            raise AcceptanceError("slice contract contains a non-object entry")
        slice_id = item.get("id")
        status = item.get("status")
        if not isinstance(slice_id, str) or not isinstance(status, str) or slice_id in statuses:
            raise AcceptanceError("slice contract contains invalid or duplicate slice identity")
        statuses[slice_id] = status
    return statuses


def level_c_case_plan(
    contract: dict[str, Any],
    *,
    slice_path: Path = DEFAULT_SLICE_CONTRACT,
) -> list[dict[str, Any]]:
    statuses = _slice_statuses(slice_path)
    plan: list[dict[str, Any]] = []
    for item in contract["level_c_case"]:
        prerequisite = item["prerequisite_slice"]
        status = statuses.get(prerequisite, "missing")
        plan.append(
            {
                **item,
                "prerequisite_status": status,
                "ready": status == "complete",
            }
        )
    return plan


def _bounded_protocol_id(value: str, label: str, maximum: int) -> str:
    if (
        not value
        or len(value) > maximum
        or not value[0].isalnum()
        or any(
            character
            not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
            for character in value
        )
    ):
        raise AcceptanceError(f"{label} must be a bounded identifier")
    return value


def _validate_source_sha(source_sha: str) -> str:
    if len(source_sha) != 40 or any(ch not in "0123456789abcdef" for ch in source_sha):
        raise AcceptanceError("source SHA must be 40 lowercase hexadecimal characters")
    return source_sha


def _case_request_from_plan(
    item: dict[str, Any],
    *,
    run_id: str,
    fixture_id: str,
    source_sha: str,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "artifact_type": "linura-v010-q11-case-request",
        "milestone": "v0.10.0",
        "run_id": run_id,
        "source_commit_sha": source_sha,
        "fixture_id": fixture_id,
        "case": item["id"],
        "mechanism": item["mechanism"],
        "required_observations": list(item["required_observations"]),
        "external_controller_required": True,
        "arbitrary_command_allowed": False,
        "release_support_promotion": False,
    }


def hardware_case_request(
    contract: dict[str, Any],
    *,
    case_id: str,
    run_id: str,
    fixture_id: str,
    source_sha: str,
    slice_path: Path = DEFAULT_SLICE_CONTRACT,
) -> dict[str, Any]:
    run_id = _bounded_protocol_id(run_id, "run-id", 128)
    fixture_id = _bounded_protocol_id(fixture_id, "fixture-id", 64)
    source_sha = _validate_source_sha(source_sha)
    plan = level_c_case_plan(contract, slice_path=slice_path)
    item = next((candidate for candidate in plan if candidate["id"] == case_id), None)
    if item is None:
        raise AcceptanceError(f"unsupported Level C case: {case_id}")
    if not item["ready"]:
        raise AcceptanceError(
            f"Level C case {case_id} prerequisite {item['prerequisite_slice']} "
            f"is {item['prerequisite_status']}, not complete"
        )
    return _case_request_from_plan(
        item,
        run_id=run_id,
        fixture_id=fixture_id,
        source_sha=source_sha,
    )


def hardware_run_requests(
    contract: dict[str, Any],
    *,
    run_id: str,
    fixture_id: str,
    source_sha: str,
    slice_path: Path = DEFAULT_SLICE_CONTRACT,
) -> list[dict[str, Any]]:
    run_id = _bounded_protocol_id(run_id, "run-id", 128)
    fixture_id = _bounded_protocol_id(fixture_id, "fixture-id", 64)
    source_sha = _validate_source_sha(source_sha)
    plan = level_c_case_plan(contract, slice_path=slice_path)
    blocked = [
        f"{item['id']}({item['prerequisite_slice']}={item['prerequisite_status']})"
        for item in plan
        if not item["ready"]
    ]
    if blocked:
        raise AcceptanceError(
            "Level C full run is blocked before execution: " + ", ".join(blocked)
        )
    return [
        _case_request_from_plan(
            item,
            run_id=run_id,
            fixture_id=fixture_id,
            source_sha=source_sha,
        )
        for item in plan
    ]


def validate_fixture_payload(
    payload: dict[str, Any],
    *,
    fixture_id: str | None = None,
) -> list[str]:
    failures: list[str] = []
    expected_keys = {
        "schema_version",
        "fixture_id",
        "profile_id",
        "machine_class",
        "evidence_tier",
        "physical_hardware",
    }
    if set(payload) != expected_keys:
        failures.append(
            "fixture contract fields must be exactly: " + ", ".join(sorted(expected_keys))
        )
    if payload.get("schema_version") != 1:
        failures.append("fixture contract schema_version must be 1")
    observed_id = payload.get("fixture_id")
    if (
        not isinstance(observed_id, str)
        or not observed_id
        or len(observed_id) > 64
        or not observed_id[0].isalnum()
        or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for ch in observed_id)
    ):
        failures.append("fixture contract fixture_id must be a bounded identifier")
    elif fixture_id is not None and observed_id != fixture_id:
        failures.append("fixture contract fixture_id does not match the requested fixture")
    expected_values = {
        "profile_id": "arch-hyprland-v1",
        "machine_class": "workstation",
        "evidence_tier": "maintainer_hardware",
        "physical_hardware": True,
    }
    for key, value in expected_values.items():
        if payload.get(key) != value:
            failures.append(f"fixture contract {key} must be {value!r}")
    return failures


def read_hardware_fixture(
    path: Path,
    *,
    fixture_id: str | None = None,
    require_root_owned: bool = True,
) -> tuple[dict[str, Any], str]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise AcceptanceError(f"maintained hardware fixture contract not found: {path}") from error
    except OSError as error:
        raise AcceptanceError(f"maintained hardware fixture contract cannot be opened safely: {error}") from error
    try:
        stat_result = os.fstat(descriptor)
        if not stat.S_ISREG(stat_result.st_mode):
            raise AcceptanceError("maintained hardware fixture contract must be a regular file")
        if stat_result.st_nlink != 1:
            raise AcceptanceError("maintained hardware fixture contract must have exactly one hard link")
        if stat_result.st_size <= 0 or stat_result.st_size > HARDWARE_FIXTURE_MAX_BYTES:
            raise AcceptanceError("maintained hardware fixture contract exceeds the bounded size")
        if require_root_owned and stat_result.st_uid != 0:
            raise AcceptanceError("maintained hardware fixture contract must be owned by root")
        if stat_result.st_mode & 0o022:
            raise AcceptanceError("maintained hardware fixture contract must not be group/world writable")
        data = os.read(descriptor, HARDWARE_FIXTURE_MAX_BYTES + 1)
        if len(data) != stat_result.st_size or len(data) > HARDWARE_FIXTURE_MAX_BYTES:
            raise AcceptanceError("maintained hardware fixture contract changed or exceeded bounds while reading")
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AcceptanceError("maintained hardware fixture contract must be valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise AcceptanceError("maintained hardware fixture contract must be a JSON object")
    failures = validate_fixture_payload(payload, fixture_id=fixture_id)
    if failures:
        raise AcceptanceError("; ".join(failures))
    return payload, hashlib.sha256(data).hexdigest()


def load_hardware_fixture(
    path: Path,
    *,
    fixture_id: str | None = None,
    require_root_owned: bool = True,
) -> dict[str, Any]:
    payload, _digest = read_hardware_fixture(
        path,
        fixture_id=fixture_id,
        require_root_owned=require_root_owned,
    )
    return payload


def sanitize_hyprland_monitors(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or not 1 <= len(payload) <= 16:
        raise AcceptanceError("Hyprland monitor snapshot must contain 1..16 outputs")
    required_numeric = ("width", "height", "refreshRate", "x", "y", "scale")
    optional_numeric = ("transform",)
    sanitized: list[dict[str, Any]] = []
    for monitor in payload:
        if not isinstance(monitor, dict):
            raise AcceptanceError("Hyprland monitor snapshot entries must be objects")
        entry: dict[str, Any] = {}
        for key in ("name", "make", "model"):
            value = monitor.get(key)
            if value is None and key != "name":
                continue
            if not isinstance(value, str) or not value or len(value) > MONITOR_TEXT_MAX_CHARS:
                raise AcceptanceError(f"Hyprland monitor field {key} is invalid")
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
                raise AcceptanceError(f"Hyprland monitor field {key} contains control characters")
            entry[key] = value
        for key in required_numeric + optional_numeric:
            if key not in monitor:
                if key in required_numeric:
                    raise AcceptanceError(f"Hyprland monitor snapshot is missing {key}")
                continue
            value = monitor[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise AcceptanceError(f"Hyprland monitor field {key} must be numeric")
            if isinstance(value, float) and not math.isfinite(value):
                raise AcceptanceError(f"Hyprland monitor field {key} must be finite")
            entry[key] = value
        focused = monitor.get("focused")
        if focused is not None:
            if not isinstance(focused, bool):
                raise AcceptanceError("Hyprland monitor field focused must be boolean")
            entry["focused"] = focused
        sanitized.append(entry)
    return sanitized


def read_sanitized_hyprland_monitors() -> list[dict[str, Any]]:
    data = sys.stdin.buffer.read(MONITOR_SNAPSHOT_MAX_BYTES + 1)
    if len(data) > MONITOR_SNAPSHOT_MAX_BYTES:
        raise AcceptanceError("Hyprland monitor snapshot exceeds the bounded input size")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AcceptanceError("Hyprland monitor snapshot must be valid UTF-8 JSON") from error
    return sanitize_hyprland_monitors(payload)


def validate_virtualization_probe(returncode: int, output: str) -> list[str]:
    observed = output.strip()
    if returncode == 0:
        return [f"Level C requires physical hardware; virtualization detected: {observed or 'unknown'}"]
    if returncode != 1:
        return [f"Level C physicality probe failed with status {returncode}"]
    if observed not in {"", "none"}:
        return [f"Level C physicality probe returned an unexpected result: {observed}"]
    return []


def hardware_doctor(
    *,
    fixture_contract: Path,
    fixture_id: str | None,
) -> list[str]:
    failures: list[str] = []
    if fixture_id is None:
        failures.append("Level C doctor requires --fixture-id")
    try:
        load_hardware_fixture(fixture_contract, fixture_id=fixture_id)
    except AcceptanceError as error:
        failures.append(str(error))
    if not (os.environ.get("WAYLAND_DISPLAY") and os.environ.get("HYPRLAND_INSTANCE_SIGNATURE")):
        failures.append("Level C requires an existing Hyprland Wayland session")
    detector = shutil.which("systemd-detect-virt")
    if detector is None:
        failures.append("systemd-detect-virt")
    else:
        completed = subprocess.run(
            [detector],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        failures.extend(validate_virtualization_probe(completed.returncode, completed.stdout))
    hyprctl = shutil.which("hyprctl")
    if hyprctl is not None:
        completed = subprocess.run(
            [hyprctl, "monitors", "-j"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if completed.returncode != 0:
            failures.append("hyprctl monitors -j failed for the Level C session")
        else:
            try:
                monitors = json.loads(completed.stdout)
            except json.JSONDecodeError:
                failures.append("hyprctl monitors -j returned invalid JSON")
            else:
                if not isinstance(monitors, list) or not 1 <= len(monitors) <= 16:
                    failures.append("Level C requires 1..16 real session outputs")
    return failures


def _which(command: str) -> bool:
    return shutil.which(command) is not None


def doctor(
    mode: str,
    display: str,
    *,
    fixture_contract: Path = DEFAULT_HARDWARE_FIXTURE_CONTRACT,
    fixture_id: str | None = None,
    record: bool = False,
) -> list[str]:
    missing: list[str] = []
    if mode not in MODES:
        return [f"unsupported mode: {mode}"]
    if mode == "automated" and display != "none":
        return ["automated mode requires display=none"]
    if mode == "interactive" and display not in INTERACTIVE_DISPLAYS:
        return ["interactive mode requires display=gtk or display=vnc"]
    if mode == "hardware" and display != "none":
        return ["hardware mode does not use a VM display backend"]
    if mode in {"automated", "interactive"}:
        commands = ["qemu-system-x86_64", "qemu-img", "ssh", "scp", "ssh-keygen", "cloud-localds", "git"]
        if mode == "automated":
            # Level A recording is mandatory regardless of the caller's --record flag.
            commands.append("ffprobe")
        if mode == "interactive":
            commands.extend(["cargo", "rustup"])
            if record:
                commands.append("ffprobe")
        for command in commands:
            if not _which(command):
                missing.append(command)
    if mode == "interactive" and display == "gtk":
        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            missing.append("host graphical display environment (DISPLAY or WAYLAND_DISPLAY)")
    if mode == "hardware":
        commands = [
            "Hyprland",
            "hyprctl",
            "systemctl",
            "systemd-detect-virt",
            "python3",
            "git",
            "sha256sum",
        ]
        if record:
            commands.extend(["wf-recorder", "ffprobe", "systemd-run", "journalctl"])
        for command in commands:
            if not _which(command):
                missing.append(command)
        if not missing:
            missing.extend(
                hardware_doctor(
                    fixture_contract=fixture_contract,
                    fixture_id=fixture_id,
                )
            )
    return missing


def plan_payload(contract: dict[str, Any], mode: str, display: str, record: bool) -> dict[str, Any]:
    if mode not in MODES:
        raise AcceptanceError(f"unsupported mode: {mode}")
    if mode == "automated":
        if display != "none":
            raise AcceptanceError("automated mode requires display=none")
        recording = True
        launcher = contract["vm_launcher"]
    elif mode == "interactive":
        if display not in INTERACTIVE_DISPLAYS:
            raise AcceptanceError("interactive mode requires display=gtk or display=vnc")
        recording = record
        launcher = contract["interactive_launcher"]
    else:
        if display != "none":
            raise AcceptanceError("hardware mode does not use a VM display backend")
        recording = record
        launcher = contract["hardware_runner"]
    payload = {
        "mode": mode,
        "target_profile": contract["target_profile"],
        "runtime_contract": contract["runtime_contract"],
        "substrate_contract": contract["substrate_contract"],
        "launcher": launcher,
        "display": display,
        "recording": recording,
        "recorder": contract["guest_recorder"],
        "recording_verifier": contract["recording_verifier"],
        "release_support_promotion": False,
    }
    if mode == "hardware":
        payload.update(
            {
                "capture": contract["hardware_capture"],
                "orchestrator": contract["hardware_orchestrator"],
                "fixture_contract": contract["level_c"]["fixture_contract_default"],
                "physicality_probe": contract["level_c"]["physicality_probe"],
                "physicality_expected": contract["level_c"]["physicality_expected"],
                "required_q11_cases": q11_required_cases(),
                "full_q11_case_set_required": True,
                "runner_may_promote_support": False,
                "case_protocol": contract["level_c"]["case_protocol"],
                "run_state_protocol": contract["level_c"]["run_state_protocol"],
                "case_evidence_protocol": contract["level_c"]["case_evidence_protocol"],
                "candidate_verifier": contract["level_c"]["candidate_verifier"],
                "run_state_outside_source_required": True,
                "candidate_finalization_may_promote_support": False,
                "arbitrary_commands_allowed": False,
                "full_run_requires_all_case_prerequisites": True,
            }
        )
    return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _safe_number(value: object, label: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise AcceptanceError(f"recording {label} is not numeric") from error
    if not (number >= 0.0):
        raise AcceptanceError(f"recording {label} must be non-negative")
    return number


def validate_probe_payload(
    probe: dict[str, Any],
    *,
    file_size: int,
    recording_contract: dict[str, Any],
) -> dict[str, Any]:
    if file_size < recording_contract["minimum_bytes"]:
        raise AcceptanceError("recording is below the minimum bounded size")
    if file_size > recording_contract["maximum_bytes"]:
        raise AcceptanceError("recording exceeds the maximum bounded size")

    streams = probe.get("streams")
    if not isinstance(streams, list):
        raise AcceptanceError("ffprobe result is missing streams")
    video_streams = [
        item for item in streams
        if isinstance(item, dict) and item.get("codec_type") == "video"
    ]
    audio_streams = [
        item for item in streams
        if isinstance(item, dict) and item.get("codec_type") == "audio"
    ]
    if len(video_streams) != recording_contract["video_stream_count"]:
        raise AcceptanceError("recording must contain exactly one video stream")
    if audio_streams and not recording_contract["audio_streams_allowed"]:
        raise AcceptanceError("recording must not contain audio streams")

    stream = video_streams[0]
    if stream.get("codec_name") != recording_contract["codec"]:
        raise AcceptanceError(
            f"recording codec mismatch: expected {recording_contract['codec']!r}"
        )
    width = stream.get("width")
    height = stream.get("height")
    if type(width) is not int or type(height) is not int or width <= 0 or height <= 0:
        raise AcceptanceError("recording dimensions must be positive integers")
    if width > recording_contract["maximum_width"] or height > recording_contract["maximum_height"]:
        raise AcceptanceError("recording dimensions exceed the bounded maximum")

    format_payload = probe.get("format")
    if not isinstance(format_payload, dict):
        raise AcceptanceError("ffprobe result is missing format metadata")
    format_name = format_payload.get("format_name")
    if not isinstance(format_name, str) or "matroska" not in format_name.split(","):
        raise AcceptanceError("recording container is not Matroska")
    duration = _safe_number(format_payload.get("duration"), "duration")
    if duration < recording_contract["minimum_duration_seconds"]:
        raise AcceptanceError("recording duration is below the minimum")
    if duration > recording_contract["maximum_duration_seconds"]:
        raise AcceptanceError("recording duration exceeds the bounded maximum")

    return {
        "codec": stream["codec_name"],
        "width": width,
        "height": height,
        "duration_seconds": duration,
        "container": "matroska",
    }


def _recording_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _open_recording_snapshot(
    path: Path,
    *,
    recording_contract: dict[str, Any],
    snapshot_path: Path,
) -> tuple[tuple[int, int, int, int, int], int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AcceptanceError(f"recording is missing or unsafe: {path}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise AcceptanceError("recording must be a regular file")
        if before.st_nlink != 1:
            raise AcceptanceError("recording must have exactly one hard link")
        file_size = before.st_size
        if file_size < recording_contract["minimum_bytes"]:
            raise AcceptanceError("recording is below the minimum bounded size")
        if file_size > recording_contract["maximum_bytes"]:
            raise AcceptanceError("recording exceeds the maximum bounded size")

        with snapshot_path.open("xb") as snapshot:
            offset = 0
            remaining = file_size
            while remaining:
                chunk = os.pread(descriptor, min(1024 * 1024, remaining), offset)
                if not chunk:
                    raise AcceptanceError("recording changed while the verifier was snapshotting it")
                snapshot.write(chunk)
                offset += len(chunk)
                remaining -= len(chunk)
            if os.pread(descriptor, 1, offset):
                raise AcceptanceError("recording grew while the verifier was snapshotting it")

        after = os.fstat(descriptor)
        identity = _recording_identity(before)
        if _recording_identity(after) != identity:
            raise AcceptanceError("recording changed while the verifier was snapshotting it")
        try:
            path_after_snapshot = os.lstat(path)
        except OSError as error:
            raise AcceptanceError("recording path changed while the verifier was snapshotting it") from error
        if stat.S_ISLNK(path_after_snapshot.st_mode) or _recording_identity(path_after_snapshot) != identity:
            raise AcceptanceError("recording path changed while the verifier was snapshotting it")
        return identity, file_size
    finally:
        os.close(descriptor)


def _require_recording_identity(path: Path, identity: tuple[int, int, int, int, int]) -> None:
    try:
        current = os.lstat(path)
    except OSError as error:
        raise AcceptanceError("recording path changed while it was being verified") from error
    if stat.S_ISLNK(current.st_mode) or _recording_identity(current) != identity:
        raise AcceptanceError("recording changed while it was being verified")



def _validate_recording_output_paths(
    path: Path,
    metadata_path: Path | None,
    digest_path: Path | None,
) -> None:
    """Reject lexical, symlink-parent and hard-link aliases before writing anything."""
    canonical_paths: dict[str, str] = {}
    existing_inodes: dict[tuple[int, int], str] = {}
    for label, candidate in (
        ("recording", path),
        ("metadata", metadata_path),
        ("digest", digest_path),
    ):
        if candidate is None:
            continue
        canonical = os.path.realpath(candidate)
        previous = canonical_paths.get(canonical)
        if previous is not None:
            raise AcceptanceError(f"recording output paths alias: {previous} and {label}")
        canonical_paths[canonical] = label

        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise AcceptanceError(f"recording {label} path cannot be inspected") from error
        if label != "recording" and (
            not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
        ):
            raise AcceptanceError(
                f"recording {label} output must be a single-link regular file or absent"
            )
        inode = (info.st_dev, info.st_ino)
        previous = existing_inodes.get(inode)
        if previous is not None:
            raise AcceptanceError(f"recording output paths alias: {previous} and {label}")
        existing_inodes[inode] = label



def _require_sidecar_parent(path: Path, directory: int) -> None:
    """Bind a sidecar's lexical parent to its pre-opened directory handle."""
    try:
        current = os.stat(path.parent, follow_symlinks=False)
        pinned = os.fstat(directory)
    except OSError as error:
        raise AcceptanceError("recording sidecar directory changed during publication") from error
    if (
        not stat.S_ISDIR(current.st_mode)
        or (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino)
    ):
        raise AcceptanceError("recording sidecar directory changed during publication")


def _unlink_owned_recording_sidecar(
    path: Path, identity: tuple[int, int], *, directory_fd: int | None = None,
) -> None:
    """Only revoke this invocation's inode, even after a parent rename."""
    owned_directory = directory_fd is None
    directory = directory_fd if directory_fd is not None else os.open(
        path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        try:
            current = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity:
            os.unlink(path.name, dir_fd=directory)
    finally:
        if owned_directory:
            os.close(directory)


def _publish_recording_sidecar(
    path: Path, content: str, *, directory_fd: int | None = None,
) -> tuple[int, int]:
    """Atomically publish relative to the parent pinned before any sidecar write."""
    owned_directory = directory_fd is None
    if owned_directory:
        path.parent.mkdir(parents=True, exist_ok=True)
    directory = directory_fd if directory_fd is not None else os.open(
        path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    temporary = f".{path.name}.{secrets.token_hex(16)}.tmp"
    published_identity: tuple[int, int] | None = None
    try:
        _require_sidecar_parent(path, directory)
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
            written = os.fstat(output.fileno())
        candidate = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
        if (
            not stat.S_ISREG(candidate.st_mode)
            or candidate.st_nlink != 1
            or (candidate.st_dev, candidate.st_ino) != (written.st_dev, written.st_ino)
        ):
            raise AcceptanceError("recording sidecar temporary file was replaced")
        # Names resolve only against the pre-opened directory; replacing a
        # swapped symlink/hardlink never opens or writes to its target.
        os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        published_identity = (written.st_dev, written.st_ino)
        published = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if (
            not stat.S_ISREG(published.st_mode)
            or published.st_nlink != 1
            or (published.st_dev, published.st_ino) != published_identity
        ):
            raise AcceptanceError("recording sidecar changed during publication")
        _require_sidecar_parent(path, directory)
        os.fsync(directory)
        return published_identity
    except (OSError, AcceptanceError):
        if published_identity is not None:
            try:
                _unlink_owned_recording_sidecar(
                    path, published_identity, directory_fd=directory,
                )
            except OSError:
                pass
        raise
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        if owned_directory:
            os.close(directory)


def verify_recording(
    path: Path,
    *,
    contract: dict[str, Any],
    metadata_path: Path | None = None,
    digest_path: Path | None = None,
    source_sha: str | None = None,
) -> dict[str, Any]:
    _validate_recording_output_paths(path, metadata_path, digest_path)
    recording = contract["recording"]
    if path.suffix != recording["extension"]:
        raise AcceptanceError(f"recording extension must be {recording['extension']}")
    with tempfile.TemporaryDirectory(prefix="linura-recording-verify-") as temp_dir:
        snapshot_path = Path(temp_dir) / f"snapshot{recording['extension']}"
        identity, file_size = _open_recording_snapshot(
            path,
            recording_contract=recording,
            snapshot_path=snapshot_path,
        )
        ffprobe = shutil.which("ffprobe")
        if ffprobe is None:
            raise AcceptanceError("ffprobe is required to verify a workstation recording")
        completed = subprocess.run(
            [
                ffprobe,
                "-v",
                "error",
                "-show_entries",
                "stream=codec_type,codec_name,width,height:format=format_name,duration",
                "-of",
                "json",
                str(snapshot_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if completed.returncode != 0:
            raise AcceptanceError(f"ffprobe rejected recording: {completed.stderr.strip()}")
        try:
            probe = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise AcceptanceError("ffprobe produced invalid JSON") from error
        summary = validate_probe_payload(
            probe,
            file_size=file_size,
            recording_contract=recording,
        )
        digest = _sha256(snapshot_path)
        _require_recording_identity(path, identity)

    metadata = {
        "schema_version": recording["metadata_schema_version"],
        "recording": path.name,
        "sha256": digest,
        "size": file_size,
        **summary,
    }
    if source_sha is not None:
        if len(source_sha) != 40 or any(ch not in "0123456789abcdef" for ch in source_sha):
            raise AcceptanceError("source SHA must be 40 lowercase hexadecimal characters")
        metadata["source_sha"] = source_sha

    # Acquire every directory before the first write. Opening each parent
    # independently during publication permits cross-sidecar rename attacks.
    pinned_directories: dict[Path, int] = {}
    published_sidecars: list[tuple[Path, tuple[int, int], int]] = []
    try:
        for sidecar in (metadata_path, digest_path):
            if sidecar is not None:
                sidecar.parent.mkdir(parents=True, exist_ok=True)
                pinned_directories[sidecar] = os.open(
                    sidecar.parent,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                )

        def confirm_all_parents() -> None:
            for sidecar, directory in pinned_directories.items():
                _require_sidecar_parent(sidecar, directory)

        confirm_all_parents()
        if metadata_path is not None:
            pinned = pinned_directories[metadata_path]
            published_sidecars.append((
                metadata_path,
                _publish_recording_sidecar(
                    metadata_path, json.dumps(metadata, indent=2, sort_keys=True) + "\n",
                    directory_fd=pinned,
                ),
                pinned,
            ))
            confirm_all_parents()
        if digest_path is not None:
            pinned = pinned_directories[digest_path]
            published_sidecars.append((
                digest_path,
                _publish_recording_sidecar(
                    digest_path, f"{digest}  {path.name}\n", directory_fd=pinned,
                ),
                pinned,
            ))
            confirm_all_parents()
        # A second sidecar must not overwrite or substitute the first one.
        for sidecar, owned_identity, directory in published_sidecars:
            observed = os.stat(sidecar.name, dir_fd=directory, follow_symlinks=False)
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_nlink != 1
                or (observed.st_dev, observed.st_ino) != owned_identity
            ):
                raise AcceptanceError("recording sidecar changed during publication")
        _require_recording_identity(path, identity)
        confirm_all_parents()
    except (OSError, AcceptanceError):
        for sidecar, owned_identity, directory in reversed(published_sidecars):
            try:
                _unlink_owned_recording_sidecar(
                    sidecar, owned_identity, directory_fd=directory,
                )
            except OSError:
                pass  # Preserve the original verification failure.
        raise
    finally:
        for directory in pinned_directories.values():
            os.close(directory)
    return metadata


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Linura v0.10 workstation acceptance helper")
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    sub = parser.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan")
    plan.add_argument("--mode", choices=MODES, required=True)
    plan.add_argument("--display", default="none")
    plan.add_argument("--record", action="store_true")
    plan.add_argument("--json", action="store_true")

    doctor_parser = sub.add_parser("doctor")
    doctor_parser.add_argument("--mode", choices=MODES, required=True)
    doctor_parser.add_argument("--display", default="none")
    doctor_parser.add_argument(
        "--fixture-contract",
        type=Path,
        default=DEFAULT_HARDWARE_FIXTURE_CONTRACT,
    )
    doctor_parser.add_argument("--fixture-id")
    doctor_parser.add_argument("--record", action="store_true")

    hardware_cases = sub.add_parser("hardware-cases")
    hardware_cases.add_argument("--json", action="store_true")

    case_request = sub.add_parser("hardware-case-request")
    case_request.add_argument("--case", required=True)
    case_request.add_argument("--run-id", required=True)
    case_request.add_argument("--fixture-id", required=True)
    case_request.add_argument("--source-sha", required=True)

    run_requests = sub.add_parser("hardware-run-requests")
    run_requests.add_argument("--run-id", required=True)
    run_requests.add_argument("--fixture-id", required=True)
    run_requests.add_argument("--source-sha", required=True)

    sub.add_parser("sanitize-monitors")

    fixture_check = sub.add_parser("fixture-check")
    fixture_check.add_argument(
        "--fixture-contract",
        type=Path,
        default=DEFAULT_HARDWARE_FIXTURE_CONTRACT,
    )
    fixture_check.add_argument("--fixture-id", required=True)

    verify = sub.add_parser("verify-recording")
    verify.add_argument("path", type=Path)
    verify.add_argument("--metadata", type=Path)
    verify.add_argument("--digest-file", type=Path)
    verify.add_argument("--source-sha")

    args = parser.parse_args(argv[1:])
    try:
        contract = load_contract(args.contract)
        if args.command == "plan":
            payload = plan_payload(contract, args.mode, args.display, args.record)
            if args.json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                for key, value in payload.items():
                    print(f"{key}={json.dumps(value, sort_keys=True)}")
            return 0
        if args.command == "doctor":
            missing = doctor(
                args.mode,
                args.display,
                fixture_contract=args.fixture_contract,
                fixture_id=args.fixture_id,
                record=args.record,
            )
            for item in missing:
                print(f"missing: {item}")
            if not missing:
                print(f"{args.mode} acceptance prerequisites available")
            return 0 if not missing else 1
        if args.command == "hardware-cases":
            case_plan = level_c_case_plan(contract)
            if args.json:
                print(json.dumps(case_plan, indent=2, sort_keys=True))
            else:
                for item in case_plan:
                    print(
                        f"{item['id']} mechanism={item['mechanism']} "
                        f"prerequisite={item['prerequisite_slice']} "
                        f"status={item['prerequisite_status']} ready={str(item['ready']).lower()}"
                    )
            return 0
        if args.command == "hardware-case-request":
            request = hardware_case_request(
                contract,
                case_id=args.case,
                run_id=args.run_id,
                fixture_id=args.fixture_id,
                source_sha=args.source_sha,
            )
            print(json.dumps(request, indent=2, sort_keys=True))
            return 0
        if args.command == "hardware-run-requests":
            requests = hardware_run_requests(
                contract,
                run_id=args.run_id,
                fixture_id=args.fixture_id,
                source_sha=args.source_sha,
            )
            print(json.dumps(requests, indent=2, sort_keys=True))
            return 0
        if args.command == "sanitize-monitors":
            print(json.dumps(read_sanitized_hyprland_monitors(), sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "fixture-check":
            payload, fixture_digest = read_hardware_fixture(
                args.fixture_contract,
                fixture_id=args.fixture_id,
            )
            result = {
                "fixture": payload,
                "sha256": fixture_digest,
                "path": str(args.fixture_contract),
            }
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        metadata = verify_recording(
            Path(os.path.abspath(args.path)),
            contract=contract,
            metadata_path=Path(os.path.abspath(args.metadata)) if args.metadata else None,
            digest_path=Path(os.path.abspath(args.digest_file)) if args.digest_file else None,
            source_sha=args.source_sha,
        )
        print(json.dumps(metadata, indent=2, sort_keys=True))
        return 0
    except (AcceptanceError, OSError, subprocess.TimeoutExpired) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
