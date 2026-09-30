#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = ROOT / "contracts/v010-workstation-acceptance.toml"
MODES = ("automated", "interactive", "hardware")
INTERACTIVE_DISPLAYS = ("gtk", "vnc")


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
        }
        for key, value in required.items():
            if level_c.get(key) != value:
                failures.append(f"level_c.{key} must remain {value!r}")

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


def _which(command: str) -> bool:
    return shutil.which(command) is not None


def doctor(mode: str, display: str) -> list[str]:
    missing: list[str] = []
    if mode in {"automated", "interactive"}:
        commands = ["qemu-system-x86_64", "qemu-img", "ssh", "scp", "ssh-keygen", "cloud-localds", "git"]
        if mode == "interactive":
            commands.extend(["cargo", "rustup"])
        for command in commands:
            if not _which(command):
                missing.append(command)
    if mode == "interactive" and display == "gtk":
        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            missing.append("host graphical display environment (DISPLAY or WAYLAND_DISPLAY)")
    if mode == "hardware":
        for command in ("wf-recorder", "ffprobe", "hyprctl", "systemctl", "python3"):
            if not _which(command):
                missing.append(command)
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
        launcher = contract["hardware_capture"]
    return {
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


def verify_recording(
    path: Path,
    *,
    contract: dict[str, Any],
    metadata_path: Path | None = None,
    source_sha: str | None = None,
) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise AcceptanceError(f"recording is missing or unsafe: {path}")
    recording = contract["recording"]
    if path.suffix != recording["extension"]:
        raise AcceptanceError(f"recording extension must be {recording['extension']}")
    file_size = path.stat().st_size
    if file_size < recording["minimum_bytes"]:
        raise AcceptanceError("recording is below the minimum bounded size")
    if file_size > recording["maximum_bytes"]:
        raise AcceptanceError("recording exceeds the maximum bounded size")
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
            str(path),
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
    digest = _sha256(path)
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

    if metadata_path is not None:
        if metadata_path.exists() and metadata_path.is_symlink():
            raise AcceptanceError("recording metadata path must not be a symlink")
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
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

    verify = sub.add_parser("verify-recording")
    verify.add_argument("path", type=Path)
    verify.add_argument("--metadata", type=Path)
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
            missing = doctor(args.mode, args.display)
            for item in missing:
                print(f"missing: {item}")
            if not missing:
                print(f"{args.mode} acceptance prerequisites available")
            return 0 if not missing else 1
        metadata = verify_recording(
            Path(os.path.abspath(args.path)),
            contract=contract,
            metadata_path=Path(os.path.abspath(args.metadata)) if args.metadata else None,
            source_sha=args.source_sha,
        )
        print(json.dumps(metadata, indent=2, sort_keys=True))
        return 0
    except (AcceptanceError, OSError, subprocess.TimeoutExpired) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
