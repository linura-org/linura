#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
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
EXPECTED_REQUIRED_VISUAL_SURFACES = [
    "linura-firstboot",
    "linura-control-center",
    "command-palette",
    "quick-settings",
    "desktop-shell-integration",
    "notifications-osd",
]
EXPECTED_ALLOWED_VISUAL_SURFACES = set(EXPECTED_REQUIRED_VISUAL_SURFACES) | {"approval-dialog"}

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
    "visual_baseline_manifest": "visual/baselines/manifest.json",
    "experience_evidence_manifest": "qualification/v010/experience-evidence.json",
    "representative_visual_scales": [1.0, 2.0],
    "representative_visual_resolutions": ["1280x800", "1440x900"],
    "required_visual_surfaces": EXPECTED_REQUIRED_VISUAL_SURFACES,
    "required_accessibility_surfaces": [
        "linura-firstboot",
        "linura-control-center",
        "command-palette",
        "quick-settings",
        "desktop-shell-integration",
        "notifications-osd",
    ],
    "require_reviewed_non_null_visual_baselines": True,
    "require_representative_resolution_scale_captures": True,
    "require_retained_visual_failure_diffs": True,
    "require_visual_interaction_evidence": True,
    "require_screen_reader_semantics": True,
    "require_reduced_motion": True,
    "require_display_scaling": True,
    "require_offline_error_states": True,
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
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_MAX_BYTES = 64 * 1024 * 1024
PNG_MAX_PIXELS = 32 * 1024 * 1024
PNG_BYTES_PER_PIXEL = {0: 1, 2: 3, 4: 2, 6: 4}
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


def _validate_png_artifact(
    path: Path | None,
    expected_digest: object,
    *,
    label: str,
    failures: list[str],
    expected_width: int | None = None,
    expected_height: int | None = None,
) -> tuple[int, int, bytes] | None:
    if path is None:
        return None
    if path.suffix.lower() != ".png":
        failures.append(f"{label} must be a PNG artifact")
        return None
    if not isinstance(expected_digest, str) or not SHA256_RE.fullmatch(expected_digest):
        failures.append(f"{label} must carry a lowercase SHA-256 digest")
        return None
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

    baseline_ids: set[str] = set()
    baseline_metadata: dict[str, tuple[int, int, float, str]] = {}
    baseline_images: dict[str, tuple[int, int, bytes]] = {}
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
        )
        if baseline_image is not None and isinstance(baseline_digest, str):
            baseline_images[baseline_id] = baseline_image
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

    comparisons = evidence.get("visual_comparisons")
    covered_baselines: set[str] = set()
    if not isinstance(comparisons, list) or not comparisons:
        failures.append("v0.10 experience evidence requires visual_comparisons")
    else:
        for index, item in enumerate(comparisons):
            if not isinstance(item, dict):
                failures.append(f"visual comparison {index} must be an object")
                continue
            baseline_id = item.get("baseline_id")
            metadata = baseline_metadata.get(str(baseline_id))
            if baseline_id not in baseline_ids or metadata is None:
                failures.append(f"visual comparison {index} references unknown or invalid baseline")
                continue
            covered_baselines.add(str(baseline_id))
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
            )
            baseline_image = baseline_images.get(str(baseline_id))
            if (
                baseline_image is not None
                and capture_image is not None
                and capture_image != baseline_image
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
            )
            baseline_image = baseline_images.get(baseline_id)
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
            _validate_png_artifact(
                diff_path,
                diff_digest,
                label=label,
                failures=failures,
                expected_width=metadata[0],
                expected_height=metadata[1],
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

        checks = report.get("checks")
        if not isinstance(checks, dict):
            failures.append(f"interaction/accessibility report {surface} missing checks")
            continue
        for key in required_checks:
            if checks.get(key) != "pass":
                failures.append(
                    f"interaction/accessibility report {surface} checks.{key} must be pass"
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
    experience = contract.get("experience")
    if not isinstance(experience, dict):
        failures.append("v0.10 qualification contract missing experience")
    else:
        static_experience = dict(experience)
        static_experience.pop("experience_evidence_ready", None)
        static_experience.pop("experience_evidence_manifest_sha256", None)
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

    if isinstance(experience, dict):
        experience_ready = experience.get("experience_evidence_ready")
        if not isinstance(experience_ready, bool):
            failures.append("experience.experience_evidence_ready must be boolean")
        if experience_ready is True:
            _validate_experience_evidence(root, experience, failures)

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
