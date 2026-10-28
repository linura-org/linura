#!/usr/bin/env python3
"""Stage the exact reviewed Hyprland source integration; never install host tools.

This consumes an explicitly supplied, published-digest-pinned release archive.
It neither downloads mutable sources nor compiles/installs/qualifies a compositor.
Native build and qualification remain separate mandatory steps.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PIN = "contracts/hyprland-display-integration.toml"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_UNPACKED = 512 * 1024 * 1024
MAX_MEMBERS = 100_000


class SourceError(ValueError):
    pass


def extract_verified_archive(
    archive: Path, destination: Path, digest: str, top: str
) -> Path:
    """Extract verified immutable bytes, with no archive-created links.

    Keeping the original descriptor alone would not prevent in-place writes
    after verification. The bounded immutable copy is the extraction input.
    """
    descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 0 < metadata.st_size <= MAX_ARCHIVE
        ):
            raise SourceError("pinned source archive is not a bounded regular file")
        content = stream.read(MAX_ARCHIVE + 1)
        if len(content) != metadata.st_size or len(content) > MAX_ARCHIVE:
            raise SourceError("pinned source archive changed while reading")
        if hashlib.sha256(content).hexdigest() != digest:
            raise SourceError("pinned source archive checksum mismatch")
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as source:
            members: list[tarfile.TarInfo] = []
            seen: set[str] = set()
            total = 0
            for member in source:
                path = PurePosixPath(member.name)
                total += member.size
                if (
                    len(members) >= MAX_MEMBERS
                    or member.size < 0
                    or total > MAX_UNPACKED
                    or not (member.isdir() or member.isfile())
                    or path.is_absolute()
                    or not path.parts
                    or path.parts[0] != top
                    or ".." in path.parts
                    or path.as_posix() in seen
                    or member.name.rstrip("/") != path.as_posix()
                    or any(ord(c) < 32 or c == "\\" for c in member.name)
                ):
                    raise SourceError("unsafe or over-budget pinned source archive")
                seen.add(path.as_posix())
                members.append(member)
            if not members:
                raise SourceError("pinned source archive is empty")
            # Reject an archive declaring a regular file as another member's
            # parent before creating anything, including reversed entry order.
            regular = {PurePosixPath(m.name) for m in members if m.isfile()}
            if any(
                any(p in regular for p in PurePosixPath(m.name).parents)
                for m in members
            ):
                raise SourceError("pinned source archive has conflicting parents")
            destination.mkdir(mode=0o700, parents=False, exist_ok=False)
            for member in members:
                target = destination / member.name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                if member.isdir():
                    target.mkdir(mode=0o700, exist_ok=True)
                    continue
                data = source.extractfile(member)
                if data is None:
                    raise SourceError("pinned source member is unreadable")
                output = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o755 if member.mode & 0o111 else 0o644,
                )
                with data, os.fdopen(output, "wb") as installed:
                    shutil.copyfileobj(data, installed, 1024 * 1024)
    return destination / top


def replace_exact(text: str, old: str, new: str, count: int = 1) -> str:
    if text.count(old) != count:
        raise SourceError("reviewed native integration point no longer matches")
    return text.replace(old, new)


def stamp_version_template(text: str, upstream_commit: str) -> str:
    # The release archive contains literal Git metadata in this template;
    # assigning CMake variables does not change those literals. Keep the actual
    # upstream revision and identify our modified compositor honestly.
    if text.count(f'#define GIT_COMMIT_HASH    "{upstream_commit}"') != 1:
        raise SourceError("pinned version template has another upstream identity")
    text = replace_exact(
        text,
        '#define GIT_DIRTY          "clean"',
        '#define GIT_DIRTY          "linura-display-integration"',
    )
    return replace_exact(
        text,
        '#define GIT_TAG            "v0.56.2"',
        '#define GIT_TAG            "v0.56.2+linura-display-v1"',
    )


def patch_sources(inputs: dict[str, str], upstream_commit: str) -> dict[str, str]:
    """Construct all outputs before any write. No fuzzy patches or symbol hooks."""
    outputs = dict(inputs)
    outputs["src/version.h.in"] = stamp_version_template(
        outputs["src/version.h.in"], upstream_commit
    )
    include = '#include "pinned_integration.h"\n'
    manager = "src/config/shared/monitor/MonitorRuleManager.cpp"
    text = outputs[manager]
    start = text.index("CMonitorRule CMonitorRuleManager::get(")
    end = text.index("const std::vector<CMonitorRule>&", start)
    getter = replace_exact(
        text[start:end],
        "return rule;",
        "return Linura::HyprlandDisplay::overlayRule(PMONITOR.get(), std::move(rule));",
        2,
    )
    outputs[manager] = include + text[:start] + getter + text[end:]

    compositor = "src/Compositor.cpp"
    text = replace_exact(
        outputs[compositor],
        "    m_wlEventLoop = wl_display_get_event_loop(m_wlDisplay);",
        "    m_wlEventLoop = wl_display_get_event_loop(m_wlDisplay);\n"
        "    Linura::HyprlandDisplay::initialize(*m_wlDisplay, *m_wlEventLoop);",
    )
    text = replace_exact(
        text,
        "void CCompositor::cleanup() {\n    if (!m_wlDisplay)\n        return;",
        "void CCompositor::cleanup() {\n    if (!m_wlDisplay)\n        return;\n"
        "    Linura::HyprlandDisplay::shutdown();",
    )
    outputs[compositor] = include + text

    lock = "src/protocols/SessionLock.cpp"
    text = replace_exact(
        outputs[lock],
        "        PROTO::sessionLock->m_locked = false;",
        "        Linura::HyprlandDisplay::lockReleased();\n"
        "        PROTO::sessionLock->m_locked = false;",
    )
    text = replace_exact(
        text,
        "    m_locked = false;",
        "    Linura::HyprlandDisplay::lockReleased();\n    m_locked = false;",
    )
    outputs[lock] = include + text

    monitor = "src/output/Monitor.cpp"
    text = replace_exact(
        outputs[monitor],
        "bool CMonitorState::commit() {\n    if (!updateSwapchain())\n        return false;",
        "bool CMonitorState::commit() {\n    if (!updateSwapchain()) {\n"
        "        Linura::HyprlandDisplay::commitObserved(m_owner, false);\n"
        "        return false;\n    }",
    )
    text = replace_exact(
        text,
        "    bool ret = m_owner->m_output->commit();\n    return ret;",
        "    bool ret = m_owner->m_output->commit();\n"
        "    Linura::HyprlandDisplay::commitObserved(m_owner, ret);\n    return ret;",
    )
    text = replace_exact(
        text,
        "void CMonitor::scheduleModeRetry() {",
        "void CMonitor::scheduleModeRetry() {\n"
        "    if (Linura::HyprlandDisplay::ownsMonitor(this)) {\n"
        "        clearModeRetry();\n        return;\n    }",
    )
    outputs[monitor] = include + text

    cmake = "CMakeLists.txt"
    text = outputs[cmake]
    outputs[cmake] = (
        text
        + "\n"
        + """# Exact-source Linura integration; no unqualified fallback build.
if(NOT IS_DIRECTORY "${LINURA_DISPLAY_INTEGRATION_DIR}")
  message(FATAL_ERROR "LINURA_DISPLAY_INTEGRATION_DIR must name the reviewed Linura native source")
endif()
add_subdirectory("${LINURA_DISPLAY_INTEGRATION_DIR}" "${CMAKE_BINARY_DIR}/linura-display")
pkg_check_modules(LINURA_DISPLAY_SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
target_sources(hyprland_lib PRIVATE "${LINURA_DISPLAY_INTEGRATION_DIR}/pinned_backend.cpp"
  "${LINURA_DISPLAY_INTEGRATION_DIR}/native_power_inhibitor.cpp"
  "${LINURA_DISPLAY_INTEGRATION_DIR}/native_owner_admission.cpp")
target_include_directories(hyprland_lib PRIVATE "${LINURA_DISPLAY_INTEGRATION_DIR}" "${CMAKE_SOURCE_DIR}")
target_link_libraries(hyprland_lib PUBLIC linura-hyprland-display-owner PkgConfig::LINURA_DISPLAY_SYSTEMD)
if(TARGET hyprland_gtests)
  target_sources(hyprland_gtests PRIVATE "${LINURA_DISPLAY_INTEGRATION_DIR}/tests/pinned_rule_overlay.cpp"
    "${LINURA_DISPLAY_INTEGRATION_DIR}/tests/pinned_owner_admission.cpp"
    "${LINURA_DISPLAY_INTEGRATION_DIR}/tests/pinned_output_identity.cpp")
  target_include_directories(hyprland_gtests PRIVATE "${LINURA_DISPLAY_INTEGRATION_DIR}")
endif()
"""
    )
    return outputs


def stage(archive: Path, destination: Path, root: Path = ROOT) -> dict[str, object]:
    pin = tomllib.loads((root / PIN).read_text(encoding="utf-8"))
    if (
        pin.get("schema_version") != 1
        or pin.get("integration_id") != "linura-hyprland-display-v1"
    ):
        raise SourceError("unsupported native integration source contract")
    source = extract_verified_archive(
        archive, destination, pin["source_sha256"], pin["source_top"]
    )
    inputs: dict[str, str] = {}
    for item in pin["upstream_file"]:
        path = PurePosixPath(item["path"])
        if path.is_absolute() or ".." in path.parts or path.as_posix() in inputs:
            raise SourceError("invalid native integration input path")
        data = (source / path).read_bytes()
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise SourceError("reviewed upstream source checksum mismatch")
        inputs[path.as_posix()] = data.decode("utf-8")
    outputs = patch_sources(inputs, pin["upstream_commit"])
    digests = {}
    for name, text in outputs.items():
        (source / name).write_text(text, encoding="utf-8")
        digests[name] = hashlib.sha256(text.encode()).hexdigest()
    manifest = {
        "schema_version": 1,
        "integration_id": pin["integration_id"],
        "upstream_commit": pin["upstream_commit"],
        "source_sha256": pin["source_sha256"],
        "patched_files": digests,
        "qualification_evidence": False,
    }
    (destination / "linura-display-source.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument(
        "--destination",
        type=Path,
        required=True,
        help="new staging directory; existing destinations are rejected",
    )
    args = parser.parse_args()
    try:
        print(json.dumps(stage(args.archive, args.destination), indent=2))
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        parser.exit(1, f"native source staging failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
