"""Exact source-pinned Hyprland hooks, included in the live integration ID.

Pure source transformation only. Archive admission, staging and build orchestration
remain repository tooling. Both the owner and compositor hash these same bytes.
"""

from __future__ import annotations


class SourceError(ValueError):
    pass


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
        "    if (!Linura::HyprlandDisplay::ownedCommitAllowed()) {\n"
        "        Linura::HyprlandDisplay::commitObserved(m_owner, false);\n"
        "        return false;\n    }\n"
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

    # Direct scanout bypasses CMonitorState::commit and can consume pending
    # output state after an earlier refused modeset. Fence both paths too.
    text = replace_exact(
        outputs[monitor],
        "            if (!m_output->commit()) {",
        "            if (!Linura::HyprlandDisplay::ownedCommitAllowed()) {\n"
        "                Linura::HyprlandDisplay::commitObserved(this, false);\n"
        "                return false;\n            }\n"
        "            if (!m_output->commit()) {",
    )
    outputs[monitor] = replace_exact(
        text,
        "    bool ok = m_output->commit();",
        "    if (!Linura::HyprlandDisplay::ownedCommitAllowed()) {\n"
        "        Linura::HyprlandDisplay::commitObserved(this, false);\n"
        "        return false;\n    }\n"
        "    bool ok = m_output->commit();",
    )

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
