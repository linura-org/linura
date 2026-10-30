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
        "        if (!Linura::HyprlandDisplay::lockReleased())\n"
        "            return;\n"
        "        PROTO::sessionLock->m_locked = false;",
    )
    text = replace_exact(
        text,
        "    m_locked = false;",
        "    if (!Linura::HyprlandDisplay::lockReleased())\n"
        "        return;\n    m_locked = false;",
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

    # A distinct native role/presentation never changes ext-session-lock state.
    role = "src/protocols/types/SurfaceRole.hpp"
    outputs[role] = replace_exact(
        outputs[role],
        "    SURFACE_ROLE_CURSOR,",
        "    SURFACE_ROLE_CURSOR,\n    SURFACE_ROLE_LINURA_PROTECTED,",
    )
    private_include = '#include "pinned_protected.h"\n'
    text = outputs[monitor]
    text = replace_exact(
        text,
        "    bool ret = m_owner->m_output->commit();",
        "    const auto protectedCommit = Linura::HyprlandDisplay::commitProtectedDisplay(m_owner);\n"
        "    bool ret = protectedCommit ? *protectedCommit : m_owner->m_output->commit();",
    )
    text = replace_exact(
        text,
        "    Event::bus()->m_events.monitor.preCommit.emit(m_owner->m_self.lock());",
        "    if (!Linura::HyprlandDisplay::protectedDisplayActive())\n"
        "        Event::bus()->m_events.monitor.preCommit.emit(m_owner->m_self.lock());",
    )
    outputs[monitor] = private_include + text

    renderer = "src/render/Renderer.cpp"
    text = outputs[renderer]
    text = replace_exact(
        text,
        "    if (canAttemptDirectScanout) {",
        "    if (canAttemptDirectScanout && !Linura::HyprlandDisplay::protectedDisplayActive()) {",
    )
    text = replace_exact(
        text,
        "    bool renderCursor = true;",
        "    bool renderCursor = true;\n"
        "    const bool linuraProtected = Linura::HyprlandDisplay::renderProtectedDisplay(pMonitor.get(), NOW);\n"
        "    if (linuraProtected) { renderCursor = false; } else {",
    )
    text = replace_exact(
        text,
        "    renderCursor = renderCursor && shouldRenderCursor();",
        "    } // Ordinary scene, IME and overlays are excluded from protected presentation.\n"
        "    renderCursor = renderCursor && shouldRenderCursor();",
    )
    for stage in ["RENDER_BEGIN", "RENDER_LAST_MOMENT", "RENDER_POST"]:
        old = f"    Event::bus()->m_events.render.stage.emit({stage});"
        text = replace_exact(
            text,
            old,
            "    if (!Linura::HyprlandDisplay::protectedDisplayActive())\n"
            + "    "
            + old,
        )
    text = replace_exact(
        text,
        "    if (pMonitor->m_dpmsBlackOpacity->value() != 0.F) {",
        "    if (!linuraProtected && pMonitor->m_dpmsBlackOpacity->value() != 0.F) {",
    )
    text = replace_exact(
        text,
        "    if (*PDAMAGETRACKINGMODE == DAMAGE_TRACKING_NONE || *PDAMAGETRACKINGMODE == DAMAGE_TRACKING_MONITOR || pMonitor->m_forceFullFrames > 0 || damageBlinkCleanup > 0)",
        "    if (Linura::HyprlandDisplay::protectedDisplayActive() || *PDAMAGETRACKINGMODE == DAMAGE_TRACKING_NONE || *PDAMAGETRACKINGMODE == DAMAGE_TRACKING_MONITOR || pMonitor->m_forceFullFrames > 0 || damageBlinkCleanup > 0)",
    )
    text = replace_exact(
        text,
        "    endRender();\n\n    TRACY_GPU_COLLECT;",
        "    SP<Aquamarine::IBuffer> linuraRenderedBuffer;\n"
        "    if (linuraProtected) linuraRenderedBuffer = m_currentBuffer;\n"
        "    endRender();\n"
        "    if (linuraProtected)\n"
        "        Linura::HyprlandDisplay::protectedFrameRendered(pMonitor.get(), linuraRenderedBuffer.get());\n\n"
        "    TRACY_GPU_COLLECT;",
    )
    outputs[renderer] = private_include + text

    input_manager = "src/managers/input/InputManager.cpp"
    text = outputs[input_manager]
    functions = {
        "void CInputManager::onKeyboardKey(const IKeyboard::SKeyEvent& event, SP<IKeyboard> pKeyboard) {": "protectedKeyboardKey(event, pKeyboard)",
        "void CInputManager::onKeyboardMod(SP<IKeyboard> pKeyboard) {": "protectedKeyboardModifiers(pKeyboard)",
        "void CInputManager::onMouseMoved(IPointer::SMotionEvent e) {": "protectedPointerMove(e)",
        "void CInputManager::onMouseWarp(IPointer::SMotionAbsoluteEvent e) {": "protectedPointerWarp(e)",
        "void CInputManager::onMouseButton(IPointer::SButtonEvent e, SP<IPointer> mouse) {": "protectedPointerButton(e, mouse)",
        "void CInputManager::mouseMoveUnified(uint32_t time, bool refocus, bool mouse, std::optional<Vector2D> overridePos) {": "protectedPointerRefocus(time)",
    }
    for signature, call in functions.items():
        text = replace_exact(
            text,
            signature,
            signature + "\n    if (Linura::HyprlandDisplay::" + call + ") return;",
        )
    # These families cannot be injected into the protected relative-pointer /
    # physical-keyboard conversation or escape to an ordinary focused client.
    for signature in [
        "void CInputManager::onMouseWheel(IPointer::SAxisEvent e, SP<IPointer> pointer) {",
        "void CInputManager::onPointerFrame() {",
        "void CInputManager::onSwipeBegin(IPointer::SSwipeBeginEvent e) {",
        "void CInputManager::onSwipeUpdate(IPointer::SSwipeUpdateEvent e) {",
        "void CInputManager::onSwipeEnd(IPointer::SSwipeEndEvent e) {",
        "void CInputManager::onPinchBegin(IPointer::SPinchBeginEvent e) {",
        "void CInputManager::onPinchUpdate(IPointer::SPinchUpdateEvent e) {",
        "void CInputManager::onPinchEnd(IPointer::SPinchEndEvent e) {",
    ]:
        text = replace_exact(
            text,
            signature,
            signature
            + "\n    if (Linura::HyprlandDisplay::protectedInputExclusive()) return;",
        )
    outputs[input_manager] = private_include + text

    for path, signatures in {
        "src/managers/input/Touch.cpp": [
            "void CInputManager::onTouchDown(ITouch::SDownEvent e) {",
            "void CInputManager::onTouchUp(ITouch::SUpEvent e) {",
            "void CInputManager::onTouchMove(ITouch::SMotionEvent e) {",
        ],
        "src/managers/input/Tablets.cpp": [
            "void CInputManager::onTabletAxis(CTablet::SAxisEvent e) {",
            "void CInputManager::onTabletTip(CTablet::STipEvent e) {",
            "void CInputManager::onTabletButton(CTablet::SButtonEvent e) {",
            "void CInputManager::onTabletProximity(CTablet::SProximityEvent e) {",
        ],
    }.items():
        text = outputs[path]
        for signature in signatures:
            text = replace_exact(
                text,
                signature,
                signature
                + "\n    if (Linura::HyprlandDisplay::protectedInputExclusive()) return;",
            )
        outputs[path] = private_include + text

    seat = "src/managers/SeatManager.cpp"
    text = outputs[seat]
    for signature, call in {
        "void CSeatManager::setKeyboardFocus(SP<CWLSurfaceResource> surf) {": "protectedKeyboardFocusAllowed",
        "void CSeatManager::setPointerFocus(SP<CWLSurfaceResource> surf, const Vector2D& local) {": "protectedPointerFocusAllowed",
    }.items():
        text = replace_exact(
            text,
            signature,
            signature
            + "\n    if (!Linura::HyprlandDisplay::"
            + call
            + "(surf)) return;",
        )
    outputs[seat] = private_include + text

    # Private presentation suppresses hardware cursors directly. Do not borrow
    # the upstream per-monitor software-lock counters: hotplug changes that set.
    pointer_header = "src/pointer/PointerManager.hpp"
    outputs[pointer_header] = replace_exact(
        outputs[pointer_header],
        "        void lockSoftwareAll();",
        "        void refreshProtectedCursorFence();\n"
        "        bool protectedCursorFenceReady();\n"
        "        void lockSoftwareAll();",
    )
    pointer = "src/pointer/PointerManager.cpp"
    text = replace_exact(
        outputs[pointer],
        "        if (state->softwareLocks > 0 || m->shouldUseSoftwareCursors() || !attemptHardwareCursor(state)) {",
        "        if (Linura::HyprlandDisplay::protectedDisplayActive() || state->softwareLocks > 0 || m->shouldUseSoftwareCursors() || !attemptHardwareCursor(state)) {",
    )
    text = replace_exact(
        text,
        "void CPointerManager::updateCursorBackend() {",
        "void CPointerManager::refreshProtectedCursorFence() { updateCursorBackend(); }\n\n"
        "bool CPointerManager::protectedCursorFenceReady() {\n"
        "    if (!Linura::HyprlandDisplay::protectedDisplayActive()) return false;\n"
        "    for (const auto& monitor : State::monitorState()->monitors()) {\n"
        "        if (!monitor->m_enabled || !monitor->m_dpmsStatus) continue;\n"
        "        const auto state = stateFor(monitor);\n"
        "        if (!state->initialPlaneCleared || state->hwApplied || state->cursorFrontBuffer) return false;\n"
        "    }\n    return true;\n}\n\n"
        "void CPointerManager::updateCursorBackend() {",
    )
    outputs[pointer] = private_include + text

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
pkg_check_modules(LINURA_DISPLAY_UDEV REQUIRED IMPORTED_TARGET libudev)
target_sources(hyprland_lib PRIVATE "${LINURA_DISPLAY_INTEGRATION_DIR}/pinned_backend.cpp"
  "${LINURA_DISPLAY_INTEGRATION_DIR}/native_power_inhibitor.cpp"
  "${LINURA_DISPLAY_INTEGRATION_DIR}/native_owner_admission.cpp"
  "${LINURA_DISPLAY_INTEGRATION_DIR}/pinned_protected.cpp")
target_include_directories(hyprland_lib PRIVATE "${LINURA_DISPLAY_INTEGRATION_DIR}" "${CMAKE_SOURCE_DIR}")
target_link_libraries(hyprland_lib PUBLIC linura-hyprland-display-owner linura-hyprland-protected-wire PkgConfig::LINURA_DISPLAY_SYSTEMD PkgConfig::LINURA_DISPLAY_UDEV)
if(TARGET hyprland_gtests)
  target_sources(hyprland_gtests PRIVATE "${LINURA_DISPLAY_INTEGRATION_DIR}/tests/pinned_rule_overlay.cpp"
    "${LINURA_DISPLAY_INTEGRATION_DIR}/tests/pinned_owner_admission.cpp"
    "${LINURA_DISPLAY_INTEGRATION_DIR}/tests/pinned_output_identity.cpp")
  target_include_directories(hyprland_gtests PRIVATE "${LINURA_DISPLAY_INTEGRATION_DIR}")
endif()
"""
    )
    return outputs
