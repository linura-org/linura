#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = (
    ".github/workflows/ci.yml",
    "apps/linura-shell/README.md",
    "apps/linura-shell/shell.qml",
    "apps/linura-shell/ui/README.md",
    "apps/linura-shell/ui/CMakeLists.txt",
    "apps/linura-shell/ui/LinuraTheme.qml",
    "apps/linura-shell/ui/LinuraIconButton.qml",
    "apps/linura-shell/ui/LinuraSwitch.qml",
    "apps/linura-shell/ui/LinuraTextField.qml",
    "apps/linura-shell/ui/LinuraActionRow.qml",
    "apps/linura-shell/ui/LinuraCard.qml",
    "apps/linura-shell/ui/LinuraStatus.qml",
    "apps/linura-shell/ui/LinuraDivider.qml",
    "apps/linura-shell/ui/LinuraPopover.qml",
    "apps/linura-shell/ui/LinuraDialog.qml",
    "apps/linura-shell/ui/LinuraSurface.qml",
    "apps/linura-shell/ui/LinuraText.qml",
    "apps/linura-shell/ui/LinuraButton.qml",
    "apps/linura-shell/ui/LinuraSlider.qml",
    "apps/linura-shell/plugins/control-center/manifest.json",
    "apps/linura-shell/plugins/control-center/ControlCenterPanel.qml",
    "apps/linura-shell/plugins/command-palette/manifest.json",
    "apps/linura-shell/plugins/command-palette/CommandPalette.qml",
    "apps/linura-shell/integrations/hyprland/WorkspaceNavigationController.qml",
    "apps/linura-shell/bridge/CMakeLists.txt",
    "apps/linura-shell/bridge/audio_session_controller.h",
    "apps/linura-shell/bridge/audio_session_controller.cpp",
    "apps/linura-shell/org.linura.ControlCenter.desktop",
    "apps/linura-shell/org.linura.CommandPalette.desktop",
    "apps/linura-control-center/README.md",
    "contracts/components.toml",
    "contracts/v010-workstation-qualification.toml",
    "profiles/arch-hyprland-v1.toml",
    "design/tokens.json",
    "docs/design-system.md",
    "docs/architecture.md",
    "docs/qualification/v0.10.0.md",
    "packaging/arch/archiso/packages.linura",
    "packaging/systemd/user/linura-shell.service",
    "tools/image.py",
)

FORBIDDEN_QML = (
    "import Quickshell.Io",
    "Process {",
    "execDetached",
    "Quickshell.Services.Pipewire",
    "Quickshell.Bluetooth",
    "Quickshell.Networking",
    "Hyprland.dispatch(",
    "HyprlandIpc.dispatch(",
    "linuractl",
    "wpctl",
    "pactl",
    "systemctl",
    "sudo",
    "pkexec",
    "SetAudioOutputVolume",
    "volumeSlider.value =",
)

FORBIDDEN_BRIDGE = (
    "QProcess",
    "std::system",
    "system(",
    "popen(",
    "/usr/bin/",
    "linuractl",
    "wpctl",
    "pactl",
    "systemctl",
    "pkexec",
    "sudo ",
    "org.freedesktop.PolicyKit1",
    "refreshTimer_",
)

REQUIRED_BRIDGE = (
    "QML_ELEMENT",
    "Q_PROPERTY(bool active READ active WRITE setActive NOTIFY activeChanged)",
    "QDBusConnection::sessionBus()",
    '"org.linura.Control1"',
    '"/org/linura/Control1"',
    '"/org/linura/Session1"',
    '"org.linura.Session1"',
    '"Observe"',
    '"SetAudioOutputVolume"',
    '"audio:session:default-output"',
    '"operation:audio.output.set-session-volume"',
    "samePrecondition(",
    "sameIdentity(",
    "draftBase_.value_or(*current_)",
    "ObservePurpose::PreApply",
    "ObservePurpose::PostApply",
    "const quint64 generation = ++observationGeneration_;",
    "generation != observationGeneration_",
    "void AudioSessionController::setActive(bool active)",
    "if (!active_ || busy())",
    "if (!active_ || !current_.has_value() || busy())",
    "freshnessTimer_.setSingleShot(true)",
    "armFreshnessExpiry(snapshot)",
    "control.setTimeout(kObserveTimeoutMs)",
    "session.setTimeout(kEffectTimeoutMs)",
    "isBoundedControlFree(receipt.planId, 256)",
    'QStringLiteral("org.freedesktop.DBus.Error.ServiceUnknown")',
    'QStringLiteral("org.freedesktop.DBus.Error.NameHasNoOwner")',
    'QStringLiteral("org.freedesktop.DBus.Error.NoReply")',
    "isServiceUnavailableError(reply.errorName())",
    "retryTimer_.setSingleShot(true)",
    "retryTimer_.start(delay)",
    "kRetryInitialMs",
    "kRetryMaximumMs",
    "scheduleActiveRetry()",
    "bool dispatched = false;",
    "pending_.has_value() && !pending_->dispatched",
    "pending_->dispatched = true;",
    'QStringLiteral("Control Center is closed.")',
    "observe(ObservePurpose::PostApply)",
)

REQUIRED_CI = (
    "qt6-base-dev",
    "qt6-declarative-dev",
    "cmake -S apps/linura-shell/bridge",
    "cmake --build",
    "cmake --install",
    "cmake -S apps/linura-shell/ui",
    'module_dir="$install_dir/lib/qt6/qml/org/linura/ShellBridge"',
    'test -f "$module_dir/qmldir"',
    'ui_module_dir="$install_dir/lib/qt6/qml/org/linura/UI"',
    'test -f "$ui_module_dir/qmldir"',
)

REQUIRED_IMAGE = (
    'ROOT / "apps/linura-shell/shell.qml"',
    'ROOT / "apps/linura-shell/plugins/control-center/ControlCenterPanel.qml"',
    'ROOT / "apps/linura-shell/plugins/control-center/manifest.json"',
    'ROOT / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"',
    'ROOT / "apps/linura-shell/plugins/command-palette/manifest.json"',
    'ROOT / "apps/linura-shell/integrations/hyprland/WorkspaceNavigationController.qml"',
    'ROOT / "apps/linura-shell/org.linura.ControlCenter.desktop"',
    '"usr/share/applications/org.linura.ControlCenter.desktop"',
    'ROOT / "apps/linura-shell/org.linura.CommandPalette.desktop"',
    '"usr/share/applications/org.linura.CommandPalette.desktop"',
    'ROOT / "packaging/systemd/user/linura-shell.service"',
    "build_shell_bridge(STAGED)",
    'UI_SDK_SOURCE = ROOT / "apps/linura-shell/ui"',
    'UI_SDK_BUILD = ROOT / ".artifacts/linura-ui-build"',
    "build_ui_sdk(STAGED)",
    'SHELL_BRIDGE_QT_MODULES = ("Qt6Core", "Qt6DBus", "Qt6Qml")',
    'UI_SDK_QT_MODULES = ("Qt6Core", "Qt6Qml", "Qt6Quick", "Qt6QuickControls2")',
    "DOCTOR_QT_MODULES = tuple(dict.fromkeys(SHELL_BRIDGE_QT_MODULES + UI_SDK_QT_MODULES))",
    "have_qt_modules(DOCTOR_QT_MODULES)",
    "graphical-session.target.wants/linura-shell.service",
    "default.target.wants/linurad.service",
)


def validate(root: Path) -> list[str]:
    failures: list[str] = []

    for relative in REQUIRED:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            failures.append(f"missing or non-regular Linura Shell file: {relative}")
    if failures:
        return failures

    contract = tomllib.loads(
        (root / "contracts/components.toml").read_text(encoding="utf-8")
    )
    components = {
        item["id"]: item
        for item in contract.get("component", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }

    shell_component = components.get("linura-shell")
    expected_shell = {
        "kind": "shell",
        "workspace_member": False,
        "maturity": "integrated-experimental",
        "activation_milestone": "v0.10.0",
        "release_artifact": False,
        "authority_role": "client",
    }
    if not isinstance(shell_component, dict):
        failures.append("component maturity contract is missing linura-shell")
    else:
        for key, value in expected_shell.items():
            if shell_component.get(key) != value:
                failures.append(f"linura-shell component {key} must remain {value!r}")

    control_center = components.get("linura-control-center")
    expected_control_center = {
        "kind": "planned-app",
        "workspace_member": False,
        "maturity": "roadmap-scaffold",
        "activation_milestone": "v0.10.0",
        "release_artifact": False,
        "authority_role": "client",
    }
    if not isinstance(control_center, dict):
        failures.append("component maturity contract is missing linura-control-center")
    else:
        for key, value in expected_control_center.items():
            if control_center.get(key) != value:
                failures.append(
                    f"standalone linura-control-center {key} must remain {value!r}"
                )

    profile = tomllib.loads(
        (root / "profiles/arch-hyprland-v1.toml").read_text(encoding="utf-8")
    )
    requirements = profile.get("requirements", {})
    if not isinstance(requirements, dict) or requirements.get("quickshell") != ">=0.3.1":
        failures.append(
            "arch-hyprland-v1 must require quickshell >=0.3.1 for typed named/special workspace activation"
        )

    shell_qml = (root / "apps/linura-shell/shell.qml").read_text(encoding="utf-8")
    panel_qml = (
        root / "apps/linura-shell/plugins/control-center/ControlCenterPanel.qml"
    ).read_text(encoding="utf-8")
    palette_qml = (
        root / "apps/linura-shell/plugins/command-palette/CommandPalette.qml"
    ).read_text(encoding="utf-8")
    workspace_controller_qml = (
        root / "apps/linura-shell/integrations/hyprland/WorkspaceNavigationController.qml"
    ).read_text(encoding="utf-8")
    ui_qml = "\n".join(
        (root / relative).read_text(encoding="utf-8")
        for relative in (
            "apps/linura-shell/ui/LinuraTheme.qml",
            "apps/linura-shell/ui/LinuraSurface.qml",
            "apps/linura-shell/ui/LinuraText.qml",
            "apps/linura-shell/ui/LinuraButton.qml",
            "apps/linura-shell/ui/LinuraSlider.qml",
            "apps/linura-shell/ui/LinuraIconButton.qml",
            "apps/linura-shell/ui/LinuraSwitch.qml",
            "apps/linura-shell/ui/LinuraTextField.qml",
            "apps/linura-shell/ui/LinuraActionRow.qml",
            "apps/linura-shell/ui/LinuraCard.qml",
            "apps/linura-shell/ui/LinuraStatus.qml",
            "apps/linura-shell/ui/LinuraDivider.qml",
            "apps/linura-shell/ui/LinuraPopover.qml",
            "apps/linura-shell/ui/LinuraDialog.qml",
        )
    )
    combined_qml = (
        shell_qml
        + "\n"
        + panel_qml
        + "\n"
        + palette_qml
        + "\n"
        + workspace_controller_qml
        + "\n"
        + ui_qml
    )

    for fragment in (
        "import Quickshell",
        "import Quickshell.Hyprland",
        "import org.linura.ShellBridge 1.0",
        'import "plugins/command-palette"',
        'import "integrations/hyprland"',
        "ShellRoot {",
        "IpcHandler {",
        'target: "linura.shell"',
        "function toggleCommandPalette()",
        "GlobalShortcut {",
        'appid: "linura"',
        'name: "commandPalette"',
        "ControlCenterPanel {",
        "WorkspaceNavigationController {",
        "CommandPalette {",
        "workspaceCatalog: workspaceNavigation.workspaceEntries",
        "onWorkspaceRequested: workspaceId =>",
        "workspaceNavigation.activateWorkspace(workspaceId)",
        "commandPalette.completeWorkspaceRequest(activated)",
    ):
        if fragment not in shell_qml:
            failures.append(f"Linura Shell root contract missing: {fragment}")

    ipc_index = shell_qml.find("IpcHandler {")
    if ipc_index < 0:
        failures.append("Linura Shell root contract missing: IpcHandler {")
    else:
        for method in (
            "showControlCenter",
            "hideControlCenter",
            "toggleControlCenter",
            "showCommandPalette",
            "hideCommandPalette",
            "toggleCommandPalette",
        ):
            declaration = f"function {method}()"
            if shell_qml.find(declaration, 0, ipc_index) < 0:
                failures.append(
                    f"Linura Shell root must own navigation method before IPC delegation: {declaration}"
                )
            delegation = f"shell.{method}()"
            if shell_qml.find(delegation, ipc_index) < 0:
                failures.append(
                    f"Linura Shell IPC must delegate navigation method to ShellRoot: {delegation}"
                )

    for fragment in (
        "PanelWindow {",
        "WlrLayershell.keyboardFocus:",
        "controller.beginVolumeDraft()",
        "controller.cancelVolumeDraft()",
        "controller.setActive(opened)",
        "closeButton.forceActiveFocus(Qt.TabFocusReason)",
        "controller.setVolume(root.draftVolume)",
        "import org.linura.UI 1.0",
        "LinuraSurface {",
        "LinuraText {",
        "LinuraButton {",
        "LinuraSlider {",
        "Accessible.name:",
        "Keys.onLeftPressed:",
        "Keys.onRightPressed:",
        'controller.state === "ready"',
    ):
        if fragment not in panel_qml:
            failures.append(f"Control Center shell panel contract missing: {fragment}")

    for fragment in FORBIDDEN_QML:
        if fragment in combined_qml:
            failures.append(
                f"trusted shell QML contains forbidden authority/process/provider surface: {fragment}"
            )
    for fragment in (
        "PanelWindow {",
        "import org.linura.UI 1.0",
        "property var workspaceCatalog:",
        "signal controlCenterRequested()",
        "signal workspaceRequested(int workspaceId)",
        'targetId: "navigation:control-center"',
        'targetId: "navigation:workspace:" + workspace.id',
        "workspaceId: workspace.id",
        "if (workspace.focused)",
        "workspace.focused ? qsTr(\"Current\") : qsTr(\"Enter\")",
        "for (let i = 0; i < workspaceCatalog.length; i++)",
        "workspaceRequested(entry.workspaceId)",
        "function completeWorkspaceRequest(activated)",
        "onWorkspaceCatalogChanged:",
        "LinuraTextField {",
        "LinuraActionRow {",
        "Keys.onDownPressed:",
        "Keys.onUpPressed:",
        "Keys.onReturnPressed:",
        "function ensureSelectedResultVisible()",
        "resultList.positionViewAtIndex(root.selectedIndex, ListView.Contain)",
        "currentIndex: root.selectedIndex",
        "function selectedAccessibilityDescription()",
        "accessibleDescription: root.selectedAccessibilityDescription()",
        'WlrLayershell.namespace: "linura-command-palette"',
    ):
        if fragment not in palette_qml:
            failures.append(f"Command palette shell contract missing: {fragment}")

    for fragment in (
        "import Quickshell.Hyprland",
        "Hyprland.",
        ".activate()",
    ):
        if fragment in palette_qml:
            failures.append(
                f"Command palette presentation must not retain Hyprland provider control: {fragment}"
            )

    for fragment in (
        "import Quickshell.Hyprland",
        "Scope {",
        "readonly property var workspaceEntries: buildWorkspaceEntries()",
        "Hyprland.workspaces.values",
        "focused: workspace.focused",
        "function activateWorkspace(workspaceId)",
        "Number.isInteger(workspaceId)",
        "if (workspace.id !== workspaceId)",
        "workspace.activate()",
    ):
        if fragment not in workspace_controller_qml:
            failures.append(
                f"Workspace navigation controller contract missing: {fragment}"
            )

    live_workspace_model = "const workspaces = Hyprland.workspaces.values"
    if workspace_controller_qml.count(live_workspace_model) != 2:
        failures.append(
            "Workspace navigation controller must read the live Hyprland workspace model once for descriptors and once immediately before activation"
        )

    raw_palette_control = re.search(
        r"(?m)^\s*(?:Rectangle|Label|Button|Slider|Switch|TextField|AbstractButton|Popup|Dialog)\s*\{",
        palette_qml,
    )
    if raw_palette_control is not None:
        failures.append(
            "Command palette product surface must consume Linura UI primitives instead of raw Qt visual controls"
        )

    root_navigation_scope = (
        shell_qml[:ipc_index] if ipc_index >= 0 else shell_qml
    )
    show_control_center_is_exclusive = re.search(
        r"function\s+showControlCenter\(\)\s*\{"
        r"\s*shell\.commandPaletteOpen\s*=\s*false"
        r"\s*shell\.controlCenterOpen\s*=\s*true\s*\}",
        root_navigation_scope,
        re.DOTALL,
    )
    show_command_palette_is_exclusive = re.search(
        r"function\s+showCommandPalette\(\)\s*\{"
        r"\s*shell\.controlCenterOpen\s*=\s*false"
        r"\s*shell\.commandPaletteOpen\s*=\s*true\s*\}",
        root_navigation_scope,
        re.DOTALL,
    )
    if (
        show_control_center_is_exclusive is None
        or show_command_palette_is_exclusive is None
    ):
        failures.append("Linura Shell transient surfaces must remain mutually exclusive")

    if panel_qml.count("controller.setActive(opened)") != 1:
        failures.append("Control Center panel must activate observation only while opened")
    if "volumeSlider.value =" in panel_qml:
        failures.append("Control Center keyboard handling must preserve the slider value binding")
    raw_visual_control = re.search(
        r"(?m)^\s*(?:Rectangle|Label|Button|Slider|Switch|TextField|AbstractButton|Popup|Dialog)\s*\{",
        panel_qml,
    )
    if raw_visual_control is not None:
        failures.append(
            "Control Center product surface must consume Linura UI primitives instead of raw Qt visual controls"
        )

    ui_requirements = {
        "apps/linura-shell/ui/LinuraSurface.qml": (
            "property string level:",
            "property color outlineColor:",
            "theme.surfaceElevated",
        ),
        "apps/linura-shell/ui/LinuraText.qml": (
            'property string role: "body"',
            "theme.typeCaption",
            "theme.typeDisplay",
        ),
        "apps/linura-shell/ui/LinuraButton.qml": (
            "activeFocusOnTab: true",
            "font.pixelSize: theme.typeBody",
            "theme.focusBorderWidth",
            "theme.highlightedText",
        ),
        "apps/linura-shell/ui/LinuraSlider.qml": (
            "activeFocusOnTab: true",
            "control.visualPosition",
            "theme.focusBorderWidth",
        ),
        "apps/linura-shell/ui/LinuraIconButton.qml": (
            "required property string accessibleName",
            "activeFocusOnTab: true",
            "Accessible.name: accessibleName",
            "Accessible.role: Accessible.Button",
            "ToolTip.visible:",
        ),
        "apps/linura-shell/ui/LinuraSwitch.qml": (
            "activeFocusOnTab: true",
            "control.visualPosition",
            "Accessible.role: Accessible.CheckBox",
        ),
        "apps/linura-shell/ui/LinuraTextField.qml": (
            "property string accessibleDescription:",
            "selectByMouse: true",
            "selectionColor: theme.accent",
            "Accessible.description: invalid ? errorText : accessibleDescription",
            "Accessible.role: Accessible.EditableText",
        ),
        "apps/linura-shell/ui/LinuraActionRow.qml": (
            "AbstractButton {",
            "LinuraText {",
            "Accessible.role: Accessible.Button",
            "Accessible.selectable: true",
            "Accessible.selected: control.selected",
        ),
        "apps/linura-shell/ui/LinuraCard.qml": (
            'property string tone: "neutral"',
            "outlineColor:",
        ),
        "apps/linura-shell/ui/LinuraStatus.qml": (
            'property string tone: "neutral"',
            "Accessible.role: Accessible.StaticText",
        ),
        "apps/linura-shell/ui/LinuraDivider.qml": (
            "property bool vertical: false",
            "theme.borderWidth",
        ),
        "apps/linura-shell/ui/LinuraPopover.qml": (
            "Popup {",
            "Popup.CloseOnEscape | Popup.CloseOnPressOutside",
            'level: "elevated"',
        ),
        "apps/linura-shell/ui/LinuraDialog.qml": (
            "signal accepted()",
            "signal rejected()",
            "property bool decisionEmitted: false",
            "onAboutToShow: decisionEmitted = false",
            "onClosed:",
            "if (!decisionEmitted)",
            "modal: true",
            "Popup.CloseOnEscape",
        ),
    }
    for relative, fragments in ui_requirements.items():
        ui_source = (root / relative).read_text(encoding="utf-8")
        for fragment in fragments:
            if fragment not in ui_source:
                failures.append(
                    f"Linura UI SDK component {relative} missing contract: {fragment}"
                )

    manifest = json.loads(
        (
            root / "apps/linura-shell/plugins/control-center/manifest.json"
        ).read_text(encoding="utf-8")
    )
    if manifest.get("schema_version") != 1:
        failures.append("Control Center shell manifest schema_version must be 1")
    if manifest.get("id") != "linura.control-center":
        failures.append("Control Center shell manifest id must be canonical")
    if manifest.get("kind") != "panel":
        failures.append("Control Center shell manifest kind must be panel")
    if manifest.get("entry_point") != "ControlCenterPanel.qml":
        failures.append("Control Center shell manifest entry_point must be canonical")
    if manifest.get("trust") != "first-party":
        failures.append("Control Center shell manifest must remain first-party")
    if manifest.get("authority") != "none":
        failures.append("Control Center shell manifest must carry no authority")
    if "capabilities" in manifest:
        failures.append("Control Center shell manifest must not become a capability grant")
    expected_protocols = {
        "org.linura.Control1.Observe",
        "org.linura.Session1.SetAudioOutputVolume",
    }
    protocols = manifest.get("protocol_requirements")
    if not isinstance(protocols, list) or set(protocols) != expected_protocols:
        failures.append("Control Center shell manifest protocol requirements drifted")

    palette_manifest = json.loads(
        (
            root / "apps/linura-shell/plugins/command-palette/manifest.json"
        ).read_text(encoding="utf-8")
    )
    expected_palette_manifest = {
        "schema_version": 1,
        "id": "linura.command-palette",
        "name": "Linura Command Palette",
        "kind": "overlay",
        "entry_point": "CommandPalette.qml",
        "trust": "first-party",
        "authority": "none",
        "interaction_scope": "experience-navigation-only",
        "navigation_targets": [
            "navigation:control-center",
            "navigation:workspace",
        ],
        "navigation_sources": ["hyprland.workspaces"],
        "protocol_requirements": [],
    }
    if palette_manifest != expected_palette_manifest:
        failures.append(
            "Command palette manifest must remain exact, first-party, navigation-only and authority-free"
        )
    if "capabilities" in palette_manifest:
        failures.append("Command palette manifest must not become a capability grant")

    bridge_header = (
        root / "apps/linura-shell/bridge/audio_session_controller.h"
    ).read_text(encoding="utf-8")
    bridge_source = (
        root / "apps/linura-shell/bridge/audio_session_controller.cpp"
    ).read_text(encoding="utf-8")
    bridge = bridge_header + "\n" + bridge_source
    for fragment in REQUIRED_BRIDGE:
        if fragment not in bridge:
            failures.append(f"Linura Shell bridge authority contract missing: {fragment}")
    for fragment in FORBIDDEN_BRIDGE:
        if fragment in bridge:
            failures.append(
                f"Linura Shell bridge contains forbidden authority/process surface: {fragment}"
            )
    if bridge.count("generation != observationGeneration_") != 1:
        failures.append("Linura Shell bridge must discard superseded observations exactly once")
    if bridge.count("samePrecondition(pending_->displayed, snapshot)") != 1:
        failures.append("Linura Shell bridge must retain one pre-dispatch state check")
    if bridge.count("sameIdentity(pending.displayed, snapshot)") != 1:
        failures.append("Linura Shell bridge must retain one post-effect identity check")
    if bridge.count("observe(ObservePurpose::PostApply)") != 1:
        failures.append("Linura Shell bridge must independently re-observe after receipt")
    if bridge.count("isServiceUnavailableError(reply.errorName())") != 2:
        failures.append(
            "Linura Shell bridge must classify Control1 and Session1 service disappearance"
        )
    if "refreshTimer_" in bridge:
        failures.append("Linura Shell bridge must not poll while Control Center is closed")
    if bridge.count('QStringLiteral("org.freedesktop.DBus.Error.NoReply")') != 1:
        failures.append("Linura Shell bridge must classify D-Bus NoReply as service unavailable")
    if "retryTimer_.start(delay)" not in bridge or "kRetryMaximumMs" not in bridge:
        failures.append("Linura Shell bridge must retain active-only bounded observation recovery")
    close_inactive_contract = re.search(
        r'if \(!active_\) \{.*?setState\(\s*'
        r'QStringLiteral\("inactive"\),\s*'
        r'QStringLiteral\("Control Center is closed\."\)\s*\);'
        r'.*?return;\s*\}',
        bridge_source,
        re.DOTALL,
    )
    if close_inactive_contract is None:
        failures.append("Linura Shell bridge must reset canceled panel observations to inactive")
    if bridge.count("pending_->dispatched = true;") != 1:
        failures.append("Linura Shell bridge must distinguish pre-dispatch from dispatched effects")

    cmake = (root / "apps/linura-shell/bridge/CMakeLists.txt").read_text(
        encoding="utf-8"
    )
    ui_cmake = (root / "apps/linura-shell/ui/CMakeLists.txt").read_text(
        encoding="utf-8"
    )
    for fragment in (
        "find_package(Qt6 6.4 REQUIRED COMPONENTS Core Qml Quick QuickControls2)",
        "qt_add_library(linura-ui SHARED)",
        "qt_add_qml_module(linura-ui",
        "URI org.linura.UI",
        "VERSION 1.0",
        "Qt6::QuickControls2",
        "lib/qt6/qml/org/linura/UI",
    ):
        if fragment not in ui_cmake:
            failures.append(f"Linura UI SDK CMake contract missing: {fragment}")

    for fragment in (
        "find_package(Qt6 6.4 REQUIRED COMPONENTS Core DBus Qml)",
        "qt_add_library(linura-shell-bridge SHARED)",
        "qt_add_qml_module(linura-shell-bridge",
        "URI org.linura.ShellBridge",
        "Qt6::DBus",
        "Qt6::Qml",
    ):
        if fragment not in cmake:
            failures.append(f"Linura Shell bridge CMake contract missing: {fragment}")

    tokens = json.loads((root / "design/tokens.json").read_text(encoding="utf-8"))
    theme = (root / "apps/linura-shell/ui/LinuraTheme.qml").read_text(
        encoding="utf-8"
    )
    token_bindings = {
        "spacing": {
            "xs": "spacingXs",
            "sm": "spacingSm",
            "md": "spacingMd",
            "lg": "spacingLg",
            "xl": "spacingXl",
            "2xl": "spacing2xl",
        },
        "radius": {
            "sm": "radiusSm",
            "md": "radiusMd",
            "lg": "radiusLg",
            "xl": "radiusXl",
        },
        "typography": {
            "caption": "typeCaption",
            "body": "typeBody",
            "title": "typeTitle",
            "display": "typeDisplay",
        },
        "motion_ms": {
            "fast": "motionFast",
            "normal": "motionNormal",
            "slow": "motionSlow",
        },
        "control_size": {
            "sm": "controlSm",
            "md": "controlMd",
            "lg": "controlLg",
        },
        "icon_size": {
            "sm": "iconSm",
            "md": "iconMd",
            "lg": "iconLg",
        },
        "border_width": {
            "default": "borderWidth",
            "focus": "focusBorderWidth",
        },
    }
    for group, names in token_bindings.items():
        values = tokens.get(group)
        if not isinstance(values, dict):
            failures.append(f"design token group {group} is missing")
            continue
        for token_name, qml_name in names.items():
            value = values.get(token_name)
            marker = f"readonly property int {qml_name}: {value}"
            if marker not in theme:
                failures.append(
                    f"Linura Shell theme drifted from design token {group}.{token_name}"
                )
    for fragment in (
        "readonly property SystemPalette systemPalette: SystemPalette",
        "systemPalette.window",
        "systemPalette.base",
        "systemPalette.highlight",
    ):
        if fragment not in theme:
            failures.append(f"Linura Shell system-palette contract missing: {fragment}")

    packages = {
        line.strip()
        for line in (
            root / "packaging/arch/archiso/packages.linura"
        ).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    if "quickshell" not in packages:
        failures.append("Arch workstation package contract must include quickshell")

    service = (
        root / "packaging/systemd/user/linura-shell.service"
    ).read_text(encoding="utf-8")
    for fragment in (
        "ExecStart=/usr/bin/quickshell -n -p /usr/share/linura/shell",
        "After=graphical-session.target linurad.service",
        "Wants=linurad.service",
        "BindsTo=graphical-session.target",
        "PartOf=graphical-session.target",
        "WantedBy=graphical-session.target",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "RestrictAddressFamilies=AF_UNIX",
    ):
        if fragment not in service:
            failures.append(f"Linura Shell user-service contract missing: {fragment}")
    for fragment in ("/bin/sh", "/bin/bash", "sudo", "pkexec"):
        if fragment in service:
            failures.append(f"Linura Shell service contains forbidden surface: {fragment}")

    launcher = (
        root / "apps/linura-shell/org.linura.ControlCenter.desktop"
    ).read_text(encoding="utf-8")
    for fragment in (
        "[Desktop Entry]",
        "Name=Linura Control Center",
        "Exec=/usr/bin/qs -p /usr/share/linura/shell ipc call -- linura.shell toggleControlCenter",
        "Terminal=false",
    ):
        if fragment not in launcher:
            failures.append(f"Control Center packaged launcher contract missing: {fragment}")

    palette_launcher = (
        root / "apps/linura-shell/org.linura.CommandPalette.desktop"
    ).read_text(encoding="utf-8")
    for fragment in (
        "[Desktop Entry]",
        "Name=Linura Command Palette",
        "Exec=/usr/bin/qs -p /usr/share/linura/shell ipc call -- linura.shell toggleCommandPalette",
        "Terminal=false",
    ):
        if fragment not in palette_launcher:
            failures.append(f"Command palette packaged launcher contract missing: {fragment}")

    image = (root / "tools/image.py").read_text(encoding="utf-8")
    for fragment in REQUIRED_IMAGE:
        if fragment not in image:
            failures.append(f"Arch image shell integration missing: {fragment}")

    ci = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for fragment in REQUIRED_CI:
        if fragment not in ci:
            failures.append(f"canonical CI must build/install Linura Shell bridge: {fragment}")

    readme = (root / "apps/linura-shell/README.md").read_text(encoding="utf-8")
    for fragment in (
        "one supervised, long-lived Quickshell process",
        "presentation and interaction infrastructure, not an authority plane",
        "arbitrary user QML is **not** loaded",
        "qs -p /usr/share/linura/shell ipc call -- linura.shell toggleControlCenter",
        "does not poll PipeWire while the panel is closed",
        "Linura QML UI SDK",
        "org.linura.UI 1.0",
        "navigation-only command palette",
        "linura:commandPalette",
        "toggleCommandPalette",
        "HYPRLAND_NO_SD_TARGET",
        "does **not** promote",
    ):
        if fragment not in readme:
            failures.append(f"Linura Shell authority/support documentation missing: {fragment}")

    ui_readme = (root / "apps/linura-shell/ui/README.md").read_text(encoding="utf-8")
    for fragment in (
        "first-party visual component layer",
        "org.linura.UI 1.0",
        "presentation only",
        "not yet a stable third-party API",
    ):
        if fragment not in ui_readme:
            failures.append(f"Linura UI SDK documentation missing: {fragment}")

    design_system = (root / "docs/design-system.md").read_text(encoding="utf-8")
    for fragment in (
        "Linura QML UI Component SDK",
        "Qt Quick Controls are implementation infrastructure",
        "LinuraSurface",
        "LinuraButton",
        "LinuraSlider",
        "not yet a stable third-party API",
    ):
        if fragment not in design_system:
            failures.append(f"Linura design-system documentation missing: {fragment}")

    qualification = (root / "docs/qualification/v0.10.0.md").read_text(encoding="utf-8")
    for fragment in (
        "hyprland-session.target",
        "graphical-session.target",
        "linura-shell.service",
        "BindsTo",
        "HYPRLAND_NO_SD_TARGET",
    ):
        if fragment not in qualification:
            failures.append(f"v0.10 workstation session qualification missing: {fragment}")

    architecture = (root / "docs/architecture.md").read_text(encoding="utf-8")
    for fragment in (
        "linura-shell",
        "integrated Experimental in v0.10",
        "Linura QML UI Component SDK",
        "Qt Quick/QML presentation",
    ):
        if fragment not in architecture:
            failures.append(f"Linura architecture documentation missing: {fragment}")

    return failures


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else ROOT
    if len(sys.argv) > 2:
        print("usage: check_linura_shell.py [root]", file=sys.stderr)
        return 2
    failures = validate(root)
    if failures:
        for failure in failures:
            print(f"Linura Shell contract failed: {failure}", file=sys.stderr)
        return 1
    print("Linura Shell contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
