//@ pragma ShellId linura-panel-qualification
import QtQuick
import Quickshell
import Quickshell.Hyprland
import Quickshell.Io
import qs.panel as Panel
import qs.integrations.hyprland as HyprlandIntegration

Scope {
    id: root

    property int commandPaletteRequests: 0
    property int quickSettingsRequests: 0
    property int controlCenterRequests: 0
    property int workspaceRequests: 0
    property bool lastWorkspaceActivation: false
    property int trayPrimaryRequests: 0
    property int traySecondaryRequests: 0
    property int trayMenuRequests: 0
    property var qualificationTrayItems: [
        trayItemOne,
        trayItemTwo,
        trayItemThree,
        trayItemFour,
        trayItemFive
    ]

    QtObject {
        id: trayItemOne
        property string tooltipTitle: "Qualification <tray> 1"
        property string title: "Qualification Tray 1"
        property string tooltipDescription: "Deterministic tray fixture one"
        property string icon: ""
        property bool hasMenu: false
        property bool onlyMenu: false
        function activate() { root.trayPrimaryRequests += 1 }
        function secondaryActivate() { root.traySecondaryRequests += 1 }
        function display(parentWindow, relativeX, relativeY) { root.trayMenuRequests += 1 }
    }

    QtObject {
        id: trayItemTwo
        property string tooltipTitle: "Qualification Tray 2"
        property string title: "Qualification Tray 2"
        property string tooltipDescription: "Deterministic tray fixture two"
        property string icon: ""
        property bool hasMenu: true
        property bool onlyMenu: true
        function activate() { root.trayPrimaryRequests += 1 }
        function secondaryActivate() { root.traySecondaryRequests += 1 }
        function display(parentWindow, relativeX, relativeY) { root.trayMenuRequests += 1 }
    }

    QtObject {
        id: trayItemThree
        property string tooltipTitle: "Qualification Tray 3"
        property string title: "Qualification Tray 3"
        property string tooltipDescription: "Deterministic tray fixture three"
        property string icon: ""
        property bool hasMenu: false
        property bool onlyMenu: false
        function activate() { root.trayPrimaryRequests += 1 }
        function secondaryActivate() { root.traySecondaryRequests += 1 }
        function display(parentWindow, relativeX, relativeY) { root.trayMenuRequests += 1 }
    }

    QtObject {
        id: trayItemFour
        property string tooltipTitle: "Qualification Tray 4"
        property string title: "Qualification Tray 4"
        property string tooltipDescription: "Deterministic tray fixture four"
        property string icon: ""
        property bool hasMenu: false
        property bool onlyMenu: false
        function activate() { root.trayPrimaryRequests += 1 }
        function secondaryActivate() { root.traySecondaryRequests += 1 }
        function display(parentWindow, relativeX, relativeY) { root.trayMenuRequests += 1 }
    }

    QtObject {
        id: trayItemFive
        property string tooltipTitle: "Qualification Tray 5"
        property string title: "Qualification Tray 5"
        property string tooltipDescription: "Deterministic tray fixture five"
        property string icon: ""
        property bool hasMenu: false
        property bool onlyMenu: false
        function activate() { root.trayPrimaryRequests += 1 }
        function secondaryActivate() { root.traySecondaryRequests += 1 }
        function display(parentWindow, relativeX, relativeY) { root.trayMenuRequests += 1 }
    }

    HyprlandIntegration.WorkspaceNavigationController {
        id: workspaceNavigation
    }

    Panel.WorkstationPanel {
        id: workstationPanel
        workspaceModel: workspaceNavigation.workspaceEntries
        trayItemModelOverride: root.qualificationTrayItems
        statusClockPrecision: SystemClock.Seconds
        onCommandPaletteRequested: screen => root.commandPaletteRequests += 1
        onQuickSettingsRequested: screen => root.quickSettingsRequests += 1
        onControlCenterRequested: screen => root.controlCenterRequests += 1
        onWorkspaceRequested: workspaceId => {
            root.workspaceRequests += 1
            root.lastWorkspaceActivation = workspaceNavigation.activateWorkspace(workspaceId)
        }
    }

    GlobalShortcut {
        appid: "linura"
        name: "workstationPanel"
        description: "Focus Linura workstation panel"
        onPressed: workstationPanel.focusPanel(0)
    }

    IpcHandler {
        target: "linura.panel-qualification"

        function trayKeyboardSnapshot(): string {
            return workstationPanel.trayKeyboardSnapshot(0)
        }

        function screenCount(): int { return workstationPanel.screenCount }
        function panelHeight(): int { return workstationPanel.panelHeight }
        function panelWindowCount(): int { return workstationPanel.instantiatedPanelCount }
        function panelScreenMatches(index: int): bool { return workstationPanel.panelScreenMatches(index) }
        function panelWindowWidth(index: int): int { return workstationPanel.panelWidth(index) }
        function panelWindowHeight(index: int): int { return workstationPanel.panelHeightActual(index) }
        function panelScreenWidth(index: int): int { return workstationPanel.panelScreenWidth(index) }
        function panelExclusiveZone(index: int): int { return workstationPanel.panelExclusiveZone(index) }
        function panelExclusionNormal(index: int): bool { return workstationPanel.panelExclusionNormal(index) }
        function panelAnchorsValid(index: int): bool { return workstationPanel.panelAnchorsValid(index) }
        function workspaceCount(): int { return workspaceNavigation.workspaceEntries.length }
        function focusedWorkspaceCount(): int {
            let count = 0
            for (let i = 0; i < workspaceNavigation.workspaceEntries.length; i++) {
                if (workspaceNavigation.workspaceEntries[i].focused)
                    count += 1
            }
            return count
        }
        function firstWorkspaceId(): int {
            return workspaceNavigation.workspaceEntries.length > 0
                ? workspaceNavigation.workspaceEntries[0].id : 0
        }
        function focusPanelControl(): bool {
            return workstationPanel.focusPanel(0)
        }
        function panelKeyboardEntryFocused(): bool {
            return workstationPanel.panelKeyboardEntryFocused(0)
        }
        function panelKeyboardNavigationActive(): bool {
            return workstationPanel.panelKeyboardNavigationActive(0)
        }
        function statusTimeText(): string { return workstationPanel.statusTimeText() }
        function statusDateText(): string { return workstationPanel.statusDateText() }
        function statusTimestampMs(): string { return String(workstationPanel.statusTimestampMs()) }
        function statusTimeRendered(): bool { return workstationPanel.statusTimeRendered(0) }
        function trayItemCount(): int { return workstationPanel.trayItemCount(0) }
        function trayOverflowCount(): int { return workstationPanel.trayOverflowCount(0) }
        function activateTrayInlineControl(index: int): bool {
            return workstationPanel.activateTrayInlineControl(0, index)
        }
        function openTrayOverflowControl(): bool {
            return workstationPanel.openTrayOverflowControl(0)
        }
        function focusTrayOverflowButtonControl(): bool {
            return workstationPanel.focusTrayOverflowButtonControl(0)
        }
        function cancelTrayOverflowControl(): bool {
            return workstationPanel.cancelTrayOverflowControl(0)
        }
        function trayOverflowVisible(): bool {
            return workstationPanel.trayOverflowVisible(0)
        }
        function trayOverflowOpenCount(): int {
            return workstationPanel.trayOverflowOpenCount(0)
        }
        function trayOverflowButtonFocused(): bool {
            return workstationPanel.trayOverflowButtonFocused(0)
        }
        function trayOverflowEntryReady(index: int): bool {
            return workstationPanel.trayOverflowEntryReady(0, index)
        }
        function trayOverflowReadinessState(index: int): string {
            return workstationPanel.trayOverflowReadinessState(0, index)
        }
        function activateTrayOverflowControl(index: int): bool {
            return workstationPanel.activateTrayOverflowControl(0, index)
        }
        function trayPrimaryCount(): int { return root.trayPrimaryRequests }
        function trayMenuCount(): int { return root.trayMenuRequests }
        function activateCommandPaletteControl(): bool {
            return workstationPanel.activateCommandPaletteControl(0)
        }
        function activateQuickSettingsControl(): bool {
            return workstationPanel.activateQuickSettingsControl(0)
        }
        function activateControlCenterControl(): bool {
            return workstationPanel.activateControlCenterControl(0)
        }
        function activateWorkspaceControl(workspaceId: int): bool {
            return workstationPanel.activateWorkspaceControl(0, workspaceId)
        }
        function commandPaletteCount(): int { return root.commandPaletteRequests }
        function quickSettingsCount(): int { return root.quickSettingsRequests }
        function controlCenterCount(): int { return root.controlCenterRequests }
        function workspaceCountRequested(): int { return root.workspaceRequests }
        function lastWorkspaceActivated(): bool { return root.lastWorkspaceActivation }
    }
}
