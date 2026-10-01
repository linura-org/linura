import QtQuick
import Quickshell
import Quickshell.Hyprland
import org.linura.ShellBridge 1.0
import "plugins/control-center"
import "plugins/quick-settings"
import "plugins/command-palette"
import "plugins/notifications-osd" as Feedback
import "panel" as Panel
import "integrations/hyprland"
import "integrations/xdg"

ShellRoot {
    id: shell

    property bool controlCenterOpen: false
    property bool quickSettingsOpen: false
    property bool commandPaletteOpen: false
    property var overlayScreen: null
    property int lifecycleFeedbackGeneration: 0
    property var lifecycleFeedbackScreen: null

    function defaultOverlayScreen() {
        const focusedMonitor = Hyprland.focusedMonitor
        if (focusedMonitor) {
            for (let i = 0; i < Quickshell.screens.length; i++) {
                const screen = Quickshell.screens[i]
                if (Hyprland.monitorFor(screen) === focusedMonitor)
                    return screen
            }
        }
        return Quickshell.screens.length > 0 ? Quickshell.screens[0] : null
    }

    function selectOverlayScreen(screen) {
        shell.overlayScreen = screen ? screen : shell.defaultOverlayScreen()
    }

    function presentLifecycleFeedback(presentationGeneration, operationKey, phase, outcome,
                                      observedValuePercent, observedValueValid, finalOutcome) {
        if (phase === "preparing") {
            shell.lifecycleFeedbackGeneration = presentationGeneration
            shell.lifecycleFeedbackScreen =
                shell.overlayScreen ? shell.overlayScreen : shell.defaultOverlayScreen()
        } else if (presentationGeneration !== shell.lifecycleFeedbackGeneration) {
            return
        }

        lifecycleFeedback.present(
            presentationGeneration,
            operationKey,
            phase,
            outcome,
            observedValuePercent,
            observedValueValid,
            finalOutcome
        )
    }

    function showControlCenterOnScreen(screen) {
        shell.selectOverlayScreen(screen)
        shell.showControlCenter()
    }

    function showControlCenter() {
        shell.quickSettingsOpen = false
        shell.commandPaletteOpen = false
        shell.controlCenterOpen = true
    }

    function hideControlCenter() {
        shell.controlCenterOpen = false
    }

    function toggleControlCenter() {
        if (shell.controlCenterOpen)
            shell.hideControlCenter()
        else
            shell.showControlCenterOnScreen(shell.defaultOverlayScreen())
    }

    function showQuickSettingsOnScreen(screen) {
        shell.selectOverlayScreen(screen)
        shell.showQuickSettings()
    }

    function showQuickSettings() {
        shell.controlCenterOpen = false
        shell.commandPaletteOpen = false
        shell.quickSettingsOpen = true
    }

    function hideQuickSettings() {
        shell.quickSettingsOpen = false
    }

    function toggleQuickSettings() {
        if (shell.quickSettingsOpen)
            shell.hideQuickSettings()
        else
            shell.showQuickSettingsOnScreen(shell.defaultOverlayScreen())
    }

    function showCommandPaletteOnScreen(screen) {
        shell.selectOverlayScreen(screen)
        shell.showCommandPalette()
    }

    function showCommandPalette() {
        shell.controlCenterOpen = false
        shell.quickSettingsOpen = false
        shell.commandPaletteOpen = true
    }

    function hideCommandPalette() {
        shell.commandPaletteOpen = false
    }

    function toggleCommandPalette() {
        if (shell.commandPaletteOpen)
            shell.hideCommandPalette()
        else
            shell.showCommandPaletteOnScreen(shell.defaultOverlayScreen())
    }

    AudioSessionController {
        id: audioController
        active: shell.controlCenterOpen || shell.quickSettingsOpen
        onLifecycleFeedback: (presentationGeneration, operationKey, phase, outcome,
                              observedValuePercent, observedValueValid, finalOutcome) =>
            shell.presentLifecycleFeedback(
                presentationGeneration,
                operationKey,
                phase,
                outcome,
                observedValuePercent,
                observedValueValid,
                finalOutcome
            )
    }

    Feedback.LifecycleFeedback {
        id: lifecycleFeedback
        targetScreen: shell.lifecycleFeedbackScreen
            ? shell.lifecycleFeedbackScreen
            : shell.defaultOverlayScreen()
    }

    Panel.WorkstationPanel {
        id: workstationPanel
        workspaceModel: workspaceNavigation.workspaceEntries
        onCommandPaletteRequested: screen => shell.showCommandPaletteOnScreen(screen)
        onQuickSettingsRequested: screen => shell.showQuickSettingsOnScreen(screen)
        onControlCenterRequested: screen => shell.showControlCenterOnScreen(screen)
        onWorkspaceRequested: workspaceId => workspaceNavigation.activateWorkspace(workspaceId)
    }

    WorkspaceNavigationController {
        id: workspaceNavigation
    }

    ApplicationLauncherController {
        id: applicationLauncher
        onLaunchCompleted: (status, requestGeneration) =>
            commandPalette.completeApplicationRequest(status, requestGeneration)
    }

    IpcHandler {
        target: "linura.shell"

        function showControlCenter() {
            shell.showControlCenterOnScreen(shell.defaultOverlayScreen())
        }

        function hideControlCenter() {
            shell.hideControlCenter()
        }

        function toggleControlCenter() {
            shell.toggleControlCenter()
        }

        function showQuickSettings() {
            shell.showQuickSettingsOnScreen(shell.defaultOverlayScreen())
        }

        function hideQuickSettings() {
            shell.hideQuickSettings()
        }

        function toggleQuickSettings() {
            shell.toggleQuickSettings()
        }

        function showCommandPalette() {
            shell.showCommandPaletteOnScreen(shell.defaultOverlayScreen())
        }

        function hideCommandPalette() {
            shell.hideCommandPalette()
        }

        function toggleCommandPalette() {
            shell.toggleCommandPalette()
        }
    }

    GlobalShortcut {
        appid: "linura"
        name: "workstationPanel"
        description: "Focus Linura workstation panel"
        onPressed: workstationPanel.focusPanelOnScreen(shell.defaultOverlayScreen())
    }

    GlobalShortcut {
        appid: "linura"
        name: "quickSettings"
        description: "Toggle Linura quick settings"
        onPressed: shell.toggleQuickSettings()
    }

    GlobalShortcut {
        appid: "linura"
        name: "commandPalette"
        description: "Toggle Linura command palette"
        onPressed: shell.toggleCommandPalette()
    }

    ControlCenterPanel {
        targetScreen: shell.overlayScreen ? shell.overlayScreen : shell.defaultOverlayScreen()
        topInset: workstationPanel.panelHeight
        opened: shell.controlCenterOpen
        controller: audioController
        onCloseRequested: shell.hideControlCenter()
    }

    QuickSettingsPanel {
        targetScreen: shell.overlayScreen ? shell.overlayScreen : shell.defaultOverlayScreen()
        topInset: workstationPanel.panelHeight
        opened: shell.quickSettingsOpen
        controller: audioController
        onCloseRequested: shell.hideQuickSettings()
        onControlCenterRequested: shell.showControlCenterOnScreen(shell.overlayScreen)
    }

    CommandPalette {
        id: commandPalette
        targetScreen: shell.overlayScreen ? shell.overlayScreen : shell.defaultOverlayScreen()
        topInset: workstationPanel.panelHeight
        opened: shell.commandPaletteOpen
        workspaceCatalog: workspaceNavigation.workspaceEntries
        applicationCatalog: applicationLauncher.applicationEntries
        onCloseRequested: shell.hideCommandPalette()
        onControlCenterRequested: shell.showControlCenterOnScreen(shell.overlayScreen)
        onQuickSettingsRequested: shell.showQuickSettingsOnScreen(shell.overlayScreen)
        onWorkspaceRequested: workspaceId => {
            const activated = workspaceNavigation.activateWorkspace(workspaceId)
            commandPalette.completeWorkspaceRequest(activated)
        }
        onApplicationRequested: (applicationId, requestGeneration) => {
            const status = applicationLauncher.launchApplication(
                applicationId,
                requestGeneration
            )
            if (status !== "accepted")
                commandPalette.completeApplicationRequest(status, requestGeneration)
        }
    }
}
