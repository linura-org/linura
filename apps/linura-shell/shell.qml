import QtQuick
import Quickshell
import Quickshell.Hyprland
import org.linura.ShellBridge 1.0
import "plugins/control-center"
import "plugins/quick-settings"
import "plugins/command-palette"
import "integrations/hyprland"
import "integrations/xdg"

ShellRoot {
    id: shell

    property bool controlCenterOpen: false
    property bool quickSettingsOpen: false
    property bool commandPaletteOpen: false

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
            shell.showControlCenter()
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
            shell.showQuickSettings()
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
            shell.showCommandPalette()
    }

    AudioSessionController {
        id: audioController
        active: shell.controlCenterOpen || shell.quickSettingsOpen
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
            shell.showControlCenter()
        }

        function hideControlCenter() {
            shell.hideControlCenter()
        }

        function toggleControlCenter() {
            shell.toggleControlCenter()
        }

        function showQuickSettings() {
            shell.showQuickSettings()
        }

        function hideQuickSettings() {
            shell.hideQuickSettings()
        }

        function toggleQuickSettings() {
            shell.toggleQuickSettings()
        }

        function showCommandPalette() {
            shell.showCommandPalette()
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
        opened: shell.controlCenterOpen
        controller: audioController
        onCloseRequested: shell.hideControlCenter()
    }

    QuickSettingsPanel {
        opened: shell.quickSettingsOpen
        controller: audioController
        onCloseRequested: shell.hideQuickSettings()
        onControlCenterRequested: shell.showControlCenter()
    }

    CommandPalette {
        id: commandPalette
        opened: shell.commandPaletteOpen
        workspaceCatalog: workspaceNavigation.workspaceEntries
        applicationCatalog: applicationLauncher.applicationEntries
        onCloseRequested: shell.hideCommandPalette()
        onControlCenterRequested: shell.showControlCenter()
        onQuickSettingsRequested: shell.showQuickSettings()
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
