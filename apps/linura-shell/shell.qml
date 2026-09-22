import QtQuick
import Quickshell
import Quickshell.Hyprland
import org.linura.ShellBridge 1.0
import "plugins/control-center"
import "plugins/command-palette"

ShellRoot {
    id: shell

    property bool controlCenterOpen: false
    property bool commandPaletteOpen: false

    function showControlCenter() {
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

    function showCommandPalette() {
        shell.controlCenterOpen = false
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
        name: "commandPalette"
        description: "Toggle Linura command palette"
        onPressed: shell.toggleCommandPalette()
    }

    ControlCenterPanel {
        opened: shell.controlCenterOpen
        controller: audioController
        onCloseRequested: shell.hideControlCenter()
    }

    CommandPalette {
        opened: shell.commandPaletteOpen
        onCloseRequested: shell.hideCommandPalette()
        onControlCenterRequested: shell.showControlCenter()
    }
}
