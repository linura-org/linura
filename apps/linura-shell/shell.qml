import QtQuick
import Quickshell
import org.linura.ShellBridge 1.0
import "plugins/control-center"

ShellRoot {
    id: shell

    property bool controlCenterOpen: false

    AudioSessionController {
        id: audioController
    }

    IpcHandler {
        target: "linura.shell"

        function showControlCenter() {
            shell.controlCenterOpen = true
        }

        function hideControlCenter() {
            shell.controlCenterOpen = false
        }

        function toggleControlCenter() {
            if (shell.controlCenterOpen)
                hideControlCenter()
            else
                showControlCenter()
        }
    }

    ControlCenterPanel {
        opened: shell.controlCenterOpen
        controller: audioController
        onCloseRequested: shell.controlCenterOpen = false
    }
}
