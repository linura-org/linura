//@ pragma ShellId linura-qualification-controller
import QtQuick
import Quickshell
import Quickshell.Io
import qs.integrations.xdg as Xdg

Scope {
    id: root

    property string completedStatus: ""
    property int completedGeneration: -1

    Xdg.ApplicationLauncherController {
        id: launcher
        onLaunchCompleted: (status, requestGeneration) => {
            root.completedStatus = status
            root.completedGeneration = requestGeneration
        }
    }

    IpcHandler {
        target: "linura.shell-qualification"

        function hasApplication(applicationId: string): bool {
            for (let i = 0; i < launcher.applicationEntries.length; i++) {
                if (launcher.applicationEntries[i].id === applicationId)
                    return true
            }
            return false
        }

        function applicationIsTerminal(applicationId: string): bool {
            for (let i = 0; i < launcher.applicationEntries.length; i++) {
                const entry = launcher.applicationEntries[i]
                if (entry.id === applicationId)
                    return entry.terminal === true
            }
            return false
        }

        function launch(applicationId: string, requestGeneration: int): string {
            return launcher.launchApplication(applicationId, requestGeneration)
        }

        function launchInFlight(): bool {
            return launcher.launchInFlight
        }

        function lastStatus(): string {
            return root.completedStatus
        }

        function lastGeneration(): int {
            return root.completedGeneration
        }

        function resetCompletion(): void {
            root.completedStatus = ""
            root.completedGeneration = -1
        }
    }
}
