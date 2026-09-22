import QtQuick
import Quickshell
import Quickshell.Hyprland

Scope {
    id: root

    readonly property var workspaceEntries: buildWorkspaceEntries()

    function buildWorkspaceEntries() {
        const entries = []
        const workspaces = Hyprland.workspaces.values

        for (let i = 0; i < workspaces.length; i++) {
            const workspace = workspaces[i]
            entries.push({
                id: workspace.id,
                name: workspace.name,
                focused: workspace.focused
            })
        }

        return entries
    }

    function activateWorkspace(workspaceId) {
        if (!Number.isInteger(workspaceId))
            return false

        const workspaces = Hyprland.workspaces.values
        for (let i = 0; i < workspaces.length; i++) {
            const workspace = workspaces[i]
            if (workspace.id !== workspaceId)
                continue

            workspace.activate()
            return true
        }

        return false
    }
}
