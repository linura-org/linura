import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Wayland
import org.linura.UI 1.0

PanelWindow {
    id: root

    property bool opened: false
    property int selectedIndex: 0
    property int sessionGeneration: 0
    property var results: []
    property var workspaceCatalog: []
    property var applicationCatalog: []
    property string statusText: ""

    readonly property var catalog: [
        {
            kind: "surface",
            targetId: "navigation:control-center",
            title: qsTr("Control Center"),
            description: qsTr("Open authoritative current-session controls"),
            keywords: "control center settings quick audio volume",
            shortcut: qsTr("Enter")
        }
    ]

    signal closeRequested()
    signal controlCenterRequested()
    signal workspaceRequested(int workspaceId)
    signal applicationRequested(string applicationId, int sessionGeneration)

    visible: opened
    implicitHeight: Math.min(560, paletteSurface.implicitHeight + theme.spacing2xl * 3)
    color: "transparent"
    exclusionMode: ExclusionMode.Ignore

    anchors {
        top: true
        left: true
        right: true
    }

    WlrLayershell.namespace: "linura-command-palette"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: opened
        ? WlrKeyboardFocus.OnDemand
        : WlrKeyboardFocus.None

    LinuraTheme {
        id: theme
    }

    function workspaceTitle(workspace) {
        const label = workspace.name && workspace.name.length > 0
            ? workspace.name
            : String(workspace.id)
        return qsTr("Workspace %1").arg(label)
    }

    function workspaceDescription(workspace) {
        if (workspace.focused)
            return qsTr("Current Hyprland workspace")
        return qsTr("Switch to Hyprland workspace")
    }

    function workspaceEntry(workspace) {
        return {
            kind: "workspace",
            targetId: "navigation:workspace:" + workspace.id,
            workspaceId: workspace.id,
            title: workspaceTitle(workspace),
            description: workspaceDescription(workspace),
            keywords: "workspace hyprland " + workspace.name + " " + workspace.id,
            shortcut: workspace.focused ? qsTr("Current") : qsTr("Enter")
        }
    }

    function applicationEntry(application) {
        const genericName = application.genericName || ""
        const comment = application.comment || ""
        const keywords = application.keywords ? application.keywords.join(" ") : ""
        const categories = application.categories ? application.categories.join(" ") : ""
        const description = genericName.length > 0
            ? genericName
            : (comment.length > 0 ? comment : qsTr("Launch desktop application"))

        return {
            kind: "application",
            targetId: "application:desktop-entry:" + application.id,
            applicationId: application.id,
            title: application.name || application.id,
            description: application.terminal
                ? qsTr("%1 — terminal launch unsupported").arg(description)
                : description,
            keywords: "application app launcher " + application.id + " "
                + keywords + " " + categories,
            shortcut: application.terminal ? qsTr("Unavailable") : qsTr("Enter"),
            disabled: application.terminal
        }
    }

    function matches(entry, needle) {
        if (needle.length === 0)
            return true
        const haystack = (entry.title + " " + entry.description + " " + entry.keywords)
            .toLowerCase()
        return haystack.indexOf(needle) !== -1
    }

    function refreshResults() {
        const needle = queryField.text.trim().toLowerCase()
        const next = []

        for (let i = 0; i < catalog.length; i++) {
            const entry = catalog[i]
            if (matches(entry, needle))
                next.push(entry)
        }

        for (let i = 0; i < workspaceCatalog.length; i++) {
            const entry = workspaceEntry(workspaceCatalog[i])
            if (matches(entry, needle))
                next.push(entry)
        }

        for (let i = 0; i < applicationCatalog.length; i++) {
            const entry = applicationEntry(applicationCatalog[i])
            if (matches(entry, needle))
                next.push(entry)
        }

        results = next
        if (results.length === 0)
            selectedIndex = -1
        else
            selectedIndex = Math.max(0, Math.min(selectedIndex, results.length - 1))

        ensureSelectedResultVisible()
    }

    function ensureSelectedResultVisible() {
        if (!opened || selectedIndex < 0)
            return

        Qt.callLater(function() {
            if (!root.opened || root.selectedIndex < 0)
                return
            if (root.selectedIndex >= resultList.count)
                return

            resultList.positionViewAtIndex(root.selectedIndex, ListView.Contain)
        })
    }

    function selectedAccessibilityDescription() {
        if (selectedIndex < 0 || selectedIndex >= results.length)
            return qsTr("No matching results.")

        const entry = results[selectedIndex]
        return qsTr("Selected result %1 of %2: %3. %4")
            .arg(selectedIndex + 1)
            .arg(results.length)
            .arg(entry.title)
            .arg(entry.description)
    }

    function moveSelection(delta) {
        if (results.length === 0) {
            selectedIndex = -1
            return
        }

        const current = selectedIndex < 0 ? 0 : selectedIndex
        selectedIndex = (current + delta + results.length) % results.length
        ensureSelectedResultVisible()
    }

    function completeWorkspaceRequest(activated) {
        if (!opened)
            return

        if (activated) {
            statusText = ""
            closeRequested()
            return
        }

        statusText = qsTr("That workspace is no longer available.")
        refreshResults()
    }

    function completeApplicationRequest(status, requestGeneration) {
        if (!opened || requestGeneration !== sessionGeneration)
            return

        if (status === "launched") {
            statusText = ""
            closeRequested()
            return
        }

        if (status === "terminal-unsupported") {
            statusText = qsTr("Terminal applications are not supported by this launcher yet.")
            return
        }

        if (status === "busy") {
            statusText = qsTr("An application launch is already in progress.")
            return
        }

        if (status === "broker-failed") {
            statusText = qsTr("The user session could not start that application.")
            return
        }

        if (status === "not-found" || status === "not-visible") {
            statusText = qsTr("That application is no longer available.")
            refreshResults()
            return
        }

        statusText = qsTr("That application target is invalid.")
    }

    function activate(index) {
        if (index < 0 || index >= results.length)
            return

        const entry = results[index]
        if (entry.targetId === "navigation:control-center") {
            statusText = ""
            controlCenterRequested()
            return
        }

        if (entry.kind === "workspace") {
            statusText = ""
            workspaceRequested(entry.workspaceId)
            return
        }

        if (entry.kind === "application") {
            if (entry.disabled) {
                statusText = qsTr("Terminal applications are not supported by this launcher yet.")
                return
            }

            statusText = ""
            applicationRequested(entry.applicationId, sessionGeneration)
            return
        }

        statusText = qsTr("Unsupported palette target.")
    }

    onOpenedChanged: {
        if (opened) {
            sessionGeneration++
            selectedIndex = 0
            statusText = ""
            queryField.text = ""
            refreshResults()
            Qt.callLater(function() {
                if (root.opened)
                    queryField.forceActiveFocus(Qt.ShortcutFocusReason)
            })
        }
    }

    onWorkspaceCatalogChanged: {
        if (opened)
            refreshResults()
    }

    onApplicationCatalogChanged: {
        if (opened)
            refreshResults()
    }

    Component.onCompleted: refreshResults()

    Shortcut {
        sequence: "Escape"
        enabled: root.opened
        onActivated: root.closeRequested()
    }

    LinuraSurface {
        id: paletteSurface
        width: Math.min(760, root.width - theme.spacing2xl * 2)
        implicitHeight: paletteColumn.implicitHeight + theme.spacingXl * 2
        anchors.top: parent.top
        anchors.topMargin: theme.spacing2xl
        anchors.horizontalCenter: parent.horizontalCenter
        level: "background"
        cornerRadius: theme.radiusXl

        ColumnLayout {
            id: paletteColumn
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.margins: theme.spacingXl
            spacing: theme.spacingLg

            RowLayout {
                Layout.fillWidth: true

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: theme.spacingXs

                    LinuraText {
                        text: qsTr("Command Palette")
                        role: "display"
                        Accessible.name: text
                    }

                    LinuraText {
                        Layout.fillWidth: true
                        text: qsTr("Find Linura surfaces, applications and Hyprland workspaces")
                        muted: true
                        elide: Text.ElideRight
                        Accessible.name: text
                    }
                }

                LinuraButton {
                    text: qsTr("Close")
                    onClicked: root.closeRequested()
                    Accessible.name: qsTr("Close command palette")
                }
            }

            LinuraTextField {
                id: queryField
                Layout.fillWidth: true
                placeholderText: qsTr("Search Linura")
                accessibleName: qsTr("Search command palette")
                accessibleDescription: root.selectedAccessibilityDescription()

                onTextChanged: {
                    root.selectedIndex = 0
                    root.refreshResults()
                }

                Keys.onDownPressed: event => {
                    root.moveSelection(1)
                    event.accepted = true
                }

                Keys.onUpPressed: event => {
                    root.moveSelection(-1)
                    event.accepted = true
                }

                Keys.onReturnPressed: event => {
                    root.activate(root.selectedIndex)
                    event.accepted = true
                }

                Keys.onEnterPressed: event => {
                    root.activate(root.selectedIndex)
                    event.accepted = true
                }
            }

            ListView {
                id: resultList
                Layout.fillWidth: true
                Layout.preferredHeight: Math.min(contentHeight, 280)
                visible: root.results.length > 0
                clip: true
                spacing: theme.spacingSm
                model: root.results
                currentIndex: root.selectedIndex
                highlightFollowsCurrentItem: true

                delegate: LinuraActionRow {
                    required property int index
                    required property var modelData

                    width: resultList.width
                    title: modelData.title
                    description: modelData.description
                    shortcut: modelData.shortcut
                    selected: index === root.selectedIndex

                    onClicked: {
                        root.selectedIndex = index
                        root.activate(index)
                    }
                }
            }

            LinuraText {
                Layout.fillWidth: true
                visible: root.results.length === 0
                text: qsTr("No Linura surface, application or workspace matches this search.")
                muted: true
                wrapMode: Text.WordWrap
                Accessible.name: text
            }

            LinuraStatus {
                Layout.fillWidth: true
                visible: root.statusText.length > 0
                text: root.statusText
                tone: "warning"
            }

            LinuraText {
                Layout.fillWidth: true
                text: qsTr("Workspace switching and trusted desktop-entry application launch are bounded experience actions. Managed effects remain typed Control operations; the palette never accepts shell, Exec, or compositor command strings.")
                role: "caption"
                muted: true
                wrapMode: Text.WordWrap
                Accessible.name: text
            }
        }
    }
}
