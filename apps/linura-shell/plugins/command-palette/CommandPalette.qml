import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Wayland
import org.linura.UI 1.0

PanelWindow {
    id: root

    property bool opened: false
    property int selectedIndex: 0
    property var results: []
    property string statusText: ""

    readonly property var catalog: [
        {
            targetId: "navigation:control-center",
            title: qsTr("Control Center"),
            description: qsTr("Open authoritative current-session controls"),
            keywords: "control center settings quick audio volume",
            shortcut: qsTr("Enter")
        }
    ]

    signal closeRequested()
    signal controlCenterRequested()

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

    function refreshResults() {
        const needle = queryField.text.trim().toLowerCase()
        const next = []

        for (let i = 0; i < catalog.length; i++) {
            const entry = catalog[i]
            const haystack = (entry.title + " " + entry.description + " " + entry.keywords)
                .toLowerCase()
            if (needle.length === 0 || haystack.indexOf(needle) !== -1)
                next.push(entry)
        }

        results = next
        if (results.length === 0)
            selectedIndex = -1
        else
            selectedIndex = Math.max(0, Math.min(selectedIndex, results.length - 1))
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
    }

    function activate(index) {
        if (index < 0 || index >= results.length)
            return

        const target = results[index].targetId
        if (target === "navigation:control-center") {
            statusText = ""
            controlCenterRequested()
            return
        }

        statusText = qsTr("Unsupported palette target.")
    }

    onOpenedChanged: {
        if (opened) {
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
                        text: qsTr("Find trusted Linura navigation targets")
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
                text: qsTr("No Linura navigation targets match this search.")
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
                text: qsTr("This slice is navigation-only. Effectful palette actions remain typed Control operations, never shell text.")
                role: "caption"
                muted: true
                wrapMode: Text.WordWrap
                Accessible.name: text
            }
        }
    }
}
