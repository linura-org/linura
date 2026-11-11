import QtQuick
import QtQuick.Layouts
import org.linura.UI 1.0

// S18-9 read-only client. Never claims "connected", portal-free, internet
// reachability, recovered access or native authorization from an NM reading.
LinuraSurface {
    id: root

    required property var controller
    implicitHeight: networkColumn.implicitHeight + theme.spacingXl * 2

    LinuraTheme {
        id: theme
    }

    ColumnLayout {
        id: networkColumn
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.margins: theme.spacingXl
        spacing: theme.spacingSm

        RowLayout {
            Layout.fillWidth: true

            LinuraText {
                Layout.fillWidth: true
                text: qsTr("Network")
                role: "title"
                Accessible.name: text
            }

            LinuraButton {
                text: qsTr("Refresh")
                enabled: root.controller.active && !root.controller.busy
                onClicked: root.controller.refresh()
                Accessible.name: qsTr("Refresh read-only Linura Control network observation")
                Accessible.description: qsTr("This does not connect, disconnect, save or delete profiles.")
            }
        }

        LinuraStatus {
            Layout.fillWidth: true
            text: root.controller.statusText
            tone: root.controller.sourceStatus === "observed-only" ? "neutral" : "warning"
            Accessible.name: text
        }

        LinuraText {
            Layout.fillWidth: true
            text: qsTr("Connection, captive portal, effective routing, DNS and internet reachability have not been independently verified. Network changes remain disabled.")
            role: "caption"
            muted: true
            wrapMode: Text.WordWrap
            Accessible.name: text
        }
    }
}
