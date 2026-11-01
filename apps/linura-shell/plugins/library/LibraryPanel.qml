import QtQuick
import QtQuick.Layouts
import org.linura.UI 1.0

// Pure presentation: the host owns authenticated transport, source freshness,
// exact revision binding and every effect. Never execute imported content.
ColumnLayout {
    id: root
    property var entries: []
    property bool loading: false
    property bool sourceAvailable: false
    property string errorText: ""
    property string databaseIdentityLabel: ""
    property bool hasNextPage: false
    signal refreshRequested()
    signal nextPageRequested()
    signal setupSelected(string setupId, int revision)
    signal profileSelected(string profileId, int revision)
    signal focusEntered(var item)
    spacing: theme.spacingMd

    LinuraTheme { id: theme }

    LinuraText {
        Layout.fillWidth: true
        role: "title"
        text: qsTr("Local Library")
        Accessible.name: text
    }

    LinuraText {
        Layout.fillWidth: true
        text: qsTr("Saved locally only. No Setup or MachineProfile shown here is verified as applied to this computer.")
        wrapMode: Text.WordWrap
        Accessible.name: text
    }

    LinuraStatus {
        Layout.fillWidth: true
        text: root.loading ? qsTr("Reading local Library…")
             : root.sourceAvailable ? qsTr("Local Library available")
             : qsTr("Library unavailable — no cached state is authoritative")
        tone: root.sourceAvailable ? "neutral" : "warning"
    }

    LinuraText {
        Layout.fillWidth: true
        visible: root.databaseIdentityLabel.length > 0
        text: qsTr("Database: %1").arg(root.databaseIdentityLabel)
        role: "caption"
        wrapMode: Text.WrapAnywhere
        Accessible.name: text
    }

    LinuraText {
        Layout.fillWidth: true
        visible: root.errorText.length > 0
        text: root.errorText
        wrapMode: Text.WordWrap
        Accessible.name: qsTr("Library error: %1").arg(text)
    }

    LinuraButton {
        text: qsTr("Refresh from local source")
        enabled: !root.loading
        onClicked: root.refreshRequested()
        onActiveFocusChanged: if (activeFocus) root.focusEntered(this)
    }

    LinuraText {
        Layout.fillWidth: true
        visible: root.sourceAvailable && !root.loading && root.entries.length === 0
        text: qsTr("No records on this page.")
        Accessible.name: text
    }

    Repeater {
        model: root.sourceAvailable && !root.loading ? root.entries : []
        delegate: LinuraActionRow {
            required property var modelData
            Layout.fillWidth: true
            title: String(modelData.title || modelData.id)
            description: qsTr("%1 · Revision %2 · Local record only").arg(
                String(modelData.id)).arg(Number(modelData.revision))
            enabled: modelData.kind === "setup" || modelData.kind === "profile"
            onClicked: {
                if (modelData.kind === "setup")
                    root.setupSelected(String(modelData.id), Number(modelData.revision));
                else if (modelData.kind === "profile")
                    root.profileSelected(String(modelData.id), Number(modelData.revision));
            }
            onActiveFocusChanged: if (activeFocus) root.focusEntered(this)
        }
    }

    LinuraButton {
        visible: root.hasNextPage && root.sourceAvailable
        text: qsTr("Next page")
        enabled: !root.loading
        onClicked: root.nextPageRequested()
        onActiveFocusChanged: if (activeFocus) root.focusEntered(this)
    }
}
