import QtQuick
import QtQuick.Layouts
import org.linura.UI 1.0

// Review only. A portable SHA-256 digest establishes no signer identity;
// imported approvals, policy, effects and secrets must not be restored.
ColumnLayout {
    id: root
    property string rootId: ""
    property int rootRevision: 0
    property string digest: ""
    property var blockers: []
    property bool requiresPlan: true
    property bool reviewAvailable: false
    signal cancelRequested()
    signal focusEntered(var item)
    spacing: theme.spacingMd

    LinuraTheme { id: theme }

    LinuraText {
        role: "title"
        text: qsTr("Portable Library review")
        Accessible.name: text
    }

    LinuraStatus {
        Layout.fillWidth: true
        tone: root.reviewAvailable && root.blockers.length === 0 ? "warning" : "danger"
        text: !root.reviewAvailable ? qsTr("No validated import review available")
            : root.blockers.length > 0 ? qsTr("Target compatibility blocked")
            : qsTr("Local review only — machine plan required")
    }

    LinuraText {
        Layout.fillWidth: true
        text: qsTr("Root: %1 · Revision: %2").arg(root.rootId).arg(root.rootRevision)
        wrapMode: Text.WrapAnywhere
        Accessible.name: text
    }

    LinuraText {
        Layout.fillWidth: true
        visible: root.reviewAvailable
        text: qsTr("Canonical content SHA-256: %1").arg(root.digest)
        wrapMode: Text.WrapAnywhere
        Accessible.name: text
    }

    Repeater {
        model: root.blockers
        delegate: LinuraText {
            required property string modelData
            Layout.fillWidth: true
            text: qsTr("Blocker: %1").arg(modelData)
            wrapMode: Text.WordWrap
            Accessible.name: text
        }
    }

    LinuraText {
        Layout.fillWidth: true
        text: qsTr("This review cannot save the import, authorize Control, restore credentials, execute a Setup or claim that the machine has changed.")
        wrapMode: Text.WordWrap
        Accessible.name: text
    }

    LinuraButton {
        text: qsTr("Close review")
        onClicked: root.cancelRequested()
        onActiveFocusChanged: if (activeFocus) root.focusEntered(this)
    }
}
