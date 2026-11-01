import QtQuick
import QtQuick.Layouts
import org.linura.UI 1.0

// No compositor/provider execution and no claims of machine convergence.
ColumnLayout {
    id: root
    required property string profileId
    required property int baseRevision
    property string draftName: ""
    property string machineClassLabel: ""
    property bool saving: false
    property bool authenticatedWriteAvailable: false
    property string errorText: ""
    signal saveRequested(string profileId, int baseRevision, string name)
    signal cancelRequested()
    signal focusEntered(var item)
    spacing: theme.spacingMd

    LinuraTheme { id: theme }

    LinuraText {
        Layout.fillWidth: true
        role: "title"
        text: qsTr("Edit MachineProfile")
        Accessible.name: text
    }

    LinuraText {
        Layout.fillWidth: true
        text: qsTr("Exact ID: %1 · Base revision: %2").arg(root.profileId).arg(root.baseRevision)
        wrapMode: Text.WrapAnywhere
        Accessible.name: text
    }

    LinuraText {
        Layout.fillWidth: true
        text: qsTr("Machine class: %1. Existing immutable Setup/Intent references remain subject to exact validation. Saving is local only.").arg(root.machineClassLabel)
        wrapMode: Text.WordWrap
        Accessible.name: text
    }

    LinuraTextField {
        Layout.fillWidth: true
        text: root.draftName
        placeholderText: qsTr("MachineProfile name")
        accessibleName: qsTr("MachineProfile name")
        onTextEdited: root.draftName = text
        onActiveFocusChanged: if (activeFocus) root.focusEntered(this)
    }

    LinuraText {
        Layout.fillWidth: true
        visible: root.errorText.length > 0
        text: root.errorText
        wrapMode: Text.WordWrap
        Accessible.name: qsTr("Profile error: %1").arg(text)
    }

    RowLayout {
        Layout.fillWidth: true
        spacing: theme.spacingSm

        LinuraButton {
            text: qsTr("Cancel draft")
            enabled: !root.saving
            onClicked: root.cancelRequested()
            onActiveFocusChanged: if (activeFocus) root.focusEntered(this)
        }

        LinuraButton {
            text: qsTr("Request local revision save")
            enabled: root.authenticatedWriteAvailable && !root.saving
                && root.profileId.length > 0 && root.baseRevision > 0
                && root.draftName.trim().length > 0
            onClicked: root.saveRequested(root.profileId, root.baseRevision,
                                          root.draftName)
            onActiveFocusChanged: if (activeFocus) root.focusEntered(this)
            Accessible.description: qsTr("Only the trusted backend may authenticate the owner and commit the exact new revision.")
        }
    }
}
