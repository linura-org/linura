import QtQuick
import QtQuick.Layouts
import org.linura.UI 1.0

// The host must reauthenticate and re-read exact identity, base revision
// and complete graph before invoking the existing local CAS save.
ColumnLayout {
    id: root
    required property string setupId
    required property int baseRevision
    property string draftName: ""
    property string draftDescription: ""
    property bool saving: false
    property bool authenticatedWriteAvailable: false
    property string errorText: ""
    signal saveRequested(string setupId, int baseRevision, string name, string description)
    signal cancelRequested()
    signal focusEntered(var item)
    spacing: theme.spacingMd

    LinuraTheme { id: theme }

    LinuraText {
        Layout.fillWidth: true
        text: qsTr("Edit Setup")
        role: "title"
        Accessible.name: text
    }

    LinuraText {
        Layout.fillWidth: true
        text: qsTr("Exact ID: %1 · Base revision: %2").arg(root.setupId).arg(root.baseRevision)
        wrapMode: Text.WrapAnywhere
        Accessible.name: text
    }

    LinuraText {
        Layout.fillWidth: true
        text: qsTr("Only a new immutable local revision can be saved. This does not apply machine configuration.")
        wrapMode: Text.WordWrap
        Accessible.name: text
    }

    LinuraTextField {
        Layout.fillWidth: true
        text: root.draftName
        placeholderText: qsTr("Setup name")
        accessibleName: qsTr("Setup name")
        onTextEdited: root.draftName = text
        onActiveFocusChanged: if (activeFocus) root.focusEntered(this)
    }

    LinuraTextField {
        Layout.fillWidth: true
        text: root.draftDescription
        placeholderText: qsTr("Setup description")
        accessibleName: qsTr("Setup description")
        onTextEdited: root.draftDescription = text
        onActiveFocusChanged: if (activeFocus) root.focusEntered(this)
    }

    LinuraText {
        Layout.fillWidth: true
        visible: root.errorText.length > 0
        text: root.errorText
        wrapMode: Text.WordWrap
        Accessible.name: qsTr("Save error: %1").arg(text)
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
                && root.setupId.length > 0 && root.draftName.trim().length > 0
                && root.baseRevision > 0
            onClicked: root.saveRequested(root.setupId, root.baseRevision,
                                          root.draftName, root.draftDescription)
            onActiveFocusChanged: if (activeFocus) root.focusEntered(this)
            Accessible.description: qsTr("Requires authenticated owner, exact compare-and-swap and independent readback. Never applies a machine effect.")
        }
    }
}
