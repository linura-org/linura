import QtQuick
import QtQuick.Controls

TextField {
    id: control
    property bool invalid: false
    property string errorText: ""
    property string accessibleName: ""
    property string accessibleDescription: ""
    LinuraTheme { id: theme }

    activeFocusOnTab: true
    selectByMouse: true
    implicitHeight: theme.controlMd
    leftPadding: theme.spacingMd
    rightPadding: theme.spacingMd
    topPadding: 0
    bottomPadding: 0
    color: control.enabled ? theme.foreground : theme.muted
    placeholderTextColor: theme.muted
    selectionColor: theme.accent
    selectedTextColor: theme.highlightedText
    font.pixelSize: theme.typeBody
    verticalAlignment: TextInput.AlignVCenter

    background: Rectangle {
        radius: theme.radiusMd
        color: theme.surface
        border.width: control.activeFocus ? theme.focusBorderWidth : theme.borderWidth
        border.color: control.invalid ? theme.danger
            : control.activeFocus ? theme.focus : theme.surfaceElevated
        opacity: control.enabled ? 1.0 : 0.55
    }

    Accessible.name: accessibleName.length > 0 ? accessibleName : placeholderText
    Accessible.description: invalid ? errorText : accessibleDescription
    Accessible.role: Accessible.EditableText
}
