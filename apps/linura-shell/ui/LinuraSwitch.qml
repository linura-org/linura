import QtQuick
import QtQuick.Controls

Switch {
    id: control
    property string accessibleName: ""
    LinuraTheme { id: theme }

    activeFocusOnTab: true
    hoverEnabled: true
    implicitHeight: theme.controlMd
    spacing: theme.spacingMd

    indicator: Rectangle {
        implicitWidth: theme.controlMd + theme.spacingXs
        implicitHeight: theme.spacingXl
        width: implicitWidth
        height: implicitHeight
        x: control.mirrored ? control.width - width - control.rightPadding : control.leftPadding
        y: control.topPadding + (control.availableHeight - height) / 2
        radius: height / 2
        color: control.checked ? theme.accent : theme.surfaceElevated
        border.width: control.activeFocus ? theme.focusBorderWidth : theme.borderWidth
        border.color: control.activeFocus ? theme.focus : theme.surfaceElevated
        opacity: control.enabled ? 1.0 : 0.55

        Rectangle {
            width: parent.height - theme.spacingSm
            height: width
            radius: width / 2
            x: theme.spacingXs
                + control.visualPosition * (parent.width - width - theme.spacingXs * 2)
            y: (parent.height - height) / 2
            color: control.checked ? theme.highlightedText : theme.foreground
        }
    }

    contentItem: Text {
        text: control.text
        font.pixelSize: theme.typeBody
        color: control.enabled ? theme.foreground : theme.muted
        verticalAlignment: Text.AlignVCenter
        leftPadding: control.mirrored ? 0 : control.indicator.width + control.spacing
        rightPadding: control.mirrored ? control.indicator.width + control.spacing : 0
        elide: Text.ElideRight
    }

    Accessible.name: accessibleName.length > 0 ? accessibleName : control.text
    Accessible.role: Accessible.CheckBox
}
