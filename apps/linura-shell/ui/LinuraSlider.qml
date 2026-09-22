import QtQuick
import QtQuick.Controls

Slider {
    id: control
    LinuraTheme { id: theme }
    activeFocusOnTab: true
    implicitWidth: 220
    implicitHeight: theme.controlSm
    leftPadding: 9
    rightPadding: 9
    topPadding: 7
    bottomPadding: 7

    background: Rectangle {
        x: control.leftPadding
        y: control.topPadding + (control.availableHeight - height) / 2
        width: control.availableWidth
        height: 4
        radius: 2
        color: theme.surfaceElevated
        Rectangle {
            width: control.visualPosition * parent.width
            height: parent.height
            radius: parent.radius
            color: control.enabled ? theme.accent : theme.muted
        }
    }

    handle: Rectangle {
        x: control.leftPadding + control.visualPosition * (control.availableWidth - width)
        y: control.topPadding + (control.availableHeight - height) / 2
        width: theme.iconMd
        height: theme.iconMd
        radius: width / 2
        color: control.enabled ? theme.accent : theme.muted
        border.width: control.activeFocus ? theme.focusBorderWidth : theme.borderWidth
        border.color: control.activeFocus ? theme.focus : theme.background
    }
}
