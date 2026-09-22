import QtQuick
import QtQuick.Controls
import "../theme"

Slider {
    id: control

    LinuraTheme {
        id: theme
    }

    activeFocusOnTab: true
    implicitWidth: 220
    implicitHeight: 32
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
        width: 18
        height: 18
        radius: 9
        color: control.enabled ? theme.accent : theme.muted
        border.width: control.activeFocus ? 2 : 1
        border.color: control.activeFocus ? theme.focus : theme.background
    }
}
