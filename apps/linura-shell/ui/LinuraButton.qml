import QtQuick
import QtQuick.Controls

Button {
    id: control
    LinuraTheme {
        id: theme
    }
    activeFocusOnTab: true
    font.pixelSize: theme.typeBody
    implicitHeight: theme.controlMd
    implicitWidth: Math.max(96, contentItem.implicitWidth + theme.spacingXl * 2)
    leftPadding: theme.spacingLg
    rightPadding: theme.spacingLg
    topPadding: theme.spacingSm
    bottomPadding: theme.spacingSm

    contentItem: Text {
        text: control.text
        font: control.font
        color: !control.enabled ? theme.muted : control.highlighted ? theme.highlightedText : theme.foreground
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
    }

    background: Rectangle {
        radius: theme.radiusMd
        color: control.highlighted ? theme.accent : control.down ? theme.surfaceElevated : theme.surface
        border.width: control.activeFocus ? theme.focusBorderWidth : theme.borderWidth
        border.color: control.activeFocus ? theme.focus : theme.surfaceElevated
        opacity: control.enabled ? 1.0 : 0.55
    }
}
