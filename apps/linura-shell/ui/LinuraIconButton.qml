import QtQuick
import QtQuick.Controls

Button {
    id: control
    property string glyph: ""
    required property string accessibleName
    property string toolTip: ""
    LinuraTheme { id: theme }

    activeFocusOnTab: true
    hoverEnabled: true
    implicitWidth: theme.controlMd
    implicitHeight: theme.controlMd
    padding: 0
    font.pixelSize: theme.iconMd

    contentItem: Text {
        text: control.glyph
        font: control.font
        color: !control.enabled ? theme.muted
            : control.highlighted ? theme.highlightedText : theme.foreground
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
    }

    background: Rectangle {
        radius: theme.radiusMd
        color: control.highlighted ? theme.accent
            : control.down || control.hovered ? theme.surfaceElevated : theme.surface
        border.width: control.activeFocus ? theme.focusBorderWidth : theme.borderWidth
        border.color: control.activeFocus ? theme.focus : theme.surfaceElevated
        opacity: control.enabled ? 1.0 : 0.55
    }

    Accessible.name: accessibleName
    Accessible.role: Accessible.Button
    ToolTip.visible: control.hovered && toolTip.length > 0
    ToolTip.text: toolTip
}
