import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

AbstractButton {
    id: control
    property string title: ""
    property string description: ""
    property string shortcut: ""
    property bool selected: false
    property string accessibleName: ""
    LinuraTheme { id: theme }

    activeFocusOnTab: true
    hoverEnabled: true
    implicitWidth: Math.max(280, row.implicitWidth + theme.spacingXl * 2)
    implicitHeight: Math.max(theme.controlLg, row.implicitHeight + theme.spacingMd * 2)
    leftPadding: theme.spacingLg
    rightPadding: theme.spacingLg
    topPadding: theme.spacingMd
    bottomPadding: theme.spacingMd

    contentItem: RowLayout {
        id: row
        spacing: theme.spacingMd
        ColumnLayout {
            Layout.fillWidth: true
            spacing: theme.spacingXs
            LinuraText {
                Layout.fillWidth: true
                text: control.title
                emphasized: true
                elide: Text.ElideRight
            }
            LinuraText {
                Layout.fillWidth: true
                visible: control.description.length > 0
                text: control.description
                role: "caption"
                muted: true
                elide: Text.ElideRight
            }
        }
        LinuraText {
            visible: control.shortcut.length > 0
            text: control.shortcut
            role: "caption"
            muted: true
        }
    }

    background: LinuraSurface {
        level: control.selected || control.hovered || control.down ? "elevated" : "surface"
        cornerRadius: theme.radiusMd
        outlineColor: control.activeFocus ? theme.focus : theme.surfaceElevated
        outlineWidth: control.activeFocus ? theme.focusBorderWidth : theme.borderWidth
        opacity: control.enabled ? 1.0 : 0.55
    }

    Accessible.name: accessibleName.length > 0 ? accessibleName : title
    Accessible.description: description
    Accessible.role: Accessible.Button
    Accessible.selectable: true
    Accessible.selected: control.selected
}
