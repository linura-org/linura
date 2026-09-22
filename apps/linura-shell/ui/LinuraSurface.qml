import QtQuick

Rectangle {
    id: root
    property string level: "surface"
    property bool outlined: true
    property color outlineColor: theme.surfaceElevated
    property int cornerRadius: theme.radiusLg
    property int outlineWidth: outlined ? theme.borderWidth : 0

    LinuraTheme { id: theme }

    radius: cornerRadius
    color: level === "background" ? theme.background
        : level === "elevated" ? theme.surfaceElevated : theme.surface
    border.width: outlineWidth
    border.color: outlineColor
}
