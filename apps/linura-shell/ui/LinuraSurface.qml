import QtQuick
import "../theme"

Rectangle {
    id: root

    property string level: "surface"
    property bool outlined: true
    property color outlineColor: theme.surfaceElevated
    property int cornerRadius: theme.radiusLg

    LinuraTheme {
        id: theme
    }

    radius: cornerRadius
    color: level === "background"
        ? theme.background
        : level === "elevated"
            ? theme.surfaceElevated
            : theme.surface
    border.width: outlined ? 1 : 0
    border.color: outlineColor
}
