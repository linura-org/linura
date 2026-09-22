import QtQuick
import QtQuick.Controls
import "../theme"

Label {
    id: root

    property string role: "body"
    property bool muted: false
    property bool emphasized: role === "display" || role === "title"

    LinuraTheme {
        id: theme
    }

    color: muted ? theme.muted : theme.foreground
    font.pixelSize: role === "display"
        ? theme.typeDisplay
        : role === "title"
            ? theme.typeTitle
            : role === "caption"
                ? theme.typeCaption
                : theme.typeBody
    font.bold: emphasized
}
