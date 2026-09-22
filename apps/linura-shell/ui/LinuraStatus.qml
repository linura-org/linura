import QtQuick
import QtQuick.Layouts

Item {
    id: root
    property string text: ""
    property string tone: "neutral"
    property bool muted: false
    LinuraTheme { id: theme }

    function toneColor() {
        if (tone === "danger")
            return theme.danger
        if (tone === "warning")
            return theme.warning
        if (tone === "success")
            return theme.success
        if (tone === "accent")
            return theme.accent
        return theme.muted
    }

    implicitWidth: row.implicitWidth
    implicitHeight: row.implicitHeight

    RowLayout {
        id: row
        anchors.fill: parent
        spacing: theme.spacingSm
        Rectangle {
            Layout.alignment: Qt.AlignVCenter
            implicitWidth: theme.spacingSm
            implicitHeight: theme.spacingSm
            radius: width / 2
            color: root.toneColor()
        }
        LinuraText {
            Layout.fillWidth: true
            text: root.text
            muted: root.muted
            elide: Text.ElideRight
        }
    }

    Accessible.name: text
    Accessible.role: Accessible.StaticText
}
