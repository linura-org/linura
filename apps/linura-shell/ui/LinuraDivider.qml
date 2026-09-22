import QtQuick

Rectangle {
    id: root
    property bool vertical: false
    LinuraTheme { id: theme }

    implicitWidth: vertical ? theme.borderWidth : theme.controlLg
    implicitHeight: vertical ? theme.controlLg : theme.borderWidth
    color: theme.surfaceElevated
}
