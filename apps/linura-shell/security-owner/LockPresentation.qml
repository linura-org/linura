import QtQuick
import org.linura.UI 1.0

LinuraSurface {
    id: root
    level: "background"
    outlined: false
    cornerRadius: 0
    clip: true
    property string heading: "Session locked"
    property string explanation: "Protected session authentication"
    property string primaryLabel: "Request unlock"
    property bool primaryAvailable: true
    property bool cancelAvailable: false
    property bool inputVisible: false
    readonly property bool layoutFits: content.implicitHeight + theme.spacingLg * 2 <= card.height
    readonly property rect primaryRectangle: Qt.rect(card.x + content.x + actions.x + primary.x, card.y + content.y + actions.y + primary.y, primary.width, primary.height)
    readonly property rect cancelRectangle: Qt.rect(card.x + content.x + actions.x + cancel.x, card.y + content.y + actions.y + cancel.y, cancel.width, cancel.height)
    readonly property color inputForeground: theme.foreground
    readonly property color inputSurface: theme.surface
    readonly property color inputFocusColor: theme.focus
    readonly property rect inputRectangle: Qt.rect(card.x + content.x + inputSlot.x, card.y + content.y + inputSlot.y, inputSlot.width, inputSlot.height)

    LinuraTheme {
        id: theme
    }
    LinuraSurface {
        id: card
        anchors.centerIn: parent
        width: Math.max(0, Math.min(480, parent.width))
        height: Math.min(parent.height, content.implicitHeight + theme.spacingLg * 2)
        Column {
            id: content
            anchors.centerIn: parent
            width: Math.max(0, parent.width - theme.spacingLg * 2)
            spacing: theme.spacingSm
            LinuraText {
                width: parent.width
                text: root.heading
                role: "title"
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
                Accessible.role: Accessible.Heading
                Accessible.name: text
            }
            LinuraText {
                width: parent.width
                text: root.explanation
                muted: true
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
                Accessible.role: Accessible.StaticText
                Accessible.name: text
            }
            Item {
                id: inputSlot
                width: parent.width
                height: root.inputVisible ? theme.controlLg : 0
                visible: root.inputVisible
            }
            Row {
                id: actions
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: theme.spacingSm
                LinuraButton {
                    id: primary
                    text: root.primaryLabel
                    enabled: root.primaryAvailable
                    width: Math.max(0, Math.min(200, (content.width - actions.spacing) / 2))
                    Accessible.name: text
                }
                LinuraButton {
                    id: cancel
                    text: "Cancel"
                    enabled: root.cancelAvailable
                    width: primary.width
                    Accessible.name: text
                }
            }
        }
    }
    // Native C++ adds protected input above this presentation. There is no QML
    // password/text input, key handler, authority object or lock-state setter.
}
