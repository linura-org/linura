import QtQuick
import QtQuick.Layouts
import org.linura.UI 1.0
import org.linura.ShellBridge 1.0

ColumnLayout {
    id: root
    required property var controller
    signal focusEntered(var item)
    spacing: theme.spacingSm

    LinuraTheme {
        id: theme
    }

    LinuraText {
        Layout.fillWidth: true
        text: qsTr("Power and session")
        role: "title"
        Accessible.name: text
    }

    LinuraText {
        Layout.fillWidth: true
        text: qsTr("These actions secure your session first, then require action-specific administrator authentication in the native locker. Logout, reboot and shutdown can lose unsaved work. Inhibitors and other sessions are never bypassed.")
        wrapMode: Text.WordWrap
        Accessible.name: text
    }

    Repeater {
        model: [{
                "label": qsTr("Lock then suspend"),
                "action": SessionController.Suspend
            }, {
                "label": qsTr("Log out…"),
                "action": SessionController.Logout
            }, {
                "label": qsTr("Reboot…"),
                "action": SessionController.Reboot
            }, {
                "label": qsTr("Shut down…"),
                "action": SessionController.PowerOff
            }]
        delegate: LinuraButton {
            required property var modelData
            Layout.fillWidth: true
            text: modelData.label
            enabled: !root.controller.busy && !root.controller.hasPending
            onClicked: root.controller.request(modelData.action)
            onActiveFocusChanged: if (activeFocus)
                root.focusEntered(this)
            Accessible.name: text
            Accessible.description: qsTr("Secures this session, then requests native administrator authentication for the exact action. No force or inhibitor bypass.")
        }
    }
}
