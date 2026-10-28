import QtQuick
import QtQuick.Layouts
import org.linura.UI 1.0
import org.linura.ShellBridge 1.0

ColumnLayout {
    id: root
    required property var controller
    property string idleAdvisory: qsTr("Compositor idle observation unavailable.")
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

    LinuraText {
        id: idleInputAdvisory
        objectName: "idleInputAdvisory"
        Layout.fillWidth: true
        text: root.idleAdvisory
        wrapMode: Text.WordWrap
        Accessible.role: Accessible.StaticText
        Accessible.name: text
        Accessible.description: qsTr("A compositor input hint only. Never a lock, power or authorization decision.")
    }

    LinuraText {
        Layout.fillWidth: true
        text: qsTr("Automatic idle actions are not enabled. An inactivity hint cannot authorize locking, screen blanking, suspend, logout, reboot or shutdown. Use the manual controls below.")
        wrapMode: Text.WordWrap
        Accessible.name: text
    }

    LinuraText {
        Layout.fillWidth: true
        text: root.controller.idlePreferenceStatus
        wrapMode: Text.WordWrap
        Accessible.name: text
    }

    LinuraButton {
        Layout.fillWidth: true
        text: qsTr("Refresh idle preference")
        enabled: !root.controller.busy && !root.controller.hasPending && !root.controller.idlePreferenceBusy
        onClicked: root.controller.refreshIdleAdvisoryPreference()
        onActiveFocusChanged: if (activeFocus)
            root.focusEntered(this)
        Accessible.name: text
        Accessible.description: qsTr("Read-only current own-user advisory setting; no power effect.")
    }

    Repeater {
        model: [{
                "label": qsTr("5-minute advisory"),
                "seconds": 300
            }, {
                "label": qsTr("10-minute advisory"),
                "seconds": 600
            }, {
                "label": qsTr("15-minute advisory"),
                "seconds": 900
            }, {
                "label": qsTr("30-minute advisory"),
                "seconds": 1800
            }]
        delegate: LinuraButton {
            required property var modelData
            Layout.fillWidth: true
            text: modelData.label
            enabled: !root.controller.busy && !root.controller.hasPending && root.controller.idlePreferenceReady && !root.controller.idlePreferenceBusy && root.controller.idleAdvisorySeconds !== modelData.seconds
            onClicked: root.controller.setIdleAdvisorySeconds(modelData.seconds)
            onActiveFocusChanged: if (activeFocus)
                root.focusEntered(this)
            Accessible.name: text
            Accessible.description: qsTr("Stores an advisory threshold only. No automatic lock, display or power effect.")
        }
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
