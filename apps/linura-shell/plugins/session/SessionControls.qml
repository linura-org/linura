import QtQuick
import QtQuick.Layouts
import org.linura.UI 1.0
import org.linura.ShellBridge 1.0
import "../power" as Power

ColumnLayout {
    id: root
    required property var controller
    signal focusEntered(var item)
    spacing: theme.spacingMd

    LinuraTheme {
        id: theme
    }

    LinuraDivider {
        Layout.fillWidth: true
    }

    LinuraText {
        Layout.fillWidth: true
        text: qsTr("Session security")
        role: "title"
        Accessible.name: text
    }

    LinuraButton {
        Layout.fillWidth: true
        text: qsTr("Lock session")
        enabled: !root.controller.busy && !root.controller.hasPending
        onClicked: root.controller.request(SessionController.Lock)
        onActiveFocusChanged: if (activeFocus)
            root.focusEntered(this)
        Accessible.name: text
        Accessible.description: qsTr("Request a native purpose-bound confirmation and independently verified managed lock.")
    }

    Power.PowerControls {
        Layout.fillWidth: true
        controller: root.controller
        onFocusEntered: item => root.focusEntered(item)
    }

    LinuraText {
        Layout.fillWidth: true
        text: qsTr("Protective pre-sleep locking is an explicit permission for this login only. These controls first secure your session, then require separate owner authentication in the native locker. They never unlock or authorize sleep. If protection fails, a closed laptop may stay awake: keep it ventilated.")
        wrapMode: Text.WordWrap
        Accessible.name: text
    }

    LinuraButton {
        Layout.fillWidth: true
        text: qsTr("Allow protective locking…")
        enabled: !root.controller.busy && !root.controller.hasPending
        onClicked: root.controller.request(SessionController.EnableProtectiveLock)
        onActiveFocusChanged: if (activeFocus)
            root.focusEntered(this)
        Accessible.name: text
        Accessible.description: qsTr("Secure this session, then authenticate as its owner to allow protective locking before trusted native sleep entries for this login. Does not authorize sleep or unlock.")
    }

    LinuraButton {
        Layout.fillWidth: true
        text: qsTr("Revoke protective locking…")
        enabled: !root.controller.busy && !root.controller.hasPending
        onClicked: root.controller.request(SessionController.RevokeProtectiveLock)
        onActiveFocusChanged: if (activeFocus)
            root.focusEntered(this)
        Accessible.name: text
        Accessible.description: qsTr("Secure this session, then authenticate as its owner to revoke this login's protective-lock permission. Does not unlock or authorize sleep.")
    }

    LinuraText {
        Layout.fillWidth: true
        objectName: "nativeSleepDiagnostic"
        text: root.controller.nativeSleepStatusText
        wrapMode: Text.WordWrap
        Accessible.role: Accessible.StaticText
        Accessible.name: text
        Accessible.description: qsTr("Read-only historical sleep diagnostics. Never proof that the computer is asleep or presently protected.")
    }

    LinuraText {
        Layout.fillWidth: true
        text: root.controller.statusText
        wrapMode: Text.WordWrap
        Accessible.role: Accessible.StaticText
        Accessible.name: text
    }

    LinuraText {
        Layout.fillWidth: true
        visible: root.controller.requestId.length > 0
        text: qsTr("Retained request: %1").arg(root.controller.requestId)
        role: "caption"
        wrapMode: Text.WrapAnywhere
        Accessible.name: text
    }

    LinuraButton {
        Layout.fillWidth: true
        visible: root.controller.hasPending
        enabled: !root.controller.busy && root.controller.requestId.length > 0
        text: qsTr("Check recovery — never repeat action")
        onClicked: root.controller.recover()
        onActiveFocusChanged: if (activeFocus)
            root.focusEntered(this)
        Accessible.name: text
    }

    LinuraButton {
        id: forgetButton
        Layout.fillWidth: true
        visible: root.controller.hasPending
        enabled: !root.controller.busy
        text: qsTr("Forget local tracking…")
        onClicked: forgetDialog.open()
        onActiveFocusChanged: if (activeFocus)
            root.focusEntered(this)
        Accessible.name: text
        Accessible.description: qsTr("Does not cancel a durable request, unlock the session, or release a native power fence.")
    }

    LinuraDialog {
        id: forgetDialog
        width: Math.max(0, Math.min(root.width, 360))
        onAccepted: root.controller.forgetTracking()
        onClosed: if (forgetButton.visible)
            forgetButton.forceActiveFocus(Qt.OtherFocusReason)
        onOpened: cancelForget.forceActiveFocus(Qt.TabFocusReason)

        contentItem: ColumnLayout {
            spacing: theme.spacingMd
            LinuraText {
                Layout.fillWidth: true
                text: qsTr("Forget only the local request tracker? This does not cancel an uncertain operation, unlock the session, or release a native power fence. Keep the request ID for durable recovery.")
                wrapMode: Text.WordWrap
                Accessible.name: text
            }
            LinuraButton {
                id: cancelForget
                Layout.fillWidth: true
                text: qsTr("Keep tracking")
                onClicked: forgetDialog.reject()
                Accessible.name: text
            }
            LinuraButton {
                Layout.fillWidth: true
                text: qsTr("Forget local tracking only")
                onClicked: forgetDialog.accept()
                Accessible.name: text
            }
        }
    }
}
