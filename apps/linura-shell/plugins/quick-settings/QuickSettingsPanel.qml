import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Wayland
import org.linura.UI 1.0

PanelWindow {
    id: root

    required property var controller
    property bool opened: false
    property int draftVolume: controller.volumePercent
    property bool draftDirty: false

    signal closeRequested()
    signal controlCenterRequested()

    visible: opened
    implicitWidth: 360
    implicitHeight: quickColumn.implicitHeight + theme.spacingXl * 2
    color: "transparent"
    exclusionMode: ExclusionMode.Ignore

    anchors {
        top: true
        right: true
    }

    margins {
        top: theme.spacingLg
        right: theme.spacingLg
    }

    WlrLayershell.namespace: "linura-quick-settings"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: opened
        ? WlrKeyboardFocus.OnDemand
        : WlrKeyboardFocus.None

    LinuraTheme {
        id: theme
    }

    function stateTone(state) {
        if (state === "ready")
            return "success"
        if (state === "loading" || state === "applying")
            return "accent"
        if (state === "stale" || state === "unavailable")
            return "warning"
        return "danger"
    }

    function resetDraft() {
        draftDirty = false
        controller.cancelVolumeDraft()
        draftVolume = Math.min(100, controller.volumePercent)
    }

    function closePanel() {
        resetDraft()
        closeRequested()
    }

    onOpenedChanged: {
        if (opened) {
            resetDraft()
            Qt.callLater(function() {
                if (root.opened)
                    closeButton.forceActiveFocus(Qt.TabFocusReason)
            })
        } else {
            draftDirty = false
            controller.cancelVolumeDraft()
        }
    }

    Connections {
        target: controller

        function onSnapshotChanged() {
            if (!root.draftDirty)
                root.draftVolume = Math.min(100, controller.volumePercent)
        }

        function onStateChanged() {
            if (controller.state === "ready" && !root.draftDirty)
                root.draftVolume = Math.min(100, controller.volumePercent)
        }
    }

    Shortcut {
        sequence: "Escape"
        enabled: root.opened
        onActivated: root.closePanel()
    }

    LinuraSurface {
        anchors.fill: parent
        level: "background"
        cornerRadius: theme.radiusXl

        ColumnLayout {
            id: quickColumn
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.margins: theme.spacingXl
            spacing: theme.spacingLg

            RowLayout {
                Layout.fillWidth: true

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: theme.spacingXs

                    LinuraText {
                        text: qsTr("Quick Settings")
                        role: "display"
                        Accessible.name: text
                    }

                    LinuraText {
                        Layout.fillWidth: true
                        text: qsTr("Authoritative current-session controls")
                        muted: true
                        elide: Text.ElideRight
                        Accessible.name: text
                    }
                }

                LinuraButton {
                    id: closeButton
                    text: qsTr("Close")
                    onClicked: root.closePanel()
                    Accessible.name: qsTr("Close Quick Settings")
                }
            }

            LinuraSurface {
                Layout.fillWidth: true
                implicitHeight: audioColumn.implicitHeight + theme.spacingXl * 2

                ColumnLayout {
                    id: audioColumn
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: theme.spacingXl
                    spacing: theme.spacingMd

                    RowLayout {
                        Layout.fillWidth: true

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: theme.spacingXs

                            LinuraText {
                                text: qsTr("Audio output")
                                role: "title"
                                Accessible.name: text
                            }

                            LinuraText {
                                Layout.fillWidth: true
                                text: controller.sinkName
                                muted: true
                                elide: Text.ElideRight
                                Accessible.name: qsTr("Current audio output: %1").arg(text)
                            }
                        }

                        LinuraText {
                            text: qsTr("%1%").arg(root.draftVolume)
                            role: "title"
                            Accessible.name: qsTr("Selected volume %1 percent").arg(root.draftVolume)
                        }
                    }

                    LinuraSlider {
                        id: volumeSlider
                        Layout.fillWidth: true
                        from: 0
                        to: 100
                        stepSize: 1
                        value: root.draftVolume
                        enabled: controller.canApply && !controller.busy

                        Accessible.name: qsTr("Output volume")
                        Accessible.description: qsTr("Apply uses fresh authoritative preconditions and independent verification.")

                        onPressedChanged: {
                            if (pressed) {
                                controller.beginVolumeDraft()
                            } else if (!root.draftDirty) {
                                controller.cancelVolumeDraft()
                            }
                        }

                        onMoved: {
                            if (!root.draftDirty)
                                controller.beginVolumeDraft()
                            root.draftDirty = true
                            root.draftVolume = Math.round(value)
                        }

                        Keys.onLeftPressed: event => {
                            controller.beginVolumeDraft()
                            root.draftDirty = true
                            root.draftVolume = Math.max(0, root.draftVolume - 1)
                            event.accepted = true
                        }

                        Keys.onRightPressed: event => {
                            controller.beginVolumeDraft()
                            root.draftDirty = true
                            root.draftVolume = Math.min(100, root.draftVolume + 1)
                            event.accepted = true
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true

                        LinuraText {
                            Layout.fillWidth: true
                            text: controller.muted ? qsTr("Muted") : qsTr("Output active")
                            role: "caption"
                            muted: true
                            Accessible.name: text
                        }

                        LinuraButton {
                            text: qsTr("Apply")
                            highlighted: true
                            enabled: controller.canCommitDraft
                                && root.draftDirty
                                && root.draftVolume !== controller.volumePercent
                            onClicked: {
                                root.draftDirty = false
                                controller.setVolume(root.draftVolume)
                            }
                            Accessible.name: qsTr("Apply selected output volume")
                        }
                    }
                }
            }

            LinuraStatus {
                Layout.fillWidth: true
                text: controller.statusText
                tone: root.stateTone(controller.state)
                Accessible.name: qsTr("%1. Observation %2, %3.")
                    .arg(controller.statusText)
                    .arg(controller.authority)
                    .arg(controller.freshness)
            }

            RowLayout {
                Layout.fillWidth: true

                LinuraButton {
                    text: qsTr("Refresh")
                    enabled: !controller.busy
                    onClicked: controller.refresh()
                    Accessible.name: qsTr("Refresh authoritative audio state")
                }

                Item {
                    Layout.fillWidth: true
                }

                LinuraButton {
                    text: qsTr("Control Center")
                    onClicked: root.controlCenterRequested()
                    Accessible.name: qsTr("Open Control Center details")
                }
            }

            LinuraText {
                Layout.fillWidth: true
                text: qsTr("Quick Settings is a client of the same registered Session1 volume operation. It cannot choose operation class, policy, risk, provider, or executor authority.")
                role: "caption"
                muted: true
                wrapMode: Text.WordWrap
                Accessible.name: text
            }
        }
    }
}
