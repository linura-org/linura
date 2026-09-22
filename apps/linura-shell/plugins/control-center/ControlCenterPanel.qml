import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Wayland
import org.linura.ShellBridge 1.0
import org.linura.UI 1.0

PanelWindow {
    id: root

    required property var controller
    property bool opened: false
    property int draftVolume: controller.volumePercent
    property bool draftDirty: false

    signal closeRequested()

    visible: opened
    implicitWidth: 420
    implicitHeight: 520
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

    WlrLayershell.namespace: "linura-control-center"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: opened
        ? WlrKeyboardFocus.OnDemand
        : WlrKeyboardFocus.None

    LinuraTheme {
        id: theme
    }

    function stateColor(state) {
        if (state === "ready")
            return theme.success
        if (state === "loading" || state === "applying")
            return theme.accent
        if (state === "stale" || state === "unavailable")
            return theme.warning
        return theme.danger
    }

    function closePanel() {
        root.draftDirty = false
        root.controller.cancelVolumeDraft()
        root.closeRequested()
    }

    onOpenedChanged: {
        controller.setActive(opened)
        if (opened) {
            draftDirty = false
            draftVolume = Math.min(100, controller.volumePercent)
            Qt.callLater(function() {
                if (root.opened)
                    closeButton.forceActiveFocus(Qt.TabFocusReason)
            })
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
            anchors.fill: parent
            anchors.margins: theme.spacingXl
            spacing: theme.spacingLg

            RowLayout {
                Layout.fillWidth: true

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: theme.spacingXs

                    LinuraText {
                        text: qsTr("Control Center")
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
                    Accessible.name: qsTr("Close Control Center")
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
                        Accessible.description: qsTr("Changes are applied only after authoritative state is revalidated.")

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

                        LinuraButton {
                            text: qsTr("Reset")
                            enabled: !controller.busy
                            onClicked: {
                                root.draftDirty = false
                                root.draftVolume = Math.min(100, controller.volumePercent)
                                controller.cancelVolumeDraft()
                            }
                            Accessible.name: qsTr("Reset selected volume")
                        }

                        Item {
                            Layout.fillWidth: true
                        }

                        LinuraButton {
                            text: qsTr("Apply volume")
                            enabled: controller.canApply
                                && !controller.busy
                                && root.draftDirty
                                && root.draftVolume !== controller.volumePercent
                            highlighted: true
                            onClicked: {
                                root.draftDirty = false
                                controller.setVolume(root.draftVolume)
                            }
                            Accessible.name: qsTr("Apply selected output volume")
                        }
                    }
                }
            }

            LinuraSurface {
                Layout.fillWidth: true
                implicitHeight: statusColumn.implicitHeight + theme.spacingXl * 2
                outlineColor: root.stateColor(controller.state)

                ColumnLayout {
                    id: statusColumn
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: theme.spacingXl
                    spacing: theme.spacingSm

                    LinuraText {
                        text: qsTr("Authority status")
                        role: "title"
                        Accessible.name: text
                    }

                    LinuraText {
                        Layout.fillWidth: true
                        text: controller.statusText
                        wrapMode: Text.WordWrap
                        Accessible.name: text
                    }

                    LinuraText {
                        Layout.fillWidth: true
                        text: qsTr("Observation: %1 · %2")
                            .arg(controller.authority)
                            .arg(controller.freshness)
                        role: "caption"
                        muted: true
                        Accessible.name: text
                    }

                    LinuraText {
                        Layout.fillWidth: true
                        visible: controller.lastReceiptStatus.length > 0
                        text: qsTr("Last Session1 receipt: %1 · evidence %2")
                            .arg(controller.lastReceiptStatus)
                            .arg(controller.lastEvidenceId)
                        role: "caption"
                        muted: true
                        elide: Text.ElideMiddle
                        Accessible.name: text
                    }
                }
            }

            LinuraText {
                Layout.fillWidth: true
                text: qsTr("This panel is a Linura client, not an executor. It cannot run provider commands or choose policy, risk, or operation class.")
                role: "caption"
                muted: true
                wrapMode: Text.WordWrap
                Accessible.name: text
            }

            Item {
                Layout.fillHeight: true
            }
        }
    }
}
