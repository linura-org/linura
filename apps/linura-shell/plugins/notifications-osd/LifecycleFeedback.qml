import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Wayland
import org.linura.UI 1.0

PanelWindow {
    id: root

    property var targetScreen: Quickshell.screens.length > 0 ? Quickshell.screens[0] : null
    screen: root.targetScreen

    property int presentationGeneration: 0
    property string operationKey: ""
    property string phase: ""
    property string outcome: "none"
    property int observedValuePercent: -1
    property bool observedValueValid: false
    property bool finalOutcome: false
    property string tone: "neutral"
    property string title: ""
    property string detail: ""
    property bool opened: false

    visible: opened
    implicitWidth: 380
    implicitHeight: feedbackColumn.implicitHeight + theme.spacingXl * 2
    color: "transparent"
    exclusionMode: ExclusionMode.Ignore
    mask: Region {}

    anchors { bottom: true; right: true }
    margins { bottom: theme.spacingLg; right: theme.spacingLg }

    WlrLayershell.namespace: "linura-lifecycle-feedback"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.None

    LinuraTheme { id: theme }

    function transitionIsValid(currentPhase, nextPhase, nextOutcome) {
        if (currentPhase === "preparing") {
            if (nextPhase === "executing")
                return nextOutcome === "none"
            if (nextPhase === "blocked")
                return nextOutcome === "cancelled" || nextOutcome === "precondition-changed"
            if (nextPhase === "failed")
                return nextOutcome === "precondition-unavailable"
                    || nextOutcome === "authority-unavailable"
            return false
        }
        if (currentPhase === "executing") {
            if (nextPhase === "verifying")
                return nextOutcome === "none"
            if (nextPhase === "failed")
                return nextOutcome === "authority-unavailable"
                    || nextOutcome === "rejected"
                    || nextOutcome === "receipt-invalid"
            return false
        }
        if (currentPhase === "verifying") {
            if (nextPhase === "verified")
                return nextOutcome === "changed" || nextOutcome === "no-change"
            if (nextPhase === "blocked")
                return nextOutcome === "target-changed"
            if (nextPhase === "failed")
                return nextOutcome === "verification-mismatch"
                    || nextOutcome === "verification-unavailable"
            return false
        }
        return false
    }

    function boundedValueIsValid(value, valid) {
        if (valid)
            return value >= 0 && value <= 100 && value === Math.floor(value)
        return value === -1
    }

    function eventIsValid(generation, nextOperationKey, nextPhase, nextOutcome,
                          nextObservedValuePercent, nextObservedValueValid, nextFinalOutcome) {
        if (generation <= 0 || generation > 2147483647 || generation !== Math.floor(generation)) return false
        if (nextOperationKey !== "audio-output-volume") return false
        if (!boundedValueIsValid(nextObservedValuePercent, nextObservedValueValid)) return false
        if (nextPhase === "preparing" || nextPhase === "executing" || nextPhase === "verifying")
            return nextOutcome === "none" && !nextObservedValueValid && !nextFinalOutcome
        if (nextPhase === "verified")
            return (nextOutcome === "changed" || nextOutcome === "no-change")
                && nextObservedValueValid && nextFinalOutcome
        if (nextPhase === "blocked") {
            if (nextOutcome === "cancelled")
                return !nextObservedValueValid && nextFinalOutcome
            return (nextOutcome === "precondition-changed" || nextOutcome === "target-changed")
                && nextFinalOutcome
        }
        if (nextPhase === "failed") {
            if (nextOutcome === "verification-mismatch")
                return nextFinalOutcome
            return (nextOutcome === "verification-unavailable"
                    || nextOutcome === "precondition-unavailable"
                    || nextOutcome === "authority-unavailable"
                    || nextOutcome === "rejected"
                    || nextOutcome === "receipt-invalid")
                && !nextObservedValueValid && nextFinalOutcome
        }
        return false
    }

    function toneFor(nextPhase, nextOutcome) {
        if (nextPhase === "verified") return "success"
        if (nextPhase === "blocked") return "warning"
        if (nextPhase === "failed")
            return nextOutcome === "authority-unavailable" ? "warning" : "danger"
        return "accent"
    }

    function titleFor(nextPhase, nextOutcome) {
        if (nextPhase === "preparing") return qsTr("Changing output volume")
        if (nextPhase === "executing") return qsTr("Applying output volume")
        if (nextPhase === "verifying") return qsTr("Verifying output volume")
        if (nextPhase === "verified")
            return nextOutcome === "no-change" ? qsTr("Volume already set") : qsTr("Volume changed")
        if (nextPhase === "blocked") {
            if (nextOutcome === "cancelled") return qsTr("Volume change cancelled")
            if (nextOutcome === "target-changed") return qsTr("Output changed during verification")
            return qsTr("Volume change blocked")
        }
        if (nextOutcome === "verification-unavailable") return qsTr("Volume verification unavailable")
        if (nextOutcome === "verification-mismatch") return qsTr("Volume verification failed")
        if (nextOutcome === "receipt-invalid") return qsTr("Volume change could not be verified")
        if (nextOutcome === "rejected") return qsTr("Volume change failed")
        return qsTr("Volume change unavailable")
    }

    function detailFor(nextPhase, nextOutcome) {
        if (nextPhase === "preparing") return qsTr("Revalidating current audio state before dispatch.")
        if (nextPhase === "executing") return qsTr("Linura dispatched the bounded session effect.")
        if (nextPhase === "verifying") return qsTr("Effect returned; waiting for authoritative post-effect state.")
        if (nextPhase === "verified") return qsTr("Authoritative post-effect state independently verified.")
        if (nextOutcome === "cancelled") return qsTr("The request was cancelled before dispatch.")
        if (nextOutcome === "precondition-changed") return qsTr("Audio state changed before dispatch; review the current state.")
        if (nextOutcome === "target-changed") return qsTr("The default output changed; Linura withheld success.")
        if (nextOutcome === "verification-mismatch") return qsTr("Authoritative state did not match the requested volume.")
        if (nextOutcome === "verification-unavailable") return qsTr("Linura withheld success because authoritative verification failed.")
        if (nextOutcome === "precondition-unavailable") return qsTr("Authoritative pre-dispatch state could not be verified; no effect was dispatched.")
        if (nextOutcome === "authority-unavailable") return qsTr("Linura Session authority is unavailable.")
        if (nextOutcome === "receipt-invalid") return qsTr("The effect receipt failed correlation or authority validation.")
        return qsTr("The bounded session effect was rejected.")
    }

    function phaseLabel() {
        if (phase === "preparing") return qsTr("Preparing")
        if (phase === "executing") return qsTr("Applying")
        if (phase === "verifying") return qsTr("Verifying")
        if (phase === "verified") return qsTr("Verified")
        if (phase === "blocked") return qsTr("Blocked")
        if (phase === "failed") return qsTr("Failed")
        return qsTr("Linura")
    }

    function accessibilityName() {
        if (observedValueValid)
            return qsTr("%1. Observed output volume %2 percent.")
                .arg(title)
                .arg(observedValuePercent)
        return title
    }

    function present(generation, nextOperationKey, nextPhase, nextOutcome,
                     nextObservedValuePercent, nextObservedValueValid, nextFinalOutcome) {
        if (!eventIsValid(generation, nextOperationKey, nextPhase, nextOutcome,
                          nextObservedValuePercent, nextObservedValueValid, nextFinalOutcome))
            return false
        const expectedNextGeneration =
            presentationGeneration === 2147483647 ? 1 : presentationGeneration + 1
        if (presentationGeneration === 0) {
            if (generation !== 1 || nextPhase !== "preparing") return false
        } else if (generation !== presentationGeneration) {
            if (!finalOutcome
                    || generation !== expectedNextGeneration
                    || nextPhase !== "preparing")
                return false
        } else if (finalOutcome || !transitionIsValid(phase, nextPhase, nextOutcome)) {
            return false
        }
        presentationGeneration = generation
        operationKey = nextOperationKey
        phase = nextPhase
        outcome = nextOutcome
        observedValuePercent = nextObservedValueValid ? nextObservedValuePercent : -1
        observedValueValid = nextObservedValueValid
        finalOutcome = nextFinalOutcome
        tone = toneFor(nextPhase, nextOutcome)
        title = titleFor(nextPhase, nextOutcome)
        detail = detailFor(nextPhase, nextOutcome)
        opened = true
        dismissTimer.interval = nextFinalOutcome ? (tone === "danger" ? 6000 : 4200) : 2600
        dismissTimer.restart()
        return true
    }

    Timer { id: dismissTimer; repeat: false; onTriggered: root.opened = false }

    LinuraSurface {
        id: feedbackSurface
        anchors.fill: parent
        level: "elevated"
        cornerRadius: theme.radiusXl
        Accessible.name: root.accessibilityName()
        Accessible.description: root.detail
        Accessible.role: Accessible.AlertMessage
        Accessible.focusable: false

        ColumnLayout {
            id: feedbackColumn
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.margins: theme.spacingXl
            spacing: theme.spacingMd

            LinuraStatus {
                Layout.fillWidth: true
                text: root.phaseLabel()
                tone: root.tone
                Accessible.ignored: true
            }
            LinuraText {
                Layout.fillWidth: true
                text: root.title
                role: "title"
                wrapMode: Text.WordWrap
                Accessible.ignored: true
            }
            LinuraText {
                Layout.fillWidth: true
                visible: root.observedValueValid
                text: qsTr("%1%").arg(root.observedValuePercent)
                role: "display"
                Accessible.ignored: true
            }
            Rectangle {
                Layout.fillWidth: true
                visible: root.observedValueValid
                implicitHeight: 4
                radius: height / 2
                color: theme.surface
                Rectangle {
                    width: parent.width * Math.max(0, root.observedValuePercent) / 100
                    height: parent.height
                    radius: parent.radius
                    color: root.tone === "danger" ? theme.danger
                        : root.tone === "warning" ? theme.warning
                        : root.tone === "success" ? theme.success
                        : theme.accent
                }
            }
            LinuraText {
                Layout.fillWidth: true
                text: root.detail
                muted: true
                wrapMode: Text.WordWrap
                Accessible.ignored: true
            }
        }
    }
}
