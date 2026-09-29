//@ pragma ShellId linura-qualification-quick-settings
import QtQuick
import Quickshell
import Quickshell.Io
import org.linura.ShellBridge 1.0
import "plugins/quick-settings" as QuickSettings
import "plugins/notifications-osd" as Feedback

Scope {
    id: root

    property bool opened: false
    property string lifecycleTrace: ""

    function recordLifecycle(presentationGeneration, operationKey, phase, outcome,
                             observedValueValid, finalOutcome) {
        const entry = presentationGeneration
            + ":" + operationKey
            + ":" + phase
            + ":" + outcome
            + ":" + (observedValueValid ? "observed" : "none")
            + ":" + (finalOutcome ? "final" : "progress")
        lifecycleTrace = lifecycleTrace.length > 0 ? lifecycleTrace + "|" + entry : entry
    }

    AudioSessionController {
        id: audioController
        active: root.opened
        onLifecycleFeedback: (presentationGeneration, operationKey, phase, outcome,
                              observedValuePercent, observedValueValid, finalOutcome) => {
            root.recordLifecycle(
                presentationGeneration,
                operationKey,
                phase,
                outcome,
                observedValueValid,
                finalOutcome
            )
            lifecycleFeedback.present(
                presentationGeneration,
                operationKey,
                phase,
                outcome,
                observedValuePercent,
                observedValueValid,
                finalOutcome
            )
        }
    }

    Feedback.LifecycleFeedback {
        id: lifecycleFeedback
    }

    QuickSettings.QuickSettingsPanel {
        id: quickSettings
        opened: root.opened
        controller: audioController
        onCloseRequested: root.opened = false
        onControlCenterRequested: root.opened = false
    }

    IpcHandler {
        target: "linura.quick-settings-qualification"

        function openSettings(): void {
            root.opened = true
        }

        function closeSettings(): void {
            root.opened = false
        }

        function isOpen(): bool {
            return root.opened
        }

        function state(): string {
            return audioController.state
        }

        function status(): string {
            return audioController.statusText
        }

        function freshness(): string {
            return audioController.freshness
        }

        function authority(): string {
            return audioController.authority
        }

        function nodeId(): int {
            return audioController.nodeId
        }

        function volumePercent(): int {
            return audioController.volumePercent
        }

        function canApply(): bool {
            return audioController.canApply
        }

        function canCommitDraft(): bool {
            return audioController.canCommitDraft
        }

        function receiptStatus(): string {
            return audioController.lastReceiptStatus
        }

        function evidenceId(): string {
            return audioController.lastEvidenceId
        }

        function feedbackTrace(): string { return root.lifecycleTrace }
        function feedbackGeneration(): int { return lifecycleFeedback.presentationGeneration }
        function feedbackOperation(): string { return lifecycleFeedback.operationKey }
        function feedbackPhase(): string { return lifecycleFeedback.phase }
        function feedbackOutcome(): string { return lifecycleFeedback.outcome }
        function feedbackTone(): string { return lifecycleFeedback.tone }
        function feedbackTitle(): string { return lifecycleFeedback.title }
        function feedbackDetail(): string { return lifecycleFeedback.detail }
        function feedbackValue(): int { return lifecycleFeedback.observedValuePercent }
        function feedbackValueValid(): bool { return lifecycleFeedback.observedValueValid }
        function feedbackFinal(): bool { return lifecycleFeedback.finalOutcome }
        function feedbackVisible(): bool { return lifecycleFeedback.opened }

        function resetFeedbackTrace(): void {
            root.lifecycleTrace = ""
        }

        function refresh(): void {
            audioController.refresh()
        }

        function beginDraft(): string {
            if (!root.opened)
                return "closed"
            if (!audioController.canApply)
                return "not-ready"
            audioController.beginVolumeDraft()
            return "begun"
        }

        function commitVolume(volumePercent: int): string {
            if (!root.opened)
                return "closed"
            if (!audioController.canCommitDraft)
                return "not-ready"
            if (volumePercent < 0 || volumePercent > 100)
                return "invalid"
            audioController.setVolume(volumePercent)
            return "requested"
        }
    }
}
