//@ pragma ShellId linura-qualification-quick-settings
import QtQuick
import Quickshell
import Quickshell.Io
import org.linura.ShellBridge 1.0
import "plugins/quick-settings" as QuickSettings

Scope {
    id: root

    property bool opened: false

    AudioSessionController {
        id: audioController
        active: root.opened
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
