//@ pragma ShellId linura-qualification-palette
import QtQuick
import Quickshell
import Quickshell.Io
import "plugins/command-palette" as Palette

Scope {
    id: root

    property bool paletteOpen: false

    Palette.CommandPalette {
        id: palette
        opened: root.paletteOpen
        workspaceCatalog: []
        applicationCatalog: []
        onCloseRequested: root.paletteOpen = false
    }

    IpcHandler {
        target: "linura.palette-qualification"

        function openPalette(): int {
            root.paletteOpen = true
            return palette.sessionGeneration
        }

        function closePalette(): void {
            root.paletteOpen = false
        }

        function generation(): int {
            return palette.sessionGeneration
        }

        function isOpen(): bool {
            return root.paletteOpen
        }

        function status(): string {
            return palette.statusText
        }

        function complete(status: string, requestGeneration: int): void {
            palette.completeApplicationRequest(status, requestGeneration)
        }
    }
}
