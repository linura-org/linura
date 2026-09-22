import QtQuick
import QtQuick.Controls

Popup {
    id: control
    signal accepted()
    signal rejected()
    property bool decisionEmitted: false
    LinuraTheme { id: theme }

    function accept() {
        if (!opened || decisionEmitted)
            return
        decisionEmitted = true
        accepted()
        close()
    }

    function reject() {
        if (!opened || decisionEmitted)
            return
        decisionEmitted = true
        rejected()
        close()
    }

    onAboutToShow: decisionEmitted = false
    onClosed: {
        if (!decisionEmitted) {
            decisionEmitted = true
            rejected()
        }
    }

    modal: true
    focus: true
    dim: true
    padding: theme.spacingXl
    closePolicy: Popup.CloseOnEscape

    background: LinuraSurface {
        level: "elevated"
        cornerRadius: theme.radiusXl
        outlineWidth: theme.borderWidth
    }
}
