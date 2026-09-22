import QtQuick
import QtQuick.Controls

Popup {
    id: control
    LinuraTheme { id: theme }

    modal: false
    focus: true
    padding: theme.spacingLg
    closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside

    background: LinuraSurface {
        level: "elevated"
        cornerRadius: theme.radiusLg
        outlineWidth: theme.borderWidth
    }
}
