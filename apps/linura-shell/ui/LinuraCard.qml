import QtQuick

LinuraSurface {
    id: root
    property string tone: "neutral"
    property bool selected: false
    LinuraTheme { id: theme }

    function toneColor() {
        if (tone === "danger")
            return theme.danger
        if (tone === "warning")
            return theme.warning
        if (tone === "success")
            return theme.success
        if (tone === "accent")
            return theme.accent
        return theme.surfaceElevated
    }

    outlineColor: selected ? theme.accent : toneColor()
}
