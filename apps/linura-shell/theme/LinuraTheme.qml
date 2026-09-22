import QtQuick

QtObject {
    readonly property SystemPalette systemPalette: SystemPalette {
        colorGroup: SystemPalette.Active
    }

    readonly property int spacingXs: 4
    readonly property int spacingSm: 8
    readonly property int spacingMd: 12
    readonly property int spacingLg: 16
    readonly property int spacingXl: 24
    readonly property int spacing2xl: 32

    readonly property int radiusSm: 6
    readonly property int radiusMd: 10
    readonly property int radiusLg: 14
    readonly property int radiusXl: 20

    readonly property int typeCaption: 12
    readonly property int typeBody: 14
    readonly property int typeTitle: 20
    readonly property int typeDisplay: 32

    readonly property color background: systemPalette.window
    readonly property color surface: systemPalette.base
    readonly property color surfaceElevated: systemPalette.button
    readonly property color foreground: systemPalette.text
    readonly property color muted: systemPalette.placeholderText
    readonly property color accent: systemPalette.highlight
    readonly property color highlightedText: systemPalette.highlightedText
    readonly property color danger: "#c94a4a"
    readonly property color warning: "#b87916"
    readonly property color success: "#2f8f63"
    readonly property color focus: systemPalette.highlight
}
