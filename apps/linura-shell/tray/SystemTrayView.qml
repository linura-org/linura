import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Services.SystemTray
import org.linura.UI 1.0

RowLayout {
    id: root

    required property var panelWindow
    property int inlineItemLimit: 4
    property var itemModelOverride: null

    signal interactionStarted()
    signal keyboardReturnRequested(var control)
    readonly property var itemModel:
        itemModelOverride === null ? SystemTray.items : itemModelOverride
    readonly property int effectiveInlineItemLimit: Math.max(1, inlineItemLimit)
    readonly property int itemCount:
        itemModelOverride === null ? SystemTray.items.values.length : itemModelOverride.length
    readonly property int overflowCount: Math.max(0, itemCount - effectiveInlineItemLimit)

    spacing: theme.spacingXs
    visible: itemCount > 0

    LinuraTheme { id: theme }

    function boundedText(value, fallback) {
        if (value === undefined || value === null)
            return fallback
        const clean = String(value).replace(/[\u0000-\u001f\u007f]/g, " ").trim()
        if (clean.length === 0)
            return fallback
        return clean.length <= 128 ? clean : clean.slice(0, 127) + "…"
    }

    function labelFor(item) {
        const tooltip = boundedText(item.tooltipTitle, "")
        if (tooltip.length > 0)
            return tooltip
        const title = boundedText(item.title, "")
        if (title.length > 0)
            return title
        return boundedText(item.id, qsTr("Application tray item"))
    }

    function openMenu(item, anchorItem, hostWindow) {
        if (!item.hasMenu || !anchorItem || !hostWindow)
            return
        root.interactionStarted()
        const point = hostWindow.mapFromItem(anchorItem, 0, anchorItem.height)
        item.display(
            hostWindow,
            Math.round(point.x),
            Math.round(point.y)
        )
    }

    function primaryAction(item, anchorItem, hostWindow) {
        if (item.onlyMenu) {
            root.openMenu(item, anchorItem, hostWindow)
            return false
        }
        root.interactionStarted()
        item.activate()
        return true
    }

    function secondaryAction(item) {
        root.interactionStarted()
        item.secondaryActivate()
    }

    function openOverflow() {
        if (overflowCount <= 0 || !panelWindow)
            return
        root.interactionStarted()
        overflowWindow.visible = true
    }

    function dismissOverflow(returnKeyboardFocus) {
        overflowWindow.visible = false
        if (!returnKeyboardFocus)
            return
        Qt.callLater(function() {
            root.keyboardReturnRequested(overflowButton)
        })
    }

    function activateInlineControl(index) {
        const entry = inlineRepeater.itemAt(index)
        if (!entry || !entry.visible)
            return false
        entry.primaryAction()
        return true
    }

    function openOverflowControl() {
        if (!overflowButton.visible || !overflowButton.enabled)
            return false
        overflowButton.click()
        return overflowWindow.visible
    }

    function cancelOverflowControl() {
        if (!overflowWindow.visible)
            return false
        root.dismissOverflow(true)
        return true
    }

    function overflowIsVisible() {
        return overflowWindow.visible
    }

    function overflowButtonFocused() {
        return overflowButton.activeFocus
    }

    function activateOverflowControl(index) {
        if (!overflowWindow.visible)
            return false
        const entry = overflowRepeater.itemAt(index)
        if (!entry || !entry.visible)
            return false
        entry.click()
        return true
    }

    onOverflowCountChanged: {
        if (overflowCount === 0 && overflowWindow.visible)
            root.dismissOverflow(true)
    }

    Repeater {
        id: inlineRepeater
        model: root.itemModel

        FocusScope {
            id: entry
            required property int index
            required property var modelData

            visible: index < root.effectiveInlineItemLimit
            Layout.alignment: Qt.AlignVCenter
            implicitWidth: theme.controlSm
            implicitHeight: theme.controlSm
            activeFocusOnTab: visible

            function openMenu() {
                root.openMenu(entry.modelData, entry, root.panelWindow)
            }

            function primaryAction() {
                root.primaryAction(entry.modelData, entry, root.panelWindow)
            }

            function secondaryAction() {
                root.secondaryAction(entry.modelData)
            }

            Keys.onReturnPressed: event => {
                if ((event.modifiers & Qt.ShiftModifier) !== 0)
                    entry.secondaryAction()
                else
                    entry.primaryAction()
                event.accepted = true
            }

            Keys.onEnterPressed: event => {
                if ((event.modifiers & Qt.ShiftModifier) !== 0)
                    entry.secondaryAction()
                else
                    entry.primaryAction()
                event.accepted = true
            }

            Keys.onSpacePressed: event => {
                entry.primaryAction()
                event.accepted = true
            }

            Keys.onPressed: event => {
                if (event.key === Qt.Key_Menu
                        || (event.key === Qt.Key_F10
                            && (event.modifiers & Qt.ShiftModifier) !== 0)) {
                    entry.openMenu()
                    event.accepted = true
                }
            }

            Accessible.name: root.labelFor(entry.modelData)
            Accessible.description: {
                const description = root.boundedText(entry.modelData.tooltipDescription, "")
                const secondaryHint = qsTr("Shift+Enter activates the secondary tray action.")
                return description.length > 0
                    ? qsTr("%1 %2").arg(description).arg(secondaryHint)
                    : secondaryHint
            }
            Accessible.role: Accessible.Button
            Accessible.focusable: visible
            Accessible.onPressAction: entry.primaryAction()

            LinuraSurface {
                anchors.fill: parent
                level: pointer.containsMouse || entry.activeFocus ? "elevated" : "surface"
                cornerRadius: theme.radiusMd
                outlineColor: entry.activeFocus ? theme.focus : theme.surfaceElevated
                outlineWidth: entry.activeFocus ? theme.focusBorderWidth : theme.borderWidth
            }

            Image {
                anchors.centerIn: parent
                width: theme.iconMd
                height: theme.iconMd
                source: entry.modelData.icon
                sourceSize.width: theme.iconLg
                sourceSize.height: theme.iconLg
                fillMode: Image.PreserveAspectFit
                smooth: true
                Accessible.ignored: true
            }

            MouseArea {
                id: pointer
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                acceptedButtons: Qt.LeftButton | Qt.MiddleButton | Qt.RightButton

                onClicked: mouse => {
                    entry.forceActiveFocus(Qt.MouseFocusReason)
                    if (mouse.button === Qt.LeftButton)
                        entry.primaryAction()
                    else if (mouse.button === Qt.MiddleButton)
                        entry.secondaryAction()
                    else if (mouse.button === Qt.RightButton)
                        entry.openMenu()
                }
            }

            ToolTip {
                id: entryToolTip
                visible: pointer.containsMouse
                text: root.labelFor(entry.modelData)
                contentItem: Label {
                    text: entryToolTip.text
                    textFormat: Text.PlainText
                }
            }
        }
    }

    LinuraIconButton {
        id: overflowButton
        visible: root.overflowCount > 0
        glyph: root.overflowCount > 9 ? "…" : "+" + root.overflowCount
        accessibleName: qsTr("Show %1 more tray items").arg(root.overflowCount)
        toolTip: accessibleName
        onClicked: root.openOverflow()
    }

    PopupWindow {
        id: overflowWindow

        anchor.item: overflowButton
        anchor.edges: Edges.Bottom | Edges.Right
        anchor.gravity: Edges.Bottom | Edges.Left
        anchor.adjustment: PopupAdjustment.All
        implicitWidth: Math.max(
            1,
            Math.min(
                320,
                (root.panelWindow ? root.panelWindow.width : 320)
                    - theme.spacingLg * 2
            )
        )
        implicitHeight: Math.min(
            320,
            overflowColumn.implicitHeight + theme.spacingLg * 2
        )
        color: "transparent"
        surfaceFormat.opaque: false
        grabFocus: true
        visible: false

        onVisibleChanged: {
            if (!visible)
                return
            Qt.callLater(function() {
                const first = overflowRepeater.itemAt(root.effectiveInlineItemLimit)
                if (first)
                    first.forceActiveFocus(Qt.TabFocusReason)
            })
        }

        Shortcut {
            sequence: "Escape"
            context: Qt.WindowShortcut
            enabled: overflowWindow.visible
            onActivated: root.dismissOverflow(true)
        }

        LinuraSurface {
            anchors.fill: parent
            level: "elevated"
            cornerRadius: theme.radiusLg
            outlineWidth: theme.borderWidth
        }

        Flickable {
            id: overflowFlickable
            anchors.fill: parent
            anchors.margins: theme.spacingLg
            contentWidth: width
            contentHeight: overflowColumn.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            interactive: contentHeight > height

            function ensureVisible(item) {
                if (!item || !item.visible)
                    return
                const point = item.mapToItem(contentItem, 0, 0)
                const top = point.y
                const bottom = top + item.height
                if (top < contentY)
                    contentY = Math.max(0, top)
                else if (bottom > contentY + height)
                    contentY = Math.min(
                        Math.max(0, contentHeight - height),
                        bottom - height
                    )
            }

            Column {
                id: overflowColumn
                width: parent.width
                spacing: theme.spacingXs

                Repeater {
                    id: overflowRepeater
                    model: root.itemModel

                    LinuraActionRow {
                        id: overflowEntry
                        required property int index
                        required property var modelData

                        visible: index >= root.effectiveInlineItemLimit
                        height: visible ? implicitHeight : 0
                        width: overflowColumn.width
                        title: root.labelFor(modelData)
                        description: {
                            const text = root.boundedText(modelData.tooltipDescription, "")
                            const hint = qsTr("Shift+Enter activates the secondary tray action. Menu or Shift+F10 opens the native menu.")
                            return text.length > 0 ? qsTr("%1 %2").arg(text).arg(hint) : hint
                        }
                        shortcut: modelData.onlyMenu ? qsTr("Menu") : qsTr("Enter")

                        onActiveFocusChanged: {
                            if (activeFocus)
                                overflowFlickable.ensureVisible(overflowEntry)
                        }

                        onClicked: {
                            const shouldDismiss = root.primaryAction(
                                modelData,
                                overflowEntry,
                                overflowWindow
                            )
                            if (shouldDismiss)
                                root.dismissOverflow()
                        }

                        Keys.onPressed: event => {
                            if ((event.key === Qt.Key_Return || event.key === Qt.Key_Enter)
                                    && (event.modifiers & Qt.ShiftModifier) !== 0) {
                                root.secondaryAction(modelData)
                                root.dismissOverflow()
                                event.accepted = true
                                return
                            }

                            if (event.key === Qt.Key_Menu
                                    || (event.key === Qt.Key_F10
                                        && (event.modifiers & Qt.ShiftModifier) !== 0)) {
                                root.openMenu(modelData, overflowEntry, overflowWindow)
                                event.accepted = true
                            }
                        }
                    }
                }
            }
        }
    }
}
