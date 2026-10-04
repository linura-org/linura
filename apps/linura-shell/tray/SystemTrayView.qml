import QtQuick
import QtQuick.Window
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
    property bool overflowKeyboardReturnPending: false

    signal interactionStarted()
    signal popupInteractionStarted()
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
        if (!item.hasMenu || !anchorItem || !hostWindow || !hostWindow.contentItem)
            return
        // A native menu opened from the overflow is another popup in the
        // same focus session; retain the mapped host and its keyboard mode.
        if (hostWindow === overflowWindow)
            root.popupInteractionStarted()
        else
            root.interactionStarted()
        const point = hostWindow.contentItem.mapFromItem(anchorItem, 0, anchorItem.height)
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
        root.overflowKeyboardReturnPending = false
        root.popupInteractionStarted()
        overflowWindow.visible = true
    }

    function dismissOverflow(returnKeyboardFocus) {
        root.overflowKeyboardReturnPending = returnKeyboardFocus === true
        overflowWindow.visible = false
        if (!returnKeyboardFocus) {
            // An action that completes without keyboard return releases the
            // panel's keyboard session after the native popup is hidden.
            root.interactionStarted()
            return
        }
        Qt.callLater(function() {
            if (root.overflowKeyboardReturnPending && !overflowWindow.visible) {
                root.overflowKeyboardReturnPending = false
                root.keyboardReturnRequested(overflowButton)
            }
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
        return overflowButton.activeFocus && overflowButton.Window.active
    }

    // Native PopupWindow focus is acquired asynchronously after the Wayland
    // surface is mapped. Do not infer focus from visibility or delegate geometry.
    // Do not steal focus from another overflow action when navigating by keyboard.
    function focusFirstOverflowEntry() {
        if (!overflowWindow.visible || !overflowWindow.backingWindowVisible)
            return false
        for (let i = root.effectiveInlineItemLimit; i < overflowRepeater.count; i++) {
            const entry = overflowRepeater.itemAt(i)
            if (entry && entry.activeFocus)
                return entry.Window.active
        }
        const first = overflowRepeater.itemAt(root.effectiveInlineItemLimit)
        if (!first || !first.visible || !first.enabled
                || first.width <= 0 || first.height <= 0)
            return false
        first.forceActiveFocus(Qt.TabFocusReason)
        return first.activeFocus && first.Window.active
    }

    function overflowReadinessState(index) {
        const entry = overflowRepeater.itemAt(index)
        return "popup=" + overflowWindow.visible
            + " mapped=" + overflowWindow.backingWindowVisible
            + " nativeGrabRequested=" + overflowWindow.grabFocus
            + " delegates=" + overflowRepeater.count
            + " item=" + !!entry
            + " visible=" + (!!entry && entry.visible)
            + " enabled=" + (!!entry && entry.enabled)
            + " focused=" + (!!entry && entry.activeFocus)
            + " nativeActive=" + (!!entry && entry.Window.active)
            + " width=" + (entry ? entry.width : 0)
            + " height=" + (entry ? entry.height : 0)
    }

    function overflowEntryReady(index) {
        if (!overflowWindow.visible || !overflowWindow.backingWindowVisible)
            return false
        const entry = overflowRepeater.itemAt(index)
        return overflowWindow.grabFocus
            && !!entry && entry.visible && entry.enabled && entry.activeFocus
            && entry.Window.active
            && entry.width > 0 && entry.height > 0
    }

    function activateOverflowControl(index) {
        if (!overflowEntryReady(index)) {
            console.warn("Linura tray overflow activation unavailable:"
                + " popup=" + overflowWindow.visible
                + " index=" + index
                + " " + root.overflowReadinessState(index))
            return false
        }
        const entry = overflowRepeater.itemAt(index)
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
        // Keep the native xdg_popup grab that passed Level A before the
        // unsupported replacement with a separate HyprlandFocusGrab.
        grabFocus: true
        visible: false

        Timer {
            id: overflowFocusRetry
            interval: 100
            repeat: true
            running: false
            property int attempts: 0

            onTriggered: {
                if (!overflowWindow.visible || !overflowWindow.backingWindowVisible
                        || root.focusFirstOverflowEntry() || ++attempts >= 20)
                    stop()
            }
        }

        onVisibleChanged: {
            if (visible) {
                Qt.callLater(root.focusFirstOverflowEntry)
            } else {
                overflowFocusRetry.stop()
                // Outside dismissal releases the panel without stealing focus.
                // Keyboard cancellation keeps its mode stable while focus
                // returns to the opener, avoiding a None/Exclusive round trip.
                if (!root.overflowKeyboardReturnPending)
                    root.interactionStarted()
            }
        }
        onBackingWindowVisibleChanged: {
            if (backingWindowVisible) {
                overflowFocusRetry.attempts = 0
                overflowFocusRetry.restart()
                Qt.callLater(root.focusFirstOverflowEntry)
            } else {
                overflowFocusRetry.stop()
            }
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
