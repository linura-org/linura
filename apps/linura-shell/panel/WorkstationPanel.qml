import QtQuick
import QtQuick.Window
import QtQuick.Layouts
import Quickshell
import Quickshell.Wayland
import org.linura.UI 1.0
import "../tray" as Tray
import "../status" as Status

Scope {
    id: root

    required property var workspaceModel
    property var trayItemModelOverride: null
    property int statusClockPrecision: SystemClock.Minutes
    readonly property int panelHeight: 56
    readonly property int screenCount: Quickshell.screens.length
    readonly property int instantiatedPanelCount: panels.instances.length

    function panelInstance(index) {
        return index >= 0 && index < panels.instances.length
            ? panels.instances[index] : null
    }

    function panelScreenMatches(index) {
        const instance = panelInstance(index)
        return instance !== null
            && index < Quickshell.screens.length
            && instance.screen === Quickshell.screens[index]
    }

    function panelWidth(index) {
        const instance = panelInstance(index)
        return instance !== null ? Math.round(instance.width) : 0
    }

    function panelHeightActual(index) {
        const instance = panelInstance(index)
        return instance !== null ? Math.round(instance.height) : 0
    }

    function panelScreenWidth(index) {
        return index >= 0 && index < Quickshell.screens.length
            ? Math.round(Quickshell.screens[index].width) : 0
    }

    function panelExclusiveZone(index) {
        const instance = panelInstance(index)
        return instance !== null ? instance.exclusiveZone : 0
    }

    function panelExclusionNormal(index) {
        const instance = panelInstance(index)
        return instance !== null && instance.exclusionMode === ExclusionMode.Normal
    }

    function panelAnchorsValid(index) {
        const instance = panelInstance(index)
        return instance !== null
            && instance.anchors.top
            && instance.anchors.left
            && instance.anchors.right
            && !instance.anchors.bottom
    }

    function activateCommandPaletteControl(index) {
        const instance = panelInstance(index)
        return instance !== null && instance.activateCommandPaletteControl()
    }

    function activateQuickSettingsControl(index) {
        const instance = panelInstance(index)
        return instance !== null && instance.activateQuickSettingsControl()
    }

    function activateControlCenterControl(index) {
        const instance = panelInstance(index)
        return instance !== null && instance.activateControlCenterControl()
    }

    function activateWorkspaceControl(index, workspaceId) {
        const instance = panelInstance(index)
        return instance !== null && instance.activateWorkspaceControl(workspaceId)
    }

    function focusPanelInstance(target) {
        if (!target)
            return false

        for (let i = 0; i < panels.instances.length; i++) {
            const instance = panels.instances[i]
            if (instance && instance !== target)
                instance.releaseKeyboardEntry()
        }

        return target.focusKeyboardEntry()
    }

    function focusPanel(index) {
        return focusPanelInstance(panelInstance(index))
    }

    function focusPanelOnScreen(screen) {
        if (!screen)
            return false
        for (let i = 0; i < panels.instances.length; i++) {
            const instance = panels.instances[i]
            if (instance && instance.screen === screen)
                return focusPanelInstance(instance)
        }
        return false
    }

    function panelKeyboardEntryFocused(index) {
        const instance = panelInstance(index)
        return instance !== null && instance.keyboardEntryFocused()
    }

    function panelKeyboardNavigationActive(index) {
        const instance = panelInstance(index)
        return instance !== null && instance.keyboardNavigationActive
    }

    function statusTimeText() { return workstationStatus.timeText }
    function statusDateText() { return workstationStatus.dateText }
    function statusTimestampMs() { return workstationStatus.timestampMs }

    function statusTimeRendered(index) {
        const instance = panelInstance(index)
        return instance !== null && instance.statusTimeRendered()
    }

    function trayItemCount(index) {
        const instance = panelInstance(index)
        return instance !== null ? instance.trayItemCount() : 0
    }

    function trayOverflowCount(index) {
        const instance = panelInstance(index)
        return instance !== null ? instance.trayOverflowCount() : 0
    }

    function activateTrayInlineControl(index, itemIndex) {
        const instance = panelInstance(index)
        return instance !== null && instance.activateTrayInlineControl(itemIndex)
    }

    function openTrayOverflowControl(index) {
        const instance = panelInstance(index)
        return instance !== null && instance.openTrayOverflowControl()
    }

    function cancelTrayOverflowControl(index) {
        const instance = panelInstance(index)
        return instance !== null && instance.cancelTrayOverflowControl()
    }

    function trayOverflowVisible(index) {
        const instance = panelInstance(index)
        return instance !== null && instance.trayOverflowVisible()
    }

    function trayOverflowButtonFocused(index) {
        const instance = panelInstance(index)
        return instance !== null && instance.trayOverflowButtonFocused()
    }

    function trayOverflowEntryReady(index, itemIndex) {
        const instance = panelInstance(index)
        return instance !== null && instance.trayOverflowEntryReady(itemIndex)
    }

    function trayOverflowReadinessState(index, itemIndex) {
        const instance = panelInstance(index)
        return instance !== null
            ? instance.trayOverflowReadinessState(itemIndex) : "panel-missing"
    }

    function activateTrayOverflowControl(index, itemIndex) {
        const instance = panelInstance(index)
        return instance !== null && instance.activateTrayOverflowControl(itemIndex)
    }

    signal commandPaletteRequested(var screen)
    signal quickSettingsRequested(var screen)
    signal controlCenterRequested(var screen)
    signal workspaceRequested(int workspaceId)

    LinuraTheme { id: theme }

    Status.WorkstationStatus {
        id: workstationStatus
        clockPrecision: root.statusClockPrecision
    }

    Variants {
        id: panels
        model: Quickshell.screens

        PanelWindow {
            id: panel
            required property var modelData

            property bool keyboardNavigationActive: false
            property bool keyboardReleasePending: false

            readonly property int workspaceInlineLimit:
                width < 640 ? 1 : width < 960 ? 2 : 4
            readonly property int trayInlineLimit:
                width < 640 ? 1 : width < 960 ? 2 : 4
            readonly property int workspaceOverflowCount:
                Math.max(0, root.workspaceModel.length - workspaceInlineLimit)

            function focusedWorkspaceIndex() {
                for (let i = 0; i < root.workspaceModel.length; i++) {
                    if (root.workspaceModel[i].focused)
                        return i
                }
                return -1
            }

            function workspaceIsInline(index) {
                if (index < 0 || index >= root.workspaceModel.length)
                    return false

                const limit = workspaceInlineLimit
                const focusedIndex = focusedWorkspaceIndex()
                if (focusedIndex >= limit) {
                    if (index === focusedIndex)
                        return true
                    return index < Math.max(0, limit - 1)
                }
                return index < limit
            }

            function controlIsUsable(control) {
                if (!control
                        || !control.visible
                        || !control.enabled
                        || !control.activeFocusOnTab
                        || control.width <= 0
                        || control.height <= 0)
                    return false

                const point = control.mapToItem(panel.contentItem, 0, 0)
                return point.x >= 0
                    && point.y >= 0
                    && point.x + control.width <= panel.width
                    && point.y + control.height <= panel.height
            }

            function activateControl(control) {
                if (!controlIsUsable(control))
                    return false
                control.click()
                return true
            }

            function keyboardRestoreTarget(control) {
                if (controlIsUsable(control))
                    return control
                if (controlIsUsable(commandPaletteButton))
                    return commandPaletteButton
                return null
            }

            function restoreKeyboardEntry(control, reason) {
                const target = keyboardRestoreTarget(control)
                if (!target)
                    return false

                keyboardReleaseTimer.stop()
                panel.keyboardReleasePending = false
                panel.keyboardNavigationActive = true
                target.forceActiveFocus(reason)
                return true
            }

            function focusKeyboardEntry() {
                return restoreKeyboardEntry(
                    commandPaletteButton,
                    Qt.ShortcutFocusReason
                )
            }

            function releaseKeyboardEntry() {
                if (!panel.keyboardNavigationActive && !panel.keyboardReleasePending)
                    return
                panel.keyboardNavigationActive = false
                panel.keyboardReleasePending = true
                keyboardReleaseTimer.restart()
            }

            function releaseKeyboardEntryForPopup() {
                keyboardReleaseTimer.stop()
                // The native popup owns its own keyboard grab. Preserve the
                // parent's current mode throughout that grab: an asynchronous
                // Exclusive re-entry on cancellation/reopening clears an
                // already-created xdg_popup grab in the pinned compositor.
                // Pointer-opened popups retain OnDemand; keyboard-opened popups
                // retain Exclusive until dismissal releases or restores focus.
                panel.keyboardReleasePending = false
            }

            function keyboardEntryFocused() {
                return panel.keyboardNavigationActive
                    && commandPaletteButton.activeFocus
                    && commandPaletteButton.Window.active
            }

            function activateCommandPaletteControl() {
                return activateControl(commandPaletteButton)
            }

            function activateQuickSettingsControl() {
                return activateControl(quickSettingsButton)
            }

            function activateControlCenterControl() {
                return activateControl(controlCenterButton)
            }

            function activateWorkspaceControl(workspaceId) {
                for (let i = 0; i < workspaceRepeater.count; i++) {
                    const button = workspaceRepeater.itemAt(i)
                    if (button && button.modelData.id === workspaceId)
                        return activateControl(button)
                }
                return false
            }

            function statusTimeRendered() {
                return timeLabel.visible
                    && timeLabel.text.length > 0
                    && timeLabel.width > 0
                    && timeLabel.height > 0
            }

            function trayItemCount() { return systemTray.itemCount }
            function trayOverflowCount() { return systemTray.overflowCount }
            function activateTrayInlineControl(index) {
                return systemTray.activateInlineControl(index)
            }
            function openTrayOverflowControl() {
                return systemTray.openOverflowControl()
            }
            function cancelTrayOverflowControl() {
                return systemTray.cancelOverflowControl()
            }
            function trayOverflowVisible() {
                return systemTray.overflowIsVisible()
            }
            function trayOverflowButtonFocused() {
                return systemTray.overflowButtonFocused()
            }
            function trayOverflowEntryReady(index) {
                return systemTray.overflowEntryReady(index)
            }
            function trayOverflowReadinessState(index) {
                return systemTray.overflowReadinessState(index)
                    + " panelKeyboardNavigationActive=" + panel.keyboardNavigationActive
                    + " panelKeyboardReleasePending=" + panel.keyboardReleasePending
            }
            function activateTrayOverflowControl(index) {
                return systemTray.activateOverflowControl(index)
            }

            function openWorkspaceOverflow() {
                if (workspaceOverflowCount <= 0)
                    return
                workspaceOverflowWindow.visible = true
            }

            function focusFirstWorkspaceOverflowEntry() {
                if (!workspaceOverflowWindow.visible
                        || !workspaceOverflowWindow.backingWindowVisible)
                    return false
                for (let i = 0; i < workspaceOverflowRepeater.count; i++) {
                    const item = workspaceOverflowRepeater.itemAt(i)
                    if (item && item.activeFocus)
                        return true
                }
                for (let i = 0; i < workspaceOverflowRepeater.count; i++) {
                    const item = workspaceOverflowRepeater.itemAt(i)
                    if (item && item.visible && item.enabled
                            && item.width > 0 && item.height > 0) {
                        item.forceActiveFocus(Qt.TabFocusReason)
                        return item.activeFocus
                    }
                }
                return false
            }

            function dismissWorkspaceOverflow() {
                workspaceOverflowWindow.visible = false
                Qt.callLater(function() {
                    panel.restoreKeyboardEntry(
                        workspaceOverflowButton,
                        Qt.TabFocusReason
                    )
                })
            }

            onWorkspaceOverflowCountChanged: {
                if (workspaceOverflowCount === 0 && workspaceOverflowWindow.visible)
                    panel.dismissWorkspaceOverflow()
            }

            screen: modelData
            implicitHeight: root.panelHeight
            color: "transparent"
            exclusiveZone: root.panelHeight

            anchors {
                top: true
                left: true
                right: true
            }

            WlrLayershell.namespace: "linura-workstation-panel"
            WlrLayershell.layer: WlrLayer.Top
            WlrLayershell.keyboardFocus: panel.keyboardReleasePending
                ? WlrKeyboardFocus.None
                : panel.keyboardNavigationActive
                    ? WlrKeyboardFocus.Exclusive
                    : WlrKeyboardFocus.OnDemand

            Timer {
                id: keyboardReleaseTimer
                interval: 100
                repeat: false
                onTriggered: panel.keyboardReleasePending = false
            }

            Shortcut {
                sequence: "Escape"
                context: Qt.WindowShortcut
                enabled: panel.keyboardNavigationActive
                onActivated: panel.releaseKeyboardEntry()
            }

            LinuraSurface {
                anchors.fill: parent
                level: "background"
                cornerRadius: 0
                outlined: false
            }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: theme.spacingLg
                anchors.rightMargin: theme.spacingLg
                spacing: theme.spacingSm

                RowLayout {
                    id: leftGroup
                    spacing: theme.spacingXs

                    LinuraIconButton {
                        id: commandPaletteButton
                        glyph: "L"
                        accessibleName: qsTr("Open Linura command palette")
                        toolTip: accessibleName
                        onClicked: {
                            panel.releaseKeyboardEntry()
                            root.commandPaletteRequested(panel.screen)
                        }
                    }

                    Repeater {
                        id: workspaceRepeater
                        model: root.workspaceModel

                        LinuraIconButton {
                            required property int index
                            required property var modelData

                            visible: panel.workspaceIsInline(index)
                            activeFocusOnTab: visible
                            glyph: modelData.id > 0 ? String(modelData.id) : "•"
                            highlighted: modelData.focused
                            accessibleName: qsTr("Workspace %1%2")
                                .arg(modelData.name && modelData.name.length > 0
                                    ? modelData.name : String(modelData.id))
                                .arg(modelData.focused ? qsTr(", current") : "")
                            toolTip: accessibleName
                            onClicked: {
                                panel.releaseKeyboardEntry()
                                root.workspaceRequested(modelData.id)
                            }
                        }
                    }

                    LinuraIconButton {
                        id: workspaceOverflowButton
                        visible: panel.workspaceOverflowCount > 0
                        glyph: panel.workspaceOverflowCount > 9
                            ? "…" : "+" + panel.workspaceOverflowCount
                        accessibleName: qsTr("Show %1 more workspaces")
                            .arg(panel.workspaceOverflowCount)
                        toolTip: accessibleName
                        onClicked: {
                            panel.releaseKeyboardEntryForPopup()
                            panel.openWorkspaceOverflow()
                        }
                    }
                }

                Item {
                    id: centerZone
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    ColumnLayout {
                        anchors.centerIn: parent
                        spacing: 0

                        LinuraText {
                            id: timeLabel
                            Layout.alignment: Qt.AlignHCenter
                            text: workstationStatus.timeText
                            emphasized: true
                            Accessible.name: workstationStatus.accessibleText
                        }

                        LinuraText {
                            id: dateLabel
                            Layout.alignment: Qt.AlignHCenter
                            visible: panel.width >= 720
                            text: workstationStatus.dateText
                            role: "caption"
                            muted: true
                            Accessible.ignored: true
                        }
                    }
                }

                RowLayout {
                    id: rightGroup
                    spacing: theme.spacingXs

                    Tray.SystemTrayView {
                        id: systemTray
                        panelWindow: panel
                        inlineItemLimit: panel.trayInlineLimit
                        itemModelOverride: root.trayItemModelOverride
                        onInteractionStarted: panel.releaseKeyboardEntry()
                        onPopupInteractionStarted: panel.releaseKeyboardEntryForPopup()
                        onKeyboardReturnRequested: control =>
                            panel.restoreKeyboardEntry(control, Qt.TabFocusReason)
                    }

                    LinuraIconButton {
                        id: quickSettingsButton
                        glyph: "⚙"
                        accessibleName: qsTr("Open Quick Settings")
                        toolTip: accessibleName
                        onClicked: {
                            panel.releaseKeyboardEntry()
                            root.quickSettingsRequested(panel.screen)
                        }
                    }

                    LinuraIconButton {
                        id: controlCenterButton
                        glyph: "≡"
                        accessibleName: qsTr("Open Control Center")
                        toolTip: accessibleName
                        onClicked: {
                            panel.releaseKeyboardEntry()
                            root.controlCenterRequested(panel.screen)
                        }
                    }
                }
            }

            PopupWindow {
                id: workspaceOverflowWindow

                anchor.item: workspaceOverflowButton
                anchor.edges: Edges.Bottom | Edges.Left
                anchor.gravity: Edges.Bottom | Edges.Right
                anchor.adjustment: PopupAdjustment.All
                implicitWidth: Math.max(
                    1,
                    Math.min(300, panel.width - theme.spacingLg * 2)
                )
                implicitHeight: Math.min(
                    320,
                    workspaceOverflowColumn.implicitHeight + theme.spacingLg * 2
                )
                color: "transparent"
                surfaceFormat.opaque: false
                grabFocus: true
                visible: false

                Timer {
                    id: workspaceFocusRetry
                    interval: 100
                    repeat: true
                    running: false
                    property int attempts: 0

                    onTriggered: {
                        if (!workspaceOverflowWindow.visible
                                || !workspaceOverflowWindow.backingWindowVisible
                                || panel.focusFirstWorkspaceOverflowEntry()
                                || ++attempts >= 20)
                            stop()
                    }
                }

                onVisibleChanged: {
                    if (visible) {
                        Qt.callLater(panel.focusFirstWorkspaceOverflowEntry)
                    } else {
                        workspaceFocusRetry.stop()
                        panel.releaseKeyboardEntry()
                    }
                }
                onBackingWindowVisibleChanged: {
                    if (backingWindowVisible) {
                        workspaceFocusRetry.attempts = 0
                        workspaceFocusRetry.restart()
                        Qt.callLater(panel.focusFirstWorkspaceOverflowEntry)
                    } else {
                        workspaceFocusRetry.stop()
                    }
                }

                Shortcut {
                    sequence: "Escape"
                    context: Qt.WindowShortcut
                    enabled: workspaceOverflowWindow.visible
                    onActivated: panel.dismissWorkspaceOverflow()
                }

                LinuraSurface {
                    anchors.fill: parent
                    level: "elevated"
                    cornerRadius: theme.radiusLg
                    outlineWidth: theme.borderWidth
                }

                Flickable {
                    id: workspaceOverflowFlickable
                    anchors.fill: parent
                    anchors.margins: theme.spacingLg
                    contentWidth: width
                    contentHeight: workspaceOverflowColumn.implicitHeight
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
                        id: workspaceOverflowColumn
                        width: parent.width
                        spacing: theme.spacingXs

                        Repeater {
                            id: workspaceOverflowRepeater
                            model: root.workspaceModel

                            LinuraActionRow {
                                id: workspaceOverflowEntry
                                required property int index
                                required property var modelData

                                visible: !panel.workspaceIsInline(index)
                                height: visible ? implicitHeight : 0
                                width: workspaceOverflowColumn.width
                                title: qsTr("Workspace %1")
                                    .arg(modelData.name && modelData.name.length > 0
                                        ? modelData.name : String(modelData.id))
                                description: modelData.focused
                                    ? qsTr("Current workspace") : qsTr("Switch workspace")
                                selected: modelData.focused

                                onActiveFocusChanged: {
                                    if (activeFocus)
                                        workspaceOverflowFlickable.ensureVisible(workspaceOverflowEntry)
                                }

                                onClicked: {
                                    panel.releaseKeyboardEntry()
                                    root.workspaceRequested(modelData.id)
                                    workspaceOverflowWindow.visible = false
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
