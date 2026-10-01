import QtQuick
import Quickshell

Scope {
    id: root

    property int clockPrecision: SystemClock.Minutes
    readonly property string timeText: Qt.formatDateTime(clock.date, "HH:mm")
    readonly property string dateText: Qt.formatDateTime(clock.date, "ddd, MMM d")
    readonly property string accessibleText: qsTr("%1, %2").arg(dateText).arg(timeText)
    readonly property real timestampMs: clock.date.getTime()

    SystemClock {
        id: clock
        precision: root.clockPrecision
    }
}
