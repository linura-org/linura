import QtQuick
import Quickshell
import Quickshell.Io

Scope {
    id: root

    property bool launchInFlight: false
    property int launchSequence: 0
    property int launchRequestGeneration: -1

    readonly property var applicationEntries: buildApplicationEntries()
    readonly property var reservedApplicationIds: [
        "org.linura.CommandPalette",
        "org.linura.CommandPalette.desktop",
        "org.linura.ControlCenter",
        "org.linura.ControlCenter.desktop"
    ]

    signal launchCompleted(string status, int requestGeneration)

    function isReservedApplicationId(applicationId) {
        return reservedApplicationIds.indexOf(applicationId) !== -1
    }

    function buildApplicationEntries() {
        const entries = []
        const applications = DesktopEntries.applications.values

        for (let i = 0; i < applications.length; i++) {
            const application = applications[i]
            if (!application.id
                    || application.noDisplay
                    || isReservedApplicationId(application.id))
                continue

            entries.push({
                id: application.id,
                name: application.name,
                genericName: application.genericName,
                comment: application.comment,
                icon: application.icon,
                keywords: application.keywords,
                categories: application.categories,
                terminal: application.runInTerminal
            })
        }

        entries.sort(function(left, right) {
            const leftName = (left.name || left.id).toLocaleLowerCase()
            const rightName = (right.name || right.id).toLocaleLowerCase()
            if (leftName < rightName)
                return -1
            if (leftName > rightName)
                return 1
            return left.id < right.id ? -1 : (left.id > right.id ? 1 : 0)
        })

        return entries
    }

    function nextTransientUnitName() {
        launchSequence = (launchSequence + 1) % 1000000
        return "linura-app-launch-" + Date.now() + "-" + launchSequence + ".service"
    }

    function isValidCommand(command) {
        if (!command || command.length === 0 || command.length > 128)
            return false

        for (let i = 0; i < command.length; i++) {
            const argument = command[i]
            if (typeof argument !== "string"
                    || argument.length > 4096
                    || argument.indexOf("\u0000") !== -1)
                return false
            if (i === 0 && argument.length === 0)
                return false
        }

        return true
    }

    function brokerCommand(application) {
        const command = application.command
        if (!isValidCommand(command))
            return []

        const workingDirectory = application.workingDirectory || ""
        if (workingDirectory.length > 4096
                || workingDirectory.indexOf("\u0000") !== -1
                || (workingDirectory.length > 0 && !workingDirectory.startsWith("/")))
            return []

        const broker = [
            "/usr/bin/systemd-run",
            "--user",
            "--collect",
            "--quiet",
            "--service-type=exec",
            "--property=ExitType=cgroup",
            "--slice=app.slice",
            "--expand-environment=no",
            "--unit=" + nextTransientUnitName()
        ]

        if (workingDirectory.length > 0)
            broker.push("--working-directory=" + workingDirectory)

        broker.push("--")
        for (let i = 0; i < command.length; i++)
            broker.push(command[i])

        return broker
    }

    function launchApplication(applicationId, requestGeneration) {
        if (!Number.isInteger(requestGeneration) || requestGeneration < 0)
            return "invalid-target"

        if (launchInFlight)
            return "busy"

        if (typeof applicationId !== "string"
                || applicationId.length === 0
                || applicationId.length > 512
                || isReservedApplicationId(applicationId))
            return "invalid-target"

        const applications = DesktopEntries.applications.values
        for (let i = 0; i < applications.length; i++) {
            const application = applications[i]
            if (application.id !== applicationId)
                continue

            if (application.noDisplay)
                return "not-visible"
            if (application.runInTerminal)
                return "terminal-unsupported"

            const command = brokerCommand(application)
            if (command.length === 0)
                return "invalid-target"

            launchRequestGeneration = requestGeneration
            launchInFlight = true
            launchBroker.exec(command)
            return "accepted"
        }

        return "not-found"
    }

    Process {
        id: launchBroker
        running: false

        onExited: (exitCode, exitStatus) => {
            const requestGeneration = root.launchRequestGeneration
            root.launchRequestGeneration = -1
            root.launchInFlight = false
            root.launchCompleted(
                exitCode === 0 ? "launched" : "broker-failed",
                requestGeneration
            )
        }
    }
}
