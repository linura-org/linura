#pragma once

#include <QString>
#include <vector>

struct NativeAssistiveApplication final
{
    QString connection;
    QString path;
    quint32 pid;
};

struct NativeAssistiveDiscovery final
{
    bool valid;
    QString owner;
};

// Registry applications, not every transport connection belonging to a PID,
// are the discovery surface. A second matching application is ambiguous even
// if its reference is identical. Absence permits bounded read-only observation;
// malformed or ambiguous registration never does.
inline NativeAssistiveDiscovery
nativeAssistiveApplication(const std::vector<NativeAssistiveApplication> &applications,
                           quint32 expectedPid)
{
    if (applications.size() > 32 || expectedPid <= 1 || expectedPid >= 0x80000000U)
        return {false, {}};
    QString owner;
    for (const auto &application : applications) {
        if (!application.connection.startsWith(QLatin1Char(':')) ||
            application.connection.size() > 128 || application.pid <= 1 ||
            application.pid >= 0x80000000U)
            return {false, {}};
        if (application.pid != expectedPid)
            continue;
        if (!owner.isEmpty() ||
            application.path != QStringLiteral("/org/a11y/atspi/accessible/root"))
            return {false, {}};
        owner = application.connection;
    }
    return {true, owner};
}
