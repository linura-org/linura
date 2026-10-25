#pragma once

#include <QStringView>

// Classify only a correlated remote ErrorMessage from a pinned unique destination. This does
// not admit a transport timeout/disconnect or a malformed local request.
inline bool nativeAssistiveDenial(QStringView error, bool knownReadOnlyProperty)
{
    return error == u"org.freedesktop.DBus.Error.UnknownMethod" ||
           error == u"org.freedesktop.DBus.Error.UnknownInterface" ||
           error == u"org.freedesktop.DBus.Error.UnknownProperty" ||
           error == u"org.freedesktop.DBus.Error.PropertyReadOnly" ||
           (knownReadOnlyProperty && error == u"org.freedesktop.DBus.Error.InvalidArgs");
}

// Failure diagnostics only. These are never unsupported-API evidence and must
// abort the probe before decoding any apparent metadata or accepting a denial.
enum class NativeAssistiveCallFailure {
    None = 0,
    Deadline = 30,
    PeerUnavailable = 31,
    Disconnected = 32
};
inline NativeAssistiveCallFailure nativeAssistiveCallFailure(QStringView error)
{
    if (error == u"org.freedesktop.DBus.Error.NoReply" ||
        error == u"org.freedesktop.DBus.Error.Timeout" ||
        error == u"org.freedesktop.DBus.Error.TimedOut")
        return NativeAssistiveCallFailure::Deadline;
    if (error == u"org.freedesktop.DBus.Error.NameHasNoOwner" ||
        error == u"org.freedesktop.DBus.Error.ServiceUnknown")
        return NativeAssistiveCallFailure::PeerUnavailable;
    if (error == u"org.freedesktop.DBus.Error.Disconnected")
        return NativeAssistiveCallFailure::Disconnected;
    return NativeAssistiveCallFailure::None;
}

// Keep both the closed transport failure and the phase active when it failed.
// Every value is a failing process status; unsupported kinds/phases cannot
// become success or alias a known diagnostic. No remote text enters this code.
inline int nativeAssistiveFailureExitCode(NativeAssistiveCallFailure failure, int stage)
{
    const auto kind = static_cast<int>(failure);
    if (kind < 30 || kind > 32 || stage < 10 || stage > 19)
        return 1;
    return 100 + (kind - 30) * 10 + (stage - 10);
}
