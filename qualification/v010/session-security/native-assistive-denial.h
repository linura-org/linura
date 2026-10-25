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
