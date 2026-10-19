#pragma once

#include <QStringView>

// Classify only an already sender-authenticated remote ErrorMessage. This does
// not admit a transport timeout/disconnect or a malformed local request.
inline bool nativeAssistiveDenial(QStringView error, bool knownReadOnlyProperty)
{
    return error == u"org.freedesktop.DBus.Error.UnknownMethod" ||
           error == u"org.freedesktop.DBus.Error.UnknownInterface" ||
           error == u"org.freedesktop.DBus.Error.UnknownProperty" ||
           error == u"org.freedesktop.DBus.Error.PropertyReadOnly" ||
           (knownReadOnlyProperty && error == u"org.freedesktop.DBus.Error.InvalidArgs");
}
