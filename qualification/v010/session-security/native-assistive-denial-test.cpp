// Component classifier test only; not actual native AT-SPI evidence.
#include "native-assistive-denial.h"
#include <cassert>

int main()
{
    for (bool readOnly : {false, true}) {
        for (auto error : {u"org.freedesktop.DBus.Error.UnknownMethod",
                           u"org.freedesktop.DBus.Error.UnknownInterface",
                           u"org.freedesktop.DBus.Error.UnknownProperty",
                           u"org.freedesktop.DBus.Error.PropertyReadOnly"})
            assert(nativeAssistiveDenial(QStringView(error), readOnly));
        for (auto error :
             {u"org.freedesktop.DBus.Error.NoReply", u"org.freedesktop.DBus.Error.Disconnected",
              u"org.freedesktop.DBus.Error.Timeout", u"org.freedesktop.DBus.Error.ServiceUnknown",
              u"", u"unknown"})
            assert(!nativeAssistiveDenial(QStringView(error), readOnly));
    }
    assert(nativeAssistiveDenial(u"org.freedesktop.DBus.Error.InvalidArgs", true));
    assert(!nativeAssistiveDenial(u"org.freedesktop.DBus.Error.InvalidArgs", false));
}
