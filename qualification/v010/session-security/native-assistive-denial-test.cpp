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
    for (auto error : {u"org.freedesktop.DBus.Error.NoReply", u"org.freedesktop.DBus.Error.Timeout",
                       u"org.freedesktop.DBus.Error.TimedOut"})
        assert(nativeAssistiveCallFailure(QStringView(error)) ==
               NativeAssistiveCallFailure::Deadline);
    for (auto error : {u"org.freedesktop.DBus.Error.NameHasNoOwner",
                       u"org.freedesktop.DBus.Error.ServiceUnknown"})
        assert(nativeAssistiveCallFailure(QStringView(error)) ==
               NativeAssistiveCallFailure::PeerUnavailable);
    assert(nativeAssistiveCallFailure(u"org.freedesktop.DBus.Error.Disconnected") ==
           NativeAssistiveCallFailure::Disconnected);
    for (auto error :
         {u"org.freedesktop.DBus.Error.UnknownMethod",
          u"org.freedesktop.DBus.Error.UnknownInterface",
          u"org.freedesktop.DBus.Error.UnknownProperty",
          u"org.freedesktop.DBus.Error.PropertyReadOnly", u"org.freedesktop.DBus.Error.InvalidArgs",
          u"org.freedesktop.DBus.Error.AccessDenied", u"private-wire-marker", u""})
        assert(nativeAssistiveCallFailure(QStringView(error)) == NativeAssistiveCallFailure::None);

    // A transport failure must retain its active phase, including the denial
    // checks: a timeout there still proves no rejected remote-input API.
    assert(nativeAssistiveFailureExitCode(NativeAssistiveCallFailure::Deadline, 16) == 106);
    assert(nativeAssistiveFailureExitCode(NativeAssistiveCallFailure::Deadline, 18) == 108);
    assert(nativeAssistiveFailureExitCode(NativeAssistiveCallFailure::PeerUnavailable, 13) == 113);
    assert(nativeAssistiveFailureExitCode(NativeAssistiveCallFailure::Disconnected, 19) == 129);
    bool statuses[256] = {};
    for (auto failure :
         {NativeAssistiveCallFailure::Deadline, NativeAssistiveCallFailure::PeerUnavailable,
          NativeAssistiveCallFailure::Disconnected}) {
        for (int stage = 10; stage <= 19; ++stage) {
            const auto status = nativeAssistiveFailureExitCode(failure, stage);
            assert(status >= 100 && status <= 129 && !statuses[status]);
            statuses[status] = true;
        }
        for (int stage : {-1, 0, 9, 20, 100, 255})
            assert(nativeAssistiveFailureExitCode(failure, stage) == 1);
    }
    for (auto failure :
         {NativeAssistiveCallFailure::None, static_cast<NativeAssistiveCallFailure>(-1),
          static_cast<NativeAssistiveCallFailure>(29), static_cast<NativeAssistiveCallFailure>(33),
          static_cast<NativeAssistiveCallFailure>(100)}) {
        for (int stage = 10; stage <= 19; ++stage)
            assert(nativeAssistiveFailureExitCode(failure, stage) == 1);
    }
}
