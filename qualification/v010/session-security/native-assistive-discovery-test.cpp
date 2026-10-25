// Registry selection component checks, not real AT-SPI qualification evidence.
#include "native-assistive-discovery.h"
#include "native-assistive-prompt.h"
#include <QDBusMessage>
#include <cassert>

int main()
{
    const auto response =
        nativeAssistivePrompt(QStringLiteral("Password (1) · UID 1000"), false, 1000);
    assert(response && response->value("kind") == "response" && response->value("uid") == 1000);
    assert(nativeAssistivePrompt(QStringLiteral("Password (1) · UID 0"), false, 1000));
    assert(!nativeAssistivePrompt(QStringLiteral("Password (1) · UID 0"), true, 1000));
    for (int count = 2; count <= 8; ++count) {
        for (int index = 1; index <= count; ++index) {
            const auto label =
                QStringLiteral("Admin %1/%2: UID 1000 (Up/Down, Enter)").arg(index).arg(count);
            const auto choice = nativeAssistivePrompt(label, false, 1000);
            assert(choice && choice->value("kind") == "identity-selection" &&
                   choice->value("uid") == 1000 && choice->value("index") == index &&
                   choice->value("count") == count);
            assert(!nativeAssistivePrompt(label, true, 1000));
        }
    }
    for (const auto &label :
         {"Admin 1/0: UID 1000 (Up/Down, Enter)", "Admin 1/1: UID 1000 (Up/Down, Enter)",
          "Admin 3/2: UID 1000 (Up/Down, Enter)", "Admin 1/9: UID 1000 (Up/Down, Enter)",
          "Admin 01/2: UID 1000 (Up/Down, Enter)", "Admin 1/2: UID 01000 (Up/Down, Enter)",
          "Admin 1/2: UID 2147483648 (Up/Down, Enter)", "Password (1) · UID 2147483648",
          "Password (2) · UID 1000", "Password (1) · UID 01000", "Password (1) · UID 1000\n",
          "Admin 1/2: UID 1000 (Up/Down, Enter)\n", "arbitrary private prompt"})
        assert(!nativeAssistivePrompt(QString::fromUtf8(label), false, 1000));
    // Qt 6 never exposes a reply sender through service(). Treating it as
    // such rejects real registry replies even with a valid pinned destination.
    const auto request = QDBusMessage::createMethodCall(
        QStringLiteral(":1.42"), QStringLiteral("/org/a11y/atspi/accessible/root"),
        QStringLiteral("org.a11y.atspi.Accessible"), QStringLiteral("GetChildren"));
    assert(request.type() == QDBusMessage::MethodCallMessage &&
           request.service() == QStringLiteral(":1.42"));
    const auto reply = request.createReply();
    assert(reply.type() == QDBusMessage::ReplyMessage && reply.service().isEmpty());
    const auto error = request.createErrorReply(
        QStringLiteral("org.freedesktop.DBus.Error.UnknownMethod"), QStringLiteral("unsupported"));
    assert(error.type() == QDBusMessage::ErrorMessage && error.service().isEmpty());
    const NativeAssistiveApplication actual{QStringLiteral(":1.7"),
                                            QStringLiteral("/org/a11y/atspi/accessible/root"), 123};
    const NativeAssistiveApplication other{QStringLiteral(":1.8"),
                                           QStringLiteral("/org/a11y/atspi/accessible/root"), 456};
    const auto selected = nativeAssistiveApplication({other, actual}, 123);
    assert(selected.valid && selected.owner == actual.connection);
    const auto absent = nativeAssistiveApplication({other}, 123);
    assert(absent.valid && absent.owner.isEmpty());
    assert(nativeAssistiveApplication({}, 123).valid);
    assert(!nativeAssistiveApplication({actual, actual}, 123).valid);
    auto replaced = actual;
    replaced.connection = QStringLiteral(":1.9");
    assert(!nativeAssistiveApplication({actual, replaced}, 123).valid);
    auto wrongPath = actual;
    wrongPath.path = QStringLiteral("/another/root");
    assert(!nativeAssistiveApplication({wrongPath}, 123).valid);
    auto wellKnown = actual;
    wellKnown.connection = QStringLiteral("org.example.Untrusted");
    assert(!nativeAssistiveApplication({wellKnown}, 123).valid);
    auto invalidPid = actual;
    invalidPid.pid = 0;
    assert(!nativeAssistiveApplication({invalidPid}, 123).valid);
    for (const auto pid : {0U, 1U, 0x80000000U, 0xffffffffU})
        assert(!nativeAssistiveApplication({actual}, pid).valid);
    assert(
        !nativeAssistiveApplication(std::vector<NativeAssistiveApplication>(33, other), 123).valid);
}
