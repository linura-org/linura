#include "session_controller.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <iostream>

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("linura-session-client-component"));
    QTemporaryDir temporary;
    if (!temporary.isValid())
        return 1;
    qputenv("XDG_DATA_HOME", temporary.path().toUtf8());
    const auto directory = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (!directory.startsWith(temporary.path() + QLatin1Char('/')) || !QDir().mkpath(directory))
        return 2;
    const auto path = directory + QStringLiteral("/session-request.json");
    for (const auto &bytes : {
             QByteArray("{\"version\":1,\"operation\":\"shell-example\",\"transition\":false}"),
             QByteArray("{\"version\":1,\"operation\":\"shell-example\",\"transition\":true}"),
             QByteArray("{\"version\":2,\"operation\":\"shell-example\",\"transition\":true}"),
             QByteArray("{\"version\":1,\"operation\":\"Bad--Operation\",\"transition\":true}"),
             QByteArray("{\"version\":1,\"operation\":\"shell-example\",\"transition\":\"true\"}"),
             QByteArray("{\"version\":1,\"operation\":\"shell-example\",\"transition\":true,"
                        "\"resume\":true}"),
             QByteArray("broken JSON"),
             QByteArray(1025, 'x'),
         }) {
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate) ||
            file.write(bytes) != bytes.size())
            return 3;
        file.close();
        SessionController controller;
        if (!controller.hasPending() || controller.busy())
            return 4;
        // Unreleased v1 tracking is deliberately not a compatibility surface.
        // Refuse it intact, rather than guessing a new request kind.
        if (!controller.requestId().isEmpty())
            return 9;
        controller.request(SessionController::Reboot);
        QCoreApplication::processEvents();
        // Loading even a valid record can only retain tracking, never continue
        // its abandoned lock/power workflow or initiate an approval prompt.
        if (controller.busy() || !controller.hasPending())
            return 5;
        controller.forgetTracking();
        if (controller.hasPending() || controller.busy() || QFile::exists(path))
            return 6;
    }
    for (
        const auto &[bytes, expected] : std::initializer_list<std::pair<QByteArray, QString>>{
            {R"({"version":2,"operation":"shell-example","kind":"lock"})",
             "request:v010:session-lock:shell-example"},
            {R"({"version":2,"operation":"shell-example","kind":"transition"})",
             "request:v010:session-transition:shell-example"},
            {R"({"version":2,"operation":"shell-example","kind":"protective-setting","resource":"session:lock:12345678-1234-1234-1234-123456789abc:1000:c1:9:12345678-1234-1234-1234-123456789abc:1","enabled":true})",
             "request:v010:protective-lock-setting:shell-example"},
            {R"({"version":2,"operation":"shell-example","kind":"protective-setting","resource":"session:lock:12345678-1234-1234-1234-123456789abc:1000:c1:9:12345678-1234-1234-1234-123456789abc:1","enabled":false})",
             "request:v010:protective-lock-setting:shell-example"},
            {R"({"version":2,"operation":"shell-example","kind":"protective-setting","enabled":true})",
             {}},
            {R"({"version":2,"operation":"shell-example","kind":"lock","enabled":true})", {}},
            {R"({"version":2,"operation":"shell-example","kind":"protective-setting","resource":"session:lock:invalid","enabled":true})",
             {}},
            {R"({"version":2,"operation":"shell-example","kind":"protective-setting","resource":"session:lock:12345678-1234-1234-1234-123456789abc:1000:c1:9:12345678-1234-1234-1234-123456789abc:1","enabled":"true"})",
             {}},
            {R"({"version":2,"operation":"shell-example","kind":"protective-setting","resource":"session:lock:12345678-1234-1234-1234-123456789abc:1000:c1:9:12345678-1234-1234-1234-123456789abc:1","enabled":true,"resume":true})",
             {}},
            {R"({"version":2,"operation":"shell-example","kind":"automatic"})", {}},
        }) {
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate) ||
            file.write(bytes) != bytes.size())
            return 10;
        file.close();
        SessionController controller;
        for (const auto action :
             {SessionController::EnableProtectiveLock, SessionController::RevokeProtectiveLock,
              SessionController::Suspend})
            controller.request(action);
        QCoreApplication::processEvents();
        if (!controller.hasPending() || controller.busy() || controller.requestId() != expected)
            return 11;
        controller.forgetTracking();
        if (controller.hasPending() || QFile::exists(path))
            return 12;
    }
    SessionController empty;
    empty.recover();
    if (empty.busy() || empty.hasPending())
        return 7;
    empty.request(static_cast<SessionController::Action>(999));
    if (empty.busy() || empty.hasPending())
        return 8;
    std::cout
        << "local tracking reload, bounds, invalid record and no implicit effect checks passed\n";
}
