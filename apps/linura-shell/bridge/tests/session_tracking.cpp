#include "session_controller.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <iostream>

struct SessionTrackingTestAccess
{
    static bool retainLock(SessionController &controller, const QString &operation)
    {
        return controller.retain(operation, SessionController::LockRequest, QString(), false);
    }
};

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("linura-session-client-component"));
    QTemporaryDir temporary;
    if (!temporary.isValid())
        return 1;
    const auto directory = temporary.path() + QStringLiteral("/managed-state");
    const auto privateMode =
        QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner;
    if (!QDir().mkpath(directory) || !QFile::setPermissions(directory, privateMode))
        return 2;
    qputenv("STATE_DIRECTORY", directory.toUtf8());
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
    // This is the actual production QSaveFile retention and reload path.
    {
        SessionController original;
        if (!SessionTrackingTestAccess::retainLock(original, QStringLiteral("shell-atomic")))
            return 13;
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly))
            return 14;
        const auto retained = file.readAll();
        const auto permissions = QFileInfo(path).permissions();
        auto unsafePermissions = QFileDevice::ReadGroup | QFileDevice::WriteGroup;
        unsafePermissions |= QFileDevice::ReadOther;
        unsafePermissions |= QFileDevice::WriteOther;
        if (!retained.contains(QByteArrayLiteral("shell-atomic")) ||
            (permissions & unsafePermissions))
            return 14;
        SessionController restored;
        if (!restored.hasPending() ||
            restored.requestId() != QStringLiteral("request:v010:session-lock:shell-atomic"))
            return 15;
        restored.forgetTracking();
        if (restored.hasPending() || QFile::exists(path))
            return 16;
    }
    // An absent, relative or multi-root StateDirectory must not fall back.
    for (const auto &bad : {QByteArray(), QByteArray("relative"), QByteArray("/tmp/a:/tmp/b"),
                            QByteArray("/tmp/../tmp")}) {
        qputenv("STATE_DIRECTORY", bad);
        SessionController rejected;
        if (SessionTrackingTestAccess::retainLock(rejected, QStringLiteral("shell-deny")))
            return 17;
        if (QFile::exists(path))
            return 18;
    }
    const QString missingPath = temporary.path() + QStringLiteral("/missing-state");
    qputenv("STATE_DIRECTORY", missingPath.toUtf8());
    SessionController missingDirectory;
    if (SessionTrackingTestAccess::retainLock(missingDirectory, QStringLiteral("shell-deny")))
        return 26;
    if (QFile::exists(path))
        return 27;
    const QString link = temporary.path() + QStringLiteral("/state-link");
    if (!QFile::link(directory, link))
        return 19;
    qputenv("STATE_DIRECTORY", link.toUtf8());
    SessionController linked;
    if (SessionTrackingTestAccess::retainLock(linked, QStringLiteral("shell-deny")))
        return 20;
    qputenv("STATE_DIRECTORY", directory.toUtf8());
    if (!QFile::setPermissions(directory, privateMode | QFileDevice::WriteGroup))
        return 21;
    SessionController permissive;
    if (SessionTrackingTestAccess::retainLock(permissive, QStringLiteral("shell-deny")))
        return 22;
    if (!QFile::setPermissions(directory, privateMode))
        return 23;
    // Refuse an attacker-controlled symlink in place of the retained record.
    if (!QFile::link(directory, path))
        return 24;
    SessionController substituted;
    if (SessionTrackingTestAccess::retainLock(substituted, QStringLiteral("shell-deny")))
        return 25;
    QFile::remove(path);
    qputenv("STATE_DIRECTORY", directory.toUtf8());
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
