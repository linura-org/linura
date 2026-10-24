#include "native_property.h"
#include "native_sleep_probe.h"

#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusObjectPath>
#include <QDBusReply>
#include <QDBusVirtualObject>
#include <QFile>
#include <QProcess>
#include <QTemporaryDir>
#include <QTimer>
#include <QThread>

#include <cassert>
#include <utility>
#include <unistd.h>

using namespace Linura::SecurityOwner;

namespace {
// An isolated, same-UID component bus, never native/root supervision evidence.
const QString Service = QStringLiteral("org.linura.Private.ComponentSupervisor");
const QString Path = QStringLiteral("/org/freedesktop/systemd1");
const QString UnitPath = QStringLiteral("/org/freedesktop/systemd1/unit/component");
const QString Manager = QStringLiteral("org.freedesktop.systemd1.Manager");

class Child final
{
  public:
    QProcess process;
    ~Child()
    {
        if (process.state() != QProcess::NotRunning) {
            process.kill();
            (void)process.waitForFinished(2000);
        }
    }
    QString start(const QString &image, const QStringList &arguments)
    {
        process.start(image, arguments);
        assert(process.waitForStarted(2000));
        assert(process.waitForReadyRead(2000));
        const auto output = process.readAllStandardOutput();
        assert(output.size() <= 4096 && output.endsWith('\n') && output.count('\n') == 1);
        return QString::fromUtf8(output).trimmed();
    }
};

class Supervisor final : public QDBusVirtualObject
{
  public:
    explicit Supervisor(QDBusConnection attacker) : attacker_(std::move(attacker)) {}
    QString introspect(const QString &) const override
    {
        return {};
    }
    bool handleMessage(const QDBusMessage &request, const QDBusConnection &connection) override
    {
        if (request.interface() == Manager && request.member() == QLatin1String("GetUnit") &&
            request.arguments().size() == 1) {
            const auto unit = request.arguments().first().toString();
            if (unit == QLatin1String("timeout.service"))
                return true; // No reply: neither a successful lookup nor absence.
            if (unit == QLatin1String("absent.service"))
                return connection.send(request.createErrorReply(
                    QStringLiteral("org.freedesktop.systemd1.NoSuchUnit"), QString{}));
            if (unit == QLatin1String("forged-reply.service") ||
                unit == QLatin1String("forged-absence.service")) {
                // The foreign connection has the exact pending serial and
                // destination. System-bus requested-reply rules must reject it.
                const auto forged =
                    unit == QLatin1String("forged-reply.service")
                        ? request.createReply(QList<QVariant>{
                              QVariant::fromValue(QDBusObjectPath(QStringLiteral("/forged")))})
                        : request.createErrorReply(
                              QStringLiteral("org.freedesktop.systemd1.NoSuchUnit"), QString{});
                assert(attacker_.send(forged));
                // Round-trip the attacker's connection before the genuine
                // reply, so delivery order cannot hide an accepted forgery.
                const auto barrier = QDBusMessage::createMethodCall(
                    QStringLiteral("org.freedesktop.DBus"), QStringLiteral("/org/freedesktop/DBus"),
                    QStringLiteral("org.freedesktop.DBus"), QStringLiteral("GetId"));
                assert(attacker_.call(barrier, QDBus::Block, 500).type() ==
                       QDBusMessage::ReplyMessage);
            }
            return connection.send(request.createReply(
                unit == QLatin1String("malformed.service")
                    ? QList<QVariant>{QStringLiteral("not-an-object-path")}
                    : QList<QVariant>{QVariant::fromValue(QDBusObjectPath(UnitPath))}));
        }
        if (request.interface() == QLatin1String("org.freedesktop.DBus.Properties") &&
            request.member() == QLatin1String("Get") && request.arguments().size() == 2) {
            const auto name = request.arguments()[1].toString();
            if (name.startsWith(QLatin1String("Batch"))) {
                bool ok = false;
                const auto index = name.mid(5).toUInt(&ok);
                if (!ok || index >= 8 || name != QStringLiteral("Batch%1").arg(index))
                    return connection.send(request.createErrorReply(
                        QStringLiteral("org.freedesktop.DBus.Error.UnknownProperty"), QString{}));
                // A serial reader can never release this barrier. Every fixed
                // read must be on the wire before any response is available.
                batch_.emplace_back(request, connection);
                if (batch_.size() == 8) {
                    for (const auto &[pending, peer] : batch_) {
                        const auto position = pending.arguments()[1].toString().mid(5).toUInt();
                        assert(peer.send(pending.createReply(QList<QVariant>{QVariant::fromValue(
                            QDBusVariant(quint32{batchRound_ * 100 + position}))})));
                    }
                    batch_.clear();
                    ++batchRound_;
                }
                return true;
            }
            if (name == QLatin1String("Malformed"))
                return connection.send(request.createReply(QList<QVariant>{QStringLiteral("bad")}));
            if (name == QLatin1String("Late")) {
                QTimer::singleShot(80, this, [request, connection] {
                    assert(connection.send(request.createReply(
                        QList<QVariant>{QVariant::fromValue(QDBusVariant(quint32{42}))})));
                });
                return true;
            }
            if (name != QLatin1String("ControlPID"))
                return connection.send(request.createErrorReply(
                    QStringLiteral("org.freedesktop.DBus.Error.UnknownProperty"), QString{}));
            return connection.send(request.createReply(
                QList<QVariant>{QVariant::fromValue(QDBusVariant(quint32{42}))}));
        }
        return connection.send(request.createErrorReply(
            QStringLiteral("org.freedesktop.DBus.Error.InvalidArgs"), QString{}));
    }

  private:
    QDBusConnection attacker_;
    std::vector<std::pair<QDBusMessage, QDBusConnection>> batch_;
    quint32 batchRound_ = 0;
};

int serve(QCoreApplication &application, const QString &address)
{
    auto service = QDBusConnection::connectToBus(address, QStringLiteral("component-service"));
    const auto attacker =
        QDBusConnection::connectToBus(address, QStringLiteral("component-attacker"));
    assert(service.isConnected() && attacker.isConnected());
    Supervisor object(attacker);
    assert(service.registerVirtualObject(Path, &object, QDBusConnection::SubPath));
    assert(service.registerService(Service));
    const auto ready = service.baseService().toUtf8() + '\n';
    assert(::write(STDOUT_FILENO, ready.constData(), size_t(ready.size())) == ready.size());
    return application.exec();
}
} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    const auto arguments = application.arguments();
    if (arguments.size() == 3 && arguments[1] == QLatin1String("--component-service"))
        return serve(application, arguments[2]);
    assert(arguments.size() == 1);
    QTemporaryDir directory;
    assert(directory.isValid());
    QFile config(directory.path() + QStringLiteral("/bus.conf"));
    assert(config.open(QIODevice::WriteOnly));
    // Match the system bus's requested-reply restriction. Do not include the
    // permissive session policy or host configuration, even when run as root.
    const auto policy =
        (QStringLiteral("<busconfig><type>session</type><auth>EXTERNAL</auth>"
                        "<listen>unix:path=") +
         directory.path().toHtmlEscaped() +
         QStringLiteral("/bus</listen><policy context=\"default\">"
                        "<allow user=\"*\"/><allow own=\"*\"/>"
                        "<allow send_type=\"method_call\"/>"
                        "<allow send_type=\"signal\"/>"
                        "<allow send_requested_reply=\"true\" send_type=\"method_return\"/>"
                        "<allow send_requested_reply=\"true\" send_type=\"error\"/>"
                        "<allow receive_type=\"method_call\"/>"
                        "<allow receive_type=\"method_return\"/>"
                        "<allow receive_type=\"error\"/><allow receive_type=\"signal\"/>"
                        "</policy></busconfig>"))
            .toUtf8();
    assert(config.write(policy) == policy.size());
    config.close();
    Child bus;
    const auto address =
        bus.start(QStringLiteral(LINURA_TEST_DBUS_DAEMON),
                  {QStringLiteral("--nofork"), QStringLiteral("--nopidfile"),
                   QStringLiteral("--nosyslog"), QStringLiteral("--print-address=1"),
                   QStringLiteral("--config-file=") + config.fileName()});
    assert(address.startsWith(QLatin1String("unix:path=")));
    Child service;
    const auto original = service.start(QCoreApplication::applicationFilePath(),
                                        {QStringLiteral("--component-service"), address});
    assert(original.startsWith(QLatin1Char(':')));
    const auto client = QDBusConnection::connectToBus(address, QStringLiteral("component-client"));
    assert(client.isConnected());
    const auto call = [&](const QString &owner, const QString &path, const QString &interface,
                          const QString &method, const QList<QVariant> &values) {
        auto request = QDBusMessage::createMethodCall(owner, path, interface, method);
        request.setArguments(values);
        return client.call(request, QDBus::Block, 500);
    };
    const auto lookup = [&](const QString &unit) {
        return call(original, Path, Manager, QStringLiteral("GetUnit"), {unit});
    };
    for (const auto &unit :
         {QStringLiteral("component.service"), QStringLiteral("forged-reply.service"),
          QStringLiteral("forged-absence.service")}) {
        const auto reply = lookup(unit);
        assert(reply.type() == QDBusMessage::ReplyMessage);
        // Qt 6.4 exposes the actual sender; Qt 6.11 deliberately hides it.
        // The received value must be either unavailable or the exact peer.
        assert(reply.service().isEmpty() || reply.service() == original);
        assert(nativeSleepUnitLookupReply(reply, original));
        assert(!nativeSleepUnitLookupReply(reply, QString{}));
        assert(!nativeSleepUnitLookupReply(reply, Service));
        if (!reply.service().isEmpty())
            assert(!nativeSleepUnitLookupReply(reply, QStringLiteral(":9.999")));
        const QDBusReply<QDBusObjectPath> path(reply);
        assert(path.isValid() && path.value().path() == UnitPath);
    }
    for (int sample = 0; sample < 2; ++sample) {
        const auto absent = lookup(QStringLiteral("absent.service"));
        assert(absent.type() == QDBusMessage::ErrorMessage);
        assert(absent.service().isEmpty() || absent.service() == original);
        assert(nativeSleepUnitLookupReply(absent, original));
        assert(absent.errorName() == QLatin1String("org.freedesktop.systemd1.NoSuchUnit"));
    }
    const QDBusReply<QDBusObjectPath> malformed(lookup(QStringLiteral("malformed.service")));
    assert(!malformed.isValid()); // A return message alone is not a typed lookup.
    assert(!nativeSleepUnitLookupReply(lookup(QStringLiteral("timeout.service")), original));
    const auto pid = readNativeDBusProperty(call, original, UnitPath,
                                            QStringLiteral("org.freedesktop.systemd1.Service"),
                                            QStringLiteral("ControlPID"));
    assert(pid && pid->metaType() == QMetaType::fromType<quint32>() && pid->toUInt() == 42);
    assert(!readNativeDBusProperty(call, original, UnitPath,
                                   QStringLiteral("org.freedesktop.systemd1.Service"),
                                   QStringLiteral("Missing")));

    const QString propertyInterface = QStringLiteral("org.freedesktop.systemd1.Service");
    const auto batch = [&](const QStringList &names, qint64 total = 500, qint64 perCall = 200,
                           const NativeProbeProgress &progress = NativeProbeProgress{}) {
        QElapsedTimer budget;
        budget.start();
        return readNativeDBusProperties(client, budget, original, UnitPath, propertyInterface,
                                        names, total, perCall, progress);
    };
    // Invalid admission must emit no partial batch (otherwise the barrier and
    // round identity in the following successful reads cannot match).
    assert(!batch({}));
    assert(!batch({QStringLiteral("Batch0"), QStringLiteral("Batch0")}));
    assert(!batch({QString{}}));
    assert(!batch({QStringLiteral("Batch0")}, 0));
    assert(!batch({QStringLiteral("Batch0")}, 500, 0));
    QStringList excessive;
    for (int index = 0; index < 33; ++index)
        excessive.append(QStringLiteral("Batch%1").arg(index));
    assert(!batch(excessive));
    assert(!batch({QStringLiteral("Batch0")}, 10, 200, [] { QThread::msleep(25); }));
    QStringList names;
    for (int index = 0; index < 8; ++index)
        names.append(QStringLiteral("Batch%1").arg(index));
    for (quint32 round = 0; round < 2; ++round) {
        unsigned progressed = 0;
        const auto fields = batch(names, 500, 200, [&] { ++progressed; });
        assert(fields && fields->size() == 8);
        assert(progressed == 9); // Admission and each wait, inside the original clock.
        for (quint32 index = 0; index < 8; ++index) {
            const auto value = fields->value(QStringLiteral("Batch%1").arg(index));
            assert(value.metaType() == QMetaType::fromType<quint32>());
            assert(value.toUInt() == round * 100 + index); // Each sample is fresh.
        }
    }
    assert(!batch({QStringLiteral("ControlPID"), QStringLiteral("Malformed")}));
    assert(!batch({QStringLiteral("ControlPID"), QStringLiteral("Missing")}));
    assert(!batch({QStringLiteral("Late")}, 20, 200)); // Late success is not evidence.
    service.process.kill();
    assert(service.process.waitForFinished(2000));
    Child replacement;
    const auto replaced = replacement.start(QCoreApplication::applicationFilePath(),
                                            {QStringLiteral("--component-service"), address});
    assert(replaced != original);
    assert(!nativeSleepUnitLookupReply(lookup(QStringLiteral("component.service")), original));
    const QDBusReply<QString> current(
        call(QStringLiteral("org.freedesktop.DBus"), QStringLiteral("/org/freedesktop/DBus"),
             QStringLiteral("org.freedesktop.DBus"), QStringLiteral("GetNameOwner"), {Service}));
    assert(current.isValid() && current.value() == replaced && current.value() != original);
    QDBusConnection::disconnectFromBus(QStringLiteral("component-client"));
}
