#include "native_launch.h"
#include "native_sleep_probe.h"
#include "session_bootstrap.h"

#include <QCoreApplication>
#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusObjectPath>
#include <QDBusPendingCallWatcher>
#include <QDBusReply>
#include <QDBusServer>
#include <QDBusVariant>
#include <QEventLoop>
#include <QTemporaryDir>
#include <QTimer>
#include <QUuid>

#include <cassert>
#include <optional>

// Official D-Bus codec exercise only: this private, same-UID peer bus does NOT
// attest root-systemd, a native session, a service launch or execution authority.
namespace Linura::SecurityOwner {
QDBusArgument &operator<<(QDBusArgument &value, const NativeLaunchFacts &facts)
{
    value.beginStructure();
    value << facts.image << facts.arguments << facts.ignoreFailure << facts.startedReal
          << facts.startedMonotonic << facts.exitedReal << facts.exitedMonotonic << facts.pid
          << facts.code << facts.status;
    value.endStructure();
    return value;
}
const QDBusArgument &operator>>(const QDBusArgument &value, NativeLaunchFacts &facts)
{
    value.beginStructure();
    value >> facts.image >> facts.arguments >> facts.ignoreFailure >> facts.startedReal >>
        facts.startedMonotonic >> facts.exitedReal >> facts.exitedMonotonic >> facts.pid >>
        facts.code >> facts.status;
    value.endStructure();
    return value;
}
} // namespace Linura::SecurityOwner
using Linura::SecurityOwner::NativeLaunchFacts;
using LaunchList = QList<NativeLaunchFacts>;
Q_DECLARE_METATYPE(NativeLaunchFacts)
Q_DECLARE_METATYPE(LaunchList)

struct WireJob
{
    quint32 id;
    QDBusObjectPath path;
};
struct WireSuccess
{
    QList<qint32> codes, signals;
};
struct WireUser
{
    quint32 uid;
    QDBusObjectPath path;
};
struct WireSeat
{
    QString name;
    QDBusObjectPath path;
};
Q_DECLARE_METATYPE(WireJob)
Q_DECLARE_METATYPE(WireSuccess)
Q_DECLARE_METATYPE(WireUser)
Q_DECLARE_METATYPE(WireSeat)
QDBusArgument &operator<<(QDBusArgument &wire, const WireJob &job)
{
    wire.beginStructure();
    wire << job.id << job.path;
    wire.endStructure();
    return wire;
}
const QDBusArgument &operator>>(const QDBusArgument &wire, WireJob &job)
{
    wire.beginStructure();
    wire >> job.id >> job.path;
    wire.endStructure();
    return wire;
}
QDBusArgument &operator<<(QDBusArgument &wire, const WireSuccess &success)
{
    wire.beginStructure();
    wire << success.codes << success.signals;
    wire.endStructure();
    return wire;
}
const QDBusArgument &operator>>(const QDBusArgument &wire, WireSuccess &success)
{
    wire.beginStructure();
    wire >> success.codes >> success.signals;
    wire.endStructure();
    return wire;
}
QDBusArgument &operator<<(QDBusArgument &wire, const WireUser &user)
{
    wire.beginStructure();
    wire << user.uid << user.path;
    wire.endStructure();
    return wire;
}
const QDBusArgument &operator>>(const QDBusArgument &wire, WireUser &user)
{
    wire.beginStructure();
    wire >> user.uid >> user.path;
    wire.endStructure();
    return wire;
}
QDBusArgument &operator<<(QDBusArgument &wire, const WireSeat &seat)
{
    wire.beginStructure();
    wire << seat.name << seat.path;
    wire.endStructure();
    return wire;
}
const QDBusArgument &operator>>(const QDBusArgument &wire, WireSeat &seat)
{
    wire.beginStructure();
    wire >> seat.name >> seat.path;
    wire.endStructure();
    return wire;
}

class LaunchFixture final : public QObject
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.linura.Private.ComponentLaunch")
  public:
    QVariant payload;
  public Q_SLOTS:
    QDBusVariant Read() const
    {
        return QDBusVariant(payload);
    }
};

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    qDBusRegisterMetaType<NativeLaunchFacts>();
    qDBusRegisterMetaType<LaunchList>();
    qDBusRegisterMetaType<WireJob>();
    qDBusRegisterMetaType<WireSuccess>();
    qDBusRegisterMetaType<WireUser>();
    qDBusRegisterMetaType<WireSeat>();
    QTemporaryDir directory;
    assert(directory.isValid());
    QDBusServer server(QStringLiteral("unix:path=") + directory.path() + QStringLiteral("/launch"));
    assert(server.isConnected());
    LaunchFixture fixture;
    std::optional<QDBusConnection> peer;
    QEventLoop accepted;
    QObject::connect(&server, &QDBusServer::newConnection, &application,
                     [&](QDBusConnection connection) {
                         assert(!peer);
                         assert(connection.registerObject(QStringLiteral("/Launch"), &fixture,
                                                          QDBusConnection::ExportAllSlots));
                         peer.emplace(connection);
                         accepted.quit();
                     });
    const QString connectionName = QStringLiteral("s17-component-launch-codec");
    const auto client = QDBusConnection::connectToPeer(server.address(), connectionName);
    assert(client.isConnected());
    QTimer deadline;
    deadline.setSingleShot(true);
    QObject::connect(&deadline, &QTimer::timeout, &accepted, &QEventLoop::quit);
    deadline.start(2000);
    if (!peer)
        accepted.exec();
    deadline.stop();
    assert(peer);
    const auto roundTrip = [&](const QVariant &payload) {
        fixture.payload = payload;
        auto request = QDBusMessage::createMethodCall(
            QString{}, QStringLiteral("/Launch"),
            QStringLiteral("org.linura.Private.ComponentLaunch"), QStringLiteral("Read"));
        QDBusPendingCallWatcher watcher(client.asyncCall(request, 1000));
        QEventLoop completion;
        QTimer timeout;
        timeout.setSingleShot(true);
        QObject::connect(&timeout, &QTimer::timeout, &completion, &QEventLoop::quit);
        QObject::connect(&watcher, &QDBusPendingCallWatcher::finished, &completion,
                         &QEventLoop::quit);
        timeout.start(2000);
        if (!watcher.isFinished())
            completion.exec();
        assert(watcher.isFinished());
        const QDBusReply<QDBusVariant> reply(watcher.reply());
        assert(reply.isValid());
        return reply.value().variant();
    };
    const QString image = QStringLiteral("/usr/lib/linura/linura-security-owner");
    NativeLaunchFacts valid{image, {image}, false, 1234, 5678, 0, 0, 2048, 0, 0};
    const auto wire = roundTrip(QVariant::fromValue(LaunchList{valid}));
    assert(wire.metaType() == QMetaType::fromType<QDBusArgument>());
    assert(wire.value<QDBusArgument>().currentSignature() == QStringLiteral("a(sasbttttuii)"));
    using Linura::SecurityOwner::exactNativeExecStart;
    assert(exactNativeExecStart(wire, image, {image}, 2048));
    assert(!exactNativeExecStart(wire, image, {image}, 2049));
    assert(
        !exactNativeExecStart(roundTrip(QVariant::fromValue(LaunchList{})), image, {image}, 2048));
    assert(!exactNativeExecStart(roundTrip(QVariant::fromValue(LaunchList{valid, valid})), image,
                                 {image}, 2048));
    valid.arguments.append(QStringLiteral("--load-user-ui"));
    assert(!exactNativeExecStart(roundTrip(QVariant::fromValue(LaunchList{valid})), image, {image},
                                 2048));
    valid.arguments.append(QStringLiteral("extra"));
    assert(!exactNativeExecStart(roundTrip(QVariant::fromValue(LaunchList{valid})), image, {image},
                                 2048));
    valid.arguments = {image, QString(129, QLatin1Char('x'))};
    assert(!exactNativeExecStart(roundTrip(QVariant::fromValue(LaunchList{valid})), image, {image},
                                 2048));
    valid.image = QString(129, QLatin1Char('x'));
    assert(!exactNativeExecStart(roundTrip(QVariant::fromValue(LaunchList{valid})), image, {image},
                                 2048));
    assert(!exactNativeExecStart(roundTrip(QVariant(image)), image, {image}, 2048));
    assert(!exactNativeExecStart(roundTrip(QVariant(QStringList{image})), image, {image}, 2048));

    const QDBusObjectPath userPath(QStringLiteral("/org/freedesktop/login1/user/_1000"));
    const QDBusObjectPath seatPath(QStringLiteral("/org/freedesktop/login1/seat/seat0"));
    const auto user = Linura::SecurityOwner::decodeNativeLogindUser(
        roundTrip(QVariant::fromValue(WireUser{1000, userPath})));
    const auto seat = Linura::SecurityOwner::decodeNativeLogindSeat(
        roundTrip(QVariant::fromValue(WireSeat{QStringLiteral("seat0"), seatPath})));
    assert(user && user->uid == 1000 &&
           user->path.path() == QStringLiteral("/org/freedesktop/login1/user/_1000"));
    assert(seat && seat->name == QStringLiteral("seat0") &&
           seat->path.path() == QStringLiteral("/org/freedesktop/login1/seat/seat0"));
    assert(!Linura::SecurityOwner::decodeNativeLogindUser(
        roundTrip(QVariant::fromValue(WireSeat{QStringLiteral("seat0"), seatPath}))));
    assert(!Linura::SecurityOwner::decodeNativeLogindSeat(
        roundTrip(QVariant::fromValue(WireUser{1000, userPath}))));

    // Official wire types exercise the private codec only, not native evidence.
    const QString helper = QStringLiteral("/usr/lib/linura/linura-executor-session");
    const QString sleep = QStringLiteral("/usr/lib/systemd/systemd-sleep");
    const QString invocation = QStringLiteral("98765432-1234-4567-89ab-0123456789ab");
    const auto emptyCommands = roundTrip(QVariant::fromValue(LaunchList{}));
    const auto job = [&](quint32 number, const QString &path) {
        return roundTrip(QVariant::fromValue(WireJob{number, QDBusObjectPath(path)}));
    };
    const auto success = [&](QList<qint32> codes, QList<qint32> signals) {
        return roundTrip(QVariant::fromValue(WireSuccess{codes, signals}));
    };
    const QVariantMap unit{
        {QStringLiteral("Id"), QStringLiteral("systemd-suspend.service")},
        {QStringLiteral("FragmentPath"),
         QStringLiteral("/usr/lib/systemd/system/systemd-suspend.service")},
        {QStringLiteral("InvocationID"), QUuid(invocation).toRfc4122()},
        {QStringLiteral("ActiveState"), QStringLiteral("activating")},
        {QStringLiteral("SubState"), QStringLiteral("start-pre")},
        {QStringLiteral("DropInPaths"),
         QStringList{QStringLiteral(
             "/usr/lib/systemd/system/systemd-suspend.service.d/50-linura-protective-lock.conf")}},
        {QStringLiteral("Job"), job(9, QStringLiteral("/org/freedesktop/systemd1/job/9"))}};
    const QVariantMap service{
        {QStringLiteral("Type"), QStringLiteral("oneshot")},
        {QStringLiteral("User"), QString{}},
        {QStringLiteral("Restart"), QStringLiteral("no")},
        {QStringLiteral("ControlPID"), quint32{42}},
        {QStringLiteral("MainPID"), quint32{0}},
        {QStringLiteral("ExecStartPre"), roundTrip(QVariant::fromValue(LaunchList{
                                             {helper,
                                              {helper, QStringLiteral("--protect-before-sleep")},
                                              false,
                                              100,
                                              200,
                                              0,
                                              0,
                                              42,
                                              0,
                                              0}}))},
        {QStringLiteral("ExecStart"),
         roundTrip(QVariant::fromValue(
             LaunchList{{sleep, {sleep, QStringLiteral("suspend")}, false, 0, 0, 0, 0, 0, 0, 0}}))},
        {QStringLiteral("ExecCondition"), emptyCommands},
        {QStringLiteral("ExecStartPost"), emptyCommands},
        {QStringLiteral("ExecStop"), emptyCommands},
        {QStringLiteral("ExecStopPost"), emptyCommands},
        {QStringLiteral("SuccessExitStatus"), success({}, {})}};
    const auto decode = [&](const QVariantMap &u, const QVariantMap &s) {
        return Linura::SecurityOwner::decodeNativeSleepUnitFacts(QStringLiteral(":1.2"), u, s);
    };
    const auto decoded = decode(unit, service);
    assert(decoded && decoded->invocation == invocation && decoded->job == 9 &&
           decoded->helper.pid == 42 && !decoded->absent);
    for (auto it = unit.cbegin(); it != unit.cend(); ++it) {
        auto missing = unit;
        missing.remove(it.key());
        assert(!decode(missing, service));
        auto malformed = unit;
        malformed[it.key()] = true;
        assert(!decode(malformed, service));
    }
    for (auto it = service.cbegin(); it != service.cend(); ++it) {
        auto missing = service;
        missing.remove(it.key());
        assert(!decode(unit, missing));
        auto malformed = service;
        malformed[it.key()] = true;
        assert(!decode(unit, malformed));
    }
    for (const auto &value : {job(9, QStringLiteral("/org/freedesktop/systemd1/job/10")),
                              job(0, QStringLiteral("/org/freedesktop/systemd1/job/9"))}) {
        auto malformed = unit;
        malformed[QStringLiteral("Job")] = value;
        assert(!decode(malformed, service));
    }
    for (const auto &value : {success({1}, {}), success({0, 0}, {}), success({}, {15})}) {
        auto malformed = service;
        malformed[QStringLiteral("SuccessExitStatus")] = value;
        assert(!decode(unit, malformed));
    }
    for (const char *key : {"ExecCondition", "ExecStartPost", "ExecStop", "ExecStopPost"}) {
        auto malformed = service;
        malformed[QLatin1String(key)] = service.value(QStringLiteral("ExecStartPre"));
        assert(!decode(unit, malformed));
    }
    for (bool unitSide : {false, true}) {
        auto oversizedUnit = unit;
        auto oversizedService = service;
        auto &values = unitSide ? oversizedUnit : oversizedService;
        for (int i = 0; i < 257; ++i)
            values[QString::number(i)] = false;
        assert(!decode(oversizedUnit, oversizedService));
    }
    QDBusConnection::disconnectFromPeer(connectionName);
    return 0;
}

#include "native_launch.moc"
