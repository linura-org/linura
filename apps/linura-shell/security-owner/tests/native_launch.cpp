#include "native_launch.h"
#include "native_sleep_probe.h"
#include "session_bootstrap.h"
#include "native_property.h"

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
#include <QDBusVirtualObject>
#include <QEventLoop>
#include <QTemporaryDir>
#include <QTemporaryFile>
#include <QTimer>
#include <QUuid>

#include <cassert>
#include <optional>
#include <unistd.h>

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

class PropertyFixture final : public QDBusVirtualObject
{
  public:
    QVariantMap fields;
    unsigned reads = 0, enumerations = 0;
    bool malformed = false;
    QString introspect(const QString &) const override
    {
        return {};
    }
    bool handleMessage(const QDBusMessage &request, const QDBusConnection &connection) override
    {
        if (request.interface() != QLatin1String("org.freedesktop.DBus.Properties"))
            return false;
        if (request.member() == QLatin1String("GetAll")) {
            ++enumerations;
            return connection.send(request.createReply(QList<QVariant>{fields}));
        }
        if (request.member() != QLatin1String("Get") || request.arguments().size() != 2)
            return false;
        ++reads;
        const auto name = request.arguments()[1].toString();
        if (!fields.contains(name))
            return connection.send(request.createErrorReply(
                QStringLiteral("org.freedesktop.DBus.Error.UnknownProperty"), QString{}));
        return connection.send(request.createReply(
            QList<QVariant>{malformed ? QVariant(QStringLiteral("invalid-reply"))
                                      : QVariant::fromValue(QDBusVariant(fields.value(name)))}));
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
    PropertyFixture properties;
    std::optional<QDBusConnection> peer;
    QEventLoop accepted;
    QObject::connect(
        &server, &QDBusServer::newConnection, &application, [&](QDBusConnection connection) {
            assert(!peer);
            assert(connection.registerObject(QStringLiteral("/Launch"), &fixture,
                                             QDBusConnection::ExportAllSlots));
            assert(connection.registerVirtualObject(QStringLiteral("/Properties"), &properties));
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
    const auto exchange = [&](const QDBusMessage &request) {
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
        return watcher.reply();
    };
    const auto roundTrip = [&](const QVariant &payload) {
        fixture.payload = payload;
        auto request = QDBusMessage::createMethodCall(
            QString{}, QStringLiteral("/Launch"),
            QStringLiteral("org.linura.Private.ComponentLaunch"), QStringLiteral("Read"));
        const QDBusReply<QDBusVariant> reply(exchange(request));
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

    // Real Polkit 127 systemd ExecStart is a three-word, exactly bound
    // launch. Exercise its actual D-Bus encoding, including extra-word denial.
    const QString polkitImage = QStringLiteral("/usr/lib/polkit-1/polkitd");
    QStringList polkitArgs{polkitImage};
    polkitArgs.append(QStringLiteral("--no-debug"));
    polkitArgs.append(QStringLiteral("--log-level=notice"));
    NativeLaunchFacts polkit;
    polkit.image = polkitImage;
    polkit.arguments = polkitArgs;
    polkit.ignoreFailure = false;
    polkit.startedReal = 1234;
    polkit.startedMonotonic = 5678;
    polkit.pid = 2048;
    polkit.code = 0;
    polkit.status = 0;
    const auto polkitWire = roundTrip(QVariant::fromValue(LaunchList{polkit}));
    assert(exactNativeExecStart(polkitWire, polkitImage, polkitArgs, 2048));
    QStringList missingFlag{polkitImage};
    missingFlag.append(QStringLiteral("--no-debug"));
    assert(!exactNativeExecStart(polkitWire, polkitImage, missingFlag, 2048));
    assert(!exactNativeExecStart(polkitWire, polkitImage, polkitArgs, 2049));
    auto excessive = polkit;
    excessive.arguments.append(QStringLiteral("--replace"));
    const auto excessiveWire = roundTrip(QVariant::fromValue(LaunchList{excessive}));
    assert(!exactNativeExecStart(excessiveWire, polkitImage, polkitArgs, 2048));

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

    // Reproduce the real systemd Service interface width. Required properties
    // must remain readable regardless of unrelated property count; malformed
    // replies and missing properties still deny. This uses the same production
    // request/variant mechanism over an actual Qt D-Bus wire connection.
    for (unsigned index = 0; index < 362; ++index)
        properties.fields[QStringLiteral("Unrelated%1").arg(index)] = false;
    properties.fields[QStringLiteral("MainPID")] = quint32{2048};
    properties.fields[QStringLiteral("User")] = QVariant::fromValue(WireUser{1000, userPath});
    const auto boundedCall = [&](const QString &owner, const QString &path,
                                 const QString &interface, const QString &method,
                                 const QList<QVariant> &arguments) {
        auto request = QDBusMessage::createMethodCall(owner, path, interface, method);
        request.setArguments(arguments);
        return exchange(request);
    };
    const auto readProperty = [&](const QString &name) {
        return Linura::SecurityOwner::readNativeDBusProperty(
            boundedCall, QString{}, QStringLiteral("/Properties"),
            QStringLiteral("org.freedesktop.systemd1.Service"), name);
    };
    const QDBusReply<QVariantMap> broad(boundedCall(
        QString{}, QStringLiteral("/Properties"), QStringLiteral("org.freedesktop.DBus.Properties"),
        QStringLiteral("GetAll"), {QStringLiteral("org.freedesktop.systemd1.Service")}));
    assert(broad.isValid() && broad.value().size() == 364 && broad.value().size() > 128);
    assert(broad.value().value(QStringLiteral("MainPID")).metaType() ==
           QMetaType::fromType<quint32>());
    const unsigned enumerationsBeforeReads = properties.enumerations;
    const auto pid = readProperty(QStringLiteral("MainPID"));
    assert(pid && pid->metaType() == QMetaType::fromType<quint32>() && pid->toUInt() == 2048);
    properties.fields[QStringLiteral("MainPID")] = quint32{4096};
    assert(readProperty(QStringLiteral("MainPID"))->toUInt() == 4096); // Fresh, never cached.
    const auto structured = readProperty(QStringLiteral("User"));
    assert(structured && Linura::SecurityOwner::decodeNativeLogindUser(*structured)->uid == 1000);
    assert(!readProperty(QStringLiteral("Missing")));
    properties.malformed = true;
    assert(!readProperty(QStringLiteral("MainPID")));
    assert(properties.reads == 5 && properties.enumerations == enumerationsBeforeReads);

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
    // Actual codec failure output is closed even when native fields contain
    // private text. Enabling diagnostics cannot change acceptance or authority.
    for (bool diagnostics : {false, true}) {
        QTemporaryFile output;
        assert(output.open());
        const int saved = dup(STDERR_FILENO);
        assert(saved >= 0 && dup2(output.handle(), STDERR_FILENO) >= 0);
        auto privateUnit = unit;
        privateUnit[QStringLiteral("FragmentPath")] = QStringLiteral("private-wire-marker");
        const auto refused = Linura::SecurityOwner::decodeNativeSleepUnitFacts(
            QStringLiteral(":1.2"), privateUnit, service, diagnostics);
        assert(dup2(saved, STDERR_FILENO) >= 0);
        close(saved);
        assert(!refused && output.seek(0));
        const auto text = output.readAll();
        assert(text == (diagnostics
                            ? QByteArrayLiteral("native-sleep-owner-denied reason=codec-fields\n")
                            : QByteArray{}));
        assert(!text.contains("private-wire-marker"));
        assert(Linura::SecurityOwner::decodeNativeSleepUnitFacts(QStringLiteral(":1.2"), unit,
                                                                 service, diagnostics) == decoded);
    }
    for (bool diagnostics : {false, true}) {
        QTemporaryFile output;
        assert(output.open());
        const int saved = dup(STDERR_FILENO);
        assert(saved >= 0 && dup2(output.handle(), STDERR_FILENO) >= 0);
        const auto error =
            QDBusMessage::createError(QStringLiteral("org.freedesktop.DBus.Error.NoReply"),
                                      QStringLiteral("private-wire-marker"));
        const bool accepted = Linura::SecurityOwner::nativeSleepUnitLookupReply(
            error, QStringLiteral(":1.2"), diagnostics);
        assert(dup2(saved, STDERR_FILENO) >= 0);
        close(saved);
        assert(!accepted && output.seek(0));
        const auto text = output.readAll();
        assert(text == (diagnostics
                            ? QByteArrayLiteral("native-sleep-owner-denied reason=lookup-timeout\n")
                            : QByteArray{}));
        assert(!text.contains("private-wire-marker"));
    }
    // A matching string on an outgoing call is not a received native reply.
    const auto outgoing = QDBusMessage::createMethodCall(
        QStringLiteral(":1.2"), QStringLiteral("/"), QStringLiteral("org.linura.Private.Component"),
        QStringLiteral("GetUnit"));
    assert(!Linura::SecurityOwner::nativeSleepUnitLookupReply(outgoing, QStringLiteral(":1.2")));
    assert(
        !Linura::SecurityOwner::nativeSleepUnitLookupReply(QDBusMessage{}, QStringLiteral(":1.2")));
    for (const auto &name : {QStringLiteral("org.freedesktop.DBus.Error.AccessDenied"),
                             QStringLiteral("org.freedesktop.DBus.Error.ServiceUnknown"),
                             QStringLiteral("org.freedesktop.DBus.Error.Disconnected"),
                             QStringLiteral("org.freedesktop.DBus.Error.InvalidArgs"),
                             QStringLiteral("org.linura.Private.NativeUnavailable"),
                             QStringLiteral("org.freedesktop.systemd1.NoSuchUnit.extra")})
        assert(!Linura::SecurityOwner::nativeSleepUnitLookupReply(
            QDBusMessage::createError(name, QStringLiteral("private-wire-marker")),
            QStringLiteral(":1.2")));
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
