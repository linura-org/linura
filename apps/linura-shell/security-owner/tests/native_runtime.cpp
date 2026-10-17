// Startup/codec/metadata component checks, NOT deployed root/PAM qualification.
#include "native_endpoint.h"
#include "native_runtime.h"
#include "native_startup.h"
#include "native_unlock_status.h"

#include <QCoreApplication>
#include <QDBusMetaType>
#include <QDBusPendingCallWatcher>
#include <QDBusReply>
#include <QDBusServer>
#include <QDBusVariant>
#include <QEventLoop>
#include <QFile>
#include <QMetaClassInfo>
#include <QTemporaryDir>
#include <QTimer>
#include <QXmlStreamReader>
#include <cassert>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <thread>
#include <type_traits>
#include <vector>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace Linura::SecurityOwner;
static_assert(!std::is_default_constructible_v<NativeStartup>);
static_assert(!std::is_copy_constructible_v<NativeStartup>);
static_assert(!std::is_move_assignable_v<NativeStartup>);
static_assert(!std::is_default_constructible_v<NativeRuntime>);
static_assert(NativeCompositorReadinessContract::maximumWait == std::chrono::seconds(5));
static_assert(NativeCompositorReadinessContract::maximumRuntimeEntries == 256);
static_assert(NativeCompositorReadinessContract::maximumInstances == 64);
static_assert(NativeCompositorReadinessContract::maximumRoutes == 16);
static_assert(NativeCompositorReadinessContract::maximumEvents == 256);

// Private component peer only. Match Authority1's actual single-structure
// status shape rather than testing the recovery decoder with a local QVariant
// that Qt would never produce from a received D-Bus reply.
struct HistoricalStatus final
{
    QString request, transaction, resource;
    bool secure = false;
    QString state;
};
Q_DECLARE_METATYPE(HistoricalStatus)
QDBusArgument &operator<<(QDBusArgument &argument, const HistoricalStatus &status)
{
    argument.beginStructure();
    argument << status.request << status.transaction << status.resource << status.secure
             << status.state;
    argument.endStructure();
    return argument;
}
const QDBusArgument &operator>>(const QDBusArgument &argument, HistoricalStatus &status)
{
    argument.beginStructure();
    argument >> status.request >> status.transaction >> status.resource >> status.secure >>
        status.state;
    argument.endStructure();
    return argument;
}

struct TransitionHistoricalStatus final
{
    QString request, transaction, resource, state;
};
Q_DECLARE_METATYPE(TransitionHistoricalStatus)
QDBusArgument &operator<<(QDBusArgument &argument, const TransitionHistoricalStatus &status)
{
    argument.beginStructure();
    argument << status.request << status.transaction << status.resource << status.state;
    argument.endStructure();
    return argument;
}
const QDBusArgument &operator>>(const QDBusArgument &argument, TransitionHistoricalStatus &status)
{
    argument.beginStructure();
    argument >> status.request >> status.transaction >> status.resource >> status.state;
    argument.endStructure();
    return argument;
}

class RuntimeCodec final : public QObject
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.linura.Private.ComponentRuntime")
  public:
    QVariant payload;
    HistoricalStatus status;
    TransitionHistoricalStatus transitionStatus;
  public Q_SLOTS:
    QDBusVariant Read() const
    {
        return QDBusVariant(payload);
    }
    HistoricalStatus ReadStatus() const
    {
        return status;
    }
    TransitionHistoricalStatus ReadTransitionStatus() const
    {
        return transitionStatus;
    }
};

void ordinaryStartupCannotBeRepaired()
{
    for (bool lateProtection : {false, true}) {
        const pid_t child = fork();
        assert(child >= 0);
        if (child == 0) {
            if (lateProtection)
                assert(prctl(PR_SET_DUMPABLE, 0) == 0);
            assert(!NativeStartup::prepare());
            assert(!NativeStartup::prepare()); // No retry after partial startup.
            _exit(0);
        }
        int status = 0;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
               WEXITSTATUS(status) == 0);
    }
}

void historicalStatusCannotSubstituteUnlockAuthorityOrIdentity()
{
    const auto resource = QStringLiteral("session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:2:"
                                         "42:98765432-1234-4567-89ab-0123456789ab:1");
    const auto lock = NativeLockIdentity::parse(resource);
    assert(lock);
    const auto request = QStringLiteral("request:v010:session-lock:unlock-component");
    const auto transaction = QStringLiteral("transaction:v1:") + QString(64, QLatin1Char('a'));
    const auto check = [&](const QString &r, const QString &t, const QString &id, bool secure,
                           const QString &state) {
        return validateNativeUnlockStatus(r, t, id, secure, state, request, *lock);
    };
    assert(check(request, transaction, resource, false, QStringLiteral("committed")) ==
           NativeUnlockRecoveryStep::AcknowledgeCommitted);
    for (const auto &state : {"indeterminate", "verified"})
        assert(check(request, transaction, resource, false, QLatin1String(state)) ==
               NativeUnlockRecoveryStep::ObserveOnly);
    for (const auto &state : {"prepared", "aborted", "recovery-blocked"})
        assert(check(request, transaction, resource, false, QLatin1String(state)) ==
               NativeUnlockRecoveryStep::Stop);
    assert(!check(request, transaction, resource, true, QStringLiteral("committed")));
    assert(!check(request + QLatin1Char('x'), transaction, resource, false,
                  QStringLiteral("committed")));
    assert(!check(request, transaction + QLatin1Char('a'), resource, false,
                  QStringLiteral("committed")));
    assert(!check(request, transaction.toUpper(), resource, false, QStringLiteral("committed")));
    assert(!check(request, transaction, resource + QLatin1Char('1'), false,
                  QStringLiteral("committed")));
    assert(!check(request, transaction, resource, false, QStringLiteral("unknown")));
    assert(!decodeNativeUnlockStatus(QDBusMessage(), request, *lock));
}

void transitionStatusOnlySelectsObserveOrCommittedBookkeeping()
{
    const auto target = NativeTransitionIdentity::parse(
        QStringLiteral("session:transition:suspend:10:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:"
                       "42:98765432-1234-4567-89ab-0123456789ab:1"));
    assert(target);
    const auto request = QStringLiteral("request:v010:session-transition:shell-power-component");
    const auto transaction = QStringLiteral("transaction:v1:") + QString(64, QLatin1Char('a'));
    const auto check = [&](const QString &r, const QString &t, const QString &resource,
                           const QString &state) {
        return validateNativeTransitionStatus(r, t, resource, state, request, *target);
    };
    assert(check(request, transaction, target->resource, QStringLiteral("committed")) ==
           NativeTransitionRecoveryStep::AcknowledgeCommitted);
    for (const auto *state : {"indeterminate", "verified"})
        assert(check(request, transaction, target->resource, QLatin1String(state)) ==
               NativeTransitionRecoveryStep::ObserveOnly);
    for (const auto *state : {"prepared", "aborted", "recovery-blocked"})
        assert(check(request, transaction, target->resource, QLatin1String(state)) ==
               NativeTransitionRecoveryStep::Stop);
    assert(!check(request + QLatin1Char('x'), transaction, target->resource,
                  QStringLiteral("committed")));
    assert(!check(request, transaction.toUpper(), target->resource, QStringLiteral("committed")));
    assert(!check(request, transaction,
                  QString(target->resource).replace("suspend:10:", "suspend:11:"),
                  QStringLiteral("committed")));
    assert(!check(request, transaction,
                  QString(target->resource).replace("suspend:10:", "logout:0:"),
                  QStringLiteral("committed")));
    assert(!check(request, transaction, target->resource, QStringLiteral("future-state")));
    assert(!decodeNativeTransitionStatus(QDBusMessage(), request, *target));
    for (const auto &badRequest :
         {QStringLiteral("request:v010:session-transition:"),
          QStringLiteral("request:v010:session-transition:Bad--Slug"),
          QStringLiteral("request:v010:session-lock:shell-power-component"),
          QStringLiteral("request:v010:session-transition:") + QString(65, QLatin1Char('a'))})
        assert(!validateNativeTransitionStatus(badRequest, transaction, target->resource,
                                               QStringLiteral("committed"), badRequest, *target));
}

void boundedRouteDiscoveryCannotAssertNativeSessionIdentity()
{
    assert(getuid() != 0);
    QTemporaryDir directory;
    assert(directory.isValid());
    struct Sockets final
    {
        std::vector<int> descriptors;
        ~Sockets()
        {
            for (const int descriptor : descriptors)
                close(descriptor);
        }
        void add(const QString &path)
        {
            const auto bytes = path.toLocal8Bit();
            sockaddr_un address{};
            address.sun_family = AF_UNIX;
            assert(bytes.size() > 0 &&
                   static_cast<std::size_t>(bytes.size()) < sizeof(address.sun_path));
            std::memcpy(address.sun_path, bytes.constData(),
                        static_cast<std::size_t>(bytes.size()) + 1);
            const int descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
            assert(descriptor >= 0 && bind(descriptor, reinterpret_cast<const sockaddr *>(&address),
                                           sizeof(address)) == 0);
            descriptors.push_back(descriptor);
        }
    } sockets;
    const auto wayland = directory.path() + QStringLiteral("/wayland-1");
    const auto instance = directory.path() + QStringLiteral("/hypr/abc_123");
    assert(QDir().mkpath(instance));
    sockets.add(wayland);
    sockets.add(instance + QStringLiteral("/.socket.sock"));
    const auto routes = discoverNativeSocketRoutes(directory.path(), getuid());
    assert(routes && routes->wayland == QStringList{wayland} &&
           routes->compositor == QStringList{instance + QStringLiteral("/.socket.sock")});
    // Candidate discovery never constructs a NativeStartup token, binds a
    // session or emits any Wayland opcode. Every actual peer is attested later.
    assert(QFile::link(wayland, directory.path() + QStringLiteral("/wayland-symlink")));
    assert(discoverNativeSocketRoutes(directory.path(), getuid())->wayland.size() == 1);
    assert(!discoverNativeSocketRoutes(directory.path(), 0));
    assert(!discoverNativeSocketRoutes(directory.path(), getuid() + 1));
    assert(!discoverNativeSocketRoutes(directory.path() + QStringLiteral("/../alias"), getuid()));
    assert(chmod(directory.path().toLocal8Bit().constData(), 0755) == 0);
    assert(!discoverNativeSocketRoutes(directory.path(), getuid()));
    assert(chmod(directory.path().toLocal8Bit().constData(), 0700) == 0);
    for (unsigned index = 2; index <= 17; ++index)
        sockets.add(directory.path() + QStringLiteral("/wayland-") + QString::number(index));
    assert(!discoverNativeSocketRoutes(
        directory.path(), getuid())); // Candidate overflow, never truncation/first-wins.
}

void eventDrivenRouteReadinessPreservesCompleteStrictDiscovery()
{
    using namespace std::chrono_literals;
    assert(getuid() != 0);
    QTemporaryDir directory;
    assert(directory.isValid());
    const auto bindSocket = [](const QString &path) {
        const auto bytes = path.toLocal8Bit();
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        assert(bytes.size() > 0 &&
               static_cast<std::size_t>(bytes.size()) < sizeof(address.sun_path));
        std::memcpy(address.sun_path, bytes.constData(),
                    static_cast<std::size_t>(bytes.size()) + 1);
        const int descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        assert(descriptor >= 0 && bind(descriptor, reinterpret_cast<const sockaddr *>(&address),
                                       sizeof(address)) == 0);
        return descriptor;
    };
    const auto wayland = directory.path() + QStringLiteral("/wayland-1");
    const int waylandDescriptor = bindSocket(wayland);
    const auto instance = directory.path() + QStringLiteral("/hypr/abc_123");
    const auto compositor = instance + QStringLiteral("/.socket.sock");
    int compositorDescriptor = -1;
    std::thread publisher([&] {
        std::this_thread::sleep_for(50ms);
        assert(QDir().mkpath(instance));
        compositorDescriptor = bindSocket(compositor);
    });
    const auto routes = waitForNativeSocketRoutes(directory.path(), getuid(), 500ms);
    publisher.join();
    assert(routes && routes->wayland == QStringList{wayland} &&
           routes->compositor == QStringList{compositor});
    assert(close(waylandDescriptor) == 0);
    assert(compositorDescriptor >= 0 && close(compositorDescriptor) == 0);

    QTemporaryDir incomplete;
    assert(incomplete.isValid());
    const int incompleteDescriptor = bindSocket(incomplete.path() + QStringLiteral("/wayland-1"));
    std::thread invalidPublisher([&] {
        std::this_thread::sleep_for(10ms);
        const auto invalidInstance = incomplete.path() + QStringLiteral("/hypr/noise_123");
        assert(QDir().mkpath(invalidInstance));
        QFile invalidSocket(invalidInstance + QStringLiteral("/.socket.sock"));
        assert(invalidSocket.open(QIODevice::WriteOnly));
        invalidSocket.close(); // An event and matching name are never readiness.
    });
    const auto started = std::chrono::steady_clock::now();
    assert(!waitForNativeSocketRoutes(incomplete.path(), getuid(), 40ms));
    invalidPublisher.join();
    assert(std::chrono::steady_clock::now() - started < 500ms);
    assert(!waitForNativeSocketRoutes(incomplete.path(), getuid(), 0ms));
    assert(!waitForNativeSocketRoutes(incomplete.path(), getuid(), 5001ms));
    assert(close(incompleteDescriptor) == 0);
}

QStringList contractShape(const QString &text)
{
    QXmlStreamReader xml(text);
    QStringList shape;
    while (!xml.atEnd()) {
        xml.readNext();
        if (xml.isStartElement()) {
            const auto tag = xml.name().toString();
            const auto attributes = xml.attributes();
            if (tag == QLatin1String("interface") || tag == QLatin1String("method") ||
                tag == QLatin1String("signal"))
                shape.append(tag + QLatin1Char(':') +
                             attributes.value(QStringLiteral("name")).toString());
            else if (tag == QLatin1String("annotation"))
                shape.append(
                    tag + QLatin1Char(':') + attributes.value(QStringLiteral("name")).toString() +
                    QLatin1Char('=') + attributes.value(QStringLiteral("value")).toString());
            else if (tag == QLatin1String("arg"))
                shape.append(
                    tag + QLatin1Char(':') + attributes.value(QStringLiteral("name")).toString() +
                    QLatin1Char(':') + attributes.value(QStringLiteral("type")).toString() +
                    QLatin1Char(':') + attributes.value(QStringLiteral("direction")).toString());
            else
                assert(tag == QLatin1String("node"));
        } else if (xml.isEndElement() &&
                   (xml.name() == QLatin1String("method") || xml.name() == QLatin1String("signal")))
            shape.append(QStringLiteral("end:") + xml.name().toString());
    }
    assert(!xml.hasError());
    return shape;
}

int main(int argc, char **argv)
{
    assert(argc == 3);
    ordinaryStartupCannotBeRepaired(); // Before Qt exists, on ordinary exec.
    const pid_t entry = fork();
    assert(entry >= 0);
    if (entry == 0) {
        assert(setenv("QT_QPA_PLATFORM", "s17-must-not-load-before-protection", 1) == 0);
        execl(argv[2], argv[2], static_cast<char *>(nullptr));
        _exit(81);
    }
    int status = 0;
    assert(waitpid(entry, &status, 0) == entry && WIFEXITED(status) && WEXITSTATUS(status) == 78);
    QCoreApplication application(argc, argv);
    boundedRouteDiscoveryCannotAssertNativeSessionIdentity();
    eventDrivenRouteReadinessPreservesCompleteStrictDiscovery();
    historicalStatusCannotSubstituteUnlockAuthorityOrIdentity();
    transitionStatusOnlySelectsObserveOrCommittedBookkeeping();
    assert(!NativeStartup::prepare()); // Qt-first startup cannot create the token.
    for (const char *method : {"armApproval()", "consumeApproval()", "dispatchPrepared()",
                               "verifyReleased()", "commitVerifiedRelease()",
                               "observePowerPermission()", "exportNativeEndpoint()", "identity()"})
        assert(NativeRuntime::staticMetaObject.indexOfMethod(method) == -1);

    const int index = NativeEndpoint::staticMetaObject.indexOfClassInfo("D-Bus Introspection");
    assert(index >= 0);
    const QString introspection =
        QString::fromUtf8(NativeEndpoint::staticMetaObject.classInfo(index).value());
    QFile contract(QString::fromLocal8Bit(argv[1]));
    assert(contract.open(QIODevice::ReadOnly) && contract.size() > 0 &&
           contract.size() <= 64 * 1024);
    assert(contractShape(QString::fromUtf8(contract.readAll())) == contractShape(introspection));
    QXmlStreamReader xml(introspection);
    unsigned methods = 0, signals = 0, annotations = 0;
    while (!xml.atEnd()) {
        xml.readNext();
        if (!xml.isStartElement())
            continue;
        if (xml.name() == QLatin1String("method"))
            methods++;
        if (xml.name() == QLatin1String("signal"))
            signals++;
        if (xml.name() == QLatin1String("annotation"))
            annotations++;
    }
    assert(!xml.hasError() && methods == 12 && signals == 1 && annotations == 3);
    assert(introspection.contains(QStringLiteral("(sssssssu)")) &&
           introspection.contains(QStringLiteral("(sbt)")));
    NativeEndpoint::registerWireTypes();
    qDBusRegisterMetaType<HistoricalStatus>();
    qDBusRegisterMetaType<TransitionHistoricalStatus>();
    assert(QByteArray(QDBusMetaType::typeToSignature(QMetaType::fromType<NativeApprovalWire>())) ==
           "(sssssssu)");
    assert(QByteArray(QDBusMetaType::typeToSignature(
               QMetaType::fromType<NativeLockObservationWire>())) == "(sbt)");
    assert(QByteArray(QDBusMetaType::typeToSignature(
               QMetaType::fromType<NativePowerPermissionWire>())) == "(sst)");
    NativeApprovalWire scope{QStringLiteral("session:lock:abcd1234-1234-4567-89ab-0123456789ab:"
                                            "1000:2:42:98765432-1234-4567-89ab-0123456789ab:1"),
                             QStringLiteral("unix:uid:1000"),
                             QStringLiteral("request:v010:session-lock:runtime-component"),
                             QStringLiteral("request:v010:session-lock:runtime-component"),
                             QStringLiteral("sha256:") + QString(64, QLatin1Char('1')),
                             QStringLiteral("sha256:") + QString(64, QLatin1Char('2')),
                             QStringLiteral("sha256:") + QString(64, QLatin1Char('3')),
                             0};
    assert(scope.scope());
    auto substituted = scope;
    substituted.purpose = 2;
    assert(!substituted.scope());
    substituted = scope;
    substituted.principal = QStringLiteral("unix:uid:0");
    assert(!substituted.scope());
    substituted = scope;
    substituted.requestDigest += QLatin1Char('0');
    assert(!substituted.scope());
    substituted = scope;
    substituted.plan += QLatin1Char('x');
    assert(!substituted.scope());
    substituted = scope;
    substituted.resource += QStringLiteral(":1");
    assert(!substituted.scope());

    QTemporaryDir directory;
    assert(directory.isValid());
    QDBusServer server(QStringLiteral("unix:path=") + directory.path() +
                       QStringLiteral("/runtime"));
    assert(server.isConnected());
    RuntimeCodec fixture;
    std::optional<QDBusConnection> peer;
    QEventLoop accepted;
    QObject::connect(
        &server, &QDBusServer::newConnection, &application, [&](QDBusConnection connection) {
            assert(!peer && connection.registerObject(QStringLiteral("/Runtime"), &fixture,
                                                      QDBusConnection::ExportAllSlots));
            peer.emplace(connection);
            accepted.quit();
        });
    const QString connectionName = QStringLiteral("s17-component-runtime-codec");
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
    const auto call = [&](const QString &method) {
        auto request = QDBusMessage::createMethodCall(
            QString{}, QStringLiteral("/Runtime"),
            QStringLiteral("org.linura.Private.ComponentRuntime"), method);
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
        const QDBusReply<QDBusVariant> reply(call(QStringLiteral("Read")));
        assert(reply.isValid());
        return reply.value().variant();
    };
    const auto approved = qdbus_cast<NativeApprovalWire>(roundTrip(QVariant::fromValue(scope)));
    assert(approved.scope() == scope.scope());
    const auto unknownPurpose =
        qdbus_cast<NativeApprovalWire>(roundTrip(QVariant::fromValue(substituted)));
    assert(!unknownPurpose.scope());
    NativeLockObservationWire observed{scope.resource, true, 12345};
    const auto decoded =
        qdbus_cast<NativeLockObservationWire>(roundTrip(QVariant::fromValue(observed)));
    assert(decoded.resource == observed.resource && decoded.secure &&
           decoded.sampledBootMs == 12345);
    assert(decoded.freshAtBootMs(12345));
    assert(decoded.freshAtBootMs(14344));
    assert(!decoded.freshAtBootMs(14345)); // Exclusive, including suspended time.
    assert(!decoded.freshAtBootMs(12344)); // Rollback/future sample is not current.
    auto invalid = decoded;
    invalid.sampledBootMs = 0;
    assert(!invalid.freshAtBootMs(1));
    invalid = decoded;
    invalid.resource = QStringLiteral("session:lock:unsupported");
    assert(!invalid.freshAtBootMs(12345));

    const auto suffix = scope.resource.mid(qsizetype(sizeof("session:lock:") - 1));
    for (const auto &action : {"suspend", "reboot", "power-off", "logout"}) {
        const auto resource = QStringLiteral("session:transition:") + QLatin1String(action) +
                              QStringLiteral(":0:") + suffix;
        const auto transition = NativeTransitionIdentity::parse(resource);
        assert(transition && transition->lock.resource == scope.resource);
        assert(bool(transition->powerPermissionAction()) ==
               (QLatin1String(action) != QLatin1String("logout")));
        for (const auto &availability : {"yes", "no", "challenge"}) {
            NativePowerPermissionWire permission{resource, QLatin1String(availability), 12345};
            const auto wire =
                qdbus_cast<NativePowerPermissionWire>(roundTrip(QVariant::fromValue(permission)));
            assert(wire.resource == resource && wire.availability == QLatin1String(availability) &&
                   wire.sampledBootMs == 12345);
            assert(wire.freshAtBootMs(14344) == (QLatin1String(action) != QLatin1String("logout")));
            assert(!wire.freshAtBootMs(14345));
            assert(!wire.freshAtBootMs(12344));
            permission.availability = QStringLiteral("allow");
            assert(!permission.freshAtBootMs(12345));
        }
    }
    for (const auto &prefix :
         {"session:transition:hibernate:0:", "session:transition:reboot:1:",
          "session:transition:suspend:00:", "session:transition:suspend:18446744073709551615:",
          "session:transition:suspend:18446744073709551616:"})
        assert(!NativeTransitionIdentity::parse(QLatin1String(prefix) + suffix));
    assert(
        NativeTransitionIdentity::parse(QStringLiteral("session:transition:suspend:42:") + suffix)
            ->successfulCyclesBefore == 42);

    const auto lock = NativeLockIdentity::parse(scope.resource);
    assert(lock);
    fixture.status = {scope.request,
                      QStringLiteral("transaction:v1:") + QString(64, QLatin1Char('a')),
                      scope.resource, false, QStringLiteral("committed")};
    auto statusReply = call(QStringLiteral("ReadStatus"));
    assert(statusReply.signature() == QLatin1String("(sssbs)"));
    assert(decodeNativeUnlockStatus(statusReply, scope.request, *lock) ==
           NativeUnlockRecoveryStep::AcknowledgeCommitted);
    fixture.status.state = QStringLiteral("indeterminate");
    assert(decodeNativeUnlockStatus(call(QStringLiteral("ReadStatus")), scope.request, *lock) ==
           NativeUnlockRecoveryStep::ObserveOnly);
    fixture.status.state = QStringLiteral("prepared");
    assert(decodeNativeUnlockStatus(call(QStringLiteral("ReadStatus")), scope.request, *lock) ==
           NativeUnlockRecoveryStep::Stop);
    fixture.status.state = QStringLiteral("committed");
    fixture.status.secure = true;
    assert(!decodeNativeUnlockStatus(call(QStringLiteral("ReadStatus")), scope.request, *lock));
    fixture.status.secure = false;
    fixture.status.resource += QStringLiteral(":1");
    assert(!decodeNativeUnlockStatus(call(QStringLiteral("ReadStatus")), scope.request, *lock));
    assert(!decodeNativeUnlockStatus(call(QStringLiteral("Read")), scope.request,
                                     *lock)); // Variant is not the contract.
    const auto target =
        NativeTransitionIdentity::parse(QStringLiteral("session:transition:suspend:10:") + suffix);
    assert(target);
    const auto transitionRequest =
        QStringLiteral("request:v010:session-transition:runtime-component");
    fixture.transitionStatus = {transitionRequest,
                                QStringLiteral("transaction:v1:") + QString(64, QLatin1Char('b')),
                                target->resource, QStringLiteral("committed")};
    const auto powerStatus = call(QStringLiteral("ReadTransitionStatus"));
    assert(powerStatus.signature() == QLatin1String("(ssss)"));
    assert(decodeNativeTransitionStatus(powerStatus, transitionRequest, *target) ==
           NativeTransitionRecoveryStep::AcknowledgeCommitted);
    fixture.transitionStatus.state = QStringLiteral("indeterminate");
    assert(decodeNativeTransitionStatus(call(QStringLiteral("ReadTransitionStatus")),
                                        transitionRequest,
                                        *target) == NativeTransitionRecoveryStep::ObserveOnly);
    fixture.transitionStatus.state = QStringLiteral("prepared");
    assert(decodeNativeTransitionStatus(call(QStringLiteral("ReadTransitionStatus")),
                                        transitionRequest,
                                        *target) == NativeTransitionRecoveryStep::Stop);
    fixture.transitionStatus.resource =
        QString(target->resource).replace("suspend:10:", "suspend:11:");
    assert(!decodeNativeTransitionStatus(call(QStringLiteral("ReadTransitionStatus")),
                                         transitionRequest, *target));
    assert(!decodeNativeTransitionStatus(call(QStringLiteral("ReadStatus")), transitionRequest,
                                         *target));
    assert(!decodeNativeTransitionStatus(call(QStringLiteral("Read")), transitionRequest, *target));
    QDBusConnection::disconnectFromPeer(connectionName);
}

#include "native_runtime.moc"
