#include "peer_guard.h"
#include "native_deadline.h"
#include "native_launch.h"
#include "native_property.h"

#include <QDBusArgument>
#include <QDBusObjectPath>
#include <QDBusReply>
#include <QDBusVariant>
#include <QFile>
#include <QStringList>
#include <QUuid>

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <limits>
#include <utility>

namespace Linura::SecurityOwner {
namespace {

// A peer snapshot includes the bus identity, systemd unit, immutable image and
// a complete fresh revalidation. Read only the required properties: systemd's
// Service interface also includes hundreds of unrelated execution settings.
constexpr qint64 ProbeBudgetMs = 2'000;
constexpr int CallBudgetMs = 500;

struct Route final
{
    const char *service;
    const char *unit;
    const char *fragment;
    const char *image;
};

Route route(NativePeerPurpose purpose)
{
    switch (purpose) {
    case NativePeerPurpose::ControlApproval:
        return {"org.linura.Authority1", "linura-authorityd.service",
                "/usr/lib/systemd/system/linura-authorityd.service",
                "/usr/lib/linura/linura-authorityd"};
    case NativePeerPurpose::PreparedSessionDispatch:
        return {"org.linura.Executor.Session1", "linura-executor-session.service",
                "/usr/lib/systemd/system/linura-executor-session.service",
                "/usr/lib/linura/linura-executor-session"};
    case NativePeerPurpose::NativeAuthenticationDaemon:
        return {"org.freedesktop.PolicyKit1", "polkit.service",
                "/usr/lib/systemd/system/polkit.service", "/usr/lib/polkit-1/polkitd"};
    }
    return {};
}

bool uniqueOwner(const QString &text)
{
    if (text.size() < 4 || text.size() > 128 || !text.startsWith(QLatin1Char(':')))
        return false;
    bool digit = false, dot = false;
    for (QChar character : QStringView(text).mid(1)) {
        if (character == QLatin1Char('.')) {
            if (!digit)
                return false;
            dot = true;
            digit = false;
        } else if (character >= QLatin1Char('0') && character <= QLatin1Char('9')) {
            digit = true;
        } else {
            return false;
        }
    }
    return dot && digit;
}

bool immutable(const char *path, bool executable)
{
    struct stat metadata
    {};
    if (lstat(path, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_uid != 0 ||
        metadata.st_nlink != 1 || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        return false;
    if (executable && (metadata.st_mode & S_IXUSR) == 0)
        return false;
    // Parent namespaces must not be replaceable through an untrusted user.
    const QStringList parents =
        executable ? QStringList{QStringLiteral("/usr"), QStringLiteral("/usr/lib"),
                                 QString::fromUtf8(path).left(
                                     QString::fromUtf8(path).lastIndexOf(QLatin1Char('/')))}
                   : QStringList{QStringLiteral("/usr"), QStringLiteral("/usr/lib"),
                                 QStringLiteral("/usr/lib/systemd"),
                                 QStringLiteral("/usr/lib/systemd/system")};
    for (const auto &parent : parents) {
        const QByteArray bytes = parent.toUtf8();
        if (lstat(bytes.constData(), &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
            metadata.st_uid != 0 || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0)
            return false;
    }
    return true;
}

bool exactExecStart(NativePeerPurpose purpose, quint32 expectedPid, const QVariant &value)
{
    const auto selected = route(purpose);
    if (!selected.image)
        return false;
    const auto expectedArgv =
        purpose == NativePeerPurpose::NativeAuthenticationDaemon
            ? QStringList{QLatin1String(selected.image), QStringLiteral("--no-debug"),
                          QStringLiteral("--log-level=notice")}
            : QStringList{QLatin1String(selected.image)};
    return exactNativeExecStart(value, QLatin1String(selected.image), expectedArgv, expectedPid);
}

std::optional<quint32> localServiceUid(NativePeerPurpose purpose)
{
    // The packaged sysusers account is local. Bounded local lookup avoids an
    // NSS/network backend selecting identity or stalling a native authority call.
    struct stat metadata
    {};
    if (lstat("/etc/passwd", &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != 0 || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        metadata.st_size < 0 || metadata.st_size > 256 * 1024)
        return std::nullopt;
    QFile file(QStringLiteral("/etc/passwd"));
    if (!file.open(QIODevice::ReadOnly))
        return std::nullopt;
    const QByteArray contents = file.read(256 * 1024 + 1);
    if (contents.size() > 256 * 1024)
        return std::nullopt;
    std::optional<quint32> result;
    const QByteArray prefix = purpose == NativePeerPurpose::NativeAuthenticationDaemon
                                  ? QByteArrayLiteral("polkitd:")
                                  : QByteArrayLiteral("linura-authority:");
    for (const auto &line : contents.split('\n')) {
        if (!line.startsWith(prefix))
            continue;
        if (result)
            return std::nullopt;
        const auto fields = line.split(':');
        if (fields.size() != 7)
            return std::nullopt;
        bool ok = false;
        const quint64 uid = fields[2].toULongLong(&ok);
        if (!ok || uid == 0 || uid > std::numeric_limits<quint32>::max() ||
            QByteArray::number(uid) != fields[2])
            return std::nullopt;
        result = static_cast<quint32>(uid);
    }
    return result;
}

bool trustedSystemBusSocket()
{
    // Verify the actual kernel peer before Qt authentication. The canonical
    // socket's entire parent namespace is root-controlled, so an untrusted
    // caller cannot replace it between this probe and Qt's fixed connection.
    struct stat metadata
    {};
    for (const char *path : {"/run", "/run/dbus"}) {
        if (lstat(path, &metadata) != 0 || !S_ISDIR(metadata.st_mode) || metadata.st_uid != 0 ||
            (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0)
            return false;
    }
    if (lstat("/run/dbus/system_bus_socket", &metadata) != 0 || !S_ISSOCK(metadata.st_mode) ||
        metadata.st_uid != 0)
        return false;
    const int descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (descriptor < 0)
        return false;
    struct Close final
    {
        int descriptor;
        ~Close()
        {
            close(descriptor);
        }
    } cleanup{descriptor};
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    constexpr char path[] = "/run/dbus/system_bus_socket";
    std::memcpy(address.sun_path, path, sizeof(path));
    const int connected =
        ::connect(descriptor, reinterpret_cast<sockaddr *>(&address), sizeof(address));
    if (connected != 0) {
        if (errno != EINPROGRESS && errno != EAGAIN)
            return false;
        pollfd pending{descriptor, POLLOUT, 0};
        if (poll(&pending, 1, CallBudgetMs) != 1)
            return false;
        int error = 0;
        socklen_t bytes = sizeof(error);
        if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &bytes) != 0 || error != 0)
            return false;
    }
    ucred credentials{};
    socklen_t length = sizeof(credentials);
    return getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &length) == 0 &&
           length == sizeof(credentials) && credentials.uid == 0 && credentials.pid > 0;
}

} // namespace

std::optional<NativePeerIdentity> bindNativeService(NativePeerPurpose purpose,
                                                    quint32 expectedServiceUid,
                                                    const NativeServiceFacts &facts)
{
    const Route selected = route(purpose);
    if (!selected.service || !uniqueOwner(facts.sender) || facts.sender != facts.namedOwner ||
        facts.nativePid == 0 || facts.mainPid != facts.nativePid ||
        facts.activeState != QLatin1String("active") ||
        facts.subState != QLatin1String("running") ||
        facts.fragment != QLatin1String(selected.fragment) || facts.dropInsPresent ||
        !facts.rootImmutableFragment || !facts.rootImmutableImage || !facts.exactNativeExecStart ||
        facts.invocation.size() != 36)
        return std::nullopt;
    const QUuid invocation(facts.invocation);
    if (invocation.isNull() || invocation.toString(QUuid::WithoutBraces) != facts.invocation)
        return std::nullopt;
    const quint32 expected =
        purpose == NativePeerPurpose::PreparedSessionDispatch ? 0 : expectedServiceUid;
    if ((purpose != NativePeerPurpose::PreparedSessionDispatch && expectedServiceUid == 0) ||
        facts.nativeUid != expected)
        return std::nullopt;
    return NativePeerIdentity{facts.sender, facts.nativeUid, facts.nativePid, facts.invocation};
}

PeerGuard::PeerGuard(QDBusConnection connection, QString name)
    : connection_(std::move(connection)), connectionName_(std::move(name))
{}

PeerGuard::~PeerGuard()
{
    if (!connectionName_.isEmpty())
        QDBusConnection::disconnectFromBus(connectionName_);
}

PeerGuard::PeerGuard(PeerGuard &&other) noexcept
    : connection_(other.connection_), connectionName_(std::exchange(other.connectionName_, {})),
      progress_(std::move(other.progress_))
{}

PeerGuard &PeerGuard::operator=(PeerGuard &&other) noexcept
{
    if (this != &other) {
        if (!connectionName_.isEmpty())
            QDBusConnection::disconnectFromBus(connectionName_);
        connection_ = other.connection_;
        connectionName_ = std::exchange(other.connectionName_, {});
        progress_ = std::move(other.progress_);
    }
    return *this;
}

std::optional<PeerGuard> PeerGuard::connect()
{
    if (!trustedSystemBusSocket())
        return std::nullopt;
    static std::atomic<quint64> sequence{0};
    const QString name = QStringLiteral("linura-private-security-owner-%1-%2")
                             .arg(getpid())
                             .arg(sequence.fetch_add(1));
    NativeDeadline authenticationDeadline(std::chrono::milliseconds(2'000),
                                          NativeDeadline::Stage::BusAuthentication);
    auto connection = QDBusConnection::connectToBus(
        QStringLiteral("unix:path=/run/dbus/system_bus_socket"), name);
    if (!connection.isConnected()) {
        QDBusConnection::disconnectFromBus(name);
        return std::nullopt;
    }
    return PeerGuard(std::move(connection), name);
}

void PeerGuard::setNativeProgress(NativeProbeProgress progress)
{
    progress_ = std::move(progress);
}

QDBusMessage PeerGuard::call(QElapsedTimer &budget, const QString &owner, const QString &path,
                             const QString &interface, const QString &method,
                             const QList<QVariant> &arguments) const
{
    if (progress_)
        progress_();
    const qint64 remaining = ProbeBudgetMs - budget.elapsed();
    if (remaining <= 0)
        return QDBusMessage::createError(QStringLiteral("org.linura.Private.NativeUnavailable"),
                                         QStringLiteral("Native identity deadline expired"));
    auto message = QDBusMessage::createMethodCall(owner, path, interface, method);
    message.setArguments(arguments);
    return connection_.call(message, QDBus::Block, int(std::min<qint64>(remaining, CallBudgetMs)));
}

std::optional<NativePeerIdentity> PeerGuard::attest(NativePeerPurpose purpose,
                                                    const QString &transportSender) const
{
    const Route selected = route(purpose);
    const auto controlUid = localServiceUid(purpose);
    if (!selected.service || !uniqueOwner(transportSender) || !controlUid)
        return std::nullopt;
    QElapsedTimer budget;
    budget.start();
    const auto bus = [&](const QString &method, const QList<QVariant> &arguments) {
        return call(budget, QStringLiteral("org.freedesktop.DBus"),
                    QStringLiteral("/org/freedesktop/DBus"), QStringLiteral("org.freedesktop.DBus"),
                    method, arguments);
    };
    const auto ownerOf = [&](const QString &service) -> std::optional<QString> {
        const QDBusReply<QString> reply(bus(QStringLiteral("GetNameOwner"), {service}));
        if (!reply.isValid() || !uniqueOwner(reply.value()))
            return std::nullopt;
        return reply.value();
    };
    const auto serviceOwner = ownerOf(QLatin1String(selected.service));
    const auto systemdOwner = ownerOf(QStringLiteral("org.freedesktop.systemd1"));
    if (!serviceOwner || *serviceOwner != transportSender || !systemdOwner)
        return std::nullopt;
    const QDBusReply<quint32> systemdUid(
        bus(QStringLiteral("GetConnectionUnixUser"), {*systemdOwner}));
    const QDBusReply<quint32> uid(bus(QStringLiteral("GetConnectionUnixUser"), {*serviceOwner}));
    const QDBusReply<quint32> pid(
        bus(QStringLiteral("GetConnectionUnixProcessID"), {*serviceOwner}));
    if (!systemdUid.isValid() || systemdUid.value() != 0 || !uid.isValid() || !pid.isValid())
        return std::nullopt;
    const QDBusReply<QDBusObjectPath> unit(
        call(budget, *systemdOwner, QStringLiteral("/org/freedesktop/systemd1"),
             QStringLiteral("org.freedesktop.systemd1.Manager"), QStringLiteral("GetUnit"),
             {QLatin1String(selected.unit)}));
    if (!unit.isValid() || unit.value().path().size() > 256 ||
        !unit.value().path().startsWith(QLatin1String("/org/freedesktop/systemd1/unit/")))
        return std::nullopt;
    const QString unitInterface = QStringLiteral("org.freedesktop.systemd1.Unit");
    const QString serviceInterface = QStringLiteral("org.freedesktop.systemd1.Service");
    const auto properties = [&](const QString &interface, const QStringList &names) {
        return readNativeDBusProperties(connection_, budget, *systemdOwner, unit.value().path(),
                                        interface, names, ProbeBudgetMs, CallBudgetMs, progress_);
    };
    const auto unitFields =
        properties(unitInterface, {QStringLiteral("ActiveState"), QStringLiteral("SubState"),
                                   QStringLiteral("FragmentPath"), QStringLiteral("InvocationID"),
                                   QStringLiteral("DropInPaths")});
    const auto serviceFields =
        properties(serviceInterface, {QStringLiteral("MainPID"), QStringLiteral("ExecStart")});
    if (!unitFields || !serviceFields)
        return std::nullopt;
    const auto property = [&](const QString &interface,
                              const QString &name) -> std::optional<QVariant> {
        if (interface != unitInterface && interface != serviceInterface)
            return std::nullopt;
        const auto &fields = interface == unitInterface ? *unitFields : *serviceFields;
        return fields.contains(name) ? std::optional<QVariant>(fields.value(name)) : std::nullopt;
    };
    const auto active = property(unitInterface, QStringLiteral("ActiveState"));
    const auto sub = property(unitInterface, QStringLiteral("SubState"));
    const auto fragment = property(unitInterface, QStringLiteral("FragmentPath"));
    const auto invocation = property(unitInterface, QStringLiteral("InvocationID"));
    const auto dropIns = property(unitInterface, QStringLiteral("DropInPaths"));
    const auto mainPid = property(serviceInterface, QStringLiteral("MainPID"));
    const auto execStart = property(serviceInterface, QStringLiteral("ExecStart"));
    if (!active || !sub || !fragment || !invocation || !dropIns || !mainPid || !execStart ||
        active->metaType() != QMetaType::fromType<QString>() ||
        sub->metaType() != QMetaType::fromType<QString>() ||
        fragment->metaType() != QMetaType::fromType<QString>() ||
        invocation->metaType() != QMetaType::fromType<QByteArray>() ||
        mainPid->metaType() != QMetaType::fromType<quint32>() ||
        invocation->toByteArray().size() != 16 || active->toString().size() > 16 ||
        sub->toString().size() > 16 || fragment->toString().size() > 128)
        return std::nullopt;
    if (dropIns->metaType() != QMetaType::fromType<QStringList>()) {
        if (dropIns->metaType() != QMetaType::fromType<QDBusArgument>() ||
            dropIns->value<QDBusArgument>().currentSignature() != QLatin1String("as"))
            return std::nullopt;
    }
    const auto dropInPaths = qdbus_cast<QStringList>(*dropIns);
    NativeServiceFacts facts{
        transportSender,
        *serviceOwner,
        uid.value(),
        pid.value(),
        mainPid->toUInt(),
        QUuid::fromRfc4122(invocation->toByteArray()).toString(QUuid::WithoutBraces),
        active->toString(),
        sub->toString(),
        fragment->toString(),
        !dropInPaths.isEmpty(),
        immutable(selected.fragment, false),
        immutable(selected.image, true),
        exactExecStart(purpose, pid.value(), *execStart)};
    const auto bound = bindNativeService(purpose, *controlUid, facts);
    if (!bound || ownerOf(QLatin1String(selected.service)) != serviceOwner ||
        ownerOf(QStringLiteral("org.freedesktop.systemd1")) != systemdOwner ||
        budget.elapsed() >= ProbeBudgetMs)
        return std::nullopt;
    // Recheck the supervised PID and invocation after the complete native probe.
    const auto freshService =
        properties(serviceInterface, {QStringLiteral("MainPID"), QStringLiteral("ExecStart")});
    const auto freshUnit = properties(unitInterface, {QStringLiteral("InvocationID")});
    if (!freshService || !freshUnit)
        return std::nullopt;
    const std::optional<QVariant> freshPid = freshService->value(QStringLiteral("MainPID"));
    const std::optional<QVariant> freshInvocation =
        freshUnit->value(QStringLiteral("InvocationID"));
    const std::optional<QVariant> freshExecStart = freshService->value(QStringLiteral("ExecStart"));
    if (!freshPid || freshPid->metaType() != QMetaType::fromType<quint32>() ||
        freshPid->toUInt() != bound->pid || !freshInvocation ||
        freshInvocation->metaType() != QMetaType::fromType<QByteArray>() ||
        freshInvocation->toByteArray() != invocation->toByteArray() || !freshExecStart ||
        !exactExecStart(purpose, bound->pid, *freshExecStart) || budget.elapsed() >= ProbeBudgetMs)
        return std::nullopt;
    return bound;
}

bool PeerGuard::stillCurrent(NativePeerPurpose purpose, const NativePeerIdentity &peer) const
{
    return attest(purpose, peer.uniqueOwner) == peer;
}

std::optional<NativePeerIdentity> PeerGuard::namedPeer(NativePeerPurpose purpose) const
{
    const Route selected = route(purpose);
    if (!selected.service)
        return std::nullopt;
    QElapsedTimer budget;
    budget.start();
    const QDBusReply<QString> owner(
        call(budget, QStringLiteral("org.freedesktop.DBus"),
             QStringLiteral("/org/freedesktop/DBus"), QStringLiteral("org.freedesktop.DBus"),
             QStringLiteral("GetNameOwner"), {QLatin1String(selected.service)}));
    if (!owner.isValid() || !uniqueOwner(owner.value()))
        return std::nullopt;
    return attest(purpose, owner.value());
}

} // namespace Linura::SecurityOwner
