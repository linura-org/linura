#include "native_connection_dispatch.h"

#include <QDBusArgument>
#include <QDBusObjectPath>
#include <QElapsedTimer>
#include <QMap>
#include <QMetaType>
#include <QVariant>

#include <unistd.h>

#include <utility>

namespace Linura::SecurityOwner {
namespace {
constexpr int ConnectionReplyDeadlineMs = 500;
constexpr qint64 ConnectionTotalDeadlineMs = 2500;

// Never deserialize an a{ss} through a QMap conversion which might silently
// collapse duplicate permission keys. A conflicting "no" must not become "yes".
std::optional<QMap<QString, QString>> readPermissions(const QDBusMessage &reply)
{
    if (reply.type() != QDBusMessage::ReplyMessage || reply.signature() != QLatin1String("a{ss}") ||
        reply.arguments().size() != 1)
        return std::nullopt;
    const QVariant value = reply.arguments().first();
    if (value.metaType() != QMetaType::fromType<QDBusArgument>())
        return std::nullopt;
    const QDBusArgument argument = value.value<QDBusArgument>();
    QMap<QString, QString> permissions;
    argument.beginMap();
    while (!argument.atEnd()) {
        if (permissions.size() >= 128)
            return std::nullopt;
        QString action;
        QString decision;
        argument.beginMapEntry();
        argument >> action >> decision;
        argument.endMapEntry();
        if (action.isEmpty() || action.size() > 160 || decision.isEmpty() || decision.size() > 32 ||
            permissions.contains(action))
            return std::nullopt;
        permissions.insert(action, decision);
    }
    argument.endMap();
    return permissions.isEmpty() ? std::nullopt : std::optional{permissions};
}

bool validDispatchReply(const QDBusMessage &reply, const NativeConnectionMethod &method)
{
    if (reply.type() != QDBusMessage::ReplyMessage)
        return false;
    if (method.mutation() == NativeConnectionMutation::Deactivate)
        return reply.signature().isEmpty() && reply.arguments().isEmpty();
    if (reply.signature() != QLatin1String("o") || reply.arguments().size() != 1)
        return false;
    const QVariant argument = reply.arguments().first();
    if (argument.metaType() != QMetaType::fromType<QDBusObjectPath>())
        return false;
    // ActivateConnection replies with a new active object path. Validate its
    // family/generation, but do not interpret a syntactically valid path as
    // proof of an active association or a successful IP configuration.
    const QString owner = method.message().service();
    const QString active = argument.value<QDBusObjectPath>().path();
    return NativeConnectionMethod::deactivate(owner, active).has_value();
}
} // namespace

NativeConnectionDispatchAttempt::NativeConnectionDispatchAttempt(NativeLockIdentity lock,
                                                                 NativePeerIdentity manager,
                                                                 NativeConnectionMethod method)
    : lock_(std::move(lock)), manager_(std::move(manager)), method_(std::move(method))
{}

NativeConnectionDispatchAttempt::NativeConnectionDispatchAttempt(
    NativeConnectionDispatchAttempt &&other) noexcept
    : lock_(std::move(other.lock_)), manager_(std::move(other.manager_)),
      method_(std::move(other.method_)), spent_(std::exchange(other.spent_, true))
{}

std::optional<NativeConnectionMethod>
NativeConnectionDispatchAttempt::spend(const NativeLockIdentity &lock,
                                       const NativePeerIdentity &manager)
{
    const bool alreadySpent = std::exchange(spent_, true);
    if (alreadySpent || lock != lock_ || manager != manager_)
        return std::nullopt;
    if (lock.uid == 0 || lock.generation == 0 || lock.createdMonotonicUs == 0)
        return std::nullopt;
    if (lock.boot.isEmpty() || lock.session.isEmpty() || lock.resource.isEmpty() ||
        lock.ownerInvocation.isEmpty())
        return std::nullopt;
    if (manager.uid != 0 || manager.pid <= 1 || manager.serviceInvocation.isEmpty() ||
        manager.uniqueOwner.isEmpty())
        return std::nullopt;
    if (method_.message().service() != manager.uniqueOwner)
        return std::nullopt;
    return method_;
}

NativeConnectionDispatchDisposition
NativeConnectionDispatchAttempt::dispatch(const PeerGuard &peers,
                                          const NativeLockIdentity &liveLock,
                                          const NativePeerIdentity &liveNetworkManager)
{
    const auto method = spend(liveLock, liveNetworkManager);
    if (!method || getuid() == 0 || geteuid() == 0 ||
        static_cast<quint32>(getuid()) != liveLock.uid ||
        static_cast<quint32>(geteuid()) != liveLock.uid ||
        !peers.nativeConnection().isConnected() ||
        !peers.stillCurrent(NativePeerPurpose::NetworkManagerDaemon, liveNetworkManager))
        return NativeConnectionDispatchDisposition::RejectedBeforeDispatch;

    // NetworkManager evaluates GetPermissions for THIS original-user sender,
    // not a privileged Control process or a claimed user in an RPC payload.
    QDBusMessage permissionsQuery = QDBusMessage::createMethodCall(
        liveNetworkManager.uniqueOwner, QStringLiteral("/org/freedesktop/NetworkManager"),
        QStringLiteral("org.freedesktop.NetworkManager"), QStringLiteral("GetPermissions"));
    permissionsQuery.setAutoStartService(false);
    const auto permissionReply =
        peers.nativeConnection().call(permissionsQuery, QDBus::Block, ConnectionReplyDeadlineMs);
    const auto permissions = readPermissions(permissionReply);
    if (!permissions || !nativeConnectionPermissionGranted(*permissions) ||
        !peers.stillCurrent(NativePeerPurpose::NetworkManagerDaemon, liveNetworkManager))
        return NativeConnectionDispatchDisposition::RejectedBeforeDispatch;

    // One fixed typed NetworkManager call. A timeout, malformed acknowledgement
    // or daemon replacement means an indeterminate attempted effect: NEVER retry.
    QElapsedTimer elapsed;
    elapsed.start();
    const auto reply =
        peers.nativeConnection().call(method->message(), QDBus::Block, ConnectionReplyDeadlineMs);
    const bool current =
        peers.stillCurrent(NativePeerPurpose::NetworkManagerDaemon, liveNetworkManager);
    if (!current || elapsed.elapsed() >= ConnectionTotalDeadlineMs ||
        !validDispatchReply(reply, *method))
        return NativeConnectionDispatchDisposition::Indeterminate;
    return NativeConnectionDispatchDisposition::Dispatched;
}

} // namespace Linura::SecurityOwner
