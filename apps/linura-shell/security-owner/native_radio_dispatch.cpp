#include "native_radio_dispatch.h"

#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QElapsedTimer>
#include <QMap>
#include <QMetaType>
#include <QVariant>

#include <unistd.h>

#include <utility>

namespace Linura::SecurityOwner {
namespace {
constexpr int NativeRadioReplyDeadlineMs = 500;
constexpr qint64 NativeRadioTotalDeadlineMs = 2'500;

// Parse raw a{ss} without folding duplicate keys into a map. A single
// conflicting NetworkManager permission entry cannot be interpreted as yes.
std::optional<QMap<QString, QString>> readNativeRadioPermissions(const QDBusMessage &reply)
{
    if (reply.type() != QDBusMessage::ReplyMessage || reply.signature() != QLatin1String("a{ss}") ||
        reply.arguments().size() != 1)
        return std::nullopt;
    // QDBusMessage::arguments() returns a temporary QList. Retain the
    // extracted QVariant by value so its lifetime cannot dangle.
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
        QString result;
        argument.beginMapEntry();
        argument >> action >> result;
        argument.endMapEntry();
        if (action.isEmpty() || action.size() > 160 || result.isEmpty() || result.size() > 32 ||
            permissions.contains(action))
            return std::nullopt;
        permissions.insert(action, result);
    }
    argument.endMap();
    return permissions.isEmpty() ? std::nullopt : std::optional{permissions};
}
} // namespace

bool nativeRadioPermissionGranted(const QMap<QString, QString> &permissions,
                                  NativeRadioMutation mutation)
{
    if (permissions.isEmpty() || permissions.size() > 128)
        return false;
    for (auto entry = permissions.cbegin(); entry != permissions.cend(); ++entry) {
        if (entry.key().isEmpty() || entry.key().size() > 160 || entry.value().isEmpty() ||
            entry.value().size() > 32)
            return false;
    }
    const char *action = nullptr;
    switch (mutation) {
    case NativeRadioMutation::NetworkingEnabled:
        action = "org.freedesktop.NetworkManager.enable-disable-network";
        break;
    case NativeRadioMutation::WirelessEnabled:
        action = "org.freedesktop.NetworkManager.enable-disable-wifi";
        break;
    }
    return action && permissions.value(QLatin1String(action)) == QLatin1String("yes");
}

bool nativeRadioConsentMatches(const NativeApprovalScope &consent, const NativeLockIdentity &lock,
                               NativeRadioMutation mutation, bool enabled)
{
    if (!consent.valid() || consent.purpose != ApprovalPurpose::AuthenticateNetworkRadio ||
        consent.lock != lock)
        return false;
    QString operation;
    switch (mutation) {
    case NativeRadioMutation::NetworkingEnabled:
        operation = QStringLiteral("networking-");
        break;
    case NativeRadioMutation::WirelessEnabled:
        operation = QStringLiteral("wifi-");
        break;
    default:
        return false;
    }
    operation += enabled ? QStringLiteral("enable-") : QStringLiteral("disable-");
    const QString prefix = QStringLiteral("request:v010:network-radio:") + operation;
    return consent.request.startsWith(prefix) && consent.request.size() > prefix.size();
}

NativeRadioDispatchAttempt::NativeRadioDispatchAttempt(NativeApprovalScope consumedConsent,
                                                       NativeLockIdentity lock,
                                                       NativePeerIdentity manager,
                                                       NativeRadioMutation mutation, bool enabled)
    : consumedConsent_(std::move(consumedConsent)), lock_(std::move(lock)),
      manager_(std::move(manager)), mutation_(mutation), enabled_(enabled)
{}

NativeRadioDispatchAttempt::NativeRadioDispatchAttempt(NativeRadioDispatchAttempt &&other) noexcept
    : consumedConsent_(std::move(other.consumedConsent_)), lock_(std::move(other.lock_)),
      manager_(std::move(other.manager_)), mutation_(other.mutation_), enabled_(other.enabled_),
      spent_(std::exchange(other.spent_, true))
{}

std::optional<NativeRadioMethod>
NativeRadioDispatchAttempt::spend(const NativeLockIdentity &lock, const NativePeerIdentity &manager)
{
    if (std::exchange(spent_, true) || lock != lock_ || manager != manager_ || manager.uid != 0 ||
        manager.pid <= 1 || manager.serviceInvocation.isEmpty() ||
        !nativeRadioConsentMatches(consumedConsent_, lock, mutation_, enabled_))
        return std::nullopt;
    return NativeRadioMethod::encode(manager.uniqueOwner, mutation_, enabled_);
}

NativeRadioDispatchDisposition
NativeRadioDispatchAttempt::dispatch(const PeerGuard &peers, const NativeLockIdentity &liveLock,
                                     const NativePeerIdentity &liveNetworkManager)
{
    const auto method = spend(liveLock, liveNetworkManager);
    if (!method || getuid() == 0 || geteuid() == 0 ||
        static_cast<quint32>(getuid()) != liveLock.uid ||
        static_cast<quint32>(geteuid()) != liveLock.uid ||
        !peers.nativeConnection().isConnected() ||
        !peers.stillCurrent(NativePeerPurpose::NetworkManagerDaemon, liveNetworkManager))
        return NativeRadioDispatchDisposition::RejectedBeforeDispatch;

    // Unlike a policy query for the original login leader, this checks
    // NetworkManager's decision for the ACTUAL user-origin D-Bus sender.
    QDBusMessage query = QDBusMessage::createMethodCall(
        liveNetworkManager.uniqueOwner, QStringLiteral("/org/freedesktop/NetworkManager"),
        QStringLiteral("org.freedesktop.NetworkManager"), QStringLiteral("GetPermissions"));
    query.setAutoStartService(false);
    const QDBusMessage permissionReply =
        peers.nativeConnection().call(query, QDBus::Block, NativeRadioReplyDeadlineMs);
    const auto permissions = readNativeRadioPermissions(permissionReply);
    if (!permissions || !nativeRadioPermissionGranted(*permissions, method->mutation()) ||
        !peers.stillCurrent(NativePeerPurpose::NetworkManagerDaemon, liveNetworkManager))
        return NativeRadioDispatchDisposition::RejectedBeforeDispatch;

    // The actual D-Bus message is issued by the original user's native
    // security-owner connection, NOT by root Control or an ambient user bus.
    // NativeRadioMethod hard-codes the only two methods, fixed object path,
    // typed arguments and no service autostart.
    QElapsedTimer deadline;
    deadline.start();
    const QDBusMessage reply =
        peers.nativeConnection().call(method->message(), QDBus::Block, NativeRadioReplyDeadlineMs);
    const bool ownerStillCurrent =
        peers.stillCurrent(NativePeerPurpose::NetworkManagerDaemon, liveNetworkManager);
    // A provider reply is at most a dispatch acknowledgement. A lost reply or
    // owner replacement after send may conceal a completed effect.
    if (!ownerStillCurrent || deadline.elapsed() >= NativeRadioTotalDeadlineMs ||
        reply.type() != QDBusMessage::ReplyMessage || !reply.arguments().isEmpty())
        return NativeRadioDispatchDisposition::Indeterminate;

    return NativeRadioDispatchDisposition::Dispatched;
}

} // namespace Linura::SecurityOwner
