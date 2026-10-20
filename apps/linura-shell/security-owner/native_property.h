#pragma once

#include <QDBusReply>
#include <QDBusVariant>
#include <optional>

namespace Linura::SecurityOwner {

// Shared private wire mechanism. The caller supplies its already-bounded call
// and independently attested owner/path. Each consumer still validates exact
// field types/values and obtains fresh replies for revalidation.
template <class Call>
[[nodiscard]] std::optional<QVariant>
readNativeDBusProperty(const Call &call, const QString &owner, const QString &object,
                       const QString &interface, const QString &name)
{
    const QDBusReply<QDBusVariant> reply(
        call(owner, object, QStringLiteral("org.freedesktop.DBus.Properties"),
             QStringLiteral("Get"), QList<QVariant>{interface, name}));
    if (!reply.isValid())
        return std::nullopt;
    return reply.value().variant();
}

} // namespace Linura::SecurityOwner
