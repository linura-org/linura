#pragma once

#include "native_probe_progress.h"

#include <QDBusReply>
#include <QDBusConnection>
#include <QDBusPendingCall>
#include <QDBusVariant>
#include <QElapsedTimer>
#include <QSet>
#include <QStringList>
#include <QVariantMap>
#include <algorithm>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

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

// One bounded read-only batch on an already attested unique connection. Queue
// every fixed Properties.Get before waiting: serial round trips must not consume
// the owner's event loop while Control is waiting for this compound probe.
// Each pending call starts its own unchanged timeout at admission; neither a
// wait nor a later reply resets that timeout or the caller's aggregate clock.
[[nodiscard]] inline std::optional<QVariantMap>
readNativeDBusProperties(const QDBusConnection &connection, QElapsedTimer &budget,
                         const QString &owner, const QString &object, const QString &interface,
                         const QStringList &names, qint64 probeBudgetMs, qint64 callBudgetMs,
                         const NativeProbeProgress &progress = {})
{
    if (!budget.isValid() || probeBudgetMs <= 0 || callBudgetMs <= 0 ||
        callBudgetMs > std::numeric_limits<int>::max() || budget.elapsed() >= probeBudgetMs ||
        !owner.startsWith(QLatin1Char(':')) || owner.size() > 128 || names.isEmpty() ||
        names.size() > 32)
        return std::nullopt;
    QSet<QString> unique;
    for (const auto &name : names) {
        if (name.isEmpty() || name.size() > 128 || unique.contains(name))
            return std::nullopt;
        unique.insert(name);
    }
    if (progress)
        progress();
    std::vector<std::pair<QString, QDBusPendingCall>> pending;
    pending.reserve(static_cast<std::size_t>(names.size()));
    for (const auto &name : names) {
        const auto remaining = probeBudgetMs - budget.elapsed();
        if (remaining <= 0)
            return std::nullopt;
        auto request = QDBusMessage::createMethodCall(
            owner, object, QStringLiteral("org.freedesktop.DBus.Properties"),
            QStringLiteral("Get"));
        request.setArguments({interface, name});
        pending.emplace_back(
            name,
            connection.asyncCall(request, static_cast<int>(std::min(remaining, callBudgetMs))));
    }
    QVariantMap values;
    for (auto &[name, call] : pending) {
        if (progress)
            progress();
        if (budget.elapsed() >= probeBudgetMs)
            return std::nullopt;
        call.waitForFinished();
        const auto message = call.reply();
        const QDBusReply<QDBusVariant> reply(message);
        if (budget.elapsed() >= probeBudgetMs || !reply.isValid() ||
            (!message.service().isEmpty() && message.service() != owner))
            return std::nullopt;
        values.insert(name, reply.value().variant());
    }
    return values; // Never return a partial batch or retain it across probes.
}

} // namespace Linura::SecurityOwner
