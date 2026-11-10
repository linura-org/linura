#include "native_radio_method.h"

#include <QDBusVariant>
#include <QStringView>
#include <QVariant>

#include <utility>

namespace Linura::SecurityOwner {
namespace {

// Require a D-Bus unique owner. Its actual process/boot/system-bus identity
// MUST be pinned separately; string format does not attest the daemon.
bool canonicalUniqueNetworkManagerOwner(const QString &name)
{
    if (!name.startsWith(QLatin1String(":1.")) || name.size() > 32)
        return false;
    const QStringView suffix = QStringView(name).mid(3);
    if (suffix.isEmpty() || (suffix.size() > 1 && suffix.startsWith(QLatin1Char('0'))))
        return false;
    for (const QChar digit : suffix) {
        if (digit < QLatin1Char('0') || digit > QLatin1Char('9'))
            return false;
    }
    return true;
}

} // namespace

NativeRadioMethod::NativeRadioMethod(QString owner, NativeRadioMutation mutation, bool enabled)
    : owner_(std::move(owner)), mutation_(mutation), enabled_(enabled)
{}

using RadioMethod = std::optional<NativeRadioMethod>;
RadioMethod NativeRadioMethod::encode(const QString &owner, NativeRadioMutation op, bool enabled)
{
    if (!canonicalUniqueNetworkManagerOwner(owner))
        return std::nullopt;
    switch (op) {
    case NativeRadioMutation::NetworkingEnabled:
    case NativeRadioMutation::WirelessEnabled:
        return NativeRadioMethod(owner, op, enabled);
    }
    return std::nullopt;
}

QDBusMessage NativeRadioMethod::message() const
{
    const QString root = QStringLiteral("/org/freedesktop/NetworkManager");
    if (mutation_ == NativeRadioMutation::NetworkingEnabled) {
        const QString interface = QStringLiteral("org.freedesktop.NetworkManager");
        auto call =
            QDBusMessage::createMethodCall(owner_, root, interface, QStringLiteral("Enable"));
        call.setAutoStartService(false);
        call.setArguments({QVariant(enabled_)});
        return call;
    }
    // The only other admissible enum is WirelessEnabled. The D-Bus Set
    // variant is mandatory, unlike a plain bool in the Enable(bool) method.
    const QString properties = QStringLiteral("org.freedesktop.DBus.Properties");
    auto call = QDBusMessage::createMethodCall(owner_, root, properties, QStringLiteral("Set"));
    call.setAutoStartService(false);
    call.setArguments({QStringLiteral("org.freedesktop.NetworkManager"),
                       QStringLiteral("WirelessEnabled"),
                       QVariant::fromValue(QDBusVariant(QVariant(enabled_)))});
    return call;
}

} // namespace Linura::SecurityOwner
