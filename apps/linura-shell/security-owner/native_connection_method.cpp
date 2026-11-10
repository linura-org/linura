#include "native_connection_method.h"

#include <QDBusObjectPath>
#include <QMap>
#include <QStringView>
#include <QVariant>

#include <utility>

namespace Linura::SecurityOwner {
namespace {

bool exactUniqueNetworkManagerOwner(const QString &name)
{
    if (!name.startsWith(QLatin1String(":1.")) || name.size() > 32)
        return false;
    const QStringView number = QStringView(name).mid(3);
    if (number.isEmpty() || (number.size() > 1 && number.front() == QLatin1Char('0')))
        return false;
    for (const QChar digit : number) {
        if (digit < QLatin1Char('0') || digit > QLatin1Char('9'))
            return false;
    }
    // A valid unique-name string does not identify an authenticated daemon.
    return true;
}

bool exactObjectPath(const QString &path, const QString &family)
{
    QString prefix = QStringLiteral("/org/freedesktop/NetworkManager/");
    prefix += family;
    prefix += QLatin1Char('/');
    if (!path.startsWith(prefix) || path.size() > prefix.size() + 20)
        return false;
    const QStringView number = QStringView(path).mid(prefix.size());
    if (number.isEmpty() || number.front() == QLatin1Char('0'))
        return false;
    for (const QChar digit : number) {
        if (digit < QLatin1Char('0') || digit > QLatin1Char('9'))
            return false;
    }
    bool valid = false;
    const quint64 generation = number.toULongLong(&valid);
    return valid && generation > 0;
}

} // namespace

using MethodResult = std::optional<NativeConnectionMethod>;

bool nativeConnectionPermissionGranted(const QMap<QString, QString> &permissions)
{
    if (permissions.isEmpty() || permissions.size() > 128)
        return false;
    for (auto it = permissions.cbegin(); it != permissions.cend(); ++it) {
        if (it.key().isEmpty() || it.key().size() > 160 || it.value().isEmpty() ||
            it.value().size() > 32)
            return false;
    }
    // NetworkManager returns "auth" if the caller may authenticate; that is
    // NOT a permission and cannot be used as this sender's authorization.
    return permissions.value(QLatin1String("org.freedesktop.NetworkManager.network-control")) ==
           QLatin1String("yes");
}

NativeConnectionMethod::NativeConnectionMethod(QString owner, NativeConnectionMutation mutation,
                                               QString target, QString device, QString accessPoint)
    : owner_(std::move(owner)), mutation_(mutation), target_(std::move(target)),
      device_(std::move(device)), accessPoint_(std::move(accessPoint))
{}

MethodResult NativeConnectionMethod::activate(const NativeConnectionActivationTarget &target)
{
    const QString &owner = target.owner;
    const QString &profile = target.profile;
    const QString &device = target.device;
    const NativeConnectionMedia media = target.media;
    const QString &accessPoint = target.accessPoint;
    if (!exactUniqueNetworkManagerOwner(owner) || !exactObjectPath(profile, "Settings") ||
        !exactObjectPath(device, "Devices"))
        return std::nullopt;
    switch (media) {
    case NativeConnectionMedia::Ethernet:
        if (accessPoint != QLatin1String("/"))
            return std::nullopt;
        break;
    case NativeConnectionMedia::Wifi:
        // No unspecified AP, hidden SSID-directed probe or implicit router
        // selection. Native source evidence must separately pin this AP.
        if (!exactObjectPath(accessPoint, "AccessPoint"))
            return std::nullopt;
        break;
    default:
        return std::nullopt;
    }
    return NativeConnectionMethod(owner, NativeConnectionMutation::Activate, profile, device,
                                  accessPoint);
}

MethodResult NativeConnectionMethod::deactivate(const QString &owner, const QString &active)
{
    if (!exactUniqueNetworkManagerOwner(owner) || !exactObjectPath(active, "ActiveConnection"))
        return std::nullopt;
    const QString none;
    return NativeConnectionMethod(owner, NativeConnectionMutation::Deactivate, active, none, none);
}

QDBusMessage NativeConnectionMethod::message() const
{
    QDBusMessage message = QDBusMessage::createMethodCall(
        owner_, QStringLiteral("/org/freedesktop/NetworkManager"),
        QStringLiteral("org.freedesktop.NetworkManager"),
        mutation_ == NativeConnectionMutation::Activate ? QStringLiteral("ActivateConnection")
                                                        : QStringLiteral("DeactivateConnection"));
    message.setAutoStartService(false);
    if (mutation_ == NativeConnectionMutation::Activate)
        message.setArguments({
            QVariant::fromValue(QDBusObjectPath(target_)),
            QVariant::fromValue(QDBusObjectPath(device_)),
            QVariant::fromValue(QDBusObjectPath(accessPoint_)),
        });
    else
        message.setArguments({QVariant::fromValue(QDBusObjectPath(target_))});
    return message;
}

} // namespace Linura::SecurityOwner
