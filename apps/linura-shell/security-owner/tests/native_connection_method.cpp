#include "native_connection_method.h"

#include <QCoreApplication>
#include <QDBusObjectPath>
#include <QMap>
#include <QMetaType>
#include <QStringList>

#include <cassert>

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    using namespace Linura::SecurityOwner;
    using Media = NativeConnectionMedia;

    const QString permission = QStringLiteral("org.freedesktop.NetworkManager.network-control");
    const QMap<QString, QString> approved{{permission, QStringLiteral("yes")}};
    assert(nativeConnectionPermissionGranted(approved));
    auto policy = approved;
    policy[permission] = QStringLiteral("auth");
    assert(!nativeConnectionPermissionGranted(policy));
    policy[permission] = QStringLiteral("no");
    assert(!nativeConnectionPermissionGranted(policy));
    policy[permission] = QStringLiteral("YES");
    assert(!nativeConnectionPermissionGranted(policy));
    policy.remove(permission);
    assert(!nativeConnectionPermissionGranted(policy));
    policy.insert(QStringLiteral("foreign"), QString(161, QLatin1Char('x')));
    assert(!nativeConnectionPermissionGranted(policy));
    assert(!nativeConnectionPermissionGranted({}));

    assert(NativeConnectionMethod::deactivate(
        QStringLiteral(":1.0"),
        QStringLiteral("/org/freedesktop/NetworkManager/ActiveConnection/12")));
    const QString owner = QStringLiteral(":1.48");
    const QString profile = QStringLiteral("/org/freedesktop/NetworkManager/Settings/9");
    const QString device = QStringLiteral("/org/freedesktop/NetworkManager/Devices/8");
    const QString active = QStringLiteral("/org/freedesktop/NetworkManager/ActiveConnection/12");
    const QString ap = QStringLiteral("/org/freedesktop/NetworkManager/AccessPoint/5");

    const QString root = QStringLiteral("/");
    NativeConnectionActivationTarget wired{owner, profile, device, Media::Ethernet, root};
    const auto eth = NativeConnectionMethod::activate(wired);
    assert(eth);
    assert(eth->mutation() == NativeConnectionMutation::Activate);
    assert(eth->targetPath() == profile);
    assert(eth->devicePath() == device);
    const auto call = eth->message();
    assert(call.service() == owner && !call.autoStartService());
    assert(call.path() == QLatin1String("/org/freedesktop/NetworkManager"));
    assert(call.interface() == QLatin1String("org.freedesktop.NetworkManager"));
    assert(call.member() == QLatin1String("ActivateConnection"));
    assert(call.arguments().size() == 3);
    for (int n = 0; n < 3; ++n)
        assert(call.arguments()[n].metaType() == QMetaType::fromType<QDBusObjectPath>());
    assert(call.arguments()[0].value<QDBusObjectPath>().path() == profile);
    assert(call.arguments()[1].value<QDBusObjectPath>().path() == device);
    assert(call.arguments()[2].value<QDBusObjectPath>().path() == root);

    auto wireless = wired;
    wireless.media = Media::Wifi;
    wireless.accessPoint = ap;
    const auto wifi = NativeConnectionMethod::activate(wireless);
    assert(wifi);
    assert(wifi->message().arguments()[2].value<QDBusObjectPath>().path() == ap);

    wireless.accessPoint = root;
    assert(!NativeConnectionMethod::activate(wireless));
    wired.accessPoint = ap;
    assert(!NativeConnectionMethod::activate(wired));
    wired.accessPoint = root;
    wired.media = static_cast<Media>(255);
    assert(!NativeConnectionMethod::activate(wired));
    wired.media = Media::Ethernet;

    const auto teardown = NativeConnectionMethod::deactivate(owner, active);
    assert(teardown);
    assert(teardown->mutation() == NativeConnectionMutation::Deactivate);
    assert(teardown->message().member() == QLatin1String("DeactivateConnection"));
    assert(teardown->message().arguments().size() == 1);
    assert(teardown->message().arguments()[0].value<QDBusObjectPath>().path() == active);
    assert(!teardown->message().autoStartService());

    QStringList invalidOwners;
    invalidOwners.append(QString());
    invalidOwners.append(QStringLiteral("org.freedesktop.NetworkManager"));
    invalidOwners.append(QStringLiteral(":1.00"));
    invalidOwners.append(QStringLiteral(":1.048"));
    invalidOwners.append(QStringLiteral(":1.48/child"));
    invalidOwners.append(QStringLiteral(":1.48\n"));
    invalidOwners.append(QStringLiteral(":2.48"));
    for (const QString &bad : invalidOwners) {
        auto target = wired;
        target.owner = bad;
        assert(!NativeConnectionMethod::activate(target));
        assert(!NativeConnectionMethod::deactivate(bad, active));
    }

    QStringList invalidProfiles;
    invalidProfiles.append(QString());
    invalidProfiles.append(root);
    invalidProfiles.append(QStringLiteral("/org/freedesktop/NetworkManager/Settings/0"));
    invalidProfiles.append(QStringLiteral("/org/freedesktop/NetworkManager/Settings/09"));
    invalidProfiles.append(QStringLiteral("/org/freedesktop/NetworkManager/Settings/9/other"));
    invalidProfiles.append(
        QStringLiteral("/org/freedesktop/NetworkManager/Settings/18446744073709551616"));
    invalidProfiles.append(device);
    for (const QString &bad : invalidProfiles) {
        auto target = wired;
        target.profile = bad;
        assert(!NativeConnectionMethod::activate(target));
    }

    QStringList invalidActives;
    invalidActives.append(QString());
    invalidActives.append(root);
    invalidActives.append(QStringLiteral("/org/freedesktop/NetworkManager/ActiveConnection/0"));
    invalidActives.append(QStringLiteral("/org/freedesktop/NetworkManager/ActiveConnection/012"));
    invalidActives.append(profile);
    invalidActives.append(device);
    invalidActives.append(ap);
    for (const QString &bad : invalidActives)
        assert(!NativeConnectionMethod::deactivate(owner, bad));

    wired.device = QStringLiteral("/org/freedesktop/NetworkManager/Devices/0");
    assert(!NativeConnectionMethod::activate(wired));
    wired.device = device;
    wired.media = Media::Wifi;
    wired.accessPoint = QStringLiteral("/org/freedesktop/NetworkManager/AccessPoint/0");
    assert(!NativeConnectionMethod::activate(wired));

    // No generic method name, mutable settings map, secret, raw shell,
    // profile mutation or service autostart is reachable from this encoder.
    return 0;
}
