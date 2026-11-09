#include "native_endpoint.h"
#include "native_network_agent.h"
#include "peer_guard.h"

#include <QCoreApplication>
#include <QDBusMetaType>
#include <QGuiApplication>

#include <iostream>
#include <stdexcept>

using namespace Linura::SecurityOwner;

namespace {

void check(bool condition)
{
    if (!condition)
        throw std::runtime_error("native S18-4 authenticated agent contract assertion failed");
}

NativeNmSettings profile()
{
    NativeNmSettings values;
    values.insert(QStringLiteral("connection"),
                  QVariantMap{{QStringLiteral("uuid"),
                               QStringLiteral("10203040-5060-7080-90ab-cdef12345678")},
                              {QStringLiteral("type"), QStringLiteral("802-11-wireless")},
                              {QStringLiteral("autoconnect"), false}});
    values.insert(QStringLiteral("802-11-wireless"),
                  QVariantMap{{QStringLiteral("mode"), QStringLiteral("infrastructure")},
                              {QStringLiteral("ssid"), QByteArrayLiteral("TestAP")}});
    values.insert(QStringLiteral("ipv4"),
                  QVariantMap{{QStringLiteral("method"), QStringLiteral("auto")}});
    values.insert(QStringLiteral("ipv6"),
                  QVariantMap{{QStringLiteral("method"), QStringLiteral("auto")}});
    values.insert(QStringLiteral("802-11-wireless-security"),
                  QVariantMap{{QStringLiteral("key-mgmt"), QStringLiteral("wpa-psk")},
                              {QStringLiteral("psk-flags"), quint32(2)}});
    return values;
}

void nativeProfileRevisionAndOneTimeSecretFlags()
{
    const auto sample = profile();
    const auto uuid = QStringLiteral("10203040-5060-7080-90ab-cdef12345678");
    const auto fingerprint = QString::fromLatin1(
        "2acb9af3277371c52d00b43f5385ced7"
        "4d5f4f5ee906ae7abc08be4c72666981");
    check(nativeProfileFingerprint(sample, uuid) == fingerprint);
    check(nativeOneTimeWpaProfile(sample, uuid, fingerprint));
    check(!nativeOneTimeWpaProfile(sample, uuid, QString(64, QLatin1Char('a'))));
    const auto foreignUuid = QStringLiteral("10203040-5060-7080-90ab-cdef12345679");
    check(!nativeOneTimeWpaProfile(sample, foreignUuid, fingerprint));

    auto changed = sample;
    changed[QStringLiteral("802-11-wireless-security")][QStringLiteral("psk-flags")] =
        quint32(0); // NM-owned and persistent
    check(!nativeOneTimeWpaProfile(changed, uuid, fingerprint));
    changed[QStringLiteral("802-11-wireless-security")][QStringLiteral("psk-flags")] =
        quint32(1); // Agent-owned and persistent
    check(!nativeOneTimeWpaProfile(changed, uuid, fingerprint));
    changed[QStringLiteral("802-11-wireless-security")][QStringLiteral("psk-flags")] =
        quint32(3); // Ambiguous ownership
    check(!nativeOneTimeWpaProfile(changed, uuid, fingerprint));
    changed = sample;
    changed[QStringLiteral("802-11-wireless-security")][QStringLiteral("psk")] =
        QStringLiteral("must-not-appear");
    check(!nativeOneTimeWpaProfile(changed, uuid, fingerprint));
    changed = sample;
    changed[QStringLiteral("802-11-wireless-security")][QStringLiteral("key-mgmt")] =
        QStringLiteral("wpa-eap");
    check(!nativeOneTimeWpaProfile(changed, uuid, fingerprint));
    changed = sample;
    changed[QStringLiteral("802-11-wireless")][QStringLiteral("ssid")] =
        QByteArrayLiteral("SubstitutedAP");
    check(!nativeOneTimeWpaProfile(changed, uuid, fingerprint));
    changed = sample;
    changed[QStringLiteral("connection")][QStringLiteral("autoconnect")] = true;
    check(!nativeOneTimeWpaProfile(changed, uuid, fingerprint));
    changed = sample;
    changed[QStringLiteral("connection")][QStringLiteral("type")] = QStringLiteral("vpn");
    check(!nativeOneTimeWpaProfile(changed, uuid, fingerprint));
}

void exactPrivateNetworkWire()
{
    NativeEndpoint::registerWireTypes();
    NativeNetworkSecretAgent::registerWireTypes();
    const auto signature =
        QDBusMetaType::typeToSignature(QMetaType::fromType<NativeNetworkCredentialWire>());
    check(signature == QByteArrayLiteral("((ssssssss)(sssssssuttb))"));
    const auto settingsSignature =
        QDBusMetaType::typeToSignature(QMetaType::fromType<NativeNmSettings>());
    check(settingsSignature == QByteArrayLiteral("a{sa{sv}}"));

    NativeNetworkCredentialWire wire;
    wire.resource = QStringLiteral("session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:2:42:"
                                   "98765432-1234-4567-89ab-0123456789ab:1");
    wire.principal = QStringLiteral("unix:uid:1000");
    wire.operation = QStringLiteral("operation:network.wifi.join");
    wire.request = QStringLiteral("request:v010:network-credential:fixture");
    wire.originalSender = QStringLiteral(":1.42");
    wire.systemBusId = QStringLiteral("fedcba9876543210abcdef0123456789");
    wire.networkManagerOwner = QStringLiteral(":1.48");
    wire.seat = QStringLiteral("seat0");
    wire.deviceObject = QStringLiteral("/org/freedesktop/NetworkManager/Devices/3");
    wire.deviceInterface = QStringLiteral("wlan0");
    wire.deviceIfindex = 3;
    wire.networkNamespace = 1024;
    wire.profileObject = QStringLiteral("/org/freedesktop/NetworkManager/Settings/9");
    wire.profileUuid = QStringLiteral("10203040-5060-7080-90ab-cdef12345678");
    wire.profileFingerprint = QString(64, QLatin1Char('a'));
    wire.requestDigest = QStringLiteral("sha256:") + QString(64, QLatin1Char('1'));
    wire.reviewDigest = QStringLiteral("sha256:") + QString(64, QLatin1Char('2'));
    wire.settingsVersion = 17;
    const auto scope = wire.scope();
    check(scope && scope->valid());
    wire.persistRequested = true;
    check(!wire.scope());
    wire.persistRequested = false;
    wire.request = QStringLiteral("request:v010:network-credential:other--request");
    check(!wire.scope());
    wire.request = QStringLiteral("request:v010:network-credential:fixture");
    wire.deviceIfindex = 0;
    check(!wire.scope());
}

void supervisedNetworkManagerMustBeRootOwned()
{
    NativeServiceFacts facts;
    facts.sender = QStringLiteral(":1.48");
    facts.namedOwner = facts.sender;
    facts.nativeUid = 0;
    facts.nativePid = 233;
    facts.mainPid = 233;
    facts.invocation = QStringLiteral("98765432-1234-4567-89ab-0123456789ab");
    facts.activeState = QStringLiteral("active");
    facts.subState = QStringLiteral("running");
    facts.fragment = QStringLiteral("/usr/lib/systemd/system/NetworkManager.service");
    facts.dropInsPresent = false;
    facts.rootImmutableFragment = true;
    facts.rootImmutableImage = true;
    facts.exactNativeExecStart = true;
    check(bindNativeService(NativePeerPurpose::NetworkManagerDaemon, 0, facts).has_value());
    facts.nativeUid = 1000;
    check(!bindNativeService(NativePeerPurpose::NetworkManagerDaemon, 0, facts));
    facts.nativeUid = 0;
    facts.dropInsPresent = true;
    check(!bindNativeService(NativePeerPurpose::NetworkManagerDaemon, 0, facts));
    facts.dropInsPresent = false;
    facts.exactNativeExecStart = false;
    check(!bindNativeService(NativePeerPurpose::NetworkManagerDaemon, 0, facts));
}

} // namespace

int main(int argc, char **argv)
{
    QGuiApplication app(argc, argv);
    try {
        nativeProfileRevisionAndOneTimeSecretFlags();
        exactPrivateNetworkWire();
        supervisedNetworkManagerMustBeRootOwned();
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
