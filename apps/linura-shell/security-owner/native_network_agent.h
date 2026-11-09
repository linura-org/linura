#pragma once

#include "native_network_credentials.h"
#include "peer_guard.h"

#include <QDBusContext>
#include <QDBusMessage>
#include <QDBusObjectPath>
#include <QMap>
#include <QObject>
#include <QTimer>
#include <QVariantMap>

#include <functional>
#include <memory>
#include <optional>

namespace Linura::SecurityOwner {

class SecretEntry;

// NetworkManager's exact a{sa{sv}} wire map. The map is never exported to
// a model, audit, UI property or a persistent profile. Unknown requests fail.
using NativeNmSettings = QMap<QString, QVariantMap>;

// Tests and native intake use the SAME nonsecret projection and explicit
// NOT_SAVED WPA-PSK check; no secret-bearing settings are retained.
using Fingerprint = std::optional<QString>;
[[nodiscard]] Fingerprint nativeProfileFingerprint(const NativeNmSettings &, const QString &);
[[nodiscard]] bool nativeOneTimeWpaProfile(const NativeNmSettings &settings,
                                           const QString &profileUuid,
                                           const QString &expectedFingerprint);

// Private, one-shot system-bus SecretAgent. Registration is impossible until
// the original supervised Control proof has been spent and pinned by Runtime.
// Neither this object nor its metadata callbacks grant network effect authority.
class NativeNetworkSecretAgent final : public QObject, protected QDBusContext
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.freedesktop.NetworkManager.SecretAgent")
    Q_CLASSINFO("D-Bus Introspection",
                ""
                "<interface name=\"org.freedesktop.NetworkManager.SecretAgent\">"
                "<method name=\"GetSecrets\">"
                "<arg name=\"connection\" type=\"a{sa{sv}}\" direction=\"in\"/>"
                "<arg name=\"connection_path\" type=\"o\" direction=\"in\"/>"
                "<arg name=\"setting_name\" type=\"s\" direction=\"in\"/>"
                "<arg name=\"hints\" type=\"as\" direction=\"in\"/>"
                "<arg name=\"flags\" type=\"u\" direction=\"in\"/>"
                "<arg name=\"secrets\" type=\"a{sa{sv}}\" direction=\"out\"/>"
                "</method>"
                "<method name=\"CancelGetSecrets\">"
                "<arg name=\"connection_path\" type=\"o\" direction=\"in\"/>"
                "<arg name=\"setting_name\" type=\"s\" direction=\"in\"/>"
                "</method>"
                "<method name=\"SaveSecrets\">"
                "<arg name=\"connection\" type=\"a{sa{sv}}\" direction=\"in\"/>"
                "<arg name=\"connection_path\" type=\"o\" direction=\"in\"/>"
                "</method>"
                "<method name=\"DeleteSecrets\">"
                "<arg name=\"connection\" type=\"a{sa{sv}}\" direction=\"in\"/>"
                "<arg name=\"connection_path\" type=\"o\" direction=\"in\"/>"
                "</method></interface>")

  public:
    using Witness = std::function<std::optional<NativeNetworkCredentialWitness>(
        const NativeNetworkCredentialScope &)>;
    using Presentation = std::function<void(bool)>;

    NativeNetworkSecretAgent(PeerGuard &peers, SecretEntry &entry, Witness witness,
                             Presentation presentation, QObject *parent = nullptr);
    ~NativeNetworkSecretAgent() override;
    NativeNetworkSecretAgent(const NativeNetworkSecretAgent &) = delete;
    NativeNetworkSecretAgent &operator=(const NativeNetworkSecretAgent &) = delete;

    static void registerWireTypes();
    static QString objectPath();
    [[nodiscard]] bool arm(const NativeNetworkCredentialScope &scope,
                           const NativePeerIdentity &networkManager);
    [[nodiscard]] bool active() const noexcept;
    void cancel();

  public Q_SLOTS:
    void nativeNameOwnerChanged(const QString &name, const QString &oldOwner,
                                const QString &newOwner);
    void GetSecrets(const NativeNmSettings &connection, const QDBusObjectPath &connectionPath,
                    const QString &settingName, const QStringList &hints, quint32 flags);
    void CancelGetSecrets(const QDBusObjectPath &connectionPath, const QString &settingName);
    void SaveSecrets(const NativeNmSettings &connection, const QDBusObjectPath &connectionPath);
    void DeleteSecrets(const NativeNmSettings &connection, const QDBusObjectPath &connectionPath);

  private:
    [[nodiscard]] bool live() const;
    [[nodiscard]] bool profileMatches() const;
    [[nodiscard]] bool originalSessionSeat() const;
    [[nodiscard]] bool requestSettingsSafe(const NativeNmSettings &connection) const;
    void deliver();
    void retire(const QString &error);

    PeerGuard &peers_;
    SecretEntry &entry_;
    Witness witness_;
    Presentation presentation_;
    QTimer expiry_;
    std::optional<NativeNetworkCredentialScope> scope_;
    std::optional<NativePeerIdentity> manager_;
    std::unique_ptr<NativeNetworkCredentialSession> session_;
    std::optional<NativeNetworkSecretAgentCall> call_;
    std::optional<QDBusMessage> pending_;
    bool registered_ = false;
    bool retiring_ = false;
};

} // namespace Linura::SecurityOwner

Q_DECLARE_METATYPE(Linura::SecurityOwner::NativeNmSettings)
