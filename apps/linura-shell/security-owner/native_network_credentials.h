#pragma once

#include "native_scope.h"

#include <QMetaObject>
#include <QPointer>
#include <QString>
#include <QStringList>
#include <QtGlobal>

#include <functional>
#include <optional>

namespace Linura::SecurityOwner {

class SecretEntry;

// S18-4 private correlation material. Nothing here is a Polkit subject,
// proof of authenticated transport, policy decision, dispatch grant, profile
// secret, agent-registration key or authorization to talk to NetworkManager.
struct NativeNetworkCredentialScope final
{
    NativeLockIdentity lock;
    QString principal;
    QString operation;
    QString originalSender;
    QString systemBusId;
    QString networkManagerOwner;
    QString deviceObject;
    QString profileObject;
    QString profileFingerprint;
    QString requestDigest;
    QString reviewDigest;
    QString seat;
    quint64 settingsVersion = 0;
    bool persistRequested = false;

    [[nodiscard]] bool valid() const noexcept;
    bool operator==(const NativeNetworkCredentialScope &) const = default;
};

// The native owner must derive each value from real transport, logind, NM,
// Polkit and compositor observations. A caller-supplied Witness is NEVER an
// authority credential: this component is an additional restrictive fence.
struct NativeNetworkCredentialWitness final
{
    NativeLockIdentity lock;
    QString operation;
    QString originalSender;
    QString systemBusId;
    QString networkManagerOwner;
    QString deviceObject;
    QString profileObject;
    QString profileFingerprint;
    QString seat;
    quint64 settingsVersion = 0;
    bool activeLogindSession = false;
    bool exactPolkitSubject = false;
    bool protectedHumanConsent = false;
    bool secureCompositor = false;

    [[nodiscard]] bool matches(const NativeNetworkCredentialScope &scope) const noexcept;
};

// Exact public NetworkManager SecretAgent GetSecrets *metadata* only. No
// connection settings/secret map is accepted here. Source must originate from
// QDBusContext::message().service() on the real native system bus; a fabricated
// struct NEVER independently proves sender authenticity.
struct NativeNetworkSecretAgentCall final
{
    QString sender;
    QString profileObject;
    QString settingName;
    QStringList hints;
    quint32 flags = 0;

    [[nodiscard]] bool admissible(const NativeNetworkCredentialScope &scope,
                                  const NativeNetworkCredentialWitness &witness) const noexcept;
    bool operator==(const NativeNetworkSecretAgentCall &) const = default;
};

// One-time protected native input. Never a QObject/QML method; no secret or
// callback is retained. The eventual real NM SecretAgent adapter MUST itself
// attest the authenticated native sender and original Control authorization.
// This component cannot register or invoke an agent, send D-Bus traffic,
// persist a profile, or bypass the S18-3 network mutation deny fence.
class NativeNetworkCredentialSession final
{
  public:
    using BootClock = std::function<quint64()>;
    using NativeConsumer = std::function<void(const char *)>;
    enum class State { Idle, AwaitingProtectedInput, Spent, Cancelled, Faulted };
    static constexpr quint64 InputDeadlineMs = 30'000;

    explicit NativeNetworkCredentialSession(BootClock clock);
    ~NativeNetworkCredentialSession();
    NativeNetworkCredentialSession(const NativeNetworkCredentialSession &) = delete;
    NativeNetworkCredentialSession &operator=(const NativeNetworkCredentialSession &) = delete;

    [[nodiscard]] State state();
    [[nodiscard]] bool begin(const NativeNetworkCredentialScope &scope,
                             const NativeNetworkCredentialWitness &witness,
                             const NativeNetworkSecretAgentCall &call, SecretEntry &entry);
    [[nodiscard]] bool submit(const NativeNetworkCredentialScope &scope,
                              const NativeNetworkCredentialWitness &witness,
                              const NativeNetworkSecretAgentCall &call,
                              const NativeConsumer &consumer);
    [[nodiscard]] bool revalidate(const NativeNetworkCredentialWitness &witness);
    void cancel();

  private:
    [[nodiscard]] std::optional<quint64> currentTime();
    void detach() noexcept;

    BootClock clock_;
    State state_ = State::Idle;
    std::optional<NativeNetworkCredentialScope> scope_;
    std::optional<NativeNetworkSecretAgentCall> call_;
    QPointer<SecretEntry> entry_;
    QMetaObject::Connection cancellation_;
    QMetaObject::Connection destroyed_;
    quint64 lastNow_ = 0;
    quint64 deadline_ = 0;
};

} // namespace Linura::SecurityOwner
