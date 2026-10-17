#pragma once

#include <QDBusConnection>
#include <QDBusMessage>
#include <QElapsedTimer>
#include <QString>

#include <optional>
#include "native_sleep_fence.h"

namespace Linura::SecurityOwner {

enum class NativePeerPurpose {
    ControlApproval,
    PreparedSessionDispatch,
    NativeAuthenticationDaemon
};

// Private native transport correlation, never exported as authority or a public
// capability. The sender comes from QDBusContext::message().service(), not args.
struct NativePeerIdentity final
{
    QString uniqueOwner;
    quint32 uid = 0;
    quint32 pid = 0;
    QString serviceInvocation;
    bool operator==(const NativePeerIdentity &) const = default;
};

struct NativeServiceFacts final
{
    QString sender;
    QString namedOwner;
    quint32 nativeUid = 0;
    quint32 nativePid = 0;
    quint32 mainPid = 0;
    QString invocation;
    QString activeState;
    QString subState;
    QString fragment;
    bool dropInsPresent = false;
    bool rootImmutableFragment = false;
    bool rootImmutableImage = false;
    bool exactNativeExecStart = false;
};

// Pure bounded identity check used after trusted native acquisition. It checks
// the supervised main process, not mere root/local UID or a claimed bus name.
[[nodiscard]] std::optional<NativePeerIdentity> bindNativeService(NativePeerPurpose purpose,
                                                                  quint32 expectedServiceUid,
                                                                  const NativeServiceFacts &facts);

class PeerGuard final
{
  public:
    ~PeerGuard();
    PeerGuard(const PeerGuard &) = delete;
    PeerGuard &operator=(const PeerGuard &) = delete;
    PeerGuard(PeerGuard &&other) noexcept;
    PeerGuard &operator=(PeerGuard &&other) noexcept;
    [[nodiscard]] static std::optional<PeerGuard> connect();
    [[nodiscard]] std::optional<NativePeerIdentity> attest(NativePeerPurpose purpose,
                                                           const QString &transportSender) const;
    [[nodiscard]] std::optional<NativePeerIdentity> namedPeer(NativePeerPurpose purpose) const;
    [[nodiscard]] bool stillCurrent(NativePeerPurpose purpose,
                                    const NativePeerIdentity &peer) const;
    [[nodiscard]] std::optional<NativeSleepUnitFacts> sleepUnitSnapshot() const;
    // Native composition only: this is the same canonical authenticated system
    // bus connection used by this guard, never a QML/client-supplied transport.
    [[nodiscard]] const QDBusConnection &nativeConnection() const noexcept
    {
        return connection_;
    }

  private:
    PeerGuard(QDBusConnection connection, QString name);
    [[nodiscard]] QDBusMessage call(QElapsedTimer &budget, const QString &owner,
                                    const QString &path, const QString &interface,
                                    const QString &method, const QList<QVariant> &arguments) const;
    QDBusConnection connection_;
    QString connectionName_;
};

} // namespace Linura::SecurityOwner
