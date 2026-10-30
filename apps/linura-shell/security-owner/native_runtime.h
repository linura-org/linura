#pragma once

#include "native_scope.h"
#include "native_sleep_fence.h"
#include "native_startup.h"
#include "compositor_probe.h"
#include "lock_mechanism.h"
#include "native_display_connection.h"

#include <QDBusMessage>
#include <QObject>
#include <memory>
#include <optional>

namespace Linura::SecurityOwner {

enum class NativePeerPurpose;

enum class NativeObservedLockState { Unlocked, Secure, Acquiring, Releasing };
struct NativeDisplaySample final
{
    QString resource, compositor, seat, topology, monitors;
    bool secure = false;
    [[nodiscard]] QString correlationDigest() const;
};
struct NativeDisplayAttemptSample final
{
    QString lock, topology, transaction;
    quint64 deadlineUnixMs = 0;
    quint32 phase = 7;
    bool secure = false;
};
[[nodiscard]] std::optional<NativeObservedLockState>
nativeObservedLockState(NativeCompositorLockState compositor, LockMechanism::State mechanism,
                        bool requested, bool coverage);

// Private security-owning composition, never registered with QML. The sole
// constructor consumes real secure-exec startup, attests the actual connection,
// then creates and retains all effect/authentication handles outside the scene.
// Transport adapters must pass the received message, not caller-authored identity.
class NativeRuntime final : public QObject
{
    Q_OBJECT
  public:
    [[nodiscard]] static std::unique_ptr<NativeRuntime> create(NativeStartup startup);
    ~NativeRuntime() override;
    [[nodiscard]] const NativeLockIdentity &identity() const noexcept;
    [[nodiscard]] bool armApproval(const QDBusMessage &received, const NativeApprovalScope &scope);
    [[nodiscard]] bool consumeApproval(const QDBusMessage &received,
                                       const NativeApprovalScope &scope);
    [[nodiscard]] bool armDisplayApproval(const QDBusMessage &, const NativeApprovalScope &);
    [[nodiscard]] std::optional<bool> displayApprovalReady(const QDBusMessage &,
                                                           const NativeApprovalScope &);
    [[nodiscard]] bool consumeDisplayApproval(const QDBusMessage &, const NativeApprovalScope &);
    [[nodiscard]] bool cancelDisplayApproval(const QDBusMessage &, const NativeApprovalScope &);
    [[nodiscard]] bool dispatchPrepared(const QDBusMessage &received,
                                        const NativeLockIdentity &identity, bool secure);
    [[nodiscard]] std::optional<NativeObservedLockState> observe(const QDBusMessage &received);
    [[nodiscard]] std::optional<NativeDisplaySample> observeDisplay(const QDBusMessage &received);
    [[nodiscard]] std::optional<NativeDisplaySample>
    observePreparedDisplay(const QDBusMessage &received);
    [[nodiscard]] std::optional<quint32>
    dispatchPreparedDisplay(const QDBusMessage &, const NativeDisplayIntent &,
                            const NativeDisplayCorrelation &, const QString &sampleDigest,
                            quint64 sampledBootMs, const QString &nativeBaselineGuard);
    [[nodiscard]] std::optional<quint32> continuePreparedDisplay(const QDBusMessage &,
                                                                 const NativeDisplayIntent &,
                                                                 const NativeDisplayDecision &);
    [[nodiscard]] std::optional<NativeDisplayAttemptSample>
    observeDisplayAttempt(const QDBusMessage &, const NativeDisplayIntent &,
                          const NativeDisplayCorrelation &);
    [[nodiscard]] bool fencePreparedTransition(const QDBusMessage &received,
                                               const NativeTransitionIdentity &target);
    [[nodiscard]] bool cancelUndispatchedTransition(const QDBusMessage &received,
                                                    const NativeTransitionIdentity &target);
    [[nodiscard]] bool commitVerifiedTransition(const QDBusMessage &received,
                                                const NativeTransitionIdentity &target);
    [[nodiscard]] bool fenceSleepEntry(const QDBusMessage &received,
                                       const NativeSleepEntryIdentity &event,
                                       const NativeLockIdentity &lock);
    [[nodiscard]] std::optional<QString>
    observePowerPermission(const QDBusMessage &received, const NativeTransitionIdentity &identity);
    [[nodiscard]] bool verifyReleased(const QDBusMessage &received,
                                      const NativeLockIdentity &identity);
    [[nodiscard]] bool retainedVerifiedRelease(const QDBusMessage &received,
                                               const NativeLockIdentity &identity);
    [[nodiscard]] bool commitVerifiedRelease(const QDBusMessage &received,
                                             const NativeLockIdentity &identity);
    void cancelApproval(const QDBusMessage &received);
    // Export only the private adapter on this same canonical system-bus
    // connection. No well-known per-user name that another user can preclaim.
    [[nodiscard]] bool exportNativeEndpoint();

  Q_SIGNALS:
    // Notification only. No signal payload or UI event becomes approval or a
    // prepared dispatch. Control must consume/revalidate the exact challenge.
    void approvalInteractionCompleted();

  private:
    NativeRuntime();
    [[nodiscard]] bool initialize(NativeStartup startup);
    void requestNativeUnlock();
    void recoverNativeUnlock();
    void recoverNativeTransition();
    void recoverNativeSleepEntry();
    [[nodiscard]] std::optional<NativeDisplaySample> displaySample(const QDBusMessage &received,
                                                                   NativePeerPurpose purpose);
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace Linura::SecurityOwner
