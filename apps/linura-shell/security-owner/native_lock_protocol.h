#pragma once

#include "lock_mechanism.h"
#include "native_deadline.h"
#include "native_managed_lock_backend.h"

#include <QMetaProperty>
#include <QObject>
#include <QPointer>
#include <QTimer>

#include <functional>
#include <memory>

namespace Linura::SecurityOwner {

// Private native binding to the root-owned runtime's typed owned backend.
// Metadata validates adapter compatibility, NOT object provenance: the production
// factory must create and retain this object in its immutable, extension-free
// runtime after ProcessGuard/SessionBootstrap. Neither the protocol QObject nor
// this binding is registered with QML or returned to an ordinary shell/client.
// The attested transport invokes dispatch only for a revalidated prepared effect.
class NativeLockProtocol final : public QObject
{
    Q_OBJECT
  public:
    using Clock = std::function<quint64()>;
    static constexpr quint64 AcquisitionMs = 5'000;
    static constexpr quint64 ReleaseMs = 2'000;
    static constexpr int NativeLockFaultExit = 72;

    NativeLockProtocol(NativeManagedLockBackend &protocol, NativeLockIdentity identity);
    // Native clock injection is solely for deterministic component tests.
    NativeLockProtocol(NativeManagedLockBackend &protocol, NativeLockIdentity identity,
                       Clock clock);
    ~NativeLockProtocol() override;

    [[nodiscard]] bool bound() const noexcept;
    [[nodiscard]] const NativeLockIdentity &identity() const noexcept;
    [[nodiscard]] LockMechanism::State inspect();
    [[nodiscard]] bool dispatch(const NativeLockIdentity &identity, bool secure);
    // Only the native transport can deliver independent canonical verification
    // and Control's durable verified-commit acknowledgement. No local callback,
    // authentication success or native false property supplies either proof.
    [[nodiscard]] bool independentlyVerifiedReleased(const NativeLockIdentity &identity);
    [[nodiscard]] bool commitVerifiedRelease(const NativeLockIdentity &identity);

  private Q_SLOTS:
    void nativeChanged();

  private:
    [[nodiscard]] bool bind(NativeManagedLockBackend &protocol);
    void refresh();
    void checkClock();
    void beginDeadline(quint64 durationMs);
    void clearDeadline();
    [[nodiscard]] bool permitNativeEffect(bool secure);
    [[noreturn]] void terminateInvocation();

    LockMechanism mechanism_;
    Clock clock_;
    QPointer<NativeManagedLockBackend> protocol_;
    const QMetaObject *metadata_ = nullptr;
    QMetaObject::Connection stateConnection_;
    QMetaObject::Connection destroyedConnection_;
    QTimer timer_;
    std::unique_ptr<NativeDeadline> watchdog_;
    quint64 lastNow_ = 0;
    quint64 deadline_ = 0;
    bool bound_ = false;
    bool dispatching_ = false;
    bool effectConsumed_ = false;
    bool dispatchSecure_ = false;
};

} // namespace Linura::SecurityOwner
