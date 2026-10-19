#include "native_lock_protocol.h"

#include "native_approval.h"
#include "native_managed_lock_backend.h"

#include <QThread>

#include <chrono>
#include <limits>
#include <utility>
#include <unistd.h>

namespace Linura::SecurityOwner {

NativeLockProtocol::NativeLockProtocol(NativeManagedLockBackend &protocol,
                                       NativeLockIdentity identity)
    : NativeLockProtocol(protocol, std::move(identity), NativeApproval::nativeBootTimeClock())
{}

NativeLockProtocol::NativeLockProtocol(NativeManagedLockBackend &protocol,
                                       NativeLockIdentity identity, Clock clock)
    : mechanism_(std::move(identity)), clock_(std::move(clock))
{
    if (!clock_ || mechanism_.state() != LockMechanism::State::Ready || !bind(protocol)) {
        mechanism_.ownerLost();
        return;
    }
    bound_ = true;
    timer_.setInterval(25);
    timer_.setTimerType(Qt::PreciseTimer);
    QObject::connect(&timer_, &QTimer::timeout, this, &NativeLockProtocol::nativeChanged);
    refresh();
    timer_.start();
}

NativeLockProtocol::~NativeLockProtocol()
{
    // Never unwind an active lock through QObject/Wayland cleanup. A normal
    // shutdown is permitted only after the durable verified-release fence.
    if (bound_ && mechanism_.state() != LockMechanism::State::Ready)
        terminateInvocation();
    bound_ = false;
    timer_.stop();
    QObject::disconnect(stateConnection_);
    QObject::disconnect(destroyedConnection_);
}

bool NativeLockProtocol::bind(NativeManagedLockBackend &protocol)
{
    if (thread() != QThread::currentThread() || protocol.thread() != thread())
        return false;
    const QMetaObject *native = &NativeManagedLockBackend::staticMetaObject;
    const int locked = native->indexOfProperty("locked");
    const int secure = native->indexOfProperty("secure");
    // Neither inherited properties nor QML aliases/shadowed properties may
    // replace the native mechanism's read-only state pair. Effects use C++ only.
    if (locked < native->propertyOffset() || secure < native->propertyOffset() ||
        protocol.metaObject()->indexOfProperty("locked") != locked ||
        protocol.metaObject()->indexOfProperty("secure") != secure)
        return false;
    if (native->property(locked).isWritable() || native->property(secure).isWritable())
        return false;
    if (protocol.requestedSecure() || protocol.secureCoverage())
        return false; // Never adopt somebody else's existing native lock.
    protocol_ = &protocol;
    metadata_ = protocol.metaObject();
    stateConnection_ =
        QObject::connect(&protocol, &NativeManagedLockBackend::nativeStateChanged, this,
                         &NativeLockProtocol::nativeChanged, Qt::DirectConnection);
    destroyedConnection_ = QObject::connect(
        &protocol, &QObject::destroyed, this,
        [this] {
            terminateInvocation(); // A binding is never reloadable, even when idle.
        },
        Qt::DirectConnection);
    if (!stateConnection_ || !destroyedConnection_)
        return false;
    const QPointer<NativeLockProtocol> owner(this);
    return protocol.installManagedEffectGate([owner](bool secure) {
        if (!owner)
            _exit(NativeLockFaultExit);
        return owner->permitNativeEffect(secure);
    });
}

bool NativeLockProtocol::bound() const noexcept
{
    return bound_;
}
const NativeLockIdentity &NativeLockProtocol::identity() const noexcept
{
    return mechanism_.identity();
}

[[noreturn]] void NativeLockProtocol::terminateInvocation()
{
    mechanism_.ownerLost();
    // No exception, log, QObject destructor or unlock-and-destroy on this path.
    _exit(NativeLockFaultExit);
}

void NativeLockProtocol::beginDeadline(quint64 durationMs)
{
    if (deadline_ != 0 || watchdog_ || lastNow_ > std::numeric_limits<quint64>::max() - durationMs)
        terminateInvocation();
    deadline_ = lastNow_ + durationMs;
    // Also bound a blocked Qt/native call: a Qt timer alone cannot do that.
    try {
        watchdog_ = std::make_unique<NativeDeadline>(std::chrono::milliseconds(durationMs));
    } catch (...) {
        terminateInvocation(); // Residency/thread exhaustion cannot unwind a lock.
    }
}

void NativeLockProtocol::clearDeadline()
{
    deadline_ = 0;
    watchdog_.reset();
}

void NativeLockProtocol::nativeChanged()
{
    refresh();
}

void NativeLockProtocol::refresh()
{
    if (!bound_)
        return;
    if (thread() != QThread::currentThread() || !protocol_ || protocol_->thread() != thread() ||
        protocol_->metaObject() != metadata_)
        terminateInvocation();
    checkClock();
    const bool locked = protocol_->requestedSecure();
    const bool secure = protocol_->secureCoverage();
    switch (mechanism_.state()) {
    case LockMechanism::State::Ready:
    case LockMechanism::State::Released:
        if (locked || secure)
            terminateInvocation();
        break;
    case LockMechanism::State::Acquiring:
    case LockMechanism::State::Secure:
        if (!locked)
            terminateInvocation();
        break;
    case LockMechanism::State::Releasing:
        // Native release acknowledgement is not independent verification.
        if (secure && !locked)
            terminateInvocation();
        break;
    case LockMechanism::State::Faulted:
        terminateInvocation();
    }
    mechanism_.compositorCoverage(secure);
    if (mechanism_.state() == LockMechanism::State::Faulted)
        terminateInvocation();
    if (mechanism_.state() == LockMechanism::State::Secure ||
        (mechanism_.state() == LockMechanism::State::Releasing && !locked && !secure))
        clearDeadline();
}

void NativeLockProtocol::checkClock()
{
    quint64 now = 0;
    try {
        now = clock_(); // CLOCK_BOOTTIME includes suspended time.
    } catch (...) {
        terminateInvocation();
    }
    if (now < lastNow_ || now > std::numeric_limits<quint64>::max() - AcquisitionMs ||
        (deadline_ != 0 && now >= deadline_))
        terminateInvocation();
    lastNow_ = now;
}

LockMechanism::State NativeLockProtocol::inspect()
{
    refresh();
    return mechanism_.state();
}

bool NativeLockProtocol::dispatch(const NativeLockIdentity &identity, bool secure)
{
    if (!bound_ || dispatching_)
        return false;
    refresh();
    if (!mechanism_.dispatch(identity, secure))
        return false;
    beginDeadline(secure ? AcquisitionMs : ReleaseMs);
    dispatching_ = true;
    effectConsumed_ = false;
    dispatchSecure_ = secure;
    try {
        if (!protocol_->dispatchNative(secure) || !effectConsumed_)
            terminateInvocation();
    } catch (...) {
        terminateInvocation();
    }
    dispatching_ = false;
    refresh();
    return true; // Dispatch acknowledgement only, never a verified postcondition.
}

bool NativeLockProtocol::permitNativeEffect(bool secure)
{
    if (!bound_ || thread() != QThread::currentThread() || !protocol_ ||
        protocol_->thread() != thread() || protocol_->metaObject() != metadata_ || !dispatching_ ||
        effectConsumed_ || secure != dispatchSecure_ || secure != mechanism_.requestedSecure())
        terminateInvocation();
    checkClock(); // Recheck immediately BEFORE the wire effect, including resume.
    effectConsumed_ = true;
    return true; // One native call frame, not an exported approval/credential.
}

bool NativeLockProtocol::independentlyVerifiedReleased(const NativeLockIdentity &identity)
{
    if (!bound_)
        return false;
    refresh();
    if (protocol_->requestedSecure() || deadline_ != 0)
        return false;
    return mechanism_.independentlyVerifiedReleased(identity);
}

bool NativeLockProtocol::commitVerifiedRelease(const NativeLockIdentity &identity)
{
    if (!bound_)
        return false;
    refresh();
    const bool committed = mechanism_.commitVerifiedRelease(identity);
    if (mechanism_.state() == LockMechanism::State::Faulted)
        terminateInvocation();
    return committed;
}

} // namespace Linura::SecurityOwner
