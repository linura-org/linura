#include "native_managed_lock_backend.h"
#include "native_lock_protocol.h"
#include <QThread>
#include <utility>
#include <unistd.h>

namespace Linura::SecurityOwner {
NativeManagedLockBackend::NativeManagedLockBackend(QObject *parent) : QObject(parent) {}
bool NativeManagedLockBackend::requestedSecure() const noexcept
{
    return requested_;
}
bool NativeManagedLockBackend::secureCoverage() const noexcept
{
    return coverage_;
}

bool NativeManagedLockBackend::installManagedEffectGate(EffectGate gate)
{
    if (thread() != QThread::currentThread() || gate_ || !gate || requested_ || coverage_)
        return false;
    gate_ = std::move(gate);
    return true;
}

void NativeManagedLockBackend::consumeNativeEffectGate(bool secure)
{
    if (thread() != QThread::currentThread() || !gate_)
        _exit(NativeLockProtocol::NativeLockFaultExit);
    try {
        if (!gate_(secure))
            _exit(NativeLockProtocol::NativeLockFaultExit);
    } catch (...) {
        _exit(NativeLockProtocol::NativeLockFaultExit);
    }
}

bool NativeManagedLockBackend::dispatchNative(bool secure)
{
    if (thread() != QThread::currentThread() || !gate_)
        return false;
    return applyNative(secure);
}

void NativeManagedLockBackend::publishNativeState(bool requested, bool coverage)
{
    if (thread() != QThread::currentThread() || (coverage && !requested))
        _exit(NativeLockProtocol::NativeLockFaultExit);
    if (requested_ == requested && coverage_ == coverage)
        return;
    requested_ = requested;
    coverage_ = coverage;
    Q_EMIT nativeStateChanged();
}
} // namespace Linura::SecurityOwner
