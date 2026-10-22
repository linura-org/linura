#pragma once
#include "native_scope.h"
#include <QDBusMessage>
#include <optional>

namespace Linura::SecurityOwner {
// Historical client status only. No value here is native coverage, approval,
// authentication success, or permission to release a compositor lock.
enum class NativeUnlockRecoveryStep { ObserveOnly, AcknowledgeCommitted, Aborted, Stop };
// A completed error from the exact Control peer is only a definitive
// pre-authorization rejection when no native proof was consumed or remains
// armed. Caller must separately attest the peer and fresh locked coverage.
[[nodiscard]] bool definitiveNativeUnlockReject(const QDBusMessage &reply, bool used, bool armed);
[[nodiscard]] std::optional<NativeUnlockRecoveryStep>
validateNativeUnlockStatus(const QString &request, const QString &transaction,
                           const QString &resource, bool secure, const QString &state,
                           const QString &expectedRequest, const NativeLockIdentity &expectedLock);
[[nodiscard]] std::optional<NativeUnlockRecoveryStep>
decodeNativeUnlockStatus(const QDBusMessage &reply, const QString &expectedRequest,
                         const NativeLockIdentity &expectedLock);

enum class NativeTransitionRecoveryStep { ObserveOnly, AcknowledgeCommitted, Stop };
[[nodiscard]] std::optional<NativeTransitionRecoveryStep>
validateNativeTransitionStatus(const QString &request, const QString &transaction,
                               const QString &resource, const QString &state,
                               const QString &expectedRequest,
                               const NativeTransitionIdentity &expectedTarget);
[[nodiscard]] std::optional<NativeTransitionRecoveryStep>
decodeNativeTransitionStatus(const QDBusMessage &reply, const QString &expectedRequest,
                             const NativeTransitionIdentity &expectedTarget);
} // namespace Linura::SecurityOwner
