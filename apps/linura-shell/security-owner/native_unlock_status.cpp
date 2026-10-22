#include "native_unlock_status.h"
#include <QDBusArgument>

namespace Linura::SecurityOwner {
std::optional<NativeUnlockRecoveryStep>
validateNativeUnlockStatus(const QString &request, const QString &transaction,
                           const QString &resource, bool secure, const QString &state,
                           const QString &expectedRequest, const NativeLockIdentity &expectedLock)
{
    const auto canonical = NativeLockIdentity::parse(resource);
    if (!canonical || *canonical != expectedLock || secure || request != expectedRequest ||
        !request.startsWith(QLatin1String("request:v010:session-lock:")) || request.size() > 96 ||
        !transaction.startsWith(QLatin1String("transaction:v1:")) || transaction.size() != 79)
        return std::nullopt;
    for (QChar c : QStringView(transaction).mid(15)) {
        const auto code = c.unicode();
        if (!((code >= '0' && code <= '9') || (code >= 'a' && code <= 'f')))
            return std::nullopt;
    }
    if (state == QLatin1String("committed"))
        return NativeUnlockRecoveryStep::AcknowledgeCommitted;
    if (state == QLatin1String("verified") || state == QLatin1String("indeterminate"))
        return NativeUnlockRecoveryStep::ObserveOnly;
    if (state == QLatin1String("aborted"))
        return NativeUnlockRecoveryStep::Aborted;
    if (state == QLatin1String("prepared") || state == QLatin1String("recovery-blocked"))
        return NativeUnlockRecoveryStep::Stop;
    return std::nullopt;
}

std::optional<NativeUnlockRecoveryStep>
decodeNativeUnlockStatus(const QDBusMessage &reply, const QString &expectedRequest,
                         const NativeLockIdentity &expectedLock)
{
    if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().size() != 1 ||
        reply.arguments().front().metaType() != QMetaType::fromType<QDBusArgument>())
        return std::nullopt;
    const auto argument = qvariant_cast<QDBusArgument>(reply.arguments().front());
    if (argument.currentSignature() != QLatin1String("(sssbs)"))
        return std::nullopt;
    QString request, transaction, resource, state;
    bool secure = true;
    argument.beginStructure();
    argument >> request >> transaction >> resource >> secure >> state;
    argument.endStructure();
    return validateNativeUnlockStatus(request, transaction, resource, secure, state,
                                      expectedRequest, expectedLock);
}

bool definitiveNativeUnlockReject(const QDBusMessage &reply, bool nativeProofConsumed,
                                  bool nativeScopeActive)
{
    return !nativeProofConsumed && !nativeScopeActive &&
           reply.type() == QDBusMessage::ErrorMessage &&
           reply.errorName() == QLatin1String("org.freedesktop.DBus.Error.Failed");
}

std::optional<NativeTransitionRecoveryStep>
validateNativeTransitionStatus(const QString &request, const QString &transaction,
                               const QString &resource, const QString &state,
                               const QString &expectedRequest,
                               const NativeTransitionIdentity &expectedTarget)
{
    const auto target = NativeTransitionIdentity::parse(resource);
    if (!target || *target != expectedTarget ||
        target->transition != NativeSessionTransition::Suspend || request != expectedRequest ||
        request.size() > 96 ||
        !request.startsWith(QLatin1String("request:v010:session-transition:")) ||
        transaction.size() != 79 || !transaction.startsWith(QLatin1String("transaction:v1:")))
        return std::nullopt;
    const auto operation =
        QStringView(request).mid(QStringView(u"request:v010:session-transition:").size());
    if (operation.empty() || operation.size() > 64 || operation.front() == QLatin1Char('-') ||
        operation.back() == QLatin1Char('-') || operation.contains(QLatin1String("--")))
        return std::nullopt;
    for (QChar c : operation) {
        const auto code = c.unicode();
        if (!((code >= 'a' && code <= 'z') || (code >= '0' && code <= '9') || code == '-'))
            return std::nullopt;
    }
    for (QChar c : QStringView(transaction).mid(15)) {
        const auto code = c.unicode();
        if (!((code >= '0' && code <= '9') || (code >= 'a' && code <= 'f')))
            return std::nullopt;
    }
    if (state == QLatin1String("committed"))
        return NativeTransitionRecoveryStep::AcknowledgeCommitted;
    if (state == QLatin1String("verified") || state == QLatin1String("indeterminate"))
        return NativeTransitionRecoveryStep::ObserveOnly;
    if (state == QLatin1String("prepared") || state == QLatin1String("aborted") ||
        state == QLatin1String("recovery-blocked"))
        return NativeTransitionRecoveryStep::Stop;
    return std::nullopt;
}

std::optional<NativeTransitionRecoveryStep>
decodeNativeTransitionStatus(const QDBusMessage &reply, const QString &expectedRequest,
                             const NativeTransitionIdentity &expectedTarget)
{
    if (reply.type() != QDBusMessage::ReplyMessage || reply.arguments().size() != 1 ||
        reply.arguments().front().metaType() != QMetaType::fromType<QDBusArgument>())
        return std::nullopt;
    const auto argument = qvariant_cast<QDBusArgument>(reply.arguments().front());
    if (argument.currentSignature() != QLatin1String("(ssss)"))
        return std::nullopt;
    QString request, transaction, resource, state;
    argument.beginStructure();
    argument >> request >> transaction >> resource >> state;
    argument.endStructure();
    return validateNativeTransitionStatus(request, transaction, resource, state, expectedRequest,
                                          expectedTarget);
}
} // namespace Linura::SecurityOwner
