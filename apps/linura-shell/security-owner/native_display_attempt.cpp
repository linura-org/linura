#include "native_display_attempt.h"

#include <algorithm>
#include <limits>

namespace Linura::SecurityOwner {
namespace {
bool digest(const QString &value)
{
    return value.size() == 64 && value != QString(64, QLatin1Char('0')) &&
           std::all_of(value.cbegin(), value.cend(), [](QChar c) {
               return (c >= QLatin1Char('0') && c <= QLatin1Char('9')) ||
                      (c >= QLatin1Char('a') && c <= QLatin1Char('f'));
           });
}
bool transactionId(const QString &value)
{
    return value.startsWith(QStringLiteral("transaction:")) && value.size() > 12 &&
           value.size() <= 256 && std::all_of(value.cbegin(), value.cend(), [](QChar c) {
               return (c >= QLatin1Char('a') && c <= QLatin1Char('z')) ||
                      (c >= QLatin1Char('0') && c <= QLatin1Char('9')) || c == QLatin1Char(':') ||
                      c == QLatin1Char('-');
           });
}
} // namespace

std::optional<NativeDisplayAttempt>
NativeDisplayAttempt::arm(const NativeDisplayIntent &intent, const QString &transaction,
                          const QString &effectDigest, const QString &dispatchDigest,
                          quint64 deadlineUnixMs, quint64 nowUnixMs, quint64 nowBootMs,
                          const NativeDisplaySnapshot &baseline, const QString &topology,
                          const NativeLockIdentity &lock, bool secure)
{
    // Reparse even typed programmatically constructed inputs to enforce the
    // canonical complete-intent shape before reserving a native attempt.
    const auto canonical = NativeDisplayIntent::parse(intent.encode());
    if (!canonical || !transactionId(transaction) || !digest(effectDigest) ||
        !digest(dispatchDigest) || nowUnixMs == 0 || nowBootMs == 0 ||
        deadlineUnixMs <= nowUnixMs || deadlineUnixMs - nowUnixMs > ConfirmationWindowMs ||
        nowBootMs > std::numeric_limits<quint64>::max() - (deadlineUnixMs - nowUnixMs) ||
        !intent.nativeOptions(baseline, topology, lock) ||
        !intent.baseline.matchesGeometry(baseline) ||
        intent.baseline.encode() == intent.desired.encode())
        return std::nullopt;
    NativeDisplayAttempt result;
    result.intent_ = *canonical;
    result.transaction_ = transaction;
    result.effectDigest_ = effectDigest;
    result.dispatchDigest_ = dispatchDigest;
    result.armedUnixMs_ = nowUnixMs;
    result.armedBootMs_ = nowBootMs;
    result.deadlineUnixMs_ = deadlineUnixMs;
    result.deadlineBootMs_ = nowBootMs + (deadlineUnixMs - nowUnixMs);
    result.initiallySecure_ = secure;
    if (!result.currentScope(baseline, topology, lock, secure))
        return std::nullopt;
    return result;
}

bool NativeDisplayAttempt::currentScope(const NativeDisplaySnapshot &snapshot,
                                        const QString &topology, const NativeLockIdentity &lock,
                                        bool secure) const
{
    // Acquiring protective coverage is permitted; losing existing coverage is
    // not. Runtime separately fences unlock and power while this attempt lives.
    return (!initiallySecure_ || secure) && intent_.nativeOptions(snapshot, topology, lock) &&
           (!secure || std::all_of(snapshot.heads.cbegin(), snapshot.heads.cend(),
                                   [](const auto &head) { return !head.enabled || head.covered; }));
}
bool NativeDisplayAttempt::recoveryDue(quint64 nowUnixMs, quint64 nowBootMs) const
{
    return (state_ == State::Armed || state_ == State::Pending) &&
           (nowUnixMs < armedUnixMs_ || nowBootMs < armedBootMs_ || nowUnixMs >= deadlineUnixMs_ ||
            nowBootMs >= deadlineBootMs_);
}
bool NativeDisplayAttempt::beginApply(quint64 nowUnixMs, quint64 nowBootMs,
                                      const NativeDisplaySnapshot &current, const QString &topology,
                                      const NativeLockIdentity &lock, bool secure)
{
    if (state_ != State::Armed || recoveryDue(nowUnixMs, nowBootMs) ||
        !currentScope(current, topology, lock, secure) ||
        !intent_.baseline.matchesGeometry(current))
        return false;
    state_ = State::Pending;
    return true;
}
bool NativeDisplayAttempt::beginRestore(const NativeDisplaySnapshot &current,
                                        const QString &topology, const NativeLockIdentity &lock,
                                        bool secure)
{
    if (state_ != State::Armed && state_ != State::Pending)
        return false;
    if (!currentScope(current, topology, lock, secure)) {
        state_ = State::RecoveryFailed;
        return false;
    }
    state_ = State::Restoring;
    return true;
}
bool NativeDisplayAttempt::confirm(const QString &transaction, const QString &dispatchDigest,
                                   quint64 nowUnixMs, quint64 nowBootMs,
                                   const NativeDisplayLayout &observed,
                                   const NativeDisplaySnapshot &snapshot, const QString &topology,
                                   const NativeLockIdentity &lock, bool secure)
{
    if (state_ != State::Pending || transaction != transaction_ ||
        dispatchDigest != dispatchDigest_ || recoveryDue(nowUnixMs, nowBootMs) ||
        !currentScope(snapshot, topology, lock, secure) ||
        observed.encode() != intent_.desired.encode() || !observed.matchesGeometry(snapshot))
        return false;
    state_ = State::Confirmed;
    return true;
}
bool NativeDisplayAttempt::verifyRestored(const NativeDisplayLayout &observed,
                                          const NativeDisplaySnapshot &snapshot,
                                          const QString &topology, const NativeLockIdentity &lock,
                                          bool secure)
{
    if ((state_ != State::Restoring && state_ != State::RecoveryFailed) ||
        !currentScope(snapshot, topology, lock, secure) ||
        observed.encode() != intent_.baseline.encode() || !observed.matchesGeometry(snapshot))
        return false;
    state_ = State::Restored;
    return true;
}
void NativeDisplayAttempt::recoveryFailed()
{
    if (state_ == State::Armed || state_ == State::Pending || state_ == State::Restoring)
        state_ = State::RecoveryFailed;
}
bool NativeDisplayAttempt::fenced() const noexcept
{
    return state_ != State::Confirmed && state_ != State::Restored;
}
} // namespace Linura::SecurityOwner
