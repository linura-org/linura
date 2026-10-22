#include "native_approval.h"

#include <limits>
#include <utility>
#include <time.h>

namespace Linura::SecurityOwner {

NativeApproval::MonotonicClock NativeApproval::nativeBootTimeClock()
{
    return []() -> quint64 {
        timespec time{};
        constexpr quint64 maximum = std::numeric_limits<quint64>::max();
        if (clock_gettime(CLOCK_BOOTTIME, &time) != 0 || time.tv_sec < 0 || time.tv_nsec < 0 ||
            time.tv_nsec >= 1'000'000'000)
            return maximum; // Existing overflow guard terminally fails closed.
        const auto seconds = static_cast<quint64>(time.tv_sec);
        if (seconds > (maximum - ConversationMs - 999) / 1'000)
            return maximum;
        return seconds * 1'000 + static_cast<quint64>(time.tv_nsec) / 1'000'000;
    };
}

NativeApproval::NativeApproval(NativeLockIdentity identity)
    : NativeApproval(std::move(identity), nativeBootTimeClock())
{}

NativeApproval::NativeApproval(NativeLockIdentity identity, MonotonicClock clock)
    : identity_(std::move(identity)), clock_(std::move(clock))
{
    const auto parsed = NativeLockIdentity::parse(identity_.resource);
    if (!clock_ || !parsed || *parsed != identity_)
        state_ = State::Faulted;
}

std::optional<quint64> NativeApproval::now()
{
    if (state_ == State::Faulted)
        return std::nullopt;
    const quint64 value = clock_();
    if (value < lastNow_ || value > std::numeric_limits<quint64>::max() - ConversationMs) {
        reset(State::Faulted);
        return std::nullopt;
    }
    lastNow_ = value;
    if (deadline_ != 0 && value >= deadline_) {
        if (state_ == State::Confirming || state_ == State::Authenticating)
            deny(value);
        else
            reset(State::Idle);
    }
    return value;
}

NativeApproval::State NativeApproval::state()
{
    (void)now();
    return state_;
}

void NativeApproval::reset(State state)
{
    scope_.reset();
    deadline_ = 0;
    prompts_ = 0;
    state_ = state;
}

void NativeApproval::deny(quint64 time)
{
    reset(State::Cooldown);
    deadline_ = time + FailureCooldownMs;
}

bool NativeApproval::begin(const NativeApprovalScope &scope, bool compositorSecure)
{
    const auto time = now();
    if (!time || state_ != State::Idle || !scope.valid() || scope.lock != identity_)
        return false;
    if ((scope.purpose != ApprovalPurpose::ConfirmLock) != compositorSecure)
        return false;
    scope_ = scope;
    prompts_ = 0;
    state_ =
        scope.purpose == ApprovalPurpose::ConfirmLock ? State::Confirming : State::Authenticating;
    deadline_ = *time + ConversationMs;
    return true;
}

bool NativeApproval::matching(const NativeApprovalScope &scope, State state)
{
    return now() && state_ == state && scope_ && *scope_ == scope;
}

bool NativeApproval::confirmHuman(const NativeApprovalScope &scope)
{
    if (!matching(scope, State::Confirming))
        return false;
    state_ = State::Confirmed;
    deadline_ = lastNow_ + ProofMs;
    return true;
}

bool NativeApproval::nativePrompt(const NativeApprovalScope &scope)
{
    if (!matching(scope, State::Authenticating))
        return false;
    if (++prompts_ > MaximumConversationPrompts) {
        deny(lastNow_);
        return false;
    }
    return true;
}

bool NativeApproval::nativeCompleted(const NativeApprovalScope &scope, bool success)
{
    if (!matching(scope, State::Authenticating))
        return false;
    // A native authorization shortcut without any fresh PAM conversation is not
    // owner authentication. Only the official helper's completion path calls us.
    if (!success || prompts_ == 0) {
        deny(lastNow_);
        return false;
    }
    state_ = State::Confirmed;
    deadline_ = lastNow_ + ProofMs;
    return true;
}

bool NativeApproval::consume(const NativeApprovalScope &scope)
{
    if (!matching(scope, State::Confirmed))
        return false;
    reset(State::Idle);
    return true;
}

bool NativeApproval::advanceIdentity(const NativeLockIdentity &identity)
{
    if (!now() || state_ != State::Idle || scope_ ||
        identity_.generation == std::numeric_limits<quint64>::max())
        return false;
    auto next = identity_;
    ++next.generation;
    next.resource = next.resource.left(next.resource.lastIndexOf(QLatin1Char(':')) + 1) +
                    QString::number(next.generation);
    const auto parsed = NativeLockIdentity::parse(identity.resource);
    if (!parsed || *parsed != identity || identity != next)
        return false;
    identity_ = identity;
    return true;
}

void NativeApproval::cancel()
{
    if (const auto time = now(); time && state_ != State::Idle && state_ != State::Cooldown)
        deny(*time);
}

void NativeApproval::ownerLost()
{
    reset(State::Faulted);
}

} // namespace Linura::SecurityOwner
