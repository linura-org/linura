#pragma once

#include "native_scope.h"

#include <functional>
#include <optional>

namespace Linura::SecurityOwner {

// One bounded, ephemeral conversation in the security-owning native process.
// Not policy, a reusable credential, an executor permit, or a lock-state setter.
// All methods are C++-only; no QML method can assert native authentication success.
class NativeApproval final
{
  public:
    using MonotonicClock = std::function<quint64()>;
    enum class State { Idle, Confirming, Authenticating, Confirmed, Denied, Cooldown, Faulted };
    static constexpr quint64 ConversationMs = 60'000;
    static constexpr quint64 ProofMs = 2'000;
    static constexpr quint64 FailureCooldownMs = 5'000;
    static constexpr quint32 MaximumConversationPrompts = 8;

    explicit NativeApproval(NativeLockIdentity identity, MonotonicClock clock);
    explicit NativeApproval(NativeLockIdentity identity);
    // CLOCK_BOOTTIME includes suspend time. A normal Qt/CLOCK_MONOTONIC elapsed
    // timer must not preserve a two-second confirmation over hours asleep.
    [[nodiscard]] static MonotonicClock nativeBootTimeClock();
    NativeApproval(const NativeApproval &) = delete;
    NativeApproval &operator=(const NativeApproval &) = delete;

    [[nodiscard]] State state();
    [[nodiscard]] bool begin(const NativeApprovalScope &scope, bool compositorSecure);
    [[nodiscard]] bool confirmHuman(const NativeApprovalScope &scope);
    [[nodiscard]] bool nativePrompt(const NativeApprovalScope &scope);
    [[nodiscard]] bool nativeCompleted(const NativeApprovalScope &scope, bool success);
    [[nodiscard]] bool consume(const NativeApprovalScope &scope);
    // Trusted native runtime, after Control's verified release commit. Rotate
    // exactly one generation in the same invocation/epoch with no live proof.
    // Never a QML setter, authority grant, cooldown reset or session retarget.
    [[nodiscard]] bool advanceIdentity(const NativeLockIdentity &identity);
    void cancel();
    void ownerLost();

  private:
    [[nodiscard]] std::optional<quint64> now();
    [[nodiscard]] bool matching(const NativeApprovalScope &scope, State state);
    void deny(quint64 now);
    void reset(State state);

    NativeLockIdentity identity_;
    MonotonicClock clock_;
    State state_ = State::Idle;
    std::optional<NativeApprovalScope> scope_;
    quint64 lastNow_ = 0;
    quint64 deadline_ = 0;
    quint32 prompts_ = 0;
};

} // namespace Linura::SecurityOwner
