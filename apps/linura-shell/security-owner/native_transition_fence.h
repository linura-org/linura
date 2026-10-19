#pragma once

#include "native_scope.h"
#include <optional>
#include <string_view>

namespace Linura::SecurityOwner {

// Coverage fence only, not planning or execution authority. Once the separately
// attested executor starts a prepared transition, no new conversation or unlock
// may race a delayed native sleep/shutdown. Never expire this on a UI timer.
class NativeTransitionFence final
{
  public:
    [[nodiscard]] bool active() const noexcept
    {
        return pending_.has_value();
    }
    [[nodiscard]] bool coversSuspend(const NativeLockIdentity &current, quint64 cycles) const
    {
        return pending_ && pending_->lock == current &&
               pending_->transition == NativeSessionTransition::Suspend &&
               pending_->successfulCyclesBefore == cycles;
    }
    [[nodiscard]] bool arm(const NativeTransitionIdentity &target,
                           const NativeLockIdentity &current, bool independentlySecure,
                           std::optional<quint64> successfulCycles);
    // Runtime exposes this ONLY to the exact executor, which must know it did
    // not invoke/queue the OS effect, including a definite authenticated native
    // pre-queue rejection. Timeout/lost reply is not such knowledge.
    [[nodiscard]] bool cancelUndispatched(const NativeTransitionIdentity &target);
    // Runtime supplies a fresh kernel counter and independent current coverage;
    // neither a Control acknowledgement nor its boolean proves completion.
    [[nodiscard]] bool commitSuspend(const NativeTransitionIdentity &target,
                                     const NativeLockIdentity &current, bool independentlySecure,
                                     std::optional<quint64> successfulCycles);

  private:
    std::optional<NativeTransitionIdentity> pending_;
    std::optional<NativeTransitionIdentity> committed_;
};

// Fixed, bounded, non-following sysfs reads. No caller-supplied path; dry-run
// suspend mode, non-sysfs substitution, malformed/overflowing counters fail.
[[nodiscard]] std::optional<quint64> nativeSuccessfulSuspendCycles();
// Adapter-private decoder, separated for negative tests. Bytes alone never
// become authoritative; the production reader attests fixed sysfs descriptors.
[[nodiscard]] std::optional<quint64> decodeNativeSuspendCycles(std::string_view testMode,
                                                               std::string_view counter);

} // namespace Linura::SecurityOwner
