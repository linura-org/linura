#pragma once

#include <cstdint>
#include <limits>
#include <optional>

namespace Linura::HyprlandDisplay {

// One live native Aquamarine IOutput's *complete subscribed commit-result*
// stream. This is not a protected-scene counter, a queued client ID, a KMS
// scanout receipt, or a release credential. The caller must separately bind
// the subscription lifetime to the exact native output and generation.
//
// Subscription starts without knowing the output's previous commit namespace.
// Until an accepted nonzero native result is seen, no claimed high-water may
// be used for release. Ambiguous, failed, replayed or reordered events
// permanently quarantine this subscription; reconnecting cannot reset an
// active Root/native one-use release attempt.
class NativeOutputCommitHistory final
{
  public:
    [[nodiscard]] bool observe(std::uint64_t nativeCommitId, bool submitted) noexcept
    {
        if (faulted_)
            return false;
        if (!submitted || nativeCommitId == 0 ||
            nativeCommitId == std::numeric_limits<std::uint64_t>::max() ||
            (seen_ && nativeCommitId <= highWater_)) {
            faulted_ = true;
            return false;
        }
        highWater_ = nativeCommitId;
        seen_ = true;
        return true;
    }

    [[nodiscard]] std::optional<std::uint64_t> highWater() const noexcept
    {
        return seen_ && !faulted_ ? std::optional{highWater_} : std::nullopt;
    }

    [[nodiscard]] bool faulted() const noexcept
    {
        return faulted_;
    }

  private:
    std::uint64_t highWater_ = 0;
    bool seen_ = false, faulted_ = false;
};

} // namespace Linura::HyprlandDisplay
