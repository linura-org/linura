#pragma once

#include "display_transaction.h"

#include <map>
#include <optional>
#include <string>

namespace Linura::HyprlandDisplay {

// Private native presentation/input lifetime. This never authenticates a human,
// approves a plan or grants an effect. The protected owner separately completes
// its purpose-bound authentication and Control retains sole managed authority.
class ProtectedInteraction final
{
  public:
    enum class Purpose { Apply, Keep, Revert };
    enum class Phase { Arming, Ready, Consumed, Cancelled };
    static constexpr std::uint64_t MaximumWindowMs = 60'000;
    static constexpr std::uint64_t DecisionWindowMs = 15'000;

    struct Scope final
    {
        std::string digest;
        Purpose purpose = Purpose::Apply;
        std::uint64_t deadlineUnixMs = 0;
        bool operator==(const Scope &) const = default;
    };
    ProtectedInteraction(const ProtectedInteraction &) = delete;
    ProtectedInteraction &operator=(const ProtectedInteraction &) = delete;
    ProtectedInteraction(ProtectedInteraction &&) noexcept;
    ProtectedInteraction &operator=(ProtectedInteraction &&) noexcept;

    [[nodiscard]] static std::optional<ProtectedInteraction>
    start(Scope, const Snapshot &, ClockSample, std::uint64_t epoch);
    [[nodiscard]] const Scope &scope() const noexcept;
    [[nodiscard]] Phase phase() const noexcept;
    [[nodiscard]] std::uint64_t epoch() const noexcept;
    // The compositor supplies these callbacks from actual owned surface and
    // backend objects. None is a wire setter accepting a client assertion.
    [[nodiscard]] bool configure(OutputKey, std::uint64_t serial);
    // Accepted backend commit IDs must strictly increase per output; reuse or
    // wrap makes this private interaction unsupported.
    [[nodiscard]] bool commit(OutputKey, std::uint64_t serial, std::uint64_t nativeCommitId);
    // A compositor-rendered opaque safety frame hides content but cannot keep
    // an old Ready proof alive or stand in for a newly presented owner frame.
    [[nodiscard]] bool safetyFrame(OutputKey);
    void presented(OutputKey, std::uint64_t nativeCommitId, bool hardwareCompleted);
    void focus(std::optional<OutputKey>);
    void inputReplaced();
    [[nodiscard]] bool refresh(const Snapshot &, ClockSample);
    // Both the owner and compositor use the current epoch as comparison data.
    // A saved epoch cannot survive focus, input, topology, configure or expiry.
    [[nodiscard]] bool eligible(std::uint64_t expectedEpoch, const Snapshot &, ClockSample);
    [[nodiscard]] bool consume(const Scope &, std::uint64_t expectedEpoch, const Snapshot &,
                               ClockSample);
    void cancel() noexcept;

  private:
    struct Frame final
    {
        std::uint64_t configure = 0, commit = 0, highWater = 0;
        bool presented = false;
    };
    ProtectedInteraction(Scope, Snapshot, ClockSample, std::uint64_t epoch);
    [[nodiscard]] bool advance() noexcept;
    void updateReady() noexcept;
    Scope scope_;
    Snapshot inventory_;
    ClockSample armed_;
    std::uint64_t deadlineBootMs_ = 0, epoch_ = 0;
    Phase phase_ = Phase::Arming;
    std::map<OutputKey, Frame> frames_;
    std::optional<OutputKey> focused_;
};

} // namespace Linura::HyprlandDisplay
