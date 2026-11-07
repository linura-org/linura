#pragma once

#include "display_transaction.h"
#include "protected_frame.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

namespace Linura::HyprlandDisplay {

// An actual-native, comparison-only barrier for the first ordinary frames
// following a separately authorized RootRetiredHeld release attempt. It never
// authenticates Root/Control, executes release, unlocks S17/input, drops an
// inhibitor, or grants ordinary startup admission. Its caller MUST acquire the
// Snapshot and ProtectedFrame objects from the live pinned compositor, and
// independently join KMS, lock, Root and Control durable facts before handoff.
//
// The object owns a single irreversible spent transition: missing ACK, a
// configuration change or a repeated call cannot create new release authority.
class NativeFirstFrameGate final
{
  public:
    enum class Phase { Held, Spent, Verified, Faulted };
    static constexpr std::uint64_t MaxProofWindowMs = 2'000;

    struct Output final
    {
        OutputKey key;
        // Captured BEFORE native release is spent. All physical completions
        // must be strictly after this previous output-specific commit.
        std::uint64_t previousCommit = 0;
    };
    struct NativeFrame final
    {
        OutputKey key;
        const ProtectedFrame *frame = nullptr;
        // The actual current native buffer lease. A completed event for some
        // other buffer or an opaque safety frame never proves an ordinary one.
        const void *retainedBuffer = nullptr;
        // Disabled outputs cannot borrow a completed frame from an enabled
        // output. This must come from that output's native commit-result path.
        std::uint64_t disableCommit = 0;
        bool disableSubmitted = false;
    };
    struct Receipt final
    {
        std::uint64_t generation = 0, securityEpoch = 0, postWriteEpoch = 0;
        std::uint64_t observedUnixMs = 0, observedBootMs = 0;
        // Fixed, bounded receipts: no heap allocation or exception while
        // the physical output/input fence is being verified.
        std::array<std::pair<OutputKey, std::uint64_t>, DisplayTransaction::MaxHeads> completed{};
        std::size_t completedCount = 0;
    };

    struct ArmRequest final
    {
        const Snapshot &held;
        std::uint64_t postWriteEpoch;
        ClockSample sampled;
        const std::vector<Output> &before;
    };
    [[nodiscard]] static std::optional<NativeFirstFrameGate> arm(const ArmRequest &request)
    {
        const auto &held = request.held;
        const auto postWriteEpoch = request.postWriteEpoch;
        const auto sampled = request.sampled;
        const auto &before = request.before;
        if (!postWriteEpoch || !sampled.unixMs || !sampled.bootMs ||
            sampled.unixMs > std::numeric_limits<std::uint64_t>::max() - MaxProofWindowMs ||
            sampled.bootMs > std::numeric_limits<std::uint64_t>::max() - MaxProofWindowMs ||
            held.generation == 0 || held.securityEpoch == 0 ||
            (held.coverage != Coverage::Secure && held.coverage != Coverage::Unlocked) ||
            held.heads.empty() || held.heads.size() > DisplayTransaction::MaxHeads ||
            before.size() != held.heads.size())
            return {};
        Layout actual;
        actual.reserve(held.heads.size());
        bool poweredRoot = false;
        for (std::size_t i = 0; i < held.heads.size(); ++i) {
            const auto &head = held.heads[i];
            if (head.key != before[i].key || head.key.generation == 0 ||
                head.outputIdentityWitness.empty() || head.baseRuleWitness.empty() ||
                (i && before[i - 1].key.handle >= head.key.handle) ||
                (head.current.enabled &&
                 (!head.powered || (held.coverage == Coverage::Secure && !head.covered))))
                return {};
            actual.push_back(head.current);
            if (head.current.enabled && !head.current.mirror && head.powered)
                poweredRoot = true;
        }
        if (!poweredRoot || !DisplayTransaction::validLayout(actual, held))
            return {};
        return NativeFirstFrameGate(held, postWriteEpoch, sampled, before);
    }

    NativeFirstFrameGate(const NativeFirstFrameGate &) = delete;
    NativeFirstFrameGate &operator=(const NativeFirstFrameGate &) = delete;
    NativeFirstFrameGate(NativeFirstFrameGate &&) = default;
    NativeFirstFrameGate &operator=(NativeFirstFrameGate &&) = delete;

    // Called only AFTER the separately authenticated, durable Root/native
    // release grant was spent. Spending is irreversible even on disagreement.
    [[nodiscard]] bool spend(const Snapshot &current, ClockSample now) noexcept
    {
        if (phase_ != Phase::Held)
            return false;
        phase_ = Phase::Faulted;
        if (!currentSample(current, now))
            return false;
        phase_ = Phase::Spent;
        return true;
    }

    // This compares native physical evidence; it is never a durable release
    // receipt by itself. A missing first frame remains pending under the
    // ORIGINAL absolute deadline, not a new clock window.
    struct ObservationRequest final
    {
        const Snapshot &current;
        ClockSample now;
        const std::vector<NativeFrame> &frames;
    };
    [[nodiscard]] std::optional<Receipt> observe(const ObservationRequest &sample) noexcept
    {
        const auto &current = sample.current;
        const auto now = sample.now;
        const auto &frames = sample.frames;
        if (phase_ != Phase::Spent)
            return {};
        if (!currentSample(current, now) || frames.size() != before_.size()) {
            phase_ = Phase::Faulted;
            return {};
        }
        Receipt receipt{held_.generation, held_.securityEpoch, epoch_, now.unixMs, now.bootMs, {}};
        bool pending = false;
        for (std::size_t i = 0; i < before_.size(); ++i) {
            const auto &head = current.heads[i];
            const auto &frame = frames[i];
            if (frame.key != head.key) {
                phase_ = Phase::Faulted;
                return {};
            }
            if (head.current.enabled) {
                if (!frame.frame || !frame.retainedBuffer || frame.disableCommit ||
                    frame.disableSubmitted) {
                    phase_ = Phase::Faulted;
                    return {};
                }
                const auto commit = frame.frame->completedCommit();
                if (!commit) {
                    pending = true;
                    continue;
                }
                if (commit <= before_[i].previousCommit ||
                    frame.frame->queuedKind() != ProtectedFrame::Kind::Content ||
                    frame.frame->completedBuffer() != frame.retainedBuffer) {
                    phase_ = Phase::Faulted;
                    return {};
                }
                receipt.completed[receipt.completedCount++] = {head.key, commit};
            } else {
                if (frame.frame || frame.retainedBuffer) {
                    phase_ = Phase::Faulted;
                    return {};
                }
                if (!frame.disableSubmitted) {
                    pending = true;
                    continue;
                }
                if (frame.disableCommit == 0 || frame.disableCommit <= before_[i].previousCommit) {
                    phase_ = Phase::Faulted;
                    return {};
                }
                receipt.completed[receipt.completedCount++] = {head.key, frame.disableCommit};
            }
        }
        if (pending)
            return {};
        phase_ = Phase::Verified; // Still no authority to unlock or release.
        return receipt;
    }

    [[nodiscard]] Phase phase() const noexcept
    {
        return phase_;
    }
    void fault() noexcept
    {
        phase_ = Phase::Faulted;
    }

  private:
    NativeFirstFrameGate(const Snapshot &held, std::uint64_t epoch, ClockSample sampled,
                         const std::vector<Output> &before)
        : held_(held), epoch_(epoch), sampled_(sampled), before_(before)
    {}
    [[nodiscard]] bool currentSample(const Snapshot &current, ClockSample now) const noexcept
    {
        if (current != held_ || now.unixMs < sampled_.unixMs || now.bootMs < sampled_.bootMs)
            return false;
        if (now.unixMs >= sampled_.unixMs + MaxProofWindowMs)
            return false;
        if (now.bootMs >= sampled_.bootMs + MaxProofWindowMs)
            return false;
        return true;
    }

    Snapshot held_;
    std::uint64_t epoch_ = 0;
    ClockSample sampled_;
    std::vector<Output> before_;
    Phase phase_ = Phase::Held;
};

} // namespace Linura::HyprlandDisplay
