#pragma once

#include "native_first_frame_gate.h"

namespace Linura::HyprlandDisplay {

// Comparison only, after the separately authenticated physical handoff. This
// cannot spend Root authority, retire input/power/startup or complete Control.
// A current ordinary desktop may advance frames; a frozen first-frame receipt
// must never be mistaken for current scanout after input routing changes.
class NativeCurrentFrameGate final
{
  public:
    using Output = NativeFirstFrameGate::Output;
    using Kernel = NativeFirstFrameGate::NativeScanout;
    using Frame = NativeFirstFrameGate::NativeFrame;
    using Receipt = NativeFirstFrameGate::Receipt;
    enum class Phase { Armed, Active, Faulted };
    struct Arm final
    {
        const Snapshot &held;
        const Receipt &first;
        ClockSample now;
        const std::vector<Output> &commits;
        const std::vector<Kernel> &kernel;
    };
    [[nodiscard]] static std::optional<NativeCurrentFrameGate> arm(const Arm &request)
    {
        const auto &held = request.held;
        const auto &first = request.first;
        const auto count = held.heads.size();
        if (!held.generation || !held.securityEpoch || !first.postWriteEpoch ||
            first.generation != held.generation || first.securityEpoch != held.securityEpoch ||
            !count || count > DisplayTransaction::MaxHeads || first.completedCount != count ||
            request.commits.size() != count || request.kernel.size() != count ||
            !validClock(request.now) || !first.observedUnixMs || !first.observedBootMs ||
            first.deadlineUnixMs <= first.observedUnixMs ||
            first.deadlineBootMs <= first.observedBootMs ||
            first.deadlineUnixMs - first.observedUnixMs > 2000 ||
            first.deadlineBootMs - first.observedBootMs > 2000 ||
            request.now.unixMs < first.observedUnixMs ||
            request.now.bootMs < first.observedBootMs ||
            request.now.unixMs >= first.deadlineUnixMs ||
            request.now.bootMs >= first.deadlineBootMs)
            return {};
        bool visible = false;
        Layout actual;
        for (std::size_t i = 0; i < count; ++i) {
            const auto &head = held.heads[i];
            const auto &row = first.completed[i];
            const auto &physical = request.kernel[i];
            actual.push_back(head.current);
            if (!head.key.handle || !head.key.generation || row.kernel.key != head.key ||
                !row.kernel.connector || !row.spendHighWater ||
                row.completedCommit <= row.spendHighWater ||
                row.completedCommit == std::numeric_limits<std::uint64_t>::max() ||
                physical != row.kernel || request.commits[i].key != head.key ||
                request.commits[i].previousCommit != row.completedCommit ||
                physical.active != head.current.enabled || head.outputIdentityWitness.empty() ||
                head.baseRuleWitness.empty() ||
                (i && held.heads[i - 1].key.handle >= head.key.handle))
                return {};
            if (physical.active) {
                if (!head.powered || !physical.crtc || !physical.plane || !physical.framebuffer)
                    return {};
                visible = visible || !head.current.mirror;
            } else if (physical.crtc || physical.plane || physical.framebuffer) {
                return {};
            }
            for (std::size_t prior = 0; prior < i; ++prior)
                if (first.completed[prior].kernel.connector == physical.connector)
                    return {};
        }
        if (!visible || !DisplayTransaction::validLayout(actual, held) ||
            (held.coverage != Coverage::Secure && held.coverage != Coverage::Unlocked))
            return {};
        return NativeCurrentFrameGate(held, first, request.now);
    }
    NativeCurrentFrameGate(const NativeCurrentFrameGate &) = delete;
    NativeCurrentFrameGate &operator=(const NativeCurrentFrameGate &) = delete;
    NativeCurrentFrameGate(NativeCurrentFrameGate &&other) noexcept
        : held_(std::move(other.held_)), first_(other.first_), last_(other.last_),
          lastCommits_(other.lastCommits_), phase_(std::exchange(other.phase_, Phase::Faulted))
    {}
    NativeCurrentFrameGate &operator=(NativeCurrentFrameGate &&) = delete;

    // Called at the actual native input/startup handoff boundary, under the
    // separate one-use Root grant. A missing ACK cannot activate this later.
    [[nodiscard]] bool activate(const Snapshot &held, ClockSample now,
                                const std::vector<Output> &commits,
                                const std::vector<Kernel> &kernel) noexcept
    {
        if (phase_ != Phase::Armed)
            return false;
        phase_ = Phase::Faulted;
        if (held != held_ || !clock(now) || now.unixMs >= first_.deadlineUnixMs ||
            now.bootMs >= first_.deadlineBootMs || commits.size() != held_.heads.size() ||
            kernel.size() != held_.heads.size())
            return false;
        for (std::size_t i = 0; i < held_.heads.size(); ++i) {
            if (commits[i].key != first_.completed[i].kernel.key ||
                commits[i].previousCommit != first_.completed[i].completedCommit ||
                kernel[i] != first_.completed[i].kernel)
                return false;
            lastCommits_[i] = commits[i].previousCommit;
        }
        phase_ = Phase::Active;
        return true;
    }

    struct Sample final
    {
        const Snapshot &held;
        ClockSample started, finished;
        const std::vector<Frame> &frames;
        const std::vector<Kernel> &kernel;
        const std::vector<Output> &commits;
    };
    [[nodiscard]] std::optional<Receipt> observe(const Sample &sample) noexcept
    {
        if (phase_ != Phase::Active)
            return {};
        const auto fail = [&]() -> std::optional<Receipt> {
            phase_ = Phase::Faulted;
            return {};
        };
        if (sample.held != held_ || !clock(sample.started) || !clock(sample.finished) ||
            sample.finished.unixMs - sample.started.unixMs >= 2000 ||
            sample.finished.bootMs - sample.started.bootMs >= 2000 ||
            sample.frames.size() != held_.heads.size() ||
            sample.kernel.size() != held_.heads.size() ||
            sample.commits.size() != held_.heads.size())
            return fail();
        Receipt receipt{};
        receipt.generation = held_.generation;
        receipt.securityEpoch = held_.securityEpoch;
        receipt.postWriteEpoch = first_.postWriteEpoch;
        receipt.observedUnixMs = sample.finished.unixMs;
        receipt.observedBootMs = sample.finished.bootMs;
        // This is a new read-only current-state sample, not renewal of either
        // original execution deadline or permission for another release.
        receipt.deadlineUnixMs = sample.started.unixMs + 2000;
        receipt.deadlineBootMs = sample.started.bootMs + 2000;
        bool pending = false;
        for (std::size_t i = 0; i < held_.heads.size(); ++i) {
            const auto &baseline = first_.completed[i];
            const auto &physical = sample.kernel[i];
            const auto &frame = sample.frames[i];
            const auto &commit = sample.commits[i];
            if (physical.key != baseline.kernel.key || frame.key != physical.key ||
                commit.key != physical.key || physical.connector != baseline.kernel.connector ||
                physical.crtc != baseline.kernel.crtc || physical.plane != baseline.kernel.plane ||
                physical.active != baseline.kernel.active ||
                commit.previousCommit < lastCommits_[i] ||
                commit.previousCommit == std::numeric_limits<std::uint64_t>::max())
                return fail();
            lastCommits_[i] = commit.previousCommit;
            if (physical.active) {
                if (!physical.framebuffer || frame.disableCommit || frame.disableSubmitted)
                    return fail();
                if (commit.previousCommit == baseline.completedCommit || !frame.frame ||
                    !frame.frame->completed()) {
                    pending = true;
                    continue;
                }
                if (!frame.retainedBuffer || !frame.retainedFramebuffer ||
                    frame.frame->queuedKind() != ProtectedFrame::Kind::Ordinary ||
                    frame.frame->completedBuffer() != frame.retainedBuffer ||
                    frame.frame->completedCommit() != commit.previousCommit ||
                    frame.retainedFramebuffer != physical.framebuffer)
                    return fail();
                for (std::size_t prior = 0; prior < i; ++prior)
                    if (sample.frames[prior].frame == frame.frame ||
                        sample.frames[prior].retainedBuffer == frame.retainedBuffer)
                        return fail();
            } else if (physical.crtc || physical.plane || physical.framebuffer || frame.frame ||
                       frame.retainedBuffer || frame.retainedFramebuffer ||
                       !frame.disableSubmitted || frame.disableCommit != baseline.completedCommit ||
                       commit.previousCommit != baseline.completedCommit) {
                return fail();
            }
            receipt.completed[receipt.completedCount++] = {physical, baseline.completedCommit,
                                                           commit.previousCommit};
        }
        if (pending)
            return {};
        return receipt;
    }
    [[nodiscard]] Phase phase() const noexcept
    {
        return phase_;
    }

  private:
    NativeCurrentFrameGate(const Snapshot &held, const Receipt &first, ClockSample now)
        : held_(held), first_(first), last_(now)
    {}
    static bool validClock(ClockSample now) noexcept
    {
        return now.unixMs && now.bootMs &&
               now.unixMs <= std::numeric_limits<std::uint64_t>::max() - 2000 &&
               now.bootMs <= std::numeric_limits<std::uint64_t>::max() - 2000;
    }
    bool clock(ClockSample now) noexcept
    {
        if (!validClock(now) || now.unixMs < last_.unixMs || now.bootMs < last_.bootMs)
            return false;
        last_ = now;
        return true;
    }
    Snapshot held_;
    Receipt first_;
    ClockSample last_;
    std::array<std::uint64_t, DisplayTransaction::MaxHeads> lastCommits_{};
    Phase phase_ = Phase::Armed;
};
} // namespace Linura::HyprlandDisplay
