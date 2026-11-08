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
        // Actual output-owned monotonic commit high-water mark. The initial
        // ArmRequest is only an identity/baseline check. At spend, a fresh
        // high-water must be sampled from each SAME live native output and
        // all later accepted completions must exceed that spend-time value.
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
        // Immutable retained Aquamarine DRM buffer's actual FB attachment.
        // Never a client-supplied or just-planned framebuffer identity.
        std::uint32_t retainedFramebuffer = 0;
    };
    struct NativeScanout final
    {
        OutputKey key;
        // Fresh read-only KMS state of the same actual connector. The caller
        // MUST obtain this from readNativeKernelScanout on the original
        // compositor's admitted DRM descriptor, not its requested monitor
        // state, and bracket the read by current native identity probes.
        std::uint32_t connector = 0, crtc = 0, framebuffer = 0, plane = 0;
        bool active = false;
    };
    struct OutputReceipt final
    {
        // The same actual independently sampled KMS identity used to verify
        // physical scanout. A completed commit number without its connector,
        // CRTC, primary plane and framebuffer cannot be reconciled by Control.
        NativeScanout kernel;
        // Immutable native output-owned counter read at the irreversible
        // grant spend boundary. Control must compare both counter values.
        std::uint64_t spendHighWater = 0;
        std::uint64_t completedCommit = 0;
    };
    struct Receipt final
    {
        std::uint64_t generation = 0, securityEpoch = 0, postWriteEpoch = 0;
        std::uint64_t observedUnixMs = 0, observedBootMs = 0;
        // Fixed bounded comparison evidence, not a Root/Control authorization,
        // output-release ACK or ordinary-startup credential.
        std::array<OutputReceipt, DisplayTransaction::MaxHeads> completed{};
        std::size_t completedCount = 0;
    };

    struct ArmRequest final
    {
        const Snapshot &held;
        std::uint64_t postWriteEpoch;
        ClockSample sampled;
        const std::vector<Output> &before;
        const std::vector<NativeScanout> &kernel;
    };
    [[nodiscard]] static std::optional<NativeFirstFrameGate> arm(const ArmRequest &request)
    {
        const auto &held = request.held;
        const auto postWriteEpoch = request.postWriteEpoch;
        const auto sampled = request.sampled;
        const auto &before = request.before;
        const auto &kernel = request.kernel;
        if (!postWriteEpoch || !sampled.unixMs || !sampled.bootMs ||
            sampled.unixMs > std::numeric_limits<std::uint64_t>::max() - MaxProofWindowMs ||
            sampled.bootMs > std::numeric_limits<std::uint64_t>::max() - MaxProofWindowMs ||
            held.generation == 0 || held.securityEpoch == 0 ||
            (held.coverage != Coverage::Secure && held.coverage != Coverage::Unlocked) ||
            held.heads.empty() || held.heads.size() > DisplayTransaction::MaxHeads ||
            before.size() != held.heads.size() || kernel.size() != held.heads.size())
            return {};
        Layout actual;
        actual.reserve(held.heads.size());
        bool poweredRoot = false;
        for (std::size_t i = 0; i < held.heads.size(); ++i) {
            const auto &head = held.heads[i];
            if (head.key != before[i].key || head.key.generation == 0 ||
                before[i].previousCommit == 0 ||
                before[i].previousCommit == std::numeric_limits<std::uint64_t>::max() ||
                head.outputIdentityWitness.empty() || head.baseRuleWitness.empty() ||
                (i && before[i - 1].key.handle >= head.key.handle) ||
                (head.current.enabled &&
                 (!head.powered || (held.coverage == Coverage::Secure && !head.covered))))
                return {};
            const auto &physical = kernel[i];
            if (physical.key != head.key || !physical.connector)
                return {};
            if (head.current.enabled) {
                if (!physical.active || !physical.crtc || !physical.plane || !physical.framebuffer)
                    return {};
            } else {
                if (physical.active || physical.crtc || physical.plane || physical.framebuffer)
                    return {};
            }
            for (std::size_t prior = 0; prior < i; ++prior)
                if (kernel[prior].connector == physical.connector)
                    return {};
            actual.push_back(head.current);
            if (head.current.enabled && !head.current.mirror && head.powered)
                poweredRoot = true;
        }
        if (!poweredRoot || !DisplayTransaction::validLayout(actual, held))
            return {};
        return NativeFirstFrameGate(held, postWriteEpoch, sampled, before, kernel);
    }

    NativeFirstFrameGate(const NativeFirstFrameGate &) = delete;
    NativeFirstFrameGate &operator=(const NativeFirstFrameGate &) = delete;
    NativeFirstFrameGate(NativeFirstFrameGate &&) = default;
    NativeFirstFrameGate &operator=(NativeFirstFrameGate &&) = delete;

    // Called only AFTER the separately authenticated, durable Root/native
    // release grant was spent. A second fresh, output-owned native commit
    // high-water read closes the arm-to-spend race: a completed frame that
    // predates the release grant MUST NOT satisfy post-release verification.
    // The caller must acquire these counters and a fresh physical KMS sample
    // from the actual pinned compositor immediately at the one-use spend
    // boundary, never from wire/client data. An arm-time physical identity
    // cannot be substituted between the Root grant and the first frame.
    // Spending is irreversible even on malformed or missing evidence.
    [[nodiscard]] bool spend(const Snapshot &current, ClockSample now,
                             const std::vector<Output> &atSpend,
                             const std::vector<NativeScanout> &atSpendKernel) noexcept
    {
        if (phase_ != Phase::Held)
            return false;
        phase_ = Phase::Faulted;
        if (!currentSample(current, now) || atSpend.size() != before_.size() ||
            atSpendKernel.size() != baselineKernel_.size())
            return false;
        for (std::size_t i = 0; i < atSpend.size(); ++i) {
            if (atSpend[i].key != before_[i].key ||
                atSpend[i].previousCommit < before_[i].previousCommit ||
                atSpend[i].previousCommit == std::numeric_limits<std::uint64_t>::max())
                return false;
            const auto &previous = baselineKernel_[i];
            const auto &physical = atSpendKernel[i];
            if (physical.key != previous.key || physical.connector != previous.connector ||
                physical.crtc != previous.crtc || physical.plane != previous.plane ||
                physical.active != previous.active)
                return false;
            if (physical.active && !physical.framebuffer)
                return false;
            if (!physical.active && physical.framebuffer)
                return false;
            spentCommit_[i] = atSpend[i].previousCommit;
        }
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
        const std::vector<NativeScanout> &kernel;
        // Separately observed output-wide native commit-result high-water.
        // A protected frame tracker by itself cannot prove that a later
        // unrelated native output write did not replace the first frame.
        const std::vector<Output> &outputCommits;
    };
    [[nodiscard]] std::optional<Receipt> observe(const ObservationRequest &sample) noexcept
    {
        const auto &current = sample.current;
        const auto now = sample.now;
        const auto &frames = sample.frames;
        const auto &kernel = sample.kernel;
        const auto &outputCommits = sample.outputCommits;
        if (phase_ != Phase::Spent)
            return {};
        if (!currentSample(current, now) || frames.size() != before_.size() ||
            kernel.size() != before_.size() || outputCommits.size() != before_.size()) {
            phase_ = Phase::Faulted;
            return {};
        }
        Receipt receipt{held_.generation, held_.securityEpoch, epoch_, now.unixMs, now.bootMs, {}};
        bool pending = false;
        for (std::size_t i = 0; i < before_.size(); ++i) {
            const auto &head = current.heads[i];
            const auto &frame = frames[i];
            const auto &scanout = kernel[i];
            const auto &nativeCommit = outputCommits[i];
            if (frame.key != head.key || scanout.key != head.key ||
                nativeCommit.key != head.key || !scanout.connector ||
                nativeCommit.previousCommit < spentCommit_[i] ||
                nativeCommit.previousCommit == std::numeric_limits<std::uint64_t>::max()) {
                phase_ = Phase::Faulted;
                return {};
            }
            const auto &original = baselineKernel_[i];
            if (original.key != scanout.key || original.connector != scanout.connector ||
                original.crtc != scanout.crtc || original.plane != scanout.plane ||
                original.active != scanout.active) {
                phase_ = Phase::Faulted;
                return {};
            }
            // A connector may not be used to certify two physical heads. In
            // mirror mode buffer bytes can be shared, but the connector
            // identity and each output-owned frame tracker must be distinct.
            for (std::size_t prior = 0; prior < i; ++prior)
                if (kernel[prior].connector == scanout.connector) {
                    phase_ = Phase::Faulted;
                    return {};
                }
            if (head.current.enabled) {
                // The ordinary surface may not have produced its first frame
                // yet. An entirely absent native frame is pending, NEVER
                // verified. Any partially populated or disable-typed claim
                // is contradictory and fails closed under the original clock.
                if (!frame.frame && !frame.retainedBuffer && !frame.retainedFramebuffer &&
                    !frame.disableCommit && !frame.disableSubmitted) {
                    if (nativeCommit.previousCommit != spentCommit_[i]) {
                        phase_ = Phase::Faulted;
                        return {};
                    }
                    pending = true;
                    continue;
                }
                if (!frame.frame || !frame.retainedBuffer || frame.disableCommit ||
                    frame.disableSubmitted) {
                    phase_ = Phase::Faulted;
                    return {};
                }
                // A tracker is owned by one native output. Sharing a hardware-
                // completed tracker between two output keys cannot establish
                // separate first ordinary frames, even for mirrored buffers.
                for (std::size_t prior = 0; prior < i; ++prior) {
                    if (current.heads[prior].current.enabled &&
                        frames[prior].frame == frame.frame) {
                        phase_ = Phase::Faulted;
                        return {};
                    }
                }
                const auto queued = frame.frame->queuedCommit();
                // A commit can be queued before its native commit-result
                // event reaches the independent observer. Only the original
                // spend mark or that exact queued commit is admissible while
                // pending. Any third output write is permanently fatal.
                if ((queued && nativeCommit.previousCommit != queued &&
                     nativeCommit.previousCommit != spentCommit_[i]) ||
                    (!queued && nativeCommit.previousCommit != spentCommit_[i])) {
                    phase_ = Phase::Faulted;
                    return {};
                }
                const auto commit = frame.frame->completedCommit();
                if (!commit) {
                    pending = true;
                    continue;
                }
                if (commit != nativeCommit.previousCommit || commit <= spentCommit_[i] ||
                    frame.frame->queuedKind() != ProtectedFrame::Kind::Content ||
                    frame.frame->completedBuffer() != frame.retainedBuffer ||
                    !frame.retainedFramebuffer || !scanout.active || !scanout.crtc ||
                    !scanout.plane || !scanout.framebuffer ||
                    frame.retainedFramebuffer != scanout.framebuffer) {
                    phase_ = Phase::Faulted;
                    return {};
                }
                receipt.completed[receipt.completedCount++] = {scanout, spentCommit_[i], commit};
            } else {
                if (frame.frame || frame.retainedBuffer || frame.retainedFramebuffer) {
                    phase_ = Phase::Faulted;
                    return {};
                }
                // Disabled heads need a distinct post-spend commit too. A
                // later unrelated commit cannot masquerade as that disable.
                if (nativeCommit.previousCommit != spentCommit_[i] &&
                    nativeCommit.previousCommit != frame.disableCommit) {
                    phase_ = Phase::Faulted;
                    return {};
                }
                if (!frame.disableSubmitted || scanout.active) {
                    pending = true;
                    continue;
                }
                if (nativeCommit.previousCommit != frame.disableCommit) {
                    phase_ = Phase::Faulted;
                    return {};
                }
                // A submitted disable must really detach the connector at
                // KMS. A logical disabled head or an old modeset ACK alone
                // cannot prove a disabled physical output.
                if (scanout.crtc || scanout.framebuffer || scanout.plane ||
                    frame.disableCommit == 0 || frame.disableCommit <= spentCommit_[i]) {
                    phase_ = Phase::Faulted;
                    return {};
                }
                OutputReceipt completed;
                completed.kernel = scanout;
                completed.spendHighWater = spentCommit_[i];
                completed.completedCommit = frame.disableCommit;
                receipt.completed[receipt.completedCount++] = completed;
            }
        }
        if (pending)
            return {};
        phase_ = Phase::Verified; // Still no authority to unlock or release.
        return receipt;
    }

    // The compositor's retained scene calls this on its existing watchdog
    // even if no readout is requested. A spent one-use grant cannot silently
    // gain a fresh proof window after the original absolute window expires.
    [[nodiscard]] bool retain(const Snapshot &current, ClockSample now) noexcept
    {
        if (phase_ != Phase::Spent && phase_ != Phase::Verified)
            return false;
        if (!currentSample(current, now)) {
            phase_ = Phase::Faulted;
            return false;
        }
        return true;
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
                         const std::vector<Output> &before,
                         const std::vector<NativeScanout> &kernel)
        : held_(held), epoch_(epoch), sampled_(sampled), before_(before), baselineKernel_(kernel)
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
    std::vector<NativeScanout> baselineKernel_; // Physical connector and plane ancestry.
    // Fixed-size per-output spend boundary, never a renewed grant/clock.
    std::array<std::uint64_t, DisplayTransaction::MaxHeads> spentCommit_{};
    Phase phase_ = Phase::Held;
};

} // namespace Linura::HyprlandDisplay
