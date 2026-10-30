#include "protected_interaction.h"

#include <algorithm>
#include <limits>
#include <set>
#include <utility>

namespace Linura::HyprlandDisplay {
namespace {
bool validDigest(const std::string &value)
{
    return value.size() == 64 && value != std::string(64, '0') &&
           std::all_of(value.begin(), value.end(), [](unsigned char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}
} // namespace

std::optional<ProtectedInteraction> ProtectedInteraction::start(Scope scope, const Snapshot &sample,
                                                                ClockSample clock,
                                                                std::uint64_t epoch)
{
    const auto maximum = scope.purpose == Purpose::Apply ? MaximumWindowMs : DecisionWindowMs;
    if ((scope.purpose != Purpose::Apply && scope.purpose != Purpose::Keep &&
         scope.purpose != Purpose::Revert) ||
        !validDigest(scope.digest) || clock.unixMs == 0 || clock.bootMs == 0 || epoch == 0 ||
        epoch >= std::numeric_limits<std::uint64_t>::max() - 1 ||
        scope.deadlineUnixMs <= clock.unixMs || scope.deadlineUnixMs - clock.unixMs > maximum ||
        clock.bootMs >
            std::numeric_limits<std::uint64_t>::max() - (scope.deadlineUnixMs - clock.unixMs) ||
        sample.generation == 0 || sample.generation == std::numeric_limits<std::uint64_t>::max() ||
        sample.securityEpoch == 0 ||
        sample.securityEpoch == std::numeric_limits<std::uint64_t>::max() || sample.heads.empty() ||
        sample.heads.size() > DisplayTransaction::MaxHeads ||
        (sample.coverage != Coverage::Unlocked && sample.coverage != Coverage::Secure))
        return std::nullopt;
    std::set<OutputKey> outputs;
    Layout current;
    bool visible = false;
    for (const auto &head : sample.heads) {
        if (head.key.handle == 0 || head.key.generation == 0 ||
            head.key.handle == std::numeric_limits<std::uint64_t>::max() ||
            head.key.generation == std::numeric_limits<std::uint64_t>::max() ||
            head.current.output != head.key || !outputs.insert(head.key).second ||
            (sample.coverage == Coverage::Secure && head.current.enabled && !head.covered))
            return std::nullopt;
        current.push_back(head.current);
        visible = visible || (head.current.enabled && head.powered && !head.current.mirror);
    }
    if (!visible || !DisplayTransaction::validLayout(current, sample))
        return std::nullopt;
    return ProtectedInteraction(std::move(scope), sample, clock, epoch);
}
ProtectedInteraction::ProtectedInteraction(Scope scope, Snapshot sample, ClockSample clock,
                                           std::uint64_t epoch)
    : scope_(std::move(scope)), inventory_(std::move(sample)), armed_(clock),
      deadlineBootMs_(clock.bootMs + (scope_.deadlineUnixMs - clock.unixMs)), epoch_(epoch)
{
    for (const auto &head : inventory_.heads)
        if (head.current.enabled)
            frames_.emplace(head.key, Frame{});
}
ProtectedInteraction::ProtectedInteraction(ProtectedInteraction &&other) noexcept
    : scope_(std::move(other.scope_)), inventory_(std::move(other.inventory_)),
      armed_(other.armed_), deadlineBootMs_(other.deadlineBootMs_),
      epoch_(std::exchange(other.epoch_, 0)), phase_(std::exchange(other.phase_, Phase::Cancelled)),
      frames_(std::move(other.frames_)), focused_(std::exchange(other.focused_, std::nullopt))
{}
ProtectedInteraction &ProtectedInteraction::operator=(ProtectedInteraction &&other) noexcept
{
    if (this != &other) {
        scope_ = std::move(other.scope_);
        inventory_ = std::move(other.inventory_);
        armed_ = other.armed_;
        deadlineBootMs_ = other.deadlineBootMs_;
        epoch_ = std::exchange(other.epoch_, 0);
        phase_ = std::exchange(other.phase_, Phase::Cancelled);
        frames_ = std::move(other.frames_);
        focused_ = std::exchange(other.focused_, std::nullopt);
    }
    return *this;
}
const ProtectedInteraction::Scope &ProtectedInteraction::scope() const noexcept
{
    return scope_;
}
ProtectedInteraction::Phase ProtectedInteraction::phase() const noexcept
{
    return phase_;
}
std::uint64_t ProtectedInteraction::epoch() const noexcept
{
    return epoch_;
}
bool ProtectedInteraction::advance() noexcept
{
    if (phase_ == Phase::Cancelled || epoch_ >= std::numeric_limits<std::uint64_t>::max() - 1) {
        cancel();
        return false;
    }
    ++epoch_;
    return true;
}
void ProtectedInteraction::updateReady() noexcept
{
    if (phase_ == Phase::Cancelled || phase_ == Phase::Consumed)
        return;
    phase_ = focused_ && !frames_.empty() &&
                     std::all_of(frames_.begin(), frames_.end(),
                                 [](const auto &item) {
                                     return item.second.configure != 0 && item.second.commit != 0 &&
                                            item.second.presented;
                                 })
                 ? Phase::Ready
                 : Phase::Arming;
}
bool ProtectedInteraction::configure(OutputKey output, std::uint64_t serial)
{
    const auto frame = frames_.find(output);
    if (phase_ == Phase::Cancelled || phase_ == Phase::Consumed || frame == frames_.end() ||
        serial == 0 || serial <= frame->second.configure || !advance()) {
        cancel();
        return false;
    }
    frame->second = Frame{serial, 0, frame->second.highWater, false};
    updateReady();
    return true;
}
bool ProtectedInteraction::commit(OutputKey output, std::uint64_t serial,
                                  std::uint64_t nativeCommitId)
{
    const auto frame = frames_.find(output);
    if (phase_ == Phase::Cancelled || frame == frames_.end() || serial == 0 ||
        serial != frame->second.configure || nativeCommitId == 0 ||
        nativeCommitId <= frame->second.highWater) {
        cancel();
        return false;
    }
    // Repainting this same configured protected surface does not invalidate a
    // previously presented safe frame or the input epoch. A new configure does.
    frame->second.commit = nativeCommitId;
    frame->second.highWater = nativeCommitId;
    updateReady();
    return true;
}
bool ProtectedInteraction::safetyFrame(OutputKey output)
{
    const auto frame = frames_.find(output);
    if (phase_ == Phase::Cancelled || frame == frames_.end()) {
        cancel();
        return false;
    }
    if (phase_ != Phase::Consumed && (frame->second.commit != 0 || frame->second.presented) &&
        !advance())
        return false;
    frame->second.commit = 0;
    frame->second.presented = false;
    updateReady();
    return true;
}
void ProtectedInteraction::presented(OutputKey output, std::uint64_t nativeCommitId,
                                     bool hardwareCompleted)
{
    if (phase_ == Phase::Cancelled)
        return;
    const auto frame = frames_.find(output);
    if (frame == frames_.end()) {
        cancel();
        return;
    }
    // Prior/dropped/non-correlated events cannot qualify the current frame.
    if (nativeCommitId == 0 || nativeCommitId != frame->second.commit)
        return;
    if (!hardwareCompleted) {
        cancel();
        return;
    } else
        frame->second.presented = true;
    updateReady();
}
void ProtectedInteraction::focus(std::optional<OutputKey> output)
{
    if (phase_ == Phase::Cancelled || output == focused_)
        return;
    if (output && !frames_.contains(*output)) {
        cancel();
        return;
    }
    if (!advance())
        return;
    focused_ = output;
    if (phase_ == Phase::Consumed) {
        cancel();
        return;
    }
    updateReady();
}
void ProtectedInteraction::inputReplaced()
{
    cancel();
}
bool ProtectedInteraction::refresh(const Snapshot &sample, ClockSample clock)
{
    if (phase_ == Phase::Cancelled || sample != inventory_ || clock.unixMs < armed_.unixMs ||
        clock.bootMs < armed_.bootMs || clock.unixMs >= scope_.deadlineUnixMs ||
        clock.bootMs >= deadlineBootMs_) {
        cancel();
        return false;
    }
    // Track every probe, so a rollback within the original window is rejected.
    armed_ = clock;
    return true;
}
bool ProtectedInteraction::eligible(std::uint64_t expectedEpoch, const Snapshot &sample,
                                    ClockSample clock)
{
    return refresh(sample, clock) && phase_ == Phase::Ready && expectedEpoch != 0 &&
           epoch_ == expectedEpoch;
}
bool ProtectedInteraction::consume(const Scope &scope, std::uint64_t expectedEpoch,
                                   const Snapshot &sample, ClockSample clock)
{
    if (scope != scope_ || !eligible(expectedEpoch, sample, clock)) {
        cancel();
        return false;
    }
    phase_ = Phase::Consumed;
    return true;
}
void ProtectedInteraction::cancel() noexcept
{
    phase_ = Phase::Cancelled;
    focused_.reset();
}
} // namespace Linura::HyprlandDisplay
