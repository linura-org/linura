#include "native_first_frame_gate.h"

#include <cassert>
#include <limits>
#include <vector>

using namespace Linura::HyprlandDisplay;
using Phase = NativeFirstFrameGate::Phase;
using Kind = ProtectedFrame::Kind;
using Presentation = ProtectedFrame::Presentation;

namespace {
Snapshot inventory(bool secondDisabled = false)
{
    Snapshot snapshot;
    snapshot.generation = 81;
    snapshot.securityEpoch = 19;
    snapshot.coverage = Coverage::Secure;
    for (int i = 0; i < 2; ++i) {
        Head head;
        head.key = {static_cast<std::uint64_t>(i + 1), static_cast<std::uint64_t>(i + 10)};
        head.modes = {{1920, 1080, 60000}};
        head.current.output = head.key;
        head.current.enabled = i == 0 || !secondDisabled;
        if (head.current.enabled) {
            head.current.mode = head.modes[0];
            head.current.scaleMilli = 1000;
            head.current.x = i * 1920;
        }
        head.powered = head.current.enabled;
        head.covered = head.current.enabled;
        head.baseRuleWitness = "source:" + std::to_string(i);
        head.outputIdentityWitness = "kernel:" + std::to_string(i);
        snapshot.heads.push_back(head);
    }
    return snapshot;
}
std::vector<NativeFirstFrameGate::Output> baseline(const Snapshot &sample)
{
    std::vector<NativeFirstFrameGate::Output> result;
    for (const auto &head : sample.heads)
        result.push_back({head.key, 7});
    return result;
}
std::vector<NativeFirstFrameGate::NativeScanout> kernel(const Snapshot &sample)
{
    std::vector<NativeFirstFrameGate::NativeScanout> result;
    for (std::size_t i = 0; i < sample.heads.size(); ++i) {
        const bool enabled = sample.heads[i].current.enabled;
        result.push_back({sample.heads[i].key, static_cast<std::uint32_t>(100 + i),
                          static_cast<std::uint32_t>(enabled ? 200 + i : 0),
                          static_cast<std::uint32_t>(enabled ? 301 + i : 0),
                          static_cast<std::uint32_t>(enabled ? 400 + i : 0), enabled});
    }
    return result;
}
// Native output commit-result history is independent of the retained
// presentation tracker. These fixtures synthesize both channels separately.
std::vector<NativeFirstFrameGate::Output> outputCommits(
    const Snapshot &sample, const std::vector<NativeFirstFrameGate::NativeFrame> &frames)
{
    auto result = baseline(sample);
    if (frames.size() != result.size())
        return result;
    for (std::size_t i = 0; i < frames.size(); ++i) {
        if (frames[i].frame && frames[i].frame->queuedCommit())
            result[i].previousCommit = frames[i].frame->queuedCommit();
        else if (frames[i].disableSubmitted && frames[i].disableCommit)
            result[i].previousCommit = frames[i].disableCommit;
    }
    return result;
}
void completed(ProtectedFrame &frame, const void *buffer, std::uint64_t commit, Kind kind)
{
    assert(frame.rendered(buffer, kind));
    assert(frame.queued(buffer, commit));
    assert(frame.submitted(commit, true));
    assert(frame.presented(commit, true) ==
           (kind == Kind::Content ? Presentation::Content : Presentation::Safety));
}
} // namespace

int main()
{
    const ClockSample start{10'000, 5'000};
    const ClockSample later{10'100, 5'100};
    int first = 0, second = 0, swapped = 0;
    const Snapshot held = inventory();
    const auto before = baseline(held);
    const auto scanout = kernel(held);

    // The exact native output inventory, source ownership and a surviving
    // powered root are mandatory even to construct comparison state.
    assert(!NativeFirstFrameGate::arm({held, 0, start, before, scanout}));
    assert(!NativeFirstFrameGate::arm({held, 1, {}, before, scanout}));
    assert(!NativeFirstFrameGate::arm({held, 1, start, {}, scanout}));
    auto invalid = held;
    invalid.coverage = Coverage::Unknown;
    assert(!NativeFirstFrameGate::arm({invalid, 1, start, before, scanout}));
    invalid = held;
    invalid.heads[0].outputIdentityWitness.clear();
    assert(!NativeFirstFrameGate::arm({invalid, 1, start, before, scanout}));
    invalid = held;
    invalid.heads[0].powered = false;
    assert(!NativeFirstFrameGate::arm({invalid, 1, start, before, scanout}));
    invalid = held;
    invalid.heads[1].key = invalid.heads[0].key;
    assert(!NativeFirstFrameGate::arm({invalid, 1, start, before, scanout}));
    auto uninitialized = before;
    uninitialized[0].previousCommit = 0;
    assert(!NativeFirstFrameGate::arm({held, 1, start, uninitialized, scanout}));
    uninitialized[0].previousCommit = std::numeric_limits<std::uint64_t>::max();
    assert(!NativeFirstFrameGate::arm({held, 1, start, uninitialized, scanout}));
    auto mismatched = before;
    mismatched[0].key.generation++;
    assert(!NativeFirstFrameGate::arm({held, 1, start, mismatched, scanout}));

    // Arming needs the real physical connector/CRTC/primary plane ancestry,
    // not just a numerical output key with a native commit counter.
    auto substitutedKernel = scanout;
    substitutedKernel[0].connector = 500;
    substitutedKernel[0].crtc = 0;
    assert(!NativeFirstFrameGate::arm({held, 13, start, before, substitutedKernel}));
    substitutedKernel = scanout;
    substitutedKernel[1].connector = substitutedKernel[0].connector;
    assert(!NativeFirstFrameGate::arm({held, 13, start, before, substitutedKernel}));

    auto gate = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
    assert(gate && gate->phase() == Phase::Held);
    assert(!gate->observe({held, later, {}, scanout, baseline(held)}));
    assert(!gate->spend(held, {9'999, 4'999}, before, scanout));
    assert(gate->phase() == Phase::Faulted);
    assert(!gate->spend(held, later, before, scanout));

    // One physical native completion cannot satisfy two independent output
    // keys by aliasing a tracker. Mirrored content may share bytes, but each
    // output must have its own native completed-frame witness.
    {
        ProtectedFrame shared;
        completed(shared, &first, 8, Kind::Content);
        auto alias = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
        assert(alias && alias->spend(held, later, before, scanout));
        std::vector<NativeFirstFrameGate::NativeFrame> reused{
            {held.heads[0].key, &shared, &first, 0, false, 301},
            {held.heads[1].key, &shared, &first, 0, false, 301},
        };
        assert(!alias->observe({held, later, reused, scanout, outputCommits(held, reused)}));
        assert(alias->phase() == Phase::Faulted);
        assert(!alias->spend(held, later, before, scanout));
    }

    // Arm is not the physical release boundary. Between arm and spend an
    // output may complete a frame. Capture a NEW output-specific high-water at
    // spend, then require a strictly newer hardware completion. No synthesized
    // pre-spend frame or disabled-output commit can inherit the old arm mark.
    {
        auto moved = before;
        moved[0].previousCommit = 8;
        ProtectedFrame stale;
        ProtectedFrame fresh;
        completed(stale, &first, 8, Kind::Content);
        completed(fresh, &second, 9, Kind::Content);
        auto preSpent = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
        assert(preSpent && preSpent->spend(held, later, moved, scanout));
        std::vector<NativeFirstFrameGate::NativeFrame> staleFrames{
            {held.heads[0].key, &stale, &first, 0, false, 301},
            {held.heads[1].key, &fresh, &second, 0, false, 302},
        };
        assert(!preSpent->observe({held, later, staleFrames, scanout,
                                   outputCommits(held, staleFrames)}));
        assert(preSpent->phase() == Phase::Faulted);
        assert(!preSpent->spend(held, later, moved, scanout));

        for (int reason = 0; reason < 4; ++reason) {
            auto bad = before;
            if (reason == 0)
                bad.pop_back();
            else if (reason == 1)
                ++bad[0].key.generation;
            else if (reason == 2)
                --bad[0].previousCommit;
            else
                bad[0].previousCommit = std::numeric_limits<std::uint64_t>::max();
            auto gated = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
            assert(gated && !gated->spend(held, later, bad, scanout));
            assert(gated->phase() == Phase::Faulted);
            assert(!gated->spend(held, later, before, scanout));
        }
    }

    // Even the actual one-use grant cannot spend against a different
    // physical output, before any ordinary framebuffer is shown.
    for (int drift = 0; drift < 5; ++drift) {
        auto physical = scanout;
        if (drift == 0)
            physical[0].connector += 30;
        else if (drift == 1)
            physical[0].crtc += 30;
        else if (drift == 2)
            physical[0].plane += 30;
        else if (drift == 3)
            physical[0].active = false;
        else
            physical.pop_back();
        auto proof = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
        assert(proof);
        assert(!proof->spend(held, later, before, physical));
        assert(proof->phase() == Phase::Faulted);
        assert(!proof->spend(held, later, before, scanout));
    }

    // A completed opaque frame is NOT a first ordinary frame, and neither is
    // an old hardware completion or a presented frame on the wrong buffer.
    for (int scenario = 0; scenario < 4; ++scenario) {
        ProtectedFrame a;
        ProtectedFrame b;
        auto proof = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
        assert(proof && proof->spend(held, later, before, scanout));
        if (scenario == 0)
            completed(a, &first, 8, Kind::Safety);
        else
            completed(a, &first, scenario == 1 ? 7 : 8, Kind::Content);
        completed(b, &second, 9, Kind::Content);
        const auto target = scenario == 3 ? &swapped : &first;
        std::vector<NativeFirstFrameGate::NativeFrame> frames{
            {held.heads[0].key, &a, target, 0, false, 301},
            {held.heads[1].key, &b, &second, 0, false, 302},
        };
        if (scenario == 2)
            frames[1].key = held.heads[0].key; // Other native output's completion.
        assert(!proof->observe({held, later, frames, scanout, outputCommits(held, frames)}));
        assert(proof->phase() == Phase::Faulted);
        assert(!proof->spend(held, later, before, scanout));
    }

    // After a real one-use spend, an ordinary output can legitimately have
    // no frame yet. Absence cannot become a receipt or renew the original
    // deadline. Substituted/partially populated native evidence must fault.
    {
        auto absent = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
        assert(absent && absent->spend(held, later, before, scanout));
        std::vector<NativeFirstFrameGate::NativeFrame> noFrames{
            {held.heads[0].key, nullptr, nullptr, 0, false, 0},
            {held.heads[1].key, nullptr, nullptr, 0, false, 0},
        };
        assert(!absent->observe({held, later, noFrames, scanout, outputCommits(held, noFrames)}));
        assert(absent->phase() == Phase::Spent);
        ProtectedFrame freshFirst;
        ProtectedFrame freshSecond;
        completed(freshFirst, &first, 8, Kind::Content);
        completed(freshSecond, &second, 9, Kind::Content);
        noFrames[0] = {held.heads[0].key, &freshFirst, &first, 0, false, 301};
        assert(!absent->observe({held, later, noFrames, scanout, outputCommits(held, noFrames)}));
        assert(absent->phase() == Phase::Spent);
        noFrames[1] = {held.heads[1].key, &freshSecond, &second, 0, false, 302};
        assert(absent->observe({held, later, noFrames, scanout, outputCommits(held, noFrames)}));
        assert(absent->phase() == Phase::Verified);

        auto incomplete = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
        assert(incomplete && incomplete->spend(held, later, before, scanout));
        noFrames[0] = {held.heads[0].key, nullptr, &first, 0, false, 301};
        assert(!incomplete->observe({held, later, noFrames, scanout,
                                     outputCommits(held, noFrames)}));
        assert(incomplete->phase() == Phase::Faulted);

        auto expired = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
        assert(expired && expired->spend(held, later, before, scanout));
        noFrames[0] = {held.heads[0].key, nullptr, nullptr, 0, false, 0};
        noFrames[1] = {held.heads[1].key, nullptr, nullptr, 0, false, 0};
        assert(!expired->observe({held, {12'000, 7'000}, noFrames, scanout,
                                  outputCommits(held, noFrames)}));
        assert(expired->phase() == Phase::Faulted);
    }

    // A native commit can be queued before its independent IOutput result
    // is observed. That scheduling gap remains pending, never an immediate
    // physical receipt. An unrelated third commit faults the original window.
    {
        ProtectedFrame queued;
        assert(queued.rendered(&first, Kind::Content));
        assert(queued.queued(&first, 8));
        std::vector<NativeFirstFrameGate::NativeFrame> pendingFrames{
            {held.heads[0].key, &queued, &first, 0, false, 301},
            {held.heads[1].key, nullptr, nullptr, 0, false, 0},
        };
        auto pending = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
        assert(pending && pending->spend(held, later, before, scanout));
        auto commits = baseline(held);
        assert(!pending->observe({held, later, pendingFrames, scanout, commits}));
        assert(pending->phase() == Phase::Spent);
        assert(queued.submitted(8, true));
        commits[0].previousCommit = 8;
        assert(!pending->observe({held, later, pendingFrames, scanout, commits}));
        assert(pending->phase() == Phase::Spent);
        commits[0].previousCommit = 9; // Some other native output write.
        assert(!pending->observe({held, later, pendingFrames, scanout, commits}));
        assert(pending->phase() == Phase::Faulted);
    }

    // No first frame remains pending, without extending the original clocks.
    ProtectedFrame a;
    ProtectedFrame b;
    auto proof = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
    assert(proof && proof->spend(held, later, before, scanout));
    std::vector<NativeFirstFrameGate::NativeFrame> frames{
        {held.heads[0].key, &a, &first, 0, false, 301},
        {held.heads[1].key, &b, &second, 0, false, 302},
    };
    assert(!proof->observe({held, later, frames, scanout, outputCommits(held, frames)}));
    assert(proof->phase() == Phase::Spent);
    completed(a, &first, 8, Kind::Content);
    assert(!proof->observe({held, later, frames, scanout, outputCommits(held, frames)}));
    completed(b, &second, 9, Kind::Content);
    const auto receipt = proof->observe({held, later, frames, scanout,
                                         outputCommits(held, frames)});
    assert(receipt);
    assert(receipt->generation == held.generation);
    assert(receipt->securityEpoch == held.securityEpoch);
    assert(receipt->postWriteEpoch == 13);
    assert(receipt->completedCount == 2);
    assert(receipt->completed[0].spendHighWater == 7);
    assert(receipt->completed[1].spendHighWater == 7);
    assert(receipt->completed[0].completedCommit == 8);
    assert(receipt->completed[1].completedCommit == 9);
    assert(receipt->completed[0].completedCommit > receipt->completed[0].spendHighWater);
    assert(receipt->completed[1].completedCommit > receipt->completed[1].spendHighWater);
    assert(receipt->completed[0].kernel.key == held.heads[0].key);
    assert(receipt->completed[1].kernel.key == held.heads[1].key);
    assert(receipt->completed[0].kernel.framebuffer == scanout[0].framebuffer);
    assert(receipt->completed[1].kernel.framebuffer == scanout[1].framebuffer);
    assert(receipt->completed[0].kernel.crtc == scanout[0].crtc);
    assert(receipt->completed[1].kernel.plane == scanout[1].plane);
    assert(proof->phase() == Phase::Verified);
    // Never redeliver or renew.
    assert(!proof->observe({held, later, frames, scanout, outputCommits(held, frames)}));
    assert(!proof->spend(held, later, before, scanout));

    // An independently subscribed IOutput counter cannot be replaced by
    // the frame tracker's own counter. Concurrent or substituted output
    // commits after LNRX are not valid physical-release evidence.
    for (int mismatch = 0; mismatch < 6; ++mismatch) {
        auto independent = outputCommits(held, frames);
        if (mismatch == 0)
            independent[0].previousCommit = 0;
        else if (mismatch == 1)
            independent[0].previousCommit = 7;
        else if (mismatch == 2)
            independent[0].previousCommit = 9;
        else if (mismatch == 3)
            independent[0].key.generation++;
        else if (mismatch == 4)
            independent[0].previousCommit = std::numeric_limits<std::uint64_t>::max();
        else
            independent[1].key = independent[0].key;
        auto guarded = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
        assert(guarded && guarded->spend(held, later, before, scanout));
        assert(!guarded->observe({held, later, frames, scanout, independent}));
        assert(guarded->phase() == Phase::Faulted);
    }

    // A spent grant has one original clock window, even when nobody asks
    // for a frame receipt. The caller's periodic watchdog must latch expiry.
    {
        auto watchdog = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
        assert(watchdog && watchdog->spend(held, later, before, scanout));
        assert(watchdog->retain(held, later));
        assert(!watchdog->retain(held, ClockSample{12'000, 7'000}));
        assert(watchdog->phase() == Phase::Faulted);
        assert(!watchdog->retain(held, later));
    }

    for (int scenario = 0; scenario < 5; ++scenario) {
        auto current = held;
        auto candidate = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
        assert(candidate && candidate->spend(held, later, before, scanout));
        if (scenario == 0)
            current.generation++;
        else if (scenario == 1)
            current.securityEpoch++;
        else if (scenario == 2)
            current.heads[0].baseRuleWitness = "replaced-source";
        else if (scenario == 3)
            current.heads[0].current.x++;
        const auto when = scenario == 4 ? ClockSample{12'000, 7'000} : later;
        assert(!candidate->observe({current, when, frames, scanout,
                                    outputCommits(current, frames)}));
        assert(candidate->phase() == Phase::Faulted);
    }

    // Physical mapping must remain the same from protected safety arming
    // through verification, even if the surface and output key are unchanged.
    for (int changed = 0; changed < 3; ++changed) {
        auto drift = scanout;
        if (changed == 0)
            drift[0].connector += 20;
        else if (changed == 1)
            drift[0].crtc += 20;
        else
            drift[0].plane += 20;
        auto heldGate = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
        assert(heldGate && heldGate->spend(held, later, before, scanout));
        assert(!heldGate->observe({held, later, frames, drift, outputCommits(held, frames)}));
        assert(heldGate->phase() == Phase::Faulted);
    }

    // KMS scanout is a separate observation from compositor content and
    // submission counters. A different primary framebuffer, connector
    // alias or missing kernel evidence is never enough to release protection.
    {
        auto badKernel = scanout;
        badKernel[0].framebuffer++;
        auto mismatch = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
        assert(mismatch && mismatch->spend(held, later, before, scanout));
        assert(!mismatch->observe({held, later, frames, badKernel, outputCommits(held, frames)}));
        assert(mismatch->phase() == Phase::Faulted);
        badKernel = scanout;
        badKernel[1].connector = badKernel[0].connector;
        auto alias = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
        assert(alias && alias->spend(held, later, before, scanout));
        assert(!alias->observe({held, later, frames, badKernel, outputCommits(held, frames)}));
        assert(alias->phase() == Phase::Faulted);
        auto absent = NativeFirstFrameGate::arm({held, 13, start, before, scanout});
        assert(absent && absent->spend(held, later, before, scanout));
        assert(!absent->observe({held, later, frames, {}, outputCommits(held, frames)}));
        assert(absent->phase() == Phase::Faulted);
    }

    // Disabled output requires its own newly submitted disabled commit. It
    // cannot borrow the powered root's content frame or a stale disable.
    const auto partlyDisabled = inventory(true);
    const auto disabledBefore = baseline(partlyDisabled);
    const auto disabledKernel = kernel(partlyDisabled);
    auto disabled =
        NativeFirstFrameGate::arm({partlyDisabled, 24, start, disabledBefore, disabledKernel});
    assert(disabled && disabled->spend(partlyDisabled, later, disabledBefore, disabledKernel));
    std::vector<NativeFirstFrameGate::NativeFrame> disabledFrames{
        {partlyDisabled.heads[0].key, &a, &first, 0, false, 301},
        {partlyDisabled.heads[1].key, nullptr, nullptr, 7, true, 0},
    };
    assert(!disabled->observe({partlyDisabled, later, disabledFrames, disabledKernel,
                               outputCommits(partlyDisabled, disabledFrames)}));
    assert(disabled->phase() == Phase::Faulted);
    auto disabledFresh =
        NativeFirstFrameGate::arm({partlyDisabled, 24, start, disabledBefore, disabledKernel});
    assert(disabledFresh);
    assert(disabledFresh->spend(partlyDisabled, later, disabledBefore, disabledKernel));
    disabledFrames[1].disableCommit = 10;
    disabledFrames[1].disableSubmitted = false;
    // The disabled-output commit result may not have arrived yet. It may
    // remain pending under the old high-water, but cannot verify early.
    assert(!disabledFresh->observe({partlyDisabled, later, disabledFrames, disabledKernel,
                                    outputCommits(partlyDisabled, disabledFrames)}));
    assert(disabledFresh->phase() == Phase::Spent);
    disabledFrames[1].disableSubmitted = true;
    const auto disabledReceipt =
        disabledFresh->observe({partlyDisabled, later, disabledFrames, disabledKernel,
                                outputCommits(partlyDisabled, disabledFrames)});
    assert(disabledReceipt);
    assert(disabledReceipt->completedCount == 2);
    assert(disabledReceipt->completed[1].spendHighWater == 7);
    assert(disabledReceipt->completed[1].completedCommit == 10);
    assert(disabledReceipt->completed[1].completedCommit >
           disabledReceipt->completed[1].spendHighWater);
    assert(!disabledReceipt->completed[1].kernel.active);
    assert(disabledReceipt->completed[1].kernel.connector == disabledKernel[1].connector);
    assert(disabledReceipt->completed[1].kernel.crtc == 0);
    assert(disabledReceipt->completed[1].kernel.framebuffer == 0);
    assert(!disabledFresh->observe({partlyDisabled, later, disabledFrames, disabledKernel,
                                    outputCommits(partlyDisabled, disabledFrames)}));

    const ClockSample exhaustedClock{std::numeric_limits<std::uint64_t>::max(), 5'000};
    auto exhaustion = NativeFirstFrameGate::arm({held, 13, exhaustedClock, before, scanout});
    assert(!exhaustion);
    return 0;
}
