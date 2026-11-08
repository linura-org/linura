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
    assert(!NativeFirstFrameGate::arm({held, 0, start, before}));
    assert(!NativeFirstFrameGate::arm({held, 1, {}, before}));
    assert(!NativeFirstFrameGate::arm({held, 1, start, {}}));
    auto invalid = held;
    invalid.coverage = Coverage::Unknown;
    assert(!NativeFirstFrameGate::arm({invalid, 1, start, before}));
    invalid = held;
    invalid.heads[0].outputIdentityWitness.clear();
    assert(!NativeFirstFrameGate::arm({invalid, 1, start, before}));
    invalid = held;
    invalid.heads[0].powered = false;
    assert(!NativeFirstFrameGate::arm({invalid, 1, start, before}));
    invalid = held;
    invalid.heads[1].key = invalid.heads[0].key;
    assert(!NativeFirstFrameGate::arm({invalid, 1, start, before}));
    auto mismatched = before;
    mismatched[0].key.generation++;
    assert(!NativeFirstFrameGate::arm({held, 1, start, mismatched}));

    auto gate = NativeFirstFrameGate::arm({held, 13, start, before});
    assert(gate && gate->phase() == Phase::Held);
    assert(!gate->observe({held, later, {}, scanout}));
    assert(!gate->spend(held, {9'999, 4'999}, before));
    assert(gate->phase() == Phase::Faulted);
    assert(!gate->spend(held, later, before));

    // One physical native completion cannot satisfy two independent output
    // keys by aliasing a tracker. Mirrored content may share bytes, but each
    // output must have its own native completed-frame witness.
    {
        ProtectedFrame shared;
        completed(shared, &first, 8, Kind::Content);
        auto alias = NativeFirstFrameGate::arm({held, 13, start, before});
        assert(alias && alias->spend(held, later, before));
        std::vector<NativeFirstFrameGate::NativeFrame> reused{
            {held.heads[0].key, &shared, &first, 0, false, 301},
            {held.heads[1].key, &shared, &first, 0, false, 301},
        };
        assert(!alias->observe({held, later, reused, scanout}));
        assert(alias->phase() == Phase::Faulted);
        assert(!alias->spend(held, later, before));
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
        auto preSpent = NativeFirstFrameGate::arm({held, 13, start, before});
        assert(preSpent && preSpent->spend(held, later, moved));
        std::vector<NativeFirstFrameGate::NativeFrame> staleFrames{
            {held.heads[0].key, &stale, &first, 0, false, 301},
            {held.heads[1].key, &fresh, &second, 0, false, 302},
        };
        assert(!preSpent->observe({held, later, staleFrames, scanout}));
        assert(preSpent->phase() == Phase::Faulted);
        assert(!preSpent->spend(held, later, moved));

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
            auto gated = NativeFirstFrameGate::arm({held, 13, start, before});
            assert(gated && !gated->spend(held, later, bad));
            assert(gated->phase() == Phase::Faulted);
            assert(!gated->spend(held, later, before));
        }
    }

    // A completed opaque frame is NOT a first ordinary frame, and neither is
    // an old hardware completion or a presented frame on the wrong buffer.
    for (int scenario = 0; scenario < 4; ++scenario) {
        ProtectedFrame a;
        ProtectedFrame b;
        auto proof = NativeFirstFrameGate::arm({held, 13, start, before});
        assert(proof && proof->spend(held, later, before));
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
        assert(!proof->observe({held, later, frames, scanout}));
        assert(proof->phase() == Phase::Faulted);
        assert(!proof->spend(held, later, before));
    }

    // No first frame remains pending, without extending the original clocks.
    ProtectedFrame a;
    ProtectedFrame b;
    auto proof = NativeFirstFrameGate::arm({held, 13, start, before});
    assert(proof && proof->spend(held, later, before));
    std::vector<NativeFirstFrameGate::NativeFrame> frames{
        {held.heads[0].key, &a, &first, 0, false, 301},
        {held.heads[1].key, &b, &second, 0, false, 302},
    };
    assert(!proof->observe({held, later, frames, scanout}));
    assert(proof->phase() == Phase::Spent);
    completed(a, &first, 8, Kind::Content);
    assert(!proof->observe({held, later, frames, scanout}));
    completed(b, &second, 9, Kind::Content);
    const auto receipt = proof->observe({held, later, frames, scanout});
    assert(receipt);
    assert(receipt->generation == held.generation);
    assert(receipt->securityEpoch == held.securityEpoch);
    assert(receipt->postWriteEpoch == 13);
    assert(receipt->completedCount == 2);
    assert(receipt->completed[0].second == 8);
    assert(receipt->completed[1].second == 9);
    assert(proof->phase() == Phase::Verified);
    assert(!proof->observe({held, later, frames, scanout})); // Never redeliver or renew.
    assert(!proof->spend(held, later, before));

    for (int scenario = 0; scenario < 5; ++scenario) {
        auto current = held;
        auto candidate = NativeFirstFrameGate::arm({held, 13, start, before});
        assert(candidate && candidate->spend(held, later, before));
        if (scenario == 0)
            current.generation++;
        else if (scenario == 1)
            current.securityEpoch++;
        else if (scenario == 2)
            current.heads[0].baseRuleWitness = "replaced-source";
        else if (scenario == 3)
            current.heads[0].current.x++;
        const auto when = scenario == 4 ? ClockSample{12'000, 7'000} : later;
        assert(!candidate->observe({current, when, frames, scanout}));
        assert(candidate->phase() == Phase::Faulted);
    }

    // KMS scanout is a separate observation from compositor content and
    // submission counters. A different primary framebuffer, connector
    // alias or missing kernel evidence is never enough to release protection.
    {
        auto badKernel = scanout;
        badKernel[0].framebuffer++;
        auto mismatch = NativeFirstFrameGate::arm({held, 13, start, before});
        assert(mismatch && mismatch->spend(held, later, before));
        assert(!mismatch->observe({held, later, frames, badKernel}));
        assert(mismatch->phase() == Phase::Faulted);
        badKernel = scanout;
        badKernel[1].connector = badKernel[0].connector;
        auto alias = NativeFirstFrameGate::arm({held, 13, start, before});
        assert(alias && alias->spend(held, later, before));
        assert(!alias->observe({held, later, frames, badKernel}));
        assert(alias->phase() == Phase::Faulted);
        auto absent = NativeFirstFrameGate::arm({held, 13, start, before});
        assert(absent && absent->spend(held, later, before));
        assert(!absent->observe({held, later, frames, {}}));
        assert(absent->phase() == Phase::Faulted);
    }

    // Disabled output requires its own newly submitted disabled commit. It
    // cannot borrow the powered root's content frame or a stale disable.
    const auto partlyDisabled = inventory(true);
    const auto disabledBefore = baseline(partlyDisabled);
    const auto disabledKernel = kernel(partlyDisabled);
    auto disabled = NativeFirstFrameGate::arm({partlyDisabled, 24, start, disabledBefore});
    assert(disabled && disabled->spend(partlyDisabled, later, disabledBefore));
    std::vector<NativeFirstFrameGate::NativeFrame> disabledFrames{
        {partlyDisabled.heads[0].key, &a, &first, 0, false, 301},
        {partlyDisabled.heads[1].key, nullptr, nullptr, 7, true, 0},
    };
    assert(!disabled->observe({partlyDisabled, later, disabledFrames, disabledKernel}));
    assert(disabled->phase() == Phase::Faulted);
    auto disabledFresh = NativeFirstFrameGate::arm({partlyDisabled, 24, start, disabledBefore});
    assert(disabledFresh && disabledFresh->spend(partlyDisabled, later, disabledBefore));
    disabledFrames[1].disableCommit = 10;
    assert(disabledFresh->observe({partlyDisabled, later, disabledFrames, disabledKernel}));
    assert(!disabledFresh->observe({partlyDisabled, later, disabledFrames, disabledKernel}));

    const ClockSample exhaustedClock{std::numeric_limits<std::uint64_t>::max(), 5'000};
    auto exhaustion = NativeFirstFrameGate::arm({held, 13, exhaustedClock, before});
    assert(!exhaustion);
    return 0;
}
