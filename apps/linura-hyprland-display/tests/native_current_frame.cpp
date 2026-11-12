#include "native_current_frame_gate.h"

#include <cassert>

using namespace Linura::HyprlandDisplay;
using Gate = NativeCurrentFrameGate;
namespace {
struct Fixture final
{
    Snapshot held;
    Gate::Receipt first{};
    std::vector<Gate::Kernel> kernel;
    std::vector<Gate::Output> commits;
    Fixture()
    {
        held.generation = 81;
        held.securityEpoch = 19;
        held.coverage = Coverage::Secure;
        for (std::uint64_t i = 0; i < 2; ++i) {
            Head head;
            head.key = {i + 1, i + 11};
            head.current.output = head.key;
            head.current.enabled = i == 0;
            head.modes = {{1920, 1080, 60000}};
            if (i == 0) {
                head.current.mode = head.modes[0];
                head.current.scaleMilli = 1000;
                head.powered = head.covered = true;
            }
            head.outputIdentityWitness = "physical:" + std::to_string(i);
            head.baseRuleWitness = "source:" + std::to_string(i);
            held.heads.push_back(head);
            const auto n = static_cast<std::uint32_t>(i);
            kernel.push_back({head.key, n + 100, i == 0 ? 200U : 0U, i == 0 ? 300U : 0U,
                              i == 0 ? 400U : 0U, i == 0});
            commits.push_back({head.key, 9});
            first.completed[i] = {kernel.back(), 7, 9};
        }
        first.generation = 81;
        first.securityEpoch = 19;
        first.postWriteEpoch = 13;
        first.observedUnixMs = 10'000;
        first.observedBootMs = 5'000;
        first.deadlineUnixMs = 12'000;
        first.deadlineBootMs = 7'000;
        first.completedCount = 2;
    }
    std::optional<Gate> arm() const
    {
        return Gate::arm({held, first, {10'100, 5'100}, commits, kernel});
    }
    Gate active() const
    {
        auto gate = arm();
        assert(gate && gate->activate(held, {10'200, 5'200}, commits, kernel));
        return std::move(*gate);
    }
};
void complete(ProtectedFrame &frame, const void *buffer, std::uint64_t commit,
              ProtectedFrame::Kind kind = ProtectedFrame::Kind::Ordinary)
{
    assert(frame.rendered(buffer, kind));
    assert(frame.queued(buffer, commit));
    assert(frame.submitted(commit, true));
    const auto observed = frame.presented(commit, true);
    assert(observed == (kind == ProtectedFrame::Kind::Ordinary
                            ? ProtectedFrame::Presentation::Ordinary
                            : ProtectedFrame::Presentation::Safety));
}
} // namespace
int main()
{
    Fixture f;
    int firstBuffer = 0, successorBuffer = 0, foreignBuffer = 0;
    ProtectedFrame first;
    complete(first, &firstBuffer, 10);
    std::vector<Gate::Frame> frames{{f.held.heads[0].key, &first, &firstBuffer, 0, false, 501},
                                    {f.held.heads[1].key, nullptr, nullptr, 9, true, 0}};
    auto currentKernel = f.kernel;
    currentKernel[0].framebuffer = 501;
    auto currentCommits = f.commits;
    currentCommits[0].previousCommit = 10;
    auto gate = f.arm();
    assert(gate &&
           !gate->observe(
               {f.held, {13'000, 8'000}, {13'010, 8'010}, frames, currentKernel, currentCommits}));
    assert(gate->activate(f.held, {10'200, 5'200}, f.commits, f.kernel));
    assert(!gate->activate(f.held, {10'200, 5'200}, f.commits, f.kernel));
    // Fresh current-state observations may outlive the spent execution window.
    // No method here authorizes a further effect or renews that window.
    auto observed = gate->observe(
        {f.held, {13'000, 8'000}, {13'010, 8'010}, frames, currentKernel, currentCommits});
    assert(observed && observed->completedCount == 2);
    assert(observed->completed[0].spendHighWater == 9);
    assert(observed->completed[0].completedCommit == 10);
    assert(observed->completed[1].completedCommit == 9); // Freshly detached KMS, no new modeset.
    assert(observed->deadlineUnixMs == 15'000 && observed->deadlineBootMs == 10'000);
    ProtectedFrame successor;
    complete(successor, &successorBuffer, 11);
    frames[0] = {f.held.heads[0].key, &successor, &successorBuffer, 0, false, 502};
    currentKernel[0].framebuffer = 502;
    currentCommits[0].previousCommit = 11;
    assert(gate->observe(
        {f.held, {14'000, 9'000}, {14'010, 9'010}, frames, currentKernel, currentCommits}));
    currentCommits[0].previousCommit = 10;
    assert(!gate->observe(
        {f.held, {14'100, 9'100}, {14'110, 9'110}, frames, currentKernel, currentCommits}));
    assert(gate->phase() == Gate::Phase::Faulted);
    assert(!gate->activate(f.held, {10'200, 5'200}, f.commits, f.kernel));

    for (unsigned fault = 0; fault < 12; ++fault) {
        auto candidate = f.active();
        auto held = f.held;
        auto kms = f.kernel;
        kms[0].framebuffer = 501;
        auto commits = f.commits;
        commits[0].previousCommit = 10;
        ProtectedFrame frame;
        complete(frame, &firstBuffer, 10,
                 fault == 0 ? ProtectedFrame::Kind::Safety : ProtectedFrame::Kind::Ordinary);
        std::vector<Gate::Frame> sample{{held.heads[0].key, &frame, &firstBuffer, 0, false, 501},
                                        {held.heads[1].key, nullptr, nullptr, 9, true, 0}};
        ClockSample started{13'000, 8'000}, finished{13'010, 8'010};
        switch (fault) {
        case 0:
            break;
        case 1:
            sample[0].retainedBuffer = &foreignBuffer;
            break;
        case 2:
            sample[0].retainedFramebuffer++;
            break;
        case 3:
            kms[0].crtc++;
            break;
        case 4:
            commits[0].previousCommit++;
            break;
        case 5:
            sample[1].disableCommit++;
            break;
        case 6:
            started.bootMs = 5'000;
            break;
        case 7:
            finished.unixMs = started.unixMs + 2000;
            break;
        case 8:
            finished.bootMs = started.bootMs + 2000;
            break;
        case 9:
            held.securityEpoch++;
            break;
        case 10:
            kms[1].plane = 1;
            break;
        case 11:
            sample[0].key.generation++;
            break;
        }
        assert(!candidate.observe({held, started, finished, sample, kms, commits}));
        assert(candidate.phase() == Gate::Phase::Faulted);
    }
    {
        auto pending = f.active();
        auto kms = f.kernel;
        auto commits = f.commits;
        ProtectedFrame old;
        complete(old, &firstBuffer, 9);
        std::vector<Gate::Frame> sample{{f.held.heads[0].key, &old, &firstBuffer, 0, false, 300},
                                        {f.held.heads[1].key, nullptr, nullptr, 9, true, 0}};
        assert(!pending.observe({f.held, {13'000, 8'000}, {13'010, 8'010}, sample, kms, commits}));
        assert(pending.phase() ==
               Gate::Phase::Active); // Frozen pre-input frame proves no current handoff.
        commits[0].previousCommit = 11;
        sample[0].frame = nullptr;
        assert(!pending.observe({f.held, {13'100, 8'100}, {13'110, 8'110}, sample, kms, commits}));
        assert(pending.phase() == Gate::Phase::Active);
        commits[0].previousCommit = 10;
        assert(!pending.observe({f.held, {13'200, 8'200}, {13'210, 8'210}, sample, kms, commits}));
        assert(pending.phase() ==
               Gate::Phase::Faulted); // Even pending reads cannot hide a regressing counter.
    }
    for (unsigned fault = 0; fault < 8; ++fault) {
        Fixture bad;
        switch (fault) {
        case 0:
            bad.first.completedCount--;
            break;
        case 1:
            bad.first.deadlineBootMs = 5'100;
            break;
        case 2:
            bad.first.deadlineUnixMs = 15'000;
            break;
        case 3:
            bad.first.completed[1].kernel.connector = bad.first.completed[0].kernel.connector;
            bad.kernel[1] = bad.first.completed[1].kernel;
            break;
        case 4:
            bad.held.heads[0].outputIdentityWitness.clear();
            break;
        case 5:
            bad.commits[0].previousCommit++;
            break;
        case 6:
            bad.first.securityEpoch++;
            break;
        case 7:
            bad.first.completed[0].spendHighWater = 9;
            break;
        }
        assert(!bad.arm());
    }
    {
        auto source = f.active();
        auto target = std::move(source);
        assert(source.phase() == Gate::Phase::Faulted && target.phase() == Gate::Phase::Active);
    }
}
