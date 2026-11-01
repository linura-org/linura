#include "display_transaction.h"
#include "mutation_fixture.h"
#include "rule_overlay.h"
#include "native_scale.h"

#include <cassert>
#include <limits>
#include <stdexcept>

using namespace Linura::HyprlandDisplay;

namespace {
const Mode Full{1920, 1080, 60'000}, Small{1280, 720, 60'000};
const ClockSample Start{100'000, 50'000};
const Correlation Bound{"transaction:display-fixture", std::string(64, 'a'), std::string(64, 'b'),
                        115'000};

class Fixture final : public Backend
{
  public:
    Snapshot facts{3,
                   1,
                   {{OutputKey{0, 1},
                     {Full, Small},
                     Target{OutputKey{0, 1}, true, Full, 1000, 0, 0, 0, {}},
                     true,
                     false},
                    {OutputKey{7, 2},
                     {Full, Small},
                     Target{OutputKey{7, 2}, true, Full, 1000, 0, 1920, 0, {}},
                     true,
                     false}},
                   Coverage::Unlocked};
    int writes = 0;
    bool available = true, acknowledge = true, throwWrite = false, performWrite = true;
    ClockSample now = Start;
    bool expireAfterWrite = false;
    bool permitInhibitor = true, inhibited = false, changeDuringInhibition = false;
    unsigned inhibitorReleases = 0;
    unsigned restores = 0;
    bool ownedStateRestored = true;
    [[nodiscard]] bool restoredOwnedState() override
    {
        return ownedStateRestored;
    }
    [[nodiscard]] bool restoreOwnedLayout(const Layout &layout, const Snapshot &expected) override
    {
        ++restores;
        return applyOwnedLayout(layout, expected);
    }
    [[nodiscard]] bool inhibitPowerTransitions() override
    {
        if (!permitInhibitor || inhibited)
            return false;
        inhibited = true;
        if (changeDuringInhibition)
            ++facts.generation;
        return true;
    }
    void releasePowerInhibitor() noexcept override
    {
        assert(inhibited);
        inhibited = false;
        ++inhibitorReleases;
    }
    [[nodiscard]] std::optional<ClockSample> clock() override
    {
        return now;
    }
    [[nodiscard]] std::optional<Snapshot> snapshot() override
    {
        return available ? std::optional(facts) : std::nullopt;
    }
    [[nodiscard]] bool applyOwnedLayout(const Layout &layout, const Snapshot &expected) override
    {
        assert(expected.generation == facts.generation);
        assert(inhibited); // Includes compensation, never just the initial apply.
        ++writes;
        if (expireAfterWrite)
            now.bootMs = 65'000;
        if (performWrite) {
            for (std::size_t i = 0; i < layout.size(); ++i)
                facts.heads[i].current = layout[i];
        }
        if (throwWrite)
            throw std::runtime_error("injected native reply loss");
        return acknowledge;
    }
    Layout baseline() const
    {
        return {facts.heads[0].current, facts.heads[1].current};
    }
    Layout desired() const
    {
        auto result = baseline();
        result[0].mode = Small;
        result[1].x = 1280;
        return result;
    }
};

void desiredVerificationAndCorrelation()
{
    Fixture native;
    auto attempt =
        DisplayTransaction::start(native, Bound, native.baseline(), native.desired(), native.facts,
                                  Start, std::make_shared<Test::MutationFixture>());
    assert(attempt && native.writes == 1 && attempt->fenced());
    for (int field = 0; field != 4; ++field) {
        auto substitute = Bound;
        if (field == 0)
            substitute.transaction += "-other";
        if (field == 1)
            substitute.effectDigest[0] = 'c';
        if (field == 2)
            substitute.dispatchDigest[0] = 'c';
        if (field == 3)
            ++substitute.deadlineUnixMs;
        assert(!attempt->confirm(substitute, {100'100, 50'100}));
    }
    native.facts.heads[0].current.scaleMilli = 1125;
    assert(!attempt->confirm(Bound, {100'100, 50'100}));
    native.facts.heads[0].current.scaleMilli = 1000;
    native.facts.heads[0].powered = false;
    native.facts.heads[1].powered = false;
    assert(!attempt->confirm(Bound, {100'100, 50'100}));
    native.facts.heads[1].powered = true;
    assert(attempt->confirm(Bound, {100'100, 50'100}));
    assert(!attempt->fenced() && attempt->phase() == DisplayTransaction::Phase::Confirmed);
    attempt->restore();
    attempt->tick(std::nullopt);
    assert(!attempt->confirm(Bound, {100'100, 50'100}) && native.writes == 1);
}

void deadlinesAndOneCompensation()
{
    for (const auto clock :
         {std::optional<ClockSample>({115'000, 50'100}),
          std::optional<ClockSample>({100'100, 65'000}),
          std::optional<ClockSample>({99'999, 50'100}),
          std::optional<ClockSample>({100'100, 49'999}), std::optional<ClockSample>{}}) {
        Fixture native;
        const auto baseline = native.baseline();
        auto attempt =
            DisplayTransaction::start(native, Bound, baseline, native.desired(), native.facts,
                                      Start, std::make_shared<Test::MutationFixture>());
        assert(attempt && native.writes == 1);
        attempt->tick(clock);
        assert(native.writes == 2 && attempt->fenced());
        assert(attempt->phase() == DisplayTransaction::Phase::Restoring);
        assert(native.baseline() == baseline);
        assert(!attempt->confirm(Bound, {100'100, 50'100}));
        attempt->tick(std::nullopt);
        assert(attempt->phase() == DisplayTransaction::Phase::Restored && !attempt->fenced());
        attempt->restore();
        attempt->tick(std::nullopt);
        assert(native.writes == 2);
    }
}

void replyLossAndIndependentRestoration()
{
    for (bool exception : {false, true}) {
        Fixture native;
        const auto baseline = native.baseline();
        native.acknowledge = false;
        native.throwWrite = exception;
        auto attempt =
            DisplayTransaction::start(native, Bound, baseline, native.desired(), native.facts,
                                      Start, std::make_shared<Test::MutationFixture>());
        assert(attempt && native.writes == 2 && attempt->fenced());
        assert(attempt->phase() == DisplayTransaction::Phase::RecoveryFailed);
        native.available = false;
        attempt->tick(Start);
        assert(attempt->fenced() && native.writes == 2);
        native.available = true;
        native.facts.heads[0].current.transform = 1;
        attempt->tick(Start);
        assert(attempt->fenced() && native.writes == 2);
        native.facts.heads[0].current = baseline[0];
        attempt->tick(Start);
        assert(!attempt->fenced() && native.writes == 2);
    }
    Fixture native;
    native.performWrite = false;
    auto attempt =
        DisplayTransaction::start(native, Bound, native.baseline(), native.desired(), native.facts,
                                  Start, std::make_shared<Test::MutationFixture>());
    assert(attempt && !attempt->confirm(Bound, {100'100, 50'100}));
    attempt->restore();
    assert(attempt->fenced()); // ACK, including a no-op ACK, is never verification.
    attempt->tick(Start);
    assert(!attempt->fenced());
    Fixture delayed;
    delayed.expireAfterWrite = true;
    auto expired =
        DisplayTransaction::start(delayed, Bound, delayed.baseline(), delayed.desired(),
                                  delayed.facts, Start, std::make_shared<Test::MutationFixture>());
    assert(expired && delayed.writes == 2 &&
           expired->phase() == DisplayTransaction::Phase::Restoring);
}

void identityAndCoverageFences()
{
    for (int fault = 0; fault != 10; ++fault) {
        Fixture native;
        native.facts.coverage = Coverage::Secure;
        for (auto &head : native.facts.heads)
            head.covered = true;
        auto attempt = DisplayTransaction::start(native, Bound, native.baseline(), native.desired(),
                                                 native.facts, Start,
                                                 std::make_shared<Test::MutationFixture>());
        assert(attempt && native.writes == 1);
        if (fault == 0)
            ++native.facts.generation;
        if (fault == 1)
            ++native.facts.heads[1].key.generation;
        if (fault == 2)
            native.facts.heads[1].modes.pop_back();
        if (fault == 3)
            native.facts.coverage = Coverage::Unlocked;
        if (fault == 4)
            native.facts.coverage = Coverage::Transitioning;
        if (fault == 5)
            native.facts.heads[1].covered = false;
        if (fault == 6)
            native.available = false;
        if (fault == 7)
            ++native.facts.securityEpoch;
        if (fault == 8)
            native.facts.heads[1].baseRuleWitness = "LNDR:1;1;";
        if (fault == 9)
            native.facts.heads[1].outputIdentityWitness = "LNDF:1;1;";
        assert(!attempt->confirm(Bound, {100'100, 50'100}));
        attempt->restore();
        assert(attempt->phase() == DisplayTransaction::Phase::RecoveryFailed && native.writes == 1);
        attempt->tick(std::nullopt);
        assert(attempt->fenced() && native.writes == 1);
    }
    Fixture native;
    auto attempt =
        DisplayTransaction::start(native, Bound, native.baseline(), native.desired(), native.facts,
                                  Start, std::make_shared<Test::MutationFixture>());
    native.facts.coverage = Coverage::Secure;
    for (auto &head : native.facts.heads)
        head.covered = true;
    // A fresh protected topology with the wrong geometry records acquisition
    // of protection even though it cannot confirm the layout.
    native.facts.heads[0].current.mode = Full;
    assert(!attempt->confirm(Bound, {100'100, 50'100}));
    native.facts.heads[0].current.mode = Small;
    native.facts.coverage = Coverage::Unlocked;
    assert(!attempt->confirm(Bound, {100'100, 50'100}));
}

void rejectBeforeWrite()
{
    for (int fault = 0; fault != 16; ++fault) {
        Fixture native;
        auto baseline = native.baseline(), desired = native.desired();
        auto correlation = Bound;
        auto clock = Start;
        if (fault == 0)
            correlation.effectDigest = std::string(64, '0');
        if (fault == 1)
            correlation.dispatchDigest[0] = 'F';
        if (fault == 2)
            correlation.transaction = "transaction:../other";
        if (fault == 3)
            correlation.deadlineUnixMs++;
        if (fault == 4)
            clock.bootMs = std::numeric_limits<std::uint64_t>::max();
        if (fault == 5)
            baseline[0].mode = Small;
        if (fault == 6)
            desired.pop_back();
        if (fault == 7)
            desired[0].mode.refreshMilliHz = 59'999;
        if (fault == 8)
            desired[1].output = desired[0].output;
        if (fault == 9)
            desired[0].scaleMilli = 499;
        if (fault == 10)
            desired[0].transform = 8;
        if (fault == 11)
            desired[0].x = std::numeric_limits<std::int32_t>::min();
        if (fault == 12)
            desired[0].mirror = desired[0].output;
        if (fault == 13) {
            const auto one = desired[0].output, two = desired[1].output;
            desired[0] = Target{};
            desired[1] = Target{};
            desired[0].output = one;
            desired[1].output = two;
        }
        if (fault == 14)
            native.facts.heads[1].modes.push_back(Full);
        if (fault == 15)
            native.facts.securityEpoch = 0;
        assert(!DisplayTransaction::start(native, correlation, baseline, desired, native.facts,
                                          clock, std::make_shared<Test::MutationFixture>()));
        assert(native.writes == 0);
    }
    Fixture native;
    {
        auto attempt = DisplayTransaction::start(native, Bound, native.baseline(), native.desired(),
                                                 native.facts, Start,
                                                 std::make_shared<Test::MutationFixture>());
        assert(attempt && native.writes == 1);
    }
    assert(native.writes == 2); // Ordinary destruction cannot silently disarm.
}

// A deliberately non-native fixture with conspicuous unmanaged fields. Actual
// integration qualification must instantiate the template against the exact
// pinned upstream CMonitorRule and inspect native color/VRR/ICC/reservations.
struct FixtureRule final
{
    struct Point
    {
        int x = 0, y = 0;
        bool operator==(const Point &) const = default;
    };
    bool m_disabled = false;
    Point m_resolution, m_offset;
    float m_refreshRate = 75, m_scale = 2;
    int m_autoDir = 6, m_transform = 7;
    std::string m_mirrorOf = "other";
    int m_drmMode = 123;
    std::string m_name = "desc:original selector", m_iccFile = "/unmanaged/profile.icc";
    int m_vrr = 2, m_reservedArea = 73, futureUpstreamProperty = 12345;
};
void staleCapturedInventoryNeverDispatches()
{
    for (int changed = 0; changed != 7; ++changed) {
        Fixture native;
        const auto captured = native.facts;
        const auto baseline = native.baseline(), desired = native.desired();
        if (changed == 0)
            ++native.facts.generation;
        if (changed == 1)
            ++native.facts.securityEpoch;
        if (changed == 2)
            native.facts.coverage = Coverage::Secure;
        if (changed == 3)
            native.facts.heads[0].powered = false;
        if (changed == 4)
            native.facts.heads[0].modes.pop_back();
        if (changed == 5)
            native.facts.heads[0].baseRuleWitness = "LNDR:1;1;";
        if (changed == 6)
            native.facts.heads[0].outputIdentityWitness = "LNDF:1;1;";
        assert(!DisplayTransaction::start(native, Bound, baseline, desired, captured, Start,
                                          std::make_shared<Test::MutationFixture>()));
        assert(native.writes == 0);
    }
}

void exactNativeScaleRoundTrip()
{
    for (std::uint32_t milli = 500; milli <= 4000; ++milli) {
        const auto value = static_cast<float>(milli) / 1000.F;
        assert(nativeScaleMilli(value) == milli);
        assert(std::bit_cast<float>(nativeScaleBits(milli)) == value);
    }
    assert(!nativeScaleMilli(0.499F));
    assert(!nativeScaleMilli(4.001F));
    assert(!nativeScaleMilli(1.234567F));
    assert(!nativeScaleMilli(std::numeric_limits<float>::infinity()));
    assert(!nativeScaleMilli(std::numeric_limits<float>::quiet_NaN()));
    Fixture native;
    auto desired = native.desired();
    desired[0].scaleMilli = 1200;
    assert(DisplayTransaction::validLayout(desired, native.facts));
}

void preserveUnmanagedRuleFields()
{
    Fixture native;
    const FixtureRule original;
    auto target = native.desired()[0];
    target.transform = 1;
    target.scaleMilli = 1250;
    const auto patched = overlayDisplayFields(original, target, "");
    assert(patched.m_name == original.m_name && patched.m_iccFile == original.m_iccFile &&
           patched.m_vrr == original.m_vrr && patched.m_reservedArea == original.m_reservedArea &&
           patched.futureUpstreamProperty == original.futureUpstreamProperty);
    assert((patched.m_resolution == FixtureRule::Point{1280, 720}) && patched.m_transform == 1 &&
           patched.m_scale == 1.25F && patched.m_refreshRate == 60.F &&
           patched.m_mirrorOf.empty() && patched.m_drmMode == 0);
    target.enabled = false;
    const auto disabled = overlayDisplayFields(original, target, "");
    assert(disabled.m_disabled && disabled.m_resolution == original.m_resolution &&
           disabled.m_scale == original.m_scale && disabled.m_iccFile == original.m_iccFile);
}
void powerCoordinationBeforeWriteAndThroughRecovery()
{
    {
        Fixture native;
        native.permitInhibitor = false;
        assert(!DisplayTransaction::start(native, Bound, native.baseline(), native.desired(),
                                          native.facts, Start,
                                          std::make_shared<Test::MutationFixture>()));
        assert(native.writes == 0 && !native.inhibited && native.inhibitorReleases == 0);
    }
    {
        Fixture native;
        native.changeDuringInhibition = true;
        const auto captured = native.facts;
        assert(!DisplayTransaction::start(native, Bound, native.baseline(), native.desired(),
                                          captured, Start,
                                          std::make_shared<Test::MutationFixture>()));
        assert(native.writes == 0 && !native.inhibited && native.inhibitorReleases == 1);
    }
    {
        Fixture native;
        const auto baseline = native.baseline(), desired = native.desired();
        auto attempt = DisplayTransaction::start(native, Bound, baseline, desired, native.facts,
                                                 Start, std::make_shared<Test::MutationFixture>());
        assert(attempt && native.inhibited && native.inhibitorReleases == 0);
        attempt->restore();
        assert(native.writes == 2 && native.inhibited && attempt->fenced());
        // A transport acknowledgement does not retire the native inhibitor.
        native.available = false;
        attempt->tick(Start);
        assert(native.inhibited && attempt->fenced());
        native.available = true;
        attempt->tick(Start);
        assert(!native.inhibited && native.inhibitorReleases == 1 && !attempt->fenced());
        attempt->tick(Start);
        assert(native.inhibitorReleases == 1);
    }
    {
        Fixture native;
        auto attempt = DisplayTransaction::start(native, Bound, native.baseline(), native.desired(),
                                                 native.facts, Start,
                                                 std::make_shared<Test::MutationFixture>());
        assert(attempt && native.inhibited);
        native.available = false;
        attempt->restore();
        assert(attempt->phase() == DisplayTransaction::Phase::RecoveryFailed && native.inhibited);
        attempt.reset();
        assert(native.inhibited && native.inhibitorReleases == 0 && native.writes == 1);
    }
}
void numericBaselineCannotSubstituteForRestoredOwnership()
{
    Fixture native;
    const auto baseline = native.baseline();
    auto attempt =
        DisplayTransaction::start(native, Bound, baseline, native.desired(), native.facts, Start,
                                  std::make_shared<Test::MutationFixture>());
    assert(attempt);
    native.ownedStateRestored = false;
    attempt->restore();
    assert(native.baseline() == baseline && native.restores == 1);
    attempt->tick(Start);
    assert(attempt->phase() == DisplayTransaction::Phase::Restoring && native.inhibited);
    attempt->restore();
    assert(native.restores == 1 && native.writes == 2);
    native.ownedStateRestored = true;
    attempt->tick(Start);
    assert(attempt->phase() == DisplayTransaction::Phase::Restored && !native.inhibited);
    assert(native.restores == 1 && native.writes == 2);
}
void overlayCheckpointCannotBeReplacedOrRetargeted()
{
    Fixture native;
    using Checkpoint = RuleOverlayCheckpoint<int, int>;
    Checkpoint checkpoint;
    Checkpoint::Overlay previous{{10, native.baseline()[0]}};
    const Checkpoint::Rules rules{{10, 100}, {20, 200}};
    const auto same = [](int a, int b) { return a == b; };
    assert(checkpoint.capture(previous, rules, native.baseline()));
    assert(!checkpoint.capture({}, rules, native.desired()));
    assert(!checkpoint.restoration(native.desired(), rules, same));
    auto changed = rules;
    changed[10] = 101;
    assert(!checkpoint.restoration(native.baseline(), changed, same));
    changed = rules;
    changed.erase(10);
    changed.emplace(30, 100);
    assert(!checkpoint.restoration(native.baseline(), changed, same));
    assert(!checkpoint.restored({}, rules, same));
    const auto restored = checkpoint.restoration(native.baseline(), rules, same);
    assert(restored && *restored == previous && checkpoint.restored(*restored, rules, same));
    assert(checkpoint.retained() && checkpoint.owns(10, native.baseline()[0].output));
    assert(!checkpoint.owns(30, native.baseline()[0].output));
    auto replaced = native.baseline()[0].output;
    ++replaced.generation;
    assert(!checkpoint.owns(10, replaced));
    checkpoint.retire();
    assert(!checkpoint.retained() && !checkpoint.restoration(native.baseline(), rules, same));
}
void nativeProtectionIsRequiredAndRetainedThroughRecovery()
{
    Fixture native;
    assert(!DisplayTransaction::start(native, Bound, native.baseline(), native.desired(),
                                      native.facts, Start, {}));
    assert(native.writes == 0 && !native.inhibited);
    auto protection = std::make_shared<Test::MutationFixture>();
    protection->allowApply = false;
    assert(!DisplayTransaction::start(native, Bound, native.baseline(), native.desired(),
                                      native.facts, Start, protection));
    assert(native.writes == 0 && !native.inhibited && protection->releases == 1);

    protection = std::make_shared<Test::MutationFixture>();
    protection->applyPresented = protection->restorePresented = false;
    protection->keepDecision = false;
    auto attempt = DisplayTransaction::start(native, Bound, native.baseline(), native.desired(),
                                             native.facts, Start, protection);
    assert(attempt && native.writes == 1 && protection->ends == 1);
    assert(!attempt->confirm(Bound, Start)); // Backend ACK is not presentation.
    protection->applyPresented = true;
    assert(!attempt->confirm(Bound, Start)); // Apply proof is not a Keep choice.
    protection->live = false;                // Owner/resources disappear before the deadline.
    attempt->tick(Start);
    assert(native.restores == 1 && protection->restores == 1 && protection->ends == 2);
    attempt->tick(Start);
    assert(attempt->phase() == DisplayTransaction::Phase::Restoring && native.inhibited);
    assert(protection->releases == 0); // Numeric baseline is insufficient.
    protection->restorePresented = true;
    attempt->tick(Start);
    assert(attempt->phase() == DisplayTransaction::Phase::Restored && !native.inhibited);
    assert(protection->releases == 1 && native.restores == 1);
}
void ambiguousWriteAlwaysCompletesItsProtectionStack()
{
    Fixture native;
    native.throwWrite = true;
    auto protection = std::make_shared<Test::MutationFixture>();
    auto attempt = DisplayTransaction::start(native, Bound, native.baseline(), native.desired(),
                                             native.facts, Start, protection);
    assert(attempt && native.writes == 2 && protection->applies == 1 && protection->restores == 1);
    assert(protection->ends == 2 && protection->releases == 0 && native.inhibited);
    protection->restorePresented = false;
    attempt->tick(Start);
    assert(attempt->fenced() && protection->releases == 0);
    protection->restorePresented = true;
    attempt->tick(Start);
    assert(!attempt->fenced() && protection->releases == 1 && !native.inhibited);
}

void protectedMultiOutputChangesRequireIndependentRetirement()
{
    for (const bool keep : {false, true}) {
        Fixture native;
        // The compositor maintains its own opaque safety coverage for every
        // head while locked; owner/Control lock-surface evidence is separate.
        native.facts.coverage = Coverage::Secure;
        for (auto &head : native.facts.heads)
            head.covered = true;
        const auto baseline = native.baseline();
        auto desired = native.desired();
        desired[1] = Target{baseline[1].output, false, {}, 0, 0, 0, 0, {}};
        assert(DisplayTransaction::validLayout(desired, native.facts));

        auto protection = std::make_shared<Test::MutationFixture>();
        protection->applyPresented = false;
        auto attempt = DisplayTransaction::start(native, Bound, baseline, desired, native.facts,
                                                 Start, protection);
        assert(attempt && attempt->fenced() && native.writes == 1 && native.inhibited);
        assert(native.facts.heads[1].current == desired[1]);
        // Neither a successful modeset nor one covered remaining output is
        // permission to Keep: all enabled-head presentation belongs to the
        // independently consumed native protection.
        assert(!attempt->confirm(Bound, {100'100, 50'100}));
        protection->applyPresented = true;
        if (keep) {
            protection->keepDecision = false;
            assert(!attempt->confirm(Bound, {100'100, 50'100}));
            protection->keepDecision = true;
            assert(attempt->confirm(Bound, {100'100, 50'100}));
            assert(attempt->phase() == DisplayTransaction::Phase::Confirmed);
            assert(!attempt->fenced() && native.writes == 1 && !native.inhibited);
            assert(!attempt->requestRestore(Bound, {100'100, 50'100}));
        } else {
            protection->revertDecision = false;
            assert(!attempt->requestRestore(Bound, {100'100, 50'100}));
            assert(native.writes == 1 && native.inhibited);
            protection->revertDecision = true;
            protection->restorePresented = false;
            native.ownedStateRestored = false;
            assert(attempt->requestRestore(Bound, {100'100, 50'100}));
            assert(attempt->phase() == DisplayTransaction::Phase::Restoring);
            assert(native.baseline() == baseline && native.restores == 1);
            attempt->tick(ClockSample{100'200, 50'200});
            assert(attempt->fenced() && native.inhibited && protection->releases == 0);
            native.ownedStateRestored = true;
            attempt->tick(ClockSample{100'200, 50'200});
            assert(attempt->fenced() && native.inhibited); // No completed restore frame.
            protection->restorePresented = true;
            attempt->tick(ClockSample{100'200, 50'200});
            assert(attempt->phase() == DisplayTransaction::Phase::Restored);
            assert(!attempt->fenced() && !native.inhibited && protection->releases == 1);
            assert(native.writes == 2 && native.restores == 1);
            assert(!attempt->confirm(Bound, {100'200, 50'200}));
            assert(!attempt->requestRestore(Bound, {100'200, 50'200}));
        }
    }
}

void failedProtectedRestorationNeverReplaysOrReleasesItsFence()
{
    Fixture native;
    const auto baseline = native.baseline();
    auto protection = std::make_shared<Test::MutationFixture>();
    protection->allowRestore = false;
    auto attempt = DisplayTransaction::start(native, Bound, baseline, native.desired(),
                                             native.facts, Start, protection);
    assert(attempt && native.inhibited && native.writes == 1);
    attempt->restore();
    assert(attempt->phase() == DisplayTransaction::Phase::RecoveryFailed);
    assert(attempt->fenced() && native.inhibited && native.restores == 0);
    assert(protection->restores == 1 && protection->releases == 0);
    for (int i = 0; i < 3; ++i) {
        attempt->restore();
        attempt->tick(ClockSample{100'500, 50'500});
        assert(attempt->phase() == DisplayTransaction::Phase::RecoveryFailed);
        assert(native.writes == 1 && native.inhibited && protection->restores == 1);
    }
    attempt.reset();
    // Compositor-local loss is not a verified recovery or permission to start
    // a new transaction. A replacement requires independent durable recovery.
    assert(native.inhibited && native.inhibitorReleases == 0 && protection->releases == 0);
}

void scenePreparationCannotRenewTheDispatchBudget()
{
    Fixture native;
    auto protection = std::make_shared<Test::MutationFixture>();
    protection->onApply = [&] { native.now.bootMs = 65'000; };
    assert(!DisplayTransaction::start(native, Bound, native.baseline(), native.desired(),
                                      native.facts, Start, protection));
    assert(native.writes == 0 && !native.inhibited && protection->ends == 1 &&
           protection->releases == 1);
}
} // namespace

int main()
{
    desiredVerificationAndCorrelation();
    deadlinesAndOneCompensation();
    replyLossAndIndependentRestoration();
    identityAndCoverageFences();
    rejectBeforeWrite();
    staleCapturedInventoryNeverDispatches();
    exactNativeScaleRoundTrip();
    preserveUnmanagedRuleFields();
    powerCoordinationBeforeWriteAndThroughRecovery();
    numericBaselineCannotSubstituteForRestoredOwnership();
    overlayCheckpointCannotBeReplacedOrRetargeted();
    nativeProtectionIsRequiredAndRetainedThroughRecovery();
    ambiguousWriteAlwaysCompletesItsProtectionStack();
    scenePreparationCannotRenewTheDispatchBudget();
    protectedMultiOutputChangesRequireIndependentRetirement();
    failedProtectedRestorationNeverReplaysOrReleasesItsFence();
}
