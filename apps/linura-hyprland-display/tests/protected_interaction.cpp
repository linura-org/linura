// Native lifetime tests only. This does not simulate PAM, physical presentation,
// a trusted session, a protected compositor or executable authority into evidence.
#include "protected_interaction.h"

#include <array>
#include <cassert>
#include <limits>
#include <type_traits>
#include <utility>

using namespace Linura::HyprlandDisplay;
static_assert(!std::is_copy_constructible_v<ProtectedInteraction>);
static_assert(!std::is_copy_assignable_v<ProtectedInteraction>);
namespace {
constexpr OutputKey One{1, 2}, Two{2, 3};
Snapshot inventory()
{
    const Mode full{1920, 1080, 60'000};
    return {4,
            5,
            {{One, {full}, {One, true, full, 1000, 0, 0, 0, {}}, true, false},
             {Two, {full}, {Two, true, full, 1000, 0, 1920, 0, {}}, true, false}},
            Coverage::Unlocked};
}
ProtectedInteraction::Scope
scope(ProtectedInteraction::Purpose purpose = ProtectedInteraction::Purpose::Keep)
{
    return {std::string(64, 'a'), purpose, 25'000};
}
ProtectedInteraction conversation()
{
    auto result = ProtectedInteraction::start(scope(), inventory(), {10'000, 1000}, 6);
    assert(result);
    return std::move(*result);
}
void ready(ProtectedInteraction &value)
{
    assert(value.configure(One, 1) && value.configure(Two, 2));
    assert(value.commit(One, 1, 20) && value.commit(Two, 2, 30));
    value.presented(One, 20, true);
    value.presented(Two, 30, true);
    value.focus(One);
    assert(value.eligible(value.epoch(), inventory(), {10'000, 1000}));
}
void everyOutputNeedsCorrelatedPresentation()
{
    auto value = conversation();
    value.focus(One);
    assert(!value.eligible(value.epoch(), inventory(), {10'000, 1000}));
    assert(value.configure(One, 1) && value.configure(Two, 2));
    assert(value.commit(One, 1, 20) && value.commit(Two, 2, 30));
    const auto epoch = value.epoch();
    value.presented(One, 0, true);
    value.presented(Two, 29, true);
    assert(!value.eligible(epoch, inventory(), {10'000, 1000}));
    value.presented(One, 20, true);
    assert(!value.eligible(epoch, inventory(), {10'000, 1000}));
    value.presented(Two, 30, true);
    assert(value.eligible(epoch, inventory(), {10'000, 1000}));
    // Ordinary trusted repaint preserves the safe presented configure and input
    // epoch. It cannot renew the scope/deadline or qualify a new configure.
    assert(value.commit(One, 1, 21));
    assert(value.eligible(epoch, inventory(), {10'000, 1000}));
    value.presented(One, 20, true);
    assert(value.eligible(epoch, inventory(), {10'000, 1000}));
    assert(value.configure(One, 3));
    assert(!value.eligible(epoch, inventory(), {10'000, 1000}) &&
           !value.eligible(value.epoch(), inventory(), {10'000, 1000}));
    value.presented(One, 21, true);
    assert(!value.eligible(value.epoch(), inventory(), {10'000, 1000}));
    assert(value.commit(One, 3, 22));
    value.presented(One, 22, true);
    assert(value.eligible(value.epoch(), inventory(), {10'000, 1000}));
}
void backendCommitIdsCannotBeReused()
{
    auto value = conversation();
    ready(value);
    assert(value.commit(One, 1, 21));
    assert(value.configure(One, 3));
    assert(!value.commit(One, 3, 20));
    assert(value.phase() == ProtectedInteraction::Phase::Cancelled);
}
void opaqueSafetyCannotPreserveOrRearmInteractionProof()
{
    auto value = conversation();
    ready(value);
    const auto readyEpoch = value.epoch();
    assert(value.safetyFrame(One));
    assert(value.epoch() != readyEpoch);
    value.presented(One, 20, true); // Old content event, after the black replacement.
    assert(!value.eligible(readyEpoch, inventory(), {10'001, 1001}));
    assert(!value.eligible(value.epoch(), inventory(), {10'001, 1001}));
    assert(value.commit(One, 1, 21));
    value.presented(One, 21, true);
    const auto freshEpoch = value.epoch();
    assert(value.eligible(freshEpoch, inventory(), {10'002, 1002}));
    assert(value.consume(scope(), freshEpoch, inventory(), {10'002, 1002}));
    assert(value.safetyFrame(One));
    assert(value.phase() == ProtectedInteraction::Phase::Consumed);
    assert(value.commit(One, 1, 22));
    value.presented(One, 22, true);
    assert(!value.eligible(value.epoch(), inventory(), {10'003, 1003}));
    assert(!value.safetyFrame({99, 99}));
    assert(value.phase() == ProtectedInteraction::Phase::Cancelled);
}
void purposeAndProofCannotBeSubstitutedOrReused()
{
    for (const auto purpose :
         {ProtectedInteraction::Purpose::Apply, ProtectedInteraction::Purpose::Keep,
          ProtectedInteraction::Purpose::Revert}) {
        auto expected = scope(purpose);
        auto value = ProtectedInteraction::start(expected, inventory(), {10'000, 1000}, 6);
        assert(value);
        ready(*value);
        const auto epoch = value->epoch();
        assert(value->consume(expected, epoch, inventory(), {10'001, 1001}));
        assert(value->phase() == ProtectedInteraction::Phase::Consumed);
        assert(!value->eligible(epoch, inventory(), {10'001, 1001}));
        assert(value->phase() == ProtectedInteraction::Phase::Consumed);
        assert(!value->consume(expected, epoch, inventory(), {10'001, 1001}));
    }
    for (unsigned which = 0; which < 4; ++which) {
        auto value = conversation();
        ready(value);
        auto changed = scope();
        auto epoch = value.epoch();
        if (which == 0)
            changed.purpose = ProtectedInteraction::Purpose::Revert;
        if (which == 1)
            changed.digest[0] = 'b';
        if (which == 2)
            ++changed.deadlineUnixMs;
        if (which == 3)
            --epoch;
        assert(!value.consume(changed, epoch, inventory(), {10'001, 1001}));
        assert(value.phase() == ProtectedInteraction::Phase::Cancelled);
    }
}
void consumedPresentationCanRepaintWithoutRearmingProof()
{
    for (unsigned fault = 0; fault != 4; ++fault) {
        auto value = conversation();
        ready(value);
        const auto epoch = value.epoch();
        assert(value.consume(scope(), epoch, inventory(), {10'001, 1001}));
        assert(value.commit(One, 1, 21));
        value.presented(One, 21, true);
        assert(value.phase() == ProtectedInteraction::Phase::Consumed && value.epoch() == epoch);
        assert(!value.eligible(epoch, inventory(), {10'002, 1002}));
        if (fault == 0)
            value.presented(One, 21, false);
        if (fault == 1)
            assert(!value.configure(One, 3));
        if (fault == 2)
            assert(!value.commit(One, 1, 20));
        if (fault == 3)
            assert(!value.consume(scope(), epoch, inventory(), {10'002, 1002}));
        assert(value.phase() == ProtectedInteraction::Phase::Cancelled);
    }
}
void focusInputAndNativeLifetimeDriftInvalidateTheProof()
{
    for (unsigned which = 0; which < 13; ++which) {
        auto value = conversation();
        ready(value);
        auto sample = inventory();
        auto clock = ClockSample{10'001, 1001};
        const auto epoch = value.epoch();
        switch (which) {
        case 0:
            value.focus(std::nullopt);
            value.focus(One);
            break;
        case 1:
            value.focus(Two);
            break;
        case 2:
            value.inputReplaced();
            break;
        case 3:
            ++sample.generation;
            break;
        case 4:
            ++sample.securityEpoch;
            break;
        case 5:
            ++sample.heads[0].key.generation;
            break;
        case 6:
            ++sample.heads[0].current.x;
            break;
        case 7:
            sample.heads[0].baseRuleWitness = "changed";
            break;
        case 8:
            sample.heads[0].outputIdentityWitness = "changed";
            break;
        case 9:
            sample.coverage = Coverage::Unknown;
            break;
        case 10:
            sample.heads[0].powered = false;
            break;
        case 11:
            clock.unixMs = 25'000;
            break;
        default:
            clock.bootMs = 16'000;
            break;
        }
        assert(!value.consume(scope(), epoch, sample, clock));
    }
    auto value = conversation();
    ready(value);
    assert(value.refresh(inventory(), {11'000, 2000}));
    assert(!value.refresh(inventory(), {10'999, 2000}));
    value = conversation();
    ready(value);
    assert(value.refresh(inventory(), {11'000, 2000}));
    assert(!value.refresh(inventory(), {11'000, 1999}));
}
void malformedOrUnqualifiedStateIsNeverReady()
{
    for (unsigned which = 0; which < 10; ++which) {
        auto sample = inventory();
        auto expected = scope();
        auto clock = ClockSample{10'000, 1000};
        std::uint64_t epoch = 6;
        switch (which) {
        case 0:
            expected.digest = std::string(64, '0');
            break;
        case 1:
            expected.digest = std::string(64, 'A');
            break;
        case 2:
            expected.purpose = static_cast<ProtectedInteraction::Purpose>(99);
            break;
        case 3:
            expected.deadlineUnixMs++;
            break;
        case 4:
            clock.unixMs = 0;
            break;
        case 5:
            clock.bootMs = std::numeric_limits<std::uint64_t>::max();
            break;
        case 6:
            epoch = 0;
            break;
        case 7:
            epoch = std::numeric_limits<std::uint64_t>::max() - 1;
            break;
        case 8:
            sample.heads[0].current.mode.width = 1;
            break;
        default:
            sample.coverage = Coverage::Secure;
            break; // No native lock coverage.
        }
        assert(!ProtectedInteraction::start(expected, sample, clock, epoch));
    }
    for (unsigned which = 0; which < 4; ++which) {
        auto value = conversation();
        ready(value);
        if (which == 0)
            value.presented(One, 20, false);
        if (which == 1)
            value.presented({99, 99}, 20, true);
        if (which == 2)
            assert(!value.commit(One, 1, 0));
        if (which == 3)
            assert(!value.configure(One, 1));
        assert(value.phase() == ProtectedInteraction::Phase::Cancelled);
    }
}
} // namespace
int main()
{
    auto original = conversation();
    ready(original);
    const auto epoch = original.epoch();
    auto moved = std::move(original);
    assert(original.phase() == ProtectedInteraction::Phase::Cancelled && original.epoch() == 0);
    assert(moved.eligible(epoch, inventory(), {10'000, 1000}));
    everyOutputNeedsCorrelatedPresentation();
    backendCommitIdsCannotBeReused();
    opaqueSafetyCannotPreserveOrRearmInteractionProof();
    purposeAndProofCannotBeSubstitutedOrReused();
    consumedPresentationCanRepaintWithoutRearmingProof();
    focusInputAndNativeLifetimeDriftInvalidateTheProof();
    malformedOrUnqualifiedStateIsNeverReady();
}
