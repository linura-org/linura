// Pure native routing traces. No simulated fact is native qualification,
// authenticated input, a human approval, a lock release or effect authority.
#include "protected_input_retirement.h"
#include <cassert>
#include <initializer_list>
#include <type_traits>

using namespace Linura::HyprlandDisplay;
using Phase = ProtectedInputRetirement::Phase;
using Held = ProtectedInputRetirement::Held;
static_assert(!std::is_copy_constructible_v<ProtectedInputRetirement>);
static_assert(!std::is_move_constructible_v<ProtectedInputRetirement>);
namespace {
void unexpectedLossDoesNotRouteTheRestOfAResponseToAnOrdinaryClient()
{
    ProtectedInputRetirement input;
    assert(input.begin({}));
    input.close(false, {true, false, true});
    assert(input.phase() == Phase::Quarantined);
    // Releasing the key at owner loss does not end the protected input lifetime.
    assert(input.key(true, false, false, {}));
    input.poll({});
    for (unsigned character = 0; character < 100; ++character) {
        assert(input.key(true, false, true, {true, false, true}));
        assert(input.key(true, false, false, {}));
        assert(input.blocked() && !input.begin({}));
    }
    // Only a new physical Escape followed by draining its release returns focus.
    assert(input.key(true, true, true, {true, true, false}));
    assert(input.phase() == Phase::Draining && input.blocked());
    assert(input.key(true, true, false, {}));
    assert(!input.blocked() && input.phase() == Phase::Open);
    assert(!input.key(true, false, true, {true, false, true}));
}
void heldOrVirtualExitCannotMigrateAcrossLoss()
{
    for (const bool pressed : {false, true}) {
        ProtectedInputRetirement input;
        assert(input.begin({}));
        input.close(false, {});
        assert(input.key(false, true, pressed, {}));
        assert(input.phase() == Phase::Quarantined);
    }
    ProtectedInputRetirement input;
    assert(input.begin({}));
    input.close(false, {true, true, false});
    // An Escape held before loss, its repeats, and another held key cannot exit.
    for (unsigned repeat = 0; repeat < 100; ++repeat)
        assert(input.key(true, true, true, {true, true, false}));
    assert(input.phase() == Phase::Quarantined);
    assert(input.key(true, true, false, {}));
    assert(input.key(true, false, true, {true, false, true}));
    assert(input.key(true, true, true, {true, true, true}));
    assert(input.phase() == Phase::Quarantined);
    // Releasing the other key while Escape remains held does not turn it into
    // a new exit gesture. Its autorepeat is still the same physical press.
    assert(input.key(true, false, false, {true, true, false}));
    assert(input.key(true, true, true, {true, true, false}));
    assert(input.phase() == Phase::Quarantined);
    assert(input.key(true, true, false, {}));
    assert(input.key(true, true, true, {true, true, false}));
    assert(input.key(true, true, false, {}));
    assert(input.phase() == Phase::Open);
}
void explicitExitStillDrainsBeforeAnotherConversation()
{
    ProtectedInputRetirement input;
    assert(!input.begin({true, false, true}));
    assert(!input.begin({false, true, false}));
    assert(!input.begin({false, false, true}));
    assert(input.begin({}));
    assert(!input.begin({}));
    input.close(true, {true, true, false});
    assert(input.phase() == Phase::Draining);
    input.close(true, {}); // Repeated cleanup cannot skip the physical drain.
    assert(input.phase() == Phase::Draining);
    assert(input.key(false, true, false, {}));
    assert(input.phase() == Phase::Draining);
    input.poll({}); // Trusted native inventory independently observes release.
    assert(input.phase() == Phase::Open && input.begin({}));
    input.close(true, {});
    assert(input.phase() == Phase::Open);
    input.close(false, {}); // Stale cleanup cannot close an unrelated lifetime.
    assert(input.phase() == Phase::Open);
}
} // namespace
int main()
{
    unexpectedLossDoesNotRouteTheRestOfAResponseToAnOrdinaryClient();
    heldOrVirtualExitCannotMigrateAcrossLoss();
    explicitExitStillDrainsBeforeAnotherConversation();
}
