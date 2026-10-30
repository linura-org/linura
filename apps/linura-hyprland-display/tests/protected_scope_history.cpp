#include "protected_scope_history.h"

#include <cassert>
#include <limits>

using namespace Linura::HyprlandDisplay;
namespace {
ProtectedInteraction::Scope scope(unsigned id, std::uint64_t deadline = 25'000)
{
    constexpr char hex[] = "0123456789abcdef";
    auto digest = std::string(64, 'a');
    for (std::size_t i = 0; i != 8; ++i) {
        digest[i] = hex[id & 15U];
        id >>= 4U;
    }
    return {digest, ProtectedInteraction::Purpose::Apply, deadline};
}
} // namespace
int main()
{
    ProtectedScopeHistory history;
    for (unsigned i = 0; i != ProtectedScopeHistory::Capacity; ++i)
        assert(history.reserve(scope(i), {10'000, 1000}));
    // Neither exact replay nor a different scope evicts any unexpired entry.
    assert(!history.reserve(scope(0), {10'001, 1001}));
    assert(!history.reserve(scope(1000), {10'001, 1001}));
    assert(!history.reserve(scope(1), {24'999, 15'999}));
    // Expiration frees capacity but the old deadline can never be revived.
    assert(history.reserve(scope(1000, 40'000), {25'000, 16'000}));
    assert(!history.reserve(scope(0), {25'000, 16'000}));
    assert(!history.reserve(scope(0), {24'999, 16'001}));
    assert(!history.reserve(scope(1001, 40'000), {25'001, 16'002})); // Rollback is terminal.

    // BOOTTIME expiry wins even if wall time advances slowly during suspend.
    ProtectedScopeHistory suspended;
    assert(suspended.reserve(scope(0), {10'000, 1000}));
    assert(!suspended.reserve(scope(0), {10'001, 16'000}));
    assert(suspended.reserve(scope(1, 26'000), {10'001, 16'000}));
    assert(!suspended.reserve(scope(2), {10'002, 15'999}));
    assert(!suspended.reserve(scope(3), {10'003, 16'001}));

    // One live reservation survives reclamation of many earlier deadlines.
    ProtectedScopeHistory mixed;
    for (unsigned i = 0; i != ProtectedScopeHistory::Capacity - 1; ++i)
        assert(mixed.reserve(scope(i), {10'000, 1000}));
    assert(mixed.reserve(scope(1000, 50'000), {10'000, 1000}));
    assert(mixed.reserve(scope(1001, 50'000), {25'000, 16'000}));
    assert(!mixed.reserve(scope(1000, 50'000), {25'000, 16'000}));

    for (unsigned fault = 0; fault != 7; ++fault) {
        ProtectedScopeHistory candidate;
        auto invalid = scope(0);
        auto now = ClockSample{10'000, 1000};
        if (fault == 0)
            invalid.digest = std::string(64, '0');
        if (fault == 1)
            invalid.digest[0] = 'g';
        if (fault == 2)
            invalid.deadlineUnixMs = 10'000;
        if (fault == 3)
            invalid.deadlineUnixMs = 70'001;
        if (fault == 4)
            now.bootMs = std::numeric_limits<std::uint64_t>::max();
        if (fault == 5)
            now.unixMs = 0;
        if (fault == 6) {
            invalid.purpose = ProtectedInteraction::Purpose::Keep;
            invalid.deadlineUnixMs = 25'001;
        }
        assert(!candidate.reserve(invalid, now));
    }
}
