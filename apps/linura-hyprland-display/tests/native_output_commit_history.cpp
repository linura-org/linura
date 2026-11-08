#include "native_output_commit_history.h"

#include <cassert>
#include <cstdint>
#include <limits>

using namespace Linura::HyprlandDisplay;

int main()
{
    NativeOutputCommitHistory one;
    NativeOutputCommitHistory two;
    assert(!one.faulted());
    assert(!one.highWater());
    assert(!two.highWater());
    assert(one.observe(7, true));
    assert(one.highWater() == std::optional<std::uint64_t>{7});
    assert(two.observe(4, true));
    assert(two.highWater() == std::optional<std::uint64_t>{4});
    assert(one.observe(8, true));
    assert(one.highWater() == std::optional<std::uint64_t>{8});
    assert(two.highWater() == std::optional<std::uint64_t>{4});
    // A duplicate or out-of-order native result poisons only its own output.
    assert(!one.observe(8, true));
    assert(one.faulted());
    assert(!one.highWater());
    assert(!one.observe(9, true));
    assert(two.observe(5, true));
    assert(two.highWater() == std::optional<std::uint64_t>{5});

    for (int fault = 0; fault < 6; ++fault) {
        NativeOutputCommitHistory history;
        if (fault >= 3)
            assert(history.observe(10, true));
        std::uint64_t id = 11;
        switch (fault) {
        case 0:
            id = 0;
            break;
        case 1:
            id = std::numeric_limits<std::uint64_t>::max();
            break;
        case 2:
        case 4:
            id = 9;
            break;
        case 3:
            id = 10;
            break;
        default:
            break;
        }
        const bool success = fault != 2 && fault != 5;
        assert(!history.observe(id, success));
        assert(history.faulted());
        assert(!history.highWater());
        assert(!history.observe(100, true));
    }
    // A new history never borrows another native output's old commit counter.
    NativeOutputCommitHistory replaced;
    assert(!replaced.highWater());
    assert(replaced.observe(2, true));
    assert(replaced.highWater() == std::optional<std::uint64_t>{2});
    return 0;
}
