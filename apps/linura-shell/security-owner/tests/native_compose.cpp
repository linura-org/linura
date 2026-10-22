#include "native_compose.h"

#include <xkbcommon/xkbcommon.h>
#include <xkbcommon/xkbcommon-compose.h>

#include <array>
#include <cassert>
#include <cstring>
#include <string>

using namespace Linura::SecurityOwner;

int main()
{
    assert(!boundedComposeSource({}));
    assert(boundedComposeSource("<dead_acute> <e> : \"é\"\n"));
    assert(!boundedComposeSource("include \"%L\"\n"));
    assert(!boundedComposeSource(" \tinclude \"%S/en_US.UTF-8/Compose\"\n"));
    const std::array<char, 4> embeddedNull{'a', '\0', 'b', '\n'};
    assert(!boundedComposeSource({embeddedNull.data(), embeddedNull.size()}));
    const std::string oversized(1024U * 1024U + 1U, 'a');
    assert(!boundedComposeSource(oversized));

    const auto flags = static_cast<xkb_context_flags>(XKB_CONTEXT_NO_DEFAULT_INCLUDES |
                                                      XKB_CONTEXT_NO_ENVIRONMENT_NAMES);
    auto *context = xkb_context_new(flags);
    assert(context);
    auto *table = trustedComposeTable(context);
    assert(table);
    auto *state = xkb_compose_state_new(table, XKB_COMPOSE_STATE_NO_FLAGS);
    assert(state);
    assert(xkb_compose_state_feed(state, XKB_KEY_dead_acute) == XKB_COMPOSE_FEED_ACCEPTED);
    assert(xkb_compose_state_get_status(state) == XKB_COMPOSE_COMPOSING);
    assert(xkb_compose_state_feed(state, XKB_KEY_e) == XKB_COMPOSE_FEED_ACCEPTED);
    assert(xkb_compose_state_get_status(state) == XKB_COMPOSE_COMPOSED);
    std::array<char, 8> output{};
    assert(xkb_compose_state_get_utf8(state, output.data(), output.size()) == 2);
    assert(std::strcmp(output.data(), "é") == 0);
    xkb_compose_state_unref(state);
    xkb_compose_table_unref(table);
    xkb_context_unref(context);
}
