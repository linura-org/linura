#pragma once

#include <chrono>

struct wl_display;

namespace Linura::SecurityOwner {

// Availability only, before any registry/input/lock binding on the exclusive,
// already-attested connection. A sync reply never supplies identity or authority.
// The caller retains ownership and its enclosing startup deadline.
[[nodiscard]] bool waitForNativeWaylandReady(wl_display *display, std::chrono::milliseconds budget);

} // namespace Linura::SecurityOwner
