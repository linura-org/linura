#pragma once

#include <string_view>

struct xkb_context;
struct xkb_compose_table;

namespace Linura::SecurityOwner {
bool boundedComposeSource(std::string_view source) noexcept;
xkb_compose_table *trustedComposeTable(xkb_context *context) noexcept;
} // namespace Linura::SecurityOwner
