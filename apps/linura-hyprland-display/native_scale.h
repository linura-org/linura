#pragma once

#include <bit>
#include <cmath>
#include <cstdint>
#include <optional>

namespace Linura::HyprlandDisplay {

// Hyprland stores scale as float; Wayland's independent output-management view
// quantizes it to 24.8 fixed point. Neither view may silently round an unknown
// native value into the canonical thousandths-based layout contract.
inline std::optional<std::uint32_t> nativeScaleMilli(float scale)
{
    if (!std::isfinite(scale) || scale < 0.5F || scale > 4.F)
        return std::nullopt;
    const auto milli = static_cast<std::uint32_t>(std::lround(static_cast<double>(scale) * 1000));
    if (static_cast<float>(milli) / 1000.F != scale)
        return std::nullopt;
    return milli;
}
inline std::uint32_t nativeScaleBits(std::uint32_t milli)
{
    return std::bit_cast<std::uint32_t>(static_cast<float>(milli) / 1000.F);
}

} // namespace Linura::HyprlandDisplay
