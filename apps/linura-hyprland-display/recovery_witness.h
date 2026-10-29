#pragma once

#include "native_output_identity.h"
#include "display_transaction.h"

#include <bit>
#include <cmath>
#include <cstdint>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

namespace Linura::HyprlandDisplay {
namespace RecoveryWitness {
inline constexpr std::size_t MaxRuleBytes = 12 * 1024, MaxIdentityBytes = 16 * 1024;
inline void hex(std::string &out, std::string_view bytes)
{
    constexpr char digits[] = "0123456789abcdef";
    for (const auto value : bytes) {
        const auto byte = static_cast<unsigned char>(value);
        out += digits[byte >> 4U];
        out += digits[byte & 15U];
    }
    out += ';';
}
inline bool real(std::string &out, double value)
{
    if (!std::isfinite(value))
        return false;
    // Normalize signed zero consistently with native rule equality. Encode
    // IEEE value bits, never locale-dependent floating-point text or padding.
    const auto bits = std::bit_cast<std::uint64_t>(value == 0 ? 0.0 : value);
    constexpr char digits[] = "0123456789abcdef";
    for (unsigned shift = 64; shift != 0; shift -= 4)
        out += digits[(bits >> (shift - 4)) & 15U];
    out += ';';
    return true;
}
inline void integer(std::string &out, std::uint64_t value)
{
    out += std::to_string(value);
    out += ';';
}

// Historical comparison material only. It contains no selectors to execute,
// commands, object pointers, policy or permission. Native ownership can resume
// only after independent scope/continuity checks and canonical Control recovery.
// Keep every field in sameOwnedDisplayFields, including automatic placement,
// scaling and custom modelines; omit all unrelated live monitor settings.
template <typename Rule> [[nodiscard]] std::optional<std::string> rule(const Rule &rule)
{
    if (rule.m_mirrorOf.size() > 4096)
        return std::nullopt;
    std::string out = "LNDR:1;";
    integer(out, rule.m_disabled ? 1U : 0U);
    for (const double value :
         {static_cast<double>(rule.m_resolution.x), static_cast<double>(rule.m_resolution.y),
          static_cast<double>(rule.m_refreshRate), static_cast<double>(rule.m_offset.x),
          static_cast<double>(rule.m_offset.y), static_cast<double>(rule.m_scale)})
        if (!real(out, value))
            return std::nullopt;
    integer(out, static_cast<std::uint64_t>(rule.m_autoDir));
    integer(out, static_cast<std::uint64_t>(rule.m_transform));
    hex(out, rule.m_mirrorOf);
    const auto &mode = rule.m_drmMode;
    for (const std::uint64_t value :
         {static_cast<std::uint64_t>(mode.clock), static_cast<std::uint64_t>(mode.hdisplay),
          static_cast<std::uint64_t>(mode.hsync_start), static_cast<std::uint64_t>(mode.hsync_end),
          static_cast<std::uint64_t>(mode.htotal), static_cast<std::uint64_t>(mode.hskew),
          static_cast<std::uint64_t>(mode.vdisplay), static_cast<std::uint64_t>(mode.vsync_start),
          static_cast<std::uint64_t>(mode.vsync_end), static_cast<std::uint64_t>(mode.vtotal),
          static_cast<std::uint64_t>(mode.vscan), static_cast<std::uint64_t>(mode.vrefresh),
          static_cast<std::uint64_t>(mode.flags), static_cast<std::uint64_t>(mode.type)})
        integer(out, value);
    hex(out, std::string_view(std::begin(mode.name), std::size(mode.name)));
    return out.size() <= MaxRuleBytes ? std::optional{std::move(out)} : std::nullopt;
}

[[nodiscard]] inline std::string target(const Target &target)
{
    std::string out = "LNOT:1;";
    for (const auto value : {target.output.handle, target.output.generation})
        integer(out, value);
    integer(out, target.enabled ? 1U : 0U);
    for (const auto value : {target.mode.width, target.mode.height, target.mode.refreshMilliHz}) {
        out += std::to_string(value);
        out += ';';
    }
    integer(out, target.scaleMilli);
    integer(out, target.transform);
    out += std::to_string(target.x) + ';' + std::to_string(target.y) + ';';
    integer(out, target.mirror ? target.mirror->handle : 0U);
    integer(out, target.mirror ? target.mirror->generation : 0U);
    return out;
}

[[nodiscard]] inline std::optional<std::string> identity(const NativeOutputIdentity &identity)
{
    std::string out = "LNDF:1;";
    for (std::size_t i = 0; i < identity.text.size(); ++i) {
        if (identity.text[i].size() > (i == 1 ? 4096U : 256U))
            return std::nullopt;
        hex(out, identity.text[i]);
    }
    for (const auto value : identity.physicalSize)
        if (!real(out, value))
            return std::nullopt;
    integer(out, identity.hdrLuminance ? 1U : 0U);
    if (identity.hdrLuminance)
        for (const auto value : *identity.hdrLuminance)
            if (!real(out, value))
                return std::nullopt;
    integer(out, identity.chromaticity ? 1U : 0U);
    if (identity.chromaticity)
        for (const auto value : *identity.chromaticity)
            if (!real(out, value))
                return std::nullopt;
    integer(out, identity.supportsPQ ? 1U : 0U);
    integer(out, identity.supportsBT2020 ? 1U : 0U);
    return out.size() <= MaxIdentityBytes ? std::optional{std::move(out)} : std::nullopt;
}
} // namespace RecoveryWitness
} // namespace Linura::HyprlandDisplay
