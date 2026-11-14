#pragma once

#include "original_completion_grant.h"

namespace Linura::HyprlandDisplay::OriginalPowerRetirementCodec {
inline constexpr std::size_t MaxPreparation =
    OriginalCompletionGrantCodec::MaxPreparation + 8 * 1024;
// Complete immutable comparison, not an authority object. The original Root
// spends the digest of THESE bytes; every post-ACK physical guard still runs.
inline std::optional<ClockSample> matches(std::string_view bytes, std::string_view parentDigest,
                                          const NativeFirstFrameGate::Receipt &physical,
                                          ClockSample now)
{
    if (bytes.empty() || bytes.size() > MaxPreparation || !physical.completedCount ||
        physical.completedCount > DisplayTransaction::MaxHeads)
        return {};
    const auto next = [&](std::size_t limit) { return OriginalGrantCodec::field(bytes, limit); };
    const auto domain = next(64), parent = next(OriginalCompletionGrantCodec::MaxPreparation);
    const auto preparation = next(64), checkpoint = next(64);
    if (!domain || *domain != "linura.native-display.power-retirement.v1" || !parent ||
        nativeSha256(*parent) != std::optional{std::string(parentDigest)} || !preparation ||
        !checkpoint || !OriginalGrantCodec::digest(*preparation) ||
        !OriginalGrantCodec::digest(*checkpoint) || *preparation == *checkpoint)
        return {};
    const auto number = [&]() -> std::optional<std::uint64_t> {
        const auto raw = next(20);
        return raw ? OriginalGrantCodec::number(*raw) : std::nullopt;
    };
    const auto expiry = number(), wall = number(), boot = number(), wallEnd = number(),
               bootEnd = number(), count = number();
    if (!expiry || !wall || !boot || !wallEnd || !bootEnd || !count || !*wall || !*boot ||
        *wall >= *wallEnd || *boot >= *bootEnd || *wallEnd - *wall > 2000 ||
        *bootEnd - *boot > 2000 || *expiry <= *wall || *expiry > *wallEnd ||
        *expiry - *wall > *bootEnd - *boot || now.unixMs < *wall || now.bootMs < *boot ||
        now.unixMs >= *expiry || now.bootMs >= *bootEnd || physical.observedUnixMs < *wall ||
        physical.observedBootMs < *boot || physical.observedUnixMs > now.unixMs ||
        physical.observedBootMs > now.bootMs || *count != physical.completedCount)
        return {};
    for (std::size_t i = 0; i < physical.completedCount; ++i) {
        const auto &row = physical.completed[i];
        const auto &kms = row.kernel;
        for (const auto expected :
             {kms.key.handle, kms.key.generation, static_cast<std::uint64_t>(kms.active),
              static_cast<std::uint64_t>(kms.connector), static_cast<std::uint64_t>(kms.crtc),
              static_cast<std::uint64_t>(kms.plane)})
            if (number() != std::optional{expected})
                return {};
        const auto framebuffer = number(), handoff = number(), completed = number();
        if (!framebuffer || !handoff || !completed ||
            *framebuffer > std::numeric_limits<std::uint32_t>::max() ||
            *handoff != row.spendHighWater || *completed > row.completedCommit ||
            (kms.active ? (!*framebuffer || *completed <= *handoff)
                        : (*framebuffer || *completed != *handoff)) ||
            (*completed == row.completedCommit && *framebuffer != kms.framebuffer))
            return {};
    }
    return bytes.empty() ? std::optional{ClockSample{*expiry, *bootEnd}} : std::nullopt;
}
} // namespace Linura::HyprlandDisplay::OriginalPowerRetirementCodec
