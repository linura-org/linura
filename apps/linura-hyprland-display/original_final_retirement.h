#pragma once

#include "original_current_commit.h"

namespace Linura::HyprlandDisplay::OriginalFinalRetirementCodec {
inline constexpr std::size_t MaxPreparation = OriginalCurrentCommitCodec::MaxPreparation + 8 * 1024;
// Comparison only. The original authenticated Root channel must spend this
// complete preparation before any obsolete native lifetime can be retired.
inline std::optional<ClockSample> matches(std::string_view bytes, std::string_view currentDigest,
                                          const NativeFirstFrameGate::Receipt &physical,
                                          ClockSample now)
{
    if (bytes.empty() || bytes.size() > MaxPreparation || !physical.completedCount ||
        physical.completedCount > DisplayTransaction::MaxHeads)
        return {};
    const auto field = [&](std::size_t bound) { return OriginalGrantCodec::field(bytes, bound); };
    const auto domain = field(64), parent = field(OriginalCurrentCommitCodec::MaxPreparation),
               prepared = field(64), verification = field(64);
    if (!domain || *domain != "linura.native-display.final-retirement.v1" || !parent ||
        nativeSha256(*parent) != std::optional{std::string(currentDigest)} || !prepared ||
        !verification || !OriginalGrantCodec::digest(*prepared) ||
        !OriginalGrantCodec::digest(*verification) || *prepared == *verification)
        return {};
    const auto number = [&]() -> std::optional<std::uint64_t> {
        const auto raw = field(20);
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
} // namespace Linura::HyprlandDisplay::OriginalFinalRetirementCodec
