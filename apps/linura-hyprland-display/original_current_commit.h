#pragma once

#include "original_power_retirement.h"

namespace Linura::HyprlandDisplay::OriginalCurrentCommitCodec {
inline constexpr std::size_t MaxRoot = OriginalPowerRetirementCodec::MaxPreparation + 8 * 1024;
inline constexpr std::size_t MaxPreparation = MaxRoot + 8 * 1024;
// These are comparison bytes, never a lifetime. Only the ORIGINAL credential-
// checked Root channel can spend the digest after all local physical guards.
inline std::optional<ClockSample> matches(std::string_view bytes, std::string_view completionDigest,
                                          const NativeFirstFrameGate::Receipt &physical,
                                          ClockSample now)
{
    if (bytes.empty() || bytes.size() > MaxPreparation || !physical.completedCount ||
        physical.completedCount > DisplayTransaction::MaxHeads)
        return {};
    const auto field = [](std::string_view &rest, std::size_t bound) {
        return OriginalGrantCodec::field(rest, bound);
    };
    const auto domain = field(bytes, 64), root = field(bytes, MaxRoot), prepared = field(bytes, 64),
               committed = field(bytes, 64);
    if (!domain || *domain != "linura.native-display.current-commit.v1" || !root || !prepared ||
        !committed || !OriginalGrantCodec::digest(*prepared) ||
        !OriginalGrantCodec::digest(*committed) || *prepared == *committed)
        return {};
    auto ancestry = *root;
    const auto rootDomain = field(ancestry, 64),
               power = field(ancestry, OriginalPowerRetirementCodec::MaxPreparation);
    if (!rootDomain || *rootDomain != "linura.native-display.root-retirement.v1" || !power)
        return {};
    ancestry = *power;
    const auto powerDomain = field(ancestry, 64),
               completion = field(ancestry, OriginalCompletionGrantCodec::MaxPreparation);
    if (!powerDomain || *powerDomain != "linura.native-display.power-retirement.v1" ||
        !completion || nativeSha256(*completion) != std::optional{std::string(completionDigest)})
        return {};
    ancestry = *completion;
    const auto completionDomain = field(ancestry, 64),
               retirement = field(ancestry, OriginalNativeReleaseGrantCodec::MaxReservation);
    if (!completionDomain ||
        *completionDomain != "linura.native-display.completion-preparation.v1" || !retirement)
        return {};
    ancestry = *retirement;
    const auto retirementDomain = field(ancestry, 64), oldVersion = field(ancestry, 20),
               oldBinding = field(ancestry, 64), oldObservation = field(ancestry, 64),
               terminal = field(ancestry, OriginalGrantCodec::MaxReservation);
    if (!retirementDomain ||
        *retirementDomain != "linura.native-display.retirement-preparation.v1" || !oldVersion ||
        !oldBinding || !oldObservation || !terminal || !ancestry.empty())
        return {};
    const auto previous = OriginalGrantCodec::number(*oldVersion);
    ancestry = *terminal;
    const auto terminalDomain = field(ancestry, 64), transaction = field(ancestry, 256),
               oldGeneration = field(ancestry, 20);
    if (!terminalDomain || *terminalDomain != "linura.native-display.finalization-reservation.v1" ||
        !transaction || !oldGeneration || !previous ||
        *previous > std::numeric_limits<std::uint64_t>::max() - 2)
        return {};
    const auto number = [&]() -> std::optional<std::uint64_t> {
        const auto raw = field(bytes, 20);
        return raw ? OriginalGrantCodec::number(*raw) : std::nullopt;
    };
    const auto generation = number(), version = number();
    const auto binding = field(bytes, 64);
    if (!generation || !version || !binding ||
        OriginalGrantCodec::number(*oldGeneration) != generation || *version != *previous + 2 ||
        *binding != *oldBinding)
        return {};
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
} // namespace Linura::HyprlandDisplay::OriginalCurrentCommitCodec
