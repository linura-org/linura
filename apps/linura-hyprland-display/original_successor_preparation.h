#pragma once

#include "original_completion_grant.h"
#include "original_final_retirement.h"

namespace Linura::HyprlandDisplay::OriginalSuccessorCodec {
inline constexpr std::size_t MaxPreparation = 64 * 1024;

// These are comparison fields. Only the continuously held actual Root channel
// may spend the new purpose, after it independently retains the new checkpoint.
inline bool matches(std::string_view bytes, std::string_view retiredDigest, const Correlation &next,
                    const Layout &baseline, const Layout &desired, const Snapshot &captured,
                    ClockSample sampled, ClockSample now, std::string_view nativeSource)
{
    if (bytes.empty() || bytes.size() > MaxPreparation ||
        !OriginalGrantCodec::digest(retiredDigest) || !OriginalGrantCodec::digest(nativeSource) ||
        !DisplayTransaction::validLayout(baseline, captured) ||
        !DisplayTransaction::validLayout(desired, captured) || baseline == desired)
        return false;
    const auto field = [&](std::size_t maximum) {
        return OriginalGrantCodec::field(bytes, maximum);
    };
    const auto domain = field(64),
               parent = field(OriginalFinalRetirementCodec::MaxPreparation + 512);
    if (!domain || *domain != "linura.native-display.successor-preparation.v1" || !parent)
        return false;
    auto previous = *parent;
    const auto parentDomain = OriginalGrantCodec::field(previous, 64);
    const auto final =
        OriginalGrantCodec::field(previous, OriginalFinalRetirementCodec::MaxPreparation);
    const auto proof = OriginalGrantCodec::field(previous, 64);
    if (!parentDomain || *parentDomain != "linura.native-display.released-current.v1" || !final ||
        nativeSha256(*final) != std::optional{std::string(retiredDigest)} || !proof ||
        !OriginalGrantCodec::digest(*proof))
        return false;
    std::array<std::uint64_t, 4> parentClocks{};
    for (auto &clock : parentClocks) {
        const auto text = OriginalGrantCodec::field(previous, 20);
        const auto value = text ? OriginalGrantCodec::number(*text) : std::nullopt;
        if (!value || !*value)
            return false;
        clock = *value;
    }
    if (!previous.empty() || parentClocks[2] <= parentClocks[0] ||
        parentClocks[3] <= parentClocks[1] || parentClocks[2] - parentClocks[0] > 2000 ||
        parentClocks[3] - parentClocks[1] > 2000)
        return false;
    const auto material = field(4096), transaction = field(256), generation = field(20),
               version = field(20);
    const auto authority = field(64), use = field(64), effect = field(64), dispatch = field(64);
    const auto checkpoint = field(64), source = field(64);
    const auto intent = material ? OriginalGrantCodec::intent(*material) : std::nullopt;
    const auto gen = generation ? OriginalGrantCodec::number(*generation) : std::nullopt;
    const auto ver = version ? OriginalGrantCodec::number(*version) : std::nullopt;
    if (!intent || intent->baseline != baseline || intent->desired != desired || !transaction ||
        *transaction != next.transaction || !gen || !ver || !*ver || !authority || !use ||
        !OriginalGrantCodec::digest(*authority) || !OriginalGrantCodec::digest(*use) || !effect ||
        *effect != next.effectDigest || !dispatch || *dispatch != next.dispatchDigest ||
        !checkpoint || !OriginalGrantCodec::digest(*checkpoint) || !source ||
        *source != nativeSource)
        return false;
    std::array<std::uint64_t, 4> clocks{};
    for (auto &clock : clocks) {
        const auto text = field(20);
        const auto value = text ? OriginalGrantCodec::number(*text) : std::nullopt;
        if (!value || !*value)
            return false;
        clock = *value;
    }
    return bytes.empty() && clocks[0] >= parentClocks[0] && clocks[1] >= parentClocks[1] &&
           clocks[0] >= sampled.unixMs && clocks[1] == sampled.bootMs && clocks[2] > clocks[0] &&
           clocks[3] > clocks[1] && clocks[2] - clocks[0] <= 2000 &&
           clocks[3] - clocks[1] <= 2000 && clocks[2] <= next.deadlineUnixMs &&
           now.unixMs >= clocks[0] && now.bootMs >= clocks[1] && now.unixMs < clocks[2] &&
           now.bootMs < clocks[3] && OriginalGrantCodec::freshSample(sampled.unixMs, now.unixMs) &&
           OriginalGrantCodec::freshSample(sampled.bootMs, now.bootMs);
}
} // namespace Linura::HyprlandDisplay::OriginalSuccessorCodec
