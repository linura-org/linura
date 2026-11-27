#pragma once

#include "original_finalization_intent.h"

namespace Linura::HyprlandDisplay::OrdinaryReleaseCodec {
inline constexpr std::size_t MaxMaterial = 6 * 1024, MaxPreparation = MaxMaterial + 4096;
enum class Outcome { Keep, Revert, Expired };

// Comparison data only. Actual terminal history, current S17 identity, fresh
// protected review and the continuously held Root peer remain mandatory.
struct Intent final
{
    std::string_view request, dispatch, terminal, checkpoint, signedBinding, source;
    std::uint64_t generation, version;
    Outcome outcome;
    std::string_view lock, original;
    OriginalGrantCodec::Intent layout;
};

inline std::optional<Intent> decode(std::string_view material)
{
    if (material.empty() || material.size() > MaxMaterial || !material.starts_with("LNOR:1;") ||
        !OriginalFinalizationCodec::text(material))
        return {};
    material.remove_prefix(7);
    constexpr std::array<std::size_t, 11> bounds{256, 64, 64, 64, 64, 20, 20, 64, 7, 256, 4096};
    std::array<std::string_view, 11> fields{};
    for (std::size_t i = 0; i < fields.size(); ++i) {
        const auto colon = material.find(':');
        if (colon == std::string_view::npos || colon > 20)
            return {};
        const auto size = OriginalGrantCodec::number(material.substr(0, colon));
        if (!size || !*size || *size > bounds[i])
            return {};
        material.remove_prefix(colon + 1);
        if (material.size() <= *size || material[static_cast<std::size_t>(*size)] != ';')
            return {};
        fields[i] = material.substr(0, static_cast<std::size_t>(*size));
        material.remove_prefix(static_cast<std::size_t>(*size) + 1);
    }
    const auto generation = OriginalGrantCodec::number(fields[5]);
    const auto version = OriginalGrantCodec::number(fields[6]);
    const auto layout = OriginalGrantCodec::intent(fields[10]);
    if (!material.empty() || fields[0].empty() || !generation || !version || !*version || !layout ||
        !fields[9].starts_with("session:lock:") || !OriginalGrantCodec::digest(fields[7]) ||
        !std::all_of(fields.begin() + 1, fields.begin() + 5, OriginalGrantCodec::digest))
        return {};
    const auto outcome = fields[8] == "keep"      ? std::optional{Outcome::Keep}
                         : fields[8] == "revert"  ? std::optional{Outcome::Revert}
                         : fields[8] == "expired" ? std::optional{Outcome::Expired}
                                                  : std::nullopt;
    const auto oldLock = OriginalFinalizationCodec::lock(fields[10]);
    // Same login epoch; a changed lock incarnation is independently checked by
    // the native owner. Neither string comparison authenticates that owner.
    const auto login = [](std::string_view lock) -> std::optional<std::string_view> {
        std::size_t end = 0;
        for (unsigned i = 0; i < 6; ++i) {
            end = lock.find(':', end);
            if (end == std::string_view::npos)
                return {};
            ++end;
        }
        return lock.substr(0, end);
    };
    if (!outcome || !oldLock || !login(*oldLock) || login(*oldLock) != login(fields[9]))
        return {};
    return Intent{fields[0],   fields[1], fields[2], fields[3], fields[4],  fields[7],
                  *generation, *version,  *outcome,  fields[9], fields[10], *layout};
}

inline bool matchesHeld(const Intent &intent, const Correlation &held, const Layout &baseline,
                        const Layout &desired, const Snapshot &current)
{
    const auto oldLock = OriginalFinalizationCodec::lock(intent.original);
    const auto topologyGeneration = OriginalGrantCodec::number(
        intent.layout.topology.substr(intent.layout.topology.rfind(':') + 1));
    if (!oldLock || intent.dispatch != held.dispatchDigest ||
        OriginalFinalizationCodec::transaction(intent.request, *oldLock) !=
            std::optional{held.transaction} ||
        intent.layout.baseline != baseline || intent.layout.desired != desired ||
        topologyGeneration != std::optional{current.generation})
        return false;
    const bool kept = intent.outcome == Outcome::Keep;
    const auto &target = kept ? desired : baseline;
    if (!DisplayTransaction::validLayout(target, current) || target.size() != current.heads.size())
        return false;
    for (std::size_t i = 0; i < target.size(); ++i)
        if (target[i] != current.heads[i].current)
            return false;
    return nativeBaselineGuard(current,
                               kept ? intent.layout.desiredText : intent.layout.baselineText) ==
           std::optional{std::string(intent.source)};
}

struct Window final
{
    ClockSample observed, deadline;
};
inline std::optional<Window> preparation(std::string_view bytes, std::string_view material,
                                         const Correlation &release, ClockSample now)
{
    if (bytes.empty() || bytes.size() > MaxPreparation || !decode(material))
        return {};
    constexpr std::array<std::size_t, 13> bounds{64, MaxMaterial, 256, 20, 20, 64, 64,
                                                 64, 64,          20,  20, 20, 20};
    std::array<std::string_view, 13> fields{};
    for (std::size_t i = 0; i < fields.size(); ++i) {
        const auto value = OriginalGrantCodec::field(bytes, bounds[i]);
        if (!value || value->empty())
            return {};
        fields[i] = *value;
    }
    std::array<std::uint64_t, 6> numbers{};
    constexpr std::array<std::size_t, 6> indices{3, 4, 9, 10, 11, 12};
    for (std::size_t i = 0; i < numbers.size(); ++i) {
        const auto value = OriginalGrantCodec::number(fields[indices[i]]);
        if (!value)
            return {};
        numbers[i] = *value;
    }
    if (!bytes.empty() || fields[0] != "linura.native-display.ordinary-release.v1" ||
        fields[1] != material || fields[2] != release.transaction || !numbers[1] ||
        !std::all_of(fields.begin() + 5, fields.begin() + 9, OriginalGrantCodec::digest) ||
        fields[7] != release.effectDigest || fields[8] != release.dispatchDigest || !numbers[2] ||
        !numbers[3] || numbers[4] <= numbers[2] || numbers[5] <= numbers[3] ||
        numbers[4] - numbers[2] > 2000 || numbers[5] - numbers[3] > 2000 ||
        numbers[4] > release.deadlineUnixMs || now.unixMs < numbers[2] || now.bootMs < numbers[3] ||
        now.unixMs >= numbers[4] || now.bootMs >= numbers[5])
        return {};
    return Window{{numbers[2], numbers[3]}, {numbers[4], numbers[5]}};
}
} // namespace Linura::HyprlandDisplay::OrdinaryReleaseCodec
