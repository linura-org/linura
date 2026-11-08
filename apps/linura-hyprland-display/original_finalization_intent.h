#pragma once

#include "native_baseline_guard.h"
#include "original_restoration_grant.h"

namespace Linura::HyprlandDisplay {

// Comparison against an already authenticated, still-held original grant.
// This never authenticates journal retirement or grants release authority.
namespace OriginalFinalizationCodec {
inline constexpr std::size_t MaxMaterial = 14 * 1024;

inline bool text(std::string_view bytes)
{
    // Canonical UTF-8, excluding Unicode Cc just like the Core material.
    for (std::size_t i = 0; i < bytes.size();) {
        const auto first = static_cast<unsigned char>(bytes[i++]);
        std::uint32_t scalar = first;
        unsigned remaining = 0;
        std::uint32_t minimum = 0;
        if (first >= 0xc2 && first <= 0xdf) {
            remaining = 1;
            scalar = first & 0x1fU;
            minimum = 0x80;
        } else if (first >= 0xe0 && first <= 0xef) {
            remaining = 2;
            scalar = first & 0x0fU;
            minimum = 0x800;
        } else if (first >= 0xf0 && first <= 0xf4) {
            remaining = 3;
            scalar = first & 0x07U;
            minimum = 0x10000;
        } else if (first >= 0x80)
            return false;
        if (remaining > bytes.size() - i)
            return false;
        for (unsigned j = 0; j < remaining; ++j) {
            const auto next = static_cast<unsigned char>(bytes[i++]);
            if ((next & 0xc0U) != 0x80U)
                return false;
            scalar = (scalar << 6U) | (next & 0x3fU);
        }
        if (scalar < minimum || scalar > 0x10ffff || (scalar >= 0xd800 && scalar <= 0xdfff) ||
            scalar < 0x20 || (scalar >= 0x7f && scalar <= 0x9f))
            return false;
    }
    return true;
}

struct Intent final
{
    std::string_view restorationRequest, restorationDispatch, terminalLink, sourceGuard;
    std::uint64_t postWriteEpoch;
    std::string_view currentLock, restoration;
};

inline std::optional<Intent> decode(std::string_view material)
{
    if (material.size() > MaxMaterial || !material.starts_with("LNRF:1;") || !text(material))
        return std::nullopt;
    material.remove_prefix(7);
    constexpr std::array<std::size_t, 7> bounds{256, 64, 64, 64, 20, 256, 12 * 1024};
    std::array<std::string_view, 7> fields{};
    for (std::size_t i = 0; i < fields.size(); ++i) {
        const auto colon = material.find(':');
        if (colon == std::string_view::npos || colon > 20)
            return std::nullopt;
        const auto length = OriginalGrantCodec::number(material.substr(0, colon));
        if (!length || *length > bounds[i])
            return std::nullopt;
        material.remove_prefix(colon + 1);
        const auto size = static_cast<std::size_t>(*length);
        if (material.size() <= size || material[size] != ';')
            return std::nullopt;
        fields[i] = material.substr(0, size);
        material.remove_prefix(size + 1);
    }
    const auto epoch = OriginalGrantCodec::number(fields[4]);
    if (!material.empty() || fields[0].empty() || !OriginalGrantCodec::digest(fields[1]) ||
        !OriginalGrantCodec::digest(fields[2]) || !OriginalGrantCodec::digest(fields[3]) ||
        !epoch || *epoch == 0 || !fields[5].starts_with("session:lock:") ||
        !fields[6].starts_with("LNRI:1;"))
        return std::nullopt;
    return Intent{fields[0], fields[1], fields[2], fields[3], *epoch, fields[5], fields[6]};
}

inline std::optional<std::string_view> lock(std::string_view intent)
{
    if (!intent.starts_with("LNDI:1;"))
        return std::nullopt;
    intent.remove_prefix(7);
    const auto end = intent.find(';');
    if (end == std::string_view::npos || end > 256 || !intent.starts_with("session:lock:"))
        return std::nullopt;
    return intent.substr(0, end);
}

inline std::optional<std::string> transaction(std::string_view request, std::string_view lock)
{
    // UID comes only from the actual Root-validated replacement lock. The
    // transport still independently authenticates the native owner and Control.
    if (!lock.starts_with("session:lock:"))
        return std::nullopt;
    lock.remove_prefix(13);
    const auto boot = lock.find(':');
    if (boot == std::string_view::npos)
        return std::nullopt;
    lock.remove_prefix(boot + 1);
    const auto uid = OriginalGrantCodec::number(lock.substr(0, lock.find(':')));
    if (!uid || *uid == 0 || *uid > std::numeric_limits<std::uint32_t>::max())
        return std::nullopt;
    std::string canonical;
    nativeGuardField(canonical, "linura.transaction.id.v1");
    nativeGuardField(canonical, "unix:uid:" + std::to_string(*uid));
    nativeGuardField(canonical, request);
    const auto digest = nativeSha256(canonical);
    return digest ? std::optional("transaction:v1:" + *digest) : std::nullopt;
}

inline bool matchesHeld(const Intent &intent, std::string_view authenticatedRestoration,
                        const Correlation &held, const Snapshot &restored,
                        std::uint64_t postWriteEpoch)
{
    // The complete nested material must be the actual immutable Root source,
    // not another structurally plausible LNRI document supplied by the owner.
    if (intent.restoration != authenticatedRestoration || intent.postWriteEpoch == 0 ||
        intent.postWriteEpoch != postWriteEpoch ||
        intent.restorationDispatch != held.dispatchDigest)
        return false;
    const auto source = OriginalGrantCodec::materialFields(authenticatedRestoration);
    if (!source || intent.restorationRequest == (*source)[0] ||
        intent.restorationDispatch == (*source)[1])
        return false;
    const auto replacement = OriginalGrantCodec::intent((*source)[5]);
    const auto exactLock = lock((*source)[5]);
    if (!replacement || !exactLock || intent.currentLock != *exactLock ||
        transaction(intent.restorationRequest, *exactLock) != std::optional(held.transaction) ||
        replacement->desired.size() != restored.heads.size())
        return false;
    const auto topology = replacement->topology;
    const auto generation = OriginalGrantCodec::number(topology.substr(topology.rfind(':') + 1));
    if (generation != std::optional(restored.generation))
        return false;
    for (std::size_t i = 0; i < restored.heads.size(); ++i)
        if (replacement->desired[i] != restored.heads[i].current)
            return false;
    return nativeBaselineGuard(restored, replacement->desiredText) ==
           std::optional(std::string(intent.sourceGuard));
}
} // namespace OriginalFinalizationCodec
} // namespace Linura::HyprlandDisplay
