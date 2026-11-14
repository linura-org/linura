#pragma once

#include "display_transaction.h"
#include "native_digest.h"
#include <limits>

namespace Linura::HyprlandDisplay {
inline void nativeGuardField(std::string &out, std::string_view value)
{
    const auto size = static_cast<std::uint64_t>(value.size());
    for (unsigned shift = 64; shift != 0; shift -= 8)
        out += static_cast<char>((size >> (shift - 8)) & 255U);
    out += value;
}
// Exact Rust/owner comparison domain, now recomputed from the compositor's
// actual immutable native snapshot. This hash is a precondition, not authority.
inline std::optional<std::string> nativeBaselineGuard(const Snapshot &snapshot,
                                                      std::string_view baseline)
{
    if (snapshot.heads.empty() || snapshot.heads.size() > DisplayTransaction::MaxHeads ||
        baseline.empty() || baseline.size() > 4096)
        return std::nullopt;
    std::string rows;
    std::optional<OutputKey> previous;
    for (const auto &head : snapshot.heads) {
        if (!head.key.handle || !head.key.generation ||
            head.key.generation == std::numeric_limits<std::uint64_t>::max() ||
            (previous && head.key.handle <= previous->handle) || head.baseRuleWitness.empty() ||
            head.baseRuleWitness.size() > 20 * 1024 || head.outputIdentityWitness.empty() ||
            head.outputIdentityWitness.size() > 16 * 1024 || head.ownedTargetWitness.size() > 512 ||
            (head.linuraOwned == head.ownedTargetWitness.empty()))
            return std::nullopt;
        previous = head.key;
        const auto rule = nativeSha256(head.baseRuleWitness),
                   identity = nativeSha256(head.outputIdentityWitness);
        if (!rule || !identity)
            return std::nullopt;
        for (const auto &field :
             {std::to_string(head.key.handle), std::to_string(head.key.generation),
              std::string(head.linuraOwned ? "true" : "false"), *rule, *identity,
              head.ownedTargetWitness})
            nativeGuardField(rows, field);
    }
    std::string canonical;
    nativeGuardField(canonical, "linura.display.native-baseline-guard.v1");
    nativeGuardField(canonical, baseline);
    nativeGuardField(canonical, rows);
    return nativeSha256(canonical);
}
} // namespace Linura::HyprlandDisplay
