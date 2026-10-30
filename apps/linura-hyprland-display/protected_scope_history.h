#pragma once

#include "protected_interaction.h"

#include <algorithm>
#include <limits>
#include <map>

namespace Linura::HyprlandDisplay {

// Compositor-lifetime at-most-once scopes. Only expired entries are reclaimed;
// capacity pressure must never evict a live scope and permit proof reuse. Both
// clocks are retained across reclamation, so rollback cannot revive a retired
// Unix deadline. This is not authentication or managed transaction recovery.
class ProtectedScopeHistory final
{
  public:
    static constexpr std::size_t Capacity = 256;
    [[nodiscard]] bool reserve(const ProtectedInteraction::Scope &scope, ClockSample now)
    {
        if (failed_ || now.unixMs == 0 || now.bootMs == 0 || now.unixMs < last_.unixMs ||
            now.bootMs < last_.bootMs) {
            failed_ = true;
            return false;
        }
        last_ = now;
        std::erase_if(entries_, [&](const auto &entry) {
            // A BOOTTIME-expired scope whose wall deadline is still ahead
            // must keep its tombstone: remapping that digest at a later begin
            // would otherwise grant it a second boot-clock window.
            return now.unixMs >= entry.second.unixMs && now.bootMs >= entry.second.bootMs;
        });
        const auto maximum = scope.purpose == ProtectedInteraction::Purpose::Apply
                                 ? ProtectedInteraction::MaximumWindowMs
                                 : ProtectedInteraction::DecisionWindowMs;
        if ((scope.purpose != ProtectedInteraction::Purpose::Apply &&
             scope.purpose != ProtectedInteraction::Purpose::Keep &&
             scope.purpose != ProtectedInteraction::Purpose::Revert) ||
            scope.digest.size() != 64 || scope.digest == std::string(64, '0') ||
            !std::all_of(scope.digest.begin(), scope.digest.end(),
                         [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }) ||
            scope.deadlineUnixMs <= now.unixMs || scope.deadlineUnixMs - now.unixMs > maximum ||
            now.bootMs >
                std::numeric_limits<std::uint64_t>::max() - (scope.deadlineUnixMs - now.unixMs) ||
            entries_.size() >= Capacity)
            return false;
        return entries_
            .emplace(scope.digest, ClockSample{scope.deadlineUnixMs,
                                               now.bootMs + (scope.deadlineUnixMs - now.unixMs)})
            .second;
    }

  private:
    std::map<std::string, ClockSample> entries_;
    ClockSample last_;
    bool failed_ = false;
};

} // namespace Linura::HyprlandDisplay
