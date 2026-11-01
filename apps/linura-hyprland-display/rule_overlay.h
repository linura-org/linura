#pragma once

#include "display_transaction.h"

#include <string>
#include <algorithm>
#include <iterator>
#include <map>
#include <optional>
#include <type_traits>
#include <utility>

namespace Linura::HyprlandDisplay {

// Private in-process compensation checkpoint. Preserve overlay ownership and
// automatic native rule semantics, not just their resolved numeric geometry.
// This is deliberately not durable recovery or an authorization credential.
template <typename Key, typename Rule> class RuleOverlayCheckpoint final
{
  public:
    using Overlay = std::map<Key, Target>;
    using Rules = std::map<Key, Rule>;
    using Identities = std::map<Key, OutputKey>;
    [[nodiscard]] bool capture(const Overlay &overlay, const Rules &rules, const Layout &baseline,
                               const Identities &identities)
    {
        if (saved_ || baseline.empty() || rules.size() != baseline.size() ||
            identities.size() != rules.size() || overlay.size() > rules.size())
            return false;
        // Capture the native-object-to-output pairing, not merely independent
        // membership of each key and output in a historical collection.
        // Otherwise a recycled/swapped monitor binding could inherit an old
        // rule-ownership privilege from a different head.
        for (const auto &[key, output] : identities) {
            if (!rules.contains(key) ||
                std::count_if(baseline.begin(), baseline.end(), [&](const Target &target) {
                    return target.output == output;
                }) != 1)
                return false;
        }
        for (const auto &[key, target] : overlay) {
            const auto found = identities.find(key);
            if (found == identities.end() || found->second != target.output)
                return false;
        }
        saved_ = Saved{overlay, rules, baseline, identities};
        return true;
    }
    [[nodiscard]] bool retained() const noexcept
    {
        return saved_.has_value();
    }
    [[nodiscard]] bool owns(const Key &key, OutputKey output) const
    {
        if (!saved_)
            return false;
        const auto found = saved_->identities.find(key);
        return found != saved_->identities.end() && found->second == output;
    }
    template <typename Same>
    [[nodiscard]] std::optional<Overlay> restoration(const Layout &baseline, const Rules &rules,
                                                     const Identities &identities, Same same) const
    {
        if (!saved_ || baseline != saved_->baseline || identities != saved_->identities ||
            !rulesMatch(rules, same))
            return std::nullopt;
        return saved_->overlay;
    }
    template <typename Same>
    [[nodiscard]] bool restored(const Overlay &overlay, const Rules &rules,
                                const Identities &identities, Same same) const
    {
        return saved_ && overlay == saved_->overlay && identities == saved_->identities &&
               rulesMatch(rules, same);
    }
    void retire() noexcept
    {
        saved_.reset();
    }

  private:
    struct Saved final
    {
        Overlay overlay;
        Rules rules;
        Layout baseline;
        Identities identities;
    };
    std::optional<Saved> saved_;
    template <typename Same> bool rulesMatch(const Rules &rules, Same same) const
    {
        if (rules.size() != saved_->rules.size())
            return false;
        for (const auto &[key, rule] : saved_->rules) {
            const auto found = rules.find(key);
            if (found == rules.end() || !same(rule, found->second))
                return false;
        }
        return true;
    }
};

// Compare every owned rule semantic, including the native custom modeline.
// Unrelated ICC/color/VRR/reservation changes remain live and are never restored
// from an old full rule. This template is instantiated against the pinned SDK.
template <typename Rule> [[nodiscard]] bool sameOwnedDisplayFields(const Rule &a, const Rule &b)
{
    const auto &x = a.m_drmMode;
    const auto &y = b.m_drmMode;
    return a.m_disabled == b.m_disabled && a.m_resolution == b.m_resolution &&
           a.m_refreshRate == b.m_refreshRate && a.m_offset == b.m_offset &&
           a.m_autoDir == b.m_autoDir && a.m_scale == b.m_scale && a.m_transform == b.m_transform &&
           a.m_mirrorOf == b.m_mirrorOf && x.clock == y.clock && x.hdisplay == y.hdisplay &&
           x.hsync_start == y.hsync_start && x.hsync_end == y.hsync_end && x.htotal == y.htotal &&
           x.hskew == y.hskew && x.vdisplay == y.vdisplay && x.vsync_start == y.vsync_start &&
           x.vsync_end == y.vsync_end && x.vtotal == y.vtotal && x.vscan == y.vscan &&
           x.vrefresh == y.vrefresh && x.flags == y.flags && x.type == y.type &&
           std::equal(std::begin(x.name), std::end(x.name), std::begin(y.name));
}

// Instantiated against Config::CMonitorRule by the pinned native build. Keep the
// original rule and its selector/precedence; merge only explicitly owned display
// fields after upstream config and wlr overrides. Color, ICC, VRR, reservations,
// luminance and any future upstream fields remain in the copied current rule.
// The caller resolves mirrorName from the exact retained native output object,
// never a client-provided compositor selector or command.
template <typename Rule>
[[nodiscard]] Rule overlayDisplayFields(Rule current, const Target &target,
                                        const std::string &mirrorName)
{
    current.m_disabled = !target.enabled;
    if (!target.enabled)
        return current;
    current.m_resolution = {target.mode.width, target.mode.height};
    current.m_refreshRate = static_cast<float>(target.mode.refreshMilliHz) / 1000.F;
    current.m_offset = {target.x, target.y};
    current.m_autoDir = static_cast<decltype(current.m_autoDir)>(0);
    current.m_scale = static_cast<float>(target.scaleMilli) / 1000.F;
    current.m_transform = static_cast<decltype(current.m_transform)>(target.transform);
    current.m_mirrorOf = mirrorName;
    // An old custom modeline belongs to mode selection. Retaining it would
    // override the exact advertised native mode requested by this transaction.
    current.m_drmMode = {};
    return current;
}

} // namespace Linura::HyprlandDisplay
