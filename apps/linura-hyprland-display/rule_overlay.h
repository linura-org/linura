#pragma once

#include "display_transaction.h"

#include <string>
#include <type_traits>
#include <utility>

namespace Linura::HyprlandDisplay {

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
