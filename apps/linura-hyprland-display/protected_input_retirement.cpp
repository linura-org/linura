#include "protected_input_retirement.h"

namespace Linura::HyprlandDisplay {
ProtectedInputRetirement::Phase ProtectedInputRetirement::phase() const noexcept
{
    return phase_;
}
bool ProtectedInputRetirement::blocked() const noexcept
{
    return phase_ != Phase::Open;
}
bool ProtectedInputRetirement::begin(Held held) noexcept
{
    if (phase_ != Phase::Open || held.any || held.escape || held.other)
        return false;
    phase_ = Phase::Private;
    escapeReleased_ = false;
    return true;
}
void ProtectedInputRetirement::close(bool freshPhysicalExit, Held held) noexcept
{
    if (phase_ != Phase::Private)
        return;
    phase_ = freshPhysicalExit
                 ? ((held.any || held.escape || held.other) ? Phase::Draining : Phase::Open)
                 : Phase::Quarantined;
    escapeReleased_ = !held.escape;
}
bool ProtectedInputRetirement::key(bool physical, bool escape, bool pressed, Held held) noexcept
{
    if (phase_ == Phase::Open)
        return false;
    if (phase_ == Phase::Private)
        return true;
    // Virtual/unknown devices cannot acknowledge exit or retire held native
    // state, even when their supplied key resembles Escape/release.
    if (!physical)
        return true;
    if (phase_ == Phase::Quarantined) {
        if (escape && !pressed)
            escapeReleased_ = true;
        if (escape && pressed) {
            const bool fresh = escapeReleased_;
            escapeReleased_ = false;
            if (fresh && held.escape && !held.other)
                phase_ = Phase::Draining;
        }
    }
    poll(held);
    return true;
}
void ProtectedInputRetirement::poll(Held held) noexcept
{
    if (phase_ == Phase::Quarantined && !held.escape)
        escapeReleased_ = true;
    if (phase_ == Phase::Draining && !held.any && !held.escape && !held.other)
        phase_ = Phase::Open;
}
} // namespace Linura::HyprlandDisplay
