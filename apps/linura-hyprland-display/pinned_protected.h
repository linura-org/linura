#pragma once

// Private types belong only to the exact-source compositor adapter.
#include "src/defines.hpp"
#include "native_first_frame_gate.h"
#include "src/devices/IKeyboard.hpp"
#include "src/devices/IPointer.hpp"
#include "src/helpers/time/Time.hpp"

#include <optional>

namespace Aquamarine {
class IBuffer;
}
struct wl_display;
class CWLSurfaceResource;
namespace Monitor {
class CMonitor;
}
namespace Linura::HyprlandDisplay {
struct Correlation;
struct OriginalRestorationFrame final
{
    SP<Aquamarine::IBuffer> buffer;
    std::uint64_t commit = 0, postWriteEpoch = 0;
};
// Read-only post-write hardware completion on the retained actual output. A
// startup frame, retired commit or owner-content frame cannot satisfy this.
[[nodiscard]] std::optional<OriginalRestorationFrame> originalRestorationFrame(Monitor::CMonitor *,
                                                                               const Correlation &);
// Retained original Recovery scene's own post-write/safety-frame queued
// high-water. Not output-wide native commit evidence or a release credential.
// The release consumer must independently capture output-wide counters again.
struct NativeProtectedFrameBaseline final
{
    std::uint64_t postWriteEpoch = 0;
    std::vector<NativeFirstFrameGate::Output> before;
};
using NativeProtectedBaseline = std::optional<NativeProtectedFrameBaseline>;
[[nodiscard]] NativeProtectedBaseline readProtectedBaseline(const Correlation &, const Snapshot &);
void initializeProtectedDisplay(wl_display &);
void shutdownProtectedDisplay();
void startupAdmissionChanged();
[[nodiscard]] bool protectedDisplayActive();
[[nodiscard]] bool protectedInputExclusive();
// A true result means that the ordinary scene must not be rendered.
[[nodiscard]] bool renderProtectedDisplay(Monitor::CMonitor *, const Time::steady_tp &);
// Engaged only inside a protected scene. A failed queued submission cannot fall
// back to an uncorrelated synchronous commit.
void protectedFrameRendered(Monitor::CMonitor *, Aquamarine::IBuffer *);
[[nodiscard]] std::optional<bool> commitProtectedDisplay(Monitor::CMonitor *);
[[nodiscard]] bool protectedKeyboardFocusAllowed(const SP<CWLSurfaceResource> &);
[[nodiscard]] bool protectedPointerFocusAllowed(const SP<CWLSurfaceResource> &);
[[nodiscard]] bool protectedKeyboardKey(const IKeyboard::SKeyEvent &, const SP<IKeyboard> &);
[[nodiscard]] bool protectedKeyboardModifiers(const SP<IKeyboard> &);
[[nodiscard]] bool protectedPointerMove(const IPointer::SMotionEvent &);
[[nodiscard]] bool protectedPointerWarp(const IPointer::SMotionAbsoluteEvent &);
[[nodiscard]] bool protectedPointerButton(const IPointer::SButtonEvent &, const SP<IPointer> &);
// Refocus/IPC, unsupported input families and client-triggered paths may clear
// focus, but cannot redirect protected input into an ordinary window.
[[nodiscard]] bool protectedPointerRefocus(std::uint32_t);
} // namespace Linura::HyprlandDisplay
