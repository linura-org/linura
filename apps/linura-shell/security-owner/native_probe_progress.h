#pragma once

#include <functional>

namespace Linura::SecurityOwner {

// Factory-owned progress on the existing attested Wayland connection only.
// Never a Qt event loop, metadata cache, approval or effect-dispatch callback.
// Its time remains inside the caller's original native probe clock.
using NativeProbeProgress = std::function<void()>;

} // namespace Linura::SecurityOwner
