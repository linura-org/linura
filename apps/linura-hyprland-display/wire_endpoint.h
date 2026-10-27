#pragma once

#include "compositor_display_service.h"

#include <functional>
#include <memory>
#include <string>

struct wl_display;

namespace Linura::HyprlandDisplay {

struct NativeBuildIdentity final
{
    std::string compositorInstance, upstreamCommit, integrationDigest;
};

// Adapter-private Wayland mechanism. Its native session scoping and ownership
// checks do not authorize a Linura operation. Linura's sole production caller
// remains the protected owner reached through prepared executor admission.
class WireEndpoint final
{
  public:
    using OutputName = std::function<std::optional<std::string>(OutputKey)>;
    WireEndpoint(wl_display &, Backend &, CompositorDisplayService &, NativeBuildIdentity,
                 OutputName);
    ~WireEndpoint();
    WireEndpoint(const WireEndpoint &) = delete;
    WireEndpoint &operator=(const WireEndpoint &) = delete;
    [[nodiscard]] bool available() const noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace Linura::HyprlandDisplay
