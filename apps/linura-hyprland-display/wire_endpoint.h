#pragma once

#include "compositor_display_service.h"

#include <functional>
#include <array>
#include <memory>
#include <string>
#include <sys/types.h>

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
    using OwnerInvocation = std::array<unsigned char, 16>;
    // Kernel credentials are adapter facts, never caller-supplied wire fields.
    // Each effect requires a fresh root-supervised invocation attestation.
    using AdmitOwner = std::function<std::optional<OwnerInvocation>(pid_t, uid_t)>;
    WireEndpoint(wl_display &, Backend &, CompositorDisplayService &, NativeBuildIdentity,
                 OutputName, AdmitOwner);
    ~WireEndpoint();
    WireEndpoint(const WireEndpoint &) = delete;
    WireEndpoint &operator=(const WireEndpoint &) = delete;
    [[nodiscard]] bool available() const noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace Linura::HyprlandDisplay
