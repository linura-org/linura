#pragma once

#include "compositor_display_service.h"
#include "owned_native_fd.h"

#include <functional>
#include <array>
#include <memory>
#include <string>
#include <sys/types.h>

struct wl_display;
struct wl_client;
struct wl_resource;

namespace Linura::HyprlandDisplay {

struct NativeBuildIdentity final
{
    std::string compositorInstance, upstreamCommit, integrationDigest;
};

struct NativeStartupPort final
{
    std::function<unsigned()> phase;
    // Takes ownership only on success; all callers are independently admitted
    // protected-owner processes, never ordinary Wayland clients.
    std::function<bool(int, bool, std::uint32_t)> admit;
};

struct NativeOriginalRestorationPort final
{
    // The move-only descriptor is consumed on every path, including exceptions.
    // Only the pinned backend may authenticate its original Root peer and
    // reserve the distinct consumed Recovery scene before a native write.
    std::function<std::optional<std::uint32_t>(OwnedNativeFd, const Correlation &, const Layout &,
                                               const Snapshot &, ClockSample, wl_resource *,
                                               wl_client *)>
        dispatch;
    std::function<std::optional<std::uint32_t>(const Correlation &)> status;
    // Fresh actual KMS/post-write frame facts only. Not acknowledgement,
    // commit authority, startup release or a cached desired layout.
    std::function<std::optional<std::string>()> presentation;
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
                 OutputName, AdmitOwner, NativeStartupPort, NativeOriginalRestorationPort);
    ~WireEndpoint();
    WireEndpoint(const WireEndpoint &) = delete;
    WireEndpoint &operator=(const WireEndpoint &) = delete;
    [[nodiscard]] bool available() const noexcept;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace Linura::HyprlandDisplay
