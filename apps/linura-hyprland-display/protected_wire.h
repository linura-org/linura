#pragma once

#include "protected_interaction.h"
#include "wire_endpoint.h"

#include <functional>
#include <memory>
#include <string_view>

struct wl_display;
struct wl_resource;
struct wl_client;

namespace Linura::HyprlandDisplay {
struct ProtectedSceneStatus final
{
    std::string compositor;
    std::uint64_t topology = 0, epoch = 0;
    ProtectedInteraction::Phase phase = ProtectedInteraction::Phase::Cancelled;
};
// A bounded native presentation mechanism, not planning, policy or approval.
// All transport primitives remain inside this pinned compositor adapter.
class ProtectedScene
{
  public:
    using Configure =
        std::function<void(std::uint32_t serial, std::uint32_t width, std::uint32_t height)>;
    virtual ~ProtectedScene() = default;
    [[nodiscard]] virtual bool attach(OutputKey, wl_resource *surface, Configure) = 0;
    [[nodiscard]] virtual bool acknowledge(OutputKey, std::uint32_t serial) = 0;
    [[nodiscard]] virtual std::optional<ProtectedSceneStatus> status() = 0;
    [[nodiscard]] virtual bool refreshPresentation() = 0;
    [[nodiscard]] virtual bool consume(const std::string &scopeDigest, std::uint64_t epoch) = 0;
    [[nodiscard]] virtual bool beginDecision(const ProtectedInteraction::Scope &) = 0;
    // Same retained Recovery scene and still-live original Root witness. A
    // fresh review is not another restoration write or permission to release.
    [[nodiscard]] virtual bool beginFinalization(const ProtectedInteraction::Scope &,
                                                 const std::string &material) = 0;
    // One prepared actual-Root channel over this exact consumed terminal scene.
    // Success retains all fences and is never retirement or ordinary admission.
    [[nodiscard]] virtual bool quiesceFinalization(OwnedNativeFd, const Correlation &,
                                                   std::uint64_t sampledBootMs) = 0;
    // One original supervised Root spend, after terminal quiescence,
    // against the same retained actual native scene. Success acknowledges
    // LNRX and scheduling the first ordinary frames with all input, S17,
    // power and Root admission fences held. It is not terminal completion.
    [[nodiscard]] virtual bool spendNativeRelease(OwnedNativeFd, const Correlation &,
                                                  std::uint64_t sampledBootMs,
                                                  std::uint64_t controlVersion,
                                                  std::string_view controlBinding,
                                                  std::string_view controlObservation) = 0;
    [[nodiscard]] virtual std::shared_ptr<MutationProtection>
    reserveMutation(const Correlation &, const Layout &baseline, const Layout &desired,
                    const Snapshot &, ClockSample captured) = 0;
    // Distinct consumed Recovery scene, admitted only alongside the original
    // Root endpoint. Post-write source witnesses are exact comparison data;
    // the native backend alone derives them from the authenticated grant.
    [[nodiscard]] virtual std::shared_ptr<MutationProtection> reserveOriginalRestoration(
        const Correlation &, const Layout &baseline, const Layout &desired, const Snapshot &,
        ClockSample, const std::map<OutputKey, std::string> &restoredSources,
        const std::string &authenticatedMaterial, std::function<bool()> originalAlive) = 0;
    virtual void close() noexcept = 0;
};

class ProtectedWireEndpoint final
{
  public:
    using Begin =
        std::function<std::unique_ptr<ProtectedScene>(const ProtectedInteraction::Scope &)>;
    ProtectedWireEndpoint(wl_display &, WireEndpoint::AdmitOwner, Begin);
    ~ProtectedWireEndpoint();
    ProtectedWireEndpoint(const ProtectedWireEndpoint &) = delete;
    ProtectedWireEndpoint &operator=(const ProtectedWireEndpoint &) = delete;
    [[nodiscard]] bool available() const noexcept;
    // Acquires only this implementation's live resource on the same attested
    // Wayland connection. Digests, UID equality and lookalike objects cannot
    // substitute for the actual consumed scene.
    [[nodiscard]] static std::shared_ptr<MutationProtection>
    reserveMutation(wl_resource *, wl_client *, const Correlation &, const Layout &baseline,
                    const Layout &desired, const Snapshot &, ClockSample captured);
    [[nodiscard]] static std::shared_ptr<MutationProtection>
    reserveOriginalRestoration(wl_resource *, wl_client *, const Correlation &,
                               const Layout &baseline, const Layout &desired, const Snapshot &,
                               ClockSample, const std::map<OutputKey, std::string> &restoredSources,
                               const std::string &authenticatedMaterial,
                               std::function<bool()> originalAlive);

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace Linura::HyprlandDisplay
