#pragma once

#include "protected_interaction.h"
#include "wire_endpoint.h"

#include <functional>
#include <memory>

struct wl_display;
struct wl_resource;

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

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace Linura::HyprlandDisplay
