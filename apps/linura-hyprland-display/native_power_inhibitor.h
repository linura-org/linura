#pragma once

namespace Linura::HyprlandDisplay {

// Private compositor-owned native mechanism. The descriptor is never exposed
// to Wayland clients and survives their loss. No force/ignore-inhibitor path.
class NativePowerInhibitor final
{
  public:
    NativePowerInhibitor() = default;
    ~NativePowerInhibitor();
    NativePowerInhibitor(const NativePowerInhibitor &) = delete;
    NativePowerInhibitor &operator=(const NativePowerInhibitor &) = delete;
    [[nodiscard]] bool acquire();
    void release() noexcept;

  private:
    int descriptor_ = -1;
};

} // namespace Linura::HyprlandDisplay
