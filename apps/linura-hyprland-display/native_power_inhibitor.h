#pragma once

#include "native_inhibitor_fd.h"

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
    [[nodiscard]] bool held() const noexcept;
    [[nodiscard]] bool retained() const noexcept;
    void release() noexcept;

  private:
    NativeInhibitorFd descriptor_;
};

} // namespace Linura::HyprlandDisplay
