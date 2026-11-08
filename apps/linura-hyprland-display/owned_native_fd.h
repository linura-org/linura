#pragma once

#include <unistd.h>
#include <utility>

namespace Linura::HyprlandDisplay {
// Adapter-local ownership only. A descriptor is not permission or evidence.
class OwnedNativeFd final
{
  public:
    explicit OwnedNativeFd(int descriptor) noexcept : descriptor_(descriptor) {}
    ~OwnedNativeFd()
    {
        if (descriptor_ >= 0)
            close(descriptor_);
    }
    OwnedNativeFd(const OwnedNativeFd &) = delete;
    OwnedNativeFd &operator=(const OwnedNativeFd &) = delete;
    OwnedNativeFd(OwnedNativeFd &&other) noexcept
        : descriptor_(std::exchange(other.descriptor_, -1))
    {}
    OwnedNativeFd &operator=(OwnedNativeFd &&other) noexcept
    {
        if (this != &other) {
            if (descriptor_ >= 0)
                close(descriptor_);
            descriptor_ = std::exchange(other.descriptor_, -1);
        }
        return *this;
    }
    [[nodiscard]] int get() const noexcept
    {
        return descriptor_;
    }

  private:
    int descriptor_;
};
} // namespace Linura::HyprlandDisplay
