#pragma once

#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>

namespace Linura::HyprlandDisplay {
// Native delivery bookkeeping only. It cannot admit a new press while input is
// gated, grant a proof, select a principal or release a session lock.
class ProtectedKeyDelivery final
{
  public:
    static constexpr std::size_t Devices = 16, Keys = 768;
    enum class Edge { Ignore, Press, Release };
    ProtectedKeyDelivery() = default;
    ProtectedKeyDelivery(const ProtectedKeyDelivery &) = delete;
    ProtectedKeyDelivery &operator=(const ProtectedKeyDelivery &) = delete;
    // A release for an already delivered press still drains to the SAME private
    // owner during an expected frame revision. Aggregate multiple native devices
    // so releasing one keyboard cannot retire another keyboard's held key.
    [[nodiscard]] Edge edge(std::size_t device, std::uint32_t key, bool pressed, bool ready)
    {
        if (device >= Devices || key >= Keys)
            return Edge::Ignore;
        auto &own = delivered_[device];
        if (pressed) {
            const bool heldBefore = pressed_[device].test(key);
            pressed_[device].set(key);
            if (!ready || heldBefore)
                return Edge::Ignore;
            bool held = false;
            for (const auto &keys : delivered_)
                held = held || keys.test(key);
            own.set(key);
            return held ? Edge::Ignore : Edge::Press;
        }
        pressed_[device].reset(key);
        if (!own.test(key))
            return Edge::Ignore;
        own.reset(key);
        for (const auto &keys : delivered_)
            if (keys.test(key))
                return Edge::Ignore;
        return Edge::Release;
    }

  private:
    std::array<std::bitset<Keys>, Devices> delivered_{};
    std::array<std::bitset<Keys>, Devices> pressed_{};
};
} // namespace Linura::HyprlandDisplay
