#pragma once

#include "owned_native_fd.h"

#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <optional>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>

namespace Linura::HyprlandDisplay::SealedNativeMaterial {
// Private comparison transport, never a credential. Full terminal material can
// exceed Wayland's ordinary string buffer. Do not grow the connection's limits.
inline constexpr std::size_t MaxBytes = 14 * 1024;
inline constexpr int Seals = F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL;

inline std::optional<OwnedNativeFd> create(std::string_view material)
{
    if (material.empty() || material.size() > MaxBytes)
        return std::nullopt;
    OwnedNativeFd descriptor{
        memfd_create("linura-display-comparison", MFD_CLOEXEC | MFD_ALLOW_SEALING)};
    if (descriptor.get() < 0)
        return std::nullopt;
    std::size_t offset = 0;
    while (offset < material.size()) {
        const auto count = pwrite(descriptor.get(), material.data() + offset,
                                  material.size() - offset, static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return std::nullopt;
        offset += static_cast<std::size_t>(count);
    }
    if (fcntl(descriptor.get(), F_ADD_SEALS, Seals) != 0)
        return std::nullopt;
    return descriptor;
}

// Consume on every path. Reject pipes/sockets/devices and mutable or oversized
// files before allocating or reading; pread ignores a sender-controlled offset.
inline std::optional<std::string> read(OwnedNativeFd descriptor)
{
    const auto seals = descriptor.get() < 0 ? -1 : fcntl(descriptor.get(), F_GET_SEALS);
    if (seals < 0 || (seals & Seals) != Seals)
        return std::nullopt;
    struct stat facts
    {};
    if (fstat(descriptor.get(), &facts) != 0 || !S_ISREG(facts.st_mode) || facts.st_nlink != 0 ||
        facts.st_uid != getuid() || facts.st_size <= 0 ||
        static_cast<std::uint64_t>(facts.st_size) > MaxBytes)
        return std::nullopt;
    std::string material(static_cast<std::size_t>(facts.st_size), '\0');
    std::size_t offset = 0;
    while (offset < material.size()) {
        const auto count = pread(descriptor.get(), material.data() + offset,
                                 material.size() - offset, static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return std::nullopt;
        offset += static_cast<std::size_t>(count);
    }
    return material;
}
} // namespace Linura::HyprlandDisplay::SealedNativeMaterial
