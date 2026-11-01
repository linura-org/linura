#pragma once

#include <aquamarine/output/Output.hpp>
#include <aquamarine/backend/DRM.hpp>

#include <array>
#include <cmath>
#include <cstdint>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <sys/sysmacros.h>

namespace Linura::HyprlandDisplay {

// Native object lifetime is necessary but insufficient: a backend may update
// connector/EDID facts in place. This bounded adapter-only value invalidates
// generation-bound plans when that happens, even if modes are unchanged.
// Enabled state, geometry, DPMS and other mutation results are deliberately not
// identity: changing the approved layout must not invalidate its own attempt.
struct NativeOutputIdentity final
{
    std::array<std::string, 8> text;
    std::array<double, 2> physicalSize;
    std::optional<std::array<float, 3>> hdrLuminance;
    std::optional<std::array<double, 8>> chromaticity;
    bool supportsPQ = false, supportsBT2020 = false;
    // Actual native device binding, not a physical-continuity credential.
    // All zero denotes a non-DRM backend; it cannot support DRM recovery.
    std::array<std::uint32_t, 3> kernelDrm{};
    bool operator==(const NativeOutputIdentity &) const = default;
};

[[nodiscard]] inline std::optional<std::array<std::uint32_t, 3>>
nativeKernelDrmBinding(Aquamarine::IOutput &output)
{
    auto *drm = dynamic_cast<Aquamarine::CDRMOutput *>(&output);
    if (!drm)
        return std::array<std::uint32_t, 3>{};
    const auto backend = drm->getBackend();
    auto *native = dynamic_cast<Aquamarine::CDRMBackend *>(backend.get());
    struct stat metadata
    {};
    const int connector = drm->getConnectorID();
    if (!native || native->drmFD() < 0 || fstat(native->drmFD(), &metadata) != 0 ||
        !S_ISCHR(metadata.st_mode) || major(metadata.st_rdev) != 226 ||
        minor(metadata.st_rdev) > 63 || connector <= 0)
        return std::nullopt;
    return std::array<std::uint32_t, 3>{226, static_cast<std::uint32_t>(minor(metadata.st_rdev)),
                                        static_cast<std::uint32_t>(connector)};
}

[[nodiscard]] inline std::optional<NativeOutputIdentity>
nativeOutputIdentity(const Aquamarine::IOutput &output)
{
    // Check lengths before copying native strings. An unbounded or ambiguous
    // source is unavailable evidence, never another identity of the same head.
    const std::array<const std::string *, 8> strings{&output.name,
                                                     &output.description,
                                                     &output.make,
                                                     &output.model,
                                                     &output.serial,
                                                     &output.parsedEDID.make,
                                                     &output.parsedEDID.model,
                                                     &output.parsedEDID.serial};
    NativeOutputIdentity result{};
    for (std::size_t i = 0; i < strings.size(); ++i) {
        const auto &text = *strings[i];
        if ((i == 0 && text.empty()) || text.size() > (i == 1 ? 4096U : 256U))
            return std::nullopt;
        for (const auto character : text) {
            const auto byte = static_cast<unsigned char>(character);
            if (byte < 32 || byte == 127)
                return std::nullopt;
        }
        result.text[i] = text;
    }
    result.physicalSize = {output.physicalSize.x, output.physicalSize.y};
    for (const auto value : result.physicalSize)
        if (!std::isfinite(value) || value < 0 || value > 32768)
            return std::nullopt;
    if (output.parsedEDID.hdrMetadata) {
        const auto &hdr = *output.parsedEDID.hdrMetadata;
        result.hdrLuminance =
            std::array{hdr.desiredContentMaxLuminance, hdr.desiredMaxFrameAverageLuminance,
                       hdr.desiredContentMinLuminance};
        for (const auto value : *result.hdrLuminance)
            if (!std::isfinite(value) || value < 0 || value > 65536)
                return std::nullopt;
        result.supportsPQ = hdr.supportsPQ;
    }
    if (output.parsedEDID.chromaticityCoords) {
        const auto &color = *output.parsedEDID.chromaticityCoords;
        result.chromaticity = std::array{color.red.x,  color.red.y,  color.green.x, color.green.y,
                                         color.blue.x, color.blue.y, color.white.x, color.white.y};
        for (const auto value : *result.chromaticity)
            if (!std::isfinite(value) || value < 0 || value > 1)
                return std::nullopt;
    }
    result.supportsBT2020 = output.parsedEDID.supportsBT2020;
    return result;
}

} // namespace Linura::HyprlandDisplay
