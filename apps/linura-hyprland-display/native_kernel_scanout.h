#pragma once

#include <xf86drmMode.h>

#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <string_view>

namespace Linura::HyprlandDisplay {

// Read-only KMS facts from the already admitted compositor descriptor. Never
// opens a device, acquires master, imports a framebuffer or submits a modeset.
// Querying a requested Aquamarine state is insufficient terminal evidence.
struct NativeKernelScanout final
{
    std::uint32_t connector = 0, crtc = 0, framebuffer = 0, plane = 0;
    drmModeModeInfo mode{};
    bool active = false;
};

[[nodiscard]] inline bool sameKernelMode(const drmModeModeInfo &a, const drmModeModeInfo &b)
{
    return a.clock == b.clock && a.hdisplay == b.hdisplay && a.hsync_start == b.hsync_start &&
           a.hsync_end == b.hsync_end && a.htotal == b.htotal && a.hskew == b.hskew &&
           a.vdisplay == b.vdisplay && a.vsync_start == b.vsync_start &&
           a.vsync_end == b.vsync_end && a.vtotal == b.vtotal && a.vscan == b.vscan &&
           a.flags == b.flags;
}

namespace KernelScanoutDetail {
using Budget = std::function<bool()>;
[[nodiscard]] inline std::optional<std::uint64_t> property(int fd, std::uint32_t object,
                                                           std::uint32_t type,
                                                           std::string_view name,
                                                           const Budget &budget)
{
    if (fd < 0 || object == 0 || !budget || !budget())
        return std::nullopt;
    const std::unique_ptr<drmModeObjectProperties, decltype(&drmModeFreeObjectProperties)> props{
        drmModeObjectGetProperties(fd, object, type), drmModeFreeObjectProperties};
    if (!props || props->count_props == 0 || props->count_props > 64 || !budget())
        return std::nullopt;
    std::optional<std::uint64_t> found;
    for (std::uint32_t i = 0; i < props->count_props; ++i) {
        if (!budget())
            return std::nullopt;
        const std::unique_ptr<drmModePropertyRes, decltype(&drmModeFreeProperty)> prop{
            drmModeGetProperty(fd, props->props[i]), drmModeFreeProperty};
        if (!prop || !budget())
            return std::nullopt;
        const auto length = strnlen(prop->name, sizeof(prop->name));
        if (length == sizeof(prop->name))
            return std::nullopt;
        if (std::string_view(prop->name, length) == name) {
            if (found)
                return std::nullopt;
            found = props->prop_values[i];
        }
    }
    return found;
}
} // namespace KernelScanoutDetail

// No retries or fallback to cached native state. Atomic KMS properties are
// required; unsupported/ambiguous driver state leaves recovery fenced.
[[nodiscard]] inline std::optional<NativeKernelScanout>
readNativeKernelScanout(int fd, std::uint32_t connector, const KernelScanoutDetail::Budget &budget)
{
    using namespace KernelScanoutDetail;
    if (fd < 0 || connector == 0 || !budget || !budget())
        return std::nullopt;
    const auto crtc = property(fd, connector, DRM_MODE_OBJECT_CONNECTOR, "CRTC_ID", budget);
    if (!crtc || *crtc > UINT32_MAX)
        return std::nullopt;
    NativeKernelScanout result;
    result.connector = connector;
    result.crtc = static_cast<std::uint32_t>(*crtc);
    if (result.crtc == 0) {
        // An actually detached connector is a disable result. A logical
        // enabled=false flag or queued disable acknowledgement is insufficient.
        return property(fd, connector, DRM_MODE_OBJECT_CONNECTOR, "CRTC_ID", budget) == crtc &&
                       budget()
                   ? std::optional{result}
                   : std::nullopt;
    }
    const auto active = property(fd, result.crtc, DRM_MODE_OBJECT_CRTC, "ACTIVE", budget);
    const auto modeId = property(fd, result.crtc, DRM_MODE_OBJECT_CRTC, "MODE_ID", budget);
    if (!active || *active != 1 || !modeId || *modeId == 0 || *modeId > UINT32_MAX || !budget())
        return std::nullopt;
    const std::unique_ptr<drmModePropertyBlobRes, decltype(&drmModeFreePropertyBlob)> mode{
        drmModeGetPropertyBlob(fd, static_cast<std::uint32_t>(*modeId)), drmModeFreePropertyBlob};
    if (!mode || mode->length != sizeof(drmModeModeInfo) || !mode->data || !budget())
        return std::nullopt;
    std::memcpy(&result.mode, mode->data, sizeof(result.mode));
    if (!result.mode.clock || !result.mode.hdisplay || !result.mode.vdisplay ||
        !result.mode.htotal || !result.mode.vtotal)
        return std::nullopt;
    const std::unique_ptr<drmModePlaneRes, decltype(&drmModeFreePlaneResources)> planes{
        drmModeGetPlaneResources(fd), drmModeFreePlaneResources};
    if (!planes || planes->count_planes == 0 || planes->count_planes > 128 || !budget())
        return std::nullopt;
    for (std::uint32_t i = 0; i < planes->count_planes; ++i) {
        if (!budget())
            return std::nullopt;
        const std::unique_ptr<drmModePlane, decltype(&drmModeFreePlane)> plane{
            drmModeGetPlane(fd, planes->planes[i]), drmModeFreePlane};
        if (!plane || !budget())
            return std::nullopt;
        if (plane->crtc_id != result.crtc || plane->fb_id == 0)
            continue;
        const auto type = property(fd, plane->plane_id, DRM_MODE_OBJECT_PLANE, "type", budget);
        // Protected cursor/overlay suppression must be reflected in actual
        // KMS, not just compositor scene selection. Exactly one primary plane.
        if (!type || *type != DRM_PLANE_TYPE_PRIMARY || result.plane != 0)
            return std::nullopt;
        result.plane = plane->plane_id;
        result.framebuffer = plane->fb_id;
    }
    if (!result.plane || !result.framebuffer || !budget())
        return std::nullopt;
    const std::unique_ptr<drmModePlane, decltype(&drmModeFreePlane)> finalPlane{
        drmModeGetPlane(fd, result.plane), drmModeFreePlane};
    if (!finalPlane || finalPlane->crtc_id != result.crtc ||
        finalPlane->fb_id != result.framebuffer ||
        property(fd, connector, DRM_MODE_OBJECT_CONNECTOR, "CRTC_ID", budget) != crtc ||
        property(fd, result.crtc, DRM_MODE_OBJECT_CRTC, "ACTIVE", budget) != active ||
        property(fd, result.crtc, DRM_MODE_OBJECT_CRTC, "MODE_ID", budget) != modeId || !budget())
        return std::nullopt;
    result.active = true;
    return result;
}
} // namespace Linura::HyprlandDisplay
