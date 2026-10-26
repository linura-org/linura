#pragma once

#include <QString>
#include <QtGlobal>
#include <memory>
#include <compare>
#include <optional>
#include <vector>

struct wl_registry;

namespace Linura::SecurityOwner {

// Adapter-local facts from the actual owned Wayland connection. Native object
// pointers and protocol serials never cross this boundary or become authority.
struct NativeDisplayMode final
{
    qint32 width = 0, height = 0, refresh = 0;
    auto operator<=>(const NativeDisplayMode &) const = default;
};

struct NativeDisplayHead final
{
    quint64 handle = 0, generation = 0;
    QString name;
    bool enabled = false;
    bool covered = false;
    std::vector<NativeDisplayMode> modes;
    std::optional<NativeDisplayMode> current;
    qint32 x = 0, y = 0, transform = 0, scaleFixed = 0;
    bool operator==(const NativeDisplayHead &) const = default;
};

struct NativeDisplaySnapshot final
{
    quint64 generation = 0;
    std::vector<NativeDisplayHead> heads;
    [[nodiscard]] QString encode() const;
    bool operator==(const NativeDisplaySnapshot &) const = default;
};

// A bounded, continuously retained native object-lifetime inventory. A removed
// connector that reappears receives another handle/generation even when its name
// is reused. No method here can construct or submit an output configuration.
class NativeDisplayTopology final
{
  public:
    NativeDisplayTopology();
    ~NativeDisplayTopology();
    NativeDisplayTopology(const NativeDisplayTopology &) = delete;
    NativeDisplayTopology &operator=(const NativeDisplayTopology &) = delete;
    void announce(wl_registry *registry, quint32 global, quint32 version);
    void removed(quint32 global);
    // Caller must first complete a bounded sync on the SAME Wayland connection.
    // The pinned compositor can send state updates without manager.done; a sync
    // fence drains those updates rather than promoting the last done as current.
    [[nodiscard]] std::optional<NativeDisplaySnapshot> snapshotAfterSync() const;

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace Linura::SecurityOwner
