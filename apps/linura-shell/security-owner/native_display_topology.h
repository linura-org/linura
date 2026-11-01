#pragma once

#include <QString>
#include <QtGlobal>
#include <memory>
#include <compare>
#include <optional>
#include <vector>
#include <array>

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
    // Exact pinned compositor facts; wlr's 24.8 projection alone cannot prove
    // an arbitrary thousandth scale. The independent projection is retained.
    quint32 scaleMilli = 0, scaleFloatBits = 0;
    // Historical native comparison metadata. Hashes are not authenticated
    // continuity across replacement, permits or current recovery authority.
    bool linuraOwned = false;
    QString baseRuleDigest{}, outputIdentityDigest{}, ownedTarget{};
    std::array<quint32, 3> kernelDrm{};
    // Root-only prepared observation data. Ordinary encode() never publishes
    // this preimage. It is not a selector, current proof or restoration permit.
    QString baseRulePreimage{};
    bool operator==(const NativeDisplayHead &) const = default;
};

struct NativeDisplaySnapshot final
{
    quint64 generation = 0;
    std::vector<NativeDisplayHead> heads;
    [[nodiscard]] QString encode() const;
    [[nodiscard]] QString recoveryPreimage() const;
    // Original canonical baseline comparison; never an execution credential.
    [[nodiscard]] std::optional<QString> baselineGuard(const QString &baseline) const;
    bool operator==(const NativeDisplaySnapshot &) const = default;
};

// Owner-local surface evidence, collected only from the owned Wayland lock
// resources. Compositor safety-fence bits never supply this projection.
struct NativeLockOutputCoverage final
{
    QString outputName;
    bool covered = false;
};
[[nodiscard]] std::optional<NativeDisplaySnapshot>
projectOwnerDisplayCoverage(NativeDisplaySnapshot, const std::vector<NativeLockOutputCoverage> &);

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
