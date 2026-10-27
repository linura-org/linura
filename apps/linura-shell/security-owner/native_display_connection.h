#pragma once

#include "native_display_layout.h"
#include <memory>

struct wl_display;
struct wl_registry;

namespace Linura::SecurityOwner {

struct NativePinnedDisplaySample final
{
    NativeDisplaySnapshot topology;
    NativeDisplayLayout current;
    QString compositor;
    quint64 securityEpoch = 0, sampledUnixMs = 0, sampledBootMs = 0;
    // Protocol enum: unlocked, secure, transitioning, unknown.
    quint32 coverage = 3;
    bool fenced = true;
};
struct NativeDisplayCorrelation final
{
    QString transaction, effectDigest, dispatchDigest;
    quint64 deadlineUnixMs = 0;
    bool operator==(const NativeDisplayCorrelation &) const = default;
};

// Adapter-private client on the security owner's SAME exclusive, attested
// connection. Live build identity is mandatory. No pathname reconnect, policy,
// principal selection, approval or retry lives here. The runtime alone admits
// an already prepared executor and retains its immutable correlation.
class NativeDisplayConnection final
{
  public:
    explicit NativeDisplayConnection(wl_display *ownedConnection);
    ~NativeDisplayConnection();
    NativeDisplayConnection(const NativeDisplayConnection &) = delete;
    NativeDisplayConnection &operator=(const NativeDisplayConnection &) = delete;
    void announce(wl_registry *, quint32 name, quint32 version);
    void removed(quint32 name);
    [[nodiscard]] bool advertised() const noexcept;
    [[nodiscard]] std::optional<NativePinnedDisplaySample> sample();
    // Must immediately follow a fresh sample from this object. Its immutable
    // native snapshot and all heads stay alive through the one-use wire apply.
    [[nodiscard]] std::optional<quint32> apply(const NativeDisplayCorrelation &,
                                               const NativeDisplayLayout &baseline,
                                               const NativeDisplayLayout &desired);
    // Reconnection can observe a reservation, never acquire its continuation.
    [[nodiscard]] std::optional<quint32> status(const NativeDisplayCorrelation &);
    [[nodiscard]] std::optional<quint32> decide(const NativeDisplayCorrelation &, bool confirm);

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace Linura::SecurityOwner
