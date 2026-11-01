#pragma once

#include "native_display_layout.h"
#include <memory>

struct wl_display;
struct wl_registry;
struct linura_protected_display_interaction_v1;

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
    [[nodiscard]] bool valid() const;
    [[nodiscard]] bool dispatchWindow(quint64 sampledBootMs, quint64 nowBootMs,
                                      quint64 nowUnixMs) const;
    [[nodiscard]] bool decisionWindow(quint64 startedUnixMs, quint64 startedBootMs,
                                      quint64 nowUnixMs, quint64 nowBootMs) const;
    bool operator==(const NativeDisplayCorrelation &) const = default;
};
// Immutable comparison data from the attested Control continuation. Neither
// digest authenticates a caller, supplies human input or grants a new effect.
struct NativeDisplayDecision final
{
    NativeDisplayCorrelation correlation;
    QString decisionDigest, protectedDecisionDigest;
    bool confirm = false;
    [[nodiscard]] bool valid() const;
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
    // Fresh read only. S17 may keep its established behavior if this compositor
    // never advertised S21. Once advertised, unknown/replaced/busy state denies
    // release/power admission; a replacement owner cannot ignore a live attempt.
    [[nodiscard]] bool securityTransitionAllowed(bool currentlySecure);
    // Must immediately follow a fresh sample from this object. Its immutable
    // native snapshot and all heads stay alive through the one-use wire apply.
    [[nodiscard]] std::optional<quint32> apply(const NativeDisplayCorrelation &,
                                               const NativeDisplayLayout &baseline,
                                               const NativeDisplayLayout &desired,
                                               linura_protected_display_interaction_v1 *protection);
    // Reconnection can observe a reservation, never acquire its continuation.
    [[nodiscard]] std::optional<quint32> status(const NativeDisplayCorrelation &);
    [[nodiscard]] std::optional<quint64>
    decisionBootDeadline(const NativeDisplayCorrelation &) const;
    [[nodiscard]] std::optional<quint32> decide(const NativeDisplayCorrelation &, bool confirm);

  private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace Linura::SecurityOwner
