#pragma once

#include "native_launch.h"
#include "native_scope.h"

namespace Linura::SecurityOwner {

struct NativeSleepEntryIdentity final
{
    QString resource, boot, invocation;
    [[nodiscard]] static std::optional<NativeSleepEntryIdentity> parse(const QString &resource);
    bool operator==(const NativeSleepEntryIdentity &) const = default;
};

// Adapter-private facts acquired afresh from the authenticated unique root
// systemd owner. Never deserialize these from a Linura client or QML surface.
struct NativeSleepUnitFacts final
{
    QString supervisor, invocation, activeState, subState;
    quint32 controlPid = 0, mainPid = 0, job = 0;
    NativeLaunchFacts helper, main;
    // Only an authenticated, twice-read NoSuchUnit from the SAME supervisor.
    // Unit GC is not a timeout and cannot erase a running/queued unit.
    bool absent = false;
    bool operator==(const NativeSleepUnitFacts &) const = default;
};

// Coverage only: this cannot lock, authenticate, prepare, dispatch or permit
// sleep. A native job can remain queued after an unrelated kernel suspend;
// therefore neither elapsed time nor the kernel counter alone retires it.
class NativeSleepFence final
{
  public:
    [[nodiscard]] bool active() const noexcept
    {
        return pending_.has_value();
    }
    [[nodiscard]] std::optional<quint64> baselineCycles() const noexcept
    {
        return pending_ ? std::optional<quint64>(pending_->cycles) : std::nullopt;
    }
    [[nodiscard]] bool arm(const NativeSleepEntryIdentity &event, const NativeLockIdentity &current,
                           bool independentlySecure, std::optional<quint64> cycles,
                           const NativeSleepUnitFacts &facts);
    [[nodiscard]] bool retire(const NativeLockIdentity &current, bool independentlySecure,
                              std::optional<quint64> cycles, const NativeSleepUnitFacts &facts);

  private:
    struct Pending final
    {
        NativeSleepEntryIdentity event;
        NativeLockIdentity lock;
        quint64 cycles = 0;
        QString supervisor;
        quint32 helperPid = 0, job = 0;
        quint64 helperStartedReal = 0, helperStartedMonotonic = 0;
    };
    std::optional<Pending> pending_;
};

} // namespace Linura::SecurityOwner
