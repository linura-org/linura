#pragma once

#include "native_display_attempt.h"
#include <QObject>
#include <QTimer>
#include <functional>

namespace Linura::SecurityOwner {

struct NativeDisplayRecoveryContext final
{
    NativeDisplaySnapshot snapshot;
    QString topology;
    NativeLockIdentity lock;
    bool secure = false;
};
struct NativeDisplayClock final
{
    quint64 unixMs = 0, bootMs = 0;
    [[nodiscard]] static std::optional<NativeDisplayClock> sample();
};

// Lives in the native security owner, outside QML and Control's lifetime. It
// restores only the already retained baseline, once, after fresh native scope
// checks. Durable admission/restart reconciliation belongs to Control; this
// timer alone is NOT a process-crash durability guarantee or success evidence.
class NativeDisplayWatchdog final : public QObject
{
  public:
    using Clock = std::function<std::optional<NativeDisplayClock>()>;
    using Probe = std::function<std::optional<NativeDisplayRecoveryContext>()>;
    using Restore = std::function<bool(const NativeDisplayLayout &, const NativeDisplaySnapshot &)>;
    NativeDisplayWatchdog(NativeDisplayAttempt &attempt, Clock clock, Probe probe, Restore restore);
    ~NativeDisplayWatchdog() override;
    NativeDisplayWatchdog(const NativeDisplayWatchdog &) = delete;
    NativeDisplayWatchdog &operator=(const NativeDisplayWatchdog &) = delete;
    [[nodiscard]] bool start();
    void restoreNow();
    // Only independent verification can make the native gate terminal. A timer
    // cancellation request or compositor acknowledgement cannot do so.
    [[nodiscard]] bool stopAfterVerification();

  private:
    NativeDisplayAttempt &attempt_;
    Clock clock_;
    Probe probe_;
    Restore restore_;
    QTimer timer_;
    void tick();
};

} // namespace Linura::SecurityOwner
