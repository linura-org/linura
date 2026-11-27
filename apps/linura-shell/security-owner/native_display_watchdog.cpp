#include "native_display_watchdog.h"

#include <QDateTime>
#include <limits>
#include <time.h>
#include <utility>

namespace Linura::SecurityOwner {
std::optional<NativeDisplayClock> NativeDisplayClock::sample()
{
    timespec boot{};
    const auto wall = QDateTime::currentMSecsSinceEpoch();
    if (wall <= 0 || clock_gettime(CLOCK_BOOTTIME, &boot) != 0 || boot.tv_sec < 0 ||
        boot.tv_nsec < 0 || boot.tv_nsec >= 1'000'000'000 ||
        static_cast<quint64>(boot.tv_sec) > (std::numeric_limits<quint64>::max() - 999U) / 1000U)
        return std::nullopt;
    return NativeDisplayClock{static_cast<quint64>(wall),
                              static_cast<quint64>(boot.tv_sec) * 1000U +
                                  static_cast<quint64>(boot.tv_nsec) / 1'000'000U};
}
NativeDisplayWatchdog::NativeDisplayWatchdog(NativeDisplayAttempt &attempt, Clock clock,
                                             Probe probe, Restore restore)
    : attempt_(attempt), clock_(std::move(clock)), probe_(std::move(probe)),
      restore_(std::move(restore))
{
    timer_.setTimerType(Qt::PreciseTimer);
    timer_.setInterval(50);
    connect(&timer_, &QTimer::timeout, this, [this] { tick(); });
}
NativeDisplayWatchdog::~NativeDisplayWatchdog()
{
    // Normal teardown must not silently remove an armed recovery timer.
    // SIGKILL/compositor loss is deliberately not represented as restoration.
    restoreNow();
}
bool NativeDisplayWatchdog::start()
{
    if (timer_.isActive() || !clock_ || !probe_ || !restore_ ||
        (attempt_.state() != NativeDisplayAttempt::State::Armed &&
         attempt_.state() != NativeDisplayAttempt::State::Pending))
        return false;
    timer_.start();
    tick(); // Expiry/clock failure before first dispatch also fails closed.
    return timer_.isActive();
}
void NativeDisplayWatchdog::tick()
{
    if (!attempt_.fenced()) {
        timer_.stop();
        return;
    }
    try {
        const auto clock = clock_();
        if (!clock || attempt_.recoveryDue(clock->unixMs, clock->bootMs))
            restoreNow();
    } catch (...) {
        // Native callbacks must not unwind through Qt's event dispatcher.
        restoreNow();
    }
}
void NativeDisplayWatchdog::restoreNow()
{
    timer_.stop();
    if (attempt_.state() != NativeDisplayAttempt::State::Armed &&
        attempt_.state() != NativeDisplayAttempt::State::Pending)
        return;
    try {
        const auto context = probe_ ? probe_() : std::nullopt;
        if (!context || !attempt_.beginRestore(context->snapshot, context->topology, context->lock,
                                               context->secure)) {
            attempt_.recoveryFailed();
            return;
        }
        // beginRestore reserves the sole compensation BEFORE any native write
        // construction. A failure/lost acknowledgement can never retry it.
        if (!restore_ || !restore_(attempt_.intent().baseline, context->snapshot))
            attempt_.recoveryFailed();
        // Even an acknowledged write remains Restoring until a distinct fresh
        // full-layout/coverage verification completes the native gate.
    } catch (...) {
        attempt_.recoveryFailed();
    }
}
bool NativeDisplayWatchdog::stopAfterVerification()
{
    if (attempt_.fenced())
        return false;
    timer_.stop();
    return true;
}
} // namespace Linura::SecurityOwner
