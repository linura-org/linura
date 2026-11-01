#include "compositor_display_service.h"

#include <cerrno>
#include <limits>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
#include <wayland-server-core.h>

namespace Linura::HyprlandDisplay {
namespace {
std::optional<std::uint64_t> milliseconds(clockid_t clock)
{
    timespec value{};
    if (clock_gettime(clock, &value) != 0 || value.tv_sec < 0 || value.tv_nsec < 0 ||
        value.tv_nsec >= 1'000'000'000 ||
        static_cast<std::uint64_t>(value.tv_sec) >
            (std::numeric_limits<std::uint64_t>::max() - 999U) / 1000U)
        return std::nullopt;
    return static_cast<std::uint64_t>(value.tv_sec) * 1000U +
           static_cast<std::uint64_t>(value.tv_nsec) / 1'000'000U;
}
CompositorDisplayService::Phase phaseOf(DisplayTransaction::Phase phase)
{
    using Phase = CompositorDisplayService::Phase;
    switch (phase) {
    case DisplayTransaction::Phase::Pending:
        return Phase::Pending;
    case DisplayTransaction::Phase::Restoring:
        return Phase::Restoring;
    case DisplayTransaction::Phase::Confirmed:
        return Phase::Confirmed;
    case DisplayTransaction::Phase::Restored:
        return Phase::Restored;
    case DisplayTransaction::Phase::RecoveryFailed:
        return Phase::RecoveryFailed;
    }
    return Phase::RecoveryFailed;
}
} // namespace

std::optional<ClockSample> compositorClock()
{
    const auto wall = milliseconds(CLOCK_REALTIME), boot = milliseconds(CLOCK_BOOTTIME);
    if (!wall || !boot || *wall == 0 || *boot == 0)
        return std::nullopt;
    return ClockSample{*wall, *boot};
}
CompositorDisplayService::CompositorDisplayService(wl_event_loop &loop, Backend &backend)
    : backend_(backend), loop_(loop)
{
    timer_ = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
    if (timer_ >= 0)
        source_ = wl_event_loop_add_fd(&loop_, timer_, WL_EVENT_READABLE, onTimer, this);
}
CompositorDisplayService::~CompositorDisplayService()
{
    // The attempt's destructor reserves compensation before the independent
    // timer is removed. This cannot promise recovery after compositor SIGKILL.
    active_.reset();
    if (source_)
        wl_event_source_remove(source_);
    if (timer_ >= 0)
        close(timer_);
}
bool CompositorDisplayService::armTimer()
{
    if (!source_ || timer_ < 0)
        return false;
    itimerspec interval{};
    interval.it_value.tv_nsec = 50'000'000;
    interval.it_interval.tv_nsec = 50'000'000;
    // CLOCK_BOOTTIME advances during suspend; a disconnected or killed client
    // cannot reset, cancel or extend this compositor-owned periodic timer.
    return timerfd_settime(timer_, 0, &interval, nullptr) == 0;
}
CompositorDisplayService::Begin
CompositorDisplayService::begin(const Correlation &correlation, const Layout &baseline,
                                const Layout &desired, const Snapshot &capturedSnapshot,
                                ClockSample captured,
                                std::shared_ptr<MutationProtection> protection)
{
    const auto retained = reservations_.find(correlation.transaction);
    if (retained != reservations_.end()) {
        return retained->second.bound == correlation && retained->second.baseline == baseline &&
                       retained->second.desired == desired
                   ? Begin::Existing
                   : Begin::Rejected;
    }
    if (!protection || fenced() || dispatches_.contains(correlation.dispatchDigest) ||
        reservations_.size() >= MaxReservations || correlation.transaction.size() > 256 ||
        correlation.effectDigest.size() > 64 || correlation.dispatchDigest.size() > 64 ||
        baseline.size() > DisplayTransaction::MaxHeads ||
        desired.size() > DisplayTransaction::MaxHeads)
        return Begin::Rejected;
    const auto now = compositorClock();
    if (!now || captured.unixMs == 0 || captured.bootMs == 0 || now->unixMs < captured.unixMs ||
        now->bootMs < captured.bootMs || now->unixMs - captured.unixMs >= 2000 ||
        now->bootMs - captured.bootMs >= 2000 || !armTimer())
        return Begin::Rejected;
    // Retain the dispatch tombstone and full bounded typed material BEFORE any
    // potentially effectful call. Duplicate starts query this reservation and
    // can never recreate an attempt, including after a native rejection.
    const auto entry = reservations_.emplace(
        correlation.transaction, Reservation{correlation, baseline, desired, Phase::Pending});
    dispatches_.insert(correlation.dispatchDigest);
    // start() invokes native inhibition/modeset callbacks before returning its
    // transaction object. Publish exclusion BEFORE entering those callbacks,
    // not only after active_ has received the completed handoff.
    starting_ = true;
    struct StartingFence final
    {
        bool &active;
        ~StartingFence()
        {
            active = false;
        }
    } startingFence{starting_};
    active_ = DisplayTransaction::start(backend_, correlation, baseline, desired, capturedSnapshot,
                                        captured, std::move(protection));
    if (!active_) {
        entry.first->second.phase = Phase::RejectedBeforeDispatch;
        return Begin::Rejected;
    }
    recordPhase();
    return Begin::Started;
}
std::optional<CompositorDisplayService::Phase>
CompositorDisplayService::status(const Correlation &correlation) const
{
    const auto retained = reservations_.find(correlation.transaction);
    if (retained == reservations_.end() || retained->second.bound != correlation)
        return std::nullopt;
    return retained->second.phase;
}
bool CompositorDisplayService::confirm(const Correlation &correlation)
{
    const auto now = compositorClock();
    if (!active_ || !now || !active_->confirm(correlation, *now))
        return false;
    recordPhase();
    return true;
}
bool CompositorDisplayService::restore(const Correlation &correlation)
{
    const auto now = compositorClock();
    if (!active_ || !now || !active_->requestRestore(correlation, *now))
        return false;
    recordPhase();
    return true;
}
bool CompositorDisplayService::fenced() const noexcept
{
    return starting_ || (active_ && active_->fenced());
}
void CompositorDisplayService::recordPhase()
{
    if (active_)
        reservations_.at(active_->correlation().transaction).phase = phaseOf(active_->phase());
}
int CompositorDisplayService::onTimer(int descriptor, std::uint32_t events, void *data) noexcept
{
    auto &self = *static_cast<CompositorDisplayService *>(data);
    std::uint64_t expirations = 0;
    const auto bytes = read(descriptor, &expirations, sizeof(expirations));
    if ((events & (WL_EVENT_HANGUP | WL_EVENT_ERROR)) != 0 ||
        bytes != static_cast<ssize_t>(sizeof(expirations))) {
        // A spurious nonblocking wakeup is not a broken timer. Every other
        // failure makes a pending attempt compensate without waiting on a UI.
        if (bytes < 0 && errno == EAGAIN && events == WL_EVENT_READABLE)
            return 0;
        if (self.active_)
            self.active_->restore();
        self.recordPhase();
        return 0;
    }
    self.tick();
    return 0;
}
void CompositorDisplayService::tick() noexcept
{
    if (active_) {
        active_->tick(compositorClock());
        recordPhase();
    }
}
} // namespace Linura::HyprlandDisplay
