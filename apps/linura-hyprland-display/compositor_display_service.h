#pragma once

#include "display_transaction.h"

#include <map>
#include <memory>
#include <optional>
#include <set>

struct wl_event_loop;
struct wl_event_source;

namespace Linura::HyprlandDisplay {

[[nodiscard]] std::optional<ClockSample> compositorClock();

// Compositor-owned supervisor. The timer and retained reservations outlive
// protocol resources and their clients. Admission by the private native endpoint
// is separate; none of these correlation values are execution credentials.
class CompositorDisplayService final
{
  public:
    enum class Phase {
        RejectedBeforeDispatch,
        Pending,
        Restoring,
        Confirmed,
        Restored,
        RecoveryFailed
    };
    enum class Begin { Rejected, Started, Existing };
    static constexpr std::size_t MaxReservations = 256;
    CompositorDisplayService(wl_event_loop &, Backend &);
    ~CompositorDisplayService();
    CompositorDisplayService(const CompositorDisplayService &) = delete;
    CompositorDisplayService &operator=(const CompositorDisplayService &) = delete;

    [[nodiscard]] Begin begin(const Correlation &, const Layout &baseline, const Layout &desired,
                              const Snapshot &capturedSnapshot, ClockSample captured,
                              std::shared_ptr<MutationProtection>);
    [[nodiscard]] std::optional<Phase> status(const Correlation &) const;
    [[nodiscard]] bool confirm(const Correlation &);
    [[nodiscard]] bool restore(const Correlation &);
    [[nodiscard]] bool fenced() const noexcept;

  private:
    struct Reservation final
    {
        Correlation bound;
        Layout baseline, desired;
        Phase phase = Phase::Pending;
    };
    static int onTimer(int descriptor, std::uint32_t events, void *data) noexcept;
    [[nodiscard]] bool armTimer();
    void tick() noexcept;
    void recordPhase();
    Backend &backend_;
    wl_event_loop &loop_;
    int timer_ = -1;
    wl_event_source *source_ = nullptr;
    std::map<std::string, Reservation> reservations_;
    std::set<std::string> dispatches_;
    std::unique_ptr<DisplayTransaction> active_;
    bool starting_ = false;
};

} // namespace Linura::HyprlandDisplay
