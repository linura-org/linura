#pragma once

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace Linura::SecurityOwner {

// Native libraries with no cancellation hook cannot leave a security owner
// indefinitely wedged. Expiry terminates this invocation without QObject/Wayland
// cleanup (and therefore without unlock-and-destroy). The compositor's native
// crash behavior is separately qualified; no mutation success is synthesized.
class NativeDeadline final
{
  public:
    enum class Stage {
        Unclassified,
        BusAuthentication,
        RuntimeInitialization,
        ApprovalArm,
        DisplayDispatch,
        SleepEntry,
        SleepRecovery,
        PowerPermission,
        WaylandInitialization,
        WaylandPump,
        WaylandRepaint,
        LockAcquisition,
        LockRelease,
        AssistiveCallback
    };
    explicit NativeDeadline(std::chrono::milliseconds duration, Stage stage = Stage::Unclassified);
    ~NativeDeadline();
    NativeDeadline(const NativeDeadline &) = delete;
    NativeDeadline &operator=(const NativeDeadline &) = delete;

    static constexpr int NativeBoundaryTimeoutExit = 71;

  private:
    std::mutex mutex_;
    std::condition_variable condition_;
    bool done_ = false;
    std::thread worker_;
};

} // namespace Linura::SecurityOwner
