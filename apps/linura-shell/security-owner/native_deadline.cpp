#include "native_deadline.h"

#include <string_view>
#include <sys/socket.h>
#include <unistd.h>

namespace Linura::SecurityOwner {

namespace {
constexpr std::string_view timeoutDiagnostic(NativeDeadline::Stage stage) noexcept
{
    using Stage = NativeDeadline::Stage;
    switch (stage) {
    case Stage::BusAuthentication:
        return "native-owner-timeout stage=bus-authentication\n";
    case Stage::RuntimeInitialization:
        return "native-owner-timeout stage=runtime-initialization\n";
    case Stage::ApprovalArm:
        return "native-owner-timeout stage=approval-arm\n";
    case Stage::SleepEntry:
        return "native-owner-timeout stage=sleep-entry\n";
    case Stage::SleepRecovery:
        return "native-owner-timeout stage=sleep-recovery\n";
    case Stage::PowerPermission:
        return "native-owner-timeout stage=power-permission\n";
    case Stage::WaylandInitialization:
        return "native-owner-timeout stage=wayland-initialization\n";
    case Stage::WaylandPump:
        return "native-owner-timeout stage=wayland-pump\n";
    case Stage::WaylandRepaint:
        return "native-owner-timeout stage=wayland-repaint\n";
    case Stage::LockAcquisition:
        return "native-owner-timeout stage=lock-acquisition\n";
    case Stage::LockRelease:
        return "native-owner-timeout stage=lock-release\n";
    case Stage::AssistiveCallback:
        return "native-owner-timeout stage=assistive-callback\n";
    case Stage::Unclassified:
        break;
    }
    return "native-owner-timeout stage=unclassified\n";
}
} // namespace

NativeDeadline::NativeDeadline(std::chrono::milliseconds duration, Stage stage)
    : worker_([this, duration, stage] {
          std::unique_lock lock(mutex_);
          if (duration <= std::chrono::milliseconds::zero() ||
              !condition_.wait_for(lock, duration, [this] { return done_; })) {
              // systemd's stderr journal stream is a socket. One nonblocking,
              // allocation-free attempt only: full/closed/non-socket stderr
              // cannot postpone the original exit or trigger cleanup/retries.
              const auto diagnostic = timeoutDiagnostic(stage);
              const auto written = ::send(STDERR_FILENO, diagnostic.data(), diagnostic.size(),
                                          MSG_DONTWAIT | MSG_NOSIGNAL);
              (void)written;
              _exit(NativeBoundaryTimeoutExit);
          }
      })
{}

NativeDeadline::~NativeDeadline()
{
    {
        std::lock_guard lock(mutex_);
        done_ = true;
    }
    condition_.notify_one();
    worker_.join();
}

} // namespace Linura::SecurityOwner
