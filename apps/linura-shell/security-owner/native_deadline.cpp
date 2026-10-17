#include "native_deadline.h"

#include <unistd.h>

namespace Linura::SecurityOwner {

NativeDeadline::NativeDeadline(std::chrono::milliseconds duration)
    : worker_([this, duration] {
          std::unique_lock lock(mutex_);
          if (duration <= std::chrono::milliseconds::zero() ||
              !condition_.wait_for(lock, duration, [this] { return done_; }))
              _exit(NativeBoundaryTimeoutExit);
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
