#pragma once

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>

namespace Linura::HyprlandDisplay {

// Local liveness of the opaque FIFO received from the attested logind owner.
// A descriptor number alone survives peer loss. No polling wait, read, write,
// reacquisition, authority grant or retry is performed by this predicate.
[[nodiscard]] inline bool nativeInhibitorFdAlive(int descriptor) noexcept
{
    struct stat metadata
    {};
    if (descriptor < 0 || fstat(descriptor, &metadata) != 0 || !S_ISFIFO(metadata.st_mode))
        return false;
    const int flags = fcntl(descriptor, F_GETFD);
    if (flags < 0 || (flags & FD_CLOEXEC) == 0)
        return false;
    pollfd observed{descriptor, POLLIN, 0};
    // POLLHUP/POLLERR/POLLNVAL are returned even when not requested. Unexpected
    // input is also unsupported: this is an inhibition handle, not a data pipe.
    return poll(&observed, 1, 0) == 0 && observed.revents == 0;
}

// Loss is terminal for this lease. Reopening a FIFO's peer must not revive the
// original logind lifetime or release deferred native output state. Only closing
// the lease can retire it; callers retain failed recovery until verified safe.
class NativeInhibitorFd final
{
  public:
    NativeInhibitorFd() = default;
    ~NativeInhibitorFd()
    {
        release();
    }
    NativeInhibitorFd(const NativeInhibitorFd &) = delete;
    NativeInhibitorFd &operator=(const NativeInhibitorFd &) = delete;
    [[nodiscard]] bool retain(int descriptor) noexcept
    {
        if (descriptor < 0 || retained())
            return false; // Ownership transfers only on success.
        descriptor_ = descriptor;
        lost_ = false;
        return true;
    }
    [[nodiscard]] bool retained() const noexcept
    {
        return descriptor_ >= 0;
    }
    [[nodiscard]] bool held() const noexcept
    {
        if (!retained() || lost_)
            return false;
        if (!nativeInhibitorFdAlive(descriptor_))
            lost_ = true;
        return !lost_;
    }
    void release() noexcept
    {
        if (descriptor_ >= 0)
            close(descriptor_);
        descriptor_ = -1;
        lost_ = false;
    }

  private:
    int descriptor_ = -1;
    mutable bool lost_ = false;
};

} // namespace Linura::HyprlandDisplay
