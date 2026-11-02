#pragma once

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace Linura::HyprlandDisplay {

// Compositor-thread mechanism only. The native startup adapter authenticates
// the supervised root peer before transferring its original socket here.
// This is neither session-lock state nor authority to restore any output.
class StartupFence final
{
  public:
    StartupFence() = default;
    ~StartupFence()
    {
        if (descriptor_ >= 0)
            close(descriptor_);
    }
    StartupFence(const StartupFence &) = delete;
    StartupFence &operator=(const StartupFence &) = delete;

    // Ownership transfers only on success. Exactly one startup admission per
    // actual invocation: no reconnect, second grant or repair after loss.
    [[nodiscard]] bool retain(int descriptor, bool ordinaryAllowed) noexcept
    {
        if (attempted_)
            return false;
        attempted_ = true;
        int type = 0, domain = 0;
        socklen_t size = sizeof(type);
        if (descriptor < 0 || fcntl(descriptor, F_GETFD) != FD_CLOEXEC ||
            getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &type, &size) != 0 ||
            size != sizeof(type) || type != SOCK_STREAM)
            return false;
        size = sizeof(domain);
        if (getsockopt(descriptor, SOL_SOCKET, SO_DOMAIN, &domain, &size) != 0 ||
            size != sizeof(domain) || domain != AF_UNIX)
            return false;
        descriptor_ = descriptor;
        ordinary_ = ordinaryAllowed;
        return true;
    }
    [[nodiscard]] bool guardAlive() const noexcept
    {
        if (descriptor_ < 0 || lost_)
            return false;
        pollfd event{descriptor_, POLLIN, 0};
        // No protocol bytes are accepted on the lease. Data, EOF, HUP, errors
        // and interrupted/unknown poll results permanently poison admission.
        if (poll(&event, 1, 0) != 0)
            lost_ = true;
        return !lost_;
    }
    [[nodiscard]] bool ordinaryAllowed() const noexcept
    {
        return guardAlive() && ordinary_;
    }
    // Private read-only protocol state: unadmitted, ordinary, recovery fenced,
    // or lost/invalid. Lost admission is terminal for this invocation.
    [[nodiscard]] unsigned phase() const noexcept
    {
        if (!attempted_)
            return 0;
        return !guardAlive() ? 3U : ordinary_ ? 1U : 2U;
    }
    [[nodiscard]] int descriptor() const noexcept
    {
        return descriptor_;
    }
    void invalidate() noexcept
    {
        lost_ = true;
    }

  private:
    int descriptor_ = -1;
    bool attempted_ = false, ordinary_ = false;
    mutable bool lost_ = false;
};

} // namespace Linura::HyprlandDisplay
