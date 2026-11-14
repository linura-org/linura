#pragma once

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <functional>

namespace Linura::HyprlandDisplay {
class OriginalCompletionGrant;

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
        return guardAlive() && (ordinary_ || currentAvailable());
    }
    [[nodiscard]] bool recoveryAvailable() const noexcept
    {
        return !ordinary_ && !currentAttempted_ && guardAlive();
    }
    // Admission of this SAME invocation only, under the live transferred Root
    // lifetime. Root's separate global barrier for future startups stays held.
    [[nodiscard]] bool currentAvailable() const noexcept
    {
        return currentAttempted_ && guardAlive() && currentAlive_ && currentAlive_();
    }
    // Private kernel-peer comparison only, never restoration permission. The
    // caller must separately consume the exact fresh protected Recovery scope,
    // prepared binding and complete one-use grant. A replacement root service
    // or root-looking file cannot replace the continuously retained lease.
    [[nodiscard]] bool authenticatesGrantPeer(int descriptor) const noexcept
    {
        return !ordinary_ && authenticatesPeer(descriptor);
    }
    // Separate peer comparison for the same-invocation ordinary-release
    // purpose. This does not admit original restoration or grant an effect.
    [[nodiscard]] bool authenticatesOrdinaryGrantPeer(int descriptor) const noexcept
    {
        return (ordinary_ || currentAttempted_) && authenticatesPeer(descriptor);
    }

  private:
    [[nodiscard]] bool authenticatesPeer(int descriptor) const noexcept
    {
        if (!guardAlive() || descriptor < 0 || fcntl(descriptor, F_GETFD) != FD_CLOEXEC)
            return false;
        int type = 0, domain = 0;
        socklen_t size = sizeof(type);
        if (getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &type, &size) != 0 ||
            size != sizeof(type) || type != SOCK_STREAM)
            return false;
        size = sizeof(domain);
        if (getsockopt(descriptor, SOL_SOCKET, SO_DOMAIN, &domain, &size) != 0 ||
            size != sizeof(domain) || domain != AF_UNIX)
            return false;
        ucred original{}, grant{};
        size = sizeof(original);
        if (getsockopt(descriptor_, SOL_SOCKET, SO_PEERCRED, &original, &size) != 0 ||
            size != sizeof(original))
            return false;
        size = sizeof(grant);
        return getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &grant, &size) == 0 &&
               size == sizeof(grant) && original.uid == 0 && original.gid == 0 &&
               original.pid > 0 && grant.uid == original.uid && grant.gid == original.gid &&
               grant.pid == original.pid && guardAlive();
    }

  public:
    // Private read-only protocol state: unadmitted, ordinary, recovery fenced,
    // or lost/invalid. Lost admission is terminal for this invocation.
    [[nodiscard]] unsigned phase() const noexcept
    {
        if (!attempted_)
            return 0;
        if (!guardAlive())
            return 3U;
        if (ordinary_)
            return 1U;
        if (currentAttempted_) {
            if (!currentAvailable())
                return 3U;
            if (retiredAlive_)
                return retiredAlive_() ? 5U : 3U;
            return 4U;
        }
        return 2U;
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
    friend class OriginalCompletionGrant;
    // A read-only phase selected only by the actual authenticated final Root
    // spend. Signed Committed and a current lifetime alone remain phase four.
    [[nodiscard]] bool markCurrentRetired(std::function<bool()> alive)
    {
        if (retiredAlive_ || !currentAvailable() || !alive || !alive())
            return false;
        retiredAlive_ = std::move(alive);
        return true;
    }
    // Only the authenticated, non-cloneable completion grant can publish a
    // current lifetime. Unknown loss never falls back into recovery admission.
    [[nodiscard]] bool admitCurrent(std::function<bool()> alive)
    {
        if (ordinary_ || currentAttempted_ || !guardAlive())
            return false;
        currentAttempted_ = true;
        if (!alive || !alive())
            return false;
        currentAlive_ = std::move(alive);
        return currentAvailable();
    }
    // Only the genuine original completion grant may replace this invocation's
    // current callback, after its separately authenticated successor spend. The
    // original startup descriptor and global exclusion are never reopened.
    [[nodiscard]] bool transferCurrent(std::function<bool()> alive)
    {
        if (ordinary_ || !currentAttempted_ || successorAttempted_ || !guardAlive())
            return false;
        successorAttempted_ = true;
        if (!alive || !alive()) {
            lost_ = true;
            return false;
        }
        currentAlive_ = std::move(alive);
        retiredAlive_ = {}; // The successor is protected/pending, not released.
        return currentAvailable();
    }
    int descriptor_ = -1;
    bool attempted_ = false, ordinary_ = false;
    bool currentAttempted_ = false;
    bool successorAttempted_ = false;
    std::function<bool()> currentAlive_;
    std::function<bool()> retiredAlive_;
    mutable bool lost_ = false;
};

} // namespace Linura::HyprlandDisplay
