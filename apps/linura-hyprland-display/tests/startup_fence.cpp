#include "startup_fence.h"

#include <array>
#include <cassert>

using namespace Linura::HyprlandDisplay;

int main()
{
    StartupFence absent;
    assert(!absent.guardAlive() && !absent.ordinaryAllowed());
    assert(!absent.authenticatesGrantPeer(-1) && !absent.recoveryAvailable());
    for (const bool allowed : {false, true}) {
        std::array<int, 2> pair{};
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair.data()) == 0);
        StartupFence fence;
        assert(fence.retain(pair[0], allowed));
        assert(fence.guardAlive() && fence.ordinaryAllowed() == allowed);
        assert(fence.recoveryAvailable() == !allowed);
        assert(!fence.retain(pair[1], true)); // Cannot replace even a fenced grant.
        assert(close(pair[1]) == 0);
        assert(!fence.guardAlive() && !fence.ordinaryAllowed() && !fence.recoveryAvailable());
        assert(!fence.retain(-1, true));
    }
    std::array<int, 2> pair{};
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair.data()) == 0);
    StartupFence poisoned;
    assert(poisoned.retain(pair[0], true));
    const char byte = 'x';
    assert(write(pair[1], &byte, 1) == 1);
    assert(!poisoned.ordinaryAllowed());
    char consumed = 0;
    assert(read(pair[0], &consumed, 1) == 1 && consumed == byte);
    assert(!poisoned.guardAlive()); // Draining data cannot revive the lease.
    assert(close(pair[1]) == 0);

    for (const int type : {SOCK_STREAM, SOCK_DGRAM}) {
        assert(socketpair(AF_UNIX, type | SOCK_CLOEXEC, 0, pair.data()) == 0);
        if (type == SOCK_STREAM)
            assert(fcntl(pair[0], F_SETFD, 0) == 0);
        StartupFence invalid;
        assert(!invalid.retain(pair[0], true));
        assert(!invalid.guardAlive() && !invalid.ordinaryAllowed());
        assert(fcntl(pair[0], F_SETFD, FD_CLOEXEC) == 0);
        assert(!invalid.retain(pair[0], true)); // Failed first admission is final.
        assert(close(pair[0]) == 0 && close(pair[1]) == 0);
    }
    const int regular = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(regular >= 0);
    StartupFence wrongKind;
    assert(!wrongKind.retain(regular, true));
    assert(close(regular) == 0);

    for (const bool ordinary : {false, true}) {
        std::array<int, 2> lease{}, grant{};
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, lease.data()) == 0);
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, grant.data()) == 0);
        StartupFence source;
        assert(source.retain(lease[0], ordinary));
        // Actual kernel credentials: matching user-created sockets cannot
        // impersonate root. Even root peers cannot authorize ordinary mode.
        const bool rootPeer = getuid() == 0 && getgid() == 0;
        assert(source.authenticatesGrantPeer(grant[0]) == (!ordinary && rootPeer));
        assert(!source.authenticatesGrantPeer(-1));
        assert(fcntl(grant[0], F_SETFD, 0) == 0);
        assert(!source.authenticatesGrantPeer(grant[0]));
        assert(fcntl(grant[0], F_SETFD, FD_CLOEXEC) == 0);
        assert(close(lease[1]) == 0);
        assert(!source.authenticatesGrantPeer(grant[0]));
        assert(close(grant[0]) == 0 && close(grant[1]) == 0);
    }
}
