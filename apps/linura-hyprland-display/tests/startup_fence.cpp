#include "startup_fence.h"

#include <array>
#include <cassert>

using namespace Linura::HyprlandDisplay;

namespace {
CurrentLifetimeChain::Token token()
{
    return std::make_shared<unsigned char>(0);
}

void repeatedCurrentLifetimes()
{
    // This is comparison-state coverage, not an authenticated Root grant or
    // compositor qualification. Every production call remains private to a
    // real grant in StartupFence, with kernel peer and full protocol checks.
    CurrentLifetimeChain chain;
    assert(!chain.attempted() && !chain.available());
    auto owner = token();
    bool obsoleteScene = true;
    assert(chain.admitInitial(owner, [&] { return obsoleteScene; }));
    assert(!chain.admitInitial(token(), [] { return true; }));
    for (unsigned cycle = 0; cycle < 8; ++cycle) {
        const auto foreign = token();
        assert(!chain.markRetired(foreign, [] { return true; }));
        assert(!chain.transfer(owner, token(), [] { return true; }));
        assert(!chain.retired());
        assert(chain.markRetired(owner, [] { return true; }));
        assert(chain.retired());
        assert(!chain.markRetired(owner, [] { return true; }));
        const auto next = token();
        const auto transfer = token();
        assert(!chain.transfer(foreign, transfer, [] { return true; }));
        // An equal pointer with another ownership identity is not this grant.
        const CurrentLifetimeChain::Token alias(owner.get(), [](void *) {});
        assert(!chain.transfer(alias, transfer, [] { return true; }));
        obsoleteScene = false; // The actual predecessor scene was moved.
        assert(chain.transfer(owner, transfer, [] { return true; }));
        assert(chain.available() && !chain.retired());
        assert(!chain.transfer(owner, token(), [] { return true; }));
        assert(!chain.admitInitial(next, [] { return true; }));
        assert(!chain.admitSuccessor(foreign, next, [] { return true; }));
        const CurrentLifetimeChain::Token aliasTransfer(transfer.get(), [](void *) {});
        assert(!chain.admitSuccessor(aliasTransfer, next, [] { return true; }));
        assert(chain.admitSuccessor(transfer, next, [] { return true; }));
        assert(!chain.admitSuccessor(transfer, token(), [] { return true; }));
        assert(!chain.markRetired(owner, [] { return true; }));
        owner = next; // Old comparison objects are not the new lifetime.
        assert(chain.available());
    }
    owner.reset();
    assert(!chain.available());
    assert(!chain.admitInitial(token(), [] { return true; }));
}

void lostCurrentLifetimesStayLost()
{
    for (unsigned fault = 0; fault < 11; ++fault) {
        CurrentLifetimeChain chain;
        auto owner = token();
        auto transfer = token();
        auto next = token();
        bool alive = true;
        bool retiredAlive = true;
        assert(chain.admitInitial(owner, [] { return true; }));
        assert(chain.markRetired(owner, [&] { return retiredAlive; }));
        if (fault == 0) {
            assert(!chain.transfer(owner, {}, [] { return true; }));
        } else if (fault == 1) {
            assert(!chain.transfer(owner, transfer, [] { return false; }));
        } else if (fault == 2) {
            assert(!chain.transfer(owner, transfer, []() -> bool { throw 1; }));
        } else if (fault < 6) {
            assert(chain.transfer(owner, transfer, [&] { return alive; }));
            if (fault == 3)
                transfer.reset();
            else if (fault == 4)
                owner.reset();
            else
                alive = false;
            assert(!chain.available());
        } else if (fault == 6) {
            retiredAlive = false;
            assert(!chain.transfer(owner, transfer, [] { return true; }));
        } else {
            assert(chain.transfer(owner, transfer, [] { return true; }));
            if (fault == 7)
                assert(!chain.admitSuccessor(transfer, owner, [] { return true; }));
            else if (fault == 8)
                assert(!chain.admitSuccessor(transfer, next, [] { return false; }));
            else if (fault == 9)
                assert(!chain.admitSuccessor(transfer, next, []() -> bool { throw 1; }));
            else
                assert(!chain.admitSuccessor(transfer, transfer, [] { return true; }));
        }
        alive = true;
        retiredAlive = true;
        assert(!chain.available());
        assert(!chain.admitSuccessor(transfer, next, [] { return true; }));
        assert(!chain.admitInitial(next, [] { return true; }));
    }
    CurrentLifetimeChain initial;
    assert(!initial.admitInitial({}, [] { return true; }));
    assert(!initial.admitInitial(token(), [] { return true; }));
    for (const bool throws : {false, true}) {
        CurrentLifetimeChain failed;
        const auto owner = token();
        assert(!failed.admitInitial(owner, [&]() -> bool {
            if (throws)
                throw 1;
            return false;
        }));
        assert(!failed.admitInitial(owner, [] { return true; }));
    }
    CurrentLifetimeChain retired;
    const auto owner = token();
    bool retiredAlive = true;
    assert(retired.admitInitial(owner, [] { return true; }));
    assert(retired.markRetired(owner, [&] { return retiredAlive; }));
    retiredAlive = false;
    assert(!retired.retired());
    retiredAlive = true;
    assert(!retired.available());
    for (const bool throws : {false, true}) {
        CurrentLifetimeChain chain;
        const auto owner = token();
        bool alive = true;
        assert(chain.admitInitial(owner, [&] {
            if (throws && !alive)
                throw 1;
            return alive;
        }));
        alive = false;
        assert(!chain.available());
        alive = true;
        assert(!chain.available());
    }
}
} // namespace

int main()
{
    repeatedCurrentLifetimes();
    lostCurrentLifetimesStayLost();
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
