// Component and identity-parser tests only, not authenticated session,
// secure compositor coverage, machine qualification or release evidence.
#include "compositor_probe.h"
#include "lock_mechanism.h"
#include "native_scope.h"
#include "native_wayland_readiness.h"
#include <wayland-client.h>
#include <wayland-server.h>
#include <atomic>
#include <cassert>
#include <chrono>
#include <thread>
#include <sys/socket.h>
#include <unistd.h>

using namespace Linura::SecurityOwner;
using namespace std::chrono_literals;

int main()
{
    // Native adapters must accept the complete canonical session alphabet
    // without permitting ambient aliases, traversal, or ambiguous identity.
    const QString resource =
        QStringLiteral("session:lock:11111111-1111-4111-8111-111111111111:1000:"
                       "seat_0-a:42:22222222-2222-4222-8222-222222222222:1");
    const auto identity = NativeLockIdentity::parse(resource);
    assert(identity && identity->session == QLatin1String("seat_0-a"));
    assert(!NativeLockIdentity::parse(
        QString(resource).replace(QStringLiteral("seat_0-a"), QStringLiteral("seat/0"))));
    assert(!NativeLockIdentity::parse(
        QString(resource).replace(QStringLiteral(":1000:"), QStringLiteral(":01000:"))));
    assert(!NativeLockIdentity::parse(
        QString(resource).replace(QStringLiteral(":1000:"), QStringLiteral(":0:"))));
    assert(!NativeLockIdentity::parse(resource + QStringLiteral(":extra")));
    for (const char *alias : {"self", "auto", "current"}) {
        assert(!NativeLockIdentity::parse(
            QString(resource).replace(QStringLiteral("seat_0-a"), QLatin1String(alias))));
    }

    assert(decodeNativeHyprlandLock("{ \"locked\" : true }") == NativeCompositorLockState::Locked);
    assert(decodeNativeHyprlandLock("{\"locked\":false}") == NativeCompositorLockState::Unlocked);
    assert(!decodeNativeHyprlandLock("{\"locked\":true,\"other\":false}"));
    assert(!decodeNativeHyprlandLock("{\"lo cked\":true}"));
    assert(!decodeNativeHyprlandLock("{\"locked\":true}junk"));

    LockMechanism lock(*identity);
    assert(lock.state() == LockMechanism::State::Ready);
    assert(!lock.dispatch(*identity, false));
    assert(lock.dispatch(*identity, true));
    assert(!lock.dispatch(*identity, true));
    lock.compositorCoverage(true);
    assert(lock.state() == LockMechanism::State::Secure && lock.secureCoverage());
    assert(lock.dispatch(*identity, false));
    assert(!lock.independentlyVerifiedReleased(*identity));
    lock.compositorCoverage(false);
    assert(lock.independentlyVerifiedReleased(*identity));
    assert(lock.commitVerifiedRelease(*identity));
    assert(lock.state() == LockMechanism::State::Ready);
    assert(lock.identity().generation == identity->generation + 1);
    assert(!lock.dispatch(*identity, true));
    lock.ownerLost();
    assert(lock.state() == LockMechanism::State::Faulted);
    assert(!lock.dispatch(lock.identity(), true));

    assert(!waitForNativeWaylandReady(nullptr, 100ms));
    for (bool responsive : {false, true}) {
        int sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
        auto *server = wl_display_create();
        assert(server && wl_client_create(server, sockets[0]));
        auto *client = wl_display_connect_to_fd(sockets[1]);
        assert(client);
        assert(!waitForNativeWaylandReady(client, 0ms));
        assert(!waitForNativeWaylandReady(client, 5001ms));
        std::atomic<bool> stop = false;
        std::thread worker;
        if (responsive) {
            worker = std::thread([&] {
                // The connected socket exists before the server services it.
                // Readiness requires a wire acknowledgment, not socket presence.
                std::this_thread::sleep_for(120ms);
                while (!stop.load()) {
                    assert(wl_event_loop_dispatch(wl_display_get_event_loop(server), 10) >= 0);
                    wl_display_flush_clients(server);
                }
            });
        }
        const auto started = std::chrono::steady_clock::now();
        assert(waitForNativeWaylandReady(client, responsive ? 1000ms : 50ms) == responsive);
        const auto elapsed = std::chrono::steady_clock::now() - started;
        assert(elapsed < 2s);
        if (responsive)
            assert(elapsed >= 100ms);
        else
            assert(elapsed >= 40ms); // A connected silent peer never supplies readiness.
        stop = true;
        if (worker.joinable())
            worker.join();
        wl_display_disconnect(client);
        wl_display_destroy_clients(server);
        wl_display_destroy(server);
    }
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    auto *disconnected = wl_display_connect_to_fd(sockets[1]);
    assert(disconnected);
    assert(close(sockets[0]) == 0);
    assert(!waitForNativeWaylandReady(disconnected, 500ms));
    wl_display_disconnect(disconnected);
}
