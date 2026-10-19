// Official Wayland wire-component evidence only, never native identity,
// authentication, coverage or machine qualification.
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
