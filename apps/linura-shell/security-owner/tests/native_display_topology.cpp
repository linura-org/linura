// Real Wayland wire component fixtures. They do not attest a real Hyprland
// session, authorize a display effect or qualify native lock/recovery behavior.
#include "native_display_topology.h"
#include "native_wayland_readiness.h"
#include "wlr-output-management-unstable-v1-server-protocol.h"
#include <wayland-client.h>
#include <wayland-server.h>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>
#include <sys/socket.h>

using namespace Linura::SecurityOwner;
using namespace std::chrono_literals;

namespace {
struct Server final
{
    struct Head
    {
        wl_resource *resource;
        std::vector<wl_resource *> modes;
    };
    wl_display *display = wl_display_create();
    wl_resource *manager = nullptr;
    std::vector<std::unique_ptr<Head>> heads;
    std::atomic<bool> stop = false;
    std::atomic<int> command = 0, completed = 0, effects = 0;
    bool missingMode = false, missingDone = false;
    std::thread worker;

    static void release(wl_client *, wl_resource *resource)
    {
        wl_resource_destroy(resource);
    }
    static void stopManager(wl_client *, wl_resource *resource)
    {
        zwlr_output_manager_v1_send_finished(resource);
        wl_resource_destroy(resource);
    }
    static void configuration(wl_client *, wl_resource *resource, uint32_t, uint32_t)
    {
        ++static_cast<Server *>(wl_resource_get_user_data(resource))->effects;
        assert(false && "observation must never create a configuration");
    }
    void head(wl_client *client, const char *name)
    {
        auto entry = std::make_unique<Head>();
        entry->resource = wl_resource_create(client, &zwlr_output_head_v1_interface, 4, 0);
        assert(entry->resource);
        static const struct zwlr_output_head_v1_interface requests
        {
            release
        };
        wl_resource_set_implementation(entry->resource, &requests, nullptr, nullptr);
        zwlr_output_manager_v1_send_head(manager, entry->resource);
        zwlr_output_head_v1_send_name(entry->resource, name);
        zwlr_output_head_v1_send_enabled(entry->resource, 1);
        zwlr_output_head_v1_send_position(entry->resource, 0, 0);
        zwlr_output_head_v1_send_transform(entry->resource, 0);
        zwlr_output_head_v1_send_scale(entry->resource, 256);
        for (int width : {1920, 1280}) {
            auto *mode = wl_resource_create(client, &zwlr_output_mode_v1_interface, 3, 0);
            assert(mode);
            static const struct zwlr_output_mode_v1_interface modeRequests
            {
                release
            };
            wl_resource_set_implementation(mode, &modeRequests, nullptr, nullptr);
            entry->modes.push_back(mode);
            zwlr_output_head_v1_send_mode(entry->resource, mode);
            if (!missingMode)
                zwlr_output_mode_v1_send_size(mode, width, width == 1920 ? 1080 : 720);
            zwlr_output_mode_v1_send_refresh(mode, 60000);
        }
        zwlr_output_head_v1_send_current_mode(entry->resource, entry->modes.front());
        heads.push_back(std::move(entry));
    }
    static void bind(wl_client *client, void *data, uint32_t version, uint32_t id)
    {
        auto &self = *static_cast<Server *>(data);
        self.manager = wl_resource_create(client, &zwlr_output_manager_v1_interface,
                                          static_cast<int>(version), id);
        assert(self.manager);
        static const struct zwlr_output_manager_v1_interface requests
        {
            configuration, stopManager
        };
        wl_resource_set_implementation(self.manager, &requests, &self, nullptr);
        self.head(client, "DP-1");
        if (!self.missingDone)
            zwlr_output_manager_v1_send_done(self.manager, 1);
    }
    void action(int command)
    {
        auto &first = *heads.front();
        auto *client = wl_resource_get_client(manager);
        if (command == 1) {
            // Match the pinned backend: updates may arrive without another done.
            zwlr_output_head_v1_send_position(first.resource, -100, 20);
            zwlr_output_head_v1_send_transform(first.resource, 1);
            zwlr_output_head_v1_send_scale(first.resource, 320);
        } else if (command == 2) {
            zwlr_output_head_v1_send_finished(first.resource);
            for (auto *mode : first.modes)
                zwlr_output_mode_v1_send_finished(mode);
            head(client, "DP-1"); // Name ABA within one server event turn.
            zwlr_output_manager_v1_send_done(manager, 2);
        } else if (command == 3) {
            head(client, "DP-1"); // Duplicate live name is ambiguous.
            zwlr_output_manager_v1_send_done(manager, 3);
        } else if (command == 4) {
            zwlr_output_mode_v1_send_finished(first.modes.front());
            zwlr_output_manager_v1_send_done(manager, 4);
        } else if (command == 5) {
            for (unsigned index = 0; index < 20; ++index)
                head(client, ("OUT-" + std::to_string(index)).c_str());
            zwlr_output_manager_v1_send_done(manager, 5);
        }
    }
    void start()
    {
        assert(wl_global_create(display, &zwlr_output_manager_v1_interface, 4, this, bind));
        worker = std::thread([&] {
            while (!stop.load()) {
                assert(wl_event_loop_dispatch(wl_display_get_event_loop(display), 5) >= 0);
                const int requested = command.load();
                if (requested != completed.load()) {
                    action(requested);
                    completed.store(requested);
                }
                wl_display_flush_clients(display);
            }
        });
    }
    void request(int action)
    {
        command.store(action);
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (completed.load() != action && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(1ms);
        assert(completed.load() == action);
    }
    void finish()
    {
        stop.store(true);
        worker.join();
        assert(effects.load() == 0);
        wl_display_destroy_clients(display);
        wl_display_destroy(display);
    }
};
struct Registry final
{
    NativeDisplayTopology &topology;
    wl_registry *native;
    uint32_t managerGlobal = 0;
    static void global(void *data, wl_registry *registry, uint32_t name, const char *interface,
                       uint32_t version)
    {
        auto &self = *static_cast<Registry *>(data);
        if (std::strcmp(interface, "zwlr_output_manager_v1") == 0) {
            self.managerGlobal = name;
            self.topology.announce(registry, name, version);
        }
    }
    static void removed(void *data, wl_registry *, uint32_t name)
    {
        static_cast<Registry *>(data)->topology.removed(name);
    }
};
void scenario(int action, bool missingMode = false, bool missingDone = false)
{
    Server server;
    server.missingMode = missingMode;
    server.missingDone = missingDone;
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    assert(server.display && wl_client_create(server.display, sockets[0]));
    auto *client = wl_display_connect_to_fd(sockets[1]);
    assert(client);
    server.start();
    {
        NativeDisplayTopology topology;
        assert(!topology.snapshotAfterSync());
        auto *registry = wl_display_get_registry(client);
        Registry context{topology, registry};
        static const wl_registry_listener listener{Registry::global, Registry::removed};
        assert(wl_registry_add_listener(registry, &listener, &context) == 0);
        assert(waitForNativeWaylandReady(client, 1000ms));
        assert(waitForNativeWaylandReady(client, 1000ms));
        const auto before = topology.snapshotAfterSync();
        if (missingMode || missingDone) {
            assert(!before);
        } else {
            assert(before && before->heads.size() == 1 && before->generation > 0);
            const auto first = before->heads.front();
            assert(first.name == QLatin1String("DP-1") && first.modes.size() == 2);
            assert(first.current && first.current->width == 1920 && first.scaleFixed == 256);
            assert(!before->encode().isEmpty());
            server.request(action);
            assert(waitForNativeWaylandReady(client, 1000ms));
            const auto after = topology.snapshotAfterSync();
            if (action == 1) {
                assert(after && after->generation == before->generation);
                assert(after->heads.front().handle == first.handle);
                assert(after->heads.front().generation == first.generation);
                assert(after->heads.front().x == -100 && after->heads.front().y == 20);
                assert(after->heads.front().transform == 1 &&
                       after->heads.front().scaleFixed == 320);
            } else if (action == 2) {
                assert(after && after->heads.size() == 1 && after->generation > before->generation);
                assert(after->heads.front().name == first.name);
                assert(after->heads.front().handle != first.handle);
                assert(after->heads.front().generation > first.generation);
            } else {
                assert(!after);
            }
            topology.removed(context.managerGlobal);
            assert(!topology.snapshotAfterSync());
        }
        wl_registry_destroy(registry);
    }
    wl_display_disconnect(client);
    server.finish();
}
} // namespace
int main()
{
    for (int action : {1, 2, 3, 4, 5})
        scenario(action);
    scenario(1, true, false);
    scenario(1, false, true);
}
