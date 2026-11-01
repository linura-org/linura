// Actual private Wayland transport/admission tests. The scene below is a
// mechanism fixture; it supplies no native frame, authentication or authority.
#include "protected_wire.h"
#include "linura-protected-display-v1-client-protocol.h"

#include <array>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <wayland-client.h>
#include <wayland-server.h>

using namespace Linura::HyprlandDisplay;
namespace {
constexpr char Instance[] = "74e3ca24-b38b-4b62-9671-ae32dc38fd57";
struct Counts final
{
    std::atomic<unsigned> begin{0}, close{0}, attach{0}, acknowledge{0}, consume{0}, refresh{0};
    std::atomic<bool> throwAttach{false};
};
class Scene final : public ProtectedScene
{
  public:
    Counts &counts;
    ProtectedInteraction::Scope scope;
    bool closed = false, used = false;
    Configure configured;
    std::uint32_t serial = 7;
    Scene(Counts &facts, ProtectedInteraction::Scope value) : counts(facts), scope(std::move(value))
    {
        assert(scope.deadlineUnixMs == 10'000);
        assert(scope.deadlineBootMs == 0x123456789abcdef0ULL);
    }
    bool attach(OutputKey key, wl_resource *, Configure configure) override
    {
        ++counts.attach;
        if (counts.throwAttach.load())
            throw std::runtime_error("native fixture failure");
        if (key != OutputKey{1, 2})
            return false;
        configured = std::move(configure);
        configured(serial, 1920, 1080);
        return true;
    }
    bool acknowledge(OutputKey key, std::uint32_t serial) override
    {
        ++counts.acknowledge;
        return key == OutputKey{1, 2} && serial == this->serial;
    }
    std::optional<ProtectedSceneStatus> status() override
    {
        return ProtectedSceneStatus{Instance, 3, 4,
                                    used ? ProtectedInteraction::Phase::Consumed
                                         : ProtectedInteraction::Phase::Arming};
    }
    bool consume(const std::string &digest, std::uint64_t epoch) override
    {
        ++counts.consume;
        if (used || digest != scope.digest || epoch != 4)
            return false;
        return used = true;
    }
    bool refreshPresentation() override
    {
        ++counts.refresh;
        if (closed || used || !configured)
            return false;
        configured(++serial, 1920, 1080);
        return true;
    }
    std::shared_ptr<MutationProtection> reserveMutation(const Correlation &, const Layout &,
                                                        const Layout &, const Snapshot &,
                                                        ClockSample) override
    {
        return {};
    }
    bool beginDecision(const ProtectedInteraction::Scope &) override
    {
        return false;
    }
    void close() noexcept override
    {
        // Endpoint ownership must close exactly once even if parent and child
        // destruction happen in either order, or a denial is followed by death.
        assert(!closed);
        closed = true;
        ++counts.close;
    }
};
void destroyResource(wl_client *, wl_resource *resource)
{
    wl_resource_destroy(resource);
}
const struct wl_surface_interface surfaceImplementation = [] {
    struct wl_surface_interface callbacks
    {};
    callbacks.destroy = destroyResource;
    return callbacks;
}();
void createSurface(wl_client *client, wl_resource *, std::uint32_t id)
{
    auto *surface = wl_resource_create(client, &wl_surface_interface, 1, id);
    assert(surface);
    wl_resource_set_implementation(surface, &surfaceImplementation, nullptr, nullptr);
}
const struct wl_compositor_interface compositorImplementation = [] {
    struct wl_compositor_interface callbacks
    {};
    callbacks.create_surface = createSurface;
    return callbacks;
}();
class Harness final
{
  public:
    Counts counts;
    std::atomic<unsigned char> invocation{1};
    std::atomic<bool> stop{false};
    wl_display *display = wl_display_create();
    wl_global *compositor;
    std::unique_ptr<ProtectedWireEndpoint> endpoint;
    std::thread server;
    int descriptor = -1;
    Harness()
    {
        assert(display);
        compositor = wl_global_create(
            display, &wl_compositor_interface, 1, nullptr,
            [](wl_client *client, void *, std::uint32_t, std::uint32_t id) {
                auto *res = wl_resource_create(client, &wl_compositor_interface, 1, id);
                assert(res);
                wl_resource_set_implementation(res, &compositorImplementation, nullptr, nullptr);
            });
        endpoint = std::make_unique<ProtectedWireEndpoint>(
            *display,
            [this](pid_t pid, uid_t uid) -> std::optional<WireEndpoint::OwnerInvocation> {
                assert(pid == getpid() && uid == getuid());
                const auto live = invocation.load();
                if (!live)
                    return std::nullopt;
                WireEndpoint::OwnerInvocation value{};
                value[0] = live;
                return value;
            },
            [this](const ProtectedInteraction::Scope &scope) {
                ++counts.begin;
                return std::make_unique<Scene>(counts, scope);
            });
        assert(endpoint->available());
        int sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
        assert(wl_client_create(display, sockets[0]));
        descriptor = sockets[1];
        server = std::thread([this] {
            auto *loop = wl_display_get_event_loop(display);
            while (!stop.load()) {
                assert(wl_event_loop_dispatch(loop, 5) == 0);
                wl_display_flush_clients(display);
            }
        });
    }
    void finish()
    {
        stop.store(true);
        if (server.joinable())
            server.join();
        wl_display_destroy_clients(display);
    }
    ~Harness()
    {
        finish();
        endpoint.reset();
        wl_global_destroy(compositor);
        wl_display_destroy(display);
    }
};
class Client final
{
  public:
    wl_display *display;
    wl_registry *registry;
    wl_compositor *compositor = nullptr;
    linura_protected_display_manager_v1 *manager = nullptr;
    linura_protected_display_interaction_v1 *interaction = nullptr;
    linura_protected_display_surface_v1 *protectedSurface = nullptr;
    wl_surface *surface = nullptr;
    unsigned denied = 0, statuses = 0;
    std::uint32_t phase = 99, serial = 0;
    explicit Client(int descriptor, bool admitted = true)
        : display(wl_display_connect_to_fd(descriptor)), registry(nullptr)
    {
        assert(display);
        registry = wl_display_get_registry(display);
        static const wl_registry_listener listener{
            [](void *data, wl_registry *registry, std::uint32_t id, const char *name,
               std::uint32_t) {
                auto &self = *static_cast<Client *>(data);
                if (!std::strcmp(name, "linura_protected_display_manager_v1"))
                    self.manager =
                        static_cast<linura_protected_display_manager_v1 *>(wl_registry_bind(
                            registry, id, &linura_protected_display_manager_v1_interface, 1));
                if (!std::strcmp(name, "wl_compositor"))
                    self.compositor = static_cast<wl_compositor *>(
                        wl_registry_bind(registry, id, &wl_compositor_interface, 1));
            },
            [](void *, wl_registry *, std::uint32_t) {}};
        wl_registry_add_listener(registry, &listener, this);
        auto result = wl_display_roundtrip(display);
        if (result >= 0)
            result = wl_display_roundtrip(display);
        if (admitted)
            assert(result >= 0 && manager && compositor);
        else
            assert(result < 0 && wl_display_get_error(display) == EPROTO);
    }
    ~Client()
    {
        if (protectedSurface)
            linura_protected_display_surface_v1_destroy(protectedSurface);
        if (surface)
            wl_surface_destroy(surface);
        if (interaction)
            linura_protected_display_interaction_v1_destroy(interaction);
        if (manager)
            linura_protected_display_manager_v1_destroy(manager);
        if (compositor)
            wl_compositor_destroy(compositor);
        wl_registry_destroy(registry);
        (void)wl_display_flush(display);
        wl_display_disconnect(display);
    }
    void roundtrip()
    {
        assert(wl_display_roundtrip(display) >= 0);
    }
    void begin(const char *digest = nullptr, unsigned purpose = 0,
               std::uint64_t deadlineBoot = 0x123456789abcdef0ULL)
    {
        const auto value = std::string(64, 'a');
        interaction = linura_protected_display_manager_v1_begin(
            manager, digest ? digest : value.c_str(), purpose, 0, 10'000,
            static_cast<std::uint32_t>(deadlineBoot >> 32U),
            static_cast<std::uint32_t>(deadlineBoot));
        static const linura_protected_display_interaction_v1_listener listener{
            [](void *data, linura_protected_display_interaction_v1 *, const char *instance,
               std::uint32_t hi, std::uint32_t lo, std::uint32_t epochHi, std::uint32_t epochLo,
               std::uint32_t phase) {
                auto &self = *static_cast<Client *>(data);
                assert(!std::strcmp(instance, Instance) && hi == 0 && lo == 3 && epochHi == 0 &&
                       epochLo == 4);
                ++self.statuses;
                self.phase = phase;
            },
            [](void *data, linura_protected_display_interaction_v1 *) {
                ++static_cast<Client *>(data)->denied;
            }};
        linura_protected_display_interaction_v1_add_listener(interaction, &listener, this);
        roundtrip();
    }
    void attach(std::uint32_t handle = 1, bool success = true)
    {
        surface = wl_compositor_create_surface(compositor);
        protectedSurface = linura_protected_display_interaction_v1_get_surface(interaction, surface,
                                                                               0, handle, 0, 2);
        static const linura_protected_display_surface_v1_listener listener{
            [](void *data, linura_protected_display_surface_v1 *, std::uint32_t serial,
               std::uint32_t w, std::uint32_t h) {
                assert(w == 1920 && h == 1080);
                static_cast<Client *>(data)->serial = serial;
            }};
        linura_protected_display_surface_v1_add_listener(protectedSurface, &listener, this);
        if (success)
            roundtrip();
        else
            assert(wl_display_roundtrip(display) < 0);
    }
    void status()
    {
        linura_protected_display_interaction_v1_get_status(interaction);
        roundtrip();
    }
};
void ownerReplacement()
{
    // Every retained mutation/read step reattests the original supervised
    // invocation; same PID/UID cannot migrate a conversation to its successor.
    for (unsigned operation = 0; operation != 5; ++operation) {
        Harness h;
        Client c(h.descriptor);
        c.begin();
        if (operation == 1)
            c.attach();
        h.invocation.store(2);
        if (operation == 0)
            c.attach();
        if (operation == 1) {
            linura_protected_display_surface_v1_ack_configure(c.protectedSurface, 7);
            c.roundtrip();
        }
        if (operation == 2) {
            linura_protected_display_interaction_v1_consume(c.interaction,
                                                            std::string(64, 'a').c_str(), 0, 4);
            c.roundtrip();
        }
        if (operation == 4) {
            linura_protected_display_interaction_v1_refresh_presentation(c.interaction);
            c.roundtrip();
        }
        c.status();
        assert(c.denied >= 1 && h.counts.close == 1 && h.counts.acknowledge == 0 &&
               h.counts.consume == 0 && h.counts.refresh == 0);
    }
}
} // namespace
int main()
{
    assert(getuid() != 0); // Native graphical owner/compositor never runs as root.
    {
        Harness h;
        Client c(h.descriptor);
        c.begin(nullptr, 0, 0);
        assert(c.denied == 1 && h.counts.begin == 0);
    }
    {
        Harness h;
        h.invocation.store(0);
        Client c(h.descriptor, false);
        assert(h.counts.begin == 0);
    }
    for (const auto &bad : std::array<std::string, 3>{"", "a", std::string(64, '0')}) {
        // Keep invalid strings alive for the complete wire roundtrip.
        const std::string value(bad);
        Harness h;
        Client c(h.descriptor);
        c.begin(value.c_str());
        assert(c.denied == 1 && h.counts.begin == 0);
    }
    {
        Harness h;
        Client c(h.descriptor);
        c.begin(nullptr, 3);
        assert(c.denied == 1 && h.counts.begin == 0);
    }
    {
        Harness h;
        Client c(h.descriptor);
        c.begin();
        c.attach();
        assert(c.serial == 7);
        linura_protected_display_surface_v1_ack_configure(c.protectedSurface, 7);
        c.roundtrip();
        c.status();
        assert(c.phase == 0 && h.counts.acknowledge == 1);
        linura_protected_display_interaction_v1_refresh_presentation(c.interaction);
        c.roundtrip();
        assert(c.serial == 8 && h.counts.refresh == 1);
        linura_protected_display_surface_v1_ack_configure(c.protectedSurface, 8);
        c.roundtrip();
        assert(h.counts.acknowledge == 2);
        linura_protected_display_interaction_v1_consume(c.interaction, std::string(64, 'a').c_str(),
                                                        0, 4);
        c.roundtrip();
        assert(c.phase == 2);
        linura_protected_display_interaction_v1_consume(c.interaction, std::string(64, 'a').c_str(),
                                                        0, 4);
        c.roundtrip();
        assert(c.denied == 1 && h.counts.close == 1);
    }
    {
        Harness h;
        Client c(h.descriptor);
        c.begin();
        c.attach(99);
        assert(c.denied == 1 && h.counts.close == 1);
        c.status();
        assert(c.denied == 2);
    }
    {
        Harness h;
        Client c(h.descriptor);
        c.begin();
        c.attach();
        linura_protected_display_surface_v1_ack_configure(c.protectedSurface, 8);
        c.roundtrip();
        assert(h.counts.close == 1);
        c.status();
        assert(c.denied == 1);
    }
    for (const bool parentFirst : {false, true}) {
        Harness h;
        Client c(h.descriptor);
        c.begin();
        c.attach();
        if (parentFirst) {
            linura_protected_display_interaction_v1_destroy(c.interaction);
            c.interaction = nullptr;
        } else {
            linura_protected_display_surface_v1_destroy(c.protectedSurface);
            c.protectedSurface = nullptr;
        }
        c.roundtrip();
        assert(h.counts.close == 1);
    }
    {
        Harness h;
        Client c(h.descriptor);
        c.begin();
        h.counts.throwAttach.store(true);
        c.attach(1, false);
        assert(h.counts.close == 1);
    }
    {
        Harness h;
        Client c(h.descriptor);
        for (unsigned i = 0; i < 127; ++i) {
            c.begin();
            wl_proxy_destroy(reinterpret_cast<wl_proxy *>(c.interaction));
            c.interaction = nullptr;
        }
        c.interaction = linura_protected_display_manager_v1_begin(
            c.manager, std::string(64, 'a').c_str(), 0, 0, 10'000, 0x12345678, 0x9abcdef0);
        assert(wl_display_roundtrip(c.display) < 0);
        h.finish(); // Protocol error delivery precedes server resource teardown.
        assert(h.counts.begin == 127 && h.counts.close == 127);
    }
    ownerReplacement();
}
