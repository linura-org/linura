#include "protected_wire.h"
#include "linura-protected-display-v1-server-protocol.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <utility>
#include <unistd.h>
#include <wayland-server-core.h>

namespace Linura::HyprlandDisplay {
namespace {
std::uint64_t joined(std::uint32_t high, std::uint32_t low)
{
    return (static_cast<std::uint64_t>(high) << 32U) | low;
}
bool digest(const char *value)
{
    return value && strnlen(value, 65) == 64 &&
           std::any_of(value, value + 64, [](char c) { return c != '0'; }) &&
           std::all_of(value, value + 64,
                       [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
bool instance(const std::string &value)
{
    if (value.size() != 36)
        return false;
    bool nonzero = false;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-')
                return false;
        } else {
            if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')))
                return false;
            nonzero = nonzero || value[i] != '0';
        }
    }
    return nonzero;
}
} // namespace
class ProtectedWireEndpoint::Impl final
{
  public:
    struct Peer final
    {
        pid_t pid = 0;
        uid_t uid = 0;
        WireEndpoint::OwnerInvocation invocation{};
    };
    struct State final
    {
        std::unique_ptr<ProtectedScene> scene;
        bool closed = false;
        void close() noexcept
        {
            if (closed)
                return;
            closed = true;
            if (scene)
                scene->close();
        }
        ~State()
        {
            close();
        }
    };
    struct Resource
    {
        Impl &owner;
        Peer peer;
        wl_resource *native = nullptr;
        Resource(Impl &parent, Peer identity) : owner(parent), peer(identity) {}
        virtual ~Resource()
        {
            if (native)
                owner.resources.erase(native);
        }
    };
    struct Manager final : Resource
    {
        using Resource::Resource;
    };
    struct Interaction final : Resource
    {
        using Resource::Resource;
        std::shared_ptr<State> state;
        ~Interaction() override
        {
            if (state)
                state->close();
        }
    };
    struct Surface final : Resource
    {
        using Resource::Resource;
        std::shared_ptr<State> state;
        OutputKey output;
        ~Surface() override
        {
            if (state)
                state->close();
        }
    };
    WireEndpoint::AdmitOwner admit;
    Begin begin;
    wl_global *global = nullptr;
    std::set<wl_resource *> resources;
    Impl(wl_display &display, WireEndpoint::AdmitOwner admission, Begin factory)
        : admit(std::move(admission)), begin(std::move(factory))
    {
        if (getuid() == 0 || getuid() != geteuid() || !admit || !begin)
            return;
        global = wl_global_create(&display, &linura_protected_display_manager_v1_interface, 1, this,
                                  bind);
    }
    ~Impl()
    {
        if (global)
            wl_global_destroy(global);
        while (!resources.empty())
            wl_resource_destroy(*resources.begin());
    }
    template <typename T> static T &object(wl_resource *resource)
    {
        return *static_cast<T *>(static_cast<Resource *>(wl_resource_get_user_data(resource)));
    }
    template <typename T>
    bool publish(std::unique_ptr<T> value, wl_client *client, const wl_interface &interface,
                 std::uint32_t id, const void *implementation)
    {
        if (resources.size() >= 128)
            return false;
        value->native = wl_resource_create(client, &interface, 1, id);
        if (!value->native)
            return false;
        try {
            resources.insert(value->native);
        } catch (...) {
            wl_resource_destroy(value->native);
            value->native = nullptr;
            return false;
        }
        auto *resource = value->native;
        wl_resource_set_implementation(
            resource, implementation, value.release(), [](wl_resource *res) {
                delete static_cast<Resource *>(wl_resource_get_user_data(res));
            });
        return true;
    }
    bool current(const Resource &value)
    {
        const auto now = admit(value.peer.pid, value.peer.uid);
        return now && *now == value.peer.invocation;
    }
    static void destroy(wl_client *, wl_resource *resource)
    {
        wl_resource_destroy(resource);
    }
    static void bind(wl_client *client, void *data, std::uint32_t, std::uint32_t id)
    {
        auto &owner = *static_cast<Impl *>(data);
        Peer peer;
        gid_t gid = 0;
        wl_client_get_credentials(client, &peer.pid, &peer.uid, &gid);
        try {
            const auto identity = owner.admit(peer.pid, peer.uid);
            if (!identity || peer.pid <= 1 || peer.uid != getuid() ||
                std::all_of(identity->begin(), identity->end(),
                            [](auto byte) { return byte == 0; })) {
                wl_client_post_implementation_error(client,
                                                    "Protected display owner admission denied");
                return;
            }
            peer.invocation = *identity;
            if (!owner.publish(std::make_unique<Manager>(owner, peer), client,
                               linura_protected_display_manager_v1_interface, id, &managerImpl))
                wl_client_post_no_memory(client);
        } catch (...) {
            wl_client_post_no_memory(client);
        }
    }
    static void beginInteraction(wl_client *client, wl_resource *resource, std::uint32_t id,
                                 const char *scope, std::uint32_t purpose, std::uint32_t high,
                                 std::uint32_t low, std::uint32_t bootHigh, std::uint32_t bootLow)
    {
        auto &manager = object<Manager>(resource);
        try {
            auto value = std::make_unique<Interaction>(manager.owner, manager.peer);
            value->state = std::make_shared<State>();
            auto state = value->state;
            if (!manager.owner.publish(std::move(value), client,
                                       linura_protected_display_interaction_v1_interface, id,
                                       &interactionImpl)) {
                wl_client_post_no_memory(client);
                return;
            }
            auto *created = wl_client_get_object(client, id);
            if (digest(scope) && purpose <= 2 && joined(high, low) != 0 &&
                joined(bootHigh, bootLow) != 0 && manager.owner.current(manager))
                state->scene =
                    manager.owner.begin({scope, static_cast<ProtectedInteraction::Purpose>(purpose),
                                         joined(high, low), joined(bootHigh, bootLow)});
            if (!state->scene)
                linura_protected_display_interaction_v1_send_denied(created);
        } catch (...) {
            wl_client_post_no_memory(client);
        }
    }
    static void getSurface(wl_client *client, wl_resource *resource, std::uint32_t id,
                           wl_resource *surface, std::uint32_t hi, std::uint32_t lo,
                           std::uint32_t genHi, std::uint32_t genLo)
    {
        auto &interaction = object<Interaction>(resource);
        try {
            auto value = std::make_unique<Surface>(interaction.owner, interaction.peer);
            value->state = interaction.state;
            value->output = {joined(hi, lo), joined(genHi, genLo)};
            auto *retained = value.get();
            if (!interaction.owner.publish(std::move(value), client,
                                           linura_protected_display_surface_v1_interface, id,
                                           &surfaceImpl)) {
                wl_client_post_no_memory(client);
                return;
            }
            const auto state = retained->state;
            if (!state || !state->scene || state->closed || !surface ||
                wl_resource_get_client(surface) != client ||
                !interaction.owner.current(interaction) ||
                !state->scene->attach(
                    retained->output, surface,
                    [weak = std::weak_ptr<State>(state), native = retained->native](
                        std::uint32_t serial, std::uint32_t width, std::uint32_t height) {
                        const auto live = weak.lock();
                        if (!live || live->closed)
                            return;
                        if (serial == 0 || width == 0 || height == 0 || width > 32768 ||
                            height > 32768) {
                            live->close();
                            return;
                        }
                        linura_protected_display_surface_v1_send_configure(native, serial, width,
                                                                           height);
                    })) {
                if (state)
                    state->close();
                linura_protected_display_interaction_v1_send_denied(resource);
            }
        } catch (...) {
            if (interaction.state)
                interaction.state->close();
            wl_client_post_no_memory(client);
        }
    }
    static void acknowledge(wl_client *, wl_resource *resource, std::uint32_t serial)
    {
        auto &surface = object<Surface>(resource);
        try {
            if (!surface.state || !surface.state->scene || surface.state->closed ||
                !surface.owner.current(surface) ||
                !surface.state->scene->acknowledge(surface.output, serial))
                if (surface.state)
                    surface.state->close();
        } catch (...) {
            if (surface.state)
                surface.state->close();
        }
    }
    static void status(wl_client *, wl_resource *resource)
    {
        auto &interaction = object<Interaction>(resource);
        try {
            const auto &state = interaction.state;
            const auto facts =
                state && state->scene && !state->closed && interaction.owner.current(interaction)
                    ? state->scene->status()
                    : std::nullopt;
            if (!facts || !instance(facts->compositor) || facts->topology == 0 ||
                facts->topology == std::numeric_limits<std::uint64_t>::max() || facts->epoch == 0 ||
                facts->epoch == std::numeric_limits<std::uint64_t>::max() ||
                static_cast<unsigned>(facts->phase) >
                    static_cast<unsigned>(ProtectedInteraction::Phase::Cancelled)) {
                if (state)
                    state->close();
                linura_protected_display_interaction_v1_send_denied(resource);
                return;
            }
            linura_protected_display_interaction_v1_send_status(
                resource, facts->compositor.c_str(),
                static_cast<std::uint32_t>(facts->topology >> 32U),
                static_cast<std::uint32_t>(facts->topology),
                static_cast<std::uint32_t>(facts->epoch >> 32U),
                static_cast<std::uint32_t>(facts->epoch), static_cast<std::uint32_t>(facts->phase));
        } catch (...) {
            if (interaction.state)
                interaction.state->close();
            linura_protected_display_interaction_v1_send_denied(resource);
        }
    }
    static void refreshPresentation(wl_client *, wl_resource *resource)
    {
        auto &interaction = object<Interaction>(resource);
        try {
            const auto &state = interaction.state;
            if (!state || !state->scene || state->closed ||
                !interaction.owner.current(interaction) || !state->scene->refreshPresentation()) {
                if (state)
                    state->close();
                linura_protected_display_interaction_v1_send_denied(resource);
            }
        } catch (...) {
            if (interaction.state)
                interaction.state->close();
            linura_protected_display_interaction_v1_send_denied(resource);
        }
    }
    static void consume(wl_client *, wl_resource *resource, const char *scope, std::uint32_t high,
                        std::uint32_t low)
    {
        auto &interaction = object<Interaction>(resource);
        try {
            const auto &state = interaction.state;
            if (!digest(scope) || !state || !state->scene || state->closed ||
                !interaction.owner.current(interaction) ||
                !state->scene->consume(scope, joined(high, low))) {
                if (state)
                    state->close();
                linura_protected_display_interaction_v1_send_denied(resource);
                return;
            }
            status(nullptr, resource);
        } catch (...) {
            if (interaction.state)
                interaction.state->close();
            linura_protected_display_interaction_v1_send_denied(resource);
        }
    }
    static const struct linura_protected_display_manager_v1_interface managerImpl;
    static const struct linura_protected_display_interaction_v1_interface interactionImpl;
    static const struct linura_protected_display_surface_v1_interface surfaceImpl;
};
const struct linura_protected_display_manager_v1_interface ProtectedWireEndpoint::Impl::managerImpl
{
    destroy, beginInteraction
};
const struct linura_protected_display_interaction_v1_interface
    ProtectedWireEndpoint::Impl::interactionImpl
{
    destroy, getSurface, status, refreshPresentation, consume
};
const struct linura_protected_display_surface_v1_interface ProtectedWireEndpoint::Impl::surfaceImpl
{
    destroy, acknowledge
};
ProtectedWireEndpoint::ProtectedWireEndpoint(wl_display &display, WireEndpoint::AdmitOwner admit,
                                             Begin begin)
    : impl_(std::make_unique<Impl>(display, std::move(admit), std::move(begin)))
{}
ProtectedWireEndpoint::~ProtectedWireEndpoint() = default;
bool ProtectedWireEndpoint::available() const noexcept
{
    return impl_->global != nullptr;
}
} // namespace Linura::HyprlandDisplay
