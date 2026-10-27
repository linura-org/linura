#include "wire_endpoint.h"
#include "native_scale.h"
#include "linura-display-management-v1-server-protocol.h"

#include <algorithm>
#include <cstring>
#include <cstddef>
#include <map>
#include <set>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <wayland-server-core.h>

namespace Linura::HyprlandDisplay {
namespace {
std::uint32_t high(std::uint64_t value)
{
    return static_cast<std::uint32_t>(value >> 32);
}
std::uint32_t low(std::uint64_t value)
{
    return static_cast<std::uint32_t>(value);
}
bool scalar(const char *value, std::size_t maximum, bool hexadecimal)
{
    if (!value)
        return false;
    const auto length = strnlen(value, maximum + 1);
    return length > 0 && length <= maximum && std::all_of(value, value + length, [=](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= (hexadecimal ? 'f' : 'z')) ||
                      (!hexadecimal && (c == ':' || c == '-'));
           });
}
std::uint32_t wirePhase(CompositorDisplayService::Phase phase)
{
    using Phase = CompositorDisplayService::Phase;
    switch (phase) {
    case Phase::RejectedBeforeDispatch:
        return LINURA_DISPLAY_ATTEMPT_V1_PHASE_REJECTED_BEFORE_DISPATCH;
    case Phase::Pending:
        return LINURA_DISPLAY_ATTEMPT_V1_PHASE_PENDING;
    case Phase::Restoring:
        return LINURA_DISPLAY_ATTEMPT_V1_PHASE_RESTORING;
    case Phase::Confirmed:
        return LINURA_DISPLAY_ATTEMPT_V1_PHASE_CONFIRMED;
    case Phase::Restored:
        return LINURA_DISPLAY_ATTEMPT_V1_PHASE_RESTORED;
    case Phase::RecoveryFailed:
        return LINURA_DISPLAY_ATTEMPT_V1_PHASE_RECOVERY_FAILED;
    }
    return LINURA_DISPLAY_ATTEMPT_V1_PHASE_UNKNOWN;
}
} // namespace

class WireEndpoint::Impl final
{
  public:
    static constexpr std::size_t MaxClients = 8, MaxResources = 64, MaxSnapshots = 2;
    struct Client final
    {
        wl_listener destroyed{};
        Impl *owner = nullptr;
        wl_client *native = nullptr;
        bool alive = true;
        std::size_t resources = 0, snapshots = 0;
    };
    struct Captured final
    {
        std::shared_ptr<Client> client;
        Snapshot sample;
        ClockSample at;
        Captured(std::shared_ptr<Client> value, Snapshot facts, ClockSample clock)
            : client(std::move(value)), sample(std::move(facts)), at(clock)
        {
            ++client->snapshots;
        }
        ~Captured()
        {
            --client->snapshots;
        }
    };
    struct Resource
    {
        Impl &owner;
        std::shared_ptr<Client> client;
        wl_resource *native = nullptr;
        Resource(Impl &endpoint, std::shared_ptr<Client> peer)
            : owner(endpoint), client(std::move(peer))
        {}
        virtual ~Resource()
        {
            if (native) {
                owner.resources.erase(native);
                --client->resources;
            }
        }
    };
    struct Manager final : Resource
    {
        using Resource::Resource;
    };
    struct SnapshotResource final : Resource
    {
        using Resource::Resource;
        std::shared_ptr<Captured> captured;
    };
    struct HeadResource final : Resource
    {
        using Resource::Resource;
        std::shared_ptr<Captured> captured;
        std::size_t index = 0;
    };
    struct Attempt final : Resource
    {
        using Resource::Resource;
        Correlation bound;
        std::shared_ptr<Captured> captured;
        std::map<OutputKey, Target> targets;
        bool used = false, invalid = false;
        void status()
        {
            if (invalid) {
                linura_display_attempt_v1_send_status(native,
                                                      LINURA_DISPLAY_ATTEMPT_V1_PHASE_DENIED);
                return;
            }
            const auto phase = owner.service.status(bound);
            linura_display_attempt_v1_send_status(
                native, phase ? wirePhase(*phase)
                              : static_cast<std::uint32_t>(
                                    used ? LINURA_DISPLAY_ATTEMPT_V1_PHASE_UNKNOWN
                                         : LINURA_DISPLAY_ATTEMPT_V1_PHASE_BUILDING));
        }
        void deny()
        {
            invalid = true;
            linura_display_attempt_v1_send_status(native, LINURA_DISPLAY_ATTEMPT_V1_PHASE_DENIED);
        }
        bool original() const
        {
            const auto found = owner.origins.find(bound.transaction);
            return client->alive && found != owner.origins.end() && found->second.lock() == client;
        }
    };

    Backend &backend;
    CompositorDisplayService &service;
    NativeBuildIdentity identity;
    OutputName outputName;
    wl_global *global = nullptr;
    std::map<wl_client *, std::shared_ptr<Client>> clients;
    std::set<wl_resource *> resources;
    std::map<std::string, std::weak_ptr<Client>> origins;
    static_assert(std::is_standard_layout_v<Client> && offsetof(Client, destroyed) == 0);

    template <typename T> static T &object(wl_resource *resource)
    {
        return *static_cast<T *>(static_cast<Resource *>(wl_resource_get_user_data(resource)));
    }

    Impl(wl_display &display, Backend &native, CompositorDisplayService &attempts,
         NativeBuildIdentity build, OutputName names)
        : backend(native), service(attempts), identity(std::move(build)),
          outputName(std::move(names))
    {
        if (getuid() == 0 || getuid() != geteuid() || identity.compositorInstance.size() != 36 ||
            identity.upstreamCommit.size() != 40 || identity.integrationDigest.size() != 64 ||
            !scalar(identity.upstreamCommit.c_str(), 40, true) ||
            !scalar(identity.integrationDigest.c_str(), 64, true) || !outputName)
            return;
        global = wl_global_create(&display, &linura_display_manager_v1_interface, 1, this, bind);
    }
    ~Impl()
    {
        if (global)
            wl_global_destroy(global);
        while (!resources.empty())
            wl_resource_destroy(*resources.begin());
        for (auto &[native, client] : clients) {
            (void)native;
            wl_list_remove(&client->destroyed.link);
            client->alive = false;
            client->native = nullptr;
        }
    }
    static void release(wl_client *, wl_resource *resource)
    {
        wl_resource_destroy(resource);
    }
    static void destroyedResource(wl_resource *resource)
    {
        delete static_cast<Resource *>(wl_resource_get_user_data(resource));
    }
    template <typename T, typename... Args>
    T *make(const std::shared_ptr<Client> &client, const wl_interface &interface,
            const void *implementation, std::uint32_t id, Args &&...args)
    {
        if (!client->alive || client->resources >= MaxResources) {
            wl_client_post_no_memory(client->native);
            return nullptr;
        }
        auto value = std::make_unique<T>(*this, client, std::forward<Args>(args)...);
        auto *native = wl_resource_create(client->native, &interface, 1, id);
        if (!native) {
            wl_client_post_no_memory(client->native);
            return nullptr;
        }
        try {
            resources.insert(native);
        } catch (...) {
            wl_resource_destroy(native);
            throw;
        }
        ++client->resources;
        value->native = native;
        wl_resource_set_implementation(value->native, implementation,
                                       static_cast<Resource *>(value.get()), destroyedResource);
        return value.release();
    }
    static void clientDestroyed(wl_listener *listener, void *)
    {
        // Client is the listener's standard-layout owner; no PID, address or
        // connection identity is reused after this notification.
        auto *client = reinterpret_cast<Client *>(listener);
        auto &self = *client->owner;
        const auto found = self.clients.find(client->native);
        if (found == self.clients.end())
            return;
        const auto retained = found->second;
        (void)retained; // Keep the listener owner alive until callback completion.
        client->alive = false;
        wl_list_remove(&client->destroyed.link);
        // The compositor timer continues independently. Every old weak origin
        // is permanently ineligible for confirmation after connection death.
        self.clients.erase(client->native);
        client->native = nullptr;
    }
    static void bind(wl_client *native, void *data, std::uint32_t, std::uint32_t id)
    {
        auto &self = *static_cast<Impl *>(data);
        pid_t pid = 0;
        uid_t uid = 0;
        gid_t gid = 0;
        wl_client_get_credentials(native, &pid, &uid, &gid);
        (void)gid;
        if (pid <= 0 || uid != getuid()) {
            wl_client_post_implementation_error(native, "native display session unavailable");
            return;
        }
        try {
            auto found = self.clients.find(native);
            if (found == self.clients.end()) {
                if (self.clients.size() >= MaxClients) {
                    wl_client_post_no_memory(native);
                    return;
                }
                auto client = std::make_shared<Client>();
                client->owner = &self;
                client->native = native;
                client->destroyed.notify = clientDestroyed;
                found = self.clients.emplace(native, std::move(client)).first;
                wl_client_add_destroy_listener(native, &found->second->destroyed);
            }
            self.make<Manager>(found->second, linura_display_manager_v1_interface,
                               &managerImplementation, id);
        } catch (...) {
            wl_client_post_no_memory(native);
        }
    }
    static void snapshot(wl_client *client, wl_resource *resource, std::uint32_t id)
    {
        auto &manager = object<Manager>(resource);
        auto &self = manager.owner;
        try {
            auto *result = self.make<SnapshotResource>(
                manager.client, linura_display_snapshot_v1_interface, &snapshotImplementation, id);
            if (!result)
                return;
            const auto at = self.backend.clock();
            const auto sample = self.backend.snapshot();
            const auto completed = self.backend.clock();
            if (!at || !sample || !completed || sample->heads.empty() ||
                sample->heads.size() > DisplayTransaction::MaxHeads ||
                manager.client->snapshots >= MaxSnapshots || completed->unixMs < at->unixMs ||
                completed->bootMs < at->bootMs || completed->unixMs - at->unixMs >= 2000 ||
                completed->bootMs - at->bootMs >= 2000) {
                linura_display_snapshot_v1_send_unavailable(result->native);
                return;
            }
            result->captured = std::make_shared<Captured>(manager.client, *sample, *at);
            linura_display_snapshot_v1_send_identity(
                result->native, self.identity.compositorInstance.c_str(),
                self.identity.upstreamCommit.c_str(), self.identity.integrationDigest.c_str(),
                high(sample->generation), low(sample->generation), high(sample->securityEpoch),
                low(sample->securityEpoch), high(at->unixMs), low(at->unixMs), high(at->bootMs),
                low(at->bootMs), static_cast<std::uint32_t>(sample->coverage),
                self.service.fenced() ? 1U : 0U);
            for (std::size_t i = 0; i < sample->heads.size(); ++i) {
                const auto &head = sample->heads[i];
                const auto name = self.outputName(head.key);
                if (!name || name->empty() || name->size() > 128 ||
                    head.modes.size() > DisplayTransaction::MaxModes) {
                    linura_display_snapshot_v1_send_unavailable(result->native);
                    return;
                }
                auto *wire = self.make<HeadResource>(
                    manager.client, linura_display_head_v1_interface, &headImplementation, 0);
                if (!wire)
                    return;
                wire->captured = result->captured;
                wire->index = i;
                linura_display_snapshot_v1_send_head(
                    result->native, wire->native, high(head.key.handle), low(head.key.handle),
                    high(head.key.generation), low(head.key.generation), name->c_str());
                for (const auto &mode : head.modes)
                    linura_display_head_v1_send_mode(wire->native, mode.width, mode.height,
                                                     mode.refreshMilliHz);
                const auto &current = head.current;
                linura_display_head_v1_send_current(
                    wire->native, current.enabled ? 1U : 0U, current.mode.width,
                    current.mode.height, current.mode.refreshMilliHz, current.scaleMilli,
                    nativeScaleBits(current.scaleMilli), current.transform, current.x, current.y,
                    head.powered ? 1U : 0U, head.covered ? 1U : 0U);
                if (current.mirror)
                    linura_display_head_v1_send_mirror(
                        wire->native, high(current.mirror->handle), low(current.mirror->handle),
                        high(current.mirror->generation), low(current.mirror->generation));
                linura_display_head_v1_send_done(wire->native);
            }
            linura_display_snapshot_v1_send_done(result->native);
        } catch (...) {
            wl_client_post_no_memory(client);
        }
    }
    static void attempt(wl_client *client, wl_resource *resource, std::uint32_t id,
                        const char *transaction, const char *effect, const char *dispatch,
                        std::uint32_t deadlineHi, std::uint32_t deadlineLo)
    {
        auto &manager = object<Manager>(resource);
        try {
            auto *result = manager.owner.make<Attempt>(
                manager.client, linura_display_attempt_v1_interface, &attemptImplementation, id);
            if (!result)
                return;
            if (!scalar(transaction, 256, false) || !scalar(effect, 64, true) ||
                !scalar(dispatch, 64, true) || strnlen(effect, 65) != 64 ||
                strnlen(dispatch, 65) != 64) {
                result->deny();
                return;
            }
            result->bound = {transaction, effect, dispatch,
                             (static_cast<std::uint64_t>(deadlineHi) << 32) | deadlineLo};
            result->used = manager.owner.service.status(result->bound).has_value();
            result->status();
        } catch (...) {
            wl_client_post_no_memory(client);
        }
    }
    static void configure(wl_client *, wl_resource *resource, wl_resource *snapshot)
    {
        auto &attempt = object<Attempt>(resource);
        if (attempt.used || attempt.invalid || attempt.captured ||
            !wl_resource_instance_of(snapshot, &linura_display_snapshot_v1_interface,
                                     &snapshotImplementation) ||
            wl_resource_get_client(resource) != wl_resource_get_client(snapshot)) {
            attempt.deny();
            return;
        }
        auto &sample = object<SnapshotResource>(snapshot);
        if (!sample.captured || sample.client != attempt.client) {
            attempt.deny();
            return;
        }
        attempt.captured = sample.captured;
    }
    static HeadResource *headFor(Attempt &attempt, wl_resource *head)
    {
        if (!head || !attempt.captured || attempt.used || attempt.invalid ||
            !wl_resource_instance_of(head, &linura_display_head_v1_interface, &headImplementation))
            return nullptr;
        auto *value = &object<HeadResource>(head);
        return value->client == attempt.client && value->captured == attempt.captured ? value
                                                                                      : nullptr;
    }
    static void enable(wl_client *client, wl_resource *resource, wl_resource *head,
                       std::int32_t width, std::int32_t height, std::int32_t refresh,
                       std::uint32_t scale, std::uint32_t transform, std::int32_t x, std::int32_t y,
                       wl_resource *mirror)
    {
        auto &attempt = object<Attempt>(resource);
        try {
            const auto *native = headFor(attempt, head);
            const auto *source = mirror ? headFor(attempt, mirror) : nullptr;
            if (!native || (mirror && !source)) {
                attempt.deny();
                return;
            }
            const auto key = native->captured->sample.heads[native->index].key;
            Target target{key, true, Mode{width, height, refresh}, scale, transform, x, y, {}};
            if (source)
                target.mirror = source->captured->sample.heads[source->index].key;
            if (!attempt.targets.emplace(key, target).second)
                attempt.deny();
        } catch (...) {
            wl_client_post_no_memory(client);
        }
    }
    static void disable(wl_client *client, wl_resource *resource, wl_resource *head)
    {
        auto &attempt = object<Attempt>(resource);
        try {
            const auto *native = headFor(attempt, head);
            if (!native) {
                attempt.deny();
                return;
            }
            Target target;
            target.output = native->captured->sample.heads[native->index].key;
            if (!attempt.targets.emplace(target.output, target).second)
                attempt.deny();
        } catch (...) {
            wl_client_post_no_memory(client);
        }
    }
    static void apply(wl_client *client, wl_resource *resource)
    {
        auto &attempt = object<Attempt>(resource);
        if (attempt.used || attempt.invalid || !attempt.captured ||
            attempt.owner.origins.contains(attempt.bound.transaction)) {
            attempt.deny();
            return;
        }
        attempt.used = true; // Before constructing a potentially effectful call.
        try {
            Layout baseline, desired;
            for (const auto &head : attempt.captured->sample.heads)
                baseline.push_back(head.current);
            for (const auto &[key, target] : attempt.targets) {
                (void)key;
                desired.push_back(target);
            }
            if (!DisplayTransaction::validLayout(desired, attempt.captured->sample)) {
                attempt.deny();
                return;
            }
            if (attempt.owner.origins.size() >= CompositorDisplayService::MaxReservations) {
                attempt.deny();
                return;
            }
            attempt.owner.origins.emplace(attempt.bound.transaction, attempt.client);
            (void)attempt.owner.service.begin(attempt.bound, baseline, desired,
                                              attempt.captured->sample, attempt.captured->at);
            if (!attempt.owner.service.status(attempt.bound))
                attempt.owner.origins.erase(attempt.bound.transaction);
            attempt.status();
        } catch (...) {
            // A retained reservation remains queryable. Memory/transport loss
            // after entry never becomes a definite pre-dispatch rejection.
            wl_client_post_no_memory(client);
        }
    }
    static void confirm(wl_client *, wl_resource *resource)
    {
        auto &attempt = object<Attempt>(resource);
        if (attempt.invalid || !attempt.original()) {
            attempt.deny();
            return;
        }
        (void)attempt.owner.service.confirm(attempt.bound);
        attempt.status();
    }
    static void restore(wl_client *, wl_resource *resource)
    {
        auto &attempt = object<Attempt>(resource);
        if (attempt.invalid || !attempt.original()) {
            attempt.deny();
            return;
        }
        (void)attempt.owner.service.restore(attempt.bound);
        attempt.status();
    }
    static void status(wl_client *, wl_resource *resource)
    {
        object<Attempt>(resource).status();
    }
    static const struct linura_display_manager_v1_interface managerImplementation;
    static const struct linura_display_snapshot_v1_interface snapshotImplementation;
    static const struct linura_display_head_v1_interface headImplementation;
    static const struct linura_display_attempt_v1_interface attemptImplementation;
};
const struct linura_display_manager_v1_interface WireEndpoint::Impl::managerImplementation
{
    release, snapshot, attempt
};
const struct linura_display_snapshot_v1_interface WireEndpoint::Impl::snapshotImplementation
{
    release
};
const struct linura_display_head_v1_interface WireEndpoint::Impl::headImplementation
{
    release
};
const struct linura_display_attempt_v1_interface WireEndpoint::Impl::attemptImplementation
{
    release, configure, enable, disable, apply, confirm, restore, status
};

WireEndpoint::WireEndpoint(wl_display &display, Backend &backend, CompositorDisplayService &service,
                           NativeBuildIdentity identity, OutputName names)
    : impl_(
          std::make_unique<Impl>(display, backend, service, std::move(identity), std::move(names)))
{}
WireEndpoint::~WireEndpoint() = default;
bool WireEndpoint::available() const noexcept
{
    return impl_->global != nullptr;
}

} // namespace Linura::HyprlandDisplay
