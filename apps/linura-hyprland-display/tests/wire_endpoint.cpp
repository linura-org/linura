#include "wire_endpoint.h"
#include "linura-display-management-v1-client-protocol.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstring>
#include <mutex>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <wayland-client.h>
#include <wayland-server-core.h>

using namespace Linura::HyprlandDisplay;

namespace {
class NativeFixture final : public Backend
{
  public:
    std::mutex mutex;
    const Mode full{1920, 1080, 60'000}, small{1280, 720, 60'000};
    Snapshot facts{1,
                   1,
                   {{OutputKey{1, 1},
                     {full, small},
                     Target{OutputKey{1, 1}, true, full, 1000, 0, 0, 0, {}},
                     true,
                     false}},
                   Coverage::Unlocked};
    std::atomic<int> writes{0};
    std::optional<ClockSample> clock() override
    {
        return compositorClock();
    }
    std::optional<Snapshot> snapshot() override
    {
        const std::lock_guard guard(mutex);
        return facts;
    }
    bool applyOwnedLayout(const Layout &layout, const Snapshot &expected) override
    {
        const std::lock_guard guard(mutex);
        assert(facts.generation == expected.generation);
        ++writes;
        facts.heads[0].current = layout[0];
        return true;
    }
};
class Harness final
{
  public:
    NativeFixture native;
    wl_display *display = wl_display_create();
    std::unique_ptr<CompositorDisplayService> service;
    std::unique_ptr<WireEndpoint> endpoint;
    std::vector<int> connections;
    std::atomic<bool> stop{false};
    std::thread server;
    Harness()
    {
        assert(display);
        auto *loop = wl_display_get_event_loop(display);
        service = std::make_unique<CompositorDisplayService>(*loop, native);
        endpoint = std::make_unique<WireEndpoint>(
            *display, native, *service,
            NativeBuildIdentity{"74e3ca24-b38b-4b62-9671-ae32dc38fd57", std::string(40, 'a'),
                                std::string(64, 'b')},
            [](OutputKey key) -> std::optional<std::string> {
                return key == OutputKey{1, 1} ? std::optional<std::string>("fixture-output")
                                              : std::nullopt;
            });
        assert(endpoint->available());
        // Create server resources before starting its event thread. Two native
        // connections have identical kernel UID/PID but different ownership.
        for (int i = 0; i != 3; ++i) {
            int pair[2];
            assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
            assert(wl_client_create(display, pair[0]));
            connections.push_back(pair[1]);
        }
        server = std::thread([this, loop] {
            while (!stop.load()) {
                assert(wl_event_loop_dispatch(loop, 10) == 0);
                wl_display_flush_clients(display);
            }
        });
    }
    ~Harness()
    {
        stop.store(true);
        server.join();
        wl_display_destroy_clients(display);
        endpoint.reset();
        service.reset();
        wl_display_destroy(display);
    }
};
struct Head final
{
    linura_display_head_v1 *wire = nullptr;
    std::vector<Mode> modes;
};
struct SnapshotData final
{
    linura_display_snapshot_v1 *wire = nullptr;
    std::vector<std::unique_ptr<Head>> heads;
    bool done = false, unavailable = false;
};
struct Attempt final
{
    linura_display_attempt_v1 *wire = nullptr;
    std::uint32_t phase = 99;
};
class Client final
{
  public:
    wl_display *display;
    wl_registry *registry;
    linura_display_manager_v1 *manager = nullptr;
    std::vector<std::unique_ptr<SnapshotData>> snapshots;
    std::vector<std::unique_ptr<Attempt>> attempts;
    explicit Client(int descriptor)
        : display(wl_display_connect_to_fd(descriptor)), registry(nullptr)
    {
        assert(display);
        registry = wl_display_get_registry(display);
        static const wl_registry_listener listener{
            [](void *data, wl_registry *registry, std::uint32_t name, const char *interface,
               std::uint32_t) {
                auto &self = *static_cast<Client *>(data);
                if (std::strcmp(interface, "linura_display_manager_v1") == 0)
                    self.manager = static_cast<linura_display_manager_v1 *>(
                        wl_registry_bind(registry, name, &linura_display_manager_v1_interface, 1));
            },
            [](void *, wl_registry *, std::uint32_t) {}};
        wl_registry_add_listener(registry, &listener, this);
        sync();
        assert(manager);
    }
    ~Client()
    {
        close();
    }
    void close()
    {
        if (!display)
            return;
        for (const auto &attempt : attempts)
            linura_display_attempt_v1_destroy(attempt->wire);
        for (const auto &snapshot : snapshots) {
            for (const auto &head : snapshot->heads)
                linura_display_head_v1_destroy(head->wire);
            linura_display_snapshot_v1_destroy(snapshot->wire);
        }
        linura_display_manager_v1_destroy(manager);
        wl_registry_destroy(registry);
        (void)wl_display_flush(display);
        wl_display_disconnect(display);
        display = nullptr;
    }
    void sync()
    {
        assert(wl_display_roundtrip(display) >= 0);
    }
    SnapshotData &snapshot()
    {
        auto sample = std::make_unique<SnapshotData>();
        sample->wire = linura_display_manager_v1_get_snapshot(manager);
        static const linura_display_head_v1_listener headListener{
            [](void *data, linura_display_head_v1 *, std::int32_t width, std::int32_t height,
               std::int32_t refresh) {
                static_cast<Head *>(data)->modes.push_back({width, height, refresh});
            },
            [](void *, linura_display_head_v1 *, std::uint32_t, std::int32_t, std::int32_t,
               std::int32_t, std::uint32_t, std::uint32_t, std::uint32_t, std::int32_t,
               std::int32_t, std::uint32_t, std::uint32_t) {},
            [](void *, linura_display_head_v1 *, std::uint32_t, std::uint32_t, std::uint32_t,
               std::uint32_t) {},
            [](void *, linura_display_head_v1 *) {}};
        static const linura_display_snapshot_v1_listener listener{
            [](void *, linura_display_snapshot_v1 *, const char *, const char *, const char *,
               std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t,
               std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t) {},
            [](void *data, linura_display_snapshot_v1 *, linura_display_head_v1 *wire,
               std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t, const char *) {
                auto head = std::make_unique<Head>();
                head->wire = wire;
                linura_display_head_v1_add_listener(wire, &headListener, head.get());
                static_cast<SnapshotData *>(data)->heads.push_back(std::move(head));
            },
            [](void *data, linura_display_snapshot_v1 *) {
                static_cast<SnapshotData *>(data)->done = true;
            },
            [](void *data, linura_display_snapshot_v1 *) {
                static_cast<SnapshotData *>(data)->unavailable = true;
            }};
        linura_display_snapshot_v1_add_listener(sample->wire, &listener, sample.get());
        snapshots.push_back(std::move(sample));
        sync();
        auto &result = *snapshots.back();
        assert(result.done && !result.unavailable && result.heads.size() == 1);
        assert(result.heads[0]->modes.size() == 2);
        return result;
    }
    Attempt &attempt(const Correlation &correlation)
    {
        auto result = std::make_unique<Attempt>();
        result->wire = linura_display_manager_v1_get_attempt(
            manager, correlation.transaction.c_str(), correlation.effectDigest.c_str(),
            correlation.dispatchDigest.c_str(),
            static_cast<std::uint32_t>(correlation.deadlineUnixMs >> 32U),
            static_cast<std::uint32_t>(correlation.deadlineUnixMs & 0xffffffffU));
        static const linura_display_attempt_v1_listener listener{
            [](void *data, linura_display_attempt_v1 *, std::uint32_t phase) {
                static_cast<Attempt *>(data)->phase = phase;
            }};
        linura_display_attempt_v1_add_listener(result->wire, &listener, result.get());
        attempts.push_back(std::move(result));
        sync();
        return *attempts.back();
    }
    void configure(Attempt &attempt, SnapshotData &sample, linura_display_head_v1 *head = nullptr)
    {
        linura_display_attempt_v1_configure(attempt.wire, sample.wire);
        linura_display_attempt_v1_enable_head(attempt.wire, head ? head : sample.heads[0]->wire,
                                              1280, 720, 60'000, 1000, 0, 0, 0, nullptr);
        sync();
    }
};
Correlation correlation(const char *name, std::uint64_t window = 5000)
{
    return {name, std::string(64, 'c'), std::string(64, 'd'), compositorClock()->unixMs + window};
}
void ownershipAndOneUse()
{
    Harness server;
    Client owner(server.connections[0]), other(server.connections[1]), third(server.connections[2]);
    auto &sample = owner.snapshot();
    auto bound = correlation("transaction:wire-owner");
    auto &attempt = owner.attempt(bound);
    owner.configure(attempt, sample);
    assert(server.native.writes.load() == 0); // Staging never dispatches.
    linura_display_attempt_v1_apply(attempt.wire);
    owner.sync();
    assert(attempt.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_PENDING &&
           server.native.writes.load() == 1);
    auto &copied = other.attempt(bound);
    linura_display_attempt_v1_confirm(copied.wire);
    other.sync();
    assert(copied.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_DENIED &&
           server.native.writes.load() == 1);
    // Same connection may recover its lost resource/reply, without re-applying.
    auto &continued = owner.attempt(bound);
    linura_display_attempt_v1_confirm(continued.wire);
    owner.sync();
    assert(continued.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_CONFIRMED);
    linura_display_attempt_v1_apply(attempt.wire);
    owner.sync();
    assert(server.native.writes.load() == 1);
    auto substituted = bound;
    substituted.effectDigest[0] = 'e';
    auto &wrong = third.attempt(substituted);
    linura_display_attempt_v1_restore(wrong.wire);
    third.sync();
    assert(wrong.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_DENIED &&
           server.native.writes.load() == 1);
}
void staleAndCrossSnapshotAreRejected()
{
    Harness server;
    Client client(server.connections[0]), other(server.connections[1]),
        third(server.connections[2]);
    auto &one = client.snapshot();
    auto &two = client.snapshot();
    auto &wrong = client.attempt(correlation("transaction:wire-cross-snapshot"));
    client.configure(wrong, one, two.heads[0]->wire);
    linura_display_attempt_v1_apply(wrong.wire);
    client.sync();
    assert(wrong.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_DENIED &&
           server.native.writes.load() == 0);
    auto &stale = other.snapshot();
    auto &attempt = other.attempt(correlation("transaction:wire-stale-generation"));
    other.configure(attempt, stale);
    {
        const std::lock_guard guard(server.native.mutex);
        ++server.native.facts.generation;
    }
    linura_display_attempt_v1_apply(attempt.wire);
    other.sync();
    assert(attempt.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_REJECTED_BEFORE_DISPATCH &&
           server.native.writes.load() == 0);
}
void disconnectRetainsIndependentRestoration()
{
    Harness server;
    Client owner(server.connections[0]), observer(server.connections[1]),
        third(server.connections[2]);
    auto &sample = owner.snapshot();
    const auto bound = correlation("transaction:wire-disconnect", 750);
    auto &attempt = owner.attempt(bound);
    owner.configure(attempt, sample);
    linura_display_attempt_v1_apply(attempt.wire);
    owner.sync();
    assert(attempt.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_PENDING &&
           server.native.writes.load() == 1);
    owner.close();
    auto &status = observer.attempt(bound);
    const auto deadline = compositorClock()->bootMs + 3000;
    while (status.phase != LINURA_DISPLAY_ATTEMPT_V1_PHASE_RESTORED &&
           compositorClock()->bootMs < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        linura_display_attempt_v1_get_status(status.wire);
        observer.sync();
    }
    assert(status.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_RESTORED &&
           server.native.writes.load() == 2);
    const auto facts = server.native.snapshot();
    assert(facts && facts->heads[0].current.mode == server.native.full);
    linura_display_attempt_v1_apply(status.wire);
    observer.sync();
    assert(server.native.writes.load() == 2);
}
} // namespace
int main()
{
    ownershipAndOneUse();
    staleAndCrossSnapshotAreRejected();
    disconnectRetainsIndependentRestoration();
}
