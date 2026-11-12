#include "protected_wire.h"
#include "linura-protected-display-v1-client-protocol.h"
#include "wire_scene_fixture.h"
#include "wire_endpoint.h"
#include "startup_fence.h"
#include "linura-display-management-v1-client-protocol.h"

#include <atomic>
#include <cassert>
#include <cerrno>
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
    bool inhibited = false;
    bool restoredOwnedState() override
    {
        return true;
    }
    bool restoreOwnedLayout(const Layout &layout, const Snapshot &expected) override
    {
        return applyOwnedLayout(layout, expected);
    }
    [[nodiscard]] bool inhibitPowerTransitions() override
    {
        assert(!inhibited);
        return inhibited = true;
    }
    void releasePowerInhibitor() noexcept override
    {
        assert(inhibited);
        inhibited = false;
    }
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
    std::unique_ptr<ProtectedWireEndpoint> protectedEndpoint;
    std::vector<int> connections;
    std::atomic<bool> stop{false};
    std::atomic<unsigned char> admittedInvocation{1};
    std::atomic<unsigned> originalDispatches{0};
    StartupFence startup;
    std::thread server;
    explicit Harness(int connectionCount = 3, bool startupFixture = false)
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
            },
            [this](pid_t pid, uid_t uid) -> std::optional<WireEndpoint::OwnerInvocation> {
                assert(pid == getpid() && uid == getuid());
                const auto value = admittedInvocation.load();
                if (value == 0)
                    return std::nullopt;
                WireEndpoint::OwnerInvocation invocation{};
                invocation[0] = value;
                return invocation;
            },
            NativeStartupPort{
                [this, startupFixture] { return startupFixture ? startup.phase() : 1U; },
                [this, startupFixture](int fd, bool ordinary, std::uint32_t guardPid) {
                    // Portable transport fixture only, not root peer/native
                    // startup evidence. Production separately requires root.
                    return startupFixture && guardPid == static_cast<std::uint32_t>(getpid()) &&
                           startup.retain(fd, ordinary);
                }},
            NativeOriginalRestorationPort{
                [this](OwnedNativeFd, const Correlation &, const Layout &, const Snapshot &,
                       ClockSample, wl_resource *, wl_client *) -> std::optional<std::uint32_t> {
                    ++originalDispatches;
                    return std::nullopt; // No original Root grant in this portable fixture.
                },
                [](const Correlation &) -> std::optional<std::uint32_t> { return std::nullopt; },
                []() -> std::optional<std::string> { return std::nullopt; },
                []() -> std::optional<std::string> { return std::nullopt; },
                []() -> std::optional<std::string> { return std::nullopt; }});
        assert(endpoint->available());
        protectedEndpoint = std::make_unique<ProtectedWireEndpoint>(
            *display,
            [this](pid_t pid, uid_t uid) -> std::optional<WireEndpoint::OwnerInvocation> {
                assert(pid == getpid() && uid == getuid());
                WireEndpoint::OwnerInvocation invocation{};
                invocation[0] = admittedInvocation.load();
                if (invocation[0] == 0)
                    return std::nullopt;
                return invocation;
            },
            [](const ProtectedInteraction::Scope &) {
                return std::make_unique<Test::WireSceneFixture>();
            });
        assert(protectedEndpoint->available());
        // Create server resources before starting its event thread. Two native
        // connections have identical kernel UID/PID but different ownership.
        for (int i = 0; i != connectionCount; ++i) {
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
        protectedEndpoint.reset();
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
    bool done = false, unavailable = false, fenced = true;
    std::uint32_t startupPhase = 99;
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
    linura_protected_display_manager_v1 *protectedManager = nullptr;
    std::vector<linura_protected_display_interaction_v1 *> protections;
    linura_display_manager_v1 *manager = nullptr;
    std::vector<std::unique_ptr<SnapshotData>> snapshots;
    std::vector<std::unique_ptr<Attempt>> attempts;
    explicit Client(int descriptor, bool expectAccepted = true)
        : display(wl_display_connect_to_fd(descriptor)), registry(nullptr)
    {
        assert(display);
        registry = wl_display_get_registry(display);
        static const wl_registry_listener listener{
            [](void *data, wl_registry *registry, std::uint32_t name, const char *interface,
               std::uint32_t) {
                auto &self = *static_cast<Client *>(data);
                if (std::strcmp(interface, "linura_protected_display_manager_v1") == 0) {
                    auto &owner = *static_cast<Client *>(data);
                    owner.protectedManager =
                        static_cast<linura_protected_display_manager_v1 *>(wl_registry_bind(
                            registry, name, &linura_protected_display_manager_v1_interface, 1));
                }
                if (std::strcmp(interface, "linura_display_manager_v1") == 0)
                    self.manager = static_cast<linura_display_manager_v1 *>(
                        wl_registry_bind(registry, name, &linura_display_manager_v1_interface, 1));
            },
            [](void *, wl_registry *, std::uint32_t) {}};
        wl_registry_add_listener(registry, &listener, this);
        auto result = wl_display_roundtrip(display);
        if (expectAccepted) {
            assert(result >= 0);
        } else {
            // The registry callback queues bind after get_registry. Depending
            // on event batching its denial may arrive on either roundtrip.
            if (result >= 0)
                result = wl_display_roundtrip(display);
            assert(result < 0 && wl_display_get_error(display) == EPROTO);
            assert(wl_display_get_protocol_error(display, nullptr, nullptr) ==
                   WL_DISPLAY_ERROR_IMPLEMENTATION);
        }
        assert(manager);
    }
    linura_protected_display_interaction_v1 *protection(bool consume = true)
    {
        const auto now = compositorClock();
        assert(now && protectedManager);
        const std::string scope(64, 'e');
        const auto wall = now->unixMs + 10'000, boot = now->bootMs + 10'000;
        auto *scene = linura_protected_display_manager_v1_begin(
            protectedManager, scope.c_str(), 0, static_cast<std::uint32_t>(wall >> 32U),
            static_cast<std::uint32_t>(wall), static_cast<std::uint32_t>(boot >> 32U),
            static_cast<std::uint32_t>(boot));
        assert(scene);
        static const linura_protected_display_interaction_v1_listener listener{
            [](void *, linura_protected_display_interaction_v1 *, const char *, std::uint32_t,
               std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t) {},
            [](void *, linura_protected_display_interaction_v1 *) {}};
        linura_protected_display_interaction_v1_add_listener(scene, &listener, nullptr);
        if (consume)
            linura_protected_display_interaction_v1_consume(scene, scope.c_str(), 0, 1);
        protections.push_back(scene);
        return scene;
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
        discardSnapshots();
        for (auto *scene : protections)
            linura_protected_display_interaction_v1_destroy(scene);
        protections.clear();
        if (protectedManager)
            linura_protected_display_manager_v1_destroy(protectedManager);
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
    void discardSnapshots()
    {
        for (const auto &snapshot : snapshots) {
            for (const auto &head : snapshot->heads)
                linura_display_head_v1_destroy(head->wire);
            linura_display_snapshot_v1_destroy(snapshot->wire);
        }
        snapshots.clear();
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
            [](void *, linura_display_head_v1 *, std::uint32_t, const char *, const char *,
               const char *) {},
            [](void *, linura_display_head_v1 *) {}};
        static const linura_display_snapshot_v1_listener listener{
            [](void *data, linura_display_snapshot_v1 *, const char *, const char *, const char *,
               std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t,
               std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t, std::uint32_t fenced,
               std::uint32_t startup) {
                auto &sample = *static_cast<SnapshotData *>(data);
                sample.fenced = fenced != 0;
                sample.startupPhase = startup;
            },
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
            },
            [](void *, linura_display_snapshot_v1 *, const char *) {
                assert(false && "portable fixture cannot attest original restoration");
            },
            [](void *, linura_display_snapshot_v1 *, const char *) {
                assert(false && "portable fixture cannot attest native handoff");
            },
            [](void *, linura_display_snapshot_v1 *, const char *) {
                assert(false && "portable fixture cannot attest current scanout");
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
    linura_display_attempt_v1_apply(attempt.wire, owner.protection());
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
    linura_display_attempt_v1_apply(attempt.wire, owner.protection());
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
    linura_display_attempt_v1_apply(wrong.wire, client.protection());
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
    linura_display_attempt_v1_apply(attempt.wire, other.protection());
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
    linura_display_attempt_v1_apply(attempt.wire, owner.protection());
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
    linura_display_attempt_v1_apply(status.wire, observer.protection());
    observer.sync();
    assert(server.native.writes.load() == 2);
}
void admissionDenialCannotWriteOrRetry()
{
    Harness server;
    Client client(server.connections[0]);
    auto &sample = client.snapshot(); // Read-only evidence needs no mutation admission.
    auto &attempt = client.attempt(correlation("transaction:wire-unattested"));
    client.configure(attempt, sample);
    server.admittedInvocation.store(0);
    linura_display_attempt_v1_apply(attempt.wire, client.protection());
    client.sync();
    assert(attempt.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_DENIED);
    assert(server.native.writes.load() == 0);
    server.admittedInvocation.store(1);
    linura_display_attempt_v1_apply(attempt.wire, client.protection());
    client.sync();
    assert(attempt.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_DENIED);
    assert(server.native.writes.load() == 0);
}
void rejectedBindingsCannotExhaustProtectedOwnerSlots()
{
    Harness server(12);
    server.admittedInvocation.store(0);
    // More refused clients than the server's entire eight-client capacity.
    // Their kernel UID and PID match this fixture, so only native admission
    // distinguishes them. No mutation request or snapshot is necessary.
    for (std::size_t i = 0; i < 11; ++i) {
        Client rejected(server.connections[i], false);
        assert(server.native.writes.load() == 0);
    }
    server.admittedInvocation.store(1);
    Client admitted(server.connections.back());
    auto &sample = admitted.snapshot();
    auto &attempt = admitted.attempt(correlation("transaction:wire-admitted-after-denials"));
    admitted.configure(attempt, sample);
    linura_display_attempt_v1_apply(attempt.wire, admitted.protection());
    admitted.sync();
    assert(attempt.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_PENDING &&
           server.native.writes.load() == 1);
    linura_display_attempt_v1_confirm(attempt.wire);
    admitted.sync();
    assert(attempt.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_CONFIRMED);
}
void changedInvocationCannotInheritAnAdmittedConnection()
{
    Harness server;
    Client client(server.connections[0]);
    auto &sample = client.snapshot();
    auto &attempt = client.attempt(correlation("transaction:wire-replaced-before-apply"));
    client.configure(attempt, sample);
    server.admittedInvocation.store(2);
    linura_display_attempt_v1_apply(attempt.wire, client.protection());
    client.sync();
    assert(attempt.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_DENIED &&
           server.native.writes.load() == 0);
}
void changedOrUnavailableOwnerCannotDecideButTimerRecovers()
{
    for (const auto replacement : {0U, 2U}) {
        Harness server;
        Client owner(server.connections[0]), observer(server.connections[1]);
        observer.sync(); // Admit this observation connection before revocation.
        auto &sample = owner.snapshot();
        const auto bound = correlation("transaction:wire-owner-replaced", 750);
        auto &attempt = owner.attempt(bound);
        owner.configure(attempt, sample);
        linura_display_attempt_v1_apply(attempt.wire, owner.protection());
        owner.sync();
        assert(attempt.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_PENDING &&
               server.native.writes.load() == 1);
        server.admittedInvocation.store(static_cast<unsigned char>(replacement));
        linura_display_attempt_v1_confirm(attempt.wire);
        owner.sync();
        assert(attempt.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_DENIED);
        // Recovering another resource on the SAME original connection cannot
        // substitute a replacement invocation or bypass service unavailability.
        auto &restoring = owner.attempt(bound);
        linura_display_attempt_v1_restore(restoring.wire);
        owner.sync();
        assert(restoring.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_DENIED &&
               server.native.writes.load() == 1);
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
    }
}
void unconsumedOrReusedSceneCannotDispatch()
{
    Harness server;
    Client owner(server.connections[0]);
    auto &sample = owner.snapshot();
    auto &denied = owner.attempt(correlation("transaction:unconsumed-scene"));
    owner.configure(denied, sample);
    auto *unconsumed = owner.protection(false);
    linura_display_attempt_v1_apply(denied.wire, unconsumed);
    owner.sync();
    assert(denied.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_DENIED && server.native.writes == 0);
    const std::string digest(64, 'e');
    linura_protected_display_interaction_v1_consume(unconsumed, digest.c_str(), 0, 1);
    linura_display_attempt_v1_apply(denied.wire, unconsumed);
    owner.sync();
    assert(denied.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_DENIED && server.native.writes == 0);

    auto &accepted = owner.attempt(correlation("transaction:consumed-scene"));
    owner.configure(accepted, sample);
    linura_display_attempt_v1_apply(accepted.wire, unconsumed);
    owner.sync();
    assert(accepted.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_PENDING && server.native.writes == 1);
    linura_display_attempt_v1_confirm(accepted.wire);
    owner.sync();
    assert(accepted.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_CONFIRMED);
    auto &fresh = owner.snapshot();
    auto &reused = owner.attempt(correlation("transaction:reused-scene"));
    owner.configure(reused, fresh);
    linura_display_attempt_v1_apply(reused.wire, unconsumed);
    owner.sync();
    assert(reused.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_DENIED && server.native.writes == 1);
}
} // namespace
void startupTransferIsOriginalOneUseAndNeverAWrite()
{
    for (const bool ordinary : {false, true}) {
        Harness server(1, true);
        Client owner(server.connections[0]);
        const auto &initial = owner.snapshot();
        assert(initial.done && initial.fenced && initial.startupPhase == 0);
        owner.discardSnapshots();
        int lease[2]{};
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, lease) == 0);
        linura_display_manager_v1_admit_startup(owner.manager, lease[0], ordinary ? 1U : 0U,
                                                static_cast<std::uint32_t>(getpid()),
                                                "a12ae886-0dd7-48de-ab8c-d42dc17e2389");
        owner.sync();
        assert(owner.snapshot().startupPhase == 0); // Cannot transfer between invocations.
        owner.discardSnapshots();
        linura_display_manager_v1_admit_startup(owner.manager, lease[0], ordinary ? 1U : 0U,
                                                static_cast<std::uint32_t>(getpid()),
                                                "74e3ca24-b38b-4b62-9671-ae32dc38fd57");
        owner.sync();
        assert(close(lease[0]) == 0); // Receiver owns its independent original reference.
        const auto &admitted = owner.snapshot();
        assert(admitted.startupPhase == (ordinary ? 1U : 2U) && admitted.fenced == !ordinary);
        owner.discardSnapshots();
        int replacement[2]{};
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, replacement) == 0);
        linura_display_manager_v1_admit_startup(owner.manager, replacement[0], 1,
                                                static_cast<std::uint32_t>(getpid()),
                                                "74e3ca24-b38b-4b62-9671-ae32dc38fd57");
        owner.sync();
        assert(owner.snapshot().startupPhase == (ordinary ? 1U : 2U));
        owner.discardSnapshots();
        assert(close(lease[1]) == 0);
        const auto &lost = owner.snapshot();
        assert(lost.startupPhase == 3 && lost.fenced);
        owner.discardSnapshots();
        linura_display_manager_v1_admit_startup(owner.manager, replacement[0], 1,
                                                static_cast<std::uint32_t>(getpid()),
                                                "74e3ca24-b38b-4b62-9671-ae32dc38fd57");
        owner.sync();
        assert(owner.snapshot().startupPhase == 3 && server.native.writes == 0);
        assert(close(replacement[0]) == 0 && close(replacement[1]) == 0);
    }
}
void originalRestorationNeverBorrowsOrdinaryAdmissionOrReplays()
{
    for (unsigned fault = 0; fault < 5; ++fault) {
        Harness server(3, true);
        Client owner(server.connections[0]);
        (void)owner.snapshot();
        owner.discardSnapshots();
        int lease[2]{}, grant[2]{};
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, lease) == 0);
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, grant) == 0);
        // The fixture models only phase/transport routing, never Root admission.
        linura_display_manager_v1_admit_startup(owner.manager, lease[0], fault == 1 ? 1U : 0U,
                                                static_cast<std::uint32_t>(getpid()),
                                                "74e3ca24-b38b-4b62-9671-ae32dc38fd57");
        owner.sync();
        close(lease[0]);
        auto &sample = owner.snapshot();
        const auto bound = correlation("transaction:wire-original");
        auto &attempt = owner.attempt(bound);
        if (fault != 2) {
            if (fault == 3)
                linura_display_attempt_v1_configure(attempt.wire, sample.wire);
            else
                owner.configure(attempt, sample);
        }
        if (fault == 4)
            server.admittedInvocation.store(2);
        linura_display_attempt_v1_restore_original(attempt.wire, grant[0], owner.protection());
        close(grant[0]);
        owner.sync();
        assert(attempt.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_DENIED);
        assert(server.originalDispatches == (fault == 0 ? 1U : 0U));
        assert(server.native.writes == 0);
        char byte = 0;
        assert(recv(grant[1], &byte, 1, MSG_DONTWAIT) == 0); // FD closed on every refusal.
        close(grant[1]);
        server.admittedInvocation.store(1);
        auto &again = owner.attempt(bound);
        owner.configure(again, sample);
        int replay[2]{};
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, replay) == 0);
        if (fault == 0) {
            linura_display_attempt_v1_restore_original(again.wire, replay[0], owner.protection());
            owner.sync();
            assert(again.phase == LINURA_DISPLAY_ATTEMPT_V1_PHASE_DENIED);
            assert(server.originalDispatches == 1); // New object cannot redeliver.
        }
        linura_display_attempt_v1_apply(attempt.wire, owner.protection());
        owner.sync();
        assert(server.native.writes == 0);
        close(replay[0]);
        close(replay[1]);
        close(lease[1]);
    }
}
int main()
{
    originalRestorationNeverBorrowsOrdinaryAdmissionOrReplays();
    startupTransferIsOriginalOneUseAndNeverAWrite();
    ownershipAndOneUse();
    staleAndCrossSnapshotAreRejected();
    disconnectRetainsIndependentRestoration();
    admissionDenialCannotWriteOrRetry();
    rejectedBindingsCannotExhaustProtectedOwnerSlots();
    changedInvocationCannotInheritAnAdmittedConnection();
    changedOrUnavailableOwnerCannotDecideButTimerRecovers();
    unconsumedOrReusedSceneCannotDispatch();
}
