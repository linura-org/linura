// Real private protocol client/server component fixture. No native session,
// root peer, prepared authority, actual compositor or qualification is simulated
// into a support claim by this test.
#include "native_display_connection.h"
#include "native_wayland_readiness.h"
#include "wire_endpoint.h"
#include "linura-display-integration-build.h"
#include <atomic>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <cassert>
#include <chrono>
#include <cstring>
#include <mutex>
#include <thread>
#include <sys/socket.h>
#include <unistd.h>
#include <wayland-client.h>
#include <wayland-server-core.h>

using namespace Linura::SecurityOwner;
using namespace Linura::HyprlandDisplay;
using namespace std::chrono_literals;

namespace {
constexpr char Instance[] = "74e3ca24-b38b-4b62-9671-ae32dc38fd57";
class Fixture final : public Backend
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
    std::atomic<unsigned> writes{0};
    bool inhibited = false;
    bool restoredOwnedState() override
    {
        return true;
    }
    bool restoreOwnedLayout(const Layout &layout, const Snapshot &expected) override
    {
        return applyOwnedLayout(layout, expected);
    }
    std::optional<ClockSample> clock() override
    {
        return compositorClock();
    }
    std::optional<Snapshot> snapshot() override
    {
        const std::lock_guard lock(mutex);
        return facts;
    }
    bool inhibitPowerTransitions() override
    {
        assert(!inhibited);
        return inhibited = true;
    }
    void releasePowerInhibitor() noexcept override
    {
        assert(inhibited);
        inhibited = false;
    }
    bool applyOwnedLayout(const Layout &layout, const Snapshot &expected) override
    {
        const std::lock_guard lock(mutex);
        assert(inhibited && facts.generation == expected.generation);
        facts.heads[0].current = layout[0];
        ++writes;
        return true;
    }
};
class Harness final
{
  public:
    Fixture backend;
    wl_display *display = wl_display_create();
    std::unique_ptr<CompositorDisplayService> service;
    std::unique_ptr<WireEndpoint> endpoint;
    std::vector<int> descriptors;
    std::atomic<bool> stopped{false};
    std::thread worker;
    enum class BuildMismatch { None, Upstream, SourceRecipe };
    explicit Harness(BuildMismatch mismatch = BuildMismatch::None)
    {
        assert(display);
        auto *loop = wl_display_get_event_loop(display);
        service = std::make_unique<CompositorDisplayService>(*loop, backend);
        endpoint = std::make_unique<WireEndpoint>(
            *display, backend, *service,
            NativeBuildIdentity{Instance,
                                mismatch == BuildMismatch::Upstream
                                    ? std::string(40, 'a')
                                    : "efb50993780079460b0cbed1363e2166a2de1d9f",
                                mismatch == BuildMismatch::SourceRecipe ? std::string(64, 'a')
                                                                        : IntegrationSourceDigest},
            [](OutputKey key) -> std::optional<std::string> {
                if (key == OutputKey{1, 1})
                    return "DP-1";
                if (key == OutputKey{2, 1})
                    return "HDMI-A-1";
                return std::nullopt;
            },
            [](pid_t pid, uid_t uid) -> std::optional<WireEndpoint::OwnerInvocation> {
                assert(pid == getpid() && uid == getuid());
                WireEndpoint::OwnerInvocation invocation{};
                invocation[0] = 1;
                return invocation;
            });
        assert(endpoint->available());
        for (int i = 0; i < 3; ++i) {
            int pair[2];
            assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
            assert(wl_client_create(display, pair[0]));
            descriptors.push_back(pair[1]);
        }
        worker = std::thread([this, loop] {
            while (!stopped.load()) {
                assert(wl_event_loop_dispatch(loop, 10) == 0);
                wl_display_flush_clients(display);
            }
        });
    }
    ~Harness()
    {
        stopped = true;
        worker.join();
        wl_display_destroy_clients(display);
        endpoint.reset();
        service.reset();
        wl_display_destroy(display);
    }
};
class Client final
{
  public:
    wl_display *display;
    wl_registry *registry;
    std::unique_ptr<NativeDisplayConnection> connection;
    explicit Client(int descriptor)
    {
        display = wl_display_connect_to_fd(descriptor);
        assert(display);
        connection = std::make_unique<NativeDisplayConnection>(display);
        registry = wl_display_get_registry(display);
        static const wl_registry_listener listener{
            [](void *data, wl_registry *registry, uint32_t name, const char *interface,
               uint32_t version) {
                if (std::strcmp(interface, "linura_display_manager_v1") == 0)
                    static_cast<Client *>(data)->connection->announce(registry, name, version);
            },
            [](void *data, wl_registry *, uint32_t name) {
                static_cast<Client *>(data)->connection->removed(name);
            }};
        assert(wl_registry_add_listener(registry, &listener, this) == 0);
        assert(waitForNativeWaylandReady(display, 250ms));
        assert(connection->advertised());
    }
    ~Client()
    {
        connection.reset();
        wl_registry_destroy(registry);
        wl_display_flush(display);
        wl_display_disconnect(display);
    }
};
NativeDisplayLayout baseline(const NativePinnedDisplaySample &sample)
{
    auto layout = sample.current;
    layout.topology = QStringLiteral("display:topology:11111111-1111-4111-8111-111111111111:") +
                      QStringLiteral("1000:c2:42:seat0:") + sample.compositor + QLatin1Char(':') +
                      QString::number(sample.topology.generation);
    assert(layout.nativeOptions(sample.topology));
    return layout;
}
NativeDisplayCorrelation bound(const QString &transaction, quint64 window = 15'000)
{
    return {transaction, QString(64, QLatin1Char('a')), QString(64, QLatin1Char('b')),
            compositorClock()->unixMs + window};
}
void identityAndContinuationOwnership()
{
    Harness harness;
    Client owner(harness.descriptors[0]), observer(harness.descriptors[1]);
    auto correlation = bound(QStringLiteral("transaction:private-client"));
    const auto captured = owner.connection->sample(), other = observer.connection->sample();
    assert(captured && other && captured->compositor == other->compositor &&
           captured->topology == other->topology && captured->sampledBootMs != 0);
    auto prior = baseline(*captured), desired = prior;
    desired.outputs[0].scaleMilli = 1126; // Requires exact native float plus wlr projection.
    desired.outputs[0].x = 100;
    assert(owner.connection->apply(correlation, prior, desired) == 2);
    assert(harness.backend.writes == 1);
    assert(observer.connection->status(correlation) == 2);
    assert(!observer.connection->decide(correlation, true));
    assert(!observer.connection->apply(correlation, prior, desired));
    assert(!owner.connection->apply(correlation, prior, desired));
    auto substituted = correlation;
    substituted.dispatchDigest[0] = QLatin1Char('c');
    assert(!owner.connection->status(substituted));
    assert(owner.connection->decide(correlation, true) == 4);
    assert(!owner.connection->decide(correlation, false));
    assert(observer.connection->status(correlation) == 4 && harness.backend.writes == 1);
    const auto current = observer.connection->sample();
    assert(current && current->current.outputs[0].scaleMilli == 1126 &&
           current->topology.heads[0].scaleMilli == 1126 && !current->fenced);
}
void clientLossDoesNotDisarmNativeRecovery()
{
    Harness harness;
    const auto correlation = bound(QStringLiteral("transaction:private-client-loss"), 500);
    {
        Client owner(harness.descriptors[0]);
        const auto captured = owner.connection->sample();
        assert(captured);
        auto prior = baseline(*captured), desired = prior;
        desired.outputs[0].x = 100;
        assert(owner.connection->apply(correlation, prior, desired) == 2);
    }
    Client replacement(harness.descriptors[1]);
    assert(!replacement.connection->decide(correlation, false));
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (replacement.connection->status(correlation) != 5) {
        assert(std::chrono::steady_clock::now() < deadline);
        std::this_thread::sleep_for(10ms);
    }
    const auto restored = replacement.connection->sample();
    assert(restored && restored->current.outputs[0].x == 0 && !restored->fenced &&
           harness.backend.writes == 2);
}
void unsupportedBuildAndSubstitutedSnapshotCannotWrite()
{
    for (auto mismatch : {Harness::BuildMismatch::Upstream, Harness::BuildMismatch::SourceRecipe}) {
        Harness harness(mismatch);
        Client owner(harness.descriptors[0]);
        assert(!owner.connection->sample());
        assert(!owner.connection->sample());
        assert(harness.backend.writes == 0);
    }
    Harness harness;
    Client owner(harness.descriptors[0]);
    const auto captured = owner.connection->sample();
    assert(captured);
    auto prior = baseline(*captured), desired = prior;
    desired.outputs[0].x = 100;
    auto wrongBaseline = prior;
    wrongBaseline.outputs[0].x = -100;
    const auto correlation = bound(QStringLiteral("transaction:substituted-capture"));
    assert(!owner.connection->apply(correlation, wrongBaseline, desired));
    desired.outputs[0].generation++;
    assert(!owner.connection->apply(correlation, prior, desired));
    assert(harness.backend.writes == 0);
}
void terminalWireObjectsRetireWithoutEvictingOneUseReservations()
{
    Harness harness;
    Client owner(harness.descriptors[0]);
    for (unsigned i = 1; i <= 70; ++i) {
        // Control fixes its deadline before the executor captures native state.
        // A new full window after capture would extend the original authority.
        auto correlation = bound(QStringLiteral("transaction:bounded-%1").arg(i));
        correlation.dispatchDigest = QString::number(i, 16).rightJustified(64, QLatin1Char('0'));
        const auto captured = owner.connection->sample();
        assert(captured);
        auto prior = baseline(*captured), desired = prior;
        desired.outputs[0].x = (i % 2) ? 100 : 0;
        assert(owner.connection->apply(correlation, prior, desired) == 2);
        assert(owner.connection->decide(correlation, true) == 4);
        assert(owner.connection->status(correlation) == 4);
        assert(!owner.connection->apply(correlation, prior, desired));
    }
    assert(harness.backend.writes == 70);
}
void compositorFenceCoverageCannotBecomeOwnerSurfaceCoverage()
{
    Harness harness;
    {
        const std::lock_guard lock(harness.backend.mutex);
        harness.backend.facts.coverage = Coverage::Secure;
        harness.backend.facts.heads[0].covered = true;
        harness.backend.facts.heads.push_back({OutputKey{2, 1},
                                               {harness.backend.full, harness.backend.small},
                                               Target{OutputKey{2, 1}, false, {}, 0, 0, 0, 0, {}},
                                               false,
                                               true});
    }
    Client owner(harness.descriptors[0]);
    const auto sampled = owner.connection->sample();
    assert(sampled && sampled->coverage == 1 && sampled->topology.heads.size() == 2);
    // Actual wire decoding retains compositor fence semantics; projection must
    // discard them even for a disabled head with no wl_output/owner surface.
    assert(sampled->topology.heads[0].covered && sampled->topology.heads[1].covered &&
           !sampled->topology.heads[1].enabled);
    const auto projected = projectOwnerDisplayCoverage(sampled->topology, {{"DP-1", true}});
    assert(projected && projected->heads[0].covered && !projected->heads[1].covered);
    assert(projected->generation == sampled->topology.generation &&
           projected->heads[1].handle == sampled->topology.heads[1].handle &&
           projected->heads[1].modes == sampled->topology.heads[1].modes);
    const auto encoded = QJsonDocument::fromJson(projected->encode().toUtf8()).object();
    assert(encoded["schema"].toInt() == 2);
    const auto heads = encoded["heads"].toArray();
    assert(heads[0].toObject()["covered"].toBool() && !heads[1].toObject()["covered"].toBool());
    const auto missing = projectOwnerDisplayCoverage(sampled->topology, {});
    const auto pending = projectOwnerDisplayCoverage(sampled->topology, {{"DP-1", false}});
    assert(missing && pending && !missing->heads[0].covered && !pending->heads[0].covered &&
           !missing->heads[1].covered && !pending->heads[1].covered);
    assert(!projectOwnerDisplayCoverage(sampled->topology, {{"HDMI-A-1", true}}));
    assert(!projectOwnerDisplayCoverage(sampled->topology, {{"DP-1", true}, {"DP-1", true}}));
    assert(!projectOwnerDisplayCoverage(sampled->topology, {{"unknown-output", true}}));
    assert(!projectOwnerDisplayCoverage(sampled->topology, {{"", true}}));
    assert(harness.backend.writes == 0); // Observation cannot configure anything.
}
} // namespace
int main()
{
    identityAndContinuationOwnership();
    clientLossDoesNotDisarmNativeRecovery();
    unsupportedBuildAndSubstitutedSnapshotCannotWrite();
    terminalWireObjectsRetireWithoutEvictingOneUseReservations();
    compositorFenceCoverageCannotBecomeOwnerSurfaceCoverage();
}
