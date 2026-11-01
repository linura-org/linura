#include "protected_wire.h"
#include "linura-protected-display-v1-client-protocol.h"
#include "tests/wire_scene_fixture.h"
// Real private protocol client/server component fixture. No native session,
// root peer, prepared authority, actual compositor or qualification is simulated
// into a support claim by this test.
#include "native_display_connection.h"
#include "native_wayland_readiness.h"
#include "wire_endpoint.h"
#include "linura-display-integration-build.h"
#include <atomic>
#include <array>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCryptographicHash>
#include <cassert>
#include <chrono>
#include <cstring>
#include <mutex>
#include <limits>
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
constexpr char ReplacementInstance[] = "a12ae886-0dd7-48de-ab8c-d42dc17e2389";
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
                     false,
                     false,
                     "LNDR:1;0;",
                     "LNDF:1;0;",
                     ""}},
                   Coverage::Unlocked};
    std::atomic<unsigned> writes{0};
    std::atomic<bool> failRestore{false};
    bool inhibited = false;
    bool restoredOwnedState() override
    {
        return true;
    }
    bool restoreOwnedLayout(const Layout &layout, const Snapshot &expected) override
    {
        if (failRestore.load())
            return false;
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
    std::unique_ptr<ProtectedWireEndpoint> protectedEndpoint;
    std::vector<int> descriptors;
    std::atomic<bool> stopped{false};
    std::thread worker;
    enum class BuildMismatch { None, Upstream, SourceRecipe };
    explicit Harness(BuildMismatch mismatch = BuildMismatch::None, bool publishIntegration = true,
                     const char *instance = Instance)
    {
        assert(display);
        auto *loop = wl_display_get_event_loop(display);
        service = std::make_unique<CompositorDisplayService>(*loop, backend);
        if (publishIntegration)
            endpoint = std::make_unique<WireEndpoint>(
                *display, backend, *service,
                NativeBuildIdentity{instance,
                                    mismatch == BuildMismatch::Upstream
                                        ? std::string(40, 'a')
                                        : "efb50993780079460b0cbed1363e2166a2de1d9f",
                                    mismatch == BuildMismatch::SourceRecipe
                                        ? std::string(64, 'a')
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
        assert(!publishIntegration || (endpoint && endpoint->available()));
        protectedEndpoint = std::make_unique<ProtectedWireEndpoint>(
            *display,
            [](pid_t pid, uid_t uid) -> std::optional<WireEndpoint::OwnerInvocation> {
                assert(pid == getpid() && uid == getuid());
                WireEndpoint::OwnerInvocation invocation{};
                invocation[0] = 1;
                if (invocation[0] == 0)
                    return std::nullopt;
                return invocation;
            },
            [](const ProtectedInteraction::Scope &) {
                return std::make_unique<Test::WireSceneFixture>();
            });
        assert(protectedEndpoint->available());
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
        protectedEndpoint.reset();
        service.reset();
        wl_display_destroy(display);
    }
};
class Client final
{
  public:
    wl_display *display;
    wl_registry *registry;
    linura_protected_display_manager_v1 *protectedManager = nullptr;
    std::vector<linura_protected_display_interaction_v1 *> protections;
    std::unique_ptr<NativeDisplayConnection> connection;
    explicit Client(int descriptor, bool expectedIntegration = true)
    {
        display = wl_display_connect_to_fd(descriptor);
        assert(display);
        connection = std::make_unique<NativeDisplayConnection>(display);
        registry = wl_display_get_registry(display);
        static const wl_registry_listener listener{
            [](void *data, wl_registry *registry, uint32_t name, const char *interface,
               uint32_t version) {
                if (std::strcmp(interface, "linura_protected_display_manager_v1") == 0) {
                    auto &owner = *static_cast<Client *>(data);
                    owner.protectedManager =
                        static_cast<linura_protected_display_manager_v1 *>(wl_registry_bind(
                            registry, name, &linura_protected_display_manager_v1_interface, 1));
                }
                if (std::strcmp(interface, "linura_display_manager_v1") == 0)
                    static_cast<Client *>(data)->connection->announce(registry, name, version);
            },
            [](void *data, wl_registry *, uint32_t name) {
                static_cast<Client *>(data)->connection->removed(name);
            }};
        assert(wl_registry_add_listener(registry, &listener, this) == 0);
        assert(waitForNativeWaylandReady(display, 250ms));
        assert(connection->advertised() == expectedIntegration);
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
        for (auto *scene : protections)
            linura_protected_display_interaction_v1_destroy(scene);
        protections.clear();
        if (protectedManager)
            linura_protected_display_manager_v1_destroy(protectedManager);
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
    assert(owner.connection->securityTransitionAllowed(false));
    assert(observer.connection->securityTransitionAllowed(false));
    auto correlation = bound(QStringLiteral("transaction:private-client"));
    const auto captured = owner.connection->sample(), other = observer.connection->sample();
    assert(captured && other && captured->compositor == other->compositor &&
           captured->topology == other->topology && captured->sampledBootMs != 0);
    auto prior = baseline(*captured), desired = prior;
    desired.outputs[0].scaleMilli = 1126; // Requires exact native float plus wlr projection.
    desired.outputs[0].x = 100;
    assert(!owner.connection->apply(correlation, prior, desired, nullptr));
    assert(harness.backend.writes == 0);
    assert(owner.connection->apply(correlation, prior, desired, owner.protection()) == 2);
    assert(owner.connection->decisionBootDeadline(correlation) ==
           captured->sampledBootMs + correlation.deadlineUnixMs - captured->sampledUnixMs);
    assert(!observer.connection->decisionBootDeadline(correlation));
    assert(harness.backend.writes == 1);
    assert(!owner.connection->securityTransitionAllowed(false));
    assert(!observer.connection->securityTransitionAllowed(false));
    assert(observer.connection->status(correlation) == 2);
    assert(!observer.connection->decide(correlation, true));
    assert(!observer.connection->apply(correlation, prior, desired, observer.protection()));
    assert(!owner.connection->apply(correlation, prior, desired, owner.protection()));
    auto substituted = correlation;
    substituted.dispatchDigest[0] = QLatin1Char('c');
    assert(!owner.connection->status(substituted));
    assert(!owner.connection->decisionBootDeadline(substituted));
    assert(owner.connection->decide(correlation, true) == 4);
    assert(!owner.connection->decisionBootDeadline(correlation));
    assert(owner.connection->securityTransitionAllowed(false));
    assert(observer.connection->securityTransitionAllowed(false));
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
        assert(owner.connection->apply(correlation, prior, desired, owner.protection()) == 2);
    }
    Client replacement(harness.descriptors[1]);
    assert(!replacement.connection->securityTransitionAllowed(false));
    assert(!replacement.connection->decide(correlation, false));
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (replacement.connection->status(correlation) != 5) {
        assert(std::chrono::steady_clock::now() < deadline);
        std::this_thread::sleep_for(10ms);
    }
    const auto restored = replacement.connection->sample();
    assert(restored && restored->current.outputs[0].x == 0 && !restored->fenced &&
           harness.backend.writes == 2);
    assert(replacement.connection->securityTransitionAllowed(false));
}
void explicitRevertCannotBecomeAnotherApplyOrDecision()
{
    Harness harness;
    Client owner(harness.descriptors[0]);
    const auto correlation = bound(QStringLiteral("transaction:private-revert"));
    const auto captured = owner.connection->sample();
    assert(captured);
    auto prior = baseline(*captured), desired = prior;
    desired.outputs[0].x = 100;
    assert(owner.connection->apply(correlation, prior, desired, owner.protection()) == 2);
    assert(owner.connection->decide(correlation, false) == 3); // Acknowledged, not verified.
    assert(!owner.connection->decide(correlation, false));
    assert(!owner.connection->decide(correlation, true));
    assert(!owner.connection->apply(correlation, prior, desired, owner.protection()));
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (owner.connection->status(correlation) != 5) {
        assert(std::chrono::steady_clock::now() < deadline);
        std::this_thread::sleep_for(10ms);
    }
    const auto restored = owner.connection->sample();
    assert(restored && restored->current.outputs[0].x == 0 && !restored->fenced &&
           harness.backend.writes == 2);
}
void expiredDecisionLeavesTheIndependentNativeTimerResponsible()
{
    Harness harness;
    Client owner(harness.descriptors[0]);
    const auto correlation = bound(QStringLiteral("transaction:expired-decision"), 1000);
    const auto captured = owner.connection->sample();
    assert(captured);
    auto prior = baseline(*captured), desired = prior;
    desired.outputs[0].x = 100;
    assert(owner.connection->apply(correlation, prior, desired, owner.protection()) == 2);
    // Expiry cannot disarm or extend the timer. Both actions remain refused
    // locally even if the client has not observed the restoration reply.
    const auto expiryBudget = std::chrono::steady_clock::now() + 2s;
    while (compositorClock()->unixMs <= correlation.deadlineUnixMs) {
        assert(std::chrono::steady_clock::now() < expiryBudget);
        std::this_thread::sleep_for(10ms);
    }
    assert(!owner.connection->decide(correlation, true));
    assert(!owner.connection->decide(correlation, false));
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (owner.connection->status(correlation) != 5) {
        assert(std::chrono::steady_clock::now() < deadline);
        std::this_thread::sleep_for(10ms);
    }
    assert(harness.backend.writes == 2);
}
void unsupportedBuildAndSubstitutedSnapshotCannotWrite()
{
    for (auto mismatch : {Harness::BuildMismatch::Upstream, Harness::BuildMismatch::SourceRecipe}) {
        Harness harness(mismatch);
        Client owner(harness.descriptors[0]);
        assert(!owner.connection->sample());
        assert(!owner.connection->sample());
        assert(!owner.connection->securityTransitionAllowed(false));
        assert(harness.backend.writes == 0);
    }
    Harness harness;
    Client owner(harness.descriptors[0]);
    const auto correlation = bound(QStringLiteral("transaction:substituted-capture"));
    const auto captured = owner.connection->sample();
    assert(captured);
    auto prior = baseline(*captured), desired = prior;
    desired.outputs[0].x = 100;
    auto wrongBaseline = prior;
    wrongBaseline.outputs[0].x = -100;
    assert(!owner.connection->apply(correlation, wrongBaseline, desired, owner.protection()));
    desired.outputs[0].generation++;
    assert(!owner.connection->apply(correlation, prior, desired, owner.protection()));
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
        assert(owner.connection->apply(correlation, prior, desired, owner.protection()) == 2);
        assert(owner.connection->decide(correlation, true) == 4);
        assert(owner.connection->status(correlation) == 4);
        assert(!owner.connection->apply(correlation, prior, desired, owner.protection()));
        // The reservation is retained by the compositor. Terminal private
        // conversation resources have their own, smaller bounded lifetime.
        for (auto *scene : owner.protections)
            linura_protected_display_interaction_v1_destroy(scene);
        owner.protections.clear();
    }
    assert(harness.backend.writes == 70);
}
void finalNativePowerStateCannotReuseAnEarlierVisibilityReview()
{
    Harness harness;
    Client owner(harness.descriptors[0]);
    const auto earlier = owner.connection->sample();
    assert(earlier);
    auto prior = baseline(*earlier), desired = prior;
    desired.outputs[0].x = 100;
    {
        const std::lock_guard lock(harness.backend.mutex);
        harness.backend.facts.heads[0].powered = false;
    }
    const auto drift = bound(QStringLiteral("transaction:dpms-drift"));
    const auto fresh = owner.connection->sample();
    assert(fresh && fresh->topology == earlier->topology &&
           fresh->current.outputs[0].encode() == earlier->current.outputs[0].encode());
    assert(!owner.connection->apply(drift, prior, desired, owner.protection()));
    assert(harness.backend.writes == 0 && !fresh->fenced);
    {
        const std::lock_guard lock(harness.backend.mutex);
        harness.backend.facts.heads[0].powered = true;
    }
    // A separate deliberate fixture attempt, never an automatic effect retry.
    const auto next = bound(QStringLiteral("transaction:powered-root"));
    assert(owner.connection->sample());
    assert(owner.connection->apply(next, prior, desired, owner.protection()) == 2);
    assert(owner.connection->decide(next, false) == 3); // Restoration is not yet verification.
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (owner.connection->status(next) != 5) {
        assert(std::chrono::steady_clock::now() < deadline);
        std::this_thread::sleep_for(10ms);
    }
    const auto restored = owner.connection->sample();
    assert(restored && !restored->fenced && restored->current.outputs[0].x == 0);
    assert(harness.backend.writes == 2);
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
                                               true,
                                               false,
                                               "LNDR:1;1;",
                                               "LNDF:1;1;",
                                               ""});
    }
    Client owner(harness.descriptors[0]);
    const auto sampled = owner.connection->sample();
    assert(sampled && sampled->coverage == 1 && sampled->topology.heads.size() == 2);
    assert(owner.connection->securityTransitionAllowed(true));
    assert(!owner.connection->securityTransitionAllowed(false));
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
    assert(encoded["schema"].toInt() == 3);
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

void recoveryMetadataIsBoundedAndNeverPublishesNativeIdentityPreimages()
{
    Harness harness;
    Client observer(harness.descriptors[0]);
    const auto initial = observer.connection->sample();
    assert(initial);
    const auto base = QString::fromLatin1(
        QCryptographicHash::hash("LNDR:1;0;", QCryptographicHash::Sha256).toHex());
    assert(initial->topology.heads[0].baseRuleDigest == base);
    {
        const std::lock_guard lock(harness.backend.mutex);
        harness.backend.facts.heads[0].outputIdentityWitness = "LNDF:1;abcdef;";
        harness.backend.facts.heads[0].linuraOwned = true;
        harness.backend.facts.heads[0].ownedTargetWitness =
            "LNOT:1;1;1;1;1920;1080;60000;1000;0;0;0;0;0;";
    }
    const auto owned = observer.connection->sample();
    assert(owned && owned->topology.heads[0].linuraOwned &&
           owned->topology.heads[0].baseRuleDigest == base &&
           owned->topology.heads[0].outputIdentityDigest !=
               initial->topology.heads[0].outputIdentityDigest);
    const auto serialized = owned->topology.encode();
    assert(!serialized.contains("LNDF:") && !serialized.contains("LNDR:"));
    for (const std::string &bad :
         {std::string{}, std::string("LNDF:2;0;"), std::string("LNDF:1;\n;"),
          "LNDF:1;" + std::string(16 * 1024, '0') + ';'}) {
        Harness invalid;
        {
            const std::lock_guard lock(invalid.backend.mutex);
            invalid.backend.facts.heads[0].outputIdentityWitness = bad;
        }
        Client rejected(invalid.descriptors[0]);
        assert(!rejected.connection->sample());
        assert(invalid.backend.writes == 0);
    }
    assert(harness.backend.writes == 0);
}

void replacementCompositorCannotAdoptOldTopologyOrContinuation()
{
    // Two independent real Wayland fixture servers model distinct compositor
    // invocations. This tests identity-bound refusal, NOT compositor SIGKILL,
    // persistent native rules, kernel continuity or durable restoration.
    Harness original;
    Client owner(original.descriptors[0]);
    const auto first = owner.connection->sample();
    assert(first);
    const auto prior = baseline(*first);
    auto desired = prior;
    desired.outputs[0].x = 100;
    const auto correlation = bound(QStringLiteral("transaction:prior-compositor"));
    assert(owner.connection->apply(correlation, prior, desired, owner.protection()) == 2);
    assert(original.backend.writes == 1);

    Harness replacement(Harness::BuildMismatch::None, true, ReplacementInstance);
    Client newOwner(replacement.descriptors[0]);
    const auto current = newOwner.connection->sample();
    assert(current && current->compositor != first->compositor);
    const auto replacementLayout = baseline(*current);
    assert(replacementLayout.topology != prior.topology);
    assert(replacementLayout.outputs.size() == prior.outputs.size());
    for (std::size_t i = 0; i < prior.outputs.size(); ++i)
        assert(replacementLayout.outputs[i].encode() == prior.outputs[i].encode());
    // Verify topology refusal BEFORE querying status: the client must not
    // reject this stale apply merely because an earlier status probe already
    // reserved a local transaction tombstone.
    assert(!newOwner.connection->apply(correlation, prior, desired, newOwner.protection()));
    assert(replacement.backend.writes == 0);
    // A fresh compositor contains no old transaction or decision right.
    // BUILDING is a newly queried wire object, never the prior dispatch.
    assert(newOwner.connection->status(correlation) == 1);
    assert(!newOwner.connection->decide(correlation, true));
    assert(!newOwner.connection->decide(correlation, false));
    assert(!newOwner.connection->decisionBootDeadline(correlation));
    assert(newOwner.connection->securityTransitionAllowed(false));
}

void securityAdmissionRejectsUnknownStateAndRetainsFailedRecoveryFence()
{
    NativeDisplayConnection unavailable(nullptr);
    assert(!unavailable.securityTransitionAllowed(false));
    {
        // A completed registry read on an otherwise valid legacy compositor
        // has no S21 mutation mechanism; preserve its qualified S17 behavior.
        Harness legacy(Harness::BuildMismatch::None, false);
        Client plain(legacy.descriptors[0], false);
        assert(plain.connection->securityTransitionAllowed(false));
        assert(!plain.connection->sample());
        assert(plain.connection->securityTransitionAllowed(false));
    }
    Harness harness;
    Client owner(harness.descriptors[0]), observer(harness.descriptors[1]);
    for (const auto coverage : {Coverage::Transitioning, Coverage::Unknown, Coverage::Unlocked}) {
        {
            const std::lock_guard lock(harness.backend.mutex);
            harness.backend.facts.coverage = coverage;
        }
        assert(owner.connection->securityTransitionAllowed(false) ==
               (coverage == Coverage::Unlocked));
    }
    const auto correlation = bound(QStringLiteral("transaction:failed-restoration-fence"));
    const auto captured = owner.connection->sample();
    assert(captured);
    auto prior = baseline(*captured), desired = prior;
    desired.outputs[0].x = 100;
    assert(owner.connection->apply(correlation, prior, desired, owner.protection()) == 2);
    harness.backend.failRestore = true;
    assert(owner.connection->decide(correlation, false) == 6);
    assert(!owner.connection->securityTransitionAllowed(false));
    assert(!observer.connection->securityTransitionAllowed(false));
    assert(observer.connection->status(correlation) == 6);
    assert(!observer.connection->securityTransitionAllowed(false));
    assert(harness.backend.writes == 1); // Admission reads never compensate/replay.
}
} // namespace
int main()
{
    const NativeDisplayCorrelation window{QStringLiteral("transaction:prepared-window"),
                                          QString(64, QLatin1Char('a')),
                                          QString(64, QLatin1Char('b')), 25'000};
    assert(window.dispatchWindow(1000, 1000, 10'000));
    assert(window.dispatchWindow(1000, 2999, 24'999));
    assert(!window.dispatchWindow(1000, 3000, 10'000));
    assert(!window.dispatchWindow(1000, 999, 10'000));
    assert(!window.dispatchWindow(0, 1000, 10'000));
    assert(!window.dispatchWindow(1000, 1000, 9999));
    assert(!window.dispatchWindow(1000, 1000, 25'000));
    assert(!window.dispatchWindow(1000, 1000, 0));
    assert(window.decisionWindow(10'000, 1000, 10'000, 1000));
    assert(window.decisionWindow(10'000, 1000, 24'999, 15'999));
    for (const auto &clock : std::vector<std::array<quint64, 4>>{
             {0, 1000, 10'000, 1000},
             {10'000, 0, 10'000, 1000},
             {9999, 1000, 10'000, 1000},
             {10'000, 1000, 9999, 1000},
             {10'000, 1000, 10'000, 999},
             {25'000, 1000, 25'000, 1000},
             {10'000, 1000, 25'000, 1000},
             {10'000, 1000, 10'000, 16'000},
             {10'000, 1000, 10'000, std::numeric_limits<quint64>::max()}})
        assert(!window.decisionWindow(clock[0], clock[1], clock[2], clock[3]));
    NativeDisplayDecision decision{window, QString(64, QLatin1Char('c')),
                                   QString(64, QLatin1Char('d')), true};
    assert(decision.valid());
    for (const auto &bad :
         {QString{}, QString(64, QLatin1Char('0')), QString(64, QLatin1Char('A')),
          QString(65, QLatin1Char('a')), QString(63, QLatin1Char('a')) + QLatin1Char('\n')}) {
        auto changed = decision;
        changed.decisionDigest = bad;
        assert(!changed.valid());
        changed = decision;
        changed.protectedDecisionDigest = bad;
        assert(!changed.valid());
    }
    identityAndContinuationOwnership();
    clientLossDoesNotDisarmNativeRecovery();
    explicitRevertCannotBecomeAnotherApplyOrDecision();
    expiredDecisionLeavesTheIndependentNativeTimerResponsible();
    unsupportedBuildAndSubstitutedSnapshotCannotWrite();
    terminalWireObjectsRetireWithoutEvictingOneUseReservations();
    finalNativePowerStateCannotReuseAnEarlierVisibilityReview();
    compositorFenceCoverageCannotBecomeOwnerSurfaceCoverage();
    recoveryMetadataIsBoundedAndNeverPublishesNativeIdentityPreimages();
    securityAdmissionRejectsUnknownStateAndRetainsFailedRecoveryFence();
    replacementCompositorCannotAdoptOldTopologyOrContinuation();
}
