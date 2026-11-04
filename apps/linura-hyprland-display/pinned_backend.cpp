#include "pinned_integration.h"
#include "pinned_protected.h"
#include "native_scale.h"
#include "rule_overlay.h"
#include "recovery_witness.h"
#include "recovery_lineage.h"
#include "wire_endpoint.h"
#include "native_power_inhibitor.h"
#include "native_owner_admission.h"
#include "native_output_identity.h"
#include "linura-display-integration-build.h"
#include "startup_fence.h"
#include "original_restoration_grant.h"
#include "native_baseline_guard.h"
#include "protected_wire.h"

#include "src/Compositor.hpp"
#include "src/config/ConfigValue.hpp"
#include "src/config/shared/monitor/MonitorRuleManager.hpp"
#include "src/managers/SessionLockManager.hpp"
#include "src/output/Monitor.hpp"
#include "src/state/MonitorState.hpp"
#include "src/render/Renderer.hpp"
#include "src/version.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <limits>
#include <map>
#include <set>
#include <string_view>
#include <sys/random.h>
#include <sys/socket.h>
#include <wayland-server-core.h>

namespace Linura::HyprlandDisplay {
static_assert(std::string_view(GIT_COMMIT_HASH) == UpstreamCommit,
              "Linura display integration requires the exact qualified Hyprland source");
namespace {
StartupFence startupFence;
wl_event_source *startupEvents = nullptr;
std::optional<std::int32_t> integer(double value, std::int32_t minimum, std::int32_t maximum)
{
    if (!std::isfinite(value) || value < minimum || value > maximum || value != std::round(value))
        return std::nullopt;
    return static_cast<std::int32_t>(value);
}
std::optional<Mode> mode(const SP<Aquamarine::SOutputMode> &value)
{
    if (!value)
        return std::nullopt;
    const auto width = integer(value->pixelSize.x, 1, 32768);
    const auto height = integer(value->pixelSize.y, 1, 32768);
    const auto refresh = integer(value->refreshRate, 1, 1'000'000);
    if (!width || !height || !refresh)
        return std::nullopt;
    return Mode{*width, *height, *refresh};
}
std::string instanceId()
{
    std::array<unsigned char, 16> bytes{};
    if (getrandom(bytes.data(), bytes.size(), GRND_NONBLOCK) != static_cast<ssize_t>(bytes.size()))
        return {};
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0fU) | 0x40U);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3fU) | 0x80U);
    constexpr char hex[] = "0123456789abcdef";
    std::string value;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10)
            value += '-';
        value += hex[bytes[i] >> 4];
        value += hex[bytes[i] & 15];
    }
    return value;
}
class PinnedBackend final : public Backend
{
  public:
    struct Binding final
    {
        OutputKey key;
        PHLMONITORREF monitor;
        WP<Aquamarine::IOutput> output;
        std::vector<Mode> modes;
        NativeOutputIdentity identity;
    };
    std::uint64_t generation = 1, securityEpoch = 1, nextHandle = 1;
    std::vector<Binding> bindings;
    std::map<Monitor::CMonitor *, Target> overlay;
    using RuleCheckpoint = RuleOverlayCheckpoint<Monitor::CMonitor *, RecoveryLineage>;
    RuleCheckpoint checkpoint;
    struct RuleSource final
    {
        RecoveryRule native;
        std::vector<std::string> selectors;
        std::optional<std::size_t> selected;
        bool wlr;
        std::uint32_t mask, refreshMilliHz;
        std::string restoredOrigin;
    };
    std::map<Monitor::CMonitor *, RuleSource> capturedSources;
    bool sourceCaptureValid = false;
    const std::string instance = instanceId();
    bool writing = false, commitFailed = false, supported = true, readingBaseRules = false;
    NativePowerInhibitor powerInhibitor;
    struct RecoveredWlrSource final
    {
        OutputKey output;
        RecoveryLineage lineage;
    };
    std::map<Monitor::CMonitor *, RecoveredWlrSource> recoveredWlr;
    struct OriginalRecovery final
    {
        Correlation bound;
        std::shared_ptr<OriginalRestorationGrant> grant;
        std::shared_ptr<MutationProtection> protection;
        Layout targets;
        bool failed = false;
    };
    std::optional<OriginalRecovery> originalRecovery;
    struct OriginalPlan final
    {
        std::map<std::size_t, RecoveryRule> rules;
        std::map<Monitor::CMonitor *, RecoveredWlrSource> wlr;
        std::map<Monitor::CMonitor *, Target> priorOverlay;
        std::map<OutputKey, std::string> sources;
    };

    [[nodiscard]] bool inhibitPowerTransitions() override
    {
        return powerInhibitor.acquire();
    }
    void releasePowerInhibitor() noexcept override
    {
        powerInhibitor.release();
        checkpoint.retire();
    }

    [[nodiscard]] std::optional<ClockSample> clock() override
    {
        return compositorClock();
    }
    [[nodiscard]] std::optional<Snapshot> snapshot() override
    {
        if (!supported || instance.empty() || !State::monitorState() || !g_pSessionLockManager ||
            (powerInhibitor.retained() && !powerInhibitor.held()) || !refresh())
            return std::nullopt;
        Snapshot sample;
        sample.generation = generation;
        sample.securityEpoch = securityEpoch;
        static auto xray = CConfigValue<Config::INTEGER>("misc:session_lock_xray");
        if (*xray)
            return std::nullopt; // This environment cannot establish S17 coverage.
        if (!g_pSessionLockManager->isSessionLocked())
            sample.coverage = Coverage::Unlocked;
        else if (g_pSessionLockManager->clientLocked() || g_pSessionLockManager->clientDenied() ||
                 g_pSessionLockManager->shallConsiderLockMissing())
            sample.coverage = Coverage::Secure;
        else
            sample.coverage = Coverage::Transitioning;
        const auto rules = baseRules();
        if (!rules)
            return std::nullopt;
        for (const auto &binding : bindings) {
            const auto monitor = binding.monitor.lock();
            if (!monitor || !monitor->m_output)
                return std::nullopt;
            Target current;
            current.output = binding.key;
            current.enabled = monitor->m_enabled;
            if (current.enabled) {
                const auto currentMode = mode(monitor->m_currentMode);
                const auto x = integer(monitor->m_position.x, -65536, 65536);
                const auto y = integer(monitor->m_position.y, -65536, 65536);
                const auto scale = nativeScaleMilli(monitor->m_scale);
                const auto transform = static_cast<std::uint32_t>(monitor->m_transform);
                if (!currentMode || !x || !y || !scale || transform > 7)
                    return std::nullopt;
                current.mode = *currentMode;
                current.x = *x;
                current.y = *y;
                current.scaleMilli = static_cast<std::uint32_t>(*scale);
                current.transform = transform;
                if (const auto source = monitor->m_mirrorOf.lock()) {
                    const auto found =
                        std::find_if(bindings.begin(), bindings.end(), [&](const Binding &other) {
                            return other.monitor.lock() == source;
                        });
                    if (found == bindings.end())
                        return std::nullopt;
                    current.mirror = found->key;
                }
            }
            // In the pinned renderer, a locked client with xray disabled makes
            // the full-output black primer and suppresses workspace rendering,
            // including outputs without a newly configured client lock surface.
            // This is a compositor safety fence; Control still requires its
            // separate native surface/geometry evidence before commitment.
            const auto rule = rules->find(monitor.get());
            if (rule == rules->end())
                return std::nullopt;
            const auto base = std::optional{rule->second.encode()};
            const auto identity = RecoveryWitness::identity(binding.identity);
            if (!base || !identity)
                return std::nullopt;
            const auto owned = overlay.find(monitor.get());
            const bool activeOwnership =
                owned != overlay.end() && owned->second.output == binding.key;
            sample.heads.push_back(
                {binding.key, binding.modes, current, monitor->m_dpmsStatus && current.enabled,
                 sample.coverage == Coverage::Secure, activeOwnership, *base, *identity,
                 activeOwnership ? RecoveryWitness::target(owned->second) : std::string{}});
        }
        return sample;
    }
    [[nodiscard]] bool applyOwnedLayout(const Layout &targets, const Snapshot &expected) override
    {
        const auto fresh = snapshot();
        if (writing || checkpoint.retained() || !powerInhibitor.held() || !fresh ||
            fresh->generation != expected.generation ||
            fresh->securityEpoch != expected.securityEpoch || !sameCurrent(*fresh, expected) ||
            !DisplayTransaction::validLayout(targets, *fresh) || !Config::monitorRuleMgr())
            return false;
        writing = true;
        commitFailed = false;
        struct Finish final
        {
            bool &writing;
            ~Finish()
            {
                writing = false;
            }
        } finish{writing};
        const auto rules = baseRules();
        Layout baseline;
        for (const auto &head : fresh->heads)
            baseline.push_back(head.current);
        const auto identities = identitiesFor(*fresh);
        if (!rules || !identities || !checkpoint.capture(overlay, *rules, baseline, *identities))
            return false;
        // Start with actual current owned fields, preserving every underlying
        // rule. Establish the desired independent roots before removing any old
        // visible root; then mirrors, and only then output disable operations.
        for (const auto &head : fresh->heads) {
            const auto monitor = monitorFor(head.key);
            if (!monitor)
                return false;
            overlay[monitor.get()] = head.current;
        }
        for (const auto &target : targets) {
            if (target.enabled && !target.mirror)
                if (!setTarget(target))
                    return false;
        }
        Config::monitorRuleMgr()->ensureMonitorStatus();
        const auto roots = snapshot();
        if (commitFailed || !roots || !hasDesiredPoweredRoot(targets, *roots))
            return false;
        for (const auto &target : targets) {
            if (target.enabled)
                if (!setTarget(target))
                    return false;
        }
        Config::monitorRuleMgr()->ensureMonitorStatus();
        if (commitFailed)
            return false;
        for (const auto &target : targets)
            if (!setTarget(target))
                return false;
        Config::monitorRuleMgr()->ensureMonitorStatus();
        const auto observed = snapshot();
        return !commitFailed && observed && observed->generation == expected.generation &&
               observed->securityEpoch == expected.securityEpoch &&
               std::equal(
                   targets.begin(), targets.end(), observed->heads.begin(), observed->heads.end(),
                   [](const Target &target, const Head &head) { return target == head.current; });
    }
    [[nodiscard]] bool restoreOwnedLayout(const Layout &targets, const Snapshot &expected) override
    {
        const auto fresh = snapshot();
        if (writing || !powerInhibitor.held() || !fresh ||
            fresh->generation != expected.generation ||
            fresh->securityEpoch != expected.securityEpoch || !sameCurrent(*fresh, expected) ||
            !DisplayTransaction::validLayout(targets, *fresh) || !Config::monitorRuleMgr())
            return false;
        if (!checkpoint.retained()) {
            // Initial admission may have failed before any owned rule changed.
            return std::equal(
                targets.begin(), targets.end(), fresh->heads.begin(), fresh->heads.end(),
                [](const Target &target, const Head &head) { return target == head.current; });
        }
        const auto rules = baseRules();
        const auto identities = identitiesFor(*fresh);
        auto prior = rules && identities
                         ? checkpoint.restoration(targets, *rules, *identities, sameOverlaySources)
                         : std::nullopt;
        if (!prior)
            return false; // Changed native layout rules cannot be silently overwritten.
        writing = true;
        commitFailed = false;
        struct Finish final
        {
            bool &writing;
            ~Finish()
            {
                writing = false;
            }
        } finish{writing};
        // Establish a baseline independent root before dropping temporary
        // ownership. Native automatic mode/scale/position rules resume only
        // after their exact owned semantics have been revalidated.
        for (const auto &target : targets)
            if (target.enabled && !target.mirror && !setTarget(target))
                return false;
        Config::monitorRuleMgr()->ensureMonitorStatus();
        const auto roots = snapshot();
        const auto currentRules = baseRules();
        const auto currentIdentities = roots ? identitiesFor(*roots) : std::nullopt;
        if (commitFailed || !roots || roots->generation != expected.generation ||
            roots->securityEpoch != expected.securityEpoch ||
            !hasDesiredPoweredRoot(targets, *roots) || !currentRules || !currentIdentities ||
            !checkpoint.restoration(targets, *currentRules, *currentIdentities, sameOverlaySources))
            return false;
        overlay = std::move(*prior);
        Config::monitorRuleMgr()->ensureMonitorStatus();
        const auto observed = snapshot();
        return !commitFailed && observed && observed->generation == expected.generation &&
               observed->securityEpoch == expected.securityEpoch &&
               std::equal(
                   targets.begin(), targets.end(), observed->heads.begin(), observed->heads.end(),
                   [](const Target &target, const Head &head) { return target == head.current; });
    }
    [[nodiscard]] bool restoredOwnedState() override
    {
        if (writing || !powerInhibitor.held())
            return false;
        if (!checkpoint.retained())
            return true; // No owned write passed initial admission.
        const auto sample = snapshot();
        const auto identities = sample ? identitiesFor(*sample) : std::nullopt;
        const auto rules = baseRules();
        return rules && identities &&
               checkpoint.restored(overlay, *rules, *identities, sameOverlaySources);
    }
    [[nodiscard]] std::optional<OriginalPlan>
    prepareOriginal(const OriginalRestorationSource &source, const Layout &targets,
                    const Snapshot &captured)
    {
        if (writing || originalRecovery || checkpoint.retained() || !overlay.empty() ||
            !recoveredWlr.empty() || source.integration != IntegrationSourceDigest ||
            source.heads.size() != captured.heads.size() || source.desired != targets ||
            !source.replacementTopology.ends_with(instance + ":" +
                                                  std::to_string(captured.generation)) ||
            !Config::monitorRuleMgr() || !DisplayTransaction::validLayout(targets, captured))
            return std::nullopt;
        Layout baseline;
        for (const auto &head : captured.heads)
            baseline.push_back(head.current);
        const auto material = OriginalGrantCodec::materialFields(source.material);
        const auto guard = nativeBaselineGuard(captured, source.baselineText);
        if (!material || baseline != source.baseline || !guard || *guard != (*material)[3])
            return std::nullopt;
        const auto current = baseRules();
        if (!current)
            return std::nullopt;
        OriginalPlan plan;
        std::map<std::size_t, std::string> sharedRules;
        for (const auto &saved : source.heads) {
            const auto monitor = monitorFor(saved.replacement);
            const auto fresh =
                std::find_if(captured.heads.begin(), captured.heads.end(),
                             [&](const Head &head) { return head.key == saved.replacement; });
            if (!monitor || fresh == captured.heads.end() || fresh->linuraOwned ||
                nativeKernelDrmBinding(*monitor->m_output) != std::optional{saved.kernel} ||
                nativeSha256(fresh->outputIdentityWitness) != std::optional{saved.identityDigest})
                return std::nullopt;
            const auto live = current->find(monitor.get());
            if (live == current->end() || !saved.lineage.replacementSourceCompatible(live->second))
                return std::nullopt;
            const auto selected = saved.lineage.selected();
            if (selected) {
                const auto &all = Config::monitorRuleMgr()->all();
                if (*selected >= all.size())
                    return std::nullopt;
                const auto merged = saved.lineage.native().mergeOwnedFields(all[*selected]);
                if (!merged)
                    return std::nullopt;
                const auto prior = sharedRules.find(*selected);
                if (prior != sharedRules.end() && prior->second != saved.lineage.native().encode())
                    return std::nullopt;
                sharedRules.insert_or_assign(*selected, saved.lineage.native().encode());
                plan.rules.insert_or_assign(*selected, saved.lineage.native());
            } else if (saved.lineage.native().encode() != live->second.native().encode()) {
                return std::nullopt; // Never invent/reorder a rule for a hardcoded fallback.
            }
            const auto post = saved.lineage.replacementProjection((*material)[2]);
            if (!post)
                return std::nullopt;
            if (post->hasWlrProjection())
                plan.wlr.emplace(monitor.get(), RecoveredWlrSource{saved.replacement, *post});
            if (saved.priorOverlay) {
                auto target = *saved.priorOverlay;
                target.output = saved.replacement;
                if (target.mirror) {
                    const auto root = std::find_if(
                        source.heads.begin(), source.heads.end(),
                        [&](const auto &head) { return head.original == *target.mirror; });
                    if (root == source.heads.end())
                        return std::nullopt;
                    target.mirror = root->replacement;
                }
                const auto desired =
                    std::find_if(targets.begin(), targets.end(),
                                 [&](const Target &row) { return row.output == target.output; });
                if (desired == targets.end() || *desired != target)
                    return std::nullopt;
                plan.priorOverlay.emplace(monitor.get(), target);
            }
            if (!plan.sources.emplace(saved.replacement, post->encode()).second)
                return std::nullopt;
        }
        return plan;
    }
    [[nodiscard]] std::optional<std::uint32_t>
    restoreOriginal(std::shared_ptr<OriginalRestorationGrant> grant, const Correlation &bound,
                    const Layout &targets, const Snapshot &captured, ClockSample at,
                    wl_resource *resource, wl_client *client)
    {
        const auto now = clock();
        const auto fresh = snapshot();
        if (!now || !fresh || *fresh != captured || !startupFence.recoveryAvailable() ||
            !grant->sampleFreshAt(now->bootMs) || at.bootMs == 0 || at.unixMs == 0 ||
            now->bootMs < at.bootMs || now->unixMs < at.unixMs || now->bootMs - at.bootMs >= 2000 ||
            now->unixMs - at.unixMs >= 2000 || bound.deadlineUnixMs <= now->unixMs ||
            bound.deadlineUnixMs - at.unixMs > DisplayTransaction::WindowMs)
            return std::nullopt;
        auto staged = prepareOriginal(grant->source(), targets, captured);
        if (!staged || !grant->verify())
            return std::nullopt;
        Layout baseline;
        for (const auto &head : captured.heads)
            baseline.push_back(head.current);
        auto protection = ProtectedWireEndpoint::reserveOriginalRestoration(
            resource, client, bound, baseline, targets, captured, at, staged->sources,
            [grant] { return grant->live(); });
        if (!protection)
            return std::nullopt;
        // Retain before the first possible effect. An error/exception never
        // destroys opaque/input protection, replays, restores the replacement
        // baseline or releases original/current power protection.
        originalRecovery.emplace(
            OriginalRecovery{bound, std::move(grant), std::move(protection), targets, false});
        auto &active = *originalRecovery;
        struct Outcome final
        {
            OriginalRecovery &active;
            bool complete = false;
            ~Outcome()
            {
                if (!complete)
                    active.failed = true;
            }
        } outcome{active};
        if (!active.grant->verify() || !inhibitPowerTransitions())
            return 6U;
        // Both calls above may block. Re-sample the original immutable sample's
        // clocks afterwards; neither the grant nor power acquisition renews it.
        const auto admitted = clock();
        if (!admitted || admitted->bootMs < at.bootMs || admitted->unixMs < at.unixMs ||
            admitted->bootMs - at.bootMs >= 2000 || admitted->unixMs - at.unixMs >= 2000 ||
            admitted->unixMs >= bound.deadlineUnixMs ||
            !active.grant->sampleFreshAt(admitted->bootMs) || !active.grant->live() ||
            !active.protection->beginWrite(MutationProtection::Write::Restore, captured))
            return 6U;
        writing = true;
        commitFailed = false;
        struct Finish final
        {
            PinnedBackend &backend;
            bool ended = false;
            void end() noexcept
            {
                if (ended)
                    return;
                // End the exact granted source transition while the reserved
                // compositor write is still active, then freeze post witnesses.
                backend.originalRecovery->protection->endWrite(MutationProtection::Write::Restore);
                backend.writing = false;
                ended = true;
            }
            ~Finish()
            {
                end();
            }
        } finish{*this};
        // beginWrite also snapshots native state and revokes old presentation.
        // Check the original sample once more after that work, immediately
        // before introducing any owned target or native rule change.
        const auto firstWrite = clock();
        if (!firstWrite || firstWrite->bootMs < admitted->bootMs ||
            firstWrite->unixMs < admitted->unixMs ||
            !active.grant->sampleFreshAt(firstWrite->bootMs) ||
            firstWrite->unixMs >= bound.deadlineUnixMs || !active.grant->live())
            return 6U;
        for (const auto &target : targets)
            if (!setTarget(target))
                return 6U;
        Config::monitorRuleMgr()->ensureMonitorStatus();
        const auto roots = snapshot();
        if (commitFailed || !roots || roots->generation != captured.generation ||
            roots->securityEpoch != captured.securityEpoch ||
            !hasDesiredPoweredRoot(targets, *roots) || !active.protection->healthy() ||
            !active.grant->verify())
            return 6U;
        if (roots->heads.size() != captured.heads.size())
            return 6U;
        for (std::size_t i = 0; i < roots->heads.size(); ++i) {
            const auto &live = roots->heads[i];
            const auto &before = captured.heads[i];
            if (live.key != before.key || live.modes != before.modes ||
                live.baseRuleWitness != before.baseRuleWitness ||
                live.outputIdentityWitness != before.outputIdentityWitness)
                return 6U;
        }
        // Only the granted owned fields change. Selected indices/selector list
        // were checked as one complete preflight; unrelated fields remain live.
        auto &rules = Config::monitorRuleMgr()->allMut();
        for (const auto &[index, rule] : staged->rules) {
            if (index >= rules.size())
                return 6U;
            // Native callbacks during the temporary modeset may update live
            // ICC/VRR and other unowned settings. Merge into the actual rule at
            // this write point rather than restoring a stale full-rule copy.
            const auto merged = rule.mergeOwnedFields(rules[index]);
            if (!merged)
                return 6U;
            rules[index] = *merged;
        }
        recoveredWlr = std::move(staged->wlr);
        Config::monitorRuleMgr()->ensureMonitorStatus();
        const auto sourceState = snapshot();
        if (commitFailed || !sourceState || sourceState->generation != captured.generation ||
            sourceState->securityEpoch != captured.securityEpoch || !active.protection->healthy() ||
            !active.grant->verify())
            return 6U;
        for (const auto &head : sourceState->heads) {
            const auto expected = staged->sources.find(head.key);
            if (expected == staged->sources.end() || expected->second != head.baseRuleWitness)
                return 6U;
        }
        overlay = std::move(staged->priorOverlay);
        Config::monitorRuleMgr()->ensureMonitorStatus();
        const auto restored = snapshot();
        if (commitFailed || !restored || restored->generation != captured.generation ||
            restored->securityEpoch != captured.securityEpoch ||
            !hasDesiredPoweredRoot(targets, *restored) ||
            !std::equal(
                targets.begin(), targets.end(), restored->heads.begin(), restored->heads.end(),
                [](const Target &target, const Head &head) { return target == head.current; }) ||
            !active.protection->healthy() || !active.grant->verify())
            return 6U;
        finish.end();
        if (active.failed || !active.protection->healthy())
            return 6U;
        outcome.complete = true;
        return 3U; // Still restoring/fenced. Native replies never supply terminal proof.
    }
    [[nodiscard]] std::optional<std::uint32_t> originalStatus(const Correlation &bound)
    {
        if (!originalRecovery || originalRecovery->bound != bound)
            return std::nullopt;
        auto &active = *originalRecovery;
        if (!active.grant->live() || !active.protection->healthy())
            active.failed = true;
        return active.failed ? 6U : 3U;
    }
    [[nodiscard]] PHLMONITOR monitorFor(OutputKey key) const
    {
        const auto found = std::find_if(bindings.begin(), bindings.end(),
                                        [&](const Binding &binding) { return binding.key == key; });
        if (found == bindings.end())
            return nullptr;
        const auto monitor = found->monitor.lock();
        return monitor && monitor->m_output && found->output.lock() == monitor->m_output ? monitor
                                                                                         : nullptr;
    }
    [[nodiscard]] bool refreshBindings()
    {
        return supported && refresh();
    }
    void captureRuleSource(Monitor::CMonitor *monitor, const Config::CMonitorRule &native,
                           std::optional<std::size_t> selected, bool wlr, std::uint32_t committed,
                           std::uint32_t refreshMilliHz)
    {
        if (wlr && recoveredWlr.contains(monitor)) {
            if (originalRecovery) {
                originalRecovery->failed = true;
                sourceCaptureValid = false;
            } else
                recoveredWlr.erase(monitor);
        }
        if (!readingBaseRules)
            return;
        const auto saved = RecoveryRule::capture(native);
        if (!sourceCaptureValid || !saved || !monitor || !Config::monitorRuleMgr() ||
            committed > 63 ||
            Config::monitorRuleMgr()->all().size() > RecoveryLineage::MaxSelectors ||
            capturedSources.size() >= DisplayTransaction::MaxHeads) {
            sourceCaptureValid = false;
            return;
        }
        std::vector<std::string> selectors;
        for (const auto &rule : Config::monitorRuleMgr()->all()) {
            if (rule.m_name.size() > 4096) {
                sourceCaptureValid = false;
                return;
            }
            selectors.push_back(rule.m_name);
        }
        if (!capturedSources
                 .emplace(monitor, RuleSource{*saved,
                                              std::move(selectors),
                                              selected,
                                              wlr,
                                              committed & 31U,
                                              refreshMilliHz,
                                              {}})
                 .second)
            sourceCaptureValid = false;
    }

  private:
    static bool sameOverlaySources(const RecoveryLineage &left, const RecoveryLineage &right)
    {
        return left.sameOverlayCompensationSources(right);
    }
    [[nodiscard]] std::optional<RuleCheckpoint::Identities>
    identitiesFor(const Snapshot &sample) const
    {
        if (sample.heads.size() != bindings.size())
            return std::nullopt;
        RuleCheckpoint::Identities identities;
        for (const auto &head : sample.heads) {
            const auto monitor = monitorFor(head.key);
            if (!monitor || !identities.emplace(monitor.get(), head.key).second)
                return std::nullopt;
        }
        return identities;
    }

    [[nodiscard]] std::optional<RuleCheckpoint::Rules> baseRules()
    {
        if (readingBaseRules || !Config::monitorRuleMgr())
            return std::nullopt;
        readingBaseRules = true;
        capturedSources.clear();
        sourceCaptureValid = true;
        struct Finish final
        {
            bool &reading;
            ~Finish()
            {
                reading = false;
            }
        } finish{readingBaseRules};
        RuleCheckpoint::Rules rules;
        for (const auto &binding : bindings) {
            const auto monitor = monitorFor(binding.key);
            if (!monitor)
                return std::nullopt;
            auto rule = Config::monitorRuleMgr()->get(monitor);
            if (!std::isfinite(rule.m_scale) || !std::isfinite(rule.m_refreshRate) ||
                !std::isfinite(rule.m_offset.x) || !std::isfinite(rule.m_offset.y) ||
                !std::isfinite(rule.m_resolution.x) || !std::isfinite(rule.m_resolution.y) ||
                rule.m_mirrorOf.size() > 4096 || rule.m_name.size() > 4096 ||
                rule.m_iccFile.size() > 4096)
                return std::nullopt;
            const auto source = capturedSources.find(monitor.get());
            const auto effective = RecoveryRule::capture(rule);
            if (!sourceCaptureValid || source == capturedSources.end() || !effective)
                return std::nullopt;
            auto lineage = RecoveryLineage::capture(
                source->second.native, *effective, source->second.selectors,
                source->second.selected, source->second.wlr, source->second.mask,
                source->second.refreshMilliHz, source->second.restoredOrigin);
            if (!lineage || !rules.emplace(monitor.get(), std::move(*lineage)).second)
                return std::nullopt;
        }
        return rules;
    }
    bool setTarget(const Target &target)
    {
        const auto monitor = monitorFor(target.output);
        if (!monitor || !powerInhibitor.held())
            return false;
        overlay[monitor.get()] = target;
        return true;
    }
    static bool sameCurrent(const Snapshot &left, const Snapshot &right)
    {
        // Include original rule lineage, ownership and native identity witnesses.
        // A config/ownership change with equal geometry still invalidates the
        // prepared preimage; unrelated live settings are absent from witnesses.
        return left.coverage == right.coverage && left.heads == right.heads;
    }
    static bool hasDesiredPoweredRoot(const Layout &targets, const Snapshot &sample)
    {
        if (sample.coverage != Coverage::Unlocked && sample.coverage != Coverage::Secure)
            return false;
        return std::any_of(targets.begin(), targets.end(), [&](const Target &target) {
            return target.enabled && !target.mirror &&
                   std::any_of(sample.heads.begin(), sample.heads.end(), [&](const Head &head) {
                       return head.current == target && head.powered &&
                              (sample.coverage == Coverage::Unlocked || head.covered);
                   });
        });
    }
    bool refresh()
    {
        const auto &monitors = State::monitorState()->allMonitors();
        if (monitors.empty() || monitors.size() > DisplayTransaction::MaxHeads)
            return false;
        std::vector<Binding> next;
        bool changed = monitors.size() != bindings.size();
        for (const auto &monitor : monitors) {
            if (!monitor || !monitor->m_output || monitor->m_isUnsafeFallback ||
                monitor->m_output->nonDesktop || monitor->m_output->modes.empty() ||
                monitor->m_output->modes.size() > DisplayTransaction::MaxModes)
                return false;
            auto identity = nativeOutputIdentity(*monitor->m_output);
            const auto kernel = nativeKernelDrmBinding(*monitor->m_output);
            if (!identity || !kernel)
                return false;
            identity->kernelDrm = *kernel;
            std::vector<Mode> modes;
            std::set<Mode> unique;
            for (const auto &candidate : monitor->m_output->modes) {
                const auto parsed = mode(candidate);
                if (!parsed || !unique.insert(*parsed).second)
                    return false;
                modes.push_back(*parsed);
            }
            const auto retained =
                std::find_if(bindings.begin(), bindings.end(), [&](const Binding &binding) {
                    return binding.monitor.lock() == monitor &&
                           binding.output.lock() == monitor->m_output;
                });
            if (retained == bindings.end()) {
                if (nextHandle == std::numeric_limits<std::uint64_t>::max())
                    return supported = false;
                next.push_back({OutputKey{nextHandle++, 1}, monitor, monitor->m_output,
                                std::move(modes), *identity});
                changed = true;
            } else {
                auto key = retained->key;
                if (retained->modes != modes || retained->identity != *identity) {
                    if (key.generation >= std::numeric_limits<std::uint64_t>::max() - 1)
                        return supported = false;
                    ++key.generation;
                    changed = true;
                }
                next.push_back({key, monitor, monitor->m_output, std::move(modes), *identity});
            }
        }
        if (changed) {
            if (generation >= std::numeric_limits<std::uint64_t>::max() - 1)
                return supported = false;
            ++generation;
        }
        std::sort(next.begin(), next.end(),
                  [](const Binding &a, const Binding &b) { return a.key < b.key; });
        bindings = std::move(next);
        std::erase_if(overlay, [&](const auto &entry) {
            const auto current = monitorFor(entry.second.output);
            return !current || current.get() != entry.first;
        });
        return true;
    }
};
std::unique_ptr<PinnedBackend> backend;
std::unique_ptr<CompositorDisplayService> service;
std::unique_ptr<WireEndpoint> endpoint;
std::optional<std::uint32_t> restoreOriginalNative(OwnedNativeFd descriptor,
                                                   const Correlation &bound, const Layout &targets,
                                                   const Snapshot &captured, ClockSample at,
                                                   wl_resource *resource, wl_client *client)
{
    auto grant = OriginalRestorationGrant::receive(startupFence, std::move(descriptor), bound);
    if (!grant || !backend || !service || service->fenced())
        return std::nullopt;
    return backend->restoreOriginal(std::shared_ptr<OriginalRestorationGrant>{std::move(grant)},
                                    bound, targets, captured, at, resource, client);
}
std::optional<std::uint32_t> originalNativeStatus(const Correlation &bound)
{
    return backend ? backend->originalStatus(bound) : std::nullopt;
}
const std::string unavailable;
} // namespace

void initialize(wl_display &display, wl_event_loop &loop)
{
    if (backend || service)
        return;
    backend = std::make_unique<PinnedBackend>();
    service = std::make_unique<CompositorDisplayService>(loop, *backend);
    endpoint = std::make_unique<WireEndpoint>(
        display, *backend, *service,
        NativeBuildIdentity{backend->instance, UpstreamCommit, IntegrationSourceDigest},
        nativeOutputName, attestDisplayOwner,
        NativeStartupPort{
            [] { return startupFence.phase(); },
            [](int descriptor, bool ordinary, std::uint32_t guardPid) {
                ucred peer{};
                socklen_t size = sizeof(peer);
                if (getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0 ||
                    size != sizeof(peer) || peer.uid != 0 || peer.pid <= 0 ||
                    static_cast<std::uint32_t>(peer.pid) != guardPid ||
                    !startupFence.retain(descriptor, ordinary))
                    return false;
                startupEvents = wl_event_loop_add_fd(
                    g_pCompositor->m_wlEventLoop, descriptor, WL_EVENT_READABLE,
                    [](int, uint32_t, void *) {
                        startupFence.invalidate();
                        startupAdmissionChanged();
                        if (startupEvents) {
                            auto *source = startupEvents;
                            startupEvents = nullptr;
                            wl_event_source_remove(source);
                        }
                        if (g_pHyprRenderer && State::monitorState())
                            for (const auto &monitor : State::monitorState()->allMonitors())
                                if (monitor)
                                    g_pHyprRenderer->damageMonitor(monitor);
                        return 0;
                    },
                    nullptr);
                if (!startupEvents)
                    startupFence.invalidate();
                startupAdmissionChanged();
                return true; // Ownership transferred, even if event setup failed.
            }},
        NativeOriginalRestorationPort{restoreOriginalNative, originalNativeStatus});
    initializeProtectedDisplay(display);
}
void shutdown()
{
    startupFence.invalidate();
    if (startupEvents) {
        wl_event_source_remove(startupEvents);
        startupEvents = nullptr;
    }
    endpoint.reset();
    service.reset(); // Compensation while monitor/rule/lock/protection still exist.
    shutdownProtectedDisplay();
    backend.reset();
}
bool startupRecoveryAvailable()
{
    return startupFence.recoveryAvailable();
}
bool startupBlocked()
{
    return !startupFence.ordinaryAllowed();
}
bool lockReleased()
{
    if (!backend || !service || service->fenced() || startupBlocked())
        return false;
    if (backend->securityEpoch >= std::numeric_limits<std::uint64_t>::max() - 1) {
        backend->supported = false;
        return false;
    }
    ++backend->securityEpoch;
    return true;
}
void commitObserved(Monitor::CMonitor *, bool success)
{
    if (backend && backend->writing && !success)
        backend->commitFailed = true;
}
bool ownedModesetInProgress()
{
    return backend && backend->writing && backend->powerInhibitor.held();
}
bool ordinaryCommitAllowed()
{
    return !protectedDisplayActive() && ownedCommitAllowed();
}
bool ownedCommitAllowed()
{
    // A modeset can invoke native callbacks after apply's initial revalidation.
    // Recheck immediately before the actual output commit, without another bus
    // call or wait. A lost retained fence also blocks deferred commits after
    // writing returns: pending native state can still contain an owned modeset.
    // No retained transaction means ordinary rendering remains unchanged.
    if (backend && backend->originalRecovery &&
        (!backend->originalRecovery->grant->live() || backend->originalRecovery->failed))
        return false;
    return !backend || (!backend->writing && !backend->powerInhibitor.retained()) ||
           backend->powerInhibitor.held();
}
Config::CMonitorRule overlayRule(Monitor::CMonitor *monitor, Config::CMonitorRule current)
{
    if (!backend)
        return current;
    const auto recovered = backend->recoveredWlr.find(monitor);
    if (recovered != backend->recoveredWlr.end()) {
        const auto bound = backend->monitorFor(recovered->second.output);
        if (!bound || bound.get() != monitor) {
            // Raw monitor addresses can be reused after hotplug. Neither a new
            // monitor nor a replacement native output inherits this projection.
            if (backend->originalRecovery) {
                backend->originalRecovery->failed = true;
                backend->sourceCaptureValid = false;
                return current;
            }
            backend->recoveredWlr.erase(recovered);
        } else {
            const auto &lineage = recovered->second.lineage;
            const auto projected = lineage.restoredWlrProjection(current);
            if (!projected) {
                if (backend->originalRecovery)
                    backend->originalRecovery->failed = true;
                backend->sourceCaptureValid = false;
                return current;
            }
            current = *projected;
            if (backend->readingBaseRules) {
                const auto source = backend->capturedSources.find(monitor);
                if (source == backend->capturedSources.end() || source->second.wlr) {
                    backend->sourceCaptureValid = false;
                    return current;
                }
                source->second.restoredOrigin = lineage.restoredOrigin();
                source->second.mask = lineage.wlrMask();
                source->second.refreshMilliHz = lineage.wlrRefreshMilliHz();
            }
        }
    }
    if (backend->readingBaseRules || !backend->refreshBindings())
        return current;
    const auto found = backend->overlay.find(monitor);
    if (found == backend->overlay.end())
        return current;
    const auto bound = backend->monitorFor(found->second.output);
    if (!bound || bound.get() != monitor)
        return current; // Native object replacement never inherits an overlay.
    std::string mirror;
    if (found->second.mirror) {
        const auto source = backend->monitorFor(*found->second.mirror);
        if (!source)
            return current;
        mirror = source->m_name;
    }
    return overlayDisplayFields(std::move(current), found->second, mirror);
}
void nativeRuleSource(Monitor::CMonitor *monitor, const Config::CMonitorRule &rule,
                      std::optional<std::size_t> selected, bool wlr, std::uint32_t committed,
                      std::uint32_t refreshMilliHz)
{
    if (backend)
        backend->captureRuleSource(monitor, rule, selected, wlr, committed, refreshMilliHz);
}
bool ownsMonitor(Monitor::CMonitor *monitor)
{
    if (!backend || !monitor)
        return false;
    for (const auto &binding : backend->bindings) {
        if (binding.monitor.lock().get() != monitor ||
            backend->monitorFor(binding.key).get() != monitor)
            continue;
        if (backend->checkpoint.owns(monitor, binding.key) ||
            (backend->originalRecovery &&
             std::any_of(backend->originalRecovery->targets.begin(),
                         backend->originalRecovery->targets.end(),
                         [&](const Target &target) { return target.output == binding.key; })))
            return true;
        const auto recovered = backend->recoveredWlr.find(monitor);
        if (recovered != backend->recoveredWlr.end() && recovered->second.output == binding.key)
            return true;
    }
    const auto found = backend->overlay.find(monitor);
    return found != backend->overlay.end() &&
           backend->monitorFor(found->second.output).get() == monitor;
}
Backend *nativeBackend()
{
    return backend.get();
}
CompositorDisplayService *nativeTransactions()
{
    return service.get();
}
std::optional<std::string> nativeOutputName(OutputKey key)
{
    const auto monitor = backend ? backend->monitorFor(key) : nullptr;
    return monitor ? std::optional(monitor->m_name) : std::nullopt;
}
Monitor::CMonitor *nativeOutputMonitor(OutputKey key)
{
    const auto monitor = backend ? backend->monitorFor(key) : nullptr;
    return monitor.get();
}
const std::string &compositorInstance()
{
    return backend ? backend->instance : unavailable;
}
} // namespace Linura::HyprlandDisplay
