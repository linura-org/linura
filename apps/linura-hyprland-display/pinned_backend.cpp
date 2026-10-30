#include "pinned_integration.h"
#include "pinned_protected.h"
#include "native_scale.h"
#include "rule_overlay.h"
#include "recovery_witness.h"
#include "wire_endpoint.h"
#include "native_power_inhibitor.h"
#include "native_owner_admission.h"
#include "native_output_identity.h"
#include "linura-display-integration-build.h"

#include "src/Compositor.hpp"
#include "src/config/ConfigValue.hpp"
#include "src/config/shared/monitor/MonitorRuleManager.hpp"
#include "src/managers/SessionLockManager.hpp"
#include "src/output/Monitor.hpp"
#include "src/state/MonitorState.hpp"
#include "src/version.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <limits>
#include <map>
#include <set>
#include <string_view>
#include <sys/random.h>

namespace Linura::HyprlandDisplay {
static_assert(std::string_view(GIT_COMMIT_HASH) == UpstreamCommit,
              "Linura display integration requires the exact qualified Hyprland source");
namespace {
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
    using RuleCheckpoint = RuleOverlayCheckpoint<Monitor::CMonitor *, Config::CMonitorRule>;
    RuleCheckpoint checkpoint;
    const std::string instance = instanceId();
    bool writing = false, commitFailed = false, supported = true, readingBaseRules = false;
    NativePowerInhibitor powerInhibitor;

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
            const auto base = RecoveryWitness::rule(rule->second);
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
        if (!rules || !checkpoint.capture(overlay, *rules, baseline))
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
        auto prior = rules ? checkpoint.restoration(targets, *rules,
                                                    sameOwnedDisplayFields<Config::CMonitorRule>)
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
        if (commitFailed || !roots || roots->generation != expected.generation ||
            roots->securityEpoch != expected.securityEpoch ||
            !hasDesiredPoweredRoot(targets, *roots) || !currentRules ||
            !checkpoint.restoration(targets, *currentRules,
                                    sameOwnedDisplayFields<Config::CMonitorRule>))
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
        const auto rules = baseRules();
        return rules &&
               checkpoint.restored(overlay, *rules, sameOwnedDisplayFields<Config::CMonitorRule>);
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

  private:
    [[nodiscard]] std::optional<RuleCheckpoint::Rules> baseRules()
    {
        if (readingBaseRules || !Config::monitorRuleMgr())
            return std::nullopt;
        readingBaseRules = true;
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
            rules.emplace(monitor.get(), std::move(rule));
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
        return left.coverage == right.coverage && left.heads.size() == right.heads.size() &&
               std::equal(left.heads.begin(), left.heads.end(), right.heads.begin(),
                          [](const Head &a, const Head &b) {
                              return a.key == b.key && a.current == b.current &&
                                     a.modes == b.modes && a.powered == b.powered &&
                                     a.covered == b.covered;
                          });
    }
    static bool hasDesiredPoweredRoot(const Layout &targets, const Snapshot &sample)
    {
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
            const auto identity = nativeOutputIdentity(*monitor->m_output);
            if (!identity)
                return false;
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
        nativeOutputName, attestDisplayOwner);
    initializeProtectedDisplay(display);
}
void shutdown()
{
    shutdownProtectedDisplay();
    endpoint.reset();
    service.reset(); // Compensation while monitor/rule/lock managers still exist.
    backend.reset();
}
bool lockReleased()
{
    if (!backend || !service || service->fenced())
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
bool ownedCommitAllowed()
{
    // A modeset can invoke native callbacks after apply's initial revalidation.
    // Recheck immediately before the actual output commit, without another bus
    // call or wait. A lost retained fence also blocks deferred commits after
    // writing returns: pending native state can still contain an owned modeset.
    // No retained transaction means ordinary rendering remains unchanged.
    return !backend || (!backend->writing && !backend->powerInhibitor.retained()) ||
           backend->powerInhibitor.held();
}
Config::CMonitorRule overlayRule(Monitor::CMonitor *monitor, Config::CMonitorRule current)
{
    if (!backend || backend->readingBaseRules || !backend->refreshBindings())
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
bool ownsMonitor(Monitor::CMonitor *monitor)
{
    if (!backend || !monitor)
        return false;
    for (const auto &binding : backend->bindings)
        if (binding.monitor.lock().get() == monitor &&
            backend->monitorFor(binding.key).get() == monitor &&
            backend->checkpoint.owns(monitor, binding.key))
            return true;
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
