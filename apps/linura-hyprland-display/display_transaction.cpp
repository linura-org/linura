#include "display_transaction.h"

#include <algorithm>
#include <limits>
#include <set>
#include <utility>

namespace Linura::HyprlandDisplay {
namespace {
bool validMode(const Mode &mode)
{
    return mode.width > 0 && mode.width <= 32768 && mode.height > 0 && mode.height <= 32768 &&
           mode.refreshMilliHz > 0 && mode.refreshMilliHz <= 1'000'000;
}
bool digest(const std::string &value)
{
    return value.size() == 64 && value != std::string(64, '0') &&
           std::all_of(value.begin(), value.end(),
                       [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
bool validCorrelation(const Correlation &value)
{
    return value.transaction.starts_with("transaction:") && value.transaction.size() > 12 &&
           value.transaction.size() <= 256 &&
           std::all_of(value.transaction.begin(), value.transaction.end(),
                       [](char c) {
                           return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ':' ||
                                  c == '-';
                       }) &&
           digest(value.effectDigest) && digest(value.dispatchDigest);
}
bool visible(const Snapshot &sample)
{
    return std::any_of(sample.heads.begin(), sample.heads.end(), [](const Head &head) {
        return head.current.enabled && !head.current.mirror && head.powered;
    });
}
} // namespace

bool DisplayTransaction::validLayout(const Layout &layout, const Snapshot &snapshot)
{
    if (snapshot.generation == 0 || snapshot.securityEpoch == 0 ||
        snapshot.generation == std::numeric_limits<std::uint64_t>::max() || layout.empty() ||
        layout.size() > MaxHeads || layout.size() != snapshot.heads.size())
        return false;
    std::set<OutputKey> keys;
    bool root = false;
    for (std::size_t i = 0; i < layout.size(); ++i) {
        const auto &target = layout[i];
        const auto &head = snapshot.heads[i];
        if (target.output != head.key || head.current.output != head.key ||
            head.key.generation == 0 ||
            head.key.generation == std::numeric_limits<std::uint64_t>::max() ||
            (i != 0 && layout[i - 1].output.handle >= target.output.handle) ||
            !keys.insert(head.key).second || head.modes.empty() || head.modes.size() > MaxModes)
            return false;
        std::set<Mode> modes;
        for (const auto &mode : head.modes) {
            if (!validMode(mode) || !modes.insert(mode).second)
                return false;
        }
        if (!target.enabled) {
            if (target.mode != Mode{} || target.scaleMilli != 0 || target.transform != 0 ||
                target.x != 0 || target.y != 0 || target.mirror)
                return false;
            continue;
        }
        if (!modes.contains(target.mode) || target.scaleMilli < 500 || target.scaleMilli > 4000 ||
            target.transform > 7 || target.x < -65536 || target.x > 65536 || target.y < -65536 ||
            target.y > 65536)
            return false;
        const auto width = target.transform % 2 == 0 ? target.mode.width : target.mode.height;
        const auto height = target.transform % 2 == 0 ? target.mode.height : target.mode.width;
        if ((static_cast<std::int64_t>(width) * 1000 + target.scaleMilli - 1) / target.scaleMilli >
                32768 ||
            (static_cast<std::int64_t>(height) * 1000 + target.scaleMilli - 1) / target.scaleMilli >
                32768)
            return false;
        if (!target.mirror)
            root = true;
    }
    for (const auto &target : layout) {
        if (!target.mirror)
            continue;
        const auto root = std::find_if(layout.begin(), layout.end(), [&](const Target &other) {
            return other.output == *target.mirror;
        });
        if (*target.mirror == target.output || root == layout.end() || !root->enabled ||
            root->mirror || root->x != target.x || root->y != target.y)
            return false;
    }
    return root;
}

DisplayTransaction::DisplayTransaction(Backend &backend, Correlation correlation, Layout baseline,
                                       Layout desired, Snapshot inventory, ClockSample armed,
                                       std::uint64_t deadlineBootMs)
    : backend_(backend), correlation_(std::move(correlation)), baseline_(std::move(baseline)),
      desired_(std::move(desired)), inventory_(std::move(inventory)), armed_(armed),
      deadlineBootMs_(deadlineBootMs), secureSeen_(inventory_.coverage == Coverage::Secure)
{}
DisplayTransaction::~DisplayTransaction()
{
    // Ordinary compositor teardown also reserves compensation once. SIGKILL or
    // compositor loss is not represented as verified restoration.
    restore();
}
std::unique_ptr<DisplayTransaction>
DisplayTransaction::start(Backend &backend, const Correlation &correlation, const Layout &baseline,
                          const Layout &desired, const Snapshot &captured, ClockSample now)
{
    if (!validCorrelation(correlation) || now.unixMs == 0 || now.bootMs == 0 ||
        now.unixMs >= correlation.deadlineUnixMs ||
        correlation.deadlineUnixMs - now.unixMs > WindowMs || baseline == desired)
        return {};
    const auto remaining = correlation.deadlineUnixMs - now.unixMs;
    if (now.bootMs > std::numeric_limits<std::uint64_t>::max() - remaining)
        return {};
    std::optional<Snapshot> sample;
    try {
        sample = backend.snapshot();
    } catch (...) {
        return {};
    }
    if (!sample || *sample != captured || !validLayout(baseline, *sample) ||
        !validLayout(desired, *sample))
        return {};
    auto attempt = std::unique_ptr<DisplayTransaction>(new DisplayTransaction(
        backend, correlation, baseline, desired, *sample, now, now.bootMs + remaining));
    if (!attempt->scopeMatches(*sample) || !attempt->matches(baseline, *sample)) {
        // No write was constructed; destruction must not create compensation.
        attempt->phase_ = Phase::RecoveryFailed;
        return {};
    }
    try {
        const auto completed = backend.clock();
        if (!completed || attempt->expired(*completed)) {
            attempt->phase_ = Phase::RecoveryFailed;
            return {};
        }
    } catch (...) {
        attempt->phase_ = Phase::RecoveryFailed;
        return {};
    }
    // The owning endpoint must retain a dispatch tombstone before entering this
    // method. The attempt itself reserves the write before calling the backend.
    try {
        if (!backend.applyOwnedLayout(desired, *sample))
            attempt->restore();
        const auto completed = backend.clock();
        if (!completed || attempt->expired(*completed))
            attempt->restore();
    } catch (...) {
        attempt->restore();
    }
    return attempt;
}
bool DisplayTransaction::scopeMatches(const Snapshot &sample)
{
    if (sample.generation != inventory_.generation ||
        sample.securityEpoch != inventory_.securityEpoch ||
        sample.heads.size() != inventory_.heads.size() ||
        (sample.coverage != Coverage::Unlocked && sample.coverage != Coverage::Secure) ||
        (secureSeen_ && sample.coverage != Coverage::Secure))
        return false;
    for (std::size_t i = 0; i < sample.heads.size(); ++i) {
        if (sample.heads[i].key != inventory_.heads[i].key ||
            sample.heads[i].modes != inventory_.heads[i].modes ||
            (sample.coverage == Coverage::Secure && !sample.heads[i].covered))
            return false;
    }
    secureSeen_ = secureSeen_ || sample.coverage == Coverage::Secure;
    return true;
}
bool DisplayTransaction::matches(const Layout &layout, const Snapshot &sample) const
{
    return validLayout(layout, sample) && visible(sample) &&
           std::equal(
               layout.begin(), layout.end(), sample.heads.begin(),
               [](const Target &target, const Head &head) { return target == head.current; });
}
bool DisplayTransaction::expired(ClockSample now) const
{
    return now.unixMs < armed_.unixMs || now.bootMs < armed_.bootMs ||
           now.unixMs >= correlation_.deadlineUnixMs || now.bootMs >= deadlineBootMs_;
}
bool DisplayTransaction::confirm(const Correlation &correlation, ClockSample now)
{
    if (phase_ != Phase::Pending || correlation != correlation_ || expired(now))
        return false;
    try {
        const auto sample = backend_.snapshot();
        if (!sample || !scopeMatches(*sample) || !matches(desired_, *sample))
            return false;
        const auto completed = backend_.clock();
        if (!completed || expired(*completed))
            return false;
        phase_ = Phase::Confirmed;
        return true;
    } catch (...) {
        return false;
    }
}
void DisplayTransaction::restore()
{
    if (phase_ != Phase::Pending)
        return;
    // Reservation precedes the first possible compensation, including a native
    // partial failure or exception. Subsequent queries never repeat the write.
    phase_ = Phase::Restoring;
    try {
        const auto sample = backend_.snapshot();
        if (!sample || !scopeMatches(*sample) || !validLayout(baseline_, *sample)) {
            phase_ = Phase::RecoveryFailed;
            return;
        }
        if (!backend_.applyOwnedLayout(baseline_, *sample))
            phase_ = Phase::RecoveryFailed;
    } catch (...) {
        phase_ = Phase::RecoveryFailed;
    }
    // Even a successful acknowledgement remains Restoring. A later snapshot is
    // required; Rust independently verifies again before durable retirement.
}
void DisplayTransaction::verifyRestoration()
{
    if (phase_ != Phase::Restoring && phase_ != Phase::RecoveryFailed)
        return;
    try {
        const auto sample = backend_.snapshot();
        if (sample && scopeMatches(*sample) && matches(baseline_, *sample))
            phase_ = Phase::Restored;
    } catch (...) {
        // A failed observation cannot become restoration, nor grant a retry.
    }
}
void DisplayTransaction::tick(std::optional<ClockSample> now)
{
    if (phase_ == Phase::Pending && (!now || expired(*now)))
        restore();
    else
        verifyRestoration();
}
DisplayTransaction::Phase DisplayTransaction::phase() const noexcept
{
    return phase_;
}
bool DisplayTransaction::fenced() const noexcept
{
    return phase_ != Phase::Confirmed && phase_ != Phase::Restored;
}
const Correlation &DisplayTransaction::correlation() const noexcept
{
    return correlation_;
}
} // namespace Linura::HyprlandDisplay
