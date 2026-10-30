#include "native_display_connection.h"
#include "native_wayland_readiness.h"
#include "linura-display-management-v1-client-protocol.h"
#include "linura-display-integration-build.h"

#include <QUuid>
#include <QCryptographicHash>
#include <algorithm>
#include <bit>
#include <chrono>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <time.h>
#include <wayland-client.h>

namespace Linura::SecurityOwner {
namespace {
constexpr char Upstream[] = "efb50993780079460b0cbed1363e2166a2de1d9f";
constexpr auto ProbeBudget = std::chrono::milliseconds(250);
quint64 joined(quint32 hi, quint32 lo)
{
    return (static_cast<quint64>(hi) << 32U) | lo;
}
bool validGeneration(quint64 value)
{
    return value != 0 && value != std::numeric_limits<quint64>::max();
}
bool name(const char *value)
{
    if (!value)
        return false;
    const auto size = strnlen(value, 129);
    return size > 0 && size <= 128 && std::all_of(value, value + size, [](unsigned char c) {
               return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                      c == '-' || c == '_' || c == '.';
           });
}
bool digest(const QString &value)
{
    const auto bytes = value.toLatin1();
    return bytes.size() == 64 && bytes != QByteArray(64, '0') &&
           std::all_of(bytes.begin(), bytes.end(),
                       [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
bool correlation(const NativeDisplayCorrelation &value)
{
    const auto text = value.transaction.toLatin1();
    return text.startsWith("transaction:") && text.size() > 12 && text.size() <= 256 &&
           std::all_of(text.begin(), text.end(),
                       [](char c) {
                           return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ':' ||
                                  c == '-';
                       }) &&
           digest(value.effectDigest) && digest(value.dispatchDigest) && value.deadlineUnixMs != 0;
}
std::optional<quint64> milliseconds(clockid_t clock)
{
    timespec value{};
    if (clock_gettime(clock, &value) != 0 || value.tv_sec < 0 || value.tv_nsec < 0 ||
        value.tv_nsec >= 1'000'000'000 ||
        static_cast<quint64>(value.tv_sec) > (std::numeric_limits<quint64>::max() - 999U) / 1000U)
        return std::nullopt;
    return static_cast<quint64>(value.tv_sec) * 1000U +
           static_cast<quint64>(value.tv_nsec) / 1'000'000U;
}
bool mode(const NativeDisplayMode &value)
{
    return value.width > 0 && value.width <= 32768 && value.height > 0 && value.height <= 32768 &&
           value.refresh > 0 && value.refresh <= 1'000'000;
}
} // namespace

class NativeDisplayConnection::Impl final
{
  public:
    struct Capture;
    struct Head final
    {
        Capture *owner = nullptr;
        linura_display_head_v1 *native = nullptr;
        NativeDisplayHead facts;
        NativeDisplayTarget current;
        bool currentReceived = false, mirrorReceived = false, recoveryReceived = false,
             done = false, powered = false;
        ~Head()
        {
            if (native)
                linura_display_head_v1_destroy(native);
        }
    };
    struct Capture final
    {
        Impl &owner;
        linura_display_snapshot_v1 *native = nullptr;
        NativePinnedDisplaySample sample;
        std::map<quint64, std::unique_ptr<Head>> heads;
        bool identityReceived = false, done = false, invalid = false;
        explicit Capture(Impl &parent) : owner(parent) {}
        ~Capture()
        {
            heads.clear();
            if (native)
                linura_display_snapshot_v1_destroy(native);
        }
    };
    struct Attempt final
    {
        linura_display_attempt_v1 *native = nullptr;
        NativeDisplayCorrelation bound;
        std::optional<quint32> phase;
        bool original = false, decisionUsed = false;
        quint64 startedUnixMs = 0, startedBootMs = 0;
        ~Attempt()
        {
            if (native)
                linura_display_attempt_v1_destroy(native);
        }
    };
    wl_display *display;
    linura_display_manager_v1 *manager = nullptr;
    quint32 global = 0;
    bool healthy = true;
    std::unique_ptr<Capture> capture;
    // Terminal reservations remain in the compositor; this bounded observation
    // map never grants a replay right.
    std::map<QString, std::unique_ptr<Attempt>> attempts;
    explicit Impl(wl_display *connection) : display(connection) {}
    ~Impl()
    {
        attempts.clear();
        capture.reset();
        if (manager)
            linura_display_manager_v1_destroy(manager);
    }
    template <class F> static void callback(Capture &capture, F &&fn) noexcept
    {
        try {
            if (!capture.invalid)
                fn();
        } catch (...) {
            capture.invalid = true;
        }
    }
    static void identity(void *data, linura_display_snapshot_v1 *, const char *instance,
                         const char *upstream, const char *integration, uint32_t generationHi,
                         uint32_t generationLo, uint32_t securityHi, uint32_t securityLo,
                         uint32_t unixHi, uint32_t unixLo, uint32_t bootHi, uint32_t bootLo,
                         uint32_t coverage, uint32_t fenced)
    {
        auto &capture = *static_cast<Capture *>(data);
        callback(capture, [&] {
            if (capture.identityReceived || capture.done || !instance || !upstream ||
                !integration || strnlen(instance, 37) != 36 ||
                std::strcmp(upstream, Upstream) != 0 ||
                std::strcmp(integration, HyprlandDisplay::IntegrationSourceDigest) != 0 ||
                coverage > 3 || fenced > 1) {
                capture.invalid = true;
                return;
            }
            const auto compositor = QString::fromLatin1(instance);
            const auto uuid = QUuid::fromString(compositor);
            auto &sample = capture.sample;
            sample.compositor = compositor;
            sample.topology.generation = joined(generationHi, generationLo);
            sample.securityEpoch = joined(securityHi, securityLo);
            sample.sampledUnixMs = joined(unixHi, unixLo);
            sample.sampledBootMs = joined(bootHi, bootLo);
            sample.coverage = coverage;
            sample.fenced = fenced != 0;
            capture.identityReceived = true;
            if (uuid.isNull() || uuid.toString(QUuid::WithoutBraces) != compositor ||
                !validGeneration(sample.topology.generation) ||
                !validGeneration(sample.securityEpoch) || sample.sampledUnixMs == 0 ||
                sample.sampledBootMs == 0)
                capture.invalid = true;
        });
    }
    static void headMode(void *data, linura_display_head_v1 *, int32_t width, int32_t height,
                         int32_t refresh)
    {
        auto &head = *static_cast<Head *>(data);
        callback(*head.owner, [&] {
            const NativeDisplayMode candidate{width, height, refresh};
            if (head.done || head.facts.modes.size() >= 128 || !mode(candidate) ||
                std::find(head.facts.modes.begin(), head.facts.modes.end(), candidate) !=
                    head.facts.modes.end())
                head.owner->invalid = true;
            else
                head.facts.modes.push_back(candidate);
        });
    }
    static void current(void *data, linura_display_head_v1 *, uint32_t enabled, int32_t width,
                        int32_t height, int32_t refresh, uint32_t scaleMilli,
                        uint32_t nativeScaleBits, uint32_t transform, int32_t x, int32_t y,
                        uint32_t powered, uint32_t covered)
    {
        auto &head = *static_cast<Head *>(data);
        callback(*head.owner, [&] {
            if (head.done || head.currentReceived || enabled > 1 || powered > 1 || covered > 1 ||
                transform > 7 || x < -65536 || x > 65536 || y < -65536 || y > 65536 ||
                (enabled &&
                 (!mode({width, height, refresh}) || scaleMilli < 500 || scaleMilli > 4000 ||
                  std::bit_cast<float>(nativeScaleBits) !=
                      static_cast<float>(scaleMilli) / 1000.F)) ||
                (!enabled && (width || height || refresh || scaleMilli || nativeScaleBits ||
                              transform || x || y || powered))) {
                head.owner->invalid = true;
                return;
            }
            head.currentReceived = true;
            head.powered = powered != 0;
            head.current = {head.facts.handle,
                            head.facts.generation,
                            enabled != 0,
                            {width, height, refresh},
                            scaleMilli,
                            transform,
                            x,
                            y,
                            {}};
            head.facts.enabled = enabled != 0;
            head.facts.covered = covered != 0;
            if (enabled) {
                head.facts.current = NativeDisplayMode{width, height, refresh};
                head.facts.x = x;
                head.facts.y = y;
                head.facts.transform = static_cast<qint32>(transform);
                head.facts.scaleFixed = wl_fixed_from_double(std::bit_cast<float>(nativeScaleBits));
                head.facts.scaleMilli = scaleMilli;
                head.facts.scaleFloatBits = nativeScaleBits;
            }
        });
    }
    static void mirror(void *data, linura_display_head_v1 *, uint32_t handleHi, uint32_t handleLo,
                       uint32_t generationHi, uint32_t generationLo)
    {
        auto &head = *static_cast<Head *>(data);
        callback(*head.owner, [&] {
            if (head.done || head.mirrorReceived || !head.currentReceived || !head.current.enabled)
                head.owner->invalid = true;
            head.mirrorReceived = true;
            head.current.mirror =
                std::pair{joined(handleHi, handleLo), joined(generationHi, generationLo)};
        });
    }
    static std::optional<QByteArray> witness(const char *raw, const char *prefix,
                                             std::size_t maximum)
    {
        if (!raw)
            return std::nullopt;
        const auto size = strnlen(raw, maximum + 1);
        const auto prefixSize = std::strlen(prefix);
        if (size <= prefixSize || size > maximum || std::strncmp(raw, prefix, prefixSize) != 0 ||
            raw[size - 1] != ';' || !std::all_of(raw + prefixSize, raw + size, [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == ';' || c == '-';
            }))
            return std::nullopt;
        return QByteArray(raw, static_cast<qsizetype>(size));
    }
    static void recoveryWitness(void *data, linura_display_head_v1 *, uint32_t owned,
                                const char *target, const char *baseRule, const char *identity)
    {
        auto &head = *static_cast<Head *>(data);
        callback(*head.owner, [&] {
            const auto base = witness(baseRule, "LNDR:1;", 12 * 1024);
            const auto native = witness(identity, "LNDF:1;", 16 * 1024);
            const auto overlay = owned == 1 ? witness(target, "LNOT:1;", 512)
                                            : std::optional<QByteArray>{QByteArray{}};
            if (head.done || head.recoveryReceived || !head.currentReceived || owned > 1 || !base ||
                !native || !overlay || !target || (owned == 0 && target[0] != '\0')) {
                head.owner->invalid = true;
                return;
            }
            head.recoveryReceived = true;
            head.facts.linuraOwned = owned == 1;
            head.facts.ownedTarget = QString::fromLatin1(*overlay);
            // Native identifiers may contain monitor serials. Retain only their
            // source-versioned digest; never publish raw identity/config bytes.
            head.facts.baseRuleDigest = QString::fromLatin1(
                QCryptographicHash::hash(*base, QCryptographicHash::Sha256).toHex());
            head.facts.outputIdentityDigest = QString::fromLatin1(
                QCryptographicHash::hash(*native, QCryptographicHash::Sha256).toHex());
        });
    }
    static void headDone(void *data, linura_display_head_v1 *)
    {
        auto &head = *static_cast<Head *>(data);
        callback(*head.owner, [&] {
            if (head.done || !head.currentReceived || !head.recoveryReceived ||
                head.facts.modes.empty() ||
                (head.current.enabled && std::find(head.facts.modes.begin(), head.facts.modes.end(),
                                                   head.current.mode) == head.facts.modes.end()))
                head.owner->invalid = true;
            head.done = true;
        });
    }
    static void head(void *data, linura_display_snapshot_v1 *, linura_display_head_v1 *native,
                     uint32_t handleHi, uint32_t handleLo, uint32_t generationHi,
                     uint32_t generationLo, const char *label)
    {
        auto &capture = *static_cast<Capture *>(data);
        // Even an unsupported build can have already queued child objects.
        // Retire those proxies instead of leaking them after identity denial.
        if (capture.invalid) {
            if (native)
                linura_display_head_v1_destroy(native);
            return;
        }
        callback(capture, [&] {
            auto head = std::make_unique<Head>();
            head->owner = &capture;
            head->native = native;
            head->facts.handle = joined(handleHi, handleLo);
            head->facts.generation = joined(generationHi, generationLo);
            if (!native || capture.done || !capture.identityReceived ||
                capture.heads.size() >= 16 || !name(label) ||
                !validGeneration(head->facts.generation) ||
                capture.heads.contains(head->facts.handle)) {
                capture.invalid = true;
                return;
            }
            head->facts.name = QString::fromLatin1(label);
            static const linura_display_head_v1_listener listener{headMode, current, mirror,
                                                                  recoveryWitness, headDone};
            if (linura_display_head_v1_add_listener(native, &listener, head.get()) != 0)
                capture.invalid = true;
            capture.heads.emplace(head->facts.handle, std::move(head));
        });
    }
    static void done(void *data, linura_display_snapshot_v1 *)
    {
        auto &capture = *static_cast<Capture *>(data);
        callback(capture, [&] {
            if (capture.done || !capture.identityReceived || capture.heads.empty()) {
                capture.invalid = true;
                return;
            }
            std::set<QString> names;
            for (const auto &[handle, head] : capture.heads) {
                (void)handle;
                if (!head->done || !names.insert(head->facts.name).second) {
                    capture.invalid = true;
                    return;
                }
                if (head->current.mirror) {
                    const auto source = capture.heads.find(head->current.mirror->first);
                    if (source == capture.heads.end() || source->second.get() == head.get() ||
                        source->second->facts.generation != head->current.mirror->second ||
                        !source->second->current.enabled || source->second->current.mirror ||
                        source->second->current.x != head->current.x ||
                        source->second->current.y != head->current.y) {
                        capture.invalid = true;
                        return;
                    }
                }
                capture.sample.topology.heads.push_back(head->facts);
                capture.sample.current.outputs.push_back(head->current);
            }
            capture.done = true;
        });
    }
    static void unavailable(void *data, linura_display_snapshot_v1 *)
    {
        static_cast<Capture *>(data)->invalid = true;
    }
    bool sync()
    {
        if (!healthy || !display || !manager || !waitForNativeWaylandReady(display, ProbeBudget)) {
            healthy = false;
            return false;
        }
        return healthy && wl_display_get_error(display) == 0;
    }
    Attempt *attempt(const NativeDisplayCorrelation &bound)
    {
        if (!healthy || !manager || !correlation(bound))
            return nullptr;
        auto retained = attempts.find(bound.transaction);
        if (retained != attempts.end() && retained->second->bound != bound)
            return nullptr;
        if (retained == attempts.end()) {
            if (attempts.size() >= 256)
                return nullptr;
            auto value = std::make_unique<Attempt>();
            value->bound = bound;
            retained = attempts.emplace(bound.transaction, std::move(value)).first;
        }
        auto &value = *retained->second;
        if (value.native)
            return &value;
        value.native = linura_display_manager_v1_get_attempt(
            manager, bound.transaction.toLatin1().constData(),
            bound.effectDigest.toLatin1().constData(), bound.dispatchDigest.toLatin1().constData(),
            static_cast<quint32>(bound.deadlineUnixMs >> 32U),
            static_cast<quint32>(bound.deadlineUnixMs));
        static const linura_display_attempt_v1_listener listener{
            [](void *data, linura_display_attempt_v1 *, uint32_t phase) {
                auto &attempt = *static_cast<Attempt *>(data);
                attempt.phase = phase <= 8 ? std::optional(phase) : std::nullopt;
            }};
        if (!value.native ||
            linura_display_attempt_v1_add_listener(value.native, &listener, &value) != 0)
            return nullptr;
        return &value;
    }
    std::optional<quint32> completed(Attempt &attempt)
    {
        const bool replied = sync();
        const auto phase = replied ? attempt.phase : std::nullopt;
        if (!attempt.original || attempt.decisionUsed || (phase && *phase != 2 && *phase != 3)) {
            if (attempt.native) {
                linura_display_attempt_v1_destroy(attempt.native);
                attempt.native = nullptr;
            }
        }
        // Keep the local correlation and one-use flags. Retiring a wire object
        // never evicts a dispatch tombstone or creates another apply right.
        return phase;
    }
};

NativeDisplayConnection::NativeDisplayConnection(wl_display *ownedConnection)
    : impl_(std::make_unique<Impl>(ownedConnection))
{}
NativeDisplayConnection::~NativeDisplayConnection() = default;
void NativeDisplayConnection::announce(wl_registry *registry, quint32 name, quint32 version)
{
    if (!impl_->healthy || !registry || version < 1 || impl_->global != 0) {
        impl_->healthy = false;
        return;
    }
    impl_->global = name;
    impl_->manager = static_cast<linura_display_manager_v1 *>(
        wl_registry_bind(registry, name, &linura_display_manager_v1_interface, 1));
    if (!impl_->manager)
        impl_->healthy = false;
}
void NativeDisplayConnection::removed(quint32 name)
{
    if (name == impl_->global)
        impl_->healthy = false; // No rebind/adoption of a replacement compositor.
}
bool NativeDisplayConnection::advertised() const noexcept
{
    return impl_->global != 0;
}
bool NativeDisplayConnection::securityTransitionAllowed(bool currentlySecure)
{
    if (!impl_->display || !impl_->healthy || wl_display_get_error(impl_->display) != 0)
        return false;
    if (!advertised())
        return true;
    const auto current = sample();
    return current && !current->fenced && current->coverage == (currentlySecure ? 1U : 0U);
}
std::optional<NativePinnedDisplaySample> NativeDisplayConnection::sample()
{
    if (!impl_->healthy || !impl_->manager)
        return std::nullopt;
    impl_->capture = std::make_unique<Impl::Capture>(*impl_);
    auto &capture = *impl_->capture;
    capture.native = linura_display_manager_v1_get_snapshot(impl_->manager);
    static const linura_display_snapshot_v1_listener listener{Impl::identity, Impl::head,
                                                              Impl::done, Impl::unavailable};
    if (!capture.native ||
        linura_display_snapshot_v1_add_listener(capture.native, &listener, &capture) != 0 ||
        !impl_->sync() || capture.invalid || !capture.done) {
        impl_->healthy = false;
        return std::nullopt;
    }
    const auto wall = milliseconds(CLOCK_REALTIME), boot = milliseconds(CLOCK_BOOTTIME);
    if (!wall || !boot || *wall < capture.sample.sampledUnixMs ||
        *boot < capture.sample.sampledBootMs || *wall - capture.sample.sampledUnixMs >= 2000 ||
        *boot - capture.sample.sampledBootMs >= 2000)
        return std::nullopt;
    return capture.sample;
}
std::optional<quint32> NativeDisplayConnection::apply(const NativeDisplayCorrelation &bound,
                                                      const NativeDisplayLayout &baseline,
                                                      const NativeDisplayLayout &desired)
{
    if (!impl_->capture || impl_->capture->invalid || !impl_->capture->done ||
        impl_->capture->sample.fenced || baseline.encode() == desired.encode() ||
        baseline.topology != desired.topology ||
        baseline.topology.section(QLatin1Char(':'), 7, 7) != impl_->capture->sample.compositor ||
        !baseline.nativeOptions(impl_->capture->sample.topology) ||
        !desired.nativeOptions(impl_->capture->sample.topology) ||
        baseline.outputs.size() != impl_->capture->heads.size() ||
        desired.outputs.size() != impl_->capture->heads.size() ||
        baseline.outputs.size() != impl_->capture->sample.current.outputs.size() ||
        impl_->attempts.contains(bound.transaction))
        return std::nullopt;
    // Rust's independently validated visibility precondition must still hold
    // in this last native snapshot. DPMS can change without a topology epoch or
    // layout diff; do not remove the only currently powered independent root.
    if (!std::any_of(desired.outputs.begin(), desired.outputs.end(), [&](const auto &target) {
            const auto head = impl_->capture->heads.find(target.handle);
            return target.enabled && !target.mirror && head != impl_->capture->heads.end() &&
                   head->second->facts.generation == target.generation && head->second->powered;
        }))
        return std::nullopt;
    const auto wall = milliseconds(CLOCK_REALTIME), boot = milliseconds(CLOCK_BOOTTIME);
    const auto &sample = impl_->capture->sample;
    if (!wall || !boot || *wall < sample.sampledUnixMs || *boot < sample.sampledBootMs ||
        *wall - sample.sampledUnixMs >= 2000 || *boot - sample.sampledBootMs >= 2000 ||
        bound.deadlineUnixMs <= *wall || bound.deadlineUnixMs - sample.sampledUnixMs > 15'000)
        return std::nullopt;
    for (std::size_t i = 0; i < baseline.outputs.size(); ++i)
        if (baseline.outputs[i].encode() != impl_->capture->sample.current.outputs[i].encode())
            return std::nullopt;
    auto *attempt = impl_->attempt(bound);
    if (!attempt)
        return std::nullopt;
    // Reserve before every potentially effectful wire request. A lost sync
    // cannot recreate an original attempt or grant another apply/decision.
    attempt->original = true;
    attempt->startedUnixMs = *wall;
    attempt->startedBootMs = *boot;
    linura_display_attempt_v1_configure(attempt->native, impl_->capture->native);
    for (const auto &target : desired.outputs) {
        const auto head = impl_->capture->heads.find(target.handle);
        if (head == impl_->capture->heads.end() ||
            head->second->facts.generation != target.generation)
            return std::nullopt;
        if (!target.enabled)
            linura_display_attempt_v1_disable_head(attempt->native, head->second->native);
        else {
            linura_display_head_v1 *mirror = nullptr;
            if (target.mirror) {
                const auto root = impl_->capture->heads.find(target.mirror->first);
                if (root == impl_->capture->heads.end() ||
                    root->second->facts.generation != target.mirror->second)
                    return std::nullopt;
                mirror = root->second->native;
            }
            linura_display_attempt_v1_enable_head(attempt->native, head->second->native,
                                                  target.mode.width, target.mode.height,
                                                  target.mode.refresh, target.scaleMilli,
                                                  target.transform, target.x, target.y, mirror);
        }
    }
    attempt->phase.reset();
    linura_display_attempt_v1_apply(attempt->native);
    return impl_->completed(*attempt);
}
std::optional<quint32> NativeDisplayConnection::status(const NativeDisplayCorrelation &bound)
{
    auto *attempt = impl_->attempt(bound);
    if (!attempt)
        return std::nullopt;
    attempt->phase.reset();
    linura_display_attempt_v1_get_status(attempt->native);
    return impl_->completed(*attempt);
}
bool NativeDisplayCorrelation::valid() const
{
    return correlation(*this);
}
bool NativeDisplayDecision::valid() const
{
    return correlation.valid() && digest(decisionDigest) && digest(protectedDecisionDigest);
}
bool NativeDisplayCorrelation::dispatchWindow(quint64 sampledBootMs, quint64 nowBootMs,
                                              quint64 nowUnixMs) const
{
    return valid() && sampledBootMs != 0 && nowBootMs >= sampledBootMs &&
           nowBootMs - sampledBootMs < 2000 && nowUnixMs != 0 && deadlineUnixMs > nowUnixMs &&
           deadlineUnixMs - nowUnixMs <= 15'000;
}
bool NativeDisplayCorrelation::decisionWindow(quint64 startedUnixMs, quint64 startedBootMs,
                                              quint64 nowUnixMs, quint64 nowBootMs) const
{
    return valid() && startedUnixMs != 0 && startedBootMs != 0 && deadlineUnixMs > startedUnixMs &&
           deadlineUnixMs - startedUnixMs <= 15'000 && nowUnixMs >= startedUnixMs &&
           nowUnixMs < deadlineUnixMs && nowBootMs >= startedBootMs &&
           nowBootMs - startedBootMs < deadlineUnixMs - startedUnixMs;
}
std::optional<quint32> NativeDisplayConnection::decide(const NativeDisplayCorrelation &bound,
                                                       bool confirm)
{
    const auto retained = impl_->attempts.find(bound.transaction);
    if (retained == impl_->attempts.end() || retained->second->bound != bound ||
        !retained->second->original || retained->second->decisionUsed || !impl_->healthy)
        return std::nullopt;
    const auto wall = milliseconds(CLOCK_REALTIME), boot = milliseconds(CLOCK_BOOTTIME);
    const auto &original = *retained->second;
    if (!wall || !boot ||
        !bound.decisionWindow(original.startedUnixMs, original.startedBootMs, *wall, *boot))
        return std::nullopt;
    auto *current = impl_->attempt(bound);
    if (!current)
        return std::nullopt;
    auto &attempt = *current;
    attempt.decisionUsed = true;
    attempt.phase.reset();
    if (confirm)
        linura_display_attempt_v1_confirm(attempt.native);
    else
        linura_display_attempt_v1_restore(attempt.native);
    return impl_->completed(attempt);
}

} // namespace Linura::SecurityOwner
