#include "native_display_topology.h"
#include "wlr-output-management-unstable-v1-client-protocol.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCryptographicHash>
#include <QtEndian>
#include <wayland-client.h>
#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <set>

namespace Linura::SecurityOwner {
namespace {
constexpr std::size_t MaximumHeads = 16, MaximumModes = 128;
bool boundedName(const char *name)
{
    if (!name)
        return false;
    const std::size_t size = strnlen(name, 129);
    return size > 0 && size <= 128 && std::all_of(name, name + size, [](unsigned char value) {
               return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
                      (value >= '0' && value <= '9') || value == '-' || value == '_' ||
                      value == '.';
           });
}
bool validMode(const NativeDisplayMode &mode)
{
    return mode.width > 0 && mode.width <= 32768 && mode.height > 0 && mode.height <= 32768 &&
           mode.refresh > 0 && mode.refresh <= 1'000'000;
}
QJsonArray modeWire(const NativeDisplayMode &mode)
{
    return {mode.width, mode.height, mode.refresh};
}
} // namespace

QString NativeDisplaySnapshot::encode() const
{
    QJsonArray entries;
    for (const auto &head : heads) {
        const auto &kernel = head.kernelDrm;
        if (kernel != std::array<quint32, 3>{} &&
            (kernel[0] != 226 || kernel[1] > 63 || kernel[2] == 0))
            return {};
        QJsonArray modes;
        for (const auto &mode : head.modes)
            modes.append(modeWire(mode));
        entries.append(QJsonObject{
            {"handle", QString::number(head.handle)},
            {"generation", QString::number(head.generation)},
            {"name", head.name},
            {"enabled", head.enabled},
            {"covered", head.covered},
            {"modes", modes},
            {"current_mode", head.current ? QJsonValue(modeWire(*head.current)) : QJsonValue()},
            {"x", head.x},
            {"y", head.y},
            {"transform", head.transform},
            {"scale_fixed", head.scaleFixed},
            {"scale_milli", static_cast<qint64>(head.scaleMilli)},
            {"scale_float_bits", static_cast<qint64>(head.scaleFloatBits)},
            {"linura_owned", head.linuraOwned},
            {"owned_target", head.ownedTarget},
            {"base_rule_digest", head.baseRuleDigest},
            {"output_identity_digest", head.outputIdentityDigest},
            {"kernel_drm",
             QJsonArray{static_cast<qint64>(kernel[0]), static_cast<qint64>(kernel[1]),
                        static_cast<qint64>(kernel[2])}}});
    }
    const auto bytes = QJsonDocument(QJsonObject{{"schema", 4},
                                                 {"generation", QString::number(generation)},
                                                 {"heads", entries}})
                           .toJson(QJsonDocument::Compact);
    return bytes.size() <= 64 * 1024 ? QString::fromUtf8(bytes) : QString{};
}

std::optional<QString> NativeDisplaySnapshot::baselineGuard(const QString &baseline) const
{
    if (heads.empty() || heads.size() > MaximumHeads || baseline.isEmpty() ||
        baseline.size() > 4096)
        return std::nullopt;
    std::vector<const NativeDisplayHead *> ordered;
    for (const auto &head : heads)
        ordered.push_back(&head);
    std::sort(ordered.begin(), ordered.end(), [](const auto *a, const auto *b) {
        return std::pair{a->handle, a->generation} < std::pair{b->handle, b->generation};
    });
    auto digest = [](const QString &value) {
        return value.size() == 64 && value != QString(64, QLatin1Char('0')) &&
               std::all_of(value.cbegin(), value.cend(), [](QChar c) {
                   const auto n = c.unicode();
                   return (n >= '0' && n <= '9') || (n >= 'a' && n <= 'f');
               });
    };
    auto append = [](QByteArray &out, const QByteArray &value) {
        const auto size = qToBigEndian(static_cast<quint64>(value.size()));
        out.append(reinterpret_cast<const char *>(&size), sizeof(size));
        out.append(value);
    };
    QByteArray rows;
    std::optional<quint64> last;
    for (const auto *head : ordered) {
        if ((last && *last == head->handle) || head->generation == 0 ||
            head->generation == std::numeric_limits<quint64>::max() ||
            !digest(head->baseRuleDigest) || !digest(head->outputIdentityDigest) ||
            head->ownedTarget.size() > 512 ||
            (head->linuraOwned ? !head->ownedTarget.startsWith(QLatin1String("LNOT:1;"))
                               : !head->ownedTarget.isEmpty()))
            return std::nullopt;
        last = head->handle;
        for (const auto &value :
             {QString::number(head->handle), QString::number(head->generation),
              head->linuraOwned ? QStringLiteral("true") : QStringLiteral("false"),
              head->baseRuleDigest, head->outputIdentityDigest, head->ownedTarget})
            append(rows, value.toUtf8());
    }
    QByteArray canonical;
    append(canonical, "linura.display.native-baseline-guard.v1");
    append(canonical, baseline.toUtf8());
    append(canonical, rows);
    return QString::fromLatin1(
        QCryptographicHash::hash(canonical, QCryptographicHash::Sha256).toHex());
}

std::optional<NativeDisplaySnapshot>
projectOwnerDisplayCoverage(NativeDisplaySnapshot snapshot,
                            const std::vector<NativeLockOutputCoverage> &surfaces)
{
    if (snapshot.heads.empty() || snapshot.heads.size() > MaximumHeads ||
        surfaces.size() > MaximumHeads)
        return std::nullopt;
    // The private compositor sample describes its safety fence, including
    // disabled outputs. This observation describes independently verified owner
    // surfaces. No incoming covered bit, even on an active head, is evidence.
    for (auto &head : snapshot.heads)
        head.covered = false;
    std::set<QString> seen;
    for (const auto &surface : surfaces) {
        if (surface.outputName.isEmpty() || !seen.insert(surface.outputName).second)
            return std::nullopt;
        const auto found =
            std::find_if(snapshot.heads.begin(), snapshot.heads.end(), [&](const auto &head) {
                return head.enabled && head.name == surface.outputName;
            });
        if (found == snapshot.heads.end())
            return std::nullopt; // Stale/mismatched owner inventory is not settled.
        found->covered = surface.covered;
    }
    return snapshot;
}

class NativeDisplayTopology::Impl final
{
  public:
    struct Head;
    struct Mode final
    {
        Head *head = nullptr;
        zwlr_output_mode_v1 *native = nullptr;
        NativeDisplayMode value;
        bool sizeReceived = false, refreshReceived = false;
        ~Mode()
        {
            if (native)
                zwlr_output_mode_v1_release(native);
        }
    };
    struct Head final
    {
        Impl *owner = nullptr;
        zwlr_output_head_v1 *native = nullptr;
        NativeDisplayHead value;
        std::map<zwlr_output_mode_v1 *, std::unique_ptr<Mode>> modes;
        zwlr_output_mode_v1 *current = nullptr;
        bool enabledReceived = false, positionReceived = false;
        bool transformReceived = false, scaleReceived = false;
        ~Head()
        {
            modes.clear();
            if (native)
                zwlr_output_head_v1_release(native);
        }
    };
    zwlr_output_manager_v1 *manager = nullptr;
    quint32 global = 0;
    quint64 generation = 0, nextHandle = 0;
    bool healthy = true, initialDone = false;
    std::map<zwlr_output_head_v1 *, std::unique_ptr<Head>> heads;

    ~Impl()
    {
        heads.clear();
        if (manager) {
            // Local proxy cleanup only; after finished no request is legal.
            // The connection owner subsequently closes the actual connection.
            zwlr_output_manager_v1_destroy(manager);
        }
    }
    void invalidate()
    {
        healthy = false;
    }
    bool advance()
    {
        if (generation >= std::numeric_limits<quint64>::max() - 1) {
            invalidate();
            return false;
        }
        ++generation;
        return true;
    }
    template <class F> static void callback(Impl &self, F &&function) noexcept
    {
        try {
            if (self.healthy)
                function();
        } catch (...) {
            self.invalidate();
        }
    }
    template <class F> static void headCallback(void *data, F &&function) noexcept
    {
        auto &head = *static_cast<Head *>(data);
        callback(*head.owner, [&] { function(head); });
    }
    static void name(void *data, zwlr_output_head_v1 *, const char *name)
    {
        headCallback(data, [&](Head &head) {
            if (!head.value.name.isEmpty() || !boundedName(name)) {
                head.owner->invalidate();
                return;
            }
            head.value.name = QString::fromLatin1(name);
        });
    }
    static void ignoredText(void *, zwlr_output_head_v1 *, const char *) {}
    static void physicalSize(void *, zwlr_output_head_v1 *, int32_t, int32_t) {}
    static void enabled(void *data, zwlr_output_head_v1 *, int32_t value)
    {
        headCallback(data, [&](Head &head) {
            if (value != 0 && value != 1) {
                head.owner->invalidate();
                return;
            }
            head.enabledReceived = true;
            head.value.enabled = value == 1;
            if (!head.value.enabled) {
                head.current = nullptr;
                head.positionReceived = head.transformReceived = head.scaleReceived = false;
            }
        });
    }
    static void currentMode(void *data, zwlr_output_head_v1 *, zwlr_output_mode_v1 *mode)
    {
        headCallback(data, [&](Head &head) {
            if (!head.modes.contains(mode)) {
                head.owner->invalidate();
                return;
            }
            head.current = mode;
        });
    }
    static void position(void *data, zwlr_output_head_v1 *, int32_t x, int32_t y)
    {
        headCallback(data, [&](Head &head) {
            head.value.x = x;
            head.value.y = y;
            head.positionReceived = true;
        });
    }
    static void transform(void *data, zwlr_output_head_v1 *, int32_t value)
    {
        headCallback(data, [&](Head &head) {
            if (value < 0 || value > 7) {
                head.owner->invalidate();
                return;
            }
            head.value.transform = value;
            head.transformReceived = true;
        });
    }
    static void scale(void *data, zwlr_output_head_v1 *, wl_fixed_t value)
    {
        headCallback(data, [&](Head &head) {
            if (value < 128 || value > 1024) {
                head.owner->invalidate();
                return;
            }
            head.value.scaleFixed = value;
            head.scaleReceived = true;
        });
    }
    static void adaptiveSync(void *data, zwlr_output_head_v1 *, uint32_t value)
    {
        headCallback(data, [&](Head &head) {
            if (value > 1)
                head.owner->invalidate();
        });
    }
    static void finishedHead(void *data, zwlr_output_head_v1 *native)
    {
        auto &head = *static_cast<Head *>(data);
        auto *self = head.owner;
        callback(*self, [&] {
            if (self->advance())
                self->heads.erase(native);
        });
    }
    static void sizeMode(void *data, zwlr_output_mode_v1 *, int32_t width, int32_t height)
    {
        auto &mode = *static_cast<Mode *>(data);
        callback(*mode.head->owner, [&] {
            if (mode.sizeReceived) {
                mode.head->owner->invalidate();
                return;
            }
            mode.value.width = width;
            mode.value.height = height;
            mode.sizeReceived = true;
        });
    }
    static void refreshMode(void *data, zwlr_output_mode_v1 *, int32_t refresh)
    {
        auto &mode = *static_cast<Mode *>(data);
        callback(*mode.head->owner, [&] {
            if (mode.refreshReceived) {
                mode.head->owner->invalidate();
                return;
            }
            mode.value.refresh = refresh;
            mode.refreshReceived = true;
        });
    }
    static void preferredMode(void *, zwlr_output_mode_v1 *) {}
    static void finishedMode(void *data, zwlr_output_mode_v1 *native)
    {
        auto &mode = *static_cast<Mode *>(data);
        auto &head = *mode.head;
        callback(*head.owner, [&] {
            if (!head.owner->advance())
                return;
            head.value.generation = head.owner->generation;
            if (head.current == native)
                head.current = nullptr;
            head.modes.erase(native);
        });
    }
    static void newMode(void *data, zwlr_output_head_v1 *, zwlr_output_mode_v1 *native)
    {
        auto &source = *static_cast<Head *>(data);
        if (!source.owner->healthy) {
            if (native)
                zwlr_output_mode_v1_release(native);
            return;
        }
        headCallback(data, [&](Head &head) {
            if (!native || head.modes.size() >= MaximumModes || head.modes.contains(native) ||
                !head.owner->advance()) {
                if (native && !head.modes.contains(native))
                    zwlr_output_mode_v1_release(native);
                head.owner->invalidate();
                return;
            }
            auto mode = std::make_unique<Mode>();
            mode->head = &head;
            mode->native = native;
            head.value.generation = head.owner->generation;
            static const zwlr_output_mode_v1_listener listener{sizeMode, refreshMode, preferredMode,
                                                               finishedMode};
            if (zwlr_output_mode_v1_add_listener(native, &listener, mode.get()) != 0)
                head.owner->invalidate();
            head.modes.emplace(native, std::move(mode));
        });
    }
    static void newHead(void *data, zwlr_output_manager_v1 *, zwlr_output_head_v1 *native)
    {
        auto &self = *static_cast<Impl *>(data);
        if (!self.healthy) {
            if (native)
                zwlr_output_head_v1_release(native);
            return;
        }
        callback(self, [&] {
            if (!native || self.heads.size() >= MaximumHeads || self.heads.contains(native) ||
                self.nextHandle >= std::numeric_limits<quint64>::max() - 1 || !self.advance()) {
                if (native && !self.heads.contains(native))
                    zwlr_output_head_v1_release(native);
                self.invalidate();
                return;
            }
            auto head = std::make_unique<Head>();
            head->owner = &self;
            head->native = native;
            head->value.handle = ++self.nextHandle;
            head->value.generation = self.generation;
            static const zwlr_output_head_v1_listener listener{
                name,        ignoredText, physicalSize, newMode,     enabled,
                currentMode, position,    transform,    scale,       finishedHead,
                ignoredText, ignoredText, ignoredText,  adaptiveSync};
            if (zwlr_output_head_v1_add_listener(native, &listener, head.get()) != 0)
                self.invalidate();
            self.heads.emplace(native, std::move(head));
        });
    }
    static void done(void *data, zwlr_output_manager_v1 *, uint32_t)
    {
        static_cast<Impl *>(data)->initialDone = true;
    }
    static void finished(void *data, zwlr_output_manager_v1 *)
    {
        static_cast<Impl *>(data)->invalidate();
    }
};

NativeDisplayTopology::NativeDisplayTopology() : impl_(std::make_unique<Impl>()) {}
NativeDisplayTopology::~NativeDisplayTopology() = default;
void NativeDisplayTopology::announce(wl_registry *registry, quint32 global, quint32 version)
{
    if (impl_->global != 0 || version < 4 || !registry || global == 0) {
        impl_->invalidate();
        return;
    }
    impl_->global = global;
    impl_->manager = static_cast<zwlr_output_manager_v1 *>(
        wl_registry_bind(registry, global, &zwlr_output_manager_v1_interface, 4));
    static const zwlr_output_manager_v1_listener listener{Impl::newHead, Impl::done,
                                                          Impl::finished};
    if (!impl_->manager ||
        zwlr_output_manager_v1_add_listener(impl_->manager, &listener, impl_.get()) != 0)
        impl_->invalidate();
}
void NativeDisplayTopology::removed(quint32 global)
{
    if (impl_->global == global)
        impl_->invalidate();
}
std::optional<NativeDisplaySnapshot> NativeDisplayTopology::snapshotAfterSync() const
{
    if (!impl_->healthy || !impl_->manager || !impl_->initialDone || impl_->generation == 0 ||
        impl_->heads.empty() || impl_->heads.size() > MaximumHeads)
        return std::nullopt;
    NativeDisplaySnapshot result{impl_->generation, {}};
    std::set<QString> names;
    for (const auto &[native, head] : impl_->heads) {
        (void)native;
        if (!head->enabledReceived || head->value.name.isEmpty() ||
            !names.insert(head->value.name).second || head->modes.empty())
            return std::nullopt;
        auto value = head->value;
        std::set<NativeDisplayMode> modes;
        for (const auto &[object, mode] : head->modes) {
            (void)object;
            if (!mode->sizeReceived || !mode->refreshReceived || !validMode(mode->value) ||
                !modes.insert(mode->value).second)
                return std::nullopt;
        }
        value.modes.assign(modes.begin(), modes.end());
        if (value.enabled) {
            if (!head->current || !head->positionReceived || !head->transformReceived ||
                !head->scaleReceived || !head->modes.contains(head->current))
                return std::nullopt;
            value.current = head->modes.at(head->current)->value;
        } else {
            value.current.reset();
            value.x = value.y = value.transform = value.scaleFixed = 0;
        }
        result.heads.push_back(std::move(value));
    }
    std::sort(result.heads.begin(), result.heads.end(),
              [](const auto &left, const auto &right) { return left.handle < right.handle; });
    return result;
}
} // namespace Linura::SecurityOwner
