#pragma once
#include "native_display_topology.h"
#include "native_scope.h"
#include <QByteArray>
#include <optional>
#include <utility>

namespace Linura::SecurityOwner {

struct NativeDisplayTarget final
{
    quint64 handle = 0, generation = 0;
    bool enabled = false;
    NativeDisplayMode mode;
    quint32 scaleMilli = 0, transform = 0;
    qint32 x = 0, y = 0;
    std::optional<std::pair<quint64, quint64>> mirror;
    [[nodiscard]] QString encode() const;
};
struct NativeDisplayLayout final
{
    QString topology;
    std::vector<NativeDisplayTarget> outputs;
    [[nodiscard]] QString encode() const;
    [[nodiscard]] bool nativeOptions(const NativeDisplaySnapshot &snapshot) const;
    [[nodiscard]] bool matchesGeometry(const NativeDisplaySnapshot &snapshot) const;
    // Candidate formatter fixtures only. The pinned keyword API replaces the
    // complete monitor rule, including unmanaged properties; these strings are
    // NOT eligible for native dispatch. No compositor writer consumes them.
    [[nodiscard]] std::vector<QByteArray> commands(const NativeDisplaySnapshot &snapshot) const;
};
struct NativeDisplayIntent final
{
    NativeLockIdentity lock;
    NativeDisplayLayout baseline, desired;
    [[nodiscard]] static std::optional<NativeDisplayIntent> parse(const QString &material);
    [[nodiscard]] QString encode() const;
    [[nodiscard]] bool nativeOptions(const NativeDisplaySnapshot &snapshot,
                                     const QString &exactTopology,
                                     const NativeLockIdentity &exactLock) const;
};

} // namespace Linura::SecurityOwner
