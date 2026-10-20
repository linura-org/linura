#pragma once

#include <QString>
#include <QtGlobal>

#include <optional>

namespace Linura::SecurityOwner {

// Adapter identity only. This is not an independently executable plan or a
// policy decision: Control still owns canonical planning, review and prepare.
struct NativeLockIdentity final
{
    QString resource;
    QString boot;
    quint32 uid = 0;
    QString session;
    quint64 createdMonotonicUs = 0;
    QString ownerInvocation;
    quint64 generation = 0;

    [[nodiscard]] static std::optional<NativeLockIdentity> parse(const QString &resource);
    [[nodiscard]] bool wasRetiredBy(const NativeLockIdentity &current) const;
    bool operator==(const NativeLockIdentity &) const = default;
};

} // namespace Linura::SecurityOwner
