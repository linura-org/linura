#pragma once

#include <QString>
#include <QStringList>
#include <QVariant>
#include <QtGlobal>
#include <optional>

namespace Linura::SecurityOwner {

// Adapter-local decoded root-systemd metadata, not caller identity or authority.
// Only inspect the reply from the attested unique systemd owner. Never accept
// these fields from a client, QML context or a persisted approval.
struct NativeLaunchFacts final
{
    QString image;
    QStringList arguments;
    bool ignoreFailure = true;
    quint64 startedReal = 0;
    quint64 startedMonotonic = 0;
    quint64 exitedReal = 0;
    quint64 exitedMonotonic = 0;
    quint32 pid = 0;
    qint32 code = -1;
    qint32 status = -1;
    bool operator==(const NativeLaunchFacts &) const = default;
};

[[nodiscard]] bool exactNativeLaunch(const NativeLaunchFacts &facts, const QString &image,
                                     const QStringList &arguments, quint32 expectedPid);
// One bounded command from trusted systemd metadata, not executable authority.
[[nodiscard]] std::optional<NativeLaunchFacts> decodeNativeSingleLaunch(const QVariant &reply);
[[nodiscard]] bool exactNativeExecStart(const QVariant &reply, const QString &image,
                                        const QStringList &arguments, quint32 expectedPid);

} // namespace Linura::SecurityOwner
