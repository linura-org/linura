#include "peer_guard.h"
#include "native_sleep_probe.h"

#include <QDBusArgument>
#include <QDBusObjectPath>
#include <QDBusReply>
#include <QUuid>
#include <sys/stat.h>

namespace Linura::SecurityOwner {
namespace {
bool immutableAssets()
{
    struct stat metadata
    {};
    for (const char *path :
         {"/usr", "/usr/lib", "/usr/lib/linura", "/usr/lib/systemd", "/usr/lib/systemd/system",
          "/usr/lib/systemd/system/systemd-suspend.service.d"}) {
        if (lstat(path, &metadata) != 0 || !S_ISDIR(metadata.st_mode) || metadata.st_uid != 0 ||
            (metadata.st_mode & 022) != 0)
            return false;
    }
    for (const char *path :
         {"/usr/lib/systemd/system/systemd-suspend.service",
          "/usr/lib/systemd/system/systemd-suspend.service.d/50-linura-protective-lock.conf",
          "/usr/lib/linura/linura-executor-session", "/usr/lib/systemd/systemd-sleep"}) {
        if (lstat(path, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_uid != 0 ||
            metadata.st_nlink != 1 || (metadata.st_mode & 022) != 0)
            return false;
    }
    return true;
}

template <typename T> bool typed(const QVariantMap &properties, const char *key)
{
    return properties.value(QLatin1String(key)).metaType() == QMetaType::fromType<T>();
}

bool signature(const QVariant &value, const char *expected)
{
    return value.metaType() == QMetaType::fromType<QDBusArgument>() &&
           value.value<QDBusArgument>().currentSignature() == QLatin1String(expected);
}

std::optional<quint32> jobId(const QVariant &value)
{
    if (!signature(value, "(uo)"))
        return std::nullopt;
    const auto wire = value.value<QDBusArgument>();
    quint32 id = 0;
    QDBusObjectPath path;
    wire.beginStructure();
    wire >> id >> path;
    wire.endStructure();
    if ((id == 0 && path.path() != QLatin1String("/")) ||
        (id != 0 && path.path() != QStringLiteral("/org/freedesktop/systemd1/job/%1").arg(id)))
        return std::nullopt;
    return id;
}

} // namespace

std::optional<NativeSleepUnitFacts> decodeNativeSleepUnitFacts(const QString &supervisor,
                                                               const QVariantMap &unit,
                                                               const QVariantMap &service)
{
    if (unit.size() > 256 || service.size() > 256 || !typed<QString>(unit, "Id") ||
        unit.value(QStringLiteral("Id")).toString() != QLatin1String("systemd-suspend.service") ||
        !typed<QString>(unit, "FragmentPath") ||
        unit.value(QStringLiteral("FragmentPath")).toString() !=
            QLatin1String("/usr/lib/systemd/system/systemd-suspend.service") ||
        !typed<QByteArray>(unit, "InvocationID") ||
        unit.value(QStringLiteral("InvocationID")).toByteArray().size() != 16 ||
        !typed<QString>(unit, "ActiveState") || !typed<QString>(unit, "SubState") ||
        !typed<quint32>(service, "ControlPID") || !typed<quint32>(service, "MainPID") ||
        !typed<QString>(service, "Type") ||
        service.value(QStringLiteral("Type")).toString() != QLatin1String("oneshot") ||
        !typed<QString>(service, "User") ||
        !(service.value(QStringLiteral("User")).toString().isEmpty() ||
          service.value(QStringLiteral("User")).toString() == QLatin1String("root")) ||
        !typed<QString>(service, "Restart") ||
        service.value(QStringLiteral("Restart")).toString() != QLatin1String("no"))
        return std::nullopt;
    const auto drops = unit.value(QStringLiteral("DropInPaths"));
    if (drops.metaType() != QMetaType::fromType<QStringList>() && !signature(drops, "as"))
        return std::nullopt;
    if (qdbus_cast<QStringList>(drops) !=
        QStringList{QStringLiteral("/usr/lib/systemd/system/systemd-suspend.service.d/"
                                   "50-linura-protective-lock.conf")})
        return std::nullopt;
    const auto job = jobId(unit.value(QStringLiteral("Job")));
    const auto helper = decodeNativeSingleLaunch(service.value(QStringLiteral("ExecStartPre")));
    const auto main = decodeNativeSingleLaunch(service.value(QStringLiteral("ExecStart")));
    if (!job || !helper || !main)
        return std::nullopt;
    // These can alter whether/when the fixed gate is effective. Unknown or
    // extended unit programs are unsupported, not accepted by root ownership.
    for (const char *key : {"ExecCondition", "ExecStartPost", "ExecStop", "ExecStopPost"}) {
        const auto value = service.value(QLatin1String(key));
        if (!signature(value, "a(sasbttttuii)"))
            return std::nullopt;
        const auto wire = value.value<QDBusArgument>();
        wire.beginArray();
        const bool empty = wire.atEnd();
        wire.endArray();
        if (!empty)
            return std::nullopt;
    }
    const auto success = service.value(QStringLiteral("SuccessExitStatus"));
    if (!signature(success, "(aiai)"))
        return std::nullopt;
    const auto statuses = success.value<QDBusArgument>();
    statuses.beginStructure();
    QList<qint32> codes, signals;
    statuses >> codes >> signals;
    statuses.endStructure();
    if (!signals.isEmpty() || codes.size() > 1 || (!codes.isEmpty() && codes.first() != 0))
        return std::nullopt;
    return NativeSleepUnitFacts{
        supervisor,
        QUuid::fromRfc4122(unit.value(QStringLiteral("InvocationID")).toByteArray())
            .toString(QUuid::WithoutBraces),
        unit.value(QStringLiteral("ActiveState")).toString(),
        unit.value(QStringLiteral("SubState")).toString(),
        service.value(QStringLiteral("ControlPID")).toUInt(),
        service.value(QStringLiteral("MainPID")).toUInt(),
        *job,
        *helper,
        *main};
}
std::optional<NativeSleepUnitFacts> PeerGuard::sleepUnitSnapshot() const
{
    QElapsedTimer budget;
    budget.start();
    const auto bus = [&](const QString &method, const QList<QVariant> &arguments) {
        return call(budget, QStringLiteral("org.freedesktop.DBus"),
                    QStringLiteral("/org/freedesktop/DBus"), QStringLiteral("org.freedesktop.DBus"),
                    method, arguments);
    };
    const auto owner = [&]() -> std::optional<QString> {
        const QDBusReply<QString> reply(
            bus(QStringLiteral("GetNameOwner"), {QStringLiteral("org.freedesktop.systemd1")}));
        if (!reply.isValid() || !reply.value().startsWith(QLatin1Char(':')) ||
            reply.value().size() > 128)
            return std::nullopt;
        return reply.value();
    };
    const auto supervisor = owner();
    if (!supervisor)
        return std::nullopt;
    const QDBusReply<quint32> uid(bus(QStringLiteral("GetConnectionUnixUser"), {*supervisor}));
    if (!uid.isValid() || uid.value() != 0 || !immutableAssets())
        return std::nullopt;
    const auto pathMessage =
        call(budget, *supervisor, QStringLiteral("/org/freedesktop/systemd1"),
             QStringLiteral("org.freedesktop.systemd1.Manager"), QStringLiteral("GetUnit"),
             {QStringLiteral("systemd-suspend.service")});
    if (pathMessage.service() != *supervisor)
        return std::nullopt;
    const QDBusReply<QDBusObjectPath> path(pathMessage);
    if (!path.isValid() &&
        path.error().name() == QLatin1String("org.freedesktop.systemd1.NoSuchUnit")) {
        const auto repeatedMessage =
            call(budget, *supervisor, QStringLiteral("/org/freedesktop/systemd1"),
                 QStringLiteral("org.freedesktop.systemd1.Manager"), QStringLiteral("GetUnit"),
                 {QStringLiteral("systemd-suspend.service")});
        const QDBusReply<QDBusObjectPath> repeated(repeatedMessage);
        if (repeatedMessage.service() != *supervisor || repeated.isValid() ||
            repeated.error().name() != path.error().name() || owner() != supervisor ||
            budget.elapsed() >= 2'000 || !immutableAssets())
            return std::nullopt;
        NativeSleepUnitFacts absent;
        absent.supervisor = *supervisor;
        absent.absent = true;
        return absent;
    }
    if (!path.isValid() || path.value().path().size() > 256 ||
        !path.value().path().startsWith(QLatin1String("/org/freedesktop/systemd1/unit/")))
        return std::nullopt;
    const auto properties = [&](const QString &interface) -> std::optional<QVariantMap> {
        const auto message = call(budget, *supervisor, path.value().path(),
                                  QStringLiteral("org.freedesktop.DBus.Properties"),
                                  QStringLiteral("GetAll"), {interface});
        const QDBusReply<QVariantMap> reply(message);
        if (message.service() != *supervisor || !reply.isValid() || reply.value().size() > 256)
            return std::nullopt;
        return reply.value();
    };
    const auto sample = [&]() -> std::optional<NativeSleepUnitFacts> {
        const auto unit = properties(QStringLiteral("org.freedesktop.systemd1.Unit"));
        const auto service = properties(QStringLiteral("org.freedesktop.systemd1.Service"));
        return unit && service ? decodeNativeSleepUnitFacts(*supervisor, *unit, *service)
                               : std::nullopt;
    };
    const auto first = sample();
    const auto second = sample();
    if (!first || !second || *first != *second || owner() != supervisor ||
        budget.elapsed() >= 2'000 || !immutableAssets())
        return std::nullopt;
    return first;
}
} // namespace Linura::SecurityOwner
