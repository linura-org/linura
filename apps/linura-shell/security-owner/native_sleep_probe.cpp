#include "peer_guard.h"
#include "native_sleep_probe.h"
#include "native_property.h"

#include <QDBusArgument>
#include <QDBusObjectPath>
#include <QDBusReply>
#include <QUuid>
#include <cstddef>
#include <sys/stat.h>
#include <unistd.h>

namespace Linura::SecurityOwner {
namespace {
template <std::size_t N>
std::nullopt_t probeUnavailable(bool diagnostics, const char (&reason)[N]) noexcept
{
    if (diagnostics) {
        // Immutable labels only. Never emit native properties or error text.
        const ssize_t written = ::write(STDERR_FILENO, reason, N - 1);
        (void)written;
    }
    return std::nullopt;
}

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

bool nativeSleepUnitLookupReply(const QDBusMessage &reply, const QString &supervisor,
                                bool failureDiagnostics)
{
    if (!supervisor.startsWith(QLatin1Char(':')) || supervisor.size() > 128 ||
        (!reply.service().isEmpty() && reply.service() != supervisor)) {
        (void)probeUnavailable(failureDiagnostics,
                               "native-sleep-owner-denied reason=lookup-reply-substitution\n");
        return false;
    }
    if (reply.type() == QDBusMessage::ReplyMessage ||
        (reply.type() == QDBusMessage::ErrorMessage &&
         reply.errorName() == QLatin1String("org.freedesktop.systemd1.NoSuchUnit")))
        return true;
    if (!failureDiagnostics)
        return false;
    if (reply.type() == QDBusMessage::ErrorMessage) {
        const auto name = reply.errorName();
        if (name == QLatin1String("org.freedesktop.DBus.Error.NoReply") ||
            name == QLatin1String("org.freedesktop.DBus.Error.Timeout"))
            (void)probeUnavailable(true, "native-sleep-owner-denied reason=lookup-timeout\n");
        else if (name == QLatin1String("org.linura.Private.NativeUnavailable"))
            (void)probeUnavailable(true, "native-sleep-owner-denied reason=lookup-deadline\n");
        else if (name == QLatin1String("org.freedesktop.DBus.Error.AccessDenied") ||
                 name == QLatin1String("org.freedesktop.DBus.Error.AuthFailed"))
            (void)probeUnavailable(true, "native-sleep-owner-denied reason=lookup-denied\n");
        else if (name == QLatin1String("org.freedesktop.DBus.Error.InvalidArgs") ||
                 name == QLatin1String("org.freedesktop.DBus.Error.InvalidSignature"))
            (void)probeUnavailable(true, "native-sleep-owner-denied reason=lookup-arguments\n");
        else if (name == QLatin1String("org.freedesktop.DBus.Error.Disconnected"))
            (void)probeUnavailable(true, "native-sleep-owner-denied reason=lookup-disconnected\n");
        else if (name == QLatin1String("org.freedesktop.DBus.Error.UnknownMethod") ||
                 name == QLatin1String("org.freedesktop.DBus.Error.UnknownObject") ||
                 name == QLatin1String("org.freedesktop.DBus.Error.UnknownInterface"))
            (void)probeUnavailable(true, "native-sleep-owner-denied reason=lookup-unsupported\n");
        else if (name == QLatin1String("org.freedesktop.DBus.Error.ServiceUnknown") ||
                 name == QLatin1String("org.freedesktop.DBus.Error.NameHasNoOwner"))
            (void)probeUnavailable(true, "native-sleep-owner-denied reason=lookup-owner-lost\n");
        else
            (void)probeUnavailable(true, "native-sleep-owner-denied reason=lookup-error-other\n");
    } else {
        (void)probeUnavailable(true, "native-sleep-owner-denied reason=lookup-invalid-type\n");
    }
    return false;
}

std::optional<NativeSleepUnitFacts> decodeNativeSleepUnitFacts(const QString &supervisor,
                                                               const QVariantMap &unit,
                                                               const QVariantMap &service,
                                                               bool failureDiagnostics)
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
        return probeUnavailable(failureDiagnostics,
                                "native-sleep-owner-denied reason=codec-fields\n");
    const auto drops = unit.value(QStringLiteral("DropInPaths"));
    if (drops.metaType() != QMetaType::fromType<QStringList>() && !signature(drops, "as"))
        return probeUnavailable(failureDiagnostics,
                                "native-sleep-owner-denied reason=codec-drop-ins\n");
    if (qdbus_cast<QStringList>(drops) !=
        QStringList{QStringLiteral("/usr/lib/systemd/system/systemd-suspend.service.d/"
                                   "50-linura-protective-lock.conf")})
        return probeUnavailable(failureDiagnostics,
                                "native-sleep-owner-denied reason=codec-drop-ins\n");
    const auto job = jobId(unit.value(QStringLiteral("Job")));
    const auto helper = decodeNativeSingleLaunch(service.value(QStringLiteral("ExecStartPre")));
    const auto main = decodeNativeSingleLaunch(service.value(QStringLiteral("ExecStart")));
    if (!job || !helper || !main)
        return probeUnavailable(failureDiagnostics,
                                "native-sleep-owner-denied reason=codec-commands\n");
    // These can alter whether/when the fixed gate is effective. Unknown or
    // extended unit programs are unsupported, not accepted by root ownership.
    for (const char *key : {"ExecCondition", "ExecStartPost", "ExecStop", "ExecStopPost"}) {
        const auto value = service.value(QLatin1String(key));
        if (!signature(value, "a(sasbttttuii)"))
            return probeUnavailable(failureDiagnostics,
                                    "native-sleep-owner-denied reason=codec-extra-signature\n");
        const auto wire = value.value<QDBusArgument>();
        wire.beginArray();
        const bool empty = wire.atEnd();
        wire.endArray();
        if (!empty)
            return probeUnavailable(failureDiagnostics,
                                    "native-sleep-owner-denied reason=codec-extra-command\n");
    }
    const auto success = service.value(QStringLiteral("SuccessExitStatus"));
    if (!signature(success, "(aiai)"))
        return probeUnavailable(failureDiagnostics,
                                "native-sleep-owner-denied reason=codec-success-signature\n");
    const auto statuses = success.value<QDBusArgument>();
    statuses.beginStructure();
    QList<qint32> codes, signals;
    statuses >> codes >> signals;
    statuses.endStructure();
    if (!signals.isEmpty() || codes.size() > 1 || (!codes.isEmpty() && codes.first() != 0))
        return probeUnavailable(failureDiagnostics,
                                "native-sleep-owner-denied reason=codec-success-status\n");
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
std::optional<NativeSleepUnitFacts> PeerGuard::sleepUnitSnapshot(bool failureDiagnostics) const
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
        return probeUnavailable(failureDiagnostics,
                                "native-sleep-owner-denied reason=unit-owner\n");
    const QDBusReply<quint32> uid(bus(QStringLiteral("GetConnectionUnixUser"), {*supervisor}));
    if (!uid.isValid() || uid.value() != 0)
        return probeUnavailable(failureDiagnostics, "native-sleep-owner-denied reason=unit-uid\n");
    if (!immutableAssets())
        return probeUnavailable(failureDiagnostics,
                                "native-sleep-owner-denied reason=unit-assets\n");
    // Address every request to this root-attested unique connection, never the
    // replaceable well-known name. The trusted bus admits only requested replies
    // from that destination. Newer Qt hides service() on reply/error messages;
    // any sender exposed by older Qt must still match. Recheck the named owner
    // after the complete snapshot.
    const auto pathMessage =
        call(budget, *supervisor, QStringLiteral("/org/freedesktop/systemd1"),
             QStringLiteral("org.freedesktop.systemd1.Manager"), QStringLiteral("GetUnit"),
             {QStringLiteral("systemd-suspend.service")});
    if (!nativeSleepUnitLookupReply(pathMessage, *supervisor, failureDiagnostics))
        return probeUnavailable(failureDiagnostics,
                                "native-sleep-owner-denied reason=unit-lookup\n");
    const QDBusReply<QDBusObjectPath> path(pathMessage);
    if (!path.isValid() &&
        path.error().name() == QLatin1String("org.freedesktop.systemd1.NoSuchUnit")) {
        const auto repeatedMessage =
            call(budget, *supervisor, QStringLiteral("/org/freedesktop/systemd1"),
                 QStringLiteral("org.freedesktop.systemd1.Manager"), QStringLiteral("GetUnit"),
                 {QStringLiteral("systemd-suspend.service")});
        const QDBusReply<QDBusObjectPath> repeated(repeatedMessage);
        if (!nativeSleepUnitLookupReply(repeatedMessage, *supervisor) || repeated.isValid() ||
            repeated.error().name() != path.error().name() || owner() != supervisor ||
            budget.elapsed() >= 2'000 || !immutableAssets())
            return probeUnavailable(failureDiagnostics,
                                    "native-sleep-owner-denied reason=unit-absence\n");
        NativeSleepUnitFacts absent;
        absent.supervisor = *supervisor;
        absent.absent = true;
        return absent;
    }
    if (!path.isValid() || path.value().path().size() > 256 ||
        !path.value().path().startsWith(QLatin1String("/org/freedesktop/systemd1/unit/")))
        return probeUnavailable(failureDiagnostics, "native-sleep-owner-denied reason=unit-path\n");
    const auto properties = [&](const QString &interface,
                                const QStringList &names) -> std::optional<QVariantMap> {
        const auto values =
            readNativeDBusProperties(connection_, budget, *supervisor, path.value().path(),
                                     interface, names, 2'000, 500, progress_);
        if (!values)
            (void)probeUnavailable(failureDiagnostics,
                                   "native-sleep-owner-denied reason=unit-property\n");
        return values;
    };
    const auto sample = [&]() -> std::optional<NativeSleepUnitFacts> {
        const auto unit = properties(QStringLiteral("org.freedesktop.systemd1.Unit"),
                                     {QStringLiteral("Id"), QStringLiteral("FragmentPath"),
                                      QStringLiteral("InvocationID"), QStringLiteral("ActiveState"),
                                      QStringLiteral("SubState"), QStringLiteral("DropInPaths"),
                                      QStringLiteral("Job")});
        const auto service = properties(
            QStringLiteral("org.freedesktop.systemd1.Service"),
            {QStringLiteral("ControlPID"), QStringLiteral("MainPID"), QStringLiteral("Type"),
             QStringLiteral("User"), QStringLiteral("Restart"), QStringLiteral("ExecStartPre"),
             QStringLiteral("ExecStart"), QStringLiteral("ExecCondition"),
             QStringLiteral("ExecStartPost"), QStringLiteral("ExecStop"),
             QStringLiteral("ExecStopPost"), QStringLiteral("SuccessExitStatus")});
        if (!unit || !service)
            return std::nullopt;
        const auto decoded =
            decodeNativeSleepUnitFacts(*supervisor, *unit, *service, failureDiagnostics);
        if (!decoded)
            return probeUnavailable(failureDiagnostics,
                                    "native-sleep-owner-denied reason=unit-codec\n");
        return decoded;
    };
    const auto first = sample();
    const auto second = sample();
    if (!first || !second || *first != *second || owner() != supervisor ||
        budget.elapsed() >= 2'000 || !immutableAssets())
        return probeUnavailable(failureDiagnostics,
                                "native-sleep-owner-denied reason=unit-revalidation\n");
    return first;
}
} // namespace Linura::SecurityOwner
