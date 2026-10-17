#include "session_bootstrap.h"
#include "native_launch.h"

#include <QDBusArgument>
#include <QDBusMessage>
#include <QDBusObjectPath>
#include <QDBusReply>
#include <QDBusVariant>
#include <QElapsedTimer>
#include <QFile>
#include <QStringList>
#include <QUuid>

#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>

namespace Linura::SecurityOwner {
namespace {

constexpr qint64 ProbeBudgetMs = 2'000;
constexpr qint64 CallBudgetMs = 500;

bool seatId(const QString &seat)
{
    if (seat.isEmpty() || seat.size() > 64)
        return false;
    for (QChar character : seat) {
        const ushort code = character.unicode();
        if (!((code >= 'a' && code <= 'z') || (code >= 'A' && code <= 'Z') ||
              (code >= '0' && code <= '9') || code == '-' || code == '_'))
            return false;
    }
    return true;
}

std::optional<QString> kernelBoot()
{
    QFile boot(QStringLiteral("/proc/sys/kernel/random/boot_id"));
    if (!boot.open(QIODevice::ReadOnly))
        return std::nullopt;
    const QByteArray text = boot.read(38);
    if (text.size() != 37 || text[36] != '\n')
        return std::nullopt;
    const QString uuid = QString::fromLatin1(text.constData(), 36);
    const QUuid value(uuid);
    if (value.isNull() || value.toString(QUuid::WithoutBraces) != uuid)
        return std::nullopt;
    return uuid;
}

std::optional<ucred> displayPeer(int descriptor)
{
    ucred peer{};
    socklen_t bytes = sizeof(peer);
    int domain = 0, type = 0;
    socklen_t numberBytes = sizeof(domain);
    if (descriptor < 0 ||
        getsockopt(descriptor, SOL_SOCKET, SO_DOMAIN, &domain, &numberBytes) != 0 ||
        numberBytes != sizeof(domain) || domain != AF_UNIX)
        return std::nullopt;
    numberBytes = sizeof(type);
    if (getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &type, &numberBytes) != 0 ||
        numberBytes != sizeof(type) || type != SOCK_STREAM ||
        getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &peer, &bytes) != 0 ||
        bytes != sizeof(peer) || peer.pid <= 0 || peer.uid == 0)
        return std::nullopt;
    return peer;
}

bool immutableSupervisorFragment()
{
    struct stat metadata
    {};
    if (lstat("/usr/lib/systemd/system/linura-security-owner@.service", &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) || metadata.st_uid != 0 || metadata.st_nlink != 1 ||
        (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        return false;
    for (const char *path :
         {"/usr", "/usr/lib", "/usr/lib/systemd", "/usr/lib/systemd/system", "/usr/lib/linura"}) {
        if (lstat(path, &metadata) != 0 || !S_ISDIR(metadata.st_mode) || metadata.st_uid != 0 ||
            (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0)
            return false;
    }
    struct stat running
    {};
    // MainPID and an old ExecStart record do not prove which image is currently
    // running: exec preserves a PID. Bind the actual executing inode too.
    return lstat("/usr/lib/linura/linura-security-owner", &metadata) == 0 &&
           S_ISREG(metadata.st_mode) && metadata.st_uid == 0 && metadata.st_nlink == 1 &&
           (metadata.st_mode & (S_IWGRP | S_IWOTH)) == 0 && (metadata.st_mode & S_IXUSR) != 0 &&
           stat("/proc/self/exe", &running) == 0 && metadata.st_dev == running.st_dev &&
           metadata.st_ino == running.st_ino;
}

} // namespace

std::optional<NativeLockIdentity> bindNativeSession(const NativeSessionFacts &facts,
                                                    quint32 socketPeerUid, quint32 socketPeerPid,
                                                    const QString &supervisorInvocation)
{
    if (facts.uid == 0 || facts.uid != socketPeerUid || socketPeerPid == 0 ||
        facts.leader != socketPeerPid || facts.type != QLatin1String("wayland") ||
        facts.sessionClass != QLatin1String("user") || facts.state != QLatin1String("active") ||
        !facts.active || facts.remote || !seatId(facts.seat))
        return std::nullopt;
    return NativeLockIdentity::parse(QStringLiteral("session:lock:%1:%2:%3:%4:%5:1")
                                         .arg(facts.boot)
                                         .arg(facts.uid)
                                         .arg(facts.session)
                                         .arg(facts.createdMonotonicUs)
                                         .arg(supervisorInvocation));
}

std::optional<NativeSessionBinding> inspectNativeSession(const QDBusConnection &trustedSystemBus,
                                                         int actualWaylandDisplayFd)
{
    const auto peer = displayPeer(actualWaylandDisplayFd);
    const auto boot = kernelBoot();
    if (!peer || !boot || peer->uid != getuid() || geteuid() != getuid() ||
        !trustedSystemBus.isConnected())
        return std::nullopt;
    QElapsedTimer budget;
    budget.start();
    const auto call = [&](const QString &owner, const QString &path, const QString &interface,
                          const QString &method, const QList<QVariant> &arguments) {
        const qint64 remaining = ProbeBudgetMs - budget.elapsed();
        if (remaining <= 0)
            return QDBusMessage::createError(QStringLiteral("org.linura.Private.NativeUnavailable"),
                                             QStringLiteral("Native session deadline expired"));
        auto request = QDBusMessage::createMethodCall(owner, path, interface, method);
        request.setArguments(arguments);
        return trustedSystemBus.call(request, QDBus::Block, int(std::min(remaining, CallBudgetMs)));
    };
    const auto ownerOf = [&](const QString &service) -> std::optional<QString> {
        const QDBusReply<QString> owner(call(
            QStringLiteral("org.freedesktop.DBus"), QStringLiteral("/org/freedesktop/DBus"),
            QStringLiteral("org.freedesktop.DBus"), QStringLiteral("GetNameOwner"), {service}));
        if (!owner.isValid() || owner.value().size() > 128 ||
            !owner.value().startsWith(QLatin1Char(':')))
            return std::nullopt;
        const QDBusReply<quint32> uid(
            call(QStringLiteral("org.freedesktop.DBus"), QStringLiteral("/org/freedesktop/DBus"),
                 QStringLiteral("org.freedesktop.DBus"), QStringLiteral("GetConnectionUnixUser"),
                 {owner.value()}));
        if (!uid.isValid() || uid.value() != 0)
            return std::nullopt;
        return owner.value();
    };
    const auto logindOwner = ownerOf(QStringLiteral("org.freedesktop.login1"));
    const auto systemdOwner = ownerOf(QStringLiteral("org.freedesktop.systemd1"));
    if (!logindOwner || !systemdOwner)
        return std::nullopt;
    const auto sessionForPeer = [&]() -> std::optional<QString> {
        const QDBusReply<QDBusObjectPath> path(
            call(*logindOwner, QStringLiteral("/org/freedesktop/login1"),
                 QStringLiteral("org.freedesktop.login1.Manager"),
                 QStringLiteral("GetSessionByPID"), {quint32(peer->pid)}));
        if (!path.isValid() || path.value().path().size() > 256 ||
            !path.value().path().startsWith(QLatin1String("/org/freedesktop/login1/session/")))
            return std::nullopt;
        return path.value().path();
    };
    const auto path = sessionForPeer();
    if (!path)
        return std::nullopt;
    const auto property = [&](const QString &owner, const QString &object, const QString &interface,
                              const QString &name) -> std::optional<QVariant> {
        const QDBusReply<QDBusVariant> reply(call(owner, object,
                                                  QStringLiteral("org.freedesktop.DBus.Properties"),
                                                  QStringLiteral("Get"), {interface, name}));
        if (!reply.isValid())
            return std::nullopt;
        return reply.value().variant();
    };
    const QString sessionInterface = QStringLiteral("org.freedesktop.login1.Session");
    const auto field = [&](const QString &name) {
        return property(*logindOwner, *path, sessionInterface, name);
    };
    const auto id = field(QStringLiteral("Id"));
    const auto uid = field(QStringLiteral("User"));
    const auto created = field(QStringLiteral("TimestampMonotonic"));
    const auto type = field(QStringLiteral("Type"));
    const auto sessionClass = field(QStringLiteral("Class"));
    const auto state = field(QStringLiteral("State"));
    const auto seat = field(QStringLiteral("Seat"));
    const auto active = field(QStringLiteral("Active"));
    const auto remote = field(QStringLiteral("Remote"));
    const auto leader = field(QStringLiteral("Leader"));
    if (!id || !uid || !created || !type || !sessionClass || !state || !seat || !active ||
        !remote || !leader || id->metaType() != QMetaType::fromType<QString>() ||
        type->metaType() != QMetaType::fromType<QString>() ||
        sessionClass->metaType() != QMetaType::fromType<QString>() ||
        state->metaType() != QMetaType::fromType<QString>() ||
        created->metaType() != QMetaType::fromType<quint64>() ||
        active->metaType() != QMetaType::fromType<bool>() ||
        remote->metaType() != QMetaType::fromType<bool>() ||
        leader->metaType() != QMetaType::fromType<quint32>() ||
        uid->metaType() != QMetaType::fromType<QDBusArgument>() ||
        uid->value<QDBusArgument>().currentSignature() != QLatin1String("(uo)") ||
        seat->metaType() != QMetaType::fromType<QDBusArgument>() ||
        seat->value<QDBusArgument>().currentSignature() != QLatin1String("(so)"))
        return std::nullopt;
    quint32 sessionUid = 0;
    QDBusObjectPath userPath, seatPath;
    QString seatName;
    auto userArgument = uid->value<QDBusArgument>();
    userArgument.beginStructure();
    userArgument >> sessionUid >> userPath;
    userArgument.endStructure();
    auto seatArgument = seat->value<QDBusArgument>();
    seatArgument.beginStructure();
    seatArgument >> seatName >> seatPath;
    seatArgument.endStructure();
    NativeSessionFacts facts{*boot,
                             sessionUid,
                             id->toString(),
                             created->toULongLong(),
                             type->toString(),
                             sessionClass->toString(),
                             state->toString(),
                             seatName,
                             active->toBool(),
                             remote->toBool(),
                             leader->toUInt()};
    const QString unitName = QStringLiteral("linura-security-owner@%1.service").arg(getuid());
    const QDBusReply<QDBusObjectPath> unit(call(
        *systemdOwner, QStringLiteral("/org/freedesktop/systemd1"),
        QStringLiteral("org.freedesktop.systemd1.Manager"), QStringLiteral("GetUnit"), {unitName}));
    if (!unit.isValid() || unit.value().path().size() > 256 ||
        !unit.value().path().startsWith(QLatin1String("/org/freedesktop/systemd1/unit/")))
        return std::nullopt;
    const QString unitInterface = QStringLiteral("org.freedesktop.systemd1.Unit");
    const QString serviceInterface = QStringLiteral("org.freedesktop.systemd1.Service");
    const auto mainPid =
        property(*systemdOwner, unit.value().path(), serviceInterface, QStringLiteral("MainPID"));
    const auto serviceUser =
        property(*systemdOwner, unit.value().path(), serviceInterface, QStringLiteral("User"));
    const auto invocation =
        property(*systemdOwner, unit.value().path(), unitInterface, QStringLiteral("InvocationID"));
    const auto fragment =
        property(*systemdOwner, unit.value().path(), unitInterface, QStringLiteral("FragmentPath"));
    const auto dropIns =
        property(*systemdOwner, unit.value().path(), unitInterface, QStringLiteral("DropInPaths"));
    const auto activeState =
        property(*systemdOwner, unit.value().path(), unitInterface, QStringLiteral("ActiveState"));
    const auto subState =
        property(*systemdOwner, unit.value().path(), unitInterface, QStringLiteral("SubState"));
    const auto execStart =
        property(*systemdOwner, unit.value().path(), serviceInterface, QStringLiteral("ExecStart"));
    const QString image = QStringLiteral("/usr/lib/linura/linura-security-owner");
    if (!mainPid || !serviceUser || !invocation || !fragment || !dropIns || !activeState ||
        !subState || !execStart || mainPid->metaType() != QMetaType::fromType<quint32>() ||
        mainPid->toUInt() != quint32(getpid()) ||
        serviceUser->metaType() != QMetaType::fromType<QString>() ||
        serviceUser->toString() != QString::number(getuid()) ||
        fragment->metaType() != QMetaType::fromType<QString>() ||
        fragment->toString() !=
            QLatin1String("/usr/lib/systemd/system/linura-security-owner@.service") ||
        invocation->metaType() != QMetaType::fromType<QByteArray>() ||
        invocation->toByteArray().size() != 16 ||
        activeState->metaType() != QMetaType::fromType<QString>() ||
        activeState->toString() != QLatin1String("active") ||
        subState->metaType() != QMetaType::fromType<QString>() ||
        subState->toString() != QLatin1String("running") ||
        !exactNativeExecStart(*execStart, image, {image}, quint32(getpid())) ||
        !immutableSupervisorFragment())
        return std::nullopt;
    if (dropIns->metaType() != QMetaType::fromType<QStringList>()) {
        if (dropIns->metaType() != QMetaType::fromType<QDBusArgument>() ||
            dropIns->value<QDBusArgument>().currentSignature() != QLatin1String("as"))
            return std::nullopt;
    }
    if (!qdbus_cast<QStringList>(*dropIns).isEmpty())
        return std::nullopt;
    const QString invocationId =
        QUuid::fromRfc4122(invocation->toByteArray()).toString(QUuid::WithoutBraces);
    const auto lock = bindNativeSession(facts, peer->uid, quint32(peer->pid), invocationId);
    if (!lock)
        return std::nullopt;
    // An attested process and a boot snapshot cannot freshen replaced session
    // identity. Re-resolve and recheck its creation before retaining the binding.
    const auto freshPath = sessionForPeer();
    const auto freshCreated = field(QStringLiteral("TimestampMonotonic"));
    const auto freshLeader = field(QStringLiteral("Leader"));
    const auto freshPeer = displayPeer(actualWaylandDisplayFd);
    const auto freshUser = field(QStringLiteral("User"));
    const auto freshSeat = field(QStringLiteral("Seat"));
    if (!freshUser || freshUser->metaType() != QMetaType::fromType<QDBusArgument>() ||
        freshUser->value<QDBusArgument>().currentSignature() != QLatin1String("(uo)") ||
        !freshSeat || freshSeat->metaType() != QMetaType::fromType<QDBusArgument>() ||
        freshSeat->value<QDBusArgument>().currentSignature() != QLatin1String("(so)"))
        return std::nullopt;
    quint32 freshUid = 0;
    QDBusObjectPath freshUserPath, freshSeatPath;
    QString freshSeatName;
    auto freshUserArgument = freshUser->value<QDBusArgument>();
    freshUserArgument.beginStructure();
    freshUserArgument >> freshUid >> freshUserPath;
    freshUserArgument.endStructure();
    auto freshSeatArgument = freshSeat->value<QDBusArgument>();
    freshSeatArgument.beginStructure();
    freshSeatArgument >> freshSeatName >> freshSeatPath;
    freshSeatArgument.endStructure();
    const auto sameField = [&](const QString &name, const QVariant &original) {
        const auto current = field(name);
        return current && current->metaType() == original.metaType() && *current == original;
    };
    const auto sameService = [&](const QString &interface, const QString &name,
                                 const QVariant &original) {
        const auto current = property(*systemdOwner, unit.value().path(), interface, name);
        return current && current->metaType() == original.metaType() && *current == original;
    };
    const auto freshExecStart =
        property(*systemdOwner, unit.value().path(), serviceInterface, QStringLiteral("ExecStart"));
    const auto freshDropIns =
        property(*systemdOwner, unit.value().path(), unitInterface, QStringLiteral("DropInPaths"));
    if (!freshDropIns ||
        (freshDropIns->metaType() != QMetaType::fromType<QStringList>() &&
         (freshDropIns->metaType() != QMetaType::fromType<QDBusArgument>() ||
          freshDropIns->value<QDBusArgument>().currentSignature() != QLatin1String("as"))) ||
        !qdbus_cast<QStringList>(*freshDropIns).isEmpty())
        return std::nullopt;
    if (freshPath != path || !freshCreated ||
        freshCreated->metaType() != QMetaType::fromType<quint64>() ||
        freshCreated->toULongLong() != facts.createdMonotonicUs || !freshLeader ||
        freshLeader->metaType() != QMetaType::fromType<quint32>() ||
        freshLeader->toUInt() != facts.leader || !freshPeer || freshPeer->uid != peer->uid ||
        freshPeer->pid != peer->pid || kernelBoot() != boot || freshUid != sessionUid ||
        freshUserPath != userPath || freshSeatName != seatName || freshSeatPath != seatPath ||
        !sameField(QStringLiteral("Id"), *id) || !sameField(QStringLiteral("Type"), *type) ||
        !sameField(QStringLiteral("Class"), *sessionClass) ||
        !sameField(QStringLiteral("State"), *state) ||
        !sameField(QStringLiteral("Active"), *active) ||
        !sameField(QStringLiteral("Remote"), *remote) ||
        !sameService(serviceInterface, QStringLiteral("MainPID"), *mainPid) ||
        !sameService(serviceInterface, QStringLiteral("User"), *serviceUser) ||
        !sameService(unitInterface, QStringLiteral("InvocationID"), *invocation) ||
        !sameService(unitInterface, QStringLiteral("ActiveState"), *activeState) ||
        !sameService(unitInterface, QStringLiteral("SubState"), *subState) ||
        !sameService(unitInterface, QStringLiteral("FragmentPath"), *fragment) || !freshExecStart ||
        !exactNativeExecStart(*freshExecStart, image, {image}, quint32(getpid())) ||
        !immutableSupervisorFragment() ||
        ownerOf(QStringLiteral("org.freedesktop.login1")) != logindOwner ||
        ownerOf(QStringLiteral("org.freedesktop.systemd1")) != systemdOwner ||
        budget.elapsed() >= ProbeBudgetMs)
        return std::nullopt;
    return NativeSessionBinding{*lock, quint32(peer->pid)};
}

} // namespace Linura::SecurityOwner
