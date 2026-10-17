#pragma once

#include "native_scope.h"

#include <QDBusConnection>
#include <QString>

#include <optional>

namespace Linura::SecurityOwner {

struct NativeSessionFacts final
{
    QString boot;
    quint32 uid = 0;
    QString session;
    quint64 createdMonotonicUs = 0;
    QString type;
    QString sessionClass;
    QString state;
    QString seat;
    bool active = false;
    bool remote = true;
    quint32 leader = 0;
};

// The fd is obtained from the owned actual native wl_display, not from a client DTO,
// a second socket probe or ambient WAYLAND_DISPLAY. The qualified login boundary
// must make the compositor the native session leader; unknown launch topologies
// fail closed rather than treating a same-UID fake compositor as secure coverage.
[[nodiscard]] std::optional<NativeLockIdentity>
bindNativeSession(const NativeSessionFacts &facts, quint32 socketPeerUid, quint32 socketPeerPid,
                  const QString &supervisorInvocation);

struct NativeSessionBinding final
{
    NativeLockIdentity lock;
    quint32 compositorPid = 0;
    bool operator==(const NativeSessionBinding &) const = default;
};

[[nodiscard]] std::optional<NativeSessionBinding>
inspectNativeSession(const QDBusConnection &trustedSystemBus, int actualWaylandDisplayFd);

} // namespace Linura::SecurityOwner
