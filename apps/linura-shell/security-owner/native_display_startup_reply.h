#pragma once

#include "peer_guard.h"

#include <QDBusUnixFileDescriptor>
#include <sys/socket.h>

namespace Linura::SecurityOwner {
enum class NativeDisplayStartupReplyFault { None, Sender, Signature, ArgumentTypes, KernelPeer };

// Private transport validation only; the caller must retain the original
// supervised peer and revalidate it and the native session before transfer.
[[nodiscard]] inline NativeDisplayStartupReplyFault
inspectNativeDisplayStartupReply(const QDBusMessage &reply, const NativePeerIdentity &peer)
{
    // Qt 6.11 service() deliberately returns empty for replies. The call is
    // addressed to the pinned unique owner; system-bus requested-reply rules
    // correlate it. An exposed sender must still match. The received socket's
    // kernel peer must independently be that original root main process.
    if (reply.type() != QDBusMessage::ReplyMessage || peer.uniqueOwner.isEmpty() ||
        !peer.uniqueOwner.startsWith(QLatin1Char(':')) || peer.uniqueOwner.size() > 128 ||
        (!reply.service().isEmpty() && reply.service() != peer.uniqueOwner))
        return NativeDisplayStartupReplyFault::Sender;
    if (reply.signature() != QLatin1String("hb"))
        return NativeDisplayStartupReplyFault::Signature;
    if (reply.arguments().size() != 2 ||
        reply.arguments()[0].metaType() != QMetaType::fromType<QDBusUnixFileDescriptor>() ||
        reply.arguments()[1].metaType() != QMetaType::fromType<bool>())
        return NativeDisplayStartupReplyFault::ArgumentTypes;
    const auto lease = reply.arguments()[0].value<QDBusUnixFileDescriptor>();
    ucred actual{};
    socklen_t size = sizeof(actual);
    if (peer.uid != 0 || peer.pid == 0 || !lease.isValid() ||
        getsockopt(lease.fileDescriptor(), SOL_SOCKET, SO_PEERCRED, &actual, &size) != 0 ||
        size != sizeof(actual) || actual.uid != 0 || actual.pid <= 0 ||
        static_cast<quint32>(actual.pid) != peer.pid)
        return NativeDisplayStartupReplyFault::KernelPeer;
    return NativeDisplayStartupReplyFault::None;
}
} // namespace Linura::SecurityOwner
