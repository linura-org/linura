#include "compositor_probe.h"

#include <QByteArray>
#include <QElapsedTimer>
#include <QStringView>

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <limits>

namespace Linura::SecurityOwner {
namespace {

constexpr qint64 ProbeBudgetMs = 500;
constexpr qsizetype MaximumReplyBytes = 64;

bool instanceName(QStringView name)
{
    if (name.isEmpty() || name.size() > 80 || name == QLatin1String(".") ||
        name == QLatin1String(".."))
        return false;
    for (QChar character : name) {
        const ushort code = character.unicode();
        if (!((code >= 'a' && code <= 'z') || (code >= 'A' && code <= 'Z') ||
              (code >= '0' && code <= '9') || code == '_' || code == '-' || code == '.'))
            return false;
    }
    return true;
}

bool socketRoute(const QString &path, quint32 uid)
{
    const QString prefix = QStringLiteral("/run/user/%1/hypr/").arg(uid);
    constexpr char suffix[] = "/.socket.sock";
    if (!path.startsWith(prefix) || !path.endsWith(QLatin1String(suffix)))
        return false;
    const qsizetype length = path.size() - prefix.size() - qsizetype(sizeof(suffix) - 1);
    return length > 0 && instanceName(QStringView(path).mid(prefix.size(), length));
}

bool peerMatches(int descriptor, const NativeSessionBinding &binding)
{
    ucred peer{};
    socklen_t bytes = sizeof(peer);
    return getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &peer, &bytes) == 0 &&
           bytes == sizeof(peer) && peer.pid > 0 && peer.uid == binding.lock.uid &&
           static_cast<quint32>(peer.pid) == binding.compositorPid;
}

bool waitReady(int descriptor, short event, QElapsedTimer &budget)
{
    while (true) {
        const qint64 remaining = ProbeBudgetMs - budget.elapsed();
        if (remaining <= 0)
            return false;
        pollfd pending{descriptor, event, 0};
        const int result = poll(&pending, 1, static_cast<int>(remaining));
        if (result < 0 && errno == EINTR)
            continue; // Original total deadline is never extended.
        if (result != 1 || (pending.revents & (POLLERR | POLLNVAL)) != 0)
            return false;
        return (pending.revents & event) != 0 ||
               (event == POLLIN && (pending.revents & POLLHUP) != 0);
    }
}

} // namespace

std::optional<NativeCompositorLockState> decodeNativeHyprlandLock(QByteArrayView reply)
{
    if (reply.isEmpty() || reply.size() > MaximumReplyBytes)
        return std::nullopt;
    // Accept precisely the qualified native response, not a generic JSON object
    // with duplicate/unknown keys, lossy coercion, trailing payload or nesting.
    // Whitespace may occur only outside the key/literal tokens. Removing it
    // globally would incorrectly turn an unknown "lo cked" key into authority.
    qsizetype position = 0;
    const auto whitespace = [&] {
        while (position < reply.size()) {
            const char c = reply[position];
            if (c != ' ' && c != '\n' && c != '\r' && c != '\t')
                break;
            ++position;
        }
    };
    const auto token = [&](QByteArrayView expected) {
        whitespace();
        if (expected.size() > reply.size() - position ||
            reply.sliced(position, expected.size()) != expected)
            return false;
        position += expected.size();
        return true;
    };
    if (!token("{") || !token("\"locked\"") || !token(":"))
        return std::nullopt;
    NativeCompositorLockState state;
    if (token("true"))
        state = NativeCompositorLockState::Locked;
    else if (token("false"))
        state = NativeCompositorLockState::Unlocked;
    else
        return std::nullopt;
    if (!token("}"))
        return std::nullopt;
    whitespace();
    if (position != reply.size())
        return std::nullopt;
    return state;
}

namespace {
enum class NativeReadQuery { Lock, Outputs };
std::optional<QByteArray>
readNativeHyprland(const QString &nativeSocketPath, const NativeSessionBinding &binding,
                   NativeReadQuery query, NativeCompositorProbeFailure *failure)
{
    if (failure)
        *failure = NativeCompositorProbeFailure::None;
    const auto deny =
        [failure](NativeCompositorProbeFailure reason) -> std::optional<QByteArray> {
        if (failure)
            *failure = reason;
        return std::nullopt;
    };
    const auto parsed = NativeLockIdentity::parse(binding.lock.resource);
    if (!parsed || *parsed != binding.lock || binding.compositorPid == 0 ||
        binding.compositorPid > static_cast<quint32>(std::numeric_limits<pid_t>::max()) ||
        !socketRoute(nativeSocketPath, binding.lock.uid))
        return deny(NativeCompositorProbeFailure::Binding);
    const QByteArray path = nativeSocketPath.toUtf8();
    sockaddr_un address{};
    if (path.isEmpty() || path.size() >= qsizetype(sizeof(address.sun_path)))
        return deny(NativeCompositorProbeFailure::Route);
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.constData(), static_cast<std::size_t>(path.size()));
    const int descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (descriptor < 0)
        return deny(NativeCompositorProbeFailure::Socket);
    struct Close final
    {
        int fd;
        ~Close()
        {
            close(fd);
        }
    } cleanup{descriptor};
    QElapsedTimer budget;
    budget.start();
    const auto unavailable = [&](NativeCompositorProbeFailure reason) {
        return deny(budget.elapsed() >= ProbeBudgetMs ? NativeCompositorProbeFailure::Deadline
                                                      : reason);
    };
    if (::connect(descriptor, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
        if ((errno != EINPROGRESS && errno != EAGAIN) || !waitReady(descriptor, POLLOUT, budget))
            return unavailable(NativeCompositorProbeFailure::Connect);
        int error = 0;
        socklen_t bytes = sizeof(error);
        if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &bytes) != 0 ||
            bytes != sizeof(error) || error != 0)
            return unavailable(NativeCompositorProbeFailure::Connect);
    }
    if (!peerMatches(descriptor, binding) || budget.elapsed() >= ProbeBudgetMs)
        return unavailable(NativeCompositorProbeFailure::Peer);
    const QByteArrayView command = query == NativeReadQuery::Lock ? QByteArrayView("j/locked")
                                                                : QByteArrayView("j/monitors all");
    std::size_t sent = 0;
    while (sent < static_cast<std::size_t>(command.size())) {
        if (budget.elapsed() >= ProbeBudgetMs)
            return deny(NativeCompositorProbeFailure::Deadline);
        const ssize_t count =
            send(descriptor, command.data() + sent, static_cast<std::size_t>(command.size()) - sent, MSG_NOSIGNAL);
        if (count > 0)
            sent += static_cast<std::size_t>(count);
        else if (count < 0 && errno == EINTR)
            continue;
        else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!waitReady(descriptor, POLLOUT, budget))
                return unavailable(NativeCompositorProbeFailure::Send);
        } else {
            return unavailable(NativeCompositorProbeFailure::Send);
        }
    }
    const qsizetype maximum = query == NativeReadQuery::Lock ? MaximumReplyBytes : 256 * 1024;
    QByteArray reply;
    std::array<char, 4096> chunk{};
    while (true) {
        if (!waitReady(descriptor, POLLIN, budget))
            return unavailable(NativeCompositorProbeFailure::Receive);
        const ssize_t count = recv(descriptor, chunk.data(), chunk.size(), 0);
        if (count > 0) {
            if (count > maximum - reply.size()) return deny(NativeCompositorProbeFailure::ReplyLimit);
            reply.append(chunk.data(), static_cast<qsizetype>(count));
        } else if (count == 0) {
            if (!peerMatches(descriptor, binding) || budget.elapsed() >= ProbeBudgetMs)
                return unavailable(NativeCompositorProbeFailure::Peer);
            return reply;
        } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
            return unavailable(NativeCompositorProbeFailure::Receive);
        }
    }
}
} // namespace

std::optional<NativeCompositorLockState>
observeNativeHyprlandLock(const QString &path, const NativeSessionBinding &binding,
                          NativeCompositorProbeFailure *failure)
{
    const auto reply = readNativeHyprland(path, binding, NativeReadQuery::Lock, failure);
    if (!reply) return std::nullopt;
    const auto decoded = decodeNativeHyprlandLock(*reply);
    if (!decoded && failure) *failure = NativeCompositorProbeFailure::Reply;
    return decoded;
}
std::optional<QByteArray>
observeNativeHyprlandOutputs(const QString &path, const NativeSessionBinding &binding)
{
    return readNativeHyprland(path, binding, NativeReadQuery::Outputs, nullptr);
}

} // namespace Linura::SecurityOwner
