#include "compositor_probe.h"
#include "native_display_layout.h"

#include <QByteArray>
#include <QElapsedTimer>
#include <QStringView>

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <algorithm>
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

bool waitReady(int descriptor, short event, QElapsedTimer &budget, qint64 limit = ProbeBudgetMs)
{
    while (true) {
        const qint64 remaining = limit - budget.elapsed();
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
std::optional<QByteArray>
nativeExchange(const QString &nativeSocketPath, const NativeSessionBinding &binding,
                QByteArrayView command, qsizetype maximum, qint64 limit,
                NativeCompositorProbeFailure *failure)
{
    if (failure)
        *failure = NativeCompositorProbeFailure::None;
    const auto deny =
        [failure](NativeCompositorProbeFailure reason) -> std::optional<QByteArray> {
        if (failure)
            *failure = reason;
        return std::nullopt;
    };
    if (command.isEmpty() || command.size() > 512 || maximum <= 0 || maximum > 256 * 1024 || limit <= 0 || limit > ProbeBudgetMs)
        return deny(NativeCompositorProbeFailure::Binding);
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
        return deny(budget.elapsed() >= limit ? NativeCompositorProbeFailure::Deadline
                                                      : reason);
    };
    if (::connect(descriptor, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0) {
        if ((errno != EINPROGRESS && errno != EAGAIN) || !waitReady(descriptor, POLLOUT, budget, limit))
            return unavailable(NativeCompositorProbeFailure::Connect);
        int error = 0;
        socklen_t bytes = sizeof(error);
        if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &bytes) != 0 ||
            bytes != sizeof(error) || error != 0)
            return unavailable(NativeCompositorProbeFailure::Connect);
    }
    if (!peerMatches(descriptor, binding) || budget.elapsed() >= limit)
        return unavailable(NativeCompositorProbeFailure::Peer);
    std::size_t sent = 0;
    while (sent < static_cast<std::size_t>(command.size())) {
        if (budget.elapsed() >= limit)
            return deny(NativeCompositorProbeFailure::Deadline);
        const ssize_t count =
            send(descriptor, command.data() + sent, static_cast<std::size_t>(command.size()) - sent, MSG_NOSIGNAL);
        if (count > 0)
            sent += static_cast<std::size_t>(count);
        else if (count < 0 && errno == EINTR)
            continue;
        else if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!waitReady(descriptor, POLLOUT, budget, limit))
                return unavailable(NativeCompositorProbeFailure::Send);
        } else {
            return unavailable(NativeCompositorProbeFailure::Send);
        }
    }
    QByteArray reply;
    std::array<char, 4096> chunk{};
    while (true) {
        if (!waitReady(descriptor, POLLIN, budget, limit))
            return unavailable(NativeCompositorProbeFailure::Receive);
        const ssize_t count = recv(descriptor, chunk.data(), chunk.size(), 0);
        if (count > 0) {
            if (count > maximum - reply.size()) return deny(NativeCompositorProbeFailure::ReplyLimit);
            reply.append(chunk.data(), static_cast<qsizetype>(count));
        } else if (count == 0) {
            if (!peerMatches(descriptor, binding) || budget.elapsed() >= limit)
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
    const auto reply = nativeExchange(path, binding, "j/locked", MaximumReplyBytes, ProbeBudgetMs, failure);
    if (!reply) return std::nullopt;
    const auto decoded = decodeNativeHyprlandLock(*reply);
    if (!decoded && failure) *failure = NativeCompositorProbeFailure::Reply;
    return decoded;
}
std::optional<QByteArray>
observeNativeHyprlandOutputs(const QString &path, const NativeSessionBinding &binding)
{
    return nativeExchange(path, binding, "j/monitors all", 256 * 1024, ProbeBudgetMs, nullptr);
}

NativeDisplayWriteResult applyNativeHyprlandLayout(const NativeDisplayLayout &layout,
    const NativeDisplaySnapshot &snapshot, const QString &path, const NativeSessionBinding &binding)
{
    const auto commands = layout.commands(snapshot);
    if (commands.empty() || commands.size() > 16) return {};
    QElapsedTimer total; total.start();
    NativeDisplayWriteResult result;
    for (const auto &command : commands) {
        const qint64 remaining = 1500 - total.elapsed();
        if (remaining <= 0) return result;
        // Set before entering the exchange: failure after connect/write may
        // hide an effect. The runtime's recovery timer is already armed.
        result.attempted = true;
        const auto reply = nativeExchange(path, binding, command, 64, std::min(remaining, ProbeBudgetMs), nullptr);
        if (!reply || (*reply != "ok" && *reply != "ok\n")) return result;
    }
    result.allAcknowledged = true;
    return result;
}

} // namespace Linura::SecurityOwner
