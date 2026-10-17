#include "native_startup.h"
#include "process_guard.h"

#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QLibraryInfo>
#include <QQuickWindow>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <utility>
#include <poll.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

namespace Linura::SecurityOwner {
namespace {
template <std::size_t N> std::nullopt_t startupUnavailable(const char (&reason)[N]) noexcept
{
    // Only immutable stage identifiers, never paths, credentials or peer data.
    const ssize_t written = ::write(STDERR_FILENO, reason, N - 1);
    (void)written;
    return std::nullopt;
}

bool immutableRootPath(const QString &path, bool directory)
{
    if (!path.startsWith(QLatin1Char('/')) || path.size() > 512 || QDir::cleanPath(path) != path ||
        path.contains(QChar::Null))
        return false;
    QString current;
    const auto segments = path.mid(1).split(QLatin1Char('/'));
    for (qsizetype i = 0; i < segments.size(); ++i) {
        current += QLatin1Char('/') + segments[i];
        struct stat metadata
        {};
        const auto bytes = current.toLocal8Bit();
        const bool requireDirectory = directory || i + 1 < segments.size();
        if (lstat(bytes.constData(), &metadata) != 0 || metadata.st_uid != 0 ||
            (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
            (requireDirectory ? !S_ISDIR(metadata.st_mode)
                              : (!S_ISREG(metadata.st_mode) || metadata.st_nlink != 1)))
            return false;
    }
    return !segments.isEmpty();
}
bool socketName(const QString &value)
{
    if (value.isEmpty() || value.size() > 128)
        return false;
    for (QChar character : value) {
        const auto code = character.unicode();
        if (!((code >= 'a' && code <= 'z') || (code >= 'A' && code <= 'Z') ||
              (code >= '0' && code <= '9') || code == '-' || code == '_'))
            return false;
    }
    return true;
}

bool ownedDirectory(const QString &path, quint32 uid, bool privateMode)
{
    struct stat metadata
    {};
    return lstat(path.toLocal8Bit().constData(), &metadata) == 0 && S_ISDIR(metadata.st_mode) &&
           metadata.st_uid == uid && (!privateMode || (metadata.st_mode & 0777) == 0700);
}

class ScopedDescriptor final
{
  public:
    explicit ScopedDescriptor(int descriptor) : descriptor_(descriptor) {}
    ~ScopedDescriptor()
    {
        if (descriptor_ >= 0)
            (void)close(descriptor_);
    }
    ScopedDescriptor(const ScopedDescriptor &) = delete;
    ScopedDescriptor &operator=(const ScopedDescriptor &) = delete;
    [[nodiscard]] int get() const
    {
        return descriptor_;
    }
    [[nodiscard]] explicit operator bool() const
    {
        return descriptor_ >= 0;
    }

  private:
    int descriptor_;
};

constexpr uint32_t readinessWatchMask = IN_ATTRIB | IN_CLOSE_WRITE | IN_CREATE | IN_DELETE |
                                        IN_DELETE_SELF | IN_MOVED_FROM | IN_MOVED_TO |
                                        IN_MOVE_SELF | IN_DONT_FOLLOW | IN_EXCL_UNLINK | IN_ONLYDIR;

enum class ReadinessWatchRole { Runtime, Hyprland, Instance };
using ReadinessWatches = std::unordered_map<int, ReadinessWatchRole>;

bool addReadinessWatch(int descriptor, const QString &path, bool required, ReadinessWatchRole role,
                       ReadinessWatches &watches)
{
    const int watch =
        inotify_add_watch(descriptor, path.toLocal8Bit().constData(), readinessWatchMask);
    if (watch >= 0) {
        const auto [existing, inserted] = watches.emplace(watch, role);
        if (!inserted && existing->second != role)
            return false;
        return true;
    }
    // Nested directories are controlled by the session owner and can disappear
    // between validation and watch installation. The already-installed parent
    // watch plus the post-install strict rescan closes that race.
    return !required && (errno == ENOENT || errno == ENOTDIR || errno == ELOOP || errno == EACCES);
}

bool installReadinessWatches(int descriptor, const QString &runtimeDirectory, quint32 uid,
                             ReadinessWatches &watches)
{
    if (!ownedDirectory(runtimeDirectory, uid, true) ||
        !addReadinessWatch(descriptor, runtimeDirectory, true, ReadinessWatchRole::Runtime,
                           watches))
        return false;
    const auto hypr = runtimeDirectory + QStringLiteral("/hypr");
    struct stat metadata
    {};
    if (lstat(hypr.toLocal8Bit().constData(), &metadata) != 0)
        return errno == ENOENT;
    if (!ownedDirectory(hypr, uid, false) ||
        !addReadinessWatch(descriptor, hypr, false, ReadinessWatchRole::Hyprland, watches))
        return false;

    const auto filters = QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System;
    QDirIterator instances(hypr, filters, QDirIterator::NoIteratorFlags);
    unsigned count = 0;
    while (instances.hasNext()) {
        if (++count > NativeCompositorReadinessContract::maximumInstances)
            return false;
        const auto path = instances.next();
        if (socketName(instances.fileName()) && ownedDirectory(path, uid, false) &&
            !addReadinessWatch(descriptor, path, false, ReadinessWatchRole::Instance, watches))
            return false;
    }
    return true;
}

bool readinessNameIsRelevant(ReadinessWatchRole role, const QString &name)
{
    switch (role) {
    case ReadinessWatchRole::Runtime:
        return name == QLatin1String("hypr") ||
               (name.startsWith(QLatin1String("wayland-")) && socketName(name));
    case ReadinessWatchRole::Hyprland:
        return socketName(name);
    case ReadinessWatchRole::Instance:
        return name == QLatin1String(".socket.sock");
    }
    return false;
}

bool consumeReadinessEvents(int descriptor, ReadinessWatches &watches, unsigned &eventCount,
                            bool &topologyChanged)
{
    alignas(inotify_event) std::array<std::byte, 16 * 1024> buffer{};
    ssize_t received;
    do {
        received = read(descriptor, buffer.data(), buffer.size());
    } while (received < 0 && errno == EINTR);
    if (received < 0)
        return errno == EAGAIN;
    if (received == 0)
        return false;

    std::size_t offset = 0;
    const auto size = static_cast<std::size_t>(received);
    while (offset < size) {
        if (size - offset < sizeof(inotify_event))
            return false;
        const auto *event = reinterpret_cast<const inotify_event *>(buffer.data() + offset);
        const std::size_t recordSize = sizeof(inotify_event) + event->len;
        if (recordSize > size - offset || (event->mask & (IN_Q_OVERFLOW | IN_UNMOUNT)) != 0)
            return false;
        const auto watch = watches.find(event->wd);
        if (watch == watches.end())
            return false;
        bool relevant =
            event->len == 0 &&
            (event->mask & (IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED)) != 0;
        if (event->len != 0) {
            const std::size_t nameLength = strnlen(event->name, event->len);
            if (nameLength == event->len)
                return false;
            relevant = relevant ||
                       readinessNameIsRelevant(
                           watch->second,
                           QString::fromLatin1(event->name, static_cast<qsizetype>(nameLength)));
        }
        if ((event->mask & IN_IGNORED) != 0)
            watches.erase(watch);
        if (relevant) {
            if (++eventCount > NativeCompositorReadinessContract::maximumEvents)
                return false;
            topologyChanged = true;
        }
        offset += recordSize;
    }
    return true;
}
} // namespace

std::optional<NativeSocketRoutes> discoverNativeSocketRoutes(const QString &runtimeDirectory,
                                                             quint32 uid)
{
    if (uid == 0 || runtimeDirectory.size() > 256 ||
        !runtimeDirectory.startsWith(QLatin1Char('/')) ||
        QDir::cleanPath(runtimeDirectory) != runtimeDirectory ||
        runtimeDirectory.contains(QChar::Null))
        return std::nullopt;
    const auto socket = [uid](const QString &path) {
        struct stat metadata
        {};
        return path.size() <= 512 && lstat(path.toLocal8Bit().constData(), &metadata) == 0 &&
               S_ISSOCK(metadata.st_mode) && metadata.st_uid == uid && metadata.st_nlink == 1;
    };
    if (!ownedDirectory(runtimeDirectory, uid, true))
        return std::nullopt;
    NativeSocketRoutes routes;
    const auto filters = QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System;
    QDirIterator entries(runtimeDirectory, filters, QDirIterator::NoIteratorFlags);
    unsigned count = 0;
    while (entries.hasNext()) {
        if (++count > NativeCompositorReadinessContract::maximumRuntimeEntries)
            return std::nullopt;
        const auto path = entries.next();
        const auto name = entries.fileName();
        if (name.startsWith(QLatin1String("wayland-")) && socketName(name) && socket(path)) {
            if (routes.wayland.size() == NativeCompositorReadinessContract::maximumRoutes)
                return std::nullopt;
            routes.wayland.append(path);
        }
    }
    const auto hypr = runtimeDirectory + QStringLiteral("/hypr");
    if (!ownedDirectory(hypr, uid, false))
        return std::nullopt;
    QDirIterator instances(hypr, filters, QDirIterator::NoIteratorFlags);
    count = 0;
    while (instances.hasNext()) {
        if (++count > NativeCompositorReadinessContract::maximumInstances)
            return std::nullopt;
        const auto path = instances.next();
        if (socketName(instances.fileName()) && ownedDirectory(path, uid, false)) {
            const auto endpoint = path + QStringLiteral("/.socket.sock");
            if (socket(endpoint)) {
                if (routes.compositor.size() == NativeCompositorReadinessContract::maximumRoutes)
                    return std::nullopt;
                routes.compositor.append(endpoint);
            }
        }
    }
    if (routes.wayland.isEmpty() || routes.compositor.isEmpty())
        return std::nullopt;
    routes.wayland.sort();
    routes.compositor.sort(); // Enumeration order is not a selection authority.
    return routes;
}

std::optional<NativeSocketRoutes>
waitForNativeSocketRoutes(const QString &runtimeDirectory, quint32 uid,
                          std::chrono::milliseconds readinessBudget)
{
    using namespace std::chrono_literals;
    if (readinessBudget <= 0ms || readinessBudget > NativeCompositorReadinessContract::maximumWait)
        return std::nullopt;
    if (auto routes = discoverNativeSocketRoutes(runtimeDirectory, uid))
        return routes;

    const ScopedDescriptor descriptor(inotify_init1(IN_CLOEXEC | IN_NONBLOCK));
    if (!descriptor)
        return std::nullopt;
    ReadinessWatches watches;
    if (!installReadinessWatches(descriptor.get(), runtimeDirectory, uid, watches))
        return std::nullopt;
    // Scan again after every currently reachable directory is watched. An
    // object created during watch installation is therefore either discovered
    // now or represented by a queued event; no filesystem event is authority.
    if (auto routes = discoverNativeSocketRoutes(runtimeDirectory, uid))
        return routes;

    const auto deadline = std::chrono::steady_clock::now() + readinessBudget;
    unsigned eventCount = 0;
    while (true) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            return std::nullopt;
        const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(deadline - now);
        pollfd request{descriptor.get(), POLLIN, 0};
        const int result = poll(&request, 1, static_cast<int>(remaining.count()));
        if (result < 0 && errno == EINTR)
            continue; // Recompute the remaining monotonic budget after interruption.
        bool topologyChanged = false;
        if (result <= 0 || (request.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
            (request.revents & POLLIN) == 0 ||
            !consumeReadinessEvents(descriptor.get(), watches, eventCount, topologyChanged))
            return std::nullopt;
        if (!topologyChanged)
            continue;
        if (!installReadinessWatches(descriptor.get(), runtimeDirectory, uid, watches))
            return std::nullopt;
        if (auto routes = discoverNativeSocketRoutes(runtimeDirectory, uid))
            return routes;
    }
}

NativeStartup::NativeStartup(quint32 owner, NativeSocketRoutes routes)
    : uid_(owner), routes_(std::move(routes))
{}
NativeStartup::NativeStartup(NativeStartup &&other) noexcept
    : uid_(std::exchange(other.uid_, 0)), routes_(std::move(other.routes_))
{}

std::optional<NativeStartup> NativeStartup::prepare()
{
    static std::atomic_flag attempted = ATOMIC_FLAG_INIT;
    if (attempted.test_and_set() || QCoreApplication::instance())
        return startupUnavailable("linura-security-owner: startup/reentered\n");
    switch (protectNativeProcess(getuid())) {
    case ProcessProtection::Protected:
        break;
    case ProcessProtection::WrongIdentity:
        return startupUnavailable("linura-security-owner: startup/wrong-identity\n");
    case ProcessProtection::UnprotectedStartup:
        return startupUnavailable("linura-security-owner: startup/insecure-exec\n");
    case ProcessProtection::UnexpectedPrivilege:
        return startupUnavailable("linura-security-owner: startup/unexpected-privilege\n");
    case ProcessProtection::NativeProtectionUnavailable:
        return startupUnavailable("linura-security-owner: startup/kernel-protection\n");
    }

    // A root-supervised service does not inherit the desktop environment.
    // Enumerate bounded connection candidates, not claimed session identity.
    // Runtime must attest exactly one real active local graphical leader and
    // an independent native IPC connection to that SAME process.
    const QString runtimeDirectory = QStringLiteral("/run/user/%1").arg(getuid());
    // systemd's path unit intentionally reacts to the first Wayland socket.
    // Hyprland publishes its independently attested control socket shortly
    // afterwards. Filesystem events only wake a bounded scan-watch-rescan loop;
    // complete strict discovery is the sole readiness/success condition.
    const auto routes = waitForNativeSocketRoutes(runtimeDirectory, getuid(),
                                                  NativeCompositorReadinessContract::maximumWait);
    if (!routes)
        return startupUnavailable("linura-security-owner: startup/socket-routes\n");
    const auto directoryBytes = runtimeDirectory.toLocal8Bit();

    const QString plugins = QDir(QLibraryInfo::path(QLibraryInfo::PluginsPath)).canonicalPath();
    const QString imports = QDir(QLibraryInfo::path(QLibraryInfo::QmlImportsPath)).canonicalPath();
    constexpr auto fontConfiguration = "/usr/share/linura/security-owner/fonts.conf";
    if (!immutableRootPath(plugins, true) || !immutableRootPath(imports, true) ||
        !immutableRootPath(QString::fromLatin1(fontConfiguration), false) ||
        !immutableRootPath(QStringLiteral("/usr/share/fonts"), true))
        return startupUnavailable("linura-security-owner: startup/immutable-toolkit\n");

    // Secure-exec handles loader variables; explicitly remove all toolkit,
    // QML, GIO, font, compose, locale and bus overrides before any GUI/plugin
    // initialization. Never use caller HOME/cache/fonts or user QML modules.
    if (clearenv() != 0 || setenv("PATH", "/usr/bin:/bin", 1) != 0 ||
        setenv("LANG", "C.UTF-8", 1) != 0 || setenv("LC_ALL", "C.UTF-8", 1) != 0 ||
        setenv("QT_QPA_PLATFORM", "offscreen", 1) != 0 ||
        setenv("QML_DISABLE_DISK_CACHE", "1", 1) != 0 || setenv("GIO_USE_VFS", "local", 1) != 0 ||
        setenv("FONTCONFIG_FILE", fontConfiguration, 1) != 0 ||
        setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/run/dbus/system_bus_socket", 1) != 0 ||
        setenv("XDG_RUNTIME_DIR", directoryBytes.constData(), 1) != 0)
        return startupUnavailable("linura-security-owner: startup/environment\n");
    QCoreApplication::setLibraryPaths({plugins});
    QQuickWindow::setSceneGraphBackend(QStringLiteral("software"));
    return NativeStartup(getuid(), *routes);
}

} // namespace Linura::SecurityOwner
