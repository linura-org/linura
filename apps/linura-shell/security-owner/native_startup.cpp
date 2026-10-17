#include "native_startup.h"
#include "process_guard.h"

#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QLibraryInfo>
#include <QQuickWindow>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <utility>
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
} // namespace

std::optional<NativeSocketRoutes> discoverNativeSocketRoutes(const QString &runtimeDirectory,
                                                             quint32 uid)
{
    if (uid == 0 || runtimeDirectory.size() > 256 ||
        !runtimeDirectory.startsWith(QLatin1Char('/')) ||
        QDir::cleanPath(runtimeDirectory) != runtimeDirectory ||
        runtimeDirectory.contains(QChar::Null))
        return std::nullopt;
    const auto ownedDirectory = [uid](const QString &path, bool privateMode) {
        struct stat metadata
        {};
        return lstat(path.toLocal8Bit().constData(), &metadata) == 0 && S_ISDIR(metadata.st_mode) &&
               metadata.st_uid == uid && (!privateMode || (metadata.st_mode & 0777) == 0700);
    };
    const auto socket = [uid](const QString &path) {
        struct stat metadata
        {};
        return path.size() <= 512 && lstat(path.toLocal8Bit().constData(), &metadata) == 0 &&
               S_ISSOCK(metadata.st_mode) && metadata.st_uid == uid && metadata.st_nlink == 1;
    };
    if (!ownedDirectory(runtimeDirectory, true))
        return std::nullopt;
    NativeSocketRoutes routes;
    const auto filters = QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System;
    QDirIterator entries(runtimeDirectory, filters, QDirIterator::NoIteratorFlags);
    unsigned count = 0;
    while (entries.hasNext()) {
        if (++count > 256)
            return std::nullopt;
        const auto path = entries.next();
        const auto name = entries.fileName();
        if (name.startsWith(QLatin1String("wayland-")) && socketName(name) && socket(path)) {
            if (routes.wayland.size() == 16)
                return std::nullopt;
            routes.wayland.append(path);
        }
    }
    const auto hypr = runtimeDirectory + QStringLiteral("/hypr");
    if (!ownedDirectory(hypr, false))
        return std::nullopt;
    QDirIterator instances(hypr, filters, QDirIterator::NoIteratorFlags);
    count = 0;
    while (instances.hasNext()) {
        if (++count > 64)
            return std::nullopt;
        const auto path = instances.next();
        if (socketName(instances.fileName()) && ownedDirectory(path, false)) {
            const auto endpoint = path + QStringLiteral("/.socket.sock");
            if (socket(endpoint)) {
                if (routes.compositor.size() == 16)
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
                          std::chrono::milliseconds readinessBudget,
                          std::chrono::milliseconds pollInterval)
{
    using namespace std::chrono_literals;
    if (readinessBudget <= 0ms || readinessBudget > 5s || pollInterval <= 0ms ||
        pollInterval > 100ms)
        return std::nullopt;
    const auto deadline = std::chrono::steady_clock::now() + readinessBudget;
    while (true) {
        if (auto routes = discoverNativeSocketRoutes(runtimeDirectory, uid))
            return routes;
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            return std::nullopt;
        std::this_thread::sleep_for(std::min(pollInterval,
                                             std::chrono::duration_cast<std::chrono::milliseconds>(
                                                 deadline - now)));
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
    // afterwards. Keep the service alive for one bounded readiness window while
    // repeating the complete strict route check; never accept a partial route.
    const auto routes = waitForNativeSocketRoutes(runtimeDirectory, getuid(),
                                                   std::chrono::seconds(5),
                                                   std::chrono::milliseconds(50));
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
