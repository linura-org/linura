#include "native_display_startup.h"
#include "native_display_connection.h"
#include "native_wayland_lock.h"
#include "peer_guard.h"
#include "session_bootstrap.h"
#include "linura-display-integration-build.h"

#include <QCryptographicHash>
#include <QDBusArgument>
#include <QDBusMetaType>
#include <QDBusUnixFileDescriptor>
#include <QElapsedTimer>
#include <array>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace Linura::SecurityOwner::StartupDetail {
struct Transfer final
{
    QString lock;
    quint32 pid = 0;
    QString seat, compositor, integration, binary;
};
QDBusArgument &operator<<(QDBusArgument &wire, const Transfer &value)
{
    wire.beginStructure();
    wire << value.lock << value.pid << value.seat << value.compositor << value.integration
         << value.binary;
    wire.endStructure();
    return wire;
}
const QDBusArgument &operator>>(const QDBusArgument &wire, Transfer &value)
{
    wire.beginStructure();
    wire >> value.lock >> value.pid >> value.seat >> value.compositor >> value.integration >>
        value.binary;
    wire.endStructure();
    return wire;
}
} // namespace Linura::SecurityOwner::StartupDetail
Q_DECLARE_METATYPE(Linura::SecurityOwner::StartupDetail::Transfer)

namespace Linura::SecurityOwner {
namespace {
class Descriptor final
{
  public:
    explicit Descriptor(int value) : value_(value) {}
    ~Descriptor()
    {
        if (value_ >= 0)
            close(value_);
    }
    Descriptor(const Descriptor &) = delete;
    Descriptor &operator=(const Descriptor &) = delete;
    int get() const
    {
        return value_;
    }

  private:
    int value_;
};
std::optional<QString> nativeImage(quint32 pid)
{
    // The protected same-UID owner can inspect its actual kernel Wayland peer.
    // The root protection service needs no ambient ptrace capability.
    Descriptor root(open("/", O_PATH | O_DIRECTORY | O_CLOEXEC));
    if (root.get() < 0)
        return std::nullopt;
    Descriptor usr(openat(root.get(), "usr", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    Descriptor bin(usr.get() < 0
                       ? -1
                       : openat(usr.get(), "bin", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    for (const int directory : {root.get(), usr.get(), bin.get()}) {
        struct stat info
        {};
        if (directory < 0 || fstat(directory, &info) != 0 || !S_ISDIR(info.st_mode) ||
            info.st_uid != 0 || (info.st_mode & 0022) != 0)
            return std::nullopt;
    }
    Descriptor installed(
        openat(bin.get(), "Hyprland", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
    const auto process = QStringLiteral("/proc/%1/exe").arg(pid).toLocal8Bit();
    Descriptor executing(open(process.constData(), O_RDONLY | O_CLOEXEC | O_NONBLOCK));
    struct stat before
    {
    }, running{};
    if (installed.get() < 0 || executing.get() < 0 || fstat(installed.get(), &before) != 0 ||
        fstat(executing.get(), &running) != 0 || !S_ISREG(before.st_mode) || before.st_uid != 0 ||
        before.st_nlink != 1 || (before.st_mode & 0022) != 0 || (before.st_mode & S_IXUSR) == 0 ||
        before.st_size <= 0 || before.st_size > 512LL * 1024 * 1024 ||
        before.st_dev != running.st_dev || before.st_ino != running.st_ino)
        return std::nullopt;
    QElapsedTimer budget;
    budget.start();
    QCryptographicHash hash(QCryptographicHash::Sha256);
    std::array<char, 65536> bytes{};
    off_t consumed = 0;
    for (;;) {
        const ssize_t size = read(executing.get(), bytes.data(), bytes.size());
        if (size < 0 || budget.elapsed() >= 1000)
            return std::nullopt;
        if (size == 0)
            break;
        consumed += size;
        if (consumed > before.st_size)
            return std::nullopt;
        hash.addData(QByteArrayView(bytes.data(), size));
    }
    struct stat after
    {
    }, current{};
    if (consumed != before.st_size || fstat(installed.get(), &after) != 0 ||
        stat(process.constData(), &current) != 0 || current.st_dev != before.st_dev ||
        current.st_ino != before.st_ino || after.st_size != before.st_size ||
        after.st_mtim.tv_sec != before.st_mtim.tv_sec ||
        after.st_mtim.tv_nsec != before.st_mtim.tv_nsec ||
        after.st_ctim.tv_sec != before.st_ctim.tv_sec ||
        after.st_ctim.tv_nsec != before.st_ctim.tv_nsec)
        return std::nullopt;
    return QString::fromLatin1(hash.result().toHex());
}
} // namespace

NativeDisplayStartupAdmission admitNativeDisplayStartup(PeerGuard &peers,
                                                        const NativeSessionBinding &binding,
                                                        NativeWaylandLock &backend)
{
    if (!backend.displayStartupRequired())
        return NativeDisplayStartupAdmission::Ready; // Preserve S17 on a compositor that never
                                                     // advertised S21.
    const auto sample = backend.displayStartupSample();
    if (!sample)
        return NativeDisplayStartupAdmission::NativeSample;
    if (inspectNativeSession(peers.nativeConnection(), backend.actualDisplayFd()) != binding)
        return NativeDisplayStartupAdmission::Session;
    if (sample->startupPhase != 0)
        return NativeDisplayStartupAdmission::Ready; // Observe existing admission/loss; never
                                                     // replace its lease.
    const auto image = nativeImage(binding.compositorPid);
    if (!image)
        return NativeDisplayStartupAdmission::NativeImage;
    const auto guard = peers.namedPeer(NativePeerPurpose::DisplayProtection);
    if (!guard)
        return NativeDisplayStartupAdmission::OriginalGuard;
    qDBusRegisterMetaType<StartupDetail::Transfer>();
    const StartupDetail::Transfer transfer{binding.lock.resource,
                                           binding.compositorPid,
                                           binding.seat,
                                           sample->compositor,
                                           QLatin1String(HyprlandDisplay::IntegrationSourceDigest),
                                           *image};
    auto request = QDBusMessage::createMethodCall(
        guard->uniqueOwner, QStringLiteral("/org/linura/DisplayProtection1"),
        QStringLiteral("org.linura.DisplayProtection1"), QStringLiteral("NativeStartup"));
    request.setArguments({QVariant::fromValue(transfer)});
    const auto reply = peers.nativeConnection().call(request, QDBus::Block, 2000);
    if (reply.type() != QDBusMessage::ReplyMessage || reply.service() != guard->uniqueOwner ||
        reply.signature() != QLatin1String("hb") || reply.arguments().size() != 2 ||
        reply.arguments()[0].metaType() != QMetaType::fromType<QDBusUnixFileDescriptor>() ||
        reply.arguments()[1].metaType() != QMetaType::fromType<bool>())
        return NativeDisplayStartupAdmission::GuardReply;
    if (!peers.stillCurrent(NativePeerPurpose::DisplayProtection, *guard))
        return NativeDisplayStartupAdmission::GuardChanged;
    if (inspectNativeSession(peers.nativeConnection(), backend.actualDisplayFd()) != binding)
        return NativeDisplayStartupAdmission::SessionChanged;
    const auto lease = reply.arguments()[0].value<QDBusUnixFileDescriptor>();
    ucred actual{};
    socklen_t size = sizeof(actual);
    if (!lease.isValid() ||
        getsockopt(lease.fileDescriptor(), SOL_SOCKET, SO_PEERCRED, &actual, &size) != 0 ||
        size != sizeof(actual) || actual.uid != 0 || actual.pid <= 0 ||
        static_cast<quint32>(actual.pid) != guard->pid)
        return NativeDisplayStartupAdmission::KernelPeer;
    if (!backend.admitDisplayStartup(lease.fileDescriptor(), reply.arguments()[1].toBool(),
                                     guard->pid, sample->compositor))
        return NativeDisplayStartupAdmission::NativeTransfer;
    return NativeDisplayStartupAdmission::Ready;
}
} // namespace Linura::SecurityOwner
