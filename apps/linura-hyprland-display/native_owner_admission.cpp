#include "native_owner_admission.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <string_view>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

namespace Linura::HyprlandDisplay {
namespace {
constexpr char Image[] = "/usr/lib/linura/linura-security-owner";
constexpr char Fragment[] = "/usr/lib/systemd/system/linura-security-owner@.service";
constexpr char Systemd[] = "org.freedesktop.systemd1";
constexpr char Unit[] = "org.freedesktop.systemd1.Unit";
constexpr char Service[] = "org.freedesktop.systemd1.Service";
constexpr char Properties[] = "org.freedesktop.DBus.Properties";
constexpr auto Budget = std::chrono::milliseconds(250);
using Bus = std::unique_ptr<sd_bus, decltype(&sd_bus_unref)>;
using Message = std::unique_ptr<sd_bus_message, decltype(&sd_bus_message_unref)>;

class Descriptor final
{
  public:
    int fd;
    explicit Descriptor(int value) : fd(value) {}
    ~Descriptor()
    {
        if (fd >= 0)
            close(fd);
    }
    Descriptor(const Descriptor &) = delete;
    Descriptor &operator=(const Descriptor &) = delete;
};

bool immutableFile(const char *path, bool executable)
{
    // Walk every component with descriptors: stat-then-open or following an
    // ancestor symlink would attest another file during a concurrent rename.
    Descriptor current(open("/", O_PATH | O_DIRECTORY | O_CLOEXEC));
    if (current.fd < 0)
        return false;
    std::string remaining(path + 1);
    for (;;) {
        struct stat metadata
        {};
        if (fstat(current.fd, &metadata) < 0 || metadata.st_uid != 0 ||
            (metadata.st_mode & 0022) != 0 || !S_ISDIR(metadata.st_mode))
            return false;
        const auto slash = remaining.find('/');
        const auto component = remaining.substr(0, slash);
        if (component.empty() || component == "." || component == "..")
            return false;
        const int next = openat(current.fd, component.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0)
            return false;
        close(current.fd);
        current.fd = next;
        if (slash == std::string::npos) {
            return fstat(current.fd, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
                   metadata.st_uid == 0 && metadata.st_nlink == 1 &&
                   (metadata.st_mode & 0022) == 0 &&
                   (!executable || (metadata.st_mode & S_IXUSR) != 0);
        }
        remaining.erase(0, slash + 1);
    }
}

bool livePid(int descriptor)
{
    pollfd state{descriptor, POLLIN, 0};
    return descriptor >= 0 && poll(&state, 1, 0) == 0;
}

class Probe final
{
  public:
    const std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();
    Bus bus{nullptr, sd_bus_unref};
    std::string owner, path;

    bool remaining()
    {
        const auto elapsed = std::chrono::steady_clock::now() - started;
        if (elapsed < decltype(elapsed)::zero() || elapsed >= Budget)
            return false;
        const auto micros =
            std::chrono::duration_cast<std::chrono::microseconds>(Budget - elapsed).count();
        return micros > 0 &&
               sd_bus_set_method_call_timeout(bus.get(), static_cast<std::uint64_t>(micros)) >= 0;
    }
    Message call(const char *destination, const char *object, const char *interface,
                 const char *method, const char *signature, const char *argument)
    {
        sd_bus_message *raw = nullptr;
        if (!remaining() || sd_bus_call_method(bus.get(), destination, object, interface, method,
                                               nullptr, &raw, signature, argument) < 0) {
            sd_bus_message_unref(raw);
            return {nullptr, sd_bus_message_unref};
        }
        return {raw, sd_bus_message_unref};
    }
    std::optional<std::string> systemdOwner()
    {
        auto message = call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                            "GetNameOwner", "s", Systemd);
        const char *value = nullptr;
        if (!message || sd_bus_message_read(message.get(), "s", &value) <= 0 || !value ||
            value[0] != ':' || strnlen(value, 128) >= 128 || !remaining())
            return std::nullopt;
        return value;
    }
    bool initialize(uid_t uid)
    {
        sd_bus *raw = nullptr;
        if (sd_bus_new(&raw) < 0)
            return false;
        bus.reset(raw);
        if (!remaining() ||
            sd_bus_set_address(bus.get(), "unix:path=/run/dbus/system_bus_socket") < 0 ||
            sd_bus_set_bus_client(bus.get(), 1) < 0 || sd_bus_start(bus.get()) < 0)
            return false;
        ucred peer{};
        socklen_t size = sizeof(peer);
        if (getsockopt(sd_bus_get_fd(bus.get()), SOL_SOCKET, SO_PEERCRED, &peer, &size) < 0 ||
            size != sizeof(peer) || peer.uid != 0 || peer.pid <= 0 || !remaining())
            return false;
        const auto name = systemdOwner();
        if (!name)
            return false;
        owner = *name;
        auto user = call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                         "GetConnectionUnixUser", "s", owner.c_str());
        std::uint32_t actualUid = UINT32_MAX;
        if (!user || sd_bus_message_read(user.get(), "u", &actualUid) <= 0 || actualUid != 0)
            return false;
        const auto unit = "linura-security-owner@" + std::to_string(uid) + ".service";
        auto handle = call(owner.c_str(), "/org/freedesktop/systemd1",
                           "org.freedesktop.systemd1.Manager", "GetUnit", "s", unit.c_str());
        const char *object = nullptr;
        const char *sender = handle ? sd_bus_message_get_sender(handle.get()) : nullptr;
        if (!handle || !sender || owner != sender ||
            sd_bus_message_read(handle.get(), "o", &object) <= 0 || !object ||
            strnlen(object, 257) > 256 ||
            std::string_view(object).find("/org/freedesktop/systemd1/unit/") != 0 || !remaining())
            return false;
        path = object;
        return true;
    }
    Message property(const char *interface, const char *name, const char *signature)
    {
        sd_bus_message *raw = nullptr;
        const int result =
            remaining() ? sd_bus_call_method(bus.get(), owner.c_str(), path.c_str(), Properties,
                                             "Get", nullptr, &raw, "ss", interface, name)
                        : -1;
        Message message(raw, sd_bus_message_unref);
        const char *sender = message ? sd_bus_message_get_sender(message.get()) : nullptr;
        if (result < 0 || !message || !sender || owner != sender ||
            sd_bus_message_enter_container(message.get(), 'v', signature) <= 0 || !remaining())
            return {nullptr, sd_bus_message_unref};
        return message;
    }
    bool text(const char *interface, const char *name, std::string &output)
    {
        auto message = property(interface, name, "s");
        const char *value = nullptr;
        if (!message || sd_bus_message_read(message.get(), "s", &value) <= 0 || !value ||
            strnlen(value, 257) > 256)
            return false;
        output = value;
        return remaining();
    }
    bool mainPid(std::uint32_t &pid)
    {
        auto message = property(Service, "MainPID", "u");
        return message && sd_bus_message_read(message.get(), "u", &pid) > 0 && remaining();
    }
    bool invocation(WireEndpoint::OwnerInvocation &value)
    {
        auto message = property(Unit, "InvocationID", "ay");
        const void *bytes = nullptr;
        std::size_t length = 0;
        if (!message || sd_bus_message_read_array(message.get(), 'y', &bytes, &length) <= 0 ||
            !bytes || length != value.size() || !remaining())
            return false;
        std::memcpy(value.data(), bytes, length);
        return true;
    }
    bool read(SupervisedDisplayOwner &facts)
    {
        if (!mainPid(facts.pid) || !invocation(facts.invocation) ||
            !text(Service, "User", facts.user) || !text(Unit, "FragmentPath", facts.fragment) ||
            !text(Unit, "ActiveState", facts.active) || !text(Unit, "SubState", facts.substate))
            return false;
        auto dropIns = property(Unit, "DropInPaths", "as");
        if (!dropIns || sd_bus_message_enter_container(dropIns.get(), 'a', "s") <= 0 ||
            sd_bus_message_at_end(dropIns.get(), 0) <= 0)
            return false;
        facts.noDropIns = true;
        auto launch = property(Service, "ExecStart", "a(sasbttttuii)");
        if (!launch || sd_bus_message_enter_container(launch.get(), 'a', "(sasbttttuii)") <= 0 ||
            sd_bus_message_enter_container(launch.get(), 'r', "sasbttttuii") <= 0)
            return false;
        const char *image = nullptr, *argument = nullptr;
        if (sd_bus_message_read(launch.get(), "s", &image) <= 0 || !image ||
            strnlen(image, 257) > 256 ||
            sd_bus_message_enter_container(launch.get(), 'a', "s") <= 0 ||
            sd_bus_message_read(launch.get(), "s", &argument) <= 0 || !argument ||
            std::strcmp(argument, Image) != 0 || sd_bus_message_at_end(launch.get(), 0) <= 0 ||
            sd_bus_message_exit_container(launch.get()) < 0)
            return false;
        facts.image = image;
        facts.exactArguments = true;
        int ignoreFailure = 1;
        std::uint64_t stoppedRealtime = 1, stoppedMonotonic = 1;
        std::int32_t code = 1, status = 1;
        if (sd_bus_message_read(launch.get(), "bttttuii", &ignoreFailure, &facts.startedRealtime,
                                &facts.startedMonotonic, &stoppedRealtime, &stoppedMonotonic,
                                &facts.launchedPid, &code, &status) <= 0 ||
            sd_bus_message_exit_container(launch.get()) < 0 ||
            sd_bus_message_at_end(launch.get(), 0) <= 0)
            return false;
        facts.runningLaunch = !ignoreFailure && stoppedRealtime == 0 && stoppedMonotonic == 0 &&
                              code == 0 && status == 0;
        facts.immutableFragment = immutableFile(Fragment, false);
        facts.immutableImage = immutableFile(Image, true);
        return remaining();
    }
};
} // namespace

std::optional<WireEndpoint::OwnerInvocation> attestDisplayOwner(pid_t pid, uid_t uid) noexcept
{
    try {
        if (pid <= 0 || uid == 0 || uid != getuid())
            return std::nullopt;
        Descriptor process(static_cast<int>(syscall(SYS_pidfd_open, pid, 0)));
        if (!livePid(process.fd))
            return std::nullopt;
        Probe probe;
        SupervisedDisplayOwner facts;
        if (!probe.initialize(uid) || !probe.read(facts))
            return std::nullopt;
        const auto admitted = validateDisplayOwner(pid, uid, facts);
        std::uint32_t freshPid = 0;
        WireEndpoint::OwnerInvocation freshInvocation{};
        std::string freshActive, freshSubstate;
        // An owner/daemon restart or PID reuse during the probe cannot join
        // evidence from different lifetimes. The pidfd is never a credential.
        const auto freshSystemd = probe.systemdOwner();
        if (!admitted || !freshSystemd || *freshSystemd != probe.owner ||
            !probe.mainPid(freshPid) || freshPid != facts.pid ||
            !probe.invocation(freshInvocation) || freshInvocation != *admitted ||
            !probe.text(Unit, "ActiveState", freshActive) || freshActive != "active" ||
            !probe.text(Unit, "SubState", freshSubstate) || freshSubstate != "running" ||
            !livePid(process.fd) || !probe.remaining())
            return std::nullopt;
        return admitted;
    } catch (...) {
        return std::nullopt;
    }
}
} // namespace Linura::HyprlandDisplay
