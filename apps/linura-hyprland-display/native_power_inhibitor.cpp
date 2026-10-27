#include "native_power_inhibitor.h"

#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

namespace Linura::HyprlandDisplay {
namespace {
constexpr auto Budget = std::chrono::milliseconds(250);
constexpr char Path[] = "/org/freedesktop/login1";
constexpr char Manager[] = "org.freedesktop.login1.Manager";
using Bus = std::unique_ptr<sd_bus, decltype(&sd_bus_unref)>;
using Message = std::unique_ptr<sd_bus_message, decltype(&sd_bus_message_unref)>;

class Probe final
{
  public:
    const std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();
    Bus bus{nullptr, sd_bus_unref};
    std::string owner;
    bool remaining()
    {
        const auto elapsed = std::chrono::steady_clock::now() - started;
        if (elapsed < decltype(elapsed)::zero() || elapsed >= Budget)
            return false;
        const auto micros =
            std::chrono::duration_cast<std::chrono::microseconds>(Budget - elapsed).count();
        return micros > 0 &&
               sd_bus_set_method_call_timeout(bus.get(), static_cast<uint64_t>(micros)) >= 0;
    }
    bool initialize()
    {
        sd_bus *native = nullptr;
        if (sd_bus_new(&native) < 0)
            return false;
        bus.reset(native);
        // No environment-selected bus, autolaunch, alternate service or command.
        if (!remaining() ||
            sd_bus_set_address(bus.get(), "unix:path=/run/dbus/system_bus_socket") < 0 ||
            sd_bus_set_bus_client(bus.get(), 1) < 0 || sd_bus_start(bus.get()) < 0)
            return false;
        ucred credentials{};
        socklen_t size = sizeof(credentials);
        if (getsockopt(sd_bus_get_fd(bus.get()), SOL_SOCKET, SO_PEERCRED, &credentials, &size) <
                0 ||
            size != sizeof(credentials) || credentials.uid != 0 || credentials.pid <= 0 ||
            !remaining())
            return false;
        sd_bus_message *reply = nullptr;
        const int result = sd_bus_call_method(
            bus.get(), "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
            "GetNameOwner", nullptr, &reply, "s", "org.freedesktop.login1");
        Message name(reply, sd_bus_message_unref);
        const char *value = nullptr;
        if (result < 0 || !name || sd_bus_message_read(name.get(), "s", &value) < 0 || !value ||
            value[0] != ':' || strnlen(value, 256) > 255 || !remaining())
            return false;
        owner = value;
        reply = nullptr;
        const int uidResult = sd_bus_call_method(
            bus.get(), "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
            "GetConnectionUnixUser", nullptr, &reply, "s", owner.c_str());
        Message uid(reply, sd_bus_message_unref);
        uint32_t user = UINT32_MAX;
        return uidResult >= 0 && uid && sd_bus_message_read(uid.get(), "u", &user) > 0 &&
               user == 0 && remaining();
    }
    bool notPreparing(const char *property)
    {
        if (!remaining())
            return false;
        sd_bus_message *reply = nullptr;
        const int result =
            sd_bus_call_method(bus.get(), owner.c_str(), Path, "org.freedesktop.DBus.Properties",
                               "Get", nullptr, &reply, "ss", Manager, property);
        Message message(reply, sd_bus_message_unref);
        const char *sender = message ? sd_bus_message_get_sender(message.get()) : nullptr;
        int preparing = 1;
        return result >= 0 && message && sender && owner == sender &&
               sd_bus_message_enter_container(message.get(), 'v', "b") > 0 &&
               sd_bus_message_read(message.get(), "b", &preparing) > 0 && preparing == 0 &&
               sd_bus_message_exit_container(message.get()) >= 0 && remaining();
    }
};
} // namespace

NativePowerInhibitor::~NativePowerInhibitor()
{
    release();
}
void NativePowerInhibitor::release() noexcept
{
    if (descriptor_ >= 0) {
        close(descriptor_);
        descriptor_ = -1;
    }
}
bool NativePowerInhibitor::acquire()
{
    if (descriptor_ >= 0)
        return false; // A retained unresolved recovery is never a new admission.
    Probe probe;
    if (!probe.initialize() || !probe.notPreparing("PreparingForSleep") ||
        !probe.notPreparing("PreparingForShutdown"))
        return false;
    sd_bus_message *reply = nullptr;
    const int result = sd_bus_call_method(probe.bus.get(), probe.owner.c_str(), Path, Manager,
                                          "Inhibit", nullptr, &reply, "ssss", "sleep:shutdown",
                                          "Linura", "Display configuration recovery", "block");
    Message message(reply, sd_bus_message_unref);
    const char *sender = message ? sd_bus_message_get_sender(message.get()) : nullptr;
    int received = -1;
    struct stat metadata
    {};
    if (result < 0 || !message || !sender || probe.owner != sender || !probe.remaining() ||
        sd_bus_message_read(message.get(), "h", &received) <= 0 || received < 0 ||
        fstat(received, &metadata) < 0 || !S_ISFIFO(metadata.st_mode))
        return false;
    // sd-bus owns the received descriptor; retain a separate CLOEXEC reference.
    const int retained = fcntl(received, F_DUPFD_CLOEXEC, 3);
    if (retained < 0)
        return false;
    if (!probe.notPreparing("PreparingForSleep") || !probe.notPreparing("PreparingForShutdown")) {
        close(retained);
        return false;
    }
    descriptor_ = retained;
    return true;
}

} // namespace Linura::HyprlandDisplay
