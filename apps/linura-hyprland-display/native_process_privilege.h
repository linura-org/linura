#pragma once

#include <array>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <string_view>
#include <linux/capability.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace Linura::HyprlandDisplay {

// The kernel marker is set before the dynamic loader/constructors. A later
// prctl or an environment variable cannot substitute for secure execution.
[[nodiscard]] inline bool secureNativeEntry() noexcept
{
    return getauxval(AT_SECURE) == 1;
}

// capset changes only the calling thread. Refuse startup if a constructor has
// already created another thread; it could retain the inherited capabilities.
[[nodiscard]] inline bool singleNativeThread() noexcept
{
    if (syscall(SYS_gettid) != getpid())
        return false;
    DIR *tasks = opendir("/proc/self/task");
    if (!tasks)
        return false;
    unsigned count = 0;
    errno = 0;
    while (const auto *entry = readdir(tasks)) {
        if (std::strcmp(entry->d_name, ".") != 0 && std::strcmp(entry->d_name, "..") != 0 &&
            ++count > 1)
            break;
    }
    const bool complete = errno == 0 && count == 1;
    return closedir(tasks) == 0 && complete;
}

// Changing the effective group resets dumpability to this kernel policy.
// Refuse policy 1 before dropping the setgid barrier: setting dumpable=0 only
// afterward would leave an attach window. This never changes host policy.
[[nodiscard]] inline bool safeGroupDropPolicy(std::string_view bytes) noexcept
{
    return bytes == "0\n" || bytes == "2\n";
}
[[nodiscard]] inline bool safeGroupDropPolicy() noexcept
{
    const int descriptor =
        open("/proc/sys/fs/suid_dumpable", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0)
        return false;
    std::array<char, 3> bytes{};
    const auto size = read(descriptor, bytes.data(), bytes.size());
    const bool closed = close(descriptor) == 0;
    return closed && size == 2 && safeGroupDropPolicy(std::string_view(bytes.data(), 2));
}

// The compositor uses its logind-owned devices and bounded mechanisms; it has
// no authority to retain PAM's ambient capabilities (normally CAP_WAKE_ALARM).
// Relinquish capabilities before config, plugins, devices or Wayland startup.
// First prohibit same-UID process inspection explicitly: clearing capabilities
// must not remove commoncap's incidental protection without a stronger barrier.
// The independent root guard attests the actual image. Do not impose NNP on
// child helpers: normal applications still need their qualified PAM/sudo paths.
[[nodiscard]] inline bool dropNativeProcessCapabilities() noexcept
{
    if (!singleNativeThread())
        return false;
    uid_t real = 0, effective = 0, saved = 0;
    if (getresuid(&real, &effective, &saved) != 0 || real == 0 || real != effective ||
        real != saved)
        return false;
    // The package's dedicated, otherwise unused setgid group exists only to
    // enter the secure loader. Discard it before config, plugins or devices;
    // ordinary applications inherit their original login group and no NNP.
    gid_t realGroup = 0, effectiveGroup = 0, savedGroup = 0;
    if (getresgid(&realGroup, &effectiveGroup, &savedGroup) != 0 || realGroup == 0 ||
        ((realGroup != effectiveGroup || realGroup != savedGroup) && !safeGroupDropPolicy()) ||
        setresgid(realGroup, realGroup, realGroup) != 0 ||
        getresgid(&realGroup, &effectiveGroup, &savedGroup) != 0 || realGroup != effectiveGroup ||
        realGroup != savedGroup)
        return false;
    if (prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) != 0 ||
        prctl(PR_GET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) != 0 ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0UL, 0UL, 0UL) != 0)
        return false;
    __user_cap_header_struct header{};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    std::array<__user_cap_data_struct, 2> empty{};
    if (syscall(SYS_capset, &header, empty.data()) != 0 ||
        syscall(SYS_capget, &header, empty.data()) != 0)
        return false;
    for (const auto &set : empty)
        if (set.effective != 0 || set.permitted != 0 || set.inheritable != 0)
            return false;
    return prctl(PR_GET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) == 0;
}
} // namespace Linura::HyprlandDisplay
