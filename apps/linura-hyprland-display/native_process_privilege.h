#pragma once

#include <array>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace Linura::HyprlandDisplay {

// The compositor uses its logind-owned devices and bounded mechanisms; it has
// no authority to retain PAM's ambient capabilities (normally CAP_WAKE_ALARM).
// Relinquish capabilities before config, plugins, devices or Wayland startup.
// First prohibit same-UID process inspection explicitly: clearing capabilities
// must not remove commoncap's incidental protection without a stronger barrier.
// The independent root guard attests the actual image. Do not impose NNP on
// child helpers: normal applications still need their qualified PAM/sudo paths.
[[nodiscard]] inline bool dropNativeProcessCapabilities() noexcept
{
    uid_t real = 0, effective = 0, saved = 0;
    if (getresuid(&real, &effective, &saved) != 0 || real == 0 || real != effective ||
        real != saved)
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
