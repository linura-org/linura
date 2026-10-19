#include "process_guard.h"

#include <linux/capability.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <array>

namespace Linura::SecurityOwner {

ProcessProtection protectNativeProcess(quint32 sessionOwnerUid) noexcept
{
    uid_t realUid = 0, effectiveUid = 0, savedUid = 0;
    if (sessionOwnerUid == 0 || getresuid(&realUid, &effectiveUid, &savedUid) != 0 ||
        realUid != sessionOwnerUid || effectiveUid != sessionOwnerUid ||
        savedUid != sessionOwnerUid)
        return ProcessProtection::WrongIdentity;
    gid_t realGid = 0, effectiveGid = 0, savedGid = 0;
    if (getresgid(&realGid, &effectiveGid, &savedGid) != 0 || realGid == 0 ||
        realGid != effectiveGid || realGid != savedGid)
        return ProcessProtection::WrongIdentity;

    // Non-dumpability alone can be established after unprotected constructors
    // have already run. Only the kernel's exec-time marker proves that the
    // dynamic loader entered secure mode. Ambient or later-acquired privileges
    // must not masquerade as the packaged file-capability startup path.
    const int initialDumpability = prctl(PR_GET_DUMPABLE);
    if (getauxval(AT_SECURE) != 1 ||
        !ProcessGuardDetail::protectedExecDumpability(initialDumpability) ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 0)
        return ProcessProtection::UnprotectedStartup;

    // A normal systemd-coredump host commonly uses fs.suid_dumpable=2. The
    // kernel's privileged-exec state still denies unprivileged same-UID ptrace,
    // but make the stronger process-local state explicit before capability use,
    // memory locking, native input or Qt initialization. Never mutate a global
    // sysctl to make this service start.
    if (prctl(PR_SET_DUMPABLE, 0) != 0 || prctl(PR_GET_DUMPABLE) != 0)
        return ProcessProtection::NativeProtectionUnavailable;

    __user_cap_header_struct header{};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    std::array<__user_cap_data_struct, 2> capabilities{};
    if (syscall(SYS_capget, &header, capabilities.data()) != 0)
        return ProcessProtection::NativeProtectionUnavailable;

    constexpr unsigned long required = 1UL << CAP_IPC_LOCK;
    if (capabilities[0].permitted != required || capabilities[0].effective != required ||
        capabilities[0].inheritable != 0 || capabilities[1].permitted != 0 ||
        capabilities[1].effective != 0 || capabilities[1].inheritable != 0)
        return ProcessProtection::UnexpectedPrivilege;
    // Native input/authentication mechanisms also use temporary response data.
    // Protect the entire owner before input, not just our explicit
    // buffer. The supervised runtime must qualify bounded cgroup/memlock limits;
    // inability to establish residency disables the owner, never a heap fallback.
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
        return ProcessProtection::NativeProtectionUnavailable;

    capabilities = {};
    if (syscall(SYS_capset, &header, capabilities.data()) != 0 || prctl(PR_SET_DUMPABLE, 0) != 0 ||
        prctl(PR_GET_DUMPABLE) != 0)
        return ProcessProtection::NativeProtectionUnavailable;
    capabilities = {};
    if (syscall(SYS_capget, &header, capabilities.data()) != 0)
        return ProcessProtection::NativeProtectionUnavailable;
    for (const auto &set : capabilities) {
        if (set.permitted != 0 || set.effective != 0 || set.inheritable != 0)
            return ProcessProtection::UnexpectedPrivilege;
    }
    return ProcessProtection::Protected;
}

} // namespace Linura::SecurityOwner
