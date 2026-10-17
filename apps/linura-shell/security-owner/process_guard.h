#pragma once

#include <QtGlobal>

namespace Linura::SecurityOwner {

enum class ProcessProtection {
    Protected,
    WrongIdentity,
    UnprotectedStartup,
    UnexpectedPrivilege,
    NativeProtectionUnavailable,
};

namespace ProcessGuardDetail {

// Linux reports privileged-exec dumpability as either disabled (0) or
// root-only/safe-path (2), depending on fs.suid_dumpable. Both deny an
// unprivileged same-UID process ptrace access. User-dumpable (1), errors and
// future/unknown values are never protected startup states.
[[nodiscard]] constexpr bool protectedExecDumpability(int value) noexcept
{
    return value == 0 || value == 2;
}

} // namespace ProcessGuardDetail

// The root-controlled private runtime must enter through a secure-exec image
// with only CAP_IPC_LOCK and no saved-user/group identity escape. AT_SECURE must be
// kernel-established at exec; setting non-dumpability after ordinary exec is
// insufficient. Linux must enter a protected dumpability state that denies
// same-UID ptrace, and the owner immediately forces and verifies state zero.
// Drop that single memory-lock capability before accepting input/loading UI;
// keep the official Polkit helper's separate protected authentication path.
[[nodiscard]] ProcessProtection protectNativeProcess(quint32 sessionOwnerUid) noexcept;

} // namespace Linura::SecurityOwner
