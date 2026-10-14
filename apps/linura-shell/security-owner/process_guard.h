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

// The root-controlled private runtime must enter through a secure-exec image
// with only CAP_IPC_LOCK and no saved-user/group identity escape. AT_SECURE must be
// kernel-established at exec; setting non-dumpability later is insufficient.
// Linux suppresses same-UID ptrace/core access from exec,
// closing the startup gap before native constructors can call PR_SET_DUMPABLE.
// Drop that single memory-lock capability before accepting input/loading UI;
// keep the official Polkit helper's separate protected authentication path.
[[nodiscard]] ProcessProtection protectNativeProcess(quint32 sessionOwnerUid) noexcept;

} // namespace Linura::SecurityOwner
