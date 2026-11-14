#include "native_owner_admission.h"

#include <algorithm>

namespace Linura::HyprlandDisplay {
std::optional<WireEndpoint::OwnerInvocation>
validateDisplayOwner(pid_t pid, uid_t uid, const SupervisedDisplayOwner &facts)
{
    if (pid <= 0 || uid == 0 || facts.pid != static_cast<std::uint32_t>(pid) ||
        facts.launchedPid != facts.pid || facts.user != std::to_string(uid) ||
        facts.fragment != "/usr/lib/systemd/system/linura-security-owner@.service" ||
        facts.active != "active" || facts.substate != "running" ||
        facts.image != "/usr/lib/linura/linura-security-owner" || facts.startedRealtime == 0 ||
        facts.startedMonotonic == 0 || !facts.noDropIns || !facts.exactArguments ||
        !facts.runningLaunch || !facts.immutableFragment || !facts.immutableImage ||
        std::all_of(facts.invocation.begin(), facts.invocation.end(),
                    [](unsigned char byte) { return byte == 0; }))
        return std::nullopt;
    return facts.invocation;
}

} // namespace Linura::HyprlandDisplay
