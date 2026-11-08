#pragma once

#include "wire_endpoint.h"

#include <cstdint>
#include <string>

namespace Linura::HyprlandDisplay {

// Private decoded root-systemd evidence. None of these fields are accepted
// from a Wayland client, environment, public SDK or native display request.
struct SupervisedDisplayOwner final
{
    std::uint32_t pid = 0, launchedPid = 0;
    std::string user, fragment, active, substate, image;
    WireEndpoint::OwnerInvocation invocation{};
    std::uint64_t startedRealtime = 0, startedMonotonic = 0;
    bool noDropIns = false, exactArguments = false, runningLaunch = false;
    bool immutableFragment = false, immutableImage = false;
};

[[nodiscard]] std::optional<WireEndpoint::OwnerInvocation>
validateDisplayOwner(pid_t, uid_t, const SupervisedDisplayOwner &);

// One bounded probe of the fixed kernel-root-peer system bus and root unique
// systemd owner. No activation, user bus, process launch or POSIX SID heuristic.
[[nodiscard]] std::optional<WireEndpoint::OwnerInvocation> attestDisplayOwner(pid_t,
                                                                              uid_t) noexcept;

} // namespace Linura::HyprlandDisplay
