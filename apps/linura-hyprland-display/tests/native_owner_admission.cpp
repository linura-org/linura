#include "native_owner_admission.h"

#include <array>
#include <cassert>
#include <functional>

using namespace Linura::HyprlandDisplay;

int main()
{
    SupervisedDisplayOwner facts;
    facts.pid = facts.launchedPid = 42;
    facts.user = "1000";
    facts.fragment = "/usr/lib/systemd/system/linura-security-owner@.service";
    facts.active = "active";
    facts.substate = "running";
    facts.image = "/usr/lib/linura/linura-security-owner";
    facts.invocation[0] = 1;
    facts.startedRealtime = facts.startedMonotonic = 1;
    facts.noDropIns = facts.exactArguments = facts.runningLaunch = true;
    facts.immutableFragment = facts.immutableImage = true;
    assert(validateDisplayOwner(42, 1000, facts) == facts.invocation);
    assert(!validateDisplayOwner(0, 1000, facts));
    assert(!validateDisplayOwner(-1, 1000, facts));
    assert(!validateDisplayOwner(43, 1000, facts));
    assert(!validateDisplayOwner(42, 0, facts));
    assert(!validateDisplayOwner(42, 1001, facts));
    const std::array<std::function<void(SupervisedDisplayOwner &)>, 17> substitutions{
        [](auto &v) { v.pid = 43; },
        [](auto &v) { v.launchedPid = 43; },
        [](auto &v) { v.user = "root"; },
        [](auto &v) { v.fragment = "/run/systemd/system/linura-security-owner@.service"; },
        [](auto &v) { v.active = "activating"; },
        [](auto &v) { v.substate = "exited"; },
        [](auto &v) { v.image = "/home/user/linura-security-owner"; },
        [](auto &v) { v.invocation.fill(0); },
        [](auto &v) { v.startedRealtime = 0; },
        [](auto &v) { v.startedMonotonic = 0; },
        [](auto &v) { v.noDropIns = false; },
        [](auto &v) { v.exactArguments = false; },
        [](auto &v) { v.runningLaunch = false; },
        [](auto &v) { v.immutableFragment = false; },
        [](auto &v) { v.immutableImage = false; },
        [](auto &v) { v.user = "01000"; },
        [](auto &v) { v.image += " --display"; },
    };
    for (const auto &substitute : substitutions) {
        auto wrong = facts;
        substitute(wrong);
        assert(!validateDisplayOwner(42, 1000, wrong));
    }
}
