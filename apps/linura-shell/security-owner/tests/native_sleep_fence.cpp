#include "native_sleep_fence.h"
#include "native_transition_fence.h"

#include <cassert>
#include <functional>
#include <limits>

using namespace Linura::SecurityOwner;

int main()
{
    const auto event = NativeSleepEntryIdentity::parse(
        QStringLiteral("session:sleep-entry:abcd1234-1234-4567-89ab-0123456789ab:"
                       "98765432-1234-4567-89ab-0123456789ab"));
    const auto lock = NativeLockIdentity::parse(
        QStringLiteral("session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:"
                       "98765432-1234-4567-89ab-0123456789ab:7"));
    assert(event && lock);
    for (const auto &bad :
         {event->resource + QLatin1Char(':'), event->resource.toUpper(),
          QString(event->resource).replace(QStringLiteral("sleep-entry"), QStringLiteral("sleep")),
          QString(event->resource)
              .replace(event->invocation, QStringLiteral("00000000-0000-0000-0000-000000000000"))})
        assert(!NativeSleepEntryIdentity::parse(bad));
    const QString helper = QStringLiteral("/usr/lib/linura/linura-executor-session");
    const QString main = QStringLiteral("/usr/lib/systemd/systemd-sleep");
    const NativeSleepUnitFacts starting{
        QStringLiteral(":1.2"),
        event->invocation,
        QStringLiteral("activating"),
        QStringLiteral("start-pre"),
        42,
        0,
        9,
        {helper,
         {helper, QStringLiteral("--protect-before-sleep")},
         false,
         100,
         200,
         0,
         0,
         42,
         0,
         0},
        {main, {main, QStringLiteral("suspend")}, false, 0, 0, 0, 0, 0, 0, 0}};
    NativeSleepFence fence;
    assert(!fence.baselineCycles());
    assert(!fence.arm(*event, *lock, false, 10, starting));
    assert(!fence.arm(*event, *lock, true, std::nullopt, starting));
    assert(!fence.arm(*event, *lock, true, std::numeric_limits<quint64>::max(), starting));
    auto fakeEvent = *event;
    fakeEvent.invocation = lock->boot;
    assert(!fence.arm(fakeEvent, *lock, true, 10, starting));
    auto wrongBoot = *event;
    wrongBoot.resource.replace(wrongBoot.boot,
                               QStringLiteral("abcd1234-1234-4567-89ab-0123456789ac"));
    wrongBoot = *NativeSleepEntryIdentity::parse(wrongBoot.resource);
    assert(!fence.arm(wrongBoot, *lock, true, 10, starting));
    using Change = std::function<void(NativeSleepUnitFacts &)>;
    for (const Change &change : std::initializer_list<Change>{
             [](auto &v) { v.invocation = QStringLiteral("abcd1234-1234-4567-89ab-0123456789ac"); },
             [](auto &v) { v.supervisor.clear(); },
             [](auto &v) { v.activeState = QStringLiteral("active"); },
             [](auto &v) { v.subState = QStringLiteral("start"); },
             [](auto &v) { v.controlPid = 0; }, [](auto &v) { v.mainPid = 43; },
             [](auto &v) { v.job = 0; }, [](auto &v) { v.helper.ignoreFailure = true; },
             [](auto &v) { v.absent = true; },
             [](auto &v) { v.helper.arguments.append(QStringLiteral("extra")); },
             [](auto &v) { v.helper.pid = 43; }, [](auto &v) { v.helper.exitedReal = 101; },
             [](auto &v) { v.helper.startedMonotonic = 0; },
             [](auto &v) { v.main.startedMonotonic = 201; },
             [](auto &v) { v.main.arguments[1] = QStringLiteral("hibernate"); }}) {
        auto changed = starting;
        change(changed);
        assert(!fence.arm(*event, *lock, true, 10, changed));
        assert(!fence.active());
    }
    assert(fence.arm(*event, *lock, true, 10, starting));
    assert(fence.baselineCycles() == 10);
    assert(fence.arm(*event, *lock, true, 10, starting)); // Lost arm reply, same scope only.
    auto replacedJob = starting;
    ++replacedJob.job;
    assert(!fence.arm(*event, *lock, true, 10, replacedJob));
    assert(fence.active());
    assert(fence.baselineCycles() == 10);
    assert(fence.arm(*event, *lock, true, 10, starting)); // Refusal cannot replace the original.
    assert(!fence.arm(*event, *lock, true, 11, starting));
    auto replaced = starting;
    ++replaced.helper.startedMonotonic;
    assert(!fence.arm(*event, *lock, true, 10, replaced));
    assert(!fence.retire(*lock, true, 11, starting)); // Unrelated suspend, old job still queued.
    assert(fence.active());
    auto completed = starting;
    completed.activeState = QStringLiteral("inactive");
    completed.subState = QStringLiteral("dead");
    completed.controlPid = completed.job = 0;
    completed.helper.exitedReal = 102;
    completed.helper.exitedMonotonic = 202;
    completed.helper.code = 1;
    completed.main.startedReal = 103;
    completed.main.startedMonotonic = 203;
    completed.main.exitedReal = 104;
    completed.main.exitedMonotonic = 204;
    completed.main.pid = 43;
    completed.main.code = 1;
    for (const Change &change : std::initializer_list<Change>{
             [](auto &v) { v.supervisor = QStringLiteral(":1.3"); },
             [](auto &v) { v.invocation = QStringLiteral("abcd1234-1234-4567-89ab-0123456789ac"); },
             [](auto &v) { v.activeState = QStringLiteral("deactivating"); },
             [](auto &v) { v.subState = QStringLiteral("stop-post"); },
             [](auto &v) { v.controlPid = 42; }, [](auto &v) { v.mainPid = 43; },
             [](auto &v) { v.job = 9; }, [](auto &v) { ++v.helper.pid; },
             [](auto &v) { ++v.helper.startedReal; }, [](auto &v) { ++v.helper.startedMonotonic; },
             [](auto &v) { v.helper.exitedMonotonic = 199; },
             [](auto &v) { v.helper.exitedReal = 0; }, [](auto &v) { v.main.exitedMonotonic = 0; },
             [](auto &v) { v.main.ignoreFailure = true; }}) {
        auto changed = completed;
        change(changed);
        assert(!fence.retire(*lock, true, 11, changed));
        assert(fence.active());
    }
    assert(!fence.retire(*lock, false, 11, completed));
    assert(!fence.retire(*lock, true, std::nullopt, completed));
    assert(!fence.retire(*lock, true, 9, completed));
    assert(!fence.retire(*lock, true, 12, completed));
    auto otherGeneration = *NativeLockIdentity::parse(
        QString(lock->resource).replace(QStringLiteral(":7"), QStringLiteral(":8")));
    assert(!fence.retire(otherGeneration, true, 11, completed));
    assert(fence.retire(*lock, true, 11, completed));
    assert(!fence.baselineCycles());
    assert(!fence.active());
    assert(!fence.retire(*lock, true, 11, completed));
    assert(fence.arm(*event, *lock, true, 10, starting));
    auto failed = completed;
    failed.activeState = failed.subState = QStringLiteral("failed");
    failed.invocation = QStringLiteral("00000000-0000-0000-0000-000000000000");
    failed.helper.status = 1;
    failed.main = starting.main;
    assert(!fence.retire(*lock, true, 11, failed)); // Counter cannot invent main execution.
    assert(fence.retire(*lock, true, 10, failed));  // Definite failure before kernel entry.
    assert(!fence.active());

    assert(fence.arm(*event, *lock, true, 10, starting));
    NativeSleepUnitFacts collected;
    collected.supervisor = starting.supervisor;
    collected.absent = true;
    auto malformedAbsence = collected;
    malformedAbsence.job = 9;
    assert(!fence.retire(*lock, true, 11, malformedAbsence));
    malformedAbsence = collected;
    malformedAbsence.helper = starting.helper;
    assert(!fence.retire(*lock, true, 11, malformedAbsence));
    malformedAbsence = collected;
    malformedAbsence.supervisor = QStringLiteral(":1.3");
    assert(!fence.retire(*lock, true, 11, malformedAbsence));
    assert(!fence.retire(*lock, true, std::nullopt, collected));
    assert(fence.retire(*lock, true, 11, collected));
    assert(!fence.active());

    const auto managed = NativeTransitionIdentity::parse(QStringLiteral(
        "session:transition:suspend:10:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:"
        "98765432-1234-4567-89ab-0123456789ab:7"));
    assert(managed);
    NativeTransitionFence transition;
    assert(!transition.coversSuspend(*lock, 10));
    assert(transition.arm(*managed, *lock, true, 10));
    assert(transition.coversSuspend(*lock, 10));
    assert(!transition.coversSuspend(*lock, 11));
    assert(!transition.coversSuspend(otherGeneration, 10));
}
