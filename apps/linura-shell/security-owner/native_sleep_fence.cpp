#include "native_sleep_fence.h"

#include <QUuid>
#include <limits>

namespace Linura::SecurityOwner {
namespace {
bool canonicalUuid(const QString &text)
{
    const QUuid value(text);
    return text.size() == 36 && !value.isNull() && value.toString(QUuid::WithoutBraces) == text;
}

bool command(const NativeLaunchFacts &facts, bool helper)
{
    const auto image = helper ? QStringLiteral("/usr/lib/linura/linura-executor-session")
                              : QStringLiteral("/usr/lib/systemd/systemd-sleep");
    const auto argument =
        helper ? QStringLiteral("--protect-before-sleep") : QStringLiteral("suspend");
    return facts.image == image && facts.arguments == QStringList{image, argument} &&
           !facts.ignoreFailure;
}

bool neverStarted(const NativeLaunchFacts &facts)
{
    return facts.startedReal == 0 && facts.startedMonotonic == 0 && facts.exitedReal == 0 &&
           facts.exitedMonotonic == 0 && facts.pid == 0 && facts.code == 0 && facts.status == 0;
}

bool ended(const NativeLaunchFacts &facts)
{
    return facts.pid > 1 && facts.startedReal > 0 && facts.startedMonotonic > 0 &&
           facts.exitedReal > 0 && facts.exitedMonotonic >= facts.startedMonotonic &&
           facts.code >= 1 && facts.code <= 3 && facts.status >= 0 && facts.status <= 255;
}
} // namespace

std::optional<NativeSleepEntryIdentity> NativeSleepEntryIdentity::parse(const QString &resource)
{
    if (resource.size() > 96)
        return std::nullopt;
    const auto fields = resource.split(QLatin1Char(':'));
    if (fields.size() != 4 || fields[0] != QLatin1String("session") ||
        fields[1] != QLatin1String("sleep-entry") || !canonicalUuid(fields[2]) ||
        !canonicalUuid(fields[3]))
        return std::nullopt;
    return NativeSleepEntryIdentity{resource, fields[2], fields[3]};
}

bool NativeSleepFence::arm(const NativeSleepEntryIdentity &event, const NativeLockIdentity &current,
                           bool independentlySecure, std::optional<quint64> cycles,
                           const NativeSleepUnitFacts &facts)
{
    if (NativeSleepEntryIdentity::parse(event.resource) != event ||
        NativeLockIdentity::parse(current.resource) != current || event.boot != current.boot ||
        !independentlySecure || !cycles || *cycles == std::numeric_limits<quint64>::max() ||
        facts.absent || !facts.supervisor.startsWith(QLatin1Char(':')) ||
        facts.supervisor.size() > 128 || facts.invocation != event.invocation ||
        facts.activeState != QLatin1String("activating") ||
        facts.subState != QLatin1String("start-pre") || facts.controlPid <= 1 ||
        facts.mainPid != 0 || facts.job == 0 || !command(facts.helper, true) ||
        !exactNativeLaunch(facts.helper, facts.helper.image, facts.helper.arguments,
                           facts.controlPid) ||
        !command(facts.main, false) || !neverStarted(facts.main))
        return false;
    if (pending_) {
        // A lost arm reply may be re-observed, but cannot replace or widen the
        // original job/lock/counter/launch identity.
        return pending_->event == event && pending_->lock == current &&
               pending_->cycles == *cycles && pending_->supervisor == facts.supervisor &&
               pending_->helperPid == facts.helper.pid && pending_->job == facts.job &&
               pending_->helperStartedReal == facts.helper.startedReal &&
               pending_->helperStartedMonotonic == facts.helper.startedMonotonic;
    }
    pending_ = Pending{event,
                       current,
                       *cycles,
                       facts.supervisor,
                       facts.helper.pid,
                       facts.job,
                       facts.helper.startedReal,
                       facts.helper.startedMonotonic};
    return true;
}

bool NativeSleepFence::retire(const NativeLockIdentity &current, bool independentlySecure,
                              std::optional<quint64> cycles, const NativeSleepUnitFacts &facts)
{
    if (!pending_ || current != pending_->lock || !independentlySecure || !cycles ||
        (*cycles != pending_->cycles && *cycles != pending_->cycles + 1) ||
        facts.supervisor != pending_->supervisor)
        return false;
    if (facts.absent) {
        if (facts.controlPid != 0 || facts.mainPid != 0 || facts.job != 0 ||
            !facts.invocation.isEmpty() || !facts.activeState.isEmpty() ||
            !facts.subState.isEmpty() || facts.helper != NativeLaunchFacts{} ||
            facts.main != NativeLaunchFacts{})
            return false;
        pending_.reset();
        return true; // Fresh native absence, not missing/failed observation.
    }
    if ((facts.invocation != pending_->event.invocation &&
         facts.invocation != QLatin1String("00000000-0000-0000-0000-000000000000")) ||
        !((facts.activeState == QLatin1String("inactive") &&
           facts.subState == QLatin1String("dead")) ||
          (facts.activeState == QLatin1String("failed") &&
           facts.subState == QLatin1String("failed"))) ||
        facts.job != 0 || facts.controlPid != 0 || facts.mainPid != 0 ||
        !command(facts.helper, true) || !command(facts.main, false) || !ended(facts.helper) ||
        facts.helper.pid != pending_->helperPid ||
        facts.helper.startedReal != pending_->helperStartedReal ||
        facts.helper.startedMonotonic != pending_->helperStartedMonotonic ||
        (!neverStarted(facts.main) && !ended(facts.main)) ||
        (*cycles == pending_->cycles + 1 && neverStarted(facts.main)))
        return false;
    pending_.reset();
    return true; // The session remains securely locked; never an unlock effect.
}
} // namespace Linura::SecurityOwner
