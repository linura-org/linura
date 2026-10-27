// Native transaction-gate fixtures; no native request or watchdog is activated.
#include "native_display_attempt.h"
#include <cassert>
#include <limits>
#include <type_traits>

using namespace Linura::SecurityOwner;
static_assert(!std::is_copy_constructible_v<NativeDisplayAttempt>);
static_assert(!std::is_copy_assignable_v<NativeDisplayAttempt>);
namespace {
struct Fixture
{
    NativeLockIdentity lock = *NativeLockIdentity::parse(
        QStringLiteral("session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-"
                       "4222-8222-222222222222:1"));
    QString topology = QStringLiteral("display:topology:11111111-1111-4111-8111-111111111111:1000:"
                                      "c2:42:seat0:33333333-3333-4333-8333-333333333333:3");
    QString transaction = QStringLiteral("transaction:display-fixture");
    QString effect = QString(64, QLatin1Char('a'));
    QString dispatch = QString(64, QLatin1Char('b'));
    NativeDisplaySnapshot baseline, desired;
    NativeDisplayIntent intent;
    Fixture()
    {
        NativeDisplayHead head;
        head.handle = 1;
        head.generation = 2;
        head.name = QStringLiteral("DP-1");
        head.enabled = true;
        head.covered = true;
        head.modes = {{1920, 1080, 60000}};
        head.current = head.modes[0];
        head.scaleFixed = 256;
        baseline.generation = 3;
        baseline.heads.push_back(head);
        desired = baseline;
        desired.heads[0].x = 100;
        const auto prefix = QStringLiteral("LNDL:1;") + topology;
        const auto a = prefix + QStringLiteral(";1:2:enabled:1920:1080:60000:1000:0:0:0:-;");
        const auto b = prefix + QStringLiteral(";1:2:enabled:1920:1080:60000:1000:0:100:0:-;");
        const auto parsed = NativeDisplayIntent::parse(QStringLiteral("LNDI:1;") + lock.resource +
                                                       QLatin1Char(';') + a + b);
        assert(parsed);
        intent = *parsed;
    }
    std::optional<NativeDisplayAttempt> arm(quint64 unixNow = 1000, quint64 bootNow = 2000,
                                            quint64 deadline = 16000, bool secure = true) const
    {
        return NativeDisplayAttempt::arm(intent, transaction, effect, dispatch, deadline, unixNow,
                                         bootNow, baseline, topology, lock, secure);
    }
    bool apply(NativeDisplayAttempt &attempt) const
    {
        return attempt.beginApply(1001, 2001, baseline, topology, lock, true);
    }
    bool confirm(NativeDisplayAttempt &attempt, quint64 unixNow = 1002,
                 quint64 bootNow = 2002) const
    {
        return attempt.confirm(transaction, dispatch, unixNow, bootNow, intent.desired, desired,
                               topology, lock, true);
    }
};
} // namespace
int main()
{
    const Fixture f;
    auto attempt = f.arm();
    assert(attempt && attempt->fenced());
    assert(f.apply(*attempt));
    assert(!f.apply(*attempt));
    assert(!attempt->confirm(f.transaction, QString(64, QLatin1Char('c')), 1002, 2002,
                             f.intent.desired, f.desired, f.topology, f.lock, true));
    assert(!attempt->confirm(f.transaction, f.dispatch, 1002, 2002, f.intent.baseline, f.baseline,
                             f.topology, f.lock, true));
    assert(f.confirm(*attempt));
    assert(!attempt->fenced());
    assert(!f.confirm(*attempt));
    assert(!attempt->beginRestore(f.desired, f.topology, f.lock, true));

    for (const auto times :
         {std::pair<quint64, quint64>{16000, 16999}, {15999, 17000}, {999, 2002}, {1002, 1999}}) {
        auto expired = f.arm();
        assert(expired && f.apply(*expired));
        assert(expired->recoveryDue(times.first, times.second));
        assert(!f.confirm(*expired, times.first, times.second));
        assert(expired->beginRestore(f.desired, f.topology, f.lock, true));
        assert(!expired->beginRestore(f.desired, f.topology, f.lock, true));
        assert(!expired->verifyRestored(f.intent.desired, f.desired, f.topology, f.lock, true));
        assert(expired->verifyRestored(f.intent.baseline, f.baseline, f.topology, f.lock, true));
        assert(!expired->fenced() && expired->state() == NativeDisplayAttempt::State::Restored);
        assert(!f.confirm(*expired));
    }
    for (int fault = 0; fault < 5; ++fault) {
        auto changed = f.desired;
        auto lock = f.lock;
        bool secure = true;
        if (fault == 0)
            ++changed.heads[0].generation;
        if (fault == 1)
            ++changed.generation;
        if (fault == 2)
            ++lock.generation;
        if (fault == 3)
            secure = false;
        if (fault == 4)
            changed.heads[0].covered = false;
        auto fenced = f.arm();
        assert(fenced && f.apply(*fenced));
        assert(!fenced->confirm(f.transaction, f.dispatch, 1002, 2002, f.intent.desired, changed,
                                f.topology, lock, secure));
        assert(!fenced->beginRestore(changed, f.topology, lock, secure));
        assert(fenced->state() == NativeDisplayAttempt::State::RecoveryFailed && fenced->fenced());
        assert(!fenced->beginRestore(f.desired, f.topology, f.lock, true));
    }
    assert(!f.arm(0));
    assert(!f.arm(1000, 0));
    assert(!f.arm(1000, 2000, 1000));
    assert(!f.arm(1000, 2000, 16001));
    assert(!f.arm(1000, std::numeric_limits<quint64>::max(), 1001));
    for (const auto &bad :
         {QString{}, QString(64, QLatin1Char('0')), QString(64, QLatin1Char('A'))}) {
        assert(!NativeDisplayAttempt::arm(f.intent, f.transaction, bad, f.dispatch, 16000, 1000,
                                          2000, f.baseline, f.topology, f.lock, true));
    }
    auto unavailable = f.baseline;
    unavailable.heads[0].covered = false;
    assert(!NativeDisplayAttempt::arm(f.intent, f.transaction, f.effect, f.dispatch, 16000, 1000,
                                      2000, unavailable, f.topology, f.lock, true));
    auto protectedLater = f.arm(1000, 2000, 16000, false);
    assert(protectedLater && f.apply(*protectedLater) && f.confirm(*protectedLater));
}
