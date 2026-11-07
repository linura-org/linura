// Real Qt timer and deterministic native recovery seams. No compositor effect,
// Control process, QML engine or display server is used as a correctness oracle.
#include "native_display_watchdog.h"
#include <QCoreApplication>
#include <QEventLoop>
#include <cassert>
#include <stdexcept>

using namespace Linura::SecurityOwner;
namespace {
struct Fixture
{
    NativeLockIdentity lock = *NativeLockIdentity::parse(
        QStringLiteral("session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-"
                       "4222-8222-222222222222:1"));
    QString topology = QStringLiteral("display:topology:11111111-1111-4111-8111-111111111111:1000:"
                                      "c2:42:seat0:33333333-3333-4333-8333-333333333333:3");
    NativeDisplayRecoveryContext context;
    NativeDisplayIntent intent;
    std::optional<NativeDisplayClock> clock = NativeDisplayClock{1000, 2000};
    unsigned restores = 0;
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
        head.scaleMilli = 1000;
        head.scaleFloatBits = 0x3f800000U;
        context = {{3, {head}}, topology, lock, true};
        const auto prefix = QStringLiteral("LNDL:1;") + topology;
        intent = *NativeDisplayIntent::parse(
            QStringLiteral("LNDI:1;") + lock.resource + QLatin1Char(';') + prefix +
            QStringLiteral(";1:2:enabled:1920:1080:60000:1000:0:0:0:-;") + prefix +
            QStringLiteral(";1:2:enabled:1920:1080:60000:1000:0:100:0:-;"));
    }
    NativeDisplayAttempt arm() const
    {
        auto attempt =
            NativeDisplayAttempt::arm(intent, QStringLiteral("transaction:watchdog"),
                                      QString(64, QLatin1Char('a')), QString(64, QLatin1Char('b')),
                                      16000, 1000, 2000, context.snapshot, topology, lock, true);
        assert(attempt);
        return std::move(*attempt);
    }
    bool restore(const NativeDisplayLayout &layout, const NativeDisplaySnapshot &snapshot)
    {
        ++restores;
        assert(layout.encode() == intent.baseline.encode());
        assert(snapshot == context.snapshot);
        return true;
    }
    void apply(NativeDisplayAttempt &attempt) const
    {
        assert(attempt.beginApply(1001, 2001, context.snapshot, topology, lock, true));
    }
};
void pump()
{
    QEventLoop loop;
    QTimer::singleShot(180, &loop, &QEventLoop::quit);
    loop.exec();
}
} // namespace
int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    const auto nativeClock = NativeDisplayClock::sample();
    assert(nativeClock && nativeClock->unixMs > 0 && nativeClock->bootMs > 0);
    {
        Fixture f;
        auto attempt = f.arm();
        NativeDisplayWatchdog timer(
            attempt, [&] { return f.clock; }, [&] { return std::optional(f.context); },
            [&](const auto &layout, const auto &snapshot) { return f.restore(layout, snapshot); });
        assert(timer.start());
        assert(!timer.start());
        f.apply(attempt);
        assert(!timer.stopAfterVerification());
        // Suspend-inclusive expiry wins even when wall time has not expired.
        f.clock = NativeDisplayClock{1002, 17000};
        pump();
        assert(f.restores == 1 && attempt.state() == NativeDisplayAttempt::State::Restoring);
        timer.restoreNow();
        assert(f.restores == 1);
        assert(!timer.stopAfterVerification()); // ACK did not verify anything.
        assert(attempt.verifyRestored(f.intent.baseline, f.context.snapshot, f.topology, f.lock,
                                      true));
        assert(timer.stopAfterVerification());
    }
    for (const int failure : {0, 1, 2, 3}) {
        Fixture f;
        auto attempt = f.arm();
        NativeDisplayWatchdog timer(
            attempt, [&] { return f.clock; },
            [&]() -> std::optional<NativeDisplayRecoveryContext> {
                if (failure == 3)
                    throw std::runtime_error("fixed test probe failure");
                if (failure == 1)
                    return std::nullopt;
                return f.context;
            },
            [&](const auto &layout, const auto &snapshot) {
                const auto acknowledged = f.restore(layout, snapshot);
                return failure == 0 ? false : acknowledged;
            });
        assert(timer.start());
        f.apply(attempt);
        if (failure == 2)
            ++f.context.snapshot.generation;
        f.clock.reset(); // Unknown clock cannot silently extend confirmation.
        pump();
        assert(attempt.state() == NativeDisplayAttempt::State::RecoveryFailed && attempt.fenced());
        assert(f.restores == (failure == 0 ? 1U : 0U));
        timer.restoreNow();
        assert(f.restores == (failure == 0 ? 1U : 0U));
        assert(!timer.stopAfterVerification());
        if (failure == 0) {
            // A lost acknowledgement does not authorize retry. Fresh independent
            // baseline proof can still resolve the ambiguity without a write.
            assert(attempt.verifyRestored(f.intent.baseline, f.context.snapshot, f.topology, f.lock,
                                          true));
            assert(timer.stopAfterVerification());
            assert(f.restores == 1);
        }
    }
    {
        Fixture f;
        auto attempt = f.arm();
        {
            NativeDisplayWatchdog timer(
                attempt, [&] { return f.clock; }, [&] { return std::optional(f.context); },
                [&](const auto &layout, const auto &snapshot) {
                    return f.restore(layout, snapshot);
                });
            assert(timer.start());
            f.apply(attempt);
        } // Ordinary destruction compensates without any UI event loop.
        assert(f.restores == 1 && attempt.state() == NativeDisplayAttempt::State::Restoring);
    }
    {
        Fixture f;
        auto attempt = f.arm();
        NativeDisplayWatchdog timer(
            attempt, [&] { return f.clock; }, [&] { return std::optional(f.context); },
            [&](const auto &layout, const auto &snapshot) { return f.restore(layout, snapshot); });
        assert(timer.start());
        f.apply(attempt);
        auto desired = f.context.snapshot;
        desired.heads[0].x = 100;
        assert(attempt.confirm(QStringLiteral("transaction:watchdog"),
                               QString(64, QLatin1Char('b')), 1002, 2002, f.intent.desired, desired,
                               f.topology, f.lock, true));
        assert(timer.stopAfterVerification());
        f.clock = NativeDisplayClock{16000, 17000};
        pump();
        assert(f.restores == 0 && !attempt.fenced());
    }
}
