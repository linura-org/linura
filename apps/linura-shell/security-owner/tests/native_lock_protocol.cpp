#include "native_lock_protocol.h"
#include "native_managed_lock_backend.h"

#include <QCoreApplication>
#include <QMetaMethod>
#include <QMetaObject>
#include <QThread>

#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <sys/wait.h>
#include <unistd.h>

using namespace Linura::SecurityOwner;

// Compiled component fixture only. This is NOT a Quickshell/Wayland mock used as
// qualification evidence: it drives property/event order and denial boundaries
// without claiming compositor coverage, authenticated identity or PAM success.
class GuardedComponentLock : public NativeManagedLockBackend
{
  public:
    bool locked() const
    {
        return requestedSecure();
    }
    bool secure() const
    {
        return secureCoverage();
    }
    void setLocked(bool value)
    {
        (void)applyNative(value);
    }
    void seedExistingLock()
    {
        publishNativeState(true, false);
        ++writes;
    }
    bool applyNative(bool value) override
    {
        if (beforeEffect)
            beforeEffect();
        consumeNativeEffectGate(value);
        if (duplicateEffect)
            consumeNativeEffectGate(value);
        if ((value && rejectAcquisition) || (!value && delayRelease))
            return true;
        if (!value) {
            publishNativeState(true, false); // Coverage can change before acknowledgement.
        }
        publishNativeState(value, false);
        ++writes;
        return true;
    }
    void coverage(bool value)
    {
        publishNativeState(requestedSecure(), value);
    }
    void completeRelease()
    {
        publishNativeState(true, false);
        publishNativeState(false, false);
    }
    void errorCleanupRelease()
    {
        setLocked(false); // Must check the native gate BEFORE a wire release.
    }
    bool rejectAcquisition = false;
    bool delayRelease = false;
    bool duplicateEffect = false;
    std::function<void()> beforeEffect;
    unsigned writes = 0;
};

static_assert(!std::is_constructible_v<NativeLockProtocol, QObject &, NativeLockIdentity>);

class ShadowedLock final : public GuardedComponentLock
{
    Q_OBJECT
    Q_PROPERTY(bool secure READ shadow WRITE setShadow NOTIFY shadowChanged)
  public:
    bool shadow() const
    {
        return false;
    }
    void setShadow(bool) {}
  Q_SIGNALS:
    void shadowChanged();
};

namespace {
unsigned checks = 0;
void check(bool value)
{
    ++checks;
    if (!value)
        throw std::runtime_error("native lock component assertion failed");
}

NativeLockIdentity identity()
{
    const auto parsed = NativeLockIdentity::parse(
        QStringLiteral("session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:2:42:"
                       "98765432-1234-4567-89ab-0123456789ab:1"));
    check(parsed.has_value());
    return *parsed;
}

void transitionAndCommitFence()
{
    quint64 now = 100;
    GuardedComponentLock native;
    NativeLockProtocol binding(native, identity(), [&] { return now; });
    check(binding.bound());
    check(binding.inspect() == LockMechanism::State::Ready);
    for (int index = binding.metaObject()->methodOffset();
         index < binding.metaObject()->methodCount(); ++index) {
        const auto name = binding.metaObject()->method(index).name();
        check(name != "dispatch" && name != "commitVerifiedRelease" &&
              name != "independentlyVerifiedReleased" && name != "permitNativeEffect");
    }
    check(binding.metaObject()->indexOfProperty("locked") < 0);
    auto other = identity();
    ++other.generation;
    check(!binding.dispatch(other, true));
    check(!binding.dispatch(identity(), false));
    check(native.writes == 0);
    check(binding.dispatch(identity(), true));
    check(native.locked() && !native.secure());
    check(binding.inspect() == LockMechanism::State::Acquiring);
    check(!binding.dispatch(identity(), true));
    check(!binding.dispatch(identity(), false));
    native.coverage(true);
    check(binding.inspect() == LockMechanism::State::Secure);
    // Remaining secure beyond acquisition budget is valid, including suspend.
    now += NativeLockProtocol::AcquisitionMs + 1;
    check(binding.inspect() == LockMechanism::State::Secure);
    check(!binding.independentlyVerifiedReleased(identity()));
    check(!binding.commitVerifiedRelease(identity()));
    check(binding.dispatch(identity(), false));
    check(!native.locked() && !native.secure());
    check(binding.inspect() == LockMechanism::State::Releasing);
    check(!binding.dispatch(identity(), false));
    check(!binding.dispatch(identity(), true));
    check(!binding.commitVerifiedRelease(identity()));
    check(!binding.independentlyVerifiedReleased(other));
    check(binding.independentlyVerifiedReleased(identity()));
    check(binding.inspect() == LockMechanism::State::Released);
    check(binding.identity() == identity());
    check(!binding.dispatch(identity(), true));
    check(!binding.commitVerifiedRelease(other));
    check(binding.commitVerifiedRelease(identity()));
    check(binding.inspect() == LockMechanism::State::Ready);
    check(binding.identity().generation == 2);
    check(identity().wasRetiredBy(binding.identity()));
    check(!binding.identity().wasRetiredBy(identity()));
    check(!binding.identity().wasRetiredBy(binding.identity()));
    auto replaced = binding.identity();
    replaced.ownerInvocation = QStringLiteral("12345678-1234-4567-89ab-0123456789ab");
    replaced.resource.replace(identity().ownerInvocation, replaced.ownerInvocation);
    check(!identity().wasRetiredBy(replaced));
    replaced = binding.identity();
    replaced.session = QStringLiteral("c3");
    replaced.resource.replace(QStringLiteral(":2:42:"), QStringLiteral(":c3:42:"));
    check(!identity().wasRetiredBy(replaced));
    replaced = binding.identity();
    ++replaced.generation; // An inconsistent in-memory identity cannot retire.
    check(!identity().wasRetiredBy(replaced));
    check(!binding.dispatch(identity(), true));
    check(!binding.commitVerifiedRelease(identity()));
    const auto next = binding.identity();
    check(binding.dispatch(next, true));
    native.coverage(true);
    check(binding.dispatch(next, false));
    check(binding.independentlyVerifiedReleased(next));
    check(binding.commitVerifiedRelease(next));
}

void delayedNativeRelease()
{
    quint64 now = 100;
    GuardedComponentLock native;
    NativeLockProtocol binding(native, identity(), [&] { return now; });
    check(binding.dispatch(identity(), true));
    native.coverage(true);
    native.delayRelease = true;
    check(binding.dispatch(identity(), false));
    // Still-covered native state is not a new secure acknowledgement and is
    // not an independently verified release. The bounded transition continues.
    check(binding.inspect() == LockMechanism::State::Releasing);
    check(native.secure());
    check(!binding.independentlyVerifiedReleased(identity()));
    native.delayRelease = false;
    native.completeRelease();
    check(binding.independentlyVerifiedReleased(identity()));
    check(binding.commitVerifiedRelease(identity()));
}

void incompatibleBindings()
{
    GuardedComponentLock readonly;
    check(!readonly.metaObject()
               ->property(readonly.metaObject()->indexOfProperty("locked"))
               .isWritable());
    check(!readonly.metaObject()
               ->property(readonly.metaObject()->indexOfProperty("secure"))
               .isWritable());
    check(!readonly.setProperty("locked", true));
    check(!readonly.setProperty("secure", true));
    check(!readonly.requestedSecure() && !readonly.secureCoverage());
    check(!readonly.dispatchNative(true)); // No gate installed; no effect attempt.
    check(readonly.writes == 0);
    ShadowedLock shadow;
    NativeLockProtocol replaced(shadow, identity());
    check(!replaced.bound());
    check(shadow.writes == 0);
    GuardedComponentLock adopted;
    adopted.seedExistingLock();
    NativeLockProtocol existing(adopted, identity());
    check(!existing.bound());
    check(adopted.writes == 1);
    GuardedComponentLock invalidIdentity;
    auto malformed = identity();
    ++malformed.generation; // Disagrees with canonical resource.
    NativeLockProtocol invalid(invalidIdentity, malformed);
    check(!invalid.bound());
    GuardedComponentLock absentClock;
    NativeLockProtocol noClock(absentClock, identity(), NativeLockProtocol::Clock{});
    check(!noClock.bound());
    QThread foreignThread;
    GuardedComponentLock foreign;
    foreign.moveToThread(&foreignThread);
    NativeLockProtocol crossThread(foreign, identity());
    check(!crossThread.bound());
    GuardedComponentLock shared;
    NativeLockProtocol first(shared, identity());
    NativeLockProtocol replacement(shared, identity());
    check(first.bound() && !replacement.bound());
    check(!replacement.dispatch(identity(), true));
    check(shared.writes == 0);
}

void expectTerminal(const std::function<void()> &body)
{
    const pid_t child = fork();
    check(child >= 0);
    if (child == 0) {
        body();
        _exit(99);
    }
    int status = 0;
    check(waitpid(child, &status, 0) == child);
    check(WIFEXITED(status) && WEXITSTATUS(status) == NativeLockProtocol::NativeLockFaultExit);
}

void terminalFailures()
{
    expectTerminal([] {
        GuardedComponentLock native;
        NativeLockProtocol binding(native, identity());
        native.setLocked(true); // No prepared native dispatch.
    });
    expectTerminal([] {
        auto native = std::make_unique<GuardedComponentLock>();
        NativeLockProtocol binding(*native, identity());
        native.reset(); // No idle reload/rebinding/generation recycling either.
    });
    expectTerminal([] {
        GuardedComponentLock native;
        NativeLockProtocol binding(native, identity());
        check(binding.dispatch(identity(), true));
        native.coverage(true);
        native.coverage(false); // Lost coverage is never an authorized unlock.
    });
    expectTerminal([] {
        GuardedComponentLock native;
        NativeLockProtocol binding(native, identity());
        native.rejectAcquisition = true;
        (void)binding.dispatch(identity(), true);
    });
    expectTerminal([] {
        GuardedComponentLock native;
        NativeLockProtocol binding(native, identity());
        check(binding.dispatch(identity(), true));
        native.coverage(true);
        native.delayRelease = true;
        check(binding.dispatch(identity(), false));
        native.coverage(false);
        native.coverage(true); // Coverage cannot disappear and reappear in release.
    });
    expectTerminal([] {
        quint64 now = 100;
        GuardedComponentLock native;
        NativeLockProtocol binding(native, identity(), [&] { return now; });
        check(binding.dispatch(identity(), true));
        now += NativeLockProtocol::AcquisitionMs;
        (void)binding.inspect(); // Includes time spent suspended.
    });
    expectTerminal([] {
        quint64 now = 100;
        GuardedComponentLock native;
        NativeLockProtocol binding(native, identity(), [&] { return now; });
        check(binding.dispatch(identity(), true));
        native.coverage(true);
        native.delayRelease = true;
        check(binding.dispatch(identity(), false));
        now += NativeLockProtocol::ReleaseMs;
        (void)binding.inspect();
    });
    expectTerminal([] {
        quint64 now = 100;
        GuardedComponentLock native;
        NativeLockProtocol binding(native, identity(), [&] { return now; });
        --now;
        (void)binding.inspect();
    });
    expectTerminal([] {
        GuardedComponentLock native;
        NativeLockProtocol binding(native, identity(),
                                   [] { return std::numeric_limits<quint64>::max(); });
    });
    expectTerminal([] {
        unsigned calls = 0;
        GuardedComponentLock native;
        NativeLockProtocol binding(native, identity(), [&]() -> quint64 {
            if (++calls > 1)
                throw std::runtime_error("synthetic native clock failure");
            return 100;
        });
        (void)binding.inspect();
    });
    expectTerminal([] {
        GuardedComponentLock native;
        NativeLockProtocol binding(native, identity());
        check(binding.dispatch(identity(), true));
        native.coverage(true);
        // Active shutdown must not run QObject/Wayland destruction/unlock.
    });
    expectTerminal([] {
        GuardedComponentLock native;
        NativeLockProtocol binding(native, identity());
        check(binding.dispatch(identity(), true));
        native.coverage(true);
        native.errorCleanupRelease(); // Fail BEFORE unauthenticated release.
    });
    expectTerminal([] {
        quint64 now = 100;
        GuardedComponentLock native;
        NativeLockProtocol binding(native, identity(), [&] { return now; });
        native.beforeEffect = [&] { now += NativeLockProtocol::AcquisitionMs; };
        (void)binding.dispatch(identity(), true); // Expired while inside native setter.
    });
    expectTerminal([] {
        GuardedComponentLock native;
        auto binding = std::make_unique<NativeLockProtocol>(native, identity());
        binding.reset();
        native.setLocked(true); // Dead binding gate cannot retain a dangling owner.
    });
    expectTerminal([] {
        GuardedComponentLock native;
        NativeLockProtocol binding(native, identity());
        native.duplicateEffect = true;
        (void)binding.dispatch(identity(), true); // Each native frame is consumed once.
    });
}
} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    try {
        transitionAndCommitFence();
        delayedNativeRelease();
        incompatibleBindings();
        terminalFailures();
        std::cout << "native lock component checks passed: " << checks << '\n';
        return 0;
    } catch (const std::exception &) {
        std::cerr << "native lock component checks failed\n";
        return 1;
    }
}

#include "native_lock_protocol.moc"
