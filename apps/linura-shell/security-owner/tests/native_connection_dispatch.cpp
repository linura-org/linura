#include "native_connection_dispatch.h"

#include <QCoreApplication>

#include <cassert>
#include <utility>

using namespace Linura::SecurityOwner;

namespace Linura::SecurityOwner {
struct NativeConnectionDispatchTestAccess
{
    static NativeConnectionDispatchAttempt make(const NativeLockIdentity &lock,
                                                const NativePeerIdentity &manager,
                                                const NativeConnectionMethod &method)
    {
        return NativeConnectionDispatchAttempt(lock, manager, method);
    }

    static std::optional<NativeConnectionMethod> spend(NativeConnectionDispatchAttempt &attempt,
                                                       const NativeLockIdentity &lock,
                                                       const NativePeerIdentity &manager)
    {
        return attempt.spend(lock, manager);
    }
};
} // namespace Linura::SecurityOwner

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QString owner = QStringLiteral(":1.48");
    NativeConnectionActivationTarget target;
    target.owner = owner;
    target.profile = QStringLiteral("/org/freedesktop/NetworkManager/Settings/9");
    target.device = QStringLiteral("/org/freedesktop/NetworkManager/Devices/8");
    target.media = NativeConnectionMedia::Ethernet;
    target.accessPoint = QStringLiteral("/");
    const auto method = NativeConnectionMethod::activate(target);
    assert(method.has_value());
    const auto deactivate = NativeConnectionMethod::deactivate(
        owner, QStringLiteral("/org/freedesktop/NetworkManager/ActiveConnection/12"));
    assert(deactivate.has_value());

    NativeLockIdentity lock;
    lock.resource = QStringLiteral("original-control-resource");
    lock.boot = QStringLiteral("test-boot");
    lock.uid = 1000;
    lock.session = QStringLiteral("3");
    lock.createdMonotonicUs = 42;
    lock.ownerInvocation = QStringLiteral("test-session-invocation");
    lock.generation = 1;
    const NativePeerIdentity manager{owner, 0, 412, QStringLiteral("test-manager-invocation")};
    using Access = NativeConnectionDispatchTestAccess;

    auto once = Access::make(lock, manager, *method);
    assert(!once.spent());
    auto first = Access::spend(once, lock, manager);
    assert(first.has_value() && first->message().member() == QLatin1String("ActivateConnection"));
    assert(once.spent());
    assert(!Access::spend(once, lock, manager));

    auto movedFrom = Access::make(lock, manager, *deactivate);
    auto movedTo = std::move(movedFrom);
    assert(movedFrom.spent() && !movedTo.spent());
    assert(Access::spend(movedTo, lock, manager).has_value());
    assert(!Access::spend(movedFrom, lock, manager));
    assert(!Access::spend(movedTo, lock, manager));

    auto wrongUser = lock;
    wrongUser.uid++;
    auto userAttempt = Access::make(lock, manager, *method);
    assert(!Access::spend(userAttempt, wrongUser, manager) && userAttempt.spent());
    assert(!Access::spend(userAttempt, lock, manager));

    auto wrongOwner = manager;
    wrongOwner.uniqueOwner = QStringLiteral(":1.49");
    auto daemonAttempt = Access::make(lock, manager, *method);
    assert(!Access::spend(daemonAttempt, lock, wrongOwner) && daemonAttempt.spent());

    auto forgedOwner = Access::make(lock, wrongOwner, *method);
    assert(!Access::spend(forgedOwner, lock, wrongOwner) && forgedOwner.spent());

    auto missingInvocation = manager;
    missingInvocation.serviceInvocation.clear();
    auto unsupervised = Access::make(lock, missingInvocation, *method);
    assert(!Access::spend(unsupervised, lock, missingInvocation));
    assert(unsupervised.spent());

    auto root = lock;
    root.uid = 0;
    auto rootAttempt = Access::make(root, manager, *method);
    assert(!Access::spend(rootAttempt, root, manager));

    // These are pure no-I/O one-use tests. Real original-user / Polkit, lost
    // replies, recovery, independent routing/DNS and Q11 need native evidence.
    return 0;
}
