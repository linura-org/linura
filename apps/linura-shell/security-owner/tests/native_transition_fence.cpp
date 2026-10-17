#include "native_transition_fence.h"
#include <cassert>
#include <limits>

using namespace Linura::SecurityOwner;

int main()
{
    assert(decodeNativeSuspendCycles("[none]\n", "0\n") == 0);
    assert(decodeNativeSuspendCycles("[none] core processors platform devices freezer \n",
                                     "42\n") == 42);
    assert(decodeNativeSuspendCycles("[none]\n", "18446744073709551615\n") ==
           std::numeric_limits<quint64>::max());
    for (std::string_view mode :
         {"", "[none]", "none\n", "none [devices]\n", "[none] [core]\n", "[none] [none]\n",
          "[none] core core\n", "[none] unknown\n", "[none]\ncore\n", "[none] freezer\r\n"})
        assert(!decodeNativeSuspendCycles(mode, "42\n"));
    for (std::string_view counter : {"", "42", "01\n", "-1\n", "+1\n", " 1\n", "1 \n", "1\n2\n",
                                     "18446744073709551616\n", "184467440737095516150\n", "NaN\n"})
        assert(!decodeNativeSuspendCycles("[none]\n", counter));
    assert(!decodeNativeSuspendCycles(std::string_view("[none]\0\n", 8), "42\n"));
    assert(!decodeNativeSuspendCycles("[none]\n", std::string_view("4\0\n", 3)));
    const auto parsed = NativeTransitionIdentity::parse(
        QStringLiteral("session:transition:suspend:10:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:"
                       "42:98765432-1234-4567-89ab-0123456789ab:7"));
    assert(parsed);
    const auto target = *parsed;
    NativeTransitionFence fence;
    auto wrong = target.lock;
    ++wrong.generation;
    assert(!fence.arm(target, wrong, true, 10));
    assert(!fence.arm(target, target.lock, false, 10));
    assert(!fence.arm(target, target.lock, true, std::nullopt));
    assert(!fence.arm(target, target.lock, true, 9));
    assert(!fence.arm(target, target.lock, true, 11));
    assert(!fence.active());
    assert(fence.arm(target, target.lock, true, 10));
    assert(fence.active());
    assert(!fence.arm(target, target.lock, true, 10));
    assert(!fence.commitSuspend(target, target.lock, true, 10));
    assert(!fence.commitSuspend(target, target.lock, true, 12));
    assert(!fence.commitSuspend(target, target.lock, false, 11));
    assert(!fence.commitSuspend(target, wrong, true, 11));
    assert(fence.active());
    assert(fence.commitSuspend(target, target.lock, true, 11));
    assert(!fence.active());
    assert(fence.commitSuspend(target, target.lock, true, 11));
    assert(!fence.arm(target, target.lock, true, 10));
    auto next = NativeTransitionIdentity::parse(
        QString(target.resource)
            .replace(QStringLiteral("suspend:10:"), QStringLiteral("suspend:11:")));
    assert(next && fence.arm(*next, next->lock, true, 11));
    assert(fence.commitSuspend(target, target.lock, true, 11));
    assert(fence.active()); // Old acknowledgement cannot retire the next fence.
    assert(!fence.cancelUndispatched(target));
    assert(fence.cancelUndispatched(*next));
    assert(!fence.active());
    for (const auto *action : {"logout", "reboot", "power-off"}) {
        const auto terminating = NativeTransitionIdentity::parse(
            QStringLiteral("session:transition:%1:0:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:"
                           "42:98765432-1234-4567-89ab-0123456789ab:7")
                .arg(QLatin1String(action)));
        assert(terminating && fence.arm(*terminating, terminating->lock, true, std::nullopt));
        assert(!fence.commitSuspend(*terminating, terminating->lock, true, 11));
        assert(fence.active());
        assert(fence.cancelUndispatched(*terminating));
    }
}
