#include "native_radio_dispatch.h"

#include <QCoreApplication>
#include <QDBusVariant>
#include <QString>

#include <cassert>
#include <utility>

namespace Linura::SecurityOwner {
struct NativeRadioDispatchTestAccess final
{
    static NativeRadioDispatchAttempt issue(const NativeLockIdentity &lock,
                                            const NativePeerIdentity &manager,
                                            NativeRadioMutation mutation, bool enabled)
    {
        const QString operation = mutation == NativeRadioMutation::NetworkingEnabled
                                      ? QStringLiteral("networking-")
                                      : QStringLiteral("wifi-");
        const QString verb = enabled ? QStringLiteral("enable-") : QStringLiteral("disable-");
        const QString request = QStringLiteral("request:v010:network-radio:") + operation + verb +
                                QStringLiteral("unit-test");
        const NativeApprovalScope consent{lock,
                                          QStringLiteral("unix:uid:%1").arg(lock.uid),
                                          request,
                                          request,
                                          QStringLiteral("sha256:") + QString(64, QLatin1Char('1')),
                                          QStringLiteral("sha256:") + QString(64, QLatin1Char('2')),
                                          QStringLiteral("sha256:") + QString(64, QLatin1Char('3')),
                                          ApprovalPurpose::AuthenticateNetworkRadio};
        return NativeRadioDispatchAttempt(consent, lock, manager, mutation, enabled);
    }
    static NativeRadioDispatchAttempt issueWithConsent(const NativeApprovalScope &consent,
                                                       const NativeLockIdentity &lock,
                                                       const NativePeerIdentity &manager,
                                                       NativeRadioMutation mutation, bool enabled)
    {
        return NativeRadioDispatchAttempt(consent, lock, manager, mutation, enabled);
    }
    static std::optional<NativeRadioMethod> spend(NativeRadioDispatchAttempt &ticket,
                                                  const NativeLockIdentity &lock,
                                                  const NativePeerIdentity &manager)
    {
        return ticket.spend(lock, manager);
    }
};
} // namespace Linura::SecurityOwner

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    using namespace Linura::SecurityOwner;
    const auto lock = NativeLockIdentity::parse(
        QStringLiteral("session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:2:42:"
                       "98765432-1234-4567-89ab-0123456789ab:1"));
    assert(lock);
    const NativePeerIdentity manager{QStringLiteral(":1.48"), 0, 900,
                                     QStringLiteral("98765432-1234-4567-89ab-0123456789ab")};

    const QString networking =
        QStringLiteral("org.freedesktop.NetworkManager.enable-disable-network");
    const QString wifi = QStringLiteral("org.freedesktop.NetworkManager.enable-disable-wifi");
    QMap<QString, QString> permissions{{networking, QStringLiteral("yes")},
                                       {wifi, QStringLiteral("no")}};
    assert(nativeRadioPermissionGranted(permissions, NativeRadioMutation::NetworkingEnabled));
    assert(!nativeRadioPermissionGranted(permissions, NativeRadioMutation::WirelessEnabled));
    permissions[wifi] = QStringLiteral("auth");
    assert(!nativeRadioPermissionGranted(permissions, NativeRadioMutation::WirelessEnabled));
    permissions[wifi] = QStringLiteral("yes");
    assert(nativeRadioPermissionGranted(permissions, NativeRadioMutation::WirelessEnabled));
    permissions[wifi] = QStringLiteral("YES");
    assert(!nativeRadioPermissionGranted(permissions, NativeRadioMutation::WirelessEnabled));
    permissions.remove(wifi);
    assert(!nativeRadioPermissionGranted(permissions, NativeRadioMutation::WirelessEnabled));
    permissions.insert(QStringLiteral("unknown"), QString(161, QLatin1Char('x')));
    assert(!nativeRadioPermissionGranted(permissions, NativeRadioMutation::NetworkingEnabled));
    assert(!nativeRadioPermissionGranted(permissions, static_cast<NativeRadioMutation>(255)));

    for (const auto mutation :
         {NativeRadioMutation::NetworkingEnabled, NativeRadioMutation::WirelessEnabled}) {
        for (const bool enabled : {false, true}) {
            auto attempt = NativeRadioDispatchTestAccess::issue(*lock, manager, mutation, enabled);
            assert(!attempt.spent());
            const auto call = NativeRadioDispatchTestAccess::spend(attempt, *lock, manager);
            assert(call && attempt.spent());
            assert(call->mutation() == mutation && call->enabled() == enabled);
            assert(!NativeRadioDispatchTestAccess::spend(attempt, *lock, manager));
            const auto message = call->message();
            assert(message.service() == manager.uniqueOwner && !message.autoStartService());
            assert(message.path() == QLatin1String("/org/freedesktop/NetworkManager"));
        }
    }

    const auto positive = NativeRadioDispatchTestAccess::issue(
        *lock, manager, NativeRadioMutation::WirelessEnabled, false);
    assert(!positive.spent());
    const auto reviewForWifiDisable = [&] {
        const QString request = QStringLiteral("request:v010:network-radio:wifi-disable-unit-test");
        return NativeApprovalScope{*lock,
                                   QStringLiteral("unix:uid:1000"),
                                   request,
                                   request,
                                   QStringLiteral("sha256:") + QString(64, QLatin1Char('1')),
                                   QStringLiteral("sha256:") + QString(64, QLatin1Char('2')),
                                   QStringLiteral("sha256:") + QString(64, QLatin1Char('3')),
                                   ApprovalPurpose::AuthenticateNetworkRadio};
    }();
    assert(nativeRadioConsentMatches(reviewForWifiDisable, *lock,
                                     NativeRadioMutation::WirelessEnabled, false));
    assert(!nativeRadioConsentMatches(reviewForWifiDisable, *lock,
                                      NativeRadioMutation::NetworkingEnabled, false));
    assert(!nativeRadioConsentMatches(reviewForWifiDisable, *lock,
                                      NativeRadioMutation::WirelessEnabled, true));
    auto wrongPurpose = reviewForWifiDisable;
    wrongPurpose.purpose = ApprovalPurpose::AuthenticateNetworkCredential;
    assert(!nativeRadioConsentMatches(wrongPurpose, *lock, NativeRadioMutation::WirelessEnabled,
                                      false));
    auto substituted = reviewForWifiDisable;
    substituted.plan = QStringLiteral("request:v010:network-radio:wifi-enable-unit-test");
    assert(!nativeRadioConsentMatches(substituted, *lock, NativeRadioMutation::WirelessEnabled,
                                      false));
    auto wrongDirection = NativeRadioDispatchTestAccess::issueWithConsent(
        reviewForWifiDisable, *lock, manager, NativeRadioMutation::WirelessEnabled, true);
    assert(!NativeRadioDispatchTestAccess::spend(wrongDirection, *lock, manager));
    assert(wrongDirection.spent());
    auto wrongOperation = NativeRadioDispatchTestAccess::issueWithConsent(
        reviewForWifiDisable, *lock, manager, NativeRadioMutation::NetworkingEnabled, false);
    assert(!NativeRadioDispatchTestAccess::spend(wrongOperation, *lock, manager));
    assert(wrongOperation.spent());

    auto wrongManager = manager;
    wrongManager.pid++;
    auto ticket = NativeRadioDispatchTestAccess::issue(*lock, manager,
                                                       NativeRadioMutation::WirelessEnabled, false);
    assert(!NativeRadioDispatchTestAccess::spend(ticket, *lock, wrongManager));
    assert(ticket.spent());
    assert(!NativeRadioDispatchTestAccess::spend(ticket, *lock, manager));

    auto wrongLock = *lock;
    wrongLock.uid = 1001;
    auto other = NativeRadioDispatchTestAccess::issue(
        *lock, manager, NativeRadioMutation::NetworkingEnabled, false);
    assert(!NativeRadioDispatchTestAccess::spend(other, wrongLock, manager));
    assert(other.spent());
    assert(!NativeRadioDispatchTestAccess::spend(other, *lock, manager));

    auto movedFrom = NativeRadioDispatchTestAccess::issue(
        *lock, manager, NativeRadioMutation::WirelessEnabled, true);
    auto movedTo = std::move(movedFrom);
    assert(movedFrom.spent() && !movedTo.spent());
    assert(!NativeRadioDispatchTestAccess::spend(movedFrom, *lock, manager));
    assert(NativeRadioDispatchTestAccess::spend(movedTo, *lock, manager));
    assert(!NativeRadioDispatchTestAccess::spend(movedTo, *lock, manager));

    auto foreign = manager;
    foreign.uid = 1000;
    auto foreignAttempt = NativeRadioDispatchTestAccess::issue(
        *lock, foreign, NativeRadioMutation::NetworkingEnabled, true);
    assert(!NativeRadioDispatchTestAccess::spend(foreignAttempt, *lock, foreign));

    auto noInvocation = manager;
    noInvocation.serviceInvocation.clear();
    auto noInvocationAttempt = NativeRadioDispatchTestAccess::issue(
        *lock, noInvocation, NativeRadioMutation::NetworkingEnabled, true);
    assert(!NativeRadioDispatchTestAccess::spend(noInvocationAttempt, *lock, noInvocation));
    return 0;
}
