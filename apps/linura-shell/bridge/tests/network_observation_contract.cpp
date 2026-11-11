#include "network_observation_contract.h"

#include <QCoreApplication>

#include <cassert>

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    using namespace Linura::ShellClient;
    using State = NetworkObservationState;

    const QString provider = QStringLiteral("networkmanager");
    const QString resource = QStringLiteral("networkmanager:connections");
    const QString capability = QStringLiteral("networkmanager.connections.observe");
    const QString native = QStringLiteral("native-api");
    const QString current = QStringLiteral("current");

    auto result = [&](const QString &p, const QString &r, const QString &c, const QString &a,
                      const QString &f, quint64 at, quint64 valid, quint64 sequence, qint64 now) {
        return classifyNetworkObservation({p, r, c, a, f, at, valid, sequence, now});
    };
    assert(result(provider, resource, capability, native, current, 900, 200, 1, 1000) ==
           State::ObservedOnly);
    assert(result(provider, resource, capability, native, current, 700, 200, 1, 1000) ==
           State::Stale);
    assert(result(provider, resource, capability, native, current, 1001, 200, 1, 1000) ==
           State::Stale);
    assert(result(provider, resource, capability, native, current, 900, 0, 1, 1000) ==
           State::Stale);
    assert(result(provider, resource, capability, native, current, 900, 200, 0, 1000) ==
           State::Stale);
    assert(result(provider, resource, capability, native, current, 900, 60001, 1, 1000) ==
           State::Stale);
    assert(result(provider, resource, capability, native, QStringLiteral("synthetic-test"), current,
                  900, 200, 1, 1000) == State::Untrusted);
    assert(result(provider, resource, capability, native, QStringLiteral("future"), 900, 200, 1,
                  1000) == State::Stale);
    assert(result(QStringLiteral("other"), resource, capability, native, current, 900, 200, 1,
                  1000) == State::Untrusted);
    assert(result(provider, QStringLiteral("networkmanager:profile:9"), capability, native, current,
                  900, 200, 1, 1000) == State::Untrusted);
    assert(result(provider, resource, QStringLiteral("networkmanager.profile.update"), native,
                  current, 900, 200, 1, 1000) == State::Untrusted);
    return 0;
}
