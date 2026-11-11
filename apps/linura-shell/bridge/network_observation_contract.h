#pragma once

#include <QString>

// A trusted Control1 observation may prove that the original service reported
// a fresh NetworkManager source. It is never network association, DNS, portal,
// remote-administrator or independent internet reachability proof.
namespace Linura::ShellClient {
enum class NetworkObservationState {
    Unavailable,
    Untrusted,
    Stale,
    ObservedOnly,
};

struct NetworkObservationFields final
{
    QString provider;
    QString resource;
    QString capability;
    QString authority;
    QString freshness;
    quint64 observedAtMs = 0;
    quint64 validForMs = 0;
    quint64 sequence = 0;
    qint64 currentUnixMs = 0;
};

[[nodiscard]] NetworkObservationState
classifyNetworkObservation(const NetworkObservationFields &source) noexcept;
} // namespace Linura::ShellClient
