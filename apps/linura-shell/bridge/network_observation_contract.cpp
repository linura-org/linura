#include "network_observation_contract.h"

namespace Linura::ShellClient {
NetworkObservationState classifyNetworkObservation(const NetworkObservationFields &source) noexcept
{
    const auto &provider = source.provider;
    const auto &resource = source.resource;
    const auto &capability = source.capability;
    const auto &authority = source.authority;
    const auto &freshness = source.freshness;
    const quint64 observedAtMs = source.observedAtMs;
    const quint64 validForMs = source.validForMs;
    const quint64 sequence = source.sequence;
    const qint64 currentUnixMs = source.currentUnixMs;
    if (provider != QLatin1String("networkmanager") ||
        resource != QLatin1String("networkmanager:connections") ||
        capability != QLatin1String("networkmanager.connections.observe"))
        return NetworkObservationState::Untrusted;
    if (authority != QLatin1String("native-api"))
        return NetworkObservationState::Untrusted;
    if (freshness != QLatin1String("current")) {
        if (freshness == QLatin1String("stale") || freshness == QLatin1String("future"))
            return NetworkObservationState::Stale;
        return NetworkObservationState::Untrusted;
    }
    if (currentUnixMs <= 0 || validForMs == 0 || validForMs > 60000 || sequence == 0 ||
        observedAtMs > static_cast<quint64>(currentUnixMs))
        return NetworkObservationState::Stale;
    const quint64 age = static_cast<quint64>(currentUnixMs) - observedAtMs;
    if (age > validForMs)
        return NetworkObservationState::Stale;
    return NetworkObservationState::ObservedOnly;
}
} // namespace Linura::ShellClient
