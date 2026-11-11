//! S18-9 read-only presentation of Control1 NetworkManager observations.
//!
//! This is NOT a connection-state, portal, internet-reachability or native
//! mutation oracle. It never exposes a credential, BSSID, SSID, route or
//! action. Unknown/stale/foreign sources cannot become "connected".

pub const NETWORK_PROVIDER: &str = "networkmanager";
pub const NETWORK_RESOURCE: &str = "networkmanager:connections";
pub const NETWORK_CAPABILITY: &str = "networkmanager.connections.observe";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkSourceStatus {
    Unavailable,
    StaleOrFuture,
    Untrusted,
    CurrentNativeObservation,
}

impl NetworkSourceStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::StaleOrFuture => "stale-or-future",
            Self::Untrusted => "untrusted",
            Self::CurrentNativeObservation => "current-native-observation-only",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadOnlyNetworkOverview {
    source: NetworkSourceStatus,
}

impl ReadOnlyNetworkOverview {
    /// Match the *exact* Control1 provider/resource/capability tuple. Fresh,
    /// native API data is still only observation, never independent routing,
    /// DNS, portal, remote-administrator or physical-recovery proof.
    #[must_use]
    pub fn from_control1(
        provider: &str,
        resource: &str,
        capability: &str,
        authority: &str,
        freshness: &str,
    ) -> Self {
        let source = if provider != NETWORK_PROVIDER
            || resource != NETWORK_RESOURCE
            || capability != NETWORK_CAPABILITY
        {
            NetworkSourceStatus::Untrusted
        } else if freshness == "stale" || freshness == "future" {
            NetworkSourceStatus::StaleOrFuture
        } else if authority == "native-api" && freshness == "current" {
            NetworkSourceStatus::CurrentNativeObservation
        } else if authority == "synthetic-test" || freshness != "current" {
            NetworkSourceStatus::Untrusted
        } else {
            NetworkSourceStatus::Unavailable
        };
        Self { source }
    }

    #[must_use]
    pub const fn source(self) -> NetworkSourceStatus {
        self.source
    }

    #[must_use]
    pub const fn reachability(self) -> &'static str {
        "not-independently-proved"
    }

    #[must_use]
    pub const fn profile_mutation(self) -> &'static str {
        "disabled-unqualified"
    }

    #[must_use]
    pub const fn lifecycle_mutation(self) -> &'static str {
        "disabled-unqualified"
    }

    #[must_use]
    pub const fn portal_state(self) -> &'static str {
        "unknown-not-verified"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(authority: &str, freshness: &str) -> ReadOnlyNetworkOverview {
        ReadOnlyNetworkOverview::from_control1(
            NETWORK_PROVIDER,
            NETWORK_RESOURCE,
            NETWORK_CAPABILITY,
            authority,
            freshness,
        )
    }

    #[test]
    fn current_native_observation_never_claims_reachability_or_execution() {
        let state = report("native-api", "current");
        assert_eq!(
            state.source(),
            NetworkSourceStatus::CurrentNativeObservation
        );
        assert_eq!(state.reachability(), "not-independently-proved");
        assert_eq!(state.profile_mutation(), "disabled-unqualified");
        assert_eq!(state.lifecycle_mutation(), "disabled-unqualified");
        assert_eq!(state.portal_state(), "unknown-not-verified");
    }

    #[test]
    fn malformed_stale_synthetic_and_substituted_sources_fail_closed() {
        assert_eq!(
            report("native-api", "stale").source(),
            NetworkSourceStatus::StaleOrFuture
        );
        assert_eq!(
            report("native-api", "future").source(),
            NetworkSourceStatus::StaleOrFuture
        );
        assert_eq!(
            report("synthetic-test", "current").source(),
            NetworkSourceStatus::Untrusted
        );
        assert_eq!(
            report("kernel", "current").source(),
            NetworkSourceStatus::Unavailable
        );
        assert_eq!(
            report("native-api", "CURRENT").source(),
            NetworkSourceStatus::Untrusted
        );
        for (provider, resource, capability) in [
            ("other", NETWORK_RESOURCE, NETWORK_CAPABILITY),
            (
                NETWORK_PROVIDER,
                "networkmanager:device:wlan0",
                NETWORK_CAPABILITY,
            ),
            (
                NETWORK_PROVIDER,
                NETWORK_RESOURCE,
                "networkmanager.connection.activate",
            ),
        ] {
            assert_eq!(
                ReadOnlyNetworkOverview::from_control1(
                    provider,
                    resource,
                    capability,
                    "native-api",
                    "current"
                )
                .source(),
                NetworkSourceStatus::Untrusted
            );
        }
    }
}
