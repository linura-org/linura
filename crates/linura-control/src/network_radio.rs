//! S18-6: fail-closed, non-authorizing review of machine-wide NM radio changes.
//!
//! This module is deliberately NOT an executor, permit, source of authoritative
//! native evidence, or proof of offline recovery. The input is an untrusted,
//! bounded *preview*. It may reject a Control review; a positive outcome MUST
//! NOT be converted to native mutation authority. Actual eligibility requires
//! a fresh original-subject Polkit decision, the inherited durable Control
//! prepare/attempt lifecycle, native corroboration and independent verification.
//! S18 network effects remain unregistered until separately qualified.

use std::collections::BTreeSet;

use linura_core::{NetworkManagerEpoch, NetworkObservationId};

use crate::network_authority::NetworkOperation;

const MAX_LINKS: usize = 128;
const MAX_PER_LINK_FACTS: u16 = 128;
const MAX_OBSERVATION_AGE_US: u64 = 5_000_000;

/// Only the two S18-6 operations. A scan, device activation or profile edit
/// cannot be misclassified as a radio toggle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RadioChange {
    Networking,
    Wifi,
}

impl RadioChange {
    #[must_use]
    pub const fn operation(self) -> NetworkOperation {
        match self {
            Self::Networking => NetworkOperation::NetworkingEnabled,
            Self::Wifi => NetworkOperation::WifiEnabled,
        }
    }

    #[must_use]
    pub const fn manager_property(self) -> &'static str {
        match self {
            Self::Networking => "NetworkingEnabled",
            Self::Wifi => "WirelessEnabled",
        }
    }

    /// The typed deterministic planner state key must agree with the native
    /// manager observation; both operations share a resource, never a key.
    #[must_use]
    pub const fn change_key(self) -> &'static str {
        self.operation().change_key()
    }
}

/// Corroboration of one kernel link with the NativeApi NetworkManager view.
/// These *supplied* facts are non-authorizing. Unknown, missing, duplicated or
/// contradictory facts deny review; in particular a Wi-Fi alias is never a
/// stable identity for native dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RadioLinkPreview {
    pub ifindex: u32,
    pub wireless: bool,
    pub managed_by_nm: bool,
    pub carrier_or_active: bool,
    pub ipv4_default_routes: u16,
    pub ipv6_default_routes: u16,
    pub dns_servers: u16,
    pub carries_remote_administration: bool,
    pub independent_link_corroboration: bool,
}

impl RadioLinkPreview {
    fn validates(&self) -> bool {
        self.ifindex != 0
            && self.independent_link_corroboration
            && self.ipv4_default_routes <= MAX_PER_LINK_FACTS
            && self.ipv6_default_routes <= MAX_PER_LINK_FACTS
            && self.dns_servers <= MAX_PER_LINK_FACTS
            && (self.carrier_or_active
                || (self.ipv4_default_routes == 0
                    && self.ipv6_default_routes == 0
                    && self.dns_servers == 0
                    && !self.carries_remote_administration))
    }
}

/// Complete *preview*, not an authenticated native attestation. In
/// particular, callers cannot prove local-console accessibility just by
/// setting the recovery booleans; native code must corroborate it separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RadioStatePreview {
    pub observation: NetworkObservationId,
    pub manager_networking_enabled: bool,
    pub manager_wifi_enabled: bool,
    pub wireless_hardware_enabled: Option<bool>,
    pub kernel_rfkill_soft_blocked: Option<bool>,
    pub kernel_rfkill_hard_blocked: Option<bool>,
    pub complete_manager: bool,
    pub complete_kernel_links: bool,
    pub complete_ipv4_routes: bool,
    pub complete_ipv6_routes: bool,
    pub complete_dns: bool,
    pub independently_observed_local_recovery: bool,
    pub offline_local_recovery_accessible: bool,
    pub remote_control_session_present: bool,
    pub links: Vec<RadioLinkPreview>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RadioReviewError {
    UnsupportedOperation,
    InvalidOrStaleObservation,
    IncompleteNativeImpact,
    InvalidLinkInventory,
    RemoteControlAtRisk,
    OfflineLocalRecoveryUnproven,
    HardwareOrRfkillUnknown,
    HardwareRfkillBlocked,
    NetworkingDisabled,
    UnmanagedWirelessImpact,
    LastViableLinkAtRisk,
    PostconditionNotProven,
    SourceEpochChanged,
    NoChange,
}

/// The only successful output means "can be considered for further native
/// qualification", NOT "approved", "safe to execute" or "verified".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RadioDisruptionPreview {
    pub operation: RadioChange,
    pub desired_enabled: bool,
    pub links_affected: usize,
    pub ipv4_default_routes_at_risk: u32,
    pub ipv6_default_routes_at_risk: u32,
    pub dns_servers_at_risk: u32,
}

impl RadioStatePreview {
    fn require_complete(
        &self,
        epoch: &NetworkManagerEpoch,
        now_boot_us: u64,
    ) -> Result<(), RadioReviewError> {
        self.observation
            .require_fresh(epoch, now_boot_us, MAX_OBSERVATION_AGE_US)
            .map_err(|_| RadioReviewError::InvalidOrStaleObservation)?;
        if !self.complete_manager
            || !self.complete_kernel_links
            || !self.complete_ipv4_routes
            || !self.complete_ipv6_routes
            || !self.complete_dns
        {
            return Err(RadioReviewError::IncompleteNativeImpact);
        }
        if self.links.len() > MAX_LINKS {
            return Err(RadioReviewError::InvalidLinkInventory);
        }
        let mut seen = BTreeSet::new();
        for link in &self.links {
            if !link.validates() || !seen.insert(link.ifindex) {
                return Err(RadioReviewError::InvalidLinkInventory);
            }
        }
        if self.manager_wifi_enabled && self.wireless_hardware_enabled.is_none() {
            return Err(RadioReviewError::HardwareOrRfkillUnknown);
        }
        // NetworkManager reports a distinct software state and hardware state;
        // neither is interchangeable with kernel rfkill, and absence is unknown.
        if self.kernel_rfkill_soft_blocked.is_none()
            || self.kernel_rfkill_hard_blocked.is_none()
            || self.wireless_hardware_enabled.is_none()
        {
            return Err(RadioReviewError::HardwareOrRfkillUnknown);
        }
        Ok(())
    }

    fn state_for(&self, change: RadioChange) -> bool {
        match change {
            RadioChange::Networking => self.manager_networking_enabled,
            RadioChange::Wifi => self.manager_wifi_enabled,
        }
    }
}

/// Conservative non-authorizing evaluation. This method does *not* take an
/// AuthorizedEffect and is not callable as an effect; it never changes host
/// state. Even a no-impact toggle needs offline local recovery proof.
pub fn review_radio_change(
    preview: &RadioStatePreview,
    epoch: &NetworkManagerEpoch,
    now_boot_us: u64,
    change: RadioChange,
    desired_enabled: bool,
) -> Result<RadioDisruptionPreview, RadioReviewError> {
    preview.require_complete(epoch, now_boot_us)?;
    if preview.state_for(change) == desired_enabled {
        return Err(RadioReviewError::NoChange);
    }
    if !preview.independently_observed_local_recovery || !preview.offline_local_recovery_accessible
    {
        return Err(RadioReviewError::OfflineLocalRecoveryUnproven);
    }
    if preview.remote_control_session_present {
        // Remote control may depend on an unenumerated route/namespace/VPN.
        // No guessed alternate route or timer is a safe exception.
        return Err(RadioReviewError::RemoteControlAtRisk);
    }
    if desired_enabled && change == RadioChange::Wifi {
        if !preview.manager_networking_enabled {
            return Err(RadioReviewError::NetworkingDisabled);
        }
        if preview.wireless_hardware_enabled != Some(true)
            || preview.kernel_rfkill_soft_blocked != Some(false)
            || preview.kernel_rfkill_hard_blocked != Some(false)
        {
            return Err(RadioReviewError::HardwareRfkillBlocked);
        }
    }

    let mut affected = 0_usize;
    let mut ipv4 = 0_u32;
    let mut ipv6 = 0_u32;
    let mut dns = 0_u32;
    if !desired_enabled {
        for link in &preview.links {
            let potentially_affected = match change {
                RadioChange::Networking => link.managed_by_nm,
                RadioChange::Wifi => link.wireless,
            };
            if !potentially_affected {
                continue;
            }
            if link.wireless && !link.managed_by_nm {
                // A global radio setting and a per-device NM managed bit are
                // different things. Never assume unmanaged Wi-Fi is unaffected.
                return Err(RadioReviewError::UnmanagedWirelessImpact);
            }
            affected += 1;
            if !link.carrier_or_active {
                continue;
            }
            if link.carries_remote_administration {
                return Err(RadioReviewError::RemoteControlAtRisk);
            }
            ipv4 += u32::from(link.ipv4_default_routes);
            ipv6 += u32::from(link.ipv6_default_routes);
            dns += u32::from(link.dns_servers);
        }
        // Deny if all live routing/DNS depends on the links the proposed
        // toggle would disable, even if a caller claims local recovery.
        let unaffected = preview
            .links
            .iter()
            .filter(|link| {
                link.carrier_or_active
                    && match change {
                        RadioChange::Networking => !link.managed_by_nm,
                        RadioChange::Wifi => !link.wireless,
                    }
            })
            .collect::<Vec<_>>();
        // IPv4, IPv6 and DNS are NOT interchangeable. An alternative link
        // must preserve each affected family, not merely any route.
        if (ipv4 != 0 && !unaffected.iter().any(|link| link.ipv4_default_routes != 0))
            || (ipv6 != 0 && !unaffected.iter().any(|link| link.ipv6_default_routes != 0))
            || (dns != 0 && !unaffected.iter().any(|link| link.dns_servers != 0))
        {
            return Err(RadioReviewError::LastViableLinkAtRisk);
        }
    }
    Ok(RadioDisruptionPreview {
        operation: change,
        desired_enabled,
        links_affected: affected,
        ipv4_default_routes_at_risk: ipv4,
        ipv6_default_routes_at_risk: ipv6,
        dns_servers_at_risk: dns,
    })
}

/// Independent native verification must do substantially more than this
/// preliminary same-source shape check: exact pre/post Control journal binding,
/// native effect attribution, original session, fresh route/DNS/kernel state,
/// and unambiguous post-dispatch timestamps remain mandatory.
pub fn check_radio_postcondition_shape(
    before: &RadioStatePreview,
    after: &RadioStatePreview,
    epoch: &NetworkManagerEpoch,
    now_boot_us: u64,
    change: RadioChange,
    desired_enabled: bool,
) -> Result<(), RadioReviewError> {
    before
        .observation
        .epoch()
        .require_same(after.observation.epoch())
        .map_err(|_| RadioReviewError::SourceEpochChanged)?;
    before
        .require_complete(epoch, now_boot_us)
        .map_err(|_| RadioReviewError::PostconditionNotProven)?;
    after
        .require_complete(epoch, now_boot_us)
        .map_err(|_| RadioReviewError::PostconditionNotProven)?;
    if before.state_for(change) == desired_enabled
        || after.observation.generation() <= before.observation.generation()
        || after.state_for(change) != desired_enabled
        || match change {
            RadioChange::Networking => before.manager_wifi_enabled != after.manager_wifi_enabled,
            RadioChange::Wifi => {
                before.manager_networking_enabled != after.manager_networking_enabled
            }
        }
        || (change == RadioChange::Wifi
            && desired_enabled
            && (!after.manager_networking_enabled
                || after.wireless_hardware_enabled != Some(true)
                || after.kernel_rfkill_soft_blocked != Some(false)
                || after.kernel_rfkill_hard_blocked != Some(false)))
    {
        return Err(RadioReviewError::PostconditionNotProven);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{BootId, NetworkManagerOwner, SystemBusInstanceId};

    fn checked<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("known radio test fixture: {error:?}"))
    }

    fn epoch() -> NetworkManagerEpoch {
        NetworkManagerEpoch::new(
            checked(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
            checked(SystemBusInstanceId::new("fedcba9876543210abcdef0123456789")),
            checked(NetworkManagerOwner::new(":1.48")),
        )
    }

    fn link(ifindex: u32, wireless: bool, managed: bool, routed: bool) -> RadioLinkPreview {
        RadioLinkPreview {
            ifindex,
            wireless,
            managed_by_nm: managed,
            carrier_or_active: true,
            ipv4_default_routes: u16::from(routed),
            ipv6_default_routes: u16::from(routed),
            dns_servers: u16::from(routed),
            carries_remote_administration: false,
            independent_link_corroboration: true,
        }
    }

    fn preview() -> RadioStatePreview {
        RadioStatePreview {
            observation: checked(NetworkObservationId::new(epoch(), 1, 10_000)),
            manager_networking_enabled: true,
            manager_wifi_enabled: true,
            wireless_hardware_enabled: Some(true),
            kernel_rfkill_soft_blocked: Some(false),
            kernel_rfkill_hard_blocked: Some(false),
            complete_manager: true,
            complete_kernel_links: true,
            complete_ipv4_routes: true,
            complete_ipv6_routes: true,
            complete_dns: true,
            independently_observed_local_recovery: true,
            offline_local_recovery_accessible: true,
            remote_control_session_present: false,
            links: vec![link(3, true, true, true), link(4, false, true, true)],
        }
    }

    fn review(
        p: &RadioStatePreview,
        change: RadioChange,
        enabled: bool,
    ) -> Result<RadioDisruptionPreview, RadioReviewError> {
        review_radio_change(p, &epoch(), 11_000, change, enabled)
    }

    #[test]
    fn distinct_radio_manager_properties_cannot_alias_one_change_key() {
        assert_eq!(RadioChange::Networking.change_key(), "networking_enabled");
        assert_eq!(RadioChange::Wifi.change_key(), "wireless_enabled");
        assert_ne!(
            RadioChange::Networking.change_key(),
            RadioChange::Wifi.change_key()
        );
        assert_eq!(
            RadioChange::Networking.manager_property(),
            "NetworkingEnabled"
        );
        assert_eq!(RadioChange::Wifi.manager_property(), "WirelessEnabled");
    }

    #[test]
    fn radio_effect_types_are_exact_and_non_authorizing() {
        assert_eq!(
            RadioChange::Networking.operation(),
            NetworkOperation::NetworkingEnabled
        );
        assert_eq!(RadioChange::Wifi.operation(), NetworkOperation::WifiEnabled);
        assert_eq!(
            RadioChange::Networking.manager_property(),
            "NetworkingEnabled"
        );
        assert_eq!(RadioChange::Wifi.manager_property(), "WirelessEnabled");
        let result = checked(review(&preview(), RadioChange::Wifi, false));
        assert_eq!(result.links_affected, 1);
        assert_eq!(result.ipv4_default_routes_at_risk, 1);
        assert_eq!(result.ipv6_default_routes_at_risk, 1);
        assert_eq!(result.dns_servers_at_risk, 1);
    }

    #[test]
    fn missing_corrupted_or_stale_evidence_denies() {
        let mut p = preview();
        p.complete_ipv6_routes = false;
        assert_eq!(
            review(&p, RadioChange::Wifi, false),
            Err(RadioReviewError::IncompleteNativeImpact)
        );
        let mut p = preview();
        p.links.push(link(3, true, true, true));
        assert_eq!(
            review(&p, RadioChange::Wifi, false),
            Err(RadioReviewError::InvalidLinkInventory)
        );
        let mut p = preview();
        p.links[0].independent_link_corroboration = false;
        assert_eq!(
            review(&p, RadioChange::Wifi, false),
            Err(RadioReviewError::InvalidLinkInventory)
        );
        let mut p = preview();
        p.links[0].ipv4_default_routes = 129;
        assert_eq!(
            review(&p, RadioChange::Wifi, false),
            Err(RadioReviewError::InvalidLinkInventory)
        );
        assert_eq!(
            review_radio_change(&preview(), &epoch(), 5_100_001, RadioChange::Wifi, false),
            Err(RadioReviewError::InvalidOrStaleObservation)
        );
    }

    #[test]
    fn offline_recovery_remote_session_and_last_link_are_protective() {
        let mut p = preview();
        p.offline_local_recovery_accessible = false;
        assert_eq!(
            review(&p, RadioChange::Wifi, false),
            Err(RadioReviewError::OfflineLocalRecoveryUnproven)
        );
        let mut p = preview();
        p.remote_control_session_present = true;
        assert_eq!(
            review(&p, RadioChange::Wifi, false),
            Err(RadioReviewError::RemoteControlAtRisk)
        );
        let mut p = preview();
        p.links.pop();
        assert_eq!(
            review(&p, RadioChange::Wifi, false),
            Err(RadioReviewError::LastViableLinkAtRisk)
        );
        let mut p = preview();
        p.links[0].carries_remote_administration = true;
        assert_eq!(
            review(&p, RadioChange::Wifi, false),
            Err(RadioReviewError::RemoteControlAtRisk)
        );
    }

    #[test]
    fn rfkill_hardware_and_managed_are_independent() {
        let mut p = preview();
        p.manager_wifi_enabled = false;
        p.kernel_rfkill_hard_blocked = Some(true);
        assert_eq!(
            review(&p, RadioChange::Wifi, true),
            Err(RadioReviewError::HardwareRfkillBlocked)
        );
        p.kernel_rfkill_hard_blocked = Some(false);
        p.kernel_rfkill_soft_blocked = Some(true);
        assert_eq!(
            review(&p, RadioChange::Wifi, true),
            Err(RadioReviewError::HardwareRfkillBlocked)
        );
        p.kernel_rfkill_soft_blocked = None;
        assert_eq!(
            review(&p, RadioChange::Wifi, true),
            Err(RadioReviewError::HardwareOrRfkillUnknown)
        );
        p.kernel_rfkill_soft_blocked = Some(false);
        p.manager_networking_enabled = false;
        assert_eq!(
            review(&p, RadioChange::Wifi, true),
            Err(RadioReviewError::NetworkingDisabled)
        );
        let mut p = preview();
        p.links[0].managed_by_nm = false;
        assert_eq!(
            review(&p, RadioChange::Wifi, false),
            Err(RadioReviewError::UnmanagedWirelessImpact)
        );
    }

    #[test]
    fn asymmetric_ipv4_ipv6_and_dns_fallback_is_insufficient() {
        let mut p = preview();
        p.links[1].ipv4_default_routes = 0;
        assert_eq!(
            review(&p, RadioChange::Wifi, false),
            Err(RadioReviewError::LastViableLinkAtRisk)
        );
        p.links[1].ipv4_default_routes = 1;
        p.links[1].ipv6_default_routes = 0;
        assert_eq!(
            review(&p, RadioChange::Wifi, false),
            Err(RadioReviewError::LastViableLinkAtRisk)
        );
        p.links[1].ipv6_default_routes = 1;
        p.links[1].dns_servers = 0;
        assert_eq!(
            review(&p, RadioChange::Wifi, false),
            Err(RadioReviewError::LastViableLinkAtRisk)
        );
    }

    #[test]
    fn no_change_and_postcondition_mismatch_never_prove_effect() {
        assert_eq!(
            review(&preview(), RadioChange::Wifi, true),
            Err(RadioReviewError::NoChange)
        );
        let before = preview();
        let mut after = before.clone();
        assert_eq!(
            check_radio_postcondition_shape(
                &before,
                &after,
                &epoch(),
                11_000,
                RadioChange::Wifi,
                false
            ),
            Err(RadioReviewError::PostconditionNotProven)
        );
        after.observation = checked(NetworkObservationId::new(epoch(), 2, 10_500));
        after.manager_wifi_enabled = false;
        assert!(
            check_radio_postcondition_shape(
                &before,
                &after,
                &epoch(),
                11_000,
                RadioChange::Wifi,
                false
            )
            .is_ok()
        );
        let mut cross_control = after.clone();
        cross_control.manager_networking_enabled = false;
        assert_eq!(
            check_radio_postcondition_shape(
                &before,
                &cross_control,
                &epoch(),
                11_000,
                RadioChange::Wifi,
                false
            ),
            Err(RadioReviewError::PostconditionNotProven)
        );
        let mut stale_before = before.clone();
        stale_before.observation = checked(NetworkObservationId::new(epoch(), 1, 1));
        assert_eq!(
            check_radio_postcondition_shape(
                &stale_before,
                &after,
                &epoch(),
                5_001_001,
                RadioChange::Wifi,
                false
            ),
            Err(RadioReviewError::PostconditionNotProven)
        );
        after.observation = checked(NetworkObservationId::new(
            NetworkManagerEpoch::new(
                epoch().boot().clone(),
                epoch().bus().clone(),
                checked(NetworkManagerOwner::new(":1.49")),
            ),
            3,
            10_500,
        ));
        assert_eq!(
            check_radio_postcondition_shape(
                &before,
                &after,
                &epoch(),
                11_000,
                RadioChange::Wifi,
                false
            ),
            Err(RadioReviewError::SourceEpochChanged)
        );
    }
}
