//! S18-7 exact, non-transmitting connection-lifecycle effect contracts.
//!
//! Native profile identity, current device and the particular active generation
//! are mandatory. These data are *correlation*, not a right to execute.
//! No operation is registered. A spent durable Control grant can only be
//! obtained through the original AuthorizedEffect, never a serialized ticket.

use linura_core::{
    NetworkAccessPointId, NetworkActiveConnectionId, NetworkDeviceId, NetworkObjectKind,
    NetworkProfileRevision, PrincipalId, ProviderId, RequestId, ResourceId,
};
use linura_provider_sdk::{ComponentDigest, EffectDescriptor, ExecutionBinding};
use linura_transaction::TransactionId;

use crate::network_authority::NETWORK_PROVIDER;
use crate::{AuthorizedEffect, DispatchPermit};

const REQUEST_PREFIX: &str = "request:v010:network-connection:";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionLifecycleOperation {
    Activate,
    Deactivate,
}

impl ConnectionLifecycleOperation {
    #[must_use]
    pub const fn operation(self) -> &'static str {
        match self {
            Self::Activate => "activate-connection",
            Self::Deactivate => "deactivate-connection",
        }
    }

    #[must_use]
    pub const fn request_slug(self) -> &'static str {
        match self {
            Self::Activate => "activate-",
            Self::Deactivate => "deactivate-",
        }
    }
}

/// Review-time identity. Does not attest a live NM source, original session,
/// network safety, Polkit permission, protected secret or durable attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactConnectionLifecycleEffect {
    operation: ConnectionLifecycleOperation,
    profile: NetworkProfileRevision,
    device: NetworkDeviceId,
    access_point: Option<NetworkAccessPointId>,
    active: Option<NetworkActiveConnectionId>,
}

impl ExactConnectionLifecycleEffect {
    /// An Ethernet-only lifecycle activation. A Wi-Fi activation must bind
    /// its exact fresh AP before it can be described by any effect.
    pub fn ethernet_activation(
        profile: NetworkProfileRevision,
        device: NetworkDeviceId,
    ) -> Result<Self, &'static str> {
        let effect = Self {
            operation: ConnectionLifecycleOperation::Activate,
            profile,
            device,
            access_point: None,
            active: None,
        };
        effect.validate()?;
        Ok(effect)
    }

    pub fn wifi_activation(
        profile: NetworkProfileRevision,
        device: NetworkDeviceId,
        access_point: NetworkAccessPointId,
    ) -> Result<Self, &'static str> {
        let effect = Self {
            operation: ConnectionLifecycleOperation::Activate,
            profile,
            device,
            access_point: Some(access_point),
            active: None,
        };
        effect.validate()?;
        Ok(effect)
    }

    pub fn deactivation(active: NetworkActiveConnectionId) -> Result<Self, &'static str> {
        let profile = active
            .profile()
            .ok_or("deactivation requires an original saved-profile revision")?
            .clone();
        let effect = Self {
            operation: ConnectionLifecycleOperation::Deactivate,
            profile,
            device: active.device().clone(),
            access_point: None,
            active: Some(active),
        };
        effect.validate()?;
        Ok(effect)
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.device.object().kind() != NetworkObjectKind::Device
            || self.profile.object().kind() != NetworkObjectKind::SettingsConnection
            || self.device.epoch() != self.profile.epoch()
            || self.device.generation() != self.device.object().sequence()
            || self.device.ifindex() == 0
            || self.device.namespace_inode() == 0
            || self.profile.revision_generation() == 0
        {
            return Err("connection target has mismatched native identity or revision");
        }
        match (self.operation, &self.active, &self.access_point) {
            (ConnectionLifecycleOperation::Activate, None, None) => {}
            (ConnectionLifecycleOperation::Activate, None, Some(ap))
                if ap.device() == &self.device
                    && ap.object().kind() == NetworkObjectKind::AccessPoint
                    && ap.observation_generation() != 0 => {}
            (ConnectionLifecycleOperation::Deactivate, Some(active), None)
                if active.device() == &self.device
                    && active.profile() == Some(&self.profile)
                    && active.object().kind() == NetworkObjectKind::ActiveConnection
                    && active.activation_generation() == active.object().sequence() => {}
            _ => return Err("connection operation has an ambiguous AP or active generation"),
        }
        Ok(())
    }

    #[must_use]
    pub const fn operation(&self) -> ConnectionLifecycleOperation {
        self.operation
    }

    #[must_use]
    pub const fn profile(&self) -> &NetworkProfileRevision {
        &self.profile
    }

    #[must_use]
    pub const fn device(&self) -> &NetworkDeviceId {
        &self.device
    }

    #[must_use]
    pub const fn active(&self) -> Option<&NetworkActiveConnectionId> {
        self.active.as_ref()
    }

    #[must_use]
    pub const fn access_point(&self) -> Option<&NetworkAccessPointId> {
        self.access_point.as_ref()
    }

    pub fn request_matches(&self, request: &RequestId) -> Result<(), &'static str> {
        let slug = request
            .as_str()
            .strip_prefix(REQUEST_PREFIX)
            .and_then(|s| s.strip_prefix(self.operation.request_slug()))
            .ok_or("connection request is not the exact operation namespace")?;
        if slug.is_empty()
            || slug.len() > 64
            || slug.starts_with('-')
            || slug.ends_with('-')
            || slug.contains("--")
            || !slug
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("connection request has an invalid canonical operation ID");
        }
        Ok(())
    }

    #[must_use]
    pub fn canonical_payload(&self) -> Vec<u8> {
        // Deterministic, newline-free native types; never include credentials,
        // user-supplied D-Bus method names or arbitrary profile maps.
        let epoch = self.device.epoch();
        let active_path = self
            .active
            .as_ref()
            .map_or_else(|| "/".to_owned(), |active| active.object().native_path());
        let ap_path = self
            .access_point
            .as_ref()
            .map_or_else(|| "/".to_owned(), |ap| ap.object().native_path());
        let ap_observation = self
            .access_point
            .as_ref()
            .map_or(0, NetworkAccessPointId::observation_generation);
        let media = match (self.operation, self.access_point.is_some()) {
            (ConnectionLifecycleOperation::Activate, true) => "wifi",
            (ConnectionLifecycleOperation::Activate, false) => "ethernet",
            (ConnectionLifecycleOperation::Deactivate, _) => "original-active",
        };
        format!(
            "boot={}\nbus={}\nowner={}\ndevice={}\ninterface={}\nifindex={}\nnetns={}\nprofile={}\nuuid={}\nsettings_version={}\nfingerprint={}\nmedia={}\naccess_point={}\nap_observation={}\nactive={}\n",
            epoch.boot().as_str(),
            epoch.bus().as_str(),
            epoch.owner().as_str(),
            self.device.object().native_path(),
            self.device.interface().as_str(),
            self.device.ifindex(),
            self.device.namespace_inode(),
            self.profile.object().native_path(),
            self.profile.uuid(),
            self.profile.revision_generation(),
            self.profile.settings_fingerprint(),
            media,
            ap_path,
            ap_observation,
            active_path,
        )
        .into_bytes()
    }

    pub fn descriptor(&self) -> Result<EffectDescriptor, String> {
        self.validate().map_err(str::to_owned)?;
        let resource = match &self.active {
            Some(active) => format!("networkmanager:active:{}", active.object().sequence()),
            None => format!(
                "networkmanager:profile:{}",
                self.profile.object().sequence()
            ),
        };
        EffectDescriptor::new(
            ProviderId::new(NETWORK_PROVIDER).map_err(|e| e.to_string())?,
            ResourceId::new(resource).map_err(|e| e.to_string())?,
            self.operation.operation(),
            self.canonical_payload(),
        )
        .map_err(|e| e.to_string())
    }

    /// Fail closed when a caller substitutes even one byte of the effect,
    /// including profile revision, kernel ifindex, active generation or verb.
    pub fn require_exact_descriptor(&self, effect: &EffectDescriptor) -> Result<(), String> {
        if *effect != self.descriptor()? {
            return Err("connection effect is not the reviewed native identity".into());
        }
        Ok(())
    }
}

/// Linear proof of a durably spent Control handoff. Intentionally neither
/// Clone nor Serialize; no native transport or effect registration consumes it.
#[derive(Debug)]
pub struct SpentConnectionLifecycleHandoff {
    target: ExactConnectionLifecycleEffect,
    principal: PrincipalId,
    request: RequestId,
    binding: ExecutionBinding,
    permit: DispatchPermit,
}

impl SpentConnectionLifecycleHandoff {
    pub(crate) fn from_authorized(
        authorization: AuthorizedEffect,
        target: ExactConnectionLifecycleEffect,
        principal: PrincipalId,
        request: RequestId,
    ) -> Result<Self, String> {
        let (effect, binding, permit) = authorization.into_connection_lifecycle_components();
        target.require_exact_descriptor(&effect)?;
        target.request_matches(&request).map_err(str::to_owned)?;
        let expected = TransactionId::for_namespace(&principal, &request);
        if binding.transaction_id != expected.as_str()
            || binding.validate_for(&effect).is_err()
            || permit.transaction_id().as_str() != binding.transaction_id
            || permit.generation() != binding.generation
            || permit.state_version() != binding.state_version
            || ComponentDigest::parse_hex(permit.binding_digest().hex())
                .map_err(|_| "durable connection binding digest malformed")?
                != binding.authority_binding_digest
            || ComponentDigest::parse_hex(permit.authority_use_digest().hex())
                .map_err(|_| "durable connection use digest malformed")?
                != binding.authority_use_digest
        {
            return Err("connection handoff differs from durably spent Control grant".into());
        }
        Ok(Self {
            target,
            principal,
            request,
            binding,
            permit,
        })
    }

    #[must_use]
    pub const fn target(&self) -> &ExactConnectionLifecycleEffect {
        &self.target
    }

    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    #[must_use]
    pub const fn request(&self) -> &RequestId {
        &self.request
    }

    #[must_use]
    pub const fn binding(&self) -> &ExecutionBinding {
        &self.binding
    }

    pub fn retire(self) {
        let _ = self.permit;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{
        BootId, NetworkInterfaceName, NetworkManagerEpoch, NetworkManagerOwner, NetworkObjectId,
        SystemBusInstanceId,
    };

    fn checked<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|err| unreachable!("fixture: {err:?}"))
    }

    fn epoch() -> NetworkManagerEpoch {
        NetworkManagerEpoch::new(
            checked(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
            checked(SystemBusInstanceId::new("fedcba9876543210abcdef0123456789")),
            checked(NetworkManagerOwner::new(":1.48")),
        )
    }

    fn device() -> NetworkDeviceId {
        checked(NetworkDeviceId::new(
            epoch(),
            checked(NetworkObjectId::from_path(
                NetworkObjectKind::Device,
                "/org/freedesktop/NetworkManager/Devices/8",
            )),
            4_026_531_840,
            7,
            checked(NetworkInterfaceName::new("wlan0")),
            8,
        ))
    }

    fn profile(version: u64) -> NetworkProfileRevision {
        checked(NetworkProfileRevision::new(
            epoch(),
            checked(NetworkObjectId::from_path(
                NetworkObjectKind::SettingsConnection,
                "/org/freedesktop/NetworkManager/Settings/9",
            )),
            "10203040-5060-7080-90ab-cdef12345678",
            version,
            "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
        ))
    }

    #[test]
    fn activation_is_exact_revisioned_and_still_unregistered() {
        let target = checked(ExactConnectionLifecycleEffect::ethernet_activation(
            profile(10),
            device(),
        ));
        let descriptor = checked(target.descriptor());
        assert_eq!(descriptor.operation, "activate-connection");
        assert_eq!(descriptor.resource.as_str(), "networkmanager:profile:9");
        assert!(target.require_exact_descriptor(&descriptor).is_ok());
        let other = checked(ExactConnectionLifecycleEffect::ethernet_activation(
            profile(11),
            device(),
        ));
        assert!(other.require_exact_descriptor(&descriptor).is_err());
        let request = checked(RequestId::new(
            "request:v010:network-connection:activate-test",
        ));
        assert!(target.request_matches(&request).is_ok());
        assert!(
            target
                .request_matches(&checked(RequestId::new(
                    "request:v010:network-connection:deactivate-test"
                )))
                .is_err()
        );
        assert!(
            crate::network_authority::require_network_effect_inactive(NETWORK_PROVIDER).is_err()
        );
        let operation = checked(linura_core::OperationId::new(
            "operation:network.connection.activate",
        ));
        let registry = checked(crate::operation_registry::trusted_builtin_operation_registry());
        assert!(registry.descriptor(&operation).is_none());
    }

    #[test]
    fn wifi_effect_seals_selected_ap_and_rejects_substitution() {
        let iface = device();
        let first_ap = checked(NetworkAccessPointId::new(
            iface.clone(),
            checked(NetworkObjectId::from_path(
                NetworkObjectKind::AccessPoint,
                "/org/freedesktop/NetworkManager/AccessPoint/4",
            )),
            41,
        ));
        let second_ap = checked(NetworkAccessPointId::new(
            iface.clone(),
            checked(NetworkObjectId::from_path(
                NetworkObjectKind::AccessPoint,
                "/org/freedesktop/NetworkManager/AccessPoint/5",
            )),
            41,
        ));
        let original = checked(ExactConnectionLifecycleEffect::wifi_activation(
            profile(10),
            iface.clone(),
            first_ap,
        ));
        let descriptor = checked(original.descriptor());
        assert!(original.require_exact_descriptor(&descriptor).is_ok());
        assert!(original.access_point().is_some());
        let swapped = checked(ExactConnectionLifecycleEffect::wifi_activation(
            profile(10),
            iface.clone(),
            second_ap,
        ));
        assert!(swapped.require_exact_descriptor(&descriptor).is_err());
        let ethernet = checked(ExactConnectionLifecycleEffect::ethernet_activation(
            profile(10),
            iface.clone(),
        ));
        assert!(ethernet.require_exact_descriptor(&descriptor).is_err());
        let other = checked(NetworkDeviceId::new(
            epoch(),
            checked(NetworkObjectId::from_path(
                NetworkObjectKind::Device,
                "/org/freedesktop/NetworkManager/Devices/9",
            )),
            iface.namespace_inode(),
            iface.ifindex(),
            iface.interface().clone(),
            9,
        ));
        let forged_ap = checked(NetworkAccessPointId::new(
            other,
            checked(NetworkObjectId::from_path(
                NetworkObjectKind::AccessPoint,
                "/org/freedesktop/NetworkManager/AccessPoint/4",
            )),
            41,
        ));
        assert!(
            ExactConnectionLifecycleEffect::wifi_activation(profile(10), iface, forged_ap,)
                .is_err()
        );
    }

    #[test]
    fn deactivation_requires_original_active_profile_and_exact_generation() {
        let active = checked(NetworkActiveConnectionId::new(
            device(),
            checked(NetworkObjectId::from_path(
                NetworkObjectKind::ActiveConnection,
                "/org/freedesktop/NetworkManager/ActiveConnection/12",
            )),
            Some(profile(10)),
            12,
        ));
        let original = checked(ExactConnectionLifecycleEffect::deactivation(active.clone()));
        let descriptor = checked(original.descriptor());
        assert_eq!(descriptor.operation, "deactivate-connection");
        assert_eq!(descriptor.resource.as_str(), "networkmanager:active:12");
        let replacement = checked(NetworkActiveConnectionId::new(
            device(),
            checked(NetworkObjectId::from_path(
                NetworkObjectKind::ActiveConnection,
                "/org/freedesktop/NetworkManager/ActiveConnection/13",
            )),
            Some(profile(10)),
            13,
        ));
        assert!(
            checked(ExactConnectionLifecycleEffect::deactivation(replacement))
                .require_exact_descriptor(&descriptor)
                .is_err()
        );
        let no_profile = checked(NetworkActiveConnectionId::new(
            device(),
            active.object().clone(),
            None,
            12,
        ));
        assert!(ExactConnectionLifecycleEffect::deactivation(no_profile).is_err());
        let stale_generation = checked(NetworkActiveConnectionId::new(
            device(),
            active.object().clone(),
            Some(profile(10)),
            13,
        ));
        assert!(ExactConnectionLifecycleEffect::deactivation(stale_generation).is_err());
    }

    #[test]
    fn cross_owner_profile_or_device_cannot_be_laundered_into_a_connection_effect() {
        let foreign = NetworkManagerEpoch::new(
            checked(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
            checked(SystemBusInstanceId::new("fedcba9876543210abcdef0123456789")),
            checked(NetworkManagerOwner::new(":1.49")),
        );
        let foreign_profile = checked(NetworkProfileRevision::new(
            foreign,
            checked(NetworkObjectId::from_path(
                NetworkObjectKind::SettingsConnection,
                "/org/freedesktop/NetworkManager/Settings/9",
            )),
            "10203040-5060-7080-90ab-cdef12345678",
            10,
            "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
        ));
        assert!(
            ExactConnectionLifecycleEffect::ethernet_activation(foreign_profile, device()).is_err()
        );
        let registry = checked(crate::operation_registry::trusted_builtin_operation_registry());
        for operation in [
            "operation:network.connection.activate",
            "operation:network.connection.deactivate",
            "operation:network.wifi.join",
        ] {
            let id = checked(linura_core::OperationId::new(operation));
            assert!(registry.descriptor(&id).is_none());
        }
    }
}
