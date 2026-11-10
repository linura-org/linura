//! S18-6 exact radio effect schema. A descriptor is not execution authority.
//!
//! Both operations remain unregistered and denied by managed Control. Only a
//! nonforgeable, durably spent DispatchPermit can later authorize a handoff.

use std::collections::BTreeMap;

use linura_core::{PrincipalId, ProviderId, RequestId, ResourceId};
use linura_provider_sdk::{ComponentDigest, EffectDescriptor, ExecutionBinding};
use linura_transaction::TransactionId;

use crate::network_authority::NETWORK_PROVIDER;
use crate::network_radio::RadioChange;
use crate::{AuthorizedEffect, DispatchPermit};

const MANAGER: &str = "networkmanager:manager";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactRadioEffect {
    change: RadioChange,
    enabled: bool,
}

impl ExactRadioEffect {
    pub fn from_desired_state(
        provider: &str,
        resource: &str,
        state: &BTreeMap<String, String>,
    ) -> Result<Self, &'static str> {
        if provider != NETWORK_PROVIDER || resource != MANAGER || state.len() != 1 {
            return Err("radio requires the exact NetworkManager manager and one state key");
        }
        let (change, enabled) = match state.first_key_value() {
            Some((key, value)) if key == "networking_enabled" => {
                (RadioChange::Networking, value.as_str())
            }
            Some((key, value)) if key == "wireless_enabled" => (RadioChange::Wifi, value.as_str()),
            _ => return Err("unknown or substituted radio state key"),
        };
        let enabled = match enabled {
            "true" => true,
            "false" => false,
            _ => return Err("radio requires a canonical true or false token"),
        };
        Ok(Self { change, enabled })
    }

    #[must_use]
    pub const fn change(self) -> RadioChange {
        self.change
    }

    #[must_use]
    pub const fn enabled(self) -> bool {
        self.enabled
    }

    #[must_use]
    pub const fn operation(self) -> &'static str {
        match self.change {
            RadioChange::Networking => "set-networking-enabled",
            RadioChange::Wifi => "set-wifi-enabled",
        }
    }

    /// The exact original-session review namespace. This is an identity
    /// discriminator, never a client-supplied Polkit action or grant.
    #[must_use]
    pub const fn request_slug(self) -> &'static str {
        match (self.change, self.enabled) {
            (RadioChange::Networking, true) => "networking-enable-",
            (RadioChange::Networking, false) => "networking-disable-",
            (RadioChange::Wifi, true) => "wifi-enable-",
            (RadioChange::Wifi, false) => "wifi-disable-",
        }
    }

    #[must_use]
    pub fn canonical_payload(self) -> Vec<u8> {
        format!(
            "manager={MANAGER}\nproperty={}\nenabled={}\n",
            self.change.manager_property(),
            self.enabled
        )
        .into_bytes()
    }

    pub fn descriptor(self) -> Result<EffectDescriptor, String> {
        EffectDescriptor::new(
            ProviderId::new(NETWORK_PROVIDER).map_err(|e| e.to_string())?,
            ResourceId::new(MANAGER).map_err(|e| e.to_string())?,
            self.operation(),
            self.canonical_payload(),
        )
        .map_err(|e| e.to_string())
    }

    /// Control owns the principal/request -> durable transaction derivation.
    /// This is a correlation check only: an ExecutionBinding is not a
    /// DispatchPermit, and passing here must never enable native dispatch.
    pub fn require_durable_control_binding(
        self,
        principal: &PrincipalId,
        request: &RequestId,
        binding: &ExecutionBinding,
    ) -> Result<(), String> {
        let effect = self.descriptor()?;
        let expected = TransactionId::for_namespace(principal, request);
        if binding.transaction_id != expected.as_str() || binding.validate_for(&effect).is_err() {
            return Err("radio binding differs from Control durable request".into());
        }
        Ok(())
    }

    pub fn from_descriptor(effect: &EffectDescriptor) -> Result<Self, &'static str> {
        if effect.provider.as_str() != NETWORK_PROVIDER || effect.resource.as_str() != MANAGER {
            return Err("radio effect has wrong provider or resource");
        }
        let change = match effect.operation.as_str() {
            "set-networking-enabled" => RadioChange::Networking,
            "set-wifi-enabled" => RadioChange::Wifi,
            _ => return Err("radio operation is not one of the two fixed methods"),
        };
        [true, false]
            .into_iter()
            .map(|enabled| Self { change, enabled })
            .find(|candidate| candidate.canonical_payload() == effect.canonical_payload)
            .ok_or("radio payload is not the exact canonical bytes")
    }
}

/// A process-local, linear witness that Control has durably crossed the
/// Prepared -> Indeterminate one-use CAS for the *exact* radio operation.
/// Neither an arbitrary transport request nor an ExecutionBinding may mint
/// this value. No public native method or mutation registration consumes it
/// yet: a qualified original-session sender, safety proof and verification
/// must be connected separately before effects can be activated.
///
/// This struct deliberately does not implement Clone or Serialize.
#[derive(Debug)]
pub struct SpentRadioControlHandoff {
    exact: ExactRadioEffect,
    principal: PrincipalId,
    request: RequestId,
    binding: ExecutionBinding,
    permit: DispatchPermit,
}

impl SpentRadioControlHandoff {
    pub(crate) fn from_authorized(
        authorization: AuthorizedEffect,
        principal: PrincipalId,
        request: RequestId,
    ) -> Result<Self, String> {
        // The only issuer of AuthorizedEffect is managed Control after its
        // authenticated durable handoff. Consume it even on validation failure
        // so a failed extraction can never be retried with the same permit.
        let (effect, binding, permit) = authorization.into_radio_components();
        let exact = ExactRadioEffect::from_descriptor(&effect).map_err(str::to_owned)?;
        exact.require_durable_control_binding(&principal, &request, &binding)?;
        if permit.transaction_id().as_str() != binding.transaction_id
            || permit.generation() != binding.generation
            || permit.state_version() != binding.state_version
            || ComponentDigest::parse_hex(permit.binding_digest().hex())
                .map_err(|_| "durable radio binding digest malformed")?
                != binding.authority_binding_digest
            || ComponentDigest::parse_hex(permit.authority_use_digest().hex())
                .map_err(|_| "durable radio authority-use digest malformed")?
                != binding.authority_use_digest
        {
            return Err("radio handoff differs from spent durable Control permit".into());
        }
        Ok(Self {
            exact,
            principal,
            request,
            binding,
            permit,
        })
    }

    #[must_use]
    pub const fn exact(&self) -> ExactRadioEffect {
        self.exact
    }

    #[must_use]
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    #[must_use]
    pub fn request(&self) -> &RequestId {
        &self.request
    }

    #[must_use]
    pub fn binding(&self) -> &ExecutionBinding {
        &self.binding
    }

    /// Terminal disposal when a native preflight fails before reaching the
    /// sender. A caller cannot obtain a second attempt from this capability.
    pub fn retire(self) {
        let _ = self.permit;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checked<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("fixture: {error:?}"))
    }

    /// A spent radio handoff is not copyable or client-constructible.
    ///
    /// ```compile_fail
    /// use linura_control::network_radio_effect::SpentRadioControlHandoff;
    /// fn replay(proof: &SpentRadioControlHandoff) {
    ///     let _second = proof.clone();
    /// }
    /// ```
    #[test]
    fn radio_effects_are_two_exact_shapes_and_never_registered() {
        for (key, change) in [
            ("networking_enabled", RadioChange::Networking),
            ("wireless_enabled", RadioChange::Wifi),
        ] {
            for (value, desired) in [("false", false), ("true", true)] {
                let original = checked(ExactRadioEffect::from_desired_state(
                    NETWORK_PROVIDER,
                    MANAGER,
                    &BTreeMap::from([(key.into(), value.into())]),
                ));
                assert_eq!(original.change(), change);
                assert_eq!(original.enabled(), desired);
                assert_eq!(
                    original.request_slug(),
                    match (change, desired) {
                        (RadioChange::Networking, true) => "networking-enable-",
                        (RadioChange::Networking, false) => "networking-disable-",
                        (RadioChange::Wifi, true) => "wifi-enable-",
                        (RadioChange::Wifi, false) => "wifi-disable-",
                    }
                );
                let descriptor = checked(original.descriptor());
                assert_eq!(
                    checked(ExactRadioEffect::from_descriptor(&descriptor)),
                    original
                );
                let mut mutated = descriptor.clone();
                mutated.canonical_payload.push(0);
                assert!(ExactRadioEffect::from_descriptor(&mutated).is_err());
                mutated = descriptor;
                mutated.operation = "set-wifi-credentials".into();
                assert!(ExactRadioEffect::from_descriptor(&mutated).is_err());
            }
        }
        let registry = crate::operation_registry::trusted_builtin_operation_registry()
            .unwrap_or_else(|e| unreachable!("{e}"));
        for id in [
            "operation:network.networking.set-enabled",
            "operation:network.wifi.set-enabled",
        ] {
            assert!(
                registry
                    .descriptor(&checked(linura_core::OperationId::new(id)))
                    .is_none()
            );
        }
        assert!(
            crate::network_authority::require_network_effect_inactive(NETWORK_PROVIDER).is_err()
        );
    }

    #[test]
    fn control_is_the_only_layer_deriving_the_radio_durable_transaction_identity() {
        let effect = checked(ExactRadioEffect::from_desired_state(
            NETWORK_PROVIDER,
            MANAGER,
            &BTreeMap::from([("wireless_enabled".into(), "false".into())]),
        ));
        let original = checked(effect.descriptor());
        let principal = checked(PrincipalId::new("unix:uid:1000"));
        let request = checked(RequestId::new(
            "request:v010:network-radio:wifi-disable-test",
        ));
        let expected = TransactionId::for_namespace(&principal, &request);
        let digest = checked(ComponentDigest::parse_hex(&"a".repeat(64)));
        let binding = checked(ExecutionBinding::new(
            expected.as_str(),
            0,
            1,
            digest,
            digest,
            &original,
        ));
        assert!(
            effect
                .require_durable_control_binding(&principal, &request, &binding)
                .is_ok()
        );
        let different_request = checked(RequestId::new("request:v010:network-radio:other"));
        assert!(
            effect
                .require_durable_control_binding(&principal, &different_request, &binding)
                .is_err()
        );
        let mut altered = binding.clone();
        altered.state_version += 1;
        assert!(
            effect
                .require_durable_control_binding(&principal, &request, &altered)
                .is_err()
        );
        altered = binding;
        altered.transaction_id = "transaction:v1:foreign".into();
        assert!(
            effect
                .require_durable_control_binding(&principal, &request, &altered)
                .is_err()
        );
    }

    #[test]
    fn injected_keys_resources_and_boolean_spellings_are_denied() {
        for (provider, resource, state) in [
            ("networkmanager", MANAGER, BTreeMap::new()),
            (
                "networkmanager",
                MANAGER,
                BTreeMap::from([("enabled".into(), "true".into())]),
            ),
            (
                "networkmanager",
                MANAGER,
                BTreeMap::from([
                    ("networking_enabled".into(), "false".into()),
                    ("wireless_enabled".into(), "false".into()),
                ]),
            ),
            (
                "networkmanager",
                MANAGER,
                BTreeMap::from([("wireless_enabled".into(), "False".into())]),
            ),
            (
                "networkmanager",
                "networkmanager:wifi:wlan0",
                BTreeMap::from([("wireless_enabled".into(), "false".into())]),
            ),
            (
                "systemd",
                MANAGER,
                BTreeMap::from([("networking_enabled".into(), "true".into())]),
            ),
        ] {
            assert!(ExactRadioEffect::from_desired_state(provider, resource, &state).is_err());
        }
    }
}
