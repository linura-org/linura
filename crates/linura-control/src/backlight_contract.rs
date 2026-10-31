//! Proposed S21-3 managed backlight effect, intentionally NOT registered.
//!
//! The only authoritative live operation registry is owned by Control. This
//! module describes its reviewable future binding without permitting a native
//! mutation, privilege escalation or policy bypass. A candidate descriptor is
//! not an executable permit and must never be registered until the entire
//! subject-bound executor and physical release gates have been accepted.

use linura_capability_sdk::{OperationDescriptor, OperationEffectBinding};
use linura_core::{
    BACKLIGHT_RESOURCE_PREFIX, BacklightResourceId, CapabilityId, OperationClass, OperationId,
    ProviderId, RiskClass,
};
use linura_provider_sdk::EffectDescriptor;

pub const OPERATION_ID: &str = "operation:display.backlight.set-brightness";
pub const PROVIDER: &str = "logind-backlight";
pub const OBSERVATION: &str = "display.backlight.observe";
pub const RESOURCE_PREFIX: &str = BACKLIGHT_RESOURCE_PREFIX;
pub const EFFECT_OPERATION: &str = "set-native-brightness";
pub const NATIVE_CHANGE_KEY: &str = "native_value";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BacklightContractError {
    NoncanonicalNativeValue,
    UnqualifiedMinimum,
    UnsafeNativeValue,
    InvalidEffect,
}

/// Exact effect data for the proposed managed route. This is neither an
/// approved plan nor a dispatch permit. In particular, supplying numeric bounds
/// does not qualify a panel: Control must bind independent current qualification
/// evidence in its canonical observation and policy review before any handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposedBacklightChange {
    target: BacklightResourceId,
    native_value: u32,
}

impl ProposedBacklightChange {
    pub fn new(
        target: BacklightResourceId,
        native_value: &str,
        qualified_minimum: u32,
        maximum: u32,
    ) -> Result<Self, BacklightContractError> {
        Ok(Self {
            target,
            native_value: parse_native_change(native_value, qualified_minimum, maximum)?,
        })
    }

    #[must_use]
    pub const fn target(&self) -> &BacklightResourceId {
        &self.target
    }

    #[must_use]
    pub const fn native_value(&self) -> u32 {
        self.native_value
    }

    /// Encode fixed semantic data only. Native paths, kernel names, methods,
    /// subsystem choices and untrusted commands are absent. A future qualified
    /// adapter must resolve this exact resource against attested inventory.
    pub fn effect_descriptor(&self) -> Result<EffectDescriptor, BacklightContractError> {
        let resource = self
            .target
            .resource_id()
            .map_err(|_| BacklightContractError::InvalidEffect)?;
        EffectDescriptor::new(
            ProviderId::new(PROVIDER).map_err(|_| BacklightContractError::InvalidEffect)?,
            resource.clone(),
            EFFECT_OPERATION,
            format!(
                "resource={}\nnative_value={}\n",
                resource.as_str(),
                self.native_value
            )
            .into_bytes(),
        )
        .map_err(|_| BacklightContractError::InvalidEffect)
    }

    /// Strictly decode the same proposed effect, never execution authority.
    /// Re-encoding equality excludes aliases, duplicate keys, extra arguments,
    /// alternate target strings and unreviewed payload changes.
    pub fn from_effect(
        effect: &EffectDescriptor,
        qualified_minimum: u32,
        maximum: u32,
    ) -> Result<Self, BacklightContractError> {
        if effect.provider.as_str() != PROVIDER
            || effect.operation != EFFECT_OPERATION
            || effect.canonical_payload.len() > linura_provider_sdk::MAX_EFFECT_PAYLOAD_BYTES
        {
            return Err(BacklightContractError::InvalidEffect);
        }
        let target = BacklightResourceId::from_resource(&effect.resource)
            .map_err(|_| BacklightContractError::InvalidEffect)?;
        let payload = std::str::from_utf8(&effect.canonical_payload)
            .map_err(|_| BacklightContractError::InvalidEffect)?;
        let value = payload
            .split_once("\nnative_value=")
            .and_then(|(_, suffix)| suffix.strip_suffix('\n'))
            .ok_or(BacklightContractError::InvalidEffect)?;
        let change = Self::new(target, value, qualified_minimum, maximum)?;
        if change.effect_descriptor()? != *effect {
            return Err(BacklightContractError::InvalidEffect);
        }
        Ok(change)
    }
}

/// Syntactic original-subject binding for Control's canonical authority path.
/// Actor provenance cannot substitute for the transport-derived principal.
/// This does not attest the session or qualify the physical generation.
pub(crate) fn original_subject_matches(
    principal: &crate::AuthenticatedPrincipal,
    resource: &linura_core::ResourceId,
) -> bool {
    BacklightResourceId::from_resource(resource)
        .is_ok_and(|target| principal.as_str() == format!("unix:uid:{}", target.epoch().uid()))
}

/// A typed conservative managed descriptor for contract testing and review.
/// It is not installed by trusted_builtin_operation_registry().
pub fn proposed_descriptor() -> Result<OperationDescriptor, String> {
    let binding = OperationEffectBinding::try_new(
        ProviderId::new(PROVIDER).map_err(|error| error.to_string())?,
        CapabilityId::new(OBSERVATION).map_err(|error| error.to_string())?,
        RESOURCE_PREFIX,
        vec![NATIVE_CHANGE_KEY.into()],
    )
    .map_err(|error| format!("{error:?}"))?;
    OperationDescriptor::try_new(
        OperationId::new(OPERATION_ID).map_err(|error| error.to_string())?,
        OperationClass::ManagedExternalEffect,
        Some(RiskClass::SecuritySensitive),
        Some(binding),
    )
    .map_err(|error| format!("{error:?}"))
}

/// Validate only the canonical requested value, not a physical panel, a
/// hardware-qualified minimum or an approval. Min/max must come from
/// independently authenticated Control-owned hardware qualification; no UI,
/// agent or provider may choose an artificially reduced safety floor.
pub fn parse_native_change(
    value: &str,
    qualified_minimum: u32,
    maximum: u32,
) -> Result<u32, BacklightContractError> {
    if value.is_empty()
        || value.len() > 10
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(BacklightContractError::NoncanonicalNativeValue);
    }
    if qualified_minimum == 0 || maximum == 0 || qualified_minimum > maximum {
        return Err(BacklightContractError::UnqualifiedMinimum);
    }
    let native = value
        .parse::<u32>()
        .map_err(|_| BacklightContractError::NoncanonicalNativeValue)?;
    if native < qualified_minimum || native > maximum {
        return Err(BacklightContractError::UnsafeNativeValue);
    }
    Ok(native)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> BacklightResourceId {
        use linura_core::{BacklightDeviceGeneration, BootId, SessionEpoch};
        BacklightResourceId::new(
            SessionEpoch::new(
                BootId::new("abcd1234-1234-4567-89ab-0123456789ab")
                    .unwrap_or_else(|e| unreachable!("{e}")),
                1000,
                "c2",
                42,
            )
            .unwrap_or_else(|e| unreachable!("{e}")),
            BacklightDeviceGeneration::new("98765432-1234-4567-89ab-0123456789ab")
                .unwrap_or_else(|e| unreachable!("{e}")),
        )
        .unwrap_or_else(|e| unreachable!("{e}"))
    }

    fn change() -> ProposedBacklightChange {
        ProposedBacklightChange::new(target(), "50", 20, 100)
            .unwrap_or_else(|e| unreachable!("{e:?}"))
    }

    #[test]
    fn proposed_effect_binds_one_exact_resource_and_native_value() {
        let change = change();
        let effect = change
            .effect_descriptor()
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        assert_eq!(
            ProposedBacklightChange::from_effect(&effect, 20, 100),
            Ok(change.clone())
        );
        assert_eq!(change.native_value(), 50);
        assert_eq!(change.target(), &target());
        assert_eq!(effect.operation, EFFECT_OPERATION);
        assert_eq!(
            effect.canonical_payload,
            format!("resource={}\nnative_value=50\n", effect.resource.as_str()).as_bytes()
        );
        let next = ProposedBacklightChange::new(target(), "51", 20, 100)
            .unwrap_or_else(|e| unreachable!("{e:?}"))
            .effect_descriptor()
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        assert_ne!(effect.digest(), next.digest());
    }

    #[test]
    fn effect_decoder_rejects_widened_methods_routes_and_payloads() {
        let effect = change()
            .effect_descriptor()
            .unwrap_or_else(|e| unreachable!("{e:?}"));
        for payload in [
            b"native_value=50\n".to_vec(),
            format!("resource={}\nnative_value=050\n", effect.resource.as_str()).into_bytes(),
            format!(
                "resource={}\nnative_value=50\nnative_value=51\n",
                effect.resource.as_str()
            )
            .into_bytes(),
            format!(
                "resource={}\nnative_value=50\nsubsystem=leds\n",
                effect.resource.as_str()
            )
            .into_bytes(),
            format!("resource={}\nnative_value=50", effect.resource.as_str()).into_bytes(),
            b"resource=backlight:physical:intel_backlight\nnative_value=50\n".to_vec(),
            vec![0xff],
            vec![b'a'; linura_provider_sdk::MAX_EFFECT_PAYLOAD_BYTES + 1],
        ] {
            let mut altered = effect.clone();
            altered.canonical_payload = payload;
            assert!(ProposedBacklightChange::from_effect(&altered, 20, 100).is_err());
        }
        for method in [
            "SetBrightness",
            "set-secure",
            "write-sysfs",
            "set-native-brightness ",
        ] {
            let mut altered = effect.clone();
            altered.operation = method.into();
            assert!(ProposedBacklightChange::from_effect(&altered, 20, 100).is_err());
        }
        let mut altered = effect.clone();
        altered.provider = ProviderId::new("systemd").unwrap_or_else(|e| unreachable!("{e}"));
        assert!(ProposedBacklightChange::from_effect(&altered, 20, 100).is_err());
        altered = effect.clone();
        altered.resource =
            linura_core::ResourceId::new(effect.resource.as_str().replace(":1000:", ":1001:"))
                .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(ProposedBacklightChange::from_effect(&altered, 20, 100).is_err());
        assert_eq!(
            ProposedBacklightChange::from_effect(&effect, 51, 100),
            Err(BacklightContractError::UnsafeNativeValue)
        );
        assert_eq!(
            ProposedBacklightChange::from_effect(&effect, 20, 49),
            Err(BacklightContractError::UnsafeNativeValue)
        );
        assert_eq!(
            ProposedBacklightChange::from_effect(&effect, 0, 100),
            Err(BacklightContractError::UnqualifiedMinimum)
        );
    }

    #[test]
    fn candidate_descriptor_matches_exact_s21_contract_but_is_not_live() {
        let descriptor = proposed_descriptor().unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(descriptor.class(), OperationClass::ManagedExternalEffect);
        assert_eq!(descriptor.risk_floor(), Some(RiskClass::SecuritySensitive));
        let binding = descriptor
            .effect_binding()
            .unwrap_or_else(|| unreachable!("the proposed backlight effect must be bound"));
        assert_eq!(binding.provider().as_str(), PROVIDER);
        assert_eq!(binding.observation_capability().as_str(), OBSERVATION);
        assert_eq!(binding.resource_prefix(), RESOURCE_PREFIX);
        assert_eq!(
            binding
                .change_keys()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![NATIVE_CHANGE_KEY]
        );
        assert!(
            binding.matches_resource(
                target()
                    .resource_id()
                    .unwrap_or_else(|error| unreachable!("{error}"))
                    .as_str()
            )
        );
        assert!(!binding.matches_resource("session:lock:foreign"));
        assert!(!binding.matches_resource("backlight:virtual:gamma"));

        let active = crate::operation_registry::trusted_builtin_operation_registry()
            .unwrap_or_else(|error| unreachable!("{error}"));
        let id = OperationId::new(OPERATION_ID).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(
            active.descriptor(&id).is_none(),
            "unqualified backlight mutation must remain absent from Control"
        );
    }

    #[test]
    fn native_decimal_is_strict_and_preserves_minimum() {
        assert_eq!(parse_native_change("1", 1, 100), Ok(1));
        assert_eq!(parse_native_change("100", 1, 100), Ok(100));
        assert_eq!(
            parse_native_change("4294967295", 20, u32::MAX),
            Ok(u32::MAX)
        );
        for invalid in [
            "",
            "00",
            "01",
            " 20",
            "+20",
            "20 ",
            "20\n",
            "-1",
            "1.5",
            "０",
            "4294967296",
        ] {
            assert_eq!(
                parse_native_change(invalid, 20, 100),
                Err(BacklightContractError::NoncanonicalNativeValue),
            );
        }
        assert_eq!(
            parse_native_change("0", 20, 100),
            Err(BacklightContractError::UnsafeNativeValue),
        );
        assert_eq!(
            parse_native_change("101", 20, 100),
            Err(BacklightContractError::UnsafeNativeValue),
        );
    }

    #[test]
    fn no_fabricated_minimum_or_unsupported_hardware_can_open_the_gate() {
        for (minimum, maximum) in [(0, 100), (1, 0), (101, 100)] {
            assert_eq!(
                parse_native_change("50", minimum, maximum),
                Err(BacklightContractError::UnqualifiedMinimum)
            );
        }
        assert_eq!(
            parse_native_change("19", 20, 100),
            Err(BacklightContractError::UnsafeNativeValue),
        );
        assert_eq!(parse_native_change("20", 20, 100), Ok(20));
    }
}
