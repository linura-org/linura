use std::fmt::{Display, Formatter};

use linura_capability_sdk::{
    OperationDescriptor, OperationDescriptorError, OperationEffectBinding,
    OperationEffectBindingError, OperationRegistry, OperationRegistryError,
};
use linura_core::{
    CapabilityId, OperationClass, OperationId, ProviderId, RiskClass, ValidationError,
};

pub const MANAGED_SYSTEMD_REGISTERED_OPERATION_ID: &str = "operation:systemd.unit.set-active-state";
pub const MANAGED_SYSTEMD_PROVIDER: &str = "systemd";
pub const MANAGED_SYSTEMD_CAPABILITY: &str = "systemd.unit.observe";
pub const MANAGED_SYSTEMD_UNIT_PREFIX: &str = "linura-managed-";
pub const MANAGED_SYSTEMD_RESOURCE_PREFIX: &str = "systemd:unit:linura-managed-";
pub const MANAGED_SYSTEMD_RESOURCE_SUFFIX: &str = ".service";
pub const MANAGED_SYSTEMD_CHANGE_KEY: &str = "active_state";
pub(crate) const MANAGED_SYSTEMD_RISK_FLOOR_RULE_ID: &str =
    "operation-registry.managed-systemd-active-state.risk-floor";

pub const TRANSIENT_AUDIO_VOLUME_OPERATION_ID: &str = "operation:audio.output.set-session-volume";
pub const TRANSIENT_AUDIO_PROVIDER: &str = "pipewire";
pub const TRANSIENT_AUDIO_CAPABILITY: &str = "audio.session.observe";
pub const TRANSIENT_AUDIO_RESOURCE_PREFIX: &str = "audio:session:output:";
pub const TRANSIENT_AUDIO_VOLUME_CHANGE_KEY: &str = "volume_percent";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TrustedOperationRegistryError {
    Identifier(String),
    EffectBinding(OperationEffectBindingError),
    Descriptor(OperationDescriptorError),
    Registry(OperationRegistryError),
}

impl Display for TrustedOperationRegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identifier(detail) => {
                write!(
                    formatter,
                    "trusted operation identifier is invalid: {detail}"
                )
            }
            Self::EffectBinding(error) => {
                write!(
                    formatter,
                    "trusted operation effect binding is invalid: {error:?}"
                )
            }
            Self::Descriptor(error) => {
                write!(
                    formatter,
                    "trusted operation descriptor is invalid: {error:?}"
                )
            }
            Self::Registry(error) => {
                write!(
                    formatter,
                    "trusted operation registry rejected a descriptor: {error:?}"
                )
            }
        }
    }
}

impl std::error::Error for TrustedOperationRegistryError {}

impl From<ValidationError> for TrustedOperationRegistryError {
    fn from(error: ValidationError) -> Self {
        Self::Identifier(error.to_string())
    }
}

impl From<OperationEffectBindingError> for TrustedOperationRegistryError {
    fn from(error: OperationEffectBindingError) -> Self {
        Self::EffectBinding(error)
    }
}

impl From<OperationDescriptorError> for TrustedOperationRegistryError {
    fn from(error: OperationDescriptorError) -> Self {
        Self::Descriptor(error)
    }
}

impl From<OperationRegistryError> for TrustedOperationRegistryError {
    fn from(error: OperationRegistryError) -> Self {
        Self::Registry(error)
    }
}

pub(crate) fn trusted_builtin_operation_registry()
-> Result<OperationRegistry, TrustedOperationRegistryError> {
    let mut registry = OperationRegistry::default();
    registry.register(managed_systemd_active_state_descriptor()?)?;
    registry.register(transient_audio_volume_descriptor()?)?;
    Ok(registry)
}

fn managed_systemd_active_state_descriptor()
-> Result<OperationDescriptor, TrustedOperationRegistryError> {
    let binding = OperationEffectBinding::try_new(
        ProviderId::new(MANAGED_SYSTEMD_PROVIDER)?,
        CapabilityId::new(MANAGED_SYSTEMD_CAPABILITY)?,
        MANAGED_SYSTEMD_RESOURCE_PREFIX,
        vec![MANAGED_SYSTEMD_CHANGE_KEY.into()],
    )?
    .with_resource_suffix(MANAGED_SYSTEMD_RESOURCE_SUFFIX)?;
    Ok(OperationDescriptor::try_new(
        OperationId::new(MANAGED_SYSTEMD_REGISTERED_OPERATION_ID)?,
        OperationClass::ManagedExternalEffect,
        Some(RiskClass::SecuritySensitive),
        Some(binding),
    )?)
}

fn transient_audio_volume_descriptor() -> Result<OperationDescriptor, TrustedOperationRegistryError>
{
    let binding = OperationEffectBinding::try_new(
        ProviderId::new(TRANSIENT_AUDIO_PROVIDER)?,
        CapabilityId::new(TRANSIENT_AUDIO_CAPABILITY)?,
        TRANSIENT_AUDIO_RESOURCE_PREFIX,
        vec![TRANSIENT_AUDIO_VOLUME_CHANGE_KEY.into()],
    )?;
    Ok(OperationDescriptor::try_new(
        OperationId::new(TRANSIENT_AUDIO_VOLUME_OPERATION_ID)?,
        OperationClass::TransientExternalEffect,
        Some(RiskClass::UserState),
        Some(binding),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_binds_the_qualified_managed_systemd_operation() {
        let registry =
            trusted_builtin_operation_registry().unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(registry.len(), 2);

        let operation_id = OperationId::new(MANAGED_SYSTEMD_REGISTERED_OPERATION_ID)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let descriptor = registry
            .descriptor(&operation_id)
            .unwrap_or_else(|| unreachable!("managed systemd operation is not registered"));
        assert_eq!(descriptor.class(), OperationClass::ManagedExternalEffect);
        assert_eq!(descriptor.risk_floor(), Some(RiskClass::SecuritySensitive));

        let binding = descriptor
            .effect_binding()
            .unwrap_or_else(|| unreachable!("managed external effect has no effect binding"));
        assert_eq!(binding.provider().as_str(), MANAGED_SYSTEMD_PROVIDER);
        assert_eq!(
            binding.observation_capability().as_str(),
            MANAGED_SYSTEMD_CAPABILITY
        );
        assert_eq!(binding.resource_prefix(), MANAGED_SYSTEMD_RESOURCE_PREFIX);
        assert_eq!(
            binding.resource_suffix(),
            Some(MANAGED_SYSTEMD_RESOURCE_SUFFIX)
        );
        assert!(binding.matches_resource("systemd:unit:linura-managed-example.service"));
        assert!(!binding.matches_resource("systemd:unit:linura-managed-example.timer"));
        assert_eq!(
            binding
                .change_keys()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![MANAGED_SYSTEMD_CHANGE_KEY]
        );
    }

    #[test]
    fn builtin_registry_binds_exact_session_audio_volume_operation() {
        let registry =
            trusted_builtin_operation_registry().unwrap_or_else(|error| unreachable!("{error}"));
        let operation_id = OperationId::new(TRANSIENT_AUDIO_VOLUME_OPERATION_ID)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let descriptor = registry
            .descriptor(&operation_id)
            .unwrap_or_else(|| unreachable!("session audio volume operation is not registered"));
        assert_eq!(descriptor.class(), OperationClass::TransientExternalEffect);
        assert_eq!(descriptor.risk_floor(), Some(RiskClass::UserState));

        let binding = descriptor
            .effect_binding()
            .unwrap_or_else(|| unreachable!("transient audio operation has no effect binding"));
        assert_eq!(binding.provider().as_str(), TRANSIENT_AUDIO_PROVIDER);
        assert_eq!(
            binding.observation_capability().as_str(),
            TRANSIENT_AUDIO_CAPABILITY
        );
        assert_eq!(binding.resource_prefix(), TRANSIENT_AUDIO_RESOURCE_PREFIX);
        assert_eq!(binding.resource_suffix(), None);
        assert!(binding.matches_resource("audio:session:output:42"));
        assert!(!binding.matches_resource("audio:session:default-output"));
        assert!(!binding.matches_resource("audio:session:input:42"));
        assert_eq!(
            binding
                .change_keys()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![TRANSIENT_AUDIO_VOLUME_CHANGE_KEY]
        );
    }

    #[test]
    fn qualified_resource_prefix_does_not_cover_arbitrary_systemd_units() {
        assert!(
            "systemd:unit:linura-managed-example.service"
                .starts_with(MANAGED_SYSTEMD_RESOURCE_PREFIX)
        );
        assert!(!"systemd:unit:ssh.service".starts_with(MANAGED_SYSTEMD_RESOURCE_PREFIX));
    }
}
