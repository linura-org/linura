#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

use linura_core::{CapabilityId, ProviderId, ResourceId};

mod display;
pub use display::{
    DISPLAY_COVERAGE_CAPABILITY, DISPLAY_OUTPUTS_CAPABILITY, DISPLAY_PROVIDER,
    DisplayEvidenceError, DisplayObservationFacts, display_observation_attributes,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationAuthority {
    NativeApi,
    Kernel,
    Filesystem,
    SyntheticTest,
}

impl ObservationAuthority {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeApi => "native-api",
            Self::Kernel => "kernel",
            Self::Filesystem => "filesystem",
            Self::SyntheticTest => "synthetic-test",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservedValue {
    Text(String),
    Bool(bool),
    U64(u64),
    I64(i64),
}

impl Display for ObservedValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text(value) => f.write_str(value),
            Self::Bool(value) => write!(f, "{value}"),
            Self::U64(value) => write!(f, "{value}"),
            Self::I64(value) => write!(f, "{value}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProviderAvailability {
    Available,
    Degraded,
    Unavailable,
}

impl ProviderAvailability {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderHealth {
    pub provider: ProviderId,
    pub availability: ProviderAvailability,
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshnessState {
    Current,
    Stale,
    Future,
}

impl FreshnessState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Stale => "stale",
            Self::Future => "future",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationEnvelope {
    pub provider: ProviderId,
    pub resource: ResourceId,
    pub capability: CapabilityId,
    pub authority: ObservationAuthority,
    pub observed_at_unix_ms: u64,
    pub valid_for_ms: u64,
    pub sequence: u64,
    pub attributes: BTreeMap<String, ObservedValue>,
}

impl ObservationEnvelope {
    pub fn validate(
        &self,
        expected_provider: &ProviderId,
        expected_resource: &ResourceId,
        expected_capability: &CapabilityId,
    ) -> Result<(), ObservationValidationError> {
        if &self.provider != expected_provider {
            return Err(ObservationValidationError::ProviderMismatch);
        }
        if &self.resource != expected_resource {
            return Err(ObservationValidationError::ResourceMismatch);
        }
        if &self.capability != expected_capability {
            return Err(ObservationValidationError::CapabilityMismatch);
        }
        if self.observed_at_unix_ms == 0 {
            return Err(ObservationValidationError::MissingTimestamp);
        }
        if self.valid_for_ms == 0 {
            return Err(ObservationValidationError::InvalidValidityWindow);
        }
        if self.attributes.is_empty() {
            return Err(ObservationValidationError::EmptyEvidence);
        }
        for key in self.attributes.keys() {
            if key.trim().is_empty() || key.chars().any(char::is_control) {
                return Err(ObservationValidationError::InvalidAttributeKey);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn freshness_at(&self, now_unix_ms: u64) -> FreshnessState {
        if now_unix_ms < self.observed_at_unix_ms {
            return FreshnessState::Future;
        }
        let expires_at = self.observed_at_unix_ms.saturating_add(self.valid_for_ms);
        if now_unix_ms <= expires_at {
            FreshnessState::Current
        } else {
            FreshnessState::Stale
        }
    }

    pub fn require_current(&self, now_unix_ms: u64) -> Result<(), ObservationValidationError> {
        match self.freshness_at(now_unix_ms) {
            FreshnessState::Current => Ok(()),
            FreshnessState::Stale => Err(ObservationValidationError::StaleEvidence),
            FreshnessState::Future => Err(ObservationValidationError::FutureEvidence),
        }
    }

    /// Opaque, collision-resistant identifier for one observation envelope.
    ///
    /// Identity components use length prefixes because provider/resource/
    /// capability IDs may themselves contain punctuation such as `:`.
    #[must_use]
    pub fn evidence_id(&self) -> String {
        let provider = self.provider.as_str();
        let resource = self.resource.as_str();
        let capability = self.capability.as_str();
        format!(
            "observation:v1:{}:{provider}:{}:{resource}:{}:{capability}:{}:{}",
            provider.len(),
            resource.len(),
            capability.len(),
            self.observed_at_unix_ms,
            self.sequence
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationValidationError {
    ProviderMismatch,
    ResourceMismatch,
    CapabilityMismatch,
    MissingTimestamp,
    InvalidValidityWindow,
    EmptyEvidence,
    InvalidAttributeKey,
    StaleEvidence,
    FutureEvidence,
}

impl Display for ObservationValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProviderMismatch => f.write_str("observation provider identity mismatch"),
            Self::ResourceMismatch => f.write_str("observation resource identity mismatch"),
            Self::CapabilityMismatch => f.write_str("observation capability identity mismatch"),
            Self::MissingTimestamp => f.write_str("observation timestamp is missing"),
            Self::InvalidValidityWindow => {
                f.write_str("observation validity window must be greater than zero")
            }
            Self::EmptyEvidence => f.write_str("observation evidence cannot be empty"),
            Self::InvalidAttributeKey => f.write_str("observation attribute key is invalid"),
            Self::StaleEvidence => f.write_str("observation evidence is stale"),
            Self::FutureEvidence => f.write_str("observation timestamp is in the future"),
        }
    }
}

impl std::error::Error for ObservationValidationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::ValidationError;

    fn id<T>(result: Result<T, ValidationError>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn observation() -> ObservationEnvelope {
        ObservationEnvelope {
            provider: id(ProviderId::new("systemd")),
            resource: id(ResourceId::new("systemd:unit:sshd.service")),
            capability: id(CapabilityId::new("systemd.unit.observe")),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: 1_000,
            valid_for_ms: 500,
            sequence: 7,
            attributes: BTreeMap::from([(
                "active_state".into(),
                ObservedValue::Text("active".into()),
            )]),
        }
    }

    #[test]
    fn freshness_is_fail_closed_outside_validity_window() {
        let observation = observation();
        assert_eq!(observation.freshness_at(999), FreshnessState::Future);
        assert_eq!(observation.freshness_at(1_500), FreshnessState::Current);
        assert_eq!(observation.freshness_at(1_501), FreshnessState::Stale);
        assert_eq!(
            observation.require_current(999),
            Err(ObservationValidationError::FutureEvidence)
        );
        assert_eq!(
            observation.require_current(1_501),
            Err(ObservationValidationError::StaleEvidence)
        );
    }

    #[test]
    fn validation_rejects_resource_substitution() {
        let observation = observation();
        let provider = id(ProviderId::new("systemd"));
        let resource = id(ResourceId::new("systemd:unit:dbus.service"));
        let capability = id(CapabilityId::new("systemd.unit.observe"));
        assert_eq!(
            observation.validate(&provider, &resource, &capability),
            Err(ObservationValidationError::ResourceMismatch)
        );
    }

    #[test]
    fn evidence_id_binds_provider_resource_capability_time_and_sequence() {
        let observation = observation();
        let original = observation.evidence_id();
        let mut other_capability = observation;
        other_capability.capability = id(CapabilityId::new("systemd.unit.metadata.observe"));
        assert_ne!(original, other_capability.evidence_id());
        assert_eq!(
            original,
            "observation:v1:7:systemd:25:systemd:unit:sshd.service:20:systemd.unit.observe:1000:7"
        );
    }
}
