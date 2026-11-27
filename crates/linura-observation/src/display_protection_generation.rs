//! Fresh supervised protection-service generation only. This observation says
//! nothing about current scanout, retained ownership, rollback or permission.
use crate::display::{number, text};
use crate::{
    DISPLAY_RECOVERY_PROVIDER, DisplayEvidenceError, ObservationAuthority, ObservationEnvelope,
    ObservedValue,
};
use linura_core::{BootId, DisplayProtectionInvocationId, ResourceId};
use std::collections::BTreeMap;

pub const DISPLAY_PROTECTION_GENERATION_CAPABILITY: &str = "display.protection-generation.observe";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayProtectionGenerationFacts {
    boot: BootId,
    invocation: DisplayProtectionInvocationId,
    sampled_boot_ms: u64,
}
impl DisplayProtectionGenerationFacts {
    pub fn new(
        boot: BootId,
        invocation: DisplayProtectionInvocationId,
        sampled_boot_ms: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if sampled_boot_ms == 0 {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(Self {
            boot,
            invocation,
            sampled_boot_ms,
        })
    }
    pub fn resource(boot: &BootId) -> Result<ResourceId, DisplayEvidenceError> {
        ResourceId::new(format!("display:protection:{}", boot.as_str()))
            .map_err(|_| DisplayEvidenceError::Identity)
    }
    pub fn boot_from_resource(resource: &ResourceId) -> Result<BootId, DisplayEvidenceError> {
        let boot = resource
            .as_str()
            .strip_prefix("display:protection:")
            .ok_or(DisplayEvidenceError::Identity)?;
        let boot = BootId::new(boot).map_err(|_| DisplayEvidenceError::Identity)?;
        if Self::resource(&boot)? != *resource {
            return Err(DisplayEvidenceError::Identity);
        }
        Ok(boot)
    }
    pub fn attributes(&self) -> BTreeMap<String, ObservedValue> {
        BTreeMap::from([
            ("protection_generation_schema".into(), ObservedValue::U64(1)),
            (
                "protection_invocation".into(),
                ObservedValue::Text(self.invocation.as_str().into()),
            ),
            (
                "sampled_boot_ms".into(),
                ObservedValue::U64(self.sampled_boot_ms),
            ),
        ])
    }
    pub fn from_envelope(
        sample: &ObservationEnvelope,
        boot: &BootId,
        now: u64,
    ) -> Result<Self, DisplayEvidenceError> {
        if sample.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || sample.capability.as_str() != DISPLAY_PROTECTION_GENERATION_CAPABILITY
            || sample.authority != ObservationAuthority::NativeApi
            || sample.sequence == 0
            || sample.resource != Self::resource(boot)?
        {
            return Err(DisplayEvidenceError::Identity);
        }
        if sample.observed_at_unix_ms == 0
            || sample.valid_for_ms == 0
            || sample.valid_for_ms > 2000
            || sample
                .observed_at_unix_ms
                .checked_add(sample.valid_for_ms)
                .is_none()
            || now
                .checked_sub(sample.observed_at_unix_ms)
                .is_none_or(|age| age >= sample.valid_for_ms)
        {
            return Err(DisplayEvidenceError::Freshness);
        }
        let a = &sample.attributes;
        if a.len() != 3 || number(a, "protection_generation_schema")? != 1 {
            return Err(DisplayEvidenceError::Shape);
        }
        let result = Self::new(
            boot.clone(),
            DisplayProtectionInvocationId::new(text(a, "protection_invocation")?)
                .map_err(|_| DisplayEvidenceError::Shape)?,
            number(a, "sampled_boot_ms")?,
        )?;
        if result.attributes() != *a {
            return Err(DisplayEvidenceError::Shape);
        }
        Ok(result)
    }
    #[must_use]
    pub const fn boot(&self) -> &BootId {
        &self.boot
    }
    #[must_use]
    pub const fn invocation(&self) -> &DisplayProtectionInvocationId {
        &self.invocation
    }
    #[must_use]
    pub const fn sampled_boot_ms(&self) -> u64 {
        self.sampled_boot_ms
    }
}

#[cfg(test)]
mod tests;
