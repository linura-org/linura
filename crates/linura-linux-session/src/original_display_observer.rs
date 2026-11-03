//! One independent retained-protection probe. Control owns current-output,
//! session and coverage queries and their cross-provider join/authorization.
use std::sync::atomic::{AtomicU64, Ordering};

use linura_core::{
    Capability, CapabilityId, DisplayRecoveryScope, ProviderId, ResourceId, SupportLevel,
};
use linura_observation::{
    DISPLAY_ORIGINAL_PROTECTION_CAPABILITY, DISPLAY_RECOVERY_PROVIDER, ObservationEnvelope,
    ProviderAvailability, ProviderHealth,
};
use linura_provider_sdk::{Observer, ProviderError};

use crate::{NativeSessionChannel, NativeSessionRole};

#[derive(Debug)]
pub struct NativeOriginalDisplayObserver {
    channel: NativeSessionChannel,
    sequence: AtomicU64,
}
impl NativeOriginalDisplayObserver {
    pub fn new(channel: NativeSessionChannel) -> Result<Self, String> {
        channel.require_role(NativeSessionRole::Control)?;
        Ok(Self {
            channel,
            sequence: AtomicU64::new(0),
        })
    }
}
impl Observer for NativeOriginalDisplayObserver {
    fn observer_id(&self) -> ProviderId {
        ProviderId::new(DISPLAY_RECOVERY_PROVIDER)
            .unwrap_or_else(|e| unreachable!("fixed provider: {e}"))
    }
    fn observation_capabilities(&self) -> Vec<Capability> {
        vec![Capability {
            id: CapabilityId::new(DISPLAY_ORIGINAL_PROTECTION_CAPABILITY)
                .unwrap_or_else(|e| unreachable!("fixed capability: {e}")),
            provider: Some(self.observer_id()),
            support: SupportLevel::Supported,
            reason: Some("retained original protection probe; no restoration authority".into()),
        }]
    }
    fn supports_observation(&self, capability: &CapabilityId) -> bool {
        capability.as_str() == DISPLAY_ORIGINAL_PROTECTION_CAPABILITY
    }
    fn requires_live_health_preflight(&self) -> bool {
        false
    }
    fn health(&self) -> ProviderHealth {
        let result = self.channel.require_role(NativeSessionRole::Control);
        ProviderHealth {
            provider: self.observer_id(),
            availability: if result.is_ok() {
                ProviderAvailability::Available
            } else {
                ProviderAvailability::Unavailable
            },
            reason: result.err(),
        }
    }
    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        Err(ProviderError::Unsupported(
            "original protection requires an exact retained-attempt and replacement scope".into(),
        ))
    }
    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if !self.supports_observation(capability) {
            return Err(ProviderError::Unsupported(
                "original protection capability is unsupported".into(),
            ));
        }
        let scope = DisplayRecoveryScope::from_resource(resource)
            .map_err(|e| ProviderError::InvalidState(e.to_string()))?;
        let sequence = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| {
                ProviderError::Unavailable("original display protection sequence exhausted".into())
            })?;
        self.channel
            .observe_original_display_protection(&scope, sequence + 1)
            .map_err(ProviderError::Unavailable)
    }
}
