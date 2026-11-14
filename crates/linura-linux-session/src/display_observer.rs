use crate::{NativeSessionChannel, NativeSessionRole};
use linura_core::{
    Capability, CapabilityId, DisplayRecoveryScope, DisplayTopologyId, ProviderId, ResourceId,
    SupportLevel,
};
use linura_observation::{
    DISPLAY_NATIVE_CURRENT_CAPABILITY, DISPLAY_NATIVE_HANDOFF_CAPABILITY,
    DISPLAY_ORDINARY_HANDOFF_CAPABILITY, DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY,
    DISPLAY_OUTPUTS_CAPABILITY, DISPLAY_PROVIDER, ObservationEnvelope, ProviderAvailability,
    ProviderHealth,
};
use linura_provider_sdk::{Observer, ProviderError};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub struct NativeDisplayObserver {
    channel: NativeSessionChannel,
    sequence: AtomicU64,
}
impl NativeDisplayObserver {
    pub fn new(channel: NativeSessionChannel) -> Result<Self, String> {
        channel.require_role(NativeSessionRole::Control)?;
        Ok(Self {
            channel,
            sequence: AtomicU64::new(0),
        })
    }
}
impl Observer for NativeDisplayObserver {
    fn observer_id(&self) -> ProviderId {
        ProviderId::new(DISPLAY_PROVIDER).unwrap_or_else(|e| unreachable!("fixed provider: {e}"))
    }
    fn observation_capabilities(&self) -> Vec<Capability> {
        vec![Capability {
            id: CapabilityId::new(DISPLAY_OUTPUTS_CAPABILITY)
                .unwrap_or_else(|e| unreachable!("fixed capability: {e}")),
            provider: Some(self.observer_id()),
            support: SupportLevel::Supported,
            reason: Some("exact own-session native output inventory; no dispatch authority".into()),
        }, Capability {
            id: CapabilityId::new(DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY).unwrap_or_else(|e| unreachable!("fixed capability: {e}")),
            provider: Some(self.observer_id()), support: SupportLevel::Supported,
            reason: Some("read-only original-restoration KMS/post-write frame probe; no release authority".into()),
        }, Capability {
            id: CapabilityId::new(DISPLAY_NATIVE_HANDOFF_CAPABILITY).unwrap_or_else(|e| unreachable!("fixed capability: {e}")),
            provider: Some(self.observer_id()), support: SupportLevel::Supported,
            reason: Some("read-only first ordinary-frame comparison with original deadlines; no release authority".into()),
        }, Capability {
            id: CapabilityId::new(DISPLAY_ORDINARY_HANDOFF_CAPABILITY).unwrap_or_else(|e| unreachable!("fixed capability: {e}")),
            provider: Some(self.observer_id()), support: SupportLevel::Supported,
            reason: Some("read-only same-invocation ordinary terminal KMS/first frames; no completion authority".into()),
        }, Capability {
            id: CapabilityId::new(DISPLAY_NATIVE_CURRENT_CAPABILITY).unwrap_or_else(|e| unreachable!("fixed capability: {e}")),
            provider: Some(self.observer_id()), support: SupportLevel::Supported,
            reason: Some("read-only current KMS/frames under the original live completion lifetime; no release authority".into()),
        }]
    }
    fn supports_observation(&self, capability: &CapabilityId) -> bool {
        matches!(
            capability.as_str(),
            DISPLAY_OUTPUTS_CAPABILITY
                | DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY
                | DISPLAY_NATIVE_HANDOFF_CAPABILITY
                | DISPLAY_NATIVE_CURRENT_CAPABILITY
                | DISPLAY_ORDINARY_HANDOFF_CAPABILITY
        )
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
            "native display discovery requires an authenticated own-session query".into(),
        ))
    }
    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if !self.supports_observation(capability) {
            return Err(ProviderError::Unsupported(
                "native display capability is unsupported".into(),
            ));
        }
        let sequence = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| ProviderError::Unavailable("native display sequence exhausted".into()))?;
        if capability.as_str() == DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY {
            let scope = DisplayRecoveryScope::from_resource(resource)
                .map_err(|e| ProviderError::InvalidState(e.to_string()))?;
            return self
                .channel
                .observe_original_display_presentation(&scope, sequence + 1)
                .map_err(ProviderError::Unavailable);
        }
        if capability.as_str() == DISPLAY_NATIVE_CURRENT_CAPABILITY {
            let scope = DisplayRecoveryScope::from_resource(resource)
                .map_err(|e| ProviderError::InvalidState(e.to_string()))?;
            return self
                .channel
                .observe_native_display_current(&scope, sequence + 1)
                .map_err(ProviderError::Unavailable);
        }
        if capability.as_str() == DISPLAY_NATIVE_HANDOFF_CAPABILITY {
            let scope = DisplayRecoveryScope::from_resource(resource)
                .map_err(|e| ProviderError::InvalidState(e.to_string()))?;
            return self
                .channel
                .observe_native_display_handoff(&scope, sequence + 1)
                .map_err(ProviderError::Unavailable);
        }
        if capability.as_str() == DISPLAY_ORDINARY_HANDOFF_CAPABILITY {
            let scope = linura_core::DisplayOrdinaryReleaseScope::from_resource(resource)
                .map_err(|e| ProviderError::InvalidState(e.to_string()))?;
            return self
                .channel
                .observe_ordinary_display_handoff(&scope, sequence + 1)
                .map_err(ProviderError::Unavailable);
        }
        let target = DisplayTopologyId::from_resource(resource)
            .map_err(|e| ProviderError::InvalidState(e.to_string()))?;
        self.channel
            .observe_display(&target, sequence + 1)
            .map_err(ProviderError::Unavailable)
    }
}
