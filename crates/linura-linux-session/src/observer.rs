use std::sync::atomic::{AtomicU64, Ordering};

use linura_core::{Capability, CapabilityId, ProviderId, ResourceId, SessionLockId, SupportLevel};
use linura_observation::{ObservationEnvelope, ProviderAvailability, ProviderHealth};
use linura_provider_sdk::{Observer, ProviderError};

#[derive(Debug)]
pub struct NativePowerPermissionObserver {
    channel: NativeSessionChannel,
    sequence: AtomicU64,
}

impl NativePowerPermissionObserver {
    pub fn new(channel: NativeSessionChannel) -> Result<Self, String> {
        channel.require_role(NativeSessionRole::Control)?;
        Ok(Self {
            channel,
            sequence: AtomicU64::new(0),
        })
    }
}

impl Observer for NativePowerPermissionObserver {
    fn observer_id(&self) -> ProviderId {
        ProviderId::new("polkit").unwrap_or_else(|e| unreachable!("fixed provider: {e}"))
    }
    fn observation_capabilities(&self) -> Vec<Capability> {
        vec![Capability {
            id: CapabilityId::new("session.power.permission.observe").unwrap_or_else(|e| unreachable!("fixed capability: {e}")),
            provider: Some(self.observer_id()), support: SupportLevel::Supported,
            reason: Some("read-only original-session permission; no interaction, approval or dispatch authority".into()),
        }]
    }
    fn supports_observation(&self, capability: &CapabilityId) -> bool {
        capability.as_str() == "session.power.permission.observe"
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
            "power permission requires an exact own-session transition".into(),
        ))
    }
    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if !self.supports_observation(capability) {
            return Err(ProviderError::Unsupported(
                "native permission capability is unsupported".into(),
            ));
        }
        let transition = linura_core::SessionTransitionId::from_permission_resource(resource)
            .map_err(|e| ProviderError::InvalidState(e.to_string()))?;
        let sequence = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| {
                ProviderError::Unavailable("native permission sequence exhausted".into())
            })?;
        self.channel
            .observe_power_permission(&transition, sequence + 1)
            .map_err(ProviderError::Unavailable)
    }
}

use crate::{NativeSessionChannel, NativeSessionRole};

#[derive(Debug)]
pub struct NativeLockObserver {
    channel: NativeSessionChannel,
    provider: ProviderId,
    capability: CapabilityId,
    sequence: AtomicU64,
}

impl NativeLockObserver {
    pub fn new(channel: NativeSessionChannel) -> Result<Self, String> {
        channel.require_role(NativeSessionRole::Control)?;
        Ok(Self {
            channel,
            provider: ProviderId::new("session-locker").map_err(|e| e.to_string())?,
            capability: CapabilityId::new("session.secure-lock.observe")
                .map_err(|e| e.to_string())?,
            sequence: AtomicU64::new(0),
        })
    }
}

impl Observer for NativeLockObserver {
    fn observer_id(&self) -> ProviderId {
        self.provider.clone()
    }

    fn observation_capabilities(&self) -> Vec<Capability> {
        vec![Capability { id: self.capability.clone(), provider: Some(self.provider.clone()),
            support: SupportLevel::Supported, reason: Some("exact own-session native lock evidence; runtime attestation is required for every probe".into()) }]
    }

    fn supports_observation(&self, capability: &CapabilityId) -> bool {
        capability == &self.capability
    }
    fn requires_live_health_preflight(&self) -> bool {
        false
    }

    fn health(&self) -> ProviderHealth {
        let result = self.channel.require_role(NativeSessionRole::Control);
        ProviderHealth {
            provider: self.provider.clone(),
            availability: if result.is_ok() {
                ProviderAvailability::Available
            } else {
                ProviderAvailability::Unavailable
            },
            reason: result.err(),
        }
    }

    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        // Discovery is an own-UID query at the authenticated Control boundary,
        // not an adapter-wide enumeration of other users' session handles.
        Err(ProviderError::Unsupported(
            "native lock resources require exact own-session discovery".into(),
        ))
    }

    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if !self.supports_observation(capability) {
            return Err(ProviderError::Unsupported(
                "native lock capability is unsupported".into(),
            ));
        }
        let lock = SessionLockId::from_resource(resource)
            .map_err(|e| ProviderError::InvalidState(e.to_string()))?;
        let sequence = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| {
                ProviderError::Unavailable("native lock observation sequence exhausted".into())
            })?;
        self.channel
            .observe_lock(&lock, sequence + 1)
            .map_err(ProviderError::Unavailable)
    }
}
