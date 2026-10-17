//! One invocation-scoped native observer. Binding only selects which received
//! transport peer to re-attest; it never caches native authority or permits an
//! effect. Transport names stay inside this concrete adapter, outside Control.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use linura_core::{
    Capability, CapabilityId, ProviderId, ResourceId, SleepInvocationId, SupportLevel,
};
use linura_observation::{ObservationEnvelope, ProviderAvailability, ProviderHealth};
use linura_provider_sdk::{Observer, ProviderError};

use crate::{NativeSessionChannel, NativeSessionRole};

#[derive(Clone, Debug, Eq, PartialEq)]
struct EntryContext {
    generation: u64,
    sender: String,
    event: SleepInvocationId,
}
#[derive(Debug, Default)]
struct EntrySlot {
    generation: u64,
    active: Option<EntryContext>,
}
impl EntrySlot {
    fn bind(&mut self, sender: String, event: SleepInvocationId) -> Result<EntryContext, String> {
        if self.active.is_some() {
            return Err("another native sleep invocation is already bound".into());
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or("native sleep scope generation exhausted")?;
        let context = EntryContext {
            generation,
            sender,
            event,
        };
        self.generation = generation;
        self.active = Some(context.clone());
        Ok(context)
    }
    fn release(&mut self, expected: &EntryContext) {
        if self.active.as_ref() == Some(expected) {
            self.active = None;
        }
    }
}

/// Concrete composition handle, not a public client or policy interface.
/// `begin_received_sender` accepts only the sender from received bus metadata.
#[derive(Debug)]
pub struct NativeSleepEntryBinding {
    channel: NativeSessionChannel,
    slot: Arc<Mutex<EntrySlot>>,
}

/// Non-cloneable scope. Dropping it removes observation availability, not an
/// inhibitor or security-coverage fence; those have separate native lifetimes.
#[derive(Debug)]
pub struct NativeSleepEntryGuard {
    slot: Arc<Mutex<EntrySlot>>,
    context: EntryContext,
}
impl NativeSleepEntryGuard {
    #[must_use]
    pub const fn event(&self) -> &SleepInvocationId {
        &self.context.event
    }
}
impl Drop for NativeSleepEntryGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.slot.lock() {
            slot.release(&self.context);
        }
        // A poisoned slot remains unusable; it is never silently reset.
    }
}
impl NativeSleepEntryBinding {
    /// Never call with a method argument, environment variable or saved sender.
    /// Every subsequent observer probe independently re-attests the live helper,
    /// supervisor, unit invocation, executable and pre-kernel phase.
    pub fn begin_received_sender(&self, sender: &str) -> Result<NativeSleepEntryGuard, String> {
        if self
            .slot
            .lock()
            .map_err(|_| "native sleep scope is poisoned")?
            .active
            .is_some()
        {
            return Err("another native sleep invocation is already bound".into());
        }
        let entry = self.channel.attest_sleep_entry_sender(sender, 1)?;
        let context = self
            .slot
            .lock()
            .map_err(|_| "native sleep scope is poisoned")?
            .bind(sender.into(), entry.event().clone())?;
        Ok(NativeSleepEntryGuard {
            slot: self.slot.clone(),
            context,
        })
    }
}

#[derive(Debug)]
pub struct NativeSleepEntryObserver {
    channel: NativeSessionChannel,
    slot: Arc<Mutex<EntrySlot>>,
    sequence: AtomicU64,
}
impl NativeSleepEntryObserver {
    pub fn scoped(
        channel: NativeSessionChannel,
    ) -> Result<(Self, NativeSleepEntryBinding), String> {
        channel.require_role(NativeSessionRole::Control)?;
        let slot = Arc::new(Mutex::new(EntrySlot::default()));
        Ok((
            Self {
                channel: channel.clone(),
                slot: slot.clone(),
                sequence: AtomicU64::new(0),
            },
            NativeSleepEntryBinding { channel, slot },
        ))
    }
}
impl Observer for NativeSleepEntryObserver {
    fn observer_id(&self) -> ProviderId {
        ProviderId::new("system-sleep").unwrap_or_else(|e| unreachable!("fixed provider: {e}"))
    }
    fn observation_capabilities(&self) -> Vec<Capability> {
        vec![Capability { id: CapabilityId::new("session.sleep-entry.observe").unwrap_or_else(|e| unreachable!("fixed capability: {e}")), provider: Some(self.observer_id()), support: SupportLevel::Supported, reason: Some("one live, freshly attested pre-kernel helper invocation only; never cached signal authority".into()) }]
    }
    fn supports_observation(&self, capability: &CapabilityId) -> bool {
        capability.as_str() == "session.sleep-entry.observe"
    }
    fn requires_live_health_preflight(&self) -> bool {
        false
    }
    fn health(&self) -> ProviderHealth {
        let available = self.slot.lock().is_ok_and(|slot| slot.active.is_some());
        ProviderHealth {
            provider: self.observer_id(),
            availability: if available {
                ProviderAvailability::Available
            } else {
                ProviderAvailability::Unavailable
            },
            reason: Some(
                "availability is not native event evidence; each probe re-attests the helper"
                    .into(),
            ),
        }
    }
    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        Err(ProviderError::Unsupported(
            "sleep entry requires an exact received helper scope".into(),
        ))
    }
    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if !self.supports_observation(capability) {
            return Err(ProviderError::Unsupported(
                "native sleep capability is unsupported".into(),
            ));
        }
        let context = self
            .slot
            .lock()
            .map_err(|_| ProviderError::Unavailable("native sleep scope is poisoned".into()))?
            .active
            .clone()
            .ok_or_else(|| {
                ProviderError::Unavailable("no live native sleep scope is bound".into())
            })?;
        if context
            .event
            .resource_id()
            .map_err(|e| ProviderError::InvalidState(e.to_string()))?
            != *resource
        {
            return Err(ProviderError::Unsupported(
                "native sleep resource differs from received invocation".into(),
            ));
        }
        let sequence = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| {
                ProviderError::Unavailable("native sleep observation sequence exhausted".into())
            })?;
        let fresh = self
            .channel
            .attest_sleep_entry_sender(&context.sender, sequence + 1)
            .map_err(ProviderError::Unavailable)?;
        if fresh.event() != &context.event
            || self
                .slot
                .lock()
                .map_err(|_| ProviderError::Unavailable("native sleep scope is poisoned".into()))?
                .active
                .as_ref()
                != Some(&context)
        {
            return Err(ProviderError::Unavailable(
                "native sleep invocation changed during observation".into(),
            ));
        }
        Ok(fresh.observation().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn value<T, E: std::fmt::Debug>(r: Result<T, E>) -> T {
        r.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    fn event() -> SleepInvocationId {
        value(SleepInvocationId::new(
            value(linura_core::BootId::new(
                "abcd1234-1234-4567-89ab-0123456789ab",
            )),
            "11223344-1234-4567-89ab-0123456789ab",
        ))
    }
    #[test]
    fn scope_is_exclusive_and_old_cleanup_cannot_retire_a_later_binding() {
        let mut slot = EntrySlot::default();
        let first = value(slot.bind(":1.1".into(), event()));
        assert!(slot.bind(":1.2".into(), event()).is_err());
        let mut substituted = first.clone();
        substituted.sender = ":1.2".into();
        slot.release(&substituted);
        assert_eq!(slot.active.as_ref(), Some(&first));
        slot.release(&first);
        let second = value(slot.bind(":1.1".into(), event()));
        assert_ne!(first.generation, second.generation);
        slot.release(&first);
        assert_eq!(slot.active.as_ref(), Some(&second));
    }
    #[test]
    fn guard_drop_removes_scope_and_generation_exhaustion_never_wraps() {
        let slot = Arc::new(Mutex::new(EntrySlot::default()));
        let context = value(value(slot.lock()).bind(":1.1".into(), event()));
        let guard = NativeSleepEntryGuard {
            slot: slot.clone(),
            context,
        };
        assert_eq!(guard.event(), &event());
        drop(guard);
        assert!(value(slot.lock()).active.is_none());
        value(slot.lock()).generation = u64::MAX;
        assert!(value(slot.lock()).bind(":1.2".into(), event()).is_err());
        assert!(value(slot.lock()).active.is_none());
    }
}
