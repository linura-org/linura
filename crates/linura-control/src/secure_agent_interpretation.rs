use linura_intent::IntentProposal;
use linura_provider_sdk::{AdapterDescriptor, CapabilitylessInterpretationAdapter, NetworkAccess};

use crate::agent_interpretation::{
    ControlInterpretationEngine as InnerInterpretationEngine, InterpretationControlError,
    InterpretationInvocation, ProviderInvocationGate,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterHealth {
    Eligible(AdapterDescriptor),
    OfflineBlocked(AdapterDescriptor),
    Unavailable,
}

/// Production-facing v0.8 interpretation engine.
///
/// The generic adapter trait remains an SDK contract, but this public Control
/// surface accepts only Linura's concrete capabilityless adapter. External
/// callers therefore cannot inject arbitrary in-process callbacks into Control.
///
/// ```compile_fail
/// use linura_control::ControlInterpretationEngine;
/// use linura_provider_sdk::InterpretationAdapter;
///
/// fn cannot_register_arbitrary_callback(
///     engine: &mut ControlInterpretationEngine,
///     adapter: Box<dyn InterpretationAdapter>,
/// ) {
///     let _ = engine.register_adapter(adapter);
/// }
/// ```
#[derive(Debug, Default)]
pub struct ControlInterpretationEngine {
    inner: InnerInterpretationEngine,
}

impl ControlInterpretationEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: InnerInterpretationEngine::new(),
        }
    }

    #[must_use]
    pub fn invocation_gate(&self) -> ProviderInvocationGate {
        self.inner.invocation_gate()
    }

    pub fn register_adapter(
        &mut self,
        adapter: CapabilitylessInterpretationAdapter,
    ) -> Result<(), InterpretationControlError> {
        self.inner.register_adapter(Box::new(adapter))
    }

    /// Metadata-only discovery. Adapter code is not invoked to answer
    /// eligibility, including in offline mode.
    #[must_use]
    pub fn eligible_adapters(&self, offline: bool) -> Vec<AdapterDescriptor> {
        self.inner.eligible_adapters(offline)
    }

    /// Metadata-only health/admission classification for one adapter. Active
    /// provider probing is intentionally outside this query path.
    #[must_use]
    pub fn adapter_health(&self, adapter_id: &str, offline: bool) -> AdapterHealth {
        let descriptor = self
            .inner
            .eligible_adapters(false)
            .into_iter()
            .find(|candidate| candidate.adapter_id == adapter_id);
        match descriptor {
            Some(descriptor) if offline && descriptor.network_access == NetworkAccess::Required => {
                AdapterHealth::OfflineBlocked(descriptor)
            }
            Some(descriptor) => AdapterHealth::Eligible(descriptor),
            None => AdapterHealth::Unavailable,
        }
    }

    pub fn interpret_with_adapter(
        &self,
        adapter_id: &str,
        invocation: &mut InterpretationInvocation<'_>,
    ) -> Result<IntentProposal, InterpretationControlError> {
        self.inner.interpret_with_adapter(adapter_id, invocation)
    }

    pub fn interpret_with_fallback(
        &self,
        ordered_adapter_ids: &[String],
        invocation: &mut InterpretationInvocation<'_>,
    ) -> Result<IntentProposal, InterpretationControlError> {
        self.inner
            .interpret_with_fallback(ordered_adapter_ids, invocation)
    }
}
