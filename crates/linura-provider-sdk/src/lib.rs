#![forbid(unsafe_code)]

// The established authority-neutral observation/component contract remains exported
// unchanged through this module. Repository boundary checks intentionally pin
// these source markers: `pub trait Observer` and
// `Result<ObservationEnvelope, ProviderError>`.
mod provider_contract;
pub use provider_contract::*;

mod capabilityless_adapter;
pub use capabilityless_adapter::CapabilitylessInterpretationAdapter;

pub mod interpretation;
pub use interpretation::{
    AdapterDescriptor, HeaderField, InterpretationAdapter, InterpretationAdapterError,
    InterpretationRequest, MinimizedSemanticProjection, NetworkAccess, PreparedProviderInvocation,
    ProviderInvocationDeadline, ProviderInvocationOutcome, ProviderInvocationTransport,
    SemanticEntry, SemanticValue,
};
