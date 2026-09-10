use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use linura_agent_runtime::{AdmittedInterpretationAttempt, AgentError, AgentRuntime};
use linura_core::{Actor, CapabilityId, ProviderId, RequestId};
use linura_intent::{
    IntentProposal, InterpretationContextBinding, ProposalDigest, ProposalValidationError,
};
use linura_provider_sdk::{
    AdapterDescriptor, InterpretationAdapter, InterpretationAdapterError, InterpretationRequest,
    MinimizedSemanticProjection, NetworkAccess, PreparedProviderInvocation,
    ProviderInvocationDeadline, ProviderInvocationOutcome, ProviderInvocationTransport,
    ProviderResponseBudget, SemanticEntry, SemanticValue,
};

const MAX_RAW_SEMANTIC_ENTRIES: usize = 512;
const MAX_RAW_SEMANTIC_BYTES: usize = 1024 * 1024;
const MAX_ADAPTERS: usize = 128;
const MAX_ATTEMPTS: u32 = 32;
const MAX_AGGREGATE_OUTPUT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_RUNTIME_PREPARED_OUTPUT_BYTES: u32 = 2 * 1024 * 1024;

static NEXT_INVOCATION_AUTHORITY_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_INVOCATION_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Eq, PartialEq)]
pub enum RawSemanticValue {
    PublicText(String),
    /// Raw secret remains inside trusted Control. Only the optional protected
    /// reference may be projected across the runtime/provider boundary.
    Secret {
        value: String,
        protected_reference: Option<String>,
    },
    ProtectedReference(String),
    Bool(bool),
    U64(u64),
    I64(i64),
}

impl std::fmt::Debug for RawSemanticValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PublicText(value) => f.debug_tuple("PublicText").field(value).finish(),
            Self::Secret {
                protected_reference,
                ..
            } => f
                .debug_struct("Secret")
                .field("value", &"[REDACTED]")
                .field("protected_reference", protected_reference)
                .finish(),
            Self::ProtectedReference(value) => {
                f.debug_tuple("ProtectedReference").field(value).finish()
            }
            Self::Bool(value) => f.debug_tuple("Bool").field(value).finish(),
            Self::U64(value) => f.debug_tuple("U64").field(value).finish(),
            Self::I64(value) => f.debug_tuple("I64").field(value).finish(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawSemanticEntry {
    pub key: String,
    pub value: RawSemanticValue,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RawSemanticProjection {
    pub entries: Vec<RawSemanticEntry>,
}

impl RawSemanticProjection {
    pub fn minimize(&self) -> Result<MinimizedSemanticProjection, InterpretationControlError> {
        if self.entries.len() > MAX_RAW_SEMANTIC_ENTRIES {
            return Err(InterpretationControlError::InvalidSemanticProjection(
                "raw semantic projection contains too many entries".into(),
            ));
        }
        let aggregate = self.entries.iter().fold(0_usize, |total, entry| {
            let value_bytes = match &entry.value {
                RawSemanticValue::PublicText(value)
                | RawSemanticValue::ProtectedReference(value) => value.len(),
                RawSemanticValue::Secret {
                    value,
                    protected_reference,
                } => value
                    .len()
                    .saturating_add(protected_reference.as_deref().map_or(0, str::len)),
                RawSemanticValue::Bool(_) => 1,
                RawSemanticValue::U64(_) | RawSemanticValue::I64(_) => 8,
            };
            total
                .saturating_add(entry.key.len())
                .saturating_add(value_bytes)
        });
        if aggregate > MAX_RAW_SEMANTIC_BYTES {
            return Err(InterpretationControlError::InvalidSemanticProjection(
                "raw semantic projection exceeds the Control input bound".into(),
            ));
        }

        let mut minimized = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let value = match &entry.value {
                RawSemanticValue::PublicText(value) => SemanticValue::Text(value.clone()),
                RawSemanticValue::Secret {
                    protected_reference: Some(reference),
                    ..
                } => SemanticValue::ProtectedReference(reference.clone()),
                RawSemanticValue::Secret {
                    protected_reference: None,
                    ..
                } => continue,
                RawSemanticValue::ProtectedReference(value) => {
                    SemanticValue::ProtectedReference(value.clone())
                }
                RawSemanticValue::Bool(value) => SemanticValue::Bool(*value),
                RawSemanticValue::U64(value) => SemanticValue::U64(*value),
                RawSemanticValue::I64(value) => SemanticValue::I64(*value),
            };
            minimized.push(
                SemanticEntry::new(entry.key.clone(), value)
                    .map_err(InterpretationControlError::AdapterContract)?,
            );
        }
        MinimizedSemanticProjection::new(minimized)
            .map_err(InterpretationControlError::AdapterContract)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterpretationWork {
    pub request_id: RequestId,
    pub actor: Actor,
    pub context: InterpretationContextBinding,
    pub projection: MinimizedSemanticProjection,
    pub capability_refs: Vec<CapabilityId>,
}

impl InterpretationWork {
    pub fn validate(&self) -> Result<(), InterpretationControlError> {
        if self.projection.digest() != self.context.semantic_input_digest {
            return Err(InterpretationControlError::ContextMismatch);
        }
        let mut capabilities = BTreeSet::new();
        for capability in &self.capability_refs {
            if !capabilities.insert(capability.as_str()) {
                return Err(InterpretationControlError::InvalidSemanticProjection(
                    "interpretation work contains duplicate capability references".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Single, non-cloneable aggregate interpretation budget.
///
/// The first admission anchors the session's absolute wall-clock deadline to a
/// process-local monotonic `Instant`. Every later fallback attempt consumes the
/// same elapsed-time budget; callers cannot reset it by reusing a stale
/// `now_unix_ms` value.
#[derive(Debug)]
pub struct InterpretationSessionBudget {
    session_id: RequestId,
    aggregate_deadline_unix_ms: u64,
    remaining_attempts: u32,
    remaining_output_bytes: u64,
    next_attempt: u32,
    deadline_started: Option<Instant>,
    initial_deadline_remaining_ms: Option<u64>,
}

impl InterpretationSessionBudget {
    pub fn new(
        session_id: RequestId,
        aggregate_deadline_unix_ms: u64,
        max_attempts: u32,
        aggregate_output_bytes: u64,
    ) -> Result<Self, InterpretationControlError> {
        if aggregate_deadline_unix_ms == 0
            || max_attempts == 0
            || max_attempts > MAX_ATTEMPTS
            || aggregate_output_bytes == 0
            || aggregate_output_bytes > MAX_AGGREGATE_OUTPUT_BYTES
        {
            return Err(InterpretationControlError::InvalidBudget);
        }
        Ok(Self {
            session_id,
            aggregate_deadline_unix_ms,
            remaining_attempts: max_attempts,
            remaining_output_bytes: aggregate_output_bytes,
            next_attempt: 1,
            deadline_started: None,
            initial_deadline_remaining_ms: None,
        })
    }

    fn remaining_deadline_ms(
        &mut self,
        now_unix_ms: u64,
    ) -> Result<u64, InterpretationControlError> {
        let wall_remaining = self
            .aggregate_deadline_unix_ms
            .checked_sub(now_unix_ms)
            .filter(|remaining| *remaining > 0)
            .ok_or(InterpretationControlError::BudgetExhausted)?;

        if self.deadline_started.is_none() {
            self.deadline_started = Some(Instant::now());
            self.initial_deadline_remaining_ms = Some(wall_remaining);
            return Ok(wall_remaining);
        }

        let started = self
            .deadline_started
            .as_ref()
            .ok_or(InterpretationControlError::InvalidBudget)?;
        let initial_remaining = self
            .initial_deadline_remaining_ms
            .ok_or(InterpretationControlError::InvalidBudget)?;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let monotonic_remaining = initial_remaining
            .checked_sub(elapsed_ms)
            .filter(|remaining| *remaining > 0)
            .ok_or(InterpretationControlError::BudgetExhausted)?;
        Ok(monotonic_remaining.min(wall_remaining))
    }

    fn admit(
        &mut self,
        adapter_id: &str,
        now_unix_ms: u64,
        requested_output_bytes: u32,
    ) -> Result<ControlInterpretationAdmission, InterpretationControlError> {
        if self.remaining_attempts == 0
            || requested_output_bytes == 0
            || u64::from(requested_output_bytes) > self.remaining_output_bytes
        {
            return Err(InterpretationControlError::BudgetExhausted);
        }
        let remaining_deadline_ms = self.remaining_deadline_ms(now_unix_ms)?;
        let attempt_id = RequestId::new(format!(
            "{}:attempt:{}",
            self.session_id.as_str(),
            self.next_attempt
        ))
        .map_err(|error| InterpretationControlError::InvalidAttemptId(error.to_string()))?;
        self.next_attempt = self
            .next_attempt
            .checked_add(1)
            .ok_or(InterpretationControlError::BudgetExhausted)?;
        self.remaining_attempts -= 1;
        self.remaining_output_bytes -= u64::from(requested_output_bytes);
        Ok(ControlInterpretationAdmission {
            runtime: AdmittedInterpretationAttempt {
                attempt_id,
                adapter_id: adapter_id.into(),
                deadline_unix_ms: self.aggregate_deadline_unix_ms,
                runtime_output_budget_bytes: MAX_RUNTIME_PREPARED_OUTPUT_BYTES,
            },
            provider_response_budget_bytes: requested_output_bytes,
            remaining_deadline_ms,
        })
    }

    #[must_use]
    pub const fn remaining_attempts(&self) -> u32 {
        self.remaining_attempts
    }

    #[must_use]
    pub const fn remaining_output_bytes(&self) -> u64 {
        self.remaining_output_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ControlInterpretationAdmission {
    runtime: AdmittedInterpretationAttempt,
    provider_response_budget_bytes: u32,
    remaining_deadline_ms: u64,
}

#[derive(Debug)]
struct AttemptDeadline {
    deadline_unix_ms: u64,
    initial_remaining_ms: u64,
    started: Instant,
}

impl AttemptDeadline {
    fn new(
        deadline_unix_ms: u64,
        initial_remaining_ms: u64,
    ) -> Result<Self, InterpretationControlError> {
        if deadline_unix_ms == 0 || initial_remaining_ms == 0 {
            return Err(InterpretationControlError::ProviderTimeout);
        }
        Ok(Self {
            deadline_unix_ms,
            initial_remaining_ms,
            started: Instant::now(),
        })
    }

    fn remaining_ms(&self) -> Result<u64, InterpretationControlError> {
        let elapsed_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.initial_remaining_ms
            .checked_sub(elapsed_ms)
            .filter(|remaining| *remaining > 0)
            .ok_or(InterpretationControlError::ProviderTimeout)
    }

    fn ensure_live(&self) -> Result<(), InterpretationControlError> {
        self.remaining_ms().map(|_| ())
    }

    fn transport_deadline(&self) -> Result<ProviderInvocationDeadline, InterpretationControlError> {
        ProviderInvocationDeadline::new(self.deadline_unix_ms, self.remaining_ms()?)
            .map_err(InterpretationControlError::AdapterContract)
    }
}

/// One Control-owned interpretation invocation context.
///
/// Keeping the mutable invocation gate and aggregate session budget in the same
/// value makes direct and fallback paths share one admission/accounting scope.
/// The runtime still receives only a single admitted attempt at a time.
#[derive(Debug)]
pub struct InterpretationInvocation<'a> {
    pub runtime: &'a AgentRuntime,
    pub gate: &'a mut ProviderInvocationGate,
    pub work: &'a InterpretationWork,
    pub offline: bool,
    pub now_unix_ms: u64,
    pub requested_output_bytes: u32,
    pub budget: &'a mut InterpretationSessionBudget,
}

struct RegisteredAdapter {
    descriptor: AdapterDescriptor,
    adapter: Box<dyn InterpretationAdapter>,
}

pub struct ControlInterpretationEngine {
    adapters: BTreeMap<String, RegisteredAdapter>,
    invocation_authority: ProviderInvocationAuthority,
}

impl std::fmt::Debug for ControlInterpretationEngine {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlInterpretationEngine")
            .field("adapter_count", &self.adapters.len())
            .field("invocation_authority", &self.invocation_authority)
            .finish()
    }
}

impl Default for ControlInterpretationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlInterpretationEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            adapters: BTreeMap::new(),
            invocation_authority: ProviderInvocationAuthority::new(),
        }
    }

    #[must_use]
    pub fn invocation_gate(&self) -> ProviderInvocationGate {
        ProviderInvocationGate::new(&self.invocation_authority)
    }

    pub fn register_adapter(
        &mut self,
        adapter: Box<dyn InterpretationAdapter>,
    ) -> Result<(), InterpretationControlError> {
        if self.adapters.len() >= MAX_ADAPTERS {
            return Err(InterpretationControlError::AdapterRegistryFull);
        }
        // Descriptor acquisition happens once at trusted composition time. All
        // offline discovery/selection/health/fallback paths below use the stored
        // descriptor and never invoke adapter code merely to inspect metadata.
        let descriptor = adapter.descriptor();
        descriptor
            .validate()
            .map_err(InterpretationControlError::AdapterContract)?;
        if self.adapters.contains_key(&descriptor.adapter_id) {
            return Err(InterpretationControlError::DuplicateAdapter(
                descriptor.adapter_id,
            ));
        }
        self.adapters.insert(
            descriptor.adapter_id.clone(),
            RegisteredAdapter {
                descriptor,
                adapter,
            },
        );
        Ok(())
    }

    #[must_use]
    pub fn eligible_adapters(&self, offline: bool) -> Vec<AdapterDescriptor> {
        self.adapters
            .values()
            .filter(|registered| {
                !offline || registered.descriptor.network_access == NetworkAccess::None
            })
            .map(|registered| registered.descriptor.clone())
            .collect()
    }

    pub fn interpret_with_adapter(
        &self,
        adapter_id: &str,
        invocation: &mut InterpretationInvocation<'_>,
    ) -> Result<IntentProposal, InterpretationControlError> {
        invocation.work.validate()?;
        let registered = self
            .adapters
            .get(adapter_id)
            .ok_or_else(|| InterpretationControlError::AdapterUnavailable(adapter_id.into()))?;
        if invocation.offline && registered.descriptor.network_access == NetworkAccess::Required {
            return Err(InterpretationControlError::OfflineNetworkAdapter(
                adapter_id.into(),
            ));
        }

        let admission = invocation.budget.admit(
            adapter_id,
            invocation.now_unix_ms,
            invocation.requested_output_bytes,
        )?;
        let effective_now_unix_ms = admission
            .runtime
            .deadline_unix_ms
            .checked_sub(admission.remaining_deadline_ms)
            .ok_or(InterpretationControlError::InvalidBudget)?;
        let deadline = AttemptDeadline::new(
            admission.runtime.deadline_unix_ms,
            admission.remaining_deadline_ms,
        )?;
        let request = InterpretationRequest {
            request_id: invocation.work.request_id.clone(),
            actor: invocation.work.actor.clone(),
            context: invocation.work.context.clone(),
            projection: invocation.work.projection.clone(),
            capability_refs: invocation.work.capability_refs.clone(),
            max_response_bytes: admission.provider_response_budget_bytes,
            attempt_deadline_unix_ms: admission.runtime.deadline_unix_ms,
        };
        request
            .validate()
            .map_err(InterpretationControlError::AdapterContract)?;

        let prepared = invocation
            .runtime
            .execute_single_attempt(
                &admission.runtime,
                effective_now_unix_ms,
                || {
                    registered
                        .adapter
                        .prepare(&request)
                        .map_err(|error| AgentError::ProviderFailure(error.to_string()))
                },
                prepared_invocation_size,
            )
            .map_err(InterpretationControlError::Runtime)?;
        deadline.ensure_live()?;
        validate_prepared_descriptor(&registered.descriptor, &prepared)?;
        let permit = self.invocation_authority.mint(
            &admission,
            &registered.descriptor,
            request.digest(),
            prepared.digest(),
        )?;
        let outcome = invocation.gate.invoke_once(
            permit,
            &request,
            &prepared,
            effective_now_unix_ms,
            deadline.transport_deadline()?,
        )?;
        deadline.ensure_live()?;
        let response = match outcome {
            ProviderInvocationOutcome::Complete(response) => response,
            ProviderInvocationOutcome::Partial => {
                return Err(InterpretationControlError::ProviderPartialResponse);
            }
            ProviderInvocationOutcome::Timeout => {
                return Err(InterpretationControlError::ProviderTimeout);
            }
            ProviderInvocationOutcome::RateLimited => {
                return Err(InterpretationControlError::ProviderRateLimited);
            }
            ProviderInvocationOutcome::TransportFailure(reason) => {
                return Err(InterpretationControlError::ProviderTransport(reason));
            }
            ProviderInvocationOutcome::Cancelled => {
                return Err(InterpretationControlError::ProviderCancelled);
            }
        };
        if response.len()
            > usize::try_from(admission.provider_response_budget_bytes).unwrap_or(usize::MAX)
        {
            return Err(InterpretationControlError::ProviderOutputExceeded);
        }
        deadline.ensure_live()?;
        let proposal = registered
            .adapter
            .decode_complete(&request, &response)
            .map_err(InterpretationControlError::AdapterContract)?;
        deadline.ensure_live()?;
        validate_provider_proposal(&proposal, &request, &registered.descriptor)?;
        deadline.ensure_live()?;
        Ok(proposal)
    }

    /// Control-owned fallback. Every repeated invocation consumes a fresh
    /// aggregate admission and therefore a fresh one-shot invocation permit.
    pub fn interpret_with_fallback(
        &self,
        ordered_adapter_ids: &[String],
        invocation: &mut InterpretationInvocation<'_>,
    ) -> Result<IntentProposal, InterpretationControlError> {
        let mut last_failure = None;
        for adapter_id in ordered_adapter_ids {
            match self.interpret_with_adapter(adapter_id, invocation) {
                Ok(proposal) => return Ok(proposal),
                Err(error)
                    if matches!(
                        error,
                        InterpretationControlError::ProviderPartialResponse
                            | InterpretationControlError::ProviderTimeout
                            | InterpretationControlError::ProviderRateLimited
                            | InterpretationControlError::ProviderTransport(_)
                            | InterpretationControlError::ProviderCancelled
                    ) =>
                {
                    last_failure = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_failure.unwrap_or(InterpretationControlError::NoEligibleAdapter))
    }
}

#[derive(Debug)]
struct ProviderInvocationAuthority {
    authority_id: u64,
}

impl ProviderInvocationAuthority {
    fn new() -> Self {
        Self {
            authority_id: next_nonzero(&NEXT_INVOCATION_AUTHORITY_ID),
        }
    }

    fn mint(
        &self,
        admission: &ControlInterpretationAdmission,
        descriptor: &AdapterDescriptor,
        request_digest: ProposalDigest,
        prepared_digest: ProposalDigest,
    ) -> Result<ProviderInvocationPermit, InterpretationControlError> {
        admission
            .runtime
            .validate()
            .map_err(InterpretationControlError::Runtime)?;
        descriptor
            .validate()
            .map_err(InterpretationControlError::AdapterContract)?;
        if admission.runtime.adapter_id != descriptor.adapter_id {
            return Err(InterpretationControlError::InvocationBindingMismatch);
        }
        Ok(ProviderInvocationPermit {
            authority_id: self.authority_id,
            nonce: next_nonzero(&NEXT_INVOCATION_NONCE),
            attempt_id: admission.runtime.attempt_id.clone(),
            provider: descriptor.provider.clone(),
            adapter_id: descriptor.adapter_id.clone(),
            endpoint_class: descriptor.endpoint_class.clone(),
            protocol_version: descriptor.protocol_version,
            network_access: descriptor.network_access,
            request_digest,
            prepared_digest,
            deadline_unix_ms: admission.runtime.deadline_unix_ms,
            output_budget_bytes: admission.provider_response_budget_bytes,
        })
    }
}

/// Non-clone, non-serializable, process-local single-use invocation authority.
#[derive(Debug)]
pub struct ProviderInvocationPermit {
    authority_id: u64,
    nonce: u64,
    attempt_id: RequestId,
    provider: ProviderId,
    adapter_id: String,
    endpoint_class: String,
    protocol_version: u16,
    network_access: NetworkAccess,
    request_digest: ProposalDigest,
    prepared_digest: ProposalDigest,
    deadline_unix_ms: u64,
    output_budget_bytes: u32,
}

struct RegisteredTransport {
    descriptor: AdapterDescriptor,
    transport: Box<dyn ProviderInvocationTransport>,
}

pub struct ProviderInvocationGate {
    authority_id: u64,
    transports: BTreeMap<String, RegisteredTransport>,
    consumed_permits: BTreeSet<u64>,
}

impl std::fmt::Debug for ProviderInvocationGate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderInvocationGate")
            .field("transport_count", &self.transports.len())
            .field("consumed_permit_count", &self.consumed_permits.len())
            .finish()
    }
}

impl ProviderInvocationGate {
    fn new(authority: &ProviderInvocationAuthority) -> Self {
        Self {
            authority_id: authority.authority_id,
            transports: BTreeMap::new(),
            consumed_permits: BTreeSet::new(),
        }
    }

    pub fn register_transport(
        &mut self,
        descriptor: AdapterDescriptor,
        transport: Box<dyn ProviderInvocationTransport>,
    ) -> Result<(), InterpretationControlError> {
        descriptor
            .validate()
            .map_err(InterpretationControlError::AdapterContract)?;
        if self.transports.contains_key(&descriptor.adapter_id) {
            return Err(InterpretationControlError::DuplicateTransport(
                descriptor.adapter_id,
            ));
        }
        self.transports.insert(
            descriptor.adapter_id.clone(),
            RegisteredTransport {
                descriptor,
                transport,
            },
        );
        Ok(())
    }

    fn invoke_once(
        &mut self,
        permit: ProviderInvocationPermit,
        request: &InterpretationRequest,
        prepared: &PreparedProviderInvocation,
        now_unix_ms: u64,
        deadline: ProviderInvocationDeadline,
    ) -> Result<ProviderInvocationOutcome, InterpretationControlError> {
        if permit.authority_id != self.authority_id
            || permit.nonce == 0
            || permit.request_digest != request.digest()
            || permit.prepared_digest != prepared.digest()
            || permit.adapter_id != prepared.adapter_id
            || permit.provider != prepared.provider
            || permit.endpoint_class != prepared.endpoint_class
            || permit.protocol_version != prepared.protocol_version
            || permit.network_access != prepared.network_access
            || permit.deadline_unix_ms != request.attempt_deadline_unix_ms
            || permit.output_budget_bytes != request.max_response_bytes
            || deadline.deadline_unix_ms() != permit.deadline_unix_ms
        {
            return Err(InterpretationControlError::InvocationBindingMismatch);
        }
        if now_unix_ms >= permit.deadline_unix_ms {
            return Err(InterpretationControlError::InvocationPermitExpired);
        }
        let maximum_remaining = permit.deadline_unix_ms - now_unix_ms;
        if deadline.remaining_ms() > maximum_remaining {
            return Err(InterpretationControlError::InvocationPermitExpired);
        }
        if self.consumed_permits.contains(&permit.nonce) {
            return Err(InterpretationControlError::InvocationPermitReplay);
        }
        let registered = self.transports.get_mut(&permit.adapter_id).ok_or_else(|| {
            InterpretationControlError::TransportUnavailable(permit.adapter_id.clone())
        })?;
        if registered.descriptor.provider != permit.provider
            || registered.descriptor.adapter_id != permit.adapter_id
            || registered.descriptor.endpoint_class != permit.endpoint_class
            || registered.descriptor.protocol_version != permit.protocol_version
            || registered.descriptor.network_access != permit.network_access
        {
            return Err(InterpretationControlError::InvocationBindingMismatch);
        }
        prepared
            .validate()
            .map_err(InterpretationControlError::AdapterContract)?;
        let response_budget = ProviderResponseBudget::new(permit.output_budget_bytes)
            .map_err(InterpretationControlError::AdapterContract)?;
        // Atomic logical consumption happens before the trusted transport is
        // allowed to resolve credentials, authenticate, perform DNS/socket
        // setup, or initialize any provider session.
        self.consumed_permits.insert(permit.nonce);
        let _ = &permit.attempt_id;
        Ok(registered
            .transport
            .invoke_once(prepared, deadline, response_budget))
    }
}

fn prepared_invocation_size(prepared: &PreparedProviderInvocation) -> usize {
    prepared
        .headers
        .iter()
        .fold(prepared.canonical_payload.len(), |total, header| {
            total
                .saturating_add(header.name.len())
                .saturating_add(header.value.len())
        })
}

fn validate_prepared_descriptor(
    descriptor: &AdapterDescriptor,
    prepared: &PreparedProviderInvocation,
) -> Result<(), InterpretationControlError> {
    prepared
        .validate()
        .map_err(InterpretationControlError::AdapterContract)?;
    if prepared.provider != descriptor.provider
        || prepared.adapter_id != descriptor.adapter_id
        || prepared.endpoint_class != descriptor.endpoint_class
        || prepared.protocol_version != descriptor.protocol_version
        || prepared.network_access != descriptor.network_access
    {
        return Err(InterpretationControlError::InvocationBindingMismatch);
    }
    Ok(())
}

fn validate_provider_proposal(
    proposal: &IntentProposal,
    request: &InterpretationRequest,
    descriptor: &AdapterDescriptor,
) -> Result<(), InterpretationControlError> {
    proposal
        .validate()
        .map_err(InterpretationControlError::Proposal)?;
    if proposal.actor != request.actor || proposal.context != request.context {
        return Err(InterpretationControlError::ContextMismatch);
    }
    if proposal.attribution.manual
        || proposal.attribution.provider.as_deref() != Some(descriptor.provider.as_str())
        || proposal.attribution.adapter != descriptor.adapter_id
    {
        return Err(InterpretationControlError::ProviderAttributionMismatch);
    }
    let allowed = request
        .capability_refs
        .iter()
        .map(CapabilityId::as_str)
        .collect::<BTreeSet<_>>();
    if proposal
        .capability_refs
        .iter()
        .any(|capability| !allowed.contains(capability.as_str()))
    {
        return Err(InterpretationControlError::ProviderCapabilityExpansion);
    }
    Ok(())
}

fn next_nonzero(counter: &AtomicU64) -> u64 {
    loop {
        let value = counter.fetch_add(1, Ordering::Relaxed);
        if value != 0 {
            return value;
        }
    }
}

#[derive(Debug)]
pub enum InterpretationControlError {
    InvalidSemanticProjection(String),
    InvalidBudget,
    BudgetExhausted,
    InvalidAttemptId(String),
    AdapterRegistryFull,
    DuplicateAdapter(String),
    DuplicateTransport(String),
    AdapterUnavailable(String),
    TransportUnavailable(String),
    NoEligibleAdapter,
    OfflineNetworkAdapter(String),
    ContextMismatch,
    InvocationBindingMismatch,
    InvocationPermitExpired,
    InvocationPermitReplay,
    ProviderPartialResponse,
    ProviderTimeout,
    ProviderRateLimited,
    ProviderTransport(String),
    ProviderCancelled,
    ProviderOutputExceeded,
    ProviderAttributionMismatch,
    ProviderCapabilityExpansion,
    Runtime(AgentError),
    AdapterContract(InterpretationAdapterError),
    Proposal(ProposalValidationError),
}

impl Display for InterpretationControlError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSemanticProjection(reason) => {
                write!(f, "invalid Control semantic projection: {reason}")
            }
            Self::InvalidBudget => f.write_str("invalid Control aggregate interpretation budget"),
            Self::BudgetExhausted => {
                f.write_str("Control aggregate interpretation budget/deadline is exhausted")
            }
            Self::InvalidAttemptId(reason) => {
                write!(f, "invalid Control interpretation attempt id: {reason}")
            }
            Self::AdapterRegistryFull => {
                f.write_str("Control interpretation adapter registry is full")
            }
            Self::DuplicateAdapter(id) => {
                write!(f, "interpretation adapter is already registered: {id}")
            }
            Self::DuplicateTransport(id) => write!(
                f,
                "provider transport is already registered for adapter: {id}"
            ),
            Self::AdapterUnavailable(id) => {
                write!(f, "interpretation adapter is unavailable: {id}")
            }
            Self::TransportUnavailable(id) => {
                write!(f, "trusted provider transport is unavailable: {id}")
            }
            Self::NoEligibleAdapter => {
                f.write_str("no eligible interpretation adapter is available")
            }
            Self::OfflineNetworkAdapter(id) => write!(
                f,
                "offline mode rejects network-required adapter before invocation: {id}"
            ),
            Self::ContextMismatch => {
                f.write_str("provider proposal/request context binding mismatch")
            }
            Self::InvocationBindingMismatch => {
                f.write_str("provider invocation permit/prepared invocation binding mismatch")
            }
            Self::InvocationPermitExpired => {
                f.write_str("provider invocation permit expired before transport initialization")
            }
            Self::InvocationPermitReplay => {
                f.write_str("provider invocation permit was already consumed")
            }
            Self::ProviderPartialResponse => {
                f.write_str("partial provider response is terminal and cannot become a proposal")
            }
            Self::ProviderTimeout => f.write_str("provider interpretation attempt timed out"),
            Self::ProviderRateLimited => {
                f.write_str("provider interpretation attempt was rate limited")
            }
            Self::ProviderTransport(reason) => {
                write!(f, "provider interpretation transport failed: {reason}")
            }
            Self::ProviderCancelled => f.write_str("provider interpretation attempt was cancelled"),
            Self::ProviderOutputExceeded => {
                f.write_str("provider response exceeded the Control-admitted output budget")
            }
            Self::ProviderAttributionMismatch => {
                f.write_str("provider proposal attribution does not match the admitted adapter")
            }
            Self::ProviderCapabilityExpansion => f.write_str(
                "provider proposal attempted to expand Control-admitted capability references",
            ),
            Self::Runtime(error) => Display::fmt(error, f),
            Self::AdapterContract(error) => Display::fmt(error, f),
            Self::Proposal(error) => Display::fmt(error, f),
        }
    }
}

impl std::error::Error for InterpretationControlError {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use linura_core::{ActorId, ActorKind, ValidationError};
    use linura_intent::ProposalAttribution;

    use super::*;

    fn id<T>(value: Result<T, ValidationError>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error}"))
    }

    struct CountingAdapter {
        descriptor: AdapterDescriptor,
        prepare_calls: Arc<AtomicUsize>,
    }

    impl InterpretationAdapter for CountingAdapter {
        fn descriptor(&self) -> AdapterDescriptor {
            self.descriptor.clone()
        }

        fn prepare(
            &self,
            request: &InterpretationRequest,
        ) -> Result<PreparedProviderInvocation, InterpretationAdapterError> {
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            PreparedProviderInvocation::new(
                &self.descriptor,
                vec![],
                request.digest().to_hex().into_bytes(),
            )
        }

        fn decode_complete(
            &self,
            request: &InterpretationRequest,
            _response: &[u8],
        ) -> Result<IntentProposal, InterpretationAdapterError> {
            IntentProposal::new_v1(
                id(RequestId::new("proposal:provider:test")),
                request.actor.clone(),
                "Configure a workstation",
                vec![],
                request.capability_refs.clone(),
                vec![],
                vec![],
                None,
                request.context.clone(),
                ProposalAttribution::provider(
                    self.descriptor.provider.as_str(),
                    self.descriptor.adapter_id.clone(),
                    Some("mock-model".into()),
                )
                .map_err(|error| InterpretationAdapterError::MalformedOutput(error.to_string()))?,
                vec![],
            )
            .map_err(|error| InterpretationAdapterError::MalformedOutput(error.to_string()))
        }
    }

    struct CountingTransport {
        calls: Arc<AtomicUsize>,
        outcome: ProviderInvocationOutcome,
    }

    impl ProviderInvocationTransport for CountingTransport {
        fn invoke_once(
            &mut self,
            _invocation: &PreparedProviderInvocation,
            _deadline: ProviderInvocationDeadline,
            _response_budget: ProviderResponseBudget,
        ) -> ProviderInvocationOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcome.clone()
        }
    }

    struct SlowTransport {
        calls: Arc<AtomicUsize>,
    }

    impl ProviderInvocationTransport for SlowTransport {
        fn invoke_once(
            &mut self,
            _invocation: &PreparedProviderInvocation,
            deadline: ProviderInvocationDeadline,
            _response_budget: ProviderResponseBudget,
        ) -> ProviderInvocationOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(
                deadline.remaining_ms().saturating_add(10),
            ));
            ProviderInvocationOutcome::Complete(vec![1])
        }
    }

    struct BudgetRecordingTransport {
        calls: Arc<AtomicUsize>,
        observed_budget: Arc<AtomicUsize>,
    }

    impl ProviderInvocationTransport for BudgetRecordingTransport {
        fn invoke_once(
            &mut self,
            _invocation: &PreparedProviderInvocation,
            _deadline: ProviderInvocationDeadline,
            response_budget: ProviderResponseBudget,
        ) -> ProviderInvocationOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.observed_budget.store(
                usize::try_from(response_budget.max_bytes()).unwrap_or(usize::MAX),
                Ordering::SeqCst,
            );
            ProviderInvocationOutcome::Complete(vec![1])
        }
    }

    fn work() -> InterpretationWork {
        let raw = RawSemanticProjection {
            entries: vec![
                RawSemanticEntry {
                    key: "goal".into(),
                    value: RawSemanticValue::PublicText("developer workstation".into()),
                },
                RawSemanticEntry {
                    key: "secret".into(),
                    value: RawSemanticValue::Secret {
                        value: "CANARY-DO-NOT-LEAK".into(),
                        protected_reference: Some("secret:provider-key".into()),
                    },
                },
            ],
        };
        let projection = raw
            .minimize()
            .unwrap_or_else(|error| unreachable!("{error}"));
        InterpretationWork {
            request_id: id(RequestId::new("interpretation:test")),
            actor: Actor {
                id: id(ActorId::new("uid:1000")),
                kind: ActorKind::Human,
                interactive: true,
            },
            context: InterpretationContextBinding::new("authority:1", projection.digest(), vec![])
                .unwrap_or_else(|error| unreachable!("{error}")),
            projection,
            capability_refs: vec![],
        }
    }

    fn descriptor(network_access: NetworkAccess) -> AdapterDescriptor {
        named_descriptor("adapter:mock", "provider:mock", network_access)
    }

    fn named_descriptor(
        adapter_id: &str,
        provider_id: &str,
        network_access: NetworkAccess,
    ) -> AdapterDescriptor {
        AdapterDescriptor {
            provider: id(ProviderId::new(provider_id)),
            adapter_id: adapter_id.into(),
            endpoint_class: "interpretation".into(),
            protocol_version: 1,
            network_access,
        }
    }

    #[test]
    fn control_minimizes_secret_before_runtime_boundary() {
        let work = work();
        let rendered = format!("{:?}", work.projection.entries());
        assert!(!rendered.contains("CANARY-DO-NOT-LEAK"));
        assert!(rendered.contains("secret:provider-key"));
    }

    #[test]
    fn offline_rejects_selected_network_adapter_before_adapter_or_transport_callback() {
        let prepare_calls = Arc::new(AtomicUsize::new(0));
        let transport_calls = Arc::new(AtomicUsize::new(0));
        let descriptor = descriptor(NetworkAccess::Required);
        let mut engine = ControlInterpretationEngine::new();
        engine
            .register_adapter(Box::new(CountingAdapter {
                descriptor: descriptor.clone(),
                prepare_calls: Arc::clone(&prepare_calls),
            }))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let mut gate = engine.invocation_gate();
        gate.register_transport(
            descriptor,
            Box::new(CountingTransport {
                calls: Arc::clone(&transport_calls),
                outcome: ProviderInvocationOutcome::Complete(vec![]),
            }),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let mut budget =
            InterpretationSessionBudget::new(id(RequestId::new("session:offline")), 1_000, 1, 4096)
                .unwrap_or_else(|error| unreachable!("{error}"));
        let runtime = AgentRuntime::default();
        let work = work();
        let mut invocation = InterpretationInvocation {
            runtime: &runtime,
            gate: &mut gate,
            work: &work,
            offline: true,
            now_unix_ms: 10,
            requested_output_bytes: 1024,
            budget: &mut budget,
        };
        let result = engine.interpret_with_adapter("adapter:mock", &mut invocation);
        assert!(matches!(
            result,
            Err(InterpretationControlError::OfflineNetworkAdapter(_))
        ));
        assert_eq!(prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(transport_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn transport_cannot_return_success_after_control_deadline() {
        let prepare_calls = Arc::new(AtomicUsize::new(0));
        let transport_calls = Arc::new(AtomicUsize::new(0));
        let descriptor = descriptor(NetworkAccess::None);
        let mut engine = ControlInterpretationEngine::new();
        engine
            .register_adapter(Box::new(CountingAdapter {
                descriptor: descriptor.clone(),
                prepare_calls: Arc::clone(&prepare_calls),
            }))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let mut gate = engine.invocation_gate();
        gate.register_transport(
            descriptor,
            Box::new(SlowTransport {
                calls: Arc::clone(&transport_calls),
            }),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let runtime = AgentRuntime::default();
        let work = work();
        let mut budget =
            InterpretationSessionBudget::new(id(RequestId::new("session:timeout")), 12, 1, 4096)
                .unwrap_or_else(|error| unreachable!("{error}"));
        let mut invocation = InterpretationInvocation {
            runtime: &runtime,
            gate: &mut gate,
            work: &work,
            offline: false,
            now_unix_ms: 10,
            requested_output_bytes: 1024,
            budget: &mut budget,
        };
        let result = engine.interpret_with_adapter("adapter:mock", &mut invocation);
        assert!(matches!(
            result,
            Err(InterpretationControlError::ProviderTimeout)
        ));
        assert_eq!(transport_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn transport_receives_exact_control_admitted_response_budget() {
        let prepare_calls = Arc::new(AtomicUsize::new(0));
        let transport_calls = Arc::new(AtomicUsize::new(0));
        let observed_budget = Arc::new(AtomicUsize::new(0));
        let descriptor = descriptor(NetworkAccess::None);
        let mut engine = ControlInterpretationEngine::new();
        engine
            .register_adapter(Box::new(CountingAdapter {
                descriptor: descriptor.clone(),
                prepare_calls: Arc::clone(&prepare_calls),
            }))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let mut gate = engine.invocation_gate();
        gate.register_transport(
            descriptor,
            Box::new(BudgetRecordingTransport {
                calls: Arc::clone(&transport_calls),
                observed_budget: Arc::clone(&observed_budget),
            }),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let runtime = AgentRuntime::default();
        let work = work();
        let mut budget = InterpretationSessionBudget::new(
            id(RequestId::new("session:response-budget")),
            1_000,
            1,
            4096,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let mut invocation = InterpretationInvocation {
            runtime: &runtime,
            gate: &mut gate,
            work: &work,
            offline: false,
            now_unix_ms: 10,
            requested_output_bytes: 777,
            budget: &mut budget,
        };
        engine
            .interpret_with_adapter("adapter:mock", &mut invocation)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(transport_calls.load(Ordering::SeqCst), 1);
        assert_eq!(observed_budget.load(Ordering::SeqCst), 777);
    }

    #[test]
    fn fallback_cannot_reset_elapsed_aggregate_deadline() {
        let first_descriptor =
            named_descriptor("adapter:first", "provider:first", NetworkAccess::None);
        let second_descriptor =
            named_descriptor("adapter:second", "provider:second", NetworkAccess::None);
        let prepare_calls = Arc::new(AtomicUsize::new(0));
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        let mut engine = ControlInterpretationEngine::new();
        engine
            .register_adapter(Box::new(CountingAdapter {
                descriptor: first_descriptor.clone(),
                prepare_calls: Arc::clone(&prepare_calls),
            }))
            .unwrap_or_else(|error| unreachable!("{error}"));
        engine
            .register_adapter(Box::new(CountingAdapter {
                descriptor: second_descriptor.clone(),
                prepare_calls: Arc::clone(&prepare_calls),
            }))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let mut gate = engine.invocation_gate();
        gate.register_transport(
            first_descriptor,
            Box::new(SlowTransport {
                calls: Arc::clone(&first_calls),
            }),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        gate.register_transport(
            second_descriptor,
            Box::new(CountingTransport {
                calls: Arc::clone(&second_calls),
                outcome: ProviderInvocationOutcome::Complete(vec![1]),
            }),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let runtime = AgentRuntime::default();
        let work = work();
        let mut budget = InterpretationSessionBudget::new(
            id(RequestId::new("session:fallback-deadline")),
            12,
            2,
            2048,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let result = {
            let mut invocation = InterpretationInvocation {
                runtime: &runtime,
                gate: &mut gate,
                work: &work,
                offline: false,
                now_unix_ms: 10,
                requested_output_bytes: 1024,
                budget: &mut budget,
            };
            engine.interpret_with_fallback(
                &["adapter:first".into(), "adapter:second".into()],
                &mut invocation,
            )
        };
        assert!(matches!(
            result,
            Err(InterpretationControlError::BudgetExhausted)
        ));
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(second_calls.load(Ordering::SeqCst), 0);
        assert_eq!(budget.remaining_attempts(), 1);
    }

    #[test]
    fn successful_provider_path_consumes_one_control_admission() {
        let prepare_calls = Arc::new(AtomicUsize::new(0));
        let transport_calls = Arc::new(AtomicUsize::new(0));
        let descriptor = descriptor(NetworkAccess::None);
        let mut engine = ControlInterpretationEngine::new();
        engine
            .register_adapter(Box::new(CountingAdapter {
                descriptor: descriptor.clone(),
                prepare_calls: Arc::clone(&prepare_calls),
            }))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let mut gate = engine.invocation_gate();
        gate.register_transport(
            descriptor,
            Box::new(CountingTransport {
                calls: Arc::clone(&transport_calls),
                outcome: ProviderInvocationOutcome::Complete(vec![1]),
            }),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let mut budget =
            InterpretationSessionBudget::new(id(RequestId::new("session:success")), 1_000, 2, 4096)
                .unwrap_or_else(|error| unreachable!("{error}"));
        let runtime = AgentRuntime::default();
        let work = work();
        let proposal = {
            let mut invocation = InterpretationInvocation {
                runtime: &runtime,
                gate: &mut gate,
                work: &work,
                offline: false,
                now_unix_ms: 10,
                requested_output_bytes: 1024,
                budget: &mut budget,
            };
            engine
                .interpret_with_adapter("adapter:mock", &mut invocation)
                .unwrap_or_else(|error| unreachable!("{error}"))
        };
        assert_eq!(proposal.validate(), Ok(()));
        assert_eq!(prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(transport_calls.load(Ordering::SeqCst), 1);
        assert_eq!(budget.remaining_attempts(), 1);
    }
}
