#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::time::{Duration, Instant};

use linura_core::{Actor, CapabilityId, RequestId};
use linura_intent::{
    IntentProposal, InterpretationContextBinding, ProposalAttribution, ProposalConfidence,
    Requirement,
};

const MAX_ADAPTER_ID_BYTES: usize = 256;
const MAX_ADVISORY_ITEMS: usize = 128;
const MAX_ADVISORY_TEXT_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SpecialistRole {
    Coordinator,
    Hardware,
    Security,
    Developer,
    Desktop,
    Productivity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentContext {
    pub actor: Actor,
    pub context_binding: InterpretationContextBinding,
    pub offline: bool,
    pub allowed_specialists: Vec<SpecialistRole>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedInterpretationAttempt {
    pub attempt_id: RequestId,
    pub adapter_id: String,
    pub deadline_unix_ms: u64,
    pub runtime_output_budget_bytes: u32,
}

impl AdmittedInterpretationAttempt {
    pub fn validate(&self) -> Result<(), AgentError> {
        if self.adapter_id.trim().is_empty()
            || self.adapter_id.len() > MAX_ADAPTER_ID_BYTES
            || self.adapter_id.chars().any(char::is_control)
        {
            return Err(AgentError::InvalidAdmission("invalid adapter id".into()));
        }
        if self.deadline_unix_ms == 0 || self.runtime_output_budget_bytes == 0 {
            return Err(AgentError::InvalidAdmission(
                "attempt deadline/runtime-output budget must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManualProposalInput {
    pub proposal_id: RequestId,
    pub requested_outcome: String,
    pub requirements: Vec<Requirement>,
    pub capability_refs: Vec<CapabilityId>,
    pub assumptions: Vec<String>,
    pub unresolved_questions: Vec<String>,
    pub explanation: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvisoryRecord {
    pub role: SpecialistRole,
    pub source: String,
    pub findings: Vec<String>,
}

pub trait Specialist: Send + Sync {
    fn role(&self) -> SpecialistRole;
    fn source(&self) -> &'static str;
    fn advise_once(
        &self,
        context: &AgentContext,
        proposal: &IntentProposal,
    ) -> Result<Vec<String>, AgentError>;
}

#[derive(Default)]
pub struct AgentRuntime {
    specialists: BTreeMap<SpecialistRole, Box<dyn Specialist>>,
}

impl std::fmt::Debug for AgentRuntime {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentRuntime")
            .field("specialist_count", &self.specialists.len())
            .finish()
    }
}

impl AgentRuntime {
    pub fn register_specialist(
        &mut self,
        specialist: Box<dyn Specialist>,
    ) -> Result<(), AgentError> {
        let role = specialist.role();
        if self.specialists.contains_key(&role) {
            return Err(AgentError::DuplicateSpecialist(role));
        }
        self.specialists.insert(role, specialist);
        Ok(())
    }

    /// Execute exactly one Control-admitted attempt. The callback is `FnOnce`
    /// and receives no orchestration object, provider registry, retry handle or
    /// aggregate-budget mutator from the runtime.
    pub fn execute_single_attempt<T, F, S>(
        &self,
        admission: &AdmittedInterpretationAttempt,
        now_unix_ms: u64,
        execute_once: F,
        output_size: S,
    ) -> Result<T, AgentError>
    where
        F: FnOnce() -> Result<T, AgentError>,
        S: FnOnce(&T) -> usize,
    {
        admission.validate()?;
        let remaining_ms = admission
            .deadline_unix_ms
            .checked_sub(now_unix_ms)
            .ok_or(AgentError::AttemptExpired)?;
        if remaining_ms == 0 {
            return Err(AgentError::AttemptExpired);
        }

        // The wall-clock value is Control-owned. `Instant` is used only to
        // enforce the admitted elapsed-time window across this single callback,
        // so a callback that returns after its admission expired is rejected
        // even when the caller cannot refresh wall-clock state mid-call. Hard
        // preemption of untrusted provider processes remains an isolation-layer
        // responsibility; this runtime never turns late completion into success.
        let started = Instant::now();
        let result = execute_once()?;
        if started.elapsed() >= Duration::from_millis(remaining_ms) {
            return Err(AgentError::AttemptExpired);
        }
        if output_size(&result)
            > usize::try_from(admission.runtime_output_budget_bytes).unwrap_or(usize::MAX)
        {
            return Err(AgentError::AttemptOutputExceeded);
        }
        Ok(result)
    }

    pub fn manual_proposal(
        &self,
        context: &AgentContext,
        input: ManualProposalInput,
    ) -> Result<IntentProposal, AgentError> {
        IntentProposal::new_v1(
            input.proposal_id,
            context.actor.clone(),
            input.requested_outcome,
            input.requirements,
            input.capability_refs,
            input.assumptions,
            input.unresolved_questions,
            None::<ProposalConfidence>,
            context.context_binding.clone(),
            ProposalAttribution::manual("linura-agent-runtime:manual")
                .map_err(|error| AgentError::InvalidProposal(error.to_string()))?,
            input.explanation,
        )
        .map_err(|error| AgentError::InvalidProposal(error.to_string()))
    }

    pub fn advise_single(
        &self,
        context: &AgentContext,
        proposal: &IntentProposal,
        role: SpecialistRole,
    ) -> Result<AdvisoryRecord, AgentError> {
        if !context.allowed_specialists.contains(&role) {
            return Err(AgentError::SpecialistNotAdmitted(role));
        }
        let specialist = self
            .specialists
            .get(&role)
            .ok_or(AgentError::SpecialistUnavailable(role))?;
        let findings = specialist.advise_once(context, proposal)?;
        if findings.len() > MAX_ADVISORY_ITEMS
            || findings
                .iter()
                .any(|item| item.len() > MAX_ADVISORY_TEXT_BYTES || item.contains('\0'))
        {
            return Err(AgentError::InvalidAdvisory);
        }
        Ok(AdvisoryRecord {
            role,
            source: specialist.source().into(),
            findings,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentError {
    InvalidAdmission(String),
    AttemptExpired,
    AttemptOutputExceeded,
    InvalidProposal(String),
    ProviderFailure(String),
    DuplicateSpecialist(SpecialistRole),
    SpecialistNotAdmitted(SpecialistRole),
    SpecialistUnavailable(SpecialistRole),
    InvalidAdvisory,
}

impl Display for AgentError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidAdmission(reason) => {
                write!(f, "invalid Control attempt admission: {reason}")
            }
            Self::AttemptExpired => f.write_str("Control-admitted interpretation attempt expired"),
            Self::AttemptOutputExceeded => f.write_str(
                "Control-admitted interpretation attempt exceeded its runtime output bound",
            ),
            Self::InvalidProposal(reason) => write!(f, "invalid intent proposal: {reason}"),
            Self::ProviderFailure(reason) => {
                write!(f, "provider interpretation attempt failed: {reason}")
            }
            Self::DuplicateSpecialist(role) => {
                write!(f, "specialist {role:?} is already registered")
            }
            Self::SpecialistNotAdmitted(role) => {
                write!(f, "specialist {role:?} was not admitted by Control")
            }
            Self::SpecialistUnavailable(role) => write!(f, "specialist {role:?} is unavailable"),
            Self::InvalidAdvisory => f.write_str("specialist advisory exceeds runtime bounds"),
        }
    }
}

impl std::error::Error for AgentError {}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{ActorId, ActorKind, IntentId, ValidationError};
    use linura_intent::ProposalDigest;

    fn id<T>(value: Result<T, ValidationError>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn context() -> AgentContext {
        AgentContext {
            actor: Actor {
                id: id(ActorId::new("uid:1000")),
                kind: ActorKind::Human,
                interactive: true,
            },
            context_binding: InterpretationContextBinding::new(
                "authority:1",
                ProposalDigest::hash_parts(b"semantic", &[b"manual"]),
                vec![],
            )
            .unwrap_or_else(|error| unreachable!("{error}")),
            offline: true,
            allowed_specialists: vec![],
        }
    }

    #[test]
    fn expired_attempt_is_rejected_before_callback() {
        let runtime = AgentRuntime::default();
        let admission = AdmittedInterpretationAttempt {
            attempt_id: id(RequestId::new("attempt:1")),
            adapter_id: "mock".into(),
            deadline_unix_ms: 100,
            runtime_output_budget_bytes: 1024,
        };
        let mut called = false;
        let result: Result<(), AgentError> = runtime.execute_single_attempt(
            &admission,
            100,
            || {
                called = true;
                Ok(())
            },
            |_| 0,
        );
        assert_eq!(result, Err(AgentError::AttemptExpired));
        assert!(!called);
    }

    #[test]
    fn late_callback_completion_is_rejected() {
        let runtime = AgentRuntime::default();
        let admission = AdmittedInterpretationAttempt {
            attempt_id: id(RequestId::new("attempt:late")),
            adapter_id: "mock".into(),
            deadline_unix_ms: 101,
            runtime_output_budget_bytes: 1024,
        };
        let result = runtime.execute_single_attempt(
            &admission,
            100,
            || {
                std::thread::sleep(Duration::from_millis(3));
                Ok(vec![1_u8])
            },
            Vec::len,
        );
        assert_eq!(result, Err(AgentError::AttemptExpired));
    }

    #[test]
    fn oversized_callback_output_is_rejected() {
        let runtime = AgentRuntime::default();
        let admission = AdmittedInterpretationAttempt {
            attempt_id: id(RequestId::new("attempt:oversized")),
            adapter_id: "mock".into(),
            deadline_unix_ms: 10_000,
            runtime_output_budget_bytes: 1,
        };
        let result =
            runtime.execute_single_attempt(&admission, 1, || Ok(vec![1_u8, 2_u8]), Vec::len);
        assert_eq!(result, Err(AgentError::AttemptOutputExceeded));
    }

    #[test]
    fn manual_path_produces_same_canonical_proposal_contract() {
        let runtime = AgentRuntime::default();
        let context = context();
        let proposal = runtime
            .manual_proposal(
                &context,
                ManualProposalInput {
                    proposal_id: id(RequestId::new("proposal:manual:1")),
                    requested_outcome: "Configure a workstation".into(),
                    requirements: vec![],
                    capability_refs: vec![],
                    assumptions: vec![],
                    unresolved_questions: vec![],
                    explanation: vec!["manual typed input".into()],
                },
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(proposal.validate(), Ok(()));
        assert!(proposal.attribution.manual);
    }

    #[test]
    fn proposal_acceptance_is_not_a_runtime_surface() {
        let runtime = AgentRuntime::default();
        let _ = runtime;
        let _ = IntentId::new("intent:compile-only");
        // Deliberately no runtime method exists for accepting/persisting intent,
        // minting policy/approval authority, or obtaining executor handles.
    }
}
