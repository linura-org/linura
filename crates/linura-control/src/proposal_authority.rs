use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

use linura_core::{Actor, CapabilityId, PrincipalId, RequestId};
use linura_intent::{IntentProposal, InterpretationContextBinding, ProposalDigest};
use linura_library::ProposalAcceptanceTarget;

use crate::plan_preview::AuthenticatedPrincipal;
use crate::proposal_acceptance::{
    AcceptanceAuthoritySnapshot, AuthorityValidityContributor, ProposalAcceptanceAuthorityGuard,
    ProposalAcceptanceAuthoritySource, ProposalAcceptanceControlError, ProposalAcceptanceDecision,
};

const MAX_ACCEPTANCE_DECISIONS: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalDecisionIssueRequest {
    pub decision_id: RequestId,
    pub operation_id: RequestId,
    pub target: ProposalAcceptanceTarget,
    pub expires_at_unix_ms: u64,
    pub validity_evidence_digest: ProposalDigest,
}

#[derive(Debug)]
struct ControlProposalAuthorityState {
    context: InterpretationContextBinding,
    generation: u64,
    actor_bindings: BTreeSet<(String, String, String, bool)>,
    supported_capabilities: BTreeSet<CapabilityId>,
    time_validities: Vec<AuthorityValidityContributor>,
    decisions: BTreeMap<String, ProposalAcceptanceDecision>,
}

/// Concrete Control-owned source for v0.8 proposal acceptance authority.
///
/// Every acceptance-relevant mutation and every final acceptance snapshot is
/// serialized by the same mutex. `ProposalAcceptanceControl::accept` holds the
/// returned guard across final context/capability/decision revalidation and the
/// durable Library commit attempt, so concurrent authority changes cannot race
/// into the write/CAS window.
#[derive(Debug)]
pub struct ControlProposalAuthority {
    state: Mutex<ControlProposalAuthorityState>,
}

impl ControlProposalAuthority {
    pub fn new(
        context: InterpretationContextBinding,
        supported_capabilities: BTreeSet<CapabilityId>,
        time_validities: Vec<AuthorityValidityContributor>,
    ) -> Result<Self, ProposalAcceptanceControlError> {
        validate_state_material(&context, 1, &supported_capabilities, &time_validities)?;
        Ok(Self {
            state: Mutex::new(ControlProposalAuthorityState {
                context,
                generation: 1,
                actor_bindings: BTreeSet::new(),
                supported_capabilities,
                time_validities,
                decisions: BTreeMap::new(),
            }),
        })
    }

    pub fn authorize_actor(
        &self,
        principal: &AuthenticatedPrincipal,
        actor: &Actor,
    ) -> Result<u64, ProposalAcceptanceControlError> {
        let mut state = self.lock_state()?;
        let binding = actor_binding(principal, actor);
        if state.actor_bindings.insert(binding) {
            advance_generation(&mut state)?;
        }
        Ok(state.generation)
    }

    pub fn revoke_actor(
        &self,
        principal: &AuthenticatedPrincipal,
        actor: &Actor,
    ) -> Result<u64, ProposalAcceptanceControlError> {
        let mut state = self.lock_state()?;
        let binding = actor_binding(principal, actor);
        if state.actor_bindings.remove(&binding) {
            advance_generation(&mut state)?;
        }
        Ok(state.generation)
    }

    pub fn replace_context(
        &self,
        context: InterpretationContextBinding,
    ) -> Result<u64, ProposalAcceptanceControlError> {
        let mut state = self.lock_state()?;
        validate_state_material(
            &context,
            state.generation,
            &state.supported_capabilities,
            &state.time_validities,
        )?;
        if state.context != context {
            state.context = context;
            advance_generation(&mut state)?;
        }
        Ok(state.generation)
    }

    pub fn replace_supported_capabilities(
        &self,
        capabilities: BTreeSet<CapabilityId>,
    ) -> Result<u64, ProposalAcceptanceControlError> {
        let mut state = self.lock_state()?;
        validate_state_material(
            &state.context,
            state.generation,
            &capabilities,
            &state.time_validities,
        )?;
        if state.supported_capabilities != capabilities {
            state.supported_capabilities = capabilities;
            advance_generation(&mut state)?;
        }
        Ok(state.generation)
    }

    pub fn replace_time_validities(
        &self,
        time_validities: Vec<AuthorityValidityContributor>,
    ) -> Result<u64, ProposalAcceptanceControlError> {
        let mut state = self.lock_state()?;
        validate_state_material(
            &state.context,
            state.generation,
            &state.supported_capabilities,
            &time_validities,
        )?;
        if state.time_validities != time_validities {
            state.time_validities = time_validities;
            advance_generation(&mut state)?;
        }
        Ok(state.generation)
    }

    /// Mint and retain one exact-bound acceptance decision from the current
    /// serialized authority generation.
    pub fn issue_decision(
        &self,
        principal: &AuthenticatedPrincipal,
        proposal: &IntentProposal,
        request: ProposalDecisionIssueRequest,
    ) -> Result<ProposalAcceptanceDecision, ProposalAcceptanceControlError> {
        proposal
            .validate()
            .map_err(|error| ProposalAcceptanceControlError::InvalidProposal(error.to_string()))?;
        let mut state = self.lock_state()?;
        if state.decisions.len() >= MAX_ACCEPTANCE_DECISIONS
            && !state.decisions.contains_key(request.decision_id.as_str())
        {
            return Err(ProposalAcceptanceControlError::InvalidDecision(
                "Control acceptance decision registry is full".into(),
            ));
        }
        if proposal.context != state.context {
            return Err(ProposalAcceptanceControlError::StaleContext);
        }
        let binding = actor_binding(principal, &proposal.actor);
        if !state.actor_bindings.contains(&binding) {
            return Err(ProposalAcceptanceControlError::ActorPrincipalUnauthorized);
        }
        if proposal
            .capability_refs
            .iter()
            .any(|capability| !state.supported_capabilities.contains(capability))
        {
            return Err(ProposalAcceptanceControlError::UnsupportedCapability);
        }
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|error| ProposalAcceptanceControlError::InvalidPrincipal(error.to_string()))?;
        let decision = ProposalAcceptanceDecision::exact_bound(
            request.decision_id.clone(),
            principal_id,
            proposal.proposal_id.clone(),
            proposal.canonical_digest,
            proposal.context.digest(),
            request.operation_id,
            request.target,
            request.expires_at_unix_ms,
            state.generation,
            request.validity_evidence_digest,
        )?;
        if let Some(existing) = state.decisions.get(request.decision_id.as_str()) {
            if existing == &decision {
                return Ok(existing.clone());
            }
            return Err(ProposalAcceptanceControlError::InvalidDecision(
                "acceptance decision identity was reused for different semantics".into(),
            ));
        }
        state
            .decisions
            .insert(request.decision_id.as_str().to_string(), decision.clone());
        Ok(decision)
    }

    pub fn revoke_decision(
        &self,
        decision_id: &RequestId,
    ) -> Result<bool, ProposalAcceptanceControlError> {
        let mut state = self.lock_state()?;
        let removed = state.decisions.remove(decision_id.as_str()).is_some();
        if removed {
            advance_generation(&mut state)?;
        }
        Ok(removed)
    }

    #[must_use]
    pub fn decision_capacity() -> usize {
        MAX_ACCEPTANCE_DECISIONS
    }

    fn lock_state(
        &self,
    ) -> Result<MutexGuard<'_, ControlProposalAuthorityState>, ProposalAcceptanceControlError> {
        self.state.lock().map_err(|_| {
            ProposalAcceptanceControlError::InvalidAuthoritySnapshot(
                "Control proposal-authority serialization lock is poisoned".into(),
            )
        })
    }
}

struct LockedProposalAuthorityGuard<'a> {
    state: MutexGuard<'a, ControlProposalAuthorityState>,
}

impl ProposalAcceptanceAuthorityGuard for LockedProposalAuthorityGuard<'_> {
    fn snapshot_at(
        &mut self,
        principal: &AuthenticatedPrincipal,
        actor: &Actor,
        _proposal: &IntentProposal,
        _now_unix_ms: u64,
    ) -> Result<AcceptanceAuthoritySnapshot, ProposalAcceptanceControlError> {
        let authorized = self
            .state
            .actor_bindings
            .contains(&actor_binding(principal, actor));
        AcceptanceAuthoritySnapshot::new(
            self.state.context.clone(),
            self.state.generation,
            authorized,
            self.state.supported_capabilities.clone(),
            self.state.time_validities.clone(),
        )
    }

    fn decision(
        &mut self,
        decision_id: &RequestId,
    ) -> Result<ProposalAcceptanceDecision, ProposalAcceptanceControlError> {
        let decision = self
            .state
            .decisions
            .get(decision_id.as_str())
            .cloned()
            .ok_or_else(|| {
                ProposalAcceptanceControlError::InvalidDecision(
                    "acceptance decision is absent or revoked".into(),
                )
            })?;
        if decision.authorization_generation != self.state.generation {
            return Err(ProposalAcceptanceControlError::InvalidDecision(
                "acceptance decision belongs to a stale Control authority generation".into(),
            ));
        }
        if decision.context_digest != self.state.context.digest() {
            return Err(ProposalAcceptanceControlError::InvalidDecision(
                "acceptance decision belongs to stale Control context".into(),
            ));
        }
        Ok(decision)
    }
}

impl ProposalAcceptanceAuthoritySource for ControlProposalAuthority {
    fn acquire_guard(
        &mut self,
    ) -> Result<Box<dyn ProposalAcceptanceAuthorityGuard + '_>, ProposalAcceptanceControlError>
    {
        Ok(Box::new(LockedProposalAuthorityGuard {
            state: self.lock_state()?,
        }))
    }
}

fn actor_binding(
    principal: &AuthenticatedPrincipal,
    actor: &Actor,
) -> (String, String, String, bool) {
    let kind = match actor.kind {
        linura_core::ActorKind::Human => "human",
        linura_core::ActorKind::Service => "service",
        linura_core::ActorKind::Agent => "agent",
        linura_core::ActorKind::Remote => "remote",
    };
    (
        principal.as_str().to_string(),
        actor.id.as_str().to_string(),
        kind.to_string(),
        actor.interactive,
    )
}

fn validate_state_material(
    context: &InterpretationContextBinding,
    generation: u64,
    supported_capabilities: &BTreeSet<CapabilityId>,
    time_validities: &[AuthorityValidityContributor],
) -> Result<(), ProposalAcceptanceControlError> {
    AcceptanceAuthoritySnapshot::new(
        context.clone(),
        generation,
        false,
        supported_capabilities.clone(),
        time_validities.to_vec(),
    )?;
    Ok(())
}

fn advance_generation(
    state: &mut ControlProposalAuthorityState,
) -> Result<(), ProposalAcceptanceControlError> {
    state.generation = state.generation.checked_add(1).ok_or_else(|| {
        ProposalAcceptanceControlError::InvalidAuthoritySnapshot(
            "Control proposal-authority generation exhausted".into(),
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use linura_core::{ActorId, ActorKind, ValidationError};
    use linura_intent::ProposalAttribution;

    use super::*;

    fn id<T>(result: Result<T, ValidationError>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn fixture() -> (
        AuthenticatedPrincipal,
        IntentProposal,
        ControlProposalAuthority,
        ProposalAcceptanceTarget,
    ) {
        let principal =
            AuthenticatedPrincipal::new("uid:1000").unwrap_or_else(|error| unreachable!("{error}"));
        let actor = Actor {
            id: id(ActorId::new("uid:1000")),
            kind: ActorKind::Human,
            interactive: true,
        };
        let context = InterpretationContextBinding::new(
            "authority:concrete-source",
            ProposalDigest::hash_parts(b"semantic", &[b"fixture"]),
            vec![],
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let proposal = IntentProposal::new_v1(
            id(RequestId::new("proposal:concrete-source")),
            actor,
            "Configure a workstation",
            vec![],
            vec![],
            vec![],
            vec![],
            None,
            context.clone(),
            ProposalAttribution::manual("manual").unwrap_or_else(|error| unreachable!("{error}")),
            vec![],
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let authority = ControlProposalAuthority::new(context, BTreeSet::new(), vec![])
            .unwrap_or_else(|error| unreachable!("{error}"));
        let target = ProposalAcceptanceTarget::Create {
            intent_id: id(linura_core::IntentId::new("intent:concrete-source")),
        };
        (principal, proposal, authority, target)
    }

    #[test]
    fn authority_mutation_invalidates_prior_decision_generation() {
        let (principal, proposal, mut authority, target) = fixture();
        authority
            .authorize_actor(&principal, &proposal.actor)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let decision = authority
            .issue_decision(
                &principal,
                &proposal,
                ProposalDecisionIssueRequest {
                    decision_id: id(RequestId::new("decision:concrete-source")),
                    operation_id: id(RequestId::new("operation:concrete-source")),
                    target,
                    expires_at_unix_ms: 10_000,
                    validity_evidence_digest: ProposalDigest::hash_parts(
                        b"decision",
                        &[b"validity"],
                    ),
                },
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        authority
            .replace_time_validities(vec![AuthorityValidityContributor::exclusive_unix_ms(
                "policy:updated",
                9_000,
                ProposalDigest::hash_parts(b"policy", &[b"updated"]),
            )])
            .unwrap_or_else(|error| unreachable!("{error}"));
        let mut guard = authority
            .acquire_guard()
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            guard.decision(&decision.decision_id),
            Err(ProposalAcceptanceControlError::InvalidDecision(_))
        ));
    }

    #[test]
    fn decision_identity_reuse_with_changed_semantics_fails_closed() {
        let (principal, proposal, authority, target) = fixture();
        authority
            .authorize_actor(&principal, &proposal.actor)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let decision_id = id(RequestId::new("decision:idempotent"));
        authority
            .issue_decision(
                &principal,
                &proposal,
                ProposalDecisionIssueRequest {
                    decision_id: decision_id.clone(),
                    operation_id: id(RequestId::new("operation:first")),
                    target: target.clone(),
                    expires_at_unix_ms: 10_000,
                    validity_evidence_digest: ProposalDigest::hash_parts(b"decision", &[b"first"]),
                },
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            authority.issue_decision(
                &principal,
                &proposal,
                ProposalDecisionIssueRequest {
                    decision_id,
                    operation_id: id(RequestId::new("operation:second")),
                    target,
                    expires_at_unix_ms: 10_000,
                    validity_evidence_digest: ProposalDigest::hash_parts(b"decision", &[b"second"]),
                },
            ),
            Err(ProposalAcceptanceControlError::InvalidDecision(_))
        ));
    }
}
