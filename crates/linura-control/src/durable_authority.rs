use std::fmt::{Display, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};

use linura_core::{
    Actor, ActorKind, ApprovalEvidenceId, ApprovalRequestId, PrincipalId, RiskClass,
};
use linura_observation::{ObservationEnvelope, ObservedValue};
use linura_policy::{ApprovalClass, PolicyDecision, ReviewFindingLevel, ReviewPlanStatus};
use linura_protocol::PlanDesiredStateRequest;
use linura_transaction::{
    AbortRequest, ApprovalAuthority, AuthorityBinding, AuthorizationBasis, CommitRequest,
    ContentDigest, HandoffCommit, PrepareOutcome, RecoveryOutcome, RecoveryResolution,
    TransactionAuthoritySigner, TransactionId, TransactionSnapshot, TransactionState,
    TransactionStore, TransactionStoreError, TransactionValidationError, digest_parts,
};
use sha2::{Digest, Sha256};

use crate::approval::ApprovalValidation;
use crate::approval_review::{ApprovalControlError, PolicyAuthenticatedApprover};
use crate::policy_review::{TrustedPolicyReview, review_plan};
use crate::risk_classification::{RiskClassification, classify_plan_risk};
use crate::{AuthenticatedPrincipal, PlanPreviewControl, PlanPreviewControlError};

const MAX_CANONICAL_DIGEST_FIELD_BYTES: usize = 256 * 1024;

/// Process-local capability minted only by `DurableAuthorityControl` after its
/// fresh authority-use critical section wins the durable CAS. Persistence stores
/// no reconstructible credential. This type intentionally is not `Clone`.
///
/// ```compile_fail
/// use linura_control::DispatchPermit;
///
/// fn duplicate(permit: DispatchPermit) {
///     let _copy = permit.clone();
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct DispatchPermit {
    transaction_id: TransactionId,
    generation: u64,
    state_version: u64,
    binding_digest: ContentDigest,
    authority_use_digest: ContentDigest,
}

impl DispatchPermit {
    fn from_commit(commit: HandoffCommit) -> Self {
        Self {
            transaction_id: commit.transaction_id,
            generation: commit.generation,
            state_version: commit.state_version,
            binding_digest: commit.binding_digest,
            authority_use_digest: commit.authority_use_digest,
        }
    }

    #[must_use]
    pub fn transaction_id(&self) -> &TransactionId {
        &self.transaction_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn state_version(&self) -> u64 {
        self.state_version
    }

    #[must_use]
    pub fn binding_digest(&self) -> &ContentDigest {
        &self.binding_digest
    }

    #[must_use]
    pub fn authority_use_digest(&self) -> &ContentDigest {
        &self.authority_use_digest
    }
}

#[derive(Debug)]
pub struct VerifiedDurableAuthority {
    snapshot: TransactionSnapshot,
    principal: PrincipalId,
    desired_state_digest: ContentDigest,
    graph_digest: ContentDigest,
    provenance_digest: ContentDigest,
}

impl VerifiedDurableAuthority {
    #[must_use]
    pub fn snapshot(&self) -> &TransactionSnapshot {
        &self.snapshot
    }
}

#[derive(Debug)]
pub enum DurableRecoveryOutcome {
    Verified(VerifiedDurableAuthority),
    Reprepared(Box<PreparedDurableAuthority>),
    Blocked(TransactionSnapshot),
    StillIndeterminate(TransactionSnapshot),
}

#[derive(Debug)]
pub struct FreshRecoveryApproval {
    request_id: ApprovalRequestId,
    approver: PolicyAuthenticatedApprover,
    expires_at_unix_seconds: u64,
}

impl FreshRecoveryApproval {
    #[must_use]
    pub fn new(
        request_id: ApprovalRequestId,
        approver: PolicyAuthenticatedApprover,
        expires_at_unix_seconds: u64,
    ) -> Self {
        Self {
            request_id,
            approver,
            expires_at_unix_seconds,
        }
    }
}

enum RecoveryApproval {
    Existing(Option<ApprovalEvidenceId>),
    OnDemand(FreshRecoveryApproval),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RiskProvenance {
    risk: RiskClass,
    revision: String,
    rule_ids: Vec<String>,
}

#[derive(Debug)]
pub struct DurableAuthorityCandidate {
    principal: AuthenticatedPrincipal,
    plan: linura_planner::ReconciliationPlan,
    observation: ObservationEnvelope,
    review: TrustedPolicyReview,
    risk: RiskProvenance,
    request_digest: ContentDigest,
    precondition_digest: ContentDigest,
    observation_digest: ContentDigest,
    review_digest: ContentDigest,
}

impl DurableAuthorityCandidate {
    #[must_use]
    pub fn principal(&self) -> &AuthenticatedPrincipal {
        &self.principal
    }

    #[must_use]
    pub fn plan_id(&self) -> &linura_core::PlanId {
        &self.plan.id
    }

    #[must_use]
    pub fn review(&self) -> &TrustedPolicyReview {
        &self.review
    }

    #[must_use]
    pub fn observation_digest(&self) -> &ContentDigest {
        &self.observation_digest
    }

    #[must_use]
    pub fn review_digest(&self) -> &ContentDigest {
        &self.review_digest
    }
}

#[derive(Debug)]
pub struct PreparedDurableAuthority {
    candidate: DurableAuthorityCandidate,
    binding: AuthorityBinding,
    snapshot: TransactionSnapshot,
    approval_evidence_id: Option<ApprovalEvidenceId>,
    handed_off: bool,
}

impl PreparedDurableAuthority {
    #[must_use]
    pub fn snapshot(&self) -> &TransactionSnapshot {
        &self.snapshot
    }

    #[must_use]
    pub fn binding(&self) -> &AuthorityBinding {
        &self.binding
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableAuthorityError {
    Preview(String),
    CandidateNotMutation,
    CandidateBlocked,
    RiskNotClassified,
    MissingApproval,
    UnexpectedApproval,
    Approval(String),
    ApprovalUnsatisfied(ApprovalValidation),
    AuthorityChanged,
    ClockUnavailable,
    ClockRollback,
    DigestFieldTooLarge,
    Transaction(String),
    AlreadyHandedOff,
    RecoveryRequestMismatch,
    RecoveryNotIndeterminate,
}

impl Display for DurableAuthorityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preview(reason) => write!(formatter, "durable authority planning failed: {reason}"),
            Self::CandidateNotMutation => {
                formatter.write_str("durable authority requires a change-proposed mutation plan")
            }
            Self::CandidateBlocked => {
                formatter.write_str("deny/blocked review cannot become durable authority")
            }
            Self::RiskNotClassified => formatter.write_str(
                "mutation plan does not have complete trusted risk-policy provenance",
            ),
            Self::MissingApproval => {
                formatter.write_str("current exact-bound approval evidence is required")
            }
            Self::UnexpectedApproval => formatter.write_str(
                "approval evidence was supplied for a policy-allow authority subject",
            ),
            Self::Approval(reason) => write!(formatter, "approval authority failed: {reason}"),
            Self::ApprovalUnsatisfied(validation) => write!(
                formatter,
                "approval authority is not currently satisfied: {validation:?}"
            ),
            Self::AuthorityChanged => formatter.write_str(
                "current observation/review/policy/risk/approval no longer matches prepared authority",
            ),
            Self::ClockUnavailable => formatter.write_str("authority clock is unavailable"),
            Self::ClockRollback => formatter.write_str("authority clock moved backwards"),
            Self::DigestFieldTooLarge => formatter.write_str(
                "canonical authority digest input exceeds the per-field bound",
            ),
            Self::Transaction(reason) => {
                write!(formatter, "durable transaction operation failed: {reason}")
            }
            Self::AlreadyHandedOff => formatter.write_str(
                "this process-local prepared authority has already crossed the handoff boundary",
            ),
            Self::RecoveryRequestMismatch => formatter.write_str(
                "recovery request does not match the durable original request namespace/material",
            ),
            Self::RecoveryNotIndeterminate => formatter.write_str(
                "recovery requires the exact current indeterminate generation",
            ),
        }
    }
}

impl std::error::Error for DurableAuthorityError {}

impl From<PlanPreviewControlError> for DurableAuthorityError {
    fn from(error: PlanPreviewControlError) -> Self {
        Self::Preview(error.to_string())
    }
}

impl From<TransactionStoreError> for DurableAuthorityError {
    fn from(error: TransactionStoreError) -> Self {
        Self::Transaction(error.to_string())
    }
}

impl From<TransactionValidationError> for DurableAuthorityError {
    fn from(error: TransactionValidationError) -> Self {
        Self::Transaction(error.to_string())
    }
}

/// Control-owned durable authority orchestrator.
///
/// This type deliberately owns both mutable approval state and the durable
/// transaction coordinator. Every approval issue/revocation and every prepare /
/// handoff authority use therefore serializes through one `&mut self` boundary.
/// Persistence receives only Control-derived canonical bindings; callers never
/// supply policy decisions, risk classifications or transaction permits.
#[derive(Debug)]
pub struct DurableAuthorityControl<S>
where
    S: TransactionStore,
{
    approvals: crate::ApprovalReviewControl,
    transactions: S,
    authority_signer: TransactionAuthoritySigner,
    last_authority_unix_ms: u64,
}

impl<S> DurableAuthorityControl<S>
where
    S: TransactionStore,
{
    pub fn new(
        store: S,
        authority_signer: TransactionAuthoritySigner,
    ) -> Result<Self, DurableAuthorityError> {
        let mut control = Self {
            approvals: crate::ApprovalReviewControl::default(),
            transactions: store,
            authority_signer,
            last_authority_unix_ms: 0,
        };
        control.abort_prepared_after_restart()?;
        Ok(control)
    }

    /// Build fresh trusted authority material entirely inside Control.
    ///
    /// The desired-state request is public input, but the authoritative
    /// observation, canonical plan, trusted risk classification and policy review
    /// are all derived internally before the candidate is returned.
    pub fn candidate(
        &mut self,
        previews: &mut PlanPreviewControl,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
    ) -> Result<DurableAuthorityCandidate, DurableAuthorityError> {
        let request_digest = digest_request(&request)?;
        let (plan, observation) =
            previews.authority_candidate(principal.clone(), actor, request)?;
        if plan.status != linura_planner::PlanStatus::ChangeProposed
            || plan.changes.is_empty()
            || plan.execution_authorized()
        {
            return Err(DurableAuthorityError::CandidateNotMutation);
        }

        let risk = risk_provenance(&plan)?;
        let review = review_plan(&principal, &plan)
            .map_err(|error| DurableAuthorityError::Preview(format!("{error:?}")))?;
        if matches!(
            review.decision(),
            PolicyDecision::Deny { .. } | PolicyDecision::Blocked { .. }
        ) || review.subject().status() != ReviewPlanStatus::ChangeProposed
            || review.subject().has_blockers()
        {
            return Err(DurableAuthorityError::CandidateBlocked);
        }
        let precondition_digest = digest_plan_precondition(&plan)?;
        let observation_digest = digest_observation(&observation)?;
        let review_digest = digest_review(&review)?;

        Ok(DurableAuthorityCandidate {
            principal,
            plan,
            observation,
            review,
            risk,
            request_digest,
            precondition_digest,
            observation_digest,
            review_digest,
        })
    }

    pub fn issue_approval(
        &mut self,
        request_id: ApprovalRequestId,
        candidate: &DurableAuthorityCandidate,
        approver: &PolicyAuthenticatedApprover,
        expires_at_unix_seconds: u64,
    ) -> Result<crate::PolicyApprovalEvidence, DurableAuthorityError> {
        self.approvals
            .issue(
                request_id,
                &candidate.review,
                approver,
                expires_at_unix_seconds,
            )
            .map_err(map_approval_error)
    }

    pub fn revoke_approval(
        &mut self,
        evidence_id: &ApprovalEvidenceId,
        revoker: &PolicyAuthenticatedApprover,
    ) -> Result<(), DurableAuthorityError> {
        self.approvals
            .revoke(evidence_id, revoker)
            .map_err(map_approval_error)
    }

    pub fn prepare(
        &mut self,
        candidate: DurableAuthorityCandidate,
        approval_evidence_id: Option<ApprovalEvidenceId>,
    ) -> Result<PreparedDurableAuthority, DurableAuthorityError> {
        let now_unix_ms = self.authority_now_unix_ms()?;
        let binding =
            self.revalidate_and_bind(&candidate, approval_evidence_id.as_ref(), now_unix_ms)?;
        let snapshot = match self.transactions.prepare(&binding)? {
            PrepareOutcome::Created(snapshot) | PrepareOutcome::Existing(snapshot) => snapshot,
        };
        if snapshot.binding_digest != *binding.digest()
            || snapshot.principal != *binding.principal()
            || snapshot.request_id != *binding.request_id()
        {
            return Err(DurableAuthorityError::AuthorityChanged);
        }
        Ok(PreparedDurableAuthority {
            candidate,
            binding,
            snapshot,
            approval_evidence_id,
            handed_off: false,
        })
    }

    /// Revalidate all mutable authority immediately before the durable
    /// `Prepared -> Indeterminate` CAS. Only a successful CAS returns a permit.
    pub fn handoff(
        &mut self,
        principal: &AuthenticatedPrincipal,
        prepared: &mut PreparedDurableAuthority,
    ) -> Result<DispatchPermit, DurableAuthorityError> {
        if prepared.handed_off {
            return Err(DurableAuthorityError::AlreadyHandedOff);
        }
        if principal.as_str() != prepared.candidate.principal.as_str()
            || principal.as_str() != prepared.binding.principal().as_str()
            || principal.as_str() != prepared.snapshot.principal.as_str()
        {
            return Err(DurableAuthorityError::AuthorityChanged);
        }
        let now_unix_ms = self.authority_now_unix_ms()?;
        let current = self.revalidate_and_bind(
            &prepared.candidate,
            prepared.approval_evidence_id.as_ref(),
            now_unix_ms,
        )?;
        if current.digest() != prepared.binding.digest() {
            return Err(DurableAuthorityError::AuthorityChanged);
        }

        let durable = self
            .transactions
            .snapshot(&prepared.snapshot.transaction_id)?;
        if durable != prepared.snapshot {
            return Err(DurableAuthorityError::AuthorityChanged);
        }
        let authority_use_digest = digest_authority_use(&durable, now_unix_ms)?;
        let expires_at_unix_ms =
            authority_expires_at_unix_ms(&prepared.candidate.observation, &current)?;
        let handoff = self.authority_signer.authorize_handoff(
            &durable,
            authority_use_digest,
            now_unix_ms,
            expires_at_unix_ms,
        )?;
        let commit = self.transactions.handoff(&handoff)?;
        prepared.handed_off = true;
        Ok(DispatchPermit::from_commit(commit))
    }

    /// Fail closed across a process restart before the ambiguity boundary.
    ///
    /// v0.4 approval/revocation state is process-local, so a fresh Control
    /// instance cannot safely resume a prior `Prepared` authority-use section.
    /// The durable exact binding remains auditable, but every prepared generation
    /// is deterministically retired before the new process accepts handoff work.
    pub fn abort_prepared_after_restart(
        &mut self,
    ) -> Result<Vec<TransactionSnapshot>, DurableAuthorityError> {
        let prepared = self.transactions.list_state(TransactionState::Prepared)?;
        let reason = digest_parts(
            "linura.control.restart-prepared-abort.v1",
            [b"process-local mutable authority state was lost at restart".as_slice()],
        );
        let mut retired = Vec::with_capacity(prepared.len());
        for snapshot in prepared {
            retired.push(self.transactions.abort_prepared(&AbortRequest {
                transaction_id: snapshot.transaction_id.clone(),
                expected_generation: snapshot.current_generation,
                expected_state_version: snapshot.state_version,
                reason_digest: reason.clone(),
            })?);
        }
        Ok(retired)
    }

    /// Classify and serialize recovery from the exact current indeterminate
    /// generation using fresh authoritative observation inside Control. Public
    /// callers may resupply desired-state request bytes, but a durable request
    /// digest prevents request substitution. Recovery resolutions themselves are
    /// never accepted from callers.
    pub fn recover_indeterminate(
        &mut self,
        previews: &mut PlanPreviewControl,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        approval_evidence_id: Option<ApprovalEvidenceId>,
    ) -> Result<DurableRecoveryOutcome, DurableAuthorityError> {
        self.recover_indeterminate_inner(
            previews,
            principal,
            actor,
            request,
            RecoveryApproval::Existing(approval_evidence_id),
        )
    }

    /// Recover using approval authority bound to the exact fresh recovery candidate.
    pub fn recover_indeterminate_with_approver(
        &mut self,
        previews: &mut PlanPreviewControl,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        approval: FreshRecoveryApproval,
    ) -> Result<DurableRecoveryOutcome, DurableAuthorityError> {
        self.recover_indeterminate_inner(
            previews,
            principal,
            actor,
            request,
            RecoveryApproval::OnDemand(approval),
        )
    }

    fn recover_indeterminate_inner(
        &mut self,
        previews: &mut PlanPreviewControl,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        approval: RecoveryApproval,
    ) -> Result<DurableRecoveryOutcome, DurableAuthorityError> {
        let principal_id = PrincipalId::new(principal.as_str().to_owned())
            .map_err(|error| DurableAuthorityError::Preview(error.to_string()))?;
        let transaction_id = TransactionId::for_namespace(&principal_id, &request.request_id);
        let anchor = self.transactions.recovery_anchor(&transaction_id)?;
        if anchor.snapshot.state != TransactionState::Indeterminate {
            return Err(DurableAuthorityError::RecoveryNotIndeterminate);
        }
        if anchor.snapshot.principal != principal_id
            || anchor.snapshot.request_id != request.request_id
            || anchor.request_digest != digest_request(&request)?
        {
            return Err(DurableAuthorityError::RecoveryRequestMismatch);
        }

        let request_digest = anchor.request_digest.clone();
        let (plan, observation) =
            previews.authority_candidate(principal.clone(), actor, request)?;
        observation
            .validate(&plan.provider, &plan.resource, &plan.observation_capability)
            .map_err(|error| DurableAuthorityError::Preview(error.to_string()))?;
        let observation_digest = digest_observation(&observation)?;

        match plan.status {
            linura_planner::PlanStatus::NoChange => {
                observation
                    .require_current(self.authority_now_unix_ms()?)
                    .map_err(|error| DurableAuthorityError::Preview(error.to_string()))?;
                let authorized_at_unix_ms = self.authority_now_unix_ms()?;
                observation
                    .require_current(authorized_at_unix_ms)
                    .map_err(|error| DurableAuthorityError::Preview(error.to_string()))?;
                let (desired_state_digest, graph_digest, provenance_digest) =
                    verified_commit_digests(&anchor, &plan, &observation_digest)?;
                let recovery = self.authority_signer.authorize_recovery(
                    &anchor.snapshot,
                    RecoveryResolution::IntendedStateVerified {
                        observation_digest: observation_digest.clone(),
                        desired_state_digest: desired_state_digest.clone(),
                        graph_digest: graph_digest.clone(),
                        provenance_digest: provenance_digest.clone(),
                    },
                    authorized_at_unix_ms,
                    observation_expires_at_unix_ms(&observation)?,
                )?;
                let outcome = self.transactions.recover(&recovery)?;
                match outcome {
                    RecoveryOutcome::Verified(snapshot) => {
                        let material = self
                            .transactions
                            .verified_commit_material(&snapshot.transaction_id)?;
                        if material.snapshot != snapshot
                            || material.desired_state_digest != desired_state_digest
                            || material.graph_digest != graph_digest
                            || material.provenance_digest != provenance_digest
                        {
                            return Err(DurableAuthorityError::AuthorityChanged);
                        }
                        Ok(DurableRecoveryOutcome::Verified(VerifiedDurableAuthority {
                            principal: material.snapshot.principal.clone(),
                            snapshot: material.snapshot,
                            desired_state_digest: material.desired_state_digest,
                            graph_digest: material.graph_digest,
                            provenance_digest: material.provenance_digest,
                        }))
                    }
                    _ => Err(DurableAuthorityError::AuthorityChanged),
                }
            }
            linura_planner::PlanStatus::ChangeProposed => {
                let precondition_digest = digest_plan_precondition(&plan)?;
                if precondition_digest != anchor.precondition_digest {
                    observation
                        .require_current(self.authority_now_unix_ms()?)
                        .map_err(|error| DurableAuthorityError::Preview(error.to_string()))?;
                    let authorized_at_unix_ms = self.authority_now_unix_ms()?;
                    observation
                        .require_current(authorized_at_unix_ms)
                        .map_err(|error| DurableAuthorityError::Preview(error.to_string()))?;
                    let recovery = self.authority_signer.authorize_recovery(
                        &anchor.snapshot,
                        RecoveryResolution::ConflictingState {
                            observation_digest: observation_digest.clone(),
                        },
                        authorized_at_unix_ms,
                        observation_expires_at_unix_ms(&observation)?,
                    )?;
                    let outcome = self.transactions.recover(&recovery)?;
                    return match outcome {
                        RecoveryOutcome::Blocked(snapshot) => {
                            Ok(DurableRecoveryOutcome::Blocked(snapshot))
                        }
                        _ => Err(DurableAuthorityError::AuthorityChanged),
                    };
                }

                let risk = risk_provenance(&plan)?;
                let review = review_plan(&principal, &plan)
                    .map_err(|error| DurableAuthorityError::Preview(format!("{error:?}")))?;
                if matches!(
                    review.decision(),
                    PolicyDecision::Deny { .. } | PolicyDecision::Blocked { .. }
                ) || review.subject().status() != ReviewPlanStatus::ChangeProposed
                    || review.subject().has_blockers()
                {
                    let authorized_at_unix_ms = self.authority_now_unix_ms()?;
                    observation
                        .require_current(authorized_at_unix_ms)
                        .map_err(|error| DurableAuthorityError::Preview(error.to_string()))?;
                    let recovery = self.authority_signer.authorize_recovery(
                        &anchor.snapshot,
                        RecoveryResolution::Ambiguous {
                            observation_digest: observation_digest.clone(),
                        },
                        authorized_at_unix_ms,
                        observation_expires_at_unix_ms(&observation)?,
                    )?;
                    let outcome = self.transactions.recover(&recovery)?;
                    return match outcome {
                        RecoveryOutcome::StillIndeterminate(snapshot) => {
                            Ok(DurableRecoveryOutcome::StillIndeterminate(snapshot))
                        }
                        _ => Err(DurableAuthorityError::AuthorityChanged),
                    };
                }
                let review_digest = digest_review(&review)?;
                let candidate = DurableAuthorityCandidate {
                    principal,
                    plan,
                    observation,
                    review,
                    risk,
                    request_digest,
                    precondition_digest,
                    observation_digest: observation_digest.clone(),
                    review_digest,
                };
                let approval_evidence_id = match &approval {
                    RecoveryApproval::Existing(existing) => existing.clone(),
                    RecoveryApproval::OnDemand(approval) => match candidate.review.decision() {
                        PolicyDecision::Allow => None,
                        PolicyDecision::RequireApproval { .. } => Some(
                            self.issue_approval(
                                approval.request_id.clone(),
                                &candidate,
                                &approval.approver,
                                approval.expires_at_unix_seconds,
                            )?
                            .id()
                            .clone(),
                        ),
                        PolicyDecision::Deny { .. } | PolicyDecision::Blocked { .. } => {
                            return Err(DurableAuthorityError::CandidateBlocked);
                        }
                    },
                };
                let now_unix_ms = self.authority_now_unix_ms()?;
                let next_binding = self.revalidate_and_bind(
                    &candidate,
                    approval_evidence_id.as_ref(),
                    now_unix_ms,
                )?;
                let authorized_at_unix_ms = self.authority_now_unix_ms()?;
                candidate
                    .observation
                    .require_current(authorized_at_unix_ms)
                    .map_err(|error| DurableAuthorityError::Preview(error.to_string()))?;
                let expires_at_unix_ms =
                    authority_expires_at_unix_ms(&candidate.observation, &next_binding)?;
                let recovery = self.authority_signer.authorize_recovery(
                    &anchor.snapshot,
                    RecoveryResolution::IntendedEffectAbsent {
                        observation_digest,
                        next_binding: Box::new(next_binding.clone()),
                    },
                    authorized_at_unix_ms,
                    expires_at_unix_ms,
                )?;
                let outcome = self.transactions.recover(&recovery)?;
                match outcome {
                    RecoveryOutcome::Reprepared(snapshot) => Ok(
                        DurableRecoveryOutcome::Reprepared(Box::new(PreparedDurableAuthority {
                            candidate,
                            binding: next_binding,
                            snapshot,
                            approval_evidence_id,
                            handed_off: false,
                        })),
                    ),
                    _ => Err(DurableAuthorityError::AuthorityChanged),
                }
            }
            linura_planner::PlanStatus::Blocked => {
                let authorized_at_unix_ms = self.authority_now_unix_ms()?;
                observation
                    .require_current(authorized_at_unix_ms)
                    .map_err(|error| DurableAuthorityError::Preview(error.to_string()))?;
                let recovery = self.authority_signer.authorize_recovery(
                    &anchor.snapshot,
                    RecoveryResolution::Ambiguous { observation_digest },
                    authorized_at_unix_ms,
                    observation_expires_at_unix_ms(&observation)?,
                )?;
                let outcome = self.transactions.recover(&recovery)?;
                match outcome {
                    RecoveryOutcome::StillIndeterminate(snapshot) => {
                        Ok(DurableRecoveryOutcome::StillIndeterminate(snapshot))
                    }
                    _ => Err(DurableAuthorityError::AuthorityChanged),
                }
            }
        }
    }

    pub fn snapshot(
        &self,
        transaction_id: &TransactionId,
    ) -> Result<TransactionSnapshot, DurableAuthorityError> {
        self.transactions
            .snapshot(transaction_id)
            .map_err(Into::into)
    }

    /// Prove that a stable request namespace still carries the exact
    /// canonical request material sealed into durable authority.
    pub fn assert_request_matches(
        &self,
        principal: &AuthenticatedPrincipal,
        request: &PlanDesiredStateRequest,
    ) -> Result<(), DurableAuthorityError> {
        let principal_id = PrincipalId::new(principal.as_str().to_owned())
            .map_err(|error| DurableAuthorityError::Preview(error.to_string()))?;
        let transaction_id = TransactionId::for_namespace(&principal_id, &request.request_id);
        let anchor = self.transactions.recovery_anchor(&transaction_id)?;
        if anchor.snapshot.principal != principal_id
            || anchor.snapshot.request_id != request.request_id
            || anchor.request_digest != digest_request(request)?
        {
            return Err(DurableAuthorityError::RecoveryRequestMismatch);
        }
        Ok(())
    }
    pub fn integrity_check(&self) -> Result<(), DurableAuthorityError> {
        self.transactions.integrity_check().map_err(Into::into)
    }

    /// Reconstruct the process-local verified commit capability from the exact
    /// durable, signer-bound verification material after restart or a retryable
    /// persistence failure. No policy/approval authority is reconstructed.
    pub fn resume_verified(
        &self,
        principal: &AuthenticatedPrincipal,
        transaction_id: &TransactionId,
    ) -> Result<VerifiedDurableAuthority, DurableAuthorityError> {
        let material = self.transactions.verified_commit_material(transaction_id)?;
        if material.snapshot.state != TransactionState::Verified
            || principal.as_str() != material.snapshot.principal.as_str()
        {
            return Err(DurableAuthorityError::AuthorityChanged);
        }
        Ok(VerifiedDurableAuthority {
            principal: material.snapshot.principal.clone(),
            snapshot: material.snapshot,
            desired_state_digest: material.desired_state_digest,
            graph_digest: material.graph_digest,
            provenance_digest: material.provenance_digest,
        })
    }

    pub fn commit_verified(
        &mut self,
        principal: &AuthenticatedPrincipal,
        verified: VerifiedDurableAuthority,
    ) -> Result<TransactionSnapshot, DurableAuthorityError> {
        if principal.as_str() != verified.principal.as_str()
            || principal.as_str() != verified.snapshot.principal.as_str()
            || verified.snapshot.state != TransactionState::Verified
        {
            return Err(DurableAuthorityError::AuthorityChanged);
        }
        let durable = self
            .transactions
            .snapshot(&verified.snapshot.transaction_id)?;
        if durable != verified.snapshot {
            return Err(DurableAuthorityError::AuthorityChanged);
        }
        let request: CommitRequest = self.authority_signer.authorize_commit(
            &durable,
            verified.desired_state_digest,
            verified.graph_digest,
            verified.provenance_digest,
        )?;
        self.transactions.commit(&request).map_err(Into::into)
    }

    fn authority_now_unix_ms(&mut self) -> Result<u64, DurableAuthorityError> {
        let sampled = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DurableAuthorityError::ClockUnavailable)?
            .as_millis();
        let sampled =
            u64::try_from(sampled).map_err(|_| DurableAuthorityError::ClockUnavailable)?;
        if sampled < self.last_authority_unix_ms {
            return Err(DurableAuthorityError::ClockRollback);
        }
        self.last_authority_unix_ms = sampled;
        Ok(sampled)
    }

    fn revalidate_and_bind(
        &self,
        candidate: &DurableAuthorityCandidate,
        approval_evidence_id: Option<&ApprovalEvidenceId>,
        now_unix_ms: u64,
    ) -> Result<AuthorityBinding, DurableAuthorityError> {
        candidate
            .observation
            .require_current(now_unix_ms)
            .map_err(|error| DurableAuthorityError::Preview(error.to_string()))?;
        candidate
            .observation
            .validate(
                &candidate.plan.provider,
                &candidate.plan.resource,
                &candidate.plan.observation_capability,
            )
            .map_err(|error| DurableAuthorityError::Preview(error.to_string()))?;
        if digest_observation(&candidate.observation)? != candidate.observation_digest {
            return Err(DurableAuthorityError::AuthorityChanged);
        }

        let risk = risk_provenance(&candidate.plan)?;
        if risk != candidate.risk {
            return Err(DurableAuthorityError::AuthorityChanged);
        }
        let review = review_plan(&candidate.principal, &candidate.plan)
            .map_err(|error| DurableAuthorityError::Preview(format!("{error:?}")))?;
        if digest_review(&review)? != candidate.review_digest || review != candidate.review {
            return Err(DurableAuthorityError::AuthorityChanged);
        }

        let authorization = match review.decision() {
            PolicyDecision::Allow => {
                if approval_evidence_id.is_some() {
                    return Err(DurableAuthorityError::UnexpectedApproval);
                }
                AuthorizationBasis::PolicyAllow
            }
            PolicyDecision::RequireApproval { class, .. } => {
                let evidence_id =
                    approval_evidence_id.ok_or(DurableAuthorityError::MissingApproval)?;
                let validation = self
                    .approvals
                    .validate(evidence_id, &review)
                    .map_err(map_approval_error)?;
                if validation != ApprovalValidation::Satisfied {
                    return Err(DurableAuthorityError::ApprovalUnsatisfied(validation));
                }
                let evidence = self
                    .approvals
                    .get(evidence_id)
                    .ok_or(DurableAuthorityError::MissingApproval)?;
                AuthorizationBasis::Approval(ApprovalAuthority::try_new(
                    evidence.id().clone(),
                    evidence.request_id().clone(),
                    evidence.approver().clone(),
                    approval_class_name(*class),
                    evidence.issued_at_unix_seconds(),
                    evidence.expires_at_unix_seconds(),
                )?)
            }
            PolicyDecision::Deny { .. } | PolicyDecision::Blocked { .. } => {
                return Err(DurableAuthorityError::CandidateBlocked);
            }
        };

        let subject = review.subject();
        let binding = review.binding();
        let principal = PrincipalId::new(candidate.principal.as_str().to_owned())
            .map_err(|error| DurableAuthorityError::Preview(error.to_string()))?;
        AuthorityBinding::try_new(
            principal,
            subject.request_id().clone(),
            subject.plan_id().clone(),
            candidate.request_digest.clone(),
            candidate.precondition_digest.clone(),
            candidate.observation_digest.clone(),
            subject.provider().clone(),
            subject.resource().clone(),
            subject.capability().clone(),
            binding.policy_id.clone(),
            binding.policy_revision_id.clone(),
            candidate.risk.risk,
            candidate.risk.revision.clone(),
            candidate.risk.rule_ids.clone(),
            candidate.review_digest.clone(),
            authorization,
        )
        .map_err(Into::into)
    }
}

fn map_approval_error(error: ApprovalControlError) -> DurableAuthorityError {
    DurableAuthorityError::Approval(format!("{error:?}"))
}

fn risk_provenance(
    plan: &linura_planner::ReconciliationPlan,
) -> Result<RiskProvenance, DurableAuthorityError> {
    match classify_plan_risk(plan) {
        RiskClassification::Classified {
            risk,
            revision,
            rule_ids,
        } => Ok(RiskProvenance {
            risk,
            revision: revision.to_owned(),
            rule_ids: rule_ids.into_iter().map(str::to_owned).collect(),
        }),
        RiskClassification::NotApplicable { .. }
        | RiskClassification::Unclassified { .. }
        | RiskClassification::DowngradeRejected { .. } => {
            Err(DurableAuthorityError::RiskNotClassified)
        }
    }
}

fn approval_class_name(class: ApprovalClass) -> &'static str {
    match class {
        ApprovalClass::InteractiveUser => "interactive-user",
        ApprovalClass::Administrator => "administrator",
        ApprovalClass::DestructiveAction => "destructive-action",
    }
}

fn risk_name(risk: RiskClass) -> &'static str {
    match risk {
        RiskClass::ReadOnly => "read-only",
        RiskClass::UserState => "user-state",
        RiskClass::SystemMutation => "system-mutation",
        RiskClass::SecuritySensitive => "security-sensitive",
        RiskClass::Destructive => "destructive",
    }
}

fn actor_kind_name(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Human => "human",
        ActorKind::Service => "service",
        ActorKind::Agent => "agent",
        ActorKind::Remote => "remote",
    }
}

fn review_status_name(status: ReviewPlanStatus) -> &'static str {
    match status {
        ReviewPlanStatus::NoChange => "no-change",
        ReviewPlanStatus::ChangeProposed => "change-proposed",
        ReviewPlanStatus::Blocked => "blocked",
    }
}

fn finding_level_name(level: ReviewFindingLevel) -> &'static str {
    match level {
        ReviewFindingLevel::Pass => "pass",
        ReviewFindingLevel::Warning => "warning",
        ReviewFindingLevel::Blocker => "blocker",
    }
}

struct CanonicalHasher {
    hasher: Sha256,
}

impl CanonicalHasher {
    fn new(domain: &str) -> Result<Self, DurableAuthorityError> {
        let mut value = Self {
            hasher: Sha256::new(),
        };
        value.field(domain.as_bytes())?;
        Ok(value)
    }

    fn field(&mut self, bytes: &[u8]) -> Result<(), DurableAuthorityError> {
        if bytes.len() > MAX_CANONICAL_DIGEST_FIELD_BYTES {
            return Err(DurableAuthorityError::DigestFieldTooLarge);
        }
        let len =
            u64::try_from(bytes.len()).map_err(|_| DurableAuthorityError::DigestFieldTooLarge)?;
        self.hasher.update(len.to_be_bytes());
        self.hasher.update(bytes);
        Ok(())
    }

    fn text(&mut self, value: &str) -> Result<(), DurableAuthorityError> {
        self.field(value.as_bytes())
    }

    fn number(&mut self, value: u64) -> Result<(), DurableAuthorityError> {
        self.field(&value.to_be_bytes())
    }

    fn finish(self) -> Result<ContentDigest, DurableAuthorityError> {
        ContentDigest::new(format!("sha256:{:x}", self.hasher.finalize())).map_err(Into::into)
    }
}

fn digest_request(
    request: &PlanDesiredStateRequest,
) -> Result<ContentDigest, DurableAuthorityError> {
    let mut digest = CanonicalHasher::new("linura.control.desired-request.v1")?;
    digest.text(request.request_id.as_str())?;
    digest.text(request.provider.as_str())?;
    digest.text(request.resource.as_str())?;
    digest.text(request.observation_capability.as_str())?;
    digest.text(&request.reason.summary)?;
    digest.number(
        u64::try_from(request.reason.intent_ids.len())
            .map_err(|_| DurableAuthorityError::DigestFieldTooLarge)?,
    )?;
    for id in &request.reason.intent_ids {
        digest.text(id.as_str())?;
    }
    digest.number(
        u64::try_from(request.reason.requirement_ids.len())
            .map_err(|_| DurableAuthorityError::DigestFieldTooLarge)?,
    )?;
    for id in &request.reason.requirement_ids {
        digest.text(id.as_str())?;
    }
    digest.number(
        u64::try_from(request.reason.capability_ids.len())
            .map_err(|_| DurableAuthorityError::DigestFieldTooLarge)?,
    )?;
    for id in &request.reason.capability_ids {
        digest.text(id.as_str())?;
    }
    digest.number(
        u64::try_from(request.desired_state.len())
            .map_err(|_| DurableAuthorityError::DigestFieldTooLarge)?,
    )?;
    for (key, value) in &request.desired_state {
        digest.text(key)?;
        digest.text(value)?;
    }
    digest.finish()
}

fn digest_plan_precondition(
    plan: &linura_planner::ReconciliationPlan,
) -> Result<ContentDigest, DurableAuthorityError> {
    let mut digest = CanonicalHasher::new("linura.control.plan-precondition.v1")?;
    digest.text(plan.provider.as_str())?;
    digest.text(plan.resource.as_str())?;
    digest.text(plan.observation_capability.as_str())?;
    digest.number(
        u64::try_from(plan.changes.len())
            .map_err(|_| DurableAuthorityError::DigestFieldTooLarge)?,
    )?;
    for change in &plan.changes {
        digest.text(&change.key)?;
        match &change.current {
            Some(value) => {
                digest.text("some")?;
                digest.text(value)?;
            }
            None => digest.text("none")?,
        }
    }
    digest.finish()
}

fn digest_observation(
    observation: &ObservationEnvelope,
) -> Result<ContentDigest, DurableAuthorityError> {
    let mut digest = CanonicalHasher::new("linura.control.observation.v1")?;
    digest.text(observation.provider.as_str())?;
    digest.text(observation.resource.as_str())?;
    digest.text(observation.capability.as_str())?;
    digest.text(observation.authority.as_str())?;
    digest.number(observation.observed_at_unix_ms)?;
    digest.number(observation.valid_for_ms)?;
    digest.number(observation.sequence)?;
    digest.number(
        u64::try_from(observation.attributes.len())
            .map_err(|_| DurableAuthorityError::DigestFieldTooLarge)?,
    )?;
    for (key, value) in &observation.attributes {
        digest.text(key)?;
        match value {
            ObservedValue::Text(value) => {
                digest.text("text")?;
                digest.text(value)?;
            }
            ObservedValue::Bool(value) => {
                digest.text("bool")?;
                digest.text(if *value { "true" } else { "false" })?;
            }
            ObservedValue::U64(value) => {
                digest.text("u64")?;
                digest.field(&value.to_be_bytes())?;
            }
            ObservedValue::I64(value) => {
                digest.text("i64")?;
                digest.field(&value.to_be_bytes())?;
            }
        }
    }
    digest.finish()
}

fn digest_review(review: &TrustedPolicyReview) -> Result<ContentDigest, DurableAuthorityError> {
    let subject = review.subject();
    let binding = review.binding();
    let mut digest = CanonicalHasher::new("linura.control.trusted-review.v1")?;
    digest.text(subject.principal().as_str())?;
    digest.text(subject.plan_id().as_str())?;
    digest.text(subject.request_id().as_str())?;
    digest.text(subject.actor().id.as_str())?;
    digest.text(actor_kind_name(subject.actor().kind))?;
    digest.text(if subject.actor().interactive {
        "interactive"
    } else {
        "non-interactive"
    })?;
    digest.text(subject.provider().as_str())?;
    digest.text(subject.resource().as_str())?;
    digest.text(subject.capability().as_str())?;
    digest.text(subject.observed_evidence_id())?;
    digest.text(risk_name(subject.prospective_risk()))?;
    digest.text(review_status_name(subject.status()))?;
    digest.text(&subject.reason().summary)?;
    digest.number(
        u64::try_from(subject.reason().intent_ids.len())
            .map_err(|_| DurableAuthorityError::DigestFieldTooLarge)?,
    )?;
    for id in &subject.reason().intent_ids {
        digest.text(id.as_str())?;
    }
    digest.number(
        u64::try_from(subject.reason().requirement_ids.len())
            .map_err(|_| DurableAuthorityError::DigestFieldTooLarge)?,
    )?;
    for id in &subject.reason().requirement_ids {
        digest.text(id.as_str())?;
    }
    digest.number(
        u64::try_from(subject.reason().capability_ids.len())
            .map_err(|_| DurableAuthorityError::DigestFieldTooLarge)?,
    )?;
    for id in &subject.reason().capability_ids {
        digest.text(id.as_str())?;
    }
    digest.number(
        u64::try_from(subject.changes().len())
            .map_err(|_| DurableAuthorityError::DigestFieldTooLarge)?,
    )?;
    for change in subject.changes() {
        digest.text(&change.key)?;
        match &change.current {
            Some(value) => {
                digest.text("some")?;
                digest.text(value)?;
            }
            None => digest.text("none")?,
        }
        digest.text(&change.desired)?;
    }
    digest.number(
        u64::try_from(subject.findings().len())
            .map_err(|_| DurableAuthorityError::DigestFieldTooLarge)?,
    )?;
    for finding in subject.findings() {
        digest.text(&finding.code)?;
        digest.text(finding_level_name(finding.level))?;
        digest.text(&finding.message)?;
    }
    digest.text(binding.policy_id.as_str())?;
    digest.text(binding.policy_revision_id.as_str())?;
    match review.decision() {
        PolicyDecision::Allow => digest.text("allow")?,
        PolicyDecision::Deny { reason } => {
            digest.text("deny")?;
            digest.text(reason)?;
        }
        PolicyDecision::RequireApproval { class, reason } => {
            digest.text("require-approval")?;
            digest.text(approval_class_name(*class))?;
            digest.text(reason)?;
        }
        PolicyDecision::Blocked { reason } => {
            digest.text("blocked")?;
            digest.text(reason)?;
        }
    }
    digest.finish()
}

fn digest_authority_use(
    snapshot: &TransactionSnapshot,
    now_unix_ms: u64,
) -> Result<ContentDigest, DurableAuthorityError> {
    let mut digest = CanonicalHasher::new("linura.control.authority-use.v1")?;
    digest.text(snapshot.transaction_id.as_str())?;
    digest.number(snapshot.current_generation)?;
    digest.number(snapshot.state_version)?;
    digest.text(snapshot.binding_digest.as_str())?;
    digest.number(now_unix_ms)?;
    digest.finish()
}

fn observation_expires_at_unix_ms(
    observation: &ObservationEnvelope,
) -> Result<u64, DurableAuthorityError> {
    observation
        .observed_at_unix_ms
        .checked_add(observation.valid_for_ms)
        .ok_or(DurableAuthorityError::ClockUnavailable)
}

fn exclusive_seconds_to_last_valid_unix_ms(
    exclusive_unix_seconds: u64,
) -> Result<u64, DurableAuthorityError> {
    exclusive_unix_seconds
        .checked_mul(1_000)
        .and_then(|exclusive_ms| exclusive_ms.checked_sub(1))
        .ok_or(DurableAuthorityError::ClockUnavailable)
}

fn authority_expires_at_unix_ms(
    observation: &ObservationEnvelope,
    binding: &AuthorityBinding,
) -> Result<u64, DurableAuthorityError> {
    let observation_expiry = observation_expires_at_unix_ms(observation)?;
    match binding.authorization() {
        AuthorizationBasis::PolicyAllow => Ok(observation_expiry),
        AuthorizationBasis::Approval(approval) => {
            let approval_expiry =
                exclusive_seconds_to_last_valid_unix_ms(approval.expires_at_unix_seconds())?;
            Ok(observation_expiry.min(approval_expiry))
        }
    }
}

fn verified_commit_digests(
    anchor: &linura_transaction::RecoveryAnchor,
    plan: &linura_planner::ReconciliationPlan,
    observation_digest: &ContentDigest,
) -> Result<(ContentDigest, ContentDigest, ContentDigest), DurableAuthorityError> {
    let desired_state_digest = anchor.request_digest.clone();
    let graph_digest = digest_parts(
        "linura.control.verified-graph.v1",
        [
            plan.id.as_str().as_bytes(),
            plan.provider.as_str().as_bytes(),
            plan.resource.as_str().as_bytes(),
            anchor.precondition_digest.as_str().as_bytes(),
            observation_digest.as_str().as_bytes(),
        ],
    );
    let provenance_digest = digest_parts(
        "linura.control.verified-provenance.v1",
        [
            anchor.snapshot.transaction_id.as_str().as_bytes(),
            anchor.snapshot.binding_digest.as_str().as_bytes(),
            anchor.request_digest.as_str().as_bytes(),
            anchor.precondition_digest.as_str().as_bytes(),
            observation_digest.as_str().as_bytes(),
        ],
    );
    Ok((desired_state_digest, graph_digest, provenance_digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_expiry_seconds_remain_exclusive_when_sealed_as_milliseconds() {
        assert_eq!(
            exclusive_seconds_to_last_valid_unix_ms(42)
                .unwrap_or_else(|error| unreachable!("{error}")),
            41_999
        );
    }
}
