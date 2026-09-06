use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Display, Formatter};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use linura_core::{
    Actor, ActorKind, ApprovalRequestId, PlanId, PrincipalId, ProviderId, RequestId, ResourceId,
};
use linura_lifecycle::{MutationProgress, MutationStage};
use linura_policy::{ApprovalClass, PolicyDecision};
use linura_protocol::PlanDesiredStateRequest;
use linura_provider_sdk::{
    ComponentDigest, EffectDescriptor, ExecutionBinding, ExecutionDisposition, ExecutionOutcome,
    VerificationDisposition, VerificationOutcome,
};
use linura_transaction::{TransactionId, TransactionState, TransactionStore};
use sha2::{Digest, Sha256};

use crate::approval_review::PolicyAuthenticatedApprover;
use crate::policy_review::TrustedPolicyReview;
use crate::{
    AuthenticatedPrincipal, DispatchPermit, DurableAuthorityCandidate, DurableAuthorityControl,
    DurableAuthorityError, DurableRecoveryOutcome, FreshRecoveryApproval, PlanPreviewControl,
    PreparedDurableAuthority,
};

pub const MANAGED_SYSTEMD_UNIT_PREFIX: &str = "linura-managed-";
pub const MANAGED_SYSTEMD_OPERATION: &str = "set-active-state";
pub const MANAGED_SYSTEMD_PROVIDER: &str = "systemd";
pub const MANAGED_SYSTEMD_CAPABILITY: &str = "systemd.unit.observe";
pub const MANAGED_SYSTEMD_INTENT_ORIGIN: &str = "intent:v06:managed-systemd-active-state";
const MANAGED_APPROVAL_TTL_SECONDS: u64 = 300;
const MANAGED_REQUEST_PREFIX: &str = "request:v06:";
const MAX_OPERATION_ID_BYTES: usize = 64;
const MAX_CANONICAL_DIGEST_FIELD_BYTES: usize = 256 * 1024;
const MAX_POST_DISPATCH_VERIFY_ATTEMPTS: usize = 64;
const MAX_POST_DISPATCH_VERIFY_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedApprovalBinding {
    plan_id: String,
    request_digest: String,
    observation_digest: String,
    review_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedApprovalChallenge {
    principal: PrincipalId,
    request_id: RequestId,
    plan_id: PlanId,
    request_digest: String,
    observation_digest: String,
    review_digest: String,
    resource: ResourceId,
    desired_active_state: String,
    reason: String,
}

impl ManagedApprovalChallenge {
    fn from_candidate(
        candidate: &DurableAuthorityCandidate,
        request: &PlanDesiredStateRequest,
    ) -> Result<Self, ManagedLifecycleError> {
        let principal = PrincipalId::new(candidate.principal().as_str().to_owned())
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
        if candidate.plan_id().as_str() != request.request_id.as_str() {
            return Err(ManagedLifecycleError::Contract(
                "canonical planner changed the request-derived plan identity".into(),
            ));
        }
        let desired_active_state = request
            .desired_state
            .get("active_state")
            .cloned()
            .ok_or_else(|| ManagedLifecycleError::Contract("active_state is missing".into()))?;
        Ok(Self {
            principal,
            request_id: request.request_id.clone(),
            plan_id: candidate.plan_id().clone(),
            request_digest: digest_managed_request(request)?,
            observation_digest: candidate.observation_digest().as_str().to_owned(),
            review_digest: candidate.review_digest().as_str().to_owned(),
            resource: request.resource.clone(),
            desired_active_state,
            reason: request.reason.summary.clone(),
        })
    }

    fn recovery(
        principal: PrincipalId,
        request: &PlanDesiredStateRequest,
        plan_id: &str,
    ) -> Result<Self, ManagedLifecycleError> {
        let plan_id = PlanId::new(plan_id.to_owned())
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
        if plan_id.as_str() != request.request_id.as_str() {
            return Err(ManagedLifecycleError::Contract(
                "durable recovery plan identity differs from the stable request identity".into(),
            ));
        }
        let desired_active_state = request
            .desired_state
            .get("active_state")
            .cloned()
            .ok_or_else(|| ManagedLifecycleError::Contract("active_state is missing".into()))?;
        Ok(Self {
            principal,
            request_id: request.request_id.clone(),
            plan_id,
            request_digest: digest_managed_request(request)?,
            observation_digest: "recovery:fresh-control-revalidation-required".into(),
            review_digest: "recovery:fresh-policy-revalidation-required".into(),
            resource: request.resource.clone(),
            desired_active_state,
            reason: request.reason.summary.clone(),
        })
    }

    fn binding(&self) -> ManagedApprovalBinding {
        ManagedApprovalBinding {
            plan_id: self.plan_id.as_str().to_owned(),
            request_digest: self.request_digest.clone(),
            observation_digest: self.observation_digest.clone(),
            review_digest: self.review_digest.clone(),
        }
    }

    #[must_use]
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    #[must_use]
    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }

    #[must_use]
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    #[must_use]
    pub fn observation_digest(&self) -> &str {
        &self.observation_digest
    }

    #[must_use]
    pub fn review_digest(&self) -> &str {
        &self.review_digest
    }

    #[must_use]
    pub fn resource(&self) -> &ResourceId {
        &self.resource
    }

    #[must_use]
    pub fn desired_active_state(&self) -> &str {
        &self.desired_active_state
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedHumanApproval {
    principal: PrincipalId,
    binding: Option<ManagedApprovalBinding>,
}

impl TrustedHumanApproval {
    /// Construct a trusted local test/embedding authorizer. Production D-Bus
    /// calls use the candidate-bound Polkit authorizer and never mint this token
    /// before Control has produced a canonical approval challenge.
    #[must_use]
    pub fn from_privileged_local_boundary(principal: PrincipalId) -> Self {
        Self {
            principal,
            binding: None,
        }
    }

    #[must_use]
    pub fn from_authorized_challenge(
        principal: PrincipalId,
        challenge: &ManagedApprovalChallenge,
    ) -> Self {
        Self {
            principal,
            binding: Some(challenge.binding()),
        }
    }

    #[must_use]
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    fn matches_challenge(&self, challenge: &ManagedApprovalChallenge) -> bool {
        self.principal == *challenge.principal()
            && self.binding.as_ref() == Some(&challenge.binding())
    }
}

pub trait ManagedApprovalAuthorizer: Debug + Send {
    fn authorize(
        &self,
        challenge: &ManagedApprovalChallenge,
    ) -> Result<TrustedHumanApproval, String>;
}

impl ManagedApprovalAuthorizer for TrustedHumanApproval {
    fn authorize(
        &self,
        challenge: &ManagedApprovalChallenge,
    ) -> Result<TrustedHumanApproval, String> {
        if self.principal != *challenge.principal() {
            return Err(
                "trusted local approval principal does not match candidate principal".into(),
            );
        }
        Ok(TrustedHumanApproval::from_authorized_challenge(
            self.principal.clone(),
            challenge,
        ))
    }
}

#[derive(Debug)]
pub struct AuthorizedEffect {
    effect: EffectDescriptor,
    binding: ExecutionBinding,
    permit: DispatchPermit,
}

impl AuthorizedEffect {
    #[must_use]
    pub fn effect(&self) -> &EffectDescriptor {
        &self.effect
    }

    #[must_use]
    pub fn binding(&self) -> &ExecutionBinding {
        &self.binding
    }

    #[must_use]
    pub fn into_executor_request(self) -> (EffectDescriptor, ExecutionBinding) {
        let Self {
            effect,
            binding,
            permit: _permit,
        } = self;
        (effect, binding)
    }
}

pub trait AuthorizedEffectExecutor: Debug + Send {
    fn execute_authorized(
        &mut self,
        authorization: AuthorizedEffect,
    ) -> Result<ExecutionOutcome, String>;
}

pub trait IndependentManagedVerifier: Debug + Send {
    fn verify_effect(&mut self, effect: &EffectDescriptor) -> Result<VerificationOutcome, String>;

    /// Control owns bounded post-dispatch settling. Implementations may request
    /// more than one fresh independent observation for asynchronous native APIs;
    /// Control clamps both values to prevent an adapter from creating an
    /// unbounded authority stall.
    fn post_dispatch_settle_attempts(&self) -> usize {
        1
    }

    fn post_dispatch_settle_interval(&self) -> Duration {
        Duration::ZERO
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedMutationReceipt {
    pub transaction_id: String,
    pub plan_id: String,
    pub resource: String,
    pub desired_active_state: String,
    pub effect_digest: String,
    pub dispatch_digest: Option<String>,
    pub execution_disposition: Option<String>,
    pub verification_disposition: String,
    pub final_state: String,
    pub recovered: bool,
    pub stages: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagedLifecycleError {
    UnsupportedEffect(String),
    InvalidRequestIdentity(String),
    ApprovalBoundary(String),
    Authority(String),
    Executor(String),
    ExecutionRejected(String),
    Verification(String),
    VerificationNotSatisfied(String),
    Indeterminate(String),
    TerminalState(String),
    Reconciliation(String),
    Contract(String),
}

impl Display for ManagedLifecycleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedEffect(detail) => {
                write!(formatter, "unsupported v0.6 effect: {detail}")
            }
            Self::InvalidRequestIdentity(detail) => {
                write!(formatter, "invalid v0.6 request identity: {detail}")
            }
            Self::ApprovalBoundary(detail) => {
                write!(formatter, "trusted approval boundary failed: {detail}")
            }
            Self::Authority(detail) => write!(formatter, "durable authority failed: {detail}"),
            Self::Executor(detail) => write!(formatter, "privileged executor failed: {detail}"),
            Self::ExecutionRejected(detail) => {
                write!(formatter, "effect was rejected before dispatch: {detail}")
            }
            Self::Verification(detail) => {
                write!(formatter, "independent verification failed: {detail}")
            }
            Self::VerificationNotSatisfied(detail) => write!(
                formatter,
                "independent verification did not prove intended state: {detail}"
            ),
            Self::Indeterminate(detail) => write!(
                formatter,
                "managed mutation remains indeterminate: {detail}"
            ),
            Self::TerminalState(detail) => write!(
                formatter,
                "durable transaction is terminal and cannot be replayed: {detail}"
            ),
            Self::Reconciliation(detail) => {
                write!(formatter, "post-commit reconciliation failed: {detail}")
            }
            Self::Contract(detail) => {
                write!(formatter, "managed lifecycle contract failed: {detail}")
            }
        }
    }
}

impl std::error::Error for ManagedLifecycleError {}

impl From<DurableAuthorityError> for ManagedLifecycleError {
    fn from(error: DurableAuthorityError) -> Self {
        Self::Authority(error.to_string())
    }
}

pub fn managed_request_id(
    operation_id: &str,
    _request: &PlanDesiredStateRequest,
) -> Result<RequestId, ManagedLifecycleError> {
    validate_operation_id(operation_id)?;
    RequestId::new(format!("{MANAGED_REQUEST_PREFIX}{operation_id}"))
        .map_err(|error| ManagedLifecycleError::InvalidRequestIdentity(error.to_string()))
}

#[derive(Debug)]
pub struct ManagedLifecycleControl<S>
where
    S: TransactionStore,
{
    previews: PlanPreviewControl,
    authority: DurableAuthorityControl<S>,
}

impl<S> ManagedLifecycleControl<S>
where
    S: TransactionStore,
{
    pub fn new(
        previews: PlanPreviewControl,
        store: S,
        authority_signer: linura_transaction::TransactionAuthoritySigner,
    ) -> Result<Self, ManagedLifecycleError> {
        Ok(Self {
            previews,
            authority: DurableAuthorityControl::new(store, authority_signer)?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn converge_systemd_active_state<E, V>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
        executor: &mut E,
        verifier: &mut V,
    ) -> Result<ManagedMutationReceipt, ManagedLifecycleError>
    where
        E: AuthorizedEffectExecutor,
        V: IndependentManagedVerifier,
    {
        validate_public_request(&request)?;
        validate_request_identity(&request)?;
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "v0.6 managed mutation requires an authenticated interactive human actor".into(),
            ));
        }

        let principal_id = PrincipalId::new(principal.as_str().to_owned())
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
        let transaction_id = TransactionId::for_namespace(&principal_id, &request.request_id);
        let effect = effect_from_request(&request)?;

        match self.authority.snapshot(&transaction_id) {
            Ok(_) => {
                return self.resume_existing(
                    principal,
                    actor,
                    request,
                    approval_authorizer,
                    effect,
                    transaction_id,
                    executor,
                    verifier,
                );
            }
            Err(DurableAuthorityError::Transaction(detail))
                if detail == "durable transaction not found" => {}
            Err(error) => return Err(error.into()),
        }

        let candidate = match self.authority.candidate(
            &mut self.previews,
            principal.clone(),
            actor.clone(),
            request.clone(),
        ) {
            Ok(candidate) => candidate,
            Err(DurableAuthorityError::CandidateNotMutation) => {
                return Err(ManagedLifecycleError::UnsupportedEffect(
                    "requested state already holds; no external effect is necessary".into(),
                ));
            }
            Err(error) => return Err(error.into()),
        };
        let canonical_effect = effect_from_candidate(&candidate)?;
        if canonical_effect != effect {
            return Err(ManagedLifecycleError::Contract(
                "trusted plan effect differs from the exact public request effect".into(),
            ));
        }
        if candidate.plan_id().as_str() != request.request_id.as_str() {
            return Err(ManagedLifecycleError::Contract(
                "canonical planner changed the request-derived plan identity".into(),
            ));
        }

        let human_approver = self.authorize_candidate(&candidate, &request, approval_authorizer)?;
        let (candidate, approval_evidence_id) = if let Some(approver) = human_approver {
            let refreshed = self.refresh_candidate_after_approval(
                &candidate,
                principal.clone(),
                actor.clone(),
                request.clone(),
                &effect,
            )?;
            let approval_request =
                ApprovalRequestId::new(format!("approval:v06:{}", refreshed.plan_id().as_str()))
                    .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
            let expires_at = now_unix_seconds()?
                .checked_add(MANAGED_APPROVAL_TTL_SECONDS)
                .ok_or_else(|| ManagedLifecycleError::Contract("approval clock overflow".into()))?;
            let evidence = self.authority.issue_approval(
                approval_request,
                &refreshed,
                &approver,
                expires_at,
            )?;
            (refreshed, Some(evidence.id().clone()))
        } else {
            (candidate, None)
        };
        let mut prepared = self.authority.prepare(candidate, approval_evidence_id)?;

        let mut progress = MutationProgress::new();
        advance(&mut progress, MutationStage::Observe)?;
        advance(&mut progress, MutationStage::Plan)?;
        advance(&mut progress, MutationStage::Validate)?;
        advance(&mut progress, MutationStage::Authorize)?;
        advance(&mut progress, MutationStage::Prepare)?;

        let plan_id = prepared.binding().plan_id().as_str().to_owned();
        let permit = self.authority.handoff(&principal, &mut prepared)?;
        let authorization = authorized_effect(effect.clone(), permit)?;
        let dispatch_digest = authorization.binding().dispatch_digest.to_hex();
        let execution = executor
            .execute_authorized(authorization)
            .map_err(ManagedLifecycleError::Executor)?;
        if execution.dispatch_digest.to_hex() != dispatch_digest {
            return Err(ManagedLifecycleError::Contract(
                "executor returned a dispatch digest different from the authorized handoff".into(),
            ));
        }
        match execution.disposition {
            ExecutionDisposition::RejectedBeforeDispatch => {
                return Err(ManagedLifecycleError::ExecutionRejected(execution.detail));
            }
            ExecutionDisposition::Dispatched | ExecutionDisposition::Indeterminate => {
                advance(&mut progress, MutationStage::Execute)?;
            }
        }

        let verification = verify_after_dispatch(verifier, &effect)?;
        match verification.disposition {
            VerificationDisposition::Satisfied => advance(&mut progress, MutationStage::Verify)?,
            VerificationDisposition::NotSatisfied => {
                return Err(ManagedLifecycleError::VerificationNotSatisfied(
                    verification.detail,
                ));
            }
            VerificationDisposition::Inconclusive => {
                return Err(ManagedLifecycleError::Indeterminate(verification.detail));
            }
        }

        let verified = match self.authority.recover_indeterminate(
            &mut self.previews,
            principal.clone(),
            actor.clone(),
            request.clone(),
            None,
        )? {
            DurableRecoveryOutcome::Verified(verified) => verified,
            DurableRecoveryOutcome::Reprepared(_) => {
                return Err(ManagedLifecycleError::Indeterminate(
                    "state changed after independent verification; authority was reprepared and requires a new explicit invocation"
                        .into(),
                ));
            }
            DurableRecoveryOutcome::Blocked(snapshot) => {
                return Err(ManagedLifecycleError::TerminalState(format!(
                    "recovery blocked transaction {}",
                    snapshot.transaction_id.as_str()
                )));
            }
            DurableRecoveryOutcome::StillIndeterminate(snapshot) => {
                return Err(ManagedLifecycleError::Indeterminate(format!(
                    "transaction {} remains indeterminate after verification",
                    snapshot.transaction_id.as_str()
                )));
            }
        };
        let committed = self.authority.commit_verified(&principal, verified)?;
        advance(&mut progress, MutationStage::Commit)?;
        self.authority.integrity_check()?;
        advance(&mut progress, MutationStage::Audit)?;
        self.reconcile(&principal, &actor, &request, &effect, verifier)?;
        advance(&mut progress, MutationStage::Reconcile)?;

        Ok(receipt(ReceiptContext {
            transaction_id: &transaction_id,
            plan_id: &plan_id,
            effect: &effect,
            execution: Some(&execution),
            verification: &verification,
            final_state: &committed.state,
            recovered: false,
            progress: &progress,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn resume_existing<E, V>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
        effect: EffectDescriptor,
        transaction_id: TransactionId,
        executor: &mut E,
        verifier: &mut V,
    ) -> Result<ManagedMutationReceipt, ManagedLifecycleError>
    where
        E: AuthorizedEffectExecutor,
        V: IndependentManagedVerifier,
    {
        self.authority
            .assert_request_matches(&principal, &request)?;
        let snapshot = self.authority.snapshot(&transaction_id)?;
        let plan_id = request.request_id.as_str().to_owned();
        match snapshot.state {
            TransactionState::Prepared => Err(ManagedLifecycleError::Indeterminate(format!(
                "{} is still prepared after a failed pre-dispatch authority use; restart the trusted control composition root so restart recovery can retire it before retry",
                transaction_id.as_str()
            ))),
            TransactionState::Indeterminate => self.finish_indeterminate(
                principal,
                actor,
                request,
                approval_authorizer,
                effect,
                transaction_id,
                plan_id,
                executor,
                verifier,
            ),
            TransactionState::Verified => {
                let verification = verifier
                    .verify_effect(&effect)
                    .map_err(ManagedLifecycleError::Verification)?;
                if verification.disposition != VerificationDisposition::Satisfied {
                    return Err(ManagedLifecycleError::Indeterminate(format!(
                        "verified durable state is not independently re-proven: {}",
                        verification.detail
                    )));
                }
                let verified = self
                    .authority
                    .resume_verified(&principal, &transaction_id)?;
                let committed = self.authority.commit_verified(&principal, verified)?;
                let mut progress = progress_through(MutationStage::Commit)?;
                self.authority.integrity_check()?;
                advance(&mut progress, MutationStage::Audit)?;
                self.reconcile(&principal, &actor, &request, &effect, verifier)?;
                advance(&mut progress, MutationStage::Reconcile)?;
                Ok(receipt(ReceiptContext {
                    transaction_id: &transaction_id,
                    plan_id: &plan_id,
                    effect: &effect,
                    execution: None,
                    verification: &verification,
                    final_state: &committed.state,
                    recovered: true,
                    progress: &progress,
                }))
            }
            TransactionState::Committed => {
                let verification = verifier
                    .verify_effect(&effect)
                    .map_err(ManagedLifecycleError::Verification)?;
                if verification.disposition != VerificationDisposition::Satisfied {
                    return Err(ManagedLifecycleError::Reconciliation(format!(
                        "committed state no longer satisfies its managed postcondition: {}. Use a new operation id to authorize a new convergence.",
                        verification.detail
                    )));
                }
                let mut progress = progress_through(MutationStage::Commit)?;
                self.authority.integrity_check()?;
                advance(&mut progress, MutationStage::Audit)?;
                self.reconcile(&principal, &actor, &request, &effect, verifier)?;
                advance(&mut progress, MutationStage::Reconcile)?;
                Ok(receipt(ReceiptContext {
                    transaction_id: &transaction_id,
                    plan_id: &plan_id,
                    effect: &effect,
                    execution: None,
                    verification: &verification,
                    final_state: &snapshot.state,
                    recovered: true,
                    progress: &progress,
                }))
            }
            TransactionState::Aborted | TransactionState::RecoveryBlocked => {
                Err(ManagedLifecycleError::TerminalState(format!(
                    "{} is {}; use a new operation id after reviewing durable evidence",
                    transaction_id.as_str(),
                    snapshot.state.as_str()
                )))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_indeterminate<E, V>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
        effect: EffectDescriptor,
        transaction_id: TransactionId,
        plan_id: String,
        executor: &mut E,
        verifier: &mut V,
    ) -> Result<ManagedMutationReceipt, ManagedLifecycleError>
    where
        E: AuthorizedEffectExecutor,
        V: IndependentManagedVerifier,
    {
        let verification = verifier
            .verify_effect(&effect)
            .map_err(ManagedLifecycleError::Verification)?;

        if verification.disposition == VerificationDisposition::Inconclusive {
            return Err(ManagedLifecycleError::Indeterminate(verification.detail));
        }

        let recovery = if verification.disposition == VerificationDisposition::NotSatisfied {
            let principal_id = PrincipalId::new(principal.as_str().to_owned())
                .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
            let challenge = ManagedApprovalChallenge::recovery(principal_id, &request, &plan_id)?;
            let approval = approval_authorizer
                .authorize(&challenge)
                .map_err(ManagedLifecycleError::ApprovalBoundary)?;
            if !approval.matches_challenge(&challenge) {
                return Err(ManagedLifecycleError::ApprovalBoundary(
                    "recovery administrator approval is not bound to the exact durable request"
                        .into(),
                ));
            }
            let approver = PolicyAuthenticatedApprover::new(
                approval.principal().clone(),
                ActorKind::Human,
                BTreeSet::from([ApprovalClass::Administrator]),
            );
            let approval_request = ApprovalRequestId::new(format!(
                "approval:v06:recovery:{}",
                request.request_id.as_str()
            ))
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
            let expires_at = now_unix_seconds()?
                .checked_add(MANAGED_APPROVAL_TTL_SECONDS)
                .ok_or_else(|| ManagedLifecycleError::Contract("approval clock overflow".into()))?;
            self.authority.recover_indeterminate_with_approver(
                &mut self.previews,
                principal.clone(),
                actor.clone(),
                request.clone(),
                FreshRecoveryApproval::new(approval_request, approver, expires_at),
            )?
        } else {
            self.authority.recover_indeterminate(
                &mut self.previews,
                principal.clone(),
                actor.clone(),
                request.clone(),
                None,
            )?
        };

        match recovery {
            DurableRecoveryOutcome::Verified(verified) => {
                if verification.disposition != VerificationDisposition::Satisfied {
                    return Err(ManagedLifecycleError::Indeterminate(
                        "fresh Control observation reached intended state after the independent verifier did not; durable state is verified but commit is withheld until a later independent re-verification"
                            .into(),
                    ));
                }
                let committed = self.authority.commit_verified(&principal, verified)?;
                let mut progress = progress_through(MutationStage::Commit)?;
                self.authority.integrity_check()?;
                advance(&mut progress, MutationStage::Audit)?;
                self.reconcile(&principal, &actor, &request, &effect, verifier)?;
                advance(&mut progress, MutationStage::Reconcile)?;
                Ok(receipt(ReceiptContext {
                    transaction_id: &transaction_id,
                    plan_id: &plan_id,
                    effect: &effect,
                    execution: None,
                    verification: &verification,
                    final_state: &committed.state,
                    recovered: true,
                    progress: &progress,
                }))
            }
            DurableRecoveryOutcome::Reprepared(prepared) => self.execute_reprepared(
                principal,
                actor,
                request,
                effect,
                transaction_id,
                prepared,
                executor,
                verifier,
            ),
            DurableRecoveryOutcome::Blocked(snapshot) => {
                Err(ManagedLifecycleError::TerminalState(format!(
                    "recovery found conflicting state and blocked {}",
                    snapshot.transaction_id.as_str()
                )))
            }
            DurableRecoveryOutcome::StillIndeterminate(snapshot) => {
                Err(ManagedLifecycleError::Indeterminate(format!(
                    "{} remains indeterminate; no replay was attempted",
                    snapshot.transaction_id.as_str()
                )))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_reprepared<E, V>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        effect: EffectDescriptor,
        transaction_id: TransactionId,
        mut prepared: Box<PreparedDurableAuthority>,
        executor: &mut E,
        verifier: &mut V,
    ) -> Result<ManagedMutationReceipt, ManagedLifecycleError>
    where
        E: AuthorizedEffectExecutor,
        V: IndependentManagedVerifier,
    {
        let plan_id = prepared.binding().plan_id().as_str().to_owned();
        if plan_id != request.request_id.as_str() {
            return Err(ManagedLifecycleError::Contract(
                "reprepared authority changed the stable request-derived plan identity".into(),
            ));
        }

        let mut progress = progress_through(MutationStage::Prepare)?;
        let permit = self.authority.handoff(&principal, prepared.as_mut())?;
        let authorization = authorized_effect(effect.clone(), permit)?;
        let dispatch_digest = authorization.binding().dispatch_digest.to_hex();
        let execution = executor
            .execute_authorized(authorization)
            .map_err(ManagedLifecycleError::Executor)?;
        if execution.dispatch_digest.to_hex() != dispatch_digest {
            return Err(ManagedLifecycleError::Contract(
                "executor returned a dispatch digest different from the reprepared authorized handoff"
                    .into(),
            ));
        }
        match execution.disposition {
            ExecutionDisposition::RejectedBeforeDispatch => {
                return Err(ManagedLifecycleError::ExecutionRejected(execution.detail));
            }
            ExecutionDisposition::Dispatched | ExecutionDisposition::Indeterminate => {
                advance(&mut progress, MutationStage::Execute)?;
            }
        }

        let verification = verify_after_dispatch(verifier, &effect)?;
        match verification.disposition {
            VerificationDisposition::Satisfied => advance(&mut progress, MutationStage::Verify)?,
            VerificationDisposition::NotSatisfied => {
                return Err(ManagedLifecycleError::VerificationNotSatisfied(
                    verification.detail,
                ));
            }
            VerificationDisposition::Inconclusive => {
                return Err(ManagedLifecycleError::Indeterminate(verification.detail));
            }
        }

        let verified = match self.authority.recover_indeterminate(
            &mut self.previews,
            principal.clone(),
            actor.clone(),
            request.clone(),
            None,
        )? {
            DurableRecoveryOutcome::Verified(verified) => verified,
            DurableRecoveryOutcome::Reprepared(_) => {
                return Err(ManagedLifecycleError::Indeterminate(
                    "fresh Control evidence changed again after the recovery dispatch; no further dispatch was attempted"
                        .into(),
                ));
            }
            DurableRecoveryOutcome::Blocked(snapshot) => {
                return Err(ManagedLifecycleError::TerminalState(format!(
                    "recovery dispatch was blocked for transaction {}",
                    snapshot.transaction_id.as_str()
                )));
            }
            DurableRecoveryOutcome::StillIndeterminate(snapshot) => {
                return Err(ManagedLifecycleError::Indeterminate(format!(
                    "transaction {} remains indeterminate after recovery dispatch",
                    snapshot.transaction_id.as_str()
                )));
            }
        };

        let committed = self.authority.commit_verified(&principal, verified)?;
        advance(&mut progress, MutationStage::Commit)?;
        self.authority.integrity_check()?;
        advance(&mut progress, MutationStage::Audit)?;
        self.reconcile(&principal, &actor, &request, &effect, verifier)?;
        advance(&mut progress, MutationStage::Reconcile)?;

        Ok(receipt(ReceiptContext {
            transaction_id: &transaction_id,
            plan_id: &plan_id,
            effect: &effect,
            execution: Some(&execution),
            verification: &verification,
            final_state: &committed.state,
            recovered: true,
            progress: &progress,
        }))
    }

    fn authorize_candidate(
        &mut self,
        candidate: &DurableAuthorityCandidate,
        request: &PlanDesiredStateRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
    ) -> Result<Option<PolicyAuthenticatedApprover>, ManagedLifecycleError> {
        match candidate.review().decision() {
            PolicyDecision::Allow => Ok(None),
            PolicyDecision::RequireApproval { class, .. } => {
                if *class != ApprovalClass::Administrator {
                    return Err(ManagedLifecycleError::ApprovalBoundary(format!(
                        "v0.6 narrow effect requires unsupported approval class {class:?}"
                    )));
                }
                let challenge = ManagedApprovalChallenge::from_candidate(candidate, request)?;
                let approval = approval_authorizer
                    .authorize(&challenge)
                    .map_err(ManagedLifecycleError::ApprovalBoundary)?;
                if !approval.matches_challenge(&challenge) {
                    return Err(ManagedLifecycleError::ApprovalBoundary(
                        "administrator approval is not bound to the exact reviewed candidate"
                            .into(),
                    ));
                }
                Ok(Some(PolicyAuthenticatedApprover::new(
                    approval.principal().clone(),
                    ActorKind::Human,
                    BTreeSet::from([*class]),
                )))
            }
            PolicyDecision::Deny { reason } | PolicyDecision::Blocked { reason } => {
                Err(ManagedLifecycleError::ApprovalBoundary(reason.clone()))
            }
        }
    }

    fn refresh_candidate_after_approval(
        &mut self,
        approved: &DurableAuthorityCandidate,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        effect: &EffectDescriptor,
    ) -> Result<DurableAuthorityCandidate, ManagedLifecycleError> {
        let approved_challenge = ManagedApprovalChallenge::from_candidate(approved, &request)?;
        let refreshed =
            match self
                .authority
                .candidate(&mut self.previews, principal, actor, request.clone())
            {
                Ok(candidate) => candidate,
                Err(DurableAuthorityError::CandidateNotMutation) => {
                    return Err(ManagedLifecycleError::ApprovalBoundary(
                        "approved mutation is no longer required after administrator interaction"
                            .into(),
                    ));
                }
                Err(error) => return Err(error.into()),
            };
        let refreshed_challenge = ManagedApprovalChallenge::from_candidate(&refreshed, &request)?;
        let semantics_unchanged = approved_challenge.principal == refreshed_challenge.principal
            && approved_challenge.request_id == refreshed_challenge.request_id
            && approved_challenge.plan_id == refreshed_challenge.plan_id
            && approved_challenge.request_digest == refreshed_challenge.request_digest
            && approved_challenge.resource == refreshed_challenge.resource
            && approved_challenge.desired_active_state == refreshed_challenge.desired_active_state
            && approved_challenge.reason == refreshed_challenge.reason
            && review_semantics_unchanged(approved.review(), refreshed.review())
            && effect_from_candidate(&refreshed)? == *effect;
        if !semantics_unchanged {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "authority semantics changed during administrator interaction; a fresh explicit approval is required"
                    .into(),
            ));
        }
        Ok(refreshed)
    }

    fn reconcile<V>(
        &mut self,
        principal: &AuthenticatedPrincipal,
        actor: &Actor,
        request: &PlanDesiredStateRequest,
        effect: &EffectDescriptor,
        verifier: &mut V,
    ) -> Result<(), ManagedLifecycleError>
    where
        V: IndependentManagedVerifier,
    {
        let verification = verifier
            .verify_effect(effect)
            .map_err(ManagedLifecycleError::Verification)?;
        if verification.disposition != VerificationDisposition::Satisfied {
            return Err(ManagedLifecycleError::Reconciliation(verification.detail));
        }
        let (plan, observation) = self
            .previews
            .authority_candidate(principal.clone(), actor.clone(), request.clone())
            .map_err(|error| ManagedLifecycleError::Reconciliation(error.to_string()))?;
        observation
            .validate(&plan.provider, &plan.resource, &plan.observation_capability)
            .map_err(|error| ManagedLifecycleError::Reconciliation(error.to_string()))?;
        if plan.status != linura_planner::PlanStatus::NoChange || !plan.changes.is_empty() {
            return Err(ManagedLifecycleError::Reconciliation(
                "fresh authoritative planning does not converge to no-change".into(),
            ));
        }
        Ok(())
    }
}

/// Compare the approval-relevant semantics of two trusted policy reviews while
/// deliberately excluding only the ephemeral observation-evidence identifier.
/// The exact fresh observation remains independently bound into durable authority
/// through its observation digest; human approval is transferable across the
/// interaction boundary only when the reviewed mutation itself is unchanged.
fn review_semantics_unchanged(left: &TrustedPolicyReview, right: &TrustedPolicyReview) -> bool {
    let left_subject = left.subject();
    let right_subject = right.subject();
    let left_binding = left.binding();
    let right_binding = right.binding();

    left_subject.principal() == right_subject.principal()
        && left_subject.plan_id() == right_subject.plan_id()
        && left_subject.request_id() == right_subject.request_id()
        && left_subject.actor() == right_subject.actor()
        && left_subject.provider() == right_subject.provider()
        && left_subject.resource() == right_subject.resource()
        && left_subject.capability() == right_subject.capability()
        && left_subject.reason() == right_subject.reason()
        && left_subject.prospective_risk() == right_subject.prospective_risk()
        && left_subject.status() == right_subject.status()
        && left_subject.changes() == right_subject.changes()
        && review_findings_unchanged(left_subject, right_subject)
        && left_binding.principal == right_binding.principal
        && left_binding.plan_id == right_binding.plan_id
        && left_binding.request_id == right_binding.request_id
        && left_binding.provider == right_binding.provider
        && left_binding.resource == right_binding.resource
        && left_binding.capability == right_binding.capability
        && left_binding.policy_id == right_binding.policy_id
        && left_binding.policy_revision_id == right_binding.policy_revision_id
        && left.decision() == right.decision()
}

fn review_findings_unchanged(
    left: &linura_policy::PolicySubject,
    right: &linura_policy::PolicySubject,
) -> bool {
    left.findings().len() == right.findings().len()
        && left
            .findings()
            .iter()
            .zip(right.findings())
            .all(|(left_finding, right_finding)| {
                if left_finding.code != right_finding.code
                    || left_finding.level != right_finding.level
                {
                    return false;
                }
                if left_finding.code == "authoritative-observation" {
                    left_finding
                        .message
                        .replace(left.observed_evidence_id(), "<observation-evidence>")
                        == right_finding
                            .message
                            .replace(right.observed_evidence_id(), "<observation-evidence>")
                } else {
                    left_finding.message == right_finding.message
                }
            })
}

fn verify_after_dispatch<V>(
    verifier: &mut V,
    effect: &EffectDescriptor,
) -> Result<VerificationOutcome, ManagedLifecycleError>
where
    V: IndependentManagedVerifier,
{
    let attempts = verifier
        .post_dispatch_settle_attempts()
        .clamp(1, MAX_POST_DISPATCH_VERIFY_ATTEMPTS);
    let interval = std::cmp::min(
        verifier.post_dispatch_settle_interval(),
        MAX_POST_DISPATCH_VERIFY_INTERVAL,
    );
    let mut fallback: Option<VerificationOutcome> = None;

    for attempt in 0..attempts {
        let outcome = verifier
            .verify_effect(effect)
            .map_err(ManagedLifecycleError::Verification)?;
        match outcome.disposition {
            VerificationDisposition::Satisfied => return Ok(outcome),
            VerificationDisposition::NotSatisfied => fallback = Some(outcome),
            VerificationDisposition::Inconclusive if fallback.is_none() => fallback = Some(outcome),
            VerificationDisposition::Inconclusive => {}
        }
        if attempt + 1 < attempts && !interval.is_zero() {
            thread::sleep(interval);
        }
    }

    fallback.ok_or_else(|| {
        ManagedLifecycleError::Verification(
            "post-dispatch verifier produced no bounded observation".into(),
        )
    })
}

fn validate_public_request(request: &PlanDesiredStateRequest) -> Result<(), ManagedLifecycleError> {
    let _ = effect_from_request(request)?;
    Ok(())
}

fn effect_from_request(
    request: &PlanDesiredStateRequest,
) -> Result<EffectDescriptor, ManagedLifecycleError> {
    if request.provider.as_str() != MANAGED_SYSTEMD_PROVIDER
        || request.observation_capability.as_str() != MANAGED_SYSTEMD_CAPABILITY
    {
        return Err(ManagedLifecycleError::UnsupportedEffect(
            "only the authoritative systemd unit observation route is supported".into(),
        ));
    }
    effect_from_parts(
        request.provider.clone(),
        request.resource.clone(),
        &request.desired_state,
    )
}

fn effect_from_candidate(
    candidate: &DurableAuthorityCandidate,
) -> Result<EffectDescriptor, ManagedLifecycleError> {
    let subject = candidate.review().subject();
    if subject.provider().as_str() != MANAGED_SYSTEMD_PROVIDER
        || subject.capability().as_str() != MANAGED_SYSTEMD_CAPABILITY
        || subject.changes().len() != 1
    {
        return Err(ManagedLifecycleError::UnsupportedEffect(
            "trusted plan is outside the single systemd active-state capability".into(),
        ));
    }
    let change = &subject.changes()[0];
    if change.key != "active_state" {
        return Err(ManagedLifecycleError::UnsupportedEffect(
            "trusted plan contains a mutation other than active_state".into(),
        ));
    }
    let desired = BTreeMap::from([(change.key.clone(), change.desired.clone())]);
    effect_from_parts(
        subject.provider().clone(),
        subject.resource().clone(),
        &desired,
    )
}

fn effect_from_parts(
    provider: ProviderId,
    resource: ResourceId,
    desired_state: &BTreeMap<String, String>,
) -> Result<EffectDescriptor, ManagedLifecycleError> {
    let unit = managed_unit_from_resource(resource.as_str())?.to_owned();
    if desired_state.len() != 1 {
        return Err(ManagedLifecycleError::UnsupportedEffect(
            "v0.6 accepts exactly one desired-state attribute".into(),
        ));
    }
    let desired = desired_state.get("active_state").ok_or_else(|| {
        ManagedLifecycleError::UnsupportedEffect("active_state is required".into())
    })?;
    if !matches!(desired.as_str(), "active" | "inactive") {
        return Err(ManagedLifecycleError::UnsupportedEffect(
            "active_state must be exactly active or inactive".into(),
        ));
    }
    EffectDescriptor::new(
        provider,
        resource,
        MANAGED_SYSTEMD_OPERATION,
        format!("unit={unit}\nactive_state={desired}\n").into_bytes(),
    )
    .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))
}

fn managed_unit_from_resource(resource: &str) -> Result<&str, ManagedLifecycleError> {
    let unit = resource.strip_prefix("systemd:unit:").ok_or_else(|| {
        ManagedLifecycleError::UnsupportedEffect("resource is not a systemd unit".into())
    })?;
    if unit.is_empty() || unit.len() > 255 || !unit.ends_with(".service") || !unit.is_ascii() {
        return Err(ManagedLifecycleError::UnsupportedEffect(
            "unit must be a bounded ASCII .service name".into(),
        ));
    }
    let suffix = unit
        .strip_prefix(MANAGED_SYSTEMD_UNIT_PREFIX)
        .ok_or_else(|| {
            ManagedLifecycleError::UnsupportedEffect(
                "unit is outside the linura-managed- namespace".into(),
            )
        })?;
    let slug = suffix.strip_suffix(".service").ok_or_else(|| {
        ManagedLifecycleError::UnsupportedEffect("managed unit suffix is not canonical".into())
    })?;
    if slug.is_empty()
        || slug.len() > 96
        || !slug.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
        || slug.starts_with('-')
        || slug.ends_with('-')
        || slug.contains("--")
    {
        return Err(ManagedLifecycleError::UnsupportedEffect(
            "managed unit name is not canonical".into(),
        ));
    }
    Ok(unit)
}

fn authorized_effect(
    effect: EffectDescriptor,
    permit: DispatchPermit,
) -> Result<AuthorizedEffect, ManagedLifecycleError> {
    let binding = ExecutionBinding::new(
        permit.transaction_id().as_str(),
        permit.generation(),
        permit.state_version(),
        ComponentDigest::parse_hex(permit.binding_digest().hex())
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?,
        ComponentDigest::parse_hex(permit.authority_use_digest().hex())
            .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?,
        &effect,
    )
    .map_err(|error| ManagedLifecycleError::Contract(error.to_string()))?;
    Ok(AuthorizedEffect {
        effect,
        binding,
        permit,
    })
}

fn validate_operation_id(operation_id: &str) -> Result<(), ManagedLifecycleError> {
    if operation_id.is_empty()
        || operation_id.len() > MAX_OPERATION_ID_BYTES
        || !operation_id.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
        || operation_id.starts_with('-')
        || operation_id.ends_with('-')
        || operation_id.contains("--")
    {
        return Err(ManagedLifecycleError::InvalidRequestIdentity(
            "operation id must be 1..64 lowercase ASCII letters/digits/hyphens in canonical form"
                .into(),
        ));
    }
    Ok(())
}

fn validate_request_identity(
    request: &PlanDesiredStateRequest,
) -> Result<(), ManagedLifecycleError> {
    let operation_id = request
        .request_id
        .as_str()
        .strip_prefix(MANAGED_REQUEST_PREFIX)
        .ok_or_else(|| {
            ManagedLifecycleError::InvalidRequestIdentity(format!(
                "request id must begin with {MANAGED_REQUEST_PREFIX}"
            ))
        })?;
    validate_operation_id(operation_id)
}

fn now_unix_seconds() -> Result<u64, ManagedLifecycleError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ManagedLifecycleError::Contract("system clock is before unix epoch".into()))
}

struct ApprovalCanonicalHasher {
    hasher: Sha256,
}

impl ApprovalCanonicalHasher {
    fn new(domain: &str) -> Result<Self, ManagedLifecycleError> {
        let mut value = Self {
            hasher: Sha256::new(),
        };
        value.field(domain.as_bytes())?;
        Ok(value)
    }

    fn field(&mut self, bytes: &[u8]) -> Result<(), ManagedLifecycleError> {
        if bytes.len() > MAX_CANONICAL_DIGEST_FIELD_BYTES {
            return Err(ManagedLifecycleError::Contract(
                "approval request digest field exceeds canonical byte bound".into(),
            ));
        }
        let len = u64::try_from(bytes.len()).map_err(|_| {
            ManagedLifecycleError::Contract("approval digest length overflow".into())
        })?;
        self.hasher.update(len.to_be_bytes());
        self.hasher.update(bytes);
        Ok(())
    }

    fn text(&mut self, value: &str) -> Result<(), ManagedLifecycleError> {
        self.field(value.as_bytes())
    }

    fn number(&mut self, value: u64) -> Result<(), ManagedLifecycleError> {
        self.field(&value.to_be_bytes())
    }

    fn finish(self) -> String {
        format!("sha256:{:x}", self.hasher.finalize())
    }
}

fn digest_managed_request(
    request: &PlanDesiredStateRequest,
) -> Result<String, ManagedLifecycleError> {
    let mut digest = ApprovalCanonicalHasher::new("linura.control.desired-request.v1")?;
    digest.text(request.request_id.as_str())?;
    digest.text(request.provider.as_str())?;
    digest.text(request.resource.as_str())?;
    digest.text(request.observation_capability.as_str())?;
    digest.text(&request.reason.summary)?;
    digest.number(
        u64::try_from(request.reason.intent_ids.len())
            .map_err(|_| ManagedLifecycleError::Contract("intent count overflow".into()))?,
    )?;
    for id in &request.reason.intent_ids {
        digest.text(id.as_str())?;
    }
    digest.number(
        u64::try_from(request.reason.requirement_ids.len())
            .map_err(|_| ManagedLifecycleError::Contract("requirement count overflow".into()))?,
    )?;
    for id in &request.reason.requirement_ids {
        digest.text(id.as_str())?;
    }
    digest.number(
        u64::try_from(request.reason.capability_ids.len())
            .map_err(|_| ManagedLifecycleError::Contract("capability count overflow".into()))?,
    )?;
    for id in &request.reason.capability_ids {
        digest.text(id.as_str())?;
    }
    digest
        .number(u64::try_from(request.desired_state.len()).map_err(|_| {
            ManagedLifecycleError::Contract("desired-state count overflow".into())
        })?)?;
    for (key, value) in &request.desired_state {
        digest.text(key)?;
        digest.text(value)?;
    }
    Ok(digest.finish())
}

fn advance(
    progress: &mut MutationProgress,
    stage: MutationStage,
) -> Result<(), ManagedLifecycleError> {
    progress.advance(stage).map_err(|error| {
        ManagedLifecycleError::Contract(format!("invalid lifecycle transition: {error:?}"))
    })
}

fn progress_through(last: MutationStage) -> Result<MutationProgress, ManagedLifecycleError> {
    let mut progress = MutationProgress::new();
    for stage in linura_lifecycle::MUTATION_STAGES.iter().copied().skip(1) {
        advance(&mut progress, stage)?;
        if stage == last {
            break;
        }
    }
    Ok(progress)
}

struct ReceiptContext<'a> {
    transaction_id: &'a TransactionId,
    plan_id: &'a str,
    effect: &'a EffectDescriptor,
    execution: Option<&'a ExecutionOutcome>,
    verification: &'a VerificationOutcome,
    final_state: &'a TransactionState,
    recovered: bool,
    progress: &'a MutationProgress,
}

fn receipt(context: ReceiptContext<'_>) -> ManagedMutationReceipt {
    let ReceiptContext {
        transaction_id,
        plan_id,
        effect,
        execution,
        verification,
        final_state,
        recovered,
        progress,
    } = context;
    let desired_active_state = String::from_utf8_lossy(&effect.canonical_payload)
        .lines()
        .find_map(|line| line.strip_prefix("active_state="))
        .unwrap_or("unknown")
        .to_owned();
    ManagedMutationReceipt {
        transaction_id: transaction_id.as_str().to_owned(),
        plan_id: plan_id.to_owned(),
        resource: effect.resource.as_str().to_owned(),
        desired_active_state,
        effect_digest: effect.digest().to_hex(),
        dispatch_digest: execution.map(|value| value.dispatch_digest.to_hex()),
        execution_disposition: execution.map(|value| execution_name(value.disposition).to_owned()),
        verification_disposition: verification_name(verification.disposition).to_owned(),
        final_state: final_state.as_str().to_owned(),
        recovered,
        stages: progress
            .completed()
            .iter()
            .map(|stage| stage.as_str().to_owned())
            .collect(),
    }
}

const fn execution_name(disposition: ExecutionDisposition) -> &'static str {
    match disposition {
        ExecutionDisposition::RejectedBeforeDispatch => "rejected-before-dispatch",
        ExecutionDisposition::Dispatched => "dispatched",
        ExecutionDisposition::Indeterminate => "indeterminate",
    }
}

const fn verification_name(disposition: VerificationDisposition) -> &'static str {
    match disposition {
        VerificationDisposition::Satisfied => "satisfied",
        VerificationDisposition::NotSatisfied => "not-satisfied",
        VerificationDisposition::Inconclusive => "inconclusive",
    }
}

#[cfg(test)]
mod tests {
    use linura_core::{CapabilityId, SemanticReason};

    use super::*;

    fn request(resource: &str, desired: &str) -> PlanDesiredStateRequest {
        let mut request = PlanDesiredStateRequest {
            request_id: RequestId::new("request:v06:placeholder")
                .unwrap_or_else(|error| unreachable!("{error}")),
            provider: ProviderId::new("systemd").unwrap_or_else(|error| unreachable!("{error}")),
            resource: ResourceId::new(resource).unwrap_or_else(|error| unreachable!("{error}")),
            observation_capability: CapabilityId::new("systemd.unit.observe")
                .unwrap_or_else(|error| unreachable!("{error}")),
            reason: SemanticReason {
                summary: "v0.6 test".into(),
                intent_ids: vec![],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
            desired_state: BTreeMap::from([("active_state".into(), desired.into())]),
        };
        request.request_id = managed_request_id("test-operation", &request)
            .unwrap_or_else(|error| unreachable!("{error}"));
        request
    }

    #[test]
    fn public_effect_is_exactly_one_reserved_systemd_active_state() {
        let effect = effect_from_request(&request(
            "systemd:unit:linura-managed-example.service",
            "active",
        ))
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(effect.operation, MANAGED_SYSTEMD_OPERATION);
        assert_eq!(
            effect.canonical_payload,
            b"unit=linura-managed-example.service\nactive_state=active\n"
        );
        assert!(effect_from_request(&request("systemd:unit:sshd.service", "active")).is_err());
        assert!(
            effect_from_request(&request(
                "systemd:unit:linura-managed-example.service",
                "failed",
            ))
            .is_err()
        );
    }

    #[test]
    fn request_id_is_stable_operation_namespace_and_plan_identity() {
        let request = request("systemd:unit:linura-managed-example.service", "active");
        assert!(validate_request_identity(&request).is_ok());
        assert!(PlanId::new(request.request_id.as_str().to_owned()).is_ok());

        let mut substituted = request.clone();
        substituted
            .desired_state
            .insert("active_state".into(), "inactive".into());
        assert_eq!(
            request.request_id,
            managed_request_id("test-operation", &substituted)
                .unwrap_or_else(|error| unreachable!("{error}"))
        );

        let mut other_operation = request.clone();
        other_operation.request_id = managed_request_id("other-operation", &other_operation)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_ne!(request.request_id, other_operation.request_id);
        assert_ne!(
            digest_managed_request(&request).unwrap_or_default(),
            digest_managed_request(&substituted).unwrap_or_default()
        );
    }

    #[test]
    fn lifecycle_progress_helper_never_skips_canonical_order() {
        let progress = progress_through(MutationStage::Reconcile)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(progress.is_complete());
        assert_eq!(
            progress.completed(),
            linura_lifecycle::MUTATION_STAGES.as_slice()
        );
    }
}
