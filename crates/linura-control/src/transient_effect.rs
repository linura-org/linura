use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

#[cfg(test)]
use linura_capability_sdk::OperationRegistry;
use linura_core::{
    Actor, ActorKind, CapabilityId, OperationClass, OperationId, PlanId, PolicyId,
    PolicyRevisionId, ProviderId, RequestId, ResourceId, RiskClass,
};
use linura_observation::{FreshnessState, ObservationEnvelope};
use linura_planner::{PlanStatus, ReconciliationPlan};
use linura_policy::PolicyDecision;
use linura_protocol::{ObservationRequest, PlanDesiredStateRequest};
use sha2::{Digest, Sha256};

use crate::operation_registry::trusted_builtin_operation_registry;
use crate::policy_review::review_plan_with_classification;
use crate::risk_classification::{REGISTERED_TRANSIENT_RISK_POLICY_REVISION, RiskClassification};
use crate::{
    AuthenticatedPrincipal, OperationSemanticsControl, OperationSemanticsError, PlanPreviewControl,
};

const MAX_TRANSIENT_DIAGNOSTIC_BYTES: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedTransientEffect {
    operation_id: OperationId,
    plan_id: PlanId,
    request_id: RequestId,
    risk: RiskClass,
    provider: ProviderId,
    resource: ResourceId,
    desired_state: BTreeMap<String, String>,
    pre_effect_evidence_id: String,
    pre_effect_observation: ObservationEnvelope,
}

impl AuthorizedTransientEffect {
    fn from_authorized_request(
        operation_id: OperationId,
        risk: RiskClass,
        plan: &ReconciliationPlan,
        requested_state: &BTreeMap<String, String>,
        pre_effect_observation: &ObservationEnvelope,
    ) -> Self {
        Self {
            operation_id,
            plan_id: plan.id.clone(),
            request_id: plan.request_id.clone(),
            risk,
            provider: plan.provider.clone(),
            resource: plan.resource.clone(),
            desired_state: requested_state.clone(),
            pre_effect_evidence_id: plan.observed_evidence_id.clone(),
            pre_effect_observation: pre_effect_observation.clone(),
        }
    }

    #[must_use]
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }

    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    #[must_use]
    pub const fn risk(&self) -> RiskClass {
        self.risk
    }

    #[must_use]
    pub fn provider(&self) -> &ProviderId {
        &self.provider
    }

    #[must_use]
    pub fn resource(&self) -> &ResourceId {
        &self.resource
    }

    #[must_use]
    pub fn desired_state(&self) -> &BTreeMap<String, String> {
        &self.desired_state
    }

    #[must_use]
    pub fn pre_effect_evidence_id(&self) -> &str {
        &self.pre_effect_evidence_id
    }

    /// Returns the exact authoritative pre-effect observation that Control
    /// bound into this authorized dispatch. Narrow executors may use this
    /// immutable evidence to revalidate volatile provider identity immediately
    /// before mutation; callers cannot supply or replace it.
    #[must_use]
    pub fn pre_effect_observation(&self) -> &ObservationEnvelope {
        &self.pre_effect_observation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransientEffectExecutorError {
    detail: String,
}

impl TransientEffectExecutorError {
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: bounded_diagnostic(detail.into()),
        }
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl Display for TransientEffectExecutorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for TransientEffectExecutorError {}

pub trait TransientEffectExecutor {
    fn execute(
        &mut self,
        effect: &AuthorizedTransientEffect,
    ) -> Result<(), TransientEffectExecutorError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransientEffectAuditDisposition {
    AttemptReserved,
    NoChange,
    Verified,
    ExecutorFailed,
    PostEffectObservationFailed,
    VerificationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransientEffectAuditFailureCode {
    ExecutorFailed,
    PostEffectObservationFailed,
    PostEffectEvidenceNotFresh,
    PostEffectEvidenceNotAfterDispatch,
    PostEffectEvidenceReused,
    PostconditionMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransientEffectAuditRecord {
    pub principal: String,
    pub operation_id: OperationId,
    pub plan_id: PlanId,
    pub request_id: RequestId,
    pub provider: ProviderId,
    pub resource: ResourceId,
    pub observation_capability: CapabilityId,
    pub risk: RiskClass,
    pub policy_id: PolicyId,
    pub policy_revision_id: PolicyRevisionId,
    pub policy_subject_risk: RiskClass,
    pub risk_classification_revision: String,
    pub risk_rule_ids: Vec<String>,
    pub canonical_plan_sha256: String,
    pub requested_postcondition_sha256: String,
    pub audit_attempt_sha256: String,
    pub pre_effect_evidence_id: String,
    pub post_effect_evidence_id: Option<String>,
    pub disposition: TransientEffectAuditDisposition,
    pub failure_code: Option<TransientEffectAuditFailureCode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransientEffectAuditError {
    detail: String,
}

impl TransientEffectAuditError {
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: bounded_diagnostic(detail.into()),
        }
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl Display for TransientEffectAuditError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for TransientEffectAuditError {}

pub trait TransientEffectAuditSink {
    /// Durably and idempotently reserve an execution attempt keyed by
    /// `record.audit_attempt_sha256`. Control never dispatches the executor
    /// unless this call succeeds.
    fn reserve_attempt(
        &mut self,
        record: &TransientEffectAuditRecord,
    ) -> Result<(), TransientEffectAuditError>;

    /// Durably and idempotently append/finalize a terminal disposition for the
    /// previously reserved attempt. No-change records use this path directly
    /// because no executor dispatch occurs.
    fn record_terminal(
        &mut self,
        record: &TransientEffectAuditRecord,
    ) -> Result<(), TransientEffectAuditError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransientEffectReceiptStatus {
    NoChange,
    Verified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransientEffectReceipt {
    pub operation_id: OperationId,
    pub plan_id: PlanId,
    pub request_id: RequestId,
    pub risk: RiskClass,
    pub pre_effect_evidence_id: String,
    pub post_effect_evidence_id: Option<String>,
    pub status: TransientEffectReceiptStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransientEffectError {
    Planning(String),
    DispatchClockFailed(String),
    Semantics(OperationSemanticsError),
    WrongOperationClass(OperationClass),
    RiskBindingMismatch {
        semantics: RiskClass,
        review: RiskClass,
    },
    PolicyDenied(String),
    PolicyRequiresApproval,
    PolicyBlocked(String),
    ExecutorFailed {
        detail: String,
        post_effect_evidence_id: Option<String>,
    },
    PostEffectObservationFailed(String),
    PostEffectEvidenceNotFresh,
    PostEffectEvidenceNotAfterDispatch {
        observed_at_unix_ms: u64,
        dispatch_started_unix_ms: u64,
    },
    PostEffectEvidenceReused,
    VerificationFailed {
        key: String,
        desired: String,
        observed: Option<String>,
        post_effect_evidence_id: String,
    },
    AuditFailed(String),
    BlockedPlan,
}

impl Display for TransientEffectError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Planning(detail) => write!(formatter, "transient planning failed: {detail}"),
            Self::DispatchClockFailed(detail) => {
                write!(formatter, "transient dispatch clock failed: {detail}")
            }
            Self::Semantics(error) => {
                write!(formatter, "transient operation semantics failed: {error:?}")
            }
            Self::WrongOperationClass(class) => {
                write!(
                    formatter,
                    "operation class {} is not transient",
                    class.as_str()
                )
            }
            Self::RiskBindingMismatch { semantics, review } => write!(
                formatter,
                "transient semantics risk {semantics:?} differs from reviewed risk {review:?}"
            ),
            Self::PolicyDenied(detail) => write!(formatter, "transient policy denied: {detail}"),
            Self::PolicyRequiresApproval => {
                formatter.write_str("transient effect unexpectedly requires approval")
            }
            Self::PolicyBlocked(detail) => write!(formatter, "transient policy blocked: {detail}"),
            Self::ExecutorFailed { detail, .. } => {
                write!(formatter, "transient executor failed: {detail}")
            }
            Self::PostEffectObservationFailed(detail) => {
                write!(
                    formatter,
                    "post-effect authoritative observation failed: {detail}"
                )
            }
            Self::PostEffectEvidenceNotFresh => {
                formatter.write_str("post-effect authoritative observation is not current")
            }
            Self::PostEffectEvidenceNotAfterDispatch {
                observed_at_unix_ms,
                dispatch_started_unix_ms,
            } => write!(
                formatter,
                "post-effect evidence timestamp {observed_at_unix_ms} does not prove production after dispatch start {dispatch_started_unix_ms}"
            ),
            Self::PostEffectEvidenceReused => {
                formatter.write_str("post-effect verification reused pre-effect evidence")
            }
            Self::VerificationFailed {
                key,
                desired,
                observed,
                ..
            } => write!(
                formatter,
                "transient verification failed for {key}: desired {desired:?}, observed {observed:?}"
            ),
            Self::AuditFailed(detail) => write!(formatter, "transient audit failed: {detail}"),
            Self::BlockedPlan => formatter.write_str("transient canonical plan is blocked"),
        }
    }
}

impl std::error::Error for TransientEffectError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransientEffectControlBuildError {
    detail: String,
}

impl Display for TransientEffectControlBuildError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for TransientEffectControlBuildError {}

#[derive(Debug)]
pub struct TransientEffectControl<E, A> {
    previews: PlanPreviewControl,
    semantics: OperationSemanticsControl,
    executor: E,
    audit: A,
}

impl<E, A> TransientEffectControl<E, A>
where
    E: TransientEffectExecutor,
    A: TransientEffectAuditSink,
{
    pub fn new(
        previews: PlanPreviewControl,
        executor: E,
        audit: A,
    ) -> Result<Self, TransientEffectControlBuildError> {
        let registry = trusted_builtin_operation_registry().map_err(|error| {
            TransientEffectControlBuildError {
                detail: format!("cannot construct trusted transient operation registry: {error}"),
            }
        })?;
        Ok(Self {
            previews,
            semantics: OperationSemanticsControl::from_trusted_registry(registry),
            executor,
            audit,
        })
    }

    #[cfg(test)]
    fn from_trusted_registry(
        previews: PlanPreviewControl,
        registry: OperationRegistry,
        executor: E,
        audit: A,
    ) -> Self {
        Self {
            previews,
            semantics: OperationSemanticsControl::from_trusted_registry(registry),
            executor,
            audit,
        }
    }

    pub fn execute(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        operation_id: OperationId,
        request: PlanDesiredStateRequest,
    ) -> Result<TransientEffectReceipt, TransientEffectError> {
        let requested_desired_state = request.desired_state.clone();
        let (plan, pre_effect_observation) = self
            .previews
            .authority_candidate(principal.clone(), actor, request)
            .map_err(|error| TransientEffectError::Planning(error.to_string()))?;

        if plan.status == PlanStatus::Blocked || plan.has_blockers() {
            return Err(TransientEffectError::BlockedPlan);
        }

        let semantics = self
            .semantics
            .resolve_external_with_requested_state(&operation_id, &plan, &requested_desired_state)
            .map_err(TransientEffectError::Semantics)?;

        if semantics.class() != OperationClass::TransientExternalEffect {
            return Err(TransientEffectError::WrongOperationClass(semantics.class()));
        }
        if semantics.permits_privileged_executor()
            || semantics.requires_durable_managed_lifecycle()
            || semantics.risk() > RiskClass::UserState
        {
            return Err(TransientEffectError::WrongOperationClass(semantics.class()));
        }

        // No-change remains an authorization decision, not a policy bypass.
        // PolicySubject deliberately models a no-change plan as ReadOnly; preserve
        // that invariant while still evaluating the authenticated actor before any
        // successful NoChange receipt or audit record is produced.
        let review = review_plan_with_classification(
            &principal,
            &plan,
            semantics.risk_classification().clone(),
        )
        .map_err(|error| TransientEffectError::Planning(format!("{error:?}")))?;

        let reviewed_risk = review.subject().prospective_risk();
        if plan.status != PlanStatus::NoChange && reviewed_risk != semantics.risk() {
            return Err(TransientEffectError::RiskBindingMismatch {
                semantics: semantics.risk(),
                review: reviewed_risk,
            });
        }

        match review.decision() {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny { reason } => {
                return Err(TransientEffectError::PolicyDenied(reason.clone()));
            }
            PolicyDecision::RequireApproval { .. } => {
                return Err(TransientEffectError::PolicyRequiresApproval);
            }
            PolicyDecision::Blocked { reason } => {
                return Err(TransientEffectError::PolicyBlocked(reason.clone()));
            }
        }

        let review_binding = review.binding();
        let audit_context = TransientAuditContext {
            principal: &principal,
            operation_id: &operation_id,
            risk: semantics.risk(),
            policy_id: &review_binding.policy_id,
            policy_revision_id: &review_binding.policy_revision_id,
            policy_subject_risk: reviewed_risk,
            risk_classification: semantics.risk_classification(),
            plan: &plan,
            pre_effect: &pre_effect_observation,
            requested_state: &requested_desired_state,
        };

        if plan.status == PlanStatus::NoChange {
            let record = audit_record(
                &audit_context,
                None,
                TransientEffectAuditDisposition::NoChange,
                None,
            );
            self.audit
                .record_terminal(&record)
                .map_err(|error| TransientEffectError::AuditFailed(error.detail().into()))?;
            return Ok(TransientEffectReceipt {
                operation_id,
                plan_id: plan.id,
                request_id: plan.request_id,
                risk: semantics.risk(),
                pre_effect_evidence_id: pre_effect_observation.evidence_id(),
                post_effect_evidence_id: None,
                status: TransientEffectReceiptStatus::NoChange,
            });
        }

        let effect = AuthorizedTransientEffect::from_authorized_request(
            operation_id.clone(),
            semantics.risk(),
            &plan,
            &requested_desired_state,
            &pre_effect_observation,
        );
        // Establish the verification lower bound before reserving the attempt.
        // No external effect can occur until the mandatory durable audit
        // reservation has been accepted.
        let dispatch_started_unix_ms =
            current_unix_ms().map_err(TransientEffectError::DispatchClockFailed)?;
        let reservation = audit_record(
            &audit_context,
            None,
            TransientEffectAuditDisposition::AttemptReserved,
            None,
        );
        self.audit
            .reserve_attempt(&reservation)
            .map_err(|error| TransientEffectError::AuditFailed(error.detail().into()))?;

        // The provider timestamp has millisecond granularity. Equality with the
        // dispatch lower bound is therefore ordering-ambiguous and must fail closed;
        // only a strictly later authoritative read can verify an attempted effect.
        let execution = self.executor.execute(&effect);

        let observation_request = ObservationRequest {
            provider: plan.provider.clone(),
            resource: plan.resource.clone(),
            capability: plan.observation_capability.clone(),
        };
        let post_effect = match self.previews.observe(&observation_request) {
            Ok(response) => response,
            Err(error) => {
                let record = audit_record(
                    &audit_context,
                    None,
                    TransientEffectAuditDisposition::PostEffectObservationFailed,
                    Some(TransientEffectAuditFailureCode::PostEffectObservationFailed),
                );
                self.audit.record_terminal(&record).map_err(|audit_error| {
                    TransientEffectError::AuditFailed(audit_error.detail().into())
                })?;
                return Err(TransientEffectError::PostEffectObservationFailed(
                    error.to_string(),
                ));
            }
        };

        let post_effect_evidence_id = post_effect.observation.evidence_id();
        if post_effect.freshness != FreshnessState::Current {
            let record = audit_record(
                &audit_context,
                Some(&post_effect.observation),
                TransientEffectAuditDisposition::VerificationFailed,
                Some(TransientEffectAuditFailureCode::PostEffectEvidenceNotFresh),
            );
            self.audit
                .record_terminal(&record)
                .map_err(|error| TransientEffectError::AuditFailed(error.detail().into()))?;
            return Err(TransientEffectError::PostEffectEvidenceNotFresh);
        }
        if post_effect.observation.observed_at_unix_ms <= dispatch_started_unix_ms {
            let observed_at_unix_ms = post_effect.observation.observed_at_unix_ms;
            let record = audit_record(
                &audit_context,
                Some(&post_effect.observation),
                TransientEffectAuditDisposition::VerificationFailed,
                Some(TransientEffectAuditFailureCode::PostEffectEvidenceNotAfterDispatch),
            );
            self.audit
                .record_terminal(&record)
                .map_err(|error| TransientEffectError::AuditFailed(error.detail().into()))?;
            return Err(TransientEffectError::PostEffectEvidenceNotAfterDispatch {
                observed_at_unix_ms,
                dispatch_started_unix_ms,
            });
        }
        if post_effect_evidence_id == pre_effect_observation.evidence_id() {
            let record = audit_record(
                &audit_context,
                Some(&post_effect.observation),
                TransientEffectAuditDisposition::VerificationFailed,
                Some(TransientEffectAuditFailureCode::PostEffectEvidenceReused),
            );
            self.audit
                .record_terminal(&record)
                .map_err(|error| TransientEffectError::AuditFailed(error.detail().into()))?;
            return Err(TransientEffectError::PostEffectEvidenceReused);
        }

        if let Err(error) = execution {
            let record = audit_record(
                &audit_context,
                Some(&post_effect.observation),
                TransientEffectAuditDisposition::ExecutorFailed,
                Some(TransientEffectAuditFailureCode::ExecutorFailed),
            );
            self.audit.record_terminal(&record).map_err(|audit_error| {
                TransientEffectError::AuditFailed(audit_error.detail().into())
            })?;
            return Err(TransientEffectError::ExecutorFailed {
                detail: error.detail().into(),
                post_effect_evidence_id: Some(post_effect_evidence_id),
            });
        }

        for (key, desired) in &requested_desired_state {
            let observed = post_effect
                .observation
                .attributes
                .get(key)
                .map(ToString::to_string);
            if observed.as_deref() != Some(desired.as_str()) {
                let record = audit_record(
                    &audit_context,
                    Some(&post_effect.observation),
                    TransientEffectAuditDisposition::VerificationFailed,
                    Some(TransientEffectAuditFailureCode::PostconditionMismatch),
                );
                self.audit
                    .record_terminal(&record)
                    .map_err(|error| TransientEffectError::AuditFailed(error.detail().into()))?;
                return Err(TransientEffectError::VerificationFailed {
                    key: key.clone(),
                    desired: desired.clone(),
                    observed,
                    post_effect_evidence_id,
                });
            }
        }

        let record = audit_record(
            &audit_context,
            Some(&post_effect.observation),
            TransientEffectAuditDisposition::Verified,
            None,
        );
        self.audit
            .record_terminal(&record)
            .map_err(|error| TransientEffectError::AuditFailed(error.detail().into()))?;

        Ok(TransientEffectReceipt {
            operation_id,
            plan_id: plan.id,
            request_id: plan.request_id,
            risk: semantics.risk(),
            pre_effect_evidence_id: pre_effect_observation.evidence_id(),
            post_effect_evidence_id: Some(post_effect_evidence_id),
            status: TransientEffectReceiptStatus::Verified,
        })
    }
}

struct TransientAuditContext<'a> {
    principal: &'a AuthenticatedPrincipal,
    operation_id: &'a OperationId,
    risk: RiskClass,
    policy_id: &'a PolicyId,
    policy_revision_id: &'a PolicyRevisionId,
    policy_subject_risk: RiskClass,
    risk_classification: &'a RiskClassification,
    plan: &'a ReconciliationPlan,
    pre_effect: &'a ObservationEnvelope,
    requested_state: &'a BTreeMap<String, String>,
}

fn audit_record(
    context: &TransientAuditContext<'_>,
    post_effect: Option<&ObservationEnvelope>,
    disposition: TransientEffectAuditDisposition,
    failure_code: Option<TransientEffectAuditFailureCode>,
) -> TransientEffectAuditRecord {
    let (risk_classification_revision, risk_rule_ids) =
        risk_classification_audit_provenance(context.risk_classification);
    let canonical_plan_sha256 = canonical_plan_sha256(context.plan);
    let requested_postcondition_sha256 = requested_postcondition_sha256(context.requested_state);
    let audit_attempt_sha256 = audit_attempt_sha256(
        context,
        &canonical_plan_sha256,
        &requested_postcondition_sha256,
        risk_classification_revision,
        &risk_rule_ids,
    );
    TransientEffectAuditRecord {
        principal: context.principal.as_str().to_owned(),
        operation_id: context.operation_id.clone(),
        plan_id: context.plan.id.clone(),
        request_id: context.plan.request_id.clone(),
        provider: context.plan.provider.clone(),
        resource: context.plan.resource.clone(),
        observation_capability: context.plan.observation_capability.clone(),
        risk: context.risk,
        policy_id: context.policy_id.clone(),
        policy_revision_id: context.policy_revision_id.clone(),
        policy_subject_risk: context.policy_subject_risk,
        risk_classification_revision: risk_classification_revision.to_owned(),
        risk_rule_ids,
        canonical_plan_sha256,
        requested_postcondition_sha256,
        audit_attempt_sha256,
        pre_effect_evidence_id: context.pre_effect.evidence_id(),
        post_effect_evidence_id: post_effect.map(ObservationEnvelope::evidence_id),
        disposition,
        failure_code,
    }
}

fn risk_classification_audit_provenance(
    classification: &RiskClassification,
) -> (&'static str, Vec<String>) {
    match classification {
        RiskClassification::NotApplicable { .. } => {
            (REGISTERED_TRANSIENT_RISK_POLICY_REVISION, Vec::new())
        }
        RiskClassification::Classified {
            revision, rule_ids, ..
        }
        | RiskClassification::DowngradeRejected {
            revision, rule_ids, ..
        } => (
            *revision,
            rule_ids
                .iter()
                .map(|rule_id| (*rule_id).to_owned())
                .collect(),
        ),
        RiskClassification::Unclassified { revision, .. } => (*revision, Vec::new()),
    }
}

fn audit_attempt_sha256(
    context: &TransientAuditContext<'_>,
    canonical_plan_sha256: &str,
    requested_postcondition_sha256: &str,
    risk_classification_revision: &str,
    risk_rule_ids: &[String],
) -> String {
    let mut hasher = Sha256::new();
    hash_text(&mut hasher, "linura.control.transient.audit-attempt.v1");
    hash_text(&mut hasher, context.principal.as_str());
    hash_text(&mut hasher, context.operation_id.as_str());
    hash_text(&mut hasher, context.plan.id.as_str());
    hash_text(&mut hasher, context.plan.request_id.as_str());
    hash_text(&mut hasher, context.plan.provider.as_str());
    hash_text(&mut hasher, context.plan.resource.as_str());
    hash_text(&mut hasher, context.plan.observation_capability.as_str());
    hash_text(&mut hasher, risk_name(context.risk));
    hash_text(&mut hasher, context.policy_id.as_str());
    hash_text(&mut hasher, context.policy_revision_id.as_str());
    hash_text(&mut hasher, risk_name(context.policy_subject_risk));
    hash_text(&mut hasher, risk_classification_revision);
    hash_text(&mut hasher, &risk_rule_ids.len().to_string());
    for rule_id in risk_rule_ids {
        hash_text(&mut hasher, rule_id);
    }
    hash_text(&mut hasher, canonical_plan_sha256);
    hash_text(&mut hasher, requested_postcondition_sha256);
    hash_text(&mut hasher, &context.pre_effect.evidence_id());
    sha256_hex(&hasher.finalize())
}

fn canonical_plan_sha256(plan: &ReconciliationPlan) -> String {
    let mut hasher = Sha256::new();
    hash_text(&mut hasher, "linura.control.transient.canonical-plan.v1");
    hash_text(&mut hasher, plan.id.as_str());
    hash_text(&mut hasher, plan.request_id.as_str());
    hash_text(&mut hasher, plan.actor.id.as_str());
    hash_text(&mut hasher, actor_kind_name(plan.actor.kind));
    hash_text(
        &mut hasher,
        if plan.actor.interactive {
            "interactive"
        } else {
            "non-interactive"
        },
    );
    hash_text(&mut hasher, plan.provider.as_str());
    hash_text(&mut hasher, plan.resource.as_str());
    hash_text(&mut hasher, plan.observation_capability.as_str());
    hash_text(&mut hasher, &plan.reason.summary);
    hash_text(&mut hasher, &plan.reason.intent_ids.len().to_string());
    for value in &plan.reason.intent_ids {
        hash_text(&mut hasher, value.as_str());
    }
    hash_text(&mut hasher, &plan.reason.requirement_ids.len().to_string());
    for value in &plan.reason.requirement_ids {
        hash_text(&mut hasher, value.as_str());
    }
    hash_text(&mut hasher, &plan.reason.capability_ids.len().to_string());
    for value in &plan.reason.capability_ids {
        hash_text(&mut hasher, value.as_str());
    }
    hash_text(&mut hasher, &plan.observed_evidence_id);
    hash_text(&mut hasher, risk_name(plan.prospective_risk));
    hash_text(&mut hasher, plan.status.as_str());
    hash_text(
        &mut hasher,
        if plan.execution_authorized() {
            "execution-authorized"
        } else {
            "execution-disabled"
        },
    );
    hash_text(&mut hasher, &plan.changes.len().to_string());
    for change in &plan.changes {
        hash_text(&mut hasher, &change.key);
        match &change.current {
            Some(current) => {
                hash_text(&mut hasher, "current:some");
                hash_text(&mut hasher, current);
            }
            None => hash_text(&mut hasher, "current:none"),
        }
        hash_text(&mut hasher, &change.desired);
    }
    hash_text(&mut hasher, &plan.findings.len().to_string());
    for finding in &plan.findings {
        hash_text(&mut hasher, &finding.code);
        hash_text(&mut hasher, finding.level.as_str());
        hash_text(&mut hasher, &finding.message);
    }
    let digest = hasher.finalize();
    sha256_hex(&digest)
}

fn requested_postcondition_sha256(requested_state: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    hash_text(
        &mut hasher,
        "linura.control.transient.requested-postcondition.v1",
    );
    hash_text(&mut hasher, &requested_state.len().to_string());
    for (key, value) in requested_state {
        hash_text(&mut hasher, key);
        hash_text(&mut hasher, value);
    }
    let digest = hasher.finalize();
    sha256_hex(&digest)
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hasher.update(value.len().to_string().as_bytes());
    hasher.update(b":");
    hasher.update(value.as_bytes());
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

const fn actor_kind_name(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Human => "human",
        ActorKind::Service => "service",
        ActorKind::Agent => "agent",
        ActorKind::Remote => "remote",
    }
}

const fn risk_name(risk: RiskClass) -> &'static str {
    match risk {
        RiskClass::ReadOnly => "read-only",
        RiskClass::UserState => "user-state",
        RiskClass::SystemMutation => "system-mutation",
        RiskClass::SecuritySensitive => "security-sensitive",
        RiskClass::Destructive => "destructive",
    }
}

fn current_unix_ms() -> Result<u64, String> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?;
    u64::try_from(duration.as_millis()).map_err(|_| "system time overflow".into())
}

fn bounded_diagnostic(value: String) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    if sanitized.len() <= MAX_TRANSIENT_DIAGNOSTIC_BYTES {
        return sanitized;
    }
    let mut end = MAX_TRANSIENT_DIAGNOSTIC_BYTES;
    while !sanitized.is_char_boundary(end) {
        end -= 1;
    }
    sanitized[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    };
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use linura_capability_sdk::{OperationDescriptor, OperationEffectBinding};
    use linura_core::{
        ActorId, ActorKind, Capability, CapabilityId, IntentId, ProviderId, ResourceId,
        SemanticReason, SupportLevel,
    };
    use linura_observation::{
        ObservationAuthority, ObservedValue, ProviderAvailability, ProviderHealth,
    };
    use linura_observation_control::ObservationCoordinator;
    use linura_provider_sdk::{Observer, ProviderError};

    use super::*;

    const PROVIDER: &str = "pipewire";
    const CAPABILITY: &str = "audio.session.observe";
    const RESOURCE: &str = "audio:session:uid:1000";
    const OPERATION: &str = "operation:audio.volume.set-session";

    struct TestAudioObserver {
        state: Arc<Mutex<BTreeMap<String, String>>>,
        sequence: AtomicU64,
        cached_post_state: Option<BTreeMap<String, String>>,
        post_observation_error: Option<String>,
        first_observed_at_unix_ms: Mutex<Option<u64>>,
    }

    impl Observer for TestAudioObserver {
        fn observer_id(&self) -> ProviderId {
            ProviderId::new(PROVIDER).unwrap_or_else(|error| unreachable!("{error}"))
        }

        fn observation_capabilities(&self) -> Vec<Capability> {
            vec![Capability {
                id: CapabilityId::new(CAPABILITY).unwrap_or_else(|error| unreachable!("{error}")),
                support: SupportLevel::Supported,
                provider: Some(self.observer_id()),
                reason: None,
            }]
        }

        fn health(&self) -> ProviderHealth {
            ProviderHealth {
                provider: self.observer_id(),
                availability: ProviderAvailability::Available,
                reason: None,
            }
        }

        fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
            Ok(vec![
                ResourceId::new(RESOURCE).unwrap_or_else(|error| unreachable!("{error}")),
            ])
        }

        fn observe_authoritative(
            &self,
            resource: &ResourceId,
            capability: &CapabilityId,
        ) -> Result<ObservationEnvelope, ProviderError> {
            if resource.as_str() != RESOURCE || capability.as_str() != CAPABILITY {
                return Err(ProviderError::Unsupported(
                    "unexpected test audio route".into(),
                ));
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| ProviderError::Internal(error.to_string()))?;
            let observed_at_unix_ms = u64::try_from(now.as_millis())
                .map_err(|_| ProviderError::Internal("test time overflow".into()))?;
            let sequence = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
            if sequence > 1
                && let Some(detail) = &self.post_observation_error
            {
                return Err(ProviderError::Internal(detail.clone()));
            }
            let observed_at_unix_ms = {
                let mut first = self.first_observed_at_unix_ms.lock().map_err(|_| {
                    ProviderError::Internal("test observation clock lock poisoned".into())
                })?;
                if sequence == 1 {
                    *first = Some(observed_at_unix_ms);
                    observed_at_unix_ms
                } else if self.cached_post_state.is_some() {
                    first.ok_or_else(|| {
                        ProviderError::Internal("missing cached pre-dispatch timestamp".into())
                    })?
                } else {
                    observed_at_unix_ms
                }
            };
            let state = if sequence > 1 {
                if let Some(cached) = &self.cached_post_state {
                    cached.clone()
                } else {
                    self.state
                        .lock()
                        .map_err(|_| ProviderError::Internal("test audio lock poisoned".into()))?
                        .clone()
                }
            } else {
                self.state
                    .lock()
                    .map_err(|_| ProviderError::Internal("test audio lock poisoned".into()))?
                    .clone()
            };
            Ok(ObservationEnvelope {
                provider: self.observer_id(),
                resource: resource.clone(),
                capability: capability.clone(),
                authority: ObservationAuthority::SyntheticTest,
                observed_at_unix_ms,
                valid_for_ms: 5_000,
                sequence,
                attributes: state
                    .into_iter()
                    .map(|(key, value)| (key, ObservedValue::Text(value)))
                    .collect(),
            })
        }
    }

    struct TestAudioExecutor {
        state: Arc<Mutex<BTreeMap<String, String>>>,
        fail: bool,
        mutate: bool,
        drift_muted: bool,
        calls: usize,
    }

    impl TransientEffectExecutor for TestAudioExecutor {
        fn execute(
            &mut self,
            effect: &AuthorizedTransientEffect,
        ) -> Result<(), TransientEffectExecutorError> {
            self.calls += 1;
            // Keep ordinary test observations unambiguously later than the
            // millisecond dispatch fence. The dedicated cached-evidence test
            // supplies an older provider timestamp and proves rejection.
            std::thread::sleep(Duration::from_millis(2));
            if self.fail {
                return Err(TransientEffectExecutorError::new(
                    "synthetic executor failure token=executor-secret",
                ));
            }
            let desired = effect
                .desired_state()
                .get("volume_percent")
                .unwrap_or_else(|| unreachable!("volume_percent must be bound"));
            if self.mutate {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|_| unreachable!("test audio lock poisoned"));
                state.insert("volume_percent".into(), desired.clone());
                if self.drift_muted {
                    state.insert("muted".into(), "true".into());
                }
            }
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct TestAudit {
        records: Arc<Mutex<Vec<TransientEffectAuditRecord>>>,
        fail_reservation: bool,
        fail_terminal: bool,
    }

    impl TransientEffectAuditSink for TestAudit {
        fn reserve_attempt(
            &mut self,
            record: &TransientEffectAuditRecord,
        ) -> Result<(), TransientEffectAuditError> {
            if self.fail_reservation {
                return Err(TransientEffectAuditError::new(
                    "synthetic audit reservation failure",
                ));
            }
            if record.disposition != TransientEffectAuditDisposition::AttemptReserved {
                return Err(TransientEffectAuditError::new(
                    "test audit reservation requires AttemptReserved",
                ));
            }
            self.records
                .lock()
                .map_err(|_| TransientEffectAuditError::new("test audit lock poisoned"))?
                .push(record.clone());
            Ok(())
        }

        fn record_terminal(
            &mut self,
            record: &TransientEffectAuditRecord,
        ) -> Result<(), TransientEffectAuditError> {
            if self.fail_terminal {
                return Err(TransientEffectAuditError::new(
                    "synthetic terminal audit failure",
                ));
            }
            if record.disposition == TransientEffectAuditDisposition::AttemptReserved {
                return Err(TransientEffectAuditError::new(
                    "test terminal audit cannot be AttemptReserved",
                ));
            }
            self.records
                .lock()
                .map_err(|_| TransientEffectAuditError::new("test audit lock poisoned"))?
                .push(record.clone());
            Ok(())
        }
    }

    fn terminal_record(
        records: &[TransientEffectAuditRecord],
        disposition: TransientEffectAuditDisposition,
    ) -> &TransientEffectAuditRecord {
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].disposition,
            TransientEffectAuditDisposition::AttemptReserved
        );
        assert_eq!(records[0].failure_code, None);
        assert!(records[0].post_effect_evidence_id.is_none());
        assert_eq!(records[1].disposition, disposition);
        assert_eq!(
            records[0].audit_attempt_sha256,
            records[1].audit_attempt_sha256
        );
        &records[1]
    }

    fn operation_id() -> OperationId {
        OperationId::new(OPERATION).unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn registry() -> OperationRegistry {
        let binding = OperationEffectBinding::try_new(
            ProviderId::new(PROVIDER).unwrap_or_else(|error| unreachable!("{error}")),
            CapabilityId::new(CAPABILITY).unwrap_or_else(|error| unreachable!("{error}")),
            "audio:session:",
            vec!["muted".into(), "volume_percent".into()],
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        let descriptor = OperationDescriptor::try_new(
            operation_id(),
            OperationClass::TransientExternalEffect,
            Some(RiskClass::UserState),
            Some(binding),
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));
        let mut registry = OperationRegistry::default();
        registry
            .register(descriptor)
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        registry
    }

    fn request(desired: &str) -> PlanDesiredStateRequest {
        request_with_state(
            &format!("request:audio-volume:{desired}"),
            BTreeMap::from([("volume_percent".into(), desired.into())]),
        )
    }

    fn request_with_state(
        request_id: &str,
        desired_state: BTreeMap<String, String>,
    ) -> PlanDesiredStateRequest {
        PlanDesiredStateRequest {
            request_id: RequestId::new(request_id).unwrap_or_else(|error| unreachable!("{error}")),
            provider: ProviderId::new(PROVIDER).unwrap_or_else(|error| unreachable!("{error}")),
            resource: ResourceId::new(RESOURCE).unwrap_or_else(|error| unreachable!("{error}")),
            observation_capability: CapabilityId::new(CAPABILITY)
                .unwrap_or_else(|error| unreachable!("{error}")),
            reason: SemanticReason {
                summary: "set current session volume".into(),
                intent_ids: vec![
                    IntentId::new("intent:audio-volume")
                        .unwrap_or_else(|error| unreachable!("{error}")),
                ],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
            desired_state,
        }
    }

    fn actor() -> Actor {
        Actor {
            id: ActorId::new("actor:human").unwrap_or_else(|error| unreachable!("{error}")),
            kind: ActorKind::Human,
            interactive: true,
        }
    }

    fn remote_actor() -> Actor {
        Actor {
            id: ActorId::new("actor:remote").unwrap_or_else(|error| unreachable!("{error}")),
            kind: ActorKind::Remote,
            interactive: false,
        }
    }

    fn principal() -> AuthenticatedPrincipal {
        AuthenticatedPrincipal::new("unix:uid:1000")
            .unwrap_or_else(|error| unreachable!("{error:?}"))
    }

    fn control(
        initial: &str,
        fail: bool,
        mutate: bool,
        drift_muted: bool,
    ) -> (
        TransientEffectControl<TestAudioExecutor, TestAudit>,
        TestAudit,
    ) {
        control_with_cached_post_state(initial, fail, mutate, drift_muted, None)
    }

    fn control_with_cached_post_state(
        initial: &str,
        fail: bool,
        mutate: bool,
        drift_muted: bool,
        cached_post_state: Option<BTreeMap<String, String>>,
    ) -> (
        TransientEffectControl<TestAudioExecutor, TestAudit>,
        TestAudit,
    ) {
        control_with_observer_options(initial, fail, mutate, drift_muted, cached_post_state, None)
    }

    fn control_with_observer_options(
        initial: &str,
        fail: bool,
        mutate: bool,
        drift_muted: bool,
        cached_post_state: Option<BTreeMap<String, String>>,
        post_observation_error: Option<String>,
    ) -> (
        TransientEffectControl<TestAudioExecutor, TestAudit>,
        TestAudit,
    ) {
        let state = Arc::new(Mutex::new(BTreeMap::from([
            ("muted".into(), "false".into()),
            ("volume_percent".into(), initial.to_owned()),
        ])));
        let observer = TestAudioObserver {
            state: Arc::clone(&state),
            sequence: AtomicU64::new(0),
            cached_post_state,
            post_observation_error,
            first_observed_at_unix_ms: Mutex::new(None),
        };
        let mut coordinator = ObservationCoordinator::new();
        coordinator
            .register_observer(Box::new(observer))
            .unwrap_or_else(|error| unreachable!("{error}"));
        let audit = TestAudit::default();
        let control = TransientEffectControl::from_trusted_registry(
            PlanPreviewControl::new(coordinator),
            registry(),
            TestAudioExecutor {
                state,
                fail,
                mutate,
                drift_muted,
                calls: 0,
            },
            audit.clone(),
        );
        (control, audit)
    }

    #[test]
    fn transient_effect_is_plan_bound_policy_allowed_reobserved_verified_and_audited() {
        let (mut control, audit) = control("20", false, true, false);
        let receipt = control
            .execute(principal(), actor(), operation_id(), request("40"))
            .unwrap_or_else(|error| unreachable!("{error:?}"));

        assert_eq!(receipt.status, TransientEffectReceiptStatus::Verified);
        assert_eq!(receipt.risk, RiskClass::UserState);
        assert_ne!(
            receipt.pre_effect_evidence_id,
            receipt
                .post_effect_evidence_id
                .clone()
                .unwrap_or_else(|| unreachable!("verified receipt requires post evidence"))
        );
        let records = audit
            .records
            .lock()
            .unwrap_or_else(|_| unreachable!("test audit lock poisoned"));
        let terminal = terminal_record(&records, TransientEffectAuditDisposition::Verified);
        assert_eq!(terminal.policy_id.as_str(), "policy:baseline");
        assert_eq!(terminal.policy_revision_id.as_str(), "policy:baseline:v1");
        assert_eq!(terminal.policy_subject_risk, RiskClass::UserState);
        assert_eq!(
            terminal.risk_classification_revision,
            REGISTERED_TRANSIENT_RISK_POLICY_REVISION
        );
        assert_eq!(
            terminal.risk_rule_ids,
            vec!["audio.session.output-state.user-state".to_owned()]
        );
        assert_eq!(terminal.failure_code, None);
        assert_eq!(terminal.audit_attempt_sha256.len(), 64);
    }

    #[test]
    fn executor_failure_still_reobserves_and_is_audited() {
        let (mut control, audit) = control("20", true, false, false);
        let error = match control.execute(principal(), actor(), operation_id(), request("40")) {
            Ok(_) => unreachable!("synthetic executor must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            TransientEffectError::ExecutorFailed {
                post_effect_evidence_id: Some(_),
                ..
            }
        ));
        let records = audit
            .records
            .lock()
            .unwrap_or_else(|_| unreachable!("test audit lock poisoned"));
        let terminal = terminal_record(&records, TransientEffectAuditDisposition::ExecutorFailed);
        assert_eq!(
            terminal.failure_code,
            Some(TransientEffectAuditFailureCode::ExecutorFailed)
        );
        assert!(terminal.post_effect_evidence_id.is_some());
        assert!(!format!("{terminal:?}").contains("executor-secret"));
    }

    #[test]
    fn post_effect_observation_diagnostic_is_not_persisted() {
        let (mut control, audit) = control_with_observer_options(
            "20",
            false,
            true,
            false,
            None,
            Some("provider failed token=observer-secret".into()),
        );
        let error = match control.execute(principal(), actor(), operation_id(), request("40")) {
            Ok(_) => unreachable!("post-effect observation must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            TransientEffectError::PostEffectObservationFailed(detail)
                if detail.contains("observer-secret")
        ));
        let records = audit
            .records
            .lock()
            .unwrap_or_else(|_| unreachable!("test audit lock poisoned"));
        let terminal = terminal_record(
            &records,
            TransientEffectAuditDisposition::PostEffectObservationFailed,
        );
        assert_eq!(
            terminal.failure_code,
            Some(TransientEffectAuditFailureCode::PostEffectObservationFailed)
        );
        assert!(!format!("{terminal:?}").contains("observer-secret"));
    }

    #[test]
    fn executor_success_without_observed_postcondition_fails_verification() {
        let (mut control, audit) = control("20", false, false, false);
        let error = match control.execute(principal(), actor(), operation_id(), request("40")) {
            Ok(_) => unreachable!("executor self-report cannot prove the postcondition"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            TransientEffectError::VerificationFailed {
                key,
                desired,
                observed: Some(observed),
                ..
            } if key == "volume_percent" && desired == "40" && observed == "20"
        ));
        let records = audit
            .records
            .lock()
            .unwrap_or_else(|_| unreachable!("test audit lock poisoned"));
        let _terminal = terminal_record(
            &records,
            TransientEffectAuditDisposition::VerificationFailed,
        );
    }

    #[test]
    fn satisfied_requested_attribute_is_still_verified_after_execution() {
        let (mut control, audit) = control("20", false, true, true);
        let request = request_with_state(
            "request:audio-complete-postcondition",
            BTreeMap::from([
                ("muted".into(), "false".into()),
                ("volume_percent".into(), "40".into()),
            ]),
        );
        let error = match control.execute(principal(), actor(), operation_id(), request) {
            Ok(_) => {
                unreachable!("drift of an initially satisfied attribute must fail verification")
            }
            Err(error) => error,
        };
        assert!(matches!(
            error,
            TransientEffectError::VerificationFailed {
                key,
                desired,
                observed: Some(observed),
                ..
            } if key == "muted" && desired == "false" && observed == "true"
        ));
        let records = audit
            .records
            .lock()
            .unwrap_or_else(|_| unreachable!("test audit lock poisoned"));
        let _terminal = terminal_record(
            &records,
            TransientEffectAuditDisposition::VerificationFailed,
        );
    }

    #[test]
    fn audit_binding_distinguishes_request_id_reuse_with_changed_effect_material() {
        let (mut control, audit) = control("20", false, true, false);
        let first = request_with_state(
            "request:audio-reused-id",
            BTreeMap::from([("volume_percent".into(), "40".into())]),
        );
        control
            .execute(principal(), actor(), operation_id(), first)
            .unwrap_or_else(|error| unreachable!("{error:?}"));

        let second = request_with_state(
            "request:audio-reused-id",
            BTreeMap::from([("volume_percent".into(), "60".into())]),
        );
        control
            .execute(principal(), actor(), operation_id(), second)
            .unwrap_or_else(|error| unreachable!("{error:?}"));

        let records = audit
            .records
            .lock()
            .unwrap_or_else(|_| unreachable!("test audit lock poisoned"));
        assert_eq!(records.len(), 4);
        assert_eq!(
            records[0].disposition,
            TransientEffectAuditDisposition::AttemptReserved
        );
        assert_eq!(
            records[1].disposition,
            TransientEffectAuditDisposition::Verified
        );
        assert_eq!(
            records[2].disposition,
            TransientEffectAuditDisposition::AttemptReserved
        );
        assert_eq!(
            records[3].disposition,
            TransientEffectAuditDisposition::Verified
        );
        assert_eq!(
            records[0].audit_attempt_sha256,
            records[1].audit_attempt_sha256
        );
        assert_eq!(
            records[2].audit_attempt_sha256,
            records[3].audit_attempt_sha256
        );
        assert_ne!(
            records[1].audit_attempt_sha256,
            records[3].audit_attempt_sha256
        );
        assert_eq!(records[1].request_id, records[3].request_id);
        assert_eq!(records[1].plan_id, records[3].plan_id);
        assert_ne!(
            records[1].canonical_plan_sha256,
            records[3].canonical_plan_sha256
        );
        assert_ne!(
            records[1].requested_postcondition_sha256,
            records[3].requested_postcondition_sha256
        );
        assert_eq!(records[1].canonical_plan_sha256.len(), 64);
        assert_eq!(records[1].requested_postcondition_sha256.len(), 64);
        assert_eq!(records[1].provider.as_str(), PROVIDER);
        assert_eq!(records[1].resource.as_str(), RESOURCE);
        assert_eq!(records[1].observation_capability.as_str(), CAPABILITY);
    }

    #[test]
    fn cached_pre_dispatch_evidence_cannot_verify_execution() {
        let cached_post_state = BTreeMap::from([
            ("muted".into(), "false".into()),
            ("volume_percent".into(), "40".into()),
        ]);
        let (mut control, audit) =
            control_with_cached_post_state("20", false, false, false, Some(cached_post_state));
        let error = match control.execute(principal(), actor(), operation_id(), request("40")) {
            Ok(_) => unreachable!("cached evidence produced before dispatch cannot verify success"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            TransientEffectError::PostEffectEvidenceNotAfterDispatch { .. }
        ));
        let records = audit
            .records
            .lock()
            .unwrap_or_else(|_| unreachable!("test audit lock poisoned"));
        let terminal = terminal_record(
            &records,
            TransientEffectAuditDisposition::VerificationFailed,
        );
        assert_ne!(
            terminal.pre_effect_evidence_id,
            terminal
                .post_effect_evidence_id
                .clone()
                .unwrap_or_else(|| unreachable!("rejected cached evidence has an identity"))
        );
    }

    #[test]
    fn audit_reservation_failure_prevents_executor_dispatch() {
        let (mut control, audit) = control("20", false, true, false);
        control.audit.fail_reservation = true;
        let error = match control.execute(principal(), actor(), operation_id(), request("40")) {
            Ok(_) => unreachable!("dispatch must not occur without durable audit reservation"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            TransientEffectError::AuditFailed(detail)
                if detail.contains("audit reservation failure")
        ));
        assert_eq!(control.executor.calls, 0);
        assert!(
            audit
                .records
                .lock()
                .unwrap_or_else(|_| unreachable!("test audit lock poisoned"))
                .is_empty()
        );
    }

    #[test]
    fn terminal_audit_failure_preserves_reserved_attempt() {
        let (mut control, audit) = control("20", false, true, false);
        control.audit.fail_terminal = true;
        let error = match control.execute(principal(), actor(), operation_id(), request("40")) {
            Ok(_) => unreachable!("terminal audit failure must fail the receipt"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            TransientEffectError::AuditFailed(detail)
                if detail.contains("terminal audit failure")
        ));
        assert_eq!(control.executor.calls, 1);
        let records = audit
            .records
            .lock()
            .unwrap_or_else(|_| unreachable!("test audit lock poisoned"));
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].disposition,
            TransientEffectAuditDisposition::AttemptReserved
        );
        assert_eq!(records[0].audit_attempt_sha256.len(), 64);
    }

    #[test]
    fn no_change_skips_execution_but_records_audit() {
        let (mut control, audit) = control("40", false, true, false);
        let receipt = control
            .execute(principal(), actor(), operation_id(), request("40"))
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(receipt.status, TransientEffectReceiptStatus::NoChange);
        let records = audit
            .records
            .lock()
            .unwrap_or_else(|_| unreachable!("test audit lock poisoned"));
        assert_eq!(
            records[0].disposition,
            TransientEffectAuditDisposition::NoChange
        );
        assert_eq!(records[0].policy_id.as_str(), "policy:baseline");
        assert_eq!(records[0].policy_revision_id.as_str(), "policy:baseline:v1");
        assert_eq!(records[0].policy_subject_risk, RiskClass::ReadOnly);
        assert_eq!(
            records[0].risk_classification_revision,
            REGISTERED_TRANSIENT_RISK_POLICY_REVISION
        );
        assert!(records[0].risk_rule_ids.is_empty());
        assert_eq!(records[0].failure_code, None);
    }

    #[test]
    fn no_change_is_still_policy_gated() {
        let (mut control, audit) = control("40", false, true, false);
        let error =
            match control.execute(principal(), remote_actor(), operation_id(), request("40")) {
                Ok(_) => unreachable!("remote no-change request must not bypass policy"),
                Err(error) => error,
            };
        assert!(matches!(
            error,
            TransientEffectError::PolicyDenied(reason)
                if reason.contains("remote actors are disabled")
        ));
        assert_eq!(control.executor.calls, 0);
        assert!(
            audit
                .records
                .lock()
                .unwrap_or_else(|_| unreachable!("test audit lock poisoned"))
                .is_empty()
        );
    }

    #[test]
    fn unregistered_operation_fails_before_executor_dispatch() {
        let (mut control, audit) = control("20", false, true, false);
        let missing =
            OperationId::new("operation:missing").unwrap_or_else(|error| unreachable!("{error}"));
        let error = match control.execute(principal(), actor(), missing.clone(), request("40")) {
            Ok(_) => unreachable!("unknown operation must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            TransientEffectError::Semantics(OperationSemanticsError::UnknownOperation(id))
                if id == missing
        ));
        assert!(
            audit
                .records
                .lock()
                .unwrap_or_else(|_| unreachable!("test audit lock poisoned"))
                .is_empty()
        );
    }
}
