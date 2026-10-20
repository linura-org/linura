use linura_core::PlanId;
use linura_policy::{ApprovalClass, PolicyDecision, ReviewFindingLevel, ReviewPlanStatus};
use linura_protocol::{
    PlanPreviewChange, PlanPreviewFinding, PlanPreviewFindingLevel, PlanPreviewStatus, PlanReview,
    PlanReviewApprovalClass, PlanReviewDecision,
};

use crate::{
    AuthenticatedPrincipal, PlanPreviewControl, PlanPreviewControlError, TrustedPolicyReview,
};

impl PlanPreviewControl {
    /// Review only canonical plan material retained by this Control instance for
    /// the authenticated principal. Public callers supply identity, never plan
    /// material, policy subjects, policy decisions, or authority risk.
    pub fn review_plan(
        &self,
        principal: &AuthenticatedPrincipal,
        plan_id: &PlanId,
    ) -> Result<PlanReview, PlanPreviewControlError> {
        let plan = self.retained_plan(principal, plan_id)?;
        let review = crate::policy_review::review_plan(principal, &plan).map_err(|error| {
            PlanPreviewControlError::Review {
                reason: format!("{error:?}"),
            }
        })?;
        Ok(plan_review_projection(plan.prospective_risk, &review))
    }

    /// Deterministic explanation is the exact same authority projection as
    /// review. v0.3 retains no separate durable authorization state.
    pub fn explain_plan_review(
        &self,
        principal: &AuthenticatedPrincipal,
        plan_id: &PlanId,
    ) -> Result<PlanReview, PlanPreviewControlError> {
        self.review_plan(principal, plan_id)
    }
}

fn plan_review_projection(
    planner_risk_floor: linura_core::RiskClass,
    review: &TrustedPolicyReview,
) -> PlanReview {
    let subject = review.subject();
    let binding = review.binding();
    let (decision, approval_class, decision_reason) = match review.decision() {
        PolicyDecision::Allow => (PlanReviewDecision::Allow, None, String::new()),
        PolicyDecision::Deny { reason } => (PlanReviewDecision::Deny, None, reason.clone()),
        PolicyDecision::RequireApproval { class, reason } => (
            PlanReviewDecision::RequireApproval,
            Some(map_approval_class(*class)),
            reason.clone(),
        ),
        PolicyDecision::Blocked { reason } => (PlanReviewDecision::Blocked, None, reason.clone()),
    };

    PlanReview {
        plan_id: subject.plan_id().clone(),
        request_id: subject.request_id().clone(),
        principal: subject.principal().clone(),
        actor: subject.actor().clone(),
        provider: subject.provider().clone(),
        resource: subject.resource().clone(),
        observation_capability: subject.capability().clone(),
        reason: subject.reason().clone(),
        observed_evidence_id: subject.observed_evidence_id().to_owned(),
        planner_risk_floor,
        reviewed_risk: subject.prospective_risk(),
        status: map_status(subject.status()),
        policy_id: binding.policy_id.clone(),
        policy_revision_id: binding.policy_revision_id.clone(),
        decision,
        approval_class,
        decision_reason,
        execution_authorized: false,
        changes: subject
            .changes()
            .iter()
            .map(|change| PlanPreviewChange {
                key: change.key.clone(),
                current: change.current.clone(),
                desired: change.desired.clone(),
            })
            .collect(),
        findings: subject
            .findings()
            .iter()
            .map(|finding| PlanPreviewFinding {
                code: finding.code.clone(),
                level: map_finding_level(finding.level),
                message: finding.message.clone(),
            })
            .collect(),
    }
}

const fn map_status(status: ReviewPlanStatus) -> PlanPreviewStatus {
    match status {
        ReviewPlanStatus::NoChange => PlanPreviewStatus::NoChange,
        ReviewPlanStatus::ChangeProposed => PlanPreviewStatus::ChangeProposed,
        ReviewPlanStatus::Blocked => PlanPreviewStatus::Blocked,
    }
}

const fn map_finding_level(level: ReviewFindingLevel) -> PlanPreviewFindingLevel {
    match level {
        ReviewFindingLevel::Pass => PlanPreviewFindingLevel::Pass,
        ReviewFindingLevel::Warning => PlanPreviewFindingLevel::Warning,
        ReviewFindingLevel::Blocker => PlanPreviewFindingLevel::Blocker,
    }
}

const fn map_approval_class(class: ApprovalClass) -> PlanReviewApprovalClass {
    match class {
        ApprovalClass::InteractiveUser => PlanReviewApprovalClass::InteractiveUser,
        ApprovalClass::SessionOwnerAuthentication => {
            PlanReviewApprovalClass::SessionOwnerAuthentication
        }
        ApprovalClass::Administrator => PlanReviewApprovalClass::Administrator,
        ApprovalClass::DestructiveAction => PlanReviewApprovalClass::DestructiveAction,
    }
}

#[cfg(test)]
mod tests {
    use linura_core::{
        Actor, ActorId, ActorKind, CapabilityId, IntentId, PlanId, PrincipalId, ProviderId,
        RequestId, ResourceId, RiskClass, SemanticReason,
    };
    use linura_policy::{PolicySubject, ReviewPlanStatus, ReviewedChange};

    use super::*;
    use crate::policy_review::review_subject_for_control;

    #[test]
    fn projection_is_non_executable_and_typed() {
        let subject = PolicySubject::try_new(
            PrincipalId::new("unix:uid:1000").unwrap_or_else(|error| unreachable!("{error}")),
            PlanId::new("request:test").unwrap_or_else(|error| unreachable!("{error}")),
            RequestId::new("request:test").unwrap_or_else(|error| unreachable!("{error}")),
            Actor {
                id: ActorId::new("actor:test").unwrap_or_else(|error| unreachable!("{error}")),
                kind: ActorKind::Service,
                interactive: false,
            },
            ProviderId::new("systemd").unwrap_or_else(|error| unreachable!("{error}")),
            ResourceId::new("systemd:unit:test.service")
                .unwrap_or_else(|error| unreachable!("{error}")),
            CapabilityId::new("systemd.unit.observe")
                .unwrap_or_else(|error| unreachable!("{error}")),
            SemanticReason {
                summary: "review test".into(),
                intent_ids: vec![
                    IntentId::new("intent:review-test")
                        .unwrap_or_else(|error| unreachable!("{error}")),
                ],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
            "evidence:test".into(),
            RiskClass::SecuritySensitive,
            ReviewPlanStatus::ChangeProposed,
            vec![ReviewedChange {
                key: "active_state".into(),
                current: Some("inactive".into()),
                desired: "active".into(),
            }],
            vec![],
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let review = review_subject_for_control(subject);
        let projection = plan_review_projection(RiskClass::SystemMutation, &review);
        assert_eq!(projection.planner_risk_floor, RiskClass::SystemMutation);
        assert_eq!(projection.reviewed_risk, RiskClass::SecuritySensitive);
        assert_eq!(projection.decision, PlanReviewDecision::RequireApproval);
        assert_eq!(
            projection.approval_class,
            Some(PlanReviewApprovalClass::Administrator)
        );
        assert!(!projection.execution_authorized);
    }
}
