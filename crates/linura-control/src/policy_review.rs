use linura_core::{PrincipalId, RiskClass, ValidationError};
use linura_planner::{PlanFindingLevel, PlanStatus, ReconciliationPlan};
use linura_policy::{
    BaselinePolicy, PolicyDecision, PolicyEngine, PolicyEvaluation, PolicySubject,
    PolicySubjectValidationError, ReviewBinding, ReviewFindingLevel, ReviewPlanStatus,
    ReviewedChange, ReviewedFinding,
};

use crate::AuthenticatedPrincipal;
use crate::risk_classification::{RiskClassification, classify_plan_risk};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicySubjectError {
    InvalidPrincipal(String),
    InvalidSubject(String),
}

/// Opaque Control-owned result of evaluating one canonical plan through the
/// trusted risk-classification and policy path.
///
/// Callers may inspect the reviewed material, but cannot construct or replace
/// the enclosed `PolicyEvaluation`. Approval issuance accepts this type rather
/// than a freely mutable `PolicyEvaluation`, so client/provider/model code cannot
/// pair a high-risk subject with a weaker approval decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedPolicyReview {
    evaluation: PolicyEvaluation,
}

impl TrustedPolicyReview {
    #[must_use]
    pub fn subject(&self) -> &PolicySubject {
        &self.evaluation.subject
    }

    #[must_use]
    pub fn binding(&self) -> &ReviewBinding {
        &self.evaluation.binding
    }

    #[must_use]
    pub fn decision(&self) -> &PolicyDecision {
        &self.evaluation.decision
    }

    #[must_use]
    pub(crate) const fn evaluation(&self) -> &PolicyEvaluation {
        &self.evaluation
    }
}

/// Derive the internal policy-review subject from Linura's canonical
/// reconciliation plan and the already-authenticated control principal.
///
/// Control applies the trusted risk-policy classification before constructing
/// the subject. The planner's prospective risk is a floor, not a complete
/// authorization classification. Unknown mutation shapes and attempted risk
/// downgrades are converted into blocker findings and fail closed.
///
/// This is intentionally owned by `linura-control`: transports authenticate,
/// the planner plans, trusted authority classifies risk, policy evaluates, and
/// Control binds those boundaries. `linura-policy` independently revalidates the
/// projected subject before it can be evaluated.
pub fn policy_subject_from_plan(
    principal: &AuthenticatedPrincipal,
    plan: &ReconciliationPlan,
) -> Result<PolicySubject, PolicySubjectError> {
    policy_subject_from_plan_with_classification(principal, plan, classify_plan_risk(plan))
}

/// Evaluate canonical plan material already owned by Control through the trusted
/// v0.3 review path.
///
/// This constructor is deliberately crate-private. `ReconciliationPlan` remains
/// an Experimental public data type with public fields, so accepting one through
/// a public authority constructor would let callers fabricate plan material and
/// obtain a misleadingly trusted review. The public integration surface will
/// review a retained canonical plan by identity through Control orchestration.
pub(crate) fn review_plan(
    principal: &AuthenticatedPrincipal,
    plan: &ReconciliationPlan,
) -> Result<TrustedPolicyReview, PolicySubjectError> {
    let subject = policy_subject_from_plan(principal, plan)?;
    Ok(review_subject_for_control(subject))
}

pub(crate) fn review_plan_with_classification(
    principal: &AuthenticatedPrincipal,
    plan: &ReconciliationPlan,
    classification: RiskClassification,
) -> Result<TrustedPolicyReview, PolicySubjectError> {
    let subject = policy_subject_from_plan_with_classification(principal, plan, classification)?;
    Ok(review_subject_for_control(subject))
}

pub(crate) fn review_subject_for_control(subject: PolicySubject) -> TrustedPolicyReview {
    TrustedPolicyReview {
        evaluation: BaselinePolicy::default().evaluate(&subject),
    }
}

fn policy_subject_from_plan_with_classification(
    principal: &AuthenticatedPrincipal,
    plan: &ReconciliationPlan,
    classification: RiskClassification,
) -> Result<PolicySubject, PolicySubjectError> {
    let principal = PrincipalId::new(principal.as_str().to_owned()).map_err(map_principal_error)?;
    let mut status = map_status(plan.status);
    let mut risk = plan.prospective_risk;
    let mut findings = plan
        .findings
        .iter()
        .map(|finding| ReviewedFinding {
            code: finding.code.clone(),
            level: map_finding_level(finding.level),
            message: finding.message.clone(),
        })
        .collect::<Vec<_>>();

    match classification {
        RiskClassification::NotApplicable {
            risk: classified_risk,
        } => {
            risk = classified_risk;
        }
        RiskClassification::Classified {
            risk: classified_risk,
            revision,
            rule_ids,
        } => {
            risk = classified_risk;
            findings.push(ReviewedFinding {
                code: "authority-risk-classified".into(),
                level: ReviewFindingLevel::Pass,
                message: format!(
                    "trusted risk policy {revision} classified the canonical plan as {} using rules {}",
                    risk_name(classified_risk),
                    rule_ids.join(",")
                ),
            });
        }
        RiskClassification::Unclassified { revision, reason } => {
            status = ReviewPlanStatus::Blocked;
            findings.push(ReviewedFinding {
                code: "authority-risk-unclassified".into(),
                level: ReviewFindingLevel::Blocker,
                message: format!(
                    "trusted risk policy {revision} cannot classify this mutation safely: {reason}"
                ),
            });
        }
        RiskClassification::DowngradeRejected {
            revision,
            floor,
            classified,
            rule_ids,
        } => {
            status = ReviewPlanStatus::Blocked;
            findings.push(ReviewedFinding {
                code: "authority-risk-downgrade-rejected".into(),
                level: ReviewFindingLevel::Blocker,
                message: format!(
                    "trusted risk policy {revision} attempted to classify below the planner floor: floor={} classified={} rules={}",
                    risk_name(floor),
                    risk_name(classified),
                    rule_ids.join(",")
                ),
            });
        }
    }

    PolicySubject::try_new(
        principal,
        plan.id.clone(),
        plan.request_id.clone(),
        plan.actor.clone(),
        plan.provider.clone(),
        plan.resource.clone(),
        plan.observation_capability.clone(),
        plan.reason.clone(),
        plan.observed_evidence_id.clone(),
        risk,
        status,
        plan.changes
            .iter()
            .map(|change| ReviewedChange {
                key: change.key.clone(),
                current: change.current.clone(),
                desired: change.desired.clone(),
            })
            .collect(),
        findings,
    )
    .map_err(map_subject_error)
}

fn map_principal_error(error: ValidationError) -> PolicySubjectError {
    PolicySubjectError::InvalidPrincipal(error.to_string())
}

fn map_subject_error(error: PolicySubjectValidationError) -> PolicySubjectError {
    PolicySubjectError::InvalidSubject(error.to_string())
}

const fn map_status(status: PlanStatus) -> ReviewPlanStatus {
    match status {
        PlanStatus::NoChange => ReviewPlanStatus::NoChange,
        PlanStatus::ChangeProposed => ReviewPlanStatus::ChangeProposed,
        PlanStatus::Blocked => ReviewPlanStatus::Blocked,
    }
}

const fn map_finding_level(level: PlanFindingLevel) -> ReviewFindingLevel {
    match level {
        PlanFindingLevel::Pass => ReviewFindingLevel::Pass,
        PlanFindingLevel::Warning => ReviewFindingLevel::Warning,
        PlanFindingLevel::Blocker => ReviewFindingLevel::Blocker,
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use linura_core::{Actor, ActorId, ActorKind, IntentId, RequestId, SemanticReason};
    use linura_planner::{
        DesiredResource, DeterministicPlanner, PlanningFreshness, PlanningObservation,
    };
    use linura_policy::{ApprovalClass, BaselinePolicy, PolicyDecision, PolicyEngine};

    use super::*;

    fn canonical_plan() -> ReconciliationPlan {
        let request_id =
            RequestId::new("request:review").unwrap_or_else(|error| unreachable!("{error}"));
        let actor = Actor {
            id: ActorId::new("actor:human").unwrap_or_else(|error| unreachable!("{error}")),
            kind: ActorKind::Human,
            interactive: true,
        };
        let provider =
            linura_core::ProviderId::new("systemd").unwrap_or_else(|error| unreachable!("{error}"));
        let resource = linura_core::ResourceId::new("systemd:unit:test.service")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let capability = linura_core::CapabilityId::new("systemd.unit.observe")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let desired = DesiredResource {
            provider: provider.clone(),
            resource: resource.clone(),
            observation_capability: capability.clone(),
            state: BTreeMap::from([("active_state".into(), "active".into())]),
            reason: SemanticReason {
                summary: "keep test active".into(),
                intent_ids: vec![
                    IntentId::new("intent:test").unwrap_or_else(|error| unreachable!("{error}")),
                ],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
        };
        let observation = PlanningObservation {
            provider,
            resource,
            observation_capability: capability,
            authority: "authoritative".into(),
            evidence_id: "evidence:review".into(),
            freshness: PlanningFreshness::Current,
            attributes: BTreeMap::from([("active_state".into(), "inactive".into())]),
        };
        DeterministicPlanner
            .plan_resource(request_id, actor, desired, &observation)
            .unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn principal() -> AuthenticatedPrincipal {
        AuthenticatedPrincipal::new("uid:1000").unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[test]
    fn canonical_plan_projects_exact_review_material() {
        let plan = canonical_plan();
        let subject = policy_subject_from_plan(&principal(), &plan)
            .unwrap_or_else(|error| unreachable!("{error:?}"));

        assert_eq!(subject.principal().as_str(), "uid:1000");
        assert_eq!(subject.plan_id(), &plan.id);
        assert_eq!(subject.observed_evidence_id(), "evidence:review");
        assert_eq!(subject.reason(), &plan.reason);
        assert_eq!(subject.changes().len(), plan.changes.len());
        assert_eq!(subject.status(), ReviewPlanStatus::ChangeProposed);
        assert_eq!(subject.prospective_risk(), RiskClass::SecuritySensitive);
        assert!(subject.findings().iter().any(|finding| {
            finding.code == "authority-risk-classified"
                && finding.message.contains("risk-policy:v0.3:1")
                && finding
                    .message
                    .contains("systemd.unit.active-state.security-sensitive")
        }));
    }

    #[test]
    fn explicit_trusted_classification_is_reflected_in_policy_subject() {
        let plan = canonical_plan();
        let review = review_plan_with_classification(
            &principal(),
            &plan,
            RiskClassification::Classified {
                risk: RiskClass::Destructive,
                revision: "risk-policy:test:registered-floor",
                rule_ids: vec!["operation-registry:test-floor"],
            },
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));

        assert_eq!(review.subject().prospective_risk(), RiskClass::Destructive);
        assert!(matches!(
            review.decision(),
            PolicyDecision::RequireApproval {
                class: ApprovalClass::DestructiveAction,
                ..
            }
        ));
    }

    #[test]
    fn canonical_systemd_change_requires_administrator_approval() {
        let plan = canonical_plan();
        let review =
            review_plan(&principal(), &plan).unwrap_or_else(|error| unreachable!("{error:?}"));

        assert!(matches!(
            review.decision(),
            PolicyDecision::RequireApproval {
                class: ApprovalClass::Administrator,
                ..
            }
        ));
        assert_eq!(review.subject().plan_id(), &plan.id);
        assert_eq!(review.binding().principal.as_str(), "uid:1000");
    }

    #[test]
    fn unclassified_canonical_mutation_fails_closed() {
        let mut plan = canonical_plan();
        plan.changes[0].key = "fragment_path".into();
        let subject = policy_subject_from_plan(&principal(), &plan)
            .unwrap_or_else(|error| unreachable!("{error:?}"));

        assert_eq!(subject.status(), ReviewPlanStatus::Blocked);
        assert!(subject.findings().iter().any(|finding| {
            finding.code == "authority-risk-unclassified"
                && finding.level == ReviewFindingLevel::Blocker
        }));
        assert!(matches!(
            BaselinePolicy::default().evaluate(&subject).decision,
            PolicyDecision::Blocked { .. }
        ));
    }

    #[test]
    fn destructive_classification_reaches_destructive_approval_on_canonical_plan() {
        let plan = canonical_plan();
        let subject = policy_subject_from_plan_with_classification(
            &principal(),
            &plan,
            RiskClassification::Classified {
                risk: RiskClass::Destructive,
                revision: "risk-policy:test:destructive",
                rule_ids: vec!["test.destructive"],
            },
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));

        assert_eq!(subject.prospective_risk(), RiskClass::Destructive);
        assert!(matches!(
            BaselinePolicy::default().evaluate(&subject).decision,
            PolicyDecision::RequireApproval {
                class: ApprovalClass::DestructiveAction,
                ..
            }
        ));
    }

    #[test]
    fn attempted_risk_downgrade_blocks_before_policy_allow() {
        let plan = canonical_plan();
        let subject = policy_subject_from_plan_with_classification(
            &principal(),
            &plan,
            RiskClassification::DowngradeRejected {
                revision: "risk-policy:test:downgrade",
                floor: RiskClass::SystemMutation,
                classified: RiskClass::UserState,
                rule_ids: vec!["unsafe-downgrade"],
            },
        )
        .unwrap_or_else(|error| unreachable!("{error:?}"));

        assert_eq!(subject.status(), ReviewPlanStatus::Blocked);
        assert!(subject.findings().iter().any(|finding| {
            finding.code == "authority-risk-downgrade-rejected"
                && finding.level == ReviewFindingLevel::Blocker
        }));
        assert!(matches!(
            BaselinePolicy::default().evaluate(&subject).decision,
            PolicyDecision::Blocked { .. }
        ));
    }
}
