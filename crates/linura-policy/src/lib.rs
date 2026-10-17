#![forbid(unsafe_code)]

mod session_lock;
pub use session_lock::SessionLockPolicy;
mod protective_lock;
pub use protective_lock::{
    PROTECTIVE_SLEEP_ACTOR, PROTECTIVE_SLEEP_PRINCIPAL, ProtectiveLockPolicy, ProtectiveLockSetting,
};

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

use linura_core::{
    Actor, ActorKind, CapabilityId, PlanId, PolicyId, PolicyRevisionId, PrincipalId, ProviderId,
    RequestId, ResourceId, RiskClass, SemanticReason,
};

const MAX_EVIDENCE_ID_BYTES: usize = 1024;
const MAX_REVIEW_CHANGES: usize = 256;
const MAX_REVIEW_FINDINGS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApprovalClass {
    InteractiveUser,
    /// Native authentication of the owner of one exact session-lock generation.
    /// This is neither administrator approval nor a destructive-action grant.
    SessionOwnerAuthentication,
    Administrator,
    DestructiveAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewPlanStatus {
    NoChange,
    ChangeProposed,
    Blocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewFindingLevel {
    Pass,
    Warning,
    Blocker,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedChange {
    pub key: String,
    pub current: Option<String>,
    pub desired: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedFinding {
    pub code: String,
    pub level: ReviewFindingLevel,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySnapshot {
    pub policy_id: PolicyId,
    pub revision_id: PolicyRevisionId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicySubjectValidationError {
    InvalidSemanticReason(String),
    EmptyEvidenceId,
    EvidenceIdTooLong,
    TooManyChanges,
    TooManyFindings,
    EmptyChangeKey,
    DuplicateChangeKey(String),
    EmptyFindingCode,
    EmptyFindingMessage,
    NoChangeContainsChanges,
    NoChangeHasNonReadOnlyRisk,
    ChangeProposedWithoutChanges,
    ChangeProposedIsReadOnly,
    NonBlockedSubjectHasBlocker,
    BlockedSubjectHasNoBlocker,
}

impl Display for PolicySubjectValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSemanticReason(reason) => write!(f, "invalid semantic reason: {reason}"),
            Self::EmptyEvidenceId => f.write_str("policy subject evidence id cannot be empty"),
            Self::EvidenceIdTooLong => write!(
                f,
                "policy subject evidence id exceeds {MAX_EVIDENCE_ID_BYTES} UTF-8 bytes"
            ),
            Self::TooManyChanges => write!(
                f,
                "policy subject exceeds the {MAX_REVIEW_CHANGES}-change review bound"
            ),
            Self::TooManyFindings => write!(
                f,
                "policy subject exceeds the {MAX_REVIEW_FINDINGS}-finding review bound"
            ),
            Self::EmptyChangeKey => f.write_str("policy subject change key cannot be empty"),
            Self::DuplicateChangeKey(key) => {
                write!(f, "policy subject contains duplicate change key {key:?}")
            }
            Self::EmptyFindingCode => f.write_str("policy subject finding code cannot be empty"),
            Self::EmptyFindingMessage => {
                f.write_str("policy subject finding message cannot be empty")
            }
            Self::NoChangeContainsChanges => {
                f.write_str("no-change policy subject cannot contain planned changes")
            }
            Self::NoChangeHasNonReadOnlyRisk => {
                f.write_str("no-change policy subject must carry read-only prospective risk")
            }
            Self::ChangeProposedWithoutChanges => {
                f.write_str("change-proposed policy subject must contain a planned change")
            }
            Self::ChangeProposedIsReadOnly => {
                f.write_str("change-proposed policy subject cannot carry read-only risk")
            }
            Self::NonBlockedSubjectHasBlocker => {
                f.write_str("non-blocked policy subject cannot contain blocker findings")
            }
            Self::BlockedSubjectHasNoBlocker => {
                f.write_str("blocked policy subject must contain at least one blocker finding")
            }
        }
    }
}

impl std::error::Error for PolicySubjectValidationError {}

/// Transport/provider-neutral projection of the canonical reconciliation plan at
/// the policy boundary.
///
/// `linura-policy` deliberately does not depend on the planner crate. Linura
/// Control owns conversion from the canonical `ReconciliationPlan` into this
/// projection and binds the transport-authenticated principal at the same time.
/// The public SDK does not expose this internal authority type.
///
/// Rust sibling crates do not have friend visibility, so the cross-crate
/// constructor is public to the sole workspace consumer allowed by the layering
/// contract. Construction is therefore fallible and independently validates the
/// invariants policy relies on instead of trusting its caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySubject {
    principal: PrincipalId,
    plan_id: PlanId,
    request_id: RequestId,
    actor: Actor,
    provider: ProviderId,
    resource: ResourceId,
    capability: CapabilityId,
    reason: SemanticReason,
    observed_evidence_id: String,
    prospective_risk: RiskClass,
    status: ReviewPlanStatus,
    changes: Vec<ReviewedChange>,
    findings: Vec<ReviewedFinding>,
}

impl PolicySubject {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        principal: PrincipalId,
        plan_id: PlanId,
        request_id: RequestId,
        actor: Actor,
        provider: ProviderId,
        resource: ResourceId,
        capability: CapabilityId,
        reason: SemanticReason,
        observed_evidence_id: String,
        prospective_risk: RiskClass,
        status: ReviewPlanStatus,
        changes: Vec<ReviewedChange>,
        findings: Vec<ReviewedFinding>,
    ) -> Result<Self, PolicySubjectValidationError> {
        reason.validate().map_err(|error| {
            PolicySubjectValidationError::InvalidSemanticReason(error.to_string())
        })?;
        if observed_evidence_id.trim().is_empty() {
            return Err(PolicySubjectValidationError::EmptyEvidenceId);
        }
        if observed_evidence_id.len() > MAX_EVIDENCE_ID_BYTES {
            return Err(PolicySubjectValidationError::EvidenceIdTooLong);
        }
        if changes.len() > MAX_REVIEW_CHANGES {
            return Err(PolicySubjectValidationError::TooManyChanges);
        }
        if findings.len() > MAX_REVIEW_FINDINGS {
            return Err(PolicySubjectValidationError::TooManyFindings);
        }

        let mut change_keys = BTreeSet::new();
        for change in &changes {
            if change.key.trim().is_empty() {
                return Err(PolicySubjectValidationError::EmptyChangeKey);
            }
            if !change_keys.insert(change.key.as_str()) {
                return Err(PolicySubjectValidationError::DuplicateChangeKey(
                    change.key.clone(),
                ));
            }
        }

        for finding in &findings {
            if finding.code.trim().is_empty() {
                return Err(PolicySubjectValidationError::EmptyFindingCode);
            }
            if finding.message.trim().is_empty() {
                return Err(PolicySubjectValidationError::EmptyFindingMessage);
            }
        }

        let has_blocker = findings
            .iter()
            .any(|finding| finding.level == ReviewFindingLevel::Blocker);
        match status {
            ReviewPlanStatus::NoChange => {
                if !changes.is_empty() {
                    return Err(PolicySubjectValidationError::NoChangeContainsChanges);
                }
                if prospective_risk != RiskClass::ReadOnly {
                    return Err(PolicySubjectValidationError::NoChangeHasNonReadOnlyRisk);
                }
                if has_blocker {
                    return Err(PolicySubjectValidationError::NonBlockedSubjectHasBlocker);
                }
            }
            ReviewPlanStatus::ChangeProposed => {
                if changes.is_empty() {
                    return Err(PolicySubjectValidationError::ChangeProposedWithoutChanges);
                }
                if prospective_risk == RiskClass::ReadOnly {
                    return Err(PolicySubjectValidationError::ChangeProposedIsReadOnly);
                }
                if has_blocker {
                    return Err(PolicySubjectValidationError::NonBlockedSubjectHasBlocker);
                }
            }
            ReviewPlanStatus::Blocked => {
                if !has_blocker {
                    return Err(PolicySubjectValidationError::BlockedSubjectHasNoBlocker);
                }
            }
        }

        Ok(Self {
            principal,
            plan_id,
            request_id,
            actor,
            provider,
            resource,
            capability,
            reason,
            observed_evidence_id,
            prospective_risk,
            status,
            changes,
            findings,
        })
    }

    #[must_use]
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
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
    pub fn actor(&self) -> &Actor {
        &self.actor
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
    pub fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    #[must_use]
    pub fn reason(&self) -> &SemanticReason {
        &self.reason
    }

    #[must_use]
    pub fn observed_evidence_id(&self) -> &str {
        &self.observed_evidence_id
    }

    #[must_use]
    pub const fn prospective_risk(&self) -> RiskClass {
        self.prospective_risk
    }

    #[must_use]
    pub const fn status(&self) -> ReviewPlanStatus {
        self.status
    }

    #[must_use]
    pub fn changes(&self) -> &[ReviewedChange] {
        &self.changes
    }

    #[must_use]
    pub fn findings(&self) -> &[ReviewedFinding] {
        &self.findings
    }

    #[must_use]
    pub fn has_blockers(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.level == ReviewFindingLevel::Blocker)
    }
}

/// Identity binding for one policy evaluation.
///
/// v0.3 approval evidence must match this exact binding. The enclosing
/// `PolicyEvaluation` also retains the full `PolicySubject`, so material planned
/// changes/findings/provenance can be compared instead of relying on `PlanId`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewBinding {
    pub principal: PrincipalId,
    pub plan_id: PlanId,
    pub request_id: RequestId,
    pub observed_evidence_id: String,
    pub provider: ProviderId,
    pub resource: ResourceId,
    pub capability: CapabilityId,
    pub policy_id: PolicyId,
    pub policy_revision_id: PolicyRevisionId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Deny {
        reason: String,
    },
    RequireApproval {
        class: ApprovalClass,
        reason: String,
    },
    Blocked {
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyEvaluation {
    pub subject: PolicySubject,
    pub binding: ReviewBinding,
    pub decision: PolicyDecision,
}

pub trait PolicyEngine {
    fn snapshot(&self) -> &PolicySnapshot;
    fn evaluate_decision(&self, subject: &PolicySubject) -> PolicyDecision;

    #[must_use]
    fn evaluate(&self, subject: &PolicySubject) -> PolicyEvaluation {
        let snapshot = self.snapshot();
        PolicyEvaluation {
            subject: subject.clone(),
            binding: ReviewBinding {
                principal: subject.principal().clone(),
                plan_id: subject.plan_id().clone(),
                request_id: subject.request_id().clone(),
                observed_evidence_id: subject.observed_evidence_id().to_owned(),
                provider: subject.provider().clone(),
                resource: subject.resource().clone(),
                capability: subject.capability().clone(),
                policy_id: snapshot.policy_id.clone(),
                policy_revision_id: snapshot.revision_id.clone(),
            },
            decision: self.evaluate_decision(subject),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaselinePolicy {
    snapshot: PolicySnapshot,
}

impl Default for BaselinePolicy {
    fn default() -> Self {
        Self {
            snapshot: PolicySnapshot {
                policy_id: PolicyId::new("policy:baseline")
                    .unwrap_or_else(|error| unreachable!("{error}")),
                revision_id: PolicyRevisionId::new("policy:baseline:v1")
                    .unwrap_or_else(|error| unreachable!("{error}")),
            },
        }
    }
}

impl PolicyEngine for BaselinePolicy {
    fn snapshot(&self) -> &PolicySnapshot {
        &self.snapshot
    }

    fn evaluate_decision(&self, subject: &PolicySubject) -> PolicyDecision {
        if subject.status() == ReviewPlanStatus::Blocked || subject.has_blockers() {
            return PolicyDecision::Blocked {
                reason: "plan contains blockers and cannot enter approval review".into(),
            };
        }
        if subject.actor().kind == ActorKind::Remote {
            return PolicyDecision::Deny {
                reason: "remote actors are disabled in the initial profile".into(),
            };
        }

        let agent_proposal = subject.actor().kind == ActorKind::Agent;
        match subject.prospective_risk() {
            RiskClass::ReadOnly | RiskClass::UserState => PolicyDecision::Allow,
            RiskClass::SystemMutation => PolicyDecision::RequireApproval {
                class: ApprovalClass::InteractiveUser,
                reason: if agent_proposal {
                    "agent-proposed system mutation requires interactive approval"
                } else {
                    "system mutation requires interactive approval"
                }
                .into(),
            },
            RiskClass::SecuritySensitive => PolicyDecision::RequireApproval {
                class: ApprovalClass::Administrator,
                reason: if agent_proposal {
                    "agent-proposed security-sensitive mutation requires administrator approval"
                } else {
                    "security-sensitive mutation requires administrator approval"
                }
                .into(),
            },
            RiskClass::Destructive => PolicyDecision::RequireApproval {
                class: ApprovalClass::DestructiveAction,
                reason: if agent_proposal {
                    "agent-proposed destructive mutation requires dedicated destructive approval"
                } else {
                    "destructive mutation requires dedicated approval"
                }
                .into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{ActorId, IntentId, ValidationError};

    fn id<T>(result: Result<T, ValidationError>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn subject_result(
        kind: ActorKind,
        risk: RiskClass,
        status: ReviewPlanStatus,
    ) -> Result<PolicySubject, PolicySubjectValidationError> {
        let blocked = status == ReviewPlanStatus::Blocked;
        let changes = if status == ReviewPlanStatus::NoChange {
            vec![]
        } else {
            vec![ReviewedChange {
                key: "active_state".into(),
                current: Some("inactive".into()),
                desired: "active".into(),
            }]
        };
        PolicySubject::try_new(
            id(PrincipalId::new("uid:1000")),
            id(PlanId::new("plan:test")),
            id(RequestId::new("req:test")),
            Actor {
                id: id(ActorId::new("actor:test")),
                kind,
                interactive: kind == ActorKind::Human,
            },
            id(ProviderId::new("systemd")),
            id(ResourceId::new("systemd:unit:test.service")),
            id(CapabilityId::new("systemd.unit.observe")),
            SemanticReason {
                summary: "test intent".into(),
                intent_ids: vec![id(IntentId::new("intent:test"))],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
            "evidence:test".into(),
            risk,
            status,
            changes,
            if blocked {
                vec![ReviewedFinding {
                    code: "blocked".into(),
                    level: ReviewFindingLevel::Blocker,
                    message: "blocked for test".into(),
                }]
            } else {
                vec![]
            },
        )
    }

    fn subject(kind: ActorKind, risk: RiskClass, status: ReviewPlanStatus) -> PolicySubject {
        subject_result(kind, risk, status).unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[test]
    fn agent_system_mutation_requires_interactive_approval() {
        let policy = BaselinePolicy::default();
        let expected_subject = subject(
            ActorKind::Agent,
            RiskClass::SystemMutation,
            ReviewPlanStatus::ChangeProposed,
        );
        let evaluation = policy.evaluate(&expected_subject);
        assert!(matches!(
            evaluation.decision,
            PolicyDecision::RequireApproval {
                class: ApprovalClass::InteractiveUser,
                ..
            }
        ));
        assert_eq!(evaluation.subject, expected_subject);
        assert_eq!(evaluation.binding.principal.as_str(), "uid:1000");
        assert_eq!(evaluation.binding.observed_evidence_id, "evidence:test");
    }

    #[test]
    fn agent_security_sensitive_plan_keeps_administrator_approval() {
        let policy = BaselinePolicy::default();
        let evaluation = policy.evaluate(&subject(
            ActorKind::Agent,
            RiskClass::SecuritySensitive,
            ReviewPlanStatus::ChangeProposed,
        ));
        assert!(matches!(
            evaluation.decision,
            PolicyDecision::RequireApproval {
                class: ApprovalClass::Administrator,
                ..
            }
        ));
    }

    #[test]
    fn agent_destructive_plan_keeps_destructive_approval() {
        let policy = BaselinePolicy::default();
        let evaluation = policy.evaluate(&subject(
            ActorKind::Agent,
            RiskClass::Destructive,
            ReviewPlanStatus::ChangeProposed,
        ));
        assert!(matches!(
            evaluation.decision,
            PolicyDecision::RequireApproval {
                class: ApprovalClass::DestructiveAction,
                ..
            }
        ));
    }

    #[test]
    fn remote_is_denied() {
        let policy = BaselinePolicy::default();
        let evaluation = policy.evaluate(&subject(
            ActorKind::Remote,
            RiskClass::ReadOnly,
            ReviewPlanStatus::NoChange,
        ));
        assert!(matches!(evaluation.decision, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn blocked_plan_cannot_be_approved() {
        let policy = BaselinePolicy::default();
        let evaluation = policy.evaluate(&subject(
            ActorKind::Human,
            RiskClass::SystemMutation,
            ReviewPlanStatus::Blocked,
        ));
        assert!(matches!(
            evaluation.decision,
            PolicyDecision::Blocked { .. }
        ));
    }

    #[test]
    fn read_only_change_proposal_is_rejected_at_construction() {
        let result = subject_result(
            ActorKind::Human,
            RiskClass::ReadOnly,
            ReviewPlanStatus::ChangeProposed,
        );
        assert!(matches!(
            result,
            Err(PolicySubjectValidationError::ChangeProposedIsReadOnly)
        ));
    }

    #[test]
    fn empty_evidence_is_rejected_at_construction() {
        let mut subject = subject(
            ActorKind::Human,
            RiskClass::SystemMutation,
            ReviewPlanStatus::ChangeProposed,
        );
        subject.observed_evidence_id.clear();
        let result = PolicySubject::try_new(
            subject.principal,
            subject.plan_id,
            subject.request_id,
            subject.actor,
            subject.provider,
            subject.resource,
            subject.capability,
            subject.reason,
            subject.observed_evidence_id,
            subject.prospective_risk,
            subject.status,
            subject.changes,
            subject.findings,
        );
        assert!(matches!(
            result,
            Err(PolicySubjectValidationError::EmptyEvidenceId)
        ));
    }

    #[test]
    fn blocked_status_requires_a_blocker() {
        let mut subject = subject(
            ActorKind::Human,
            RiskClass::SystemMutation,
            ReviewPlanStatus::ChangeProposed,
        );
        subject.status = ReviewPlanStatus::Blocked;
        let result = PolicySubject::try_new(
            subject.principal,
            subject.plan_id,
            subject.request_id,
            subject.actor,
            subject.provider,
            subject.resource,
            subject.capability,
            subject.reason,
            subject.observed_evidence_id,
            subject.prospective_risk,
            subject.status,
            subject.changes,
            subject.findings,
        );
        assert!(matches!(
            result,
            Err(PolicySubjectValidationError::BlockedSubjectHasNoBlocker)
        ));
    }
}
