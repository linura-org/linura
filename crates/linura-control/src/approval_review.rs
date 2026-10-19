use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::atomic::{AtomicU64 as AuthorityAtomicU64, Ordering as AuthorityOrdering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::approval::{
    ApprovalEvidence, ApprovalIssueError, ApprovalRequirement, ApprovalRevocation,
    ApprovalValidation, AuthenticatedApprover, MAX_APPROVAL_TTL_SECONDS, validate_approval,
};
use crate::policy_review::TrustedPolicyReview;
use linura_core::{ApprovalEvidenceId, ApprovalRequestId, ValidationError};
use linura_policy::{ApprovalClass, PolicyDecision, PolicyEvaluation};

pub const MAX_APPROVAL_ENTRIES: usize = 256;
pub const MAX_APPROVAL_ENTRY_BYTES: usize = 256 * 1024;
pub const MAX_APPROVAL_TOTAL_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_APPROVAL_TOMBSTONES: usize = 4096;
pub const MAX_APPROVAL_TOMBSTONE_BYTES: usize = 2 * 1024 * 1024;
pub const APPROVAL_TOMBSTONE_RETENTION_SECONDS: u64 = MAX_APPROVAL_TTL_SECONDS;
const APPROVAL_RECORD_OVERHEAD_BYTES: usize = 256;
const APPROVAL_TOMBSTONE_OVERHEAD_BYTES: usize = 64;

pub type PolicyApprovalRequirement = ApprovalRequirement<PolicyEvaluation, ApprovalClass>;
pub type PolicyApprovalEvidence = ApprovalEvidence<PolicyEvaluation, ApprovalClass>;
pub type PolicyAuthenticatedApprover = AuthenticatedApprover<ApprovalClass>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalRequirementError {
    NotRequired,
    NotApprovable,
}

fn required_approval_class(
    review: &TrustedPolicyReview,
) -> Result<ApprovalClass, ApprovalRequirementError> {
    match review.decision() {
        PolicyDecision::RequireApproval { class, .. } => Ok(*class),
        PolicyDecision::Allow => Err(ApprovalRequirementError::NotRequired),
        PolicyDecision::Deny { .. } | PolicyDecision::Blocked { .. } => {
            Err(ApprovalRequirementError::NotApprovable)
        }
    }
}

fn approval_requirement_from_review(
    review: &TrustedPolicyReview,
    class: ApprovalClass,
) -> PolicyApprovalRequirement {
    ApprovalRequirement::new(class, review.evaluation().clone())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyApprovalIssueError {
    Requirement(ApprovalRequirementError),
    Evidence(ApprovalIssueError<ApprovalClass>),
}

fn validate_policy_approval(
    evidence: &PolicyApprovalEvidence,
    review: &TrustedPolicyReview,
    now_unix_seconds: u64,
    revocation: Option<&ApprovalRevocation>,
) -> ApprovalValidation {
    let Ok(class) = required_approval_class(review) else {
        return ApprovalValidation::BindingMismatch;
    };
    validate_approval(
        evidence,
        review.evaluation(),
        &class,
        now_unix_seconds,
        revocation,
    )
}

fn add_len(total: &mut usize, value: &str) {
    *total = total.saturating_add(value.len());
}

/// Deterministic upper-accounting estimate for one retained policy evaluation.
/// It borrows the trusted review and must run before any retained evaluation is
/// cloned, so hostile oversized review material cannot force a second large
/// allocation before the per-entry bound is enforced.
fn approval_binding_bytes(evaluation: &PolicyEvaluation) -> usize {
    let subject = &evaluation.subject;
    let mut bytes = 0usize;

    add_len(&mut bytes, subject.principal().as_str());
    add_len(&mut bytes, subject.plan_id().as_str());
    add_len(&mut bytes, subject.request_id().as_str());
    add_len(&mut bytes, subject.actor().id.as_str());
    add_len(&mut bytes, subject.provider().as_str());
    add_len(&mut bytes, subject.resource().as_str());
    add_len(&mut bytes, subject.capability().as_str());
    add_len(&mut bytes, subject.observed_evidence_id());
    add_len(&mut bytes, &subject.reason().summary);
    for id in &subject.reason().intent_ids {
        add_len(&mut bytes, id.as_str());
    }
    for id in &subject.reason().requirement_ids {
        add_len(&mut bytes, id.as_str());
    }
    for id in &subject.reason().capability_ids {
        add_len(&mut bytes, id.as_str());
    }
    for change in subject.changes() {
        add_len(&mut bytes, &change.key);
        if let Some(current) = &change.current {
            add_len(&mut bytes, current);
        }
        add_len(&mut bytes, &change.desired);
    }
    for finding in subject.findings() {
        add_len(&mut bytes, &finding.code);
        add_len(&mut bytes, &finding.message);
    }

    add_len(&mut bytes, evaluation.binding.principal.as_str());
    add_len(&mut bytes, evaluation.binding.plan_id.as_str());
    add_len(&mut bytes, evaluation.binding.request_id.as_str());
    add_len(&mut bytes, &evaluation.binding.observed_evidence_id);
    add_len(&mut bytes, evaluation.binding.provider.as_str());
    add_len(&mut bytes, evaluation.binding.resource.as_str());
    add_len(&mut bytes, evaluation.binding.capability.as_str());
    add_len(&mut bytes, evaluation.binding.policy_id.as_str());
    add_len(&mut bytes, evaluation.binding.policy_revision_id.as_str());
    match &evaluation.decision {
        PolicyDecision::Allow => {}
        PolicyDecision::Deny { reason }
        | PolicyDecision::RequireApproval { reason, .. }
        | PolicyDecision::Blocked { reason } => add_len(&mut bytes, reason),
    }
    bytes
}

fn approval_tombstone_bytes(request_id: &ApprovalRequestId) -> usize {
    request_id
        .as_str()
        .len()
        .saturating_add(APPROVAL_TOMBSTONE_OVERHEAD_BYTES)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ApprovalRecord {
    evidence: PolicyApprovalEvidence,
    revocation: Option<ApprovalRevocation>,
    accounted_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ApprovalTombstone {
    retired_at_unix_seconds: u64,
    accounted_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalControlError {
    Issue(PolicyApprovalIssueError),
    InvalidEvidenceId(ValidationError),
    IdempotencyConflict,
    CapacityExceeded,
    EntryTooLarge,
    TotalCapacityExceeded,
    TombstoneCapacityExceeded,
    TombstoneTotalCapacityExceeded,
    SequenceExhausted,
    EvidenceNotFound,
    RevokerNotAuthorized,
    ClockUnavailable,
    ClockRollback,
}

trait ApprovalClock: Debug + Send + Sync {
    fn now_unix_seconds(&self) -> Result<u64, ApprovalControlError>;
}

#[derive(Debug, Default)]
struct SystemApprovalClock;

impl ApprovalClock for SystemApprovalClock {
    fn now_unix_seconds(&self) -> Result<u64, ApprovalControlError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| ApprovalControlError::ClockUnavailable)
    }
}

/// Bounded, process-local v0.3 approval lifecycle.
///
/// The store deliberately has no persistence, prepare record, executor handle,
/// or crash-recovery claim. Exact live retries return the original evidence;
/// request-ID reuse after evidence becomes inactive is rejected while a bounded
/// replay tombstone is retained. Expired/revoked records are reclaimed before
/// live-capacity checks, so inactive authority does not permanently consume the
/// live approval budget. Live authority evidence is never silently evicted.
#[derive(Debug)]
pub struct ApprovalReviewControl {
    clock: Box<dyn ApprovalClock>,
    last_authority_unix_seconds: AuthorityAtomicU64,
    records: BTreeMap<ApprovalEvidenceId, ApprovalRecord>,
    requests: BTreeMap<ApprovalRequestId, ApprovalEvidenceId>,
    tombstones: BTreeMap<ApprovalRequestId, ApprovalTombstone>,
    next_evidence_sequence: u64,
    total_accounted_bytes: usize,
    tombstone_accounted_bytes: usize,
}

impl Default for ApprovalReviewControl {
    fn default() -> Self {
        Self::with_clock(Box::new(SystemApprovalClock))
    }
}

impl ApprovalReviewControl {
    fn with_clock(clock: Box<dyn ApprovalClock>) -> Self {
        Self {
            clock,
            last_authority_unix_seconds: AuthorityAtomicU64::new(0),
            records: BTreeMap::new(),
            requests: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            next_evidence_sequence: 0,
            total_accounted_bytes: 0,
            tombstone_accounted_bytes: 0,
        }
    }

    fn authority_now_unix_seconds(&self) -> Result<u64, ApprovalControlError> {
        let sampled = self.clock.now_unix_seconds()?;
        let previous = self
            .last_authority_unix_seconds
            .fetch_max(sampled, AuthorityOrdering::SeqCst);
        if sampled < previous {
            return Err(ApprovalControlError::ClockRollback);
        }
        Ok(sampled)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    #[must_use]
    pub fn tombstone_len(&self) -> usize {
        self.tombstones.len()
    }

    #[must_use]
    pub const fn total_accounted_bytes(&self) -> usize {
        self.total_accounted_bytes
    }

    #[must_use]
    pub const fn tombstone_accounted_bytes(&self) -> usize {
        self.tombstone_accounted_bytes
    }

    fn prune_tombstones(&mut self, now_unix_seconds: u64) {
        let expired = self
            .tombstones
            .iter()
            .filter(|(_, tombstone)| {
                tombstone
                    .retired_at_unix_seconds
                    .saturating_add(APPROVAL_TOMBSTONE_RETENTION_SECONDS)
                    <= now_unix_seconds
            })
            .map(|(request_id, _)| request_id.clone())
            .collect::<Vec<_>>();

        for request_id in expired {
            if let Some(tombstone) = self.tombstones.remove(&request_id) {
                self.tombstone_accounted_bytes = self
                    .tombstone_accounted_bytes
                    .saturating_sub(tombstone.accounted_bytes);
            }
        }
    }

    fn reclaim_inactive(&mut self, now_unix_seconds: u64) -> Result<(), ApprovalControlError> {
        self.prune_tombstones(now_unix_seconds);

        let candidates = self
            .records
            .iter()
            .filter(|(_, record)| {
                record.revocation.is_some()
                    || record.evidence.expires_at_unix_seconds() <= now_unix_seconds
            })
            .map(|(evidence_id, record)| {
                (
                    evidence_id.clone(),
                    record.evidence.request_id().clone(),
                    approval_tombstone_bytes(record.evidence.request_id()),
                )
            })
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return Ok(());
        }

        let new_tombstone_count = self
            .tombstones
            .len()
            .checked_add(candidates.len())
            .ok_or(ApprovalControlError::TombstoneCapacityExceeded)?;
        if new_tombstone_count > MAX_APPROVAL_TOMBSTONES {
            return Err(ApprovalControlError::TombstoneCapacityExceeded);
        }

        let candidate_bytes = candidates.iter().try_fold(0usize, |total, (_, _, bytes)| {
            total
                .checked_add(*bytes)
                .ok_or(ApprovalControlError::TombstoneTotalCapacityExceeded)
        })?;
        let new_tombstone_bytes = self
            .tombstone_accounted_bytes
            .checked_add(candidate_bytes)
            .ok_or(ApprovalControlError::TombstoneTotalCapacityExceeded)?;
        if new_tombstone_bytes > MAX_APPROVAL_TOMBSTONE_BYTES {
            return Err(ApprovalControlError::TombstoneTotalCapacityExceeded);
        }

        for (evidence_id, request_id, accounted_bytes) in candidates {
            if let Some(record) = self.records.remove(&evidence_id) {
                self.requests.remove(&request_id);
                self.total_accounted_bytes = self
                    .total_accounted_bytes
                    .saturating_sub(record.accounted_bytes);
                self.tombstones.insert(
                    request_id,
                    ApprovalTombstone {
                        retired_at_unix_seconds: now_unix_seconds,
                        accounted_bytes,
                    },
                );
                self.tombstone_accounted_bytes = self
                    .tombstone_accounted_bytes
                    .saturating_add(accounted_bytes);
            }
        }

        Ok(())
    }

    /// Issue approval evidence using Control-owned current time.
    ///
    /// The caller may request an absolute expiry, but cannot supply the
    /// authority clock used for issuance, reclamation, validation, revocation,
    /// or replay-tombstone pruning.
    pub fn issue(
        &mut self,
        request_id: ApprovalRequestId,
        review: &TrustedPolicyReview,
        approver: &PolicyAuthenticatedApprover,
        expires_at_unix_seconds: u64,
    ) -> Result<PolicyApprovalEvidence, ApprovalControlError> {
        let issued_at_unix_seconds = self.authority_now_unix_seconds()?;
        self.issue_at(
            request_id,
            review,
            approver,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
        )
    }

    fn issue_at(
        &mut self,
        request_id: ApprovalRequestId,
        review: &TrustedPolicyReview,
        approver: &PolicyAuthenticatedApprover,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<PolicyApprovalEvidence, ApprovalControlError> {
        self.reclaim_inactive(issued_at_unix_seconds)?;

        if self.tombstones.contains_key(&request_id) {
            return Err(ApprovalControlError::IdempotencyConflict);
        }

        let class = required_approval_class(review).map_err(|error| {
            ApprovalControlError::Issue(PolicyApprovalIssueError::Requirement(error))
        })?;

        if let Some(existing_id) = self.requests.get(&request_id) {
            let Some(existing) = self.records.get(existing_id) else {
                return Err(ApprovalControlError::IdempotencyConflict);
            };
            if existing.evidence.requirement().binding() == review.evaluation()
                && existing.evidence.requirement().class() == &class
                && existing.evidence.approver() == approver.principal()
                && existing.evidence.expires_at_unix_seconds() == expires_at_unix_seconds
            {
                return Ok(existing.evidence.clone());
            }
            return Err(ApprovalControlError::IdempotencyConflict);
        }

        // Enforce the borrowed-input bound before constructing an approval
        // requirement, because requirement construction clones the evaluation.
        let accounted_bytes = approval_binding_bytes(review.evaluation())
            .saturating_add(request_id.as_str().len())
            .saturating_add(approver.principal().as_str().len())
            .saturating_add(APPROVAL_RECORD_OVERHEAD_BYTES);
        if accounted_bytes > MAX_APPROVAL_ENTRY_BYTES {
            return Err(ApprovalControlError::EntryTooLarge);
        }

        if self.records.len() >= MAX_APPROVAL_ENTRIES {
            return Err(ApprovalControlError::CapacityExceeded);
        }

        let new_total = self
            .total_accounted_bytes
            .checked_add(accounted_bytes)
            .ok_or(ApprovalControlError::TotalCapacityExceeded)?;
        if new_total > MAX_APPROVAL_TOTAL_BYTES {
            return Err(ApprovalControlError::TotalCapacityExceeded);
        }

        let evidence_id = ApprovalEvidenceId::new(format!(
            "approval:evidence:{:016x}",
            self.next_evidence_sequence
        ))
        .map_err(ApprovalControlError::InvalidEvidenceId)?;
        self.next_evidence_sequence = self
            .next_evidence_sequence
            .checked_add(1)
            .ok_or(ApprovalControlError::SequenceExhausted)?;

        let requirement = approval_requirement_from_review(review, class);
        let evidence = ApprovalEvidence::try_issue(
            evidence_id.clone(),
            request_id.clone(),
            requirement,
            approver,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
        )
        .map_err(|error| ApprovalControlError::Issue(PolicyApprovalIssueError::Evidence(error)))?;

        self.requests.insert(request_id, evidence_id.clone());
        self.records.insert(
            evidence_id,
            ApprovalRecord {
                evidence: evidence.clone(),
                revocation: None,
                accounted_bytes,
            },
        );
        self.total_accounted_bytes = new_total;
        Ok(evidence)
    }

    /// Validate retained approval against Control-owned current time and
    /// authoritative revocation state.
    pub fn validate(
        &self,
        evidence_id: &ApprovalEvidenceId,
        review: &TrustedPolicyReview,
    ) -> Result<ApprovalValidation, ApprovalControlError> {
        let now_unix_seconds = self.authority_now_unix_seconds()?;
        Ok(self.validate_at(evidence_id, review, now_unix_seconds))
    }

    fn validate_at(
        &self,
        evidence_id: &ApprovalEvidenceId,
        review: &TrustedPolicyReview,
        now_unix_seconds: u64,
    ) -> ApprovalValidation {
        let Some(record) = self.records.get(evidence_id) else {
            return ApprovalValidation::BindingMismatch;
        };
        validate_policy_approval(
            &record.evidence,
            review,
            now_unix_seconds,
            record.revocation.as_ref(),
        )
    }

    /// Revoke retained approval using Control-owned current time.
    pub fn revoke(
        &mut self,
        evidence_id: &ApprovalEvidenceId,
        revoker: &PolicyAuthenticatedApprover,
    ) -> Result<(), ApprovalControlError> {
        let revoked_at_unix_seconds = self.authority_now_unix_seconds()?;
        self.revoke_at(evidence_id, revoker, revoked_at_unix_seconds)
    }

    fn revoke_at(
        &mut self,
        evidence_id: &ApprovalEvidenceId,
        revoker: &PolicyAuthenticatedApprover,
        revoked_at_unix_seconds: u64,
    ) -> Result<(), ApprovalControlError> {
        let Some(record) = self.records.get_mut(evidence_id) else {
            return Err(ApprovalControlError::EvidenceNotFound);
        };
        if !revoker.can_satisfy(*record.evidence.requirement().class()) {
            return Err(ApprovalControlError::RevokerNotAuthorized);
        }
        if record.revocation.is_none() {
            record.revocation = Some(ApprovalRevocation::new(
                revoker.principal().clone(),
                revoked_at_unix_seconds,
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn get(&self, evidence_id: &ApprovalEvidenceId) -> Option<&PolicyApprovalEvidence> {
        self.records.get(evidence_id).map(|record| &record.evidence)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use linura_core::{
        Actor, ActorId, ActorKind, CapabilityId, IntentId, PlanId, PrincipalId, ProviderId,
        RequestId, ResourceId, RiskClass, SemanticReason, ValidationError,
    };
    use linura_policy::{
        ApprovalClass, PolicyDecision, PolicySubject, ReviewFindingLevel, ReviewPlanStatus,
        ReviewedChange, ReviewedFinding,
    };

    use super::*;
    use crate::policy_review::review_subject_for_control;

    fn id<T>(result: Result<T, ValidationError>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[derive(Clone, Debug)]
    struct TestClock {
        now_unix_seconds: Arc<AtomicU64>,
    }

    impl TestClock {
        fn new(now_unix_seconds: u64) -> Self {
            Self {
                now_unix_seconds: Arc::new(AtomicU64::new(now_unix_seconds)),
            }
        }

        fn set(&self, now_unix_seconds: u64) {
            self.now_unix_seconds
                .store(now_unix_seconds, Ordering::SeqCst);
        }
    }

    impl ApprovalClock for TestClock {
        fn now_unix_seconds(&self) -> Result<u64, ApprovalControlError> {
            Ok(self.now_unix_seconds.load(Ordering::SeqCst))
        }
    }

    fn control_with_clock(now_unix_seconds: u64) -> (ApprovalReviewControl, TestClock) {
        let clock = TestClock::new(now_unix_seconds);
        let control = ApprovalReviewControl::with_clock(Box::new(clock.clone()));
        (control, clock)
    }

    fn review_with(
        risk: RiskClass,
        status: ReviewPlanStatus,
        desired: String,
        plan_id: &str,
    ) -> TrustedPolicyReview {
        let blocked = status == ReviewPlanStatus::Blocked;
        let changes = if status == ReviewPlanStatus::NoChange {
            vec![]
        } else {
            vec![ReviewedChange {
                key: "active_state".into(),
                current: Some("inactive".into()),
                desired,
            }]
        };
        let findings = if blocked {
            vec![ReviewedFinding {
                code: "test-blocker".into(),
                level: ReviewFindingLevel::Blocker,
                message: "blocked for approval test".into(),
            }]
        } else {
            vec![]
        };
        let subject = PolicySubject::try_new(
            id(PrincipalId::new("uid:1000")),
            id(PlanId::new(plan_id)),
            id(RequestId::new(format!("request:{plan_id}"))),
            Actor {
                id: id(ActorId::new("actor:approval-control")),
                kind: ActorKind::Human,
                interactive: true,
            },
            id(ProviderId::new("systemd")),
            id(ResourceId::new("systemd:unit:test.service")),
            id(CapabilityId::new("systemd.unit.observe")),
            SemanticReason {
                summary: "review approval binding".into(),
                intent_ids: vec![id(IntentId::new("intent:approval-control"))],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
            "evidence:approval-control".into(),
            risk,
            status,
            changes,
            findings,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        review_subject_for_control(subject)
    }

    fn review(risk: RiskClass) -> TrustedPolicyReview {
        review_with(
            risk,
            ReviewPlanStatus::ChangeProposed,
            "active".into(),
            "plan:approval-control",
        )
    }

    fn admin() -> PolicyAuthenticatedApprover {
        PolicyAuthenticatedApprover::new(
            id(PrincipalId::new("uid:0")),
            ActorKind::Human,
            BTreeSet::from([ApprovalClass::Administrator]),
        )
    }

    #[test]
    fn session_owner_authentication_is_not_an_administrator_or_destructive_grant() {
        let owner = PolicyAuthenticatedApprover::new(
            id(PrincipalId::new("unix:uid:1000")),
            ActorKind::Human,
            BTreeSet::from([ApprovalClass::SessionOwnerAuthentication]),
        );
        assert!(owner.can_satisfy(ApprovalClass::SessionOwnerAuthentication));
        for class in [
            ApprovalClass::Administrator,
            ApprovalClass::DestructiveAction,
            ApprovalClass::InteractiveUser,
        ] {
            assert!(!owner.can_satisfy(class));
        }
        assert!(!admin().can_satisfy(ApprovalClass::SessionOwnerAuthentication));
        let agent = PolicyAuthenticatedApprover::new(
            id(PrincipalId::new("unix:uid:1000")),
            ActorKind::Agent,
            BTreeSet::from([ApprovalClass::SessionOwnerAuthentication]),
        );
        assert!(!agent.can_satisfy(ApprovalClass::SessionOwnerAuthentication));
    }

    #[test]
    fn exact_trusted_review_is_the_approval_binding() {
        let review = review(RiskClass::SecuritySensitive);
        let changed = review_with(
            RiskClass::SecuritySensitive,
            ReviewPlanStatus::ChangeProposed,
            "active".into(),
            "plan:approval-control-changed",
        );
        let mut control = ApprovalReviewControl::default();
        let evidence = control
            .issue_at(
                id(ApprovalRequestId::new("approval:request:control")),
                &review,
                &admin(),
                100,
                200,
            )
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(
            control.validate_at(evidence.id(), &review, 150),
            ApprovalValidation::Satisfied
        );
        assert_eq!(
            control.validate_at(evidence.id(), &changed, 150),
            ApprovalValidation::BindingMismatch
        );
    }

    #[test]
    fn forged_policy_evaluation_cannot_weaken_trusted_review() {
        let review = review(RiskClass::SecuritySensitive);
        let mut forged = review.evaluation().clone();
        forged.decision = PolicyDecision::RequireApproval {
            class: ApprovalClass::InteractiveUser,
            reason: "forged weaker approval".into(),
        };
        assert!(matches!(
            forged.decision,
            PolicyDecision::RequireApproval {
                class: ApprovalClass::InteractiveUser,
                ..
            }
        ));

        let weak = PolicyAuthenticatedApprover::new(
            id(PrincipalId::new("uid:1001")),
            ActorKind::Human,
            BTreeSet::from([ApprovalClass::InteractiveUser]),
        );
        let mut control = ApprovalReviewControl::default();
        assert!(matches!(
            control.issue_at(
                id(ApprovalRequestId::new("approval:request:forged")),
                &review,
                &weak,
                100,
                200,
            ),
            Err(ApprovalControlError::Issue(
                PolicyApprovalIssueError::Evidence(ApprovalIssueError::MissingApprovalClass(
                    ApprovalClass::Administrator
                ))
            ))
        ));
    }

    #[test]
    fn weak_approver_cannot_satisfy_security_sensitive_requirement() {
        let review = review(RiskClass::SecuritySensitive);
        let weak = PolicyAuthenticatedApprover::new(
            id(PrincipalId::new("uid:1001")),
            ActorKind::Human,
            BTreeSet::from([ApprovalClass::InteractiveUser]),
        );
        let mut control = ApprovalReviewControl::default();
        assert!(matches!(
            control.issue_at(
                id(ApprovalRequestId::new("approval:request:weak-control")),
                &review,
                &weak,
                100,
                200,
            ),
            Err(ApprovalControlError::Issue(
                PolicyApprovalIssueError::Evidence(ApprovalIssueError::MissingApprovalClass(
                    ApprovalClass::Administrator
                ))
            ))
        ));
    }

    #[test]
    fn blocked_and_allowed_reviews_cannot_be_minted_as_approval() {
        let blocked = review_with(
            RiskClass::SecuritySensitive,
            ReviewPlanStatus::Blocked,
            "active".into(),
            "plan:blocked",
        );
        assert_eq!(
            required_approval_class(&blocked),
            Err(ApprovalRequirementError::NotApprovable)
        );

        let allowed = review_with(
            RiskClass::ReadOnly,
            ReviewPlanStatus::NoChange,
            String::new(),
            "plan:allowed",
        );
        assert_eq!(
            required_approval_class(&allowed),
            Err(ApprovalRequirementError::NotRequired)
        );
    }

    #[test]
    fn process_local_issue_is_idempotent_and_conflicts_fail_closed() {
        let review = review(RiskClass::SecuritySensitive);
        let request = id(ApprovalRequestId::new("approval:request:idempotent"));
        let mut control = ApprovalReviewControl::default();
        let first = control
            .issue_at(request.clone(), &review, &admin(), 100, 200)
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        let retry = control
            .issue_at(request.clone(), &review, &admin(), 100, 200)
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(first, retry);
        assert_eq!(control.len(), 1);
        assert_eq!(
            control.issue_at(request, &review, &admin(), 100, 201),
            Err(ApprovalControlError::IdempotencyConflict)
        );
    }

    #[test]
    fn revocation_is_authoritative_even_when_evidence_was_cloned() {
        let review = review(RiskClass::SecuritySensitive);
        let mut control = ApprovalReviewControl::default();
        let evidence = control
            .issue_at(
                id(ApprovalRequestId::new("approval:request:revoke")),
                &review,
                &admin(),
                100,
                200,
            )
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        let stolen_clone = evidence.clone();
        assert_eq!(
            control.validate_at(stolen_clone.id(), &review, 150),
            ApprovalValidation::Satisfied
        );
        control
            .revoke_at(evidence.id(), &admin(), 151)
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(
            control.validate_at(stolen_clone.id(), &review, 152),
            ApprovalValidation::Revoked
        );
    }

    #[test]
    fn unqualified_revoker_is_rejected() {
        let review = review(RiskClass::SecuritySensitive);
        let mut control = ApprovalReviewControl::default();
        let evidence = control
            .issue_at(
                id(ApprovalRequestId::new("approval:request:revoker")),
                &review,
                &admin(),
                100,
                200,
            )
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        let weak = PolicyAuthenticatedApprover::new(
            id(PrincipalId::new("uid:1001")),
            ActorKind::Human,
            BTreeSet::from([ApprovalClass::InteractiveUser]),
        );
        assert_eq!(
            control.revoke_at(evidence.id(), &weak, 150),
            Err(ApprovalControlError::RevokerNotAuthorized)
        );
    }

    #[test]
    fn oversized_review_is_rejected_before_retained_clone() {
        let review = review_with(
            RiskClass::SecuritySensitive,
            ReviewPlanStatus::ChangeProposed,
            "x".repeat(MAX_APPROVAL_ENTRY_BYTES),
            "plan:oversized",
        );
        let mut control = ApprovalReviewControl::default();
        assert_eq!(
            control.issue_at(
                id(ApprovalRequestId::new("approval:request:oversized")),
                &review,
                &admin(),
                100,
                200,
            ),
            Err(ApprovalControlError::EntryTooLarge)
        );
        assert!(control.is_empty());
        assert_eq!(control.total_accounted_bytes(), 0);
    }

    #[test]
    fn expired_records_are_reclaimed_and_request_replay_stays_blocked() {
        let review = review(RiskClass::SecuritySensitive);
        let mut control = ApprovalReviewControl::default();
        for index in 0..MAX_APPROVAL_ENTRIES {
            let request = id(ApprovalRequestId::new(format!(
                "approval:request:capacity:{index}"
            )));
            let _ = control
                .issue_at(request, &review, &admin(), 100, 101)
                .unwrap_or_else(|error| unreachable!("{error:?}"));
        }
        assert_eq!(control.len(), MAX_APPROVAL_ENTRIES);

        let _ = control
            .issue_at(
                id(ApprovalRequestId::new("approval:request:after-reclaim")),
                &review,
                &admin(),
                102,
                200,
            )
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(control.len(), 1);
        assert_eq!(control.tombstone_len(), MAX_APPROVAL_ENTRIES);
        assert!(control.tombstone_accounted_bytes() <= MAX_APPROVAL_TOMBSTONE_BYTES);

        assert_eq!(
            control.issue_at(
                id(ApprovalRequestId::new("approval:request:capacity:0")),
                &review,
                &admin(),
                102,
                200,
            ),
            Err(ApprovalControlError::IdempotencyConflict)
        );
    }

    #[test]
    fn revoked_records_are_reclaimed_without_reopening_request_id() {
        let review = review(RiskClass::SecuritySensitive);
        let request = id(ApprovalRequestId::new("approval:request:reclaimed-revoked"));
        let mut control = ApprovalReviewControl::default();
        let evidence = control
            .issue_at(request.clone(), &review, &admin(), 100, 200)
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        control
            .revoke_at(evidence.id(), &admin(), 120)
            .unwrap_or_else(|error| unreachable!("{error:?}"));

        let _ = control
            .issue_at(
                id(ApprovalRequestId::new("approval:request:reclaim-trigger")),
                &review,
                &admin(),
                121,
                200,
            )
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert!(control.get(evidence.id()).is_none());
        assert_eq!(
            control.issue_at(request, &review, &admin(), 121, 200),
            Err(ApprovalControlError::IdempotencyConflict)
        );
    }

    #[test]
    fn tombstone_retention_is_bounded_and_deterministically_pruned() {
        let review = review(RiskClass::SecuritySensitive);
        let request = id(ApprovalRequestId::new("approval:request:tombstone-window"));
        let mut control = ApprovalReviewControl::default();
        let _ = control
            .issue_at(request.clone(), &review, &admin(), 100, 101)
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        let _ = control
            .issue_at(
                id(ApprovalRequestId::new("approval:request:tombstone-trigger")),
                &review,
                &admin(),
                102,
                200,
            )
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(control.tombstone_len(), 1);

        let after_retention = 102 + APPROVAL_TOMBSTONE_RETENTION_SECONDS;
        let _ = control
            .issue_at(
                request,
                &review,
                &admin(),
                after_retention,
                after_retention + 1,
            )
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(control.tombstone_len(), 1);
    }

    #[test]
    fn public_authority_api_uses_control_owned_time() {
        let review = review(RiskClass::SecuritySensitive);
        let request = id(ApprovalRequestId::new("approval:request:authority-clock"));
        let (mut control, clock) = control_with_clock(100);

        let evidence = control
            .issue(request.clone(), &review, &admin(), 200)
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(evidence.issued_at_unix_seconds(), 100);
        assert_eq!(evidence.expires_at_unix_seconds(), 200);

        clock.set(101);
        let retry = control
            .issue(request.clone(), &review, &admin(), 200)
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(retry, evidence);

        clock.set(150);
        assert_eq!(
            control.validate(evidence.id(), &review),
            Ok(ApprovalValidation::Satisfied)
        );

        clock.set(200);
        assert_eq!(
            control.validate(evidence.id(), &review),
            Ok(ApprovalValidation::Expired)
        );

        let _ = control
            .issue_at(
                id(ApprovalRequestId::new(
                    "approval:request:authority-clock-trigger",
                )),
                &review,
                &admin(),
                200,
                250,
            )
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert!(control.get(evidence.id()).is_none());
        assert_eq!(
            control.issue_at(request, &review, &admin(), 200, 250),
            Err(ApprovalControlError::IdempotencyConflict)
        );
    }

    #[test]
    fn authority_clock_rollback_cannot_revive_expired_evidence() {
        let review = review(RiskClass::SecuritySensitive);
        let request = id(ApprovalRequestId::new("approval:request:clock-rollback"));
        let (mut control, clock) = control_with_clock(100);
        let evidence = control
            .issue(request, &review, &admin(), 200)
            .unwrap_or_else(|error| unreachable!("{error:?}"));

        clock.set(200);
        assert_eq!(
            control.validate(evidence.id(), &review),
            Ok(ApprovalValidation::Expired)
        );

        clock.set(150);
        assert_eq!(
            control.validate(evidence.id(), &review),
            Err(ApprovalControlError::ClockRollback)
        );
        assert_eq!(
            control.issue(
                id(ApprovalRequestId::new(
                    "approval:request:clock-rollback-new"
                )),
                &review,
                &admin(),
                250,
            ),
            Err(ApprovalControlError::ClockRollback)
        );
    }

    #[test]
    fn retained_bytes_are_bounded_and_idempotent_retry_does_not_grow_store() {
        let review = review(RiskClass::SecuritySensitive);
        let request = id(ApprovalRequestId::new("approval:request:bytes"));
        let mut control = ApprovalReviewControl::default();
        let _ = control
            .issue_at(request.clone(), &review, &admin(), 100, 200)
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        let first_bytes = control.total_accounted_bytes();
        assert!(first_bytes > 0);
        assert!(first_bytes <= MAX_APPROVAL_TOTAL_BYTES);
        let _ = control
            .issue_at(request, &review, &admin(), 100, 200)
            .unwrap_or_else(|error| unreachable!("{error:?}"));
        assert_eq!(control.total_accounted_bytes(), first_bytes);
    }
}
