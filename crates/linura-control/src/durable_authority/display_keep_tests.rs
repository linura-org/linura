use std::collections::{BTreeMap, BTreeSet};

use linura_core::{
    ActorId, CapabilityId, IntentId, ProviderId, RequestId, ResourceId, SemanticReason,
};
use linura_planner::{
    DesiredResource, DeterministicPlanner, PlanningFreshness, PlanningObservation,
};

use super::*;

fn checked<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|error| unreachable!("{error:?}"))
}

fn principal() -> AuthenticatedPrincipal {
    checked(AuthenticatedPrincipal::new("unix:uid:1000"))
}

fn floor() -> TrustedRiskFloor {
    TrustedRiskFloor::new(
        RiskClass::SecuritySensitive,
        crate::operation_registry::MANAGED_DISPLAY_LAYOUT_RISK_FLOOR_RULE_ID,
    )
}

fn administrator() -> PolicyAuthenticatedApprover {
    PolicyAuthenticatedApprover::new(
        checked(PrincipalId::new("unix:uid:1000")),
        ActorKind::Human,
        BTreeSet::from([ApprovalClass::Administrator]),
    )
}

// Policy-only fixture: the real planner and approval store produce the original
// review. These string attributes never enter a native layout/effect adapter.
fn fixture() -> (DisplayKeepReview, crate::ApprovalReviewControl) {
    let provider = checked(ProviderId::new(linura_observation::DISPLAY_PROVIDER));
    let resource = checked(ResourceId::new(
        "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3",
    ));
    let capability = checked(CapabilityId::new(
        linura_observation::DISPLAY_OUTPUTS_CAPABILITY,
    ));
    let plan = checked(DeterministicPlanner.plan_resource(
        checked(RequestId::new("request:display-keep-policy")),
        Actor {
            id: checked(ActorId::new("actor:display-keep-policy")),
            kind: ActorKind::Human,
            interactive: true,
        },
        DesiredResource {
            provider: provider.clone(),
            resource: resource.clone(),
            observation_capability: capability.clone(),
            state: BTreeMap::from([("layout".into(), "desired-layout".into())]),
            reason: SemanticReason {
                summary: "keep the explicitly reviewed layout".into(),
                intent_ids: vec![checked(IntentId::new("intent:display-keep-policy"))],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
        },
        &PlanningObservation {
            provider,
            resource,
            observation_capability: capability,
            authority: "hyprland-native".into(),
            evidence_id: "evidence:display-keep-policy".into(),
            freshness: PlanningFreshness::Current,
            attributes: BTreeMap::from([("layout".into(), "baseline-layout".into())]),
        },
    ));
    let classification = classify_candidate_risk(&plan, Some(floor()));
    let risk = checked(risk_provenance_for_plan(&plan, &classification));
    let review = checked(review_plan_with_classification(
        &principal(),
        &plan,
        classification,
    ));
    let mut approvals = crate::ApprovalReviewControl::default();
    let now = checked(SystemTime::now().duration_since(UNIX_EPOCH)).as_secs();
    let evidence = checked(approvals.issue(
        checked(ApprovalRequestId::new("approval:display-keep-policy")),
        &review,
        &administrator(),
        now + 120,
    ));
    let digest = digest_parts("linura.test.display-keep", [b"policy-only".as_slice()]);
    let binding = checked(AuthorityBinding::try_new(
        checked(PrincipalId::new(principal().as_str())),
        plan.request_id.clone(),
        plan.id.clone(),
        digest.clone(),
        digest.clone(),
        digest,
        plan.provider.clone(),
        plan.resource.clone(),
        plan.observation_capability.clone(),
        review.binding().policy_id.clone(),
        review.binding().policy_revision_id.clone(),
        risk.risk,
        risk.revision,
        risk.rule_ids,
        checked(digest_review(&review)),
        AuthorizationBasis::Approval(checked(ApprovalAuthority::try_new(
            evidence.id().clone(),
            evidence.request_id().clone(),
            evidence.approver().clone(),
            "administrator",
            evidence.issued_at_unix_seconds(),
            evidence.expires_at_unix_seconds(),
        ))),
    ));
    (
        DisplayKeepReview {
            plan,
            binding,
            risk_floor: floor(),
            approval_evidence_id: evidence.id().clone(),
            transaction_id: checked(TransactionId::new("transaction:display-keep-policy")),
            generation: 1,
        },
        approvals,
    )
}

#[test]
fn keep_uses_original_mutation_and_honors_current_approval_revocation() {
    let (original, mut approvals) = fixture();
    assert_eq!(
        original.revalidate(&principal(), floor(), &approvals),
        Ok(())
    );
    assert_eq!(
        original.plan.status,
        linura_planner::PlanStatus::ChangeProposed
    );
    assert_eq!(
        original.plan.changes[0].current.as_deref(),
        Some("baseline-layout")
    );
    checked(approvals.revoke(&original.approval_evidence_id, &administrator()));
    assert_eq!(
        original.revalidate(&principal(), floor(), &approvals),
        Err(DurableAuthorityError::ApprovalUnsatisfied(
            ApprovalValidation::Revoked
        ))
    );
}

#[test]
fn keep_rejects_principal_floor_and_original_review_material_substitution() {
    let (original, approvals) = fixture();
    assert_eq!(
        original.revalidate(
            &checked(AuthenticatedPrincipal::new("unix:uid:1001")),
            floor(),
            &approvals
        ),
        Err(DurableAuthorityError::AuthorityChanged)
    );
    assert_eq!(
        original.revalidate(
            &principal(),
            TrustedRiskFloor::new(RiskClass::SecuritySensitive, "replaced-rule"),
            &approvals
        ),
        Err(DurableAuthorityError::AuthorityChanged)
    );
    for fault in [
        "no-change",
        "desired",
        "evidence",
        "provenance",
        "capability",
    ] {
        let (mut original, approvals) = fixture();
        match fault {
            "no-change" => {
                original.plan.status = linura_planner::PlanStatus::NoChange;
                original.plan.changes.clear();
            }
            "desired" => original.plan.changes[0].desired = "other-layout".into(),
            "evidence" => original.plan.observed_evidence_id = "evidence:replaced".into(),
            "provenance" => original.plan.reason.summary = "different purpose".into(),
            "capability" => {
                original.plan.observation_capability = checked(CapabilityId::new("other.observe"))
            }
            _ => unreachable!(),
        }
        assert!(
            original
                .revalidate(&principal(), floor(), &approvals)
                .is_err(),
            "{fault}"
        );
    }
}

#[test]
fn registered_display_floor_preserves_source_classifier_revision() {
    let (original, _) = fixture();
    assert_eq!(
        original.binding.risk_policy_revision(),
        "risk-policy:v0.10:registered-operation-floor/risk-policy:v0.10:display-layout:1"
    );
    let mut unrelated = original.plan.clone();
    unrelated.provider = checked(ProviderId::new("systemd"));
    unrelated.observation_capability = checked(CapabilityId::new("systemd.unit.observe"));
    unrelated.resource = checked(ResourceId::new("systemd:unit:test.service"));
    unrelated.changes[0].key = "active_state".into();
    let classification = classify_candidate_risk(&unrelated, Some(floor()));
    assert_eq!(
        checked(risk_provenance_for_plan(&unrelated, &classification)),
        checked(risk_provenance(&classification))
    );
}

#[test]
fn keep_rejects_old_risk_source_or_policy_revision_even_with_live_approval() {
    for field in ["risk-source", "policy-revision", "review-digest"] {
        let (mut original, approvals) = fixture();
        let binding = &original.binding;
        original.binding = checked(AuthorityBinding::try_new(
            binding.principal().clone(),
            binding.request_id().clone(),
            binding.plan_id().clone(),
            binding.request_digest().clone(),
            binding.precondition_digest().clone(),
            binding.observation_digest().clone(),
            binding.provider().clone(),
            binding.resource().clone(),
            binding.capability().clone(),
            binding.policy_id().clone(),
            if field == "policy-revision" {
                checked(linura_core::PolicyRevisionId::new(
                    "policy:previous-revision",
                ))
            } else {
                binding.policy_revision_id().clone()
            },
            binding.trusted_risk(),
            if field == "risk-source" {
                // The floor wrapper alone previously hid the source revision.
                crate::risk_classification::REGISTERED_OPERATION_RISK_POLICY_REVISION.to_owned()
            } else {
                binding.risk_policy_revision().to_owned()
            },
            binding.risk_rule_ids().to_vec(),
            if field == "review-digest" {
                digest_parts("linura.test.other-review", [b"other".as_slice()])
            } else {
                binding.review_digest().clone()
            },
            binding.authorization().clone(),
        ));
        assert_eq!(
            original.revalidate(&principal(), floor(), &approvals),
            Err(DurableAuthorityError::AuthorityChanged),
            "{field}"
        );
    }
}
