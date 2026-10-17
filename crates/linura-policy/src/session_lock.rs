//! Purpose-scoped policy for the native secure locker. The general baseline
//! approval-strength invariant is unchanged, including for human/service/agent
//! proposals. This rule cannot authorize any non-locker security-sensitive work.

use linura_core::{ActorKind, PolicyId, PolicyRevisionId, RiskClass, SessionLockId};

use crate::{
    ApprovalClass, PolicyDecision, PolicyEngine, PolicySnapshot, PolicySubject, ReviewPlanStatus,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionLockPolicy {
    snapshot: PolicySnapshot,
}

impl Default for SessionLockPolicy {
    fn default() -> Self {
        Self {
            snapshot: PolicySnapshot {
                policy_id: PolicyId::new("policy:session-lock")
                    .unwrap_or_else(|error| unreachable!("{error}")),
                revision_id: PolicyRevisionId::new("policy:session-lock:v1")
                    .unwrap_or_else(|error| unreachable!("{error}")),
            },
        }
    }
}

impl PolicyEngine for SessionLockPolicy {
    fn snapshot(&self) -> &PolicySnapshot {
        &self.snapshot
    }

    fn evaluate_decision(&self, subject: &PolicySubject) -> PolicyDecision {
        if subject.status() == ReviewPlanStatus::Blocked || subject.has_blockers() {
            return PolicyDecision::Blocked {
                reason: "session-lock plan contains blockers".into(),
            };
        }
        let deny = || PolicyDecision::Deny {
            reason: "session-lock policy requires an exact owner-bound native lock plan".into(),
        };
        let Ok(lock) = SessionLockId::from_resource(subject.resource()) else {
            return deny();
        };
        if lock.epoch().uid() == 0
            || subject.provider().as_str() != "session-locker"
            || subject.capability().as_str() != "session.secure-lock.observe"
            || subject.principal().as_str() != format!("unix:uid:{}", lock.epoch().uid())
            || subject.actor().kind != ActorKind::Human
            || !subject.actor().interactive
        {
            return deny();
        }
        if subject.status() == ReviewPlanStatus::NoChange
            && subject.prospective_risk() == RiskClass::ReadOnly
            && subject.changes().is_empty()
        {
            return PolicyDecision::Allow;
        }
        if subject.status() != ReviewPlanStatus::ChangeProposed
            || subject.prospective_risk() != RiskClass::SecuritySensitive
        {
            return deny();
        }
        let [change] = subject.changes() else {
            return deny();
        };
        if change.key != "secure" {
            return deny();
        }
        match (change.current.as_deref(), change.desired.as_str()) {
            (Some("false"), "true") => PolicyDecision::RequireApproval {
                class: ApprovalClass::InteractiveUser,
                reason: "explicit owner request to secure this native lock generation".into(),
            },
            (Some("true"), "false") => PolicyDecision::RequireApproval {
                class: ApprovalClass::SessionOwnerAuthentication,
                reason: "native session-owner authentication for this exact unlock only".into(),
            },
            _ => deny(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BaselinePolicy, ReviewedChange};
    use linura_core::{
        Actor, ActorId, BootId, CapabilityId, IntentId, PlanId, PrincipalId, ProviderId, RequestId,
        ResourceId, SemanticReason, SessionEpoch,
    };

    fn subject() -> PolicySubject {
        let epoch = SessionEpoch::new(
            BootId::new("abcd1234-1234-4567-89ab-0123456789ab")
                .unwrap_or_else(|error| unreachable!("{error}")),
            1000,
            "c2",
            42,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        PolicySubject::try_new(
            PrincipalId::new("unix:uid:1000").unwrap_or_else(|error| unreachable!("{error}")),
            PlanId::new("plan:unlock").unwrap_or_else(|error| unreachable!("{error}")),
            RequestId::new("request:unlock").unwrap_or_else(|error| unreachable!("{error}")),
            Actor {
                id: ActorId::new("actor:interactive")
                    .unwrap_or_else(|error| unreachable!("{error}")),
                kind: ActorKind::Human,
                interactive: true,
            },
            ProviderId::new("session-locker").unwrap_or_else(|error| unreachable!("{error}")),
            SessionLockId::new(
                epoch,
                linura_core::SecurityOwnerInvocationId::new("98765432-1234-4567-89ab-0123456789ab")
                    .unwrap_or_else(|error| unreachable!("{error}")),
                7,
            )
            .unwrap_or_else(|error| unreachable!("{error}"))
            .resource_id()
            .unwrap_or_else(|error| unreachable!("{error}")),
            CapabilityId::new("session.secure-lock.observe")
                .unwrap_or_else(|error| unreachable!("{error}")),
            SemanticReason {
                summary: "Unlock this session".into(),
                intent_ids: vec![
                    IntentId::new("intent:s17:unlock")
                        .unwrap_or_else(|error| unreachable!("{error}")),
                ],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
            "evidence:native-lock".into(),
            RiskClass::SecuritySensitive,
            ReviewPlanStatus::ChangeProposed,
            vec![ReviewedChange {
                key: "secure".into(),
                current: Some("true".into()),
                desired: "false".into(),
            }],
            vec![],
        )
        .unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[test]
    fn owner_unlock_is_native_purpose_scoped_not_administrator_approval() {
        let subject = subject();
        let reviewed = SessionLockPolicy::default().evaluate(&subject);
        assert!(matches!(
            reviewed.decision,
            PolicyDecision::RequireApproval {
                class: ApprovalClass::SessionOwnerAuthentication,
                ..
            }
        ));
        assert_eq!(reviewed.binding.resource, *subject.resource());
        assert_eq!(
            reviewed.binding.policy_revision_id.as_str(),
            "policy:session-lock:v1"
        );
        assert!(matches!(
            BaselinePolicy::default().evaluate_decision(&subject),
            PolicyDecision::RequireApproval {
                class: ApprovalClass::Administrator,
                ..
            }
        ));
    }

    #[test]
    fn lock_requires_explicit_interactive_owner_request() {
        let mut subject = subject();
        subject.changes[0].current = Some("false".into());
        subject.changes[0].desired = "true".into();
        assert!(matches!(
            SessionLockPolicy::default().evaluate_decision(&subject),
            PolicyDecision::RequireApproval {
                class: ApprovalClass::InteractiveUser,
                ..
            }
        ));
    }

    #[test]
    fn every_scope_substitution_denies_without_weakening_baseline() {
        let original = subject();
        let mut variants = Vec::new();
        let mut root_session = original.clone();
        root_session.resource =
            ResourceId::new("session:lock:abcd1234-1234-4567-89ab-0123456789ab:0:c2:42:98765432-1234-4567-89ab-0123456789ab:7")
                .unwrap_or_else(|error| unreachable!("{error}"));
        root_session.principal =
            PrincipalId::new("unix:uid:0").unwrap_or_else(|error| unreachable!("{error}"));
        variants.push(root_session);
        for kind in [ActorKind::Agent, ActorKind::Service, ActorKind::Remote] {
            let mut item = original.clone();
            item.actor.kind = kind;
            variants.push(item);
        }
        for principal in ["unix:uid:0", "unix:uid:1001", "unix:uid:01000"] {
            let mut item = original.clone();
            item.principal =
                PrincipalId::new(principal).unwrap_or_else(|error| unreachable!("{error}"));
            variants.push(item);
        }
        let mut item = original.clone();
        item.actor.interactive = false;
        variants.push(item);
        let mut item = original.clone();
        item.provider = ProviderId::new("systemd").unwrap_or_else(|error| unreachable!("{error}"));
        variants.push(item);
        let mut item = original.clone();
        item.capability = CapabilityId::new("session.epoch.observe")
            .unwrap_or_else(|error| unreachable!("{error}"));
        variants.push(item);
        let mut item = original.clone();
        item.resource =
            ResourceId::new("session:lock:unknown").unwrap_or_else(|error| unreachable!("{error}"));
        variants.push(item);
        let mut item = original.clone();
        item.changes[0].current = None;
        variants.push(item);
        let mut item = original.clone();
        item.changes[0].desired = "FALSE".into();
        variants.push(item);
        let mut item = original.clone();
        item.changes[0].key = "active_state".into();
        variants.push(item);
        let mut item = original.clone();
        item.changes.push(item.changes[0].clone());
        variants.push(item);
        for risk in [
            RiskClass::UserState,
            RiskClass::SystemMutation,
            RiskClass::Destructive,
        ] {
            let mut item = original.clone();
            item.prospective_risk = risk;
            variants.push(item);
        }
        for item in variants {
            assert!(matches!(
                SessionLockPolicy::default().evaluate_decision(&item),
                PolicyDecision::Deny { .. }
            ));
        }
    }
}
