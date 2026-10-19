//! Explicit protective-lock policy; never an implicit service or root bypass.
//!
//! Inputs are typed facts, not credentials. Only Control may select this rule
//! after reading the current authenticated durable owner setting and freshly
//! attested native sleep event. The ordinary session-lock rule is unchanged.
//! An Allow still requires canonical managed prepare/revalidation/verification.

use linura_core::{
    ActorKind, IntentId, PolicyId, PolicyRevisionId, PrincipalId, RiskClass, SessionEpoch,
    SessionLockId, SleepInvocationId,
};

use crate::{PolicyDecision, PolicyEngine, PolicySnapshot, PolicySubject, ReviewPlanStatus};

/// Transport-derived ONLY after exact native sleep-helper invocation attestation.
/// UID 0, a Service Actor, or possession of this text does not establish identity.
pub const PROTECTIVE_SLEEP_PRINCIPAL: &str = "service:system-sleep-protection";
pub const PROTECTIVE_SLEEP_ACTOR: &str = "actor:system-sleep-protection";

/// Current Linura-owned structured policy state, not a reusable approval token.
/// Its revision is the canonical authenticated record digest. Storage/Control
/// must validate approval provenance, latest revision and revocation before use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectiveLockSetting {
    owner: PrincipalId,
    epoch: SessionEpoch,
    intent: IntentId,
    revision: PolicyRevisionId,
    enabled: bool,
}

impl ProtectiveLockSetting {
    pub fn new(
        owner: PrincipalId,
        epoch: SessionEpoch,
        intent: IntentId,
        revision: PolicyRevisionId,
        enabled: bool,
    ) -> Result<Self, &'static str> {
        let Some(digest) = revision.as_str().strip_prefix("policy:protective-lock:v1:") else {
            return Err("protective-lock revision is not a canonical record digest");
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err("protective-lock revision is not a canonical record digest");
        }
        if epoch.uid() == 0 || owner.as_str() != format!("unix:uid:{}", epoch.uid()) {
            return Err("protective-lock setting must belong to the exact non-root session owner");
        }
        Ok(Self {
            owner,
            epoch,
            intent,
            revision,
            enabled,
        })
    }

    #[must_use]
    pub const fn owner(&self) -> &PrincipalId {
        &self.owner
    }
    #[must_use]
    pub const fn epoch(&self) -> &SessionEpoch {
        &self.epoch
    }
    #[must_use]
    pub const fn intent(&self) -> &IntentId {
        &self.intent
    }
    #[must_use]
    pub const fn revision(&self) -> &PolicyRevisionId {
        &self.revision
    }
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
}

/// No default constructor: a manual/public request never implicitly selects
/// protective policy. Event authenticity/freshness is checked by Control, not
/// inferred here from identifiers or caller-supplied findings.
#[derive(Debug)]
pub struct ProtectiveLockPolicy<'a> {
    snapshot: PolicySnapshot,
    setting: &'a ProtectiveLockSetting,
    event: &'a SleepInvocationId,
    lock: &'a SessionLockId,
}

impl<'a> ProtectiveLockPolicy<'a> {
    #[must_use]
    pub fn new(
        setting: &'a ProtectiveLockSetting,
        event: &'a SleepInvocationId,
        lock: &'a SessionLockId,
    ) -> Self {
        Self {
            snapshot: PolicySnapshot {
                policy_id: PolicyId::new("policy:protective-lock")
                    .unwrap_or_else(|error| unreachable!("{error}")),
                revision_id: setting.revision.clone(),
            },
            setting,
            event,
            lock,
        }
    }
}

impl PolicyEngine for ProtectiveLockPolicy<'_> {
    fn snapshot(&self) -> &PolicySnapshot {
        &self.snapshot
    }

    fn evaluate_decision(&self, subject: &PolicySubject) -> PolicyDecision {
        if subject.status() == ReviewPlanStatus::Blocked || subject.has_blockers() {
            return PolicyDecision::Blocked {
                reason: "protective-lock plan contains blockers".into(),
            };
        }
        let deny = || PolicyDecision::Deny {
            reason:
                "protective-lock policy does not cover this exact event and canonical lock plan"
                    .into(),
        };
        let Ok(request) = self.event.protective_request_id(&self.setting.epoch) else {
            return deny();
        };
        let Ok(resource) = self.lock.resource_id() else {
            return deny();
        };
        if !self.setting.enabled
            || self.lock.epoch() != &self.setting.epoch
            || subject.principal().as_str() != PROTECTIVE_SLEEP_PRINCIPAL
            || subject.actor().kind != ActorKind::Service
            || subject.actor().interactive
            || subject.actor().id.as_str() != PROTECTIVE_SLEEP_ACTOR
            || subject.provider().as_str() != "session-locker"
            || subject.capability().as_str() != "session.secure-lock.observe"
            || subject.resource() != &resource
            || subject.request_id() != &request
            || subject.plan_id().as_str() != request.as_str()
            || subject.reason().intent_ids.as_slice() != [self.setting.intent.clone()]
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
        if change.key == "secure"
            && change.current.as_deref() == Some("false")
            && change.desired == "true"
        {
            PolicyDecision::Allow
        } else {
            deny()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ApprovalClass, ReviewFindingLevel, ReviewedChange, ReviewedFinding, SessionLockPolicy,
    };
    use linura_core::{
        Actor, ActorId, BootId, CapabilityId, PlanId, ProviderId, RequestId, ResourceId,
        SecurityOwnerInvocationId, SemanticReason,
    };

    fn id<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn setting() -> ProtectiveLockSetting {
        id(ProtectiveLockSetting::new(
            id(PrincipalId::new("unix:uid:1000")),
            id(SessionEpoch::new(
                id(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
                1000,
                "c2",
                42,
            )),
            id(IntentId::new("intent:s17:protective-lock:owner-approved")),
            id(PolicyRevisionId::new(format!(
                "policy:protective-lock:v1:{}",
                "a".repeat(64)
            ))),
            true,
        ))
    }
    fn lock(setting: &ProtectiveLockSetting) -> SessionLockId {
        id(SessionLockId::new(
            setting.epoch.clone(),
            id(SecurityOwnerInvocationId::new(
                "98765432-1234-4567-89ab-0123456789ab",
            )),
            7,
        ))
    }
    fn event(setting: &ProtectiveLockSetting) -> SleepInvocationId {
        id(SleepInvocationId::new(
            setting.epoch.boot().clone(),
            "01234567-1234-4567-89ab-0123456789ab",
        ))
    }
    fn subject(
        setting: &ProtectiveLockSetting,
        event: &SleepInvocationId,
        lock: &SessionLockId,
    ) -> PolicySubject {
        let request = id(event.protective_request_id(&setting.epoch));
        id(PolicySubject::try_new(
            id(PrincipalId::new(PROTECTIVE_SLEEP_PRINCIPAL)),
            id(PlanId::new(request.as_str())),
            request,
            Actor {
                id: id(ActorId::new(PROTECTIVE_SLEEP_ACTOR)),
                kind: ActorKind::Service,
                interactive: false,
            },
            id(ProviderId::new("session-locker")),
            id(lock.resource_id()),
            id(CapabilityId::new("session.secure-lock.observe")),
            SemanticReason {
                summary: "Protect this owner's session before native sleep".into(),
                intent_ids: vec![setting.intent.clone()],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
            "evidence:protective-lock:current".into(),
            RiskClass::SecuritySensitive,
            ReviewPlanStatus::ChangeProposed,
            vec![ReviewedChange {
                key: "secure".into(),
                current: Some("false".into()),
                desired: "true".into(),
            }],
            vec![],
        ))
    }

    #[test]
    fn protective_rule_is_exact_and_manual_rule_is_unchanged() {
        let setting = setting();
        let event = event(&setting);
        let lock = lock(&setting);
        let protective = subject(&setting, &event, &lock);
        let policy = ProtectiveLockPolicy::new(&setting, &event, &lock);
        assert_eq!(policy.evaluate_decision(&protective), PolicyDecision::Allow);
        let reviewed = policy.evaluate(&protective);
        assert_eq!(&reviewed.binding.policy_revision_id, setting.revision());
        assert_eq!(&reviewed.binding.resource, protective.resource());
        assert_eq!(&reviewed.binding.request_id, protective.request_id());
        assert!(matches!(
            SessionLockPolicy::default().evaluate_decision(&protective),
            PolicyDecision::Deny { .. }
        ));
        let mut manual = protective.clone();
        manual.principal = setting.owner.clone();
        manual.actor.kind = ActorKind::Human;
        manual.actor.interactive = true;
        assert!(matches!(
            SessionLockPolicy::default().evaluate_decision(&manual),
            PolicyDecision::RequireApproval {
                class: ApprovalClass::InteractiveUser,
                ..
            }
        ));
        assert!(matches!(
            policy.evaluate_decision(&manual),
            PolicyDecision::Deny { .. }
        ));
        manual.changes[0].current = Some("true".into());
        manual.changes[0].desired = "false".into();
        assert!(matches!(
            SessionLockPolicy::default().evaluate_decision(&manual),
            PolicyDecision::RequireApproval {
                class: ApprovalClass::SessionOwnerAuthentication,
                ..
            }
        ));
        assert!(matches!(
            policy.evaluate_decision(&manual),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn root_owner_aliases_and_noncanonical_revision_records_are_rejected() {
        let original = setting();
        for owner in [
            "unix:uid:0",
            "unix:uid:1001",
            "unix:uid:01000",
            PROTECTIVE_SLEEP_PRINCIPAL,
        ] {
            assert!(
                ProtectiveLockSetting::new(
                    id(PrincipalId::new(owner)),
                    original.epoch.clone(),
                    original.intent.clone(),
                    original.revision.clone(),
                    true
                )
                .is_err()
            );
        }
        for revision in [
            "policy:protective-lock:v1:1".into(),
            format!("policy:protective-lock:v1:{}", "A".repeat(64)),
            format!("policy:session-lock:v1:{}", "a".repeat(64)),
        ] {
            assert!(
                ProtectiveLockSetting::new(
                    original.owner.clone(),
                    original.epoch.clone(),
                    original.intent.clone(),
                    id(PolicyRevisionId::new(revision)),
                    true
                )
                .is_err()
            );
        }
    }

    #[test]
    fn disabled_wrong_epoch_and_other_native_invocations_do_not_authorize() {
        let original = setting();
        let event = event(&original);
        let lock = lock(&original);
        let subject = subject(&original, &event, &lock);
        let mut disabled = original.clone();
        disabled.enabled = false;
        let mut other_epoch = original.clone();
        other_epoch.epoch = id(SessionEpoch::new(
            original.epoch.boot().clone(),
            1000,
            "c2",
            43,
        ));
        for setting in [&disabled, &other_epoch] {
            assert!(matches!(
                ProtectiveLockPolicy::new(setting, &event, &lock).evaluate_decision(&subject),
                PolicyDecision::Deny { .. }
            ));
        }
        let other_event = id(SleepInvocationId::new(
            original.epoch.boot().clone(),
            "01234567-1234-4567-89ab-0123456789ac",
        ));
        assert!(matches!(
            ProtectiveLockPolicy::new(&original, &other_event, &lock).evaluate_decision(&subject),
            PolicyDecision::Deny { .. }
        ));
        let other_lock = id(SessionLockId::new(
            lock.epoch().clone(),
            lock.security_owner_invocation().clone(),
            8,
        ));
        assert!(matches!(
            ProtectiveLockPolicy::new(&original, &event, &other_lock).evaluate_decision(&subject),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn service_provenance_cannot_unlock_authorize_power_or_substitute_scope() {
        let setting = setting();
        let event = event(&setting);
        let lock = lock(&setting);
        let policy = ProtectiveLockPolicy::new(&setting, &event, &lock);
        let original = subject(&setting, &event, &lock);
        let mut variants = Vec::new();
        for kind in [ActorKind::Agent, ActorKind::Human, ActorKind::Remote] {
            let mut item = original.clone();
            item.actor.kind = kind;
            variants.push(item);
        }
        for principal in ["unix:uid:0", "unix:uid:1000", "service:other"] {
            let mut item = original.clone();
            item.principal = id(PrincipalId::new(principal));
            variants.push(item);
        }
        let mut item = original.clone();
        item.actor.interactive = true;
        variants.push(item);
        let mut item = original.clone();
        item.actor.id = id(ActorId::new("actor:other"));
        variants.push(item);
        let mut item = original.clone();
        item.provider = id(ProviderId::new("logind"));
        variants.push(item);
        let mut item = original.clone();
        item.capability = id(CapabilityId::new("session.power.observe"));
        variants.push(item);
        let mut item = original.clone();
        item.resource = id(ResourceId::new("session:lock:unknown"));
        variants.push(item);
        let mut item = original.clone();
        item.request_id = id(RequestId::new("request:v010:protective-lock:forged"));
        variants.push(item);
        let mut item = original.clone();
        item.plan_id = id(PlanId::new("plan:substituted"));
        variants.push(item);
        let mut item = original.clone();
        item.reason.intent_ids.clear();
        variants.push(item);
        let mut item = original.clone();
        item.reason
            .intent_ids
            .push(id(IntentId::new("intent:other")));
        variants.push(item);
        for (current, desired) in [
            (Some("true"), "false"),
            (None, "true"),
            (Some("false"), "TRUE"),
            (Some("false"), "false"),
        ] {
            let mut item = original.clone();
            item.changes[0].current = current.map(str::to_owned);
            item.changes[0].desired = desired.into();
            variants.push(item);
        }
        for key in ["completed", "power_off", "active_state"] {
            let mut item = original.clone();
            item.changes[0].key = key.into();
            variants.push(item);
        }
        let mut item = original.clone();
        item.changes.push(item.changes[0].clone());
        variants.push(item);
        for risk in [
            RiskClass::ReadOnly,
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
                policy.evaluate_decision(&item),
                PolicyDecision::Deny { .. }
            ));
        }
        let mut blocked = original.clone();
        blocked.status = ReviewPlanStatus::Blocked;
        blocked.findings.push(ReviewedFinding {
            code: "unknown-native-state".into(),
            level: ReviewFindingLevel::Blocker,
            message: "Cannot establish current native coverage".into(),
        });
        assert!(matches!(
            policy.evaluate_decision(&blocked),
            PolicyDecision::Blocked { .. }
        ));
    }

    #[test]
    fn no_change_is_not_a_new_lock_or_sleep_dispatch_permission() {
        let setting = setting();
        let event = event(&setting);
        let lock = lock(&setting);
        let policy = ProtectiveLockPolicy::new(&setting, &event, &lock);
        let mut subject = subject(&setting, &event, &lock);
        subject.status = ReviewPlanStatus::NoChange;
        subject.prospective_risk = RiskClass::ReadOnly;
        subject.changes.clear();
        assert_eq!(policy.evaluate_decision(&subject), PolicyDecision::Allow);
        subject.prospective_risk = RiskClass::SecuritySensitive;
        assert!(matches!(
            policy.evaluate_decision(&subject),
            PolicyDecision::Deny { .. }
        ));
    }
}
