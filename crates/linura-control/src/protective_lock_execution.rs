//! Private protective authority context. No caller-authored policy, retained
//! grant or executor shortcut; native facts are acquired by the same coordinator.
use std::collections::BTreeMap;

use linura_core::{
    Actor, ActorId, ActorKind, CapabilityId, PrincipalId, ProviderId, SemanticReason,
    SessionLockId, SleepInvocationId,
};
use linura_policy::{PROTECTIVE_SLEEP_ACTOR, PROTECTIVE_SLEEP_PRINCIPAL, ProtectiveLockSetting};
use linura_protocol::{ObservationRequest, PlanDesiredStateRequest};

use crate::{
    AuthenticatedPrincipal, ManagedApprovalAuthorizer, ManagedApprovalChallenge,
    PlanPreviewControl, ProtectiveLockSafetyReview, ProtectiveLockSettingsControl,
    TrustedHumanApproval,
};

#[derive(Clone, Debug)]
pub(crate) struct ProtectiveLockContext {
    pub(crate) setting: ProtectiveLockSetting,
    pub(crate) event: SleepInvocationId,
    pub(crate) lock: SessionLockId,
}

impl ProtectiveLockContext {
    pub(crate) fn from_current(
        settings: &ProtectiveLockSettingsControl,
        event: SleepInvocationId,
        lock: SessionLockId,
    ) -> Result<Self, String> {
        let owner = PrincipalId::new(format!("unix:uid:{}", lock.epoch().uid()))
            .map_err(|e| e.to_string())?;
        let setting = settings
            .current(&owner, lock.epoch())?
            .filter(|s| s.enabled())
            .ok_or("owner protective-lock consent is absent or revoked")?;
        let context = Self {
            setting,
            event,
            lock,
        };
        context
            .event
            .protective_request_id(context.lock.epoch())
            .map_err(|e| e.to_string())?;
        Ok(context)
    }

    pub(crate) fn request(&self) -> Result<PlanDesiredStateRequest, String> {
        Ok(PlanDesiredStateRequest {
            request_id: self.event.protective_request_id(self.lock.epoch()).map_err(|e| e.to_string())?,
            provider: ProviderId::new("session-locker").map_err(|e| e.to_string())?,
            resource: self.lock.resource_id().map_err(|e| e.to_string())?,
            observation_capability: CapabilityId::new("session.secure-lock.observe").map_err(|e| e.to_string())?,
            reason: SemanticReason { summary: "Protect the current owner session before this authenticated native suspend invocation".into(), intent_ids: vec![self.setting.intent().clone()], requirement_ids: Vec::new(), capability_ids: Vec::new() },
            desired_state: BTreeMap::from([("secure".into(), "true".into())]),
        })
    }

    pub(crate) fn require_request(
        &self,
        principal: &AuthenticatedPrincipal,
        actor: &Actor,
        request: &PlanDesiredStateRequest,
    ) -> Result<(), String> {
        if principal.as_str() != PROTECTIVE_SLEEP_PRINCIPAL
            || actor != &protective_actor()?
            || request != &self.request()?
        {
            return Err("protective-lock initiator or exact approved request changed".into());
        }
        Ok(())
    }

    pub(crate) fn require_current(
        &self,
        settings: &ProtectiveLockSettingsControl,
    ) -> Result<(), String> {
        if settings
            .current(self.setting.owner(), self.setting.epoch())?
            .as_ref()
            != Some(&self.setting)
            || !self.setting.enabled()
        {
            return Err("protective-lock consent was revoked or superseded".into());
        }
        Ok(())
    }

    pub(crate) fn observe_entry(
        &self,
        previews: &mut PlanPreviewControl,
    ) -> Result<linura_observation::ObservationEnvelope, String> {
        previews
            .observe(&ObservationRequest {
                provider: ProviderId::new("system-sleep").map_err(|e| e.to_string())?,
                resource: self.event.resource_id().map_err(|e| e.to_string())?,
                capability: CapabilityId::new("session.sleep-entry.observe")
                    .map_err(|e| e.to_string())?,
            })
            .map(|r| r.observation)
            .map_err(|e| e.to_string())
    }

    pub(crate) fn review_facts(
        &self,
        principal: &AuthenticatedPrincipal,
        event: &linura_observation::ObservationEnvelope,
        session: &linura_observation::ObservationEnvelope,
        lock: &linura_observation::ObservationEnvelope,
        now: u64,
    ) -> Result<ProtectiveLockSafetyReview, String> {
        ProtectiveLockSafetyReview::review(
            principal,
            &self.setting,
            &self.event,
            &self.lock,
            event,
            session,
            lock,
            now,
        )
        .map_err(|e| e.to_string())
    }
}

pub(crate) fn protective_actor() -> Result<Actor, String> {
    Ok(Actor {
        id: ActorId::new(PROTECTIVE_SLEEP_ACTOR).map_err(|e| e.to_string())?,
        kind: ActorKind::Service,
        interactive: false,
    })
}

/// Retained request integrity and transaction anchoring are checked separately
/// before this predicate is used for observe-only recovery. This is NOT grant
/// validation and cannot select protective mutation policy.
pub(crate) fn retained_protective_request(
    principal: &AuthenticatedPrincipal,
    request: &PlanDesiredStateRequest,
) -> bool {
    if principal.as_str() != PROTECTIVE_SLEEP_PRINCIPAL
        || request.provider.as_str() != "session-locker"
        || request.observation_capability.as_str() != "session.secure-lock.observe"
        || request.desired_state != BTreeMap::from([("secure".into(), "true".into())])
        || request.reason.intent_ids.len() != 1
        || !request.reason.requirement_ids.is_empty()
        || !request.reason.capability_ids.is_empty()
    {
        return false;
    }
    let Ok(lock) = SessionLockId::from_resource(&request.resource) else {
        return false;
    };
    SleepInvocationId::from_protective_request_id(&request.request_id, lock.epoch()).is_ok()
}

#[derive(Debug)]
pub(crate) struct NoInteractiveProtectiveApproval;
impl ManagedApprovalAuthorizer for NoInteractiveProtectiveApproval {
    fn authorize(&self, _: &ManagedApprovalChallenge) -> Result<TrustedHumanApproval, String> {
        Err("protective locking cannot manufacture per-event human approval".into())
    }
}
