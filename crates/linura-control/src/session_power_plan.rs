//! Control-owned aggregation for S17 transition plans. Providers supply narrow
//! native facts only; neither permission, authentication nor executor replies
//! determine completion. Recovery of an ended session/boot needs no live owner.

use linura_core::{CapabilityId, ProviderId, SessionTransition, SessionTransitionId};
use linura_observation::{ObservationEnvelope, ObservedValue};
use linura_planner::{PlanFinding, PlanFindingLevel};
use linura_protocol::{ObservationRequest, PlanDesiredStateRequest};

use crate::operation_registry::{
    MANAGED_SESSION_TRANSITION_CAPABILITY, MANAGED_SESSION_TRANSITION_PROVIDER,
};
use crate::plan_preview::restrict_session_validity;
use crate::{
    AuthenticatedPrincipal, PlanPreviewControl, PlanPreviewControlError, SessionAction,
    SessionPowerSafetyReview, SessionSafetyReview, SessionTransitionPostcondition,
    review_session_transition_postcondition,
};

pub(crate) struct SessionPowerPlanFacts {
    pub(crate) completed: bool,
    pub(crate) findings: Vec<PlanFinding>,
}

fn fail(reason: impl ToString) -> PlanPreviewControlError {
    PlanPreviewControlError::Planning {
        reason: reason.to_string(),
    }
}

fn finding(observation: &ObservationEnvelope) -> PlanFinding {
    // Bind stable, approval-relevant native semantics, not refreshed probe
    // timestamps/sequences. Each actual validity window is narrowed separately.
    PlanFinding {
        code: format!(
            "native-session-transition-{}",
            observation.capability.as_str()
        ),
        level: PlanFindingLevel::Pass,
        message: format!(
            "NativeApi {}/{}/{}: {:?}",
            observation.provider.as_str(),
            observation.capability.as_str(),
            observation.resource.as_str(),
            observation.attributes
        ),
    }
}

impl PlanPreviewControl {
    pub(crate) fn session_power_plan_facts(
        &mut self,
        principal: &AuthenticatedPrincipal,
        request: &PlanDesiredStateRequest,
        native: &mut ObservationEnvelope,
    ) -> Result<Option<SessionPowerPlanFacts>, PlanPreviewControlError> {
        if request.provider.as_str() != MANAGED_SESSION_TRANSITION_PROVIDER
            || request.observation_capability.as_str() != MANAGED_SESSION_TRANSITION_CAPABILITY
        {
            return Ok(None);
        }
        let target = SessionTransitionId::from_resource(&request.resource).map_err(fail)?;
        if request.desired_state.len() != 1
            || request.desired_state.get("completed").map(String::as_str) != Some("true")
            || principal.as_str() != format!("unix:uid:{}", target.lock().epoch().uid())
        {
            return Err(fail(
                "transition requires exact owner and the sole completed=true postcondition",
            ));
        }
        let now = || -> Result<u64, PlanPreviewControlError> {
            u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(fail)?
                    .as_millis(),
            )
            .map_err(fail)
        };
        let observe = |control: &mut Self, provider: &str, capability: &str, resource| {
            control
                .observe(&ObservationRequest {
                    provider: ProviderId::new(provider).map_err(fail)?,
                    capability: CapabilityId::new(capability).map_err(fail)?,
                    resource,
                })
                .map(|response| response.observation)
                .map_err(PlanPreviewControlError::from)
        };
        let mut coverage = None;
        // Acquire coverage only when native facts claim a completed suspend.
        // Missing coverage cannot be inferred from a logind LockedHint.
        if let SessionTransition::Suspend {
            successful_cycles_before,
        } = target.transition()
            && native.attributes.get("successful_suspend_cycles")
                == Some(&ObservedValue::U64(successful_cycles_before + 1))
        {
            coverage = Some(observe(
                self,
                "session-locker",
                "session.secure-lock.observe",
                target.lock().resource_id().map_err(fail)?,
            )?);
        }
        let postcondition =
            review_session_transition_postcondition(&target, native, coverage.as_ref(), now()?)
                .map_err(fail)?;
        let completed = match postcondition {
            SessionTransitionPostcondition::ResumedSecurely
            | SessionTransitionPostcondition::OriginalSessionEnded
            | SessionTransitionPostcondition::OriginalBootEnded => true,
            SessionTransitionPostcondition::NotSatisfied => false,
            SessionTransitionPostcondition::Indeterminate => {
                return Err(fail(
                    "native transition remains ambiguous; no replay is permitted",
                ));
            }
        };
        let mut findings = vec![finding(native)];
        if let Some(coverage) = &coverage {
            restrict_session_validity(native, coverage, now()?)?;
            findings.push(finding(coverage));
        }
        if completed {
            // Historical completion must remain recoverable after logout,
            // compositor death or reboot; no fresh mutation is authorized here.
            return Ok(Some(SessionPowerPlanFacts {
                completed,
                findings,
            }));
        }
        let epoch = target.lock().epoch();
        let session = observe(
            self,
            "logind",
            "session.epoch.observe",
            epoch.resource_id().map_err(fail)?,
        )?;
        let action = match target.transition() {
            SessionTransition::Suspend { .. } => SessionAction::Suspend,
            SessionTransition::Logout => SessionAction::Logout,
            SessionTransition::Reboot => SessionAction::Reboot,
            SessionTransition::PowerOff => SessionAction::PowerOff,
        };
        let ownership = SessionSafetyReview::review(principal, epoch, action, &session, now()?)
            .map_err(fail)?;
        let coverage = observe(
            self,
            "session-locker",
            "session.secure-lock.observe",
            target.lock().resource_id().map_err(fail)?,
        )?;
        if ownership
            .require_secure_coverage(&coverage, now()?)
            .map_err(fail)?
            != *target.lock()
        {
            return Err(fail("transition secure coverage generation changed"));
        }
        for evidence in [&session, &coverage] {
            restrict_session_validity(native, evidence, now()?)?;
            findings.push(finding(evidence));
        }
        if action != SessionAction::Logout {
            let conditions = observe(
                self,
                "logind",
                "session.power.conditions.observe",
                epoch.resource_id().map_err(fail)?,
            )?;
            let permission = observe(
                self,
                "polkit",
                "session.power.permission.observe",
                target.permission_resource_id().map_err(fail)?,
            )?;
            let safety = SessionPowerSafetyReview::review_with_permission(
                principal,
                &target,
                &conditions,
                &permission,
                now()?,
            )
            .map_err(fail)?;
            if action == SessionAction::Suspend
                && safety
                    .require_secure_suspend(&coverage, now()?)
                    .map_err(fail)?
                    != *target.lock()
            {
                return Err(fail("power secure coverage generation changed"));
            }
            for evidence in [&conditions, &permission] {
                restrict_session_validity(native, evidence, now()?)?;
                findings.push(finding(evidence));
            }
        }
        Ok(Some(SessionPowerPlanFacts {
            completed,
            findings,
        }))
    }
}
