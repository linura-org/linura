//! Control-owned aggregation for S17 transition plans. Providers supply narrow
//! native facts only; neither permission, authentication nor executor replies
//! determine completion. Recovery of an ended session/boot needs no live owner.

use linura_core::{CapabilityId, ProviderId, SessionTransition, SessionTransitionId};
use linura_observation::ObservationEnvelope;
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
        // Classify the complete native envelope before querying the owner.
        // A known pending sleep must not start a lock probe that can straddle
        // kernel sleep. Only canonical review can request secure coverage.
        let mut postcondition =
            review_session_transition_postcondition(&target, native, None, now()?).map_err(fail)?;
        if postcondition == SessionTransitionPostcondition::SecureCoverageRequired {
            coverage = Some(observe(
                self,
                "session-locker",
                "session.secure-lock.observe",
                target.lock().resource_id().map_err(fail)?,
            )?);
            // The coverage probe consumes native validity too. Recheck both
            // original envelopes at the current time before using either fact.
            postcondition =
                review_session_transition_postcondition(&target, native, coverage.as_ref(), now()?)
                    .map_err(fail)?;
        }
        let completed = match postcondition {
            SessionTransitionPostcondition::ResumedSecurely
            | SessionTransitionPostcondition::OriginalSessionEnded
            | SessionTransitionPostcondition::OriginalBootEnded => true,
            SessionTransitionPostcondition::NotSatisfied => false,
            SessionTransitionPostcondition::Indeterminate
            | SessionTransitionPostcondition::SecureCoverageRequired => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{RequestId, SemanticReason, SessionLockId};
    use linura_observation::{ObservationAuthority, ObservedValue};
    use linura_observation_control::ObservationCoordinator;
    use std::collections::BTreeMap;

    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }

    fn sample_now(template: &ObservationEnvelope) -> ObservationEnvelope {
        let mut sample = template.clone();
        sample.observed_at_unix_ms =
            value(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH))
                .as_millis()
                .try_into()
                .unwrap_or_else(|error| unreachable!("{error:?}"));
        sample
    }

    #[test]
    fn planning_classifies_native_pending_or_invalid_before_requesting_coverage() {
        let lock = value(SessionLockId::from_resource(&value(
            linura_core::ResourceId::new(
                "session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:98765432-1234-4567-89ab-0123456789ab:7",
            ),
        )));
        let target = value(SessionTransitionId::new(
            lock,
            SessionTransition::Suspend {
                successful_cycles_before: 10,
            },
        ));
        let capability = value(CapabilityId::new("session.transition.observe"));
        let request = PlanDesiredStateRequest {
            request_id: value(RequestId::new("request:s17:pending-coverage")),
            provider: value(ProviderId::new("logind")),
            resource: value(target.resource_id()),
            observation_capability: capability.clone(),
            reason: SemanticReason {
                summary: "Retained native suspend completion".into(),
                intent_ids: Vec::new(),
                requirement_ids: Vec::new(),
                capability_ids: vec![capability],
            },
            desired_state: BTreeMap::from([("completed".into(), "true".into())]),
        };
        let principal = value(AuthenticatedPrincipal::new("unix:uid:1000"));
        let native = ObservationEnvelope {
            provider: request.provider.clone(),
            resource: request.resource.clone(),
            capability: request.observation_capability.clone(),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: 0, // Each independent case samples immediately before review.
            valid_for_ms: 2_000,
            sequence: 1,
            attributes: BTreeMap::from([
                (
                    "current_boot_id".into(),
                    ObservedValue::Text(target.lock().epoch().boot().as_str().into()),
                ),
                ("target_epoch_present".into(), ObservedValue::Bool(true)),
                (
                    "suspend_test_mode".into(),
                    ObservedValue::Text("none".into()),
                ),
                ("preparing_for_sleep".into(), ObservedValue::Bool(false)),
                ("successful_suspend_cycles".into(), ObservedValue::U64(11)),
            ]),
        };
        // A missing observer makes every attempted provider query observable as
        // an Observation error. Pending/invalid classification must precede it.
        let mut control = PlanPreviewControl::new(ObservationCoordinator::new());
        for (key, fact) in [
            ("preparing_for_sleep", ObservedValue::Bool(true)),
            ("preparing_for_sleep", ObservedValue::Text("false".into())),
            ("successful_suspend_cycles", ObservedValue::U64(12)),
            (
                "successful_suspend_cycles",
                ObservedValue::Text("11".into()),
            ),
            ("suspend_test_mode", ObservedValue::Text("devices".into())),
            ("target_epoch_present", ObservedValue::Bool(false)),
        ] {
            let mut changed = native.clone();
            changed.attributes.insert(key.into(), fact);
            let mut changed = sample_now(&changed);
            assert!(matches!(
                control.session_power_plan_facts(&principal, &request, &mut changed),
                Err(PlanPreviewControlError::Planning { .. })
            ));
        }
        // Exact completion still requires a real independent coverage query;
        // the native facts alone cannot produce a completed plan.
        let mut completed = sample_now(&native);
        assert!(matches!(
            control.session_power_plan_facts(&principal, &request, &mut completed),
            Err(PlanPreviewControlError::Observation { .. })
        ));
    }
}
