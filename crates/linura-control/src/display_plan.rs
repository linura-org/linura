//! One canonical fresh display-plan derivation shared by previews and managed
//! authority. Native providers supply facts; Control binds independent session,
//! lock coverage, recovery baseline and complete desired layout into the plan.
use crate::{
    AuthenticatedPrincipal, DisplayLayoutSafetyReview, PlanPreviewControl, PlanPreviewControlError,
};
use linura_core::{
    Actor, CapabilityId, DisplayLayout, DisplayLayoutIntent, DisplayLayoutMaterial, ProviderId,
    RequestId, SemanticReason, SessionLockId,
};
use linura_observation::{
    DISPLAY_OUTPUTS_CAPABILITY, DISPLAY_PROVIDER, DisplayObservationFacts, ObservationEnvelope,
    ObservedValue,
};
use linura_planner::{
    DesiredResource, DeterministicPlanner, PlanFinding, PlanFindingLevel, PlanningFreshness,
    PlanningObservation, ReconciliationPlan,
};
use linura_protocol::{ObservationRequest, PlanDesiredStateRequest};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayLayoutPlanRequest {
    pub request_id: RequestId,
    pub baseline: DisplayLayout,
    pub layout: DisplayLayout,
    pub lock: SessionLockId,
    pub reason: SemanticReason,
}
impl DisplayLayoutPlanRequest {
    pub fn desired_request(&self) -> Result<PlanDesiredStateRequest, PlanPreviewControlError> {
        let intent = DisplayLayoutIntent::new(
            self.lock.clone(),
            self.baseline.clone(),
            self.layout.clone(),
        )
        .map_err(fail)?;
        Ok(PlanDesiredStateRequest {
            request_id: self.request_id.clone(),
            provider: ProviderId::new(DISPLAY_PROVIDER).map_err(fail)?,
            resource: self.layout.topology().resource_id().map_err(fail)?,
            observation_capability: CapabilityId::new(DISPLAY_OUTPUTS_CAPABILITY).map_err(fail)?,
            desired_state: BTreeMap::from([(
                "layout".into(),
                intent.canonical_text().map_err(fail)?,
            )]),
            reason: self.reason.clone(),
        })
    }
}
impl PlanPreviewControl {
    pub fn plan_display_layout(
        &mut self,
        principal: &AuthenticatedPrincipal,
        actor: Actor,
        request: &DisplayLayoutPlanRequest,
    ) -> Result<ReconciliationPlan, PlanPreviewControlError> {
        let desired = request.desired_request()?;
        let input =
            crate::plan_preview::NormalizedPlanInput::new(principal.clone(), desired.clone())?;
        if let Some(retained) = self.replay_display_preview(&input)? {
            return Ok(retained);
        }
        let (plan, _) = self.build_fresh_display_plan(principal, actor, &desired)?;
        self.retain_display_preview(input, plan.clone())?;
        Ok(plan)
    }

    pub(super) fn build_fresh_display_plan(
        &mut self,
        principal: &AuthenticatedPrincipal,
        actor: Actor,
        request: &PlanDesiredStateRequest,
    ) -> Result<(ReconciliationPlan, ObservationEnvelope), PlanPreviewControlError> {
        if request.provider.as_str() != DISPLAY_PROVIDER
            || request.observation_capability.as_str() != DISPLAY_OUTPUTS_CAPABILITY
            || request.desired_state.len() != 1
        {
            return Err(fail("display request has an unsupported effect shape"));
        }
        let text = request
            .desired_state
            .get("layout")
            .ok_or_else(|| fail("display intent is missing"))?;
        let material = DisplayLayoutMaterial::decode(text).map_err(fail)?;
        let topology = material.topology();
        if topology.resource_id().map_err(fail)? != request.resource {
            return Err(fail("display intent refers to another topology"));
        }
        let mut display = self
            .observe(&ObservationRequest {
                provider: request.provider.clone(),
                capability: request.observation_capability.clone(),
                resource: request.resource.clone(),
            })?
            .observation;
        let session = self
            .observe(&ObservationRequest {
                provider: ProviderId::new("logind").map_err(fail)?,
                capability: CapabilityId::new("session.epoch.observe").map_err(fail)?,
                resource: topology.session().resource_id().map_err(fail)?,
            })?
            .observation;
        let locker = self
            .observe(&ObservationRequest {
                provider: ProviderId::new("session-locker").map_err(fail)?,
                capability: CapabilityId::new(linura_observation::DISPLAY_COVERAGE_CAPABILITY)
                    .map_err(fail)?,
                resource: material.lock().resource_id().map_err(fail)?,
            })?
            .observation;
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(fail)?
                .as_millis(),
        )
        .map_err(fail)?;
        let facts =
            DisplayObservationFacts::from_envelope(&display, topology, now).map_err(fail)?;
        let intent = material
            .validate_native(facts.inventory(), facts.capabilities())
            .map_err(fail)?;
        if intent.canonical_text().map_err(fail)? != *text {
            return Err(fail("display intent is not canonical"));
        }
        if facts.layout() != intent.desired() && facts.layout() != intent.baseline() {
            return Err(fail(
                "native layout drifted from the exact recovery baseline",
            ));
        }
        let safety = DisplayLayoutSafetyReview::review(
            principal,
            intent.desired(),
            &display,
            &session,
            &locker,
            now,
        )
        .map_err(fail)?;
        let findings = [&display, &session, &locker]
            .into_iter()
            .map(native_finding)
            .collect::<Vec<_>>();
        let observed_intent = DisplayLayoutIntent::new(
            intent.lock().clone(),
            intent.baseline().clone(),
            safety.last_known_good().clone(),
        )
        .map_err(fail)?;
        // Narrow all contributing deadlines and bind their exact canonical
        // envelopes. These Control-derived fields are never provider authority.
        crate::plan_preview::restrict_session_validity(&mut display, &session, now)?;
        crate::plan_preview::restrict_session_validity(&mut display, &locker, now)?;
        for (key, source) in [
            ("control.display_session_digest", &session),
            ("control.display_coverage_digest", &locker),
        ] {
            display.attributes.insert(
                key.into(),
                ObservedValue::Text(
                    crate::durable_authority::digest_observation(source)
                        .map_err(fail)?
                        .as_str()
                        .into(),
                ),
            );
        }
        let observation = PlanningObservation {
            provider: display.provider.clone(),
            resource: display.resource.clone(),
            observation_capability: display.capability.clone(),
            authority: display.authority.as_str().into(),
            evidence_id: display.evidence_id(),
            freshness: PlanningFreshness::Current,
            attributes: BTreeMap::from([(
                "layout".into(),
                observed_intent.canonical_text().map_err(fail)?,
            )]),
        };
        let desired = DesiredResource {
            provider: request.provider.clone(),
            resource: request.resource.clone(),
            observation_capability: request.observation_capability.clone(),
            state: request.desired_state.clone(),
            reason: request.reason.clone(),
        };
        let mut plan = DeterministicPlanner
            .plan_resource(request.request_id.clone(), actor, desired, &observation)
            .map_err(fail)?;
        plan.findings.extend(findings);
        plan.findings.push(PlanFinding {
            code: "display-managed-activation-unavailable".into(),
            level: PlanFindingLevel::Warning,
            message: "Native mutation and recovery qualification remain required before activation"
                .into(),
        });
        Ok((plan, display))
    }
}

fn native_finding(source: &ObservationEnvelope) -> PlanFinding {
    let attributes: BTreeMap<_, _> = source
        .attributes
        .iter()
        .filter(|(key, _)| {
            source.provider.as_str() == DISPLAY_PROVIDER
                || matches!(
                    key.as_str(),
                    "boot_id"
                        | "session_id"
                        | "uid"
                        | "created_monotonic_us"
                        | "session_type"
                        | "session_class"
                        | "state"
                        | "active"
                        | "remote"
                        | "seat"
                        | "leader_present"
                        | "lock_generation"
                        | "security_owner_invocation"
                        | "lock_protocol"
                        | "secure"
                        | "display_topology"
                        | "observed_outputs"
                        | "covered_outputs"
                )
        })
        .collect();
    PlanFinding {
        code: format!("native-display-{}", source.capability.as_str()),
        level: PlanFindingLevel::Pass,
        // Exact material semantics enter canonical plan lineage. Native adapters
        // must emit sanitized facts; probe times/counters grant no authority.
        message: format!(
            "NativeApi {}/{}/{}: {:?}",
            source.provider.as_str(),
            source.capability.as_str(),
            source.resource.as_str(),
            attributes
        ),
    }
}

fn fail(error: impl ToString) -> PlanPreviewControlError {
    PlanPreviewControlError::Planning {
        reason: error.to_string(),
    }
}
