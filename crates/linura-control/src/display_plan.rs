//! Display preview composition through the canonical observation coordinator
//! and deterministic planner. No native observer or executable operation is
//! registered here. A preview never authorizes an external effect.

use crate::{
    AuthenticatedPrincipal, DisplayLayoutSafetyReview, PlanPreviewControl, PlanPreviewControlError,
};
use linura_core::{
    Actor, CapabilityId, DisplayLayout, ProviderId, RequestId, SemanticReason, SessionLockId,
};
use linura_observation::{DISPLAY_OUTPUTS_CAPABILITY, DISPLAY_PROVIDER, ObservationEnvelope};
use linura_planner::{
    DesiredResource, DeterministicPlanner, PlanFinding, PlanFindingLevel, PlanningFreshness,
    PlanningObservation, ReconciliationPlan,
};
use linura_protocol::{ObservationRequest, PlanDesiredStateRequest};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayLayoutPlanRequest {
    pub request_id: RequestId,
    pub layout: DisplayLayout,
    pub lock: SessionLockId,
    pub reason: SemanticReason,
}

impl PlanPreviewControl {
    /// Re-observe each independent source through Control. Supplied lock and
    /// layout are correlation/intent, never native coverage or authority.
    pub fn plan_display_layout(
        &mut self,
        principal: &AuthenticatedPrincipal,
        actor: Actor,
        request: &DisplayLayoutPlanRequest,
    ) -> Result<ReconciliationPlan, PlanPreviewControlError> {
        let topology = request.layout.topology();
        if request.lock.epoch() != topology.session() {
            return Err(fail(
                "display and lock target different session generations",
            ));
        }
        let input = crate::plan_preview::NormalizedPlanInput::display(
            principal.clone(),
            PlanDesiredStateRequest {
                request_id: request.request_id.clone(),
                provider: ProviderId::new(DISPLAY_PROVIDER).map_err(fail)?,
                resource: topology.resource_id().map_err(fail)?,
                observation_capability: CapabilityId::new(DISPLAY_OUTPUTS_CAPABILITY)
                    .map_err(fail)?,
                desired_state: BTreeMap::from([(
                    "layout".into(),
                    request.layout.canonical_text().map_err(fail)?,
                )]),
                reason: request.reason.clone(),
            },
            request.lock.clone(),
        )?;
        if let Some(retained) = self.replay_display_preview(&input)? {
            return Ok(retained);
        }
        let display = self
            .observe(&ObservationRequest {
                provider: ProviderId::new(DISPLAY_PROVIDER).map_err(fail)?,
                capability: CapabilityId::new(DISPLAY_OUTPUTS_CAPABILITY).map_err(fail)?,
                resource: topology.resource_id().map_err(fail)?,
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
                capability: CapabilityId::new("session.secure-lock.observe").map_err(fail)?,
                resource: request.lock.resource_id().map_err(fail)?,
            })?
            .observation;
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(fail)?
                .as_millis(),
        )
        .map_err(fail)?;
        let safety = DisplayLayoutSafetyReview::review(
            principal,
            &request.layout,
            &display,
            &session,
            &locker,
            now,
        )
        .map_err(fail)?;
        let desired = DesiredResource {
            provider: display.provider.clone(),
            resource: display.resource.clone(),
            observation_capability: display.capability.clone(),
            state: BTreeMap::from([(
                "layout".into(),
                safety.desired_layout().canonical_text().map_err(fail)?,
            )]),
            reason: request.reason.clone(),
        };
        let observation = PlanningObservation {
            provider: display.provider.clone(),
            resource: display.resource.clone(),
            observation_capability: display.capability.clone(),
            authority: display.authority.as_str().into(),
            evidence_id: display.evidence_id(),
            freshness: PlanningFreshness::Current,
            attributes: BTreeMap::from([(
                "layout".into(),
                safety.last_known_good().canonical_text().map_err(fail)?,
            )]),
        };
        let mut plan = DeterministicPlanner
            .plan_resource(request.request_id.clone(), actor, desired, &observation)
            .map_err(fail)?;
        for source in [&display, &session, &locker] {
            plan.findings.push(native_finding(source));
        }
        plan.findings.push(PlanFinding {
            code: "display-managed-activation-unavailable".into(),
            level: PlanFindingLevel::Warning,
            message: "Non-executable preview only; native generation/coverage qualification, durable recovery and registered managed dispatch remain required".into(),
        });
        self.retain_display_preview(input, plan.clone())?;
        Ok(plan)
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
