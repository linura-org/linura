//! Control-derived ordinary terminal planning. Neither this private scoped
//! context nor a canonical plan is authority to release native protection.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use linura_core::{Actor, CapabilityId, DisplayOrdinaryReleaseMaterial, ProviderId};
use linura_observation::{
    DISPLAY_COVERAGE_CAPABILITY, DISPLAY_ORDINARY_ORIGINAL_CAPABILITY, DISPLAY_OUTPUTS_CAPABILITY,
    DISPLAY_PROVIDER, DISPLAY_RECOVERY_PROVIDER, DisplayObservationFacts,
    DisplayOrdinaryOriginalFacts, ObservationEnvelope, ObservedValue,
};
use linura_planner::{
    DesiredResource, DeterministicPlanner, PlanFinding, PlanFindingLevel, PlanningFreshness,
    PlanningObservation, ReconciliationPlan,
};
use linura_protocol::{ObservationRequest, PlanDesiredStateRequest};
use linura_transaction::ContentDigest;

use crate::{AuthenticatedPrincipal, PlanPreviewControl, PlanPreviewControlError};

#[derive(Debug)]
pub(crate) struct OrdinaryReleasePlanningContext {
    pub(crate) principal: AuthenticatedPrincipal,
    pub(crate) material: String,
    pub(crate) root: DisplayOrdinaryOriginalFacts,
    pub(crate) observation: ObservationEnvelope,
}
#[derive(Debug)]
struct BoundContext {
    source: OrdinaryReleasePlanningContext,
    request: ContentDigest,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct OrdinaryReleaseContextSlot(Arc<Mutex<Option<Arc<BoundContext>>>>);
pub(crate) struct OrdinaryReleaseContextGuard {
    slot: OrdinaryReleaseContextSlot,
    bound: Arc<BoundContext>,
}
impl Drop for OrdinaryReleaseContextGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.slot.0.lock()
            && slot
                .as_ref()
                .is_some_and(|bound| Arc::ptr_eq(bound, &self.bound))
        {
            *slot = None;
        }
    }
}
impl PlanPreviewControl {
    pub(crate) fn enter_ordinary_display_release_context(
        &mut self,
        source: OrdinaryReleasePlanningContext,
        request: &PlanDesiredStateRequest,
    ) -> Result<OrdinaryReleaseContextGuard, PlanPreviewControlError> {
        let material = DisplayOrdinaryReleaseMaterial::decode(&source.material).map_err(fail)?;
        let scope = material.release_scope().map_err(fail)?;
        let effect =
            linura_provider_sdk::display_ordinary_release_effect(&source.material).map_err(fail)?;
        source
            .observation
            .require_current(now_ms()?)
            .map_err(fail)?;
        if source.principal.as_str()
            != format!("unix:uid:{}", material.current_lock().epoch().uid())
            || source.root.scope() != &scope
            || source.root.comparison().material != material.original_text()
            || source.root.comparison().checkpoint != material.lineage().original_checkpoint
            || source.observation.resource != request.resource
            || source.observation.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || source.observation.capability.as_str() != DISPLAY_ORDINARY_ORIGINAL_CAPABILITY
            || request.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || request.observation_capability.as_str() != DISPLAY_ORDINARY_ORIGINAL_CAPABILITY
            || request.resource != effect.resource
            || request.desired_state
                != BTreeMap::from([(
                    "release_ordinary".into(),
                    String::from_utf8(effect.canonical_payload).map_err(fail)?,
                )])
        {
            return Err(fail(
                "ordinary release context differs from authenticated terminal history",
            ));
        }
        let bound = Arc::new(BoundContext {
            source,
            request: crate::durable_authority::digest_request(request).map_err(fail)?,
        });
        let mut slot = self
            .ordinary_release_context
            .0
            .try_lock()
            .map_err(|_| fail("ordinary release planning context unavailable"))?;
        if slot.is_some() {
            return Err(fail("ordinary release planning context already in use"));
        }
        *slot = Some(Arc::clone(&bound));
        Ok(OrdinaryReleaseContextGuard {
            slot: self.ordinary_release_context.clone(),
            bound,
        })
    }

    pub(crate) fn build_fresh_ordinary_display_release_plan(
        &mut self,
        principal: &AuthenticatedPrincipal,
        actor: Actor,
        request: &PlanDesiredStateRequest,
    ) -> Result<(ReconciliationPlan, ObservationEnvelope), PlanPreviewControlError> {
        // Reject client-authored generic previews before invoking any provider.
        let bound = self
            .ordinary_release_context
            .0
            .try_lock()
            .map_err(|_| fail("ordinary release context unavailable"))?
            .as_ref()
            .cloned()
            .ok_or_else(|| fail("ordinary release requires authenticated terminal history"))?;
        if &bound.source.principal != principal
            || bound.request != crate::durable_authority::digest_request(request).map_err(fail)?
        {
            return Err(fail("ordinary release principal or exact request changed"));
        }
        let material =
            DisplayOrdinaryReleaseMaterial::decode(&bound.source.material).map_err(fail)?;
        let scope = material.release_scope().map_err(fail)?;
        let query = |provider: &str,
                     capability: &str,
                     resource|
         -> Result<ObservationRequest, PlanPreviewControlError> {
            Ok(ObservationRequest {
                provider: ProviderId::new(provider).map_err(fail)?,
                capability: CapabilityId::new(capability).map_err(fail)?,
                resource,
            })
        };
        let root_query = query(
            DISPLAY_RECOVERY_PROVIDER,
            DISPLAY_ORDINARY_ORIGINAL_CAPABILITY,
            request.resource.clone(),
        )?;
        let display_query = query(
            DISPLAY_PROVIDER,
            DISPLAY_OUTPUTS_CAPABILITY,
            scope.topology().resource_id().map_err(fail)?,
        )?;
        let root = self.observe(&root_query)?.observation;
        let display = self.observe(&display_query)?.observation;
        let session = self
            .observe(&query(
                "logind",
                "session.epoch.observe",
                scope.topology().session().resource_id().map_err(fail)?,
            )?)?
            .observation;
        let coverage = self
            .observe(&query(
                "session-locker",
                DISPLAY_COVERAGE_CAPABILITY,
                material.current_lock().resource_id().map_err(fail)?,
            )?)?
            .observation;
        let after_display = self.observe(&display_query)?.observation;
        let after_root = self.observe(&root_query)?.observation;
        let now = now_ms()?;
        let facts = DisplayObservationFacts::from_envelope(&display, scope.topology(), now)
            .map_err(fail)?;
        let checked = DisplayObservationFacts::from_envelope(&after_display, scope.topology(), now)
            .map_err(fail)?;
        let desired = material
            .validate_native(facts.inventory(), facts.capabilities())
            .map_err(fail)?;
        if DisplayOrdinaryOriginalFacts::from_envelope(&root, &scope, now).map_err(fail)?
            != bound.source.root
            || DisplayOrdinaryOriginalFacts::from_envelope(&after_root, &scope, now)
                .map_err(fail)?
                != bound.source.root
            || after_root.sequence <= root.sequence
            || after_display.sequence <= display.sequence
            || facts != checked
            || facts.layout() != &desired
            || linura_provider_sdk::display_baseline_guard(&facts)
                .map_err(fail)?
                .to_hex()
                != material.lineage().current_source_guard
        {
            return Err(fail(
                "ordinary release Root, layout or complete source ownership changed",
            ));
        }
        crate::DisplayLayoutSafetyReview::review(
            principal, &desired, &display, &session, &coverage, now,
        )
        .map_err(fail)?;
        let mut joined = root.clone();
        for (name, sample) in [
            ("terminal_inspection", &bound.source.observation),
            ("display", &display),
            ("session", &session),
            ("coverage", &coverage),
            ("rechecked_display", &after_display),
            ("rechecked_root", &after_root),
        ] {
            crate::plan_preview::restrict_session_validity(&mut joined, sample, now)?;
            joined.attributes.insert(
                format!("control.ordinary.{name}_digest"),
                ObservedValue::Text(
                    crate::durable_authority::digest_observation(sample)
                        .map_err(fail)?
                        .as_str()
                        .into(),
                ),
            );
        }
        let observation = PlanningObservation {
            provider: joined.provider.clone(),
            resource: joined.resource.clone(),
            observation_capability: joined.capability.clone(),
            authority: joined.authority.as_str().into(),
            evidence_id: joined.evidence_id(),
            freshness: PlanningFreshness::Current,
            attributes: BTreeMap::from([("release_ordinary".into(), "protection retained".into())]),
        };
        let mut plan = DeterministicPlanner
            .plan_resource(
                request.request_id.clone(),
                actor,
                DesiredResource {
                    provider: request.provider.clone(),
                    resource: request.resource.clone(),
                    observation_capability: request.observation_capability.clone(),
                    state: request.desired_state.clone(),
                    reason: request.reason.clone(),
                },
                &observation,
            )
            .map_err(fail)?;
        plan.findings.push(PlanFinding { code: "display-ordinary-release-lineage".into(), level: PlanFindingLevel::Pass,
            message: format!("Separate {} release of original {} / terminal {} / signed binding {} / complete source guard {}; physical handoff remains independently required", material.outcome().as_str(), material.lineage().original_request.as_str(), material.lineage().terminal_record, material.lineage().signed_binding, material.lineage().current_source_guard) });
        joined.require_current(now_ms()?).map_err(fail)?;
        Ok((plan, joined))
    }
}
fn fail(error: impl ToString) -> PlanPreviewControlError {
    PlanPreviewControlError::Planning {
        reason: error.to_string(),
    }
}
fn now_ms() -> Result<u64, PlanPreviewControlError> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(fail)?
            .as_millis(),
    )
    .map_err(fail)
}
