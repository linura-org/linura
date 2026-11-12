//! Canonical terminal planning from authenticated linked history and fresh facts.
//! A private scoped context is necessary even for preview. Neither the context,
//! the resulting plan nor retained completion data authorizes native release.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use linura_core::{Actor, DisplayFinalizationMaterial, PrincipalId};
use linura_observation::{
    DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY, DISPLAY_RECOVERY_PROVIDER, DisplayFinalizationPhase,
    DisplayOriginalFinalizationFacts, ObservationEnvelope, ObservedValue,
};
use linura_planner::{
    DesiredResource, DeterministicPlanner, PlanFinding, PlanFindingLevel, PlanStatus,
    PlanningFreshness, PlanningObservation, ReconciliationPlan,
};
use linura_protocol::{ObservationRequest, PlanDesiredStateRequest};
use linura_transaction::{ContentDigest, TransactionId, TransactionSnapshot, TransactionState};

use crate::display_recovery_journal::{Phase, Record};
use crate::display_restoration_plan::OriginalDisplayPlanningContext;
use crate::{AuthenticatedPrincipal, PlanPreviewControl, PlanPreviewControlError};

/// Only ManagedLifecycleControl constructs this after loading/authenticating both
/// actual requests, their exact terminal snapshots, immutable link and checkpoint.
#[derive(Clone, Debug)]
pub(crate) struct FinalizationPlanningContext {
    pub(crate) principal: AuthenticatedPrincipal,
    pub(crate) original: OriginalDisplayPlanningContext,
    pub(crate) restoration: PlanDesiredStateRequest,
    pub(crate) snapshot: TransactionSnapshot,
    pub(crate) dispatched: Record,
    pub(crate) link: ContentDigest,
    pub(crate) material: String,
}

#[derive(Debug)]
struct BoundContext {
    source: FinalizationPlanningContext,
    request: ContentDigest,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct FinalizationContextSlot(Arc<Mutex<Option<Arc<BoundContext>>>>);
pub(crate) struct FinalizationContextGuard {
    slot: FinalizationContextSlot,
    context: Arc<BoundContext>,
}
impl Drop for FinalizationContextGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.slot.0.lock()
            && slot
                .as_ref()
                .is_some_and(|entry| Arc::ptr_eq(entry, &self.context))
        {
            *slot = None;
        }
    }
}

impl PlanPreviewControl {
    pub(crate) fn enter_original_display_finalization_context(
        &mut self,
        source: FinalizationPlanningContext,
        request: &PlanDesiredStateRequest,
    ) -> Result<FinalizationContextGuard, PlanPreviewControlError> {
        let principal = PrincipalId::new(source.principal.as_str()).map_err(fail)?;
        let material = DisplayFinalizationMaterial::decode(&source.material).map_err(fail)?;
        if source.snapshot.state != TransactionState::Committed
            || material.terminal_link() != source.link.hex()
            || source.snapshot.principal != principal
            || source.snapshot.request_id != source.restoration.request_id
            || source.snapshot.transaction_id
                != TransactionId::for_namespace(&principal, &source.restoration.request_id)
            || material.restoration_request() != &source.restoration.request_id
            || source
                .restoration
                .desired_state
                .get("restore_original")
                .map(String::as_str)
                != Some(material.restoration_text())
            || source.dispatched.phase != Phase::Dispatched
            || source.dispatched.transaction_id != source.snapshot.transaction_id
            || source.dispatched.request_digest
                != crate::durable_authority::digest_request(&source.restoration).map_err(fail)?
            || source.dispatched.dispatch_digest.as_deref() != Some(material.restoration_dispatch())
            || request.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || request.observation_capability.as_str() != DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY
            || request.resource
                != material
                    .recovery_scope()
                    .map_err(fail)?
                    .resource_id()
                    .map_err(fail)?
            || request.desired_state.len() != 1
            || request
                .desired_state
                .get("finalize_original")
                .map(String::as_bytes)
                != Some(
                    linura_provider_sdk::display_finalization_effect(&source.material)
                        .map_err(fail)?
                        .canonical_payload
                        .as_slice(),
                )
        {
            return Err(fail(
                "terminal planning differs from authenticated linked restoration",
            ));
        }
        let context = Arc::new(BoundContext {
            source,
            request: crate::durable_authority::digest_request(request).map_err(fail)?,
        });
        let mut slot = self
            .finalization_context
            .0
            .try_lock()
            .map_err(|_| fail("terminal planning context unavailable"))?;
        if slot.is_some() {
            return Err(fail("terminal planning context is already in use"));
        }
        *slot = Some(Arc::clone(&context));
        Ok(FinalizationContextGuard {
            slot: self.finalization_context.clone(),
            context,
        })
    }

    /// Canonical post-effect NoChange planning from Control's independently
    /// joined, phase-specific current inspection. Historical nested first
    /// frames remain comparison data; the actual Root/current/lock/input/power
    /// contributors and their fixed deadlines are retained in this envelope.
    /// This produces no policy allow, dispatch permit or native credential.
    pub(crate) fn build_verified_original_display_current_plan(
        &self,
        principal: &AuthenticatedPrincipal,
        actor: Actor,
        request: &PlanDesiredStateRequest,
        inspection: &crate::OriginalDisplayRootPowerInspection,
    ) -> Result<(ReconciliationPlan, ObservationEnvelope), PlanPreviewControlError> {
        let current = inspection.current();
        let root = inspection.root();
        let observation = current.observation();
        let now = now_ms()?;
        observation.require_current(now).map_err(fail)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(fail)?;
        let effect = linura_provider_sdk::display_finalization_effect(
            &root.completion_comparison().lineage().material,
        )
        .map_err(fail)?;
        let material =
            DisplayFinalizationMaterial::decode(&root.completion_comparison().lineage().material)
                .map_err(fail)?;
        let scope = material.recovery_scope().map_err(fail)?;
        let mut expected = root.attributes();
        let mut contributors = std::collections::BTreeSet::new();
        for name in [
            "protection",
            "display",
            "session",
            "coverage",
            "current",
            "rechecked_current",
            "rechecked_root",
            "rechecked_protection",
        ] {
            let key = format!("control.current.{name}_digest");
            let Some(ObservedValue::Text(raw)) = observation.attributes.get(&key) else {
                return Err(fail("current postcondition contributor missing"));
            };
            let digest = ContentDigest::new(raw).map_err(fail)?;
            if digest == ContentDigest::zero() || !contributors.insert(digest) {
                return Err(fail("current postcondition contributors are ambiguous"));
            }
            expected.insert(key, ObservedValue::Text(raw.clone()));
        }
        if current.terminal().principal != principal_id
            || current.terminal().request_id != request.request_id
            || current.terminal().transaction_id
                != TransactionId::for_namespace(&principal_id, &request.request_id)
            || current.comparison_terminal().state != TransactionState::Indeterminate
            || !request
                .request_id
                .as_str()
                .starts_with("request:v010:display-finalization:")
            || request.provider != effect.provider
            || request.resource != effect.resource
            || request.observation_capability.as_str() != DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY
            || request.desired_state.len() != 1
            || request
                .desired_state
                .get("finalize_original")
                .map(String::as_bytes)
                != Some(effect.canonical_payload.as_slice())
            || observation.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || observation.capability.as_str()
                != linura_observation::DISPLAY_ORIGINAL_ROOT_RETIREMENT_CAPABILITY
            || observation.resource != request.resource
            || observation.authority != linura_observation::ObservationAuthority::NativeApi
            || observation.sequence == 0
            || observation.valid_for_ms > 2000
            || observation.attributes != expected
            || current.frames().scope() != &scope
            || !current
                .frames()
                .follows_handoff(root.completion_comparison().first())
            || current.frames().completion_digest() != root.completion_comparison().lineage().record
            || current.frames().power_fence_held()
            || !current.frames().input_retired()
        {
            return Err(fail("canonical original-current completion proof changed"));
        }
        // The post-effect evidence capability is derived from the actual join,
        // never selected by a client or substituted into the earlier review.
        let observed = PlanningObservation {
            provider: observation.provider.clone(),
            resource: observation.resource.clone(),
            observation_capability: observation.capability.clone(),
            authority: observation.authority.as_str().into(),
            evidence_id: observation.evidence_id(),
            freshness: PlanningFreshness::Current,
            attributes: request.desired_state.clone(),
        };
        let desired = DesiredResource {
            provider: request.provider.clone(),
            resource: request.resource.clone(),
            observation_capability: observation.capability.clone(),
            state: request.desired_state.clone(),
            reason: request.reason.clone(),
        };
        let mut plan = DeterministicPlanner
            .plan_resource(request.request_id.clone(), actor, desired, &observed)
            .map_err(fail)?;
        if plan.status != PlanStatus::NoChange
            || !plan.changes.is_empty()
            || plan.execution_authorized()
        {
            return Err(fail(
                "original-current verification cannot authorize execution",
            ));
        }
        plan.findings.push(PlanFinding{code:"display-original-current-postcondition".into(),level:PlanFindingLevel::Pass,message:"Independent original Root/kernel/power absence, current native scanout/input, source, login and S17 proof; future admission and provenance remain retained".into()});
        observation.require_current(now_ms()?).map_err(fail)?;
        Ok((plan, observation.clone()))
    }

    pub(super) fn build_fresh_original_display_finalization_plan(
        &mut self,
        principal: &AuthenticatedPrincipal,
        actor: Actor,
        request: &PlanDesiredStateRequest,
    ) -> Result<(ReconciliationPlan, ObservationEnvelope), PlanPreviewControlError> {
        // Reject generic/client-authored previews before probing a provider.
        let bound = self
            .finalization_context
            .0
            .try_lock()
            .map_err(|_| fail("terminal planning context unavailable"))?
            .as_ref()
            .cloned()
            .ok_or_else(|| fail("terminal planning requires authenticated linked history"))?;
        if bound.source.principal != *principal
            || bound.request != crate::durable_authority::digest_request(request).map_err(fail)?
            || request.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || request.observation_capability.as_str() != DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY
            || request.desired_state.len() != 1
            || request
                .desired_state
                .get("finalize_original")
                .map(String::as_bytes)
                != Some(
                    linura_provider_sdk::display_finalization_effect(&bound.source.material)
                        .map_err(fail)?
                        .canonical_payload
                        .as_slice(),
                )
        {
            return Err(fail(
                "terminal context is bound to another exact principal/request",
            ));
        }
        let material = DisplayFinalizationMaterial::decode(&bound.source.material).map_err(fail)?;
        let scope = material.recovery_scope().map_err(fail)?;
        if request.resource != scope.resource_id().map_err(fail)? {
            return Err(fail("terminal request changed recovery scope"));
        }
        let mut mechanism = self
            .observe(&ObservationRequest {
                provider: request.provider.clone(),
                capability: request.observation_capability.clone(),
                resource: request.resource.clone(),
            })?
            .observation;
        let state = DisplayOriginalFinalizationFacts::from_envelope(&mechanism, &scope, now_ms()?)
            .map_err(fail)?;
        let restoration_effect =
            linura_provider_sdk::display_restoration_effect(material.restoration_text())
                .map_err(fail)?;
        if state.phase() != DisplayFinalizationPhase::Protected
            || state.terminal().is_some()
            || state.checkpoint() != material.restoration().original_checkpoint()
            || state.restoration_transaction() != bound.source.snapshot.transaction_id.as_str()
            || state.restoration_effect() != restoration_effect.digest().to_hex()
            || state.restoration_dispatch() != material.restoration_dispatch()
        {
            return Err(fail(
                "terminal Root state differs from authenticated restoration",
            ));
        }
        let proof = {
            let _context = self.enter_original_display_verification_context(
                bound.source.original.clone(),
                &bound.source.restoration,
                &bound.source.snapshot,
                &bound.source.dispatched,
            )?;
            self.build_fresh_original_display_restoration_proof(
                principal,
                actor.clone(),
                &bound.source.restoration,
            )?
        };
        let presentation = proof
            .presentation
            .as_ref()
            .ok_or_else(|| fail("terminal planning lacks independent post-write presentation"))?;
        if proof.plan.status != PlanStatus::NoChange
            || !proof.plan.changes.is_empty()
            || proof.plan.execution_authorized()
            || presentation.source_guard() != material.restored_source_guard()
            || presentation.post_write_epoch() != material.post_write_epoch()
            || material.current_lock() != material.restoration().replacement().lock()
        {
            return Err(fail(
                "terminal restored sources, epoch, lock or physical proof changed",
            ));
        }
        let mut findings = proof.plan.findings;
        // Exact fresh contributor bytes remain in the observation digest below.
        // They are not stable human intent: a nested evidence ID or a later
        // valid frame cannot manufacture a different release operation. Retain
        // every finding, replacing only these two already-validated projections.
        let mut observations = 0;
        let mut presentations = 0;
        for finding in &mut findings {
            if finding.code == "authoritative-observation" {
                observations += 1;
                finding.code = "display-terminal-restoration-proof".into();
                finding.message = "Fresh canonical five-source restoration proof; exact contributors remain bound in the terminal observation".into();
            } else if finding.code
                == format!(
                    "native-display-{}",
                    linura_observation::DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY
                )
            {
                presentations += 1;
                finding.message = format!(
                    "Fresh physical post-write proof for restoration {} / checkpoint {} / source {} / epoch {} and its complete output inventory",
                    material.restoration_request().as_str(),
                    material.restoration().original_checkpoint(),
                    material.restored_source_guard(),
                    material.post_write_epoch()
                );
            }
        }
        if observations != 1 || presentations != 1 {
            return Err(fail(
                "terminal canonical restoration proof contributors changed",
            ));
        }
        findings.push(crate::display_plan::native_finding(&mechanism));
        crate::plan_preview::restrict_session_validity(
            &mut mechanism,
            &proof.observation,
            now_ms()?,
        )?;
        mechanism.attributes.insert(
            "control.restoration_postcondition_digest".into(),
            ObservedValue::Text(
                crate::durable_authority::digest_observation(&proof.observation)
                    .map_err(fail)?
                    .as_str()
                    .into(),
            ),
        );
        let observed = PlanningObservation {
            provider: mechanism.provider.clone(),
            resource: mechanism.resource.clone(),
            observation_capability: mechanism.capability.clone(),
            authority: mechanism.authority.as_str().into(),
            evidence_id: mechanism.evidence_id(),
            freshness: PlanningFreshness::Current,
            attributes: BTreeMap::from([(
                "finalize_original".into(),
                "protection retained".into(),
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
            .plan_resource(request.request_id.clone(), actor, desired, &observed)
            .map_err(fail)?;
        plan.findings.extend(findings);
        plan.findings.push(PlanFinding {
            code: "display-original-finalization".into(), level: PlanFindingLevel::Pass,
            message: format!("Finalize only linked restoration {} with source guard {} and post-write epoch {}; preserve the real session lock and quarantine held input before ordinary focus", material.restoration_request().as_str(), material.restored_source_guard(), material.post_write_epoch()),
        });
        mechanism.require_current(now_ms()?).map_err(fail)?;
        Ok((plan, mechanism))
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

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{
        ActorId, ActorKind, CapabilityId, DisplayRestorationMaterial, ProviderId, RequestId,
        SemanticReason,
    };
    use linura_observation_control::ObservationCoordinator;
    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    #[test]
    fn client_terminal_bytes_cannot_establish_private_history_or_probe_a_provider() {
        let original =
            include_str!("../../linura-core/src/display_recovery/fixtures/original-baseline.txt")
                .trim_end();
        let restoration = value(DisplayRestorationMaterial::decode(original));
        let material = value(DisplayFinalizationMaterial::encode(
            &value(RequestId::new("request:restoration")),
            &"1".repeat(64),
            &"2".repeat(64),
            &"3".repeat(64),
            29,
            restoration.replacement().lock(),
            original,
        ));
        let scope = value(restoration.recovery_scope());
        let payload = value(String::from_utf8(
            value(linura_provider_sdk::display_finalization_effect(&material)).canonical_payload,
        ));
        assert!(payload.len() < 4096);
        let request = PlanDesiredStateRequest {
            request_id: value(RequestId::new("request:client-terminal")),
            provider: value(ProviderId::new(DISPLAY_RECOVERY_PROVIDER)),
            observation_capability: value(CapabilityId::new(
                DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY,
            )),
            resource: value(scope.resource_id()),
            desired_state: BTreeMap::from([("finalize_original".into(), payload)]),
            reason: SemanticReason {
                summary: "Release retained display protection".into(),
                intent_ids: vec![],
                requirement_ids: vec![],
                capability_ids: vec![value(CapabilityId::new(
                    DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY,
                ))],
            },
        };
        let mut previews = PlanPreviewControl::new(ObservationCoordinator::new());
        let mut oversized = request.clone();
        oversized
            .desired_state
            .insert("finalize_original".into(), "x".repeat(4097));
        assert!(matches!(
            previews.authority_candidate(
                value(AuthenticatedPrincipal::new("unix:uid:1000")),
                Actor {
                    id: value(ActorId::new("actor:terminal-client")),
                    kind: ActorKind::Human,
                    interactive: true
                },
                oversized,
            ),
            Err(PlanPreviewControlError::InvalidRequest { .. })
        ));
        for uid in [1000, 1001, 0] {
            let error = previews
                .authority_candidate(
                    value(AuthenticatedPrincipal::new(format!("unix:uid:{uid}"))),
                    Actor {
                        id: value(ActorId::new("actor:terminal-client")),
                        kind: ActorKind::Human,
                        interactive: true,
                    },
                    request.clone(),
                )
                .err()
                .unwrap_or_else(|| unreachable!("client established a private terminal context"));
            assert!(
                matches!(&error, PlanPreviewControlError::Planning { reason } if reason == "terminal planning requires authenticated linked history"),
                "unexpected boundary failure: {error:?}"
            );
            assert!(value(previews.finalization_context.0.try_lock()).is_none());
        }
    }
}
