//! One canonical original-restoration recipe. Historical context comes only
//! from authenticated Control history and grants no current evidence/approval.
//! Control joins separately bounded original protection, native output, logind
//! and coverage observations. Providers never aggregate or choose a plan.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use linura_core::{
    Actor, CapabilityId, DisplayLayoutIntent, DisplayLayoutMaterial, DisplayRecoveryMapping,
    DisplayRestorationMaterial, PrincipalId, ProviderId, RequestId, SemanticReason, SessionLockId,
};
use linura_observation::{
    DISPLAY_COVERAGE_CAPABILITY, DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY,
    DISPLAY_ORIGINAL_PROTECTION_CAPABILITY, DISPLAY_OUTPUTS_CAPABILITY, DISPLAY_PROVIDER,
    DISPLAY_RECOVERY_PROVIDER, DisplayObservationFacts, DisplayOriginalPresentationFacts,
    DisplayOriginalProtectionFacts, ObservationEnvelope, ObservedValue,
};
use linura_planner::{
    DesiredResource, DeterministicPlanner, PlanFinding, PlanFindingLevel, PlanningFreshness,
    PlanningObservation, ReconciliationPlan,
};
use linura_protocol::{ObservationRequest, PlanDesiredStateRequest};
use linura_provider_sdk::ComponentDigest;
use linura_transaction::{ContentDigest, TransactionSnapshot, TransactionState};

use crate::{
    AuthenticatedPrincipal, DisplayLayoutSafetyReview, ManagedLifecycleError, PlanPreviewControl,
    PlanPreviewControlError,
};

#[derive(Debug)]
pub(crate) struct OriginalDisplayPlanningContext {
    principal: AuthenticatedPrincipal,
    original_request: PlanDesiredStateRequest,
    original_transaction: String,
    original_dispatch: ComponentDigest,
    original_guard: ComponentDigest,
    original_deadline_unix_ms: u64,
    historical: DisplayObservationFacts,
}

impl OriginalDisplayPlanningContext {
    pub(crate) fn new(
        principal: AuthenticatedPrincipal,
        request: PlanDesiredStateRequest,
        snapshot: &TransactionSnapshot,
        dispatch: &crate::display_recovery_journal::Record,
        checkpoint: &crate::display_checkpoint::Checkpoint,
    ) -> Result<Self, ManagedLifecycleError> {
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        if snapshot.principal != principal_id
            || snapshot.request_id != request.request_id
            || snapshot.transaction_id
                != linura_transaction::TransactionId::for_namespace(
                    &principal_id,
                    &request.request_id,
                )
            || !matches!(
                snapshot.state,
                TransactionState::Indeterminate
                    | TransactionState::Verified
                    | TransactionState::RecoveryBlocked
            )
            || dispatch.phase != crate::display_recovery_journal::Phase::Dispatched
            || dispatch.transaction_id != snapshot.transaction_id
            || dispatch.request_digest != crate::durable_authority::digest_request(&request)?
        {
            return Err(ManagedLifecycleError::Authority(
                "original restoration context differs from unresolved authenticated history".into(),
            ));
        }
        let text = request.desired_state.get("layout").ok_or_else(|| {
            ManagedLifecycleError::Contract("original display intent is absent".into())
        })?;
        let material = DisplayLayoutMaterial::decode(text)
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let historical = checkpoint.historical_facts.clone();
        let intent = material
            .validate_native(historical.inventory(), historical.capabilities())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        if request.provider.as_str() != DISPLAY_PROVIDER
            || request.observation_capability.as_str() != DISPLAY_OUTPUTS_CAPABILITY
            || request.desired_state.len() != 1
            || request.resource
                != material
                    .topology()
                    .resource_id()
                    .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?
            || principal.as_str() != format!("unix:uid:{}", material.lock().epoch().uid())
            || intent.baseline() != historical.layout()
            || linura_provider_sdk::display_baseline_guard(&historical)
                .map_err(ManagedLifecycleError::Contract)?
                != checkpoint.native_guard
        {
            return Err(ManagedLifecycleError::Authority(
                "original restoration context has another principal, baseline or native lineage"
                    .into(),
            ));
        }
        let original_dispatch =
            ComponentDigest::parse_hex(dispatch.dispatch_digest.as_deref().ok_or_else(|| {
                ManagedLifecycleError::Authority("original dispatch is absent".into())
            })?)
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        Ok(Self {
            principal,
            original_request: request,
            original_transaction: snapshot.transaction_id.as_str().into(),
            original_dispatch,
            original_guard: checkpoint.native_guard,
            original_deadline_unix_ms: dispatch.deadline_unix_ms,
            historical,
        })
    }

    fn require_original(
        &self,
        facts: &DisplayOriginalProtectionFacts,
    ) -> Result<DisplayLayoutIntent, PlanPreviewControlError> {
        if facts.original_material()
            != self
                .original_request
                .desired_state
                .get("layout")
                .ok_or_else(|| fail("original intent is missing"))?
            || facts.original_transaction() != self.original_transaction
            || facts.scope().original_dispatch() != self.original_dispatch.to_hex()
            || facts.native_guard() != self.original_guard.to_hex()
            || facts.confirmation_deadline_unix_ms() != self.original_deadline_unix_ms
            || Some(facts.outputs()) != self.historical.recovery_metadata()
        {
            return Err(fail(
                "live original protection differs from authenticated historical intent/ownership",
            ));
        }
        DisplayLayoutMaterial::decode(facts.original_material())
            .map_err(fail)?
            .validate_native(self.historical.inventory(), self.historical.capabilities())
            .map_err(fail)
    }

    fn derive_restoration(
        &self,
        protection: &DisplayOriginalProtectionFacts,
        current: &DisplayObservationFacts,
        lock: SessionLockId,
    ) -> Result<(DisplayLayoutIntent, DisplayRecoveryMapping), PlanPreviewControlError> {
        if protection.scope().replacement() != current.inventory().topology() {
            return Err(fail(
                "original protection names a different replacement invocation",
            ));
        }
        let original = self.require_original(protection)?;
        let current_metadata = current
            .recovery_metadata()
            .ok_or_else(|| fail("replacement has incomplete native ownership/identity evidence"))?;
        if protection.outputs().len() != current_metadata.len() {
            return Err(fail("replacement original-output inventory is incomplete"));
        }
        let mut native = BTreeMap::new();
        for (output, metadata) in current_metadata {
            if native
                .insert(metadata.native_identity_digest(), output)
                .is_some()
            {
                return Err(fail("replacement native output identity is ambiguous"));
            }
        }
        let pairs = protection
            .outputs()
            .iter()
            .map(|(old, metadata)| {
                native
                    .get(metadata.native_identity_digest())
                    .map(|new| (old.clone(), (*new).clone()))
                    .ok_or_else(|| {
                        fail("original retained kernel/native identity has no replacement")
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mapping = DisplayRecoveryMapping::new(
            self.historical.inventory().clone(),
            current.inventory().clone(),
            pairs,
        )
        .map_err(fail)?;
        let intent = mapping
            .restoration_intent(
                &original,
                current.layout().clone(),
                current.capabilities(),
                lock,
            )
            .map_err(fail)?;
        Ok((intent, mapping))
    }

    pub(crate) fn original_dispatch(&self) -> String {
        self.original_dispatch.to_hex()
    }

    // Derive the postcondition from authenticated ORIGINAL source facts. The
    // replacement supplies only fresh inventory/capabilities, never the expected
    // rule hashes. This comparison digest is not terminal presentation evidence.
    fn restored_source_guard(
        &self,
        material: &DisplayRestorationMaterial<'_>,
        protection: &DisplayOriginalProtectionFacts,
        current: &DisplayObservationFacts,
    ) -> Result<ComponentDigest, PlanPreviewControlError> {
        let original = self.require_original(protection)?;
        if material.original_request() != &self.original_request.request_id
            || material.original_dispatch() != self.original_dispatch.to_hex()
            || material.original_checkpoint() != protection.checkpoint_digest()
            || material.recovery_scope().map_err(fail)? != *protection.scope()
        {
            return Err(fail(
                "restored source projection has another original binding",
            ));
        }
        let (source, restored) = material
            .validate_native(
                self.historical.inventory(),
                self.historical.capabilities(),
                current.inventory(),
                current.capabilities(),
            )
            .map_err(fail)?;
        if source != original {
            return Err(fail(
                "restored source projection substituted the original intent",
            ));
        }
        let mut expected = BTreeMap::new();
        for (old, new) in material.mapping().outputs() {
            let metadata = protection
                .outputs()
                .get(old)
                .ok_or_else(|| fail("original source is absent"))?;
            let digest = protection
                .restored_source_digests()
                .get(old)
                .ok_or_else(|| fail("restored source projection is absent"))?;
            let row = linura_observation::DisplayRecoveryMetadata::new(
                metadata.linura_owned(),
                digest.clone(),
                metadata.native_identity_digest().into(),
            )
            .map_err(fail)?;
            if expected.insert(new.clone(), row).is_some() {
                return Err(fail("restored source mapping is ambiguous"));
            }
        }
        linura_provider_sdk::display_layout_source_guard(restored.desired(), &expected)
            .map_err(fail)
    }

    pub(crate) fn form_request(
        &self,
        request_id: RequestId,
        protection: &DisplayOriginalProtectionFacts,
        current: &DisplayObservationFacts,
        lock: SessionLockId,
        mut reason: SemanticReason,
    ) -> Result<PlanDesiredStateRequest, PlanPreviewControlError> {
        let (restored, mapping) = self.derive_restoration(protection, current, lock)?;
        let original = self.require_original(protection)?;
        let guard = linura_provider_sdk::display_baseline_guard(current).map_err(fail)?;
        let material = DisplayRestorationMaterial::encode(
            &self.original_request.request_id,
            &self.original_dispatch.to_hex(),
            protection.checkpoint_digest(),
            &guard.to_hex(),
            &original,
            &restored,
            &mapping,
        )
        .map_err(fail)?;
        inherit_original_reason(&mut reason, &self.original_request.reason).map_err(fail)?;
        Ok(PlanDesiredStateRequest {
            request_id,
            provider: ProviderId::new(DISPLAY_RECOVERY_PROVIDER).map_err(fail)?,
            resource: protection.scope().resource_id().map_err(fail)?,
            observation_capability: CapabilityId::new(DISPLAY_ORIGINAL_PROTECTION_CAPABILITY)
                .map_err(fail)?,
            desired_state: BTreeMap::from([("restore_original".into(), material)]),
            reason,
        })
    }
}

// Compensation preserves the original why-chain, including on restart-readable
// request identity checks. Neither caller prose nor a receipt grants authority.
pub(crate) fn inherit_original_reason(
    reason: &mut SemanticReason,
    original: &SemanticReason,
) -> Result<(), String> {
    for origin in &original.intent_ids {
        if !reason.intent_ids.contains(origin) {
            reason.intent_ids.push(origin.clone());
        }
    }
    for origin in &original.requirement_ids {
        if !reason.requirement_ids.contains(origin) {
            reason.requirement_ids.push(origin.clone());
        }
    }
    for origin in &original.capability_ids {
        if !reason.capability_ids.contains(origin) {
            reason.capability_ids.push(origin.clone());
        }
    }
    reason.validate().map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Debug)]
struct BoundContext {
    source: OriginalDisplayPlanningContext,
    request: ContentDigest,
    verification: Option<RestorationDispatch>,
}
#[derive(Debug)]
struct RestorationDispatch {
    transaction: String,
    effect: ComponentDigest,
    dispatch: ComponentDigest,
    recorded_at_unix_ms: u64,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct OriginalContextSlot(Arc<Mutex<Option<Arc<BoundContext>>>>);
pub(crate) struct OriginalContextGuard {
    slot: OriginalContextSlot,
    context: Arc<BoundContext>,
}
impl Drop for OriginalContextGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.slot.0.lock()
            && slot
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.context))
        {
            *slot = None;
        }
    }
}

impl PlanPreviewControl {
    pub(crate) fn enter_original_display_context(
        &mut self,
        source: OriginalDisplayPlanningContext,
        request: &PlanDesiredStateRequest,
    ) -> Result<OriginalContextGuard, PlanPreviewControlError> {
        self.enter_original_context(source, request, None)
    }

    // Only the managed controller loads these authenticated immutable records.
    // This context permits observe-only NoChange derivation, never reprepare,
    // another display write or native release from an acknowledgement.
    pub(crate) fn enter_original_display_verification_context(
        &mut self,
        source: OriginalDisplayPlanningContext,
        request: &PlanDesiredStateRequest,
        snapshot: &TransactionSnapshot,
        record: &crate::display_recovery_journal::Record,
    ) -> Result<OriginalContextGuard, PlanPreviewControlError> {
        let principal = PrincipalId::new(source.principal.as_str()).map_err(fail)?;
        if snapshot.principal != principal
            || snapshot.request_id != request.request_id
            || snapshot.transaction_id
                != linura_transaction::TransactionId::for_namespace(&principal, &request.request_id)
            || !matches!(
                snapshot.state,
                TransactionState::Indeterminate
                    | TransactionState::Verified
                    | TransactionState::Committed
            )
            || record.phase != crate::display_recovery_journal::Phase::Dispatched
            || record.transaction_id != snapshot.transaction_id
            || record.request_digest
                != crate::durable_authority::digest_request(request).map_err(fail)?
        {
            return Err(fail(
                "original restoration verification differs from authenticated dispatch history",
            ));
        }
        let text = request
            .desired_state
            .get("restore_original")
            .ok_or_else(|| fail("original restoration material is absent"))?;
        let effect = linura_provider_sdk::display_restoration_effect(text)
            .map_err(fail)?
            .digest();
        let dispatch = ComponentDigest::parse_hex(
            record
                .dispatch_digest
                .as_deref()
                .ok_or_else(|| fail("original restoration dispatch is absent"))?,
        )
        .map_err(fail)?;
        let verification = RestorationDispatch {
            transaction: snapshot.transaction_id.as_str().into(),
            effect,
            dispatch,
            recorded_at_unix_ms: record.recorded_at_unix_ms,
        };
        self.enter_original_context(source, request, Some(verification))
    }

    fn enter_original_context(
        &mut self,
        source: OriginalDisplayPlanningContext,
        request: &PlanDesiredStateRequest,
        verification: Option<RestorationDispatch>,
    ) -> Result<OriginalContextGuard, PlanPreviewControlError> {
        let context = Arc::new(BoundContext {
            source,
            request: crate::durable_authority::digest_request(request).map_err(fail)?,
            verification,
        });
        let mut slot = self
            .restoration_context
            .0
            .try_lock()
            .map_err(|_| fail("original restoration planning context unavailable"))?;
        if slot.is_some() {
            return Err(fail(
                "original restoration planning context is already in use",
            ));
        }
        *slot = Some(Arc::clone(&context));
        Ok(OriginalContextGuard {
            slot: self.restoration_context.clone(),
            context,
        })
    }

    pub(super) fn build_fresh_original_display_restoration_plan(
        &mut self,
        principal: &AuthenticatedPrincipal,
        actor: Actor,
        request: &PlanDesiredStateRequest,
    ) -> Result<(ReconciliationPlan, ObservationEnvelope), PlanPreviewControlError> {
        let bound = self
            .restoration_context
            .0
            .try_lock()
            .map_err(|_| fail("original restoration planning context unavailable"))?
            .as_ref()
            .cloned()
            .ok_or_else(|| {
                fail("original restoration requires authenticated historical context")
            })?;
        if bound.source.principal != *principal
            || bound.request != crate::durable_authority::digest_request(request).map_err(fail)?
            || request.provider.as_str() != DISPLAY_RECOVERY_PROVIDER
            || request.observation_capability.as_str() != DISPLAY_ORIGINAL_PROTECTION_CAPABILITY
            || request.desired_state.len() != 1
        {
            return Err(fail(
                "original restoration context is bound to another exact principal/request",
            ));
        }
        let text = request
            .desired_state
            .get("restore_original")
            .ok_or_else(|| fail("original restoration intent is absent"))?;
        let material = DisplayRestorationMaterial::decode(text).map_err(fail)?;
        let scope = material.recovery_scope().map_err(fail)?;
        if scope.resource_id().map_err(fail)? != request.resource
            || material.original_request() != &bound.source.original_request.request_id
        {
            return Err(fail(
                "original restoration has a different resource or original request",
            ));
        }
        let mut protection = self
            .observe(&ObservationRequest {
                provider: request.provider.clone(),
                capability: request.observation_capability.clone(),
                resource: request.resource.clone(),
            })?
            .observation;
        let current = material.replacement();
        let display = self
            .observe(&ObservationRequest {
                provider: ProviderId::new(DISPLAY_PROVIDER).map_err(fail)?,
                capability: CapabilityId::new(DISPLAY_OUTPUTS_CAPABILITY).map_err(fail)?,
                resource: current.topology().resource_id().map_err(fail)?,
            })?
            .observation;
        let session = self
            .observe(&ObservationRequest {
                provider: ProviderId::new("logind").map_err(fail)?,
                capability: CapabilityId::new("session.epoch.observe").map_err(fail)?,
                resource: current.topology().session().resource_id().map_err(fail)?,
            })?
            .observation;
        let coverage = self
            .observe(&ObservationRequest {
                provider: ProviderId::new("session-locker").map_err(fail)?,
                capability: CapabilityId::new(DISPLAY_COVERAGE_CAPABILITY).map_err(fail)?,
                resource: current.lock().resource_id().map_err(fail)?,
            })?
            .observation;
        let presentation = if bound.verification.is_some() {
            Some(
                self.observe(&ObservationRequest {
                    provider: ProviderId::new(DISPLAY_PROVIDER).map_err(fail)?,
                    capability: CapabilityId::new(DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY)
                        .map_err(fail)?,
                    resource: scope.resource_id().map_err(fail)?,
                })?
                .observation,
            )
        } else {
            None
        };
        let now = now_ms()?;
        let original = DisplayOriginalProtectionFacts::from_envelope(&protection, &scope, now)
            .map_err(fail)?;
        let facts = DisplayObservationFacts::from_envelope(&display, current.topology(), now)
            .map_err(fail)?;
        let (restored, mapping) =
            bound
                .source
                .derive_restoration(&original, &facts, current.lock().clone())?;
        let guard = linura_provider_sdk::display_baseline_guard(&facts).map_err(fail)?;
        let source_intent = bound.source.require_original(&original)?;
        let canonical = DisplayRestorationMaterial::encode(
            &bound.source.original_request.request_id,
            scope.original_dispatch(),
            original.checkpoint_digest(),
            &guard.to_hex(),
            &source_intent,
            &restored,
            &mapping,
        )
        .map_err(fail)?;
        if bound.verification.is_none() && canonical != *text {
            return Err(fail(
                "original restoration candidate changed in native baseline, checkpoint or complete mapping",
            ));
        }
        let restored_source_guard = bound
            .source
            .restored_source_guard(&material, &original, &facts)?;
        if let Some(verification) = &bound.verification {
            let presentation = presentation
                .as_ref()
                .ok_or_else(|| fail("post-write presentation is absent"))?;
            let observed =
                DisplayOriginalPresentationFacts::from_envelope(presentation, &scope, now)
                    .map_err(fail)?;
            for (valid, label) in [
                // Inventories preserve provider enumeration order; the decoded
                // candidate reconstructs them in original-key order. Compare
                // the complete typed bijection, including both scoped IDs,
                // rather than incidental replacement vector ordering.
                (
                    material.mapping().outputs() == mapping.outputs(),
                    "output-mapping",
                ),
                (facts.layout() == restored.desired(), "native-layout"),
                (guard == restored_source_guard, "native-source-guard"),
                (
                    observed.source_guard() == restored_source_guard.to_hex(),
                    "frame-source-guard",
                ),
                (
                    observed.matches_layout(restored.desired()),
                    "frame-inventory",
                ),
                (
                    observed.matches_binding(
                        material.original_checkpoint(),
                        &verification.transaction,
                        &verification.effect.to_hex(),
                        &verification.dispatch.to_hex(),
                    ),
                    "restoration-dispatch",
                ),
                (
                    presentation.observed_at_unix_ms >= verification.recorded_at_unix_ms,
                    "post-dispatch-sample",
                ),
            ] {
                if !valid {
                    return Err(fail(format!(
                        "original restoration postcondition mismatch: {label}"
                    )));
                }
            }
        }
        DisplayLayoutSafetyReview::review(
            principal,
            restored.desired(),
            &display,
            &session,
            &coverage,
            now,
        )
        .map_err(fail)?;
        // Human review binds material source semantics. Fresh envelope hashes
        // belong in the precise observation binding below, not in those
        // semantic findings: re-sampling must not manufacture a changed rule.
        let mut findings = [&protection, &display, &session, &coverage]
            .into_iter()
            .map(crate::display_plan::native_finding)
            .collect::<Vec<_>>();
        for source in [&display, &session, &coverage] {
            crate::plan_preview::restrict_session_validity(&mut protection, source, now)?;
        }
        if let Some(presentation) = &presentation {
            findings.push(crate::display_plan::native_finding(presentation));
            crate::plan_preview::restrict_session_validity(&mut protection, presentation, now)?;
            protection.attributes.insert(
                "control.replacement_presentation_digest".into(),
                ObservedValue::Text(
                    crate::durable_authority::digest_observation(presentation)
                        .map_err(fail)?
                        .as_str()
                        .into(),
                ),
            );
        }
        for (key, source) in [
            ("control.replacement_display_digest", &display),
            ("control.replacement_session_digest", &session),
            ("control.replacement_coverage_digest", &coverage),
        ] {
            protection.attributes.insert(
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
            provider: protection.provider.clone(),
            resource: protection.resource.clone(),
            observation_capability: protection.capability.clone(),
            authority: protection.authority.as_str().into(),
            evidence_id: protection.evidence_id(),
            freshness: PlanningFreshness::Current,
            attributes: BTreeMap::from([(
                "restore_original".into(),
                if bound.verification.is_some() {
                    text.clone()
                } else {
                    "original restoration unresolved".into()
                },
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
        plan.findings.push(PlanFinding { code: "display-original-restoration-source".into(), level: PlanFindingLevel::Pass, message: format!("Original authenticated request {} / {}; restore only its original baseline and ownership", bound.source.original_request.request_id.as_str(), bound.source.original_transaction) });
        plan.findings.push(PlanFinding {
            code: "display-original-restoration-postcondition".into(),
            level: PlanFindingLevel::Pass,
            message: format!("Expected checkpoint-derived restored layout/source guard {}; terminal hardware presentation remains independently required", restored_source_guard.to_hex()),
        });
        Ok((plan, protection))
    }
}

fn fail(error: impl ToString) -> PlanPreviewControlError {
    PlanPreviewControlError::Planning {
        reason: error.to_string(),
    }
}
fn now_ms() -> Result<u64, PlanPreviewControlError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(fail)?
            .as_millis(),
    )
    .map_err(fail)
}

#[cfg(test)]
mod tests;
