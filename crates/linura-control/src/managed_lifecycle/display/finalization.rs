//! Read-only prerequisite inspection for a separate terminal managed effect.
//! No caller-supplied receipt, retained proof or codec becomes execution
//! authority. This module neither retires history nor releases protection.
use super::*;
use crate::display_finalization_plan::FinalizationPlanningContext;
use crate::display_restoration_link::RestorationLink;
use crate::display_restoration_plan::OriginalDisplayPlanningContext;
use linura_core::{DisplayFinalizationMaterial, DisplayRestorationMaterial, SemanticReason};
use linura_observation::{
    DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY, DISPLAY_RECOVERY_PROVIDER, DisplayFinalizationPhase,
    DisplayOriginalFinalizationFacts,
};
use linura_transaction::TransactionSnapshot;

/// The caller identifies existing restoration history and supplies provenance.
/// Original sources, current proof and terminal material come only from Control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalDisplayFinalizationRequest {
    pub operation_id: String,
    pub restoration_request: RequestId,
    pub reason: SemanticReason,
}

/// Fresh restoration evidence joined to exact authenticated linked history.
/// This report may expire immediately. It is not an approval, prepared request,
/// finalization result, cleanup decision or native/Root release credential.
#[derive(Debug)]
pub struct OriginalDisplayFinalizationInspection {
    material: String,
    observation: ObservationEnvelope,
    original: TransactionSnapshot,
    restoration: TransactionSnapshot,
}
impl OriginalDisplayFinalizationInspection {
    #[must_use]
    pub fn material(&self) -> &str {
        &self.material
    }
    #[must_use]
    pub const fn observation(&self) -> &ObservationEnvelope {
        &self.observation
    }
    #[must_use]
    pub const fn original(&self) -> &TransactionSnapshot {
        &self.original
    }
    #[must_use]
    pub const fn restoration(&self) -> &TransactionSnapshot {
        &self.restoration
    }
}

#[derive(Debug, Eq, PartialEq)]
struct LinkedHistory {
    original: PlanDesiredStateRequest,
    restoration: PlanDesiredStateRequest,
    original_snapshot: TransactionSnapshot,
    restoration_snapshot: TransactionSnapshot,
    reserved: Record,
    dispatched: Record,
    link: RestorationLink,
    source: OriginalDisplayPlanningContext,
}
fn invalid() -> ManagedLifecycleError {
    ManagedLifecycleError::Authority(
        "display finalization requires exact authenticated linked retirement and fresh proof"
            .into(),
    )
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    /// Canonical non-executable review of a separate security-sensitive managed
    /// terminal effect. This performs no approval, prepare, dispatch or release.
    pub fn plan_original_display_finalization(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        input: OriginalDisplayFinalizationRequest,
    ) -> Result<linura_planner::ReconciliationPlan, ManagedLifecycleError> {
        validate_operation_id(&input.operation_id)?;
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "terminal finalization requires an authenticated interactive human".into(),
            ));
        }
        let inspection = self.inspect_original_display_finalization(
            principal.clone(),
            actor.clone(),
            &input.restoration_request,
        )?;
        let history = self.finalization_history(&principal, &input.restoration_request)?;
        if inspection.original != history.original_snapshot
            || inspection.restoration != history.restoration_snapshot
        {
            return Err(invalid());
        }
        let material =
            DisplayFinalizationMaterial::decode(&inspection.material).map_err(|_| invalid())?;
        if material.terminal_link() != history.link.digest().hex()
            || material.restoration_request() != &history.restoration.request_id
            || Some(material.restoration_dispatch())
                != history.dispatched.dispatch_digest.as_deref()
            || history
                .restoration
                .desired_state
                .get("restore_original")
                .map(String::as_str)
                != Some(material.restoration_text())
        {
            return Err(invalid());
        }
        let mut reason = input.reason;
        crate::display_restoration_plan::inherit_original_reason(
            &mut reason,
            &history.restoration.reason,
        )
        .map_err(ManagedLifecycleError::Contract)?;
        let request = PlanDesiredStateRequest {
            request_id: RequestId::new(format!(
                "{DISPLAY_FINALIZATION_REQUEST_PREFIX}{}",
                input.operation_id
            ))
            .map_err(|_| invalid())?,
            provider: ProviderId::new(DISPLAY_RECOVERY_PROVIDER).map_err(|_| invalid())?,
            resource: material
                .recovery_scope()
                .map_err(|_| invalid())?
                .resource_id()
                .map_err(|_| invalid())?,
            observation_capability: linura_core::CapabilityId::new(
                DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY,
            )
            .map_err(|_| invalid())?,
            desired_state: BTreeMap::from([(
                "finalize_original".into(),
                String::from_utf8(
                    linura_provider_sdk::display_finalization_effect(&inspection.material)
                        .map_err(|_| invalid())?
                        .canonical_payload,
                )
                .map_err(|_| invalid())?,
            )]),
            reason,
        };
        validate_public_request(&request)?;
        validate_request_identity(&request)?;
        let source = FinalizationPlanningContext {
            principal: principal.clone(),
            original: history.source.clone(),
            restoration: history.restoration.clone(),
            snapshot: history.restoration_snapshot.clone(),
            dispatched: history.dispatched.clone(),
            link: history.link.digest().clone(),
            material: inspection.material,
        };
        let (plan, observation) = {
            let _context = self
                .previews
                .enter_original_display_finalization_context(source, &request)
                .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
            self.previews
                .authority_candidate(principal.clone(), actor, request)
                .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?
        };
        self.validate_registered_managed_plan(&plan, RiskClass::SecuritySensitive)?;
        if self.finalization_history(&principal, &input.restoration_request)? != history {
            return Err(invalid());
        }
        observation
            .require_current(now_ms()?)
            .map_err(|_| invalid())?;
        Ok(plan)
    }

    fn finalization_history(
        &self,
        principal: &AuthenticatedPrincipal,
        request_id: &RequestId,
    ) -> Result<LinkedHistory, ManagedLifecycleError> {
        let suffix = request_id
            .as_str()
            .strip_prefix(DISPLAY_RESTORATION_REQUEST_PREFIX)
            .ok_or_else(invalid)?;
        validate_operation_id(suffix)?;
        self.display_journal()?
            .integrity_check()
            .map_err(|_| invalid())?;
        self.authority.integrity_check()?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let retained = self
            .display_journal()?
            .load(&principal_id, request_id)
            .map_err(|_| invalid())?;
        if retained.principal() != &principal_id || retained.request_id() != request_id {
            return Err(invalid());
        }
        let request = crate::retained_request::decode(&retained)?;
        validate_public_request(&request)?;
        validate_request_identity(&request)?;
        self.authority.assert_request_matches(principal, &request)?;
        if retained.digest() != &crate::durable_authority::digest_request(&request)? {
            return Err(invalid());
        }
        let material = DisplayRestorationMaterial::decode(
            request
                .desired_state
                .get("restore_original")
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
        if principal.as_str() != format!("unix:uid:{}", material.replacement().lock().epoch().uid())
        {
            return Err(invalid());
        }
        effect_from_request(&request)?;
        let transaction = TransactionId::for_namespace(&principal_id, request_id);
        let committed = self.authority.snapshot(&transaction)?;
        if committed.state != TransactionState::Committed
            || committed.principal != principal_id
            || committed.request_id != *request_id
            || committed.transaction_id != transaction
        {
            return Err(invalid());
        }
        let reserved = Record::load(
            self.display_journal()?,
            &principal_id,
            retained.digest(),
            Phase::Reserved,
        )?
        .ok_or_else(invalid)?;
        reserved.validate_after(None)?;
        let dispatched = Record::load(
            self.display_journal()?,
            &principal_id,
            retained.digest(),
            Phase::Dispatched,
        )?
        .ok_or_else(invalid)?;
        dispatched.validate_after(Some(&reserved))?;
        if reserved.transaction_id != transaction || dispatched.transaction_id != transaction {
            return Err(invalid());
        }
        let original = self.retained_display_request(principal, material.original_request())?;
        self.authority
            .assert_request_matches(principal, &original)?;
        let original_transaction =
            TransactionId::for_namespace(&principal_id, &original.request_id);
        let original_snapshot = self.authority.snapshot(&original_transaction)?;
        let link = RestorationLink::load(
            self.display_journal()?,
            principal,
            &original,
            &request,
            &committed,
            dispatched.dispatch_digest.as_deref().ok_or_else(invalid)?,
            now_ms()?,
        )?
        .ok_or_else(invalid)?;
        // A link written before the original CAS is not terminal retirement.
        // State name alone also misses generation/version/binding substitution.
        link.require_retired(&original_snapshot, &committed)?;
        let source = self.original_display_context(principal, &original.request_id)?;
        Ok(LinkedHistory {
            original,
            restoration: request,
            original_snapshot,
            restoration_snapshot: committed,
            reserved,
            dispatched,
            link,
            source,
        })
    }

    /// AuthoritativeQuery prerequisites only. It performs no durable state
    /// transitions, approval, prepare, dispatch, reservation or cleanup. In
    /// particular it cannot repair an absent link or retire the original CAS.
    /// Fresh evidence must still be obtained during any later terminal managed
    /// review/prepare/handoff; this report is never reusable authority.
    pub fn inspect_original_display_finalization(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        restoration_request: &RequestId,
    ) -> Result<OriginalDisplayFinalizationInspection, ManagedLifecycleError> {
        // Authenticate every durable anchor before contacting any provider.
        let history = self.finalization_history(&principal, restoration_request)?;
        let text = &history.restoration.desired_state["restore_original"];
        let restoration = DisplayRestorationMaterial::decode(text).map_err(|_| invalid())?;
        let scope = restoration.recovery_scope().map_err(|_| invalid())?;
        let mut mechanism = self
            .previews
            .observe(&linura_protocol::ObservationRequest {
                provider: ProviderId::new(DISPLAY_RECOVERY_PROVIDER).map_err(|_| invalid())?,
                capability: linura_core::CapabilityId::new(
                    DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY,
                )
                .map_err(|_| invalid())?,
                resource: scope.resource_id().map_err(|_| invalid())?,
            })
            .map_err(|_| invalid())?
            .observation;
        let state = DisplayOriginalFinalizationFacts::from_envelope(&mechanism, &scope, now_ms()?)
            .map_err(|_| invalid())?;
        if state.phase() != DisplayFinalizationPhase::Protected
            || state.terminal().is_some()
            || state.checkpoint() != restoration.original_checkpoint()
            || state.restoration_transaction()
                != history.restoration_snapshot.transaction_id.as_str()
            || state.restoration_effect()
                != effect_from_request(&history.restoration)?.digest().to_hex()
            || Some(state.restoration_dispatch()) != history.dispatched.dispatch_digest.as_deref()
        {
            return Err(invalid());
        }
        let proof = {
            let _context = self
                .previews
                .enter_original_display_verification_context(
                    history.source.clone(),
                    &history.restoration,
                    &history.restoration_snapshot,
                    &history.dispatched,
                )
                .map_err(|_| invalid())?;
            self.previews
                .build_fresh_original_display_restoration_proof(
                    &principal,
                    actor,
                    &history.restoration,
                )
                .map_err(|_| invalid())?
        };
        if proof.plan.status != linura_planner::PlanStatus::NoChange
            || !proof.plan.changes.is_empty()
            || proof.plan.execution_authorized()
        {
            return Err(invalid());
        }
        let presentation = proof.presentation.ok_or_else(invalid)?;
        let material = DisplayFinalizationMaterial::encode(
            restoration_request,
            history
                .dispatched
                .dispatch_digest
                .as_deref()
                .ok_or_else(invalid)?,
            history.link.digest().hex(),
            presentation.source_guard(),
            presentation.post_write_epoch(),
            restoration.replacement().lock(),
            text,
        )
        .map_err(|_| invalid())?;
        // A read-only probe can race another Control connection. Re-read all
        // immutable history and both exact snapshots after the provider join.
        if self.finalization_history(&principal, restoration_request)? != history {
            return Err(invalid());
        }
        proof
            .observation
            .require_current(now_ms()?)
            .map_err(|_| invalid())?;
        crate::plan_preview::restrict_session_validity(
            &mut mechanism,
            &proof.observation,
            now_ms()?,
        )
        .map_err(|_| invalid())?;
        mechanism.attributes.insert(
            "control.restoration_postcondition_digest".into(),
            ObservedValue::Text(
                crate::durable_authority::digest_observation(&proof.observation)?
                    .as_str()
                    .into(),
            ),
        );
        mechanism
            .require_current(now_ms()?)
            .map_err(|_| invalid())?;
        Ok(OriginalDisplayFinalizationInspection {
            material,
            observation: mechanism,
            original: history.original_snapshot,
            restoration: history.restoration_snapshot,
        })
    }
}
