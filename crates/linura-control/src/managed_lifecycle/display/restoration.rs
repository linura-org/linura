//! Authenticated historical-source loading and deterministic original recovery
//! review. This API produces a canonical non-executable plan, never a permit.
use super::*;
use crate::display_restoration_plan::OriginalDisplayPlanningContext;
use linura_core::{DisplayRecoveryScope, DisplayTopologyId, SemanticReason};
use linura_observation::{
    DISPLAY_ORIGINAL_PROTECTION_CAPABILITY, DISPLAY_OUTPUTS_CAPABILITY, DISPLAY_PROVIDER,
    DISPLAY_RECOVERY_PROVIDER, DisplayObservationFacts, DisplayOriginalProtectionFacts,
};
use linura_protocol::ObservationRequest;

/// A caller identifies unresolved history and the replacement invocation. It
/// cannot supply the original rules, output mapping, desired layout or approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalDisplayRestorationRequest {
    pub operation_id: String,
    pub original_request: RequestId,
    pub replacement: DisplayTopologyId,
    pub lock: SessionLockId,
    pub reason: SemanticReason,
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    fn original_display_context(
        &self,
        principal: &AuthenticatedPrincipal,
        original_request: &RequestId,
    ) -> Result<OriginalDisplayPlanningContext, ManagedLifecycleError> {
        let request = self.retained_display_request(principal, original_request)?;
        self.authority.assert_request_matches(principal, &request)?;
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let transaction = TransactionId::for_namespace(&principal_id, original_request);
        let snapshot = self.authority.snapshot(&transaction)?;
        let history = DisplayHistory::load(
            self.display_journal()?,
            &principal_id,
            &crate::durable_authority::digest_request(&request)?,
            &transaction,
            snapshot.state,
            now_ms()?,
        )?;
        if history.confirmed.is_some() || history.restored.is_some() {
            return Err(ManagedLifecycleError::TerminalState(
                "original display history already has a terminal result".into(),
            ));
        }
        let dispatched = history.dispatched.ok_or_else(|| {
            ManagedLifecycleError::Authority(
                "original display was never reserved for dispatch".into(),
            )
        })?;
        let checkpoint = crate::display_checkpoint::Checkpoint::load(
            self.display_journal()?,
            &request,
            &snapshot,
            now_ms()?,
        )?;
        OriginalDisplayPlanningContext::new(
            principal.clone(),
            request,
            &snapshot,
            &dispatched,
            &checkpoint,
        )
    }

    /// Re-read the source chain and independently observe all replacement facts
    /// on every review. No retained preview or old approval can admit recovery.
    pub fn plan_original_display_restoration(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        input: OriginalDisplayRestorationRequest,
    ) -> Result<linura_planner::ReconciliationPlan, ManagedLifecycleError> {
        validate_operation_id(&input.operation_id)?;
        if actor.kind != ActorKind::Human
            || !actor.interactive
            || principal.as_str() != format!("unix:uid:{}", input.replacement.session().uid())
            || input.lock.epoch() != input.replacement.session()
        {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "original recovery requires the authenticated replacement-session human".into(),
            ));
        }
        let source = self.original_display_context(&principal, &input.original_request)?;
        let scope =
            DisplayRecoveryScope::new(&source.original_dispatch(), input.replacement.clone())
                .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let observe =
            |provider, capability, resource| -> Result<ObservationRequest, ManagedLifecycleError> {
                Ok(ObservationRequest {
                    provider: ProviderId::new(provider)
                        .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?,
                    capability: linura_core::CapabilityId::new(capability)
                        .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?,
                    resource,
                })
            };
        let protection = self
            .previews
            .observe(&observe(
                DISPLAY_RECOVERY_PROVIDER,
                DISPLAY_ORIGINAL_PROTECTION_CAPABILITY,
                scope
                    .resource_id()
                    .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?,
            )?)
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?
            .observation;
        let display = self
            .previews
            .observe(&observe(
                DISPLAY_PROVIDER,
                DISPLAY_OUTPUTS_CAPABILITY,
                input
                    .replacement
                    .resource_id()
                    .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?,
            )?)
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?
            .observation;
        let at = now_ms()?;
        let protection = DisplayOriginalProtectionFacts::from_envelope(&protection, &scope, at)
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        let facts = DisplayObservationFacts::from_envelope(&display, &input.replacement, at)
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        let request = source
            .form_request(
                RequestId::new(format!(
                    "{DISPLAY_RESTORATION_REQUEST_PREFIX}{}",
                    input.operation_id
                ))
                .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?,
                &protection,
                &facts,
                input.lock,
                input.reason,
            )
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        validate_public_request(&request)?;
        validate_request_identity(&request)?;
        let _context = self
            .previews
            .enter_original_display_context(source, &request)
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        let (plan, _) = self
            .previews
            .authority_candidate(principal, actor, request)
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        self.validate_registered_managed_plan(&plan, RiskClass::SecuritySensitive)?;
        Ok(plan)
    }
}
