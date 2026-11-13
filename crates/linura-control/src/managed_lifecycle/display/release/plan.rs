//! Separate canonical managed release purpose, derived entirely by Control.
//! Planning performs no approval, durable prepare or native/Root effect.
use super::*;
use linura_core::{
    CapabilityId, DisplayOrdinaryReleaseLineage, DisplayOrdinaryReleaseMaterial,
    DisplayOrdinaryReleaseOutcome, SemanticReason,
};
use linura_observation::{
    DISPLAY_ORDINARY_ORIGINAL_CAPABILITY, DISPLAY_OUTPUTS_CAPABILITY, DISPLAY_PROVIDER,
    DISPLAY_RECOVERY_PROVIDER, DisplayObservationFacts, DisplayRecoveryMetadata,
};
use linura_protocol::ObservationRequest;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrdinaryDisplayReleaseRequest {
    pub operation_id: String,
    pub original_request: RequestId,
    pub reason: SemanticReason,
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    pub fn plan_ordinary_display_release<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        input: OrdinaryDisplayReleaseRequest,
        port: &mut P,
        verifier: &mut V,
    ) -> Result<linura_planner::ReconciliationPlan, ManagedLifecycleError> {
        validate_operation_id(&input.operation_id)?;
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "ordinary release requires authenticated interactive human ownership".into(),
            ));
        }
        let inspection = self.inspect_ordinary_display_original(
            principal.clone(),
            &input.original_request,
            port,
            verifier,
        )?;
        let request = inspection.request();
        let snapshot = inspection.original_snapshot();
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let checkpoint = crate::display_checkpoint::Checkpoint::load(
            self.display_journal()?,
            request,
            snapshot,
            now_ms()?,
        )?;
        let history = DisplayHistory::load(
            self.display_journal()?,
            &principal_id,
            &crate::durable_authority::digest_request(request)?,
            &snapshot.transaction_id,
            snapshot.state,
            now_ms()?,
        )?;
        let layout = material(request)?;
        let original_intent = layout
            .validate_native(
                checkpoint.historical_facts.inventory(),
                checkpoint.historical_facts.capabilities(),
            )
            .map_err(|_| invalid_original())?;
        let disposition = if !inspection.eligibility().restored() {
            DisplayOrdinaryReleaseOutcome::Keep
        } else if history.revert.is_some() {
            DisplayOrdinaryReleaseOutcome::Revert
        } else {
            DisplayOrdinaryReleaseOutcome::Expired
        };
        let target = if disposition == DisplayOrdinaryReleaseOutcome::Keep {
            original_intent.desired()
        } else {
            original_intent.baseline()
        };
        let mut expected = checkpoint
            .historical_facts
            .recovery_metadata()
            .cloned()
            .ok_or_else(invalid_original)?;
        if disposition == DisplayOrdinaryReleaseOutcome::Keep {
            // Apply takes ownership of each exact original output. The base
            // configuration and native identity must still be the checkpoint's;
            // never bless a newly observed rule or foreign overlay as ours.
            expected = expected
                .into_iter()
                .map(|(id, old)| {
                    DisplayRecoveryMetadata::new(
                        true,
                        old.base_configuration_digest().into(),
                        old.native_identity_digest().into(),
                    )
                    .map(|metadata| (id, metadata))
                    .map_err(|_| invalid_original())
                })
                .collect::<Result<_, _>>()?;
        }
        let expected_guard = linura_provider_sdk::display_layout_source_guard(target, &expected)
            .map_err(|_| invalid_original())?;
        let display = self
            .previews
            .observe(&ObservationRequest {
                provider: ProviderId::new(DISPLAY_PROVIDER).map_err(|_| invalid_original())?,
                capability: CapabilityId::new(DISPLAY_OUTPUTS_CAPABILITY)
                    .map_err(|_| invalid_original())?,
                resource: request.resource.clone(),
            })
            .map_err(|_| invalid_original())?
            .observation;
        let facts = DisplayObservationFacts::from_envelope(&display, layout.topology(), now_ms()?)
            .map_err(|_| invalid_original())?;
        if facts.layout() != target
            || facts.recovery_metadata() != Some(&expected)
            || linura_provider_sdk::display_baseline_guard(&facts)
                .map_err(|_| invalid_original())?
                != expected_guard
        {
            return Err(invalid_original());
        }
        let eligibility = inspection.eligibility();
        let guard = expected_guard.to_hex();
        let full_material = DisplayOrdinaryReleaseMaterial::encode(
            &DisplayOrdinaryReleaseLineage {
                original_request: request.request_id.clone(),
                original_dispatch: eligibility.dispatch_digest(),
                terminal_record: terminal_for_inspection(&history, snapshot.state)?
                    .0
                    .digest()
                    .hex(),
                original_checkpoint: &inspection.root().comparison().checkpoint,
                signed_binding: snapshot.binding_digest.hex(),
                generation: snapshot.current_generation,
                state_version: snapshot.state_version,
                current_source_guard: &guard,
            },
            disposition,
            layout.lock(),
            &request.desired_state["layout"],
        )
        .map_err(|_| invalid_original())?;
        let effect = linura_provider_sdk::display_ordinary_release_effect(&full_material)
            .map_err(|_| invalid_original())?;
        let mut reason = input.reason;
        crate::display_restoration_plan::inherit_original_reason(&mut reason, &request.reason)
            .map_err(ManagedLifecycleError::Contract)?;
        let desired = PlanDesiredStateRequest {
            request_id: RequestId::new(format!(
                "{DISPLAY_ORDINARY_RELEASE_REQUEST_PREFIX}{}",
                input.operation_id
            ))
            .map_err(|_| invalid_original())?,
            provider: ProviderId::new(DISPLAY_RECOVERY_PROVIDER).map_err(|_| invalid_original())?,
            resource: effect.resource,
            observation_capability: CapabilityId::new(DISPLAY_ORDINARY_ORIGINAL_CAPABILITY)
                .map_err(|_| invalid_original())?,
            desired_state: BTreeMap::from([(
                "release_ordinary".into(),
                String::from_utf8(effect.canonical_payload).map_err(|_| invalid_original())?,
            )]),
            reason,
        };
        let source = crate::display_ordinary_release_plan::OrdinaryReleasePlanningContext {
            principal: principal.clone(),
            material: full_material,
            root: inspection.root().clone(),
            observation: inspection.observation().clone(),
        };
        let (plan, observation) = {
            let _context = self
                .previews
                .enter_ordinary_display_release_context(source, &desired)
                .map_err(|_| invalid_original())?;
            self.previews
                .authority_candidate(principal.clone(), actor, desired.clone())
                .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?
        };
        self.validate_registered_managed_plan(&plan, RiskClass::SecuritySensitive)?;
        if self.retained_display_request(&principal, &input.original_request)? != *request
            || self
                .authority
                .matching_request_snapshot(&principal, request)?
                != *snapshot
            || terminal_for_inspection(
                &DisplayHistory::load(
                    self.display_journal()?,
                    &principal_id,
                    &crate::durable_authority::digest_request(request)?,
                    &snapshot.transaction_id,
                    snapshot.state,
                    now_ms()?,
                )?,
                snapshot.state,
            )?
            .0
            .digest()
            .as_str()
                != eligibility.terminal_record_digest()
        {
            return Err(invalid_original());
        }
        observation
            .require_current(now_ms()?)
            .map_err(|_| invalid_original())?;
        Ok(plan)
    }
}
