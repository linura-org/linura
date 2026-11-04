//! Authenticated historical-source loading and deterministic original recovery
//! review and one-use managed handoff. Native restoration remains fenced until
//! separate independent terminal verification; dispatch is never success.
use super::*;
use crate::display_restoration_plan::OriginalDisplayPlanningContext;
use linura_core::{
    DisplayRecoveryScope, DisplayRestorationMaterial, DisplayTopologyId, SemanticReason,
};
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

/// Nonterminal correlation only. Even a successful native call leaves the
/// durable transaction indeterminate and all recovery fences retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalDisplayRestorationReceipt {
    pub request_id: RequestId,
    pub transaction_id: TransactionId,
    pub dispatch_digest: Option<String>,
}

/// Historical linked compensation only. This is not current native state or a
/// credential for cleanup, release, another write or another approval purpose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalDisplayRestorationTerminalReceipt {
    pub original: linura_transaction::TransactionSnapshot,
    pub restoration: linura_transaction::TransactionSnapshot,
    pub link_digest: String,
}

/// A one-use Control handoff plus its exact complete private material. The
/// digest-only effect descriptor cannot reconstruct or select a native intent.
#[derive(Debug)]
pub struct AuthorizedOriginalDisplayRestoration {
    authorization: AuthorizedEffect,
    material: String,
    dispatch_deadline_unix_ms: u64,
}
impl AuthorizedOriginalDisplayRestoration {
    #[must_use]
    pub fn into_executor_request(self) -> (AuthorizedEffect, String, u64) {
        (
            self.authorization,
            self.material,
            self.dispatch_deadline_unix_ms,
        )
    }
}
pub trait OriginalDisplayRestorationPort: Debug + Send {
    fn dispatch_original(
        &mut self,
        restoration: AuthorizedOriginalDisplayRestoration,
    ) -> Result<ExecutionOutcome, String>;
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

    fn original_display_request(
        &mut self,
        principal: &AuthenticatedPrincipal,
        actor: &Actor,
        input: &OriginalDisplayRestorationRequest,
    ) -> Result<(OriginalDisplayPlanningContext, PlanDesiredStateRequest), ManagedLifecycleError>
    {
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
        let source = self.original_display_context(principal, &input.original_request)?;
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
                input.lock.clone(),
                input.reason.clone(),
            )
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        validate_public_request(&request)?;
        validate_request_identity(&request)?;
        Ok((source, request))
    }

    fn restoration_receipt(
        &self,
        principal: &AuthenticatedPrincipal,
        request: &PlanDesiredStateRequest,
    ) -> Result<OriginalDisplayRestorationReceipt, ManagedLifecycleError> {
        self.authority.assert_request_matches(principal, request)?;
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let transaction = TransactionId::for_namespace(&principal_id, &request.request_id);
        let snapshot = self.authority.snapshot(&transaction)?;
        if !matches!(
            snapshot.state,
            TransactionState::Prepared | TransactionState::Indeterminate
        ) {
            return Err(ManagedLifecycleError::TerminalState(
                "restoration requires separate qualified terminal reconciliation".into(),
            ));
        }
        let digest = crate::durable_authority::digest_request(request)?;
        let reserved = Record::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            Phase::Reserved,
        )?;
        let dispatched = Record::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            Phase::Dispatched,
        )?;
        if let Some(reserved) = &reserved {
            reserved.validate_after(None)?;
            if reserved.transaction_id != transaction {
                return Err(ManagedLifecycleError::Authority(
                    "restoration reservation changed transaction".into(),
                ));
            }
        }
        if let Some(dispatched) = &dispatched {
            dispatched.validate_after(reserved.as_ref())?;
            if snapshot.state != TransactionState::Indeterminate {
                return Err(ManagedLifecycleError::Authority(
                    "restoration dispatch contradicts durable authority".into(),
                ));
            }
        }
        Ok(OriginalDisplayRestorationReceipt {
            request_id: request.request_id.clone(),
            transaction_id: transaction,
            dispatch_digest: dispatched.and_then(|record| record.dispatch_digest),
        })
    }

    /// Prepare and spend one canonical managed authorization. Existing requests
    /// are observation-only, including after failed persistence, rejected native
    /// admission or a lost reply. This never verifies/commits the restoration,
    /// releases a startup/input/power fence, or retires its original checkpoint.
    pub fn begin_original_display_restoration<P: OriginalDisplayRestorationPort>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        input: OriginalDisplayRestorationRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
        port: &mut P,
    ) -> Result<OriginalDisplayRestorationReceipt, ManagedLifecycleError> {
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
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let request_id = RequestId::new(format!(
            "{DISPLAY_RESTORATION_REQUEST_PREFIX}{}",
            input.operation_id
        ))
        .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let transaction = TransactionId::for_namespace(&principal_id, &request_id);
        self.display_journal()?
            .integrity_check()
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        match self.authority.snapshot(&transaction) {
            Ok(_) => {
                let retained = self
                    .display_journal()?
                    .load(&principal_id, &request_id)
                    .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
                if retained.principal() != &principal_id || retained.request_id() != &request_id {
                    return Err(ManagedLifecycleError::Authority(
                        "restoration journal substituted the request identity".into(),
                    ));
                }
                let request = crate::retained_request::decode(&retained)?;
                validate_public_request(&request)?;
                validate_request_identity(&request)?;
                let text = request
                    .desired_state
                    .get("restore_original")
                    .ok_or_else(|| {
                        ManagedLifecycleError::Contract("restoration intent is missing".into())
                    })?;
                let material = DisplayRestorationMaterial::decode(text)
                    .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
                let original =
                    self.retained_display_request(&principal, &input.original_request)?;
                self.authority
                    .assert_request_matches(&principal, &original)?;
                let mut reason = input.reason.clone();
                crate::display_restoration_plan::inherit_original_reason(
                    &mut reason,
                    &original.reason,
                )
                .map_err(ManagedLifecycleError::Contract)?;
                if material.original_request() != &input.original_request
                    || material.replacement().topology() != &input.replacement
                    || material.replacement().lock() != &input.lock
                    || request.reason != reason
                    || retained.digest() != &crate::durable_authority::digest_request(&request)?
                {
                    return Err(ManagedLifecycleError::Authority(
                        "restoration request identity was reused with different material".into(),
                    ));
                }
                effect_from_request(&request)?;
                return self.restoration_receipt(&principal, &request);
            }
            Err(DurableAuthorityError::Transaction(detail))
                if detail == "durable transaction not found" => {}
            Err(error) => return Err(error.into()),
        }
        let (source, request) = self.original_display_request(&principal, &actor, &input)?;
        let candidate = {
            let _context = self
                .previews
                .enter_original_display_context(source, &request)
                .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
            let floor = self.registered_managed_risk_floor(&request)?;
            self.authority.candidate_with_risk_floor(
                &mut self.previews,
                principal.clone(),
                actor.clone(),
                request.clone(),
                floor,
            )?
        };
        self.validate_registered_managed_candidate(&candidate)?;
        let effect = effect_from_request(&request)?;
        if effect_from_candidate(&candidate)? != effect {
            return Err(ManagedLifecycleError::Contract(
                "canonical restoration plan and effect differ".into(),
            ));
        }
        let approver = self
            .authorize_candidate(&candidate, &request, approval_authorizer)?
            .ok_or_else(|| {
                ManagedLifecycleError::ApprovalBoundary(
                    "original restoration requires fresh protected Recovery approval".into(),
                )
            })?;
        // Approval cannot refresh historical evidence or bless a changed mapping.
        // Reload history and every authoritative replacement fact after interaction.
        let (source, fresh_request) = self.original_display_request(&principal, &actor, &input)?;
        if fresh_request != request {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "original restoration changed during protected interaction".into(),
            ));
        }
        let refreshed = {
            let _context = self
                .previews
                .enter_original_display_context(source, &request)
                .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
            self.refresh_candidate_after_approval(
                &candidate,
                principal.clone(),
                actor,
                request.clone(),
                &effect,
            )?
        };
        let expiry = now_unix_seconds()?
            .checked_add(MANAGED_APPROVAL_TTL_SECONDS)
            .ok_or_else(|| {
                ManagedLifecycleError::Contract("restoration approval clock overflow".into())
            })?;
        let evidence = self.authority.issue_approval(
            ApprovalRequestId::new(format!(
                "approval:v010:display-restoration:{}",
                input.operation_id
            ))
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?,
            &refreshed,
            &approver,
            expiry,
        )?;
        let retained = crate::retained_request::encode(principal_id.clone(), &request)?;
        self.request_journal
            .as_mut()
            .ok_or_else(|| {
                ManagedLifecycleError::Authority("restoration journal is unavailable".into())
            })?
            .retain(&retained)
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        // Require the authenticated immutable request to be readable before CAS.
        if self
            .display_journal()?
            .load(&principal_id, &request_id)
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?
            != retained
        {
            return Err(ManagedLifecycleError::Authority(
                "restoration request readback differs".into(),
            ));
        }
        let mut prepared = self
            .authority
            .prepare(refreshed, Some(evidence.id().clone()))?;
        let started = now_ms()?;
        let deadline = started
            .checked_add(DISPLAY_CONFIRMATION_WINDOW_MS)
            .ok_or_else(|| {
                ManagedLifecycleError::Contract("restoration dispatch clock overflow".into())
            })?;
        let reserved = Record::new(
            retained.digest().clone(),
            transaction.clone(),
            Phase::Reserved,
            deadline,
            started,
            None,
            None,
            None,
        )?;
        self.append_display_record(&reserved, principal_id.clone(), None)?;
        if Record::load(
            self.display_journal()?,
            &principal_id,
            retained.digest(),
            Phase::Reserved,
        )?
        .as_ref()
            != Some(&reserved)
        {
            return Err(ManagedLifecycleError::Authority(
                "restoration reservation readback differs".into(),
            ));
        }
        // Final history check. Durable handoff separately enforces the candidate's
        // original freshness, approval purpose, exact binding and one-use CAS.
        self.original_display_context(&principal, &input.original_request)?;
        let permit = self.handoff_registered_managed(&principal, &mut prepared)?;
        let authorization = authorized_effect(effect, permit)?;
        let dispatch_digest = authorization.binding().dispatch_digest.to_hex();
        let dispatched = Record::new(
            retained.digest().clone(),
            transaction,
            Phase::Dispatched,
            deadline,
            now_ms()?,
            Some(dispatch_digest.clone()),
            Some(reserved.digest().clone()),
            None,
        )?;
        self.append_display_record(&dispatched, principal_id.clone(), Some(&reserved))?;
        if Record::load(
            self.display_journal()?,
            &principal_id,
            retained.digest(),
            Phase::Dispatched,
        )?
        .as_ref()
            != Some(&dispatched)
        {
            return Err(ManagedLifecycleError::Authority(
                "restoration dispatch readback differs".into(),
            ));
        }
        if now_ms()? < deadline {
            // Any rejection/error is still durable uncertainty. Never retry a
            // potentially consumed native grant and never commit from its reply.
            if let Ok(outcome) = port.dispatch_original(AuthorizedOriginalDisplayRestoration {
                authorization,
                material: request.desired_state["restore_original"].clone(),
                dispatch_deadline_unix_ms: deadline,
            }) && outcome.dispatch_digest.to_hex() != dispatch_digest
            {
                return Err(ManagedLifecycleError::Contract(
                    "restoration executor substituted the dispatch digest".into(),
                ));
            }
        }
        self.restoration_receipt(&principal, &request)
    }

    /// Re-read the source chain and independently observe all replacement facts
    /// on every review. No retained preview or old approval can admit recovery.
    pub fn plan_original_display_restoration(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        input: OriginalDisplayRestorationRequest,
    ) -> Result<linura_planner::ReconciliationPlan, ManagedLifecycleError> {
        let (source, request) = self.original_display_request(&principal, &actor, &input)?;
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

    /// Observe-only reconciliation of the restoration's intended baseline.
    /// Canonical NoChange requires independently fresh original Root protection,
    /// complete native sources/layout, logind/coverage and actual post-write
    /// KMS/frame facts bound to this durable dispatch. This cannot reprepare or
    /// dispatch, and it never retires the ORIGINAL transaction/checkpoint or
    /// releases any native fence. A committed snapshot is historical Control
    /// state, not a credential for that separate qualified terminal continuation.
    pub fn reconcile_original_display_restoration(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request_id: &RequestId,
    ) -> Result<linura_transaction::TransactionSnapshot, ManagedLifecycleError> {
        let suffix = request_id
            .as_str()
            .strip_prefix(DISPLAY_RESTORATION_REQUEST_PREFIX)
            .ok_or_else(|| {
                ManagedLifecycleError::InvalidRequestIdentity(
                    "not an original restoration request".into(),
                )
            })?;
        validate_operation_id(suffix)?;
        self.display_journal()?
            .integrity_check()
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        self.authority.integrity_check()?;
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let retained = self
            .display_journal()?
            .load(&principal_id, request_id)
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        if retained.principal() != &principal_id || retained.request_id() != request_id {
            return Err(ManagedLifecycleError::Authority(
                "restoration journal substituted request identity".into(),
            ));
        }
        let request = crate::retained_request::decode(&retained)?;
        validate_public_request(&request)?;
        validate_request_identity(&request)?;
        self.authority
            .assert_request_matches(&principal, &request)?;
        if retained.digest() != &crate::durable_authority::digest_request(&request)? {
            return Err(ManagedLifecycleError::Authority(
                "restoration retained request digest differs".into(),
            ));
        }
        let text = request
            .desired_state
            .get("restore_original")
            .ok_or_else(|| {
                ManagedLifecycleError::Contract("restoration material is missing".into())
            })?;
        let material = DisplayRestorationMaterial::decode(text)
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        if principal.as_str()
            != format!(
                "unix:uid:{}",
                material.replacement().topology().session().uid()
            )
        {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "restoration reconciliation requires its authenticated owner".into(),
            ));
        }
        effect_from_request(&request)?;
        let transaction = TransactionId::for_namespace(&principal_id, request_id);
        let snapshot = self.authority.snapshot(&transaction)?;
        let reserved = Record::load(
            self.display_journal()?,
            &principal_id,
            retained.digest(),
            Phase::Reserved,
        )?
        .ok_or_else(|| {
            ManagedLifecycleError::Authority("restoration reservation is absent".into())
        })?;
        reserved.validate_after(None)?;
        let dispatched = Record::load(
            self.display_journal()?,
            &principal_id,
            retained.digest(),
            Phase::Dispatched,
        )?
        .ok_or_else(|| ManagedLifecycleError::Authority("restoration dispatch is absent".into()))?;
        dispatched.validate_after(Some(&reserved))?;
        let source = self.original_display_context(&principal, material.original_request())?;
        let _context = self
            .previews
            .enter_original_display_verification_context(source, &request, &snapshot, &dispatched)
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        if snapshot.state == TransactionState::Indeterminate {
            let floor = self.registered_managed_risk_floor(&request)?;
            let recovered = self.authority.recover_indeterminate_without_replay(
                &mut self.previews,
                principal.clone(),
                actor,
                request,
                floor,
            )?;
            let DurableRecoveryOutcome::Verified(verified) = recovered else {
                return Err(ManagedLifecycleError::Authority(
                    "restoration postcondition remains unresolved".into(),
                ));
            };
            self.authority.commit_verified(&principal, verified)?;
        } else {
            // A restart after durable verification/commit still performs the
            // SAME fresh canonical proof. An old commit is never current state.
            let (plan, observed) = self
                .previews
                .build_fresh_original_display_restoration_plan(&principal, actor, &request)
                .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
            if plan.status != linura_planner::PlanStatus::NoChange || plan.execution_authorized() {
                return Err(ManagedLifecycleError::Authority(
                    "restoration postcondition is not independently satisfied".into(),
                ));
            }
            observed
                .require_current(now_ms()?)
                .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
            if snapshot.state == TransactionState::Verified {
                let verified = self.authority.resume_verified(&principal, &transaction)?;
                self.authority.commit_verified(&principal, verified)?;
            } else if snapshot.state != TransactionState::Committed {
                return Err(ManagedLifecycleError::TerminalState(
                    "restoration is not a dispatched observe-only transaction".into(),
                ));
            }
        }
        let terminal = self.authority.snapshot(&transaction)?;
        if terminal.state != TransactionState::Committed
            || terminal.principal != principal_id
            || terminal.request_id != *request_id
        {
            return Err(ManagedLifecycleError::Authority(
                "restoration commit readback differs".into(),
            ));
        }
        Ok(terminal)
    }

    /// Durably link independently proven restoration before closing the old
    /// authority as compensated. Every retry observes the same complete fresh
    /// canonical proof and exact retained link; no native port, approval or
    /// write can be reconstructed. Native/Root finalization remains separate.
    pub fn retire_original_display_restoration(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request_id: &RequestId,
    ) -> Result<OriginalDisplayRestorationTerminalReceipt, ManagedLifecycleError> {
        use crate::display_restoration_link::RestorationLink;
        let committed = self.reconcile_original_display_restoration(
            principal.clone(),
            actor.clone(),
            request_id,
        )?;
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let retained = self
            .display_journal()?
            .load(&principal_id, request_id)
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        if retained.principal() != &principal_id || retained.request_id() != request_id {
            return Err(ManagedLifecycleError::Authority(
                "restoration link request identity differs".into(),
            ));
        }
        let request = crate::retained_request::decode(&retained)?;
        self.authority
            .assert_request_matches(&principal, &request)?;
        let material = DisplayRestorationMaterial::decode(
            request
                .desired_state
                .get("restore_original")
                .ok_or_else(|| {
                    ManagedLifecycleError::Contract("restoration material missing".into())
                })?,
        )
        .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let original = self.retained_display_request(&principal, material.original_request())?;
        let original_transaction =
            TransactionId::for_namespace(&principal_id, &original.request_id);
        let original_snapshot = self.authority.snapshot(&original_transaction)?;
        let dispatched = Record::load(
            self.display_journal()?,
            &principal_id,
            retained.digest(),
            Phase::Dispatched,
        )?
        .ok_or_else(|| ManagedLifecycleError::Authority("restoration dispatch missing".into()))?;
        let dispatch = dispatched.dispatch_digest.as_deref().ok_or_else(|| {
            ManagedLifecycleError::Authority("restoration dispatch digest missing".into())
        })?;
        let source = self.original_display_context(&principal, &original.request_id)?;
        let _context = self
            .previews
            .enter_original_display_verification_context(source, &request, &committed, &dispatched)
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        let link = if let Some(link) = RestorationLink::load(
            self.display_journal()?,
            &principal,
            &original,
            &request,
            &committed,
            dispatch,
            now_ms()?,
        )? {
            link
        } else {
            let (plan, observed) = self
                .previews
                .build_fresh_original_display_restoration_plan(&principal, actor.clone(), &request)
                .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
            if plan.status != linura_planner::PlanStatus::NoChange
                || !plan.changes.is_empty()
                || plan.execution_authorized()
            {
                return Err(ManagedLifecycleError::Authority(
                    "restoration link lacks canonical proof".into(),
                ));
            }
            let at = now_ms()?;
            observed
                .require_current(at)
                .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
            let link = RestorationLink::capture(
                &principal,
                &original,
                &request,
                original_snapshot,
                committed.clone(),
                dispatch.into(),
                crate::durable_authority::digest_observation(&observed)?,
                at,
            )?;
            link.append(self.request_journal.as_deref_mut().ok_or_else(|| {
                ManagedLifecycleError::Authority("restoration journal unavailable".into())
            })?)?;
            if RestorationLink::load(
                self.display_journal()?,
                &principal,
                &original,
                &request,
                &committed,
                dispatch,
                now_ms()?,
            )?
            .as_ref()
                != Some(&link)
            {
                return Err(ManagedLifecycleError::Authority(
                    "restoration link readback differs".into(),
                ));
            }
            link
        };
        let retired = self.authority.retire_replaced_display_without_replay(
            &mut self.previews,
            &principal,
            actor,
            &original,
            &request,
            &link,
        )?;
        if RestorationLink::load(
            self.display_journal()?,
            &principal,
            &original,
            &request,
            &committed,
            dispatch,
            now_ms()?,
        )?
        .as_ref()
            != Some(&link)
            || self.authority.snapshot(&original_transaction)? != retired
        {
            return Err(ManagedLifecycleError::Authority(
                "linked original retirement readback differs".into(),
            ));
        }
        Ok(OriginalDisplayRestorationTerminalReceipt {
            original: retired,
            restoration: committed,
            link_digest: link.digest().as_str().into(),
        })
    }
}
