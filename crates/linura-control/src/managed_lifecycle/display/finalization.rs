//! Terminal inspection, canonical planning and separately prepared one-use handoff.
//! Reports and acknowledgements never become execution authority. Qualified
//! native/Root finalization and independent completion remain separate requirements.
use super::*;
use crate::display_finalization_intent::FinalizationIntent;
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

/// A fresh protected terminal-purpose challenge. The complete material must
/// recompute the managed digest; neither field alone is approval or a permit.
pub struct OriginalDisplayFinalizationChallenge {
    managed: ManagedApprovalChallenge,
    material: String,
}
impl Debug for OriginalDisplayFinalizationChallenge {
    fn fmt(&self, out: &mut Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalDisplayFinalizationChallenge")
            .field("managed", &self.managed)
            .field("material_bytes", &self.material.len())
            .finish()
    }
}
impl OriginalDisplayFinalizationChallenge {
    #[must_use]
    pub fn managed(&self) -> &ManagedApprovalChallenge {
        &self.managed
    }
    #[must_use]
    pub fn material(&self) -> &str {
        &self.material
    }
}
/// Trusted protected-interaction adapter, distinct from ordinary restoration,
/// Apply/Keep/Revert, unlock and power. Implementations authenticate the actual
/// current native purpose and administrator; they never acquire executor access.
pub trait OriginalDisplayFinalizationAuthorizer: Debug + Send {
    fn authorize_finalization(
        &self,
        challenge: &OriginalDisplayFinalizationChallenge,
    ) -> Result<TrustedHumanApproval, String>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
/// Nonterminal retained correlation; not native completion or release authority.
pub struct OriginalDisplayFinalizationReceipt {
    pub request_id: RequestId,
    pub transaction_id: TransactionId,
    pub dispatch_digest: Option<String>,
}
/// A separately prepared one-use handoff. It cannot be constructed from the
/// comparison receipt, a historical approval, or an arbitrary digest/material.
pub struct AuthorizedOriginalDisplayFinalization {
    authorization: AuthorizedEffect,
    material: String,
    dispatch_deadline_unix_ms: u64,
}
impl Debug for AuthorizedOriginalDisplayFinalization {
    fn fmt(&self, out: &mut Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("AuthorizedOriginalDisplayFinalization")
            .field("binding", self.authorization.binding())
            .field("material_bytes", &self.material.len())
            .field("dispatch_deadline_unix_ms", &self.dispatch_deadline_unix_ms)
            .finish()
    }
}
impl AuthorizedOriginalDisplayFinalization {
    #[must_use]
    pub fn into_executor_request(self) -> (AuthorizedEffect, String, u64) {
        (
            self.authorization,
            self.material,
            self.dispatch_deadline_unix_ms,
        )
    }
}
pub trait OriginalDisplayFinalizationPort: Debug + Send {
    fn dispatch_finalization(
        &mut self,
        finalization: AuthorizedOriginalDisplayFinalization,
    ) -> Result<ExecutionOutcome, String>;
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

/// One private Control-to-Root preparation, created only after durable
/// authenticated terminal dispatch and fresh independent held-quiescence
/// verification. This is not a release, new approval, or execution permit.
pub struct AuthorizedOriginalDisplayRetirementPreparation {
    material: String,
    terminal: TransactionSnapshot,
    dispatch_digest: String,
    observation_digest: linura_transaction::ContentDigest,
    expires_at_unix_ms: u64,
}
impl Debug for AuthorizedOriginalDisplayRetirementPreparation {
    fn fmt(&self, out: &mut Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("AuthorizedOriginalDisplayRetirementPreparation")
            .field("terminal_transaction", &self.terminal.transaction_id)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish_non_exhaustive()
    }
}
impl AuthorizedOriginalDisplayRetirementPreparation {
    #[must_use]
    pub fn material(&self) -> &str {
        &self.material
    }
    #[must_use]
    pub fn terminal(&self) -> &TransactionSnapshot {
        &self.terminal
    }
    #[must_use]
    pub fn dispatch_digest(&self) -> &str {
        &self.dispatch_digest
    }
    #[must_use]
    pub fn observation_digest(&self) -> &linura_transaction::ContentDigest {
        &self.observation_digest
    }
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

/// Control's narrow Root preparation adapter. Implementation must authenticate
/// the exact Root peer and immutable native terminal reservation; comparison
/// values are not authority to retire anything, including S17 protection.
pub trait OriginalDisplayRetirementPreparationPort: Debug + Send {
    fn prepare_retirement(
        &mut self,
        preparation: AuthorizedOriginalDisplayRetirementPreparation,
    ) -> Result<(), String>;
}

/// Read-only independent proof of held quiescence for one actual dispatched
/// terminal transaction. It cannot retire witnesses, release fences or commit.
#[derive(Debug)]
pub struct OriginalDisplayQuiescenceInspection {
    restoration: OriginalDisplayFinalizationInspection,
    terminal: TransactionSnapshot,
}
impl OriginalDisplayQuiescenceInspection {
    #[must_use]
    pub const fn restoration(&self) -> &OriginalDisplayFinalizationInspection {
        &self.restoration
    }
    #[must_use]
    pub const fn terminal(&self) -> &TransactionSnapshot {
        &self.terminal
    }
}

#[derive(Debug, Eq, PartialEq)]
struct TerminalInspectionContext {
    request: PlanDesiredStateRequest,
    intent: FinalizationIntent,
    snapshot: TransactionSnapshot,
    receipt: OriginalDisplayFinalizationReceipt,
}
impl TerminalInspectionContext {
    fn matches(
        &self,
        state: &DisplayOriginalFinalizationFacts,
        expected: DisplayFinalizationPhase,
    ) -> bool {
        let Some(terminal) = state.terminal() else {
            return false;
        };
        state.phase() == expected
            && terminal.material() == self.intent.material()
            && terminal.transaction() == self.snapshot.transaction_id.as_str()
            && effect_from_request(&self.request)
                .is_ok_and(|effect| terminal.effect() == effect.digest().to_hex())
            && Some(terminal.dispatch()) == self.receipt.dispatch_digest.as_deref()
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
    fn finalization_receipt(
        &self,
        principal: &AuthenticatedPrincipal,
        request: &PlanDesiredStateRequest,
    ) -> Result<OriginalDisplayFinalizationReceipt, ManagedLifecycleError> {
        self.authority.assert_request_matches(principal, request)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let intent = FinalizationIntent::load(self.display_journal()?, &principal_id, request)?;
        intent.require_claim(self.display_journal()?, &principal_id, request)?;
        let transaction = TransactionId::for_namespace(&principal_id, &request.request_id);
        let snapshot = self.authority.snapshot(&transaction)?;
        if snapshot.principal != principal_id
            || snapshot.request_id != request.request_id
            || snapshot.transaction_id != transaction
        {
            return Err(invalid());
        }
        if !matches!(
            snapshot.state,
            TransactionState::Prepared | TransactionState::Indeterminate
        ) {
            return Err(ManagedLifecycleError::TerminalState(
                "terminal display effect requires separate qualified completion verification"
                    .into(),
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
        if let Some(record) = &reserved {
            record.validate_after(None)?;
            if record.transaction_id != transaction {
                return Err(invalid());
            }
        } else if snapshot.state == TransactionState::Indeterminate {
            return Err(invalid());
        }
        if let Some(record) = &dispatched {
            record.validate_after(reserved.as_ref())?;
            if snapshot.state != TransactionState::Indeterminate
                || record.transaction_id != transaction
            {
                return Err(invalid());
            }
        }
        Ok(OriginalDisplayFinalizationReceipt {
            request_id: request.request_id.clone(),
            transaction_id: transaction,
            dispatch_digest: dispatched.and_then(|record| record.dispatch_digest),
        })
    }

    /// Fresh terminal-purpose authorization and separately prepared one-use
    /// handoff. Existing operation identities are read-only after any prepare,
    /// including failed persistence, native refusal and ambiguous/lost replies.
    /// A reply does not verify completion, commit or authorize another handoff.
    pub fn begin_original_display_finalization<P: OriginalDisplayFinalizationPort>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        input: OriginalDisplayFinalizationRequest,
        authorizer: &dyn OriginalDisplayFinalizationAuthorizer,
        port: &mut P,
    ) -> Result<OriginalDisplayFinalizationReceipt, ManagedLifecycleError> {
        validate_operation_id(&input.operation_id)?;
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "terminal finalization requires the authenticated interactive human".into(),
            ));
        }
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let request_id = RequestId::new(format!(
            "{DISPLAY_FINALIZATION_REQUEST_PREFIX}{}",
            input.operation_id
        ))
        .map_err(|_| invalid())?;
        let transaction = TransactionId::for_namespace(&principal_id, &request_id);
        self.display_journal()?
            .integrity_check()
            .map_err(|_| invalid())?;
        self.authority.integrity_check()?;
        match self.authority.snapshot(&transaction) {
            Ok(_) => {
                let retained = self
                    .display_journal()?
                    .load(&principal_id, &request_id)
                    .map_err(|_| invalid())?;
                if retained.principal() != &principal_id || retained.request_id() != &request_id {
                    return Err(invalid());
                }
                let request = crate::retained_request::decode(&retained)?;
                validate_public_request(&request)?;
                validate_request_identity(&request)?;
                let intent =
                    FinalizationIntent::load(self.display_journal()?, &principal_id, &request)?;
                let material = DisplayFinalizationMaterial::decode(intent.material())
                    .map_err(|_| invalid())?;
                let history = self.finalization_history(&principal, &input.restoration_request)?;
                let mut reason = input.reason.clone();
                crate::display_restoration_plan::inherit_original_reason(
                    &mut reason,
                    &history.restoration.reason,
                )
                .map_err(ManagedLifecycleError::Contract)?;
                if material.restoration_request() != &input.restoration_request
                    || material.terminal_link() != history.link.digest().hex()
                    || Some(material.restoration_dispatch())
                        != history.dispatched.dispatch_digest.as_deref()
                    || history
                        .restoration
                        .desired_state
                        .get("restore_original")
                        .map(String::as_str)
                        != Some(material.restoration_text())
                    || request.reason != reason
                    || retained.digest() != &crate::durable_authority::digest_request(&request)?
                {
                    return Err(invalid());
                }
                return self.finalization_receipt(&principal, &request);
            }
            Err(DurableAuthorityError::Transaction(detail))
                if detail == "durable transaction not found" => {}
            Err(error) => return Err(error.into()),
        }
        let (history, request, source) =
            self.original_finalization_request(&principal, &actor, &input)?;
        let full_material = source.material.clone();
        let candidate = {
            let _context = self
                .previews
                .enter_original_display_finalization_context(source, &request)
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
        if effect
            != linura_provider_sdk::display_finalization_effect(&full_material)
                .map_err(|_| invalid())?
            || effect_from_candidate(&candidate)? != effect
        {
            return Err(invalid());
        }
        if !matches!(
            candidate.review().decision(),
            PolicyDecision::RequireApproval {
                class: ApprovalClass::Administrator,
                ..
            }
        ) {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "terminal finalization requires fresh protected administrator approval".into(),
            ));
        }
        let challenge = OriginalDisplayFinalizationChallenge {
            managed: ManagedApprovalChallenge::from_candidate(&candidate, &request)?,
            material: full_material.clone(),
        };
        let approval = authorizer
            .authorize_finalization(&challenge)
            .map_err(ManagedLifecycleError::ApprovalBoundary)?;
        if !approval.matches_challenge(&challenge.managed) {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "terminal approval differs from the exact reviewed purpose and request".into(),
            ));
        }
        let approver = PolicyAuthenticatedApprover::new(
            approval.principal().clone(),
            ActorKind::Human,
            BTreeSet::from([ApprovalClass::Administrator]),
        );
        let (fresh_history, fresh_request, fresh_source) =
            self.original_finalization_request(&principal, &actor, &input)?;
        if fresh_history != history
            || fresh_request != request
            || fresh_source.material != full_material
        {
            return Err(ManagedLifecycleError::ApprovalBoundary("terminal history, current sources or presentation changed during protected interaction".into()));
        }
        let refreshed = {
            let _context = self
                .previews
                .enter_original_display_finalization_context(fresh_source, &request)
                .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
            self.refresh_candidate_after_approval(
                &candidate,
                principal.clone(),
                actor,
                request.clone(),
                &effect,
            )?
        };
        if self.finalization_history(&principal, &input.restoration_request)? != history {
            return Err(invalid());
        }
        let expiry = now_unix_seconds()?
            .checked_add(MANAGED_APPROVAL_TTL_SECONDS)
            .ok_or_else(invalid)?;
        let evidence = self.authority.issue_approval(
            ApprovalRequestId::new(format!(
                "approval:v010:display-finalization:{}",
                input.operation_id
            ))
            .map_err(|_| invalid())?,
            &refreshed,
            &approver,
            expiry,
        )?;
        let retained = crate::retained_request::encode(principal_id.clone(), &request)?;
        let intent = FinalizationIntent::capture(&request, &full_material)?;
        {
            let journal = self.request_journal.as_mut().ok_or_else(invalid)?;
            journal.retain(&retained).map_err(|_| invalid())?;
            intent.append(journal.as_mut(), principal_id.clone(), &request)?;
            intent.claim(journal.as_mut(), principal_id.clone(), &request)?;
        }
        if self
            .display_journal()?
            .load(&principal_id, &request_id)
            .map_err(|_| invalid())?
            != retained
            || FinalizationIntent::load(self.display_journal()?, &principal_id, &request)? != intent
        {
            return Err(invalid());
        }
        intent.require_claim(self.display_journal()?, &principal_id, &request)?;
        let mut prepared = self
            .authority
            .prepare(refreshed, Some(evidence.id().clone()))?;
        let started = now_ms()?;
        let deadline = started
            .checked_add(DISPLAY_CONFIRMATION_WINDOW_MS)
            .ok_or_else(invalid)?;
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
            return Err(invalid());
        }
        if self.finalization_history(&principal, &input.restoration_request)? != history
            || FinalizationIntent::load(self.display_journal()?, &principal_id, &request)? != intent
        {
            return Err(invalid());
        }
        intent.require_claim(self.display_journal()?, &principal_id, &request)?;
        let permit = self.handoff_registered_managed(&principal, &mut prepared)?;
        let authorization = authorized_effect(effect, permit)?;
        let dispatch = authorization.binding().dispatch_digest.to_hex();
        let dispatched = Record::new(
            retained.digest().clone(),
            transaction,
            Phase::Dispatched,
            deadline,
            now_ms()?,
            Some(dispatch.clone()),
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
            return Err(invalid());
        }
        intent.require_claim(self.display_journal()?, &principal_id, &request)?;
        if FinalizationIntent::load(self.display_journal()?, &principal_id, &request)? != intent
            || self.finalization_history(&principal, &input.restoration_request)? != history
        {
            return Err(invalid());
        }
        prepared
            .display_checkpoint_observation()
            .require_current(now_ms()?)
            .map_err(|_| invalid())?;
        if now_ms()? < deadline
            && let Ok(outcome) = port.dispatch_finalization(AuthorizedOriginalDisplayFinalization {
                authorization,
                material: full_material,
                dispatch_deadline_unix_ms: deadline,
            })
            && outcome.dispatch_digest.to_hex() != dispatch
        {
            return Err(ManagedLifecycleError::Contract(
                "terminal executor substituted the dispatch digest".into(),
            ));
        }
        self.finalization_receipt(&principal, &request)
    }

    /// Canonical non-executable review of a separate security-sensitive managed
    /// terminal effect. This performs no approval, prepare, dispatch or release.
    pub fn plan_original_display_finalization(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        input: OriginalDisplayFinalizationRequest,
    ) -> Result<linura_planner::ReconciliationPlan, ManagedLifecycleError> {
        let (history, request, source) =
            self.original_finalization_request(&principal, &actor, &input)?;
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

    fn original_finalization_request(
        &mut self,
        principal: &AuthenticatedPrincipal,
        actor: &Actor,
        input: &OriginalDisplayFinalizationRequest,
    ) -> Result<
        (
            LinkedHistory,
            PlanDesiredStateRequest,
            FinalizationPlanningContext,
        ),
        ManagedLifecycleError,
    > {
        validate_operation_id(&input.operation_id)?;
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "terminal finalization requires an authenticated interactive human".into(),
            ));
        }
        let history = self.finalization_history(principal, &input.restoration_request)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let request_id = RequestId::new(format!(
            "{DISPLAY_FINALIZATION_REQUEST_PREFIX}{}",
            input.operation_id
        ))
        .map_err(|_| invalid())?;
        if FinalizationIntent::claimed_request(
            self.display_journal()?,
            &principal_id,
            &input.restoration_request,
        )?
        .is_some_and(|owner| owner != request_id)
        {
            return Err(ManagedLifecycleError::Authority(
                "restoration already has a terminal attempt; qualified supersession is required"
                    .into(),
            ));
        }
        let inspection = self.inspect_original_display_finalization(
            principal.clone(),
            actor.clone(),
            &input.restoration_request,
        )?;
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
        let mut reason = input.reason.clone();
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
        Ok((history, request, source))
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
        let history = self.finalization_history(&principal, restoration_request)?;
        self.inspect_finalization_state(principal, actor, restoration_request, history, None)
    }

    /// AuthoritativeQuery only. Authenticate the actual dispatched terminal
    /// history before probing, then join fresh quiescence and restoration facts.
    /// Neither an executor reply nor this expiring report is release authority.
    pub fn inspect_quiesced_original_display_finalization(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        terminal_request: &RequestId,
    ) -> Result<OriginalDisplayQuiescenceInspection, ManagedLifecycleError> {
        self.inspect_terminal_phase(
            principal,
            actor,
            terminal_request,
            DisplayFinalizationPhase::Quiesced,
        )
    }

    /// A read-only post-Root-retirement inspection. It does not infer native
    /// first-frame continuity from the Root marker and it cannot release any
    /// retained input, power, startup or compositor protection.
    pub fn inspect_root_retired_held_original_display_finalization(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        terminal_request: &RequestId,
    ) -> Result<OriginalDisplayQuiescenceInspection, ManagedLifecycleError> {
        self.inspect_original_display_release_reservation_phase(
            principal,
            actor,
            terminal_request,
            DisplayFinalizationPhase::Retired,
        )
    }

    /// Read-only lost-ack reconciliation after this original Root invocation
    /// spent its one-use LNRN:1 before-effect native reservation. It is not an
    /// ACK for native consumption, a physical completion or release authority.
    pub fn inspect_native_release_reserved_original_display_finalization(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        terminal_request: &RequestId,
    ) -> Result<OriginalDisplayQuiescenceInspection, ManagedLifecycleError> {
        self.inspect_original_display_release_reservation_phase(
            principal,
            actor,
            terminal_request,
            DisplayFinalizationPhase::NativeReleaseReserved,
        )
    }

    fn inspect_original_display_release_reservation_phase(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        terminal_request: &RequestId,
        expected: DisplayFinalizationPhase,
    ) -> Result<OriginalDisplayQuiescenceInspection, ManagedLifecycleError> {
        if !matches!(
            expected,
            DisplayFinalizationPhase::Retired | DisplayFinalizationPhase::NativeReleaseReserved
        ) {
            return Err(invalid());
        }
        // Root's durable phase-3 marker is only one side of the two-phase
        // protocol. Demand this *original* Control one-use reservation and
        // its exact signed request/transaction/intent correlation before
        // visiting providers. An expired historical observation is NOT renewed.
        let terminal = self.terminal_inspection_context(&principal, terminal_request)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let dispatch = terminal
            .receipt
            .dispatch_digest
            .as_deref()
            .ok_or_else(invalid)?;
        let before = crate::display_terminal_retirement::TerminalRetirementPrepared::load_spent(
            self.display_journal()?,
            &principal_id,
            &terminal.request,
            &terminal.snapshot,
            dispatch,
            terminal.intent.material(),
        )?;
        let proof = self.inspect_terminal_phase(
            principal.clone(),
            actor,
            terminal_request,
            expected,
        )?;
        // A lost reply is reconciled by fresh physical facts and the exact
        // old immutable record, never another Root/native write or approval.
        if self.terminal_inspection_context(&principal, terminal_request)? != terminal
            || crate::display_terminal_retirement::TerminalRetirementPrepared::load_spent(
                self.display_journal()?,
                &principal_id,
                &terminal.request,
                &terminal.snapshot,
                dispatch,
                terminal.intent.material(),
            )? != before
        {
            return Err(invalid());
        }
        Ok(proof)
    }

    fn inspect_terminal_phase(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        terminal_request: &RequestId,
        expected: DisplayFinalizationPhase,
    ) -> Result<OriginalDisplayQuiescenceInspection, ManagedLifecycleError> {
        if !matches!(
            expected,
            DisplayFinalizationPhase::Quiesced
                | DisplayFinalizationPhase::Retired
                | DisplayFinalizationPhase::NativeReleaseReserved
        ) {
            return Err(invalid());
        }
        let terminal = self.terminal_inspection_context(&principal, terminal_request)?;
        let material = DisplayFinalizationMaterial::decode(terminal.intent.material())
            .map_err(|_| invalid())?;
        let restoration_request = material.restoration_request().clone();
        let history = self.finalization_history(&principal, &restoration_request)?;
        if material.terminal_link() != history.link.digest().hex()
            || material.restoration_text() != history.restoration.desired_state["restore_original"]
            || Some(material.restoration_dispatch())
                != history.dispatched.dispatch_digest.as_deref()
        {
            return Err(invalid());
        }
        let restoration = self.inspect_finalization_state(
            principal,
            actor,
            &restoration_request,
            history,
            Some((&terminal, expected)),
        )?;
        Ok(OriginalDisplayQuiescenceInspection {
            restoration,
            terminal: terminal.snapshot,
        })
    }

    /// Journal a one-use Control retirement-preparation decision before asking
    /// Root to reserve its independent immutable preparation. This method
    /// NEVER commits terminal completion, retires original witnesses, or
    /// releases native frame/input/power/startup fences. Ambiguous calls are
    /// non-retryable, including after a caller or service restart.
    pub fn prepare_original_display_terminal_retirement<
        P: OriginalDisplayRetirementPreparationPort,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        terminal_request: &RequestId,
        port: &mut P,
    ) -> Result<(), ManagedLifecycleError> {
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "terminal retirement preparation requires authenticated interactive ownership"
                    .into(),
            ));
        }
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        crate::display_terminal_retirement::TerminalRetirementPrepared::require_absent(
            self.display_journal()?,
            &principal_id,
            terminal_request,
        )?;
        let terminal = self.terminal_inspection_context(&principal, terminal_request)?;
        let receipt_dispatch = terminal
            .receipt
            .dispatch_digest
            .as_ref()
            .ok_or_else(invalid)?
            .clone();
        let complete = self.inspect_quiesced_original_display_finalization(
            principal.clone(),
            actor.clone(),
            terminal_request,
        )?;
        if complete.terminal != terminal.snapshot
            || self.terminal_inspection_context(&principal, terminal_request)? != terminal
        {
            return Err(invalid());
        }
        let observation = complete.restoration.observation();
        let now = now_ms()?;
        let record = crate::display_terminal_retirement::TerminalRetirementPrepared::capture(
            &principal_id,
            &terminal.request,
            &terminal.snapshot,
            &receipt_dispatch,
            terminal.intent.material(),
            observation,
            now,
        )?;
        let prepared = AuthorizedOriginalDisplayRetirementPreparation {
            material: terminal.intent.material().to_owned(),
            terminal: terminal.snapshot.clone(),
            dispatch_digest: receipt_dispatch,
            observation_digest: record.observation().clone(),
            expires_at_unix_ms: record.expiry(),
        };
        // A durable intent is reserved BEFORE an external Root write; a failed
        // append/readback/validation cannot invoke the Root adapter.
        crate::display_terminal_retirement::TerminalRetirementPrepared::require_absent(
            self.display_journal()?,
            &principal_id,
            terminal_request,
        )?;
        record.append(
            self.request_journal.as_deref_mut().ok_or_else(invalid)?,
            principal_id.clone(),
            terminal_request,
        )?;
        record.require_readback(self.display_journal()?, &principal_id, terminal_request)?;
        if now_ms()? >= record.expiry()
            || self.terminal_inspection_context(&principal, terminal_request)? != terminal
        {
            return Err(invalid());
        }
        observation
            .require_current(now_ms()?)
            .map_err(|_| invalid())?;
        // The port receives a non-cloneable private correlation, not a renewed
        // permit. Reconciliation may inspect only the already-spent history.
        port.prepare_retirement(prepared).map_err(|_| {
            ManagedLifecycleError::Indeterminate(
                "terminal Root retirement preparation reply is uncertain; no retry".into(),
            )
        })?;
        record.require_readback(self.display_journal()?, &principal_id, terminal_request)?;
        if self.terminal_inspection_context(&principal, terminal_request)? != terminal
            || now_ms()? >= record.expiry()
        {
            return Err(invalid());
        }
        // Re-check Root and all independent current sources after the native
        // mechanism, even though this operation has no release side effect.
        let after = self.inspect_root_retired_held_original_display_finalization(
            principal,
            actor,
            terminal_request,
        )?;
        if after.terminal != terminal.snapshot {
            return Err(invalid());
        }
        Ok(())
    }

    fn terminal_inspection_context(
        &self,
        principal: &AuthenticatedPrincipal,
        request_id: &RequestId,
    ) -> Result<TerminalInspectionContext, ManagedLifecycleError> {
        validate_operation_id(
            request_id
                .as_str()
                .strip_prefix(DISPLAY_FINALIZATION_REQUEST_PREFIX)
                .ok_or_else(invalid)?,
        )?;
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
        let intent = FinalizationIntent::load(self.display_journal()?, &principal_id, &request)?;
        let receipt = self.finalization_receipt(principal, &request)?;
        let snapshot = self.authority.snapshot(&receipt.transaction_id)?;
        if snapshot.state != TransactionState::Indeterminate || receipt.dispatch_digest.is_none() {
            return Err(invalid());
        }
        Ok(TerminalInspectionContext {
            request,
            intent,
            snapshot,
            receipt,
        })
    }

    fn inspect_finalization_state(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        restoration_request: &RequestId,
        history: LinkedHistory,
        terminal: Option<(&TerminalInspectionContext, DisplayFinalizationPhase)>,
    ) -> Result<OriginalDisplayFinalizationInspection, ManagedLifecycleError> {
        let text = &history.restoration.desired_state["restore_original"];
        let restoration = DisplayRestorationMaterial::decode(text).map_err(|_| invalid())?;
        let scope = restoration.recovery_scope().map_err(|_| invalid())?;
        let observation_request = linura_protocol::ObservationRequest {
            provider: ProviderId::new(DISPLAY_RECOVERY_PROVIDER).map_err(|_| invalid())?,
            capability: linura_core::CapabilityId::new(DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY)
                .map_err(|_| invalid())?,
            resource: scope.resource_id().map_err(|_| invalid())?,
        };
        let mut mechanism = self
            .previews
            .observe(&observation_request)
            .map_err(|_| invalid())?
            .observation;
        let state = DisplayOriginalFinalizationFacts::from_envelope(&mechanism, &scope, now_ms()?)
            .map_err(|_| invalid())?;
        if !terminal.map_or_else(
            || state.phase() == DisplayFinalizationPhase::Protected && state.terminal().is_none(),
            |(terminal, phase)| terminal.matches(&state, phase),
        ) || state.checkpoint() != restoration.original_checkpoint()
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
        if let Some((terminal, phase)) = terminal {
            if material != terminal.intent.material()
                || self.terminal_inspection_context(&principal, &terminal.request.request_id)?
                    != *terminal
            {
                return Err(invalid());
            }
            // Quiescence can be lost while native/KMS facts are sampled. Read
            // the same live Root state again, without renewing either expiry.
            let after = self
                .previews
                .observe(&observation_request)
                .map_err(|_| invalid())?
                .observation;
            let current =
                DisplayOriginalFinalizationFacts::from_envelope(&after, &scope, now_ms()?)
                    .map_err(|_| invalid())?;
            if current != state || !terminal.matches(&current, phase) {
                return Err(invalid());
            }
            crate::plan_preview::restrict_session_validity(&mut mechanism, &after, now_ms()?)
                .map_err(|_| invalid())?;
        }
        // A read-only probe can race another Control connection. Re-read all
        // immutable history and both exact snapshots after the provider join.
        if self.finalization_history(&principal, restoration_request)? != history {
            return Err(invalid());
        }
        if let Some((terminal, _)) = terminal
            && self.terminal_inspection_context(&principal, &terminal.request.request_id)?
                != *terminal
        {
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
