//! Display-specific confirmation/recovery phases over the same canonical plan,
//! policy and durable authority engine. None of these data records are reusable
//! executor credentials. Existing requests are always reconciled without apply.
use super::*;
use crate::display_recovery_journal::{Phase, Record};
use linura_core::DisplayLayoutMaterial;
use linura_observation::{ObservationAuthority, ObservationEnvelope, ObservedValue};

pub const DISPLAY_CONFIRMATION_WINDOW_MS: u64 = 15_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayLayoutState {
    AwaitingConfirmation,
    Confirmed,
    Restored,
    NotDispatched,
    Indeterminate,
}
impl DisplayLayoutState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingConfirmation => "awaiting-confirmation",
            Self::Confirmed => "confirmed",
            Self::Restored => "restored",
            Self::NotDispatched => "not-dispatched",
            Self::Indeterminate => "indeterminate",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayLayoutReceipt {
    pub request_id: RequestId,
    pub transaction_id: String,
    pub resource: ResourceId,
    pub state: DisplayLayoutState,
    pub confirmation_expires_at_unix_ms: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayContinuationAction {
    Confirm,
    Revert,
}

/// A one-use continuation of an already durably dispatched exact display
/// transaction, minted only after the authenticated decision was retained.
/// It cannot request a different layout or initiate another apply operation.
#[derive(Debug)]
pub struct AuthorizedDisplayContinuation {
    request: PlanDesiredStateRequest,
    transaction_id: TransactionId,
    dispatch_digest: String,
    decision_digest: String,
    action: DisplayContinuationAction,
}
impl AuthorizedDisplayContinuation {
    #[must_use]
    pub fn request(&self) -> &PlanDesiredStateRequest {
        &self.request
    }
    #[must_use]
    pub fn transaction_id(&self) -> &str {
        self.transaction_id.as_str()
    }
    #[must_use]
    pub fn dispatch_digest(&self) -> &str {
        &self.dispatch_digest
    }
    #[must_use]
    pub fn decision_digest(&self) -> &str {
        &self.decision_digest
    }
    #[must_use]
    pub const fn action(&self) -> DisplayContinuationAction {
        self.action
    }
}
pub trait DisplayTransactionPort: Debug + Send {
    fn dispatch_layout(
        &mut self,
        authorization: AuthorizedEffect,
        request: &PlanDesiredStateRequest,
        deadline_unix_ms: u64,
    ) -> Result<ExecutionOutcome, String>;
    fn observe_attempt(
        &mut self,
        request: &PlanDesiredStateRequest,
        transaction_id: &str,
    ) -> Result<ObservationEnvelope, String>;
    fn continue_layout(
        &mut self,
        continuation: AuthorizedDisplayContinuation,
    ) -> Result<(), String>;
}
pub trait IndependentDisplayVerifier: Debug + Send {
    /// A single fresh native probe; scheduling and all retry limits stay here
    /// in Control. Restoration checks the retained baseline, not executor flags.
    fn verify_layout(
        &mut self,
        request: &PlanDesiredStateRequest,
        restoration: bool,
        after_unix_ms: u64,
    ) -> Result<VerificationOutcome, String>;
}

fn now_ms() -> Result<u64, ManagedLifecycleError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ManagedLifecycleError::Contract("display clock unavailable".into()))?
            .as_millis(),
    )
    .map_err(|_| ManagedLifecycleError::Contract("display clock overflow".into()))
}
fn material(
    request: &PlanDesiredStateRequest,
) -> Result<DisplayLayoutMaterial<'_>, ManagedLifecycleError> {
    DisplayLayoutMaterial::decode(request.desired_state.get("layout").ok_or_else(|| {
        ManagedLifecycleError::UnsupportedEffect("display intent is missing".into())
    })?)
    .map_err(|e| ManagedLifecycleError::UnsupportedEffect(e.to_string()))
}
fn require_owner(
    principal: &AuthenticatedPrincipal,
    request: &PlanDesiredStateRequest,
) -> Result<(), ManagedLifecycleError> {
    validate_public_request(request)?;
    validate_request_identity(request)?;
    if !is_display_request(request)
        || principal.as_str() != format!("unix:uid:{}", material(request)?.lock().epoch().uid())
    {
        return Err(ManagedLifecycleError::ApprovalBoundary(
            "display request is not owned by the exact native session principal".into(),
        ));
    }
    Ok(())
}
fn receipt(
    request: &PlanDesiredStateRequest,
    deadline: u64,
    state: DisplayLayoutState,
    principal: &PrincipalId,
) -> DisplayLayoutReceipt {
    DisplayLayoutReceipt {
        request_id: request.request_id.clone(),
        transaction_id: TransactionId::for_namespace(principal, &request.request_id)
            .as_str()
            .into(),
        resource: request.resource.clone(),
        state,
        confirmation_expires_at_unix_ms: deadline,
    }
}
fn attempt_state(
    observation: &ObservationEnvelope,
    request: &PlanDesiredStateRequest,
    dispatched: &Record,
) -> Result<String, ManagedLifecycleError> {
    let fail = || {
        ManagedLifecycleError::Verification(
            "native display attempt evidence is stale, malformed or substituted".into(),
        )
    };
    let expected = material(request)?;
    let provider = ProviderId::new(linura_observation::DISPLAY_PROVIDER).map_err(|_| fail())?;
    let capability =
        linura_core::CapabilityId::new("display.layout-attempt.observe").map_err(|_| fail())?;
    let resource = ResourceId::new(format!(
        "display:attempt:{}",
        dispatched.transaction_id.as_str()
    ))
    .map_err(|_| fail())?;
    observation
        .validate(&provider, &resource, &capability)
        .map_err(|_| fail())?;
    let now = now_ms()?;
    if observation.authority != ObservationAuthority::NativeApi
        || observation.sequence == 0
        || observation.observed_at_unix_ms == 0
        || observation.valid_for_ms == 0
        || observation.valid_for_ms > 2000
        || observation.observed_at_unix_ms > now
        || observation
            .observed_at_unix_ms
            .checked_add(observation.valid_for_ms)
            .is_none_or(|expiry| now >= expiry)
    {
        return Err(fail());
    }
    for (key, value) in [
        (
            "lock_resource",
            expected
                .lock()
                .resource_id()
                .map_err(|_| fail())?
                .as_str()
                .to_owned(),
        ),
        ("topology_resource", request.resource.as_str().to_owned()),
        (
            "effect_digest",
            effect_from_request(request)?.digest().to_hex(),
        ),
        (
            "dispatch_digest",
            dispatched.dispatch_digest.clone().ok_or_else(fail)?,
        ),
    ] {
        if observation.attributes.get(key) != Some(&ObservedValue::Text(value)) {
            return Err(fail());
        }
    }
    if observation.attributes.get("deadline_unix_ms")
        != Some(&ObservedValue::U64(dispatched.deadline_unix_ms))
    {
        return Err(fail());
    }
    match observation.attributes.get("state") {
        Some(ObservedValue::Text(state))
            if [
                "pending",
                "confirmed",
                "restored",
                "restoring",
                "recovery-failed",
                "absent",
            ]
            .contains(&state.as_str()) =>
        {
            Ok(state.clone())
        }
        _ => Err(fail()),
    }
}

fn validate_terminal_display_history(
    phase: Phase,
    state: TransactionState,
) -> Result<(), ManagedLifecycleError> {
    match (phase, state) {
        (Phase::Confirmed, TransactionState::Committed) => Ok(()),
        (Phase::Restored, TransactionState::Committed) | (Phase::Confirmed, _) => {
            Err(ManagedLifecycleError::Authority(
                "display terminal record contradicts the durable authority state".into(),
            ))
        }
        (Phase::Restored, _) => Ok(()),
        _ => Err(ManagedLifecycleError::Authority(
            "display journal supplied a non-terminal phase as terminal".into(),
        )),
    }
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    fn display_journal(&self) -> Result<&dyn ApprovedRequestJournal, ManagedLifecycleError> {
        self.request_journal.as_deref().ok_or_else(|| {
            ManagedLifecycleError::Authority(
                "display management requires its protected durable request/recovery journal".into(),
            )
        })
    }
    fn append_display_record(
        &mut self,
        record: &Record,
        principal: PrincipalId,
        previous: Option<&Record>,
    ) -> Result<(), ManagedLifecycleError> {
        record.append(
            self.request_journal.as_deref_mut().ok_or_else(|| {
                ManagedLifecycleError::Authority("display recovery journal is unavailable".into())
            })?,
            principal,
            previous,
        )
    }
    fn retained_display_request(
        &self,
        principal: &AuthenticatedPrincipal,
        request_id: &RequestId,
    ) -> Result<PlanDesiredStateRequest, ManagedLifecycleError> {
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
        let request = crate::retained_request::decode(&retained)?;
        require_owner(principal, &request)?;
        if retained.digest() != &crate::durable_authority::digest_request(&request)? {
            return Err(ManagedLifecycleError::Authority(
                "display retained request digest mismatch".into(),
            ));
        }
        Ok(request)
    }

    /// Prepare and dispatch once. Completion remains provisional until a separate
    /// authenticated confirmation; the independently owned native recovery timer
    /// must be armed before the first potentially effectful native request.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_display_layout<P: DisplayTransactionPort, V: IndependentDisplayVerifier>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: PlanDesiredStateRequest,
        approval_authorizer: &dyn ManagedApprovalAuthorizer,
        port: &mut P,
        verifier: &mut V,
    ) -> Result<DisplayLayoutReceipt, ManagedLifecycleError> {
        require_owner(&principal, &request)?;
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "display changes require authenticated interactive human provenance".into(),
            ));
        }
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let transaction_id = TransactionId::for_namespace(&principal_id, &request.request_id);
        match self.authority.snapshot(&transaction_id) {
            Ok(_) => {
                if self.retained_display_request(&principal, &request.request_id)? != request {
                    return Err(ManagedLifecycleError::Authority(
                        "display request identity was reused with different material".into(),
                    ));
                }
                return self.display_layout_status(
                    principal,
                    actor,
                    &request.request_id,
                    port,
                    verifier,
                );
            }
            Err(DurableAuthorityError::Transaction(detail))
                if detail == "durable transaction not found" => {}
            Err(error) => return Err(error.into()),
        }
        self.display_journal()?
            .integrity_check()
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        let floor = self.registered_managed_risk_floor(&request)?;
        let candidate = self.authority.candidate_with_risk_floor(
            &mut self.previews,
            principal.clone(),
            actor.clone(),
            request.clone(),
            floor,
        )?;
        self.validate_registered_managed_candidate(&candidate)?;
        let effect = effect_from_request(&request)?;
        if effect_from_candidate(&candidate)? != effect {
            return Err(ManagedLifecycleError::Contract(
                "display canonical plan and effect differ".into(),
            ));
        }
        let approver = self.authorize_candidate(&candidate, &request, approval_authorizer)?;
        let (candidate, evidence) = if let Some(approver) = approver {
            let refreshed = self.refresh_candidate_after_approval(
                &candidate,
                principal.clone(),
                actor.clone(),
                request.clone(),
                &effect,
            )?;
            let id = ApprovalRequestId::new(format!(
                "approval:v010:display:{}",
                request.request_id.as_str()
            ))
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
            let expiry = now_unix_seconds()?
                .checked_add(MANAGED_APPROVAL_TTL_SECONDS)
                .ok_or_else(|| {
                    ManagedLifecycleError::Contract("display approval clock overflow".into())
                })?;
            let evidence = self
                .authority
                .issue_approval(id, &refreshed, &approver, expiry)?;
            (refreshed, Some(evidence.id().clone()))
        } else {
            (candidate, None)
        };
        let retained = crate::retained_request::encode(principal_id.clone(), &request)?;
        self.request_journal
            .as_mut()
            .ok_or_else(|| {
                ManagedLifecycleError::Authority("display journal is unavailable".into())
            })?
            .retain(&retained)
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?;
        let mut prepared = self.authority.prepare(candidate, evidence)?;
        let started = now_ms()?;
        let deadline = started
            .checked_add(DISPLAY_CONFIRMATION_WINDOW_MS)
            .ok_or_else(|| {
                ManagedLifecycleError::Contract("display confirmation deadline overflow".into())
            })?;
        let reserved = Record::new(
            retained.digest().clone(),
            transaction_id.clone(),
            Phase::Reserved,
            deadline,
            started,
            None,
            None,
            None,
        )?;
        self.append_display_record(&reserved, principal_id.clone(), None)?;
        let permit = self.handoff_registered_managed(&principal, &mut prepared)?;
        let authorization = authorized_effect(effect, permit)?;
        let dispatch_digest = authorization.binding().dispatch_digest.to_hex();
        let dispatched = Record::new(
            retained.digest().clone(),
            transaction_id,
            Phase::Dispatched,
            deadline,
            now_ms()?,
            Some(dispatch_digest.clone()),
            Some(reserved.digest().clone()),
            None,
        )?;
        // Persist both baseline and ambiguity/dispatch correlation BEFORE calling
        // the effect port. A failed or uncertain journal write cannot dispatch.
        self.append_display_record(&dispatched, principal_id.clone(), Some(&reserved))?;
        if now_ms()? >= deadline {
            return Ok(receipt(
                &request,
                deadline,
                DisplayLayoutState::Indeterminate,
                &principal_id,
            ));
        }
        match port.dispatch_layout(authorization, &request, deadline) {
            Ok(outcome) if outcome.dispatch_digest.to_hex() != dispatch_digest => {
                return Err(ManagedLifecycleError::Contract(
                    "display executor substituted the dispatch digest".into(),
                ));
            }
            Ok(outcome) if outcome.disposition == ExecutionDisposition::RejectedBeforeDispatch => {
                // The dispatch reservation was retained before calling the port.
                // Without a separately durable rejection record, the same
                // request must remain indeterminate across a process restart.
                // A transient port reply cannot override durable uncertainty.
                return Ok(receipt(
                    &request,
                    deadline,
                    DisplayLayoutState::Indeterminate,
                    &principal_id,
                ));
            }
            _ => {} // Lost transport never authorizes retry or optimistic success.
        }
        self.display_layout_status(principal, actor, &request.request_id, port, verifier)
    }

    pub fn display_layout_status<P: DisplayTransactionPort, V: IndependentDisplayVerifier>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request_id: &RequestId,
        port: &mut P,
        verifier: &mut V,
    ) -> Result<DisplayLayoutReceipt, ManagedLifecycleError> {
        let request = self.retained_display_request(&principal, request_id)?;
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let digest = crate::durable_authority::digest_request(&request)?;
        let reserved = Record::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            Phase::Reserved,
        )?
        .ok_or_else(|| {
            ManagedLifecycleError::Authority("display recovery reservation is missing".into())
        })?;
        reserved.validate_after(None)?;
        let snapshot = self.authority.snapshot(&reserved.transaction_id)?;
        if snapshot.principal != principal_id || snapshot.request_id != request.request_id {
            return Err(ManagedLifecycleError::Authority(
                "display transaction scope changed".into(),
            ));
        }
        let Some(dispatched) = Record::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            Phase::Dispatched,
        )?
        else {
            return Ok(receipt(
                &request,
                reserved.deadline_unix_ms,
                if matches!(
                    snapshot.state,
                    TransactionState::Prepared | TransactionState::Aborted
                ) {
                    DisplayLayoutState::NotDispatched
                } else {
                    DisplayLayoutState::Indeterminate
                },
                &principal_id,
            ));
        };
        dispatched.validate_after(Some(&reserved))?;
        let confirmation = Record::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            Phase::ConfirmRequested,
        )?;
        let revert = Record::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            Phase::RevertRequested,
        )?;
        if confirmation.is_some() && revert.is_some() {
            return Err(ManagedLifecycleError::Authority(
                "display confirmation/reversion history forked".into(),
            ));
        }
        for decision in [&confirmation, &revert].into_iter().flatten() {
            decision.validate_after(Some(&dispatched))?;
        }
        let predecessor = confirmation
            .as_ref()
            .or(revert.as_ref())
            .unwrap_or(&dispatched);
        let confirmed = Record::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            Phase::Confirmed,
        )?;
        let restored = Record::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            Phase::Restored,
        )?;
        if confirmed.is_some() && restored.is_some() {
            return Err(ManagedLifecycleError::Authority(
                "display confirmation and restoration are conflicting terminal histories".into(),
            ));
        }
        if let Some(confirmed) = confirmed {
            confirmed.validate_after(confirmation.as_ref())?;
            validate_terminal_display_history(Phase::Confirmed, snapshot.state)?;
            return Ok(receipt(
                &request,
                reserved.deadline_unix_ms,
                DisplayLayoutState::Confirmed,
                &principal_id,
            ));
        }
        if let Some(restored) = restored {
            restored.validate_after(Some(predecessor))?;
            validate_terminal_display_history(Phase::Restored, snapshot.state)?;
            return Ok(receipt(
                &request,
                reserved.deadline_unix_ms,
                DisplayLayoutState::Restored,
                &principal_id,
            ));
        }
        let observed = match port.observe_attempt(&request, reserved.transaction_id.as_str()) {
            Ok(observation) => observation,
            Err(_) => {
                return Ok(receipt(
                    &request,
                    reserved.deadline_unix_ms,
                    DisplayLayoutState::Indeterminate,
                    &principal_id,
                ));
            }
        };
        let state = attempt_state(&observed, &request, &dispatched)?;
        let after = observed.observed_at_unix_ms;
        let verified = |verifier: &mut V, restoration| matches!(verifier.verify_layout(&request, restoration, after), Ok(result) if result.disposition == VerificationDisposition::Satisfied);
        let state = match state.as_str() {
            "restored" if verified(verifier, true) => {
                let restored = Record::new(
                    digest,
                    reserved.transaction_id,
                    Phase::Restored,
                    reserved.deadline_unix_ms,
                    now_ms()?,
                    dispatched.dispatch_digest.clone(),
                    Some(predecessor.digest().clone()),
                    Some(crate::durable_authority::digest_observation(&observed)?),
                )?;
                self.append_display_record(&restored, principal_id.clone(), Some(predecessor))?;
                DisplayLayoutState::Restored
            }
            "confirmed" if confirmation.is_some() && verified(verifier, false) => {
                let floor = self.registered_managed_risk_floor(&request)?;
                if snapshot.state == TransactionState::Indeterminate {
                    let recovered = self.authority.recover_indeterminate_without_replay(
                        &mut self.previews,
                        principal.clone(),
                        actor,
                        request.clone(),
                        floor,
                    )?;
                    let DurableRecoveryOutcome::Verified(verified) = recovered else {
                        return Ok(receipt(
                            &request,
                            reserved.deadline_unix_ms,
                            DisplayLayoutState::Indeterminate,
                            &principal_id,
                        ));
                    };
                    self.authority.commit_verified(&principal, verified)?;
                } else if snapshot.state == TransactionState::Verified {
                    let verified = self
                        .authority
                        .resume_verified(&principal, &reserved.transaction_id)?;
                    self.authority.commit_verified(&principal, verified)?;
                } else if snapshot.state != TransactionState::Committed {
                    return Ok(receipt(
                        &request,
                        reserved.deadline_unix_ms,
                        DisplayLayoutState::Indeterminate,
                        &principal_id,
                    ));
                }
                let confirmed = Record::new(
                    digest,
                    reserved.transaction_id,
                    Phase::Confirmed,
                    reserved.deadline_unix_ms,
                    now_ms()?,
                    dispatched.dispatch_digest,
                    confirmation.as_ref().map(|record| record.digest().clone()),
                    Some(crate::durable_authority::digest_observation(&observed)?),
                )?;
                self.append_display_record(
                    &confirmed,
                    principal_id.clone(),
                    confirmation.as_ref(),
                )?;
                DisplayLayoutState::Confirmed
            }
            "pending"
                if confirmation.is_none()
                    && revert.is_none()
                    && now_ms()? < reserved.deadline_unix_ms
                    && verified(verifier, false) =>
            {
                DisplayLayoutState::AwaitingConfirmation
            }
            _ => DisplayLayoutState::Indeterminate,
        };
        Ok(receipt(
            &request,
            reserved.deadline_unix_ms,
            state,
            &principal_id,
        ))
    }

    /// A repeat after an uncertain continuation reply observes only. It never
    /// sends the phase again or issues another layout apply.
    pub fn decide_display_layout<P: DisplayTransactionPort, V: IndependentDisplayVerifier>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request_id: &RequestId,
        action: DisplayContinuationAction,
        port: &mut P,
        verifier: &mut V,
    ) -> Result<DisplayLayoutReceipt, ManagedLifecycleError> {
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "display confirmation requires authenticated interactive human provenance".into(),
            ));
        }
        let request = self.retained_display_request(&principal, request_id)?;
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|e| ManagedLifecycleError::Contract(e.to_string()))?;
        let digest = crate::durable_authority::digest_request(&request)?;
        for phase in [
            Phase::ConfirmRequested,
            Phase::RevertRequested,
            Phase::Confirmed,
            Phase::Restored,
        ] {
            if Record::load(self.display_journal()?, &principal_id, &digest, phase)?.is_some() {
                return self.display_layout_status(principal, actor, request_id, port, verifier);
            }
        }
        let dispatched = Record::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            Phase::Dispatched,
        )?
        .ok_or_else(|| {
            ManagedLifecycleError::Authority("display has no durable dispatch reservation".into())
        })?;
        if now_ms()? >= dispatched.deadline_unix_ms {
            return self.display_layout_status(principal, actor, request_id, port, verifier);
        }
        let observed = port
            .observe_attempt(&request, dispatched.transaction_id.as_str())
            .map_err(ManagedLifecycleError::Verification)?;
        if attempt_state(&observed, &request, &dispatched)? != "pending" {
            return self.display_layout_status(principal, actor, request_id, port, verifier);
        }
        if action == DisplayContinuationAction::Confirm
            && !matches!(verifier.verify_layout(&request, false, observed.observed_at_unix_ms), Ok(result) if result.disposition == VerificationDisposition::Satisfied)
        {
            return Ok(receipt(
                &request,
                dispatched.deadline_unix_ms,
                DisplayLayoutState::Indeterminate,
                &principal_id,
            ));
        }
        let phase = if action == DisplayContinuationAction::Confirm {
            Phase::ConfirmRequested
        } else {
            Phase::RevertRequested
        };
        let decision = Record::new(
            digest,
            dispatched.transaction_id.clone(),
            phase,
            dispatched.deadline_unix_ms,
            now_ms()?,
            dispatched.dispatch_digest.clone(),
            Some(dispatched.digest().clone()),
            Some(crate::durable_authority::digest_observation(&observed)?),
        )?;
        self.append_display_record(&decision, principal_id, Some(&dispatched))?;
        let continuation = AuthorizedDisplayContinuation {
            request,
            transaction_id: dispatched.transaction_id,
            dispatch_digest: dispatched.dispatch_digest.ok_or_else(|| {
                ManagedLifecycleError::Contract("display dispatch digest is missing".into())
            })?,
            decision_digest: decision.digest().as_str().into(),
            action,
        };
        let _ = port.continue_layout(continuation);
        self.display_layout_status(principal, actor, request_id, port, verifier)
    }
}

#[cfg(test)]
mod terminal_history_tests {
    use super::*;

    #[test]
    fn confirmed_requires_committed_authority_and_restoration_cannot_follow_commit() {
        assert!(validate_terminal_display_history(
            Phase::Confirmed,
            TransactionState::Committed,
        )
        .is_ok());
        assert!(validate_terminal_display_history(
            Phase::Confirmed,
            TransactionState::Indeterminate,
        )
        .is_err());
        assert!(validate_terminal_display_history(
            Phase::Restored,
            TransactionState::Committed,
        )
        .is_err());
        assert!(validate_terminal_display_history(
            Phase::Restored,
            TransactionState::Indeterminate,
        )
        .is_ok());
        assert!(validate_terminal_display_history(
            Phase::Dispatched,
            TransactionState::Committed,
        )
        .is_err());
    }
}
