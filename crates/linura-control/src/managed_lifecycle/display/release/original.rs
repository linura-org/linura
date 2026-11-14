//! Independent ordinary original-witness/terminal-history join. This report
//! does not establish ordinary-frame handoff or authorize any release effect.
use super::*;
use linura_core::{CapabilityId, DisplayOrdinaryReleaseScope, ProviderId};
use linura_observation::{
    DISPLAY_ORDINARY_ORIGINAL_CAPABILITY, DISPLAY_RECOVERY_PROVIDER, DisplayOrdinaryOriginalFacts,
};
use linura_protocol::ObservationRequest;
use linura_transaction::TransactionSnapshot;
#[derive(Debug)]
pub struct OrdinaryDisplayOriginalInspection {
    eligibility: OrdinaryDisplayReleaseInspection,
    root: DisplayOrdinaryOriginalFacts,
    observation: ObservationEnvelope,
    pub(crate) request: PlanDesiredStateRequest,
    pub(crate) snapshot: TransactionSnapshot,
}
impl OrdinaryDisplayOriginalInspection {
    #[must_use]
    pub const fn eligibility(&self) -> &OrdinaryDisplayReleaseInspection {
        &self.eligibility
    }
    #[must_use]
    pub const fn root(&self) -> &DisplayOrdinaryOriginalFacts {
        &self.root
    }
    #[must_use]
    pub const fn observation(&self) -> &ObservationEnvelope {
        &self.observation
    }
    #[must_use]
    pub const fn request(&self) -> &PlanDesiredStateRequest {
        &self.request
    }
    #[must_use]
    pub const fn original_snapshot(&self) -> &TransactionSnapshot {
        &self.snapshot
    }
}
pub(super) fn invalid_original() -> ManagedLifecycleError {
    ManagedLifecycleError::Verification(
        "ordinary original-witness/history comparison unavailable; no release authority".into(),
    )
}

/// Common current-scanout ancestry without asserting that a retired Root power
/// witness is still held. This internal comparison cannot authorize an effect.
pub(super) struct OrdinaryCurrentOriginal {
    request: PlanDesiredStateRequest,
    snapshot: TransactionSnapshot,
    eligibility: OrdinaryDisplayReleaseInspection,
    pub(super) checkpoint: String,
    observation: ObservationEnvelope,
    current_grant: Option<linura_observation::DisplayCurrentGrantLineage>,
}
impl OrdinaryCurrentOriginal {
    pub(super) fn current_grant(&self) -> Option<&linura_observation::DisplayCurrentGrantLineage> {
        self.current_grant.as_ref()
    }
    pub(super) fn request(&self) -> &PlanDesiredStateRequest {
        &self.request
    }
    pub(super) fn original_snapshot(&self) -> &TransactionSnapshot {
        &self.snapshot
    }
    pub(super) fn eligibility(&self) -> &OrdinaryDisplayReleaseInspection {
        &self.eligibility
    }
    pub(super) fn observation(&self) -> &ObservationEnvelope {
        &self.observation
    }
}
impl<S: TransactionStore> ManagedLifecycleControl<S> {
    pub(super) fn inspect_ordinary_current_original<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        request_id: &RequestId,
        port: &mut P,
        verifier: &mut V,
        retired: bool,
    ) -> Result<OrdinaryCurrentOriginal, ManagedLifecycleError> {
        if !retired {
            let original =
                self.inspect_ordinary_display_original(principal, request_id, port, verifier)?;
            return Ok(OrdinaryCurrentOriginal {
                request: original.request,
                snapshot: original.snapshot,
                eligibility: original.eligibility,
                checkpoint: original.root.comparison().checkpoint.clone(),
                observation: original.observation,
                current_grant: None,
            });
        }
        use linura_observation::{
            DISPLAY_ORDINARY_ROOT_RETIREMENT_CAPABILITY, DisplayOrdinaryRootRetirementFacts,
        };
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let (request, snapshot, guard, deadline, dispatch) = {
            let checked = self.checked_display_history()?;
            let request = checked.original_request(&principal, request_id)?;
            let snapshot = self
                .authority
                .matching_request_snapshot(&principal, &request)?;
            let history = DisplayHistory::load(
                self.display_journal()?,
                &principal_id,
                &crate::durable_authority::digest_request(&request)?,
                &snapshot.transaction_id,
                snapshot.state,
                now_ms()?,
            )?;
            terminal_for_inspection(&history, snapshot.state)?;
            let dispatched = history.dispatched.as_ref().ok_or_else(invalid_original)?;
            let checkpoint = crate::display_checkpoint::Checkpoint::load(
                self.display_journal()?,
                &request,
                &snapshot,
                now_ms()?,
            )?;
            (
                request,
                snapshot,
                checkpoint.native_guard,
                dispatched.deadline_unix_ms,
                dispatched
                    .dispatch_digest
                    .clone()
                    .ok_or_else(invalid_original)?,
            )
        };
        let scope =
            DisplayOrdinaryReleaseScope::new(&dispatch, material(&request)?.topology().clone())
                .map_err(|_| invalid_original())?;
        let query = ObservationRequest {
            provider: ProviderId::new(DISPLAY_RECOVERY_PROVIDER).map_err(|_| invalid_original())?,
            capability: CapabilityId::new(DISPLAY_ORDINARY_ROOT_RETIREMENT_CAPABILITY)
                .map_err(|_| invalid_original())?,
            resource: scope.resource_id().map_err(|_| invalid_original())?,
        };
        let mut before = self
            .previews
            .observe(&query)
            .map_err(|_| invalid_original())?
            .observation;
        let root = DisplayOrdinaryRootRetirementFacts::from_envelope(&before, &scope, now_ms()?)
            .map_err(|_| invalid_original())?;
        let eligibility =
            self.inspect_ordinary_display_release(principal.clone(), request_id, port, verifier)?;
        let after = self
            .previews
            .observe(&query)
            .map_err(|_| invalid_original())?
            .observation;
        let again = DisplayOrdinaryRootRetirementFacts::from_envelope(&after, &scope, now_ms()?)
            .map_err(|_| invalid_original())?;
        let original = root.original();
        if root != again
            || after.sequence <= before.sequence
            || after.observed_at_unix_ms < before.observed_at_unix_ms
            || original.material != request.desired_state["layout"]
            || original.transaction != snapshot.transaction_id.as_str()
            || original.native_guard != guard.to_hex()
            || original.original_deadline_unix_ms != deadline
            || eligibility.transaction_id() != &snapshot.transaction_id
            || eligibility.dispatch_digest() != dispatch
            || eligibility.durable_binding_digest() != snapshot.binding_digest.as_str()
        {
            return Err(invalid_original());
        }
        self.require_ordinary_terminal_history(&principal, &request, &snapshot, &eligibility)?;
        {
            let _checked = self.checked_display_history()?;
            if crate::display_checkpoint::Checkpoint::load(
                self.display_journal()?,
                &request,
                &snapshot,
                now_ms()?,
            )?
            .native_guard
                != guard
            {
                return Err(invalid_original());
            }
        }
        crate::plan_preview::restrict_session_validity(&mut before, &after, now_ms()?)
            .map_err(|_| invalid_original())?;
        let expiry = before
            .observed_at_unix_ms
            .checked_add(before.valid_for_ms)
            .ok_or_else(invalid_original)?
            .min(eligibility.expires_at_unix_ms());
        before.valid_for_ms = expiry
            .checked_sub(before.observed_at_unix_ms)
            .filter(|v| *v != 0)
            .ok_or_else(invalid_original)?;
        before
            .require_current(now_ms()?)
            .map_err(|_| invalid_original())?;
        Ok(OrdinaryCurrentOriginal {
            request,
            snapshot,
            eligibility,
            checkpoint: original.checkpoint.clone(),
            observation: before,
            current_grant: root.current_grant().cloned(),
        })
    }
    pub fn inspect_ordinary_display_original<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        request_id: &RequestId,
        port: &mut P,
        verifier: &mut V,
    ) -> Result<OrdinaryDisplayOriginalInspection, ManagedLifecycleError> {
        let checked = self.checked_display_history()?;
        let request = checked.original_request(&principal, request_id)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let snapshot = self
            .authority
            .matching_request_snapshot(&principal, &request)?;
        let digest = crate::durable_authority::digest_request(&request)?;
        let history = DisplayHistory::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            &snapshot.transaction_id,
            snapshot.state,
            now_ms()?,
        )?;
        let terminal = terminal_for_inspection(&history, snapshot.state)?
            .0
            .digest()
            .clone();
        let dispatched = history.dispatched.as_ref().ok_or_else(invalid_original)?;
        let dispatch = dispatched
            .dispatch_digest
            .as_deref()
            .ok_or_else(invalid_original)?;
        let material = material(&request)?;
        let scope = DisplayOrdinaryReleaseScope::new(dispatch, material.topology().clone())
            .map_err(|_| invalid_original())?;
        let checkpoint = crate::display_checkpoint::Checkpoint::load(
            self.display_journal()?,
            &request,
            &snapshot,
            now_ms()?,
        )?;
        let query = ObservationRequest {
            provider: ProviderId::new(DISPLAY_RECOVERY_PROVIDER).map_err(|_| invalid_original())?,
            capability: CapabilityId::new(DISPLAY_ORDINARY_ORIGINAL_CAPABILITY)
                .map_err(|_| invalid_original())?,
            resource: scope.resource_id().map_err(|_| invalid_original())?,
        };
        drop(checked);
        let before = self
            .previews
            .observe(&query)
            .map_err(|_| invalid_original())?
            .observation;
        let root = DisplayOrdinaryOriginalFacts::from_envelope(&before, &scope, now_ms()?)
            .map_err(|_| invalid_original())?;
        let eligibility =
            self.inspect_ordinary_display_release(principal.clone(), request_id, port, verifier)?;
        let after = self
            .previews
            .observe(&query)
            .map_err(|_| invalid_original())?
            .observation;
        let checked = DisplayOrdinaryOriginalFacts::from_envelope(&after, &scope, now_ms()?)
            .map_err(|_| invalid_original())?;
        let comparison = root.comparison();
        if checked != root
            || after.sequence <= before.sequence
            || comparison.material != request.desired_state["layout"]
            || comparison.transaction != snapshot.transaction_id.as_str()
            || comparison.native_guard != checkpoint.native_guard.to_hex()
            || comparison.original_deadline_unix_ms != dispatched.deadline_unix_ms
            || eligibility.transaction_id() != &snapshot.transaction_id
            || eligibility.dispatch_digest() != dispatch
            || eligibility.terminal_record_digest() != terminal.as_str()
            || eligibility.durable_binding_digest() != snapshot.binding_digest.as_str()
        {
            return Err(invalid_original());
        }
        let checked = self.checked_display_history()?;
        if self
            .authority
            .matching_request_snapshot(&principal, &request)?
            != snapshot
        {
            return Err(invalid_original());
        }
        let retained = checked.original_request(&principal, request_id)?;
        let latest = DisplayHistory::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            &snapshot.transaction_id,
            snapshot.state,
            now_ms()?,
        )?;
        if retained != request
            || terminal_for_inspection(&latest, snapshot.state)?.0.digest() != &terminal
            || latest
                .dispatched
                .as_ref()
                .is_none_or(|v| v.digest() != dispatched.digest())
            || crate::display_checkpoint::Checkpoint::load(
                self.display_journal()?,
                &request,
                &snapshot,
                now_ms()?,
            )?
            .native_guard
                != checkpoint.native_guard
        {
            return Err(invalid_original());
        }
        let now = now_ms()?;
        let mut observation = before;
        crate::plan_preview::restrict_session_validity(&mut observation, &after, now)
            .map_err(|_| invalid_original())?;
        let expiry = observation
            .observed_at_unix_ms
            .checked_add(observation.valid_for_ms)
            .ok_or_else(invalid_original)?
            .min(eligibility.expires_at_unix_ms());
        observation.valid_for_ms = expiry
            .checked_sub(observation.observed_at_unix_ms)
            .filter(|v| *v != 0)
            .ok_or_else(invalid_original)?;
        for (key, value) in [
            (
                "control.ordinary.native_attempt_digest",
                eligibility.observation_digest().to_owned(),
            ),
            (
                "control.ordinary.terminal_record_digest",
                terminal.as_str().into(),
            ),
            (
                "control.ordinary.signed_binding_digest",
                snapshot.binding_digest.as_str().into(),
            ),
            (
                "control.ordinary.rechecked_root_digest",
                crate::durable_authority::digest_observation(&after)?
                    .as_str()
                    .into(),
            ),
        ] {
            observation
                .attributes
                .insert(key.into(), ObservedValue::Text(value));
        }
        observation
            .require_current(now_ms()?)
            .map_err(|_| invalid_original())?;
        Ok(OrdinaryDisplayOriginalInspection {
            eligibility,
            root,
            observation,
            request,
            snapshot,
        })
    }
}
