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
impl<S: TransactionStore> ManagedLifecycleControl<S> {
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
