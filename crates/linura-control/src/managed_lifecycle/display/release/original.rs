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
pub(in crate::managed_lifecycle::display) fn invalid_original() -> ManagedLifecycleError {
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
        let history = self.ordinary_release_history(&principal, request_id)?;
        let scope = DisplayOrdinaryReleaseScope::new(
            &history.dispatch_digest,
            material(&history.request)?.topology().clone(),
        )
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
        let pending = self.compare_ordinary_release_native(&history, port, verifier)?;
        let after = self
            .previews
            .observe(&query)
            .map_err(|_| invalid_original())?
            .observation;
        let again = DisplayOrdinaryRootRetirementFacts::from_envelope(&after, &scope, now_ms()?)
            .map_err(|_| invalid_original())?;
        let original = root.original();
        let dispatched = history
            .history
            .dispatched
            .as_ref()
            .ok_or_else(invalid_original)?;
        if root != again
            || after.sequence <= before.sequence
            || after.observed_at_unix_ms < before.observed_at_unix_ms
            || original.material != history.request.desired_state["layout"]
            || original.transaction != history.snapshot.transaction_id.as_str()
            || original.native_guard != history.checkpoint.native_guard.to_hex()
            || original.original_deadline_unix_ms != dispatched.deadline_unix_ms
        {
            return Err(invalid_original());
        }
        let checked = self.checked_display_history()?;
        let eligibility =
            self.finish_ordinary_release_comparison(&checked, &principal, &history, pending)?;
        if eligibility.transaction_id() != &history.snapshot.transaction_id
            || eligibility.dispatch_digest() != history.dispatch_digest
            || eligibility.durable_binding_digest() != history.snapshot.binding_digest.as_str()
        {
            return Err(invalid_original());
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
            request: history.request,
            snapshot: history.snapshot,
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
        let history = self.ordinary_release_history(&principal, request_id)?;
        let scope = DisplayOrdinaryReleaseScope::new(
            &history.dispatch_digest,
            material(&history.request)?.topology().clone(),
        )
        .map_err(|_| invalid_original())?;
        let query = ObservationRequest {
            provider: ProviderId::new(DISPLAY_RECOVERY_PROVIDER).map_err(|_| invalid_original())?,
            capability: CapabilityId::new(DISPLAY_ORDINARY_ORIGINAL_CAPABILITY)
                .map_err(|_| invalid_original())?,
            resource: scope.resource_id().map_err(|_| invalid_original())?,
        };
        // One full durable before/after comparison brackets BOTH independent
        // source pairs. No read snapshot, cached observation or authority is
        // carried across a provider boundary. The pending native comparison
        // cannot become a public inspection until the final history check.
        let before = self
            .previews
            .observe(&query)
            .map_err(|_| invalid_original())?
            .observation;
        let root = DisplayOrdinaryOriginalFacts::from_envelope(&before, &scope, now_ms()?)
            .map_err(|_| invalid_original())?;
        let pending = self.compare_ordinary_release_native(&history, port, verifier)?;
        let after = self
            .previews
            .observe(&query)
            .map_err(|_| invalid_original())?
            .observation;
        let again = DisplayOrdinaryOriginalFacts::from_envelope(&after, &scope, now_ms()?)
            .map_err(|_| invalid_original())?;
        let comparison = root.comparison();
        let dispatched = history
            .history
            .dispatched
            .as_ref()
            .ok_or_else(invalid_original)?;
        if again != root
            || after.sequence <= before.sequence
            || comparison.material != history.request.desired_state["layout"]
            || comparison.transaction != history.snapshot.transaction_id.as_str()
            || comparison.native_guard != history.checkpoint.native_guard.to_hex()
            || comparison.original_deadline_unix_ms != dispatched.deadline_unix_ms
        {
            return Err(invalid_original());
        }
        let checked = self.checked_display_history()?;
        let eligibility =
            self.finish_ordinary_release_comparison(&checked, &principal, &history, pending)?;
        if eligibility.transaction_id() != &history.snapshot.transaction_id
            || eligibility.dispatch_digest() != history.dispatch_digest
            || eligibility.terminal_record_digest() != history.terminal_digest.as_str()
            || eligibility.durable_binding_digest() != history.snapshot.binding_digest.as_str()
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
                history.terminal_digest.as_str().into(),
            ),
            (
                "control.ordinary.signed_binding_digest",
                history.snapshot.binding_digest.as_str().into(),
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
            request: history.request,
            snapshot: history.snapshot,
        })
    }
}
