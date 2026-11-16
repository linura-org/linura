//! Independent ordinary current scanout join. Inspection never completes a signed
//! transaction, retires a fence, admits a successor or authorizes cleanup.
use super::*;
use crate::display_ordinary_release_intent::OrdinaryReleaseIntent;
use linura_core::{CapabilityId, DisplayOrdinaryReleaseMaterial, ProviderId};
use linura_observation::{
    DISPLAY_COVERAGE_CAPABILITY, DISPLAY_ORDINARY_COMPLETION_CAPABILITY,
    DISPLAY_ORDINARY_CURRENT_CAPABILITY, DISPLAY_OUTPUTS_CAPABILITY, DISPLAY_PROVIDER,
    DISPLAY_RECOVERY_PROVIDER, DisplayObservationFacts, DisplayOrdinaryCompletionFacts,
    DisplayOrdinaryCurrentFacts,
};
use linura_protocol::ObservationRequest;
use linura_transaction::TransactionSnapshot;

fn unavailable_at(stage: &str) -> ManagedLifecycleError {
    ManagedLifecycleError::Verification(format!(
        "ordinary current completion unavailable at {stage}; no completion authority"
    ))
}

#[derive(Debug)]
pub struct OrdinaryDisplayCurrentInspection {
    pub(super) observation: ObservationEnvelope,
    frames: DisplayOrdinaryCurrentFacts,
    root: DisplayOrdinaryCompletionFacts,
    release: TransactionSnapshot,
    comparison_release: TransactionSnapshot,
    request: PlanDesiredStateRequest,
    layout: linura_core::DisplayLayout,
}
impl OrdinaryDisplayCurrentInspection {
    pub const fn current_layout(&self) -> &linura_core::DisplayLayout {
        &self.layout
    }
    #[must_use]
    pub const fn observation(&self) -> &ObservationEnvelope {
        &self.observation
    }
    #[must_use]
    pub const fn frames(&self) -> &DisplayOrdinaryCurrentFacts {
        &self.frames
    }
    #[must_use]
    pub const fn root(&self) -> &DisplayOrdinaryCompletionFacts {
        &self.root
    }
    #[must_use]
    pub const fn request(&self) -> &PlanDesiredStateRequest {
        &self.request
    }
    #[must_use]
    /// Historical Indeterminate comparison authenticated against immutable
    /// before-CAS records and the actual signed release. Never authority.
    pub const fn comparison_release(&self) -> &TransactionSnapshot {
        &self.comparison_release
    }
    pub const fn release(&self) -> &TransactionSnapshot {
        &self.release
    }
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    /// A lost dispatch acknowledgement can be inspected without replaying the
    /// native port. All contributors and immutable history must still agree.
    pub fn inspect_current_ordinary_display_completion<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        release_request: &RequestId,
        attempt: &mut P,
        verifier: &mut V,
    ) -> Result<OrdinaryDisplayCurrentInspection, ManagedLifecycleError> {
        self.inspect_current_ordinary_display_completion_phase(
            principal,
            release_request,
            attempt,
            verifier,
            true,
            false,
        )
    }
    pub(super) fn inspect_current_ordinary_display_completion_phase<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        release_request: &RequestId,
        attempt: &mut P,
        verifier: &mut V,
        power_held: bool,
        root_retired: bool,
    ) -> Result<OrdinaryDisplayCurrentInspection, ManagedLifecycleError> {
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let checked = self.checked_display_history()?;
        let retained = self
            .display_journal()?
            .load(&principal_id, release_request)
            .map_err(|_| invalid_original())?;
        if retained.principal() != &principal_id || retained.request_id() != release_request {
            return Err(unavailable_at("retained request identity"));
        }
        let request = crate::retained_request::decode(&retained)?;
        validate_public_request(&request)?;
        validate_request_identity(&request)?;
        let intent = OrdinaryReleaseIntent::load(self.display_journal()?, &principal_id, &request)?;
        intent.require_claim(self.display_journal()?, &principal_id, &request)?;
        let actual = self
            .authority
            .matching_request_snapshot(&principal, &request)?;
        let snapshot = if root_retired {
            self.ordinary_current_comparison_snapshot(&principal, &request, &actual)?
        } else {
            actual.clone()
        };
        let receipt = self.ordinary_release_receipt_at(&principal, &request, &snapshot)?;
        let dispatch = receipt
            .dispatch_digest
            .as_deref()
            .ok_or_else(invalid_original)?;
        if snapshot.state != TransactionState::Indeterminate {
            return Err(unavailable_at("signed release dispatch"));
        }
        let material = DisplayOrdinaryReleaseMaterial::decode(intent.material())
            .map_err(|_| invalid_original())?;
        let scope = material.release_scope().map_err(|_| invalid_original())?;
        drop(checked);
        let original = self.inspect_ordinary_current_original(
            principal.clone(),
            &material.lineage().original_request,
            attempt,
            verifier,
            root_retired,
        )?;
        let eligibility = original.eligibility();
        if material.original_text() != original.request().desired_state["layout"]
            || material.lineage().original_dispatch != eligibility.dispatch_digest()
            || material.lineage().terminal_record
                != linura_transaction::ContentDigest::new(eligibility.terminal_record_digest())
                    .map_err(|_| invalid_original())?
                    .hex()
            || material.lineage().signed_binding
                != original.original_snapshot().binding_digest.hex()
            || material.lineage().generation != original.original_snapshot().current_generation
            || material.lineage().state_version != original.original_snapshot().state_version
            || material.lineage().original_checkpoint != original.checkpoint
        {
            return Err(unavailable_at("original signed terminal ancestry"));
        }
        let query = |provider: &str, capability: &str, resource: ResourceId| {
            Ok::<_, ManagedLifecycleError>(ObservationRequest {
                provider: ProviderId::new(provider).map_err(|_| invalid_original())?,
                capability: CapabilityId::new(capability).map_err(|_| invalid_original())?,
                resource,
            })
        };
        let observe = |this: &mut Self, query: &ObservationRequest| {
            this.previews
                .observe(query)
                .map(|value| value.observation)
                .map_err(|_| unavailable_at(query.capability.as_str()))
        };
        let resource = scope.resource_id().map_err(|_| invalid_original())?;
        let root_query = query(
            DISPLAY_RECOVERY_PROVIDER,
            DISPLAY_ORDINARY_COMPLETION_CAPABILITY,
            resource.clone(),
        )?;
        let frame_query = query(
            DISPLAY_PROVIDER,
            DISPLAY_ORDINARY_CURRENT_CAPABILITY,
            resource,
        )?;
        let mut root = observe(self, &root_query)?;
        let display = observe(
            self,
            &query(
                DISPLAY_PROVIDER,
                DISPLAY_OUTPUTS_CAPABILITY,
                scope
                    .topology()
                    .resource_id()
                    .map_err(|_| invalid_original())?,
            )?,
        )?;
        let session = observe(
            self,
            &query(
                "logind",
                "session.epoch.observe",
                scope
                    .topology()
                    .session()
                    .resource_id()
                    .map_err(|_| invalid_original())?,
            )?,
        )?;
        let coverage = observe(
            self,
            &query(
                "session-locker",
                DISPLAY_COVERAGE_CAPABILITY,
                material
                    .current_lock()
                    .resource_id()
                    .map_err(|_| invalid_original())?,
            )?,
        )?;
        let frames = observe(self, &frame_query)?;
        let now = now_ms()?;
        let root_facts = DisplayOrdinaryCompletionFacts::from_envelope(&root, &scope, now)
            .map_err(|_| unavailable_at("Root spend comparison"))?;
        let native = DisplayOrdinaryCurrentFacts::from_envelope(&frames, &scope, now)
            .map_err(|_| unavailable_at("native first-frame comparison"))?;
        let current = DisplayObservationFacts::from_envelope(&display, scope.topology(), now)
            .map_err(|_| invalid_original())?;
        let target = material
            .validate_native(current.inventory(), current.capabilities())
            .map_err(|_| invalid_original())?;
        let final_sample = if let Some(digest) = native.final_retirement_digest() {
            if !root_retired || actual.state != TransactionState::Committed {
                return Err(invalid_original());
            }
            let final_sample = observe(
                self,
                &query(
                    DISPLAY_RECOVERY_PROVIDER,
                    linura_observation::DISPLAY_ORDINARY_FINAL_RETIREMENT_CAPABILITY,
                    scope.resource_id().map_err(|_| invalid_original())?,
                )?,
            )?;
            let final_root =
                linura_observation::DisplayOrdinaryFinalRetirementFacts::from_envelope(
                    &final_sample,
                    &scope,
                    now_ms()?,
                )
                .map_err(|_| invalid_original())?;
            if final_root.phase() < 2
                || final_root.lineage().record != digest
                || Some(final_root.lineage().current_grant.as_str())
                    != native.current_commit_digest()
                || original.current_grant().is_none_or(|g| {
                    g.record != final_root.lineage().current_grant
                        || g.committed_record != final_root.lineage().committed_record
                })
                || !native.follows_final_retirement(final_root.checkpoint())
            {
                return Err(invalid_original());
            }
            Some(final_sample)
        } else {
            None
        };
        let lineage = root_facts.first().lineage();
        let comparison = root_facts.lineage();
        if comparison.material != intent.material()
            || lineage.release_transaction != snapshot.transaction_id.as_str()
            || lineage.release_effect != effect_from_request(&request)?.digest().to_hex()
            || lineage.release_dispatch != dispatch
            || !native.follows_handoff(root_facts.first())
            || native.completion_digest() != comparison.record
            || native.power_fence_held() != power_held
            || native.current_commit_digest().is_some_and(|digest| {
                !root_retired
                    || actual.state != TransactionState::Committed
                    || original
                        .current_grant()
                        .is_none_or(|grant| grant.record != digest)
            })
            || native.lineage().original_transaction
                != original.original_snapshot().transaction_id.as_str()
            || native.lineage().original_effect
                != effect_from_request(original.request())?.digest().to_hex()
            || !native.matches_layout(&target)
            || current.layout() != &target
            || !current.has_powered_independent_output()
            || linura_provider_sdk::display_baseline_guard(&current)
                .map_err(|_| invalid_original())?
                .to_hex()
                != material.lineage().current_source_guard
        {
            return Err(unavailable_at(
                "Root, native, layout and original lineage join",
            ));
        }
        {
            let _checked = self.checked_display_history()?;
            completion::require_current_preparation(
                self.display_journal()?,
                &principal_id,
                &request,
                &snapshot,
                &root_facts,
            )?;
        }
        crate::DisplayLayoutSafetyReview::review(
            &principal, &target, &display, &session, &coverage, now,
        )
        .map_err(|_| unavailable_at("independent session and lock review"))?;
        let after_frames = observe(self, &frame_query)?;
        let after_root = observe(self, &root_query)?;
        let checked_frames =
            DisplayOrdinaryCurrentFacts::from_envelope(&after_frames, &scope, now_ms()?)
                .map_err(|_| invalid_original())?;
        let checked_root =
            DisplayOrdinaryCompletionFacts::from_envelope(&after_root, &scope, now_ms()?)
                .map_err(|_| invalid_original())?;
        if after_frames.sequence <= frames.sequence
            || after_root.sequence <= root.sequence
            || after_frames.observed_at_unix_ms < frames.observed_at_unix_ms
            || after_root.observed_at_unix_ms < root.observed_at_unix_ms
            || !checked_frames.reconciles(&native)
            || checked_root != root_facts
            || !checked_frames.follows_handoff(checked_root.first())
            || checked_frames.completion_digest() != checked_root.lineage().record
        {
            return Err(unavailable_at("post-read frame and Root reconciliation"));
        }
        self.require_ordinary_terminal_history(
            &principal,
            original.request(),
            original.original_snapshot(),
            original.eligibility(),
        )?;
        let checked = self.checked_display_history()?;
        if self
            .authority
            .matching_request_snapshot(&principal, &request)?
            != actual
            || self
                .display_journal()?
                .load(&principal_id, release_request)
                .map_err(|_| invalid_original())?
                != retained
            || OrdinaryReleaseIntent::load(self.display_journal()?, &principal_id, &request)?
                != intent
            || self.ordinary_release_receipt_at(&principal, &request, &snapshot)? != receipt
        {
            return Err(unavailable_at("post-read durable history"));
        }
        intent.require_claim(self.display_journal()?, &principal_id, &request)?;
        completion::require_current_preparation(
            self.display_journal()?,
            &principal_id,
            &request,
            &snapshot,
            &checked_root,
        )?;
        drop(checked);
        let now = now_ms()?;
        for (label, source) in [
            ("original", original.observation()),
            ("display", &display),
            ("session", &session),
            ("coverage", &coverage),
            ("current_frame", &frames),
            ("reconciled_frame", &after_frames),
            ("rechecked_root", &after_root),
        ] {
            crate::plan_preview::restrict_session_validity(&mut root, source, now)
                .map_err(|_| invalid_original())?;
            root.attributes.insert(
                format!("control.ordinary-current.{label}_digest"),
                ObservedValue::Text(
                    crate::durable_authority::digest_observation(source)?
                        .as_str()
                        .into(),
                ),
            );
        }
        if let Some(sample) = &final_sample {
            crate::plan_preview::restrict_session_validity(&mut root, sample, now_ms()?)
                .map_err(|_| invalid_original())?;
            root.attributes.insert(
                "control.ordinary-current.final_grant_digest".into(),
                ObservedValue::Text(
                    crate::durable_authority::digest_observation(sample)?
                        .as_str()
                        .into(),
                ),
            );
        }
        root.require_current(now_ms()?)
            .map_err(|_| invalid_original())?;
        Ok(OrdinaryDisplayCurrentInspection {
            observation: root,
            frames: checked_frames,
            root: checked_root,
            comparison_release: snapshot,
            release: actual,
            request,
            layout: target,
        })
    }
}
