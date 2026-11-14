//! Independent ordinary first-frame join. Inspection never completes a signed
//! transaction, retires a fence, admits a successor or authorizes cleanup.
use super::*;
use crate::display_ordinary_release_intent::OrdinaryReleaseIntent;
use linura_core::{CapabilityId, DisplayOrdinaryReleaseMaterial, ProviderId};
use linura_observation::{
    DISPLAY_COVERAGE_CAPABILITY, DISPLAY_ORDINARY_HANDOFF_CAPABILITY,
    DISPLAY_ORDINARY_RELEASE_CAPABILITY, DISPLAY_OUTPUTS_CAPABILITY, DISPLAY_PROVIDER,
    DISPLAY_RECOVERY_PROVIDER, DisplayObservationFacts, DisplayOrdinaryHandoffFacts,
    DisplayOrdinaryReleaseFacts,
};
use linura_protocol::ObservationRequest;
use linura_transaction::TransactionSnapshot;
mod proof;
pub use proof::OrdinaryDisplayHandoffVerification;

fn unavailable_at(stage: &str) -> ManagedLifecycleError {
    ManagedLifecycleError::Verification(format!(
        "ordinary handoff unavailable at {stage}; no completion authority"
    ))
}

#[derive(Debug)]
pub struct OrdinaryDisplayHandoffInspection {
    observation: ObservationEnvelope,
    frames: DisplayOrdinaryHandoffFacts,
    root: DisplayOrdinaryReleaseFacts,
    release: TransactionSnapshot,
    request: PlanDesiredStateRequest,
}
impl OrdinaryDisplayHandoffInspection {
    #[must_use]
    pub const fn observation(&self) -> &ObservationEnvelope {
        &self.observation
    }
    #[must_use]
    pub const fn frames(&self) -> &DisplayOrdinaryHandoffFacts {
        &self.frames
    }
    #[must_use]
    pub const fn root(&self) -> &DisplayOrdinaryReleaseFacts {
        &self.root
    }
    #[must_use]
    pub const fn release(&self) -> &TransactionSnapshot {
        &self.release
    }
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    /// A lost dispatch acknowledgement can be inspected without replaying the
    /// native port. All contributors and immutable history must still agree.
    pub fn inspect_ordinary_display_handoff<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        release_request: &RequestId,
        attempt: &mut P,
        verifier: &mut V,
    ) -> Result<OrdinaryDisplayHandoffInspection, ManagedLifecycleError> {
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        self.authority.integrity_check()?;
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
        let receipt = self.ordinary_release_receipt(&principal, &request)?;
        let dispatch = receipt
            .dispatch_digest
            .as_deref()
            .ok_or_else(invalid_original)?;
        let snapshot = self
            .authority
            .matching_request_snapshot(&principal, &request)?;
        if snapshot.state != TransactionState::Indeterminate {
            return Err(unavailable_at("signed release dispatch"));
        }
        let material = DisplayOrdinaryReleaseMaterial::decode(intent.material())
            .map_err(|_| invalid_original())?;
        let scope = material.release_scope().map_err(|_| invalid_original())?;
        let original = self.inspect_ordinary_display_original(
            principal.clone(),
            &material.lineage().original_request,
            attempt,
            verifier,
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
            || material.lineage().original_checkpoint != original.root().comparison().checkpoint
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
            DISPLAY_ORDINARY_RELEASE_CAPABILITY,
            resource.clone(),
        )?;
        let frame_query = query(
            DISPLAY_PROVIDER,
            DISPLAY_ORDINARY_HANDOFF_CAPABILITY,
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
        let root_facts = DisplayOrdinaryReleaseFacts::from_envelope(&root, &scope, now)
            .map_err(|_| unavailable_at("Root spend comparison"))?;
        let native = DisplayOrdinaryHandoffFacts::from_envelope(&frames, &scope, now)
            .map_err(|_| unavailable_at("native first-frame comparison"))?;
        let current = DisplayObservationFacts::from_envelope(&display, scope.topology(), now)
            .map_err(|_| invalid_original())?;
        let target = material
            .validate_native(current.inventory(), current.capabilities())
            .map_err(|_| invalid_original())?;
        let comparison = root_facts.comparison();
        if comparison.material != intent.material()
            || comparison.transaction != snapshot.transaction_id.as_str()
            || comparison.effect != effect_from_request(&request)?.digest().to_hex()
            || comparison.dispatch != dispatch
            || !root_facts.matches_native(&native)
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
        crate::DisplayLayoutSafetyReview::review(
            &principal, &target, &display, &session, &coverage, now,
        )
        .map_err(|_| unavailable_at("independent session and lock review"))?;
        let after_frames = observe(self, &frame_query)?;
        let after_root = observe(self, &root_query)?;
        let checked_frames =
            DisplayOrdinaryHandoffFacts::from_envelope(&after_frames, &scope, now_ms()?)
                .map_err(|_| invalid_original())?;
        let checked_root =
            DisplayOrdinaryReleaseFacts::from_envelope(&after_root, &scope, now_ms()?)
                .map_err(|_| invalid_original())?;
        if after_frames.sequence <= frames.sequence
            || after_root.sequence <= root.sequence
            || after_frames.observed_at_unix_ms < frames.observed_at_unix_ms
            || after_root.observed_at_unix_ms < root.observed_at_unix_ms
            || !checked_frames.reconciles(&native)
            || !checked_root.reconciles(&root_facts)
            || !checked_root.matches_native(&checked_frames)
        {
            return Err(unavailable_at("post-read frame and Root reconciliation"));
        }
        self.require_ordinary_release_history(&principal, &original)?;
        self.authority.integrity_check()?;
        if self
            .authority
            .matching_request_snapshot(&principal, &request)?
            != snapshot
            || self
                .display_journal()?
                .load(&principal_id, release_request)
                .map_err(|_| invalid_original())?
                != retained
            || OrdinaryReleaseIntent::load(self.display_journal()?, &principal_id, &request)?
                != intent
            || self.ordinary_release_receipt(&principal, &request)? != receipt
        {
            return Err(unavailable_at("post-read durable history"));
        }
        intent.require_claim(self.display_journal()?, &principal_id, &request)?;
        let now = now_ms()?;
        for (label, source) in [
            ("original", original.observation()),
            ("display", &display),
            ("session", &session),
            ("coverage", &coverage),
            ("first_frame", &frames),
            ("reconciled_frame", &after_frames),
            ("rechecked_root", &after_root),
        ] {
            crate::plan_preview::restrict_session_validity(&mut root, source, now)
                .map_err(|_| invalid_original())?;
            root.attributes.insert(
                format!("control.ordinary-handoff.{label}_digest"),
                ObservedValue::Text(
                    crate::durable_authority::digest_observation(source)?
                        .as_str()
                        .into(),
                ),
            );
        }
        root.require_current(now_ms()?)
            .map_err(|_| invalid_original())?;
        Ok(OrdinaryDisplayHandoffInspection {
            observation: root,
            frames: checked_frames,
            root: checked_root,
            release: snapshot,
            request,
        })
    }
}
