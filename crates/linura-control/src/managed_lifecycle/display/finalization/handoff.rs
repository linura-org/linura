//! Purpose-bound original continuations and independent post-effect comparison.
//! Physical effects, immutable proofs, signed completion and admission are distinct.
use super::*;
use crate::display_native_release_spend::verification::NativeHandoffVerified;
use linura_core::CapabilityId;
use linura_observation::{
    DISPLAY_COVERAGE_CAPABILITY, DISPLAY_NATIVE_HANDOFF_CAPABILITY,
    DISPLAY_ORIGINAL_PROTECTION_CAPABILITY, DISPLAY_OUTPUTS_CAPABILITY, DISPLAY_PROVIDER,
    DisplayNativeHandoffFacts, DisplayObservationFacts, DisplayOriginalProtectionFacts,
};
use linura_protocol::ObservationRequest;

mod completed;
mod completion;
mod successor;
pub use completed::OriginalDisplayCurrentCommit;
mod current;
mod final_retirement;
pub use final_retirement::{
    AuthorizedOriginalDisplayFinalRetirement, OriginalDisplayFinalRetirementPort,
    OriginalDisplayFinalRetirementVerification, OriginalDisplayReleasedCurrent,
    OriginalDisplayReleasedCurrentCompletion, OriginalDisplayReleasedCurrentPort,
};
mod current_commit;
pub use current_commit::{
    AuthorizedOriginalDisplayCurrentCommit, OriginalDisplayCurrentCommitPort,
    OriginalDisplayQualifiedCurrent,
};
mod power;
mod root_power;
pub use completion::{
    AuthorizedOriginalDisplayCompletion, OriginalDisplayCompletionPort,
    OriginalDisplayCompletionReceipt,
};
pub use current::{OriginalDisplayCurrentInspection, OriginalDisplayCurrentVerification};
pub use power::{
    AuthorizedOriginalDisplayNativePowerRetirement, OriginalDisplayNativePowerInspection,
    OriginalDisplayNativePowerRetirementPort,
};
pub use root_power::{
    AuthorizedOriginalDisplayRootPowerRetirement, OriginalDisplayRootPowerInspection,
    OriginalDisplayRootPowerRetirementPort,
};

fn unavailable_at(stage: &'static str) -> ManagedLifecycleError {
    ManagedLifecycleError::Verification(format!("original display handoff unavailable at {stage}"))
}

/// Durably retained first-frame verification, with a separate fresh inspection.
/// The signed terminal remains Indeterminate. No member is completion authority.
#[derive(Debug)]
pub struct OriginalDisplayNativeHandoffVerification {
    inspection: OriginalDisplayNativeHandoffInspection,
    record_digest: linura_transaction::ContentDigest,
    first_verified_unix_ms: u64,
    valid_until_unix_ms: u64,
    proof: NativeHandoffVerified,
}
impl OriginalDisplayNativeHandoffVerification {
    #[must_use]
    pub const fn inspection(&self) -> &OriginalDisplayNativeHandoffInspection {
        &self.inspection
    }
    #[must_use]
    pub const fn record_digest(&self) -> &linura_transaction::ContentDigest {
        &self.record_digest
    }
    #[must_use]
    pub const fn first_verified_unix_ms(&self) -> u64 {
        self.first_verified_unix_ms
    }
    #[must_use]
    pub const fn valid_until_unix_ms(&self) -> u64 {
        self.valid_until_unix_ms
    }
}

/// Fresh, expiring comparison of the independently read post-effect sources.
/// This cannot complete durable history, recreate a permit after restart or
/// release original Root, input, S17, power or startup admission.
#[derive(Debug)]
pub struct OriginalDisplayNativeHandoffInspection {
    material: String,
    observation: ObservationEnvelope,
    frames: DisplayNativeHandoffFacts,
    terminal: TransactionSnapshot,
    // Authenticated and reloaded at the end of this exact inspection. These
    // private immutable anchors avoid repeating the same pre-write reads with
    // no intervening effect; storage is freshly reloaded again AFTER retention.
    context: TerminalInspectionContext,
    anchors: HandoffAnchors,
}
impl OriginalDisplayNativeHandoffInspection {
    #[must_use]
    pub fn material(&self) -> &str {
        &self.material
    }
    #[must_use]
    pub const fn observation(&self) -> &ObservationEnvelope {
        &self.observation
    }
    #[must_use]
    pub const fn frames(&self) -> &DisplayNativeHandoffFacts {
        &self.frames
    }
    #[must_use]
    pub const fn terminal(&self) -> &TransactionSnapshot {
        &self.terminal
    }
}

#[derive(Debug, Eq, PartialEq)]
struct HandoffAnchors {
    retirement: crate::display_terminal_retirement::TerminalRetirementPrepared,
    reserved: NativeReleasePrepared,
    spent: NativeReleaseSpendPrepared,
}
impl<S: TransactionStore> ManagedLifecycleControl<S> {
    /// Record only an independently re-observed original first-frame tuple.
    /// This also recovers verification after a missing dispatch reply, without
    /// invoking an effect port or reconstructing approval. The first durable
    /// proof and its original expiry cannot be refreshed by subsequent calls.
    pub fn verify_native_handoff_original_display_finalization(
        &mut self,
        principal: AuthenticatedPrincipal,
        terminal_request: &RequestId,
    ) -> Result<OriginalDisplayNativeHandoffVerification, ManagedLifecycleError> {
        self.verify_native_handoff_with_spend(principal, terminal_request, None)
    }

    pub(super) fn verify_native_handoff_with_spend(
        &mut self,
        principal: AuthenticatedPrincipal,
        terminal_request: &RequestId,
        expected_spend: Option<&NativeReleaseSpendPrepared>,
    ) -> Result<OriginalDisplayNativeHandoffVerification, ManagedLifecycleError> {
        let inspection =
            self.inspect_native_handoff_inner(principal.clone(), terminal_request, expected_spend)?;
        let terminal = &inspection.context;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let anchors = &inspection.anchors;
        if inspection.terminal != terminal.snapshot
            || inspection.material != terminal.intent.material()
        {
            return Err(invalid());
        }
        let proof = NativeHandoffVerified::capture(
            &principal_id,
            &terminal.request,
            &terminal.snapshot,
            terminal
                .receipt
                .dispatch_digest
                .as_deref()
                .ok_or_else(invalid)?,
            terminal.intent.material(),
            &anchors.spent,
            &inspection.observation,
            &inspection.frames,
            now_ms()?,
        )
        .map_err(|_| {
            ManagedLifecycleError::Verification(
                "independent handoff proof cannot bind its canonical terminal and spent ancestry"
                    .into(),
            )
        })?;
        let retained = proof
            .retain_or_reconcile(self.request_journal.as_deref_mut().ok_or_else(invalid)?)
            .map_err(|_| {
                ManagedLifecycleError::Verification(
                    "independent handoff verification journal unavailable or contradictory".into(),
                )
            })?;
        let expiry = retained.expiry().min(proof.expiry());
        {
            let checked = self.checked_display_history()?;
            if self.terminal_context_from_checked(&principal, terminal_request, &checked)?
                != *terminal
                || self.native_handoff_anchors(&principal_id, terminal)? != *anchors
            {
                return Err(invalid());
            }
        }
        let finished = now_ms()?;
        if finished < proof.observed_at() || finished >= expiry {
            return Err(invalid());
        }
        Ok(OriginalDisplayNativeHandoffVerification {
            inspection,
            record_digest: retained.digest(),
            first_verified_unix_ms: retained.observed_at(),
            valid_until_unix_ms: expiry,
            proof: retained,
        })
    }

    fn native_handoff_anchors(
        &self,
        principal: &PrincipalId,
        terminal: &TerminalInspectionContext,
    ) -> Result<HandoffAnchors, ManagedLifecycleError> {
        let dispatch = terminal
            .receipt
            .dispatch_digest
            .as_deref()
            .ok_or_else(invalid)?;
        let retirement =
            crate::display_terminal_retirement::TerminalRetirementPrepared::load_spent(
                self.display_journal()?,
                principal,
                &terminal.request,
                &terminal.snapshot,
                dispatch,
                terminal.intent.material(),
            )?;
        let reserved = NativeReleasePrepared::load_spent(
            self.display_journal()?,
            principal,
            &terminal.request,
            &terminal.snapshot,
            dispatch,
            terminal.intent.material(),
            &retirement,
        )?;
        let spent = NativeReleaseSpendPrepared::load_spent(
            self.display_journal()?,
            principal,
            &terminal.request,
            &terminal.snapshot,
            dispatch,
            terminal.intent.material(),
            &reserved,
        )?;
        Ok(HandoffAnchors {
            retirement,
            reserved,
            spent,
        })
    }

    pub fn inspect_native_handoff_original_display_finalization(
        &mut self,
        principal: AuthenticatedPrincipal,
        terminal_request: &RequestId,
    ) -> Result<OriginalDisplayNativeHandoffInspection, ManagedLifecycleError> {
        self.inspect_native_handoff_inner(principal, terminal_request, None)
    }

    fn inspect_native_handoff_inner(
        &mut self,
        principal: AuthenticatedPrincipal,
        terminal_request: &RequestId,
        expected_spend: Option<&NativeReleaseSpendPrepared>,
    ) -> Result<OriginalDisplayNativeHandoffInspection, ManagedLifecycleError> {
        // Authenticate all immutable history before probing any current source.
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let (terminal, history, anchors) = {
            let checked = self.checked_display_history()?;
            let terminal =
                self.terminal_context_from_checked(&principal, terminal_request, &checked)?;
            let material = DisplayFinalizationMaterial::decode(terminal.intent.material())
                .map_err(|_| invalid())?;
            let history = self.finalization_history_from_checked(
                &principal,
                material.restoration_request(),
                &checked,
            )?;
            let anchors = self.native_handoff_anchors(&principal_id, &terminal)?;
            (terminal, history, anchors)
        };
        if expected_spend.is_some_and(|expected| expected != &anchors.spent) {
            return Err(unavailable_at("exact spent record readback"));
        }
        let material = DisplayFinalizationMaterial::decode(terminal.intent.material())
            .map_err(|_| invalid())?;
        let restoration = material.restoration();
        let scope = material.recovery_scope().map_err(|_| invalid())?;
        if material.terminal_link() != history.link.digest().hex()
            || material.restoration_text() != history.restoration.desired_state["restore_original"]
            || Some(material.restoration_dispatch())
                != history.dispatched.dispatch_digest.as_deref()
            || now_ms()? >= anchors.spent.expiry()
        {
            return Err(unavailable_at("linked history or original spend deadline"));
        }
        let scope_resource = scope.resource_id().map_err(|_| invalid())?;
        let request = |provider: &str, capability: &str, resource: ResourceId| {
            Ok::<_, ManagedLifecycleError>(ObservationRequest {
                provider: ProviderId::new(provider).map_err(|_| invalid())?,
                capability: CapabilityId::new(capability).map_err(|_| invalid())?,
                resource,
            })
        };
        let root_query = request(
            DISPLAY_RECOVERY_PROVIDER,
            DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY,
            scope_resource.clone(),
        )?;
        let protection_query = request(
            DISPLAY_RECOVERY_PROVIDER,
            DISPLAY_ORIGINAL_PROTECTION_CAPABILITY,
            scope_resource.clone(),
        )?;
        let frame_query = request(
            DISPLAY_PROVIDER,
            DISPLAY_NATIVE_HANDOFF_CAPABILITY,
            scope_resource,
        )?;
        let observe = |this: &mut Self, request: &ObservationRequest| {
            this.previews
                .observe(request)
                .map(|value| value.observation)
                .map_err(|_| invalid())
        };
        let mut root = observe(self, &root_query)?;
        let protection = observe(self, &protection_query)?;
        let display = observe(
            self,
            &request(
                DISPLAY_PROVIDER,
                DISPLAY_OUTPUTS_CAPABILITY,
                restoration
                    .replacement()
                    .topology()
                    .resource_id()
                    .map_err(|_| invalid())?,
            )?,
        )?;
        let session = observe(
            self,
            &request(
                "logind",
                "session.epoch.observe",
                restoration
                    .replacement()
                    .topology()
                    .session()
                    .resource_id()
                    .map_err(|_| invalid())?,
            )?,
        )?;
        let coverage = observe(
            self,
            &request(
                "session-locker",
                DISPLAY_COVERAGE_CAPABILITY,
                material
                    .current_lock()
                    .resource_id()
                    .map_err(|_| invalid())?,
            )?,
        )?;
        let frames = observe(self, &frame_query)?;
        let now = now_ms()?;
        let root_facts = DisplayOriginalFinalizationFacts::from_envelope(&root, &scope, now)
            .map_err(|_| unavailable_at("Root facts"))?;
        let original = DisplayOriginalProtectionFacts::from_envelope(&protection, &scope, now)
            .map_err(|_| unavailable_at("original protection facts"))?;
        let current = DisplayObservationFacts::from_envelope(
            &display,
            restoration.replacement().topology(),
            now,
        )
        .map_err(|_| unavailable_at("current display facts"))?;
        let ordinary = DisplayNativeHandoffFacts::from_envelope(&frames, &scope, now)
            .map_err(|_| unavailable_at("first ordinary frame facts"))?;
        let (restored, source_guard) = history
            .source
            .verify_handoff_source(restoration, &original, &current)
            .map_err(|_| unavailable_at("restored source ownership"))?;
        let lineage = ordinary.lineage();
        if !terminal.matches(&root_facts, DisplayFinalizationPhase::NativeReleaseSpent)
            || root_facts.checkpoint() != restoration.original_checkpoint()
            || root_facts.restoration_transaction()
                != history.restoration_snapshot.transaction_id.as_str()
            || root_facts.restoration_effect()
                != effect_from_request(&history.restoration)?.digest().to_hex()
            || Some(root_facts.restoration_dispatch())
                != history.dispatched.dispatch_digest.as_deref()
            || !ordinary.matches_root(&root_facts)
            || lineage.source_guard != source_guard.to_hex()
            || !ordinary.matches_layout(restored.desired())
        {
            return Err(unavailable_at(
                "native, Root and restored lineage comparison",
            ));
        }
        crate::DisplayLayoutSafetyReview::review(
            &principal,
            restored.desired(),
            &display,
            &session,
            &coverage,
            now,
        )
        .map_err(|_| unavailable_at("independent session and lock safety review"))?;
        // Re-sample the same retained first frame and Root state. Neither read
        // may adopt a successor buffer, renewed deadline or new authority.
        let after_frames = observe(self, &frame_query)?;
        let after_root = observe(self, &root_query)?;
        let after_protection = observe(self, &protection_query)?;
        let checked = DisplayNativeHandoffFacts::from_envelope(&after_frames, &scope, now_ms()?)
            .map_err(|_| unavailable_at("reconciled ordinary frame facts"))?;
        if !checked.reconciles(&ordinary)
            || after_frames.sequence <= frames.sequence
            || after_root.sequence <= root.sequence
            || after_protection.sequence <= protection.sequence
            || DisplayOriginalFinalizationFacts::from_envelope(&after_root, &scope, now_ms()?)
                .map_err(|_| invalid())?
                != root_facts
            || DisplayOriginalProtectionFacts::from_envelope(&after_protection, &scope, now_ms()?)
                .map_err(|_| invalid())?
                != original
        {
            return Err(unavailable_at("post-read native and Root reconciliation"));
        }
        {
            let checked = self.checked_display_history()?;
            if self.finalization_history_from_checked(
                &principal,
                material.restoration_request(),
                &checked,
            )? != history
            {
                return Err(unavailable_at("post-read restoration history"));
            }
            if self.terminal_context_from_checked(&principal, terminal_request, &checked)?
                != terminal
            {
                return Err(unavailable_at("post-read terminal history"));
            }
            if self.native_handoff_anchors(&principal_id, &terminal)? != anchors {
                return Err(unavailable_at("post-read spent ancestry"));
            }
        }
        if now_ms()? >= anchors.spent.expiry() {
            return Err(unavailable_at(
                "original spend deadline after durable reconciliation",
            ));
        }
        // Join absolute expiries, preserving every producer's original sample.
        let now = now_ms()?;
        let expiry = root
            .observed_at_unix_ms
            .checked_add(root.valid_for_ms)
            .ok_or_else(invalid)?
            .min(anchors.spent.expiry());
        root.valid_for_ms = expiry
            .checked_sub(root.observed_at_unix_ms)
            .ok_or_else(invalid)?;
        for (label, source) in [
            ("original_protection", &protection),
            ("display", &display),
            ("session", &session),
            ("coverage", &coverage),
            ("first_ordinary_frame", &frames),
            ("reconciled_frame", &after_frames),
            ("rechecked_root", &after_root),
            ("rechecked_protection", &after_protection),
        ] {
            crate::plan_preview::restrict_session_validity(&mut root, source, now)
                .map_err(|_| invalid())?;
            root.attributes.insert(
                format!("control.handoff.{label}_digest"),
                ObservedValue::Text(
                    crate::durable_authority::digest_observation(source)?
                        .as_str()
                        .into(),
                ),
            );
        }
        root.require_current(now_ms()?).map_err(|_| invalid())?;
        Ok(OriginalDisplayNativeHandoffInspection {
            material: terminal.intent.material().to_owned(),
            observation: root,
            frames: checked,
            terminal: terminal.snapshot.clone(),
            context: terminal,
            anchors,
        })
    }
}
