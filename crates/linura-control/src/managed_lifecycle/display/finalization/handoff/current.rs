//! Independent current-state comparison after the physical handoff. Read-only
//! recovery never recreates the spent continuation, commits ReleasedCurrent or
//! retires input, power, admission or retained evidence.
use super::*;
use crate::display_native_release_spend::verification::completion::NativeCompletionPrepared;
use crate::display_native_release_spend::verification::current::NativeCurrentVerified;
use linura_observation::{
    DISPLAY_NATIVE_CURRENT_CAPABILITY, DISPLAY_ORIGINAL_COMPLETION_CAPABILITY,
    DisplayNativeCurrentFacts, DisplayOriginalCompletionFacts,
};

#[derive(Debug)]
pub struct OriginalDisplayCurrentInspection {
    observation: ObservationEnvelope,
    frames: DisplayNativeCurrentFacts,
    terminal: TransactionSnapshot,
    preparation: linura_transaction::ContentDigest,
    prepared: NativeCompletionPrepared,
    root: DisplayOriginalCompletionFacts,
    context: TerminalInspectionContext,
    anchors: HandoffAnchors,
    history: LinkedHistory,
}
impl OriginalDisplayCurrentInspection {
    #[must_use]
    pub const fn observation(&self) -> &ObservationEnvelope {
        &self.observation
    }
    #[must_use]
    pub const fn frames(&self) -> &DisplayNativeCurrentFacts {
        &self.frames
    }
    #[must_use]
    pub const fn terminal(&self) -> &TransactionSnapshot {
        &self.terminal
    }
    #[must_use]
    pub const fn preparation(&self) -> &linura_transaction::ContentDigest {
        &self.preparation
    }
}

/// Immutable first current-state checkpoint plus a separate fresh inspection.
/// Neither historical proof nor its digest is a retirement credential. The
/// expiry below belongs only to the new inspection; the retained proof keeps
/// its own original verification time and expiry across restart/re-observation.
#[derive(Debug)]
pub struct OriginalDisplayCurrentVerification {
    inspection: OriginalDisplayCurrentInspection,
    record_digest: linura_transaction::ContentDigest,
    first_verified_unix_ms: u64,
    first_proof_valid_until_unix_ms: u64,
    valid_until_unix_ms: u64,
}
impl OriginalDisplayCurrentVerification {
    #[must_use]
    pub const fn inspection(&self) -> &OriginalDisplayCurrentInspection {
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
    pub const fn first_proof_valid_until_unix_ms(&self) -> u64 {
        self.first_proof_valid_until_unix_ms
    }
    #[must_use]
    pub const fn valid_until_unix_ms(&self) -> u64 {
        self.valid_until_unix_ms
    }
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    /// Retain independent current-state evidence without changing terminal
    /// state or invoking an effect. A prior checkpoint is compared, never
    /// overwritten; after restart every source must still be read afresh.
    pub fn verify_current_original_display_completion(
        &mut self,
        principal: AuthenticatedPrincipal,
        terminal_request: &RequestId,
    ) -> Result<OriginalDisplayCurrentVerification, ManagedLifecycleError> {
        let inspection =
            self.inspect_current_original_display_completion(principal.clone(), terminal_request)?;
        let context = &inspection.context;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let proof = NativeCurrentVerified::capture(
            &principal_id,
            &context.request,
            &context.snapshot,
            context
                .receipt
                .dispatch_digest
                .as_deref()
                .ok_or_else(invalid)?,
            &inspection.prepared,
            &inspection.root,
            &inspection.observation,
            &inspection.frames,
            now_ms()?,
        )?;
        let retained =
            proof.retain_or_reconcile(self.request_journal.as_deref_mut().ok_or_else(invalid)?)?;
        inspection
            .prepared
            .require_readback(self.display_journal()?)?;
        if self.terminal_inspection_context(&principal, terminal_request)? != *context
            || self.native_handoff_anchors(&principal_id, context)? != inspection.anchors
            || self.finalization_history(
                &principal,
                DisplayFinalizationMaterial::decode(context.intent.material())
                    .map_err(|_| invalid())?
                    .restoration_request(),
            )? != inspection.history
        {
            return Err(invalid());
        }
        let finished = now_ms()?;
        inspection
            .observation
            .require_current(finished)
            .map_err(|_| invalid())?;
        if finished < proof.verified_at() || finished >= proof.expiry() {
            return Err(invalid());
        }
        Ok(OriginalDisplayCurrentVerification {
            record_digest: retained.digest(),
            first_verified_unix_ms: retained.verified_at(),
            first_proof_valid_until_unix_ms: retained.expiry(),
            valid_until_unix_ms: proof.expiry(),
            inspection,
        })
    }

    /// Lost acknowledgements and Control restart may inspect the actual live
    /// Root/native lifetime, but cannot redeliver any spent grant. This joins
    /// current native frames with immutable old proof without relabelling the
    /// old first-frame tuple as current observation or extending its clocks.
    pub fn inspect_current_original_display_completion(
        &mut self,
        principal: AuthenticatedPrincipal,
        terminal_request: &RequestId,
    ) -> Result<OriginalDisplayCurrentInspection, ManagedLifecycleError> {
        let terminal = self.terminal_inspection_context(&principal, terminal_request)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let anchors = self.native_handoff_anchors(&principal_id, &terminal)?;
        let material = DisplayFinalizationMaterial::decode(terminal.intent.material())
            .map_err(|_| invalid())?;
        let restoration = material.restoration();
        let scope = material.recovery_scope().map_err(|_| invalid())?;
        let resource = scope.resource_id().map_err(|_| invalid())?;
        let history = self.finalization_history(&principal, material.restoration_request())?;
        if material.terminal_link() != history.link.digest().hex()
            || material.restoration_text() != history.restoration.desired_state["restore_original"]
            || Some(material.restoration_dispatch())
                != history.dispatched.dispatch_digest.as_deref()
        {
            return Err(invalid());
        }
        let query = |provider: &str, capability: &str, resource: ResourceId| {
            Ok::<_, ManagedLifecycleError>(ObservationRequest {
                provider: ProviderId::new(provider).map_err(|_| invalid())?,
                capability: CapabilityId::new(capability).map_err(|_| invalid())?,
                resource,
            })
        };
        let root_query = query(
            DISPLAY_RECOVERY_PROVIDER,
            DISPLAY_ORIGINAL_COMPLETION_CAPABILITY,
            resource.clone(),
        )?;
        let protection_query = query(
            DISPLAY_RECOVERY_PROVIDER,
            DISPLAY_ORIGINAL_PROTECTION_CAPABILITY,
            resource.clone(),
        )?;
        let current_query = query(
            DISPLAY_PROVIDER,
            DISPLAY_NATIVE_CURRENT_CAPABILITY,
            resource,
        )?;
        let observe = |this: &mut Self, request: &ObservationRequest| {
            this.previews
                .observe(request)
                .map(|result| result.observation)
                .map_err(|_| invalid())
        };
        let mut root = observe(self, &root_query)?;
        let protection = observe(self, &protection_query)?;
        let display = observe(
            self,
            &query(
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
            &query(
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
            &query(
                "session-locker",
                DISPLAY_COVERAGE_CAPABILITY,
                material
                    .current_lock()
                    .resource_id()
                    .map_err(|_| invalid())?,
            )?,
        )?;
        let frames = observe(self, &current_query)?;
        let now = now_ms()?;
        let root_facts = DisplayOriginalCompletionFacts::from_envelope(&root, &scope, now)
            .map_err(|_| invalid())?;
        let current = DisplayNativeCurrentFacts::from_envelope(&frames, &scope, now)
            .map_err(|_| invalid())?;
        let original = DisplayOriginalProtectionFacts::from_envelope(&protection, &scope, now)
            .map_err(|_| invalid())?;
        let outputs = DisplayObservationFacts::from_envelope(
            &display,
            restoration.replacement().topology(),
            now,
        )
        .map_err(|_| invalid())?;
        let dispatch = terminal
            .receipt
            .dispatch_digest
            .as_deref()
            .ok_or_else(invalid)?;
        let first = root_facts.first().lineage();
        let prepared = NativeCompletionPrepared::load_comparison(
            self.display_journal()?,
            &principal_id,
            &terminal.request,
            &terminal.snapshot,
            dispatch,
            &anchors.spent,
            &root_facts,
        )?;
        let (restored, source_guard) = history
            .source
            .verify_handoff_source(restoration, &original, &outputs)
            .map_err(|_| invalid())?;
        if root_facts.lineage().material != terminal.intent.material()
            || first.terminal_transaction != terminal.snapshot.transaction_id.as_str()
            || first.terminal_effect != effect_from_request(&terminal.request)?.digest().to_hex()
            || first.terminal_dispatch != dispatch
            || first.restoration_transaction != history.restoration_snapshot.transaction_id.as_str()
            || first.restoration_effect
                != effect_from_request(&history.restoration)?.digest().to_hex()
            || current.completion_digest() != root_facts.lineage().record
            || !current.input_retired()
            || !current.power_fence_held()
            || !current.follows_handoff(root_facts.first())
            || current.lineage().source_guard != source_guard.to_hex()
            || !current.matches_layout(restored.desired())
        {
            return Err(invalid());
        }
        crate::DisplayLayoutSafetyReview::review(
            &principal,
            restored.desired(),
            &display,
            &session,
            &coverage,
            now,
        )
        .map_err(|_| invalid())?;
        let after_frames = observe(self, &current_query)?;
        let after_root = observe(self, &root_query)?;
        let after_protection = observe(self, &protection_query)?;
        let checked = DisplayNativeCurrentFacts::from_envelope(&after_frames, &scope, now_ms()?)
            .map_err(|_| invalid())?;
        if after_frames.sequence <= frames.sequence
            || after_root.sequence <= root.sequence
            || after_protection.sequence <= protection.sequence
            || !checked.reconciles(&current)
            || DisplayOriginalCompletionFacts::from_envelope(&after_root, &scope, now_ms()?)
                .map_err(|_| invalid())?
                != root_facts
            || DisplayOriginalProtectionFacts::from_envelope(&after_protection, &scope, now_ms()?)
                .map_err(|_| invalid())?
                != original
            || self.finalization_history(&principal, material.restoration_request())? != history
            || self.terminal_inspection_context(&principal, terminal_request)? != terminal
            || self.native_handoff_anchors(&principal_id, &terminal)? != anchors
            || NativeCompletionPrepared::load_comparison(
                self.display_journal()?,
                &principal_id,
                &terminal.request,
                &terminal.snapshot,
                dispatch,
                &anchors.spent,
                &root_facts,
            )? != prepared
        {
            return Err(invalid());
        }
        let now = now_ms()?;
        for (name, source) in [
            ("protection", &protection),
            ("display", &display),
            ("session", &session),
            ("coverage", &coverage),
            ("current", &frames),
            ("rechecked_current", &after_frames),
            ("rechecked_root", &after_root),
            ("rechecked_protection", &after_protection),
        ] {
            crate::plan_preview::restrict_session_validity(&mut root, source, now)
                .map_err(|_| invalid())?;
            root.attributes.insert(
                format!("control.current.{name}_digest"),
                ObservedValue::Text(
                    crate::durable_authority::digest_observation(source)?
                        .as_str()
                        .into(),
                ),
            );
        }
        root.require_current(now_ms()?).map_err(|_| invalid())?;
        Ok(OriginalDisplayCurrentInspection {
            observation: root,
            frames: checked,
            terminal: terminal.snapshot.clone(),
            preparation: prepared.digest(),
            prepared,
            root: root_facts,
            context: terminal,
            anchors,
            history,
        })
    }
}
