//! Read-only independent post-effect comparison. No completion or release port.
use super::*;
use linura_core::CapabilityId;
use linura_observation::{
    DISPLAY_COVERAGE_CAPABILITY, DISPLAY_NATIVE_HANDOFF_CAPABILITY,
    DISPLAY_ORIGINAL_PROTECTION_CAPABILITY, DISPLAY_OUTPUTS_CAPABILITY, DISPLAY_PROVIDER,
    DisplayNativeHandoffFacts, DisplayObservationFacts, DisplayOriginalProtectionFacts,
};
use linura_protocol::ObservationRequest;

/// Fresh, expiring comparison of the independently read post-effect sources.
/// This cannot complete durable history, recreate a permit after restart or
/// release original Root, input, S17, power or startup admission.
#[derive(Debug)]
pub struct OriginalDisplayNativeHandoffInspection {
    material: String,
    observation: ObservationEnvelope,
    frames: DisplayNativeHandoffFacts,
    terminal: TransactionSnapshot,
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
        // Authenticate all immutable history before probing any current source.
        let terminal = self.terminal_inspection_context(&principal, terminal_request)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let anchors = self.native_handoff_anchors(&principal_id, &terminal)?;
        let material = DisplayFinalizationMaterial::decode(terminal.intent.material())
            .map_err(|_| invalid())?;
        let restoration = material.restoration();
        let scope = material.recovery_scope().map_err(|_| invalid())?;
        let history = self.finalization_history(&principal, material.restoration_request())?;
        if material.terminal_link() != history.link.digest().hex()
            || material.restoration_text() != history.restoration.desired_state["restore_original"]
            || Some(material.restoration_dispatch())
                != history.dispatched.dispatch_digest.as_deref()
            || now_ms()? >= anchors.spent.expiry()
        {
            return Err(invalid());
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
            .map_err(|_| invalid())?;
        let original = DisplayOriginalProtectionFacts::from_envelope(&protection, &scope, now)
            .map_err(|_| invalid())?;
        let current = DisplayObservationFacts::from_envelope(
            &display,
            restoration.replacement().topology(),
            now,
        )
        .map_err(|_| invalid())?;
        let ordinary = DisplayNativeHandoffFacts::from_envelope(&frames, &scope, now)
            .map_err(|_| invalid())?;
        let (restored, source_guard) = history
            .source
            .verify_handoff_source(restoration, &original, &current)
            .map_err(|_| invalid())?;
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
        // Re-sample the same retained first frame and Root state. Neither read
        // may adopt a successor buffer, renewed deadline or new authority.
        let after_frames = observe(self, &frame_query)?;
        let after_root = observe(self, &root_query)?;
        let after_protection = observe(self, &protection_query)?;
        let checked = DisplayNativeHandoffFacts::from_envelope(&after_frames, &scope, now_ms()?)
            .map_err(|_| invalid())?;
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
            || self.finalization_history(&principal, material.restoration_request())? != history
            || self.terminal_inspection_context(&principal, terminal_request)? != terminal
            || self.native_handoff_anchors(&principal_id, &terminal)? != anchors
            || now_ms()? >= anchors.spent.expiry()
        {
            return Err(invalid());
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
            terminal: terminal.snapshot,
        })
    }
}
