//! Separately durable, one-use continuation of the original canonical review.
//! No acknowledgement commits Control history or proves a released fence.
use super::*;
use crate::display_native_release_spend::verification::completion::NativeCompletionPrepared;

/// Non-cloneable prepared continuation, minted only after the original live
/// review, fresh independent first-frame proof and immutable before-effect
/// journal readback. Every transport adapter must authenticate the original
/// Root/native owners and consume a distinct one-use completion grant.
pub struct AuthorizedOriginalDisplayCompletion {
    material: String,
    terminal: TransactionSnapshot,
    dispatch_digest: String,
    retirement_observation: linura_transaction::ContentDigest,
    preparation_digest: linura_transaction::ContentDigest,
    verification_digest: linura_transaction::ContentDigest,
    frames: DisplayNativeHandoffFacts,
    expires_at_unix_ms: u64,
}
impl Debug for AuthorizedOriginalDisplayCompletion {
    fn fmt(&self, out: &mut Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("AuthorizedOriginalDisplayCompletion")
            .field("transaction", &self.terminal.transaction_id)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish_non_exhaustive()
    }
}
impl AuthorizedOriginalDisplayCompletion {
    #[must_use]
    pub fn material(&self) -> &str {
        &self.material
    }
    #[must_use]
    pub const fn terminal(&self) -> &TransactionSnapshot {
        &self.terminal
    }
    #[must_use]
    pub fn dispatch_digest(&self) -> &str {
        &self.dispatch_digest
    }
    #[must_use]
    pub const fn retirement_observation(&self) -> &linura_transaction::ContentDigest {
        &self.retirement_observation
    }
    #[must_use]
    pub const fn preparation_digest(&self) -> &linura_transaction::ContentDigest {
        &self.preparation_digest
    }
    #[must_use]
    pub const fn verification_digest(&self) -> &linura_transaction::ContentDigest {
        &self.verification_digest
    }
    #[must_use]
    pub const fn frames(&self) -> &DisplayNativeHandoffFacts {
        &self.frames
    }
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

pub trait OriginalDisplayCompletionPort: Debug + Send {
    fn dispatch_completion(
        &mut self,
        completion: AuthorizedOriginalDisplayCompletion,
    ) -> Result<(), String>;
}

/// Attempt correlation only. It is not independent post-retirement evidence,
/// ReleasedCurrent, a signing capability or permission to repeat dispatch.
#[derive(Debug)]
pub struct OriginalDisplayCompletionReceipt {
    request: RequestId,
    transaction: TransactionId,
    preparation: linura_transaction::ContentDigest,
}
impl OriginalDisplayCompletionReceipt {
    #[must_use]
    pub const fn request(&self) -> &RequestId {
        &self.request
    }
    #[must_use]
    pub const fn transaction(&self) -> &TransactionId {
        &self.transaction
    }
    #[must_use]
    pub const fn preparation(&self) -> &linura_transaction::ContentDigest {
        &self.preparation
    }
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    pub(super) fn revalidate_completion_review(
        &mut self,
        principal: &AuthenticatedPrincipal,
        terminal: &TerminalInspectionContext,
        review: &RetainedDisplayReview,
    ) -> Result<(), ManagedLifecycleError> {
        let now = now_ms()?;
        if review.review.purpose()
            != crate::durable_authority::DisplayReviewPurpose::OriginalFinalization
            || now < review.created_unix_ms
            || now >= review.deadline_unix_ms
        {
            return Err(invalid());
        }
        let floor = self.registered_managed_risk_floor(&terminal.request)?;
        self.validate_registered_managed_plan(review.review.plan(), review.review.risk())?;
        self.authority.revalidate_display_review(
            principal,
            &terminal.request,
            &review.review,
            floor,
            &terminal.snapshot,
        )?;
        Ok(())
    }

    /// This is a continuation of the ORIGINAL reviewed managed operation.
    /// History, a read-only verified proof and restart cannot recreate the
    /// process-local phase consumed here. Every uncertainty excludes redelivery.
    pub fn dispatch_original_display_completion<P: OriginalDisplayCompletionPort>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        terminal_request: &RequestId,
        port: &mut P,
    ) -> Result<OriginalDisplayCompletionReceipt, ManagedLifecycleError> {
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "display completion requires authenticated interactive ownership".into(),
            ));
        }
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let transaction = TransactionId::for_namespace(&principal_id, terminal_request);
        // Removing before any persistence/provider/Root call is irreversible.
        // The same cache slot is restored only into a later, non-replay stage.
        let retained = self.display_reviews.get(&transaction).ok_or_else(|| {
            ManagedLifecycleError::ApprovalBoundary(
                "original completion review unavailable; retained proof cannot recreate it".into(),
            )
        })?;
        let (spent, verified, deadline) = match &retained.stage {
            DisplayReviewStage::HandoffVerified {
                spend,
                verification,
                expires_at_unix_ms,
            } => (spend.clone(), verification.clone(), *expires_at_unix_ms),
            _ => return Err(invalid()),
        };
        if now_ms()? >= deadline {
            return Err(invalid());
        }
        let mut review = self
            .display_reviews
            .remove(&transaction)
            .ok_or_else(invalid)?;
        NativeCompletionPrepared::require_absent(
            self.display_journal()?,
            &principal_id,
            terminal_request,
        )?;
        // This inspection authenticates the exact terminal and spend before
        // probing, and reloads them after independent proof retention. Reuse
        // its private qualified anchors: an identical scan before it has no
        // intervening effect to protect and consumes the original two-second
        // first-frame budget on slower machines. No clock or gate is renewed.
        let proof =
            self.verify_native_handoff_with_spend(principal.clone(), terminal_request, None)?;
        let terminal = &proof.inspection.context;
        let anchors = &proof.inspection.anchors;
        if terminal.snapshot.transaction_id != transaction
            || spent != anchors.spent.digest()
            || proof.record_digest != verified
        {
            return Err(invalid());
        }
        self.revalidate_completion_review(&principal, terminal, &review)?;
        let dispatch = terminal
            .receipt
            .dispatch_digest
            .as_deref()
            .ok_or_else(invalid)?;
        let preparation = NativeCompletionPrepared::capture(
            &principal_id,
            &terminal.request,
            &terminal.snapshot,
            dispatch,
            terminal.intent.material(),
            &anchors.spent,
            &proof.proof,
            &proof.inspection.observation,
            &proof.inspection.frames,
            now_ms()?,
        )?;
        self.revalidate_completion_review(&principal, terminal, &review)?;
        preparation.retain_once(self.request_journal.as_deref_mut().ok_or_else(invalid)?)?;
        if self.terminal_inspection_context(&principal, terminal_request)? != *terminal
            || self.native_handoff_anchors(&principal_id, terminal)? != *anchors
        {
            return Err(invalid());
        }
        self.revalidate_completion_review(&principal, terminal, &review)?;
        // Policy and durable readbacks consume the original budget too. Check
        // AFTER them, immediately before the sole adapter call, including a
        // backward wall-clock transition since preparation.
        preparation.require_current(now_ms()?)?;
        let intent = preparation.digest();
        // Move the ORIGINAL live review forward before dispatch. An absent
        // acknowledgement cannot reconstruct authority or repeat completion;
        // the later phase may proceed only after fresh independent proof.
        review.stage = DisplayReviewStage::CompletionDispatched {
            preparation: intent.clone(),
            verification: verified.clone(),
        };
        self.check_display_review_capacity(review.retained_bytes)?;
        self.display_reviews
            .insert(terminal.snapshot.transaction_id.clone(), review);
        port.dispatch_completion(AuthorizedOriginalDisplayCompletion {
            material: terminal.intent.material().into(),
            terminal: terminal.snapshot.clone(),
            dispatch_digest: dispatch.into(),
            retirement_observation: anchors.retirement.observation().clone(),
            preparation_digest: intent.clone(),
            verification_digest: verified,
            frames: proof.inspection.frames,
            expires_at_unix_ms: preparation.expiry(),
        })
        .map_err(|_| {
            ManagedLifecycleError::Indeterminate(
                "original completion outcome uncertain; no replay".into(),
            )
        })?;
        preparation.require_readback(self.display_journal()?)?;
        if self.terminal_inspection_context(&principal, terminal_request)? != *terminal
            || self.native_handoff_anchors(&principal_id, terminal)? != *anchors
        {
            return Err(invalid());
        }
        let review = self
            .display_reviews
            .remove(&terminal.snapshot.transaction_id)
            .ok_or_else(invalid)?;
        let current = self.revalidate_completion_review(&principal, terminal, &review);
        self.display_reviews
            .insert(terminal.snapshot.transaction_id.clone(), review);
        current?;
        Ok(OriginalDisplayCompletionReceipt {
            request: terminal_request.clone(),
            transaction: terminal.snapshot.transaction_id.clone(),
            preparation: intent,
        })
    }
}
