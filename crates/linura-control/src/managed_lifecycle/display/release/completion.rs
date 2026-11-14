//! One-use continuation of the actual ordinary-release review. Neither the
//! durable preparation nor its ACK commits state or permits fence retirement.
use super::*;
use crate::durable_authority::DisplayReviewPurpose;
use linura_observation::DisplayOrdinaryHandoffFacts;
use linura_transaction::{
    ContentDigest, RetainedRequest, TransactionSnapshot, TransactionStoreError,
};

const DOMAIN: &str = "linura.display.ordinary-completion-prepared.v1";
const KEY_DOMAIN: &str = "linura.display.ordinary-completion-prepared-key.v1";
const MAX_BYTES: usize = 4 * 1024;

/// Non-cloneable continuation, constructed only after current independent
/// first-frame verification, live purpose-13 review and durable before-effect
/// publication. Transport adapters must bind the original Root/native owners.
pub struct AuthorizedOrdinaryDisplayCompletion {
    material: String,
    release: TransactionSnapshot,
    dispatch: String,
    root_preparation: String,
    preparation: ContentDigest,
    verification: ContentDigest,
    frames: DisplayOrdinaryHandoffFacts,
    expires_at_unix_ms: u64,
}
impl Debug for AuthorizedOrdinaryDisplayCompletion {
    fn fmt(&self, out: &mut Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("AuthorizedOrdinaryDisplayCompletion")
            .field("transaction", &self.release.transaction_id)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish_non_exhaustive()
    }
}
impl AuthorizedOrdinaryDisplayCompletion {
    #[must_use]
    pub fn material(&self) -> &str {
        &self.material
    }
    #[must_use]
    pub const fn release(&self) -> &TransactionSnapshot {
        &self.release
    }
    #[must_use]
    pub fn dispatch(&self) -> &str {
        &self.dispatch
    }
    #[must_use]
    pub fn root_preparation(&self) -> &str {
        &self.root_preparation
    }
    #[must_use]
    pub const fn preparation(&self) -> &ContentDigest {
        &self.preparation
    }
    #[must_use]
    pub const fn verification(&self) -> &ContentDigest {
        &self.verification
    }
    #[must_use]
    pub const fn frames(&self) -> &DisplayOrdinaryHandoffFacts {
        &self.frames
    }
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

pub trait OrdinaryDisplayCompletionPort: Debug + Send {
    fn dispatch_ordinary_completion(
        &mut self,
        completion: AuthorizedOrdinaryDisplayCompletion,
    ) -> Result<(), String>;
}

/// Dispatch correlation only. Independent current-state verification and all
/// ordered retirement gates remain necessary, even when this receipt exists.
#[derive(Debug)]
pub struct OrdinaryDisplayCompletionReceipt {
    request: RequestId,
    transaction: TransactionId,
    preparation: ContentDigest,
}
impl OrdinaryDisplayCompletionReceipt {
    #[must_use]
    pub const fn request(&self) -> &RequestId {
        &self.request
    }
    #[must_use]
    pub const fn transaction(&self) -> &TransactionId {
        &self.transaction
    }
    #[must_use]
    pub const fn preparation(&self) -> &ContentDigest {
        &self.preparation
    }
}

fn key(request: &RequestId) -> Result<RequestId, ManagedLifecycleError> {
    RequestId::new(format!(
        "request:v010:display-ordinary-completion-prepared:{}",
        linura_transaction::digest_bytes(KEY_DOMAIN, request.as_str().as_bytes()).hex()
    ))
    .map_err(|_| invalid_original())
}
fn append(out: &mut Vec<u8>, value: &str) -> Result<(), ManagedLifecycleError> {
    if value.is_empty()
        || out
            .len()
            .checked_add(8)
            .and_then(|n| n.checked_add(value.len()))
            .is_none_or(|n| n > MAX_BYTES)
    {
        return Err(invalid_original());
    }
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    fn revalidate_ordinary_completion_review(
        &mut self,
        principal: &AuthenticatedPrincipal,
        proof: &OrdinaryDisplayHandoffVerification,
        review: &RetainedDisplayReview,
    ) -> Result<(), ManagedLifecycleError> {
        let now = now_ms()?;
        if review.review.purpose() != DisplayReviewPurpose::OrdinaryRelease
            || now < review.created_unix_ms
            || now >= review.deadline_unix_ms
            || now >= proof.first_valid_until_unix_ms()
        {
            return Err(invalid_original());
        }
        let inspection = proof.inspection();
        let floor = self.registered_managed_risk_floor(&inspection.request)?;
        self.validate_registered_managed_plan(review.review.plan(), review.review.risk())?;
        self.authority.revalidate_display_review(
            principal,
            &inspection.request,
            &review.review,
            floor,
            inspection.release(),
        )?;
        Ok(())
    }

    /// Consume the same-invocation review BEFORE independent probes, storage or
    /// native dispatch. A lost initial release ACK, failed proof, persistence
    /// uncertainty, restart or second operation cannot reconstruct this review.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_ordinary_display_completion<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
        C: OrdinaryDisplayCompletionPort,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        release_request: &RequestId,
        attempt: &mut P,
        verifier: &mut V,
        port: &mut C,
    ) -> Result<OrdinaryDisplayCompletionReceipt, ManagedLifecycleError> {
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "ordinary completion requires authenticated interactive ownership".into(),
            ));
        }
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let transaction = TransactionId::for_namespace(&principal_id, release_request);
        let live = self.display_reviews.get(&transaction).ok_or_else(|| {
            ManagedLifecycleError::ApprovalBoundary(
                "ordinary completion review unavailable; retained proof cannot recreate it".into(),
            )
        })?;
        if live.review.purpose() != DisplayReviewPurpose::OrdinaryRelease
            || live.stage != DisplayReviewStage::Initial
        {
            return Err(invalid_original());
        }
        let mut review = self
            .display_reviews
            .remove(&transaction)
            .ok_or_else(invalid_original)?;
        let proof = self.verify_ordinary_display_handoff(
            principal.clone(),
            release_request,
            attempt,
            verifier,
        )?;
        self.revalidate_ordinary_completion_review(&principal, &proof, &review)?;
        let inspection = proof.inspection();
        let release = inspection.release().clone();
        if release.transaction_id != transaction {
            return Err(invalid_original());
        }
        let root = inspection.root().comparison();
        let prepared_at = now_ms()?;
        let expiry = proof
            .first_valid_until_unix_ms()
            .min(review.deadline_unix_ms);
        if prepared_at >= expiry {
            return Err(invalid_original());
        }
        let mut canonical = Vec::new();
        for value in [
            DOMAIN.into(),
            principal_id.as_str().into(),
            release_request.as_str().into(),
            transaction.as_str().into(),
            crate::durable_authority::digest_request(&inspection.request)?
                .as_str()
                .into(),
            release.current_generation.to_string(),
            release.state_version.to_string(),
            release.binding_digest.as_str().into(),
            root.dispatch.clone(),
            root.preparation_digest.clone(),
            proof.record_digest().as_str().into(),
            crate::durable_authority::digest_observation(inspection.observation())?
                .as_str()
                .into(),
            prepared_at.to_string(),
            expiry.to_string(),
        ] {
            append(&mut canonical, &value)?;
        }
        let retained = RetainedRequest::new(principal_id.clone(), key(release_request)?, canonical)
            .map_err(|_| invalid_original())?;
        // Absence, exclusive retain and exact readback. Idempotent journal
        // retention can never be interpreted as permission to redeliver.
        {
            let checked = self.checked_display_history()?;
            match self
                .display_journal()?
                .load(&principal_id, retained.request_id())
            {
                Err(TransactionStoreError::NotFound) => (),
                _ => return Err(invalid_original()),
            }
            drop(checked);
        }
        self.request_journal
            .as_mut()
            .ok_or_else(invalid_original)?
            .retain(&retained)
            .map_err(|_| invalid_original())?;
        {
            let _checked = self.checked_display_history()?;
            if self
                .display_journal()?
                .load(&principal_id, retained.request_id())
                .map_err(|_| invalid_original())?
                != retained
                || self
                    .authority
                    .matching_request_snapshot(&principal, &inspection.request)?
                    != release
            {
                return Err(invalid_original());
            }
        }
        // Re-read all independent contributors AFTER durable publication. The
        // immutable proof identity and first deadline cannot be overwritten.
        let fresh = self.inspect_ordinary_display_handoff(
            principal.clone(),
            release_request,
            attempt,
            verifier,
        )?;
        if fresh.release() != &release
            || !fresh.frames().reconciles(inspection.frames())
            || !fresh.root().reconciles(inspection.root())
        {
            return Err(invalid_original());
        }
        {
            let _checked = self.checked_display_history()?;
            proof.require_retained(self.display_journal()?, &principal_id, release_request)?;
            if self
                .display_journal()?
                .load(&principal_id, retained.request_id())
                .map_err(|_| invalid_original())?
                != retained
            {
                return Err(invalid_original());
            }
        }
        self.revalidate_ordinary_completion_review(&principal, &proof, &review)?;
        let preparation = linura_transaction::digest_bytes(DOMAIN, retained.canonical());
        let now = now_ms()?;
        if now < prepared_at || now >= expiry {
            return Err(invalid_original());
        }
        review.stage = DisplayReviewStage::OrdinaryCompletionDispatched {
            preparation: preparation.clone(),
            verification: proof.record_digest().clone(),
        };
        self.check_display_review_capacity(review.retained_bytes)?;
        self.display_reviews.insert(transaction.clone(), review);
        port.dispatch_ordinary_completion(AuthorizedOrdinaryDisplayCompletion {
            material: root.material.clone(),
            release: release.clone(),
            dispatch: root.dispatch.clone(),
            root_preparation: root.preparation_digest.clone(),
            preparation: preparation.clone(),
            verification: proof.record_digest().clone(),
            frames: fresh.frames().clone(),
            expires_at_unix_ms: expiry,
        })
        .map_err(|_| {
            ManagedLifecycleError::Indeterminate(
                "ordinary completion outcome uncertain; no replay".into(),
            )
        })?;
        // An ACK is only correlation. It cannot sign Committed, erase the
        // first proof or advance any input/power/startup retirement phase.
        let checked = self.checked_display_history()?;
        if self
            .display_journal()?
            .load(&principal_id, retained.request_id())
            .map_err(|_| invalid_original())?
            != retained
            || self
                .authority
                .matching_request_snapshot(&principal, &inspection.request)?
                != release
        {
            return Err(invalid_original());
        }
        drop(checked);
        let review = self
            .display_reviews
            .remove(&transaction)
            .ok_or_else(invalid_original)?;
        let current = self.revalidate_ordinary_completion_review(&principal, &proof, &review);
        self.display_reviews.insert(transaction.clone(), review);
        current?;
        Ok(OrdinaryDisplayCompletionReceipt {
            request: release_request.clone(),
            transaction,
            preparation,
        })
    }
}
