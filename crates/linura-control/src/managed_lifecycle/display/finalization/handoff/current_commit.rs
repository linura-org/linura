//! One-use original committed-current continuation. The retained original
//! policy review remains mandatory; durable history alone cannot dispatch it.
use super::*;
use completed::{Entry, Kind, content, header, unsigned};
use linura_observation::{DisplayNativeCurrentFacts, DisplayOriginalRootRetirementFacts};
use linura_transaction::{ContentDigest, TransactionStoreError};

#[derive(Debug)]
pub struct AuthorizedOriginalDisplayCurrentCommit {
    root: DisplayOriginalRootRetirementFacts,
    frames: DisplayNativeCurrentFacts,
    preparation: ContentDigest,
    committed: OriginalDisplayCurrentCommit,
    expiry: u64,
}
impl AuthorizedOriginalDisplayCurrentCommit {
    pub const fn root(&self) -> &DisplayOriginalRootRetirementFacts {
        &self.root
    }
    pub const fn frames(&self) -> &DisplayNativeCurrentFacts {
        &self.frames
    }
    pub const fn preparation(&self) -> &ContentDigest {
        &self.preparation
    }
    pub const fn committed(&self) -> &OriginalDisplayCurrentCommit {
        &self.committed
    }
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expiry
    }
}
pub trait OriginalDisplayCurrentCommitPort: Debug + Send {
    fn commit_current(
        &mut self,
        prepared: AuthorizedOriginalDisplayCurrentCommit,
    ) -> Result<(), String>;
}
#[derive(Debug)]
pub struct OriginalDisplayQualifiedCurrent {
    inspection: OriginalDisplayRootPowerInspection,
    record: ContentDigest,
    first_verified: u64,
}
impl OriginalDisplayQualifiedCurrent {
    pub const fn inspection(&self) -> &OriginalDisplayRootPowerInspection {
        &self.inspection
    }
    pub const fn record_digest(&self) -> &ContentDigest {
        &self.record
    }
    pub const fn first_verified_at_unix_ms(&self) -> u64 {
        self.first_verified
    }
}
impl<S: TransactionStore> ManagedLifecycleControl<S> {
    pub(super) fn revalidate_current_commit_review(
        &mut self,
        principal: &AuthenticatedPrincipal,
        context: &TerminalInspectionContext,
        review: &RetainedDisplayReview,
        committed: &OriginalDisplayCurrentCommit,
    ) -> Result<(), ManagedLifecycleError> {
        let now = now_ms()?;
        if review.review.purpose()
            != crate::durable_authority::DisplayReviewPurpose::OriginalFinalization
            || now < review.created_unix_ms
            || now >= review.deadline_unix_ms
            || committed.terminal().state != TransactionState::Committed
        {
            return Err(invalid());
        }
        let floor = self.registered_managed_risk_floor(&context.request)?;
        self.validate_registered_managed_plan(review.review.plan(), review.review.risk())?;
        self.authority.revalidate_committed_display_review(
            principal,
            &context.request,
            &review.review,
            floor,
            committed.terminal(),
            &context.snapshot,
        )?;
        Ok(())
    }
    pub fn dispatch_original_display_current_commit<P: OriginalDisplayCurrentCommitPort>(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: &RequestId,
        port: &mut P,
    ) -> Result<(), ManagedLifecycleError> {
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(invalid());
        }
        let context = self.current_finalization_comparison_context(&principal, request)?;
        if self
            .authority
            .matching_request_snapshot(&principal, &context.request)?
            .state
            != TransactionState::Committed
        {
            return Err(invalid());
        }
        let proof =
            self.inspect_original_display_root_power_retirement(principal.clone(), request)?;
        let review = self
            .display_reviews
            .get(&context.snapshot.transaction_id)
            .ok_or_else(invalid)?;
        if !matches!(&review.stage, DisplayReviewStage::RootPowerDispatched { preparation } if preparation == proof.preparation())
            || proof.root().current_grant().is_some()
            || proof.current().frames().current_commit_digest().is_some()
        {
            return Err(invalid());
        }
        let mut review = self
            .display_reviews
            .remove(&context.snapshot.transaction_id)
            .ok_or_else(invalid)?;
        let committed = self.commit_original_display_current(principal.clone(), actor, request)?;
        self.revalidate_current_commit_review(&principal, &context, &review, &committed)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let kind = Kind::NativePrepared;
        self.display_journal()?
            .integrity_check()
            .map_err(|_| invalid())?;
        if !matches!(
            self.display_journal()?
                .load(&principal_id, &kind.key(request)?),
            Err(TransactionStoreError::NotFound)
        ) {
            return Err(invalid());
        }
        let current = proof.current();
        let now = now_ms()?;
        let window = current.frames().window();
        let expiry = review
            .deadline_unix_ms
            .min(
                current
                    .observation()
                    .observed_at_unix_ms
                    .checked_add(current.observation().valid_for_ms)
                    .ok_or_else(invalid)?,
            )
            .min(
                window
                    .observed_unix_ms
                    .checked_add(window.valid_for_ms().map_err(|_| invalid())?)
                    .ok_or_else(invalid)?,
            );
        if now < window.observed_unix_ms || now >= expiry {
            return Err(invalid());
        }
        let mut fields = header(kind, &principal_id, &context.request)?;
        fields.extend([
            committed.record_digest().as_str().into(),
            proof.root().lineage().record.clone(),
            crate::durable_authority::digest_observation(current.observation())?
                .as_str()
                .into(),
            expiry.to_string(),
            now.to_string(),
        ]);
        let prepared = Entry::retain(
            self.request_journal.as_deref_mut().ok_or_else(invalid)?,
            kind,
            &principal_id,
            &context.request,
            fields,
        )?;
        self.require_current_inspection_history(&principal, current)?;
        self.revalidate_current_commit_review(&principal, &context, &review, &committed)?;
        if now_ms()? >= expiry {
            return Err(invalid());
        }
        let permit = AuthorizedOriginalDisplayCurrentCommit {
            root: proof.root().clone(),
            frames: current.frames().clone(),
            preparation: prepared.digest(kind),
            committed,
            expiry,
        };
        review.stage = DisplayReviewStage::CurrentCommitDispatched;
        self.check_display_review_capacity(review.retained_bytes)?;
        self.display_reviews
            .insert(context.snapshot.transaction_id, review);
        port.commit_current(permit).map_err(|_| {
            ManagedLifecycleError::Indeterminate(
                "native current qualification outcome uncertain; no replay".into(),
            )
        })?;
        let retained = Entry::load(
            self.display_journal()?,
            kind,
            &principal_id,
            &context.request,
        )?;
        if retained.bytes != prepared.bytes {
            return Err(invalid());
        }
        Ok(()) // ACK only; independent inspection below establishes qualification.
    }
    /// Recovery after a missing ACK is read-only. Matching Root permission and
    /// actual native qualified lifetime are necessary, along with all current
    /// physical sources. No journal entry can recreate the original review.
    pub fn verify_original_display_qualified_current(
        &mut self,
        principal: AuthenticatedPrincipal,
        request: &RequestId,
    ) -> Result<OriginalDisplayQualifiedCurrent, ManagedLifecycleError> {
        let proof =
            self.inspect_original_display_root_power_retirement(principal.clone(), request)?;
        let current = proof.current();
        let context = self.current_finalization_comparison_context(&principal, request)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        if current.terminal().state != TransactionState::Committed {
            return Err(invalid());
        }
        let committed = Entry::load(
            self.display_journal()?,
            Kind::Committed,
            &principal_id,
            &context.request,
        )?;
        let prepared = Entry::load(
            self.display_journal()?,
            Kind::NativePrepared,
            &principal_id,
            &context.request,
        )?;
        let ready = Entry::load(
            self.display_journal()?,
            Kind::Ready,
            &principal_id,
            &context.request,
        )?;
        let verified = Entry::load(
            self.display_journal()?,
            Kind::Verified,
            &principal_id,
            &context.request,
        )?;
        if content(&committed.fields[5])? != ready.digest(Kind::Ready)
            || content(&committed.fields[6])? != verified.digest(Kind::Verified)
            || unsigned(&committed.fields[7])? != current.terminal().state_version
            || committed.fields[8] != proof.root().lineage().record
            || unsigned(&committed.fields[10])? > now_ms()?
        {
            return Err(invalid());
        }
        let grant = proof.root().current_grant().ok_or_else(invalid)?;
        let first = unsigned(&prepared.fields[9])?;
        if content(&prepared.fields[5])? != committed.digest(Kind::Committed)
            || prepared.fields[6] != proof.root().lineage().record
            || grant.preparation != prepared.digest(Kind::NativePrepared).hex()
            || grant.committed_record != committed.digest(Kind::Committed).hex()
            || current.frames().current_commit_digest() != Some(grant.record.as_str())
            || current.observation().observed_at_unix_ms < first
            || current.frames().window().observed_unix_ms < first
        {
            return Err(invalid());
        }
        let kind = Kind::NativeVerified;
        let mut fields = header(kind, &principal_id, &context.request)?;
        fields.extend([
            prepared.digest(Kind::NativePrepared).as_str().into(),
            committed.digest(Kind::Committed).as_str().into(),
            grant.record.clone(),
            crate::durable_authority::digest_observation(current.observation())?
                .as_str()
                .into(),
            now_ms()?.to_string(),
        ]);
        let retained = match self
            .display_journal()?
            .load(&principal_id, &kind.key(request)?)
        {
            Err(TransactionStoreError::NotFound) => Entry::retain(
                self.request_journal.as_deref_mut().ok_or_else(invalid)?,
                kind,
                &principal_id,
                &context.request,
                fields,
            )?,
            Ok(_) => {
                let old = Entry::load(
                    self.display_journal()?,
                    kind,
                    &principal_id,
                    &context.request,
                )?;
                if old.fields[..8] != fields[..8] || unsigned(&old.fields[9])? > now_ms()? {
                    return Err(invalid());
                }
                old
            }
            Err(_) => return Err(invalid()),
        };
        self.require_current_inspection_history(&principal, current)?;
        Ok(OriginalDisplayQualifiedCurrent {
            record: retained.digest(kind),
            first_verified: unsigned(&retained.fields[9])?,
            inspection: proof,
        })
    }
}
