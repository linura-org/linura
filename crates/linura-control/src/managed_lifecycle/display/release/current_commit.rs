//! Signed bookkeeping, one-use native commit and independent qualification are
//! distinct milestones. No signed state or ACK releases the remaining fences.
use super::current_records::{Entry, Kind, digest, number};
use super::*;
use linura_observation::{DisplayOrdinaryCurrentFacts, DisplayOrdinaryRootRetirementFacts};
use linura_transaction::{ContentDigest, TransactionSnapshot, TransactionStoreError};
fn at(stage: &str) -> ManagedLifecycleError {
    ManagedLifecycleError::Verification(format!(
        "ordinary current completion unavailable at {stage}; no release authority"
    ))
}

#[derive(Debug)]
pub struct OrdinaryDisplayCurrentCommit {
    release: TransactionSnapshot,
    record: ContentDigest,
    at: u64,
}
impl OrdinaryDisplayCurrentCommit {
    pub const fn release(&self) -> &TransactionSnapshot {
        &self.release
    }
    pub const fn record_digest(&self) -> &ContentDigest {
        &self.record
    }
    pub const fn committed_at_unix_ms(&self) -> u64 {
        self.at
    }
}
#[derive(Debug)]
pub struct AuthorizedOrdinaryDisplayCurrentCommit {
    root: DisplayOrdinaryRootRetirementFacts,
    frames: DisplayOrdinaryCurrentFacts,
    preparation: ContentDigest,
    committed: OrdinaryDisplayCurrentCommit,
    expiry: u64,
}
impl AuthorizedOrdinaryDisplayCurrentCommit {
    pub const fn root(&self) -> &DisplayOrdinaryRootRetirementFacts {
        &self.root
    }
    pub const fn frames(&self) -> &DisplayOrdinaryCurrentFacts {
        &self.frames
    }
    pub const fn preparation(&self) -> &ContentDigest {
        &self.preparation
    }
    pub const fn committed(&self) -> &OrdinaryDisplayCurrentCommit {
        &self.committed
    }
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expiry
    }
}
pub trait OrdinaryDisplayCurrentCommitPort: Debug + Send {
    fn commit_ordinary_current(
        &mut self,
        permit: AuthorizedOrdinaryDisplayCurrentCommit,
    ) -> Result<(), String>;
}
#[derive(Debug)]
pub struct OrdinaryDisplayQualifiedCurrent {
    inspection: OrdinaryDisplayRootPowerInspection,
    record: ContentDigest,
    at: u64,
}
impl OrdinaryDisplayQualifiedCurrent {
    pub const fn inspection(&self) -> &OrdinaryDisplayRootPowerInspection {
        &self.inspection
    }
    pub const fn record_digest(&self) -> &ContentDigest {
        &self.record
    }
    pub const fn first_verified_at_unix_ms(&self) -> u64 {
        self.at
    }
}
impl<S: TransactionStore> ManagedLifecycleControl<S> {
    pub(super) fn require_ordinary_current_review(
        &mut self,
        principal: &AuthenticatedPrincipal,
        proof: &OrdinaryDisplayRootPowerInspection,
        review: &RetainedDisplayReview,
    ) -> Result<(), ManagedLifecycleError> {
        let c = proof.power().current();
        let now = now_ms()?;
        if review.review.purpose()
            != crate::durable_authority::DisplayReviewPurpose::OrdinaryRelease
            || now < review.created_unix_ms
            || now >= review.deadline_unix_ms
        {
            return Err(invalid_original());
        }
        if c.release().state == TransactionState::Indeterminate {
            return self.require_ordinary_power_review(principal, c, review);
        }
        if c.release().state != TransactionState::Committed {
            return Err(invalid_original());
        }
        let floor = self.registered_managed_risk_floor(c.request())?;
        self.validate_registered_managed_plan(review.review.plan(), review.review.risk())?;
        self.authority
            .revalidate_committed_ordinary_display_review(
                principal,
                c.request(),
                &review.review,
                floor,
                c.release(),
                c.comparison_release(),
            )?;
        Ok(())
    }
    pub(super) fn ordinary_committed_record(
        &self,
        principal: &AuthenticatedPrincipal,
        proof: &OrdinaryDisplayRootPowerInspection,
    ) -> Result<(Entry, Entry, Entry), ManagedLifecycleError> {
        let c = proof.power().current();
        let pid = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let _checked = self.checked_display_history()?;
        let ready = Entry::load(self.display_journal()?, Kind::Ready, &pid, c.request())?;
        let verified = Entry::load(self.display_journal()?, Kind::Verified, &pid, c.request())?;
        let committed = Entry::load(self.display_journal()?, Kind::Committed, &pid, c.request())?;
        if c.release().state != TransactionState::Committed
            || digest(&verified.fields[5])? != ready.digest()
            || digest(&committed.fields[5])? != ready.digest()
            || digest(&committed.fields[6])? != verified.digest()
            || number(&committed.fields[7])? != c.release().state_version
            || committed.fields[8] != proof.root().lineage().record
            || number(&ready.fields[5])? != c.comparison_release().current_generation
            || number(&ready.fields[6])? != c.comparison_release().state_version
            || digest(&ready.fields[7])? != c.comparison_release().binding_digest
            || number(&verified.fields[6])?.checked_add(1) != Some(c.release().state_version)
            || ready.fields[8] != c.root().first().lineage().release_dispatch
            || ready.fields[9] != proof.preparation().as_str()
            || ready.fields[10] != proof.root().lineage().record
            || number(&ready.fields[11])? == 0
            || number(&ready.fields[11])? > now_ms()?
            || number(&committed.fields[10])? < number(&ready.fields[11])?
            || number(&committed.fields[10])? == 0
            || number(&committed.fields[10])? > now_ms()?
        {
            return Err(invalid_original());
        }
        for raw in &verified.fields[7..10] {
            digest(raw)?;
        }
        digest(&committed.fields[9])?;
        if self
            .authority
            .matching_request_snapshot(principal, c.request())?
            != *c.release()
        {
            return Err(invalid_original());
        }
        Ok((ready, verified, committed))
    }
    /// Reconcile already verified physical current state into signed metadata.
    /// This has no native port, grant, successor or cleanup authority.
    pub fn commit_ordinary_display_current<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: &RequestId,
        attempt: &mut P,
        verifier: &mut V,
    ) -> Result<OrdinaryDisplayCurrentCommit, ManagedLifecycleError> {
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(invalid_original());
        }
        let proof = self.inspect_ordinary_display_root_power_retirement(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        let c = proof.power().current();
        let pid = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let actual = c.release().clone();
        let before = c.comparison_release().clone();
        let desired = c.request().clone();
        if actual.state == TransactionState::Committed {
            if matches!(
                self.display_journal()?
                    .load(&pid, &Kind::Committed.key(request)?),
                Err(TransactionStoreError::NotFound)
            ) {
                // The signed CAS may succeed before its correlation publication.
                // Reconcile that metadata only while no native preparation/grant
                // exists. Missing history after native dispatch is never rebuilt.
                if proof.root().current_grant().is_some()
                    || c.frames().current_commit_digest().is_some()
                    || !matches!(
                        self.display_journal()?
                            .load(&pid, &Kind::NativePrepared.key(request)?),
                        Err(TransactionStoreError::NotFound)
                    )
                {
                    return Err(invalid_original());
                }
                let ready = Entry::load(self.display_journal()?, Kind::Ready, &pid, &desired)?;
                let verified =
                    Entry::load(self.display_journal()?, Kind::Verified, &pid, &desired)?;
                if digest(&verified.fields[5])? != ready.digest()
                    || number(&verified.fields[6])?.checked_add(1) != Some(actual.state_version)
                    || ready.fields[9] != proof.preparation().as_str()
                    || ready.fields[10] != proof.root().lineage().record
                {
                    return Err(invalid_original());
                }
                for raw in &verified.fields[7..10] {
                    digest(raw)?;
                }
                c.observation()
                    .require_current(now_ms()?)
                    .map_err(|_| invalid_original())?;
                Entry::retain(
                    self.request_journal
                        .as_deref_mut()
                        .ok_or_else(invalid_original)?,
                    Kind::Committed,
                    &pid,
                    &desired,
                    vec![
                        ready.digest().as_str().into(),
                        verified.digest().as_str().into(),
                        actual.state_version.to_string(),
                        proof.root().lineage().record.clone(),
                        crate::durable_authority::digest_observation(c.observation())?
                            .as_str()
                            .into(),
                        now_ms()?.to_string(),
                    ],
                )?;
            }
            let (_, _, committed) = self.ordinary_committed_record(&principal, &proof)?;
            return Ok(OrdinaryDisplayCurrentCommit {
                release: actual,
                record: committed.digest(),
                at: number(&committed.fields[10])?,
            });
        }
        self.previews
            .build_verified_ordinary_display_current_plan(
                &principal,
                actor.clone(),
                &desired,
                &proof,
            )
            .map_err(|_| at("canonical NoChange before CAS"))?;
        let receipt = self.ordinary_release_receipt_at(&principal, &desired, &before)?;
        let fields = vec![
            before.current_generation.to_string(),
            before.state_version.to_string(),
            before.binding_digest.as_str().into(),
            receipt.dispatch_digest.ok_or_else(invalid_original)?,
            proof.preparation().as_str().into(),
            proof.root().lineage().record.clone(),
            now_ms()?.to_string(),
        ];
        let ready = match self
            .display_journal()?
            .load(&pid, &Kind::Ready.key(request)?)
        {
            Err(TransactionStoreError::NotFound) => {
                if actual.state != TransactionState::Indeterminate {
                    return Err(invalid_original());
                }
                Entry::retain(
                    self.request_journal
                        .as_deref_mut()
                        .ok_or_else(invalid_original)?,
                    Kind::Ready,
                    &pid,
                    &desired,
                    fields.clone(),
                )?
            }
            Ok(_) => {
                let old = Entry::load(self.display_journal()?, Kind::Ready, &pid, &desired)?;
                if old.fields[5..11] != fields[..6]
                    || number(&old.fields[11])? == 0
                    || number(&old.fields[11])? > now_ms()?
                {
                    return Err(invalid_original());
                }
                old
            }
            Err(_) => return Err(invalid_original()),
        };
        if self
            .authority
            .matching_request_snapshot(&principal, &desired)?
            != actual
        {
            return Err(invalid_original());
        }
        let verified = match actual.state {
            TransactionState::Indeterminate => self
                .authority
                .verify_ordinary_display_current_without_replay(
                    &self.previews,
                    &principal,
                    actor.clone(),
                    &desired,
                    &proof,
                )?,
            TransactionState::Verified => self
                .authority
                .resume_verified(&principal, &actual.transaction_id)?,
            _ => return Err(invalid_original()),
        };
        let material = self
            .authority
            .display_verified_material(&principal, &desired)?;
        let tail = vec![
            ready.digest().as_str().into(),
            material.snapshot.state_version.to_string(),
            material.desired_state_digest.as_str().into(),
            material.graph_digest.as_str().into(),
            material.provenance_digest.as_str().into(),
        ];
        let verified_entry = match self
            .display_journal()?
            .load(&pid, &Kind::Verified.key(request)?)
        {
            Err(TransactionStoreError::NotFound) => Entry::retain(
                self.request_journal
                    .as_deref_mut()
                    .ok_or_else(invalid_original)?,
                Kind::Verified,
                &pid,
                &desired,
                tail.clone(),
            )?,
            Ok(_) => {
                let e = Entry::load(self.display_journal()?, Kind::Verified, &pid, &desired)?;
                if e.fields[5..] != tail {
                    return Err(invalid_original());
                }
                e
            }
            Err(_) => return Err(invalid_original()),
        };
        // Re-observe after both durable verification publications, without
        // replaying the original managed effect or extending any source window.
        let fresh = self.inspect_ordinary_display_root_power_retirement(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        if fresh.root() != proof.root()
            || fresh.power().current().comparison_release() != &before
            || fresh.power().current().release() != &material.snapshot
            || !fresh.power().current().frames().reconciles(c.frames())
        {
            return Err(invalid_original());
        }
        self.previews
            .build_verified_ordinary_display_current_plan(&principal, actor, &desired, &fresh)
            .map_err(|_| invalid_original())?;
        {
            let _checked = self.checked_display_history()?;
            ready.readback(self.display_journal()?, &pid, &desired)?;
            verified_entry.readback(self.display_journal()?, &pid, &desired)?;
        }
        fresh
            .power()
            .current()
            .observation()
            .require_current(now_ms()?)
            .map_err(|_| invalid_original())?;
        let committed = self.authority.commit_verified(&principal, verified)?;
        if committed.state != TransactionState::Committed
            || committed.state_version
                != before
                    .state_version
                    .checked_add(2)
                    .ok_or_else(invalid_original)?
        {
            return Err(invalid_original());
        }
        let tail = vec![
            ready.digest().as_str().into(),
            verified_entry.digest().as_str().into(),
            committed.state_version.to_string(),
            proof.root().lineage().record.clone(),
            crate::durable_authority::digest_observation(fresh.power().current().observation())?
                .as_str()
                .into(),
            now_ms()?.to_string(),
        ];
        let record = Entry::retain(
            self.request_journal
                .as_deref_mut()
                .ok_or_else(invalid_original)?,
            Kind::Committed,
            &pid,
            &desired,
            tail,
        )?;
        if self
            .authority
            .matching_request_snapshot(&principal, &desired)?
            != committed
        {
            return Err(invalid_original());
        }
        Ok(OrdinaryDisplayCurrentCommit {
            release: committed,
            record: record.digest(),
            at: number(&record.fields[10])?,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_ordinary_display_current_commit<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
        N: OrdinaryDisplayCurrentCommitPort,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: &RequestId,
        attempt: &mut P,
        verifier: &mut V,
        port: &mut N,
    ) -> Result<(), ManagedLifecycleError> {
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(invalid_original());
        }
        let pid = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let transaction = TransactionId::for_namespace(&pid, request);
        let review = self
            .display_reviews
            .get(&transaction)
            .ok_or_else(invalid_original)?;
        let root_preparation = match &review.stage {
            DisplayReviewStage::OrdinaryRootPowerDispatched { preparation } => preparation.clone(),
            _ => return Err(invalid_original()),
        };
        // Consume before probes, bookkeeping CAS or any durable publication.
        let mut review = self
            .display_reviews
            .remove(&transaction)
            .ok_or_else(invalid_original)?;
        {
            let _checked = self.checked_display_history()?;
            match self
                .display_journal()?
                .load(&pid, &Kind::NativePrepared.key(request)?)
            {
                Err(TransactionStoreError::NotFound) => (),
                _ => return Err(invalid_original()),
            }
        }
        let before = self.inspect_ordinary_display_root_power_retirement(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        if before.preparation() != &root_preparation
            || before.root().current_grant().is_some()
            || before
                .power()
                .current()
                .frames()
                .current_commit_digest()
                .is_some()
        {
            return Err(invalid_original());
        }
        self.require_ordinary_current_review(&principal, &before, &review)?;
        let committed = self.commit_ordinary_display_current(
            principal.clone(),
            actor,
            request,
            attempt,
            verifier,
        )?;
        let proof = self.inspect_ordinary_display_root_power_retirement(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        self.require_ordinary_current_review(&principal, &proof, &review)?;
        if proof.root() != before.root()
            || proof.power().current().release() != committed.release()
            || !proof
                .power()
                .current()
                .frames()
                .reconciles(before.power().current().frames())
        {
            return Err(invalid_original());
        }
        let c = proof.power().current();
        let now = now_ms()?;
        let w = c.frames().window();
        let expiry = review
            .deadline_unix_ms
            .min(
                c.observation()
                    .observed_at_unix_ms
                    .checked_add(c.observation().valid_for_ms)
                    .ok_or_else(invalid_original)?,
            )
            .min(
                w.observed_unix_ms
                    .checked_add(w.valid_for_ms().map_err(|_| invalid_original())?)
                    .ok_or_else(invalid_original)?,
            );
        if now < w.observed_unix_ms || now >= expiry {
            return Err(invalid_original());
        }
        let prepared = Entry::retain(
            self.request_journal
                .as_deref_mut()
                .ok_or_else(invalid_original)?,
            Kind::NativePrepared,
            &pid,
            c.request(),
            vec![
                committed.record_digest().as_str().into(),
                proof.root().lineage().record.clone(),
                crate::durable_authority::digest_observation(c.observation())?
                    .as_str()
                    .into(),
                now.to_string(),
                expiry.to_string(),
            ],
        )?;
        let fresh = self.inspect_ordinary_display_root_power_retirement(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        if fresh.root() != proof.root()
            || fresh.power().current().release() != committed.release()
            || !fresh.power().current().frames().reconciles(c.frames())
        {
            return Err(invalid_original());
        }
        self.require_ordinary_current_review(&principal, &fresh, &review)?;
        {
            let _checked = self.checked_display_history()?;
            prepared.readback(self.display_journal()?, &pid, c.request())?;
        }
        if now_ms()? < now || now_ms()? >= expiry {
            return Err(at("native preparation expiry after independent recheck"));
        }
        let permit = AuthorizedOrdinaryDisplayCurrentCommit {
            root: fresh.root().clone(),
            frames: fresh.power().current().frames().clone(),
            preparation: prepared.digest(),
            committed,
            expiry,
        };
        review.stage = DisplayReviewStage::OrdinaryCurrentCommitDispatched {
            preparation: prepared.digest(),
        };
        self.check_display_review_capacity(review.retained_bytes)?;
        self.display_reviews.insert(transaction, review);
        port.commit_ordinary_current(permit).map_err(|_| {
            ManagedLifecycleError::Indeterminate(
                "ordinary native current-commit outcome uncertain; no replay".into(),
            )
        })?;
        let _checked = self.checked_display_history()?;
        prepared.readback(self.display_journal()?, &pid, c.request())?;
        if self
            .authority
            .matching_request_snapshot(&principal, c.request())?
            != *fresh.power().current().release()
        {
            return Err(invalid_original());
        }
        Ok(())
    }
    pub fn verify_ordinary_display_qualified_current<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        request: &RequestId,
        attempt: &mut P,
        verifier: &mut V,
    ) -> Result<OrdinaryDisplayQualifiedCurrent, ManagedLifecycleError> {
        let proof = self.inspect_ordinary_display_root_power_retirement(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        let c = proof.power().current();
        let pid = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let (ready, verified, committed) = self.ordinary_committed_record(&principal, &proof)?;
        let prepared = Entry::load(
            self.display_journal()?,
            Kind::NativePrepared,
            &pid,
            c.request(),
        )?;
        let grant = proof.root().current_grant().ok_or_else(invalid_original)?;
        let first = number(&prepared.fields[8])?;
        let expiry = number(&prepared.fields[9])?;
        if digest(&prepared.fields[5])? != committed.digest()
            || prepared.fields[6] != proof.root().lineage().record
            || first < number(&committed.fields[10])?
            || first == 0
            || first > now_ms()?
            || first >= expiry
            || expiry - first > 2000
            || grant.preparation != prepared.digest().hex()
            || grant.committed_record != committed.digest().hex()
            || !c.frames().retains_current_qualification(
                proof.root().current_frames().ok_or_else(invalid_original)?,
            )
            || c.frames().current_commit_digest() != Some(grant.record.as_str())
            || c.observation().observed_at_unix_ms < first
            || c.frames().window().observed_unix_ms < first
        {
            return Err(invalid_original());
        }
        digest(&prepared.fields[7])?;
        let record = match self
            .display_journal()?
            .load(&pid, &Kind::NativeVerified.key(request)?)
        {
            Err(TransactionStoreError::NotFound) => Entry::retain(
                self.request_journal
                    .as_deref_mut()
                    .ok_or_else(invalid_original)?,
                Kind::NativeVerified,
                &pid,
                c.request(),
                vec![
                    prepared.digest().as_str().into(),
                    grant.record.clone(),
                    now_ms()?.to_string(),
                ],
            )?,
            Ok(_) => {
                let e = Entry::load(
                    self.display_journal()?,
                    Kind::NativeVerified,
                    &pid,
                    c.request(),
                )?;
                if digest(&e.fields[5])? != prepared.digest()
                    || e.fields[6] != grant.record
                    || number(&e.fields[7])? < first
                    || number(&e.fields[7])? > now_ms()?
                {
                    return Err(invalid_original());
                }
                e
            }
            Err(_) => return Err(invalid_original()),
        };
        let fresh = self.inspect_ordinary_display_root_power_retirement(
            principal, request, attempt, verifier,
        )?;
        if fresh.root() != proof.root()
            || fresh.power().current().release() != c.release()
            || !fresh.power().current().frames().reconciles(c.frames())
        {
            return Err(invalid_original());
        }
        {
            let _checked = self.checked_display_history()?;
            for e in [&ready, &verified, &committed, &prepared, &record] {
                e.readback(self.display_journal()?, &pid, c.request())?;
            }
        }
        Ok(OrdinaryDisplayQualifiedCurrent {
            inspection: fresh,
            record: record.digest(),
            at: number(&record.fields[7])?,
        })
    }
}
