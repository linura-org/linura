//! Final ordinary fence retirement. Signed Committed and ACKs are comparison
//! milestones; only the independently joined final state can complete release.
use super::current_records::{Entry, Kind, digest, number};
use super::*;
use linura_observation::{
    DisplayNativeHandoffWindow, DisplayOrdinaryCurrentFacts, DisplayOrdinaryFinalRetirementFacts,
    DisplayOrdinaryRootRetirementFacts,
};
use linura_transaction::{ContentDigest, TransactionStoreError};
#[derive(Debug)]
pub struct AuthorizedOrdinaryDisplayFinalRetirement {
    root: DisplayOrdinaryRootRetirementFacts,
    frames: DisplayOrdinaryCurrentFacts,
    preparation: ContentDigest,
    qualification: ContentDigest,
    expiry: u64,
}
impl AuthorizedOrdinaryDisplayFinalRetirement {
    pub const fn root(&self) -> &DisplayOrdinaryRootRetirementFacts {
        &self.root
    }
    pub const fn frames(&self) -> &DisplayOrdinaryCurrentFacts {
        &self.frames
    }
    pub const fn preparation(&self) -> &ContentDigest {
        &self.preparation
    }
    pub const fn qualification(&self) -> &ContentDigest {
        &self.qualification
    }
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expiry
    }
}
pub trait OrdinaryDisplayFinalRetirementPort: Debug + Send {
    fn retire_ordinary_current(
        &mut self,
        permit: AuthorizedOrdinaryDisplayFinalRetirement,
    ) -> Result<(), String>;
}
#[derive(Debug)]
pub struct OrdinaryDisplayFinalRetirementVerification {
    qualified: OrdinaryDisplayQualifiedCurrent,
    root: DisplayOrdinaryFinalRetirementFacts,
    record: ContentDigest,
    window: DisplayNativeHandoffWindow,
}
impl OrdinaryDisplayFinalRetirementVerification {
    pub const fn qualified(&self) -> &OrdinaryDisplayQualifiedCurrent {
        &self.qualified
    }
    pub const fn root(&self) -> &DisplayOrdinaryFinalRetirementFacts {
        &self.root
    }
    pub const fn record_digest(&self) -> &ContentDigest {
        &self.record
    }
    pub const fn first_window(&self) -> DisplayNativeHandoffWindow {
        self.window
    }
}
/// Metadata only. Reconciliation cannot produce a native grant or new review.
#[derive(Debug)]
pub struct OrdinaryDisplayReleasedCurrentCompletion {
    scope: linura_core::DisplayOrdinaryReleaseScope,
    final_record: ComponentDigest,
    verification: ContentDigest,
    window: DisplayNativeHandoffWindow,
}
impl OrdinaryDisplayReleasedCurrentCompletion {
    pub const fn scope(&self) -> &linura_core::DisplayOrdinaryReleaseScope {
        &self.scope
    }
    pub const fn final_record(&self) -> &ComponentDigest {
        &self.final_record
    }
    pub const fn verification(&self) -> &ContentDigest {
        &self.verification
    }
    pub const fn first_window(&self) -> DisplayNativeHandoffWindow {
        self.window
    }
}
pub trait OrdinaryDisplayReleasedCurrentPort: Debug + Send {
    fn complete_ordinary_released_current(
        &mut self,
        metadata: OrdinaryDisplayReleasedCurrentCompletion,
    ) -> Result<(), String>;
}
#[derive(Debug)]
pub struct OrdinaryDisplayReleasedCurrent {
    verification: OrdinaryDisplayFinalRetirementVerification,
    record: ContentDigest,
}
impl OrdinaryDisplayReleasedCurrent {
    pub const fn verification(&self) -> &OrdinaryDisplayFinalRetirementVerification {
        &self.verification
    }
    pub const fn record_digest(&self) -> &ContentDigest {
        &self.record
    }
}
impl<S: TransactionStore> ManagedLifecycleControl<S> {
    pub(in crate::managed_lifecycle::display) fn observe_ordinary_final(
        &mut self,
        scope: &linura_core::DisplayOrdinaryReleaseScope,
    ) -> Result<(ObservationEnvelope, DisplayOrdinaryFinalRetirementFacts), ManagedLifecycleError>
    {
        let q = linura_protocol::ObservationRequest {
            provider: ProviderId::new(linura_observation::DISPLAY_RECOVERY_PROVIDER)
                .map_err(|_| invalid_original())?,
            capability: linura_core::CapabilityId::new(
                linura_observation::DISPLAY_ORDINARY_FINAL_RETIREMENT_CAPABILITY,
            )
            .map_err(|_| invalid_original())?,
            resource: scope.resource_id().map_err(|_| invalid_original())?,
        };
        let sample = self
            .previews
            .observe(&q)
            .map_err(|_| invalid_original())?
            .observation;
        let facts = DisplayOrdinaryFinalRetirementFacts::from_envelope(&sample, scope, now_ms()?)
            .map_err(|_| invalid_original())?;
        Ok((sample, facts))
    }
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_ordinary_display_final_retirement<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
        N: OrdinaryDisplayFinalRetirementPort,
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
        let tx = TransactionId::for_namespace(&pid, request);
        let live = self.display_reviews.get(&tx).ok_or_else(invalid_original)?;
        let native_preparation = match &live.stage {
            DisplayReviewStage::OrdinaryCurrentCommitDispatched { preparation } => {
                preparation.clone()
            }
            _ => return Err(invalid_original()),
        };
        let mut review = self
            .display_reviews
            .remove(&tx)
            .ok_or_else(invalid_original)?;
        let proof = self.verify_ordinary_display_qualified_current(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        let inspection = proof.inspection();
        let c = inspection.power().current();
        if c.frames().final_retirement_digest().is_some() {
            return Err(invalid_original());
        }
        self.require_ordinary_current_review(&principal, inspection, &review)?;
        let (_, _, committed) = self.ordinary_committed_record(&principal, inspection)?;
        let prepared_current = Entry::load(
            self.display_journal()?,
            Kind::NativePrepared,
            &pid,
            c.request(),
        )?;
        if prepared_current.digest() != native_preparation {
            return Err(invalid_original());
        }
        let checked = self.checked_display_history()?;
        if !matches!(
            self.display_journal()?
                .load(&pid, &Kind::FinalPrepared.key(request)?),
            Err(TransactionStoreError::NotFound)
        ) {
            return Err(invalid_original());
        }
        drop(checked);
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
        let grant = inspection
            .root()
            .current_grant()
            .ok_or_else(invalid_original)?;
        let prepared = Entry::retain(
            self.request_journal
                .as_deref_mut()
                .ok_or_else(invalid_original)?,
            Kind::FinalPrepared,
            &pid,
            c.request(),
            vec![
                committed.digest().as_str().into(),
                proof.record_digest().as_str().into(),
                grant.record.clone(),
                crate::durable_authority::digest_observation(c.observation())?
                    .as_str()
                    .into(),
                expiry.to_string(),
                now.to_string(),
            ],
        )?;
        let fresh = self.verify_ordinary_display_qualified_current(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        if fresh.record_digest() != proof.record_digest()
            || fresh.inspection().root() != inspection.root()
            || fresh.inspection().power().current().release() != c.release()
            || !fresh
                .inspection()
                .power()
                .current()
                .frames()
                .reconciles(c.frames())
        {
            return Err(invalid_original());
        }
        self.require_ordinary_current_review(&principal, fresh.inspection(), &review)?;
        {
            let _checked = self.checked_display_history()?;
            prepared.readback(self.display_journal()?, &pid, c.request())?;
            prepared_current.readback(self.display_journal()?, &pid, c.request())?;
        }
        if now_ms()? < now || now_ms()? >= expiry {
            return Err(invalid_original());
        }
        let permit = AuthorizedOrdinaryDisplayFinalRetirement {
            root: fresh.inspection().root().clone(),
            frames: fresh.inspection().power().current().frames().clone(),
            preparation: prepared.digest(),
            qualification: proof.record_digest().clone(),
            expiry,
        };
        review.stage = DisplayReviewStage::OrdinaryFinalRetirementDispatched;
        self.check_display_review_capacity(review.retained_bytes)?;
        self.display_reviews.insert(tx, review);
        port.retire_ordinary_current(permit).map_err(|_| {
            ManagedLifecycleError::Indeterminate(
                "ordinary final retirement outcome uncertain; no replay".into(),
            )
        })?;
        let _checked = self.checked_display_history()?;
        prepared.readback(self.display_journal()?, &pid, c.request())?;
        if self
            .authority
            .matching_request_snapshot(&principal, c.request())?
            != *c.release()
        {
            return Err(invalid_original());
        }
        Ok(())
    }
    /// Fresh independent post-effect comparison. Original proof clocks never renew.
    pub fn verify_ordinary_display_final_retirement<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        request: &RequestId,
        attempt: &mut P,
        verifier: &mut V,
    ) -> Result<OrdinaryDisplayFinalRetirementVerification, ManagedLifecycleError> {
        let qualified = self.verify_ordinary_display_qualified_current(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        let c = qualified.inspection().power().current();
        let scope = c.frames().scope();
        let pid = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let prepared = Entry::load(
            self.display_journal()?,
            Kind::FinalPrepared,
            &pid,
            c.request(),
        )?;
        let (before, root) = self.observe_ordinary_final(scope)?;
        let grant = qualified
            .inspection()
            .root()
            .current_grant()
            .ok_or_else(invalid_original)?;
        if root.phase() < 2
            || root.lineage().preparation != prepared.digest().hex()
            || root.lineage().verification != qualified.record_digest().hex()
            || root.lineage().current_grant != grant.record
            || root.lineage().committed_record != grant.committed_record
            || digest(&prepared.fields[5])?.hex() != grant.committed_record
            || digest(&prepared.fields[6])? != *qualified.record_digest()
            || prepared.fields[7] != grant.record
            || c.frames().final_retirement_digest() != Some(root.lineage().record.as_str())
            || !c.frames().follows_final_retirement(root.checkpoint())
            || c.frames().window().observed_unix_ms < number(&prepared.fields[10])?
            || number(&prepared.fields[10])? == 0
            || number(&prepared.fields[10])? >= number(&prepared.fields[9])?
            || number(&prepared.fields[9])? - number(&prepared.fields[10])? > 2000
        {
            return Err(invalid_original());
        }
        digest(&prepared.fields[8])?;
        let (after, checked) = self.observe_ordinary_final(scope)?;
        if checked != root
            || after.sequence <= before.sequence
            || after.observed_at_unix_ms < before.observed_at_unix_ms
        {
            return Err(invalid_original());
        }
        before
            .require_current(now_ms()?)
            .map_err(|_| invalid_original())?;
        c.observation()
            .require_current(now_ms()?)
            .map_err(|_| invalid_original())?;
        let w = c.frames().window();
        let tail = vec![
            prepared.digest().as_str().into(),
            qualified.record_digest().as_str().into(),
            root.lineage().record.clone(),
            crate::durable_authority::digest_observation(c.observation())?
                .as_str()
                .into(),
            w.observed_unix_ms.to_string(),
            w.observed_boot_ms.to_string(),
            w.deadline_unix_ms.to_string(),
            w.deadline_boot_ms.to_string(),
            now_ms()?.to_string(),
        ];
        let record = match self
            .display_journal()?
            .load(&pid, &Kind::FinalVerified.key(request)?)
        {
            Err(TransactionStoreError::NotFound) => Entry::retain(
                self.request_journal
                    .as_deref_mut()
                    .ok_or_else(invalid_original)?,
                Kind::FinalVerified,
                &pid,
                c.request(),
                tail,
            )?,
            Ok(_) => {
                let old = Entry::load(
                    self.display_journal()?,
                    Kind::FinalVerified,
                    &pid,
                    c.request(),
                )?;
                if old.fields[5..8] != tail[..3]
                    || number(&old.fields[13])? > now_ms()?
                    || number(&old.fields[9])? > w.observed_unix_ms
                    || number(&old.fields[10])? > w.observed_boot_ms
                {
                    return Err(invalid_original());
                }
                old
            }
            Err(_) => return Err(invalid_original()),
        };
        let window = DisplayNativeHandoffWindow {
            observed_unix_ms: number(&record.fields[9])?,
            observed_boot_ms: number(&record.fields[10])?,
            deadline_unix_ms: number(&record.fields[11])?,
            deadline_boot_ms: number(&record.fields[12])?,
        };
        window.valid_for_ms().map_err(|_| invalid_original())?;
        digest(&record.fields[8])?;
        let fresh =
            self.verify_ordinary_display_qualified_current(principal, request, attempt, verifier)?;
        if fresh.record_digest() != qualified.record_digest()
            || fresh.inspection().root() != qualified.inspection().root()
            || fresh.inspection().power().current().release() != c.release()
            || !fresh
                .inspection()
                .power()
                .current()
                .frames()
                .reconciles(c.frames())
        {
            return Err(invalid_original());
        }
        {
            let _checked = self.checked_display_history()?;
            prepared.readback(self.display_journal()?, &pid, c.request())?;
            record.readback(self.display_journal()?, &pid, c.request())?;
        }
        Ok(OrdinaryDisplayFinalRetirementVerification {
            qualified: fresh,
            root,
            record: record.digest(),
            window,
        })
    }
    pub fn complete_ordinary_display_released_current<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
        N: OrdinaryDisplayReleasedCurrentPort,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        request: &RequestId,
        attempt: &mut P,
        verifier: &mut V,
        port: &mut N,
    ) -> Result<OrdinaryDisplayReleasedCurrent, ManagedLifecycleError> {
        let proof = self.verify_ordinary_display_final_retirement(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        if proof.root.completed().is_none() {
            port.complete_ordinary_released_current(OrdinaryDisplayReleasedCurrentCompletion{
            scope:proof.qualified.inspection().power().current().frames().scope().clone(),final_record:ComponentDigest::parse_hex(&proof.root.lineage().record).map_err(|_|invalid_original())?,verification:proof.record.clone(),window:proof.window,
        }).map_err(|_|ManagedLifecycleError::Indeterminate("ordinary Root ReleasedCurrent metadata acknowledgement uncertain; retry metadata only".into()))?;
        }
        let after = self.verify_ordinary_display_final_retirement(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        let completed = after.root.completed().ok_or_else(invalid_original)?;
        if after.record != proof.record
            || after.root.lineage() != proof.root.lineage()
            || completed.verification != proof.record.hex()
        {
            return Err(invalid_original());
        }
        let c = after.qualified.inspection().power().current();
        let pid = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let prepared = Entry::load(
            self.display_journal()?,
            Kind::FinalPrepared,
            &pid,
            c.request(),
        )?;
        let tail = vec![
            prepared.digest().as_str().into(),
            after.record.as_str().into(),
            after.root.lineage().record.clone(),
            completed.record.clone(),
            now_ms()?.to_string(),
        ];
        let record = match self
            .display_journal()?
            .load(&pid, &Kind::Released.key(request)?)
        {
            Err(TransactionStoreError::NotFound) => Entry::retain(
                self.request_journal
                    .as_deref_mut()
                    .ok_or_else(invalid_original)?,
                Kind::Released,
                &pid,
                c.request(),
                tail,
            )?,
            Ok(_) => {
                let old = Entry::load(self.display_journal()?, Kind::Released, &pid, c.request())?;
                if old.fields[5..9] != tail[..4] || number(&old.fields[9])? > now_ms()? {
                    return Err(invalid_original());
                }
                old
            }
            Err(_) => return Err(invalid_original()),
        };
        let fresh =
            self.verify_ordinary_display_final_retirement(principal, request, attempt, verifier)?;
        if fresh.record != after.record || fresh.root != after.root {
            return Err(invalid_original());
        }
        {
            let _checked = self.checked_display_history()?;
            record.readback(self.display_journal()?, &pid, c.request())?;
            prepared.readback(self.display_journal()?, &pid, c.request())?;
        }
        Ok(OrdinaryDisplayReleasedCurrent {
            verification: fresh,
            record: record.digest(),
        })
    }
}
