//! Original final fence retirement. Committed history and Root ACKs are not
//! physical verification, successor admission, or checkpoint cleanup authority.
use super::*;
use completed::{Entry, Kind, content, header, unsigned};
use linura_observation::{
    DISPLAY_ORIGINAL_FINAL_RETIREMENT_CAPABILITY, DisplayNativeCurrentFacts,
    DisplayNativeHandoffWindow, DisplayOriginalFinalRetirementFacts,
    DisplayOriginalRootRetirementFacts,
};
use linura_transaction::{ContentDigest, TransactionStoreError};

#[derive(Debug)]
pub struct AuthorizedOriginalDisplayFinalRetirement {
    root: DisplayOriginalRootRetirementFacts,
    frames: DisplayNativeCurrentFacts,
    preparation: ContentDigest,
    qualification: ContentDigest,
    expiry: u64,
}
impl AuthorizedOriginalDisplayFinalRetirement {
    pub const fn root(&self) -> &DisplayOriginalRootRetirementFacts {
        &self.root
    }
    pub const fn frames(&self) -> &DisplayNativeCurrentFacts {
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
pub trait OriginalDisplayFinalRetirementPort: Debug + Send {
    fn retire_current(
        &mut self,
        prepared: AuthorizedOriginalDisplayFinalRetirement,
    ) -> Result<(), String>;
}
#[derive(Debug)]
pub struct OriginalDisplayFinalRetirementVerification {
    qualified: OriginalDisplayQualifiedCurrent,
    root: DisplayOriginalFinalRetirementFacts,
    record: ContentDigest,
    window: DisplayNativeHandoffWindow,
}
impl OriginalDisplayFinalRetirementVerification {
    pub const fn qualified(&self) -> &OriginalDisplayQualifiedCurrent {
        &self.qualified
    }
    pub const fn root(&self) -> &DisplayOriginalFinalRetirementFacts {
        &self.root
    }
    pub const fn record_digest(&self) -> &ContentDigest {
        &self.record
    }
    pub const fn first_window(&self) -> DisplayNativeHandoffWindow {
        self.window
    }
}
/// Metadata only. No constructor is exported, and this contains no native grant.
#[derive(Debug)]
pub struct OriginalDisplayReleasedCurrentCompletion {
    scope: linura_core::DisplayRecoveryScope,
    final_record: ComponentDigest,
    verification: ContentDigest,
    window: DisplayNativeHandoffWindow,
}
impl OriginalDisplayReleasedCurrentCompletion {
    pub const fn scope(&self) -> &linura_core::DisplayRecoveryScope {
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
pub trait OriginalDisplayReleasedCurrentPort: Debug + Send {
    fn complete_released_current(
        &mut self,
        completion: OriginalDisplayReleasedCurrentCompletion,
    ) -> Result<(), String>;
}
#[derive(Debug)]
pub struct OriginalDisplayReleasedCurrent {
    verification: OriginalDisplayFinalRetirementVerification,
    record: ContentDigest,
}
impl OriginalDisplayReleasedCurrent {
    pub const fn verification(&self) -> &OriginalDisplayFinalRetirementVerification {
        &self.verification
    }
    pub const fn record_digest(&self) -> &ContentDigest {
        &self.record
    }
}
impl<S: TransactionStore> ManagedLifecycleControl<S> {
    fn observe_final_retirement(
        &mut self,
        scope: &linura_core::DisplayRecoveryScope,
    ) -> Result<(ObservationEnvelope, DisplayOriginalFinalRetirementFacts), ManagedLifecycleError>
    {
        let request = ObservationRequest {
            provider: ProviderId::new(DISPLAY_RECOVERY_PROVIDER).map_err(|_| invalid())?,
            capability: CapabilityId::new(DISPLAY_ORIGINAL_FINAL_RETIREMENT_CAPABILITY)
                .map_err(|_| invalid())?,
            resource: scope.resource_id().map_err(|_| invalid())?,
        };
        let sample = self
            .previews
            .observe(&request)
            .map_err(|_| invalid())?
            .observation;
        let facts = DisplayOriginalFinalRetirementFacts::from_envelope(&sample, scope, now_ms()?)
            .map_err(|_| invalid())?;
        Ok((sample, facts))
    }
    pub fn dispatch_original_display_final_retirement<P: OriginalDisplayFinalRetirementPort>(
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
        let proof = self.verify_original_display_qualified_current(principal.clone(), request)?;
        let current = proof.inspection().current();
        if current.frames().final_retirement_digest().is_some() {
            return Err(invalid());
        }
        let review = self
            .display_reviews
            .get(&context.snapshot.transaction_id)
            .ok_or_else(invalid)?;
        if !matches!(review.stage, DisplayReviewStage::CurrentCommitDispatched) {
            return Err(invalid());
        }
        let mut review = self
            .display_reviews
            .remove(&context.snapshot.transaction_id)
            .ok_or_else(invalid)?;
        let committed = self.commit_original_display_current(principal.clone(), actor, request)?;
        self.revalidate_current_commit_review(&principal, &context, &review, &committed)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let kind = Kind::FinalPrepared;
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
        let window = current.frames().window();
        let now = now_ms()?;
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
            proof.record_digest().as_str().into(),
            proof
                .inspection()
                .root()
                .current_grant()
                .ok_or_else(invalid)?
                .record
                .clone(),
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
        let permit = AuthorizedOriginalDisplayFinalRetirement {
            root: proof.inspection().root().clone(),
            frames: current.frames().clone(),
            preparation: prepared.digest(kind),
            qualification: proof.record_digest().clone(),
            expiry,
        };
        review.stage = DisplayReviewStage::FinalRetirementDispatched;
        self.check_display_review_capacity(review.retained_bytes)?;
        self.display_reviews
            .insert(context.snapshot.transaction_id, review);
        port.retire_current(permit).map_err(|_| {
            ManagedLifecycleError::Indeterminate(
                "native final retirement outcome uncertain; no replay".into(),
            )
        })?;
        if Entry::load(
            self.display_journal()?,
            kind,
            &principal_id,
            &context.request,
        )?
        .bytes
            != prepared.bytes
        {
            return Err(invalid());
        }
        Ok(()) // Permission ACK only.
    }
    /// Read-only recovery. The original first proof clocks are immutable.
    pub fn verify_original_display_final_retirement(
        &mut self,
        principal: AuthenticatedPrincipal,
        request: &RequestId,
    ) -> Result<OriginalDisplayFinalRetirementVerification, ManagedLifecycleError> {
        let context = self.current_finalization_comparison_context(&principal, request)?;
        let scope = DisplayFinalizationMaterial::decode(context.intent.material())
            .map_err(|_| invalid())?
            .recovery_scope()
            .map_err(|_| invalid())?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let prepared = Entry::load(
            self.display_journal()?,
            Kind::FinalPrepared,
            &principal_id,
            &context.request,
        )?;
        let (before, root) = self.observe_final_retirement(&scope)?;
        let qualified =
            self.verify_original_display_qualified_current(principal.clone(), request)?;
        let current = qualified.inspection().current();
        let grant = qualified
            .inspection()
            .root()
            .current_grant()
            .ok_or_else(invalid)?;
        if root.phase() < 2
            || root.lineage().preparation != prepared.digest(Kind::FinalPrepared).hex()
            || root.lineage().verification != qualified.record_digest().hex()
            || root.lineage().current_grant != grant.record
            || root.lineage().committed_record != grant.committed_record
            || content(&prepared.fields[5])?.hex() != grant.committed_record
            || content(&prepared.fields[6])? != *qualified.record_digest()
            || prepared.fields[7] != grant.record
            || current.frames().final_retirement_digest() != Some(root.lineage().record.as_str())
            || current.frames().window().observed_unix_ms < unsigned(&prepared.fields[10])?
        {
            return Err(invalid());
        }
        let (after, checked) = self.observe_final_retirement(&scope)?;
        if checked != root || after.sequence <= before.sequence {
            return Err(invalid());
        }
        before.require_current(now_ms()?).map_err(|_| invalid())?;
        current
            .observation()
            .require_current(now_ms()?)
            .map_err(|_| invalid())?;
        let window = current.frames().window();
        let kind = Kind::FinalVerified;
        let mut fields = header(kind, &principal_id, &context.request)?;
        fields.extend([
            prepared.digest(Kind::FinalPrepared).as_str().into(),
            qualified.record_digest().as_str().into(),
            root.lineage().record.clone(),
            crate::durable_authority::digest_observation(current.observation())?
                .as_str()
                .into(),
            window.observed_unix_ms.to_string(),
            window.observed_boot_ms.to_string(),
            window.deadline_unix_ms.to_string(),
            window.deadline_boot_ms.to_string(),
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
                if old.fields[..8] != fields[..8]
                    || unsigned(&old.fields[13])? > now_ms()?
                    || unsigned(&old.fields[9])? > window.observed_unix_ms
                    || unsigned(&old.fields[10])? > window.observed_boot_ms
                {
                    return Err(invalid());
                }
                old
            }
            Err(_) => return Err(invalid()),
        };
        self.require_current_inspection_history(&principal, current)?;
        if Entry::load(
            self.display_journal()?,
            Kind::FinalPrepared,
            &principal_id,
            &context.request,
        )?
        .bytes
            != prepared.bytes
        {
            return Err(invalid());
        }
        Ok(OriginalDisplayFinalRetirementVerification {
            qualified,
            root,
            record: retained.digest(kind),
            window: DisplayNativeHandoffWindow {
                observed_unix_ms: unsigned(&retained.fields[9])?,
                observed_boot_ms: unsigned(&retained.fields[10])?,
                deadline_unix_ms: unsigned(&retained.fields[11])?,
                deadline_boot_ms: unsigned(&retained.fields[12])?,
            },
        })
    }
    /// Complete metadata after fresh independent verification. Retrying this
    /// operation cannot call a native effect or reconstruct the original review.
    pub fn complete_original_display_released_current<P: OriginalDisplayReleasedCurrentPort>(
        &mut self,
        principal: AuthenticatedPrincipal,
        request: &RequestId,
        port: &mut P,
    ) -> Result<OriginalDisplayReleasedCurrent, ManagedLifecycleError> {
        let proof = self.verify_original_display_final_retirement(principal.clone(), request)?;
        let scope = proof
            .qualified()
            .inspection()
            .current()
            .frames()
            .scope()
            .clone();
        let final_record =
            ComponentDigest::parse_hex(&proof.root.lineage().record).map_err(|_| invalid())?;
        if proof.root.completed().is_none() {
            port.complete_released_current(OriginalDisplayReleasedCurrentCompletion {
                scope,
                final_record,
                verification: proof.record.clone(),
                window: proof.window,
            })
            .map_err(|_| {
                ManagedLifecycleError::Indeterminate(
                    "Root released-current metadata acknowledgement uncertain; retry metadata only"
                        .into(),
                )
            })?;
        }
        let after = self.verify_original_display_final_retirement(principal.clone(), request)?;
        let completed = after.root.completed().ok_or_else(invalid)?;
        if after.record != proof.record
            || after.root.lineage() != proof.root.lineage()
            || completed.verification != proof.record.hex()
        {
            return Err(invalid());
        }
        let context = self.current_finalization_comparison_context(&principal, request)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let prepared = Entry::load(
            self.display_journal()?,
            Kind::FinalPrepared,
            &principal_id,
            &context.request,
        )?;
        let kind = Kind::Released;
        let mut fields = header(kind, &principal_id, &context.request)?;
        fields.extend([
            prepared.digest(Kind::FinalPrepared).as_str().into(),
            after.record.as_str().into(),
            after.root.lineage().record.clone(),
            completed.record.clone(),
            now_ms()?.to_string(),
        ]);
        let record = match self
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
                if old.fields[..9] != fields[..9] || unsigned(&old.fields[9])? > now_ms()? {
                    return Err(invalid());
                }
                old
            }
            Err(_) => return Err(invalid()),
        };
        self.require_current_inspection_history(
            &principal,
            after.qualified().inspection().current(),
        )?;
        Ok(OriginalDisplayReleasedCurrent {
            verification: after,
            record: record.digest(kind),
        })
    }
}
