//! Adopt retained committed intent only after independently completed release.
//! Adoption preserves semantic lineage; it grants no physical continuation,
//! successor admission, compensation or checkpoint removal authority.
use super::current_records::{Entry, Kind, digest, number};
use super::*;
use linura_transaction::{CommittedStateMaterial, ContentDigest, TransactionStoreError};

#[derive(Debug)]
pub struct OrdinaryDisplayCommittedAdoption {
    request: PlanDesiredStateRequest,
    material: CommittedStateMaterial,
    released: ContentDigest,
    record: ContentDigest,
    first_adopted_at: u64,
    observation: ObservationEnvelope,
}
impl OrdinaryDisplayCommittedAdoption {
    pub const fn request(&self) -> &PlanDesiredStateRequest {
        &self.request
    }
    pub const fn material(&self) -> &CommittedStateMaterial {
        &self.material
    }
    pub const fn released_record(&self) -> &ContentDigest {
        &self.released
    }
    pub const fn record_digest(&self) -> &ContentDigest {
        &self.record
    }
    pub const fn first_adopted_at_unix_ms(&self) -> u64 {
        self.first_adopted_at
    }
    /// The current comparison expires independently of the immutable adoption.
    pub const fn observation(&self) -> &ObservationEnvelope {
        &self.observation
    }
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    /// Control-local metadata, after fresh independent physical verification.
    /// Across Control restarts this reloads the approved structured intent and
    /// its authenticated committed graph/provenance; no effect port is present.
    pub fn adopt_ordinary_display_committed_state<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        request: &RequestId,
        attempt: &mut P,
        verifier: &mut V,
    ) -> Result<OrdinaryDisplayCommittedAdoption, ManagedLifecycleError> {
        let pid = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let (retained, released) = {
            let _checked = self.checked_display_history()?;
            let row = self
                .display_journal()?
                .load(&pid, request)
                .map_err(|_| invalid_original())?;
            if row.principal() != &pid || row.request_id() != request {
                return Err(invalid_original());
            }
            let retained = crate::retained_request::decode(&row)?;
            validate_public_request(&retained)?;
            validate_request_identity(&retained)?;
            if row.digest() != &crate::durable_authority::digest_request(&retained)? {
                return Err(invalid_original());
            }
            let intent = crate::display_ordinary_release_intent::OrdinaryReleaseIntent::load(
                self.display_journal()?,
                &pid,
                &retained,
            )?;
            intent.require_claim(self.display_journal()?, &pid, &retained)?;
            // Missing completion is refused before observations or metadata writes.
            let released = Entry::load(self.display_journal()?, Kind::Released, &pid, &retained)?;
            (retained, released)
        };
        let material = self
            .authority
            .display_committed_material(&principal, &retained)?;
        let proof = self.verify_ordinary_display_final_retirement(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        let qualified = proof.qualified();
        let current = qualified.inspection().power().current();
        let completed = proof.root().completed().ok_or_else(invalid_original)?;
        let (ready, verified, _) =
            self.ordinary_committed_record(&principal, qualified.inspection())?;
        let final_prepared = Entry::load(
            self.display_journal()?,
            Kind::FinalPrepared,
            &pid,
            &retained,
        )?;
        if current.request() != &retained
            || current.release() != &material.snapshot
            || digest(&released.fields[5])? != final_prepared.digest()
            || digest(&released.fields[6])? != *proof.record_digest()
            || released.fields[7] != proof.root().lineage().record
            || released.fields[8] != completed.record
            || completed.verification != proof.record_digest().hex()
            || number(&released.fields[9])? == 0
            || number(&released.fields[9])? > now_ms()?
            || digest(&verified.fields[5])? != ready.digest()
            || digest(&verified.fields[7])? != material.desired_state_digest
            || digest(&verified.fields[8])? != material.graph_digest
            || digest(&verified.fields[9])? != material.provenance_digest
        {
            return Err(invalid_original());
        }
        let tail = vec![
            released.digest().as_str().into(),
            completed.record.clone(),
            proof.record_digest().as_str().into(),
            material.desired_state_digest.as_str().into(),
            material.graph_digest.as_str().into(),
            material.provenance_digest.as_str().into(),
            material.snapshot.binding_digest.as_str().into(),
            material.snapshot.current_generation.to_string(),
            material.snapshot.state_version.to_string(),
            now_ms()?.to_string(),
        ];
        let adopted = match self
            .display_journal()?
            .load(&pid, &Kind::Adopted.key(request)?)
        {
            Err(TransactionStoreError::NotFound) => Entry::retain(
                self.request_journal
                    .as_deref_mut()
                    .ok_or_else(invalid_original)?,
                Kind::Adopted,
                &pid,
                &retained,
                tail,
            )?,
            Ok(_) => {
                let old = Entry::load(self.display_journal()?, Kind::Adopted, &pid, &retained)?;
                if old.fields[5..14] != tail[..9]
                    || number(&old.fields[14])? == 0
                    || number(&old.fields[14])? > now_ms()?
                {
                    return Err(invalid_original());
                }
                old
            }
            Err(_) => return Err(invalid_original()),
        };
        // Publication is a boundary: re-observe, re-authenticate all history,
        // and compare the exact committed lineage again. ACKs cannot adopt.
        let fresh = self.verify_ordinary_display_final_retirement(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        if fresh.root() != proof.root()
            || fresh.record_digest() != proof.record_digest()
            || self
                .authority
                .display_committed_material(&principal, &retained)?
                != material
        {
            return Err(invalid_original());
        }
        {
            let _checked = self.checked_display_history()?;
            released.readback(self.display_journal()?, &pid, &retained)?;
            adopted.readback(self.display_journal()?, &pid, &retained)?;
        }
        let observation = fresh
            .qualified()
            .inspection()
            .power()
            .current()
            .observation()
            .clone();
        observation
            .require_current(now_ms()?)
            .map_err(|_| invalid_original())?;
        Ok(OrdinaryDisplayCommittedAdoption {
            request: retained,
            material,
            released: released.digest(),
            record: adopted.digest(),
            first_adopted_at: number(&adopted.fields[14])?,
            observation,
        })
    }
}
