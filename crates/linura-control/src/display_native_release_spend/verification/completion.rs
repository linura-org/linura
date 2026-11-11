//! Irreversible Control completion intent, retained before a further Root write.
//! This is neither physical completion nor a replayable release credential.
use super::*;

const DOMAIN: &str = "linura.display.original-completion-prepared.v1";
const KEY_DOMAIN: &str = "linura.display.original-completion-prepared-key.v1";
const MAX_COMPLETION_BYTES: usize = 2 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct NativeCompletionPrepared {
    principal: PrincipalId,
    request: RequestId,
    canonical: Vec<u8>,
    prepared_at: u64,
    expiry: u64,
}

impl NativeCompletionPrepared {
    pub(crate) fn key(request: &RequestId) -> Result<RequestId, ManagedLifecycleError> {
        RequestId::new(format!(
            "request:v010:display-completion-prepared:{}",
            digest_bytes(KEY_DOMAIN, request.as_str().as_bytes()).hex()
        ))
        .map_err(|_| invalid())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture(
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
        snapshot: &TransactionSnapshot,
        dispatch: &str,
        material: &str,
        spend: &NativeReleaseSpendPrepared,
        verification: &NativeHandoffVerified,
        observation: &ObservationEnvelope,
        frames: &DisplayNativeHandoffFacts,
        now: u64,
    ) -> Result<Self, ManagedLifecycleError> {
        // Reconstruct the complete fresh independent proof and compare the
        // immutable retained proof. A digest passed by a caller cannot replace
        // this lineage, its exact frame tuple or either original clock.
        let fresh = NativeHandoffVerified::capture(
            principal,
            request,
            snapshot,
            dispatch,
            material,
            spend,
            observation,
            frames,
            now,
        )?;
        let retained = NativeHandoffVerified::reconcile(&verification.canonical, &fresh)?;
        if verification.principal != *principal
            || verification.request != request.request_id
            || retained != *verification
        {
            return Err(invalid());
        }
        let expiry = retained.expiry().min(fresh.expiry());
        if now >= expiry {
            return Err(invalid());
        }
        let mut canonical = Vec::new();
        for value in [
            DOMAIN.to_owned(),
            principal.as_str().into(),
            request.request_id.as_str().into(),
            snapshot.transaction_id.as_str().into(),
            crate::durable_authority::digest_request(request)?
                .as_str()
                .into(),
            snapshot.current_generation.to_string(),
            snapshot.state_version.to_string(),
            snapshot.binding_digest.as_str().into(),
            dispatch.into(),
            spend.digest().as_str().into(),
            verification.digest().as_str().into(),
            crate::durable_authority::digest_observation(observation)?
                .as_str()
                .into(),
            digest_bytes(FRAME_DOMAIN, &frame_bytes(frames)?)
                .as_str()
                .into(),
            now.to_string(),
            expiry.to_string(),
        ] {
            append(&mut canonical, &value)?;
        }
        if canonical.len() > MAX_COMPLETION_BYTES {
            return Err(invalid());
        }
        Ok(Self {
            principal: principal.clone(),
            request: request.request_id.clone(),
            canonical,
            prepared_at: now,
            expiry,
        })
    }

    pub(crate) fn require_absent(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        request: &RequestId,
    ) -> Result<(), ManagedLifecycleError> {
        journal.integrity_check().map_err(|_| invalid())?;
        match journal.load(principal, &Self::key(request)?) {
            Err(TransactionStoreError::NotFound) => Ok(()),
            _ => Err(invalid()),
        }
    }

    /// Exclusive preparation, never idempotent effect delivery. An old exact
    /// record, corrupt bytes or an ambiguous write all exclude another port call.
    pub(crate) fn retain_once(
        &self,
        journal: &mut dyn ApprovedRequestJournal,
    ) -> Result<(), ManagedLifecycleError> {
        Self::require_absent(journal, &self.principal, &self.request)?;
        let retained = RetainedRequest::new(
            self.principal.clone(),
            Self::key(&self.request)?,
            self.canonical.clone(),
        )
        .map_err(|_| invalid())?;
        journal.retain(&retained).map_err(|_| invalid())?;
        self.require_readback(journal)
    }

    pub(crate) fn require_readback(
        &self,
        journal: &dyn ApprovedRequestJournal,
    ) -> Result<(), ManagedLifecycleError> {
        journal.integrity_check().map_err(|_| invalid())?;
        let record = journal
            .load(&self.principal, &Self::key(&self.request)?)
            .map_err(|_| invalid())?;
        if record.principal() != &self.principal
            || record.request_id() != &Self::key(&self.request)?
            || record.canonical() != self.canonical
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> ContentDigest {
        digest_bytes(DOMAIN, &self.canonical)
    }
    pub(crate) fn require_current(&self, now: u64) -> Result<(), ManagedLifecycleError> {
        if now < self.prepared_at || now >= self.expiry {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) const fn expiry(&self) -> u64 {
        self.expiry
    }
}
