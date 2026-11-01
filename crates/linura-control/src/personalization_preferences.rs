//! S25 owner-authenticated Control boundary for durable preferences.
//! The trusted transport must derive AuthenticatedPrincipal from peer identity;
//! neither a client-supplied Actor nor an imported profile may mint a principal.
//! Saved state never implies native renderer success or an executor credential.

use std::time::{SystemTime, UNIX_EPOCH};

use linura_core::{OperationClass, PrincipalId, RequestId, RiskClass};
use linura_transaction::{
    ContentDigest, PERSONALIZATION_REQUEST_PREFIX, PersonalizationChoices,
    PersonalizationPreferenceRecord, PersonalizationPreferenceStore,
    TransactionAuthoritySigner, TransactionStoreError,
};

use crate::AuthenticatedPrincipal;

const SIGNED_WRITE_TTL_MS: u64 = 1500;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalizationConfigurationRequest {
    /// Canonical suffix for a purpose-specific idempotent local request ID.
    pub operation_id: String,
    pub expected_revision: u64,
    pub expected_digest: Option<ContentDigest>,
    pub choices: PersonalizationChoices,
}

impl PersonalizationConfigurationRequest {
    #[must_use]
    pub const fn operation_class(&self) -> OperationClass {
        OperationClass::LinuraOwnedState
    }

    #[must_use]
    pub const fn risk_floor(&self) -> RiskClass {
        RiskClass::UserState
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalizationConfigurationReceipt {
    pub record: PersonalizationPreferenceRecord,
    /// Whether the saved request is the latest local choice. Not actual
    /// compositor, theme, wallpaper or cross-surface applied state.
    pub current_saved_revision: bool,
}

#[derive(Debug)]
pub struct PersonalizationPreferencesControl {
    store: Box<dyn PersonalizationPreferenceStore>,
    signer: TransactionAuthoritySigner,
}

impl PersonalizationPreferencesControl {
    pub fn new(
        store: Box<dyn PersonalizationPreferenceStore>,
        signer: TransactionAuthoritySigner,
    ) -> Result<Self, String> {
        store.integrity_check().map_err(|error| error.to_string())?;
        Ok(Self { store, signer })
    }

    /// Owner-only saved-state query; never a native observation.
    pub fn current(
        &self,
        principal: &AuthenticatedPrincipal,
    ) -> Result<Option<PersonalizationPreferenceRecord>, String> {
        let owner = checked_owner(principal)?;
        self.store.current(&owner).map_err(|error| error.to_string())
    }

    /// Lost-reply recovery is read-only and cannot replay an old change.
    pub fn request_status(
        &self,
        principal: &AuthenticatedPrincipal,
        operation_id: &str,
    ) -> Result<PersonalizationConfigurationReceipt, String> {
        let owner = checked_owner(principal)?;
        let request = checked_request(operation_id)?;
        let record = self.store.request(&owner, &request)
            .map_err(|error| error.to_string())?
            .ok_or("personalization request is not retained for this owner")?;
        self.receipt(record)
    }

    /// A trusted local-state write. Caller identity must be authenticated at
    /// transport before constructing principal. Never apply native effects.
    pub fn configure(
        &mut self,
        principal: &AuthenticatedPrincipal,
        request: &PersonalizationConfigurationRequest,
    ) -> Result<PersonalizationConfigurationReceipt, String> {
        self.configure_with_clock(principal, request, now)
    }

    fn configure_with_clock(
        &mut self,
        principal: &AuthenticatedPrincipal,
        request: &PersonalizationConfigurationRequest,
        clock: impl Fn() -> Result<u64, String>,
    ) -> Result<PersonalizationConfigurationReceipt, String> {
        let owner = checked_owner(principal)?;
        let request_id = checked_request(&request.operation_id)?;
        if let Some(old) = self.store.request(&owner, &request_id)
            .map_err(|error| error.to_string())?
        {
            // Exactly same content and original expected base is a historical
            // retry; it must never restore the old configuration.
            if old.choices() != &request.choices
                || old.revision() != request.expected_revision.saturating_add(1)
                || old.previous_digest() != request.expected_digest.as_ref()
            {
                return Err(TransactionStoreError::IdempotencyConflict.to_string());
            }
            return self.receipt(old);
        }

        let previous = self.store.current(&owner)
            .map_err(|error| error.to_string())?;
        let observed_revision = previous.as_ref()
            .map_or(0, PersonalizationPreferenceRecord::revision);
        let observed_digest = previous.as_ref()
            .map(PersonalizationPreferenceRecord::digest);
        if request.expected_revision != observed_revision
            || request.expected_digest.as_ref() != observed_digest
        {
            return Err(TransactionStoreError::StateConflict.to_string());
        }
        let revision = observed_revision.checked_add(1)
            .ok_or_else(|| TransactionStoreError::CapacityExceeded.to_string())?;
        let record = PersonalizationPreferenceRecord::new(
            owner, request_id, revision, request.expected_digest.clone(), request.choices.clone(),
        ).map_err(|error| error.to_string())?;
        let sampled = clock()?;
        let expiry = sampled.checked_add(SIGNED_WRITE_TTL_MS)
            .ok_or("personalization clock overflow")?;
        let signed = self.signer.authorize_personalization_preference(
            record, sampled, expiry,
        ).map_err(|error| error.to_string())?;
        let saved = self.store.apply(&signed)
            .map_err(|error| error.to_string())?;
        self.receipt(saved)
    }

    fn receipt(
        &self,
        record: PersonalizationPreferenceRecord,
    ) -> Result<PersonalizationConfigurationReceipt, String> {
        let current = self.store.current(record.owner())
            .map_err(|error| error.to_string())?;
        Ok(PersonalizationConfigurationReceipt {
            current_saved_revision: current.as_ref()
                .is_some_and(|latest| latest.digest() == record.digest()),
            record,
        })
    }
}

fn checked_owner(principal: &AuthenticatedPrincipal) -> Result<PrincipalId, String> {
    let value = principal.as_str();
    let uid = value.strip_prefix("unix:uid:")
        .and_then(|text| text.parse::<u32>().ok())
        .filter(|uid| *uid != 0 && value == format!("unix:uid:{uid}"))
        .ok_or("personalization requires an authenticated non-root owner")?;
    let _ = uid;
    PrincipalId::new(value).map_err(|error| error.to_string())
}

fn checked_request(operation: &str) -> Result<RequestId, String> {
    let request = RequestId::new(format!("{PERSONALIZATION_REQUEST_PREFIX}{operation}"))
        .map_err(|error| error.to_string())?;
    // Canonical operation identity is checked by record construction; enforce
    // it before even looking up retained request material.
    if operation.is_empty() || operation.len() > 128
        || !operation.bytes().all(|value| value.is_ascii_lowercase()
            || value.is_ascii_digit() || value == b'-')
    {
        return Err("noncanonical personalization operation identity".into());
    }
    Ok(request)
}

fn now() -> Result<u64, String> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "personalization clock unavailable")?;
    let now = u64::try_from(duration.as_millis())
        .map_err(|_| "personalization clock unsupported")?;
    if now == 0 || now > i64::MAX as u64 {
        return Err("personalization clock unsupported".into());
    }
    Ok(now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_transaction::{
        TransactionAuthorityKey, TransactionAuthorityVerifier,
        PersonalizationPreferenceUpdate,
    };
    use std::fs::File;
    use std::io::Read;

    #[derive(Debug)]
    struct MemoryStore {
        records: Vec<PersonalizationPreferenceRecord>,
        verifier: TransactionAuthorityVerifier,
    }

    impl PersonalizationPreferenceStore for MemoryStore {
        fn current(
            &self, owner: &PrincipalId,
        ) -> Result<Option<PersonalizationPreferenceRecord>, TransactionStoreError> {
            Ok(self.records.iter().rev().find(|value| value.owner() == owner).cloned())
        }
        fn request(
            &self, owner: &PrincipalId, request: &RequestId,
        ) -> Result<Option<PersonalizationPreferenceRecord>, TransactionStoreError> {
            Ok(self.records.iter().find(|value| value.owner() == owner
                && value.request() == request).cloned())
        }
        fn apply(
            &mut self, update: &PersonalizationPreferenceUpdate,
        ) -> Result<PersonalizationPreferenceRecord, TransactionStoreError> {
            if !self.verifier.verify_personalization_preference(update) {
                return Err(TransactionStoreError::AuthorityRejected);
            }
            let record = update.record();
            let current = self.current(record.owner())?;
            let revision = current.as_ref().map_or(0, PersonalizationPreferenceRecord::revision);
            if record.revision() != revision + 1
                || current.as_ref().map(PersonalizationPreferenceRecord::digest)
                    != record.previous_digest()
            {
                return Err(TransactionStoreError::StateConflict);
            }
            self.records.push(record.clone());
            Ok(record.clone())
        }
        fn integrity_check(&self) -> Result<(), TransactionStoreError> { Ok(()) }
    }

    fn control() -> PersonalizationPreferencesControl {
        let mut bytes = Vec::new();
        let n = File::open("/dev/urandom")
            .and_then(|f| f.take(32).read_to_end(&mut bytes))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(n, 32);
        let (signer, verifier) = TransactionAuthorityKey::new(bytes)
            .unwrap_or_else(|error| unreachable!("{error}")).split();
        PersonalizationPreferencesControl::new(
            Box::new(MemoryStore { records: Vec::new(), verifier }), signer,
        ).unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn principal(uid: u32) -> AuthenticatedPrincipal {
        AuthenticatedPrincipal::new(format!("unix:uid:{uid}"))
            .unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn request(operation: &str) -> PersonalizationConfigurationRequest {
        PersonalizationConfigurationRequest {
            operation_id: operation.into(),
            expected_revision: 0,
            expected_digest: None,
            choices: PersonalizationChoices::default(),
        }
    }

    #[test]
    fn rejects_untrusted_identity_and_reuses_only_exact_request_receipt() {
        let mut control = control();
        assert!(control.configure_with_clock(&principal(0), &request("first"), || Ok(1000)).is_err());
        assert!(control.configure_with_clock(
            &AuthenticatedPrincipal::new("remote:uid:1000")
                .unwrap_or_else(|error| unreachable!("{error}")),
            &request("first"), || Ok(1000),
        ).is_err());
        let first = control.configure_with_clock(&principal(1000), &request("first"), || Ok(1000))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(first.record.revision(), 1);
        assert!(first.current_saved_revision);
        assert!(control.configure_with_clock(&principal(1001), &request("first"), || Ok(1000)).is_ok());
        let mut second = request("second");
        second.expected_revision = 1;
        second.expected_digest = Some(first.record.digest().clone());
        let second_receipt = control.configure_with_clock(&principal(1000), &second, || Ok(1000))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(second_receipt.record.revision(), 2);
        let retry = control.configure_with_clock(&principal(1000), &request("first"), || Ok(2000))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(!retry.current_saved_revision);
        assert_eq!(
            control.current(&principal(1000))
                .unwrap_or_else(|error| unreachable!("{error}")),
            Some(second_receipt.record)
        );
        let mut conflicting = request("first");
        conflicting.choices.reduced_motion = true;
        assert!(control.configure_with_clock(&principal(1000), &conflicting, || Ok(1000)).is_err());
    }

    #[test]
    fn stale_cas_and_invalid_operation_never_write() {
        let mut control = control();
        assert!(control.configure_with_clock(&principal(1000), &request("BAD"), || Ok(1000)).is_err());
        assert!(control.configure_with_clock(&principal(1000), &request("first"), || Ok(1000)).is_ok());
        assert!(control.configure_with_clock(&principal(1000), &request("stale"), || Ok(1000)).is_err());
    }
}
