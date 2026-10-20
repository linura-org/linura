//! S17 owner-approved local policy state. Records are provenance, not credentials.
//! Enabling this setting never authorizes unlock or a power transition. Control
//! must re-read the current record and attest the native event at every use.

use std::fmt::Debug;

use linura_core::{IntentId, PrincipalId, RequestId, ResourceId, SessionEpoch, SessionLockId};

use crate::{
    AUTHORITY_MUTATION_TAG_BYTES, ContentDigest, TransactionAuthoritySigner,
    TransactionAuthorityVerifier, TransactionStoreError, TransactionValidationError, authority_tag,
    digest_bytes, mutation_field, verify_authority_tag,
};

pub const MAX_PROTECTIVE_LOCK_SETTING_BYTES: usize = 4096;
const DOMAIN: &str = "linura.protective-lock.setting-record.v1";
const MUTATION_DOMAIN: &str = "linura.protective-lock.setting-mutation.v1";

/// Exact structured decision and its purpose-specific native confirmation
/// lineage. Constructing/decoding this data does not authenticate approval.
/// Only a Control-signed update may enter the protected durable store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectiveLockSettingRecord {
    owner: PrincipalId,
    epoch: SessionEpoch,
    intent: IntentId,
    request: RequestId,
    previous: Option<ContentDigest>,
    enabled: bool,
    confirmed_lock: SessionLockId,
    confirmed_at_unix_ms: u64,
    confirmation_digest: ContentDigest,
    canonical: Vec<u8>,
    digest: ContentDigest,
}

impl ProtectiveLockSettingRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner: PrincipalId,
        epoch: SessionEpoch,
        intent: IntentId,
        request: RequestId,
        previous: Option<ContentDigest>,
        enabled: bool,
        confirmed_lock: SessionLockId,
        confirmed_at_unix_ms: u64,
        confirmation_digest: ContentDigest,
    ) -> Result<Self, TransactionStoreError> {
        if epoch.uid() == 0
            || owner.as_str() != format!("unix:uid:{}", epoch.uid())
            || confirmed_lock.epoch() != &epoch
            || confirmed_at_unix_ms == 0
            || confirmation_digest == ContentDigest::zero()
            || previous.as_ref() == Some(&ContentDigest::zero())
        {
            return Err(TransactionStoreError::AuthorityRejected);
        }
        let mut canonical = Vec::new();
        for value in [
            DOMAIN,
            owner.as_str(),
            epoch.resource_id().map_err(|_| invalid())?.as_str(),
            intent.as_str(),
            request.as_str(),
            previous.as_ref().map_or("", ContentDigest::as_str),
            if enabled { "true" } else { "false" },
            confirmed_lock
                .resource_id()
                .map_err(|_| invalid())?
                .as_str(),
            &confirmed_at_unix_ms.to_string(),
            confirmation_digest.as_str(),
        ] {
            mutation_field(&mut canonical, value.as_bytes());
        }
        if canonical.len() > MAX_PROTECTIVE_LOCK_SETTING_BYTES {
            return Err(TransactionStoreError::CapacityExceeded);
        }
        let digest = digest_bytes(DOMAIN, &canonical);
        Ok(Self {
            owner,
            epoch,
            intent,
            request,
            previous,
            enabled,
            confirmed_lock,
            confirmed_at_unix_ms,
            confirmation_digest,
            canonical,
            digest,
        })
    }

    /// Bounded canonical decoding, not storage authentication or policy review.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransactionStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_PROTECTIVE_LOCK_SETTING_BYTES {
            return Err(invalid());
        }
        let mut rest = bytes;
        let mut field = || -> Result<&str, TransactionStoreError> {
            let (length, tail) = rest.split_at_checked(8).ok_or_else(invalid)?;
            let length = usize::try_from(u64::from_be_bytes(
                length.try_into().map_err(|_| invalid())?,
            ))
            .map_err(|_| invalid())?;
            if length > 256 {
                return Err(invalid());
            }
            let (value, tail) = tail.split_at_checked(length).ok_or_else(invalid)?;
            rest = tail;
            std::str::from_utf8(value).map_err(|_| invalid())
        };
        if field()? != DOMAIN {
            return Err(invalid());
        }
        let owner = PrincipalId::new(field()?).map_err(|_| invalid())?;
        let epoch = SessionEpoch::from_resource(&ResourceId::new(field()?).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        let intent = IntentId::new(field()?).map_err(|_| invalid())?;
        let request = RequestId::new(field()?).map_err(|_| invalid())?;
        let previous = match field()? {
            "" => None,
            value => Some(ContentDigest::new(value).map_err(|_| invalid())?),
        };
        let enabled = match field()? {
            "true" => true,
            "false" => false,
            _ => return Err(invalid()),
        };
        let lock = SessionLockId::from_resource(&ResourceId::new(field()?).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        let confirmed_at = field()?.parse().map_err(|_| invalid())?;
        let confirmation = ContentDigest::new(field()?).map_err(|_| invalid())?;
        if !rest.is_empty() {
            return Err(invalid());
        }
        let record = Self::new(
            owner,
            epoch,
            intent,
            request,
            previous,
            enabled,
            lock,
            confirmed_at,
            confirmation,
        )?;
        if record.canonical != bytes {
            return Err(invalid());
        }
        Ok(record)
    }

    #[must_use]
    pub const fn owner(&self) -> &PrincipalId {
        &self.owner
    }
    #[must_use]
    pub const fn epoch(&self) -> &SessionEpoch {
        &self.epoch
    }
    #[must_use]
    pub const fn intent(&self) -> &IntentId {
        &self.intent
    }
    #[must_use]
    pub const fn request(&self) -> &RequestId {
        &self.request
    }
    #[must_use]
    pub const fn previous(&self) -> Option<&ContentDigest> {
        self.previous.as_ref()
    }
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
    #[must_use]
    pub const fn confirmed_lock(&self) -> &SessionLockId {
        &self.confirmed_lock
    }
    #[must_use]
    pub const fn confirmed_at_unix_ms(&self) -> u64 {
        self.confirmed_at_unix_ms
    }
    #[must_use]
    pub const fn confirmation_digest(&self) -> &ContentDigest {
        &self.confirmation_digest
    }
    #[must_use]
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }
    #[must_use]
    pub const fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

fn invalid() -> TransactionStoreError {
    TransactionStoreError::Corruption("protective-lock setting validation failed".into())
}

/// One signed, time-bounded configuration write, never an effect permit.
/// Persistence cannot mint this type; it only receives the verifier capability.
#[derive(Debug)]
pub struct ProtectiveLockSettingUpdate {
    record: ProtectiveLockSettingRecord,
    expires_at_unix_ms: u64,
    authority_tag: [u8; AUTHORITY_MUTATION_TAG_BYTES],
}

impl ProtectiveLockSettingUpdate {
    #[must_use]
    pub const fn record(&self) -> &ProtectiveLockSettingRecord {
        &self.record
    }
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
    /// Non-secret, exact-record authentication retained for provenance. This is
    /// not a bearer grant: writes are CAS/expiry-bound and effects still require
    /// fresh policy/current-state review and the full managed lifecycle.
    #[must_use]
    pub fn authentication_tag(&self) -> &[u8] {
        &self.authority_tag
    }
    fn canonical(&self) -> Vec<u8> {
        mutation_material(&self.record, self.expires_at_unix_ms)
    }
}

impl TransactionAuthoritySigner {
    /// The trusted composition root must give this signer only to Control,
    /// using a separately provisioned key for the local S17 policy store.
    /// Control calls this ONLY after exact purpose-bound native owner approval.
    pub fn authorize_protective_lock_setting(
        &self,
        record: ProtectiveLockSettingRecord,
        expires_at_unix_ms: u64,
    ) -> Result<ProtectiveLockSettingUpdate, TransactionValidationError> {
        let duration = expires_at_unix_ms
            .checked_sub(record.confirmed_at_unix_ms())
            .ok_or(TransactionValidationError::InvalidAuthorityMutation)?;
        if duration == 0 || duration > 2000 {
            return Err(TransactionValidationError::InvalidAuthorityMutation);
        }
        let mut update = ProtectiveLockSettingUpdate {
            record,
            expires_at_unix_ms,
            authority_tag: [0; AUTHORITY_MUTATION_TAG_BYTES],
        };
        update.authority_tag = authority_tag(&self.bytes, MUTATION_DOMAIN, &update.canonical())?;
        Ok(update)
    }
}

impl TransactionAuthorityVerifier {
    #[must_use]
    pub fn verify_protective_lock_setting(&self, update: &ProtectiveLockSettingUpdate) -> bool {
        self.verify_retained_protective_lock_setting(
            &update.record,
            update.expires_at_unix_ms,
            &update.authority_tag,
        )
    }

    /// Verify historical Control provenance without reconstructing a writable
    /// update. Its former deadline is not refreshed and cannot permit replay.
    #[must_use]
    pub fn verify_retained_protective_lock_setting(
        &self,
        record: &ProtectiveLockSettingRecord,
        expires_at_unix_ms: u64,
        tag: &[u8],
    ) -> bool {
        let Ok(tag): Result<&[u8; AUTHORITY_MUTATION_TAG_BYTES], _> = tag.try_into() else {
            return false;
        };
        if expires_at_unix_ms
            .checked_sub(record.confirmed_at_unix_ms())
            .is_none_or(|duration| duration == 0 || duration > 2000)
        {
            return false;
        }
        verify_authority_tag(
            &self.bytes,
            MUTATION_DOMAIN,
            &mutation_material(record, expires_at_unix_ms),
            tag,
        )
    }
}

fn mutation_material(record: &ProtectiveLockSettingRecord, expires_at_unix_ms: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    mutation_field(&mut bytes, record.canonical());
    mutation_field(&mut bytes, &expires_at_unix_ms.to_be_bytes());
    bytes
}

/// Append-only compare-and-swap policy state. An exact historic retry may return
/// its original receipt but MUST NOT replace current state or undo revocation.
/// Missing state means disabled, never implicit consent. Full database rollback
/// is outside record authentication and needs protected filesystem recovery.
pub trait ProtectiveLockSettingStore: Debug + Send {
    fn current(
        &self,
        owner: &PrincipalId,
        epoch: &SessionEpoch,
    ) -> Result<Option<ProtectiveLockSettingRecord>, TransactionStoreError>;
    fn request(
        &self,
        owner: &PrincipalId,
        request: &RequestId,
    ) -> Result<Option<ProtectiveLockSettingRecord>, TransactionStoreError>;
    fn apply(
        &mut self,
        update: &ProtectiveLockSettingUpdate,
    ) -> Result<ProtectiveLockSettingRecord, TransactionStoreError>;
    fn integrity_check(&self) -> Result<(), TransactionStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransactionAuthorityKey;
    use linura_core::{BootId, SecurityOwnerInvocationId};
    use std::fs::File;
    use std::io::Read;

    fn test_key_material() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
        let read = File::open("/dev/urandom")
            .and_then(|file| file.take(32).read_to_end(&mut bytes))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(read, 32);
        bytes
    }

    pub(crate) fn record() -> ProtectiveLockSettingRecord {
        let epoch = SessionEpoch::new(
            BootId::new("abcd1234-1234-4567-89ab-0123456789ab")
                .unwrap_or_else(|e| unreachable!("{e}")),
            1000,
            "c2",
            42,
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        let lock = SessionLockId::new(
            epoch.clone(),
            SecurityOwnerInvocationId::new("98765432-1234-4567-89ab-0123456789ab")
                .unwrap_or_else(|e| unreachable!("{e}")),
            7,
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        ProtectiveLockSettingRecord::new(
            PrincipalId::new("unix:uid:1000").unwrap_or_else(|e| unreachable!("{e}")),
            epoch,
            IntentId::new("intent:s17:protective-lock:test")
                .unwrap_or_else(|e| unreachable!("{e}")),
            RequestId::new("request:s17:protective-lock:test")
                .unwrap_or_else(|e| unreachable!("{e}")),
            None,
            true,
            lock,
            1000,
            digest_bytes("test", b"purpose-bound native confirmation"),
        )
        .unwrap_or_else(|e| unreachable!("{e}"))
    }

    #[test]
    fn canonical_decoding_rejects_truncation_trailing_bytes_and_unbounded_fields() {
        let record = record();
        assert_eq!(
            ProtectiveLockSettingRecord::decode(record.canonical()),
            Ok(record.clone())
        );
        for end in 0..record.canonical().len() {
            assert!(ProtectiveLockSettingRecord::decode(&record.canonical()[..end]).is_err());
        }
        let mut bytes = record.canonical().to_vec();
        bytes.push(0);
        assert!(ProtectiveLockSettingRecord::decode(&bytes).is_err());
        let mut bytes = record.canonical().to_vec();
        bytes[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(ProtectiveLockSettingRecord::decode(&bytes).is_err());
        assert!(
            ProtectiveLockSettingRecord::decode(&vec![0; MAX_PROTECTIVE_LOCK_SETTING_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn update_requires_the_separate_control_signer_and_exclusive_bounded_deadline() {
        let (signer, verifier) = TransactionAuthorityKey::new(test_key_material())
            .unwrap_or_else(|e| unreachable!("{e}"))
            .split();
        let (_, wrong) = TransactionAuthorityKey::new(test_key_material())
            .unwrap_or_else(|e| unreachable!("{e}"))
            .split();
        for expiry in [0, 999, 1000, 3001, u64::MAX] {
            assert!(
                signer
                    .authorize_protective_lock_setting(record(), expiry)
                    .is_err()
            );
        }
        let mut update = signer
            .authorize_protective_lock_setting(record(), 3000)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(verifier.verify_protective_lock_setting(&update));
        assert!(!wrong.verify_protective_lock_setting(&update));
        update.record.enabled = false;
        // Even internal field corruption cannot pass merely by retaining bytes.
        update.record.canonical = vec![1];
        assert!(!verifier.verify_protective_lock_setting(&update));
    }
}
