//! Restart-readable request material, never an approval or dispatch credential.

use std::fmt::{Debug, Formatter};

use linura_core::{PrincipalId, RequestId};
use sha2::{Digest, Sha256};

use crate::{ContentDigest, TransactionStoreError};

pub const MAX_RETAINED_REQUEST_BYTES: usize = 256 * 1024;
pub const RETAINED_REQUEST_FORMAT: u32 = 1;

/// Opaque, bounded canonical structured request supplied by trusted Control.
/// The payload contains no reusable approval, executor handle or secret.
/// Persistence authenticates its principal/identity and bytes; only Control
/// interprets the format and joins it to a validated transaction recovery anchor.
#[derive(Clone, Eq, PartialEq)]
pub struct RetainedRequest {
    principal: PrincipalId,
    request_id: RequestId,
    canonical: Vec<u8>,
    digest: ContentDigest,
}

impl Debug for RetainedRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedRequest")
            .field("principal", &self.principal)
            .field("request_id", &self.request_id)
            .field("digest", &self.digest)
            .field("bytes", &self.canonical.len())
            .finish_non_exhaustive()
    }
}

impl RetainedRequest {
    pub fn new(
        principal: PrincipalId,
        request_id: RequestId,
        canonical: Vec<u8>,
    ) -> Result<Self, TransactionStoreError> {
        if canonical.is_empty() || canonical.len() > MAX_RETAINED_REQUEST_BYTES {
            return Err(TransactionStoreError::CapacityExceeded);
        }
        // Control's format already includes its length-framed domain. Do not
        // apply another digest domain or substitute a persistence-owned digest.
        let hash_hex = hex::encode(Sha256::digest(&canonical));
        let digest = ContentDigest::new(format!("sha256:{hash_hex}"))
            .map_err(|_| TransactionStoreError::AuthorityRejected)?;
        Ok(Self {
            principal,
            request_id,
            canonical,
            digest,
        })
    }

    #[must_use]
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    #[must_use]
    pub fn canonical(&self) -> &[u8] {
        &self.canonical
    }

    #[must_use]
    pub fn digest(&self) -> &ContentDigest {
        &self.digest
    }
}

/// Write-once retention. Identical retries are idempotent; identity reuse with
/// different bytes is rejected. A successful retain precedes durable prepare.
/// An orphan record after a failed prepare grants no authority. Missing or
/// corrupt material on recovery fails closed and can never authorize replay.
pub trait ApprovedRequestJournal: Debug + Send {
    fn retain(&mut self, request: &RetainedRequest) -> Result<(), TransactionStoreError>;
    fn load(
        &self,
        principal: &PrincipalId,
        request_id: &RequestId,
    ) -> Result<RetainedRequest, TransactionStoreError>;
    fn integrity_check(&self) -> Result<(), TransactionStoreError>;
}
