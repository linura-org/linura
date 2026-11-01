//! S22-5: conservative local history policy, before native ingestion.
//!
//! No native clipboard monitor, key store or encrypted database is qualified.
//! The default is disabled, enable requests are rejected, and no payload bytes
//! are persisted or retained by these policy helpers.

const MAX_REVISION: u64 = u64::MAX - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryPolicyError {
    InvalidOwner,
    StaleRevision,
    UnqualifiedProtectedSource,
    NoProtectedKeyCustody,
    RevisionExhausted,
}

/// No user content lives in this struct; never expose it as proof that a
/// history writer, encryption backend or independent consent exists.
pub struct HistoryPolicy {
    owner_uid: u32,
    session_id: String,
    seat_id: String,
    revision: u64,
    enabled: bool,
}

impl HistoryPolicy {
    pub fn new(
        owner_uid: u32,
        session_id: String,
        seat_id: String,
    ) -> Result<Self, HistoryPolicyError> {
        if owner_uid == 0 || session_id.is_empty() || seat_id.is_empty() {
            return Err(HistoryPolicyError::InvalidOwner);
        }
        Ok(Self {
            owner_uid,
            session_id,
            seat_id,
            revision: 1,
            enabled: false,
        })
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Always fail closed until a Control-authenticated opt-in transaction,
    /// native source-exclusion oracle and reviewed encryption-key lifecycle
    /// exist. In particular, this is *not* a plaintext-history fallback.
    pub fn request_persistent_enable(
        &self,
        principal_uid: u32,
        session_id: &str,
        seat_id: &str,
        expected_revision: u64,
    ) -> Result<(), HistoryPolicyError> {
        self.require_scope(principal_uid, session_id, seat_id, expected_revision)?;
        Err(HistoryPolicyError::NoProtectedKeyCustody)
    }

    /// Reject unqualified source ingestion unconditionally. Even an
    /// authenticated ordinary clipboard offer may originate in a password
    /// manager, secure prompt, or foreign-seat selection.
    pub fn request_offer_ingest(
        &self,
        principal_uid: u32,
        session_id: &str,
        seat_id: &str,
        expected_revision: u64,
    ) -> Result<(), HistoryPolicyError> {
        self.require_scope(principal_uid, session_id, seat_id, expected_revision)?;
        Err(HistoryPolicyError::UnqualifiedProtectedSource)
    }

    pub fn revoke(
        &mut self,
        principal_uid: u32,
        session_id: &str,
        seat_id: &str,
        expected_revision: u64,
    ) -> Result<u64, HistoryPolicyError> {
        self.require_scope(principal_uid, session_id, seat_id, expected_revision)?;
        if self.revision >= MAX_REVISION {
            return Err(HistoryPolicyError::RevisionExhausted);
        }
        self.enabled = false;
        self.revision += 1;
        Ok(self.revision)
    }

    fn require_scope(
        &self,
        principal_uid: u32,
        session_id: &str,
        seat_id: &str,
        expected_revision: u64,
    ) -> Result<(), HistoryPolicyError> {
        if principal_uid != self.owner_uid
            || session_id != self.session_id
            || seat_id != self.seat_id
        {
            return Err(HistoryPolicyError::InvalidOwner);
        }
        if expected_revision != self.revision {
            return Err(HistoryPolicyError::StaleRevision);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_is_off_and_cannot_enable_without_key_custody() {
        let policy = HistoryPolicy::new(1000, "2".into(), "seat0".into()).unwrap();
        assert!(!policy.enabled());
        assert_eq!(
            policy.request_persistent_enable(1000, "2", "seat0", 1),
            Err(HistoryPolicyError::NoProtectedKeyCustody)
        );
        assert_eq!(
            policy.request_offer_ingest(1000, "2", "seat0", 1),
            Err(HistoryPolicyError::UnqualifiedProtectedSource)
        );
    }

    #[test]
    fn revision_and_cross_seat_replay_are_denied() {
        let mut policy = HistoryPolicy::new(1000, "2".into(), "seat0".into()).unwrap();
        assert_eq!(
            policy.revoke(1001, "2", "seat0", 1),
            Err(HistoryPolicyError::InvalidOwner)
        );
        assert_eq!(
            policy.revoke(1000, "2", "seat1", 1),
            Err(HistoryPolicyError::InvalidOwner)
        );
        assert_eq!(policy.revoke(1000, "2", "seat0", 1), Ok(2));
        assert_eq!(
            policy.revoke(1000, "2", "seat0", 1),
            Err(HistoryPolicyError::StaleRevision)
        );
        assert!(!policy.enabled());
    }
}
