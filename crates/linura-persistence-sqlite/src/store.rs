use std::fmt::{Debug, Formatter};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use linura_transaction::{
    AbortRequest, AuthorityBinding, CommitRequest, ContentDigest, HandoffCommit, HandoffRequest,
    MAX_TRANSACTION_GENERATIONS, PrepareOutcome, RecoveryAnchor, RecoveryOutcome, RecoveryRequest,
    RecoveryResolution, TransactionAuthorityVerifier, TransactionId, TransactionSnapshot,
    TransactionState, TransactionStore, TransactionStoreError, VerifiedCommitMaterial, digest_parts,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::filesystem_reserve::release_preopen_recovery_headroom;
use crate::integrity::SqliteIntegrityKey;
use crate::schema::{APPLICATION_ID, MAX_AUDIT_EVENT_KIND_BYTES, SCHEMA_VERSION};
use crate::validation::{
    StoredAuditEvent, StoredGeneration, StoredTransaction, as_i64, audit_digest, audit_tag,
    check_count_capacity, check_logical_audit_reserve, configure_connection, generation_tag,
    initialize_or_validate_schema, list_transaction_ids, load_current, load_last_audit_event,
    pragma_i64, pragma_string, reservation_bytes, sqlite, transaction_tag,
    validate_aggregate_capacity, validate_audit_chain, validate_generation_history,
    validate_logical_audit_reserve, validate_physical_reservations_locked, validate_runtime_settings,
    validate_schema_identity, with_immediate_validation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreLimits {
    pub max_transactions: u64,
    pub max_generations: u64,
    pub max_audit_events: u64,
    pub max_pages: u64,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            max_transactions: 4_096,
            max_generations: 16_384,
            max_audit_events: 131_072,
            max_pages: 262_144,
        }
    }
}

impl StoreLimits {
    fn validate(self) -> Result<Self, TransactionStoreError> {
        if self.max_transactions == 0
            || self.max_generations == 0
            || self.max_audit_events == 0
            || self.max_pages == 0
        {
            return Err(TransactionStoreError::CapacityExceeded);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteSettings {
    pub journal_mode: String,
    pub synchronous: i64,
    pub foreign_keys: i64,
    pub trusted_schema: i64,
    pub application_id: i64,
    pub user_version: i64,
    pub max_page_count: i64,
}

pub struct SqliteTransactionStore {
    pub(crate) connection: Connection,
    limits: StoreLimits,
    authority_verifier: TransactionAuthorityVerifier,
    integrity_key: SqliteIntegrityKey,
    opener_released_for_terminal_recovery: bool,
}

impl Debug for SqliteTransactionStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteTransactionStore")
            .field("limits", &self.limits)
            .field("integrity_key", &self.integrity_key)
            .finish_non_exhaustive()
    }
}

impl SqliteTransactionStore {
    /// Open an authority database with both semantic-mutation verification and
    /// independent durable-record authentication.
    ///
    /// The integrity key is an externally provisioned, non-zero 256-bit secret
    /// distinct from Control's transaction signer. The same protected value
    /// must be provided on restart.
    pub fn open(
        path: impl AsRef<Path>,
        authority_verifier: TransactionAuthorityVerifier,
        integrity_key: SqliteIntegrityKey,
    ) -> Result<Self, TransactionStoreError> {
        Self::open_with_limits_mode(
            path.as_ref(),
            StoreLimits::default(),
            authority_verifier,
            integrity_key,
            false,
        )
    }

    /// Open an existing authority database specifically to retire a Prepared
    /// transaction while the backing filesystem may already be at ENOSPC.
    pub fn open_for_terminal_recovery(
        path: impl AsRef<Path>,
        authority_verifier: TransactionAuthorityVerifier,
        integrity_key: SqliteIntegrityKey,
    ) -> Result<Self, TransactionStoreError> {
        Self::open_for_terminal_recovery_with_limits(
            path,
            StoreLimits::default(),
            authority_verifier,
            integrity_key,
        )
    }

    /// Terminal-recovery open preserving the caller's capacity contract.
    pub fn open_for_terminal_recovery_with_limits(
        path: impl AsRef<Path>,
        limits: StoreLimits,
        authority_verifier: TransactionAuthorityVerifier,
        integrity_key: SqliteIntegrityKey,
    ) -> Result<Self, TransactionStoreError> {
        Self::open_with_limits_mode(
            path.as_ref(),
            limits,
            authority_verifier,
            integrity_key,
            true,
        )
    }

    pub fn open_with_limits(
        path: impl AsRef<Path>,
        limits: StoreLimits,
        authority_verifier: TransactionAuthorityVerifier,
        integrity_key: SqliteIntegrityKey,
    ) -> Result<Self, TransactionStoreError> {
        Self::open_with_limits_mode(path.as_ref(), limits, authority_verifier, integrity_key, false)
    }

    fn open_with_limits_mode(
        path: &Path,
        limits: StoreLimits,
        authority_verifier: TransactionAuthorityVerifier,
        integrity_key: SqliteIntegrityKey,
        terminal_recovery: bool,
    ) -> Result<Self, TransactionStoreError> {
        let limits = limits.validate()?;
        let opener_released_for_terminal_recovery = if terminal_recovery {
            if !release_preopen_recovery_headroom(path)? {
                return Err(TransactionStoreError::StateConflict);
            }
            true
        } else {
            false
        };
        let mut connection = Connection::open(path).map_err(sqlite)?;
        configure_connection(&connection, limits)?;
        let authority_fingerprint = authority_verifier.fingerprint();
        let integrity_fingerprint = integrity_key.fingerprint();
        initialize_or_validate_schema(&mut connection, &authority_fingerprint, &integrity_fingerprint)?;
        let store = Self {
            connection,
            limits,
            authority_verifier,
            integrity_key,
            opener_released_for_terminal_recovery,
        };
        store.integrity_check()?;
        Ok(store)
    }

    pub fn settings(&self) -> Result<SqliteSettings, TransactionStoreError> {
        Ok(SqliteSettings {
            journal_mode: pragma_string(&self.connection, "journal_mode")?,
            synchronous: pragma_i64(&self.connection, "synchronous")?,
            foreign_keys: pragma_i64(&self.connection, "foreign_keys")?,
            trusted_schema: pragma_i64(&self.connection, "trusted_schema")?,
            application_id: pragma_i64(&self.connection, "application_id")?,
            user_version: pragma_i64(&self.connection, "user_version")?,
            max_page_count: pragma_i64(&self.connection, "max_page_count")?,
        })
    }

    fn require_normal_open(&self) -> Result<(), TransactionStoreError> {
        if self.opener_released_for_terminal_recovery {
            return Err(TransactionStoreError::StateConflict);
        }
        Ok(())
    }

    fn reconcile_filesystem_reserve_after_commit(&self) -> Result<(), TransactionStoreError> {
        // Filesystem reserve shrink is intentionally outside the SQLite
        // transaction. The final reservation's full reserve is kept until
        // SQLite commit succeeds, then reconciled against authenticated durable
        // reservation rows under the same write-serialization boundary used by
        // open-time integrity validation. A crash after commit but before this
        // cleanup is safe: the next open only needs to shrink provably excess
        // sidecar allocation and never needs new disk blocks.
        with_immediate_validation(&self.connection, || {
            validate_physical_reservations_locked(
                &self.connection,
                &self.integrity_key,
                false,
            )
        })
    }

    fn assert_expected(
        snapshot: &TransactionSnapshot,
        expected_generation: u64,
        expected_state_version: u64,
        expected_binding_digest: &ContentDigest,
        expected_state: TransactionState,
    ) -> Result<(), TransactionStoreError> {
        if snapshot.current_generation != expected_generation
            || snapshot.state_version != expected_state_version
            || snapshot.binding_digest != *expected_binding_digest
            || snapshot.state != expected_state
        {
            return Err(TransactionStoreError::StateConflict);
        }
        Ok(())
    }

    fn ensure_audit_reservations(
        transaction: &Transaction<'_>,
        transaction_id: &TransactionId,
        required: u64,
    ) -> Result<(), TransactionStoreError> {
        let reserve_bytes = reservation_bytes(transaction)?;
        let mut statement = transaction
            .prepare(
                "SELECT slot, length(reserved) FROM audit_reservations
                 WHERE transaction_id = ?1 ORDER BY slot",
            )
            .map_err(sqlite)?;
        let rows = statement
            .query_map(params![transaction_id.as_str()], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(sqlite)?;
        let mut existing = 0_u64;
        for row in rows {
            let (slot, length) = row.map_err(sqlite)?;
            if u64::try_from(slot).ok() != Some(existing)
                || u64::try_from(length).ok() != Some(reserve_bytes)
            {
                return Err(TransactionStoreError::Corruption(
                    "physical audit reservation is malformed".into(),
                ));
            }
            existing = existing
                .checked_add(1)
                .ok_or(TransactionStoreError::CapacityExceeded)?;
        }
        drop(statement);
        if existing > required {
            return Err(TransactionStoreError::Corruption(
                "physical audit reservation count exceeds transition requirement".into(),
            ));
        }
        for slot in existing..required {
            transaction
                .execute(
                    "INSERT INTO audit_reservations (transaction_id, slot, reserved)
                     VALUES (?1, ?2, zeroblob(?3))",
                    params![
                        transaction_id.as_str(),
                        as_i64(slot)?,
                        as_i64(reserve_bytes)?,
                    ],
                )
                .map_err(sqlite)?;
        }
        Ok(())
    }

    fn consume_audit_reservation(
        transaction: &Transaction<'_>,
        transaction_id: &TransactionId,
    ) -> Result<(), TransactionStoreError> {
        let reserve_bytes = reservation_bytes(transaction)?;
        let reservation: Option<(i64, i64)> = transaction
            .query_row(
                "SELECT slot, length(reserved) FROM audit_reservations
                 WHERE transaction_id = ?1 ORDER BY slot DESC LIMIT 1",
                params![transaction_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite)?;
        let (slot, length) = reservation.ok_or_else(|| {
            TransactionStoreError::Corruption(
                "required physical audit reservation is missing".into(),
            )
        })?;
        if u64::try_from(length).ok() != Some(reserve_bytes) {
            return Err(TransactionStoreError::Corruption(
                "physical audit reservation byte length is invalid".into(),
            ));
        }
        let deleted = transaction
            .execute(
                "DELETE FROM audit_reservations WHERE transaction_id = ?1 AND slot = ?2",
                params![transaction_id.as_str(), slot],
            )
            .map_err(sqlite)?;
        if deleted != 1 {
            return Err(TransactionStoreError::Corruption(
                "physical audit reservation could not be consumed".into(),
            ));
        }
        Ok(())
    }

    fn append_audit(
        transaction: &Transaction<'_>,
        limits: StoreLimits,
        integrity_key: &SqliteIntegrityKey,
        transaction_id: &TransactionId,
        generation: u64,
        state_version: u64,
        event_kind: &str,
        payload_digest: &ContentDigest,
        consume_reservation: bool,
    ) -> Result<ContentDigest, TransactionStoreError> {
        if event_kind.is_empty() || event_kind.len() > MAX_AUDIT_EVENT_KIND_BYTES {
            return Err(TransactionStoreError::Corruption(
                "internal audit event kind exceeds persisted byte bound".into(),
            ));
        }
        check_count_capacity(transaction, "audit_events", limits.max_audit_events, 1)?;
        let previous = load_last_audit_event(transaction, integrity_key, transaction_id)?;
        let (sequence, previous_digest) = match previous {
            Some(previous) => {
                let digest = ContentDigest::new(previous.event_digest)
                    .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
                (
                    previous
                        .event_sequence
                        .checked_add(1)
                        .ok_or(TransactionStoreError::CapacityExceeded)?,
                    digest,
                )
            }
            None => (0, ContentDigest::zero()),
        };
        if consume_reservation {
            Self::consume_audit_reservation(transaction, transaction_id)?;
        }
        let event_digest = audit_digest(
            transaction_id,
            sequence,
            generation,
            state_version,
            event_kind,
            payload_digest,
            &previous_digest,
        );
        let mut record = StoredAuditEvent {
            transaction_id: transaction_id.as_str().to_owned(),
            event_sequence: sequence,
            generation,
            state_version,
            event_kind: event_kind.to_owned(),
            payload_digest: payload_digest.as_str().to_owned(),
            previous_digest: previous_digest.as_str().to_owned(),
            event_digest: event_digest.as_str().to_owned(),
            integrity_tag: Vec::new(),
        };
        record.integrity_tag = audit_tag(integrity_key, &record)?;
        transaction
            .execute(
                "INSERT INTO audit_events (
                    transaction_id, event_sequence, generation, state_version,
                    event_kind, payload_digest, previous_digest, event_digest, integrity_tag
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    record.transaction_id,
                    as_i64(record.event_sequence)?,
                    as_i64(record.generation)?,
                    as_i64(record.state_version)?,
                    record.event_kind,
                    record.payload_digest,
                    record.previous_digest,
                    record.event_digest,
                    record.integrity_tag,
                ],
            )
            .map_err(sqlite)?;
        Ok(event_digest)
    }

    fn update_transaction_pointer(
        transaction: &Transaction<'_>,
        integrity_key: &SqliteIntegrityKey,
        record: &StoredTransaction,
        next_generation: u64,
        next_version: u64,
    ) -> Result<StoredTransaction, TransactionStoreError> {
        let mut next = record.clone();
        next.current_generation = next_generation;
        next.state_version = next_version;
        next.integrity_tag = transaction_tag(integrity_key, &next)?;
        let updated = transaction
            .execute(
                "UPDATE transactions
                 SET current_generation = ?4, state_version = ?5, integrity_tag = ?6
                 WHERE transaction_id = ?1 AND current_generation = ?2 AND state_version = ?3
                   AND integrity_tag = ?7",
                params![
                    record.transaction_id,
                    as_i64(record.current_generation)?,
                    as_i64(record.state_version)?,
                    as_i64(next_generation)?,
                    as_i64(next_version)?,
                    next.integrity_tag,
                    record.integrity_tag,
                ],
            )
            .map_err(sqlite)?;
        if updated != 1 {
            return Err(TransactionStoreError::StateConflict);
        }
        Ok(next)
    }

    fn update_generation_state(
        transaction: &Transaction<'_>,
        integrity_key: &SqliteIntegrityKey,
        record: &StoredGeneration,
        expected_state: TransactionState,
        next_state: TransactionState,
    ) -> Result<StoredGeneration, TransactionStoreError> {
        if record.state != expected_state.as_str() {
            return Err(TransactionStoreError::StateConflict);
        }
        let mut next = record.clone();
        next.state = next_state.as_str().to_owned();
        next.integrity_tag = generation_tag(integrity_key, &next)?;
        let updated = transaction
            .execute(
                "UPDATE generations SET state = ?4, integrity_tag = ?5
                 WHERE transaction_id = ?1 AND generation = ?2 AND state = ?3
                   AND integrity_tag = ?6",
                params![
                    record.transaction_id,
                    as_i64(record.generation)?,
                    expected_state.as_str(),
                    next_state.as_str(),
                    next.integrity_tag,
                    record.integrity_tag,
                ],
            )
            .map_err(sqlite)?;
        if updated != 1 {
            return Err(TransactionStoreError::StateConflict);
        }
        Ok(next)
    }

    fn update_generation_to_verified(
        transaction: &Transaction<'_>,
        integrity_key: &SqliteIntegrityKey,
        record: &StoredGeneration,
        desired_state_digest: &ContentDigest,
        graph_digest: &ContentDigest,
        provenance_digest: &ContentDigest,
    ) -> Result<StoredGeneration, TransactionStoreError> {
        if record.state != TransactionState::Indeterminate.as_str()
            || record.desired_state_digest.is_some()
            || record.graph_digest.is_some()
            || record.provenance_digest.is_some()
        {
            return Err(TransactionStoreError::StateConflict);
        }
        let mut next = record.clone();
        next.state = TransactionState::Verified.as_str().to_owned();
        next.desired_state_digest = Some(desired_state_digest.as_str().to_owned());
        next.graph_digest = Some(graph_digest.as_str().to_owned());
        next.provenance_digest = Some(provenance_digest.as_str().to_owned());
        next.integrity_tag = generation_tag(integrity_key, &next)?;
        let updated = transaction
            .execute(
                "UPDATE generations
                 SET state = 'verified', desired_state_digest = ?3, graph_digest = ?4,
                     provenance_digest = ?5, integrity_tag = ?6
                 WHERE transaction_id = ?1 AND generation = ?2 AND state = 'indeterminate'
                   AND integrity_tag = ?7",
                params![
                    record.transaction_id,
                    as_i64(record.generation)?,
                    desired_state_digest.as_str(),
                    graph_digest.as_str(),
                    provenance_digest.as_str(),
                    next.integrity_tag,
                    record.integrity_tag,
                ],
            )
            .map_err(sqlite)?;
        if updated != 1 {
            return Err(TransactionStoreError::StateConflict);
        }
        Ok(next)
    }

    fn insert_generation(
        transaction: &Transaction<'_>,
        integrity_key: &SqliteIntegrityKey,
        binding: &AuthorityBinding,
        generation: u64,
    ) -> Result<StoredGeneration, TransactionStoreError> {
        let transaction_id = binding.transaction_id();
        let mut record = StoredGeneration {
            transaction_id: transaction_id.as_str().to_owned(),
            generation,
            state: TransactionState::Prepared.as_str().to_owned(),
            binding_digest: binding.digest().as_str().to_owned(),
            binding_canonical: binding.canonical_bytes().to_vec(),
            request_digest: binding.request_digest().as_str().to_owned(),
            precondition_digest: binding.precondition_digest().as_str().to_owned(),
            observation_digest: binding.observation_digest().as_str().to_owned(),
            desired_state_digest: None,
            graph_digest: None,
            provenance_digest: None,
            integrity_tag: Vec::new(),
        };
        record.integrity_tag = generation_tag(integrity_key, &record)?;
        transaction
            .execute(
                "INSERT INTO generations (
                    transaction_id, generation, state, binding_digest, binding_canonical,
                    request_digest, precondition_digest, observation_digest,
                    desired_state_digest, graph_digest, provenance_digest, integrity_tag
                 ) VALUES (?1, ?2, 'prepared', ?3, ?4, ?5, ?6, ?7, NULL, NULL, NULL, ?8)",
                params![
                    record.transaction_id,
                    as_i64(generation)?,
                    record.binding_digest,
                    record.binding_canonical,
                    record.request_digest,
                    record.precondition_digest,
                    record.observation_digest,
                    record.integrity_tag,
                ],
            )
            .map_err(sqlite)?;
        Ok(record)
    }
}

impl TransactionStore for SqliteTransactionStore {
    fn prepare(
        &mut self,
        binding: &AuthorityBinding,
    ) -> Result<PrepareOutcome, TransactionStoreError> {
        self.require_normal_open()?;
        let transaction_id = binding.transaction_id();
        let limits = self.limits;
        let integrity_key = &self.integrity_key;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite)?;
        match load_current(&transaction, integrity_key, &transaction_id) {
            Ok((_, _, snapshot)) => {
                if snapshot.state == TransactionState::Prepared
                    && snapshot.binding_digest == *binding.digest()
                    && snapshot.principal == *binding.principal()
                    && snapshot.request_id == *binding.request_id()
                {
                    transaction.commit().map_err(sqlite)?;
                    return Ok(PrepareOutcome::Existing(snapshot));
                }
                return Err(TransactionStoreError::IdempotencyConflict);
            }
            Err(TransactionStoreError::NotFound) => {}
            Err(error) => return Err(error),
        }
        check_count_capacity(&transaction, "transactions", limits.max_transactions, 1)?;
        check_count_capacity(&transaction, "generations", limits.max_generations, 1)?;
        check_logical_audit_reserve(&transaction, limits, 1, 1)?;

        let mut transaction_record = StoredTransaction {
            transaction_id: transaction_id.as_str().to_owned(),
            principal: binding.principal().as_str().to_owned(),
            request_id: binding.request_id().as_str().to_owned(),
            current_generation: 0,
            state_version: 1,
            integrity_tag: Vec::new(),
        };
        transaction_record.integrity_tag = transaction_tag(integrity_key, &transaction_record)?;
        transaction
            .execute(
                "INSERT INTO transactions (
                    transaction_id, principal, request_id, current_generation, state_version, integrity_tag
                 ) VALUES (?1, ?2, ?3, 0, 1, ?4)",
                params![
                    transaction_record.transaction_id,
                    transaction_record.principal,
                    transaction_record.request_id,
                    transaction_record.integrity_tag,
                ],
            )
            .map_err(sqlite)?;
        Self::insert_generation(&transaction, integrity_key, binding, 0)?;
        Self::append_audit(
            &transaction,
            limits,
            integrity_key,
            &transaction_id,
            0,
            1,
            "prepared",
            binding.digest(),
            false,
        )?;
        Self::ensure_audit_reservations(&transaction, &transaction_id, 1)?;
        transaction.commit().map_err(sqlite)?;
        Ok(PrepareOutcome::Created(TransactionSnapshot {
            transaction_id,
            principal: binding.principal().clone(),
            request_id: binding.request_id().clone(),
            current_generation: 0,
            state_version: 1,
            state: TransactionState::Prepared,
            binding_digest: binding.digest().clone(),
        }))
    }

    fn handoff(
        &mut self,
        request: &HandoffRequest,
    ) -> Result<HandoffCommit, TransactionStoreError> {
        self.require_normal_open()?;
        if !self.authority_verifier.verify_handoff(request) {
            return Err(TransactionStoreError::AuthorityRejected);
        }
        let limits = self.limits;
        let integrity_key = &self.integrity_key;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite)?;
        enforce_authority_window(
            request.authorized_at_unix_ms(),
            request.expires_at_unix_ms(),
        )?;
        let (transaction_record, generation_record, snapshot) =
            load_current(&transaction, integrity_key, request.transaction_id())?;
        Self::assert_expected(
            &snapshot,
            request.expected_generation(),
            request.expected_state_version(),
            request.expected_binding_digest(),
            TransactionState::Prepared,
        )?;
        if request.authority_use_digest() == &ContentDigest::zero() {
            return Err(TransactionStoreError::StateConflict);
        }
        check_logical_audit_reserve(&transaction, limits, 1, 0)?;
        Self::ensure_audit_reservations(&transaction, request.transaction_id(), 2)?;
        let next_version = snapshot
            .state_version
            .checked_add(1)
            .ok_or(TransactionStoreError::CapacityExceeded)?;
        Self::update_generation_state(
            &transaction,
            integrity_key,
            &generation_record,
            TransactionState::Prepared,
            TransactionState::Indeterminate,
        )?;
        Self::update_transaction_pointer(
            &transaction,
            integrity_key,
            &transaction_record,
            snapshot.current_generation,
            next_version,
        )?;
        Self::append_audit(
            &transaction,
            limits,
            integrity_key,
            request.transaction_id(),
            snapshot.current_generation,
            next_version,
            "handoff-indeterminate",
            request.authority_use_digest(),
            true,
        )?;
        transaction.commit().map_err(sqlite)?;
        self.reconcile_filesystem_reserve_after_commit()?;
        Ok(HandoffCommit {
            transaction_id: request.transaction_id().clone(),
            generation: snapshot.current_generation,
            state_version: next_version,
            binding_digest: snapshot.binding_digest,
            authority_use_digest: request.authority_use_digest().clone(),
        })
    }

    fn recover(
        &mut self,
        request: &RecoveryRequest,
    ) -> Result<RecoveryOutcome, TransactionStoreError> {
        self.require_normal_open()?;
        if !self.authority_verifier.verify_recovery(request) {
            return Err(TransactionStoreError::AuthorityRejected);
        }
        let limits = self.limits;
        let integrity_key = &self.integrity_key;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite)?;
        enforce_authority_window(
            request.authorized_at_unix_ms(),
            request.expires_at_unix_ms(),
        )?;
        let (transaction_record, generation_record, snapshot) =
            load_current(&transaction, integrity_key, request.transaction_id())?;
        Self::assert_expected(
            &snapshot,
            request.expected_generation(),
            request.expected_state_version(),
            request.expected_binding_digest(),
            TransactionState::Indeterminate,
        )?;
        let next_version = snapshot
            .state_version
            .checked_add(1)
            .ok_or(TransactionStoreError::CapacityExceeded)?;

        let outcome = match request.resolution() {
            RecoveryResolution::IntendedStateVerified {
                observation_digest,
                desired_state_digest,
                graph_digest,
                provenance_digest,
            } => {
                check_logical_audit_reserve(&transaction, limits, 1, 0)?;
                Self::ensure_audit_reservations(&transaction, request.transaction_id(), 2)?;
                Self::update_generation_to_verified(
                    &transaction,
                    integrity_key,
                    &generation_record,
                    desired_state_digest,
                    graph_digest,
                    provenance_digest,
                )?;
                Self::update_transaction_pointer(
                    &transaction,
                    integrity_key,
                    &transaction_record,
                    snapshot.current_generation,
                    next_version,
                )?;
                Self::append_audit(
                    &transaction,
                    limits,
                    integrity_key,
                    request.transaction_id(),
                    snapshot.current_generation,
                    next_version,
                    "recovery-verified",
                    observation_digest,
                    true,
                )?;
                RecoveryOutcome::Verified(TransactionSnapshot {
                    state: TransactionState::Verified,
                    state_version: next_version,
                    ..snapshot.clone()
                })
            }
            RecoveryResolution::ConflictingState { observation_digest } => {
                check_logical_audit_reserve(&transaction, limits, 1, -1)?;
                Self::ensure_audit_reservations(&transaction, request.transaction_id(), 1)?;
                Self::update_generation_state(
                    &transaction,
                    integrity_key,
                    &generation_record,
                    TransactionState::Indeterminate,
                    TransactionState::RecoveryBlocked,
                )?;
                Self::update_transaction_pointer(
                    &transaction,
                    integrity_key,
                    &transaction_record,
                    snapshot.current_generation,
                    next_version,
                )?;
                Self::append_audit(
                    &transaction,
                    limits,
                    integrity_key,
                    request.transaction_id(),
                    snapshot.current_generation,
                    next_version,
                    "recovery-blocked",
                    observation_digest,
                    true,
                )?;
                RecoveryOutcome::Blocked(TransactionSnapshot {
                    state: TransactionState::RecoveryBlocked,
                    state_version: next_version,
                    ..snapshot.clone()
                })
            }
            RecoveryResolution::Ambiguous { observation_digest } => {
                check_logical_audit_reserve(&transaction, limits, 1, 0)?;
                Self::ensure_audit_reservations(&transaction, request.transaction_id(), 2)?;
                Self::update_transaction_pointer(
                    &transaction,
                    integrity_key,
                    &transaction_record,
                    snapshot.current_generation,
                    next_version,
                )?;
                Self::append_audit(
                    &transaction,
                    limits,
                    integrity_key,
                    request.transaction_id(),
                    snapshot.current_generation,
                    next_version,
                    "recovery-ambiguous",
                    observation_digest,
                    true,
                )?;
                RecoveryOutcome::StillIndeterminate(TransactionSnapshot {
                    state_version: next_version,
                    ..snapshot.clone()
                })
            }
            RecoveryResolution::IntendedEffectAbsent {
                observation_digest,
                next_binding,
            } => {
                if next_binding.transaction_id() != *request.transaction_id() {
                    return Err(TransactionStoreError::IdempotencyConflict);
                }
                let next_generation = snapshot
                    .current_generation
                    .checked_add(1)
                    .ok_or(TransactionStoreError::CapacityExceeded)?;
                if next_generation >= MAX_TRANSACTION_GENERATIONS {
                    return Err(TransactionStoreError::CapacityExceeded);
                }
                check_count_capacity(&transaction, "generations", limits.max_generations, 1)?;
                check_logical_audit_reserve(&transaction, limits, 2, 0)?;
                Self::ensure_audit_reservations(&transaction, request.transaction_id(), 3)?;
                Self::update_generation_state(
                    &transaction,
                    integrity_key,
                    &generation_record,
                    TransactionState::Indeterminate,
                    TransactionState::Aborted,
                )?;
                Self::insert_generation(&transaction, integrity_key, next_binding, next_generation)?;
                Self::update_transaction_pointer(
                    &transaction,
                    integrity_key,
                    &transaction_record,
                    next_generation,
                    next_version,
                )?;
                Self::append_audit(
                    &transaction,
                    limits,
                    integrity_key,
                    request.transaction_id(),
                    snapshot.current_generation,
                    next_version,
                    "recovery-retired-no-effect",
                    observation_digest,
                    true,
                )?;
                Self::append_audit(
                    &transaction,
                    limits,
                    integrity_key,
                    request.transaction_id(),
                    next_generation,
                    next_version,
                    "recovery-reprepared",
                    next_binding.digest(),
                    true,
                )?;
                RecoveryOutcome::Reprepared(TransactionSnapshot {
                    transaction_id: request.transaction_id().clone(),
                    principal: next_binding.principal().clone(),
                    request_id: next_binding.request_id().clone(),
                    current_generation: next_generation,
                    state_version: next_version,
                    state: TransactionState::Prepared,
                    binding_digest: next_binding.digest().clone(),
                })
            }
        };
        transaction.commit().map_err(sqlite)?;
        self.reconcile_filesystem_reserve_after_commit()?;
        Ok(outcome)
    }

    fn commit(
        &mut self,
        request: &CommitRequest,
    ) -> Result<TransactionSnapshot, TransactionStoreError> {
        self.require_normal_open()?;
        if !self.authority_verifier.verify_commit(request) {
            return Err(TransactionStoreError::AuthorityRejected);
        }
        let limits = self.limits;
        let integrity_key = &self.integrity_key;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite)?;
        let (transaction_record, generation_record, snapshot) =
            load_current(&transaction, integrity_key, request.transaction_id())?;
        Self::assert_expected(
            &snapshot,
            request.expected_generation(),
            request.expected_state_version(),
            request.expected_binding_digest(),
            TransactionState::Verified,
        )?;
        if generation_record.desired_state_digest.as_deref()
            != Some(request.desired_state_digest().as_str())
            || generation_record.graph_digest.as_deref() != Some(request.graph_digest().as_str())
            || generation_record.provenance_digest.as_deref()
                != Some(request.provenance_digest().as_str())
        {
            return Err(TransactionStoreError::StateConflict);
        }
        check_logical_audit_reserve(&transaction, limits, 1, -1)?;
        Self::ensure_audit_reservations(&transaction, request.transaction_id(), 1)?;
        let next_version = snapshot
            .state_version
            .checked_add(1)
            .ok_or(TransactionStoreError::CapacityExceeded)?;
        Self::update_generation_state(
            &transaction,
            integrity_key,
            &generation_record,
            TransactionState::Verified,
            TransactionState::Committed,
        )?;
        Self::update_transaction_pointer(
            &transaction,
            integrity_key,
            &transaction_record,
            snapshot.current_generation,
            next_version,
        )?;
        let payload = digest_parts(
            "linura.sqlite.commit-payload.v1",
            [
                request.desired_state_digest().as_str().as_bytes(),
                request.graph_digest().as_str().as_bytes(),
                request.provenance_digest().as_str().as_bytes(),
            ],
        );
        Self::append_audit(
            &transaction,
            limits,
            integrity_key,
            request.transaction_id(),
            snapshot.current_generation,
            next_version,
            "committed",
            &payload,
            true,
        )?;
        transaction.commit().map_err(sqlite)?;
        self.reconcile_filesystem_reserve_after_commit()?;
        Ok(TransactionSnapshot {
            state: TransactionState::Committed,
            state_version: next_version,
            ..snapshot
        })
    }

    fn abort_prepared(
        &mut self,
        request: &AbortRequest,
    ) -> Result<TransactionSnapshot, TransactionStoreError> {
        let limits = self.limits;
        let integrity_key = &self.integrity_key;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite)?;
        let (transaction_record, generation_record, snapshot) =
            load_current(&transaction, integrity_key, &request.transaction_id)?;
        if snapshot.current_generation != request.expected_generation
            || snapshot.state_version != request.expected_state_version
            || snapshot.state != TransactionState::Prepared
        {
            return Err(TransactionStoreError::StateConflict);
        }
        check_logical_audit_reserve(&transaction, limits, 1, -1)?;
        Self::ensure_audit_reservations(&transaction, &request.transaction_id, 1)?;
        let next_version = snapshot
            .state_version
            .checked_add(1)
            .ok_or(TransactionStoreError::CapacityExceeded)?;
        Self::update_generation_state(
            &transaction,
            integrity_key,
            &generation_record,
            TransactionState::Prepared,
            TransactionState::Aborted,
        )?;
        Self::update_transaction_pointer(
            &transaction,
            integrity_key,
            &transaction_record,
            snapshot.current_generation,
            next_version,
        )?;
        Self::append_audit(
            &transaction,
            limits,
            integrity_key,
            &request.transaction_id,
            snapshot.current_generation,
            next_version,
            "aborted-prepared",
            &request.reason_digest,
            true,
        )?;
        transaction.commit().map_err(sqlite)?;
        self.reconcile_filesystem_reserve_after_commit()?;
        self.opener_released_for_terminal_recovery = false;
        Ok(TransactionSnapshot {
            state: TransactionState::Aborted,
            state_version: next_version,
            ..snapshot
        })
    }

    fn snapshot(
        &self,
        transaction_id: &TransactionId,
    ) -> Result<TransactionSnapshot, TransactionStoreError> {
        load_current(&self.connection, &self.integrity_key, transaction_id)
            .map(|(_, _, snapshot)| snapshot)
    }

    fn recovery_anchor(
        &self,
        transaction_id: &TransactionId,
    ) -> Result<RecoveryAnchor, TransactionStoreError> {
        let (_, generation, snapshot) =
            load_current(&self.connection, &self.integrity_key, transaction_id)?;
        Ok(RecoveryAnchor {
            snapshot,
            request_digest: ContentDigest::new(generation.request_digest)
                .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?,
            precondition_digest: ContentDigest::new(generation.precondition_digest)
                .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?,
        })
    }

    fn verified_commit_material(
        &self,
        transaction_id: &TransactionId,
    ) -> Result<VerifiedCommitMaterial, TransactionStoreError> {
        let (_, generation, snapshot) =
            load_current(&self.connection, &self.integrity_key, transaction_id)?;
        if snapshot.state != TransactionState::Verified {
            return Err(TransactionStoreError::StateConflict);
        }
        Ok(VerifiedCommitMaterial {
            snapshot,
            desired_state_digest: ContentDigest::new(generation.desired_state_digest.ok_or_else(
                || {
                    TransactionStoreError::Corruption(
                        "verified desired-state digest missing".into(),
                    )
                },
            )?)
            .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?,
            graph_digest: ContentDigest::new(generation.graph_digest.ok_or_else(|| {
                TransactionStoreError::Corruption("verified graph digest missing".into())
            })?)
            .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?,
            provenance_digest: ContentDigest::new(generation.provenance_digest.ok_or_else(
                || TransactionStoreError::Corruption("verified provenance digest missing".into()),
            )?)
            .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?,
        })
    }

    fn list_state(
        &self,
        state: TransactionState,
    ) -> Result<Vec<TransactionSnapshot>, TransactionStoreError> {
        let mut snapshots = Vec::new();
        for transaction_id in list_transaction_ids(&self.connection)? {
            let snapshot = self.snapshot(&transaction_id)?;
            if snapshot.state == state {
                snapshots.push(snapshot);
            }
        }
        Ok(snapshots)
    }

    fn list_state_in_namespace(
        &self,
        state: TransactionState,
        request_prefix: &str,
        maximum: usize,
    ) -> Result<Vec<TransactionSnapshot>, TransactionStoreError> {
        if maximum == 0
            || maximum > 4096
            || request_prefix.is_empty()
            || request_prefix.len() > 256
            || request_prefix.chars().any(char::is_control)
        {
            return Err(TransactionStoreError::CapacityExceeded);
        }
        with_immediate_validation(&self.connection, || {
            // Authenticate ALL rows before filtering: tampered namespace/state
            // metadata must not hide a recovery fence. Keep validation and
            // selection in the SAME SQLite snapshot, including capacity checks.
            self.validate_integrity_locked()?;
            let mut statement = self
                .connection
                .prepare(
                    "SELECT t.transaction_id FROM transactions AS t
                 JOIN generations AS g ON g.transaction_id = t.transaction_id
                     AND g.generation = t.current_generation
                 WHERE g.state = ?1 AND substr(t.request_id, 1, length(?2)) = ?2
                 ORDER BY t.transaction_id LIMIT ?3",
                )
                .map_err(sqlite)?;
            let limit =
                i64::try_from(maximum + 1).map_err(|_| TransactionStoreError::CapacityExceeded)?;
            let ids = statement
                .query_map(params![state.as_str(), request_prefix, limit], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(sqlite)?;
            let mut snapshots = Vec::new();
            for id in ids {
                if snapshots.len() == maximum {
                    return Err(TransactionStoreError::CapacityExceeded);
                }
                let id = TransactionId::new(id.map_err(sqlite)?)
                    .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
                let snapshot = self.snapshot(&id)?;
                if snapshot.state != state
                    || !snapshot.request_id.as_str().starts_with(request_prefix)
                {
                    return Err(TransactionStoreError::Corruption(
                        "recovery query identity changed".into(),
                    ));
                }
                snapshots.push(snapshot);
            }
            Ok(snapshots)
        })
    }

    fn integrity_check(&self) -> Result<(), TransactionStoreError> {
        with_immediate_validation(&self.connection, || self.validate_integrity_locked())
    }
}

impl SqliteTransactionStore {
    // Caller owns BEGIN IMMEDIATE. Shared by full validation and bounded
    // recovery selection; never call outside an authenticated read snapshot.
    fn validate_integrity_locked(&self) -> Result<(), TransactionStoreError> {
        validate_runtime_settings(&self.connection, self.limits)?;
        validate_schema_identity(
            &self.connection,
            &self.authority_verifier.fingerprint(),
            &self.integrity_key.fingerprint(),
        )?;
        validate_aggregate_capacity(
            &self.connection,
            "transactions",
            self.limits.max_transactions,
        )?;
        validate_aggregate_capacity(&self.connection, "generations", self.limits.max_generations)?;
        validate_aggregate_capacity(
            &self.connection,
            "audit_events",
            self.limits.max_audit_events,
        )?;
        validate_logical_audit_reserve(&self.connection, self.limits)?;

        let integrity: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(sqlite)?;
        if integrity != "ok" {
            return Err(TransactionStoreError::Corruption(format!(
                "SQLite integrity_check returned {integrity:?}"
            )));
        }
        let mut foreign = self
            .connection
            .prepare("PRAGMA foreign_key_check")
            .map_err(sqlite)?;
        if foreign
            .query([])
            .map_err(sqlite)?
            .next()
            .map_err(sqlite)?
            .is_some()
        {
            return Err(TransactionStoreError::Corruption(
                "SQLite foreign_key_check reported violations".into(),
            ));
        }
        drop(foreign);

        for transaction_id in list_transaction_ids(&self.connection)? {
            let (transaction, _, _) =
                load_current(&self.connection, &self.integrity_key, &transaction_id)?;
            validate_generation_history(
                &self.connection,
                &self.integrity_key,
                &transaction_id,
                transaction.current_generation,
                self.limits,
            )?;
            validate_audit_chain(
                &self.connection,
                &self.integrity_key,
                &transaction_id,
                transaction.current_generation,
                transaction.state_version,
                self.limits,
            )?;
        }
        validate_physical_reservations_locked(
            &self.connection,
            &self.integrity_key,
            self.opener_released_for_terminal_recovery,
        )
    }
}

fn enforce_authority_window(
    authorized_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<(), TransactionStoreError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TransactionStoreError::AuthorityRejected)?
        .as_millis();
    let now = u64::try_from(now).map_err(|_| TransactionStoreError::AuthorityRejected)?;
    if now < authorized_at_unix_ms || now > expires_at_unix_ms {
        return Err(TransactionStoreError::AuthorityRejected);
    }
    Ok(())
}

#[allow(dead_code)]
fn _schema_identity_constants_are_intentional() -> (i64, i64) {
    (APPLICATION_ID, SCHEMA_VERSION)
}
