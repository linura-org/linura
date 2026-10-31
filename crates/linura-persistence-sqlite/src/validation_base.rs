use std::time::Duration;

use linura_core::{PrincipalId, RequestId};
use linura_transaction::{
    ContentDigest, MAX_AUTHORITY_BINDING_BYTES, MAX_TRANSACTION_GENERATIONS, TransactionId,
    TransactionSnapshot, TransactionState, TransactionStoreError, digest_bytes, digest_parts,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::integrity::{
    INTEGRITY_TAG_BYTES, SqliteIntegrityKey, canonical_field, canonical_optional,
};
use crate::schema::{
    APPLICATION_ID, BUSY_TIMEOUT_MS, CONTENT_DIGEST_TEXT_BYTES, MAX_AUDIT_EVENT_KIND_BYTES,
    MAX_PERSISTED_PRINCIPAL_BYTES, MAX_PERSISTED_REQUEST_ID_BYTES, MAX_SQLITE_PAGE_SIZE,
    MAX_TRANSACTION_ID_BYTES, MIGRATION_ID, MIGRATION_V1, MIN_SQLITE_PAGE_SIZE, SCHEMA_VERSION,
};
use crate::store::StoreLimits;

const MAX_STATE_TEXT_BYTES: usize = 32;
const MAX_SCHEMA_NAME_BYTES: usize = 256;
const MAX_SCHEMA_SQL_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct StoredTransaction {
    pub(crate) transaction_id: String,
    pub(crate) principal: String,
    pub(crate) request_id: String,
    pub(crate) current_generation: u64,
    pub(crate) state_version: u64,
    pub(crate) integrity_tag: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct StoredGeneration {
    pub(crate) transaction_id: String,
    pub(crate) generation: u64,
    pub(crate) state: String,
    pub(crate) binding_digest: String,
    pub(crate) binding_canonical: Vec<u8>,
    pub(crate) request_digest: String,
    pub(crate) precondition_digest: String,
    pub(crate) observation_digest: String,
    pub(crate) desired_state_digest: Option<String>,
    pub(crate) graph_digest: Option<String>,
    pub(crate) provenance_digest: Option<String>,
    pub(crate) integrity_tag: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct StoredAuditEvent {
    pub(crate) transaction_id: String,
    pub(crate) event_sequence: u64,
    pub(crate) generation: u64,
    pub(crate) state_version: u64,
    pub(crate) event_kind: String,
    pub(crate) payload_digest: String,
    pub(crate) previous_digest: String,
    pub(crate) event_digest: String,
    pub(crate) integrity_tag: Vec<u8>,
}

pub(crate) fn configure_connection(
    connection: &Connection,
    limits: StoreLimits,
) -> Result<(), TransactionStoreError> {
    connection
        .busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))
        .map_err(sqlite)?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA recursive_triggers=ON; PRAGMA synchronous=FULL;",
        )
        .map_err(sqlite)?;
    let mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .map_err(sqlite)?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(TransactionStoreError::UnsupportedSchema(format!(
            "SQLite WAL mode unavailable: {mode}"
        )));
    }
    connection
        .pragma_update(None, "max_page_count", as_i64(limits.max_pages)?)
        .map_err(sqlite)?;
    validate_runtime_settings(connection, limits)
}

pub(crate) fn initialize_or_validate_schema(
    connection: &mut Connection,
    authority_fingerprint: &ContentDigest,
    integrity_fingerprint: &ContentDigest,
) -> Result<(), TransactionStoreError> {
    let application_id = pragma_i64(connection, "application_id")?;
    let user_version = pragma_i64(connection, "user_version")?;
    if application_id == 0 && user_version == 0 {
        let object_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite)?;
        if object_count != 0 {
            return Err(TransactionStoreError::UnsupportedSchema(
                "unidentified authority database contains application schema objects".into(),
            ));
        }
        let migration = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sqlite)?;
        migration
            .pragma_update(None, "application_id", APPLICATION_ID)
            .map_err(sqlite)?;
        migration.execute_batch(MIGRATION_V1).map_err(sqlite)?;
        migration
            .execute(
                "INSERT INTO authority_store_identity (
                    singleton, verifier_fingerprint, integrity_fingerprint
                 ) VALUES (1, ?1, ?2)",
                params![authority_fingerprint.as_str(), integrity_fingerprint.as_str()],
            )
            .map_err(sqlite)?;
        let checksum = migration_checksum();
        migration
            .execute(
                "INSERT INTO schema_migrations (migration_id, checksum) VALUES (?1, ?2)",
                params![MIGRATION_ID, checksum.as_str()],
            )
            .map_err(sqlite)?;
        migration
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(sqlite)?;
        migration.commit().map_err(sqlite)?;
    } else {
        if application_id != APPLICATION_ID {
            return Err(TransactionStoreError::UnsupportedSchema(format!(
                "application_id {application_id} is not Linura authority storage"
            )));
        }
        if user_version != SCHEMA_VERSION {
            return Err(TransactionStoreError::UnsupportedSchema(format!(
                "database schema {user_version} is not supported schema {SCHEMA_VERSION}"
            )));
        }
    }
    validate_schema_identity(connection, authority_fingerprint, integrity_fingerprint)
}

pub(crate) fn validate_runtime_settings(
    connection: &Connection,
    limits: StoreLimits,
) -> Result<(), TransactionStoreError> {
    let mode = pragma_string(connection, "journal_mode")?.to_ascii_lowercase();
    if mode != "wal" {
        return Err(TransactionStoreError::UnsupportedSchema(format!(
            "authority database journal mode must be WAL, found {mode}"
        )));
    }
    if pragma_i64(connection, "synchronous")? != 2 {
        return Err(TransactionStoreError::UnsupportedSchema(
            "authority database synchronous mode must be FULL".into(),
        ));
    }
    if pragma_i64(connection, "foreign_keys")? != 1 {
        return Err(TransactionStoreError::UnsupportedSchema(
            "authority database foreign keys must be enabled".into(),
        ));
    }
    if pragma_i64(connection, "trusted_schema")? != 0 {
        return Err(TransactionStoreError::UnsupportedSchema(
            "authority database trusted_schema must be disabled".into(),
        ));
    }
    if pragma_i64(connection, "recursive_triggers")? != 1 {
        return Err(TransactionStoreError::UnsupportedSchema(
            "authority database recursive triggers must be enabled".into(),
        ));
    }
    let page_size = page_size(connection)?;
    if !(MIN_SQLITE_PAGE_SIZE..=MAX_SQLITE_PAGE_SIZE).contains(&page_size)
        || !page_size.is_power_of_two()
    {
        return Err(TransactionStoreError::UnsupportedSchema(format!(
            "unsupported SQLite page_size {page_size}"
        )));
    }
    let max_pages = pragma_i64(connection, "max_page_count")?;
    if max_pages <= 0
        || u64::try_from(max_pages).map_err(|_| TransactionStoreError::CapacityExceeded)?
            > limits.max_pages
    {
        return Err(TransactionStoreError::CapacityExceeded);
    }
    Ok(())
}

pub(crate) fn validate_schema_identity(
    connection: &Connection,
    authority_fingerprint: &ContentDigest,
    integrity_fingerprint: &ContentDigest,
) -> Result<(), TransactionStoreError> {
    if pragma_i64(connection, "application_id")? != APPLICATION_ID {
        return Err(TransactionStoreError::UnsupportedSchema(
            "authority database application_id mismatch".into(),
        ));
    }
    if pragma_i64(connection, "user_version")? != SCHEMA_VERSION {
        return Err(TransactionStoreError::UnsupportedSchema(
            "authority database user_version mismatch".into(),
        ));
    }

    let identity = connection
        .query_row(
            "SELECT
                length(CAST(verifier_fingerprint AS BLOB)),
                CASE WHEN length(CAST(verifier_fingerprint AS BLOB)) = ?1 THEN verifier_fingerprint ELSE NULL END,
                length(CAST(integrity_fingerprint AS BLOB)),
                CASE WHEN length(CAST(integrity_fingerprint AS BLOB)) = ?1 THEN integrity_fingerprint ELSE NULL END
             FROM authority_store_identity WHERE singleton = 1",
            params![as_i64(CONTENT_DIGEST_TEXT_BYTES as u64)?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite)?
        .ok_or(TransactionStoreError::AuthorityRejected)?;
    if identity.0 != CONTENT_DIGEST_TEXT_BYTES as i64
        || identity.2 != CONTENT_DIGEST_TEXT_BYTES as i64
    {
        return Err(TransactionStoreError::Corruption(
            "authority-store identity fingerprint length is invalid".into(),
        ));
    }
    let stored_authority = ContentDigest::new(identity.1.ok_or_else(|| {
        TransactionStoreError::Corruption("authority fingerprint withheld by length preflight".into())
    })?)
    .map_err(|_| TransactionStoreError::AuthorityRejected)?;
    let stored_integrity = ContentDigest::new(identity.3.ok_or_else(|| {
        TransactionStoreError::Corruption("integrity fingerprint withheld by length preflight".into())
    })?)
    .map_err(|_| TransactionStoreError::AuthorityRejected)?;
    if stored_authority != *authority_fingerprint || stored_integrity != *integrity_fingerprint {
        return Err(TransactionStoreError::AuthorityRejected);
    }

    let checksum = connection
        .query_row(
            "SELECT length(CAST(checksum AS BLOB)),
                    CASE WHEN length(CAST(checksum AS BLOB)) = ?2 THEN checksum ELSE NULL END
             FROM schema_migrations WHERE migration_id = ?1",
            params![MIGRATION_ID, as_i64(CONTENT_DIGEST_TEXT_BYTES as u64)?],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .optional()
        .map_err(sqlite)?
        .ok_or_else(|| {
            TransactionStoreError::UnsupportedSchema("migration ledger entry missing".into())
        })?;
    if checksum.0 != CONTENT_DIGEST_TEXT_BYTES as i64
        || checksum.1.as_deref() != Some(migration_checksum().as_str())
    {
        return Err(TransactionStoreError::UnsupportedSchema(
            "migration checksum mismatch".into(),
        ));
    }
    if schema_fingerprint(connection)? != expected_schema_fingerprint()? {
        return Err(TransactionStoreError::UnsupportedSchema(
            "installed authority schema objects differ from the canonical migration".into(),
        ));
    }
    Ok(())
}

fn schema_fingerprint(connection: &Connection) -> Result<ContentDigest, TransactionStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT
                length(CAST(type AS BLOB)), CASE WHEN length(CAST(type AS BLOB)) <= ?1 THEN type ELSE NULL END,
                length(CAST(name AS BLOB)), CASE WHEN length(CAST(name AS BLOB)) <= ?2 THEN name ELSE NULL END,
                length(CAST(tbl_name AS BLOB)), CASE WHEN length(CAST(tbl_name AS BLOB)) <= ?2 THEN tbl_name ELSE NULL END,
                length(CAST(COALESCE(sql, '') AS BLOB)), CASE WHEN length(CAST(COALESCE(sql, '') AS BLOB)) <= ?3 THEN COALESCE(sql, '') ELSE NULL END
             FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%'
             ORDER BY type, name",
        )
        .map_err(sqlite)?;
    let rows = statement
        .query_map(
            params![32_i64, MAX_SCHEMA_NAME_BYTES as i64, MAX_SCHEMA_SQL_BYTES as i64],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?, row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?, row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?, row.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .map_err(sqlite)?;
    let mut encoded = Vec::new();
    for row in rows {
        let row = row.map_err(sqlite)?;
        if row.0 > 32
            || row.2 > MAX_SCHEMA_NAME_BYTES as i64
            || row.4 > MAX_SCHEMA_NAME_BYTES as i64
            || row.6 > MAX_SCHEMA_SQL_BYTES as i64
        {
            return Err(TransactionStoreError::UnsupportedSchema(
                "SQLite schema object exceeds validation byte bound".into(),
            ));
        }
        for value in [row.1, row.3, row.5, row.7] {
            let value = value.ok_or_else(|| {
                TransactionStoreError::UnsupportedSchema(
                    "SQLite schema object withheld by length preflight".into(),
                )
            })?;
            canonical_field(&mut encoded, value.as_bytes());
        }
    }
    Ok(digest_bytes("linura.sqlite.schema-objects.v1", &encoded))
}

fn expected_schema_fingerprint() -> Result<ContentDigest, TransactionStoreError> {
    let reference = Connection::open_in_memory().map_err(sqlite)?;
    reference.execute_batch(MIGRATION_V1).map_err(sqlite)?;
    schema_fingerprint(&reference)
}

pub(crate) fn validate_aggregate_capacity(
    connection: &Connection,
    table: &str,
    maximum: u64,
) -> Result<(), TransactionStoreError> {
    let query = match table {
        "transactions" => "SELECT COUNT(*) FROM transactions",
        "generations" => "SELECT COUNT(*) FROM generations",
        "audit_events" => "SELECT COUNT(*) FROM audit_events",
        _ => {
            return Err(TransactionStoreError::Corruption(
                "unknown capacity table".into(),
            ));
        }
    };
    let count: i64 = connection
        .query_row(query, [], |row| row.get(0))
        .map_err(sqlite)?;
    let count = u64::try_from(count)
        .map_err(|_| TransactionStoreError::Corruption("negative aggregate row count".into()))?;
    if count > maximum {
        return Err(TransactionStoreError::CapacityExceeded);
    }
    Ok(())
}

pub(crate) fn validate_logical_audit_reserve(
    connection: &Connection,
    limits: StoreLimits,
) -> Result<(), TransactionStoreError> {
    let audit_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
        .map_err(sqlite)?;
    let nonterminal_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM transactions t
             JOIN generations g ON g.transaction_id=t.transaction_id
              AND g.generation=t.current_generation
             WHERE g.state IN ('prepared','indeterminate','verified')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite)?;
    let audit_count = u64::try_from(audit_count)
        .map_err(|_| TransactionStoreError::Corruption("negative aggregate audit count".into()))?;
    let nonterminal_count = u64::try_from(nonterminal_count).map_err(|_| {
        TransactionStoreError::Corruption("negative aggregate nonterminal count".into())
    })?;
    if audit_count
        .checked_add(nonterminal_count)
        .ok_or(TransactionStoreError::CapacityExceeded)?
        > limits.max_audit_events
    {
        return Err(TransactionStoreError::CapacityExceeded);
    }
    Ok(())
}

pub(crate) fn transaction_canonical(record: &StoredTransaction) -> Vec<u8> {
    let mut canonical = Vec::with_capacity(512);
    canonical_field(&mut canonical, record.transaction_id.as_bytes());
    canonical_field(&mut canonical, record.principal.as_bytes());
    canonical_field(&mut canonical, record.request_id.as_bytes());
    canonical_field(&mut canonical, &record.current_generation.to_be_bytes());
    canonical_field(&mut canonical, &record.state_version.to_be_bytes());
    canonical
}

pub(crate) fn generation_canonical(record: &StoredGeneration) -> Vec<u8> {
    let mut canonical = Vec::with_capacity(record.binding_canonical.len().saturating_add(512));
    canonical_field(&mut canonical, record.transaction_id.as_bytes());
    canonical_field(&mut canonical, &record.generation.to_be_bytes());
    canonical_field(&mut canonical, record.state.as_bytes());
    canonical_field(&mut canonical, record.binding_digest.as_bytes());
    canonical_field(&mut canonical, &record.binding_canonical);
    canonical_field(&mut canonical, record.request_digest.as_bytes());
    canonical_field(&mut canonical, record.precondition_digest.as_bytes());
    canonical_field(&mut canonical, record.observation_digest.as_bytes());
    canonical_optional(&mut canonical, record.desired_state_digest.as_deref());
    canonical_optional(&mut canonical, record.graph_digest.as_deref());
    canonical_optional(&mut canonical, record.provenance_digest.as_deref());
    canonical
}

pub(crate) fn audit_canonical(record: &StoredAuditEvent) -> Vec<u8> {
    let mut canonical = Vec::with_capacity(768);
    canonical_field(&mut canonical, record.transaction_id.as_bytes());
    canonical_field(&mut canonical, &record.event_sequence.to_be_bytes());
    canonical_field(&mut canonical, &record.generation.to_be_bytes());
    canonical_field(&mut canonical, &record.state_version.to_be_bytes());
    canonical_field(&mut canonical, record.event_kind.as_bytes());
    canonical_field(&mut canonical, record.payload_digest.as_bytes());
    canonical_field(&mut canonical, record.previous_digest.as_bytes());
    canonical_field(&mut canonical, record.event_digest.as_bytes());
    canonical
}

pub(crate) fn authenticate_transaction(
    key: &SqliteIntegrityKey,
    record: &StoredTransaction,
) -> Result<(), TransactionStoreError> {
    if !key.verify(
        "linura.sqlite.transaction-record.v1",
        &transaction_canonical(record),
        &record.integrity_tag,
    ) {
        return Err(TransactionStoreError::Corruption(
            "transaction record integrity tag mismatch".into(),
        ));
    }
    Ok(())
}

pub(crate) fn authenticate_generation(
    key: &SqliteIntegrityKey,
    record: &StoredGeneration,
) -> Result<(), TransactionStoreError> {
    if !key.verify(
        "linura.sqlite.generation-record.v1",
        &generation_canonical(record),
        &record.integrity_tag,
    ) {
        return Err(TransactionStoreError::Corruption(
            "generation record integrity tag mismatch".into(),
        ));
    }
    Ok(())
}

pub(crate) fn authenticate_audit(
    key: &SqliteIntegrityKey,
    record: &StoredAuditEvent,
) -> Result<(), TransactionStoreError> {
    if !key.verify(
        "linura.sqlite.audit-record.v1",
        &audit_canonical(record),
        &record.integrity_tag,
    ) {
        return Err(TransactionStoreError::Corruption(
            "audit record integrity tag mismatch".into(),
        ));
    }
    Ok(())
}

pub(crate) fn transaction_tag(
    key: &SqliteIntegrityKey,
    record: &StoredTransaction,
) -> Result<Vec<u8>, TransactionStoreError> {
    Ok(key
        .tag("linura.sqlite.transaction-record.v1", &transaction_canonical(record))?
        .to_vec())
}

pub(crate) fn generation_tag(
    key: &SqliteIntegrityKey,
    record: &StoredGeneration,
) -> Result<Vec<u8>, TransactionStoreError> {
    Ok(key
        .tag("linura.sqlite.generation-record.v1", &generation_canonical(record))?
        .to_vec())
}

pub(crate) fn audit_tag(
    key: &SqliteIntegrityKey,
    record: &StoredAuditEvent,
) -> Result<Vec<u8>, TransactionStoreError> {
    Ok(key
        .tag("linura.sqlite.audit-record.v1", &audit_canonical(record))?
        .to_vec())
}

pub(crate) fn load_transaction(
    connection: &Connection,
    key: &SqliteIntegrityKey,
    transaction_id: &TransactionId,
) -> Result<StoredTransaction, TransactionStoreError> {
    let raw = connection
        .query_row(
            "SELECT
                length(CAST(transaction_id AS BLOB)), CASE WHEN length(CAST(transaction_id AS BLOB)) BETWEEN 1 AND ?2 THEN transaction_id ELSE NULL END,
                length(CAST(principal AS BLOB)), CASE WHEN length(CAST(principal AS BLOB)) BETWEEN 1 AND ?3 THEN principal ELSE NULL END,
                length(CAST(request_id AS BLOB)), CASE WHEN length(CAST(request_id AS BLOB)) BETWEEN 1 AND ?4 THEN request_id ELSE NULL END,
                current_generation, state_version,
                length(integrity_tag), CASE WHEN length(integrity_tag) = ?5 THEN integrity_tag ELSE NULL END
             FROM transactions WHERE transaction_id = ?1",
            params![
                transaction_id.as_str(),
                MAX_TRANSACTION_ID_BYTES as i64,
                MAX_PERSISTED_PRINCIPAL_BYTES as i64,
                MAX_PERSISTED_REQUEST_ID_BYTES as i64,
                INTEGRITY_TAG_BYTES as i64,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?, row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?, row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?, row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?, row.get::<_, Option<Vec<u8>>>(9)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite)?
        .ok_or(TransactionStoreError::NotFound)?;
    if raw.0 <= 0
        || raw.0 > MAX_TRANSACTION_ID_BYTES as i64
        || raw.2 <= 0
        || raw.2 > MAX_PERSISTED_PRINCIPAL_BYTES as i64
        || raw.4 <= 0
        || raw.4 > MAX_PERSISTED_REQUEST_ID_BYTES as i64
        || raw.8 != INTEGRITY_TAG_BYTES as i64
    {
        return Err(TransactionStoreError::Corruption(
            "transaction record exceeds persisted byte bounds".into(),
        ));
    }
    let record = StoredTransaction {
        transaction_id: require_text(raw.1, "transaction id")?,
        principal: require_text(raw.3, "transaction principal")?,
        request_id: require_text(raw.5, "transaction request id")?,
        current_generation: u64::try_from(raw.6).map_err(|_| {
            TransactionStoreError::Corruption("negative current generation".into())
        })?,
        state_version: u64::try_from(raw.7)
            .map_err(|_| TransactionStoreError::Corruption("negative state version".into()))?,
        integrity_tag: require_blob(raw.9, "transaction integrity tag")?,
    };
    authenticate_transaction(key, &record)?;
    Ok(record)
}

pub(crate) fn load_generation(
    connection: &Connection,
    key: &SqliteIntegrityKey,
    transaction_id: &TransactionId,
    generation: u64,
) -> Result<StoredGeneration, TransactionStoreError> {
    let raw = connection
        .query_row(
            "SELECT
                length(CAST(transaction_id AS BLOB)), CASE WHEN length(CAST(transaction_id AS BLOB)) BETWEEN 1 AND ?3 THEN transaction_id ELSE NULL END,
                generation,
                length(CAST(state AS BLOB)), CASE WHEN length(CAST(state AS BLOB)) BETWEEN 1 AND ?4 THEN state ELSE NULL END,
                length(CAST(binding_digest AS BLOB)), CASE WHEN length(CAST(binding_digest AS BLOB)) = ?5 THEN binding_digest ELSE NULL END,
                length(binding_canonical), CASE WHEN length(binding_canonical) <= ?6 THEN binding_canonical ELSE NULL END,
                length(CAST(request_digest AS BLOB)), CASE WHEN length(CAST(request_digest AS BLOB)) = ?5 THEN request_digest ELSE NULL END,
                length(CAST(precondition_digest AS BLOB)), CASE WHEN length(CAST(precondition_digest AS BLOB)) = ?5 THEN precondition_digest ELSE NULL END,
                length(CAST(observation_digest AS BLOB)), CASE WHEN length(CAST(observation_digest AS BLOB)) = ?5 THEN observation_digest ELSE NULL END,
                CASE WHEN desired_state_digest IS NULL THEN -1 ELSE length(CAST(desired_state_digest AS BLOB)) END,
                CASE WHEN desired_state_digest IS NULL OR length(CAST(desired_state_digest AS BLOB)) = ?5 THEN desired_state_digest ELSE NULL END,
                CASE WHEN graph_digest IS NULL THEN -1 ELSE length(CAST(graph_digest AS BLOB)) END,
                CASE WHEN graph_digest IS NULL OR length(CAST(graph_digest AS BLOB)) = ?5 THEN graph_digest ELSE NULL END,
                CASE WHEN provenance_digest IS NULL THEN -1 ELSE length(CAST(provenance_digest AS BLOB)) END,
                CASE WHEN provenance_digest IS NULL OR length(CAST(provenance_digest AS BLOB)) = ?5 THEN provenance_digest ELSE NULL END,
                length(integrity_tag), CASE WHEN length(integrity_tag) = ?7 THEN integrity_tag ELSE NULL END
             FROM generations WHERE transaction_id = ?1 AND generation = ?2",
            params![
                transaction_id.as_str(), as_i64(generation)?,
                MAX_TRANSACTION_ID_BYTES as i64, MAX_STATE_TEXT_BYTES as i64,
                CONTENT_DIGEST_TEXT_BYTES as i64, MAX_AUTHORITY_BINDING_BYTES as i64,
                INTEGRITY_TAG_BYTES as i64,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?, row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?, row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?, row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, i64>(9)?, row.get::<_, Option<String>>(10)?,
                    row.get::<_, i64>(11)?, row.get::<_, Option<String>>(12)?,
                    row.get::<_, i64>(13)?, row.get::<_, Option<String>>(14)?,
                    row.get::<_, i64>(15)?, row.get::<_, Option<String>>(16)?,
                    row.get::<_, i64>(17)?, row.get::<_, Option<String>>(18)?,
                    row.get::<_, i64>(19)?, row.get::<_, Option<String>>(20)?,
                    row.get::<_, i64>(21)?, row.get::<_, Option<Vec<u8>>>(22)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite)?
        .ok_or(TransactionStoreError::NotFound)?;
    if raw.0 <= 0
        || raw.0 > MAX_TRANSACTION_ID_BYTES as i64
        || raw.3 <= 0
        || raw.3 > MAX_STATE_TEXT_BYTES as i64
        || raw.5 != CONTENT_DIGEST_TEXT_BYTES as i64
        || raw.7 < 0
        || raw.7 > MAX_AUTHORITY_BINDING_BYTES as i64
        || raw.9 != CONTENT_DIGEST_TEXT_BYTES as i64
        || raw.11 != CONTENT_DIGEST_TEXT_BYTES as i64
        || raw.13 != CONTENT_DIGEST_TEXT_BYTES as i64
        || !optional_digest_length_valid(raw.15)
        || !optional_digest_length_valid(raw.17)
        || !optional_digest_length_valid(raw.19)
        || raw.21 != INTEGRITY_TAG_BYTES as i64
    {
        return Err(TransactionStoreError::Corruption(
            "generation record exceeds persisted byte bounds".into(),
        ));
    }
    let canonical = require_blob(raw.8, "authority binding canonical bytes")?;
    if canonical.len() != usize::try_from(raw.7).unwrap_or(usize::MAX) {
        return Err(TransactionStoreError::Corruption(
            "authority binding length changed during validation".into(),
        ));
    }
    let record = StoredGeneration {
        transaction_id: require_text(raw.1, "generation transaction id")?,
        generation: u64::try_from(raw.2)
            .map_err(|_| TransactionStoreError::Corruption("negative generation".into()))?,
        state: require_text(raw.4, "generation state")?,
        binding_digest: require_text(raw.6, "binding digest")?,
        binding_canonical: canonical,
        request_digest: require_text(raw.10, "request digest")?,
        precondition_digest: require_text(raw.12, "precondition digest")?,
        observation_digest: require_text(raw.14, "observation digest")?,
        desired_state_digest: optional_digest_value(raw.15, raw.16, "desired-state digest")?,
        graph_digest: optional_digest_value(raw.17, raw.18, "graph digest")?,
        provenance_digest: optional_digest_value(raw.19, raw.20, "provenance digest")?,
        integrity_tag: require_blob(raw.22, "generation integrity tag")?,
    };
    authenticate_generation(key, &record)?;
    Ok(record)
}

pub(crate) fn load_last_audit_event(
    connection: &Connection,
    key: &SqliteIntegrityKey,
    transaction_id: &TransactionId,
) -> Result<Option<StoredAuditEvent>, TransactionStoreError> {
    bounded_audit_query(
        connection,
        key,
        "WHERE transaction_id = ?1 ORDER BY event_sequence DESC LIMIT 1",
        transaction_id,
    )
    .map(|mut events| events.pop())
}

fn bounded_audit_query(
    connection: &Connection,
    key: &SqliteIntegrityKey,
    suffix: &str,
    transaction_id: &TransactionId,
) -> Result<Vec<StoredAuditEvent>, TransactionStoreError> {
    let query = format!(
        "SELECT
            length(CAST(transaction_id AS BLOB)), CASE WHEN length(CAST(transaction_id AS BLOB)) BETWEEN 1 AND ?2 THEN transaction_id ELSE NULL END,
            event_sequence, generation, state_version,
            length(CAST(event_kind AS BLOB)), CASE WHEN length(CAST(event_kind AS BLOB)) BETWEEN 1 AND ?3 THEN event_kind ELSE NULL END,
            length(CAST(payload_digest AS BLOB)), CASE WHEN length(CAST(payload_digest AS BLOB)) = ?4 THEN payload_digest ELSE NULL END,
            length(CAST(previous_digest AS BLOB)), CASE WHEN length(CAST(previous_digest AS BLOB)) = ?4 THEN previous_digest ELSE NULL END,
            length(CAST(event_digest AS BLOB)), CASE WHEN length(CAST(event_digest AS BLOB)) = ?4 THEN event_digest ELSE NULL END,
            length(integrity_tag), CASE WHEN length(integrity_tag) = ?5 THEN integrity_tag ELSE NULL END
         FROM audit_events {suffix}"
    );
    let mut statement = connection.prepare(&query).map_err(sqlite)?;
    let rows = statement
        .query_map(
            params![
                transaction_id.as_str(), MAX_TRANSACTION_ID_BYTES as i64,
                MAX_AUDIT_EVENT_KIND_BYTES as i64, CONTENT_DIGEST_TEXT_BYTES as i64,
                INTEGRITY_TAG_BYTES as i64,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?, row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?, row.get::<_, Option<String>>(8)?,
                    row.get::<_, i64>(9)?, row.get::<_, Option<String>>(10)?,
                    row.get::<_, i64>(11)?, row.get::<_, Option<String>>(12)?,
                    row.get::<_, i64>(13)?, row.get::<_, Option<Vec<u8>>>(14)?,
                ))
            },
        )
        .map_err(sqlite)?;
    let mut events = Vec::new();
    for raw in rows {
        let raw = raw.map_err(sqlite)?;
        if raw.0 <= 0
            || raw.0 > MAX_TRANSACTION_ID_BYTES as i64
            || raw.5 <= 0
            || raw.5 > MAX_AUDIT_EVENT_KIND_BYTES as i64
            || raw.7 != CONTENT_DIGEST_TEXT_BYTES as i64
            || raw.9 != CONTENT_DIGEST_TEXT_BYTES as i64
            || raw.11 != CONTENT_DIGEST_TEXT_BYTES as i64
            || raw.13 != INTEGRITY_TAG_BYTES as i64
        {
            return Err(TransactionStoreError::Corruption(
                "audit record exceeds persisted byte bounds".into(),
            ));
        }
        let event = StoredAuditEvent {
            transaction_id: require_text(raw.1, "audit transaction id")?,
            event_sequence: u64::try_from(raw.2).map_err(|_| {
                TransactionStoreError::Corruption("negative audit event sequence".into())
            })?,
            generation: u64::try_from(raw.3).map_err(|_| {
                TransactionStoreError::Corruption("negative audit generation".into())
            })?,
            state_version: u64::try_from(raw.4).map_err(|_| {
                TransactionStoreError::Corruption("negative audit state version".into())
            })?,
            event_kind: require_text(raw.6, "audit event kind")?,
            payload_digest: require_text(raw.8, "audit payload digest")?,
            previous_digest: require_text(raw.10, "audit previous digest")?,
            event_digest: require_text(raw.12, "audit event digest")?,
            integrity_tag: require_blob(raw.14, "audit integrity tag")?,
        };
        authenticate_audit(key, &event)?;
        events.push(event);
    }
    Ok(events)
}

pub(crate) fn load_all_audit_events(
    connection: &Connection,
    key: &SqliteIntegrityKey,
    transaction_id: &TransactionId,
) -> Result<Vec<StoredAuditEvent>, TransactionStoreError> {
    bounded_audit_query(
        connection,
        key,
        "WHERE transaction_id = ?1 ORDER BY event_sequence",
        transaction_id,
    )
}

pub(crate) fn snapshot_from_records(
    transaction: &StoredTransaction,
    generation: &StoredGeneration,
) -> Result<TransactionSnapshot, TransactionStoreError> {
    if transaction.transaction_id != generation.transaction_id
        || transaction.current_generation != generation.generation
    {
        return Err(TransactionStoreError::Corruption(
            "transaction pointer does not identify the authenticated generation".into(),
        ));
    }
    let transaction_id = TransactionId::new(transaction.transaction_id.clone())
        .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
    let principal = PrincipalId::new(transaction.principal.clone())
        .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
    let request_id = RequestId::new(transaction.request_id.clone())
        .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
    if TransactionId::for_namespace(&principal, &request_id) != transaction_id {
        return Err(TransactionStoreError::Corruption(
            "transaction identity does not match principal/request namespace".into(),
        ));
    }
    let state = TransactionState::parse(&generation.state)
        .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
    let binding_digest = ContentDigest::new(generation.binding_digest.clone())
        .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
    Ok(TransactionSnapshot {
        transaction_id,
        principal,
        request_id,
        current_generation: transaction.current_generation,
        state_version: transaction.state_version,
        state,
        binding_digest,
    })
}

pub(crate) fn load_current(
    connection: &Connection,
    key: &SqliteIntegrityKey,
    transaction_id: &TransactionId,
) -> Result<(StoredTransaction, StoredGeneration, TransactionSnapshot), TransactionStoreError> {
    let transaction = load_transaction(connection, key, transaction_id)?;
    let generation = load_generation(
        connection,
        key,
        transaction_id,
        transaction.current_generation,
    )?;
    let snapshot = snapshot_from_records(&transaction, &generation)?;
    let tail = load_last_audit_event(connection, key, transaction_id)?.ok_or_else(|| {
        TransactionStoreError::Corruption("transaction has no authenticated audit history".into())
    })?;
    if tail.generation != snapshot.current_generation
        || tail.state_version != snapshot.state_version
        || state_for_event_kind(&tail.event_kind)? != snapshot.state
    {
        return Err(TransactionStoreError::Corruption(
            "authenticated audit tail disagrees with current transaction state".into(),
        ));
    }
    Ok((transaction, generation, snapshot))
}

pub(crate) fn validate_generation_history(
    connection: &Connection,
    key: &SqliteIntegrityKey,
    transaction_id: &TransactionId,
    current_generation: u64,
    limits: StoreLimits,
) -> Result<(), TransactionStoreError> {
    if current_generation >= MAX_TRANSACTION_GENERATIONS {
        return Err(TransactionStoreError::Corruption(
            "current generation exceeds domain bound".into(),
        ));
    }
    let expected_rows = current_generation
        .checked_add(1)
        .ok_or(TransactionStoreError::CapacityExceeded)?;
    if expected_rows > limits.max_generations {
        return Err(TransactionStoreError::CapacityExceeded);
    }
    let persisted_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM generations WHERE transaction_id = ?1",
            params![transaction_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite)?;
    let persisted_rows = u64::try_from(persisted_rows).map_err(|_| {
        TransactionStoreError::Corruption("negative retained generation row count".into())
    })?;
    if persisted_rows != expected_rows {
        return Err(TransactionStoreError::Corruption(
            "retained generation row count disagrees with authenticated current pointer".into(),
        ));
    }

    let mut expected = 0_u64;
    while expected <= current_generation {
        let record = match load_generation(connection, key, transaction_id, expected) {
            Ok(record) => record,
            Err(TransactionStoreError::NotFound) => {
                return Err(TransactionStoreError::Corruption(
                    "retained generation history is not contiguous".into(),
                ));
            }
            Err(error) => return Err(error),
        };
        let state = TransactionState::parse(&record.state)
            .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
        let binding_digest = ContentDigest::new(record.binding_digest.clone())
            .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
        ContentDigest::new(record.request_digest.clone())
            .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
        ContentDigest::new(record.precondition_digest.clone())
            .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
        ContentDigest::new(record.observation_digest.clone())
            .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
        if digest_bytes(
            "linura.authority-binding.digest.v1",
            &record.binding_canonical,
        ) != binding_digest
        {
            return Err(TransactionStoreError::Corruption(
                "stored authority binding digest mismatch".into(),
            ));
        }
        let commit_material = [
            record.desired_state_digest.as_deref(),
            record.graph_digest.as_deref(),
            record.provenance_digest.as_deref(),
        ];
        if matches!(state, TransactionState::Verified | TransactionState::Committed) {
            if commit_material.iter().any(|value| value.is_none()) {
                return Err(TransactionStoreError::Corruption(
                    "verified/committed generation is missing durable commit material".into(),
                ));
            }
            for value in commit_material.into_iter().flatten() {
                ContentDigest::new(value.to_owned())
                    .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
            }
        } else if commit_material.iter().any(|value| value.is_some()) {
            return Err(TransactionStoreError::Corruption(
                "non-verified generation contains durable commit material".into(),
            ));
        }
        if expected < current_generation && state != TransactionState::Aborted {
            return Err(TransactionStoreError::Corruption(
                "historical generation is not safely retired".into(),
            ));
        }
        expected = expected
            .checked_add(1)
            .ok_or(TransactionStoreError::CapacityExceeded)?;
    }
    Ok(())
}

pub(crate) fn validate_audit_chain(
    connection: &Connection,
    key: &SqliteIntegrityKey,
    transaction_id: &TransactionId,
    current_generation: u64,
    state_version: u64,
    limits: StoreLimits,
) -> Result<(), TransactionStoreError> {
    let events = load_all_audit_events(connection, key, transaction_id)?;
    let mut expected_sequence = 0_u64;
    let mut previous = ContentDigest::zero();
    let mut last = None;
    for event in events {
        if event.event_sequence != expected_sequence {
            return Err(TransactionStoreError::Corruption(
                "audit sequence is not contiguous".into(),
            ));
        }
        let payload = ContentDigest::new(event.payload_digest.clone())
            .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
        let stored_previous = ContentDigest::new(event.previous_digest.clone())
            .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
        let stored_digest = ContentDigest::new(event.event_digest.clone())
            .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
        if stored_previous != previous {
            return Err(TransactionStoreError::Corruption(
                "audit previous-digest chain is broken".into(),
            ));
        }
        let expected_digest = audit_digest(
            transaction_id,
            event.event_sequence,
            event.generation,
            event.state_version,
            &event.event_kind,
            &payload,
            &previous,
        );
        if expected_digest != stored_digest {
            return Err(TransactionStoreError::Corruption(
                "audit event digest mismatch".into(),
            ));
        }
        previous = stored_digest;
        last = Some((event.generation, event.state_version, event.event_kind, payload));
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(TransactionStoreError::CapacityExceeded)?;
        if expected_sequence > limits.max_audit_events {
            return Err(TransactionStoreError::CapacityExceeded);
        }
    }
    let (last_generation, last_version, last_kind, last_payload) = last.ok_or_else(|| {
        TransactionStoreError::Corruption("transaction has no audit history".into())
    })?;
    if last_generation != current_generation || last_version != state_version {
        return Err(TransactionStoreError::Corruption(
            "transaction pointer/version disagrees with authenticated audit tail".into(),
        ));
    }
    let (_, generation, snapshot) = load_current(connection, key, transaction_id)?;
    if state_for_event_kind(&last_kind)? != snapshot.state {
        return Err(TransactionStoreError::Corruption(
            "current transaction state disagrees with authenticated audit tail".into(),
        ));
    }
    if snapshot.state == TransactionState::Committed {
        let desired = ContentDigest::new(generation.desired_state_digest.ok_or_else(|| {
            TransactionStoreError::Corruption("committed desired-state digest missing".into())
        })?)
        .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
        let graph = ContentDigest::new(generation.graph_digest.ok_or_else(|| {
            TransactionStoreError::Corruption("committed graph digest missing".into())
        })?)
        .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
        let provenance = ContentDigest::new(generation.provenance_digest.ok_or_else(|| {
            TransactionStoreError::Corruption("committed provenance digest missing".into())
        })?)
        .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?;
        let expected_payload = digest_parts(
            "linura.sqlite.commit-payload.v1",
            [
                desired.as_str().as_bytes(),
                graph.as_str().as_bytes(),
                provenance.as_str().as_bytes(),
            ],
        );
        if last_payload != expected_payload {
            return Err(TransactionStoreError::Corruption(
                "committed provenance digests disagree with audit payload".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn list_transaction_ids(
    connection: &Connection,
) -> Result<Vec<TransactionId>, TransactionStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT length(CAST(transaction_id AS BLOB)),
                    CASE WHEN length(CAST(transaction_id AS BLOB)) BETWEEN 1 AND ?1 THEN transaction_id ELSE NULL END
             FROM transactions ORDER BY transaction_id",
        )
        .map_err(sqlite)?;
    let rows = statement
        .query_map(params![MAX_TRANSACTION_ID_BYTES as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
        })
        .map_err(sqlite)?;
    let mut ids = Vec::new();
    for row in rows {
        let (length, value) = row.map_err(sqlite)?;
        if length <= 0 || length > MAX_TRANSACTION_ID_BYTES as i64 {
            return Err(TransactionStoreError::Corruption(
                "transaction id exceeds persisted byte bound".into(),
            ));
        }
        ids.push(
            TransactionId::new(require_text(value, "transaction id")?)
                .map_err(|error| TransactionStoreError::Corruption(error.to_string()))?,
        );
    }
    Ok(ids)
}

pub(crate) fn reservation_bytes(connection: &Connection) -> Result<u64, TransactionStoreError> {
    page_size(connection)?
        .checked_mul(2)
        .ok_or(TransactionStoreError::CapacityExceeded)
}

pub(crate) fn validate_physical_reservations(
    connection: &Connection,
    key: &SqliteIntegrityKey,
) -> Result<(), TransactionStoreError> {
    let expected_bytes = reservation_bytes(connection)?;
    let ids = list_transaction_ids(connection)?;
    let mut expected_total = 0_u64;
    for id in ids {
        let (_, _, snapshot) = load_current(connection, key, &id)?;
        let expected = u64::from(matches!(
            snapshot.state,
            TransactionState::Prepared | TransactionState::Indeterminate | TransactionState::Verified
        ));
        expected_total = expected_total
            .checked_add(expected)
            .ok_or(TransactionStoreError::CapacityExceeded)?;
        let mut statement = connection
            .prepare(
                "SELECT slot, length(reserved) FROM audit_reservations
                 WHERE transaction_id = ?1 ORDER BY slot",
            )
            .map_err(sqlite)?;
        let rows = statement
            .query_map(params![id.as_str()], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(sqlite)?;
        let mut count = 0_u64;
        for row in rows {
            let (slot, length) = row.map_err(sqlite)?;
            if u64::try_from(slot).ok() != Some(count)
                || u64::try_from(length).ok() != Some(expected_bytes)
            {
                return Err(TransactionStoreError::Corruption(
                    "physical audit reservation is malformed".into(),
                ));
            }
            count = count
                .checked_add(1)
                .ok_or(TransactionStoreError::CapacityExceeded)?;
        }
        if count != expected {
            return Err(TransactionStoreError::Corruption(
                "physical audit reservation count disagrees with current state".into(),
            ));
        }
    }
    let actual_total: i64 = connection
        .query_row("SELECT COUNT(*) FROM audit_reservations", [], |row| row.get(0))
        .map_err(sqlite)?;
    if u64::try_from(actual_total).ok() != Some(expected_total) {
        return Err(TransactionStoreError::Corruption(
            "aggregate physical audit reservation count mismatch".into(),
        ));
    }
    Ok(())
}

pub(crate) fn audit_digest(
    transaction_id: &TransactionId,
    sequence: u64,
    generation: u64,
    state_version: u64,
    event_kind: &str,
    payload_digest: &ContentDigest,
    previous_digest: &ContentDigest,
) -> ContentDigest {
    let sequence = sequence.to_string();
    let generation = generation.to_string();
    let state_version = state_version.to_string();
    digest_parts(
        "linura.sqlite.audit-event.v1",
        [
            transaction_id.as_str().as_bytes(),
            sequence.as_bytes(),
            generation.as_bytes(),
            state_version.as_bytes(),
            event_kind.as_bytes(),
            payload_digest.as_str().as_bytes(),
            previous_digest.as_str().as_bytes(),
        ],
    )
}

pub(crate) fn state_for_event_kind(
    kind: &str,
) -> Result<TransactionState, TransactionStoreError> {
    match kind {
        "prepared" | "recovery-reprepared" => Ok(TransactionState::Prepared),
        "handoff-indeterminate" | "recovery-ambiguous" => Ok(TransactionState::Indeterminate),
        "recovery-verified" => Ok(TransactionState::Verified),
        "committed" => Ok(TransactionState::Committed),
        "aborted-prepared" | "recovery-retired-no-effect" => Ok(TransactionState::Aborted),
        "recovery-blocked" => Ok(TransactionState::RecoveryBlocked),
        _ => Err(TransactionStoreError::Corruption(format!(
            "unknown audit event kind {kind:?}"
        ))),
    }
}

pub(crate) fn migration_checksum() -> ContentDigest {
    digest_bytes("linura.sqlite.migration.v1", MIGRATION_V1.as_bytes())
}

pub(crate) fn pragma_i64(
    connection: &Connection,
    name: &str,
) -> Result<i64, TransactionStoreError> {
    connection
        .pragma_query_value(None, name, |row| row.get(0))
        .map_err(sqlite)
}

pub(crate) fn pragma_string(
    connection: &Connection,
    name: &str,
) -> Result<String, TransactionStoreError> {
    connection
        .pragma_query_value(None, name, |row| row.get(0))
        .map_err(sqlite)
}

pub(crate) fn page_size(connection: &Connection) -> Result<u64, TransactionStoreError> {
    let value = pragma_i64(connection, "page_size")?;
    u64::try_from(value)
        .map_err(|_| TransactionStoreError::UnsupportedSchema("negative page_size".into()))
}

pub(crate) fn as_i64(value: u64) -> Result<i64, TransactionStoreError> {
    i64::try_from(value).map_err(|_| TransactionStoreError::CapacityExceeded)
}

pub(crate) fn sqlite(error: rusqlite::Error) -> TransactionStoreError {
    if let rusqlite::Error::SqliteFailure(code, _) = &error
        && code.code == rusqlite::ErrorCode::DiskFull
    {
        return TransactionStoreError::CapacityExceeded;
    }
    TransactionStoreError::Storage(error.to_string())
}

fn require_text(value: Option<String>, label: &str) -> Result<String, TransactionStoreError> {
    value.ok_or_else(|| {
        TransactionStoreError::Corruption(format!("{label} withheld by byte-length preflight"))
    })
}

fn require_blob(value: Option<Vec<u8>>, label: &str) -> Result<Vec<u8>, TransactionStoreError> {
    value.ok_or_else(|| {
        TransactionStoreError::Corruption(format!("{label} withheld by byte-length preflight"))
    })
}

fn optional_digest_length_valid(length: i64) -> bool {
    length == -1 || length == CONTENT_DIGEST_TEXT_BYTES as i64
}

fn optional_digest_value(
    length: i64,
    value: Option<String>,
    label: &str,
) -> Result<Option<String>, TransactionStoreError> {
    if length == -1 {
        return Ok(None);
    }
    if length != CONTENT_DIGEST_TEXT_BYTES as i64 {
        return Err(TransactionStoreError::Corruption(format!(
            "{label} has invalid persisted byte length"
        )));
    }
    Ok(Some(require_text(value, label)?))
}

pub(crate) fn check_logical_audit_reserve(
    transaction: &Transaction<'_>,
    limits: StoreLimits,
    additional_events: u64,
    nonterminal_delta: i64,
) -> Result<(), TransactionStoreError> {
    let audit_count: i64 = transaction
        .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
        .map_err(sqlite)?;
    let nonterminal_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM transactions t
             JOIN generations g ON g.transaction_id=t.transaction_id
              AND g.generation=t.current_generation
             WHERE g.state IN ('prepared','indeterminate','verified')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite)?;
    let audit_count = u64::try_from(audit_count)
        .map_err(|_| TransactionStoreError::Corruption("negative audit row count".into()))?;
    let nonterminal_count = u64::try_from(nonterminal_count).map_err(|_| {
        TransactionStoreError::Corruption("negative nonterminal transaction count".into())
    })?;
    let resulting_nonterminal = if nonterminal_delta >= 0 {
        nonterminal_count
            .checked_add(u64::try_from(nonterminal_delta).map_err(|_| {
                TransactionStoreError::CapacityExceeded
            })?)
            .ok_or(TransactionStoreError::CapacityExceeded)?
    } else {
        nonterminal_count
            .checked_sub(nonterminal_delta.unsigned_abs())
            .ok_or_else(|| {
                TransactionStoreError::Corruption("nonterminal reserve underflow".into())
            })?
    };
    let required = audit_count
        .checked_add(additional_events)
        .and_then(|value| value.checked_add(resulting_nonterminal))
        .ok_or(TransactionStoreError::CapacityExceeded)?;
    if required > limits.max_audit_events {
        return Err(TransactionStoreError::CapacityExceeded);
    }
    Ok(())
}

pub(crate) fn check_count_capacity(
    transaction: &Transaction<'_>,
    table: &str,
    maximum: u64,
    additional: u64,
) -> Result<(), TransactionStoreError> {
    let query = match table {
        "transactions" => "SELECT COUNT(*) FROM transactions",
        "generations" => "SELECT COUNT(*) FROM generations",
        "audit_events" => "SELECT COUNT(*) FROM audit_events",
        _ => {
            return Err(TransactionStoreError::Corruption(
                "unknown capacity table".into(),
            ));
        }
    };
    let count: i64 = transaction
        .query_row(query, [], |row| row.get(0))
        .map_err(sqlite)?;
    let count = u64::try_from(count)
        .map_err(|_| TransactionStoreError::Corruption("negative row count".into()))?;
    if count.saturating_add(additional) > maximum {
        return Err(TransactionStoreError::CapacityExceeded);
    }
    Ok(())
}
