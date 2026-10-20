//! Independent write-once request retention; does not change the released
//! transaction schema or reconstruct any approval/dispatch credential.

use std::fmt::{Debug, Formatter};
use std::path::Path;
use std::time::Duration;

use linura_core::{PrincipalId, RequestId};
use linura_transaction::{
    ApprovedRequestJournal, RETAINED_REQUEST_FORMAT, RetainedRequest, TransactionStoreError,
    digest_bytes,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};

use crate::integrity::{SqliteIntegrityKey, canonical_field};
use crate::validation::sqlite;

const APPLICATION_ID: i64 = 0x4c4e5251; // LNRQ, distinct from transaction LNRT.
const SCHEMA: &str = include_str!("request_journal_schema.sql");
const MAX_REQUESTS: i64 = 4096;
const MAX_PAGES: i64 = 8192;
const RECORD_DOMAIN: &str = "linura.sqlite.retained-request.v1";
const IDENTITY_DOMAIN: &str = "linura.sqlite.request-journal-identity.v1";

pub struct SqliteApprovedRequestJournal {
    connection: Connection,
    integrity_key: SqliteIntegrityKey,
}

impl Debug for SqliteApprovedRequestJournal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteApprovedRequestJournal")
            .finish_non_exhaustive()
    }
}

fn corrupt() -> TransactionStoreError {
    TransactionStoreError::Corruption("approved request journal validation failed".into())
}

impl SqliteApprovedRequestJournal {
    /// The composition root must protect the directory and this independently
    /// provisioned integrity key exactly like its transaction authority store.
    /// No transaction migration or orphan journal entry grants effect authority.
    pub fn open(
        path: impl AsRef<Path>,
        integrity_key: SqliteIntegrityKey,
    ) -> Result<Self, TransactionStoreError> {
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(sqlite)?;
        connection
            .busy_timeout(Duration::from_millis(500))
            .map_err(sqlite)?;
        // Refuse foreign schemas before applying persistent journal settings.
        let application: i64 = connection
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(sqlite)?;
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(sqlite)?;
        let objects: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )
            .map_err(sqlite)?;
        if !((application == 0 && version == 0 && objects == 0)
            || (application == APPLICATION_ID && version == 1))
        {
            return Err(corrupt());
        }
        connection.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=128; PRAGMA journal_size_limit=524288;").map_err(sqlite)?;
        let mode: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(sqlite)?;
        if mode != "wal" {
            return Err(corrupt());
        }
        connection
            .pragma_update(None, "max_page_count", MAX_PAGES)
            .map_err(sqlite)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite)?;
        if application == 0 {
            // Recheck under the writer lock: concurrent creators cannot replace
            // identity or silently claim another initialized database.
            let current: i64 = transaction
                .pragma_query_value(None, "application_id", |r| r.get(0))
                .map_err(sqlite)?;
            if current != 0 {
                return Err(corrupt());
            }
            transaction.execute_batch(SCHEMA).map_err(sqlite)?;
            transaction
                .pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(sqlite)?;
            transaction
                .pragma_update(None, "user_version", 1)
                .map_err(sqlite)?;
            let (fingerprint, schema, canonical) = identity_material(&integrity_key);
            transaction
                .execute(
                    "INSERT INTO request_journal_identity VALUES (1,1,?1,?2,?3)",
                    params![
                        fingerprint,
                        schema,
                        integrity_key.tag(IDENTITY_DOMAIN, &canonical)?.as_slice()
                    ],
                )
                .map_err(sqlite)?;
        }
        validate_identity(&transaction, &integrity_key)?;
        transaction.commit().map_err(sqlite)?;
        let journal = Self {
            connection,
            integrity_key,
        };
        journal.integrity_check()?;
        Ok(journal)
    }
}

fn identity_material(key: &SqliteIntegrityKey) -> (String, String, Vec<u8>) {
    let fingerprint = key.fingerprint().as_str().to_owned();
    let schema = digest_bytes("linura.sqlite.request-journal-schema.v1", SCHEMA.as_bytes())
        .as_str()
        .to_owned();
    let mut canonical = Vec::new();
    canonical_field(&mut canonical, &RETAINED_REQUEST_FORMAT.to_be_bytes());
    canonical_field(&mut canonical, fingerprint.as_bytes());
    canonical_field(&mut canonical, schema.as_bytes());
    (fingerprint, schema, canonical)
}

type SchemaObject = (String, String, String, String);

fn schema_objects(connection: &Connection) -> Result<Vec<SchemaObject>, TransactionStoreError> {
    let mut statement = connection
        .prepare("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name LIMIT 4")
        .map_err(sqlite)?;
    let rows = statement
        .query_map([], |row| {
            for index in 0..4 {
                if row.get_ref(index)?.as_bytes()?.len() > 16384 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite)
}

fn validate_identity(
    connection: &Connection,
    key: &SqliteIntegrityKey,
) -> Result<(), TransactionStoreError> {
    let reference = Connection::open_in_memory().map_err(sqlite)?;
    reference.execute_batch(SCHEMA).map_err(sqlite)?;
    if schema_objects(connection)? != schema_objects(&reference)? {
        return Err(corrupt());
    }
    let application: i64 = connection
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(sqlite)?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(sqlite)?;
    let synchronous: i64 = connection
        .pragma_query_value(None, "synchronous", |r| r.get(0))
        .map_err(sqlite)?;
    let trusted: i64 = connection
        .pragma_query_value(None, "trusted_schema", |r| r.get(0))
        .map_err(sqlite)?;
    let pages: i64 = connection
        .pragma_query_value(None, "page_count", |r| r.get(0))
        .map_err(sqlite)?;
    let page_size: i64 = connection
        .pragma_query_value(None, "page_size", |r| r.get(0))
        .map_err(sqlite)?;
    let max_pages: i64 = connection
        .pragma_query_value(None, "max_page_count", |r| r.get(0))
        .map_err(sqlite)?;
    let mode: String = connection
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .map_err(sqlite)?;
    if application != APPLICATION_ID
        || version != 1
        || synchronous != 2
        || trusted != 0
        || pages > MAX_PAGES
        || page_size > 4096
        || max_pages != MAX_PAGES
        || mode != "wal"
    {
        return Err(corrupt());
    }
    let identities: i64 = connection
        .query_row("SELECT count(*) FROM request_journal_identity", [], |r| {
            r.get(0)
        })
        .map_err(sqlite)?;
    if identities != 1 {
        return Err(corrupt());
    }
    let (expected_fingerprint, expected_schema, canonical) = identity_material(key);
    let valid = connection.query_row("SELECT format,integrity_fingerprint,schema_digest,integrity_tag FROM request_journal_identity WHERE singleton=1", [], |r| {
        Ok(r.get::<_, i64>(0)? == 1
            && r.get_ref(1)?.as_str()? == expected_fingerprint
            && r.get_ref(2)?.as_str()? == expected_schema
            && key.verify(IDENTITY_DOMAIN, &canonical, r.get_ref(3)?.as_blob()?))
    }).map_err(sqlite)?;
    let count: i64 = connection
        .query_row("SELECT count(*) FROM retained_requests", [], |r| r.get(0))
        .map_err(sqlite)?;
    if !valid || count > MAX_REQUESTS {
        return Err(corrupt());
    }
    Ok(())
}

fn record_material(record: &RetainedRequest) -> Vec<u8> {
    let mut canonical = Vec::new();
    canonical_field(&mut canonical, &RETAINED_REQUEST_FORMAT.to_be_bytes());
    canonical_field(&mut canonical, record.principal().as_str().as_bytes());
    canonical_field(&mut canonical, record.request_id().as_str().as_bytes());
    canonical_field(&mut canonical, record.digest().as_str().as_bytes());
    canonical_field(&mut canonical, record.canonical());
    canonical
}

fn load_record(
    connection: &Connection,
    key: &SqliteIntegrityKey,
    principal: &PrincipalId,
    request_id: &RequestId,
) -> Result<Option<RetainedRequest>, TransactionStoreError> {
    connection.query_row("SELECT format,CASE WHEN length(canonical) BETWEEN 1 AND 262144 THEN canonical ELSE NULL END,CASE WHEN length(CAST(request_digest AS BLOB))=71 THEN request_digest ELSE NULL END,CASE WHEN length(integrity_tag)=32 THEN integrity_tag ELSE NULL END FROM retained_requests WHERE principal=?1 AND request_id=?2",
        params![principal.as_str(), request_id.as_str()], |row| {
            let bytes = row.get_ref(1)?.as_blob()?;
            let digest = row.get_ref(2)?.as_str()?;
            let tag = row.get_ref(3)?.as_blob()?;
            if row.get::<_, i64>(0)? != 1 || bytes.is_empty()
                || bytes.len() > linura_transaction::MAX_RETAINED_REQUEST_BYTES || digest.len() != 71 || tag.len() != 32 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let record = RetainedRequest::new(principal.clone(), request_id.clone(), bytes.to_vec())
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            if record.digest().as_str() != digest || !key.verify(RECORD_DOMAIN, &record_material(&record), tag) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(record)
        }).optional().map_err(|_| corrupt())
}

impl ApprovedRequestJournal for SqliteApprovedRequestJournal {
    fn retain(&mut self, request: &RetainedRequest) -> Result<(), TransactionStoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite)?;
        validate_identity(&transaction, &self.integrity_key)?;
        if let Some(existing) = load_record(
            &transaction,
            &self.integrity_key,
            request.principal(),
            request.request_id(),
        )? {
            if &existing != request {
                return Err(TransactionStoreError::IdempotencyConflict);
            }
        } else {
            let count: i64 = transaction
                .query_row("SELECT count(*) FROM retained_requests", [], |r| r.get(0))
                .map_err(sqlite)?;
            if count >= MAX_REQUESTS {
                return Err(TransactionStoreError::CapacityExceeded);
            }
            let tag = self
                .integrity_key
                .tag(RECORD_DOMAIN, &record_material(request))?;
            transaction
                .execute(
                    "INSERT INTO retained_requests VALUES (?1,?2,1,?3,?4,?5)",
                    params![
                        request.principal().as_str(),
                        request.request_id().as_str(),
                        request.canonical(),
                        request.digest().as_str(),
                        tag.as_slice()
                    ],
                )
                .map_err(sqlite)?;
        }
        transaction.commit().map_err(sqlite)
    }

    fn load(
        &self,
        principal: &PrincipalId,
        request_id: &RequestId,
    ) -> Result<RetainedRequest, TransactionStoreError> {
        let transaction = self.connection.unchecked_transaction().map_err(sqlite)?;
        validate_identity(&transaction, &self.integrity_key)?;
        load_record(&transaction, &self.integrity_key, principal, request_id)?
            .ok_or(TransactionStoreError::NotFound)
    }

    fn integrity_check(&self) -> Result<(), TransactionStoreError> {
        let transaction = self.connection.unchecked_transaction().map_err(sqlite)?;
        validate_identity(&transaction, &self.integrity_key)?;
        let check: String = transaction
            .query_row("PRAGMA integrity_check(1)", [], |r| r.get(0))
            .map_err(sqlite)?;
        if check != "ok" {
            return Err(corrupt());
        }
        let mut statement = transaction
            .prepare("SELECT principal,request_id FROM retained_requests LIMIT 4097")
            .map_err(sqlite)?;
        let rows = statement
            .query_map([], |row| {
                let principal = row.get_ref(0)?.as_str()?;
                let request = row.get_ref(1)?.as_str()?;
                if principal.len() > 256 || request.len() > 256 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok((principal.to_owned(), request.to_owned()))
            })
            .map_err(sqlite)?;
        for row in rows {
            let (principal, request) = row.map_err(sqlite)?;
            let principal = PrincipalId::new(principal).map_err(|_| corrupt())?;
            let request = RequestId::new(request).map_err(|_| corrupt())?;
            load_record(&transaction, &self.integrity_key, &principal, &request)?
                .ok_or_else(corrupt)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Database {
        root: PathBuf,
        path: PathBuf,
    }

    impl Database {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "linura-approved-request-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap_or_else(|e| unreachable!("{e}"));
            let path = root.join("requests.sqlite3");
            Self { root, path }
        }
        fn open(&self) -> SqliteApprovedRequestJournal {
            SqliteApprovedRequestJournal::open(&self.path, key(0x61))
                .unwrap_or_else(|e| unreachable!("{e}"))
        }
    }

    impl Drop for Database {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn key(byte: u8) -> SqliteIntegrityKey {
        SqliteIntegrityKey::new(vec![byte; 32]).unwrap_or_else(|e| unreachable!("{e}"))
    }

    fn record(principal: &str, request: &str, bytes: &[u8]) -> RetainedRequest {
        RetainedRequest::new(
            PrincipalId::new(principal).unwrap_or_else(|e| unreachable!("{e}")),
            RequestId::new(request).unwrap_or_else(|e| unreachable!("{e}")),
            bytes.to_vec(),
        )
        .unwrap_or_else(|e| unreachable!("{e}"))
    }

    #[test]
    fn restart_retains_exact_material_without_granting_authority() {
        let database = Database::new();
        let request = record(
            "unix:uid:1000",
            "request:s17:a",
            b"structured request, not approval",
        );
        {
            let mut journal = database.open();
            assert!(journal.retain(&request).is_ok());
            assert!(journal.retain(&request).is_ok());
        }
        let journal = database.open();
        assert_eq!(
            journal.load(request.principal(), request.request_id()),
            Ok(request)
        );
        assert!(journal.integrity_check().is_ok());
    }

    #[test]
    fn principal_namespaces_do_not_alias_and_identity_reuse_is_not_an_update() {
        let database = Database::new();
        let mut journal = database.open();
        let original = record("unix:uid:1000", "request:s17:a", b"lock");
        let replaced = record("unix:uid:1000", "request:s17:a", b"unlock");
        let other = record("unix:uid:1001", "request:s17:a", b"different owner");
        assert!(journal.retain(&original).is_ok());
        assert_eq!(
            journal.retain(&replaced),
            Err(TransactionStoreError::IdempotencyConflict)
        );
        assert_eq!(
            journal.load(other.principal(), other.request_id()),
            Err(TransactionStoreError::NotFound)
        );
        assert!(journal.retain(&other).is_ok());
        assert_eq!(
            journal.load(original.principal(), original.request_id()),
            Ok(original)
        );
        assert_eq!(
            journal.load(other.principal(), other.request_id()),
            Ok(other)
        );
    }

    #[test]
    fn wrong_key_and_unknown_schema_are_rejected_not_reinitialized() {
        let database = Database::new();
        drop(database.open());
        assert!(SqliteApprovedRequestJournal::open(&database.path, key(0x62)).is_err());
        let raw = Connection::open(&database.path).unwrap_or_else(|e| unreachable!("{e}"));
        raw.pragma_update(None, "user_version", 2)
            .unwrap_or_else(|e| unreachable!("{e}"));
        drop(raw);
        assert!(SqliteApprovedRequestJournal::open(&database.path, key(0x61)).is_err());
    }

    #[test]
    fn unidentified_existing_database_is_preserved() {
        let database = Database::new();
        let raw = Connection::open(&database.path).unwrap_or_else(|e| unreachable!("{e}"));
        raw.execute_batch(
            "CREATE TABLE foreign_data(value TEXT); INSERT INTO foreign_data VALUES ('preserve');",
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(SqliteApprovedRequestJournal::open(&database.path, key(0x61)).is_err());
        let value: String = raw
            .query_row("SELECT value FROM foreign_data", [], |r| r.get(0))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(value, "preserve");
    }

    #[test]
    fn every_record_field_is_authenticated_and_missing_rows_are_not_success() {
        for sql in [
            "UPDATE retained_requests SET canonical=x'756e6c6f636b'",
            "UPDATE retained_requests SET request_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000'",
            "UPDATE retained_requests SET principal='unix:uid:1001'",
            "UPDATE retained_requests SET request_id='request:s17:b'",
            "UPDATE retained_requests SET integrity_tag=zeroblob(32)",
            "DELETE FROM retained_requests",
        ] {
            let database = Database::new();
            let mut journal = database.open();
            let request = record("unix:uid:1000", "request:s17:a", b"lock");
            assert!(journal.retain(&request).is_ok());
            journal
                .connection
                .execute_batch(sql)
                .unwrap_or_else(|e| unreachable!("{e}"));
            assert!(
                journal
                    .load(request.principal(), request.request_id())
                    .is_err()
            );
            if !sql.starts_with("DELETE") {
                assert!(journal.integrity_check().is_err());
            }
        }
    }

    #[test]
    fn extra_triggers_views_or_tables_fail_closed_before_writing() {
        for sql in [
            "CREATE TRIGGER malicious AFTER INSERT ON retained_requests BEGIN DELETE FROM retained_requests; END;",
            "CREATE VIEW alias AS SELECT * FROM retained_requests;",
            "CREATE TABLE another(value BLOB);",
        ] {
            let database = Database::new();
            let mut journal = database.open();
            journal
                .connection
                .execute_batch(sql)
                .unwrap_or_else(|e| unreachable!("{e}"));
            assert!(
                journal
                    .retain(&record("unix:uid:1000", "request:s17:a", b"lock"))
                    .is_err()
            );
            assert!(journal.integrity_check().is_err());
        }
    }

    #[test]
    fn authenticated_identity_and_durability_settings_are_revalidated() {
        for sql in [
            "UPDATE request_journal_identity SET integrity_tag=zeroblob(32)",
            "DELETE FROM request_journal_identity",
            "PRAGMA synchronous=OFF",
            "PRAGMA trusted_schema=ON",
            "PRAGMA max_page_count=9000",
        ] {
            let database = Database::new();
            let mut journal = database.open();
            journal
                .connection
                .execute_batch(sql)
                .unwrap_or_else(|e| unreachable!("{e}"));
            assert!(
                journal
                    .retain(&record("unix:uid:1000", "request:s17:a", b"lock"))
                    .is_err()
            );
        }
    }

    #[test]
    fn oversized_and_unsupported_material_is_bounded_before_copy() {
        let database = Database::new();
        let mut journal = database.open();
        let request = record("unix:uid:1000", "request:s17:a", b"lock");
        assert!(journal.retain(&request).is_ok());
        journal.connection.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE retained_requests SET canonical=zeroblob(262145);").unwrap_or_else(|e| unreachable!("{e}"));
        assert!(
            journal
                .load(request.principal(), request.request_id())
                .is_err()
        );
        assert!(journal.integrity_check().is_err());
    }

    #[test]
    fn capacity_failure_does_not_leave_a_partially_retained_request() {
        let database = Database::new();
        let mut journal = database.open();
        // Fill the actual production page budget, without lowering a guard or
        // confusing a rejected runtime setting with a failed SQLite write.
        let payload = vec![0x42; 256 * 1024];
        let mut failure = None;
        for index in 0..200 {
            let request = record("unix:uid:1000", &format!("request:s17:{index}"), &payload);
            if let Err(error) = journal.retain(&request) {
                // The existing persistence mapper classifies SQLITE_FULL as
                // CapacityExceeded, not a generic Storage diagnostic.
                assert_eq!(error, TransactionStoreError::CapacityExceeded);
                failure = Some(request);
                break;
            }
        }
        let request = failure.unwrap_or_else(|| unreachable!("expected SQLITE_FULL"));
        assert_eq!(
            journal.load(request.principal(), request.request_id()),
            Err(TransactionStoreError::NotFound)
        );
        assert!(journal.integrity_check().is_ok());
        drop(journal);
        assert_eq!(
            database
                .open()
                .load(request.principal(), request.request_id()),
            Err(TransactionStoreError::NotFound)
        );
    }

    #[test]
    fn sqlite_symlink_target_is_not_followed() {
        let database = Database::new();
        let target = database.root.join("target.sqlite3");
        let raw = Connection::open(&target).unwrap_or_else(|e| unreachable!("{e}"));
        raw.execute_batch("CREATE TABLE original(value TEXT);")
            .unwrap_or_else(|e| unreachable!("{e}"));
        std::os::unix::fs::symlink(&target, &database.path).unwrap_or_else(|e| unreachable!("{e}"));
        assert!(SqliteApprovedRequestJournal::open(&database.path, key(0x61)).is_err());
    }
}
