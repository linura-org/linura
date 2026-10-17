//! Separate S17 local policy journal. Neither the released transaction schema
//! nor write-once managed request retention is reused as configuration state.
//! All writes require a separately keyed Control seal. An authenticated global
//! chain tip detects row/suffix deletion; protected whole-file rollback remains
//! a filesystem/recovery boundary, not something HMACs alone can prevent.

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use linura_core::{PrincipalId, SessionEpoch};
use linura_transaction::{
    ContentDigest, ProtectiveLockSettingRecord, ProtectiveLockSettingStore,
    ProtectiveLockSettingUpdate, TransactionAuthorityVerifier, TransactionStoreError, digest_bytes,
    digest_parts,
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};

use crate::integrity::{SqliteIntegrityKey, canonical_field};
use crate::validation::sqlite;

const APPLICATION_ID: i64 = 0x4c4e5250; // LNRP, not LNRT or LNRQ.
const SCHEMA: &str = include_str!("protective_lock_settings_schema.sql");
const MAX_RECORDS: u64 = 4096;
const MAX_PAGES: i64 = 8192;
const IDENTITY_DOMAIN: &str = "linura.sqlite.protective-lock-identity.v1";
const RECORD_DOMAIN: &str = "linura.sqlite.protective-lock-record.v1";

pub struct SqliteProtectiveLockSettingStore {
    connection: Connection,
    integrity_key: SqliteIntegrityKey,
    authority: TransactionAuthorityVerifier,
}

impl Debug for SqliteProtectiveLockSettingStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteProtectiveLockSettingStore")
            .finish_non_exhaustive()
    }
}

fn corrupt() -> TransactionStoreError {
    TransactionStoreError::Corruption("protective-lock policy journal validation failed".into())
}

fn now() -> Result<u64, TransactionStoreError> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TransactionStoreError::AuthorityRejected)?
        .as_millis();
    let value = u64::try_from(value).map_err(|_| TransactionStoreError::AuthorityRejected)?;
    if value == 0 || value > i64::MAX as u64 {
        return Err(TransactionStoreError::AuthorityRejected);
    }
    Ok(value)
}

#[derive(Debug)]
struct Snapshot {
    count: u64,
    tip: ContentDigest,
    last_write: u64,
    records: Vec<ProtectiveLockSettingRecord>,
}

impl Snapshot {
    fn current(
        &self,
        owner: &PrincipalId,
        epoch: &SessionEpoch,
    ) -> Option<&ProtectiveLockSettingRecord> {
        self.records
            .iter()
            .rev()
            .find(|record| record.owner() == owner && record.epoch() == epoch)
    }
}

impl SqliteProtectiveLockSettingStore {
    /// Creation requires an empty database and a protected directory. Restart
    /// requires the same independent integrity and local-policy authority keys.
    /// Unknown schemas, wrong keys, corruption and capacity exhaustion fail closed.
    pub fn open(
        path: impl AsRef<Path>,
        integrity_key: SqliteIntegrityKey,
        authority: TransactionAuthorityVerifier,
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
            let current: i64 = transaction
                .pragma_query_value(None, "application_id", |r| r.get(0))
                .map_err(sqlite)?;
            let objects: i64 = transaction
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                    [],
                    |r| r.get(0),
                )
                .map_err(sqlite)?;
            if current != 0 || objects != 0 {
                return Err(corrupt());
            }
            transaction.execute_batch(SCHEMA).map_err(sqlite)?;
            transaction
                .pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(sqlite)?;
            transaction
                .pragma_update(None, "user_version", 1)
                .map_err(sqlite)?;
            let snapshot = Snapshot {
                count: 0,
                tip: ContentDigest::zero(),
                last_write: 0,
                records: Vec::new(),
            };
            write_identity(&transaction, &integrity_key, &authority, &snapshot, true)?;
        }
        validate(&transaction, &integrity_key, &authority)?;
        transaction.commit().map_err(sqlite)?;
        let store = Self {
            connection,
            integrity_key,
            authority,
        };
        store.integrity_check()?;
        Ok(store)
    }

    #[cfg(test)]
    fn apply_at(
        &mut self,
        update: &ProtectiveLockSettingUpdate,
        sampled: u64,
    ) -> Result<ProtectiveLockSettingRecord, TransactionStoreError> {
        self.apply_with_clock(update, || Ok(sampled))
    }

    fn apply_with_clock(
        &mut self,
        update: &ProtectiveLockSettingUpdate,
        mut clock: impl FnMut() -> Result<u64, TransactionStoreError>,
    ) -> Result<ProtectiveLockSettingRecord, TransactionStoreError> {
        if !self.authority.verify_protective_lock_setting(update) {
            return Err(TransactionStoreError::AuthorityRejected);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite)?;
        let mut snapshot = validate(&transaction, &self.integrity_key, &self.authority)?;
        let record = update.record();
        if let Some(existing) = snapshot.records.iter().find(|existing| {
            existing.owner() == record.owner() && existing.request() == record.request()
        }) {
            if existing != record {
                return Err(TransactionStoreError::IdempotencyConflict);
            }
            // A retry returns only its historical receipt. Never rewrite the
            // tip/current setting, even when a later record revoked the grant.
            return Ok(existing.clone());
        }
        let sampled = clock()?;
        if sampled == 0
            || sampled < snapshot.last_write
            || sampled < record.confirmed_at_unix_ms()
            || sampled >= update.expires_at_unix_ms()
        {
            return Err(TransactionStoreError::AuthorityRejected);
        }
        if snapshot
            .current(record.owner(), record.epoch())
            .map(ProtectiveLockSettingRecord::digest)
            != record.previous()
        {
            return Err(TransactionStoreError::StateConflict);
        }
        if snapshot.count >= MAX_RECORDS {
            return Err(TransactionStoreError::CapacityExceeded);
        }
        let position = snapshot.count + 1;
        let chain = chain_digest(position, &snapshot.tip, record.digest());
        let tag = self.integrity_key.tag(
            RECORD_DOMAIN,
            &record_material(
                position,
                record,
                &chain,
                update.expires_at_unix_ms(),
                update.authentication_tag(),
            ),
        )?;
        transaction
            .execute(
                "INSERT INTO protective_lock_records VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    position,
                    record.owner().as_str(),
                    record
                        .epoch()
                        .resource_id()
                        .map_err(|_| corrupt())?
                        .as_str(),
                    record.request().as_str(),
                    record.canonical(),
                    record.digest().as_str(),
                    chain.as_str(),
                    update.expires_at_unix_ms(),
                    update.authentication_tag(),
                    tag.as_slice(),
                ],
            )
            .map_err(sqlite)?;
        snapshot.count = position;
        snapshot.tip = chain;
        snapshot.last_write = sampled;
        write_identity(
            &transaction,
            &self.integrity_key,
            &self.authority,
            &snapshot,
            false,
        )?;
        // Re-validate bytes and lineage inside the same atomic write before
        // committing. Failure/ENOSPC never records a successful configuration.
        validate(&transaction, &self.integrity_key, &self.authority)?;
        let final_sample = clock()?;
        if final_sample < sampled || final_sample >= update.expires_at_unix_ms() {
            return Err(TransactionStoreError::AuthorityRejected);
        }
        transaction.commit().map_err(sqlite)?;
        Ok(record.clone())
    }
}

fn chain_digest(position: u64, previous: &ContentDigest, record: &ContentDigest) -> ContentDigest {
    digest_parts(
        "linura.sqlite.protective-lock-chain.v1",
        [
            position.to_be_bytes().as_slice(),
            previous.as_str().as_bytes(),
            record.as_str().as_bytes(),
        ],
    )
}

fn record_material(
    position: u64,
    record: &ProtectiveLockSettingRecord,
    chain: &ContentDigest,
    expiry: u64,
    authority_tag: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    canonical_field(&mut bytes, &position.to_be_bytes());
    canonical_field(&mut bytes, record.canonical());
    canonical_field(&mut bytes, record.digest().as_str().as_bytes());
    canonical_field(&mut bytes, chain.as_str().as_bytes());
    canonical_field(&mut bytes, &expiry.to_be_bytes());
    canonical_field(&mut bytes, authority_tag);
    bytes
}

fn identity_material(
    key: &SqliteIntegrityKey,
    authority: &TransactionAuthorityVerifier,
    snapshot: &Snapshot,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [
        key.fingerprint(),
        authority.fingerprint(),
        digest_bytes("linura.sqlite.protective-lock-schema.v1", SCHEMA.as_bytes()),
    ] {
        canonical_field(&mut bytes, value.as_str().as_bytes());
    }
    canonical_field(&mut bytes, &snapshot.count.to_be_bytes());
    canonical_field(&mut bytes, snapshot.tip.as_str().as_bytes());
    canonical_field(&mut bytes, &snapshot.last_write.to_be_bytes());
    bytes
}

fn write_identity(
    connection: &Connection,
    key: &SqliteIntegrityKey,
    authority: &TransactionAuthorityVerifier,
    snapshot: &Snapshot,
    create: bool,
) -> Result<(), TransactionStoreError> {
    let tag = key.tag(
        IDENTITY_DOMAIN,
        &identity_material(key, authority, snapshot),
    )?;
    let affected = if create {
        connection.execute("INSERT INTO protective_lock_identity VALUES (1,?1,?2,?3,?4,?5,?6,?7)", params![
            key.fingerprint().as_str(), authority.fingerprint().as_str(), digest_bytes("linura.sqlite.protective-lock-schema.v1", SCHEMA.as_bytes()).as_str(),
            snapshot.count, snapshot.tip.as_str(), snapshot.last_write, tag.as_slice(),
        ])
    } else {
        connection.execute("UPDATE protective_lock_identity SET record_count=?1,chain_tip=?2,last_write_unix_ms=?3,integrity_tag=?4 WHERE singleton=1", params![
            snapshot.count, snapshot.tip.as_str(), snapshot.last_write, tag.as_slice(),
        ])
    }.map_err(sqlite)?;
    if affected != 1 {
        return Err(corrupt());
    }
    Ok(())
}

type SchemaObject = (String, String, String, String);
fn schema_objects(connection: &Connection) -> Result<Vec<SchemaObject>, TransactionStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_schema ORDER BY name LIMIT 5",
        )
        .map_err(sqlite)?;
    let rows = statement
        .query_map([], |r| {
            for index in 0..4 {
                if r.get_ref(index)?.as_bytes()?.len() > 16384 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .map_err(sqlite)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite)
}

fn validate(
    connection: &Connection,
    key: &SqliteIntegrityKey,
    authority: &TransactionAuthorityVerifier,
) -> Result<Snapshot, TransactionStoreError> {
    let reference = Connection::open_in_memory().map_err(sqlite)?;
    reference.execute_batch(SCHEMA).map_err(sqlite)?;
    if schema_objects(connection)? != schema_objects(&reference)? {
        return Err(corrupt());
    }
    for (name, expected) in [
        ("application_id", APPLICATION_ID),
        ("user_version", 1),
        ("synchronous", 2),
        ("trusted_schema", 0),
        ("max_page_count", MAX_PAGES),
    ] {
        let actual: i64 = connection
            .pragma_query_value(None, name, |r| r.get(0))
            .map_err(sqlite)?;
        if actual != expected {
            return Err(corrupt());
        }
    }
    let mode: String = connection
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .map_err(sqlite)?;
    let pages: i64 = connection
        .pragma_query_value(None, "page_count", |r| r.get(0))
        .map_err(sqlite)?;
    let page_size: i64 = connection
        .pragma_query_value(None, "page_size", |r| r.get(0))
        .map_err(sqlite)?;
    let identities: u64 = connection
        .query_row("SELECT count(*) FROM protective_lock_identity", [], |r| {
            r.get(0)
        })
        .map_err(sqlite)?;
    if mode != "wal" || pages > MAX_PAGES || page_size > 4096 || identities != 1 {
        return Err(corrupt());
    }
    let mut snapshot = connection
        .query_row(
            "SELECT * FROM protective_lock_identity WHERE singleton=1",
            [],
            |r| {
                if r.get_ref(1)?.as_str()? != key.fingerprint().as_str()
                    || r.get_ref(2)?.as_str()? != authority.fingerprint().as_str()
                    || r.get_ref(3)?.as_str()?
                        != digest_bytes(
                            "linura.sqlite.protective-lock-schema.v1",
                            SCHEMA.as_bytes(),
                        )
                        .as_str()
                    || r.get_ref(5)?.as_str()?.len() != 71
                    || r.get_ref(7)?.as_blob()?.len() != 32
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                let snapshot = Snapshot {
                    count: r.get(4)?,
                    tip: ContentDigest::new(r.get_ref(5)?.as_str()?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    last_write: r.get(6)?,
                    records: Vec::new(),
                };
                if snapshot.count > MAX_RECORDS
                    || !key.verify(
                        IDENTITY_DOMAIN,
                        &identity_material(key, authority, &snapshot),
                        r.get_ref(7)?.as_blob()?,
                    )
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok(snapshot)
            },
        )
        .map_err(|_| corrupt())?;
    let mut statement = connection
        .prepare("SELECT * FROM protective_lock_records ORDER BY position LIMIT 4097")
        .map_err(sqlite)?;
    let rows = statement
        .query_map([], |r| {
            for index in [1, 2, 3] {
                if r.get_ref(index)?.as_str()?.len() > 256 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            let canonical = r.get_ref(4)?.as_blob()?;
            let record = ProtectiveLockSettingRecord::decode(canonical)
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            let chain = r.get_ref(6)?.as_str()?;
            let expiry: u64 = r.get(7)?;
            let approval = r.get_ref(8)?.as_blob()?;
            let tag = r.get_ref(9)?.as_blob()?;
            let position: u64 = r.get(0)?;
            if chain.len() != 71
                || tag.len() != 32
                || record.owner().as_str() != r.get_ref(1)?.as_str()?
                || record
                    .epoch()
                    .resource_id()
                    .map_err(|_| rusqlite::Error::InvalidQuery)?
                    .as_str()
                    != r.get_ref(2)?.as_str()?
                || record.request().as_str() != r.get_ref(3)?.as_str()?
                || record.digest().as_str() != r.get_ref(5)?.as_str()?
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let chain = ContentDigest::new(chain).map_err(|_| rusqlite::Error::InvalidQuery)?;
            if !authority.verify_retained_protective_lock_setting(&record, expiry, approval)
                || !key.verify(
                    RECORD_DOMAIN,
                    &record_material(position, &record, &chain, expiry, approval),
                    tag,
                )
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok((position, record, chain))
        })
        .map_err(sqlite)?;
    let mut count = 0;
    let mut tip = ContentDigest::zero();
    let mut current = BTreeMap::new();
    for row in rows {
        let (position, record, chain) = row.map_err(|_| corrupt())?;
        count += 1;
        let scope = (record.owner().clone(), record.epoch().clone());
        if position != count
            || count > MAX_RECORDS
            || record.confirmed_at_unix_ms() > snapshot.last_write
            || chain != chain_digest(position, &tip, record.digest())
            || current.get(&scope) != record.previous()
        {
            return Err(corrupt());
        }
        current.insert(scope, record.digest().clone());
        tip = chain;
        snapshot.records.push(record);
    }
    if count != snapshot.count
        || tip != snapshot.tip
        || ((count == 0) != (snapshot.last_write == 0))
    {
        return Err(corrupt());
    }
    Ok(snapshot)
}

impl ProtectiveLockSettingStore for SqliteProtectiveLockSettingStore {
    fn current(
        &self,
        owner: &PrincipalId,
        epoch: &SessionEpoch,
    ) -> Result<Option<ProtectiveLockSettingRecord>, TransactionStoreError> {
        let transaction = self.connection.unchecked_transaction().map_err(sqlite)?;
        Ok(
            validate(&transaction, &self.integrity_key, &self.authority)?
                .current(owner, epoch)
                .cloned(),
        )
    }
    fn apply(
        &mut self,
        update: &ProtectiveLockSettingUpdate,
    ) -> Result<ProtectiveLockSettingRecord, TransactionStoreError> {
        self.apply_with_clock(update, now)
    }
    fn request(
        &self,
        owner: &PrincipalId,
        request: &linura_core::RequestId,
    ) -> Result<Option<ProtectiveLockSettingRecord>, TransactionStoreError> {
        let transaction = self.connection.unchecked_transaction().map_err(sqlite)?;
        Ok(
            validate(&transaction, &self.integrity_key, &self.authority)?
                .records
                .into_iter()
                .find(|record| record.owner() == owner && record.request() == request),
        )
    }
    fn integrity_check(&self) -> Result<(), TransactionStoreError> {
        let transaction = self.connection.unchecked_transaction().map_err(sqlite)?;
        validate(&transaction, &self.integrity_key, &self.authority)?;
        let check: String = transaction
            .query_row("PRAGMA integrity_check(1)", [], |r| r.get(0))
            .map_err(sqlite)?;
        if check != "ok" {
            return Err(corrupt());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{BootId, IntentId, RequestId, SecurityOwnerInvocationId, SessionLockId};
    use linura_transaction::{TransactionAuthorityKey, TransactionAuthoritySigner};
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
                "linura-protective-setting-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap_or_else(|e| unreachable!("{e}"));
            let path = root.join("settings.sqlite3");
            Self { root, path }
        }
        fn open(&self) -> SqliteProtectiveLockSettingStore {
            SqliteProtectiveLockSettingStore::open(&self.path, key(0x61), authority(0x71).1)
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
    fn authority(byte: u8) -> (TransactionAuthoritySigner, TransactionAuthorityVerifier) {
        TransactionAuthorityKey::new(vec![byte; 32])
            .unwrap_or_else(|e| unreachable!("{e}"))
            .split()
    }
    fn epoch(uid: u32, created: u64) -> SessionEpoch {
        SessionEpoch::new(
            BootId::new("abcd1234-1234-4567-89ab-0123456789ab")
                .unwrap_or_else(|e| unreachable!("{e}")),
            uid,
            "c2",
            created,
        )
        .unwrap_or_else(|e| unreachable!("{e}"))
    }
    fn record(
        request: &str,
        epoch: SessionEpoch,
        previous: Option<&ContentDigest>,
        enabled: bool,
        at: u64,
    ) -> ProtectiveLockSettingRecord {
        let lock = SessionLockId::new(
            epoch.clone(),
            SecurityOwnerInvocationId::new("98765432-1234-4567-89ab-0123456789ab")
                .unwrap_or_else(|e| unreachable!("{e}")),
            7,
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        ProtectiveLockSettingRecord::new(
            PrincipalId::new(format!("unix:uid:{}", epoch.uid()))
                .unwrap_or_else(|e| unreachable!("{e}")),
            epoch,
            IntentId::new("intent:s17:protective-lock:owner-approved")
                .unwrap_or_else(|e| unreachable!("{e}")),
            RequestId::new(request).unwrap_or_else(|e| unreachable!("{e}")),
            previous.cloned(),
            enabled,
            lock,
            at,
            digest_bytes("test-native-purpose-bound-confirmation", request.as_bytes()),
        )
        .unwrap_or_else(|e| unreachable!("{e}"))
    }
    fn update(record: &ProtectiveLockSettingRecord) -> ProtectiveLockSettingUpdate {
        authority(0x71)
            .0
            .authorize_protective_lock_setting(record.clone(), record.confirmed_at_unix_ms() + 2000)
            .unwrap_or_else(|e| unreachable!("{e}"))
    }

    #[test]
    fn missing_is_disabled_and_restart_reads_exact_owner_epoch_policy_lineage() {
        let database = Database::new();
        let enabled = record("request:enable", epoch(1000, 42), None, true, 1000);
        {
            let mut store = database.open();
            assert_eq!(store.current(enabled.owner(), enabled.epoch()), Ok(None));
            assert_eq!(store.apply_at(&update(&enabled), 1000), Ok(enabled.clone()));
        }
        let store = database.open();
        assert_eq!(
            store.current(enabled.owner(), enabled.epoch()),
            Ok(Some(enabled.clone()))
        );
        assert_eq!(store.current(enabled.owner(), &epoch(1000, 43)), Ok(None));
        assert_eq!(
            store.current(
                &PrincipalId::new("unix:uid:1001").unwrap_or_else(|e| unreachable!("{e}")),
                &epoch(1001, 42)
            ),
            Ok(None)
        );
        assert!(store.integrity_check().is_ok());
    }

    #[test]
    fn historic_enable_retry_cannot_resurrect_revocation_even_after_expiry() {
        let database = Database::new();
        let mut store = database.open();
        let enabled = record("request:enable", epoch(1000, 42), None, true, 1000);
        let revoked = record(
            "request:revoke",
            epoch(1000, 42),
            Some(enabled.digest()),
            false,
            1001,
        );
        let enable = update(&enabled);
        assert!(store.apply_at(&enable, 1000).is_ok());
        assert!(store.apply_at(&update(&revoked), 1001).is_ok());
        assert_eq!(store.apply_at(&enable, 10000), Ok(enabled.clone()));
        assert_eq!(
            store.current(enabled.owner(), enabled.epoch()),
            Ok(Some(revoked.clone()))
        );
        drop(store);
        assert_eq!(
            database.open().current(enabled.owner(), enabled.epoch()),
            Ok(Some(revoked))
        );
    }

    #[test]
    fn stale_compare_and_swap_changed_content_and_wrong_signer_never_write() {
        let database = Database::new();
        let mut store = database.open();
        let enabled = record("request:enable", epoch(1000, 42), None, true, 1000);
        let wrong = authority(0x72)
            .0
            .authorize_protective_lock_setting(enabled.clone(), 3000)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(
            store.apply_at(&wrong, 1000),
            Err(TransactionStoreError::AuthorityRejected)
        );
        assert_eq!(store.current(enabled.owner(), enabled.epoch()), Ok(None));
        assert!(store.apply_at(&update(&enabled), 1000).is_ok());
        let changed = record(
            "request:enable",
            epoch(1000, 42),
            Some(enabled.digest()),
            false,
            1001,
        );
        assert_eq!(
            store.apply_at(&update(&changed), 1001),
            Err(TransactionStoreError::IdempotencyConflict)
        );
        let stale = record("request:stale", epoch(1000, 42), None, false, 1001);
        assert_eq!(
            store.apply_at(&update(&stale), 1001),
            Err(TransactionStoreError::StateConflict)
        );
        let other_epoch = record("request:enable", epoch(1000, 43), None, true, 1001);
        assert_eq!(
            store.apply_at(&update(&other_epoch), 1001),
            Err(TransactionStoreError::IdempotencyConflict)
        );
        assert_eq!(
            store.current(enabled.owner(), enabled.epoch()),
            Ok(Some(enabled))
        );
    }

    #[test]
    fn future_expired_and_clock_rollback_configuration_fail_closed() {
        let database = Database::new();
        let mut store = database.open();
        let enabled = record("request:enable", epoch(1000, 42), None, true, 1000);
        for sampled in [0, 999, 3000, 3001, u64::MAX] {
            assert_eq!(
                store.apply_at(&update(&enabled), sampled),
                Err(TransactionStoreError::AuthorityRejected)
            );
            assert_eq!(store.current(enabled.owner(), enabled.epoch()), Ok(None));
        }
        assert!(store.apply_at(&update(&enabled), 2000).is_ok());
        let revoked = record(
            "request:revoke",
            epoch(1000, 42),
            Some(enabled.digest()),
            false,
            1500,
        );
        assert_eq!(
            store.apply_at(&update(&revoked), 1999),
            Err(TransactionStoreError::AuthorityRejected)
        );
        assert!(store.apply_at(&update(&revoked), 2000).is_ok());
    }

    #[test]
    fn concurrent_writers_cannot_both_replace_the_same_revision() {
        let database = Database::new();
        let mut first = database.open();
        let mut second = database.open();
        let enabled = record("request:enable", epoch(1000, 42), None, true, 1000);
        let competing = record("request:competing", epoch(1000, 42), None, false, 1000);
        assert!(first.apply_at(&update(&enabled), 1000).is_ok());
        assert_eq!(
            second.apply_at(&update(&competing), 1000),
            Err(TransactionStoreError::StateConflict)
        );
        assert_eq!(
            second.current(enabled.owner(), enabled.epoch()),
            Ok(Some(enabled))
        );
    }

    #[test]
    fn wrong_keys_unknown_schema_and_existing_foreign_data_are_not_reinitialized() {
        let database = Database::new();
        drop(database.open());
        assert!(
            SqliteProtectiveLockSettingStore::open(&database.path, key(0x62), authority(0x71).1)
                .is_err()
        );
        assert!(
            SqliteProtectiveLockSettingStore::open(&database.path, key(0x61), authority(0x72).1)
                .is_err()
        );
        let raw = Connection::open(&database.path).unwrap_or_else(|e| unreachable!("{e}"));
        raw.pragma_update(None, "user_version", 2)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(
            SqliteProtectiveLockSettingStore::open(&database.path, key(0x61), authority(0x71).1)
                .is_err()
        );
        drop(raw);
        let foreign = Database::new();
        let raw = Connection::open(&foreign.path).unwrap_or_else(|e| unreachable!("{e}"));
        raw.execute_batch(
            "CREATE TABLE preserve(value TEXT); INSERT INTO preserve VALUES ('existing data');",
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(
            SqliteProtectiveLockSettingStore::open(&foreign.path, key(0x61), authority(0x71).1)
                .is_err()
        );
        let value: String = raw
            .query_row("SELECT value FROM preserve", [], |r| r.get(0))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(value, "existing data");
    }

    #[test]
    fn row_tip_deletion_reordering_and_schema_injection_are_detected_before_use() {
        for sql in [
            "UPDATE protective_lock_records SET canonical=x'00' WHERE position=2",
            "UPDATE protective_lock_records SET owner='unix:uid:1001' WHERE position=2",
            "UPDATE protective_lock_records SET epoch='session:epoch:other' WHERE position=2",
            "UPDATE protective_lock_records SET request_id='request:substitution' WHERE position=2",
            "UPDATE protective_lock_records SET record_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000' WHERE position=2",
            "UPDATE protective_lock_records SET chain_digest='sha256:0000000000000000000000000000000000000000000000000000000000000000' WHERE position=2",
            "UPDATE protective_lock_records SET integrity_tag=zeroblob(32) WHERE position=2",
            "UPDATE protective_lock_records SET approval_authority_tag=zeroblob(32) WHERE position=2",
            "UPDATE protective_lock_records SET approval_write_expiry_unix_ms=3000 WHERE position=2",
            "UPDATE protective_lock_records SET position=3 WHERE position=2",
            "DELETE FROM protective_lock_records WHERE position=2",
            "DELETE FROM protective_lock_records",
            "DELETE FROM protective_lock_identity",
            "UPDATE protective_lock_identity SET record_count=1",
            "UPDATE protective_lock_identity SET last_write_unix_ms=999",
            "UPDATE protective_lock_identity SET integrity_tag=zeroblob(32)",
            "CREATE TRIGGER bypass AFTER INSERT ON protective_lock_records BEGIN DELETE FROM protective_lock_records; END;",
            "CREATE VIEW alias AS SELECT * FROM protective_lock_records",
            "CREATE TABLE extra(value BLOB)",
        ] {
            let database = Database::new();
            let mut store = database.open();
            let enabled = record("request:enable", epoch(1000, 42), None, true, 1000);
            let revoked = record(
                "request:revoke",
                epoch(1000, 42),
                Some(enabled.digest()),
                false,
                1001,
            );
            assert!(store.apply_at(&update(&enabled), 1000).is_ok());
            assert!(store.apply_at(&update(&revoked), 1001).is_ok());
            store
                .connection
                .execute_batch(sql)
                .unwrap_or_else(|e| unreachable!("{e}: {sql}"));
            assert!(
                store.current(enabled.owner(), enabled.epoch()).is_err(),
                "{sql}"
            );
            assert!(store.integrity_check().is_err(), "{sql}");
            assert!(store.apply_at(&update(&enabled), 1002).is_err(), "{sql}");
        }
    }

    #[test]
    fn interrupted_transaction_rolls_back_both_record_and_current_tip() {
        let database = Database::new();
        let mut store = database.open();
        let enabled = record("request:enable", epoch(1000, 42), None, true, 1000);
        assert!(store.apply_at(&update(&enabled), 1000).is_ok());
        // Simulate loss before commit with both halves tentatively changed.
        store.connection.execute_batch("BEGIN IMMEDIATE; DELETE FROM protective_lock_records; DELETE FROM protective_lock_identity; ROLLBACK;")
            .unwrap_or_else(|e| unreachable!("{e}"));
        drop(store);
        assert_eq!(
            database.open().current(enabled.owner(), enabled.epoch()),
            Ok(Some(enabled))
        );
    }

    #[test]
    fn deadline_expiry_or_rollback_during_atomic_validation_does_not_commit() {
        for final_sample in [999, 3000] {
            let database = Database::new();
            let mut store = database.open();
            let enabled = record("request:enable", epoch(1000, 42), None, true, 1000);
            let mut samples = [1000, final_sample].into_iter();
            assert_eq!(
                store.apply_with_clock(&update(&enabled), || samples
                    .next()
                    .ok_or(TransactionStoreError::AuthorityRejected)),
                Err(TransactionStoreError::AuthorityRejected)
            );
            assert_eq!(store.current(enabled.owner(), enabled.epoch()), Ok(None));
            assert!(store.integrity_check().is_ok());
        }
    }

    #[test]
    fn record_integrity_key_alone_cannot_forge_owner_configuration_approval() {
        let database = Database::new();
        let mut store = database.open();
        let original = record("request:revoke", epoch(1000, 42), None, false, 1000);
        let approved = update(&original);
        assert!(store.apply_at(&approved, 1000).is_ok());
        let forged = record("request:revoke", epoch(1000, 42), None, true, 1000);
        let chain = chain_digest(1, &ContentDigest::zero(), forged.digest());
        // Deliberately give the test the record-integrity key and allow a fully
        // consistent new record/tip. It still lacks Control's approval signer.
        let tag = store
            .integrity_key
            .tag(
                RECORD_DOMAIN,
                &record_material(
                    1,
                    &forged,
                    &chain,
                    approved.expires_at_unix_ms(),
                    approved.authentication_tag(),
                ),
            )
            .unwrap_or_else(|e| unreachable!("{e}"));
        store.connection.execute("UPDATE protective_lock_records SET canonical=?1,record_digest=?2,chain_digest=?3,integrity_tag=?4 WHERE position=1",
            params![forged.canonical(),forged.digest().as_str(),chain.as_str(),tag.as_slice()]).unwrap_or_else(|e| unreachable!("{e}"));
        let snapshot = Snapshot {
            count: 1,
            tip: chain,
            last_write: 1000,
            records: Vec::new(),
        };
        write_identity(
            &store.connection,
            &store.integrity_key,
            &store.authority,
            &snapshot,
            false,
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(store.current(original.owner(), original.epoch()).is_err());
        assert!(store.integrity_check().is_err());
    }

    #[test]
    fn full_history_is_never_evicted_to_make_room_for_new_policy_authority() {
        let database = Database::new();
        let mut store = database.open();
        let transaction = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap_or_else(|e| unreachable!("{e}"));
        let mut snapshot = Snapshot {
            count: 0,
            tip: ContentDigest::zero(),
            last_write: 1000,
            records: Vec::new(),
        };
        let mut previous = None;
        let mut last = record("request:placeholder", epoch(1000, 42), None, false, 1000);
        for position in 1..=MAX_RECORDS {
            let current = record(
                &format!("request:capacity:{position}"),
                epoch(1000, 42),
                previous.as_ref(),
                position % 2 == 0,
                1000,
            );
            let chain = chain_digest(position, &snapshot.tip, current.digest());
            let approved = update(&current);
            let tag = store
                .integrity_key
                .tag(
                    RECORD_DOMAIN,
                    &record_material(
                        position,
                        &current,
                        &chain,
                        approved.expires_at_unix_ms(),
                        approved.authentication_tag(),
                    ),
                )
                .unwrap_or_else(|e| unreachable!("{e}"));
            transaction
                .execute(
                    "INSERT INTO protective_lock_records VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    params![
                        position,
                        current.owner().as_str(),
                        current
                            .epoch()
                            .resource_id()
                            .unwrap_or_else(|e| unreachable!("{e}"))
                            .as_str(),
                        current.request().as_str(),
                        current.canonical(),
                        current.digest().as_str(),
                        chain.as_str(),
                        approved.expires_at_unix_ms(),
                        approved.authentication_tag(),
                        tag.as_slice()
                    ],
                )
                .unwrap_or_else(|e| unreachable!("{e}"));
            snapshot.count = position;
            snapshot.tip = chain;
            previous = Some(current.digest().clone());
            last = current;
        }
        write_identity(
            &transaction,
            &store.integrity_key,
            &store.authority,
            &snapshot,
            false,
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        transaction.commit().unwrap_or_else(|e| unreachable!("{e}"));
        assert!(store.integrity_check().is_ok());
        let excess = record(
            "request:excess",
            epoch(1000, 42),
            Some(last.digest()),
            false,
            1001,
        );
        assert_eq!(
            store.apply_at(&update(&excess), 1001),
            Err(TransactionStoreError::CapacityExceeded)
        );
        assert_eq!(
            store.current(last.owner(), last.epoch()),
            Ok(Some(last.clone()))
        );
        assert_eq!(store.apply_at(&update(&last), 10000), Ok(last));
    }
}
