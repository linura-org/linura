//! S25 append-only, owner-scoped local preferences. Data is never a wallpaper
//! executor permit or proof of an applied renderer revision.
//! Protected directory and separately provisioned integrity/Control keys are
//! mandatory composition-root obligations; no runtime caller is wired yet.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Debug, Formatter};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use linura_core::{PrincipalId, RequestId};
use linura_transaction::{
    ContentDigest, PersonalizationPreferenceRecord, PersonalizationPreferenceUpdate,
    TransactionAuthorityVerifier, TransactionStoreError, digest_bytes, digest_parts,
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};

use crate::integrity::{SqliteIntegrityKey, canonical_field};
use crate::validation::sqlite;

const APPLICATION_ID: i64 = 0x4c4e5350; // LNSP: distinct from LNRT and LNRP.
const SCHEMA: &str = include_str!("personalization_schema.sql");
const MAX_RECORDS: u64 = 4096;
const MAX_PAGES: i64 = 8192;
const IDENTITY_DOMAIN: &str = "linura.sqlite.personalization-identity.v1";
const RECORD_DOMAIN: &str = "linura.sqlite.personalization-record.v1";
const CHAIN_DOMAIN: &str = "linura.sqlite.personalization-chain.v1";
const SCHEMA_DOMAIN: &str = "linura.sqlite.personalization-schema.v1";

pub struct SqlitePersonalizationPreferenceStore {
    connection: Connection,
    integrity_key: SqliteIntegrityKey,
    authority: TransactionAuthorityVerifier,
}

impl Debug for SqlitePersonalizationPreferenceStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqlitePersonalizationPreferenceStore")
            .finish_non_exhaustive()
    }
}

fn corrupt() -> TransactionStoreError {
    TransactionStoreError::Corruption("personalization store integrity validation failed".into())
}

fn sql_i64(value: u64) -> Result<i64, TransactionStoreError> {
    i64::try_from(value).map_err(|_| TransactionStoreError::CapacityExceeded)
}

fn now() -> Result<u64, TransactionStoreError> {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TransactionStoreError::AuthorityRejected)?
        .as_millis();
    let value = u64::try_from(time).map_err(|_| TransactionStoreError::AuthorityRejected)?;
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
    records: Vec<PersonalizationPreferenceRecord>,
}

impl Snapshot {
    fn current(&self, owner: &PrincipalId) -> Option<&PersonalizationPreferenceRecord> {
        self.records.iter().rev().find(|record| record.owner() == owner)
    }

    fn request(&self, owner: &PrincipalId, request: &RequestId) -> Option<&PersonalizationPreferenceRecord> {
        self.records.iter().find(|record| record.owner() == owner && record.request() == request)
    }
}

impl SqlitePersonalizationPreferenceStore {
    /// Use an owner-only protected directory, no-follow path, and independent
    /// 256-bit record-integrity and Control-authority keys. Never provision keys
    /// from stored preferences or imported themes; retain them across restarts.
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
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .map_err(sqlite)?;
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(sqlite)?;
        let object_count: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite)?;
        if !((application == 0 && version == 0 && object_count == 0)
            || (application == APPLICATION_ID && version == 1))
        {
            return Err(TransactionStoreError::UnsupportedSchema(
                "unknown personalization database generation".into(),
            ));
        }

        connection
            .execute_batch(
                "PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; \
                 PRAGMA wal_autocheckpoint=128; PRAGMA journal_size_limit=524288;",
            )
            .map_err(sqlite)?;
        let mode: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
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
                .pragma_query_value(None, "application_id", |row| row.get(0))
                .map_err(sqlite)?;
            let objects: i64 = transaction
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                    [],
                    |row| row.get(0),
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
            write_identity(
                &transaction,
                &integrity_key,
                &authority,
                &Snapshot {
                    count: 0,
                    tip: ContentDigest::zero(),
                    last_write: 0,
                    records: Vec::new(),
                },
                true,
            )?;
        }
        validate(&transaction, &integrity_key, &authority)?;
        transaction.commit().map_err(sqlite)?;

        let store = Self { connection, integrity_key, authority };
        store.integrity_check()?;
        Ok(store)
    }

    /// Read-back only: current saved intent is not actual applied appearance.
    pub fn current(
        &self,
        owner: &PrincipalId,
    ) -> Result<Option<PersonalizationPreferenceRecord>, TransactionStoreError> {
        Ok(validate(&self.connection, &self.integrity_key, &self.authority)?
            .current(owner)
            .cloned())
    }

    /// Historical idempotency/lost-reply lookup; never re-applies old state.
    pub fn request(
        &self,
        owner: &PrincipalId,
        request: &RequestId,
    ) -> Result<Option<PersonalizationPreferenceRecord>, TransactionStoreError> {
        Ok(validate(&self.connection, &self.integrity_key, &self.authority)?
            .request(owner, request)
            .cloned())
    }

    pub fn apply(
        &mut self,
        update: &PersonalizationPreferenceUpdate,
    ) -> Result<PersonalizationPreferenceRecord, TransactionStoreError> {
        self.apply_with_clock(update, now)
    }

    fn apply_with_clock(
        &mut self,
        update: &PersonalizationPreferenceUpdate,
        mut clock: impl FnMut() -> Result<u64, TransactionStoreError>,
    ) -> Result<PersonalizationPreferenceRecord, TransactionStoreError> {
        if !self.authority.verify_personalization_preference(update) {
            return Err(TransactionStoreError::AuthorityRejected);
        }
        let tx = self.connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite)?;
        let mut snapshot = validate(&tx, &self.integrity_key, &self.authority)?;
        let record = update.record();
        if let Some(prior) = snapshot.request(record.owner(), record.request()) {
            if prior != record {
                return Err(TransactionStoreError::IdempotencyConflict);
            }
            // A superseded retry is a historical receipt, not a state change.
            return Ok(prior.clone());
        }

        let sampled = clock()?;
        if sampled == 0
            || sampled < snapshot.last_write
            || sampled < update.issued_at_unix_ms()
            || sampled >= update.expires_at_unix_ms()
        {
            return Err(TransactionStoreError::AuthorityRejected);
        }
        let previous = snapshot.current(record.owner());
        let next_revision = previous
            .map_or(Some(1), |entry| entry.revision().checked_add(1))
            .ok_or(TransactionStoreError::CapacityExceeded)?;
        if record.revision() != next_revision
            || previous.map(PersonalizationPreferenceRecord::digest) != record.previous_digest()
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
                position, record, &chain,
                update.issued_at_unix_ms(),
                update.expires_at_unix_ms(),
                update.authority_tag(),
            ),
        )?;
        tx.execute(
            "INSERT INTO personalization_records VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                sql_i64(position)?,
                record.owner().as_str(),
                record.request().as_str(),
                record.canonical(),
                record.digest().as_str(),
                chain.as_str(),
                sql_i64(update.issued_at_unix_ms())?,
                sql_i64(update.expires_at_unix_ms())?,
                update.authority_tag(),
                tag.as_slice(),
            ],
        ).map_err(sqlite)?;
        snapshot.count = position;
        snapshot.tip = chain;
        snapshot.last_write = sampled;
        snapshot.records.push(record.clone());
        write_identity(&tx, &self.integrity_key, &self.authority, &snapshot, false)?;
        validate(&tx, &self.integrity_key, &self.authority)?;
        let final_sample = clock()?;
        if final_sample < sampled || final_sample >= update.expires_at_unix_ms() {
            return Err(TransactionStoreError::AuthorityRejected);
        }
        tx.commit().map_err(sqlite)?;
        // Success means durable local preferences, never renderer application.
        Ok(record.clone())
    }

    pub fn integrity_check(&self) -> Result<(), TransactionStoreError> {
        let check: String = self.connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(sqlite)?;
        if check != "ok" {
            return Err(corrupt());
        }
        validate(&self.connection, &self.integrity_key, &self.authority)?;
        Ok(())
    }
}

fn chain_digest(
    position: u64,
    previous: &ContentDigest,
    record: &ContentDigest,
) -> ContentDigest {
    digest_parts(
        CHAIN_DOMAIN,
        [
            position.to_be_bytes().as_slice(),
            previous.as_str().as_bytes(),
            record.as_str().as_bytes(),
        ],
    )
}

fn record_material(
    position: u64,
    record: &PersonalizationPreferenceRecord,
    chain: &ContentDigest,
    issued: u64,
    expiry: u64,
    authority_tag: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    canonical_field(&mut bytes, &position.to_be_bytes());
    canonical_field(&mut bytes, record.canonical());
    canonical_field(&mut bytes, record.digest().as_str().as_bytes());
    canonical_field(&mut bytes, chain.as_str().as_bytes());
    canonical_field(&mut bytes, &issued.to_be_bytes());
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
    for digest in [
        key.fingerprint(),
        authority.fingerprint(),
        digest_bytes(SCHEMA_DOMAIN, SCHEMA.as_bytes()),
    ] {
        canonical_field(&mut bytes, digest.as_str().as_bytes());
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
    let result = if create {
        connection.execute(
            "INSERT INTO personalization_identity VALUES (1,?1,?2,?3,?4,?5,?6,?7)",
            params![
                key.fingerprint().as_str(),
                authority.fingerprint().as_str(),
                digest_bytes(SCHEMA_DOMAIN, SCHEMA.as_bytes()).as_str(),
                sql_i64(snapshot.count)?,
                snapshot.tip.as_str(),
                sql_i64(snapshot.last_write)?,
                tag.as_slice(),
            ],
        )
    } else {
        connection.execute(
            "UPDATE personalization_identity SET record_count=?1,chain_tip=?2,last_write_unix_ms=?3,integrity_tag=?4 WHERE singleton=1",
            params![
                sql_i64(snapshot.count)?,
                snapshot.tip.as_str(),
                sql_i64(snapshot.last_write)?,
                tag.as_slice(),
            ],
        )
    }.map_err(sqlite)?;
    if result != 1 {
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
        .query_map([], |row| {
            for field in 0..4 {
                if row.get_ref(field)?.as_bytes()?.len() > 16384 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite)
}

fn validate(
    connection: &Connection,
    key: &SqliteIntegrityKey,
    authority: &TransactionAuthorityVerifier,
) -> Result<Snapshot, TransactionStoreError> {
    // Refuse schema widening, dropped constraints, rogue triggers, injected
    // tables and changed pragma modes, not just unknown schema version.
    let reference = Connection::open_in_memory().map_err(sqlite)?;
    reference.execute_batch(SCHEMA).map_err(sqlite)?;
    if schema_objects(connection)? != schema_objects(&reference)? {
        return Err(corrupt());
    }
    for (pragma, expected) in [
        ("application_id", APPLICATION_ID),
        ("user_version", 1),
        ("synchronous", 2),
        ("trusted_schema", 0),
        ("max_page_count", MAX_PAGES),
    ] {
        let actual: i64 = connection
            .pragma_query_value(None, pragma, |row| row.get(0))
            .map_err(sqlite)?;
        if actual != expected {
            return Err(corrupt());
        }
    }
    let mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(sqlite)?;
    let page_count: i64 = connection
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .map_err(sqlite)?;
    let page_size: i64 = connection
        .pragma_query_value(None, "page_size", |row| row.get(0))
        .map_err(sqlite)?;
    let identities: i64 = connection
        .query_row("SELECT count(*) FROM personalization_identity", [], |row| row.get(0))
        .map_err(sqlite)?;
    if mode != "wal" || page_count > MAX_PAGES || page_size > 4096 || identities != 1 {
        return Err(corrupt());
    }

    let identity = connection.query_row(
        "SELECT integrity_fingerprint,authority_fingerprint,schema_digest,record_count,chain_tip,last_write_unix_ms,integrity_tag FROM personalization_identity WHERE singleton=1",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Vec<u8>>(6)?,
            ))
        },
    ).map_err(sqlite)?;
    let (key_id, authority_id, schema_id, count, tip, last_write, identity_tag) = identity;
    if key_id != key.fingerprint().as_str()
        || authority_id != authority.fingerprint().as_str()
        || schema_id != digest_bytes(SCHEMA_DOMAIN, SCHEMA.as_bytes()).as_str()
        || count < 0 || count > MAX_RECORDS as i64 || last_write < 0
    {
        return Err(corrupt());
    }
    let tip = ContentDigest::new(tip).map_err(|_| corrupt())?;
    let mut snapshot = Snapshot {
        count: u64::try_from(count).map_err(|_| corrupt())?,
        tip: tip.clone(),
        last_write: u64::try_from(last_write).map_err(|_| corrupt())?,
        records: Vec::new(),
    };
    if !key.verify(
        IDENTITY_DOMAIN,
        &identity_material(key, authority, &snapshot),
        &identity_tag,
    ) {
        return Err(corrupt());
    }

    let mut stmt = connection.prepare(
        "SELECT position,owner,request_id,canonical,record_digest,chain_digest,issued_at_unix_ms,expires_at_unix_ms,authority_tag,integrity_tag FROM personalization_records ORDER BY position LIMIT 4097",
    ).map_err(sqlite)?;
    let mut rows = stmt.query([]).map_err(sqlite)?;
    let mut expected_tip = ContentDigest::zero();
    let mut last_per_owner = BTreeMap::<String, (u64, ContentDigest)>::new();
    let mut requests = BTreeSet::<(String, String)>::new();
    let mut pos = 0_u64;
    while let Some(row) = rows.next().map_err(sqlite)? {
        pos = pos.checked_add(1).ok_or_else(corrupt)?;
        if pos > MAX_RECORDS {
            return Err(corrupt());
        }
        let position: i64 = row.get(0).map_err(sqlite)?;
        let owner: String = row.get(1).map_err(sqlite)?;
        let request: String = row.get(2).map_err(sqlite)?;
        let canonical: Vec<u8> = row.get(3).map_err(sqlite)?;
        let saved_digest: String = row.get(4).map_err(sqlite)?;
        let chain_digest_value: String = row.get(5).map_err(sqlite)?;
        let issued: i64 = row.get(6).map_err(sqlite)?;
        let expiry: i64 = row.get(7).map_err(sqlite)?;
        let approval_tag: Vec<u8> = row.get(8).map_err(sqlite)?;
        let integrity_tag: Vec<u8> = row.get(9).map_err(sqlite)?;
        let record = PersonalizationPreferenceRecord::decode(&canonical)
            .map_err(|_| corrupt())?;
        let issued = u64::try_from(issued).map_err(|_| corrupt())?;
        let expiry = u64::try_from(expiry).map_err(|_| corrupt())?;
        let expected_chain = chain_digest(pos, &expected_tip, record.digest());
        if position != sql_i64(pos)?
            || record.owner().as_str() != owner
            || record.request().as_str() != request
            || !requests.insert((owner.clone(), request))
            || record.digest().as_str() != saved_digest
            || expected_chain.as_str() != chain_digest_value
            || !authority.verify_retained_personalization_preference(
                &record, issued, expiry, &approval_tag,
            )
            || !key.verify(
                RECORD_DOMAIN,
                &record_material(pos, &record, &expected_chain, issued, expiry, &approval_tag),
                &integrity_tag,
            )
        {
            return Err(corrupt());
        }
        let expected_revision = match last_per_owner.get(&owner) {
            Some((revision, _)) => revision.checked_add(1).ok_or_else(corrupt)?,
            None => 1,
        };
        let previous = last_per_owner.get(&owner).map(|(_, digest)| digest);
        if record.revision() != expected_revision || record.previous_digest() != previous {
            return Err(corrupt());
        }
        last_per_owner.insert(owner, (record.revision(), record.digest().clone()));
        expected_tip = expected_chain;
        snapshot.records.push(record);
    }
    if pos != snapshot.count || expected_tip != tip {
        return Err(corrupt());
    }
    if pos == 0 && (snapshot.last_write != 0 || snapshot.tip != ContentDigest::zero()) {
        return Err(corrupt());
    }
    Ok(snapshot)
}


impl linura_transaction::PersonalizationPreferenceStore for SqlitePersonalizationPreferenceStore {
    fn current(
        &self,
        owner: &PrincipalId,
    ) -> Result<Option<PersonalizationPreferenceRecord>, TransactionStoreError> {
        Self::current(self, owner)
    }

    fn request(
        &self,
        owner: &PrincipalId,
        request: &RequestId,
    ) -> Result<Option<PersonalizationPreferenceRecord>, TransactionStoreError> {
        Self::request(self, owner, request)
    }

    fn apply(
        &mut self,
        update: &PersonalizationPreferenceUpdate,
    ) -> Result<PersonalizationPreferenceRecord, TransactionStoreError> {
        Self::apply(self, update)
    }

    fn integrity_check(&self) -> Result<(), TransactionStoreError> {
        Self::integrity_check(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_transaction::{PersonalizationChoices, ThemeMode, TransactionAuthorityKey};
    use std::fs::{self, File};
    use std::io::Read;
    use std::path::PathBuf;

    fn random_key() -> Vec<u8> {
        let mut bytes = Vec::new();
        let n = File::open("/dev/urandom")
            .and_then(|file| file.take(32).read_to_end(&mut bytes))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(n, 32);
        bytes
    }

    struct Fixture {
        directory: PathBuf,
        path: PathBuf,
        key: Vec<u8>,
        authority: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let name = random_key().iter().take(12)
                .map(|byte| format!("{byte:02x}")).collect::<String>();
            let directory = std::env::temp_dir().join(format!("linura-s25-{name}"));
            fs::create_dir(&directory).unwrap_or_else(|error| unreachable!("{error}"));
            Self {
                path: directory.join("preferences.sqlite"),
                directory,
                key: random_key(),
                authority: random_key(),
            }
        }

        fn open(&self) -> (SqlitePersonalizationPreferenceStore, linura_transaction::TransactionAuthoritySigner) {
            let (signer, verifier) = TransactionAuthorityKey::new(self.authority.clone())
                .unwrap_or_else(|error| unreachable!("{error}")).split();
            let store = SqlitePersonalizationPreferenceStore::open(
                &self.path,
                SqliteIntegrityKey::new(self.key.clone())
                    .unwrap_or_else(|error| unreachable!("{error}")),
                verifier,
            ).unwrap_or_else(|error| unreachable!("{error}"));
            (store, signer)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn owner() -> PrincipalId {
        PrincipalId::new("unix:uid:1000").unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn record(
        label: &str, revision: u64, previous: Option<ContentDigest>, dark: bool,
    ) -> PersonalizationPreferenceRecord {
        let mut choices = PersonalizationChoices::default();
        if dark { choices.mode = ThemeMode::Dark; }
        PersonalizationPreferenceRecord::new(
            owner(),
            RequestId::new(format!("request:v010:personalization:{label}"))
                .unwrap_or_else(|error| unreachable!("{error}")),
            revision, previous, choices,
        ).unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[test]
    fn persisted_cas_restart_and_old_request_retry_never_undo_revision() {
        let fixture = Fixture::new();
        let (mut store, signer) = fixture.open();
        let first = record("first", 1, None, false);
        let update = signer.authorize_personalization_preference(first.clone(), 1000, 2000)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(store.apply_with_clock(&update, || Ok(1500)), Ok(first.clone()));
        let second = record("second", 2, Some(first.digest().clone()), true);
        let second_update = signer.authorize_personalization_preference(second.clone(), 1500, 2500)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(store.apply_with_clock(&second_update, || Ok(2000)), Ok(second.clone()));
        assert_eq!(store.apply_with_clock(&update, || Ok(3000)), Ok(first.clone()));
        assert_eq!(store.current(&owner()), Ok(Some(second.clone())));
        assert_eq!(store.request(&owner(), first.request()), Ok(Some(first)));
        drop(store);
        let (restarted, _) = fixture.open();
        assert_eq!(restarted.current(&owner()), Ok(Some(second)));
        assert!(restarted.integrity_check().is_ok());
    }

    #[test]
    fn stale_edits_wrong_signer_and_expired_updates_fail_closed() {
        let fixture = Fixture::new();
        let (mut store, signer) = fixture.open();
        let first = record("first", 1, None, false);
        let update = signer.authorize_personalization_preference(first.clone(), 1000, 2000)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(store.apply_with_clock(&update, || Ok(2000)), Err(TransactionStoreError::AuthorityRejected));
        assert_eq!(store.current(&owner()), Ok(None));
        assert!(store.apply_with_clock(&update, || Ok(1500)).is_ok());
        let stale = record("stale", 1, None, true);
        let stale_update = signer.authorize_personalization_preference(stale, 1000, 2000)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(store.apply_with_clock(&stale_update, || Ok(1500)), Err(TransactionStoreError::StateConflict));
        let candidate = record("candidate", 2, Some(first.digest().clone()), true);
        let (wrong_signer, _) = TransactionAuthorityKey::new(random_key())
            .unwrap_or_else(|error| unreachable!("{error}")).split();
        let wrong_update = wrong_signer.authorize_personalization_preference(candidate, 1000, 2000)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(store.apply_with_clock(&wrong_update, || Ok(1500)), Err(TransactionStoreError::AuthorityRejected));
        assert_eq!(store.current(&owner()), Ok(Some(first)));
    }

    #[test]
    fn corrupted_row_or_unsupported_schema_never_claims_success() {
        let fixture = Fixture::new();
        let (mut store, signer) = fixture.open();
        let first = record("first", 1, None, false);
        let update = signer.authorize_personalization_preference(first, 1000, 2000)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(store.apply_with_clock(&update, || Ok(1500)).is_ok());
        store.connection.execute(
            "UPDATE personalization_records SET canonical=?1 WHERE position=1",
            params![b"invalid".as_slice()],
        ).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(store.integrity_check().is_err());
        assert!(store.current(&owner()).is_err());
        drop(store);
        let (signer, verifier) = TransactionAuthorityKey::new(fixture.authority.clone())
            .unwrap_or_else(|error| unreachable!("{error}")).split();
        let _ = signer;
        let result = SqlitePersonalizationPreferenceStore::open(
            &fixture.path,
            SqliteIntegrityKey::new(fixture.key.clone()).unwrap_or_else(|error| unreachable!("{error}")),
            verifier,
        );
        assert!(result.is_err());
    }
    #[test]
    fn foreign_schema_object_and_deleted_identity_are_rejected() {
        let fixture = Fixture::new();
        let (store, _) = fixture.open();
        store.connection.execute_batch(
            "CREATE TABLE unexpected_mutation_surface (value TEXT NOT NULL);",
        ).unwrap_or_else(|error| unreachable!("{error}"));
        assert!(store.integrity_check().is_err());
        drop(store);

        let other = Fixture::new();
        let (store, _) = other.open();
        store.connection.execute("DELETE FROM personalization_identity", [])
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(store.integrity_check().is_err());
    }


}
