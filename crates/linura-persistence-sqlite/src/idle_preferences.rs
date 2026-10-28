//! Durable, non-authorizing per-UID input-advisory preferences.
//! This store cannot grant an unattended lock, suspend or power capability.
//! An independently keyed integrity tag detects unauthorized row edits or
//! truncation. Whole-database protected rollback remains an OS backup boundary.

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};

use crate::SqliteIntegrityKey;
use crate::integrity::canonical_field;

const APPLICATION_ID: i64 = 0x4c4e5249; // LNRI, distinct from authority journals.
const MAX_PAGES: i64 = 2048;
const MAX_OWNERS: usize = 512;
const DOMAIN: &str = "linura.sqlite.idle-advisory-preferences.v1";
const SCHEMA: &str = "
CREATE TABLE idle_advisory_identity (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    key_fingerprint TEXT NOT NULL,
    integrity_tag BLOB NOT NULL
) STRICT;
CREATE TABLE idle_advisory_entries (
    uid INTEGER PRIMARY KEY CHECK(uid>0 AND uid<=4294967295),
    seconds INTEGER NOT NULL CHECK(seconds>=60 AND seconds<=3600 AND seconds%60=0),
    revision INTEGER NOT NULL CHECK(revision>=1)
) STRICT;
";

/// Seconds from 60 through 3600, in exact minute increments. The value affects
/// advisory presentation only and is never read by an executor or authority gate.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct IdleAdvisoryPreference {
    pub seconds: u32,
    pub revision: u64,
}

pub struct SqliteIdleAdvisoryPreferenceStore {
    connection: Connection,
    integrity_key: SqliteIntegrityKey,
}

impl Debug for SqliteIdleAdvisoryPreferenceStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteIdleAdvisoryPreferenceStore")
            .finish_non_exhaustive()
    }
}

fn invalid() -> String {
    "idle advisory preferences are unavailable or have failed validation".into()
}

fn accepted_seconds(seconds: u32) -> bool {
    (60..=3600).contains(&seconds) && seconds.is_multiple_of(60)
}

fn schema_objects(conn: &Connection) -> Result<Vec<(String, String, String)>, String> {
    let mut statement = conn
        .prepare(
            "SELECT type,name,coalesce(sql,'') FROM sqlite_schema \
             WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .map_err(|_| invalid())?;
    let items = statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(|_| invalid())?;
    items.collect::<Result<Vec<_>, _>>().map_err(|_| invalid())
}

fn compute_tag(
    key: &SqliteIntegrityKey,
    entries: &BTreeMap<u32, IdleAdvisoryPreference>,
) -> Result<[u8; 32], String> {
    let mut bytes = Vec::new();
    canonical_field(&mut bytes, key.fingerprint().as_str().as_bytes());
    canonical_field(&mut bytes, &(entries.len() as u64).to_be_bytes());
    for (uid, value) in entries {
        canonical_field(&mut bytes, &uid.to_be_bytes());
        canonical_field(&mut bytes, &value.seconds.to_be_bytes());
        canonical_field(&mut bytes, &value.revision.to_be_bytes());
    }
    key.tag(DOMAIN, &bytes).map_err(|_| invalid())
}

fn read_verified(
    conn: &Connection,
    key: &SqliteIntegrityKey,
) -> Result<BTreeMap<u32, IdleAdvisoryPreference>, String> {
    let reference = Connection::open_in_memory().map_err(|_| invalid())?;
    reference.execute_batch(SCHEMA).map_err(|_| invalid())?;
    if schema_objects(conn)? != schema_objects(&reference)? {
        return Err(invalid());
    }
    let app: i64 = conn
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| invalid())?;
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| invalid())?;
    let pages: i64 = conn
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .map_err(|_| invalid())?;
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|_| invalid())?;
    if app != APPLICATION_ID || version != 1 || pages > MAX_PAGES || mode != "wal" {
        return Err(invalid());
    }
    let mut entries = BTreeMap::new();
    let mut statement = conn
        .prepare("SELECT uid, seconds, revision FROM idle_advisory_entries ORDER BY uid")
        .map_err(|_| invalid())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|_| invalid())?;
    for record in rows {
        let (uid, seconds, revision) = record.map_err(|_| invalid())?;
        let uid = u32::try_from(uid).map_err(|_| invalid())?;
        let seconds = u32::try_from(seconds).map_err(|_| invalid())?;
        let revision = u64::try_from(revision).map_err(|_| invalid())?;
        if uid == 0 || revision == 0 || !accepted_seconds(seconds) || entries.len() >= MAX_OWNERS {
            return Err(invalid());
        }
        entries.insert(uid, IdleAdvisoryPreference { seconds, revision });
    }
    let (fingerprint, tag): (String, Vec<u8>) = conn
        .query_row(
            "SELECT key_fingerprint,integrity_tag FROM idle_advisory_identity WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| invalid())?;
    let count: i64 = conn
        .query_row("SELECT count(*) FROM idle_advisory_identity", [], |row| {
            row.get(0)
        })
        .map_err(|_| invalid())?;
    if count != 1 || fingerprint != key.fingerprint().as_str() {
        return Err(invalid());
    }
    let mut expected = Vec::new();
    canonical_field(&mut expected, key.fingerprint().as_str().as_bytes());
    canonical_field(&mut expected, &(entries.len() as u64).to_be_bytes());
    for (uid, value) in &entries {
        canonical_field(&mut expected, &uid.to_be_bytes());
        canonical_field(&mut expected, &value.seconds.to_be_bytes());
        canonical_field(&mut expected, &value.revision.to_be_bytes());
    }
    if !key.verify(DOMAIN, &expected, &tag) {
        return Err(invalid());
    }
    Ok(entries)
}

impl SqliteIdleAdvisoryPreferenceStore {
    pub fn open(path: impl AsRef<Path>, key: SqliteIntegrityKey) -> Result<Self, String> {
        let mut connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| invalid())?;
        connection
            .busy_timeout(Duration::from_millis(500))
            .map_err(|_| invalid())?;
        let app: i64 = connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .map_err(|_| invalid())?;
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| invalid())?;
        let objects: i64 = connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| invalid())?;
        if !((app == 0 && version == 0 && objects == 0) || (app == APPLICATION_ID && version == 1))
        {
            return Err(invalid());
        }
        connection
            .execute_batch(
                "PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; \
                 PRAGMA wal_autocheckpoint=128; PRAGMA journal_size_limit=524288;",
            )
            .map_err(|_| invalid())?;
        let mode: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .map_err(|_| invalid())?;
        if mode != "wal" {
            return Err(invalid());
        }
        connection
            .pragma_update(None, "max_page_count", MAX_PAGES)
            .map_err(|_| invalid())?;
        if app == 0 {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| invalid())?;
            transaction.execute_batch(SCHEMA).map_err(|_| invalid())?;
            transaction
                .pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(|_| invalid())?;
            transaction
                .pragma_update(None, "user_version", 1)
                .map_err(|_| invalid())?;
            transaction
                .execute(
                    "INSERT INTO idle_advisory_identity VALUES (1,?1,?2)",
                    params![
                        key.fingerprint().as_str(),
                        compute_tag(&key, &BTreeMap::new())?.as_slice()
                    ],
                )
                .map_err(|_| invalid())?;
            read_verified(&transaction, &key)?;
            transaction.commit().map_err(|_| invalid())?;
        }
        let result = Self {
            connection,
            integrity_key: key,
        };
        read_verified(&result.connection, &result.integrity_key)?;
        Ok(result)
    }

    pub fn get(&self, uid: u32) -> Result<IdleAdvisoryPreference, String> {
        if uid == 0 {
            return Err(invalid());
        }
        let records = read_verified(&self.connection, &self.integrity_key)?;
        Ok(records
            .get(&uid)
            .copied()
            .unwrap_or(IdleAdvisoryPreference {
                seconds: 300,
                revision: 0,
            }))
    }

    /// Revision CAS. A lost response must never trigger an implicit retry.
    pub fn compare_and_set(
        &mut self,
        uid: u32,
        seconds: u32,
        expected_revision: u64,
    ) -> Result<IdleAdvisoryPreference, String> {
        if uid == 0 || !accepted_seconds(seconds) || expected_revision > i64::MAX as u64 {
            return Err(invalid());
        }
        let txn = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| invalid())?;
        let mut records = read_verified(&txn, &self.integrity_key)?;
        let current = records
            .get(&uid)
            .copied()
            .unwrap_or(IdleAdvisoryPreference {
                seconds: 300,
                revision: 0,
            });
        if current.revision != expected_revision {
            return Err("idle advisory preference revision changed".into());
        }
        if current.seconds == seconds {
            return Ok(current);
        }
        let revision = current.revision.checked_add(1).ok_or_else(invalid)?;
        if revision > i64::MAX as u64
            || (records.len() >= MAX_OWNERS && !records.contains_key(&uid))
        {
            return Err(invalid());
        }
        txn.execute(
            "INSERT INTO idle_advisory_entries(uid,seconds,revision) VALUES (?1,?2,?3) \
             ON CONFLICT(uid) DO UPDATE SET seconds=excluded.seconds,revision=excluded.revision",
            params![i64::from(uid), i64::from(seconds), revision as i64],
        )
        .map_err(|_| invalid())?;
        let preference = IdleAdvisoryPreference { seconds, revision };
        records.insert(uid, preference);
        let tag = compute_tag(&self.integrity_key, &records)?;
        let changed = txn
            .execute(
                "UPDATE idle_advisory_identity SET integrity_tag=?1 WHERE singleton=1",
                params![tag.as_slice()],
            )
            .map_err(|_| invalid())?;
        if changed != 1 {
            return Err(invalid());
        }
        read_verified(&txn, &self.integrity_key)?;
        txn.commit().map_err(|_| invalid())?;
        Ok(preference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SqliteIntegrityKey {
        SqliteIntegrityKey::new(vec![17_u8; 32]).unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[test]
    fn durable_cas_recovery_and_corruption_are_fail_closed() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("linura-idle-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&directory).unwrap_or_else(|error| unreachable!("{error}"));
        let path = directory.join("prefs.sqlite3");
        {
            let mut store = SqliteIdleAdvisoryPreferenceStore::open(&path, key())
                .unwrap_or_else(|error| unreachable!("{error}"));
            assert_eq!(
                store
                    .get(1000)
                    .unwrap_or_else(|error| unreachable!("{error}")),
                IdleAdvisoryPreference {
                    seconds: 300,
                    revision: 0,
                }
            );
            assert!(store.compare_and_set(0, 600, 0).is_err());
            for seconds in [0, 59, 61, 3601, 7200] {
                assert!(store.compare_and_set(1000, seconds, 0).is_err());
            }
            assert_eq!(
                store
                    .compare_and_set(1000, 600, 0)
                    .unwrap_or_else(|error| unreachable!("{error}")),
                IdleAdvisoryPreference {
                    seconds: 600,
                    revision: 1,
                }
            );
            assert!(store.compare_and_set(1000, 900, 0).is_err());
            assert_eq!(
                store
                    .get(1000)
                    .unwrap_or_else(|error| unreachable!("{error}"))
                    .revision,
                1
            );
        }
        {
            let store = SqliteIdleAdvisoryPreferenceStore::open(&path, key())
                .unwrap_or_else(|error| unreachable!("{error}"));
            assert_eq!(
                store
                    .get(1000)
                    .unwrap_or_else(|error| unreachable!("{error}"))
                    .seconds,
                600
            );
        }
        let wrong_key = SqliteIntegrityKey::new(vec![18_u8; 32])
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(SqliteIdleAdvisoryPreferenceStore::open(&path, wrong_key).is_err());
        let connection = Connection::open(&path).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(
            connection
                .execute(
                    "UPDATE idle_advisory_entries SET seconds=300 WHERE uid=1000",
                    []
                )
                .unwrap_or_else(|error| unreachable!("{error}")),
            1
        );
        drop(connection);
        assert!(SqliteIdleAdvisoryPreferenceStore::open(&path, key()).is_err());
        std::fs::remove_dir_all(&directory).unwrap_or_else(|error| unreachable!("{error}"));
    }
}
