//! S18-5 native scan event journal.
//!
//! A scan is a one-shot *event*, not an endlessly desired state. This
//! independent write-ahead journal consumes a request BEFORE RequestScan.
//! An indeterminate attempt never becomes retryable after a timeout/restart.
//! Row HMACs and a signed append-only chain detect local record edits and
//! suffix deletion, but cannot by themselves detect rollback of the complete
//! database and its protected metadata: recovery must use trusted backup/
//! filesystem rollback protection, or remain fail-closed.
//!
//! This is persistence and replay prevention, NEVER policy or dispatch
//! authorization. The caller must separately prove the original authenticated
//! Control subject, purpose-bound approval, exact native identity, and an
//! independently witnessed postcondition before marking an attempt verified.

use std::fmt::{Debug, Formatter};
use std::path::Path;
use std::time::Duration;

use linura_transaction::TransactionStoreError;
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior, params};

use crate::integrity::{SqliteIntegrityKey, canonical_field};
use crate::validation::sqlite;

const APPLICATION_ID: i64 = 0x4c4e5253; // LNRS, separate from LNRT/LNRP/LNRQ.
const SCHEMA_VERSION: i64 = 1;
const MAX_EVENTS: u64 = 8192;
const MAX_PAGES: i64 = 8192;
const MIN_INTERVAL_MS: u64 = 30_000;
const EVENT_DOMAIN: &str = "linura.sqlite.wifi-scan-event.v1";
const CHAIN_DOMAIN: &str = "linura.sqlite.wifi-scan-chain.v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WifiScanAttempt {
    pub request_id: String,
    pub principal: String,
    /// Exact digest of boot/bus/NM-owner/kernel-device/session/seat facts.
    pub device_binding: String,
    /// Native boot ID, not UI or wall-clock input.
    pub boot_id: String,
    /// The sealed one-use Control dispatch digest, not an executor grant.
    pub dispatch_digest: String,
    /// CLOCK_BOOTTIME milliseconds, sampled before native handoff.
    pub started_boot_ms: u64,
    pub baseline_last_scan_ms: i64,
}

impl WifiScanAttempt {
    fn validate(&self) -> Result<(), TransactionStoreError> {
        let nonzero = |value: &str| !value.is_empty() && (value.len() == 1 || !value.starts_with('0'))
            && value.bytes().all(|b| b.is_ascii_digit());
        let principal_uid = self.principal.strip_prefix("unix:uid:").unwrap_or("");
        if !self.request_id.starts_with("request:v010:wifi-scan:")
            || self.request_id.len() > 128
            || self.request_id.len() <= "request:v010:wifi-scan:".len()
            || !self.request_id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b,b':'|b'-'|b'_'|b'.'))
            || !nonzero(principal_uid)
            || principal_uid.parse::<u32>().is_err()
            || principal_uid == "0"
            || !canonical_sha256(&self.device_binding)
            || !canonical_sha256(&self.dispatch_digest)
            || self.boot_id.len() != 36
            || self.boot_id.bytes().enumerate().any(|(i, b)| {
                if [8,13,18,23].contains(&i) { b != b'-' } else { !b.is_ascii_hexdigit() || b.is_ascii_uppercase() }
            })
            || self.started_boot_ms == 0
            || i64::try_from(self.started_boot_ms).is_err()
            || self.baseline_last_scan_ms < -1
            || (self.baseline_last_scan_ms >= 0
                && u64::try_from(self.baseline_last_scan_ms).is_ok_and(|ms| ms > self.started_boot_ms))
        {
            return Err(TransactionStoreError::AuthorityRejected);
        }
        Ok(())
    }
}

fn canonical_sha256(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WifiScanAttemptState {
    Indeterminate,
    Verified,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WifiScanAttemptStatus {
    pub attempt: WifiScanAttempt,
    pub state: WifiScanAttemptState,
    pub verified_last_scan_ms: Option<u64>,
}

#[derive(Clone, Debug)]
struct Event {
    sequence: u64,
    attempt: WifiScanAttempt,
    kind: &'static str,
    completed_last_scan_ms: Option<u64>,
    tag: Vec<u8>,
}

fn corrupt() -> TransactionStoreError {
    TransactionStoreError::Corruption("native scan journal signature/chain or event sequence invalid".into())
}

fn event_bytes(event: &Event) -> Vec<u8> {
    let mut result = Vec::with_capacity(480);
    for value in [
        event.sequence.to_string(),
        event.attempt.request_id.clone(),
        event.attempt.principal.clone(),
        event.attempt.device_binding.clone(),
        event.attempt.boot_id.clone(),
        event.attempt.dispatch_digest.clone(),
        event.attempt.started_boot_ms.to_string(),
        event.attempt.baseline_last_scan_ms.to_string(),
        event.kind.to_owned(),
        event.completed_last_scan_ms.map(|v| v.to_string()).unwrap_or_default(),
    ] {
        canonical_field(&mut result, value.as_bytes());
    }
    result
}

fn chain_tag(
    key: &SqliteIntegrityKey,
    previous: &[u8],
    event: &Event,
) -> Result<Vec<u8>, TransactionStoreError> {
    let mut payload = Vec::with_capacity(128);
    canonical_field(&mut payload, previous);
    canonical_field(&mut payload, &event.sequence.to_be_bytes());
    canonical_field(&mut payload, &event.tag);
    Ok(key.tag(CHAIN_DOMAIN, &payload)?.to_vec())
}

fn load_events(
    db: &Connection,
    key: &SqliteIntegrityKey,
) -> Result<Vec<Event>, TransactionStoreError> {
    let (count, tip): (i64, Vec<u8>) = db.query_row(
        "SELECT event_count, chain_tip FROM metadata WHERE id=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(sqlite)?;
    let count = u64::try_from(count).map_err(|_| corrupt())?;
    if count > MAX_EVENTS || tip.len() != 32 {
        return Err(corrupt());
    }
    let mut stmt = db.prepare(
        "SELECT sequence, request_id, principal, device_binding, boot_id, dispatch_digest, \
         started_boot_ms, baseline_last_scan_ms, kind, completed_last_scan_ms, tag \
         FROM events ORDER BY sequence ASC"
    ).map_err(sqlite)?;
    let mut rows = stmt.query([]).map_err(sqlite)?;
    let mut events = Vec::new();
    let mut prior = key.tag(CHAIN_DOMAIN, b"genesis")?.to_vec();
    while let Some(row) = rows.next().map_err(sqlite)? {
        if events.len() >= MAX_EVENTS as usize {
            return Err(corrupt());
        }
        let sequence: i64 = row.get(0).map_err(sqlite)?;
        let kind: String = row.get(8).map_err(sqlite)?;
        let completed: Option<i64> = row.get(9).map_err(sqlite)?;
        let event = Event {
            sequence: u64::try_from(sequence).map_err(|_| corrupt())?,
            attempt: WifiScanAttempt {
                request_id: row.get(1).map_err(sqlite)?,
                principal: row.get(2).map_err(sqlite)?,
                device_binding: row.get(3).map_err(sqlite)?,
                boot_id: row.get(4).map_err(sqlite)?,
                dispatch_digest: row.get(5).map_err(sqlite)?,
                started_boot_ms: u64::try_from(row.get::<_,i64>(6).map_err(sqlite)?)
                    .map_err(|_| corrupt())?,
                baseline_last_scan_ms: row.get(7).map_err(sqlite)?,
            },
            kind: match kind.as_str() {
                "spent" => "spent",
                "verified" => "verified",
                _ => return Err(corrupt()),
            },
            completed_last_scan_ms: completed
                .map(|ms| u64::try_from(ms).map_err(|_| corrupt()))
                .transpose()?,
            tag: row.get(10).map_err(sqlite)?,
        };
        if event.sequence != events.len() as u64 + 1 || event.attempt.validate().is_err()
            || (event.kind == "spent" && event.completed_last_scan_ms.is_some())
            || (event.kind == "verified" && event.completed_last_scan_ms.is_none())
            || !key.verify(EVENT_DOMAIN, &event_bytes(&event), &event.tag)
        {
            return Err(corrupt());
        }
        prior = chain_tag(key, &prior, &event)?;
        events.push(event);
    }
    if events.len() as u64 != count || prior != tip {
        return Err(corrupt());
    }
    let mut state = std::collections::BTreeMap::<&str, (&WifiScanAttempt,bool)>::new();
    for event in &events {
        if event.kind == "spent" {
            if state.contains_key(event.attempt.request_id.as_str()) {
                return Err(corrupt());
            }
            state.insert(&event.attempt.request_id, (&event.attempt,false));
        } else {
            let Some((original,verified)) = state.get_mut(event.attempt.request_id.as_str()) else {
                return Err(corrupt());
            };
            if *verified || *original != &event.attempt
                || event.completed_last_scan_ms.is_none_or(|ms|
                    ms < original.started_boot_ms
                    || ms <= u64::try_from(original.baseline_last_scan_ms).unwrap_or(0)
                )
            {
                return Err(corrupt());
            }
            *verified = true;
        }
    }
    Ok(events)
}

pub struct SqliteWifiScanAttemptJournal {
    db: Connection,
    key: SqliteIntegrityKey,
}

impl Debug for SqliteWifiScanAttemptJournal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SqliteWifiScanAttemptJournal([REDACTED])")
    }
}

impl SqliteWifiScanAttemptJournal {
    pub fn open(path: impl AsRef<Path>, key: SqliteIntegrityKey)
        -> Result<Self, TransactionStoreError>
    {
        let db = Connection::open_with_flags(
            path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ).map_err(sqlite)?;
        db.busy_timeout(Duration::from_millis(500)).map_err(sqlite)?;
        let application: i64 = db.pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(sqlite)?;
        let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(sqlite)?;
        let objects: i64 = db.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'", [],
            |r| r.get(0)
        ).map_err(sqlite)?;
        let fresh = application == 0 && version == 0 && objects == 0;
        if !fresh && (application != APPLICATION_ID || version != SCHEMA_VERSION) {
            return Err(corrupt());
        }
        db.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; \
             PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=128; \
             PRAGMA journal_size_limit=524288;"
        ).map_err(sqlite)?;
        let mode: String = db.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(sqlite)?;
        if mode != "wal" {
            return Err(corrupt());
        }
        db.pragma_update(None, "max_page_count", MAX_PAGES).map_err(sqlite)?;
        if fresh {
            let initial = key.tag(CHAIN_DOMAIN, b"genesis")?;
            db.execute_batch(
                "BEGIN IMMEDIATE; \
                 CREATE TABLE metadata(id INTEGER PRIMARY KEY CHECK(id=1), \
                    event_count INTEGER NOT NULL, chain_tip BLOB NOT NULL); \
                 CREATE TABLE events ( \
                    sequence INTEGER PRIMARY KEY, \
                    request_id TEXT NOT NULL,principal TEXT NOT NULL,device_binding TEXT NOT NULL, \
                    boot_id TEXT NOT NULL,dispatch_digest TEXT NOT NULL, \
                    started_boot_ms INTEGER NOT NULL,baseline_last_scan_ms INTEGER NOT NULL, \
                    kind TEXT NOT NULL CHECK(kind IN ('spent','verified')), \
                    completed_last_scan_ms INTEGER,tag BLOB NOT NULL); \
                 PRAGMA application_id=1280201299; PRAGMA user_version=1;"
            ).map_err(sqlite)?;
            // The application id is LNRS; never accept a mismatched literal.
            db.execute(
                "INSERT INTO metadata(id,event_count,chain_tip) VALUES(1,0,?1)",
                params![initial.as_slice()]
            ).map_err(sqlite)?;
            db.execute_batch("COMMIT").map_err(sqlite)?;
        }
        let store = Self {db,key};
        if store.db.pragma_query_value(None,"application_id",|r|r.get::<_,i64>(0))
            .map_err(sqlite)? != APPLICATION_ID
        {
            return Err(corrupt());
        }
        load_events(&store.db,&store.key)?;
        Ok(store)
    }

    pub fn begin(&mut self, attempt: WifiScanAttempt)
        -> Result<(), TransactionStoreError>
    {
        attempt.validate()?;
        let transaction = self.db.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite)?;
        let history = load_events(&transaction, &self.key)?;
        if history.len() >= MAX_EVENTS as usize {
            return Err(TransactionStoreError::CapacityExceeded);
        }
        if history.iter().any(|e| e.attempt.request_id == attempt.request_id) {
            return Err(TransactionStoreError::IdempotencyConflict);
        }
        let mut last_start = None::<u64>;
        for event in &history {
            if event.kind != "spent" || event.attempt.boot_id != attempt.boot_id
                || event.attempt.device_binding != attempt.device_binding {
                continue;
            }
            let resolved = history.iter().any(|other|
                other.kind == "verified" && other.attempt.request_id == event.attempt.request_id);
            if !resolved {
                return Err(TransactionStoreError::StateConflict);
            }
            last_start = Some(last_start.map_or(event.attempt.started_boot_ms,
                |last| last.max(event.attempt.started_boot_ms)));
        }
        if let Some(last) = last_start {
            if attempt.started_boot_ms < last || attempt.started_boot_ms-last < MIN_INTERVAL_MS {
                return Err(TransactionStoreError::StateConflict);
            }
        }
        append(&transaction,&self.key,&history,Event {
            sequence: history.len() as u64 + 1, attempt,
            kind:"spent",completed_last_scan_ms:None,tag:Vec::new()
        })?;
        transaction.commit().map_err(sqlite)
    }

    /// Only an independently attested native observer may provide this
    /// completion evidence. It does not grant permission to dispatch again.
    pub fn verified(&mut self, request_id: &str, observed_last_scan_ms: u64)
        -> Result<(), TransactionStoreError>
    {
        let transaction = self.db.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite)?;
        let history = load_events(&transaction,&self.key)?;
        if history.len() >= MAX_EVENTS as usize {
            return Err(TransactionStoreError::CapacityExceeded);
        }
        let spent = history.iter().find(|e|
            e.kind=="spent" && e.attempt.request_id==request_id)
            .ok_or(TransactionStoreError::NotFound)?;
        if history.iter().any(|e| e.kind=="verified" && e.attempt.request_id==request_id)
            || observed_last_scan_ms < spent.attempt.started_boot_ms
            || i64::try_from(observed_last_scan_ms).is_err()
            || (spent.attempt.baseline_last_scan_ms >= 0
                && observed_last_scan_ms <= spent.attempt.baseline_last_scan_ms as u64)
        {
            return Err(TransactionStoreError::StateConflict);
        }
        append(&transaction,&self.key,&history,Event {
            sequence:history.len() as u64+1, attempt:spent.attempt.clone(),
            kind:"verified",completed_last_scan_ms:Some(observed_last_scan_ms),tag:Vec::new()
        })?;
        transaction.commit().map_err(sqlite)
    }

    pub fn status(&self, request_id: &str)
        -> Result<Option<WifiScanAttemptStatus>, TransactionStoreError>
    {
        let history = load_events(&self.db,&self.key)?;
        let Some(spent) = history.iter().find(|e|
            e.kind=="spent" && e.attempt.request_id==request_id)
        else {return Ok(None);};
        let finished = history.iter().find(|e|
            e.kind=="verified" && e.attempt.request_id==request_id);
        Ok(Some(WifiScanAttemptStatus {
            attempt:spent.attempt.clone(),
            state:if finished.is_some() {
                WifiScanAttemptState::Verified
            } else {WifiScanAttemptState::Indeterminate},
            verified_last_scan_ms:finished.and_then(|e|e.completed_last_scan_ms),
        }))
    }
}

fn append(
    db: &Transaction<'_>, key: &SqliteIntegrityKey,
    history: &[Event], mut event: Event
) -> Result<(), TransactionStoreError> {
    let mut prior = key.tag(CHAIN_DOMAIN, b"genesis")?.to_vec();
    for row in history {
        prior = chain_tag(key, &prior, row)?;
    }
    let sequence=i64::try_from(event.sequence).map_err(|_| TransactionStoreError::CapacityExceeded)?;
    event.tag = key.tag(EVENT_DOMAIN,&event_bytes(&event))?.to_vec();
    let tip=chain_tag(key,&prior,&event)?;
    db.execute(
        "INSERT INTO events(sequence,request_id,principal,device_binding,boot_id,dispatch_digest, \
            started_boot_ms,baseline_last_scan_ms,kind,completed_last_scan_ms,tag) \
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![sequence,&event.attempt.request_id,&event.attempt.principal,
            &event.attempt.device_binding,&event.attempt.boot_id,&event.attempt.dispatch_digest,
            i64::try_from(event.attempt.started_boot_ms).map_err(|_|TransactionStoreError::CapacityExceeded)?,
            event.attempt.baseline_last_scan_ms,event.kind,
            event.completed_last_scan_ms.map(|ms|i64::try_from(ms).map_err(|_|TransactionStoreError::CapacityExceeded)).transpose()?,
            &event.tag]
    ).map_err(sqlite)?;
    let written=db.execute(
        "UPDATE metadata SET event_count=?1,chain_tip=?2 WHERE id=1",
        params![sequence,tip]
    ).map_err(sqlite)?;
    if written != 1 {
        return Err(corrupt());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64,Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn scratch(label:&str)->std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "linura-s18-wifi-scan-{}-{}-{label}.sqlite3",
            std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed)))
    }
    fn key()->SqliteIntegrityKey {
        SqliteIntegrityKey::new(vec![0x33;32])
            .unwrap_or_else(|e|unreachable!("{e}"))
    }
    fn attempt(request:&str,time:u64)->WifiScanAttempt {
        WifiScanAttempt {
            request_id:format!("request:v010:wifi-scan:{request}"),
            principal:"unix:uid:1000".into(),
            device_binding:format!("sha256:{}", "1".repeat(64)),
            boot_id:"abcd1234-1234-4567-89ab-0123456789ab".into(),
            dispatch_digest:format!("sha256:{}", "2".repeat(64)),
            started_boot_ms:time,
            baseline_last_scan_ms:100_000,
        }
    }
    #[test]
    fn spent_attempt_survives_restart_and_never_replays() {
        let path=scratch("restart");
        {
            let mut db=SqliteWifiScanAttemptJournal::open(&path,key())
                .unwrap_or_else(|e|unreachable!("{e}"));
            db.begin(attempt("first",120_000)).unwrap_or_else(|e|unreachable!("{e}"));
            assert_eq!(db.status("request:v010:wifi-scan:first")
                .unwrap_or_else(|e|unreachable!("{e}")).unwrap().state,
                WifiScanAttemptState::Indeterminate);
            assert!(db.begin(attempt("first",200_000)).is_err());
            assert!(db.begin(attempt("second",200_000)).is_err());
        }
        let mut db=SqliteWifiScanAttemptJournal::open(&path,key())
            .unwrap_or_else(|e|unreachable!("{e}"));
        assert!(db.begin(attempt("third",200_000)).is_err());
        db.verified("request:v010:wifi-scan:first",120_005)
            .unwrap_or_else(|e|unreachable!("{e}"));
        assert!(db.begin(attempt("second",135_000)).is_err());
        db.begin(attempt("second",155_000))
            .unwrap_or_else(|e|unreachable!("{e}"));
        let _=std::fs::remove_file(path);
    }
    #[test]
    fn tamper_deletion_and_changed_credentials_refuse_reopen() {
        let path=scratch("tamper");
        {
            let mut db=SqliteWifiScanAttemptJournal::open(&path,key())
                .unwrap_or_else(|e|unreachable!("{e}"));
            db.begin(attempt("first",120_000)).unwrap_or_else(|e|unreachable!("{e}"));
        }
        assert!(SqliteWifiScanAttemptJournal::open(&path,
            SqliteIntegrityKey::new(vec![0x22;32]).unwrap_or_else(|e|unreachable!("{e}"))).is_err());
        let direct=Connection::open(&path).unwrap_or_else(|e|unreachable!("{e}"));
        direct.execute("DELETE FROM events WHERE sequence=1",[])
            .unwrap_or_else(|e|unreachable!("{e}"));
        drop(direct);
        assert!(SqliteWifiScanAttemptJournal::open(&path,key()).is_err());
        let _=std::fs::remove_file(path);
    }
    #[test]
    fn malformed_requests_and_unverified_evidence_are_denied() {
        let path=scratch("negative");
        let mut db=SqliteWifiScanAttemptJournal::open(&path,key())
            .unwrap_or_else(|e|unreachable!("{e}"));
        let mut a=attempt("first",120_000);
        a.principal="unix:uid:0".into();
        assert!(db.begin(a).is_err());
        db.begin(attempt("first",120_000)).unwrap_or_else(|e|unreachable!("{e}"));
        assert!(db.verified("request:v010:wifi-scan:first",115_000).is_err());
        assert!(db.verified("request:v010:wifi-scan:first",120_100).is_ok());
        assert!(db.verified("request:v010:wifi-scan:first",121_000).is_err());
        let _=std::fs::remove_file(path);
    }
}
