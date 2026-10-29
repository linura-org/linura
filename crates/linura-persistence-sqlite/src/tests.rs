use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use linura_core::{
    CapabilityId, PlanId, PolicyId, PolicyRevisionId, PrincipalId, ProviderId, RequestId,
    ResourceId, RiskClass, ValidationError,
};
use linura_transaction::{
    AuthorizationBasis, RecoveryResolution, TransactionAuthorityKey, TransactionAuthoritySigner,
    TransactionAuthorityVerifier, TransactionSnapshot, TransactionState, TransactionStore,
    TransactionStoreError, TransactionValidationError, digest_bytes,
};
use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, params};

use super::*;
use crate::schema::{APPLICATION_ID, MIGRATION_ID, MIGRATION_V1, MIGRATION_V2_ID, SCHEMA_VERSION};
use crate::validation::{pragma_i64, reservation_bytes};

static NEXT_DB: AtomicU64 = AtomicU64::new(0);

struct TestDatabase {
    path: PathBuf,
}

impl TestDatabase {
    fn new() -> Self {
        let sequence = NEXT_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "linura-v04-hardened-sqlite-{}-{sequence}.db",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(PathBuf::from(format!("{}-wal", path.display())));
        let _ = fs::remove_file(PathBuf::from(format!("{}-shm", path.display())));
        let _ = fs::remove_file(PathBuf::from(format!(
            "{}.linura-recovery-reserve",
            path.display()
        )));
        Self { path }
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(PathBuf::from(format!("{}-wal", self.path.display())));
        let _ = fs::remove_file(PathBuf::from(format!("{}-shm", self.path.display())));
        let _ = fs::remove_file(PathBuf::from(format!(
            "{}.linura-recovery-reserve",
            self.path.display()
        )));
    }
}

fn id<T>(value: Result<T, ValidationError>) -> T {
    value.unwrap_or_else(|error| unreachable!("{error}"))
}

fn digest(value: &str) -> linura_transaction::ContentDigest {
    digest_bytes("test", value.as_bytes())
}

fn fixture_key(index: usize) -> Vec<u8> {
    use std::io::Read;
    // Retain independently generated test domains across simulated reopen.
    static KEYS: std::sync::OnceLock<[[u8; 32]; 4]> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        let mut keys = [[0_u8; 32]; 4];
        let mut entropy = fs::File::open("/dev/urandom")
            .unwrap_or_else(|error| unreachable!("test entropy unavailable: {error}"));
        for key in &mut keys {
            entropy.read_exact(key)
                .unwrap_or_else(|error| unreachable!("test entropy unavailable: {error}"));
        }
        keys
    })[index].to_vec()
}

#[test]
fn fixture_keys_survive_reopen_without_sharing_authority_or_integrity_material() {
    for first in 0..4 {
        assert!(fixture_key(first) == fixture_key(first));
        assert!(fixture_key(first).iter().any(|byte| *byte != 0));
        for second in first + 1..4 {
            // Boolean assertions never include random material in panic output.
            assert!(fixture_key(first) != fixture_key(second));
        }
    }
}

fn authority() -> (TransactionAuthoritySigner, TransactionAuthorityVerifier) {
    TransactionAuthorityKey::new(fixture_key(0))
        .unwrap_or_else(|error| unreachable!("{error}"))
        .split()
}

fn integrity_key() -> SqliteIntegrityKey {
    SqliteIntegrityKey::new(fixture_key(1))
        .unwrap_or_else(|error| unreachable!("{error}"))
}

fn alternate_integrity_key() -> SqliteIntegrityKey {
    SqliteIntegrityKey::new(fixture_key(2))
        .unwrap_or_else(|error| unreachable!("{error}"))
}

fn open_store(path: impl AsRef<Path>) -> (TransactionAuthoritySigner, SqliteTransactionStore) {
    let (signer, verifier) = authority();
    let store = SqliteTransactionStore::open(path, verifier, integrity_key())
        .unwrap_or_else(|error| unreachable!("{error}"));
    (signer, store)
}

fn binding_with_request(request: &str, observation: &str) -> linura_transaction::AuthorityBinding {
    linura_transaction::AuthorityBinding::try_new(
        id(PrincipalId::new("uid:1000")),
        id(RequestId::new(request)),
        id(PlanId::new(request)),
        digest("request"),
        digest("precondition"),
        digest(observation),
        id(ProviderId::new("systemd")),
        id(ResourceId::new("systemd:unit:test.service")),
        id(CapabilityId::new("systemd.unit.observe")),
        id(PolicyId::new("policy:baseline")),
        id(PolicyRevisionId::new("policy:baseline:v1")),
        RiskClass::SecuritySensitive,
        "risk-policy:v0.4:1",
        vec!["systemd.active-state.security".into()],
        digest("review"),
        AuthorizationBasis::PolicyAllow,
    )
    .unwrap_or_else(|error: TransactionValidationError| unreachable!("{error}"))
}

fn binding_with_observation(observation: &str) -> linura_transaction::AuthorityBinding {
    binding_with_request("request:sqlite", observation)
}

fn prepared_snapshot(outcome: linura_transaction::PrepareOutcome) -> TransactionSnapshot {
    match outcome {
        linura_transaction::PrepareOutcome::Created(snapshot)
        | linura_transaction::PrepareOutcome::Existing(snapshot) => snapshot,
    }
}

// S21-3 physical brightness is deliberately not registered or executable.
// This fixture checks only the existing production SQLite transaction store's
// persistence/one-shot behavior when handed syntactically canonical backlight
// authority material. The signer represents trusted Control in this test; it
// is NOT proof of hardware qualification, native execution or approval policy.
fn s21_backlight_sqlite_binding(
    generation: &str,
) -> linura_transaction::AuthorityBinding {
    use linura_core::{
        ApprovalEvidenceId, ApprovalRequestId, BacklightDeviceGeneration,
        BacklightResourceId, BootId, SessionEpoch,
    };
    use linura_transaction::ApprovalAuthority;
    let target = BacklightResourceId::new(
        SessionEpoch::new(
            BootId::new("abcd1234-1234-4567-89ab-0123456789ab")
                .unwrap_or_else(|error| unreachable!("{error}")),
            1000,
            "c2",
            42,
        )
        .unwrap_or_else(|error| unreachable!("{error}")),
        BacklightDeviceGeneration::new(generation)
            .unwrap_or_else(|error| unreachable!("{error}")),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    let approval = ApprovalAuthority::try_new(
        id(ApprovalEvidenceId::new("approval:backlight-sqlite")),
        id(ApprovalRequestId::new("approval-request:backlight-sqlite")),
        id(PrincipalId::new("unix:uid:1000")),
        "administrator",
        1,
        u64::MAX,
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    linura_transaction::AuthorityBinding::try_new(
        id(PrincipalId::new("unix:uid:1000")),
        id(RequestId::new("request:backlight-sqlite-once")),
        id(PlanId::new("request:backlight-sqlite-once")),
        digest("backlight-request"),
        digest("physical-qualification-not-proven"),
        digest("fresh-native-observation-not-proven"),
        id(ProviderId::new("logind-backlight")),
        target.resource_id().unwrap_or_else(|error| unreachable!("{error}")),
        id(CapabilityId::new("display.backlight.observe")),
        id(PolicyId::new("policy:baseline")),
        id(PolicyRevisionId::new("policy:baseline:v1")),
        RiskClass::SecuritySensitive,
        "risk-policy:s21-3:1",
        vec!["test.backlight.security-sensitive".into()],
        digest("review"),
        AuthorizationBasis::Approval(approval),
    )
    .unwrap_or_else(|error| unreachable!("{error}"))
}

#[test]
fn s21_backlight_sqlite_consumed_handoff_survives_reopen_without_replay() {
    let db = TestDatabase::new();
    let binding = s21_backlight_sqlite_binding(
        "98765432-1234-4567-89ab-0123456789ab",
    );
    let (signer, mut store) = open_store(&db.path);
    let prepared = prepared_snapshot(
        store.prepare(&binding).unwrap_or_else(|error| unreachable!("{error}")),
    );
    assert_eq!(prepared.state, TransactionState::Prepared);
    assert_eq!(prepared.principal.as_str(), "unix:uid:1000");
    let reserved = signer
        .authorize_handoff(&prepared, digest("backlight-dispatch-once"), 1, u64::MAX)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let consumed = store
        .handoff(&reserved)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(consumed.transaction_id, prepared.transaction_id);
    drop(store); // Simulate loss of Control process state after dispatch reservation.

    let (_, mut restarted) = open_store(&db.path);
    let retained = restarted
        .snapshot(&prepared.transaction_id)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(retained.state, TransactionState::Indeterminate);
    assert_eq!(retained.state_version, consumed.state_version);
    assert_eq!(retained.current_generation, prepared.current_generation);
    assert_eq!(retained.binding_digest, *binding.digest());
    // Even a byte-for-byte replay of a genuine, previously signed handoff
    // cannot dispatch a second time or roll the persisted attempt backward.
    assert!(matches!(
        restarted.handoff(&reserved),
        Err(TransactionStoreError::StateConflict)
    ));
    assert!(matches!(
        restarted.prepare(&binding),
        Err(TransactionStoreError::IdempotencyConflict)
    ));
    assert_eq!(
        restarted
            .snapshot(&prepared.transaction_id)
            .unwrap_or_else(|error| unreachable!("{error}")),
        retained
    );
    restarted
        .integrity_check()
        .unwrap_or_else(|error| unreachable!("{error}"));
}

#[test]
fn s21_backlight_sqlite_indeterminate_recovery_remains_no_replay_after_restart() {
    let db = TestDatabase::new();
    let binding = s21_backlight_sqlite_binding(
        "98765432-1234-4567-89ab-0123456789ab",
    );
    let (signer, mut store) = open_store(&db.path);
    let prepared = prepared_snapshot(
        store.prepare(&binding).unwrap_or_else(|error| unreachable!("{error}")),
    );
    let reserved = signer
        .authorize_handoff(&prepared, digest("one-original-backlight-attempt"), 1, u64::MAX)
        .unwrap_or_else(|error| unreachable!("{error}"));
    store.handoff(&reserved).unwrap_or_else(|error| unreachable!("{error}"));
    drop(store);

    let (_, mut reopened) = open_store(&db.path);
    let uncertain = reopened
        .snapshot(&prepared.transaction_id)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(uncertain.state, TransactionState::Indeterminate);
    // The signed ambiguous resolution records an observation without claiming
    // either a successful physical write or the absence of an earlier effect.
    let ambiguous = signer
        .authorize_recovery(
            &uncertain,
            RecoveryResolution::Ambiguous {
                observation_digest: digest("unsettled-actual-brightness"),
            },
            1,
            u64::MAX,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let recovered = reopened
        .recover(&ambiguous)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let linura_transaction::RecoveryOutcome::StillIndeterminate(next) = recovered else {
        unreachable!("ambiguous actual brightness cannot verify or reprepare an effect");
    };
    assert_eq!(next.state, TransactionState::Indeterminate);
    assert_eq!(next.current_generation, uncertain.current_generation);
    assert!(next.state_version > uncertain.state_version);
    drop(reopened);

    let (_, mut restarted_again) = open_store(&db.path);
    assert_eq!(
        restarted_again
            .snapshot(&prepared.transaction_id)
            .unwrap_or_else(|error| unreachable!("{error}")),
        next
    );
    assert!(matches!(
        restarted_again.handoff(&reserved),
        Err(TransactionStoreError::StateConflict)
    ));
    // A different physical device generation under the *same* request must
    // not silently reuse the retained authority or allocate an alternative
    // attempt. Storage rejects changed binding material.
    let replaced = s21_backlight_sqlite_binding(
        "98765432-1234-4567-89ab-0123456789ac",
    );
    assert_ne!(binding.digest(), replaced.digest());
    assert!(matches!(
        restarted_again.prepare(&replaced),
        Err(TransactionStoreError::IdempotencyConflict)
    ));
    restarted_again
        .integrity_check()
        .unwrap_or_else(|error| unreachable!("{error}"));
}

#[test]
fn qualified_sqlite_settings_are_enforced() {
    let db = TestDatabase::new();
    let store = open_store(&db.path).1;
    let settings = store
        .settings()
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(settings.journal_mode.to_ascii_lowercase(), "wal");
    assert_eq!(settings.synchronous, 2);
    assert_eq!(settings.foreign_keys, 1);
    assert_eq!(settings.trusted_schema, 0);
    assert!(settings.max_page_count > 0);
}

#[test]
fn exact_prepare_replay_survives_reopen_and_changed_binding_conflicts() {
    let db = TestDatabase::new();
    let binding = binding_with_observation("observation-a");
    let first = {
        let mut store = open_store(&db.path).1;
        prepared_snapshot(
            store
                .prepare(&binding)
                .unwrap_or_else(|error| unreachable!("{error}")),
        )
    };
    let mut reopened = open_store(&db.path).1;
    let replay = prepared_snapshot(
        reopened
            .prepare(&binding)
            .unwrap_or_else(|error| unreachable!("{error}")),
    );
    assert_eq!(first, replay);
    assert!(matches!(
        reopened.prepare(&binding_with_observation("observation-b")),
        Err(TransactionStoreError::IdempotencyConflict)
    ));
}

#[test]
fn wrong_verifier_or_record_integrity_key_is_rejected_on_reopen() {
    let db = TestDatabase::new();
    drop(open_store(&db.path).1);

    let wrong_verifier = TransactionAuthorityKey::new(fixture_key(3))
        .unwrap_or_else(|error| unreachable!("{error}"))
        .split()
        .1;
    assert!(matches!(
        SqliteTransactionStore::open(&db.path, wrong_verifier, integrity_key()),
        Err(TransactionStoreError::AuthorityRejected)
    ));
    assert!(matches!(
        SqliteTransactionStore::open(&db.path, authority().1, alternate_integrity_key()),
        Err(TransactionStoreError::AuthorityRejected)
    ));
}

#[test]
fn handoff_recovery_verified_commit_and_restart_resume_are_authenticated() {
    let db = TestDatabase::new();
    let binding = binding_with_observation("authenticated-flow");
    let (signer, mut store) = open_store(&db.path);
    let prepared = prepared_snapshot(
        store
            .prepare(&binding)
            .unwrap_or_else(|error| unreachable!("{error}")),
    );
    let handoff = store
        .handoff(
            &signer
                .authorize_handoff(&prepared, digest("authority-use"), 1, u64::MAX)
                .unwrap_or_else(|error| unreachable!("{error}")),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let indeterminate = TransactionSnapshot {
        state: TransactionState::Indeterminate,
        state_version: handoff.state_version,
        ..prepared.clone()
    };
    let desired = digest("desired");
    let graph = digest("graph");
    let provenance = digest("provenance");
    let recovery = signer
        .authorize_recovery(
            &indeterminate,
            RecoveryResolution::IntendedStateVerified {
                observation_digest: digest("verified-observation"),
                desired_state_digest: desired.clone(),
                graph_digest: graph.clone(),
                provenance_digest: provenance.clone(),
            },
            1,
            u64::MAX,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let linura_transaction::RecoveryOutcome::Verified(verified) = store
        .recover(&recovery)
        .unwrap_or_else(|error| unreachable!("{error}"))
    else {
        unreachable!("expected verified")
    };
    drop(store);

    let (signer, mut reopened) = open_store(&db.path);
    let material = reopened
        .verified_commit_material(&verified.transaction_id)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(material.snapshot, verified);
    assert_eq!(material.desired_state_digest, desired);
    assert_eq!(material.graph_digest, graph);
    assert_eq!(material.provenance_digest, provenance);
    let commit = signer
        .authorize_commit(
            &material.snapshot,
            material.desired_state_digest,
            material.graph_digest,
            material.provenance_digest,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let committed = reopened
        .commit(&commit)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(committed.state, TransactionState::Committed);
    reopened
        .integrity_check()
        .unwrap_or_else(|error| unreachable!("{error}"));
}

#[test]
fn a_spoofed_sql_function_cannot_forge_authenticated_state() {
    let db = TestDatabase::new();
    let binding = binding_with_observation("spoofed-gate");
    let (_, mut store) = open_store(&db.path);
    let prepared = prepared_snapshot(
        store
            .prepare(&binding)
            .unwrap_or_else(|error| unreachable!("{error}")),
    );

    let raw = Connection::open(&db.path).unwrap_or_else(|error| unreachable!("{error}"));
    raw.create_scalar_function(
        "linura_internal_mutation_gate",
        0,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_INNOCUOUS,
        |_| Ok(1_i64),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    raw.execute(
        "UPDATE generations SET state='verified' WHERE transaction_id=?1 AND generation=0",
        params![prepared.transaction_id.as_str()],
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(matches!(
        store.snapshot(&prepared.transaction_id),
        Err(TransactionStoreError::Corruption(reason))
            if reason.contains("integrity tag mismatch")
    ));
}

#[test]
fn a_forged_audit_tail_cannot_be_legitimized_by_the_next_store_write() {
    let db = TestDatabase::new();
    let binding = binding_with_observation("forged-audit");
    let (_, mut store) = open_store(&db.path);
    let prepared = prepared_snapshot(
        store
            .prepare(&binding)
            .unwrap_or_else(|error| unreachable!("{error}")),
    );
    let raw = Connection::open(&db.path).unwrap_or_else(|error| unreachable!("{error}"));
    let zero = linura_transaction::ContentDigest::zero();
    raw.execute(
        "INSERT INTO audit_events (
            transaction_id,event_sequence,generation,state_version,event_kind,
            payload_digest,previous_digest,event_digest,integrity_tag
         ) VALUES (?1,1,0,2,'handoff-indeterminate',?2,?2,?2,zeroblob(32))",
        params![prepared.transaction_id.as_str(), zero.as_str()],
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    drop(raw);
    assert!(matches!(
        store.abort_prepared(&linura_transaction::AbortRequest {
            transaction_id: prepared.transaction_id.clone(),
            expected_generation: prepared.current_generation,
            expected_state_version: prepared.state_version,
            reason_digest: digest("restart-abort"),
        }),
        Err(TransactionStoreError::Corruption(reason))
            if reason.contains("audit record integrity tag mismatch")
    ));
}

#[test]
fn generation_rows_beyond_authenticated_current_pointer_fail_closed() {
    let db = TestDatabase::new();
    let (_, mut store) = open_store(&db.path);
    let prepared = prepared_snapshot(
        store
            .prepare(&binding_with_observation("forged-future-generation"))
            .unwrap_or_else(|error| unreachable!("{error}")),
    );
    let raw = Connection::open(&db.path).unwrap_or_else(|error| unreachable!("{error}"));
    raw.execute(
        "INSERT INTO generations (
            transaction_id,generation,state,binding_digest,binding_canonical,
            request_digest,precondition_digest,observation_digest,
            desired_state_digest,graph_digest,provenance_digest,integrity_tag
         ) SELECT transaction_id,1,state,binding_digest,binding_canonical,
                  request_digest,precondition_digest,observation_digest,
                  desired_state_digest,graph_digest,provenance_digest,zeroblob(32)
           FROM generations WHERE transaction_id=?1 AND generation=0",
        params![prepared.transaction_id.as_str()],
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    drop(raw);

    assert!(matches!(
        store.integrity_check(),
        Err(TransactionStoreError::Corruption(reason))
            if reason.contains("retained generation row count disagrees")
    ));
    drop(store);
    assert!(matches!(
        SqliteTransactionStore::open(&db.path, authority().1, integrity_key()),
        Err(TransactionStoreError::Corruption(reason))
            if reason.contains("retained generation row count disagrees")
    ));
}

#[test]
fn complete_integrity_validation_acquires_write_serialization_before_scanning() {
    let db = TestDatabase::new();
    let (_, store) = open_store(&db.path);
    let writer = Connection::open(&db.path).unwrap_or_else(|error| unreachable!("{error}"));
    writer
        .execute_batch("BEGIN IMMEDIATE")
        .unwrap_or_else(|error| unreachable!("{error}"));
    store
        .connection
        .busy_timeout(Duration::ZERO)
        .unwrap_or_else(|error| unreachable!("{error}"));

    assert!(matches!(
        store.integrity_check(),
        Err(TransactionStoreError::Storage(reason)) if reason.contains("locked")
    ));

    writer
        .execute_batch("ROLLBACK")
        .unwrap_or_else(|error| unreachable!("{error}"));
    store
        .connection
        .busy_timeout(Duration::from_secs(5))
        .unwrap_or_else(|error| unreachable!("{error}"));
    store
        .integrity_check()
        .unwrap_or_else(|error| unreachable!("{error}"));
}

#[test]
fn physical_page_reserve_prevents_nonterminal_stranding_and_preserves_abort() {
    let db = TestDatabase::new();
    let binding = binding_with_observation("physical-reserve");
    let (signer, mut store) = open_store(&db.path);
    let prepared = prepared_snapshot(
        store
            .prepare(&binding)
            .unwrap_or_else(|error| unreachable!("{error}")),
    );
    store
        .connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")
        .unwrap_or_else(|error| unreachable!("{error}"));
    let freelist = pragma_i64(&store.connection, "freelist_count").unwrap_or(-1);
    assert_eq!(freelist, 0);
    let page_count = pragma_i64(&store.connection, "page_count")
        .unwrap_or_else(|error| unreachable!("{error}"));
    store
        .connection
        .pragma_update(None, "max_page_count", page_count)
        .unwrap_or_else(|error| unreachable!("{error}"));

    let request = signer
        .authorize_handoff(&prepared, digest("physical-reserve-use"), 1, u64::MAX)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(matches!(
        store.handoff(&request),
        Err(TransactionStoreError::CapacityExceeded)
    ));
    assert_eq!(
        store
            .snapshot(&prepared.transaction_id)
            .unwrap_or_else(|error| unreachable!("{error}")),
        prepared
    );

    let aborted = store
        .abort_prepared(&linura_transaction::AbortRequest {
            transaction_id: prepared.transaction_id.clone(),
            expected_generation: prepared.current_generation,
            expected_state_version: prepared.state_version,
            reason_digest: digest("physical-capacity-abort"),
        })
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(aborted.state, TransactionState::Aborted);
}

#[test]
fn every_nonterminal_transaction_has_exactly_one_durable_reservation_after_commit() {
    let db = TestDatabase::new();
    let (_, mut store) = open_store(&db.path);
    let prepared = prepared_snapshot(
        store
            .prepare(&binding_with_observation("reservation-shape"))
            .unwrap_or_else(|error| unreachable!("{error}")),
    );
    let (count, length): (i64, i64) = store
        .connection
        .query_row(
            "SELECT COUNT(*), MIN(length(reserved)) FROM audit_reservations WHERE transaction_id=?1",
            params![prepared.transaction_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(count, 1);
    assert_eq!(
        u64::try_from(length).unwrap_or_default(),
        reservation_bytes(&store.connection).unwrap_or_default()
    );
}

#[test]
fn audit_text_is_length_preflighted_before_rust_materialization() {
    let db = TestDatabase::new();
    let (_, mut store) = open_store(&db.path);
    let prepared = prepared_snapshot(
        store
            .prepare(&binding_with_observation("audit-bound"))
            .unwrap_or_else(|error| unreachable!("{error}")),
    );
    let raw = Connection::open(&db.path).unwrap_or_else(|error| unreachable!("{error}"));
    raw.execute_batch("PRAGMA ignore_check_constraints=ON;")
        .unwrap_or_else(|error| unreachable!("{error}"));
    let zero = linura_transaction::ContentDigest::zero();
    raw.execute(
        "INSERT INTO audit_events (
            transaction_id,event_sequence,generation,state_version,event_kind,
            payload_digest,previous_digest,event_digest,integrity_tag
         ) VALUES (?1,1,0,2,?2,?3,?3,?3,zeroblob(32))",
        params![prepared.transaction_id.as_str(), "x".repeat(65), zero.as_str()],
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    drop(raw);
    assert!(matches!(
        store.snapshot(&prepared.transaction_id),
        Err(TransactionStoreError::Corruption(reason))
            if reason.contains("audit record exceeds persisted byte bounds")
    ));
}

#[test]
fn logical_audit_capacity_still_reserves_a_safe_exit() {
    let db = TestDatabase::new();
    let limits = StoreLimits {
        max_audit_events: 1,
        ..StoreLimits::default()
    };
    let (_, verifier) = authority();
    let mut store = SqliteTransactionStore::open_with_limits(
        &db.path,
        limits,
        verifier,
        integrity_key(),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(matches!(
        store.prepare(&binding_with_observation("logical-reserve")),
        Err(TransactionStoreError::CapacityExceeded)
    ));
}

#[test]
fn installed_schema_tampering_is_detected_on_reopen() {
    let db = TestDatabase::new();
    drop(open_store(&db.path).1);
    let raw = Connection::open(&db.path).unwrap_or_else(|error| unreachable!("{error}"));
    raw.execute_batch("DROP TRIGGER generations_binding_immutable;")
        .unwrap_or_else(|error| unreachable!("{error}"));
    drop(raw);
    assert!(matches!(
        SqliteTransactionStore::open(&db.path, authority().1, integrity_key()),
        Err(TransactionStoreError::UnsupportedSchema(_))
    ));
}

#[test]
fn invalid_integrity_key_material_is_rejected() {
    assert!(matches!(
        SqliteIntegrityKey::new(vec![0_u8; 32]),
        Err(TransactionStoreError::AuthorityRejected)
    ));
    assert!(matches!(
        SqliteIntegrityKey::new(vec![0x11; 31]),
        Err(TransactionStoreError::AuthorityRejected)
    ));
}

#[test]
fn schema_v1_migrates_forward_without_rewriting_its_ledger_entry() {
    let database = TestDatabase::new();
    let (_, verifier) = authority();
    let authority_fingerprint = verifier.fingerprint();
    let key = integrity_key();
    let integrity_fingerprint = key.fingerprint();
    let connection = Connection::open(&database.path)
        .unwrap_or_else(|error| unreachable!("{error}"));
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA recursive_triggers=ON; PRAGMA synchronous=FULL;",
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    connection
        .pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap_or_else(|error| unreachable!("{error}"));
    connection
        .execute_batch(MIGRATION_V1)
        .unwrap_or_else(|error| unreachable!("{error}"));
    connection
        .execute(
            "INSERT INTO authority_store_identity (
                singleton, verifier_fingerprint, integrity_fingerprint
             ) VALUES (1, ?1, ?2)",
            params![authority_fingerprint.as_str(), integrity_fingerprint.as_str()],
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let v1_checksum = digest_bytes("linura.sqlite.migration.v1", MIGRATION_V1.as_bytes());
    connection
        .execute(
            "INSERT INTO schema_migrations (migration_id, checksum) VALUES (?1, ?2)",
            params![MIGRATION_ID, v1_checksum.as_str()],
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    connection
        .pragma_update(None, "user_version", 1_i64)
        .unwrap_or_else(|error| unreachable!("{error}"));
    drop(connection);

    let store = SqliteTransactionStore::open(&database.path, verifier, key)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(
        store
            .settings()
            .unwrap_or_else(|error| unreachable!("{error}"))
            .user_version,
        SCHEMA_VERSION,
    );
    let (count, preserved_v1, v2_count): (i64, String, i64) = store
        .connection
        .query_row(
            "SELECT COUNT(*),
                    MAX(CASE WHEN migration_id=?1 THEN checksum ELSE '' END),
                    SUM(CASE WHEN migration_id=?2 THEN 1 ELSE 0 END)
             FROM schema_migrations",
            params![MIGRATION_ID, MIGRATION_V2_ID],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(count, 2);
    assert_eq!(preserved_v1, v1_checksum.as_str());
    assert_eq!(v2_count, 1);
    let trigger_sql: String = store
        .connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='audit_reservations_filesystem_release'",
            [],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(trigger_sql.contains("SELECT 1"));
    assert!(!trigger_sql.contains("linura_fs_release_slots"));
}

#[cfg(target_os = "linux")]
#[test]
fn terminal_recovery_with_limits_preserves_custom_capacity_contract() {
    let database = TestDatabase::new();
    let limits = StoreLimits {
        max_pages: StoreLimits::default().max_pages / 2,
        ..StoreLimits::default()
    };
    let prepared_binding =
        binding_with_request("request:custom-limit-terminal", "observation:custom-limit");
    let (_, verifier) = authority();
    let mut store = SqliteTransactionStore::open_with_limits(
        &database.path,
        limits,
        verifier,
        integrity_key(),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    let prepared = prepared_snapshot(
        store
            .prepare(&prepared_binding)
            .unwrap_or_else(|error| unreachable!("{error}")),
    );
    assert_eq!(
        store
            .settings()
            .unwrap_or_else(|error| unreachable!("{error}"))
            .max_page_count,
        i64::try_from(limits.max_pages).unwrap_or_else(|error| unreachable!("{error}")),
    );
    drop(store);

    let (_, verifier) = authority();
    let mut recovery = SqliteTransactionStore::open_for_terminal_recovery_with_limits(
        &database.path,
        limits,
        verifier,
        integrity_key(),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(
        recovery
            .settings()
            .unwrap_or_else(|error| unreachable!("{error}"))
            .max_page_count,
        i64::try_from(limits.max_pages).unwrap_or_else(|error| unreachable!("{error}")),
    );
    let aborted = recovery
        .abort_prepared(&linura_transaction::AbortRequest {
            transaction_id: prepared.transaction_id,
            expected_generation: prepared.current_generation,
            expected_state_version: prepared.state_version,
            reason_digest: digest("custom-limit-terminal-abort"),
        })
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(aborted.state, TransactionState::Aborted);
}

#[cfg(target_os = "linux")]
#[test]
fn terminal_recovery_open_blocks_nonterminal_mutation_and_restores_normal_mode() {
    let database = TestDatabase::new();
    let prepared_binding = binding_with_request("request:preopen-terminal", "observation:preopen");
    let (_, verifier) = authority();
    let mut store = SqliteTransactionStore::open(&database.path, verifier, integrity_key())
        .unwrap_or_else(|error| unreachable!("{error}"));
    let prepared = match store.prepare(&prepared_binding).unwrap_or_else(|error| unreachable!("{error}")) {
        linura_transaction::PrepareOutcome::Created(snapshot)
        | linura_transaction::PrepareOutcome::Existing(snapshot) => snapshot,
    };
    drop(store);
    let (_, verifier) = authority();
    let mut recovery = SqliteTransactionStore::open_for_terminal_recovery(
        &database.path, verifier, integrity_key(),
    ).unwrap_or_else(|error| unreachable!("{error}"));
    let unrelated = binding_with_request("request:preopen-denied", "observation:preopen-denied");
    assert!(matches!(recovery.prepare(&unrelated), Err(TransactionStoreError::StateConflict)));
    let aborted = recovery.abort_prepared(&linura_transaction::AbortRequest {
        transaction_id: prepared.transaction_id,
        expected_generation: prepared.current_generation,
        expected_state_version: prepared.state_version,
        reason_digest: digest("preopen-terminal-abort"),
    }).unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(aborted.state, TransactionState::Aborted);
    recovery.integrity_check().unwrap_or_else(|error| unreachable!("{error}"));
    let outcome = recovery.prepare(&unrelated).unwrap_or_else(|error| unreachable!("{error}"));
    assert!(matches!(outcome, linura_transaction::PrepareOutcome::Created(_)));
}


#[cfg(target_os = "linux")]
#[test]
fn terminal_recovery_defers_final_reserve_shrink_until_sqlite_commit() {
    let database = TestDatabase::new();
    let binding = binding_with_request(
        "request:terminal-reserve-rollback",
        "observation:terminal-reserve-rollback",
    );
    let (_, verifier) = authority();
    let mut store = SqliteTransactionStore::open(&database.path, verifier, integrity_key())
        .unwrap_or_else(|error| unreachable!("{error}"));
    let prepared = prepared_snapshot(
        store
            .prepare(&binding)
            .unwrap_or_else(|error| unreachable!("{error}")),
    );
    drop(store);

    let reserve_path = filesystem_reserve::reserve_path_for_database(&database.path);
    let original_len = fs::metadata(&reserve_path)
        .unwrap_or_else(|error| unreachable!("{error}"))
        .len();
    assert!(original_len >= 2 * 1024 * 1024);

    let (_, verifier) = authority();
    let mut recovery = SqliteTransactionStore::open_for_terminal_recovery(
        &database.path,
        verifier,
        integrity_key(),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(
        fs::metadata(&reserve_path)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .len(),
        original_len,
    );

    // Exercise the exact pre-commit failure window. The DELETE trigger must
    // not shorten or reallocate the sidecar while SQLite can still roll the row
    // back, including while the opener slot is deliberately sparse.
    {
        let transaction = recovery
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap_or_else(|error| unreachable!("{error}"));
        let deleted = transaction
            .execute(
                "DELETE FROM audit_reservations WHERE transaction_id=?1",
                params![prepared.transaction_id.as_str()],
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(deleted, 1);
        assert_eq!(
            fs::metadata(&reserve_path)
                .unwrap_or_else(|error| unreachable!("{error}"))
                .len(),
            original_len,
        );
        transaction
            .rollback()
            .unwrap_or_else(|error| unreachable!("{error}"));
    }
    assert_eq!(
        fs::metadata(&reserve_path)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .len(),
        original_len,
    );
    drop(recovery);

    // A process death at the rollback point leaves the same persistent shape.
    // A fresh terminal opener must remain usable at true ENOSPC.
    let (_, verifier) = authority();
    let mut reopened = SqliteTransactionStore::open_for_terminal_recovery(
        &database.path,
        verifier,
        integrity_key(),
    )
    .unwrap_or_else(|error| unreachable!("{error}"));
    let aborted = reopened
        .abort_prepared(&linura_transaction::AbortRequest {
            transaction_id: prepared.transaction_id,
            expected_generation: prepared.current_generation,
            expected_state_version: prepared.state_version,
            reason_digest: digest("terminal-reserve-rollback-abort"),
        })
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(aborted.state, TransactionState::Aborted);
    assert_eq!(
        fs::metadata(&reserve_path)
            .unwrap_or_else(|error| unreachable!("{error}"))
            .len(),
        0,
    );
}
