//! Real SQLite/WAL bookkeeping fixtures, not native display qualification.
use super::*;
use linura_transaction::{RecoveryOutcome, TransactionSnapshot};

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}
fn at() -> u64 {
    value(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)).as_millis() as u64
}
fn verified(
    store: &mut SqliteTransactionStore,
    signer: &TransactionAuthoritySigner,
) -> TransactionSnapshot {
    let binding = binding_with_observation("verified-before-compositor-loss");
    let prepared = prepared_snapshot(value(store.prepare(&binding)));
    assert_eq!(
        store.committed_state_material(&prepared.transaction_id),
        Err(TransactionStoreError::StateConflict)
    );
    value(store.handoff(&value(signer.authorize_handoff(
        &prepared,
        digest("use"),
        1,
        u64::MAX,
    ))));
    let dispatched = value(store.snapshot(&prepared.transaction_id));
    assert_eq!(
        store.committed_state_material(&prepared.transaction_id),
        Err(TransactionStoreError::StateConflict)
    );
    let request = value(signer.authorize_recovery(
        &dispatched,
        RecoveryResolution::IntendedStateVerified {
            observation_digest: digest("old verified observation"),
            desired_state_digest: digest("desired"),
            graph_digest: digest("graph"),
            provenance_digest: digest("provenance"),
        },
        1,
        u64::MAX,
    ));
    let RecoveryOutcome::Verified(snapshot) = value(store.recover(&request)) else {
        unreachable!("expected verified")
    };
    assert_eq!(
        store.committed_state_material(&snapshot.transaction_id),
        Err(TransactionStoreError::StateConflict)
    );
    snapshot
}

#[test]
fn committed_adoption_material_survives_restart_without_reopening_verified_authority() {
    for field in [
        None,
        Some("desired_state_digest"),
        Some("graph_digest"),
        Some("provenance_digest"),
    ] {
        let db = TestDatabase::new();
        let (signer, mut store) = open_store(&db.path);
        let verified = verified(&mut store, &signer);
        let material = value(store.verified_commit_material(&verified.transaction_id));
        let committed = value(store.commit(&value(signer.authorize_commit(
            &verified,
            material.desired_state_digest.clone(),
            material.graph_digest.clone(),
            material.provenance_digest.clone(),
        ))));
        assert!(
            store
                .verified_commit_material(&verified.transaction_id)
                .is_err()
        );
        let adopted = value(store.committed_state_material(&committed.transaction_id));
        assert_eq!(adopted.snapshot, committed);
        assert_eq!(adopted.desired_state_digest, material.desired_state_digest);
        assert_eq!(adopted.graph_digest, material.graph_digest);
        assert_eq!(adopted.provenance_digest, material.provenance_digest);
        drop(store);
        let (_, reopened) = open_store(&db.path);
        assert_eq!(
            value(reopened.committed_state_material(&committed.transaction_id)),
            adopted
        );
        assert!(
            reopened
                .verified_commit_material(&committed.transaction_id)
                .is_err()
        );
        if let Some(field) = field {
            let raw = value(Connection::open(&db.path));
            value(raw.create_scalar_function(
                "linura_internal_mutation_gate",
                0,
                FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_INNOCUOUS,
                |_| Ok(1_i64),
            ));
            // A caller-selected SQL gate cannot manufacture authenticated lineage.
            assert!(
                raw.execute(
                    &format!("UPDATE generations SET {field}=?1 WHERE transaction_id=?2"),
                    params![
                        digest("substituted committed lineage").as_str(),
                        committed.transaction_id.as_str()
                    ],
                )
                .is_err(),
                "committed lineage remains immutable despite a spoofed SQL gate"
            );
            assert_eq!(
                value(reopened.committed_state_material(&committed.transaction_id)),
                adopted
            );
            // Direct corruption after a successful read is independently
            // rejected; a previous authenticated read must never be cached.
            value(raw.execute(
                "UPDATE generations SET integrity_tag=zeroblob(32) WHERE transaction_id=?1",
                params![committed.transaction_id.as_str()],
            ));
            assert!(
                reopened
                    .committed_state_material(&committed.transaction_id)
                    .is_err()
            );
            assert!(reopened.integrity_check().is_err());
        }
    }
}

#[test]
fn compensation_retires_verified_without_committing_or_losing_provenance() {
    let db = TestDatabase::new();
    let (signer, mut store) = open_store(&db.path);
    let verified = verified(&mut store, &signer);
    let old = value(store.verified_commit_material(&verified.transaction_id));
    let old_commit = value(signer.authorize_commit(
        &verified,
        old.desired_state_digest,
        old.graph_digest,
        old.provenance_digest,
    ));
    let now = at();
    let retirement = value(signer.authorize_verified_compensation(
        &verified,
        digest("fresh actual restored proof"),
        digest("immutable linked result"),
        now,
        now + 2000,
    ));
    let RecoveryOutcome::Blocked(blocked) = value(store.recover(&retirement)) else {
        unreachable!("compensation is terminal blocked")
    };
    assert_eq!(blocked.state, TransactionState::RecoveryBlocked);
    assert_eq!(blocked.state_version, verified.state_version + 1);
    assert_eq!(blocked.current_generation, verified.current_generation);
    assert_eq!(
        store.commit(&old_commit),
        Err(TransactionStoreError::StateConflict)
    );
    assert_eq!(
        store.recover(&retirement),
        Err(TransactionStoreError::StateConflict)
    );
    assert!(
        store
            .verified_commit_material(&verified.transaction_id)
            .is_err()
    );
    value(store.integrity_check());
    drop(store);
    let (_, reopened) = open_store(&db.path);
    assert_eq!(value(reopened.snapshot(&verified.transaction_id)), blocked);
    value(reopened.integrity_check());
    let row = value(reopened.connection.query_row(
        "SELECT desired_state_digest, graph_digest, provenance_digest FROM generations WHERE transaction_id = ?1",
        params![verified.transaction_id.as_str()], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))));
    assert_eq!(
        row,
        (
            digest("desired").as_str().to_owned(),
            digest("graph").as_str().to_owned(),
            digest("provenance").as_str().to_owned()
        )
    );
}

#[test]
fn compensation_cannot_use_old_verified_state_after_a_commit_or_a_changed_version() {
    for case in 0..6 {
        let db = TestDatabase::new();
        let (signer, mut store) = open_store(&db.path);
        let verified = verified(&mut store, &signer);
        let mut stale = verified.clone();
        if case == 0 {
            let material = value(store.verified_commit_material(&verified.transaction_id));
            value(store.commit(&value(signer.authorize_commit(
                &verified,
                material.desired_state_digest,
                material.graph_digest,
                material.provenance_digest,
            ))));
        } else if case == 1 {
            stale.state_version += 1;
        } else if case == 2 {
            stale.current_generation += 1;
        } else if case == 3 {
            stale.binding_digest = digest("foreign binding");
        }
        let before = value(store.snapshot(&verified.transaction_id));
        let now = if case == 4 { at() - 3000 } else { at() };
        let (other_signer, _) = value(TransactionAuthorityKey::new(fixture_key(3))).split();
        let signing = if case == 5 { &other_signer } else { &signer };
        let request = value(signing.authorize_verified_compensation(
            &stale,
            digest("proof"),
            digest("link"),
            now,
            now + 2000,
        ));
        assert_eq!(
            store.recover(&request),
            Err(if case >= 4 {
                TransactionStoreError::AuthorityRejected
            } else {
                TransactionStoreError::StateConflict
            })
        );
        assert_eq!(value(store.snapshot(&verified.transaction_id)), before);
        value(store.integrity_check());
    }
}
