//! Parser/correlation fixtures only; no durable or native qualification.
use super::*;
use crate::display_restoration_link::RestorationLink;
use linura_transaction::{
    ApprovedRequestJournal, RetainedRequest, TransactionId, TransactionStoreError,
};

#[derive(Debug, Default)]
struct Journal(Option<RetainedRequest>);
impl ApprovedRequestJournal for Journal {
    fn retain(&mut self, record: &RetainedRequest) -> Result<(), TransactionStoreError> {
        if self.0.as_ref().is_some_and(|existing| existing != record) {
            return Err(TransactionStoreError::IdempotencyConflict);
        }
        self.0 = Some(record.clone());
        Ok(())
    }
    fn load(
        &self,
        _: &PrincipalId,
        _: &RequestId,
    ) -> Result<RetainedRequest, TransactionStoreError> {
        // Deliberately return a record even for the wrong address. The consumer
        // must independently reject principal/key substitution.
        self.0.clone().ok_or(TransactionStoreError::NotFound)
    }
    fn integrity_check(&self) -> Result<(), TransactionStoreError> {
        Ok(())
    }
}
fn fixture() -> (Fixture, PlanDesiredStateRequest, RestorationLink, Journal) {
    let fixture = Fixture::new();
    let request = fixture.request();
    let principal = value(PrincipalId::new(fixture.source.principal.as_str()));
    let snapshot = |request: &PlanDesiredStateRequest, state, version| TransactionSnapshot {
        transaction_id: TransactionId::for_namespace(&principal, &request.request_id),
        principal: principal.clone(),
        request_id: request.request_id.clone(),
        current_generation: 0,
        state_version: version,
        state,
        binding_digest: linura_transaction::digest_bytes(
            "fixture:binding",
            request.request_id.as_str().as_bytes(),
        ),
    };
    let link = value(RestorationLink::capture(
        &fixture.source.principal,
        &fixture.source.original_request,
        &request,
        snapshot(
            &fixture.source.original_request,
            TransactionState::Indeterminate,
            2,
        ),
        snapshot(&request, TransactionState::Committed, 4),
        "8".repeat(64),
        linura_transaction::digest_bytes("fixture:proof", b"five fresh sources"),
        value(now_ms()),
    ));
    let mut journal = Journal::default();
    value(link.append(&mut journal));
    (fixture, request, link, journal)
}
#[test]
fn link_is_exact_write_once_historical_data_with_a_single_retirement_version() {
    let (fixture, request, link, mut journal) = fixture();
    let load = |journal: &Journal| {
        value(RestorationLink::load(
            journal,
            &fixture.source.principal,
            &fixture.source.original_request,
            &request,
            link.restoration(),
            &"8".repeat(64),
            value(now_ms()),
        ))
    };
    assert_eq!(load(&journal).as_ref(), Some(&link));
    value(link.append(&mut journal));
    assert_eq!(load(&journal).as_ref(), Some(&link));
    let retired = value(link.retired_original());
    assert_eq!(retired.state, TransactionState::RecoveryBlocked);
    assert_eq!(retired.state_version, link.original().state_version + 1);
    assert_eq!(retired.binding_digest, link.original().binding_digest);
    assert_eq!(
        retired.current_generation,
        link.original().current_generation
    );
    assert_eq!(retired.transaction_id, link.original().transaction_id);
    value(link.require_retired(&retired, link.restoration()));
    assert!(
        link.require_retired(link.original(), link.restoration())
            .is_err()
    );
    for original in [true, false] {
        for field in 0..7 {
            let mut old = retired.clone();
            let mut restored = link.restoration().clone();
            let changed = if original { &mut old } else { &mut restored };
            match field {
                0 => changed.current_generation += 1,
                1 => changed.state_version += 1,
                2 => {
                    changed.binding_digest =
                        linura_transaction::digest_bytes("fixture:other", b"binding")
                }
                3 => changed.state = TransactionState::Verified,
                4 => changed.principal = value(PrincipalId::new("unix:uid:1001")),
                5 => changed.request_id = value(RequestId::new("request:other")),
                _ => {
                    changed.transaction_id = TransactionId::for_namespace(
                        &changed.principal,
                        &value(RequestId::new("request:other")),
                    )
                }
            }
            assert!(
                link.require_retired(&old, &restored).is_err(),
                "original={original} field={field}"
            );
        }
    }
}

#[test]
fn link_refuses_truncation_trailing_oversized_or_substituted_history() {
    let (fixture, request, link, journal) = fixture();
    let original_record = journal.0.as_ref().unwrap_or_else(|| unreachable!("record"));
    let bytes = original_record.canonical();
    for size in 1..bytes.len() {
        let bad = Journal(Some(value(RetainedRequest::new(
            original_record.principal().clone(),
            original_record.request_id().clone(),
            bytes[..size].to_vec(),
        ))));
        assert!(
            RestorationLink::load(
                &bad,
                &fixture.source.principal,
                &fixture.source.original_request,
                &request,
                link.restoration(),
                &"8".repeat(64),
                value(now_ms())
            )
            .is_err()
        );
    }
    for case in 0..9 {
        let mut bytes = bytes.to_vec();
        let mut owner = original_record.principal().clone();
        let mut key = original_record.request_id().clone();
        let mut committed = link.restoration().clone();
        let mut dispatch = "8".repeat(64);
        let mut now = value(now_ms());
        let mut expected_request = request.clone();
        match case {
            0 => bytes.push(0),
            1 => bytes = vec![b'x'; 4097],
            2 => bytes[8] = b'x',
            3 => owner = value(PrincipalId::new("unix:uid:1001")),
            4 => key = value(RequestId::new("request:foreign-link")),
            5 => committed.state_version += 1,
            6 => {
                dispatch = "9".repeat(64);
            }
            7 => {
                now = 1;
            }
            _ => expected_request.reason.summary.push_str(" changed"),
        }
        let bad = Journal(Some(value(RetainedRequest::new(owner, key, bytes))));
        assert!(
            RestorationLink::load(
                &bad,
                &fixture.source.principal,
                &fixture.source.original_request,
                &expected_request,
                &committed,
                &dispatch,
                now
            )
            .is_err(),
            "case {case}"
        );
    }
}
