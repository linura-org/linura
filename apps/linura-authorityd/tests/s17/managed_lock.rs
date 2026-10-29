//! Deterministic lifecycle/denial fixtures only, not native authentication,
//! compositor, suspend, visual, or production qualification evidence.

use super::*;
use linura_control::{ManagedApprovalAuthorizer, ManagedApprovalChallenge};
use linura_core::{BootId, SecurityOwnerInvocationId, SessionEpoch, SessionLockId};

pub(super) fn lock_id() -> SessionLockId {
    value(SessionLockId::new(
        value(SessionEpoch::new(
            value(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
            1000,
            "c2",
            42,
        )),
        value(SecurityOwnerInvocationId::new(
            "98765432-1234-4567-89ab-0123456789ab",
        )),
        7,
    ))
}

pub(super) fn lock_observation(secure: bool, sequence: u64) -> ObservationEnvelope {
    let lock = lock_id();
    let epoch = lock.epoch();
    ObservationEnvelope {
        provider: value(ProviderId::new("session-locker")),
        resource: value(lock.resource_id()),
        capability: value(CapabilityId::new("session.secure-lock.observe")),
        // NativeApi is deliberately simulated to exercise Control's predicates.
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms: now_unix_ms(),
        valid_for_ms: 2000,
        sequence,
        attributes: BTreeMap::from([
            ("secure".into(), ObservedValue::Bool(secure)),
            (
                "boot_id".into(),
                ObservedValue::Text(epoch.boot().as_str().into()),
            ),
            (
                "session_id".into(),
                ObservedValue::Text(epoch.session_id().into()),
            ),
            ("uid".into(), ObservedValue::U64(u64::from(epoch.uid()))),
            (
                "created_monotonic_us".into(),
                ObservedValue::U64(epoch.created_monotonic_us()),
            ),
            (
                "lock_generation".into(),
                ObservedValue::U64(lock.generation()),
            ),
            (
                "security_owner_invocation".into(),
                ObservedValue::Text(lock.security_owner_invocation().as_str().into()),
            ),
            (
                "lock_protocol".into(),
                ObservedValue::Text("ext-session-lock-v1".into()),
            ),
        ]),
    }
}

pub(super) fn session_observation(sequence: u64) -> ObservationEnvelope {
    let lock = lock_id();
    let epoch = lock.epoch();
    let mut observation = lock_observation(false, sequence);
    observation.provider = value(ProviderId::new("logind"));
    observation.resource = value(epoch.resource_id());
    observation.capability = value(CapabilityId::new("session.epoch.observe"));
    observation.attributes.extend([
        ("session_type".into(), ObservedValue::Text("wayland".into())),
        ("session_class".into(), ObservedValue::Text("user".into())),
        ("state".into(), ObservedValue::Text("active".into())),
        ("active".into(), ObservedValue::Bool(true)),
        ("remote".into(), ObservedValue::Bool(false)),
        ("seat".into(), ObservedValue::Text("seat0".into())),
        ("leader_present".into(), ObservedValue::Bool(true)),
    ]);
    observation
}

fn lock_preview_control(
    locks: Vec<ObservationEnvelope>,
    sessions: Vec<ObservationEnvelope>,
) -> PlanPreviewControl {
    let mut coordinator = ObservationCoordinator::new();
    value(
        coordinator.register_observer(Box::new(QueueObserver::for_route(
            locks,
            value(ProviderId::new("session-locker")),
            value(CapabilityId::new("session.secure-lock.observe")),
            value(lock_id().resource_id()),
        ))),
    );
    value(
        coordinator.register_observer(Box::new(QueueObserver::for_route(
            sessions,
            value(ProviderId::new("logind")),
            value(CapabilityId::new("session.epoch.observe")),
            value(lock_id().epoch().resource_id()),
        ))),
    );
    PlanPreviewControl::new(coordinator)
}

fn open_lock_control(
    database: &Path,
    locks: Vec<ObservationEnvelope>,
    sessions: Vec<ObservationEnvelope>,
) -> ManagedLifecycleControl<SqliteTransactionStore> {
    // Preserve supplied timestamps for stale/future/expiry negative fixtures.
    open_lock_control_after_storage_ready(database, || (locks, sessions))
}

fn open_lock_control_after_storage_ready(
    database: &Path,
    observations: impl FnOnce() -> (Vec<ObservationEnvelope>, Vec<ObservationEnvelope>),
) -> ManagedLifecycleControl<SqliteTransactionStore> {
    let (signer, verifier) = authority_material();
    let store = value(SqliteTransactionStore::open(
        database,
        verifier,
        value(SqliteIntegrityKey::new(fixture_key(5))),
    ));
    let journal = value(
        linura_persistence_sqlite::SqliteApprovedRequestJournal::open(
            database.with_extension("requests.sqlite3"),
            value(SqliteIntegrityKey::new(fixture_key(6))),
        ),
    );
    // Positive handoff fixtures sample AFTER unrelated database initialization,
    // as real observers do. Never extend validity or restamp captured evidence.
    let (locks, sessions) = observations();
    let control = value(ManagedLifecycleControl::new(
        lock_preview_control(locks, sessions),
        store,
        signer,
    ));
    value(control.with_request_journal(Box::new(journal)))
}

#[test]
fn public_preview_includes_the_same_native_session_prerequisite_as_managed_prepare() {
    let mut control = lock_preview_control(
        vec![lock_observation(true, 1)],
        vec![session_observation(1)],
    );
    let preview = value(control.plan_desired_state(
        principal(),
        actor(true),
        lock_request("preview-unlock", false),
    ));
    assert!(!preview.execution_authorized);
    assert!(preview.findings.iter().any(|finding| {
        finding.code == "native-session-lock-precondition"
            && finding.message.contains("seat=seat0")
            && finding.message.contains("owner=1000")
    }));
}

#[test]
fn public_preview_rejects_native_session_denial_and_does_not_retain_a_review() {
    let mut inactive_session = session_observation(1);
    inactive_session
        .attributes
        .insert("active".into(), ObservedValue::Bool(false));
    let mut control = lock_preview_control(vec![lock_observation(true, 1)], vec![inactive_session]);
    let request = lock_request("preview-inactive", false);
    let plan_id = value(linura_core::PlanId::new(request.request_id.as_str()));
    assert!(
        control
            .plan_desired_state(principal(), actor(true), request)
            .is_err()
    );
    assert!(control.get_plan_preview(&principal(), &plan_id).is_err());
}

fn lock_request(operation: &str, secure: bool) -> PlanDesiredStateRequest {
    let mut request = request(operation, "inactive");
    request.provider = value(ProviderId::new("session-locker"));
    request.resource = value(lock_id().resource_id());
    request.observation_capability = value(CapabilityId::new("session.secure-lock.observe"));
    request.desired_state = BTreeMap::from([("secure".into(), secure.to_string())]);
    request.reason.intent_ids = vec![value(IntentId::new("intent:v010:s17:session-lock"))];
    request.request_id = value(managed_request_id(operation, &request));
    request
}

#[derive(Debug)]
struct DeniedAuthentication;
impl ManagedApprovalAuthorizer for DeniedAuthentication {
    fn authorize(
        &self,
        _challenge: &ManagedApprovalChallenge,
    ) -> Result<TrustedHumanApproval, String> {
        Err("native owner authentication denied".into())
    }
}

#[test]
fn native_seat_drift_during_authentication_requires_new_review_before_dispatch() {
    let database = TestDatabase::new();
    let mut changed_session = session_observation(2);
    changed_session
        .attributes
        .insert("seat".into(), ObservedValue::Text("seat1".into()));
    let mut control = open_lock_control(
        database.path(),
        vec![lock_observation(true, 1), lock_observation(true, 2)],
        vec![session_observation(1), changed_session],
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    let mut verifier = ScriptedVerifier::new([]);
    assert!(matches!(
        control.converge_session_lock(
            principal(),
            actor(true),
            lock_request("seat-drift", false),
            &approval(),
            &mut executor,
            &mut verifier
        ),
        Err(ManagedLifecycleError::ApprovalBoundary(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn independent_verifier_success_cannot_commit_when_native_owner_session_is_gone_or_unsupported() {
    let database = TestDatabase::new();
    let mut closing_session = session_observation(3);
    closing_session
        .attributes
        .insert("active".into(), ObservedValue::Bool(false));
    let mut control = open_lock_control(
        database.path(),
        vec![
            lock_observation(true, 1),
            lock_observation(true, 2),
            lock_observation(false, 3),
        ],
        vec![
            session_observation(1),
            session_observation(2),
            closing_session,
        ],
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    let mut verifier =
        ScriptedVerifier::new([VerifierStep::Outcome(VerificationDisposition::Satisfied)]);
    assert!(
        control
            .converge_session_lock(
                principal(),
                actor(true),
                lock_request("owner-disappeared", false),
                &approval(),
                &mut executor,
                &mut verifier
            )
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn owner_unlock_runs_all_stages_and_exact_retry_never_redispatches() {
    let database = TestDatabase::new();
    let mut control = open_lock_control(
        database.path(),
        [true, true, false, false, false]
            .into_iter()
            .enumerate()
            .map(|(index, state)| lock_observation(state, index as u64 + 1))
            .collect(),
        (1..=5).map(session_observation).collect(),
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    let mut verifier = ScriptedVerifier::new(
        (0..4).map(|_| VerifierStep::Outcome(VerificationDisposition::Satisfied)),
    );
    let request = lock_request("unlock-once", false);
    let first = value(control.converge_session_lock(
        principal(),
        actor(true),
        request.clone(),
        &approval(),
        &mut executor,
        &mut verifier,
    ));
    assert_complete(&first);
    assert_eq!(first.change_key, "secure");
    assert_eq!(first.desired_value, "false");
    let retry = value(control.converge_session_lock(
        principal(),
        actor(true),
        request,
        &approval(),
        &mut executor,
        &mut verifier,
    ));
    assert_complete(&retry);
    assert!(retry.recovered);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn historical_committed_status_survives_restart_without_claiming_current_native_coverage() {
    let database = TestDatabase::new();
    let request = lock_request("historical-unlock", false);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    let mut verifier = ScriptedVerifier::new(
        (0..2).map(|_| VerifierStep::Outcome(VerificationDisposition::Satisfied)),
    );
    let mut control = open_lock_control(
        database.path(),
        [true, true, false, false]
            .into_iter()
            .enumerate()
            .map(|(index, secure)| lock_observation(secure, index as u64 + 1))
            .collect(),
        (1..=4).map(session_observation).collect(),
    );
    let receipt = value(control.converge_session_lock(
        principal(),
        actor(true),
        request.clone(),
        &approval(),
        &mut executor,
        &mut verifier,
    ));
    assert_complete(&receipt);
    drop(control);
    // No native facts at all: this must not manufacture a fresh verification
    // receipt, consume an approval, or dispatch after generation/owner changes.
    let control = open_lock_control(database.path(), vec![], vec![]);
    let status = value(control.session_lock_request_status(&principal(), &request.request_id));
    assert_eq!(status.state, "committed");
    assert_eq!(status.transaction_id, receipt.transaction_id);
    assert_eq!(status.lock, lock_id());
    assert!(!status.secure);
    assert!(
        control
            .session_lock_request_status(
                &value(AuthenticatedPrincipal::new("unix:uid:1001")),
                &request.request_id
            )
            .is_err()
    );
    assert!(
        control
            .session_lock_request_status(
                &principal(),
                &value(RequestId::new("request:v010:session-lock:absent"))
            )
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn failed_owner_authentication_and_cross_user_request_never_dispatch() {
    let database = TestDatabase::new();
    let mut control = open_lock_control(
        database.path(),
        vec![lock_observation(true, 1)],
        vec![session_observation(1)],
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    let mut verifier = ScriptedVerifier::new([]);
    let request = lock_request("denied-unlock", false);
    assert!(
        control
            .converge_session_lock(
                value(AuthenticatedPrincipal::new("unix:uid:0")),
                actor(true),
                request.clone(),
                &approval(),
                &mut executor,
                &mut verifier
            )
            .is_err()
    );
    assert!(
        control
            .converge_session_lock(
                principal(),
                actor(true),
                request,
                &DeniedAuthentication,
                &mut executor,
                &mut verifier
            )
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn hints_wrong_generation_or_synthetic_coverage_never_authorize_unlock() {
    for mode in 0..4 {
        let database = TestDatabase::new();
        let mut lock = lock_observation(true, 1);
        match mode {
            0 => {
                lock.authority = ObservationAuthority::SyntheticTest;
            }
            1 => {
                lock.attributes
                    .insert("lock_generation".into(), ObservedValue::U64(8));
            }
            2 => {
                lock.attributes
                    .insert("secure".into(), ObservedValue::Text("true".into()));
            }
            _ => {
                lock.attributes.remove("lock_protocol");
            }
        }
        let mut control =
            open_lock_control(database.path(), vec![lock], vec![session_observation(1)]);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut executor =
            ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
        let mut verifier = ScriptedVerifier::new([]);
        assert!(
            control
                .converge_session_lock(
                    principal(),
                    actor(true),
                    lock_request("fake-coverage", false),
                    &approval(),
                    &mut executor,
                    &mut verifier
                )
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn crash_after_dispatch_stays_durable_and_recovery_does_not_guess_or_replay() {
    let database = TestDatabase::new();
    let request = lock_request("ambiguous-unlock", false);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::failure(calls.clone());
    let mut verifier = ScriptedVerifier::new([]);
    {
        let mut control = open_lock_control_after_storage_ready(database.path(), || {
            (
                vec![lock_observation(true, 1), lock_observation(true, 2)],
                vec![session_observation(1), session_observation(2)],
            )
        });
        assert!(matches!(
            control.converge_session_lock(
                principal(),
                actor(true),
                request.clone(),
                &approval(),
                &mut executor,
                &mut verifier
            ),
            Err(ManagedLifecycleError::Executor(_))
        ));
    }
    let mut control = open_lock_control(database.path(), vec![], vec![]);
    // The approved structured request survives process loss. Retrieving it is
    // historical evidence only: no observer, verifier or executor is invoked.
    assert_eq!(
        value(control.retained_session_request(&principal(), &request.request_id)),
        request
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        control
            .retained_session_request(
                &value(AuthenticatedPrincipal::new("unix:uid:1001")),
                &request.request_id,
            )
            .is_err()
    );
    assert!(matches!(
        control.converge_session_lock(
            principal(),
            actor(true),
            request,
            &approval(),
            &mut executor,
            &mut verifier
        ),
        Err(ManagedLifecycleError::Indeterminate(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[derive(Debug)]
struct FailingRetention;

impl linura_transaction::ApprovedRequestJournal for FailingRetention {
    fn retain(
        &mut self,
        _request: &linura_transaction::RetainedRequest,
    ) -> Result<(), linura_transaction::TransactionStoreError> {
        Err(linura_transaction::TransactionStoreError::Storage(
            "injected journal write failure".into(),
        ))
    }
    fn load(
        &self,
        _principal: &PrincipalId,
        _request: &RequestId,
    ) -> Result<linura_transaction::RetainedRequest, linura_transaction::TransactionStoreError>
    {
        Err(linura_transaction::TransactionStoreError::NotFound)
    }
    fn integrity_check(&self) -> Result<(), linura_transaction::TransactionStoreError> {
        Ok(())
    }
}

#[test]
fn failed_retention_prevents_prepare_and_dispatch_after_authentication() {
    let database = TestDatabase::new();
    let mut control = value(
        open_lock_control(
            database.path(),
            vec![lock_observation(true, 1), lock_observation(true, 2)],
            vec![session_observation(1), session_observation(2)],
        )
        .with_request_journal(Box::new(FailingRetention)),
    );
    let request = lock_request("journal-write-failed", false);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::failure(calls.clone());
    let mut verifier = ScriptedVerifier::new([]);
    let error = control
        .converge_session_lock(
            principal(),
            actor(true),
            request,
            &approval(),
            &mut executor,
            &mut verifier,
        )
        .error_or_unreachable();
    assert!(matches!(error, ManagedLifecycleError::Authority(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(control);
    let (_, authority_verifier) = authority_material();
    let store = value(SqliteTransactionStore::open(
        database.path(),
        authority_verifier,
        value(SqliteIntegrityKey::new(fixture_key(5))),
    ));
    use linura_transaction::TransactionStore;
    assert!(value(store.list_state(linura_transaction::TransactionState::Prepared)).is_empty());
    assert!(
        value(store.list_state(linura_transaction::TransactionState::Indeterminate)).is_empty()
    );
}

#[test]
fn unconfigured_retention_cannot_be_skipped_by_an_authenticated_session_owner() {
    let database = TestDatabase::new();
    let (signer, authority_verifier) = authority_material();
    let store = value(SqliteTransactionStore::open(
        database.path(),
        authority_verifier,
        value(SqliteIntegrityKey::new(fixture_key(5))),
    ));
    let mut control = value(ManagedLifecycleControl::new(
        lock_preview_control(vec![], vec![]),
        store,
        signer,
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::failure(calls.clone());
    let mut verifier = ScriptedVerifier::new([]);
    let error = control
        .converge_session_lock(
            principal(),
            actor(true),
            lock_request("missing-journal", false),
            &approval(),
            &mut executor,
            &mut verifier,
        )
        .error_or_unreachable();
    assert!(matches!(error, ManagedLifecycleError::Authority(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn orphan_retained_material_is_not_durable_authority_or_replay_permission() {
    use linura_transaction::ApprovedRequestJournal;
    let database = TestDatabase::new();
    let request = lock_request("orphan", false);
    let mut journal = value(
        linura_persistence_sqlite::SqliteApprovedRequestJournal::open(
            database.path().with_extension("requests.sqlite3"),
            value(SqliteIntegrityKey::new(fixture_key(6))),
        ),
    );
    // An opaque record with no corresponding transaction cannot be recovered,
    // even when persistence integrity authenticates it successfully.
    value(
        journal.retain(&value(linura_transaction::RetainedRequest::new(
            value(PrincipalId::new(principal().as_str())),
            request.request_id.clone(),
            b"not an authority credential".to_vec(),
        ))),
    );
    drop(journal);
    let control = open_lock_control(database.path(), vec![], vec![]);
    assert!(
        control
            .retained_session_request(&principal(), &request.request_id)
            .is_err()
    );
}

#[test]
fn deleted_journal_material_cannot_be_reconstructed_from_a_transaction_digest() {
    let database = TestDatabase::new();
    let request = lock_request("lost-journal", false);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::failure(calls.clone());
    let mut verifier = ScriptedVerifier::new([]);
    {
        let mut control = open_lock_control(
            database.path(),
            vec![lock_observation(true, 1), lock_observation(true, 2)],
            vec![session_observation(1), session_observation(2)],
        );
        assert!(
            control
                .converge_session_lock(
                    principal(),
                    actor(true),
                    request.clone(),
                    &approval(),
                    &mut executor,
                    &mut verifier
                )
                .is_err()
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Simulate losing only this test's inactive journal, not the transaction.
    value(std::fs::remove_file(
        database.path().with_extension("requests.sqlite3"),
    ));
    let mut control = open_lock_control(database.path(), vec![], vec![]);
    assert!(
        control
            .retained_session_request(&principal(), &request.request_id)
            .is_err()
    );
    assert!(matches!(
        control.converge_session_lock(
            principal(),
            actor(true),
            request,
            &approval(),
            &mut executor,
            &mut verifier
        ),
        Err(ManagedLifecycleError::Authority(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

fn leave_dispatched_lock_ambiguous(
    database: &TestDatabase,
    request: &PlanDesiredStateRequest,
    calls: &Arc<AtomicUsize>,
) {
    let mut control = open_lock_control_after_storage_ready(database.path(), || {
        (
            vec![lock_observation(true, 1), lock_observation(true, 2)],
            vec![session_observation(1), session_observation(2)],
        )
    });
    let mut executor = ScriptedExecutor::failure(calls.clone());
    let mut verifier = ScriptedVerifier::new([]);
    let result = control.converge_session_lock(
        principal(),
        actor(true),
        request.clone(),
        &approval(),
        &mut executor,
        &mut verifier,
    );
    assert!(
        matches!(result, Err(ManagedLifecycleError::Executor(_))),
        "expected an ambiguous executor handoff, got {result:?}"
    );
}

#[test]
fn automatic_recovery_commits_only_freshly_verified_completion_without_an_executor() {
    let database = TestDatabase::new();
    let request = lock_request("observe-only-completion", false);
    let calls = Arc::new(AtomicUsize::new(0));
    leave_dispatched_lock_ambiguous(&database, &request, &calls);
    let mut control = open_lock_control(
        database.path(),
        vec![lock_observation(false, 3), lock_observation(false, 4)],
        vec![session_observation(3), session_observation(4)],
    );
    let mut verifier = ScriptedVerifier::new([
        VerifierStep::Outcome(VerificationDisposition::Satisfied),
        VerifierStep::Outcome(VerificationDisposition::Satisfied),
    ]);
    let mut recovery_actor = actor(false);
    recovery_actor.kind = ActorKind::Service;
    let receipt = value(control.recover_session_request_without_replay(
        principal(),
        recovery_actor,
        &request.request_id,
        &mut verifier,
    ));
    assert_complete(&receipt);
    assert!(receipt.recovered);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 2);
}

#[derive(Debug)]
struct NoRecoveryApproval;
impl ManagedApprovalAuthorizer for NoRecoveryApproval {
    fn authorize(&self, _: &ManagedApprovalChallenge) -> Result<TrustedHumanApproval, String> {
        unreachable!("an ambiguous session retry cannot obtain fresh replay authority")
    }
}

#[test]
fn ordinary_converge_retry_cannot_reprepare_an_ambiguous_session_effect() {
    for step in [
        VerifierStep::Outcome(VerificationDisposition::NotSatisfied),
        VerifierStep::Outcome(VerificationDisposition::Inconclusive),
        VerifierStep::Failure,
    ] {
        let database = TestDatabase::new();
        let request = lock_request("ordinary-retry-denial", false);
        let calls = Arc::new(AtomicUsize::new(0));
        leave_dispatched_lock_ambiguous(&database, &request, &calls);
        let mut control = open_lock_control(database.path(), vec![], vec![]);
        let mut verifier = ScriptedVerifier::new([step]);
        let mut executor = ScriptedExecutor::failure(calls.clone());
        assert!(
            control
                .converge_session_lock(
                    principal(),
                    actor(true),
                    request.clone(),
                    &NoRecoveryApproval,
                    &mut executor,
                    &mut verifier
                )
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
        let status = value(control.session_lock_request_status(&principal(), &request.request_id));
        assert_eq!(status.state, "indeterminate");
    }
}

#[test]
fn ordinary_converge_retry_finishes_only_independently_proven_completion() {
    let database = TestDatabase::new();
    let request = lock_request("ordinary-retry-completion", false);
    let calls = Arc::new(AtomicUsize::new(0));
    leave_dispatched_lock_ambiguous(&database, &request, &calls);
    let mut control = open_lock_control(
        database.path(),
        vec![lock_observation(false, 3), lock_observation(false, 4)],
        vec![session_observation(3), session_observation(4)],
    );
    let mut verifier = ScriptedVerifier::new([
        VerifierStep::Outcome(VerificationDisposition::Satisfied),
        VerifierStep::Outcome(VerificationDisposition::Satisfied),
    ]);
    let mut executor = ScriptedExecutor::failure(calls.clone());
    let receipt = value(control.converge_session_lock(
        principal(),
        actor(true),
        request,
        &NoRecoveryApproval,
        &mut executor,
        &mut verifier,
    ));
    assert_complete(&receipt);
    assert!(receipt.recovered);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn automatic_recovery_never_reprepares_when_verifier_and_control_disagree() {
    let database = TestDatabase::new();
    let request = lock_request("observe-only-disagreement", false);
    let calls = Arc::new(AtomicUsize::new(0));
    leave_dispatched_lock_ambiguous(&database, &request, &calls);
    let mut control = open_lock_control(
        database.path(),
        vec![lock_observation(true, 3)],
        vec![session_observation(3)],
    );
    let mut verifier =
        ScriptedVerifier::new([VerifierStep::Outcome(VerificationDisposition::Satisfied)]);
    assert!(matches!(
        control.recover_session_request_without_replay(
            principal(),
            actor(false),
            &request.request_id,
            &mut verifier
        ),
        Err(ManagedLifecycleError::Indeterminate(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(control);
    let (_, authority_verifier) = authority_material();
    let store = value(SqliteTransactionStore::open(
        database.path(),
        authority_verifier,
        value(SqliteIntegrityKey::new(fixture_key(5))),
    ));
    use linura_transaction::TransactionStore;
    let snapshots = value(store.list_state(linura_transaction::TransactionState::Indeterminate));
    assert_eq!(snapshots.len(), 1);
    // Transaction generations start at zero (unlike native lock generations).
    // Observe-only recovery must not advance that durable generation.
    assert_eq!(snapshots[0].current_generation, 0);
    assert!(value(store.list_state(linura_transaction::TransactionState::Prepared)).is_empty());
}

#[test]
fn absent_unknown_or_failed_native_observation_does_not_turn_recovery_into_retry() {
    for step in [
        VerifierStep::Outcome(VerificationDisposition::NotSatisfied),
        VerifierStep::Outcome(VerificationDisposition::Inconclusive),
        VerifierStep::Failure,
    ] {
        let database = TestDatabase::new();
        let request = lock_request("observe-only-denial", false);
        let calls = Arc::new(AtomicUsize::new(0));
        leave_dispatched_lock_ambiguous(&database, &request, &calls);
        let mut control = open_lock_control(database.path(), vec![], vec![]);
        let mut verifier = ScriptedVerifier::new([step]);
        assert!(
            control
                .recover_session_request_without_replay(
                    principal(),
                    actor(false),
                    &request.request_id,
                    &mut verifier
                )
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn wrong_recovery_principal_fails_before_independent_native_probe() {
    let database = TestDatabase::new();
    let request = lock_request("observe-only-cross-user", false);
    let calls = Arc::new(AtomicUsize::new(0));
    leave_dispatched_lock_ambiguous(&database, &request, &calls);
    let mut control = open_lock_control(database.path(), vec![], vec![]);
    let mut verifier =
        ScriptedVerifier::new([VerifierStep::Outcome(VerificationDisposition::Satisfied)]);
    assert!(
        control
            .recover_session_request_without_replay(
                value(AuthenticatedPrincipal::new("unix:uid:0")),
                actor(true),
                &request.request_id,
                &mut verifier
            )
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 0);
}
