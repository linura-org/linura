//! Deterministic authority tests with simulated native observations. These are
//! NOT real sleep, PAM, compositor, recovery or production qualification evidence.
use super::s17_managed_lock::{lock_id, lock_observation, session_observation};
use super::*;
use linura_control::ProtectiveLockSettingsControl;
use linura_core::SleepInvocationId;
use linura_persistence_sqlite::SqliteProtectiveLockSettingStore;
use linura_transaction::{ProtectiveLockSettingRecord, ProtectiveLockSettingStore, digest_bytes};

const SERVICE: &str = "service:system-sleep-protection";

fn fixture_key(index: usize) -> Vec<u8> {
    use std::io::Read;

    // Preserve one process-local key per isolated test domain, including DB
    // reopen/recovery, without embedding production-like secrets in source.
    static KEYS: std::sync::OnceLock<[[u8; 32]; 4]> = std::sync::OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        let mut keys = [[0_u8; 32]; 4];
        let mut entropy = value(std::fs::File::open("/dev/urandom"));
        for key in &mut keys {
            value(entropy.read_exact(key));
        }
        keys
    });
    keys[index].to_vec()
}

#[test]
fn fixture_keys_are_process_stable_and_domain_separated() {
    for first in 0..4 {
        assert_eq!(fixture_key(first), fixture_key(first));
        for second in (first + 1)..4 {
            assert_ne!(fixture_key(first), fixture_key(second));
        }
    }
}

fn service() -> AuthenticatedPrincipal {
    value(AuthenticatedPrincipal::new(SERVICE))
}
fn event() -> SleepInvocationId {
    value(SleepInvocationId::new(
        lock_id().epoch().boot().clone(),
        "11223344-1234-4567-89ab-0123456789ab",
    ))
}
fn entry(sequence: u64) -> ObservationEnvelope {
    let event = event();
    ObservationEnvelope {
        provider: value(ProviderId::new("system-sleep")),
        resource: value(event.resource_id()),
        capability: value(CapabilityId::new("session.sleep-entry.observe")),
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms: now_unix_ms(),
        valid_for_ms: 2000,
        sequence,
        attributes: BTreeMap::from([
            (
                "boot_id".into(),
                ObservedValue::Text(event.boot().as_str().into()),
            ),
            (
                "sleep_invocation".into(),
                ObservedValue::Text(event.invocation().into()),
            ),
            (
                "sleep_operation".into(),
                ObservedValue::Text("suspend".into()),
            ),
            ("pre_kernel_gate".into(), ObservedValue::Bool(true)),
            ("helper_attested".into(), ObservedValue::Bool(true)),
        ]),
    }
}
fn policy_authority() -> (
    linura_transaction::TransactionAuthoritySigner,
    linura_transaction::TransactionAuthorityVerifier,
) {
    value(TransactionAuthorityKey::new(fixture_key(0))).split()
}
fn settings_store(database: &Path) -> SqliteProtectiveLockSettingStore {
    value(SqliteProtectiveLockSettingStore::open(
        database.with_extension("protective.sqlite3"),
        value(SqliteIntegrityKey::new(fixture_key(1))),
        policy_authority().1,
    ))
}
fn set_policy(database: &Path, enabled: bool) {
    let mut store = settings_store(database);
    let lock = lock_id();
    let owner = value(PrincipalId::new("unix:uid:1000"));
    let previous = value(store.current(&owner, lock.epoch()));
    let request = value(RequestId::new(if enabled {
        "request:v010:protective-lock-setting:enable"
    } else {
        "request:v010:protective-lock-setting:revoke"
    }));
    let record = value(ProtectiveLockSettingRecord::new(
        owner,
        lock.epoch().clone(),
        value(IntentId::new("intent:s17:protective-lock:owner-approved")),
        request.clone(),
        previous.map(|p| p.digest().clone()),
        enabled,
        lock,
        now_unix_ms(),
        digest_bytes(
            "test-only-native-owner-confirmation",
            request.as_str().as_bytes(),
        ),
    ));
    let expires = record.confirmed_at_unix_ms() + 2000;
    let update = value(
        policy_authority()
            .0
            .authorize_protective_lock_setting(record, expires),
    );
    value(store.apply(&update));
}

type Hook = Box<dyn FnOnce() + Send>;
fn unexpected_recovery_entry_probe() {
    unreachable!("observe-only recovery consulted the native entry");
}
#[derive(Default)]
struct ObserverHooks {
    entry: Vec<Option<Hook>>,
    lock: Vec<Option<Hook>>,
    renew_samples: bool,
}
impl From<Vec<Option<Hook>>> for ObserverHooks {
    fn from(entry: Vec<Option<Hook>>) -> Self {
        Self {
            entry,
            ..Self::default()
        }
    }
}
struct ScriptedNativeObserver {
    inner: QueueObserver,
    hooks: Mutex<VecDeque<Option<Hook>>>,
    renew_samples: bool,
}
impl Observer for ScriptedNativeObserver {
    fn observer_id(&self) -> ProviderId {
        self.inner.observer_id()
    }
    fn observation_capabilities(&self) -> Vec<Capability> {
        self.inner.observation_capabilities()
    }
    fn health(&self) -> ProviderHealth {
        self.inner.health()
    }
    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        self.inner.resources()
    }
    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if let Some(Some(hook)) = value(self.hooks.lock()).pop_front() {
            hook();
        }
        let mut observation = self.inner.observe_authoritative(resource, capability)?;
        if self.renew_samples {
            // Explicit deterministic fresh-probe fixture, never production or
            // native evidence. Used to prove old authority cannot be renewed.
            observation.observed_at_unix_ms = now_unix_ms();
        }
        Ok(observation)
    }
}

fn open_protective_control(
    database: &Path,
    locks: Vec<ObservationEnvelope>,
    sessions: Vec<ObservationEnvelope>,
    entries: Vec<ObservationEnvelope>,
    hooks: impl Into<ObserverHooks>,
    with_policy_store: bool,
) -> ManagedLifecycleControl<SqliteTransactionStore> {
    let mut coordinator = ObservationCoordinator::new();
    let mut hooks = hooks.into();
    for (samples, provider, capability, resource) in [
        (
            locks,
            "session-locker",
            "session.secure-lock.observe",
            value(lock_id().resource_id()),
        ),
        (
            sessions,
            "logind",
            "session.epoch.observe",
            value(lock_id().epoch().resource_id()),
        ),
    ] {
        value(
            coordinator.register_observer(Box::new(ScriptedNativeObserver {
                inner: QueueObserver::for_route(
                    samples,
                    value(ProviderId::new(provider)),
                    value(CapabilityId::new(capability)),
                    resource,
                ),
                hooks: Mutex::new(if provider == "session-locker" {
                    std::mem::take(&mut hooks.lock).into()
                } else {
                    VecDeque::new()
                }),
                renew_samples: hooks.renew_samples,
            })),
        );
    }
    // Even an exhausted event observer must not be consulted during recovery.
    value(
        coordinator.register_observer(Box::new(ScriptedNativeObserver {
            inner: QueueObserver::for_route(
                entries,
                value(ProviderId::new("system-sleep")),
                value(CapabilityId::new("session.sleep-entry.observe")),
                value(event().resource_id()),
            ),
            hooks: Mutex::new(hooks.entry.into()),
            renew_samples: hooks.renew_samples,
        })),
    );
    let (signer, verifier) = authority_material();
    let control = value(ManagedLifecycleControl::new(
        PlanPreviewControl::new(coordinator),
        value(SqliteTransactionStore::open(
            database,
            verifier,
            value(SqliteIntegrityKey::new(fixture_key(2))),
        )),
        signer,
    ));
    let control = value(control.with_request_journal(Box::new(value(
        linura_persistence_sqlite::SqliteApprovedRequestJournal::open(
            database.with_extension("requests.sqlite3"),
            value(SqliteIntegrityKey::new(fixture_key(3))),
        ),
    ))));
    if with_policy_store {
        control.with_protective_lock_settings(value(ProtectiveLockSettingsControl::new(
            Box::new(settings_store(database)),
            policy_authority().0,
        )))
    } else {
        control
    }
}

fn successful_observations() -> (
    Vec<ObservationEnvelope>,
    Vec<ObservationEnvelope>,
    Vec<ObservationEnvelope>,
) {
    (
        [false, false, false, true, true]
            .into_iter()
            .enumerate()
            .map(|(i, s)| lock_observation(s, i as u64 + 1))
            .collect(),
        (1..=5).map(session_observation).collect(),
        (1..=3).map(entry).collect(),
    )
}

#[test]
fn protective_lock_runs_all_stages_without_impersonating_owner_and_retry_is_observe_only() {
    let db = TestDatabase::new();
    set_policy(db.path(), true);
    let (locks, sessions, entries) = successful_observations();
    let mut control = open_protective_control(db.path(), locks, sessions, entries, vec![], true);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    let mut verifier = ScriptedVerifier::new(
        (0..4).map(|_| VerifierStep::Outcome(VerificationDisposition::Satisfied)),
    );
    let receipt = value(control.converge_protective_session_lock(
        service(),
        event(),
        lock_id(),
        &mut executor,
        &mut verifier,
    ));
    assert_complete(&receipt);
    let request_id = value(event().protective_request_id(lock_id().epoch()));
    let retained = value(control.retained_session_request(&service(), &request_id));
    assert_eq!(
        retained.reason.intent_ids,
        [value(IntentId::new(
            "intent:s17:protective-lock:owner-approved"
        ))]
    );
    assert!(
        control
            .retained_session_request(&principal(), &request_id)
            .is_err()
    );
    drop(control);
    set_policy(db.path(), false);
    // A restart needs neither current consent nor the completed native event.
    let mut restarted = open_protective_control(
        db.path(),
        vec![lock_observation(true, 1)],
        vec![session_observation(1)],
        vec![],
        vec![Some(Box::new(unexpected_recovery_entry_probe) as Hook)],
        false,
    );
    let retry = value(restarted.converge_protective_session_lock(
        service(),
        event(),
        lock_id(),
        &mut executor,
        &mut verifier,
    ));
    assert_complete(&retry);
    assert!(retry.recovered);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn missing_revoked_and_wrong_principal_never_dispatch() {
    for mode in 0..4 {
        let db = TestDatabase::new();
        if mode != 0 {
            set_policy(db.path(), true);
        }
        if mode == 1 {
            set_policy(db.path(), false);
        }
        let (locks, sessions, entries) = successful_observations();
        let mut control =
            open_protective_control(db.path(), locks, sessions, entries, vec![], true);
        let caller = match mode {
            2 => principal(),
            3 => value(AuthenticatedPrincipal::new("unix:uid:0")),
            _ => service(),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let mut executor =
            ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
        let mut verifier = ScriptedVerifier::new([]);
        assert!(
            control
                .converge_protective_session_lock(
                    caller,
                    event(),
                    lock_id(),
                    &mut executor,
                    &mut verifier
                )
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn revocation_during_prepare_and_handoff_cannot_use_the_retained_setting() {
    for read in [2, 3] {
        let db = TestDatabase::new();
        set_policy(db.path(), true);
        let (locks, sessions, entries) = successful_observations();
        let path = db.path().to_owned();
        let mut hooks: Vec<Option<Hook>> = (1..read).map(|_| None).collect();
        hooks.push(Some(Box::new(move || set_policy(&path, false))));
        let mut control = open_protective_control(db.path(), locks, sessions, entries, hooks, true);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut executor =
            ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
        assert!(
            control
                .converge_protective_session_lock(
                    service(),
                    event(),
                    lock_id(),
                    &mut executor,
                    &mut ScriptedVerifier::new([])
                )
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        // The handoff case has already persisted Prepared. Revoking consent
        // cannot convert its retry into dispatch or reconstructed approval.
        if read == 3 {
            assert!(
                control
                    .converge_protective_session_lock(
                        service(),
                        event(),
                        lock_id(),
                        &mut executor,
                        &mut ScriptedVerifier::new([])
                    )
                    .is_err()
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
}

#[test]
fn protective_request_cannot_select_automatic_policy_through_the_manual_route() {
    let db = TestDatabase::new();
    set_policy(db.path(), true);
    let (locks, sessions, entries) = successful_observations();
    let mut control = open_protective_control(db.path(), locks, sessions, entries, vec![], true);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    let mut verifier = ScriptedVerifier::new(
        (0..2).map(|_| VerifierStep::Outcome(VerificationDisposition::Satisfied)),
    );
    value(control.converge_protective_session_lock(
        service(),
        event(),
        lock_id(),
        &mut executor,
        &mut verifier,
    ));
    let request = value(control.retained_session_request(
        &service(),
        &value(event().protective_request_id(lock_id().epoch())),
    ));
    for caller in [service(), principal()] {
        assert!(
            control
                .converge_session_lock(
                    caller,
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
    // Public planning does not have access to the private protective context.
    let mut coordinator = ObservationCoordinator::new();
    value(
        coordinator.register_observer(Box::new(QueueObserver::for_route(
            vec![lock_observation(false, 1)],
            value(ProviderId::new("session-locker")),
            value(CapabilityId::new("session.secure-lock.observe")),
            value(lock_id().resource_id()),
        ))),
    );
    value(
        coordinator.register_observer(Box::new(QueueObserver::for_route(
            vec![session_observation(1)],
            value(ProviderId::new("logind")),
            value(CapabilityId::new("session.epoch.observe")),
            value(lock_id().epoch().resource_id()),
        ))),
    );
    let mut previews = PlanPreviewControl::new(coordinator);
    assert!(
        previews
            .plan_desired_state(service(), actor(true), request)
            .is_err()
    );
}

#[test]
fn unqualified_substituted_stale_and_disappeared_events_are_not_lock_authority() {
    for mode in 0..5 {
        let db = TestDatabase::new();
        set_policy(db.path(), true);
        let (locks, sessions, mut entries) = successful_observations();
        match mode {
            0 => {
                entries[0]
                    .attributes
                    .insert("pre_kernel_gate".into(), ObservedValue::Bool(false));
            }
            1 => {
                entries[1].attributes.insert(
                    "sleep_invocation".into(),
                    ObservedValue::Text("11223344-1234-4567-89ab-0123456789ac".into()),
                );
            }
            2 => {
                entries[2].observed_at_unix_ms = now_unix_ms().saturating_sub(2000);
            }
            3 => {
                entries.truncate(2);
            }
            _ => {
                entries[2].authority = ObservationAuthority::SyntheticTest;
            }
        }
        let mut control =
            open_protective_control(db.path(), locks, sessions, entries, vec![], true);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut executor =
            ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
        assert!(
            control
                .converge_protective_session_lock(
                    service(),
                    event(),
                    lock_id(),
                    &mut executor,
                    &mut ScriptedVerifier::new([])
                )
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn native_seat_and_lock_generation_drift_cannot_cross_protective_handoff() {
    for mode in 0..3 {
        let db = TestDatabase::new();
        set_policy(db.path(), true);
        let (mut locks, mut sessions, entries) = successful_observations();
        match mode {
            0 => {
                sessions[1]
                    .attributes
                    .insert("seat".into(), ObservedValue::Text("seat1".into()));
            }
            1 => {
                sessions[2]
                    .attributes
                    .insert("active".into(), ObservedValue::Bool(false));
            }
            _ => {
                locks[2]
                    .attributes
                    .insert("lock_generation".into(), ObservedValue::U64(8));
            }
        }
        let mut control =
            open_protective_control(db.path(), locks, sessions, entries, vec![], true);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut executor =
            ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
        assert!(
            control
                .converge_protective_session_lock(
                    service(),
                    event(),
                    lock_id(),
                    &mut executor,
                    &mut ScriptedVerifier::new([])
                )
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn lost_executor_reply_recovers_without_event_consent_or_dispatch_replay() {
    let db = TestDatabase::new();
    set_policy(db.path(), true);
    let (locks, sessions, entries) = successful_observations();
    let mut control = open_protective_control(db.path(), locks, sessions, entries, vec![], true);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::failure(calls.clone());
    assert!(
        control
            .converge_protective_session_lock(
                service(),
                event(),
                lock_id(),
                &mut executor,
                &mut ScriptedVerifier::new([])
            )
            .is_err()
    );
    drop(control);
    set_policy(db.path(), false);
    let mut restarted = open_protective_control(
        db.path(),
        vec![lock_observation(true, 1), lock_observation(true, 2)],
        vec![session_observation(1), session_observation(2)],
        vec![],
        vec![Some(Box::new(unexpected_recovery_entry_probe) as Hook)],
        false,
    );
    let mut verifier = ScriptedVerifier::new(
        (0..2).map(|_| VerifierStep::Outcome(VerificationDisposition::Satisfied)),
    );
    let recovered = value(restarted.converge_protective_session_lock(
        service(),
        event(),
        lock_id(),
        &mut executor,
        &mut verifier,
    ));
    assert_complete(&recovered);
    assert!(recovered.recovered);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn absent_effect_and_new_owner_generation_never_mint_retry_authority() {
    let db = TestDatabase::new();
    set_policy(db.path(), true);
    let (locks, sessions, entries) = successful_observations();
    let mut control = open_protective_control(db.path(), locks, sessions, entries, vec![], true);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::failure(calls.clone());
    assert!(
        control
            .converge_protective_session_lock(
                service(),
                event(),
                lock_id(),
                &mut executor,
                &mut ScriptedVerifier::new([])
            )
            .is_err()
    );
    let changed_lock = value(linura_core::SessionLockId::new(
        lock_id().epoch().clone(),
        lock_id().security_owner_invocation().clone(),
        8,
    ));
    assert!(
        control
            .converge_protective_session_lock(
                service(),
                event(),
                changed_lock,
                &mut executor,
                &mut ScriptedVerifier::new([])
            )
            .is_err()
    );
    assert!(
        control
            .converge_protective_session_lock(
                service(),
                event(),
                lock_id(),
                &mut executor,
                &mut ScriptedVerifier::new([VerifierStep::Outcome(
                    VerificationDisposition::NotSatisfied
                )])
            )
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[derive(Debug)]
struct FailedReadStore {
    inner: SqliteProtectiveLockSettingStore,
    failed: Arc<std::sync::atomic::AtomicBool>,
}
impl ProtectiveLockSettingStore for FailedReadStore {
    fn current(
        &self,
        owner: &PrincipalId,
        epoch: &linura_core::SessionEpoch,
    ) -> Result<Option<ProtectiveLockSettingRecord>, linura_transaction::TransactionStoreError>
    {
        if self.failed.load(Ordering::SeqCst) {
            return Err(linura_transaction::TransactionStoreError::Corruption(
                "injected settings read failure".into(),
            ));
        }
        self.inner.current(owner, epoch)
    }
    fn request(
        &self,
        owner: &PrincipalId,
        request: &RequestId,
    ) -> Result<Option<ProtectiveLockSettingRecord>, linura_transaction::TransactionStoreError>
    {
        self.inner.request(owner, request)
    }
    fn apply(
        &mut self,
        update: &linura_transaction::ProtectiveLockSettingUpdate,
    ) -> Result<ProtectiveLockSettingRecord, linura_transaction::TransactionStoreError> {
        self.inner.apply(update)
    }
    fn integrity_check(&self) -> Result<(), linura_transaction::TransactionStoreError> {
        self.inner.integrity_check()
    }
}

#[test]
fn unreadable_current_policy_at_prepare_or_handoff_is_not_a_cached_grant() {
    for read in [2, 3] {
        let db = TestDatabase::new();
        set_policy(db.path(), true);
        let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_flag = failed.clone();
        let mut hooks: Vec<Option<Hook>> = (1..read).map(|_| None).collect();
        hooks.push(Some(Box::new(move || {
            hook_flag.store(true, Ordering::SeqCst)
        })));
        let (locks, sessions, entries) = successful_observations();
        let mut control =
            open_protective_control(db.path(), locks, sessions, entries, hooks, false)
                .with_protective_lock_settings(value(ProtectiveLockSettingsControl::new(
                    Box::new(FailedReadStore {
                        inner: settings_store(db.path()),
                        failed,
                    }),
                    policy_authority().0,
                )));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut executor =
            ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
        assert!(
            control
                .converge_protective_session_lock(
                    service(),
                    event(),
                    lock_id(),
                    &mut executor,
                    &mut ScriptedVerifier::new([])
                )
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn fresh_revalidation_cannot_extend_the_original_candidate_deadline() {
    let db = TestDatabase::new();
    set_policy(db.path(), true);
    let (locks, sessions, entries) = successful_observations();
    let entry_probes = Arc::new(AtomicUsize::new(0));
    let hooks = ObserverHooks {
        lock: vec![
            None,
            Some(Box::new(|| {
                std::thread::sleep(std::time::Duration::from_millis(2100))
            })),
        ],
        entry: (0..3)
            .map(|_| {
                let probes = entry_probes.clone();
                Some(Box::new(move || {
                    probes.fetch_add(1, Ordering::SeqCst);
                }) as Hook)
            })
            .collect(),
        renew_samples: true,
    };
    let mut control = open_protective_control(db.path(), locks, sessions, entries, hooks, true);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    assert!(
        control
            .converge_protective_session_lock(
                service(),
                event(),
                lock_id(),
                &mut executor,
                &mut ScriptedVerifier::new([])
            )
            .is_err()
    );
    // Both canonical candidates acquired fresh event/session/coverage samples;
    // the second did not make the original two-second authority current again.
    assert_eq!(entry_probes.load(Ordering::SeqCst), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
