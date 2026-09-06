use std::collections::{BTreeMap, VecDeque};
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use linura_core::{
    Actor, ActorId, ActorKind, Capability, CapabilityId, IntentId, PrincipalId, ProviderId,
    RequestId, ResourceId, SemanticReason, SupportLevel,
};
use linura_observation::{
    ObservationAuthority, ObservationEnvelope, ObservedValue, ProviderAvailability, ProviderHealth,
};
use linura_observation_control::ObservationCoordinator;
use linura_persistence_sqlite::{SqliteIntegrityKey, SqliteTransactionStore};
use linura_protocol::PlanDesiredStateRequest;
use linura_provider_sdk::{
    ExecutionDisposition, ExecutionOutcome, Observer, ProviderError, VerificationDisposition,
    VerificationOutcome,
};
use linura_transaction::TransactionAuthorityKey;

use linura_control::{
    AuthenticatedPrincipal, AuthorizedEffect, AuthorizedEffectExecutor, IndependentManagedVerifier,
    MANAGED_SYSTEMD_INTENT_ORIGIN, ManagedLifecycleControl, ManagedLifecycleError,
    ManagedMutationReceipt, PlanPreviewControl, TrustedHumanApproval, managed_request_id,
};

const RESOURCE: &str = "systemd:unit:linura-managed-qualification.service";
static NEXT_DB: AtomicU64 = AtomicU64::new(1);

fn value<T, E: Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}

trait ResultErrorExt<T, E> {
    fn error_or_unreachable(self) -> E;
}

impl<T, E> ResultErrorExt<T, E> for Result<T, E> {
    fn error_or_unreachable(self) -> E {
        match self {
            Ok(_) => unreachable!("expected operation to fail"),
            Err(error) => error,
        }
    }
}

fn now_unix_ms() -> u64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| unreachable!("{error}"));
    u64::try_from(duration.as_millis()).unwrap_or_else(|error| unreachable!("{error}"))
}

fn provider() -> ProviderId {
    value(ProviderId::new("systemd"))
}

fn resource(value: &str) -> ResourceId {
    value_or_unreachable(ResourceId::new(value))
}

fn capability_id() -> CapabilityId {
    value(CapabilityId::new("systemd.unit.observe"))
}

fn value_or_unreachable<T, E: Debug>(result: Result<T, E>) -> T {
    value(result)
}

#[derive(Debug)]
struct TestDatabase {
    root: PathBuf,
    path: PathBuf,
}

impl TestDatabase {
    fn new() -> Self {
        let sequence = NEXT_DB.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "linura-v06-qualification-{}-{sequence}",
            std::process::id()
        ));
        value(std::fs::create_dir_all(&root));
        let path = root.join("authority.sqlite3");
        Self { root, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_dir_all(&self.root);
    }
}

struct QueueObserver {
    provider: ProviderId,
    capability: Capability,
    health: ProviderHealth,
    resource: ResourceId,
    observations: Mutex<VecDeque<ObservationEnvelope>>,
}

impl QueueObserver {
    fn new(observations: Vec<ObservationEnvelope>) -> Self {
        let provider = provider();
        let capability_id = capability_id();
        Self {
            capability: Capability {
                id: capability_id,
                support: SupportLevel::Supported,
                provider: Some(provider.clone()),
                reason: None,
            },
            health: ProviderHealth {
                provider: provider.clone(),
                availability: ProviderAvailability::Available,
                reason: None,
            },
            provider,
            resource: resource(RESOURCE),
            observations: Mutex::new(observations.into()),
        }
    }
}

impl Observer for QueueObserver {
    fn observer_id(&self) -> ProviderId {
        self.provider.clone()
    }

    fn observation_capabilities(&self) -> Vec<Capability> {
        vec![self.capability.clone()]
    }

    fn health(&self) -> ProviderHealth {
        self.health.clone()
    }

    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        Ok(vec![self.resource.clone()])
    }

    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if resource != &self.resource || capability != &self.capability.id {
            return Err(ProviderError::Unsupported(
                "qualification observer received an out-of-scope request".into(),
            ));
        }
        self.observations
            .lock()
            .map_err(|_| ProviderError::Internal("qualification observer queue poisoned".into()))?
            .pop_front()
            .ok_or_else(|| ProviderError::Unavailable("qualification observation exhausted".into()))
    }
}

fn observation(state: &str, sequence: u64) -> ObservationEnvelope {
    ObservationEnvelope {
        provider: provider(),
        resource: resource(RESOURCE),
        capability: capability_id(),
        authority: ObservationAuthority::SyntheticTest,
        observed_at_unix_ms: now_unix_ms(),
        valid_for_ms: 60_000,
        sequence,
        attributes: BTreeMap::from([("active_state".into(), ObservedValue::Text(state.into()))]),
    }
}

fn stale_observation(state: &str, sequence: u64) -> ObservationEnvelope {
    ObservationEnvelope {
        observed_at_unix_ms: now_unix_ms().saturating_sub(60_000),
        valid_for_ms: 1,
        ..observation(state, sequence)
    }
}

fn authority_material() -> (
    linura_transaction::TransactionAuthoritySigner,
    linura_transaction::TransactionAuthorityVerifier,
) {
    value(TransactionAuthorityKey::new(vec![0x41; 32])).split()
}

fn open_control(
    database: &Path,
    observations: Vec<ObservationEnvelope>,
) -> ManagedLifecycleControl<SqliteTransactionStore> {
    let mut coordinator = ObservationCoordinator::new();
    value(coordinator.register_observer(Box::new(QueueObserver::new(observations))));
    let previews = PlanPreviewControl::new(coordinator);
    let (signer, verifier) = authority_material();
    let integrity = value(SqliteIntegrityKey::new(vec![0x52; 32]));
    let store = value(SqliteTransactionStore::open(database, verifier, integrity));
    value(ManagedLifecycleControl::new(previews, store, signer))
}

fn principal() -> AuthenticatedPrincipal {
    value(AuthenticatedPrincipal::new("unix:uid:1000"))
}

fn actor(interactive: bool) -> Actor {
    Actor {
        id: value(ActorId::new("qualification:human")),
        kind: ActorKind::Human,
        interactive,
    }
}

fn approval() -> TrustedHumanApproval {
    TrustedHumanApproval::from_privileged_local_boundary(value(PrincipalId::new("unix:uid:1000")))
}

fn request_for(operation: &str, target_resource: &str, desired: &str) -> PlanDesiredStateRequest {
    let mut request = PlanDesiredStateRequest {
        request_id: value(RequestId::new("request:v06:pending")),
        provider: provider(),
        resource: resource(target_resource),
        observation_capability: capability_id(),
        reason: SemanticReason {
            summary: "v0.6 qualification".into(),
            intent_ids: vec![value(IntentId::new(MANAGED_SYSTEMD_INTENT_ORIGIN))],
            requirement_ids: vec![],
            capability_ids: vec![],
        },
        desired_state: BTreeMap::from([("active_state".into(), desired.into())]),
    };
    request.request_id = value(managed_request_id(operation, &request));
    request
}

fn request(operation: &str, desired: &str) -> PlanDesiredStateRequest {
    request_for(operation, RESOURCE, desired)
}

#[derive(Debug)]
struct ScriptedExecutor {
    disposition: Option<ExecutionDisposition>,
    failure: Option<String>,
    calls: Arc<AtomicUsize>,
}

impl ScriptedExecutor {
    fn outcome(disposition: ExecutionDisposition, calls: Arc<AtomicUsize>) -> Self {
        Self {
            disposition: Some(disposition),
            failure: None,
            calls,
        }
    }

    fn failure(calls: Arc<AtomicUsize>) -> Self {
        Self {
            disposition: None,
            failure: Some("injected executor transport failure".into()),
            calls,
        }
    }
}

impl AuthorizedEffectExecutor for ScriptedExecutor {
    fn execute_authorized(
        &mut self,
        authorization: AuthorizedEffect,
    ) -> Result<ExecutionOutcome, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(detail) = &self.failure {
            return Err(detail.clone());
        }
        let (_effect, binding) = authorization.into_executor_request();
        let disposition = self
            .disposition
            .unwrap_or(ExecutionDisposition::RejectedBeforeDispatch);
        ExecutionOutcome::new(
            disposition,
            binding.dispatch_digest,
            "qualification executor",
        )
        .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug)]
enum VerifierStep {
    Outcome(VerificationDisposition),
    Failure,
}

#[derive(Debug)]
struct ScriptedVerifier {
    steps: VecDeque<VerifierStep>,
    calls: Arc<AtomicUsize>,
}

impl ScriptedVerifier {
    fn new(steps: impl IntoIterator<Item = VerifierStep>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl IndependentManagedVerifier for ScriptedVerifier {
    fn verify_effect(
        &mut self,
        _effect: &linura_provider_sdk::EffectDescriptor,
    ) -> Result<VerificationOutcome, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self
            .steps
            .pop_front()
            .unwrap_or(VerifierStep::Outcome(VerificationDisposition::Inconclusive))
        {
            VerifierStep::Outcome(disposition) => {
                VerificationOutcome::new(disposition, "qualification verifier")
                    .map_err(|error| error.to_string())
            }
            VerifierStep::Failure => Err("injected independent verifier failure".into()),
        }
    }
}

fn converge(
    control: &mut ManagedLifecycleControl<SqliteTransactionStore>,
    request: PlanDesiredStateRequest,
    executor: &mut ScriptedExecutor,
    verifier: &mut ScriptedVerifier,
) -> Result<ManagedMutationReceipt, ManagedLifecycleError> {
    control.converge_systemd_active_state(
        principal(),
        actor(true),
        request,
        &approval(),
        executor,
        verifier,
    )
}

fn assert_complete(receipt: &ManagedMutationReceipt) {
    assert_eq!(receipt.final_state, "committed");
    assert_eq!(
        receipt.stages,
        [
            "request-intent",
            "observe",
            "plan",
            "validate",
            "authorize",
            "prepare",
            "execute",
            "verify",
            "commit",
            "audit",
            "reconcile",
        ]
    );
}

#[test]
fn success_exact_retry_and_request_substitution_are_durable() {
    let database = TestDatabase::new();
    let mut control = open_control(
        database.path(),
        vec![
            observation("inactive", 1),
            observation("inactive", 2),
            observation("active", 3),
            observation("active", 4),
            observation("active", 5),
        ],
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    let mut verifier = ScriptedVerifier::new([
        VerifierStep::Outcome(VerificationDisposition::Satisfied),
        VerifierStep::Outcome(VerificationDisposition::Satisfied),
        VerifierStep::Outcome(VerificationDisposition::Satisfied),
        VerifierStep::Outcome(VerificationDisposition::Satisfied),
    ]);
    let desired = request("activate-once", "active");

    let first = value(converge(
        &mut control,
        desired.clone(),
        &mut executor,
        &mut verifier,
    ));
    assert_complete(&first);
    assert!(!first.recovered);

    let retry = value(converge(
        &mut control,
        desired.clone(),
        &mut executor,
        &mut verifier,
    ));
    assert_complete(&retry);
    assert!(retry.recovered);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let substituted = request("activate-once", "inactive");
    let error =
        converge(&mut control, substituted, &mut executor, &mut verifier).error_or_unreachable();
    assert!(
        matches!(error, ManagedLifecycleError::Authority(detail) if detail.contains("recovery request does not match"))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn active_to_inactive_success_is_qualified() {
    let database = TestDatabase::new();
    let mut control = open_control(
        database.path(),
        vec![
            observation("active", 1),
            observation("active", 2),
            observation("inactive", 3),
            observation("inactive", 4),
        ],
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    let mut verifier = ScriptedVerifier::new([
        VerifierStep::Outcome(VerificationDisposition::Satisfied),
        VerifierStep::Outcome(VerificationDisposition::Satisfied),
    ]);
    let receipt = value(converge(
        &mut control,
        request("deactivate-once", "inactive"),
        &mut executor,
        &mut verifier,
    ));
    assert_complete(&receipt);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn denial_and_out_of_scope_requests_stop_before_dispatch() {
    let database = TestDatabase::new();
    let mut control = open_control(database.path(), vec![]);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    let mut verifier = ScriptedVerifier::new([]);

    let denied = control
        .converge_systemd_active_state(
            principal(),
            actor(false),
            request("denied-human", "active"),
            &approval(),
            &mut executor,
            &mut verifier,
        )
        .error_or_unreachable();
    assert!(matches!(denied, ManagedLifecycleError::ApprovalBoundary(_)));

    let bad_namespace = converge(
        &mut control,
        request_for("bad-unit", "systemd:unit:sshd.service", "active"),
        &mut executor,
        &mut verifier,
    )
    .error_or_unreachable();
    assert!(matches!(
        bad_namespace,
        ManagedLifecycleError::UnsupportedEffect(_)
    ));

    let bad_state = converge(
        &mut control,
        request("bad-state", "restarting"),
        &mut executor,
        &mut verifier,
    )
    .error_or_unreachable();
    assert!(matches!(
        bad_state,
        ManagedLifecycleError::UnsupportedEffect(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn stale_authoritative_evidence_fails_before_dispatch() {
    let database = TestDatabase::new();
    let mut control = open_control(database.path(), vec![stale_observation("inactive", 1)]);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    let mut verifier = ScriptedVerifier::new([]);
    let error = converge(
        &mut control,
        request("stale-evidence", "active"),
        &mut executor,
        &mut verifier,
    )
    .error_or_unreachable();
    assert!(error.to_string().contains("stale"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn executor_failure_becomes_indeterminate_and_never_redispatches() {
    let database = TestDatabase::new();
    let mut control = open_control(
        database.path(),
        vec![observation("inactive", 1), observation("inactive", 2)],
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::failure(calls.clone());
    let mut verifier = ScriptedVerifier::new([]);
    let desired = request("executor-failure", "active");

    let first = converge(&mut control, desired.clone(), &mut executor, &mut verifier)
        .error_or_unreachable();
    assert!(matches!(first, ManagedLifecycleError::Executor(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut retry_verifier =
        ScriptedVerifier::new([VerifierStep::Outcome(VerificationDisposition::Inconclusive)]);
    let retry =
        converge(&mut control, desired, &mut executor, &mut retry_verifier).error_or_unreachable();
    assert!(matches!(retry, ManagedLifecycleError::Indeterminate(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn verifier_transport_failure_never_commits_or_replays() {
    let database = TestDatabase::new();
    let mut control = open_control(
        database.path(),
        vec![observation("inactive", 1), observation("inactive", 2)],
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    let desired = request("verifier-failure", "active");
    let mut verifier = ScriptedVerifier::new([VerifierStep::Failure]);

    let first = converge(&mut control, desired.clone(), &mut executor, &mut verifier)
        .error_or_unreachable();
    assert!(matches!(first, ManagedLifecycleError::Verification(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut retry_verifier =
        ScriptedVerifier::new([VerifierStep::Outcome(VerificationDisposition::Inconclusive)]);
    let retry =
        converge(&mut control, desired, &mut executor, &mut retry_verifier).error_or_unreachable();
    assert!(matches!(retry, ManagedLifecycleError::Indeterminate(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn indeterminate_execution_never_blindly_replays() {
    let database = TestDatabase::new();
    let mut control = open_control(
        database.path(),
        vec![observation("inactive", 1), observation("inactive", 2)],
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor =
        ScriptedExecutor::outcome(ExecutionDisposition::Indeterminate, calls.clone());
    let desired = request("indeterminate-dispatch", "active");
    let mut verifier =
        ScriptedVerifier::new([VerifierStep::Outcome(VerificationDisposition::Inconclusive)]);

    let first = converge(&mut control, desired.clone(), &mut executor, &mut verifier)
        .error_or_unreachable();
    assert!(matches!(first, ManagedLifecycleError::Indeterminate(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut retry_verifier =
        ScriptedVerifier::new([VerifierStep::Outcome(VerificationDisposition::Inconclusive)]);
    let retry =
        converge(&mut control, desired, &mut executor, &mut retry_verifier).error_or_unreachable();
    assert!(matches!(retry, ManagedLifecycleError::Indeterminate(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn crash_restart_after_handoff_preserves_indeterminate_without_dispatch_reconstruction() {
    let database = TestDatabase::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let desired = request("restart-after-handoff", "active");

    {
        let mut control = open_control(
            database.path(),
            vec![observation("inactive", 1), observation("inactive", 2)],
        );
        let mut executor = ScriptedExecutor::failure(calls.clone());
        let mut verifier = ScriptedVerifier::new([]);
        let error = converge(&mut control, desired.clone(), &mut executor, &mut verifier)
            .error_or_unreachable();
        assert!(matches!(error, ManagedLifecycleError::Executor(_)));
    }

    let mut restarted = open_control(database.path(), vec![]);
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    let mut verifier =
        ScriptedVerifier::new([VerifierStep::Outcome(VerificationDisposition::Inconclusive)]);
    let error =
        converge(&mut restarted, desired, &mut executor, &mut verifier).error_or_unreachable();
    assert!(matches!(error, ManagedLifecycleError::Indeterminate(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn not_satisfied_reprepare_is_consumed_by_explicit_recovery_invocation() {
    let database = TestDatabase::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let desired = request("not-satisfied", "active");
    let mut control = open_control(
        database.path(),
        vec![
            observation("inactive", 1),
            observation("inactive", 2),
            observation("inactive", 3),
            observation("active", 4),
            observation("active", 5),
        ],
    );
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    let mut verifier =
        ScriptedVerifier::new([VerifierStep::Outcome(VerificationDisposition::NotSatisfied)]);

    let first = converge(&mut control, desired.clone(), &mut executor, &mut verifier)
        .error_or_unreachable();
    assert!(matches!(
        first,
        ManagedLifecycleError::VerificationNotSatisfied(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut recovery_verifier = ScriptedVerifier::new([
        VerifierStep::Outcome(VerificationDisposition::NotSatisfied),
        VerifierStep::Outcome(VerificationDisposition::Satisfied),
        VerifierStep::Outcome(VerificationDisposition::Satisfied),
    ]);
    let recovered = value(converge(
        &mut control,
        desired,
        &mut executor,
        &mut recovery_verifier,
    ));
    assert_complete(&recovered);
    assert!(recovered.recovered);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn conflicting_recovery_blocks_instead_of_reusing_authority() {
    let database = TestDatabase::new();
    let mut control = open_control(
        database.path(),
        vec![
            observation("inactive", 1),
            observation("inactive", 2),
            observation("failed", 3),
        ],
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor =
        ScriptedExecutor::outcome(ExecutionDisposition::Indeterminate, calls.clone());
    let desired = request("conflicting-recovery", "active");
    let mut verifier =
        ScriptedVerifier::new([VerifierStep::Outcome(VerificationDisposition::Inconclusive)]);
    let first = converge(&mut control, desired.clone(), &mut executor, &mut verifier)
        .error_or_unreachable();
    assert!(matches!(first, ManagedLifecycleError::Indeterminate(_)));

    let mut retry_verifier =
        ScriptedVerifier::new([VerifierStep::Outcome(VerificationDisposition::NotSatisfied)]);
    let blocked =
        converge(&mut control, desired, &mut executor, &mut retry_verifier).error_or_unreachable();
    assert!(matches!(blocked, ManagedLifecycleError::TerminalState(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn reconciliation_failure_does_not_undo_commit_or_replay_execution() {
    let database = TestDatabase::new();
    let mut control = open_control(
        database.path(),
        vec![
            observation("inactive", 1),
            observation("inactive", 2),
            observation("active", 3),
            observation("active", 4),
        ],
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ScriptedExecutor::outcome(ExecutionDisposition::Dispatched, calls.clone());
    let desired = request("reconciliation-failure", "active");
    let mut verifier = ScriptedVerifier::new([
        VerifierStep::Outcome(VerificationDisposition::Satisfied),
        VerifierStep::Outcome(VerificationDisposition::NotSatisfied),
    ]);
    let first = converge(&mut control, desired.clone(), &mut executor, &mut verifier)
        .error_or_unreachable();
    assert!(matches!(first, ManagedLifecycleError::Reconciliation(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut retry_verifier = ScriptedVerifier::new([
        VerifierStep::Outcome(VerificationDisposition::Satisfied),
        VerifierStep::Outcome(VerificationDisposition::Satisfied),
    ]);
    let recovered = value(converge(
        &mut control,
        desired,
        &mut executor,
        &mut retry_verifier,
    ));
    assert!(recovered.recovered);
    assert_eq!(recovered.final_state, "committed");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
