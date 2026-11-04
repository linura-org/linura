//! SQLite + simulated observer/approval/effect tests. These do not qualify a
//! native compositor, original kernel witnesses, PAM or independent restoration.
use super::*;
use linura_control::{
    AuthorizedOriginalDisplayRestoration, OriginalDisplayRestorationPort,
    OriginalDisplayRestorationRequest,
};
use linura_core::DisplayRecoveryScope;
use linura_observation::{DisplayObservationFacts, DisplayOriginalProtectionFacts};
use linura_transaction::TransactionStore;

fn input(original: &PlanDesiredStateRequest) -> OriginalDisplayRestorationRequest {
    OriginalDisplayRestorationRequest {
        operation_id: "restore-original-once".into(),
        original_request: original.request_id.clone(),
        replacement: value(DisplayTopologyId::new(
            s17_managed_lock::lock_id().epoch().clone(),
            "seat0",
            value(CompositorInvocationId::new(
                "22223344-1234-4567-89ab-0123456789ab",
            )),
            1,
        )),
        lock: s17_managed_lock::lock_id(),
        reason: SemanticReason {
            summary: "Recover the original display arrangement".into(),
            intent_ids: vec![],
            requirement_ids: vec![],
            capability_ids: vec![],
        },
    }
}
fn replacement_previews(
    machine: &Arc<Mutex<Machine>>,
    original: &PlanDesiredStateRequest,
    input: &OriginalDisplayRestorationRequest,
) -> PlanPreviewControl {
    let (baseline, _, old_inventory, caps) = layouts();
    let metadata = BTreeMap::from([(
        old_inventory.outputs()[0].clone(),
        value(DisplayRecoveryMetadata::new(
            false,
            "a".repeat(64),
            "b".repeat(64),
        )),
    )]);
    let historical = value(display_recovery_observation_attributes(
        &old_inventory,
        &caps,
        &baseline,
        &std::collections::BTreeSet::from([old_inventory.outputs()[0].clone()]),
        &metadata,
    ));
    let mut old = s17_managed_lock::session_observation(1);
    old.provider = value(ProviderId::new("hyprland"));
    old.capability = value(CapabilityId::new("display.outputs.observe"));
    old.resource = value(baseline.topology().resource_id());
    old.attributes = historical;
    let facts = value(DisplayObservationFacts::from_envelope(
        &old,
        baseline.topology(),
        now_unix_ms(),
    ));
    let m = machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"));
    let binding = m
        .binding
        .as_ref()
        .unwrap_or_else(|| unreachable!("original dispatched"));
    let scope = value(DisplayRecoveryScope::new(
        &binding.dispatch_digest.to_hex(),
        input.replacement.clone(),
    ));
    let protection = value(DisplayOriginalProtectionFacts::new(
        scope.clone(),
        original.desired_state["layout"].clone(),
        binding.transaction_id.clone(),
        "e".repeat(64),
        value(linura_provider_sdk::display_baseline_guard(&facts)).to_hex(),
        "f".repeat(64),
        1,
        m.deadline,
        metadata,
    ));
    drop(m);
    let mut root = old.clone();
    root.provider = value(ProviderId::new("hyprland-recovery"));
    root.capability = value(CapabilityId::new("display.original-protection.observe"));
    root.resource = value(scope.resource_id());
    root.attributes = protection.attributes();
    let output = value(DisplayOutputId::new(input.replacement.clone(), 19, 3));
    let inventory = value(DisplayOutputSet::new(
        input.replacement.clone(),
        vec![output.clone()],
    ));
    let mode = value(DisplayMode::new(1920, 1080, 60000));
    let caps = vec![value(NativeOutputCapabilities::new(
        output.clone(),
        vec![mode],
        false,
    ))];
    let layout = value(DisplayLayout::new(
        &inventory,
        &caps,
        vec![DisplayOutputLayout::Enabled {
            output: output.clone(),
            mode,
            scale: value(DisplayScale::new(1000)),
            transform: DisplayTransform::Normal,
            x: 100,
            y: 0,
            mirror: None,
        }],
    ));
    let mut native = old;
    native.resource = value(input.replacement.resource_id());
    native.attributes = value(display_recovery_observation_attributes(
        &inventory,
        &caps,
        &layout,
        &std::collections::BTreeSet::from([output.clone()]),
        &BTreeMap::from([(
            output,
            value(DisplayRecoveryMetadata::new(
                false,
                "a".repeat(64),
                "b".repeat(64),
            )),
        )]),
    ));
    let mut coverage = s17_managed_lock::lock_observation(false, 1);
    coverage.capability = value(CapabilityId::new(
        linura_observation::DISPLAY_COVERAGE_CAPABILITY,
    ));
    coverage.attributes.extend([
        (
            "display_topology".into(),
            ObservedValue::Text(native.resource.as_str().into()),
        ),
        (
            "observed_outputs".into(),
            ObservedValue::Text("19:3".into()),
        ),
        ("covered_outputs".into(), ObservedValue::Text(String::new())),
    ]);
    let mut coordinator = ObservationCoordinator::new();
    for template in [
        root,
        native,
        coverage,
        s17_managed_lock::session_observation(1),
    ] {
        value(coordinator.register_observer(Box::new(LiveFixtureObserver {
            machine: machine.clone(),
            template,
            replacement: true,
        })));
    }
    PlanPreviewControl::new(coordinator)
}
fn prepare_original(
    database: &TestDatabase,
    machine: &Arc<Mutex<Machine>>,
) -> (PlanDesiredStateRequest, OriginalDisplayRestorationRequest) {
    let original = display_request("original-before-loss");
    let mut control = open(database.path(), machine, 0);
    value(control.begin_display_layout(
        principal(),
        actor(true),
        original.clone(),
        &approval(),
        &mut Port(machine.clone()),
        &mut Verifier(machine.clone()),
    ));
    let input = input(&original);
    (original, input)
}
#[derive(Debug)]
struct Executor(Arc<Mutex<Machine>>);
impl OriginalDisplayRestorationPort for Executor {
    fn dispatch_original(
        &mut self,
        restoration: AuthorizedOriginalDisplayRestoration,
    ) -> Result<ExecutionOutcome, String> {
        let (authorization, material, deadline) = restoration.into_executor_request();
        assert!(deadline > now_unix_ms() && deadline - now_unix_ms() <= 15_000);
        let (effect, binding) = authorization.into_executor_request();
        assert_eq!(
            value(linura_provider_sdk::display_restoration_effect(&material)),
            effect
        );
        value(binding.validate_for(&effect));
        assert_eq!(effect.provider.as_str(), "hyprland-recovery");
        let mut m = self
            .0
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        m.restoration_calls += 1;
        if m.restoration_outcome == 1 {
            return Err("simulated lost native reply after grant consumption".into());
        }
        ExecutionOutcome::new(
            if m.restoration_outcome == 2 {
                ExecutionDisposition::RejectedBeforeDispatch
            } else {
                ExecutionDisposition::Dispatched
            },
            if m.restoration_outcome == 3 {
                linura_provider_sdk::ComponentDigest::from_bytes([9; 32])
            } else {
                binding.dispatch_digest
            },
            "simulated native call; not independent verification",
        )
        .map_err(|e| e.to_string())
    }
}
#[test]
fn original_restoration_is_one_use_across_restart_and_never_commits_from_a_reply() {
    for outcome in [0, 1, 2, 3] {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine {
            restoration_outcome: outcome,
            ..Machine::default()
        }));
        let (original, input) = prepare_original(&database, &machine);
        let previews = replacement_previews(&machine, &original, &input);
        let mut control = open_with_previews(database.path(), &machine, 0, previews);
        let result = control.begin_original_display_restoration(
            principal(),
            actor(true),
            input.clone(),
            &approval(),
            &mut Executor(machine.clone()),
        );
        assert_eq!(result.is_err(), outcome == 3);
        let receipt = value(control.begin_original_display_restoration(
            principal(),
            actor(true),
            input.clone(),
            &Deny,
            &mut Executor(machine.clone()),
        ));
        assert!(receipt.dispatch_digest.is_some());
        drop(control);
        // No live replacement facts are available on restart. A duplicate is
        // retained uncertainty, not a fresh approval, native call or recovery.
        let mut control = open(database.path(), &machine, 0);
        assert_eq!(
            value(control.begin_original_display_restoration(
                principal(),
                actor(true),
                input.clone(),
                &Deny,
                &mut Executor(machine.clone())
            )),
            receipt
        );
        let mut changed = input.clone();
        changed.reason.summary.push_str(" changed");
        assert!(
            control
                .begin_original_display_restoration(
                    principal(),
                    actor(true),
                    changed,
                    &approval(),
                    &mut Executor(machine.clone())
                )
                .is_err()
        );
        for (caller, provenance) in [
            (
                value(AuthenticatedPrincipal::new("unix:uid:1001")),
                actor(true),
            ),
            (principal(), actor(false)),
        ] {
            assert!(
                control
                    .begin_original_display_restoration(
                        caller,
                        provenance,
                        input.clone(),
                        &approval(),
                        &mut Executor(machine.clone())
                    )
                    .is_err()
            );
        }
        let (_, verifier) = authority_material();
        let store = value(SqliteTransactionStore::open(
            database.path(),
            verifier,
            value(SqliteIntegrityKey::new(fixture_key(5))),
        ));
        assert_eq!(
            value(store.snapshot(&receipt.transaction_id)).state,
            linura_transaction::TransactionState::Indeterminate
        );
        let m = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_eq!(m.restoration_calls, 1);
        assert_eq!(m.applies, 1);
        assert_eq!(m.decisions, 0);
    }
}
#[derive(Debug)]
struct DriftApproval(Arc<Mutex<Machine>>, bool);
impl ManagedApprovalAuthorizer for DriftApproval {
    fn authorize(
        &self,
        challenge: &ManagedApprovalChallenge,
    ) -> Result<TrustedHumanApproval, String> {
        let mut m = self
            .0
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        if self.1 {
            m.original_protection_lost = true;
        } else {
            m.native_base_drift = true;
        }
        drop(m);
        approval().authorize(challenge)
    }
}
#[test]
fn restoration_denial_or_drift_during_interaction_never_prepares_an_effect() {
    for case in [0, 1, 2] {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (original, input) = prepare_original(&database, &machine);
        let previews = replacement_previews(&machine, &original, &input);
        let mut control = open_with_previews(database.path(), &machine, 0, previews);
        let drift = DriftApproval(machine.clone(), case == 2);
        let authorizer: &dyn ManagedApprovalAuthorizer = if case == 0 { &Deny } else { &drift };
        assert!(
            control
                .begin_original_display_restoration(
                    principal(),
                    actor(true),
                    input,
                    authorizer,
                    &mut Executor(machine.clone())
                )
                .is_err()
        );
        assert_eq!(
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .restoration_calls,
            0
        );
    }
}
#[test]
fn restoration_persistence_failures_and_missing_readback_cannot_dispatch() {
    for fail_at in [1, 2, 3, 0] {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (original, input) = prepare_original(&database, &machine);
        let previews = replacement_previews(&machine, &original, &input);
        if fail_at == 0 {
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .lose_restoration_dispatch = true;
        }
        let mut control = open_with_previews(database.path(), &machine, fail_at, previews);
        assert!(
            control
                .begin_original_display_restoration(
                    principal(),
                    actor(true),
                    input.clone(),
                    &approval(),
                    &mut Executor(machine.clone())
                )
                .is_err()
        );
        drop(control);
        let mut control = open(database.path(), &machine, 0);
        // Retained Prepared/Indeterminate state is never transparently replayed.
        let _retained = control.begin_original_display_restoration(
            principal(),
            actor(true),
            input,
            &approval(),
            &mut Executor(machine.clone()),
        );
        assert_eq!(
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .restoration_calls,
            0
        );
    }
}
