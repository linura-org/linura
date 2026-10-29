//! Deterministic managed-controller and SQLite restart/fault fixtures.
//! NativeApi labels are simulated here; these are not compositor qualification.
use super::*;
use linura_control::{
    AuthorizedDisplayContinuation, DisplayContinuationAction, DisplayDecisionAuthorizer,
    DisplayDecisionChallenge, DisplayLayoutPlanRequest, DisplayTransactionPort,
    IndependentDisplayVerifier, ManagedApprovalAuthorizer, ManagedApprovalChallenge,
    TrustedDisplayDecision,
};
use linura_core::{
    CompositorInvocationId, DisplayLayout, DisplayMode, DisplayOutputId, DisplayOutputLayout,
    DisplayOutputSet, DisplayScale, DisplayTopologyId, DisplayTransform, NativeOutputCapabilities,
};
use linura_observation::display_observation_attributes;
use linura_protocol::DisplayLayoutState;
use linura_provider_sdk::ExecutionBinding;
use linura_transaction::{ApprovedRequestJournal, RetainedRequest, TransactionStoreError};

#[derive(Debug, Default)]
struct Machine {
    desired: bool,
    state: Option<&'static str>,
    binding: Option<ExecutionBinding>,
    deadline: u64,
    applies: usize,
    decisions: usize,
    lose_apply_reply: bool,
    lose_decision_reply: bool,
    sequence: u64,
    wrong_attempt: bool,
    journal_failures: usize,
}
fn layouts() -> (
    DisplayLayout,
    DisplayLayout,
    DisplayOutputSet,
    Vec<NativeOutputCapabilities>,
) {
    let topology = value(DisplayTopologyId::new(
        s17_managed_lock::lock_id().epoch().clone(),
        "seat0",
        value(CompositorInvocationId::new(
            "11223344-1234-4567-89ab-0123456789ab",
        )),
        7,
    ));
    let output = value(DisplayOutputId::new(topology.clone(), 1, 1));
    let inventory = value(DisplayOutputSet::new(topology, vec![output.clone()]));
    let mode = value(DisplayMode::new(1920, 1080, 60000));
    let caps = vec![value(NativeOutputCapabilities::new(
        output.clone(),
        vec![mode],
        false,
    ))];
    let layout = |x| {
        value(DisplayLayout::new(
            &inventory,
            &caps,
            vec![DisplayOutputLayout::Enabled {
                output: output.clone(),
                mode,
                scale: value(DisplayScale::new(1000)),
                transform: DisplayTransform::Normal,
                x,
                y: 0,
                mirror: None,
            }],
        ))
    };
    (layout(0), layout(100), inventory, caps)
}
fn display_request(operation: &str) -> PlanDesiredStateRequest {
    let (baseline, layout, _, _) = layouts();
    let mut request = value(
        DisplayLayoutPlanRequest {
            request_id: value(RequestId::new("request:v010:display-layout:placeholder")),
            baseline,
            layout,
            lock: s17_managed_lock::lock_id(),
            reason: SemanticReason {
                summary: "Place the display at the requested position".into(),
                intent_ids: vec![value(IntentId::new("intent:v010:s21:display-layout"))],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
        }
        .desired_request(),
    );
    request.request_id = value(managed_request_id(operation, &request));
    request
}
struct LiveFixtureObserver {
    machine: Arc<Mutex<Machine>>,
    template: ObservationEnvelope,
}
impl Observer for LiveFixtureObserver {
    fn observer_id(&self) -> ProviderId {
        self.template.provider.clone()
    }
    fn observation_capabilities(&self) -> Vec<Capability> {
        vec![Capability {
            id: self.template.capability.clone(),
            support: SupportLevel::Supported,
            provider: Some(self.template.provider.clone()),
            reason: None,
        }]
    }
    fn health(&self) -> ProviderHealth {
        ProviderHealth {
            provider: self.observer_id(),
            availability: ProviderAvailability::Available,
            reason: None,
        }
    }
    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        Ok(vec![self.template.resource.clone()])
    }
    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if resource != &self.template.resource || capability != &self.template.capability {
            return Err(ProviderError::Unsupported("fixture route mismatch".into()));
        }
        let mut machine = self
            .machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        machine.sequence += 1;
        let mut sample = self.template.clone();
        sample.observed_at_unix_ms = now_unix_ms();
        sample.sequence = machine.sequence;
        if machine.desired && sample.provider.as_str() == "hyprland" {
            sample.attributes.insert(
                "layout".into(),
                ObservedValue::Text(value(layouts().1.canonical_text())),
            );
        }
        Ok(sample)
    }
}
fn previews(machine: &Arc<Mutex<Machine>>) -> PlanPreviewControl {
    let (baseline, _, inventory, caps) = layouts();
    let mut display = s17_managed_lock::session_observation(1);
    display.provider = value(ProviderId::new("hyprland"));
    display.resource = value(baseline.topology().resource_id());
    display.capability = value(CapabilityId::new("display.outputs.observe"));
    display.attributes = value(display_observation_attributes(
        &inventory,
        &caps,
        &baseline,
        &std::collections::BTreeSet::from([inventory.outputs()[0].clone()]),
    ));
    let mut coverage = s17_managed_lock::lock_observation(false, 1);
    coverage.capability = value(CapabilityId::new(
        linura_observation::DISPLAY_COVERAGE_CAPABILITY,
    ));
    coverage.attributes.extend([
        (
            "display_topology".into(),
            ObservedValue::Text(display.resource.as_str().into()),
        ),
        ("observed_outputs".into(), ObservedValue::Text("1:1".into())),
        ("covered_outputs".into(), ObservedValue::Text(String::new())),
    ]);
    let mut coordinator = ObservationCoordinator::new();
    for template in [display, s17_managed_lock::session_observation(1), coverage] {
        value(coordinator.register_observer(Box::new(LiveFixtureObserver {
            machine: machine.clone(),
            template,
        })));
    }
    PlanPreviewControl::new(coordinator)
}
#[derive(Debug)]
struct FailingJournal {
    inner: linura_persistence_sqlite::SqliteApprovedRequestJournal,
    machine: Arc<Mutex<Machine>>,
    fail_at: usize,
    writes: usize,
}
impl ApprovedRequestJournal for FailingJournal {
    fn retain(&mut self, record: &RetainedRequest) -> Result<(), TransactionStoreError> {
        self.writes += 1;
        if self.writes == self.fail_at {
            self.machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .journal_failures += 1;
            return Err(TransactionStoreError::CapacityExceeded);
        }
        self.inner.retain(record)
    }
    fn load(
        &self,
        principal: &PrincipalId,
        request: &RequestId,
    ) -> Result<RetainedRequest, TransactionStoreError> {
        self.inner.load(principal, request)
    }
    fn integrity_check(&self) -> Result<(), TransactionStoreError> {
        self.inner.integrity_check()
    }
}
fn open(
    database: &Path,
    machine: &Arc<Mutex<Machine>>,
    fail_at: usize,
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
    value(
        value(ManagedLifecycleControl::new(
            previews(machine),
            store,
            signer,
        ))
        .with_request_journal(Box::new(FailingJournal {
            inner: journal,
            machine: machine.clone(),
            fail_at,
            writes: 0,
        })),
    )
}
#[derive(Debug)]
struct Port(Arc<Mutex<Machine>>);
impl DisplayTransactionPort for Port {
    fn dispatch_layout(
        &mut self,
        authorization: AuthorizedEffect,
        request: &PlanDesiredStateRequest,
        deadline: u64,
    ) -> Result<ExecutionOutcome, String> {
        let (effect, binding) = authorization.into_executor_request();
        if effect != linura_provider_sdk::display_layout_effect(&request.desired_state["layout"])? {
            return Err("fixture substituted intent".into());
        }
        binding.validate_for(&effect).map_err(|e| e.to_string())?;
        let mut m = self
            .0
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        m.applies += 1;
        m.desired = true;
        m.state = Some("pending");
        m.deadline = deadline;
        m.binding = Some(binding.clone());
        if m.lose_apply_reply {
            return Err("simulated acknowledgement loss after effect".into());
        }
        ExecutionOutcome::new(
            ExecutionDisposition::Dispatched,
            binding.dispatch_digest,
            "simulated dispatch; independent verification required",
        )
        .map_err(|e| e.to_string())
    }
    fn observe_attempt(
        &mut self,
        query: &linura_control::DisplayAttemptQuery<'_>,
    ) -> Result<ObservationEnvelope, String> {
        let request = query.request();
        let transaction = query.transaction_id();
        // Ensure a strictly post-dispatch native sample at millisecond precision.
        std::thread::sleep(std::time::Duration::from_millis(2));
        let mut m = self
            .0
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        let binding = m.binding.clone().ok_or("simulated native attempt absent")?;
        if transaction != binding.transaction_id
            || query.dispatch_digest() != binding.dispatch_digest.to_hex()
            || query.deadline_unix_ms() != m.deadline
        {
            return Err("fixture transaction mismatch".into());
        }
        m.sequence += 1;
        let mut sample = ObservationEnvelope {
            provider: value(ProviderId::new("hyprland")),
            resource: value(ResourceId::new(format!("display:attempt:{transaction}"))),
            capability: value(CapabilityId::new("display.layout-attempt.observe")),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: now_unix_ms(),
            valid_for_ms: 2000,
            sequence: m.sequence,
            attributes: BTreeMap::from([
                (
                    "lock_resource".into(),
                    ObservedValue::Text(
                        value(s17_managed_lock::lock_id().resource_id())
                            .as_str()
                            .into(),
                    ),
                ),
                (
                    "topology_resource".into(),
                    ObservedValue::Text(request.resource.as_str().into()),
                ),
                (
                    "effect_digest".into(),
                    ObservedValue::Text(binding.effect_digest.to_hex()),
                ),
                (
                    "dispatch_digest".into(),
                    ObservedValue::Text(binding.dispatch_digest.to_hex()),
                ),
                ("deadline_unix_ms".into(), ObservedValue::U64(m.deadline)),
                (
                    "state".into(),
                    ObservedValue::Text(m.state.ok_or("simulated native attempt absent")?.into()),
                ),
            ]),
        };
        if m.wrong_attempt {
            sample.attributes.insert(
                "dispatch_digest".into(),
                ObservedValue::Text("f".repeat(64)),
            );
        }
        Ok(sample)
    }
    fn continue_layout(
        &mut self,
        continuation: AuthorizedDisplayContinuation,
    ) -> Result<(), String> {
        let mut m = self
            .0
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        let binding = m.binding.as_ref().ok_or("simulated attempt absent")?;
        if continuation.transaction_id() != binding.transaction_id
            || continuation.dispatch_digest() != binding.dispatch_digest.to_hex()
            || m.state != Some("pending")
        {
            return Err("fixture continuation scope mismatch".into());
        }
        assert!(
            continuation
                .protected_decision_digest()
                .starts_with("sha256:")
        );
        m.decisions += 1;
        match continuation.action() {
            DisplayContinuationAction::Confirm => m.state = Some("confirmed"),
            DisplayContinuationAction::Revert => {
                m.state = Some("restored");
                m.desired = false;
            }
        }
        if m.lose_decision_reply {
            Err("simulated decision reply loss".into())
        } else {
            Ok(())
        }
    }
}
#[derive(Debug)]
struct Verifier(Arc<Mutex<Machine>>);
impl IndependentDisplayVerifier for Verifier {
    fn verify_layout(
        &mut self,
        _: &PlanDesiredStateRequest,
        restoration: bool,
        _: u64,
    ) -> Result<VerificationOutcome, String> {
        let m = self
            .0
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        VerificationOutcome::new(
            if m.desired != restoration {
                VerificationDisposition::Satisfied
            } else {
                VerificationDisposition::NotSatisfied
            },
            "simulated independent layout check",
        )
        .map_err(|e| e.to_string())
    }
}
#[derive(Debug)]
struct Deny;
impl ManagedApprovalAuthorizer for Deny {
    fn authorize(&self, _: &ManagedApprovalChallenge) -> Result<TrustedHumanApproval, String> {
        Err("simulated native denial".into())
    }
}

// Simulated trusted native boundary, deliberately separate from the apply
// approval fixture. These tests do not claim a real protected input proof.
#[derive(Clone, Copy, Debug)]
enum DecisionBehavior {
    Approve,
    Deny,
    ForeignPrincipal,
    ChangeAttempt,
    DriftLayout,
}
#[derive(Debug)]
struct Decision {
    machine: Arc<Mutex<Machine>>,
    behavior: DecisionBehavior,
    calls: AtomicUsize,
}
impl Decision {
    fn approve(machine: &Arc<Mutex<Machine>>) -> Self {
        Self::with_behavior(machine, DecisionBehavior::Approve)
    }
    fn with_behavior(machine: &Arc<Mutex<Machine>>, behavior: DecisionBehavior) -> Self {
        Self {
            machine: machine.clone(),
            behavior,
            calls: AtomicUsize::new(0),
        }
    }
}
impl DisplayDecisionAuthorizer for Decision {
    fn authorize_decision(
        &self,
        challenge: &DisplayDecisionChallenge,
    ) -> Result<TrustedDisplayDecision, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(challenge.principal().as_str(), "unix:uid:1000");
        assert!(challenge.deadline_unix_ms() > now_unix_ms());
        assert!(challenge.request().desired_state.contains_key("layout"));
        assert!(challenge.digest().starts_with("sha256:"));
        let mut m = self
            .machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_eq!(
            challenge.transaction_id(),
            m.binding
                .as_ref()
                .unwrap_or_else(|| unreachable!("no dispatch"))
                .transaction_id
        );
        let principal = match self.behavior {
            DecisionBehavior::Deny => return Err("simulated protected cancellation".into()),
            DecisionBehavior::ForeignPrincipal => value(PrincipalId::new("unix:uid:1001")),
            DecisionBehavior::ChangeAttempt => {
                m.state = Some("restoring");
                challenge.principal().clone()
            }
            DecisionBehavior::DriftLayout => {
                m.desired = false;
                challenge.principal().clone()
            }
            DecisionBehavior::Approve => challenge.principal().clone(),
        };
        Ok(TrustedDisplayDecision::from_protected_boundary(
            principal, challenge,
        ))
    }
}

#[test]
fn protected_denial_and_foreign_proof_cannot_keep_or_revert_or_reserve_a_decision() {
    for action in [
        DisplayContinuationAction::Confirm,
        DisplayContinuationAction::Revert,
    ] {
        for behavior in [DecisionBehavior::Deny, DecisionBehavior::ForeignPrincipal] {
            let database = TestDatabase::new();
            let machine = Arc::new(Mutex::new(Machine::default()));
            let mut port = Port(machine.clone());
            let mut verifier = Verifier(machine.clone());
            let request = display_request("protected-denial");
            let mut control = open(database.path(), &machine, 0);
            value(control.begin_display_layout(
                principal(),
                actor(true),
                request.clone(),
                &approval(),
                &mut port,
                &mut verifier,
            ));
            let denied = Decision::with_behavior(&machine, behavior);
            assert!(
                control
                    .decide_display_layout(
                        principal(),
                        actor(true),
                        &request.request_id,
                        action,
                        &denied,
                        &mut port,
                        &mut verifier
                    )
                    .is_err()
            );
            assert_eq!(denied.calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                    .decisions,
                0
            );
            // A failed interaction did not reserve a continuation. A separately
            // completed, fresh human decision can still continue this attempt.
            let accepted = Decision::approve(&machine);
            value(control.decide_display_layout(
                principal(),
                actor(true),
                &request.request_id,
                action,
                &accepted,
                &mut port,
                &mut verifier,
            ));
            assert_eq!(accepted.calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                    .decisions,
                1
            );
            // A durable decision is observe-only even with a denying boundary.
            value(control.decide_display_layout(
                principal(),
                actor(true),
                &request.request_id,
                action,
                &denied,
                &mut port,
                &mut verifier,
            ));
            assert_eq!(denied.calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn native_attempt_and_layout_are_reverified_after_protected_interaction() {
    for behavior in [
        DecisionBehavior::ChangeAttempt,
        DecisionBehavior::DriftLayout,
    ] {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let mut port = Port(machine.clone());
        let mut verifier = Verifier(machine.clone());
        let request = display_request("protected-drift");
        let mut control = open(database.path(), &machine, 0);
        value(control.begin_display_layout(
            principal(),
            actor(true),
            request.clone(),
            &approval(),
            &mut port,
            &mut verifier,
        ));
        let result = control.decide_display_layout(
            principal(),
            actor(true),
            &request.request_id,
            DisplayContinuationAction::Confirm,
            &Decision::with_behavior(&machine, behavior),
            &mut port,
            &mut verifier,
        );
        assert!(
            result.is_err()
                || matches!(result, Ok(receipt) if receipt.state == DisplayLayoutState::Indeterminate)
        );
        assert_eq!(
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .decisions,
            0
        );
    }
}

#[derive(Debug, Default)]
struct StaleDecision(Mutex<Option<TrustedDisplayDecision>>);
impl DisplayDecisionAuthorizer for StaleDecision {
    fn authorize_decision(
        &self,
        challenge: &DisplayDecisionChallenge,
    ) -> Result<TrustedDisplayDecision, String> {
        let mut retained = self
            .0
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        if let Some(proof) = retained.take() {
            return Ok(proof);
        }
        *retained = Some(TrustedDisplayDecision::from_protected_boundary(
            challenge.principal().clone(),
            challenge,
        ));
        Err("simulated lost protected interaction reply".into())
    }
}

#[test]
fn a_retained_human_proof_cannot_authorize_a_new_probe_or_opposite_decision() {
    for second_action in [
        DisplayContinuationAction::Confirm,
        DisplayContinuationAction::Revert,
    ] {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let mut port = Port(machine.clone());
        let mut verifier = Verifier(machine.clone());
        let request = display_request("protected-replay");
        let mut control = open(database.path(), &machine, 0);
        value(control.begin_display_layout(
            principal(),
            actor(true),
            request.clone(),
            &approval(),
            &mut port,
            &mut verifier,
        ));
        let stale = StaleDecision::default();
        assert!(
            control
                .decide_display_layout(
                    principal(),
                    actor(true),
                    &request.request_id,
                    DisplayContinuationAction::Confirm,
                    &stale,
                    &mut port,
                    &mut verifier
                )
                .is_err()
        );
        assert!(
            control
                .decide_display_layout(
                    principal(),
                    actor(true),
                    &request.request_id,
                    second_action,
                    &stale,
                    &mut port,
                    &mut verifier
                )
                .is_err()
        );
        assert_eq!(
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .decisions,
            0
        );
    }
}

#[test]
fn lost_apply_reply_and_restart_never_reapply_then_confirmation_commits_once() {
    let database = TestDatabase::new();
    let machine = Arc::new(Mutex::new(Machine {
        lose_apply_reply: true,
        lose_decision_reply: true,
        ..Machine::default()
    }));
    let mut port = Port(machine.clone());
    let mut verifier = Verifier(machine.clone());
    let request = display_request("lost-reply");
    let mut control = open(database.path(), &machine, 0);
    assert_eq!(
        value(control.begin_display_layout(
            principal(),
            actor(true),
            request.clone(),
            &approval(),
            &mut port,
            &mut verifier
        ))
        .state,
        DisplayLayoutState::AwaitingConfirmation
    );
    drop(control);
    let mut control = open(database.path(), &machine, 0);
    assert_eq!(
        value(control.begin_display_layout(
            principal(),
            actor(true),
            request.clone(),
            &Deny,
            &mut port,
            &mut verifier
        ))
        .state,
        DisplayLayoutState::AwaitingConfirmation
    );
    assert_eq!(
        value(control.decide_display_layout(
            principal(),
            actor(true),
            &request.request_id,
            DisplayContinuationAction::Confirm,
            &Decision::approve(&machine),
            &mut port,
            &mut verifier
        ))
        .state,
        DisplayLayoutState::Confirmed
    );
    drop(control);
    let mut control = open(database.path(), &machine, 0);
    assert_eq!(
        value(control.decide_display_layout(
            principal(),
            actor(true),
            &request.request_id,
            DisplayContinuationAction::Revert,
            &Decision::approve(&machine),
            &mut port,
            &mut verifier
        ))
        .state,
        DisplayLayoutState::Confirmed
    );
    let m = machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"));
    assert_eq!((m.applies, m.decisions), (1, 1));
}

#[test]
fn autonomous_restoration_reconciles_after_restart_without_any_continuation() {
    let database = TestDatabase::new();
    let machine = Arc::new(Mutex::new(Machine::default()));
    let mut port = Port(machine.clone());
    let mut verifier = Verifier(machine.clone());
    let request = display_request("watchdog");
    let mut control = open(database.path(), &machine, 0);
    value(control.begin_display_layout(
        principal(),
        actor(true),
        request.clone(),
        &approval(),
        &mut port,
        &mut verifier,
    ));
    {
        let mut m = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        m.state = Some("restored");
        m.desired = false;
    }
    drop(control);
    let mut control = open(database.path(), &machine, 0);
    assert_eq!(
        value(control.display_layout_status(
            principal(),
            actor(true),
            &request.request_id,
            &mut port,
            &mut verifier
        ))
        .state,
        DisplayLayoutState::Restored
    );
    assert_eq!(
        value(control.begin_display_layout(
            principal(),
            actor(true),
            request,
            &Deny,
            &mut port,
            &mut verifier
        ))
        .state,
        DisplayLayoutState::Restored
    );
    let m = machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"));
    assert_eq!((m.applies, m.decisions), (1, 0));
}

#[test]
fn every_preeffect_journal_failure_prevents_native_dispatch() {
    for fail_at in 1..=3 {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let mut port = Port(machine.clone());
        let mut verifier = Verifier(machine.clone());
        let request = display_request("journal-fault");
        let mut control = open(database.path(), &machine, fail_at);
        assert!(
            control
                .begin_display_layout(
                    principal(),
                    actor(true),
                    request.clone(),
                    &approval(),
                    &mut port,
                    &mut verifier
                )
                .is_err()
        );
        assert_eq!(
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .applies,
            0
        );
        assert_eq!(
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .journal_failures,
            1
        );
        drop(control);
        let mut control = open(database.path(), &machine, 0);
        // Only failures before prepare can accept a newly authorized invocation.
        if fail_at > 1 {
            let _ = control.begin_display_layout(
                principal(),
                actor(true),
                request,
                &Deny,
                &mut port,
                &mut verifier,
            );
            assert_eq!(
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                    .applies,
                0
            );
        }
    }
}

#[test]
fn decision_durability_loss_cannot_reach_native_confirmation() {
    let database = TestDatabase::new();
    let machine = Arc::new(Mutex::new(Machine::default()));
    let mut port = Port(machine.clone());
    let mut verifier = Verifier(machine.clone());
    let request = display_request("decision-fault");
    let mut control = open(database.path(), &machine, 4);
    value(control.begin_display_layout(
        principal(),
        actor(true),
        request.clone(),
        &approval(),
        &mut port,
        &mut verifier,
    ));
    assert!(
        control
            .decide_display_layout(
                principal(),
                actor(true),
                &request.request_id,
                DisplayContinuationAction::Confirm,
                &Decision::approve(&machine),
                &mut port,
                &mut verifier
            )
            .is_err()
    );
    assert_eq!(
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .decisions,
        0
    );
    assert_eq!(
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .journal_failures,
        1
    );
}

#[test]
fn native_attempt_digest_substitution_never_produces_a_continuation() {
    let database = TestDatabase::new();
    let machine = Arc::new(Mutex::new(Machine::default()));
    let mut port = Port(machine.clone());
    let mut verifier = Verifier(machine.clone());
    let request = display_request("substitution");
    let mut control = open(database.path(), &machine, 0);
    value(control.begin_display_layout(
        principal(),
        actor(true),
        request.clone(),
        &approval(),
        &mut port,
        &mut verifier,
    ));
    machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"))
        .wrong_attempt = true;
    assert!(
        control
            .decide_display_layout(
                principal(),
                actor(true),
                &request.request_id,
                DisplayContinuationAction::Confirm,
                &Decision::approve(&machine),
                &mut port,
                &mut verifier
            )
            .is_err()
    );
    assert_eq!(
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .decisions,
        0
    );
}

#[test]
fn wrong_principal_nonhuman_denial_and_rebound_request_cannot_dispatch() {
    let database = TestDatabase::new();
    let machine = Arc::new(Mutex::new(Machine::default()));
    let mut port = Port(machine.clone());
    let mut verifier = Verifier(machine.clone());
    let request = display_request("denied");
    let mut control = open(database.path(), &machine, 0);
    assert!(
        control
            .begin_display_layout(
                value(AuthenticatedPrincipal::new("unix:uid:1001")),
                actor(true),
                request.clone(),
                &approval(),
                &mut port,
                &mut verifier
            )
            .is_err()
    );
    assert!(
        control
            .begin_display_layout(
                principal(),
                actor(false),
                request.clone(),
                &approval(),
                &mut port,
                &mut verifier
            )
            .is_err()
    );
    assert!(
        control
            .begin_display_layout(
                principal(),
                actor(true),
                request.clone(),
                &Deny,
                &mut port,
                &mut verifier
            )
            .is_err()
    );
    assert_eq!(
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .applies,
        0
    );
    value(control.begin_display_layout(
        principal(),
        actor(true),
        request.clone(),
        &approval(),
        &mut port,
        &mut verifier,
    ));
    let mut changed = request;
    changed.reason.summary = "Substituted reason".into();
    assert!(
        control
            .begin_display_layout(
                principal(),
                actor(true),
                changed,
                &approval(),
                &mut port,
                &mut verifier
            )
            .is_err()
    );
    assert_eq!(
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .applies,
        1
    );
}

#[test]
fn crash_gap_after_restoration_retirement_before_terminal_journal_never_replays() {
    let database = TestDatabase::new();
    let machine = Arc::new(Mutex::new(Machine::default()));
    let mut port = Port(machine.clone());
    let mut verifier = Verifier(machine.clone());
    let request = display_request("terminal-journal-fault");
    let mut control = open(database.path(), &machine, 4);
    value(control.begin_display_layout(
        principal(),
        actor(true),
        request.clone(),
        &approval(),
        &mut port,
        &mut verifier,
    ));
    {
        let mut m = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        m.state = Some("restored");
        m.desired = false;
    }
    assert!(
        control
            .display_layout_status(
                principal(),
                actor(true),
                &request.request_id,
                &mut port,
                &mut verifier
            )
            .is_err()
    );
    assert_eq!(
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .journal_failures,
        1
    );
    drop(control);
    let (_, verifier_key) = authority_material();
    let store = value(SqliteTransactionStore::open(
        database.path(),
        verifier_key,
        value(SqliteIntegrityKey::new(fixture_key(5))),
    ));
    let transaction = linura_transaction::TransactionId::for_namespace(
        &value(PrincipalId::new(principal().as_str())),
        &request.request_id,
    );
    assert_eq!(
        value(linura_transaction::TransactionStore::snapshot(
            &store,
            &transaction
        ))
        .state,
        linura_transaction::TransactionState::RecoveryBlocked
    );
    drop(store);
    let mut control = open(database.path(), &machine, 0);
    assert_eq!(
        value(control.begin_display_layout(
            principal(),
            actor(true),
            request,
            &Deny,
            &mut port,
            &mut verifier
        ))
        .state,
        DisplayLayoutState::Restored
    );
    let m = machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"));
    assert_eq!((m.applies, m.decisions), (1, 0));
}
