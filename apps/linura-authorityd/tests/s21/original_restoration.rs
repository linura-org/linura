//! SQLite + simulated observer/approval/effect tests. These do not qualify a
//! native compositor, original kernel witnesses, PAM or independent restoration.
use super::*;
use linura_control::{
    AuthorizedOriginalDisplayFinalization, AuthorizedOriginalDisplayRestoration,
    OriginalDisplayFinalizationAuthorizer, OriginalDisplayFinalizationChallenge,
    OriginalDisplayFinalizationPort, OriginalDisplayFinalizationRequest,
    OriginalDisplayRestorationPort, OriginalDisplayRestorationRequest,
};
use linura_core::DisplayRecoveryScope;
use linura_observation::{DisplayObservationFacts, DisplayOriginalProtectionFacts};
use linura_transaction::{TransactionId, TransactionStore};

#[path = "native_handoff.rs"]
mod native_handoff;

fn finalization_input(restoration_request: &RequestId) -> OriginalDisplayFinalizationRequest {
    OriginalDisplayFinalizationRequest {
        operation_id: "finalize-original-once".into(),
        restoration_request: restoration_request.clone(),
        reason: SemanticReason {
            summary: "Finish the independently verified original display recovery".into(),
            intent_ids: vec![],
            requirement_ids: vec![],
            capability_ids: vec![],
        },
    }
}

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
        metadata.clone(),
        metadata
            .keys()
            .cloned()
            .map(|id| (id, "9".repeat(64)))
            .collect(),
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
        if template.provider.as_str() == "hyprland" {
            value(coordinator.register_observer(Box::new(RestorationObserver {
                machine: machine.clone(),
                template,
                scope: scope.clone(),
            })));
        } else {
            value(coordinator.register_observer(Box::new(LiveFixtureObserver {
                machine: machine.clone(),
                template,
                replacement: true,
            })));
        }
    }
    PlanPreviewControl::new(coordinator)
}

// Simulated native observation remains separate from the executor reply. Tests
// explicitly advance its independent physical/source evidence; no real KMS,
// Root/PAM or frame qualification is claimed by this fixture.
struct RestorationObserver {
    machine: Arc<Mutex<Machine>>,
    template: ObservationEnvelope,
    scope: DisplayRecoveryScope,
}
impl Observer for RestorationObserver {
    fn observer_id(&self) -> ProviderId {
        self.template.provider.clone()
    }
    fn observation_capabilities(&self) -> Vec<Capability> {
        [
            linura_observation::DISPLAY_OUTPUTS_CAPABILITY,
            linura_observation::DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY,
            linura_observation::DISPLAY_NATIVE_HANDOFF_CAPABILITY,
        ]
        .into_iter()
        .map(|id| Capability {
            id: value(CapabilityId::new(id)),
            provider: Some(self.observer_id()),
            support: SupportLevel::Supported,
            reason: None,
        })
        .collect()
    }
    fn health(&self) -> ProviderHealth {
        ProviderHealth {
            provider: self.observer_id(),
            availability: ProviderAvailability::Available,
            reason: None,
        }
    }
    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        Ok(vec![
            self.template.resource.clone(),
            value(self.scope.resource_id()),
        ])
    }
    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        let base = LiveFixtureObserver {
            machine: self.machine.clone(),
            template: self.template.clone(),
            replacement: true,
        };
        let mut sample =
            base.observe_authoritative(&self.template.resource, &self.template.capability)?;
        let mut m = self
            .machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        if m.restoration_native_verified {
            let text = m
                .restoration_material
                .as_ref()
                .unwrap_or_else(|| unreachable!("restoration material"));
            let material = value(linura_core::DisplayRestorationMaterial::decode(text));
            let current = value(DisplayObservationFacts::from_envelope(
                &sample,
                self.scope.replacement(),
                now_unix_ms(),
            ));
            let (_, _, historical, caps) = layouts();
            let (_, restored) = value(material.validate_native(
                &historical,
                &caps,
                current.inventory(),
                current.capabilities(),
            ));
            sample.attributes.insert(
                "layout".into(),
                ObservedValue::Text(value(restored.desired().canonical_text())),
            );
            if !m.native_base_drift {
                sample.attributes.insert(
                    "output.0.base_configuration_digest".into(),
                    ObservedValue::Text("9".repeat(64)),
                );
            }
        }
        if capability.as_str() == linura_observation::DISPLAY_OUTPUTS_CAPABILITY
            && resource == &sample.resource
        {
            return Ok(sample);
        }
        if capability.as_str() == linura_observation::DISPLAY_NATIVE_HANDOFF_CAPABILITY
            && resource == &value(self.scope.resource_id())
        {
            return native_handoff::observe(&mut m, sample, &self.scope);
        }
        if capability.as_str() != linura_observation::DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY
            || resource != &value(self.scope.resource_id())
            || !m.restoration_native_verified
        {
            return Err(ProviderError::Unavailable(
                "simulated independent restoration proof is unavailable".into(),
            ));
        }
        let binding = m
            .restoration_binding
            .as_ref()
            .unwrap_or_else(|| unreachable!("restoration binding"));
        let material = value(linura_core::DisplayRestorationMaterial::decode(
            m.restoration_material
                .as_ref()
                .unwrap_or_else(|| unreachable!("material")),
        ));
        let facts = value(DisplayObservationFacts::from_envelope(
            &sample,
            self.scope.replacement(),
            now_unix_ms(),
        ));
        let frames = facts
            .inventory()
            .outputs()
            .iter()
            .cloned()
            .map(|output| {
                (
                    output,
                    linura_observation::DisplayPostWriteFrame::Presented {
                        crtc: 7,
                        framebuffer: 42 + m.restoration_frame_version,
                        commit: 99 + u64::from(m.restoration_frame_version),
                    },
                )
            })
            .collect();
        let proof = value(linura_observation::DisplayOriginalPresentationFacts::new(
            self.scope.clone(),
            material.original_checkpoint().into(),
            binding.transaction_id.clone(),
            binding.effect_digest.to_hex(),
            binding.dispatch_digest.to_hex(),
            value(linura_provider_sdk::display_baseline_guard(&facts)).to_hex(),
            1,
            frames,
        ));
        sample.resource = resource.clone();
        sample.capability = capability.clone();
        sample.attributes = proof.attributes();
        match m.restoration_proof_fault {
            1 => {
                sample.attributes.insert(
                    "dispatch_digest".into(),
                    ObservedValue::Text("f".repeat(64)),
                );
            }
            2 => {
                sample
                    .attributes
                    .insert("source_guard".into(), ObservedValue::Text("f".repeat(64)));
            }
            3 => {
                sample.attributes.insert(
                    "checkpoint_digest".into(),
                    ObservedValue::Text("f".repeat(64)),
                );
            }
            4 => {
                sample
                    .attributes
                    .insert("effect_digest".into(), ObservedValue::Text("f".repeat(64)));
            }
            5 => {
                sample.attributes.insert(
                    "transaction".into(),
                    ObservedValue::Text("transaction:foreign".into()),
                );
            }
            6 => {
                sample
                    .attributes
                    .insert("post_write_epoch".into(), ObservedValue::U64(0));
            }
            7 => {
                sample
                    .attributes
                    .insert("output.0.commit".into(), ObservedValue::U64(0));
            }
            8 => {
                sample.observed_at_unix_ms = now_unix_ms() - 2001;
            }
            9 => {
                sample.authority = ObservationAuthority::SyntheticTest;
            }
            _ => {}
        }
        Ok(sample)
    }
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
        m.restoration_binding = Some(binding.clone());
        m.restoration_material = Some(material);
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
    terminal_finalization_is_separately_authorized_prepared_and_never_replayed();
}

#[derive(Debug)]
struct TerminalApproval(Arc<Mutex<Machine>>, u8);
impl OriginalDisplayFinalizationAuthorizer for TerminalApproval {
    fn authorize_finalization(
        &self,
        challenge: &OriginalDisplayFinalizationChallenge,
    ) -> Result<TrustedHumanApproval, String> {
        let managed = challenge.managed();
        assert_eq!(managed.change_key(), "finalize_original");
        assert_eq!(
            managed.approval_class(),
            linura_control::ManagedApprovalClass::Administrator
        );
        assert!(
            managed
                .request_id()
                .as_str()
                .starts_with("request:v010:display-finalization:")
        );
        assert_eq!(
            managed.desired_value().as_bytes(),
            value(linura_provider_sdk::display_finalization_effect(
                challenge.material()
            ))
            .canonical_payload
        );
        let mut m = self
            .0
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        m.finalization_approvals += 1;
        match self.1 {
            1 => return Err("simulated protected terminal cancellation".into()),
            2 => m.restoration_proof_fault = 8,
            3 => m.native_base_drift = true,
            4 => {
                return Ok(TrustedHumanApproval::from_privileged_local_boundary(
                    managed.principal().clone(),
                ));
            }
            5 => {
                return Ok(TrustedHumanApproval::from_authorized_challenge(
                    value(PrincipalId::new("unix:uid:99999")),
                    managed,
                ));
            }
            // A later genuinely valid frame changes current proof, not the
            // reviewed source/epoch/lock or the complete release intent.
            _ => m.restoration_frame_version += 1,
        }
        Ok(TrustedHumanApproval::from_authorized_challenge(
            managed.principal().clone(),
            managed,
        ))
    }
}
#[derive(Debug)]
struct TerminalPort(Arc<Mutex<Machine>>);
impl OriginalDisplayFinalizationPort for TerminalPort {
    fn dispatch_finalization(
        &mut self,
        finalization: AuthorizedOriginalDisplayFinalization,
    ) -> Result<ExecutionOutcome, String> {
        let (authorization, material, deadline) = finalization.into_executor_request();
        assert!(deadline > now_unix_ms() && deadline - now_unix_ms() <= 15_000);
        let (effect, binding) = authorization.into_executor_request();
        assert_eq!(
            effect,
            value(linura_provider_sdk::display_finalization_effect(&material))
        );
        value(binding.validate_for(&effect));
        value(linura_linux_session::NativeDisplayFinalizationReservation::new(&material, &binding));
        let mut m = self
            .0
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_ne!(
            binding.dispatch_digest,
            m.restoration_binding
                .as_ref()
                .unwrap_or_else(|| unreachable!("restoration binding"))
                .dispatch_digest
        );
        m.finalization_calls += 1;
        m.finalization_binding = Some(binding.clone());
        m.finalization_material = Some(material);
        // A port acknowledgement deliberately does not advance native phase.
        if m.finalization_outcome == 1 {
            return Err("simulated terminal lost reply".into());
        }
        ExecutionOutcome::new(
            if m.finalization_outcome == 2 {
                ExecutionDisposition::RejectedBeforeDispatch
            } else {
                ExecutionDisposition::Dispatched
            },
            if m.finalization_outcome == 3 {
                linura_provider_sdk::ComponentDigest::from_bytes([9; 32])
            } else {
                binding.dispatch_digest
            },
            "simulated terminal handoff; no native quiescence or release",
        )
        .map_err(|e| e.to_string())
    }
}
// Called by the existing one-use/restart qualification case. Fresh independent
// databases avoid reviving the earlier matrix's permanently lost Root witness.
fn terminal_finalization_is_separately_authorized_prepared_and_never_replayed() {
    for (outcome, approval_fault, fail_at, history_fault) in [
        (0, 0, 0, 0),
        (1, 0, 0, 0),
        (2, 0, 0, 0),
        (3, 0, 0, 0),
        (0, 1, 0, 0),
        (0, 2, 0, 0),
        (0, 3, 0, 0),
        (0, 4, 0, 0),
        (0, 5, 0, 0),
        (0, 0, 1, 0),
        (0, 0, 2, 0),
        (0, 0, 3, 0),
        (0, 0, 4, 0),
        (0, 0, 5, 0),
        (0, 0, 0, 1),
        (0, 0, 0, 2),
        (0, 0, 0, 3),
        (0, 0, 0, 4),
        (0, 0, 0, 5),
        (0, 0, 0, 6),
    ] {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine {
            finalization_outcome: outcome,
            ..Machine::default()
        }));
        let (original, input) = prepare_original(&database, &machine);
        let previews = replacement_previews(&machine, &original, &input);
        let mut control = open_with_previews(database.path(), &machine, 0, previews);
        let receipt = value(control.begin_original_display_restoration(
            principal(),
            actor(true),
            input.clone(),
            &approval(),
            &mut Executor(machine.clone()),
        ));
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .restoration_native_verified = true;
        value(control.reconcile_original_display_restoration(
            principal(),
            actor(true),
            &receipt.request_id,
        ));
        let linked = value(control.retire_original_display_restoration(
            principal(),
            actor(true),
            &receipt.request_id,
        ));
        drop(control);
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .finalization_history_fault = history_fault;
        let previews = replacement_previews(&machine, &original, &input);
        let mut control = open_with_previews(database.path(), &machine, fail_at, previews);
        let terminal_input = finalization_input(&receipt.request_id);
        let result = control.begin_original_display_finalization(
            principal(),
            actor(true),
            terminal_input.clone(),
            &TerminalApproval(machine.clone(), approval_fault),
            &mut TerminalPort(machine.clone()),
        );
        let handoff = approval_fault == 0 && fail_at == 0 && history_fault == 0;
        assert_eq!(
            result.is_ok(),
            handoff && outcome != 3,
            "outcome {outcome}, approval {approval_fault}, write {fail_at}, history {history_fault}"
        );
        assert_eq!(
            snapshot(&database, &original_transaction_id(&original)),
            linked.original
        );
        assert_eq!(
            snapshot(&database, &receipt.transaction_id),
            linked.restoration
        );
        {
            let m = machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"));
            assert_eq!(m.finalization_calls, usize::from(handoff));
            assert_eq!(m.restoration_calls, 1);
            assert_eq!(m.applies, 1);
            assert_eq!(m.decisions, 0);
        }
        if handoff && outcome == 0 {
            quiescence_requires_exact_dispatched_history_and_independent_live_proof(
                &mut control,
                &database,
                &machine,
                &result
                    .as_ref()
                    .unwrap_or_else(|_| unreachable!("terminal receipt"))
                    .request_id,
            );
        }
        // All acknowledgement dispositions remain durable uncertainty. A new
        // process has no live providers and no authorizer able to approve.
        if handoff || fail_at >= 4 || matches!(history_fault, 3 | 5 | 6) {
            let retained = value(control.begin_original_display_finalization(
                principal(),
                actor(true),
                terminal_input.clone(),
                &TerminalApproval(machine.clone(), 1),
                &mut TerminalPort(machine.clone()),
            ));
            assert_eq!(
                snapshot(&database, &retained.transaction_id).state,
                if handoff || fail_at == 5 || matches!(history_fault, 3 | 6) {
                    linura_transaction::TransactionState::Indeterminate
                } else {
                    linura_transaction::TransactionState::Prepared
                }
            );
            assert_eq!(
                retained.dispatch_digest.is_some(),
                handoff || history_fault == 6
            );
            drop(control);
            let mut restarted = open(database.path(), &machine, 0);
            let duplicate = restarted.begin_original_display_finalization(
                principal(),
                actor(true),
                terminal_input.clone(),
                &TerminalApproval(machine.clone(), 1),
                &mut TerminalPort(machine.clone()),
            );
            if !handoff && (fail_at == 4 || history_fault == 5) {
                // Preserve qualified v0.6 startup behavior: never-dispatched
                // Prepared authority is aborted, not resurrected for retry.
                assert!(duplicate.is_err());
                assert_eq!(
                    snapshot(&database, &retained.transaction_id).state,
                    linura_transaction::TransactionState::Aborted
                );
            } else {
                assert_eq!(value(duplicate), retained);
            }
            let mut changed = terminal_input.clone();
            changed.reason.summary.push_str(" changed");
            assert!(
                restarted
                    .begin_original_display_finalization(
                        principal(),
                        actor(true),
                        changed,
                        &TerminalApproval(machine.clone(), 0),
                        &mut TerminalPort(machine.clone())
                    )
                    .is_err()
            );
            let sampled = machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .sequence;
            let mut superseding = terminal_input;
            superseding.operation_id.push_str("-another");
            assert!(
                restarted
                    .begin_original_display_finalization(
                        principal(),
                        actor(true),
                        superseding,
                        &TerminalApproval(machine.clone(), 0),
                        &mut TerminalPort(machine.clone())
                    )
                    .is_err()
            );
            let m = machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"));
            assert_eq!(m.sequence, sampled);
            assert_eq!(m.finalization_calls, usize::from(handoff));
            assert_eq!(m.finalization_approvals, 1);
        }
    }
}
// Simulated provider matrix, not native/Root/PAM/physical-frame qualification.
fn quiescence_requires_exact_dispatched_history_and_independent_live_proof(
    control: &mut ManagedLifecycleControl<SqliteTransactionStore>,
    database: &TestDatabase,
    machine: &Arc<Mutex<Machine>>,
    terminal_request: &RequestId,
) {
    let transaction = TransactionId::for_namespace(
        &value(PrincipalId::new(principal().as_str())),
        terminal_request,
    );
    let before = snapshot(database, &transaction);
    // An acknowledgement and a reservation still do not prove quiescence.
    for phase in [0, 1, 3, 4] {
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .finalization_native_phase = phase;
        assert!(
            control
                .inspect_quiesced_original_display_finalization(
                    principal(),
                    actor(true),
                    terminal_request
                )
                .is_err()
        );
    }
    machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"))
        .finalization_native_phase = 2;
    let checked = value(control.inspect_quiesced_original_display_finalization(
        principal(),
        actor(true),
        terminal_request,
    ));
    assert_eq!(checked.terminal(), &before);
    assert!(
        checked
            .restoration()
            .observation()
            .require_current(now_unix_ms())
            .is_ok()
    );
    for fault in 1..=4 {
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .finalization_state_fault = fault;
        assert!(
            control
                .inspect_quiesced_original_display_finalization(
                    principal(),
                    actor(true),
                    terminal_request
                )
                .is_err(),
            "terminal substitution {fault}"
        );
    }
    machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"))
        .finalization_state_fault = 0;
    for fault in 1..=9 {
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .restoration_root_state_fault = fault;
        assert!(
            control
                .inspect_quiesced_original_display_finalization(
                    principal(),
                    actor(true),
                    terminal_request
                )
                .is_err(),
            "Root fault {fault}"
        );
    }
    machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"))
        .restoration_root_state_fault = 0;
    // Fresh independent presentation checks remain mandatory after Q.
    for fault in 1..=9 {
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .restoration_proof_fault = fault;
        assert!(
            control
                .inspect_quiesced_original_display_finalization(
                    principal(),
                    actor(true),
                    terminal_request
                )
                .is_err(),
            "restoration proof {fault}"
        );
    }
    {
        let mut m = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        m.restoration_proof_fault = 0;
        m.finalization_probe_fault_after = Some(m.restoration_root_reads + 2);
    }
    assert!(
        control
            .inspect_quiesced_original_display_finalization(
                principal(),
                actor(true),
                terminal_request
            )
            .is_err(),
        "Root loss after native join"
    );
    machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"))
        .finalization_probe_fault_after = None;
    value(control.inspect_quiesced_original_display_finalization(
        principal(),
        actor(true),
        terminal_request,
    ));
    {
        let mut m = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        m.native_base_drift = true;
    }
    assert!(
        control
            .inspect_quiesced_original_display_finalization(
                principal(),
                actor(true),
                terminal_request
            )
            .is_err(),
        "restored source drift"
    );
    {
        let mut m = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        m.native_base_drift = false;
        m.restoration_frame_version += 1;
    }
    // A fresh genuinely later frame is evidence of the same held material.
    value(control.inspect_quiesced_original_display_finalization(
        principal(),
        actor(true),
        terminal_request,
    ));
    let sampled = machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"))
        .sequence;
    for id in [
        "request:v010:display-finalization:missing",
        "request:v010:display-restoration:old",
    ] {
        assert!(
            control
                .inspect_quiesced_original_display_finalization(
                    principal(),
                    actor(true),
                    &value(RequestId::new(id))
                )
                .is_err()
        );
    }
    assert!(
        control
            .inspect_quiesced_original_display_finalization(
                value(AuthenticatedPrincipal::new("unix:uid:99999")),
                actor(true),
                terminal_request
            )
            .is_err()
    );
    let m = machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"));
    assert_eq!(m.sequence, sampled); // Foreign history refused before any probe.
    assert_eq!(m.finalization_calls, 1);
    assert_eq!(m.finalization_approvals, 1);
    assert_eq!(m.restoration_calls, 1);
    assert_eq!(m.applies, 1);
    assert_eq!(m.decisions, 0);
    assert_eq!(snapshot(database, &transaction), before); // Query never commits.
    drop(m);
    // Leave the earlier retry/supersession matrix's simulated state unchanged.
    machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"))
        .finalization_native_phase = 0;
}

fn original_transaction_id(original: &PlanDesiredStateRequest) -> TransactionId {
    TransactionId::for_namespace(
        &value(PrincipalId::new(principal().as_str())),
        &original.request_id,
    )
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

fn snapshot(
    database: &TestDatabase,
    transaction: &TransactionId,
) -> linura_transaction::TransactionSnapshot {
    let (_, verifier) = authority_material();
    let store = value(SqliteTransactionStore::open(
        database.path(),
        verifier,
        value(SqliteIntegrityKey::new(fixture_key(5))),
    ));
    value(store.snapshot(transaction))
}

#[test]
fn restoration_reconciliation_needs_independent_proof_and_never_replays_after_restart() {
    for outcome in [0, 1] {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine {
            restoration_outcome: outcome,
            ..Machine::default()
        }));
        let (original, input) = prepare_original(&database, &machine);
        let original_transaction = TransactionId::for_namespace(
            &value(PrincipalId::new(principal().as_str())),
            &original.request_id,
        );
        let previews = replacement_previews(&machine, &original, &input);
        let mut control = open_with_previews(database.path(), &machine, 0, previews);
        let receipt = value(control.begin_original_display_restoration(
            principal(),
            actor(true),
            input.clone(),
            &approval(),
            &mut Executor(machine.clone()),
        ));
        // Neither a successful executor reply nor a lost reply is verification.
        assert!(
            control
                .reconcile_original_display_restoration(
                    principal(),
                    actor(true),
                    &receipt.request_id,
                )
                .is_err()
        );
        assert_eq!(
            snapshot(&database, &receipt.transaction_id).state,
            linura_transaction::TransactionState::Indeterminate
        );
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .restoration_native_verified = true;
        let committed = value(control.reconcile_original_display_restoration(
            principal(),
            actor(true),
            &receipt.request_id,
        ));
        assert_eq!(
            committed.state,
            linura_transaction::TransactionState::Committed
        );
        // Committing restoration does not claim the original desired layout was
        // applied, retire its checkpoint, or release any native/Root fence.
        assert_eq!(
            snapshot(&database, &original_transaction).state,
            linura_transaction::TransactionState::Indeterminate
        );
        drop(control);
        let mut unavailable = open(database.path(), &machine, 0);
        assert!(
            unavailable
                .reconcile_original_display_restoration(
                    principal(),
                    actor(true),
                    &receipt.request_id,
                )
                .is_err()
        );
        drop(unavailable);
        let previews = replacement_previews(&machine, &original, &input);
        let mut restarted = open_with_previews(database.path(), &machine, 0, previews);
        assert_eq!(
            value(restarted.reconcile_original_display_restoration(
                principal(),
                actor(true),
                &receipt.request_id,
            )),
            committed
        );
        let m = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_eq!(m.restoration_calls, 1);
        assert_eq!(m.applies, 1);
        assert_eq!(m.decisions, 0);
    }
}

#[test]
fn restoration_reconciliation_refuses_substituted_stale_or_lost_protection() {
    for fault in 1..=11 {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (original, input) = prepare_original(&database, &machine);
        let previews = replacement_previews(&machine, &original, &input);
        let mut control = open_with_previews(database.path(), &machine, 0, previews);
        let receipt = value(control.begin_original_display_restoration(
            principal(),
            actor(true),
            input,
            &approval(),
            &mut Executor(machine.clone()),
        ));
        {
            let mut m = machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"));
            m.restoration_native_verified = true;
            m.restoration_proof_fault = if fault <= 9 { fault } else { 0 };
            m.native_base_drift = fault == 10;
            m.original_protection_lost = fault == 11;
        }
        assert!(
            control
                .reconcile_original_display_restoration(
                    principal(),
                    actor(true),
                    &receipt.request_id,
                )
                .is_err(),
            "fault {fault} must not become a commit"
        );
        assert_eq!(
            snapshot(&database, &receipt.transaction_id).state,
            linura_transaction::TransactionState::Indeterminate
        );
        assert!(
            control
                .reconcile_original_display_restoration(
                    value(AuthenticatedPrincipal::new("unix:uid:1001")),
                    actor(true),
                    &receipt.request_id,
                )
                .is_err()
        );
        let m = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_eq!(m.restoration_calls, 1);
        assert_eq!(m.applies, 1);
        assert_eq!(m.decisions, 0);
    }
}

#[test]
fn qualified_restoration_links_and_retires_original_authority_without_releasing_or_replaying() {
    for originally_verified in [false, true] {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (original, input) = prepare_original(&database, &machine);
        let original_transaction = TransactionId::for_namespace(
            &value(PrincipalId::new(principal().as_str())),
            &original.request_id,
        );
        if originally_verified {
            // Simulate the authenticated SQLite verification/commit crash gap.
            // This is bookkeeping evidence, not real Keep or native qualification.
            let (signer, verifier) = authority_material();
            let mut store = value(SqliteTransactionStore::open(
                database.path(),
                verifier,
                value(SqliteIntegrityKey::new(fixture_key(5))),
            ));
            let before = value(store.snapshot(&original_transaction));
            let digest = |text: &str| {
                linura_transaction::digest_bytes("fixture:original-verified", text.as_bytes())
            };
            let recovery = value(signer.authorize_recovery(
                &before,
                linura_transaction::RecoveryResolution::IntendedStateVerified {
                    observation_digest: digest("old observation"),
                    desired_state_digest: digest("desired"),
                    graph_digest: digest("graph"),
                    provenance_digest: digest("provenance"),
                },
                1,
                u64::MAX,
            ));
            assert!(matches!(
                value(store.recover(&recovery)),
                linura_transaction::RecoveryOutcome::Verified(_)
            ));
        }
        let before = snapshot(&database, &original_transaction);
        let previews = replacement_previews(&machine, &original, &input);
        let mut control = open_with_previews(database.path(), &machine, 0, previews);
        let receipt = value(control.begin_original_display_restoration(
            principal(),
            actor(true),
            input.clone(),
            &approval(),
            &mut Executor(machine.clone()),
        ));
        assert!(
            control
                .retire_original_display_restoration(principal(), actor(true), &receipt.request_id)
                .is_err()
        );
        assert_eq!(snapshot(&database, &original_transaction), before);
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .restoration_native_verified = true;
        // Committed restoration alone is insufficient. Inspection must not
        // create the missing link or silently perform original retirement.
        let committed = value(control.reconcile_original_display_restoration(
            principal(),
            actor(true),
            &receipt.request_id,
        ));
        let sampled = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .sequence;
        assert!(
            control
                .inspect_original_display_finalization(
                    principal(),
                    actor(true),
                    &receipt.request_id
                )
                .is_err()
        );
        assert_eq!(snapshot(&database, &original_transaction), before);
        assert_eq!(snapshot(&database, &receipt.transaction_id), committed);
        assert_eq!(
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .sequence,
            sampled
        );
        let terminal = value(control.retire_original_display_restoration(
            principal(),
            actor(true),
            &receipt.request_id,
        ));
        assert_eq!(
            terminal.original.state,
            linura_transaction::TransactionState::RecoveryBlocked
        );
        assert_eq!(terminal.original.state_version, before.state_version + 1);
        assert_eq!(
            terminal.restoration.state,
            linura_transaction::TransactionState::Committed
        );
        let inspection = value(control.inspect_original_display_finalization(
            principal(),
            actor(true),
            &receipt.request_id,
        ));
        let material = value(linura_core::DisplayFinalizationMaterial::decode(
            inspection.material(),
        ));
        assert_eq!(inspection.original(), &terminal.original);
        assert_eq!(inspection.restoration(), &terminal.restoration);
        assert_eq!(material.restoration_request(), &receipt.request_id);
        assert_eq!(
            Some(material.restoration_dispatch()),
            receipt.dispatch_digest.as_deref()
        );
        assert_eq!(
            material.terminal_link(),
            terminal
                .link_digest
                .strip_prefix("sha256:")
                .unwrap_or_else(|| unreachable!("canonical link"))
        );
        assert_eq!(material.current_lock(), &input.lock);
        assert_eq!(material.post_write_epoch(), 1);
        assert_eq!(
            material.restoration_text(),
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .restoration_material
                .as_deref()
                .unwrap_or_else(|| unreachable!("material"))
        );
        value(inspection.observation().require_current(now_unix_ms()));
        assert_eq!(
            inspection.observation().capability.as_str(),
            linura_observation::DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY
        );
        assert!(
            inspection
                .observation()
                .attributes
                .contains_key("control.restoration_postcondition_digest")
        );
        assert_eq!(
            snapshot(&database, &original_transaction),
            terminal.original
        );
        assert_eq!(
            snapshot(&database, &receipt.transaction_id),
            terminal.restoration
        );
        let expected_material = inspection.material().to_owned();
        let plan = value(control.plan_original_display_finalization(
            principal(),
            actor(true),
            finalization_input(&receipt.request_id),
        ));
        assert_eq!(plan.status.as_str(), "change-proposed");
        assert!(!plan.execution_authorized());
        assert_eq!(plan.changes.len(), 1);
        assert_eq!(plan.changes[0].key, "finalize_original");
        assert_eq!(
            plan.changes[0].desired.as_bytes(),
            value(linura_provider_sdk::display_finalization_effect(
                &expected_material
            ))
            .canonical_payload
        );
        assert_eq!(
            plan.provider.as_str(),
            linura_observation::DISPLAY_RECOVERY_PROVIDER
        );
        assert_eq!(
            plan.observation_capability.as_str(),
            linura_observation::DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY
        );
        for origin in &original.reason.intent_ids {
            assert!(plan.reason.intent_ids.contains(origin));
        }
        for origin in &original.reason.requirement_ids {
            assert!(plan.reason.requirement_ids.contains(origin));
        }
        for origin in &original.reason.capability_ids {
            assert!(plan.reason.capability_ids.contains(origin));
        }
        let sampled = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .sequence;
        let mut agent = actor(true);
        agent.kind = ActorKind::Agent;
        for actor in [actor(false), agent] {
            assert!(
                control
                    .plan_original_display_finalization(
                        principal(),
                        actor,
                        finalization_input(&receipt.request_id)
                    )
                    .is_err()
            );
        }
        assert!(
            control
                .plan_original_display_finalization(
                    value(AuthenticatedPrincipal::new("unix:uid:1001")),
                    actor(true),
                    finalization_input(&receipt.request_id),
                )
                .is_err()
        );
        assert_eq!(
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .sequence,
            sampled
        );
        assert_eq!(
            snapshot(&database, &original_transaction),
            terminal.original
        );
        assert_eq!(
            snapshot(&database, &receipt.transaction_id),
            terminal.restoration
        );
        // A successful initial inspection cannot supply stale evidence to the
        // actual canonical recipe. Failure must also retire its private context.
        {
            let mut m = machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"));
            m.finalization_probe_fault_after = Some(m.restoration_root_reads + 2);
        }
        assert!(
            control
                .plan_original_display_finalization(
                    principal(),
                    actor(true),
                    finalization_input(&receipt.request_id)
                )
                .is_err()
        );
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .finalization_probe_fault_after = None;
        value(control.plan_original_display_finalization(
            principal(),
            actor(true),
            finalization_input(&receipt.request_id),
        ));
        // History readback is required before and after the canonical join.
        // No missing immutable anchor is repaired by this read-only API.
        for read in 1..=4 {
            {
                let mut m = machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!("fixture poisoned"));
                m.restoration_link_reads = 0;
                m.restoration_link_fail_read = Some(read);
            }
            assert!(
                control
                    .plan_original_display_finalization(
                        principal(),
                        actor(true),
                        finalization_input(&receipt.request_id)
                    )
                    .is_err(),
                "terminal planning readback {read}"
            );
            assert_eq!(
                snapshot(&database, &original_transaction),
                terminal.original
            );
            assert_eq!(
                snapshot(&database, &receipt.transaction_id),
                terminal.restoration
            );
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .restoration_link_fail_read = None;
            value(control.plan_original_display_finalization(
                principal(),
                actor(true),
                finalization_input(&receipt.request_id),
            ));
        }
        drop(control);
        let previews = replacement_previews(&machine, &original, &input);
        let mut restarted = open_with_previews(database.path(), &machine, 0, previews);
        assert_eq!(
            value(restarted.retire_original_display_restoration(
                principal(),
                actor(true),
                &receipt.request_id
            )),
            terminal
        );
        let fresh = value(restarted.inspect_original_display_finalization(
            principal(),
            actor(true),
            &receipt.request_id,
        ));
        assert_eq!(fresh.material(), expected_material);
        assert!(fresh.observation().sequence > inspection.observation().sequence);
        assert!(
            restarted
                .inspect_original_display_finalization(
                    value(AuthenticatedPrincipal::new("unix:uid:1001")),
                    actor(true),
                    &receipt.request_id,
                )
                .is_err()
        );
        for fail_after in [1, 2] {
            let sequence = {
                let mut m = machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!("fixture poisoned"));
                m.restoration_link_fail_read = Some(m.restoration_link_reads + fail_after);
                m.sequence
            };
            assert!(
                restarted
                    .inspect_original_display_finalization(
                        principal(),
                        actor(true),
                        &receipt.request_id,
                    )
                    .is_err()
            );
            let mut m = machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"));
            if fail_after == 1 {
                assert_eq!(m.sequence, sequence); // Authenticate history before provider calls.
            } else {
                assert!(m.sequence > sequence); // Failure after the independent join still refuses.
            }
            m.restoration_link_fail_read = None;
        }
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .restoration_proof_fault = 8;
        assert!(
            restarted
                .retire_original_display_restoration(principal(), actor(true), &receipt.request_id)
                .is_err()
        );
        // A retained successful inspection cannot freshen missing/substituted
        // current proof. These faults never authorize or dispatch any effect.
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .restoration_proof_fault = 0;
        value(restarted.inspect_original_display_finalization(
            principal(),
            actor(true),
            &receipt.request_id,
        ));
        for fault in 1..=9 {
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .restoration_root_state_fault = fault;
            assert!(
                restarted
                    .inspect_original_display_finalization(
                        principal(),
                        actor(true),
                        &receipt.request_id,
                    )
                    .is_err(),
                "Root mechanism fault {fault}"
            );
            assert!(
                restarted
                    .plan_original_display_finalization(
                        principal(),
                        actor(true),
                        finalization_input(&receipt.request_id)
                    )
                    .is_err(),
                "terminal plan Root fault {fault}"
            );
            assert_eq!(
                snapshot(&database, &original_transaction),
                terminal.original
            );
            assert_eq!(
                snapshot(&database, &receipt.transaction_id),
                terminal.restoration
            );
        }
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .restoration_root_state_fault = 0;
        value(restarted.inspect_original_display_finalization(
            principal(),
            actor(true),
            &receipt.request_id,
        ));
        for fault in 1..=11 {
            {
                let mut m = machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!("fixture poisoned"));
                m.restoration_proof_fault = if fault <= 9 { fault } else { 0 };
                m.native_base_drift = fault == 10;
                m.original_protection_lost = fault == 11;
            }
            assert!(
                restarted
                    .inspect_original_display_finalization(
                        principal(),
                        actor(true),
                        &receipt.request_id,
                    )
                    .is_err(),
                "terminal inspection fault {fault}"
            );
            assert!(
                restarted
                    .plan_original_display_finalization(
                        principal(),
                        actor(true),
                        finalization_input(&receipt.request_id)
                    )
                    .is_err(),
                "terminal plan independent proof fault {fault}"
            );
            assert_eq!(
                snapshot(&database, &original_transaction),
                terminal.original
            );
            assert_eq!(
                snapshot(&database, &receipt.transaction_id),
                terminal.restoration
            );
        }
        let m = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_eq!(m.restoration_calls, 1);
        assert_eq!(m.applies, 1);
        assert_eq!(m.decisions, 0);
    }
}

#[test]
fn lost_link_or_post_link_proof_and_terminal_readback_cannot_release_or_repeat_effects() {
    for fault in 1..=3 {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (original, input) = prepare_original(&database, &machine);
        let original_transaction = TransactionId::for_namespace(
            &value(PrincipalId::new(principal().as_str())),
            &original.request_id,
        );
        let previews = replacement_previews(&machine, &original, &input);
        let mut control = open_with_previews(database.path(), &machine, 0, previews);
        let receipt = value(control.begin_original_display_restoration(
            principal(),
            actor(true),
            input.clone(),
            &approval(),
            &mut Executor(machine.clone()),
        ));
        {
            let mut m = machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"));
            m.restoration_native_verified = true;
            m.restoration_link_fault = fault;
        }
        assert!(
            control
                .retire_original_display_restoration(principal(), actor(true), &receipt.request_id)
                .is_err()
        );
        assert_eq!(
            snapshot(&database, &receipt.transaction_id).state,
            linura_transaction::TransactionState::Committed
        );
        assert_eq!(
            snapshot(&database, &original_transaction).state,
            if fault == 3 {
                linura_transaction::TransactionState::RecoveryBlocked
            } else {
                linura_transaction::TransactionState::Indeterminate
            }
        );
        // Inspection never repairs a missing link or completes a missing CAS.
        // A lost terminal readback can be resolved only by reading the actual
        // committed history and independently probing the native state again.
        let inspected = control.inspect_original_display_finalization(
            principal(),
            actor(true),
            &receipt.request_id,
        );
        if fault == 3 {
            let inspected = value(inspected);
            assert_eq!(
                inspected.original(),
                &snapshot(&database, &original_transaction)
            );
            assert_eq!(
                inspected.restoration(),
                &snapshot(&database, &receipt.transaction_id)
            );
        } else {
            assert!(inspected.is_err());
            assert_eq!(
                snapshot(&database, &original_transaction).state,
                linura_transaction::TransactionState::Indeterminate
            );
        }
        drop(control);
        {
            let mut m = machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"));
            m.restoration_link_fault = 0;
            m.restoration_proof_fault = 0; // A new fresh probe; original Root continuity never ceased.
        }
        let previews = replacement_previews(&machine, &original, &input);
        let mut restarted = open_with_previews(database.path(), &machine, 0, previews);
        let terminal = value(restarted.retire_original_display_restoration(
            principal(),
            actor(true),
            &receipt.request_id,
        ));
        assert_eq!(
            terminal.original.state,
            linura_transaction::TransactionState::RecoveryBlocked
        );
        let m = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_eq!(m.restoration_calls, 1);
        assert_eq!(m.applies, 1);
        assert_eq!(m.decisions, 0);
    }
}
