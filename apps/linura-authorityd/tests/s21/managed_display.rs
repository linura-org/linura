//! Deterministic managed-controller and SQLite restart/fault fixtures.
//! NativeApi labels are simulated here; these are not compositor qualification.
use super::*;
#[path = "ordinary_release.rs"]
mod ordinary_release;
#[path = "original_restoration.rs"]
mod original_restoration;
use linura_control::{
    AuthorizedDisplayApplication, AuthorizedDisplayContinuation, DisplayContinuationAction,
    DisplayDecisionAuthorizer, DisplayDecisionChallenge, DisplayLayoutPlanRequest,
    DisplayTransactionPort, DisplayVerificationTarget, IndependentDisplayVerifier,
    ManagedApprovalAuthorizer, ManagedApprovalChallenge, TrustedDisplayDecision,
};
use linura_core::{
    CompositorInvocationId, DisplayLayout, DisplayMode, DisplayOutputId, DisplayOutputLayout,
    DisplayOutputSet, DisplayScale, DisplayTopologyId, DisplayTransform, NativeOutputCapabilities,
};
use linura_observation::{DisplayRecoveryMetadata, display_recovery_observation_attributes};
use linura_protocol::DisplayLayoutState;
use linura_provider_sdk::ExecutionBinding;
use linura_transaction::{ApprovedRequestJournal, RetainedRequest, TransactionStoreError};

#[derive(Debug, Default)]
struct Machine {
    journal_keys: std::collections::BTreeSet<(PrincipalId, RequestId)>,
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
    lose_checkpoint: bool,
    read_only_outputs: bool,
    native_base_drift: bool,
    original_native_guard: Option<linura_provider_sdk::ComponentDigest>,
    ordinary_root_reads: u64,
    ordinary_root_fault: u8,
    ordinary_checkpoint_unavailable: bool,
    ordinary_release_approvals: usize,
    ordinary_release_calls: usize,
    ordinary_release_write_fault: u8,
    original_protection_lost: bool,
    restoration_calls: usize,
    restoration_outcome: u8,
    lose_restoration_dispatch: bool,
    restoration_binding: Option<ExecutionBinding>,
    restoration_material: Option<String>,
    restoration_native_verified: bool,
    restoration_proof_fault: u8,
    restoration_link_fault: u8,
    restoration_link_reads: usize,
    restoration_link_fail_read: Option<usize>,
    restoration_root_state_fault: u8,
    restoration_root_reads: usize,
    finalization_probe_fault_after: Option<usize>,
    finalization_approvals: usize,
    finalization_calls: usize,
    finalization_outcome: u8,
    finalization_binding: Option<ExecutionBinding>,
    finalization_material: Option<String>,
    finalization_native_phase: u8,
    finalization_state_fault: u8,
    restoration_frame_version: u32,
    finalization_history_fault: u8,
    retirement_preparations: usize,
    native_release_reservations: usize,
    native_release_spends: usize,
    native_handoff_reads: usize,
    native_handoff_fault: u8,
    native_handoff_window: Option<(u64, u64)>,
    native_verification_write_fault: u8,
    current_completion: Option<linura_observation::DisplayOriginalCompletionFacts>,
    current_reads: u64,
    current_fault: u8,
    native_power_write_fault: u8,
    completion_write_key: u8,
    completion_write_fault: u8,
    root_power_write_fault: u8,
    root_power_retired: bool,
    native_current_grant: Option<String>,
    native_final_retirement: Option<String>,
    final_retirement: Option<linura_observation::DisplayOriginalFinalRetirementFacts>,
    root_retirement: Option<linura_observation::DisplayOriginalRootRetirementFacts>,
    last_original_protection: Option<linura_observation::DisplayOriginalProtectionFacts>,
    native_power_retired: bool,
    power_grant: Option<linura_observation::DisplayOriginalPowerRetirementFacts>,
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

#[test]
fn replacement_review_reloads_authenticated_history_without_replaying_an_apply() {
    ordinary_release::ordinary_release_dispatch_is_separately_approved_durable_and_never_replayed();
    ordinary_release::original_source_and_terminal_inspection_are_read_only_across_restart();
    ordinary_release::early_automatic_restoration_is_not_expiry_release_authority();
    let database = TestDatabase::new();
    let machine = Arc::new(Mutex::new(Machine::default()));
    let mut port = Port(machine.clone());
    let mut verifier = Verifier(machine.clone());
    let original = display_request("review-original");
    let replacement = value(DisplayTopologyId::new(
        s17_managed_lock::lock_id().epoch().clone(),
        "seat0",
        value(CompositorInvocationId::new(
            "22223344-1234-4567-89ab-0123456789ab",
        )),
        1,
    ));
    let input = linura_control::OriginalDisplayRestorationRequest {
        operation_id: "review-original-restoration".into(),
        original_request: original.request_id.clone(),
        replacement,
        lock: s17_managed_lock::lock_id(),
        reason: original.reason.clone(),
    };
    {
        let mut control = open(database.path(), &machine, 0);
        assert!(
            control
                .plan_original_display_restoration(principal(), actor(true), input.clone())
                .is_err()
        );
        value(control.begin_display_layout(
            principal(),
            actor(true),
            original.clone(),
            &approval(),
            &mut port,
            &mut verifier,
        ));
    }
    let mut control = open(database.path(), &machine, 0);
    // Validated source history survives Control restart. Missing live original
    // protection still refuses recovery and cannot dispatch either intent.
    let failure = control
        .plan_original_display_restoration(principal(), actor(true), input.clone())
        .err()
        .unwrap_or_else(|| unreachable!("no original-protection observer"));
    assert!(
        failure.to_string().contains("hyprland-recovery"),
        "{failure}"
    );
    for (principal, actor) in [
        (
            value(AuthenticatedPrincipal::new("unix:uid:1001")),
            actor(true),
        ),
        (principal(), actor(false)),
    ] {
        assert!(
            control
                .plan_original_display_restoration(principal, actor, input.clone())
                .is_err()
        );
    }
    value(control.decide_display_layout(
        principal(),
        actor(true),
        &original.request_id,
        DisplayContinuationAction::Revert,
        &Decision::approve(&machine),
        &mut port,
        &mut verifier,
    ));
    assert!(matches!(
        control.plan_original_display_restoration(principal(), actor(true), input),
        Err(ManagedLifecycleError::TerminalState(_))
    ));
    assert_eq!(
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .applies,
        1
    );
}
struct LiveFixtureObserver {
    machine: Arc<Mutex<Machine>>,
    template: ObservationEnvelope,
    replacement: bool,
}
impl Observer for LiveFixtureObserver {
    fn observer_id(&self) -> ProviderId {
        self.template.provider.clone()
    }
    fn observation_capabilities(&self) -> Vec<Capability> {
        let mut capabilities = vec![Capability {
            id: self.template.capability.clone(),
            support: SupportLevel::Supported,
            provider: Some(self.template.provider.clone()),
            reason: None,
        }];
        if self.template.provider.as_str() == linura_observation::DISPLAY_RECOVERY_PROVIDER {
            capabilities.push(Capability {
                id: value(CapabilityId::new(
                    linura_observation::DISPLAY_ORIGINAL_FINAL_RETIREMENT_CAPABILITY,
                )),
                support: SupportLevel::Supported,
                provider: Some(self.template.provider.clone()),
                reason: None,
            });
            capabilities.push(Capability {
                id: value(CapabilityId::new(
                    linura_observation::DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY,
                )),
                support: SupportLevel::Supported,
                provider: Some(self.template.provider.clone()),
                reason: None,
            });
            capabilities.push(Capability {
                id: value(CapabilityId::new(
                    linura_observation::DISPLAY_ORIGINAL_COMPLETION_CAPABILITY,
                )),
                support: SupportLevel::Supported,
                provider: Some(self.template.provider.clone()),
                reason: None,
            });
        }
        if self.template.provider.as_str() == linura_observation::DISPLAY_RECOVERY_PROVIDER {
            capabilities.push(Capability {
                id: value(CapabilityId::new(
                    linura_observation::DISPLAY_ORIGINAL_ROOT_RETIREMENT_CAPABILITY,
                )),
                support: SupportLevel::Supported,
                provider: Some(self.template.provider.clone()),
                reason: None,
            });
            capabilities.push(Capability {
                id: value(CapabilityId::new(
                    linura_observation::DISPLAY_ORIGINAL_POWER_RETIREMENT_CAPABILITY,
                )),
                support: SupportLevel::Supported,
                provider: Some(self.template.provider.clone()),
                reason: None,
            });
        }
        capabilities
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
        let finalization = self.template.provider.as_str()
            == linura_observation::DISPLAY_RECOVERY_PROVIDER
            && capability.as_str() == linura_observation::DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY;
        let completion = self.template.provider.as_str()
            == linura_observation::DISPLAY_RECOVERY_PROVIDER
            && capability.as_str() == linura_observation::DISPLAY_ORIGINAL_COMPLETION_CAPABILITY;
        let power = self.template.provider.as_str()
            == linura_observation::DISPLAY_RECOVERY_PROVIDER
            && capability.as_str()
                == linura_observation::DISPLAY_ORIGINAL_POWER_RETIREMENT_CAPABILITY;
        let final_retirement = self.template.provider.as_str()
            == linura_observation::DISPLAY_RECOVERY_PROVIDER
            && capability.as_str()
                == linura_observation::DISPLAY_ORIGINAL_FINAL_RETIREMENT_CAPABILITY;
        let root_retirement = self.template.provider.as_str()
            == linura_observation::DISPLAY_RECOVERY_PROVIDER
            && capability.as_str()
                == linura_observation::DISPLAY_ORIGINAL_ROOT_RETIREMENT_CAPABILITY;
        if resource != &self.template.resource
            || (capability != &self.template.capability
                && !finalization
                && !completion
                && !power
                && !root_retirement
                && !final_retirement)
        {
            return Err(ProviderError::Unsupported("fixture route mismatch".into()));
        }
        let mut machine = self
            .machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        if machine.original_protection_lost
            && self.template.provider.as_str() == "hyprland-recovery"
        {
            return Err(ProviderError::Unsupported(
                "original kernel witness lost".into(),
            ));
        }
        machine.sequence += 1;
        let mut sample = self.template.clone();
        sample.observed_at_unix_ms = now_unix_ms();
        sample.sequence = machine.sequence;
        if final_retirement {
            let root = machine.final_retirement.as_ref().ok_or_else(|| {
                ProviderError::Unavailable("no simulated final Root permission".into())
            })?;
            sample.capability = capability.clone();
            sample.attributes = root.attributes();
            return Ok(sample);
        }
        if root_retirement {
            let root = machine
                .root_retirement
                .as_ref()
                .ok_or_else(|| ProviderError::Unavailable("no simulated retired Root".into()))?;
            sample.capability = capability.clone();
            sample.attributes = root.attributes();
            if machine.current_fault == 9 {
                sample.attributes.insert(
                    "phase".into(),
                    ObservedValue::Text("released-current".into()),
                );
            }
            return Ok(sample);
        }
        if machine.root_power_retired
            && self.template.provider.as_str() == linura_observation::DISPLAY_RECOVERY_PROVIDER
        {
            return Err(ProviderError::Unavailable(
                "simulated Root no longer holds power; old-phase probe denied".into(),
            ));
        }
        if power {
            let grant = machine.power_grant.as_ref().ok_or_else(|| {
                ProviderError::Unavailable("no simulated power permission".into())
            })?;
            sample.capability = capability.clone();
            sample.attributes = grant.attributes();
            return Ok(sample);
        }
        if completion {
            let root = machine.current_completion.as_ref().ok_or_else(|| {
                ProviderError::Unavailable("no simulated transferred Root lifetime".into())
            })?;
            sample.capability = capability.clone();
            sample.attributes = root.attributes();
            if machine.current_fault == 9 {
                sample.attributes.insert(
                    "phase".into(),
                    ObservedValue::Text("released-current".into()),
                );
            }
            return Ok(sample);
        }
        if finalization {
            machine.restoration_root_reads += 1;
            let binding = machine.restoration_binding.as_ref().ok_or_else(|| {
                ProviderError::Unavailable("no simulated Root restoration reservation".into())
            })?;
            let material = value(linura_core::DisplayRestorationMaterial::decode(
                machine
                    .restoration_material
                    .as_deref()
                    .unwrap_or_else(|| unreachable!("restoration material")),
            ));
            let facts = value(linura_observation::DisplayOriginalFinalizationFacts::new(
                value(material.recovery_scope()),
                material.original_checkpoint().into(),
                binding.transaction_id.clone(),
                binding.effect_digest.to_hex(),
                binding.dispatch_digest.to_hex(),
                match machine.finalization_native_phase {
                    0 => linura_observation::DisplayFinalizationPhase::Protected,
                    1 => linura_observation::DisplayFinalizationPhase::Reserved,
                    2 => linura_observation::DisplayFinalizationPhase::Quiesced,
                    3 => linura_observation::DisplayFinalizationPhase::Retired,
                    4 => linura_observation::DisplayFinalizationPhase::ReleasedCurrent,
                    5 => linura_observation::DisplayFinalizationPhase::NativeReleaseReserved,
                    6 => linura_observation::DisplayFinalizationPhase::NativeReleaseSpent,
                    _ => unreachable!("unsupported simulated terminal phase"),
                },
                if machine.finalization_native_phase == 0 {
                    None
                } else {
                    let terminal = machine
                        .finalization_binding
                        .as_ref()
                        .unwrap_or_else(|| unreachable!("terminal reservation"));
                    Some(value(
                        linura_observation::DisplayFinalizationReservationFacts::new(
                            machine
                                .finalization_material
                                .clone()
                                .unwrap_or_else(|| unreachable!("terminal material")),
                            terminal.transaction_id.clone(),
                            terminal.effect_digest.to_hex(),
                            terminal.dispatch_digest.to_hex(),
                        ),
                    ))
                },
            ));
            sample.capability = capability.clone();
            sample.attributes = facts.attributes();
            let substituted = match machine.finalization_state_fault {
                1 => Some(("terminal_transaction", "transaction:another".to_owned())),
                2 => Some(("terminal_effect", "f".repeat(64))),
                3 => Some(("terminal_dispatch", "f".repeat(64))),
                4 => {
                    let decoded = value(linura_core::DisplayFinalizationMaterial::decode(
                        machine
                            .finalization_material
                            .as_deref()
                            .unwrap_or_else(|| unreachable!("terminal material")),
                    ));
                    Some((
                        "terminal_material",
                        value(linura_core::DisplayFinalizationMaterial::encode(
                            decoded.restoration_request(),
                            decoded.restoration_dispatch(),
                            decoded.terminal_link(),
                            &"f".repeat(64),
                            decoded.post_write_epoch(),
                            decoded.current_lock(),
                            decoded.restoration_text(),
                        )),
                    ))
                }
                _ => None,
            };
            if let Some((key, text)) = substituted {
                sample
                    .attributes
                    .insert(key.into(), ObservedValue::Text(text));
            }
            let fault =
                if machine.finalization_probe_fault_after == Some(machine.restoration_root_reads) {
                    1 // Fresh first inspection cannot excuse a stale planning probe.
                } else {
                    machine.restoration_root_state_fault
                };
            match fault {
                1 => sample.observed_at_unix_ms = now_unix_ms() - 2001,
                2 => sample.authority = ObservationAuthority::SyntheticTest,
                3 => {
                    sample.attributes.insert(
                        "original_checkpoint_digest".into(),
                        ObservedValue::Text("f".repeat(64)),
                    );
                }
                4 => {
                    sample.attributes.insert(
                        "restoration_effect".into(),
                        ObservedValue::Text("f".repeat(64)),
                    );
                }
                5 => {
                    sample.attributes.insert(
                        "restoration_dispatch".into(),
                        ObservedValue::Text("f".repeat(64)),
                    );
                }
                6 => {
                    sample.attributes.insert(
                        "restoration_transaction".into(),
                        ObservedValue::Text("transaction:other".into()),
                    );
                }
                7 => {
                    sample.attributes.insert(
                        "phase".into(),
                        ObservedValue::Text("released-current".into()),
                    );
                }
                8 => {
                    return Err(ProviderError::Unavailable(
                        "simulated Root state unavailable".into(),
                    ));
                }
                9 => sample.resource = value(material.replacement().topology().resource_id()),
                _ => {}
            }
            return Ok(sample);
        }
        if machine.read_only_outputs && sample.provider.as_str() == "hyprland" {
            sample
                .attributes
                .insert("display_schema".into(), ObservedValue::U64(1));
            for key in [
                "output.0.linura_owned",
                "output.0.base_configuration_digest",
                "output.0.native_identity_digest",
            ] {
                sample.attributes.remove(key);
            }
        }
        if machine.desired && !self.replacement && sample.provider.as_str() == "hyprland" {
            sample
                .attributes
                .insert("output.0.linura_owned".into(), ObservedValue::Bool(true));
            sample.attributes.insert(
                "layout".into(),
                ObservedValue::Text(value(layouts().1.canonical_text())),
            );
        }
        if machine.native_base_drift && sample.provider.as_str() == "hyprland" {
            sample.attributes.insert(
                "output.0.base_configuration_digest".into(),
                ObservedValue::Text("c".repeat(64)),
            );
        }
        if sample.provider.as_str() == linura_observation::DISPLAY_RECOVERY_PROVIDER
            && sample.capability.as_str()
                == linura_observation::DISPLAY_ORIGINAL_PROTECTION_CAPABILITY
            && let Ok(scope) = linura_core::DisplayRecoveryScope::from_resource(&sample.resource)
            && let Ok(facts) = linura_observation::DisplayOriginalProtectionFacts::from_envelope(
                &sample,
                &scope,
                now_unix_ms(),
            )
        {
            machine.last_original_protection = Some(facts);
        }
        Ok(sample)
    }
}
fn previews(machine: &Arc<Mutex<Machine>>) -> PlanPreviewControl {
    previews_inner(machine, false)
}
fn previews_inner(machine: &Arc<Mutex<Machine>>, ordinary_original: bool) -> PlanPreviewControl {
    let (baseline, _, inventory, caps) = layouts();
    let mut display = s17_managed_lock::session_observation(1);
    display.provider = value(ProviderId::new("hyprland"));
    display.resource = value(baseline.topology().resource_id());
    display.capability = value(CapabilityId::new("display.outputs.observe"));
    display.attributes = value(display_recovery_observation_attributes(
        &inventory,
        &caps,
        &baseline,
        &std::collections::BTreeSet::from([inventory.outputs()[0].clone()]),
        &BTreeMap::from([(
            inventory.outputs()[0].clone(),
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
            replacement: false,
        })));
    }
    if ordinary_original {
        value(
            coordinator.register_observer(Box::new(ordinary_release::OriginalObserver(
                machine.clone(),
            ))),
        );
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
    fn checked_read_scope(
        &self,
    ) -> Result<Box<dyn linura_transaction::ApprovedRequestReadScope + '_>, TransactionStoreError>
    {
        self.inner.checked_read_scope()
    }

    fn retain(&mut self, record: &RetainedRequest) -> Result<(), TransactionStoreError> {
        self.machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .journal_keys
            .insert((record.principal().clone(), record.request_id().clone()));
        let completion_kind = if record
            .request_id()
            .as_str()
            .starts_with("request:v010:display-current-completion-prepared:")
        {
            1
        } else if record
            .request_id()
            .as_str()
            .starts_with("request:v010:display-current-completion-verified:")
        {
            2
        } else if record
            .request_id()
            .as_str()
            .starts_with("request:v010:display-current-committed:")
        {
            3
        } else if record
            .request_id()
            .as_str()
            .starts_with("request:v010:display-native-current-prepared:")
        {
            4
        } else if record
            .request_id()
            .as_str()
            .starts_with("request:v010:display-native-current-verified:")
        {
            5
        } else if record
            .request_id()
            .as_str()
            .starts_with("request:v010:display-final-retirement-prepared:")
        {
            6
        } else if record
            .request_id()
            .as_str()
            .starts_with("request:v010:display-final-retirement-verified:")
        {
            7
        } else if record
            .request_id()
            .as_str()
            .starts_with("request:v010:display-released-current:")
        {
            8
        } else {
            0
        };
        if completion_kind != 0 {
            let fault = {
                let state = self
                    .machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!("fixture poisoned"));
                if state.completion_write_key == completion_kind {
                    state.completion_write_fault
                } else {
                    0
                }
            };
            match fault {
                1 => return Err(TransactionStoreError::CapacityExceeded),
                2 => return Ok(()),
                3 => {
                    self.inner.retain(record)?;
                    return Err(TransactionStoreError::Storage(
                        "simulated ambiguous current completion sync".into(),
                    ));
                }
                _ => (),
            }
        }
        if record
            .request_id()
            .as_str()
            .starts_with("request:v010:display-root-power-prepared:")
        {
            let fault = self
                .machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .root_power_write_fault;
            match fault {
                1 => return Err(TransactionStoreError::CapacityExceeded),
                2 => return Ok(()),
                3 => {
                    self.inner.retain(record)?;
                    return Err(TransactionStoreError::Storage(
                        "simulated ambiguous Root power sync".into(),
                    ));
                }
                _ => (),
            }
        }
        if record
            .request_id()
            .as_str()
            .starts_with("request:v010:display-native-power-prepared:")
        {
            let fault = self
                .machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .native_power_write_fault;
            match fault {
                1 => return Err(TransactionStoreError::CapacityExceeded),
                2 => return Ok(()),
                3 => {
                    self.inner.retain(record)?;
                    return Err(TransactionStoreError::Storage(
                        "simulated ambiguous native power sync".into(),
                    ));
                }
                _ => (),
            }
        }
        if record
            .request_id()
            .as_str()
            .starts_with("request:v010:display-physical-verified:")
        {
            let fault = self
                .machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .native_verification_write_fault;
            match fault {
                1 => return Err(TransactionStoreError::CapacityExceeded),
                2 => return Ok(()), // Acknowledged but not durable.
                3 => {
                    self.inner.retain(record)?;
                    return Err(TransactionStoreError::Storage(
                        "simulated ambiguous verification sync".into(),
                    ));
                }
                _ => (),
            }
        }
        let fault = self
            .machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .finalization_history_fault;
        if (fault == 1
            && record
                .request_id()
                .as_str()
                .starts_with("request:v010:display-finalization-material:"))
            || (fault == 2
                && record
                    .request_id()
                    .as_str()
                    .starts_with("request:v010:display-finalization-owner:"))
            || (fault == 3
                && record
                    .request_id()
                    .as_str()
                    .starts_with("request:v010:display-recovery:")
                && record.request_id().as_str().ends_with(":dispatched"))
            || (fault == 4
                && record
                    .request_id()
                    .as_str()
                    .starts_with("request:v010:display-finalization:"))
            || (fault == 5
                && record
                    .request_id()
                    .as_str()
                    .starts_with("request:v010:display-recovery:")
                && record.request_id().as_str().ends_with(":reserved"))
        {
            return Ok(());
        } // Acknowledgement is not durable readback.
        if fault == 6
            && record
                .request_id()
                .as_str()
                .starts_with("request:v010:display-recovery:")
            && record.request_id().as_str().ends_with(":dispatched")
        {
            // Deliberately cross the unchanged two-second observation expiry
            // after handoff bookkeeping. No stale authorization reaches a port.
            std::thread::sleep(std::time::Duration::from_millis(2_100));
        }
        if record
            .request_id()
            .as_str()
            .starts_with("request:v010:display-restoration-link:")
        {
            let mut m = self
                .machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"));
            match m.restoration_link_fault {
                1 => return Ok(()), // Lost link persistence despite acknowledgement.
                2 => m.restoration_proof_fault = 8, // Next physical probe is stale, not loss/revival of Root.
                _ => {}
            }
        }
        if record
            .request_id()
            .as_str()
            .starts_with("request:v010:display-native-baseline:")
            && self
                .machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .lose_checkpoint
        {
            return Ok(()); // A write acknowledgement cannot replace readback.
        }
        if record
            .request_id()
            .as_str()
            .starts_with("request:v010:display-recovery:")
            && record.request_id().as_str().ends_with(":dispatched")
            && self
                .machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .lose_restoration_dispatch
        {
            return Ok(()); // Acknowledged but absent correlation must never reach the native call.
        }
        self.writes += 1;
        if self.writes == self.fail_at {
            let fault = self
                .machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .ordinary_release_write_fault;
            if fault == 1 {
                return Ok(()); // A false ACK is never readback.
            }
            if fault == 2 {
                self.inner.retain(record)?;
            }
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
        if request
            .as_str()
            .starts_with("request:v010:display-native-baseline:")
            && self
                .machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .ordinary_checkpoint_unavailable
        {
            return Err(TransactionStoreError::Storage(
                "simulated ordinary checkpoint read failure".into(),
            ));
        }
        if request
            .as_str()
            .starts_with("request:v010:display-restoration-link:")
        {
            let mut m = self
                .machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"));
            m.restoration_link_reads += 1;
            if m.restoration_link_fail_read == Some(m.restoration_link_reads) {
                return Err(TransactionStoreError::Storage(
                    "simulated finalization history readback loss".into(),
                ));
            }
            if m.restoration_link_fault == 3 && m.restoration_link_reads == 3 {
                return Err(TransactionStoreError::Storage(
                    "simulated terminal readback loss".into(),
                ));
            }
        }
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
    open_with_previews(database, machine, fail_at, previews(machine))
}
fn open_with_previews(
    database: &Path,
    machine: &Arc<Mutex<Machine>>,
    fail_at: usize,
    previews: PlanPreviewControl,
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
        value(ManagedLifecycleControl::new(previews, store, signer)).with_request_journal(
            Box::new(FailingJournal {
                inner: journal,
                machine: machine.clone(),
                fail_at,
                writes: 0,
            }),
        ),
    )
}
#[derive(Debug)]
struct Port(Arc<Mutex<Machine>>);
impl DisplayTransactionPort for Port {
    fn dispatch_layout(
        &mut self,
        application: AuthorizedDisplayApplication,
        request: &PlanDesiredStateRequest,
        deadline: u64,
    ) -> Result<ExecutionOutcome, String> {
        let (authorization, native_guard) = application.into_executor_request();
        assert_ne!(
            native_guard,
            linura_provider_sdk::ComponentDigest::from_bytes([0; 32])
        );
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
        m.original_native_guard = Some(native_guard);
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
            || continuation.deadline_unix_ms() != m.deadline
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
        target: DisplayVerificationTarget,
        _: u64,
    ) -> Result<VerificationOutcome, String> {
        let m = self
            .0
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        let restoration = matches!(target, DisplayVerificationTarget::Restored { .. });
        if let DisplayVerificationTarget::Restored {
            native_baseline_guard,
        } = target
        {
            assert_eq!(Some(native_baseline_guard), m.original_native_guard);
        }
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
        assert_eq!(
            challenge.dispatch_digest(),
            m.binding
                .as_ref()
                .unwrap_or_else(|| unreachable!("no dispatch"))
                .dispatch_digest
                .to_hex()
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
fn lost_apply_reply_never_replays_and_restart_cannot_reconstruct_keep_review() {
    for recovery in ["keep", "timer", "revert"] {
        let restart = recovery != "keep";
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
        if restart {
            drop(control);
            control = open(database.path(), &machine, 0);
        }
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
        let human = Decision::approve(&machine);
        let decision = control.decide_display_layout(
            principal(),
            actor(true),
            &request.request_id,
            DisplayContinuationAction::Confirm,
            &human,
            &mut port,
            &mut verifier,
        );
        let expected = if restart {
            assert!(
                matches!(decision, Err(ManagedLifecycleError::ApprovalBoundary(ref detail)) if detail.contains("original display review is unavailable"))
            );
            assert_eq!(human.calls.load(Ordering::SeqCst), 0);
            if recovery == "revert" {
                assert_eq!(
                    value(control.decide_display_layout(
                        principal(),
                        actor(true),
                        &request.request_id,
                        DisplayContinuationAction::Revert,
                        &Decision::approve(&machine),
                        &mut port,
                        &mut verifier,
                    ))
                    .state,
                    DisplayLayoutState::Restored
                );
            } else {
                // Simulate the separately owned native timer's restored facts.
                // Restart may observe/retire them, never manufacture a keep review.
                let mut m = machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!("fixture poisoned"));
                assert_eq!((m.applies, m.decisions), (1, 0));
                m.desired = false;
                m.state = Some("restored");
            }
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
            DisplayLayoutState::Restored
        } else {
            assert_eq!(value(decision).state, DisplayLayoutState::Confirmed);
            assert_eq!(human.calls.load(Ordering::SeqCst), 1);
            DisplayLayoutState::Confirmed
        };
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
            expected
        );
        let m = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_eq!(
            (m.applies, m.decisions),
            (1, usize::from(recovery != "timer"))
        );
    }
}

#[test]
fn autonomous_restoration_reconciles_after_restart_without_any_continuation() {
    for reconcile_on_begin in [false, true] {
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
        drop(control);
        let mut control = open(database.path(), &machine, 0);
        {
            // A replacement mechanism may have no reservation or visible pending
            // bit. Durable ambiguity still belongs to the SEAT, not its old UUID.
            let mut m = machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"));
            m.state = None;
            m.desired = false;
        }
        for (native_state, desired) in [
            (None, false),
            (Some("confirmed"), true), // No retained protected Keep proof.
            (Some("restored"), true),  // Native flag contradicts independent layout.
        ] {
            {
                let mut m = machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!("fixture poisoned"));
                m.state = native_state;
                m.desired = desired;
            }
            for replacement in [false, true] {
                let mut next = display_request("after-mechanism-loss");
                if replacement {
                    let prior = "11223344-1234-4567-89ab-0123456789ab";
                    let current = "22334455-1234-4567-89ab-0123456789ab";
                    next.resource = value(ResourceId::new(
                        next.resource.as_str().replace(prior, current),
                    ));
                    let intent = next
                        .desired_state
                        .get_mut("layout")
                        .unwrap_or_else(|| unreachable!("no fixture layout"));
                    *intent = intent.replace(prior, current);
                    next.request_id =
                        value(managed_request_id("after-compositor-replacement", &next));
                }
                let admission = control.begin_display_layout(
                    principal(),
                    actor(true),
                    next,
                    &approval(),
                    &mut port,
                    &mut verifier,
                );
                assert!(
                    matches!(admission,
                Err(ManagedLifecycleError::Indeterminate(ref reason)) if reason.contains("recovery is unresolved")),
                    "unexpected admission after replacement={replacement}: {admission:?}"
                );
                assert_eq!(
                    value(control.display_layout_status(
                        principal(),
                        actor(true),
                        &request.request_id,
                        &mut port,
                        &mut verifier
                    ))
                    .state,
                    DisplayLayoutState::Indeterminate
                );
            }
        }
        {
            let mut m = machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"));
            m.state = Some("restored");
            m.desired = false;
            m.native_base_drift = true;
        }
        // Even a verifier reporting satisfied numeric geometry cannot retire
        // recovery after the independently observed native rule identity drifts.
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
                .applies,
            1
        );
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .native_base_drift = false;
        drop(control);
        let mut control = open(database.path(), &machine, 0);
        if reconcile_on_begin {
            assert_eq!(
                value(control.begin_display_layout(
                    principal(),
                    actor(true),
                    display_request("on-demand-recovery"),
                    &approval(),
                    &mut port,
                    &mut verifier
                ))
                .state,
                DisplayLayoutState::AwaitingConfirmation
            );
        }
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
        assert_eq!(
            (m.applies, m.decisions),
            (1 + usize::from(reconcile_on_begin), 0)
        );
        drop(m);
        // Only independently verified, durably retired restoration frees admission.
        if !reconcile_on_begin {
            assert_eq!(
                value(control.begin_display_layout(
                    principal(),
                    actor(true),
                    display_request("after-verified-restoration"),
                    &approval(),
                    &mut port,
                    &mut verifier
                ))
                .state,
                DisplayLayoutState::AwaitingConfirmation
            );
        }
        assert_eq!(
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .applies,
            2
        );
    }
}

#[test]
fn every_preeffect_journal_failure_prevents_native_dispatch() {
    for lose_checkpoint in [false, true] {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine {
            lose_checkpoint,
            read_only_outputs: !lose_checkpoint,
            ..Machine::default()
        }));
        let mut control = open(database.path(), &machine, 0);
        let mut port = Port(machine.clone());
        let mut verifier = Verifier(machine.clone());
        let result = control.begin_display_layout(
            principal(),
            actor(true),
            display_request("unqualified-checkpoint"),
            &approval(),
            &mut port,
            &mut verifier,
        );
        assert!(
            matches!(result, Err(ManagedLifecycleError::Authority(reason)) if reason.contains("checkpoint"))
        );
        assert_eq!(
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .applies,
            0
        );
    }
    // Canonical request, native baseline checkpoint, reservation and dispatch.
    for fail_at in 1..=4 {
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
    let mut control = open(database.path(), &machine, 5);
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
    let mut control = open(database.path(), &machine, 5);
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
