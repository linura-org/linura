//! Real Control + authenticated SQLite history with SIMULATED native sources.
//! No KMS/compositor execution, hardware or Level A/B evidence is claimed.
use super::*;
use linura_control::{
    AuthorizedOriginalDisplayCompletion, AuthorizedOriginalDisplayNativeReleaseReservation,
    AuthorizedOriginalDisplayNativeReleaseSpend, AuthorizedOriginalDisplayRetirementPreparation,
    OriginalDisplayCompletionPort, OriginalDisplayNativeReleaseReservationPort,
    OriginalDisplayNativeReleaseSpendPort, OriginalDisplayRetirementPreparationPort,
};
use linura_observation::{
    DisplayNativeHandoffFacts, DisplayNativeHandoffLineage, DisplayNativeHandoffOutput,
    DisplayNativeHandoffWindow,
};
use linura_transaction::TransactionState;

pub(super) fn observe_current(
    machine: &mut Machine,
    mut sample: ObservationEnvelope,
    scope: &DisplayRecoveryScope,
) -> Result<ObservationEnvelope, ProviderError> {
    use linura_observation::{DisplayNativeCurrentFacts, DisplayNativeCurrentOutput};
    let root = machine.current_completion.as_ref().ok_or_else(|| {
        ProviderError::Unavailable("no simulated current Root/native handoff".into())
    })?;
    machine.current_reads += 1;
    // Fault-pair counters may reset, but the producer clock cannot. Derive
    // BOOTTIME from the fixture's monotonic observation sequence instead.
    let boot = 200_000 + sample.sequence;
    let current = value(DisplayNativeCurrentFacts::new(
        scope.clone(),
        root.first().lineage().clone(),
        DisplayNativeHandoffWindow {
            observed_unix_ms: sample.observed_at_unix_ms,
            observed_boot_ms: boot,
            deadline_unix_ms: sample.observed_at_unix_ms + 2000,
            deadline_boot_ms: boot + 2000,
        },
        root.first()
            .outputs()
            .iter()
            .map(|(id, output)| {
                (
                    id.clone(),
                    DisplayNativeCurrentOutput {
                        enabled: output.enabled,
                        connector: output.connector,
                        crtc: output.crtc,
                        plane: output.plane,
                        framebuffer: output.framebuffer + u32::from(output.enabled),
                        handoff_commit: output.completed_commit,
                        completed_commit: output.completed_commit + u64::from(output.enabled),
                    },
                )
            })
            .collect(),
        root.lineage().record.clone(),
        true,
        !machine.native_power_retired,
        machine.native_current_grant.clone(),
        machine.native_final_retirement.clone(),
    ));
    sample.resource = value(scope.resource_id());
    sample.capability = value(CapabilityId::new(
        linura_observation::DISPLAY_NATIVE_CURRENT_CAPABILITY,
    ));
    sample.valid_for_ms = 2000;
    sample.attributes = current.attributes();
    match machine.current_fault {
        1 => {
            sample
                .attributes
                .insert("input_retired".into(), ObservedValue::Bool(false));
        }
        2 => {
            sample
                .attributes
                .insert("power_fence_held".into(), ObservedValue::Bool(false));
        }
        3 => {
            sample.attributes.insert(
                "completion_digest".into(),
                ObservedValue::Text("8".repeat(64)),
            );
        }
        4 => {
            sample
                .attributes
                .insert("source_guard".into(), ObservedValue::Text("8".repeat(64)));
        }
        5 => {
            sample
                .attributes
                .insert("output.0.handoff_commit".into(), ObservedValue::U64(99));
        }
        6 => {
            sample
                .attributes
                .insert("output.0.completed_commit".into(), ObservedValue::U64(100));
        }
        7 if machine.current_reads.is_multiple_of(2) => {
            sample
                .attributes
                .insert("output.0.framebuffer".into(), ObservedValue::U64(99));
        }
        8 => sample.authority = ObservationAuthority::SyntheticTest,
        10 => sample.observed_at_unix_ms -= 2001,
        11 => {
            sample.attributes.remove("input_retired");
        }
        12 => {
            sample.capability = value(CapabilityId::new(
                linura_observation::DISPLAY_NATIVE_HANDOFF_CAPABILITY,
            ))
        }
        _ => (),
    }
    Ok(sample)
}

pub(super) fn observe(
    machine: &mut Machine,
    mut sample: ObservationEnvelope,
    scope: &DisplayRecoveryScope,
) -> Result<ObservationEnvelope, ProviderError> {
    let unavailable =
        || ProviderError::Unavailable("simulated first ordinary frame unavailable".into());
    let (started, deadline) = machine.native_handoff_window.ok_or_else(unavailable)?;
    if machine.finalization_native_phase != 6 {
        return Err(unavailable());
    }
    let now = sample.observed_at_unix_ms;
    let elapsed = now.checked_sub(started).ok_or_else(unavailable)?;
    let window = DisplayNativeHandoffWindow {
        observed_unix_ms: now,
        observed_boot_ms: 100_000 + elapsed,
        deadline_unix_ms: deadline,
        deadline_boot_ms: 100_000 + (deadline - started),
    };
    let valid_for_ms = window.valid_for_ms().map_err(|_| unavailable())?;
    let terminal = machine
        .finalization_binding
        .as_ref()
        .ok_or_else(unavailable)?;
    let restoration = machine
        .restoration_binding
        .as_ref()
        .ok_or_else(unavailable)?;
    let material = linura_core::DisplayFinalizationMaterial::decode(
        machine
            .finalization_material
            .as_deref()
            .ok_or_else(unavailable)?,
    )
    .map_err(|_| unavailable())?;
    let current = DisplayObservationFacts::from_envelope(&sample, scope.replacement(), now)
        .map_err(|_| unavailable())?;
    let frames = value(DisplayNativeHandoffFacts::new(
        scope.clone(),
        DisplayNativeHandoffLineage {
            checkpoint: material.restoration().original_checkpoint().into(),
            restoration_transaction: restoration.transaction_id.clone(),
            restoration_effect: restoration.effect_digest.to_hex(),
            restoration_dispatch: restoration.dispatch_digest.to_hex(),
            terminal_transaction: terminal.transaction_id.clone(),
            terminal_effect: terminal.effect_digest.to_hex(),
            terminal_dispatch: terminal.dispatch_digest.to_hex(),
            terminal_link: material.terminal_link().into(),
            source_guard: material.restored_source_guard().into(),
            post_write_epoch: material.post_write_epoch(),
            security_epoch: 1,
        },
        window,
        current
            .inventory()
            .outputs()
            .iter()
            .cloned()
            .map(|output| {
                (
                    output,
                    DisplayNativeHandoffOutput {
                        enabled: true,
                        connector: 5,
                        crtc: 7,
                        plane: 8,
                        framebuffer: 43,
                        spend_high_water: 99,
                        completed_commit: 100,
                    },
                )
            })
            .collect(),
    ));
    sample.resource = value(scope.resource_id());
    sample.capability = value(CapabilityId::new(
        linura_observation::DISPLAY_NATIVE_HANDOFF_CAPABILITY,
    ));
    sample.valid_for_ms = valid_for_ms;
    sample.attributes = frames.attributes();
    machine.native_handoff_reads += 1;
    match machine.native_handoff_fault {
        1 => {
            sample
                .attributes
                .insert("source_guard".into(), ObservedValue::Text("a".repeat(64)));
        }
        2 => {
            sample.attributes.insert(
                "terminal_dispatch".into(),
                ObservedValue::Text("b".repeat(64)),
            );
        }
        3 => {
            sample.attributes.insert(
                "restoration_transaction".into(),
                ObservedValue::Text("transaction:foreign".into()),
            );
        }
        4 => {
            sample
                .attributes
                .insert("output.0.completed_commit".into(), ObservedValue::U64(99));
        }
        5 => {
            sample.authority = ObservationAuthority::SyntheticTest;
        }
        6 => {
            sample.valid_for_ms = 2000;
        }
        7 if machine.native_handoff_reads > 1 => {
            sample
                .attributes
                .insert("output.0.framebuffer".into(), ObservedValue::U64(44));
        }
        8 if machine.native_handoff_reads > 1 => {
            sample.attributes.insert(
                "deadline_boot_ms".into(),
                ObservedValue::U64(window.deadline_boot_ms + 1),
            );
        }
        9 => {
            sample
                .attributes
                .insert("native_ack".into(), ObservedValue::Bool(true));
        }
        _ => (),
    }
    Ok(sample)
}

#[derive(Debug)]
struct RootPort(Arc<Mutex<Machine>>, bool, u8);

// An ACK-only adapter deliberately performs no physical retirement. Control
// must retain uncertainty rather than treating this reply as ReleasedCurrent.
#[derive(Debug, Default)]
struct CompletionPort {
    calls: usize,
    lose_reply: bool,
    machine: Option<Arc<Mutex<Machine>>>,
}
impl OriginalDisplayCompletionPort for CompletionPort {
    fn dispatch_completion(
        &mut self,
        completion: AuthorizedOriginalDisplayCompletion,
    ) -> Result<(), String> {
        self.calls += 1;
        assert!(completion.expires_at_unix_ms() > now_unix_ms());
        assert_eq!(completion.terminal().state, TransactionState::Indeterminate);
        assert_eq!(
            completion.frames().lineage().terminal_transaction,
            completion.terminal().transaction_id.as_str()
        );
        assert_eq!(
            completion.frames().lineage().terminal_dispatch,
            completion.dispatch_digest()
        );
        assert_ne!(
            completion.preparation_digest(),
            completion.verification_digest()
        );
        if let Some(machine) = &self.machine {
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .current_completion = Some(value(
                linura_observation::DisplayOriginalCompletionFacts::new(
                    linura_observation::DisplayCompletionLineage {
                        record: "7".repeat(64),
                        preparation: completion.preparation_digest().hex().into(),
                        verification: completion.verification_digest().hex().into(),
                        material: completion.material().into(),
                    },
                    completion.frames().clone(),
                ),
            ));
        }
        if self.lose_reply {
            Err("simulated missing completion acknowledgement".into())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct PowerPort {
    machine: Arc<Mutex<Machine>>,
    calls: usize,
    lose_reply: bool,
    effect: bool,
}
impl linura_control::OriginalDisplayNativePowerRetirementPort for PowerPort {
    fn retire_native_power(
        &mut self,
        prepared: linura_control::AuthorizedOriginalDisplayNativePowerRetirement,
    ) -> Result<(), String> {
        self.calls += 1;
        assert!(prepared.expires_at_unix_ms() > now_unix_ms());
        assert!(prepared.frames().input_retired() && prepared.frames().power_fence_held());
        assert_eq!(
            prepared.frames().completion_digest(),
            prepared.root().lineage().record
        );
        let mut state = self
            .machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert!(state.power_grant.is_none());
        state.power_grant = Some(value(
            linura_observation::DisplayOriginalPowerRetirementFacts::new(
                prepared.frames().scope().clone(),
                "9".repeat(64),
                prepared.root().lineage().record.clone(),
                prepared.preparation().hex().into(),
                prepared.checkpoint().hex().into(),
                true,
            ),
        ));
        state.native_power_retired = self.effect;
        if self.lose_reply {
            Err("simulated lost power ACK".into())
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct RootPowerPort {
    machine: Arc<Mutex<Machine>>,
    calls: usize,
    lose_reply: bool,
    effect: bool,
}
impl linura_control::OriginalDisplayRootPowerRetirementPort for RootPowerPort {
    fn retire_root_power(
        &mut self,
        prepared: linura_control::AuthorizedOriginalDisplayRootPowerRetirement,
    ) -> Result<(), String> {
        self.calls += 1;
        assert!(prepared.expires_at_unix_ms() > now_unix_ms());
        assert!(prepared.frames().input_retired() && !prepared.frames().power_fence_held());
        assert_eq!(
            prepared.power().completion_digest(),
            prepared.root().lineage().record
        );
        let mut state = self
            .machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert!(state.native_power_retired && !state.root_power_retired);
        if self.effect {
            state.root_retirement = Some(value(
                linura_observation::DisplayOriginalRootRetirementFacts::new(
                    linura_observation::DisplayRootRetirementLineage {
                        record: "6".repeat(64),
                        preparation: prepared.preparation().hex().into(),
                        verification: prepared.verification().hex().into(),
                        power_record: prepared.power().record_digest().into(),
                    },
                    state
                        .last_original_protection
                        .clone()
                        .unwrap_or_else(|| unreachable!("original source comparison")),
                    prepared.root().clone(),
                    None,
                ),
            ));
            state.root_power_retired = true;
        }
        if self.lose_reply {
            Err("simulated lost Root power ACK".into())
        } else {
            Ok(())
        }
    }
}
#[test]
fn root_power_requires_original_review_and_independent_retired_phase() {
    for (lost_reply, effect, fault) in [
        (false, true, 0),
        (true, true, 0),
        (false, false, 0),
        (false, true, 1),
        (false, true, 2),
        (false, true, 3),
    ] {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (mut control, original, input, request) = prepared(&database, &machine);
        let transaction =
            TransactionId::for_namespace(&value(PrincipalId::new(principal().as_str())), &request);
        let before = snapshot(&database, &transaction);
        value(control.spend_original_display_native_release(
            principal(),
            actor(true),
            &request,
            &mut RootPort(machine.clone(), false, 0),
        ));
        let mut completion = CompletionPort {
            machine: Some(machine.clone()),
            ..CompletionPort::default()
        };
        value(control.dispatch_original_display_completion(
            principal(),
            actor(true),
            &request,
            &mut completion,
        ));
        let mut native = PowerPort {
            machine: machine.clone(),
            calls: 0,
            lose_reply: false,
            effect: true,
        };
        value(control.dispatch_original_display_native_power_retirement(
            principal(),
            actor(true),
            &request,
            &mut native,
        ));
        let mut port = RootPowerPort {
            machine: machine.clone(),
            calls: 0,
            lose_reply: lost_reply,
            effect,
        };
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .root_power_write_fault = fault;
        assert!(
            control
                .dispatch_original_display_root_power_retirement(
                    principal(),
                    actor(false),
                    &request,
                    &mut port
                )
                .is_err()
        );
        assert_eq!(port.calls, 0);
        let result = control.dispatch_original_display_root_power_retirement(
            principal(),
            actor(true),
            &request,
            &mut port,
        );
        assert_eq!(result.is_err(), lost_reply || fault != 0, "{result:?}");
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .root_power_write_fault = 0;
        assert!(
            control
                .dispatch_original_display_root_power_retirement(
                    principal(),
                    actor(true),
                    &request,
                    &mut port
                )
                .is_err()
        );
        assert_eq!(port.calls, usize::from(fault == 0));
        let inspection =
            control.inspect_original_display_root_power_retirement(principal(), &request);
        assert_eq!(inspection.is_ok(), effect && fault == 0, "{inspection:?}");
        if let Ok(inspection) = inspection {
            assert!(!inspection.current().frames().power_fence_held());
            assert_eq!(
                inspection.root().completion_comparison().lineage().record,
                inspection.current().frames().completion_digest()
            );
        }
        assert_eq!(snapshot(&database, &transaction), before);
        drop(control);
        let previews = replacement_previews(&machine, &original, &input);
        let mut restarted = open_with_previews(database.path(), &machine, 0, previews);
        assert!(
            restarted
                .dispatch_original_display_root_power_retirement(
                    principal(),
                    actor(true),
                    &request,
                    &mut port
                )
                .is_err()
        );
        assert_eq!(port.calls, usize::from(fault == 0));
        assert_eq!(
            restarted
                .inspect_original_display_root_power_retirement(principal(), &request)
                .is_ok(),
            effect && fault == 0
        );
        if effect && fault == 0 {
            assert!(
                restarted
                    .inspect_original_display_native_power_retirement(principal(), &request)
                    .is_err()
            );
            for fault in 1..=12 {
                if fault == 2 {
                    continue;
                }
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                    .current_fault = fault;
                assert!(
                    restarted
                        .inspect_original_display_root_power_retirement(principal(), &request)
                        .is_err(),
                    "post-Root fault {fault}"
                );
            }
        }
        assert_eq!(snapshot(&database, &transaction), before);
    }
}

#[test]
fn current_completion_is_signed_durable_and_recovers_metadata_without_replaying_effects() {
    for (kind, fault) in [
        (0, 0),
        (1, 1),
        (1, 2),
        (1, 3),
        (2, 1),
        (2, 2),
        (2, 3),
        (3, 1),
        (3, 2),
        (3, 3),
    ] {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (mut control, original, input, request) = prepared(&database, &machine);
        let transaction =
            TransactionId::for_namespace(&value(PrincipalId::new(principal().as_str())), &request);
        value(control.spend_original_display_native_release(
            principal(),
            actor(true),
            &request,
            &mut RootPort(machine.clone(), false, 0),
        ));
        let mut completion = CompletionPort {
            machine: Some(machine.clone()),
            ..CompletionPort::default()
        };
        value(control.dispatch_original_display_completion(
            principal(),
            actor(true),
            &request,
            &mut completion,
        ));
        let mut native = PowerPort {
            machine: machine.clone(),
            calls: 0,
            lose_reply: false,
            effect: true,
        };
        value(control.dispatch_original_display_native_power_retirement(
            principal(),
            actor(true),
            &request,
            &mut native,
        ));
        let mut root = RootPowerPort {
            machine: machine.clone(),
            calls: 0,
            lose_reply: true,
            effect: true,
        };
        assert!(
            control
                .dispatch_original_display_root_power_retirement(
                    principal(),
                    actor(true),
                    &request,
                    &mut root
                )
                .is_err()
        );
        {
            let mut state = machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"));
            state.completion_write_key = kind;
            state.completion_write_fault = fault;
        }
        let result = control.commit_original_display_current(principal(), actor(true), &request);
        assert_eq!(
            result.is_err(),
            fault != 0,
            "{result:?}; key {kind} fault {fault}"
        );
        assert_eq!(
            snapshot(&database, &transaction).state,
            match kind {
                1 => TransactionState::Indeterminate,
                2 => TransactionState::Verified,
                _ => TransactionState::Committed,
            }
        );
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .completion_write_fault = 0;
        drop(control);
        let previews = replacement_previews(&machine, &original, &input);
        let mut restarted = open_with_previews(database.path(), &machine, 0, previews);
        let released =
            value(restarted.commit_original_display_current(principal(), actor(true), &request));
        assert_eq!(released.terminal().state, TransactionState::Committed);
        assert_eq!(&snapshot(&database, &transaction), released.terminal());
        let digest = released.record_digest().clone();
        let first = released.first_committed_at_unix_ms();
        let again =
            value(restarted.commit_original_display_current(principal(), actor(true), &request));
        assert_eq!(again.record_digest(), &digest);
        assert_eq!(again.first_committed_at_unix_ms(), first);
        let current =
            value(restarted.inspect_original_display_root_power_retirement(principal(), &request));
        assert_eq!(
            current.current().terminal().state,
            TransactionState::Committed
        );
        assert_eq!(
            current.current().comparison_terminal().state,
            TransactionState::Indeterminate
        );
        assert!(
            restarted
                .dispatch_original_display_root_power_retirement(
                    principal(),
                    actor(true),
                    &request,
                    &mut root
                )
                .is_err()
        );
        assert!(
            restarted
                .dispatch_original_display_native_power_retirement(
                    principal(),
                    actor(true),
                    &request,
                    &mut native
                )
                .is_err()
        );
        assert_eq!(root.calls, 1);
        assert_eq!(native.calls, 1);
        assert_eq!(completion.calls, 1);
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .original_protection_lost = true;
        assert!(
            restarted
                .commit_original_display_current(principal(), actor(true), &request)
                .is_err()
        );
        assert_eq!(
            snapshot(&database, &transaction).state,
            TransactionState::Committed
        );
    }
}
#[derive(Debug)]
struct CurrentCommitPort {
    machine: Arc<Mutex<Machine>>,
    calls: usize,
    fault: u8,
}
impl linura_control::OriginalDisplayCurrentCommitPort for CurrentCommitPort {
    fn commit_current(
        &mut self,
        prepared: linura_control::AuthorizedOriginalDisplayCurrentCommit,
    ) -> Result<(), String> {
        self.calls += 1;
        assert_eq!(self.calls, 1);
        assert_eq!(
            prepared.committed().terminal().state,
            TransactionState::Committed
        );
        assert!(prepared.expires_at_unix_ms() > now_unix_ms());
        assert!(prepared.frames().input_retired() && !prepared.frames().power_fence_held());
        let mut state = self
            .machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert!(state.root_power_retired && state.native_current_grant.is_none());
        let old = state
            .root_retirement
            .as_ref()
            .unwrap_or_else(|| unreachable!("Root phase"));
        if self.fault != 3 {
            state.root_retirement = Some(value(
                linura_observation::DisplayOriginalRootRetirementFacts::new(
                    old.lineage().clone(),
                    old.original_comparison().clone(),
                    old.completion_comparison().clone(),
                    Some(linura_observation::DisplayCurrentGrantLineage {
                        record: "5".repeat(64),
                        preparation: prepared.preparation().hex().into(),
                        committed_record: if self.fault == 4 {
                            "9".repeat(64)
                        } else {
                            prepared.committed().record_digest().hex().into()
                        },
                    }),
                ),
            ));
        }
        if self.fault != 2 {
            state.native_current_grant = Some("5".repeat(64));
        }
        if self.fault == 1 {
            Err("simulated lost native qualification ACK".into())
        } else {
            Ok(())
        }
    }
}
fn retained_recovery_bytes(
    database: &TestDatabase,
    machine: &Arc<Mutex<Machine>>,
) -> Vec<(PrincipalId, RequestId, Vec<u8>)> {
    let keys = machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"))
        .journal_keys
        .clone();
    let journal = value(
        linura_persistence_sqlite::SqliteApprovedRequestJournal::open(
            database.path().with_extension("requests.sqlite3"),
            value(SqliteIntegrityKey::new(fixture_key(6))),
        ),
    );
    value(journal.integrity_check());
    keys.into_iter()
        .filter_map(|(principal, request)| {
            match journal.load(&principal, &request) {
                Ok(record) => Some((principal, request, record.canonical().to_vec())),
                Err(TransactionStoreError::NotFound) => None, // A failed before-write reservation.
                Err(error) => unreachable!("{error}"),
            }
        })
        .collect()
}
fn committed_is_not_competing_apply_or_cleanup_authority(
    control: &mut ManagedLifecycleControl<SqliteTransactionStore>,
    database: &TestDatabase,
    machine: &Arc<Mutex<Machine>>,
) {
    let retained = retained_recovery_bytes(database, machine);
    let (state, sampled, applies, decisions) = {
        let mut native = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        let state = native.state;
        native.state = None; // Even an idle/replaced native must not admit it.
        (state, native.sequence, native.applies, native.decisions)
    };
    for replacement in [false, true] {
        let mut competing = display_request("competing-with-current-committed");
        if replacement {
            let old = "11223344-1234-4567-89ab-0123456789ab";
            let new = "33445566-1234-4567-89ab-0123456789ab";
            competing.resource = value(ResourceId::new(
                competing.resource.as_str().replace(old, new),
            ));
            let material = competing
                .desired_state
                .get_mut("layout")
                .unwrap_or_else(|| unreachable!("layout"));
            *material = material.replace(old, new);
            competing.request_id = value(managed_request_id("competing-successor", &competing));
        }
        let result = control.begin_display_layout(
            principal(),
            actor(true),
            competing,
            &approval(),
            &mut Port(machine.clone()),
            &mut Verifier(machine.clone()),
        );
        assert!(
            matches!(result, Err(ManagedLifecycleError::Indeterminate(ref reason)) if reason.contains("completion ownership remains retained")),
            "{result:?}"
        );
    }
    let mut native = machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"));
    assert_eq!(
        (native.sequence, native.applies, native.decisions),
        (sampled, applies, decisions)
    );
    native.state = state;
    drop(native);
    // Compare every retained intent/checkpoint/proof byte, not just row count.
    assert_eq!(retained_recovery_bytes(database, machine), retained);
}
#[test]
fn current_qualification_requires_original_review_and_independent_matching_root_and_native_sources()
{
    for fault in 0..12 {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (mut control, original, input, request) = prepared(&database, &machine);
        value(control.spend_original_display_native_release(
            principal(),
            actor(true),
            &request,
            &mut RootPort(machine.clone(), false, 0),
        ));
        let mut completion = CompletionPort {
            machine: Some(machine.clone()),
            ..CompletionPort::default()
        };
        value(control.dispatch_original_display_completion(
            principal(),
            actor(true),
            &request,
            &mut completion,
        ));
        let mut native = PowerPort {
            machine: machine.clone(),
            calls: 0,
            lose_reply: false,
            effect: true,
        };
        value(control.dispatch_original_display_native_power_retirement(
            principal(),
            actor(true),
            &request,
            &mut native,
        ));
        let mut root = RootPowerPort {
            machine: machine.clone(),
            calls: 0,
            lose_reply: false,
            effect: true,
        };
        value(control.dispatch_original_display_root_power_retirement(
            principal(),
            actor(true),
            &request,
            &mut root,
        ));
        value(control.commit_original_display_current(principal(), actor(true), &request));
        committed_is_not_competing_apply_or_cleanup_authority(&mut control, &database, &machine);
        assert!(
            control
                .verify_original_display_qualified_current(principal(), &request)
                .is_err()
        );
        if fault >= 6 {
            let mut state = machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"));
            state.completion_write_key = if fault < 9 { 4 } else { 5 };
            state.completion_write_fault = (fault - 6) % 3 + 1;
        }
        let mut port = CurrentCommitPort {
            machine: machine.clone(),
            calls: 0,
            fault,
        };
        if fault == 5 {
            drop(control);
            let previews = replacement_previews(&machine, &original, &input);
            control = open_with_previews(database.path(), &machine, 0, previews);
        }
        let dispatched = control.dispatch_original_display_current_commit(
            principal(),
            actor(true),
            &request,
            &mut port,
        );
        assert_eq!(
            dispatched.is_err(),
            fault == 1 || (5..9).contains(&fault),
            "{dispatched:?}; fault {fault}"
        );
        assert!(
            control
                .dispatch_original_display_current_commit(
                    principal(),
                    actor(true),
                    &request,
                    &mut port
                )
                .is_err()
        );
        assert_eq!(port.calls, usize::from(!(5..9).contains(&fault)));
        committed_is_not_competing_apply_or_cleanup_authority(&mut control, &database, &machine);
        drop(control);
        let previews = replacement_previews(&machine, &original, &input);
        let mut restarted = open_with_previews(database.path(), &machine, 0, previews);
        committed_is_not_competing_apply_or_cleanup_authority(&mut restarted, &database, &machine);
        if fault >= 9 {
            assert!(
                restarted
                    .verify_original_display_qualified_current(principal(), &request)
                    .is_err()
            );
        }
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .completion_write_fault = 0;
        let proof = restarted.verify_original_display_qualified_current(principal(), &request);
        if matches!(fault, 0 | 1 | 9..=11) {
            let proof = value(proof);
            let digest = proof.record_digest().clone();
            let first = proof.first_verified_at_unix_ms();
            let next =
                value(restarted.verify_original_display_qualified_current(principal(), &request));
            assert_eq!(next.record_digest(), &digest);
            assert_eq!(next.first_verified_at_unix_ms(), first);
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .original_protection_lost = true;
            assert!(
                restarted
                    .verify_original_display_qualified_current(principal(), &request)
                    .is_err()
            );
        } else {
            assert!(proof.is_err(), "fault {fault}");
        }
        assert!(
            restarted
                .dispatch_original_display_current_commit(
                    principal(),
                    actor(true),
                    &request,
                    &mut port
                )
                .is_err()
        );
        assert_eq!(port.calls, usize::from(!(5..9).contains(&fault)));
        assert_eq!(root.calls, 1);
        assert_eq!(native.calls, 1);
        assert_eq!(completion.calls, 1);
    }
}
#[derive(Debug)]
struct FinalRetirementPort {
    machine: Arc<Mutex<Machine>>,
    calls: usize,
    fault: u8,
}
impl linura_control::OriginalDisplayFinalRetirementPort for FinalRetirementPort {
    fn retire_current(
        &mut self,
        prepared: linura_control::AuthorizedOriginalDisplayFinalRetirement,
    ) -> Result<(), String> {
        self.calls += 1;
        assert_eq!(self.calls, 1);
        assert!(prepared.frames().current_commit_digest().is_some());
        assert!(prepared.frames().final_retirement_digest().is_none());
        assert!(prepared.expires_at_unix_ms() > now_unix_ms());
        let mut state = self
            .machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        let grant = prepared
            .root()
            .current_grant()
            .unwrap_or_else(|| unreachable!("qualified"));
        if self.fault != 3 {
            state.final_retirement = Some(value(
                linura_observation::DisplayOriginalFinalRetirementFacts::new(
                    prepared.frames().scope().clone(),
                    linura_observation::DisplayFinalRetirementLineage {
                        record: "6".repeat(64),
                        preparation: prepared.preparation().hex().into(),
                        verification: if self.fault == 4 {
                            "9".repeat(64)
                        } else {
                            prepared.qualification().hex().into()
                        },
                        current_grant: grant.record.clone(),
                        committed_record: grant.committed_record.clone(),
                    },
                    2,
                    None,
                ),
            ));
        }
        if self.fault != 2 {
            state.native_final_retirement = Some("6".repeat(64));
        }
        if self.fault == 1 {
            Err("simulated lost final retirement ACK".into())
        } else {
            Ok(())
        }
    }
}
#[derive(Debug)]
struct ReleasedCurrentPort {
    machine: Arc<Mutex<Machine>>,
    calls: usize,
    fault: u8,
}
impl linura_control::OriginalDisplayReleasedCurrentPort for ReleasedCurrentPort {
    fn complete_released_current(
        &mut self,
        completed: linura_control::OriginalDisplayReleasedCurrentCompletion,
    ) -> Result<(), String> {
        self.calls += 1;
        let mut state = self
            .machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_eq!(
            state.native_final_retirement.as_deref(),
            Some(completed.final_record().to_hex().as_str())
        );
        let old = state
            .final_retirement
            .as_ref()
            .unwrap_or_else(|| unreachable!("Root final"));
        if self.fault != 11 {
            state.final_retirement = Some(value(
                linura_observation::DisplayOriginalFinalRetirementFacts::new(
                    completed.scope().clone(),
                    old.lineage().clone(),
                    3,
                    Some(linura_observation::DisplayReleasedCurrentLineage {
                        record: "7".repeat(64),
                        verification: completed.verification().hex().into(),
                    }),
                ),
            ));
        }
        if self.fault == 10 {
            Err("simulated lost metadata ACK".into())
        } else {
            Ok(())
        }
    }
}
#[test]
fn final_retirement_requires_original_review_independent_postconditions_and_durable_completion() {
    for fault in 0..=13 {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (mut control, original, input, request) = prepared(&database, &machine);
        value(control.spend_original_display_native_release(
            principal(),
            actor(true),
            &request,
            &mut RootPort(machine.clone(), false, 0),
        ));
        let mut completion = CompletionPort {
            machine: Some(machine.clone()),
            ..CompletionPort::default()
        };
        value(control.dispatch_original_display_completion(
            principal(),
            actor(true),
            &request,
            &mut completion,
        ));
        let mut native = PowerPort {
            machine: machine.clone(),
            calls: 0,
            lose_reply: false,
            effect: true,
        };
        value(control.dispatch_original_display_native_power_retirement(
            principal(),
            actor(true),
            &request,
            &mut native,
        ));
        let mut root = RootPowerPort {
            machine: machine.clone(),
            calls: 0,
            lose_reply: false,
            effect: true,
        };
        value(control.dispatch_original_display_root_power_retirement(
            principal(),
            actor(true),
            &request,
            &mut root,
        ));

        value(control.commit_original_display_current(principal(), actor(true), &request));
        if fault == 0 {
            let challenge = SuccessorApproval {
                machine: machine.clone(),
                calls: AtomicUsize::new(0),
            };
            let mut successor_port = SuccessorPort {
                calls: 0,
                machine: machine.clone(),
                attempt: None,
            };
            assert!(
                control
                    .begin_successor_display_layout(
                        principal(),
                        actor(true),
                        &request,
                        successor_request(&machine, "early-committed"),
                        &challenge,
                        &mut successor_port,
                        &mut Verifier(machine.clone())
                    )
                    .is_err()
            );
            assert_eq!(challenge.calls.load(Ordering::SeqCst), 0);
            assert_eq!(successor_port.calls, 0);
        }

        value(control.dispatch_original_display_current_commit(
            principal(),
            actor(true),
            &request,
            &mut CurrentCommitPort {
                machine: machine.clone(),
                calls: 0,
                fault: 0,
            },
        ));
        assert!(
            control
                .verify_original_display_final_retirement(principal(), &request)
                .is_err()
        );
        if fault == 5 {
            drop(control);
            control = open_with_previews(
                database.path(),
                &machine,
                0,
                replacement_previews(&machine, &original, &input),
            );
        }
        if (6..=8).contains(&fault) {
            let mut state = machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"));
            state.completion_write_key = 6;
            state.completion_write_fault = fault - 5;
        }
        let mut port = FinalRetirementPort {
            machine: machine.clone(),
            calls: 0,
            fault,
        };
        let result = control.dispatch_original_display_final_retirement(
            principal(),
            actor(true),
            &request,
            &mut port,
        );
        assert_eq!(
            result.is_err(),
            fault == 1 || (5..=8).contains(&fault),
            "fault {fault}: {result:?}"
        );
        assert!(
            control
                .dispatch_original_display_final_retirement(
                    principal(),
                    actor(true),
                    &request,
                    &mut port
                )
                .is_err()
        );
        assert_eq!(port.calls, usize::from(!(5..=8).contains(&fault)));
        committed_is_not_competing_apply_or_cleanup_authority(&mut control, &database, &machine);
        drop(control);
        let mut restarted = open_with_previews(
            database.path(),
            &machine,
            0,
            replacement_previews(&machine, &original, &input),
        );
        {
            let mut state = machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"));
            state.completion_write_fault = 0;
            if fault == 9 || fault == 12 {
                state.completion_write_key = 7;
                state.completion_write_fault = if fault == 9 { 2 } else { 3 };
            }
            if fault == 13 {
                state.completion_write_key = 8;
                state.completion_write_fault = 3;
            }
        }
        let verified = restarted.verify_original_display_final_retirement(principal(), &request);
        if matches!(fault, 2..=8) {
            assert!(verified.is_err(), "fault {fault}");
        } else {
            if matches!(fault, 9 | 12) {
                assert!(verified.is_err());
            }
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .completion_write_fault = if fault == 13 { 3 } else { 0 };
            let first =
                value(restarted.verify_original_display_final_retirement(principal(), &request));
            let second =
                value(restarted.verify_original_display_final_retirement(principal(), &request));
            assert_eq!(first.record_digest(), second.record_digest());
            assert_eq!(first.first_window(), second.first_window());
            let mut metadata = ReleasedCurrentPort {
                machine: machine.clone(),
                calls: 0,
                fault,
            };
            let completed = restarted.complete_original_display_released_current(
                principal(),
                &request,
                &mut metadata,
            );
            assert_eq!(
                completed.is_err(),
                matches!(fault, 10 | 11 | 13),
                "fault {fault}: {completed:?}"
            );
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .completion_write_fault = 0;
            metadata.fault = 0;
            let next = value(restarted.complete_original_display_released_current(
                principal(),
                &request,
                &mut metadata,
            ));
            if let Ok(old) = completed {
                assert_eq!(old.record_digest(), next.record_digest());
            }
            let count = metadata.calls;
            let again = value(restarted.complete_original_display_released_current(
                principal(),
                &request,
                &mut metadata,
            ));
            assert_eq!(again.record_digest(), next.record_digest());
            assert_eq!(metadata.calls, count);
            assert_eq!(count, if fault == 11 { 2 } else { 1 });
            committed_is_not_competing_apply_or_cleanup_authority(
                &mut restarted,
                &database,
                &machine,
            );
            if fault == 0 {
                successor_ack_loss_is_not_replayed(
                    &mut restarted,
                    &database,
                    &machine,
                    &original,
                    &input,
                    &request,
                );
            }
        }
        assert!(
            restarted
                .dispatch_original_display_final_retirement(
                    principal(),
                    actor(true),
                    &request,
                    &mut port
                )
                .is_err()
        );
        assert_eq!(port.calls, usize::from(!(5..=8).contains(&fault)));
    }
}

#[test]
fn native_power_requires_original_live_review_and_independent_post_effect_state() {
    for fault in 1..=3 {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (mut control, _, _, request) = prepared(&database, &machine);
        value(control.spend_original_display_native_release(
            principal(),
            actor(true),
            &request,
            &mut RootPort(machine.clone(), false, 0),
        ));
        let mut completion = CompletionPort {
            machine: Some(machine.clone()),
            ..CompletionPort::default()
        };
        value(control.dispatch_original_display_completion(
            principal(),
            actor(true),
            &request,
            &mut completion,
        ));
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .native_power_write_fault = fault;
        let mut port = PowerPort {
            machine: machine.clone(),
            calls: 0,
            lose_reply: false,
            effect: true,
        };
        assert!(
            control
                .dispatch_original_display_native_power_retirement(
                    principal(),
                    actor(true),
                    &request,
                    &mut port
                )
                .is_err()
        );
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .native_power_write_fault = 0;
        assert!(
            control
                .dispatch_original_display_native_power_retirement(
                    principal(),
                    actor(true),
                    &request,
                    &mut port
                )
                .is_err()
        );
        assert_eq!(
            port.calls, 0,
            "storage fault {fault} cannot dispatch or rearm"
        );
    }
    for (lost_completion, lost_power, effect) in [
        (false, false, true),
        (true, true, true),
        (false, false, false),
    ] {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (mut control, original, input, request) = prepared(&database, &machine);
        let transaction =
            TransactionId::for_namespace(&value(PrincipalId::new(principal().as_str())), &request);
        let before = snapshot(&database, &transaction);
        value(control.spend_original_display_native_release(
            principal(),
            actor(true),
            &request,
            &mut RootPort(machine.clone(), false, 0),
        ));
        let mut completion = CompletionPort {
            machine: Some(machine.clone()),
            lose_reply: lost_completion,
            ..CompletionPort::default()
        };
        let completion_started = std::time::Instant::now();
        let completed = control.dispatch_original_display_completion(
            principal(),
            actor(true),
            &request,
            &mut completion,
        );
        assert_eq!(
            completed.is_err(),
            lost_completion,
            "lost_completion={lost_completion}, lost_power={lost_power}, effect={effect}, elapsed={:?}: {completed:?}",
            completion_started.elapsed(),
        );
        let mut port = PowerPort {
            machine: machine.clone(),
            calls: 0,
            lose_reply: lost_power,
            effect,
        };
        // Caller provenance cannot replace authenticated interactive ownership.
        assert!(
            control
                .dispatch_original_display_native_power_retirement(
                    principal(),
                    actor(false),
                    &request,
                    &mut port
                )
                .is_err()
        );
        assert_eq!(port.calls, 0);
        assert_eq!(
            control
                .dispatch_original_display_native_power_retirement(
                    principal(),
                    actor(true),
                    &request,
                    &mut port
                )
                .is_err(),
            lost_power
        );
        assert_eq!(port.calls, 1);
        assert!(
            control
                .dispatch_original_display_native_power_retirement(
                    principal(),
                    actor(true),
                    &request,
                    &mut port
                )
                .is_err()
        );
        assert_eq!(port.calls, 1);
        let inspection =
            control.inspect_original_display_native_power_retirement(principal(), &request);
        assert_eq!(inspection.is_ok(), effect, "{inspection:?}");
        if let Ok(inspection) = inspection {
            assert!(!inspection.current().frames().power_fence_held());
            assert!(inspection.grant().grant_spent());
        }
        assert_eq!(snapshot(&database, &transaction), before);
        drop(control);
        let previews = replacement_previews(&machine, &original, &input);
        let mut restarted = open_with_previews(database.path(), &machine, 0, previews);
        assert!(
            restarted
                .dispatch_original_display_native_power_retirement(
                    principal(),
                    actor(true),
                    &request,
                    &mut port
                )
                .is_err()
        );
        assert_eq!(port.calls, 1);
        assert_eq!(
            restarted
                .inspect_original_display_native_power_retirement(principal(), &request)
                .is_ok(),
            effect
        );
        if effect {
            for fault in 1..=12 {
                // Power false is now the required postcondition, not fault #2.
                if fault == 2 {
                    continue;
                }
                machine
                    .lock()
                    .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                    .current_fault = fault;
                assert!(
                    restarted
                        .inspect_original_display_native_power_retirement(principal(), &request)
                        .is_err(),
                    "fault {fault}"
                );
            }
        }
        assert_eq!(snapshot(&database, &transaction), before);
    }
}
impl OriginalDisplayRetirementPreparationPort for RootPort {
    fn prepare_retirement(
        &mut self,
        preparation: AuthorizedOriginalDisplayRetirementPreparation,
    ) -> Result<(), String> {
        let mut machine = self
            .0
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_eq!(machine.finalization_native_phase, 2);
        assert_eq!(
            Some(preparation.material()),
            machine.finalization_material.as_deref()
        );
        assert!(preparation.expires_at_unix_ms() > now_unix_ms());
        machine.retirement_preparations += 1;
        machine.finalization_native_phase = if self.2 == 3 { 5 } else { 3 };
        Ok(())
    }
}
impl OriginalDisplayNativeReleaseReservationPort for RootPort {
    fn reserve_native_release(
        &mut self,
        reservation: AuthorizedOriginalDisplayNativeReleaseReservation,
    ) -> Result<(), String> {
        let mut machine = self
            .0
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_eq!(machine.finalization_native_phase, 3);
        assert_eq!(
            Some(reservation.material()),
            machine.finalization_material.as_deref()
        );
        assert!(reservation.expires_at_unix_ms() > now_unix_ms());
        machine.native_release_reservations += 1;
        machine.finalization_native_phase = if self.2 == 5 { 3 } else { 5 };
        Ok(())
    }
}
impl OriginalDisplayNativeReleaseSpendPort for RootPort {
    fn spend_native_release(
        &mut self,
        attempt: AuthorizedOriginalDisplayNativeReleaseSpend,
    ) -> Result<(), String> {
        let mut machine = self
            .0
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_eq!(machine.finalization_native_phase, 5);
        assert_eq!(
            Some(attempt.material()),
            machine.finalization_material.as_deref()
        );
        let now = now_unix_ms();
        assert!(attempt.expires_at_unix_ms() > now);
        machine.native_release_spends += 1;
        machine.finalization_native_phase = 6;
        machine.native_handoff_window = Some((now, attempt.expires_at_unix_ms().min(now + 2000)));
        if self.1 {
            Err("simulated lost native spend reply".into())
        } else {
            Ok(())
        }
    }
}

fn quiesced(
    database: &TestDatabase,
    machine: &Arc<Mutex<Machine>>,
) -> (
    ManagedLifecycleControl<SqliteTransactionStore>,
    PlanDesiredStateRequest,
    OriginalDisplayRestorationRequest,
    RequestId,
) {
    let (original, input) = prepare_original(database, machine);
    let previews = replacement_previews(machine, &original, &input);
    let mut control = open_with_previews(database.path(), machine, 0, previews);
    let restoration = value(control.begin_original_display_restoration(
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
    value(control.retire_original_display_restoration(
        principal(),
        actor(true),
        &restoration.request_id,
    ));
    let terminal = value(control.begin_original_display_finalization(
        principal(),
        actor(true),
        finalization_input(&restoration.request_id),
        &TerminalApproval(machine.clone(), 0),
        &mut TerminalPort(machine.clone()),
    ));
    machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"))
        .finalization_native_phase = 2;
    (control, original, input, terminal.request_id)
}

fn prepared(
    database: &TestDatabase,
    machine: &Arc<Mutex<Machine>>,
) -> (
    ManagedLifecycleControl<SqliteTransactionStore>,
    PlanDesiredStateRequest,
    OriginalDisplayRestorationRequest,
    RequestId,
) {
    let (mut control, original, input, request) = quiesced(database, machine);
    let mut root = RootPort(machine.clone(), false, 0);
    value(control.prepare_original_display_terminal_retirement(
        principal(),
        actor(true),
        &request,
        &mut root,
    ));
    value(control.prepare_original_display_native_release(
        principal(),
        actor(true),
        &request,
        &mut root,
    ));
    (control, original, input, request)
}

#[test]
fn restart_cannot_reconstruct_review_for_another_root_reservation_write() {
    for after_retirement in [false, true] {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (mut control, original, input, request) = quiesced(&database, &machine);
        if after_retirement {
            value(control.prepare_original_display_terminal_retirement(
                principal(),
                actor(true),
                &request,
                &mut RootPort(machine.clone(), false, 0),
            ));
        }
        drop(control);
        let previews = replacement_previews(&machine, &original, &input);
        let mut restarted = open_with_previews(database.path(), &machine, 0, previews);
        let sampled = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .sequence;
        let result = if after_retirement {
            restarted.prepare_original_display_native_release(
                principal(),
                actor(true),
                &request,
                &mut RootPort(machine.clone(), false, 0),
            )
        } else {
            restarted.prepare_original_display_terminal_retirement(
                principal(),
                actor(true),
                &request,
                &mut RootPort(machine.clone(), false, 0),
            )
        };
        assert!(
            matches!(result, Err(ManagedLifecycleError::ApprovalBoundary(_))),
            "{result:?}"
        );
        let state = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_eq!(state.sequence, sampled);
        assert_eq!(state.retirement_preparations, usize::from(after_retirement));
        assert_eq!(state.native_release_reservations, 0);
        assert_eq!(state.native_release_spends, 0);
    }
}

#[test]
fn original_native_handoff_verification_is_durable_and_expired_restart_cannot_replay() {
    for (lost_reply, lost_completion_reply) in [(false, false), (false, true), (true, false)] {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (mut control, original, input, request) = prepared(&database, &machine);
        let transaction =
            TransactionId::for_namespace(&value(PrincipalId::new(principal().as_str())), &request);
        let before = snapshot(&database, &transaction);
        let attempt = control.spend_original_display_native_release(
            principal(),
            actor(true),
            &request,
            &mut RootPort(machine.clone(), lost_reply, 0),
        );
        assert_eq!(attempt.is_err(), lost_reply, "{attempt:?}");
        let verification = match attempt {
            Ok(first) => first,
            Err(_) => value(
                control.verify_native_handoff_original_display_finalization(principal(), &request),
            ),
        };
        let digest = verification.record_digest().clone();
        let expires_at = verification.valid_until_unix_ms();
        assert_eq!(verification.inspection().terminal(), &before);
        assert_eq!(snapshot(&database, &transaction), before);
        let mut completion = CompletionPort {
            lose_reply: lost_completion_reply,
            machine: Some(machine.clone()),
            ..CompletionPort::default()
        };
        let window_before_completion = expires_at.saturating_sub(now_unix_ms());
        let completion_started = std::time::Instant::now();
        let attempted = control.dispatch_original_display_completion(
            principal(),
            actor(true),
            &request,
            &mut completion,
        );
        // Only a directly acknowledged spend can carry its ORIGINAL live
        // review forward. Read-only verification after a lost spend ACK
        // cannot reconstruct that authority, even in the same process.
        assert_eq!(
            attempted.is_ok(),
            !lost_reply && !lost_completion_reply,
            "{attempted:?}"
        );
        assert_eq!(
            completion.calls,
            usize::from(!lost_reply),
            "lost_reply={lost_reply}, lost_completion_reply={lost_completion_reply}, window_before_ms={window_before_completion}, elapsed={:?}, attempted={attempted:?}",
            completion_started.elapsed(),
        );
        if let Ok(receipt) = attempted {
            assert_eq!(receipt.request(), &request);
            assert_eq!(receipt.transaction(), &transaction);
        }
        assert!(
            control
                .dispatch_original_display_completion(
                    principal(),
                    actor(true),
                    &request,
                    &mut completion,
                )
                .is_err()
        );
        assert_eq!(completion.calls, usize::from(!lost_reply));
        // A completion ACK cannot retire a fence or sign terminal completion.
        assert_eq!(snapshot(&database, &transaction), before);
        let mut current_checkpoint = None;
        if !lost_reply {
            let current =
                value(control.inspect_current_original_display_completion(principal(), &request));
            assert_eq!(current.terminal(), &before);
            assert!(current.frames().input_retired() && current.frames().power_fence_held());
            let proof =
                value(control.verify_current_original_display_completion(principal(), &request));
            assert_eq!(proof.inspection().terminal(), &before);
            current_checkpoint = Some((
                proof.record_digest().clone(),
                proof.first_verified_unix_ms(),
                proof.first_proof_valid_until_unix_ms(),
            ));
            for fault in 1..=12 {
                {
                    let mut state = machine
                        .lock()
                        .unwrap_or_else(|_| unreachable!("fixture poisoned"));
                    state.current_fault = fault;
                    state.current_reads = 0;
                }
                assert!(
                    control
                        .verify_current_original_display_completion(principal(), &request)
                        .is_err(),
                    "fault {fault}"
                );
                assert_eq!(snapshot(&database, &transaction), before);
            }
            machine
                .lock()
                .unwrap_or_else(|_| unreachable!("fixture poisoned"))
                .current_fault = 0;
        } else {
            assert!(
                control
                    .verify_current_original_display_completion(principal(), &request)
                    .is_err()
            );
        }
        drop(control);
        let journal = value(
            linura_persistence_sqlite::SqliteApprovedRequestJournal::open(
                database.path().with_extension("requests.sqlite3"),
                value(SqliteIntegrityKey::new(fixture_key(6))),
            ),
        );
        let key = value(RequestId::new(format!(
            "request:v010:display-physical-verified:{}",
            linura_transaction::digest_bytes(
                "linura.display.original-physical-release-verified-key.v1",
                request.as_str().as_bytes()
            )
            .hex()
        )));
        let retained = value(journal.load(&value(PrincipalId::new(principal().as_str())), &key));
        assert_eq!(
            linura_transaction::digest_bytes(
                "linura.display.original-physical-release-verified.v1",
                retained.canonical()
            ),
            digest
        );
        drop(journal);
        let previews = replacement_previews(&machine, &original, &input);
        let mut restarted = open_with_previews(database.path(), &machine, 0, previews);
        assert!(
            restarted
                .dispatch_original_display_completion(
                    principal(),
                    actor(true),
                    &request,
                    &mut completion,
                )
                .is_err()
        );
        assert_eq!(completion.calls, usize::from(!lost_reply));
        // Deliberately expire the ORIGINAL retained window. Restart and a
        // durable verification record must not manufacture current evidence.
        let now = now_unix_ms();
        if now <= expires_at {
            std::thread::sleep(std::time::Duration::from_millis(expires_at - now + 1));
        }
        assert!(
            restarted
                .verify_native_handoff_original_display_finalization(principal(), &request)
                .is_err()
        );
        if !lost_reply {
            // Old immutable proof is comparison history, never renewed first-
            // frame evidence. A fresh current Root/native read may still be
            // inspected after restart and lost ACK, without any effect replay.
            let current =
                value(restarted.inspect_current_original_display_completion(principal(), &request));
            assert_eq!(current.terminal(), &before);
            let proof =
                value(restarted.verify_current_original_display_completion(principal(), &request));
            let retained = current_checkpoint
                .as_ref()
                .unwrap_or_else(|| unreachable!("first checkpoint"));
            assert_eq!(proof.record_digest(), &retained.0);
            assert_eq!(proof.first_verified_unix_ms(), retained.1);
            assert_eq!(proof.first_proof_valid_until_unix_ms(), retained.2);
            assert!(proof.valid_until_unix_ms() > now_unix_ms());
            assert_eq!(proof.inspection().terminal(), &before);
            assert_eq!(completion.calls, 1);
        }
        assert!(
            restarted
                .spend_original_display_native_release(
                    principal(),
                    actor(true),
                    &request,
                    &mut RootPort(machine.clone(), false, 0)
                )
                .is_err()
        );
        assert_eq!(snapshot(&database, &transaction), before);
        let state = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_eq!(
            (
                state.retirement_preparations,
                state.native_release_reservations,
                state.native_release_spends
            ),
            (1, 1, 1)
        );
        assert_eq!(state.finalization_native_phase, 6);
        assert_eq!(state.applies, 1);
        assert_eq!(state.restoration_calls, 1);
    }
}

#[test]
fn post_effect_proof_faults_do_not_commit_or_repeat_the_spent_handoff() {
    // Metadata-only Root writes still need independent exact-phase readback.
    // A false ACK must retain the spend exclusion and every physical fence.
    for wrong_phase in [3, 5] {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (mut control, _, _, request) = quiesced(&database, &machine);
        let transaction =
            TransactionId::for_namespace(&value(PrincipalId::new(principal().as_str())), &request);
        let before = snapshot(&database, &transaction);
        if wrong_phase == 5 {
            value(control.prepare_original_display_terminal_retirement(
                principal(),
                actor(true),
                &request,
                &mut RootPort(machine.clone(), false, 0),
            ));
        }
        let mut root = RootPort(machine.clone(), false, wrong_phase);
        for _ in 0..2 {
            let result = if wrong_phase == 3 {
                control.prepare_original_display_terminal_retirement(
                    principal(),
                    actor(true),
                    &request,
                    &mut root,
                )
            } else {
                control.prepare_original_display_native_release(
                    principal(),
                    actor(true),
                    &request,
                    &mut root,
                )
            };
            assert!(result.is_err(), "false Root ACK for phase {wrong_phase}");
        }
        assert_eq!(snapshot(&database, &transaction), before);
        let state = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_eq!(state.retirement_preparations, 1);
        assert_eq!(
            state.native_release_reservations,
            usize::from(wrong_phase == 5)
        );
        assert_eq!(state.native_release_spends, 0);
        assert_eq!(state.applies, 1);
        assert_eq!(state.restoration_calls, 1);
    }

    for fault in 1..=9 {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (mut control, _, _, request) = prepared(&database, &machine);
        let transaction =
            TransactionId::for_namespace(&value(PrincipalId::new(principal().as_str())), &request);
        let before = snapshot(&database, &transaction);
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .native_handoff_fault = fault;
        assert!(
            control
                .spend_original_display_native_release(
                    principal(),
                    actor(true),
                    &request,
                    &mut RootPort(machine.clone(), false, 0)
                )
                .is_err(),
            "fault {fault}"
        );
        assert!(
            control
                .spend_original_display_native_release(
                    principal(),
                    actor(true),
                    &request,
                    &mut RootPort(machine.clone(), false, 0)
                )
                .is_err()
        );
        assert_eq!(snapshot(&database, &transaction), before);
        let state = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert_eq!(state.native_release_spends, 1);
        assert!(
            state.native_handoff_reads >= if matches!(fault, 7 | 8) { 2 } else { 1 },
            "fault {fault} must exercise independent post-effect observation"
        );
        drop(state);
        let mut completion = CompletionPort::default();
        assert!(
            control
                .dispatch_original_display_completion(
                    principal(),
                    actor(true),
                    &request,
                    &mut completion,
                )
                .is_err()
        );
        assert_eq!(
            completion.calls, 0,
            "failed independent proof is not completion authority"
        );
    }
}

#[test]
fn verification_storage_failure_or_false_ack_keeps_terminal_indeterminate_and_spend_once() {
    for fault in 1..=3 {
        let database = TestDatabase::new();
        let machine = Arc::new(Mutex::new(Machine::default()));
        let (mut control, _, _, request) = prepared(&database, &machine);
        let transaction =
            TransactionId::for_namespace(&value(PrincipalId::new(principal().as_str())), &request);
        let before = snapshot(&database, &transaction);
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .native_verification_write_fault = fault;
        let result = control.spend_original_display_native_release(
            principal(),
            actor(true),
            &request,
            &mut RootPort(machine.clone(), false, 0),
        );
        assert!(matches!(
            result,
            Err(ManagedLifecycleError::Indeterminate(_))
        ));
        assert!(
            control
                .spend_original_display_native_release(
                    principal(),
                    actor(true),
                    &request,
                    &mut RootPort(machine.clone(), false, 0)
                )
                .is_err()
        );
        assert_eq!(snapshot(&database, &transaction), before);
        let state = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        assert!(state.native_handoff_reads >= 2);
        assert_eq!(state.native_release_spends, 1);
        drop(state);
        let journal = value(
            linura_persistence_sqlite::SqliteApprovedRequestJournal::open(
                database.path().with_extension("requests.sqlite3"),
                value(SqliteIntegrityKey::new(fixture_key(6))),
            ),
        );
        let key = value(RequestId::new(format!(
            "request:v010:display-physical-verified:{}",
            linura_transaction::digest_bytes(
                "linura.display.original-physical-release-verified-key.v1",
                request.as_str().as_bytes()
            )
            .hex()
        )));
        let stored = journal.load(&value(PrincipalId::new(principal().as_str())), &key);
        assert_eq!(stored.is_ok(), fault == 3);
    }
}

// This is Control/SQLite component evidence. The port deliberately reports an
// uncertain outcome; it does not manufacture a Root grant or physical success.
#[derive(Debug)]
struct SuccessorPort {
    calls: usize,
    machine: Arc<Mutex<Machine>>,
    attempt: Option<(ExecutionBinding, u64)>,
}
impl DisplayTransactionPort for SuccessorPort {
    fn dispatch_layout(
        &mut self,
        application: AuthorizedDisplayApplication,
        request: &PlanDesiredStateRequest,
        deadline: u64,
    ) -> Result<ExecutionOutcome, String> {
        let (authorization, guard, predecessor) = application.into_executor_request();
        let predecessor = predecessor.ok_or("successor has no sealed predecessor")?;
        let next = value(linura_core::DisplayLayoutMaterial::decode(
            &request.desired_state["layout"],
        ));
        assert_eq!(predecessor.replacement(), next.topology());
        assert_ne!(
            guard,
            linura_provider_sdk::ComponentDigest::from_bytes([0; 32])
        );
        let (effect, binding) = authorization.into_executor_request();
        assert_eq!(
            effect,
            value(linura_provider_sdk::display_layout_effect(
                &request.desired_state["layout"]
            ))
        );
        value(binding.validate_for(&effect));
        self.calls += 1;
        let mut machine = self
            .machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        let parent = machine
            .final_retirement
            .as_ref()
            .and_then(|v| v.completed())
            .ok_or("no simulated released parent")?
            .record
            .clone();
        machine.successor = Some(value(linura_observation::DisplaySuccessorFacts::new(
            predecessor,
            linura_observation::DisplaySuccessorLineage {
                record: "8".repeat(64),
                released_parent: parent,
                checkpoint: "9".repeat(64),
                native_guard: guard.to_hex(),
                transaction: binding.transaction_id.clone(),
                effect: binding.effect_digest.to_hex(),
                dispatch: binding.dispatch_digest.to_hex(),
            },
            true,
        )));
        self.attempt = Some((binding, deadline));
        Err("simulated lost successor acknowledgement".into())
    }
    fn observe_attempt(
        &mut self,
        query: &linura_control::DisplayAttemptQuery<'_>,
    ) -> Result<ObservationEnvelope, String> {
        let (binding, deadline) = self.attempt.as_ref().ok_or("no simulated successor")?;
        let mut machine = self
            .machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        if !machine.successor_native_available
            || query.transaction_id() != binding.transaction_id
            || query.dispatch_digest() != binding.dispatch_digest.to_hex()
            || query.deadline_unix_ms() != *deadline
        {
            return Err("no independent successor completion in this fixture".into());
        }
        machine.sequence += 1;
        Ok(ObservationEnvelope {
            provider: value(ProviderId::new("hyprland")),
            resource: value(ResourceId::new(format!(
                "display:attempt:{}",
                binding.transaction_id
            ))),
            capability: value(CapabilityId::new("display.layout-attempt.observe")),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: now_unix_ms(),
            valid_for_ms: 2000,
            sequence: machine.sequence,
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
                    ObservedValue::Text(query.request().resource.as_str().into()),
                ),
                (
                    "effect_digest".into(),
                    ObservedValue::Text(binding.effect_digest.to_hex()),
                ),
                (
                    "dispatch_digest".into(),
                    ObservedValue::Text(binding.dispatch_digest.to_hex()),
                ),
                ("deadline_unix_ms".into(), ObservedValue::U64(*deadline)),
                ("state".into(), ObservedValue::Text("pending".into())),
            ]),
        })
    }
    fn continue_layout(&mut self, _: AuthorizedDisplayContinuation) -> Result<(), String> {
        unreachable!("uncertain handoff cannot authorize a decision")
    }
}
#[derive(Debug)]
struct SuccessorApproval {
    machine: Arc<Mutex<Machine>>,
    calls: AtomicUsize,
}
impl ManagedApprovalAuthorizer for SuccessorApproval {
    fn authorize(
        &self,
        challenge: &ManagedApprovalChallenge,
    ) -> Result<TrustedHumanApproval, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let approved = approval().authorize(challenge)?;
        // The opaque next review covers the old ordinary frame. Reading that
        // old frame as current after approval must not be necessary or accepted.
        self.machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .current_fault = 1;
        Ok(approved)
    }
}
fn successor_request(machine: &Arc<Mutex<Machine>>, operation: &str) -> PlanDesiredStateRequest {
    let state = machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"));
    let text = state
        .restoration_material
        .as_ref()
        .unwrap_or_else(|| unreachable!("restored"));
    let restored = value(linura_core::DisplayRestorationMaterial::decode(text));
    let topology = restored.replacement().topology().clone();
    let output = value(DisplayOutputId::new(topology.clone(), 19, 3));
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
    let mut next = value(
        DisplayLayoutPlanRequest {
            request_id: value(RequestId::new(
                "request:v010:display-layout:successor-placeholder",
            )),
            baseline: layout(0),
            layout: layout(200),
            lock: restored.replacement().lock().clone(),
            reason: display_request("successor-reason").reason,
        }
        .desired_request(),
    );
    next.request_id = value(managed_request_id(operation, &next));
    next
}
fn successor_ack_loss_is_not_replayed(
    control: &mut ManagedLifecycleControl<SqliteTransactionStore>,
    database: &TestDatabase,
    machine: &Arc<Mutex<Machine>>,
    original: &PlanDesiredStateRequest,
    input: &OriginalDisplayRestorationRequest,
    predecessor: &RequestId,
) {
    let next = successor_request(machine, "same-invocation-successor");
    let approved = SuccessorApproval {
        machine: machine.clone(),
        calls: AtomicUsize::new(0),
    };
    let mut port = SuccessorPort {
        calls: 0,
        machine: machine.clone(),
        attempt: None,
    };
    let receipt = value(control.begin_successor_display_layout(
        principal(),
        actor(true),
        predecessor,
        next.clone(),
        &approved,
        &mut port,
        &mut Verifier(machine.clone()),
    ));
    assert_eq!(receipt.state, DisplayLayoutState::Indeterminate);
    assert_eq!(approved.calls.load(Ordering::SeqCst), 1);
    assert_eq!(port.calls, 1);
    let receipt = value(control.begin_successor_display_layout(
        principal(),
        actor(true),
        predecessor,
        next.clone(),
        &approved,
        &mut port,
        &mut Verifier(machine.clone()),
    ));
    assert_eq!(receipt.state, DisplayLayoutState::Indeterminate);
    assert_eq!(approved.calls.load(Ordering::SeqCst), 1);
    assert_eq!(port.calls, 1);
    let mut reopened = open_with_previews(
        database.path(),
        machine,
        0,
        replacement_previews(machine, original, input),
    );
    let receipt = value(reopened.begin_successor_display_layout(
        principal(),
        actor(true),
        predecessor,
        next.clone(),
        &approved,
        &mut port,
        &mut Verifier(machine.clone()),
    ));
    assert_eq!(receipt.state, DisplayLayoutState::Indeterminate);
    assert_eq!(approved.calls.load(Ordering::SeqCst), 1);
    assert_eq!(port.calls, 1);
    {
        let mut state = machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"));
        state.successor_native_available = true;
        state.desired = false; // Root + native ACK without independent desired state is insufficient.
    }
    assert_eq!(
        value(reopened.display_layout_status(
            principal(),
            actor(true),
            &next.request_id,
            &mut port,
            &mut Verifier(machine.clone())
        ))
        .state,
        DisplayLayoutState::Indeterminate
    );
    machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"))
        .desired = true;
    assert_eq!(
        value(reopened.display_layout_status(
            principal(),
            actor(true),
            &next.request_id,
            &mut port,
            &mut Verifier(machine.clone())
        ))
        .state,
        DisplayLayoutState::AwaitingConfirmation
    );
    let retained = retained_recovery_bytes(database, machine);
    for fault in 1..=14 {
        machine
            .lock()
            .unwrap_or_else(|_| unreachable!("fixture poisoned"))
            .successor_fault = fault;
        assert_eq!(
            value(reopened.display_layout_status(
                principal(),
                actor(true),
                &next.request_id,
                &mut port,
                &mut Verifier(machine.clone())
            ))
            .state,
            DisplayLayoutState::Indeterminate,
            "successor evidence fault {fault}"
        );
        assert_eq!(retained_recovery_bytes(database, machine), retained);
        assert_eq!(port.calls, 1);
    }
    machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"))
        .successor_fault = 0;
    assert_eq!(
        value(reopened.display_layout_status(
            principal(),
            actor(true),
            &next.request_id,
            &mut port,
            &mut Verifier(machine.clone())
        ))
        .state,
        DisplayLayoutState::AwaitingConfirmation
    );
    assert_eq!(retained_recovery_bytes(database, machine), retained);
    assert!(
        reopened
            .begin_successor_display_layout(
                principal(),
                actor(true),
                &original.request_id,
                next,
                &approved,
                &mut port,
                &mut Verifier(machine.clone())
            )
            .is_err()
    );
    machine
        .lock()
        .unwrap_or_else(|_| unreachable!("fixture poisoned"))
        .current_fault = 0;
    assert!(
        reopened
            .begin_successor_display_layout(
                principal(),
                actor(true),
                predecessor,
                successor_request(machine, "competing-same-predecessor"),
                &approved,
                &mut port,
                &mut Verifier(machine.clone())
            )
            .is_err()
    );
    assert_eq!(port.calls, 1);
}
