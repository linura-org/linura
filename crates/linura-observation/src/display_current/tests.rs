//! Synthetic canonical-envelope checks; never physical scanout qualification.
use super::*;
use linura_core::{CapabilityId, DisplayTopologyId, ProviderId, ResourceId};

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}
fn fixture() -> (DisplayNativeCurrentFacts, ObservationEnvelope) {
    let topology = value(DisplayTopologyId::from_resource(&value(ResourceId::new(
        "display:topology:11111111-1111-4111-8111-111111111111:1000:c3:99:seat0:44444444-4444-4444-8444-444444444444:1",
    ))));
    let scope = value(DisplayRecoveryScope::new(&"a".repeat(64), topology.clone()));
    let lineage = DisplayNativeHandoffLineage {
        checkpoint: "b".repeat(64),
        restoration_transaction: "transaction:restored".into(),
        restoration_effect: "c".repeat(64),
        restoration_dispatch: "d".repeat(64),
        terminal_transaction: "transaction:terminal".into(),
        terminal_effect: "e".repeat(64),
        terminal_dispatch: "f".repeat(64),
        terminal_link: "1".repeat(64),
        source_guard: "2".repeat(64),
        post_write_epoch: 3,
        security_epoch: 4,
    };
    let window = DisplayNativeHandoffWindow {
        observed_unix_ms: 1001,
        observed_boot_ms: 101,
        deadline_unix_ms: 1200,
        deadline_boot_ms: 300,
    };
    let outputs = BTreeMap::from([
        (
            value(DisplayOutputId::new(topology.clone(), 10, 1)),
            DisplayNativeCurrentOutput {
                enabled: true,
                connector: 5,
                crtc: 7,
                plane: 8,
                framebuffer: 42,
                handoff_commit: 90,
                completed_commit: 99,
            },
        ),
        (
            value(DisplayOutputId::new(topology, 20, 2)),
            DisplayNativeCurrentOutput {
                enabled: false,
                connector: 6,
                crtc: 0,
                plane: 0,
                framebuffer: 0,
                handoff_commit: 51,
                completed_commit: 51,
            },
        ),
    ]);
    let facts = value(DisplayNativeCurrentFacts::new(
        scope.clone(),
        lineage,
        window,
        outputs,
        "3".repeat(64),
        true,
        true,
        None,
    ));
    let envelope = ObservationEnvelope {
        provider: value(ProviderId::new(DISPLAY_PROVIDER)),
        resource: value(scope.resource_id()),
        capability: value(CapabilityId::new(DISPLAY_NATIVE_CURRENT_CAPABILITY)),
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms: window.observed_unix_ms,
        valid_for_ms: value(window.valid_for_ms()),
        sequence: 1,
        attributes: facts.attributes(),
    };
    (facts, envelope)
}

#[test]
fn current_scanout_is_closed_fresh_and_distinct_from_first_frame() {
    let (facts, envelope) = fixture();
    assert_eq!(
        value(DisplayNativeCurrentFacts::from_envelope(
            &envelope,
            &facts.scope,
            1002
        )),
        facts
    );
    assert_eq!(facts.outputs().len(), 2);
    assert!(facts.input_retired() && facts.power_fence_held());
    assert!(DisplayNativeHandoffFacts::from_envelope(&envelope, &facts.scope, 1002).is_err());
    let mut relabelled = envelope.clone();
    relabelled.capability = value(CapabilityId::new(crate::DISPLAY_NATIVE_HANDOFF_CAPABILITY));
    assert!(DisplayNativeHandoffFacts::from_envelope(&relabelled, &facts.scope, 1002).is_err());
    for now in [0, 1000, 1200, u64::MAX] {
        assert!(DisplayNativeCurrentFacts::from_envelope(&envelope, &facts.scope, now).is_err());
    }
    for key in envelope.attributes.keys() {
        let mut changed = envelope.clone();
        changed.attributes.remove(key);
        assert!(
            DisplayNativeCurrentFacts::from_envelope(&changed, &facts.scope, 1002).is_err(),
            "{key}"
        );
    }
    for (key, value) in [
        ("released", ObservedValue::Bool(true)),
        ("completion_digest", ObservedValue::Text("0".repeat(64))),
        ("input_retired", ObservedValue::Text("true".into())),
        ("power_fence_held", ObservedValue::U64(1)),
        ("output.0.completed_commit", ObservedValue::U64(90)),
        ("output.1.completed_commit", ObservedValue::U64(52)),
        ("output.1.framebuffer", ObservedValue::U64(99)),
        ("output.1.connector", ObservedValue::U64(5)),
    ] {
        let mut changed = envelope.clone();
        changed.attributes.insert(key.into(), value);
        assert!(
            DisplayNativeCurrentFacts::from_envelope(&changed, &facts.scope, 1002).is_err(),
            "{key}"
        );
    }
}

#[test]
fn current_frames_may_advance_but_never_rebind_outputs_or_completion() {
    let (original, _) = fixture();
    let mut next = original.clone();
    next.window.observed_unix_ms += 1;
    next.window.observed_boot_ms += 1;
    next.window.deadline_unix_ms += 1;
    next.window.deadline_boot_ms += 1;
    let output = next
        .outputs
        .values_mut()
        .next()
        .unwrap_or_else(|| unreachable!("head"));
    output.completed_commit += 1;
    output.framebuffer += 1;
    assert!(next.reconciles(&original));
    for case in 0..12 {
        let mut changed = next.clone();
        let output = changed
            .outputs
            .values_mut()
            .next()
            .unwrap_or_else(|| unreachable!("head"));
        match case {
            0 => {
                output.completed_commit = original
                    .outputs
                    .values()
                    .next()
                    .unwrap_or_else(|| unreachable!("head"))
                    .completed_commit
            }
            1 => output.handoff_commit += 1,
            2 => output.connector += 10,
            3 => output.crtc += 1,
            4 => output.plane += 1,
            5 => changed.completion_digest = "4".repeat(64),
            6 => changed.input_retired = false,
            7 => changed.power_fence_held = false,
            8 => changed.window.observed_unix_ms = original.window.observed_unix_ms - 1,
            9 => changed.window.observed_boot_ms = original.window.observed_boot_ms - 1,
            10 => changed.lineage.security_epoch += 1,
            _ => changed.lineage.source_guard = "5".repeat(64),
        }
        assert!(!changed.reconciles(&original), "case {case}");
    }
}

#[test]
fn current_facts_follow_the_exact_original_handoff_boundary() {
    let (current, _) = fixture();
    let first = value(DisplayNativeHandoffFacts::new(
        current.scope.clone(),
        current.lineage.clone(),
        current.window,
        current
            .outputs
            .iter()
            .map(|(id, output)| {
                (
                    id.clone(),
                    crate::DisplayNativeHandoffOutput {
                        enabled: output.enabled,
                        connector: output.connector,
                        crtc: output.crtc,
                        plane: output.plane,
                        framebuffer: output.framebuffer,
                        spend_high_water: output.handoff_commit - 1,
                        completed_commit: output.handoff_commit,
                    },
                )
            })
            .collect(),
    ));
    assert!(current.follows_handoff(&first));
    let mut changed = current.clone();
    changed
        .outputs
        .values_mut()
        .next()
        .unwrap_or_else(|| unreachable!("head"))
        .handoff_commit -= 1;
    assert!(!changed.follows_handoff(&first));
    let mut changed = current.clone();
    changed.lineage.restoration_dispatch = "4".repeat(64);
    assert!(!changed.follows_handoff(&first));
}

#[test]
fn power_transition_comparison_never_weakens_same_phase_or_inventory_checks() {
    let (held, _) = fixture();
    let mut retired = held.clone();
    retired.power_fence_held = false;
    assert!(!retired.reconciles(&held));
    assert!(retired.follows_native_power_retirement(&held));
    assert!(!held.follows_native_power_retirement(&retired));
    assert!(!retired.follows_native_power_retirement(&retired));
    for fault in 0..5 {
        let mut wrong = retired.clone();
        match fault {
            0 => wrong.input_retired = false,
            1 => wrong.completion_digest = "4".repeat(64),
            2 => wrong.window.observed_boot_ms -= 1,
            3 => {
                wrong
                    .outputs
                    .values_mut()
                    .next()
                    .unwrap_or_else(|| unreachable!())
                    .completed_commit -= 1;
            }
            _ => {
                wrong
                    .outputs
                    .values_mut()
                    .next()
                    .unwrap_or_else(|| unreachable!())
                    .framebuffer += 1;
            }
        }
        assert!(!wrong.follows_native_power_retirement(&held));
    }
}
