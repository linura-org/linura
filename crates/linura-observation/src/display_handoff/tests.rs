//! Synthetic canonical-envelope checks; never physical scanout qualification.
use super::*;
use linura_core::{CapabilityId, DisplayTopologyId, ProviderId, ResourceId};

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}
fn fixture() -> (DisplayNativeHandoffFacts, ObservationEnvelope) {
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
            DisplayNativeHandoffOutput {
                enabled: true,
                connector: 5,
                crtc: 7,
                plane: 8,
                framebuffer: 42,
                spend_high_water: 90,
                completed_commit: 99,
            },
        ),
        (
            value(DisplayOutputId::new(topology, 20, 2)),
            DisplayNativeHandoffOutput {
                enabled: false,
                connector: 6,
                crtc: 0,
                plane: 0,
                framebuffer: 0,
                spend_high_water: 50,
                completed_commit: 51,
            },
        ),
    ]);
    let facts = value(DisplayNativeHandoffFacts::new(
        scope.clone(),
        lineage,
        window,
        outputs,
    ));
    let envelope = ObservationEnvelope {
        provider: value(ProviderId::new(DISPLAY_PROVIDER)),
        resource: value(scope.resource_id()),
        capability: value(CapabilityId::new(DISPLAY_NATIVE_HANDOFF_CAPABILITY)),
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms: window.observed_unix_ms,
        valid_for_ms: value(window.valid_for_ms()),
        sequence: 1,
        attributes: facts.attributes(),
    };
    (facts, envelope)
}

#[test]
fn ordinary_frame_projection_preserves_both_original_deadlines_and_exact_lineage() {
    let (facts, envelope) = fixture();
    assert_eq!(
        value(DisplayNativeHandoffFacts::from_envelope(
            &envelope,
            &facts.scope,
            1002
        )),
        facts
    );
    assert_eq!(envelope.valid_for_ms, 199);
    assert_eq!(facts.window().deadline_unix_ms, 1200);
    assert_eq!(facts.window().deadline_boot_ms, 300);
    assert_eq!(facts.lineage().terminal_dispatch, "f".repeat(64));
    assert_eq!(facts.outputs().len(), 2);
    for now in [0, 1000, 1200, u64::MAX] {
        assert!(DisplayNativeHandoffFacts::from_envelope(&envelope, &facts.scope, now).is_err());
    }
    let mut renewed = envelope.clone();
    renewed.valid_for_ms = 2000;
    assert!(DisplayNativeHandoffFacts::from_envelope(&renewed, &facts.scope, 1002).is_err());
    let mut boot_expiry = facts.window();
    boot_expiry.deadline_boot_ms = 200;
    assert_eq!(value(boot_expiry.valid_for_ms()), 99);
    for window in [
        DisplayNativeHandoffWindow {
            observed_unix_ms: 0,
            ..facts.window()
        },
        DisplayNativeHandoffWindow {
            observed_boot_ms: 0,
            ..facts.window()
        },
        DisplayNativeHandoffWindow {
            deadline_unix_ms: 1001,
            ..facts.window()
        },
        DisplayNativeHandoffWindow {
            deadline_boot_ms: 101,
            ..facts.window()
        },
        DisplayNativeHandoffWindow {
            deadline_unix_ms: 3002,
            ..facts.window()
        },
        DisplayNativeHandoffWindow {
            deadline_boot_ms: 2102,
            ..facts.window()
        },
    ] {
        assert!(window.valid_for_ms().is_err());
    }
}

#[test]
fn ordinary_projection_rejects_missing_mistyped_extra_ack_and_wrong_provider_fields() {
    let (facts, envelope) = fixture();
    let accepts = |e: &ObservationEnvelope| {
        DisplayNativeHandoffFacts::from_envelope(e, &facts.scope, 1002).is_ok()
    };
    for key in envelope.attributes.keys() {
        let mut missing = envelope.clone();
        missing.attributes.remove(key);
        assert!(!accepts(&missing), "missing {key}");
        let mut wrong = envelope.clone();
        wrong.attributes.insert(key.clone(), ObservedValue::I64(1));
        assert!(!accepts(&wrong), "mistyped {key}");
    }
    for case in 0..8 {
        let mut changed = envelope.clone();
        match case {
            0 => changed.authority = ObservationAuthority::SyntheticTest,
            1 => changed.sequence = 0,
            2 => changed.provider = value(ProviderId::new("hyprland-recovery")),
            3 => {
                changed.capability =
                    value(CapabilityId::new("display.original-presentation.observe"))
            }
            4 => changed.resource = value(facts.scope.replacement().resource_id()),
            5 => changed.valid_for_ms = 0,
            6 => changed.observed_at_unix_ms = u64::MAX,
            _ => {
                changed
                    .attributes
                    .insert("released".into(), ObservedValue::Bool(true));
            }
        }
        assert!(!accepts(&changed), "case {case}");
    }
}

#[test]
fn first_frame_requires_complete_physical_identity_and_fresh_commits_even_when_disabled() {
    let (facts, envelope) = fixture();
    for (key, changed) in [
        ("handoff_schema", ObservedValue::U64(2)),
        ("output_count", ObservedValue::U64(17)),
        ("post_write_epoch", ObservedValue::U64(0)),
        ("security_epoch", ObservedValue::U64(0)),
        ("original_dispatch", ObservedValue::Text("c".repeat(64))),
        ("source_guard", ObservedValue::Text("A".repeat(64))),
        (
            "terminal_transaction",
            ObservedValue::Text(facts.lineage.restoration_transaction.clone()),
        ),
        (
            "terminal_dispatch",
            ObservedValue::Text(facts.lineage.restoration_dispatch.clone()),
        ),
        ("restoration_dispatch", ObservedValue::Text("a".repeat(64))),
        ("terminal_dispatch", ObservedValue::Text("a".repeat(64))),
        ("output.0.connector", ObservedValue::U64(0)),
        (
            "output.0.connector",
            ObservedValue::U64(u64::from(u32::MAX) + 1),
        ),
        ("output.0.crtc", ObservedValue::U64(0)),
        ("output.0.plane", ObservedValue::U64(0)),
        ("output.0.framebuffer", ObservedValue::U64(0)),
        ("output.0.spend_high_water", ObservedValue::U64(0)),
        ("output.0.completed_commit", ObservedValue::U64(90)),
        ("output.0.completed_commit", ObservedValue::U64(u64::MAX)),
        ("output.1.completed_commit", ObservedValue::U64(50)),
        ("output.1.connector", ObservedValue::U64(5)),
        ("output.1.crtc", ObservedValue::U64(7)),
        ("output.1.plane", ObservedValue::U64(8)),
        ("output.1.framebuffer", ObservedValue::U64(42)),
        ("output.1.handle", ObservedValue::U64(10)),
    ] {
        let mut observation = envelope.clone();
        observation.attributes.insert(key.into(), changed);
        assert!(
            DisplayNativeHandoffFacts::from_envelope(&observation, &facts.scope, 1002).is_err(),
            "{key}"
        );
    }
    let mut none_enabled = facts.outputs.clone();
    for output in none_enabled.values_mut() {
        output.enabled = false;
        output.crtc = 0;
        output.plane = 0;
        output.framebuffer = 0;
    }
    assert!(
        DisplayNativeHandoffFacts::new(
            facts.scope.clone(),
            facts.lineage.clone(),
            facts.window,
            none_enabled
        )
        .is_err()
    );
}

#[test]
fn ordinary_frame_facts_cannot_be_reinterpreted_as_opaque_restoration_presentation() {
    let (facts, envelope) = fixture();
    assert!(
        crate::DisplayOriginalPresentationFacts::from_envelope(&envelope, &facts.scope, 1002)
            .is_err()
    );
    let mut relabelled = envelope;
    relabelled.capability = value(CapabilityId::new(
        crate::DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY,
    ));
    assert!(
        crate::DisplayOriginalPresentationFacts::from_envelope(&relabelled, &facts.scope, 1002)
            .is_err()
    );
}

#[test]
fn read_only_reconciliation_cannot_adopt_new_frame_lineage_or_deadline() {
    let (original, _) = fixture();
    let mut fresh = original.clone();
    fresh.window.observed_unix_ms += 1;
    fresh.window.observed_boot_ms += 1;
    assert!(fresh.reconciles(&original));
    for case in 0..12 {
        let mut changed = fresh.clone();
        let output = changed
            .outputs
            .values_mut()
            .next()
            .unwrap_or_else(|| unreachable!("output"));
        match case {
            0 => output.completed_commit += 1,
            1 => output.spend_high_water += 1,
            2 => output.framebuffer += 1,
            3 => output.connector += 10,
            4 => output.plane += 1,
            5 => changed.window.deadline_unix_ms += 1,
            6 => changed.window.deadline_boot_ms += 1,
            7 => changed.window.observed_unix_ms = original.window.observed_unix_ms - 1,
            8 => changed.window.observed_boot_ms = original.window.observed_boot_ms - 1,
            9 => changed.lineage.post_write_epoch += 1,
            10 => changed.lineage.security_epoch += 1,
            _ => changed.lineage.terminal_dispatch = "3".repeat(64),
        }
        assert!(!changed.reconciles(&original), "case {case}");
    }
}

#[test]
fn native_and_root_comparison_requires_the_same_full_terminal_ancestry_and_spent_phase() {
    use crate::{
        DisplayFinalizationPhase, DisplayFinalizationReservationFacts,
        DisplayOriginalFinalizationFacts,
    };
    let encoded = include_str!(
        "../../../linura-core/src/display_recovery/fixtures/original-finalization.txt"
    )
    .trim_end();
    let material = value(linura_core::DisplayFinalizationMaterial::decode(encoded));
    let scope = value(material.recovery_scope());
    let terminal = value(DisplayFinalizationReservationFacts::new(
        encoded.into(),
        "transaction:terminal".into(),
        "e".repeat(64),
        "f".repeat(64),
    ));
    let root = value(DisplayOriginalFinalizationFacts::new(
        scope.clone(),
        material.restoration().original_checkpoint().into(),
        "transaction:restored".into(),
        "c".repeat(64),
        material.restoration_dispatch().into(),
        DisplayFinalizationPhase::NativeReleaseSpent,
        Some(terminal),
    ));
    let (mut native, _) = fixture();
    native.scope = scope;
    native.outputs = native
        .outputs
        .into_iter()
        .map(|(id, output)| {
            (
                value(DisplayOutputId::new(
                    native.scope.replacement().clone(),
                    id.handle(),
                    id.generation(),
                )),
                output,
            )
        })
        .collect();
    native.lineage.checkpoint = root.checkpoint().into();
    native.lineage.restoration_dispatch = root.restoration_dispatch().into();
    native.lineage.terminal_link = material.terminal_link().into();
    native.lineage.source_guard = material.restored_source_guard().into();
    native.lineage.post_write_epoch = material.post_write_epoch();
    assert!(native.matches_root(&root));
    for field in 0..10 {
        let mut changed = native.clone();
        match field {
            0 => changed.lineage.checkpoint = "4".repeat(64),
            1 => changed.lineage.restoration_transaction = "transaction:other".into(),
            2 => changed.lineage.restoration_effect = "4".repeat(64),
            3 => changed.lineage.restoration_dispatch = "4".repeat(64),
            4 => changed.lineage.terminal_transaction = "transaction:other".into(),
            5 => changed.lineage.terminal_effect = "4".repeat(64),
            6 => changed.lineage.terminal_dispatch = "4".repeat(64),
            7 => changed.lineage.terminal_link = "4".repeat(64),
            8 => changed.lineage.source_guard = "4".repeat(64),
            _ => changed.lineage.post_write_epoch += 1,
        }
        assert!(!changed.matches_root(&root), "field {field}");
    }
    for phase in [
        DisplayFinalizationPhase::Reserved,
        DisplayFinalizationPhase::Quiesced,
        DisplayFinalizationPhase::Retired,
        DisplayFinalizationPhase::NativeReleaseReserved,
        DisplayFinalizationPhase::ReleasedCurrent,
    ] {
        let other = value(DisplayOriginalFinalizationFacts::new(
            root.scope().clone(),
            root.checkpoint().into(),
            root.restoration_transaction().into(),
            root.restoration_effect().into(),
            root.restoration_dispatch().into(),
            phase,
            root.terminal().cloned(),
        ));
        assert!(!native.matches_root(&other), "{phase:?}");
    }
}
