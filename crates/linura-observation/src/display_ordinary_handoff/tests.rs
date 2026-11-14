//! Synthetic canonical-envelope checks; never physical scanout qualification.
use super::*;
use linura_core::{CapabilityId, DisplayTopologyId, ProviderId, ResourceId};

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}
fn fixture() -> (DisplayOrdinaryHandoffFacts, ObservationEnvelope) {
    let topology = value(DisplayTopologyId::from_resource(&value(ResourceId::new(
        "display:topology:11111111-1111-4111-8111-111111111111:1000:c3:99:seat0:44444444-4444-4444-8444-444444444444:1",
    ))));
    let scope = value(DisplayOrdinaryReleaseScope::new(
        &"a".repeat(64),
        topology.clone(),
    ));
    let lineage = DisplayOrdinaryHandoffLineage {
        checkpoint: "b".repeat(64),
        original_transaction: "transaction:restored".into(),
        original_effect: "c".repeat(64),
        release_transaction: "transaction:terminal".into(),
        release_effect: "e".repeat(64),
        release_dispatch: "f".repeat(64),
        terminal_record: "1".repeat(64),
        preparation_digest: "3".repeat(64),
        signed_binding: "4".repeat(64),
        outcome: "keep".into(),
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
    let facts = value(DisplayOrdinaryHandoffFacts::new(
        scope.clone(),
        lineage,
        window,
        outputs,
    ));
    let envelope = ObservationEnvelope {
        provider: value(ProviderId::new(DISPLAY_PROVIDER)),
        resource: value(scope.resource_id()),
        capability: value(CapabilityId::new(DISPLAY_ORDINARY_HANDOFF_CAPABILITY)),
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
        value(DisplayOrdinaryHandoffFacts::from_envelope(
            &envelope,
            &facts.scope,
            1002
        )),
        facts
    );
    assert_eq!(envelope.valid_for_ms, 199);
    assert_eq!(facts.window().deadline_unix_ms, 1200);
    assert_eq!(facts.window().deadline_boot_ms, 300);
    assert_eq!(facts.lineage().release_dispatch, "f".repeat(64));
    assert_eq!(facts.outputs().len(), 2);
    for now in [0, 1000, 1200, u64::MAX] {
        assert!(DisplayOrdinaryHandoffFacts::from_envelope(&envelope, &facts.scope, now).is_err());
    }
    let mut renewed = envelope.clone();
    renewed.valid_for_ms = 2000;
    assert!(DisplayOrdinaryHandoffFacts::from_envelope(&renewed, &facts.scope, 1002).is_err());
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
        DisplayOrdinaryHandoffFacts::from_envelope(e, &facts.scope, 1002).is_ok()
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
            4 => changed.resource = value(facts.scope.topology().resource_id()),
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
        ("ordinary_handoff_schema", ObservedValue::U64(2)),
        ("output_count", ObservedValue::U64(17)),
        ("post_write_epoch", ObservedValue::U64(0)),
        ("security_epoch", ObservedValue::U64(0)),
        ("original_dispatch", ObservedValue::Text("c".repeat(64))),
        ("source_guard", ObservedValue::Text("A".repeat(64))),
        (
            "release_transaction",
            ObservedValue::Text(facts.lineage.original_transaction.clone()),
        ),
        (
            "release_dispatch",
            ObservedValue::Text(facts.scope.original_dispatch().into()),
        ),
        ("release_dispatch", ObservedValue::Text("a".repeat(64))),
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
            DisplayOrdinaryHandoffFacts::from_envelope(&observation, &facts.scope, 1002).is_err(),
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
        DisplayOrdinaryHandoffFacts::new(
            facts.scope.clone(),
            facts.lineage.clone(),
            facts.window,
            none_enabled
        )
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
            _ => changed.lineage.release_dispatch = "3".repeat(64),
        }
        assert!(!changed.reconciles(&original), "case {case}");
    }
}
