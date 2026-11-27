//! Comparison fixtures only, never live Root or physical scanout evidence.
use super::*;
use crate::{
    DisplayNativeHandoffOutput, DisplayNativeHandoffWindow, DisplayOrdinaryHandoffLineage,
    DisplayOrdinaryReleaseComparison, DisplayOrdinaryReleaseFacts,
};
use linura_core::{
    CapabilityId, DisplayLayoutMaterial, DisplayOrdinaryReleaseLineage,
    DisplayOrdinaryReleaseOutcome, DisplayOutputId, ProviderId, RequestId,
};
fn value<T, E: std::fmt::Debug>(v: Result<T, E>) -> T {
    v.unwrap_or_else(|e| unreachable!("{e:?}"))
}
fn fixture() -> (DisplayOrdinaryCompletionFacts, ObservationEnvelope) {
    let topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3";
    let layout = format!("LNDL:1;{topology};10:1:enabled:1920:1080:60000:1000:0:0:0:-;");
    let original = format!(
        "LNDI:1;session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1;{layout}{layout}"
    );
    let old = value(DisplayLayoutMaterial::decode(&original));
    let material = value(DisplayOrdinaryReleaseMaterial::encode(
        &DisplayOrdinaryReleaseLineage {
            original_request: value(RequestId::new("request:v010:display-layout:original")),
            original_dispatch: &"a".repeat(64),
            terminal_record: &"b".repeat(64),
            original_checkpoint: &"c".repeat(64),
            signed_binding: &"d".repeat(64),
            generation: 0,
            state_version: 9,
            current_source_guard: &"e".repeat(64),
        },
        DisplayOrdinaryReleaseOutcome::Keep,
        old.lock(),
        &original,
    ));
    let scope = value(value(DisplayOrdinaryReleaseMaterial::decode(&material)).release_scope());
    let producer = DisplayNativeHandoffWindow {
        observed_unix_ms: 1000,
        observed_boot_ms: 100,
        deadline_unix_ms: 1200,
        deadline_boot_ms: 300,
    };
    let root = value(DisplayOrdinaryReleaseFacts::new(
        scope.clone(),
        DisplayOrdinaryReleaseComparison {
            material,
            transaction: "transaction:release".into(),
            effect: "1".repeat(64),
            dispatch: "2".repeat(64),
            preparation_digest: "3".repeat(64),
            spent: true,
            producer,
            sampled_boot_ms: 102,
        },
    ));
    let native = value(DisplayOrdinaryHandoffFacts::new(
        scope.clone(),
        DisplayOrdinaryHandoffLineage {
            original_transaction: "transaction:original".into(),
            original_effect: "4".repeat(64),
            release_transaction: "transaction:release".into(),
            release_effect: "1".repeat(64),
            release_dispatch: "2".repeat(64),
            preparation_digest: "3".repeat(64),
            terminal_record: "b".repeat(64),
            checkpoint: "c".repeat(64),
            signed_binding: "d".repeat(64),
            source_guard: "e".repeat(64),
            outcome: "keep".into(),
            post_write_epoch: 1,
            security_epoch: 2,
        },
        DisplayNativeHandoffWindow {
            observed_unix_ms: 1001,
            observed_boot_ms: 101,
            ..producer
        },
        BTreeMap::from([(
            value(DisplayOutputId::new(scope.topology().clone(), 10, 1)),
            DisplayNativeHandoffOutput {
                enabled: true,
                connector: 5,
                crtc: 6,
                plane: 7,
                framebuffer: 8,
                spend_high_water: 90,
                completed_commit: 91,
            },
        )]),
    ));

    let facts = value(DisplayOrdinaryCompletionFacts::new(
        DisplayCompletionLineage {
            record: "5".repeat(64),
            preparation: "6".repeat(64),
            verification: "7".repeat(64),
            material: root.comparison().material.clone(),
        },
        native,
        producer,
    ));
    let envelope = ObservationEnvelope {
        provider: value(ProviderId::new(DISPLAY_RECOVERY_PROVIDER)),
        capability: value(CapabilityId::new(DISPLAY_ORDINARY_COMPLETION_CAPABILITY)),
        resource: value(scope.resource_id()),
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms: 5000,
        valid_for_ms: 2000,
        sequence: 1,
        attributes: facts.attributes(),
    };
    (facts, envelope)
}
#[test]
fn live_ordinary_completion_keeps_first_frames_historical_and_closed() {
    let (facts, envelope) = fixture();
    let scope = facts.first().scope();
    assert_eq!(
        value(DisplayOrdinaryCompletionFacts::from_envelope(
            &envelope, scope, 5001
        )),
        facts
    );
    assert!(facts.first().window().deadline_unix_ms < envelope.observed_at_unix_ms);
    for key in envelope.attributes.keys() {
        let mut wrong = envelope.clone();
        wrong.attributes.remove(key);
        assert!(
            DisplayOrdinaryCompletionFacts::from_envelope(&wrong, scope, 5001).is_err(),
            "{key}"
        );
    }
    for now in [0, 4999, 7000, u64::MAX] {
        assert!(DisplayOrdinaryCompletionFacts::from_envelope(&envelope, scope, now).is_err());
    }
    for (key, value) in [
        ("phase", ObservedValue::Text("released-current".into())),
        ("first.outcome", ObservedValue::Text("expired".into())),
        (
            "first.original_dispatch",
            ObservedValue::Text("f".repeat(64)),
        ),
        ("first.signed_binding", ObservedValue::Text("f".repeat(64))),
        (
            "preparation_digest",
            envelope.attributes["verification_digest"].clone(),
        ),
        ("unexpected", ObservedValue::Bool(true)),
    ] {
        let mut wrong = envelope.clone();
        wrong.attributes.insert(key.into(), value);
        assert!(
            DisplayOrdinaryCompletionFacts::from_envelope(&wrong, scope, 5001).is_err(),
            "{key}"
        );
    }
    let mut relabelled = envelope.clone();
    relabelled.capability = value(CapabilityId::new(
        crate::DISPLAY_ORIGINAL_COMPLETION_CAPABILITY,
    ));
    assert!(DisplayOrdinaryCompletionFacts::from_envelope(&relabelled, scope, 5001).is_err());
}

#[test]
fn ordinary_root_retirement_has_separate_fresh_authority_and_historical_first() {
    use crate::{
        DISPLAY_ORDINARY_ROOT_RETIREMENT_CAPABILITY, DisplayOrdinaryOriginalComparison,
        DisplayOrdinaryRootRetirementFacts, DisplayRootRetirementLineage,
    };
    let (completion, mut sample) = fixture();
    let scope = completion.first().scope().clone();
    let original = value(DisplayOrdinaryReleaseMaterial::decode(
        &completion.lineage().material,
    ))
    .original_text()
    .to_owned();
    let facts = value(DisplayOrdinaryRootRetirementFacts::new(
        DisplayRootRetirementLineage {
            record: "8".repeat(64),
            preparation: "9".repeat(64),
            verification: "a".repeat(64),
            power_record: "b".repeat(64),
        },
        completion,
        DisplayOrdinaryOriginalComparison {
            material: original,
            transaction: "transaction:original".into(),
            checkpoint: "c".repeat(64),
            native_guard: "d".repeat(64),
            integration: "e".repeat(64),
            sampled_boot_ms: 100,
            original_deadline_unix_ms: 1200,
        },
        None,
    ));
    sample.capability = value(CapabilityId::new(
        DISPLAY_ORDINARY_ROOT_RETIREMENT_CAPABILITY,
    ));
    sample.attributes = facts.attributes();
    assert_eq!(
        value(DisplayOrdinaryRootRetirementFacts::from_envelope(
            &sample, &scope, 5001
        )),
        facts
    );
    assert!(facts.completion().first().window().deadline_unix_ms < sample.observed_at_unix_ms);
    assert!(!sample.attributes.contains_key("root_power_held"));
    // The full before-native-current checkpoint stays historical under a fresh
    // actual Root observation, and never becomes another effect permission.
    let before = value(crate::DisplayOrdinaryCurrentFacts::new(
        scope.clone(),
        facts.completion().first().lineage().clone(),
        DisplayNativeHandoffWindow {
            observed_unix_ms: 3000,
            observed_boot_ms: 2100,
            deadline_unix_ms: 4000,
            deadline_boot_ms: 3100,
        },
        facts
            .completion()
            .first()
            .outputs()
            .iter()
            .map(|(id, row)| {
                (
                    id.clone(),
                    crate::DisplayNativeCurrentOutput {
                        enabled: row.enabled,
                        connector: row.connector,
                        crtc: row.crtc,
                        plane: row.plane,
                        framebuffer: if row.enabled { 9 } else { 0 },
                        handoff_commit: row.completed_commit,
                        completed_commit: row.completed_commit + u64::from(row.enabled) * 2,
                    },
                )
            })
            .collect(),
        facts.completion().lineage().record.clone(),
        true,
        false,
        None,
        None,
    ));
    let current = value(DisplayOrdinaryRootRetirementFacts::new(
        facts.lineage().clone(),
        facts.completion().clone(),
        facts.original().clone(),
        Some((
            crate::DisplayCurrentGrantLineage {
                record: "f".repeat(64),
                preparation: "8".repeat(64),
                committed_record: "9".repeat(64),
            },
            before.clone(),
        )),
    ));
    let mut with_current = sample.clone();
    with_current.attributes = current.attributes();
    assert_eq!(
        value(DisplayOrdinaryRootRetirementFacts::from_envelope(
            &with_current,
            &scope,
            5001
        )),
        current
    );
    assert!(
        current
            .current_frames()
            .unwrap_or_else(|| unreachable!())
            .window()
            .deadline_unix_ms
            < with_current.observed_at_unix_ms
    );
    for key in [
        "current_prepared.output.0.completed_commit",
        "current_grant_preparation",
        "current_prepared_observed_unix_ms",
    ] {
        let mut wrong = with_current.clone();
        wrong.attributes.remove(key);
        assert!(DisplayOrdinaryRootRetirementFacts::from_envelope(&wrong, &scope, 5001).is_err());
    }
    for (key, value) in [
        (
            "current_prepared.power_fence_held",
            ObservedValue::Bool(true),
        ),
        ("current_prepared_observed_unix_ms", ObservedValue::U64(0)),
        ("current_grant_digest", ObservedValue::Text("0".repeat(64))),
    ] {
        let mut wrong = with_current.clone();
        wrong.attributes.insert(key.into(), value);
        assert!(DisplayOrdinaryRootRetirementFacts::from_envelope(&wrong, &scope, 5001).is_err());
    }

    for key in sample.attributes.keys() {
        let mut wrong = sample.clone();
        wrong.attributes.remove(key);
        assert!(
            DisplayOrdinaryRootRetirementFacts::from_envelope(&wrong, &scope, 5001).is_err(),
            "{key}"
        );
    }
    for now in [0, 4999, 7000, u64::MAX] {
        assert!(DisplayOrdinaryRootRetirementFacts::from_envelope(&sample, &scope, now).is_err());
    }
    for (key, v) in [
        ("power_absent", ObservedValue::Bool(false)),
        ("root_power_held", ObservedValue::Bool(true)),
        ("original.native_guard", ObservedValue::Text("bad".into())),
        ("completion.phase", ObservedValue::Text("prepared".into())),
        ("ordinary_root_retirement_schema", ObservedValue::U64(3)),
    ] {
        let mut wrong = sample.clone();
        wrong.attributes.insert(key.into(), v);
        assert!(
            DisplayOrdinaryRootRetirementFacts::from_envelope(&wrong, &scope, 5001).is_err(),
            "{key}"
        );
    }
    let mut wrong = sample.clone();
    wrong.capability = value(CapabilityId::new(DISPLAY_ORDINARY_COMPLETION_CAPABILITY));
    assert!(DisplayOrdinaryRootRetirementFacts::from_envelope(&wrong, &scope, 5001).is_err());
    let mut wrong = sample.clone();
    wrong.authority = ObservationAuthority::SyntheticTest;
    assert!(DisplayOrdinaryRootRetirementFacts::from_envelope(&wrong, &scope, 5001).is_err());
    let mut wrong = sample;
    wrong.sequence = 0;
    assert!(DisplayOrdinaryRootRetirementFacts::from_envelope(&wrong, &scope, 5001).is_err());
}
