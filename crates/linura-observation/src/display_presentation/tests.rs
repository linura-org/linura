//! Simulated NativeApi envelope projection, not native KMS/frame qualification.
use super::*;
use linura_core::{CapabilityId, DisplayTopologyId, ProviderId, ResourceId};

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}
fn fixture() -> (DisplayOriginalPresentationFacts, ObservationEnvelope) {
    let topology = value(DisplayTopologyId::from_resource(&value(ResourceId::new(
        "display:topology:11111111-1111-4111-8111-111111111111:1000:c3:99:seat0:44444444-4444-4444-8444-444444444444:1",
    ))));
    let scope = value(DisplayRecoveryScope::new(&"a".repeat(64), topology.clone()));
    let frames = BTreeMap::from([
        (
            value(DisplayOutputId::new(topology.clone(), 10, 1)),
            DisplayPostWriteFrame::Presented {
                crtc: 7,
                framebuffer: 42,
                commit: 99,
            },
        ),
        (
            value(DisplayOutputId::new(topology, 20, 2)),
            DisplayPostWriteFrame::Disabled,
        ),
    ]);
    let facts = value(DisplayOriginalPresentationFacts::new(
        scope.clone(),
        "b".repeat(64),
        "transaction:restoration".into(),
        "c".repeat(64),
        "d".repeat(64),
        "e".repeat(64),
        3,
        frames,
    ));
    let envelope = ObservationEnvelope {
        provider: value(ProviderId::new(DISPLAY_PROVIDER)),
        resource: value(scope.resource_id()),
        capability: value(CapabilityId::new(DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY)),
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms: 1000,
        valid_for_ms: 2000,
        sequence: 1,
        attributes: facts.attributes(),
    };
    (facts, envelope)
}

#[test]
fn original_post_write_facts_require_exact_scope_and_effect_correlation() {
    let (facts, envelope) = fixture();
    assert_eq!(
        value(DisplayOriginalPresentationFacts::from_envelope(
            &envelope,
            &facts.scope,
            1001
        )),
        facts
    );
    assert!(facts.matches_binding(
        &"b".repeat(64),
        "transaction:restoration",
        &"c".repeat(64),
        &"d".repeat(64)
    ));
    for case in 0..4 {
        let mut binding = [
            "b".repeat(64),
            "transaction:restoration".into(),
            "c".repeat(64),
            "d".repeat(64),
        ];
        binding[case] = "f".repeat(64);
        assert!(!facts.matches_binding(&binding[0], &binding[1], &binding[2], &binding[3]));
    }
}

#[test]
fn presentation_projection_is_closed_typed_and_never_accepts_an_acknowledgement() {
    let (facts, envelope) = fixture();
    for key in envelope.attributes.keys() {
        let mut missing = envelope.clone();
        missing.attributes.remove(key);
        assert!(
            DisplayOriginalPresentationFacts::from_envelope(&missing, &facts.scope, 1001).is_err(),
            "{key}"
        );
        let mut wrong = envelope.clone();
        wrong.attributes.insert(key.clone(), ObservedValue::I64(1));
        assert!(
            DisplayOriginalPresentationFacts::from_envelope(&wrong, &facts.scope, 1001).is_err(),
            "{key}"
        );
    }
    for (key, changed) in [
        ("state", ObservedValue::Text("restored".into())),
        ("presentation_schema", ObservedValue::U64(2)),
        ("post_write_epoch", ObservedValue::U64(0)),
        ("original_dispatch", ObservedValue::Text("f".repeat(64))),
        ("checkpoint_digest", ObservedValue::Text("0".repeat(64))),
        ("source_guard", ObservedValue::Text("A".repeat(64))),
        (
            "transaction",
            ObservedValue::Text("transaction:injected\"".into()),
        ),
        ("output_count", ObservedValue::U64(17)),
        ("output.0.crtc", ObservedValue::U64(0)),
        ("output.0.framebuffer", ObservedValue::U64(0)),
        ("output.0.commit", ObservedValue::U64(0)),
        ("output.0.crtc", ObservedValue::U64(u64::from(u32::MAX) + 1)),
        ("output.1.crtc", ObservedValue::U64(7)),
        ("output.1.framebuffer", ObservedValue::U64(42)),
        ("output.1.commit", ObservedValue::U64(99)),
        ("output.1.handle", ObservedValue::U64(10)),
    ] {
        let mut observation = envelope.clone();
        observation.attributes.insert(key.into(), changed);
        assert!(
            DisplayOriginalPresentationFacts::from_envelope(&observation, &facts.scope, 1001)
                .is_err(),
            "{key}"
        );
    }
}

#[test]
fn stale_wrong_owner_or_synthetic_frames_never_become_current_presentation() {
    let (facts, envelope) = fixture();
    for now in [0, 999, 3000, u64::MAX] {
        assert_eq!(
            DisplayOriginalPresentationFacts::from_envelope(&envelope, &facts.scope, now),
            Err(DisplayEvidenceError::Freshness)
        );
    }
    for case in 0..8 {
        let mut observation = envelope.clone();
        match case {
            0 => observation.authority = ObservationAuthority::SyntheticTest,
            1 => observation.sequence = 0,
            2 => observation.provider = value(ProviderId::new("hyprland-recovery")),
            3 => observation.capability = value(CapabilityId::new("display.outputs.observe")),
            4 => observation.resource = value(facts.scope.replacement().resource_id()),
            5 => observation.valid_for_ms = 0,
            6 => observation.valid_for_ms = 2001,
            _ => observation.observed_at_unix_ms = u64::MAX,
        }
        assert!(
            DisplayOriginalPresentationFacts::from_envelope(&observation, &facts.scope, 1001)
                .is_err()
        );
    }
}

#[test]
fn disabled_heads_need_actual_disable_and_every_enabled_head_needs_a_frame() {
    let (facts, _) = fixture();
    let build = |frames| {
        DisplayOriginalPresentationFacts::new(
            facts.scope.clone(),
            facts.checkpoint.clone(),
            facts.transaction.clone(),
            facts.effect.clone(),
            facts.dispatch.clone(),
            facts.source_guard.clone(),
            facts.epoch,
            frames,
        )
    };
    let mut disabled = facts.frames.clone();
    for frame in disabled.values_mut() {
        *frame = DisplayPostWriteFrame::Disabled;
    }
    assert!(build(disabled).is_err());
    assert!(build(BTreeMap::new()).is_err());
    let mut mirrored = facts.frames.clone();
    for frame in mirrored.values_mut() {
        *frame = DisplayPostWriteFrame::Presented {
            crtc: 7,
            framebuffer: 42,
            commit: 99,
        };
    }
    assert!(build(mirrored).is_ok()); // Shared scanout is permitted; outputs remain exact.
}

#[test]
fn presentation_requires_the_exact_complete_enabled_and_disabled_layout_inventory() {
    use linura_core::{DisplayMode, DisplayOutputSet, NativeOutputCapabilities};
    let (facts, _) = fixture();
    let ids: Vec<_> = facts.frames.keys().cloned().collect();
    let inventory = value(DisplayOutputSet::new(
        facts.scope.replacement().clone(),
        ids.clone(),
    ));
    let mode = value(DisplayMode::new(1920, 1080, 60000));
    let capabilities: Vec<_> = ids
        .iter()
        .map(|id| value(NativeOutputCapabilities::new(id.clone(), vec![mode], true)))
        .collect();
    let layout = |second| {
        value(DisplayLayout::from_canonical_text(
            &inventory,
            &capabilities,
            &format!(
                "LNDL:1;{};10:1:enabled:1920:1080:60000:1000:0:0:0:-;{second}",
                value(facts.scope.replacement().resource_id()).as_str()
            ),
        ))
    };
    let restored = layout("20:2:disabled;");
    assert!(facts.matches_layout(&restored));
    assert!(!facts.matches_layout(&layout("20:2:enabled:1920:1080:60000:1000:0:1920:0:-;")));
    let mut partial = facts.clone();
    partial.frames.remove(&ids[1]);
    assert!(!partial.matches_layout(&restored));
    let mut extra = facts.clone();
    extra.frames.insert(
        value(DisplayOutputId::new(
            facts.scope.replacement().clone(),
            30,
            3,
        )),
        DisplayPostWriteFrame::Disabled,
    );
    assert!(!extra.matches_layout(&restored));
}
