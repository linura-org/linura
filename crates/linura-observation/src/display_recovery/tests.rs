use super::*;
use linura_core::{CapabilityId, DisplayTopologyId, ProviderId, ResourceId};

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}

fn fixture() -> (DisplayOriginalProtectionFacts, ObservationEnvelope) {
    let old = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:8";
    let new = value(DisplayTopologyId::from_resource(&value(ResourceId::new(
        "display:topology:11111111-1111-4111-8111-111111111111:1000:c3:99:seat0:44444444-4444-4444-8444-444444444444:1",
    ))));
    let scope = value(DisplayRecoveryScope::new(&"a".repeat(64), new));
    let layout = |x| format!("LNDL:1;{old};1:2:enabled:1920:1080:60000:1000:0:{x}:0:-;");
    let material = format!(
        "LNDI:1;session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1;{}{}",
        layout(0),
        layout(100)
    );
    let original = value(DisplayLayoutMaterial::decode(&material));
    let row = value(DisplayOutputId::new(original.topology().clone(), 1, 2));
    let facts = value(DisplayOriginalProtectionFacts::new(
        scope.clone(),
        material,
        "transaction:original".into(),
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64),
        1,
        10,
        BTreeMap::from([(
            row,
            value(DisplayRecoveryMetadata::new(
                false,
                "e".repeat(64),
                "f".repeat(64),
            )),
        )]),
    ));
    let envelope = ObservationEnvelope {
        provider: value(ProviderId::new(DISPLAY_RECOVERY_PROVIDER)),
        resource: value(scope.resource_id()),
        capability: value(CapabilityId::new(DISPLAY_ORIGINAL_PROTECTION_CAPABILITY)),
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms: 1000,
        valid_for_ms: 2000,
        sequence: 1,
        attributes: facts.attributes(),
    };
    (facts, envelope)
}

#[test]
fn original_history_keeps_its_own_clocks_while_only_live_protection_is_current() {
    let (facts, envelope) = fixture();
    assert_eq!(
        value(DisplayOriginalProtectionFacts::from_envelope(
            &envelope,
            facts.scope(),
            1001
        )),
        facts
    );
    assert_eq!(facts.confirmation_deadline_unix_ms, 10); // Never renewed to now.
    assert_eq!(facts.sampled_boot_ms, 1);
    for now in [0, 999, 3000, u64::MAX] {
        assert_eq!(
            DisplayOriginalProtectionFacts::from_envelope(&envelope, facts.scope(), now),
            Err(DisplayEvidenceError::Freshness)
        );
    }
}

#[test]
fn every_original_attribute_is_closed_typed_and_canonically_reencoded() {
    let (facts, envelope) = fixture();
    for key in envelope.attributes.keys() {
        let mut missing = envelope.clone();
        missing.attributes.remove(key);
        assert!(
            DisplayOriginalProtectionFacts::from_envelope(&missing, facts.scope(), 1001).is_err(),
            "{key}"
        );
        let mut wrong_type = envelope.clone();
        wrong_type
            .attributes
            .insert(key.clone(), ObservedValue::I64(1));
        assert!(
            DisplayOriginalProtectionFacts::from_envelope(&wrong_type, facts.scope(), 1001)
                .is_err(),
            "{key}"
        );
    }
    for (key, value) in [
        ("unexpected", ObservedValue::Bool(true)),
        ("original_protection_schema", ObservedValue::U64(2)),
        ("original_dispatch", ObservedValue::Text("b".repeat(64))),
        (
            "original_checkpoint_digest",
            ObservedValue::Text("0".repeat(64)),
        ),
        ("original_native_guard", ObservedValue::Text("A".repeat(64))),
        (
            "original_integration_digest",
            ObservedValue::Text("d".repeat(65)),
        ),
        ("original_output_count", ObservedValue::U64(0)),
        ("original_output_count", ObservedValue::U64(17)),
        ("original_sampled_boot_ms", ObservedValue::U64(0)),
        (
            "original_confirmation_deadline_unix_ms",
            ObservedValue::U64(0),
        ),
    ] {
        let mut changed = envelope.clone();
        changed.attributes.insert(key.into(), value);
        assert!(
            DisplayOriginalProtectionFacts::from_envelope(&changed, facts.scope(), 1001).is_err(),
            "{key}"
        );
    }
}

#[test]
fn wrong_provider_capability_resource_authority_or_freshness_is_not_original_protection() {
    let (facts, envelope) = fixture();
    for case in 0..9 {
        let mut changed = envelope.clone();
        match case {
            0 => changed.provider = value(ProviderId::new("hyprland")),
            1 => changed.capability = value(CapabilityId::new("display.outputs.observe")),
            2 => changed.resource = value(facts.scope.replacement().resource_id()),
            3 => changed.authority = ObservationAuthority::SyntheticTest,
            4 => changed.sequence = 0,
            5 => changed.observed_at_unix_ms = 0,
            6 => changed.valid_for_ms = 0,
            7 => changed.valid_for_ms = 2001,
            _ => {
                changed.observed_at_unix_ms = u64::MAX;
            }
        }
        assert!(
            DisplayOriginalProtectionFacts::from_envelope(&changed, facts.scope(), 1001).is_err(),
            "{case}"
        );
    }
}

#[test]
fn duplicate_native_identities_or_recycled_handle_generations_fail_closed() {
    let (facts, envelope) = fixture();
    let mut attrs = envelope.attributes.clone();
    attrs.insert("original_output_count".into(), ObservedValue::U64(2));
    for (key, value) in &envelope.attributes {
        if let Some(suffix) = key.strip_prefix("original_output.0.") {
            attrs.insert(format!("original_output.1.{suffix}"), value.clone());
        }
    }
    for (handle, generation, identity) in [(1, 2, "1"), (1, 3, "1"), (2, 3, "f")] {
        let mut changed = envelope.clone();
        changed.attributes = attrs.clone();
        changed.attributes.insert(
            "original_output.1.handle".into(),
            ObservedValue::U64(handle),
        );
        changed.attributes.insert(
            "original_output.1.generation".into(),
            ObservedValue::U64(generation),
        );
        changed.attributes.insert(
            "original_output.1.native_identity_digest".into(),
            ObservedValue::Text(identity.repeat(64)),
        );
        assert!(
            DisplayOriginalProtectionFacts::from_envelope(&changed, facts.scope(), 1001).is_err()
        );
    }
}
