use super::*;
use linura_core::{CapabilityId, ProviderId};

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|e| unreachable!("{e:?}"))
}
fn boot() -> BootId {
    value(BootId::new("11111111-1111-4111-8111-111111111111"))
}
fn sample() -> ObservationEnvelope {
    let facts = value(DisplayProtectionGenerationFacts::new(
        boot(),
        value(DisplayProtectionInvocationId::new(
            "22222222-2222-4222-8222-222222222222",
        )),
        50,
    ));
    ObservationEnvelope {
        provider: value(ProviderId::new(DISPLAY_RECOVERY_PROVIDER)),
        capability: value(CapabilityId::new(DISPLAY_PROTECTION_GENERATION_CAPABILITY)),
        resource: value(DisplayProtectionGenerationFacts::resource(&boot())),
        authority: ObservationAuthority::NativeApi,
        observed_at_unix_ms: 1000,
        valid_for_ms: 2000,
        sequence: 1,
        attributes: facts.attributes(),
    }
}

#[test]
fn generation_roundtrip_attests_only_exact_boot_scoped_identity() {
    let sample = sample();
    let facts = value(DisplayProtectionGenerationFacts::from_envelope(
        &sample,
        &boot(),
        2999,
    ));
    assert_eq!(facts.boot(), &boot());
    assert_eq!(
        facts.invocation().as_str(),
        "22222222-2222-4222-8222-222222222222"
    );
    assert_eq!(facts.sampled_boot_ms(), 50);
    assert_eq!(facts.attributes(), sample.attributes);
    assert_eq!(
        value(DisplayProtectionGenerationFacts::boot_from_resource(
            &sample.resource
        )),
        boot()
    );
    // No scanout, held power, historical Keep, grant or ownership assertions.
    assert_eq!(facts.attributes().len(), 3);
    for resource in [
        "display:protection:11111111-1111-4111-8111-111111111111:extra",
        "display:protection:00000000-0000-0000-0000-000000000000",
        "display:topology:11111111-1111-4111-8111-111111111111",
    ] {
        assert!(
            DisplayProtectionGenerationFacts::boot_from_resource(&value(ResourceId::new(resource)))
                .is_err()
        );
    }
}

#[test]
fn generation_never_accepts_another_provider_authority_scope_or_capability() {
    for mutation in 0..7 {
        let mut changed = sample();
        match mutation {
            0 => changed.provider = value(ProviderId::new("other-provider")),
            1 => {
                changed.capability = value(CapabilityId::new(
                    crate::DISPLAY_ORIGINAL_PROTECTION_CAPABILITY,
                ))
            }
            2 => changed.authority = ObservationAuthority::SyntheticTest,
            3 => changed.authority = ObservationAuthority::Filesystem,
            4 => changed.authority = ObservationAuthority::Kernel,
            5 => changed.sequence = 0,
            6 => {
                changed.resource = value(DisplayProtectionGenerationFacts::resource(&value(
                    BootId::new("33333333-3333-4333-8333-333333333333"),
                )))
            }
            _ => unreachable!(),
        }
        assert!(
            DisplayProtectionGenerationFacts::from_envelope(&changed, &boot(), 1000).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn strict_two_second_generation_window_rejects_future_expired_or_widened_evidence() {
    for (observed, validity, now) in [
        (1000, 2000, 999),
        (1000, 2000, 3000),
        (1000, 2000, 3001),
        (0, 2000, 1000),
        (1000, 0, 1000),
        (1000, 2001, 1000),
        (u64::MAX, 2000, 1000),
        (u64::MAX - 1000, 2000, u64::MAX - 500),
    ] {
        let mut changed = sample();
        changed.observed_at_unix_ms = observed;
        changed.valid_for_ms = validity;
        assert!(DisplayProtectionGenerationFacts::from_envelope(&changed, &boot(), now).is_err());
    }
    let mut short = sample();
    short.valid_for_ms = 1;
    value(DisplayProtectionGenerationFacts::from_envelope(
        &short,
        &boot(),
        1000,
    ));
    assert!(DisplayProtectionGenerationFacts::from_envelope(&short, &boot(), 1001).is_err());
}

#[test]
fn closed_generation_shape_rejects_unknown_missing_noncanonical_and_mistyped_fields() {
    for mutation in 0..10 {
        let mut changed = sample();
        match mutation {
            0 => {
                changed
                    .attributes
                    .insert("root_power_held".into(), ObservedValue::Bool(true));
            }
            1 => {
                changed.attributes.remove("sampled_boot_ms");
            }
            2 => {
                changed
                    .attributes
                    .insert("sampled_boot_ms".into(), ObservedValue::U64(0));
            }
            3 => {
                changed
                    .attributes
                    .insert("sampled_boot_ms".into(), ObservedValue::Text("50".into()));
            }
            4 => {
                changed
                    .attributes
                    .insert("protection_generation_schema".into(), ObservedValue::U64(2));
            }
            5 => {
                changed.attributes.insert(
                    "protection_generation_schema".into(),
                    ObservedValue::Bool(true),
                );
            }
            6 => {
                changed.attributes.insert(
                    "protection_invocation".into(),
                    ObservedValue::Text("00000000-0000-0000-0000-000000000000".into()),
                );
            }
            7 => {
                changed.attributes.insert(
                    "protection_invocation".into(),
                    ObservedValue::Text("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA".into()),
                );
            }
            8 => {
                changed
                    .attributes
                    .insert("protection_invocation".into(), ObservedValue::U64(42));
            }
            9 => {
                changed.attributes.insert(
                    "protection_invocation".into(),
                    ObservedValue::Text("22222222222242228222222222222222".into()),
                );
            }
            _ => unreachable!(),
        }
        assert!(
            DisplayProtectionGenerationFacts::from_envelope(&changed, &boot(), 1000).is_err(),
            "mutation {mutation}"
        );
    }
}
