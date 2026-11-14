use super::*;

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}
fn fixture() -> NativeDisplayRestorationReservation {
    let old = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3";
    let new = old.replace("c2:42", "c3:99").replace(
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
    );
    let lock = "session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1";
    let original = format!(
        "LNDI:1;{lock};LNDL:1;{old};1:2:enabled:1920:1080:60000:1000:0:0:0:-;LNDL:1;{old};1:2:enabled:1920:1080:60000:1000:0:100:0:-;"
    );
    let replacement = original
        .replace(old, &new)
        .replace("c2:42", "c3:99")
        .replace("0:100:0:-", "0:0:0:-");
    let mut material = "LNRI:1;".to_owned();
    for field in [
        "request:v010:display-layout:original",
        &"a".repeat(64),
        &"b".repeat(64),
        &"c".repeat(64),
        &original,
        &replacement,
        "1:2:1:2;",
    ] {
        material.push_str(&format!("{}:{field};", field.len()));
    }
    let effect = value(display_restoration_effect(&material));
    let binding = value(ExecutionBinding::new(
        "transaction:restoration-test",
        0,
        1,
        ComponentDigest::from_bytes([1; 32]),
        ComponentDigest::from_bytes([2; 32]),
        &effect,
    ));
    value(NativeDisplayRestorationReservation::new(
        &material, &binding,
    ))
}
#[test]
fn complete_binding_and_material_are_canonical_without_becoming_permission() {
    let record = fixture();
    let bytes = record.canonical_bytes();
    let decoded = value(NativeDisplayRestorationReservation::decode(&bytes));
    assert_eq!(decoded.binding(), record.binding());
    assert_eq!(decoded.material(), record.material());
    assert_eq!(decoded.canonical_bytes(), bytes);
    assert!(!format!("{record:?}").contains("LNRI:"));
    for end in 0..bytes.len() {
        assert!(NativeDisplayRestorationReservation::decode(&bytes[..end]).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(NativeDisplayRestorationReservation::decode(&extra).is_err());
    assert!(
        NativeDisplayRestorationReservation::decode(&vec![
            0;
            MAX_NATIVE_DISPLAY_RESTORATION_RESERVATION
                + 1
        ])
        .is_err()
    );
}
#[test]
fn binding_substitution_and_apply_purpose_are_rejected() {
    let record = fixture();
    for index in 0..7 {
        let mut binding = record.binding().clone();
        match index {
            0 => binding.transaction_id.push_str("-other"),
            1 => binding.generation += 1,
            2 => binding.state_version += 1,
            3 => binding.authority_binding_digest = ComponentDigest::from_bytes([3; 32]),
            4 => binding.authority_use_digest = ComponentDigest::from_bytes([3; 32]),
            5 => binding.effect_digest = ComponentDigest::from_bytes([3; 32]),
            _ => binding.dispatch_digest = ComponentDigest::from_bytes([3; 32]),
        }
        assert!(NativeDisplayRestorationReservation::new(record.material(), &binding).is_err());
    }
    let changed = record
        .material()
        .replacen(&"b".repeat(64), &"d".repeat(64), 1);
    assert!(NativeDisplayRestorationReservation::new(&changed, record.binding()).is_err());
    let material = value(record.decoded_material());
    let old = format!(
        "LNDI:1;{};",
        value(material.original().lock().resource_id()).as_str()
    );
    assert!(NativeDisplayRestorationReservation::new(&old, record.binding()).is_err());
    let zero = ComponentDigest::from_bytes([0; 32]);
    let effect = value(display_restoration_effect(record.material()));
    let binding = value(ExecutionBinding::new(
        "transaction:zero",
        0,
        1,
        zero,
        zero,
        &effect,
    ));
    assert!(NativeDisplayRestorationReservation::new(record.material(), &binding).is_err());
}
