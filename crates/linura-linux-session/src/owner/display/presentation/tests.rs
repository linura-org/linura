//! Simulated native JSON comparison/refusal, not KMS or frame acceptance.
use super::*;
use serde_json::{Value, json};
fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}
fn fixture() -> (DisplayRecoveryScope, Value) {
    let topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c3:99:seat0:44444444-4444-4444-8444-444444444444:1";
    let scope = value(DisplayRecoveryScope::new(
        &"a".repeat(64),
        value(DisplayTopologyId::from_resource(&value(
            linura_core::ResourceId::new(topology),
        ))),
    ));
    let raw = json!({"schema":1,"topology":topology,"original_dispatch":"a".repeat(64),"checkpoint":"b".repeat(64),
        "transaction":"transaction:restoration", "effect":"c".repeat(64),"dispatch":"d".repeat(64),"source_guard":"e".repeat(64),
        "sampled_boot_ms":"101","post_write_epoch":"3","heads":[
            {"handle":"10","generation":"1","enabled":true,"crtc":7,"framebuffer":42,"commit":"99"},
            {"handle":"20","generation":"2","enabled":false,"crtc":0,"framebuffer":0,"commit":"0"}]});
    (scope, raw)
}
fn accepts(scope: &DisplayRecoveryScope, raw: &Value) -> bool {
    project(&raw.to_string(), scope, 100, 102, 1000, 1002, 1).is_ok()
}

#[test]
fn bounded_native_post_write_facts_preserve_scope_and_original_probe_deadline() {
    let (scope, raw) = fixture();
    let envelope = value(project(&raw.to_string(), &scope, 100, 102, 1000, 1002, 1));
    assert_eq!(envelope.observed_at_unix_ms, 1000);
    assert_eq!(envelope.valid_for_ms, 2000);
    let facts = value(DisplayOriginalPresentationFacts::from_envelope(
        &envelope, &scope, 1003,
    ));
    assert!(facts.matches_binding(
        &"b".repeat(64),
        "transaction:restoration",
        &"c".repeat(64),
        &"d".repeat(64)
    ));
    assert_eq!(facts.source_guard(), "e".repeat(64));
    for (start_boot, end_boot, start_unix, end_unix) in [
        (0, 102, 1000, 1002),
        (100, 99, 1000, 1002),
        (102, 103, 1000, 1002),
        (100, 100, 1000, 1002),
        (100, 2100, 1000, 1002),
        (100, 102, 0, 1002),
        (100, 102, 1000, 999),
        (100, 102, 1000, 3000),
    ] {
        assert!(
            project(
                &raw.to_string(),
                &scope,
                start_boot,
                end_boot,
                start_unix,
                end_unix,
                1
            )
            .is_err()
        );
    }
    assert!(project(&raw.to_string(), &scope, 100, 102, 1000, 1002, 0).is_err());
}

#[test]
fn missing_unknown_cross_scope_or_incomplete_raw_native_presentation_fails_closed() {
    let (scope, raw) = fixture();
    assert!(accepts(&scope, &raw));
    for key in raw
        .as_object()
        .unwrap_or_else(|| unreachable!("object"))
        .keys()
    {
        let mut missing = raw.clone();
        missing
            .as_object_mut()
            .unwrap_or_else(|| unreachable!("object"))
            .remove(key);
        assert!(!accepts(&scope, &missing), "{key}");
    }
    for (key, changed) in [
        ("schema", json!(2)),
        ("state", json!("restored")),
        ("original_dispatch", json!("f".repeat(64))),
        ("topology", json!("display:topology:another")),
        ("post_write_epoch", json!("0")),
        ("sampled_boot_ms", json!("0101")),
        ("sampled_boot_ms", json!("99")),
        ("sampled_boot_ms", json!("103")),
        ("heads", json!([])),
        ("source_guard", json!("0".repeat(64))),
    ] {
        let mut changed_raw = raw.clone();
        changed_raw[key] = changed;
        assert!(!accepts(&scope, &changed_raw), "{key}");
    }
    for (key, changed) in [
        ("handle", json!("010")),
        ("generation", json!("0")),
        ("crtc", json!(0)),
        ("framebuffer", json!(0)),
        ("commit", json!("0")),
        ("commit", json!("099")),
        ("enabled", json!(false)),
        ("extra", json!(true)),
    ] {
        let mut changed_raw = raw.clone();
        changed_raw["heads"][0][key] = changed;
        assert!(!accepts(&scope, &changed_raw), "{key}");
    }
    let mut duplicate = raw.clone();
    duplicate["heads"][1] = raw["heads"][0].clone();
    assert!(!accepts(&scope, &duplicate));
    let mut reordered = raw.clone();
    reordered["heads"]
        .as_array_mut()
        .unwrap_or_else(|| unreachable!("heads"))
        .reverse();
    assert!(!accepts(&scope, &reordered));
    for end in 0..raw.to_string().len() {
        assert!(project(&raw.to_string()[..end], &scope, 100, 102, 1000, 1002, 1).is_err());
    }
    assert!(project(&"x".repeat(16 * 1024 + 1), &scope, 100, 102, 1000, 1002, 1).is_err());
}
