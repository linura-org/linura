//! Simulated native wire facts, not actual compositor/DRM qualification.
use super::*;
use serde_json::{Value, json};
fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}
fn fixture() -> (DisplayOrdinaryReleaseScope, Value) {
    let topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c3:99:seat0:44444444-4444-4444-8444-444444444444:1";
    let scope = value(DisplayOrdinaryReleaseScope::new(
        &"a".repeat(64),
        value(DisplayTopologyId::from_resource(&value(
            linura_core::ResourceId::new(topology),
        ))),
    ));
    let raw = json!({"schema":1,"topology":topology,"original_dispatch":"a".repeat(64),"checkpoint":"b".repeat(64),
        "original_transaction":"transaction:restored","original_effect":"c".repeat(64),
        "release_transaction":"transaction:terminal","release_effect":"e".repeat(64),"release_dispatch":"f".repeat(64),
        "terminal_record":"1".repeat(64),"signed_binding":"3".repeat(64),"preparation_digest":"4".repeat(64),"outcome":"keep","source_guard":"2".repeat(64),"post_write_epoch":"3","security_epoch":"4",
        "sampled_unix_ms":"1001","sampled_boot_ms":"101","deadline_unix_ms":"1200","deadline_boot_ms":"300",
        "heads":[{"handle":"10","generation":"1","enabled":true,"connector":5,"crtc":7,"plane":8,"framebuffer":42,"spend_high_water":"90","completed_commit":"99"},
        {"handle":"20","generation":"2","enabled":false,"connector":6,"crtc":0,"plane":0,"framebuffer":0,"spend_high_water":"50","completed_commit":"51"}]});
    (scope, raw)
}
fn accepts(scope: &DisplayOrdinaryReleaseScope, raw: &Value) -> bool {
    project(&raw.to_string(), scope, 100, 102, 1000, 1002, 1).is_ok()
}

#[test]
fn native_first_frame_projection_does_not_renew_deadlines_or_observation_time() {
    let (scope, raw) = fixture();
    let envelope = value(project(&raw.to_string(), &scope, 100, 102, 1000, 1002, 1));
    assert_eq!(envelope.observed_at_unix_ms, 1001);
    assert_eq!(envelope.valid_for_ms, 199);
    let facts = value(DisplayOrdinaryHandoffFacts::from_envelope(
        &envelope, &scope, 1003,
    ));
    assert_eq!(facts.window().deadline_boot_ms, 300);
    assert_eq!(facts.window().deadline_unix_ms, 1200);
    for (start_boot, end_boot, start_unix, end_unix) in [
        (0, 102, 1000, 1002),
        (100, 99, 1000, 1002),
        (102, 103, 1000, 1002),
        (100, 100, 1000, 1002),
        (100, 300, 1000, 1002),
        (100, 2100, 1000, 1002),
        (100, 102, 0, 1002),
        (100, 102, 1002, 1003),
        (100, 102, 1000, 1000),
        (100, 102, 1000, 1200),
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
fn native_first_frame_rejects_missing_extra_cross_scope_or_retired_commit_facts() {
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
        ("released", json!(true)),
        ("topology", json!("display:topology:other")),
        ("original_dispatch", json!("f".repeat(64))),
        ("post_write_epoch", json!("0")),
        ("security_epoch", json!("0")),
        ("sampled_boot_ms", json!("0101")),
        ("sampled_boot_ms", json!("99")),
        ("sampled_boot_ms", json!("103")),
        ("sampled_unix_ms", json!("999")),
        ("sampled_unix_ms", json!("1003")),
        ("deadline_unix_ms", json!("1002")),
        ("deadline_boot_ms", json!("102")),
        ("deadline_unix_ms", json!("3002")),
        ("deadline_boot_ms", json!("2102")),
        ("heads", json!([])),
        ("source_guard", json!("0".repeat(64))),
        ("release_dispatch", raw["original_dispatch"].clone()),
    ] {
        let mut changed_raw = raw.clone();
        changed_raw[key] = changed;
        assert!(!accepts(&scope, &changed_raw), "{key}");
    }
    for (key, changed) in [
        ("handle", json!("010")),
        ("generation", json!("0")),
        ("connector", json!(0)),
        ("crtc", json!(0)),
        ("plane", json!(0)),
        ("framebuffer", json!(0)),
        ("spend_high_water", json!("99")),
        ("completed_commit", json!("90")),
        ("completed_commit", json!("099")),
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
    // Duplicate JSON keys must not select a second interpretation of a binding.
    let duplicate_key = raw.to_string().replacen("{", "{\"schema\":1,", 1);
    assert!(project(&duplicate_key, &scope, 100, 102, 1000, 1002, 1).is_err());
}
