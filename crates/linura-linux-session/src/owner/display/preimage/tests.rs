use super::*;
use serde_json::{Value, json};

const RULE: &str = concat!(
    "LNDR:1;0;0000000000000000;0000000000000000;404e000000000000;",
    "0000000000000000;0000000000000000;bff0000000000000;0;0;;",
    "0;0;0;0;0;0;0;0;0;0;0;0;0;0;",
    "0000000000000000000000000000000000000000000000000000000000000000;"
);
fn inputs() -> (Value, Value) {
    let (mut native, _) = super::super::tests::inputs();
    native["heads"][0]["base_rule_digest"] =
        json!(ComponentDigest::from_bytes(Sha256::digest(RULE.as_bytes()).into()).to_hex());
    let head = &native["heads"][0];
    let saved = json!({"schema":1,"upstream":"efb50993780079460b0cbed1363e2166a2de1d9f",
        "integration":"a".repeat(64), "generation":"3", "heads":[{
            "handle":head["handle"],"generation":head["generation"],
            "kernel_drm":head["kernel_drm"],"linura_owned":head["linura_owned"],
            "owned_target":head["owned_target"],"output_identity_digest":head["output_identity_digest"],
            "base_rule":RULE}]});
    (saved, native)
}
fn accepts(saved: &Value, native: &Value) -> bool {
    validate(&saved.to_string(), &native.to_string()).is_ok()
}
#[test]
fn root_preimage_matches_every_exact_original_native_row() {
    let (saved, native) = inputs();
    assert!(accepts(&saved, &native));
    for (key, bad) in [
        ("handle", json!("2")),
        ("generation", json!("3")),
        ("kernel_drm", json!([226, 0, 2])),
        ("linura_owned", json!(true)),
        ("owned_target", json!("LNOT:1;")),
        ("output_identity_digest", json!("c".repeat(64))),
        (
            "base_rule",
            json!(RULE.replacen("LNDR:1;0;", "LNDR:1;1;", 1)),
        ),
    ] {
        let mut changed = saved.clone();
        changed["heads"][0][key] = bad;
        assert!(!accepts(&changed, &native), "{key}");
    }
    for (key, bad) in [
        ("schema", json!(2)),
        ("generation", json!("4")),
        ("upstream", json!("0".repeat(40))),
        ("integration", json!("0".repeat(64))),
        ("integration", json!("A".repeat(64))),
        ("heads", json!([])),
        ("extra", json!("unreviewed")),
    ] {
        let mut changed = saved.clone();
        changed[key] = bad;
        assert!(!accepts(&changed, &native), "{key}");
    }
    for key in [
        "kernel_drm",
        "base_rule",
        "owned_target",
        "output_identity_digest",
    ] {
        let mut changed = saved.clone();
        changed["heads"][0]
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .remove(key);
        assert!(!accepts(&changed, &native), "{key}");
    }
    let mut duplicate = saved.clone();
    duplicate["heads"]
        .as_array_mut()
        .unwrap_or_else(|| unreachable!())
        .push(saved["heads"][0].clone());
    let mut extra = native.clone();
    extra["heads"]
        .as_array_mut()
        .unwrap_or_else(|| unreachable!())
        .push(native["heads"][0].clone());
    assert!(!accepts(&duplicate, &extra));
    assert!(validate(&"x".repeat(MAX_PREIMAGE + 1), &native.to_string()).is_err());
    assert!(
        validate(
            &saved
                .to_string()
                .replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1),
            &native.to_string()
        )
        .is_err()
    );
}
#[test]
fn native_rule_bytes_are_canonical_bounded_and_exactly_reconstructable() {
    assert!(rule(RULE).is_ok());
    for end in 0..RULE.len() {
        assert!(rule(&RULE[..end]).is_err());
    }
    for bad in [
        RULE.to_owned() + ";",
        RULE.replacen("LNDR:1;", "LNDR:2;", 1),
        RULE.replacen("LNDR:1;0;", "LNDR:1;00;", 1),
        RULE.replacen("0000000000000000", "8000000000000000", 1),
        RULE.replacen("0000000000000000", "7ff0000000000000", 1),
        RULE.replacen("0000000000000000", "7ff8000000000000", 1),
        RULE.replacen("404e000000000000", "3ff0000000000001", 1),
        RULE.replacen("404e000000000000", "47efffffe0000001", 1),
        RULE.replacen("404e000000000000", "404E000000000000", 1),
        RULE.replacen(";0;0;;", ";9;0;;", 1),
        RULE.replacen(";0;0;;", ";0;8;;", 1),
        RULE.replacen(";;0;0;", ";;4294967296;0;", 1),
        RULE.replacen(";;0;0;", ";;0;65536;", 1),
        RULE.replacen(";;", &format!(";{};", "a".repeat(8194)), 1),
        "x".repeat(12 * 1024 + 1),
    ] {
        assert!(rule(&bad).is_err());
    }
}

#[test]
fn checkpoint_retains_original_binding_owner_and_clocks_without_logging_preimages() {
    let (saved, native) = inputs();
    let coverage = super::super::tests::coverage(true);
    let material = format!(
        "LNDI:1;{};LNDL:1;display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3;1:2:enabled:1920:1080:59940:1250:0:0:0:-;LNDL:1;display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3;1:2:enabled:1920:1080:59940:1250:0:100:0:-;",
        coverage.resource.as_str()
    );
    let effect = linura_provider_sdk::display_layout_effect(&material)
        .unwrap_or_else(|e| unreachable!("{e}"));
    let binding = ExecutionBinding::new(
        "transaction:display-checkpoint",
        0,
        1,
        ComponentDigest::from_bytes([1; 32]),
        ComponentDigest::from_bytes([2; 32]),
        &effect,
    )
    .unwrap_or_else(|e| unreachable!("{e}"));
    let mut sample = PreparedSample {
        owner: crate::owner::NativeOwnerIdentity {
            unique_name: ":1.42".into(),
            uid: 1000,
            pid: 42,
            invocation: linura_core::SecurityOwnerInvocationId::new(
                "22222222-2222-4222-8222-222222222222",
            )
            .unwrap_or_else(|e| unreachable!("{e}")),
        },
        boot: linura_core::BootId::new("11111111-1111-4111-8111-111111111111")
            .unwrap_or_else(|e| unreachable!("{e}")),
        started: Instant::now(),
        digest: ComponentDigest::from_bytes([3; 32]),
        sampled_boot_ms: 100,
        native_baseline_guard: Some(ComponentDigest::from_bytes([4; 32])),
        recovery_preimage: checked(saved.to_string(), &native.to_string())
            .unwrap_or_else(|e| unreachable!("{e}")),
    };
    let record = NativeDisplayRecoveryCheckpoint::capture(&material, &binding, 25_000, &sample)
        .unwrap_or_else(|e| unreachable!("{e}"));
    assert_eq!(record.dispatch_digest(), &binding.dispatch_digest);
    assert_eq!(record.kernel_outputs(), &[[226, 0, 1]]);
    let mut cursor = record.canonical_bytes();
    let mut fields = Vec::new();
    while !cursor.is_empty() {
        let size = u64::from_be_bytes(
            cursor[..8]
                .try_into()
                .unwrap_or_else(|e| unreachable!("{e}")),
        ) as usize;
        fields.push(
            std::str::from_utf8(&cursor[8..8 + size]).unwrap_or_else(|e| unreachable!("{e}")),
        );
        cursor = &cursor[8 + size..];
    }
    assert_eq!(fields.len(), 19);
    assert_eq!(fields[7], binding.dispatch_digest.to_hex());
    assert_eq!(fields[8], material);
    assert_eq!(
        &fields[9..16],
        &[
            "25000",
            sample.boot.as_str(),
            ":1.42",
            "1000",
            "42",
            sample.owner.invocation.as_str(),
            "100"
        ]
    );
    assert_eq!(fields[18], sample.recovery_preimage);
    assert!(!format!("{record:?}").contains("LNDR:") && !format!("{record:?}").contains("LNDI:"));
    sample.native_baseline_guard = None;
    assert!(
        NativeDisplayRecoveryCheckpoint::capture(&material, &binding, 25_000, &sample).is_err()
    );
}
