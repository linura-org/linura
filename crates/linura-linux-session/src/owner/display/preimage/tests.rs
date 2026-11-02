use super::*;
use serde_json::{Value, json};

const RULE: &str = concat!(
    "LNDR:2;0;0000000000000000;0000000000000000;404e000000000000;",
    "0000000000000000;0000000000000000;bff0000000000000;0;0;;",
    "0;0;0;0;0;0;0;0;0;0;0;0;0;0;",
    "0000000000000000000000000000000000000000000000000000000000000000;;"
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
            json!(RULE.replacen("LNDR:2;0;", "LNDR:2;1;", 1)),
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
        RULE.replacen("LNDR:2;", "LNDR:3;", 1),
        RULE.replacen("LNDR:2;0;", "LNDR:2;00;", 1),
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
        "x".repeat(20 * 1024 + 1),
    ] {
        assert!(rule(&bad).is_err());
    }
}

#[test]
fn selector_lineage_is_bounded_canonical_and_required_for_new_preimages() {
    let with_selector = |selector: &str| format!("{}{selector};", &RULE[..RULE.len() - 1]);
    // Same byte representation as the native codec: arbitrary selector bytes
    // are comparison data, never parsed as a command or reapplied as a rule.
    for selector in [
        String::new(),
        "646573633a44502d31".into(),
        "ff00".into(),
        "61".repeat(4096),
    ] {
        assert!(rule(&with_selector(&selector)).is_ok());
    }
    for selector in [
        "0".into(),
        "GG".into(),
        "AA".into(),
        "61;62".into(),
        "61".repeat(4097),
    ] {
        assert!(rule(&with_selector(&selector)).is_err());
    }
    let legacy = RULE[..RULE.len() - 1].replacen("LNDR:2;", "LNDR:1;", 1);
    assert!(validate_rule(&legacy, true).is_ok());
    assert!(rule(&legacy).is_err());
    // A version-1 label cannot carry a version-2 selector or an alternate tail.
    assert!(validate_rule(&RULE.replacen("LNDR:2;", "LNDR:1;", 1), true).is_err());
    assert!(validate_rule(&(legacy + "garbage"), true).is_err());
    let (mut saved, mut native) = inputs();
    saved["heads"][0]["base_rule"] = json!(with_selector("646573633a44502d31"));
    assert!(!accepts(&saved, &native)); // Same geometry cannot substitute lineage.
    native["heads"][0]["base_rule_digest"] = json!(
        ComponentDigest::from_bytes(
            Sha256::digest(
                saved["heads"][0]["base_rule"]
                    .as_str()
                    .unwrap_or_default()
                    .as_bytes()
            )
            .into()
        )
        .to_hex()
    );
    assert!(accepts(&saved, &native));
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
    assert!(
        NativeDisplayRecoveryCheckpoint::validate_stored(
            record.canonical_bytes(),
            &binding.dispatch_digest
        )
        .is_ok()
    );
    assert_eq!(
        NativeDisplayRecoveryCheckpoint::stored_dispatch(record.canonical_bytes()),
        Ok(binding.dispatch_digest)
    );
    assert_eq!(record.kernel_outputs(), &[[226, 0, 1]]);
    assert_eq!(
        NativeDisplayRecoveryCheckpoint::original_startup_scope(
            record.canonical_bytes(),
            &binding.dispatch_digest
        )
        .ok(),
        Some((
            linura_core::DisplayLayoutMaterial::decode(&material)
                .unwrap_or_else(|e| unreachable!("{e}"))
                .topology()
                .clone(),
            ComponentDigest::parse_hex(&"a".repeat(64)).unwrap_or_else(|e| unreachable!("{e}"))
        ))
    );

    let reserve = |subscription, boot_ms, unix_ms, boot| {
        NativeDisplayRecoveryCheckpoint::reservation_at(
            record.canonical_bytes(),
            &binding.dispatch_digest,
            subscription,
            boot_ms,
            unix_ms,
            boot,
        )
    };
    assert_eq!(
        reserve(100, 101, 10_000, sample.boot.as_str()).ok(),
        Some(vec![[226, 0, 1]])
    );
    assert!(reserve(99, 2099, 24_999, sample.boot.as_str()).is_ok());
    for (subscription, boot_ms, unix_ms, boot) in [
        (0, 101, 10_000, sample.boot.as_str()),
        (101, 101, 10_000, sample.boot.as_str()),
        (100, 99, 10_000, sample.boot.as_str()),
        (100, 2100, 10_000, sample.boot.as_str()),
        (100, 101, 25_000, sample.boot.as_str()),
        (100, 101, 25_001, sample.boot.as_str()),
        (100, 101, 9_999, sample.boot.as_str()),
        (100, 101, 10_000, "22222222-2222-4222-8222-222222222222"),
    ] {
        assert!(reserve(subscription, boot_ms, unix_ms, boot).is_err());
    }
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
    // Previously persisted owned-field records remain readable as history;
    // lacking selector lineage never becomes a new reservation or permission.
    let legacy_rule = RULE[..RULE.len() - 1].replacen("LNDR:2;", "LNDR:1;", 1);
    let mut legacy_preimage = saved.clone();
    legacy_preimage["heads"][0]["base_rule"] = json!(legacy_rule);
    let legacy_preimage = legacy_preimage.to_string();
    let mut legacy_fields = fields.clone();
    legacy_fields[18] = &legacy_preimage;
    let mut legacy_bytes = Vec::new();
    for field in legacy_fields {
        legacy_bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        legacy_bytes.extend_from_slice(field.as_bytes());
    }
    assert!(
        NativeDisplayRecoveryCheckpoint::validate_stored(&legacy_bytes, &binding.dispatch_digest)
            .is_ok()
    );
    assert!(
        NativeDisplayRecoveryCheckpoint::reservation_at(
            &legacy_bytes,
            &binding.dispatch_digest,
            100,
            101,
            10_000,
            sample.boot.as_str()
        )
        .is_err()
    );
    assert_eq!(fields[18], sample.recovery_preimage); // No implicit migration.
    for index in 1..19 {
        let mut changed = fields.clone();
        changed[index] = "unsupported-or-substituted";
        let mut bytes = Vec::new();
        for field in changed {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        assert!(
            NativeDisplayRecoveryCheckpoint::validate_stored(&bytes, &binding.dispatch_digest)
                .is_err(),
            "field {index}"
        );
    }
    assert!(!format!("{record:?}").contains("LNDR:") && !format!("{record:?}").contains("LNDI:"));
    sample.native_baseline_guard = None;
    assert!(
        NativeDisplayRecoveryCheckpoint::capture(&material, &binding, 25_000, &sample).is_err()
    );
}
