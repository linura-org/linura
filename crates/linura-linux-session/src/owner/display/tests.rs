use super::*;
use linura_core::{BootId, SecurityOwnerInvocationId};
use serde_json::{Value, json};

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}
const COMPOSITOR: &str = "33333333-3333-4333-8333-333333333333";
fn coverage(secure: bool) -> ObservationEnvelope {
    let boot = value(BootId::new("11111111-1111-4111-8111-111111111111"));
    let invocation = value(SecurityOwnerInvocationId::new(
        "22222222-2222-4222-8222-222222222222",
    ));
    let identity = crate::owner::NativeOwnerIdentity {
        unique_name: ":1.42".into(),
        uid: 1000,
        pid: 42,
        invocation,
    };
    value(observation(
        &identity,
        &boot,
        "session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1",
        secure,
        100,
        100,
        10000,
        1,
    ))
}
fn inputs() -> (Value, Value) {
    let head = json!({"handle":"1", "generation":"2", "name":"DP-1", "enabled":true,
        "covered":true, "modes":[[1920,1080,59940],[1280,720,60000]], "current_mode":[1920,1080,59940],
        "x":0, "y":0, "transform":0, "scale_fixed":320});
    (
        json!({"schema":1, "generation":"3", "heads":[head]}),
        json!([{"id":0,"name":"DP-1",
        "disabled":false,"dpmsStatus":true,"mirrorOf":"none", "availableModes":["1920x1080@59.94Hz"]}]),
    )
}
fn decode(
    topology: &Value,
    monitors: &Value,
) -> Result<(ObservationEnvelope, ObservationEnvelope), String> {
    project(
        coverage(true),
        COMPOSITOR,
        "seat0",
        &topology.to_string(),
        &monitors.to_string(),
    )
}
#[test]
fn exact_native_modes_scale_and_coverage_enter_only_canonical_envelopes() {
    let (topology, monitors) = inputs();
    let (display, coverage) = value(decode(&topology, &monitors));
    let identity = value(DisplayTopologyId::from_resource(&display.resource));
    let facts = value(linura_observation::DisplayObservationFacts::from_envelope(
        &display, &identity, 10000,
    ));
    assert_eq!(facts.inventory().outputs()[0].handle(), 1);
    assert!(facts.has_powered_independent_output());
    assert_eq!(coverage.capability.as_str(), DISPLAY_COVERAGE_CAPABILITY);
    assert_eq!(
        coverage.attributes["display_topology"],
        ObservedValue::Text(display.resource.as_str().into())
    );
    assert_eq!(
        coverage.attributes["covered_outputs"],
        ObservedValue::Text("1:2".into())
    );
    assert!(
        matches!(facts.layout().outputs()[0], DisplayOutputLayout::Enabled { mode, scale, .. }
        if mode.refresh_millihz() == 59940 && scale.milli() == 1250)
    );
    assert!(!display.attributes.contains_key("name"));
    assert!(
        !display
            .attributes
            .values()
            .any(|value| value.to_string().contains("DP-1"))
    );
}
#[test]
fn closed_native_schema_rejects_missing_unknown_duplicate_and_wrong_types() {
    let (topology, monitors) = inputs();
    for key in ["schema", "generation", "heads"] {
        let mut bad = topology.clone();
        bad.as_object_mut()
            .unwrap_or_else(|| unreachable!("typed fixture"))
            .remove(key);
        assert!(decode(&bad, &monitors).is_err(), "{key}");
    }
    for key in [
        "handle",
        "generation",
        "name",
        "enabled",
        "covered",
        "modes",
        "current_mode",
        "x",
        "y",
        "transform",
        "scale_fixed",
    ] {
        let mut bad = topology.clone();
        bad["heads"][0]
            .as_object_mut()
            .unwrap_or_else(|| unreachable!("typed fixture"))
            .remove(key);
        assert!(decode(&bad, &monitors).is_err(), "{key}");
    }
    let mut bad = topology.clone();
    bad["unknown"] = json!(1);
    assert!(decode(&bad, &monitors).is_err());
    for raw in [
        topology
            .to_string()
            .replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1),
        topology
            .to_string()
            .replacen("\"schema\":1", "\"schema\":1,\"sch\\u0065ma\":1", 1),
    ] {
        assert!(
            project(
                coverage(true),
                COMPOSITOR,
                "seat0",
                &raw,
                &monitors.to_string()
            )
            .is_err()
        );
    }
    let mut bad = topology.clone();
    bad["heads"][0]["enabled"] = json!(1);
    assert!(decode(&bad, &monitors).is_err());
    for field in ["id", "name", "disabled", "dpmsStatus", "mirrorOf"] {
        let mut bad = monitors.clone();
        bad[0]
            .as_object_mut()
            .unwrap_or_else(|| unreachable!("typed fixture"))
            .remove(field);
        assert!(decode(&topology, &bad).is_err());
    }
    let bad = monitors.to_string().replacen(
        "\"disabled\":false",
        "\"disabled\":false,\"disabled\":true",
        1,
    );
    assert!(
        project(
            coverage(true),
            COMPOSITOR,
            "seat0",
            &topology.to_string(),
            &bad
        )
        .is_err()
    );
}
#[test]
fn independent_inventory_and_supported_native_precision_cannot_be_substituted() {
    let (topology, monitors) = inputs();
    for (field, invalid) in [
        ("name", json!("HDMI-A-1")),
        ("disabled", json!(true)),
        ("mirrorOf", json!("99")),
    ] {
        let mut bad = monitors.clone();
        bad[0][field] = invalid;
        assert!(decode(&topology, &bad).is_err());
    }
    for (field, invalid) in [
        ("scale_fixed", json!(257)),
        ("transform", json!(8)),
        ("current_mode", json!([1920, 1080, 60000])),
        ("x", json!(65537)),
        ("current_mode", json!(null)),
    ] {
        let mut bad = topology.clone();
        bad["heads"][0][field] = invalid;
        assert!(decode(&bad, &monitors).is_err());
    }
    for invalid in [
        "0",
        "01",
        "+1",
        "18446744073709551615",
        "18446744073709551616",
    ] {
        let mut bad = topology.clone();
        bad["generation"] = json!(invalid);
        assert!(decode(&bad, &monitors).is_err());
    }
    assert!(
        project(
            coverage(true),
            COMPOSITOR,
            "current",
            &topology.to_string(),
            &monitors.to_string()
        )
        .is_err()
    );
    assert!(
        project(
            coverage(true),
            "00000000-0000-0000-0000-000000000000",
            "seat0",
            &topology.to_string(),
            &monitors.to_string()
        )
        .is_err()
    );
}
#[test]
fn duplicate_heads_names_modes_and_metadata_ids_are_not_normalized() {
    let (topology, monitors) = inputs();
    let mut bad = topology.clone();
    bad["heads"]
        .as_array_mut()
        .unwrap_or_else(|| unreachable!("typed fixture"))
        .push(topology["heads"][0].clone());
    let mut two = monitors.clone();
    two.as_array_mut()
        .unwrap_or_else(|| unreachable!("typed fixture"))
        .push(monitors[0].clone());
    assert!(decode(&bad, &two).is_err());
    let mut bad = topology.clone();
    bad["heads"][0]["modes"]
        .as_array_mut()
        .unwrap_or_else(|| unreachable!("typed fixture"))
        .push(json!([1920, 1080, 59940]));
    assert!(decode(&bad, &monitors).is_err());
    let mut bad = topology.clone();
    bad["heads"][0]["modes"] = json!([]);
    assert!(decode(&bad, &monitors).is_err());
    let mut bad = topology.clone();
    bad["heads"][0]["modes"] = json!(vec![[1920, 1080, 59940]; 129]);
    assert!(decode(&bad, &monitors).is_err());
}
#[test]
fn mirrors_use_attested_inventory_identity_and_power_is_independent() {
    let (mut topology, mut monitors) = inputs();
    let mut head = topology["heads"][0].clone();
    head["handle"] = json!("2");
    head["generation"] = json!("4");
    head["name"] = json!("HDMI-A-1");
    topology["heads"]
        .as_array_mut()
        .unwrap_or_else(|| unreachable!("typed fixture"))
        .push(head);
    monitors
        .as_array_mut()
        .unwrap_or_else(|| unreachable!("typed fixture"))
        .push(json!({"id":7,"name":"HDMI-A-1","disabled":false,"dpmsStatus":false,"mirrorOf":"0"}));
    let (display, _) = value(decode(&topology, &monitors));
    let identity = value(DisplayTopologyId::from_resource(&display.resource));
    let facts = value(linura_observation::DisplayObservationFacts::from_envelope(
        &display, &identity, 10000,
    ));
    assert!(
        matches!(&facts.layout().outputs()[1], DisplayOutputLayout::Enabled { mirror:Some(root), .. } if root.handle() == 1)
    );
    assert_eq!(facts.powered_outputs().len(), 1);
    monitors[0]["mirrorOf"] = json!("7");
    assert!(decode(&topology, &monitors).is_err());
    monitors[0]["mirrorOf"] = json!("none");
    topology["heads"][1]["handle"] = json!("1");
    assert!(decode(&topology, &monitors).is_err());
}
#[test]
fn settled_unlocked_coverage_is_empty_and_incomplete_secure_coverage_is_visible() {
    let (mut topology, monitors) = inputs();
    assert!(
        project(
            coverage(false),
            COMPOSITOR,
            "seat0",
            &topology.to_string(),
            &monitors.to_string()
        )
        .is_err()
    );
    topology["heads"][0]["covered"] = json!(false);
    let (_, uncovered) = value(decode(&topology, &monitors));
    assert_eq!(
        uncovered.attributes["covered_outputs"],
        ObservedValue::Text(String::new())
    );
    let (_, unlocked) = value(project(
        coverage(false),
        COMPOSITOR,
        "seat0",
        &topology.to_string(),
        &monitors.to_string(),
    ));
    assert_eq!(unlocked.attributes["secure"], ObservedValue::Bool(false));
    assert_eq!(
        unlocked.attributes["observed_outputs"],
        ObservedValue::Text("1:2".into())
    );
    assert!(
        project(
            coverage(true),
            COMPOSITOR,
            "seat0",
            &"x".repeat(65537),
            &monitors.to_string()
        )
        .is_err()
    );
    let mut invalid = coverage(true);
    invalid.sequence = 0;
    assert!(
        project(
            invalid,
            COMPOSITOR,
            "seat0",
            &topology.to_string(),
            &monitors.to_string()
        )
        .is_err()
    );
}

#[test]
fn prepared_sample_digest_matches_native_framing_and_binds_every_raw_fact() {
    let sample: Wire = (
        "session:lock:fixture".into(),
        "id".into(),
        "seat0".into(),
        100,
        "{}".into(),
        "[]".into(),
        false,
    );
    let digest = sample_digest(&sample);
    assert_eq!(
        digest.to_hex(),
        "44b57ddd19b647a800af370d9c77da32ca2ee684d62b906773639292c9367c57"
    );
    for field in 0..6 {
        let mut changed = sample.clone();
        match field {
            0 => changed.0.push('x'),
            1 => changed.1.push('x'),
            2 => changed.2.push('x'),
            3 => changed.4.push(' '),
            4 => changed.5.push(' '),
            _ => changed.6 = true,
        }
        assert_ne!(sample_digest(&changed), digest);
    }
    // Probe time is separately checked against the original native boot-clock
    // deadline. It cannot be in a content digest compared across two probes.
    let mut sampled_later = sample;
    sampled_later.3 += 1;
    assert_eq!(sample_digest(&sampled_later), digest);
}
