use super::*;
use linura_core::{BootId, SecurityOwnerInvocationId};
use serde_json::{Value, json};

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}
const COMPOSITOR: &str = "33333333-3333-4333-8333-333333333333";
pub(super) fn coverage(secure: bool) -> ObservationEnvelope {
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
        "x":0, "y":0, "transform":0, "scale_fixed":320,
        "scale_milli":1250, "scale_float_bits":1.25_f32.to_bits(),
        "linura_owned":false, "owned_target":"", "base_rule_digest":"a".repeat(64),
        "output_identity_digest":"b".repeat(64)});
    (
        json!({"schema":3, "generation":"3", "heads":[head]}),
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
    assert!(
        !value(facts.recovery_metadata().ok_or("missing recovery"))
            .values()
            .next()
            .unwrap_or_else(|| unreachable!("output"))
            .linura_owned()
    );
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
fn overlay_checkpoint_requires_exact_owned_target_without_hiding_partial_layouts() {
    let (mut topology, monitors) = inputs();
    topology["heads"][0]["linura_owned"] = json!(true);
    topology["heads"][0]["owned_target"] = json!("LNOT:1;1;2;1;1920;1080;59940;1250;0;0;0;0;0;");
    let (display, _) = value(decode(&topology, &monitors));
    let identity = value(DisplayTopologyId::from_resource(&display.resource));
    let facts = value(linura_observation::DisplayObservationFacts::from_envelope(
        &display, &identity, 10000,
    ));
    assert!(
        value(facts.recovery_metadata().ok_or("missing metadata"))
            .values()
            .all(|value| value.linura_owned())
    );
    // A real partially applied target is observable; it cannot be saved as LKG.
    topology["heads"][0]["owned_target"] = json!("LNOT:1;1;2;1;1280;720;60000;1000;0;0;0;0;0;");
    let (partial, _) = value(decode(&topology, &monitors));
    let partial_facts = value(linura_observation::DisplayObservationFacts::from_envelope(
        &partial, &identity, 10000,
    ));
    assert!(partial_facts.recovery_metadata().is_none());
    assert_eq!(partial_facts.layout(), facts.layout());
    for invalid in [
        "",
        "LNOT:2;1;2;1;1920;1080;59940;1250;0;0;0;0;0;",
        "LNOT:1;1;3;1;1920;1080;59940;1250;0;0;0;0;0;",
        "LNOT:1;1;2;0;1920;1080;59940;1250;0;0;0;0;0;",
        "LNOT:1;1;2;1;1920;1080;59940;1250;0;-0;0;0;0;",
        "LNOT:1;1;2;1;1920;1080;59940;1250;0;0;0;1;2;",
        "LNOT:1;1;2;1;1920;1080;59940;1250;0;0;0;9;2;",
        "LNOT:1;01;2;1;1920;1080;59940;1250;0;0;0;0;0;",
    ] {
        topology["heads"][0]["owned_target"] = json!(invalid);
        assert!(decode(&topology, &monitors).is_err(), "{invalid}");
    }
    for (key, invalid) in [
        ("base_rule_digest", json!("A".repeat(64))),
        ("output_identity_digest", json!("0".repeat(64))),
    ] {
        let (mut bad, monitors) = inputs();
        bad["heads"][0][key] = invalid;
        assert!(decode(&bad, &monitors).is_err());
    }
}

#[test]
fn original_native_baseline_guard_has_cross_language_vectors_and_rejects_drift() {
    let (mut topology, monitors) = inputs();
    let guard = |topology: &Value| {
        let (display, _) = value(decode(topology, &monitors));
        let scope = value(DisplayTopologyId::from_resource(&display.resource));
        let facts = value(linura_observation::DisplayObservationFacts::from_envelope(
            &display, &scope, 10000,
        ));
        value(linura_provider_sdk::display_baseline_guard(&facts)).to_hex()
    };
    assert_eq!(
        guard(&topology),
        "3982e30fe93e501fb6940d694fe0e19da3d66c3dee2c3f23cd7165ff3b2f6948"
    );
    topology["heads"][0]["linura_owned"] = json!(true);
    topology["heads"][0]["owned_target"] = json!("LNOT:1;1;2;1;1920;1080;59940;1250;0;0;0;0;0;");
    let original = guard(&topology);
    assert_eq!(
        original,
        "706b46fd9ed14f8a56238057e390924b131c5c134935e532faff42763292b21b"
    );
    for key in ["base_rule_digest", "output_identity_digest"] {
        let mut changed = topology.clone();
        changed["heads"][0][key] = json!("c".repeat(64));
        assert_ne!(guard(&changed), original);
    }
    let (mut two, mut monitors) = inputs();
    let mut second = two["heads"][0].clone();
    for (key, value) in [
        ("handle", json!("2")),
        ("generation", json!("3")),
        ("name", json!("DP-2")),
        ("enabled", json!(false)),
        ("covered", json!(false)),
        ("current_mode", json!(null)),
        ("scale_fixed", json!(0)),
        ("scale_milli", json!(0)),
        ("scale_float_bits", json!(0)),
        ("linura_owned", json!(true)),
        ("base_rule_digest", json!("c".repeat(64))),
        ("output_identity_digest", json!("d".repeat(64))),
        ("owned_target", json!("LNOT:1;2;3;0;0;0;0;0;0;0;0;0;0;")),
    ] {
        second[key] = value;
    }
    two["heads"]
        .as_array_mut()
        .unwrap_or_else(|| unreachable!("heads"))
        .push(second);
    monitors
        .as_array_mut()
        .unwrap_or_else(|| unreachable!("monitors"))
        .push(json!({
        "id":1,"name":"DP-2","disabled":true,"dpmsStatus":false,"mirrorOf":"none"}));
    let (display, _) = value(decode(&two, &monitors));
    let scope = value(DisplayTopologyId::from_resource(&display.resource));
    let facts = value(linura_observation::DisplayObservationFacts::from_envelope(
        &display, &scope, 10000,
    ));
    assert_eq!(
        value(linura_provider_sdk::display_baseline_guard(&facts)).to_hex(),
        "568c84130da7712c595748f4dc80408d63ef01f64cca8486ddb5907cccaea21d"
    );
    for (key, value) in [
        ("enabled", json!(true)),
        ("covered", json!(true)),
        ("current_mode", json!([1920, 1080, 59940])),
        ("scale_fixed", json!(320)),
        ("scale_milli", json!(1250)),
        ("scale_float_bits", json!(1.25_f32.to_bits())),
        (
            "owned_target",
            json!("LNOT:1;2;3;1;1920;1080;59940;1250;0;0;0;1;2;"),
        ),
    ] {
        two["heads"][1][key] = value;
    }
    monitors[1]["disabled"] = json!(false);
    monitors[1]["dpmsStatus"] = json!(true);
    monitors[1]["mirrorOf"] = json!("0");
    let (display, _) = value(decode(&two, &monitors));
    let facts = value(linura_observation::DisplayObservationFacts::from_envelope(
        &display, &scope, 10000,
    ));
    assert_eq!(
        value(linura_provider_sdk::display_baseline_guard(&facts)).to_hex(),
        "f5284e6c0630a02c97f4bf8c2ccadf9282e835e4285b28d2baec0e10ee691721"
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
        "scale_milli",
        "scale_float_bits",
        "linura_owned",
        "owned_target",
        "base_rule_digest",
        "output_identity_digest",
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
            .replacen("\"schema\":3", "\"schema\":3,\"schema\":3", 1),
        topology
            .to_string()
            .replacen("\"schema\":3", "\"schema\":3,\"sch\\u0065ma\":3", 1),
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
        ("scale_milli", json!(1251)),
        ("scale_float_bits", json!(1.25_f32.to_bits() + 1)),
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
fn locked_disabled_output_keeps_identity_without_inheriting_surface_coverage() {
    let (mut topology, mut monitors) = inputs();
    let mut disabled = topology["heads"][0].clone();
    for (field, entry) in [
        ("handle", json!("2")),
        ("generation", json!("4")),
        ("name", json!("HDMI-A-1")),
        ("enabled", json!(false)),
        ("covered", json!(false)),
        ("current_mode", Value::Null),
        ("scale_fixed", json!(0)),
        ("scale_milli", json!(0)),
        ("scale_float_bits", json!(0)),
    ] {
        disabled[field] = entry;
    }
    topology["heads"]
        .as_array_mut()
        .unwrap_or_else(|| unreachable!("typed fixture"))
        .push(disabled);
    monitors
        .as_array_mut()
        .unwrap_or_else(|| unreachable!("typed fixture"))
        .push(json!({"id":7,"name":"HDMI-A-1","disabled":true,
            "dpmsStatus":false,"mirrorOf":"none"}));
    let (display, locker) = value(decode(&topology, &monitors));
    let identity = value(DisplayTopologyId::from_resource(&display.resource));
    let facts = value(linura_observation::DisplayObservationFacts::from_envelope(
        &display, &identity, 10000,
    ));
    assert_eq!(facts.inventory().outputs().len(), 2);
    assert!(matches!(
        &facts.layout().outputs()[1],
        DisplayOutputLayout::Disabled { output } if output.handle() == 2 && output.generation() == 4
    ));
    assert_eq!(locker.attributes["secure"], ObservedValue::Bool(true));
    for field in ["observed_outputs", "covered_outputs"] {
        assert_eq!(locker.attributes[field], ObservedValue::Text("1:2".into()));
    }
    // The pre-fix producer leaked this compositor fence bit. It must remain a
    // hard decoder error, rather than silently ignoring contradictory evidence.
    topology["heads"][1]["covered"] = json!(true);
    assert!(decode(&topology, &monitors).is_err());
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

#[test]
fn all_native_thousandth_scales_require_exact_float_and_independent_fixed_projection() {
    let (mut topology, monitors) = inputs();
    for milli in 500_u32..=4000 {
        let native = milli as f32 / 1000.0;
        topology["heads"][0]["scale_milli"] = json!(milli);
        topology["heads"][0]["scale_float_bits"] = json!(native.to_bits());
        let independent_fixed = (f64::from(native) * 256.0).round_ties_even() as i32;
        topology["heads"][0]["scale_fixed"] = json!(independent_fixed);
        assert!(decode(&topology, &monitors).is_ok(), "scale {milli}");
        topology["heads"][0]["scale_float_bits"] = json!(native.to_bits() + 1);
        assert!(
            decode(&topology, &monitors).is_err(),
            "adjacent native float {milli}"
        );
    }
}
