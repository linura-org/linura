use super::*;
use crate::{
    BootId, CompositorInvocationId, DisplayMode, DisplayScale, DisplayTopologyId, DisplayTransform,
    SecurityOwnerInvocationId, SessionEpoch,
};
use crate::{DisplayRecoveryScope, DisplayRestorationMaterial, RequestId, ResourceId};

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}

fn scope(replacement: bool, uid: u32, seat: &str, boot: &str) -> DisplayTopologyId {
    value(DisplayTopologyId::new(
        value(SessionEpoch::new(
            value(BootId::new(boot)),
            uid,
            if replacement { "c3" } else { "c2" },
            if replacement { 99 } else { 42 },
        )),
        seat,
        value(CompositorInvocationId::new(if replacement {
            "44444444-4444-4444-8444-444444444444"
        } else {
            "33333333-3333-4333-8333-333333333333"
        })),
        if replacement { 1 } else { 8 },
    ))
}

fn inventory(scope: &DisplayTopologyId, handles: [u64; 3]) -> DisplayOutputSet {
    value(DisplayOutputSet::new(
        scope.clone(),
        handles
            .into_iter()
            .map(|handle| value(DisplayOutputId::new(scope.clone(), handle, handle + 1)))
            .collect(),
    ))
}

fn capabilities(set: &DisplayOutputSet) -> Vec<NativeOutputCapabilities> {
    set.outputs()
        .iter()
        .map(|output| {
            value(NativeOutputCapabilities::new(
                output.clone(),
                vec![
                    value(DisplayMode::new(1920, 1080, 60_000)),
                    value(DisplayMode::new(1280, 720, 60_000)),
                ],
                true,
            ))
        })
        .collect()
}

fn layout(set: &DisplayOutputSet, x: i32, baseline: bool) -> DisplayLayout {
    let outputs = set.outputs();
    let root = outputs[0].clone();
    value(DisplayLayout::new(
        set,
        &capabilities(set),
        vec![
            DisplayOutputLayout::Enabled {
                output: root.clone(),
                mode: value(DisplayMode::new(1920, 1080, 60_000)),
                scale: value(DisplayScale::new(1250)),
                transform: DisplayTransform::Rotate90,
                x,
                y: 80,
                mirror: None,
            },
            DisplayOutputLayout::Enabled {
                output: outputs[1].clone(),
                mode: value(DisplayMode::new(1280, 720, 60_000)),
                scale: value(DisplayScale::new(1000)),
                transform: DisplayTransform::Flip,
                x,
                y: 80,
                mirror: Some(root),
            },
            if baseline {
                DisplayOutputLayout::Disabled {
                    output: outputs[2].clone(),
                }
            } else {
                DisplayOutputLayout::Enabled {
                    output: outputs[2].clone(),
                    mode: value(DisplayMode::new(1280, 720, 60_000)),
                    scale: value(DisplayScale::new(1000)),
                    transform: DisplayTransform::Normal,
                    x: 5000,
                    y: 0,
                    mirror: None,
                }
            },
        ],
    ))
}

fn lock(set: &DisplayOutputSet) -> SessionLockId {
    value(SessionLockId::new(
        set.topology().session().clone(),
        value(SecurityOwnerInvocationId::new(
            "55555555-5555-4555-8555-555555555555",
        )),
        3,
    ))
}

fn fixture() -> (DisplayOutputSet, DisplayOutputSet, DisplayLayoutIntent) {
    let boot = "11111111-1111-4111-8111-111111111111";
    let old = inventory(&scope(false, 1000, "seat0", boot), [1, 2, 3]);
    let new = inventory(&scope(true, 1000, "seat0", boot), [9, 8, 7]);
    let original = value(DisplayLayoutIntent::new(
        lock(&old),
        layout(&old, 100, true),
        layout(&old, 300, false),
    ));
    (old, new, original)
}

fn pairs(
    old: &DisplayOutputSet,
    new: &DisplayOutputSet,
) -> Vec<(DisplayOutputId, DisplayOutputId)> {
    old.outputs()
        .iter()
        .cloned()
        .zip(new.outputs().iter().cloned())
        .collect()
}

#[test]
fn baseline_only_is_remapped_with_mirrors_disable_and_new_login_lock() {
    let (old, new, original) = fixture();
    let map = value(DisplayRecoveryMapping::new(
        old.clone(),
        new.clone(),
        pairs(&old, &new),
    ));
    let current = layout(&new, 200, false);
    let restored =
        value(map.restoration_intent(&original, current.clone(), &capabilities(&new), lock(&new)));
    assert_eq!(restored.baseline(), &current);
    assert_eq!(restored.lock(), &lock(&new));
    assert_ne!(restored.lock().epoch(), original.lock().epoch());
    assert_eq!(restored.desired(), &layout(&new, 100, true));
    assert_ne!(restored.desired(), &layout(&new, 300, false));
    assert_eq!(map.original(), &old);
    assert_eq!(map.replacement(), &new);
    assert_eq!(map.outputs().len(), 3);
    // Pair order is not precedence, mapping is canonical and complete.
    let mut reversed = pairs(&old, &new);
    reversed.reverse();
    assert_eq!(map, value(DisplayRecoveryMapping::new(old, new, reversed)));
}

#[test]
fn missing_extra_duplicate_foreign_or_recycled_pairs_fail_closed() {
    let (old, new, _) = fixture();
    for case in 0..7 {
        let mut rows = pairs(&old, &new);
        match case {
            0 => {
                rows.pop();
            }
            1 => rows.push(rows[0].clone()),
            2 => rows[1].0 = rows[0].0.clone(),
            3 => rows[1].1 = rows[0].1.clone(),
            4 => rows[1].0 = new.outputs()[1].clone(),
            5 => rows[1].1 = old.outputs()[1].clone(),
            _ => rows[0].1 = value(DisplayOutputId::new(new.topology().clone(), 9, 999)),
        }
        assert!(DisplayRecoveryMapping::new(old.clone(), new.clone(), rows).is_err());
    }
}

#[test]
fn boot_user_seat_and_original_compositor_cannot_be_substituted() {
    let (old, new, _) = fixture();
    for changed in [
        scope(
            true,
            1001,
            "seat0",
            old.topology().session().boot().as_str(),
        ),
        scope(
            true,
            1000,
            "seat1",
            old.topology().session().boot().as_str(),
        ),
        scope(true, 1000, "seat0", "22222222-2222-4222-8222-222222222222"),
        scope(
            false,
            1000,
            "seat0",
            old.topology().session().boot().as_str(),
        ),
    ] {
        let changed = inventory(&changed, [9, 8, 7]);
        assert!(
            DisplayRecoveryMapping::new(old.clone(), changed.clone(), pairs(&old, &changed))
                .is_err()
        );
    }
    assert!(DisplayRecoveryMapping::new(old.clone(), old.clone(), pairs(&old, &old)).is_err());
    assert!(DisplayRecoveryMapping::new(new.clone(), new.clone(), pairs(&new, &new)).is_err());
}

#[test]
fn original_and_current_material_cannot_be_rebound_to_another_scope() {
    let (old, new, original) = fixture();
    let map = value(DisplayRecoveryMapping::new(
        old.clone(),
        new.clone(),
        pairs(&old, &new),
    ));
    assert!(
        map.restoration_intent(
            &original,
            layout(&old, 200, false),
            &capabilities(&new),
            lock(&new)
        )
        .is_err()
    );
    assert!(
        map.restoration_intent(
            &original,
            layout(&new, 200, false),
            &capabilities(&new),
            lock(&old)
        )
        .is_err()
    );
    let other = value(DisplayLayoutIntent::new(
        lock(&new),
        layout(&new, 100, true),
        layout(&new, 300, false),
    ));
    assert!(
        map.restoration_intent(
            &other,
            layout(&new, 200, false),
            &capabilities(&new),
            lock(&new)
        )
        .is_err()
    );
}

#[test]
fn removed_or_changed_capabilities_never_round_or_drop_baseline_fields() {
    let (old, new, original) = fixture();
    let map = value(DisplayRecoveryMapping::new(
        old.clone(),
        new.clone(),
        pairs(&old, &new),
    ));
    let current = layout(&new, 200, false);
    let check = |caps: &[NativeOutputCapabilities]| {
        map.restoration_intent(&original, current.clone(), caps, lock(&new))
    };
    assert!(check(&capabilities(&new)[..2]).is_err());
    let mut caps = capabilities(&new);
    // Current third output is enabled, but restoring its original disabled
    // state still requires the replacement's independent disable capability.
    caps[2] = value(NativeOutputCapabilities::new(
        new.outputs()[2].clone(),
        caps[2].modes().iter().copied().collect(),
        false,
    ));
    assert_eq!(check(&caps), Err(DisplayLayoutError::UnsupportedDisable));
    let mut caps = capabilities(&new);
    caps[0] = value(NativeOutputCapabilities::new(
        new.outputs()[0].clone(),
        vec![value(DisplayMode::new(1920, 1080, 59_940))],
        true,
    ));
    assert_eq!(check(&caps), Err(DisplayLayoutError::UnsupportedMode));
}

fn encoded_restoration() -> (
    String,
    DisplayOutputSet,
    DisplayOutputSet,
    DisplayLayoutIntent,
) {
    let (old, new, original) = fixture();
    let mapping = value(DisplayRecoveryMapping::new(
        old.clone(),
        new.clone(),
        pairs(&old, &new),
    ));
    let replacement = value(mapping.restoration_intent(
        &original,
        layout(&new, 200, false),
        &capabilities(&new),
        lock(&new),
    ));
    let encoded = value(DisplayRestorationMaterial::encode(
        &value(RequestId::new("request:original")),
        &"a".repeat(64),
        &"b".repeat(64),
        &"c".repeat(64),
        &original,
        &replacement,
        &mapping,
    ));
    (encoded, old, new, original)
}

#[test]
fn restoration_material_binds_original_request_checkpoint_and_new_intent() {
    let (encoded, old, new, original) = encoded_restoration();
    let material = value(DisplayRestorationMaterial::decode(&encoded));
    assert_eq!(material.original_request().as_str(), "request:original");
    assert_eq!(material.original_dispatch(), "a".repeat(64));
    assert_eq!(material.original_checkpoint(), "b".repeat(64));
    assert_eq!(material.original().topology(), old.topology());
    assert_eq!(material.replacement().topology(), new.topology());
    let (retained, restored) =
        value(material.validate_native(&old, &capabilities(&old), &new, &capabilities(&new)));
    assert_eq!(retained, original);
    assert_eq!(restored.desired(), &layout(&new, 100, true));
    assert_eq!(
        encoded,
        value(DisplayRestorationMaterial::encode(
            material.original_request(),
            material.original_dispatch(),
            material.original_checkpoint(),
            material.replacement_baseline_guard(),
            &retained,
            &restored,
            material.mapping()
        ))
    );
}

#[test]
fn malformed_truncated_oversize_or_noncanonical_restoration_never_decodes() {
    let (encoded, ..) = encoded_restoration();
    for size in 0..encoded.len() {
        assert!(DisplayRestorationMaterial::decode(&encoded[..size]).is_err());
    }
    for bad in [
        encoded.clone() + ";",
        encoded.replacen("LNRI:1;", "LNRI:2;", 1),
        encoded.replacen("16:request:original;", "016:request:original;", 1),
        encoded.replacen("16:request:original;", "15:request:original;", 1),
        encoded.replacen(&"a".repeat(64), &"A".repeat(64), 1),
        encoded.replacen(&"a".repeat(64), &"0".repeat(64), 1),
        encoded.replacen(&"b".repeat(64), &"0".repeat(64), 1),
        encoded.replacen("1:2:9:10;2:3:8:9;", "2:3:8:9;1:2:9:10;", 1),
        encoded.replacen("1:2:9:10;2:3:8:9;", "1:2:9:10;2:3:9:10;", 1),
        "x".repeat(crate::MAX_DISPLAY_RESTORATION_BYTES + 1),
    ] {
        assert_ne!(bad, encoded);
        assert!(DisplayRestorationMaterial::decode(&bad).is_err());
    }
}

#[test]
fn failed_desired_layout_cannot_be_encoded_or_validated_as_restoration() {
    let (encoded, old, new, original) = encoded_restoration();
    let map = value(DisplayRecoveryMapping::new(
        old.clone(),
        new.clone(),
        pairs(&old, &new),
    ));
    let replay = value(DisplayLayoutIntent::new(
        lock(&new),
        layout(&new, 200, false),
        layout(&new, 300, false),
    ));
    assert!(
        DisplayRestorationMaterial::encode(
            &value(RequestId::new("request:original")),
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
            &original,
            &replay,
            &map
        )
        .is_err()
    );
    // Length-preserving mutation can survive shallow material decoding, but
    // exact baseline derivation must refuse it before authority review.
    let tampered = encoded.replacen(":100:80:-;", ":101:80:-;", 1);
    assert_ne!(tampered, encoded);
    let material = value(DisplayRestorationMaterial::decode(&tampered));
    assert!(
        material
            .validate_native(&old, &capabilities(&old), &new, &capabilities(&new))
            .is_err()
    );
}

#[test]
fn partial_historical_or_current_inventory_cannot_validate_restoration() {
    let (encoded, old, new, _) = encoded_restoration();
    let material = value(DisplayRestorationMaterial::decode(&encoded));
    let reduced_old = value(DisplayOutputSet::new(
        old.topology().clone(),
        old.outputs()[..2].to_vec(),
    ));
    let reduced_new = value(DisplayOutputSet::new(
        new.topology().clone(),
        new.outputs()[..2].to_vec(),
    ));
    assert!(
        material
            .validate_native(
                &reduced_old,
                &capabilities(&reduced_old),
                &new,
                &capabilities(&new)
            )
            .is_err()
    );
    assert!(
        material
            .validate_native(
                &old,
                &capabilities(&old),
                &reduced_new,
                &capabilities(&reduced_new)
            )
            .is_err()
    );
}

#[test]
fn recovery_resource_preserves_original_dispatch_and_full_replacement_identity() {
    let (_, new, _) = fixture();
    let scope = value(DisplayRecoveryScope::new(
        &"a".repeat(64),
        new.topology().clone(),
    ));
    let resource = value(scope.resource_id());
    assert_eq!(value(DisplayRecoveryScope::from_resource(&resource)), scope);
    assert_eq!(scope.replacement(), new.topology());
    assert_eq!(scope.original_dispatch(), "a".repeat(64));
    for bad in [
        String::new(),
        "0".repeat(64),
        "A".repeat(64),
        "g".repeat(64),
        "a".repeat(63),
        "a".repeat(65),
    ] {
        assert!(DisplayRecoveryScope::new(&bad, new.topology().clone()).is_err());
    }
    for bad in [
        resource
            .as_str()
            .replacen("display:recovery:", "display:topology:", 1),
        resource.as_str().replacen(":1000:", ":01000:", 1),
        resource.as_str().to_owned() + ":tail",
    ] {
        assert!(DisplayRecoveryScope::from_resource(&value(ResourceId::new(bad))).is_err());
    }
    let changed = value(DisplayRecoveryScope::new(
        &"b".repeat(64),
        new.topology().clone(),
    ));
    assert_ne!(changed.resource_id(), scope.resource_id());
}
