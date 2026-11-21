use super::*;
use crate::{
    BootId, CompositorInvocationId, DisplayMode, DisplayOutputLayout, DisplayRecoveryMapping,
    DisplayRecoveryScope, DisplayScale, DisplayTransform, SecurityOwnerInvocationId, SessionEpoch,
};

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|e| unreachable!("{e:?}"))
}
fn topology(replacement: bool, uid: u32, seat: &str, boot: &str) -> DisplayTopologyId {
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
fn inventory(topology: DisplayTopologyId, handles: [u64; 3]) -> DisplayOutputSet {
    let rows = handles
        .into_iter()
        .map(|h| value(DisplayOutputId::new(topology.clone(), h, h + 1)))
        .collect();
    value(DisplayOutputSet::new(topology, rows))
}
fn capabilities(set: &DisplayOutputSet) -> Vec<NativeOutputCapabilities> {
    set.outputs()
        .iter()
        .map(|output| {
            value(NativeOutputCapabilities::new(
                output.clone(),
                vec![
                    value(DisplayMode::new(1920, 1080, 60000)),
                    value(DisplayMode::new(1280, 720, 60000)),
                ],
                true,
            ))
        })
        .collect()
}
fn layout(set: &DisplayOutputSet, x: i32) -> DisplayLayout {
    let heads = set.outputs();
    value(DisplayLayout::new(
        set,
        &capabilities(set),
        vec![
            DisplayOutputLayout::Enabled {
                output: heads[0].clone(),
                mode: value(DisplayMode::new(1920, 1080, 60000)),
                scale: value(DisplayScale::new(1250)),
                transform: DisplayTransform::Rotate90,
                x,
                y: 80,
                mirror: None,
            },
            DisplayOutputLayout::Enabled {
                output: heads[1].clone(),
                mode: value(DisplayMode::new(1280, 720, 60000)),
                scale: value(DisplayScale::new(1000)),
                transform: DisplayTransform::Flip,
                x,
                y: 80,
                mirror: Some(heads[0].clone()),
            },
            DisplayOutputLayout::Disabled {
                output: heads[2].clone(),
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
fn fixture() -> (DisplayOutputSet, DisplayOutputSet) {
    let boot = "11111111-1111-4111-8111-111111111111";
    (
        inventory(topology(false, 1000, "seat0", boot), [1, 2, 3]),
        inventory(topology(true, 1000, "seat0", boot), [9, 8, 7]),
    )
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
fn replacement_candidates_preserve_kept_layout_mirror_and_disable_semantics() {
    let (old, new) = fixture();
    let mut rows = pairs(&old, &new);
    rows.reverse();
    let map = value(DisplayKeptAdoptionMapping::new(
        old.clone(),
        new.clone(),
        rows,
    ));
    assert_eq!(
        map.replacement(),
        DisplayKeptAdoptionReplacement::CompositorReplacement
    );
    let candidate = value(map.candidate(
        &layout(&old, 300),
        layout(&new, -500),
        &capabilities(&new),
        lock(&new),
    ));
    assert_eq!(candidate.baseline(), &layout(&new, -500));
    assert_eq!(candidate.desired(), &layout(&new, 300));
    assert_eq!(candidate.lock(), &lock(&new));
    assert_eq!(map.original(), &old);
    assert_eq!(map.current(), &new);
    assert_eq!(map.outputs().len(), 3);
}

#[test]
fn root_only_comparison_can_represent_unchanged_geometry_without_weakening_restoration() {
    let (old, _) = fixture();
    let rows = pairs(&old, &old);
    assert!(DisplayRecoveryMapping::new(old.clone(), old.clone(), rows.clone()).is_err());
    let map = value(DisplayKeptAdoptionMapping::new(
        old.clone(),
        old.clone(),
        rows,
    ));
    assert_eq!(
        map.replacement(),
        DisplayKeptAdoptionReplacement::ProtectionReplacement
    );
    let candidate = value(map.candidate(
        &layout(&old, 300),
        layout(&old, 300),
        &capabilities(&old),
        lock(&old),
    ));
    assert_eq!(candidate.baseline(), candidate.desired());
    // This is only a proposal: no loss observation, approval, lease, grant or
    // native no-change exception is constructed by this pure comparison.
}

#[test]
fn missing_duplicate_or_foreign_output_pairs_refuse() {
    let (old, new) = fixture();
    let valid = pairs(&old, &new);
    let mut missing = valid.clone();
    missing.pop();
    let mut duplicate_source = valid.clone();
    duplicate_source[1].0 = duplicate_source[0].0.clone();
    let mut duplicate_destination = valid.clone();
    duplicate_destination[1].1 = duplicate_destination[0].1.clone();
    let mut foreign = valid.clone();
    foreign[0].1 = value(DisplayOutputId::new(new.topology().clone(), 999, 1));
    for rows in [missing, duplicate_source, duplicate_destination, foreign] {
        assert!(DisplayKeptAdoptionMapping::new(old.clone(), new.clone(), rows).is_err());
    }
}

#[test]
fn other_boot_user_seat_or_reused_compositor_session_is_not_an_adoption_mapping() {
    let (old, _) = fixture();
    let boot = "11111111-1111-4111-8111-111111111111";
    for scope in [
        topology(true, 1001, "seat0", boot),
        topology(true, 1000, "seat1", boot),
        topology(true, 1000, "seat0", "22222222-2222-4222-8222-222222222222"),
        value(DisplayTopologyId::new(
            topology(true, 1000, "seat0", boot).session().clone(),
            "seat0",
            old.topology().compositor().clone(),
            1,
        )),
    ] {
        let new = inventory(scope, [9, 8, 7]);
        assert!(
            DisplayKeptAdoptionMapping::new(old.clone(), new.clone(), pairs(&old, &new)).is_err()
        );
    }
}

#[test]
fn current_capability_or_lock_drift_is_not_hidden_by_a_typed_layout() {
    let (old, new) = fixture();
    let map = value(DisplayKeptAdoptionMapping::new(
        old.clone(),
        new.clone(),
        pairs(&old, &new),
    ));
    assert!(
        map.candidate(
            &layout(&old, 300),
            layout(&new, -500),
            &capabilities(&new),
            lock(&old)
        )
        .is_err()
    );
    let reduced: Vec<_> = new
        .outputs()
        .iter()
        .map(|output| {
            value(NativeOutputCapabilities::new(
                output.clone(),
                vec![value(DisplayMode::new(1280, 720, 60000))],
                true,
            ))
        })
        .collect();
    assert!(
        map.candidate(&layout(&old, 300), layout(&new, -500), &reduced, lock(&new))
            .is_err()
    );
    assert!(
        map.candidate(
            &layout(&new, 300),
            layout(&new, -500),
            &capabilities(&new),
            lock(&new)
        )
        .is_err()
    );
}

#[test]
fn scope_is_canonical_bounded_and_cannot_alias_restoration_or_ordinary_release() {
    let (_, new) = fixture();
    let scope = value(DisplayKeptAdoptionScope::new(
        &"1".repeat(64),
        new.topology().clone(),
    ));
    let resource = value(scope.resource_id());
    assert_eq!(
        value(DisplayKeptAdoptionScope::from_resource(&resource)),
        scope
    );
    assert_eq!(scope.current(), new.topology());
    assert_eq!(scope.original_dispatch(), "1".repeat(64));
    assert!(DisplayRecoveryScope::from_resource(&resource).is_err());
    assert!(crate::DisplayOrdinaryReleaseScope::from_resource(&resource).is_err());
    for digest in [
        "0".repeat(64),
        "A".repeat(64),
        "1".repeat(63),
        "1".repeat(65),
    ] {
        assert!(DisplayKeptAdoptionScope::new(&digest, new.topology().clone()).is_err());
    }
    let long = value(DisplayTopologyId::new(
        value(SessionEpoch::new(
            new.topology().session().boot().clone(),
            1000,
            "s".repeat(64),
            1234567890123456789,
        )),
        "q".repeat(32),
        new.topology().compositor().clone(),
        1,
    ));
    assert!(DisplayKeptAdoptionScope::new(&"1".repeat(64), long).is_err());
}

#[test]
fn root_invocation_identifiers_are_exact_nonzero_generation_comparisons_only() {
    let valid = "66666666-6666-4666-8666-666666666666";
    assert_eq!(
        value(DisplayProtectionInvocationId::new(valid)).as_str(),
        valid
    );
    for raw in [
        "",
        "00000000-0000-0000-0000-000000000000",
        "self",
        "66666666666646668666666666666666",
        "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
        "66666666-6666-4666-8666-666666666666\n",
    ] {
        assert!(DisplayProtectionInvocationId::new(raw).is_err());
    }
}
