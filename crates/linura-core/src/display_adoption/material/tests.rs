use super::*;
use crate::{DisplayMode, DisplayOrdinaryReleaseLineage, DisplayRestorationMaterial};
fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|e| unreachable!("{e:?}"))
}
fn caps(set: &DisplayOutputSet) -> Vec<NativeOutputCapabilities> {
    set.outputs()
        .iter()
        .map(|id| {
            value(NativeOutputCapabilities::new(
                id.clone(),
                vec![
                    value(DisplayMode::new(1920, 1080, 60000)),
                    value(DisplayMode::new(1280, 720, 60000)),
                ],
                true,
            ))
        })
        .collect()
}
fn fixture(
    root_only: bool,
) -> (
    DisplayLayoutIntent,
    DisplayLayoutIntent,
    DisplayKeptAdoptionMapping,
) {
    let restore = value(DisplayRestorationMaterial::decode(
        include_str!("../../display_recovery/fixtures/original-baseline.txt").trim_end(),
    ));
    let old = restore.mapping().original();
    let original = value(restore.original().validate_native(old, &caps(old)));
    let new = if root_only {
        old
    } else {
        restore.mapping().replacement()
    };
    let pairs = if root_only {
        old.outputs()
            .iter()
            .cloned()
            .zip(old.outputs().iter().cloned())
            .collect()
    } else {
        restore
            .mapping()
            .outputs()
            .iter()
            .map(|(a, b)| (a.clone(), b.clone()))
            .collect()
    };
    let mapping = value(DisplayKeptAdoptionMapping::new(
        old.clone(),
        new.clone(),
        pairs,
    ));
    let current = if root_only {
        original.desired().clone()
    } else {
        value(restore.replacement().validate_native(new, &caps(new)))
            .baseline()
            .clone()
    };
    let lock = if root_only {
        original.lock().clone()
    } else {
        restore.replacement().lock().clone()
    };
    let candidate = value(mapping.candidate(original.desired(), current, &caps(new), lock));
    (original, candidate, mapping)
}
fn lineage() -> DisplayKeptAdoptionLineage<'static> {
    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    DisplayKeptAdoptionLineage {
        release_request: value(RequestId::new("release-before-replacement")),
        release_dispatch: A,
        release_binding: B,
        release_generation: 0,
        release_state_version: 9,
        release_desired: A,
        release_graph: B,
        release_provenance: A,
        kept_desired: B,
        kept_graph: A,
        kept_provenance: B,
        released_record: A,
        adopted_record: B,
        state_record: A,
    }
}
fn protection() -> DisplayProtectionInvocationId {
    value(DisplayProtectionInvocationId::new(
        "77777777-7777-4777-8777-777777777777",
    ))
}
fn release(original: &DisplayLayoutIntent, outcome: DisplayOrdinaryReleaseOutcome) -> String {
    let l = lineage();
    value(DisplayOrdinaryReleaseMaterial::encode(
        &DisplayOrdinaryReleaseLineage {
            original_request: value(RequestId::new("original-kept-layout")),
            original_dispatch: l.kept_desired,
            terminal_record: l.kept_graph,
            original_checkpoint: l.kept_provenance,
            signed_binding: l.release_binding,
            generation: 0,
            state_version: 5,
            current_source_guard: l.release_desired,
        },
        outcome,
        original.lock(),
        &value(original.canonical_text()),
    ))
}
fn encode(root_only: bool) -> String {
    let (original, current, mapping) = fixture(root_only);
    value(DisplayKeptAdoptionMaterial::encode(
        &lineage(),
        &protection(),
        lineage().kept_graph,
        &release(&original, DisplayOrdinaryReleaseOutcome::Keep),
        &original,
        &current,
        &mapping,
    ))
}
fn fields(text: &str) -> Vec<String> {
    let mut rest = text.strip_prefix(PREFIX).unwrap_or_else(|| unreachable!());
    let mut result = Vec::new();
    while !rest.is_empty() {
        result.push(value(field(&mut rest, MAX_DISPLAY_KEPT_ADOPTION_BYTES)).into());
    }
    result
}
fn frame(fields: &[String]) -> String {
    let mut out = PREFIX.to_owned();
    for f in fields {
        out.push_str(&format!("{}:{f};", f.len()));
    }
    out
}

#[test]
fn full_kept_adoption_material_roundtrips_root_only_and_compositor_replacement() {
    for root_only in [false, true] {
        let text = encode(root_only);
        let decoded = value(DisplayKeptAdoptionMaterial::decode(&text));
        let (old, current, mapping) = fixture(root_only);
        assert_eq!(decoded.lineage(), &lineage());
        assert_eq!(decoded.protection(), &protection());
        assert_eq!(decoded.mapping(), &mapping);
        assert_eq!(decoded.current_source_guard(), lineage().kept_graph);
        assert_eq!(
            value(decoded.validate_native(
                mapping.original(),
                &caps(mapping.original()),
                mapping.current(),
                &caps(mapping.current())
            )),
            (old, current)
        );
        let scope = value(decoded.scope());
        assert_eq!(scope.current(), mapping.current().topology());
        assert_eq!(
            scope.original_dispatch(),
            decoded.release().lineage().original_dispatch
        );
        assert_eq!(
            value(DisplayOrdinaryReleaseMaterial::decode(
                decoded.release_text()
            )),
            *decoded.release()
        );
    }
}

#[test]
fn complete_inventory_permutations_validate_without_dropping_any_identity() {
    let text = encode(false);
    let decoded = value(DisplayKeptAdoptionMaterial::decode(&text));
    let (old, current, mapping) = fixture(false);
    let permute = |set: &DisplayOutputSet| {
        let mut outputs = set.outputs().to_vec();
        outputs.reverse();
        value(DisplayOutputSet::new(set.topology().clone(), outputs))
    };
    let historical = permute(mapping.original());
    let native = permute(mapping.current());
    assert_eq!(
        value(decoded.validate_native(&historical, &caps(&historical), &native, &caps(&native))),
        (old, current)
    );
    let mut changed = native.outputs().to_vec();
    changed[0] = value(DisplayOutputId::new(
        native.topology().clone(),
        changed[0].handle(),
        changed[0].generation() + 1,
    ));
    let substituted = value(DisplayOutputSet::new(native.topology().clone(), changed));
    assert!(
        decoded
            .validate_native(
                &historical,
                &caps(&historical),
                &substituted,
                &caps(&substituted)
            )
            .is_err()
    );
}

#[test]
fn revert_expiry_and_restoration_targets_never_become_kept_adoption() {
    let (original, current, mapping) = fixture(false);
    for outcome in [
        DisplayOrdinaryReleaseOutcome::Revert,
        DisplayOrdinaryReleaseOutcome::Expired,
    ] {
        let release = release(&original, outcome);
        assert!(
            DisplayKeptAdoptionMaterial::encode(
                &lineage(),
                &protection(),
                lineage().kept_graph,
                &release,
                &original,
                &current,
                &mapping
            )
            .is_err()
        );
        let mut parts = fields(&encode(false));
        parts[16] = release;
        assert!(DisplayKeptAdoptionMaterial::decode(&frame(&parts)).is_err());
    }
    let wrong = value(DisplayLayoutIntent::new(
        current.lock().clone(),
        current.baseline().clone(),
        current.baseline().clone(),
    ));
    assert_ne!(wrong.desired(), current.desired());
    assert!(
        DisplayKeptAdoptionMaterial::encode(
            &lineage(),
            &protection(),
            lineage().kept_graph,
            &release(&original, DisplayOrdinaryReleaseOutcome::Keep),
            &original,
            &wrong,
            &mapping
        )
        .is_err()
    );
    let mut parts = fields(&encode(false));
    parts[17] = value(wrong.canonical_text());
    let malformed = frame(&parts);
    let decoded = value(DisplayKeptAdoptionMaterial::decode(&malformed));
    assert!(
        decoded
            .validate_native(
                mapping.original(),
                &caps(mapping.original()),
                mapping.current(),
                &caps(mapping.current())
            )
            .is_err()
    );
}

#[test]
fn full_material_is_closed_bounded_canonical_and_never_aliases_another_purpose() {
    let text = encode(false);
    for end in 0..text.len() {
        assert!(
            DisplayKeptAdoptionMaterial::decode(&text[..end]).is_err(),
            "truncated {end}"
        );
    }
    for bad in [
        format!("{text}extra"),
        text.replacen("LNKA:1;", "LNKA:2;", 1),
        text.replacen("LNKA:1;", "LNRI:1;", 1),
        format!("{text}\n"),
        "a".repeat(MAX_DISPLAY_KEPT_ADOPTION_BYTES + 1),
    ] {
        assert!(DisplayKeptAdoptionMaterial::decode(&bad).is_err());
    }
    let original = fields(&text);
    for index in [1, 2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15] {
        for bad in [
            "0".repeat(64),
            "A".repeat(64),
            "1".repeat(63),
            "g".repeat(64),
        ] {
            let mut f = original.clone();
            f[index] = bad;
            assert!(
                DisplayKeptAdoptionMaterial::decode(&frame(&f)).is_err(),
                "field {index}"
            );
        }
    }
    for (index, bad) in [
        (3, "00"),
        (3, "18446744073709551616"),
        (4, "0"),
        (4, "01"),
        (14, "00000000-0000-0000-0000-000000000000"),
    ] {
        let mut f = original.clone();
        f[index] = bad.into();
        assert!(DisplayKeptAdoptionMaterial::decode(&frame(&f)).is_err());
    }
    assert!(
        DisplayKeptAdoptionMaterial::decode(&text.replacen(
            &format!("LNKA:1;{}:", original[0].len()),
            &format!("LNKA:1;0{}:", original[0].len()),
            1
        ))
        .is_err()
    );
}

#[test]
fn new_generation_and_each_retained_identity_are_material_even_with_unchanged_geometry() {
    let text = encode(true);
    let original = fields(&text);
    for index in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] {
        let mut f = original.clone();
        f[index] = match index {
            0 => "different-release-request".into(),
            3 => "1".into(),
            4 => "10".into(),
            14 => "88888888-8888-4888-8888-888888888888".into(),
            _ => "c".repeat(64),
        };
        let changed = frame(&f);
        assert_ne!(changed, text);
        value(DisplayKeptAdoptionMaterial::decode(&changed));
        // The codec preserves identity substitutions for Control to compare
        // against actual fresh facts and full authenticated historical data.
    }
}

#[test]
fn incomplete_duplicate_noncanonical_and_reordered_pairs_refuse() {
    let original = fields(&encode(false));
    let rows: Vec<_> = original[18].trim_end_matches(';').split(';').collect();
    for bad in [
        format!("{};", rows[0]),
        format!("{};{};{};", rows[0], rows[0], rows[2]),
        format!("{};{};{};", rows[2], rows[1], rows[0]),
        format!("0{}", original[18]),
        format!("{}x", original[18]),
        original[18].replacen("1:2:", "101:2:", 1),
    ] {
        let mut f = original.clone();
        f[18] = bad;
        assert!(DisplayKeptAdoptionMaterial::decode(&frame(&f)).is_err());
    }
}
