//! Codec/domain cases only; these comparisons never represent native evidence.
use super::*;
use crate::{DisplayMode, DisplayOutputId, DisplayRestorationMaterial};
fn value<T, E: std::fmt::Debug>(v: Result<T, E>) -> T {
    v.unwrap_or_else(|e| unreachable!("{e:?}"))
}
fn original() -> String {
    let restored = value(DisplayRestorationMaterial::decode(
        include_str!("../display_recovery/fixtures/original-baseline.txt").trim_end(),
    ));
    let material = restored.original();
    let topology = material.topology();
    let (set, capabilities) = inventory(topology);
    value(value(material.validate_native(&set, &capabilities)).canonical_text())
}
fn inventory(topology: &DisplayTopologyId) -> (DisplayOutputSet, Vec<NativeOutputCapabilities>) {
    let set = value(DisplayOutputSet::new(
        topology.clone(),
        [(1, 2), (2, 2), (3, 3)]
            .into_iter()
            .map(|(handle, generation)| {
                value(DisplayOutputId::new(topology.clone(), handle, generation))
            })
            .collect(),
    ));
    let capabilities = set
        .outputs()
        .iter()
        .map(|id| {
            value(NativeOutputCapabilities::new(
                id.clone(),
                vec![
                    value(DisplayMode::new(1920, 1080, 60_000)),
                    value(DisplayMode::new(1280, 720, 60_000)),
                ],
                true,
            ))
        })
        .collect();
    (set, capabilities)
}
fn lineage() -> DisplayOrdinaryReleaseLineage<'static> {
    DisplayOrdinaryReleaseLineage {
        original_request: value(RequestId::new("request:v010:display-layout:original")),
        original_dispatch: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        terminal_record: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        original_checkpoint: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        signed_binding: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        generation: 0,
        state_version: 9,
        current_source_guard: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    }
}
fn fields(text: &str) -> Vec<String> {
    let mut rest = text.strip_prefix(PREFIX).unwrap_or_else(|| unreachable!());
    let mut result = Vec::new();
    while !rest.is_empty() {
        result.push(value(field(&mut rest, MAX_DISPLAY_ORDINARY_RELEASE_BYTES)).into());
    }
    result
}
fn framed(fields: &[String]) -> String {
    let mut out = PREFIX.to_owned();
    for field in fields {
        out.push_str(&format!("{}:{field};", field.len()));
    }
    out
}
#[test]
fn ordinary_release_is_same_scope_and_exposes_only_its_actual_terminal_layout() {
    let original = original();
    let material = value(DisplayLayoutMaterial::decode(&original));
    let (set, caps) = inventory(material.topology());
    let intent = value(material.validate_native(&set, &caps));
    for outcome in [
        DisplayOrdinaryReleaseOutcome::Keep,
        DisplayOrdinaryReleaseOutcome::Revert,
        DisplayOrdinaryReleaseOutcome::Expired,
    ] {
        let encoded = value(DisplayOrdinaryReleaseMaterial::encode(
            &lineage(),
            outcome,
            material.lock(),
            &original,
        ));
        let release = value(DisplayOrdinaryReleaseMaterial::decode(&encoded));
        assert_eq!(release.lineage(), &lineage());
        assert_eq!(release.original_text(), original);
        assert_eq!(release.current_lock(), material.lock());
        assert_eq!(release.outcome(), outcome);
        assert_eq!(
            value(release.validate_native(&set, &caps)),
            if outcome == DisplayOrdinaryReleaseOutcome::Keep {
                intent.desired().clone()
            } else {
                intent.baseline().clone()
            }
        );
        let scope = value(release.release_scope());
        let resource = value(scope.resource_id());
        assert_eq!(
            value(DisplayOrdinaryReleaseScope::from_resource(&resource)),
            scope
        );
        assert!(crate::DisplayRecoveryScope::from_resource(&resource).is_err());
        let recovery = value(crate::DisplayRecoveryScope::new(
            scope.original_dispatch(),
            scope.topology().clone(),
        ));
        assert!(
            DisplayOrdinaryReleaseScope::from_resource(&value(recovery.resource_id())).is_err()
        );
        let other = value(DisplayTopologyId::new(
            material.topology().session().clone(),
            material.topology().seat(),
            value(crate::CompositorInvocationId::new(
                "99999999-9999-4999-8999-999999999999",
            )),
            material.topology().generation(),
        ));
        let (other_set, other_caps) = inventory(&other);
        assert!(release.validate_native(&other_set, &other_caps).is_err());
        let incomplete = value(DisplayOutputSet::new(
            set.topology().clone(),
            set.outputs()[..2].to_vec(),
        ));
        assert!(release.validate_native(&incomplete, &caps[..2]).is_err());
    }
}
#[test]
fn malformed_foreign_or_relabelled_history_never_decodes_as_ordinary_release() {
    let original = original();
    let material = value(DisplayLayoutMaterial::decode(&original));
    let encoded = value(DisplayOrdinaryReleaseMaterial::encode(
        &lineage(),
        DisplayOrdinaryReleaseOutcome::Keep,
        material.lock(),
        &original,
    ));
    for end in 0..encoded.len() {
        if encoded.is_char_boundary(end) {
            assert!(
                DisplayOrdinaryReleaseMaterial::decode(&encoded[..end]).is_err(),
                "truncation {end}"
            );
        }
    }
    for bad in [
        format!("{encoded}x"),
        encoded.replacen(PREFIX, "LNRF:1;", 1),
        encoded.replacen(PREFIX, "LNRI:1;", 1),
        "x".repeat(MAX_DISPLAY_ORDINARY_RELEASE_BYTES + 1),
        format!("{encoded}\n"),
    ] {
        assert!(DisplayOrdinaryReleaseMaterial::decode(&bad).is_err());
    }
    let original_fields = fields(&encoded);
    for (index, bad) in [
        (0, "".into()),
        (1, "0".repeat(64)),
        (2, "b".repeat(63)),
        (3, "C".repeat(64)),
        (4, "sha256:denied".into()),
        (5, "00".into()),
        (6, "0".into()),
        (6, "09".into()),
        (7, "ack".into()),
        (8, "released".into()),
        (
            9,
            material
                .lock()
                .resource_id()
                .unwrap_or_else(|e| unreachable!("{e}"))
                .as_str()
                .replace(":1000:", ":1001:"),
        ),
        (
            10,
            include_str!("../display_recovery/fixtures/original-baseline.txt")
                .trim_end()
                .into(),
        ),
    ] {
        let mut changed = original_fields.clone();
        changed[index] = bad;
        assert!(
            DisplayOrdinaryReleaseMaterial::decode(&framed(&changed)).is_err(),
            "field {index}"
        );
    }
    let mut extra = original_fields.clone();
    extra.push("permit".into());
    assert!(DisplayOrdinaryReleaseMaterial::decode(&framed(&extra)).is_err());
    let mut wrong = lineage();
    wrong.state_version = 0;
    assert!(
        DisplayOrdinaryReleaseMaterial::encode(
            &wrong,
            DisplayOrdinaryReleaseOutcome::Keep,
            material.lock(),
            &original
        )
        .is_err()
    );
}
