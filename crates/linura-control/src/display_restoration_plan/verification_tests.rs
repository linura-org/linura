//! Simulated canonical joins only; no native acceptance or durable authority.
use super::*;
use crate::display_recovery_journal::{Phase, Record};
use linura_observation::{DisplayOriginalPresentationFacts, DisplayPostWriteFrame};
use linura_transaction::TransactionId;

fn fixture() -> (
    Fixture,
    PlanDesiredStateRequest,
    TransactionSnapshot,
    Record,
    Vec<ObservationEnvelope>,
) {
    let fixture = Fixture::new();
    let request = fixture.request();
    let material = value(DisplayRestorationMaterial::decode(
        &request.desired_state["restore_original"],
    ));
    let mut sources = fixture.sources();
    let mut post = native(
        material.replacement().topology(),
        [(10, 1), (20, 2)],
        [1920, 0],
        ["b", "a"],
    );
    for i in 0..2 {
        post.attributes.insert(
            format!("output.{i}.base_configuration_digest"),
            ObservedValue::Text("9".repeat(64)),
        );
        post.attributes.insert(
            format!("output.{i}.linura_owned"),
            ObservedValue::Bool(i == 0),
        );
    }
    let facts = value(DisplayObservationFacts::from_envelope(
        &post,
        material.replacement().topology(),
        value(now_ms()),
    ));
    let guard = value(
        fixture
            .source
            .restored_source_guard(&material, &fixture.protection, &facts),
    );
    let principal = value(PrincipalId::new(fixture.source.principal.as_str()));
    let transaction = TransactionId::for_namespace(&principal, &request.request_id);
    let snapshot = TransactionSnapshot {
        transaction_id: transaction.clone(),
        principal,
        request_id: request.request_id.clone(),
        current_generation: 0,
        state_version: 2,
        state: TransactionState::Indeterminate,
        binding_digest: value(ContentDigest::new(format!("sha256:{}", "1".repeat(64)))),
    };
    let at = value(now_ms()) - 100;
    let digest = value(crate::durable_authority::digest_request(&request));
    let reserved = value(Record::new(
        digest.clone(),
        transaction.clone(),
        Phase::Reserved,
        at + 15000,
        at,
        None,
        None,
        None,
    ));
    let dispatched = value(Record::new(
        digest,
        transaction.clone(),
        Phase::Dispatched,
        at + 15000,
        at + 1,
        Some("8".repeat(64)),
        Some(reserved.digest().clone()),
        None,
    ));
    let frames = facts
        .inventory()
        .outputs()
        .iter()
        .enumerate()
        .map(|(i, output)| {
            (
                output.clone(),
                DisplayPostWriteFrame::Presented {
                    crtc: 7 + i as u32,
                    framebuffer: 42 + i as u32,
                    commit: 99 + i as u64,
                },
            )
        })
        .collect();
    let presentation = value(DisplayOriginalPresentationFacts::new(
        value(material.recovery_scope()),
        material.original_checkpoint().into(),
        transaction.as_str().into(),
        value(linura_provider_sdk::display_restoration_effect(
            &request.desired_state["restore_original"],
        ))
        .digest()
        .to_hex(),
        "8".repeat(64),
        guard.to_hex(),
        1,
        frames,
    ));
    sources[1] = post;
    sources.push(envelope(
        DISPLAY_PROVIDER,
        DISPLAY_ORIGINAL_PRESENTATION_CAPABILITY,
        value(value(material.recovery_scope()).resource_id()),
        presentation.attributes(),
    ));
    (fixture, request, snapshot, dispatched, sources)
}

#[test]
fn only_exact_dispatched_context_and_five_fresh_sources_derive_observe_only_no_change() {
    let (fixture, request, snapshot, dispatched, mut sources) = fixture();
    // Contributors need not have equal sample times. A combined duration may
    // exceed a later contributor's duration while still expiring before it.
    // Compare absolute expiry, including deliberate timestamp skew.
    let sampled = value(now_ms()) - 50;
    for (index, source) in sources.iter_mut().enumerate() {
        source.observed_at_unix_ms = sampled + index as u64 * 5;
    }
    sources[4].valid_for_ms = 1000;
    let expiries = sources
        .iter()
        .map(|source| source.observed_at_unix_ms + source.valid_for_ms)
        .collect::<Vec<_>>();
    let principal = fixture.source.principal.clone();
    let mut control = PlanPreviewControl::new(coordinator(sources));
    let _context = value(control.enter_original_display_verification_context(
        fixture.source,
        &request,
        &snapshot,
        &dispatched,
    ));
    let (plan, observation) = value(control.authority_candidate(principal, actor(), request));
    assert_eq!(plan.status, linura_planner::PlanStatus::NoChange);
    assert!(plan.changes.is_empty() && !plan.execution_authorized());
    assert_eq!(observation.observed_at_unix_ms, sampled);
    assert!(
        expiries
            .into_iter()
            .all(|expiry| observation.observed_at_unix_ms + observation.valid_for_ms <= expiry)
    );
    assert!(
        observation
            .attributes
            .contains_key("control.replacement_presentation_digest")
    );
    assert_eq!(
        observation.attributes["original_confirmation_deadline_unix_ms"],
        ObservedValue::U64(10)
    );
}

#[test]
fn current_geometry_or_a_terminal_flag_never_substitutes_for_exact_source_and_frame_proof() {
    for case in 0..15 {
        let (fixture, request, snapshot, dispatched, mut sources) = fixture();
        if case < 5 {
            sources[case].observed_at_unix_ms = value(now_ms()) - 2001;
        } else {
            let (source, key, changed) = match case {
                5 => (4, "dispatch_digest", ObservedValue::Text("f".repeat(64))),
                6 => (4, "effect_digest", ObservedValue::Text("f".repeat(64))),
                7 => (
                    4,
                    "transaction",
                    ObservedValue::Text("transaction:other".into()),
                ),
                8 => (4, "checkpoint_digest", ObservedValue::Text("f".repeat(64))),
                9 => (4, "source_guard", ObservedValue::Text("f".repeat(64))),
                10 => (4, "post_write_epoch", ObservedValue::U64(0)),
                11 => (4, "output.0.commit", ObservedValue::U64(0)),
                12 => (4, "state", ObservedValue::Text("restored".into())),
                13 => (1, "output.0.linura_owned", ObservedValue::Bool(false)),
                _ => (
                    1,
                    "output.0.base_configuration_digest",
                    ObservedValue::Text("c".repeat(64)),
                ),
            };
            sources[source].attributes.insert(key.into(), changed);
        }
        let principal = fixture.source.principal.clone();
        let mut control = PlanPreviewControl::new(coordinator(sources));
        let _context = value(control.enter_original_display_verification_context(
            fixture.source,
            &request,
            &snapshot,
            &dispatched,
        ));
        assert!(
            control
                .authority_candidate(principal, actor(), request)
                .is_err(),
            "case {case}"
        );
    }
}

#[test]
fn even_matching_native_postcondition_cannot_reuse_pre_effect_authority_context() {
    let (fixture, request, _, _, sources) = fixture();
    let principal = fixture.source.principal.clone();
    let mut control = PlanPreviewControl::new(coordinator(sources));
    let _context = value(control.enter_original_display_context(fixture.source, &request));
    assert!(
        control
            .authority_candidate(principal, actor(), request)
            .is_err()
    );
}

#[test]
fn unprepared_foreign_or_substituted_dispatch_history_never_enters_verification_context() {
    for case in 0..6 {
        let (fixture, request, mut snapshot, mut dispatched, _) = fixture();
        match case {
            0 => snapshot.state = TransactionState::Prepared,
            1 => snapshot.state = TransactionState::RecoveryBlocked,
            2 => snapshot.principal = value(PrincipalId::new("unix:uid:1001")),
            3 => {
                snapshot.request_id =
                    value(RequestId::new("request:v010:display-restoration:other"))
            }
            4 => dispatched.phase = Phase::Reserved,
            _ => {
                dispatched.request_digest =
                    value(ContentDigest::new(format!("sha256:{}", "2".repeat(64))))
            }
        }
        let mut control = PlanPreviewControl::new(ObservationCoordinator::new());
        assert!(
            control
                .enter_original_display_verification_context(
                    fixture.source,
                    &request,
                    &snapshot,
                    &dispatched
                )
                .is_err(),
            "case {case}"
        );
    }
}

#[test]
fn ordinary_handoff_source_proof_uses_original_ownership_and_complete_restored_mapping() {
    let (fixture, request, _, _, sources) = fixture();
    let material = value(DisplayRestorationMaterial::decode(
        &request.desired_state["restore_original"],
    ));
    let current = value(DisplayObservationFacts::from_envelope(
        &sources[1],
        material.replacement().topology(),
        value(now_ms()),
    ));
    let (restored, guard) = value(fixture.source.verify_handoff_source(
        &material,
        &fixture.protection,
        &current,
    ));
    assert_eq!(restored.desired(), current.layout());
    assert_eq!(
        value(linura_provider_sdk::display_baseline_guard(&current)),
        guard
    );
    for (key, changed) in [
        ("output.0.linura_owned", ObservedValue::Bool(false)),
        (
            "output.0.base_configuration_digest",
            ObservedValue::Text("c".repeat(64)),
        ),
        (
            "output.0.native_identity_digest",
            ObservedValue::Text("f".repeat(64)),
        ),
    ] {
        let mut source = sources[1].clone();
        source.attributes.insert(key.into(), changed);
        let changed = value(DisplayObservationFacts::from_envelope(
            &source,
            material.replacement().topology(),
            value(now_ms()),
        ));
        assert!(
            fixture
                .source
                .verify_handoff_source(&material, &fixture.protection, &changed)
                .is_err(),
            "{key}"
        );
    }
    // An independent probe from before restoration cannot become the expected
    // postcondition simply by omitting opaque safety-frame evidence.
    let before = value(DisplayObservationFacts::from_envelope(
        &fixture.sources()[1],
        material.replacement().topology(),
        value(now_ms()),
    ));
    assert!(
        fixture
            .source
            .verify_handoff_source(&material, &fixture.protection, &before)
            .is_err()
    );
}
