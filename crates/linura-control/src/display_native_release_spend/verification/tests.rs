//! Synthetic journal/fault fixtures; no native execution or qualification claim.
use super::*;
use linura_core::{
    CapabilityId, DisplayOutputId, DisplayRestorationMaterial, ProviderId, SemanticReason,
};
use linura_observation::{
    DisplayFinalizationPhase, DisplayFinalizationReservationFacts, DisplayNativeHandoffLineage,
    DisplayNativeHandoffOutput, DisplayNativeHandoffWindow, DisplayOriginalFinalizationFacts,
    ObservationAuthority,
};
use linura_transaction::TransactionId;
use std::collections::BTreeMap;

fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}

struct Fixture {
    principal: PrincipalId,
    request: PlanDesiredStateRequest,
    snapshot: TransactionSnapshot,
    material: String,
    dispatch: String,
    parent: NativeReleaseSpendPrepared,
    observation: ObservationEnvelope,
    frames: DisplayNativeHandoffFacts,
}
impl Fixture {
    fn new() -> Self {
        let restoration_text = include_str!(
            "../../../../linura-core/src/display_recovery/fixtures/original-baseline.txt"
        )
        .trim_end();
        let restoration = value(DisplayRestorationMaterial::decode(restoration_text));
        let material = value(DisplayFinalizationMaterial::encode(
            &value(RequestId::new("request:restored")),
            &"1".repeat(64),
            &"2".repeat(64),
            &"3".repeat(64),
            29,
            restoration.replacement().lock(),
            restoration_text,
        ));
        let decoded = value(DisplayFinalizationMaterial::decode(&material));
        let scope = value(decoded.recovery_scope());
        let principal = value(PrincipalId::new("unix:uid:1000"));
        let request_id = value(RequestId::new("request:v010:display-finalization:verified"));
        let transaction = TransactionId::for_namespace(&principal, &request_id);
        let effect = value(linura_provider_sdk::display_finalization_effect(&material));
        let dispatch = "4".repeat(64);
        let restoration_effect = value(linura_provider_sdk::display_restoration_effect(
            restoration_text,
        ));
        let root = value(DisplayOriginalFinalizationFacts::new(
            scope.clone(),
            restoration.original_checkpoint().into(),
            "transaction:restored".into(),
            restoration_effect.digest().to_hex(),
            decoded.restoration_dispatch().into(),
            DisplayFinalizationPhase::NativeReleaseSpent,
            Some(value(DisplayFinalizationReservationFacts::new(
                material.clone(),
                transaction.as_str().into(),
                effect.digest().to_hex(),
                dispatch.clone(),
            ))),
        ));
        let frames = value(DisplayNativeHandoffFacts::new(
            scope.clone(),
            DisplayNativeHandoffLineage {
                checkpoint: root.checkpoint().into(),
                restoration_transaction: root.restoration_transaction().into(),
                restoration_effect: root.restoration_effect().into(),
                restoration_dispatch: root.restoration_dispatch().into(),
                terminal_transaction: transaction.as_str().into(),
                terminal_effect: effect.digest().to_hex(),
                terminal_dispatch: dispatch.clone(),
                terminal_link: decoded.terminal_link().into(),
                source_guard: decoded.restored_source_guard().into(),
                post_write_epoch: decoded.post_write_epoch(),
                security_epoch: 4,
            },
            DisplayNativeHandoffWindow {
                observed_unix_ms: 1001,
                observed_boot_ms: 101,
                deadline_unix_ms: 1200,
                deadline_boot_ms: 300,
            },
            BTreeMap::from([(
                value(DisplayOutputId::new(scope.replacement().clone(), 10, 1)),
                DisplayNativeHandoffOutput {
                    enabled: true,
                    connector: 5,
                    crtc: 7,
                    plane: 8,
                    framebuffer: 42,
                    spend_high_water: 90,
                    completed_commit: 99,
                },
            )]),
        ));
        let mut attributes = root.attributes();
        for name in [
            "original_protection",
            "display",
            "session",
            "coverage",
            "first_ordinary_frame",
            "reconciled_frame",
            "rechecked_root",
            "rechecked_protection",
        ] {
            attributes.insert(
                format!("control.handoff.{name}_digest"),
                ObservedValue::Text(
                    digest_bytes("synthetic-test", name.as_bytes())
                        .as_str()
                        .into(),
                ),
            );
        }
        let request = PlanDesiredStateRequest {
            request_id: request_id.clone(),
            provider: effect.provider,
            observation_capability: value(CapabilityId::new(
                linura_observation::DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY,
            )),
            resource: effect.resource,
            desired_state: BTreeMap::from([(
                "finalize_original".into(),
                value(String::from_utf8(effect.canonical_payload)),
            )]),
            reason: SemanticReason {
                summary: "Finalize exact restored display".into(),
                intent_ids: vec![],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
        };
        let snapshot = TransactionSnapshot {
            transaction_id: transaction,
            principal: principal.clone(),
            request_id,
            current_generation: 0,
            state_version: 2,
            state: TransactionState::Indeterminate,
            binding_digest: digest_bytes("synthetic-binding", b"terminal"),
        };
        let observation = ObservationEnvelope {
            provider: value(ProviderId::new(
                linura_observation::DISPLAY_RECOVERY_PROVIDER,
            )),
            resource: request.resource.clone(),
            capability: request.observation_capability.clone(),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: 1001,
            valid_for_ms: 199,
            sequence: 1,
            attributes,
        };
        Self {
            principal,
            request,
            snapshot,
            material,
            dispatch,
            parent: NativeReleaseSpendPrepared {
                canonical: b"synthetic-spent-anchor".to_vec(),
                expiry: 1150,
            },
            observation,
            frames,
        }
    }
    fn capture(&self, now: u64) -> Result<NativeHandoffVerified, ManagedLifecycleError> {
        NativeHandoffVerified::capture(
            &self.principal,
            &self.request,
            &self.snapshot,
            &self.dispatch,
            &self.material,
            &self.parent,
            &self.observation,
            &self.frames,
            now,
        )
    }
}

#[derive(Debug, Default)]
struct Journal {
    records: BTreeMap<(PrincipalId, RequestId), RetainedRequest>,
    write_failure: bool,
    integrity_failure: bool,
}
impl ApprovedRequestJournal for Journal {
    fn retain(&mut self, record: &RetainedRequest) -> Result<(), TransactionStoreError> {
        let key = (record.principal().clone(), record.request_id().clone());
        if self.records.get(&key).is_some_and(|old| old != record) {
            return Err(TransactionStoreError::AuthorityRejected);
        }
        self.records.insert(key, record.clone());
        if self.write_failure {
            Err(TransactionStoreError::AuthorityRejected)
        } else {
            Ok(())
        }
    }
    fn load(
        &self,
        principal: &PrincipalId,
        request: &RequestId,
    ) -> Result<RetainedRequest, TransactionStoreError> {
        self.records
            .get(&(principal.clone(), request.clone()))
            .cloned()
            .ok_or(TransactionStoreError::NotFound)
    }
    fn integrity_check(&self) -> Result<(), TransactionStoreError> {
        if self.integrity_failure {
            Err(TransactionStoreError::AuthorityRejected)
        } else {
            Ok(())
        }
    }
}

#[test]
fn durable_verification_retains_first_proof_without_committing_or_renewing_it() {
    let mut fixture = Fixture::new();
    let first = value(fixture.capture(1002));
    let mut journal = Journal::default();
    assert_eq!(value(first.retain_or_reconcile(&mut journal)), first);
    fixture.observation.sequence += 1;
    fixture.observation.observed_at_unix_ms += 10;
    fixture.observation.valid_for_ms -= 10;
    let current = value(fixture.capture(1012));
    assert_ne!(current.digest(), first.digest());
    let retained = value(current.retain_or_reconcile(&mut journal));
    assert_eq!(retained, first);
    assert_eq!(retained.observed_at(), 1002);
    assert_eq!(retained.expiry(), 1150);
    assert_eq!(fixture.snapshot.state, TransactionState::Indeterminate);
    assert_eq!(journal.records.len(), 1);
}

#[test]
fn missing_join_contributors_and_ack_like_or_synthetic_proofs_never_persist() {
    let fixture = Fixture::new();
    for key in fixture
        .observation
        .attributes
        .keys()
        .filter(|key| key.starts_with("control.handoff."))
    {
        let mut changed = Fixture::new();
        changed.observation.attributes.remove(key);
        assert!(changed.capture(1002).is_err(), "missing {key}");
        changed
            .observation
            .attributes
            .insert(key.clone(), ObservedValue::Bool(true));
        assert!(changed.capture(1002).is_err(), "ACK-like {key}");
    }
    let mut changed = Fixture::new();
    changed.observation.authority = ObservationAuthority::SyntheticTest;
    assert!(changed.capture(1002).is_err());
    changed = Fixture::new();
    let duplicate = changed.observation.attributes["control.handoff.display_digest"].clone();
    changed
        .observation
        .attributes
        .insert("control.handoff.coverage_digest".into(), duplicate);
    assert!(changed.capture(1002).is_err());
    changed = Fixture::new();
    changed.observation.attributes.insert(
        "control.handoff.unknown_digest".into(),
        ObservedValue::Text(digest_bytes("synthetic", b"unknown").as_str().into()),
    );
    assert!(changed.capture(1002).is_err());
    changed = Fixture::new();
    changed.observation.attributes.insert(
        "phase".into(),
        ObservedValue::Text("released-current".into()),
    );
    assert!(changed.capture(1002).is_err());
}

#[test]
fn wrong_owner_payload_terminal_dispatch_generation_and_spent_anchor_fail_closed() {
    for case in 0..8 {
        let mut changed = Fixture::new();
        match case {
            0 => changed.principal = value(PrincipalId::new("unix:uid:1001")),
            1 => changed.snapshot.state = TransactionState::Committed,
            2 => changed.snapshot.binding_digest = ContentDigest::zero(),
            3 => changed.snapshot.state_version = 0,
            4 => changed.dispatch = "9".repeat(64),
            5 => {
                changed
                    .request
                    .desired_state
                    .insert("finalize_original".into(), changed.material.clone());
            }
            6 => changed.request.request_id = value(RequestId::new("request:foreign")),
            _ => changed.parent.expiry = 1002,
        }
        assert!(changed.capture(1002).is_err(), "case {case}");
    }
    let fixture = Fixture::new();
    let first = value(fixture.capture(1002));
    let mut replaced = Fixture::new();
    replaced.snapshot.current_generation += 1;
    assert!(
        NativeHandoffVerified::reconcile(&first.canonical, &value(replaced.capture(1003))).is_err()
    );
    let mut replaced = Fixture::new();
    replaced.parent.canonical.push(1);
    assert!(
        NativeHandoffVerified::reconcile(&first.canonical, &value(replaced.capture(1003))).is_err()
    );
}

#[test]
fn truncation_trailing_data_and_every_immutable_field_substitution_are_rejected() {
    let fixture = Fixture::new();
    let proof = value(fixture.capture(1002));
    for length in 0..proof.canonical.len() {
        assert!(NativeHandoffVerified::reconcile(&proof.canonical[..length], &proof).is_err());
    }
    let mut trailing = proof.canonical.clone();
    trailing.push(0);
    assert!(NativeHandoffVerified::reconcile(&trailing, &proof).is_err());
    let mut rest = proof.canonical.as_slice();
    for index in 0..HEADER_FIELDS {
        let offset = proof.canonical.len() - rest.len();
        let _ = value(field(&mut rest, 256));
        if matches!(index, 10..=14) {
            continue;
        }
        let mut changed = proof.canonical.clone();
        changed[offset + 8] ^= 1;
        assert!(
            NativeHandoffVerified::reconcile(&changed, &proof).is_err(),
            "field {index}"
        );
    }
}

#[test]
fn failed_sync_corruption_and_store_integrity_do_not_replace_history() {
    let fixture = Fixture::new();
    let proof = value(fixture.capture(1002));
    let mut journal = Journal {
        write_failure: true,
        ..Journal::default()
    };
    assert!(proof.retain_or_reconcile(&mut journal).is_err());
    // The ambiguous write remains reserved. Re-observation compares it; it
    // never creates another effect attempt, approval or later verification time.
    assert_eq!(journal.records.len(), 1);
    journal.write_failure = false;
    assert_eq!(value(proof.retain_or_reconcile(&mut journal)), proof);
    journal.integrity_failure = true;
    assert!(proof.retain_or_reconcile(&mut journal).is_err());
    journal.integrity_failure = false;
    let key = value(NativeHandoffVerified::key(&fixture.request.request_id));
    journal.records.insert(
        (fixture.principal.clone(), key.clone()),
        value(RetainedRequest::new(
            fixture.principal.clone(),
            key,
            vec![1, 2, 3],
        )),
    );
    assert!(proof.retain_or_reconcile(&mut journal).is_err());
}

#[test]
fn clock_rollback_boundary_expiry_and_changed_first_buffer_never_refresh_proof() {
    let fixture = Fixture::new();
    let first = value(fixture.capture(1002));
    for now in [0, 1000, 1150, 1200, u64::MAX] {
        assert!(fixture.capture(now).is_err());
    }
    let earlier = value(fixture.capture(1001));
    assert!(NativeHandoffVerified::reconcile(&first.canonical, &earlier).is_err());
    let mut changed = Fixture::new();
    let mut outputs = changed.frames.outputs().clone();
    outputs
        .values_mut()
        .next()
        .unwrap_or_else(|| unreachable!())
        .framebuffer += 1;
    let scope = value(DisplayFinalizationMaterial::decode(&changed.material))
        .recovery_scope()
        .unwrap_or_else(|_| unreachable!());
    changed.frames = value(DisplayNativeHandoffFacts::new(
        scope,
        changed.frames.lineage().clone(),
        changed.frames.window(),
        outputs,
    ));
    assert!(
        NativeHandoffVerified::reconcile(&first.canonical, &value(changed.capture(1003))).is_err()
    );
}

fn completion(
    fixture: &Fixture,
    proof: &NativeHandoffVerified,
    now: u64,
) -> Result<completion::NativeCompletionPrepared, ManagedLifecycleError> {
    completion::NativeCompletionPrepared::capture(
        &fixture.principal,
        &fixture.request,
        &fixture.snapshot,
        &fixture.dispatch,
        &fixture.material,
        &fixture.parent,
        proof,
        &fixture.observation,
        &fixture.frames,
        now,
    )
}

#[test]
fn completion_preparation_is_separate_durable_once_and_preserves_original_expiry() {
    let fixture = Fixture::new();
    let proof = value(fixture.capture(1002));
    let prepared = value(completion(&fixture, &proof, 1003));
    assert_eq!(prepared.expiry(), proof.expiry());
    for now in [1003, prepared.expiry() - 1] {
        value(prepared.require_current(now));
    }
    for now in [0, 1002, prepared.expiry(), u64::MAX] {
        assert!(prepared.require_current(now).is_err());
    }
    assert_ne!(prepared.digest(), proof.digest());
    let mut journal = Journal::default();
    value(prepared.retain_once(&mut journal));
    value(prepared.require_readback(&journal));
    assert!(prepared.retain_once(&mut journal).is_err());
    assert!(
        completion::NativeCompletionPrepared::require_absent(
            &journal,
            &fixture.principal,
            &fixture.request.request_id,
        )
        .is_err()
    );
    assert_eq!(journal.records.len(), 1);
    assert_eq!(fixture.snapshot.state, TransactionState::Indeterminate);
}

#[test]
fn completion_cannot_adopt_foreign_proof_frame_generation_or_later_clock() {
    let fixture = Fixture::new();
    let proof = value(fixture.capture(1002));
    for case in 0..7 {
        let mut changed = Fixture::new();
        match case {
            0 => changed.principal = value(PrincipalId::new("unix:uid:1001")),
            1 => changed.snapshot.current_generation += 1,
            2 => changed.snapshot.binding_digest = digest_bytes("foreign", b"binding"),
            3 => changed.parent.canonical.push(1),
            4 => changed.dispatch = "9".repeat(64),
            5 => changed.snapshot.state = TransactionState::Committed,
            _ => changed.request.request_id = value(RequestId::new("request:foreign")),
        }
        assert!(completion(&changed, &proof, 1003).is_err(), "case {case}");
    }
    for now in [0, 1001, 1150, 1200, u64::MAX] {
        assert!(completion(&fixture, &proof, now).is_err());
    }
    let mut changed = Fixture::new();
    let mut outputs = changed.frames.outputs().clone();
    outputs
        .values_mut()
        .next()
        .unwrap_or_else(|| unreachable!())
        .framebuffer += 1;
    let scope =
        value(value(DisplayFinalizationMaterial::decode(&changed.material)).recovery_scope());
    changed.frames = value(DisplayNativeHandoffFacts::new(
        scope,
        changed.frames.lineage().clone(),
        changed.frames.window(),
        outputs,
    ));
    assert!(completion(&changed, &proof, 1003).is_err());
}

#[test]
fn completion_storage_failure_ambiguity_or_substituted_readback_never_rearms() {
    let fixture = Fixture::new();
    let proof = value(fixture.capture(1002));
    let prepared = value(completion(&fixture, &proof, 1003));
    let mut journal = Journal {
        write_failure: true,
        ..Journal::default()
    };
    assert!(prepared.retain_once(&mut journal).is_err());
    assert_eq!(journal.records.len(), 1); // Persisted-before-error remains spent.
    journal.write_failure = false;
    assert!(prepared.retain_once(&mut journal).is_err());
    value(prepared.require_readback(&journal));
    let key = value(completion::NativeCompletionPrepared::key(
        &fixture.request.request_id,
    ));
    let entry = journal
        .records
        .get_mut(&(fixture.principal.clone(), key.clone()))
        .unwrap_or_else(|| unreachable!());
    let mut bytes = entry.canonical().to_vec();
    bytes.push(0);
    *entry = value(RetainedRequest::new(fixture.principal.clone(), key, bytes));
    assert!(prepared.require_readback(&journal).is_err());
    assert!(prepared.retain_once(&mut journal).is_err());
    journal.integrity_failure = true;
    assert!(prepared.require_readback(&journal).is_err());
}
