//! Level A only: proposed backlight data through the canonical planner, policy
//! and a recording transaction-store port. Process reconstruction is simulated;
//! this is not SQLite crash/durability, native execution or physical evidence.
//! The live managed route stays unregistered; concrete persistence remains an
//! adapter/composition concern, covered separately by inherited qualification.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use linura_core::{
    Actor, ActorId, ActorKind, ApprovalRequestId, BacklightDeviceGeneration, BacklightResourceId,
    BootId, Capability, CapabilityId, PrincipalId, ProviderId, RequestId, ResourceId, RiskClass,
    SemanticReason, SessionEpoch, SupportLevel,
};
use linura_observation::{
    ObservationAuthority, ObservationEnvelope, ObservedValue, ProviderAvailability, ProviderHealth,
};
use linura_observation_control::ObservationCoordinator;
use linura_policy::{ApprovalClass, PolicyDecision};
use linura_protocol::PlanDesiredStateRequest;
use linura_provider_sdk::{Observer, ProviderError};
use linura_transaction::{
    AbortRequest, AuthorityBinding, CommitRequest, HandoffCommit, HandoffRequest, PrepareOutcome,
    RecoveryAnchor, RecoveryOutcome, RecoveryRequest, RecoveryResolution, TransactionAuthorityKey,
    TransactionAuthorityVerifier, TransactionId, TransactionSnapshot, TransactionState,
    TransactionStore, TransactionStoreError, VerifiedCommitMaterial,
};

use crate::backlight_contract::{NATIVE_CHANGE_KEY, OBSERVATION, PROVIDER};
use crate::durable_authority::TrustedRiskFloor;
use crate::{
    AuthenticatedPrincipal, DurableAuthorityControl, DurableAuthorityError, DurableRecoveryOutcome,
    PlanPreviewControl, PolicyAuthenticatedApprover,
};

fn valid<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| unreachable!("{error:?}"))
}

fn now_ms() -> u64 {
    valid(u64::try_from(
        valid(SystemTime::now().duration_since(UNIX_EPOCH)).as_millis(),
    ))
}

fn resource() -> ResourceId {
    valid(
        valid(BacklightResourceId::new(
            valid(SessionEpoch::new(
                valid(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
                1000,
                "c2",
                42,
            )),
            valid(BacklightDeviceGeneration::new(
                "98765432-1234-4567-89ab-0123456789ab",
            )),
        ))
        .resource_id(),
    )
}

fn principal() -> AuthenticatedPrincipal {
    valid(AuthenticatedPrincipal::new("unix:uid:1000"))
}

fn actor() -> Actor {
    Actor {
        id: valid(ActorId::new("human:backlight-level-a")),
        kind: ActorKind::Human,
        interactive: true,
    }
}

fn request() -> PlanDesiredStateRequest {
    PlanDesiredStateRequest {
        request_id: valid(RequestId::new("request:backlight-level-a:one-attempt")),
        provider: valid(ProviderId::new(PROVIDER)),
        resource: resource(),
        observation_capability: valid(CapabilityId::new(OBSERVATION)),
        desired_state: BTreeMap::from([(NATIVE_CHANGE_KEY.into(), "70".into())]),
        reason: SemanticReason {
            summary: "Exercise observe-only recovery without native execution".into(),
            intent_ids: vec![valid(linura_core::IntentId::new(
                "intent:backlight-level-a",
            ))],
            requirement_ids: vec![],
            capability_ids: vec![valid(CapabilityId::new(OBSERVATION))],
        },
    }
}

fn floor() -> TrustedRiskFloor {
    TrustedRiskFloor::new(
        RiskClass::SecuritySensitive,
        "test.backlight.managed-risk-floor",
    )
}

#[derive(Debug)]
struct ReadState {
    native_value: u32,
    sequence: u64,
    unavailable: bool,
}

#[derive(Debug)]
struct SyntheticObserver(Arc<Mutex<ReadState>>);

impl Observer for SyntheticObserver {
    fn observer_id(&self) -> ProviderId {
        valid(ProviderId::new(PROVIDER))
    }
    fn observation_capabilities(&self) -> Vec<Capability> {
        vec![Capability {
            id: valid(CapabilityId::new(OBSERVATION)),
            support: SupportLevel::Supported,
            provider: Some(self.observer_id()),
            reason: None,
        }]
    }
    fn health(&self) -> ProviderHealth {
        ProviderHealth {
            provider: self.observer_id(),
            availability: ProviderAvailability::Available,
            reason: None,
        }
    }
    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        Ok(vec![resource()])
    }
    fn observe_authoritative(
        &self,
        target: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        let mut state = valid(self.0.lock());
        if state.unavailable {
            return Err(ProviderError::Unavailable(
                "injected observer outage".into(),
            ));
        }
        state.sequence += 1;
        Ok(ObservationEnvelope {
            provider: self.observer_id(),
            resource: target.clone(),
            capability: capability.clone(),
            authority: ObservationAuthority::SyntheticTest,
            observed_at_unix_ms: now_ms(),
            valid_for_ms: 30_000,
            sequence: state.sequence,
            attributes: BTreeMap::from([(
                NATIVE_CHANGE_KEY.into(),
                ObservedValue::U64(u64::from(state.native_value)),
            )]),
        })
    }
}

// This spy records Control's signed decisions; it deliberately refuses any
// IntendedEffectAbsent/reprepare resolution instead of implementing that path.
// It is not a persistence engine or a substitute for SQLite qualification.
#[derive(Debug, Default)]
struct Stored {
    binding: Option<AuthorityBinding>,
    snapshot: Option<TransactionSnapshot>,
    verified: Option<VerifiedCommitMaterial>,
    handoffs: usize,
    reprepares: usize,
}

#[derive(Debug)]
struct RecordingStore {
    shared: Arc<Mutex<Stored>>,
    verifier: TransactionAuthorityVerifier,
}

impl TransactionStore for RecordingStore {
    fn prepare(
        &mut self,
        binding: &AuthorityBinding,
    ) -> Result<PrepareOutcome, TransactionStoreError> {
        let mut stored = valid(self.shared.lock());
        if stored.snapshot.is_some() {
            return Err(TransactionStoreError::IdempotencyConflict);
        }
        let snapshot = TransactionSnapshot {
            transaction_id: binding.transaction_id(),
            principal: binding.principal().clone(),
            request_id: binding.request_id().clone(),
            current_generation: 0,
            state_version: 1,
            state: TransactionState::Prepared,
            binding_digest: binding.digest().clone(),
        };
        stored.binding = Some(binding.clone());
        stored.snapshot = Some(snapshot.clone());
        Ok(PrepareOutcome::Created(snapshot))
    }
    fn handoff(
        &mut self,
        request: &HandoffRequest,
    ) -> Result<HandoffCommit, TransactionStoreError> {
        assert!(self.verifier.verify_handoff(request));
        let mut stored = valid(self.shared.lock());
        let snapshot = stored
            .snapshot
            .as_mut()
            .ok_or(TransactionStoreError::NotFound)?;
        assert_eq!(snapshot.state, TransactionState::Prepared);
        assert_eq!(snapshot.transaction_id, *request.transaction_id());
        assert_eq!(snapshot.state_version, request.expected_state_version());
        assert_eq!(snapshot.current_generation, request.expected_generation());
        assert_eq!(snapshot.binding_digest, *request.expected_binding_digest());
        snapshot.state = TransactionState::Indeterminate;
        snapshot.state_version += 1;
        let handoff = HandoffCommit {
            transaction_id: snapshot.transaction_id.clone(),
            generation: snapshot.current_generation,
            state_version: snapshot.state_version,
            binding_digest: snapshot.binding_digest.clone(),
            authority_use_digest: request.authority_use_digest().clone(),
        };
        stored.handoffs += 1;
        Ok(handoff)
    }
    fn recover(
        &mut self,
        request: &RecoveryRequest,
    ) -> Result<RecoveryOutcome, TransactionStoreError> {
        assert!(self.verifier.verify_recovery(request));
        let mut stored = valid(self.shared.lock());
        let snapshot = stored
            .snapshot
            .as_mut()
            .ok_or(TransactionStoreError::NotFound)?;
        assert_eq!(snapshot.state, TransactionState::Indeterminate);
        assert_eq!(snapshot.transaction_id, *request.transaction_id());
        assert_eq!(snapshot.state_version, request.expected_state_version());
        assert_eq!(snapshot.current_generation, request.expected_generation());
        assert_eq!(snapshot.binding_digest, *request.expected_binding_digest());
        snapshot.state_version += 1;
        match request.resolution() {
            RecoveryResolution::Ambiguous { .. } => {
                Ok(RecoveryOutcome::StillIndeterminate(snapshot.clone()))
            }
            RecoveryResolution::ConflictingState { .. } => {
                snapshot.state = TransactionState::RecoveryBlocked;
                Ok(RecoveryOutcome::Blocked(snapshot.clone()))
            }
            RecoveryResolution::IntendedStateVerified {
                desired_state_digest,
                graph_digest,
                provenance_digest,
                ..
            } => {
                snapshot.state = TransactionState::Verified;
                let snapshot = snapshot.clone();
                stored.verified = Some(VerifiedCommitMaterial {
                    snapshot: snapshot.clone(),
                    desired_state_digest: desired_state_digest.clone(),
                    graph_digest: graph_digest.clone(),
                    provenance_digest: provenance_digest.clone(),
                });
                Ok(RecoveryOutcome::Verified(snapshot))
            }
            RecoveryResolution::IntendedEffectAbsent { .. } => {
                stored.reprepares += 1;
                Err(TransactionStoreError::StateConflict)
            }
        }
    }
    fn commit(
        &mut self,
        request: &CommitRequest,
    ) -> Result<TransactionSnapshot, TransactionStoreError> {
        assert!(self.verifier.verify_commit(request));
        let mut stored = valid(self.shared.lock());
        let verified = stored
            .verified
            .as_ref()
            .ok_or(TransactionStoreError::NotFound)?;
        assert_eq!(
            verified.desired_state_digest,
            *request.desired_state_digest()
        );
        assert_eq!(verified.graph_digest, *request.graph_digest());
        assert_eq!(verified.provenance_digest, *request.provenance_digest());
        let snapshot = stored
            .snapshot
            .as_mut()
            .ok_or(TransactionStoreError::NotFound)?;
        assert_eq!(snapshot.state, TransactionState::Verified);
        assert_eq!(snapshot.transaction_id, *request.transaction_id());
        assert_eq!(snapshot.state_version, request.expected_state_version());
        assert_eq!(snapshot.current_generation, request.expected_generation());
        assert_eq!(snapshot.binding_digest, *request.expected_binding_digest());
        snapshot.state = TransactionState::Committed;
        snapshot.state_version += 1;
        Ok(snapshot.clone())
    }
    fn abort_prepared(
        &mut self,
        request: &AbortRequest,
    ) -> Result<TransactionSnapshot, TransactionStoreError> {
        let mut stored = valid(self.shared.lock());
        let snapshot = stored
            .snapshot
            .as_mut()
            .ok_or(TransactionStoreError::NotFound)?;
        assert_eq!(snapshot.state, TransactionState::Prepared);
        assert_eq!(snapshot.transaction_id, request.transaction_id);
        assert_eq!(snapshot.state_version, request.expected_state_version);
        assert_eq!(snapshot.current_generation, request.expected_generation);
        snapshot.state = TransactionState::Aborted;
        snapshot.state_version += 1;
        Ok(snapshot.clone())
    }
    fn snapshot(&self, id: &TransactionId) -> Result<TransactionSnapshot, TransactionStoreError> {
        valid(self.shared.lock())
            .snapshot
            .as_ref()
            .filter(|s| s.transaction_id == *id)
            .cloned()
            .ok_or(TransactionStoreError::NotFound)
    }
    fn recovery_anchor(&self, id: &TransactionId) -> Result<RecoveryAnchor, TransactionStoreError> {
        let snapshot = self.snapshot(id)?;
        let stored = valid(self.shared.lock());
        let binding = stored
            .binding
            .as_ref()
            .ok_or(TransactionStoreError::NotFound)?;
        Ok(RecoveryAnchor {
            snapshot,
            request_digest: binding.request_digest().clone(),
            precondition_digest: binding.precondition_digest().clone(),
        })
    }
    fn verified_commit_material(
        &self,
        id: &TransactionId,
    ) -> Result<VerifiedCommitMaterial, TransactionStoreError> {
        valid(self.shared.lock())
            .verified
            .as_ref()
            .filter(|v| v.snapshot.transaction_id == *id)
            .cloned()
            .ok_or(TransactionStoreError::NotFound)
    }
    fn list_state(
        &self,
        state: TransactionState,
    ) -> Result<Vec<TransactionSnapshot>, TransactionStoreError> {
        Ok(valid(self.shared.lock())
            .snapshot
            .iter()
            .filter(|s| s.state == state)
            .cloned()
            .collect())
    }
    fn integrity_check(&self) -> Result<(), TransactionStoreError> {
        Ok(())
    }
}

struct Fixture {
    authority_key: Vec<u8>,
    state: Arc<Mutex<ReadState>>,
    stored: Arc<Mutex<Stored>>,
}

impl Fixture {
    fn new() -> Self {
        let mut authority_key = Vec::with_capacity(32);
        let read = valid(
            valid(std::fs::File::open("/dev/urandom"))
                .take(32)
                .read_to_end(&mut authority_key),
        );
        assert_eq!(read, 32);
        Self {
            authority_key,
            state: Arc::new(Mutex::new(ReadState {
                native_value: 30,
                sequence: 0,
                unavailable: false,
            })),
            stored: Arc::new(Mutex::new(Stored::default())),
        }
    }

    fn open(&self) -> DurableAuthorityControl<RecordingStore> {
        let (signer, verifier) =
            valid(TransactionAuthorityKey::new(self.authority_key.clone())).split();
        let store = RecordingStore {
            shared: self.stored.clone(),
            verifier,
        };
        valid(DurableAuthorityControl::new(store, signer))
    }

    fn previews(&self) -> PlanPreviewControl {
        let mut coordinator = ObservationCoordinator::new();
        valid(coordinator.register_observer(Box::new(SyntheticObserver(self.state.clone()))));
        PlanPreviewControl::new(coordinator)
    }

    fn prepare(
        &self,
        control: &mut DurableAuthorityControl<RecordingStore>,
        previews: &mut PlanPreviewControl,
    ) -> crate::PreparedDurableAuthority {
        let candidate = valid(control.candidate_with_risk_floor(
            previews,
            principal(),
            actor(),
            request(),
            floor(),
        ));
        assert!(matches!(
            candidate.review().decision(),
            PolicyDecision::RequireApproval {
                class: ApprovalClass::Administrator,
                ..
            }
        ));
        let admin = PolicyAuthenticatedApprover::new(
            valid(PrincipalId::new("unix:uid:1001")),
            ActorKind::Human,
            BTreeSet::from([ApprovalClass::Administrator]),
        );
        let evidence = valid(control.issue_approval(
            valid(ApprovalRequestId::new("approval:backlight-level-a")),
            &candidate,
            &admin,
            now_ms() / 1000 + 60,
        ));
        valid(control.prepare(candidate, Some(evidence.id().clone())))
    }
}

fn transaction() -> TransactionId {
    TransactionId::for_namespace(
        &valid(PrincipalId::new(principal().as_str())),
        &request().request_id,
    )
}

#[test]
fn reconstructed_control_aborts_prepared_backlight_before_any_attempt() {
    let fixture = Fixture::new();
    {
        let mut control = fixture.open();
        let mut previews = fixture.previews();
        let _prepared = fixture.prepare(&mut control, &mut previews);
        assert_eq!(
            valid(control.snapshot(&transaction())).state,
            TransactionState::Prepared
        );
    }
    let reopened = fixture.open();
    assert_eq!(
        valid(reopened.snapshot(&transaction())).state,
        TransactionState::Aborted
    );
}

#[test]
fn retained_attempt_survives_control_reconstruction_without_repreparing_original_state() {
    let fixture = Fixture::new();
    let reserved = {
        let mut control = fixture.open();
        let mut previews = fixture.previews();
        let mut prepared = fixture.prepare(&mut control, &mut previews);
        // Reserving an attempt is not performing a native operation in this test.
        let _consumed = valid(control.handoff(&principal(), &mut prepared));
        assert_eq!(
            control.handoff(&principal(), &mut prepared),
            Err(DurableAuthorityError::AlreadyHandedOff)
        );
        valid(control.snapshot(&transaction()))
    };
    assert_eq!(reserved.state, TransactionState::Indeterminate);
    let mut reopened = fixture.open();
    let mut previews = fixture.previews();
    for _ in 0..3 {
        assert!(matches!(
            valid(reopened.recover_indeterminate_without_replay(
                &mut previews,
                principal(),
                actor(),
                request(),
                floor()
            )),
            DurableRecoveryOutcome::StillIndeterminate(_)
        ));
        let current = valid(reopened.snapshot(&transaction()));
        assert_eq!(current.state, TransactionState::Indeterminate);
        assert_eq!(current.current_generation, reserved.current_generation);
        assert_eq!(current.binding_digest, reserved.binding_digest);
        assert_eq!(valid(fixture.stored.lock()).handoffs, 1);
        assert_eq!(valid(fixture.stored.lock()).reprepares, 0);
    }
}

#[test]
fn uncertain_desired_observation_can_verify_but_never_mint_another_dispatch() {
    let fixture = Fixture::new();
    let mut control = fixture.open();
    let mut previews = fixture.previews();
    let mut prepared = fixture.prepare(&mut control, &mut previews);
    let _consumed = valid(control.handoff(&principal(), &mut prepared));
    valid(fixture.state.lock()).native_value = 70;
    let verified = match valid(control.recover_indeterminate_without_replay(
        &mut previews,
        principal(),
        actor(),
        request(),
        floor(),
    )) {
        DurableRecoveryOutcome::Verified(verified) => verified,
        other => unreachable!("unexpected recovery {other:?}"),
    };
    assert_eq!(
        verified.snapshot().current_generation,
        prepared.snapshot().current_generation
    );
    assert_eq!(
        control.handoff(&principal(), &mut prepared),
        Err(DurableAuthorityError::AlreadyHandedOff)
    );
    let snapshot = valid(control.commit_verified(&principal(), verified));
    assert_eq!(snapshot.state, TransactionState::Committed);
    drop(control);
    assert_eq!(
        valid(fixture.open().snapshot(&transaction())).state,
        TransactionState::Committed
    );
}

#[test]
fn observer_outage_and_foreign_recovery_cannot_reset_a_consumed_attempt() {
    let fixture = Fixture::new();
    let mut control = fixture.open();
    let mut previews = fixture.previews();
    let mut prepared = fixture.prepare(&mut control, &mut previews);
    let _consumed = valid(control.handoff(&principal(), &mut prepared));
    let reserved = valid(control.snapshot(&transaction()));
    valid(fixture.state.lock()).unavailable = true;
    assert!(
        control
            .recover_indeterminate_without_replay(
                &mut previews,
                principal(),
                actor(),
                request(),
                floor()
            )
            .is_err()
    );
    assert_eq!(valid(control.snapshot(&transaction())), reserved);
    valid(fixture.state.lock()).unavailable = false;
    let mut changed = request();
    changed
        .desired_state
        .insert(NATIVE_CHANGE_KEY.into(), "71".into());
    assert!(matches!(
        control.recover_indeterminate_without_replay(
            &mut previews,
            principal(),
            actor(),
            changed,
            floor()
        ),
        Err(DurableAuthorityError::RecoveryRequestMismatch)
    ));
    assert!(
        control
            .recover_indeterminate_without_replay(
                &mut previews,
                valid(AuthenticatedPrincipal::new("unix:uid:1001")),
                actor(),
                request(),
                floor()
            )
            .is_err()
    );
    assert_eq!(valid(control.snapshot(&transaction())), reserved);
}

#[test]
fn neither_existing_nor_fresh_approval_can_reprepare_an_uncertain_backlight_attempt() {
    let fixture = Fixture::new();
    let mut control = fixture.open();
    let mut previews = fixture.previews();
    let mut prepared = fixture.prepare(&mut control, &mut previews);
    let _consumed = valid(control.handoff(&principal(), &mut prepared));
    let reserved = valid(control.snapshot(&transaction()));
    assert!(matches!(
        control.recover_indeterminate(&mut previews, principal(), actor(), request(), None),
        Err(DurableAuthorityError::AuthorityChanged)
    ));
    let admin = PolicyAuthenticatedApprover::new(
        valid(PrincipalId::new("unix:uid:1001")),
        ActorKind::Human,
        BTreeSet::from([ApprovalClass::Administrator]),
    );
    let approval = crate::FreshRecoveryApproval::new(
        valid(ApprovalRequestId::new(
            "approval:backlight-level-a:fresh-retry",
        )),
        admin,
        now_ms() / 1000 + 60,
    );
    assert!(matches!(
        control.recover_indeterminate_with_approver(
            &mut previews,
            principal(),
            actor(),
            request(),
            approval,
        ),
        Err(DurableAuthorityError::AuthorityChanged)
    ));
    assert_eq!(valid(control.snapshot(&transaction())), reserved);
    assert_eq!(valid(fixture.stored.lock()).reprepares, 0);
    assert_eq!(valid(fixture.stored.lock()).handoffs, 1);
}

#[test]
fn changed_native_state_blocks_recovery_without_repreparing_or_dispatching() {
    let fixture = Fixture::new();
    let mut control = fixture.open();
    let mut previews = fixture.previews();
    let mut prepared = fixture.prepare(&mut control, &mut previews);
    let _consumed = valid(control.handoff(&principal(), &mut prepared));
    valid(fixture.state.lock()).native_value = 40;
    assert!(matches!(
        valid(control.recover_indeterminate_without_replay(
            &mut previews,
            principal(),
            actor(),
            request(),
            floor(),
        )),
        DurableRecoveryOutcome::Blocked(_)
    ));
    assert_eq!(
        valid(control.snapshot(&transaction())).state,
        TransactionState::RecoveryBlocked
    );
    assert_eq!(valid(fixture.stored.lock()).reprepares, 0);
    assert_eq!(valid(fixture.stored.lock()).handoffs, 1);
}

#[test]
fn conservative_risk_review_cannot_downgrade_or_register_a_backlight_effect() {
    let fixture = Fixture::new();
    let mut control = fixture.open();
    let mut previews = fixture.previews();
    let candidate = valid(control.candidate_with_risk_floor(
        &mut previews,
        principal(),
        actor(),
        request(),
        TrustedRiskFloor::new(RiskClass::UserState, "test.attempted-lower-floor"),
    ));
    assert_eq!(
        candidate.review().subject().prospective_risk(),
        RiskClass::SecuritySensitive
    );
    assert!(matches!(
        candidate.review().decision(),
        PolicyDecision::RequireApproval {
            class: ApprovalClass::Administrator,
            ..
        }
    ));
    let semantics = crate::OperationSemanticsControl::from_trusted_registry(valid(
        crate::operation_registry::trusted_builtin_operation_registry(),
    ));
    let id = valid(linura_core::OperationId::new(
        crate::backlight_contract::OPERATION_ID,
    ));
    assert_eq!(
        semantics.resolve_external(&id, candidate.plan()),
        Err(crate::OperationSemanticsError::UnknownOperation(id))
    );
    assert!(matches!(
        control.prepare(candidate, None),
        Err(DurableAuthorityError::MissingApproval)
    ));
    assert!(valid(fixture.stored.lock()).snapshot.is_none());
}

#[test]
fn wrong_resource_capability_and_extra_material_changes_are_not_classified() {
    let fixture = Fixture::new();
    for case in 0..3 {
        let mut control = fixture.open();
        let mut previews = fixture.previews();
        let mut changed = request();
        match case {
            0 => changed.resource = valid(ResourceId::new("backlight:physical:intel_backlight")),
            1 => {
                changed.observation_capability =
                    valid(CapabilityId::new("session.transition.observe"))
            }
            _ => {
                changed
                    .desired_state
                    .insert("subsystem".into(), "leds".into());
            }
        }
        assert!(
            control
                .candidate_with_risk_floor(&mut previews, principal(), actor(), changed, floor(),)
                .is_err()
        );
        assert!(valid(fixture.stored.lock()).snapshot.is_none());
    }
}

#[test]
fn foreign_or_root_principal_cannot_borrow_the_actor_or_resource_owner() {
    let fixture = Fixture::new();
    let mut control = fixture.open();
    let mut previews = fixture.previews();
    for identity in ["unix:uid:1001", "unix:uid:0", "uid:1000", "unix:uid:01000"] {
        assert!(matches!(
            control.candidate_with_risk_floor(
                &mut previews,
                valid(AuthenticatedPrincipal::new(identity)),
                actor(),
                request(),
                floor(),
            ),
            Err(DurableAuthorityError::CandidateBlocked)
        ));
    }
    assert_eq!(valid(fixture.state.lock()).sequence, 0);
    assert!(valid(fixture.stored.lock()).snapshot.is_none());
}
