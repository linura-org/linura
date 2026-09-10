use linura_core::{Actor, ActorId, ActorKind, IntentId, PrincipalId, RequestId, ValidationError};
use linura_intent::{Intent, IntentStatus, ProposalDigest};
use linura_transaction::{TransactionAuthorityKey, TransactionAuthoritySigner};

use crate::{
    AcceptanceLinearizationClock, AuthorityTimeSample, AuthorityTimeSeal, LocalLibrary,
    ProposalAcceptanceAuthority, ProposalAcceptanceError, ProposalAcceptanceMaterial,
    ProposalAcceptanceTarget,
};

fn id<T>(value: Result<T, ValidationError>) -> T {
    value.unwrap_or_else(|error| unreachable!("{error}"))
}

fn authority_pair(
    byte: u8,
) -> (TransactionAuthoritySigner, ProposalAcceptanceAuthority) {
    let key = TransactionAuthorityKey::new(vec![byte; 32])
        .unwrap_or_else(|error| unreachable!("{error}"));
    let (signer, verifier) = key.split();
    (signer, ProposalAcceptanceAuthority::from_verifier(verifier))
}

fn intent() -> Intent {
    Intent {
        id: id(IntentId::new("intent:v08:library-authority")),
        actor: Actor {
            id: id(ActorId::new("uid:1000")),
            kind: ActorKind::Human,
            interactive: true,
        },
        statement: "Persist only a proposed intent".into(),
        status: IntentStatus::Proposed,
        requirements: vec![],
        supersedes: vec![],
    }
}

fn material(intent: &Intent) -> ProposalAcceptanceMaterial {
    ProposalAcceptanceMaterial::new(
        id(PrincipalId::new("principal:uid:1000")),
        id(RequestId::new("decision:v08:library-authority")),
        ProposalDigest::hash_parts(b"decision", &[b"binding"]),
        id(RequestId::new("proposal:v08:library-authority")),
        ProposalDigest::hash_parts(b"proposal", &[b"digest"]),
        ProposalDigest::hash_parts(b"context", &[b"digest"]),
        id(RequestId::new("operation:v08:library-authority")),
        ProposalAcceptanceTarget::Create {
            intent_id: intent.id.clone(),
        },
        7,
        ProposalDigest::hash_parts(b"authority", &[b"evidence"]),
        ProposalDigest::hash_parts(b"decision", &[b"validity"]),
        intent,
    )
    .unwrap_or_else(|error| unreachable!("{error}"))
}

fn time_seal() -> AuthorityTimeSeal {
    AuthorityTimeSeal {
        time_floor_unix_ms: 100,
        exclusive_deadline_unix_ms: 200,
        continuity_generation: 9,
        normalization_evidence_digest: ProposalDigest::hash_parts(
            b"normalization",
            &[b"exclusive-first-invalid"],
        ),
    }
}

struct TestClock(Option<AuthorityTimeSample>);

impl AcceptanceLinearizationClock for TestClock {
    fn sample(&mut self) -> Option<AuthorityTimeSample> {
        self.0
    }
}

#[test]
fn unprovisioned_library_fails_closed() {
    let mut library =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let (_, authority) = authority_pair(0x71);
    assert!(matches!(
        authority.begin(&mut library),
        Err(ProposalAcceptanceError::AuthorityNotProvisioned)
    ));
}

#[test]
fn provisioning_is_idempotent_and_cannot_be_rebound() {
    let mut library =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let (_, authority) = authority_pair(0x71);
    let (_, wrong_authority) = authority_pair(0x72);

    authority
        .provision(&mut library)
        .unwrap_or_else(|error| unreachable!("{error}"));
    authority
        .provision(&mut library)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(matches!(
        wrong_authority.provision(&mut library),
        Err(ProposalAcceptanceError::AuthorityBindingMismatch)
    ));
}

#[test]
fn handoff_signed_by_another_authority_is_rejected() {
    let mut library =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let (_, authority) = authority_pair(0x71);
    let (wrong_signer, _) = authority_pair(0x72);
    authority
        .provision(&mut library)
        .unwrap_or_else(|error| unreachable!("{error}"));

    let intent = intent();
    let material = material(&intent);
    let session = authority
        .begin(&mut library)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let challenge = session
        .signing_challenge(&material, time_seal())
        .unwrap_or_else(|error| unreachable!("{error}"));
    let handoff = wrong_signer
        .authorize_handoff(
            challenge.snapshot(),
            challenge.authority_use_digest().clone(),
            challenge.authorized_at_unix_ms(),
            challenge.expires_at_unix_ms(),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert!(matches!(
        session.bind_signed_handoff(&authority, challenge, handoff),
        Err(ProposalAcceptanceError::InvalidPermit)
    ));
}

#[test]
fn exact_signed_handoff_commits_and_replays_without_fresh_time() {
    let mut library =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let (signer, authority) = authority_pair(0x71);
    authority
        .provision(&mut library)
        .unwrap_or_else(|error| unreachable!("{error}"));

    let intent = intent();
    let material = material(&intent);
    let session = authority
        .begin(&mut library)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let challenge = session
        .signing_challenge(&material, time_seal())
        .unwrap_or_else(|error| unreachable!("{error}"));
    let handoff = signer
        .authorize_handoff(
            challenge.snapshot(),
            challenge.authority_use_digest().clone(),
            challenge.authorized_at_unix_ms(),
            challenge.expires_at_unix_ms(),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let permit = session
        .bind_signed_handoff(&authority, challenge, handoff)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let mut clock = TestClock(Some(AuthorityTimeSample {
        unix_ms: 150,
        continuity_generation: 9,
        continuity_established: true,
    }));
    let committed = session
        .commit(&authority, permit, &material, &intent, &mut clock)
        .unwrap_or_else(|error| unreachable!("{error}"));
    assert_eq!(committed.resulting_revision, 1);

    let replay = authority
        .replay_committed(&library, &material)
        .unwrap_or_else(|error| unreachable!("{error}"))
        .unwrap_or_else(|| unreachable!("committed acceptance must replay"));
    assert_eq!(replay, committed);
}

#[test]
fn write_at_exclusive_deadline_fails_without_mutation() {
    let mut library =
        LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
    let (signer, authority) = authority_pair(0x71);
    authority
        .provision(&mut library)
        .unwrap_or_else(|error| unreachable!("{error}"));

    let intent = intent();
    let material = material(&intent);
    let session = authority
        .begin(&mut library)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let challenge = session
        .signing_challenge(&material, time_seal())
        .unwrap_or_else(|error| unreachable!("{error}"));
    let handoff = signer
        .authorize_handoff(
            challenge.snapshot(),
            challenge.authority_use_digest().clone(),
            challenge.authorized_at_unix_ms(),
            challenge.expires_at_unix_ms(),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
    let permit = session
        .bind_signed_handoff(&authority, challenge, handoff)
        .unwrap_or_else(|error| unreachable!("{error}"));
    let mut clock = TestClock(Some(AuthorityTimeSample {
        unix_ms: 200,
        continuity_generation: 9,
        continuity_established: true,
    }));
    assert!(matches!(
        session.commit(&authority, permit, &material, &intent, &mut clock),
        Err(ProposalAcceptanceError::AuthorityExpired)
    ));
    assert!(library.intent(&intent.id).is_err());
}
