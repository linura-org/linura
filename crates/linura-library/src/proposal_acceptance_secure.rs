use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};

use linura_core::{ActorKind, IntentId, PrincipalId, RequestId};
use linura_intent::{Intent, IntentStatus, ProposalDigest, RequirementKind};
use linura_transaction::{
    ContentDigest, HandoffRequest, TransactionAuthorityVerifier, TransactionId,
    TransactionSnapshot, TransactionState, digest_bytes, digest_parts,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{LibraryError, LocalLibrary};

const ACCEPTANCE_RESULT_KIND: &str = "intent-proposal-acceptance";
const ACCEPTANCE_RECORD_PREFIX: &str = "v08:acceptance:";
const PROPOSAL_INDEX_PREFIX: &str = "v08:proposal:";
const DECISION_INDEX_PREFIX: &str = "v08:decision:";
const AUTHORITY_BINDING_ENTITY_ID: &str = "v08:proposal-acceptance-authority";
const MAX_RECORD_PAYLOAD_BYTES: usize = 64 * 1024;

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalAcceptanceAction {
    Create,
    ReviseProposed,
}

impl ProposalAcceptanceAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::ReviseProposed => "revise-proposed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalAcceptanceTarget {
    Create {
        intent_id: IntentId,
    },
    ReviseProposed {
        intent_id: IntentId,
        expected_revision: u64,
    },
}

impl ProposalAcceptanceTarget {
    #[must_use]
    pub const fn action(&self) -> ProposalAcceptanceAction {
        match self {
            Self::Create { .. } => ProposalAcceptanceAction::Create,
            Self::ReviseProposed { .. } => ProposalAcceptanceAction::ReviseProposed,
        }
    }

    #[must_use]
    pub fn intent_id(&self) -> &IntentId {
        match self {
            Self::Create { intent_id } | Self::ReviseProposed { intent_id, .. } => intent_id,
        }
    }

    #[must_use]
    pub const fn expected_revision(&self) -> Option<u64> {
        match self {
            Self::Create { .. } => None,
            Self::ReviseProposed {
                expected_revision, ..
            } => Some(*expected_revision),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalAcceptanceMaterial {
    pub principal: PrincipalId,
    pub decision_id: RequestId,
    pub decision_binding_digest: ProposalDigest,
    pub proposal_id: RequestId,
    pub proposal_digest: ProposalDigest,
    pub accepted_context_digest: ProposalDigest,
    pub operation_id: RequestId,
    pub target: ProposalAcceptanceTarget,
    pub authority_generation: u64,
    pub authority_evidence_digest: ProposalDigest,
    pub decision_validity_digest: ProposalDigest,
    pub resulting_intent_digest: ProposalDigest,
}

impl ProposalAcceptanceMaterial {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal: PrincipalId,
        decision_id: RequestId,
        decision_binding_digest: ProposalDigest,
        proposal_id: RequestId,
        proposal_digest: ProposalDigest,
        accepted_context_digest: ProposalDigest,
        operation_id: RequestId,
        target: ProposalAcceptanceTarget,
        authority_generation: u64,
        authority_evidence_digest: ProposalDigest,
        decision_validity_digest: ProposalDigest,
        resulting_intent: &Intent,
    ) -> Result<Self, ProposalAcceptanceError> {
        validate_proposed_intent(resulting_intent)?;
        if authority_generation == 0 {
            return Err(ProposalAcceptanceError::BindingMismatch(
                "acceptance authority generation must be non-zero".into(),
            ));
        }
        if target.intent_id() != &resulting_intent.id {
            return Err(ProposalAcceptanceError::BindingMismatch(
                "acceptance target does not match resulting intent id".into(),
            ));
        }
        Ok(Self {
            principal,
            decision_id,
            decision_binding_digest,
            proposal_id,
            proposal_digest,
            accepted_context_digest,
            operation_id,
            target,
            authority_generation,
            authority_evidence_digest,
            decision_validity_digest,
            resulting_intent_digest: digest_intent(resulting_intent),
        })
    }

    #[must_use]
    pub fn semantic_digest(&self) -> ProposalDigest {
        let expected_revision = self
            .target
            .expected_revision()
            .map_or_else(|| "none".to_string(), |value| value.to_string());
        ProposalDigest::hash_parts(
            b"linura:proposal-acceptance-material:v1",
            &[
                self.principal.as_str().as_bytes(),
                self.decision_id.as_str().as_bytes(),
                self.decision_binding_digest.to_hex().as_bytes(),
                self.proposal_id.as_str().as_bytes(),
                self.proposal_digest.to_hex().as_bytes(),
                self.accepted_context_digest.to_hex().as_bytes(),
                self.operation_id.as_str().as_bytes(),
                self.target.action().as_str().as_bytes(),
                self.target.intent_id().as_str().as_bytes(),
                expected_revision.as_bytes(),
                self.authority_generation.to_string().as_bytes(),
                self.authority_evidence_digest.to_hex().as_bytes(),
                self.decision_validity_digest.to_hex().as_bytes(),
                self.resulting_intent_digest.to_hex().as_bytes(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityTimeSeal {
    pub time_floor_unix_ms: u64,
    pub exclusive_deadline_unix_ms: u64,
    pub continuity_generation: u64,
    pub normalization_evidence_digest: ProposalDigest,
}

impl AuthorityTimeSeal {
    pub fn validate(&self) -> Result<(), ProposalAcceptanceError> {
        if self.time_floor_unix_ms == 0
            || self.time_floor_unix_ms >= self.exclusive_deadline_unix_ms
        {
            return Err(ProposalAcceptanceError::InvalidTimeSeal(
                "time floor must be non-zero and strictly before the exclusive authority-validity deadline"
                    .into(),
            ));
        }
        if self.continuity_generation == 0 {
            return Err(ProposalAcceptanceError::InvalidTimeSeal(
                "trusted-time continuity generation must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityTimeSample {
    pub unix_ms: u64,
    pub continuity_generation: u64,
    pub continuity_established: bool,
}

pub trait AcceptanceLinearizationClock {
    /// Sample trusted Linura Control time. `None` means time cannot currently be
    /// established and therefore fails closed.
    fn sample(&mut self) -> Option<AuthorityTimeSample>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalAcceptanceRecord {
    pub material: ProposalAcceptanceMaterial,
    pub time_seal: AuthorityTimeSeal,
    pub resulting_intent_id: IntentId,
    pub resulting_revision: u64,
    pub linearized_at_unix_ms: u64,
}

/// Persistence-side verifier for Control-authorized proposal acceptance.
///
/// This object can verify sealed Control handoffs but cannot mint them. The
/// corresponding signer is deliberately absent from this crate's acceptance
/// implementation. A trusted composition root must provision the verifier
/// fingerprint into a Library before `begin`; `begin` never bootstraps trust.
#[derive(Debug)]
pub struct ProposalAcceptanceAuthority {
    verifier: TransactionAuthorityVerifier,
}

impl ProposalAcceptanceAuthority {
    #[must_use]
    pub fn from_verifier(verifier: TransactionAuthorityVerifier) -> Self {
        Self { verifier }
    }

    /// Establish the expected verifier for a newly composed Library.
    ///
    /// Provisioning is explicit and idempotent. It never replaces an existing
    /// different binding. Production composition must perform this before the
    /// Library handle is made available to request-processing code.
    pub fn provision(
        &self,
        library: &mut LocalLibrary,
    ) -> Result<(), ProposalAcceptanceError> {
        provision_authority_binding(&mut library.connection, &self.verifier)
    }

    pub fn replay_committed(
        &self,
        library: &LocalLibrary,
        material: &ProposalAcceptanceMaterial,
    ) -> Result<Option<ProposalAcceptanceRecord>, ProposalAcceptanceError> {
        require_authority_binding(&library.connection, &self.verifier)?;
        replay_committed(&library.connection, material)
    }

    pub fn begin<'a>(
        &self,
        library: &'a mut LocalLibrary,
    ) -> Result<ProposalAcceptanceTransaction<'a>, ProposalAcceptanceError> {
        require_authority_binding(&library.connection, &self.verifier)?;
        let authority_fingerprint = self.verifier.fingerprint().as_str().to_string();
        let transaction = library
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Ok(ProposalAcceptanceTransaction {
            transaction,
            authority_fingerprint,
            session_id: next_nonzero(&NEXT_SESSION_ID),
        })
    }

    fn verify_handoff(&self, handoff: &HandoffRequest) -> bool {
        self.verifier.verify_handoff(handoff)
    }

    fn fingerprint(&self) -> String {
        self.verifier.fingerprint().as_str().to_string()
    }
}

/// Exact, non-authoritative signing material produced only after Library has
/// acquired its durable write/CAS guard. It contains no credential or signing
/// capability. Control may inspect it solely to seal the corresponding handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptanceSigningChallenge {
    snapshot: TransactionSnapshot,
    authority_use_digest: ContentDigest,
    material_digest: ProposalDigest,
    time_seal: AuthorityTimeSeal,
}

impl AcceptanceSigningChallenge {
    #[must_use]
    pub fn snapshot(&self) -> &TransactionSnapshot {
        &self.snapshot
    }

    #[must_use]
    pub fn authority_use_digest(&self) -> &ContentDigest {
        &self.authority_use_digest
    }

    #[must_use]
    pub const fn authorized_at_unix_ms(&self) -> u64 {
        self.time_seal.time_floor_unix_ms
    }

    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.time_seal.exclusive_deadline_unix_ms
    }
}

#[derive(Debug)]
pub struct ProposalAcceptanceTransaction<'a> {
    transaction: Transaction<'a>,
    authority_fingerprint: String,
    session_id: u64,
}

impl<'a> ProposalAcceptanceTransaction<'a> {
    /// Read the target while the durable SQLite write/CAS guard is held.
    pub fn current_target(
        &self,
        intent_id: &IntentId,
    ) -> Result<Option<(u64, IntentStatus)>, ProposalAcceptanceError> {
        self.transaction
            .query_row(
                "SELECT c.revision, r.status FROM intents_current c JOIN intent_revisions r ON r.intent_id = c.intent_id AND r.revision = c.revision WHERE c.intent_id = ?1",
                params![intent_id.as_str()],
                |row| {
                    let revision: i64 = row.get(0)?;
                    let status: String = row.get(1)?;
                    Ok((revision, status))
                },
            )
            .optional()?
            .map(|(revision, status)| {
                let revision = u64::try_from(revision).map_err(|_| {
                    ProposalAcceptanceError::Corrupt(
                        "negative/out-of-range current intent revision".into(),
                    )
                })?;
                Ok((revision, parse_intent_status(&status)?))
            })
            .transpose()
    }

    /// Construct exact material for Control to sign after final revalidation.
    /// No signer or raw key crosses into Library.
    pub fn signing_challenge(
        &self,
        material: &ProposalAcceptanceMaterial,
        time_seal: AuthorityTimeSeal,
    ) -> Result<AcceptanceSigningChallenge, ProposalAcceptanceError> {
        time_seal.validate()?;
        let snapshot = acceptance_snapshot(material, self.session_id);
        Ok(AcceptanceSigningChallenge {
            authority_use_digest: time_seal_digest(&time_seal),
            material_digest: material.semantic_digest(),
            snapshot,
            time_seal,
        })
    }

    /// Verify and bind a Control-sealed handoff to this exact transaction.
    pub fn bind_signed_handoff(
        &self,
        authority: &ProposalAcceptanceAuthority,
        challenge: AcceptanceSigningChallenge,
        handoff: HandoffRequest,
    ) -> Result<AcceptanceCommitPermit, ProposalAcceptanceError> {
        if self.authority_fingerprint != authority.fingerprint()
            || !authority.verify_handoff(&handoff)
            || !challenge_matches_session(&challenge, self.session_id)
            || !handoff_matches_challenge(&handoff, &challenge)
        {
            return Err(ProposalAcceptanceError::InvalidPermit);
        }
        Ok(AcceptanceCommitPermit { challenge, handoff })
    }

    pub fn commit<C: AcceptanceLinearizationClock>(
        self,
        authority: &ProposalAcceptanceAuthority,
        permit: AcceptanceCommitPermit,
        material: &ProposalAcceptanceMaterial,
        resulting_intent: &Intent,
        clock: &mut C,
    ) -> Result<ProposalAcceptanceRecord, ProposalAcceptanceError> {
        if self.authority_fingerprint != authority.fingerprint()
            || !authority.verify_handoff(&permit.handoff)
            || !challenge_matches_session(&permit.challenge, self.session_id)
            || !handoff_matches_challenge(&permit.handoff, &permit.challenge)
        {
            return Err(ProposalAcceptanceError::InvalidPermit);
        }
        let semantic_digest = material.semantic_digest();
        if permit.challenge.material_digest != semantic_digest {
            return Err(ProposalAcceptanceError::BindingMismatch(
                "sealed acceptance handoff does not match acceptance material".into(),
            ));
        }
        permit.challenge.time_seal.validate()?;
        validate_proposed_intent(resulting_intent)?;
        if digest_intent(resulting_intent) != material.resulting_intent_digest
            || &resulting_intent.id != material.target.intent_id()
        {
            return Err(ProposalAcceptanceError::BindingMismatch(
                "resulting intent differs from the exact accepted material".into(),
            ));
        }

        if let Some(record) = replay_committed(&self.transaction, material)? {
            self.transaction.rollback()?;
            return Ok(record);
        }
        reject_identity_conflicts(&self.transaction, material, &semantic_digest)?;
        let resulting_revision = validate_target(&self.transaction, material)?;

        // There are intentionally no callbacks or externally controllable waits
        // after this trusted-time sample and before the atomic write set.
        let sample = clock
            .sample()
            .ok_or(ProposalAcceptanceError::TrustedTimeUnavailable)?;
        enforce_time_sample(&permit.challenge.time_seal, sample)?;

        insert_intent_revision(&self.transaction, resulting_intent, resulting_revision)?;
        match material.target {
            ProposalAcceptanceTarget::Create { .. } => {
                self.transaction.execute(
                    "INSERT INTO intents_current(intent_id, revision, causal_generation, causal_complete) VALUES (?1, ?2, 0, 0)",
                    params![resulting_intent.id.as_str(), revision_sql(resulting_revision)?],
                )?;
            }
            ProposalAcceptanceTarget::ReviseProposed { .. } => {
                self.transaction.execute(
                    "UPDATE intents_current SET revision = ?2, causal_generation = 0, causal_complete = 0 WHERE intent_id = ?1",
                    params![resulting_intent.id.as_str(), revision_sql(resulting_revision)?],
                )?;
            }
        }

        let record = ProposalAcceptanceRecord {
            material: material.clone(),
            time_seal: permit.challenge.time_seal,
            resulting_intent_id: resulting_intent.id.clone(),
            resulting_revision,
            linearized_at_unix_ms: sample.unix_ms,
        };
        persist_acceptance_record(&self.transaction, &record, &semantic_digest)?;
        self.transaction.commit()?;
        Ok(record)
    }
}

#[derive(Debug)]
pub struct AcceptanceCommitPermit {
    challenge: AcceptanceSigningChallenge,
    handoff: HandoffRequest,
}

#[derive(Debug)]
pub enum ProposalAcceptanceError {
    Library(LibraryError),
    Sqlite(rusqlite::Error),
    AuthorityNotProvisioned,
    AuthorityBindingMismatch,
    InvalidPermit,
    BindingMismatch(String),
    InvalidTimeSeal(String),
    TrustedTimeUnavailable,
    TrustedTimeRollback,
    TrustedTimeContinuityLost,
    AuthorityExpired,
    IdentityConflict { kind: &'static str, id: String },
    TargetAlreadyExists(IntentId),
    TargetNotFound(IntentId),
    TargetNotProposed(IntentId),
    RevisionConflict { expected: u64, actual: u64 },
    Corrupt(String),
}

impl Display for ProposalAcceptanceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Library(error) => Display::fmt(error, f),
            Self::Sqlite(error) => write!(f, "SQLite proposal-acceptance error: {error}"),
            Self::AuthorityNotProvisioned => f.write_str(
                "proposal acceptance authority is not provisioned for this Library",
            ),
            Self::AuthorityBindingMismatch => f.write_str(
                "proposal acceptance verifier does not match the authority provisioned for this Library",
            ),
            Self::InvalidPermit => f.write_str(
                "proposal acceptance requires the exact Control-sealed handoff for this durable transaction",
            ),
            Self::BindingMismatch(reason) => {
                write!(f, "proposal acceptance binding mismatch: {reason}")
            }
            Self::InvalidTimeSeal(reason) => {
                write!(f, "invalid proposal acceptance authority-time seal: {reason}")
            }
            Self::TrustedTimeUnavailable => {
                f.write_str("trusted Control time is unavailable at acceptance linearization")
            }
            Self::TrustedTimeRollback => {
                f.write_str("trusted Control time moved below the sealed authority-time floor")
            }
            Self::TrustedTimeContinuityLost => f.write_str(
                "trusted Control time continuity was reset, rebound, or cannot be proven",
            ),
            Self::AuthorityExpired => f.write_str(
                "proposal acceptance authority expired before durable linearization",
            ),
            Self::IdentityConflict { kind, id } => write!(
                f,
                "{kind} identity {id} was already used for different proposal-acceptance semantics"
            ),
            Self::TargetAlreadyExists(id) => write!(
                f,
                "proposal acceptance create target already exists: {}",
                id.as_str()
            ),
            Self::TargetNotFound(id) => write!(
                f,
                "proposal acceptance revision target does not exist: {}",
                id.as_str()
            ),
            Self::TargetNotProposed(id) => write!(
                f,
                "proposal acceptance may revise only Proposed intent: {}",
                id.as_str()
            ),
            Self::RevisionConflict { expected, actual } => write!(
                f,
                "proposal acceptance target revision conflict: expected {expected}, current revision is {actual}"
            ),
            Self::Corrupt(reason) => write!(f, "corrupt proposal-acceptance evidence: {reason}"),
        }
    }
}

impl std::error::Error for ProposalAcceptanceError {}

impl From<LibraryError> for ProposalAcceptanceError {
    fn from(value: LibraryError) -> Self {
        Self::Library(value)
    }
}

impl From<rusqlite::Error> for ProposalAcceptanceError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

fn acceptance_snapshot(material: &ProposalAcceptanceMaterial, session_id: u64) -> TransactionSnapshot {
    TransactionSnapshot {
        transaction_id: TransactionId::for_namespace(&material.principal, &material.operation_id),
        principal: material.principal.clone(),
        request_id: material.operation_id.clone(),
        current_generation: material.authority_generation,
        state_version: session_id,
        state: TransactionState::Prepared,
        binding_digest: material_content_digest(material),
    }
}

fn material_content_digest(material: &ProposalAcceptanceMaterial) -> ContentDigest {
    digest_bytes(
        "linura.proposal-acceptance.material.v1",
        material.semantic_digest().to_hex().as_bytes(),
    )
}

fn time_seal_digest(seal: &AuthorityTimeSeal) -> ContentDigest {
    let floor = seal.time_floor_unix_ms.to_be_bytes();
    let deadline = seal.exclusive_deadline_unix_ms.to_be_bytes();
    let continuity = seal.continuity_generation.to_be_bytes();
    let normalization = seal.normalization_evidence_digest.to_hex();
    digest_parts(
        "linura.proposal-acceptance.time-seal.v1",
        [
            floor.as_slice(),
            deadline.as_slice(),
            continuity.as_slice(),
            normalization.as_bytes(),
        ],
    )
}

fn challenge_matches_session(challenge: &AcceptanceSigningChallenge, session_id: u64) -> bool {
    challenge.snapshot.state == TransactionState::Prepared
        && challenge.snapshot.state_version == session_id
        && challenge.snapshot.current_generation != 0
        && challenge.authority_use_digest == time_seal_digest(&challenge.time_seal)
}

fn handoff_matches_challenge(
    handoff: &HandoffRequest,
    challenge: &AcceptanceSigningChallenge,
) -> bool {
    handoff.transaction_id() == &challenge.snapshot.transaction_id
        && handoff.expected_generation() == challenge.snapshot.current_generation
        && handoff.expected_state_version() == challenge.snapshot.state_version
        && handoff.expected_binding_digest() == &challenge.snapshot.binding_digest
        && handoff.authority_use_digest() == &challenge.authority_use_digest
        && handoff.authorized_at_unix_ms() == challenge.time_seal.time_floor_unix_ms
        && handoff.expires_at_unix_ms() == challenge.time_seal.exclusive_deadline_unix_ms
}

fn require_authority_binding(
    connection: &rusqlite::Connection,
    verifier: &TransactionAuthorityVerifier,
) -> Result<(), ProposalAcceptanceError> {
    let mut statement = connection.prepare(
        "SELECT content_digest FROM lifecycle_records WHERE entity_id = ?1 ORDER BY sequence",
    )?;
    let bindings = statement
        .query_map(params![AUTHORITY_BINDING_ENTITY_ID], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    match bindings.as_slice() {
        [] => Err(ProposalAcceptanceError::AuthorityNotProvisioned),
        [stored] if stored == verifier.fingerprint().as_str() => Ok(()),
        [_] => Err(ProposalAcceptanceError::AuthorityBindingMismatch),
        _ => Err(ProposalAcceptanceError::Corrupt(
            "Library contains multiple proposal-acceptance authority bindings".into(),
        )),
    }
}

fn provision_authority_binding(
    connection: &mut rusqlite::Connection,
    verifier: &TransactionAuthorityVerifier,
) -> Result<(), ProposalAcceptanceError> {
    let fingerprint = verifier.fingerprint();
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let bindings = {
        let mut statement = transaction.prepare(
            "SELECT content_digest FROM lifecycle_records WHERE entity_id = ?1 ORDER BY sequence",
        )?;
        statement
            .query_map(params![AUTHORITY_BINDING_ENTITY_ID], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    match bindings.as_slice() {
        [] => {
            let payload = format!(
                "version=1\nkind=proposal-acceptance-authority\nfingerprint={}",
                fingerprint.as_str()
            );
            transaction.execute(
                "INSERT INTO lifecycle_records(record_kind, entity_id, content_digest, payload) VALUES ('provenance', ?1, ?2, ?3)",
                params![AUTHORITY_BINDING_ENTITY_ID, fingerprint.as_str(), payload],
            )?;
        }
        [stored] if stored == fingerprint.as_str() => {}
        [_] => return Err(ProposalAcceptanceError::AuthorityBindingMismatch),
        _ => {
            return Err(ProposalAcceptanceError::Corrupt(
                "Library contains multiple proposal-acceptance authority bindings".into(),
            ));
        }
    }
    transaction.commit()?;
    Ok(())
}

fn enforce_time_sample(
    seal: &AuthorityTimeSeal,
    sample: AuthorityTimeSample,
) -> Result<(), ProposalAcceptanceError> {
    if !sample.continuity_established || sample.continuity_generation != seal.continuity_generation
    {
        return Err(ProposalAcceptanceError::TrustedTimeContinuityLost);
    }
    if sample.unix_ms < seal.time_floor_unix_ms {
        return Err(ProposalAcceptanceError::TrustedTimeRollback);
    }
    if sample.unix_ms >= seal.exclusive_deadline_unix_ms {
        return Err(ProposalAcceptanceError::AuthorityExpired);
    }
    Ok(())
}

fn validate_target(
    transaction: &Transaction<'_>,
    material: &ProposalAcceptanceMaterial,
) -> Result<u64, ProposalAcceptanceError> {
    let current = transaction
        .query_row(
            "SELECT c.revision, r.status FROM intents_current c JOIN intent_revisions r ON r.intent_id = c.intent_id AND r.revision = c.revision WHERE c.intent_id = ?1",
            params![material.target.intent_id().as_str()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    match (&material.target, current) {
        (ProposalAcceptanceTarget::Create { .. }, None) => Ok(1),
        (ProposalAcceptanceTarget::Create { intent_id }, Some(_)) => Err(
            ProposalAcceptanceError::TargetAlreadyExists(intent_id.clone()),
        ),
        (ProposalAcceptanceTarget::ReviseProposed { intent_id, .. }, None) => {
            Err(ProposalAcceptanceError::TargetNotFound(intent_id.clone()))
        }
        (
            ProposalAcceptanceTarget::ReviseProposed {
                intent_id,
                expected_revision,
            },
            Some((actual, status)),
        ) => {
            let actual = u64::try_from(actual)
                .map_err(|_| ProposalAcceptanceError::Corrupt("invalid target revision".into()))?;
            if actual != *expected_revision {
                return Err(ProposalAcceptanceError::RevisionConflict {
                    expected: *expected_revision,
                    actual,
                });
            }
            if parse_intent_status(&status)? != IntentStatus::Proposed {
                return Err(ProposalAcceptanceError::TargetNotProposed(
                    intent_id.clone(),
                ));
            }
            actual
                .checked_add(1)
                .ok_or_else(|| ProposalAcceptanceError::Corrupt("intent revision overflow".into()))
        }
    }
}

fn reject_identity_conflicts(
    transaction: &Transaction<'_>,
    material: &ProposalAcceptanceMaterial,
    semantic_digest: &ProposalDigest,
) -> Result<(), ProposalAcceptanceError> {
    for (kind, entity_id) in [
        (
            "proposal",
            format!("{PROPOSAL_INDEX_PREFIX}{}", material.proposal_id.as_str()),
        ),
        (
            "acceptance decision",
            format!("{DECISION_INDEX_PREFIX}{}", material.decision_id.as_str()),
        ),
    ] {
        let existing = transaction
            .query_row(
                "SELECT content_digest FROM lifecycle_records WHERE entity_id = ?1 ORDER BY sequence DESC LIMIT 1",
                params![entity_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing) = existing
            && existing != semantic_digest.to_hex()
        {
            return Err(ProposalAcceptanceError::IdentityConflict {
                kind,
                id: entity_id,
            });
        }
    }
    Ok(())
}

fn replay_committed(
    connection: &rusqlite::Connection,
    material: &ProposalAcceptanceMaterial,
) -> Result<Option<ProposalAcceptanceRecord>, ProposalAcceptanceError> {
    let semantic_digest = material.semantic_digest().to_hex();
    let operation = connection
        .query_row(
            "SELECT semantic_digest, result_kind, result_id, result_revision FROM library_operations WHERE operation_id = ?1",
            params![material.operation_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((stored_digest, result_kind, result_id, result_revision)) = operation else {
        return Ok(None);
    };
    if stored_digest != semantic_digest || result_kind != ACCEPTANCE_RESULT_KIND {
        return Err(ProposalAcceptanceError::IdentityConflict {
            kind: "operation",
            id: material.operation_id.as_str().into(),
        });
    }
    let payload = connection
        .query_row(
            "SELECT payload FROM lifecycle_records WHERE entity_id = ?1 AND content_digest = ?2 ORDER BY sequence DESC LIMIT 1",
            params![format!("{ACCEPTANCE_RECORD_PREFIX}{}", material.operation_id.as_str()), semantic_digest],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| ProposalAcceptanceError::Corrupt(
            "operation exists without durable v0.8 acceptance record".into(),
        ))?;
    let result_id = IntentId::new(result_id)
        .map_err(|error| ProposalAcceptanceError::Corrupt(error.to_string()))?;
    let result_revision = u64::try_from(result_revision)
        .map_err(|_| ProposalAcceptanceError::Corrupt("invalid durable result revision".into()))?;
    let time_seal = AuthorityTimeSeal {
        time_floor_unix_ms: parse_u64_field(&payload, "time_floor_unix_ms")?,
        exclusive_deadline_unix_ms: parse_u64_field(&payload, "exclusive_deadline_unix_ms")?,
        continuity_generation: parse_u64_field(&payload, "continuity_generation")?,
        normalization_evidence_digest: parse_digest_field(
            &payload,
            "normalization_evidence_digest",
        )?,
    };
    time_seal.validate()?;
    Ok(Some(ProposalAcceptanceRecord {
        material: material.clone(),
        time_seal,
        resulting_intent_id: result_id,
        resulting_revision: result_revision,
        linearized_at_unix_ms: parse_u64_field(&payload, "linearized_at_unix_ms")?,
    }))
}

fn persist_acceptance_record(
    transaction: &Transaction<'_>,
    record: &ProposalAcceptanceRecord,
    semantic_digest: &ProposalDigest,
) -> Result<(), ProposalAcceptanceError> {
    let revision = revision_sql(record.resulting_revision)?;
    transaction.execute(
        "INSERT INTO library_operations(operation_id, semantic_digest, result_kind, result_id, result_revision) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            record.material.operation_id.as_str(),
            semantic_digest.to_hex(),
            ACCEPTANCE_RESULT_KIND,
            record.resulting_intent_id.as_str(),
            revision,
        ],
    )?;
    let payload = record_payload(record);
    if payload.len() > MAX_RECORD_PAYLOAD_BYTES {
        return Err(ProposalAcceptanceError::BindingMismatch(
            "durable acceptance record exceeds bounded payload size".into(),
        ));
    }
    for entity_id in [
        format!(
            "{ACCEPTANCE_RECORD_PREFIX}{}",
            record.material.operation_id.as_str()
        ),
        format!(
            "{PROPOSAL_INDEX_PREFIX}{}",
            record.material.proposal_id.as_str()
        ),
        format!(
            "{DECISION_INDEX_PREFIX}{}",
            record.material.decision_id.as_str()
        ),
    ] {
        transaction.execute(
            "INSERT INTO lifecycle_records(record_kind, entity_id, content_digest, payload) VALUES ('provenance', ?1, ?2, ?3)",
            params![entity_id, semantic_digest.to_hex(), payload],
        )?;
    }
    Ok(())
}

fn record_payload(record: &ProposalAcceptanceRecord) -> String {
    let material = &record.material;
    let expected_revision = material
        .target
        .expected_revision()
        .map_or_else(|| "none".to_string(), |value| value.to_string());
    [
        "version=1".to_string(),
        format!("principal={}", material.principal.as_str()),
        format!("decision_id={}", material.decision_id.as_str()),
        format!(
            "decision_binding_digest={}",
            material.decision_binding_digest
        ),
        format!("proposal_id={}", material.proposal_id.as_str()),
        format!("proposal_digest={}", material.proposal_digest),
        format!(
            "accepted_context_digest={}",
            material.accepted_context_digest
        ),
        format!("operation_id={}", material.operation_id.as_str()),
        format!("action={}", material.target.action().as_str()),
        format!("target_intent_id={}", material.target.intent_id().as_str()),
        format!("expected_revision={expected_revision}"),
        format!("authority_generation={}", material.authority_generation),
        format!(
            "authority_evidence_digest={}",
            material.authority_evidence_digest
        ),
        format!(
            "decision_validity_digest={}",
            material.decision_validity_digest
        ),
        format!(
            "resulting_intent_digest={}",
            material.resulting_intent_digest
        ),
        format!(
            "time_floor_unix_ms={}",
            record.time_seal.time_floor_unix_ms
        ),
        format!(
            "exclusive_deadline_unix_ms={}",
            record.time_seal.exclusive_deadline_unix_ms
        ),
        format!(
            "continuity_generation={}",
            record.time_seal.continuity_generation
        ),
        format!(
            "normalization_evidence_digest={}",
            record.time_seal.normalization_evidence_digest
        ),
        format!(
            "resulting_intent_id={}",
            record.resulting_intent_id.as_str()
        ),
        format!("resulting_revision={}", record.resulting_revision),
        format!("linearized_at_unix_ms={}", record.linearized_at_unix_ms),
    ]
    .join("\n")
}

fn parse_u64_field(payload: &str, field: &'static str) -> Result<u64, ProposalAcceptanceError> {
    field_value(payload, field)?.parse::<u64>().map_err(|_| {
        ProposalAcceptanceError::Corrupt(format!("invalid {field} in durable acceptance record"))
    })
}

fn parse_digest_field(
    payload: &str,
    field: &'static str,
) -> Result<ProposalDigest, ProposalAcceptanceError> {
    ProposalDigest::parse_hex(field_value(payload, field)?)
        .map_err(|error| ProposalAcceptanceError::Corrupt(error.to_string()))
}

fn field_value<'a>(
    payload: &'a str,
    field: &'static str,
) -> Result<&'a str, ProposalAcceptanceError> {
    let prefix = format!("{field}=");
    payload
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or_else(|| {
            ProposalAcceptanceError::Corrupt(format!(
                "missing {field} in durable acceptance record"
            ))
        })
}

fn insert_intent_revision(
    transaction: &Transaction<'_>,
    intent: &Intent,
    revision: u64,
) -> Result<(), ProposalAcceptanceError> {
    let revision = revision_sql(revision)?;
    transaction.execute(
        "INSERT INTO intent_revisions(intent_id, revision, actor_id, actor_kind, actor_interactive, statement, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'proposed')",
        params![
            intent.id.as_str(),
            revision,
            intent.actor.id.as_str(),
            actor_kind(intent.actor.kind),
            i64::from(intent.actor.interactive),
            intent.statement,
        ],
    )?;
    for requirement in &intent.requirements {
        transaction.execute(
            "INSERT INTO intent_requirements(intent_id, intent_revision, requirement_id, kind, statement) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                intent.id.as_str(),
                revision,
                requirement.id.as_str(),
                requirement_kind(requirement.kind),
                requirement.statement,
            ],
        )?;
    }
    for superseded in &intent.supersedes {
        transaction.execute(
            "INSERT INTO intent_supersedes(intent_id, intent_revision, superseded_intent_id) VALUES (?1, ?2, ?3)",
            params![intent.id.as_str(), revision, superseded.as_str()],
        )?;
    }
    Ok(())
}

fn validate_proposed_intent(intent: &Intent) -> Result<(), ProposalAcceptanceError> {
    if intent.status != IntentStatus::Proposed {
        return Err(ProposalAcceptanceError::BindingMismatch(
            "accepted proposal may create only Proposed intent".into(),
        ));
    }
    if intent.statement.trim().is_empty() || intent.statement.len() > MAX_RECORD_PAYLOAD_BYTES {
        return Err(ProposalAcceptanceError::BindingMismatch(
            "resulting intent statement is empty or oversized".into(),
        ));
    }
    let mut requirement_ids = BTreeSet::new();
    for requirement in &intent.requirements {
        if requirement.statement.trim().is_empty()
            || requirement.statement.len() > MAX_RECORD_PAYLOAD_BYTES
            || !requirement_ids.insert(requirement.id.as_str())
        {
            return Err(ProposalAcceptanceError::BindingMismatch(
                "resulting intent contains invalid or duplicate requirements".into(),
            ));
        }
    }
    let mut supersedes = BTreeSet::new();
    for id in &intent.supersedes {
        if id == &intent.id || !supersedes.insert(id.as_str()) {
            return Err(ProposalAcceptanceError::BindingMismatch(
                "resulting intent contains invalid or duplicate supersedes references".into(),
            ));
        }
    }
    Ok(())
}

pub fn digest_intent(intent: &Intent) -> ProposalDigest {
    let mut owned = vec![
        intent.id.as_str().as_bytes().to_vec(),
        intent.actor.id.as_str().as_bytes().to_vec(),
        actor_kind(intent.actor.kind).as_bytes().to_vec(),
        if intent.actor.interactive {
            b"1".to_vec()
        } else {
            b"0".to_vec()
        },
        intent.statement.as_bytes().to_vec(),
        b"proposed".to_vec(),
    ];
    for requirement in &intent.requirements {
        owned.push(requirement.id.as_str().as_bytes().to_vec());
        owned.push(requirement_kind(requirement.kind).as_bytes().to_vec());
        owned.push(requirement.statement.as_bytes().to_vec());
    }
    for superseded in &intent.supersedes {
        owned.push(superseded.as_str().as_bytes().to_vec());
    }
    let refs = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
    ProposalDigest::hash_parts(b"linura:accepted-intent:v1", &refs)
}

fn actor_kind(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::Human => "human",
        ActorKind::Service => "service",
        ActorKind::Agent => "agent",
        ActorKind::Remote => "remote",
    }
}

fn requirement_kind(kind: RequirementKind) -> &'static str {
    match kind {
        RequirementKind::Goal => "goal",
        RequirementKind::Constraint => "constraint",
        RequirementKind::Preference => "preference",
        RequirementKind::Prohibition => "prohibition",
    }
}

fn parse_intent_status(value: &str) -> Result<IntentStatus, ProposalAcceptanceError> {
    match value {
        "proposed" => Ok(IntentStatus::Proposed),
        "active" => Ok(IntentStatus::Active),
        "suspended" => Ok(IntentStatus::Suspended),
        "superseded" => Ok(IntentStatus::Superseded),
        "retired" => Ok(IntentStatus::Retired),
        other => Err(ProposalAcceptanceError::Corrupt(format!(
            "unknown durable intent status {other}"
        ))),
    }
}

fn revision_sql(revision: u64) -> Result<i64, ProposalAcceptanceError> {
    i64::try_from(revision).map_err(|_| {
        ProposalAcceptanceError::BindingMismatch("intent revision exceeds SQLite range".into())
    })
}

fn next_nonzero(counter: &AtomicU64) -> u64 {
    loop {
        let value = counter.fetch_add(1, Ordering::Relaxed);
        if value != 0 {
            return value;
        }
    }
}
