use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

use linura_core::{Actor, CapabilityId, IntentId, PrincipalId, RequestId};
use linura_intent::{IntentProposal, InterpretationContextBinding, ProposalDigest};
use linura_library::{
    AcceptanceLinearizationClock, AuthorityTimeSample, AuthorityTimeSeal, LocalLibrary,
    ProposalAcceptanceAuthority, ProposalAcceptanceError as LibraryAcceptanceError,
    ProposalAcceptanceMaterial, ProposalAcceptanceRecord, ProposalAcceptanceReplayKey,
    ProposalAcceptanceTarget,
};
use linura_transaction::{TransactionAuthorityKey, TransactionAuthoritySigner};

use crate::AuthenticatedPrincipal;

const MAX_AUTHORITY_VALIDITY_CONTRIBUTORS: usize = 512;
const MAX_AUTHORITY_CONTRIBUTOR_ID_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityValidityPredicate {
    /// Authority is valid at `endpoint`; the normalized deadline is the first
    /// representable trusted-Control millisecond after it.
    InclusiveThrough,
    /// Authority is invalid for `now >= endpoint`; `endpoint` is already the
    /// exclusive first-invalid instant.
    InvalidAtOrAfter,
    /// Explicit fail-closed representation for a source whose endpoint
    /// semantics cannot be established.
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityClockUnit {
    UnixMilliseconds,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityValidityContributor {
    pub id: String,
    pub predicate: AuthorityValidityPredicate,
    pub clock_unit: AuthorityClockUnit,
    pub endpoint: u64,
    pub evidence_digest: ProposalDigest,
}

impl AuthorityValidityContributor {
    pub fn inclusive_unix_ms(
        id: impl Into<String>,
        valid_through_unix_ms: u64,
        evidence_digest: ProposalDigest,
    ) -> Self {
        Self {
            id: id.into(),
            predicate: AuthorityValidityPredicate::InclusiveThrough,
            clock_unit: AuthorityClockUnit::UnixMilliseconds,
            endpoint: valid_through_unix_ms,
            evidence_digest,
        }
    }

    pub fn exclusive_unix_ms(
        id: impl Into<String>,
        first_invalid_unix_ms: u64,
        evidence_digest: ProposalDigest,
    ) -> Self {
        Self {
            id: id.into(),
            predicate: AuthorityValidityPredicate::InvalidAtOrAfter,
            clock_unit: AuthorityClockUnit::UnixMilliseconds,
            endpoint: first_invalid_unix_ms,
            evidence_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptanceAuthoritySnapshot {
    pub context: InterpretationContextBinding,
    pub authority_generation: u64,
    pub actor_principal_authorized: bool,
    pub supported_capabilities: BTreeSet<CapabilityId>,
    pub time_validities: Vec<AuthorityValidityContributor>,
    pub evidence_digest: ProposalDigest,
}

impl AcceptanceAuthoritySnapshot {
    pub fn new(
        context: InterpretationContextBinding,
        authority_generation: u64,
        actor_principal_authorized: bool,
        supported_capabilities: BTreeSet<CapabilityId>,
        mut time_validities: Vec<AuthorityValidityContributor>,
    ) -> Result<Self, ProposalAcceptanceControlError> {
        if authority_generation == 0 {
            return Err(ProposalAcceptanceControlError::InvalidAuthoritySnapshot(
                "authority generation must be non-zero".into(),
            ));
        }
        if time_validities.len() > MAX_AUTHORITY_VALIDITY_CONTRIBUTORS {
            return Err(ProposalAcceptanceControlError::InvalidAuthoritySnapshot(
                "too many time-limited authority contributors".into(),
            ));
        }
        for contributor in &time_validities {
            if contributor.id.trim().is_empty()
                || contributor.id.len() > MAX_AUTHORITY_CONTRIBUTOR_ID_BYTES
                || contributor.id.chars().any(char::is_control)
            {
                return Err(ProposalAcceptanceControlError::InvalidAuthoritySnapshot(
                    "authority validity contributor has invalid identity".into(),
                ));
            }
        }
        time_validities.sort_by(|left, right| left.id.cmp(&right.id));
        if time_validities
            .windows(2)
            .any(|pair| pair[0].id == pair[1].id)
        {
            return Err(ProposalAcceptanceControlError::InvalidAuthoritySnapshot(
                "duplicate time-limited authority contributor".into(),
            ));
        }
        let evidence_digest = snapshot_evidence_digest(
            &context,
            authority_generation,
            actor_principal_authorized,
            &supported_capabilities,
            &time_validities,
        );
        Ok(Self {
            context,
            authority_generation,
            actor_principal_authorized,
            supported_capabilities,
            time_validities,
            evidence_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalAcceptanceDecision {
    pub decision_id: RequestId,
    pub principal: PrincipalId,
    pub proposal_id: RequestId,
    pub proposal_digest: ProposalDigest,
    pub context_digest: ProposalDigest,
    pub operation_id: RequestId,
    pub target: ProposalAcceptanceTarget,
    pub expires_at_unix_ms: u64,
    pub authorization_generation: u64,
    pub validity_evidence_digest: ProposalDigest,
    pub binding_digest: ProposalDigest,
}

impl ProposalAcceptanceDecision {
    #[allow(clippy::too_many_arguments)]
    pub fn exact_bound(
        decision_id: RequestId,
        principal: PrincipalId,
        proposal_id: RequestId,
        proposal_digest: ProposalDigest,
        context_digest: ProposalDigest,
        operation_id: RequestId,
        target: ProposalAcceptanceTarget,
        expires_at_unix_ms: u64,
        authorization_generation: u64,
        validity_evidence_digest: ProposalDigest,
    ) -> Result<Self, ProposalAcceptanceControlError> {
        if expires_at_unix_ms == 0 || authorization_generation == 0 {
            return Err(ProposalAcceptanceControlError::InvalidDecision(
                "decision expiry and authorization generation must be non-zero".into(),
            ));
        }
        let binding_digest = decision_binding_digest(
            &decision_id,
            &principal,
            &proposal_id,
            proposal_digest,
            context_digest,
            &operation_id,
            &target,
            expires_at_unix_ms,
            authorization_generation,
            validity_evidence_digest,
        );
        Ok(Self {
            decision_id,
            principal,
            proposal_id,
            proposal_digest,
            context_digest,
            operation_id,
            target,
            expires_at_unix_ms,
            authorization_generation,
            validity_evidence_digest,
            binding_digest,
        })
    }

    fn validate_exact(
        &self,
        principal: &PrincipalId,
        proposal: &IntentProposal,
        operation_id: &RequestId,
        target: &ProposalAcceptanceTarget,
    ) -> Result<(), ProposalAcceptanceControlError> {
        let expected = decision_binding_digest(
            &self.decision_id,
            &self.principal,
            &self.proposal_id,
            self.proposal_digest,
            self.context_digest,
            &self.operation_id,
            &self.target,
            self.expires_at_unix_ms,
            self.authorization_generation,
            self.validity_evidence_digest,
        );
        if self.binding_digest != expected
            || &self.principal != principal
            || self.proposal_id != proposal.proposal_id
            || self.proposal_digest != proposal.canonical_digest
            || self.context_digest != proposal.context.digest()
            || &self.operation_id != operation_id
            || &self.target != target
        {
            return Err(ProposalAcceptanceControlError::DecisionBindingMismatch);
        }
        Ok(())
    }
}

/// A trusted authority guard holds the Control serialization/CAS boundary for
/// policy, capability-registry, observation, context and decision state until
/// the durable Library commit attempt is complete.
pub trait ProposalAcceptanceAuthorityGuard {
    fn snapshot_at(
        &mut self,
        principal: &AuthenticatedPrincipal,
        actor: &Actor,
        proposal: &IntentProposal,
        now_unix_ms: u64,
    ) -> Result<AcceptanceAuthoritySnapshot, ProposalAcceptanceControlError>;

    fn decision(
        &mut self,
        decision_id: &RequestId,
    ) -> Result<ProposalAcceptanceDecision, ProposalAcceptanceControlError>;
}

pub trait ProposalAcceptanceAuthoritySource {
    fn acquire_guard(
        &mut self,
    ) -> Result<Box<dyn ProposalAcceptanceAuthorityGuard + '_>, ProposalAcceptanceControlError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptProposalRequest {
    pub operation_id: RequestId,
    pub decision_id: RequestId,
    pub target: ProposalAcceptanceTarget,
    pub supersedes: Vec<IntentId>,
}

/// Internal acceptance engine. Control owns the signing half of the durable
/// mutation authority; Library receives only its verifier and signed handoffs.
#[derive(Debug)]
pub(crate) struct ProposalAcceptanceControl {
    signer: TransactionAuthoritySigner,
    library_authority: ProposalAcceptanceAuthority,
}

impl ProposalAcceptanceControl {
    #[must_use]
    pub(crate) fn from_authority_key(key: TransactionAuthorityKey) -> Self {
        let (signer, verifier) = key.split();
        Self {
            signer,
            library_authority: ProposalAcceptanceAuthority::from_verifier(verifier),
        }
    }

    pub(crate) fn provision_library(
        &self,
        library: &mut LocalLibrary,
    ) -> Result<(), ProposalAcceptanceControlError> {
        self.library_authority
            .provision(library)
            .map_err(ProposalAcceptanceControlError::Library)
    }

    pub(crate) fn accept<
        C: AcceptanceLinearizationClock,
        S: ProposalAcceptanceAuthoritySource,
    >(
        &self,
        library: &mut LocalLibrary,
        principal: &AuthenticatedPrincipal,
        proposal: &IntentProposal,
        request: &AcceptProposalRequest,
        authority_source: &mut S,
        clock: &mut C,
    ) -> Result<ProposalAcceptanceRecord, ProposalAcceptanceControlError> {
        proposal
            .validate()
            .map_err(|error| ProposalAcceptanceControlError::InvalidProposal(error.to_string()))?;
        let principal_id = PrincipalId::new(principal.as_str())
            .map_err(|error| ProposalAcceptanceControlError::InvalidPrincipal(error.to_string()))?;
        if request.target.intent_id().as_str().is_empty() {
            return Err(ProposalAcceptanceControlError::InvalidTarget);
        }
        let resulting_intent = proposal
            .to_proposed_intent(
                request.target.intent_id().clone(),
                request.supersedes.clone(),
            )
            .map_err(|error| ProposalAcceptanceControlError::InvalidProposal(error.to_string()))?;

        // Lost-response/restart idempotency is resolved before fresh authority
        // is consulted. A completed exact transaction remains replayable even if
        // the original observation/approval has since expired or policy changed.
        let replay_key = ProposalAcceptanceReplayKey {
            principal: principal_id.clone(),
            proposal_id: proposal.proposal_id.clone(),
            proposal_digest: proposal.canonical_digest,
            decision_id: request.decision_id.clone(),
            operation_id: request.operation_id.clone(),
            target: request.target.clone(),
            resulting_intent_digest: linura_library::digest_intent(&resulting_intent),
        };
        if let Some(record) = self
            .library_authority
            .replay_request(library, &replay_key)
            .map_err(ProposalAcceptanceControlError::Library)?
        {
            return Ok(record);
        }

        // Global lock order: durable Library write/CAS guard first, then the
        // serialized Control authority guard. Both remain held through commit.
        let session = self
            .library_authority
            .begin(library)
            .map_err(ProposalAcceptanceControlError::Library)?;
        let mut authority_guard = authority_source.acquire_guard()?;

        let initial_time = clock
            .sample()
            .ok_or(ProposalAcceptanceControlError::TrustedTimeUnavailable)?;
        validate_time_sample_baseline(initial_time)?;
        let _initial_snapshot = authority_guard.snapshot_at(
            principal,
            &proposal.actor,
            proposal,
            initial_time.unix_ms,
        )?;
        let _initial_decision = authority_guard.decision(&request.decision_id)?;

        let final_time = clock
            .sample()
            .ok_or(ProposalAcceptanceControlError::TrustedTimeUnavailable)?;
        if !final_time.continuity_established
            || final_time.continuity_generation != initial_time.continuity_generation
        {
            return Err(ProposalAcceptanceControlError::TrustedTimeContinuityLost);
        }
        if final_time.unix_ms < initial_time.unix_ms {
            return Err(ProposalAcceptanceControlError::TrustedTimeRollback);
        }
        let snapshot = authority_guard.snapshot_at(
            principal,
            &proposal.actor,
            proposal,
            final_time.unix_ms,
        )?;
        let decision = authority_guard.decision(&request.decision_id)?;

        validate_snapshot(&snapshot, proposal, final_time.unix_ms)?;
        decision.validate_exact(
            &principal_id,
            proposal,
            &request.operation_id,
            &request.target,
        )?;
        if decision.decision_id != request.decision_id {
            return Err(ProposalAcceptanceControlError::DecisionBindingMismatch);
        }
        if final_time.unix_ms >= decision.expires_at_unix_ms {
            return Err(ProposalAcceptanceControlError::DecisionExpired);
        }
        validate_target_under_library_guard(&session, &request.target)?;

        let mut contributors = snapshot.time_validities.clone();
        contributors.push(AuthorityValidityContributor::exclusive_unix_ms(
            format!("decision:{}", decision.decision_id.as_str()),
            decision.expires_at_unix_ms,
            decision.validity_evidence_digest,
        ));
        let normalized = normalize_authority_deadline(&contributors)?;
        if final_time.unix_ms >= normalized.exclusive_deadline_unix_ms {
            return Err(ProposalAcceptanceControlError::AuthorityExpired);
        }
        let time_seal = AuthorityTimeSeal {
            time_floor_unix_ms: final_time.unix_ms,
            exclusive_deadline_unix_ms: normalized.exclusive_deadline_unix_ms,
            continuity_generation: final_time.continuity_generation,
            normalization_evidence_digest: normalized.evidence_digest,
        };
        let material = ProposalAcceptanceMaterial::new(
            principal_id,
            decision.decision_id.clone(),
            decision.binding_digest,
            proposal.proposal_id.clone(),
            proposal.canonical_digest,
            proposal.context.digest(),
            request.operation_id.clone(),
            request.target.clone(),
            snapshot.authority_generation,
            snapshot.evidence_digest,
            decision_validity_digest(&decision),
            &resulting_intent,
        )
        .map_err(ProposalAcceptanceControlError::Library)?;

        // Library creates only an exact non-authoritative challenge. The signer
        // remains in Control and seals it only after all final checks above.
        let challenge = session
            .signing_challenge(&material, time_seal)
            .map_err(ProposalAcceptanceControlError::Library)?;
        let handoff = self
            .signer
            .authorize_handoff(
                challenge.snapshot(),
                challenge.authority_use_digest().clone(),
                challenge.authorized_at_unix_ms(),
                challenge.expires_at_unix_ms(),
            )
            .map_err(|error| ProposalAcceptanceControlError::AuthoritySeal(error.to_string()))?;
        let permit = session
            .bind_signed_handoff(&self.library_authority, challenge, handoff)
            .map_err(ProposalAcceptanceControlError::Library)?;
        let result = session
            .commit(
                &self.library_authority,
                permit,
                &material,
                &resulting_intent,
                clock,
            )
            .map_err(ProposalAcceptanceControlError::Library);

        drop(authority_guard);
        result
    }
}

fn validate_time_sample_baseline(
    sample: AuthorityTimeSample,
) -> Result<(), ProposalAcceptanceControlError> {
    if !sample.continuity_established || sample.continuity_generation == 0 {
        return Err(ProposalAcceptanceControlError::TrustedTimeContinuityLost);
    }
    Ok(())
}

fn validate_snapshot(
    snapshot: &AcceptanceAuthoritySnapshot,
    proposal: &IntentProposal,
    now_unix_ms: u64,
) -> Result<(), ProposalAcceptanceControlError> {
    if !snapshot.actor_principal_authorized {
        return Err(ProposalAcceptanceControlError::ActorPrincipalUnauthorized);
    }
    if snapshot.context != proposal.context {
        return Err(ProposalAcceptanceControlError::StaleContext);
    }
    if snapshot.authority_generation == 0 {
        return Err(ProposalAcceptanceControlError::InvalidAuthoritySnapshot(
            "zero authority generation".into(),
        ));
    }
    if proposal
        .capability_refs
        .iter()
        .any(|capability| !snapshot.supported_capabilities.contains(capability))
    {
        return Err(ProposalAcceptanceControlError::UnsupportedCapability);
    }
    for contributor in &snapshot.time_validities {
        match (contributor.clock_unit, contributor.predicate) {
            (
                AuthorityClockUnit::UnixMilliseconds,
                AuthorityValidityPredicate::InclusiveThrough,
            ) => {
                if now_unix_ms > contributor.endpoint {
                    return Err(ProposalAcceptanceControlError::AuthorityExpired);
                }
            }
            (
                AuthorityClockUnit::UnixMilliseconds,
                AuthorityValidityPredicate::InvalidAtOrAfter,
            ) => {
                if now_unix_ms >= contributor.endpoint {
                    return Err(ProposalAcceptanceControlError::AuthorityExpired);
                }
            }
            _ => {
                return Err(
                    ProposalAcceptanceControlError::UnknownAuthorityTimeSemantics(
                        contributor.id.clone(),
                    ),
                );
            }
        }
    }
    let expected = snapshot_evidence_digest(
        &snapshot.context,
        snapshot.authority_generation,
        snapshot.actor_principal_authorized,
        &snapshot.supported_capabilities,
        &snapshot.time_validities,
    );
    if expected != snapshot.evidence_digest {
        return Err(ProposalAcceptanceControlError::InvalidAuthoritySnapshot(
            "authority snapshot evidence digest mismatch".into(),
        ));
    }
    Ok(())
}

fn validate_target_under_library_guard(
    session: &linura_library::ProposalAcceptanceTransaction<'_>,
    target: &ProposalAcceptanceTarget,
) -> Result<(), ProposalAcceptanceControlError> {
    let current = session
        .current_target(target.intent_id())
        .map_err(ProposalAcceptanceControlError::Library)?;
    match (target, current) {
        (ProposalAcceptanceTarget::Create { .. }, None) => Ok(()),
        (ProposalAcceptanceTarget::Create { .. }, Some(_)) => {
            Err(ProposalAcceptanceControlError::InvalidTarget)
        }
        (
            ProposalAcceptanceTarget::ReviseProposed {
                expected_revision, ..
            },
            Some((actual, linura_intent::IntentStatus::Proposed)),
        ) if actual == *expected_revision => Ok(()),
        (ProposalAcceptanceTarget::ReviseProposed { .. }, _) => {
            Err(ProposalAcceptanceControlError::InvalidTarget)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NormalizedAuthorityDeadline {
    exclusive_deadline_unix_ms: u64,
    evidence_digest: ProposalDigest,
}

fn normalize_authority_deadline(
    contributors: &[AuthorityValidityContributor],
) -> Result<NormalizedAuthorityDeadline, ProposalAcceptanceControlError> {
    if contributors.is_empty() || contributors.len() > MAX_AUTHORITY_VALIDITY_CONTRIBUTORS + 1 {
        return Err(ProposalAcceptanceControlError::InvalidAuthoritySnapshot(
            "authority deadline contributor set is empty or oversized".into(),
        ));
    }
    let mut normalized = Vec::with_capacity(contributors.len());
    for contributor in contributors {
        if contributor.clock_unit != AuthorityClockUnit::UnixMilliseconds {
            return Err(
                ProposalAcceptanceControlError::UnknownAuthorityTimeSemantics(
                    contributor.id.clone(),
                ),
            );
        }
        let first_invalid = match contributor.predicate {
            AuthorityValidityPredicate::InclusiveThrough => {
                contributor.endpoint.checked_add(1).ok_or_else(|| {
                    ProposalAcceptanceControlError::AuthorityTimeNormalizationOverflow(
                        contributor.id.clone(),
                    )
                })?
            }
            AuthorityValidityPredicate::InvalidAtOrAfter => contributor.endpoint,
            AuthorityValidityPredicate::Unknown => {
                return Err(
                    ProposalAcceptanceControlError::UnknownAuthorityTimeSemantics(
                        contributor.id.clone(),
                    ),
                );
            }
        };
        if first_invalid == 0 {
            return Err(ProposalAcceptanceControlError::AuthorityExpired);
        }
        normalized.push((contributor, first_invalid));
    }
    normalized.sort_by(|left, right| left.0.id.cmp(&right.0.id));
    let exclusive_deadline_unix_ms = normalized
        .iter()
        .map(|(_, deadline)| *deadline)
        .min()
        .ok_or_else(|| {
            ProposalAcceptanceControlError::InvalidAuthoritySnapshot(
                "no normalized authority deadline".into(),
            )
        })?;
    let mut owned = Vec::new();
    for (contributor, deadline) in &normalized {
        owned.push(contributor.id.as_bytes().to_vec());
        owned.push(match contributor.predicate {
            AuthorityValidityPredicate::InclusiveThrough => b"inclusive-through".to_vec(),
            AuthorityValidityPredicate::InvalidAtOrAfter => b"invalid-at-or-after".to_vec(),
            AuthorityValidityPredicate::Unknown => b"unknown".to_vec(),
        });
        owned.push(contributor.endpoint.to_be_bytes().to_vec());
        owned.push(deadline.to_be_bytes().to_vec());
        owned.push(contributor.evidence_digest.to_hex().into_bytes());
    }
    let refs = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
    Ok(NormalizedAuthorityDeadline {
        exclusive_deadline_unix_ms,
        evidence_digest: ProposalDigest::hash_parts(
            b"linura:authority-validity-normalization:v1",
            &refs,
        ),
    })
}

fn snapshot_evidence_digest(
    context: &InterpretationContextBinding,
    authority_generation: u64,
    actor_principal_authorized: bool,
    supported_capabilities: &BTreeSet<CapabilityId>,
    time_validities: &[AuthorityValidityContributor],
) -> ProposalDigest {
    let mut owned = vec![
        context.digest().to_hex().into_bytes(),
        authority_generation.to_be_bytes().to_vec(),
        if actor_principal_authorized {
            b"actor-authorized".to_vec()
        } else {
            b"actor-denied".to_vec()
        },
    ];
    for capability in supported_capabilities {
        owned.push(capability.as_str().as_bytes().to_vec());
    }
    for contributor in time_validities {
        owned.push(contributor.id.as_bytes().to_vec());
        owned.push(match contributor.predicate {
            AuthorityValidityPredicate::InclusiveThrough => b"inclusive-through".to_vec(),
            AuthorityValidityPredicate::InvalidAtOrAfter => b"invalid-at-or-after".to_vec(),
            AuthorityValidityPredicate::Unknown => b"unknown".to_vec(),
        });
        owned.push(match contributor.clock_unit {
            AuthorityClockUnit::UnixMilliseconds => b"unix-ms".to_vec(),
            AuthorityClockUnit::Unknown => b"unknown-unit".to_vec(),
        });
        owned.push(contributor.endpoint.to_be_bytes().to_vec());
        owned.push(contributor.evidence_digest.to_hex().into_bytes());
    }
    let refs = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
    ProposalDigest::hash_parts(b"linura:acceptance-authority-snapshot:v1", &refs)
}

#[allow(clippy::too_many_arguments)]
fn decision_binding_digest(
    decision_id: &RequestId,
    principal: &PrincipalId,
    proposal_id: &RequestId,
    proposal_digest: ProposalDigest,
    context_digest: ProposalDigest,
    operation_id: &RequestId,
    target: &ProposalAcceptanceTarget,
    expires_at_unix_ms: u64,
    authorization_generation: u64,
    validity_evidence_digest: ProposalDigest,
) -> ProposalDigest {
    let expected_revision = target
        .expected_revision()
        .map_or_else(|| "none".to_string(), |value| value.to_string());
    let owned = [
        decision_id.as_str().as_bytes().to_vec(),
        principal.as_str().as_bytes().to_vec(),
        proposal_id.as_str().as_bytes().to_vec(),
        proposal_digest.to_hex().into_bytes(),
        context_digest.to_hex().into_bytes(),
        operation_id.as_str().as_bytes().to_vec(),
        target.action().as_str().as_bytes().to_vec(),
        target.intent_id().as_str().as_bytes().to_vec(),
        expected_revision.into_bytes(),
        expires_at_unix_ms.to_be_bytes().to_vec(),
        authorization_generation.to_be_bytes().to_vec(),
        validity_evidence_digest.to_hex().into_bytes(),
    ];
    let refs = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
    ProposalDigest::hash_parts(b"linura:proposal-acceptance-decision:v1", &refs)
}

fn decision_validity_digest(decision: &ProposalAcceptanceDecision) -> ProposalDigest {
    ProposalDigest::hash_parts(
        b"linura:proposal-acceptance-decision-validity:v1",
        &[
            decision.decision_id.as_str().as_bytes(),
            decision.binding_digest.to_hex().as_bytes(),
            decision.expires_at_unix_ms.to_string().as_bytes(),
            decision.authorization_generation.to_string().as_bytes(),
            decision.validity_evidence_digest.to_hex().as_bytes(),
        ],
    )
}

#[derive(Debug)]
pub enum ProposalAcceptanceControlError {
    InvalidProposal(String),
    InvalidPrincipal(String),
    InvalidTarget,
    InvalidAuthoritySnapshot(String),
    InvalidDecision(String),
    AuthoritySource(String),
    AuthoritySeal(String),
    ActorPrincipalUnauthorized,
    StaleContext,
    UnsupportedCapability,
    DecisionBindingMismatch,
    DecisionExpired,
    TrustedTimeUnavailable,
    TrustedTimeRollback,
    TrustedTimeContinuityLost,
    AuthorityExpired,
    UnknownAuthorityTimeSemantics(String),
    AuthorityTimeNormalizationOverflow(String),
    Library(LibraryAcceptanceError),
}

impl Display for ProposalAcceptanceControlError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProposal(reason) => write!(f, "invalid proposal acceptance input: {reason}"),
            Self::InvalidPrincipal(reason) => {
                write!(f, "invalid authenticated acceptance principal: {reason}")
            }
            Self::InvalidTarget => f.write_str(
                "proposal acceptance target is unavailable or does not match its exact revision expectation",
            ),
            Self::InvalidAuthoritySnapshot(reason) => {
                write!(f, "invalid Control authority snapshot: {reason}")
            }
            Self::InvalidDecision(reason) => {
                write!(f, "invalid proposal acceptance decision: {reason}")
            }
            Self::AuthoritySource(reason) => {
                write!(f, "proposal acceptance authority source failed: {reason}")
            }
            Self::AuthoritySeal(reason) => {
                write!(f, "failed to seal proposal acceptance authority: {reason}")
            }
            Self::ActorPrincipalUnauthorized => f.write_str(
                "proposal actor provenance is not authorized for the authenticated principal",
            ),
            Self::StaleContext => f.write_str(
                "proposal context binding is stale relative to current Control authority",
            ),
            Self::UnsupportedCapability => f.write_str(
                "proposal references a capability not supported by the current Control-owned registry",
            ),
            Self::DecisionBindingMismatch => f.write_str(
                "acceptance decision is not exact-bound to this principal/proposal/context/operation/action/target",
            ),
            Self::DecisionExpired => {
                f.write_str("acceptance decision expired before final Control revalidation")
            }
            Self::TrustedTimeUnavailable => f.write_str("trusted Control time is unavailable"),
            Self::TrustedTimeRollback => {
                f.write_str("trusted Control time rolled backward during acceptance")
            }
            Self::TrustedTimeContinuityLost => f.write_str(
                "trusted Control time reset/rebound or monotonic continuity is unknown",
            ),
            Self::AuthorityExpired => {
                f.write_str("time-limited acceptance authority is no longer valid")
            }
            Self::UnknownAuthorityTimeSemantics(id) => {
                write!(f, "authority time endpoint semantics/unit are unknown for {id}")
            }
            Self::AuthorityTimeNormalizationOverflow(id) => write!(
                f,
                "exclusive first-invalid authority deadline cannot be represented for {id}"
            ),
            Self::Library(error) => Display::fmt(error, f),
        }
    }
}

impl std::error::Error for ProposalAcceptanceControlError {}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use linura_core::{ActorId, ActorKind, ValidationError};
    use linura_intent::ProposalAttribution;

    use super::*;

    fn id<T>(value: Result<T, ValidationError>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error}"))
    }

    struct SequenceClock(VecDeque<AuthorityTimeSample>);

    impl AcceptanceLinearizationClock for SequenceClock {
        fn sample(&mut self) -> Option<AuthorityTimeSample> {
            self.0.pop_front()
        }
    }

    struct MockSource {
        snapshot: AcceptanceAuthoritySnapshot,
        decision: ProposalAcceptanceDecision,
        acquisitions: Arc<AtomicUsize>,
    }

    struct MockGuard {
        snapshot: AcceptanceAuthoritySnapshot,
        decision: ProposalAcceptanceDecision,
    }

    impl ProposalAcceptanceAuthorityGuard for MockGuard {
        fn snapshot_at(
            &mut self,
            _principal: &AuthenticatedPrincipal,
            _actor: &Actor,
            _proposal: &IntentProposal,
            _now_unix_ms: u64,
        ) -> Result<AcceptanceAuthoritySnapshot, ProposalAcceptanceControlError> {
            Ok(self.snapshot.clone())
        }

        fn decision(
            &mut self,
            _decision_id: &RequestId,
        ) -> Result<ProposalAcceptanceDecision, ProposalAcceptanceControlError> {
            Ok(self.decision.clone())
        }
    }

    impl ProposalAcceptanceAuthoritySource for MockSource {
        fn acquire_guard(
            &mut self,
        ) -> Result<Box<dyn ProposalAcceptanceAuthorityGuard + '_>, ProposalAcceptanceControlError>
        {
            self.acquisitions.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(MockGuard {
                snapshot: self.snapshot.clone(),
                decision: self.decision.clone(),
            }))
        }
    }

    fn proposal() -> IntentProposal {
        let context = InterpretationContextBinding::new(
            "authority:42",
            ProposalDigest::hash_parts(b"semantic", &[b"workstation"]),
            vec![],
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        IntentProposal::new_v1(
            id(RequestId::new("proposal:v08:accept")),
            Actor {
                id: id(ActorId::new("uid:1000")),
                kind: ActorKind::Human,
                interactive: true,
            },
            "Configure a workstation",
            vec![],
            vec![],
            vec![],
            vec![],
            None,
            context,
            ProposalAttribution::manual("manual").unwrap_or_else(|error| unreachable!("{error}")),
            vec![],
        )
        .unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn fixture(
        proposal: &IntentProposal,
        principal: &AuthenticatedPrincipal,
        request: &AcceptProposalRequest,
        valid_through: u64,
    ) -> (AcceptanceAuthoritySnapshot, ProposalAcceptanceDecision) {
        let principal_id = id(PrincipalId::new(principal.as_str()));
        let snapshot = AcceptanceAuthoritySnapshot::new(
            proposal.context.clone(),
            7,
            true,
            BTreeSet::new(),
            vec![AuthorityValidityContributor::inclusive_unix_ms(
                "observation:system",
                valid_through,
                ProposalDigest::hash_parts(b"observation", &[b"current"]),
            )],
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let decision = ProposalAcceptanceDecision::exact_bound(
            request.decision_id.clone(),
            principal_id,
            proposal.proposal_id.clone(),
            proposal.canonical_digest,
            proposal.context.digest(),
            request.operation_id.clone(),
            request.target.clone(),
            1_000,
            3,
            ProposalDigest::hash_parts(b"decision-validity", &[b"approved"]),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        (snapshot, decision)
    }

    fn samples(linearization: u64) -> SequenceClock {
        SequenceClock(VecDeque::from([
            AuthorityTimeSample {
                unix_ms: 100,
                continuity_generation: 9,
                continuity_established: true,
            },
            AuthorityTimeSample {
                unix_ms: 100,
                continuity_generation: 9,
                continuity_established: true,
            },
            AuthorityTimeSample {
                unix_ms: linearization,
                continuity_generation: 9,
                continuity_established: true,
            },
        ]))
    }

    fn control(library: &mut LocalLibrary) -> ProposalAcceptanceControl {
        let key = TransactionAuthorityKey::new(vec![0x73; 32])
            .unwrap_or_else(|error| unreachable!("{error}"));
        let control = ProposalAcceptanceControl::from_authority_key(key);
        control
            .provision_library(library)
            .unwrap_or_else(|error| unreachable!("{error}"));
        control
    }

    #[test]
    fn acceptance_binds_principal_decision_context_and_durable_result() {
        let proposal = proposal();
        let principal = AuthenticatedPrincipal::new("principal:uid:1000")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let request = AcceptProposalRequest {
            operation_id: id(RequestId::new("operation:v08:accept")),
            decision_id: id(RequestId::new("decision:v08:accept")),
            target: ProposalAcceptanceTarget::Create {
                intent_id: id(IntentId::new("intent:v08:accept")),
            },
            supersedes: vec![],
        };
        let (snapshot, decision) = fixture(&proposal, &principal, &request, 200);
        let acquisitions = Arc::new(AtomicUsize::new(0));
        let mut source = MockSource {
            snapshot,
            decision,
            acquisitions: Arc::clone(&acquisitions),
        };
        let mut library =
            LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
        let control = control(&mut library);
        let record = control
            .accept(
                &mut library,
                &principal,
                &proposal,
                &request,
                &mut source,
                &mut samples(150),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(record.resulting_revision, 1);
        assert_eq!(record.time_seal.exclusive_deadline_unix_ms, 201);
        assert_eq!(acquisitions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn exact_retry_replays_before_fresh_authority_is_consulted() {
        let proposal = proposal();
        let principal = AuthenticatedPrincipal::new("principal:uid:1000")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let request = AcceptProposalRequest {
            operation_id: id(RequestId::new("operation:v08:replay")),
            decision_id: id(RequestId::new("decision:v08:replay")),
            target: ProposalAcceptanceTarget::Create {
                intent_id: id(IntentId::new("intent:v08:replay")),
            },
            supersedes: vec![],
        };
        let (snapshot, decision) = fixture(&proposal, &principal, &request, 200);
        let acquisitions = Arc::new(AtomicUsize::new(0));
        let mut source = MockSource {
            snapshot,
            decision,
            acquisitions: Arc::clone(&acquisitions),
        };
        let mut library =
            LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
        let control = control(&mut library);
        let first = control
            .accept(
                &mut library,
                &principal,
                &proposal,
                &request,
                &mut source,
                &mut samples(150),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        let before = acquisitions.load(Ordering::SeqCst);
        let replay = control
            .accept(
                &mut library,
                &principal,
                &proposal,
                &request,
                &mut source,
                &mut SequenceClock(VecDeque::new()),
            )
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(first, replay);
        assert_eq!(acquisitions.load(Ordering::SeqCst), before);
    }

    #[test]
    fn inclusive_observation_endpoint_normalizes_to_first_invalid_instant() {
        let contributor = AuthorityValidityContributor::inclusive_unix_ms(
            "observation:test",
            200,
            ProposalDigest::hash_parts(b"observation", &[b"endpoint"]),
        );
        let normalized = normalize_authority_deadline(&[contributor])
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(normalized.exclusive_deadline_unix_ms, 201);
    }

    #[test]
    fn inclusive_endpoint_success_and_first_invalid_failure_are_distinct() {
        for (linearization, succeeds) in [(200, true), (201, false)] {
            let proposal = proposal();
            let principal = AuthenticatedPrincipal::new("principal:uid:1000")
                .unwrap_or_else(|error| unreachable!("{error}"));
            let request = AcceptProposalRequest {
                operation_id: id(RequestId::new(format!(
                    "operation:v08:boundary:{linearization}"
                ))),
                decision_id: id(RequestId::new(format!(
                    "decision:v08:boundary:{linearization}"
                ))),
                target: ProposalAcceptanceTarget::Create {
                    intent_id: id(IntentId::new(format!(
                        "intent:v08:boundary:{linearization}"
                    ))),
                },
                supersedes: vec![],
            };
            let (snapshot, decision) = fixture(&proposal, &principal, &request, 200);
            let mut source = MockSource {
                snapshot,
                decision,
                acquisitions: Arc::new(AtomicUsize::new(0)),
            };
            let mut library =
                LocalLibrary::open_in_memory().unwrap_or_else(|error| unreachable!("{error}"));
            let control = control(&mut library);
            let result = control.accept(
                &mut library,
                &principal,
                &proposal,
                &request,
                &mut source,
                &mut samples(linearization),
            );
            assert_eq!(result.is_ok(), succeeds);
        }
    }

    #[test]
    fn unknown_time_semantics_and_inclusive_successor_overflow_fail_closed() {
        let unknown = AuthorityValidityContributor {
            id: "unknown".into(),
            predicate: AuthorityValidityPredicate::Unknown,
            clock_unit: AuthorityClockUnit::Unknown,
            endpoint: 10,
            evidence_digest: ProposalDigest::hash_parts(b"unknown", &[b"time"]),
        };
        assert!(matches!(
            normalize_authority_deadline(&[unknown]),
            Err(ProposalAcceptanceControlError::UnknownAuthorityTimeSemantics(_))
        ));
        let overflow = AuthorityValidityContributor::inclusive_unix_ms(
            "overflow",
            u64::MAX,
            ProposalDigest::hash_parts(b"overflow", &[b"time"]),
        );
        assert!(matches!(
            normalize_authority_deadline(&[overflow]),
            Err(ProposalAcceptanceControlError::AuthorityTimeNormalizationOverflow(_))
        ));
    }
}
