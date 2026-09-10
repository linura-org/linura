use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

use linura_core::{Actor, ActorKind, CapabilityId, IntentId, RequestId};
use sha2::{Digest, Sha256};

use crate::{Intent, IntentStatus, Requirement};

pub const INTENT_PROPOSAL_SCHEMA_VERSION: u16 = 1;
const PROPOSAL_DIGEST_DOMAIN: &[u8] = b"linura:intent-proposal:v1";
const MAX_TOKEN_CHARS: usize = 256;
const MAX_CORE_ID_BYTES: usize = 256;
const MAX_TEXT_CHARS: usize = 16 * 1024;
const MAX_COLLECTION_ITEMS: usize = 256;
const MAX_PROPOSAL_BYTES: usize = 512 * 1024;
const SHA256_HEX_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProposalDigest([u8; 32]);

impl ProposalDigest {
    pub const ZERO: Self = Self([0; 32]);

    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn parse_hex(value: &str) -> Result<Self, ProposalValidationError> {
        if value.len() != SHA256_HEX_BYTES {
            return Err(ProposalValidationError::MalformedDigest);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high =
                decode_hex_nibble(pair[0]).ok_or(ProposalValidationError::MalformedDigest)?;
            let low = decode_hex_nibble(pair[1]).ok_or(ProposalValidationError::MalformedDigest)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(SHA256_HEX_BYTES);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }

    #[must_use]
    pub fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> Self {
        let mut hasher = Sha256::new();
        hash_bytes(&mut hasher, domain);
        for part in parts {
            hash_bytes(&mut hasher, part);
        }
        Self(hasher.finalize().into())
    }
}

impl Display for ProposalDigest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AuthoritySourceKind {
    Observation,
    Policy,
    Library,
    CapabilityRegistry,
    ExistingIntent,
}

impl AuthoritySourceKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Policy => "policy",
            Self::Library => "library",
            Self::CapabilityRegistry => "capability-registry",
            Self::ExistingIntent => "existing-intent",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AuthoritySourceRevision {
    pub kind: AuthoritySourceKind,
    pub id: String,
    pub revision: String,
}

impl AuthoritySourceRevision {
    pub fn new(
        kind: AuthoritySourceKind,
        id: impl Into<String>,
        revision: impl Into<String>,
    ) -> Result<Self, ProposalValidationError> {
        let value = Self {
            kind,
            id: id.into(),
            revision: revision.into(),
        };
        validate_token("authority source id", &value.id)?;
        validate_token("authority source revision", &value.revision)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterpretationContextBinding {
    pub authority_revision: String,
    pub semantic_input_digest: ProposalDigest,
    pub source_revisions: Vec<AuthoritySourceRevision>,
}

impl InterpretationContextBinding {
    pub fn new(
        authority_revision: impl Into<String>,
        semantic_input_digest: ProposalDigest,
        mut source_revisions: Vec<AuthoritySourceRevision>,
    ) -> Result<Self, ProposalValidationError> {
        let authority_revision = authority_revision.into();
        validate_token("authority context revision", &authority_revision)?;
        if source_revisions.len() > MAX_COLLECTION_ITEMS {
            return Err(ProposalValidationError::TooManyItems("authority sources"));
        }
        source_revisions.sort();
        if source_revisions.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProposalValidationError::DuplicateAuthoritySource);
        }
        let value = Self {
            authority_revision,
            semantic_input_digest,
            source_revisions,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ProposalValidationError> {
        validate_token("authority context revision", &self.authority_revision)?;
        if self.source_revisions.len() > MAX_COLLECTION_ITEMS {
            return Err(ProposalValidationError::TooManyItems("authority sources"));
        }
        let mut canonical = self.source_revisions.clone();
        for source in &canonical {
            validate_token("authority source id", &source.id)?;
            validate_token("authority source revision", &source.revision)?;
        }
        canonical.sort();
        if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProposalValidationError::DuplicateAuthoritySource);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> ProposalDigest {
        let mut source_revisions = self.source_revisions.clone();
        source_revisions.sort();
        let mut hasher = Sha256::new();
        hash_bytes(&mut hasher, b"linura:interpretation-context:v1");
        hash_str(&mut hasher, &self.authority_revision);
        hash_str(&mut hasher, &self.semantic_input_digest.to_hex());
        hash_u64(&mut hasher, source_revisions.len() as u64);
        for source in &source_revisions {
            hash_str(&mut hasher, source.kind.as_str());
            hash_str(&mut hasher, &source.id);
            hash_str(&mut hasher, &source.revision);
        }
        ProposalDigest::from_bytes(hasher.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProposalConfidence {
    pub permille: u16,
}

impl ProposalConfidence {
    pub fn new(permille: u16) -> Result<Self, ProposalValidationError> {
        let value = Self { permille };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ProposalValidationError> {
        if self.permille > 1_000 {
            return Err(ProposalValidationError::InvalidConfidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalAttribution {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub adapter: String,
    pub manual: bool,
}

impl ProposalAttribution {
    pub fn manual(adapter: impl Into<String>) -> Result<Self, ProposalValidationError> {
        let value = Self {
            provider: None,
            model: None,
            adapter: adapter.into(),
            manual: true,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn provider(
        provider: impl Into<String>,
        adapter: impl Into<String>,
        model: Option<String>,
    ) -> Result<Self, ProposalValidationError> {
        let value = Self {
            provider: Some(provider.into()),
            model,
            adapter: adapter.into(),
            manual: false,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ProposalValidationError> {
        validate_token("proposal adapter id", &self.adapter)?;
        if let Some(provider) = &self.provider {
            validate_token("proposal provider id", provider)?;
        }
        if let Some(model) = &self.model {
            validate_token("proposal model id", model)?;
        }
        if self.manual && (self.provider.is_some() || self.model.is_some()) {
            return Err(ProposalValidationError::InvalidAttribution);
        }
        if !self.manual && self.provider.is_none() {
            return Err(ProposalValidationError::InvalidAttribution);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentProposal {
    pub schema_version: u16,
    pub proposal_id: RequestId,
    pub actor: Actor,
    pub requested_outcome: String,
    pub requirements: Vec<Requirement>,
    pub capability_refs: Vec<CapabilityId>,
    pub assumptions: Vec<String>,
    pub unresolved_questions: Vec<String>,
    pub confidence: Option<ProposalConfidence>,
    pub context: InterpretationContextBinding,
    pub attribution: ProposalAttribution,
    pub explanation: Vec<String>,
    pub canonical_digest: ProposalDigest,
}

impl IntentProposal {
    #[allow(clippy::too_many_arguments)]
    pub fn new_v1(
        proposal_id: RequestId,
        actor: Actor,
        requested_outcome: impl Into<String>,
        requirements: Vec<Requirement>,
        capability_refs: Vec<CapabilityId>,
        assumptions: Vec<String>,
        unresolved_questions: Vec<String>,
        confidence: Option<ProposalConfidence>,
        context: InterpretationContextBinding,
        attribution: ProposalAttribution,
        explanation: Vec<String>,
    ) -> Result<Self, ProposalValidationError> {
        let mut proposal = Self {
            schema_version: INTENT_PROPOSAL_SCHEMA_VERSION,
            proposal_id,
            actor,
            requested_outcome: requested_outcome.into(),
            requirements,
            capability_refs,
            assumptions,
            unresolved_questions,
            confidence,
            context,
            attribution,
            explanation,
            canonical_digest: ProposalDigest::ZERO,
        };
        proposal.validate_material()?;
        proposal.canonical_digest = proposal.derive_digest();
        Ok(proposal)
    }

    pub fn validate(&self) -> Result<(), ProposalValidationError> {
        self.validate_material()?;
        if self.canonical_digest != self.derive_digest() {
            return Err(ProposalValidationError::DigestMismatch);
        }
        Ok(())
    }

    pub fn to_proposed_intent(
        &self,
        intent_id: IntentId,
        supersedes: Vec<IntentId>,
    ) -> Result<Intent, ProposalValidationError> {
        self.validate()?;
        Ok(Intent {
            id: intent_id,
            actor: self.actor.clone(),
            statement: self.requested_outcome.clone(),
            status: IntentStatus::Proposed,
            requirements: self.requirements.clone(),
            supersedes,
        })
    }

    #[must_use]
    pub fn derive_digest(&self) -> ProposalDigest {
        let mut hasher = Sha256::new();
        hash_bytes(&mut hasher, PROPOSAL_DIGEST_DOMAIN);
        hash_u64(&mut hasher, u64::from(self.schema_version));
        hash_str(&mut hasher, self.proposal_id.as_str());
        hash_actor(&mut hasher, &self.actor);
        hash_str(&mut hasher, &self.requested_outcome);
        hash_u64(&mut hasher, self.requirements.len() as u64);
        for requirement in &self.requirements {
            hash_str(&mut hasher, requirement.id.as_str());
            hash_str(&mut hasher, requirement_kind_str(requirement));
            hash_str(&mut hasher, &requirement.statement);
        }
        hash_u64(&mut hasher, self.capability_refs.len() as u64);
        for capability in &self.capability_refs {
            hash_str(&mut hasher, capability.as_str());
        }
        hash_string_list(&mut hasher, &self.assumptions);
        hash_string_list(&mut hasher, &self.unresolved_questions);
        match self.confidence {
            Some(confidence) => {
                hash_str(&mut hasher, "confidence");
                hash_u64(&mut hasher, u64::from(confidence.permille));
            }
            None => hash_str(&mut hasher, "no-confidence"),
        }
        hash_str(&mut hasher, &self.context.digest().to_hex());
        hash_str(
            &mut hasher,
            self.attribution.provider.as_deref().unwrap_or(""),
        );
        hash_str(&mut hasher, self.attribution.model.as_deref().unwrap_or(""));
        hash_str(&mut hasher, &self.attribution.adapter);
        hash_str(
            &mut hasher,
            if self.attribution.manual {
                "manual"
            } else {
                "provider"
            },
        );
        hash_string_list(&mut hasher, &self.explanation);
        ProposalDigest::from_bytes(hasher.finalize().into())
    }

    fn validate_material(&self) -> Result<(), ProposalValidationError> {
        if self.schema_version != INTENT_PROPOSAL_SCHEMA_VERSION {
            return Err(ProposalValidationError::UnsupportedVersion(
                self.schema_version,
            ));
        }
        validate_core_id("proposal id", self.proposal_id.as_str())?;
        validate_core_id("proposal actor id", self.actor.id.as_str())?;
        validate_text("requested outcome", &self.requested_outcome, false)?;
        validate_collection_len("requirements", self.requirements.len())?;
        validate_collection_len("capability references", self.capability_refs.len())?;
        validate_collection_len("assumptions", self.assumptions.len())?;
        validate_collection_len("unresolved questions", self.unresolved_questions.len())?;
        validate_collection_len("explanation", self.explanation.len())?;

        let mut requirement_ids = BTreeSet::new();
        for requirement in &self.requirements {
            validate_core_id("proposal requirement id", requirement.id.as_str())?;
            validate_text("requirement statement", &requirement.statement, false)?;
            if !requirement_ids.insert(requirement.id.as_str()) {
                return Err(ProposalValidationError::DuplicateRequirement);
            }
        }
        let mut capabilities = BTreeSet::new();
        for capability in &self.capability_refs {
            validate_core_id("proposal capability id", capability.as_str())?;
            if !capabilities.insert(capability.as_str()) {
                return Err(ProposalValidationError::DuplicateCapability);
            }
        }
        validate_text_list("assumption", &self.assumptions)?;
        validate_text_list("unresolved question", &self.unresolved_questions)?;
        validate_text_list("explanation", &self.explanation)?;
        if let Some(confidence) = self.confidence {
            confidence.validate()?;
        }
        self.attribution.validate()?;
        self.context.validate()?;
        if self.estimated_size() > MAX_PROPOSAL_BYTES {
            return Err(ProposalValidationError::ProposalTooLarge);
        }
        Ok(())
    }

    fn estimated_size(&self) -> usize {
        let requirement_bytes = self
            .requirements
            .iter()
            .map(|value| {
                value
                    .id
                    .as_str()
                    .len()
                    .saturating_add(value.statement.len())
            })
            .sum::<usize>();
        let capability_bytes = self
            .capability_refs
            .iter()
            .map(|value| value.as_str().len())
            .sum::<usize>();
        let source_bytes = self
            .context
            .source_revisions
            .iter()
            .map(|value| value.id.len().saturating_add(value.revision.len()))
            .sum::<usize>();
        self.requested_outcome
            .len()
            .saturating_add(requirement_bytes)
            .saturating_add(capability_bytes)
            .saturating_add(string_list_bytes(&self.assumptions))
            .saturating_add(string_list_bytes(&self.unresolved_questions))
            .saturating_add(string_list_bytes(&self.explanation))
            .saturating_add(self.context.authority_revision.len())
            .saturating_add(source_bytes)
            .saturating_add(self.attribution.adapter.len())
            .saturating_add(self.attribution.provider.as_deref().map_or(0, str::len))
            .saturating_add(self.attribution.model.as_deref().map_or(0, str::len))
    }
}

fn requirement_kind_str(requirement: &Requirement) -> &'static str {
    match requirement.kind {
        crate::RequirementKind::Goal => "goal",
        crate::RequirementKind::Constraint => "constraint",
        crate::RequirementKind::Preference => "preference",
        crate::RequirementKind::Prohibition => "prohibition",
    }
}

fn validate_collection_len(label: &'static str, len: usize) -> Result<(), ProposalValidationError> {
    if len > MAX_COLLECTION_ITEMS {
        return Err(ProposalValidationError::TooManyItems(label));
    }
    Ok(())
}

fn validate_text_list(
    label: &'static str,
    values: &[String],
) -> Result<(), ProposalValidationError> {
    for value in values {
        validate_text(label, value, true)?;
    }
    Ok(())
}

fn validate_core_id(label: &'static str, value: &str) -> Result<(), ProposalValidationError> {
    if value.is_empty() {
        return Err(ProposalValidationError::Empty(label));
    }
    if value.len() > MAX_CORE_ID_BYTES {
        return Err(ProposalValidationError::TooLong(label));
    }
    if !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(ProposalValidationError::InvalidCoreId(label));
    }
    Ok(())
}

fn validate_token(label: &'static str, value: &str) -> Result<(), ProposalValidationError> {
    if value.trim().is_empty() {
        return Err(ProposalValidationError::Empty(label));
    }
    if value.chars().count() > MAX_TOKEN_CHARS {
        return Err(ProposalValidationError::TooLong(label));
    }
    if value.chars().any(char::is_control) {
        return Err(ProposalValidationError::ControlCharacter(label));
    }
    Ok(())
}

fn validate_text(
    label: &'static str,
    value: &str,
    allow_empty: bool,
) -> Result<(), ProposalValidationError> {
    if !allow_empty && value.trim().is_empty() {
        return Err(ProposalValidationError::Empty(label));
    }
    if value.chars().count() > MAX_TEXT_CHARS {
        return Err(ProposalValidationError::TooLong(label));
    }
    if value.chars().any(|character| character == '\0') {
        return Err(ProposalValidationError::ControlCharacter(label));
    }
    Ok(())
}

fn string_list_bytes(values: &[String]) -> usize {
    values.iter().map(String::len).sum()
}

fn hash_actor(hasher: &mut Sha256, actor: &Actor) {
    hash_str(hasher, actor.id.as_str());
    hash_str(
        hasher,
        match actor.kind {
            ActorKind::Human => "human",
            ActorKind::Service => "service",
            ActorKind::Agent => "agent",
            ActorKind::Remote => "remote",
        },
    );
    hash_str(
        hasher,
        if actor.interactive {
            "interactive"
        } else {
            "non-interactive"
        },
    );
}

fn hash_string_list(hasher: &mut Sha256, values: &[String]) {
    hash_u64(hasher, values.len() as u64);
    for value in values {
        hash_str(hasher, value);
    }
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_be_bytes());
}

fn hash_str(hasher: &mut Sha256, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hash_u64(hasher, value.len() as u64);
    hasher.update(value);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposalValidationError {
    UnsupportedVersion(u16),
    Empty(&'static str),
    TooLong(&'static str),
    ControlCharacter(&'static str),
    TooManyItems(&'static str),
    DuplicateRequirement,
    DuplicateCapability,
    DuplicateAuthoritySource,
    InvalidConfidence,
    InvalidAttribution,
    InvalidCoreId(&'static str),
    MalformedDigest,
    DigestMismatch,
    ProposalTooLarge,
}

impl Display for ProposalValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported intent proposal schema version {version}")
            }
            Self::Empty(label) => write!(f, "{label} cannot be empty"),
            Self::TooLong(label) => write!(f, "{label} exceeds the proposal bound"),
            Self::ControlCharacter(label) => {
                write!(f, "{label} contains a forbidden control character")
            }
            Self::TooManyItems(label) => write!(f, "{label} exceeds the proposal collection bound"),
            Self::DuplicateRequirement => {
                f.write_str("proposal contains a duplicate requirement id")
            }
            Self::DuplicateCapability => {
                f.write_str("proposal contains a duplicate capability reference")
            }
            Self::DuplicateAuthoritySource => {
                f.write_str("proposal context contains a duplicate authority source revision")
            }
            Self::InvalidConfidence => {
                f.write_str("proposal confidence must be between 0 and 1000 permille")
            }
            Self::InvalidAttribution => {
                f.write_str("proposal attribution is inconsistent with manual/provider mode")
            }
            Self::InvalidCoreId(label) => write!(
                f,
                "{label} must use the proposal-v1 printable-ASCII core-ID wire contract"
            ),
            Self::MalformedDigest => {
                f.write_str("proposal digest must be exactly 32 bytes / 64 hex digits")
            }
            Self::DigestMismatch => f.write_str("intent proposal canonical digest mismatch"),
            Self::ProposalTooLarge => {
                f.write_str("intent proposal exceeds the aggregate size bound")
            }
        }
    }
}

impl std::error::Error for ProposalValidationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RequirementKind;
    use linura_core::{ActorId, CapabilityId, RequirementId, ValidationError};

    fn core_id<T>(value: Result<T, ValidationError>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn proposal() -> IntentProposal {
        let context = InterpretationContextBinding::new(
            "authority:7",
            ProposalDigest::hash_parts(b"semantic", &[b"desktop workstation"]),
            vec![
                AuthoritySourceRevision::new(
                    AuthoritySourceKind::CapabilityRegistry,
                    "registry:local",
                    "7",
                )
                .unwrap_or_else(|error| unreachable!("{error}")),
            ],
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        IntentProposal::new_v1(
            core_id(RequestId::new("proposal:v08:test")),
            Actor {
                id: core_id(ActorId::new("uid:1000")),
                kind: ActorKind::Human,
                interactive: true,
            },
            "Configure a development workstation",
            vec![Requirement {
                id: core_id(RequirementId::new("requirement:developer-tools")),
                kind: RequirementKind::Goal,
                statement: "Provide a Rust development environment".into(),
            }],
            vec![core_id(CapabilityId::new("developer.rust"))],
            vec!["User prefers stable toolchains".into()],
            vec![],
            Some(ProposalConfidence::new(900).unwrap_or_else(|error| unreachable!("{error}"))),
            context,
            ProposalAttribution::manual("linura-manual")
                .unwrap_or_else(|error| unreachable!("{error}")),
            vec!["Typed manual interpretation".into()],
        )
        .unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[test]
    fn proposal_digest_detects_semantic_substitution() {
        let proposal = proposal();
        assert_eq!(proposal.validate(), Ok(()));
        let mut substituted = proposal;
        substituted.requested_outcome = "Different outcome".into();
        assert_eq!(
            substituted.validate(),
            Err(ProposalValidationError::DigestMismatch)
        );
    }

    #[test]
    fn proposal_converts_only_to_proposed_intent() {
        let proposal = proposal();
        let intent = proposal
            .to_proposed_intent(core_id(IntentId::new("intent:v08:test")), vec![])
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(intent.status, IntentStatus::Proposed);
        assert_eq!(intent.actor, proposal.actor);
    }

    #[test]
    fn core_id_wire_contract_allows_spaces_but_rejects_non_ascii() {
        let mut spaces = proposal();
        spaces.proposal_id = core_id(RequestId::new("   "));
        spaces.canonical_digest = spaces.derive_digest();
        assert_eq!(spaces.validate(), Ok(()));

        let mut non_ascii = proposal();
        non_ascii.proposal_id = core_id(RequestId::new("proposal:é"));
        non_ascii.canonical_digest = non_ascii.derive_digest();
        assert!(matches!(
            non_ascii.validate(),
            Err(ProposalValidationError::InvalidCoreId("proposal id"))
        ));
    }

    #[test]
    fn context_digest_is_order_independent_for_source_revisions() {
        let a = AuthoritySourceRevision::new(AuthoritySourceKind::Policy, "policy:a", "2")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let b = AuthoritySourceRevision::new(AuthoritySourceKind::Library, "library:b", "3")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let semantic = ProposalDigest::hash_parts(b"semantic", &[b"same"]);
        let left =
            InterpretationContextBinding::new("authority:9", semantic, vec![a.clone(), b.clone()])
                .unwrap_or_else(|error| unreachable!("{error}"));
        let right = InterpretationContextBinding::new("authority:9", semantic, vec![b, a])
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(left.digest(), right.digest());
    }

    #[test]
    fn provider_attribution_cannot_smuggle_provider_into_manual_mode() {
        let attribution = ProposalAttribution {
            provider: Some("hosted".into()),
            model: None,
            adapter: "manual".into(),
            manual: true,
        };
        assert_eq!(
            attribution.validate(),
            Err(ProposalValidationError::InvalidAttribution)
        );
    }

    #[test]
    fn unicode_text_limits_are_character_based_and_keep_byte_aggregate_bound() {
        let mut value = proposal();
        value.requested_outcome = "é".repeat(MAX_TEXT_CHARS);
        value.canonical_digest = value.derive_digest();
        assert_eq!(value.validate(), Ok(()));

        value.requested_outcome.push('é');
        value.canonical_digest = value.derive_digest();
        assert_eq!(
            value.validate(),
            Err(ProposalValidationError::TooLong("requested outcome"))
        );
    }

    #[test]
    fn required_text_rejects_whitespace_only_and_all_text_rejects_nul() {
        let mut whitespace = proposal();
        whitespace.requested_outcome = " \t\n".into();
        whitespace.canonical_digest = whitespace.derive_digest();
        assert_eq!(
            whitespace.validate(),
            Err(ProposalValidationError::Empty("requested outcome"))
        );

        let mut nul = proposal();
        nul.assumptions = vec!["bad\0value".into()];
        nul.canonical_digest = nul.derive_digest();
        assert_eq!(
            nul.validate(),
            Err(ProposalValidationError::ControlCharacter("assumption"))
        );
    }
}

#[cfg(test)]
mod review_regression_tests {
    use super::*;
    use linura_core::{ActorId, ValidationError};

    fn id<T>(value: Result<T, ValidationError>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn actor() -> Actor {
        Actor {
            id: id(ActorId::new("uid:review")),
            kind: ActorKind::Human,
            interactive: true,
        }
    }

    #[test]
    fn direct_invalid_confidence_is_rejected() {
        let context = InterpretationContextBinding::new(
            "authority:review",
            ProposalDigest::hash_parts(b"semantic", &[b"review"]),
            vec![],
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let result = IntentProposal::new_v1(
            id(RequestId::new("proposal:invalid-confidence")),
            actor(),
            "review",
            vec![],
            vec![],
            vec![],
            vec![],
            Some(ProposalConfidence { permille: 1_001 }),
            context,
            ProposalAttribution::manual("manual").unwrap_or_else(|error| unreachable!("{error}")),
            vec![],
        );
        assert_eq!(result, Err(ProposalValidationError::InvalidConfidence));
    }

    #[test]
    fn context_digest_is_canonical_even_for_public_unsorted_material() {
        let a = AuthoritySourceRevision::new(AuthoritySourceKind::Policy, "policy", "1")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let b = AuthoritySourceRevision::new(AuthoritySourceKind::Library, "library", "2")
            .unwrap_or_else(|error| unreachable!("{error}"));
        let semantic = ProposalDigest::hash_parts(b"semantic", &[b"review"]);
        let left = InterpretationContextBinding {
            authority_revision: "authority:review".into(),
            semantic_input_digest: semantic,
            source_revisions: vec![a.clone(), b.clone()],
        };
        let right = InterpretationContextBinding {
            authority_revision: "authority:review".into(),
            semantic_input_digest: semantic,
            source_revisions: vec![b, a],
        };
        assert_eq!(left.validate(), Ok(()));
        assert_eq!(right.validate(), Ok(()));
        assert_eq!(left.digest(), right.digest());
    }
}
