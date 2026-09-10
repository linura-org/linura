use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

use linura_core::{Actor, CapabilityId, ProviderId, RequestId};
use linura_intent::{IntentProposal, InterpretationContextBinding, ProposalDigest};

const INTERPRETATION_REQUEST_DOMAIN: &[u8] = b"linura:interpretation-request:v1";
const PREPARED_INVOCATION_DOMAIN: &[u8] = b"linura:prepared-provider-invocation:v1";
const MAX_TOKEN_BYTES: usize = 256;
const MAX_SEMANTIC_ENTRIES: usize = 512;
const MAX_SEMANTIC_VALUE_BYTES: usize = 32 * 1024;
const MAX_REQUEST_BYTES: usize = 512 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_PREPARED_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkAccess {
    None,
    Required,
}

impl NetworkAccess {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Required => "required",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterDescriptor {
    pub provider: ProviderId,
    pub adapter_id: String,
    pub endpoint_class: String,
    pub protocol_version: u16,
    pub network_access: NetworkAccess,
}

impl AdapterDescriptor {
    pub fn validate(&self) -> Result<(), InterpretationAdapterError> {
        validate_token("adapter id", &self.adapter_id)?;
        validate_token("endpoint class", &self.endpoint_class)?;
        if self.protocol_version == 0 {
            return Err(InterpretationAdapterError::InvalidDescriptor(
                "protocol version must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SemanticValue {
    Text(String),
    ProtectedReference(String),
    Bool(bool),
    U64(u64),
    I64(i64),
}

impl SemanticValue {
    fn validate(&self) -> Result<(), InterpretationAdapterError> {
        match self {
            Self::Text(value) => validate_semantic_value(value),
            Self::ProtectedReference(value) => {
                validate_token("protected semantic reference", value)
            }
            Self::Bool(_) | Self::U64(_) | Self::I64(_) => Ok(()),
        }
    }

    fn digest_into(&self, parts: &mut Vec<Vec<u8>>) {
        match self {
            Self::Text(value) => {
                parts.push(b"text".to_vec());
                parts.push(value.as_bytes().to_vec());
            }
            Self::ProtectedReference(value) => {
                parts.push(b"protected-reference".to_vec());
                parts.push(value.as_bytes().to_vec());
            }
            Self::Bool(value) => {
                parts.push(b"bool".to_vec());
                parts.push(if *value {
                    b"true".to_vec()
                } else {
                    b"false".to_vec()
                });
            }
            Self::U64(value) => {
                parts.push(b"u64".to_vec());
                parts.push(value.to_be_bytes().to_vec());
            }
            Self::I64(value) => {
                parts.push(b"i64".to_vec());
                parts.push(value.to_be_bytes().to_vec());
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticEntry {
    pub key: String,
    pub value: SemanticValue,
}

impl SemanticEntry {
    pub fn new(
        key: impl Into<String>,
        value: SemanticValue,
    ) -> Result<Self, InterpretationAdapterError> {
        let entry = Self {
            key: key.into(),
            value,
        };
        validate_token("semantic projection key", &entry.key)?;
        entry.value.validate()?;
        Ok(entry)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinimizedSemanticProjection {
    entries: Vec<SemanticEntry>,
    digest: ProposalDigest,
}

impl MinimizedSemanticProjection {
    pub fn new(mut entries: Vec<SemanticEntry>) -> Result<Self, InterpretationAdapterError> {
        if entries.len() > MAX_SEMANTIC_ENTRIES {
            return Err(InterpretationAdapterError::TooLarge("semantic projection"));
        }
        for entry in &entries {
            validate_token("semantic projection key", &entry.key)?;
            entry.value.validate()?;
        }
        entries.sort_by(|left, right| left.key.cmp(&right.key));
        if entries.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(InterpretationAdapterError::DuplicateSemanticKey);
        }
        let bytes = entries.iter().fold(0_usize, |total, entry| {
            total
                .saturating_add(entry.key.len())
                .saturating_add(match &entry.value {
                    SemanticValue::Text(value) | SemanticValue::ProtectedReference(value) => {
                        value.len()
                    }
                    SemanticValue::Bool(_) => 1,
                    SemanticValue::U64(_) | SemanticValue::I64(_) => 8,
                })
        });
        if bytes > MAX_REQUEST_BYTES {
            return Err(InterpretationAdapterError::TooLarge("semantic projection"));
        }
        let digest = projection_digest(&entries);
        Ok(Self { entries, digest })
    }

    #[must_use]
    pub fn entries(&self) -> &[SemanticEntry] {
        &self.entries
    }

    #[must_use]
    pub const fn digest(&self) -> ProposalDigest {
        self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterpretationRequest {
    pub request_id: RequestId,
    pub actor: Actor,
    pub context: InterpretationContextBinding,
    pub projection: MinimizedSemanticProjection,
    pub capability_refs: Vec<CapabilityId>,
    pub max_response_bytes: u32,
    pub attempt_deadline_unix_ms: u64,
}

impl InterpretationRequest {
    pub fn validate(&self) -> Result<(), InterpretationAdapterError> {
        if self.projection.digest() != self.context.semantic_input_digest {
            return Err(InterpretationAdapterError::ContextDigestMismatch);
        }
        if self.max_response_bytes == 0
            || usize::try_from(self.max_response_bytes)
                .map_or(true, |value| value > MAX_RESPONSE_BYTES)
        {
            return Err(InterpretationAdapterError::InvalidBudget);
        }
        if self.attempt_deadline_unix_ms == 0 {
            return Err(InterpretationAdapterError::InvalidBudget);
        }
        let mut seen = BTreeSet::new();
        for capability in &self.capability_refs {
            if !seen.insert(capability.as_str()) {
                return Err(InterpretationAdapterError::DuplicateCapability);
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> ProposalDigest {
        let mut owned = vec![
            self.request_id.as_str().as_bytes().to_vec(),
            self.actor.id.as_str().as_bytes().to_vec(),
            actor_kind(&self.actor).as_bytes().to_vec(),
            if self.actor.interactive {
                b"interactive".to_vec()
            } else {
                b"non-interactive".to_vec()
            },
            self.context.digest().to_hex().into_bytes(),
            self.projection.digest().to_hex().into_bytes(),
            self.max_response_bytes.to_be_bytes().to_vec(),
            self.attempt_deadline_unix_ms.to_be_bytes().to_vec(),
        ];
        for capability in &self.capability_refs {
            owned.push(capability.as_str().as_bytes().to_vec());
        }
        let refs = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
        ProposalDigest::hash_parts(INTERPRETATION_REQUEST_DOMAIN, &refs)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderField {
    pub name: String,
    pub value: String,
}

impl HeaderField {
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, InterpretationAdapterError> {
        let field = Self {
            name: name.into(),
            value: value.into(),
        };
        validate_token("provider header name", &field.name)?;
        if field.value.len() > MAX_TOKEN_BYTES || field.value.chars().any(char::is_control) {
            return Err(InterpretationAdapterError::CredentialLikeMaterial);
        }
        let normalized = field.name.to_ascii_lowercase();
        if matches!(
            normalized.as_str(),
            "authorization"
                | "proxy-authorization"
                | "cookie"
                | "set-cookie"
                | "x-api-key"
                | "api-key"
        ) {
            return Err(InterpretationAdapterError::CredentialLikeMaterial);
        }
        Ok(field)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedProviderInvocation {
    pub provider: ProviderId,
    pub adapter_id: String,
    pub endpoint_class: String,
    pub protocol_version: u16,
    pub network_access: NetworkAccess,
    pub headers: Vec<HeaderField>,
    pub canonical_payload: Vec<u8>,
}

impl PreparedProviderInvocation {
    pub fn new(
        descriptor: &AdapterDescriptor,
        headers: Vec<HeaderField>,
        canonical_payload: Vec<u8>,
    ) -> Result<Self, InterpretationAdapterError> {
        descriptor.validate()?;
        if headers.len() > MAX_HEADERS {
            return Err(InterpretationAdapterError::TooLarge("provider headers"));
        }
        if canonical_payload.len() > MAX_PREPARED_PAYLOAD_BYTES {
            return Err(InterpretationAdapterError::TooLarge(
                "prepared provider payload",
            ));
        }
        let value = Self {
            provider: descriptor.provider.clone(),
            adapter_id: descriptor.adapter_id.clone(),
            endpoint_class: descriptor.endpoint_class.clone(),
            protocol_version: descriptor.protocol_version,
            network_access: descriptor.network_access,
            headers,
            canonical_payload,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), InterpretationAdapterError> {
        validate_token("adapter id", &self.adapter_id)?;
        validate_token("endpoint class", &self.endpoint_class)?;
        if self.protocol_version == 0
            || self.headers.len() > MAX_HEADERS
            || self.canonical_payload.len() > MAX_PREPARED_PAYLOAD_BYTES
        {
            return Err(InterpretationAdapterError::InvalidPreparedInvocation);
        }
        for header in &self.headers {
            HeaderField::new(header.name.clone(), header.value.clone())?;
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> ProposalDigest {
        let mut owned = vec![
            self.provider.as_str().as_bytes().to_vec(),
            self.adapter_id.as_bytes().to_vec(),
            self.endpoint_class.as_bytes().to_vec(),
            self.protocol_version.to_be_bytes().to_vec(),
            self.network_access.as_str().as_bytes().to_vec(),
        ];
        for header in &self.headers {
            owned.push(header.name.as_bytes().to_vec());
            owned.push(header.value.as_bytes().to_vec());
        }
        owned.push(self.canonical_payload.clone());
        let refs = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
        ProposalDigest::hash_parts(PREPARED_INVOCATION_DOMAIN, &refs)
    }
}

pub trait InterpretationAdapter: Send + Sync {
    fn descriptor(&self) -> AdapterDescriptor;

    /// Pure protocol adaptation only. Implementations receive no transport or
    /// credential handle through this API.
    fn prepare(
        &self,
        request: &InterpretationRequest,
    ) -> Result<PreparedProviderInvocation, InterpretationAdapterError>;

    /// Decode one complete terminal response. Partial responses are never
    /// proposal inputs.
    fn decode_complete(
        &self,
        request: &InterpretationRequest,
        response: &[u8],
    ) -> Result<IntentProposal, InterpretationAdapterError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderInvocationDeadline {
    deadline_unix_ms: u64,
    remaining_ms: u64,
}

impl ProviderInvocationDeadline {
    pub fn new(
        deadline_unix_ms: u64,
        remaining_ms: u64,
    ) -> Result<Self, InterpretationAdapterError> {
        if deadline_unix_ms == 0 || remaining_ms == 0 {
            return Err(InterpretationAdapterError::InvalidBudget);
        }
        Ok(Self {
            deadline_unix_ms,
            remaining_ms,
        })
    }

    #[must_use]
    pub const fn deadline_unix_ms(self) -> u64 {
        self.deadline_unix_ms
    }

    #[must_use]
    pub const fn remaining_ms(self) -> u64 {
        self.remaining_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderInvocationOutcome {
    Complete(Vec<u8>),
    Partial,
    Timeout,
    RateLimited,
    TransportFailure(String),
    Cancelled,
}

/// Trusted transport port. Implementations may retain provider credentials
/// internally, but credentials are never parameters or return values. One call
/// means one provider invocation; retry/reissue/redirect/reconnect loops are not
/// part of this contract. `deadline.remaining_ms()` is the maximum remaining
/// Control-admitted wall-clock budget at dispatch; trusted transports must bind
/// every underlying request/socket/process timeout to no more than that value.
pub trait ProviderInvocationTransport: Send {
    fn invoke_once(
        &mut self,
        invocation: &PreparedProviderInvocation,
        deadline: ProviderInvocationDeadline,
    ) -> ProviderInvocationOutcome;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InterpretationAdapterError {
    Empty(&'static str),
    TooLong(&'static str),
    TooLarge(&'static str),
    ControlCharacter(&'static str),
    InvalidDescriptor(String),
    InvalidBudget,
    DuplicateSemanticKey,
    DuplicateCapability,
    ContextDigestMismatch,
    CredentialLikeMaterial,
    InvalidPreparedInvocation,
    MalformedOutput(String),
}

impl Display for InterpretationAdapterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty(label) => write!(f, "{label} cannot be empty"),
            Self::TooLong(label) => write!(f, "{label} exceeds its bound"),
            Self::TooLarge(label) => write!(f, "{label} exceeds its aggregate bound"),
            Self::ControlCharacter(label) => {
                write!(f, "{label} contains a forbidden control character")
            }
            Self::InvalidDescriptor(reason) => {
                write!(f, "invalid interpretation adapter descriptor: {reason}")
            }
            Self::InvalidBudget => f.write_str("interpretation attempt budget/deadline is invalid"),
            Self::DuplicateSemanticKey => {
                f.write_str("semantic projection contains a duplicate key")
            }
            Self::DuplicateCapability => {
                f.write_str("interpretation request contains a duplicate capability reference")
            }
            Self::ContextDigestMismatch => {
                f.write_str("semantic projection digest does not match the Control context binding")
            }
            Self::CredentialLikeMaterial => {
                f.write_str("prepared invocation contains credential-like material")
            }
            Self::InvalidPreparedInvocation => {
                f.write_str("prepared provider invocation is invalid")
            }
            Self::MalformedOutput(reason) => {
                write!(f, "provider interpretation output is invalid: {reason}")
            }
        }
    }
}

impl std::error::Error for InterpretationAdapterError {}

fn validate_token(label: &'static str, value: &str) -> Result<(), InterpretationAdapterError> {
    if value.trim().is_empty() {
        return Err(InterpretationAdapterError::Empty(label));
    }
    if value.len() > MAX_TOKEN_BYTES {
        return Err(InterpretationAdapterError::TooLong(label));
    }
    if value.chars().any(char::is_control) {
        return Err(InterpretationAdapterError::ControlCharacter(label));
    }
    Ok(())
}

fn validate_semantic_value(value: &str) -> Result<(), InterpretationAdapterError> {
    if value.len() > MAX_SEMANTIC_VALUE_BYTES {
        return Err(InterpretationAdapterError::TooLong(
            "semantic projection value",
        ));
    }
    if value.chars().any(|character| character == '\0') {
        return Err(InterpretationAdapterError::ControlCharacter(
            "semantic projection value",
        ));
    }
    Ok(())
}

fn projection_digest(entries: &[SemanticEntry]) -> ProposalDigest {
    let mut owned = Vec::new();
    for entry in entries {
        owned.push(entry.key.as_bytes().to_vec());
        entry.value.digest_into(&mut owned);
    }
    let refs = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
    ProposalDigest::hash_parts(b"linura:minimized-semantic-projection:v1", &refs)
}

fn actor_kind(actor: &Actor) -> &'static str {
    match actor.kind {
        linura_core::ActorKind::Human => "human",
        linura_core::ActorKind::Service => "service",
        linura_core::ActorKind::Agent => "agent",
        linura_core::ActorKind::Remote => "remote",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{ActorId, ActorKind, ValidationError};

    fn id<T>(value: Result<T, ValidationError>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error}"))
    }

    #[test]
    fn projection_is_canonical_by_key_order() {
        let left = MinimizedSemanticProjection::new(vec![
            SemanticEntry::new("b", SemanticValue::Bool(true))
                .unwrap_or_else(|error| unreachable!("{error}")),
            SemanticEntry::new("a", SemanticValue::Text("value".into()))
                .unwrap_or_else(|error| unreachable!("{error}")),
        ])
        .unwrap_or_else(|error| unreachable!("{error}"));
        let right = MinimizedSemanticProjection::new(vec![
            SemanticEntry::new("a", SemanticValue::Text("value".into()))
                .unwrap_or_else(|error| unreachable!("{error}")),
            SemanticEntry::new("b", SemanticValue::Bool(true))
                .unwrap_or_else(|error| unreachable!("{error}")),
        ])
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(left.digest(), right.digest());
    }

    #[test]
    fn projection_revalidates_directly_constructed_entries() {
        assert!(matches!(
            MinimizedSemanticProjection::new(vec![SemanticEntry {
                key: String::new(),
                value: SemanticValue::Text("value".into()),
            }]),
            Err(InterpretationAdapterError::Empty("semantic projection key"))
        ));
        assert!(matches!(
            MinimizedSemanticProjection::new(vec![SemanticEntry {
                key: "secret".into(),
                value: SemanticValue::ProtectedReference("bad\nreference".into()),
            }]),
            Err(InterpretationAdapterError::ControlCharacter(
                "protected semantic reference"
            ))
        ));
    }

    #[test]
    fn request_digest_binds_actor_interactivity() {
        let projection = MinimizedSemanticProjection::new(vec![])
            .unwrap_or_else(|error| unreachable!("{error}"));
        let context = InterpretationContextBinding::new(
            "authority:actor-binding",
            projection.digest(),
            vec![],
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let mut request = InterpretationRequest {
            request_id: id(RequestId::new("request:actor-binding")),
            actor: Actor {
                id: id(ActorId::new("uid:1000")),
                kind: ActorKind::Human,
                interactive: true,
            },
            context,
            projection,
            capability_refs: vec![],
            max_response_bytes: 4096,
            attempt_deadline_unix_ms: 10_000,
        };
        let interactive = request.digest();
        request.actor.interactive = false;
        assert_ne!(interactive, request.digest());
    }

    #[test]
    fn provider_deadline_rejects_empty_budget_and_preserves_exact_bounds() {
        assert_eq!(
            ProviderInvocationDeadline::new(100, 0),
            Err(InterpretationAdapterError::InvalidBudget)
        );
        let deadline = ProviderInvocationDeadline::new(100, 25)
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(deadline.deadline_unix_ms(), 100);
        assert_eq!(deadline.remaining_ms(), 25);
    }

    #[test]
    fn prepared_invocation_rejects_auth_headers() {
        assert_eq!(
            HeaderField::new("Authorization", "Bearer secret"),
            Err(InterpretationAdapterError::CredentialLikeMaterial)
        );
    }

    #[test]
    fn request_rejects_projection_context_substitution() {
        let projection = MinimizedSemanticProjection::new(vec![
            SemanticEntry::new("goal", SemanticValue::Text("developer workstation".into()))
                .unwrap_or_else(|error| unreachable!("{error}")),
        ])
        .unwrap_or_else(|error| unreachable!("{error}"));
        let context = InterpretationContextBinding::new(
            "authority:1",
            ProposalDigest::hash_parts(b"wrong", &[b"digest"]),
            vec![],
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let request = InterpretationRequest {
            request_id: id(RequestId::new("request:v08:test")),
            actor: Actor {
                id: id(ActorId::new("uid:1000")),
                kind: ActorKind::Human,
                interactive: true,
            },
            context,
            projection,
            capability_refs: vec![],
            max_response_bytes: 4096,
            attempt_deadline_unix_ms: 10_000,
        };
        assert_eq!(
            request.validate(),
            Err(InterpretationAdapterError::ContextDigestMismatch)
        );
    }
}
