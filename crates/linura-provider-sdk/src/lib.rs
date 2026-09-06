#![forbid(unsafe_code)]

use std::fmt::{Display, Formatter};

use linura_core::{Capability, CapabilityId, ProviderId, ResourceId};
use linura_observation::{ObservationEnvelope, ProviderHealth};
use sha2::{Digest, Sha256};

pub const MAX_COMPONENT_TOKEN_BYTES: usize = 256;
pub const MAX_EFFECT_PAYLOAD_BYTES: usize = 1024;
pub const SHA256_HEX_BYTES: usize = 64;
// These domains identify the component-contract schema introduced during v0.5.
// They remain stable in v0.6 so the now-integrated handoff is compatible with
// the independently qualified executor/verifier correlation format.
const EFFECT_DOMAIN: &[u8] = b"linura:v0.5:effect:v1";
const DISPATCH_DOMAIN: &[u8] = b"linura:v0.5:dispatch-binding:v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderError {
    Unsupported(String),
    Unavailable(String),
    InvalidState(String),
    Internal(String),
}

impl Display for ProviderError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let (kind, detail) = match self {
            Self::Unsupported(detail) => ("unsupported", detail),
            Self::Unavailable(detail) => ("unavailable", detail),
            Self::InvalidState(detail) => ("invalid state", detail),
            Self::Internal(detail) => ("internal error", detail),
        };
        write!(f, "provider {kind}: {detail}")
    }
}

impl std::error::Error for ProviderError {}

/// Read-only authoritative observation provider.
///
/// Implementing `Observer` grants no planning, policy, approval, execution or
/// verification authority. One call is a bounded provider-backed probe that
/// returns Linura's canonical authoritative [`ObservationEnvelope`].
///
/// Cross-provider fan-out, global retry policy, deadlines, cancellation, query
/// coalescing, cache policy, backpressure and aggregate resource budgets belong
/// to Linura's control-plane orchestration rather than to an individual observer.
/// Transport-specific handles and values must not escape through this trait.
pub trait Observer: Send + Sync {
    fn observer_id(&self) -> ProviderId;
    fn observation_capabilities(&self) -> Vec<Capability>;
    fn health(&self) -> ProviderHealth;
    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError>;
    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError>;

    fn supports_observation(&self, capability: &CapabilityId) -> bool {
        self.observation_capabilities()
            .iter()
            .any(|candidate| &candidate.id == capability)
    }
}

/// Fixed-size content identity used by the isolated executor/verifier component
/// contract introduced in v0.5 and consumed by the v0.6 managed handoff.
///
/// A digest is correlation and integrity material. It is never a credential,
/// approval, durable dispatch permit, or independent source of authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ComponentDigest([u8; 32]);

impl ComponentDigest {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn parse_hex(value: &str) -> Result<Self, ComponentContractError> {
        if value.len() != SHA256_HEX_BYTES {
            return Err(ComponentContractError::MalformedDigest);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = decode_hex_nibble(pair[0]).ok_or(ComponentContractError::MalformedDigest)?;
            let low = decode_hex_nibble(pair[1]).ok_or(ComponentContractError::MalformedDigest)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(SHA256_HEX_BYTES);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

impl Display for ComponentDigest {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComponentContractError {
    Empty(&'static str),
    TooLong(&'static str),
    ControlCharacter(&'static str),
    MalformedDigest,
    ZeroStateVersion,
    BindingMismatch,
}

impl Display for ComponentContractError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty(label) => write!(f, "{label} cannot be empty"),
            Self::TooLong(label) => write!(f, "{label} exceeds the component bound"),
            Self::ControlCharacter(label) => write!(f, "{label} contains control characters"),
            Self::MalformedDigest => f.write_str("digest must be exactly 32 bytes / 64 hex digits"),
            Self::ZeroStateVersion => f.write_str("durable state version must be non-zero"),
            Self::BindingMismatch => {
                f.write_str("dispatch binding does not match its exact material")
            }
        }
    }
}

impl std::error::Error for ComponentContractError {}

fn validate_component_token(
    label: &'static str,
    value: &str,
) -> Result<(), ComponentContractError> {
    if value.is_empty() {
        return Err(ComponentContractError::Empty(label));
    }
    if value.len() > MAX_COMPONENT_TOKEN_BYTES {
        return Err(ComponentContractError::TooLong(label));
    }
    if value.chars().any(char::is_control) {
        return Err(ComponentContractError::ControlCharacter(label));
    }
    Ok(())
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> ComponentDigest {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    ComponentDigest::from_bytes(hasher.finalize().into())
}

/// Canonical typed effect description used to bind a narrow executor request.
///
/// `canonical_payload` must be an operation-specific deterministic encoding,
/// not shell text, a generic command line, or arbitrary executable input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectDescriptor {
    pub provider: ProviderId,
    pub resource: ResourceId,
    pub operation: String,
    pub canonical_payload: Vec<u8>,
}

impl EffectDescriptor {
    pub fn new(
        provider: ProviderId,
        resource: ResourceId,
        operation: impl Into<String>,
        canonical_payload: Vec<u8>,
    ) -> Result<Self, ComponentContractError> {
        let operation = operation.into();
        validate_component_token("operation", &operation)?;
        if canonical_payload.len() > MAX_EFFECT_PAYLOAD_BYTES {
            return Err(ComponentContractError::TooLong("canonical effect payload"));
        }
        Ok(Self {
            provider,
            resource,
            operation,
            canonical_payload,
        })
    }

    pub fn digest(&self) -> ComponentDigest {
        hash_parts(
            EFFECT_DOMAIN,
            &[
                self.provider.as_str().as_bytes(),
                self.resource.as_str().as_bytes(),
                self.operation.as_bytes(),
                &self.canonical_payload,
            ],
        )
    }
}

/// Exact executor correlation material.
///
/// This structure intentionally does not depend on `linura-transaction`: the
/// one-shot `DispatchPermit` remains sealed inside Linura Control and cannot be
/// serialized, persisted, cloned, or reconstructed. v0.5 qualified this
/// integrity shape; v0.6 consumes the real permit into a one-shot authorized
/// effect before this correlation material can cross the executor transport.
///
/// Durable transaction generation zero is valid and is the first SQLite-backed
/// generation. `state_version` remains strictly non-zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionBinding {
    pub transaction_id: String,
    pub generation: u64,
    pub state_version: u64,
    pub authority_binding_digest: ComponentDigest,
    pub authority_use_digest: ComponentDigest,
    pub effect_digest: ComponentDigest,
    pub dispatch_digest: ComponentDigest,
}

impl ExecutionBinding {
    pub fn new(
        transaction_id: impl Into<String>,
        generation: u64,
        state_version: u64,
        authority_binding_digest: ComponentDigest,
        authority_use_digest: ComponentDigest,
        effect: &EffectDescriptor,
    ) -> Result<Self, ComponentContractError> {
        let transaction_id = transaction_id.into();
        validate_component_token("transaction id", &transaction_id)?;
        if state_version == 0 {
            return Err(ComponentContractError::ZeroStateVersion);
        }
        let effect_digest = effect.digest();
        let dispatch_digest = derive_dispatch_digest(
            &transaction_id,
            generation,
            state_version,
            authority_binding_digest,
            authority_use_digest,
            effect,
            effect_digest,
        );
        Ok(Self {
            transaction_id,
            generation,
            state_version,
            authority_binding_digest,
            authority_use_digest,
            effect_digest,
            dispatch_digest,
        })
    }

    pub fn validate_for(&self, effect: &EffectDescriptor) -> Result<(), ComponentContractError> {
        validate_component_token("transaction id", &self.transaction_id)?;
        if self.state_version == 0 {
            return Err(ComponentContractError::ZeroStateVersion);
        }
        let effect_digest = effect.digest();
        let dispatch_digest = derive_dispatch_digest(
            &self.transaction_id,
            self.generation,
            self.state_version,
            self.authority_binding_digest,
            self.authority_use_digest,
            effect,
            effect_digest,
        );
        if self.effect_digest != effect_digest || self.dispatch_digest != dispatch_digest {
            return Err(ComponentContractError::BindingMismatch);
        }
        Ok(())
    }
}

fn derive_dispatch_digest(
    transaction_id: &str,
    generation: u64,
    state_version: u64,
    authority_binding_digest: ComponentDigest,
    authority_use_digest: ComponentDigest,
    effect: &EffectDescriptor,
    effect_digest: ComponentDigest,
) -> ComponentDigest {
    let generation_bytes = generation.to_be_bytes();
    let state_version_bytes = state_version.to_be_bytes();
    let authority_binding_hex = authority_binding_digest.to_hex();
    let authority_use_hex = authority_use_digest.to_hex();
    let effect_hex = effect_digest.to_hex();
    hash_parts(
        DISPATCH_DOMAIN,
        &[
            transaction_id.as_bytes(),
            &generation_bytes,
            &state_version_bytes,
            authority_binding_hex.as_bytes(),
            authority_use_hex.as_bytes(),
            effect.provider.as_str().as_bytes(),
            effect.resource.as_str().as_bytes(),
            effect.operation.as_bytes(),
            effect_hex.as_bytes(),
        ],
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionDisposition {
    RejectedBeforeDispatch,
    Dispatched,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionOutcome {
    pub disposition: ExecutionDisposition,
    pub dispatch_digest: ComponentDigest,
    pub detail: String,
}

impl ExecutionOutcome {
    pub fn new(
        disposition: ExecutionDisposition,
        dispatch_digest: ComponentDigest,
        detail: impl Into<String>,
    ) -> Result<Self, ComponentContractError> {
        let detail = detail.into();
        validate_component_token("execution outcome detail", &detail)?;
        Ok(Self {
            disposition,
            dispatch_digest,
            detail,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationDisposition {
    Satisfied,
    NotSatisfied,
    Inconclusive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationOutcome {
    pub disposition: VerificationDisposition,
    pub detail: String,
}

impl VerificationOutcome {
    pub fn new(
        disposition: VerificationDisposition,
        detail: impl Into<String>,
    ) -> Result<Self, ComponentContractError> {
        let detail = detail.into();
        validate_component_token("verification outcome detail", &detail)?;
        Ok(Self {
            disposition,
            detail,
        })
    }
}

/// Transport-neutral shape for a deliberately narrow privileged component.
/// Implementors still require a separate authenticated authority handoff; this
/// trait does not make `ExecutionBinding` sufficient authorization.
pub trait PrivilegedExecutor: Send + Sync {
    type Request;

    fn execute_qualified(&self, request: Self::Request) -> ExecutionOutcome;
}

/// Independent verifier contract. Verification consumes expected postcondition
/// material plus fresh authoritative observation; executor receipts are not an
/// input and cannot prove machine state.
pub trait IndependentVerifier: Send + Sync {
    type Expectation;

    fn verify(
        &self,
        expectation: &Self::Expectation,
        observation: &ObservationEnvelope,
    ) -> VerificationOutcome;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        match value {
            Ok(value) => value,
            Err(error) => unreachable!("{error:?}"),
        }
    }

    fn digest(byte: u8) -> ComponentDigest {
        ComponentDigest::from_bytes([byte; 32])
    }

    fn effect(unit: &str) -> EffectDescriptor {
        id(EffectDescriptor::new(
            id(ProviderId::new("systemd")),
            id(ResourceId::new(format!("systemd:unit:{unit}"))),
            "restart-unit",
            unit.as_bytes().to_vec(),
        ))
    }

    #[test]
    fn digest_hex_round_trip_is_canonical() {
        let value = digest(0xab);
        assert_eq!(id(ComponentDigest::parse_hex(&value.to_hex())), value);
        assert_eq!(
            id(ComponentDigest::parse_hex(&value.to_hex().to_uppercase())),
            value
        );
        assert!(ComponentDigest::parse_hex("00").is_err());
        assert!(ComponentDigest::parse_hex(&"g".repeat(64)).is_err());
    }

    #[test]
    fn effect_identity_changes_with_provider_resource_operation_and_payload() {
        let base = effect("linura-v05-qualification-a.service");
        let provider = id(EffectDescriptor::new(
            id(ProviderId::new("different")),
            base.resource.clone(),
            base.operation.clone(),
            base.canonical_payload.clone(),
        ));
        let resource = effect("linura-v05-qualification-b.service");
        let operation = id(EffectDescriptor::new(
            base.provider.clone(),
            base.resource.clone(),
            "different-operation",
            base.canonical_payload.clone(),
        ));
        let payload = id(EffectDescriptor::new(
            base.provider.clone(),
            base.resource.clone(),
            base.operation.clone(),
            b"different".to_vec(),
        ));
        assert_ne!(base.digest(), provider.digest());
        assert_ne!(base.digest(), resource.digest());
        assert_ne!(base.digest(), operation.digest());
        assert_ne!(base.digest(), payload.digest());
    }

    #[test]
    fn durable_generation_zero_is_valid_executor_correlation_material() {
        let base_effect = effect("linura-v05-qualification-a.service");
        let binding = id(ExecutionBinding::new(
            "tx:zero-generation",
            0,
            2,
            digest(1),
            digest(2),
            &base_effect,
        ));
        assert_eq!(binding.generation, 0);
        assert!(binding.validate_for(&base_effect).is_ok());
    }

    #[test]
    fn dispatch_identity_binds_every_authority_and_effect_field() {
        let base_effect = effect("linura-v05-qualification-a.service");
        let base = id(ExecutionBinding::new(
            "tx:a",
            1,
            2,
            digest(1),
            digest(2),
            &base_effect,
        ));
        let candidates = [
            id(ExecutionBinding::new(
                "tx:b",
                1,
                2,
                digest(1),
                digest(2),
                &base_effect,
            )),
            id(ExecutionBinding::new(
                "tx:a",
                2,
                2,
                digest(1),
                digest(2),
                &base_effect,
            )),
            id(ExecutionBinding::new(
                "tx:a",
                1,
                3,
                digest(1),
                digest(2),
                &base_effect,
            )),
            id(ExecutionBinding::new(
                "tx:a",
                1,
                2,
                digest(3),
                digest(2),
                &base_effect,
            )),
            id(ExecutionBinding::new(
                "tx:a",
                1,
                2,
                digest(1),
                digest(3),
                &base_effect,
            )),
            id(ExecutionBinding::new(
                "tx:a",
                1,
                2,
                digest(1),
                digest(2),
                &effect("linura-v05-qualification-b.service"),
            )),
        ];
        for candidate in candidates {
            assert_ne!(base.dispatch_digest, candidate.dispatch_digest);
        }
    }

    #[test]
    fn substituted_effect_fails_exact_binding_validation() {
        let expected = effect("linura-v05-qualification-a.service");
        let substituted = effect("linura-v05-qualification-b.service");
        let binding = id(ExecutionBinding::new(
            "tx:a",
            1,
            1,
            digest(1),
            digest(2),
            &expected,
        ));
        assert_eq!(
            binding.validate_for(&substituted),
            Err(ComponentContractError::BindingMismatch)
        );
    }

    #[test]
    fn hostile_component_material_is_bounded() {
        let oversized = "x".repeat(MAX_COMPONENT_TOKEN_BYTES + 1);
        assert!(
            EffectDescriptor::new(
                id(ProviderId::new("systemd")),
                id(ResourceId::new("systemd:unit:test.service")),
                oversized,
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            EffectDescriptor::new(
                id(ProviderId::new("systemd")),
                id(ResourceId::new("systemd:unit:test.service")),
                "restart\nunit",
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            EffectDescriptor::new(
                id(ProviderId::new("systemd")),
                id(ResourceId::new("systemd:unit:test.service")),
                "restart-unit",
                vec![0; MAX_EFFECT_PAYLOAD_BYTES + 1],
            )
            .is_err()
        );
    }
}
