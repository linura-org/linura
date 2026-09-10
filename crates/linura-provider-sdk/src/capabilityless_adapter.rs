use linura_core::RequestId;
use linura_intent::{IntentProposal, ProposalAttribution, ProposalDigest};

use crate::interpretation::{
    AdapterDescriptor, HeaderField, InterpretationAdapter, InterpretationAdapterError,
    InterpretationRequest, PreparedProviderInvocation, SemanticValue,
};

const CAPABILITYLESS_REQUEST_DOMAIN: &[u8] = b"linura:capabilityless-adapter-request:v1";
const MAX_STATIC_HEADERS: usize = 32;
const MAX_MODEL_BYTES: usize = 256;
const MAX_PREFIX_BYTES: usize = 64 * 1024;

/// A capabilityless interpretation adapter whose behavior is entirely described
/// by bounded data owned by Linura.
///
/// Unlike arbitrary `InterpretationAdapter` implementations, this concrete type
/// cannot embed provider-specific Rust callbacks. It receives no filesystem,
/// environment, process, socket, DNS, credential or session handle. The only
/// operations available to it are deterministic encoding of an already-minimized
/// `InterpretationRequest` and bounded decoding of one complete response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilitylessInterpretationAdapter {
    descriptor: AdapterDescriptor,
    static_headers: Vec<HeaderField>,
    request_prefix: Vec<u8>,
    model: Option<String>,
}

impl CapabilitylessInterpretationAdapter {
    pub fn new(
        descriptor: AdapterDescriptor,
        static_headers: Vec<HeaderField>,
        request_prefix: Vec<u8>,
        model: Option<String>,
    ) -> Result<Self, InterpretationAdapterError> {
        descriptor.validate()?;
        if static_headers.len() > MAX_STATIC_HEADERS {
            return Err(InterpretationAdapterError::TooLarge(
                "capabilityless adapter static headers",
            ));
        }
        if request_prefix.len() > MAX_PREFIX_BYTES {
            return Err(InterpretationAdapterError::TooLarge(
                "capabilityless adapter request prefix",
            ));
        }
        if request_prefix.contains(&0) {
            return Err(InterpretationAdapterError::ControlCharacter(
                "capabilityless adapter request prefix",
            ));
        }
        if let Some(model_id) = &model
            && (model_id.trim().is_empty()
                || model_id.len() > MAX_MODEL_BYTES
                || model_id.chars().any(char::is_control))
        {
            return Err(InterpretationAdapterError::InvalidDescriptor(
                "capabilityless adapter model id is invalid".into(),
            ));
        }
        ProposalAttribution::provider(
            descriptor.provider.as_str(),
            descriptor.adapter_id.clone(),
            model.clone(),
        )
        .map_err(|error| InterpretationAdapterError::InvalidDescriptor(error.to_string()))?;
        for header in &static_headers {
            HeaderField::new(header.name.clone(), header.value.clone())?;
            validate_static_protocol_header(header)?;
        }
        Ok(Self {
            descriptor,
            static_headers,
            request_prefix,
            model,
        })
    }

    #[must_use]
    pub fn descriptor_ref(&self) -> &AdapterDescriptor {
        &self.descriptor
    }

    #[must_use]
    pub fn semantic_digest(&self) -> ProposalDigest {
        let mut owned = vec![
            self.descriptor.provider.as_str().as_bytes().to_vec(),
            self.descriptor.adapter_id.as_bytes().to_vec(),
            self.descriptor.endpoint_class.as_bytes().to_vec(),
            self.descriptor.protocol_version.to_be_bytes().to_vec(),
            self.descriptor.network_access.as_str().as_bytes().to_vec(),
            self.request_prefix.clone(),
            self.model.as_deref().unwrap_or("").as_bytes().to_vec(),
        ];
        for header in &self.static_headers {
            owned.push(header.name.as_bytes().to_vec());
            owned.push(header.value.as_bytes().to_vec());
        }
        let refs = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
        ProposalDigest::hash_parts(b"linura:capabilityless-adapter-config:v1", &refs)
    }

    fn encode_request(&self, request: &InterpretationRequest) -> Vec<u8> {
        let mut payload = Vec::new();
        push_bytes(&mut payload, CAPABILITYLESS_REQUEST_DOMAIN);
        push_bytes(&mut payload, &self.request_prefix);
        push_bytes(&mut payload, request.digest().to_hex().as_bytes());
        push_bytes(&mut payload, request.context.digest().to_hex().as_bytes());
        push_bytes(
            &mut payload,
            request.projection.digest().to_hex().as_bytes(),
        );
        push_u64(&mut payload, request.projection.entries().len() as u64);
        for entry in request.projection.entries() {
            push_bytes(&mut payload, entry.key.as_bytes());
            match &entry.value {
                SemanticValue::Text(value) => {
                    push_bytes(&mut payload, b"text");
                    push_bytes(&mut payload, value.as_bytes());
                }
                SemanticValue::ProtectedReference(value) => {
                    push_bytes(&mut payload, b"protected-reference");
                    push_bytes(&mut payload, value.as_bytes());
                }
                SemanticValue::Bool(value) => {
                    push_bytes(&mut payload, b"bool");
                    push_bytes(&mut payload, if *value { b"true" } else { b"false" });
                }
                SemanticValue::U64(value) => {
                    push_bytes(&mut payload, b"u64");
                    push_bytes(&mut payload, &value.to_be_bytes());
                }
                SemanticValue::I64(value) => {
                    push_bytes(&mut payload, b"i64");
                    push_bytes(&mut payload, &value.to_be_bytes());
                }
            }
        }
        push_u64(&mut payload, request.capability_refs.len() as u64);
        for capability in &request.capability_refs {
            push_bytes(&mut payload, capability.as_str().as_bytes());
        }
        payload
    }
}

impl InterpretationAdapter for CapabilitylessInterpretationAdapter {
    fn descriptor(&self) -> AdapterDescriptor {
        self.descriptor.clone()
    }

    fn prepare(
        &self,
        request: &InterpretationRequest,
    ) -> Result<PreparedProviderInvocation, InterpretationAdapterError> {
        request.validate()?;
        PreparedProviderInvocation::new(
            &self.descriptor,
            self.static_headers.clone(),
            self.encode_request(request),
        )
    }

    fn decode_complete(
        &self,
        request: &InterpretationRequest,
        response: &[u8],
    ) -> Result<IntentProposal, InterpretationAdapterError> {
        request.validate()?;
        let requested_outcome = std::str::from_utf8(response)
            .map_err(|error| InterpretationAdapterError::MalformedOutput(error.to_string()))?;
        if requested_outcome.trim().is_empty() {
            return Err(InterpretationAdapterError::MalformedOutput(
                "complete provider response is empty".into(),
            ));
        }
        let proposal_id = RequestId::new(format!(
            "proposal:capabilityless:{}",
            request.digest().to_hex()
        ))
        .map_err(|error| InterpretationAdapterError::MalformedOutput(error.to_string()))?;
        let attribution = ProposalAttribution::provider(
            self.descriptor.provider.as_str(),
            self.descriptor.adapter_id.clone(),
            self.model.clone(),
        )
        .map_err(|error| InterpretationAdapterError::MalformedOutput(error.to_string()))?;
        IntentProposal::new_v1(
            proposal_id,
            request.actor.clone(),
            requested_outcome,
            vec![],
            request.capability_refs.clone(),
            vec![],
            vec![],
            None,
            request.context.clone(),
            attribution,
            vec![],
        )
        .map_err(|error| InterpretationAdapterError::MalformedOutput(error.to_string()))
    }
}

fn validate_static_protocol_header(header: &HeaderField) -> Result<(), InterpretationAdapterError> {
    let name = header.name.to_ascii_lowercase();
    let value = header.value.to_ascii_lowercase();
    let safe_media_type = matches!(
        value.as_str(),
        "application/json"
            | "application/octet-stream"
            | "application/x-ndjson"
            | "text/event-stream"
    );
    if !matches!(name.as_str(), "accept" | "content-type") || !safe_media_type {
        return Err(InterpretationAdapterError::CredentialLikeMaterial);
    }
    Ok(())
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) {
    push_u64(output, value.len() as u64);
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use linura_core::{Actor, ActorId, ActorKind, ProviderId, ValidationError};
    use linura_intent::InterpretationContextBinding;

    use super::*;
    use crate::interpretation::{
        MinimizedSemanticProjection, NetworkAccess, SemanticEntry, SemanticValue,
    };

    fn id<T>(value: Result<T, ValidationError>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error}"))
    }

    fn descriptor() -> AdapterDescriptor {
        AdapterDescriptor {
            provider: id(ProviderId::new("provider:capabilityless-test")),
            adapter_id: "adapter:capabilityless-test".into(),
            endpoint_class: "interpretation".into(),
            protocol_version: 1,
            network_access: NetworkAccess::Required,
        }
    }

    fn request() -> InterpretationRequest {
        let projection = MinimizedSemanticProjection::new(vec![
            SemanticEntry::new("goal", SemanticValue::Text("configure workstation".into()))
                .unwrap_or_else(|error| unreachable!("{error}")),
        ])
        .unwrap_or_else(|error| unreachable!("{error}"));
        InterpretationRequest {
            request_id: id(RequestId::new("request:capabilityless-test")),
            actor: Actor {
                id: id(ActorId::new("uid:1000")),
                kind: ActorKind::Human,
                interactive: true,
            },
            context: InterpretationContextBinding::new(
                "authority:capabilityless-test",
                projection.digest(),
                vec![],
            )
            .unwrap_or_else(|error| unreachable!("{error}")),
            projection,
            capability_refs: vec![],
            max_response_bytes: 4096,
            attempt_deadline_unix_ms: 10_000,
        }
    }

    #[test]
    fn configuration_is_deterministic_and_credential_free() {
        let adapter = CapabilitylessInterpretationAdapter::new(
            descriptor(),
            vec![
                HeaderField::new("content-type", "application/octet-stream")
                    .unwrap_or_else(|error| unreachable!("{error}")),
            ],
            b"provider-neutral-prefix".to_vec(),
            Some("mock-model".into()),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let prepared_a = adapter
            .prepare(&request())
            .unwrap_or_else(|error| unreachable!("{error}"));
        let prepared_b = adapter
            .prepare(&request())
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(prepared_a, prepared_b);
        assert_eq!(adapter.semantic_digest(), adapter.semantic_digest());
        assert!(
            prepared_a
                .headers
                .iter()
                .all(|header| !header.name.eq_ignore_ascii_case("authorization"))
        );
    }

    #[test]
    fn complete_response_decodes_only_to_non_authoritative_proposal() {
        let adapter = CapabilitylessInterpretationAdapter::new(
            descriptor(),
            vec![],
            vec![],
            Some("mock-model".into()),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let proposal = adapter
            .decode_complete(&request(), b"Configure a reproducible workstation")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(proposal.validate(), Ok(()));
        assert!(!proposal.attribution.manual);
        assert_eq!(
            proposal.attribution.provider.as_deref(),
            Some("provider:capabilityless-test")
        );
    }

    #[test]
    fn credential_like_static_header_is_rejected_before_registration() {
        let result = HeaderField::new("Authorization", "Bearer canary");
        assert!(matches!(
            result,
            Err(InterpretationAdapterError::CredentialLikeMaterial)
        ));
    }

    #[test]
    fn vendor_credential_headers_are_rejected_by_capabilityless_configuration() {
        for name in [
            "x-goog-api-key",
            "x-azure-key",
            "x-vendor-token",
            "x-custom",
        ] {
            let header = HeaderField::new(name, "secret-canary")
                .unwrap_or_else(|error| unreachable!("{error}"));
            let result = CapabilitylessInterpretationAdapter::new(
                descriptor(),
                vec![header],
                vec![],
                Some("mock-model".into()),
            );
            assert!(matches!(
                result,
                Err(InterpretationAdapterError::CredentialLikeMaterial)
            ));
        }
    }
}
