//! The sole codec for restart-readable canonical desired requests. Its bytes
//! exactly match the existing durable request digest, including domain framing.

use std::collections::BTreeMap;

use linura_core::{
    CapabilityId, IntentId, PrincipalId, ProviderId, RequestId, RequirementId, ResourceId,
    SemanticReason,
};
use linura_protocol::PlanDesiredStateRequest;
use linura_transaction::{MAX_RETAINED_REQUEST_BYTES, RetainedRequest};

use crate::ManagedLifecycleError;

const DOMAIN: &str = "linura.control.desired-request.v1";
const MAX_ENTRIES: usize = 1024;

fn invalid() -> ManagedLifecycleError {
    ManagedLifecycleError::Authority(
        "retained structured request is malformed or noncanonical".into(),
    )
}

pub(crate) fn encode(
    principal: PrincipalId,
    request: &PlanDesiredStateRequest,
) -> Result<RetainedRequest, ManagedLifecycleError> {
    if [
        request.reason.intent_ids.len(),
        request.reason.requirement_ids.len(),
        request.reason.capability_ids.len(),
        request.desired_state.len(),
    ]
    .iter()
    .any(|count| *count > MAX_ENTRIES)
    {
        return Err(invalid());
    }
    request.reason.validate().map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    field(&mut bytes, DOMAIN.as_bytes())?;
    for value in [
        request.request_id.as_str(),
        request.provider.as_str(),
        request.resource.as_str(),
        request.observation_capability.as_str(),
        &request.reason.summary,
    ] {
        field(&mut bytes, value.as_bytes())?;
    }
    count(&mut bytes, request.reason.intent_ids.len())?;
    for id in &request.reason.intent_ids {
        field(&mut bytes, id.as_str().as_bytes())?;
    }
    count(&mut bytes, request.reason.requirement_ids.len())?;
    for id in &request.reason.requirement_ids {
        field(&mut bytes, id.as_str().as_bytes())?;
    }
    count(&mut bytes, request.reason.capability_ids.len())?;
    for id in &request.reason.capability_ids {
        field(&mut bytes, id.as_str().as_bytes())?;
    }
    count(&mut bytes, request.desired_state.len())?;
    for (key, value) in &request.desired_state {
        field(&mut bytes, key.as_bytes())?;
        field(&mut bytes, value.as_bytes())?;
    }
    RetainedRequest::new(principal, request.request_id.clone(), bytes).map_err(|_| invalid())
}

fn field(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), ManagedLifecycleError> {
    if value.len() > MAX_RETAINED_REQUEST_BYTES
        || bytes
            .len()
            .checked_add(8)
            .and_then(|n| n.checked_add(value.len()))
            .is_none_or(|n| n > MAX_RETAINED_REQUEST_BYTES)
    {
        return Err(invalid());
    }
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn count(bytes: &mut Vec<u8>, entries: usize) -> Result<(), ManagedLifecycleError> {
    if entries > MAX_ENTRIES {
        return Err(invalid());
    }
    field(bytes, &(entries as u64).to_be_bytes())
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn field(&mut self) -> Result<&'a [u8], ManagedLifecycleError> {
        let (length, rest) = self.0.split_at_checked(8).ok_or_else(invalid)?;
        let length = u64::from_be_bytes(length.try_into().map_err(|_| invalid())?);
        let length = usize::try_from(length).map_err(|_| invalid())?;
        let (value, rest) = rest.split_at_checked(length).ok_or_else(invalid)?;
        self.0 = rest;
        Ok(value)
    }

    fn text(&mut self) -> Result<String, ManagedLifecycleError> {
        std::str::from_utf8(self.field()?)
            .map(str::to_owned)
            .map_err(|_| invalid())
    }

    fn count(&mut self) -> Result<usize, ManagedLifecycleError> {
        let count = u64::from_be_bytes(self.field()?.try_into().map_err(|_| invalid())?);
        let count = usize::try_from(count).map_err(|_| invalid())?;
        if count > MAX_ENTRIES {
            return Err(invalid());
        }
        Ok(count)
    }
}

pub(crate) fn decode(
    record: &RetainedRequest,
) -> Result<PlanDesiredStateRequest, ManagedLifecycleError> {
    let mut reader = Reader(record.canonical());
    if reader.field()? != DOMAIN.as_bytes() {
        return Err(invalid());
    }
    let request_id = RequestId::new(reader.text()?).map_err(|_| invalid())?;
    if &request_id != record.request_id() {
        return Err(invalid());
    }
    let provider = ProviderId::new(reader.text()?).map_err(|_| invalid())?;
    let resource = ResourceId::new(reader.text()?).map_err(|_| invalid())?;
    let observation_capability = CapabilityId::new(reader.text()?).map_err(|_| invalid())?;
    let summary = reader.text()?;
    let mut intent_ids = Vec::new();
    for _ in 0..reader.count()? {
        intent_ids.push(IntentId::new(reader.text()?).map_err(|_| invalid())?);
    }
    let mut requirement_ids = Vec::new();
    for _ in 0..reader.count()? {
        requirement_ids.push(RequirementId::new(reader.text()?).map_err(|_| invalid())?);
    }
    let mut capability_ids = Vec::new();
    for _ in 0..reader.count()? {
        capability_ids.push(CapabilityId::new(reader.text()?).map_err(|_| invalid())?);
    }
    let reason = SemanticReason {
        summary,
        intent_ids,
        requirement_ids,
        capability_ids,
    };
    reason.validate().map_err(|_| invalid())?;
    let mut desired_state = BTreeMap::new();
    for _ in 0..reader.count()? {
        if desired_state
            .insert(reader.text()?, reader.text()?)
            .is_some()
        {
            return Err(invalid());
        }
    }
    if !reader.0.is_empty() {
        return Err(invalid());
    }
    let request = PlanDesiredStateRequest {
        request_id,
        provider,
        resource,
        observation_capability,
        reason,
        desired_state,
    };
    // Reject alternate key order, duplicate keys/origins, or trailing encodings.
    if encode(record.principal().clone(), &request)?.canonical() != record.canonical() {
        return Err(invalid());
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }

    fn principal() -> PrincipalId {
        value(PrincipalId::new("unix:uid:1000"))
    }

    fn request() -> PlanDesiredStateRequest {
        PlanDesiredStateRequest {
            request_id: value(RequestId::new("request:codec:a")),
            provider: value(ProviderId::new("session-locker")),
            resource: value(ResourceId::new("resource:codec")),
            observation_capability: value(CapabilityId::new("session.secure-lock.observe")),
            reason: SemanticReason {
                summary: "Protect my session — 保護".into(),
                intent_ids: vec![value(IntentId::new("intent:protect"))],
                requirement_ids: vec![value(RequirementId::new("requirement:private"))],
                capability_ids: vec![value(CapabilityId::new("capability:lock"))],
            },
            desired_state: BTreeMap::from([
                ("secure".into(), "true".into()),
                ("z".into(), "last".into()),
            ]),
        }
    }

    #[test]
    fn exact_bytes_roundtrip_and_match_the_existing_authority_digest() {
        let request = request();
        let retained = value(encode(principal(), &request));
        assert_eq!(value(decode(&retained)), request);
        assert_eq!(
            retained.digest(),
            &value(crate::durable_authority::digest_request(&request))
        );
        assert!(!format!("{retained:?}").contains(&request.reason.summary));
    }

    #[test]
    fn truncated_trailing_wrong_domain_and_wrong_request_namespace_are_rejected() {
        let request = request();
        let retained = value(encode(principal(), &request));
        for length in 1..retained.canonical().len() {
            let truncated = value(RetainedRequest::new(
                principal(),
                request.request_id.clone(),
                retained.canonical()[..length].to_vec(),
            ));
            assert!(decode(&truncated).is_err());
        }
        let mut trailing = retained.canonical().to_vec();
        trailing.push(0);
        assert!(
            decode(&value(RetainedRequest::new(
                principal(),
                request.request_id.clone(),
                trailing
            )))
            .is_err()
        );
        let mut wrong_domain = retained.canonical().to_vec();
        wrong_domain[8] ^= 1;
        assert!(
            decode(&value(RetainedRequest::new(
                principal(),
                request.request_id.clone(),
                wrong_domain
            )))
            .is_err()
        );
        assert!(
            decode(&value(RetainedRequest::new(
                principal(),
                value(RequestId::new("request:other")),
                retained.canonical().to_vec()
            )))
            .is_err()
        );
    }

    #[test]
    fn malformed_and_excessive_count_cannot_allocate_from_untrusted_length() {
        for bytes in [
            u64::MAX.to_be_bytes().to_vec(),
            vec![0; 7],
            [8_u64.to_be_bytes(), u64::MAX.to_be_bytes()].concat(),
        ] {
            assert!(Reader(&bytes).count().is_err());
        }
        let mut request = request();
        request.reason.intent_ids = vec![value(IntentId::new("intent:many")); MAX_ENTRIES + 1];
        assert!(encode(principal(), &request).is_err());
        request.reason.intent_ids.truncate(2);
        assert!(encode(principal(), &request).is_err());
    }

    #[test]
    fn duplicate_or_unsorted_keys_are_not_alternative_canonical_encodings() {
        let mut request = request();
        request.desired_state =
            BTreeMap::from([("a".into(), "one".into()), ("b".into(), "two".into())]);
        let retained = value(encode(principal(), &request));
        let suffix = 8 + 1 + 8 + 3;
        let key_offset = retained.canonical().len() - 2 * suffix + 8;
        let mut duplicate = retained.canonical().to_vec();
        duplicate[key_offset + suffix] = b'a';
        assert!(
            decode(&value(RetainedRequest::new(
                principal(),
                request.request_id.clone(),
                duplicate
            )))
            .is_err()
        );
        let mut unsorted = retained.canonical().to_vec();
        unsorted[key_offset] = b'b';
        unsorted[key_offset + suffix] = b'a';
        assert!(
            decode(&value(RetainedRequest::new(
                principal(),
                request.request_id.clone(),
                unsorted
            )))
            .is_err()
        );
    }

    #[test]
    fn aggregate_bound_and_utf8_are_enforced() {
        let mut request = request();
        request.reason.summary = "x".repeat(MAX_RETAINED_REQUEST_BYTES);
        assert!(encode(principal(), &request).is_err());
        let retained = value(encode(principal(), &self::request()));
        let mut invalid_utf8 = retained.canonical().to_vec();
        *invalid_utf8.last_mut().unwrap_or_else(|| unreachable!()) = 0xff;
        assert!(
            decode(&value(RetainedRequest::new(
                principal(),
                retained.request_id().clone(),
                invalid_utf8
            )))
            .is_err()
        );
    }
}
