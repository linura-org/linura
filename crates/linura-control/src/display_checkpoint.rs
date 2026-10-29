//! Immutable historical native baseline in the existing authenticated journal.
//! It cannot mint an approval, dispatch permit or cross-compositor continuity.
use std::collections::BTreeMap;

use linura_core::{DisplayLayoutMaterial, PrincipalId, RequestId};
use linura_observation::{
    DisplayObservationFacts, ObservationAuthority, ObservationEnvelope, ObservedValue,
};
use linura_protocol::PlanDesiredStateRequest;
use linura_transaction::{
    ApprovedRequestJournal, ContentDigest, RetainedRequest, TransactionSnapshot,
};

use crate::{ManagedLifecycleError, PreparedDurableAuthority};

const DOMAIN: &str = "linura.display.native-baseline.v1";
const MAX_BYTES: usize = 128 * 1024;
const MAX_ATTRIBUTES: usize = 133;

fn invalid() -> ManagedLifecycleError {
    ManagedLifecycleError::Authority(
        "native display recovery checkpoint is missing, inconsistent or unsupported".into(),
    )
}

pub(crate) fn require_baseline(
    observation: &ObservationEnvelope,
    request: &PlanDesiredStateRequest,
    at: u64,
) -> Result<(), ManagedLifecycleError> {
    let text = request.desired_state.get("layout").ok_or_else(invalid)?;
    let material = DisplayLayoutMaterial::decode(text).map_err(|_| invalid())?;
    let mut native = observation.clone();
    for key in [
        "control.display_session_digest",
        "control.display_coverage_digest",
    ] {
        match native.attributes.remove(key) {
            Some(ObservedValue::Text(digest))
                if ContentDigest::new(digest.as_str())
                    .is_ok_and(|digest| digest != ContentDigest::zero()) => {}
            _ => return Err(invalid()),
        }
    }
    let facts = DisplayObservationFacts::from_envelope(&native, material.topology(), at)
        .map_err(|_| invalid())?;
    let intent = material
        .validate_native(facts.inventory(), facts.capabilities())
        .map_err(|_| invalid())?;
    if facts.recovery_metadata().is_none()
        || facts.layout() != intent.baseline()
        || !facts.has_powered_independent_output()
    {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct Checkpoint {
    canonical: Vec<u8>,
}

impl Checkpoint {
    pub(crate) fn capture(
        prepared: &PreparedDurableAuthority,
        request: &PlanDesiredStateRequest,
        now: u64,
    ) -> Result<Self, ManagedLifecycleError> {
        let observation = prepared.display_checkpoint_observation();
        require_baseline(observation, request, now)?;
        if crate::durable_authority::digest_observation(observation)?
            != *prepared.binding().observation_digest()
        {
            return Err(invalid());
        }
        Self::encode(request, prepared.snapshot(), observation)
    }

    fn key(request: &PlanDesiredStateRequest) -> Result<RequestId, ManagedLifecycleError> {
        RequestId::new(format!(
            "request:v010:display-native-baseline:{}",
            crate::durable_authority::digest_request(request)?.hex()
        ))
        .map_err(|_| invalid())
    }

    fn encode(
        request: &PlanDesiredStateRequest,
        snapshot: &TransactionSnapshot,
        observation: &ObservationEnvelope,
    ) -> Result<Self, ManagedLifecycleError> {
        if observation.attributes.len() > MAX_ATTRIBUTES {
            return Err(invalid());
        }
        let request_digest = crate::durable_authority::digest_request(request)?;
        let observation_digest = crate::durable_authority::digest_observation(observation)?;
        let mut canonical = Vec::new();
        for value in [
            DOMAIN,
            request_digest.as_str(),
            snapshot.transaction_id.as_str(),
            &snapshot.current_generation.to_string(),
            snapshot.binding_digest.as_str(),
            observation_digest.as_str(),
            &observation.observed_at_unix_ms.to_string(),
            &observation.valid_for_ms.to_string(),
            &observation.sequence.to_string(),
            &observation.attributes.len().to_string(),
        ] {
            field(&mut canonical, value)?;
        }
        for (key, value) in &observation.attributes {
            if key.len() > 128 {
                return Err(invalid());
            }
            field(&mut canonical, key)?;
            match value {
                ObservedValue::Text(value) => {
                    field(&mut canonical, "text")?;
                    field(&mut canonical, value)?;
                }
                ObservedValue::Bool(value) => {
                    field(&mut canonical, "bool")?;
                    field(&mut canonical, if *value { "true" } else { "false" })?;
                }
                ObservedValue::U64(value) => {
                    field(&mut canonical, "u64")?;
                    field(&mut canonical, &value.to_string())?;
                }
                ObservedValue::I64(_) => return Err(invalid()),
            }
        }
        Ok(Self { canonical })
    }

    pub(crate) fn append(
        &self,
        journal: &mut dyn ApprovedRequestJournal,
        principal: PrincipalId,
        request: &PlanDesiredStateRequest,
    ) -> Result<(), ManagedLifecycleError> {
        journal
            .retain(
                &RetainedRequest::new(principal, Self::key(request)?, self.canonical.clone())
                    .map_err(|_| invalid())?,
            )
            .map_err(|error| ManagedLifecycleError::Authority(error.to_string()))
    }

    pub(crate) fn load(
        journal: &dyn ApprovedRequestJournal,
        request: &PlanDesiredStateRequest,
        snapshot: &TransactionSnapshot,
        now: u64,
    ) -> Result<Self, ManagedLifecycleError> {
        let key = Self::key(request)?;
        let retained = journal
            .load(&snapshot.principal, &key)
            .map_err(|_| invalid())?;
        if retained.principal() != &snapshot.principal || retained.request_id() != &key {
            return Err(invalid());
        }
        Self::decode(retained.canonical(), request, snapshot, now)
    }

    fn decode(
        bytes: &[u8],
        request: &PlanDesiredStateRequest,
        snapshot: &TransactionSnapshot,
        now: u64,
    ) -> Result<Self, ManagedLifecycleError> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        let mut reader = Reader(bytes);
        if reader.text()? != DOMAIN
            || reader.text()? != crate::durable_authority::digest_request(request)?.as_str()
            || reader.text()? != snapshot.transaction_id.as_str()
            || reader.number()? != snapshot.current_generation
            || reader.text()? != snapshot.binding_digest.as_str()
            || request.request_id != snapshot.request_id
            || snapshot.transaction_id
                != linura_transaction::TransactionId::for_namespace(
                    &snapshot.principal,
                    &request.request_id,
                )
        {
            return Err(invalid());
        }
        let digest = ContentDigest::new(reader.text()?).map_err(|_| invalid())?;
        let observed_at_unix_ms = reader.number()?;
        let valid_for_ms = reader.number()?;
        let sequence = reader.number()?;
        let count = reader.number()?;
        if count > MAX_ATTRIBUTES as u64 || observed_at_unix_ms > now {
            return Err(invalid());
        }
        let mut attributes = BTreeMap::new();
        for _ in 0..count {
            let key = reader.text()?;
            if key.len() > 128 {
                return Err(invalid());
            }
            let kind = reader.text()?;
            let value = match kind {
                "text" => ObservedValue::Text(reader.text()?.into()),
                "u64" => ObservedValue::U64(reader.number()?),
                "bool" => ObservedValue::Bool(match reader.text()? {
                    "true" => true,
                    "false" => false,
                    _ => return Err(invalid()),
                }),
                _ => return Err(invalid()),
            };
            if attributes.insert(key.into(), value).is_some() {
                return Err(invalid());
            }
        }
        if !reader.0.is_empty() {
            return Err(invalid());
        }
        let historical = ObservationEnvelope {
            provider: request.provider.clone(),
            resource: request.resource.clone(),
            capability: request.observation_capability.clone(),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms,
            valid_for_ms,
            sequence,
            attributes,
        };
        // Validate historical shape at its ORIGINAL timestamp. This deliberately
        // does not return it as current evidence or refresh its lifetime.
        require_baseline(&historical, request, observed_at_unix_ms)?;
        if crate::durable_authority::digest_observation(&historical)? != digest {
            return Err(invalid());
        }
        let result = Self::encode(request, snapshot, &historical)?;
        if result.canonical != bytes {
            return Err(invalid());
        }
        Ok(result)
    }
}

fn field(out: &mut Vec<u8>, value: &str) -> Result<(), ManagedLifecycleError> {
    if value.len() > 4096 || out.len().saturating_add(8).saturating_add(value.len()) > MAX_BYTES {
        return Err(invalid());
    }
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn text(&mut self) -> Result<&'a str, ManagedLifecycleError> {
        let (length, tail) = self.0.split_at_checked(8).ok_or_else(invalid)?;
        let length = usize::try_from(u64::from_be_bytes(
            length.try_into().map_err(|_| invalid())?,
        ))
        .map_err(|_| invalid())?;
        if length > 4096 {
            return Err(invalid());
        }
        let (field, tail) = tail.split_at_checked(length).ok_or_else(invalid)?;
        self.0 = tail;
        std::str::from_utf8(field).map_err(|_| invalid())
    }
    fn number(&mut self) -> Result<u64, ManagedLifecycleError> {
        let raw = self.text()?;
        let value: u64 = raw.parse().map_err(|_| invalid())?;
        if value.to_string() != raw {
            return Err(invalid());
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{
        CapabilityId, DisplayLayout, DisplayMode, DisplayOutputId, DisplayOutputLayout,
        DisplayOutputSet, DisplayScale, DisplayTopologyId, DisplayTransform, IntentId,
        NativeOutputCapabilities, ProviderId, ResourceId, SemanticReason, SessionLockId,
    };
    use linura_observation::{DisplayRecoveryMetadata, display_recovery_observation_attributes};
    use linura_transaction::{TransactionId, TransactionState, TransactionStoreError};
    use std::collections::BTreeSet;

    fn id<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    fn fixture() -> (
        PlanDesiredStateRequest,
        TransactionSnapshot,
        ObservationEnvelope,
    ) {
        let topology = id(DisplayTopologyId::from_resource(&id(ResourceId::new(
            "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3",
        ))));
        let output = id(DisplayOutputId::new(topology.clone(), 1, 2));
        let inventory = id(DisplayOutputSet::new(
            topology.clone(),
            vec![output.clone()],
        ));
        let mode = id(DisplayMode::new(1920, 1080, 60000));
        let capabilities = vec![id(NativeOutputCapabilities::new(
            output.clone(),
            vec![mode],
            true,
        ))];
        let layout = id(DisplayLayout::new(
            &inventory,
            &capabilities,
            vec![DisplayOutputLayout::Enabled {
                output: output.clone(),
                mode,
                scale: id(DisplayScale::new(1000)),
                transform: DisplayTransform::Normal,
                x: 0,
                y: 0,
                mirror: None,
            }],
        ));
        let lock = id(SessionLockId::from_resource(&id(ResourceId::new(
            "session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1",
        ))));
        let request = id(crate::DisplayLayoutPlanRequest {
            request_id: id(RequestId::new("request:v010:display-layout:checkpoint")),
            baseline: layout.clone(),
            layout: layout.clone(),
            lock,
            reason: SemanticReason {
                summary: "Restore the retained display baseline".into(),
                intent_ids: vec![id(IntentId::new("intent:checkpoint"))],
                requirement_ids: vec![],
                capability_ids: vec![],
            },
        }
        .desired_request());
        let principal = id(PrincipalId::new("unix:uid:1000"));
        let snapshot = TransactionSnapshot {
            transaction_id: TransactionId::for_namespace(&principal, &request.request_id),
            principal,
            request_id: request.request_id.clone(),
            current_generation: 1,
            state_version: 2,
            state: TransactionState::Indeterminate,
            binding_digest: id(ContentDigest::new(format!("sha256:{}", "c".repeat(64)))),
        };
        let mut attributes = id(display_recovery_observation_attributes(
            &inventory,
            &capabilities,
            &layout,
            &BTreeSet::from([output.clone()]),
            &BTreeMap::from([(
                output,
                id(DisplayRecoveryMetadata::new(
                    true,
                    "a".repeat(64),
                    "b".repeat(64),
                )),
            )]),
        ));
        for key in [
            "control.display_session_digest",
            "control.display_coverage_digest",
        ] {
            attributes.insert(
                key.into(),
                ObservedValue::Text(format!("sha256:{}", "d".repeat(64))),
            );
        }
        let observation = ObservationEnvelope {
            provider: id(ProviderId::new("hyprland")),
            resource: id(topology.resource_id()),
            capability: id(CapabilityId::new("display.outputs.observe")),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: 1000,
            valid_for_ms: 2000,
            sequence: 1,
            attributes,
        };
        (request, snapshot, observation)
    }
    #[derive(Debug)]
    struct Journal(Option<RetainedRequest>);
    impl ApprovedRequestJournal for Journal {
        fn retain(&mut self, record: &RetainedRequest) -> Result<(), TransactionStoreError> {
            if self.0.as_ref().is_some_and(|old| old != record) {
                return Err(TransactionStoreError::AuthorityRejected);
            }
            self.0 = Some(record.clone());
            Ok(())
        }
        fn load(
            &self,
            _: &PrincipalId,
            _: &RequestId,
        ) -> Result<RetainedRequest, TransactionStoreError> {
            self.0.clone().ok_or(TransactionStoreError::NotFound)
        }
        fn integrity_check(&self) -> Result<(), TransactionStoreError> {
            Ok(())
        }
    }
    #[test]
    fn checkpoint_is_immutable_historical_and_cannot_be_promoted_into_current_evidence() {
        let (request, snapshot, observation) = fixture();
        id(require_baseline(&observation, &request, 1000));
        assert!(require_baseline(&observation, &request, 3000).is_err());
        let checkpoint = id(Checkpoint::encode(&request, &snapshot, &observation));
        let mut journal = Journal(None);
        id(checkpoint.append(&mut journal, snapshot.principal.clone(), &request));
        id(checkpoint.append(&mut journal, snapshot.principal.clone(), &request));
        let recovered = id(Checkpoint::load(&journal, &request, &snapshot, 30_000));
        assert_eq!(recovered.canonical, checkpoint.canonical);
        let mut changed = observation.clone();
        changed
            .attributes
            .insert("output.0.linura_owned".into(), ObservedValue::Bool(false));
        assert!(
            id(Checkpoint::encode(&request, &snapshot, &changed))
                .append(&mut journal, snapshot.principal.clone(), &request)
                .is_err()
        );
        assert!(Checkpoint::load(&journal, &request, &snapshot, 999).is_err());
        assert!(Checkpoint::load(&Journal(None), &request, &snapshot, 3000).is_err());
    }
    #[test]
    fn checkpoint_rejects_substitution_unknown_schema_truncation_and_exhaustion() {
        let (request, snapshot, observation) = fixture();
        let checkpoint = id(Checkpoint::encode(&request, &snapshot, &observation));
        for size in [0, 7, 100, checkpoint.canonical.len() - 1] {
            assert!(
                Checkpoint::decode(&checkpoint.canonical[..size], &request, &snapshot, 3000)
                    .is_err()
            );
        }
        let mut appended = checkpoint.canonical.clone();
        appended.push(0);
        assert!(Checkpoint::decode(&appended, &request, &snapshot, 3000).is_err());
        assert!(Checkpoint::decode(&vec![0; MAX_BYTES + 1], &request, &snapshot, 3000).is_err());
        let mut malformed = checkpoint.canonical.clone();
        malformed[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(Checkpoint::decode(&malformed, &request, &snapshot, 3000).is_err());
        let malformed = checkpoint
            .canonical
            .windows(DOMAIN.len())
            .position(|value| value == DOMAIN.as_bytes())
            .unwrap_or_else(|| unreachable!("domain"));
        let mut unknown = checkpoint.canonical.clone();
        unknown[malformed + DOMAIN.len() - 1] = b'2';
        assert!(Checkpoint::decode(&unknown, &request, &snapshot, 3000).is_err());
        for field in [
            "binding",
            "generation",
            "principal",
            "request",
            "transaction",
        ] {
            let mut other = snapshot.clone();
            match field {
                "binding" => other.binding_digest = ContentDigest::zero(),
                "generation" => other.current_generation += 1,
                "principal" => other.principal = id(PrincipalId::new("unix:uid:1001")),
                "request" => other.request_id = id(RequestId::new("request:other")),
                _ => other.transaction_id = id(TransactionId::new("transaction:other")),
            }
            assert!(
                Checkpoint::decode(&checkpoint.canonical, &request, &other, 3000).is_err(),
                "{field}"
            );
        }
        let wrong_key = id(RetainedRequest::new(
            snapshot.principal.clone(),
            id(RequestId::new("request:other")),
            checkpoint.canonical,
        ));
        assert!(Checkpoint::load(&Journal(Some(wrong_key)), &request, &snapshot, 3000).is_err());
        let mut read_only = observation.clone();
        read_only
            .attributes
            .insert("display_schema".into(), ObservedValue::U64(1));
        for key in [
            "output.0.linura_owned",
            "output.0.base_configuration_digest",
            "output.0.native_identity_digest",
        ] {
            read_only.attributes.remove(key);
        }
        assert!(require_baseline(&read_only, &request, 1000).is_err());
    }
}
