//! Immutable history of independently verified first ordinary presentation.
//! This records PhysicalReleaseVerified, with every remaining fence held. It
//! contains no approval, continuation permit or claim of ReleasedCurrent.
use super::*;
use linura_core::DisplayFinalizationMaterial;
use linura_observation::{DisplayNativeHandoffFacts, ObservedValue};

pub(crate) mod completion;
pub(crate) mod current;

const DOMAIN: &str = "linura.display.original-physical-release-verified.v1";
const KEY_DOMAIN: &str = "linura.display.original-physical-release-verified-key.v1";
const FRAME_DOMAIN: &str = "linura.display.original-first-ordinary-frame.v1";
const MAX_BYTES: usize = 24 * 1024;
const HEADER_FIELDS: usize = 16;

/// Historical evidence only. A load always requires authenticated terminal
/// history, the original spent anchor and a NEW independently joined proof.
/// Neither restart nor an identical journal entry can recover effect authority.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct NativeHandoffVerified {
    principal: PrincipalId,
    request: RequestId,
    canonical: Vec<u8>,
    observed_at: u64,
    expiry: u64,
}

fn append(bytes: &mut Vec<u8>, value: &str) -> Result<(), ManagedLifecycleError> {
    if value.is_empty()
        || bytes
            .len()
            .checked_add(8)
            .and_then(|size| size.checked_add(value.len()))
            .is_none_or(|size| size > MAX_BYTES)
    {
        return Err(invalid());
    }
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

// Canonical immutable frame identity. Observation timestamps may advance on a
// read; deadlines, complete output inventory, KMS IDs and first commits cannot.
fn frame_bytes(facts: &DisplayNativeHandoffFacts) -> Result<Vec<u8>, ManagedLifecycleError> {
    let mut bytes = Vec::new();
    append(&mut bytes, FRAME_DOMAIN)?;
    for (key, value) in facts.attributes() {
        if key == "sampled_boot_ms" {
            continue;
        }
        append(&mut bytes, &key)?;
        let (kind, text) = match value {
            ObservedValue::Text(text) => ("text", text),
            ObservedValue::Bool(value) => ("bool", value.to_string()),
            ObservedValue::U64(value) => ("u64", value.to_string()),
            _ => return Err(invalid()),
        };
        append(&mut bytes, kind)?;
        append(&mut bytes, &text)?;
    }
    Ok(bytes)
}

impl NativeHandoffVerified {
    /// Historical comparison only, against a fresh independently authenticated
    /// Root lifetime. Expired first-frame history cannot become current native
    /// evidence, reconstruct approval or rearm any execution continuation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn load_comparison(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
        snapshot: &TransactionSnapshot,
        dispatch: &str,
        parent: &NativeReleaseSpendPrepared,
        first: &DisplayNativeHandoffFacts,
    ) -> Result<Self, ManagedLifecycleError> {
        if snapshot.principal != *principal
            || snapshot.request_id != request.request_id
            || snapshot.state != TransactionState::Indeterminate
            || snapshot.transaction_id
                != linura_transaction::TransactionId::for_namespace(principal, &request.request_id)
            || first.lineage().terminal_transaction != snapshot.transaction_id.as_str()
            || first.lineage().terminal_dispatch != dispatch
        {
            return Err(invalid());
        }
        journal.integrity_check().map_err(|_| invalid())?;
        let key = Self::key(&request.request_id)?;
        let retained = journal.load(principal, &key).map_err(|_| invalid())?;
        if retained.principal() != principal
            || retained.request_id() != &key
            || retained.canonical().len() > MAX_BYTES
        {
            return Err(invalid());
        }
        let mut rest = retained.canonical();
        let expected = [
            DOMAIN.into(),
            principal.as_str().into(),
            request.request_id.as_str().into(),
            snapshot.transaction_id.as_str().into(),
            crate::durable_authority::digest_request(request)?
                .as_str()
                .into(),
            snapshot.current_generation.to_string(),
            snapshot.state_version.to_string(),
            snapshot.binding_digest.as_str().into(),
            dispatch.into(),
            parent.digest().as_str().into(),
        ];
        for value in expected {
            if field(&mut rest, 256)? != value {
                return Err(invalid());
            }
        }
        if ContentDigest::new(field(&mut rest, 256)?).map_err(|_| invalid())?
            == ContentDigest::zero()
        {
            return Err(invalid());
        }
        let wall = number(field(&mut rest, 20)?)?;
        let boot = number(field(&mut rest, 20)?)?;
        let observed_at = number(field(&mut rest, 20)?)?;
        let expiry = number(field(&mut rest, 20)?)?;
        let bytes = frame_bytes(first)?;
        if field(&mut rest, 256)? != digest_bytes(FRAME_DOMAIN, &bytes).as_str()
            || rest != bytes
            || wall > observed_at
            || observed_at >= expiry
            || expiry > parent.expiry()
            || expiry - wall > 2000
            || wall > first.window().observed_unix_ms
            || boot > first.window().observed_boot_ms
            || expiry > first.window().deadline_unix_ms
        {
            return Err(invalid());
        }
        Ok(Self {
            principal: principal.clone(),
            request: request.request_id.clone(),
            canonical: retained.canonical().to_vec(),
            observed_at,
            expiry,
        })
    }

    fn key(request: &RequestId) -> Result<RequestId, ManagedLifecycleError> {
        RequestId::new(format!(
            "request:v010:display-physical-verified:{}",
            digest_bytes(KEY_DOMAIN, request.as_str().as_bytes()).hex()
        ))
        .map_err(|_| invalid())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture(
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
        snapshot: &TransactionSnapshot,
        dispatch: &str,
        material: &str,
        parent: &NativeReleaseSpendPrepared,
        observation: &ObservationEnvelope,
        frames: &DisplayNativeHandoffFacts,
        now: u64,
    ) -> Result<Self, ManagedLifecycleError> {
        let effect =
            linura_provider_sdk::display_finalization_effect(material).map_err(|_| invalid())?;
        let decoded = DisplayFinalizationMaterial::decode(material).map_err(|_| invalid())?;
        let scope = decoded.recovery_scope().map_err(|_| invalid())?;
        let lineage = frames.lineage();
        observation.require_current(now).map_err(|_| invalid())?;
        let window = frames.window();
        let frame_expiry = window
            .observed_unix_ms
            .checked_add(window.valid_for_ms().map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        let expiry = observation
            .observed_at_unix_ms
            .checked_add(observation.valid_for_ms)
            .ok_or_else(invalid)?
            .min(parent.expiry())
            .min(frame_expiry);
        if snapshot.principal != *principal
            || snapshot.request_id != request.request_id
            || snapshot.transaction_id
                != linura_transaction::TransactionId::for_namespace(principal, &request.request_id)
            || snapshot.state != TransactionState::Indeterminate
            || snapshot.state_version == 0
            || snapshot.binding_digest == ContentDigest::zero()
            || !request
                .request_id
                .as_str()
                .starts_with("request:v010:display-finalization:")
            || request.provider != effect.provider
            || request.resource != effect.resource
            || request.desired_state.len() != 1
            || request
                .desired_state
                .get("finalize_original")
                .map(String::as_bytes)
                != Some(effect.canonical_payload.as_slice())
            || request.observation_capability.as_str()
                != linura_observation::DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY
            || observation.provider.as_str() != linura_observation::DISPLAY_RECOVERY_PROVIDER
            || observation.capability != request.observation_capability
            || observation.resource != request.resource
            || observation.authority != linura_observation::ObservationAuthority::NativeApi
            || observation.sequence == 0
            || observation.attributes.len() != 18
            || observation.observed_at_unix_ms == 0
            || observation.valid_for_ms > 2000
            || now < window.observed_unix_ms
            || now >= expiry
            || lineage.terminal_transaction != snapshot.transaction_id.as_str()
            || lineage.terminal_dispatch != dispatch
            || lineage.terminal_effect != effect.digest().to_hex()
            || lineage.checkpoint != decoded.restoration().original_checkpoint()
            || lineage.restoration_dispatch != decoded.restoration_dispatch()
            || lineage.terminal_link != decoded.terminal_link()
            || lineage.source_guard != decoded.restored_source_guard()
            || lineage.post_write_epoch != decoded.post_write_epoch()
            || !frames
                .outputs()
                .keys()
                .all(|id| id.topology() == scope.replacement())
        {
            return Err(invalid());
        }
        // The independent join must contain every required contributor, with
        // each complete envelope digest distinct from an ACK or native flag.
        let mut contributors = std::collections::BTreeSet::new();
        for name in [
            "original_protection",
            "display",
            "session",
            "coverage",
            "first_ordinary_frame",
            "reconciled_frame",
            "rechecked_root",
            "rechecked_protection",
        ] {
            let Some(ObservedValue::Text(value)) = observation
                .attributes
                .get(&format!("control.handoff.{name}_digest"))
            else {
                return Err(invalid());
            };
            if ContentDigest::new(value).map_err(|_| invalid())? == ContentDigest::zero()
                || !contributors.insert(value)
            {
                return Err(invalid());
            }
        }
        let mut root = observation.clone();
        root.attributes
            .retain(|key, _| !key.starts_with("control.handoff."));
        let root =
            linura_observation::DisplayOriginalFinalizationFacts::from_envelope(&root, &scope, now)
                .map_err(|_| invalid())?;
        if !frames.matches_root(&root)
            || root
                .terminal()
                .is_none_or(|terminal| terminal.material() != material)
        {
            return Err(invalid());
        }
        let mut canonical = Vec::new();
        for value in [
            DOMAIN.to_owned(),
            principal.as_str().into(),
            request.request_id.as_str().into(),
            snapshot.transaction_id.as_str().into(),
            crate::durable_authority::digest_request(request)?
                .as_str()
                .into(),
            snapshot.current_generation.to_string(),
            snapshot.state_version.to_string(),
            snapshot.binding_digest.as_str().into(),
            dispatch.into(),
            parent.digest().as_str().into(),
            crate::durable_authority::digest_observation(observation)?
                .as_str()
                .into(),
            window.observed_unix_ms.to_string(),
            window.observed_boot_ms.to_string(),
            now.to_string(),
            expiry.to_string(),
            digest_bytes(FRAME_DOMAIN, &frame_bytes(frames)?)
                .as_str()
                .into(),
        ] {
            append(&mut canonical, &value)?;
        }
        canonical.extend_from_slice(&frame_bytes(frames)?);
        if canonical.len() > MAX_BYTES {
            return Err(invalid());
        }
        Ok(Self {
            principal: principal.clone(),
            request: request.request_id.clone(),
            canonical,
            observed_at: now,
            expiry,
        })
    }

    /// Save once, or compare an existing immutable proof with the fresh proof.
    /// Existing timestamps never advance. Corrupt, torn, substituted, missing
    /// parent or storage-failure outcomes cannot be overwritten as a new proof.
    pub(crate) fn retain_or_reconcile(
        &self,
        journal: &mut dyn ApprovedRequestJournal,
    ) -> Result<Self, ManagedLifecycleError> {
        journal.integrity_check().map_err(|_| invalid())?;
        let principal = &self.principal;
        let key = Self::key(&self.request)?;
        match journal.load(principal, &key) {
            Err(TransactionStoreError::NotFound) => {
                journal
                    .retain(
                        &RetainedRequest::new(
                            principal.clone(),
                            key.clone(),
                            self.canonical.clone(),
                        )
                        .map_err(|_| invalid())?,
                    )
                    .map_err(|_| invalid())?;
            }
            Ok(_) => (),
            Err(_) => return Err(invalid()),
        }
        journal.integrity_check().map_err(|_| invalid())?;
        let retained = journal.load(principal, &key).map_err(|_| invalid())?;
        if retained.principal() != principal
            || retained.request_id() != &key
            || retained.canonical().len() > MAX_BYTES
        {
            return Err(invalid());
        }
        Self::reconcile(retained.canonical(), self)
    }

    fn reconcile(bytes: &[u8], current: &Self) -> Result<Self, ManagedLifecycleError> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        let mut old = bytes;
        let mut new = current.canonical.as_slice();
        let mut times = [0; 4];
        for index in 0..HEADER_FIELDS {
            let a = field(&mut old, 256)?;
            let b = field(&mut new, 256)?;
            match index {
                // Preserve the first independently joined observation; later
                // re-reads can compare it, never refresh its digest or expiry.
                10 => {
                    if ContentDigest::new(a).map_err(|_| invalid())? == ContentDigest::zero() {
                        return Err(invalid());
                    }
                }
                11..=14 => {
                    times[index - 11] = number(a)?;
                    if (11..=12).contains(&index) && number(a)? > number(b)? {
                        return Err(invalid());
                    }
                }
                _ if a == b => (),
                _ => return Err(invalid()),
            }
        }
        if old.is_empty()
            || old != new
            || times[0] > times[2]
            || times[2] >= times[3]
            || times[3] - times[0] > 2000
            || times[2] > current.observed_at
            || times[3] <= current.observed_at
        {
            return Err(invalid());
        }
        Ok(Self {
            principal: current.principal.clone(),
            request: current.request.clone(),
            canonical: bytes.to_vec(),
            observed_at: times[2],
            expiry: times[3],
        })
    }

    pub(crate) fn digest(&self) -> ContentDigest {
        digest_bytes(DOMAIN, &self.canonical)
    }

    pub(crate) const fn observed_at(&self) -> u64 {
        self.observed_at
    }
    pub(crate) const fn expiry(&self) -> u64 {
        self.expiry
    }
}

#[cfg(test)]
mod tests;
