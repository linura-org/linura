//! Immutable independently joined current-state checkpoint. Historical proof
//! cannot authorize final retirement or replace a new current-state inspection.
use super::*;
use linura_observation::{
    DisplayNativeCurrentFacts, DisplayNativeCurrentOutput, DisplayNativeHandoffWindow,
    DisplayOriginalCompletionFacts,
};

const DOMAIN: &str = "linura.display.original-current-verified.v1";
const KEY_DOMAIN: &str = "linura.display.original-current-verified-key.v1";
const LIMIT: usize = 8 * 1024;
const HEADER: usize = 13;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct NativeCurrentVerified {
    principal: PrincipalId,
    request: RequestId,
    canonical: Vec<u8>,
    frames: DisplayNativeCurrentFacts,
    verified_at: u64,
    expiry: u64,
}

fn unsigned(rest: &mut &[u8]) -> Result<u64, ManagedLifecycleError> {
    let text = field(rest, 20)?;
    let value = text.parse::<u64>().map_err(|_| invalid())?;
    if value.to_string() != text {
        return Err(invalid());
    }
    Ok(value)
}

impl NativeCurrentVerified {
    fn key(request: &RequestId) -> Result<RequestId, ManagedLifecycleError> {
        RequestId::new(format!(
            "request:v010:display-current-verified:{}",
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
        preparation: &completion::NativeCompletionPrepared,
        root: &DisplayOriginalCompletionFacts,
        observation: &ObservationEnvelope,
        frames: &DisplayNativeCurrentFacts,
        now: u64,
    ) -> Result<Self, ManagedLifecycleError> {
        let effect = linura_provider_sdk::display_finalization_effect(&root.lineage().material)
            .map_err(|_| invalid())?;
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
            .min(frame_expiry);
        let mut expected = root.attributes();
        let mut contributors = std::collections::BTreeSet::new();
        for name in [
            "protection",
            "display",
            "session",
            "coverage",
            "current",
            "rechecked_current",
            "rechecked_root",
            "rechecked_protection",
        ] {
            let key = format!("control.current.{name}_digest");
            let Some(ObservedValue::Text(text)) = observation.attributes.get(&key) else {
                return Err(invalid());
            };
            let digest = ContentDigest::new(text).map_err(|_| invalid())?;
            if digest == ContentDigest::zero() || !contributors.insert(digest) {
                return Err(invalid());
            }
            expected.insert(key, ObservedValue::Text(text.clone()));
        }
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
            || request.observation_capability.as_str()
                != linura_observation::DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY
            || request.desired_state.len() != 1
            || request
                .desired_state
                .get("finalize_original")
                .map(String::as_bytes)
                != Some(effect.canonical_payload.as_slice())
            || root.first().lineage().terminal_transaction != snapshot.transaction_id.as_str()
            || root.first().lineage().terminal_dispatch != dispatch
            || root.first().lineage().terminal_effect != effect.digest().to_hex()
            || root.lineage().preparation != preparation.digest().hex()
            || observation.provider.as_str() != linura_observation::DISPLAY_RECOVERY_PROVIDER
            || observation.capability.as_str()
                != linura_observation::DISPLAY_ORIGINAL_COMPLETION_CAPABILITY
            || observation.resource != request.resource
            || observation.authority != linura_observation::ObservationAuthority::NativeApi
            || observation.sequence == 0
            || observation.observed_at_unix_ms == 0
            || observation.valid_for_ms > 2000
            || observation.attributes != expected
            || !frames.follows_handoff(root.first())
            || frames.completion_digest() != root.lineage().record
            || !frames.input_retired()
            || !frames.power_fence_held()
            || now < window.observed_unix_ms
            || now >= expiry
        {
            return Err(invalid());
        }
        let mut canonical = Vec::new();
        for value in [
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
            preparation.digest().as_str().into(),
            root.lineage().record.clone(),
            root.lineage().verification.clone(),
            digest_bytes(FRAME_DOMAIN, &frame_bytes(root.first())?)
                .as_str()
                .into(),
            crate::durable_authority::digest_observation(observation)?
                .as_str()
                .into(),
            now.to_string(),
            expiry.to_string(),
            window.observed_unix_ms.to_string(),
            window.observed_boot_ms.to_string(),
            window.deadline_unix_ms.to_string(),
            window.deadline_boot_ms.to_string(),
            frames.outputs().len().to_string(),
        ] {
            append(&mut canonical, &value)?;
        }
        for (id, output) in frames.outputs() {
            for value in [
                id.handle(),
                id.generation(),
                u64::from(output.enabled),
                u64::from(output.connector),
                u64::from(output.crtc),
                u64::from(output.plane),
                u64::from(output.framebuffer),
                output.handoff_commit,
                output.completed_commit,
            ] {
                append(&mut canonical, &value.to_string())?;
            }
        }
        if canonical.len() > LIMIT {
            return Err(invalid());
        }
        Ok(Self {
            principal: principal.clone(),
            request: request.request_id.clone(),
            canonical,
            frames: frames.clone(),
            verified_at: now,
            expiry,
        })
    }

    fn reconcile(&self, bytes: &[u8]) -> Result<Self, ManagedLifecycleError> {
        if bytes.is_empty() || bytes.len() > LIMIT {
            return Err(invalid());
        }
        let mut old = bytes;
        let mut new = self.canonical.as_slice();
        for _ in 0..HEADER {
            if field(&mut old, 256)? != field(&mut new, 256)? {
                return Err(invalid());
            }
        }
        if ContentDigest::new(field(&mut old, 256)?).map_err(|_| invalid())?
            == ContentDigest::zero()
        {
            return Err(invalid());
        }
        let verified_at = unsigned(&mut old)?;
        let expiry = unsigned(&mut old)?;
        let window = DisplayNativeHandoffWindow {
            observed_unix_ms: unsigned(&mut old)?,
            observed_boot_ms: unsigned(&mut old)?,
            deadline_unix_ms: unsigned(&mut old)?,
            deadline_boot_ms: unsigned(&mut old)?,
        };
        if verified_at < window.observed_unix_ms
            || verified_at >= expiry
            || expiry
                > window
                    .observed_unix_ms
                    .checked_add(window.valid_for_ms().map_err(|_| invalid())?)
                    .ok_or_else(invalid)?
            || expiry - window.observed_unix_ms > 2000
            || verified_at > self.verified_at
            || unsigned(&mut old)? != self.frames.outputs().len() as u64
        {
            return Err(invalid());
        }
        let mut outputs = std::collections::BTreeMap::new();
        for id in self.frames.outputs().keys() {
            if unsigned(&mut old)? != id.handle() || unsigned(&mut old)? != id.generation() {
                return Err(invalid());
            }
            let enabled = match unsigned(&mut old)? {
                0 => false,
                1 => true,
                _ => return Err(invalid()),
            };
            let mut u32_field = || u32::try_from(unsigned(&mut old)?).map_err(|_| invalid());
            outputs.insert(
                id.clone(),
                DisplayNativeCurrentOutput {
                    enabled,
                    connector: u32_field()?,
                    crtc: u32_field()?,
                    plane: u32_field()?,
                    framebuffer: u32_field()?,
                    handoff_commit: unsigned(&mut old)?,
                    completed_commit: unsigned(&mut old)?,
                },
            );
        }
        // Decode typed comparison history, never reconstruct an authoritative
        // observation or renew the historical proof's original clocks.
        let frames = DisplayNativeCurrentFacts::new(
            self.frames.scope().clone(),
            self.frames.lineage().clone(),
            window,
            outputs,
            self.frames.completion_digest().into(),
            true,
            true,
            None,
            None,
        )
        .map_err(|_| invalid())?;
        if !old.is_empty() || !self.frames.reconciles(&frames) {
            return Err(invalid());
        }
        Ok(Self {
            principal: self.principal.clone(),
            request: self.request.clone(),
            canonical: bytes.to_vec(),
            frames,
            verified_at,
            expiry,
        })
    }

    pub(crate) fn retain_or_reconcile(
        &self,
        journal: &mut dyn ApprovedRequestJournal,
    ) -> Result<Self, ManagedLifecycleError> {
        journal.integrity_check().map_err(|_| invalid())?;
        let key = Self::key(&self.request)?;
        match journal.load(&self.principal, &key) {
            Err(TransactionStoreError::NotFound) => journal
                .retain(
                    &RetainedRequest::new(
                        self.principal.clone(),
                        key.clone(),
                        self.canonical.clone(),
                    )
                    .map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?,
            Ok(_) => (),
            Err(_) => return Err(invalid()),
        }
        journal.integrity_check().map_err(|_| invalid())?;
        let record = journal.load(&self.principal, &key).map_err(|_| invalid())?;
        if record.principal() != &self.principal || record.request_id() != &key {
            return Err(invalid());
        }
        self.reconcile(record.canonical())
    }

    pub(crate) fn require_digest_readback(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        request: &RequestId,
        expected: &ContentDigest,
    ) -> Result<(), ManagedLifecycleError> {
        journal.integrity_check().map_err(|_| invalid())?;
        let key = Self::key(request)?;
        let record = journal.load(principal, &key).map_err(|_| invalid())?;
        if record.principal() != principal
            || record.request_id() != &key
            || record.canonical().len() > LIMIT
            || *expected == ContentDigest::zero()
            || digest_bytes(DOMAIN, record.canonical()) != *expected
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> ContentDigest {
        digest_bytes(DOMAIN, &self.canonical)
    }
    pub(crate) const fn verified_at(&self) -> u64 {
        self.verified_at
    }
    pub(crate) const fn expiry(&self) -> u64 {
        self.expiry
    }
}
