//! Immutable, one-use Control release-preparation provenance. This is retained
//! *before* invoking Root and survives ambiguous replies; it is not a native
//! release grant, a Control terminal commit or a physical first-frame proof.
use linura_core::{DisplayFinalizationMaterial, PrincipalId, RequestId};
use linura_observation::ObservationEnvelope;
use linura_protocol::PlanDesiredStateRequest;
use linura_transaction::{
    ApprovedRequestJournal, ContentDigest, RetainedRequest, TransactionSnapshot, TransactionState,
    TransactionStoreError, digest_bytes,
};

use crate::ManagedLifecycleError;

const DOMAIN: &str = "linura.display.original-terminal-retirement-prepared.v1";
const KEY_DOMAIN: &str = "linura.display.original-terminal-retirement-prepared-key.v1";
const MAX_BYTES: usize = 2 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct TerminalRetirementPrepared {
    canonical: Vec<u8>,
    expiry: u64,
    observation: ContentDigest,
}

fn invalid() -> ManagedLifecycleError {
    ManagedLifecycleError::Authority(
        "original display terminal retirement preparation is unavailable or conflicting".into(),
    )
}

/// Decode one complete bounded retained field; unknown or partial journal
/// bytes are not repaired, silently ignored or promoted to current authority.
fn retained_field<'a>(bytes: &mut &'a [u8], max: usize) -> Result<&'a str, ManagedLifecycleError> {
    let (raw_len, rest) = bytes.split_at_checked(8).ok_or_else(invalid)?;
    let len = usize::try_from(u64::from_be_bytes(
        raw_len.try_into().map_err(|_| invalid())?,
    ))
    .map_err(|_| invalid())?;
    if len == 0 || len > max {
        return Err(invalid());
    }
    let (field, remaining) = rest.split_at_checked(len).ok_or_else(invalid)?;
    *bytes = remaining;
    std::str::from_utf8(field).map_err(|_| invalid())
}

fn retained_number(field: &str) -> Result<u64, ManagedLifecycleError> {
    let n = field.parse::<u64>().map_err(|_| invalid())?;
    if n.to_string() != field || n == 0 {
        return Err(invalid());
    }
    Ok(n)
}

impl TerminalRetirementPrepared {
    pub(crate) fn key(request: &RequestId) -> Result<RequestId, ManagedLifecycleError> {
        let id = digest_bytes(KEY_DOMAIN, request.as_str().as_bytes());
        RequestId::new(format!(
            "request:v010:display-terminal-retirement:{}",
            id.hex()
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
        observation: &ObservationEnvelope,
        now: u64,
    ) -> Result<Self, ManagedLifecycleError> {
        if snapshot.principal != *principal
            || snapshot.request_id != request.request_id
            || snapshot.transaction_id
                != linura_transaction::TransactionId::for_namespace(principal, &request.request_id)
            || snapshot.state != TransactionState::Indeterminate
            || snapshot.state_version == 0
            || snapshot.binding_digest == ContentDigest::zero()
            || !linura_provider_sdk::ComponentDigest::parse_hex(dispatch)
                .is_ok_and(|parsed| parsed.to_hex() == dispatch)
            || !request
                .request_id
                .as_str()
                .starts_with("request:v010:display-finalization:")
            || observation.observed_at_unix_ms == 0
            || observation.valid_for_ms == 0
            || now < observation.observed_at_unix_ms
        {
            return Err(invalid());
        }
        let finalization = DisplayFinalizationMaterial::decode(material).map_err(|_| invalid())?;
        if principal.as_str() != format!("unix:uid:{}", finalization.current_lock().epoch().uid())
            || request.provider.as_str() != linura_observation::DISPLAY_RECOVERY_PROVIDER
            || request.observation_capability.as_str()
                != linura_observation::DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY
            || request.resource
                != finalization
                    .recovery_scope()
                    .map_err(|_| invalid())?
                    .resource_id()
                    .map_err(|_| invalid())?
            || request.desired_state.len() != 1
            || request
                .desired_state
                .get("finalize_original")
                .map(String::as_bytes)
                != Some(
                    linura_provider_sdk::display_finalization_effect(material)
                        .map_err(|_| invalid())?
                        .canonical_payload
                        .as_slice(),
                )
        {
            return Err(invalid());
        }
        // Do not grant the caller a newly computed period. The actual original
        // evidence timestamp controls the entire later Root preparation.
        let expiry = observation
            .observed_at_unix_ms
            .checked_add(observation.valid_for_ms.min(2_000))
            .ok_or_else(invalid)?;
        if now >= expiry {
            return Err(invalid());
        }
        observation.require_current(now).map_err(|_| invalid())?;
        let obs = crate::durable_authority::digest_observation(observation)?;
        let intent = digest_bytes(
            "linura.display.original-terminal-retirement-intent.v1",
            material.as_bytes(),
        );
        let request_digest = crate::durable_authority::digest_request(request)?;
        let version = snapshot.state_version.to_string();
        let at = observation.observed_at_unix_ms.to_string();
        let until = expiry.to_string();
        let mut canonical = Vec::new();
        for field in [
            DOMAIN,
            principal.as_str(),
            request.request_id.as_str(),
            snapshot.transaction_id.as_str(),
            request_digest.as_str(),
            version.as_str(),
            snapshot.binding_digest.as_str(),
            dispatch,
            intent.as_str(),
            obs.as_str(),
            at.as_str(),
            until.as_str(),
        ] {
            if canonical
                .len()
                .checked_add(8)
                .and_then(|length| length.checked_add(field.len()))
                .is_none_or(|length| length > MAX_BYTES)
            {
                return Err(invalid());
            }
            canonical.extend_from_slice(&(field.len() as u64).to_be_bytes());
            canonical.extend_from_slice(field.as_bytes());
        }
        Ok(Self {
            canonical,
            expiry,
            observation: obs,
        })
    }

    /// Read-only recovery of exactly one previously spent Control operation.
    /// No freshening of its original observation or retry of its Root/native
    /// effect is possible. The caller independently verifies Root's *current*
    /// phase and the same signed Control lineage before and after this query.
    pub(crate) fn load_spent(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
        snapshot: &TransactionSnapshot,
        dispatch: &str,
        material: &str,
    ) -> Result<Self, ManagedLifecycleError> {
        if snapshot.state != TransactionState::Indeterminate
            || snapshot.principal != *principal
            || snapshot.request_id != request.request_id
            || snapshot.transaction_id
                != linura_transaction::TransactionId::for_namespace(principal, &request.request_id)
            || snapshot.state_version == 0
            || snapshot.binding_digest == ContentDigest::zero()
            || !request
                .request_id
                .as_str()
                .starts_with("request:v010:display-finalization:")
            || !linura_provider_sdk::ComponentDigest::parse_hex(dispatch)
                .is_ok_and(|digest| digest.to_hex() == dispatch)
        {
            return Err(invalid());
        }
        let expected_effect =
            linura_provider_sdk::display_finalization_effect(material).map_err(|_| invalid())?;
        let decoded = DisplayFinalizationMaterial::decode(material).map_err(|_| invalid())?;
        if request.provider != expected_effect.provider
            || request.resource != expected_effect.resource
            || request.observation_capability.as_str()
                != linura_observation::DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY
            || request.desired_state.len() != 1
            || request
                .desired_state
                .get("finalize_original")
                .map(String::as_bytes)
                != Some(expected_effect.canonical_payload.as_slice())
            || principal.as_str() != format!("unix:uid:{}", decoded.current_lock().epoch().uid())
        {
            return Err(invalid());
        }
        let key = Self::key(&request.request_id)?;
        journal.integrity_check().map_err(|_| invalid())?;
        let retained = journal.load(principal, &key).map_err(|_| invalid())?;
        let bytes = retained.canonical();
        if retained.principal() != principal
            || retained.request_id() != &key
            || bytes.is_empty()
            || bytes.len() > MAX_BYTES
        {
            return Err(invalid());
        }
        let mut rem = bytes;
        let mut fields = Vec::with_capacity(12);
        for bound in [
            DOMAIN.len(),
            128,
            256,
            256,
            128,
            20,
            128,
            64,
            128,
            128,
            20,
            20,
        ] {
            fields.push(retained_field(&mut rem, bound)?);
        }
        if !rem.is_empty()
            || fields[0] != DOMAIN
            || fields[1] != principal.as_str()
            || fields[2] != request.request_id.as_str()
            || fields[3] != snapshot.transaction_id.as_str()
            || fields[4] != crate::durable_authority::digest_request(request)?.as_str()
            || retained_number(fields[5])? != snapshot.state_version
            || fields[6] != snapshot.binding_digest.as_str()
            || fields[7] != dispatch
            || fields[8]
                != digest_bytes(
                    "linura.display.original-terminal-retirement-intent.v1",
                    material.as_bytes(),
                )
                .as_str()
        {
            return Err(invalid());
        }
        let observation = ContentDigest::new(fields[9]).map_err(|_| invalid())?;
        if observation == ContentDigest::zero() {
            return Err(invalid());
        }
        let observed_at = retained_number(fields[10])?;
        let expires_at = retained_number(fields[11])?;
        if expires_at <= observed_at || expires_at - observed_at > 2_000 {
            return Err(invalid());
        }
        // An expired stored observation is historical provenance, not grounds
        // to renew a lost grant or retrospectively claim native success.
        Ok(Self {
            canonical: bytes.to_vec(),
            expiry: expires_at,
            observation,
        })
    }

    pub(crate) fn require_absent(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        terminal_request: &RequestId,
    ) -> Result<(), ManagedLifecycleError> {
        journal.integrity_check().map_err(|_| invalid())?;
        match journal.load(principal, &Self::key(terminal_request)?) {
            Err(TransactionStoreError::NotFound) => Ok(()),
            // An already retained preparation is spent even if its ACK was
            // lost; conflicting or corrupt history also cannot be repaired.
            _ => Err(invalid()),
        }
    }

    pub(crate) fn append(
        &self,
        journal: &mut dyn ApprovedRequestJournal,
        principal: PrincipalId,
        terminal_request: &RequestId,
    ) -> Result<(), ManagedLifecycleError> {
        journal
            .retain(
                &RetainedRequest::new(
                    principal,
                    Self::key(terminal_request)?,
                    self.canonical.clone(),
                )
                .map_err(|_| invalid())?,
            )
            .map_err(|_| invalid())
    }

    pub(crate) fn require_readback(
        &self,
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        terminal_request: &RequestId,
    ) -> Result<(), ManagedLifecycleError> {
        journal.integrity_check().map_err(|_| invalid())?;
        let key = Self::key(terminal_request)?;
        let record = journal.load(principal, &key).map_err(|_| invalid())?;
        if record.principal() != principal
            || record.request_id() != &key
            || record.canonical() != self.canonical
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> ContentDigest {
        // Historical immutable Control parent, never a release credential.
        digest_bytes(
            "linura.display.original-terminal-retirement-parent.v1",
            &self.canonical,
        )
    }
    pub(crate) const fn expiry(&self) -> u64 {
        self.expiry
    }
    pub(crate) const fn observation(&self) -> &ContentDigest {
        &self.observation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_transaction::ContentDigest;
    use std::collections::BTreeMap;

    #[derive(Debug, Default)]
    struct Journal(BTreeMap<(PrincipalId, RequestId), RetainedRequest>);
    impl ApprovedRequestJournal for Journal {
        fn retain(&mut self, record: &RetainedRequest) -> Result<(), TransactionStoreError> {
            let key = (record.principal().clone(), record.request_id().clone());
            if self.0.get(&key).is_some_and(|current| current != record) {
                return Err(TransactionStoreError::AuthorityRejected);
            }
            self.0.insert(key, record.clone());
            Ok(())
        }
        fn load(
            &self,
            principal: &PrincipalId,
            request: &RequestId,
        ) -> Result<RetainedRequest, TransactionStoreError> {
            self.0
                .get(&(principal.clone(), request.clone()))
                .cloned()
                .ok_or(TransactionStoreError::NotFound)
        }
        fn integrity_check(&self) -> Result<(), TransactionStoreError> {
            Ok(())
        }
    }

    fn valid<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error:?}"))
    }

    #[test]
    fn historical_preparation_parser_refuses_noncanonical_and_partial_frames() {
        let domain = b"linura.display.original-terminal-retirement-prepared.v1";
        let mut frame = Vec::new();
        frame.extend_from_slice(&(domain.len() as u64).to_be_bytes());
        frame.extend_from_slice(domain);
        let mut remaining = frame.as_slice();
        assert_eq!(
            retained_field(&mut remaining, DOMAIN.len()).ok(),
            Some(DOMAIN)
        );
        assert!(remaining.is_empty());
        for cut in 0..frame.len() {
            let mut invalid_frame = &frame[..cut];
            assert!(retained_field(&mut invalid_frame, DOMAIN.len()).is_err());
        }
        for number in ["", "0", "01", "1.0", "-1", "18446744073709551616"] {
            assert!(retained_number(number).is_err());
        }
        for (text, value) in [
            ("1", 1_u64),
            ("2000", 2000_u64),
            ("18446744073709551615", u64::MAX),
        ] {
            assert_eq!(retained_number(text).ok(), Some(value));
        }
        let mut overlong = frame.clone();
        overlong[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        let mut malformed = overlong.as_slice();
        assert!(retained_field(&mut malformed, DOMAIN.len()).is_err());
        let zero = [0_u8; 8];
        let mut malformed = zero.as_slice();
        assert!(retained_field(&mut malformed, DOMAIN.len()).is_err());
        let mut invalid_utf8 = vec![0_u8; 9];
        invalid_utf8[7] = 1;
        invalid_utf8[8] = 0xFF;
        let mut malformed = invalid_utf8.as_slice();
        assert!(retained_field(&mut malformed, 1).is_err());
    }

    #[test]
    fn prepared_history_is_independent_immutable_and_spent_after_lost_ack() {
        let request = valid(RequestId::new("request:v010:display-finalization:one"));
        let principal = valid(PrincipalId::new("unix:uid:1000"));
        let record = TerminalRetirementPrepared {
            canonical: vec![1, 2, 3, 4],
            expiry: 200,
            observation: ContentDigest::zero(),
        };
        let mut journal = Journal::default();
        valid(TerminalRetirementPrepared::require_absent(
            &journal, &principal, &request,
        ));
        valid(record.append(&mut journal, principal.clone(), &request));
        valid(record.require_readback(&journal, &principal, &request));
        assert!(
            TerminalRetirementPrepared::require_absent(&journal, &principal, &request).is_err()
        );
        assert!(
            TerminalRetirementPrepared::require_absent(
                &journal,
                &valid(PrincipalId::new("unix:uid:999")),
                &request
            )
            .is_ok()
        );
        let mut changed = TerminalRetirementPrepared {
            canonical: vec![1, 2, 3, 5],
            expiry: 200,
            observation: ContentDigest::zero(),
        };
        assert!(
            changed
                .require_readback(&journal, &principal, &request)
                .is_err()
        );
        assert!(
            changed
                .append(&mut journal, principal.clone(), &request)
                .is_err()
        );
        changed.canonical = vec![1, 2, 3, 4];
        valid(changed.require_readback(&journal, &principal, &request));
    }
}
