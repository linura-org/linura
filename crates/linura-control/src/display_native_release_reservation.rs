//! Durable Control authorization to reserve one native release attempt, only.
//! This record is NOT a terminal commit, first-frame receipt, Root grant or
//! permission to drop S17/input/power/startup protection. An uncertain attempt
//! is permanently spent, including if its private Root acknowledgement is lost.
use linura_core::{PrincipalId, RequestId};
use linura_observation::ObservationEnvelope;
use linura_protocol::PlanDesiredStateRequest;
use linura_transaction::{
    ApprovedRequestJournal, ContentDigest, RetainedRequest, TransactionSnapshot, TransactionState,
    TransactionStoreError, digest_bytes,
};

use crate::ManagedLifecycleError;
use crate::display_terminal_retirement::TerminalRetirementPrepared;

const DOMAIN: &str = "linura.display.original-native-release-prepared.v1";
const KEY_DOMAIN: &str = "linura.display.original-native-release-prepared-key.v1";
const INTENT_DOMAIN: &str = "linura.display.original-native-release-intent.v1";
const PARENT_DOMAIN: &str = "linura.display.original-native-release-parent.v1";
const MAX_BYTES: usize = 2 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct NativeReleasePrepared {
    canonical: Vec<u8>,
    expiry: u64,
}

fn invalid() -> ManagedLifecycleError {
    ManagedLifecycleError::Authority(
        "original display native release reservation is missing, conflicting or spent".into(),
    )
}
fn field<'a>(rest: &mut &'a [u8], max: usize) -> Result<&'a str, ManagedLifecycleError> {
    let (length, tail) = rest.split_at_checked(8).ok_or_else(invalid)?;
    let length = usize::try_from(u64::from_be_bytes(length.try_into().map_err(|_| invalid())?))
        .map_err(|_| invalid())?;
    if length == 0 || length > max {
        return Err(invalid());
    }
    let (bytes, tail) = tail.split_at_checked(length).ok_or_else(invalid)?;
    *rest = tail;
    std::str::from_utf8(bytes).map_err(|_| invalid())
}
fn number(raw: &str) -> Result<u64, ManagedLifecycleError> {
    let value = raw.parse::<u64>().map_err(|_| invalid())?;
    if value == 0 || value.to_string() != raw {
        return Err(invalid());
    }
    Ok(value)
}

impl NativeReleasePrepared {
    fn key(request: &RequestId) -> Result<RequestId, ManagedLifecycleError> {
        let digest = digest_bytes(KEY_DOMAIN, request.as_str().as_bytes());
        RequestId::new(format!("request:v010:display-native-release:{}", digest.hex()))
            .map_err(|_| invalid())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture(
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
        snapshot: &TransactionSnapshot,
        dispatch: &str,
        material: &str,
        parent: &TerminalRetirementPrepared,
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
            || !request
                .request_id
                .as_str()
                .starts_with("request:v010:display-finalization:")
            || !linura_provider_sdk::ComponentDigest::parse_hex(dispatch)
                .is_ok_and(|digest| digest.to_hex() == dispatch)
            || now == 0
        {
            return Err(invalid());
        }
        observation.require_current(now).map_err(|_| invalid())?;
        if observation.observed_at_unix_ms == 0
            || observation.valid_for_ms == 0
            || observation.valid_for_ms > 2_000
            || now < observation.observed_at_unix_ms
        {
            return Err(invalid());
        }
        let observed_expiry = observation
            .observed_at_unix_ms
            .checked_add(observation.valid_for_ms)
            .ok_or_else(invalid)?;
        let expiry = parent.expiry().min(observed_expiry);
        if now >= expiry {
            return Err(invalid());
        }
        let effect =
            linura_provider_sdk::display_finalization_effect(material).map_err(|_| invalid())?;
        if request.provider != effect.provider
            || request.resource != effect.resource
            || request.desired_state.len() != 1
            || request
                .desired_state
                .get("finalize_original")
                .map(String::as_bytes)
                != Some(effect.canonical_payload.as_slice())
        {
            return Err(invalid());
        }
        let request_digest = crate::durable_authority::digest_request(request)?;
        let observation_digest = crate::durable_authority::digest_observation(observation)?;
        let intent_digest = digest_bytes(INTENT_DOMAIN, material.as_bytes());
        let parent_digest = parent.digest();
        let version = snapshot.state_version.to_string();
        let observed_at = observation.observed_at_unix_ms.to_string();
        let expires_at = expiry.to_string();
        let mut canonical = Vec::new();
        for value in [
            DOMAIN,
            principal.as_str(),
            request.request_id.as_str(),
            snapshot.transaction_id.as_str(),
            request_digest.as_str(),
            version.as_str(),
            snapshot.binding_digest.as_str(),
            dispatch,
            intent_digest.as_str(),
            parent_digest.as_str(),
            observation_digest.as_str(),
            observed_at.as_str(),
            expires_at.as_str(),
        ] {
            if canonical
                .len()
                .checked_add(8)
                .and_then(|size| size.checked_add(value.len()))
                .is_none_or(|size| size > MAX_BYTES)
            {
                return Err(invalid());
            }
            canonical.extend_from_slice(&(value.len() as u64).to_be_bytes());
            canonical.extend_from_slice(value.as_bytes());
        }
        Ok(Self { canonical, expiry })
    }

    pub(crate) fn load_spent(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
        snapshot: &TransactionSnapshot,
        dispatch: &str,
        material: &str,
        parent: &TerminalRetirementPrepared,
    ) -> Result<Self, ManagedLifecycleError> {
        if snapshot.principal != *principal
            || snapshot.request_id != request.request_id
            || snapshot.transaction_id
                != linura_transaction::TransactionId::for_namespace(principal, &request.request_id)
            || snapshot.state != TransactionState::Indeterminate
            || snapshot.state_version == 0
        {
            return Err(invalid());
        }
        journal.integrity_check().map_err(|_| invalid())?;
        let key = Self::key(&request.request_id)?;
        let retained = journal.load(principal, &key).map_err(|_| invalid())?;
        let bytes = retained.canonical();
        if retained.principal() != principal
            || retained.request_id() != &key
            || bytes.is_empty()
            || bytes.len() > MAX_BYTES
        {
            return Err(invalid());
        }
        let mut rest = bytes;
        let mut fields = Vec::with_capacity(13);
        for max in [
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
            128,
            20,
            20,
        ] {
            fields.push(field(&mut rest, max)?);
        }
        if !rest.is_empty()
            || fields[0] != DOMAIN
            || fields[1] != principal.as_str()
            || fields[2] != request.request_id.as_str()
            || fields[3] != snapshot.transaction_id.as_str()
            || fields[4] != crate::durable_authority::digest_request(request)?.as_str()
            || number(fields[5])? != snapshot.state_version
            || fields[6] != snapshot.binding_digest.as_str()
            || fields[7] != dispatch
            || fields[8] != digest_bytes(INTENT_DOMAIN, material.as_bytes()).as_str()
            || fields[9] != parent.digest().as_str()
            || ContentDigest::new(fields[10]).map_err(|_| invalid())? == ContentDigest::zero()
        {
            return Err(invalid());
        }
        let observed_at = number(fields[11])?;
        let expiry = number(fields[12])?;
        if expiry <= observed_at
            || expiry - observed_at > 2_000
            || expiry > parent.expiry()
        {
            return Err(invalid());
        }
        Ok(Self {
            canonical: bytes.to_vec(),
            expiry,
        })
    }

    pub(crate) fn require_absent(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        request: &RequestId,
    ) -> Result<(), ManagedLifecycleError> {
        journal.integrity_check().map_err(|_| invalid())?;
        match journal.load(principal, &Self::key(request)?) {
            Err(TransactionStoreError::NotFound) => Ok(()),
            // A missing reply never authorizes a second Root reservation.
            _ => Err(invalid()),
        }
    }
    pub(crate) fn append(
        &self,
        journal: &mut dyn ApprovedRequestJournal,
        principal: PrincipalId,
        request: &RequestId,
    ) -> Result<(), ManagedLifecycleError> {
        journal
            .retain(
                &RetainedRequest::new(principal, Self::key(request)?, self.canonical.clone())
                    .map_err(|_| invalid())?,
            )
            .map_err(|_| invalid())
    }
    pub(crate) fn require_readback(
        &self,
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        request: &RequestId,
    ) -> Result<(), ManagedLifecycleError> {
        journal.integrity_check().map_err(|_| invalid())?;
        let key = Self::key(request)?;
        let retained = journal.load(principal, &key).map_err(|_| invalid())?;
        if retained.principal() != principal
            || retained.request_id() != &key
            || retained.canonical() != self.canonical
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) const fn expiry(&self) -> u64 {
        self.expiry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Debug, Default)]
    struct Journal(BTreeMap<(PrincipalId, RequestId), RetainedRequest>);
    impl ApprovedRequestJournal for Journal {
        fn retain(&mut self, record: &RetainedRequest) -> Result<(), TransactionStoreError> {
            let key = (record.principal().clone(), record.request_id().clone());
            if self.0.get(&key).is_some_and(|prior| prior != record) {
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
    fn valid<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    #[test]
    fn original_control_native_release_decision_is_one_use_and_durable() {
        let principal = valid(PrincipalId::new("unix:uid:1000"));
        let request = valid(RequestId::new("request:v010:display-finalization:test"));
        let record = NativeReleasePrepared {
            canonical: vec![1, 3, 5, 7],
            expiry: 20_000,
        };
        let mut journal = Journal::default();
        valid(NativeReleasePrepared::require_absent(
            &journal, &principal, &request,
        ));
        valid(record.append(&mut journal, principal.clone(), &request));
        valid(record.require_readback(&journal, &principal, &request));
        assert!(NativeReleasePrepared::require_absent(&journal, &principal, &request).is_err());
        let different = NativeReleasePrepared {
            canonical: vec![1, 3, 5, 8],
            expiry: 20_000,
        };
        assert!(different.append(&mut journal, principal.clone(), &request).is_err());
        assert!(different.require_readback(&journal, &principal, &request).is_err());
        let other = valid(PrincipalId::new("unix:uid:1001"));
        valid(NativeReleasePrepared::require_absent(&journal, &other, &request));
    }
    #[test]
    fn native_release_retained_parser_refuses_partial_noncanonical_and_extra_fields() {
        let mut raw = [0u8; 8].as_slice();
        assert!(field(&mut raw, 4).is_err());
        for raw in ["", "0", "00", "01", "-1", "1.0", "18446744073709551616"] {
            assert!(number(raw).is_err());
        }
        let mut raw = [0u8; 9].as_slice();
        assert!(field(&mut raw, 4).is_err());
        let mut raw = [0u8; 9].as_slice();
        raw = &raw[..8];
        assert!(field(&mut raw, 4).is_err());
    }
}
