//! Original Control's separately durable, irreversible first-frame handoff intent.
//! The earlier NativeReleasePrepared reserves LNRN, not the later Root LNRX
//! use. This record must be durable BEFORE the sole authenticated Root/native
//! grant request. An ACK, absent ACK, or this record never proves physical
//! output release, independent post-frame verification or terminal Control
//! completion. No delete-to-retry, owner substitution or renewed time window.
use linura_core::{PrincipalId, RequestId};
use linura_observation::ObservationEnvelope;
use linura_protocol::PlanDesiredStateRequest;
use linura_transaction::{
    ApprovedRequestJournal, ContentDigest, RetainedRequest, TransactionSnapshot, TransactionState,
    TransactionStoreError, digest_bytes,
};

use crate::ManagedLifecycleError;
use crate::display_native_release_reservation::NativeReleasePrepared;

pub(crate) mod verification;

// Keep the key unchanged: a historical spend-only entry must still prevent
// redelivery. Its old payload is not upgraded into a physical handoff permit.
const DOMAIN: &str = "linura.display.original-native-handoff-attempt.v1";
const KEY_DOMAIN: &str = "linura.display.original-native-release-spend-key.v1";
const INTENT_DOMAIN: &str = "linura.display.original-native-release-intent.v1";
const MAX_BYTES: usize = 2 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct NativeReleaseSpendPrepared {
    canonical: Vec<u8>,
    expiry: u64,
}

fn invalid() -> ManagedLifecycleError {
    ManagedLifecycleError::Authority(
        "original display native release spend is absent, ambiguous or already consumed".into(),
    )
}
fn field<'a>(rest: &mut &'a [u8], maximum: usize) -> Result<&'a str, ManagedLifecycleError> {
    let (length, tail) = rest.split_at_checked(8).ok_or_else(invalid)?;
    let length = usize::try_from(u64::from_be_bytes(
        length.try_into().map_err(|_| invalid())?,
    ))
    .map_err(|_| invalid())?;
    if length == 0 || length > maximum {
        return Err(invalid());
    }
    let (value, tail) = tail.split_at_checked(length).ok_or_else(invalid)?;
    *rest = tail;
    std::str::from_utf8(value).map_err(|_| invalid())
}
fn number(text: &str) -> Result<u64, ManagedLifecycleError> {
    let value = text.parse::<u64>().map_err(|_| invalid())?;
    if value == 0 || value.to_string() != text {
        return Err(invalid());
    }
    Ok(value)
}
impl NativeReleaseSpendPrepared {
    fn key(request: &RequestId) -> Result<RequestId, ManagedLifecycleError> {
        let digest = digest_bytes(KEY_DOMAIN, request.as_str().as_bytes());
        RequestId::new(format!(
            "request:v010:display-native-spend:{}",
            digest.hex()
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
        parent: &NativeReleasePrepared,
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
        parent: &NativeReleasePrepared,
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
        if expiry <= observed_at || expiry - observed_at > 2_000 || expiry > parent.expiry() {
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
            // Even the same canonical bytes cannot reenter a spent attempt.
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

    pub(crate) fn digest(&self) -> ContentDigest {
        digest_bytes(DOMAIN, &self.canonical)
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
            if self.0.contains_key(&key) {
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
        result.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    #[test]
    fn native_spend_before_effect_is_distinct_immutable_and_replay_safe() {
        let principal = valid(PrincipalId::new("unix:uid:1000"));
        let request = valid(RequestId::new("request:v010:display-finalization:test"));
        let once = NativeReleaseSpendPrepared {
            canonical: vec![1, 3, 5, 7],
            expiry: 10_000,
        };
        let mut journal = Journal::default();
        valid(NativeReleaseSpendPrepared::require_absent(
            &journal, &principal, &request,
        ));
        valid(once.append(&mut journal, principal.clone(), &request));
        valid(once.require_readback(&journal, &principal, &request));
        assert!(
            NativeReleaseSpendPrepared::require_absent(&journal, &principal, &request).is_err()
        );
        assert!(
            once.append(&mut journal, principal.clone(), &request)
                .is_err()
        );
        let altered = NativeReleaseSpendPrepared {
            canonical: vec![1, 3, 5, 8],
            expiry: 10_000,
        };
        assert!(
            altered
                .require_readback(&journal, &principal, &request)
                .is_err()
        );
        assert!(
            altered
                .append(&mut journal, principal.clone(), &request)
                .is_err()
        );
        let other = valid(PrincipalId::new("unix:uid:1001"));
        valid(NativeReleaseSpendPrepared::require_absent(
            &journal, &other, &request,
        ));
    }

    #[test]
    fn historical_spend_only_record_cannot_be_upgraded_into_a_physical_handoff() {
        let principal = valid(PrincipalId::new("unix:uid:1000"));
        let request = valid(RequestId::new("request:v010:display-finalization:legacy"));
        let mut bytes = Vec::new();
        let domain = b"linura.display.original-native-release-spend.v1";
        bytes.extend_from_slice(&(domain.len() as u64).to_be_bytes());
        bytes.extend_from_slice(domain);
        let mut journal = Journal::default();
        let old = valid(RetainedRequest::new(
            principal.clone(),
            valid(NativeReleaseSpendPrepared::key(&request)),
            bytes,
        ));
        valid(journal.retain(&old));
        assert!(
            NativeReleaseSpendPrepared::require_absent(&journal, &principal, &request,).is_err()
        );
        let physical = NativeReleaseSpendPrepared {
            canonical: vec![1, 2, 3],
            expiry: 20_000,
        };
        assert!(
            physical
                .append(&mut journal, principal.clone(), &request)
                .is_err()
        );
        assert_eq!(
            valid(journal.load(
                &principal,
                &valid(NativeReleaseSpendPrepared::key(&request))
            )),
            old,
        );
    }
}
