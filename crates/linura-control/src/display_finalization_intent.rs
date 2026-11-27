//! Complete terminal intent retained in Control's authenticated opaque journal.
//! This is immutable comparison history, never a permit, current observation,
//! reconstructed approval or authority to repair/repeat an external effect.
use linura_core::{DisplayFinalizationMaterial, PrincipalId, RequestId};
use linura_protocol::PlanDesiredStateRequest;
use linura_transaction::{
    ApprovedRequestJournal, ContentDigest, RetainedRequest, TransactionStoreError, digest_bytes,
};

use crate::ManagedLifecycleError;

const DOMAIN: &str = "linura.display.original-finalization-material.v1";
const MAX_BYTES: usize = 16 * 1024;
const OWNER_DOMAIN: &str = "linura.display.original-finalization-owner.v1";

#[derive(Eq, PartialEq)]
pub(crate) struct FinalizationIntent {
    material: String,
    canonical: Vec<u8>,
}
impl std::fmt::Debug for FinalizationIntent {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("FinalizationIntent")
            .field("material_bytes", &self.material.len())
            .finish()
    }
}
fn invalid() -> ManagedLifecycleError {
    ManagedLifecycleError::Authority(
        "terminal display intent history is missing, inconsistent or unsupported".into(),
    )
}
impl FinalizationIntent {
    fn owner_key(restoration: &RequestId) -> Result<RequestId, ManagedLifecycleError> {
        let digest = digest_bytes(
            "linura.display.original-finalization-owner-key.v1",
            restoration.as_str().as_bytes(),
        );
        RequestId::new(format!(
            "request:v010:display-finalization-owner:{}",
            digest.hex()
        ))
        .map_err(|_| invalid())
    }
    fn owner_record(
        &self,
        principal: PrincipalId,
        request: &PlanDesiredStateRequest,
    ) -> Result<RetainedRequest, ManagedLifecycleError> {
        self.require_owner(&principal)?;
        if Self::capture(request, &self.material)?.canonical != self.canonical {
            return Err(invalid());
        }
        let material =
            DisplayFinalizationMaterial::decode(&self.material).map_err(|_| invalid())?;
        let digest = crate::durable_authority::digest_request(request)?;
        let intent = digest_bytes(
            "linura.display.original-finalization-material-history.v1",
            &self.canonical,
        );
        let mut canonical = Vec::new();
        for text in [
            OWNER_DOMAIN,
            material.restoration_request().as_str(),
            request.request_id.as_str(),
            digest.as_str(),
            intent.as_str(),
        ] {
            canonical.extend_from_slice(&(text.len() as u64).to_be_bytes());
            canonical.extend_from_slice(text.as_bytes());
        }
        if canonical.len() > 1024 {
            return Err(invalid());
        }
        RetainedRequest::new(
            principal,
            Self::owner_key(material.restoration_request())?,
            canonical,
        )
        .map_err(|_| invalid())
    }
    /// Immutable per-restoration ownership prevents another operation ID from
    /// silently superseding an unresolved terminal attempt. It is comparison
    /// history only; qualified no-effect/supersession is a separate workflow.
    pub(crate) fn claimed_request(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        restoration: &RequestId,
    ) -> Result<Option<RequestId>, ManagedLifecycleError> {
        let key = Self::owner_key(restoration)?;
        let record = match journal.load(principal, &key) {
            Ok(record) => record,
            Err(TransactionStoreError::NotFound) => return Ok(None),
            Err(_) => return Err(invalid()),
        };
        if record.principal() != principal
            || record.request_id() != &key
            || record.canonical().is_empty()
            || record.canonical().len() > 1024
        {
            return Err(invalid());
        }
        let mut reader = Reader(record.canonical());
        if reader.text()? != OWNER_DOMAIN || reader.text()? != restoration.as_str() {
            return Err(invalid());
        }
        let owner = RequestId::new(reader.text()?).map_err(|_| invalid())?;
        for _ in 0..2 {
            let raw = reader.text()?;
            let digest = ContentDigest::new(raw).map_err(|_| invalid())?;
            if digest == ContentDigest::zero() || digest.as_str() != raw {
                return Err(invalid());
            }
        }
        if !reader.0.is_empty() {
            return Err(invalid());
        }
        Ok(Some(owner))
    }
    pub(crate) fn claim(
        &self,
        journal: &mut dyn ApprovedRequestJournal,
        principal: PrincipalId,
        request: &PlanDesiredStateRequest,
    ) -> Result<(), ManagedLifecycleError> {
        journal
            .retain(&self.owner_record(principal, request)?)
            .map_err(|_| invalid())
    }
    pub(crate) fn require_claim(
        &self,
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
    ) -> Result<(), ManagedLifecycleError> {
        let expected = self.owner_record(principal.clone(), request)?;
        let retained = journal
            .load(principal, expected.request_id())
            .map_err(|_| invalid())?;
        if retained != expected {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) fn capture(
        request: &PlanDesiredStateRequest,
        material: &str,
    ) -> Result<Self, ManagedLifecycleError> {
        let effect =
            linura_provider_sdk::display_finalization_effect(material).map_err(|_| invalid())?;
        if request.provider != effect.provider
            || request.resource != effect.resource
            || request.observation_capability.as_str()
                != linura_observation::DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY
            || request.desired_state.len() != 1
            || request
                .desired_state
                .get("finalize_original")
                .map(String::as_bytes)
                != Some(effect.canonical_payload.as_slice())
        {
            return Err(invalid());
        }
        let digest = crate::durable_authority::digest_request(request)?;
        let mut canonical = Vec::new();
        for field in [
            DOMAIN,
            request.request_id.as_str(),
            digest.as_str(),
            material,
        ] {
            if canonical
                .len()
                .saturating_add(8)
                .saturating_add(field.len())
                > MAX_BYTES
            {
                return Err(invalid());
            }
            canonical.extend_from_slice(&(field.len() as u64).to_be_bytes());
            canonical.extend_from_slice(field.as_bytes());
        }
        Ok(Self {
            material: material.into(),
            canonical,
        })
    }
    pub(crate) fn material(&self) -> &str {
        &self.material
    }
    fn key(request: &PlanDesiredStateRequest) -> Result<RequestId, ManagedLifecycleError> {
        RequestId::new(format!(
            "request:v010:display-finalization-material:{}",
            crate::durable_authority::digest_request(request)?.hex()
        ))
        .map_err(|_| invalid())
    }
    fn require_owner(&self, principal: &PrincipalId) -> Result<(), ManagedLifecycleError> {
        let material =
            DisplayFinalizationMaterial::decode(&self.material).map_err(|_| invalid())?;
        if principal.as_str() != format!("unix:uid:{}", material.current_lock().epoch().uid()) {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) fn append(
        &self,
        journal: &mut dyn ApprovedRequestJournal,
        principal: PrincipalId,
        request: &PlanDesiredStateRequest,
    ) -> Result<(), ManagedLifecycleError> {
        self.require_owner(&principal)?;
        if Self::capture(request, &self.material)?.canonical != self.canonical {
            return Err(invalid());
        }
        journal
            .retain(
                &RetainedRequest::new(principal, Self::key(request)?, self.canonical.clone())
                    .map_err(|_| invalid())?,
            )
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))
    }
    pub(crate) fn load(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
    ) -> Result<Self, ManagedLifecycleError> {
        let key = Self::key(request)?;
        let record = journal.load(principal, &key).map_err(|_| invalid())?;
        if record.principal() != principal || record.request_id() != &key {
            return Err(invalid());
        }
        let result = Self::decode(record.canonical(), request)?;
        result.require_owner(principal)?;
        Ok(result)
    }
    fn decode(
        bytes: &[u8],
        request: &PlanDesiredStateRequest,
    ) -> Result<Self, ManagedLifecycleError> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        let mut reader = Reader(bytes);
        if reader.text()? != DOMAIN
            || reader.text()? != request.request_id.as_str()
            || reader.text()? != crate::durable_authority::digest_request(request)?.as_str()
        {
            return Err(invalid());
        }
        let material = reader.text()?;
        if !reader.0.is_empty() {
            return Err(invalid());
        }
        let result = Self::capture(request, material)?;
        if result.canonical != bytes {
            return Err(invalid());
        }
        Ok(result)
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn text(&mut self) -> Result<&'a str, ManagedLifecycleError> {
        let (length, tail) = self.0.split_at_checked(8).ok_or_else(invalid)?;
        let size = usize::try_from(u64::from_be_bytes(
            length.try_into().map_err(|_| invalid())?,
        ))
        .map_err(|_| invalid())?;
        if size > linura_core::MAX_DISPLAY_FINALIZATION_BYTES {
            return Err(invalid());
        }
        let (field, tail) = tail.split_at_checked(size).ok_or_else(invalid)?;
        self.0 = tail;
        std::str::from_utf8(field).map_err(|_| invalid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{CapabilityId, DisplayRestorationMaterial, SemanticReason};
    use linura_transaction::TransactionStoreError;
    use std::collections::BTreeMap;
    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    fn fixture() -> (PlanDesiredStateRequest, FinalizationIntent, PrincipalId) {
        let old =
            include_str!("../../linura-core/src/display_recovery/fixtures/original-baseline.txt")
                .trim_end();
        let restoration = value(DisplayRestorationMaterial::decode(old));
        let material = value(DisplayFinalizationMaterial::encode(
            &value(RequestId::new("request:restoration")),
            &"1".repeat(64),
            &"2".repeat(64),
            &"3".repeat(64),
            29,
            restoration.replacement().lock(),
            old,
        ));
        let effect = value(linura_provider_sdk::display_finalization_effect(&material));
        let capability = value(CapabilityId::new(
            linura_observation::DISPLAY_ORIGINAL_FINALIZATION_CAPABILITY,
        ));
        let request = PlanDesiredStateRequest {
            request_id: value(RequestId::new("request:v010:display-finalization:retained")),
            provider: effect.provider,
            resource: effect.resource,
            observation_capability: capability.clone(),
            desired_state: BTreeMap::from([(
                "finalize_original".into(),
                value(String::from_utf8(effect.canonical_payload)),
            )]),
            reason: SemanticReason {
                summary: "Complete original restoration".into(),
                intent_ids: vec![],
                requirement_ids: vec![],
                capability_ids: vec![capability],
            },
        };
        let intent = value(FinalizationIntent::capture(&request, &material));
        let principal = value(PrincipalId::new(format!(
            "unix:uid:{}",
            restoration.replacement().lock().epoch().uid()
        )));
        (request, intent, principal)
    }
    #[derive(Debug, Default)]
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
    fn full_terminal_material_is_immutable_and_bound_to_the_exact_principal_request_and_digest() {
        let (request, intent, principal) = fixture();
        let mut journal = Journal::default();
        assert!(FinalizationIntent::load(&journal, &principal, &request).is_err());
        value(intent.append(&mut journal, principal.clone(), &request));
        value(intent.append(&mut journal, principal.clone(), &request));
        assert_eq!(
            value(FinalizationIntent::load(&journal, &principal, &request)),
            intent
        );
        let foreign = value(PrincipalId::new("unix:uid:99999"));
        assert!(
            intent
                .append(&mut journal, foreign.clone(), &request)
                .is_err()
        );
        assert!(FinalizationIntent::load(&journal, &foreign, &request).is_err());
        for case in 0..5 {
            let mut changed = request.clone();
            match case {
                0 => {
                    changed.request_id =
                        value(RequestId::new("request:v010:display-finalization:other"))
                }
                1 => changed.reason.summary.push_str(" altered"),
                2 => {
                    changed.observation_capability = value(CapabilityId::new(
                        linura_observation::DISPLAY_ORIGINAL_PROTECTION_CAPABILITY,
                    ))
                }
                3 => {
                    changed
                        .desired_state
                        .insert("restore_original".into(), intent.material.clone());
                }
                _ => {
                    changed.desired_state.insert(
                        "finalize_original".into(),
                        format!("LNRF-SHA256:1:{}", "f".repeat(64)),
                    );
                }
            }
            assert!(FinalizationIntent::load(&journal, &principal, &changed).is_err());
            assert!(
                intent
                    .append(&mut journal, principal.clone(), &changed)
                    .is_err()
            );
        }
    }
    #[test]
    fn unresolved_terminal_owner_cannot_be_replaced_by_another_operation_id_or_material() {
        let (request, intent, principal) = fixture();
        let restoration = value(DisplayFinalizationMaterial::decode(intent.material()))
            .restoration_request()
            .clone();
        let mut journal = Journal::default();
        assert_eq!(
            value(FinalizationIntent::claimed_request(
                &journal,
                &principal,
                &restoration
            )),
            None
        );
        value(intent.claim(&mut journal, principal.clone(), &request));
        value(intent.require_claim(&journal, &principal, &request));
        assert_eq!(
            value(FinalizationIntent::claimed_request(
                &journal,
                &principal,
                &restoration
            )),
            Some(request.request_id.clone())
        );
        value(intent.claim(&mut journal, principal.clone(), &request));
        let mut other = request.clone();
        other.request_id = value(RequestId::new("request:v010:display-finalization:another"));
        let different = value(FinalizationIntent::capture(&other, intent.material()));
        assert!(
            different
                .claim(&mut journal, principal.clone(), &other)
                .is_err()
        );
        assert!(
            different
                .require_claim(&journal, &principal, &other)
                .is_err()
        );
        assert!(
            intent
                .require_claim(&Journal::default(), &principal, &request)
                .is_err()
        );
        let record = journal
            .0
            .as_ref()
            .unwrap_or_else(|| unreachable!("owner record"));
        let mut bytes = record.canonical().to_vec();
        bytes[8] = b'X';
        let corrupt = Journal(Some(value(RetainedRequest::new(
            principal.clone(),
            record.request_id().clone(),
            bytes,
        ))));
        assert!(FinalizationIntent::claimed_request(&corrupt, &principal, &restoration).is_err());
    }
    #[test]
    fn terminal_material_history_rejects_unknown_domain_truncation_trailing_data_and_exhaustion() {
        let (request, intent, _) = fixture();
        for length in 0..intent.canonical.len() {
            assert!(FinalizationIntent::decode(&intent.canonical[..length], &request).is_err());
        }
        for case in 0..4 {
            let mut bytes = intent.canonical.clone();
            match case {
                0 => bytes.push(0),
                1 => bytes[..8].copy_from_slice(&u64::MAX.to_be_bytes()),
                2 => bytes[8] = b'X',
                _ => bytes[8] = 0xff,
            }
            assert!(FinalizationIntent::decode(&bytes, &request).is_err());
        }
        assert!(FinalizationIntent::decode(&vec![0; MAX_BYTES + 1], &request).is_err());
        assert!(!format!("{intent:?}").contains("LNRF:1"));
    }
}
