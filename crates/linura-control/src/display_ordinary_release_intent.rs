//! Complete terminal intent retained in Control's authenticated opaque journal.
//! This is immutable comparison history, never a permit, current observation,
//! reconstructed approval or authority to repair/repeat an external effect.
use linura_core::{DisplayOrdinaryReleaseMaterial, PrincipalId, RequestId};
use linura_protocol::PlanDesiredStateRequest;
use linura_transaction::{
    ApprovedRequestJournal, ContentDigest, RetainedRequest, TransactionStoreError, digest_bytes,
};

use crate::ManagedLifecycleError;

const DOMAIN: &str = "linura.display.ordinary-release-material.v1";
const MAX_BYTES: usize = 16 * 1024;
const OWNER_DOMAIN: &str = "linura.display.ordinary-release-owner.v1";

#[derive(Eq, PartialEq)]
pub(crate) struct OrdinaryReleaseIntent {
    material: String,
    canonical: Vec<u8>,
}
impl std::fmt::Debug for OrdinaryReleaseIntent {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OrdinaryReleaseIntent")
            .field("material_bytes", &self.material.len())
            .finish()
    }
}
fn invalid() -> ManagedLifecycleError {
    ManagedLifecycleError::Authority(
        "ordinary display intent history is missing, inconsistent or unsupported".into(),
    )
}
impl OrdinaryReleaseIntent {
    fn owner_key(original: &RequestId) -> Result<RequestId, ManagedLifecycleError> {
        let digest = digest_bytes(
            "linura.display.ordinary-release-owner-key.v1",
            original.as_str().as_bytes(),
        );
        RequestId::new(format!(
            "request:v010:display-ordinary-release-owner:{}",
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
            DisplayOrdinaryReleaseMaterial::decode(&self.material).map_err(|_| invalid())?;
        let digest = crate::durable_authority::digest_request(request)?;
        let intent = digest_bytes(
            "linura.display.ordinary-release-material-history.v1",
            &self.canonical,
        );
        let mut canonical = Vec::new();
        for text in [
            OWNER_DOMAIN,
            material.lineage().original_request.as_str(),
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
            Self::owner_key(&material.lineage().original_request)?,
            canonical,
        )
        .map_err(|_| invalid())
    }
    /// Immutable per-original ownership prevents another operation ID from
    /// silently superseding an unresolved terminal attempt. It is comparison
    /// history only; qualified no-effect/supersession is a separate workflow.
    pub(crate) fn claimed_request(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        original: &RequestId,
    ) -> Result<Option<RequestId>, ManagedLifecycleError> {
        let key = Self::owner_key(original)?;
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
        if reader.text()? != OWNER_DOMAIN || reader.text()? != original.as_str() {
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
        let effect = linura_provider_sdk::display_ordinary_release_effect(material)
            .map_err(|_| invalid())?;
        // The canonical plan observes Root's original checkpoint through the
        // recovery provider; the bounded effect belongs to native Hyprland.
        if request.provider.as_str() != linura_observation::DISPLAY_RECOVERY_PROVIDER
            || request.resource != effect.resource
            || request.observation_capability.as_str()
                != linura_observation::DISPLAY_ORDINARY_ORIGINAL_CAPABILITY
            || request.desired_state.len() != 1
            || request
                .desired_state
                .get("release_ordinary")
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
            "request:v010:display-ordinary-release-material:{}",
            crate::durable_authority::digest_request(request)?.hex()
        ))
        .map_err(|_| invalid())
    }
    fn require_owner(&self, principal: &PrincipalId) -> Result<(), ManagedLifecycleError> {
        let material =
            DisplayOrdinaryReleaseMaterial::decode(&self.material).map_err(|_| invalid())?;
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
        if size > linura_core::MAX_DISPLAY_ORDINARY_RELEASE_BYTES {
            return Err(invalid());
        }
        let (field, tail) = tail.split_at_checked(size).ok_or_else(invalid)?;
        self.0 = tail;
        std::str::from_utf8(field).map_err(|_| invalid())
    }
}
