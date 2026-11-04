//! Immutable qualified compensation correlation in the authenticated journal.
//! Recording a link is not original retirement, current evidence, an executor
//! permit or permission to release any native/Root fence. Retirement separately
//! checks fresh canonical proof and the exact original authority CAS.
use crate::{AuthenticatedPrincipal, ManagedLifecycleError};
use linura_core::{DisplayLayoutMaterial, DisplayRestorationMaterial, PrincipalId, RequestId};
use linura_protocol::PlanDesiredStateRequest;
use linura_transaction::{
    ApprovedRequestJournal, ContentDigest, RetainedRequest, TransactionId, TransactionSnapshot,
    TransactionState, TransactionStoreError, digest_parts,
};

const DOMAIN: &str = "linura.display.original-restoration-link.v1";
const MAX_BYTES: usize = 4096;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RestorationLink {
    original: TransactionSnapshot,
    restoration: TransactionSnapshot,
    original_request: ContentDigest,
    restoration_request: ContentDigest,
    original_dispatch: String,
    checkpoint: String,
    restoration_dispatch: String,
    observation: ContentDigest,
    recorded_at: u64,
    canonical: Vec<u8>,
    digest: ContentDigest,
}

fn invalid() -> ManagedLifecycleError {
    ManagedLifecycleError::Authority(
        "original restoration link is missing, conflicting or unsupported".into(),
    )
}
fn snapshot_fields(snapshot: &TransactionSnapshot) -> Vec<String> {
    vec![
        snapshot.transaction_id.as_str().into(),
        snapshot.principal.as_str().into(),
        snapshot.request_id.as_str().into(),
        snapshot.current_generation.to_string(),
        snapshot.state_version.to_string(),
        snapshot.state.as_str().into(),
        snapshot.binding_digest.as_str().into(),
    ]
}
fn valid_snapshot(snapshot: &TransactionSnapshot) -> bool {
    snapshot.state_version > 0
        && snapshot.binding_digest != ContentDigest::zero()
        && snapshot.transaction_id
            == TransactionId::for_namespace(&snapshot.principal, &snapshot.request_id)
}
impl RestorationLink {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn capture(
        principal: &AuthenticatedPrincipal,
        original_request: &PlanDesiredStateRequest,
        restoration_request: &PlanDesiredStateRequest,
        original: TransactionSnapshot,
        restoration: TransactionSnapshot,
        restoration_dispatch: String,
        observation: ContentDigest,
        recorded_at: u64,
    ) -> Result<Self, ManagedLifecycleError> {
        let material = DisplayRestorationMaterial::decode(
            restoration_request
                .desired_state
                .get("restore_original")
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
        let original_material = DisplayLayoutMaterial::decode(
            original_request
                .desired_state
                .get("layout")
                .ok_or_else(invalid)?,
        )
        .map_err(|_| invalid())?;
        if principal.as_str() != original.principal.as_str()
            || original.principal != restoration.principal
            || original.request_id != original_request.request_id
            || restoration.request_id != restoration_request.request_id
            || material.original_request() != &original_request.request_id
            || &original_material != material.original()
            || !valid_snapshot(&original)
            || !valid_snapshot(&restoration)
            || !matches!(
                original.state,
                TransactionState::Indeterminate
                    | TransactionState::Verified
                    | TransactionState::RecoveryBlocked
            )
            || restoration.state != TransactionState::Committed
            || observation == ContentDigest::zero()
            || recorded_at == 0
            || !linura_provider_sdk::ComponentDigest::parse_hex(&restoration_dispatch).is_ok_and(
                |digest| {
                    digest.to_hex() == restoration_dispatch
                        && digest != linura_provider_sdk::ComponentDigest::from_bytes([0; 32])
                },
            )
        {
            return Err(invalid());
        }
        let mut result = Self {
            original,
            restoration,
            original_request: crate::durable_authority::digest_request(original_request)?,
            restoration_request: crate::durable_authority::digest_request(restoration_request)?,
            original_dispatch: material.original_dispatch().into(),
            checkpoint: material.original_checkpoint().into(),
            restoration_dispatch,
            observation,
            recorded_at,
            canonical: Vec::new(),
            digest: ContentDigest::zero(),
        };
        let fields = [
            vec![DOMAIN.into()],
            snapshot_fields(&result.original),
            snapshot_fields(&result.restoration),
            vec![
                result.original_request.as_str().into(),
                result.restoration_request.as_str().into(),
                result.original_dispatch.clone(),
                result.checkpoint.clone(),
                result.restoration_dispatch.clone(),
                result.observation.as_str().into(),
                result.recorded_at.to_string(),
            ],
        ]
        .concat();
        for field in fields {
            if field.is_empty() || field.len() > 256 {
                return Err(invalid());
            }
            result
                .canonical
                .extend_from_slice(&(field.len() as u64).to_be_bytes());
            result.canonical.extend_from_slice(field.as_bytes());
        }
        if result.canonical.len() > MAX_BYTES {
            return Err(invalid());
        }
        result.digest = digest_parts(DOMAIN, [result.canonical.as_slice()]);
        Ok(result)
    }

    fn key(request: &ContentDigest) -> Result<RequestId, ManagedLifecycleError> {
        RequestId::new(format!(
            "request:v010:display-restoration-link:{}",
            request.hex()
        ))
        .map_err(|_| invalid())
    }

    pub(crate) fn append(
        &self,
        journal: &mut dyn ApprovedRequestJournal,
    ) -> Result<(), ManagedLifecycleError> {
        journal
            .retain(
                &RetainedRequest::new(
                    self.original.principal.clone(),
                    Self::key(&self.restoration_request)?,
                    self.canonical.clone(),
                )
                .map_err(|_| invalid())?,
            )
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn load(
        journal: &dyn ApprovedRequestJournal,
        principal: &AuthenticatedPrincipal,
        original: &PlanDesiredStateRequest,
        restoration: &PlanDesiredStateRequest,
        committed: &TransactionSnapshot,
        dispatch: &str,
        now: u64,
    ) -> Result<Option<Self>, ManagedLifecycleError> {
        let key = Self::key(&crate::durable_authority::digest_request(restoration)?)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let retained = match journal.load(&principal_id, &key) {
            Ok(record) => record,
            Err(TransactionStoreError::NotFound) => return Ok(None),
            Err(error) => return Err(ManagedLifecycleError::Authority(error.to_string())),
        };
        if retained.principal() != &principal_id
            || retained.request_id() != &key
            || retained.canonical().is_empty()
            || retained.canonical().len() > MAX_BYTES
        {
            return Err(invalid());
        }
        let mut reader = Reader(retained.canonical());
        if reader.text()? != DOMAIN {
            return Err(invalid());
        }
        let original_snapshot = reader.snapshot()?;
        let restoration_snapshot = reader.snapshot()?;
        if &restoration_snapshot != committed {
            return Err(invalid());
        }
        let original_digest = reader.text()?;
        let restoration_digest = reader.text()?;
        let original_dispatch = reader.text()?;
        let checkpoint = reader.text()?;
        let restoration_dispatch = reader.text()?;
        let observation = ContentDigest::new(reader.text()?).map_err(|_| invalid())?;
        let recorded_at = reader.number()?;
        if !reader.0.is_empty() || recorded_at > now || restoration_dispatch != dispatch {
            return Err(invalid());
        }
        let result = Self::capture(
            principal,
            original,
            restoration,
            original_snapshot,
            restoration_snapshot,
            restoration_dispatch.into(),
            observation,
            recorded_at,
        )?;
        if result.original_request.as_str() != original_digest
            || result.restoration_request.as_str() != restoration_digest
            || result.original_dispatch != original_dispatch
            || result.checkpoint != checkpoint
            || result.canonical != retained.canonical()
        {
            return Err(invalid());
        }
        Ok(Some(result))
    }
    pub(crate) fn digest(&self) -> &ContentDigest {
        &self.digest
    }
    pub(crate) fn original(&self) -> &TransactionSnapshot {
        &self.original
    }
    pub(crate) fn restoration(&self) -> &TransactionSnapshot {
        &self.restoration
    }
    pub(crate) fn retired_original(&self) -> Result<TransactionSnapshot, ManagedLifecycleError> {
        let mut snapshot = self.original.clone();
        if snapshot.state != TransactionState::RecoveryBlocked {
            snapshot.state_version = snapshot.state_version.checked_add(1).ok_or_else(invalid)?;
            snapshot.state = TransactionState::RecoveryBlocked;
        }
        Ok(snapshot)
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn text(&mut self) -> Result<&'a str, ManagedLifecycleError> {
        let (length, rest) = self.0.split_at_checked(8).ok_or_else(invalid)?;
        let length = usize::try_from(u64::from_be_bytes(
            length.try_into().map_err(|_| invalid())?,
        ))
        .map_err(|_| invalid())?;
        if length == 0 || length > 256 {
            return Err(invalid());
        }
        let (field, rest) = rest.split_at_checked(length).ok_or_else(invalid)?;
        self.0 = rest;
        std::str::from_utf8(field).map_err(|_| invalid())
    }
    fn number(&mut self) -> Result<u64, ManagedLifecycleError> {
        let text = self.text()?;
        let value: u64 = text.parse().map_err(|_| invalid())?;
        if value.to_string() != text {
            return Err(invalid());
        }
        Ok(value)
    }
    fn snapshot(&mut self) -> Result<TransactionSnapshot, ManagedLifecycleError> {
        Ok(TransactionSnapshot {
            transaction_id: TransactionId::new(self.text()?).map_err(|_| invalid())?,
            principal: PrincipalId::new(self.text()?).map_err(|_| invalid())?,
            request_id: RequestId::new(self.text()?).map_err(|_| invalid())?,
            current_generation: self.number()?,
            state_version: self.number()?,
            state: TransactionState::parse(self.text()?).map_err(|_| invalid())?,
            binding_digest: ContentDigest::new(self.text()?).map_err(|_| invalid())?,
        })
    }
}
