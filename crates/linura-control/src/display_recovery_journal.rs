//! Purpose-versioned immutable display phase records in the existing protected
//! opaque journal. They retain decisions/recovery facts, never executor authority.
use crate::ManagedLifecycleError;
use linura_core::{PrincipalId, RequestId};
use linura_transaction::{
    ApprovedRequestJournal, ContentDigest, RetainedRequest, TransactionId, TransactionStoreError,
};

const DOMAIN: &str = "linura.display.recovery-phase.v1";
const MAX_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Reserved,
    Dispatched,
    ConfirmRequested,
    RevertRequested,
    Confirmed,
    Restored,
}
impl Phase {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Dispatched => "dispatched",
            Self::ConfirmRequested => "confirm-requested",
            Self::RevertRequested => "revert-requested",
            Self::Confirmed => "confirmed",
            Self::Restored => "restored",
        }
    }
    fn parse(text: &str) -> Result<Self, ManagedLifecycleError> {
        [
            Self::Reserved,
            Self::Dispatched,
            Self::ConfirmRequested,
            Self::RevertRequested,
            Self::Confirmed,
            Self::Restored,
        ]
        .into_iter()
        .find(|phase| phase.as_str() == text)
        .ok_or_else(invalid)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Record {
    pub(crate) request_digest: ContentDigest,
    pub(crate) transaction_id: TransactionId,
    pub(crate) phase: Phase,
    pub(crate) deadline_unix_ms: u64,
    pub(crate) recorded_at_unix_ms: u64,
    pub(crate) dispatch_digest: Option<String>,
    pub(crate) previous: Option<ContentDigest>,
    pub(crate) observation_digest: Option<ContentDigest>,
    digest: ContentDigest,
    canonical: Vec<u8>,
}
fn invalid() -> ManagedLifecycleError {
    ManagedLifecycleError::Authority(
        "display recovery journal is malformed, conflicting or unsupported".into(),
    )
}
fn optional_digest(value: &str) -> Result<Option<ContentDigest>, ManagedLifecycleError> {
    if value.is_empty() {
        Ok(None)
    } else {
        ContentDigest::new(value).map(Some).map_err(|_| invalid())
    }
}
impl Record {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        request_digest: ContentDigest,
        transaction_id: TransactionId,
        phase: Phase,
        deadline_unix_ms: u64,
        recorded_at_unix_ms: u64,
        dispatch_digest: Option<String>,
        previous: Option<ContentDigest>,
        observation_digest: Option<ContentDigest>,
    ) -> Result<Self, ManagedLifecycleError> {
        if deadline_unix_ms == 0
            || recorded_at_unix_ms == 0
            || request_digest == ContentDigest::zero()
            || previous.as_ref() == Some(&ContentDigest::zero())
            || observation_digest.as_ref() == Some(&ContentDigest::zero())
            || matches!(
                phase,
                Phase::ConfirmRequested
                    | Phase::RevertRequested
                    | Phase::Confirmed
                    | Phase::Restored
            ) && observation_digest.is_none()
            || dispatch_digest.as_ref().is_some_and(|digest| {
                digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            || (phase == Phase::Reserved) != previous.is_none()
            || (phase == Phase::Reserved) != dispatch_digest.is_none()
            || matches!(phase, Phase::ConfirmRequested | Phase::RevertRequested)
                && recorded_at_unix_ms >= deadline_unix_ms
        {
            return Err(invalid());
        }
        let mut canonical = Vec::new();
        for field in [
            DOMAIN,
            request_digest.as_str(),
            transaction_id.as_str(),
            phase.as_str(),
            &deadline_unix_ms.to_string(),
            &recorded_at_unix_ms.to_string(),
            dispatch_digest.as_deref().unwrap_or(""),
            previous.as_ref().map_or("", ContentDigest::as_str),
            observation_digest
                .as_ref()
                .map_or("", ContentDigest::as_str),
        ] {
            if field.len() > 256 {
                return Err(invalid());
            }
            canonical.extend_from_slice(&(field.len() as u64).to_be_bytes());
            canonical.extend_from_slice(field.as_bytes());
        }
        if canonical.len() > MAX_BYTES {
            return Err(invalid());
        }
        let digest = linura_transaction::digest_parts(
            "linura.display.recovery-phase.digest.v1",
            [canonical.as_slice()],
        );
        Ok(Self {
            request_digest,
            transaction_id,
            phase,
            deadline_unix_ms,
            recorded_at_unix_ms,
            dispatch_digest,
            previous,
            observation_digest,
            digest,
            canonical,
        })
    }
    pub(crate) fn digest(&self) -> &ContentDigest {
        &self.digest
    }
    fn key(request: &ContentDigest, phase: Phase) -> Result<RequestId, ManagedLifecycleError> {
        RequestId::new(format!(
            "request:v010:display-recovery:{}:{}",
            request.hex(),
            phase.as_str()
        ))
        .map_err(|_| invalid())
    }
    fn decode(bytes: &[u8]) -> Result<Self, ManagedLifecycleError> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(invalid());
        }
        let mut rest = bytes;
        let mut read = || -> Result<&str, ManagedLifecycleError> {
            let (size, tail) = rest.split_at_checked(8).ok_or_else(invalid)?;
            let size = usize::try_from(u64::from_be_bytes(size.try_into().map_err(|_| invalid())?))
                .map_err(|_| invalid())?;
            if size > 256 {
                return Err(invalid());
            }
            let (field, tail) = tail.split_at_checked(size).ok_or_else(invalid)?;
            rest = tail;
            std::str::from_utf8(field).map_err(|_| invalid())
        };
        if read()? != DOMAIN {
            return Err(invalid());
        }
        let request = ContentDigest::new(read()?).map_err(|_| invalid())?;
        let transaction = TransactionId::new(read()?).map_err(|_| invalid())?;
        let phase = Phase::parse(read()?)?;
        let deadline = read()?.parse().map_err(|_| invalid())?;
        let sampled = read()?.parse().map_err(|_| invalid())?;
        let dispatch = read()?;
        let dispatch = if dispatch.is_empty() {
            None
        } else {
            Some(dispatch.into())
        };
        let previous = optional_digest(read()?)?;
        let observation = optional_digest(read()?)?;
        if !rest.is_empty() {
            return Err(invalid());
        }
        let result = Self::new(
            request,
            transaction,
            phase,
            deadline,
            sampled,
            dispatch,
            previous,
            observation,
        )?;
        if result.canonical != bytes {
            return Err(invalid());
        }
        Ok(result)
    }
    pub(crate) fn load(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        request: &ContentDigest,
        phase: Phase,
    ) -> Result<Option<Self>, ManagedLifecycleError> {
        let retained = match journal.load(principal, &Self::key(request, phase)?) {
            Ok(record) => record,
            Err(TransactionStoreError::NotFound) => return Ok(None),
            Err(error) => return Err(ManagedLifecycleError::Authority(error.to_string())),
        };
        if retained.principal() != principal {
            return Err(invalid());
        }
        let record = Self::decode(retained.canonical())?;
        if &record.request_digest != request || record.phase != phase {
            return Err(invalid());
        }
        Ok(Some(record))
    }
    pub(crate) fn append(
        &self,
        journal: &mut dyn ApprovedRequestJournal,
        principal: PrincipalId,
        previous: Option<&Self>,
    ) -> Result<(), ManagedLifecycleError> {
        self.validate_after(previous)?;
        journal
            .retain(
                &RetainedRequest::new(
                    principal,
                    Self::key(&self.request_digest, self.phase)?,
                    self.canonical.clone(),
                )
                .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))?,
            )
            .map_err(|e| ManagedLifecycleError::Authority(e.to_string()))
    }
    pub(crate) fn validate_after(
        &self,
        previous: Option<&Self>,
    ) -> Result<(), ManagedLifecycleError> {
        match (previous, self.phase) {
            (None, Phase::Reserved) => {}
            (Some(prior), phase)
                if self.previous.as_ref() == Some(prior.digest())
                    && self.request_digest == prior.request_digest
                    && self.transaction_id == prior.transaction_id
                    && self.deadline_unix_ms == prior.deadline_unix_ms
                    && self.recorded_at_unix_ms >= prior.recorded_at_unix_ms
                    && (prior.dispatch_digest.is_none()
                        || self.dispatch_digest == prior.dispatch_digest)
                    && matches!(
                        (prior.phase, phase),
                        (Phase::Reserved, Phase::Dispatched)
                            | (
                                Phase::Dispatched,
                                Phase::ConfirmRequested | Phase::RevertRequested | Phase::Restored
                            )
                            | (Phase::ConfirmRequested, Phase::Confirmed | Phase::Restored)
                            | (Phase::RevertRequested, Phase::Restored)
                    ) => {}
            _ => return Err(invalid()),
        }
        Ok(())
    }
}
