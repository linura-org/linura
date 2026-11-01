//! Purpose-versioned immutable display phase records in the existing protected
//! opaque journal. They retain decisions/recovery facts, never executor authority.
use crate::ManagedLifecycleError;
use linura_core::{PrincipalId, RequestId};
use linura_transaction::{
    ApprovedRequestJournal, ContentDigest, RetainedRequest, TransactionId, TransactionStoreError,
};

const DOMAIN: &str = "linura.display.recovery-phase.v1";
const PROTECTED_DECISION_DOMAIN: &str = "linura.display.recovery-protected-decision.v2";
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
    pub(crate) protected_decision_digest: Option<ContentDigest>,
    digest: ContentDigest,
    canonical: Vec<u8>,
}
fn invalid() -> ManagedLifecycleError {
    ManagedLifecycleError::Authority(
        "display recovery journal is malformed, conflicting or unsupported".into(),
    )
}
fn read_frame<'a>(rest: &mut &'a [u8], maximum: usize) -> Result<&'a [u8], ManagedLifecycleError> {
    let (size, tail) = rest.split_at_checked(8).ok_or_else(invalid)?;
    let size = usize::try_from(u64::from_be_bytes(size.try_into().map_err(|_| invalid())?))
        .map_err(|_| invalid())?;
    if size > maximum {
        return Err(invalid());
    }
    let (field, tail) = tail.split_at_checked(size).ok_or_else(invalid)?;
    *rest = tail;
    Ok(field)
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
            || matches!(phase, Phase::Reserved | Phase::Dispatched)
                && recorded_at_unix_ms >= deadline_unix_ms
            || phase == Phase::Reserved
                && deadline_unix_ms.saturating_sub(recorded_at_unix_ms)
                    > crate::managed_lifecycle::DISPLAY_CONFIRMATION_WINDOW_MS
            || request_digest == ContentDigest::zero()
            || previous.as_ref() == Some(&ContentDigest::zero())
            || observation_digest.as_ref() == Some(&ContentDigest::zero())
            // Pre-effect reservation and dispatch phases cannot contain
            // post-effect observation evidence, even if they arrive through a
            // structurally valid retained-record payload.
            || matches!(phase, Phase::Reserved | Phase::Dispatched)
                && observation_digest.is_some()
            || matches!(
                phase,
                Phase::ConfirmRequested
                    | Phase::RevertRequested
                    | Phase::Confirmed
                    | Phase::Restored
            ) && observation_digest.is_none()
            || dispatch_digest.as_ref().is_some_and(|digest| {
                digest.len() != 64
                    || digest == &"0".repeat(64)
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
            protected_decision_digest: None,
            digest,
            canonical,
        })
    }
    /// Add the consumed protected challenge correlation to a decision phase.
    /// This distinct persisted version preserves v1 bytes and their meaning;
    /// reading legacy unprotected decisions never manufactures a human proof.
    pub(crate) fn with_protected_decision(
        mut self,
        proof: ContentDigest,
    ) -> Result<Self, ManagedLifecycleError> {
        if !matches!(self.phase, Phase::ConfirmRequested | Phase::RevertRequested)
            || self.protected_decision_digest.is_some()
            || proof == ContentDigest::zero()
        {
            return Err(invalid());
        }
        let mut canonical = Vec::new();
        for bytes in [
            PROTECTED_DECISION_DOMAIN.as_bytes(),
            self.canonical.as_slice(),
            proof.as_str().as_bytes(),
        ] {
            canonical.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            canonical.extend_from_slice(bytes);
        }
        if canonical.len() > MAX_BYTES {
            return Err(invalid());
        }
        self.digest = linura_transaction::digest_parts(
            "linura.display.recovery-protected-decision.digest.v2",
            [canonical.as_slice()],
        );
        self.canonical = canonical;
        self.protected_decision_digest = Some(proof);
        Ok(self)
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
        // Version 2 wraps the original phase bytes plus a challenge digest.
        // No rewriting, automatic approval upgrade or destructive migration.
        let mut framed = bytes;
        let domain = read_frame(&mut framed, 256)?;
        if domain == PROTECTED_DECISION_DOMAIN.as_bytes() {
            let legacy = read_frame(&mut framed, MAX_BYTES)?;
            let proof =
                std::str::from_utf8(read_frame(&mut framed, 256)?).map_err(|_| invalid())?;
            if !framed.is_empty() {
                return Err(invalid());
            }
            // Nested wrappers are invalid, even within the aggregate byte cap.
            let mut inner = legacy;
            if read_frame(&mut inner, 256)? != DOMAIN.as_bytes() {
                return Err(invalid());
            }
            let result = Self::decode(legacy)?
                .with_protected_decision(ContentDigest::new(proof).map_err(|_| invalid())?)?;
            if result.canonical != bytes {
                return Err(invalid());
            }
            return Ok(result);
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
        // A journal backend must return the exact addressed record. Checking
        // its payload alone would accept substituted phase-key material from
        // a compromised or incorrect retention implementation.
        if retained.principal() != principal || retained.request_id() != &Self::key(request, phase)?
        {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn id<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error:?}"))
    }

    fn fixture() -> (PrincipalId, ContentDigest, Record) {
        let principal = id(PrincipalId::new("unix:uid:1000"));
        let request_id = id(RequestId::new("request:v010:display-fixture"));
        let digest = linura_transaction::digest_parts(
            "linura.display.recovery-test.request.v1",
            [b"request".as_slice()],
        );
        let transaction = TransactionId::for_namespace(&principal, &request_id);
        let record = id(Record::new(
            digest.clone(),
            transaction,
            Phase::Reserved,
            200,
            100,
            None,
            None,
            None,
        ));
        (principal, digest, record)
    }

    #[test]
    fn protected_decision_has_an_explicit_roundtripping_persisted_version() {
        let (_, request, reserved) = fixture();
        let legacy = id(Record::new(
            request,
            reserved.transaction_id.clone(),
            Phase::ConfirmRequested,
            200,
            120,
            Some("a".repeat(64)),
            Some(reserved.digest().clone()),
            Some(linura_transaction::digest_parts(
                "decision-observation-test",
                [b"native".as_slice()],
            )),
        ));
        let proof =
            linura_transaction::digest_parts("decision-proof-test", [b"protected".as_slice()]);
        let protected = id(legacy.clone().with_protected_decision(proof.clone()));
        assert_ne!(protected.digest(), legacy.digest());
        assert_eq!(id(Record::decode(&legacy.canonical)), legacy);
        assert_eq!(id(Record::decode(&protected.canonical)), protected);
        assert_eq!(protected.protected_decision_digest, Some(proof.clone()));
        assert!(
            protected
                .clone()
                .with_protected_decision(proof.clone())
                .is_err()
        );
        assert!(reserved.with_protected_decision(proof).is_err());
        assert!(
            legacy
                .with_protected_decision(ContentDigest::zero())
                .is_err()
        );
        let mut appended = protected.canonical.clone();
        appended.push(0);
        assert!(Record::decode(&appended).is_err());
        for size in [0, 7, 50, protected.canonical.len() - 1] {
            assert!(Record::decode(&protected.canonical[..size]).is_err());
        }
    }

    #[derive(Debug)]
    struct SubstitutionJournal(RetainedRequest);

    impl ApprovedRequestJournal for SubstitutionJournal {
        fn retain(&mut self, _: &RetainedRequest) -> Result<(), TransactionStoreError> {
            Err(TransactionStoreError::AuthorityRejected)
        }

        fn load(
            &self,
            _: &PrincipalId,
            _: &RequestId,
        ) -> Result<RetainedRequest, TransactionStoreError> {
            Ok(self.0.clone())
        }

        fn integrity_check(&self) -> Result<(), TransactionStoreError> {
            Ok(())
        }
    }

    #[test]
    fn journal_rejects_substituted_phase_key_even_with_valid_payload() {
        let (principal, request, reserved) = fixture();
        let wrong_key = id(Record::key(&request, Phase::Dispatched));
        let substituted = SubstitutionJournal(id(RetainedRequest::new(
            principal.clone(),
            wrong_key,
            reserved.canonical.clone(),
        )));
        assert!(Record::load(&substituted, &principal, &request, Phase::Reserved).is_err());

        let correct = SubstitutionJournal(id(RetainedRequest::new(
            principal.clone(),
            id(Record::key(&request, Phase::Reserved)),
            reserved.canonical.clone(),
        )));
        assert_eq!(
            id(Record::load(
                &correct,
                &principal,
                &request,
                Phase::Reserved
            )),
            Some(reserved)
        );
    }

    #[test]
    fn preeffect_phases_refuse_posteffect_observation_evidence() {
        let (_, request, reserved) = fixture();
        let observation = linura_transaction::digest_parts(
            "linura.display.recovery-test.observation.v1",
            [b"native".as_slice()],
        );
        assert!(
            Record::new(
                request.clone(),
                reserved.transaction_id.clone(),
                Phase::Reserved,
                200,
                100,
                None,
                None,
                Some(observation.clone()),
            )
            .is_err()
        );
        assert!(
            Record::new(
                request.clone(),
                reserved.transaction_id.clone(),
                Phase::Dispatched,
                200,
                110,
                Some("a".repeat(64)),
                Some(reserved.digest().clone()),
                Some(observation),
            )
            .is_err()
        );
        assert!(
            Record::new(
                request,
                reserved.transaction_id.clone(),
                Phase::Dispatched,
                200,
                110,
                Some("a".repeat(64)),
                Some(reserved.digest().clone()),
                None,
            )
            .is_ok()
        );
    }

    #[test]
    fn recovery_phases_are_linear_and_reject_terminal_replay() {
        let (_, request, reserved) = fixture();
        let dispatch_digest = "a".repeat(64);
        let dispatched = id(Record::new(
            request.clone(),
            reserved.transaction_id.clone(),
            Phase::Dispatched,
            200,
            110,
            Some(dispatch_digest.clone()),
            Some(reserved.digest().clone()),
            None,
        ));
        assert!(dispatched.validate_after(Some(&reserved)).is_ok());

        let observation = linura_transaction::digest_parts(
            "linura.display.recovery-test.observation.v1",
            [b"native".as_slice()],
        );
        let decision = id(Record::new(
            request.clone(),
            reserved.transaction_id.clone(),
            Phase::ConfirmRequested,
            200,
            120,
            Some(dispatch_digest.clone()),
            Some(dispatched.digest().clone()),
            Some(observation.clone()),
        ));
        assert!(decision.validate_after(Some(&dispatched)).is_ok());

        let confirmed = id(Record::new(
            request.clone(),
            reserved.transaction_id.clone(),
            Phase::Confirmed,
            200,
            130,
            Some(dispatch_digest.clone()),
            Some(decision.digest().clone()),
            Some(observation.clone()),
        ));
        assert!(confirmed.validate_after(Some(&decision)).is_ok());

        let restored = id(Record::new(
            request,
            reserved.transaction_id.clone(),
            Phase::Restored,
            200,
            140,
            Some(dispatch_digest),
            Some(confirmed.digest().clone()),
            Some(observation),
        ));
        assert!(restored.validate_after(Some(&confirmed)).is_err());
        assert!(decision.validate_after(Some(&confirmed)).is_err());
        assert!(dispatched.validate_after(Some(&dispatched)).is_err());
    }
}
