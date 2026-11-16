//! Immutable ordinary current-completion correlations. These are comparison
//! records in the authenticated journal, never review or execution authority.
use super::*;
use linura_transaction::{ContentDigest, RetainedRequest, digest_bytes};
const LIMIT: usize = 8192;

#[derive(Clone, Copy, Debug)]
pub(in crate::managed_lifecycle::display) enum Kind {
    Ready,
    Verified,
    Committed,
    NativePrepared,
    NativeVerified,
    FinalPrepared,
    FinalVerified,
    Released,
    Adopted,
    AdoptedState,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Verified => "verified",
            Self::Committed => "committed",
            Self::NativePrepared => "native-prepared",
            Self::NativeVerified => "native-verified",
            Self::FinalPrepared => "final-prepared",
            Self::FinalVerified => "final-verified",
            Self::Released => "released",
            Self::Adopted => "adopted",
            Self::AdoptedState => "adopted-state",
        }
    }
    fn domain(self) -> String {
        format!("linura.display.ordinary-current-{}.v1", self.name())
    }
    pub(in crate::managed_lifecycle::display) fn key(
        self,
        request: &RequestId,
    ) -> Result<RequestId, ManagedLifecycleError> {
        RequestId::new(format!(
            "request:v010:display-ordinary-current-{}:{}",
            self.name(),
            digest_bytes(
                "linura.display.ordinary-current-key.v1",
                request.as_str().as_bytes()
            )
            .hex()
        ))
        .map_err(|_| invalid_original())
    }
    fn count(self) -> usize {
        match self {
            Self::Ready => 12,
            Self::Verified => 10,
            Self::Committed => 11,
            Self::NativePrepared => 10,
            Self::NativeVerified => 8,
            Self::FinalPrepared => 11,
            Self::FinalVerified => 14,
            Self::Released => 10,
            Self::Adopted => 15,
            Self::AdoptedState => 17,
        }
    }
}
fn append(out: &mut Vec<u8>, v: &str) -> Result<(), ManagedLifecycleError> {
    if v.is_empty() || v.len() > 256 || out.len().checked_add(8 + v.len()).is_none_or(|n| n > LIMIT)
    {
        return Err(invalid_original());
    }
    out.extend_from_slice(&(v.len() as u64).to_be_bytes());
    out.extend_from_slice(v.as_bytes());
    Ok(())
}
pub(in crate::managed_lifecycle::display) fn number(
    raw: &str,
) -> Result<u64, ManagedLifecycleError> {
    let v = raw.parse::<u64>().map_err(|_| invalid_original())?;
    if v.to_string() != raw {
        return Err(invalid_original());
    }
    Ok(v)
}
pub(in crate::managed_lifecycle::display) fn digest(
    raw: &str,
) -> Result<ContentDigest, ManagedLifecycleError> {
    let d = ContentDigest::new(raw).map_err(|_| invalid_original())?;
    if d == ContentDigest::zero() {
        return Err(invalid_original());
    }
    Ok(d)
}
#[derive(Debug)]
pub(in crate::managed_lifecycle::display) struct Entry {
    pub(in crate::managed_lifecycle::display) fields: Vec<String>,
    bytes: Vec<u8>,
    kind: Kind,
}
impl Entry {
    fn header(
        kind: Kind,
        pid: &PrincipalId,
        request: &PlanDesiredStateRequest,
    ) -> Result<Vec<String>, ManagedLifecycleError> {
        let payload = request
            .desired_state
            .get("release_ordinary")
            .ok_or_else(invalid_original)?;
        Ok(vec![
            kind.domain(),
            pid.as_str().into(),
            request.request_id.as_str().into(),
            crate::durable_authority::digest_request(request)?
                .as_str()
                .into(),
            digest_bytes(
                "linura.display.ordinary-current-material.v1",
                payload.as_bytes(),
            )
            .as_str()
            .into(),
        ])
    }
    fn encode(kind: Kind, fields: Vec<String>) -> Result<Self, ManagedLifecycleError> {
        if fields.len() != kind.count() {
            return Err(invalid_original());
        }
        let mut bytes = Vec::new();
        for v in &fields {
            append(&mut bytes, v)?;
        }
        Ok(Self {
            fields,
            bytes,
            kind,
        })
    }
    pub(in crate::managed_lifecycle::display) fn load(
        journal: &dyn ApprovedRequestJournal,
        kind: Kind,
        pid: &PrincipalId,
        request: &PlanDesiredStateRequest,
    ) -> Result<Self, ManagedLifecycleError> {
        let k = kind.key(&request.request_id)?;
        let row = journal.load(pid, &k).map_err(|_| invalid_original())?;
        if row.principal() != pid || row.request_id() != &k || row.canonical().len() > LIMIT {
            return Err(invalid_original());
        }
        let mut rest = row.canonical();
        let mut fields = Vec::new();
        while !rest.is_empty() {
            let (n, body) = rest.split_at_checked(8).ok_or_else(invalid_original)?;
            let n = usize::try_from(u64::from_be_bytes(
                n.try_into().map_err(|_| invalid_original())?,
            ))
            .map_err(|_| invalid_original())?;
            if n == 0 || n > 256 || fields.len() >= kind.count() {
                return Err(invalid_original());
            }
            let (v, tail) = body.split_at_checked(n).ok_or_else(invalid_original)?;
            fields.push(
                std::str::from_utf8(v)
                    .map_err(|_| invalid_original())?
                    .to_owned(),
            );
            rest = tail;
        }
        let e = Self::encode(kind, fields)?;
        if e.bytes != row.canonical() || e.fields[..5] != Self::header(kind, pid, request)? {
            return Err(invalid_original());
        }
        Ok(e)
    }
    pub(in crate::managed_lifecycle::display) fn retain(
        journal: &mut dyn ApprovedRequestJournal,
        kind: Kind,
        pid: &PrincipalId,
        request: &PlanDesiredStateRequest,
        tail: Vec<String>,
    ) -> Result<Self, ManagedLifecycleError> {
        let mut fields = Self::header(kind, pid, request)?;
        fields.extend(tail);
        let e = Self::encode(kind, fields)?;
        let row =
            RetainedRequest::new(pid.clone(), kind.key(&request.request_id)?, e.bytes.clone())
                .map_err(|_| invalid_original())?;
        journal.retain(&row).map_err(|_| invalid_original())?;
        e.readback(journal, pid, request)?;
        Ok(e)
    }
    pub(in crate::managed_lifecycle::display) fn readback(
        &self,
        journal: &dyn ApprovedRequestJournal,
        pid: &PrincipalId,
        request: &PlanDesiredStateRequest,
    ) -> Result<(), ManagedLifecycleError> {
        if Self::load(journal, self.kind, pid, request)?.bytes != self.bytes {
            return Err(invalid_original());
        }
        Ok(())
    }
    pub(in crate::managed_lifecycle::display) fn digest(&self) -> ContentDigest {
        digest_bytes(&self.kind.domain(), &self.bytes)
    }
}
impl<S: TransactionStore> ManagedLifecycleControl<S> {
    /// Read-only old-state comparison tied to the actual authenticated current
    /// state and immutable before-CAS record. This cannot resume a native port.
    pub(in crate::managed_lifecycle::display) fn ordinary_current_comparison_snapshot(
        &self,
        principal: &AuthenticatedPrincipal,
        request: &PlanDesiredStateRequest,
        actual: &linura_transaction::TransactionSnapshot,
    ) -> Result<linura_transaction::TransactionSnapshot, ManagedLifecycleError> {
        if actual.state == TransactionState::Indeterminate {
            return Ok(actual.clone());
        }
        if !matches!(
            actual.state,
            TransactionState::Verified | TransactionState::Committed
        ) {
            return Err(invalid_original());
        }
        let pid = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let ready = Entry::load(self.display_journal()?, Kind::Ready, &pid, request)?;
        let version = number(&ready.fields[6])?;
        let steps = if actual.state == TransactionState::Verified {
            1
        } else {
            2
        };
        if actual.current_generation != number(&ready.fields[5])?
            || version.checked_add(steps) != Some(actual.state_version)
            || actual.binding_digest != digest(&ready.fields[7])?
            || number(&ready.fields[11])? == 0
            || number(&ready.fields[11])? > now_ms()?
        {
            return Err(invalid_original());
        }
        ComponentDigest::parse_hex(&ready.fields[8]).map_err(|_| invalid_original())?;
        digest(&ready.fields[9])?;
        ComponentDigest::parse_hex(&ready.fields[10]).map_err(|_| invalid_original())?;
        if actual.state == TransactionState::Verified {
            self.authority
                .display_verified_material(principal, request)?;
        } else {
            let verified = Entry::load(self.display_journal()?, Kind::Verified, &pid, request)?;
            if digest(&verified.fields[5])? != ready.digest()
                || number(&verified.fields[6])?
                    != version.checked_add(1).ok_or_else(invalid_original)?
            {
                return Err(invalid_original());
            }
            for raw in &verified.fields[7..10] {
                digest(raw)?;
            }
        }
        if self
            .authority
            .matching_request_snapshot(principal, request)?
            != *actual
        {
            return Err(invalid_original());
        }
        let comparison = linura_transaction::TransactionSnapshot {
            state: TransactionState::Indeterminate,
            state_version: version,
            ..actual.clone()
        };
        if self
            .ordinary_release_receipt_at(principal, request, &comparison)?
            .dispatch_digest
            .as_deref()
            != Some(ready.fields[8].as_str())
        {
            return Err(invalid_original());
        }
        Ok(comparison)
    }
}
