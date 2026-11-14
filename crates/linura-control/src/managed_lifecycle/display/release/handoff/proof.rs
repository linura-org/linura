//! Immutable first independently joined ordinary handoff. Reconciliation reads
//! current sources; it never changes the first proof, expiry or effect count.
use super::*;
use linura_transaction::{ContentDigest, RetainedRequest, TransactionStoreError, digest_bytes};
const DOMAIN: &str = "linura.display.ordinary-handoff-verified.v1";
const MAX_BYTES: usize = 32 * 1024;

#[derive(Debug)]
pub struct OrdinaryDisplayHandoffVerification {
    inspection: OrdinaryDisplayHandoffInspection,
    record_digest: ContentDigest,
    first_verified_unix_ms: u64,
    first_valid_until_unix_ms: u64,
}
impl OrdinaryDisplayHandoffVerification {
    #[must_use]
    pub const fn inspection(&self) -> &OrdinaryDisplayHandoffInspection {
        &self.inspection
    }
    #[must_use]
    pub const fn record_digest(&self) -> &ContentDigest {
        &self.record_digest
    }
    #[must_use]
    pub const fn first_verified_unix_ms(&self) -> u64 {
        self.first_verified_unix_ms
    }
    #[must_use]
    pub const fn first_valid_until_unix_ms(&self) -> u64 {
        self.first_valid_until_unix_ms
    }
}
fn append(bytes: &mut Vec<u8>, value: &str) -> Result<(), ManagedLifecycleError> {
    if value.is_empty()
        || bytes
            .len()
            .checked_add(8)
            .and_then(|n| n.checked_add(value.len()))
            .is_none_or(|n| n > MAX_BYTES)
    {
        return Err(invalid_original());
    }
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}
fn field<'a>(rest: &mut &'a [u8], bound: usize) -> Result<&'a str, ManagedLifecycleError> {
    let (size, bytes) = rest.split_at_checked(8).ok_or_else(invalid_original)?;
    let size = usize::try_from(u64::from_be_bytes(
        size.try_into().map_err(|_| invalid_original())?,
    ))
    .map_err(|_| invalid_original())?;
    if size == 0 || size > bound {
        return Err(invalid_original());
    }
    let (value, tail) = bytes.split_at_checked(size).ok_or_else(invalid_original)?;
    let value = std::str::from_utf8(value).map_err(|_| invalid_original())?;
    *rest = tail;
    Ok(value)
}
fn number(rest: &mut &[u8]) -> Result<u64, ManagedLifecycleError> {
    let raw = field(rest, 20)?;
    let value = raw.parse::<u64>().map_err(|_| invalid_original())?;
    if value == 0 || value.to_string() != raw {
        return Err(invalid_original());
    }
    Ok(value)
}

fn identity(
    principal: &PrincipalId,
    inspection: &OrdinaryDisplayHandoffInspection,
) -> Result<Vec<u8>, ManagedLifecycleError> {
    let mut bytes = Vec::new();
    let snapshot = &inspection.release;
    let root = inspection.root.comparison();
    if snapshot.principal != *principal
        || snapshot.request_id != inspection.request.request_id
        || snapshot.state != TransactionState::Indeterminate
        || !inspection.root.matches_native(&inspection.frames)
    {
        return Err(invalid_original());
    }
    for value in [
        DOMAIN.into(),
        principal.as_str().into(),
        inspection.request.request_id.as_str().into(),
        snapshot.transaction_id.as_str().into(),
        snapshot.current_generation.to_string(),
        snapshot.state_version.to_string(),
        snapshot.binding_digest.as_str().into(),
        crate::durable_authority::digest_request(&inspection.request)?
            .as_str()
            .into(),
        root.preparation_digest.clone(),
        root.material.clone(),
        root.producer.observed_unix_ms.to_string(),
        root.producer.observed_boot_ms.to_string(),
        root.producer.deadline_unix_ms.to_string(),
        root.producer.deadline_boot_ms.to_string(),
    ] {
        append(&mut bytes, &value)?;
    }
    for (key, value) in inspection.frames.attributes() {
        // Read time may advance; immutable output/lineage/producer deadlines may not.
        if key == "sampled_boot_ms" {
            continue;
        }
        append(&mut bytes, &key)?;
        let (kind, value) = match value {
            ObservedValue::Text(value) => ("text", value),
            ObservedValue::U64(value) => ("u64", value.to_string()),
            ObservedValue::Bool(value) => ("bool", value.to_string()),
            _ => return Err(invalid_original()),
        };
        append(&mut bytes, kind)?;
        append(&mut bytes, &value)?;
    }
    Ok(bytes)
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    /// Persist the first physical comparison, or compare it after a lost ACK or
    /// restart. A proof digest cannot be used as a continuation/retirement permit.
    pub fn verify_ordinary_display_handoff<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        request: &RequestId,
        attempt: &mut P,
        verifier: &mut V,
    ) -> Result<OrdinaryDisplayHandoffVerification, ManagedLifecycleError> {
        let inspection =
            self.inspect_ordinary_display_handoff(principal.clone(), request, attempt, verifier)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let immutable = identity(&principal_id, &inspection)?;
        let key = RequestId::new(format!(
            "request:v010:display-ordinary-physical-verified:{}",
            digest_bytes(
                "linura.display.ordinary-handoff-verified-key.v1",
                request.as_str().as_bytes()
            )
            .hex()
        ))
        .map_err(|_| invalid_original())?;
        let now = now_ms()?;
        inspection
            .observation
            .require_current(now)
            .map_err(|_| invalid_original())?;
        let expiry = inspection
            .observation
            .observed_at_unix_ms
            .checked_add(inspection.observation.valid_for_ms)
            .ok_or_else(invalid_original)?;
        let mut canonical = Vec::new();
        append(&mut canonical, &now.to_string())?;
        append(&mut canonical, &expiry.to_string())?;
        append(
            &mut canonical,
            crate::durable_authority::digest_observation(&inspection.observation)?.as_str(),
        )?;
        canonical.extend_from_slice(&immutable);
        if canonical.len() > MAX_BYTES {
            return Err(invalid_original());
        }
        let existing = {
            let journal = self.display_journal()?;
            let _scope = journal
                .checked_read_scope()
                .map_err(|_| invalid_original())?;
            journal.load(&principal_id, &key)
        };
        match existing {
            Err(TransactionStoreError::NotFound) => self
                .request_journal
                .as_mut()
                .ok_or_else(invalid_original)?
                .retain(
                    &RetainedRequest::new(principal_id.clone(), key.clone(), canonical)
                        .map_err(|_| invalid_original())?,
                )
                .map_err(|_| invalid_original())?,
            Ok(_) => (),
            Err(_) => return Err(invalid_original()),
        }
        let retained = {
            let journal = self.display_journal()?;
            let _scope = journal
                .checked_read_scope()
                .map_err(|_| invalid_original())?;
            journal
                .load(&principal_id, &key)
                .map_err(|_| invalid_original())?
        };
        if retained.principal() != &principal_id
            || retained.request_id() != &key
            || retained.canonical().len() > MAX_BYTES
        {
            return Err(invalid_original());
        }
        let mut rest = retained.canonical();
        let first_verified_unix_ms = number(&mut rest)?;
        let first_valid_until_unix_ms = number(&mut rest)?;
        if ContentDigest::new(field(&mut rest, 256)?).map_err(|_| invalid_original())?
            == ContentDigest::zero()
            || rest != immutable
            || first_verified_unix_ms < inspection.root.comparison().producer.observed_unix_ms
            || first_verified_unix_ms >= first_valid_until_unix_ms
            || first_verified_unix_ms > now
            || first_valid_until_unix_ms > inspection.root.comparison().producer.deadline_unix_ms
            || now >= first_valid_until_unix_ms
        {
            return Err(invalid_original());
        }
        // Storage latency or concurrent source change cannot turn a historical
        // readback into current proof. Re-read every contributor after retention.
        let fresh = self.inspect_ordinary_display_handoff(principal, request, attempt, verifier)?;
        if identity(&principal_id, &fresh)? != immutable
            || !fresh.frames.reconciles(&inspection.frames)
            || now_ms()? >= first_valid_until_unix_ms
        {
            return Err(invalid_original());
        }
        Ok(OrdinaryDisplayHandoffVerification {
            inspection: fresh,
            record_digest: digest_bytes(DOMAIN, retained.canonical()),
            first_verified_unix_ms,
            first_valid_until_unix_ms,
        })
    }
}
