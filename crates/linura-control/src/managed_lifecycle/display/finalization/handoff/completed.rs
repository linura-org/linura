//! Durable original CurrentCommitted bookkeeping. Every invocation observes the
//! real current Root/native state; no restart path dispatches a physical effect.
//! The before-CAS context is retained as comparison, never as approval or a
//! manufactured native observation. Future admission remains separately held.
use super::*;
use linura_transaction::{ContentDigest, RetainedRequest, TransactionStoreError, digest_bytes};

const LIMIT: usize = 4 * 1024;
#[derive(Clone, Copy)]
pub(super) enum Kind {
    Ready,
    Verified,
    Committed,
    NativePrepared,
    NativeVerified,
    FinalPrepared,
    FinalVerified,
    Released,
}
impl Kind {
    pub(super) fn domain(self) -> &'static str {
        match self {
            Self::Ready => "linura.display.original-current-completion-prepared.v1",
            Self::Verified => "linura.display.original-current-completion-verified.v1",
            Self::Committed => "linura.display.original-current-committed.v1",
            Self::NativePrepared => "linura.display.original-native-current-prepared.v1",
            Self::NativeVerified => "linura.display.original-native-current-verified.v1",
            Self::FinalPrepared => "linura.display.original-final-retirement-prepared.v1",
            Self::FinalVerified => "linura.display.original-final-retirement-verified.v1",
            Self::Released => "linura.display.original-released-current.v1",
        }
    }
    fn prefix(self) -> &'static str {
        match self {
            Self::Ready => "display-current-completion-prepared",
            Self::Verified => "display-current-completion-verified",
            Self::Committed => "display-current-committed",
            Self::NativePrepared => "display-native-current-prepared",
            Self::NativeVerified => "display-native-current-verified",
            Self::FinalPrepared => "display-final-retirement-prepared",
            Self::FinalVerified => "display-final-retirement-verified",
            Self::Released => "display-released-current",
        }
    }
    pub(super) fn key(self, request: &RequestId) -> Result<RequestId, ManagedLifecycleError> {
        RequestId::new(format!(
            "request:v010:{}:{}",
            self.prefix(),
            digest_bytes(self.domain(), request.as_str().as_bytes()).hex()
        ))
        .map_err(|_| invalid())
    }
}
pub(super) fn encode(fields: &[String]) -> Result<Vec<u8>, ManagedLifecycleError> {
    let mut out = Vec::new();
    for value in fields {
        if value.is_empty()
            || value.len() > 256
            || out
                .len()
                .checked_add(8 + value.len())
                .is_none_or(|n| n > LIMIT)
        {
            return Err(invalid());
        }
        out.extend_from_slice(&(value.len() as u64).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    Ok(out)
}
pub(super) fn decode(bytes: &[u8]) -> Result<Vec<String>, ManagedLifecycleError> {
    if bytes.is_empty() || bytes.len() > LIMIT {
        return Err(invalid());
    }
    let mut rest = bytes;
    let mut fields = Vec::new();
    while !rest.is_empty() {
        let (size, body) = rest.split_at_checked(8).ok_or_else(invalid)?;
        let size = usize::try_from(u64::from_be_bytes(size.try_into().map_err(|_| invalid())?))
            .map_err(|_| invalid())?;
        if size == 0 || size > 256 || fields.len() >= 24 {
            return Err(invalid());
        }
        let (value, tail) = body.split_at_checked(size).ok_or_else(invalid)?;
        fields.push(std::str::from_utf8(value).map_err(|_| invalid())?.into());
        rest = tail;
    }
    if encode(&fields)? != bytes {
        return Err(invalid());
    }
    Ok(fields)
}
pub(super) fn unsigned(raw: &str) -> Result<u64, ManagedLifecycleError> {
    let n = raw.parse::<u64>().map_err(|_| invalid())?;
    if n.to_string() != raw {
        return Err(invalid());
    }
    Ok(n)
}
pub(super) fn content(raw: &str) -> Result<ContentDigest, ManagedLifecycleError> {
    let digest = ContentDigest::new(raw).map_err(|_| invalid())?;
    if digest == ContentDigest::zero() {
        return Err(invalid());
    }
    Ok(digest)
}
fn raw_digest(raw: &str) -> Result<(), ManagedLifecycleError> {
    let parsed = ComponentDigest::parse_hex(raw).map_err(|_| invalid())?;
    if parsed == ComponentDigest::from_bytes([0; 32]) || parsed.to_hex() != raw {
        return Err(invalid());
    }
    Ok(())
}
fn validate_fields(kind: Kind, fields: &[String]) -> Result<(), ManagedLifecycleError> {
    let expected = match kind {
        Kind::Ready => 12,
        Kind::Verified | Kind::Committed => 11,
        Kind::NativePrepared | Kind::NativeVerified | Kind::Released => 10,
        Kind::FinalPrepared => 11,
        Kind::FinalVerified => 14,
    };
    if fields.len() != expected {
        return Err(invalid());
    }
    match kind {
        Kind::Ready => {
            unsigned(&fields[5])?;
            if unsigned(&fields[6])? == 0 {
                return Err(invalid());
            }
            content(&fields[7])?;
            raw_digest(&fields[8])?;
            content(&fields[9])?;
            raw_digest(&fields[10])?;
        }
        Kind::Verified => {
            content(&fields[5])?;
            if unsigned(&fields[6])? == 0 {
                return Err(invalid());
            }
            for value in &fields[7..10] {
                content(value)?;
            }
        }
        Kind::Committed => {
            content(&fields[5])?;
            content(&fields[6])?;
            if unsigned(&fields[7])? == 0 {
                return Err(invalid());
            }
            raw_digest(&fields[8])?;
            content(&fields[9])?;
        }
        Kind::NativePrepared => {
            content(&fields[5])?;
            raw_digest(&fields[6])?;
            content(&fields[7])?;
            if unsigned(&fields[8])? <= unsigned(&fields[9])? {
                return Err(invalid());
            }
        }
        Kind::FinalPrepared => {
            content(&fields[5])?;
            content(&fields[6])?;
            raw_digest(&fields[7])?;
            content(&fields[8])?;
            if unsigned(&fields[9])? <= unsigned(&fields[10])? {
                return Err(invalid());
            }
        }
        Kind::FinalVerified => {
            content(&fields[5])?;
            content(&fields[6])?;
            raw_digest(&fields[7])?;
            content(&fields[8])?;
            linura_observation::DisplayNativeHandoffWindow {
                observed_unix_ms: unsigned(&fields[9])?,
                observed_boot_ms: unsigned(&fields[10])?,
                deadline_unix_ms: unsigned(&fields[11])?,
                deadline_boot_ms: unsigned(&fields[12])?,
            }
            .valid_for_ms()
            .map_err(|_| invalid())?;
        }
        Kind::Released => {
            content(&fields[5])?;
            content(&fields[6])?;
            raw_digest(&fields[7])?;
            raw_digest(&fields[8])?;
        }
        Kind::NativeVerified => {
            content(&fields[5])?;
            content(&fields[6])?;
            raw_digest(&fields[7])?;
            content(&fields[8])?;
        }
    }
    if unsigned(fields.last().ok_or_else(invalid)?)? == 0 {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn header(
    kind: Kind,
    principal: &PrincipalId,
    request: &PlanDesiredStateRequest,
) -> Result<Vec<String>, ManagedLifecycleError> {
    Ok(vec![
        kind.domain().into(),
        principal.as_str().into(),
        request.request_id.as_str().into(),
        TransactionId::for_namespace(principal, &request.request_id)
            .as_str()
            .into(),
        crate::durable_authority::digest_request(request)?
            .as_str()
            .into(),
    ])
}
#[derive(Debug)]
pub(super) struct Entry {
    pub(super) bytes: Vec<u8>,
    pub(super) fields: Vec<String>,
}
impl Entry {
    pub(super) fn load(
        journal: &dyn ApprovedRequestJournal,
        kind: Kind,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
    ) -> Result<Self, ManagedLifecycleError> {
        journal.integrity_check().map_err(|_| invalid())?;
        let key = kind.key(&request.request_id)?;
        let record = journal.load(principal, &key).map_err(|_| invalid())?;
        if record.principal() != principal || record.request_id() != &key {
            return Err(invalid());
        }
        let fields = decode(record.canonical())?;
        validate_fields(kind, &fields)?;
        if !fields.starts_with(&header(kind, principal, request)?) {
            return Err(invalid());
        }
        Ok(Self {
            bytes: record.canonical().to_vec(),
            fields,
        })
    }
    pub(super) fn digest(&self, kind: Kind) -> ContentDigest {
        digest_bytes(kind.domain(), &self.bytes)
    }
    pub(super) fn retain(
        journal: &mut dyn ApprovedRequestJournal,
        kind: Kind,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
        fields: Vec<String>,
    ) -> Result<Self, ManagedLifecycleError> {
        validate_fields(kind, &fields)?;
        let bytes = encode(&fields)?;
        let key = kind.key(&request.request_id)?;
        journal.integrity_check().map_err(|_| invalid())?;
        match journal.load(principal, &key) {
            Err(TransactionStoreError::NotFound) => journal
                .retain(
                    &RetainedRequest::new(principal.clone(), key, bytes.clone())
                        .map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?,
            Ok(record) if record.canonical() == bytes => (),
            _ => return Err(invalid()),
        };
        let stored = Self::load(journal, kind, principal, request)?;
        if stored.bytes != bytes {
            return Err(invalid());
        }
        Ok(stored)
    }
}
#[derive(Debug)]
pub struct OriginalDisplayCurrentCommit {
    terminal: TransactionSnapshot,
    record: ContentDigest,
    committed_at: u64,
}
impl OriginalDisplayCurrentCommit {
    pub const fn terminal(&self) -> &TransactionSnapshot {
        &self.terminal
    }
    pub const fn record_digest(&self) -> &ContentDigest {
        &self.record
    }
    pub const fn first_committed_at_unix_ms(&self) -> u64 {
        self.committed_at
    }
}
pub(super) fn require_ready_lineage(
    journal: &dyn ApprovedRequestJournal,
    principal: &PrincipalId,
    request: &PlanDesiredStateRequest,
    preparation: &ContentDigest,
    root_record: &str,
) -> Result<(), ManagedLifecycleError> {
    journal.integrity_check().map_err(|_| invalid())?;
    match journal.load(principal, &Kind::Ready.key(&request.request_id)?) {
        Err(TransactionStoreError::NotFound) => Ok(()),
        Ok(_) => {
            let ready = Entry::load(journal, Kind::Ready, principal, request)?;
            if ready.fields.len() != 12
                || content(&ready.fields[9])? != *preparation
                || ready.fields[10] != root_record
                || unsigned(&ready.fields[11])? == 0
                || unsigned(&ready.fields[11])? > now_ms()?
            {
                return Err(invalid());
            }
            Ok(())
        }
        Err(_) => Err(invalid()),
    }
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    /// Read-only reconstruction of the old signed context for inspecting a
    /// completion CAS, using immutable MAC-checked preparation and the ACTUAL
    /// current signed state. Effect dispatch still uses Indeterminate-only
    /// terminal_inspection_context and cannot enter this recovery path.
    pub(super) fn current_finalization_comparison_context(
        &self,
        principal: &AuthenticatedPrincipal,
        request_id: &RequestId,
    ) -> Result<TerminalInspectionContext, ManagedLifecycleError> {
        let checked = self.checked_display_history()?;
        self.current_context_from_checked(principal, request_id, &checked)
    }

    pub(super) fn current_context_from_checked(
        &self,
        principal: &AuthenticatedPrincipal,
        request_id: &RequestId,
        checked: &CheckedDisplayHistoryRead<'_>,
    ) -> Result<TerminalInspectionContext, ManagedLifecycleError> {
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let retained = self
            .display_journal()?
            .load(&principal_id, request_id)
            .map_err(|_| invalid())?;
        if retained.principal() != &principal_id || retained.request_id() != request_id {
            return Err(invalid());
        }
        let request = crate::retained_request::decode(&retained)?;
        validate_public_request(&request)?;
        validate_request_identity(&request)?;
        if !request_id
            .as_str()
            .starts_with(DISPLAY_FINALIZATION_REQUEST_PREFIX)
            || retained.digest() != &crate::durable_authority::digest_request(&request)?
        {
            return Err(invalid());
        }
        let actual = self
            .authority
            .matching_request_snapshot(principal, &request)?;
        if actual.state == TransactionState::Indeterminate {
            return self.terminal_context_from_checked(principal, request_id, checked);
        }
        if !matches!(
            actual.state,
            TransactionState::Verified | TransactionState::Committed
        ) {
            return Err(invalid());
        }
        let ready = Entry::load(
            self.display_journal()?,
            Kind::Ready,
            &principal_id,
            &request,
        )?;
        if ready.fields.len() != 12 {
            return Err(invalid());
        }
        let generation = unsigned(&ready.fields[5])?;
        let version = unsigned(&ready.fields[6])?;
        let binding = content(&ready.fields[7])?;
        let steps = if actual.state == TransactionState::Verified {
            1
        } else {
            2
        };
        if version == 0
            || actual.current_generation != generation
            || actual.state_version != version.checked_add(steps).ok_or_else(invalid)?
            || actual.binding_digest != binding
        {
            return Err(invalid());
        }
        if actual.state == TransactionState::Verified {
            self.authority
                .original_display_verified_material(principal, &request)?;
        } else {
            let verified = Entry::load(
                self.display_journal()?,
                Kind::Verified,
                &principal_id,
                &request,
            )?;
            if verified.fields.len() != 11
                || verified.fields[5] != ready.digest(Kind::Ready).as_str()
                || unsigned(&verified.fields[6])? != version.checked_add(1).ok_or_else(invalid)?
                || content(&verified.fields[7])?
                    != crate::durable_authority::digest_request(&request)?
            {
                return Err(invalid());
            }
            content(&verified.fields[8])?;
            content(&verified.fields[9])?;
            unsigned(&verified.fields[10])?;
        }
        content(&ready.fields[9])?;
        ComponentDigest::parse_hex(&ready.fields[10]).map_err(|_| invalid())?;
        let created = unsigned(&ready.fields[11])?;
        if created == 0 || created > now_ms()? {
            return Err(invalid());
        }
        let intent = FinalizationIntent::load(self.display_journal()?, &principal_id, &request)?;
        intent.require_claim(self.display_journal()?, &principal_id, &request)?;
        let digest = crate::durable_authority::digest_request(&request)?;
        let reserved = Record::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            Phase::Reserved,
        )?
        .ok_or_else(invalid)?;
        let dispatched = Record::load(
            self.display_journal()?,
            &principal_id,
            &digest,
            Phase::Dispatched,
        )?
        .ok_or_else(invalid)?;
        reserved.validate_after(None)?;
        dispatched.validate_after(Some(&reserved))?;
        if reserved.transaction_id != actual.transaction_id
            || dispatched.transaction_id != actual.transaction_id
            || dispatched.dispatch_digest.as_deref() != Some(ready.fields[8].as_str())
        {
            return Err(invalid());
        }
        let snapshot = TransactionSnapshot {
            state: TransactionState::Indeterminate,
            state_version: version,
            ..actual.clone()
        };
        let receipt = OriginalDisplayFinalizationReceipt {
            request_id: request_id.clone(),
            transaction_id: actual.transaction_id.clone(),
            dispatch_digest: dispatched.dispatch_digest,
        };
        if self
            .authority
            .matching_request_snapshot(principal, &request)?
            != actual
        {
            return Err(invalid());
        }
        Ok(TerminalInspectionContext {
            request,
            intent,
            snapshot,
            receipt,
        })
    }

    /// Commit independently verified original current state. Every retry/restart
    /// re-observes actual Root/native sources; none of these paths has an effect
    /// port, grant constructor or approval reconstruction.
    pub fn commit_original_display_current(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        terminal_request: &RequestId,
    ) -> Result<OriginalDisplayCurrentCommit, ManagedLifecycleError> {
        let proof = self
            .inspect_original_display_root_power_retirement(principal.clone(), terminal_request)?;
        let context = self.current_finalization_comparison_context(&principal, terminal_request)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let actual = self
            .authority
            .matching_request_snapshot(&principal, &context.request)?;
        let mut ready_fields = header(Kind::Ready, &principal_id, &context.request)?;
        ready_fields.extend([
            context.snapshot.current_generation.to_string(),
            context.snapshot.state_version.to_string(),
            context.snapshot.binding_digest.as_str().into(),
            context
                .receipt
                .dispatch_digest
                .clone()
                .ok_or_else(invalid)?,
            proof.preparation().as_str().into(),
            proof.root().lineage().record.clone(),
            now_ms()?.to_string(),
        ]);
        let ready = match self
            .display_journal()?
            .load(&principal_id, &Kind::Ready.key(terminal_request)?)
        {
            Err(TransactionStoreError::NotFound) => {
                if actual.state != TransactionState::Indeterminate {
                    return Err(invalid());
                }
                Entry::retain(
                    self.request_journal.as_deref_mut().ok_or_else(invalid)?,
                    Kind::Ready,
                    &principal_id,
                    &context.request,
                    ready_fields,
                )?
            }
            Ok(_) => {
                let old = Entry::load(
                    self.display_journal()?,
                    Kind::Ready,
                    &principal_id,
                    &context.request,
                )?;
                if old.fields.len() != 12
                    || old.fields[..11] != ready_fields[..11]
                    || unsigned(&old.fields[11])? > now_ms()?
                {
                    return Err(invalid());
                }
                old
            }
            Err(_) => return Err(invalid()),
        };
        self.require_current_inspection_history(&principal, proof.current())?;
        self.previews
            .build_verified_original_display_current_plan(
                &principal,
                actor.clone(),
                &context.request,
                &proof,
            )
            .map_err(|_| invalid())?;
        let snapshot = match actual.state {
            TransactionState::Indeterminate => {
                let verified = self
                    .authority
                    .verify_original_display_current_without_replay(
                        &self.previews,
                        &principal,
                        actor,
                        &context.request,
                        &proof,
                    )?;
                let material = self
                    .authority
                    .original_display_verified_material(&principal, &context.request)?;
                self.retain_current_verified(&principal_id, &context.request, &ready, &material)?;
                self.require_current_inspection_history_at(
                    &principal,
                    proof.current(),
                    &material.snapshot,
                )?;
                self.authority.commit_verified(&principal, verified)?
            }
            TransactionState::Verified => {
                let material = self
                    .authority
                    .original_display_verified_material(&principal, &context.request)?;
                self.retain_current_verified(&principal_id, &context.request, &ready, &material)?;
                self.require_current_inspection_history_at(
                    &principal,
                    proof.current(),
                    &material.snapshot,
                )?;
                let verified = self
                    .authority
                    .resume_verified(&principal, &actual.transaction_id)?;
                self.authority.commit_verified(&principal, verified)?
            }
            TransactionState::Committed => actual,
            _ => return Err(invalid()),
        };
        if snapshot.state != TransactionState::Committed
            || self
                .authority
                .matching_request_snapshot(&principal, &context.request)?
                != snapshot
        {
            return Err(invalid());
        }
        self.require_current_inspection_history_at(&principal, proof.current(), &snapshot)?;
        let verified = Entry::load(
            self.display_journal()?,
            Kind::Verified,
            &principal_id,
            &context.request,
        )?;
        let mut fields = header(Kind::Committed, &principal_id, &context.request)?;
        fields.extend([
            ready.digest(Kind::Ready).as_str().into(),
            verified.digest(Kind::Verified).as_str().into(),
            snapshot.state_version.to_string(),
            proof.root().lineage().record.clone(),
            crate::durable_authority::digest_observation(proof.current().observation())?
                .as_str()
                .into(),
            now_ms()?.to_string(),
        ]);
        let committed = match self
            .display_journal()?
            .load(&principal_id, &Kind::Committed.key(terminal_request)?)
        {
            Err(TransactionStoreError::NotFound) => Entry::retain(
                self.request_journal.as_deref_mut().ok_or_else(invalid)?,
                Kind::Committed,
                &principal_id,
                &context.request,
                fields,
            )?,
            Ok(_) => {
                let old = Entry::load(
                    self.display_journal()?,
                    Kind::Committed,
                    &principal_id,
                    &context.request,
                )?;
                if old.fields.len() != 11 || old.fields[..9] != fields[..9] {
                    return Err(invalid());
                }
                content(&old.fields[9])?;
                if unsigned(&old.fields[10])? > now_ms()? {
                    return Err(invalid());
                }
                old
            }
            Err(_) => return Err(invalid()),
        };
        self.require_current_inspection_history_at(&principal, proof.current(), &snapshot)?;
        Ok(OriginalDisplayCurrentCommit {
            terminal: snapshot,
            record: committed.digest(Kind::Committed),
            committed_at: unsigned(&committed.fields[10])?,
        })
    }
    fn retain_current_verified(
        &mut self,
        principal: &PrincipalId,
        request: &PlanDesiredStateRequest,
        ready: &Entry,
        material: &linura_transaction::VerifiedCommitMaterial,
    ) -> Result<(), ManagedLifecycleError> {
        if material.snapshot.state != TransactionState::Verified
            || material.snapshot.state_version
                != unsigned(&ready.fields[6])?
                    .checked_add(1)
                    .ok_or_else(invalid)?
            || material.desired_state_digest != crate::durable_authority::digest_request(request)?
            || material.graph_digest == ContentDigest::zero()
            || material.provenance_digest == ContentDigest::zero()
        {
            return Err(invalid());
        }
        let mut fields = header(Kind::Verified, principal, request)?;
        fields.extend([
            ready.digest(Kind::Ready).as_str().into(),
            material.snapshot.state_version.to_string(),
            material.desired_state_digest.as_str().into(),
            material.graph_digest.as_str().into(),
            material.provenance_digest.as_str().into(),
            now_ms()?.to_string(),
        ]);
        match self
            .display_journal()?
            .load(principal, &Kind::Verified.key(&request.request_id)?)
        {
            Err(TransactionStoreError::NotFound) => {
                Entry::retain(
                    self.request_journal.as_deref_mut().ok_or_else(invalid)?,
                    Kind::Verified,
                    principal,
                    request,
                    fields,
                )?;
            }
            Ok(_) => {
                let old = Entry::load(self.display_journal()?, Kind::Verified, principal, request)?;
                if old.fields.len() != 11
                    || old.fields[..10] != fields[..10]
                    || unsigned(&old.fields[10])? > now_ms()?
                {
                    return Err(invalid());
                }
            }
            Err(_) => return Err(invalid()),
        }
        Ok(())
    }
}
