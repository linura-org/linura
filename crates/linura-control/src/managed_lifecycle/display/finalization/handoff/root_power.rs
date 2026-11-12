//! Original reviewed continuation for the final Root power close. A close ACK
//! cannot commit Control, admit a successor or retire checkpoint provenance.
use super::*;
use linura_observation::{
    DisplayNativeCurrentFacts, DisplayOriginalCompletionFacts, DisplayOriginalPowerRetirementFacts,
    DisplayOriginalRootRetirementFacts,
};
use linura_transaction::{ContentDigest, RetainedRequest, TransactionStoreError, digest_bytes};

const DOMAIN: &str = "linura.display.original-root-power-prepared.v1";
const KEY_DOMAIN: &str = "linura.display.original-root-power-prepared-key.v1";
const LIMIT: usize = 4 * 1024;

#[derive(Debug)]
pub struct AuthorizedOriginalDisplayRootPowerRetirement {
    root: DisplayOriginalCompletionFacts,
    power: DisplayOriginalPowerRetirementFacts,
    frames: DisplayNativeCurrentFacts,
    preparation: ContentDigest,
    verification: ContentDigest,
    expiry: u64,
}
impl AuthorizedOriginalDisplayRootPowerRetirement {
    pub const fn root(&self) -> &DisplayOriginalCompletionFacts {
        &self.root
    }
    pub const fn power(&self) -> &DisplayOriginalPowerRetirementFacts {
        &self.power
    }
    pub const fn frames(&self) -> &DisplayNativeCurrentFacts {
        &self.frames
    }
    pub const fn preparation(&self) -> &ContentDigest {
        &self.preparation
    }
    pub const fn verification(&self) -> &ContentDigest {
        &self.verification
    }
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expiry
    }
}
pub trait OriginalDisplayRootPowerRetirementPort: Debug + Send {
    fn retire_root_power(
        &mut self,
        prepared: AuthorizedOriginalDisplayRootPowerRetirement,
    ) -> Result<(), String>;
}
#[derive(Debug)]
pub struct OriginalDisplayRootPowerInspection {
    current: OriginalDisplayCurrentInspection,
    preparation: ContentDigest,
    root: DisplayOriginalRootRetirementFacts,
}
impl OriginalDisplayRootPowerInspection {
    pub const fn current(&self) -> &OriginalDisplayCurrentInspection {
        &self.current
    }
    pub const fn preparation(&self) -> &ContentDigest {
        &self.preparation
    }
    pub const fn root(&self) -> &DisplayOriginalRootRetirementFacts {
        &self.root
    }
}
#[derive(Debug)]
struct RootPreparation {
    principal: PrincipalId,
    request: RequestId,
    bytes: Vec<u8>,
    power: ContentDigest,
    verification: ContentDigest,
    created: u64,
    expiry: u64,
}
fn key(request: &RequestId) -> Result<RequestId, ManagedLifecycleError> {
    RequestId::new(format!(
        "request:v010:display-root-power-prepared:{}",
        digest_bytes(KEY_DOMAIN, request.as_str().as_bytes()).hex()
    ))
    .map_err(|_| invalid())
}
fn append(out: &mut Vec<u8>, value: &str) -> Result<(), ManagedLifecycleError> {
    if value.is_empty()
        || out
            .len()
            .checked_add(8 + value.len())
            .is_none_or(|n| n > LIMIT)
    {
        return Err(invalid());
    }
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
fn field<'a>(rest: &mut &'a [u8]) -> Result<&'a str, ManagedLifecycleError> {
    let (size, body) = rest.split_at_checked(8).ok_or_else(invalid)?;
    let size = usize::try_from(u64::from_be_bytes(size.try_into().map_err(|_| invalid())?))
        .map_err(|_| invalid())?;
    if size == 0 || size > 256 {
        return Err(invalid());
    }
    let (text, tail) = body.split_at_checked(size).ok_or_else(invalid)?;
    *rest = tail;
    std::str::from_utf8(text).map_err(|_| invalid())
}
fn number(rest: &mut &[u8]) -> Result<u64, ManagedLifecycleError> {
    let raw = field(rest)?;
    let value = raw.parse::<u64>().map_err(|_| invalid())?;
    if value.to_string() != raw {
        return Err(invalid());
    }
    Ok(value)
}
impl RootPreparation {
    fn prefix(
        principal: &PrincipalId,
        context: &TerminalInspectionContext,
    ) -> Result<Vec<u8>, ManagedLifecycleError> {
        let mut bytes = Vec::new();
        for value in [
            DOMAIN.into(),
            principal.as_str().into(),
            context.request.request_id.as_str().into(),
            context.snapshot.transaction_id.as_str().into(),
            crate::durable_authority::digest_request(&context.request)?
                .as_str()
                .into(),
            context.snapshot.current_generation.to_string(),
            context.snapshot.state_version.to_string(),
            context.snapshot.binding_digest.as_str().into(),
            context
                .receipt
                .dispatch_digest
                .clone()
                .ok_or_else(invalid)?,
        ] {
            append(&mut bytes, &value)?;
        }
        Ok(bytes)
    }
    fn absent(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        request: &RequestId,
    ) -> Result<(), ManagedLifecycleError> {
        journal.integrity_check().map_err(|_| invalid())?;
        match journal.load(principal, &key(request)?) {
            Err(TransactionStoreError::NotFound) => Ok(()),
            _ => Err(invalid()),
        }
    }
    fn capture(
        principal: &PrincipalId,
        context: &TerminalInspectionContext,
        proof: &OriginalDisplayNativePowerInspection,
        deadline: u64,
    ) -> Result<Self, ManagedLifecycleError> {
        let current = proof.current();
        let created = now_ms()?;
        current
            .observation()
            .require_current(created)
            .map_err(|_| invalid())?;
        let window = current.frames().window();
        let native_expiry = window
            .observed_unix_ms
            .checked_add(window.valid_for_ms().map_err(|_| invalid())?)
            .ok_or_else(invalid)?;
        let expiry = current
            .observation()
            .observed_at_unix_ms
            .checked_add(current.observation().valid_for_ms)
            .ok_or_else(invalid)?
            .min(deadline)
            .min(native_expiry);
        if created < window.observed_unix_ms
            || created >= expiry
            || current.frames().power_fence_held()
            || !current.frames().input_retired()
            || !proof.grant().grant_spent()
            || current.terminal() != &context.snapshot
        {
            return Err(invalid());
        }
        let verification = crate::durable_authority::digest_observation(current.observation())?;
        let mut bytes = Self::prefix(principal, context)?;
        for value in [
            proof.preparation().as_str().into(),
            proof.grant().record_digest().into(),
            current.root.lineage().record.clone(),
            verification.as_str().into(),
            created.to_string(),
            expiry.to_string(),
        ] {
            append(&mut bytes, &value)?;
        }
        Ok(Self {
            principal: principal.clone(),
            request: context.request.request_id.clone(),
            bytes,
            power: proof.preparation().clone(),
            verification,
            created,
            expiry,
        })
    }
    fn digest(&self) -> ContentDigest {
        digest_bytes(DOMAIN, &self.bytes)
    }
    fn current(&self) -> Result<(), ManagedLifecycleError> {
        let now = now_ms()?;
        if now < self.created || now >= self.expiry {
            return Err(invalid());
        }
        Ok(())
    }
    fn readback(&self, journal: &dyn ApprovedRequestJournal) -> Result<(), ManagedLifecycleError> {
        journal.integrity_check().map_err(|_| invalid())?;
        let record = journal
            .load(&self.principal, &key(&self.request)?)
            .map_err(|_| invalid())?;
        if record.principal() != &self.principal
            || record.request_id() != &key(&self.request)?
            || record.canonical() != self.bytes
        {
            return Err(invalid());
        }
        power::require_power_preparation_readback(
            journal,
            &self.principal,
            &self.request,
            &self.power,
        )
    }
    fn retain(
        &self,
        journal: &mut dyn ApprovedRequestJournal,
    ) -> Result<(), ManagedLifecycleError> {
        Self::absent(journal, &self.principal, &self.request)?;
        journal
            .retain(
                &RetainedRequest::new(
                    self.principal.clone(),
                    key(&self.request)?,
                    self.bytes.clone(),
                )
                .map_err(|_| invalid())?,
            )
            .map_err(|_| invalid())?;
        self.readback(journal)
    }
    fn compare(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        context: &TerminalInspectionContext,
        current: &OriginalDisplayCurrentInspection,
    ) -> Result<Self, ManagedLifecycleError> {
        let root = current.retired_root.as_ref().ok_or_else(invalid)?;
        journal.integrity_check().map_err(|_| invalid())?;
        let record = journal
            .load(principal, &key(&context.request.request_id)?)
            .map_err(|_| invalid())?;
        let prefix = Self::prefix(principal, context)?;
        if record.principal() != principal
            || record.request_id() != &key(&context.request.request_id)?
            || record.canonical().len() > LIMIT
            || !record.canonical().starts_with(&prefix)
        {
            return Err(invalid());
        }
        let mut rest = &record.canonical()[prefix.len()..];
        let power = ContentDigest::new(field(&mut rest)?).map_err(|_| invalid())?;
        if power == ContentDigest::zero()
            || field(&mut rest)? != root.lineage().power_record
            || field(&mut rest)? != root.completion_comparison().lineage().record
        {
            return Err(invalid());
        }
        let verification = ContentDigest::new(field(&mut rest)?).map_err(|_| invalid())?;
        let created = number(&mut rest)?;
        let expiry = number(&mut rest)?;
        if !rest.is_empty()
            || verification == ContentDigest::zero()
            || verification.hex() != root.lineage().verification
            || created == 0
            || created >= expiry
            || expiry - created > 2000
            || current.observation().observed_at_unix_ms < created
            || current.frames().window().observed_unix_ms < created
        {
            return Err(invalid());
        }
        let result = Self {
            principal: principal.clone(),
            request: context.request.request_id.clone(),
            bytes: record.canonical().to_vec(),
            power,
            verification,
            created,
            expiry,
        };
        if result.digest().hex() != root.lineage().preparation {
            return Err(invalid());
        }
        result.readback(journal)?;
        Ok(result)
    }
}
impl<S: TransactionStore> ManagedLifecycleControl<S> {
    pub fn dispatch_original_display_root_power_retirement<
        P: OriginalDisplayRootPowerRetirementPort,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        terminal_request: &RequestId,
        port: &mut P,
    ) -> Result<(), ManagedLifecycleError> {
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "Root power retirement requires authenticated interactive ownership".into(),
            ));
        }
        let context = self.terminal_inspection_context(&principal, terminal_request)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let retained = self
            .display_reviews
            .get(&context.snapshot.transaction_id)
            .ok_or_else(invalid)?;
        if retained.stage != DisplayReviewStage::PowerDispatched {
            return Err(invalid());
        }
        let mut review = self
            .display_reviews
            .remove(&context.snapshot.transaction_id)
            .ok_or_else(invalid)?;
        self.revalidate_completion_review(&principal, &context, &review)?;
        RootPreparation::absent(self.display_journal()?, &principal_id, terminal_request)?;
        let proof = self.inspect_original_display_native_power_retirement(
            principal.clone(),
            terminal_request,
        )?;
        let prepared =
            RootPreparation::capture(&principal_id, &context, &proof, review.deadline_unix_ms)?;
        self.revalidate_completion_review(&principal, &context, &review)?;
        prepared.retain(self.request_journal.as_deref_mut().ok_or_else(invalid)?)?;
        self.require_current_inspection_history(&principal, proof.current())?;
        prepared.readback(self.display_journal()?)?;
        self.revalidate_completion_review(&principal, &context, &review)?;
        prepared.current()?;
        let permit = AuthorizedOriginalDisplayRootPowerRetirement {
            root: proof.current().root.clone(),
            power: proof.grant().clone(),
            frames: proof.current().frames().clone(),
            preparation: prepared.digest(),
            verification: prepared.verification.clone(),
            expiry: prepared.expiry,
        };
        review.stage = DisplayReviewStage::RootPowerDispatched {
            preparation: prepared.digest(),
        };
        self.check_display_review_capacity(review.retained_bytes)?;
        self.display_reviews
            .insert(context.snapshot.transaction_id, review);
        port.retire_root_power(permit).map_err(|_| {
            ManagedLifecycleError::Indeterminate(
                "Root power retirement outcome uncertain; no replay".into(),
            )
        })?;
        prepared.readback(self.display_journal()?)
    }
    /// Read-only recovery joins actual post-Root logind absence/kernel lineage
    /// with current native KMS/input/power, source, login and S17 evidence.
    pub fn inspect_original_display_root_power_retirement(
        &mut self,
        principal: AuthenticatedPrincipal,
        terminal_request: &RequestId,
    ) -> Result<OriginalDisplayRootPowerInspection, ManagedLifecycleError> {
        let context = self.current_finalization_comparison_context(&principal, terminal_request)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let current = self.inspect_current_original_display_completion_root(
            principal.clone(),
            terminal_request,
            current::CurrentRootPhase::Retired,
        )?;
        let prepared =
            RootPreparation::compare(self.display_journal()?, &principal_id, &context, &current)?;
        self.require_current_inspection_history(&principal, &current)?;
        prepared.readback(self.display_journal()?)?;
        let root = current.retired_root.clone().ok_or_else(invalid)?;
        completed::require_ready_lineage(
            self.display_journal()?,
            &principal_id,
            &context.request,
            &prepared.digest(),
            &root.lineage().record,
        )?;
        Ok(OriginalDisplayRootPowerInspection {
            root,
            current,
            preparation: prepared.digest(),
        })
    }
}
