//! Separate one-use native power retirement. The original canonical review is
//! consumed forward; independent Root power, S17 and startup fences stay held.
use super::*;
use linura_observation::{
    DISPLAY_ORIGINAL_POWER_RETIREMENT_CAPABILITY, DisplayNativeCurrentFacts,
    DisplayOriginalCompletionFacts, DisplayOriginalPowerRetirementFacts,
};
use linura_transaction::{ContentDigest, RetainedRequest, TransactionStoreError, digest_bytes};

const DOMAIN: &str = "linura.display.original-native-power-prepared.v1";
const KEY_DOMAIN: &str = "linura.display.original-native-power-prepared-key.v1";
const LIMIT: usize = 4 * 1024;

/// Non-cloneable continuation of the original reviewed managed operation.
/// Digests correlate immutable evidence; they cannot recreate this permit.
#[derive(Debug)]
pub struct AuthorizedOriginalDisplayNativePowerRetirement {
    root: DisplayOriginalCompletionFacts,
    frames: DisplayNativeCurrentFacts,
    preparation: ContentDigest,
    checkpoint: ContentDigest,
    expiry: u64,
}
impl AuthorizedOriginalDisplayNativePowerRetirement {
    pub const fn root(&self) -> &DisplayOriginalCompletionFacts {
        &self.root
    }
    pub const fn frames(&self) -> &DisplayNativeCurrentFacts {
        &self.frames
    }
    pub const fn preparation(&self) -> &ContentDigest {
        &self.preparation
    }
    pub const fn checkpoint(&self) -> &ContentDigest {
        &self.checkpoint
    }
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.expiry
    }
}
pub trait OriginalDisplayNativePowerRetirementPort: Debug + Send {
    fn retire_native_power(
        &mut self,
        prepared: AuthorizedOriginalDisplayNativePowerRetirement,
    ) -> Result<(), String>;
}

/// Fresh independent post-native-effect inspection. Root's spent grant alone
/// cannot produce this result; terminal state is still Indeterminate.
#[derive(Debug)]
pub struct OriginalDisplayNativePowerInspection {
    current: OriginalDisplayCurrentInspection,
    grant: DisplayOriginalPowerRetirementFacts,
    preparation: ContentDigest,
}
impl OriginalDisplayNativePowerInspection {
    pub const fn current(&self) -> &OriginalDisplayCurrentInspection {
        &self.current
    }
    pub const fn grant(&self) -> &DisplayOriginalPowerRetirementFacts {
        &self.grant
    }
    pub const fn preparation(&self) -> &ContentDigest {
        &self.preparation
    }
}

#[derive(Debug)]
struct PowerPreparation {
    principal: PrincipalId,
    request: RequestId,
    bytes: Vec<u8>,
    created: u64,
    expiry: u64,
}
fn key(request: &RequestId) -> Result<RequestId, ManagedLifecycleError> {
    RequestId::new(format!(
        "request:v010:display-native-power-prepared:{}",
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
impl PowerPreparation {
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
    fn prefix(
        principal: &PrincipalId,
        context: &TerminalInspectionContext,
        current: &OriginalDisplayCurrentInspection,
        checkpoint: &str,
    ) -> Result<Vec<u8>, ManagedLifecycleError> {
        let mut out = Vec::new();
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
            current.preparation().as_str().into(),
            current.root.lineage().record.clone(),
            checkpoint.into(),
        ] {
            append(&mut out, &value)?;
        }
        Ok(out)
    }
    fn capture(
        principal: &PrincipalId,
        context: &TerminalInspectionContext,
        current: &OriginalDisplayCurrentVerification,
        deadline: u64,
    ) -> Result<Self, ManagedLifecycleError> {
        let created = now_ms()?;
        let expiry = current.valid_until_unix_ms().min(deadline);
        current
            .inspection()
            .observation()
            .require_current(created)
            .map_err(|_| invalid())?;
        if created >= expiry
            || !current.inspection().frames().power_fence_held()
            || !current.inspection().frames().input_retired()
        {
            return Err(invalid());
        }
        let mut bytes = Self::prefix(
            principal,
            context,
            current.inspection(),
            current.record_digest().as_str(),
        )?;
        for value in [
            crate::durable_authority::digest_observation(current.inspection().observation())?
                .as_str()
                .into(),
            created.to_string(),
            expiry.to_string(),
        ] {
            append(&mut bytes, &value)?;
        }
        Ok(Self {
            principal: principal.clone(),
            request: context.request.request_id.clone(),
            bytes,
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
        let stored = journal
            .load(&self.principal, &key(&self.request)?)
            .map_err(|_| invalid())?;
        if stored.principal() != &self.principal
            || stored.request_id() != &key(&self.request)?
            || stored.canonical() != self.bytes
        {
            return Err(invalid());
        }
        Ok(())
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
        grant: &DisplayOriginalPowerRetirementFacts,
    ) -> Result<Self, ManagedLifecycleError> {
        journal.integrity_check().map_err(|_| invalid())?;
        let stored = journal
            .load(principal, &key(&context.request.request_id)?)
            .map_err(|_| invalid())?;
        let checkpoint = ContentDigest::new(format!("sha256:{}", grant.checkpoint_digest()))
            .map_err(|_| invalid())?;
        let prefix = Self::prefix(principal, context, current, checkpoint.as_str())?;
        if stored.principal() != principal
            || stored.request_id() != &key(&context.request.request_id)?
            || stored.canonical().len() > LIMIT
            || !stored.canonical().starts_with(&prefix)
        {
            return Err(invalid());
        }
        let mut rest = &stored.canonical()[prefix.len()..];
        if ContentDigest::new(field(&mut rest)?).map_err(|_| invalid())? == ContentDigest::zero() {
            return Err(invalid());
        }
        let created = number(&mut rest)?;
        let expiry = number(&mut rest)?;
        if !rest.is_empty()
            || created == 0
            || created >= expiry
            || expiry - created > 2000
            || current.frames().window().observed_unix_ms < created
            || current.observation().observed_at_unix_ms < created
        {
            return Err(invalid());
        }
        let result = Self {
            principal: principal.clone(),
            request: context.request.request_id.clone(),
            bytes: stored.canonical().to_vec(),
            created,
            expiry,
        };
        if result.digest().hex() != grant.preparation_digest()
            || grant.completion_digest() != current.root.lineage().record
            || !grant.grant_spent()
        {
            return Err(invalid());
        }
        Ok(result)
    }
}

pub(super) fn require_power_preparation_readback(
    journal: &dyn ApprovedRequestJournal,
    principal: &PrincipalId,
    request: &RequestId,
    expected: &ContentDigest,
) -> Result<(), ManagedLifecycleError> {
    journal.integrity_check().map_err(|_| invalid())?;
    let retained = journal
        .load(principal, &key(request)?)
        .map_err(|_| invalid())?;
    if retained.principal() != principal
        || retained.request_id() != &key(request)?
        || retained.canonical().len() > LIMIT
        || digest_bytes(DOMAIN, retained.canonical()) != *expected
        || *expected == ContentDigest::zero()
    {
        return Err(invalid());
    }
    let mut fields = retained.canonical();
    // The original immutable decision names its first current checkpoint.
    // A missing referenced proof never becomes permission to clean up or finish.
    for _ in 0..11 {
        field(&mut fields)?;
    }
    let checkpoint = ContentDigest::new(field(&mut fields)?).map_err(|_| invalid())?;
    crate::display_native_release_spend::verification::current::NativeCurrentVerified::require_digest_readback(journal,principal,request,&checkpoint)?;
    Ok(())
}

impl<S: TransactionStore> ManagedLifecycleControl<S> {
    /// One further effect under the ORIGINAL process-local canonical review.
    /// A restart or a historical checkpoint cannot mint this continuation.
    pub fn dispatch_original_display_native_power_retirement<
        P: OriginalDisplayNativePowerRetirementPort,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        terminal_request: &RequestId,
        port: &mut P,
    ) -> Result<(), ManagedLifecycleError> {
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(ManagedLifecycleError::ApprovalBoundary(
                "native power retirement requires authenticated interactive ownership".into(),
            ));
        }
        let context = self.terminal_inspection_context(&principal, terminal_request)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let retained = self
            .display_reviews
            .get(&context.snapshot.transaction_id)
            .ok_or_else(invalid)?;
        let (completion, verification) = match &retained.stage {
            DisplayReviewStage::CompletionDispatched {
                preparation,
                verification,
            } => (preparation.clone(), verification.clone()),
            _ => return Err(invalid()),
        };
        // Consume before any provider or storage call. Failure cannot restore
        // the earlier phase or create a second reservation.
        let mut review = self
            .display_reviews
            .remove(&context.snapshot.transaction_id)
            .ok_or_else(invalid)?;
        self.revalidate_completion_review(&principal, &context, &review)?;
        PowerPreparation::absent(self.display_journal()?, &principal_id, terminal_request)?;
        let proof =
            self.verify_current_original_display_completion(principal.clone(), terminal_request)?;
        if proof.inspection().terminal() != &context.snapshot
            || proof.inspection().preparation() != &completion
            || proof.inspection().root.lineage().verification != verification.hex()
        {
            return Err(invalid());
        }
        let prepared =
            PowerPreparation::capture(&principal_id, &context, &proof, review.deadline_unix_ms)?;
        self.revalidate_completion_review(&principal, &context, &review)?;
        prepared.retain(self.request_journal.as_deref_mut().ok_or_else(invalid)?)?;
        if self.terminal_inspection_context(&principal, terminal_request)? != context {
            return Err(invalid());
        }
        self.require_current_inspection_history(&principal, proof.inspection())?;
        self.revalidate_completion_review(&principal, &context, &review)?;
        prepared.current()?;
        let permit = AuthorizedOriginalDisplayNativePowerRetirement {
            root: proof.inspection().root.clone(),
            frames: proof.inspection().frames().clone(),
            preparation: prepared.digest(),
            checkpoint: proof.record_digest().clone(),
            expiry: prepared.expiry,
        };
        review.stage = DisplayReviewStage::PowerDispatched;
        self.check_display_review_capacity(review.retained_bytes)?;
        self.display_reviews
            .insert(context.snapshot.transaction_id, review);
        port.retire_native_power(permit).map_err(|_| {
            ManagedLifecycleError::Indeterminate(
                "native power retirement outcome uncertain; no replay".into(),
            )
        })?;
        prepared.readback(self.display_journal()?)
    }

    /// Observation-only recovery after the one-use permission, including a lost
    /// ACK. Independently read current KMS/input/native power and Root's retained
    /// power, lock and history; no grant is inferred from journal presence.
    pub fn inspect_original_display_native_power_retirement(
        &mut self,
        principal: AuthenticatedPrincipal,
        terminal_request: &RequestId,
    ) -> Result<OriginalDisplayNativePowerInspection, ManagedLifecycleError> {
        let context = self.terminal_inspection_context(&principal, terminal_request)?;
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid())?;
        let material = DisplayFinalizationMaterial::decode(context.intent.material())
            .map_err(|_| invalid())?;
        let scope = material.recovery_scope().map_err(|_| invalid())?;
        let query = ObservationRequest {
            provider: ProviderId::new(DISPLAY_RECOVERY_PROVIDER).map_err(|_| invalid())?,
            capability: CapabilityId::new(DISPLAY_ORIGINAL_POWER_RETIREMENT_CAPABILITY)
                .map_err(|_| invalid())?,
            resource: scope.resource_id().map_err(|_| invalid())?,
        };
        let before = self
            .previews
            .observe(&query)
            .map_err(|_| invalid())?
            .observation;
        let grant = DisplayOriginalPowerRetirementFacts::from_envelope(&before, &scope, now_ms()?)
            .map_err(|_| invalid())?;
        let mut current = self.inspect_current_original_display_completion_phase(
            principal.clone(),
            terminal_request,
            false,
        )?;
        let prepared = PowerPreparation::compare(
            self.display_journal()?,
            &principal_id,
            &context,
            &current,
            &grant,
        )?;
        let after = self
            .previews
            .observe(&query)
            .map_err(|_| invalid())?
            .observation;
        if after.sequence <= before.sequence
            || DisplayOriginalPowerRetirementFacts::from_envelope(&after, &scope, now_ms()?)
                .map_err(|_| invalid())?
                != grant
            || self.terminal_inspection_context(&principal, terminal_request)? != context
        {
            return Err(invalid());
        }
        prepared.readback(self.display_journal()?)?;
        self.require_current_inspection_history(&principal, &current)?;
        for (name, source) in [("power_grant", &before), ("rechecked_power_grant", &after)] {
            crate::plan_preview::restrict_session_validity(
                &mut current.observation,
                source,
                now_ms()?,
            )
            .map_err(|_| invalid())?;
            current.observation.attributes.insert(
                format!("control.current.{name}_digest"),
                ObservedValue::Text(
                    crate::durable_authority::digest_observation(source)?
                        .as_str()
                        .into(),
                ),
            );
        }
        current
            .observation
            .require_current(now_ms()?)
            .map_err(|_| invalid())?;
        Ok(OriginalDisplayNativePowerInspection {
            current,
            grant,
            preparation: prepared.digest(),
        })
    }
}
