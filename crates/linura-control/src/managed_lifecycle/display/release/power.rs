//! Separate one-use ordinary native-power retirement. Fresh comparison is
//! required before and after the effect; Root's own power fence remains held.
use super::*;
use crate::durable_authority::DisplayReviewPurpose;
use linura_observation::{
    DISPLAY_ORDINARY_POWER_RETIREMENT_CAPABILITY, DISPLAY_RECOVERY_PROVIDER,
    DisplayOrdinaryCompletionFacts, DisplayOrdinaryCurrentFacts,
    DisplayOrdinaryPowerRetirementFacts,
};
use linura_transaction::{ContentDigest, RetainedRequest, TransactionStoreError, digest_bytes};

const DOMAIN: &str = "linura.display.ordinary-native-power-prepared.v1";
const CHECKPOINT_DOMAIN: &str = "linura.display.ordinary-current-checkpoint.v1";
const KEY_DOMAIN: &str = "linura.display.ordinary-native-power-prepared-key.v1";
const LIMIT: usize = 32 * 1024;

/// Non-cloneable continuation of the genuine original ordinary review. Neither
/// a saved checkpoint nor an acknowledgement can reconstruct this permit.
#[derive(Debug)]
pub struct AuthorizedOrdinaryDisplayNativePowerRetirement {
    root: DisplayOrdinaryCompletionFacts,
    frames: DisplayOrdinaryCurrentFacts,
    preparation: ContentDigest,
    checkpoint: ContentDigest,
    expiry: u64,
}
impl AuthorizedOrdinaryDisplayNativePowerRetirement {
    pub const fn root(&self) -> &DisplayOrdinaryCompletionFacts {
        &self.root
    }
    pub const fn frames(&self) -> &DisplayOrdinaryCurrentFacts {
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
pub trait OrdinaryDisplayNativePowerRetirementPort: Debug + Send {
    fn retire_ordinary_native_power(
        &mut self,
        permit: AuthorizedOrdinaryDisplayNativePowerRetirement,
    ) -> Result<(), String>;
}
#[derive(Debug)]
pub struct OrdinaryDisplayNativePowerInspection {
    current: OrdinaryDisplayCurrentInspection,
    grant: DisplayOrdinaryPowerRetirementFacts,
    preparation: ContentDigest,
}
impl OrdinaryDisplayNativePowerInspection {
    pub const fn current(&self) -> &OrdinaryDisplayCurrentInspection {
        &self.current
    }
    pub const fn grant(&self) -> &DisplayOrdinaryPowerRetirementFacts {
        &self.grant
    }
    pub const fn preparation(&self) -> &ContentDigest {
        &self.preparation
    }
}

fn key(request: &RequestId) -> Result<RequestId, ManagedLifecycleError> {
    RequestId::new(format!(
        "request:v010:display-ordinary-native-power-prepared:{}",
        digest_bytes(KEY_DOMAIN, request.as_str().as_bytes()).hex()
    ))
    .map_err(|_| invalid_original())
}
fn append(out: &mut Vec<u8>, value: &str) -> Result<(), ManagedLifecycleError> {
    if value.is_empty()
        || out
            .len()
            .checked_add(8 + value.len())
            .is_none_or(|n| n > LIMIT)
    {
        return Err(invalid_original());
    }
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
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
    *rest = tail;
    std::str::from_utf8(value).map_err(|_| invalid_original())
}
fn number(rest: &mut &[u8]) -> Result<u64, ManagedLifecycleError> {
    let raw = field(rest, 20)?;
    let value = raw.parse::<u64>().map_err(|_| invalid_original())?;
    if value.to_string() != raw {
        return Err(invalid_original());
    }
    Ok(value)
}
#[derive(Debug)]
struct PowerPrepared {
    bytes: Vec<u8>,
    frames: DisplayOrdinaryCurrentFacts,
    created: u64,
    expiry: u64,
}
impl PowerPrepared {
    fn prefix(
        principal: &PrincipalId,
        current: &OrdinaryDisplayCurrentInspection,
    ) -> Result<Vec<u8>, ManagedLifecycleError> {
        let request = current.request();
        let snapshot = current.release();
        let root = current.root().lineage();
        let mut bytes = Vec::new();
        for value in [
            DOMAIN.into(),
            principal.as_str().into(),
            request.request_id.as_str().into(),
            snapshot.transaction_id.as_str().into(),
            crate::durable_authority::digest_request(request)?
                .as_str()
                .into(),
            snapshot.current_generation.to_string(),
            snapshot.state_version.to_string(),
            snapshot.binding_digest.as_str().into(),
            root.record.clone(),
            root.preparation.clone(),
            root.verification.clone(),
        ] {
            append(&mut bytes, &value)?;
        }
        Ok(bytes)
    }
    fn encode(
        principal: &PrincipalId,
        current: &OrdinaryDisplayCurrentInspection,
        source: &str,
        created: u64,
        expiry: u64,
        frames: &DisplayOrdinaryCurrentFacts,
    ) -> Result<Vec<u8>, ManagedLifecycleError> {
        let mut bytes = Self::prefix(principal, current)?;
        for value in [
            source.into(),
            created.to_string(),
            expiry.to_string(),
            frames.window().observed_unix_ms.to_string(),
            frames.attributes().len().to_string(),
        ] {
            append(&mut bytes, &value)?;
        }
        for (key, value) in frames.attributes() {
            append(&mut bytes, &key)?;
            let (kind, value) = match value {
                ObservedValue::Text(v) => ("text", v),
                ObservedValue::U64(v) => ("u64", v.to_string()),
                ObservedValue::Bool(v) => ("bool", v.to_string()),
                _ => return Err(invalid_original()),
            };
            append(&mut bytes, kind)?;
            append(&mut bytes, &value)?;
        }
        Ok(bytes)
    }
    fn capture(
        principal: &PrincipalId,
        current: &OrdinaryDisplayCurrentInspection,
        deadline: u64,
    ) -> Result<Self, ManagedLifecycleError> {
        let created = now_ms()?;
        current
            .observation()
            .require_current(created)
            .map_err(|_| invalid_original())?;
        let window = current.frames().window();
        let expiry = current
            .observation()
            .observed_at_unix_ms
            .checked_add(current.observation().valid_for_ms)
            .ok_or_else(invalid_original)?
            .min(
                window
                    .observed_unix_ms
                    .checked_add(window.valid_for_ms().map_err(|_| invalid_original())?)
                    .ok_or_else(invalid_original)?,
            )
            .min(deadline);
        if !current.frames().input_retired()
            || !current.frames().power_fence_held()
            || created >= expiry
            || created > now_ms()?
        {
            return Err(invalid_original());
        }
        let bytes = Self::encode(
            principal,
            current,
            crate::durable_authority::digest_observation(current.observation())?.as_str(),
            created,
            expiry,
            current.frames(),
        )?;
        Ok(Self {
            bytes,
            frames: current.frames().clone(),
            created,
            expiry,
        })
    }
    fn load(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        current: &OrdinaryDisplayCurrentInspection,
    ) -> Result<Self, ManagedLifecycleError> {
        let key = key(&current.request().request_id)?;
        let retained = journal
            .load(principal, &key)
            .map_err(|_| invalid_original())?;
        let prefix = Self::prefix(principal, current)?;
        if retained.principal() != principal
            || retained.request_id() != &key
            || retained.canonical().len() > LIMIT
            || !retained.canonical().starts_with(&prefix)
        {
            return Err(invalid_original());
        }
        let mut rest = &retained.canonical()[prefix.len()..];
        let source = field(&mut rest, 256)?.to_owned();
        if ContentDigest::new(&source).map_err(|_| invalid_original())? == ContentDigest::zero() {
            return Err(invalid_original());
        }
        let created = number(&mut rest)?;
        let expiry = number(&mut rest)?;
        let observed = number(&mut rest)?;
        let count = number(&mut rest)?;
        if count > 169 {
            return Err(invalid_original());
        }
        let mut attrs = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let key = field(&mut rest, 64)?.to_owned();
            if previous.as_ref().is_some_and(|old| old >= &key) {
                return Err(invalid_original());
            }
            previous = Some(key.clone());
            let kind = field(&mut rest, 4)?;
            let value = match kind {
                "text" => ObservedValue::Text(field(&mut rest, 256)?.into()),
                "u64" => ObservedValue::U64(number(&mut rest)?),
                "bool" => ObservedValue::Bool(match field(&mut rest, 5)? {
                    "true" => true,
                    "false" => false,
                    _ => return Err(invalid_original()),
                }),
                _ => return Err(invalid_original()),
            };
            attrs.insert(key, value);
        }
        let frames = DisplayOrdinaryCurrentFacts::from_comparison_attributes(
            &attrs,
            current.frames().scope(),
            observed,
        )
        .map_err(|_| invalid_original())?;
        let w = frames.window();
        if !rest.is_empty()
            || created < observed
            || created >= expiry
            || created > now_ms()?
            || expiry
                > w.observed_unix_ms
                    .checked_add(w.valid_for_ms().map_err(|_| invalid_original())?)
                    .ok_or_else(invalid_original)?
            || !frames.input_retired()
            || !frames.power_fence_held()
            || frames.current_commit_digest().is_some()
            || frames.final_retirement_digest().is_some()
            || frames.completion_digest() != current.root().lineage().record
            || !frames.follows_handoff(current.root().first())
            || Self::encode(principal, current, &source, created, expiry, &frames)?
                != retained.canonical()
        {
            return Err(invalid_original());
        }
        Ok(Self {
            bytes: retained.canonical().to_vec(),
            frames,
            created,
            expiry,
        })
    }
    fn preparation(&self) -> ContentDigest {
        digest_bytes(DOMAIN, &self.bytes)
    }
    fn checkpoint(&self) -> ContentDigest {
        digest_bytes(CHECKPOINT_DOMAIN, &self.bytes)
    }
    fn current(&self) -> Result<(), ManagedLifecycleError> {
        let now = now_ms()?;
        if now < self.created || now >= self.expiry {
            Err(invalid_original())
        } else {
            Ok(())
        }
    }
    fn readback(
        &self,
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        request: &RequestId,
    ) -> Result<(), ManagedLifecycleError> {
        let key = key(request)?;
        let stored = journal
            .load(principal, &key)
            .map_err(|_| invalid_original())?;
        if stored.principal() != principal
            || stored.request_id() != &key
            || stored.canonical() != self.bytes
        {
            return Err(invalid_original());
        }
        Ok(())
    }
}
impl<S: TransactionStore> ManagedLifecycleControl<S> {
    fn require_ordinary_power_review(
        &mut self,
        principal: &AuthenticatedPrincipal,
        current: &OrdinaryDisplayCurrentInspection,
        review: &RetainedDisplayReview,
    ) -> Result<(), ManagedLifecycleError> {
        let now = now_ms()?;
        if review.review.purpose() != DisplayReviewPurpose::OrdinaryRelease
            || now < review.created_unix_ms
            || now >= review.deadline_unix_ms
        {
            return Err(invalid_original());
        }
        let floor = self.registered_managed_risk_floor(current.request())?;
        self.validate_registered_managed_plan(review.review.plan(), review.review.risk())?;
        self.authority.revalidate_display_review(
            principal,
            current.request(),
            &review.review,
            floor,
            current.release(),
        )?;
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn retire_ordinary_display_native_power<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
        N: OrdinaryDisplayNativePowerRetirementPort,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        actor: Actor,
        request: &RequestId,
        attempt: &mut P,
        verifier: &mut V,
        port: &mut N,
    ) -> Result<(), ManagedLifecycleError> {
        if actor.kind != ActorKind::Human || !actor.interactive {
            return Err(invalid_original());
        }
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let transaction = TransactionId::for_namespace(&principal_id, request);
        let live = self
            .display_reviews
            .get(&transaction)
            .ok_or_else(invalid_original)?;
        let (completion, verification) = match &live.stage {
            DisplayReviewStage::OrdinaryCompletionDispatched {
                preparation,
                verification,
            } => (preparation.clone(), verification.clone()),
            _ => return Err(invalid_original()),
        };
        // Consume before any probe or persistence; no failure restores it.
        let mut review = self
            .display_reviews
            .remove(&transaction)
            .ok_or_else(invalid_original)?;
        {
            let _checked = self.checked_display_history()?;
            match self.display_journal()?.load(&principal_id, &key(request)?) {
                Err(TransactionStoreError::NotFound) => (),
                _ => return Err(invalid_original()),
            }
        }
        let current = self.inspect_current_ordinary_display_completion(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        if current.root().lineage().preparation != completion.hex()
            || current.root().lineage().verification != verification.hex()
        {
            return Err(invalid_original());
        }
        self.require_ordinary_power_review(&principal, &current, &review)?;
        let prepared = PowerPrepared::capture(&principal_id, &current, review.deadline_unix_ms)?;
        let retained =
            RetainedRequest::new(principal_id.clone(), key(request)?, prepared.bytes.clone())
                .map_err(|_| invalid_original())?;
        self.request_journal
            .as_mut()
            .ok_or_else(invalid_original)?
            .retain(&retained)
            .map_err(|_| invalid_original())?;
        {
            let _checked = self.checked_display_history()?;
            prepared.readback(self.display_journal()?, &principal_id, request)?;
        }
        // Storage latency and drift cannot convert saved comparison into current proof.
        let fresh = self.inspect_current_ordinary_display_completion(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        if fresh.root() != current.root()
            || fresh.release() != current.release()
            || !fresh.frames().reconciles(&prepared.frames)
        {
            return Err(invalid_original());
        }
        self.require_ordinary_power_review(&principal, &fresh, &review)?;
        {
            let _checked = self.checked_display_history()?;
            prepared.readback(self.display_journal()?, &principal_id, request)?;
        }
        prepared.current()?;
        review.stage = DisplayReviewStage::OrdinaryPowerDispatched {
            preparation: prepared.preparation(),
            checkpoint: prepared.checkpoint(),
        };
        self.check_display_review_capacity(review.retained_bytes)?;
        self.display_reviews.insert(transaction, review);
        port.retire_ordinary_native_power(AuthorizedOrdinaryDisplayNativePowerRetirement {
            root: fresh.root().clone(),
            frames: fresh.frames().clone(),
            preparation: prepared.preparation(),
            checkpoint: prepared.checkpoint(),
            expiry: prepared.expiry,
        })
        .map_err(|_| {
            ManagedLifecycleError::Indeterminate(
                "ordinary native-power outcome uncertain; no replay".into(),
            )
        })?;
        let _checked = self.checked_display_history()?;
        prepared.readback(self.display_journal()?, &principal_id, request)?;
        if self
            .authority
            .matching_request_snapshot(&principal, fresh.request())?
            != *fresh.release()
        {
            return Err(invalid_original());
        }
        Ok(()) // ACK only; independent postconditions remain required.
    }
    pub fn inspect_ordinary_display_native_power_retirement<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        request: &RequestId,
        attempt: &mut P,
        verifier: &mut V,
    ) -> Result<OrdinaryDisplayNativePowerInspection, ManagedLifecycleError> {
        let principal_id = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let current = self.inspect_current_ordinary_display_completion_phase(
            principal.clone(),
            request,
            attempt,
            verifier,
            false,
        )?;
        let query = linura_protocol::ObservationRequest {
            provider: ProviderId::new(DISPLAY_RECOVERY_PROVIDER).map_err(|_| invalid_original())?,
            capability: linura_core::CapabilityId::new(
                DISPLAY_ORDINARY_POWER_RETIREMENT_CAPABILITY,
            )
            .map_err(|_| invalid_original())?,
            resource: current
                .frames()
                .scope()
                .resource_id()
                .map_err(|_| invalid_original())?,
        };
        let before = self
            .previews
            .observe(&query)
            .map_err(|_| invalid_original())?
            .observation;
        let grant = DisplayOrdinaryPowerRetirementFacts::from_envelope(
            &before,
            current.frames().scope(),
            now_ms()?,
        )
        .map_err(|_| invalid_original())?;
        let prepared = {
            let _checked = self.checked_display_history()?;
            PowerPrepared::load(self.display_journal()?, &principal_id, &current)?
        };
        if !grant.grant_spent()
            || grant.completion_digest() != current.root().lineage().record
            || grant.preparation_digest() != prepared.preparation().hex()
            || grant.checkpoint_digest() != prepared.checkpoint().hex()
            || !current
                .frames()
                .follows_native_power_retirement(&prepared.frames)
        {
            return Err(invalid_original());
        }
        let after = self
            .previews
            .observe(&query)
            .map_err(|_| invalid_original())?
            .observation;
        if after.sequence <= before.sequence
            || after.observed_at_unix_ms < before.observed_at_unix_ms
            || DisplayOrdinaryPowerRetirementFacts::from_envelope(
                &after,
                current.frames().scope(),
                now_ms()?,
            )
            .map_err(|_| invalid_original())?
                != grant
        {
            return Err(invalid_original());
        }
        let mut latest = self.inspect_current_ordinary_display_completion_phase(
            principal, request, attempt, verifier, false,
        )?;
        if latest.root() != current.root()
            || latest.release() != current.release()
            || !latest.frames().reconciles(current.frames())
        {
            return Err(invalid_original());
        }
        {
            let _checked = self.checked_display_history()?;
            prepared.readback(self.display_journal()?, &principal_id, request)?;
        }
        // Retain fresh post-effect sources, never the old preparation expiry.
        for source in [&before, &after, current.observation()] {
            crate::plan_preview::restrict_session_validity(
                &mut latest.observation,
                source,
                now_ms()?,
            )
            .map_err(|_| invalid_original())?;
        }
        latest.observation.attributes.insert(
            "control.ordinary-current.native_power_grant_digest".into(),
            ObservedValue::Text(
                crate::durable_authority::digest_observation(&after)?
                    .as_str()
                    .into(),
            ),
        );
        Ok(OrdinaryDisplayNativePowerInspection {
            current: latest,
            grant,
            preparation: prepared.preparation(),
        })
    }
}
