//! Ordered ordinary Root-power retirement. The original signed terminal and
//! release Indeterminate state stay unchanged. All remaining fences are held.
use super::*;
use linura_observation::{
    DISPLAY_ORDINARY_ROOT_RETIREMENT_CAPABILITY, DISPLAY_RECOVERY_PROVIDER,
    DisplayOrdinaryCurrentFacts, DisplayOrdinaryPowerRetirementFacts,
    DisplayOrdinaryRootRetirementFacts,
};
use linura_transaction::{ContentDigest, RetainedRequest, TransactionStoreError, digest_bytes};

const DOMAIN: &str = "linura.display.ordinary-root-power-prepared.v1";
const KEY_DOMAIN: &str = "linura.display.ordinary-root-power-key.v1";
const LIMIT: usize = 4096;

#[derive(Debug)]
pub struct AuthorizedOrdinaryDisplayRootPowerRetirement {
    power: DisplayOrdinaryPowerRetirementFacts,
    frames: DisplayOrdinaryCurrentFacts,
    preparation: ContentDigest,
    verification: ContentDigest,
    expiry: u64,
}
impl AuthorizedOrdinaryDisplayRootPowerRetirement {
    pub const fn power(&self) -> &DisplayOrdinaryPowerRetirementFacts {
        &self.power
    }
    pub const fn frames(&self) -> &DisplayOrdinaryCurrentFacts {
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
pub trait OrdinaryDisplayRootPowerRetirementPort: Debug + Send {
    fn retire_ordinary_root_power(
        &mut self,
        permit: AuthorizedOrdinaryDisplayRootPowerRetirement,
    ) -> Result<(), String>;
}
#[derive(Debug)]
pub struct OrdinaryDisplayRootPowerInspection {
    power: OrdinaryDisplayNativePowerInspection,
    root: DisplayOrdinaryRootRetirementFacts,
    preparation: ContentDigest,
}
impl OrdinaryDisplayRootPowerInspection {
    pub const fn power(&self) -> &OrdinaryDisplayNativePowerInspection {
        &self.power
    }
    pub const fn root(&self) -> &DisplayOrdinaryRootRetirementFacts {
        &self.root
    }
    pub const fn preparation(&self) -> &ContentDigest {
        &self.preparation
    }
}
fn key(request: &RequestId) -> Result<RequestId, ManagedLifecycleError> {
    RequestId::new(format!(
        "request:v010:display-ordinary-root-power-prepared:{}",
        digest_bytes(KEY_DOMAIN, request.as_str().as_bytes()).hex()
    ))
    .map_err(|_| invalid_original())
}
fn append(out: &mut Vec<u8>, v: &str) -> Result<(), ManagedLifecycleError> {
    if v.is_empty() || out.len().checked_add(8 + v.len()).is_none_or(|n| n > LIMIT) {
        return Err(invalid_original());
    }
    out.extend_from_slice(&(v.len() as u64).to_be_bytes());
    out.extend_from_slice(v.as_bytes());
    Ok(())
}
fn field<'a>(rest: &mut &'a [u8]) -> Result<&'a str, ManagedLifecycleError> {
    let (n, body) = rest.split_at_checked(8).ok_or_else(invalid_original)?;
    let n = usize::try_from(u64::from_be_bytes(
        n.try_into().map_err(|_| invalid_original())?,
    ))
    .map_err(|_| invalid_original())?;
    if n == 0 || n > 256 {
        return Err(invalid_original());
    }
    let (s, tail) = body.split_at_checked(n).ok_or_else(invalid_original)?;
    *rest = tail;
    std::str::from_utf8(s).map_err(|_| invalid_original())
}
fn number(rest: &mut &[u8]) -> Result<u64, ManagedLifecycleError> {
    let s = field(rest)?;
    let n = s.parse::<u64>().map_err(|_| invalid_original())?;
    if n.to_string() != s {
        return Err(invalid_original());
    }
    Ok(n)
}
struct Prepared {
    bytes: Vec<u8>,
    verification: ContentDigest,
    created: u64,
    expiry: u64,
}
impl Prepared {
    fn prefix(
        principal: &PrincipalId,
        power: &OrdinaryDisplayNativePowerInspection,
    ) -> Result<Vec<u8>, ManagedLifecycleError> {
        let c = power.current();
        let s = c.release();
        let r = c.root().lineage();
        let mut b = Vec::new();
        for v in [
            DOMAIN.into(),
            principal.as_str().into(),
            c.request().request_id.as_str().into(),
            s.transaction_id.as_str().into(),
            crate::durable_authority::digest_request(c.request())?
                .as_str()
                .into(),
            s.current_generation.to_string(),
            s.state_version.to_string(),
            s.binding_digest.as_str().into(),
            r.record.clone(),
            r.preparation.clone(),
            r.verification.clone(),
            power.grant().record_digest().into(),
            power.preparation().as_str().into(),
            power.grant().checkpoint_digest().into(),
        ] {
            append(&mut b, &v)?;
        }
        Ok(b)
    }
    fn capture(
        principal: &PrincipalId,
        power: &OrdinaryDisplayNativePowerInspection,
        deadline: u64,
    ) -> Result<Self, ManagedLifecycleError> {
        let c = power.current();
        let created = now_ms()?;
        c.observation()
            .require_current(created)
            .map_err(|_| invalid_original())?;
        let w = c.frames().window();
        let expiry = c
            .observation()
            .observed_at_unix_ms
            .checked_add(c.observation().valid_for_ms)
            .ok_or_else(invalid_original)?
            .min(
                w.observed_unix_ms
                    .checked_add(w.valid_for_ms().map_err(|_| invalid_original())?)
                    .ok_or_else(invalid_original)?,
            )
            .min(deadline);
        if created < w.observed_unix_ms
            || created >= expiry
            || c.frames().power_fence_held()
            || !c.frames().input_retired()
            || !power.grant().grant_spent()
        {
            return Err(invalid_original());
        }
        let verification = crate::durable_authority::digest_observation(c.observation())?;
        let mut bytes = Self::prefix(principal, power)?;
        for v in [
            verification.as_str().into(),
            created.to_string(),
            expiry.to_string(),
        ] {
            append(&mut bytes, &v)?;
        }
        Ok(Self {
            bytes,
            verification,
            created,
            expiry,
        })
    }
    fn load(
        journal: &dyn ApprovedRequestJournal,
        principal: &PrincipalId,
        power: &OrdinaryDisplayNativePowerInspection,
    ) -> Result<Self, ManagedLifecycleError> {
        let k = key(&power.current().request().request_id)?;
        let row = journal
            .load(principal, &k)
            .map_err(|_| invalid_original())?;
        let prefix = Self::prefix(principal, power)?;
        if row.principal() != principal
            || row.request_id() != &k
            || row.canonical().len() > LIMIT
            || !row.canonical().starts_with(&prefix)
        {
            return Err(invalid_original());
        }
        let mut rest = &row.canonical()[prefix.len()..];
        let verification = ContentDigest::new(field(&mut rest)?).map_err(|_| invalid_original())?;
        let created = number(&mut rest)?;
        let expiry = number(&mut rest)?;
        if !rest.is_empty()
            || verification == ContentDigest::zero()
            || created == 0
            || created >= expiry
            || created > now_ms()?
            || expiry - created > 2000
        {
            return Err(invalid_original());
        }
        Ok(Self {
            bytes: row.canonical().to_vec(),
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
        let k = key(request)?;
        let row = journal
            .load(principal, &k)
            .map_err(|_| invalid_original())?;
        if row.principal() != principal || row.request_id() != &k || row.canonical() != self.bytes {
            return Err(invalid_original());
        }
        Ok(())
    }
}
impl<S: TransactionStore> ManagedLifecycleControl<S> {
    #[allow(clippy::too_many_arguments)]
    pub fn retire_ordinary_display_root_power<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
        N: OrdinaryDisplayRootPowerRetirementPort,
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
        let pid = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let transaction = TransactionId::for_namespace(&pid, request);
        let live = self
            .display_reviews
            .get(&transaction)
            .ok_or_else(invalid_original)?;
        let (native, checkpoint) = match &live.stage {
            DisplayReviewStage::OrdinaryPowerDispatched {
                preparation,
                checkpoint,
            } => (preparation.clone(), checkpoint.clone()),
            _ => return Err(invalid_original()),
        };
        let mut review = self
            .display_reviews
            .remove(&transaction)
            .ok_or_else(invalid_original)?;
        {
            let _checked = self.checked_display_history()?;
            match self.display_journal()?.load(&pid, &key(request)?) {
                Err(TransactionStoreError::NotFound) => (),
                _ => return Err(invalid_original()),
            }
        }
        let power = self.inspect_ordinary_display_native_power_retirement(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        if power.preparation() != &native || power.grant().checkpoint_digest() != checkpoint.hex() {
            return Err(invalid_original());
        }
        self.require_ordinary_power_review(&principal, power.current(), &review)?;
        let prepared = Prepared::capture(&pid, &power, review.deadline_unix_ms)?;
        let row = RetainedRequest::new(pid.clone(), key(request)?, prepared.bytes.clone())
            .map_err(|_| invalid_original())?;
        self.request_journal
            .as_mut()
            .ok_or_else(invalid_original)?
            .retain(&row)
            .map_err(|_| invalid_original())?;
        {
            let _checked = self.checked_display_history()?;
            prepared.readback(self.display_journal()?, &pid, request)?;
        }
        let fresh = self.inspect_ordinary_display_native_power_retirement(
            principal.clone(),
            request,
            attempt,
            verifier,
        )?;
        if fresh.grant() != power.grant()
            || fresh.current().root() != power.current().root()
            || fresh.current().release() != power.current().release()
            || !fresh
                .current()
                .frames()
                .reconciles(power.current().frames())
        {
            return Err(invalid_original());
        }
        self.require_ordinary_power_review(&principal, fresh.current(), &review)?;
        {
            let _checked = self.checked_display_history()?;
            prepared.readback(self.display_journal()?, &pid, request)?;
        }
        prepared.current()?;
        review.stage = DisplayReviewStage::OrdinaryRootPowerDispatched {
            preparation: prepared.digest(),
        };
        self.check_display_review_capacity(review.retained_bytes)?;
        self.display_reviews.insert(transaction, review);
        port.retire_ordinary_root_power(AuthorizedOrdinaryDisplayRootPowerRetirement {
            power: fresh.grant().clone(),
            frames: fresh.current().frames().clone(),
            preparation: prepared.digest(),
            verification: prepared.verification.clone(),
            expiry: prepared.expiry,
        })
        .map_err(|_| {
            ManagedLifecycleError::Indeterminate(
                "ordinary Root power outcome uncertain; no replay".into(),
            )
        })?;
        let _checked = self.checked_display_history()?;
        prepared.readback(self.display_journal()?, &pid, request)?;
        if self
            .authority
            .matching_request_snapshot(&principal, fresh.current().request())?
            != *fresh.current().release()
        {
            return Err(invalid_original());
        }
        Ok(())
    }
    pub fn inspect_ordinary_display_root_power_retirement<
        P: DisplayTransactionPort,
        V: IndependentDisplayVerifier,
    >(
        &mut self,
        principal: AuthenticatedPrincipal,
        request: &RequestId,
        attempt: &mut P,
        verifier: &mut V,
    ) -> Result<OrdinaryDisplayRootPowerInspection, ManagedLifecycleError> {
        let pid = PrincipalId::new(principal.as_str()).map_err(|_| invalid_original())?;
        let power = self.inspect_ordinary_display_native_power_retirement_phase(
            principal.clone(),
            request,
            attempt,
            verifier,
            true,
        )?;
        let scope = power.current().frames().scope();
        let q = linura_protocol::ObservationRequest {
            provider: ProviderId::new(DISPLAY_RECOVERY_PROVIDER).map_err(|_| invalid_original())?,
            capability: linura_core::CapabilityId::new(DISPLAY_ORDINARY_ROOT_RETIREMENT_CAPABILITY)
                .map_err(|_| invalid_original())?,
            resource: scope.resource_id().map_err(|_| invalid_original())?,
        };
        let before = self
            .previews
            .observe(&q)
            .map_err(|_| invalid_original())?
            .observation;
        let root = DisplayOrdinaryRootRetirementFacts::from_envelope(&before, scope, now_ms()?)
            .map_err(|_| invalid_original())?;
        let prepared = {
            let _checked = self.checked_display_history()?;
            Prepared::load(self.display_journal()?, &pid, &power)?
        };
        if root.completion() != power.current().root()
            || root.lineage().power_record != power.grant().record_digest()
            || root.lineage().preparation != prepared.digest().hex()
            || root.lineage().verification != prepared.verification.hex()
        {
            return Err(invalid_original());
        }
        let after = self
            .previews
            .observe(&q)
            .map_err(|_| invalid_original())?
            .observation;
        if after.sequence <= before.sequence
            || after.observed_at_unix_ms < before.observed_at_unix_ms
            || DisplayOrdinaryRootRetirementFacts::from_envelope(&after, scope, now_ms()?)
                .map_err(|_| invalid_original())?
                != root
        {
            return Err(invalid_original());
        }
        let mut latest = self.inspect_ordinary_display_native_power_retirement_phase(
            principal, request, attempt, verifier, true,
        )?;
        if latest.grant() != power.grant()
            || latest.current().root() != power.current().root()
            || latest.current().release() != power.current().release()
            || !latest
                .current()
                .frames()
                .reconciles(power.current().frames())
        {
            return Err(invalid_original());
        }
        {
            let _checked = self.checked_display_history()?;
            prepared.readback(self.display_journal()?, &pid, request)?;
        }
        // Preserve the actual retired-Root envelope as the aggregate base. Its
        // capability must not be relabelled from an earlier held-power source.
        let mut joined = after;
        for (name, source) in [
            ("root_before", &before),
            ("native_power", power.current().observation()),
            ("current", latest.current().observation()),
        ] {
            crate::plan_preview::restrict_session_validity(&mut joined, source, now_ms()?)
                .map_err(|_| invalid_original())?;
            joined.attributes.insert(
                format!("control.ordinary-root.{name}_digest"),
                ObservedValue::Text(
                    crate::durable_authority::digest_observation(source)?
                        .as_str()
                        .into(),
                ),
            );
        }
        joined
            .require_current(now_ms()?)
            .map_err(|_| invalid_original())?;
        latest.current.observation = joined;
        Ok(OrdinaryDisplayRootPowerInspection {
            power: latest,
            root,
            preparation: prepared.digest(),
        })
    }
}
