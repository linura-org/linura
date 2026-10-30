//! Private native comparison/interaction transport. These values neither create
//! a policy review nor grant prepared execution or human approval.
use super::*;
use linura_core::{PlanId, PrincipalId, RequestId};
use linura_provider_sdk::ComponentDigest;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use super::super::{ApprovalWire, approval_operation_slug};

/// Separate display purposes cannot enter S17's lock-only approval transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeDisplayApprovalPurpose {
    Apply,
    Keep,
    Revert,
}
impl NativeDisplayApprovalPurpose {
    fn wire(self) -> u32 {
        match self {
            Self::Apply => 8,
            Self::Keep => 9,
            Self::Revert => 10,
        }
    }

    fn authentication_action(self) -> Result<&'static str, String> {
        Ok(match self {
            NativeDisplayApprovalPurpose::Apply => "org.linura.authority.apply-display-layout",
            NativeDisplayApprovalPurpose::Keep | NativeDisplayApprovalPurpose::Revert => {
                return Err("display decisions require the retained native attempt".into());
            }
        })
    }
}

/// Original canonical lineage plus complete native presentation data. The
/// constructor validates syntax/identity only; Control must supply a genuine
/// sealed canonical challenge and independently authenticate the caller.
#[derive(Debug)]
pub struct NativeDisplayApprovalRequest {
    lock: SessionLockId,
    principal: PrincipalId,
    request: RequestId,
    plan: PlanId,
    request_digest: ComponentDigest,
    observation_digest: ComponentDigest,
    review_digest: ComponentDigest,
    material: String,
    reason: String,
    deadline_unix_ms: u64,
    deadline_boot_ms: u64,
    last_unix_ms: AtomicU64,
    last_boot_ms: AtomicU64,
}

impl NativeDisplayApprovalRequest {
    /// Apply admission only. Keep/Revert continue a retained original native
    /// transaction; they cannot reconstruct its review from client hashes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal: PrincipalId,
        request: RequestId,
        plan: PlanId,
        request_digest: ComponentDigest,
        observation_digest: ComponentDigest,
        review_digest: ComponentDigest,
        material: &str,
        reason: &str,
        budget: Duration,
    ) -> Result<Self, String> {
        let started_unix_ms = unix_ms()?;
        let started_boot_ms = boot_ms()?;
        Self::at(
            principal,
            request,
            plan,
            request_digest,
            observation_digest,
            review_digest,
            material,
            reason,
            budget,
            started_unix_ms,
            started_boot_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn at(
        principal: PrincipalId,
        request: RequestId,
        plan: PlanId,
        request_digest: ComponentDigest,
        observation_digest: ComponentDigest,
        review_digest: ComponentDigest,
        material: &str,
        reason: &str,
        budget: Duration,
        started_unix_ms: u64,
        started_boot_ms: u64,
    ) -> Result<Self, String> {
        if material.len() > linura_core::MAX_DISPLAY_INTENT_BYTES
            || reason.is_empty()
            || reason.len() > 8192
            || reason.encode_utf16().count() > 2048
            || reason.chars().any(|c| c.is_control() && c != '\n')
            || budget.is_zero()
            || budget > Duration::from_secs(60)
            || !budget.subsec_nanos().is_multiple_of(1_000_000)
            || started_unix_ms == 0
            || started_boot_ms == 0
        {
            return Err("native display interaction material/window is unsupported".into());
        }
        let intent =
            linura_core::DisplayLayoutMaterial::decode(material).map_err(|e| e.to_string())?;
        let prefix = "request:v010:display-layout:";
        let operation = request
            .as_str()
            .strip_prefix(prefix)
            .ok_or("native display approval has another operation purpose")?;
        if !approval_operation_slug(operation)
            || plan.as_str() != request.as_str()
            || principal.as_str() != format!("unix:uid:{}", intent.lock().epoch().uid())
        {
            return Err("native display approval principal/plan/request mismatch".into());
        }
        let millis = u64::try_from(budget.as_millis())
            .map_err(|_| "native display interaction window overflow")?;
        Ok(Self {
            lock: intent.lock().clone(),
            principal,
            request,
            plan,
            request_digest,
            observation_digest,
            review_digest,
            material: material.into(),
            reason: reason.into(),
            deadline_unix_ms: started_unix_ms
                .checked_add(millis)
                .ok_or("native display interaction wall clock overflow")?,
            deadline_boot_ms: started_boot_ms
                .checked_add(millis)
                .ok_or("native display interaction boot clock overflow")?,
            last_unix_ms: AtomicU64::new(started_unix_ms),
            last_boot_ms: AtomicU64::new(started_boot_ms),
        })
    }

    #[must_use]
    pub fn lock(&self) -> &SessionLockId {
        &self.lock
    }

    #[must_use]
    pub fn request_id(&self) -> &RequestId {
        &self.request
    }

    /// Comparison with the native compositor conversation, not a credential.
    pub fn protected_scope_digest(&self) -> Result<ComponentDigest, String> {
        let (lock, principal, request, plan, request_digest, observation, review, purpose) =
            self.wire()?;
        let fields = [
            "linura.native.display-approval.v1".to_owned(),
            lock,
            principal,
            request,
            plan,
            request_digest,
            observation,
            review,
            purpose.to_string(),
            self.material.clone(),
            String::new(),
            self.deadline_unix_ms.to_string(),
            self.deadline_boot_ms.to_string(),
            self.reason.clone(),
        ];
        let mut hash = Sha256::new();
        for field in fields {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        Ok(ComponentDigest::from_bytes(hash.finalize().into()))
    }

    /// Original dual-clock budget. Polling, a native reply or suspend cannot
    /// renew it. A detected rollback terminally exhausts this comparison scope.
    pub fn remaining(&self) -> Result<Duration, String> {
        self.remaining_at(unix_ms()?, boot_ms()?)
    }

    fn remaining_at(&self, unix: u64, boot: u64) -> Result<Duration, String> {
        let old_unix = self.last_unix_ms.fetch_max(unix, Ordering::SeqCst);
        let old_boot = self.last_boot_ms.fetch_max(boot, Ordering::SeqCst);
        if unix < old_unix || boot < old_boot {
            self.last_unix_ms.store(u64::MAX, Ordering::SeqCst);
            self.last_boot_ms.store(u64::MAX, Ordering::SeqCst);
            return Err("native display interaction clock rolled back".into());
        }
        self.deadline_unix_ms
            .checked_sub(unix)
            .zip(self.deadline_boot_ms.checked_sub(boot))
            .map(|(wall, monotonic)| wall.min(monotonic))
            .filter(|left| *left != 0)
            .map(Duration::from_millis)
            .ok_or_else(|| "native display interaction original deadline expired".into())
    }

    fn wire(&self) -> Result<ApprovalWire, String> {
        Ok((
            self.lock
                .resource_id()
                .map_err(|e| e.to_string())?
                .as_str()
                .into(),
            self.principal.as_str().into(),
            self.request.as_str().into(),
            self.plan.as_str().into(),
            format!("sha256:{}", self.request_digest.to_hex()),
            format!("sha256:{}", self.observation_digest.to_hex()),
            format!("sha256:{}", self.review_digest.to_hex()),
            NativeDisplayApprovalPurpose::Apply.wire(),
        ))
    }
}

impl NativeSessionChannel {
    fn display_approval_call(
        &self,
        request: &NativeDisplayApprovalRequest,
        method: &str,
    ) -> Result<bool, String> {
        self.require_role(NativeSessionRole::Control)?;
        // Cancellation is scoped comparison-only cleanup. It must remain
        // possible after expiry/clock rollback, without reaching a new scope.
        if method != "CancelDisplayApproval" {
            request.remaining()?;
        }
        let started = Instant::now();
        let owner = self.discover(request.lock.epoch().uid(), started)?;
        if owner.invocation != *request.lock.security_owner_invocation()
            || current_boot()? != *request.lock.epoch().boot()
        {
            return Err("display approval native owner/boot was replaced".into());
        }
        let reply = self.call_with_budget(
            &owner.unique_name,
            ENDPOINT,
            INTERFACE,
            method,
            &(
                request.wire()?,
                request.material.as_str(),
                request.reason.as_str(),
                request.deadline_unix_ms,
                request.deadline_boot_ms,
            ),
            if method == "CancelDisplayApproval" {
                owner_reply_budget(started.elapsed())?
            } else {
                owner_reply_budget(started.elapsed())?.min(request.remaining()?)
            },
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != owner.unique_name)
            || reply.body().signature().to_string() != "b"
        {
            return Err("display approval native reply identity/shape mismatch".into());
        }
        let (result,): (bool,) = reply
            .body()
            .deserialize()
            .map_err(|_| "display approval native result is malformed")?;
        self.revalidate(&owner, started)?;
        if method != "CancelDisplayApproval" {
            request.remaining()?;
        }
        Ok(result)
    }

    pub fn arm_display_approval(
        &self,
        request: &NativeDisplayApprovalRequest,
    ) -> Result<bool, String> {
        self.display_approval_call(request, "ArmDisplayApproval")
    }
    pub fn display_approval_ready(
        &self,
        request: &NativeDisplayApprovalRequest,
    ) -> Result<bool, String> {
        self.display_approval_call(request, "DisplayApprovalReady")
    }
    pub fn consume_display_approval(
        &self,
        request: &NativeDisplayApprovalRequest,
    ) -> Result<bool, String> {
        self.display_approval_call(request, "ConsumeDisplayApproval")
    }
    pub fn cancel_display_approval(
        &self,
        request: &NativeDisplayApprovalRequest,
    ) -> Result<bool, String> {
        self.display_approval_call(request, "CancelDisplayApproval")
    }

    /// Same Control connection, official Polkit/PAM and original dual-clock
    /// interaction window. A positive reply still requires native consumption.
    pub fn authenticate_display_approval(
        &self,
        request: &NativeDisplayApprovalRequest,
    ) -> Result<(), String> {
        let budget = request.remaining()?;
        request.wire()?;
        self.authenticate_native_scope(
            &request.lock,
            &request.request,
            NativeDisplayApprovalPurpose::Apply.authentication_action()?,
            "linura-s21-display",
            budget,
        )?;
        request.remaining()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    fn fixture() -> NativeDisplayApprovalRequest {
        let topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3";
        let material = format!(
            "LNDI:1;session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1;LNDL:1;{topology};1:2:enabled:1920:1080:60000:1000:0:0:0:-;LNDL:1;{topology};1:2:enabled:1280:720:59940:1250:1:-100:20:-;"
        );
        value(NativeDisplayApprovalRequest::at(
            value(PrincipalId::new("unix:uid:1000")),
            value(RequestId::new("request:v010:display-layout:review")),
            value(PlanId::new("request:v010:display-layout:review")),
            ComponentDigest::from_bytes([0x11; 32]),
            ComponentDigest::from_bytes([0x22; 32]),
            ComponentDigest::from_bytes([0x33; 32]),
            &material,
            "Make text easier to read",
            Duration::from_millis(999),
            1,
            1,
        ))
    }
    #[test]
    fn original_deadline_includes_suspend_and_rollback_is_terminal() {
        let request = fixture();
        assert_eq!(request.remaining_at(2, 2), Ok(Duration::from_millis(998)));
        assert!(request.remaining_at(3, 1000).is_err());
        assert!(request.remaining_at(4, 4).is_err());
        assert!(request.remaining_at(5, 1001).is_err());
        let request = fixture();
        assert!(request.remaining_at(200, 200).is_ok());
        assert!(request.remaining_at(199, 201).is_err());
        assert!(request.remaining_at(201, 201).is_err());
    }
    #[test]
    fn wire_is_apply_only_and_retains_original_canonical_review() {
        let request = fixture();
        let wire = value(request.wire());
        assert_eq!(wire.7, 8);
        assert_eq!(wire.1, "unix:uid:1000");
        assert_eq!(wire.2, wire.3);
        assert_eq!(wire.6, format!("sha256:{}", "3".repeat(64)));
        assert_eq!(NativeDisplayApprovalPurpose::Keep.wire(), 9);
        assert_eq!(NativeDisplayApprovalPurpose::Revert.wire(), 10);
        assert_eq!(
            value(NativeDisplayApprovalPurpose::Apply.authentication_action()),
            "org.linura.authority.apply-display-layout"
        );
        assert!(
            NativeDisplayApprovalPurpose::Keep
                .authentication_action()
                .is_err()
        );
        assert!(
            NativeDisplayApprovalPurpose::Revert
                .authentication_action()
                .is_err()
        );
        let original = value(request.protected_scope_digest());
        assert_eq!(
            original.to_hex(),
            "1912667e4c6dda437542c3d34758044bdf6b575ce2aec12b6837e682bf92e907"
        );
        let mut changed = fixture();
        changed.review_digest = ComponentDigest::from_bytes([0x44; 32]);
        assert_ne!(value(changed.protected_scope_digest()), original);
        changed = fixture();
        changed.material = changed.material.replace(":-100:", ":-101:");
        assert_ne!(value(changed.protected_scope_digest()), original);
        changed = fixture();
        changed.deadline_unix_ms += 1;
        assert_ne!(value(changed.protected_scope_digest()), original);
        changed = fixture();
        changed.deadline_boot_ms += 1;
        assert_ne!(value(changed.protected_scope_digest()), original);
    }
    #[test]
    fn malformed_or_substituted_scope_and_unbounded_window_are_rejected() {
        let source = fixture();
        for (principal, request, plan, reason, budget) in [
            (
                "unix:uid:1001",
                "request:v010:display-layout:review",
                "request:v010:display-layout:review",
                "why",
                Duration::from_secs(1),
            ),
            (
                "unix:uid:1000",
                "request:v010:session-lock:review",
                "request:v010:session-lock:review",
                "why",
                Duration::from_secs(1),
            ),
            (
                "unix:uid:1000",
                "request:v010:display-layout:review",
                "request:v010:display-layout:other",
                "why",
                Duration::from_secs(1),
            ),
            (
                "unix:uid:1000",
                "request:v010:display-layout:review",
                "request:v010:display-layout:review",
                "",
                Duration::from_secs(1),
            ),
            (
                "unix:uid:1000",
                "request:v010:display-layout:review",
                "request:v010:display-layout:review",
                "why",
                Duration::ZERO,
            ),
            (
                "unix:uid:1000",
                "request:v010:display-layout:review",
                "request:v010:display-layout:review",
                "why",
                Duration::from_secs(61),
            ),
        ] {
            assert!(
                NativeDisplayApprovalRequest::at(
                    value(PrincipalId::new(principal)),
                    value(RequestId::new(request)),
                    value(PlanId::new(plan)),
                    source.request_digest,
                    source.observation_digest,
                    source.review_digest,
                    &source.material,
                    reason,
                    budget,
                    1,
                    1,
                )
                .is_err()
            );
        }
    }
}
