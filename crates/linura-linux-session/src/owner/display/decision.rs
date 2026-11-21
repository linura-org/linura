//! Bounded private human-decision transport for an ORIGINAL native attempt.
//! The owner retains canonical review and both native attempt clock bounds.
//! This scheduling budget cannot create or extend either native deadline.
use super::*;
use linura_core::{PrincipalId, RequestId};
use linura_provider_sdk::ComponentDigest;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Debug)]
pub struct NativeDisplayDecisionRequest {
    principal: PrincipalId,
    request: RequestId,
    material: String,
    transaction: String,
    dispatch: ComponentDigest,
    decision: ComponentDigest,
    deadline: u64,
    confirm: bool,
    // Local query scheduling only; never transmitted as a native scope bound.
    started_boot: u64,
    scheduling_budget: u64,
    last_unix: AtomicU64,
    last_boot: AtomicU64,
}
impl NativeDisplayDecisionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal: PrincipalId,
        request: RequestId,
        material: &str,
        transaction: &str,
        dispatch: ComponentDigest,
        decision: ComponentDigest,
        deadline: u64,
        confirm: bool,
    ) -> Result<Self, String> {
        Self::at(
            principal,
            request,
            material,
            transaction,
            dispatch,
            decision,
            deadline,
            confirm,
            unix_ms()?,
            boot_ms()?,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn at(
        principal: PrincipalId,
        request: RequestId,
        material: &str,
        transaction: &str,
        dispatch: ComponentDigest,
        decision: ComponentDigest,
        deadline: u64,
        confirm: bool,
        unix: u64,
        boot: u64,
    ) -> Result<Self, String> {
        let query = attempt::Query::new(material, transaction, &dispatch, deadline)?;
        if unix == 0
            || boot == 0
            || deadline <= unix
            || deadline - unix > 15_000
            || decision == ComponentDigest::from_bytes([0; 32])
            || principal.as_str() != format!("unix:uid:{}", query.material().lock().epoch().uid())
            || !request
                .as_str()
                .strip_prefix("request:v010:display-layout:")
                .is_some_and(super::super::approval_operation_slug)
        {
            return Err("native display decision principal/request/deadline is unsupported".into());
        }
        Ok(Self {
            principal,
            request,
            material: material.into(),
            transaction: transaction.into(),
            dispatch,
            decision,
            deadline,
            confirm,
            started_boot: boot,
            scheduling_budget: deadline - unix,
            last_unix: AtomicU64::new(unix),
            last_boot: AtomicU64::new(boot),
        })
    }
    pub fn remaining(&self) -> Result<Duration, String> {
        self.remaining_at(unix_ms()?, boot_ms()?)
    }
    fn remaining_at(&self, unix: u64, boot: u64) -> Result<Duration, String> {
        let old_unix = self.last_unix.fetch_max(unix, Ordering::SeqCst);
        let old_boot = self.last_boot.fetch_max(boot, Ordering::SeqCst);
        if unix < old_unix || boot < old_boot {
            self.last_unix.store(u64::MAX, Ordering::SeqCst);
            self.last_boot.store(u64::MAX, Ordering::SeqCst);
            return Err("native display decision scheduling clock rolled back".into());
        }
        self.deadline
            .checked_sub(unix)
            .zip(
                boot.checked_sub(self.started_boot)
                    .and_then(|elapsed| self.scheduling_budget.checked_sub(elapsed)),
            )
            .map(|(wall, budget)| wall.min(budget))
            .filter(|left| *left != 0)
            .map(Duration::from_millis)
            .ok_or_else(|| "native display decision budget expired".into())
    }
}
#[derive(Clone, Copy)]
enum Call {
    Arm,
    Ready,
    Consume,
    Cancel,
}
impl Call {
    fn method(self) -> &'static str {
        match self {
            Self::Arm => "ArmDisplayDecision",
            Self::Ready => "DisplayDecisionReady",
            Self::Consume => "ConsumeDisplayDecision",
            Self::Cancel => "CancelDisplayDecision",
        }
    }
    fn cancellation(self) -> bool {
        matches!(self, Self::Cancel)
    }
}
impl NativeSessionChannel {
    fn display_decision_call(
        &self,
        request: &NativeDisplayDecisionRequest,
        call: Call,
    ) -> Result<bool, String> {
        self.require_role(NativeSessionRole::Control)?;
        if !call.cancellation() {
            request.remaining()?;
        }
        let query = attempt::Query::new(
            &request.material,
            &request.transaction,
            &request.dispatch,
            request.deadline,
        )?;
        let started = Instant::now();
        let owner = self.discover(query.material().lock().epoch().uid(), started)?;
        if owner.invocation != *query.material().lock().security_owner_invocation()
            || current_boot()? != *query.material().lock().epoch().boot()
        {
            return Err("native display decision owner/boot was replaced".into());
        }
        let budget = owner_reply_budget(started.elapsed())?;
        let budget = if call.cancellation() {
            budget
        } else {
            budget.min(request.remaining()?)
        };
        let wire = (
            request.material.as_str(),
            request.transaction.as_str(),
            query.effect_digest().to_hex(),
            request.dispatch.to_hex(),
            request.deadline,
        );
        let reply = self.call_with_budget(
            &owner.unique_name,
            ENDPOINT,
            INTERFACE,
            call.method(),
            &(
                request.principal.as_str(),
                request.request.as_str(),
                wire,
                request.decision.to_hex(),
                request.confirm,
            ),
            budget,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != owner.unique_name)
            || reply.body().signature().to_string() != "b"
        {
            return Err("native display decision reply identity/shape mismatch".into());
        }
        let (accepted,): (bool,) = reply
            .body()
            .deserialize()
            .map_err(|_| "native display decision result is malformed")?;
        self.revalidate(&owner, started)?;
        if !call.cancellation() {
            request.remaining()?;
        }
        Ok(accepted)
    }
    pub fn arm_display_decision(
        &self,
        request: &NativeDisplayDecisionRequest,
    ) -> Result<bool, String> {
        self.display_decision_call(request, Call::Arm)
    }
    pub fn display_decision_ready(
        &self,
        request: &NativeDisplayDecisionRequest,
    ) -> Result<bool, String> {
        self.display_decision_call(request, Call::Ready)
    }
    pub fn consume_display_decision(
        &self,
        request: &NativeDisplayDecisionRequest,
    ) -> Result<bool, String> {
        self.display_decision_call(request, Call::Consume)
    }
    pub fn cancel_display_decision(
        &self,
        request: &NativeDisplayDecisionRequest,
    ) -> Result<bool, String> {
        self.display_decision_call(request, Call::Cancel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn material() -> String {
        let topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3";
        format!(
            "LNDI:1;session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1;LNDL:1;{topology};1:2:enabled:1920:1080:60000:1000:0:0:0:-;LNDL:1;{topology};1:2:enabled:1280:720:59940:1250:1:-100:20:-;"
        )
    }
    fn make(
        unix: u64,
        boot: u64,
        deadline: u64,
        principal: &str,
        request: &str,
        dispatch: u8,
        decision: u8,
    ) -> Result<NativeDisplayDecisionRequest, String> {
        NativeDisplayDecisionRequest::at(
            PrincipalId::new(principal).map_err(|e| e.to_string())?,
            RequestId::new(request).map_err(|e| e.to_string())?,
            &material(),
            "transaction:original",
            ComponentDigest::from_bytes([dispatch; 32]),
            ComponentDigest::from_bytes([decision; 32]),
            deadline,
            true,
            unix,
            boot,
        )
    }
    fn fixture() -> NativeDisplayDecisionRequest {
        make(
            10_000,
            1000,
            11_000,
            "unix:uid:1000",
            "request:v010:display-layout:original",
            1,
            2,
        )
        .unwrap_or_else(|e| unreachable!("{e}"))
    }
    #[test]
    fn local_scheduling_is_bounded_and_rollback_is_terminal() {
        let request = fixture();
        assert_eq!(
            request.remaining_at(10_001, 1001),
            Ok(Duration::from_millis(999))
        );
        assert!(request.remaining_at(10_002, 2000).is_err());
        assert!(request.remaining_at(10_003, 1002).is_err());
        let request = fixture();
        assert!(request.remaining_at(10_100, 1100).is_ok());
        assert!(request.remaining_at(10_099, 1101).is_err());
        assert!(request.remaining_at(10_101, 1102).is_err());
        let request = fixture();
        assert!(request.remaining_at(11_000, 1001).is_err());
    }
    #[test]
    fn another_principal_operation_or_original_bound_is_not_a_choice() {
        for (unix, boot, deadline, principal, request, dispatch, decision) in [
            (
                0,
                1000,
                11_000,
                "unix:uid:1000",
                "request:v010:display-layout:original",
                1,
                2,
            ),
            (
                10_000,
                0,
                11_000,
                "unix:uid:1000",
                "request:v010:display-layout:original",
                1,
                2,
            ),
            (
                10_000,
                1000,
                10_000,
                "unix:uid:1000",
                "request:v010:display-layout:original",
                1,
                2,
            ),
            (
                10_000,
                1000,
                25_001,
                "unix:uid:1000",
                "request:v010:display-layout:original",
                1,
                2,
            ),
            (
                10_000,
                1000,
                11_000,
                "unix:uid:1001",
                "request:v010:display-layout:original",
                1,
                2,
            ),
            (
                10_000,
                1000,
                11_000,
                "unix:uid:1000",
                "request:v010:unlock:original",
                1,
                2,
            ),
            (
                10_000,
                1000,
                11_000,
                "unix:uid:1000",
                "request:v010:display-layout:original",
                0,
                2,
            ),
            (
                10_000,
                1000,
                11_000,
                "unix:uid:1000",
                "request:v010:display-layout:original",
                1,
                0,
            ),
        ] {
            assert!(make(unix, boot, deadline, principal, request, dispatch, decision).is_err());
        }
    }
}
