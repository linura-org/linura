//! Composition of a sealed canonical Apply challenge with native review/PAM.
//! Public display execution remains unavailable until its complete recovery and
//! native acceptance are qualified. Neither this proof nor Polkit is an executor
//! credential; managed prepare and fresh pre-dispatch revalidation remain inward.
use std::thread;
use std::time::Duration;

use linura_control::{ManagedApprovalChallenge, ManagedApprovalClass, TrustedHumanApproval};
use linura_core::{DisplayLayoutMaterial, PrincipalId};
use linura_linux_session::{NativeDisplayApprovalRequest, NativeSessionChannel};

const INTERACTION_BUDGET: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(100);

pub(crate) fn authorize(
    channel: &NativeSessionChannel,
    principal: &PrincipalId,
    challenge: &ManagedApprovalChallenge,
) -> Result<TrustedHumanApproval, String> {
    let request = request(principal, challenge)?;
    complete(
        &ProductionPort { channel },
        &request,
        &|| request.remaining(),
        &thread::sleep,
    )?;
    Ok(TrustedHumanApproval::from_authorized_challenge(
        principal.clone(),
        challenge,
    ))
}

fn request(
    principal: &PrincipalId,
    challenge: &ManagedApprovalChallenge,
) -> Result<NativeDisplayApprovalRequest, String> {
    if challenge.principal() != principal
        || challenge.change_key() != "layout"
        || challenge.approval_class() != ManagedApprovalClass::Administrator
    {
        return Err("native display approval has another principal/class/purpose".into());
    }
    let material =
        DisplayLayoutMaterial::decode(challenge.desired_value()).map_err(|e| e.to_string())?;
    if material
        .topology()
        .resource_id()
        .map_err(|e| e.to_string())?
        != *challenge.resource()
    {
        return Err("native display approval material has another resource".into());
    }
    NativeDisplayApprovalRequest::new(
        principal.clone(),
        challenge.request_id().clone(),
        challenge.plan_id().clone(),
        super::session_approval::digest(challenge.request_digest())?,
        super::session_approval::digest(challenge.observation_digest())?,
        super::session_approval::digest(challenge.review_digest())?,
        challenge.desired_value(),
        challenge.reason(),
        INTERACTION_BUDGET,
    )
}

trait Port {
    fn arm(&self, request: &NativeDisplayApprovalRequest) -> Result<bool, String>;
    fn ready(&self, request: &NativeDisplayApprovalRequest) -> Result<bool, String>;
    fn authenticate(&self, request: &NativeDisplayApprovalRequest) -> Result<(), String>;
    fn consume(&self, request: &NativeDisplayApprovalRequest) -> Result<bool, String>;
    fn cancel(&self, request: &NativeDisplayApprovalRequest);
}

struct Pending<'a, P: Port> {
    port: &'a P,
    request: &'a NativeDisplayApprovalRequest,
    consumed: bool,
}
impl<P: Port> Drop for Pending<'_, P> {
    fn drop(&mut self) {
        if !self.consumed {
            self.port.cancel(self.request);
        }
    }
}

fn complete<P: Port>(
    port: &P,
    request: &NativeDisplayApprovalRequest,
    remaining: &impl Fn() -> Result<Duration, String>,
    wait: &impl Fn(Duration),
) -> Result<(), String> {
    // Register cleanup before Arm: a lost reply can leave the native view live.
    // Its exact immutable scope cannot cancel a later or replaced conversation.
    let mut pending = Pending {
        port,
        request,
        consumed: false,
    };
    remaining()?;
    if !port.arm(request)? {
        return Err("native display owner refused the scoped review".into());
    }
    remaining()?;
    loop {
        remaining()?;
        let ready = port.ready(request)?;
        remaining()?;
        if ready {
            break;
        }
        wait(POLL.min(remaining()?));
    }
    // Only the native owner may report that the final physically acknowledged
    // page and fresh frame are ready. Control owns bounded scheduling; the
    // native adapter never polls, renews a deadline or supplies approval itself.
    port.authenticate(request)?;
    remaining()?;
    if !port.consume(request)? {
        return Err("native display owner did not prove fresh scoped authentication".into());
    }
    remaining()?; // A late consume reply cannot authorize dispatch.
    pending.consumed = true;
    Ok(())
}

struct ProductionPort<'a> {
    channel: &'a NativeSessionChannel,
}
impl Port for ProductionPort<'_> {
    fn arm(&self, request: &NativeDisplayApprovalRequest) -> Result<bool, String> {
        self.channel.arm_display_approval(request)
    }
    fn ready(&self, request: &NativeDisplayApprovalRequest) -> Result<bool, String> {
        self.channel.display_approval_ready(request)
    }
    fn authenticate(&self, request: &NativeDisplayApprovalRequest) -> Result<(), String> {
        self.channel.authenticate_display_approval(request)
    }
    fn consume(&self, request: &NativeDisplayApprovalRequest) -> Result<bool, String> {
        self.channel.consume_display_approval(request)
    }
    fn cancel(&self, request: &NativeDisplayApprovalRequest) {
        let _cancelled_or_unavailable = self.channel.cancel_display_approval(request);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{PlanId, RequestId};
    use linura_provider_sdk::ComponentDigest;
    use std::cell::{Cell, RefCell};

    fn value<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|e| unreachable!("{e:?}"))
    }
    fn fixture() -> NativeDisplayApprovalRequest {
        let topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3";
        let layout = format!("LNDL:1;{topology};1:2:enabled:1920:1080:60000:1000:0:0:0:-;");
        let material = format!(
            "LNDI:1;session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1;{layout}{layout}"
        );
        value(NativeDisplayApprovalRequest::new(
            value(PrincipalId::new("unix:uid:1000")),
            value(RequestId::new("request:v010:display-layout:approval")),
            value(PlanId::new("request:v010:display-layout:approval")),
            ComponentDigest::from_bytes([1; 32]),
            ComponentDigest::from_bytes([2; 32]),
            ComponentDigest::from_bytes([3; 32]),
            &material,
            "Keep the requested native layout",
            INTERACTION_BUDGET,
        ))
    }
    struct Fake {
        calls: RefCell<Vec<&'static str>>,
        budget: Cell<u64>,
        waiting: Cell<bool>,
        fault: Option<&'static str>,
        late: Option<&'static str>,
        refused: Option<&'static str>,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                budget: Cell::new(1000),
                waiting: Cell::new(true),
                fault: None,
                late: None,
                refused: None,
            }
        }
        fn call(&self, stage: &'static str) -> Result<bool, String> {
            self.calls.borrow_mut().push(stage);
            if self.late == Some(stage) {
                self.budget.set(0);
            }
            if self.fault == Some(stage) {
                return Err("native unavailable".into());
            }
            Ok(self.refused != Some(stage))
        }
        fn run(&self, request: &NativeDisplayApprovalRequest) -> Result<(), String> {
            complete(
                self,
                request,
                &|| {
                    if self.budget.get() == 0 {
                        Err("original deadline expired".into())
                    } else {
                        Ok(Duration::from_millis(self.budget.get()))
                    }
                },
                &|delay| {
                    self.calls.borrow_mut().push("wait");
                    self.waiting.set(false);
                    self.budget
                        .set(self.budget.get().saturating_sub(delay.as_millis() as u64));
                },
            )
        }
    }
    impl Port for Fake {
        fn arm(&self, _: &NativeDisplayApprovalRequest) -> Result<bool, String> {
            self.call("arm")
        }
        fn ready(&self, _: &NativeDisplayApprovalRequest) -> Result<bool, String> {
            Ok(self.call("ready")? && !self.waiting.get())
        }
        fn authenticate(&self, _: &NativeDisplayApprovalRequest) -> Result<(), String> {
            if self.call("authenticate")? {
                Ok(())
            } else {
                Err("denied".into())
            }
        }
        fn consume(&self, _: &NativeDisplayApprovalRequest) -> Result<bool, String> {
            self.call("consume")
        }
        fn cancel(&self, _: &NativeDisplayApprovalRequest) {
            self.calls.borrow_mut().push("cancel");
        }
    }
    #[test]
    fn fresh_ready_frame_precedes_authentication_and_one_native_consumption() {
        let port = Fake::new();
        assert!(port.run(&fixture()).is_ok());
        assert_eq!(
            *port.calls.borrow(),
            ["arm", "ready", "wait", "ready", "authenticate", "consume"]
        );
    }
    #[test]
    fn every_uncertain_or_late_reply_cancels_without_advancing_or_retrying() {
        for stage in ["arm", "ready", "authenticate", "consume"] {
            for late in [false, true] {
                let mut port = Fake::new();
                if late {
                    port.late = Some(stage);
                } else {
                    port.fault = Some(stage);
                }
                assert!(port.run(&fixture()).is_err());
                let calls = port.calls.borrow();
                assert_eq!(calls.last(), Some(&"cancel"));
                assert_eq!(calls.iter().filter(|value| **value == stage).count(), 1);
                let index = value(
                    calls
                        .iter()
                        .position(|value| *value == stage)
                        .ok_or("missing stage"),
                );
                assert_eq!(calls[index + 1..], ["cancel"]);
            }
        }
    }
    #[test]
    fn denial_missing_proof_and_expiry_never_return_approval() {
        for stage in ["arm", "ready", "authenticate", "consume"] {
            let mut port = Fake::new();
            port.refused = Some(stage);
            assert!(port.run(&fixture()).is_err());
            let calls = port.calls.borrow();
            assert_eq!(calls.last(), Some(&"cancel"));
            if stage != "consume" {
                assert!(!calls.contains(&"consume"));
            }
        }
        let port = Fake::new();
        port.budget.set(0);
        assert!(port.run(&fixture()).is_err());
        assert_eq!(*port.calls.borrow(), ["cancel"]);
    }
}
