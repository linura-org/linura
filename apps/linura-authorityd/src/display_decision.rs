//! One fresh protected human choice over a retained managed display attempt.
//! Original Apply approval/Polkit cannot substitute for this native receipt.
use linura_control::{DisplayContinuationAction, DisplayDecisionChallenge, TrustedDisplayDecision};
use linura_core::PrincipalId;
use linura_linux_session::{NativeDisplayDecisionRequest, NativeSessionChannel};
use std::thread;
use std::time::Duration;

const POLL: Duration = Duration::from_millis(100);
pub(crate) fn authorize(
    channel: &NativeSessionChannel,
    principal: &PrincipalId,
    challenge: &DisplayDecisionChallenge,
) -> Result<TrustedDisplayDecision, String> {
    if challenge.principal() != principal {
        return Err(
            "native display decision principal differs from its canonical challenge".into(),
        );
    }
    let digest =
        linura_transaction::ContentDigest::new(challenge.digest()).map_err(|e| e.to_string())?;
    let request = NativeDisplayDecisionRequest::new(
        principal.clone(),
        challenge.request().request_id.clone(),
        crate::display_adapter::display_material(challenge.request())?,
        challenge.transaction_id(),
        linura_provider_sdk::ComponentDigest::parse_hex(challenge.dispatch_digest())
            .map_err(|e| e.to_string())?,
        linura_provider_sdk::ComponentDigest::parse_hex(digest.hex()).map_err(|e| e.to_string())?,
        challenge.deadline_unix_ms(),
        challenge.action() == DisplayContinuationAction::Confirm,
    )?;
    complete(
        &Production {
            channel,
            request: &request,
        },
        &|| request.remaining(),
        &thread::sleep,
    )?;
    Ok(TrustedDisplayDecision::from_protected_boundary(
        principal.clone(),
        challenge,
    ))
}
trait Port {
    fn arm(&self) -> Result<bool, String>;
    fn ready(&self) -> Result<bool, String>;
    fn consume(&self) -> Result<bool, String>;
    fn cancel(&self);
}
struct Pending<'a, P: Port> {
    port: &'a P,
    consumed: bool,
}
impl<P: Port> Drop for Pending<'_, P> {
    fn drop(&mut self) {
        if !self.consumed {
            self.port.cancel();
        }
    }
}
fn complete<P: Port>(
    port: &P,
    remaining: &impl Fn() -> Result<Duration, String>,
    wait: &impl Fn(Duration),
) -> Result<(), String> {
    let mut pending = Pending {
        port,
        consumed: false,
    };
    remaining()?;
    if !port.arm()? {
        return Err("native display decision review was refused".into());
    }
    remaining()?;
    loop {
        remaining()?;
        if port.ready()? {
            break;
        }
        wait(POLL.min(remaining()?));
    }
    remaining()?;
    if !port.consume()? {
        return Err("native display decision has no fresh protected human receipt".into());
    }
    remaining()?;
    pending.consumed = true;
    Ok(())
}
struct Production<'a> {
    channel: &'a NativeSessionChannel,
    request: &'a NativeDisplayDecisionRequest,
}
impl Port for Production<'_> {
    fn arm(&self) -> Result<bool, String> {
        self.channel.arm_display_decision(self.request)
    }
    fn ready(&self) -> Result<bool, String> {
        self.channel.display_decision_ready(self.request)
    }
    fn consume(&self) -> Result<bool, String> {
        self.channel.consume_display_decision(self.request)
    }
    fn cancel(&self) {
        let _cancelled_or_unavailable = self.channel.cancel_display_decision(self.request);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    struct Fixture {
        calls: RefCell<Vec<&'static str>>,
        stage: Option<&'static str>,
        refused: bool,
        expired: Cell<bool>,
        late: bool,
    }
    impl Fixture {
        fn call(&self, stage: &'static str) -> Result<bool, String> {
            self.calls.borrow_mut().push(stage);
            if self.stage == Some(stage) {
                if self.late {
                    self.expired.set(true);
                } else if self.refused {
                    return Ok(false);
                } else {
                    return Err("native peer unavailable".into());
                }
            }
            Ok(true)
        }
        fn remaining(&self) -> Result<Duration, String> {
            if self.expired.get() {
                Err("original deadline expired".into())
            } else {
                Ok(Duration::from_millis(10))
            }
        }
    }
    impl Port for Fixture {
        fn arm(&self) -> Result<bool, String> {
            self.call("arm")
        }
        fn ready(&self) -> Result<bool, String> {
            self.call("ready")
        }
        fn consume(&self) -> Result<bool, String> {
            self.call("consume")
        }
        fn cancel(&self) {
            self.calls.borrow_mut().push("cancel");
        }
    }
    fn fixture() -> Fixture {
        Fixture {
            calls: RefCell::new(vec![]),
            stage: None,
            refused: false,
            expired: Cell::new(false),
            late: false,
        }
    }
    #[test]
    fn only_a_consumed_fresh_choice_returns_without_cancelling() {
        let port = fixture();
        assert!(complete(&port, &|| port.remaining(), &|_| unreachable!()).is_ok());
        assert_eq!(*port.calls.borrow(), ["arm", "ready", "consume"]);
    }
    #[test]
    fn uncertain_denied_and_late_stages_cancel_exact_scope_without_advancing() {
        for stage in ["arm", "ready", "consume"] {
            for mode in 0..3 {
                let port = Fixture {
                    stage: Some(stage),
                    refused: mode == 1,
                    late: mode == 2,
                    ..fixture()
                };
                let result = complete(&port, &|| port.remaining(), &|_| port.expired.set(true));
                assert!(result.is_err());
                let calls = port.calls.borrow();
                assert_eq!(calls.last(), Some(&"cancel"));
                assert_eq!(calls.iter().filter(|s| **s == stage).count(), 1);
                if stage != "consume" {
                    assert!(!calls.contains(&"consume"));
                }
            }
        }
        let port = Fixture {
            expired: Cell::new(true),
            ..fixture()
        };
        assert!(complete(&port, &|| port.remaining(), &|_| unreachable!()).is_err());
        assert_eq!(*port.calls.borrow(), ["cancel"]);
    }
}
