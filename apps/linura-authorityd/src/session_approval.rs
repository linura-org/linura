//! Composition-root approval port. A native proof authorizes one canonical
//! challenge only; it never becomes an executor credential or durable secret.

use std::thread;
use std::time::{Duration, Instant};

use linura_control::{ManagedApprovalAuthorizer, ManagedApprovalChallenge, TrustedHumanApproval};
use linura_core::{PrincipalId, SessionLockId, SessionTransition, SessionTransitionId};
use linura_linux_session::{NativeApprovalPurpose, NativeApprovalRequest, NativeSessionChannel};
use linura_provider_sdk::ComponentDigest;

const INTERACTION_BUDGET: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub(crate) struct NativeSessionApprovalAuthorizer {
    pub(crate) channel: NativeSessionChannel,
    pub(crate) principal: PrincipalId,
}

impl ManagedApprovalAuthorizer for NativeSessionApprovalAuthorizer {
    fn authorize(
        &self,
        challenge: &ManagedApprovalChallenge,
    ) -> Result<TrustedHumanApproval, String> {
        if challenge.principal() != &self.principal {
            return Err("native approval challenge has another principal or purpose".into());
        }
        let (lock, transition, purpose) = match (challenge.change_key(), challenge.desired_value())
        {
            ("protective_lock.enabled", desired @ ("true" | "false")) => {
                if challenge.approval_class()
                    != linura_control::ManagedApprovalClass::SessionOwnerAuthentication
                {
                    return Err(
                        "protective-lock setting requires exact owner authentication".into(),
                    );
                }
                (
                    SessionLockId::from_resource(challenge.resource())
                        .map_err(|e| e.to_string())?,
                    None,
                    if desired == "true" {
                        NativeApprovalPurpose::EnableProtectiveLock
                    } else {
                        NativeApprovalPurpose::RevokeProtectiveLock
                    },
                )
            }
            ("secure", desired @ ("true" | "false")) => {
                let expected = if desired == "true" {
                    linura_control::ManagedApprovalClass::InteractiveUser
                } else {
                    linura_control::ManagedApprovalClass::SessionOwnerAuthentication
                };
                if challenge.approval_class() != expected {
                    return Err("native lock approval class mismatch".into());
                }
                (
                    SessionLockId::from_resource(challenge.resource())
                        .map_err(|e| e.to_string())?,
                    None,
                    if desired == "true" {
                        NativeApprovalPurpose::Lock
                    } else {
                        NativeApprovalPurpose::Unlock
                    },
                )
            }
            ("completed", "true") => {
                let target = SessionTransitionId::from_resource(challenge.resource())
                    .map_err(|e| e.to_string())?;
                let purpose = match target.transition() {
                    SessionTransition::Suspend { .. } => NativeApprovalPurpose::Suspend,
                    SessionTransition::Logout => NativeApprovalPurpose::Logout,
                    SessionTransition::Reboot => NativeApprovalPurpose::Reboot,
                    SessionTransition::PowerOff => NativeApprovalPurpose::PowerOff,
                };
                let expected = if purpose == NativeApprovalPurpose::Suspend {
                    linura_control::ManagedApprovalClass::Administrator
                } else {
                    linura_control::ManagedApprovalClass::DestructiveAction
                };
                if challenge.approval_class() != expected {
                    return Err("native power approval class mismatch".into());
                }
                (target.lock().clone(), Some(target), purpose)
            }
            _ => return Err("native approval desired state is unsupported".into()),
        };
        let request = NativeApprovalRequest {
            transition,
            lock,
            principal: challenge.principal().clone(),
            request: challenge.request_id().clone(),
            plan: challenge.plan_id().clone(),
            request_digest: digest(challenge.request_digest())?,
            observation_digest: digest(challenge.observation_digest())?,
            review_digest: digest(challenge.review_digest())?,
            purpose,
        };
        let port = ProductionApprovalPort {
            channel: &self.channel,
        };
        complete_native_approval(&port, &request, INTERACTION_BUDGET)?;
        Ok(TrustedHumanApproval::from_authorized_challenge(
            self.principal.clone(),
            challenge,
        ))
    }
}

fn digest(value: &str) -> Result<ComponentDigest, String> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or("native challenge digest has the wrong domain")?;
    if hex
        .bytes()
        .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err("native challenge digest is noncanonical".into());
    }
    ComponentDigest::parse_hex(hex).map_err(|e| e.to_string())
}

trait NativeApprovalPort {
    fn arm(&self, request: &NativeApprovalRequest) -> Result<bool, String>;
    fn authenticate(
        &self,
        request: &NativeApprovalRequest,
        started: Instant,
        budget: Duration,
    ) -> Result<(), String>;
    fn consume(&self, request: &NativeApprovalRequest) -> Result<bool, String>;
    fn cancel(&self, uid: u32);
}

struct CancelPending<'a, P: NativeApprovalPort> {
    port: &'a P,
    uid: u32,
    consumed: bool,
}
impl<P: NativeApprovalPort> Drop for CancelPending<'_, P> {
    fn drop(&mut self) {
        if !self.consumed {
            self.port.cancel(self.uid);
        }
    }
}

fn complete_native_approval<P: NativeApprovalPort>(
    port: &P,
    request: &NativeApprovalRequest,
    budget: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    complete_native_approval_bounded(port, request, budget, started, &|| started.elapsed())
}

fn complete_native_approval_bounded<P: NativeApprovalPort>(
    port: &P,
    request: &NativeApprovalRequest,
    budget: Duration,
    started: Instant,
    elapsed: &impl Fn() -> Duration,
) -> Result<(), String> {
    // Even an uncertain ArmApproval reply must cancel any possibly armed scope.
    let mut pending = CancelPending {
        port,
        uid: request.lock.epoch().uid(),
        consumed: false,
    };
    if !port.arm(request)? {
        return Err("native owner refused the scoped interaction".into());
    }
    if elapsed() >= budget {
        return Err("native approval expired before interaction".into());
    }
    if request.purpose != NativeApprovalPurpose::Lock {
        port.authenticate(request, started, budget)?;
        // No polling a positive permission into proof: PAM must have produced
        // the exact native confirmation by the time the authorization finishes.
        if elapsed() >= budget || !port.consume(request)? {
            return Err("native owner did not prove fresh purpose-bound authentication".into());
        }
    } else {
        loop {
            if elapsed() >= budget {
                return Err("native confirmation expired".into());
            }
            if port.consume(request)? {
                break;
            }
            thread::sleep(POLL.min(budget.saturating_sub(elapsed())));
        }
    }
    // Consuming the native proof crosses a bounded transport/attestation call.
    // A valid proof sampled before expiry cannot renew the original request
    // deadline when its reply arrives late. Discard it without authorizing an
    // effect; cancellation is safe even when the native proof was consumed.
    if elapsed() >= budget {
        return Err("native approval proof arrived after its original deadline".into());
    }
    pending.consumed = true;
    Ok(())
}

struct ProductionApprovalPort<'a> {
    channel: &'a NativeSessionChannel,
}
impl NativeApprovalPort for ProductionApprovalPort<'_> {
    fn arm(&self, request: &NativeApprovalRequest) -> Result<bool, String> {
        self.channel.arm_approval(request)
    }
    fn consume(&self, request: &NativeApprovalRequest) -> Result<bool, String> {
        self.channel.consume_approval(request)
    }
    fn cancel(&self, uid: u32) {
        let _denied_or_cancelled = self.channel.cancel_approval(uid);
    }
    fn authenticate(
        &self,
        request: &NativeApprovalRequest,
        started: Instant,
        budget: Duration,
    ) -> Result<(), String> {
        self.channel
            .authenticate_approval(request, budget.saturating_sub(started.elapsed()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    struct Port {
        armed: bool,
        authenticated: bool,
        proof: bool,
        cancelled: Cell<bool>,
        authentications: Cell<u32>,
        consumes: Cell<u32>,
    }
    impl NativeApprovalPort for Port {
        fn arm(&self, _: &NativeApprovalRequest) -> Result<bool, String> {
            Ok(self.armed)
        }
        fn authenticate(
            &self,
            _: &NativeApprovalRequest,
            _: Instant,
            _: Duration,
        ) -> Result<(), String> {
            self.authentications.set(self.authentications.get() + 1);
            if self.authenticated {
                Ok(())
            } else {
                Err("denied".into())
            }
        }
        fn consume(&self, _: &NativeApprovalRequest) -> Result<bool, String> {
            self.consumes.set(self.consumes.get() + 1);
            Ok(self.proof)
        }
        fn cancel(&self, _: u32) {
            self.cancelled.set(true);
        }
    }
    fn request(purpose: NativeApprovalPurpose) -> NativeApprovalRequest {
        let lock = SessionLockId::from_resource(&linura_core::ResourceId::new("session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:98765432-1234-4567-89ab-0123456789ab:7").unwrap_or_else(|e| unreachable!("{e}"))).unwrap_or_else(|e| unreachable!("{e}"));
        NativeApprovalRequest {
            transition: None,
            lock,
            principal: PrincipalId::new("unix:uid:1000").unwrap_or_else(|e| unreachable!("{e}")),
            request: linura_core::RequestId::new("request:v010:session-lock:test")
                .unwrap_or_else(|e| unreachable!("{e}")),
            plan: linura_core::PlanId::new("request:v010:session-lock:test")
                .unwrap_or_else(|e| unreachable!("{e}")),
            request_digest: ComponentDigest::from_bytes([1; 32]),
            observation_digest: ComponentDigest::from_bytes([2; 32]),
            review_digest: ComponentDigest::from_bytes([3; 32]),
            purpose,
        }
    }
    #[test]
    fn permission_without_native_proof_is_denied_and_cancelled() {
        let port = Port {
            armed: true,
            authenticated: true,
            proof: false,
            cancelled: Cell::new(false),
            authentications: Cell::new(0),
            consumes: Cell::new(0),
        };
        assert!(
            complete_native_approval(
                &port,
                &request(NativeApprovalPurpose::Unlock),
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(port.cancelled.get());
        assert_eq!(port.consumes.get(), 1);
    }
    #[test]
    fn failed_authentication_never_consumes_native_proof() {
        let port = Port {
            armed: true,
            authenticated: false,
            proof: true,
            cancelled: Cell::new(false),
            authentications: Cell::new(0),
            consumes: Cell::new(0),
        };
        assert!(
            complete_native_approval(
                &port,
                &request(NativeApprovalPurpose::Unlock),
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert!(port.cancelled.get());
        assert_eq!(port.consumes.get(), 0);
    }
    #[test]
    fn lock_uses_confirmation_only_and_expired_scope_is_cancelled() {
        let port = Port {
            armed: true,
            authenticated: false,
            proof: true,
            cancelled: Cell::new(false),
            authentications: Cell::new(0),
            consumes: Cell::new(0),
        };
        assert!(
            complete_native_approval(
                &port,
                &request(NativeApprovalPurpose::Lock),
                Duration::from_secs(1)
            )
            .is_ok()
        );
        assert_eq!(port.authentications.get(), 0);
        assert!(!port.cancelled.get());
        assert!(
            complete_native_approval(&port, &request(NativeApprovalPurpose::Lock), Duration::ZERO)
                .is_err()
        );
        assert!(port.cancelled.get());
    }
    #[test]
    fn authentication_digests_cannot_accept_recovery_placeholders_or_aliases() {
        assert!(digest("sha256:ABC").is_err());
        assert!(digest("recovery:fresh-control-revalidation-required").is_err());
    }
    #[test]
    fn late_native_proof_reply_cannot_renew_confirmation_or_authentication_budget() {
        for purpose in [NativeApprovalPurpose::Lock, NativeApprovalPurpose::Unlock] {
            let port = Port {
                armed: true,
                authenticated: true,
                proof: true,
                cancelled: Cell::new(false),
                authentications: Cell::new(0),
                consumes: Cell::new(0),
            };
            let samples = Cell::new(0_u32);
            let elapsed = || {
                let sample = samples.get();
                samples.set(sample + 1);
                if sample < 2 {
                    Duration::ZERO
                } else {
                    Duration::from_secs(1)
                }
            };
            assert!(
                complete_native_approval_bounded(
                    &port,
                    &request(purpose),
                    Duration::from_secs(1),
                    Instant::now(),
                    &elapsed,
                )
                .is_err()
            );
            assert_eq!(port.consumes.get(), 1);
            assert!(port.cancelled.get());
            assert_eq!(
                port.authentications.get(),
                u32::from(purpose != NativeApprovalPurpose::Lock)
            );
        }
    }
}
