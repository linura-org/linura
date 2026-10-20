#![forbid(unsafe_code)]
//! Narrow prepared session effector. No planner, policy, durable store,
//! generic command, authentication response or caller-selected principal.

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use linura_core::{ProviderId, ResourceId, SessionLockId, SessionTransitionId};
use linura_linux_session::{NativeSessionChannel, NativeSessionRole};
use linura_provider_sdk::{
    ComponentDigest, EffectDescriptor, ExecutionBinding, ExecutionDisposition,
};
use zbus::message::Header;

mod introspection;

const ACTION: &str = "org.linura.executor.session.set-secure";
const TRANSITION_ACTION: &str = "org.linura.executor.session.execute-transition";
const OBJECT_PATH: &str = "/org/linura/Executor/Session1";
pub const INTERFACE_NAME: &str = "org.linura.Executor.Session1";
type OutcomeWire = (String, String, String);

pub fn lock_effect(lock: &SessionLockId, secure: bool) -> Result<EffectDescriptor, String> {
    if lock.epoch().uid() == 0 {
        return Err("root graphical sessions are unsupported".into());
    }
    let resource = lock.resource_id().map_err(|e| e.to_string())?;
    EffectDescriptor::new(
        ProviderId::new("session-locker").map_err(|e| e.to_string())?,
        resource.clone(),
        "set-secure",
        format!("lock={}\nsecure={secure}\n", resource.as_str()).into_bytes(),
    )
    .map_err(|e| e.to_string())
}

pub fn transition_effect(target: &SessionTransitionId) -> Result<EffectDescriptor, String> {
    let resource = target.resource_id().map_err(|e| e.to_string())?;
    EffectDescriptor::new(
        ProviderId::new("logind").map_err(|e| e.to_string())?,
        resource.clone(),
        "execute-session-transition",
        format!("transition={}\n", resource.as_str()).into_bytes(),
    )
    .map_err(|e| e.to_string())
}

// Private mechanism seam also permits denial-only component fixtures without
// creating a fake trusted system bus or weakening NativeSessionChannel.
trait SessionDispatch: Clone + Send + Sync + 'static {
    fn require_control(&self, sender: &str) -> Result<(), String>;
    fn dispatch(&self, lock: &SessionLockId, secure: bool) -> Result<bool, String>;
    fn transition(&self, target: &SessionTransitionId) -> Result<bool, String>;
}
impl SessionDispatch for NativeSessionChannel {
    fn require_control(&self, sender: &str) -> Result<(), String> {
        self.require_trusted_control_sender(sender)
    }
    fn dispatch(&self, lock: &SessionLockId, secure: bool) -> Result<bool, String> {
        self.dispatch_prepared_lock(lock, secure)
    }
    fn transition(&self, target: &SessionTransitionId) -> Result<bool, String> {
        self.dispatch_prepared_transition(target)
    }
}

#[derive(Debug)]
struct SessionExecutor<C: SessionDispatch> {
    channel: C,
}

#[zbus::interface(name = "org.linura.Executor.Session1")]
impl<C: SessionDispatch> SessionExecutor<C> {
    #[allow(clippy::too_many_arguments)]
    #[zbus(out_args("outcome"))]
    async fn set_secure(
        &self,
        resource: &str,
        secure: bool,
        transaction_id: &str,
        generation: u64,
        state_version: u64,
        authority_binding_digest: &str,
        authority_use_digest: &str,
        effect_digest: &str,
        dispatch_digest: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(OutcomeWire,)> {
        let sender = header
            .sender()
            .ok_or_else(|| {
                zbus::fdo::Error::AccessDenied(
                    "session executor call has no authenticated sender".into(),
                )
            })?
            .as_str()
            .to_owned();
        if resource.len() > 256
            || transaction_id.len() > 256
            || [
                authority_binding_digest,
                authority_use_digest,
                effect_digest,
                dispatch_digest,
            ]
            .iter()
            .any(|value| value.len() != 64)
        {
            return Err(zbus::fdo::Error::InvalidArgs(
                "session executor request exceeds its bound".into(),
            ));
        }
        let lock = SessionLockId::from_resource(
            &ResourceId::new(resource).map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?,
        )
        .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        let parse = |value| {
            ComponentDigest::parse_hex(value)
                .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))
        };
        let binding = ExecutionBinding {
            transaction_id: transaction_id.into(),
            generation,
            state_version,
            authority_binding_digest: parse(authority_binding_digest)?,
            authority_use_digest: parse(authority_use_digest)?,
            effect_digest: parse(effect_digest)?,
            dispatch_digest: parse(dispatch_digest)?,
        };
        let effect = lock_effect(&lock, secure).map_err(zbus::fdo::Error::InvalidArgs)?;
        binding
            .validate_for(&effect)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        let channel = self.channel.clone();
        blocking::unblock(move || {
            channel
                .require_control(&sender)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            authorize_service(&sender, false).map_err(zbus::fdo::Error::AccessDenied)?;
            channel
                .require_control(&sender)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            // Never retry on timeout or fault: Control persisted ambiguity
            // before this handoff. The native protocol gates its generation
            // and refuses duplicated acquisition/release independently.
            let (disposition, detail) = match channel.dispatch(&lock, secure) {
                Ok(true) => (
                    ExecutionDisposition::Dispatched,
                    "native lock dispatch accepted; independent verification required",
                ),
                Ok(false) => (
                    ExecutionDisposition::RejectedBeforeDispatch,
                    "native lock precondition refused dispatch",
                ),
                Err(_) => (
                    ExecutionDisposition::Indeterminate,
                    "native lock transport outcome is indeterminate; no retry attempted",
                ),
            };
            let disposition = match disposition {
                ExecutionDisposition::Dispatched => "dispatched",
                ExecutionDisposition::RejectedBeforeDispatch => "rejected-before-dispatch",
                ExecutionDisposition::Indeterminate => "indeterminate",
            };
            Ok(((
                disposition.into(),
                binding.dispatch_digest.to_hex(),
                detail.into(),
            ),))
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    #[zbus(out_args("outcome"))]
    async fn execute_transition(
        &self,
        resource: &str,
        transaction_id: &str,
        generation: u64,
        state_version: u64,
        authority_binding_digest: &str,
        authority_use_digest: &str,
        effect_digest: &str,
        dispatch_digest: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(OutcomeWire,)> {
        let sender = header
            .sender()
            .ok_or_else(|| {
                zbus::fdo::Error::AccessDenied(
                    "session executor call has no authenticated sender".into(),
                )
            })?
            .as_str()
            .to_owned();
        if resource.len() > 256
            || transaction_id.len() > 256
            || [
                authority_binding_digest,
                authority_use_digest,
                effect_digest,
                dispatch_digest,
            ]
            .iter()
            .any(|value| value.len() != 64)
        {
            return Err(zbus::fdo::Error::InvalidArgs(
                "session transition request exceeds its bound".into(),
            ));
        }
        let target = SessionTransitionId::from_resource(
            &ResourceId::new(resource).map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?,
        )
        .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        let parse = |value| {
            ComponentDigest::parse_hex(value)
                .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))
        };
        let binding = ExecutionBinding {
            transaction_id: transaction_id.into(),
            generation,
            state_version,
            authority_binding_digest: parse(authority_binding_digest)?,
            authority_use_digest: parse(authority_use_digest)?,
            effect_digest: parse(effect_digest)?,
            dispatch_digest: parse(dispatch_digest)?,
        };
        let effect = transition_effect(&target).map_err(zbus::fdo::Error::InvalidArgs)?;
        binding
            .validate_for(&effect)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        let channel = self.channel.clone();
        blocking::unblock(move || {
            channel
                .require_control(&sender)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            authorize_service(&sender, true).map_err(zbus::fdo::Error::AccessDenied)?;
            channel
                .require_control(&sender)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            let (disposition, detail) = match channel.transition(&target) {
                Ok(true) => (
                    "dispatched",
                    "native transition accepted; independent verification required",
                ),
                Ok(false) => (
                    "rejected-before-dispatch",
                    "native transition precondition refused dispatch",
                ),
                Err(_) => (
                    "indeterminate",
                    "native transition outcome is indeterminate; no retry attempted",
                ),
            };
            Ok(((
                disposition.into(),
                binding.dispatch_digest.to_hex(),
                detail.into(),
            ),))
        })
        .await
    }
}

fn authorize_service(sender: &str, transition: bool) -> Result<(), String> {
    let mut child = Command::new("/usr/bin/pkcheck")
        .args(if transition {
            [
                "--action-id",
                TRANSITION_ACTION,
                "--system-bus-name",
                sender,
            ]
        } else {
            ["--action-id", ACTION, "--system-bus-name", sender]
        })
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(
            "DBUS_SYSTEM_BUS_ADDRESS",
            "unix:path=/run/dbus/system_bus_socket",
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "session executor policy service is unavailable".to_owned())?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err("session executor service authorization denied".into())
                };
            }
            Ok(None) if started.elapsed() < Duration::from_secs(2) => {
                thread::sleep(Duration::from_millis(10))
            }
            _ => {
                let _killed = child.kill();
                let _reaped = child.wait();
                return Err("session executor service authorization failed or timed out".into());
            }
        }
    }
}

pub fn serve() -> Result<(), String> {
    let channel = NativeSessionChannel::connect(NativeSessionRole::Executor)?;
    let connection = channel.service_connection();
    let service = introspection::SessionContract(SessionExecutor { channel });
    connection
        .object_server()
        .at(OBJECT_PATH, service)
        .map_err(|e| e.to_string())?;
    loop {
        thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::object_server::Interface;

    #[derive(Clone, Debug)]
    struct DenyNative;
    impl SessionDispatch for DenyNative {
        fn require_control(&self, _: &str) -> Result<(), String> {
            Err("component fixture has no trusted Control".into())
        }
        fn dispatch(&self, _: &SessionLockId, _: bool) -> Result<bool, String> {
            unreachable!("untrusted calls must never dispatch")
        }
        fn transition(&self, _: &SessionTransitionId) -> Result<bool, String> {
            unreachable!("untrusted calls must never dispatch a transition")
        }
    }

    #[test]
    fn untrusted_caller_with_valid_binding_cannot_dispatch_power_or_invoke_policy() {
        let target = SessionTransitionId::from_resource(&ResourceId::new("session:transition:reboot:0:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:98765432-1234-4567-89ab-0123456789ab:7")
            .unwrap_or_else(|e| unreachable!("{e}"))).unwrap_or_else(|e| unreachable!("{e}"));
        let effect = transition_effect(&target).unwrap_or_else(|e| unreachable!("{e}"));
        let binding = ExecutionBinding::new(
            "transaction:test",
            0,
            1,
            ComponentDigest::from_bytes([1; 32]),
            ComponentDigest::from_bytes([2; 32]),
            &effect,
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        let message = zbus::Message::method_call(OBJECT_PATH, "ExecuteTransition")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .sender(":1.7")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .build(&())
            .unwrap_or_else(|e| unreachable!("{e}"));
        let service = SessionExecutor {
            channel: DenyNative,
        };
        let resource = target.resource_id().unwrap_or_else(|e| unreachable!("{e}"));
        let result = async_io::block_on(service.execute_transition(
            resource.as_str(),
            &binding.transaction_id,
            binding.generation,
            binding.state_version,
            &binding.authority_binding_digest.to_hex(),
            &binding.authority_use_digest.to_hex(),
            &binding.effect_digest.to_hex(),
            &binding.dispatch_digest.to_hex(),
            message.header(),
        ));
        assert!(matches!(result, Err(zbus::fdo::Error::AccessDenied(_))));
    }

    #[test]
    fn actual_service_introspection_matches_canonical_contract() {
        let service = introspection::SessionContract(SessionExecutor {
            channel: DenyNative,
        });
        let mut live = String::new();
        service.introspect_to_writer(&mut live, 0);
        let canonical = include_str!("../../../interfaces/dbus/org.linura.Executor.Session1.xml");
        for name in [
            "org.linura.ContractId",
            "org.linura.ContractVersion",
            "org.linura.Stability",
        ] {
            let marker = format!("name=\"{name}\"");
            assert_eq!(live.matches(&marker).count(), 1);
            assert_eq!(canonical.matches(&marker).count(), 1);
        }
        assert_eq!(live.matches("<method ").count(), 2);
        assert_eq!(canonical.matches("<method ").count(), 2);
        for (name, kind, direction) in [
            ("resource", "s", "in"),
            ("secure", "b", "in"),
            ("transaction_id", "s", "in"),
            ("generation", "t", "in"),
            ("state_version", "t", "in"),
            ("authority_binding_digest", "s", "in"),
            ("authority_use_digest", "s", "in"),
            ("effect_digest", "s", "in"),
            ("dispatch_digest", "s", "in"),
            ("outcome", "(sss)", "out"),
        ] {
            let marker = format!("name=\"{name}\" type=\"{kind}\" direction=\"{direction}\"");
            let expected = if name == "secure" { 1 } else { 2 };
            assert_eq!(live.matches(&marker).count(), expected, "live {name}");
            assert_eq!(
                canonical.matches(&marker).count(),
                expected,
                "canonical {name}"
            );
        }
        assert!(live.contains("<method name=\"SetSecure\">"));
        assert!(live.contains("<method name=\"ExecuteTransition\">"));
    }
    #[test]
    fn canonical_effect_is_exact_and_cannot_target_another_generation() {
        let resource = ResourceId::new("session:lock:abcd1234-1234-4567-89ab-0123456789ab:1000:c2:42:98765432-1234-4567-89ab-0123456789ab:7").unwrap_or_else(|e| unreachable!("{e}"));
        let lock = SessionLockId::from_resource(&resource).unwrap_or_else(|e| unreachable!("{e}"));
        let effect = lock_effect(&lock, true).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(effect.operation, "set-secure");
        assert_eq!(effect.provider.as_str(), "session-locker");
        let binding = ExecutionBinding::new(
            "transaction:test",
            0,
            1,
            ComponentDigest::from_bytes([1; 32]),
            ComponentDigest::from_bytes([2; 32]),
            &effect,
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(
            binding
                .validate_for(&lock_effect(&lock, false).unwrap_or_else(|e| unreachable!("{e}")))
                .is_err()
        );
        let next = SessionLockId::new(
            lock.epoch().clone(),
            lock.security_owner_invocation().clone(),
            8,
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(
            binding
                .validate_for(&lock_effect(&next, true).unwrap_or_else(|e| unreachable!("{e}")))
                .is_err()
        );
    }
}
