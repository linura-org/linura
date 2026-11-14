#![forbid(unsafe_code)]
//! Narrow prepared session effector. No planner, policy, authority journal,
//! generic command, authentication response or caller-selected principal.

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use linura_core::{ProviderId, ResourceId, SessionLockId, SessionTransitionId};
use linura_linux_session::{NativeDisplayContinuation, NativeSessionChannel, NativeSessionRole};
use linura_provider_sdk::{
    ComponentDigest, EffectDescriptor, ExecutionBinding, ExecutionDisposition,
};
use zbus::message::Header;

mod display_checkpoint;
mod display_completion_grant;
mod display_finalization_grant;
mod display_kernel;
mod display_native_release_grant;
mod display_protection_service;
mod introspection;
mod native_message;
mod protection_lock;

const ACTION: &str = "org.linura.executor.session.set-secure";
const TRANSITION_ACTION: &str = "org.linura.executor.session.execute-transition";
const DISPLAY_ACTION: &str = "org.linura.executor.session.apply-display-layout";
const ORIGINAL_DISPLAY_ACTION: &str = "org.linura.executor.session.restore-original-display-layout";
const FINALIZATION_DISPLAY_ACTION: &str =
    "org.linura.executor.session.quiesce-original-display-finalization";
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
    fn display(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
        native_baseline_guard: &ComponentDigest,
    ) -> Result<u32, String>;
    fn display_successor(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
        native_baseline_guard: &ComponentDigest,
        predecessor: &linura_core::DisplayRecoveryScope,
    ) -> Result<u32, String>;
    fn restore_original(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
    ) -> Result<u32, String>;
    fn finalize_original(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
    ) -> Result<u32, String>;
    fn continue_display(&self, continuation: &NativeDisplayContinuation) -> Result<u32, String>;
}
#[derive(Clone, Debug)]
struct NativeSessionDispatch {
    channel: NativeSessionChannel,
}
impl SessionDispatch for NativeSessionDispatch {
    fn display_successor(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
        native_baseline_guard: &ComponentDigest,
        predecessor: &linura_core::DisplayRecoveryScope,
    ) -> Result<u32, String> {
        self.channel
            .begin_display_protection(&binding.dispatch_digest)?;
        let result = self.channel.dispatch_prepared_successor_display(
            material,
            binding,
            deadline_unix_ms,
            native_baseline_guard,
            predecessor,
        );
        self.channel
            .verify_display_protection(&binding.dispatch_digest)?;
        result
    }
    fn finalize_original(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
    ) -> Result<u32, String> {
        self.channel
            .dispatch_original_display_finalization(material, binding, deadline_unix_ms)
    }
    fn restore_original(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
    ) -> Result<u32, String> {
        self.channel
            .dispatch_original_display_restoration(material, binding, deadline_unix_ms)
    }

    fn continue_display(&self, continuation: &NativeDisplayContinuation) -> Result<u32, String> {
        self.channel
            .verify_display_protection(continuation.dispatch_digest())?;
        let result = self.channel.dispatch_display_continuation(continuation);
        self.channel
            .verify_display_protection(continuation.dispatch_digest())?;
        result
    }
    fn require_control(&self, sender: &str) -> Result<(), String> {
        self.channel.require_trusted_control_sender(sender)
    }
    fn dispatch(&self, lock: &SessionLockId, secure: bool) -> Result<bool, String> {
        self.channel.dispatch_prepared_lock(lock, secure)
    }
    fn transition(&self, target: &SessionTransitionId) -> Result<bool, String> {
        self.channel.dispatch_prepared_transition(target)
    }
    fn display(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
        native_baseline_guard: &ComponentDigest,
    ) -> Result<u32, String> {
        // Subscription must precede native baseline sampling. Capturing a new
        // subscription after compositor death cannot replace this lifetime.
        self.channel
            .begin_display_protection(&binding.dispatch_digest)?;
        let result = self.channel.dispatch_prepared_display(
            material,
            binding,
            deadline_unix_ms,
            native_baseline_guard,
            |record| self.channel.reserve_display_protection(record),
        );
        self.channel
            .verify_display_protection(&binding.dispatch_digest)?;
        result
    }
}

#[derive(Debug)]
struct SessionExecutor<C: SessionDispatch> {
    channel: C,
}

#[zbus::interface(name = "org.linura.Executor.Session1")]
impl<C: SessionDispatch> SessionExecutor<C> {
    #[allow(clippy::too_many_arguments)]
    #[zbus(out_args("phase"))]
    async fn continue_display_layout(
        &self,
        material: &str,
        transaction_id: &str,
        dispatch_digest: &str,
        deadline_unix_ms: u64,
        decision_digest: &str,
        protected_decision_digest: &str,
        confirm: bool,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<u32> {
        let sender = header
            .sender()
            .ok_or_else(|| {
                zbus::fdo::Error::AccessDenied(
                    "display decision has no authenticated sender".into(),
                )
            })?
            .as_str()
            .to_owned();
        // These are comparison hashes, never a policy/prepare bypass. The
        // native reservation independently binds the exact original effect.
        let parse = |value: &str| {
            ComponentDigest::parse_hex(value)
                .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))
        };
        let continuation = NativeDisplayContinuation::new(
            material,
            transaction_id,
            parse(dispatch_digest)?,
            deadline_unix_ms,
            parse(decision_digest)?,
            parse(protected_decision_digest)?,
            confirm,
        )
        .map_err(zbus::fdo::Error::InvalidArgs)?;
        let channel = self.channel.clone();
        blocking::unblock(move || {
            channel
                .require_control(&sender)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            authorize_service(&sender, ServiceAction::Display)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            channel
                .require_control(&sender)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            channel.continue_display(&continuation).map_err(|_| {
                zbus::fdo::Error::Failed(
                    "native display decision outcome is indeterminate; no retry".into(),
                )
            })
        })
        .await
    }

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
            authorize_service(&sender, ServiceAction::Lock)
                .map_err(zbus::fdo::Error::AccessDenied)?;
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
            authorize_service(&sender, ServiceAction::Transition)
                .map_err(zbus::fdo::Error::AccessDenied)?;
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
    #[allow(clippy::too_many_arguments)]
    #[zbus(out_args("outcome"))]
    async fn apply_display_layout(
        &self,
        material: &str,
        deadline_unix_ms: u64,
        transaction_id: &str,
        generation: u64,
        state_version: u64,
        authority_binding_digest: &str,
        authority_use_digest: &str,
        effect_digest: &str,
        dispatch_digest: &str,
        native_baseline_guard: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(OutcomeWire,)> {
        let sender = header
            .sender()
            .ok_or_else(|| {
                zbus::fdo::Error::AccessDenied(
                    "display executor call has no authenticated sender".into(),
                )
            })?
            .as_str()
            .to_owned();
        if material.len() > linura_core::MAX_DISPLAY_INTENT_BYTES
            || transaction_id.len() > 256
            || [
                authority_binding_digest,
                authority_use_digest,
                effect_digest,
                dispatch_digest,
                native_baseline_guard,
            ]
            .iter()
            .any(|value| value.len() != 64)
        {
            return Err(zbus::fdo::Error::InvalidArgs(
                "display executor request exceeds its bound".into(),
            ));
        }
        let effect = linura_provider_sdk::display_layout_effect(material)
            .map_err(zbus::fdo::Error::InvalidArgs)?;
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
        binding
            .validate_for(&effect)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        let material = material.to_owned();
        let native_baseline_guard = parse(native_baseline_guard)?;
        let channel = self.channel.clone();
        blocking::unblock(move || {
            channel
                .require_control(&sender)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            authorize_service(&sender, ServiceAction::Display)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            channel
                .require_control(&sender)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            // The bounded native adapter independently validates full metadata,
            // preserves its original sample time/owner and makes ONE apply.
            // Any uncertain result remains durable ambiguity, with no retry.
            let (disposition, detail) = display_disposition(channel.display(
                &material,
                &binding,
                deadline_unix_ms,
                &native_baseline_guard,
            ));
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
    async fn apply_successor_display_layout(
        &self,
        material: &str,
        predecessor_scope: &str,
        deadline_unix_ms: u64,
        transaction_id: &str,
        generation: u64,
        state_version: u64,
        authority_binding_digest: &str,
        authority_use_digest: &str,
        effect_digest: &str,
        dispatch_digest: &str,
        native_baseline_guard: &str,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<(OutcomeWire,)> {
        let sender = header
            .sender()
            .ok_or_else(|| {
                zbus::fdo::Error::AccessDenied(
                    "display executor call has no authenticated sender".into(),
                )
            })?
            .as_str()
            .to_owned();
        if predecessor_scope.len() > 256
            || material.len() > linura_core::MAX_DISPLAY_INTENT_BYTES
            || transaction_id.len() > 256
            || [
                authority_binding_digest,
                authority_use_digest,
                effect_digest,
                dispatch_digest,
                native_baseline_guard,
            ]
            .iter()
            .any(|value| value.len() != 64)
        {
            return Err(zbus::fdo::Error::InvalidArgs(
                "display executor request exceeds its bound".into(),
            ));
        }
        let effect = linura_provider_sdk::display_layout_effect(material)
            .map_err(zbus::fdo::Error::InvalidArgs)?;
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
        binding
            .validate_for(&effect)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        let predecessor = linura_core::DisplayRecoveryScope::from_resource(
            &ResourceId::new(predecessor_scope)
                .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?,
        )
        .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        let layout = linura_core::DisplayLayoutMaterial::decode(material)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        if layout.topology() != predecessor.replacement() {
            return Err(zbus::fdo::Error::InvalidArgs(
                "successor scope differs from the prepared layout".into(),
            ));
        }
        let material = material.to_owned();
        let native_baseline_guard = parse(native_baseline_guard)?;
        let channel = self.channel.clone();
        blocking::unblock(move || {
            channel
                .require_control(&sender)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            authorize_service(&sender, ServiceAction::Display)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            channel
                .require_control(&sender)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            // The bounded native adapter independently validates full metadata,
            // preserves its original sample time/owner and makes ONE apply.
            // Any uncertain result remains durable ambiguity, with no retry.
            let (disposition, detail) = display_disposition(channel.display_successor(
                &material,
                &binding,
                deadline_unix_ms,
                &native_baseline_guard,
                &predecessor,
            ));
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
    async fn restore_original_display_layout(
        &self,
        material: &str,
        deadline_unix_ms: u64,
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
                    "display executor call has no authenticated sender".into(),
                )
            })?
            .as_str()
            .to_owned();
        if material.len() > linura_core::MAX_DISPLAY_RESTORATION_BYTES
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
                "display executor request exceeds its bound".into(),
            ));
        }
        let effect = linura_provider_sdk::display_restoration_effect(material)
            .map_err(zbus::fdo::Error::InvalidArgs)?;
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
        binding
            .validate_for(&effect)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        let material = material.to_owned();
        let channel = self.channel.clone();
        blocking::unblock(move || {
            channel
                .require_control(&sender)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            authorize_service(&sender, ServiceAction::OriginalDisplay)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            channel
                .require_control(&sender)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            // The bounded native adapter independently validates full metadata,
            // preserves its original sample time/owner and makes ONE restoration.
            // Any uncertain result remains durable ambiguity, with no retry.
            let (disposition, detail) = display_disposition(channel.restore_original(
                &material,
                &binding,
                deadline_unix_ms,
            ));
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
    async fn quiesce_original_display_finalization(
        &self,
        material: &str,
        deadline_unix_ms: u64,
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
                    "display executor call has no authenticated sender".into(),
                )
            })?
            .as_str()
            .to_owned();
        if material.len() > linura_core::MAX_DISPLAY_FINALIZATION_BYTES
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
                "display executor request exceeds its bound".into(),
            ));
        }
        let effect = linura_provider_sdk::display_finalization_effect(material)
            .map_err(zbus::fdo::Error::InvalidArgs)?;
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
        binding
            .validate_for(&effect)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(e.to_string()))?;
        let material = material.to_owned();
        let channel = self.channel.clone();
        blocking::unblock(move || {
            channel
                .require_control(&sender)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            authorize_service(&sender, ServiceAction::FinalizationDisplay)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            channel
                .require_control(&sender)
                .map_err(zbus::fdo::Error::AccessDenied)?;
            // The bounded native adapter independently validates full metadata,
            // preserves its original sample time/owner and attempts quiescence ONCE.
            // Any uncertain result remains durable ambiguity, with no retry.
            let (disposition, detail) = display_disposition(channel.finalize_original(
                &material,
                &binding,
                deadline_unix_ms,
            ));
            Ok(((
                disposition.into(),
                binding.dispatch_digest.to_hex(),
                detail.into(),
            ),))
        })
        .await
    }
}

fn display_disposition(phase: Result<u32, String>) -> (&'static str, &'static str) {
    match phase {
        Ok(1) => (
            "rejected-before-dispatch",
            "native display reservation refused before dispatch",
        ),
        Ok(2..=6) => (
            "dispatched",
            "native display attempt acknowledged; independent verification required",
        ),
        _ => (
            "indeterminate",
            "native display outcome is indeterminate; no retry attempted",
        ),
    }
}

enum ServiceAction {
    Lock,
    Transition,
    Display,
    OriginalDisplay,
    FinalizationDisplay,
}

fn authorize_service(sender: &str, action: ServiceAction) -> Result<(), String> {
    let mut child = Command::new("/usr/bin/pkcheck")
        .args(match action {
            ServiceAction::Lock => ["--action-id", ACTION, "--system-bus-name", sender],
            ServiceAction::Transition => [
                "--action-id",
                TRANSITION_ACTION,
                "--system-bus-name",
                sender,
            ],
            ServiceAction::Display => ["--action-id", DISPLAY_ACTION, "--system-bus-name", sender],
            ServiceAction::OriginalDisplay => [
                "--action-id",
                ORIGINAL_DISPLAY_ACTION,
                "--system-bus-name",
                sender,
            ],
            ServiceAction::FinalizationDisplay => [
                "--action-id",
                FINALIZATION_DISPLAY_ACTION,
                "--system-bus-name",
                sender,
            ],
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
    let service = introspection::SessionContract(SessionExecutor {
        channel: NativeSessionDispatch { channel },
    });
    connection
        .object_server()
        .at(OBJECT_PATH, service)
        .map_err(|e| e.to_string())?;
    loop {
        thread::park();
    }
}

/// Independently supervised protection mechanism entry point. It cannot dispatch
/// an output effect or authorize a managed operation.
pub fn serve_display_protection() -> Result<(), String> {
    display_protection_service::serve()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::object_server::Interface;

    #[derive(Clone, Debug)]
    struct DenyNative;
    impl SessionDispatch for DenyNative {
        fn display_successor(
            &self,
            _: &str,
            _: &ExecutionBinding,
            _: u64,
            _: &ComponentDigest,
            _: &linura_core::DisplayRecoveryScope,
        ) -> Result<u32, String> {
            unreachable!("untrusted calls must never transfer display ownership")
        }
        fn finalize_original(&self, _: &str, _: &ExecutionBinding, _: u64) -> Result<u32, String> {
            unreachable!("untrusted calls must never quiesce an original display restoration")
        }
        fn restore_original(&self, _: &str, _: &ExecutionBinding, _: u64) -> Result<u32, String> {
            unreachable!("untrusted calls must never restore an original display layout")
        }

        fn continue_display(&self, _: &NativeDisplayContinuation) -> Result<u32, String> {
            unreachable!("untrusted calls must never continue a display attempt")
        }
        fn require_control(&self, _: &str) -> Result<(), String> {
            Err("component fixture has no trusted Control".into())
        }
        fn dispatch(&self, _: &SessionLockId, _: bool) -> Result<bool, String> {
            unreachable!("untrusted calls must never dispatch")
        }
        fn transition(&self, _: &SessionTransitionId) -> Result<bool, String> {
            unreachable!("untrusted calls must never dispatch a transition")
        }
        fn display(
            &self,
            _: &str,
            _: &ExecutionBinding,
            _: u64,
            _: &ComponentDigest,
        ) -> Result<u32, String> {
            unreachable!("untrusted calls must never dispatch a display layout")
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
    fn original_restoration_binding_cannot_bypass_control_or_service_policy() {
        let material = include_str!(
            "../../../crates/linura-core/src/display_recovery/fixtures/original-baseline.txt"
        )
        .trim_end();
        let effect = linura_provider_sdk::display_restoration_effect(material)
            .unwrap_or_else(|_| unreachable!());
        let binding = ExecutionBinding::new(
            "transaction:original-test",
            0,
            1,
            ComponentDigest::from_bytes([1; 32]),
            ComponentDigest::from_bytes([2; 32]),
            &effect,
        )
        .unwrap_or_else(|_| unreachable!());
        let service = SessionExecutor {
            channel: DenyNative,
        };
        let call = |material: &str, effect: &str, message: &zbus::Message| {
            async_io::block_on(service.restore_original_display_layout(
                material,
                25_000,
                &binding.transaction_id,
                binding.generation,
                binding.state_version,
                &binding.authority_binding_digest.to_hex(),
                &binding.authority_use_digest.to_hex(),
                effect,
                &binding.dispatch_digest.to_hex(),
                message.header(),
            ))
        };
        let message = zbus::Message::method_call(OBJECT_PATH, "RestoreOriginalDisplayLayout")
            .unwrap_or_else(|_| unreachable!())
            .sender(":1.7")
            .unwrap_or_else(|_| unreachable!())
            .build(&())
            .unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            call(material, &binding.effect_digest.to_hex(), &message),
            Err(zbus::fdo::Error::AccessDenied(_))
        ));
        let anonymous = zbus::Message::method_call(OBJECT_PATH, "RestoreOriginalDisplayLayout")
            .unwrap_or_else(|_| unreachable!())
            .build(&())
            .unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            call(material, &binding.effect_digest.to_hex(), &anonymous),
            Err(zbus::fdo::Error::AccessDenied(_))
        ));
        for (material, digest) in [
            (material, "0".repeat(64)),
            ("LNDI:1;", binding.effect_digest.to_hex()),
        ] {
            assert!(matches!(
                call(material, &digest, &message),
                Err(zbus::fdo::Error::InvalidArgs(_))
            ));
        }
    }

    #[test]
    fn terminal_binding_cannot_bypass_control_or_service_policy() {
        let material = include_str!(
            "../../../crates/linura-core/src/display_recovery/fixtures/original-finalization.txt"
        )
        .trim_end();
        let effect = linura_provider_sdk::display_finalization_effect(material)
            .unwrap_or_else(|_| unreachable!());
        let binding = ExecutionBinding::new(
            "transaction:terminal-test",
            0,
            1,
            ComponentDigest::from_bytes([1; 32]),
            ComponentDigest::from_bytes([2; 32]),
            &effect,
        )
        .unwrap_or_else(|_| unreachable!());
        let service = SessionExecutor {
            channel: DenyNative,
        };
        let call = |material: &str, effect: &str, message: &zbus::Message| {
            async_io::block_on(service.quiesce_original_display_finalization(
                material,
                25_000,
                &binding.transaction_id,
                binding.generation,
                binding.state_version,
                &binding.authority_binding_digest.to_hex(),
                &binding.authority_use_digest.to_hex(),
                effect,
                &binding.dispatch_digest.to_hex(),
                message.header(),
            ))
        };
        let message = zbus::Message::method_call(OBJECT_PATH, "QuiesceOriginalDisplayFinalization")
            .unwrap_or_else(|_| unreachable!())
            .sender(":1.7")
            .unwrap_or_else(|_| unreachable!())
            .build(&())
            .unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            call(material, &binding.effect_digest.to_hex(), &message),
            Err(zbus::fdo::Error::AccessDenied(_))
        ));
        let anonymous =
            zbus::Message::method_call(OBJECT_PATH, "QuiesceOriginalDisplayFinalization")
                .unwrap_or_else(|_| unreachable!())
                .build(&())
                .unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            call(material, &binding.effect_digest.to_hex(), &anonymous),
            Err(zbus::fdo::Error::AccessDenied(_))
        ));
        for (material, digest) in [
            (material, "0".repeat(64)),
            ("LNDI:1;", binding.effect_digest.to_hex()),
        ] {
            assert!(matches!(
                call(material, &digest, &message),
                Err(zbus::fdo::Error::InvalidArgs(_))
            ));
        }
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
        assert_eq!(live.matches("<method ").count(), 7);
        assert_eq!(canonical.matches("<method ").count(), 7);
        for (name, kind, direction) in [
            ("resource", "s", "in"),
            ("material", "s", "in"),
            ("predecessor_scope", "s", "in"),
            ("deadline_unix_ms", "t", "in"),
            ("secure", "b", "in"),
            ("transaction_id", "s", "in"),
            ("generation", "t", "in"),
            ("state_version", "t", "in"),
            ("authority_binding_digest", "s", "in"),
            ("authority_use_digest", "s", "in"),
            ("effect_digest", "s", "in"),
            ("dispatch_digest", "s", "in"),
            ("outcome", "(sss)", "out"),
            ("decision_digest", "s", "in"),
            ("protected_decision_digest", "s", "in"),
            ("confirm", "b", "in"),
            ("phase", "u", "out"),
        ] {
            let marker = format!("name=\"{name}\" type=\"{kind}\" direction=\"{direction}\"");
            let expected = match name {
                "secure"
                | "decision_digest"
                | "protected_decision_digest"
                | "confirm"
                | "phase"
                | "predecessor_scope" => 1,
                "resource" => 2,
                "material" | "deadline_unix_ms" => 5,
                "transaction_id" | "dispatch_digest" => 7,
                _ => 6,
            };
            assert_eq!(live.matches(&marker).count(), expected, "live {name}");
            assert_eq!(
                canonical.matches(&marker).count(),
                expected,
                "canonical {name}"
            );
        }
        assert!(live.contains("<method name=\"SetSecure\">"));
        assert!(live.contains("<method name=\"ExecuteTransition\">"));
        assert!(live.contains("<method name=\"ApplyDisplayLayout\">"));
        assert!(live.contains("<method name=\"ApplySuccessorDisplayLayout\">"));
        assert!(live.contains("<method name=\"RestoreOriginalDisplayLayout\">"));
        assert!(live.contains("<method name=\"QuiesceOriginalDisplayFinalization\">"));
        assert!(live.contains("<method name=\"ContinueDisplayLayout\">"));
        // The actual tuple codecs depend on argument ORDER as well as counts.
        for contract in [live.as_str(), canonical] {
            let successor = contract
                .split("<method name=\"ApplySuccessorDisplayLayout\">")
                .nth(1)
                .and_then(|rest| rest.split("</method>").next())
                .unwrap_or_else(|| unreachable!("successor method absent"));
            let mut previous = 0;
            for name in [
                "material",
                "predecessor_scope",
                "deadline_unix_ms",
                "transaction_id",
                "generation",
                "state_version",
                "authority_binding_digest",
                "authority_use_digest",
                "effect_digest",
                "dispatch_digest",
                "native_baseline_guard",
                "outcome",
            ] {
                let offset = successor
                    .find(&format!("name=\"{name}\""))
                    .unwrap_or_else(|| unreachable!("successor argument absent"));
                assert!(offset > previous, "successor argument order: {name}");
                previous = offset;
            }
            assert_eq!(successor.matches("<arg ").count(), 12);
            let terminal = contract
                .split("<method name=\"QuiesceOriginalDisplayFinalization\">")
                .nth(1)
                .and_then(|rest| rest.split("</method>").next())
                .unwrap_or_else(|| unreachable!("terminal method is absent"));
            let mut previous = 0;
            for name in [
                "material",
                "deadline_unix_ms",
                "transaction_id",
                "generation",
                "state_version",
                "authority_binding_digest",
                "authority_use_digest",
                "effect_digest",
                "dispatch_digest",
                "outcome",
            ] {
                let offset = terminal
                    .find(&format!("name=\"{name}\""))
                    .unwrap_or_else(|| unreachable!("terminal argument is absent"));
                assert!(offset > previous, "terminal argument order: {name}");
                previous = offset;
            }
            assert_eq!(terminal.matches("<arg ").count(), 10);
            let method = contract
                .split("<method name=\"ContinueDisplayLayout\">")
                .nth(1)
                .and_then(|rest| rest.split("</method>").next())
                .unwrap_or_else(|| unreachable!("continuation method is absent"));
            let mut previous = 0;
            for name in [
                "material",
                "transaction_id",
                "dispatch_digest",
                "deadline_unix_ms",
                "decision_digest",
                "protected_decision_digest",
                "confirm",
                "phase",
            ] {
                let offset = method
                    .find(&format!("name=\"{name}\""))
                    .unwrap_or_else(|| unreachable!("continuation argument is absent"));
                assert!(offset > previous, "continuation argument order: {name}");
                previous = offset;
            }
            assert_eq!(method.matches("<arg ").count(), 8);
        }
    }
    #[test]
    fn untrusted_caller_with_valid_display_binding_cannot_dispatch_or_invoke_policy() {
        let topology = "display:topology:11111111-1111-4111-8111-111111111111:1000:c2:42:seat0:33333333-3333-4333-8333-333333333333:3";
        let layout = |x| format!("LNDL:1;{topology};1:2:enabled:1920:1080:59940:1250:0:{x}:0:-;");
        let material = format!(
            "LNDI:1;session:lock:11111111-1111-4111-8111-111111111111:1000:c2:42:22222222-2222-4222-8222-222222222222:1;{}{}",
            layout(0),
            layout(100)
        );
        let effect = linura_provider_sdk::display_layout_effect(&material)
            .unwrap_or_else(|e| unreachable!("{e}"));
        let binding = ExecutionBinding::new(
            "transaction:display-test",
            0,
            1,
            ComponentDigest::from_bytes([1; 32]),
            ComponentDigest::from_bytes([2; 32]),
            &effect,
        )
        .unwrap_or_else(|e| unreachable!("{e}"));
        let message = zbus::Message::method_call(OBJECT_PATH, "ApplyDisplayLayout")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .sender(":1.7")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .build(&())
            .unwrap_or_else(|e| unreachable!("{e}"));
        let service = SessionExecutor {
            channel: DenyNative,
        };
        let invoke = |material: &str, digest: &str| {
            async_io::block_on(service.apply_display_layout(
                material,
                25_000,
                &binding.transaction_id,
                binding.generation,
                binding.state_version,
                &binding.authority_binding_digest.to_hex(),
                &binding.authority_use_digest.to_hex(),
                digest,
                &binding.dispatch_digest.to_hex(),
                &ComponentDigest::from_bytes([3; 32]).to_hex(),
                message.header(),
            ))
        };
        assert!(matches!(
            invoke(&material, &binding.effect_digest.to_hex()),
            Err(zbus::fdo::Error::AccessDenied(_))
        ));
        let next = linura_core::DisplayLayoutMaterial::decode(&material)
            .unwrap_or_else(|e| unreachable!("{e}"));
        let predecessor =
            linura_core::DisplayRecoveryScope::new(&"a".repeat(64), next.topology().clone())
                .and_then(|scope| scope.resource_id())
                .unwrap_or_else(|e| unreachable!("{e}"));
        for anonymous in [false, true] {
            let message = if anonymous {
                zbus::Message::method_call(OBJECT_PATH, "ApplySuccessorDisplayLayout")
                    .unwrap_or_else(|e| unreachable!("{e}"))
                    .build(&())
                    .unwrap_or_else(|e| unreachable!("{e}"))
            } else {
                message.clone()
            };
            assert!(matches!(
                async_io::block_on(service.apply_successor_display_layout(
                    &material,
                    predecessor.as_str(),
                    25_000,
                    &binding.transaction_id,
                    binding.generation,
                    binding.state_version,
                    &binding.authority_binding_digest.to_hex(),
                    &binding.authority_use_digest.to_hex(),
                    &binding.effect_digest.to_hex(),
                    &binding.dispatch_digest.to_hex(),
                    &ComponentDigest::from_bytes([3; 32]).to_hex(),
                    message.header(),
                )),
                Err(zbus::fdo::Error::AccessDenied(_))
            ));
        }
        assert!(matches!(
            invoke(&material, &"0".repeat(64)),
            Err(zbus::fdo::Error::InvalidArgs(_))
        ));
        assert!(matches!(
            invoke(&"x".repeat(4097), &binding.effect_digest.to_hex()),
            Err(zbus::fdo::Error::InvalidArgs(_))
        ));
        assert!(matches!(
            invoke(
                &material.replace(":100:0:-;", ":101:0:-;"),
                &binding.effect_digest.to_hex()
            ),
            Err(zbus::fdo::Error::InvalidArgs(_))
        ));
        // Public/ordinary callers cannot turn knowledge of valid correlation
        // and decision hashes into continuation authority, for either action.
        for confirm in [false, true] {
            let continue_call = |material: &str,
                                 transaction: &str,
                                 dispatch: &str,
                                 decision: &str,
                                 protected: &str| {
                async_io::block_on(service.continue_display_layout(
                    material,
                    transaction,
                    dispatch,
                    25_000,
                    decision,
                    protected,
                    confirm,
                    message.header(),
                ))
            };
            let digest = ComponentDigest::from_bytes([3; 32]).to_hex();
            assert!(matches!(
                continue_call(
                    &material,
                    &binding.transaction_id,
                    &binding.dispatch_digest.to_hex(),
                    &digest,
                    &digest
                ),
                Err(zbus::fdo::Error::AccessDenied(_))
            ));
            for (bad_material, transaction, dispatch, decision, protected) in [
                (
                    "not an intent",
                    binding.transaction_id.as_str(),
                    binding.dispatch_digest.to_hex(),
                    digest.clone(),
                    digest.clone(),
                ),
                (
                    &material,
                    "transaction:UPPER",
                    binding.dispatch_digest.to_hex(),
                    digest.clone(),
                    digest.clone(),
                ),
                (
                    &material,
                    binding.transaction_id.as_str(),
                    "0".repeat(64),
                    digest.clone(),
                    digest.clone(),
                ),
                (
                    &material,
                    binding.transaction_id.as_str(),
                    binding.dispatch_digest.to_hex(),
                    "0".repeat(64),
                    digest.clone(),
                ),
                (
                    &material,
                    binding.transaction_id.as_str(),
                    binding.dispatch_digest.to_hex(),
                    digest.clone(),
                    "0".repeat(64),
                ),
            ] {
                assert!(matches!(
                    continue_call(bad_material, transaction, &dispatch, &decision, &protected),
                    Err(zbus::fdo::Error::InvalidArgs(_))
                ));
            }
        }
    }

    #[test]
    fn unknown_denied_or_lost_native_display_reply_never_asserts_no_dispatch_or_verification() {
        assert_eq!(display_disposition(Ok(1)).0, "rejected-before-dispatch");
        for phase in 2..=6 {
            assert_eq!(display_disposition(Ok(phase)).0, "dispatched");
        }
        for phase in [0, 7, 8, 9, u32::MAX] {
            assert_eq!(display_disposition(Ok(phase)).0, "indeterminate");
        }
        assert_eq!(
            display_disposition(Err("lost reply".into())).0,
            "indeterminate"
        );
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
