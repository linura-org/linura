//! Fresh fixed-service attestation for the narrow prepared handoff. Correlation
//! hashes alone are never permission to call the executor.
use std::collections::HashMap;
use std::time::Duration;
use std::time::Instant;

use linura_core::{SessionLockId, SessionTransitionId};
use linura_provider_sdk::{
    ComponentDigest, ExecutionBinding, ExecutionDisposition, ExecutionOutcome,
};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use crate::{NativeSessionChannel, NativeSessionRole};

#[derive(Debug, Eq, PartialEq)]
struct Identity {
    sender: String,
    uid: u32,
    pid: u32,
    invocation: Vec<u8>,
}

type ExecStart = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

fn live_launch(role: NativeSessionRole, image: &str, pid: u32, launches: &[ExecStart]) -> bool {
    let arguments = match role {
        NativeSessionRole::DisplayProtection => vec![image, "--display-protection"],
        NativeSessionRole::Control | NativeSessionRole::Executor => vec![image],
    };
    matches!(launches, [(exe, argv, false, real, mono, 0, 0, launch_pid, 0, 0)]
        if exe == image && argv == &arguments && *real != 0 && *mono != 0 && *launch_pid == pid)
}

/// Fixed supervised pre-start helper only. The anonymous connection acquires
/// no executor/Control name and exposes no channel/effect handle to its caller.
/// Control independently authenticates this process and exact systemd program.
pub fn protect_before_native_sleep() -> Result<(), String> {
    // This is the fixed process entry mode, before any bus/runtime thread or
    // transport is created. The same-PID re-exec retains native supervision.
    crate::sleep_helper::enter_unprivileged()?;
    let channel = NativeSessionChannel {
        connection: crate::bus::connect_native_bus(None)?,
        role: NativeSessionRole::Executor,
    };
    let control = channel.trusted_service(NativeSessionRole::Control, Instant::now())?;
    let reply = channel.call_with_budget(
        &control.sender,
        "/org/linura/SleepGate1",
        "org.linura.SleepGate1",
        "ProtectBeforeSleep",
        &(),
        Duration::from_secs(35),
    )?;
    if reply
        .header()
        .sender()
        .is_none_or(|sender| sender.as_str() != control.sender)
    {
        return Err("native sleep gate reply has a different authenticated sender".into());
    }
    let (fenced,): (bool,) = reply
        .body()
        .deserialize()
        .map_err(|_| "native sleep gate reply is malformed")?;
    if !fenced || channel.trusted_service(NativeSessionRole::Control, Instant::now())? != control {
        return Err("native sleep coverage is not fenced by the same supervised Control".into());
    }
    Ok(())
}

impl NativeSessionChannel {
    pub(crate) fn observe_original_display_protection(
        &self,
        scope: &linura_core::DisplayRecoveryScope,
        sequence: u64,
    ) -> Result<linura_observation::ObservationEnvelope, String> {
        self.require_role(NativeSessionRole::Control)?;
        if sequence == 0 || crate::owner::current_boot()? != *scope.replacement().session().boot() {
            return Err("original display protection observation scope unavailable".into());
        }
        let started = Instant::now();
        let began_boot = crate::owner::boot_ms()?;
        let identity = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let resource = scope.resource_id().map_err(|e| e.to_string())?;
        let reply = self.call(
            &identity.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReadOriginal",
            &(resource.as_str(),),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
            || reply.body().signature().to_string() != "ay"
        {
            return Err("original display protection observation peer or signature differs".into());
        }
        let (payload,): (Vec<u8>,) = reply
            .body()
            .deserialize()
            .map_err(|_| "original checkpoint observation reply is malformed")?;
        let facts =
            crate::NativeDisplayRecoveryCheckpoint::original_protection_facts(&payload, scope)?;
        if self.trusted_service(NativeSessionRole::DisplayProtection, started)? != identity
            || crate::owner::current_boot()? != *scope.replacement().session().boot()
        {
            return Err("original protection service changed; no witness reacquisition".into());
        }
        let now_boot = crate::owner::boot_ms()?;
        let now = crate::owner::unix_ms()?;
        let age = now_boot
            .checked_sub(began_boot)
            .ok_or("original protection observation clock regressed")?;
        if began_boot == 0 || age >= 2000 || started.elapsed() >= Duration::from_secs(2) {
            return Err(
                "original display protection observation exceeded its original budget".into(),
            );
        }
        let observation = linura_observation::ObservationEnvelope {
            provider: linura_core::ProviderId::new(linura_observation::DISPLAY_RECOVERY_PROVIDER)
                .map_err(|e| e.to_string())?,
            capability: linura_core::CapabilityId::new(
                linura_observation::DISPLAY_ORIGINAL_PROTECTION_CAPABILITY,
            )
            .map_err(|e| e.to_string())?,
            resource,
            authority: linura_observation::ObservationAuthority::NativeApi,
            observed_at_unix_ms: now
                .checked_sub(age)
                .filter(|ms| *ms != 0)
                .ok_or("original protection wall-clock mapping underflow")?,
            valid_for_ms: 2000,
            sequence,
            attributes: facts.attributes(),
        };
        linura_observation::DisplayOriginalProtectionFacts::from_envelope(&observation, scope, now)
            .map_err(|e| e.to_string())?;
        Ok(observation)
    }
    fn display_protection_call<B: serde::Serialize + zbus::zvariant::DynamicType>(
        &self,
        method: &str,
        body: &B,
    ) -> Result<(), String> {
        self.require_role(NativeSessionRole::Executor)?;
        let started = Instant::now();
        let identity = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let reply = self.call(
            &identity.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            method,
            body,
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
            || reply.body().signature().to_string() != "b"
        {
            return Err("display protection peer or reply is unavailable".into());
        }
        let (verified,): (bool,) = reply
            .body()
            .deserialize()
            .map_err(|_| "display protection reply is malformed")?;
        if !verified
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != identity
        {
            return Err("original display protection is unavailable; no retry".into());
        }
        Ok(())
    }

    pub fn begin_display_protection(&self, dispatch: &ComponentDigest) -> Result<(), String> {
        self.display_protection_call("Begin", &(dispatch.to_hex(),))
    }

    pub fn reserve_display_protection(
        &self,
        record: &crate::NativeDisplayRecoveryCheckpoint,
    ) -> Result<(), String> {
        self.display_protection_call("Reserve", &(record.canonical_bytes(),))
    }

    /// Reserve exactly once after Control's fresh prepared handoff. This
    /// private endpoint remains adapter data; the native recipient must match
    /// its kernel peer to the continuously retained original startup lease.
    /// This API never retries an ambiguous call or reconstructs a lost grant.
    pub fn reserve_display_restoration(
        &self,
        record: &crate::NativeDisplayRestorationReservation,
    ) -> Result<std::os::fd::OwnedFd, String> {
        self.require_role(NativeSessionRole::Executor)?;
        let started = Instant::now();
        let identity = self.trusted_service(NativeSessionRole::DisplayProtection, started)?;
        let bytes = record.canonical_bytes();
        let reply = self.call(
            &identity.sender,
            "/org/linura/DisplayProtection1",
            "org.linura.DisplayProtection1",
            "ReserveRestoration",
            &(bytes,),
            started,
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
            || reply.body().signature().to_string() != "h"
        {
            return Err("original restoration grant peer or signature differs; no retry".into());
        }
        let (descriptor,): (zbus::zvariant::OwnedFd,) = reply
            .body()
            .deserialize()
            .map_err(|_| "original restoration grant is malformed; no retry")?;
        let descriptor: std::os::fd::OwnedFd = descriptor.into();
        let peer = rustix::net::sockopt::socket_peercred(&descriptor)
            .map_err(|_| "original restoration grant has no authenticated kernel peer")?;
        if peer.uid.as_raw() != 0
            || peer.pid.as_raw_nonzero().get() as u32 != identity.pid
            || self.trusted_service(NativeSessionRole::DisplayProtection, started)? != identity
        {
            return Err("original restoration grant service changed; no reconnection".into());
        }
        Ok(descriptor)
    }

    pub fn verify_display_protection(&self, dispatch: &ComponentDigest) -> Result<(), String> {
        self.display_protection_call("Verify", &(dispatch.to_hex(),))
    }

    /// Continue the already durably reserved operation once. The supplied
    /// digests correlate Control's retained decision; they grant no authority.
    pub fn handoff_display_continuation(
        &self,
        continuation: &crate::NativeDisplayContinuation,
    ) -> Result<u32, String> {
        self.require_role(NativeSessionRole::Control)?;
        continuation.validate_at(crate::owner::unix_ms()?)?;
        let started = Instant::now();
        let identity = self.trusted_service(NativeSessionRole::Executor, started)?;
        continuation.validate_at(crate::owner::unix_ms()?)?;
        let reply = self.call_with_budget(
            &identity.sender,
            "/org/linura/Executor/Session1",
            "org.linura.Executor.Session1",
            "ContinueDisplayLayout",
            &continuation.wire(),
            Duration::from_secs(10),
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
            || reply.body().signature().to_string() != "u"
        {
            return Err("display executor decision reply identity or signature differs".into());
        }
        let (phase,): (u32,) = reply
            .body()
            .deserialize()
            .map_err(|_| "display executor decision reply is malformed")?;
        if self.trusted_service(NativeSessionRole::Executor, Instant::now())? != identity
            || !(2..=6).contains(&phase)
        {
            return Err("display executor decision outcome is indeterminate; no retry".into());
        }
        Ok(phase)
    }

    fn trusted_service(
        &self,
        role: NativeSessionRole,
        started: Instant,
    ) -> Result<Identity, String> {
        let (unit, fragment, image, account) = match role {
            NativeSessionRole::Control => (
                "linura-authorityd.service",
                "/usr/lib/systemd/system/linura-authorityd.service",
                "/usr/lib/linura/linura-authorityd",
                "linura-authority",
            ),
            NativeSessionRole::Executor => (
                "linura-executor-session.service",
                "/usr/lib/systemd/system/linura-executor-session.service",
                "/usr/lib/linura/linura-executor-session",
                "root",
            ),
            NativeSessionRole::DisplayProtection => (
                "linura-display-protection.service",
                "/usr/lib/systemd/system/linura-display-protection.service",
                "/usr/lib/linura/linura-executor-session",
                "root",
            ),
        };
        let sender: String = self
            .bus_call("GetNameOwner", &(role.service(),), started)?
            .body()
            .deserialize()
            .map_err(|_| "native named service has no unique owner".to_owned())?;
        let credentials: HashMap<String, OwnedValue> = self
            .bus_call("GetConnectionCredentials", &(sender.as_str(),), started)?
            .body()
            .deserialize()
            .map_err(|_| "native named service credentials are malformed".to_owned())?;
        let uid: u32 = field(&credentials, "UnixUserID")?;
        let pid: u32 = field(&credentials, "ProcessID")?;
        let expected_uid = match role {
            NativeSessionRole::Executor | NativeSessionRole::DisplayProtection => 0,
            NativeSessionRole::Control => {
                crate::account::local_service_uid(crate::account::LocalServiceAccount::Authority)?
            }
        };
        if uid != expected_uid || pid == 0 {
            return Err("native named service has the wrong kernel identity".into());
        }
        let supervisor: String = self
            .bus_call("GetNameOwner", &("org.freedesktop.systemd1",), started)?
            .body()
            .deserialize()
            .map_err(|_| "native supervisor has no unique owner".to_owned())?;
        let supervisor_uid: u32 = self
            .bus_call("GetConnectionUnixUser", &(supervisor.as_str(),), started)?
            .body()
            .deserialize()
            .map_err(|_| "native supervisor credentials are malformed".to_owned())?;
        if supervisor_uid != 0 {
            return Err("native supervisor is not root".into());
        }
        let path: OwnedObjectPath = self
            .call(
                &supervisor,
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "GetUnit",
                &(unit,),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native service unit is unavailable".to_owned())?;
        if path.as_str().len() > 256
            || !path.as_str().starts_with("/org/freedesktop/systemd1/unit/")
        {
            return Err("native service unit handle is unsupported".into());
        }
        let get = |interface| -> Result<HashMap<String, OwnedValue>, String> {
            self.call(
                &supervisor,
                path.as_str(),
                "org.freedesktop.DBus.Properties",
                "GetAll",
                &(interface,),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native named service properties are malformed".into())
        };
        let facts = get("org.freedesktop.systemd1.Unit")?;
        let service = get("org.freedesktop.systemd1.Service")?;
        let invocation: Vec<u8> = array(&facts, "InvocationID")?;
        let drop_ins: Vec<String> = array(&facts, "DropInPaths")?;
        let launches: Vec<ExecStart> = array(&service, "ExecStart")?;
        if field::<u32>(&service, "MainPID")? != pid
            || field::<&str>(&service, "User")? != account
            || field::<&str>(&facts, "FragmentPath")? != fragment
            || !drop_ins.is_empty()
            || field::<&str>(&facts, "ActiveState")? != "active"
            || field::<&str>(&facts, "SubState")? != "running"
            || invocation.len() != 16
            || invocation.iter().all(|b| *b == 0)
            || !live_launch(role, image, pid, &launches)
            || !crate::owner::immutable_file(std::path::Path::new(fragment), false)
            || !crate::owner::immutable_file(std::path::Path::new(image), true)
        {
            return Err("native service is not the exact immutable supervised invocation".into());
        }
        for (name, expected) in [
            (role.service(), sender.as_str()),
            ("org.freedesktop.systemd1", supervisor.as_str()),
        ] {
            let fresh: String = self
                .bus_call("GetNameOwner", &(name,), started)?
                .body()
                .deserialize()
                .map_err(|_| "native named service recheck failed".to_owned())?;
            if fresh != expected {
                return Err("native service owner changed during attestation".into());
            }
        }
        Ok(Identity {
            sender,
            uid,
            pid,
            invocation,
        })
    }

    /// Executor-only caller authentication. This is not policy approval; the
    /// service must separately authorize the fixed native executor action and
    /// validate the exact prepared binding before dispatch.
    pub fn require_trusted_control_sender(&self, sender: &str) -> Result<(), String> {
        self.require_role(NativeSessionRole::Executor)?;
        if sender.len() > 128
            || self
                .trusted_service(NativeSessionRole::Control, Instant::now())?
                .sender
                != sender
        {
            return Err("session executor caller is not the supervised Control owner".into());
        }
        Ok(())
    }

    /// The protection process accepts only the current independently supervised
    /// session executor. Root UID or possession of a dispatch digest is not
    /// sufficient. This admits a bounded mechanism, not a new effect path.
    pub fn require_trusted_display_executor_sender(&self, sender: &str) -> Result<(), String> {
        self.require_role(NativeSessionRole::DisplayProtection)?;
        if !crate::owner::unique_name(sender)
            || self
                .trusted_service(NativeSessionRole::Executor, Instant::now())?
                .sender
                != sender
        {
            return Err("display protection caller is not the supervised executor".into());
        }
        Ok(())
    }

    /// Read-only original-protection observation admits the exact supervised
    /// Control invocation, never an arbitrary root or same-account process.
    pub fn require_trusted_display_control_sender(&self, sender: &str) -> Result<(), String> {
        self.require_role(NativeSessionRole::DisplayProtection)?;
        if !crate::owner::unique_name(sender)
            || self
                .trusted_service(NativeSessionRole::Control, Instant::now())?
                .sender
                != sender
        {
            return Err(
                "original display observation requires the supervised Control owner".into(),
            );
        }
        Ok(())
    }

    /// Control-only, single-attempt handoff. A failed/uncertain reply is never
    /// retried here. The managed lifecycle already persisted ambiguity before
    /// consuming its process-local permit and calling this adapter.
    pub fn handoff_prepared_lock(
        &self,
        lock: &SessionLockId,
        secure: bool,
        binding: &ExecutionBinding,
    ) -> Result<ExecutionOutcome, String> {
        self.require_role(NativeSessionRole::Control)?;
        let started = Instant::now();
        let identity = self.trusted_service(NativeSessionRole::Executor, started)?;
        let resource = lock.resource_id().map_err(|e| e.to_string())?;
        let reply = self.call(
            &identity.sender,
            "/org/linura/Executor/Session1",
            "org.linura.Executor.Session1",
            "SetSecure",
            &(
                resource.as_str(),
                secure,
                binding.transaction_id.as_str(),
                binding.generation,
                binding.state_version,
                binding.authority_binding_digest.to_hex(),
                binding.authority_use_digest.to_hex(),
                binding.effect_digest.to_hex(),
                binding.dispatch_digest.to_hex(),
            ),
            started,
        )?;
        self.decode_executor_outcome(&identity, reply, binding, started)
    }

    pub fn handoff_prepared_transition(
        &self,
        target: &SessionTransitionId,
        binding: &ExecutionBinding,
    ) -> Result<ExecutionOutcome, String> {
        self.require_role(NativeSessionRole::Control)?;
        let identity = self.trusted_service(NativeSessionRole::Executor, Instant::now())?;
        let resource = target.resource_id().map_err(|e| e.to_string())?;
        // Fixed aggregate mechanism budget, not a human interaction deadline.
        // The root service rechecks native preconditions and arms coverage;
        // any late/lost response remains durable ambiguity, never an OS retry.
        let reply = self.call_with_budget(
            &identity.sender,
            "/org/linura/Executor/Session1",
            "org.linura.Executor.Session1",
            "ExecuteTransition",
            &(
                resource.as_str(),
                binding.transaction_id.as_str(),
                binding.generation,
                binding.state_version,
                binding.authority_binding_digest.to_hex(),
                binding.authority_use_digest.to_hex(),
                binding.effect_digest.to_hex(),
                binding.dispatch_digest.to_hex(),
            ),
            Duration::from_secs(10),
        )?;
        self.decode_executor_outcome(&identity, reply, binding, Instant::now())
    }

    /// Single prepared full-layout handoff. Neither this adapter nor the root
    /// executor can manufacture a Control permit from the correlation binding.
    /// Native strict validation preserves its own original two-second sample.
    pub fn handoff_prepared_display(
        &self,
        material: &str,
        binding: &ExecutionBinding,
        deadline_unix_ms: u64,
        native_baseline_guard: &ComponentDigest,
    ) -> Result<ExecutionOutcome, String> {
        self.require_role(NativeSessionRole::Control)?;
        let effect = linura_provider_sdk::display_layout_effect(material)?;
        binding.validate_for(&effect).map_err(|e| e.to_string())?;
        let identity = self.trusted_service(NativeSessionRole::Executor, Instant::now())?;
        // Separate fixed mechanism budget, including root's service policy and
        // one native probe/dispatch. It cannot extend the human deadline or the
        // native sample's freshness. Fault/timeout never requests redelivery.
        let reply = self.call_with_budget(
            &identity.sender,
            "/org/linura/Executor/Session1",
            "org.linura.Executor.Session1",
            "ApplyDisplayLayout",
            &(
                material,
                deadline_unix_ms,
                binding.transaction_id.as_str(),
                binding.generation,
                binding.state_version,
                binding.authority_binding_digest.to_hex(),
                binding.authority_use_digest.to_hex(),
                binding.effect_digest.to_hex(),
                binding.dispatch_digest.to_hex(),
                native_baseline_guard.to_hex(),
            ),
            Duration::from_secs(10),
        )?;
        if reply
            .header()
            .sender()
            .is_none_or(|sender| sender.as_str() != identity.sender)
        {
            return Err(
                "prepared display executor result has a different authenticated sender".into(),
            );
        }
        self.decode_executor_outcome(&identity, reply, binding, Instant::now())
    }

    fn decode_executor_outcome(
        &self,
        identity: &Identity,
        reply: zbus::Message,
        binding: &ExecutionBinding,
        started: Instant,
    ) -> Result<ExecutionOutcome, String> {
        let ((disposition, digest, detail),): ((String, String, String),) = reply
            .body()
            .deserialize()
            .map_err(|_| "native executor outcome is malformed".to_owned())?;
        if &self.trusted_service(NativeSessionRole::Executor, started)? != identity {
            return Err("native executor changed across dispatch; outcome is indeterminate".into());
        }
        let disposition = match disposition.as_str() {
            "dispatched" => ExecutionDisposition::Dispatched,
            "rejected-before-dispatch" => ExecutionDisposition::RejectedBeforeDispatch,
            "indeterminate" => ExecutionDisposition::Indeterminate,
            _ => return Err("native executor disposition is unknown".into()),
        };
        if detail.len() > 192
            || ComponentDigest::parse_hex(&digest).map_err(|e| e.to_string())?
                != binding.dispatch_digest
        {
            return Err("native executor substituted its exact handoff binding".into());
        }
        ExecutionOutcome::new(disposition, binding.dispatch_digest, detail)
            .map_err(|e| e.to_string())
    }
}

pub(crate) fn field<'a, T: TryFrom<&'a OwnedValue>>(
    properties: &'a HashMap<String, OwnedValue>,
    name: &str,
) -> Result<T, String> {
    properties
        .get(name)
        .and_then(|v| T::try_from(v).ok())
        .ok_or_else(|| format!("native named service field {name} is absent or malformed"))
}
pub(crate) fn array<T>(
    properties: &HashMap<String, OwnedValue>,
    name: &str,
) -> Result<Vec<T>, String>
where
    for<'a> T: TryFrom<zbus::zvariant::Value<'a>>,
    for<'a> <T as TryFrom<zbus::zvariant::Value<'a>>>::Error: Into<zbus::zvariant::Error>,
{
    let value = properties
        .get(name)
        .ok_or("native service array field is absent")?
        .try_clone()
        .map_err(|_| "native service array field is unavailable".to_owned())?;
    Vec::<T>::try_from(value).map_err(|_| "native service array field has the wrong type".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_mode_is_not_an_executor_or_control_launch() {
        let image = "/usr/lib/linura/linura-executor-session";
        let original: ExecStart = (
            image.into(),
            vec![image.into(), "--display-protection".into()],
            false,
            1,
            2,
            0,
            0,
            42,
            0,
            0,
        );
        assert!(live_launch(
            NativeSessionRole::DisplayProtection,
            image,
            42,
            std::slice::from_ref(&original)
        ));
        for role in [NativeSessionRole::Control, NativeSessionRole::Executor] {
            assert!(!live_launch(
                role,
                image,
                42,
                std::slice::from_ref(&original)
            ));
            let mut regular = original.clone();
            regular.1.pop();
            assert!(live_launch(role, image, 42, std::slice::from_ref(&regular)));
            assert!(!live_launch(
                NativeSessionRole::DisplayProtection,
                image,
                42,
                &[regular]
            ));
        }
        for change in 0..12 {
            let mut bad = original.clone();
            match change {
                0 => bad.0 = "/tmp/executor".into(),
                1 => bad.1[0] = "/tmp/executor".into(),
                2 => bad.1[1] = "--protect-before-sleep".into(),
                3 => bad.1.push("unexpected".into()),
                4 => bad.2 = true,
                5 => bad.3 = 0,
                6 => bad.4 = 0,
                7 => bad.5 = 3,
                8 => bad.6 = 4,
                9 => bad.7 = 43,
                10 => bad.8 = 1,
                11 => bad.9 = 1,
                _ => unreachable!(),
            }
            assert!(
                !live_launch(NativeSessionRole::DisplayProtection, image, 42, &[bad]),
                "field {change}"
            );
        }
        assert!(!live_launch(
            NativeSessionRole::DisplayProtection,
            image,
            42,
            &[]
        ));
        assert!(!live_launch(
            NativeSessionRole::DisplayProtection,
            image,
            42,
            &[original.clone(), original]
        ));
    }
}
