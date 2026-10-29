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
            NativeSessionRole::Executor => 0,
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
        type ExecStart = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);
        let launches: Vec<ExecStart> = array(&service, "ExecStart")?;
        if field::<u32>(&service, "MainPID")? != pid
            || field::<&str>(&service, "User")? != account
            || field::<&str>(&facts, "FragmentPath")? != fragment
            || !drop_ins.is_empty()
            || field::<&str>(&facts, "ActiveState")? != "active"
            || field::<&str>(&facts, "SubState")? != "running"
            || invocation.len() != 16
            || invocation.iter().all(|b| *b == 0)
            || !matches!(launches.as_slice(), [(exe, argv, false, real, mono, 0, 0, launch_pid, 0, 0)] if exe == image && argv == &[image] && *real != 0 && *mono != 0 && *launch_pid == pid)
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
