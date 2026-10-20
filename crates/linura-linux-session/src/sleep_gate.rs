//! Read-only exact native pre-sleep-helper attestation. This probe neither locks
//! nor permits sleep; Control must read the current durable policy, plan and
//! prepare any protective lock, then independently verify and fence coverage.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Instant;

use linura_core::{CapabilityId, ProviderId, SleepInvocationId};
use linura_observation::{ObservationAuthority, ObservationEnvelope, ObservedValue};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use crate::owner::{boot_ms, current_boot, immutable_file, process_start, unique_name, unix_ms};
use crate::service::{array, field};
use crate::{NativeSessionChannel, NativeSessionRole};

const UNIT: &str = "systemd-suspend.service";
const FRAGMENT: &str = "/usr/lib/systemd/system/systemd-suspend.service";
const DROP_IN: &str =
    "/usr/lib/systemd/system/systemd-suspend.service.d/50-linura-protective-lock.conf";
const HELPER: &str = "/usr/lib/linura/linura-executor-session";
const ARGUMENT: &str = "--protect-before-sleep";
const SLEEP_IMAGE: &str = "/usr/lib/systemd/systemd-sleep";
const MAX_PROCESS_BYTES: u64 = 4096;
type ExecCommand = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

/// Ephemeral attested facts, not an approval or reusable sleep permit. No public
/// constructor, transport handle, caller-selected UID or native operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeSleepEntry {
    event: SleepInvocationId,
    observation: ObservationEnvelope,
}
impl NativeSleepEntry {
    #[must_use]
    pub const fn event(&self) -> &SleepInvocationId {
        &self.event
    }
    #[must_use]
    pub const fn observation(&self) -> &ObservationEnvelope {
        &self.observation
    }
}

#[derive(Debug, Eq, PartialEq)]
struct GateIdentity {
    supervisor: String,
    pid: u32,
    start_ticks: u64,
    invocation: Vec<u8>,
}

impl NativeSessionChannel {
    /// `sender` comes from authenticated received system-bus metadata, NEVER a
    /// method argument. An ordinary root process is deliberately insufficient.
    pub fn attest_sleep_entry_sender(
        &self,
        sender: &str,
        sequence: u64,
    ) -> Result<NativeSleepEntry, String> {
        self.require_role(NativeSessionRole::Control)?;
        if !unique_name(sender) || sequence == 0 {
            return Err("native sleep helper metadata is invalid".into());
        }
        let started = Instant::now();
        let observed_at_unix_ms = unix_ms()?;
        let started_boot_ms = boot_ms()?;
        let boot = current_boot()?;
        let before = self.sleep_gate_identity(sender, started)?;
        let event = SleepInvocationId::new(boot.clone(), invocation_text(&before.invocation)?)
            .map_err(|_| "native sleep invocation is invalid")?;
        if self.sleep_gate_identity(sender, started)? != before || current_boot()? != boot {
            return Err("native sleep helper or boot changed during attestation".into());
        }
        let elapsed = boot_ms()?
            .checked_sub(started_boot_ms)
            .ok_or("native sleep clock moved backwards")?;
        let valid_for_ms = 2000u64
            .checked_sub(elapsed)
            .filter(|remaining| *remaining > 0)
            .ok_or("native sleep entry attestation expired")?;
        let observation = ObservationEnvelope {
            provider: ProviderId::new("system-sleep").map_err(|_| "sleep provider is invalid")?,
            resource: event
                .resource_id()
                .map_err(|_| "sleep event resource is invalid")?,
            capability: CapabilityId::new("session.sleep-entry.observe")
                .map_err(|_| "sleep capability is invalid")?,
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms,
            valid_for_ms,
            sequence,
            attributes: BTreeMap::from([
                ("boot_id".into(), ObservedValue::Text(boot.as_str().into())),
                (
                    "sleep_invocation".into(),
                    ObservedValue::Text(event.invocation().into()),
                ),
                (
                    "sleep_operation".into(),
                    ObservedValue::Text("suspend".into()),
                ),
                ("pre_kernel_gate".into(), ObservedValue::Bool(true)),
                ("helper_attested".into(), ObservedValue::Bool(true)),
            ]),
        };
        Ok(NativeSleepEntry { event, observation })
    }

    fn sleep_gate_identity(&self, sender: &str, started: Instant) -> Result<GateIdentity, String> {
        let credentials: HashMap<String, OwnedValue> = self
            .bus_call("GetConnectionCredentials", &(sender,), started)?
            .body()
            .deserialize()
            .map_err(|_| "native sleep helper credentials are malformed")?;
        let pid: u32 = field(&credentials, "ProcessID")?;
        if field::<u32>(&credentials, "UnixUserID")? != 0 || pid <= 1 {
            return Err("native sleep helper has the wrong kernel identity".into());
        }
        let start_ticks = process_start(pid)?;
        require_helper_process(pid)?;
        let supervisor: String = self
            .bus_call("GetNameOwner", &("org.freedesktop.systemd1",), started)?
            .body()
            .deserialize()
            .map_err(|_| "native sleep supervisor is unavailable")?;
        let supervisor_uid: u32 = self
            .bus_call("GetConnectionUnixUser", &(supervisor.as_str(),), started)?
            .body()
            .deserialize()
            .map_err(|_| "native sleep supervisor credentials are malformed")?;
        if !unique_name(&supervisor) || supervisor_uid != 0 {
            return Err("native sleep supervisor is not root".into());
        }
        let path: OwnedObjectPath = self
            .call(
                &supervisor,
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "GetUnit",
                &(UNIT,),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native suspend unit is unavailable")?;
        if path.as_str().len() > 256
            || !path.as_str().starts_with("/org/freedesktop/systemd1/unit/")
        {
            return Err("native suspend unit handle is unsupported".into());
        }
        let get = |interface, names: &[&str]| -> Result<HashMap<String, OwnedValue>, String> {
            let mut selected = HashMap::new();
            for name in names {
                let value: OwnedValue = self
                    .call(
                        &supervisor,
                        path.as_str(),
                        "org.freedesktop.DBus.Properties",
                        "Get",
                        &(interface, *name),
                        started,
                    )?
                    .body()
                    .deserialize()
                    .map_err(|_| "native sleep unit property is malformed".to_owned())?;
                selected.insert((*name).to_owned(), value);
            }
            Ok(selected)
        };
        let facts = get(
            "org.freedesktop.systemd1.Unit",
            &[
                "Id",
                "FragmentPath",
                "InvocationID",
                "ActiveState",
                "SubState",
                "DropInPaths",
                "Job",
            ],
        )?;
        let service = get(
            "org.freedesktop.systemd1.Service",
            &[
                "Type",
                "User",
                "Restart",
                "ControlPID",
                "MainPID",
                "ExecStartPre",
                "ExecStart",
                "ExecCondition",
                "ExecStartPost",
                "ExecStop",
                "ExecStopPost",
                "SuccessExitStatus",
            ],
        )?;
        let invocation = validate_gate_properties(&facts, &service, pid)?;
        if !immutable_file(Path::new(FRAGMENT), false)
            || !immutable_file(Path::new(DROP_IN), false)
            || !immutable_file(Path::new(HELPER), true)
            || !immutable_file(Path::new(SLEEP_IMAGE), true)
        {
            return Err("native sleep gate assets are not immutable root-owned files".into());
        }
        let current_supervisor: String = self
            .bus_call("GetNameOwner", &("org.freedesktop.systemd1",), started)?
            .body()
            .deserialize()
            .map_err(|_| "native sleep supervisor recheck failed")?;
        require_helper_process(pid)?;
        if current_supervisor != supervisor || process_start(pid)? != start_ticks {
            return Err("native sleep helper generation changed".into());
        }
        Ok(GateIdentity {
            supervisor,
            pid,
            start_ticks,
            invocation,
        })
    }
}

fn validate_gate_properties(
    facts: &HashMap<String, OwnedValue>,
    service: &HashMap<String, OwnedValue>,
    pid: u32,
) -> Result<Vec<u8>, String> {
    if facts.len() > 256 || service.len() > 256 {
        return Err("native sleep unit property inventory exceeds its bound".into());
    }
    let invocation: Vec<u8> = array(facts, "InvocationID")?;
    let drop_ins: Vec<String> = array(facts, "DropInPaths")?;
    let pre: Vec<ExecCommand> = array(service, "ExecStartPre")?;
    let start: Vec<ExecCommand> = array(service, "ExecStart")?;
    for key in ["ExecCondition", "ExecStartPost", "ExecStop", "ExecStopPost"] {
        let commands: Vec<ExecCommand> = array(service, key)?;
        if !commands.is_empty() {
            return Err("native sleep unit has an unsupported additional program".into());
        }
    }
    let job: (u32, OwnedObjectPath) = facts
        .get("Job")
        .ok_or("native sleep job is absent")?
        .try_clone()
        .map_err(|_| "native sleep job is unavailable")?
        .try_into()
        .map_err(|_| "native sleep job is malformed")?;
    let success: (Vec<i32>, Vec<i32>) = service
        .get("SuccessExitStatus")
        .ok_or("native sleep success status is absent")?
        .try_clone()
        .map_err(|_| "native sleep success status is unavailable")?
        .try_into()
        .map_err(|_| "native sleep success status is malformed")?;
    if pid <= 1
        || field::<&str>(facts, "ActiveState")? != "activating"
        || field::<&str>(facts, "SubState")? != "start-pre"
        || field::<&str>(facts, "Id")? != UNIT
        || field::<&str>(facts, "FragmentPath")? != FRAGMENT
        || drop_ins != [DROP_IN]
        || field::<&str>(service, "Type")? != "oneshot"
        || !matches!(field::<&str>(service, "User")?, "" | "root")
        || field::<&str>(service, "Restart")? != "no"
        || field::<u32>(service, "ControlPID")? != pid
        || field::<u32>(service, "MainPID")? != 0
        || invocation.len() != 16 || invocation.iter().all(|byte| *byte == 0)
        || job.0 == 0 || job.1.as_str() != format!("/org/freedesktop/systemd1/job/{}", job.0)
        || success.0.len() > 1 || !success.0.iter().all(|status| *status == 0) || !success.1.is_empty()
        || !matches!(pre.as_slice(), [(image, argv, false, real, mono, 0, 0, launched, 0, 0)] if image == HELPER && argv == &[HELPER, ARGUMENT] && *real > 0 && *mono > 0 && *launched == pid)
        // systemd resets command status at invocation start. Main execution
        // must not have begun while the exact pre-start helper is being attested.
        || !matches!(start.as_slice(), [(image, argv, false, 0, 0, 0, 0, 0, 0, 0)] if image == SLEEP_IMAGE && argv == &[SLEEP_IMAGE, "suspend"])
    {
        return Err("caller is not the exact immutable supervised pre-sleep helper".into());
    }
    Ok(invocation)
}

fn require_helper_process(pid: u32) -> Result<(), String> {
    let image = fs::metadata(HELPER).map_err(|_| "native sleep helper image is unavailable")?;
    let executing = fs::metadata(format!("/proc/{pid}/exe"))
        .map_err(|_| "native sleep helper process image is unavailable")?;
    let mut bytes = Vec::new();
    fs::File::open(format!("/proc/{pid}/cmdline"))
        .map_err(|_| "native sleep helper arguments are unavailable")?
        .take(MAX_PROCESS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "native sleep helper arguments cannot be read")?;
    if executing.uid() != 0
        || image.dev() != executing.dev()
        || image.ino() != executing.ino()
        || bytes != format!("{HELPER}\0{ARGUMENT}\0").as_bytes()
    {
        return Err(
            "native sleep helper process does not match the fixed image and arguments".into(),
        );
    }
    Ok(())
}

fn invocation_text(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() != 16 || bytes.iter().all(|byte| *byte == 0) {
        return Err("native sleep invocation is absent".into());
    }
    let mut result = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            result.push('-');
        }
        use std::fmt::Write;
        write!(&mut result, "{byte:02x}").map_err(|_| "native sleep invocation encoding failed")?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::zvariant::Value;

    fn id<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("{error:?}"))
    }
    fn owned<T: Into<Value<'static>>>(value: T) -> OwnedValue {
        id(OwnedValue::try_from(value.into()))
    }
    fn properties() -> (HashMap<String, OwnedValue>, HashMap<String, OwnedValue>) {
        (
            HashMap::from([
                ("Id".into(), owned(UNIT)),
                ("ActiveState".into(), owned("activating")),
                ("SubState".into(), owned("start-pre")),
                ("FragmentPath".into(), owned(FRAGMENT)),
                ("DropInPaths".into(), owned(vec![DROP_IN.to_owned()])),
                ("InvocationID".into(), owned(vec![1_u8; 16])),
                (
                    "Job".into(),
                    owned((
                        9_u32,
                        id(OwnedObjectPath::try_from("/org/freedesktop/systemd1/job/9")),
                    )),
                ),
            ]),
            HashMap::from([
                ("Type".into(), owned("oneshot")),
                ("User".into(), owned("")),
                ("Restart".into(), owned("no")),
                ("ControlPID".into(), OwnedValue::from(42_u32)),
                ("MainPID".into(), OwnedValue::from(0_u32)),
                (
                    "ExecStartPre".into(),
                    owned(vec![(
                        HELPER.to_owned(),
                        vec![HELPER.to_owned(), ARGUMENT.to_owned()],
                        false,
                        1_u64,
                        1_u64,
                        0_u64,
                        0_u64,
                        42_u32,
                        0_i32,
                        0_i32,
                    )]),
                ),
                (
                    "ExecStart".into(),
                    owned(vec![(
                        SLEEP_IMAGE.to_owned(),
                        vec![SLEEP_IMAGE.to_owned(), "suspend".to_owned()],
                        false,
                        0_u64,
                        0_u64,
                        0_u64,
                        0_u64,
                        0_u32,
                        0_i32,
                        0_i32,
                    )]),
                ),
                ("ExecCondition".into(), owned(Vec::<ExecCommand>::new())),
                ("ExecStartPost".into(), owned(Vec::<ExecCommand>::new())),
                ("ExecStop".into(), owned(Vec::<ExecCommand>::new())),
                ("ExecStopPost".into(), owned(Vec::<ExecCommand>::new())),
                (
                    "SuccessExitStatus".into(),
                    owned((Vec::<i32>::new(), Vec::<i32>::new())),
                ),
            ]),
        )
    }

    #[test]
    fn only_live_exact_pre_sleep_helper_can_supply_native_evidence() {
        let (facts, service) = properties();
        assert_eq!(
            id(validate_gate_properties(&facts, &service, 42)),
            vec![1_u8; 16]
        );
        for pid in [0, 1, 43] {
            assert!(validate_gate_properties(&facts, &service, pid).is_err());
        }
        for key in facts.keys() {
            let (mut current, service) = properties();
            current.remove(key);
            assert!(
                validate_gate_properties(&current, &service, 42).is_err(),
                "{key}"
            );
        }
        for key in service.keys() {
            let (facts, mut current) = properties();
            current.remove(key);
            assert!(
                validate_gate_properties(&facts, &current, 42).is_err(),
                "{key}"
            );
        }
        for (key, wrong) in [
            ("ActiveState", owned("active")),
            ("SubState", owned("running")),
            ("Id", owned("other.service")),
            (
                "FragmentPath",
                owned("/etc/systemd/system/systemd-suspend.service"),
            ),
            ("DropInPaths", owned(Vec::<String>::new())),
            (
                "DropInPaths",
                owned(vec![DROP_IN.to_owned(), "/etc/override.conf".to_owned()]),
            ),
            ("InvocationID", owned(vec![0_u8; 16])),
            ("InvocationID", owned(vec![1_u8; 15])),
            ("Job", owned((0_u32, id(OwnedObjectPath::try_from("/"))))),
            (
                "Job",
                owned((
                    9_u32,
                    id(OwnedObjectPath::try_from(
                        "/org/freedesktop/systemd1/job/10",
                    )),
                )),
            ),
            ("Job", owned(9_u32)),
        ] {
            let (mut facts, service) = properties();
            facts.insert(key.into(), wrong);
            assert!(
                validate_gate_properties(&facts, &service, 42).is_err(),
                "{key}"
            );
        }
        for (key, wrong) in [
            ("Type", owned("simple")),
            ("User", owned("1000")),
            ("Restart", owned("always")),
            ("ControlPID", OwnedValue::from(43_u32)),
            ("ControlPID", OwnedValue::from(42_u64)),
            ("MainPID", OwnedValue::from(42_u32)),
            ("ExecStartPre", owned(Vec::<ExecCommand>::new())),
            ("SuccessExitStatus", owned((vec![1_i32], Vec::<i32>::new()))),
            (
                "SuccessExitStatus",
                owned((vec![0_i32, 0], Vec::<i32>::new())),
            ),
            (
                "SuccessExitStatus",
                owned((Vec::<i32>::new(), vec![15_i32])),
            ),
        ] {
            let (facts, mut service) = properties();
            service.insert(key.into(), wrong);
            assert!(
                validate_gate_properties(&facts, &service, 42).is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn added_unit_programs_or_unbounded_property_inventory_deny() {
        for key in ["ExecCondition", "ExecStartPost", "ExecStop", "ExecStopPost"] {
            let (facts, mut service) = properties();
            let commands: Vec<ExecCommand> = id(array(&service, "ExecStartPre"));
            service.insert(key.into(), owned(commands));
            assert!(
                validate_gate_properties(&facts, &service, 42).is_err(),
                "{key}"
            );
        }
        for unit_side in [true, false] {
            let (mut facts, mut service) = properties();
            let map = if unit_side { &mut facts } else { &mut service };
            for index in 0..257 {
                map.insert(format!("Extra{index}"), owned(false));
            }
            assert!(validate_gate_properties(&facts, &service, 42).is_err());
        }
    }

    #[test]
    fn historical_helper_status_or_failure_ignored_command_cannot_authenticate() {
        for column in 0..10 {
            let (facts, mut service) = properties();
            let mut commands: Vec<ExecCommand> = id(array(&service, "ExecStartPre"));
            let command = &mut commands[0];
            match column {
                0 => command.0 = SLEEP_IMAGE.into(),
                1 => command.1.push("--substitution".into()),
                2 => command.2 = true,
                3 => command.3 = 0,
                4 => command.4 = 0,
                5 => command.5 = 1,
                6 => command.6 = 1,
                7 => command.7 = 43,
                8 => command.8 = 1,
                _ => command.9 = 1,
            }
            service.insert("ExecStartPre".into(), owned(commands));
            assert!(validate_gate_properties(&facts, &service, 42).is_err());
        }
        let (facts, mut service) = properties();
        let commands: Vec<ExecCommand> = id(array(&service, "ExecStartPre"));
        service.insert(
            "ExecStartPre".into(),
            owned(vec![commands[0].clone(), commands[0].clone()]),
        );
        assert!(validate_gate_properties(&facts, &service, 42).is_err());
    }

    #[test]
    fn historical_or_already_started_main_status_is_not_current_gate_authority() {
        let (facts, mut service) = properties();
        let mut commands: Vec<ExecCommand> = id(array(&service, "ExecStart"));
        commands[0].3 = 100;
        commands[0].4 = 100;
        commands[0].5 = 101;
        commands[0].6 = 101;
        commands[0].7 = 123;
        service.insert("ExecStart".into(), owned(commands));
        assert!(validate_gate_properties(&facts, &service, 42).is_err());
    }

    #[test]
    fn invocation_encoding_is_exact_nonzero_and_non_aliasing() {
        assert_eq!(
            id(invocation_text(&[1_u8; 16])),
            "01010101-0101-0101-0101-010101010101"
        );
        for bytes in [vec![], vec![1_u8; 15], vec![1_u8; 17], vec![0_u8; 16]] {
            assert!(invocation_text(&bytes).is_err());
        }
    }
}
