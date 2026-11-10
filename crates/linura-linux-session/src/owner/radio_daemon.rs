//! S18-6: independently pin the exact supervised NetworkManager process.
//!
//! A root-owned system bus name alone is not a supervised process identity.
//! This source check is only a prerequisite for a future native radio effect;
//! it never manufactures a durable approval, dispatcher permit or local recovery.

use super::*;
use linura_core::NetworkManagerEpoch;

const NM_UNIT: &str = "NetworkManager.service";
const NM_IMAGE: &str = "/usr/bin/NetworkManager";
const NM_FRAGMENT: &str = "/usr/lib/systemd/system/NetworkManager.service";
const NM_SERVICE_NAME: &str = "org.freedesktop.NetworkManager";

#[derive(Clone, Debug, Eq, PartialEq)]
struct RadioDaemonFacts {
    owner: String,
    systemd_owner: String,
    bus_uid: u32,
    bus_pid: u32,
    main_pid: u32,
    unit: String,
    fragment: String,
    active: String,
    substate: String,
    drop_ins: Vec<String>,
    invocation: Vec<u8>,
    launches: Vec<ExecStart>,
    immutable_fragment: bool,
    immutable_image: bool,
    process_start_ticks: u64,
}

fn verify_supervision(facts: &RadioDaemonFacts) -> Result<[u8; 16], String> {
    let expected_argv = [NM_IMAGE, "--no-daemon"];
    let exact_launch = matches!(
        facts.launches.as_slice(),
        [(image, args, false, real, mono, 0, 0, launch_pid, 0, 0)]
            if image == NM_IMAGE
                && args == &expected_argv
                && *real != 0
                && *mono != 0
                && *launch_pid == facts.main_pid
    );
    if !unique_name(&facts.owner)
        || !unique_name(&facts.systemd_owner)
        || facts.bus_uid != 0
        || facts.bus_pid <= 1
        || facts.bus_pid > i32::MAX as u32
        || facts.main_pid != facts.bus_pid
        || facts.unit != NM_UNIT
        || facts.fragment != NM_FRAGMENT
        || facts.active != "active"
        || facts.substate != "running"
        || !facts.drop_ins.is_empty()
        || facts.invocation.len() != 16
        || facts.invocation.iter().all(|x| *x == 0)
        || !exact_launch
        || !facts.immutable_fragment
        || !facts.immutable_image
        || facts.process_start_ticks == 0
    {
        return Err("native radio source is not the exact supervised NetworkManager".into());
    }
    facts
        .invocation
        .as_slice()
        .try_into()
        .map_err(|_| "native radio NetworkManager invocation generation is malformed".into())
}

impl NativeSessionChannel {
    fn radio_supervision_snapshot(
        &self,
        epoch: &NetworkManagerEpoch,
        started: Instant,
    ) -> Result<RadioDaemonFacts, String> {
        let systemd_owner: String = self
            .bus_call("GetNameOwner", &(SYSTEMD,), started)?
            .body()
            .deserialize()
            .map_err(|_| "native radio systemd owner is malformed".to_owned())?;
        let manager_owner: String = self
            .bus_call("GetNameOwner", &(NM_SERVICE_NAME,), started)?
            .body()
            .deserialize()
            .map_err(|_| "native radio NetworkManager owner is malformed".to_owned())?;
        if manager_owner != epoch.owner().as_str()
            || !unique_name(&manager_owner)
            || !unique_name(&systemd_owner)
            || self.connection_credentials(&systemd_owner, started)?.0 != 0
        {
            return Err("native radio system bus owner or supervisor was replaced".into());
        }
        let (uid, pid) = self.connection_credentials(&manager_owner, started)?;
        if uid != 0 || pid <= 1 || pid > i32::MAX as u32 {
            return Err("native radio NetworkManager peer is not a root daemon".into());
        }
        let path: OwnedObjectPath = self
            .call(
                &systemd_owner,
                MANAGER,
                "org.freedesktop.systemd1.Manager",
                "GetUnit",
                &(NM_UNIT,),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| {
                "native radio NetworkManager supervision unit is unavailable".to_owned()
            })?;
        if !path.as_str().starts_with("/org/freedesktop/systemd1/unit/")
            || path.as_str().len() > 256
        {
            return Err("native radio supervision object path is malformed".into());
        }
        let unit = self.properties(&systemd_owner, path.as_str(), UNIT, started)?;
        let service = self.properties(&systemd_owner, path.as_str(), SERVICE, started)?;
        Ok(RadioDaemonFacts {
            owner: manager_owner,
            systemd_owner,
            bus_uid: uid,
            bus_pid: pid,
            main_pid: property(&service, "MainPID")?,
            unit: property::<&str>(&unit, "Id")?.to_owned(),
            fragment: property::<&str>(&unit, "FragmentPath")?.to_owned(),
            active: property::<&str>(&unit, "ActiveState")?.to_owned(),
            substate: property::<&str>(&unit, "SubState")?.to_owned(),
            drop_ins: array_property(&unit, "DropInPaths")?,
            invocation: array_property(&unit, "InvocationID")?,
            launches: array_property(&service, "ExecStart")?,
            immutable_fragment: immutable_file(Path::new(NM_FRAGMENT), false),
            immutable_image: immutable_file(Path::new(NM_IMAGE), true),
            process_start_ticks: process_start(pid)?,
        })
    }

    /// Pin boot/bus/unique-owner and the immutable Arch systemd binary and
    /// launch contract. Cross-check two independent systemd and process
    /// snapshots before returning a non-authorizing source witness.
    pub(super) fn supervised_radio_manager(
        &self,
        started: Instant,
    ) -> Result<NetworkManagerEpoch, String> {
        self.require_role(NativeSessionRole::Control)?;
        let epoch = self.native_network_epoch(started)?;
        let first = self.radio_supervision_snapshot(&epoch, started)?;
        verify_supervision(&first)?;
        let second = self.radio_supervision_snapshot(&epoch, started)?;
        verify_supervision(&second)?;
        if first != second
            || self.native_network_epoch(started)? != epoch
            || current_boot()? != *epoch.boot()
            || started.elapsed() >= crate::bus::PROBE_BUDGET
        {
            return Err("native radio NetworkManager process changed during attestation".into());
        }
        Ok(epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted() -> RadioDaemonFacts {
        RadioDaemonFacts {
            owner: ":1.48".into(),
            systemd_owner: ":1.2".into(),
            bus_uid: 0,
            bus_pid: 931,
            main_pid: 931,
            unit: NM_UNIT.into(),
            fragment: NM_FRAGMENT.into(),
            active: "active".into(),
            substate: "running".into(),
            drop_ins: vec![],
            invocation: vec![42; 16],
            launches: vec![(
                NM_IMAGE.into(),
                vec![NM_IMAGE.into(), "--no-daemon".into()],
                false,
                123,
                456,
                0,
                0,
                931,
                0,
                0,
            )],
            immutable_fragment: true,
            immutable_image: true,
            process_start_ticks: 15_000,
        }
    }

    #[test]
    fn exact_supervised_arch_networkmanager_process_is_required() {
        let valid = accepted();
        assert!(verify_supervision(&valid).is_ok());
        let mut foreign = valid.clone();
        foreign.bus_uid = 1000;
        assert!(verify_supervision(&foreign).is_err());
        let mut pid_reuse = valid.clone();
        pid_reuse.main_pid = 1001;
        assert!(verify_supervision(&pid_reuse).is_err());
        let mut bootless = valid.clone();
        bootless.invocation.fill(0);
        assert!(verify_supervision(&bootless).is_err());
        let mut replaced = valid.clone();
        replaced.process_start_ticks = 0;
        assert!(verify_supervision(&replaced).is_err());
        let mut mutable = valid.clone();
        mutable.immutable_image = false;
        assert!(verify_supervision(&mutable).is_err());
        let mut dropin = valid.clone();
        dropin
            .drop_ins
            .push("/etc/systemd/system/NetworkManager.service.d/x.conf".into());
        assert!(verify_supervision(&dropin).is_err());
        let mut other = valid.clone();
        other.launches[0].1.push("--config=/tmp/evil".into());
        assert!(verify_supervision(&other).is_err());
        let mut stopped = valid.clone();
        stopped.substate = "dead".into();
        assert!(verify_supervision(&stopped).is_err());
        let mut other_user = valid.clone();
        other_user.owner = "org.freedesktop.NetworkManager".into();
        assert!(verify_supervision(&other_user).is_err());
    }
}
