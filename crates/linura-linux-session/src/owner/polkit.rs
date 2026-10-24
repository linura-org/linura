//! Fixed Polkit 127 service attestation, matching the native owner's route.
//! The local service account alone never proves daemon identity or approval.
use super::*;

const NAME: &str = "org.freedesktop.PolicyKit1";
const POLKIT_UNIT: &str = "polkit.service";
const POLKIT_FRAGMENT: &str = "/usr/lib/systemd/system/polkit.service";
const POLKIT_IMAGE: &str = "/usr/lib/polkit-1/polkitd";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthenticationDaemonIdentity {
    pub(super) unique_name: String,
    systemd_owner: String,
    uid: u32,
    pid: u32,
    invocation: [u8; 16],
}

impl NativeSessionChannel {
    pub(super) fn authentication_daemon(&self) -> Result<AuthenticationDaemonIdentity, String> {
        let started = Instant::now();
        let account_uid =
            crate::account::local_service_uid(crate::account::LocalServiceAccount::Polkit)?;
        let owner = self.polkit_name_owner(NAME, started)?;
        let systemd = self.polkit_name_owner(SYSTEMD, started)?;
        if self.connection_credentials(&systemd, started)?.0 != 0 {
            return Err("native authentication supervision is not root".into());
        }
        let first = self.polkit_snapshot(&owner, &systemd, account_uid, started)?;
        let fresh = self.polkit_snapshot(&owner, &systemd, account_uid, started)?;
        if first != fresh
            || self.polkit_name_owner(NAME, started)? != owner
            || self.polkit_name_owner(SYSTEMD, started)? != systemd
            || started.elapsed() >= crate::bus::PROBE_BUDGET
        {
            return Err("native authentication daemon changed during attestation".into());
        }
        Ok(fresh)
    }

    fn polkit_name_owner(&self, name: &str, started: Instant) -> Result<String, String> {
        let owner: String = self
            .bus_call("GetNameOwner", &(name,), started)?
            .body()
            .deserialize()
            .map_err(|_| "native authentication service owner is malformed".to_owned())?;
        if !unique_name(&owner) {
            return Err("native authentication service owner is unsupported".into());
        }
        Ok(owner)
    }

    fn polkit_snapshot(
        &self,
        owner: &str,
        systemd: &str,
        account_uid: u32,
        started: Instant,
    ) -> Result<AuthenticationDaemonIdentity, String> {
        let (uid, pid) = self.connection_credentials(owner, started)?;
        let path: OwnedObjectPath = self
            .call(
                systemd,
                MANAGER,
                "org.freedesktop.systemd1.Manager",
                "GetUnit",
                &(POLKIT_UNIT,),
                started,
            )?
            .body()
            .deserialize()
            .map_err(|_| "native authentication unit is unavailable".to_owned())?;
        if path.as_str().len() > 256
            || !path.as_str().starts_with("/org/freedesktop/systemd1/unit/")
        {
            return Err("native authentication unit handle is unsupported".into());
        }
        let unit = self.properties(systemd, path.as_str(), UNIT, started)?;
        let service = self.properties(systemd, path.as_str(), SERVICE, started)?;
        bind_polkit(
            (owner, uid, pid),
            systemd,
            account_uid,
            &unit,
            &service,
            (
                immutable_file(Path::new(POLKIT_FRAGMENT), false),
                immutable_file(Path::new(POLKIT_IMAGE), true),
            ),
        )
    }
}

fn bind_polkit(
    peer: (&str, u32, u32),
    systemd: &str,
    account_uid: u32,
    unit: &Properties,
    service: &Properties,
    immutable: (bool, bool),
) -> Result<AuthenticationDaemonIdentity, String> {
    let (owner, uid, pid) = peer;
    let invocation: Vec<u8> = array_property(unit, "InvocationID")?;
    let drop_ins: Vec<String> = array_property(unit, "DropInPaths")?;
    let launches: Vec<ExecStart> = array_property(service, "ExecStart")?;
    let argv = [POLKIT_IMAGE, "--no-debug", "--log-level=notice"];
    let exact_launch = matches!(launches.as_slice(), [(image, args, false, real, mono, 0, 0, launch_pid, 0, 0)]
        if image == POLKIT_IMAGE && args == &argv && *real != 0 && *mono != 0 && *launch_pid == pid);
    if !unique_name(owner)
        || !unique_name(systemd)
        || account_uid == 0
        || uid != account_uid
        || pid <= 1
        || pid > i32::MAX as u32
        || property::<u32>(service, "MainPID")? != pid
        || property::<&str>(unit, "Id")? != POLKIT_UNIT
        || property::<&str>(unit, "FragmentPath")? != POLKIT_FRAGMENT
        || property::<&str>(unit, "ActiveState")? != "active"
        || property::<&str>(unit, "SubState")? != "running"
        || !drop_ins.is_empty()
        || invocation.len() != 16
        || invocation.iter().all(|byte| *byte == 0)
        || !exact_launch
        || !immutable.0
        || !immutable.1
    {
        return Err(
            "native authentication daemon is not the exact supervised polkitd invocation".into(),
        );
    }
    Ok(AuthenticationDaemonIdentity {
        unique_name: owner.into(),
        systemd_owner: systemd.into(),
        uid,
        pid,
        invocation: invocation
            .try_into()
            .map_err(|_| "native authentication invocation is malformed")?,
    })
}

#[cfg(test)]
mod tests;
