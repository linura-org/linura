//! Read-only, non-interactive, exact-subject PolicyKit review for S21-4.
//!
//! A positive PolicyKit result is NOT a Control permit, executor authority,
//! durable approval, or assurance the device has not been replaced.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use linura_provider_sdk::ProviderError;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, Value};

use crate::provider_bus_error;
use crate::removable_storage::StorageAction;
use crate::removable_storage_native::{
    ReadOnlySessionScope, connect_native_bus, native_logind_scope, valid_owner,
};

const POLKIT: &str = "org.freedesktop.PolicyKit1";
const POLKIT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const BUDGET: Duration = Duration::from_secs(3);
const MAX_REPLY: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ReadOnlyPolkitCandidate {
    pub unique_name: String,
    pub uid: u32,
    pub pid: u32,
    pub session: ReadOnlySessionScope,
    pub polkit_owner: String,
    pub action: StorageAction,
}

fn invalid(message: &str) -> ProviderError {
    ProviderError::InvalidState(message.into())
}

/// UDisks2 does not define a general permission for unmounting a filesystem
/// owned by the same user. Filesystem-unmount-others is NOT interchangeable.
#[must_use]
pub const fn explicit_polkit_action(action: StorageAction) -> Option<&'static str> {
    match action {
        StorageAction::Mount => Some("org.freedesktop.udisks2.filesystem-mount"),
        StorageAction::Unmount => None,
        StorageAction::Eject => Some("org.freedesktop.udisks2.eject-media"),
        StorageAction::PowerOff => Some("org.freedesktop.udisks2.power-off-drive"),
    }
}

fn system_bus(connection: &Connection) -> Result<Proxy<'_>, ProviderError> {
    Proxy::new(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .map_err(provider_bus_error)
}

fn root_owner(bus: &Proxy<'_>, service: &str) -> Result<String, ProviderError> {
    let owner: String = bus
        .call("GetNameOwner", &(service,))
        .map_err(provider_bus_error)?;
    if !valid_owner(&owner) {
        return Err(invalid("service unique bus owner is malformed"));
    }
    let uid: u32 = bus
        .call("GetConnectionUnixUser", &(owner.as_str(),))
        .map_err(provider_bus_error)?;
    if uid != 0 {
        return Err(invalid("PolicyKit service is not root-owned"));
    }
    Ok(owner)
}

fn scope_for_peer(
    connection: &Connection,
    unique_name: &str,
    uid: u32,
    pid: u32,
    session: &str,
) -> Result<ReadOnlySessionScope, ProviderError> {
    if !valid_owner(unique_name) || uid == 0 || pid == 0 {
        return Err(invalid("missing authenticated nonroot D-Bus peer"));
    }
    let bus = system_bus(connection)?;
    let peer_uid: u32 = bus
        .call("GetConnectionUnixUser", &(unique_name,))
        .map_err(provider_bus_error)?;
    let peer_pid: u32 = bus
        .call("GetConnectionUnixProcessID", &(unique_name,))
        .map_err(provider_bus_error)?;
    if uid != peer_uid || pid != peer_pid {
        return Err(invalid("authenticated user or process changed"));
    }
    let scope = native_logind_scope(connection, session, uid)?;
    let manager = Proxy::new(
        connection,
        scope.logind_unique_owner.as_str(),
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    )
    .map_err(provider_bus_error)?;
    let by_uid: OwnedObjectPath = manager
        .call("GetSession", &(session,))
        .map_err(provider_bus_error)?;
    let by_pid: OwnedObjectPath = manager
        .call("GetSessionByPID", &(pid,))
        .map_err(provider_bus_error)?;
    if by_pid != by_uid {
        return Err(invalid(
            "D-Bus peer PID does not belong to the selected live session",
        ));
    }
    Ok(scope.clone())
}

/// Strictly non-interactive and never exposed as a privileged effect. Control
/// must separately bind the actual Authority1 sender and durable approval.
pub fn inspect_polkit_storage_subject(
    unique_name: &str,
    uid: u32,
    pid: u32,
    session: &str,
    action: StorageAction,
) -> Result<ReadOnlyPolkitCandidate, ProviderError> {
    let action_id = explicit_polkit_action(action).ok_or_else(|| {
        ProviderError::Unsupported(
            "unmount needs an independent exact native ownership review".into(),
        )
    })?;
    let started = Instant::now();
    let connection = connect_native_bus()?;
    let first = scope_for_peer(&connection, unique_name, uid, pid, session)?;
    let bus = system_bus(&connection)?;
    let polkit_owner = root_owner(&bus, POLKIT)?;
    let authority = Proxy::new(
        &connection,
        polkit_owner.as_str(),
        POLKIT_PATH,
        POLKIT_INTERFACE,
    )
    .map_err(provider_bus_error)?;
    let subject = HashMap::from([("name", Value::from(unique_name))]);
    let details: HashMap<String, String> = HashMap::new();
    // Flags=0; reading candidate capability must never prompt the user.
    let reply = authority
        .call_method(
            "CheckAuthorization",
            &(("system-bus-name", subject), action_id, details, 0_u32, ""),
        )
        .map_err(provider_bus_error)?;
    if reply.body().len() > MAX_REPLY {
        return Err(invalid("PolicyKit answer exceeds a bounded reply"));
    }
    let (authorized, challenge, _unused): (bool, bool, HashMap<String, String>) =
        reply.body().deserialize().map_err(provider_bus_error)?;
    if !authorized || challenge {
        return Err(invalid(
            "actual user has no existing PolicyKit authorization",
        ));
    }
    let repeated = scope_for_peer(&connection, unique_name, uid, pid, session)?;
    if first != repeated || root_owner(&bus, POLKIT)? != polkit_owner || started.elapsed() >= BUDGET
    {
        return Err(ProviderError::Unavailable(
            "PolicyKit owner or authenticated caller changed during read".into(),
        ));
    }
    Ok(ReadOnlyPolkitCandidate {
        unique_name: unique_name.into(),
        uid,
        pid,
        session: repeated,
        polkit_owner: polkit_owner.clone(),
        action,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_actions_never_conflate_unmount_with_other_users() {
        assert_eq!(
            explicit_polkit_action(StorageAction::Mount),
            Some("org.freedesktop.udisks2.filesystem-mount")
        );
        assert_eq!(explicit_polkit_action(StorageAction::Unmount), None);
        assert_eq!(
            explicit_polkit_action(StorageAction::Eject),
            Some("org.freedesktop.udisks2.eject-media")
        );
        assert_eq!(
            explicit_polkit_action(StorageAction::PowerOff),
            Some("org.freedesktop.udisks2.power-off-drive")
        );
        assert!(matches!(
            inspect_polkit_storage_subject(":1.2", 1000, 200, "c2", StorageAction::Unmount),
            Err(ProviderError::Unsupported(_))
        ));
    }
}
