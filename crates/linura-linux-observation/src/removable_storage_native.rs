//! S21-4 authenticated, read-only UDisks2 ObjectManager inventory.
//!
//! These are untrusted-as-authorization native observations. A valid D-Bus
//! reply cannot authorize Polkit, establish device generation or prove a
//! destructive effect. No native storage mutation API is exposed.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::time::{Duration, Instant};

use linura_provider_sdk::ProviderError;
use rustix::net::sockopt::socket_peercred;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use crate::{provider_bus_error, snapshot_property};

const SERVICE: &str = "org.freedesktop.UDisks2";
const MANAGER_PATH: &str = "/org/freedesktop/UDisks2";
const DRIVE_INTERFACE: &str = "org.freedesktop.UDisks2.Drive";
const BLOCK_INTERFACE: &str = "org.freedesktop.UDisks2.Block";
const FILESYSTEM_INTERFACE: &str = "org.freedesktop.UDisks2.Filesystem";
const PARTITION_INTERFACE: &str = "org.freedesktop.UDisks2.Partition";
const TIMEOUT: Duration = Duration::from_millis(750);
const TOTAL_BUDGET: Duration = Duration::from_secs(3);
const MAX_REPLY_BYTES: usize = 1024 * 1024;
const MAX_OBJECTS: usize = 256;

type Properties = HashMap<String, OwnedValue>;
type Interfaces = HashMap<String, Properties>;
type ManagedObjects = HashMap<OwnedObjectPath, Interfaces>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyDrive {
    pub path: String,
    pub removable: bool,
    pub media_available: bool,
    pub ejectable: bool,
    pub can_power_off: bool,
    /// UDisks2 reports the physical seat but Control must verify this against logind.
    pub seat: String,
    /// Conservative USB-only candidate review; connection-bus is a provider hint.
    pub connection_bus: String,
    /// Shared power/eject effects may affect other drives with the same sibling ID.
    pub sibling_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyBlock {
    pub path: String,
    pub drive: Option<String>,
    pub device_number: u64,
    pub hint_system: bool,
    pub hint_ignore: bool,
    /// Native mappings are correlations, not an independently proven kernel graph.
    pub crypto_backing_device: Option<String>,
    pub mdraid: Option<String>,
    pub mdraid_member: Option<String>,
    pub partition_table: Option<String>,
    pub mount_points: Vec<String>,
    pub has_filesystem: bool,
    pub partition_number: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlyStorageInventory {
    pub unique_owner: String,
    pub drives: Vec<ReadOnlyDrive>,
    pub blocks: Vec<ReadOnlyBlock>,
}

fn valid_owner(owner: &str) -> bool {
    owner.starts_with(':')
        && owner.len() <= 128
        && owner[1..].split('.').count() >= 2
        && owner[1..]
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn bus_owner(bus: &Proxy<'_>) -> Result<String, ProviderError> {
    let owner: String = bus
        .call("GetNameOwner", &(SERVICE,))
        .map_err(provider_bus_error)?;
    if !valid_owner(&owner) {
        return Err(ProviderError::InvalidState(
            "invalid UDisks2 unique owner".into(),
        ));
    }
    Ok(owner)
}

fn object_path(path: &str, prefix: &str) -> bool {
    path.starts_with(prefix)
        && path.len() > prefix.len()
        && path.len() <= 256
        && path[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn mount_point(bytes: &[u8]) -> Result<String, ProviderError> {
    let Some((&0, path)) = bytes.split_last() else {
        return Err(ProviderError::InvalidState(
            "mount path lacks trailing NUL".into(),
        ));
    };
    let path = std::str::from_utf8(path)
        .map_err(|_| ProviderError::InvalidState("mount path is not UTF-8".into()))?;
    if !path.starts_with('/')
        || path.len() > 4096
        || path
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
        || path
            .split('/')
            .any(|component| component == "." || component == "..")
    {
        return Err(ProviderError::InvalidState("malformed mount path".into()));
    }
    Ok(path.to_owned())
}

fn decode(
    owner: String,
    objects: ManagedObjects,
) -> Result<ReadOnlyStorageInventory, ProviderError> {
    if !valid_owner(&owner) || objects.len() > MAX_OBJECTS {
        return Err(ProviderError::InvalidState(
            "unbounded UDisks2 inventory".into(),
        ));
    }
    let mut drives = Vec::new();
    let mut blocks = Vec::new();
    let mut numbers = BTreeSet::new();
    for (path, interfaces) in &objects {
        let name = path.as_str();
        if !name.starts_with(MANAGER_PATH) {
            return Err(ProviderError::InvalidState("foreign UDisks2 object".into()));
        }
        if let Some(properties) = interfaces.get(DRIVE_INTERFACE) {
            if !object_path(name, "/org/freedesktop/UDisks2/drives/") {
                return Err(ProviderError::InvalidState(
                    "invalid UDisks2 drive path".into(),
                ));
            }
            drives.push(ReadOnlyDrive {
                path: name.into(),
                removable: snapshot_property(properties, "Removable")?,
                media_available: snapshot_property(properties, "MediaAvailable")?,
                ejectable: snapshot_property(properties, "Ejectable")?,
                can_power_off: snapshot_property(properties, "CanPowerOff")?,
                seat: snapshot_property(properties, "Seat")?,
                connection_bus: snapshot_property(properties, "ConnectionBus")?,
                sibling_id: snapshot_property(properties, "SiblingId")?,
            });
        }
        if let Some(properties) = interfaces.get(BLOCK_INTERFACE) {
            if !object_path(name, "/org/freedesktop/UDisks2/block_devices/") {
                return Err(ProviderError::InvalidState(
                    "invalid UDisks2 block path".into(),
                ));
            }
            let number: u64 = snapshot_property(properties, "DeviceNumber")?;
            if number == 0 || !numbers.insert(number) {
                return Err(ProviderError::InvalidState(
                    "duplicate block device identity".into(),
                ));
            }
            let drive: OwnedObjectPath = snapshot_property(properties, "Drive")?;
            let backing: OwnedObjectPath = snapshot_property(properties, "CryptoBackingDevice")?;
            let raid: OwnedObjectPath = snapshot_property(properties, "MDRaid")?;
            let raid_member: OwnedObjectPath = snapshot_property(properties, "MDRaidMember")?;
            let filesystem = interfaces.get(FILESYSTEM_INTERFACE);
            let mount_points = if let Some(filesystem) = filesystem {
                let encoded: Vec<Vec<u8>> = snapshot_property(filesystem, "MountPoints")?;
                if encoded.len() > 8 {
                    return Err(ProviderError::InvalidState("too many mount points".into()));
                }
                let result = encoded
                    .iter()
                    .map(|value| mount_point(value))
                    .collect::<Result<Vec<_>, _>>()?;
                if result.iter().collect::<BTreeSet<_>>().len() != result.len() {
                    return Err(ProviderError::InvalidState("duplicate mount points".into()));
                }
                result
            } else {
                Vec::new()
            };
            let partition_number = interfaces
                .get(PARTITION_INTERFACE)
                .map(|part| snapshot_property::<u32>(part, "Number"))
                .transpose()?;
            let partition_table = interfaces
                .get(PARTITION_INTERFACE)
                .map(|part| snapshot_property::<OwnedObjectPath>(part, "Table"))
                .transpose()?;
            blocks.push(ReadOnlyBlock {
                path: name.into(),
                drive: (drive.as_str() != "/").then(|| drive.as_str().into()),
                device_number: number,
                hint_system: snapshot_property(properties, "HintSystem")?,
                hint_ignore: snapshot_property(properties, "HintIgnore")?,
                crypto_backing_device: non_root_path(backing.as_str()),
                mdraid: non_root_path(raid.as_str()),
                mdraid_member: non_root_path(raid_member.as_str()),
                partition_table: partition_table.and_then(|table| non_root_path(table.as_str())),
                mount_points,
                has_filesystem: filesystem.is_some(),
                partition_number,
            });
        }
    }
    if drives.len() > 32 || blocks.len() > 128 {
        return Err(ProviderError::InvalidState(
            "storage inventory limit exceeded".into(),
        ));
    }
    resolve_block_ancestry(&mut blocks, &drives)?;
    drives.sort_by(|a, b| a.path.cmp(&b.path));
    blocks.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(ReadOnlyStorageInventory {
        unique_owner: owner,
        drives,
        blocks,
    })
}

/// UDisks2's root object reference represents no relationship.
fn non_root_path(value: &str) -> Option<String> {
    (value != "/").then(|| value.to_owned())
}

/// Resolve one partition through its actual table/parent block. Unknown,
/// cyclic or contradictory ancestry is denied rather than inferred from a
/// convenient /dev/sdX name or filesystem label.
fn resolve_block_ancestry(
    blocks: &mut [ReadOnlyBlock],
    drives: &[ReadOnlyDrive],
) -> Result<(), ProviderError> {
    let known_drives: BTreeSet<_> = drives.iter().map(|drive| drive.path.as_str()).collect();
    let parent: std::collections::BTreeMap<_, _> = blocks
        .iter()
        .map(|block| {
            (
                block.path.clone(),
                (block.drive.clone(), block.partition_table.clone()),
            )
        })
        .collect();
    for block in blocks {
        if block.partition_number.is_some() && block.partition_table.is_none() {
            return Err(ProviderError::InvalidState(
                "partition has no resolvable parent table".into(),
            ));
        }
        if let Some(table) = &block.partition_table {
            if table == &block.path {
                return Err(ProviderError::InvalidState(
                    "partition references itself as a parent".into(),
                ));
            }
            let Some((parent_drive, parent_table)) = parent.get(table) else {
                return Err(ProviderError::InvalidState(
                    "partition table parent is absent from complete inventory".into(),
                ));
            };
            if parent_table.is_some() || parent_drive.is_none() {
                return Err(ProviderError::InvalidState(
                    "nested or unassociated partition ancestry is unsupported".into(),
                ));
            }
            if block.drive.is_some() && block.drive != *parent_drive {
                return Err(ProviderError::InvalidState(
                    "partition ancestry conflicts with direct drive identity".into(),
                ));
            }
            block.drive.clone_from(parent_drive);
        }
        if block
            .drive
            .as_deref()
            .is_some_and(|path| !known_drives.contains(path))
        {
            return Err(ProviderError::InvalidState(
                "block ancestry references an unknown drive".into(),
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeStorageSafetyError {
    UnknownDrive,
    WrongSeatOrNonUsb,
    UnprovenSiblingGroup,
    MountedOrUnsafeSibling,
    IncompleteTopology,
}

/// Read-only advisory physical-group review. A successful review is *not*
/// permission to eject, mount, power off or change media. Before any effect,
/// kernel ancestry, real logind subject, device generation, busy processes,
/// approved Control plan and independent verification must be established.
pub fn review_read_only_drive_group(
    inventory: &ReadOnlyStorageInventory,
    expected_seat: &str,
    selected_drive: &str,
) -> Result<usize, NativeStorageSafetyError> {
    if expected_seat.is_empty() || expected_seat.len() > 128 {
        return Err(NativeStorageSafetyError::WrongSeatOrNonUsb);
    }
    let drive = inventory
        .drives
        .iter()
        .find(|drive| drive.path == selected_drive)
        .ok_or(NativeStorageSafetyError::UnknownDrive)?;
    if drive.seat != expected_seat
        || drive.connection_bus != "usb"
        || !drive.removable
        || !drive.media_available
    {
        return Err(NativeStorageSafetyError::WrongSeatOrNonUsb);
    }
    if drive.sibling_id.is_empty() || drive.sibling_id.len() > 256 {
        return Err(NativeStorageSafetyError::UnprovenSiblingGroup);
    }
    let siblings: BTreeSet<_> = inventory
        .drives
        .iter()
        .filter(|candidate| {
            candidate.sibling_id == drive.sibling_id
                && candidate.connection_bus == "usb"
                && candidate.seat == drive.seat
        })
        .map(|candidate| candidate.path.as_str())
        .collect();
    if inventory.drives.iter().any(|candidate| {
        candidate.sibling_id == drive.sibling_id
            && (candidate.seat != drive.seat || candidate.connection_bus != "usb")
    }) {
        return Err(NativeStorageSafetyError::UnprovenSiblingGroup);
    }
    if siblings.is_empty()
        || siblings.iter().any(|path| {
            !inventory
                .blocks
                .iter()
                .any(|block| block.drive.as_deref() == Some(*path))
        })
        || inventory
            .blocks
            .iter()
            .any(|block| block.drive.is_none() && block.partition_table.is_some())
    {
        return Err(NativeStorageSafetyError::IncompleteTopology);
    }
    let affected: Vec<_> = inventory
        .blocks
        .iter()
        .filter(|block| {
            block
                .drive
                .as_deref()
                .is_some_and(|path| siblings.contains(path))
        })
        .collect();
    if affected.is_empty() {
        return Err(NativeStorageSafetyError::IncompleteTopology);
    }
    if affected.iter().any(|block| {
        block.hint_system
            || block.hint_ignore
            || block.crypto_backing_device.is_some()
            || block.mdraid.is_some()
            || block.mdraid_member.is_some()
            || !block.mount_points.is_empty()
    }) {
        return Err(NativeStorageSafetyError::MountedOrUnsafeSibling);
    }
    Ok(affected.len())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadOnlySessionScope {
    /// Correlation with the actual logind owner, never a Polkit subject permit.
    pub logind_unique_owner: String,
    pub boot_id: String,
    pub session_id: String,
    pub seat_id: String,
    pub uid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopedReadOnlyStorage {
    pub session: ReadOnlySessionScope,
    pub inventory: ReadOnlyStorageInventory,
    /// Independent *candidate* evidence from this process's mount namespace.
    /// Cannot qualify the actual Polkit caller or authorization.
    pub kernel_mount_review: crate::removable_storage_kernel::KernelMountReview,
}

/// Validate the second native observation against the first. A caller-provided
/// session ID/UID is *not* a verified invocation identity: Control must supply
/// a separately authenticated Authority1 subject.
fn require_stable_session(
    first: &ReadOnlySessionScope,
    second: &ReadOnlySessionScope,
) -> Result<(), ProviderError> {
    if first != second {
        return Err(ProviderError::Unavailable(
            "logind session, seat, owner or boot changed during storage observation".into(),
        ));
    }
    Ok(())
}

fn native_logind_scope(
    connection: &Connection,
    session_id: &str,
    expected_uid: u32,
) -> Result<ReadOnlySessionScope, ProviderError> {
    if expected_uid == 0
        || session_id.is_empty()
        || session_id.len() > 128
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ProviderError::InvalidState(
            "storage observation requires a bounded non-root logind session".into(),
        ));
    }
    let bus = Proxy::new(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .map_err(provider_bus_error)?;
    let logind: String = bus
        .call("GetNameOwner", &("org.freedesktop.login1",))
        .map_err(provider_bus_error)?;
    if !valid_owner(&logind) {
        return Err(ProviderError::InvalidState(
            "logind has an invalid system-bus owner".into(),
        ));
    }
    let owner_uid: u32 = bus
        .call("GetConnectionUnixUser", &(logind.as_str(),))
        .map_err(provider_bus_error)?;
    if owner_uid != 0 {
        return Err(ProviderError::InvalidState(
            "logind system-bus owner is not root".into(),
        ));
    }
    let manager = Proxy::new(
        connection,
        logind.as_str(),
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    )
    .map_err(provider_bus_error)?;
    let path: OwnedObjectPath = manager
        .call("GetSession", &(session_id,))
        .map_err(provider_bus_error)?;
    if path.as_str().len() > 256
        || !path
            .as_str()
            .starts_with("/org/freedesktop/login1/session/")
    {
        return Err(ProviderError::InvalidState(
            "logind returned an unsupported session object".into(),
        ));
    }
    let session = Proxy::new(
        connection,
        logind.as_str(),
        path.as_str(),
        "org.freedesktop.login1.Session",
    )
    .map_err(provider_bus_error)?;
    let observed_id: String = session.get_property("Id").map_err(provider_bus_error)?;
    let user: (u32, OwnedObjectPath) = session.get_property("User").map_err(provider_bus_error)?;
    let seat: (String, OwnedObjectPath) =
        session.get_property("Seat").map_err(provider_bus_error)?;
    let active: bool = session.get_property("Active").map_err(provider_bus_error)?;
    let remote: bool = session.get_property("Remote").map_err(provider_bus_error)?;
    let class: String = session.get_property("Class").map_err(provider_bus_error)?;
    if observed_id != session_id
        || user.0 != expected_uid
        || !active
        || remote
        || class != "user"
        || seat.0.is_empty()
        || seat.0.len() > 128
        || !seat
            .0
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || !seat.1.as_str().starts_with("/org/freedesktop/login1/seat/")
    {
        return Err(ProviderError::InvalidState(
            "storage session ownership, seat or activity is not qualified".into(),
        ));
    }
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| ProviderError::Unavailable("kernel boot identity unavailable".into()))?;
    let boot_id = boot_id.trim();
    if boot_id.len() != 36
        || !boot_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        return Err(ProviderError::InvalidState(
            "kernel boot identity is malformed".into(),
        ));
    }
    let fresh_owner: String = bus
        .call("GetNameOwner", &("org.freedesktop.login1",))
        .map_err(provider_bus_error)?;
    if fresh_owner != logind {
        return Err(ProviderError::Unavailable(
            "logind owner replaced during native session observation".into(),
        ));
    }
    Ok(ReadOnlySessionScope {
        logind_unique_owner: logind.clone(),
        boot_id: boot_id.into(),
        session_id: observed_id,
        seat_id: seat.0,
        uid: expected_uid,
    })
}

/// A native read-only join, not a mutation authorization. The session
/// selection must originate at the separately authenticated Authority1
/// boundary and cannot substitute for the Polkit caller's actual D-Bus peer.
pub fn observe_scoped_native_storage(
    session_id: &str,
    expected_uid: u32,
) -> Result<ScopedReadOnlyStorage, ProviderError> {
    let started = Instant::now();
    let connection = connect_native_bus()?;
    let session = native_logind_scope(&connection, session_id, expected_uid)?;
    let inventory = inventory_from_bus(&connection)?;
    let kernel = crate::removable_storage_kernel::sample_kernel_mountinfo()?;
    let kernel_mount_review =
        crate::removable_storage_kernel::review_udisks_kernel_mount_state(&inventory, &kernel);
    if kernel_mount_review.decision
        != crate::removable_storage_kernel::KernelMountDecision::CandidateConsistent
    {
        return Err(ProviderError::InvalidState(
            "kernel mount namespace does not corroborate UDisks2 mount state".into(),
        ));
    }
    let after = native_logind_scope(&connection, session_id, expected_uid)?;
    require_stable_session(&session, &after)?;
    if started.elapsed() >= TOTAL_BUDGET {
        return Err(ProviderError::Unavailable(
            "scoped storage native observation exceeded its bounded deadline".into(),
        ));
    }
    Ok(ScopedReadOnlyStorage {
        session,
        inventory,
        kernel_mount_review,
    })
}

/// Repeated native observations must agree, but are not Polkit approval,
/// an execution permit, or independent physical-device generation proof.
fn read_snapshot(
    manager: &Proxy<'_>,
    owner: &str,
) -> Result<ReadOnlyStorageInventory, ProviderError> {
    let reply = manager
        .call_method("GetManagedObjects", &())
        .map_err(provider_bus_error)?;
    if reply.body().len() > MAX_REPLY_BYTES {
        return Err(ProviderError::InvalidState(
            "UDisks2 reply too large".into(),
        ));
    }
    let objects: ManagedObjects = reply.body().deserialize().map_err(provider_bus_error)?;
    decode(owner.to_owned(), objects)
}

fn require_stable_inventory(
    first: &ReadOnlyStorageInventory,
    fresh: &ReadOnlyStorageInventory,
) -> Result<(), ProviderError> {
    if first != fresh {
        return Err(ProviderError::Unavailable(
            "UDisks2 native inventory changed between observations".into(),
        ));
    }
    Ok(())
}

/// Reads bounded native state from a root-owned system bus and a stable,
/// unique root-owned UDisks2 service. It never issues a mutating call.
fn connect_native_bus() -> Result<Connection, ProviderError> {
    let stream = crate::platform_discovery::connect_unix_with_deadline(
        Path::new("/run/dbus/system_bus_socket"),
        TIMEOUT,
        "UDisks2 observation bus",
    )
    .map_err(|_| ProviderError::Unavailable("trusted system bus unavailable".into()))?;
    let credentials = socket_peercred(&stream)
        .map_err(|_| ProviderError::Unavailable("system bus peer inaccessible".into()))?;
    if credentials.uid.as_raw() != 0 {
        return Err(ProviderError::InvalidState(
            "system bus peer is not root".into(),
        ));
    }
    let builder = zbus::connection::Builder::async_io_unix_stream(stream).method_timeout(TIMEOUT);
    let connection: Connection = crate::platform_discovery::build_dbus_connection_with_deadline(
        builder,
        "UDisks2 observation bus",
    )
    .map_err(|_| ProviderError::Unavailable("system bus authentication failed".into()))?;
    Ok(connection)
}

pub fn observe_native_udisks_inventory() -> Result<ReadOnlyStorageInventory, ProviderError> {
    let connection = connect_native_bus()?;
    inventory_from_bus(&connection)
}

fn inventory_from_bus(connection: &Connection) -> Result<ReadOnlyStorageInventory, ProviderError> {
    let started = Instant::now();
    let bus = Proxy::new(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .map_err(provider_bus_error)?;
    let owner = bus_owner(&bus)?;
    let uid: u32 = bus
        .call("GetConnectionUnixUser", &(owner.as_str(),))
        .map_err(provider_bus_error)?;
    if uid != 0 {
        return Err(ProviderError::InvalidState(
            "UDisks2 owner is not root".into(),
        ));
    }
    let manager = Proxy::new(
        connection,
        owner.as_str(),
        MANAGER_PATH,
        "org.freedesktop.DBus.ObjectManager",
    )
    .map_err(provider_bus_error)?;
    let first = read_snapshot(&manager, &owner)?;
    if bus_owner(&bus)? != owner {
        return Err(ProviderError::Unavailable(
            "UDisks2 owner changed between native observations".into(),
        ));
    }
    let fresh = read_snapshot(&manager, &owner)?;
    require_stable_inventory(&first, &fresh)?;
    if bus_owner(&bus)? != owner || started.elapsed() >= TOTAL_BUDGET {
        return Err(ProviderError::Unavailable(
            "UDisks2 owner changed or timed out".into(),
        ));
    }
    Ok(fresh)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_session_is_not_accepted_after_a_seat_or_owner_swap() {
        let first = ReadOnlySessionScope {
            logind_unique_owner: ":1.5".into(),
            boot_id: "d3cd25af-38f2-4829-b42d-ef2bd35af042".into(),
            session_id: "c2".into(),
            seat_id: "seat0".into(),
            uid: 1000,
        };
        assert!(require_stable_session(&first, &first).is_ok());
        let mut second = first.clone();
        second.seat_id = "seat1".into();
        assert!(require_stable_session(&first, &second).is_err());
        second = first.clone();
        second.logind_unique_owner = ":1.6".into();
        assert!(require_stable_session(&first, &second).is_err());
        second = first.clone();
        second.uid = 1001;
        assert!(require_stable_session(&first, &second).is_err());
    }

    #[test]
    fn owner_and_paths_are_canonical() {
        assert!(valid_owner(":1.42"));
        assert!(!valid_owner("org.freedesktop.UDisks2"));
        assert!(!object_path(
            "/org/freedesktop/UDisks2/drives/../disk",
            "/org/freedesktop/UDisks2/drives/"
        ));
        assert!(decode("not-owner".into(), HashMap::new()).is_err());
    }

    #[test]
    fn rejects_changed_owner_or_media_between_native_observations() {
        let stable = ReadOnlyStorageInventory {
            unique_owner: ":1.42".into(),
            drives: Vec::new(),
            blocks: Vec::new(),
        };
        assert!(require_stable_inventory(&stable, &stable).is_ok());
        let mut changed = stable.clone();
        changed.unique_owner = ":1.43".into();
        assert!(require_stable_inventory(&stable, &changed).is_err());
        changed = stable.clone();
        changed.drives.push(ReadOnlyDrive {
            path: "/org/freedesktop/UDisks2/drives/usb1".into(),
            removable: true,
            media_available: true,
            ejectable: false,
            can_power_off: true,
            seat: "seat0".into(),
            connection_bus: "usb".into(),
            sibling_id: "usb-group-1".into(),
        });
        assert!(require_stable_inventory(&stable, &changed).is_err());
    }

    #[test]
    fn partition_parent_must_be_present_and_exact() {
        let mut blocks = vec![ReadOnlyBlock {
            path: "/org/freedesktop/UDisks2/block_devices/sdb1".into(),
            drive: None,
            device_number: 2050,
            hint_system: false,
            hint_ignore: false,
            crypto_backing_device: None,
            mdraid: None,
            mdraid_member: None,
            partition_table: Some("/org/freedesktop/UDisks2/block_devices/sdb".into()),
            mount_points: Vec::new(),
            has_filesystem: true,
            partition_number: Some(1),
        }];
        assert!(resolve_block_ancestry(&mut blocks, &[]).is_err());
        blocks.push(ReadOnlyBlock {
            path: "/org/freedesktop/UDisks2/block_devices/sdb".into(),
            drive: Some("/org/freedesktop/UDisks2/drives/usb1".into()),
            device_number: 2048,
            hint_system: false,
            hint_ignore: false,
            crypto_backing_device: None,
            mdraid: None,
            mdraid_member: None,
            partition_table: None,
            mount_points: Vec::new(),
            has_filesystem: false,
            partition_number: None,
        });
        let drives = vec![ReadOnlyDrive {
            path: "/org/freedesktop/UDisks2/drives/usb1".into(),
            removable: true,
            media_available: true,
            ejectable: true,
            can_power_off: true,
            seat: "seat0".into(),
            connection_bus: "usb".into(),
            sibling_id: "physical-group-1".into(),
        }];
        assert!(resolve_block_ancestry(&mut blocks, &drives).is_ok());
        assert_eq!(blocks[0].drive.as_deref(), Some(drives[0].path.as_str()));
    }

    #[test]
    fn read_only_group_does_not_ignore_mounted_or_foreign_siblings() {
        let mut inventory = ReadOnlyStorageInventory {
            unique_owner: ":1.42".into(),
            drives: vec![ReadOnlyDrive {
                path: "/org/freedesktop/UDisks2/drives/a".into(),
                removable: true,
                media_available: true,
                ejectable: true,
                can_power_off: true,
                seat: "seat0".into(),
                connection_bus: "usb".into(),
                sibling_id: "physical-group-1".into(),
            }],
            blocks: vec![ReadOnlyBlock {
                path: "/org/freedesktop/UDisks2/block_devices/sda1".into(),
                drive: Some("/org/freedesktop/UDisks2/drives/a".into()),
                device_number: 2049,
                hint_system: false,
                hint_ignore: false,
                crypto_backing_device: None,
                mdraid: None,
                mdraid_member: None,
                partition_table: None,
                mount_points: Vec::new(),
                has_filesystem: true,
                partition_number: None,
            }],
        };
        assert_eq!(
            review_read_only_drive_group(&inventory, "seat0", &inventory.drives[0].path),
            Ok(1)
        );
        inventory.blocks[0]
            .mount_points
            .push("/run/media/usb".into());
        assert_eq!(
            review_read_only_drive_group(&inventory, "seat0", &inventory.drives[0].path),
            Err(NativeStorageSafetyError::MountedOrUnsafeSibling)
        );
        inventory.blocks[0].mount_points.clear();
        let mut second_drive = inventory.drives[0].clone();
        second_drive.path = "/org/freedesktop/UDisks2/drives/b".into();
        second_drive.seat = "seat1".into();
        inventory.drives.push(second_drive);
        assert_eq!(
            review_read_only_drive_group(&inventory, "seat0", &inventory.drives[0].path),
            Err(NativeStorageSafetyError::UnprovenSiblingGroup)
        );
        inventory.drives[1].seat = "seat0".into();
        // Once the second sibling's block is accounted for, the protected
        // system media on the first drive must still block the entire group.
        let mut other_block = inventory.blocks[0].clone();
        other_block.path = "/org/freedesktop/UDisks2/block_devices/sdb1".into();
        other_block.drive = Some(inventory.drives[1].path.clone());
        other_block.device_number = 2050;
        inventory.blocks.push(other_block);
        inventory.blocks[0].hint_system = true;
        assert_eq!(
            review_read_only_drive_group(&inventory, "seat0", &inventory.drives[0].path),
            Err(NativeStorageSafetyError::MountedOrUnsafeSibling)
        );
    }

    #[test]
    fn missing_sibling_block_lineage_is_not_safe_for_removal() {
        let inventory_drive = ReadOnlyDrive {
            path: "/org/freedesktop/UDisks2/drives/a".into(),
            removable: true,
            media_available: true,
            ejectable: true,
            can_power_off: true,
            seat: "seat0".into(),
            connection_bus: "usb".into(),
            sibling_id: "group-1".into(),
        };
        let mut inventory = ReadOnlyStorageInventory {
            unique_owner: ":1.42".into(),
            drives: vec![inventory_drive.clone()],
            blocks: vec![ReadOnlyBlock {
                path: "/org/freedesktop/UDisks2/block_devices/sda".into(),
                drive: Some(inventory_drive.path.clone()),
                device_number: 2048,
                hint_system: false,
                hint_ignore: false,
                crypto_backing_device: None,
                mdraid: None,
                mdraid_member: None,
                partition_table: None,
                mount_points: Vec::new(),
                has_filesystem: false,
                partition_number: None,
            }],
        };
        let mut second = inventory_drive;
        second.path = "/org/freedesktop/UDisks2/drives/b".into();
        inventory.drives.push(second);
        assert_eq!(
            review_read_only_drive_group(&inventory, "seat0", &inventory.drives[0].path),
            Err(NativeStorageSafetyError::IncompleteTopology)
        );
    }

    #[test]
    fn mountpoints_are_bounded_and_nul_terminated() {
        assert_eq!(
            mount_point(b"/run/media/usb\0").ok().as_deref(),
            Some("/run/media/usb")
        );
        for invalid in [
            b"relative\0".as_slice(),
            b"/tmp/../root\0",
            b"/tmp/unclosed",
            b"/a\nb\0",
            b"/tmp\0internal\0",
        ] {
            assert!(mount_point(invalid).is_err());
        }
    }
}
