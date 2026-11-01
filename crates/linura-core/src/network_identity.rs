//! Canonical correlation identities for S18 NetworkManager resources.
//!
//! These values are NOT authority, trusted observations, or execution credentials.
//! A native adapter must independently attest every input against the live
//! system bus, NetworkManager owner, kernel namespace and native objects.
//! A typed identity cannot substitute for an authenticated principal, current
//! observation, reviewed plan, durable prepare, or independently verified effect.

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

use crate::BootId;

const MAX_INTERFACE_BYTES: usize = 15;
const MAX_UNIQUE_OWNER_BYTES: usize = 96;
const MAX_DEVICES: usize = 128;
const NM_OBJECT_ROOT: &str = "/org/freedesktop/NetworkManager/";

/// Errors contain no SSID, BSSID, profile name, password or untrusted value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkIdentityError {
    InvalidBusInstance,
    InvalidUniqueOwner,
    InvalidObjectPath,
    InvalidInterface,
    InvalidGeneration,
    InvalidNamespace,
    InvalidIfindex,
    InvalidProfileUuid,
    InvalidProfileFingerprint,
    MixedEpoch,
    AmbiguousDevice,
    TooManyDevices,
    ClockMismatch,
    StaleObservation,
}

impl Display for NetworkIdentityError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidBusInstance => "system bus instance is not canonical",
            Self::InvalidUniqueOwner => "NetworkManager unique owner is not canonical",
            Self::InvalidObjectPath => "NetworkManager native object path is not canonical",
            Self::InvalidInterface => "network interface name is not canonical",
            Self::InvalidGeneration => "network generation must be nonzero",
            Self::InvalidNamespace => "network namespace witness must be nonzero",
            Self::InvalidIfindex => "kernel interface index must be nonzero",
            Self::InvalidProfileUuid => "profile UUID is not canonical",
            Self::InvalidProfileFingerprint => "non-secret profile fingerprint is not canonical",
            Self::MixedEpoch => "network identities belong to different provider epochs",
            Self::AmbiguousDevice => "network device inventory contains ambiguous identities",
            Self::TooManyDevices => "network device inventory is over budget",
            Self::ClockMismatch => "network observation clock moved backward",
            Self::StaleObservation => "network observation is no longer fresh",
        })
    }
}

impl std::error::Error for NetworkIdentityError {}

fn nonzero_decimal(value: &str) -> Option<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let parsed = value.parse::<u64>().ok()?;
    (parsed != 0).then_some(parsed)
}

fn canonical_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && value.bytes().any(|byte| byte != b'0')
}

/// The native D-Bus `GetId` result; owner numbers can be reused if a bus is
/// restarted, so a unique owner without this bus-instance witness is unsafe.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SystemBusInstanceId(String);

impl SystemBusInstanceId {
    pub fn new(value: impl Into<String>) -> Result<Self, NetworkIdentityError> {
        let value = value.into();
        if !canonical_hex(&value, 32) {
            return Err(NetworkIdentityError::InvalidBusInstance);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A real unique system-bus name such as `:1.47`, not the replaceable
/// `org.freedesktop.NetworkManager` well-known name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkManagerOwner(String);

impl NetworkManagerOwner {
    pub fn new(value: impl Into<String>) -> Result<Self, NetworkIdentityError> {
        let value = value.into();
        if value.len() > MAX_UNIQUE_OWNER_BYTES || !valid_unique_owner(&value) {
            return Err(NetworkIdentityError::InvalidUniqueOwner);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_unique_owner(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix(':') else {
        return false;
    };
    // The real system-bus daemon uses numeric unique-name components. Do not
    // accept requestor-selected well-known names, aliases or noncanonical text.
    let mut parts = suffix.split('.');
    let Some(bus) = parts.next() else {
        return false;
    };
    if nonzero_decimal(bus).is_none() {
        return false;
    }
    let Some(serial) = parts.next() else {
        return false;
    };
    if serial.is_empty()
        || (serial.len() > 1 && serial.starts_with('0'))
        || !serial.bytes().all(|b| b.is_ascii_digit())
        || serial.parse::<u64>().is_err()
    {
        return false;
    }
    // Additional unique-name parts are not part of the native NM/system bus
    // identity contract and may not be supplied as an interchangeable owner.
    parts.next().is_none()
}

/// The owner epoch includes the boot AND the actual system-bus incarnation.
/// A typed epoch is merely correlation; the adapter still reobserves it.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkManagerEpoch {
    boot: BootId,
    bus: SystemBusInstanceId,
    owner: NetworkManagerOwner,
}

impl NetworkManagerEpoch {
    #[must_use]
    pub fn new(boot: BootId, bus: SystemBusInstanceId, owner: NetworkManagerOwner) -> Self {
        Self { boot, bus, owner }
    }

    #[must_use]
    pub const fn boot(&self) -> &BootId {
        &self.boot
    }

    #[must_use]
    pub const fn bus(&self) -> &SystemBusInstanceId {
        &self.bus
    }

    #[must_use]
    pub const fn owner(&self) -> &NetworkManagerOwner {
        &self.owner
    }

    pub fn require_same(&self, other: &Self) -> Result<(), NetworkIdentityError> {
        if self != other {
            return Err(NetworkIdentityError::MixedEpoch);
        }
        Ok(())
    }
}

/// The exact native object *family* prevents swapping a device path for an
/// ActiveConnection, AP or saved settings path with the same numeric suffix.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NetworkObjectKind {
    Device,
    AccessPoint,
    ActiveConnection,
    SettingsConnection,
}

impl NetworkObjectKind {
    const fn path_component(self) -> &'static str {
        match self {
            Self::Device => "Devices",
            Self::AccessPoint => "AccessPoint",
            Self::ActiveConnection => "ActiveConnection",
            Self::SettingsConnection => "Settings",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkObjectId {
    kind: NetworkObjectKind,
    sequence: u64,
}

impl NetworkObjectId {
    pub fn from_path(
        kind: NetworkObjectKind,
        path: &str,
    ) -> Result<Self, NetworkIdentityError> {
        let prefix = format!("{NM_OBJECT_ROOT}{}/", kind.path_component());
        let suffix = path.strip_prefix(&prefix).ok_or(NetworkIdentityError::InvalidObjectPath)?;
        if suffix.len() > 20 {
            return Err(NetworkIdentityError::InvalidObjectPath);
        }
        let sequence = nonzero_decimal(suffix).ok_or(NetworkIdentityError::InvalidObjectPath)?;
        Ok(Self { kind, sequence })
    }

    #[must_use]
    pub const fn kind(&self) -> NetworkObjectKind {
        self.kind
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// This reconstructs correlation data, NOT a native authority target.
    #[must_use]
    pub fn native_path(&self) -> String {
        format!("{NM_OBJECT_ROOT}{}/{}", self.kind.path_component(), self.sequence)
    }
}

/// A kernel ifname is an observation/correlation attribute, never an effect ID.
/// Reject non-ASCII or control/separator bytes rather than silently normalizing.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkInterfaceName(String);

impl NetworkInterfaceName {
    pub fn new(value: impl Into<String>) -> Result<Self, NetworkIdentityError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_INTERFACE_BYTES
            || value == "."
            || value == ".."
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(NetworkIdentityError::InvalidInterface);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Device generation is a required, nonzero *attested observation witness*.
/// A number invented by a client or local UI never proves a new native device.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkDeviceId {
    epoch: NetworkManagerEpoch,
    object: NetworkObjectId,
    namespace_inode: u64,
    ifindex: u32,
    interface: NetworkInterfaceName,
    generation: u64,
}

impl NetworkDeviceId {
    pub fn new(
        epoch: NetworkManagerEpoch,
        object: NetworkObjectId,
        namespace_inode: u64,
        ifindex: u32,
        interface: NetworkInterfaceName,
        generation: u64,
    ) -> Result<Self, NetworkIdentityError> {
        if object.kind != NetworkObjectKind::Device {
            return Err(NetworkIdentityError::InvalidObjectPath);
        }
        if namespace_inode == 0 {
            return Err(NetworkIdentityError::InvalidNamespace);
        }
        if ifindex == 0 {
            return Err(NetworkIdentityError::InvalidIfindex);
        }
        if generation == 0 {
            return Err(NetworkIdentityError::InvalidGeneration);
        }
        Ok(Self {
            epoch,
            object,
            namespace_inode,
            ifindex,
            interface,
            generation,
        })
    }

    #[must_use]
    pub const fn epoch(&self) -> &NetworkManagerEpoch {
        &self.epoch
    }

    #[must_use]
    pub const fn object(&self) -> &NetworkObjectId {
        &self.object
    }

    #[must_use]
    pub const fn namespace_inode(&self) -> u64 {
        self.namespace_inode
    }

    #[must_use]
    pub const fn ifindex(&self) -> u32 {
        self.ifindex
    }

    #[must_use]
    pub const fn interface(&self) -> &NetworkInterfaceName {
        &self.interface
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// A checked snapshot cannot conceal duplicate native paths, interface
/// aliases or kernel namespace+ifindex pairs. This is NOT mutation proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkDeviceInventory {
    epoch: NetworkManagerEpoch,
    devices: Vec<NetworkDeviceId>,
}

impl NetworkDeviceInventory {
    pub fn new(
        epoch: NetworkManagerEpoch,
        devices: Vec<NetworkDeviceId>,
    ) -> Result<Self, NetworkIdentityError> {
        if devices.len() > MAX_DEVICES {
            return Err(NetworkIdentityError::TooManyDevices);
        }
        let mut paths = BTreeSet::new();
        let mut interfaces = BTreeSet::new();
        let mut kernel_ids = BTreeSet::new();
        for device in &devices {
            epoch.require_same(&device.epoch)?;
            if !paths.insert(device.object.clone())
                || !interfaces.insert((device.namespace_inode, device.interface.clone()))
                || !kernel_ids.insert((device.namespace_inode, device.ifindex))
            {
                return Err(NetworkIdentityError::AmbiguousDevice);
            }
        }
        Ok(Self { epoch, devices })
    }

    #[must_use]
    pub const fn epoch(&self) -> &NetworkManagerEpoch {
        &self.epoch
    }

    #[must_use]
    pub fn devices(&self) -> &[NetworkDeviceId] {
        &self.devices
    }
}

/// A native AP has its own path and generation but may share SSID/BSSID
/// labels with another AP. Neither SSID nor BSSID is stored in this identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkAccessPointId {
    device: NetworkDeviceId,
    object: NetworkObjectId,
    observation_generation: u64,
}

impl NetworkAccessPointId {
    pub fn new(
        device: NetworkDeviceId,
        object: NetworkObjectId,
        observation_generation: u64,
    ) -> Result<Self, NetworkIdentityError> {
        if object.kind != NetworkObjectKind::AccessPoint {
            return Err(NetworkIdentityError::InvalidObjectPath);
        }
        if observation_generation == 0 {
            return Err(NetworkIdentityError::InvalidGeneration);
        }
        Ok(Self {
            device,
            object,
            observation_generation,
        })
    }

    #[must_use]
    pub const fn device(&self) -> &NetworkDeviceId {
        &self.device
    }

    #[must_use]
    pub const fn object(&self) -> &NetworkObjectId {
        &self.object
    }

    #[must_use]
    pub const fn observation_generation(&self) -> u64 {
        self.observation_generation
    }
}

/// An NM profile revision is correlated by owner, settings object, canonical
/// profile UUID, a required revision witness, and a digest of *non-secret*
/// normalized typed settings. A revision witness protects against ABA updates
/// that restore identical settings bytes. S18-8 must derive these witnesses
/// from independently attested native facts, not caller-supplied values.
/// A typed ID never grants compare-and-swap authority.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkProfileRevision {
    epoch: NetworkManagerEpoch,
    object: NetworkObjectId,
    uuid: String,
    revision_generation: u64,
    settings_fingerprint: String,
}

impl NetworkProfileRevision {
    pub fn new(
        epoch: NetworkManagerEpoch,
        object: NetworkObjectId,
        uuid: impl Into<String>,
        revision_generation: u64,
        settings_fingerprint: impl Into<String>,
    ) -> Result<Self, NetworkIdentityError> {
        if object.kind != NetworkObjectKind::SettingsConnection {
            return Err(NetworkIdentityError::InvalidObjectPath);
        }
        let uuid = uuid.into();
        if !canonical_uuid(&uuid) {
            return Err(NetworkIdentityError::InvalidProfileUuid);
        }
        if revision_generation == 0 {
            return Err(NetworkIdentityError::InvalidGeneration);
        }
        let settings_fingerprint = settings_fingerprint.into();
        if !canonical_hex(&settings_fingerprint, 64) {
            return Err(NetworkIdentityError::InvalidProfileFingerprint);
        }
        Ok(Self {
            epoch,
            object,
            uuid,
            revision_generation,
            settings_fingerprint,
        })
    }

    #[must_use]
    pub const fn epoch(&self) -> &NetworkManagerEpoch {
        &self.epoch
    }

    #[must_use]
    pub const fn object(&self) -> &NetworkObjectId {
        &self.object
    }

    #[must_use]
    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    #[must_use]
    pub const fn revision_generation(&self) -> u64 {
        self.revision_generation
    }

    #[must_use]
    pub fn settings_fingerprint(&self) -> &str {
        &self.settings_fingerprint
    }
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value != "00000000-0000-0000-0000-000000000000"
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                matches!(byte, b'0'..=b'9' | b'a'..=b'f')
            }
        })
}

/// An active connection may have no saved profile (e.g. transient NM state).
/// Do not infer persistence from a live active-connection object.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkActiveConnectionId {
    device: NetworkDeviceId,
    object: NetworkObjectId,
    profile: Option<NetworkProfileRevision>,
    activation_generation: u64,
}

impl NetworkActiveConnectionId {
    pub fn new(
        device: NetworkDeviceId,
        object: NetworkObjectId,
        profile: Option<NetworkProfileRevision>,
        activation_generation: u64,
    ) -> Result<Self, NetworkIdentityError> {
        if object.kind != NetworkObjectKind::ActiveConnection {
            return Err(NetworkIdentityError::InvalidObjectPath);
        }
        if activation_generation == 0 {
            return Err(NetworkIdentityError::InvalidGeneration);
        }
        if let Some(profile) = &profile {
            device.epoch.require_same(&profile.epoch)?;
        }
        Ok(Self {
            device,
            object,
            profile,
            activation_generation,
        })
    }

    #[must_use]
    pub const fn device(&self) -> &NetworkDeviceId {
        &self.device
    }

    #[must_use]
    pub const fn object(&self) -> &NetworkObjectId {
        &self.object
    }

    #[must_use]
    pub fn profile(&self) -> Option<&NetworkProfileRevision> {
        self.profile.as_ref()
    }

    #[must_use]
    pub const fn activation_generation(&self) -> u64 {
        self.activation_generation
    }
}

/// A local observation checkpoint. Equal generation numbers on different
/// owners/buses/boots are never equivalent. Freshness alone is NOT an
/// independently attested native postcondition or an atomic multi-object view.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkObservationId {
    epoch: NetworkManagerEpoch,
    generation: u64,
    observed_monotonic_us: u64,
}

impl NetworkObservationId {
    pub fn new(
        epoch: NetworkManagerEpoch,
        generation: u64,
        observed_monotonic_us: u64,
    ) -> Result<Self, NetworkIdentityError> {
        if generation == 0 || observed_monotonic_us == 0 {
            return Err(NetworkIdentityError::InvalidGeneration);
        }
        Ok(Self {
            epoch,
            generation,
            observed_monotonic_us,
        })
    }

    #[must_use]
    pub const fn epoch(&self) -> &NetworkManagerEpoch {
        &self.epoch
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The caller supplies a monotonic clock from the *same kernel boot* and
    /// rechecks the live provider epoch separately. A timestamp cannot attest
    /// an epoch; unknown/current time going backward is denied.
    pub fn require_fresh(
        &self,
        current_epoch: &NetworkManagerEpoch,
        now_monotonic_us: u64,
        max_age_us: u64,
    ) -> Result<(), NetworkIdentityError> {
        self.epoch.require_same(current_epoch)?;
        if now_monotonic_us < self.observed_monotonic_us {
            return Err(NetworkIdentityError::ClockMismatch);
        }
        if max_age_us == 0
            || now_monotonic_us - self.observed_monotonic_us > max_age_us
        {
            return Err(NetworkIdentityError::StaleObservation);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: &str = "abcd1234-1234-4567-89ab-0123456789ab";
    const BUS: &str = "fedcba9876543210abcdef0123456789";
    const UUID: &str = "10203040-5060-7080-90ab-cdef12345678";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|e| panic!("{e:?}"))
    }

    fn epoch() -> NetworkManagerEpoch {
        NetworkManagerEpoch::new(
            ok(BootId::new(BOOT)),
            ok(SystemBusInstanceId::new(BUS)),
            ok(NetworkManagerOwner::new(":1.47")),
        )
    }

    fn object(kind: NetworkObjectKind, number: u32) -> NetworkObjectId {
        ok(NetworkObjectId::from_path(
            kind,
            &format!("{NM_OBJECT_ROOT}{}/{}", kind.path_component(), number),
        ))
    }

    fn device() -> NetworkDeviceId {
        ok(NetworkDeviceId::new(
            epoch(),
            object(NetworkObjectKind::Device, 1),
            4026531840,
            3,
            ok(NetworkInterfaceName::new("wlp2s0")),
            11,
        ))
    }

    fn profile() -> NetworkProfileRevision {
        ok(NetworkProfileRevision::new(
            epoch(),
            object(NetworkObjectKind::SettingsConnection, 7),
            UUID,
            7,
            DIGEST,
        ))
    }

    #[test]
    fn rejects_replaceable_service_and_noncanonical_bus_instances() {
        for name in [
            "",
            "org.freedesktop.NetworkManager",
            ":1",
            ":0.11",
            ":01.4",
            ":1.04",
            ":1.2.3",
            ":1.2\n",
            ":1.18446744073709551616",
        ] {
            assert!(NetworkManagerOwner::new(name).is_err(), "{name:?}");
        }
        assert!(NetworkManagerOwner::new(":1.0").is_ok());
        for bus in [
            "",
            "00000000000000000000000000000000",
            "FEDCBA9876543210ABCDEF0123456789",
            "fedcba9876543210abcdef012345678",
            "fedcba9876543210abcdef012345678g",
        ] {
            assert!(SystemBusInstanceId::new(bus).is_err(), "{bus:?}");
        }
        assert!(SystemBusInstanceId::new(BUS).is_ok());
    }

    #[test]
    fn epoch_is_strict_across_boot_bus_and_owner_replacement() {
        let original = epoch();
        let changed_boot = NetworkManagerEpoch::new(
            ok(BootId::new("abcd1234-1234-4567-89ab-0123456789ac")),
            original.bus.clone(),
            original.owner.clone(),
        );
        let changed_bus = NetworkManagerEpoch::new(
            original.boot.clone(),
            ok(SystemBusInstanceId::new("fedcba9876543210abcdef0123456788")),
            original.owner.clone(),
        );
        let changed_owner = NetworkManagerEpoch::new(
            original.boot.clone(),
            original.bus.clone(),
            ok(NetworkManagerOwner::new(":1.48")),
        );
        for changed in [&changed_boot, &changed_bus, &changed_owner] {
            assert_eq!(original.require_same(changed), Err(NetworkIdentityError::MixedEpoch));
            assert_ne!(&original, changed);
        }
        assert!(original.require_same(&original).is_ok());
    }

    #[test]
    fn native_object_paths_are_typed_canonical_and_bounded() {
        for kind in [
            NetworkObjectKind::Device,
            NetworkObjectKind::AccessPoint,
            NetworkObjectKind::ActiveConnection,
            NetworkObjectKind::SettingsConnection,
        ] {
            let id = object(kind, 9);
            assert_eq!(id.kind(), kind);
            assert_eq!(id.sequence(), 9);
            assert_eq!(ok(NetworkObjectId::from_path(kind, &id.native_path())), id);
        }
        for path in [
            "/org/freedesktop/NetworkManager/Devices/0",
            "/org/freedesktop/NetworkManager/Devices/01",
            "/org/freedesktop/NetworkManager/Devices/-1",
            "/org/freedesktop/NetworkManager/Devices/1/child",
            "/org/freedesktop/NetworkManager/Devices/18446744073709551616",
            "/org/freedesktop/NetworkManager/ActiveConnection/1",
            "/org/freedesktop/NetworkManager/Devices/1\n",
        ] {
            assert!(NetworkObjectId::from_path(NetworkObjectKind::Device, path).is_err(), "{path}");
        }
    }

    #[test]
    fn interface_names_are_ascii_kernel_scoped_not_free_form() {
        for name in ["", ".", "..", "enp0 s1", "wlán0", "eth0/0", "eth0:1", "eth0\n", "0123456789abcdef"] {
            assert!(NetworkInterfaceName::new(name).is_err(), "{name:?}");
        }
        for name in ["lo", "eth0", "wlan0", "enp0s31f6", "veth-a.b"] {
            assert!(NetworkInterfaceName::new(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn a_device_requires_namespace_ifindex_and_nonzero_generation() {
        let d = device();
        assert_eq!(d.interface().as_str(), "wlp2s0");
        assert_eq!(d.namespace_inode(), 4026531840);
        assert_eq!(d.ifindex(), 3);
        assert_eq!(d.generation(), 11);
        let mk = |ns, ifindex, gen, obj| NetworkDeviceId::new(
            epoch(), obj, ns, ifindex, ok(NetworkInterfaceName::new("wlp2s0")), gen,
        );
        assert_eq!(mk(0, 3, 1, object(NetworkObjectKind::Device, 1)).unwrap_err(), NetworkIdentityError::InvalidNamespace);
        assert_eq!(mk(1, 0, 1, object(NetworkObjectKind::Device, 1)).unwrap_err(), NetworkIdentityError::InvalidIfindex);
        assert_eq!(mk(1, 3, 0, object(NetworkObjectKind::Device, 1)).unwrap_err(), NetworkIdentityError::InvalidGeneration);
        assert_eq!(mk(1, 3, 1, object(NetworkObjectKind::AccessPoint, 1)).unwrap_err(), NetworkIdentityError::InvalidObjectPath);
    }

    #[test]
    fn device_inventory_rejects_duplicate_path_interface_ifindex_and_mixed_epoch() {
        let d = device();
        assert_eq!(ok(NetworkDeviceInventory::new(epoch(), vec![d.clone()])).devices(), &[d.clone()]);
        let duplicate_path = ok(NetworkDeviceId::new(
            epoch(), d.object.clone(), d.namespace_inode, d.ifindex + 1,
            ok(NetworkInterfaceName::new("wlan1")), d.generation + 1,
        ));
        let duplicate_ifname = ok(NetworkDeviceId::new(
            epoch(), object(NetworkObjectKind::Device, 9), d.namespace_inode, d.ifindex + 1,
            d.interface.clone(), d.generation + 1,
        ));
        let duplicate_ifindex = ok(NetworkDeviceId::new(
            epoch(), object(NetworkObjectKind::Device, 9), d.namespace_inode, d.ifindex,
            ok(NetworkInterfaceName::new("wlan1")), d.generation + 1,
        ));
        for other in [d.clone(), duplicate_path, duplicate_ifname, duplicate_ifindex] {
            assert_eq!(NetworkDeviceInventory::new(epoch(), vec![d.clone(), other]).unwrap_err(),
                NetworkIdentityError::AmbiguousDevice);
        }
        let swapped = ok(NetworkDeviceId::new(
            NetworkManagerEpoch::new(
                d.epoch.boot.clone(), d.epoch.bus.clone(),
                ok(NetworkManagerOwner::new(":1.48")),
            ),
            d.object.clone(), d.namespace_inode, d.ifindex,
            d.interface.clone(), d.generation,
        ));
        assert_eq!(NetworkDeviceInventory::new(epoch(), vec![swapped]).unwrap_err(), NetworkIdentityError::MixedEpoch);
        assert_eq!(NetworkDeviceInventory::new(epoch(), vec![d; 129]).unwrap_err(), NetworkIdentityError::TooManyDevices);
        assert!(NetworkDeviceInventory::new(epoch(), vec![]).is_ok());
    }

    #[test]
    fn same_ifindex_in_distinct_namespace_is_not_ambiguity() {
        let d = device();
        let another = ok(NetworkDeviceId::new(
            epoch(), object(NetworkObjectKind::Device, 8), d.namespace_inode+1,
            d.ifindex, d.interface.clone(), d.generation,
        ));
        assert!(NetworkDeviceInventory::new(epoch(), vec![d, another]).is_ok());
    }

    #[test]
    fn ap_generation_path_and_device_are_all_part_of_identity() {
        let d = device();
        let ap = ok(NetworkAccessPointId::new(
            d.clone(), object(NetworkObjectKind::AccessPoint, 2), 11,
        ));
        let next = ok(NetworkAccessPointId::new(d.clone(), ap.object.clone(), 12));
        assert_ne!(ap, next);
        let replaced = ok(NetworkAccessPointId::new(
            d, object(NetworkObjectKind::AccessPoint, 3), 11,
        ));
        assert_ne!(ap, replaced);
        assert_eq!(NetworkAccessPointId::new(device(), object(NetworkObjectKind::Device, 2), 11).unwrap_err(), NetworkIdentityError::InvalidObjectPath);
        assert_eq!(NetworkAccessPointId::new(device(), object(NetworkObjectKind::AccessPoint, 2), 0).unwrap_err(), NetworkIdentityError::InvalidGeneration);
    }

    #[test]
    fn saved_profile_revision_depends_on_object_uuid_fingerprint_and_owner() {
        let p = profile();
        let next = ok(NetworkProfileRevision::new(
            epoch(), p.object.clone(), UUID, 7,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdee",
        ));
        assert_ne!(p, next);
        let same_content_different_revision = ok(NetworkProfileRevision::new(
            epoch(), p.object.clone(), UUID, 8, DIGEST,
        ));
        assert_ne!(p, same_content_different_revision);
        assert_eq!(p.revision_generation(), 7);
        assert_eq!(NetworkProfileRevision::new(
            epoch(), p.object.clone(), UUID, 0, DIGEST,
        ).unwrap_err(), NetworkIdentityError::InvalidGeneration);
        let other_object = ok(NetworkProfileRevision::new(
            epoch(), object(NetworkObjectKind::SettingsConnection, 8), UUID, 7, DIGEST,
        ));
        assert_ne!(p, other_object);
        for uuid in ["", "00000000-0000-0000-0000-000000000000", "10203040-5060-7080-90AB-cdef12345678", "102030405060708090abcdef12345678"] {
            assert!(NetworkProfileRevision::new(epoch(), p.object.clone(), uuid, 7, DIGEST).is_err());
        }
        for digest in ["".to_string(), "0".repeat(64), "z".repeat(64), "A".repeat(64)] {
            assert!(NetworkProfileRevision::new(epoch(), p.object.clone(), UUID, 7, digest).is_err());
        }
    }

    #[test]
    fn active_connection_rejects_cross_epoch_profile_and_generation_replay() {
        let d = device();
        let active = ok(NetworkActiveConnectionId::new(
            d.clone(), object(NetworkObjectKind::ActiveConnection, 10),
            Some(profile()), 9,
        ));
        assert_eq!(active.profile(), Some(&profile()));
        let next = ok(NetworkActiveConnectionId::new(
            d.clone(), active.object.clone(), Some(profile()), 10,
        ));
        assert_ne!(active, next);
        assert!(NetworkActiveConnectionId::new(
            d.clone(), object(NetworkObjectKind::ActiveConnection, 10), None, 9,
        ).is_ok());
        assert_eq!(NetworkActiveConnectionId::new(
            d.clone(), active.object.clone(), None, 0,
        ).unwrap_err(), NetworkIdentityError::InvalidGeneration);
        let other_profile = ok(NetworkProfileRevision::new(
            NetworkManagerEpoch::new(
                ok(BootId::new(BOOT)),
                ok(SystemBusInstanceId::new(BUS)),
                ok(NetworkManagerOwner::new(":1.48")),
            ),
            object(NetworkObjectKind::SettingsConnection, 7), UUID, 7, DIGEST,
        ));
        assert_eq!(NetworkActiveConnectionId::new(
            d, active.object.clone(), Some(other_profile), 10,
        ).unwrap_err(), NetworkIdentityError::MixedEpoch);
    }

    #[test]
    fn observation_generation_is_exact_and_freshness_rejects_clock_and_age() {
        let seen = ok(NetworkObservationId::new(epoch(), 8, 100));
        assert_eq!(seen.generation(), 8);
        assert!(seen.require_fresh(&epoch(), 100, 50).is_ok());
        assert!(seen.require_fresh(&epoch(), 150, 50).is_ok());
        assert_eq!(seen.require_fresh(&epoch(), 151, 50), Err(NetworkIdentityError::StaleObservation));
        assert_eq!(seen.require_fresh(&epoch(), 99, 50), Err(NetworkIdentityError::ClockMismatch));
        assert_eq!(seen.require_fresh(&epoch(), 100, 0), Err(NetworkIdentityError::StaleObservation));
        let owner_changed = NetworkManagerEpoch::new(
            ok(BootId::new(BOOT)), ok(SystemBusInstanceId::new(BUS)),
            ok(NetworkManagerOwner::new(":1.48")),
        );
        assert_eq!(seen.require_fresh(&owner_changed, 120, 50), Err(NetworkIdentityError::MixedEpoch));
        assert_ne!(seen, ok(NetworkObservationId::new(epoch(), 9, 100)));
        assert!(NetworkObservationId::new(epoch(), 0, 100).is_err());
        assert!(NetworkObservationId::new(epoch(), 8, 0).is_err());
        // age math does not overflow, even for u64::MAX.
        assert!(seen.require_fresh(&epoch(), u64::MAX, u64::MAX).is_ok());
    }
}
