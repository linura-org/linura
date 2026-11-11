//! S18-2: passive, source-pinned NetworkManager observation.
//!
//! The well-known NM name is used only to discover the unique system-bus
//! owner. Every observation is pinned to that unique owner, bus instance and
//! kernel boot before and after its D-Bus reads. Nothing in this module calls
//! an NM mutation or obtains connection secrets.

use super::*;
use linura_core::{
    BootId, NetworkDeviceId, NetworkDeviceInventory, NetworkInterfaceName, NetworkManagerEpoch,
    NetworkManagerOwner, NetworkObjectId, NetworkObjectKind, NetworkProfileRevision,
    SystemBusInstanceId,
};
use sha2::{Digest, Sha256};
use std::net::IpAddr;

pub(super) const WIFI_CAPABILITY: &str = "networkmanager.wifi.observe";
pub(super) const CONNECTIONS_CAPABILITY: &str = "networkmanager.connections.observe";
pub(super) const IPCONFIG_CAPABILITY: &str = "networkmanager.ipconfig.observe";

const WIFI_PREFIX: &str = "networkmanager:wifi:";
const AP_PREFIX: &str = "networkmanager:ap:";
const CONNECTIONS_RESOURCE: &str = "networkmanager:connections";
const PROFILE_PREFIX: &str = "networkmanager:profile:";
const ACTIVE_PREFIX: &str = "networkmanager:active:";
const IP4_PREFIX: &str = "networkmanager:ip4:";
const IP6_PREFIX: &str = "networkmanager:ip6:";
const NM_WIRELESS_INTERFACE: &str = "org.freedesktop.NetworkManager.Device.Wireless";
const NM_AP_INTERFACE: &str = "org.freedesktop.NetworkManager.AccessPoint";
const NM_SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
const NM_SETTINGS_INTERFACE: &str = "org.freedesktop.NetworkManager.Settings";
const NM_PROFILE_INTERFACE: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const NM_ACTIVE_INTERFACE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const NM_IP4_INTERFACE: &str = "org.freedesktop.NetworkManager.IP4Config";
const NM_IP6_INTERFACE: &str = "org.freedesktop.NetworkManager.IP6Config";
const MAX_NETWORK_OBJECTS: usize = 256;
const MAX_ACCESS_POINTS: usize = 128;
const MAX_PROFILE_OBJECTS: usize = 128;
const MAX_IP_ROWS: usize = 128;
const MAX_IP_DICTIONARY_KEYS: usize = 24;
const MAX_DNS_ENTRIES: usize = 32;
const MAX_PROPERTY_KEYS: usize = 128;
// Guard the encoded D-Bus body before serde/zvariant deserializes it.
// The underlying zbus transport must still allocate the framed message;
// this is a decoder budget, not a claim of socket-level allocation control.
const MAX_NM_REPLY_BYTES: usize = 64 * 1024;
const MAX_NM_SETTINGS_SECTIONS: usize = 48;
const MAX_NM_SETTINGS_FIELDS: usize = 64;

fn invalid(label: &str) -> ProviderError {
    ProviderError::InvalidState(format!("NetworkManager {label} is invalid or ambiguous"))
}

fn typed<T, E: std::fmt::Display>(value: Result<T, E>, label: &str) -> Result<T, ProviderError> {
    value.map_err(|_| invalid(label))
}

// Bound encoded replies before invoking any dynamic D-Bus body decoding.
// A bounded reply can still have invalid structure: all typed decoding
// errors also fail closed. zvariant enforces D-Bus's nesting constraints.
fn within_decoder_budget(bytes: usize) -> bool {
    bytes <= MAX_NM_REPLY_BYTES
}

pub(super) fn require_bounded_body(message: &zbus::message::Message) -> Result<(), ProviderError> {
    if !within_decoder_budget(message.body().len()) {
        return Err(invalid("encoded D-Bus response exceeds decoder budget"));
    }
    Ok(())
}

pub(super) fn bounded_props(
    connection: &Connection,
    owner: &str,
    path: &str,
    interface: &str,
) -> Result<HashMap<String, OwnedValue>, ProviderError> {
    let proxy = Proxy::new(connection, owner, path, DBUS_PROPERTIES).map_err(provider_bus_error)?;
    let reply = proxy
        .call_method("GetAll", &(interface,))
        .map_err(provider_bus_error)?;
    require_bounded_body(&reply)?;
    let values: HashMap<String, OwnedValue> =
        reply.body().deserialize().map_err(provider_bus_error)?;
    if values.len() > MAX_PROPERTY_KEYS
        || values.keys().any(|key| key.len() > 96 || !key.is_ascii())
    {
        return Err(invalid("property inventory"));
    }
    Ok(values)
}

// The digest covers a bounded, normalized, secret-free subset of settings.
// The NM Settings.VersionId, not the digest alone, fences every profile edit
// (including changes outside this subset and ABA restoration).
fn profile_fingerprint(
    sections: &HashMap<String, HashMap<String, OwnedValue>>,
) -> Result<(String, String), ProviderError> {
    if sections.len() > MAX_NM_SETTINGS_SECTIONS {
        return Err(invalid("profile section inventory"));
    }
    for (name, values) in sections {
        if name.is_empty()
            || name.len() > 96
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || values.len() > MAX_NM_SETTINGS_FIELDS
            || values.keys().any(|key| {
                key.is_empty()
                    || key.len() > 96
                    || !key
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err(invalid("profile property inventory"));
        }
    }
    let connection = sections
        .get("connection")
        .ok_or_else(|| invalid("profile connection section"))?;
    let uuid: String = snapshot_property(connection, "uuid")?;
    let profile_type: String = snapshot_property(connection, "type")?;
    if profile_type.is_empty()
        || profile_type.len() > 64
        || !profile_type
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(invalid("profile connection type"));
    }
    // UUID validity is rechecked by NetworkProfileRevision::new. The
    // allowlisted normalized projection prevents secret-bearing arbitrary
    // variant values from crossing into Control observations or logs.
    let mut normalized = BTreeMap::<String, Vec<u8>>::new();
    normalized.insert("connection.uuid".into(), uuid.as_bytes().to_vec());
    normalized.insert("connection.type".into(), profile_type.into_bytes());
    for (section, field) in [
        ("connection", "interface-name"),
        ("ipv4", "method"),
        ("ipv6", "method"),
        ("802-11-wireless", "mode"),
    ] {
        if let Some(values) = sections.get(section)
            && values.contains_key(field)
        {
            let value: String = snapshot_property(values, field)?;
            bounded_nm_text("allowlisted profile setting", &value)?;
            if section == "connection" && field == "interface-name" {
                let _ = typed(
                    NetworkInterfaceName::new(value.as_str()),
                    "profile interface",
                )?;
            }
            normalized.insert(format!("{section}.{field}"), value.into_bytes());
        }
    }
    if connection.contains_key("autoconnect") {
        let enabled: bool = snapshot_property(connection, "autoconnect")?;
        normalized.insert("connection.autoconnect".into(), vec![u8::from(enabled)]);
    }
    if let Some(wifi) = sections.get("802-11-wireless")
        && wifi.contains_key("ssid")
    {
        let ssid: Vec<u8> = snapshot_property(wifi, "ssid")?;
        if ssid.is_empty() || ssid.len() > 32 {
            return Err(invalid("profile Wi-Fi SSID"));
        }
        normalized.insert("802-11-wireless.ssid".into(), ssid);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"linura-s18-profile-projection-v1\0");
    for (name, bytes) in normalized {
        let name = name.as_bytes();
        hasher.update((name.len() as u32).to_le_bytes());
        hasher.update(name);
        hasher.update((bytes.len() as u32).to_le_bytes());
        hasher.update(&bytes);
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut fingerprint = String::with_capacity(64);
    for byte in hasher.finalize().iter().copied() {
        fingerprint.push(char::from(HEX[usize::from(byte >> 4)]));
        fingerprint.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok((uuid, fingerprint))
}

fn parse_network_seq(path: &str, prefix: &str) -> Result<u64, ProviderError> {
    let suffix = path
        .strip_prefix(prefix)
        .ok_or_else(|| invalid("object path"))?;
    if suffix.is_empty()
        || suffix.len() > 20
        || suffix.starts_with('0')
        || !suffix.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid("object path"));
    }
    let value = suffix.parse::<u64>().map_err(|_| invalid("object path"))?;
    (value > 0)
        .then_some(value)
        .ok_or_else(|| invalid("object path"))
}

fn native_index(
    paths: Vec<OwnedObjectPath>,
    kind: NetworkObjectKind,
    maximum: usize,
) -> Result<BTreeMap<u64, OwnedObjectPath>, ProviderError> {
    if paths.len() > maximum {
        return Err(invalid("object inventory limit"));
    }
    let mut index = BTreeMap::new();
    for path in paths {
        let id = typed(
            NetworkObjectId::from_path(kind, path.as_str()),
            "object family",
        )?;
        if index.insert(id.sequence(), path).is_some() {
            return Err(invalid("duplicate native object"));
        }
    }
    Ok(index)
}

fn ip_index(
    paths: Vec<(bool, OwnedObjectPath)>,
) -> Result<BTreeMap<String, (bool, OwnedObjectPath)>, ProviderError> {
    if paths.len() > MAX_NETWORK_OBJECTS {
        return Err(invalid("IP configuration inventory limit"));
    }
    let mut index = BTreeMap::new();
    for (v6, path) in paths {
        let prefix = if v6 {
            "/org/freedesktop/NetworkManager/IP6Config/"
        } else {
            "/org/freedesktop/NetworkManager/IP4Config/"
        };
        let number = parse_network_seq(path.as_str(), prefix)?;
        let resource = format!("{}{number}", if v6 { IP6_PREFIX } else { IP4_PREFIX });
        if index.insert(resource, (v6, path)).is_some() {
            return Err(invalid("duplicate IP configuration"));
        }
    }
    Ok(index)
}

fn bounded_unique(
    paths: Vec<OwnedObjectPath>,
    maximum: usize,
) -> Result<Vec<OwnedObjectPath>, ProviderError> {
    if paths.len() > maximum {
        return Err(invalid("native object inventory limit"));
    }
    let mut seen = BTreeSet::new();
    for path in &paths {
        if !seen.insert(path.to_string()) {
            return Err(invalid("duplicate native path"));
        }
    }
    Ok(paths)
}

fn ip_row(
    values: &HashMap<String, OwnedValue>,
    family: u8,
    is_route: bool,
) -> Result<String, ProviderError> {
    if values.len() > MAX_IP_DICTIONARY_KEYS {
        return Err(invalid("IP row complexity"));
    }
    let field = if is_route { "dest" } else { "address" };
    let address: String = snapshot_property(values, field)?;
    let prefix: u32 = snapshot_property(values, "prefix")?;
    let parsed: IpAddr = address.parse().map_err(|_| invalid("IP address"))?;
    if (family == 4 && (!parsed.is_ipv4() || prefix > 32))
        || (family == 6 && (!parsed.is_ipv6() || prefix > 128))
    {
        return Err(invalid("IP address family/prefix"));
    }
    let mut row = format!("{parsed}/{prefix}");
    if is_route {
        if values.contains_key("next-hop") {
            let hop: String = snapshot_property(values, "next-hop")?;
            if !hop.is_empty() {
                let hop_ip: IpAddr = hop.parse().map_err(|_| invalid("route next-hop"))?;
                if (family == 4 && !hop_ip.is_ipv4()) || (family == 6 && !hop_ip.is_ipv6()) {
                    return Err(invalid("route next-hop family"));
                }
                row.push('|');
                row.push_str(&hop_ip.to_string());
            }
        }
        if values.contains_key("metric") {
            let metric: u32 = snapshot_property(values, "metric")?;
            row.push_str(&format!("|metric={metric}"));
        }
    }
    Ok(row)
}

fn ip_rows(
    attributes: &mut BTreeMap<String, ObservedValue>,
    properties: &HashMap<String, OwnedValue>,
    native: &str,
    name: &str,
    family: u8,
    is_route: bool,
) -> Result<(), ProviderError> {
    let entries: Vec<HashMap<String, OwnedValue>> = snapshot_property(properties, native)?;
    if entries.len() > MAX_IP_ROWS {
        return Err(invalid("IP row inventory limit"));
    }
    attributes.insert(
        format!("{name}_count"),
        ObservedValue::U64(entries.len() as u64),
    );
    for (index, row) in entries.iter().enumerate() {
        attributes.insert(
            format!("{name}_{index}"),
            ObservedValue::Text(ip_row(row, family, is_route)?),
        );
    }
    Ok(())
}

/// Validate only the bounded, visible profile UUID correlation. An empty
/// result is NOT a permission, uniqueness proof or authorization to create.
fn canonical_profile_uuid(value: &str) -> bool {
    value.len() == 36
        && value != "00000000-0000-0000-0000-000000000000"
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
}

fn reject_visible_uuid_collision(requested: &str, visible: &[String]) -> Result<(), ProviderError> {
    if !canonical_profile_uuid(requested) || visible.len() > MAX_PROFILE_OBJECTS {
        return Err(invalid(
            "requested profile UUID or visible inventory bounds",
        ));
    }
    let mut unique = BTreeSet::new();
    for uuid in visible {
        if !canonical_profile_uuid(uuid)
            || !unique.insert(uuid.as_str())
            || uuid.as_str() == requested
        {
            return Err(invalid(
                "duplicate or already existing visible profile UUID",
            ));
        }
    }
    Ok(())
}

impl NetworkManagerObserver {
    // The transport has a method timeout (configured in connect) independently
    // of these post-decode consistency checks. A sole unique owner is insufficient
    // after system-bus restart; GetId provides the bus incarnation.
    pub(super) fn native_epoch(&self) -> Result<NetworkManagerEpoch, ProviderError> {
        let boot = typed(BootId::new(nm_boot_id()?), "boot identity")?;
        let bus = Proxy::new(
            &self.connection,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .map_err(provider_bus_error)?;
        let reply = bus.call_method("GetId", &()).map_err(provider_bus_error)?;
        require_bounded_body(&reply)?;
        let id: String = reply.body().deserialize().map_err(provider_bus_error)?;
        let bus = typed(SystemBusInstanceId::new(id), "system bus instance")?;
        let owner = typed(
            NetworkManagerOwner::new(self.unique_owner()?),
            "unique NM owner",
        )?;
        Ok(NetworkManagerEpoch::new(boot, bus, owner))
    }

    pub(super) fn require_native_epoch(
        &self,
        wanted: &NetworkManagerEpoch,
    ) -> Result<(), ProviderError> {
        wanted.require_same(&self.native_epoch()?).map_err(|_| {
            ProviderError::Unavailable(
                "NetworkManager boot, bus, or unique owner changed during observation".into(),
            )
        })
    }

    // An alias or NM path alone cannot attest device identity. Kernel ifindex
    // is read from the current network namespace and cross-checked twice.
    pub(super) fn device_identity(
        &self,
        epoch: &NetworkManagerEpoch,
        path: &OwnedObjectPath,
        interface: &str,
    ) -> Result<NetworkDeviceId, ProviderError> {
        let object = typed(
            NetworkObjectId::from_path(NetworkObjectKind::Device, path.as_str()),
            "device object path",
        )?;
        let interface = typed(NetworkInterfaceName::new(interface), "kernel interface")?;
        let namespace = fs::metadata("/proc/self/ns/net")
            .map_err(|_| ProviderError::Unavailable("network namespace is unreadable".into()))?
            .ino();
        let file = format!("/sys/class/net/{}/ifindex", interface.as_str());
        let index: u32 = fs::read_to_string(&file)
            .map_err(|_| ProviderError::Unavailable("kernel interface disappeared".into()))?
            .trim()
            .parse()
            .map_err(|_| invalid("kernel ifindex"))?;
        let after_namespace = fs::metadata("/proc/self/ns/net")
            .map_err(|_| ProviderError::Unavailable("network namespace disappeared".into()))?
            .ino();
        let after_index: u32 = fs::read_to_string(&file)
            .map_err(|_| ProviderError::Unavailable("kernel interface disappeared".into()))?
            .trim()
            .parse()
            .map_err(|_| invalid("kernel ifindex"))?;
        if namespace != after_namespace || index == 0 || index != after_index {
            return Err(invalid("kernel device generation changed"));
        }
        typed(
            NetworkDeviceId::new(
                epoch.clone(),
                object.clone(),
                namespace,
                index,
                interface,
                object.sequence(),
            ),
            "kernel device generation",
        )
    }

    fn device_inventory(
        &self,
        epoch: &NetworkManagerEpoch,
    ) -> Result<NetworkDeviceInventory, ProviderError> {
        let owner = epoch.owner().as_str();
        let index = self.device_index(owner)?;
        let mut devices = Vec::with_capacity(index.len());
        for (interface, path) in index {
            devices.push(self.device_identity(epoch, &path, &interface)?);
        }
        let inventory = typed(
            NetworkDeviceInventory::new(epoch.clone(), devices),
            "device identity",
        )?;
        self.require_native_epoch(epoch)?;
        Ok(inventory)
    }

    fn wireless_index(
        &self,
        owner: &str,
        device: &OwnedObjectPath,
    ) -> Result<BTreeMap<u64, OwnedObjectPath>, ProviderError> {
        let proxy = Proxy::new(
            &self.connection,
            owner,
            device.as_str(),
            NM_WIRELESS_INTERFACE,
        )
        .map_err(provider_bus_error)?;
        // Passive enumeration only; no active wireless scanning operation.
        let reply = proxy
            .call_method("GetAllAccessPoints", &())
            .map_err(provider_bus_error)?;
        require_bounded_body(&reply)?;
        let paths: Vec<OwnedObjectPath> = reply.body().deserialize().map_err(provider_bus_error)?;
        native_index(paths, NetworkObjectKind::AccessPoint, MAX_ACCESS_POINTS)
    }

    fn wifi_devices(
        &self,
        epoch: &NetworkManagerEpoch,
    ) -> Result<BTreeMap<String, OwnedObjectPath>, ProviderError> {
        let mut devices = BTreeMap::new();
        for (interface, path) in self.device_index(epoch.owner().as_str())? {
            let props = bounded_props(
                &self.connection,
                epoch.owner().as_str(),
                path.as_str(),
                NM_DEVICE_INTERFACE,
            )?;
            let kind: u32 = snapshot_property(&props, "DeviceType")?;
            if kind == 2 {
                devices.insert(interface, path);
            }
        }
        self.require_native_epoch(epoch)?;
        Ok(devices)
    }

    fn active_index(&self, owner: &str) -> Result<BTreeMap<u64, OwnedObjectPath>, ProviderError> {
        let props = bounded_props(&self.connection, owner, NM_PATH, NM_INTERFACE)?;
        let paths: Vec<OwnedObjectPath> = snapshot_property(&props, "ActiveConnections")?;
        native_index(
            paths,
            NetworkObjectKind::ActiveConnection,
            MAX_PROFILE_OBJECTS,
        )
    }

    fn profile_index(&self, owner: &str) -> Result<BTreeMap<u64, OwnedObjectPath>, ProviderError> {
        let settings = Proxy::new(
            &self.connection,
            owner,
            NM_SETTINGS_PATH,
            NM_SETTINGS_INTERFACE,
        )
        .map_err(provider_bus_error)?;
        let reply = settings
            .call_method("ListConnections", &())
            .map_err(provider_bus_error)?;
        require_bounded_body(&reply)?;
        let paths: Vec<OwnedObjectPath> = reply.body().deserialize().map_err(provider_bus_error)?;
        native_index(
            paths,
            NetworkObjectKind::SettingsConnection,
            MAX_PROFILE_OBJECTS,
        )
    }

    fn require_same_settings_version(before: u64, after: u64) -> Result<(), ProviderError> {
        if before == 0 || before != after {
            return Err(invalid(
                "profile settings version changed during observation",
            ));
        }
        Ok(())
    }

    fn settings_version(&self, owner: &str) -> Result<u64, ProviderError> {
        // This is the *settings-wide* NM VersionId, not a per-profile
        // counter. It is intentionally conservative: any profile update
        // invalidates concurrently observed profile revision evidence.
        let props = bounded_props(
            &self.connection,
            owner,
            NM_SETTINGS_PATH,
            NM_SETTINGS_INTERFACE,
        )?;
        let version: u64 = snapshot_property(&props, "VersionId")?;
        if version == 0 {
            return Err(invalid("settings version is not attestable"));
        }
        Ok(version)
    }

    fn profile_revision(
        &self,
        epoch: &NetworkManagerEpoch,
        path: &OwnedObjectPath,
        old_properties: &HashMap<String, OwnedValue>,
    ) -> Result<NetworkProfileRevision, ProviderError> {
        let owner = epoch.owner().as_str();
        let before = self.settings_version(owner)?;
        let profile = Proxy::new(&self.connection, owner, path.as_str(), NM_PROFILE_INTERFACE)
            .map_err(provider_bus_error)?;
        // GetSettings is guaranteed by NM to exclude connection secrets.
        // The bounded reply is checked *before* dynamic map decoding. This
        // reader never calls GetSecrets or forwards raw profile maps.
        let reply = profile
            .call_method("GetSettings", &())
            .map_err(provider_bus_error)?;
        require_bounded_body(&reply)?;
        let settings: HashMap<String, HashMap<String, OwnedValue>> =
            reply.body().deserialize().map_err(provider_bus_error)?;
        let (uuid, fingerprint) = profile_fingerprint(&settings)?;
        let new_properties =
            bounded_props(&self.connection, owner, path.as_str(), NM_PROFILE_INTERFACE)?;
        let old_unsaved: bool = snapshot_property(old_properties, "Unsaved")?;
        let new_unsaved: bool = snapshot_property(&new_properties, "Unsaved")?;
        let old_flags: u32 = snapshot_property(old_properties, "Flags")?;
        let new_flags: u32 = snapshot_property(&new_properties, "Flags")?;
        if old_unsaved != new_unsaved || old_flags != new_flags {
            return Err(invalid("profile flags changed during observation"));
        }
        Self::require_same_settings_version(before, self.settings_version(owner)?)?;
        if self
            .profile_index(owner)?
            .values()
            .filter(|current| *current == path)
            .count()
            != 1
        {
            return Err(invalid("profile was modified during observation"));
        }
        self.require_native_epoch(epoch)?;
        let object = typed(
            NetworkObjectId::from_path(NetworkObjectKind::SettingsConnection, path.as_str()),
            "profile object",
        )?;
        typed(
            NetworkProfileRevision::new(epoch.clone(), object, uuid, before, fingerprint),
            "profile revision evidence",
        )
    }

    /// Read-only, double-source verification of an existing saved-profile
    /// revision. The actual unique NM owner, original settings path, UUID,
    /// global Settings.VersionId, secret-free fingerprint, flags and complete
    /// bounded native inventory must agree across dependent reads.
    ///
    /// This is a preflight *veto*, not native compare-and-swap, Polkit consent,
    /// a durable grant or a verified post-mutation state. An NM Update2/Delete
    /// dispatcher must still prove atomic revision safety independently.
    pub fn require_native_saved_profile_revision(
        &self,
        expected: &NetworkProfileRevision,
    ) -> Result<(), ProviderError> {
        let epoch = self.native_epoch()?;
        if epoch != *expected.epoch() {
            return Err(invalid("saved profile owner, bus or boot changed"));
        }
        let owner = epoch.owner().as_str();
        let before = self.profile_index(owner)?;
        let path = before
            .get(&expected.object().sequence())
            .ok_or_else(|| invalid("saved profile path is absent"))?;
        if path.as_str() != expected.object().native_path() {
            return Err(invalid("saved profile object path was substituted"));
        }
        let first_props =
            bounded_props(&self.connection, owner, path.as_str(), NM_PROFILE_INTERFACE)?;
        let first = self.profile_revision(&epoch, path, &first_props)?;
        if first != *expected {
            return Err(invalid("saved profile has a foreign or stale revision"));
        }
        let second_props =
            bounded_props(&self.connection, owner, path.as_str(), NM_PROFILE_INTERFACE)?;
        let second = self.profile_revision(&epoch, path, &second_props)?;
        if first != second || self.profile_index(owner)? != before {
            return Err(invalid("saved profile source changed during verification"));
        }
        self.require_native_epoch(&epoch)?;
        Ok(())
    }

    /// Bounded and source-pinned *visible-inventory veto* for future
    /// S18-8 create requests. D-Bus visibility depends on the authenticated
    /// caller; absence in ListConnections is not authoritative proof that
    /// another user's profile/UUID does not exist. A future native dispatcher
    /// must establish complete original-user, Polkit and global uniqueness
    /// evidence separately before AddConnection2 may be enabled.
    pub fn reject_existing_visible_profile_uuid(
        &self,
        original_epoch: &NetworkManagerEpoch,
        requested_uuid: &str,
    ) -> Result<(), ProviderError> {
        let current = self.native_epoch()?;
        if current != *original_epoch {
            return Err(invalid(
                "saved profile inventory owner, bus or boot changed",
            ));
        }
        let owner = current.owner().as_str();
        let initial_version = self.settings_version(owner)?;
        let initial_index = self.profile_index(owner)?;
        let mut found = Vec::with_capacity(initial_index.len());
        for path in initial_index.values() {
            let props =
                bounded_props(&self.connection, owner, path.as_str(), NM_PROFILE_INTERFACE)?;
            let profile = self.profile_revision(&current, path, &props)?;
            found.push(profile.uuid().to_owned());
        }
        if self.settings_version(owner)? != initial_version
            || self.profile_index(owner)? != initial_index
        {
            return Err(invalid("saved profile inventory changed during UUID check"));
        }
        self.require_native_epoch(&current)?;
        reject_visible_uuid_collision(requested_uuid, &found)
    }

    fn ip_resources(
        &self,
        epoch: &NetworkManagerEpoch,
    ) -> Result<BTreeMap<String, (bool, OwnedObjectPath)>, ProviderError> {
        let index = self.device_index(epoch.owner().as_str())?;
        let mut paths = Vec::new();
        for (_interface, device) in index {
            let props = bounded_props(
                &self.connection,
                epoch.owner().as_str(),
                device.as_str(),
                NM_DEVICE_INTERFACE,
            )?;
            for (property, v6) in [("Ip4Config", false), ("Ip6Config", true)] {
                let path: OwnedObjectPath = snapshot_property(&props, property)?;
                if path.as_str() != "/" {
                    paths.push((v6, path));
                }
            }
        }
        let result = ip_index(paths)?;
        self.require_native_epoch(epoch)?;
        Ok(result)
    }

    pub(super) fn passive_resources(
        &self,
        epoch: &NetworkManagerEpoch,
    ) -> Result<Vec<ResourceId>, ProviderError> {
        let mut values = vec![
            ResourceId::new(CONNECTIONS_RESOURCE).map_err(|_| invalid("connections resource"))?,
        ];
        // Correlate the advertised devices to live kernel ifindices and
        // one network-namespace witness, never interface aliases alone.
        let _inventory = self.device_inventory(epoch)?;
        let wifi = self.wifi_devices(epoch)?;
        for (interface, path) in wifi {
            values.push(
                ResourceId::new(format!("{WIFI_PREFIX}{interface}"))
                    .map_err(|_| invalid("wireless resource"))?,
            );
            for id in self.wireless_index(epoch.owner().as_str(), &path)?.keys() {
                values.push(
                    ResourceId::new(format!("{AP_PREFIX}{interface}:{id}"))
                        .map_err(|_| invalid("access point resource"))?,
                );
            }
        }
        for id in self.profile_index(epoch.owner().as_str())?.keys() {
            values.push(
                ResourceId::new(format!("{PROFILE_PREFIX}{id}"))
                    .map_err(|_| invalid("profile resource"))?,
            );
        }
        for id in self.active_index(epoch.owner().as_str())?.keys() {
            values.push(
                ResourceId::new(format!("{ACTIVE_PREFIX}{id}"))
                    .map_err(|_| invalid("active connection resource"))?,
            );
        }
        for path in self.ip_resources(epoch)?.keys() {
            values.push(ResourceId::new(path.clone()).map_err(|_| invalid("IP resource"))?);
        }
        if values.len() > 1 + MAX_NM_DEVICES + MAX_NETWORK_OBJECTS * 2
            || values.len()
                != values
                    .iter()
                    .map(ResourceId::as_str)
                    .collect::<BTreeSet<_>>()
                    .len()
        {
            return Err(invalid("aggregate resource inventory"));
        }
        self.require_native_epoch(epoch)?;
        Ok(values)
    }

    fn passive_observation(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
        epoch: &NetworkManagerEpoch,
        attributes: BTreeMap<String, ObservedValue>,
    ) -> Result<ObservationEnvelope, ProviderError> {
        self.require_native_epoch(epoch)?;
        let mut attributes = attributes;
        attributes.insert(
            "service_owner".into(),
            ObservedValue::Text(epoch.owner().as_str().to_owned()),
        );
        attributes.insert(
            "system_bus_id".into(),
            ObservedValue::Text(epoch.bus().as_str().to_owned()),
        );
        attributes.insert(
            "boot_id".into(),
            ObservedValue::Text(epoch.boot().as_str().to_owned()),
        );
        Ok(ObservationEnvelope {
            provider: provider_id(NM_PROVIDER),
            resource: resource.clone(),
            capability: capability.clone(),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: now_unix_ms()?,
            valid_for_ms: OBSERVATION_VALID_FOR_MS,
            sequence: next_sequence(&self.sequence)?,
            attributes,
        })
    }

    pub(super) fn observe_passive(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        let started = Instant::now();
        let epoch = self.native_epoch()?;
        let original_devices = self.device_inventory(&epoch)?;
        let owner = epoch.owner().as_str();
        let value = resource.as_str();
        let mut attributes = BTreeMap::new();
        match capability.as_str() {
            WIFI_CAPABILITY => {
                if let Some(iface) = value.strip_prefix(WIFI_PREFIX) {
                    let _ = typed(NetworkInterfaceName::new(iface), "Wi-Fi interface")?;
                    let path = self.wifi_devices(&epoch)?.remove(iface).ok_or_else(|| {
                        ProviderError::Unavailable("selected Wi-Fi device is missing".into())
                    })?;
                    let props = bounded_props(
                        &self.connection,
                        owner,
                        path.as_str(),
                        NM_WIRELESS_INTERFACE,
                    )?;
                    let aps = self.wireless_index(owner, &path)?;
                    let active: OwnedObjectPath = snapshot_property(&props, "ActiveAccessPoint")?;
                    if active.as_str() != "/" && !aps.values().any(|path| path == &active) {
                        return Err(invalid("active access point membership"));
                    }
                    attributes.insert("device_path".into(), ObservedValue::Text(path.to_string()));
                    attributes.insert(
                        "access_point_count".into(),
                        ObservedValue::U64(aps.len() as u64),
                    );
                    attributes.insert(
                        "active_access_point".into(),
                        ObservedValue::Text(active.to_string()),
                    );
                    let last_scan: i64 = snapshot_property(&props, "LastScan")?;
                    attributes.insert("last_scan_boot_ms".into(), ObservedValue::I64(last_scan));
                    let mode: u32 = snapshot_property(&props, "Mode")?;
                    attributes.insert("mode".into(), ObservedValue::U64(u64::from(mode)));
                    let bitrate: u32 = snapshot_property(&props, "Bitrate")?;
                    attributes.insert(
                        "bitrate_kbps".into(),
                        ObservedValue::U64(u64::from(bitrate)),
                    );
                    let capabilities: u32 = snapshot_property(&props, "WirelessCapabilities")?;
                    attributes.insert(
                        "wireless_capabilities".into(),
                        ObservedValue::U64(u64::from(capabilities)),
                    );
                    if self.wireless_index(owner, &path)? != aps {
                        return Err(invalid("Wi-Fi AP inventory changed"));
                    }
                } else if let Some(spec) = value.strip_prefix(AP_PREFIX) {
                    let (iface, number) =
                        spec.split_once(':').ok_or_else(|| invalid("AP resource"))?;
                    let _ = typed(NetworkInterfaceName::new(iface), "Wi-Fi interface")?;
                    let id = parse_network_seq(number, "")?;
                    let device = self.wifi_devices(&epoch)?.remove(iface).ok_or_else(|| {
                        ProviderError::Unavailable("selected Wi-Fi device is missing".into())
                    })?;
                    let before = self.wireless_index(owner, &device)?;
                    let ap = before.get(&id).ok_or_else(|| {
                        ProviderError::Unavailable("selected AP is no longer present".into())
                    })?;
                    let props =
                        bounded_props(&self.connection, owner, ap.as_str(), NM_AP_INTERFACE)?;
                    let ssid: Vec<u8> = snapshot_property(&props, "Ssid")?;
                    if ssid.len() > 32 {
                        return Err(invalid("AP SSID length"));
                    }
                    let ssid_hex: String = ssid.iter().map(|byte| format!("{byte:02x}")).collect();
                    attributes.insert("ssid_hex".into(), ObservedValue::Text(ssid_hex));
                    let bssid: String = snapshot_property(&props, "HwAddress")?;
                    bounded_nm_text("BSSID", &bssid)?;
                    attributes.insert("bssid".into(), ObservedValue::Text(bssid));
                    for (property, name) in [
                        ("Flags", "flags"),
                        ("WpaFlags", "wpa_flags"),
                        ("RsnFlags", "rsn_flags"),
                        ("Frequency", "frequency_mhz"),
                        ("Mode", "mode"),
                        ("MaxBitrate", "max_bitrate_kbps"),
                    ] {
                        let number: u32 = snapshot_property(&props, property)?;
                        attributes.insert(name.into(), ObservedValue::U64(u64::from(number)));
                    }
                    let strength: u8 = snapshot_property(&props, "Strength")?;
                    if strength > 100 {
                        return Err(invalid("AP signal strength"));
                    }
                    attributes.insert("strength".into(), ObservedValue::U64(u64::from(strength)));
                    let seen: i32 = snapshot_property(&props, "LastSeen")?;
                    attributes.insert(
                        "last_seen_boot_s".into(),
                        ObservedValue::I64(i64::from(seen)),
                    );
                    attributes.insert("object_path".into(), ObservedValue::Text(ap.to_string()));
                    attributes.insert(
                        "device_path".into(),
                        ObservedValue::Text(device.to_string()),
                    );
                    if self.wireless_index(owner, &device)? != before {
                        return Err(invalid("AP membership changed"));
                    }
                } else {
                    return Err(ProviderError::Unsupported(
                        "Wi-Fi resource is unsupported".into(),
                    ));
                }
            }
            CONNECTIONS_CAPABILITY => {
                if value == CONNECTIONS_RESOURCE {
                    let profiles = self.profile_index(owner)?;
                    let active = self.active_index(owner)?;
                    attributes.insert(
                        "saved_or_unsaved_profile_count".into(),
                        ObservedValue::U64(profiles.len() as u64),
                    );
                    attributes.insert(
                        "active_count".into(),
                        ObservedValue::U64(active.len() as u64),
                    );
                    if self.profile_index(owner)? != profiles || self.active_index(owner)? != active
                    {
                        return Err(invalid("connection inventories changed"));
                    }
                } else if let Some(number) = value.strip_prefix(PROFILE_PREFIX) {
                    let id = parse_network_seq(number, "")?;
                    let before = self.profile_index(owner)?;
                    let path = before
                        .get(&id)
                        .ok_or_else(|| ProviderError::Unavailable("profile disappeared".into()))?;
                    let props = bounded_props(
                        &self.connection,
                        owner,
                        path.as_str(),
                        NM_PROFILE_INTERFACE,
                    )?;
                    let unsaved: bool = snapshot_property(&props, "Unsaved")?;
                    let flags: u32 = snapshot_property(&props, "Flags")?;
                    attributes.insert("object_path".into(), ObservedValue::Text(path.to_string()));
                    attributes.insert("unsaved".into(), ObservedValue::Bool(unsaved));
                    attributes.insert("flags".into(), ObservedValue::U64(u64::from(flags)));
                    let revision = self.profile_revision(&epoch, path, &props)?;
                    attributes.insert(
                        "profile_uuid".into(),
                        ObservedValue::Text(revision.uuid().to_owned()),
                    );
                    attributes.insert(
                        "settings_version".into(),
                        ObservedValue::U64(revision.revision_generation()),
                    );
                    attributes.insert(
                        "settings_projection_sha256".into(),
                        ObservedValue::Text(revision.settings_fingerprint().to_owned()),
                    );
                    // This attests a source-pinned read-only snapshot; it
                    // never authorizes a later Update2 without fresh Control
                    // policy, native preconditions and independent CAS.
                    attributes.insert("revision_attested".into(), ObservedValue::Bool(true));
                    if self.profile_index(owner)? != before {
                        return Err(invalid("profile membership changed"));
                    }
                } else if let Some(number) = value.strip_prefix(ACTIVE_PREFIX) {
                    let id = parse_network_seq(number, "")?;
                    let before = self.active_index(owner)?;
                    let path = before.get(&id).ok_or_else(|| {
                        ProviderError::Unavailable("activation disappeared".into())
                    })?;
                    let props =
                        bounded_props(&self.connection, owner, path.as_str(), NM_ACTIVE_INTERFACE)?;
                    let devices: Vec<OwnedObjectPath> = snapshot_property(&props, "Devices")?;
                    let devices = bounded_unique(devices, MAX_NM_DEVICES)?;
                    let current_devices: BTreeSet<_> = self
                        .device_index(owner)?
                        .into_values()
                        .map(|path| path.to_string())
                        .collect();
                    if devices
                        .iter()
                        .any(|path| !current_devices.contains(&path.to_string()))
                    {
                        return Err(invalid("active connection device mapping"));
                    }
                    let saved: OwnedObjectPath = snapshot_property(&props, "Connection")?;
                    if saved.as_str() != "/"
                        && !self.profile_index(owner)?.values().any(|v| v == &saved)
                    {
                        return Err(invalid("active connection profile mapping"));
                    }
                    attributes.insert("object_path".into(), ObservedValue::Text(path.to_string()));
                    attributes.insert(
                        "saved_profile_path".into(),
                        ObservedValue::Text(saved.to_string()),
                    );
                    attributes.insert(
                        "device_count".into(),
                        ObservedValue::U64(devices.len() as u64),
                    );
                    for (field, name) in [("State", "state"), ("StateFlags", "state_flags")] {
                        let state: u32 = snapshot_property(&props, field)?;
                        attributes.insert(name.into(), ObservedValue::U64(u64::from(state)));
                    }
                    for (field, name) in [
                        ("Default", "default_ipv4"),
                        ("Default6", "default_ipv6"),
                        ("Vpn", "vpn"),
                    ] {
                        let flag: bool = snapshot_property(&props, field)?;
                        attributes.insert(name.into(), ObservedValue::Bool(flag));
                    }
                    for (field, name) in [("Uuid", "uuid"), ("Type", "connection_type")] {
                        let text: String = snapshot_property(&props, field)?;
                        bounded_nm_text(name, &text)?;
                        attributes.insert(name.into(), ObservedValue::Text(text));
                    }
                    if self.active_index(owner)? != before {
                        return Err(invalid("active membership changed"));
                    }
                } else {
                    return Err(ProviderError::Unsupported(
                        "connection resource is unsupported".into(),
                    ));
                }
            }
            IPCONFIG_CAPABILITY => {
                if !value.starts_with(IP4_PREFIX) && !value.starts_with(IP6_PREFIX) {
                    return Err(ProviderError::Unsupported(
                        "IP resource is unsupported".into(),
                    ));
                }
                let before = self.ip_resources(&epoch)?;
                let (v6, path) = before.get(value).ok_or_else(|| {
                    ProviderError::Unavailable("selected IP configuration disappeared".into())
                })?;
                let family = if *v6 { 6 } else { 4 };
                let props = bounded_props(
                    &self.connection,
                    owner,
                    path.as_str(),
                    if *v6 {
                        NM_IP6_INTERFACE
                    } else {
                        NM_IP4_INTERFACE
                    },
                )?;
                let gateway: String = snapshot_property(&props, "Gateway")?;
                if !gateway.is_empty() {
                    let parsed: IpAddr = gateway.parse().map_err(|_| invalid("IP gateway"))?;
                    if (*v6 && !parsed.is_ipv6()) || (!*v6 && !parsed.is_ipv4()) {
                        return Err(invalid("IP gateway family"));
                    }
                    attributes.insert("gateway".into(), ObservedValue::Text(parsed.to_string()));
                }
                let priority: i32 = snapshot_property(&props, "DnsPriority")?;
                attributes.insert(
                    "dns_priority".into(),
                    ObservedValue::I64(i64::from(priority)),
                );
                attributes.insert("family".into(), ObservedValue::U64(family as u64));
                attributes.insert("object_path".into(), ObservedValue::Text(path.to_string()));
                ip_rows(
                    &mut attributes,
                    &props,
                    "AddressData",
                    "address",
                    family,
                    false,
                )?;
                ip_rows(&mut attributes, &props, "RouteData", "route", family, true)?;
                for (field, name) in [
                    ("Domains", "domain"),
                    ("Searches", "search"),
                    ("DnsOptions", "dns_option"),
                ] {
                    let values: Vec<String> = snapshot_property(&props, field)?;
                    if values.len() > MAX_DNS_ENTRIES {
                        return Err(invalid("DNS entry inventory"));
                    }
                    attributes.insert(
                        format!("{name}_count"),
                        ObservedValue::U64(values.len() as u64),
                    );
                    for (index, item) in values.iter().enumerate() {
                        bounded_nm_text(name, item)?;
                        attributes
                            .insert(format!("{name}_{index}"), ObservedValue::Text(item.clone()));
                    }
                }
                // These are the per-configuration resolver addresses exposed
                // by NetworkManager, not a claim about systemd-resolved's
                // eventual global precedence or upstream DNS reachability.
                let mut servers = Vec::new();
                if *v6 {
                    let raw: Vec<Vec<u8>> = snapshot_property(&props, "Nameservers")?;
                    if raw.len() > MAX_DNS_ENTRIES {
                        return Err(invalid("IPv6 nameserver inventory"));
                    }
                    for address in raw {
                        let octets: [u8; 16] = address
                            .try_into()
                            .map_err(|_| invalid("IPv6 nameserver width"))?;
                        servers.push(std::net::Ipv6Addr::from(octets).to_string());
                    }
                } else {
                    let raw: Vec<u32> = snapshot_property(&props, "Nameservers")?;
                    if raw.len() > MAX_DNS_ENTRIES {
                        return Err(invalid("IPv4 nameserver inventory"));
                    }
                    for address in raw {
                        // NM exposes IPv4 nameservers as integers holding
                        // network-byte-order address bytes, not host-order
                        // numeric IP values. Retain their actual octet order.
                        servers.push(std::net::Ipv4Addr::from(address.to_ne_bytes()).to_string());
                    }
                }
                let mut unique_servers = BTreeSet::new();
                for (index, address) in servers.iter().enumerate() {
                    if !unique_servers.insert(address) {
                        return Err(invalid("duplicate nameserver"));
                    }
                    attributes.insert(
                        format!("nameserver_{index}"),
                        ObservedValue::Text(address.clone()),
                    );
                }
                attributes.insert(
                    "nameserver_count".into(),
                    ObservedValue::U64(servers.len() as u64),
                );
                if self.ip_resources(&epoch)? != before {
                    return Err(invalid("IP config membership changed"));
                }
            }
            _ => {
                return Err(ProviderError::Unsupported(
                    "unknown passive network capability".into(),
                ));
            }
        }
        if self.device_inventory(&epoch)? != original_devices {
            return Err(invalid("kernel device inventory changed"));
        }
        require_nm_elapsed(started)?;
        self.passive_observation(resource, capability, &epoch, attributes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn path(value: &str) -> OwnedObjectPath {
        OwnedObjectPath::try_from(value.to_owned())
            .unwrap_or_else(|error| unreachable!("static path: {error}"))
    }

    fn text_value(value: &str) -> OwnedValue {
        OwnedValue::from(zbus::zvariant::Str::from(value.to_owned()))
    }

    fn simple_profile() -> HashMap<String, HashMap<String, OwnedValue>> {
        HashMap::from([(
            "connection".to_owned(),
            HashMap::from([
                (
                    "uuid".to_owned(),
                    text_value("10203040-5060-7080-90ab-cdef12345678"),
                ),
                ("type".to_owned(), text_value("802-3-ethernet")),
            ]),
        )])
    }

    #[test]
    fn visible_uuid_veto_rejects_duplicate_or_substituted_profile_identity() {
        const A: &str = "10203040-5060-7080-90ab-cdef12345678";
        const B: &str = "20203040-5060-7080-90ab-cdef12345678";
        const C: &str = "30203040-5060-7080-90ab-cdef12345678";
        assert!(reject_visible_uuid_collision(A, &[]).is_ok());
        assert!(reject_visible_uuid_collision(A, &[B.into(), C.into()]).is_ok());
        assert!(reject_visible_uuid_collision(A, &[A.into()]).is_err());
        assert!(reject_visible_uuid_collision(A, &[B.into(), B.into()]).is_err());
        assert!(reject_visible_uuid_collision(A, &[String::new()]).is_err());
        assert!(reject_visible_uuid_collision("NOT_A_UUID", &[]).is_err());
        assert!(
            reject_visible_uuid_collision("00000000-0000-0000-0000-000000000000", &[],).is_err()
        );
        assert!(
            reject_visible_uuid_collision(A, &vec![B.into(); MAX_PROFILE_OBJECTS + 1],).is_err()
        );
    }

    #[test]
    fn settings_projection_digest_is_secret_free_and_version_fenced() {
        let initial = simple_profile();
        let Ok((uuid, digest)) = profile_fingerprint(&initial) else {
            unreachable!("valid canonical profile fixture");
        };
        assert_eq!(uuid, "10203040-5060-7080-90ab-cdef12345678");
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let mut secret_variant = simple_profile();
        secret_variant.insert(
            "802-11-wireless-security".into(),
            HashMap::from([("psk".into(), text_value("redacted-private-value"))]),
        );
        // Neither untrusted secret-bearing settings nor their bytes appear
        // in the explicit safe digest projection; the global version tracks
        // changes to *all* profile settings, including unprojected fields.
        assert_eq!(
            profile_fingerprint(&secret_variant),
            Ok((uuid.clone(), digest.clone()))
        );
        let mut changed = simple_profile();
        let Some(connection) = changed.get_mut("connection") else {
            unreachable!("known fixture section");
        };
        connection.insert("autoconnect".into(), OwnedValue::from(false));
        assert_ne!(profile_fingerprint(&changed), Ok((uuid, digest)));
        assert!(NetworkManagerObserver::require_same_settings_version(7, 7).is_ok());
        assert!(NetworkManagerObserver::require_same_settings_version(7, 8).is_err());
        assert!(NetworkManagerObserver::require_same_settings_version(0, 0).is_err());
        // Byte-for-byte same settings after modification still invalidates
        // the version, preventing silent profile ABA reuse.
        assert!(NetworkManagerObserver::require_same_settings_version(10, 12).is_err());
    }

    #[test]
    fn profile_parser_rejects_malformed_and_oversized_provider_maps() {
        let mut profiles = simple_profile();
        profiles.insert("illegal.section".into(), HashMap::new());
        assert!(profile_fingerprint(&profiles).is_err());
        let mut profiles = simple_profile();
        for index in 0..MAX_NM_SETTINGS_SECTIONS {
            profiles.insert(format!("unit{index}"), HashMap::new());
        }
        assert!(profile_fingerprint(&profiles).is_err());
        let mut profiles = simple_profile();
        let Some(connection) = profiles.get_mut("connection") else {
            unreachable!("known fixture section");
        };
        connection.insert("type".into(), text_value("bad\nsource"));
        assert!(profile_fingerprint(&profiles).is_err());
    }

    #[test]
    fn encoded_native_responses_have_a_pre_decode_byte_budget() {
        assert!(within_decoder_budget(0));
        assert!(within_decoder_budget(MAX_NM_REPLY_BYTES));
        assert!(!within_decoder_budget(MAX_NM_REPLY_BYTES + 1));
        assert!(!within_decoder_budget(usize::MAX));
    }

    #[test]
    fn strict_native_object_family_and_duplicate_detection() {
        let ids = vec![
            path("/org/freedesktop/NetworkManager/AccessPoint/2"),
            path("/org/freedesktop/NetworkManager/AccessPoint/3"),
        ];
        assert!(native_index(ids.clone(), NetworkObjectKind::AccessPoint, 2).is_ok());
        assert!(native_index(ids.clone(), NetworkObjectKind::Device, 2).is_err());
        assert!(
            native_index(
                vec![ids[0].clone(), ids[0].clone()],
                NetworkObjectKind::AccessPoint,
                2,
            )
            .is_err()
        );
        assert!(native_index(ids, NetworkObjectKind::AccessPoint, 1).is_err());
    }

    #[test]
    fn ip_paths_reject_ambiguous_or_noncanonical_generations() {
        for invalid in ["", "0", "01", "-2", "1/2", "18446744073709551616"] {
            assert!(parse_network_seq(invalid, "").is_err(), "{invalid}");
        }
        assert_eq!(parse_network_seq("21", ""), Ok(21));
        assert!(
            ip_index(vec![
                (false, path("/org/freedesktop/NetworkManager/IP4Config/1")),
                (false, path("/org/freedesktop/NetworkManager/IP4Config/1")),
            ])
            .is_err()
        );
        assert!(
            ip_index(vec![(
                true,
                path("/org/freedesktop/NetworkManager/IP4Config/1")
            ),])
            .is_err()
        );
    }

    #[test]
    fn ip_rows_validate_family_prefix_and_gateway() {
        let address = |text: &str, prefix: u32| {
            HashMap::from([
                (
                    "address".into(),
                    OwnedValue::from(zbus::zvariant::Str::from(text.to_owned())),
                ),
                ("prefix".into(), OwnedValue::from(prefix)),
            ])
        };
        assert_eq!(
            ip_row(&address("192.0.2.5", 24), 4, false),
            Ok("192.0.2.5/24".into())
        );
        assert!(ip_row(&address("2001:db8::1", 64), 4, false).is_err());
        assert!(ip_row(&address("192.0.2.5", 33), 4, false).is_err());
        assert_eq!(
            ip_row(&address("2001:db8::1", 64), 6, false),
            Ok("2001:db8::1/64".into())
        );
    }

    #[test]
    fn ipv4_nameserver_wire_byte_order_is_preserved() {
        let native = u32::from_ne_bytes([192, 0, 2, 53]);
        assert_eq!(
            std::net::Ipv4Addr::from(native.to_ne_bytes()).to_string(),
            "192.0.2.53"
        );
    }

    #[test]
    fn native_read_bounds_refuse_duplicate_and_oversized_rows() {
        let duplicate = vec![
            path("/org/freedesktop/NetworkManager/Devices/1"),
            path("/org/freedesktop/NetworkManager/Devices/1"),
        ];
        assert!(bounded_unique(duplicate, 2).is_err());
        let excessive = (1..=MAX_ACCESS_POINTS + 1)
            .map(|index| {
                path(&format!(
                    "/org/freedesktop/NetworkManager/AccessPoint/{index}"
                ))
            })
            .collect();
        assert!(
            native_index(excessive, NetworkObjectKind::AccessPoint, MAX_ACCESS_POINTS).is_err()
        );
    }
}
