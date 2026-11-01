#![forbid(unsafe_code)]

//! S19-1: read-only BlueZ ObjectManager observation.
//! This crate owns no effect, discovery lease, pairing agent or authorization.
//! The well-known service name, object path, address and alias never grant identity
//! continuity or permission to act on the remote device.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::{Debug, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use linura_core::{
    Capability, CapabilityId, ProviderId, ResourceId, SupportLevel, ValidationError,
};
use linura_observation::{
    ObservationAuthority, ObservationEnvelope, ObservedValue, ProviderAvailability, ProviderHealth,
};
use linura_provider_sdk::{Observer, ProviderError};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

const SERVICE: &str = "org.bluez";
const BUS_SERVICE: &str = "org.freedesktop.DBus";
const BUS_PATH: &str = "/org/freedesktop/DBus";
const BUS_INTERFACE: &str = "org.freedesktop.DBus";
const OBJECT_MANAGER: &str = "org.freedesktop.DBus.ObjectManager";
const ADAPTER_INTERFACE: &str = "org.bluez.Adapter1";
const DEVICE_INTERFACE: &str = "org.bluez.Device1";
const PROVIDER: &str = "bluez";
const ADAPTER_CAPABILITY: &str = "bluez.adapter.observe";
const DEVICE_CAPABILITY: &str = "bluez.device.observe";
const BOND_CAPABILITY: &str = "bluez.bond.observe";
const ADAPTER_RESOURCE: &str = "bluez:adapter:";
const DEVICE_RESOURCE: &str = "bluez:device:";
const VALID_FOR_MS: u64 = 2_000;
const CALL_TIMEOUT: Duration = Duration::from_millis(750);
const MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;
const MAX_OBJECTS: usize = 2048;
const MAX_ADAPTERS: usize = 32;
const MAX_DEVICES: usize = 1024;
const MAX_INTERFACES: usize = 24;
const MAX_PROPERTIES: usize = 96;
const MAX_UUIDS: usize = 96;
const MAX_LABEL_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 192;

type ManagedObjects = HashMap<OwnedObjectPath, HashMap<String, HashMap<String, OwnedValue>>>;
type Attributes = BTreeMap<String, ObservedValue>;

#[derive(Debug)]
struct Inventory {
    owner: String,
    boot_id: String,
    adapters: BTreeMap<String, Attributes>,
    devices: BTreeMap<String, Attributes>,
}

impl Inventory {
    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        self.adapters
            .keys()
            .map(|path| bound_resource(ADAPTER_RESOURCE, path, &self.boot_id, &self.owner))
            .chain(self.devices.keys().map(|path| {
                bound_resource(DEVICE_RESOURCE, path, &self.boot_id, &self.owner)
            }))
            .collect()
    }

    fn observe(
        &self,
        resource_id: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<Attributes, ProviderError> {
        // Resource enumeration and observation are independent native calls. Reject
        // a reused BlueZ path if the system boot or unique bus owner has changed.
        // This is a freshness guard, not authentication of a remote Bluetooth peer.
        let epoch_suffix = format!("@{}@{}", self.boot_id, self.owner);
        let key = resource_id
            .as_str()
            .strip_suffix(&epoch_suffix)
            .ok_or_else(|| {
                ProviderError::Unavailable("stale Bluetooth resource owner/boot epoch".into())
            })?;
        let (path, attributes) = match capability.as_str() {
            ADAPTER_CAPABILITY => {
                let path = key.strip_prefix(ADAPTER_RESOURCE).ok_or_else(|| {
                    ProviderError::Unsupported("adapter capability/resource mismatch".into())
                })?;
                (path, self.adapters.get(path))
            }
            DEVICE_CAPABILITY | BOND_CAPABILITY => {
                let path = key.strip_prefix(DEVICE_RESOURCE).ok_or_else(|| {
                    ProviderError::Unsupported("device capability/resource mismatch".into())
                })?;
                (path, self.devices.get(path))
            }
            _ => {
                return Err(ProviderError::Unsupported(
                    "unsupported BlueZ observation capability".into(),
                ));
            }
        };
        let attributes = attributes.ok_or_else(|| {
            ProviderError::Unavailable(
                "requested Bluetooth object no longer exists in the current native inventory"
                    .into(),
            )
        })?;
        let mut result = attributes.clone();
        result.insert("object_path".into(), ObservedValue::Text(path.into()));
        result.insert("boot_id".into(), ObservedValue::Text(self.boot_id.clone()));
        result.insert(
            "bluez_unique_owner".into(),
            ObservedValue::Text(self.owner.clone()),
        );
        // No authenticated remote-identity continuity can be inferred from this query.
        result.insert(
            "remote_identity_assurance".into(),
            ObservedValue::Text("unverified".into()),
        );
        result.insert(
            "controller_generation_assurance".into(),
            ObservedValue::Text("unverified".into()),
        );
        Ok(result)
    }
}

pub struct BlueZObserver {
    connection: Connection,
    sequence: AtomicU64,
}

impl Debug for BlueZObserver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlueZObserver").finish_non_exhaustive()
    }
}

impl BlueZObserver {
    /// A connection to the system bus is not evidence that BlueZ or a controller exists.
    pub fn connect() -> Result<Self, ProviderError> {
        // Bound both bus authentication and subsequent synchronous native method calls.
        let builder = zbus::connection::Builder::system()
            .map_err(|_| ProviderError::Unavailable("cannot configure system D-Bus".into()))?
            .method_timeout(CALL_TIMEOUT);
        let result: Result<Option<zbus::Connection>, zbus::Error> = async_io::block_on(async {
            futures_lite::future::race(async { builder.build().await.map(Some) }, async {
                async_io::Timer::after(CALL_TIMEOUT).await;
                Ok(None)
            })
            .await
        });
        let connection = result
            .map_err(|_| ProviderError::Unavailable("system D-Bus authentication failed".into()))?
            .ok_or_else(|| {
                ProviderError::Unavailable("system D-Bus authentication timed out".into())
            })?;
        Ok(Self {
            connection: Connection::from(connection),
            sequence: AtomicU64::new(0),
        })
    }

    fn owner(&self) -> Result<String, ProviderError> {
        let proxy =
            Proxy::new(&self.connection, BUS_SERVICE, BUS_PATH, BUS_INTERFACE).map_err(|_| {
                ProviderError::Unavailable("system D-Bus owner query is unavailable".into())
            })?;
        let owner: String = proxy
            .call("GetNameOwner", &(SERVICE,))
            .map_err(|_| ProviderError::Unavailable("BlueZ has no verified live owner".into()))?;
        if !owner.starts_with(':')
            || owner.len() > 128
            || owner.bytes().any(|b| b.is_ascii_whitespace())
        {
            return Err(ProviderError::InvalidState(
                "invalid BlueZ unique bus owner".into(),
            ));
        }
        Ok(owner)
    }

    fn inventory(&self) -> Result<Inventory, ProviderError> {
        let boot_before = boot_id()?;
        let owner_before = self.owner()?;
        // Destination is an exact unique name, so no owner replacement can auto-activate
        // another daemon under the well-known service name during this call.
        let proxy = Proxy::new(&self.connection, owner_before.as_str(), "/", OBJECT_MANAGER)
            .map_err(|_| ProviderError::Unavailable("BlueZ ObjectManager is unavailable".into()))?;
        let message = proxy.call_method("GetManagedObjects", &()).map_err(|_| {
            ProviderError::Unavailable("BlueZ ObjectManager native read failed".into())
        })?;
        let body = message.body();
        if body.len() > MAX_REPLY_BYTES {
            return Err(ProviderError::InvalidState(
                "BlueZ ObjectManager response exceeds byte budget".into(),
            ));
        }
        let objects: ManagedObjects = body.deserialize().map_err(|_| {
            ProviderError::InvalidState("invalid BlueZ ObjectManager response".into())
        })?;
        let owner_after = self.owner()?;
        let boot_after = boot_id()?;
        if owner_before != owner_after || boot_before != boot_after {
            return Err(ProviderError::InvalidState(
                "BlueZ owner/boot epoch changed during native read".into(),
            ));
        }
        parse_inventory(objects, owner_before.clone(), boot_before)
    }
}

impl Observer for BlueZObserver {
    fn observer_id(&self) -> ProviderId {
        static_provider()
    }

    fn observation_capabilities(&self) -> Vec<Capability> {
        let health = self.health();
        [ADAPTER_CAPABILITY, DEVICE_CAPABILITY, BOND_CAPABILITY]
            .into_iter()
            .map(|id| Capability {
                id: static_capability(id),
                support: match health.availability {
                    ProviderAvailability::Available => SupportLevel::Supported,
                    ProviderAvailability::Degraded => SupportLevel::Degraded,
                    ProviderAvailability::Unavailable => SupportLevel::Unsupported,
                },
                provider: Some(static_provider()),
                reason: health.reason.clone(),
            })
            .collect()
    }

    fn health(&self) -> ProviderHealth {
        let outcome = self.owner().and_then(|owner| {
            let proxy = Proxy::new(
                &self.connection,
                owner.as_str(),
                "/",
                "org.freedesktop.DBus.Peer",
            )
            .map_err(|_| ProviderError::Unavailable("BlueZ health endpoint unavailable".into()))?;
            let _: () = proxy.call("Ping", &()).map_err(|_| {
                ProviderError::Unavailable("BlueZ health endpoint not responding".into())
            })?;
            Ok(())
        });
        match outcome {
            Ok(()) => ProviderHealth {
                provider: static_provider(),
                availability: ProviderAvailability::Available,
                reason: None,
            },
            Err(error) => ProviderHealth {
                provider: static_provider(),
                availability: ProviderAvailability::Unavailable,
                reason: Some(error.to_string()),
            },
        }
    }

    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        self.inventory()?.resources()
    }

    fn requires_live_health_preflight(&self) -> bool {
        // The owner-bound inventory read and exact owner recheck are stricter than Ping.
        false
    }

    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if !matches!(
            capability.as_str(),
            ADAPTER_CAPABILITY | DEVICE_CAPABILITY | BOND_CAPABILITY
        ) {
            return Err(ProviderError::Unsupported(
                "unsupported BlueZ observation capability".into(),
            ));
        }
        let inventory = self.inventory()?;
        let attributes = inventory.observe(resource, capability)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProviderError::Internal("invalid observation clock".into()))?;
        let observed_at_unix_ms = u64::try_from(now.as_millis())
            .map_err(|_| ProviderError::Internal("observation clock overflow".into()))?;
        let sequence = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| ProviderError::Internal("BlueZ observation sequence exhausted".into()))?
            + 1;
        Ok(ObservationEnvelope {
            provider: static_provider(),
            resource: resource.clone(),
            capability: capability.clone(),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms,
            valid_for_ms: VALID_FOR_MS,
            sequence,
            attributes,
        })
    }
}

fn static_provider() -> ProviderId {
    ProviderId::new(PROVIDER).unwrap_or_else(|_| unreachable!("invalid static BlueZ provider"))
}
fn static_capability(value: &str) -> CapabilityId {
    CapabilityId::new(value).unwrap_or_else(|_| unreachable!("invalid static BlueZ capability"))
}
fn bound_resource(
    prefix: &str,
    path: &str,
    boot_id: &str,
    owner: &str,
) -> Result<ResourceId, ProviderError> {
    // D-Bus object paths contain no '@', so this suffix is unambiguous.
    // The core ResourceId length budget also bounds the composed identifier.
    ResourceId::new(format!("{prefix}{path}@{boot_id}@{owner}")).map_err(
        |error: ValidationError| {
            ProviderError::InvalidState(format!("invalid BlueZ resource: {error}"))
        },
    )
}
fn boot_id() -> Result<String, ProviderError> {
    let id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| ProviderError::Unavailable("cannot establish Linux boot identity".into()))?;
    let id = id.trim();
    if id.len() != 36 || !id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(ProviderError::InvalidState(
            "invalid Linux boot identifier".into(),
        ));
    }
    Ok(id.into())
}
fn property<T>(values: &HashMap<String, OwnedValue>, name: &str) -> Result<T, ProviderError>
where
    T: TryFrom<OwnedValue>,
    <T as TryFrom<OwnedValue>>::Error: std::fmt::Display,
{
    let value = values
        .get(name)
        .ok_or_else(|| ProviderError::InvalidState(format!("missing BlueZ property {name}")))?;
    let value = value
        .try_clone()
        .map_err(|_| ProviderError::InvalidState(format!("invalid BlueZ property {name}")))?;
    T::try_from(value)
        .map_err(|_| ProviderError::InvalidState(format!("wrong BlueZ property type for {name}")))
}
fn optional<T>(values: &HashMap<String, OwnedValue>, name: &str) -> Result<Option<T>, ProviderError>
where
    T: TryFrom<OwnedValue>,
    <T as TryFrom<OwnedValue>>::Error: std::fmt::Display,
{
    if values.contains_key(name) {
        property(values, name).map(Some)
    } else {
        Ok(None)
    }
}
fn bounded_label(value: &str, name: &str) -> Result<(), ProviderError> {
    if value.len() > MAX_LABEL_BYTES || value.chars().any(char::is_control) {
        return Err(ProviderError::InvalidState(format!(
            "invalid or oversized BlueZ {name}"
        )));
    }
    Ok(())
}
fn path_check(value: &str) -> Result<(), ProviderError> {
    if value.len() > MAX_PATH_BYTES || !value.starts_with("/org/bluez/") {
        return Err(ProviderError::InvalidState(
            "invalid or oversized BlueZ object path".into(),
        ));
    }
    Ok(())
}
fn required_text(
    values: &HashMap<String, OwnedValue>,
    name: &str,
) -> Result<String, ProviderError> {
    let value: String = property(values, name)?;
    bounded_label(&value, name)?;
    if value.is_empty() {
        return Err(ProviderError::InvalidState(format!(
            "empty BlueZ property {name}"
        )));
    }
    Ok(value)
}
fn optional_bool(
    attributes: &mut Attributes,
    source: &HashMap<String, OwnedValue>,
    key: &str,
    destination: &str,
) -> Result<(), ProviderError> {
    match optional::<bool>(source, key)? {
        Some(value) => {
            attributes.insert(destination.into(), ObservedValue::Bool(value));
        }
        None => {
            attributes.insert(destination.into(), ObservedValue::Text("unknown".into()));
        }
    }
    Ok(())
}
fn address_type(source: &HashMap<String, OwnedValue>) -> Result<String, ProviderError> {
    match optional::<String>(source, "AddressType")? {
        Some(value) if value == "public" || value == "random" => Ok(value),
        None => Ok("unknown".into()),
        _ => Err(ProviderError::InvalidState(
            "invalid Bluetooth address type".into(),
        )),
    }
}
fn address(source: &HashMap<String, OwnedValue>) -> Result<String, ProviderError> {
    let address = required_text(source, "Address")?;
    if address.len() != 17
        || address.as_bytes().iter().enumerate().any(|(i, b)| {
            if i % 3 == 2 {
                *b != b':'
            } else {
                !b.is_ascii_hexdigit()
            }
        })
    {
        return Err(ProviderError::InvalidState(
            "invalid native Bluetooth address".into(),
        ));
    }
    Ok(address.to_ascii_uppercase())
}
fn bounded_uuids(
    source: &HashMap<String, OwnedValue>,
) -> Result<Option<(String, u64)>, ProviderError> {
    let Some(values): Option<Vec<String>> = optional(source, "UUIDs")? else {
        return Ok(None);
    };
    if values.len() > MAX_UUIDS {
        return Err(ProviderError::InvalidState(
            "BlueZ UUID count exceeds budget".into(),
        ));
    }
    let mut set = BTreeSet::new();
    for value in values {
        if value.len() != 36
            || !value.bytes().enumerate().all(|(i, b)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
            || !set.insert(value.to_ascii_lowercase())
        {
            return Err(ProviderError::InvalidState(
                "invalid or duplicated BlueZ service UUID".into(),
            ));
        }
    }
    let count = u64::try_from(set.len())
        .map_err(|_| ProviderError::InvalidState("UUID count overflow".into()))?;
    Ok(Some((set.into_iter().collect::<Vec<_>>().join(","), count)))
}
fn parse_adapter(source: &HashMap<String, OwnedValue>) -> Result<Attributes, ProviderError> {
    let mut values = Attributes::new();
    values.insert("address".into(), ObservedValue::Text(address(source)?));
    values.insert(
        "address_type".into(),
        ObservedValue::Text(address_type(source)?),
    );
    for (raw, key) in [
        ("Powered", "powered"),
        ("Discoverable", "discoverable"),
        ("Pairable", "pairable"),
        ("Discovering", "discovering"),
    ] {
        optional_bool(&mut values, source, raw, key)?;
    }
    if let Some(alias) = optional::<String>(source, "Alias")? {
        bounded_label(&alias, "Alias")?;
        values.insert("alias".into(), ObservedValue::Text(alias));
    }
    Ok(values)
}
fn parse_device(
    source: &HashMap<String, OwnedValue>,
) -> Result<(String, Attributes), ProviderError> {
    let adapter: OwnedObjectPath = property(source, "Adapter")?;
    let adapter = adapter.to_string();
    path_check(&adapter)?;
    let mut values = Attributes::new();
    values.insert("adapter_path".into(), ObservedValue::Text(adapter.clone()));
    values.insert("address".into(), ObservedValue::Text(address(source)?));
    values.insert(
        "address_type".into(),
        ObservedValue::Text(address_type(source)?),
    );
    for (raw, key) in [
        ("Paired", "paired"),
        ("Trusted", "trusted"),
        ("Blocked", "blocked"),
        ("Connected", "connected"),
        ("ServicesResolved", "services_resolved"),
    ] {
        optional_bool(&mut values, source, raw, key)?;
    }
    if let Some(alias) = optional::<String>(source, "Alias")? {
        bounded_label(&alias, "Alias")?;
        values.insert("alias".into(), ObservedValue::Text(alias));
    }
    if let Some(rssi) = optional::<i16>(source, "RSSI")? {
        values.insert("rssi_dbm".into(), ObservedValue::I64(i64::from(rssi)));
    }
    if let Some((uuids, count)) = bounded_uuids(source)? {
        values.insert("service_uuids".into(), ObservedValue::Text(uuids));
        values.insert("service_uuid_count".into(), ObservedValue::U64(count));
    }
    values.insert(
        "bond_continuity_verified".into(),
        ObservedValue::Bool(false),
    );
    values.insert("transport".into(), ObservedValue::Text("unverified".into()));
    Ok((adapter, values))
}

fn parse_inventory(
    objects: ManagedObjects,
    owner: String,
    boot_id: String,
) -> Result<Inventory, ProviderError> {
    if objects.len() > MAX_OBJECTS {
        return Err(ProviderError::InvalidState(
            "BlueZ managed-object count exceeds budget".into(),
        ));
    }
    let mut adapters = BTreeMap::new();
    let mut devices = BTreeMap::new();
    let mut parents = BTreeMap::new();
    for (path, interfaces) in objects {
        if interfaces.len() > MAX_INTERFACES {
            return Err(ProviderError::InvalidState(
                "BlueZ object interface count exceeds budget".into(),
            ));
        }
        for source in interfaces.values() {
            if source.len() > MAX_PROPERTIES {
                return Err(ProviderError::InvalidState(
                    "BlueZ interface property count exceeds budget".into(),
                ));
            }
        }
        let path = path.to_string();
        let adapter = interfaces.get(ADAPTER_INTERFACE);
        let device = interfaces.get(DEVICE_INTERFACE);
        if adapter.is_some() && device.is_some() {
            return Err(ProviderError::InvalidState(
                "ambiguous BlueZ object exposes both adapter and device".into(),
            ));
        }
        if adapter.is_some() || device.is_some() {
            path_check(&path)?;
        }
        if let Some(source) = adapter {
            if adapters.len() >= MAX_ADAPTERS {
                return Err(ProviderError::InvalidState(
                    "BlueZ adapter count exceeds budget".into(),
                ));
            }
            adapters.insert(path.clone(), parse_adapter(source)?);
        }
        if let Some(source) = device {
            if devices.len() >= MAX_DEVICES {
                return Err(ProviderError::InvalidState(
                    "BlueZ device count exceeds budget".into(),
                ));
            }
            let (parent, values) = parse_device(source)?;
            if parent == path || !path.starts_with(&format!("{parent}/")) {
                return Err(ProviderError::InvalidState(
                    "BlueZ device path/parent mismatch".into(),
                ));
            }
            parents.insert(path.clone(), parent);
            devices.insert(path, values);
        }
    }
    // One adapter/address/type can never silently select two competing remote objects.
    // This is not proof of cryptographic peer identity or of controller hotplug generation.
    let mut seen = BTreeSet::new();
    for (path, parent) in &parents {
        if !adapters.contains_key(parent) {
            return Err(ProviderError::InvalidState(
                "BlueZ device references absent parent adapter".into(),
            ));
        }
        let properties = devices
            .get(path)
            .ok_or_else(|| ProviderError::Internal("missing parsed device".into()))?;
        let address = match properties.get("address") {
            Some(ObservedValue::Text(value)) => value.as_str(),
            _ => return Err(ProviderError::Internal("missing parsed address".into())),
        };
        let ty = match properties.get("address_type") {
            Some(ObservedValue::Text(value)) => value.as_str(),
            _ => {
                return Err(ProviderError::Internal(
                    "missing parsed address type".into(),
                ));
            }
        };
        if !seen.insert((parent.clone(), address.to_owned(), ty.to_owned())) {
            return Err(ProviderError::InvalidState(
                "ambiguous duplicate BlueZ remote identity".into(),
            ));
        }
    }
    Ok(Inventory {
        owner,
        boot_id,
        adapters,
        devices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn str_value(s: &str) -> OwnedValue {
        OwnedValue::from(zbus::zvariant::Str::from(s))
    }
    fn adapter_properties() -> HashMap<String, OwnedValue> {
        HashMap::from([
            ("Address".into(), str_value("AA:BB:CC:DD:EE:FF")),
            ("Powered".into(), OwnedValue::from(true)),
            ("Discovering".into(), OwnedValue::from(false)),
        ])
    }
    fn device_properties(adapter: &str) -> HashMap<String, OwnedValue> {
        let adapter = zbus::zvariant::ObjectPath::try_from(adapter)
            .unwrap_or_else(|error| unreachable!("{error}"));
        HashMap::from([
            ("Adapter".into(), OwnedValue::from(adapter)),
            ("Address".into(), str_value("11:22:33:44:55:66")),
            ("AddressType".into(), str_value("random")),
            ("Paired".into(), OwnedValue::from(false)),
            ("Connected".into(), OwnedValue::from(true)),
            ("ServicesResolved".into(), OwnedValue::from(false)),
        ])
    }
    fn object_path(value: &str) -> OwnedObjectPath {
        OwnedObjectPath::try_from(value).unwrap_or_else(|error| unreachable!("{error}"))
    }
    fn snapshot() -> ManagedObjects {
        HashMap::from([
            (
                object_path("/org/bluez/hci0"),
                HashMap::from([(ADAPTER_INTERFACE.into(), adapter_properties())]),
            ),
            (
                object_path("/org/bluez/hci0/dev_11_22_33_44_55_66"),
                HashMap::from([(
                    DEVICE_INTERFACE.into(),
                    device_properties("/org/bluez/hci0"),
                )]),
            ),
        ])
    }
    fn parse(objects: ManagedObjects) -> Result<Inventory, ProviderError> {
        parse_inventory(
            objects,
            ":1.78".into(),
            "00000000-0000-0000-0000-000000000000".into(),
        )
    }
    #[test]
    fn exact_owner_and_device_facts_do_not_imply_bond_or_service_readiness() {
        let inventory = parse(snapshot()).unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(inventory.resources().unwrap_or_default().len(), 2);
        let resource = bound_resource(
            DEVICE_RESOURCE,
            "/org/bluez/hci0/dev_11_22_33_44_55_66",
            &inventory.boot_id,
            &inventory.owner,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let facts = inventory
            .observe(&resource, &static_capability(DEVICE_CAPABILITY))
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(facts.get("connected"), Some(&ObservedValue::Bool(true)));
        assert_eq!(
            facts.get("services_resolved"),
            Some(&ObservedValue::Bool(false))
        );
        assert_eq!(
            facts.get("trusted"),
            Some(&ObservedValue::Text("unknown".into()))
        );
        assert_eq!(
            facts.get("bond_continuity_verified"),
            Some(&ObservedValue::Bool(false))
        );
        assert_eq!(
            facts.get("bluez_unique_owner"),
            Some(&ObservedValue::Text(":1.78".into()))
        );
    }
    #[test]
    fn duplicate_device_identity_is_rejected() {
        let mut raw = snapshot();
        raw.insert(
            object_path("/org/bluez/hci0/dev_duplicate"),
            HashMap::from([(
                DEVICE_INTERFACE.into(),
                device_properties("/org/bluez/hci0"),
            )]),
        );
        assert!(parse(raw).is_err());
    }
    #[test]
    fn missing_adapter_is_rejected() {
        let mut raw = snapshot();
        raw.remove(&object_path("/org/bluez/hci0"));
        assert!(parse(raw).is_err());
    }
    #[test]
    fn malformed_address_type_and_missing_address_are_rejected() {
        let mut raw = snapshot();
        let props = raw
            .get_mut(&object_path("/org/bluez/hci0/dev_11_22_33_44_55_66"))
            .and_then(|item| item.get_mut(DEVICE_INTERFACE))
            .unwrap_or_else(|| unreachable!("missing test device"));
        props.insert("AddressType".into(), str_value("untrusted-type"));
        assert!(parse(raw).is_err());
        let mut raw = snapshot();
        let props = raw
            .get_mut(&object_path("/org/bluez/hci0"))
            .and_then(|item| item.get_mut(ADAPTER_INTERFACE))
            .unwrap_or_else(|| unreachable!("missing test adapter"));
        props.remove("Address");
        assert!(parse(raw).is_err());
    }
    #[test]
    fn wrong_native_property_type_is_rejected() {
        let mut raw = snapshot();
        let props = raw
            .get_mut(&object_path("/org/bluez/hci0"))
            .and_then(|item| item.get_mut(ADAPTER_INTERFACE))
            .unwrap_or_else(|| unreachable!("missing test adapter"));
        props.insert("Powered".into(), OwnedValue::from(42_u32));
        assert!(parse(raw).is_err());
    }
    #[test]
    fn oversized_inventory_and_properties_fail_closed() {
        let mut raw = snapshot();
        for i in 0..=MAX_PROPERTIES {
            let props = raw
                .get_mut(&object_path("/org/bluez/hci0"))
                .and_then(|item| item.get_mut(ADAPTER_INTERFACE))
                .unwrap_or_else(|| unreachable!("missing test adapter"));
            props.insert(format!("Untrusted{i}"), OwnedValue::from(i as u32));
        }
        assert!(parse(raw).is_err());
        let mut raw = snapshot();
        for i in 0..=MAX_OBJECTS {
            raw.insert(
                object_path(&format!("/org/bluez/other_{i}")),
                HashMap::new(),
            );
        }
        assert!(parse(raw).is_err());
    }
    #[test]
    fn duplicate_uuid_and_unbounded_alias_rejected() {
        let mut source = device_properties("/org/bluez/hci0");
        source.insert("Alias".into(), str_value(&"X".repeat(MAX_LABEL_BYTES + 1)));
        assert!(parse_device(&source).is_err());
    }
    #[test]
    fn resource_enumeration_cannot_cross_replaced_owner_or_boot_epoch() {
        let initial = parse(snapshot()).unwrap_or_else(|error| unreachable!("{error}"));
        let resource = bound_resource(
            DEVICE_RESOURCE,
            "/org/bluez/hci0/dev_11_22_33_44_55_66",
            &initial.boot_id,
            &initial.owner,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        let changed_owner = parse_inventory(
            snapshot(),
            ":1.79".into(),
            initial.boot_id.clone(),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(
            changed_owner
                .observe(&resource, &static_capability(DEVICE_CAPABILITY))
                .is_err()
        );
        let changed_boot = parse_inventory(
            snapshot(),
            initial.owner.clone(),
            "00000000-0000-0000-0000-000000000001".into(),
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(
            changed_boot
                .observe(&resource, &static_capability(DEVICE_CAPABILITY))
                .is_err()
        );
    }

    #[test]
    fn unavailable_device_and_wrong_scope_never_fall_back() {
        let inventory = parse(snapshot()).unwrap_or_else(|error| unreachable!("{error}"));
        let bad = bound_resource(
            DEVICE_RESOURCE,
            "/org/bluez/hci1/dev_11_22_33_44_55_66",
            &inventory.boot_id,
            &inventory.owner,
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(
            inventory
                .observe(&bad, &static_capability(DEVICE_CAPABILITY))
                .is_err()
        );
        assert!(
            inventory
                .observe(&bad, &static_capability(ADAPTER_CAPABILITY))
                .is_err()
        );
    }
}
