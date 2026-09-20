#![forbid(unsafe_code)]

pub mod platform_discovery;

use std::collections::{BTreeMap, HashMap};
use std::fmt::{Debug, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use linura_core::{
    Capability, CapabilityId, ProviderId, ResourceId, SupportLevel, ValidationError,
};
use linura_observation::{
    ObservationAuthority, ObservationEnvelope, ObservedValue, ProviderAvailability, ProviderHealth,
};
use linura_provider_sdk::{Observer, ProviderError};
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

const DBUS_PROPERTIES: &str = "org.freedesktop.DBus.Properties";
const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1";
const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER: &str = "org.freedesktop.systemd1.Manager";
const SYSTEMD_UNIT: &str = "org.freedesktop.systemd1.Unit";
const SYSTEMD_PROVIDER: &str = "systemd";
const SYSTEMD_CAPABILITY: &str = "systemd.unit.observe";
const SYSTEMD_RESOURCE_PREFIX: &str = "systemd:unit:";
pub const SYSTEMD_ACTIVE_ENTER_TIMESTAMP_MONOTONIC_ATTRIBUTE: &str =
    "active_enter_timestamp_monotonic";

const NM_SERVICE: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const NM_INTERFACE: &str = "org.freedesktop.NetworkManager";
const NM_DEVICE_INTERFACE: &str = "org.freedesktop.NetworkManager.Device";
const NM_PROVIDER: &str = "networkmanager";
const NM_MANAGER_CAPABILITY: &str = "networkmanager.manager.observe";
const NM_DEVICE_CAPABILITY: &str = "networkmanager.device.observe";
const NM_MANAGER_RESOURCE: &str = "networkmanager:manager";
const NM_DEVICE_RESOURCE_PREFIX: &str = "networkmanager:device:";
const OBSERVATION_VALID_FOR_MS: u64 = 2_000;

type SystemdUnitRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    OwnedObjectPath,
    u32,
    String,
    OwnedObjectPath,
);

pub struct SystemdObserver {
    connection: Connection,
    sequence: AtomicU64,
}

impl Debug for SystemdObserver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemdObserver").finish_non_exhaustive()
    }
}

impl SystemdObserver {
    pub fn connect() -> Result<Self, ProviderError> {
        let connection = Connection::system().map_err(provider_connection_error)?;
        Ok(Self {
            connection,
            sequence: AtomicU64::new(0),
        })
    }

    fn manager(&self) -> Result<Proxy<'_>, ProviderError> {
        Proxy::new(
            &self.connection,
            SYSTEMD_SERVICE,
            SYSTEMD_PATH,
            SYSTEMD_MANAGER,
        )
        .map_err(provider_bus_error)
    }

    fn unit_resource(name: &str) -> Result<ResourceId, ProviderError> {
        ResourceId::new(format!("{SYSTEMD_RESOURCE_PREFIX}{name}"))
            .map_err(|error| invalid_identifier("systemd unit resource", error))
    }

    fn unit_name(resource: &ResourceId) -> Result<&str, ProviderError> {
        let value = resource.as_str();
        let Some(name) = value.strip_prefix(SYSTEMD_RESOURCE_PREFIX) else {
            return Err(ProviderError::Unsupported(format!(
                "resource {value} is not a systemd unit resource"
            )));
        };
        if name.is_empty() {
            return Err(ProviderError::InvalidState(
                "systemd unit resource has an empty unit name".into(),
            ));
        }
        Ok(name)
    }
}

impl Observer for SystemdObserver {
    fn observer_id(&self) -> ProviderId {
        provider_id(SYSTEMD_PROVIDER)
    }

    fn observation_capabilities(&self) -> Vec<Capability> {
        let health = self.health();
        vec![capability(
            SYSTEMD_CAPABILITY,
            SYSTEMD_PROVIDER,
            health.availability,
            health.reason,
        )]
    }

    fn health(&self) -> ProviderHealth {
        service_health(&self.connection, SYSTEMD_PROVIDER, SYSTEMD_SERVICE)
    }

    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        require_available(&self.health())?;
        let units: Vec<SystemdUnitRow> = self
            .manager()?
            .call("ListUnits", &())
            .map_err(provider_bus_error)?;
        let mut resources = Vec::with_capacity(units.len());
        for (name, _, _, _, _, _, _, _, _, _) in units {
            resources.push(Self::unit_resource(&name)?);
        }
        resources.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        resources.dedup();
        Ok(resources)
    }

    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        if capability.as_str() != SYSTEMD_CAPABILITY {
            return Err(ProviderError::Unsupported(format!(
                "systemd observer does not support {}",
                capability.as_str()
            )));
        }
        require_available(&self.health())?;
        let unit_name = Self::unit_name(resource)?;

        // `GetUnit` only resolves units resident in systemd's loaded-unit set. `LoadUnit` is the
        // authoritative lookup for an explicitly named resource: it loads configuration without
        // starting the unit and returns the native Unit object whose properties describe current
        // state.
        let unit_path: OwnedObjectPath = self
            .manager()?
            .call("LoadUnit", &(unit_name,))
            .map_err(provider_bus_error)?;
        let properties = all_properties(
            &self.connection,
            SYSTEMD_SERVICE,
            unit_path.as_str(),
            SYSTEMD_UNIT,
        )?;
        let id: String = snapshot_property(&properties, "Id")?;
        let description: String = snapshot_property(&properties, "Description")?;
        let load_state: String = snapshot_property(&properties, "LoadState")?;
        let active_state: String = snapshot_property(&properties, "ActiveState")?;
        let sub_state: String = snapshot_property(&properties, "SubState")?;
        let fragment_path: String = snapshot_property(&properties, "FragmentPath")?;
        let active_enter_timestamp_monotonic: u64 =
            snapshot_property(&properties, "ActiveEnterTimestampMonotonic")?;

        Ok(ObservationEnvelope {
            provider: provider_id(SYSTEMD_PROVIDER),
            resource: resource.clone(),
            capability: capability.clone(),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: now_unix_ms()?,
            valid_for_ms: OBSERVATION_VALID_FOR_MS,
            sequence: next_sequence(&self.sequence)?,
            attributes: BTreeMap::from([
                ("id".into(), ObservedValue::Text(id)),
                ("description".into(), ObservedValue::Text(description)),
                ("load_state".into(), ObservedValue::Text(load_state)),
                ("active_state".into(), ObservedValue::Text(active_state)),
                ("sub_state".into(), ObservedValue::Text(sub_state)),
                ("fragment_path".into(), ObservedValue::Text(fragment_path)),
                (
                    SYSTEMD_ACTIVE_ENTER_TIMESTAMP_MONOTONIC_ATTRIBUTE.into(),
                    ObservedValue::U64(active_enter_timestamp_monotonic),
                ),
            ]),
        })
    }
}

pub struct NetworkManagerObserver {
    connection: Connection,
    sequence: AtomicU64,
}

impl Debug for NetworkManagerObserver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkManagerObserver")
            .finish_non_exhaustive()
    }
}

impl NetworkManagerObserver {
    pub fn connect() -> Result<Self, ProviderError> {
        let connection = Connection::system().map_err(provider_connection_error)?;
        Ok(Self {
            connection,
            sequence: AtomicU64::new(0),
        })
    }

    fn manager(&self) -> Result<Proxy<'_>, ProviderError> {
        Proxy::new(&self.connection, NM_SERVICE, NM_PATH, NM_INTERFACE).map_err(provider_bus_error)
    }

    fn device_resource(interface: &str) -> Result<ResourceId, ProviderError> {
        ResourceId::new(format!("{NM_DEVICE_RESOURCE_PREFIX}{interface}"))
            .map_err(|error| invalid_identifier("NetworkManager device resource", error))
    }

    fn device_interface(resource: &ResourceId) -> Result<&str, ProviderError> {
        let value = resource.as_str();
        let Some(interface) = value.strip_prefix(NM_DEVICE_RESOURCE_PREFIX) else {
            return Err(ProviderError::Unsupported(format!(
                "resource {value} is not a NetworkManager device resource"
            )));
        };
        if interface.is_empty() {
            return Err(ProviderError::InvalidState(
                "NetworkManager device resource has an empty interface".into(),
            ));
        }
        Ok(interface)
    }

    fn device_paths(&self) -> Result<Vec<OwnedObjectPath>, ProviderError> {
        self.manager()?
            .call("GetDevices", &())
            .map_err(provider_bus_error)
    }

    fn find_device_path(&self, interface: &str) -> Result<OwnedObjectPath, ProviderError> {
        for path in self.device_paths()? {
            let device = Proxy::new(
                &self.connection,
                NM_SERVICE,
                path.as_str(),
                NM_DEVICE_INTERFACE,
            )
            .map_err(provider_bus_error)?;
            let candidate: String = device
                .get_property("Interface")
                .map_err(provider_bus_error)?;
            if candidate == interface {
                drop(device);
                return Ok(path);
            }
        }
        Err(ProviderError::Unavailable(format!(
            "NetworkManager device {interface} is not present"
        )))
    }

    fn observe_manager(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        let properties = all_properties(&self.connection, NM_SERVICE, NM_PATH, NM_INTERFACE)?;
        let version: String = snapshot_property(&properties, "Version")?;
        let state: u32 = snapshot_property(&properties, "State")?;
        let connectivity: u32 = snapshot_property(&properties, "Connectivity")?;
        let networking_enabled: bool = snapshot_property(&properties, "NetworkingEnabled")?;
        Ok(ObservationEnvelope {
            provider: provider_id(NM_PROVIDER),
            resource: resource.clone(),
            capability: capability.clone(),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: now_unix_ms()?,
            valid_for_ms: OBSERVATION_VALID_FOR_MS,
            sequence: next_sequence(&self.sequence)?,
            attributes: BTreeMap::from([
                ("version".into(), ObservedValue::Text(version)),
                ("state".into(), ObservedValue::U64(u64::from(state))),
                (
                    "connectivity".into(),
                    ObservedValue::U64(u64::from(connectivity)),
                ),
                (
                    "networking_enabled".into(),
                    ObservedValue::Bool(networking_enabled),
                ),
            ]),
        })
    }

    fn observe_device(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        let interface = Self::device_interface(resource)?;
        let path = self.find_device_path(interface)?;
        let properties = all_properties(
            &self.connection,
            NM_SERVICE,
            path.as_str(),
            NM_DEVICE_INTERFACE,
        )?;
        let observed_interface: String = snapshot_property(&properties, "Interface")?;
        if observed_interface != interface {
            return Err(ProviderError::InvalidState(format!(
                "NetworkManager device identity changed during observation: expected {interface}, got {observed_interface}"
            )));
        }
        let state: u32 = snapshot_property(&properties, "State")?;
        let device_type: u32 = snapshot_property(&properties, "DeviceType")?;
        let managed: bool = snapshot_property(&properties, "Managed")?;
        let driver: String = snapshot_property(&properties, "Driver")?;
        Ok(ObservationEnvelope {
            provider: provider_id(NM_PROVIDER),
            resource: resource.clone(),
            capability: capability.clone(),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: now_unix_ms()?,
            valid_for_ms: OBSERVATION_VALID_FOR_MS,
            sequence: next_sequence(&self.sequence)?,
            attributes: BTreeMap::from([
                ("interface".into(), ObservedValue::Text(observed_interface)),
                ("state".into(), ObservedValue::U64(u64::from(state))),
                (
                    "device_type".into(),
                    ObservedValue::U64(u64::from(device_type)),
                ),
                ("managed".into(), ObservedValue::Bool(managed)),
                ("driver".into(), ObservedValue::Text(driver)),
                ("object_path".into(), ObservedValue::Text(path.to_string())),
            ]),
        })
    }
}

impl Observer for NetworkManagerObserver {
    fn observer_id(&self) -> ProviderId {
        provider_id(NM_PROVIDER)
    }

    fn observation_capabilities(&self) -> Vec<Capability> {
        let health = self.health();
        vec![
            capability(
                NM_MANAGER_CAPABILITY,
                NM_PROVIDER,
                health.availability,
                health.reason.clone(),
            ),
            capability(
                NM_DEVICE_CAPABILITY,
                NM_PROVIDER,
                health.availability,
                health.reason,
            ),
        ]
    }

    fn health(&self) -> ProviderHealth {
        service_health(&self.connection, NM_PROVIDER, NM_SERVICE)
    }

    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        require_available(&self.health())?;
        let mut resources = vec![
            ResourceId::new(NM_MANAGER_RESOURCE)
                .map_err(|error| invalid_identifier("NetworkManager manager resource", error))?,
        ];
        for path in self.device_paths()? {
            let device = Proxy::new(
                &self.connection,
                NM_SERVICE,
                path.as_str(),
                NM_DEVICE_INTERFACE,
            )
            .map_err(provider_bus_error)?;
            let interface: String = device
                .get_property("Interface")
                .map_err(provider_bus_error)?;
            resources.push(Self::device_resource(&interface)?);
        }
        resources.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        resources.dedup();
        Ok(resources)
    }

    fn observe_authoritative(
        &self,
        resource: &ResourceId,
        capability: &CapabilityId,
    ) -> Result<ObservationEnvelope, ProviderError> {
        require_available(&self.health())?;
        match (resource.as_str(), capability.as_str()) {
            (NM_MANAGER_RESOURCE, NM_MANAGER_CAPABILITY) => {
                self.observe_manager(resource, capability)
            }
            (resource_value, NM_DEVICE_CAPABILITY)
                if resource_value.starts_with(NM_DEVICE_RESOURCE_PREFIX) =>
            {
                self.observe_device(resource, capability)
            }
            _ => Err(ProviderError::Unsupported(format!(
                "NetworkManager cannot observe {} with {}",
                resource.as_str(),
                capability.as_str()
            ))),
        }
    }
}

fn all_properties(
    connection: &Connection,
    service: &str,
    path: &str,
    interface: &str,
) -> Result<HashMap<String, OwnedValue>, ProviderError> {
    let proxy =
        Proxy::new(connection, service, path, DBUS_PROPERTIES).map_err(provider_bus_error)?;
    proxy
        .call("GetAll", &(interface,))
        .map_err(provider_bus_error)
}

fn snapshot_property<T>(
    properties: &HashMap<String, OwnedValue>,
    name: &str,
) -> Result<T, ProviderError>
where
    T: TryFrom<OwnedValue>,
    <T as TryFrom<OwnedValue>>::Error: std::fmt::Display,
{
    let value = properties.get(name).ok_or_else(|| {
        ProviderError::InvalidState(format!("native D-Bus property snapshot is missing {name}"))
    })?;
    let value = value.try_clone().map_err(|error| {
        ProviderError::Internal(format!("cannot clone D-Bus property {name}: {error}"))
    })?;
    T::try_from(value).map_err(|error| {
        ProviderError::InvalidState(format!(
            "native D-Bus property {name} has an unexpected type: {error}"
        ))
    })
}

fn provider_id(value: &str) -> ProviderId {
    ProviderId::new(value)
        .unwrap_or_else(|error| unreachable!("static provider id invalid: {error}"))
}

fn capability_id(value: &str) -> CapabilityId {
    CapabilityId::new(value)
        .unwrap_or_else(|error| unreachable!("static capability id invalid: {error}"))
}

fn capability(
    id: &str,
    provider: &str,
    availability: ProviderAvailability,
    reason: Option<String>,
) -> Capability {
    let support = match availability {
        ProviderAvailability::Available => SupportLevel::Supported,
        ProviderAvailability::Degraded => SupportLevel::Degraded,
        ProviderAvailability::Unavailable => SupportLevel::Unsupported,
    };
    Capability {
        id: capability_id(id),
        support,
        provider: Some(provider_id(provider)),
        reason,
    }
}

fn service_health(connection: &Connection, provider: &str, service: &str) -> ProviderHealth {
    let provider = provider_id(provider);
    match name_has_owner(connection, service) {
        Ok(true) => ProviderHealth {
            provider,
            availability: ProviderAvailability::Available,
            reason: None,
        },
        Ok(false) => ProviderHealth {
            provider,
            availability: ProviderAvailability::Unavailable,
            reason: Some(format!("D-Bus service {service} has no owner")),
        },
        Err(error) => ProviderHealth {
            provider,
            availability: ProviderAvailability::Degraded,
            reason: Some(format!("D-Bus health query failed: {error}")),
        },
    }
}

fn name_has_owner(connection: &Connection, service: &str) -> Result<bool, zbus::Error> {
    let proxy = Proxy::new(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )?;
    proxy.call("NameHasOwner", &(service,))
}

fn require_available(health: &ProviderHealth) -> Result<(), ProviderError> {
    match health.availability {
        ProviderAvailability::Available | ProviderAvailability::Degraded => Ok(()),
        ProviderAvailability::Unavailable => Err(ProviderError::Unavailable(
            health
                .reason
                .clone()
                .unwrap_or_else(|| "provider is unavailable".into()),
        )),
    }
}

fn now_unix_ms() -> Result<u64, ProviderError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            ProviderError::Internal(format!("system clock before Unix epoch: {error}"))
        })?;
    u64::try_from(duration.as_millis())
        .map_err(|_| ProviderError::Internal("Unix timestamp exceeds u64 milliseconds".into()))
}

fn next_sequence(sequence: &AtomicU64) -> Result<u64, ProviderError> {
    sequence
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map(|previous| previous + 1)
        .map_err(|_| ProviderError::Internal("observation sequence exhausted".into()))
}

fn provider_connection_error(error: zbus::Error) -> ProviderError {
    ProviderError::Unavailable(format!("cannot connect to system D-Bus: {error}"))
}

fn provider_bus_error(error: zbus::Error) -> ProviderError {
    ProviderError::Unavailable(format!("native D-Bus observation failed: {error}"))
}

fn invalid_identifier(label: &str, error: ValidationError) -> ProviderError {
    ProviderError::InvalidState(format!("{label} is invalid: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_resource_parser_is_strict() {
        let valid = ResourceId::new("systemd:unit:sshd.service")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(SystemdObserver::unit_name(&valid), Ok("sshd.service"));
        let invalid =
            ResourceId::new("service:sshd").unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            SystemdObserver::unit_name(&invalid),
            Err(ProviderError::Unsupported(_))
        ));
    }

    #[test]
    fn systemd_restart_verification_attribute_is_canonical() {
        assert_eq!(
            SYSTEMD_ACTIVE_ENTER_TIMESTAMP_MONOTONIC_ATTRIBUTE,
            "active_enter_timestamp_monotonic"
        );
    }

    #[test]
    fn networkmanager_device_resource_parser_is_strict() {
        let valid = ResourceId::new("networkmanager:device:eth0")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(NetworkManagerObserver::device_interface(&valid), Ok("eth0"));
        let invalid = ResourceId::new("networkmanager:manager")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert!(matches!(
            NetworkManagerObserver::device_interface(&invalid),
            Err(ProviderError::Unsupported(_))
        ));
    }

    #[test]
    fn sequence_is_monotonic_and_fail_closed_on_overflow() {
        let sequence = AtomicU64::new(0);
        assert_eq!(next_sequence(&sequence), Ok(1));
        assert_eq!(next_sequence(&sequence), Ok(2));
        let exhausted = AtomicU64::new(u64::MAX);
        assert!(next_sequence(&exhausted).is_err());
    }
}
