#![forbid(unsafe_code)]

pub mod platform_discovery;

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::ffi::OsString;
use std::fmt::{Debug, Formatter};
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

pub const PIPEWIRE_SESSION_PROVIDER: &str = "pipewire";
pub const PIPEWIRE_SESSION_CAPABILITY: &str = "audio.session.observe";
pub const PIPEWIRE_OUTPUT_RESOURCE_PREFIX: &str = "audio:session:output:";
pub const PIPEWIRE_DEFAULT_OUTPUT_RESOURCE: &str = "audio:session:default-output";
pub const WIREPLUMBER_EXECUTABLE_PATH: &str = "/usr/bin/wpexec";
pub const LINURA_SESSION_AUDIO_HELPER_PATH: &str = "/usr/lib/linura/linura-session-audio.lua";
const WIREPLUMBER_HELPER_TIMEOUT: Duration = Duration::from_secs(2);
const WIREPLUMBER_HELPER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const WIREPLUMBER_HELPER_MAX_OUTPUT_BYTES: u64 = 64 * 1024;
const MAX_AUDIO_SINKS: usize = 256;

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct PipeWireSink {
    node_id: u32,
    object_serial: u64,
    node_name: String,
    is_default: bool,
    volume_percent: u64,
    muted: bool,
}

#[derive(Debug, Default)]
pub struct PipeWireSessionObserver {
    sequence: AtomicU64,
}

impl PipeWireSessionObserver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn list_sinks(&self) -> Result<Vec<PipeWireSink>, ProviderError> {
        parse_wireplumber_sink_snapshot(&run_wireplumber_audio_helper("{ action = \"observe\" }")?)
    }

    fn resolve_sink(&self, resource: &ResourceId) -> Result<PipeWireSink, ProviderError> {
        let sinks = self.list_sinks()?;
        if resource.as_str() == PIPEWIRE_DEFAULT_OUTPUT_RESOURCE {
            return sinks
                .into_iter()
                .find(|sink| sink.is_default)
                .ok_or_else(|| {
                    ProviderError::Unavailable("PipeWire has no current default audio sink".into())
                });
        }

        let node_id = pipewire_output_node_id(resource)?;
        sinks
            .into_iter()
            .find(|sink| sink.node_id == node_id)
            .ok_or_else(|| {
                ProviderError::Unavailable(format!(
                    "PipeWire output node {node_id} is not present in the current session"
                ))
            })
    }
}

impl Observer for PipeWireSessionObserver {
    fn observer_id(&self) -> ProviderId {
        provider_id(PIPEWIRE_SESSION_PROVIDER)
    }

    fn observation_capabilities(&self) -> Vec<Capability> {
        let health = self.health();
        vec![capability(
            PIPEWIRE_SESSION_CAPABILITY,
            PIPEWIRE_SESSION_PROVIDER,
            health.availability,
            health.reason,
        )]
    }

    fn health(&self) -> ProviderHealth {
        let provider = provider_id(PIPEWIRE_SESSION_PROVIDER);
        match self.list_sinks() {
            Ok(_) => ProviderHealth {
                provider,
                availability: ProviderAvailability::Available,
                reason: None,
            },
            Err(ProviderError::Unavailable(reason)) => ProviderHealth {
                provider,
                availability: ProviderAvailability::Unavailable,
                reason: Some(reason),
            },
            Err(error) => ProviderHealth {
                provider,
                availability: ProviderAvailability::Degraded,
                reason: Some(error.to_string()),
            },
        }
    }

    fn resources(&self) -> Result<Vec<ResourceId>, ProviderError> {
        let sinks = self.list_sinks()?;
        let mut resources = sinks
            .iter()
            .map(|sink| {
                ResourceId::new(format!("{PIPEWIRE_OUTPUT_RESOURCE_PREFIX}{}", sink.node_id))
                    .map_err(|error| invalid_identifier("PipeWire output resource", error))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if sinks.iter().any(|sink| sink.is_default) {
            resources.push(
                ResourceId::new(PIPEWIRE_DEFAULT_OUTPUT_RESOURCE).map_err(|error| {
                    invalid_identifier("PipeWire default output resource", error)
                })?,
            );
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
        if capability.as_str() != PIPEWIRE_SESSION_CAPABILITY {
            return Err(ProviderError::Unsupported(format!(
                "PipeWire session observer does not support {}",
                capability.as_str()
            )));
        }
        let sink = self.resolve_sink(resource)?;
        Ok(ObservationEnvelope {
            provider: provider_id(PIPEWIRE_SESSION_PROVIDER),
            resource: resource.clone(),
            capability: capability.clone(),
            authority: ObservationAuthority::NativeApi,
            observed_at_unix_ms: now_unix_ms()?,
            valid_for_ms: OBSERVATION_VALID_FOR_MS,
            sequence: next_sequence(&self.sequence)?,
            attributes: BTreeMap::from([
                (
                    "node_id".into(),
                    ObservedValue::U64(u64::from(sink.node_id)),
                ),
                ("name".into(), ObservedValue::Text(sink.node_name.clone())),
                ("is_default".into(), ObservedValue::Bool(sink.is_default)),
                (
                    "object_serial".into(),
                    ObservedValue::U64(sink.object_serial),
                ),
                ("node_name".into(), ObservedValue::Text(sink.node_name)),
                (
                    "media_class".into(),
                    ObservedValue::Text("Audio/Sink".into()),
                ),
                (
                    "volume_percent".into(),
                    ObservedValue::U64(sink.volume_percent),
                ),
                ("muted".into(), ObservedValue::Bool(sink.muted)),
            ]),
        })
    }
}

pub fn pipewire_output_node_id(resource: &ResourceId) -> Result<u32, ProviderError> {
    let value = resource.as_str();
    let Some(raw) = value.strip_prefix(PIPEWIRE_OUTPUT_RESOURCE_PREFIX) else {
        return Err(ProviderError::Unsupported(format!(
            "resource {value} is not an exact PipeWire output-node resource"
        )));
    };
    if raw.is_empty()
        || raw.len() > 10
        || raw.starts_with('+')
        || (raw.len() > 1 && raw.starts_with('0'))
        || !raw.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ProviderError::InvalidState(
            "PipeWire output-node resource has a non-canonical numeric id".into(),
        ));
    }
    let node_id = raw.parse::<u32>().map_err(|_| {
        ProviderError::InvalidState("PipeWire output-node id exceeds the u32 range".into())
    })?;
    if node_id == u32::MAX {
        return Err(ProviderError::InvalidState(
            "PipeWire output-node id is the reserved invalid id".into(),
        ));
    }
    Ok(node_id)
}

pub fn verify_packaged_session_audio_helper() -> Result<(), ProviderError> {
    let metadata = fs::symlink_metadata(LINURA_SESSION_AUDIO_HELPER_PATH).map_err(|_| {
        ProviderError::Unavailable(
            "Linura WirePlumber session-audio helper is not installed".into(),
        )
    })?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(ProviderError::InvalidState(
            "Linura WirePlumber session-audio helper integrity check failed".into(),
        ));
    }
    Ok(())
}

fn wireplumber_runtime_dir() -> Result<OsString, ProviderError> {
    let value = env::var_os("XDG_RUNTIME_DIR").ok_or_else(|| {
        ProviderError::Unavailable("XDG_RUNTIME_DIR is unavailable for PipeWire".into())
    })?;
    let path = PathBuf::from(&value);
    if !path.is_absolute() {
        return Err(ProviderError::InvalidState(
            "XDG_RUNTIME_DIR must be absolute for PipeWire".into(),
        ));
    }
    let metadata = fs::metadata(&path).map_err(|_| {
        ProviderError::Unavailable("XDG_RUNTIME_DIR cannot be inspected for PipeWire".into())
    })?;
    if !metadata.is_dir() {
        return Err(ProviderError::InvalidState(
            "XDG_RUNTIME_DIR is not a directory".into(),
        ));
    }
    Ok(value)
}

fn parse_wireplumber_sink_snapshot(output: &str) -> Result<Vec<PipeWireSink>, ProviderError> {
    let mut lines = output.lines();
    if lines.next() != Some("protocol\t1") {
        return Err(ProviderError::InvalidState(
            "WirePlumber helper protocol header is invalid".into(),
        ));
    }

    let mut sinks = Vec::new();
    let mut last_node_id = None;
    let mut default_count = 0_usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if sinks.len() >= MAX_AUDIO_SINKS {
            return Err(ProviderError::InvalidState(
                "WirePlumber audio-sink snapshot exceeds the bounded sink ceiling".into(),
            ));
        }

        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 7 || fields[0] != "sink" {
            return Err(ProviderError::InvalidState(
                "WirePlumber audio-sink snapshot has an invalid record shape".into(),
            ));
        }

        let node_id = parse_canonical_node_id(fields[1])?;
        if last_node_id.is_some_and(|previous| node_id <= previous) {
            return Err(ProviderError::InvalidState(
                "WirePlumber audio-sink snapshot is not strictly ordered".into(),
            ));
        }
        last_node_id = Some(node_id);

        let object_serial = parse_canonical_u64(fields[2], "object serial")?;
        if sinks
            .iter()
            .any(|sink: &PipeWireSink| sink.object_serial == object_serial)
        {
            return Err(ProviderError::InvalidState(
                "WirePlumber audio-sink snapshot contains a duplicate object serial".into(),
            ));
        }

        let node_name = fields[3];
        if node_name.is_empty()
            || node_name.len() > 1_024
            || node_name.chars().any(char::is_control)
        {
            return Err(ProviderError::InvalidState(
                "WirePlumber audio sink has an invalid node name".into(),
            ));
        }

        let is_default = parse_binary_flag(fields[4], "default marker")?;
        if is_default {
            default_count += 1;
            if default_count > 1 {
                return Err(ProviderError::InvalidState(
                    "WirePlumber reported more than one default audio sink".into(),
                ));
            }
        }

        let volume_percent = parse_canonical_u64(fields[5], "volume percentage")?;
        if volume_percent > 1_000 {
            return Err(ProviderError::InvalidState(
                "WirePlumber volume exceeds the bounded 1000% observation ceiling".into(),
            ));
        }
        let muted = parse_binary_flag(fields[6], "mute marker")?;

        sinks.push(PipeWireSink {
            node_id,
            object_serial,
            node_name: node_name.into(),
            is_default,
            volume_percent,
            muted,
        });
    }
    Ok(sinks)
}

fn parse_canonical_node_id(value: &str) -> Result<u32, ProviderError> {
    let value = parse_canonical_u64(value, "node id")?;
    let node_id = u32::try_from(value).map_err(|_| {
        ProviderError::InvalidState("WirePlumber node id exceeds the u32 range".into())
    })?;
    if node_id == u32::MAX {
        return Err(ProviderError::InvalidState(
            "WirePlumber node id is the reserved invalid id".into(),
        ));
    }
    Ok(node_id)
}

fn parse_canonical_u64(value: &str, label: &str) -> Result<u64, ProviderError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ProviderError::InvalidState(format!(
            "WirePlumber {label} is not a canonical unsigned integer"
        )));
    }
    value.parse::<u64>().map_err(|_| {
        ProviderError::InvalidState(format!("WirePlumber {label} exceeds the u64 range"))
    })
}

fn parse_binary_flag(value: &str, label: &str) -> Result<bool, ProviderError> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(ProviderError::InvalidState(format!(
            "WirePlumber {label} is not canonical"
        ))),
    }
}

fn run_wireplumber_audio_helper(arguments: &str) -> Result<String, ProviderError> {
    verify_packaged_session_audio_helper()?;
    let runtime_dir = wireplumber_runtime_dir()?;
    let mut child = Command::new(WIREPLUMBER_EXECUTABLE_PATH)
        .arg(LINURA_SESSION_AUDIO_HELPER_PATH)
        .arg(arguments)
        .env_clear()
        .env("XDG_RUNTIME_DIR", runtime_dir)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| {
            ProviderError::Unavailable(
                "cannot start bounded WirePlumber session-audio helper".into(),
            )
        })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        ProviderError::Internal("WirePlumber helper stdout pipe is unavailable".into())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        ProviderError::Internal("WirePlumber helper stderr pipe is unavailable".into())
    })?;
    let stdout_reader = thread::spawn(move || read_bounded_pipe(stdout));
    let stderr_reader = thread::spawn(move || read_bounded_pipe(stderr));

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_| {
            ProviderError::Unavailable(
                "cannot observe WirePlumber session-audio helper state".into(),
            )
        })? {
            break status;
        }
        if started.elapsed() >= WIREPLUMBER_HELPER_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(ProviderError::Unavailable(
                "WirePlumber session-audio helper exceeded the two-second deadline".into(),
            ));
        }
        thread::sleep(WIREPLUMBER_HELPER_POLL_INTERVAL);
    };

    let stdout = join_bounded_pipe(stdout_reader)?;
    join_bounded_pipe(stderr_reader)?;
    if !status.success() {
        return Err(ProviderError::Unavailable(format!(
            "WirePlumber session-audio helper failed with status {:?}",
            status.code()
        )));
    }
    String::from_utf8(stdout).map_err(|_| {
        ProviderError::InvalidState("WirePlumber session-audio output is not UTF-8".into())
    })
}

fn read_bounded_pipe<R: Read>(reader: R) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    reader
        .take(WIREPLUMBER_HELPER_MAX_OUTPUT_BYTES + 1)
        .read_to_end(&mut output)
        .map_err(|_| "cannot read WirePlumber helper pipe".to_owned())?;
    if u64::try_from(output.len()).unwrap_or(u64::MAX) > WIREPLUMBER_HELPER_MAX_OUTPUT_BYTES {
        return Err("WirePlumber helper output exceeds the bounded output ceiling".into());
    }
    Ok(output)
}

fn join_bounded_pipe(
    handle: thread::JoinHandle<Result<Vec<u8>, String>>,
) -> Result<Vec<u8>, ProviderError> {
    handle
        .join()
        .map_err(|_| {
            ProviderError::Internal(
                "WirePlumber helper output reader terminated unexpectedly".into(),
            )
        })?
        .map_err(ProviderError::InvalidState)
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
    fn pipewire_output_resource_is_exact_and_canonical() {
        let valid = ResourceId::new("audio:session:output:42")
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(pipewire_output_node_id(&valid), Ok(42));
        for value in [
            "audio:session:default-output",
            "audio:session:output:",
            "audio:session:output:042",
            "audio:session:output:+42",
            "audio:session:input:42",
        ] {
            let resource = ResourceId::new(value).unwrap_or_else(|error| unreachable!("{error}"));
            assert!(pipewire_output_node_id(&resource).is_err(), "{value}");
        }
    }

    #[test]
    fn wireplumber_snapshot_parser_requires_canonical_identity_and_order() {
        let sinks = parse_wireplumber_sink_snapshot(
            "protocol\t1\nsink\t42\t9876\talsa_output.pci\t1\t40\t0\nsink\t77\t9999\tusb_dac\t0\t125\t1\n",
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(sinks.len(), 2);
        assert_eq!(sinks[0].node_id, 42);
        assert_eq!(sinks[0].object_serial, 9_876);
        assert_eq!(sinks[0].node_name, "alsa_output.pci");
        assert!(sinks[0].is_default);
        assert_eq!(sinks[0].volume_percent, 40);
        assert!(!sinks[0].muted);
        assert_eq!(sinks[1].volume_percent, 125);
        assert!(sinks[1].muted);

        for invalid in [
            "sink\t42\t9876\tsink\t1\t40\t0\n",
            "protocol\t2\n",
            "protocol\t1\nsink\t42\t9876\tsink\t1\t40\t0\nsink\t42\t9999\tother\t0\t40\t0\n",
            "protocol\t1\nsink\t77\t9876\tsink\t0\t40\t0\nsink\t42\t9999\tother\t0\t40\t0\n",
            "protocol\t1\nsink\t42\t9876\tsink\t1\t40\t0\nsink\t77\t9876\tother\t0\t40\t0\n",
            "protocol\t1\nsink\t42\t9876\tsink\t1\t40\t0\nsink\t77\t9999\tother\t1\t40\t0\n",
            "protocol\t1\nsink\t4294967295\t9876\tsink\t0\t40\t0\n",
            "protocol\t1\nsink\t042\t9876\tsink\t0\t40\t0\n",
        ] {
            assert!(
                parse_wireplumber_sink_snapshot(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn wireplumber_snapshot_parser_rejects_control_material_and_unbounded_volume() {
        assert!(
            parse_wireplumber_sink_snapshot("protocol\t1\nsink\t42\t9876\tbad\rname\t0\t40\t0\n",)
                .is_err()
        );
        assert!(
            parse_wireplumber_sink_snapshot("protocol\t1\nsink\t42\t9876\tsink\t0\t1001\t0\n",)
                .is_err()
        );
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
