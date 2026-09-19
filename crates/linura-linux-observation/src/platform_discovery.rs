use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use linura_core::{CapabilityId, ProviderId, ResourceId};
use linura_observation::{ObservationAuthority, ObservationEnvelope, ObservedValue};
use zbus::blocking::connection::Builder as ConnectionBuilder;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::OwnedObjectPath;

const LOGIN1_SERVICE: &str = "org.freedesktop.login1";
const LOGIN1_PATH: &str = "/org/freedesktop/login1";
const LOGIN1_MANAGER: &str = "org.freedesktop.login1.Manager";
const LOGIN1_SESSION: &str = "org.freedesktop.login1.Session";
const LOGIN1_USER: &str = "org.freedesktop.login1.User";

const DBUS_SERVICE: &str = "org.freedesktop.DBus";
const DBUS_PATH: &str = "/org/freedesktop/DBus";
const DBUS_INTERFACE: &str = "org.freedesktop.DBus";
const DBUS_PEER: &str = "org.freedesktop.DBus.Peer";

const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1";
const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER: &str = "org.freedesktop.systemd1.Manager";
const SYSTEMD_UNIT: &str = "org.freedesktop.systemd1.Unit";

const PLATFORM_PROVIDER: &str = "linux-platform";
pub const PLATFORM_DISTRIBUTION_CAPABILITY: &str = "platform.distribution.observe";
pub const PLATFORM_ARCHITECTURE_CAPABILITY: &str = "platform.architecture.observe";
pub const PLATFORM_INIT_CAPABILITY: &str = "platform.init-system.observe";
pub const PLATFORM_SESSION_CAPABILITY: &str = "platform.session.observe";
pub const PLATFORM_COMPOSITOR_CAPABILITY: &str = "platform.compositor.observe";
pub const PLATFORM_NETWORK_PROVIDER_CAPABILITY: &str = "platform.provider.network.observe";
pub const PLATFORM_BLUETOOTH_PROVIDER_CAPABILITY: &str = "platform.provider.bluetooth.observe";
pub const PLATFORM_AUDIO_PROVIDER_CAPABILITY: &str = "platform.provider.audio.observe";
pub const PLATFORM_STORAGE_PROVIDER_CAPABILITY: &str = "platform.provider.storage.observe";
pub const PLATFORM_AUTHORIZATION_PROVIDER_CAPABILITY: &str =
    "platform.provider.authorization.observe";
pub const PLATFORM_FILESYSTEM_PROVIDER_CAPABILITY: &str = "platform.provider.filesystem.observe";
pub const PLATFORM_SNAPSHOTS_PROVIDER_CAPABILITY: &str = "platform.provider.snapshots.observe";

const OBSERVATION_VALID_FOR_MS: u64 = 2_000;
const NATIVE_PROBE_TIMEOUT: Duration = Duration::from_millis(750);
const HYPRLAND_IO_TIMEOUT: Duration = Duration::from_millis(750);
const HYPRLAND_MAX_RESPONSE_BYTES: u64 = 64 * 1024;
const OS_RELEASE_MAX_BYTES: u64 = 16 * 1024;
const PROC_COMM_MAX_BYTES: u64 = 256;
const MOUNTINFO_MAX_BYTES: u64 = 2 * 1024 * 1024;
const HYPRLAND_SOCKET_NAME: &str = ".socket.sock";
static PLATFORM_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogindSessionTarget {
    session_id: String,
    uid: u32,
}

impl LogindSessionTarget {
    pub fn new(session_id: impl Into<String>, uid: u32) -> Result<Self, PlatformProbeError> {
        let session_id = session_id.into();
        if session_id.is_empty()
            || session_id.len() > 128
            || session_id.chars().any(char::is_control)
            || !session_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(PlatformProbeError::new("invalid logind session identifier"));
        }
        Ok(Self { session_id, uid })
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeSessionContext {
    session_id: String,
    session_type: String,
    desktop: String,
    runtime_path: PathBuf,
    uid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformProbeError {
    message: String,
}

impl PlatformProbeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PlatformProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PlatformProbeError {}

pub fn observe_distribution() -> Result<ObservationEnvelope, PlatformProbeError> {
    let text = read_bounded_utf8("/etc/os-release", OS_RELEASE_MAX_BYTES)?;
    let identity = parse_os_release_id(&text)?;
    platform_identity_envelope(
        "platform:distribution",
        PLATFORM_DISTRIBUTION_CAPABILITY,
        ObservationAuthority::Filesystem,
        identity,
        "/etc/os-release",
    )
}

pub fn observe_architecture() -> Result<ObservationEnvelope, PlatformProbeError> {
    platform_identity_envelope(
        "platform:architecture",
        PLATFORM_ARCHITECTURE_CAPABILITY,
        ObservationAuthority::NativeApi,
        normalized_identity("native architecture", std::env::consts::ARCH)?,
        "rust-target",
    )
}

pub fn observe_init_system() -> Result<ObservationEnvelope, PlatformProbeError> {
    let text = read_bounded_utf8("/proc/1/comm", PROC_COMM_MAX_BYTES)?;
    platform_identity_envelope(
        "platform:init",
        PLATFORM_INIT_CAPABILITY,
        ObservationAuthority::Kernel,
        normalized_identity("PID 1 identity", &text)?,
        "procfs:/proc/1/comm",
    )
}

pub fn observe_session(
    target: &LogindSessionTarget,
) -> Result<ObservationEnvelope, PlatformProbeError> {
    let connection = connect_system_bus()?;
    let context = query_session_context(&connection, target)?;
    platform_identity_envelope(
        "platform:session",
        PLATFORM_SESSION_CAPABILITY,
        ObservationAuthority::NativeApi,
        context.session_type,
        "logind",
    )
}

pub fn observe_compositor(
    target: &LogindSessionTarget,
) -> Result<ObservationEnvelope, PlatformProbeError> {
    let connection = connect_system_bus()?;
    let context = query_session_context(&connection, target)?;
    let identity = probe_compositor(&context)?;
    platform_identity_envelope(
        "platform:compositor",
        PLATFORM_COMPOSITOR_CAPABILITY,
        ObservationAuthority::NativeApi,
        identity,
        "hyprland-ipc",
    )
}

pub fn observe_network_provider() -> Result<ObservationEnvelope, PlatformProbeError> {
    observe_selected_dbus_provider(
        "networkmanager",
        "network",
        PLATFORM_NETWORK_PROVIDER_CAPABILITY,
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
    )
}

pub fn observe_bluetooth_provider() -> Result<ObservationEnvelope, PlatformProbeError> {
    observe_selected_dbus_provider(
        "bluez",
        "bluetooth",
        PLATFORM_BLUETOOTH_PROVIDER_CAPABILITY,
        "org.bluez",
        "/",
    )
}

pub fn observe_storage_provider() -> Result<ObservationEnvelope, PlatformProbeError> {
    observe_selected_dbus_provider(
        "udisks2",
        "storage",
        PLATFORM_STORAGE_PROVIDER_CAPABILITY,
        "org.freedesktop.UDisks2",
        "/org/freedesktop/UDisks2",
    )
}

pub fn observe_authorization_provider() -> Result<ObservationEnvelope, PlatformProbeError> {
    observe_selected_dbus_provider(
        "polkit",
        "authorization",
        PLATFORM_AUTHORIZATION_PROVIDER_CAPABILITY,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
    )
}

pub fn observe_snapshots_provider() -> Result<ObservationEnvelope, PlatformProbeError> {
    observe_selected_dbus_provider(
        "snapper",
        "snapshots",
        PLATFORM_SNAPSHOTS_PROVIDER_CAPABILITY,
        "org.opensuse.Snapper",
        "/org/opensuse/Snapper",
    )
}

pub fn observe_filesystem_provider() -> Result<ObservationEnvelope, PlatformProbeError> {
    let mountinfo = read_bounded_utf8("/proc/self/mountinfo", MOUNTINFO_MAX_BYTES)?;
    let identity = root_filesystem_type(&mountinfo)?;
    provider_identity_envelope(
        &identity,
        "filesystem",
        PLATFORM_FILESYSTEM_PROVIDER_CAPABILITY,
        ObservationAuthority::Kernel,
        "procfs:/proc/self/mountinfo",
    )
}

pub fn observe_audio_provider(
    target: &LogindSessionTarget,
) -> Result<ObservationEnvelope, PlatformProbeError> {
    let system_bus = connect_system_bus()?;
    let context = query_session_context(&system_bus, target)?;
    let connection = connect_runtime_bus(&context)?;
    let pipewire = user_unit_active(&connection, "pipewire.service")?;
    let wireplumber = user_unit_active(&connection, "wireplumber.service")?;
    let identity = audio_identity(pipewire, wireplumber);
    if identity != "pipewire-wireplumber" {
        return Err(PlatformProbeError::new(format!(
            "active audio provider set is {identity}, not pipewire-wireplumber"
        )));
    }
    provider_identity_envelope(
        identity,
        "audio",
        PLATFORM_AUDIO_PROVIDER_CAPABILITY,
        ObservationAuthority::NativeApi,
        "logind-user-systemd",
    )
}

fn connect_system_bus() -> Result<Connection, PlatformProbeError> {
    ConnectionBuilder::system()
        .map(|builder| builder.method_timeout(NATIVE_PROBE_TIMEOUT))
        .and_then(ConnectionBuilder::build)
        .map_err(|error| {
            PlatformProbeError::new(format!("cannot connect to system D-Bus: {error}"))
        })
}

fn query_session_context(
    connection: &Connection,
    target: &LogindSessionTarget,
) -> Result<NativeSessionContext, PlatformProbeError> {
    let manager =
        Proxy::new(connection, LOGIN1_SERVICE, LOGIN1_PATH, LOGIN1_MANAGER).map_err(|error| {
            PlatformProbeError::new(format!("cannot create logind manager proxy: {error}"))
        })?;
    let session_path: OwnedObjectPath = manager
        .call("GetSession", &(target.session_id(),))
        .map_err(|error| {
            PlatformProbeError::new(format!(
                "cannot resolve requested logind session {}: {error}",
                target.session_id()
            ))
        })?;
    let session = Proxy::new(
        connection,
        LOGIN1_SERVICE,
        session_path.as_str(),
        LOGIN1_SESSION,
    )
    .map_err(|error| {
        PlatformProbeError::new(format!("cannot create logind session proxy: {error}"))
    })?;

    let session_type: String = session.get_property("Type").map_err(|error| {
        PlatformProbeError::new(format!("cannot read logind session Type: {error}"))
    })?;
    let desktop: String = session.get_property("Desktop").map_err(|error| {
        PlatformProbeError::new(format!("cannot read logind session Desktop: {error}"))
    })?;
    let user: (u32, OwnedObjectPath) = session.get_property("User").map_err(|error| {
        PlatformProbeError::new(format!("cannot read logind session User: {error}"))
    })?;
    if user.0 != target.uid() {
        return Err(PlatformProbeError::new(
            "requested logind session user does not match the Control-selected uid",
        ));
    }
    let user_proxy =
        Proxy::new(connection, LOGIN1_SERVICE, user.1.as_str(), LOGIN1_USER).map_err(|error| {
            PlatformProbeError::new(format!("cannot create logind user proxy: {error}"))
        })?;
    let runtime_path: String = user_proxy.get_property("RuntimePath").map_err(|error| {
        PlatformProbeError::new(format!("cannot read logind user RuntimePath: {error}"))
    })?;

    let session_type = normalized_identity("logind session type", &session_type)?;
    let desktop = if desktop.trim().is_empty() {
        String::new()
    } else {
        normalized_identity("logind desktop identity", &desktop)?
    };
    let runtime_path = PathBuf::from(runtime_path);
    validate_runtime_path(&runtime_path, user.0)?;

    Ok(NativeSessionContext {
        session_id: target.session_id().to_owned(),
        session_type,
        desktop,
        runtime_path,
        uid: user.0,
    })
}

fn observe_selected_dbus_provider(
    identity: &str,
    role: &str,
    capability: &str,
    service: &str,
    path: &str,
) -> Result<ObservationEnvelope, PlatformProbeError> {
    let connection = connect_system_bus()?;
    require_owned_service(&connection, service)?;
    let peer = Proxy::new(&connection, service, path, DBUS_PEER).map_err(|error| {
        PlatformProbeError::new(format!("cannot create {identity} health proxy: {error}"))
    })?;
    let _: () = peer.call("Ping", &()).map_err(|error| {
        PlatformProbeError::new(format!("{identity} direct health probe failed: {error}"))
    })?;
    provider_identity_envelope(
        identity,
        role,
        capability,
        ObservationAuthority::NativeApi,
        service,
    )
}

fn require_owned_service(connection: &Connection, service: &str) -> Result<(), PlatformProbeError> {
    let proxy =
        Proxy::new(connection, DBUS_SERVICE, DBUS_PATH, DBUS_INTERFACE).map_err(|error| {
            PlatformProbeError::new(format!("cannot create D-Bus daemon proxy: {error}"))
        })?;
    let owned: bool = proxy.call("NameHasOwner", &(service,)).map_err(|error| {
        PlatformProbeError::new(format!(
            "cannot query D-Bus ownership for {service}: {error}"
        ))
    })?;
    if !owned {
        return Err(PlatformProbeError::new(format!(
            "D-Bus service {service} is not currently owned; activatable presence is insufficient evidence"
        )));
    }
    Ok(())
}

fn connect_runtime_bus(context: &NativeSessionContext) -> Result<Connection, PlatformProbeError> {
    let bus_path = context.runtime_path.join("bus");
    let metadata = std::fs::symlink_metadata(&bus_path).map_err(|error| {
        PlatformProbeError::new(format!("cannot inspect logind user bus socket: {error}"))
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_socket()
        || metadata.uid() != context.uid
    {
        return Err(PlatformProbeError::new(
            "logind user bus socket is not trusted for the selected session",
        ));
    }
    let path = bus_path
        .to_str()
        .ok_or_else(|| PlatformProbeError::new("logind user bus socket path is not UTF-8"))?;
    if path.contains([',', ';']) {
        return Err(PlatformProbeError::new(
            "logind user bus socket path cannot be represented safely as a D-Bus address",
        ));
    }
    let address = format!("unix:path={path}");
    ConnectionBuilder::address(address.as_str())
        .map(|builder| builder.method_timeout(NATIVE_PROBE_TIMEOUT))
        .and_then(ConnectionBuilder::build)
        .map_err(|error| {
            PlatformProbeError::new(format!("cannot connect to logind user D-Bus: {error}"))
        })
}

fn user_unit_active(connection: &Connection, unit_name: &str) -> Result<bool, PlatformProbeError> {
    let manager = Proxy::new(connection, SYSTEMD_SERVICE, SYSTEMD_PATH, SYSTEMD_MANAGER).map_err(
        |error| {
            PlatformProbeError::new(format!("cannot create user systemd manager proxy: {error}"))
        },
    )?;
    let unit_path: OwnedObjectPath = manager.call("GetUnit", &(unit_name,)).map_err(|error| {
        PlatformProbeError::new(format!(
            "cannot resolve active user unit {unit_name}: {error}"
        ))
    })?;
    let unit = Proxy::new(
        connection,
        SYSTEMD_SERVICE,
        unit_path.as_str(),
        SYSTEMD_UNIT,
    )
    .map_err(|error| {
        PlatformProbeError::new(format!(
            "cannot create user unit proxy for {unit_name}: {error}"
        ))
    })?;
    let active_state: String = unit.get_property("ActiveState").map_err(|error| {
        PlatformProbeError::new(format!(
            "cannot read user unit ActiveState for {unit_name}: {error}"
        ))
    })?;
    Ok(active_state == "active")
}

fn probe_compositor(context: &NativeSessionContext) -> Result<String, PlatformProbeError> {
    if context.desktop.is_empty() {
        return Err(PlatformProbeError::new(format!(
            "selected logind session {} does not identify a desktop; compositor IPC cannot be bound safely",
            context.session_id
        )));
    }
    if context.desktop != "hyprland" {
        return Ok(context.desktop.clone());
    }
    let socket = locate_hyprland_socket(context)?;
    verify_hyprland_ipc(&socket)?;
    Ok("hyprland".to_owned())
}

fn locate_hyprland_socket(context: &NativeSessionContext) -> Result<PathBuf, PlatformProbeError> {
    let hypr_root = context.runtime_path.join("hypr");
    let metadata = std::fs::symlink_metadata(&hypr_root).map_err(|error| {
        PlatformProbeError::new(format!(
            "cannot inspect Hyprland runtime directory: {error}"
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != context.uid {
        return Err(PlatformProbeError::new(
            "Hyprland runtime directory is not trusted for the selected session",
        ));
    }

    let hinted_socket = std::env::var("HYPRLAND_INSTANCE_SIGNATURE")
        .ok()
        .filter(|signature| safe_instance_signature(signature))
        .map(|signature| hypr_root.join(signature))
        .filter(|instance| valid_owned_directory(instance, context.uid))
        .map(|instance| instance.join(HYPRLAND_SOCKET_NAME))
        .filter(|socket| valid_hyprland_socket(socket, context.uid));

    let entries = std::fs::read_dir(&hypr_root).map_err(|error| {
        PlatformProbeError::new(format!(
            "cannot enumerate Hyprland runtime instances: {error}"
        ))
    })?;
    let mut candidates = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            PlatformProbeError::new(format!("cannot inspect Hyprland runtime instance: {error}"))
        })?;
        let directory = entry.path();
        if !valid_owned_directory(&directory, context.uid) {
            continue;
        }
        let socket = directory.join(HYPRLAND_SOCKET_NAME);
        if valid_hyprland_socket(&socket, context.uid) {
            candidates.push(socket);
        }
    }

    let selected = select_unique_hyprland_socket(candidates, &context.session_id)?;
    if hinted_socket.is_some_and(|hinted| hinted != selected) {
        return Err(PlatformProbeError::new(format!(
            "HYPRLAND_INSTANCE_SIGNATURE does not identify the unique IPC instance for selected session {}",
            context.session_id
        )));
    }
    Ok(selected)
}

fn select_unique_hyprland_socket(
    mut candidates: Vec<PathBuf>,
    session_id: &str,
) -> Result<PathBuf, PlatformProbeError> {
    match candidates.len() {
        1 => Ok(candidates
            .pop()
            .unwrap_or_else(|| unreachable!("one candidate was checked"))),
        0 => Err(PlatformProbeError::new(format!(
            "no trusted Hyprland IPC socket can be bound to selected session {session_id}"
        ))),
        _ => Err(PlatformProbeError::new(format!(
            "multiple trusted Hyprland IPC instances exist for the selected user; selected session {session_id} cannot be bound unambiguously"
        ))),
    }
}

fn validate_runtime_path(path: &Path, uid: u32) -> Result<(), PlatformProbeError> {
    if !path.is_absolute() {
        return Err(PlatformProbeError::new(
            "logind RuntimePath is not absolute",
        ));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        PlatformProbeError::new(format!("cannot inspect logind RuntimePath: {error}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PlatformProbeError::new(
            "logind RuntimePath is not a real directory",
        ));
    }
    if metadata.uid() != uid {
        return Err(PlatformProbeError::new(
            "logind RuntimePath ownership does not match the selected session user",
        ));
    }
    Ok(())
}

fn valid_owned_directory(path: &Path, uid: u32) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        !metadata.file_type().is_symlink() && metadata.is_dir() && metadata.uid() == uid
    })
}

fn valid_hyprland_socket(path: &Path, uid: u32) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        !metadata.file_type().is_symlink()
            && metadata.file_type().is_socket()
            && metadata.uid() == uid
    })
}

fn verify_hyprland_ipc(path: &Path) -> Result<(), PlatformProbeError> {
    let mut stream = UnixStream::connect(path).map_err(|error| {
        PlatformProbeError::new(format!("cannot connect to Hyprland IPC: {error}"))
    })?;
    stream
        .set_read_timeout(Some(HYPRLAND_IO_TIMEOUT))
        .map_err(|error| {
            PlatformProbeError::new(format!("cannot set Hyprland IPC read timeout: {error}"))
        })?;
    stream
        .set_write_timeout(Some(HYPRLAND_IO_TIMEOUT))
        .map_err(|error| {
            PlatformProbeError::new(format!("cannot set Hyprland IPC write timeout: {error}"))
        })?;
    stream.write_all(b"version").map_err(|error| {
        PlatformProbeError::new(format!("cannot query Hyprland IPC version: {error}"))
    })?;
    stream.shutdown(Shutdown::Write).map_err(|error| {
        PlatformProbeError::new(format!("cannot close Hyprland IPC request side: {error}"))
    })?;

    let mut response = Vec::new();
    Read::by_ref(&mut stream)
        .take(HYPRLAND_MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)
        .map_err(|error| {
            PlatformProbeError::new(format!(
                "cannot read Hyprland IPC version response: {error}"
            ))
        })?;
    if response.len() as u64 > HYPRLAND_MAX_RESPONSE_BYTES {
        return Err(PlatformProbeError::new(
            "Hyprland IPC version response exceeds the bounded evidence size",
        ));
    }
    let response = String::from_utf8(response)
        .map_err(|_| PlatformProbeError::new("Hyprland IPC version response is not UTF-8"))?;
    if !valid_hyprland_version_response(&response) {
        return Err(PlatformProbeError::new(
            "Hyprland IPC returned an unexpected version response",
        ));
    }
    Ok(())
}

fn read_bounded_utf8(path: &str, max_bytes: u64) -> Result<String, PlatformProbeError> {
    let file = File::open(path)
        .map_err(|error| PlatformProbeError::new(format!("cannot open {path}: {error}")))?;
    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| PlatformProbeError::new(format!("cannot read {path}: {error}")))?;
    if bytes.len() as u64 > max_bytes {
        return Err(PlatformProbeError::new(format!(
            "{path} exceeds the bounded evidence size"
        )));
    }
    String::from_utf8(bytes)
        .map_err(|_| PlatformProbeError::new(format!("{path} is not valid UTF-8")))
}

fn parse_os_release_id(text: &str) -> Result<String, PlatformProbeError> {
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(value) = line.strip_prefix("ID=") else {
            continue;
        };
        let value = parse_os_release_scalar(value)?;
        if value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(PlatformProbeError::new(
                "os-release ID contains unsupported characters",
            ));
        }
        return normalized_identity("os-release ID", &value);
    }
    Err(PlatformProbeError::new(
        "/etc/os-release does not contain ID",
    ))
}

fn parse_os_release_scalar(value: &str) -> Result<String, PlatformProbeError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(PlatformProbeError::new("os-release ID is empty"));
    }
    let bytes = value.as_bytes();
    if matches!(bytes.first(), Some(b'"') | Some(b'\'')) {
        let quote = bytes[0];
        if bytes.len() < 2 || bytes.last().copied() != Some(quote) {
            return Err(PlatformProbeError::new(
                "os-release ID has an unterminated quoted value",
            ));
        }
        let inner = &value[1..value.len() - 1];
        if inner.contains('\\') {
            return Err(PlatformProbeError::new(
                "os-release ID uses unsupported escape syntax",
            ));
        }
        return Ok(inner.to_owned());
    }
    if value.contains('"') || value.contains('\'') || value.contains('\\') {
        return Err(PlatformProbeError::new(
            "os-release ID has malformed quoting",
        ));
    }
    Ok(value.to_owned())
}

fn normalized_identity(label: &str, value: &str) -> Result<String, PlatformProbeError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(PlatformProbeError::new(format!("{label} is empty")));
    }
    if value.len() > 256 || value.chars().any(char::is_control) {
        return Err(PlatformProbeError::new(format!("{label} is malformed")));
    }
    Ok(value.to_ascii_lowercase())
}

fn root_filesystem_type(mountinfo: &str) -> Result<String, PlatformProbeError> {
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        if left.split_whitespace().nth(4) != Some("/") {
            continue;
        }
        let Some(filesystem) = right.split_whitespace().next() else {
            return Err(PlatformProbeError::new(
                "root mount entry is missing a filesystem type",
            ));
        };
        return normalized_identity("root filesystem type", filesystem);
    }
    Err(PlatformProbeError::new(
        "mountinfo does not contain the root mount",
    ))
}

fn audio_identity(pipewire: bool, wireplumber: bool) -> &'static str {
    match (pipewire, wireplumber) {
        (true, true) => "pipewire-wireplumber",
        (true, false) => "pipewire-only",
        (false, true) => "wireplumber-only",
        (false, false) => "absent",
    }
}

fn safe_instance_signature(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_hyprland_version_response(response: &str) -> bool {
    response
        .lines()
        .find(|line| !line.trim().is_empty())
        .is_some_and(|line| {
            line.trim_start()
                .to_ascii_lowercase()
                .starts_with("hyprland")
        })
}

fn platform_identity_envelope(
    resource: &str,
    capability: &str,
    authority: ObservationAuthority,
    identity: String,
    source: &str,
) -> Result<ObservationEnvelope, PlatformProbeError> {
    envelope(
        PLATFORM_PROVIDER,
        resource,
        capability,
        authority,
        Some(identity),
        source,
    )
}

fn provider_identity_envelope(
    provider: &str,
    role: &str,
    capability: &str,
    authority: ObservationAuthority,
    source: &str,
) -> Result<ObservationEnvelope, PlatformProbeError> {
    envelope(
        provider,
        &format!("platform:provider:{role}"),
        capability,
        authority,
        None,
        source,
    )
}

fn envelope(
    provider: &str,
    resource: &str,
    capability: &str,
    authority: ObservationAuthority,
    identity: Option<String>,
    source: &str,
) -> Result<ObservationEnvelope, PlatformProbeError> {
    let mut attributes =
        BTreeMap::from([("source".to_owned(), ObservedValue::Text(source.to_owned()))]);
    if let Some(identity) = identity {
        attributes.insert("identity".to_owned(), ObservedValue::Text(identity));
    }
    Ok(ObservationEnvelope {
        provider: ProviderId::new(provider)
            .map_err(|error| PlatformProbeError::new(format!("invalid provider id: {error}")))?,
        resource: ResourceId::new(resource)
            .map_err(|error| PlatformProbeError::new(format!("invalid resource id: {error}")))?,
        capability: CapabilityId::new(capability)
            .map_err(|error| PlatformProbeError::new(format!("invalid capability id: {error}")))?,
        authority,
        observed_at_unix_ms: now_unix_ms()?,
        valid_for_ms: OBSERVATION_VALID_FOR_MS,
        sequence: next_sequence()?,
        attributes,
    })
}

fn now_unix_ms() -> Result<u64, PlatformProbeError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PlatformProbeError::new("system clock is before the Unix epoch"))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| PlatformProbeError::new("system time does not fit observation timestamp"))
}

fn next_sequence() -> Result<u64, PlatformProbeError> {
    PLATFORM_SEQUENCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map(|previous| previous + 1)
        .map_err(|_| PlatformProbeError::new("platform observation sequence exhausted"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_target_rejects_unbounded_or_unsafe_identifiers() {
        assert!(LogindSessionTarget::new("2", 1000).is_ok());
        assert!(LogindSessionTarget::new("../../other", 1000).is_err());
        assert!(LogindSessionTarget::new("bad\nvalue", 1000).is_err());
    }

    #[test]
    fn os_release_id_accepts_quoted_and_unquoted_values() {
        assert_eq!(
            parse_os_release_id("NAME=Arch Linux\nID=arch\n"),
            Ok("arch".to_owned())
        );
        assert_eq!(parse_os_release_id("ID=\"Arch\"\n"), Ok("arch".to_owned()));
        assert!(parse_os_release_id("ID=\"arch\n").is_err());
        assert!(parse_os_release_id("NAME=Arch Linux\n").is_err());
    }

    #[test]
    fn root_filesystem_parser_reads_kernel_mountinfo_identity() {
        let btrfs = "36 25 0:31 /@ / rw,relatime - btrfs /dev/vda2 rw,ssd\n";
        assert_eq!(root_filesystem_type(btrfs), Ok("btrfs".to_owned()));
        let ext4 = "36 25 8:2 / / rw,relatime - ext4 /dev/vda2 rw\n";
        assert_eq!(root_filesystem_type(ext4), Ok("ext4".to_owned()));
        assert!(root_filesystem_type("malformed\n").is_err());
    }

    #[test]
    fn audio_provider_requires_both_pipewire_and_wireplumber_units() {
        assert_eq!(audio_identity(true, true), "pipewire-wireplumber");
        assert_eq!(audio_identity(true, false), "pipewire-only");
        assert_eq!(audio_identity(false, true), "wireplumber-only");
        assert_eq!(audio_identity(false, false), "absent");
    }

    #[test]
    fn hyprland_signature_is_only_a_bounded_locator_hint() {
        assert!(safe_instance_signature("deadbeef_123-1.0"));
        assert!(!safe_instance_signature(""));
        assert!(!safe_instance_signature(".."));
        assert!(!safe_instance_signature("../../other"));
        assert!(!safe_instance_signature("contains/slash"));
    }

    #[test]
    fn compositor_socket_selection_fails_closed_on_cross_session_ambiguity() {
        let only = PathBuf::from("/run/user/1000/hypr/one/.socket.sock");
        assert_eq!(
            select_unique_hyprland_socket(vec![only.clone()], "2"),
            Ok(only)
        );
        assert!(select_unique_hyprland_socket(Vec::new(), "2").is_err());
        assert!(
            select_unique_hyprland_socket(
                vec![
                    PathBuf::from("/run/user/1000/hypr/one/.socket.sock"),
                    PathBuf::from("/run/user/1000/hypr/two/.socket.sock"),
                ],
                "2",
            )
            .is_err()
        );
    }

    #[test]
    fn compositor_ipc_response_must_identify_hyprland() {
        assert!(valid_hyprland_version_response(
            "Hyprland, built from branch main at commit abc\n"
        ));
        assert!(valid_hyprland_version_response(
            "\n  Hyprland 0.55.0 built from branch main\n"
        ));
        assert!(!valid_hyprland_version_response("sway version 1.10\n"));
        assert!(!valid_hyprland_version_response(""));
    }
}
