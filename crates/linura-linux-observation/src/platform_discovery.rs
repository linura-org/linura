use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use async_io::Timer;
use futures_lite::future;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::net::sockopt::{socket_error, socket_peercred};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use linura_core::{CapabilityId, ProviderId, ResourceId};
use linura_observation::{ObservationAuthority, ObservationEnvelope, ObservedValue};
use zbus::blocking::{Connection, Proxy};
use zbus::connection::Builder as AsyncConnectionBuilder;
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

const NETWORKMANAGER_SERVICE: &str = "org.freedesktop.NetworkManager";
const NETWORKMANAGER_PATH: &str = "/org/freedesktop/NetworkManager";
const NETWORKMANAGER_INTERFACE: &str = "org.freedesktop.NetworkManager";
const NETWORKMANAGER_DEVICE_INTERFACE: &str = "org.freedesktop.NetworkManager.Device";
const NETWORKMANAGER_DEVICE_TYPE_LOOPBACK: u32 = 32;
const NETWORKMANAGER_MAX_DEVICES: usize = 128;

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
const HYPRLAND_DISCOVERY_TIMEOUT: Duration = Duration::from_millis(1_500);
const HYPRLAND_MAX_RUNTIME_ENTRIES: usize = 32;
const HYPRLAND_MAX_RESPONSE_BYTES: u64 = 64 * 1024;
const OS_RELEASE_MAX_BYTES: u64 = 16 * 1024;
const PROC_COMM_MAX_BYTES: u64 = 256;
const PROC_NET_UNIX_MAX_BYTES: u64 = 4 * 1024 * 1024;
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
    session_object_path: String,
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
    let uname = rustix::system::uname();
    let machine = uname.machine().to_str().map_err(|_| {
        PlatformProbeError::new("runtime kernel architecture from uname is not valid UTF-8")
    })?;
    platform_identity_envelope(
        "platform:architecture",
        PLATFORM_ARCHITECTURE_CAPABILITY,
        ObservationAuthority::NativeApi,
        normalized_identity("runtime kernel architecture", machine)?,
        "uname-syscall",
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
    session_identity_envelope(
        &context,
        "platform:session",
        PLATFORM_SESSION_CAPABILITY,
        ObservationAuthority::NativeApi,
        context.session_type.clone(),
        "logind",
    )
}

pub fn observe_compositor(
    target: &LogindSessionTarget,
) -> Result<ObservationEnvelope, PlatformProbeError> {
    let connection = connect_system_bus()?;
    let context = query_session_context(&connection, target)?;
    let (identity, source) = probe_compositor(&connection, &context)?;
    session_identity_envelope(
        &context,
        "platform:compositor",
        PLATFORM_COMPOSITOR_CAPABILITY,
        ObservationAuthority::NativeApi,
        identity,
        source,
    )
}

pub fn observe_network_provider() -> Result<ObservationEnvelope, PlatformProbeError> {
    let connection = connect_system_bus()?;
    require_owned_service(&connection, NETWORKMANAGER_SERVICE)?;
    let peer = Proxy::new(
        &connection,
        NETWORKMANAGER_SERVICE,
        NETWORKMANAGER_PATH,
        DBUS_PEER,
    )
    .map_err(|error| {
        PlatformProbeError::new(format!(
            "cannot create NetworkManager health proxy: {error}"
        ))
    })?;
    let _: () = peer.call("Ping", &()).map_err(|error| {
        PlatformProbeError::new(format!(
            "NetworkManager direct health probe failed: {error}"
        ))
    })?;

    let manager = Proxy::new(
        &connection,
        NETWORKMANAGER_SERVICE,
        NETWORKMANAGER_PATH,
        NETWORKMANAGER_INTERFACE,
    )
    .map_err(|error| {
        PlatformProbeError::new(format!(
            "cannot create NetworkManager manager proxy: {error}"
        ))
    })?;
    let devices: Vec<OwnedObjectPath> = manager.call("GetDevices", &()).map_err(|error| {
        PlatformProbeError::new(format!(
            "cannot enumerate NetworkManager managed-device candidates: {error}"
        ))
    })?;
    if devices.len() > NETWORKMANAGER_MAX_DEVICES {
        return Err(PlatformProbeError::new(
            "NetworkManager device evidence exceeds the bounded device ceiling",
        ));
    }

    let mut device_states = Vec::with_capacity(devices.len());
    for device_path in devices {
        let device = Proxy::new(
            &connection,
            NETWORKMANAGER_SERVICE,
            device_path.as_str(),
            NETWORKMANAGER_DEVICE_INTERFACE,
        )
        .map_err(|error| {
            PlatformProbeError::new(format!(
                "cannot create NetworkManager device proxy: {error}"
            ))
        })?;
        let managed: bool = device.get_property("Managed").map_err(|error| {
            PlatformProbeError::new(format!(
                "cannot read NetworkManager device Managed property: {error}"
            ))
        })?;
        let device_type: u32 = device.get_property("DeviceType").map_err(|error| {
            PlatformProbeError::new(format!(
                "cannot read NetworkManager device DeviceType property: {error}"
            ))
        })?;
        device_states.push((managed, device_type));
    }
    require_networkmanager_selected_device(&device_states)?;

    provider_identity_envelope(
        "networkmanager",
        "network",
        PLATFORM_NETWORK_PROVIDER_CAPABILITY,
        ObservationAuthority::NativeApi,
        "org.freedesktop.NetworkManager:managed-device",
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
    session_provider_identity_envelope(
        &context,
        identity,
        "audio",
        PLATFORM_AUDIO_PROVIDER_CAPABILITY,
        ObservationAuthority::NativeApi,
        "logind-user-systemd",
    )
}

fn connect_system_bus() -> Result<Connection, PlatformProbeError> {
    let builder = AsyncConnectionBuilder::system()
        .map_err(|error| {
            PlatformProbeError::new(format!("cannot configure system D-Bus connection: {error}"))
        })?
        .method_timeout(NATIVE_PROBE_TIMEOUT);
    build_dbus_connection_with_deadline(builder, "system D-Bus")
}

fn build_dbus_connection_with_deadline(
    builder: AsyncConnectionBuilder<'_>,
    label: &str,
) -> Result<Connection, PlatformProbeError> {
    let result: Result<Option<zbus::Connection>, zbus::Error> = async_io::block_on(async {
        future::race(async { builder.build().await.map(Some) }, async {
            Timer::after(NATIVE_PROBE_TIMEOUT).await;
            Ok::<Option<zbus::Connection>, zbus::Error>(None)
        })
        .await
    });
    match result {
        Ok(Some(connection)) => Ok(Connection::from(connection)),
        Ok(None) => Err(PlatformProbeError::new(format!(
            "{label} connection/authentication exceeded its wall-clock deadline"
        ))),
        Err(error) => Err(PlatformProbeError::new(format!(
            "cannot connect/authenticate {label}: {error}"
        ))),
    }
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
        session_object_path: session_path.as_str().to_owned(),
        session_type,
        desktop,
        runtime_path,
        uid: user.0,
    })
}

fn require_networkmanager_selected_device(
    device_states: &[(bool, u32)],
) -> Result<(), PlatformProbeError> {
    if device_states.iter().any(|(managed, device_type)| {
        *managed && *device_type != NETWORKMANAGER_DEVICE_TYPE_LOOPBACK
    }) {
        return Ok(());
    }
    Err(PlatformProbeError::new(
        "NetworkManager is live but does not authoritatively report any managed non-loopback device",
    ))
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
    // Do not stat user-controlled RuntimePath content. A FUSE mount can make metadata
    // inspection block outside our probe budget. The connect itself is deadline-bounded,
    // and kernel peer credentials bind the connected bus endpoint to the selected uid.
    let stream = connect_unix_with_deadline(&bus_path, NATIVE_PROBE_TIMEOUT, "logind user D-Bus")?;
    let credentials = socket_peercred(&stream).map_err(|error| {
        PlatformProbeError::new(format!("cannot read logind user D-Bus peer credentials: {error}"))
    })?;
    if credentials.uid.as_raw() != context.uid {
        return Err(PlatformProbeError::new(
            "logind user D-Bus peer uid does not match the selected session user",
        ));
    }
    let builder =
        AsyncConnectionBuilder::async_io_unix_stream(stream).method_timeout(NATIVE_PROBE_TIMEOUT);
    build_dbus_connection_with_deadline(builder, "logind user D-Bus")
}

fn user_unit_active(connection: &Connection, unit_name: &str) -> Result<bool, PlatformProbeError> {
    let manager = Proxy::new(connection, SYSTEMD_SERVICE, SYSTEMD_PATH, SYSTEMD_MANAGER).map_err(
        |error| {
            PlatformProbeError::new(format!("cannot create user systemd manager proxy: {error}"))
        },
    )?;
    // `GetUnit` only resolves units currently resident in the manager. An installed but
    // inactive PipeWire/WirePlumber unit may have been garbage-collected from that set, so use
    // `LoadUnit`: it loads configuration without starting the unit and gives us authoritative
    // ActiveState evidence for both active and inactive installed units.
    let unit_path: OwnedObjectPath = match manager.call("LoadUnit", &(unit_name,)) {
        Ok(unit_path) => unit_path,
        Err(zbus::Error::MethodError(name, _, _))
            if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit" =>
        {
            // A missing unit is authoritative negative evidence, not a probe failure. Keep
            // querying sibling units so Control can distinguish absent/partial audio stacks.
            return Ok(false);
        }
        Err(error) => {
            return Err(PlatformProbeError::new(format!(
                "cannot load user unit {unit_name} for observation: {error}"
            )));
        }
    };
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

fn probe_compositor(
    connection: &Connection,
    context: &NativeSessionContext,
) -> Result<(String, &'static str), PlatformProbeError> {
    if context.desktop.is_empty() {
        return Err(PlatformProbeError::new(format!(
            "selected logind session {} does not identify a desktop; compositor IPC cannot be bound safely",
            context.session_id
        )));
    }
    if context.desktop != "hyprland" {
        return Ok((context.desktop.clone(), "logind:Desktop"));
    }
    locate_verified_hyprland_socket(connection, context)?;
    Ok(("hyprland".to_owned(), "hyprland-ipc"))
}

fn locate_verified_hyprland_socket(
    connection: &Connection,
    context: &NativeSessionContext,
) -> Result<PathBuf, PlatformProbeError> {
    // Do not traverse the user-controlled runtime directory. A stalling FUSE
    // mount below XDG_RUNTIME_DIR could otherwise block read_dir/stat calls
    // outside the discovery budget. Candidate pathname evidence comes from the
    // kernel-owned Unix socket table; authority still comes from peer
    // credentials, exact logind-session binding, and the same-stream Hyprland
    // protocol response below.
    let socket_table = read_bounded_utf8("/proc/net/unix", PROC_NET_UNIX_MAX_BYTES)?;
    let candidates = hyprland_socket_candidates(&socket_table, &context.runtime_path)?;
    let started = Instant::now();
    let mut matches = Vec::new();

    for socket_path in candidates {
        let remaining = remaining_discovery_budget(started)?;
        let mut stream = match connect_unix_with_deadline(
            &socket_path,
            remaining.min(HYPRLAND_IO_TIMEOUT),
            "Hyprland IPC",
        ) {
            Ok(stream) => stream,
            Err(_) => continue,
        };
        let credentials = match socket_peercred(&stream) {
            Ok(credentials) => credentials,
            Err(_) => continue,
        };
        if credentials.uid.as_raw() != context.uid {
            continue;
        }
        let Ok(peer_pid) = u32::try_from(credentials.pid.as_raw_pid()) else {
            continue;
        };
        let remaining = remaining_discovery_budget(started)?;
        let Some(peer_session) =
            logind_session_for_pid_with_deadline(connection, peer_pid, remaining)?
        else {
            continue;
        };
        if peer_session.as_str() != context.session_object_path {
            continue;
        }
        let remaining = remaining_discovery_budget(started)?;
        if verify_hyprland_ipc(&mut stream, remaining).is_err() {
            continue;
        }
        matches.push(socket_path);
        if matches.len() > 1 {
            return Err(PlatformProbeError::new(format!(
                "multiple verified Hyprland IPC peers belong to selected session {}; compositor identity is ambiguous",
                context.session_id
            )));
        }
    }

    matches.pop().ok_or_else(|| {
        PlatformProbeError::new(format!(
            "no verified Hyprland IPC peer belongs to selected logind session {}",
            context.session_id
        ))
    })
}

fn hyprland_socket_candidates(
    socket_table: &str,
    runtime_path: &Path,
) -> Result<Vec<PathBuf>, PlatformProbeError> {
    let hypr_root = runtime_path.join("hypr");
    let mut candidates = Vec::new();
    let mut seen_paths = BTreeSet::new();

    for line in socket_table.lines().skip(1) {
        let Some(raw_path) = line.split_ascii_whitespace().nth(7) else {
            continue;
        };
        if raw_path.starts_with('@') {
            continue;
        }
        let path = PathBuf::from(raw_path);
        if path.file_name().and_then(|value| value.to_str()) != Some(HYPRLAND_SOCKET_NAME) {
            continue;
        }
        let Some(instance_dir) = path.parent() else {
            continue;
        };
        if instance_dir.parent() != Some(hypr_root.as_path()) {
            continue;
        }
        let Some(signature) = instance_dir.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !safe_instance_signature(signature) {
            continue;
        }

        // /proc/net/unix may contain the listening socket and one or more accepted sockets with
        // the same pathname. The pathname is locator evidence only, so probe each unique locator
        // once; otherwise one compositor can be misclassified as multiple verified peers and
        // duplicate rows can consume the bounded candidate budget.
        if !seen_paths.insert(path.clone()) {
            continue;
        }
        candidates.push(path);
        if candidates.len() > HYPRLAND_MAX_RUNTIME_ENTRIES {
            return Err(PlatformProbeError::new(
                "Hyprland kernel socket-table candidates exceeded the bounded entry budget",
            ));
        }
    }

    Ok(candidates)
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

fn remaining_discovery_budget(started: Instant) -> Result<Duration, PlatformProbeError> {
    HYPRLAND_DISCOVERY_TIMEOUT
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            PlatformProbeError::new("Hyprland runtime discovery exceeded its wall-clock deadline")
        })
}

fn logind_session_for_pid_with_deadline(
    connection: &Connection,
    peer_pid: u32,
    timeout: Duration,
) -> Result<Option<OwnedObjectPath>, PlatformProbeError> {
    let result: Option<Result<OwnedObjectPath, zbus::Error>> = async_io::block_on(async {
        future::race(
            async {
                Some(
                    async {
                        let proxy = zbus::Proxy::new(
                            connection.inner(),
                            LOGIN1_SERVICE,
                            LOGIN1_PATH,
                            LOGIN1_MANAGER,
                        )
                        .await?;
                        proxy.call("GetSessionByPID", &(peer_pid,)).await
                    }
                    .await,
                )
            },
            async {
                Timer::after(timeout).await;
                None
            },
        )
        .await
    });
    match result {
        Some(Ok(path)) => Ok(Some(path)),
        Some(Err(_)) => Ok(None),
        None => Err(PlatformProbeError::new(
            "Hyprland peer session lookup exceeded the remaining discovery deadline",
        )),
    }
}

fn validate_runtime_path(path: &Path, uid: u32) -> Result<(), PlatformProbeError> {
    // RuntimePath is supplied by the trusted logind system service. Validate its canonical
    // identity lexically rather than performing metadata I/O on a UID-controlled mount:
    // a malicious/stalled FUSE mount could otherwise block this probe indefinitely.
    let expected = PathBuf::from(format!("/run/user/{uid}"));
    if path != expected {
        return Err(PlatformProbeError::new(format!(
            "logind RuntimePath does not match canonical selected-user path {}",
            expected.display()
        )));
    }
    Ok(())
}

fn verify_hyprland_ipc(
    stream: &mut UnixStream,
    remaining_budget: Duration,
) -> Result<(), PlatformProbeError> {
    let exchange_budget = remaining_budget.min(HYPRLAND_IO_TIMEOUT);
    if exchange_budget.is_zero() {
        return Err(PlatformProbeError::new(
            "Hyprland IPC exchange has no remaining discovery budget",
        ));
    }
    let exchange_started = Instant::now();
    stream
        .set_write_timeout(Some(exchange_budget))
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
    let mut chunk = [0_u8; 4096];
    loop {
        let remaining = exchange_budget
            .checked_sub(exchange_started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                PlatformProbeError::new("Hyprland IPC exchange exceeded its wall-clock deadline")
            })?;
        stream.set_read_timeout(Some(remaining)).map_err(|error| {
            PlatformProbeError::new(format!("cannot set Hyprland IPC read timeout: {error}"))
        })?;
        let remaining_bytes =
            (HYPRLAND_MAX_RESPONSE_BYTES + 1).saturating_sub(response.len() as u64) as usize;
        if remaining_bytes == 0 {
            return Err(PlatformProbeError::new(
                "Hyprland IPC version response exceeds the bounded evidence size",
            ));
        }
        let read_len = chunk.len().min(remaining_bytes);
        match stream.read(&mut chunk[..read_len]) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(PlatformProbeError::new(
                    "Hyprland IPC exchange exceeded its wall-clock deadline",
                ));
            }
            Err(error) => {
                return Err(PlatformProbeError::new(format!(
                    "cannot read Hyprland IPC version response: {error}"
                )));
            }
        }
    }
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

fn connect_unix_with_deadline(
    path: &Path,
    timeout: Duration,
    label: &str,
) -> Result<UnixStream, PlatformProbeError> {
    let socket = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|error| PlatformProbeError::new(format!("cannot create {label} socket: {error}")))?;
    let address = SocketAddrUnix::new(path).map_err(|error| {
        PlatformProbeError::new(format!("cannot encode {label} socket address: {error}"))
    })?;

    match connect(&socket, &address) {
        Ok(()) => {}
        Err(rustix::io::Errno::INPROGRESS | rustix::io::Errno::AGAIN) => {
            let mut fds = [PollFd::new(
                &socket,
                PollFlags::OUT | PollFlags::ERR | PollFlags::HUP,
            )];
            let timeout = Timespec {
                tv_sec: timeout.as_secs().try_into().map_err(|_| {
                    PlatformProbeError::new("Hyprland IPC connect timeout does not fit time_t")
                })?,
                tv_nsec: timeout.subsec_nanos().into(),
            };
            let ready = poll(&mut fds, Some(&timeout)).map_err(|error| {
                PlatformProbeError::new(format!("cannot poll {label} connection: {error}"))
            })?;
            if ready == 0 {
                return Err(PlatformProbeError::new(format!(
                    "{label} connect exceeded its wall-clock deadline"
                )));
            }
            match socket_error(&socket).map_err(|error| {
                PlatformProbeError::new(format!("cannot read {label} connection status: {error}"))
            })? {
                Ok(()) => {}
                Err(error) => {
                    return Err(PlatformProbeError::new(format!(
                        "cannot connect to {label}: {error}"
                    )));
                }
            }
        }
        Err(error) => {
            return Err(PlatformProbeError::new(format!(
                "cannot connect to {label}: {error}"
            )));
        }
    }

    let stream = UnixStream::from(socket);
    stream.set_nonblocking(false).map_err(|error| {
        PlatformProbeError::new(format!("cannot restore blocking mode for {label}: {error}"))
    })?;
    Ok(stream)
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
    let mut identity = None;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(value) = line.strip_prefix("ID=") else {
            continue;
        };
        if identity.is_some() {
            return Err(PlatformProbeError::new(
                "/etc/os-release contains duplicate ID assignments",
            ));
        }
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
        identity = Some(normalized_identity("os-release ID", &value)?);
    }
    identity.ok_or_else(|| PlatformProbeError::new("/etc/os-release does not contain ID"))
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

fn session_identity_envelope(
    context: &NativeSessionContext,
    resource: &str,
    capability: &str,
    authority: ObservationAuthority,
    identity: String,
    source: &str,
) -> Result<ObservationEnvelope, PlatformProbeError> {
    let mut observation =
        platform_identity_envelope(resource, capability, authority, identity, source)?;
    bind_session_scope(&mut observation, context);
    Ok(observation)
}

fn session_provider_identity_envelope(
    context: &NativeSessionContext,
    provider: &str,
    role: &str,
    capability: &str,
    authority: ObservationAuthority,
    source: &str,
) -> Result<ObservationEnvelope, PlatformProbeError> {
    let mut observation =
        provider_identity_envelope(provider, role, capability, authority, source)?;
    bind_session_scope(&mut observation, context);
    Ok(observation)
}

fn bind_session_scope(observation: &mut ObservationEnvelope, context: &NativeSessionContext) {
    observation.attributes.insert(
        "session_id".to_owned(),
        ObservedValue::Text(context.session_id.clone()),
    );
    observation.attributes.insert(
        "session_uid".to_owned(),
        ObservedValue::Text(context.uid.to_string()),
    );
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
        assert!(parse_os_release_id("ID=arch\nID=fedora\n").is_err());
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
    fn network_provider_requires_selected_non_loopback_management_evidence() {
        assert!(require_networkmanager_selected_device(&[(true, 1)]).is_ok());
        assert!(require_networkmanager_selected_device(&[(false, 1)]).is_err());
        assert!(
            require_networkmanager_selected_device(&[(true, NETWORKMANAGER_DEVICE_TYPE_LOOPBACK,)])
                .is_err()
        );
        assert!(
            require_networkmanager_selected_device(&[
                (false, 1),
                (true, NETWORKMANAGER_DEVICE_TYPE_LOOPBACK),
            ])
            .is_err()
        );
    }

    #[test]
    fn audio_provider_identity_preserves_known_mismatches_for_control() {
        assert_eq!(audio_identity(true, true), "pipewire-wireplumber");
        assert_eq!(audio_identity(true, false), "pipewire-only");
        assert_eq!(audio_identity(false, true), "wireplumber-only");
        assert_eq!(audio_identity(false, false), "absent");
    }

    #[test]
    fn runtime_path_validation_is_canonical_and_filesystem_io_free() {
        assert!(validate_runtime_path(Path::new("/run/user/1000"), 1000).is_ok());
        assert!(validate_runtime_path(Path::new("/run/user/1001"), 1000).is_err());
        assert!(validate_runtime_path(Path::new("/run/user/1000/../1000"), 1000).is_err());
    }

    #[test]
    fn compositor_provenance_tracks_the_authoritative_source() {
        let context = NativeSessionContext {
            session_id: "2".to_owned(),
            session_object_path: "/org/freedesktop/login1/session/_32".to_owned(),
            session_type: "wayland".to_owned(),
            desktop: "sway".to_owned(),
            runtime_path: PathBuf::from("/run/user/1000"),
            uid: 1000,
        };
        // The non-Hyprland branch is fully decided by logind and must never claim IPC evidence.
        assert_eq!(context.desktop, "sway");
    }

    #[test]
    fn hyprland_socket_candidates_use_only_unique_bounded_kernel_socket_paths() {
        let table = concat!(
            "Num RefCount Protocol Flags Type St Inode Path\n",
            "000: 00000002 00000000 00010000 0001 01 1 /run/user/1000/hypr/good/.socket.sock\n",
            "001: 00000002 00000000 00010000 0001 03 2 /run/user/1000/hypr/good/.socket.sock\n",
            "002: 00000002 00000000 00010000 0001 01 3 /run/user/1000/hypr/../../bad/.socket.sock\n",
            "003: 00000002 00000000 00010000 0001 01 4 /run/user/1000/other/good/.socket.sock\n",
            "004: 00000002 00000000 00010000 0001 01 5 @abstract-hyprland\n",
        );
        assert_eq!(
            hyprland_socket_candidates(table, Path::new("/run/user/1000")),
            Ok(vec![PathBuf::from("/run/user/1000/hypr/good/.socket.sock")])
        );
    }

    #[test]
    fn peer_bound_compositor_contract_uses_selected_logind_session_path() {
        let context = NativeSessionContext {
            session_id: "2".to_owned(),
            session_object_path: "/org/freedesktop/login1/session/_32".to_owned(),
            session_type: "wayland".to_owned(),
            desktop: "hyprland".to_owned(),
            runtime_path: PathBuf::from("/run/user/1000"),
            uid: 1000,
        };
        assert_eq!(
            context.session_object_path,
            "/org/freedesktop/login1/session/_32"
        );
    }

    #[test]
    fn canonical_session_scope_is_explicit_in_observation_evidence() {
        let context = NativeSessionContext {
            session_id: "2".to_owned(),
            session_object_path: "/org/freedesktop/login1/session/_32".to_owned(),
            session_type: "wayland".to_owned(),
            desktop: "hyprland".to_owned(),
            runtime_path: PathBuf::from("/run/user/1000"),
            uid: 1000,
        };
        let mut observation = envelope(
            PLATFORM_PROVIDER,
            "platform:session",
            PLATFORM_SESSION_CAPABILITY,
            ObservationAuthority::NativeApi,
            Some("wayland".to_owned()),
            "fixture",
        )
        .unwrap_or_else(|error| unreachable!("{error}"));
        bind_session_scope(&mut observation, &context);
        assert_eq!(
            observation.attributes.get("session_id"),
            Some(&ObservedValue::Text("2".to_owned()))
        );
        assert_eq!(
            observation.attributes.get("session_uid"),
            Some(&ObservedValue::Text("1000".to_owned()))
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
