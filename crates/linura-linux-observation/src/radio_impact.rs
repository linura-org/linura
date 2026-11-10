//! S18-6: independent, bounded *read-only* NetworkManager/kernel radio evidence.
//!
//! This is not a native executor, policy decision, authorization, or proof that
//! a remote administration channel can survive a radio change. NetworkManager
//! properties do not attest the kernel routing policy or effective split DNS.
//! This source intentionally does not expose an "all impact complete" bit:
//! a later qualified authority must separately prove those obligations.

use super::*;
use linura_core::{NetworkDeviceId, NetworkInterfaceName, NetworkManagerEpoch};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

const MAX_LINKS: usize = 128;
const MAX_ROUTE_ROWS: usize = 2048;
const MAX_RFKILL: usize = 32;
const MAX_KERNEL_TEXT_BYTES: u64 = 256 * 1024;
const MAX_SYSFS_VALUE_BYTES: u64 = 256;

fn invalid(label: &str) -> ProviderError {
    ProviderError::InvalidState(format!("native radio {label} is invalid or unavailable"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelLinkState {
    Up,
    Down,
    Dormant,
    LowerLayerDown,
    NotPresent,
    Testing,
    Unknown,
}

impl KernelLinkState {
    fn parse(value: &str) -> Result<Self, ProviderError> {
        match value {
            "up" => Ok(Self::Up),
            "down" => Ok(Self::Down),
            "dormant" => Ok(Self::Dormant),
            "lowerlayerdown" => Ok(Self::LowerLayerDown),
            "notpresent" => Ok(Self::NotPresent),
            "testing" => Ok(Self::Testing),
            "unknown" => Ok(Self::Unknown),
            _ => Err(invalid("kernel operstate")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelRadioBlock {
    pub wlan_devices: usize,
    pub any_soft_blocked: bool,
    pub any_hard_blocked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRadioLink {
    pub interface: NetworkInterfaceName,
    pub kernel_ifindex: u32,
    pub wireless: bool,
    pub kernel_state: KernelLinkState,
    pub network_manager_device: Option<NetworkDeviceId>,
    pub network_manager_device_type: Option<u32>,
    pub network_manager_managed: Option<bool>,
    pub network_manager_state: Option<u32>,
    pub ipv4_main_default_routes: u16,
    pub ipv6_main_default_routes: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRadioSafetySample {
    epoch: NetworkManagerEpoch,
    observed_at_unix_ms: u64,
    /// Non-serializable same-process timing witness; never an authorization token.
    observed_at_monotonic: Instant,
    /// Native-observer sequence used to reject cached or replayed readbacks.
    observation_sequence: u64,
    observer_instance: u64,
    kernel_policy: radio_netlink::PolicyRouteSnapshot,
    resolver: radio_dns::ResolverSnapshot,
    remote_tcp: radio_remote::RemoteTcpSnapshot,
    remote_routes: BTreeMap<radio_remote::SocketIdentity, u32>,
    networking_enabled: bool,
    wireless_enabled: bool,
    wireless_hardware_enabled: bool,
    rfkill: Option<KernelRadioBlock>,
    links: Vec<NativeRadioLink>,
    /// Deliberate nonclaims: /proc route tables do not cover policy routing,
    /// and NetworkManager's DNS properties do not prove effective split DNS.
    /// An eventual execution gate MUST reject missing independent evidence.
    provider_process_unverified: bool,
    device_generation_unverified: bool,
    policy_routing_unverified: bool,
    effective_dns_unverified: bool,
    remote_administration_unverified: bool,
    offline_local_recovery_unverified: bool,
}

// This type is intentionally sealed outside its native source adapter.
// A caller can inspect these observations but cannot manufacture a completed
// safety attestation or set any of the unresolved obligations to false.
impl NativeRadioSafetySample {
    #[must_use]
    pub const fn epoch(&self) -> &NetworkManagerEpoch {
        &self.epoch
    }

    #[must_use]
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }

    #[must_use]
    pub const fn observation_sequence(&self) -> u64 {
        self.observation_sequence
    }

    #[must_use]
    pub const fn networking_enabled(&self) -> bool {
        self.networking_enabled
    }

    #[must_use]
    pub const fn wireless_enabled(&self) -> bool {
        self.wireless_enabled
    }

    #[must_use]
    pub const fn wireless_hardware_enabled(&self) -> bool {
        self.wireless_hardware_enabled
    }

    #[must_use]
    pub const fn rfkill(&self) -> Option<KernelRadioBlock> {
        self.rfkill
    }

    #[must_use]
    pub fn links(&self) -> &[NativeRadioLink] {
        &self.links
    }

    #[must_use]
    pub const fn native_authorization_incomplete(&self) -> bool {
        !self.resolver.proves_effective_split_dns()
            || !self.remote_tcp.proves_remote_administration_survival()
            || self.provider_process_unverified
            || self.device_generation_unverified
            || self.policy_routing_unverified
            || self.effective_dns_unverified
            || self.remote_administration_unverified
            || self.offline_local_recovery_unverified
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KernelMainDefaultRoutes {
    ipv4: BTreeMap<String, u16>,
    ipv6: BTreeMap<String, u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KernelLinkRow {
    interface: NetworkInterfaceName,
    ifindex: u32,
    wireless: bool,
    state: KernelLinkState,
}

fn bounded_file(path: &Path, max: u64) -> Result<String, ProviderError> {
    let file = File::open(path)
        .map_err(|_| ProviderError::Unavailable("native kernel evidence is unreadable".into()))?;
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("kernel evidence read"))?;
    if bytes.len() as u64 > max {
        return Err(invalid("kernel evidence exceeds byte budget"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("non-UTF8 kernel evidence"))
}

fn bounded_sysfs(path: &Path) -> Result<String, ProviderError> {
    let data = bounded_file(path, MAX_SYSFS_VALUE_BYTES)?;
    let value = data.trim_end_matches('\n');
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(invalid("kernel sysfs value"));
    }
    Ok(value.into())
}

fn kernel_link_rows() -> Result<BTreeMap<String, KernelLinkRow>, ProviderError> {
    let mut result = BTreeMap::new();
    let mut indices = BTreeSet::new();
    let entries = fs::read_dir("/sys/class/net")
        .map_err(|_| ProviderError::Unavailable("kernel link inventory unavailable".into()))?;
    for item in entries {
        let item = item.map_err(|_| invalid("kernel link inventory changed"))?;
        if result.len() >= MAX_LINKS {
            return Err(invalid("kernel link count exceeds bound"));
        }
        let name = item
            .file_name()
            .into_string()
            .map_err(|_| invalid("kernel interface name"))?;
        let interface = NetworkInterfaceName::new(name.clone())
            .map_err(|_| invalid("kernel interface name"))?;
        let path = item.path();
        let index: u32 = bounded_sysfs(&path.join("ifindex"))?
            .parse()
            .map_err(|_| invalid("kernel interface index"))?;
        if index == 0 || !indices.insert(index) {
            return Err(invalid("duplicate or zero kernel ifindex"));
        }
        let state = KernelLinkState::parse(&bounded_sysfs(&path.join("operstate"))?)?;
        let wireless = path.join("wireless").exists();
        if result
            .insert(
                name,
                KernelLinkRow {
                    interface,
                    ifindex: index,
                    wireless,
                    state,
                },
            )
            .is_some()
        {
            return Err(invalid("duplicate kernel link"));
        }
    }
    Ok(result)
}

fn parse_hex(value: &str, bytes: usize) -> Result<u64, ProviderError> {
    if value.len() != bytes * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("kernel route hexadecimal field"));
    }
    u64::from_str_radix(value, 16).map_err(|_| invalid("kernel route hexadecimal field"))
}

fn checked_default_counter(
    map: &mut BTreeMap<String, u16>,
    interface: &str,
) -> Result<(), ProviderError> {
    let name = NetworkInterfaceName::new(interface)
        .map_err(|_| invalid("route interface is not canonical"))?;
    let count = map.entry(name.as_str().into()).or_default();
    *count = count
        .checked_add(1)
        .ok_or_else(|| invalid("default-route count overflow"))?;
    Ok(())
}

// /proc/net/route enumerates IPv4 main-table routes of the current namespace,
// not policy-routing rules, other routing tables, NAT or route reachability.
fn ipv4_main_defaults(text: &str) -> Result<BTreeMap<String, u16>, ProviderError> {
    let mut lines = text.lines();
    let header = lines.next().ok_or_else(|| invalid("IPv4 route header"))?;
    if !header.contains("Iface") || !header.contains("Destination") || !header.contains("Mask") {
        return Err(invalid("IPv4 route header"));
    }
    let mut routes = BTreeMap::new();
    for (row, line) in lines.enumerate() {
        if row >= MAX_ROUTE_ROWS {
            return Err(invalid("IPv4 route count"));
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 11 {
            return Err(invalid("IPv4 route row"));
        }
        let _ =
            NetworkInterfaceName::new(fields[0]).map_err(|_| invalid("IPv4 route interface"))?;
        let destination = parse_hex(fields[1], 4)?;
        let _gateway = parse_hex(fields[2], 4)?;
        let flags = parse_hex(fields[3], 2)?;
        let mask = parse_hex(fields[7], 4)?;
        if destination == 0 && mask == 0 && flags & 1 != 0 {
            checked_default_counter(&mut routes, fields[0])?;
        }
    }
    Ok(routes)
}

// /proc/net/ipv6_route is likewise not a policy-routing/effective-route oracle.
fn ipv6_main_defaults(text: &str) -> Result<BTreeMap<String, u16>, ProviderError> {
    let mut routes = BTreeMap::new();
    for (row, line) in text.lines().enumerate() {
        if row >= MAX_ROUTE_ROWS {
            return Err(invalid("IPv6 route count"));
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 10 {
            return Err(invalid("IPv6 route row"));
        }
        if fields[0].len() != 32
            || !fields[0].bytes().all(|v| v.is_ascii_hexdigit())
            || fields[2].len() != 32
            || !fields[2].bytes().all(|v| v.is_ascii_hexdigit())
            || fields[4].len() != 32
            || !fields[4].bytes().all(|v| v.is_ascii_hexdigit())
        {
            return Err(invalid("IPv6 route address"));
        }
        let destination_prefix = parse_hex(fields[1], 1)?;
        let _source_prefix = parse_hex(fields[3], 1)?;
        for value in &fields[5..8] {
            let _ = parse_hex(value, 4)?;
        }
        let flags = parse_hex(fields[8], 4)?;
        let _ =
            NetworkInterfaceName::new(fields[9]).map_err(|_| invalid("IPv6 route interface"))?;
        if fields[0].bytes().all(|v| v == b'0') && destination_prefix == 0 && flags & 1 != 0 {
            checked_default_counter(&mut routes, fields[9])?;
        }
    }
    Ok(routes)
}

fn parse_kernel_block(
    entries: &[(String, String, String)],
) -> Result<Option<KernelRadioBlock>, ProviderError> {
    if entries.len() > MAX_RFKILL {
        return Err(invalid("rfkill inventory exceeds bound"));
    }
    let mut found = 0;
    let mut soft = false;
    let mut hard = false;
    for (kind, is_soft, is_hard) in entries {
        if !matches!(
            kind.as_str(),
            "wlan" | "bluetooth" | "wwan" | "gps" | "fm" | "nfc"
        ) {
            return Err(invalid("unsupported rfkill device type"));
        }
        if !matches!(is_soft.as_str(), "0" | "1") || !matches!(is_hard.as_str(), "0" | "1") {
            return Err(invalid("rfkill bit"));
        }
        if kind == "wlan" {
            found += 1;
            soft |= is_soft == "1";
            hard |= is_hard == "1";
        }
    }
    if found == 0 {
        return Ok(None);
    }
    Ok(Some(KernelRadioBlock {
        wlan_devices: found,
        any_soft_blocked: soft,
        any_hard_blocked: hard,
    }))
}

fn kernel_rfkill() -> Result<Option<KernelRadioBlock>, ProviderError> {
    let mut entries = Vec::new();
    let reader = fs::read_dir("/sys/class/rfkill")
        .map_err(|_| ProviderError::Unavailable("kernel rfkill inventory unavailable".into()))?;
    let mut seen = BTreeSet::new();
    for entry in reader {
        let entry = entry.map_err(|_| invalid("rfkill inventory changed"))?;
        if entries.len() >= MAX_RFKILL {
            return Err(invalid("rfkill inventory exceeds bound"));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("rfkill name"))?;
        let id = name
            .strip_prefix("rfkill")
            .ok_or_else(|| invalid("rfkill name"))?;
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) || !seen.insert(id.to_owned()) {
            return Err(invalid("rfkill identity"));
        }
        let path = entry.path();
        entries.push((
            bounded_sysfs(&path.join("type"))?,
            bounded_sysfs(&path.join("soft"))?,
            bounded_sysfs(&path.join("hard"))?,
        ));
    }
    parse_kernel_block(&entries)
}

fn kernel_route_inventory() -> Result<KernelMainDefaultRoutes, ProviderError> {
    let ipv4 = bounded_file(Path::new("/proc/net/route"), MAX_KERNEL_TEXT_BYTES)?;
    let ipv6 = bounded_file(Path::new("/proc/net/ipv6_route"), MAX_KERNEL_TEXT_BYTES)?;
    Ok(KernelMainDefaultRoutes {
        ipv4: ipv4_main_defaults(&ipv4)?,
        ipv6: ipv6_main_defaults(&ipv6)?,
    })
}

impl NetworkManagerObserver {
    /// Independently re-observe kernel and NM facts on the same boot, system
    /// bus owner and network namespace. This is a *diagnostic source snapshot*,
    /// not a safety permit or pre-dispatch fence.
    pub fn sample_radio_safety(&self) -> Result<NativeRadioSafetySample, ProviderError> {
        let started = Instant::now();
        let epoch = self.native_epoch()?;
        let owner = epoch.owner().as_str();
        let ns = fs::metadata("/proc/self/ns/net")
            .map_err(|_| invalid("network namespace"))?
            .ino();
        let root_ns = fs::metadata("/proc/1/ns/net")
            .map_err(|_| invalid("initial network namespace"))?
            .ino();
        if ns == 0 || root_ns != ns {
            return Err(invalid("control is not in its initial kernel namespace"));
        }
        let before_links = kernel_link_rows()?;
        let before_routes = kernel_route_inventory()?;
        let before_rfkill = kernel_rfkill()?;
        let before_policy = radio_netlink::policy_snapshot()?;
        let before_resolver = radio_dns::sample()?;
        let before_remote = radio_remote::sample()?;
        let before_remote_routes = before_remote.destination_routes()?;
        let nm_before = self.device_index(owner)?;
        let manager =
            networkmanager_native::bounded_props(&self.connection, owner, NM_PATH, NM_INTERFACE)?;
        let networking_enabled: bool = snapshot_property(&manager, "NetworkingEnabled")?;
        let wireless_enabled: bool = snapshot_property(&manager, "WirelessEnabled")?;
        let wireless_hardware_enabled: bool =
            snapshot_property(&manager, "WirelessHardwareEnabled")?;
        let mut links = Vec::new();
        for (name, link) in &before_links {
            let mut device = None;
            let mut native_type = None;
            let mut managed = None;
            let mut state = None;
            if let Some(path) = nm_before.get(name) {
                let properties = networkmanager_native::bounded_props(
                    &self.connection,
                    owner,
                    path.as_str(),
                    NM_DEVICE_INTERFACE,
                )?;
                let matched_name: String = snapshot_property(&properties, "Interface")?;
                let native_kind: u32 = snapshot_property(&properties, "DeviceType")?;
                if matched_name != *name || (native_kind == 2) != link.wireless {
                    return Err(invalid("NM/kernel interface mapping changed"));
                }
                let identity = self.device_identity(&epoch, path, name)?;
                if identity.ifindex() != link.ifindex || identity.namespace_inode() != ns {
                    return Err(invalid("NM/kernel device generation differs"));
                }
                device = Some(identity);
                native_type = Some(native_kind);
                managed = Some(snapshot_property(&properties, "Managed")?);
                state = Some(snapshot_property(&properties, "State")?);
            }
            links.push(NativeRadioLink {
                interface: link.interface.clone(),
                kernel_ifindex: link.ifindex,
                wireless: link.wireless,
                kernel_state: link.state,
                network_manager_device: device,
                network_manager_device_type: native_type,
                network_manager_managed: managed,
                network_manager_state: state,
                ipv4_main_default_routes: *before_routes.ipv4.get(name).unwrap_or(&0),
                ipv6_main_default_routes: *before_routes.ipv6.get(name).unwrap_or(&0),
            });
        }
        if nm_before
            .keys()
            .any(|name| !before_links.contains_key(name))
            || before_routes
                .ipv4
                .keys()
                .any(|name| !before_links.contains_key(name))
            || before_routes
                .ipv6
                .keys()
                .any(|name| !before_links.contains_key(name))
        {
            return Err(invalid("unmapped NM/kernel route or device"));
        }
        let after_manager =
            networkmanager_native::bounded_props(&self.connection, owner, NM_PATH, NM_INTERFACE)?;
        if networking_enabled != snapshot_property::<bool>(&after_manager, "NetworkingEnabled")?
            || wireless_enabled != snapshot_property::<bool>(&after_manager, "WirelessEnabled")?
            || wireless_hardware_enabled
                != snapshot_property::<bool>(&after_manager, "WirelessHardwareEnabled")?
            || nm_before != self.device_index(owner)?
            || before_links != kernel_link_rows()?
            || before_routes != kernel_route_inventory()?
            || before_rfkill != kernel_rfkill()?
            || before_policy != radio_netlink::policy_snapshot()?
            || before_resolver != radio_dns::sample()?
            || before_remote != radio_remote::sample()?
            || before_remote_routes != before_remote.destination_routes()?
            || ns
                != fs::metadata("/proc/self/ns/net")
                    .map_err(|_| invalid("namespace"))?
                    .ino()
            || root_ns
                != fs::metadata("/proc/1/ns/net")
                    .map_err(|_| invalid("namespace"))?
                    .ino()
        {
            return Err(invalid("radio evidence changed during native read"));
        }
        // A stable object path and inventory are not enough: Managed/State can
        // change without changing either. Independently reread every owned
        // device and its kernel mapping before accepting this diagnostic view.
        for link in &links {
            if let Some(original) = &link.network_manager_device {
                let props = networkmanager_native::bounded_props(
                    &self.connection,
                    owner,
                    &original.object().native_path(),
                    NM_DEVICE_INTERFACE,
                )?;
                if snapshot_property::<String>(&props, "Interface")? != link.interface.as_str()
                    || Some(snapshot_property::<u32>(&props, "DeviceType")?)
                        != link.network_manager_device_type
                    || Some(snapshot_property::<bool>(&props, "Managed")?)
                        != link.network_manager_managed
                    || Some(snapshot_property::<u32>(&props, "State")?)
                        != link.network_manager_state
                    || self.device_identity(
                        &epoch,
                        nm_before
                            .get(link.interface.as_str())
                            .ok_or_else(|| invalid("native device disappeared"))?,
                        link.interface.as_str(),
                    )? != *original
                {
                    return Err(invalid("native device properties or identity changed"));
                }
            }
        }
        self.require_native_epoch(&epoch)?;
        require_nm_elapsed(started)?;
        Ok(NativeRadioSafetySample {
            epoch,
            observed_at_unix_ms: now_unix_ms()?,
            observed_at_monotonic: Instant::now(),
            observation_sequence: next_sequence(&self.sequence)?,
            observer_instance: self.radio_observer_instance,
            kernel_policy: before_policy,
            resolver: before_resolver,
            remote_tcp: before_remote,
            remote_routes: before_remote_routes,
            networking_enabled,
            wireless_enabled,
            wireless_hardware_enabled,
            rfkill: before_rfkill,
            links,
            // Neither system-bus ownership nor ifindex equality proves the
            // NM systemd process or excludes ABA recycling. Distinct native
            // authority evidence is mandatory before granting effects.
            provider_process_unverified: true,
            device_generation_unverified: true,
            policy_routing_unverified: true,
            effective_dns_unverified: true,
            remote_administration_unverified: true,
            offline_local_recovery_unverified: true,
        })
    }
}

// S18-6 native source readback, not an authorization or a verifier receipt.
// The native observer owns each sample. Even a successful readback cannot
// establish original-subject Polkit, independent policy routing/effective DNS,
// remote administration, accessible offline recovery or durable attribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeRadioSetting {
    Networking,
    Wireless,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeRadioReadback {
    after: NativeRadioSafetySample,
    requested_enabled: bool,
    setting: NativeRadioSetting,
}

impl NativeRadioReadback {
    #[must_use]
    pub const fn sample(&self) -> &NativeRadioSafetySample {
        &self.after
    }

    #[must_use]
    pub const fn setting(&self) -> NativeRadioSetting {
        self.setting
    }

    #[must_use]
    pub const fn requested_enabled(&self) -> bool {
        self.requested_enabled
    }

    /// A readback is deliberately never an effect approval or final verified
    /// receipt. A trusted Control transaction and independent recovery oracle
    /// must still be attached by a separately qualified integration.
    #[must_use]
    pub const fn is_authorized_or_fully_verified(&self) -> bool {
        false
    }
}

fn radio_setting_state(sample: &NativeRadioSafetySample, setting: NativeRadioSetting) -> bool {
    match setting {
        NativeRadioSetting::Networking => sample.networking_enabled,
        NativeRadioSetting::Wireless => sample.wireless_enabled,
    }
}

fn affected_radio_link(link: &NativeRadioLink, setting: NativeRadioSetting) -> bool {
    match setting {
        NativeRadioSetting::Networking => link.network_manager_managed == Some(true),
        NativeRadioSetting::Wireless => link.wireless,
    }
}

/// Check a separately acquired, identity-pinned native *shape* after a
/// previous observation. This is not a causal proof of a specific dispatch:
/// another caller may have changed the state, and successful activation does
/// not prove connectivity or effective DNS. The caller must not translate the
/// result directly into VerificationDisposition::Satisfied.
fn assess_radio_readback(
    before: &NativeRadioSafetySample,
    after: NativeRadioSafetySample,
    setting: NativeRadioSetting,
    requested_enabled: bool,
) -> Result<NativeRadioReadback, ProviderError> {
    if before.epoch != after.epoch {
        return Err(invalid("radio postcondition source epoch changed"));
    }
    let affected = before
        .links
        .iter()
        .filter(|link| affected_radio_link(link, setting))
        .map(|link| link.kernel_ifindex)
        .collect::<BTreeSet<_>>();
    // A source/UID-conditioned FIB route cannot prove the live admin socket's
    // actual marked/overlay path. But one selecting a disabled link is an
    // independent, conservative reason to reject any future settlement.
    if !requested_enabled
        && before
            .remote_routes
            .values()
            .any(|ifindex| affected.contains(ifindex))
    {
        return Err(invalid(
            "disabled link carries a possible remote-control route",
        ));
    }
    before.resolver.require_same_source(&after.resolver)?;
    before.remote_tcp.require_continuity(&after.remote_tcp)?;
    if before.remote_routes != after.remote_routes {
        return Err(invalid(
            "selected remote route changed during radio readback",
        ));
    }
    before.kernel_policy.require_affected_only_change(
        &after.kernel_policy,
        &affected,
        !requested_enabled,
    )?;
    if before.observer_instance == 0 || before.observer_instance != after.observer_instance {
        return Err(invalid("radio postcondition observer instance changed"));
    }
    if before.observation_sequence == 0
        || after.observation_sequence <= before.observation_sequence
        || after.observed_at_monotonic <= before.observed_at_monotonic
        || after
            .observed_at_monotonic
            .duration_since(before.observed_at_monotonic)
            > Duration::from_secs(15)
    {
        return Err(invalid(
            "radio postcondition is stale or not a newer native sample",
        ));
    }
    if radio_setting_state(before, setting) == requested_enabled
        || radio_setting_state(&after, setting) != requested_enabled
    {
        return Err(invalid(
            "radio postcondition is absent or the before state was no-change",
        ));
    }
    // A result for one manager property must never silently approve an
    // unrelated global/radio toggle. In particular, a disabled Wi-Fi radio
    // does not excuse a simultaneous loss of manager-wide networking.
    let unrelated_changed = match setting {
        NativeRadioSetting::Networking => before.wireless_enabled != after.wireless_enabled,
        NativeRadioSetting::Wireless => before.networking_enabled != after.networking_enabled,
    };
    if unrelated_changed {
        return Err(invalid(
            "radio postcondition changed unrelated manager control",
        ));
    }
    if before.links.len() != after.links.len() || before.links.len() > MAX_LINKS {
        return Err(invalid("radio postcondition link inventory was replaced"));
    }
    let previous = before
        .links
        .iter()
        .map(|link| (link.interface.as_str(), link))
        .collect::<BTreeMap<_, _>>();
    if previous.len() != before.links.len() {
        return Err(invalid(
            "radio postcondition baseline has duplicate link identities",
        ));
    }
    let mut seen = BTreeSet::new();
    for link in &after.links {
        if !seen.insert(link.interface.as_str()) {
            return Err(invalid("radio postcondition has duplicate link identities"));
        }
        let old = previous
            .get(link.interface.as_str())
            .ok_or_else(|| invalid("radio postcondition added or replaced a link"))?;
        // Device object, generation, native ifindex, wireless class and
        // original owner must all remain the same. A renamed alias alone is
        // never a safe substitute.
        if old.kernel_ifindex != link.kernel_ifindex
            || old.interface != link.interface
            || old.wireless != link.wireless
            || old.network_manager_device != link.network_manager_device
            || old.network_manager_device_type != link.network_manager_device_type
            || old.network_manager_managed != link.network_manager_managed
        {
            return Err(invalid(
                "radio postcondition has a recycled device or changed ownership",
            ));
        }

        if !affected_radio_link(link, setting) {
            if old.kernel_state != link.kernel_state
                || old.network_manager_state != link.network_manager_state
                || old.ipv4_main_default_routes != link.ipv4_main_default_routes
                || old.ipv6_main_default_routes != link.ipv6_main_default_routes
            {
                return Err(invalid(
                    "unaffected link or route changed during radio readback",
                ));
            }
        } else if !requested_enabled {
            // An old active managed connection, or a retained default route,
            // means disabling is not independently demonstrated to have
            // settled; neither NM's method reply nor its software toggle bit
            // can override that contradiction.
            if link.network_manager_state == Some(100)
                || link.ipv4_main_default_routes != 0
                || link.ipv6_main_default_routes != 0
                || (link.wireless && link.network_manager_managed != Some(true))
            {
                return Err(invalid(
                    "radio postcondition has an active or unmanaged affected link",
                ));
            }
        }
    }
    if setting == NativeRadioSetting::Wireless && requested_enabled {
        let block = after
            .rfkill
            .ok_or_else(|| invalid("enabled Wi-Fi has no kernel rfkill attestation"))?;
        if !after.networking_enabled
            || !after.wireless_hardware_enabled
            || block.wlan_devices == 0
            || block.any_soft_blocked
            || block.any_hard_blocked
            || !after.links.iter().any(|link| link.wireless)
        {
            return Err(invalid(
                "enabled Wi-Fi hardware or kernel state is still blocked",
            ));
        }
    }
    Ok(NativeRadioReadback {
        after,
        setting,
        requested_enabled,
    })
}

impl NetworkManagerObserver {
    /// Independently reread native NM and kernel state on the current pinned
    /// connection. Never perform a mutation or treat a matching post-state as
    /// proof of the triggering request, durable attempt or offline recovery.
    pub fn sample_radio_readback(
        &self,
        before: &NativeRadioSafetySample,
        setting: NativeRadioSetting,
        requested_enabled: bool,
    ) -> Result<NativeRadioReadback, ProviderError> {
        // Old samples from earlier calls are not authority; require a bounded
        // same-process monotonic preflight-to-readback window.
        let elapsed = Instant::now()
            .checked_duration_since(before.observed_at_monotonic)
            .ok_or_else(|| invalid("radio baseline monotonic clock mismatch"))?;
        if elapsed > Duration::from_secs(15) {
            return Err(invalid("radio baseline expired before native readback"));
        }
        let after = self.sample_radio_safety()?;
        assess_radio_readback(before, after, setting, requested_enabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checked<T, E: Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| unreachable!("known radio readback fixture: {error:?}"))
    }

    fn radio_fixture() -> NativeRadioSafetySample {
        use linura_core::{
            BootId, NetworkManagerOwner, NetworkObjectId, NetworkObjectKind, SystemBusInstanceId,
        };
        let epoch = NetworkManagerEpoch::new(
            checked(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
            checked(SystemBusInstanceId::new("fedcba9876543210abcdef0123456789")),
            checked(NetworkManagerOwner::new(":1.48")),
        );
        let interface = checked(NetworkInterfaceName::new("wlan0"));
        let device = checked(NetworkDeviceId::new(
            epoch.clone(),
            checked(NetworkObjectId::from_path(
                NetworkObjectKind::Device,
                "/org/freedesktop/NetworkManager/Devices/8",
            )),
            4_026_531_840,
            3,
            interface.clone(),
            8,
        ));
        NativeRadioSafetySample {
            epoch,
            observed_at_unix_ms: 10_000,
            observed_at_monotonic: Instant::now(),
            observation_sequence: 1,
            observer_instance: 7,
            kernel_policy: radio_netlink::PolicyRouteSnapshot::fixture(7),
            resolver: radio_dns::ResolverSnapshot::fixture(),
            remote_tcp: radio_remote::RemoteTcpSnapshot::fixture(),
            remote_routes: BTreeMap::new(),
            networking_enabled: true,
            wireless_enabled: true,
            wireless_hardware_enabled: true,
            rfkill: Some(KernelRadioBlock {
                wlan_devices: 1,
                any_soft_blocked: false,
                any_hard_blocked: false,
            }),
            links: vec![NativeRadioLink {
                interface,
                kernel_ifindex: 3,
                wireless: true,
                kernel_state: KernelLinkState::Up,
                network_manager_device: Some(device),
                network_manager_device_type: Some(2),
                network_manager_managed: Some(true),
                network_manager_state: Some(100),
                ipv4_main_default_routes: 1,
                ipv6_main_default_routes: 1,
            }],
            provider_process_unverified: true,
            device_generation_unverified: true,
            policy_routing_unverified: true,
            effective_dns_unverified: true,
            remote_administration_unverified: true,
            offline_local_recovery_unverified: true,
        }
    }

    #[test]
    fn native_readback_is_never_authority_and_must_be_fresh() {
        let baseline = radio_fixture();
        let mut after = baseline.clone();
        after.observation_sequence += 1;
        after.observed_at_monotonic += Duration::from_millis(1);
        after.wireless_enabled = false;
        after.links[0].network_manager_state = Some(30);
        after.links[0].ipv4_main_default_routes = 0;
        after.links[0].ipv6_main_default_routes = 0;
        let result = assess_radio_readback(
            &baseline,
            after.clone(),
            NativeRadioSetting::Wireless,
            false,
        );
        assert!(result.is_ok());
        assert!(result.is_ok_and(|sample| {
            sample.setting() == NativeRadioSetting::Wireless
                && !sample.requested_enabled()
                && sample.sample().native_authorization_incomplete()
                && !sample.is_authorized_or_fully_verified()
        }));
        let mut foreign = after.clone();
        foreign.observer_instance = 8;
        assert!(
            assess_radio_readback(&baseline, foreign, NativeRadioSetting::Wireless, false,)
                .is_err()
        );
        let mut changed_policy = after.clone();
        changed_policy.kernel_policy = radio_netlink::PolicyRouteSnapshot::fixture(8);
        assert!(
            assess_radio_readback(
                &baseline,
                changed_policy,
                NativeRadioSetting::Wireless,
                false,
            )
            .is_err()
        );
        let mut replay = after.clone();
        replay.observation_sequence = 1;
        assert!(
            assess_radio_readback(&baseline, replay, NativeRadioSetting::Wireless, false,).is_err()
        );
        after.observed_at_monotonic += Duration::from_secs(16);
        assert!(
            assess_radio_readback(&baseline, after, NativeRadioSetting::Wireless, false,).is_err()
        );
    }

    #[test]
    fn native_readback_denies_missing_postconditions_and_changed_sources() {
        let baseline = radio_fixture();
        let mut after = baseline.clone();
        after.observation_sequence += 1;
        after.observed_at_monotonic += Duration::from_millis(1);
        assert!(
            assess_radio_readback(
                &baseline,
                after.clone(),
                NativeRadioSetting::Wireless,
                false,
            )
            .is_err()
        );
        after.wireless_enabled = false;
        assert!(
            assess_radio_readback(
                &baseline,
                after.clone(),
                NativeRadioSetting::Wireless,
                false,
            )
            .is_err()
        );
        after.links[0].network_manager_state = Some(30);
        after.links[0].ipv4_main_default_routes = 0;
        after.links[0].ipv6_main_default_routes = 0;
        after.links[0].kernel_ifindex = 13;
        assert!(
            assess_radio_readback(
                &baseline,
                after.clone(),
                NativeRadioSetting::Wireless,
                false,
            )
            .is_err()
        );
        after.links[0].kernel_ifindex = 3;
        after.epoch = NetworkManagerEpoch::new(
            baseline.epoch.boot().clone(),
            baseline.epoch.bus().clone(),
            checked(linura_core::NetworkManagerOwner::new(":1.49")),
        );
        assert!(
            assess_radio_readback(&baseline, after, NativeRadioSetting::Wireless, false,).is_err()
        );
    }

    #[test]
    fn readback_cannot_hide_a_second_networkmanager_control_mutation() {
        let baseline = radio_fixture();
        let mut after = baseline.clone();
        after.observation_sequence += 1;
        after.observed_at_monotonic += Duration::from_millis(1);
        after.wireless_enabled = false;
        after.networking_enabled = false;
        after.links[0].network_manager_state = Some(30);
        after.links[0].ipv4_main_default_routes = 0;
        after.links[0].ipv6_main_default_routes = 0;
        assert!(
            assess_radio_readback(
                &baseline,
                after.clone(),
                NativeRadioSetting::Wireless,
                false
            )
            .is_err()
        );
        after.networking_enabled = true;
        assert!(
            assess_radio_readback(&baseline, after, NativeRadioSetting::Wireless, false).is_ok()
        );

        let mut global = baseline.clone();
        global.observation_sequence += 1;
        global.observed_at_monotonic += Duration::from_millis(1);
        global.networking_enabled = false;
        global.wireless_enabled = false;
        global.links[0].network_manager_state = Some(30);
        global.links[0].ipv4_main_default_routes = 0;
        global.links[0].ipv6_main_default_routes = 0;
        assert!(
            assess_radio_readback(
                &baseline,
                global.clone(),
                NativeRadioSetting::Networking,
                false
            )
            .is_err()
        );
        global.wireless_enabled = true;
        assert!(
            assess_radio_readback(&baseline, global, NativeRadioSetting::Networking, false).is_ok()
        );
    }

    #[test]
    fn readback_denies_remote_kernel_fib_using_an_affected_radio_link() {
        let mut baseline = radio_fixture();
        baseline
            .remote_routes
            .insert(radio_remote::SocketIdentity::fixture(), 3);
        let mut after = baseline.clone();
        after.observation_sequence += 1;
        after.observed_at_monotonic += Duration::from_millis(1);
        after.wireless_enabled = false;
        after.links[0].network_manager_state = Some(30);
        after.links[0].ipv4_main_default_routes = 0;
        after.links[0].ipv6_main_default_routes = 0;
        assert!(
            assess_radio_readback(&baseline, after, NativeRadioSetting::Wireless, false).is_err()
        );
    }

    #[test]
    fn wifi_enable_readback_requires_native_hardware_rfkill_and_manager() {
        let mut baseline = radio_fixture();
        baseline.wireless_enabled = false;
        let mut after = baseline.clone();
        after.observation_sequence += 1;
        after.observed_at_monotonic += Duration::from_millis(1);
        after.wireless_enabled = true;
        assert!(
            assess_radio_readback(&baseline, after.clone(), NativeRadioSetting::Wireless, true,)
                .is_ok()
        );
        if let Some(block) = &mut after.rfkill {
            block.any_soft_blocked = true;
        }
        assert!(
            assess_radio_readback(&baseline, after.clone(), NativeRadioSetting::Wireless, true,)
                .is_err()
        );
        after.rfkill = None;
        assert!(
            assess_radio_readback(&baseline, after, NativeRadioSetting::Wireless, true,).is_err()
        );
    }

    const IP4: &str = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\nwlan0 00000000 0100000A 0003 0 0 100 00000000 0 0 0\neth0 0000000A 00000000 0001 0 0 100 00FFFFFF 0 0 0\n";
    const IP6: &str = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000064 00000000 00000000 00000003 wlan0\n";

    #[test]
    fn kernel_route_tables_are_only_bounded_main_table_evidence() {
        let result = ipv4_main_defaults(IP4);
        assert_eq!(
            result.as_ref().ok().and_then(|x| x.get("wlan0")).copied(),
            Some(1)
        );
        assert!(
            result
                .as_ref()
                .ok()
                .is_some_and(|x| !x.contains_key("eth0"))
        );
        let result = ipv6_main_defaults(IP6);
        assert_eq!(
            result.as_ref().ok().and_then(|x| x.get("wlan0")).copied(),
            Some(1)
        );
        assert!(ipv4_main_defaults("invalid").is_err());
        assert!(ipv4_main_defaults(&IP4.replace("wlan0", "../../etc/passwd")).is_err());
        assert!(ipv4_main_defaults(&IP4.replace("0003", "zzzz")).is_err());
        assert!(ipv6_main_defaults(&IP6.replace("wlan0", "wlan0/../")).is_err());
        assert!(ipv6_main_defaults(&IP6.replace(" 00 ", " gg ")).is_err());
        assert!(
            ipv6_main_defaults(&IP6.replace("00000003 wlan0", "00000000 wlan0"))
                .is_ok_and(|routes| routes.is_empty())
        );
    }

    #[test]
    fn native_radio_block_is_not_nm_software_or_hardware_enabled() {
        assert_eq!(parse_kernel_block(&[]), Ok(None));
        assert_eq!(
            parse_kernel_block(&[
                ("wlan".into(), "1".into(), "0".into()),
                ("bluetooth".into(), "0".into(), "0".into()),
            ]),
            Ok(Some(KernelRadioBlock {
                wlan_devices: 1,
                any_soft_blocked: true,
                any_hard_blocked: false,
            }))
        );
        assert!(parse_kernel_block(&[("wlan".into(), "2".into(), "0".into())]).is_err());
        assert!(parse_kernel_block(&[("wlan".into(), "0".into(), "".into())]).is_err());
        assert!(
            parse_kernel_block(&vec![
                ("wlan".into(), "0".into(), "0".into());
                MAX_RFKILL + 1
            ])
            .is_err()
        );
    }

    #[test]
    fn route_rows_cannot_overflow_or_launder_interface_aliases() {
        let mut defaults = BTreeMap::new();
        assert!(checked_default_counter(&mut defaults, "wlan0").is_ok());
        assert!(checked_default_counter(&mut defaults, "../wlan0").is_err());
        let rows = IP6.repeat(MAX_ROUTE_ROWS + 1);
        assert!(ipv6_main_defaults(&rows).is_err());
    }
}
