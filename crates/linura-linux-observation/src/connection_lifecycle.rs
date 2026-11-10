//! S18-7 source-pinned passive NM connection lifecycle evidence.
//!
//! A durable Control transaction may later consume this evidence, but these
//! reads are neither execution authority nor a claim of actual connectivity:
//! the original session/Polkit subject, kernel routes, effective resolver,
//! remote-control survival, and offline recovery require separate witnesses.

use super::*;
use linura_core::{
    NetworkAccessPointId, NetworkActiveConnectionId, NetworkDeviceId, NetworkManagerEpoch,
    NetworkObjectId, NetworkObjectKind, NetworkProfileRevision,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const NM_ACTIVE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const NM_IP4: &str = "org.freedesktop.NetworkManager.IP4Config";
const NM_IP6: &str = "org.freedesktop.NetworkManager.IP6Config";
const NM_WIFI: &str = "org.freedesktop.NetworkManager.Device.Wireless";
const NM_AP: &str = "org.freedesktop.NetworkManager.AccessPoint";
const MAX_LIFECYCLE_ROWS: usize = 128;
const MAX_LIFECYCLE_DNS: usize = 32;
const MAX_LIFECYCLE_AGE: Duration = Duration::from_secs(15);

fn deny(reason: &str) -> ProviderError {
    ProviderError::InvalidState(format!("native connection lifecycle {reason}"))
}

/// A scoped, nonsecret AP source fingerprint. This is correlation only,
/// never an authorization or a claim that the access point is reachable.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PinnedConnectionAccessPoint {
    ssid: Vec<u8>,
    bssid: String,
    frequency: u32,
    flags: u32,
    wpa_flags: u32,
    rsn_flags: u32,
}

fn pinned_connection_ap(
    connection: &Connection,
    owner: &str,
    path: &str,
) -> Result<PinnedConnectionAccessPoint, ProviderError> {
    let props = networkmanager_native::bounded_props(connection, owner, path, NM_AP)?;
    let ssid: Vec<u8> = snapshot_property(&props, "Ssid")?;
    let bssid: String = snapshot_property(&props, "HwAddress")?;
    let frequency: u32 = snapshot_property(&props, "Frequency")?;
    // A BSSID is public metadata but must never become a method target.
    // Strict canonical bytes guard malformed/ambiguous AP source identity.
    if ssid.len() > 32 || bssid.len() != 17 || frequency == 0 || frequency > 100_000 {
        return Err(deny("Wi-Fi AP identity or frequency is invalid"));
    }
    let bytes = bssid.as_bytes();
    if bytes.iter().enumerate().any(|(index, byte)| {
        if matches!(index, 2 | 5 | 8 | 11 | 14) {
            *byte != b':'
        } else {
            !byte.is_ascii_hexdigit()
        }
    }) {
        return Err(deny("Wi-Fi AP BSSID is malformed"));
    }
    Ok(PinnedConnectionAccessPoint {
        ssid,
        bssid,
        frequency,
        flags: snapshot_property(&props, "Flags")?,
        wpa_flags: snapshot_property(&props, "WpaFlags")?,
        rsn_flags: snapshot_property(&props, "RsnFlags")?,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeConnectionTarget {
    /// A wired activation cannot silently select a Wi-Fi access point.
    Activate {
        device: NetworkDeviceId,
        profile: NetworkProfileRevision,
    },
    ActivateWifi {
        device: NetworkDeviceId,
        profile: NetworkProfileRevision,
        access_point: NetworkAccessPointId,
    },
    Deactivate(NetworkActiveConnectionId),
}

impl NativeConnectionTarget {
    #[must_use]
    pub fn device(&self) -> &NetworkDeviceId {
        match self {
            Self::Activate { device, .. } | Self::ActivateWifi { device, .. } => device,
            Self::Deactivate(active) => active.device(),
        }
    }

    pub fn profile(&self) -> Result<&NetworkProfileRevision, ProviderError> {
        match self {
            Self::Activate { profile, .. } | Self::ActivateWifi { profile, .. } => Ok(profile),
            Self::Deactivate(active) => active
                .profile()
                .ok_or_else(|| deny("deactivation has no saved profile revision")),
        }
    }

    pub fn require_consistent(&self) -> Result<(), ProviderError> {
        let device = self.device();
        let profile = self.profile()?;
        if device.epoch() != profile.epoch()
            || device.object().kind() != NetworkObjectKind::Device
            || profile.object().kind() != NetworkObjectKind::SettingsConnection
            || device.object().sequence() != device.generation()
            || device.ifindex() == 0
            || device.namespace_inode() == 0
        {
            return Err(deny(
                "profile and kernel device belong to different generations",
            ));
        }
        if let Self::ActivateWifi { access_point, .. } = self
            && (access_point.device() != device
                || access_point.object().kind() != NetworkObjectKind::AccessPoint
                || access_point.observation_generation() == 0)
        {
            return Err(deny(
                "Wi-Fi activation AP belongs to a foreign device or generation",
            ));
        }
        if let Self::Deactivate(active) = self
            && (active.profile() != Some(profile)
                || active.device() != device
                || active.object().kind() != NetworkObjectKind::ActiveConnection
                || active.activation_generation() != active.object().sequence())
        {
            return Err(deny("original active generation is inconsistent"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeIpConfiguration {
    path: OwnedObjectPath,
    addresses: Vec<String>,
    routes: Vec<String>,
    nameservers: Vec<String>,
    gateway: String,
}

impl NativeIpConfiguration {
    #[must_use]
    pub fn source_path(&self) -> &str {
        self.path.as_str()
    }

    #[must_use]
    pub fn gateway(&self) -> &str {
        &self.gateway
    }

    #[must_use]
    pub fn has_address(&self) -> bool {
        !self.addresses.is_empty()
    }

    #[must_use]
    pub fn has_resolver(&self) -> bool {
        !self.nameservers.is_empty()
    }

    #[must_use]
    pub fn has_default_route(&self) -> bool {
        self.routes
            .iter()
            .any(|route| route.starts_with("0.0.0.0/0") || route.starts_with("::/0"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActiveInstance {
    identity: NetworkActiveConnectionId,
    state: u32,
    state_flags: u32,
    default4: bool,
    default6: bool,
    connection_type: String,
    wireless_access_point: Option<OwnedObjectPath>,
}

#[derive(Clone, Debug)]
pub struct NativeConnectionLifecycleSample {
    epoch: NetworkManagerEpoch,
    device: NetworkDeviceId,
    profile: NetworkProfileRevision,
    active: Option<ActiveInstance>,
    device_state: u32,
    ipv4: Option<NativeIpConfiguration>,
    ipv6: Option<NativeIpConfiguration>,
    observer_sequence: u64,
    observed_at: Instant,
    kernel: connection_kernel::KernelConnectionSnapshot,
}

impl NativeConnectionLifecycleSample {
    #[must_use]
    pub const fn epoch(&self) -> &NetworkManagerEpoch {
        &self.epoch
    }

    #[must_use]
    pub const fn device(&self) -> &NetworkDeviceId {
        &self.device
    }

    #[must_use]
    pub const fn profile(&self) -> &NetworkProfileRevision {
        &self.profile
    }

    #[must_use]
    pub fn active(&self) -> Option<&NetworkActiveConnectionId> {
        self.active.as_ref().map(|active| &active.identity)
    }

    /// NM state or a successful D-Bus reply is never proof that routing,
    /// effective DNS, secure original-user dispatch or offline recovery holds.
    /// These kernel-table checks cannot independently attest marked routing,
    /// effective DNS, remote-admin survival or real offline restoration.
    #[must_use]
    pub const fn execution_safety_unverified(&self) -> bool {
        !self.kernel.proves_safe_effective_routing_or_recovery()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionReadbackRequirements {
    pub ipv4: bool,
    pub ipv6: bool,
    pub dns: bool,
    pub default4: bool,
    pub default6: bool,
}

#[derive(Debug)]
pub struct NativeConnectionLifecycleReadback {
    sample: NativeConnectionLifecycleSample,
}

impl NativeConnectionLifecycleReadback {
    #[must_use]
    pub const fn sample(&self) -> &NativeConnectionLifecycleSample {
        &self.sample
    }

    /// Verified NM/device snapshot only. Not a sufficient independent
    /// verifier for durable commit; kernel and original-session proof missing.
    #[must_use]
    pub const fn commit_authority_unverified(&self) -> bool {
        self.sample.execution_safety_unverified()
    }
}

fn validate_ip_rows(
    properties: &HashMap<String, OwnedValue>,
    label: &str,
    family: u8,
    route: bool,
) -> Result<Vec<String>, ProviderError> {
    let entries: Vec<HashMap<String, OwnedValue>> = snapshot_property(properties, label)?;
    if entries.len() > MAX_LIFECYCLE_ROWS {
        return Err(deny("IP address or route inventory exceeded fixed bound"));
    }
    entries
        .iter()
        .map(|entry| networkmanager_native::ip_row(entry, family, route))
        .collect()
}

fn sample_ip_config(
    connection: &Connection,
    owner: &str,
    path: &OwnedObjectPath,
    family: u8,
) -> Result<Option<NativeIpConfiguration>, ProviderError> {
    if path.as_str() == "/" {
        return Ok(None);
    }
    let prefix = match family {
        4 => "/org/freedesktop/NetworkManager/IP4Config/",
        6 => "/org/freedesktop/NetworkManager/IP6Config/",
        _ => return Err(deny("unrecognized IP family")),
    };
    let sequence = path
        .as_str()
        .strip_prefix(prefix)
        .ok_or_else(|| deny("IP configuration path has an unexpected family"))?;
    if sequence.starts_with('0')
        || sequence.len() > 20
        || sequence.is_empty()
        || !sequence.bytes().all(|digit| digit.is_ascii_digit())
        || sequence.parse::<u64>().ok().is_none_or(|value| value == 0)
    {
        return Err(deny("IP configuration path is not canonical"));
    }
    let iface = if family == 4 { NM_IP4 } else { NM_IP6 };
    let props = networkmanager_native::bounded_props(connection, owner, path.as_str(), iface)?;
    let addresses = validate_ip_rows(&props, "AddressData", family, false)?;
    let routes = validate_ip_rows(&props, "RouteData", family, true)?;
    let gateway: String = snapshot_property(&props, "Gateway")?;
    if !gateway.is_empty() {
        let parsed: IpAddr = gateway
            .parse()
            .map_err(|_| deny("invalid configured IP gateway"))?;
        if (family == 4 && !parsed.is_ipv4()) || (family == 6 && !parsed.is_ipv6()) {
            return Err(deny("IP gateway uses wrong address family"));
        }
    }
    let nameservers = if family == 4 {
        let raw: Vec<u32> = snapshot_property(&props, "Nameservers")?;
        if raw.len() > MAX_LIFECYCLE_DNS {
            return Err(deny("IPv4 resolver inventory exceeds fixed bound"));
        }
        raw.into_iter()
            .map(|value| Ipv4Addr::from(value.to_ne_bytes()).to_string())
            .collect::<Vec<_>>()
    } else {
        let raw: Vec<Vec<u8>> = snapshot_property(&props, "Nameservers")?;
        if raw.len() > MAX_LIFECYCLE_DNS {
            return Err(deny("IPv6 resolver inventory exceeds fixed bound"));
        }
        raw.into_iter()
            .map(|value| {
                let octets: [u8; 16] = value
                    .try_into()
                    .map_err(|_| deny("IPv6 resolver has invalid byte width"))?;
                Ok(Ipv6Addr::from(octets).to_string())
            })
            .collect::<Result<Vec<_>, ProviderError>>()?
    };
    if nameservers.iter().collect::<BTreeSet<_>>().len() != nameservers.len() {
        return Err(deny("duplicate nameservers in native IP configuration"));
    }
    Ok(Some(NativeIpConfiguration {
        path: path.clone(),
        addresses,
        routes,
        nameservers,
        gateway,
    }))
}

impl NetworkManagerObserver {
    /// Passive native source read for one exact saved profile and kernel
    /// device. Reject partial inventory, daemon replacement and ABA. The
    /// profile is re-read after all dependent NM objects, not merely matched
    /// by a user-supplied UUID.
    pub fn sample_connection_lifecycle(
        &self,
        target: &NativeConnectionTarget,
    ) -> Result<NativeConnectionLifecycleSample, ProviderError> {
        let sample = self.sample_connection_unqualified(target)?;
        match target {
            NativeConnectionTarget::Activate { .. }
            | NativeConnectionTarget::ActivateWifi { .. }
                if sample.active.is_some() =>
            {
                return Err(deny("activation would replace a currently active device"));
            }
            NativeConnectionTarget::Deactivate(expected)
                if sample
                    .active
                    .as_ref()
                    .is_none_or(|value| &value.identity != expected) =>
            {
                return Err(deny(
                    "deactivation target is not the current active generation",
                ));
            }
            _ => {}
        }
        Ok(sample)
    }

    // Shared source read has NO preflight no-change assumption. A successful
    // activation must have acquired a new object by the time this is called.
    fn sample_connection_unqualified(
        &self,
        target: &NativeConnectionTarget,
    ) -> Result<NativeConnectionLifecycleSample, ProviderError> {
        target.require_consistent()?;
        let started = Instant::now();
        let kernel_before = connection_kernel::sample()?;
        let epoch = self.native_epoch()?;
        if &epoch != target.device().epoch() {
            return Err(deny("original NetworkManager owner/bus/boot changed"));
        }
        let owner = epoch.owner().as_str();
        let device_before = self.device_index(owner)?;
        let device_path = target.device().object().native_path();
        if device_before
            .get(target.device().interface().as_str())
            .is_none_or(|path| path.as_str() != device_path)
        {
            return Err(deny("native device is absent or has a substituted path"));
        }
        let device_object = OwnedObjectPath::try_from(device_path.clone())
            .map_err(|_| deny("device path is not canonical"))?;
        if self.device_identity(&epoch, &device_object, target.device().interface().as_str())?
            != *target.device()
        {
            return Err(deny(
                "kernel interface/ifindex/namespace generation changed",
            ));
        }

        let profiles_before = self.profile_index(owner)?;
        let profile = target.profile()?;
        let profile_path = profile.object().native_path();
        if profiles_before
            .get(&profile.object().sequence())
            .is_none_or(|path| path.as_str() != profile_path)
        {
            return Err(deny("profile path disappeared or was replaced"));
        }
        let old_profile_props = networkmanager_native::bounded_props(
            &self.connection,
            owner,
            &profile_path,
            "org.freedesktop.NetworkManager.Settings.Connection",
        )?;
        let unsaved: bool = snapshot_property(&old_profile_props, "Unsaved")?;
        if unsaved
            || self.profile_revision(
                &epoch,
                profiles_before
                    .get(&profile.object().sequence())
                    .ok_or_else(|| deny("profile path vanished"))?,
                &old_profile_props,
            )? != *profile
        {
            return Err(deny("saved profile revision or persistence changed"));
        }
        let device_props = networkmanager_native::bounded_props(
            &self.connection,
            owner,
            device_path.as_str(),
            NM_DEVICE_INTERFACE,
        )?;
        let observed_name: String = snapshot_property(&device_props, "Interface")?;
        let device_state: u32 = snapshot_property(&device_props, "State")?;
        let native_kind: u32 = snapshot_property(&device_props, "DeviceType")?;
        let managed: bool = snapshot_property(&device_props, "Managed")?;
        let active_path: OwnedObjectPath = snapshot_property(&device_props, "ActiveConnection")?;
        let ip4_path: OwnedObjectPath = snapshot_property(&device_props, "Ip4Config")?;
        let ip6_path: OwnedObjectPath = snapshot_property(&device_props, "Ip6Config")?;
        if observed_name != target.device().interface().as_str()
            || !managed
            || !matches!(native_kind, 1 | 2)
            || matches!(
                (target, native_kind),
                (NativeConnectionTarget::Activate { .. }, 2)
                    | (NativeConnectionTarget::ActivateWifi { .. }, 1)
            )
        {
            return Err(deny(
                "target is unmanaged, a VPN/bridge, or a different interface",
            ));
        }
        // A Wi-Fi activation is never allowed to pick a substitute AP at
        // the native method call. Pin membership and nonsecret AP properties
        // before dependent reads, and reattest both at the end.
        let requested_ap = if let NativeConnectionTarget::ActivateWifi { access_point, .. } = target
        {
            let inventory = self.wireless_index(owner, &device_object)?;
            let path = OwnedObjectPath::try_from(access_point.object().native_path())
                .map_err(|_| deny("requested Wi-Fi AP path is invalid"))?;
            if inventory.get(&access_point.object().sequence()) != Some(&path) {
                return Err(deny("selected Wi-Fi AP is not in the pinned native device"));
            }
            let evidence = pinned_connection_ap(&self.connection, owner, path.as_str())?;
            Some((inventory, path, evidence))
        } else {
            None
        };
        let actives_before = self.active_index(owner)?;
        let active = if active_path.as_str() == "/" {
            None
        } else {
            let object = NetworkObjectId::from_path(
                NetworkObjectKind::ActiveConnection,
                active_path.as_str(),
            )
            .map_err(|_| deny("active object identity is not canonical"))?;
            if actives_before.get(&object.sequence()) != Some(&active_path) {
                return Err(deny(
                    "device active connection is not in original NM inventory",
                ));
            }
            let properties = networkmanager_native::bounded_props(
                &self.connection,
                owner,
                active_path.as_str(),
                NM_ACTIVE,
            )?;
            let devices: Vec<OwnedObjectPath> = snapshot_property(&properties, "Devices")?;
            let saved: OwnedObjectPath = snapshot_property(&properties, "Connection")?;
            let uuid: String = snapshot_property(&properties, "Uuid")?;
            let kind: String = snapshot_property(&properties, "Type")?;
            let vpn: bool = snapshot_property(&properties, "Vpn")?;
            let state: u32 = snapshot_property(&properties, "State")?;
            let state_flags: u32 = snapshot_property(&properties, "StateFlags")?;
            let default4: bool = snapshot_property(&properties, "Default")?;
            let default6: bool = snapshot_property(&properties, "Default6")?;
            if devices.len() != 1
                || devices[0] != device_object
                || saved.as_str() != profile_path
                || uuid != profile.uuid()
                || vpn
                || !matches!(
                    (native_kind, kind.as_str()),
                    (1, "802-3-ethernet") | (2, "802-11-wireless")
                )
                || state > 4
            {
                return Err(deny(
                    "active connection is foreign, partial or changed profile",
                ));
            }
            let wireless_access_point = if native_kind == 2 {
                let props = networkmanager_native::bounded_props(
                    &self.connection,
                    owner,
                    device_path.as_str(),
                    NM_WIFI,
                )?;
                let ap: OwnedObjectPath = snapshot_property(&props, "ActiveAccessPoint")?;
                if state == 2 && ap.as_str() == "/" {
                    return Err(deny("active Wi-Fi connection has no associated AP"));
                }
                (ap.as_str() != "/").then_some(ap)
            } else {
                None
            };
            let identity = NetworkActiveConnectionId::new(
                target.device().clone(),
                object.clone(),
                Some(profile.clone()),
                object.sequence(),
            )
            .map_err(|_| deny("active connection generation is invalid"))?;
            Some(ActiveInstance {
                identity,
                state,
                state_flags,
                default4,
                default6,
                connection_type: kind,
                wireless_access_point,
            })
        };
        // IP configuration can be absent during DHCP or for an intentionally
        // disabled address family, but cannot be presumed 'connected'.
        let ipv4 = sample_ip_config(&self.connection, owner, &ip4_path, 4)?;
        let ipv6 = sample_ip_config(&self.connection, owner, &ip6_path, 6)?;
        // IPConfig objects may change their *contents* while retaining the
        // same path; compare a full second typed read, not object IDs alone.
        if ipv4 != sample_ip_config(&self.connection, owner, &ip4_path, 4)?
            || ipv6 != sample_ip_config(&self.connection, owner, &ip6_path, 6)?
        {
            return Err(deny(
                "address, route or resolver contents drifted during native read",
            ));
        }
        if let Some(instance) = &active {
            let original_path = instance.identity.object().native_path();
            let current = networkmanager_native::bounded_props(
                &self.connection,
                owner,
                &original_path,
                NM_ACTIVE,
            )?;
            let retained: OwnedObjectPath = snapshot_property(&current, "Connection")?;
            let present: Vec<OwnedObjectPath> = snapshot_property(&current, "Devices")?;
            if retained.as_str() != profile_path
                || present.len() != 1
                || present[0] != device_object
                || snapshot_property::<String>(&current, "Uuid")? != profile.uuid()
                || snapshot_property::<u32>(&current, "State")? != instance.state
                || snapshot_property::<u32>(&current, "StateFlags")? != instance.state_flags
                || snapshot_property::<bool>(&current, "Default")? != instance.default4
                || snapshot_property::<bool>(&current, "Default6")? != instance.default6
                || snapshot_property::<String>(&current, "Type")? != instance.connection_type
                || snapshot_property::<bool>(&current, "Vpn")?
            {
                return Err(deny(
                    "active connection state changed in place during native read",
                ));
            }
            if let Some(original_ap) = &instance.wireless_access_point {
                let wifi = networkmanager_native::bounded_props(
                    &self.connection,
                    owner,
                    &device_path,
                    NM_WIFI,
                )?;
                if snapshot_property::<OwnedObjectPath>(&wifi, "ActiveAccessPoint")? != *original_ap
                {
                    return Err(deny(
                        "associated Wi-Fi access point changed during native read",
                    ));
                }
            }
        }
        if let Some((original_inventory, ap_path, original_evidence)) = &requested_ap
            && (self.wireless_index(owner, &device_object)? != *original_inventory
                || pinned_connection_ap(&self.connection, owner, ap_path.as_str())?
                    != *original_evidence)
        {
            return Err(deny(
                "selected Wi-Fi AP changed in place during native read",
            ));
        }
        // The first profile read can become stale while device/AP/IP objects
        // are sampled. Re-read the saved settings revision *after* those
        // dependencies, not only the profile object-path inventory.
        let late_profile_props = networkmanager_native::bounded_props(
            &self.connection,
            owner,
            &profile_path,
            "org.freedesktop.NetworkManager.Settings.Connection",
        )?;
        let late_unsaved: bool = snapshot_property(&late_profile_props, "Unsaved")?;
        // Flags are a native source dimension not guaranteed to change the
        // secret-free settings fingerprint. Reject in-place scope changes.
        if snapshot_property::<u32>(&old_profile_props, "Flags")?
            != snapshot_property::<u32>(&late_profile_props, "Flags")?
        {
            return Err(deny("saved profile flags changed during source read"));
        }
        let late_path = profiles_before
            .get(&profile.object().sequence())
            .ok_or_else(|| deny("saved profile disappeared during native read"))?;
        if late_unsaved
            || self.profile_revision(&epoch, late_path, &late_profile_props)? != *profile
        {
            return Err(deny(
                "saved profile revision changed after dependent native reads",
            ));
        }
        if self.device_index(owner)? != device_before
            || self.profile_index(owner)? != profiles_before
            || self.active_index(owner)? != actives_before
            || self.device_identity(&epoch, &device_object, target.device().interface().as_str())?
                != *target.device()
        {
            return Err(deny(
                "native object, owner or device inventory changed during read",
            ));
        }
        let check = networkmanager_native::bounded_props(
            &self.connection,
            owner,
            device_path.as_str(),
            NM_DEVICE_INTERFACE,
        )?;
        if snapshot_property::<OwnedObjectPath>(&check, "ActiveConnection")? != active_path
            || snapshot_property::<OwnedObjectPath>(&check, "Ip4Config")? != ip4_path
            || snapshot_property::<OwnedObjectPath>(&check, "Ip6Config")? != ip6_path
            || snapshot_property::<u32>(&check, "State")? != device_state
            || snapshot_property::<bool>(&check, "Managed")? != managed
            || snapshot_property::<u32>(&check, "DeviceType")? != native_kind
            || snapshot_property::<String>(&check, "Interface")? != observed_name
        {
            return Err(deny("device or IP source changed during read"));
        }
        self.require_native_epoch(&epoch)?;
        let kernel_after = connection_kernel::sample()?;
        kernel_before.require_same_source(&kernel_after)?;
        require_nm_elapsed(started)?;
        let sample = NativeConnectionLifecycleSample {
            epoch,
            device: target.device().clone(),
            profile: profile.clone(),
            active,
            device_state,
            ipv4,
            ipv6,
            observer_sequence: next_sequence(&self.sequence)?,
            observed_at: Instant::now(),
            kernel: kernel_before,
        };
        Ok(sample)
    }

    /// Fresh, bounded readback after *another* separately authorized sender
    /// has attempted exactly one operation. Never sends, commits or retries.
    pub fn sample_connection_readback(
        &self,
        before: &NativeConnectionLifecycleSample,
        target: &NativeConnectionTarget,
        required: ConnectionReadbackRequirements,
    ) -> Result<NativeConnectionLifecycleReadback, ProviderError> {
        if Instant::now()
            .checked_duration_since(before.observed_at)
            .is_none_or(|elapsed| elapsed > MAX_LIFECYCLE_AGE)
        {
            return Err(deny(
                "original preflight expired or has a foreign monotonic clock",
            ));
        }
        // This is a *post*-mutation read, not the preflight method above:
        // activation may now have acquired a new active object, deactivation
        // must have lost exactly the original object.
        let after = self.sample_connection_post_state(target)?;
        assess_connection_readback(before, after, target, required)
    }

    fn sample_connection_post_state(
        &self,
        target: &NativeConnectionTarget,
    ) -> Result<NativeConnectionLifecycleSample, ProviderError> {
        // Same source checks as the preflight, without its no-change boundary.
        self.sample_connection_unqualified(target)
    }
}

/// Strictly local postcondition classifier. It never returns a durable
/// VerificationDisposition; that needs independent kernel/route/DNS evidence.
fn assess_connection_readback(
    before: &NativeConnectionLifecycleSample,
    after: NativeConnectionLifecycleSample,
    target: &NativeConnectionTarget,
    required: ConnectionReadbackRequirements,
) -> Result<NativeConnectionLifecycleReadback, ProviderError> {
    target.require_consistent()?;
    if before.epoch != after.epoch
        || before.device != after.device
        || before.profile != after.profile
        || before.device != *target.device()
        || before.profile != *target.profile()?
        || before.observer_sequence == 0
        || after.observer_sequence <= before.observer_sequence
        || after.observed_at <= before.observed_at
        || after.observed_at.duration_since(before.observed_at) > MAX_LIFECYCLE_AGE
    {
        return Err(deny(
            "connection postcondition has an ambiguous original epoch or sample",
        ));
    }
    before.kernel.require_unaffected_stable(
        &after.kernel,
        target.device().interface().as_str(),
        target.device().ifindex(),
    )?;
    // NM IPConfig can report addresses that the actual kernel never
    // installed. Cross-check every claimed IPv4 address on the exact ifindex
    // before accepting even this noncommitting post-state readback.
    let asserted_ipv4 = after
        .ipv4
        .as_ref()
        .map_or(&[][..], |ip| ip.addresses.as_slice());
    after
        .kernel
        .require_provider_ipv4(target.device().ifindex(), asserted_ipv4)?;
    let asserted_ipv6 = after
        .ipv6
        .as_ref()
        .map_or(&[][..], |ip| ip.addresses.as_slice());
    after
        .kernel
        .require_provider_ipv6(target.device().ifindex(), asserted_ipv6)?;
    match target {
        NativeConnectionTarget::Activate { .. } | NativeConnectionTarget::ActivateWifi { .. } => {
            let association_is_exact = match target {
                NativeConnectionTarget::Activate { .. } => {
                    after.active.as_ref().is_some_and(|active| {
                        active.connection_type == "802-3-ethernet"
                            && active.wireless_access_point.is_none()
                    })
                }
                NativeConnectionTarget::ActivateWifi { access_point, .. } => {
                    after.active.as_ref().is_some_and(|active| {
                        active.connection_type == "802-11-wireless"
                            && active.wireless_access_point.as_ref().is_some_and(|ap| {
                                ap.as_str() == access_point.object().native_path()
                            })
                    })
                }
                NativeConnectionTarget::Deactivate(_) => false,
            };
            if before.active.is_some()
                || after.device_state != 100
                || !association_is_exact
                || after.active.as_ref().is_none_or(|active| active.state != 2)
            {
                return Err(deny(
                    "requested activation has no independently reobserved NM state",
                ));
            }
            let ip4 = after.ipv4.as_ref();
            let ip6 = after.ipv6.as_ref();
            let ifname = target.device().interface().as_str();
            if (required.default4 && after.active.as_ref().is_none_or(|active| !active.default4))
                || (required.default6
                    && after.active.as_ref().is_none_or(|active| !active.default6))
                || (required.ipv4 && ip4.is_none_or(|ip| !ip.has_address()))
                || (required.ipv6 && ip6.is_none_or(|ip| !ip.has_address()))
                || (required.dns
                    && !ip4.is_some_and(NativeIpConfiguration::has_resolver)
                    && !ip6.is_some_and(NativeIpConfiguration::has_resolver))
                || (required.default4 && ip4.is_none_or(|ip| !ip.has_default_route()))
                || (required.default6 && ip6.is_none_or(|ip| !ip.has_default_route()))
                || (required.default4 && !after.kernel.main_default_for(4, ifname))
                || (required.default6 && !after.kernel.main_default_for(6, ifname))
                || (ip4.is_none_or(|ip| !ip.has_address())
                    && ip6.is_none_or(|ip| !ip.has_address()))
            {
                return Err(deny(
                    "requested activation has partial IP, DNS or route settlement",
                ));
            }
        }
        NativeConnectionTarget::Deactivate(expected) => {
            before.kernel.require_deactivated(
                &after.kernel,
                target.device().interface().as_str(),
                target.device().ifindex(),
            )?;
            if before
                .active
                .as_ref()
                .is_none_or(|active| &active.identity != expected)
                || after.active.is_some()
                || after.device_state == 100
                || after
                    .ipv4
                    .as_ref()
                    .is_some_and(|value| value.has_default_route())
                || after
                    .ipv6
                    .as_ref()
                    .is_some_and(|value| value.has_default_route())
            {
                return Err(deny(
                    "original active instance was not independently retired",
                ));
            }
            // A device becoming 'disconnected' does not demonstrate that an
            // administrator kept connectivity through a different link.
            if required.ipv4
                || required.ipv6
                || required.dns
                || required.default4
                || required.default6
            {
                return Err(deny("deactivation cannot establish alternate link safety"));
            }
        }
    }
    Ok(NativeConnectionLifecycleReadback { sample: after })
}

#[cfg(test)]
mod tests {
    use super::*;
    use linura_core::{BootId, NetworkInterfaceName, NetworkManagerOwner, SystemBusInstanceId};

    fn ok<T, E: Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|e| unreachable!("fixture: {e:?}"))
    }

    fn source() -> (NetworkDeviceId, NetworkProfileRevision) {
        let epoch = NetworkManagerEpoch::new(
            ok(BootId::new("abcd1234-1234-4567-89ab-0123456789ab")),
            ok(SystemBusInstanceId::new("fedcba9876543210abcdef0123456789")),
            ok(NetworkManagerOwner::new(":1.48")),
        );
        let device = ok(NetworkDeviceId::new(
            epoch.clone(),
            ok(NetworkObjectId::from_path(
                NetworkObjectKind::Device,
                "/org/freedesktop/NetworkManager/Devices/8",
            )),
            4_026_531_840,
            7,
            ok(NetworkInterfaceName::new("wlan0")),
            8,
        ));
        let profile = ok(NetworkProfileRevision::new(
            epoch,
            ok(NetworkObjectId::from_path(
                NetworkObjectKind::SettingsConnection,
                "/org/freedesktop/NetworkManager/Settings/9",
            )),
            "10203040-5060-7080-90ab-cdef12345678",
            10,
            "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
        ));
        (device, profile)
    }

    fn sample(
        target: &NativeConnectionTarget,
        active: bool,
        sequence: u64,
        at: Instant,
    ) -> NativeConnectionLifecycleSample {
        let device = target.device().clone();
        let profile = ok(target.profile()).clone();
        let identity = ok(NetworkActiveConnectionId::new(
            device.clone(),
            ok(NetworkObjectId::from_path(
                NetworkObjectKind::ActiveConnection,
                "/org/freedesktop/NetworkManager/ActiveConnection/12",
            )),
            Some(profile.clone()),
            12,
        ));
        let wifi = matches!(target, NativeConnectionTarget::ActivateWifi { .. });
        NativeConnectionLifecycleSample {
            epoch: device.epoch().clone(),
            device,
            profile,
            active: active.then_some(ActiveInstance {
                identity,
                state: 2,
                state_flags: 0,
                default4: true,
                default6: false,
                connection_type: if wifi {
                    "802-11-wireless"
                } else {
                    "802-3-ethernet"
                }
                .into(),
                wireless_access_point: if wifi {
                    Some(ok(OwnedObjectPath::try_from(
                        "/org/freedesktop/NetworkManager/AccessPoint/4",
                    )))
                } else {
                    None
                },
            }),
            device_state: if active { 100 } else { 30 },
            ipv4: active.then_some(NativeIpConfiguration {
                path: ok(OwnedObjectPath::try_from(
                    "/org/freedesktop/NetworkManager/IP4Config/3",
                )),
                addresses: vec!["10.0.0.4/24".into()],
                routes: vec!["0.0.0.0/0|10.0.0.1".into()],
                nameservers: vec!["1.1.1.1".into()],
                gateway: "10.0.0.1".into(),
            }),
            ipv6: None,
            observer_sequence: sequence,
            observed_at: at,
            kernel: connection_kernel::KernelConnectionSnapshot::with_fallback_fixture(
                target.device().interface().as_str(),
                active,
                target.device().ifindex(),
            ),
        }
    }

    #[test]
    fn activation_checks_real_ip_dns_route_and_new_generation_without_granting_execution() {
        let (device, profile) = source();
        let target = NativeConnectionTarget::Activate { device, profile };
        let at = Instant::now();
        let before = sample(&target, false, 1, at);
        let after = sample(&target, true, 2, at + Duration::from_millis(5));
        let requirements = ConnectionReadbackRequirements {
            ipv4: true,
            ipv6: false,
            dns: true,
            default4: true,
            default6: false,
        };
        let readback = ok(assess_connection_readback(
            &before,
            after.clone(),
            &target,
            requirements,
        ));
        assert!(readback.commit_authority_unverified());
        assert!(readback.sample().execution_safety_unverified());
        let mut stale = after.clone();
        stale.observer_sequence = 1;
        assert!(assess_connection_readback(&before, stale, &target, requirements).is_err());
        let mut missing_dns = after.clone();
        missing_dns
            .ipv4
            .as_mut()
            .unwrap_or_else(|| unreachable!("fixture"))
            .nameservers
            .clear();
        assert!(assess_connection_readback(&before, missing_dns, &target, requirements).is_err());
        let mut wrong_epoch = after;
        wrong_epoch.profile = ok(NetworkProfileRevision::new(
            wrong_epoch.epoch.clone(),
            wrong_epoch.profile.object().clone(),
            wrong_epoch.profile.uuid(),
            11,
            wrong_epoch.profile.settings_fingerprint(),
        ));
        assert!(assess_connection_readback(&before, wrong_epoch, &target, requirements).is_err());
    }

    #[test]
    fn wifi_activation_rejects_substituted_association_even_after_nm_reports_online() {
        let (device, profile) = source();
        let ap = ok(NetworkAccessPointId::new(
            device.clone(),
            ok(NetworkObjectId::from_path(
                NetworkObjectKind::AccessPoint,
                "/org/freedesktop/NetworkManager/AccessPoint/4",
            )),
            41,
        ));
        let target = NativeConnectionTarget::ActivateWifi {
            device,
            profile,
            access_point: ap,
        };
        let initial = Instant::now();
        let before = sample(&target, false, 1, initial);
        let after = sample(&target, true, 2, initial + Duration::from_millis(5));
        let required = ConnectionReadbackRequirements {
            ipv4: true,
            ipv6: false,
            dns: true,
            default4: true,
            default6: false,
        };
        assert!(assess_connection_readback(&before, after.clone(), &target, required).is_ok());
        let mut replaced = after.clone();
        let current = replaced
            .active
            .as_mut()
            .unwrap_or_else(|| unreachable!("active fixture"));
        current.wireless_access_point = Some(ok(OwnedObjectPath::try_from(
            "/org/freedesktop/NetworkManager/AccessPoint/5",
        )));
        assert!(assess_connection_readback(&before, replaced, &target, required).is_err());
        let mut changed_type = after;
        changed_type
            .active
            .as_mut()
            .unwrap_or_else(|| unreachable!("active fixture"))
            .connection_type = "802-3-ethernet".into();
        assert!(assess_connection_readback(&before, changed_type, &target, required).is_err());
    }

    #[test]
    fn deactivation_never_proves_offline_survival_or_permits_replay() {
        let (device, profile) = source();
        let initially = NativeConnectionTarget::Activate {
            device: device.clone(),
            profile: profile.clone(),
        };
        let at = Instant::now();
        let before = sample(&initially, true, 1, at);
        let target = NativeConnectionTarget::Deactivate(
            before
                .active()
                .unwrap_or_else(|| unreachable!("fixture"))
                .clone(),
        );
        let after = sample(&target, false, 2, at + Duration::from_millis(5));
        let no_routes = ConnectionReadbackRequirements {
            ipv4: false,
            ipv6: false,
            dns: false,
            default4: false,
            default6: false,
        };
        assert!(assess_connection_readback(&before, after.clone(), &target, no_routes).is_ok());
        assert!(
            assess_connection_readback(
                &before,
                after,
                &target,
                ConnectionReadbackRequirements {
                    default4: true,
                    ..no_routes
                },
            )
            .is_err()
        );
    }
}
